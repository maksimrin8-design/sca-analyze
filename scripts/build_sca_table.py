#!/usr/bin/env python3
"""Reproducible, conservative comparison of OSV-Scanner and Grype evidence.

Ground truth is human-curated, not inferred from scanner output. Distinguishes missing,
invalid and unsuccessful scans from genuine absence of a detection.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


SCANNERS = ("osv", "grype")
VALID_STATUSES = {"verified", "candidate", "unverified", "rejected"}


def norm(value):
    return str(value or "").strip().lower().replace("_", "-")


def clean_ids(ids):
    return {norm(i) for i in ids if isinstance(i, str) and i.strip()}


def read_json(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def emit_csv(path, columns, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def md(value):
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def emit_md(path, title, intro, columns, rows):
    out = [f"# {title}", "", intro, "", "| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        out.append("| " + " | ".join(md(row.get(k, "")) for k in columns) + " |")
    if not rows:
        out.append("| " + " | ".join(["—"] + ["Нет данных"] + [""] * (len(columns) - 2)) + " |")
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


def finding(package, version, ecosystem, ids, source=""):
    return {
        "package": norm(package),
        "version": str(version or "").strip(),
        "ecosystem": norm(ecosystem),
        "ids": clean_ids(ids),
        "source": source,
    }


def osv_findings(data):
    """OSV v2 stores vulnerability detail in packages[].vulnerabilities and aliases in groups[]."""
    result = []
    for entry in data.get("results", []) or []:
        source = (entry.get("source") or {}).get("path", "")
        for group in entry.get("packages", []) or []:
            package = group.get("package") or {}
            group_aliases = {}
            for g in group.get("groups", []) or []:
                ids = clean_ids((g.get("ids") or []) + (g.get("aliases") or []))
                for key in ids:
                    group_aliases[key] = group_aliases.get(key, set()) | ids
            vulns = group.get("vulnerabilities") or []
            if not vulns:
                for g in group.get("groups", []) or []:
                    ids = list((g.get("ids") or []) + (g.get("aliases") or []))
                    if ids:
                        result.append(finding(package.get("name"), package.get("version"), package.get("ecosystem"), ids, source))
            for v in vulns:
                ids = clean_ids([v.get("id", "")] + (v.get("aliases") or []))
                for identifier in list(ids):
                    ids |= group_aliases.get(identifier, set())
                if ids:
                    result.append(finding(package.get("name"), package.get("version"), package.get("ecosystem"), ids, source))
    return result


def grype_findings(data):
    result = []
    for entry in data.get("matches", []) or []:
        artifact = entry.get("artifact") or {}
        vulnerability = entry.get("vulnerability") or {}
        related = entry.get("relatedVulnerabilities") or []
        ids = [vulnerability.get("id", "")] + [x.get("id", "") for x in related]
        locations = artifact.get("locations") or []
        source = locations[0].get("path", "") if locations else ""
        result.append(finding(artifact.get("name"), artifact.get("version"), artifact.get("type"), ids, source))
    return result


def scan_info(root, tool):
    path = root / tool / "result.json"
    code_file = root / tool / "exit-code.txt"
    if not code_file.exists():
        return {"state": "not_run", "detail": "Нет exit-code.txt; инструмент не выполнился", "findings": []}
    code = code_file.read_text(encoding="utf-8").strip()
    # OSV=1 means vulnerabilities found. Grype without --fail-on returns 0.
    if code not in ({"0", "1"} if tool == "osv" else {"0"}):
        return {"state": "failed", "detail": f"Код завершения {code}", "findings": []}
    data = read_json(path)
    if data is None:
        return {"state": "invalid_report", "detail": "Отсутствует/повреждён JSON", "findings": []}
    required = "results" if tool == "osv" else "matches"
    if required not in data or not isinstance(data[required], list):
        return {"state": "invalid_report", "detail": f"Нет массива {required}", "findings": []}
    findings = osv_findings(data) if tool == "osv" else grype_findings(data)
    return {"state": "ok", "detail": "", "findings": findings}


def equivalent_ecosystem(expected, observed):
    a, b = norm(expected), norm(observed)
    if not a or not b:
        return True
    mapping = {"npm": "npm", "maven": "java", "java": "java", "pypi": "python", "python": "python", "gem": "ruby", "rubygems": "ruby", "ruby": "ruby", "golang": "go", "go": "go", "composer": "php", "php": "php", "cargo": "rust", "rust": "rust", "nuget": "dotnet", "dotnet": "dotnet"}
    return mapping.get(a, a) == mapping.get(b, b)


def assess(expected, actual, scan_state="ok"):
    if scan_state != "ok":
        return "Не оценивалось", f"Сканирование: {scan_state}; нельзя считать пропуском"
    pkg, version = norm(expected.get("package")), str(expected.get("version", "")).strip()
    aliases = clean_ids(str(expected.get("vulnerability_ids", "")).replace(",", ";").split(";"))
    same_pkg = [x for x in actual if x["package"] == pkg and equivalent_ecosystem(expected.get("ecosystem"), x["ecosystem"])]
    exact = [x for x in same_pkg if x["version"] == version]
    matched = [x for x in exact if x["ids"] & aliases]
    if matched:
        identifiers = sorted(set().union(*(x["ids"] & aliases for x in matched)))
        return "Найдено полностью", f"Совпали пакет, версия и advisory: {', '.join(identifiers)}"
    wrong_version = [x for x in same_pkg if x["ids"] & aliases]
    if wrong_version:
        return "Частично", "Advisory совпал, но версия отличается: " + ", ".join(sorted({x["version"] for x in wrong_version}))
    if exact:
        return "Частично", "Пакет и версия есть, но ожидаемый advisory отсутствует (другие уязвимости не эквивалентны)"
    return "Не найдено", "Ожидаемое сочетание пакет + версия + уязвимость не обнаружено"


def aggregate(findings):
    """Deduplicate by component/version and intersecting alias sets (not by package alone)."""
    groups = {}
    for item in findings:
        key = (item["package"], item["version"], item["ecosystem"])
        groups.setdefault(key, []).append(item)
    merged = []
    for key, items in groups.items():
        sets = []
        for item in items:
            overlap = [s for s in sets if s["ids"] & item["ids"]]
            if overlap:
                destination = overlap[0]
                destination["ids"].update(item["ids"])
                destination["sources"].add(item["source"])
                for other in overlap[1:]:
                    destination["ids"].update(other["ids"])
                    destination["sources"].update(other["sources"])
                    sets.remove(other)
            else:
                sets.append({"package": key[0], "version": key[1], "ecosystem": key[2], "ids": set(item["ids"]), "sources": {item["source"]}})
        # Bridge aliases may link previously separate items after merges.
        again = True
        while again:
            again = False
            for i in range(len(sets)):
                for j in range(i + 1, len(sets)):
                    if sets[i]["ids"] & sets[j]["ids"]:
                        sets[i]["ids"] |= sets[j]["ids"]
                        sets[i]["sources"] |= sets[j]["sources"]
                        sets.pop(j)
                        again = True
                        break
                if again:
                    break
        merged.extend(sets)
    return merged


def primary_id(ids):
    if not ids:
        return ""
    return sorted(ids, key=lambda x: (0 if x.startswith("cve-") else 1 if x.startswith("ghsa-") else 2, x))[0].upper()


def disparities(osv, grype):
    left, right = aggregate(osv), aggregate(grype)
    used_right = set()
    comparisons = []
    for a in left:
        overlaps = [i for i, b in enumerate(right) if i not in used_right and a["package"] == b["package"] and a["version"] == b["version"] and equivalent_ecosystem(a["ecosystem"], b["ecosystem"]) and a["ids"] & b["ids"]]
        if overlaps:
            i = overlaps[0]
            used_right.add(i)
            comparisons.append((a, right[i], "Оба"))
        else:
            comparisons.append((a, None, "Только OSV"))
    for i, b in enumerate(right):
        if i not in used_right:
            comparisons.append((None, b, "Только Grype"))
    return comparisons


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--results-dir", required=True)
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--manifest", help="Optional 30-project manifest, includes projects with missing artifacts")
    a = p.parse_args()
    source = Path(a.results_dir)
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    reference = read_csv(Path(a.ground_truth))
    unknown = [x for x in reference if (x.get("status") or "").strip().lower() not in VALID_STATUSES]
    if unknown:
        raise ValueError("Unrecognized ground truth status: " + str(unknown[0].get("status")))
    truth = defaultdict(list)
    for row in reference:
        if row.get("status", "").lower() == "verified":
            truth[row["project_id"]].append(row)
    all_projects = {}
    if a.manifest:
        for project in read_json(Path(a.manifest))["projects"]:
            all_projects[project["id"]] = {"name": project["name"], "root": None, "repo": project["repo"]}
    for meta_file in source.rglob("project.json"):
        data = read_json(meta_file) or {}
        project_id = data.get("project_id")
        if project_id:
            all_projects[project_id] = {"name": data.get("name", meta_file.parent.name), "root": meta_file.parent, "repo": data.get("repository", "")}

    reference_rows, project_rows, difference_rows, metric_rows = [], [], [], []
    evidence = []
    for project_id, project in sorted(all_projects.items()):
        root = project["root"]
        scans = {tool: scan_info(root, tool) if root is not None else {"state": "missing_artifact", "detail": "Нет артефакта проекта", "findings": []} for tool in SCANNERS}
        statuses = {tool: Counter() for tool in SCANNERS}
        for x in truth.get(project_id, []):
            row = {"project_id": project_id, "project": project["name"], "package": x["package"], "version": x["version"], "ecosystem": x.get("ecosystem", ""), "vulnerability_ids": x["vulnerability_ids"], "evidence_url": x.get("evidence_url", ""), "reference_status": "verified"}
            for tool in SCANNERS:
                result, note = assess(x, scans[tool]["findings"], scans[tool]["state"])
                row[f"{tool}_status"] = result
                row[f"{tool}_comment"] = note
                statuses[tool][result] += 1
            reference_rows.append(row)
        if not truth.get(project_id):
            reference_rows.append({
                "project_id": project_id,
                "project": project["name"],
                "package": "",
                "version": "",
                "ecosystem": "",
                "vulnerability_ids": "",
                "reference_status": "not_yet_adjudicated",
                "evidence_url": "",
                "osv_status": "Не оценивалось",
                "osv_comment": "Эталон не подтверждён; состояние отчёта: " + scans["osv"]["state"],
                "grype_status": "Не оценивалось",
                "grype_comment": "Эталон не подтверждён; состояние отчёта: " + scans["grype"]["state"],
            })
        active = all(scans[t]["state"] == "ok" for t in SCANNERS)
        combos = disparities(scans["osv"]["findings"], scans["grype"]["findings"]) if active else []
        count_by_type = Counter()
        for left, right, label in combos:
            item = left or right
            ids = left["ids"] | right["ids"] if left and right else item["ids"]
            count_by_type[label] += 1
            difference_rows.append({"project_id": project_id, "project": project["name"], "package": item["package"], "version": item["version"], "ecosystem": item["ecosystem"], "vulnerability_id": primary_id(ids), "all_ids": ";".join(sorted(ids)), "presence": label, "status": "Не проверено по эталону", "note": "Расхождение сканеров не доказывает ошибку/ложноположительность"})
        row = {"project_id": project_id, "project": project["name"], "repository": project["repo"], "verified_reference": len(truth.get(project_id, [])), "osv_scan": scans["osv"]["state"], "grype_scan": scans["grype"]["state"], "osv_vulns": len(aggregate(scans["osv"]["findings"])), "grype_vulns": len(aggregate(scans["grype"]["findings"])), "both": count_by_type["Оба"], "only_osv": count_by_type["Только OSV"], "only_grype": count_by_type["Только Grype"], "osv_full": statuses["osv"]["Найдено полностью"], "osv_partial": statuses["osv"]["Частично"], "osv_missed": statuses["osv"]["Не найдено"], "grype_full": statuses["grype"]["Найдено полностью"], "grype_partial": statuses["grype"]["Частично"], "grype_missed": statuses["grype"]["Не найдено"], "comment": "Эталон не составлен; оценка полноты невозможна" if not truth.get(project_id) else ("Неполные отчёты" if not active else "Оценены только подтверждённые эталонные записи")}
        project_rows.append(row)
        evidence.append({"project_id": project_id, "name": project["name"], "reference_count": len(truth.get(project_id, [])), "scan_status": {tool: scans[tool]["state"] for tool in SCANNERS}, "error_details": {tool: scans[tool]["detail"] for tool in SCANNERS}, "raw_findings": {tool: len(scans[tool]["findings"]) for tool in SCANNERS}})

    counts = Counter()
    for r in project_rows:
        counts["total"] += 1
        counts["complete"] += int(r["osv_scan"] == "ok" and r["grype_scan"] == "ok")
        counts["reference_projects"] += int(r["verified_reference"] > 0)
        counts["reference_rows"] += r["verified_reference"]
        for s in SCANNERS:
            for label in ("full", "partial", "missed"):
                counts[f"{s}_{label}"] += r[f"{s}_{label}"]
    for name, value, note in [
        ("Проектов в корпусе", counts["total"], "Всего в manifest/артефактах"),
        ("Сканирований обоими инструментами завершено", counts["complete"], "Только корректные JSON с допустимыми кодами выхода"),
        ("Проектов с подтверждённым эталоном", counts["reference_projects"], "Эталон не создаётся автоматически по отчётам"),
        ("Подтверждённых эталонных записей", counts["reference_rows"], "Дубликаты CVE/GHSA в одной записи не удваивают подсчёт"),
        *[(f"{s.upper()}: {label}", counts[f"{s}_{key}"], "Только verified Ground Truth") for s in SCANNERS for key, label in (("full", "полных совпадений"), ("partial", "частичных совпадений"), ("missed", "не найдено"))],
    ]:
        metric_rows.append({"metric": name, "value": value, "note": note})

    # One final SCA comparison table (CSV + Markdown representations).
    columns = [
        "project_id", "project", "package", "version", "ecosystem",
        "vulnerability_ids", "reference_status", "evidence_url",
        "osv_status", "osv_comment", "grype_status", "grype_comment",
    ]
    emit_csv(out / "sca-comparison.csv", columns, reference_rows)
    concise = []
    for r in reference_rows:
        expected = (
            f'{r["package"]}@{r["version"]} ({r["vulnerability_ids"]})'
            if r["reference_status"] == "verified"
            else "Эталон не подготовлен (не означает, что уязвимостей нет)"
        )
        concise.append({
            "Проект": f'{r["project_id"]}: {r["project"]}',
            "Эталонная уязвимость": expected,
            "OSV-Scanner": r["osv_status"] + ". " + r["osv_comment"],
            "Grype": r["grype_status"] + ". " + r["grype_comment"],
        })
    emit_md(
        out / "sca-comparison.md",
        "Сравнительная таблица SCA: OSV-Scanner и Grype",
        "Каждая подтверждённая уязвимость — отдельная строка. "
        "Проекты без проверенного эталона также перечислены, но не оцениваются. "
        "Пустой эталон не означает отсутствия уязвимостей.",
        ["Проект", "Эталонная уязвимость", "OSV-Scanner", "Grype"],
        concise,
    )

    (out / "evidence-index.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Projects: {counts['total']}; valid paired scans: {counts['complete']}; verified rows: {counts['reference_rows']}; discrepancies: {len(difference_rows)}")


if __name__ == "__main__":
    main()