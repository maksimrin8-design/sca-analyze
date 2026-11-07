#!/usr/bin/env python3
"""Build one qualitative SCA table from per-application OSV and Grype evidence."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def norm(value: object) -> str:
    return str(value or "").strip().lower().replace("_", "-").replace(" ", "")


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def osv_findings(data: dict) -> list[dict]:
    findings = []
    for result in data.get("results", []) or []:
        for package_group in result.get("packages", []) or []:
            package = package_group.get("package", {}) or {}
            for vuln in package_group.get("vulnerabilities", []) or []:
                findings.append({
                    "package": norm(package.get("name")),
                    "version": str(package.get("version") or ""),
                    "id": norm(vuln.get("id")),
                })
    return findings


def grype_findings(data: dict) -> list[dict]:
    findings = []
    for match in data.get("matches", []) or []:
        artifact = match.get("artifact", {}) or {}
        vuln = match.get("vulnerability", {}) or {}
        findings.append({
            "package": norm(artifact.get("name")),
            "version": str(artifact.get("version") or ""),
            "id": norm(vuln.get("id")),
        })
    return findings


def assess(expected: dict, actual: list[dict]) -> tuple[str, str]:
    package = norm(expected["package"])
    version = str(expected["version"]).strip()
    aliases = {norm(x) for x in expected["vulnerability_ids"].replace(",", ";").split(";") if x.strip()}
    exact = [f for f in actual if f["package"] == package and f["version"] == version]
    if any(f["id"] in aliases for f in exact):
        ids = sorted({f["id"] for f in exact if f["id"] in aliases})
        return "Найдено полностью", "Совпали пакет, точная версия и идентификатор: " + ", ".join(ids)
    same_package = [f for f in actual if f["package"] == package]
    if any(f["id"] in aliases for f in same_package):
        versions = sorted({f["version"] or "не указана" for f in same_package if f["id"] in aliases})
        return "Найдено, но версия отличается", "Advisory совпал, обнаруженная версия: " + ", ".join(versions)
    if exact:
        ids = sorted({f["id"] or "ID не указан" for f in exact})
        return "Частичное совпадение", "Пакет и версия обнаружены, но ожидаемый CVE/GHSA не совпал; IDs: " + ", ".join(ids)
    return "Не найдено", "Ожидаемая комбинация package + version + CVE/GHSA отсутствует в отчёте"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    expected_by_project: dict[str, list[dict]] = {}
    with open(args.ground_truth, newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            if row.get("status", "").strip().lower() == "verified":
                expected_by_project.setdefault(row["project_id"], []).append(row)

    roots = []
    for project_file in Path(args.results_dir).rglob("project.json"):
        app_root = project_file.parent
        if (app_root / "osv" / "result.json").exists() and (app_root / "grype" / "result.json").exists():
            roots.append(app_root)

    rows = []
    evidence_index = []
    for app_root in sorted(roots):
        meta = load_json(app_root / "project.json")
        project_id = meta.get("project_id", app_root.name)
        project_name = meta.get("name", app_root.name)
        reference = load_json(app_root / "default" / "reference.json")
        osv = osv_findings(load_json(app_root / "osv" / "result.json"))
        grype = grype_findings(load_json(app_root / "grype" / "result.json"))
        evidence_index.append({
            "project_id": project_id,
            "project": project_name,
            "reference_status": reference.get("reference_status", "missing"),
            "osv_findings": len(osv),
            "grype_findings": len(grype),
        })
        for item in expected_by_project.get(project_id, []):
            osv_status, osv_note = assess(item, osv)
            grype_status, grype_note = assess(item, grype)
            rows.append({
                "project_id": project_id,
                "project": project_name,
                "package": item["package"],
                "version": item["version"],
                "ecosystem": item.get("ecosystem", ""),
                "vulnerability_ids": item["vulnerability_ids"],
                "osv_status": osv_status,
                "osv_comment": osv_note,
                "grype_status": grype_status,
                "grype_comment": grype_note,
            })

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    columns = ["project_id", "project", "package", "version", "ecosystem", "vulnerability_ids",
               "osv_status", "osv_comment", "grype_status", "grype_comment"]
    with open(out / "sca-comparison.csv", "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    def md(value: object) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = [
        "# Сравнительная таблица SCA",
        "",
        "В таблицу включаются только независимо подтверждённые записи со статусом `verified` из Ground Truth.",
        "Пустой эталон для приложения означает «не проверено», а не «уязвимостей нет».",
        "",
        "| Приложение | Эталонная уязвимость | OSV-Scanner | Grype |",
        "|---|---|---|---|",
    ]
    if rows:
        for row in rows:
            expected = f'{row["package"]}@{row["version"]} ({row["ecosystem"]}); {row["vulnerability_ids"]}'
            osv_text = f'{row["osv_status"]}. {row["osv_comment"]}'
            grype_text = f'{row["grype_status"]}. {row["grype_comment"]}'
            lines.append("| " + " | ".join(md(x) for x in [row["project"], expected, osv_text, grype_text]) + " |")
    else:
        lines.append("| — | Подтверждённых эталонных записей пока нет | Не оценивается | Не оценивается |")
    lines += [
        "",
        "## Ограничения интерпретации",
        "",
        "- «Не найдено» означает отсутствие совпадения в конкретном отчёте сканера, а не доказательство отсутствия уязвимости в приложении.",
        "- Находки, которых нет в неполном Ground Truth, не объявляются ложноположительными.",
        "- Если для приложения нет проверенных эталонных записей, оно не участвует в оценке полноты обнаружения.",
        "",
        f"Проверено артефактов приложений: {len(evidence_index)}. Строк в таблице по verified Ground Truth: {len(rows)}.",
        "",
    ]
    (out / "sca-comparison.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "evidence-index.json").write_text(json.dumps(evidence_index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Applications with evidence: {len(evidence_index)}; verified comparison rows: {len(rows)}")


if __name__ == "__main__":
    main()
