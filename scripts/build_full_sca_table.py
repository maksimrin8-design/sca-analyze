#!/usr/bin/env python3
"""Build ONE exhaustive *observed* SCA comparison from OSV and Grype JSON.

Every distinct observed (project, component, installed version, advisory) is a row.
Verified independent ground-truth rows are incorporated even if both tools miss them.
This inventory is NOT a complete independent truth set unless every row (and every
project's dependency coverage) has been independently adjudicated.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from build_sca_table import (
    aggregate, clean_ids, emit_csv, emit_md, finding,
    norm, primary_id, read_csv, read_json, scan_info,
)

COLUMNS = [
    'project_id', 'project', 'repository', 'upstream_commit',
    'ecosystem', 'package', 'version', 'vulnerability_id', 'all_identifiers',
    'reference_status', 'reference_evidence', 'advisory_url',
    'osv_status', 'grype_status', 'comparison',
    'osv_source', 'grype_source', 'explanation',
]


def canonical_ecosystem(value):
    v = norm(value)
    mapping = {
        'maven': 'maven', 'java': 'maven', 'java-archive': 'maven',
        'npm': 'npm', 'pypi': 'pypi', 'python': 'pypi',
        'rubygems': 'rubygems', 'ruby': 'rubygems', 'gem': 'rubygems',
        'go': 'go', 'golang': 'go', 'go-module': 'go',
        'php': 'composer', 'composer': 'composer',
        'rust': 'cargo', 'cargo': 'cargo', 'dotnet': 'nuget', 'nuget': 'nuget',
    }
    return mapping.get(v, v)


def detailed_grype_findings(data):
    """Preserve Maven groupId when Grype reports only artifactId in name."""
    results = []
    for entry in data.get('matches', []) or []:
        artifact = entry.get('artifact') or {}
        vuln = entry.get('vulnerability') or {}
        ids = [vuln.get('id', '')]
        ids.extend(v.get('id', '') for v in entry.get('relatedVulnerabilities', []) or [])
        name = artifact.get('name', '')
        if canonical_ecosystem(artifact.get('type')) == 'maven':
            meta = artifact.get('metadata') or {}
            group = meta.get('pomGroupID', '')
            art = meta.get('pomArtifactID', '') or name
            if group:
                name = group + ':' + art
        locations = artifact.get('locations') or []
        paths = [x.get('path', '') for x in locations if x.get('path')]
        item = finding(name, artifact.get('version'), artifact.get('type'), ids, paths[0] if paths else '')
        results.append(item)
    return results


def component_key(package, version, ecosystem):
    """Normalize known tool-specific notation without combining different versions."""
    eco = canonical_ecosystem(ecosystem)
    pkg = norm(package)
    if eco == 'maven':
        pkg = pkg.rsplit(':', 1)[-1]  # Grype java-archive commonly omits Maven groupId.
    ver = str(version or '').strip()
    if eco == 'go' and ver.startswith('v') and len(ver) > 1 and ver[1].isdigit():
        ver = ver[1:]
    return eco, pkg, ver


def group_records(entries):
    """Transitive alias merging within a specific ecosystem/component/version.

    Each record contains source='osv'/'grype'/'reference', ids, and package.
    Two records with overlapping aliases in the SAME component are grouped.
    """
    buckets = {}
    for record in entries:
        key = component_key(record['package'], record['version'], record['ecosystem'])
        buckets.setdefault(key, []).append(record)
    grouped = []
    for key, bucket in buckets.items():
        groups = []
        for record in bucket:
            ids = set(record['ids'])
            overlaps = [g for g in groups if g['ids'] & ids]
            if not overlaps:
                groups.append({'ids': ids, 'records': [record]})
                continue
            main = overlaps[0]
            main['ids'].update(ids)
            main['records'].append(record)
            for g in overlaps[1:]:
                main['ids'].update(g['ids'])
                main['records'].extend(g['records'])
                groups.remove(g)
        # A chain of shared identifiers can join groups out of insertion order.
        i = 0
        while i < len(groups):
            j = i + 1
            while j < len(groups):
                if groups[i]['ids'] & groups[j]['ids']:
                    groups[i]['ids'].update(groups[j]['ids'])
                    groups[i]['records'].extend(groups[j]['records'])
                    groups.pop(j)
                else:
                    j += 1
            i += 1
        grouped.extend((key, g) for g in groups)
    return grouped


def link_to_source(repo, ref, path):
    if not repo or not ref or not path:
        return ''
    marker = 'target-repo/'
    if marker in path:
        relative = path.split(marker, 1)[1].lstrip('/')
    elif path.startswith('/') and not path.startswith(('/home/', '/usr/', '/opt/', '/tmp/')):
        # Grype expresses paths inside dir:target-repo from a virtual / root.
        relative = path.lstrip('/')
    else:
        return ''
    if not relative or '..' in relative.split('/'):
        return ''
    return 'https://github.com/' + repo + '/blob/' + ref + '/' + quote(relative, safe='/@+-.')


def advisory_link(ids):
    ids = sorted(ids)
    ghsa = next((i for i in ids if i.startswith('ghsa-')), '')
    if ghsa:
        return 'https://github.com/advisories/' + ghsa.upper()
    cv = next((i for i in ids if i.startswith('cve-')), '')
    if cv:
        return 'https://nvd.nist.gov/vuln/detail/' + cv.upper()
    ident = primary_id(ids)
    return 'https://osv.dev/vulnerability/' + quote(ident) if ident else ''


def as_record(item, source):
    return dict(
        source=source, package=item['package'], version=item['version'],
        ecosystem=item['ecosystem'], ids=set(item['ids']),
        paths=sorted(p for p in item.get('sources', ()) if p),
        evidence='', note='',
    )


def truth_record(row):
    return dict(
        source='reference', package=row['package'], version=row['version'],
        ecosystem=row.get('ecosystem', ''),
        ids=clean_ids(row.get('vulnerability_ids', '').replace(',', ';').split(';')),
        paths=[], evidence=row.get('evidence_url', ''), note=row.get('notes', ''),
    )


def render_status(source, presence, scan):
    if scan['state'] != 'ok':
        return 'Не оценивалось (' + scan['state'] + ')'
    return 'Найдено' if source in presence else 'Не найдено'


def inventory(manifest, reference, results_dir):
    """Return all observed rows and per-project technical diagnostics."""
    roots = {}
    for meta_file in Path(results_dir).rglob('project.json'):
        meta = read_json(meta_file) or {}
        if meta.get('project_id'):
            roots[meta['project_id']] = meta_file.parent
    verified = {}
    for ref in reference:
        if norm(ref.get('status')) == 'verified':
            verified.setdefault(ref['project_id'], []).append(ref)
    rows, diagnostics = [], []
    for project in sorted(manifest['projects'], key=lambda p: p['id']):
        project_id, name = project['id'], project['name']
        project_repo = project['repo']
        ref = project['ref']
        root = roots.get(project_id)
        scans = {
            t: scan_info(root, t) if root else {
                'state': 'missing_artifact', 'detail': 'Нет артефакта проекта', 'findings': []
            }
            for t in ('osv', 'grype')
        }
        # scan_info checks exit codes/JSON validity; only then replace the
        # simplified Grype interpretation with Maven-coordinate-aware data.
        if root is not None and scans['grype']['state'] == 'ok':
            scans['grype']['findings'] = detailed_grype_findings(read_json(root/'grype'/'result.json'))
        entries = []
        for scanner in ('osv', 'grype'):
            for item in aggregate(scans[scanner]['findings']):
                entries.append(as_record(item, scanner))
        for entry in verified.get(project_id, []):
            entries.append(truth_record(entry))

        seen = Counter()
        for (eco, pkg_key, version), g in group_records(entries):
            members = g['records']
            sources = {r['source'] for r in members}
            confirmed = [r for r in members if r['source'] == 'reference']
            status = 'verified' if confirmed else 'candidate_not_independently_verified'
            # Prefer full Maven coordinate from OSV/reference, rather than Grype's basename.
            exact_names = [r['package'] for r in members]
            named = [r['package'] for r in members if r['source'] == 'reference']
            named += [r['package'] for r in members if r['source'] == 'osv']
            named += exact_names
            package = next((p for p in named if eco != 'maven' or ':' in p), named[0])
            presence = set(sources) - {'reference'}
            if all(scans[t]['state'] == 'ok' for t in ('osv', 'grype')):
                if presence == {'osv', 'grype'}:
                    compare = 'Оба'
                elif presence == {'osv'}:
                    compare = 'Только OSV'
                elif presence == {'grype'}:
                    compare = 'Только Grype'
                else:
                    compare = 'Не найдено обоими (подтверждённый эталон)'
            else:
                compare = 'Неполное сканирование'
            seen[compare] += 1
            ids = g['ids']
            sources_text = {}
            for scanner in ('osv', 'grype'):
                paths = sorted({p for r in members if r['source'] == scanner for p in r['paths']})
                urls = sorted({u for path in paths if (u := link_to_source(project_repo, ref, path))})
                sources_text[scanner] = ';'.join(urls[:3])
            ref_urls = sorted({r['evidence'] for r in confirmed if r['evidence']})
            note = '; '.join(r['note'] for r in confirmed if r['note'])
            if not confirmed:
                note = 'Требуется независимая проверка пакета, версии и advisory; находки сканеров не являются эталоном.'
            elif not presence:
                note = (note + ' Оба инструмента пропустили подтверждённую запись.').strip()
            rows.append(dict(
                project_id=project_id, project=name, repository=project_repo, upstream_commit=ref,
                ecosystem=eco, package=package, version=version,
                vulnerability_id=primary_id(ids), all_identifiers=';'.join(i.upper() for i in sorted(ids)),
                reference_status=status, reference_evidence=';'.join(ref_urls),
                advisory_url=advisory_link(ids), osv_status=render_status('osv', presence, scans['osv']),
                grype_status=render_status('grype', presence, scans['grype']),
                comparison=compare, osv_source=sources_text['osv'], grype_source=sources_text['grype'],
                explanation=note,
            ))
        if not entries:
            rows.append(dict(
                project_id=project_id, project=name, repository=project_repo, upstream_commit=ref,
                ecosystem='', package='', version='', vulnerability_id='', all_identifiers='',
                reference_status='no_reference_and_no_observations', reference_evidence='', advisory_url='',
                osv_status=render_status('osv', set(), scans['osv']),
                grype_status=render_status('grype', set(), scans['grype']),
                comparison='Наблюдений нет; это не подтверждение безопасности',
                osv_source='', grype_source='', explanation='Инструменты не сообщили уязвимостей; полный независимый эталон не построен.',
            ))
        diagnostics.append(dict(
            project_id=project_id, project=name, reference_entries=len(verified.get(project_id, [])),
            scans={t: scans[t]['state'] for t in ('osv', 'grype')},
            raw_osv=len(scans['osv']['findings']), raw_grype=len(scans['grype']['findings']),
            distinct_observations=dict(seen),
        ))
    rows.sort(key=lambda r: (r['project_id'], r['ecosystem'], r['package'], r['version'], r['vulnerability_id']))
    return rows, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results-dir', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--ground-truth', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    manifest = read_json(Path(args.manifest))
    if not manifest or not isinstance(manifest.get('projects'), list):
        raise ValueError('Invalid project manifest')
    gt = read_csv(Path(args.ground_truth))
    if gt and not {'project_id', 'package', 'version', 'status', 'vulnerability_ids'}.issubset(gt[0]):
        raise ValueError('Invalid ground-truth columns')
    rows, diag = inventory(manifest, gt, args.results_dir)
    emit_csv(out / 'sca-comparison.csv', COLUMNS, rows)
    concise = [{
        'Проект': f"{r['project_id']} {r['project']}",
        'Зависимость': r['package'] + ('@' + r['version'] if r['version'] else ''),
        'Уязвимость': r['vulnerability_id'],
        'Эталон': 'Подтверждено' if r['reference_status'] == 'verified' else 'Не подтверждено',
        'OSV-Scanner': r['osv_status'],
        'Grype': r['grype_status'],
        'Примечание': r['explanation'],
    } for r in rows]
    emit_md(
        out / 'sca-comparison.md',
        'Единая таблица SCA: OSV-Scanner vs Grype',
        'ВСЕ уникальные НАБЛЮДАЕМЫЕ уязвимости по 30 проектам, а также верифицированные '
        'эталонные пункты, даже когда их не обнаружили инструменты. '
        'Кандидатные наблюдения не являются независимым ground truth; '
        'для заявлений о полноте эталон нужно верифицировать отдельно.',
        ['Проект', 'Зависимость', 'Уязвимость', 'Эталон', 'OSV-Scanner', 'Grype', 'Примечание'], concise,
    )
    (out / 'evidence-index.json').write_text(json.dumps(diag, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    counts = Counter(r['reference_status'] for r in rows)
    matches = Counter(r['comparison'] for r in rows)
    print(f"Projects: {len(diag)}; inventory rows: {len(rows)}; "
          f"verified: {counts['verified']}; unverified: {counts['candidate_not_independently_verified']}; "
          f"both: {matches['Оба']}; only OSV: {matches['Только OSV']}; "
          f"only Grype: {matches['Только Grype']}")


if __name__ == '__main__':
    main()