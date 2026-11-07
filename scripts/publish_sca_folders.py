#!/usr/bin/env python3
"""Publish 30 application/<name>/{osv,grype,default} directories from scan artifacts.

IMPORTANT: The 'default' list is a union of two scanners, NOT independent truth.
Do not use it to claim independent precision or recall of either scanner.
"""
from __future__ import annotations
import argparse
import csv
import json
import shutil
from pathlib import Path
from collections import Counter, defaultdict

from build_full_sca_table import inventory, read_csv, read_json

SOURCE_RUN = 'https://github.com/maksimrin8-design/sca-analyze/actions/runs/42363667019'


def dump_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def dump_csv(path, columns, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(values)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True)
    p.add_argument('--ground-truth', required=True)
    p.add_argument('--results-dir', required=True)
    p.add_argument('--output-dir', required=True)
    p.add_argument('--source-run', default=SOURCE_RUN)
    a = p.parse_args()
    manifest = read_json(Path(a.manifest))
    truth = read_csv(Path(a.ground_truth))
    source = Path(a.results_dir)
    dest = Path(a.output_dir)
    rows, diagnostics = inventory(manifest, truth, source)
    by_project = defaultdict(list)
    for row in rows:
        by_project[row['project_id']].append(row)
    scan_roots = {}
    for project_json in source.rglob('project.json'):
        project = read_json(project_json) or {}
        if project.get('project_id'):
            scan_roots[project['project_id']] = project_json.parent
    diag = {d['project_id']: d for d in diagnostics}
    expected = manifest['projects']
    assert len(expected) == 30, f'Expected 30 projects; have {len(expected)}'
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    index = []
    totals = Counter()
    for project in expected:
        pid, name = project['id'], project['name']
        upstream = scan_roots.get(pid)
        if upstream is None:
            raise RuntimeError('Missing scan artifacts for ' + pid)
        record = diag[pid]
        if not all(record['scans'][t] == 'ok' for t in ('osv', 'grype')):
            raise RuntimeError('Scanner failure: ' + pid + ' ' + str(record['scans']))
        root = dest / name
        combined = [r for r in by_project[pid] if r.get('vulnerability_id')]
        # Normalized union of scanner observations, plus independent verified entries if any.
        normalized = []
        for r in combined:
            by = []
            if r['osv_status'] == 'Найдено': by.append('osv')
            if r['grype_status'] == 'Найдено': by.append('grype')
            normalized.append({
                'package': r['package'], 'installed_version': r['version'],
                'ecosystem': r['ecosystem'], 'vulnerability_id': r['vulnerability_id'],
                'all_identifiers': r['all_identifiers'],
                'detected_by': by,
                'osv_status': r['osv_status'], 'grype_status': r['grype_status'],
                'reference_status': ('independently_verified_example'
                                     if r['reference_status'] == 'verified'
                                     else 'provisional_scanner_union'),
                'advisory_url': r['advisory_url'],
                'verified_evidence_url': r['reference_evidence'],
                'osv_source': r['osv_source'], 'grype_source': r['grype_source'],
                'notes': r['explanation'],
            })
        count = Counter()
        for item in normalized:
            if len(item['detected_by']) == 2: count['both'] += 1
            elif item['detected_by'] == ['osv']: count['only_osv'] += 1
            elif item['detected_by'] == ['grype']: count['only_grype'] += 1
            else: count['missed_both_verified'] += 1
            if item['reference_status'] == 'independently_verified_example':
                count['verified'] += 1
        count['total'] = len(normalized)
        count['osv'] = count['both'] + count['only_osv']
        count['grype'] = count['both'] + count['only_grype']
        assert count['total'] == sum(count[k] for k in ('both','only_osv','only_grype','missed_both_verified'))
        totals.update(count)
        for scanner in ('osv','grype'):
            src = upstream/scanner
            target = root/scanner
            target.mkdir(parents=True, exist_ok=True)
            for filename in ('result.json', 'exit-code.txt', 'version.txt', 'stderr.log'):
                f = src/filename
                if f.is_file():
                    shutil.copy2(f, target/filename)
            found = [x for x in normalized if scanner in x['detected_by']]
            assert len(found) == count[scanner], (pid, scanner)
            dump_json(target/'findings.json', {
                'project_id': pid, 'project': name, 'scanner': scanner,
                'source_run': a.source_run, 'scan_status': 'ok',
                'count': len(found), 'normalized_findings': found,
                'raw_json': 'result.json',
                'note': 'Original scanner JSON is in result.json; normalized CVE/GHSA aliases are grouped in findings.json',
            })
        default = root/'default'
        dump_json(default/'reference.json', {
            'project_id': pid, 'project': name, 'repository': project['repo'],
            'source_commit': project['ref'], 'source_run': a.source_run,
            'reference_type': 'union_of_OSV_and_Grype_findings',
            'is_independent_ground_truth': False,
            'warning': ('Составной предварительный эталон. Список образован объединением двух сканеров, '
                        'поэтому не включает неизвестные находки, пропущенные ОБОИМИ. '
                        'Без внешней проверки не годится для объективного precision/recall.'),
            'counts': dict(count), 'vulnerabilities': normalized,
        })
        dump_csv(default/'reference.csv',
            ['package','installed_version','ecosystem','vulnerability_id','all_identifiers',
             'detected_by','osv_status','grype_status','reference_status','advisory_url',
             'verified_evidence_url','osv_source','grype_source','notes'],
            [{**x, 'detected_by': ';'.join(x['detected_by'])} for x in normalized])
        dump_json(root/'project.json', {
            'project_id': pid, 'name': name, 'repository': project['repo'],
            'commit': project['ref'], 'source_run': a.source_run, 'counts': dict(count),
            'directories': ['osv','grype','default'],
        })
        index.append({
            'ID':pid, 'Приложение':name, 'Репозиторий':project['repo'],
            'Экосистема':project.get('ecosystem',''),
            'Объединённый список':count['total'], 'OSV-Scanner':count['osv'],
            'Grype':count['grype'], 'Оба':count['both'],
            'Только OSV':count['only_osv'], 'Только Grype':count['only_grype'],
            'Проверено независимо':count['verified'],
            'Каталог':name,
        })
    assert len(index) == 30
    dump_csv(dest/'INDEX.csv',list(index[0]),index)
    readme = f'''# SCA — 30 приложений / 3 папки для каждого

Этот каталог содержит **30 подпапок с именами приложений**. В каждой ровно три
подпапки `osv/`, `grype/`, `default/` и файл `project.json`.

- `osv/result.json` — исходный отчёт OSV-Scanner; `osv/findings.json` — нормализованные записи.
- `grype/result.json` — исходный отчёт Grype; `grype/findings.json` — нормализованные записи.
- `default/reference.json` и `default/reference.csv` — объединённый список находок двух сканеров.

**Составной эталон не является независимым ground truth.** Он включает находки
OSV и Grype вместе, CVE/GHSA-алиасы объединены, повторы удалены. Он не содержит
уязвимостей, которые пропустили **оба** инструмента, если только такая запись
не была дополнительно подтверждена вручную. Поля `reference_status` и
`detected_by` показывают источник каждой записи. Такой эталон нельзя использовать
для объективной оценки precision/recall этих двух инструментов без внешней проверки.

Список 30 приложений и числа находок: [`INDEX.csv`](INDEX.csv).

Источник: [{a.source_run}]({a.source_run}).

Итоги: приложений **30**, кандидатных записей **{totals['total']}**,
OSV **{totals['osv']}**, Grype **{totals['grype']}**,
оба инструмента **{totals['both']}**, только OSV **{totals['only_osv']}**,
только Grype **{totals['only_grype']}**,
независимо подтверждённых записей **{totals['verified']}**.
'''
    (dest/'README.md').write_text(readme,encoding='utf-8')
    print('Published:', len(index), 'apps,', dict(totals))


if __name__ == '__main__':
    main()