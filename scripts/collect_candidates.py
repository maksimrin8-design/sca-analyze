#!/usr/bin/env python3
"""Non-authoritative leads for *independent* ground-truth verification.

Never label candidate rows as verified simply because either scanner reported them.
"""
import argparse
import csv
import json
from pathlib import Path

from build_sca_table import aggregate, osv_findings, grype_findings, primary_id, read_json


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--results-dir', required=True)
    p.add_argument('--manifest', required=True)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    projects = read_json(Path(args.manifest))['projects']
    roots = {}
    for f in Path(args.results_dir).rglob('project.json'):
        meta = read_json(f) or {}
        roots[meta.get('project_id')] = f.parent
    rows = []
    for project in projects:
        root = roots.get(project['id'])
        if root is None:
            rows.append({'project_id':project['id'], 'project':project['name'], 'status':'no_evidence', 'notes':'Missing scan artifact; review manually'})
            continue
        osv = read_json(root/'osv'/'result.json') or {}
        grype = read_json(root/'grype'/'result.json') or {}
        # Only show leads present in both scanners first; this is *not* independent proof.
        a, b = aggregate(osv_findings(osv)), aggregate(grype_findings(grype))
        proposals = []
        for x in a:
            if any(x['package'] == y['package'] and x['version'] == y['version'] and x['ids'] & y['ids'] for y in b):
                proposals.append(x)
        if not proposals:
            proposals = a or b
        if not proposals:
            rows.append({'project_id':project['id'], 'project':project['name'], 'status':'no_candidate', 'notes':'No detected vulnerability or scanner output unavailable; this is NOT a clean bill of health'})
            continue
        x = next((t for t in proposals if any(i.startswith('ghsa-') for i in t['ids'])), proposals[0])
        ids = x['ids']
        ghsa = next((i for i in sorted(ids) if i.startswith('ghsa-')), '')
        advisory = 'https://github.com/advisories/'+ghsa.upper() if ghsa else 'https://osv.dev/vulnerability/'+primary_id(ids)
        source_path = next((s for s in sorted(x['sources']) if 'target-repo/' in s), '')
        source_path = source_path.split('target-repo/',1)[-1]
        dependency = f"https://github.com/{project['repo']}/blob/{project['ref']}/{source_path}" if source_path else ''
        rows.append({'project_id':project['id'], 'project':project['name'], 'package':x['package'], 'version':x['version'], 'ecosystem':x['ecosystem'], 'vulnerability_ids':';'.join(sorted(ids)), 'status':'candidate', 'advisory_url':advisory, 'dependency_url':dependency, 'notes':'UNVERIFIED lead from scan results; independently check dependency version and advisory affected range before promoting to verified'})
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    columns = ['project_id','project','package','version','ecosystem','vulnerability_ids','status','advisory_url','dependency_url','notes']
    with output.open('w', newline='', encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    print(f'Ground truth candidates: {len(rows)} (NOT verified).')


if __name__=='__main__':
    main()