import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_sca_table as bench


class FindingTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"package":"minimist","version":"0.0.8","ecosystem":"npm","vulnerability_ids":"GHSA-xvch-5gv4-984h;CVE-2021-44906"}
        self.grype = {"matches":[{"artifact":{"name":"minimist","version":"0.0.8","type":"npm","locations":[{"path":"/package-lock.json"}]},"vulnerability":{"id":"GHSA-xvch-5gv4-984h"},"relatedVulnerabilities":[{"id":"CVE-2021-44906"}]}]}
        self.osv = {"results":[{"source":{"path":"package-lock.json"},"packages":[{"package":{"name":"minimist","version":"0.0.8","ecosystem":"npm"},"groups":[{"ids":["GHSA-xvch-5gv4-984h"],"aliases":["CVE-2021-44906"]}],"vulnerabilities":[{"id":"GHSA-xvch-5gv4-984h"}]}]}]}

    def test_osv_alias_and_grype_related(self):
        for report, parse in [(self.osv, bench.osv_findings),(self.grype, bench.grype_findings)]:
            findings = parse(report)
            self.assertIn('cve-2021-44906', findings[0]['ids'])
            self.assertEqual('Найдено полностью', bench.assess(self.expected, findings)[0])

    def test_wrong_advisory_is_not_full_match(self):
        other = bench.finding('minimist','0.0.8','npm',['CVE-1234-9999'])
        result, note = bench.assess(self.expected,[other])
        self.assertEqual(result, 'Частично')
        self.assertIn('ожидаемый advisory отсутствует',note)

    def test_wrong_version_is_partial(self):
        other = bench.finding('minimist','1.0.0','npm',['CVE-2021-44906'])
        self.assertEqual('Частично',bench.assess(self.expected,[other])[0])

    def test_failed_and_missing_not_false_negatives(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            self.assertEqual('not_run',bench.scan_info(root,'osv')['state'])
            (root/'osv').mkdir()
            (root/'osv/exit-code.txt').write_text('137\n')
            (root/'osv/result.json').write_text('{"results":[]}')
            self.assertEqual('failed',bench.scan_info(root,'osv')['state'])
            self.assertEqual('Не оценивалось',bench.assess(self.expected,[],"failed")[0])

    def test_valid_empty_report(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/'grype').mkdir()
            (root/'grype/exit-code.txt').write_text('0\n')
            (root/'grype/result.json').write_text('{"matches": []}')
            self.assertEqual('ok', bench.scan_info(root,'grype')['state'])
            self.assertEqual('Не найдено',bench.assess(self.expected,[])[0])

    def test_alias_dedup_and_disparities(self):
        a = [bench.finding('x','1','npm',['CVE-2025-1234','GHSA-aaaa-bbbb-cccc'])]
        b = [bench.finding('x','1','npm',['GHSA-aaaa-bbbb-cccc'])]
        self.assertEqual('Оба',bench.disparities(a,b)[0][2])
        self.assertEqual(1,len(bench.aggregate(a+b)))

    def test_end_to_end_all_manifest_projects_even_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base/'manifest.json').write_text(json.dumps({'projects':[{'id':'P001','name':'sample','repo':'test/sample'},{'id':'P002','name':'missing','repo':'test/none'}]}))
            (base/'gt.csv').write_text('project_id,package,version,ecosystem,vulnerability_ids,status,evidence_url,notes\nP001,minimist,0.0.8,npm,CVE-2021-44906,verified,,\n')
            root=base/'raw/application/sample'
            (root/'osv').mkdir(parents=True)
            (root/'grype').mkdir()
            (root/'project.json').write_text(json.dumps({'project_id':'P001','name':'sample','repository':'test/sample'}))
            (root/'osv/result.json').write_text(json.dumps(self.osv))
            (root/'osv/exit-code.txt').write_text('1')
            (root/'grype/result.json').write_text(json.dumps(self.grype))
            (root/'grype/exit-code.txt').write_text('0')
            subprocess.run([sys.executable,str(ROOT/'scripts/build_sca_table.py'),'--results-dir',str(base/'raw'),'--manifest',str(base/'manifest.json'),'--ground-truth',str(base/'gt.csv'),'--output-dir',str(base/'out')],check=True,capture_output=True)
            for i in range(1,5):
                self.assertTrue(list((base/'out').glob(f'0{i}*.csv')))
            with (base/'out/02-project-summary.csv').open() as f:
                rows=list(csv.DictReader(f))
            self.assertEqual(2,len(rows))
            self.assertEqual('missing_artifact',rows[1]['osv_scan'])


if __name__ == '__main__':
    unittest.main()