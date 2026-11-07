import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_full_sca_table as full


class FullInventoryTests(unittest.TestCase):
    def test_normalize_maven_and_go(self):
        self.assertEqual(full.component_key("org.apache.commons:commons-lang3", "3.12.0", "Maven"),
                         full.component_key("commons-lang3", "3.12.0", "java-archive"))
        self.assertEqual(full.component_key("github.com/demo/pkg", "v1.2.3", "go-module"),
                         full.component_key("github.com/demo/pkg", "1.2.3", "Go"))

    def test_union_of_aliases(self):
        records = [
            {"source": "osv", "package": "alpha", "version": "1.0", "ecosystem": "npm",
             "ids": {"cve-2026-1000", "ghsa-xxxx-yyyy-zzzz"}},
            {"source": "grype", "package": "alpha", "version": "1.0", "ecosystem": "npm",
             "ids": {"ghsa-xxxx-yyyy-zzzz"}},
            {"source": "osv", "package": "alpha", "version": "1.0", "ecosystem": "npm",
             "ids": {"cve-2026-2000"}},
        ]
        self.assertEqual(2, len(full.group_records(records)))

    def test_full_inventory_includes_all_and_reference_misses(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "raw" / "artifact" / "project"
            for name in ["osv", "grype"]:
                (source / name).mkdir(parents=True)
            (source / "project.json").write_text(json.dumps({"project_id": "P001", "name": "project"}))
            (source / "osv" / "exit-code.txt").write_text("1")
            (source / "grype" / "exit-code.txt").write_text("0")
            packages = [
                {"package": {"name": "alpha", "version": "1.0", "ecosystem": "npm"},
                 "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-1000"]}]},
                {"package": {"name": "beta", "version": "2.0", "ecosystem": "npm"},
                 "vulnerabilities": [{"id": "GHSA-dddd-eeee-ffff"}]},
            ]
            (source / "osv" / "result.json").write_text(json.dumps({"results": [{"packages": packages}]}))
            (source / "grype" / "result.json").write_text(json.dumps({"matches": [
                {"artifact": {"name": "alpha", "version": "1.0", "type": "npm"},
                 "vulnerability": {"id": "CVE-2026-1000"}}
            ]}))
            manifest = {"projects": [
                {"id": "P001", "name": "project", "repo": "x/project", "ref": "a"*40},
                {"id": "P002", "name": "empty", "repo": "x/empty", "ref": "b"*40},
            ]}
            truth = [{"project_id": "P001", "package": "gamma", "version": "3.0",
                      "ecosystem": "npm", "vulnerability_ids": "CVE-2026-3000",
                      "status": "verified", "evidence_url": "https://example.com", "notes": "manual"}]
            rows, diagnostics = full.inventory(manifest, truth, root/"raw")
            a = [r for r in rows if r["project_id"] == "P001"]
            self.assertEqual(3, len(a))
            self.assertEqual("Оба", next(r for r in a if r["package"] == "alpha")["comparison"])
            self.assertEqual("Только OSV", next(r for r in a if r["package"] == "beta")["comparison"])
            missed = next(r for r in a if r["package"] == "gamma")
            self.assertEqual("verified", missed["reference_status"])
            self.assertEqual("Не найдено", missed["osv_status"])
            self.assertEqual("Не найдено", missed["grype_status"])
            empty = next(r for r in rows if r["project_id"] == "P002")
            self.assertEqual("no_reference_and_no_observations", empty["reference_status"])
            self.assertEqual("Не оценивалось (missing_artifact)", empty["grype_status"])

    def test_csv_markdown_single_table(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "manifest.json").write_text(json.dumps({"projects": [
                {"id": "P001", "name": "empty", "repo": "test/empty", "ref": "a" * 40}]}))
            (base / "gt.csv").write_text("project_id,package,version,ecosystem,vulnerability_ids,status,evidence_url,notes\n")
            subprocess.run([sys.executable, str(ROOT/"scripts/build_full_sca_table.py"),
                "--results-dir", str(base/"none"), "--manifest", str(base/"manifest.json"),
                "--ground-truth", str(base/"gt.csv"), "--output-dir", str(base/"comparison")],
                check=True, capture_output=True)
            self.assertEqual(["sca-comparison.csv"], sorted(p.name for p in (base/"comparison").glob("*.csv")))
            self.assertEqual(["sca-comparison.md"], sorted(p.name for p in (base/"comparison").glob("*.md")))
            with (base/"comparison/sca-comparison.csv").open(newline="") as file:
                self.assertEqual(1, len(list(csv.DictReader(file))))


if __name__ == "__main__":
    unittest.main()
