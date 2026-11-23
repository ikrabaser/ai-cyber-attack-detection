import json
import tempfile
import unittest
from pathlib import Path

import export_report

CSV = Path(__file__).resolve().parent / "data" / "windows_lycos.csv"


@unittest.skipUnless(CSV.exists(), "windows_lycos.csv yok")
class ExtrasOnlyTests(unittest.TestCase):
    """--extras-only: mevcut rapora yalnızca H1, etiket gürültüsü ve xgboost sürümü eklenir."""

    def test_extras_only_keeps_every_other_section_untouched(self):
        existing = {"generated": "2000-01-01", "xgb": {"macro_f1": 0.5}, "lab": {"runs": 1}, "autoencoder": {"seeds": 5}}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            out.write_text(json.dumps(existing), encoding="utf-8")
            export_report.main([str(CSV), "--out", str(out), "--extras-only"])
            report = json.loads(out.read_text(encoding="utf-8"))
        for key, value in existing.items():
            self.assertEqual(report[key], value, key)
        self.assertIn("equal_fpr", report)
        self.assertIn("label_noise", report)
        self.assertRegex(report["xgboost_version"], r"^\d+\.\d+")
        self.assertEqual(set(report["equal_fpr"]["variants"]), {"all", "clean"})
        self.assertGreater(report["label_noise"]["profile"]["suspects"], 0)

    def test_extras_only_needs_an_existing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                export_report.main([str(CSV), "--out", str(Path(tmp) / "yok.json"), "--extras-only"])


if __name__ == "__main__":
    unittest.main()
