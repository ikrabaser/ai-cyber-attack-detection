import unittest
from pathlib import Path

import _sensor  # noqa: F401
import lab_eval as le
from features import extract
from zeek_reader import read_log

SAMPLE = Path(__file__).resolve().parent.parent / "sensor" / "sample" / "conn.log"
ATT, NORM = "192.168.56.200", "192.168.56.50"


def run(run_id, label, src, start, end):
    return {"run_id": run_id, "label": label, "scenario": "s", "src_ip": src, "dst_ip": "192.168.56.20",
            "start": start, "end": end}


RUNS = [
    run("scan", "port_scan", ATT, 1794301259.5, 1794301262.5),
    run("brute", "brute_force", ATT, 1794301289.0, 1794301352.0),
    run("norm", "normal", NORM, 1794301200.0, 1794301380.0),
]


class AlwaysNormal:
    def predict_proba(self, X):
        import numpy as np
        return np.array([[1.0, 0.0, 0.0]] * len(X))


class LabEvalTests(unittest.TestCase):
    def setUp(self):
        self.rows = le.label_rows(extract(list(read_log(SAMPLE))), RUNS)

    def test_rows_get_labels_and_classes(self):
        self.assertTrue(any(r["cls"] == "brute_force" for r in self.rows))
        self.assertTrue(all((r["cls"] is None) == (r["label"] == "unknown") for r in self.rows))

    def test_rule_calls_without_ssh_ignore_failed_auth(self):
        rows = [dict(r, ssh_failed_auth=50) for r in self.rows]
        self.assertTrue(set(le.rule_calls(rows, False)) <= set(le.rule_calls(rows, True)))

    def test_evaluate_scores_only_whole_known_windows(self):
        calls = {"rules": le.rule_calls(self.rows)}
        res = le.evaluate_lab(self.rows, calls)["rules"]
        scored = [r for r in self.rows if r["cls"] and not r["boundary"]]
        self.assertEqual(sum(sum(row.values()) for row in res["matrix"].values()), len(scored))

    def test_always_normal_model_catches_nothing(self):
        import numpy  # noqa: F401  (xgboost yoksa bile numpy var)
        scored = [r for r in self.rows if r["cls"]]
        calls = {"m": le.model_calls(AlwaysNormal(), scored)}
        res = le.evaluate_lab(self.rows, calls)["m"]
        for c in ("port_scan", "brute_force"):
            self.assertEqual(res["per_class"][c]["recall"], 0.0)

    def test_macro_f1_ignores_classes_without_samples(self):
        calls = {"rules": le.rule_calls(self.rows)}
        res = le.evaluate_lab(self.rows, calls)["rules"]
        self.assertEqual(res["per_class"]["port_scan"]["support"], 0)  # örnekte tarama pencereleri yarım
        self.assertAlmostEqual(res["macro_f1"], 1.0)

    def test_per_run_and_outside(self):
        calls = {"rules": le.rule_calls(self.rows)}
        table = le.per_run(self.rows, calls)
        self.assertEqual({t["run_id"] for t in table}, {"scan", "brute", "norm"})
        for t in table:
            self.assertLessEqual(t["hit"]["rules"], t["windows"])
        out = le.outside_runs(self.rows, calls)
        self.assertEqual(out["windows"], sum(1 for r in self.rows if r["label"] == "unknown"))

    def test_format_runs(self):
        calls = {"xgb": le.model_calls(AlwaysNormal(), [r for r in self.rows if r["cls"]]),
                 "rules_nossh": le.rule_calls(self.rows, False)}
        res = le.evaluate_lab(self.rows, calls)
        text = le.format_lab(self.rows, res, le.per_run(self.rows, calls), le.outside_runs(self.rows, calls))
        self.assertIn("XGBoost", text)
        self.assertIn("koşu başına", text)


if __name__ == "__main__":
    unittest.main()
