import csv
import tempfile
import unittest
from pathlib import Path

import baseline
import dataset as ds
import metrics as mt
from lycos_windows import COLUMNS

LABELS = ["normal", "port_scan", "brute_force"]


def row(label, ws, day="Friday", src="10.0.0.1", share=1.0, **kw):
    r = {"day": day, "src_ip": src, "window_start": ws, "n_conns": 1, "n_dst_ports": 1, "n_dst_hosts": 1,
         "fail_ratio": 0.0, "mean_duration": 1.0, "mean_bytes": 100.0, "top_port_share": 1.0,
         "top_port": 80, "top_dst_host": "10.0.0.9", "label": label, "label_share": share, "n_flows": 1}
    r.update(kw)
    return r


class MetricsTests(unittest.TestCase):
    def test_confusion_matrix(self):
        m = mt.confusion_matrix(["a", "a", "b", "b"], ["a", "b", "b", "b"], ["a", "b"])
        self.assertEqual(m, {"a": {"a": 1, "b": 1}, "b": {"a": 0, "b": 2}})

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            mt.confusion_matrix(["a"], [], ["a"])

    def test_precision_recall_f1_by_hand(self):
        # port_scan: TP=3, FN=1 (normal dendi), FP=2 (normal'e port_scan dendi)
        y_true = ["port_scan"] * 4 + ["normal"] * 6
        y_pred = ["port_scan"] * 3 + ["normal"] + ["port_scan"] * 2 + ["normal"] * 4
        res = mt.evaluate(y_true, y_pred, ["normal", "port_scan"])
        ps = res["per_class"]["port_scan"]
        self.assertAlmostEqual(ps["precision"], 3 / 5)
        self.assertAlmostEqual(ps["recall"], 3 / 4)
        self.assertAlmostEqual(ps["f1"], 2 * 0.6 * 0.75 / (0.6 + 0.75))
        self.assertEqual(ps["support"], 4)
        self.assertAlmostEqual(res["fpr"], 2 / 6)
        self.assertAlmostEqual(res["accuracy"], 7 / 10)

    def test_never_predicted_class_has_zero_not_error(self):
        res = mt.evaluate(["a", "b"], ["a", "a"], ["a", "b"])
        self.assertEqual(res["per_class"]["b"]["precision"], 0.0)
        self.assertEqual(res["per_class"]["b"]["f1"], 0.0)

    def test_macro_f1_ignores_classes_without_support(self):
        res = mt.evaluate(["a", "a"], ["a", "a"], ["a", "b"])
        self.assertEqual(res["macro_f1"], 1.0)

    def test_do_nothing_classifier_has_high_accuracy_but_zero_recall(self):
        y_true = ["normal"] * 98 + ["port_scan"] * 2
        res = mt.evaluate(y_true, ["normal"] * 100, ["normal", "port_scan"])
        self.assertAlmostEqual(res["accuracy"], 0.98)
        self.assertEqual(res["per_class"]["port_scan"]["recall"], 0.0)

    def test_format_report_mentions_all_classes(self):
        res = mt.evaluate(["normal", "port_scan"], ["normal", "port_scan"], ["normal", "port_scan"])
        text = mt.format_report(res, ["normal", "port_scan"])
        self.assertIn("macro-F1 1.000", text)
        self.assertIn("port_scan", text)


class SplitTests(unittest.TestCase):
    def test_attack_split_is_chronological_with_gap(self):
        rows = [row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(100)]
        out = ds.assign_split(rows, train_fraction=0.6, gap_seconds=60)
        by = {r["window_start"]: r["split"] for r in out}
        train = [t for t, s in by.items() if s == "train"]
        gap = [t for t, s in by.items() if s == "gap"]
        test = [t for t, s in by.items() if s == "test"]
        self.assertEqual(len(train), 60)
        self.assertEqual(len(gap), 6)       # 60 sn = 6 pencere
        self.assertEqual(len(test), 34)
        self.assertLess(max(train), min(gap))
        self.assertLess(max(gap), min(test))

    def test_no_window_is_lost_or_duplicated(self):
        rows = [row("portscan", 1000 + i * 10) for i in range(50)]
        self.assertEqual(len(ds.assign_split(rows)), 50)

    def test_each_attack_label_is_split_on_its_own_timeline(self):
        rows = ([row("ftp_patator", 100 + i * 10, day="Tuesday") for i in range(50)]
                + [row("ssh_patator", 90000 + i * 10, day="Tuesday") for i in range(50)])
        out = ds.assign_split(rows)
        for label in ("ftp_patator", "ssh_patator"):
            splits = {r["split"] for r in out if r["label"] == label}
            self.assertEqual(splits, {"train", "gap", "test"}, label)

    def test_benign_is_split_per_day(self):
        rows = ([row("benign", 100 + i * 10, day="Monday") for i in range(50)]
                + [row("benign", 90000 + i * 10, day="Tuesday") for i in range(50)])
        out = ds.assign_split(rows)
        for day in ("Monday", "Tuesday"):
            self.assertIn("test", {r["split"] for r in out if r["day"] == day})
            self.assertIn("train", {r["split"] for r in out if r["day"] == day})

    def test_classes_are_mapped_and_brute_force_merges_ftp_ssh(self):
        rows = [row("ftp_patator", 1), row("ssh_patator", 2), row("portscan", 3), row("benign", 4)]
        self.assertEqual({r["label"]: r["cls"] for r in ds.assign_split(rows)},
                         {"ftp_patator": "brute_force", "ssh_patator": "brute_force",
                          "portscan": "port_scan", "benign": "normal"})

    def test_other_labels_and_mixed_windows_are_excluded(self):
        rows = [row("ddos", 1), row("bot", 2), row("portscan", 3, share=0.75), row("portscan", 4)]
        out = {r["window_start"]: r for r in ds.assign_split(rows)}
        for ws in (1, 2, 3):
            self.assertEqual(out[ws]["split"], "excluded")
            self.assertIsNone(out[ws]["cls"])
        self.assertNotEqual(out[4]["split"], "excluded")

    def test_input_rows_are_not_mutated(self):
        rows = [row("portscan", 1)]
        ds.assign_split(rows)
        self.assertNotIn("split", rows[0])

    def test_load_windows_converts_types(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "w.csv"
            with path.open("w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=COLUMNS)
                w.writeheader()
                w.writerow(row("benign", 1499443530))
            r = ds.load_windows(path)[0]
            self.assertEqual(r["window_start"], 1499443530)
            self.assertIsInstance(r["fail_ratio"], float)
            self.assertIsInstance(r["top_port"], int)

    def test_feature_matrix_order_follows_features(self):
        from features import FEATURES
        r = ds.assign_split([row("benign", 1, n_conns=7)])
        X, y = ds.feature_matrix(r)
        self.assertEqual(X[0][FEATURES.index("n_conns")], 7)
        self.assertEqual(y, ["normal"])


class BaselineTests(unittest.TestCase):
    def rows(self):
        scan = row("portscan", 1000, src="172.16.0.1", n_conns=50, n_dst_ports=40, fail_ratio=1.0,
                   top_port=80, top_port_share=0.05)
        brute = row("ssh_patator", 1000, src="172.16.0.2", n_conns=12, top_port=22, top_port_share=1.0)
        quiet = row("benign", 1000, src="192.168.10.9")
        quiet_ssh = row("benign", 1010, src="192.168.10.9", n_conns=3, top_port=22)  # az bağlantı: kural yok
        return [dict(r, cls=ds.CLASS_MAP[r["label"]], split="test") for r in (scan, brute, quiet, quiet_ssh)]

    def test_rules_catch_scan_and_brute_and_leave_normal(self):
        preds = baseline.rule_predictions(self.rows())
        self.assertEqual(preds[("172.16.0.1", 1000)], "port_scan")
        self.assertEqual(preds[("172.16.0.2", 1000)], "brute_force")
        self.assertNotIn(("192.168.10.9", 1000), preds)
        self.assertNotIn(("192.168.10.9", 1010), preds)

    def test_min_score_filters_weak_alerts(self):
        # 12 bağlantı: skor 0,50 + 0,20 x (12-8)/12 ~ 0,57 < 0,7 (ısrar bonusu yok, tek pencere)
        self.assertIn(("172.16.0.2", 1000), baseline.rule_predictions(self.rows(), min_score=0.0))
        self.assertNotIn(("172.16.0.2", 1000), baseline.rule_predictions(self.rows(), min_score=0.7))

    def test_evaluate_rules_perfect_on_toy_data(self):
        res = baseline.evaluate_rules(self.rows(), ("test",))
        self.assertEqual(res["accuracy"], 1.0)
        self.assertEqual(res["fpr"], 0.0)

    def test_evaluate_rules_only_scores_selected_splits(self):
        rows = self.rows()
        rows[0]["split"] = "train"
        res = baseline.evaluate_rules(rows, ("test",))
        self.assertEqual(res["per_class"]["port_scan"]["support"], 0)

    def test_rows_in_any_order_are_fed_chronologically(self):
        # ısrar bonusu zamana göre sıralı beslemeyi ister; ters sırada verilse de aynı sonuç çıkmalı
        brute = [dict(row("ssh_patator", 1000 + i * 10, src="172.16.0.2", n_conns=12, top_port=22),
                      cls="brute_force", split="test") for i in range(5)]
        a = baseline.rule_predictions(brute)
        b = baseline.rule_predictions(list(reversed(brute)))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 5)

    def test_persistence_raises_score_so_min_score_catches_later_windows(self):
        brute = [dict(row("ssh_patator", 1000 + i * 10, src="172.16.0.2", n_conns=12, top_port=22),
                      cls="brute_force", split="test") for i in range(5)]
        strict = baseline.rule_predictions(brute, min_score=0.7)
        self.assertNotIn(("172.16.0.2", 1000), strict)
        self.assertIn(("172.16.0.2", 1040), strict)


if __name__ == "__main__":
    unittest.main()
