"""ML-7: ağaç yorumlayıcısı (tree_model) ve modelin Detector'a bağlanışı."""

import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import detect
from features import FEATURES
from rules import MODEL_ONLY_MAX, Detector, detect as detect_rows
from test_rules import row
from tree_model import TreeModel

CLASSES = ["normal", "port_scan", "brute_force"]


def leaf(value):
    return {"f": [0], "t": [value], "l": [-1], "r": [-1], "d": [0]}


def split(feature, threshold, left_value, right_value, default_left=0):
    """Tek bölmeli ağaç: x[feature] < threshold ise sol yaprak, değilse sağ yaprak."""
    return {"f": [feature, 0, 0], "t": [threshold, left_value, right_value],
            "l": [1, -1, -1], "r": [2, -1, -1], "d": [default_left, 0, 0]}


def toy_model_dict(base=(0.0, 0.0, 0.0)):
    """n_conns >= 50 ise port_scan'e güçlü eğilim; aksi halde normal. brute_force hep düşük."""
    return {
        "classes": CLASSES, "features": FEATURES, "base_margin": list(base),
        "tree_class": [0, 1, 2],
        "trees": [split(0, 50.0, 2.0, -2.0), split(0, 50.0, -2.0, 3.0), leaf(-3.0)],
    }


def toy_model(**kw):
    d = toy_model_dict()
    d.update(kw)
    return TreeModel(d["classes"], d["features"], d["base_margin"], d["trees"], d["tree_class"])


def softmax(vals):
    top = max(vals)
    e = [math.exp(v - top) for v in vals]
    return [v / sum(e) for v in e]


class TreeModelTests(unittest.TestCase):
    def test_probabilities_follow_summed_leaves_and_softmax(self):
        m = toy_model()
        p = m.predict_proba(row(conns=60))
        want = softmax([-2.0, 3.0, -3.0])
        for c, w in zip(CLASSES, want):
            self.assertAlmostEqual(p[c], w, places=6)
        self.assertAlmostEqual(sum(p.values()), 1.0)

    def test_other_side_of_the_split(self):
        p = toy_model().predict_proba(row(conns=5))
        self.assertGreater(p["normal"], 0.95)

    def test_base_margin_is_added_per_class(self):
        m = toy_model(base_margin=[0.0, 1.0, 0.0])
        want = softmax([2.0, -1.0, -3.0])  # conns=5: normal +2, port_scan -2+1
        p = m.predict_proba(row(conns=5))
        self.assertAlmostEqual(p["port_scan"], want[1], places=6)

    def test_value_equal_to_threshold_goes_right(self):
        # XGBoost kuralı "x < eşik" sola gider; eşitlik sağa.
        p = toy_model().predict_proba(row(conns=50))
        self.assertGreater(p["port_scan"], 0.9)

    def test_inputs_are_rounded_to_float32_like_xgboost(self):
        # 49.999999999 çift duyarlıkta 50'den küçük, float32'de 50.0 olur -> sağa gider.
        p = toy_model().predict_proba(row(conns=49.999999999))
        self.assertGreater(p["port_scan"], 0.9)

    def test_missing_value_follows_default_direction(self):
        nan = float("nan")
        left = toy_model(trees=[split(0, 50.0, 2.0, -2.0, default_left=1), split(0, 50.0, -2.0, 3.0, 1), leaf(-3.0)])
        right = toy_model(trees=[split(0, 50.0, 2.0, -2.0, default_left=0), split(0, 50.0, -2.0, 3.0, 0), leaf(-3.0)])
        self.assertGreater(left.predict_proba(row(conns=nan))["normal"], 0.9)
        self.assertGreater(right.predict_proba(row(conns=nan))["port_scan"], 0.9)

    def test_feature_order_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            toy_model(features=list(reversed(FEATURES)))

    def test_tree_class_length_must_match(self):
        with self.assertRaises(ValueError):
            toy_model(tree_class=[0, 1])

    def test_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.json"
            path.write_text(json.dumps(toy_model_dict()), encoding="utf-8")
            m = TreeModel.load(path)
        self.assertEqual(m.classes, CLASSES)
        self.assertGreater(m.predict_proba(row(conns=60))["port_scan"], 0.9)


class ShippedModelTests(unittest.TestCase):
    """Depoyla gelen models/xgb.json gerçekten yüklenir ve akla yatkın karar verir."""

    @classmethod
    def setUpClass(cls):
        cls.model = TreeModel.load(Path(__file__).parent / "models" / "xgb.json")

    def test_loads_with_the_project_classes(self):
        self.assertEqual(self.model.classes, CLASSES)
        self.assertEqual(len(self.model.trees), 600)

    def test_obvious_port_scan_is_port_scan(self):
        p = self.model.predict_proba(row(conns=60, ports=50, fail=1.0, share=0.03))
        self.assertGreater(p["port_scan"], 0.9)

    def test_ordinary_web_browsing_is_normal(self):
        p = self.model.predict_proba(row(conns=3, ports=1, fail=0.0, share=1.0))
        self.assertGreater(p["normal"], 0.9)


def scan_like(start=1000, src="10.0.0.9", **kw):
    """Kuralların tetiklenmediği ama (toy) modelin saldırı gördüğü satır: çok bağlantı, az port."""
    return row(src=src, start=start, conns=60, ports=3, top_port=80, share=0.4, **kw)


class DetectorWithModelTests(unittest.TestCase):
    def test_without_model_behaviour_is_unchanged(self):
        self.assertIsNone(Detector().feed(scan_like()))

    def test_model_only_detection_when_rules_are_silent(self):
        det = Detector(model=toy_model()).feed(scan_like())
        self.assertEqual(det.attack_type, "port_scan")
        self.assertIn("yalnızca model", det.reasons[0])
        self.assertGreater(det.risk_score, 0.5)
        self.assertLess(det.risk_score, MODEL_ONLY_MAX + 1e-9)

    def test_score_grows_with_model_confidence(self):
        weak = toy_model(trees=[split(0, 50.0, 2.0, -2.0), split(0, 50.0, -2.0, 2.5), leaf(-3.0)])
        strong = toy_model(trees=[split(0, 50.0, 2.0, -2.0), split(0, 50.0, -2.0, 6.0), leaf(-3.0)])
        a = Detector(model=weak).feed(scan_like())
        b = Detector(model=strong).feed(scan_like())
        self.assertLess(a.risk_score, b.risk_score)

    def test_model_only_never_reaches_high(self):
        det = Detector(model=toy_model())
        scores = [det.feed(scan_like(start=1000 + 10 * i)).risk_score for i in range(8)]
        self.assertEqual(max(scores), MODEL_ONLY_MAX)
        self.assertLess(MODEL_ONLY_MAX, 0.9)

    def test_persistence_bonus_applies_to_model_hits(self):
        det = Detector(model=toy_model())
        first = det.feed(scan_like(start=1000))
        second = det.feed(scan_like(start=1010))
        self.assertGreater(second.risk_score, first.risk_score)
        self.assertIn("2. pencerede", second.reasons[-1])

    def test_below_threshold_is_not_reported_and_breaks_the_chain(self):
        det = Detector(model=toy_model(), model_threshold=0.999)
        self.assertIsNone(det.feed(scan_like()))
        self.assertNotIn(("10.0.0.9", "model"), det.streaks)

    def test_normal_prediction_gives_no_detection(self):
        self.assertIsNone(Detector(model=toy_model()).feed(row(conns=5)))

    def test_rule_decision_wins_and_model_agreement_is_noted(self):
        r = row(conns=60, ports=40, fail=1.0, share=0.1)
        without = Detector().feed(r)
        with_model = Detector(model=toy_model()).feed(r)
        self.assertEqual(with_model.attack_type, "port_scan")
        self.assertEqual(with_model.risk_score, without.risk_score)  # skor değişmez
        self.assertIn("model de aynı fikirde", with_model.reasons[-1])

    def test_model_disagreement_is_noted_but_rule_still_decides(self):
        # Kurallar brute_force der (SSH'a çok bağlantı), toy model port_scan der.
        r = row(conns=60, ports=2, top_port=22, share=1.0)
        det = Detector(model=toy_model()).feed(r)
        self.assertEqual(det.attack_type, "brute_force")
        self.assertIn("model farklı tür öneriyor: port_scan", det.reasons[-1])

    def test_sources_are_tracked_separately(self):
        det = Detector(model=toy_model())
        det.feed(scan_like(src="10.0.0.1", start=1000))
        other = det.feed(scan_like(src="10.0.0.2", start=1010))
        self.assertNotIn("ısrar", " ".join(other.reasons))

    def test_invalid_threshold_is_rejected(self):
        for bad in (0.0, 1.0, 1.5, -0.1):
            with self.assertRaises(ValueError):
                Detector(model=toy_model(), model_threshold=bad)

    def test_detect_function_passes_the_model_through(self):
        rows = [scan_like(start=1000), scan_like(start=1010)]
        self.assertEqual(detect_rows(rows), [])
        self.assertEqual(len(detect_rows(rows, model=toy_model())), 2)


class DetectCommandModelTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            try:
                code = detect.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_threshold_requires_model(self):
        code, _, err = self.run_main("x.log", "--model-threshold", "0.8")
        self.assertEqual(code, 2)
        self.assertIn("--model", err)

    def test_threshold_must_be_between_zero_and_one(self):
        _, _, err = self.run_main("x.log", "--model", "m.json", "--model-threshold", "1")
        self.assertIn("0 ile 1", err)

    def test_missing_model_file_is_reported(self):
        code, _, err = self.run_main("x.log", "--model", "/yok/model.json")
        self.assertEqual(code, 1)
        self.assertIn("model yüklenemedi", err)

    def test_broken_model_file_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "m.json"
            bad.write_text("{bozuk", encoding="utf-8")
            code, _, err = self.run_main("x.log", "--model", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("model yüklenemedi", err)

    def test_model_flows_into_batch_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "m.json").write_text(json.dumps(toy_model_dict()), encoding="utf-8")
            from test_follow import HEADER, line  # aynı biçimde conn.log satırları
            # 60 bağlantı, hepsi aynı porta (80): kurallar susar, toy model "çok bağlantı = saldırı" der.
            (tmp / "conn.log").write_text(
                HEADER + "".join(line(1000 + i * 0.1, src="10.0.0.9", port=80) for i in range(60)),
                encoding="utf-8")
            plain = self.run_main(str(tmp / "conn.log"), "--no-ssh")
            with_model = self.run_main(str(tmp / "conn.log"), "--no-ssh", "--model", str(tmp / "m.json"))
        self.assertIn("0 tespit", plain[1])
        self.assertIn("1 tespit", with_model[1])
        self.assertIn("yalnızca model", with_model[1])


if __name__ == "__main__":
    unittest.main()
