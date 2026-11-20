import tempfile
import unittest
from pathlib import Path

import dataset as ds
import train_xgb as tx
from features import FEATURES

try:
    import xgboost  # noqa: F401
    import sklearn  # noqa: F401
    HAVE_ML = True
except ImportError:  # pragma: no cover
    HAVE_ML = False

FAST = dict(tx.PARAMS, n_estimators=20)


def row(cls, **kw):
    base = {"n_conns": 1, "n_dst_ports": 1, "n_dst_hosts": 1, "fail_ratio": 0.0, "mean_duration": 1.0,
            "mean_bytes": 100.0, "top_port_share": 1.0}
    base.update(kw)
    return dict(base, cls=cls, split="train")


def toy_rows(n=40):
    """Ayrışabilir oyuncak veri: tarama = çok port + hep başarısız, brute = çok bağlantı + tek port."""
    rows = []
    for i in range(n):
        rows.append(row("normal", n_conns=1 + i % 3, mean_bytes=500.0 + i))
        rows.append(row("port_scan", n_conns=40 + i, n_dst_ports=30 + i, fail_ratio=1.0, top_port_share=0.05,
                        mean_bytes=0.0))
        rows.append(row("brute_force", n_conns=12 + i % 5, mean_duration=5.0, mean_bytes=300.0))
    return rows


class WeightTests(unittest.TestCase):
    def test_balanced_weights_equalise_class_totals(self):
        y = ["normal"] * 90 + ["port_scan"] * 10
        w = tx.balanced_weights(y)
        total = {"normal": 0.0, "port_scan": 0.0}
        for c, wi in zip(y, w):
            total[c] += wi
        self.assertAlmostEqual(total["normal"], total["port_scan"])

    def test_rare_class_gets_larger_weight(self):
        w = tx.balanced_weights(["normal"] * 99 + ["port_scan"])
        self.assertGreater(w[-1], w[0] * 50)

    def test_weights_sum_to_sample_count(self):
        y = ["a"] * 7 + ["b"] * 3
        self.assertAlmostEqual(sum(tx.balanced_weights(y)), len(y))

    def test_encode_follows_classes_order(self):
        self.assertEqual(tx.encode(["port_scan", "normal", "brute_force"]), [1, 0, 2])


@unittest.skipUnless(HAVE_ML, "xgboost / scikit-learn yok")
class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = toy_rows()
        cls.model = tx.train(cls.rows, FAST)

    def test_learns_separable_toy_data(self):
        self.assertEqual(tx.predict(self.model, self.rows), [r["cls"] for r in self.rows])

    def test_probabilities_have_one_column_per_class_and_sum_to_one(self):
        p = tx.predict_proba(self.model, self.rows[:5])
        self.assertEqual(p.shape, (5, len(ds.CLASSES)))
        for line in p:
            self.assertAlmostEqual(float(line.sum()), 1.0, places=4)

    def test_evaluate_model_reports_pr_auc_for_each_class(self):
        res = tx.evaluate_model(self.model, self.rows)
        self.assertEqual(res["macro_f1"], 1.0)
        self.assertEqual(set(res["pr_auc"]), set(ds.CLASSES))
        for v in res["pr_auc"].values():
            self.assertAlmostEqual(v, 1.0, places=3)

    def test_importances_cover_all_features_and_sum_to_one(self):
        imp = tx.importances(self.model)
        self.assertEqual({n for n, _ in imp}, set(FEATURES))
        self.assertAlmostEqual(sum(v for _, v in imp), 1.0, places=4)
        self.assertEqual([v for _, v in imp], sorted((v for _, v in imp), reverse=True))

    def test_same_seed_gives_same_predictions(self):
        again = tx.train(self.rows, FAST)
        self.assertEqual(tx.predict_proba(self.model, self.rows[:20]).tolist(),
                         tx.predict_proba(again, self.rows[:20]).tolist())

    def test_save_and_load_roundtrip(self):
        from xgboost import XGBClassifier
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "m.json"
            self.model.save_model(path)
            loaded = XGBClassifier()
            loaded.load_model(path)
            self.assertEqual(tx.predict(loaded, self.rows), tx.predict(self.model, self.rows))

    def test_model_input_is_exactly_the_sensor_features(self):
        X, _ = ds.feature_matrix(self.rows[:1])
        self.assertEqual(len(X[0]), len(FEATURES))
        self.assertEqual(self.model.n_features_in_, len(FEATURES))


if __name__ == "__main__":
    unittest.main()
