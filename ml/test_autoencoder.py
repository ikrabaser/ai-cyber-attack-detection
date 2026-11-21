import unittest

import autoencoder as ae
from features import FEATURES

try:
    import numpy  # noqa: F401
    import sklearn  # noqa: F401
    import xgboost  # noqa: F401
    HAVE_ML = True
except ImportError:  # pragma: no cover
    HAVE_ML = False


def win(ts, label="benign", cls="normal", split="train", share=1.0, **kw):
    base = {"n_conns": 3, "n_dst_ports": 2, "n_dst_hosts": 1, "fail_ratio": 0.0, "mean_duration": 2.0,
            "mean_bytes": 800.0, "top_port_share": 0.6, "top_port": 80}
    base.update(kw)
    return dict(base, src_ip=f"10.0.0.{ts % 50}", window_start=ts, label=label, cls=cls, split=split,
                label_share=share)


def normals(n=300, split="train", start=0):
    # küçük, düzenli bir değişim: gerçek normal trafik gibi tek bir "küme"
    return [win(start + i * 10, split=split, n_conns=2 + i % 4, n_dst_ports=1 + i % 3,
                mean_bytes=700.0 + (i % 7) * 40, mean_duration=1.5 + (i % 5) * 0.3) for i in range(n)]


class SplitAndSetsTests(unittest.TestCase):
    def test_validation_is_the_later_part_of_normals(self):
        fit, val = ae.fit_validation_split(normals(100))
        self.assertEqual((len(fit), len(val)), (80, 20))
        self.assertLess(max(r["window_start"] for r in fit), min(r["window_start"] for r in val))

    def test_attack_sets_rules(self):
        rows = [
            win(1, "portscan", "port_scan", "train"),          # görülen tür, eğitim bölmesi: girmez
            win(2, "portscan", "port_scan", "test"),           # görülen tür, test: girer
            win(3, "ddos", None, "excluded"),                  # görülmeyen tür: tümü girer
            win(4, "ddos", None, "excluded", share=0.5),       # karışık pencere: girmez
            win(5, "benign", "normal", "test"),                # normal: girmez
        ]
        sets = ae.attack_sets(rows)
        self.assertEqual({k: len(v) for k, v in sets.items()}, {"portscan": 1, "ddos": 1})


@unittest.skipUnless(HAVE_ML, "numpy/scikit-learn gerekli")
class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fit, cls.val = ae.fit_validation_split(normals(400))
        cls.model = ae.train(fit, seed=0)

    def test_scaler_uses_only_the_given_rows_and_logs_heavy_tails(self):
        sc = ae.Scaler(normals(50))
        z = sc.transform(normals(50))
        self.assertEqual(z.shape, (50, len(FEATURES)))
        self.assertAlmostEqual(float(z.mean()), 0.0, places=6)

    def test_flood_scores_much_higher_than_normal(self):
        flood = [win(i, "ddos", None, "excluded", n_conns=900, n_dst_ports=1, mean_bytes=40.0,
                     mean_duration=0.01, top_port_share=1.0) for i in range(20)]
        normal_err = ae.errors(self.model, normals(100, "test", start=9000))
        flood_err = ae.errors(self.model, flood)
        self.assertGreater(ae.auc(normal_err, flood_err), 0.99)
        thr = ae.threshold(ae.errors(self.model, self.val), 0.99)
        self.assertGreater((flood_err > thr).mean(), 0.9)

    def test_threshold_controls_false_alarms_on_similar_normals(self):
        thr = ae.threshold(ae.errors(self.model, self.val), 0.99)
        fpr = (ae.errors(self.model, normals(300, "test", start=20000)) > thr).mean()
        self.assertLess(fpr, 0.05)

    def test_same_seed_is_reproducible(self):
        fit, _ = ae.fit_validation_split(normals(120))
        a = ae.errors(ae.train(fit, 3), fit[:5])
        b = ae.errors(ae.train(fit, 3), fit[:5])
        self.assertTrue((a == b).all())

    def test_empty_rows_give_empty_errors(self):
        self.assertEqual(len(ae.errors(self.model, [])), 0)

    def test_run_end_to_end_on_toy_rows(self):
        rows = normals(300) + normals(100, "test", start=5000)
        # XGBoost karşılaştırması üç sınıf da ister: oyuncak tarama ve kaba kuvvet eğitim pencereleri
        rows += [win(9000 + i, "portscan", "port_scan", "train", n_conns=60, n_dst_ports=60, fail_ratio=1.0,
                     top_port_share=0.02) for i in range(20)]
        rows += [win(9500 + i, "ssh_patator", "brute_force", "train", n_conns=80, n_dst_ports=1, top_port=22)
                 for i in range(20)]
        rows += [win(7000 + i, "ddos", None, "excluded", n_conns=800, mean_bytes=40.0) for i in range(15)]
        rep = ae.run(rows, seeds=(0, 1))
        self.assertEqual(rep["counts"]["attacks"], {"ddos": 15})
        self.assertGreater(rep["ae"]["auc"]["ddos"]["mean"], 0.99)
        self.assertGreater(rep["volume"][0.99]["recall"]["ddos"], 0.9)
        self.assertIn("ddos", ae.format_report(rep))


class SummaryTests(unittest.TestCase):
    def test_summarize_gives_mean_min_max(self):
        per = [{"fpr": {0.99: 0.01, 0.999: 0.001}, "recall": {0.99: {"x": 0.5}, 0.999: {"x": 0.1}}, "auc": {"x": 0.9}},
               {"fpr": {0.99: 0.03, 0.999: 0.003}, "recall": {0.99: {"x": 0.7}, 0.999: {"x": 0.3}}, "auc": {"x": 0.7}}]
        s = ae.summarize(per)
        self.assertAlmostEqual(s["auc"]["x"]["mean"], 0.8)
        self.assertEqual((s["auc"]["x"]["min"], s["auc"]["x"]["max"]), (0.7, 0.9))
        self.assertAlmostEqual(s["fpr"][0.99]["mean"], 0.02)


if __name__ == "__main__":
    unittest.main()
