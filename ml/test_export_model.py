"""export_model.py + sensor/tree_model.py: XGBoost'suz yorumlayıcı, XGBoost ile aynı olasılıkları vermeli."""

import json
import tempfile
import unittest
from pathlib import Path

import _sensor  # noqa: F401
import export_model as em
import train_xgb as tx
from dataset import CLASSES, feature_matrix
from test_train_xgb import FAST, HAVE_ML, toy_rows
from tree_model import TreeModel


@unittest.skipUnless(HAVE_ML, "xgboost / scikit-learn yok")
class ExportedModelMatchesXGBoostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = toy_rows()
        cls.xgb = tx.train(cls.rows, FAST)
        cls.tmp = tempfile.TemporaryDirectory()
        src = Path(cls.tmp.name) / "xgb.json"
        cls.xgb.save_model(str(src))
        cls.out = em.convert(json.loads(src.read_text(encoding="utf-8")))
        cls.pure = TreeModel(cls.out["classes"], cls.out["features"], cls.out["base_margin"],
                             cls.out["trees"], cls.out["tree_class"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_probabilities_match_xgboost(self):
        X, _ = feature_matrix(self.rows)
        ref = self.xgb.predict_proba(X)
        for row, want in zip(self.rows, ref):
            got = self.pure.predict_proba(row)
            for i, c in enumerate(CLASSES):
                self.assertAlmostEqual(got[c], float(want[i]), places=5)

    def test_predicted_classes_match(self):
        X, _ = feature_matrix(self.rows)
        ref = [CLASSES[i] for i in self.xgb.predict_proba(X).argmax(axis=1)]
        got = [max(p, key=p.get) for p in (self.pure.predict_proba(r) for r in self.rows)]
        self.assertEqual(got, ref)

    def test_export_keeps_class_and_tree_layout(self):
        self.assertEqual(self.out["classes"], CLASSES)
        self.assertEqual(len(self.out["trees"]), FAST["n_estimators"] * len(CLASSES))
        self.assertEqual(self.out["tree_class"][:6], [0, 1, 2, 0, 1, 2])

    def test_main_writes_loadable_file(self):
        src = Path(self.tmp.name) / "xgb2.json"
        dst = Path(self.tmp.name) / "compact.json"
        self.xgb.save_model(str(src))
        self.assertEqual(em.main([str(src), str(dst)]), 0)
        loaded = TreeModel.load(dst)
        self.assertEqual(loaded.classes, CLASSES)
        self.assertLess(dst.stat().st_size, src.stat().st_size)


class ConvertGuardTests(unittest.TestCase):
    def test_non_softprob_objective_is_rejected(self):
        bad = {"learner": {"objective": {"name": "binary:logistic"}, "learner_model_param": {}}}
        with self.assertRaises(ValueError):
            em.convert(bad)


if __name__ == "__main__":
    unittest.main()
