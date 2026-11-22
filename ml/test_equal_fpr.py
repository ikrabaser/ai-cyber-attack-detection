import unittest

import equal_fpr as ef


class RecallAtFprTests(unittest.TestCase):
    def test_picks_the_most_generous_threshold_within_the_budget(self):
        pos = [0.9, 0.8, 0.6, 0.4]
        neg = [0.7, 0.5, 0.3, 0.2, 0.1, 0.05, 0.04, 0.03, 0.02, 0.01]
        # bütçe 0: hiçbir normal geçmesin -> eşik 0.8 (0.7'deki normali geçirmez), 2/4 yakalanır
        self.assertEqual(ef.recall_at_fpr(pos, neg, 0.0), (0.5, 0.0, 0.8))
        # bütçe 1/10: 0.7'deki normal geçebilir -> eşik 0.6, 3/4
        self.assertEqual(ef.recall_at_fpr(pos, neg, 0.1), (0.75, 0.1, 0.6))
        # bütçe 2/10: 0.5'teki normal de geçebilir -> eşik 0.4, 4/4
        self.assertEqual(ef.recall_at_fpr(pos, neg, 0.2), (1.0, 0.2, 0.4))

    def test_budget_of_zero_only_counts_positives_above_every_negative(self):
        recall, fpr, _ = ef.recall_at_fpr([0.9, 0.5], [0.6, 0.1], 0.0)
        self.assertEqual((recall, fpr), (0.5, 0.0))

    def test_ties_move_together(self):
        # iki normal aynı skorda: hedef %50 ise ikisini birden geçirmeden duramayız -> eşik yukarıda kalır
        recall, fpr, thr = ef.recall_at_fpr([0.9, 0.5], [0.5, 0.5, 0.1, 0.1], 0.25)
        self.assertEqual((recall, thr), (0.5, 0.9))

    def test_unreachable_budget_gives_zero_recall(self):
        recall, fpr, thr = ef.recall_at_fpr([0.5], [0.9, 0.8], 0.0)
        self.assertEqual((recall, thr), (0.0, None))

    def test_empty_inputs(self):
        self.assertEqual(ef.recall_at_fpr([], [0.1], 0.1), (0.0, 0.0, None))
        self.assertEqual(ef.recall_at_fpr([0.1], [], 0.1), (0.0, 0.0, None))


class WilsonTests(unittest.TestCase):
    def test_interval_contains_the_estimate_and_stays_in_bounds(self):
        lo, hi = ef.wilson(24, 30)
        self.assertLess(lo, 0.8)
        self.assertGreater(hi, 0.8)
        self.assertGreaterEqual(lo, 0.0)
        self.assertLessEqual(hi, 1.0)

    def test_small_samples_give_wide_intervals(self):
        lo, hi = ef.wilson(30, 30)
        self.assertLess(lo, 0.9)
        self.assertEqual(hi, 1.0)

    def test_zero_n(self):
        self.assertEqual(ef.wilson(0, 0), (0.0, 0.0))


class CompareTests(unittest.TestCase):
    def test_compare_covers_each_class_and_target(self):
        data = {"pos": [0.9, 0.8], "neg": [0.1] * 10, "neg_clean": [0.1] * 5}
        scores = {m: {c: data for c in ef.CLASSES_UNDER_TEST} for m in ("kurallar", "model")}
        rows = ef.compare(scores, "neg", targets=(0.01, 0.1))
        self.assertEqual(len(rows), 2 * len(ef.CLASSES_UNDER_TEST))
        recall, _, n, _ = rows[("port_scan", 0.01)]["model"]
        self.assertEqual((recall, n), (1.0, 2))
        self.assertIn("port_scan", ef.format_comparison(rows))


if __name__ == "__main__":
    unittest.main()
