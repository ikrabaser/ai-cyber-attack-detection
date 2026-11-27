import unittest

import dataset as ds
import lstm_sequences as ls


def row(label, ws, day="Friday", src="10.0.0.1", share=1.0, **kw):
    r = {"day": day, "src_ip": src, "window_start": ws, "n_conns": 1, "n_dst_ports": 1, "n_dst_hosts": 1,
         "fail_ratio": 0.0, "mean_duration": 1.0, "mean_bytes": 100.0, "top_port_share": 1.0,
         "top_port": 80, "top_dst_host": "10.0.0.9", "label": label, "label_share": share, "n_flows": 1}
    r.update(kw)
    return r


class BuildSequencesTests(unittest.TestCase):
    def test_consecutive_windows_form_a_sliding_sequence(self):
        rows = ds.assign_split([row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(10)])
        X, y, split = ls.build_sequences(rows, seq_len=3)
        # 10 ardışık pencere, uzunluk 3 -> 8 dizi (hepsi aynı grup/bölmede olduğu sürece)
        self.assertEqual(len(X), len(y))
        self.assertEqual(len(X), len(split))
        self.assertTrue(all(len(seq) == 3 for seq in X))

    def test_sequence_label_is_the_last_windows_class(self):
        rows = ds.assign_split([row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(5)])
        X, y, split = ls.build_sequences(rows, seq_len=3)
        self.assertTrue(all(label == "port_scan" for label in y))

    def test_feature_order_follows_features_module(self):
        from features import FEATURES
        rows = ds.assign_split(
            [row("portscan", 1000 + i * 10, src="172.16.0.1", n_conns=7) for i in range(3)],
            train_fraction=1.0, gap_seconds=0,
        )
        X, y, split = ls.build_sequences(rows, seq_len=3)
        self.assertEqual(X[0][0][FEATURES.index("n_conns")], 7)

    def test_time_gap_breaks_the_sequence(self):
        # ilk 3 pencere ardışık, sonra büyük bir boşluk, sonra 3 pencere daha ardışık.
        # train_fraction=1.0, gap_seconds=0: hepsi "train" olsun, yalnızca boşluk kuralı test edilsin.
        rows = ([row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(3)]
                + [row("portscan", 100000 + i * 10, src="172.16.0.1") for i in range(3)])
        rows = ds.assign_split(rows, train_fraction=1.0, gap_seconds=0)
        X, y, split = ls.build_sequences(rows, seq_len=3)
        # iki ayrı 3'lü çalışma var ama aralarında boşluk köprüsü kurulmamalı: tam olarak 2 dizi (3-3+1 her biri)
        self.assertEqual(len(X), 2)

    def test_different_source_ips_are_not_mixed_into_one_sequence(self):
        # train_fraction=1.0, gap_seconds=0: her iki IP de "train"de olsun, yalnızca IP ayrımı test edilsin.
        rows = ([row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(3)]
                + [row("portscan", 1030 + i * 10, src="172.16.0.2") for i in range(3)])
        rows = ds.assign_split(rows, train_fraction=1.0, gap_seconds=0)
        X, y, split = ls.build_sequences(rows, seq_len=3)
        self.assertEqual(len(X), 2)  # her IP kendi 3'lük dizisini oluşturur, karışmaz

    def test_excluded_and_gap_windows_are_never_used(self):
        rows = [row("ddos", 1000, src="172.16.0.1")]  # ddos -> excluded (sınıf dışı)
        rows = ds.assign_split(rows)
        X, y, split = ls.build_sequences(rows, seq_len=1)
        self.assertEqual(X, [])

    def test_too_short_a_run_produces_no_sequence(self):
        rows = ds.assign_split(
            [row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(2)],
            train_fraction=1.0, gap_seconds=0,
        )
        X, y, split = ls.build_sequences(rows, seq_len=3)
        self.assertEqual(X, [])

    def test_sequences_never_cross_the_train_test_boundary(self):
        rows = ds.assign_split(
            [row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(100)],
            train_fraction=0.6, gap_seconds=60,
        )
        X, y, split = ls.build_sequences(rows, seq_len=5)
        self.assertTrue(set(split) <= {"train", "test"})
        # bölme değişiminin olduğu pencereler arası boşluk (gap) sayesinde hiçbir dizi iki bölmeyi karıştırmaz
        self.assertNotIn("gap", split)

    def test_format_summary_mentions_seq_len_and_total(self):
        rows = ds.assign_split([row("portscan", 1000 + i * 10, src="172.16.0.1") for i in range(5)])
        X, y, split = ls.build_sequences(rows, seq_len=3)
        out = ls.format_summary(X, y, split, seq_len=3)
        self.assertIn("dizi uzunluğu: 3", out)
        self.assertIn(f"toplam dizi: {len(X)}", out)


if __name__ == "__main__":
    unittest.main()
