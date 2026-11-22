import unittest

import label_noise as ln


def row(src, cls, split="test", ws=1000, label=None, fail=0.0, mean_bytes=100.0):
    label = label or ("benign" if cls == "normal" else cls)
    return {"src_ip": src, "cls": cls, "split": split, "window_start": ws, "label": label,
            "fail_ratio": fail, "mean_bytes": mean_bytes, "n_conns": 2, "n_dst_ports": 1, "n_dst_hosts": 1,
            "mean_duration": 1.0, "top_port_share": 1.0, "top_port": 80, "top_dst_host": "10.0.0.2"}


class SuspectTests(unittest.TestCase):
    def test_only_normal_windows_from_the_attacker_address_are_suspect(self):
        self.assertTrue(ln.is_suspect(row(ln.SUSPECT_IP, "normal")))
        self.assertFalse(ln.is_suspect(row("192.168.10.5", "normal")))
        self.assertFalse(ln.is_suspect(row(ln.SUSPECT_IP, "port_scan")))

    def test_profile_compares_suspects_with_other_normals(self):
        rows = [
            row(ln.SUSPECT_IP, "normal", ws=1000, fail=1.0, mean_bytes=0.0),
            row(ln.SUSPECT_IP, "normal", ws=5000, fail=0.0),
            row(ln.SUSPECT_IP, "port_scan", ws=1100),
            row("192.168.10.5", "normal", fail=0.0),
            row("192.168.10.6", "normal", fail=1.0, mean_bytes=0.0),
        ]
        p = ln.profile(rows)
        self.assertEqual(p["suspects"], 2)
        self.assertAlmostEqual(p["suspect_all_failed"], 0.5)
        self.assertAlmostEqual(p["others_all_failed"], 0.5)
        self.assertAlmostEqual(p["suspect_failed_empty"], 0.5)
        self.assertAlmostEqual(p["suspect_near_attack"], 0.5)  # yalnızca ws=1000 olan, 1100'e yakın

    def test_profile_with_no_suspects_does_not_divide_by_zero(self):
        p = ln.profile([row("192.168.10.5", "normal")])
        self.assertEqual(p["suspects"], 0)
        self.assertEqual(p["suspect_failed_empty"], 0.0)


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            row("192.168.10.5", "normal", split="train"),
            row(ln.SUSPECT_IP, "normal", split="train", ws=10),
            row("192.168.10.5", "normal"),
            row("192.168.10.6", "normal"),
            row(ln.SUSPECT_IP, "normal"),                      # şüpheli, testte
            row(ln.SUSPECT_IP, "port_scan", ws=2000),
        ]

    def test_dropping_suspects_removes_them_from_the_evaluation_only(self):
        trained_on = []

        def train_fn(rs):
            trained_on.append(len(rs))
            return None

        # model: saldırgan adresinden gelen her pencereye port_scan der
        def predict_fn(_m, rs):
            return ["port_scan" if r["src_ip"] == ln.SUSPECT_IP else "normal" for r in rs]

        out = ln.compare(self.rows, train_fn, predict_fn)
        self.assertEqual(trained_on, [2, 1])  # ikinci eğitimde şüpheli çıkarıldı
        allt = out[("model", "tüm test")]
        clean = out[("model", "şüpheliler hariç")]
        self.assertEqual((allt["normals"], allt["false_alarms"]), (3, 1))
        self.assertEqual((clean["normals"], clean["false_alarms"]), (2, 0))

    def test_format_has_a_line_per_method_and_evaluation(self):
        out = ln.compare(self.rows, lambda rs: None, lambda m, rs: ["normal"] * len(rs))
        text = ln.format_comparison(out)
        self.assertEqual(len(text.splitlines()), 1 + 6)
        self.assertIn("kurallar", text)


if __name__ == "__main__":
    unittest.main()
