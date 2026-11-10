import csv
import tempfile
import unittest
from pathlib import Path

from extract_features import write_csv
from features import FEATURES, compute_features, extract, window_start
from zeek_reader import read_log

SAMPLE = Path(__file__).parent / "sample" / "conn.log"


def conn(dst_h="10.0.0.2", dst_p=80, state="SF", duration=1.0, ob=100, rb=900, src="10.0.0.9", ts=1000.0):
    return {"id.orig_h": src, "id.resp_h": dst_h, "id.resp_p": dst_p, "conn_state": state,
            "duration": duration, "orig_bytes": ob, "resp_bytes": rb, "ts": ts}


class WindowTests(unittest.TestCase):
    def test_window_start_rounds_down(self):
        self.assertEqual(window_start(1794301207.3, 10), 1794301200)
        self.assertEqual(window_start(1794301200.0, 10), 1794301200)  # sınır bir sonraki pencereye ait
        self.assertEqual(window_start(1794301209.999, 10), 1794301200)
        self.assertEqual(window_start(17, 5), 15)


class ComputeFeaturesTests(unittest.TestCase):
    def test_hand_computed_values(self):
        conns = [
            conn(dst_p=22, state="SF", duration=2.0, ob=100, rb=300),
            conn(dst_p=22, state="SF", duration=4.0, ob=200, rb=400),
            conn(dst_p=80, state="REJ", duration=None, ob=0, rb=None),
            conn(dst_p=443, state="S0", duration=None, ob=0, rb=None, dst_h="10.0.0.3"),
        ]
        f = compute_features(conns)
        self.assertEqual(f["n_conns"], 4)
        self.assertEqual(f["n_dst_ports"], 3)
        self.assertEqual(f["n_dst_hosts"], 2)
        self.assertEqual(f["fail_ratio"], 0.5)                 # REJ + S0
        self.assertEqual(f["mean_duration"], (2 + 4 + 0 + 0) / 4)  # None -> 0
        self.assertEqual(f["mean_bytes"], (400 + 600 + 0 + 0) / 4)
        self.assertEqual(f["top_port_share"], 0.5)             # 22 numaralı port 4 bağlantının 2'si

    def test_all_same_port_gives_share_one(self):
        f = compute_features([conn(dst_p=22) for _ in range(5)])
        self.assertEqual((f["n_dst_ports"], f["top_port_share"]), (1, 1.0))

    def test_empty_is_rejected(self):
        with self.assertRaises(ValueError):
            compute_features([])

    def test_result_has_exactly_the_declared_features(self):
        self.assertEqual(list(compute_features([conn()])), FEATURES)


class ExtractTests(unittest.TestCase):
    def test_groups_by_source_and_window(self):
        records = [
            conn(src="A", ts=1000.1), conn(src="A", ts=1009.9),  # aynı pencere
            conn(src="A", ts=1010.0),                            # sonraki pencere
            conn(src="B", ts=1000.5),                            # başka kaynak
        ]
        rows = extract(records, window=10)
        got = [(r["src_ip"], r["window_start"], r["n_conns"]) for r in rows]
        self.assertEqual(got, [("A", 1000, 2), ("B", 1000, 1), ("A", 1010, 1)])


class SampleScenarioTests(unittest.TestCase):
    """Örnek senaryoda üç davranış özellik sütunlarında birbirinden ayrışmalı."""

    def setUp(self):
        self.rows = extract(read_log(SAMPLE))
        self.attacker = [r for r in self.rows if r["src_ip"] == "192.168.56.200"]
        self.normal = [r for r in self.rows if r["src_ip"] == "192.168.56.50"]

    def test_port_scan_window(self):
        scans = [r for r in self.attacker if r["n_dst_ports"] > 10]
        self.assertEqual(len(scans), 1)
        s = scans[0]
        self.assertEqual((s["n_conns"], s["n_dst_ports"], s["n_dst_hosts"]), (40, 40, 1))
        self.assertGreaterEqual(s["fail_ratio"], 0.9)
        self.assertLess(s["top_port_share"], 0.05)

    def test_ssh_bruteforce_windows(self):
        brute = [r for r in self.attacker if r["n_dst_ports"] == 1]
        self.assertGreaterEqual(len(brute), 5)
        for r in brute:
            self.assertEqual(r["top_port_share"], 1.0)  # hep 22'ye
            self.assertEqual(r["fail_ratio"], 0.0)      # TCP düzeyinde başarılı, tarama gibi değil
            self.assertGreaterEqual(r["n_conns"], 8)    # saniyede ~1 deneme

    def test_normal_client_stays_quiet(self):
        for r in self.normal:
            self.assertLessEqual(r["n_conns"], 5)
            self.assertEqual(r["fail_ratio"], 0.0)
            self.assertLessEqual(r["n_dst_hosts"], 2)

    def test_every_row_is_complete_and_numeric(self):
        for r in self.rows:
            for name in FEATURES:
                self.assertIsInstance(r[name], (int, float), name)


class CsvTests(unittest.TestCase):
    def test_csv_has_header_and_all_rows(self):
        rows = extract(read_log(SAMPLE))
        path = tempfile.NamedTemporaryFile(suffix=".csv", delete=False).name
        write_csv(rows, path)
        with open(path, newline="", encoding="utf-8") as f:
            data = list(csv.DictReader(f))
        self.assertEqual(len(data), len(rows))
        self.assertEqual(list(data[0]), ["src_ip", "window_start", *FEATURES])


if __name__ == "__main__":
    unittest.main()
