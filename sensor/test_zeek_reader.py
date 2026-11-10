import json
import tempfile
import unittest
from pathlib import Path

from zeek_reader import read_log

SAMPLE = Path(__file__).parent / "sample" / "conn.log"

TSV_HEADER = (
    "#separator \\x09\n"
    "#set_separator\t,\n"
    "#empty_field\t(empty)\n"
    "#unset_field\t-\n"
    "#path\tconn\n"
    "#fields\tts\tid.orig_p\tduration\tlocal_orig\ttunnel_parents\tservice\n"
    "#types\ttime\tport\tinterval\tbool\tset[string]\tstring\n"
)


def write_tmp(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8")
    f.write(text)
    f.close()
    return f.name


class ReadLogTests(unittest.TestCase):
    def test_types_are_converted(self):
        path = write_tmp(TSV_HEADER + "1731229200.5\t44321\t0.25\tT\ta,b\thttp\n")
        (rec,) = list(read_log(path))
        self.assertEqual(rec["ts"], 1731229200.5)
        self.assertEqual(rec["id.orig_p"], 44321)
        self.assertEqual(rec["duration"], 0.25)
        self.assertIs(rec["local_orig"], True)
        self.assertEqual(rec["tunnel_parents"], ["a", "b"])
        self.assertEqual(rec["service"], "http")

    def test_unset_and_empty_values(self):
        path = write_tmp(TSV_HEADER + "1731229200.5\t44321\t-\tF\t(empty)\t(empty)\n")
        (rec,) = list(read_log(path))
        self.assertIsNone(rec["duration"])  # "-" -> None
        self.assertIs(rec["local_orig"], False)
        self.assertEqual(rec["tunnel_parents"], [])
        self.assertEqual(rec["service"], "")

    def test_comment_and_close_lines_are_skipped(self):
        path = write_tmp(TSV_HEADER + "1.0\t1\t-\tF\t(empty)\tdns\n#close\t2026-11-10-09-03-00\n")
        self.assertEqual(len(list(read_log(path))), 1)

    def test_json_lines(self):
        line = json.dumps({"ts": 1.5, "id.orig_h": "10.0.0.1", "conn_state": "S0"})
        (rec,) = list(read_log(write_tmp(line + "\n")))
        self.assertEqual(rec["conn_state"], "S0")

    def test_wrong_column_count_names_the_line(self):
        path = write_tmp(TSV_HEADER + "1.0\t1\n")
        with self.assertRaisesRegex(ValueError, r":8: 6 sütun bekleniyordu, 2 geldi"):
            list(read_log(path))

    def test_data_before_header_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "#fields/#types başlığı yok"):
            list(read_log(write_tmp("1.0\t1\t2\n")))

    def test_invalid_json_line_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "geçersiz JSON"):
            list(read_log(write_tmp("{bozuk\n")))


class SampleFileTests(unittest.TestCase):
    def setUp(self):
        self.records = list(read_log(SAMPLE))

    def test_sample_loads_with_expected_shape(self):
        self.assertEqual(len(self.records), 161)
        self.assertTrue(all(isinstance(r["ts"], float) for r in self.records))
        self.assertTrue(all(isinstance(r["id.resp_p"], int) for r in self.records))

    def test_scenario_attacker_touches_many_ports_normal_client_few(self):
        ports = {}
        for r in self.records:
            ports.setdefault(r["id.orig_h"], set()).add(r["id.resp_p"])
        self.assertEqual(len(ports["192.168.56.200"]), 40)  # tarama + ssh
        self.assertEqual(len(ports["192.168.56.50"]), 3)    # dns, http, ssh

    def test_unanswered_syn_has_no_duration(self):
        s0 = [r for r in self.records if r["conn_state"] == "S0"]
        self.assertEqual(len(s0), 4)
        self.assertTrue(all(r["duration"] is None and r["resp_bytes"] is None for r in s0))


if __name__ == "__main__":
    unittest.main()
