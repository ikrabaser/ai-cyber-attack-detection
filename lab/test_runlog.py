import json
import os
import tempfile
import unittest

import _paths  # noqa: F401
from runlog import append_record, logged_run, new_run_id, read_runs


class LoggedRunTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "alt", "runs.jsonl")

    def tearDown(self):
        self.dir.cleanup()

    def test_writes_one_complete_line_and_creates_folder(self):
        ticks = iter([100.0, 130.5])
        with logged_run(self.path, "port_scan", "nmap_syn", "10.77.0.20", "10.77.0.10", {"timing": 4},
                        clock=lambda: next(ticks)) as run:
            run["exit_code"] = 0
        (rec,) = read_runs(self.path)
        self.assertEqual((rec["label"], rec["scenario"], rec["src_ip"], rec["dst_ip"]),
                         ("port_scan", "nmap_syn", "10.77.0.20", "10.77.0.10"))
        self.assertEqual((rec["start"], rec["end"], rec["exit_code"]), (100.0, 130.5, 0))
        self.assertEqual(rec["params"], {"timing": 4})

    def test_failure_is_logged_with_exit_code_minus_one_and_reraised(self):
        with self.assertRaises(KeyboardInterrupt):
            with logged_run(self.path, "brute_force", "hydra_ssh", "10.77.0.20", "10.77.0.10"):
                raise KeyboardInterrupt
        (rec,) = read_runs(self.path)
        self.assertEqual(rec["exit_code"], -1)
        self.assertIsNotNone(rec["end"])

    def test_explicit_exit_code_survives_exception(self):
        with self.assertRaises(RuntimeError):
            with logged_run(self.path, "normal", "n", "10.77.0.30", "10.77.0.10") as run:
                run["exit_code"] = 2
                raise RuntimeError
        self.assertEqual(read_runs(self.path)[0]["exit_code"], 2)

    def test_runs_append_not_overwrite(self):
        for label in ("normal", "port_scan"):
            with logged_run(self.path, label, "s", "10.77.0.20", "10.77.0.10") as run:
                run["exit_code"] = 0
        self.assertEqual([r["label"] for r in read_runs(self.path)], ["normal", "port_scan"])

    def test_run_ids_differ(self):
        self.assertNotEqual(new_run_id(1.0), new_run_id(1.0))


class ReadRunsTests(unittest.TestCase):
    def read(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return read_runs(path)

    def good(self, **over):
        rec = {"run_id": "a", "label": "normal", "scenario": "s", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
               "start": 1.0, "end": 2.0}
        rec.update(over)
        return json.dumps(rec)

    def test_blank_lines_are_ignored(self):
        self.assertEqual(len(self.read(self.good() + "\n\n" + self.good(run_id="b") + "\n")), 2)

    def test_bad_lines_name_the_line_number(self):
        cases = {
            "{bozuk": "geçersiz JSON",
            "[1,2]": "JSON nesnesi",
            self.good(label=None): "eksik alan: label",
            self.good(start="x"): "sayı olmalı",
            self.good(start=5.0, end=1.0): "start'tan önce",
        }
        for text, needle in cases.items():
            with self.assertRaises(ValueError, msg=text) as ctx:
                self.read(self.good() + "\n" + text + "\n")
            self.assertIn(":2:", str(ctx.exception))
            self.assertIn(needle, str(ctx.exception))

    def test_append_record_is_one_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            append_record(path, {"a": "ş\nı"})  # satır sonu JSON içinde kaçışlanır
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(len(fh.read().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
