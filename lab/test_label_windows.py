import csv
import os
import tempfile
import unittest
from pathlib import Path

import _paths  # noqa: F401
import label_windows as lw
from zeek_reader import read_log

SAMPLE = Path(__file__).resolve().parent.parent / "sensor" / "sample" / "conn.log"
ATT, NORM = "192.168.56.200", "192.168.56.50"


def run(run_id, label, src, start, end):
    return {"run_id": run_id, "label": label, "scenario": "s", "src_ip": src, "dst_ip": "192.168.56.20",
            "start": start, "end": end}


def sample_runs():
    return [
        run("scan", "port_scan", ATT, 1794301259.5, 1794301262.5),
        run("brute", "brute_force", ATT, 1794301289.0, 1794301352.0),
        run("norm", "normal", NORM, 1794301200.0, 1794301380.0),
    ]


class LabelRowTests(unittest.TestCase):
    def row(self, src, ws):
        return {"src_ip": src, "window_start": ws}

    def test_fully_inside_run_is_not_boundary(self):
        rid, label, boundary = lw.label_row(self.row(ATT, 100), [run("a", "port_scan", ATT, 95, 125)], 10)
        self.assertEqual((rid, label, boundary), ("a", "port_scan", False))

    def test_partial_window_is_boundary(self):
        r = [run("a", "port_scan", ATT, 105, 125)]
        self.assertTrue(lw.label_row(self.row(ATT, 100), r, 10)[2])  # koşu pencere ortasında başladı
        self.assertTrue(lw.label_row(self.row(ATT, 120), r, 10)[2])  # koşu pencere ortasında bitti

    def test_no_run_for_that_source_is_unknown(self):
        self.assertEqual(lw.label_row(self.row("10.0.0.9", 100), [run("a", "normal", ATT, 0, 500)], 10),
                         (None, "unknown", True))

    def test_window_outside_every_run_is_unknown(self):
        self.assertEqual(lw.label_row(self.row(ATT, 300), [run("a", "normal", ATT, 0, 100)], 10)[1], "unknown")

    def test_touching_only_at_the_edge_does_not_match(self):
        self.assertEqual(lw.label_row(self.row(ATT, 100), [run("a", "normal", ATT, 110, 200)], 10)[1], "unknown")

    def test_back_to_back_runs_pick_larger_overlap_and_mark_boundary(self):
        runs = [run("a", "port_scan", ATT, 90, 103), run("b", "brute_force", ATT, 103, 130)]
        rid, label, boundary = lw.label_row(self.row(ATT, 100), runs, 10)
        self.assertEqual((rid, label, boundary), ("b", "brute_force", True))


class SampleLogTests(unittest.TestCase):
    def setUp(self):
        self.runs = sample_runs()
        self.labeled = lw.label_windows(list(read_log(SAMPLE)), self.runs)

    def test_every_window_gets_the_right_label(self):
        by_src = {}
        for r in self.labeled:
            by_src.setdefault((r["src_ip"], r["label"]), 0)
            by_src[(r["src_ip"], r["label"])] += 1
        self.assertEqual(by_src, {(NORM, "normal"): 18, (ATT, "port_scan"): 1, (ATT, "brute_force"): 6})
        self.assertNotIn("unknown", {r["label"] for r in self.labeled})

    def test_scan_window_is_boundary_but_brute_windows_are_not(self):
        scan = [r for r in self.labeled if r["label"] == "port_scan"]
        brute = [r for r in self.labeled if r["label"] == "brute_force"]
        self.assertTrue(all(r["boundary"] for r in scan))
        self.assertFalse(any(r["boundary"] for r in brute))

    def test_summary_counts_windows_per_run(self):
        summary, extra = lw.summarize(self.labeled, self.runs)
        got = {s["run_id"]: s for s in summary}
        self.assertEqual((got["scan"]["windows"], got["scan"]["boundary_windows"], got["scan"]["detected_windows"]),
                         (1, 1, 1))
        self.assertEqual((got["brute"]["windows"], got["brute"]["detected_windows"]), (6, 6))
        # ilk tespit penceresi 1794301290-1794301300; süre pencere BİTİŞİnden ölçülür (1794301300 - 1794301289)
        self.assertEqual(got["brute"]["first_detection_s"], 11.0)
        self.assertEqual((got["norm"]["windows"], got["norm"]["detected_windows"], got["norm"]["wrong_rule_windows"]),
                         (18, 0, 0))
        self.assertEqual(extra, {"unknown_windows": 0, "unknown_detected": 0})

    def test_missing_runs_make_everything_unknown_and_count_detections(self):
        labeled = lw.label_windows(list(read_log(SAMPLE)), [])
        summary, extra = lw.summarize(labeled, [])
        self.assertEqual(summary, [])
        self.assertEqual(extra["unknown_windows"], 25)
        self.assertEqual(extra["unknown_detected"], 7)  # kural 7 tespit verdi ama etiketli koşu yok

    def test_wrong_rule_is_counted(self):
        runs = [run("x", "brute_force", ATT, 1794301259.5, 1794301262.5)]  # tarama penceresine yanlış etiket
        labeled = lw.label_windows(list(read_log(SAMPLE)), runs)
        summary, _ = lw.summarize(labeled, runs)
        self.assertEqual((summary[0]["detected_windows"], summary[0]["wrong_rule_windows"]), (0, 1))


class SshLogTests(unittest.TestCase):
    """Hydra benzeri koşu: pencerede az bağlantı ama bağlantı başına 5 başarısız parola."""

    SRC = "10.77.0.20"

    def conns(self):
        return [{"ts": 1000.0 + i * 2.0, "id.orig_h": self.SRC, "id.resp_h": "10.77.0.10", "id.resp_p": 22,
                 "conn_state": "SF", "duration": 15.0, "orig_bytes": 500, "resp_bytes": 500} for i in range(4)]

    def ssh(self):
        return [{"ts": 1000.0 + i * 2.0, "id.orig_h": self.SRC, "auth_success": False, "auth_attempts": 5}
                for i in range(4)]

    def runs(self):
        return [run("b", "brute_force", self.SRC, 995.0, 1040.0)]

    def test_without_ssh_log_the_run_is_missed(self):
        labeled = lw.label_windows(self.conns(), self.runs())
        summary, _ = lw.summarize(labeled, self.runs())
        self.assertEqual((summary[0]["windows"], summary[0]["detected_windows"]), (1, 0))
        self.assertEqual(labeled[0]["ssh_failed_auth"], 0)

    def test_with_ssh_log_the_run_is_detected(self):
        labeled = lw.label_windows(self.conns(), self.runs(), ssh_records=self.ssh())
        summary, _ = lw.summarize(labeled, self.runs())
        self.assertEqual(labeled[0]["ssh_failed_auth"], 20)
        self.assertEqual((summary[0]["detected_windows"], summary[0]["wrong_rule_windows"]), (1, 0))
        # pencere 1000-1010, koşu 995'te başladı: 1010 - 995
        self.assertEqual(summary[0]["first_detection_s"], 15.0)


class MainTests(unittest.TestCase):
    def test_writes_csv_with_documented_columns_and_prints_summary(self):
        import contextlib
        import io
        import json
        with tempfile.TemporaryDirectory() as d:
            runs_path = os.path.join(d, "runs.jsonl")
            with open(runs_path, "w", encoding="utf-8") as fh:
                for r in sample_runs():
                    fh.write(json.dumps(r) + "\n")
            out = os.path.join(d, "w.csv")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = lw.main([str(SAMPLE), runs_path, "--out", out])
            self.assertEqual(rc, 0)
            self.assertIn("25 pencere, 3 koşu", buf.getvalue())
            with open(out, newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(list(rows[0].keys()), lw.COLUMNS)
            self.assertEqual(len(rows), 25)
            self.assertNotIn("10.77", open(out, encoding="utf-8").read())

    def test_sibling_ssh_log_is_used_and_no_ssh_ignores_it(self):
        import contextlib
        import io
        import json
        conn_hdr = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
                    "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tconn_state\tduration\torig_bytes\tresp_bytes\n"
                    "#types\ttime\taddr\taddr\tport\tstring\tinterval\tcount\tcount\n")
        ssh_hdr = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tssh\n"
                   "#fields\tts\tid.orig_h\tauth_success\tauth_attempts\n#types\ttime\taddr\tbool\tcount\n")
        with tempfile.TemporaryDirectory() as d:
            Path(d, "conn.log").write_text(conn_hdr + "".join(
                f"{1000 + i * 2.0}\t10.77.0.20\t10.77.0.10\t22\tSF\t15.0\t500\t500\n" for i in range(4)), encoding="utf-8")
            Path(d, "ssh.log").write_text(ssh_hdr + "".join(
                f"{1000 + i * 2.0}\t10.77.0.20\tF\t5\n" for i in range(4)), encoding="utf-8")
            runs_path = os.path.join(d, "runs.jsonl")
            Path(runs_path).write_text(json.dumps(run("b", "brute_force", "10.77.0.20", 995.0, 1040.0)) + "\n",
                                       encoding="utf-8")
            outs = []
            for extra in ([], ["--no-ssh"]):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(lw.main([os.path.join(d, "conn.log"), runs_path, *extra]), 0)
                outs.append(buf.getvalue())
            self.assertIn("4 SSH kaydı", outs[0])
            self.assertIn("15.0 sn", outs[0])        # tespit edildi
            self.assertNotIn("SSH kaydı", outs[1])
            self.assertNotIn("15.0 sn", outs[1])     # ssh.log olmadan kaçırıldı

    def test_bad_runlog_gives_message_and_nonzero(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "runs.jsonl")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("{bozuk\n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = lw.main([str(SAMPLE), bad])
            self.assertEqual(rc, 1)
            self.assertIn("geçersiz JSON", err.getvalue())


if __name__ == "__main__":
    unittest.main()
