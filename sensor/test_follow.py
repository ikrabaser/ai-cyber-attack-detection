import io
import tempfile
import unittest
import urllib.error
from argparse import Namespace
from pathlib import Path
from unittest import mock

import detect
from features import extract
from follow import LiveMonitor, tail_records
from rules import detect as detect_rules
from zeek_reader import read_log

SAMPLE = Path(__file__).parent / "sample" / "conn.log"

HEADER = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
    "#fields\tts\tid.orig_h\tid.resp_h\tid.resp_p\tconn_state\tduration\torig_bytes\tresp_bytes\n"
    "#types\ttime\taddr\taddr\tport\tstring\tinterval\tcount\tcount\n"
)


def line(ts, src="10.0.0.9", dst="10.0.0.2", port=22, state="SF"):
    return f"{ts}\t{src}\t{dst}\t{port}\t{state}\t1.0\t100\t100\n"


def conn(ts, src="10.0.0.9", port=22):
    return {"ts": ts, "id.orig_h": src, "id.resp_h": "10.0.0.2", "id.resp_p": port,
            "conn_state": "SF", "duration": 1.0, "orig_bytes": 100, "resp_bytes": 100}


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def tmp_path():
    f = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    f.close()
    return f.name


def append(path, text):
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def drain(gen):
    """Bir sonraki zaman tikine (None) kadar verilen kayıtlar."""
    out = []
    for item in gen:
        if item is None:
            return out
        out.append(item)
    return out


class LiveMonitorTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.mon = LiveMonitor(window=10, grace=8, clock=self.clock)

    def burst(self, start, n=10, src="10.0.0.9"):
        for i in range(n):
            self.mon.add(conn(start + i * 0.9, src))

    def test_window_stays_open_until_its_end_plus_grace(self):
        self.burst(1000)
        self.clock.t = 0.0
        # son kayıt ts=1008.1; pencere 1010'da biter, grace ile 1018.
        self.clock.t = 8.0   # watermark = 8 + (1008.1 - 0) = 1016.1 < 1018
        self.assertEqual(self.mon.close_ready(), [])
        self.clock.t = 10.0  # watermark 1018.1
        results = self.mon.close_ready()
        self.assertEqual(len(results), 1)
        row, det = results[0]
        self.assertEqual((row["src_ip"], row["window_start"], row["n_conns"]), ("10.0.0.9", 1000, 10))
        self.assertEqual(det.attack_type, "brute_force")

    def test_time_keeps_moving_when_traffic_stops(self):
        # Kayıt gelmese de duvar saati ilerleyince son pencere kapanır (saldırı bitti, sessizlik).
        self.burst(1000)
        self.clock.t = 1000.0
        self.assertEqual(len(self.mon.close_ready()), 1)

    def test_windows_close_in_order_and_streak_carries_over(self):
        self.burst(1000)
        self.burst(1010)
        self.clock.t = 1000.0
        results = self.mon.close_ready()
        self.assertEqual([r["window_start"] for r, _ in results], [1000, 1010])
        first, second = results[0][1], results[1][1]
        self.assertGreater(second.risk_score, first.risk_score)
        self.assertIn("2. ardışık pencere", second.reasons[-1])

    def test_late_record_is_dropped_and_counted(self):
        self.burst(1000)
        self.clock.t = 1000.0
        self.mon.close_ready()
        self.mon.add(conn(1005.0))
        self.assertEqual(self.mon.late, 1)
        self.assertEqual(self.mon.pending, {})

    def test_record_within_grace_still_counts(self):
        self.burst(1000, n=9)
        self.clock.t = 1.0
        self.mon.add(conn(1005.0))  # uzun bağlantı, kaydı geç yazıldı ama pencere hâlâ açık
        self.clock.t = 1000.0
        (row, _), = self.mon.close_ready()
        self.assertEqual(row["n_conns"], 10)
        self.assertEqual(self.mon.late, 0)

    def test_clock_skew_between_zeek_and_monitor_does_not_matter(self):
        for skew in (-5000.0, 0.0, 86400.0):
            clock = Clock()
            clock.t = skew
            mon = LiveMonitor(window=10, grace=8, clock=clock)
            for i in range(10):
                mon.add(conn(1000 + i * 0.9))
            clock.t = skew + 5
            self.assertEqual(mon.close_ready(), [], f"skew={skew}")
            clock.t = skew + 20
            self.assertEqual(len(mon.close_ready()), 1, f"skew={skew}")

    def test_same_result_as_batch_on_sample_log(self):
        records = list(read_log(SAMPLE))
        batch = detect_rules(extract(records, window=10), window=10)
        for rec in records:
            self.mon.add(rec)
        self.clock.t = 100000.0
        live = [det for _, det in self.mon.close_ready() if det]
        key = lambda d: (d.src_ip, d.window_start, d.attack_type, round(d.risk_score, 6), d.reasons)
        self.assertEqual([key(d) for d in live], [key(d) for d in batch])
        self.assertGreater(len(live), 0)


class TailRecordsTests(unittest.TestCase):
    def gen(self, path, **kw):
        return tail_records(path, poll=0, sleep=lambda s: None, **kw)

    def test_existing_records_are_skipped_by_default(self):
        path = tmp_path()
        append(path, HEADER + line(1000.0) + line(1001.0))
        g = self.gen(path)
        self.assertEqual(drain(g), [])
        append(path, line(1002.0))
        self.assertEqual([r["ts"] for r in drain(g)], [1002.0])  # başlık hâlâ biliniyor

    def test_from_start_yields_existing_records(self):
        path = tmp_path()
        append(path, HEADER + line(1000.0) + line(1001.0))
        self.assertEqual([r["ts"] for r in drain(self.gen(path, from_start=True))], [1000.0, 1001.0])

    def test_partial_line_waits_for_newline(self):
        path = tmp_path()
        append(path, HEADER)
        g = self.gen(path)
        drain(g)
        full = line(1000.0)
        append(path, full[:12])
        self.assertEqual(drain(g), [])
        append(path, full[12:])
        self.assertEqual([r["ts"] for r in drain(g)], [1000.0])

    def test_file_created_later_is_read_from_its_start(self):
        path = tmp_path()
        Path(path).unlink()
        g = self.gen(path)
        self.assertEqual(drain(g), [])
        append(path, HEADER + line(1000.0))
        self.assertEqual([r["ts"] for r in drain(g)], [1000.0])

    def test_truncated_file_is_read_again_from_the_start(self):
        path = tmp_path()
        append(path, HEADER + line(1000.0) + line(1001.0) + line(1002.0))
        g = self.gen(path, from_start=True)
        self.assertEqual(len(drain(g)), 3)
        Path(path).write_text(HEADER + line(2000.0), encoding="utf-8")  # Zeek yeniden başladı
        self.assertEqual([r["ts"] for r in drain(g)], [2000.0])

    def test_bad_line_goes_to_on_error_and_reading_continues(self):
        path = tmp_path()
        append(path, HEADER + line(1000.0) + "bozuk\tsatir\n" + line(1001.0))
        errors = []
        got = drain(self.gen(path, from_start=True, on_error=errors.append))
        self.assertEqual([r["ts"] for r in got], [1000.0, 1001.0])
        self.assertEqual(len(errors), 1)
        self.assertIn("sütun bekleniyordu", str(errors[0]))

    def test_bad_line_raises_without_on_error(self):
        path = tmp_path()
        append(path, HEADER + "bozuk\n")
        with self.assertRaises(ValueError):
            drain(self.gen(path, from_start=True))

    def test_stop_ends_the_generator(self):
        path = tmp_path()
        append(path, HEADER)
        flag = [False]
        g = tail_records(path, poll=0, sleep=lambda s: flag.__setitem__(0, True), stop=lambda: flag[0])
        self.assertEqual(list(g), [None])


class FollowCommandTests(unittest.TestCase):
    """detect.follow uçtan uca: sahte saat, gerçek dosya, sahte backend."""

    def run_follow(self, steps, send=True, send_effect=None, verbose=False, ticks=8):
        path = tmp_path()
        append(path, HEADER)
        clock, count = Clock(), [0]

        def sleep(_):
            count[0] += 1
            clock.t += 5
            if count[0] in steps:
                append(path, steps[count[0]])

        args = Namespace(path=path, window=10, grace=8.0, poll=0.5, from_start=False, send=send,
                         url="http://x/api/events/", token="t", verbose=verbose)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("detect.send_event") as fake:
            fake.side_effect = send_effect or (lambda *a, **k: (201, {"status": "created"}))
            code = detect.follow(args, sleep=sleep, clock=clock, stop=lambda: count[0] >= ticks,
                                 out=out, err=err)
        return code, out.getvalue(), err.getvalue(), fake

    BURST = "".join(line(1000 + i * 0.9, src="10.0.0.9") for i in range(10))

    def test_attack_is_sent_after_its_window_closes(self):
        code, out, err, fake = self.run_follow({1: self.BURST})
        self.assertEqual(code, 0)
        self.assertEqual(fake.call_count, 1)
        payload = fake.call_args.args[2]
        self.assertEqual((payload["source_ip"], payload["attack_type"]), ("10.0.0.9", "brute_force"))
        self.assertIn("HTTP 201 created", out)
        self.assertIn("1 gönderildi, 0 gönderilemedi", out)

    def test_nothing_is_sent_before_the_window_closes(self):
        code, out, _, fake = self.run_follow({1: self.BURST}, ticks=2)
        self.assertEqual(fake.call_count, 0)
        self.assertIn("1 pencere beklemede", out)

    def test_without_send_only_prints(self):
        _, out, _, fake = self.run_follow({1: self.BURST}, send=False)
        self.assertEqual(fake.call_count, 0)
        self.assertIn("brute_force", out)

    def test_backend_down_does_not_stop_monitoring(self):
        code, out, _, fake = self.run_follow(
            {1: self.BURST}, send_effect=urllib.error.URLError("bağlantı reddedildi"))
        self.assertEqual(code, 0)
        self.assertIn("gönderilemedi: bağlantı reddedildi", out)
        self.assertIn("0 gönderildi, 1 gönderilemedi", out)

    def test_rejected_token_stops_with_error(self):
        code, _, err, _ = self.run_follow({1: self.BURST}, send_effect=lambda *a, **k: (401, {"error": "x"}))
        self.assertEqual(code, 1)
        self.assertIn("Token reddedildi", err)

    def test_verbose_shows_quiet_windows(self):
        quiet = line(1000.0, port=80) + line(1001.0, port=80)
        _, out, _, fake = self.run_follow({1: quiet}, verbose=True)
        self.assertEqual(fake.call_count, 0)
        self.assertIn("2 bağlantı, 1 port", out)

    def test_quiet_windows_hidden_by_default(self):
        quiet = line(1000.0, port=80) + line(1001.0, port=80)
        _, out, _, _ = self.run_follow({1: quiet})
        self.assertNotIn("2 bağlantı, 1 port", out)
        self.assertIn("1 pencere incelendi, 0 tespit", out)


class FollowArgsTests(unittest.TestCase):
    def parse_error(self, *argv):
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err, self.assertRaises(SystemExit):
            detect.main(list(argv))
        return err.getvalue()

    def test_follow_only_flags_need_follow(self):
        self.assertIn("--follow", self.parse_error("x.log", "--from-start"))
        self.assertIn("--follow", self.parse_error("x.log", "-v"))

    def test_delay_is_rejected_with_follow(self):
        self.assertIn("--delay", self.parse_error("x.log", "--follow", "--delay", "1"))

    def test_bad_grace_and_poll(self):
        self.assertIn("--grace", self.parse_error("x.log", "--follow", "--grace", "-1"))
        self.assertIn("--poll", self.parse_error("x.log", "--follow", "--poll", "0"))


if __name__ == "__main__":
    unittest.main()
