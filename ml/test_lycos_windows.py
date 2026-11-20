import csv
import tempfile
import unittest
from pathlib import Path

import lycos_windows as lw
from features import FEATURES, extract

try:
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None

ATT, VICTIM, HOST = "172.16.0.1", "192.168.10.50", "192.168.10.9"
T0 = 1_499_443_500  # saniye; 10 sn'nin katı değil, bilerek


def flow(src=ATT, dst=VICTIM, dport=80, ts=T0, dur_us=3000, fwd=1, bwd=1, fwd_len=0, bwd_len=0,
         syn=1, rst=1, prot=6, label="portscan"):
    return {"src_addr": src, "dst_addr": dst, "dst_port": dport, "ip_prot": prot,
            "timestamp": int(ts * 1e6), "flow_duration": dur_us, "fwd_pkt_cnt": fwd, "bwd_pkt_cnt": bwd,
            "fwd_pkt_len_tot": fwd_len, "bwd_pkt_len_tot": bwd_len, "flag_SYN": syn, "flag_rst": rst,
            "label": label}


def scan_flows(n=20, ts=T0 + 5):
    return [flow(dport=1000 + i, ts=ts + i * 0.1) for i in range(n)]


class StateFromFlagsTests(unittest.TestCase):
    def test_no_reply_is_s0(self):
        self.assertEqual(lw.state_from_flags(flow(bwd=0, rst=0)), "S0")

    def test_syn_rst_pair_is_rej(self):
        self.assertEqual(lw.state_from_flags(flow()), "REJ")

    def test_long_connection_ending_with_rst_is_not_failed(self):
        self.assertEqual(lw.state_from_flags(flow(fwd=12, bwd=15, fwd_len=900, bwd_len=4000)), "SF")

    def test_udp_with_reply_is_sf(self):
        self.assertEqual(lw.state_from_flags(flow(prot=17, syn=0, rst=0, fwd=1, bwd=1)), "SF")

    def test_udp_without_reply_is_s0(self):
        self.assertEqual(lw.state_from_flags(flow(prot=17, syn=0, rst=0, bwd=0)), "S0")

    def test_failed_states_are_the_ones_features_counts(self):
        from features import FAILED_STATES
        self.assertIn("S0", FAILED_STATES)
        self.assertIn("REJ", FAILED_STATES)
        self.assertNotIn("SF", FAILED_STATES)


class FlowToRecordTests(unittest.TestCase):
    def test_units_and_fields(self):
        r = lw.flow_to_record(flow(dport=22, ts=T0, dur_us=2_500_000, fwd=5, bwd=6, fwd_len=100,
                                   bwd_len=300, rst=0))
        self.assertEqual(r["ts"], T0)
        self.assertEqual(r["duration"], 2.5)
        self.assertEqual((r["id.orig_h"], r["id.resp_h"], r["id.resp_p"]), (ATT, VICTIM, 22))
        self.assertEqual((r["orig_bytes"], r["resp_bytes"]), (100, 300))
        self.assertEqual(r["conn_state"], "SF")

    def test_dst_port_float_becomes_int(self):
        f = flow()
        f["dst_port"] = 443.0
        self.assertEqual(lw.flow_to_record(f)["id.resp_p"], 443)


class WindowsFromFlowsTests(unittest.TestCase):
    def test_port_scan_window(self):
        rows = lw.windows_from_flows(scan_flows(20), "Friday")
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["day"], "Friday")
        self.assertEqual(r["src_ip"], ATT)
        self.assertEqual(r["n_dst_ports"], 20)
        self.assertEqual(r["fail_ratio"], 1.0)
        self.assertEqual(r["n_conns"], 20)
        self.assertEqual(r["label"], "portscan")
        self.assertEqual(r["label_share"], 1.0)
        self.assertEqual(r["n_flows"], 20)

    def test_features_match_sensor_extract(self):
        flows = scan_flows(15) + [flow(src=HOST, dst="192.168.10.3", dport=53, syn=0, rst=0, prot=17,
                                       fwd_len=40, bwd_len=120, dur_us=20_000, label="benign")]
        rows = lw.windows_from_flows(flows, "Friday")
        direct = extract([lw.flow_to_record(f) for f in flows])
        self.assertEqual(len(rows), len(direct))
        for got, want in zip(rows, direct):
            for k in FEATURES:
                self.assertEqual(got[k], want[k], k)

    def test_rows_have_exactly_the_declared_columns(self):
        rows = lw.windows_from_flows(scan_flows(3), "Friday")
        self.assertEqual(list(rows[0]), lw.COLUMNS)

    def test_same_source_in_two_windows_gives_two_rows(self):
        rows = lw.windows_from_flows(scan_flows(3, ts=T0 + 1) + scan_flows(3, ts=T0 + 31), "Friday")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["window_start"] - rows[0]["window_start"], 30)

    def test_mixed_window_takes_majority_label_and_reports_share(self):
        flows = scan_flows(3) + [flow(dport=80, ts=T0 + 6, label="benign", syn=0, rst=0, fwd=4, bwd=4)]
        r = lw.windows_from_flows(flows, "Friday")[0]
        self.assertEqual(r["label"], "portscan")
        self.assertEqual(r["label_share"], 0.75)
        self.assertEqual(r["n_flows"], 4)

    def test_zero_duration_flow_is_fine(self):
        r = lw.windows_from_flows([flow(dur_us=0)], "Friday")[0]
        self.assertEqual(r["mean_duration"], 0.0)

    def test_empty_input(self):
        self.assertEqual(lw.windows_from_flows([], "Friday"), [])


class DayNameTests(unittest.TestCase):
    def test_day_name(self):
        self.assertEqual(lw.day_name("/x/y/Tuesday-WorkingHours.pcap_lycos.csv"), "Tuesday")


@unittest.skipIf(pd is None, "pandas yok")
class FrameTests(unittest.TestCase):
    def frame(self, flows):
        return pd.DataFrame(flows)

    def test_chunked_result_equals_unchunked(self):
        # 3 sn'lik dilimlerle (10'un katı değil) hata verir; 20 sn'lik dilimle iki dilime bölünür.
        flows = scan_flows(5, ts=T0 + 1) + scan_flows(5, ts=T0 + 31) + scan_flows(5, ts=T0 + 61)
        whole = lw.windows_from_flows(flows, "Friday")
        chunked = lw.windows_from_frame(self.frame(flows), "Friday", chunk=20)
        self.assertEqual(chunked, whole)

    def test_unsorted_input_is_sorted_by_time(self):
        flows = scan_flows(3, ts=T0 + 31) + scan_flows(3, ts=T0 + 1)
        rows = lw.windows_from_frame(self.frame(flows), "Friday")
        self.assertEqual([r["window_start"] for r in rows], sorted(r["window_start"] for r in rows))

    def test_chunk_must_be_multiple_of_window(self):
        with self.assertRaises(ValueError):
            lw.windows_from_frame(self.frame(scan_flows(2)), "Friday", chunk=25)

    def test_build_writes_csv(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "Friday-WorkingHours.pcap_lycos.csv"
            df = self.frame(scan_flows(12))
            df["extra_column"] = 1  # usecols ile ihmal edilmeli
            df.to_csv(src, index=False)
            out = Path(d) / "out" / "w.csv"
            totals = lw.build(d, out)
            self.assertEqual(totals["portscan"], 1)
            with out.open(newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(list(rows[0]), lw.COLUMNS)
            self.assertEqual(rows[0]["day"], "Friday")
            self.assertEqual(rows[0]["n_dst_ports"], "12")

    def test_build_without_files_exits(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):
                lw.build(d, Path(d) / "x.csv")


if __name__ == "__main__":
    unittest.main()
