import unittest
from pathlib import Path

from features import extract
from rules import AUTH_PORTS, Detection, brute_force, detect, level_for, port_scan
from zeek_reader import read_log

SAMPLE = Path(__file__).parent / "sample" / "conn.log"


def row(src="10.0.0.9", start=1000, conns=5, ports=2, fail=0.0, share=0.5, top_port=80, host="10.0.0.2",
        ssh_failed=0):
    return {"src_ip": src, "window_start": start, "n_conns": conns, "n_dst_ports": ports,
            "n_dst_hosts": 1, "fail_ratio": fail, "mean_duration": 1.0, "mean_bytes": 100.0,
            "top_port_share": share, "top_port": top_port, "top_dst_host": host,
            "ssh_failed_auth": ssh_failed}


class PortScanRuleTests(unittest.TestCase):
    def test_below_min_ports_does_not_fire(self):
        self.assertIsNone(port_scan(row(ports=9, fail=1.0)))

    def test_minimum_case_scores_base(self):
        score, _ = port_scan(row(ports=10, fail=0.0))
        self.assertAlmostEqual(score, 0.55)

    def test_big_failed_scan_scores_near_one(self):
        score, reasons = port_scan(row(conns=40, ports=40, fail=0.95))
        self.assertAlmostEqual(score, 0.55 + 0.25 + 0.20 * 0.95)
        self.assertIn("40 farklı porta", reasons[0])
        self.assertIn("%95", reasons[1])

    def test_more_ports_and_more_failures_never_lower_the_score(self):
        a, _ = port_scan(row(ports=15, fail=0.2))
        b, _ = port_scan(row(ports=30, fail=0.2))
        c, _ = port_scan(row(ports=30, fail=0.9))
        self.assertLess(a, b)
        self.assertLess(b, c)


class BruteForceRuleTests(unittest.TestCase):
    def fires(self, **kw):
        base = dict(conns=10, ports=1, share=1.0, top_port=22)
        base.update(kw)
        return brute_force(row(**base))

    def test_ssh_burst_fires(self):
        score, reasons = self.fires()
        self.assertAlmostEqual(score, 0.5 + 0.2 * (2 / 12))
        self.assertIn("SSH (22)", reasons[0])

    def test_same_traffic_on_a_normal_port_does_not_fire(self):
        # Bir web sayfası da 10 bağlantı açabilir: giriş servisi olmayan port brute force sayılmaz.
        self.assertIsNone(self.fires(top_port=80))

    def test_needs_enough_connections(self):
        self.assertIsNone(self.fires(conns=7))

    def test_needs_connections_concentrated_on_one_port(self):
        self.assertIsNone(self.fires(share=0.8))

    def test_every_auth_port_is_recognized(self):
        for port in AUTH_PORTS:
            self.assertIsNotNone(self.fires(top_port=port), port)

    def test_score_is_capped_by_abundance(self):
        score, _ = self.fires(conns=500)
        self.assertAlmostEqual(score, 0.7)


class DetectTests(unittest.TestCase):
    def burst(self, start):
        return row(start=start, conns=10, ports=1, share=1.0, top_port=22)

    def test_persistence_bonus_grows_with_consecutive_windows(self):
        found = detect([self.burst(1000), self.burst(1010), self.burst(1020)])
        scores = [d.risk_score for d in found]
        base = 0.5 + 0.2 * (2 / 12)
        self.assertAlmostEqual(scores[0], base)
        self.assertAlmostEqual(scores[1], base + 0.10)
        self.assertAlmostEqual(scores[2], base + 0.20)
        self.assertIn("3. tetiklenen pencere", found[2].reasons[-1])

    def test_short_gap_of_empty_windows_keeps_the_streak(self):
        # Hydra: bağlantılar uzun açık kalır, yeni bağlantı 40-60 sn arayla başlar; arada o kaynaktan kayıt yok.
        found = detect([self.burst(1000), self.burst(1030)])
        self.assertAlmostEqual(found[1].risk_score, found[0].risk_score + 0.10)
        self.assertIn("2. tetiklenen pencere", found[1].reasons[-1])

    def test_gap_of_exactly_nine_windows_keeps_and_ten_resets(self):
        kept = detect([self.burst(1000), self.burst(1090)])
        self.assertAlmostEqual(kept[1].risk_score, kept[0].risk_score + 0.10)
        reset = detect([self.burst(1000), self.burst(1100)])
        self.assertAlmostEqual(reset[1].risk_score, reset[0].risk_score)

    def test_hydra_like_bursts_climb_to_high(self):
        # Gerçek lab verisi: 840, 900, 940, 990, 1030 (başlangıçlar arası 40-60 sn), pencere başına 20 başarısız parola.
        rows = [row(start=1794945000 + off, conns=4, ports=1, share=1.0, top_port=22, ssh_failed=20)
                for off in (0, 60, 100, 150, 190)]
        scores = [d.risk_score for d in detect(rows)]
        self.assertEqual([round(x, 2) for x in scores], [0.70, 0.80, 0.90, 1.00, 1.00])
        self.assertEqual(level_for(scores[0]), "medium")
        self.assertEqual(level_for(scores[2]), "high")

    def test_quiet_window_in_between_resets_the_streak(self):
        quiet = row(start=1010, conns=3, ports=1, share=1.0, top_port=22)
        found = detect([self.burst(1000), quiet, self.burst(1020)])
        self.assertEqual(len(found), 2)
        self.assertAlmostEqual(found[0].risk_score, found[1].risk_score)

    def test_streaks_are_tracked_per_source(self):
        a, b = self.burst(1000), self.burst(1010)
        b["src_ip"] = "10.0.0.77"
        found = detect([a, b])
        self.assertAlmostEqual(found[0].risk_score, found[1].risk_score)

    def test_streak_bonus_is_capped_and_score_never_exceeds_one(self):
        found = detect([self.burst(1000 + 10 * i) for i in range(20)])
        self.assertLessEqual(max(d.risk_score for d in found), 1.0)
        self.assertAlmostEqual(found[-1].risk_score, 0.5 + 0.2 * (2 / 12) + 0.40)

    def test_one_detection_per_source_and_window_picks_highest(self):
        both = row(conns=40, ports=40, fail=0.95, share=1.0, top_port=22)  # her iki kural da tetiklenir
        (d,) = detect([both])
        self.assertEqual(d.attack_type, "port_scan")

    def test_level_uses_the_same_rounding_as_the_backend(self):
        self.assertLess(0.7 + 0.2, 0.9)  # kayan nokta: 0.8999999999999999
        self.assertEqual(level_for(0.7 + 0.2), "high")
        self.assertEqual(level_for(0.6 + 0.1), "medium")

    def test_level_mapping_matches_backend_thresholds(self):
        self.assertEqual([level_for(s) for s in (0.5, 0.69, 0.7, 0.89, 0.9, 1.0)],
                         ["low", "low", "medium", "medium", "high", "high"])


class BruteForceFailedAuthTests(unittest.TestCase):
    """Hydra gibi araçlar bir bağlantıdan çok deneme yapar: bağlantı sayısı küçük, deneme sayısı büyük."""

    def hydra(self, failed, conns=4):
        # 4 bağlantı: bağlantı eşiğinin (8) altında; hepsi SSH portunda.
        return row(conns=conns, ports=1, share=1.0, top_port=22, ssh_failed=failed)

    def test_connection_rule_alone_misses_it(self):
        self.assertIsNone(brute_force(self.hydra(0)))

    def test_failed_attempts_below_minimum_do_not_fire(self):
        self.assertIsNone(brute_force(self.hydra(9)))

    def test_minimum_case_scores_060(self):
        score, reasons = brute_force(self.hydra(10))
        self.assertAlmostEqual(score, 0.60)
        self.assertIn("10 başarısız SSH parola denemesi", reasons[0])
        self.assertIn("4 bağlantıda", reasons[0])

    def test_score_grows_with_attempts_and_saturates(self):
        scores = [brute_force(self.hydra(n))[0] for n in (10, 20, 30, 80)]
        self.assertAlmostEqual(scores[1], 0.70)
        self.assertEqual(scores, sorted(scores))
        self.assertAlmostEqual(scores[2], 0.80)
        self.assertAlmostEqual(scores[3], 0.80)

    def test_applies_to_ssh_on_any_port(self):
        # ssh.log protokolü tanır: SSH 2222'de çalışsa da parola denemeleri sayılır.
        self.assertIsNotNone(brute_force(row(conns=3, share=1.0, top_port=2222, ssh_failed=15)))

    def test_one_slip_does_not_fire(self):
        # Meşru kullanıcı 3 kez yanlış girip sonra girdi: eşiğin çok altında.
        self.assertIsNone(brute_force(self.hydra(2, conns=1)))

    def test_higher_of_the_two_evidences_wins(self):
        both = row(conns=20, ports=1, share=1.0, top_port=22, ssh_failed=12)
        score, reasons = brute_force(both)
        self.assertAlmostEqual(score, 0.70)                # bağlantı kanıtı: 0,5 + 0,2 x 1; deneme kanıtı: 0,6 + 0,2 x 0,1
        self.assertIn("servisine 20 bağlantı", reasons[0])

    def test_rows_without_ssh_column_still_work(self):
        r = row(conns=10, ports=1, share=1.0, top_port=22)
        del r["ssh_failed_auth"]
        self.assertIsNotNone(brute_force(r))

    def test_streak_bonus_applies_to_attempt_evidence(self):
        found = detect([self.hydra(12), {**self.hydra(12), "window_start": 1010}])
        self.assertEqual(len(found), 2)
        self.assertGreater(found[1].risk_score, found[0].risk_score)


class SampleScenarioTests(unittest.TestCase):
    def setUp(self):
        self.found = detect(extract(read_log(SAMPLE)))

    def test_normal_client_is_never_flagged(self):
        # 12:00:30 penceresindeki uzun meşru SSH oturumu dahil
        self.assertEqual([d for d in self.found if d.src_ip == "192.168.56.50"], [])

    def test_exactly_one_port_scan_and_it_is_high(self):
        scans = [d for d in self.found if d.attack_type == "port_scan"]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].src_ip, "192.168.56.200")
        self.assertEqual(scans[0].level, "high")
        self.assertEqual(scans[0].row["top_dst_host"], "192.168.56.20")

    def test_brute_force_risk_climbs_across_windows(self):
        brute = [d for d in self.found if d.attack_type == "brute_force"]
        self.assertEqual(len(brute), 6)
        scores = [d.risk_score for d in brute]
        self.assertEqual(scores, sorted(scores))        # azalmaz
        self.assertLess(scores[0], 0.7)                 # ilk pencere tek başına zayıf kanıt
        self.assertGreaterEqual(scores[-1], 0.9)        # ısrar sonunda yüksek
        self.assertEqual([d.level for d in brute][0], "low")
        self.assertEqual([d.level for d in brute][-1], "high")

    def test_detections_are_dataclasses_in_time_order(self):
        self.assertTrue(all(isinstance(d, Detection) for d in self.found))
        times = [d.window_start for d in self.found]
        self.assertEqual(times, sorted(times))


if __name__ == "__main__":
    unittest.main()
