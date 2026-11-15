import base64
import hashlib
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import stats, views_panel
from .models import Action, Event

User = get_user_model()
# Europe/Istanbul 12:30:30 (UTC+3): kovalar sabit ve kolay okunur olsun diye sabit an.
NOW = timezone.make_aware(datetime(2026, 11, 15, 12, 30, 30))


def make(ip="203.0.113.7", attack="port_scan", level="high", risk=0.9, ago=timedelta(0), summary=""):
    event = Event.objects.create(
        source_ip=ip, attack_type=attack, risk_score=risk, risk_level=level, summary=summary
    )
    Event.objects.filter(pk=event.pk).update(created_at=NOW - ago)  # auto_now_add'i aş
    return event


def make_action(status, event=None, kind="block_ip", ago=timedelta(0), **extra):
    action = Action.objects.create(
        event=event, kind=kind, target="203.0.113.7", status=status, **extra
    )
    Action.objects.filter(pk=action.pk).update(created_at=NOW - ago)
    return action


class StatsTests(TestCase):
    def test_empty_database_gives_zero_filled_series(self):
        data = stats.build_stats("24h", now=NOW)
        self.assertEqual(len(data["timeline"]), 24)
        self.assertTrue(all(p["low"] == p["medium"] == p["high"] == 0 for p in data["timeline"]))
        self.assertEqual(data["totals"]["events"], 0)
        self.assertEqual(data["attack_types"], [])
        self.assertEqual(data["top_sources"], [])
        self.assertEqual(data["action_statuses"], [])

    def test_bucket_counts_per_range(self):
        for key, count in (("1h", 60), ("24h", 24), ("7d", 7)):
            self.assertEqual(len(stats.build_stats(key, now=NOW)["timeline"]), count, key)

    def test_hour_buckets_are_counted_by_level_and_last_bucket_is_current_hour(self):
        make(level="high", ago=timedelta(minutes=5))      # 12:25 -> son kova (12:00)
        make(level="low", risk=0.55, ago=timedelta(minutes=10))
        make(level="medium", risk=0.75, ago=timedelta(hours=2))  # 10:30 -> 10:00 kovası
        data = stats.build_stats("24h", now=NOW)
        last, third_last = data["timeline"][-1], data["timeline"][-3]
        self.assertEqual((last["high"], last["low"], last["medium"]), (1, 1, 0))
        self.assertEqual((third_last["medium"], third_last["high"]), (1, 0))
        self.assertEqual(data["totals"]["events"], 3)
        self.assertEqual(data["totals"]["high_events"], 1)
        # Zaman etiketleri art arda, saatlik ve artan sırada.
        stamps = [datetime.fromisoformat(p["t"]) for p in data["timeline"]]
        self.assertEqual({b - a for a, b in zip(stamps, stamps[1:])}, {timedelta(hours=1)})

    def test_minute_buckets(self):
        make(ago=timedelta(seconds=10))     # 12:30:20 -> 12:30 kovası
        make(ago=timedelta(minutes=2))      # 12:28 kovası
        data = stats.build_stats("1h", now=NOW)
        self.assertEqual(data["timeline"][-1]["high"], 1)
        self.assertEqual(data["timeline"][-3]["high"], 1)

    def test_day_buckets_use_local_dates(self):
        make(ago=timedelta(hours=1))        # bugün 11:30
        make(ago=timedelta(hours=13))       # dün 23:30 yerel saat (UTC'de hâlâ 20:30 dün)
        data = stats.build_stats("7d", now=NOW)
        self.assertEqual(data["timeline"][-1]["t"], "2026-11-15")
        self.assertEqual(data["timeline"][-1]["high"], 1)
        self.assertEqual(data["timeline"][-2]["t"], "2026-11-14")
        self.assertEqual(data["timeline"][-2]["high"], 1)

    def test_events_outside_the_window_are_ignored(self):
        make(ago=timedelta(hours=30))
        make(ago=timedelta(minutes=5))
        self.assertEqual(stats.build_stats("24h", now=NOW)["totals"]["events"], 1)
        self.assertEqual(stats.build_stats("7d", now=NOW)["totals"]["events"], 2)

    def test_attack_types_top_n_and_other_row(self):
        for i in range(10):
            for _ in range(10 - i):
                make(attack=f"type_{i}", level="low", risk=0.5, ago=timedelta(minutes=1))
        data = stats.build_stats("24h", now=NOW)
        names = [r["name"] for r in data["attack_types"]]
        self.assertEqual(names[: stats.TOP_ATTACK_TYPES], [f"type_{i}" for i in range(8)])
        other = data["attack_types"][-1]
        self.assertEqual(other["name"], stats.OTHER_LABEL)
        self.assertEqual(other["count"], 2 + 1)  # type_8 (2) + type_9 (1)
        self.assertEqual(sum(r["count"] for r in data["attack_types"]), data["totals"]["events"])

    def test_top_sources_ordered_with_max_risk(self):
        for _ in range(3):
            make(ip="198.51.100.1", risk=0.6, level="low", ago=timedelta(minutes=1))
        make(ip="198.51.100.1", risk=0.95, ago=timedelta(minutes=1))
        make(ip="198.51.100.2", risk=0.8, level="medium", ago=timedelta(minutes=1))
        data = stats.build_stats("24h", now=NOW)
        self.assertEqual(data["top_sources"][0], {"ip": "198.51.100.1", "count": 4, "max_risk": 0.95})
        self.assertEqual(data["top_sources"][1]["ip"], "198.51.100.2")

    def test_top_sources_is_capped(self):
        for i in range(10):
            make(ip=f"198.51.100.{i}", ago=timedelta(minutes=1))
        self.assertEqual(len(stats.build_stats("24h", now=NOW)["top_sources"]), stats.TOP_SOURCES)

    def test_action_statuses_and_current_counters(self):
        event = make(ago=timedelta(minutes=1))
        make_action("pending_approval", event, approval_deadline=NOW + timedelta(minutes=10), ago=timedelta(minutes=1))
        make_action("pending_approval", event, approval_deadline=NOW - timedelta(minutes=1), ago=timedelta(minutes=2))
        make_action("executed", event, effect_expires_at=NOW + timedelta(minutes=5), ago=timedelta(minutes=3))
        make_action("executed", event, effect_expires_at=NOW - timedelta(minutes=5), ago=timedelta(minutes=4))
        make_action("refused", event, ago=timedelta(hours=40))  # pencere dışı
        data = stats.build_stats("24h", now=NOW)
        by_status = {r["status"]: r["count"] for r in data["action_statuses"]}
        self.assertEqual(by_status, {"pending_approval": 2, "executed": 2})
        self.assertEqual(data["totals"]["pending_actions"], 1)  # süresi dolan sayılmaz
        self.assertEqual(data["totals"]["active_blocks"], 1)    # süresi bitmiş engel sayılmaz

    def test_attacker_text_and_features_never_appear(self):
        Event.objects.create(
            source_ip="203.0.113.7", risk_score=0.9, risk_level="high",
            summary="<script>alert(1)</script>", features={"secret": "internal"},
        )
        body = str(stats.build_stats("24h"))
        self.assertNotIn("alert(1)", body)
        self.assertNotIn("internal", body)


class StatsViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def test_requires_staff_and_returns_json_403(self):
        resp = self.client.get("/panel/api/stats/")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json(), {"error": "yetkisiz"})
        self.client.force_login(self.plain)
        self.assertEqual(self.client.get("/panel/api/stats/").status_code, 403)

    def test_staff_gets_default_range_without_caching(self):
        self.client.force_login(self.staff)
        Event.objects.create(source_ip="203.0.113.7", risk_score=0.9, risk_level="high")
        resp = self.client.get("/panel/api/stats/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        data = resp.json()
        self.assertEqual(data["range"], "24h")
        self.assertEqual(data["totals"]["events"], 1)

    def test_each_range_and_invalid_range(self):
        self.client.force_login(self.staff)
        for key in stats.RANGES:
            self.assertEqual(self.client.get("/panel/api/stats/", {"range": key}).status_code, 200, key)
        for bad in ("2h", "", "24h; drop", "../x"):
            resp = self.client.get("/panel/api/stats/", {"range": bad})
            self.assertEqual(resp.status_code, 400, bad)

    def test_post_is_not_allowed(self):
        self.client.force_login(self.staff)
        self.assertEqual(self.client.post("/panel/api/stats/").status_code, 405)


class ChartAssetTests(TestCase):
    def test_vendored_chart_matches_sri_and_is_served(self):
        resp = self.client.get(views_panel.CHART_URL)  # oturumsuz da erişilebilir
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp["Content-Type"].startswith("text/javascript"))
        digest = base64.b64encode(hashlib.sha384(resp.content).digest()).decode()
        self.assertEqual(f"sha384-{digest}", views_panel.CHART_SRI)
        self.assertIn(b"Chart.js v" + views_panel.CHART_VERSION.encode(), resp.content)

    def test_panel_loads_chart_from_own_origin_under_strict_csp(self):
        staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.client.force_login(staff)
        resp = self.client.get("/panel/", HTTP_HOST="127.0.0.1:8000")
        body = resp.content.decode()
        self.assertIn(views_panel.CHART_URL, body)
        self.assertIn(views_panel.CHART_SRI, body)
        self.assertIn("/panel/api/stats/", body)
        csp = resp["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertNotIn("http", csp.split("script-src")[1].split(";")[0])
