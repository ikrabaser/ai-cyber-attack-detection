from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import source_detail
from .models import Action, Event

User = get_user_model()
IP = "198.51.100.4"


def make(ip=IP, attack="port_scan", level="high", risk=0.9, ago=timedelta(0), summary=""):
    event = Event.objects.create(
        source_ip=ip, attack_type=attack, risk_score=risk, risk_level=level, summary=summary
    )
    Event.objects.filter(pk=event.pk).update(created_at=timezone.now() - ago)
    return event


class SourceDetailTests(TestCase):
    def test_invalid_ips_are_rejected(self):
        for bad in (None, "", "abc", "1.2.3", "1.2.3.4/24", "1.2.3.4; drop", "198.51.100.%", "1.2.3.256"):
            with self.assertRaises(source_detail.SourceError, msg=bad):
                source_detail.build_source(bad)

    def test_ipv6_is_normalized(self):
        make("2001:db8::1")
        data = source_detail.build_source("2001:DB8:0:0:0:0:0:1")
        self.assertEqual(data["ip"], "2001:db8::1")
        self.assertEqual(data["totals"]["events"], 1)

    def test_unknown_ip_gives_empty_but_valid_detail(self):
        data = source_detail.build_source("203.0.113.99")
        self.assertEqual(data["totals"], {"events": 0, "first_seen": None, "last_seen": None, "max_risk": None})
        self.assertEqual((data["events"], data["actions"], data["attack_types"]), ([], [], []))
        self.assertFalse(data["events_truncated"])

    def test_events_are_oldest_first_and_only_this_ip(self):
        newest = make(ago=timedelta(minutes=1), risk=0.95)
        oldest = make(ago=timedelta(hours=2), risk=0.55, level="low")
        make("198.51.100.5")  # başka kaynak
        data = source_detail.build_source(IP)
        self.assertEqual([e["id"] for e in data["events"]], [oldest.pk, newest.pk])
        self.assertEqual(data["totals"]["events"], 2)
        self.assertEqual(data["totals"]["max_risk"], 0.95)
        self.assertLess(data["totals"]["first_seen"], data["totals"]["last_seen"])

    def test_timeline_is_capped_to_newest_events_and_flags_truncation(self):
        Event.objects.bulk_create(
            [
                Event(source_ip=IP, attack_type="flood", risk_score=0.6, risk_level="low")
                for _ in range(source_detail.TIMELINE_EVENTS + 7)
            ]
        )
        data = source_detail.build_source(IP)
        ids = [e["id"] for e in data["events"]]
        self.assertEqual(len(ids), source_detail.TIMELINE_EVENTS)
        self.assertEqual(ids, sorted(ids))  # eskiden yeniye
        self.assertEqual(data["totals"]["events"], source_detail.TIMELINE_EVENTS + 7)
        self.assertTrue(data["events_truncated"])
        self.assertEqual(ids[-1], Event.objects.filter(source_ip=IP).order_by("-created_at", "-id").first().pk)

    def test_attack_types_counted(self):
        for _ in range(3):
            make(attack="brute_force")
        make(attack="port_scan")
        self.assertEqual(
            source_detail.build_source(IP)["attack_types"],
            [{"name": "brute_force", "count": 3}, {"name": "port_scan", "count": 1}],
        )

    def test_actions_by_target_or_by_event_but_not_other_ips(self):
        event = make()
        other = make("198.51.100.5")
        by_target = Action.objects.create(kind="block_ip", target=IP, status="executed")
        by_event = Action.objects.create(event=event, kind="isolate_host", target="web-01", status="pending_approval")
        Action.objects.create(event=other, kind="block_ip", target="198.51.100.5", status="executed")
        data = source_detail.build_source(IP)
        self.assertEqual({a["id"] for a in data["actions"]}, {by_target.pk, by_event.pk})
        self.assertEqual(len(data["actions"]), 2)  # OR + JOIN çift satır üretmez
        self.assertIn("created_at", data["actions"][0])

    def test_protected_flag_and_thresholds(self):
        self.assertTrue(source_detail.build_source("192.168.56.1")["protected"])
        data = source_detail.build_source(IP)
        self.assertFalse(data["protected"])
        self.assertEqual(set(data["thresholds"]), {"low", "medium", "high"})

    def test_features_and_long_summary_do_not_leak(self):
        Event.objects.create(
            source_ip=IP, attack_type="x", risk_score=0.9, risk_level="high",
            features={"secret": "internal"}, summary="y" * 800,
        )
        data = source_detail.build_source(IP)
        self.assertNotIn("internal", str(data))
        self.assertEqual(len(data["events"][0]["summary"]), 500)


class SourceViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def test_requires_staff_and_returns_json_403(self):
        resp = self.client.get("/panel/api/source/", {"ip": IP})
        self.assertEqual((resp.status_code, resp.json()), (403, {"error": "yetkisiz"}))
        self.client.force_login(self.plain)
        self.assertEqual(self.client.get("/panel/api/source/", {"ip": IP}).status_code, 403)

    def test_staff_gets_detail_without_caching(self):
        self.client.force_login(self.staff)
        make()
        resp = self.client.get("/panel/api/source/", {"ip": IP})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        self.assertEqual(resp.json()["totals"]["events"], 1)

    def test_bad_or_missing_ip_gives_400_json(self):
        self.client.force_login(self.staff)
        for params in ({}, {"ip": ""}, {"ip": "nope"}, {"ip": "198.51.100.%"}):
            resp = self.client.get("/panel/api/source/", params)
            self.assertEqual(resp.status_code, 400, params)
            self.assertIn("error", resp.json())

    def test_post_is_not_allowed(self):
        self.client.force_login(self.staff)
        self.assertEqual(self.client.post("/panel/api/source/").status_code, 405)

    def test_panel_config_exposes_source_url(self):
        self.client.force_login(self.staff)
        self.assertIn("/panel/api/source/", self.client.get("/panel/").content.decode())
