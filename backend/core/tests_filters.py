from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase

from . import event_filters
from .models import Event

User = get_user_model()


def make(ip="203.0.113.7", attack="port_scan", level="high", risk=0.9, ago=timedelta(0), summary=""):
    from django.utils import timezone

    event = Event.objects.create(
        source_ip=ip, attack_type=attack, risk_score=risk, risk_level=level, summary=summary
    )
    Event.objects.filter(pk=event.pk).update(created_at=timezone.now() - ago)
    return event


class ParseTests(TestCase):
    def test_defaults(self):
        self.assertEqual(
            event_filters.parse({}), {"ip": "", "attack_type": "", "min_level": "", "range": "all"}
        )

    def test_ip_is_lowercased_and_trimmed(self):
        self.assertEqual(event_filters.parse({"ip": " 2001:DB8:: "})["ip"], "2001:db8::")

    def test_rejects_bad_values(self):
        for bad in (
            {"ip": "198.51.100.%"},        # LIKE jokeri
            {"ip": "198.51.100.1'; --"},
            {"ip": "a" * 46},
            {"ip": "198.51.100.x"},
            {"attack_type": "x" * 65},
            {"min_level": "critical"},
            {"range": "30d"},
        ):
            with self.assertRaises(event_filters.FilterError, msg=bad):
                event_filters.parse(bad)


class EventsViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")
        self.client.force_login(self.staff)
        self.a = make("198.51.100.1", "port_scan", "low", 0.55, timedelta(minutes=10))
        self.b = make("198.51.100.2", "brute_force", "medium", 0.75, timedelta(hours=3))
        self.c = make("198.51.100.10", "brute_force", "high", 0.95, timedelta(days=2))
        self.d = make("203.0.113.5", "port_scan", "high", 0.92, timedelta(days=10))

    def ids(self, **params):
        resp = self.client.get("/panel/api/events/", params)
        self.assertEqual(resp.status_code, 200, resp.content)
        return [e["id"] for e in resp.json()["events"]]

    def test_requires_staff_and_returns_json_403(self):
        self.client.logout()
        resp = self.client.get("/panel/api/events/")
        self.assertEqual((resp.status_code, resp.json()), (403, {"error": "yetkisiz"}))
        self.client.force_login(self.plain)
        self.assertEqual(self.client.get("/panel/api/events/").status_code, 403)

    def test_post_is_not_allowed(self):
        self.assertEqual(self.client.post("/panel/api/events/").status_code, 405)

    def test_no_filter_lists_newest_first_with_total(self):
        resp = self.client.get("/panel/api/events/")
        data = resp.json()
        self.assertEqual([e["id"] for e in data["events"]], [self.d.pk, self.c.pk, self.b.pk, self.a.pk])
        self.assertEqual((data["total"], data["limit"]), (4, event_filters.LIMIT))
        self.assertEqual(resp["Cache-Control"], "no-store")
        self.assertEqual(data["events"][0]["type"], "event")  # canlı akışla aynı biçim

    def test_ip_prefix(self):
        self.assertEqual(self.ids(ip="198.51.100."), [self.c.pk, self.b.pk, self.a.pk])
        self.assertEqual(self.ids(ip="198.51.100.1"), [self.c.pk, self.a.pk])  # .1 ve .10
        self.assertEqual(self.ids(ip="203."), [self.d.pk])
        self.assertEqual(self.ids(ip="10."), [])

    def test_attack_type_is_exact(self):
        self.assertEqual(self.ids(attack_type="brute_force"), [self.c.pk, self.b.pk])
        self.assertEqual(self.ids(attack_type="brute"), [])

    def test_min_level_means_at_least(self):
        self.assertEqual(self.ids(min_level="high"), [self.d.pk, self.c.pk])
        self.assertEqual(self.ids(min_level="medium"), [self.d.pk, self.c.pk, self.b.pk])
        self.assertEqual(len(self.ids(min_level="low")), 4)

    def test_time_range(self):
        self.assertEqual(self.ids(range="1h"), [self.a.pk])
        self.assertEqual(self.ids(range="24h"), [self.b.pk, self.a.pk])
        self.assertEqual(self.ids(range="7d"), [self.c.pk, self.b.pk, self.a.pk])
        self.assertEqual(len(self.ids(range="all")), 4)

    def test_filters_combine(self):
        self.assertEqual(self.ids(ip="198.51.100.", attack_type="brute_force", min_level="high"), [self.c.pk])
        self.assertEqual(self.ids(ip="198.51.100.", range="24h", min_level="medium"), [self.b.pk])

    def test_total_counts_all_matches_but_list_is_capped(self):
        Event.objects.bulk_create(
            [
                Event(source_ip="192.0.2.1", attack_type="flood", risk_score=0.6, risk_level="low")
                for _ in range(event_filters.LIMIT + 5)
            ]
        )
        data = self.client.get("/panel/api/events/", {"attack_type": "flood"}).json()
        self.assertEqual(len(data["events"]), event_filters.LIMIT)
        self.assertEqual(data["total"], event_filters.LIMIT + 5)

    def test_invalid_parameters_give_400_json(self):
        for params in ({"ip": "1.2.3.%"}, {"min_level": "x"}, {"range": "2h"}, {"attack_type": "x" * 65}):
            resp = self.client.get("/panel/api/events/", params)
            self.assertEqual(resp.status_code, 400, params)
            self.assertIn("error", resp.json())

    def test_features_and_full_summary_do_not_leak(self):
        Event.objects.create(
            source_ip="192.0.2.9", attack_type="x", risk_score=0.9, risk_level="high",
            features={"secret": "internal"}, summary="y" * 800,
        )
        resp = self.client.get("/panel/api/events/", {"ip": "192.0.2.9"})
        self.assertNotIn("internal", resp.content.decode())
        self.assertEqual(len(resp.json()["events"][0]["summary"]), 500)


class PanelFilterUiTests(TestCase):
    def test_panel_has_filter_form_and_events_url_under_strict_csp(self):
        staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.client.force_login(staff)
        resp = self.client.get("/panel/", HTTP_HOST="127.0.0.1:8000")
        body = resp.content.decode()
        for needle in ('id="f-ip"', 'id="f-attack"', 'id="f-level"', 'id="f-range"', "/panel/api/events/"):
            self.assertIn(needle, body)
        csp = resp["Content-Security-Policy"]
        self.assertNotIn("unsafe-inline", csp)
        self.assertIn("form-action 'none'", csp)  # form gönderilemez; JS submit'i zaten engeller
