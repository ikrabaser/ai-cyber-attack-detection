import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import incident_detail, incidents, realtime
from .ingest import ingest_event
from .models import Action, AnalysisRun, Event, Incident
from .tasks import investigate_event

User = get_user_model()
HOST = {"HTTP_HOST": "127.0.0.1:8000"}
SECRET = {"HTTP_X_CENTRIFUGO_PROXY_SECRET": "test-proxy-secret"}


def make_incident(ip="203.0.113.7", status=Incident.Status.NEW, ago=0, count=1, risk=0.9):
    seen = timezone.now() - timedelta(seconds=ago)
    return Incident.objects.create(
        source_ip=ip, status=status, risk_level="high", max_risk=risk, attack_type="brute_force",
        event_count=count, first_seen=seen, last_seen=seen,
    )


def make_event(incident, risk=0.9, features=None, summary=""):
    return Event.objects.create(
        source_ip=incident.source_ip, attack_type="brute_force", risk_score=risk, risk_level="high",
        incident=incident, features=features or {}, summary=summary,
    )


class IncidentPayloadTests(TestCase):
    def test_payload_fields_and_truncation(self):
        inc = make_incident()
        inc.summary = "s" * 900
        payload = realtime.incident_payload(inc)
        self.assertEqual(
            set(payload),
            {"type", "id", "source_ip", "status", "risk_level", "max_risk", "attack_type",
             "attck", "source_known_bad", "event_count", "first_seen", "last_seen", "closed_at", "summary"},
        )
        self.assertEqual(payload["type"], "incident")
        self.assertEqual(len(payload["summary"]), 300)
        self.assertIsNone(payload["closed_at"])

    def test_source_known_bad_flag_from_static_list(self):
        from django.test import override_settings

        with override_settings(THREAT_INTEL_BAD_IPS=["203.0.113.7"]):
            inc = make_incident(ip="203.0.113.7")
            self.assertTrue(realtime.incident_payload(inc)["source_known_bad"])

    def test_source_known_bad_false_when_not_listed(self):
        inc = make_incident(ip="198.51.100.9")
        self.assertFalse(realtime.incident_payload(inc)["source_known_bad"])


def incident_publishes(pub):
    return [c.args[1] for c in pub.call_args_list if c.args[0] == realtime.CHANNEL_INCIDENTS]


@mock.patch("core.ingest.enqueue_investigation")
@mock.patch("core.realtime.publish")
class IncidentPublishTests(TestCase):
    def test_ingest_publishes_incident_after_commit(self, pub, enq):
        with self.captureOnCommitCallbacks(execute=True):
            event = ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.92, "attack_type": "brute_force"})
        (payload,) = incident_publishes(pub)
        self.assertEqual((payload["id"], payload["event_count"], payload["status"]),
                         (event.incident_id, 1, "new"))

    def test_second_event_publishes_updated_count(self, pub, enq):
        with self.captureOnCommitCallbacks(execute=True):
            ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.75, "attack_type": "port_scan"})
            ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.95, "attack_type": "brute_force"})
        counts = [p["event_count"] for p in incident_publishes(pub)]
        self.assertEqual(counts, [1, 2])

    def test_nothing_published_before_commit(self, pub, enq):
        ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.92})
        self.assertEqual(incident_publishes(pub), [])

    def test_close_publishes_resolved_state(self, pub, enq):
        inc = make_incident(ago=7200)
        with self.captureOnCommitCallbacks(execute=True):
            incidents.close_idle()
        (payload,) = incident_publishes(pub)
        self.assertEqual((payload["id"], payload["status"]), (inc.pk, "resolved"))
        self.assertIsNotNone(payload["closed_at"])

    def test_agent_run_publishes_investigating_then_summary(self, pub, enq):
        with self.captureOnCommitCallbacks(execute=True):
            event = ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.92})
        pub.reset_mock()
        with mock.patch("core.tasks.get_agent") as get, self.captureOnCommitCallbacks(execute=True):
            get.return_value.name = "a"
            get.return_value.investigate.return_value = "özet metni"
            investigate_event(event.pk)
        states = [(p["status"], p["summary"]) for p in incident_publishes(pub)]
        self.assertEqual(states, [("investigating", ""), ("investigating", "özet metni")])


class IncidentDetailTests(TestCase):
    def test_parse_id_rejects_garbage(self):
        for bad in (None, "", "abc", "-1", "1.5", "１２", "1 2", "9" * 13, "0x10"):
            with self.assertRaises(incident_detail.IncidentError, msg=repr(bad)):
                incident_detail.parse_id(bad)
        self.assertEqual(incident_detail.parse_id(" 42 "), 42)

    def test_unknown_incident(self):
        with self.assertRaises(incident_detail.IncidentNotFound):
            incident_detail.build_incident("999999")

    def test_detail_collects_events_runs_and_actions(self):
        inc = make_incident(count=2)
        first = make_event(inc, risk=0.7, summary="ilk")
        second = make_event(inc, risk=0.9, summary="ikinci")
        other = make_incident(ip="203.0.113.8")
        make_event(other)
        AnalysisRun.objects.create(incident=inc, event=first, agent="rule-agent", status="ok", summary="not")
        AnalysisRun.objects.create(incident=other, agent="rule-agent", status="ok")
        Action.objects.create(event=second, kind="block_ip", target=inc.source_ip, status="pending_approval")
        Action.objects.create(event=other.events.first(), kind="block_ip", target="203.0.113.8",
                              status="pending_approval")

        data = incident_detail.build_incident(str(inc.pk))
        self.assertEqual(data["incident"]["id"], inc.pk)
        self.assertEqual([e["summary"] for e in data["events"]], ["ikinci", "ilk"])  # en yeni üstte
        self.assertEqual([r["summary"] for r in data["runs"]], ["not"])
        self.assertEqual([a["target"] for a in data["actions"]], [inc.source_ip])
        self.assertFalse(data["events_truncated"])

    def test_event_list_is_capped_and_flagged(self):
        inc = make_incident(count=incident_detail.MAX_EVENTS + 5)
        Event.objects.bulk_create([
            Event(source_ip=inc.source_ip, attack_type="x", risk_score=0.9, risk_level="high", incident=inc)
            for _ in range(incident_detail.MAX_EVENTS + 5)
        ])
        data = incident_detail.build_incident(str(inc.pk))
        self.assertEqual(len(data["events"]), incident_detail.MAX_EVENTS)
        self.assertTrue(data["events_truncated"])

    def test_protected_flag(self):
        inc = make_incident(ip="192.168.56.1")
        self.assertTrue(incident_detail.build_incident(str(inc.pk))["protected"])


class IncidentViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def get(self, params="", user=None):
        if user:
            self.client.force_login(user)
        return self.client.get(f"/panel/api/incident/{params}", **HOST)

    def test_non_staff_and_anonymous_get_403_json(self):
        inc = make_incident()
        for user in (None, self.plain):
            resp = self.get(f"?id={inc.pk}", user)
            self.assertEqual(resp.status_code, 403)
            self.assertEqual(resp.json(), {"error": "yetkisiz"})

    def test_bad_and_missing_ids(self):
        for params, code in (("", 400), ("?id=abc", 400), ("?id=-3", 400), ("?id=999999", 404)):
            self.assertEqual(self.get(params, self.staff).status_code, code, params)

    def test_success_never_exposes_features(self):
        inc = make_incident()
        make_event(inc, features={"gizli": "saldırgan kontrollü"}, summary="özet")
        resp = self.get(f"?id={inc.pk}", self.staff)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        self.assertNotIn("gizli", resp.content.decode())
        self.assertNotIn("features", resp.json()["events"][0])

    def test_post_not_allowed(self):
        self.client.force_login(self.staff)
        self.assertEqual(self.client.post("/panel/api/incident/", {}, **HOST).status_code, 405)


class IncidentSnapshotAndChannelTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)

    def test_snapshot_lists_incidents_newest_activity_first_and_capped(self):
        for i in range(55):
            make_incident(ip=f"203.0.113.{i}", ago=1000 - i)
        self.client.force_login(self.staff)
        data = self.client.get("/panel/api/snapshot/", **HOST).json()
        rows = data["incidents"]
        self.assertEqual(len(rows), 50)
        times = [r["last_seen"] for r in rows]
        self.assertEqual(times, sorted(times, reverse=True))

    def test_staff_can_subscribe_to_incident_channel_others_cannot(self):
        plain = User.objects.create_user("guest", password="x")
        body = {"user": str(self.staff.pk), "channel": realtime.CHANNEL_INCIDENTS}
        ok = self.client.post("/centrifugo/subscribe/", json.dumps(body), content_type="application/json", **SECRET)
        self.assertEqual(ok.json(), {"result": {}})
        body["user"] = str(plain.pk)
        denied = self.client.post("/centrifugo/subscribe/", json.dumps(body), content_type="application/json", **SECRET)
        self.assertEqual(denied.json()["error"]["code"], 403)

    def test_panel_has_incident_cards_and_config_under_strict_csp(self):
        self.client.force_login(self.staff)
        resp = self.client.get("/panel/", **HOST)
        body = resp.content.decode()
        for needle in ('id="inc-body"', 'id="incd-card"', "/panel/api/incident/", realtime.CHANNEL_INCIDENTS):
            self.assertIn(needle, body)
        self.assertNotIn("unsafe-inline", resp["Content-Security-Policy"])
