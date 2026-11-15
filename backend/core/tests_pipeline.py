import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import audit, realtime
from .models import AuditLog, Event
from .tasks import investigate_event

User = get_user_model()
SECRET = {"HTTP_X_CENTRIFUGO_PROXY_SECRET": "test-proxy-secret"}


def pipeline_calls(pub):
    return [c.args[1] for c in pub.call_args_list if c.args[0] == realtime.CHANNEL_PIPELINE]


@mock.patch("core.realtime.publish")
class PipelinePublishTests(TestCase):
    def test_record_publishes_step_after_commit(self, pub):
        with self.captureOnCommitCallbacks(execute=True):
            entry = audit.record("rule-agent", "propose_block_ip", "203.0.113.7", "proposed",
                                 event_id=4, action_id=9, ttl_seconds=600)
        (step,) = pipeline_calls(pub)
        self.assertEqual(step["id"], entry.pk)
        self.assertEqual(step["verb"], "propose_block_ip")
        self.assertEqual((step["event_id"], step["action_id"]), (4, 9))
        self.assertEqual(step["outcome"], "proposed")

    def test_nothing_published_before_commit(self, pub):
        audit.record("system", "send_notification", "", "sent")  # TestCase: on_commit çalışmaz
        self.assertEqual(pipeline_calls(pub), [])

    def test_publish_failure_does_not_break_record(self, pub):
        pub.side_effect = RuntimeError("centrifugo down")
        with self.assertLogs("core.audit", "ERROR"), self.captureOnCommitCallbacks(execute=True):
            audit.record("system", "send_notification", "", "sent")
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_payload_is_whitelisted(self, pub):
        with self.captureOnCommitCallbacks(execute=True):
            audit.record("user:42", "execute_block_ip", "203.0.113.7", "failed", action_id=3,
                         error="Traceback: parola=hunter2", reason="gizli", features={"a": 1}, recipients=3)
        (step,) = pipeline_calls(pub)
        self.assertEqual(set(step), {"type", "id", "created_at", "actor", "verb", "target", "outcome",
                                     "event_id", "action_id"})
        self.assertEqual(step["actor"], "user")  # kullanıcı numarası yayınlanmaz
        self.assertNotIn("hunter2", json.dumps(step))

    def test_ids_must_be_integers(self, pub):
        with self.captureOnCommitCallbacks(execute=True):
            audit.record("sensor", "ingest_event", "203.0.113.7", "created", event_id="7; drop", action_id=True)
        (step,) = pipeline_calls(pub)
        self.assertIsNone(step["event_id"])
        self.assertIsNone(step["action_id"])

    def test_target_is_truncated(self, pub):
        with self.captureOnCommitCallbacks(execute=True):
            audit.record("system", "x", "a" * 250, "ok")
        self.assertEqual(len(pipeline_calls(pub)[0]["target"]), 100)

    def test_note_only_for_investigation(self, pub):
        with self.captureOnCommitCallbacks(execute=True):
            audit.record("worker", "investigate_event", "203.0.113.7", "done", event_id=1, note="n" * 500)
            audit.record("system", "send_notification", "", "sent", note="sızmamalı")
        first, second = pipeline_calls(pub)
        self.assertEqual(len(first["note"]), realtime.NOTE_MAX)
        self.assertNotIn("note", second)

    def test_worker_step_carries_agent_summary(self, pub):
        event = Event.objects.create(source_ip="203.0.113.7", attack_type="port_scan",
                                     risk_score=0.9, risk_level="high")
        with mock.patch("core.tasks.get_agent") as agent, self.captureOnCommitCallbacks(execute=True):
            agent.return_value.investigate.return_value = "Agent notu: tarama şüphesi"
            investigate_event(event.pk)
        steps = [s for s in pipeline_calls(pub) if s["verb"] == "investigate_event"]
        self.assertEqual(steps[0]["note"], "Agent notu: tarama şüphesi")


class PipelineAccessTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def post(self, body):
        return self.client.post("/centrifugo/subscribe/", json.dumps(body),
                                content_type="application/json", **SECRET)

    def test_staff_can_subscribe_but_others_cannot(self):
        ok = self.post({"user": str(self.staff.pk), "channel": realtime.CHANNEL_PIPELINE})
        self.assertEqual(ok.json(), {"result": {}})
        for user in (str(self.plain.pk), ""):
            denied = self.post({"user": user, "channel": realtime.CHANNEL_PIPELINE})
            self.assertEqual(denied.json()["error"]["code"], 403)

    def test_subscribe_requires_proxy_secret(self):
        resp = self.client.post("/centrifugo/subscribe/",
                                json.dumps({"user": str(self.staff.pk), "channel": realtime.CHANNEL_PIPELINE}),
                                content_type="application/json")
        self.assertEqual(resp.status_code, 403)


class PipelineSnapshotTests(TestCase):
    def test_snapshot_returns_recent_steps_newest_first_and_capped(self):
        staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.client.force_login(staff)
        with mock.patch("core.realtime.publish"):
            for i in range(50):
                audit.record("sensor", "ingest_event", "203.0.113.7", "created", event_id=i, error="gizli")
        data = self.client.get("/panel/api/snapshot/", HTTP_HOST="127.0.0.1:8000").json()
        steps = data["steps"]
        self.assertEqual(len(steps), 40)
        self.assertGreater(steps[0]["id"], steps[1]["id"])
        self.assertNotIn("gizli", json.dumps(steps))
        self.assertNotIn("detail", steps[0])

    def test_snapshot_still_forbidden_for_non_staff(self):
        self.client.force_login(User.objects.create_user("guest", password="x"))
        resp = self.client.get("/panel/api/snapshot/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp.status_code, 403)


class PipelinePanelUiTests(TestCase):
    def test_panel_subscribes_to_pipeline_and_has_flow_card(self):
        staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.client.force_login(staff)
        resp = self.client.get("/panel/", HTTP_HOST="127.0.0.1:8000")
        body = resp.content.decode()
        for needle in ('id="flow-list"', 'id="flow-toggle"', realtime.CHANNEL_PIPELINE):
            self.assertIn(needle, body)
        self.assertNotIn("unsafe-inline", resp["Content-Security-Policy"])
