import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from . import actions
from .actions import ActionError
from .agent import RuleAgent
from .ingest import IngestError, ingest_event
from .models import Action, AuditLog, Event
from .protection import is_protected_ip, is_protected_target

User = get_user_model()
SECRET = {"HTTP_X_CENTRIFUGO_PROXY_SECRET": "test-proxy-secret"}


def make_event(ip="203.0.113.7", risk=0.92, level=Event.Level.HIGH):
    return Event.objects.create(
        source_ip=ip, attack_type="ssh_bruteforce", risk_score=risk, risk_level=level
    )


class ProtectionTests(TestCase):
    def test_listed_ip_and_cidr_are_protected(self):
        self.assertTrue(is_protected_ip("192.168.56.1"))
        self.assertTrue(is_protected_ip("10.0.0.55"))  # CIDR içinde
        self.assertFalse(is_protected_ip("203.0.113.7"))

    def test_unparseable_is_protected_fail_closed(self):
        self.assertTrue(is_protected_ip("not-an-ip"))
        self.assertTrue(is_protected_ip(""))

    def test_loopback_always_protected(self):
        self.assertTrue(is_protected_ip("127.0.0.1"))

    def test_hostnames(self):
        self.assertTrue(is_protected_target("Sensor"))
        self.assertFalse(is_protected_target("web-01"))


class ActionDedupTests(TestCase):
    """Sensör aynı saldırgan için her pencerede olay üretir; eylem yığılmamalı."""

    IP = "203.0.113.7"

    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)

    def propose(self, kind="block_ip", target=None, **kw):
        return actions.propose_action(make_event(), kind, target or self.IP, **kw)

    def count(self, **filters):
        return Action.objects.filter(**filters).count()

    def test_repeated_proposal_returns_the_same_pending_action(self):
        first = self.propose()
        second = self.propose()
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(self.count(), 1)
        self.assertTrue(AuditLog.objects.filter(outcome="deduplicated", target=self.IP).exists())

    def test_isolate_host_is_deduplicated_too(self):
        self.assertEqual(self.propose("isolate_host", "web-01").pk, self.propose("isolate_host", "web-01").pk)

    def test_different_target_or_kind_is_not_a_duplicate(self):
        self.propose()
        self.propose(target="203.0.113.8")
        self.propose("isolate_host", self.IP)
        self.assertEqual(self.count(), 3)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_active_block_is_not_repeated(self):
        first = self.propose(params={"ttl_seconds": 120})
        self.assertEqual(first.status, Action.Status.EXECUTED)
        self.assertEqual(self.propose(params={"ttl_seconds": 120}).pk, first.pk)
        self.assertEqual(self.count(), 1)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_new_proposal_allowed_after_block_ttl_ran_out(self):
        first = self.propose(params={"ttl_seconds": 120})
        Action.objects.filter(pk=first.pk).update(effect_expires_at=timezone.now() - timedelta(seconds=1))
        self.assertNotEqual(self.propose(params={"ttl_seconds": 120}).pk, first.pk)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_new_proposal_allowed_after_rollback(self):
        first = self.propose(params={"ttl_seconds": 120})
        actions.rollback_by_user(first.pk, self.staff)
        self.assertNotEqual(self.propose(params={"ttl_seconds": 120}).pk, first.pk)

    def test_new_proposal_allowed_after_rejection(self):
        first = self.propose()
        actions.reject_action(first.pk, self.staff)
        self.assertNotEqual(self.propose().pk, first.pk)

    def test_new_proposal_allowed_after_approval_deadline_passed(self):
        first = self.propose()
        Action.objects.filter(pk=first.pk).update(approval_deadline=timezone.now() - timedelta(seconds=1))
        self.assertNotEqual(self.propose().pk, first.pk)

    @override_settings(AUTO_REMEDIATION_MODE="dry_run", AUTO_BLOCK_TTL_SECONDS=600)
    def test_dry_run_counts_only_within_ttl_window(self):
        first = self.propose()
        self.assertEqual(first.status, Action.Status.DRY_RUN)
        self.assertEqual(self.propose().pk, first.pk)
        Action.objects.filter(pk=first.pk).update(created_at=timezone.now() - timedelta(seconds=601))
        self.assertNotEqual(self.propose().pk, first.pk)

    def test_config_fix_is_not_deduplicated(self):
        params = {"fix_id": "ssh_disable_password_auth"}
        self.propose("config_fix", "web-01", params=params)
        self.propose("config_fix", "web-01", params=params)
        self.assertEqual(self.count(kind="config_fix"), 2)

    def test_protected_target_is_still_refused_each_time(self):
        for _ in range(2):
            self.assertEqual(self.propose(target="192.168.56.10").status, Action.Status.REFUSED)
        self.assertEqual(self.count(status=Action.Status.REFUSED), 2)


class ActionPolicyTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")
        self.event = make_event()

    def test_protected_ip_is_refused_and_audited(self):
        action = actions.propose_action(make_event("192.168.56.10"), "block_ip", "192.168.56.10")
        self.assertEqual(action.status, Action.Status.REFUSED)
        self.assertTrue(AuditLog.objects.filter(outcome="refused", target="192.168.56.10").exists())

    def test_advise_mode_requires_approval_for_block(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)
        self.assertTrue(action.requires_approval)
        self.assertIsNotNone(action.approval_deadline)

    @override_settings(AUTO_REMEDIATION_MODE="dry_run")
    def test_dry_run_mode_auto_block_is_not_applied(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        self.assertEqual(action.status, Action.Status.DRY_RUN)
        self.assertFalse(action.requires_approval)
        self.assertIsNone(action.effect_expires_at)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_enforce_mode_auto_block_has_ttl(self):
        action = actions.propose_action(
            self.event, "block_ip", "203.0.113.7", params={"ttl_seconds": 120}
        )
        self.assertEqual(action.status, Action.Status.EXECUTED)
        self.assertIsNotNone(action.effect_expires_at)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_long_ttl_block_needs_approval_even_in_enforce(self):
        action = actions.propose_action(
            self.event, "block_ip", "203.0.113.7", params={"ttl_seconds": 7200}
        )
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)

    @override_settings(AUTO_REMEDIATION_MODE="enforce")
    def test_isolate_always_needs_approval(self):
        action = actions.propose_action(self.event, "isolate_host", "web-01")
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)

    def test_invalid_ttl_rejected(self):
        for bad in ("abc", 0, -5, 10**9):
            with self.assertRaises(ActionError):
                actions.propose_action(self.event, "block_ip", "203.0.113.7", params={"ttl_seconds": bad})

    def test_config_fix_must_be_allowlisted(self):
        with self.assertRaises(ActionError):
            actions.propose_action(self.event, "config_fix", "web-01", params={"fix_id": "rm -rf /"})
        ok = actions.propose_action(
            self.event, "config_fix", "web-01", params={"fix_id": "ssh_disable_password_auth"}
        )
        self.assertEqual(ok.status, Action.Status.PENDING_APPROVAL)

    def test_non_staff_cannot_approve(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        with self.assertRaises(ActionError) as ctx:
            actions.approve_action(action.pk, self.plain)
        self.assertEqual(ctx.exception.code, 403)
        action.refresh_from_db()
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)

    def test_staff_approval_executes_and_records_decider(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        done = actions.approve_action(action.pk, self.staff)
        self.assertEqual(done.status, Action.Status.EXECUTED)
        self.assertEqual(done.decided_by, self.staff)
        self.assertTrue(AuditLog.objects.filter(actor=f"user:{self.staff.pk}").exists())

    def test_cannot_approve_twice(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        actions.approve_action(action.pk, self.staff)
        with self.assertRaises(ActionError) as ctx:
            actions.approve_action(action.pk, self.staff)
        self.assertEqual(ctx.exception.code, 409)

    def test_protection_rechecked_at_execution_time(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        with override_settings(PROTECTED_IPS=["203.0.113.7"]):
            done = actions.approve_action(action.pk, self.staff)
        self.assertEqual(done.status, Action.Status.REFUSED)

    def test_expired_approval_cannot_be_executed(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        Action.objects.filter(pk=action.pk).update(approval_deadline=timezone.now() - timedelta(seconds=1))
        with self.assertRaises(ActionError) as ctx:
            actions.approve_action(action.pk, self.staff)
        self.assertEqual(ctx.exception.code, 409)

    def test_reject(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        done = actions.reject_action(action.pk, self.staff)
        self.assertEqual(done.status, Action.Status.REJECTED)

    def test_expire_due_actions_closes_stale_approvals_and_rolls_back_ttl(self):
        stale = actions.propose_action(self.event, "block_ip", "203.0.113.8")
        Action.objects.filter(pk=stale.pk).update(approval_deadline=timezone.now() - timedelta(seconds=1))

        live = actions.approve_action(
            actions.propose_action(self.event, "block_ip", "203.0.113.9").pk, self.staff
        )
        Action.objects.filter(pk=live.pk).update(effect_expires_at=timezone.now() - timedelta(seconds=1))

        counts = actions.expire_due_actions()
        self.assertEqual(counts, {"expired": 1, "rolled_back": 1})
        stale.refresh_from_db()
        live.refresh_from_db()
        self.assertEqual(stale.status, Action.Status.EXPIRED)
        self.assertEqual(live.status, Action.Status.ROLLED_BACK)

    def test_manual_rollback(self):
        action = actions.approve_action(
            actions.propose_action(self.event, "block_ip", "203.0.113.7").pk, self.staff
        )
        back = actions.rollback_by_user(action.pk, self.staff)
        self.assertEqual(back.status, Action.Status.ROLLED_BACK)

    def test_backend_failure_marks_failed(self):
        action = actions.propose_action(self.event, "block_ip", "203.0.113.7")
        with mock.patch("core.actions.get_backend", side_effect=RuntimeError("boom")):
            done = actions.approve_action(action.pk, self.staff)
        self.assertEqual(done.status, Action.Status.FAILED)

    def test_realtime_publish_happens_after_commit(self):
        with mock.patch("core.realtime.publish") as pub:
            with self.captureOnCommitCallbacks(execute=True):
                actions.propose_action(self.event, "block_ip", "203.0.113.7")
        self.assertTrue(pub.called)
        self.assertEqual(pub.call_args[0][0], "events:actions")


class RuleAgentTests(TestCase):
    def test_high_risk_proposes_block(self):
        event = make_event()
        summary = RuleAgent().investigate(event)
        self.assertEqual(Action.objects.filter(event=event, kind="block_ip").count(), 1)
        self.assertIn("Öneri", summary)

    def test_low_risk_proposes_nothing(self):
        event = make_event(risk=0.55, level=Event.Level.LOW)
        RuleAgent().investigate(event)
        self.assertEqual(Action.objects.count(), 0)

    def test_protected_source_is_refused_through_agent(self):
        event = make_event(ip="192.168.56.1")
        RuleAgent().investigate(event)
        self.assertEqual(Action.objects.get(event=event).status, Action.Status.REFUSED)


@mock.patch("core.ingest.enqueue_investigation")
@mock.patch("core.realtime.publish")
class IngestTests(TestCase):
    def test_below_threshold_ignored(self, pub, enq):
        self.assertIsNone(ingest_event({"source_ip": "203.0.113.7", "risk_score": 0.2}))
        self.assertEqual(Event.objects.count(), 0)

    def test_creates_event_publishes_and_enqueues(self, pub, enq):
        with self.captureOnCommitCallbacks(execute=True):
            event = ingest_event(
                {"source_ip": "203.0.113.7", "risk_score": 0.95, "attack_type": "port_scan"}
            )
        self.assertEqual(event.risk_level, Event.Level.HIGH)
        self.assertEqual(pub.call_args[0][0], "events:feed")
        enq.assert_called_once()

    def test_validation(self, pub, enq):
        for bad in (
            {"source_ip": "nope", "risk_score": 0.9},
            {"source_ip": "203.0.113.7"},
            {"source_ip": "203.0.113.7", "risk_score": 1.5},
            {"source_ip": "203.0.113.7", "risk_score": "x"},
            {"source_ip": "203.0.113.7", "risk_score": 0.9, "features": [1]},
            [],
        ):
            with self.subTest(bad=bad), self.assertRaises(IngestError):
                ingest_event(bad)

    def test_http_endpoint_auth(self, pub, enq):
        url = "/api/events/"
        body = json.dumps({"source_ip": "203.0.113.7", "risk_score": 0.8})
        self.assertEqual(self.client.post(url, body, content_type="application/json").status_code, 401)
        bad = self.client.post(url, body, content_type="application/json",
                               HTTP_AUTHORIZATION="Bearer wrong")
        self.assertEqual(bad.status_code, 401)
        ok = self.client.post(url, body, content_type="application/json",
                              HTTP_AUTHORIZATION="Bearer test-sensor-token")
        self.assertEqual(ok.status_code, 201)

    @override_settings(SENSOR_API_TOKEN="")
    def test_http_endpoint_closed_without_token(self, pub, enq):
        resp = self.client.post("/api/events/", "{}", content_type="application/json",
                                HTTP_AUTHORIZATION="Bearer ")
        self.assertEqual(resp.status_code, 401)


class CentrifugoProxyTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def post(self, path, body=None, secret=True):
        extra = SECRET if secret else {}
        return self.client.post(path, json.dumps(body or {}), content_type="application/json", **extra)

    def test_secret_required_everywhere(self):
        for path in ("connect", "refresh", "subscribe", "rpc"):
            self.assertEqual(self.post(f"/centrifugo/{path}/", secret=False).status_code, 403, path)

    @override_settings(RT_PROXY_SECRET="")
    def test_closed_when_secret_not_configured(self):
        resp = self.client.post("/centrifugo/connect/", "{}", content_type="application/json",
                                HTTP_X_CENTRIFUGO_PROXY_SECRET="")
        self.assertEqual(resp.status_code, 403)

    def test_connect_staff_session(self):
        self.client.force_login(self.staff)
        data = self.post("/centrifugo/connect/").json()
        self.assertEqual(data["result"]["user"], str(self.staff.pk))
        self.assertIn("expire_at", data["result"])

    def test_connect_anonymous_or_non_staff_disconnected(self):
        self.assertIn("disconnect", self.post("/centrifugo/connect/").json())
        self.client.force_login(self.plain)
        self.assertIn("disconnect", self.post("/centrifugo/connect/").json())

    def test_refresh(self):
        self.client.force_login(self.staff)
        ok = self.post("/centrifugo/refresh/", {"user": str(self.staff.pk)}).json()
        self.assertIn("expire_at", ok["result"])
        gone = self.post("/centrifugo/refresh/", {"user": "99999"}).json()
        self.assertTrue(gone["result"]["expired"])

    @override_settings(RT_SESSION_TTL_SECONDS=10)
    def test_session_lifetime_is_configurable(self):
        import time

        self.client.force_login(self.staff)
        data = self.post("/centrifugo/connect/").json()
        self.assertTrue(8 <= data["result"]["expire_at"] - int(time.time()) <= 12)
        again = self.post("/centrifugo/refresh/", {"user": str(self.staff.pk)}).json()
        self.assertTrue(8 <= again["result"]["expire_at"] - int(time.time()) <= 12)

    def test_refresh_without_cookie_expires(self):
        out = self.post("/centrifugo/refresh/", {"user": str(self.staff.pk)}).json()
        self.assertTrue(out["result"]["expired"])

    def test_subscribe(self):
        uid = str(self.staff.pk)
        self.assertEqual(self.post("/centrifugo/subscribe/", {"user": uid, "channel": "events:feed"}).json(),
                         {"result": {}})
        for body in (
            {"user": uid, "channel": "events:secret"},
            {"user": str(self.plain.pk), "channel": "events:feed"},
            {"user": "", "channel": "events:feed"},
        ):
            self.assertEqual(self.post("/centrifugo/subscribe/", body).json()["error"]["code"], 403)

    def test_rpc_approve(self):
        action = actions.propose_action(make_event(), "block_ip", "203.0.113.7")
        out = self.post("/centrifugo/rpc/", {
            "user": str(self.staff.pk), "method": "ids:approve_action",
            "data": {"action_id": action.pk},
        }).json()
        self.assertEqual(out["result"]["data"]["status"], "executed")

    def test_rpc_rejects_non_staff_unknown_method_and_bad_input(self):
        action = actions.propose_action(make_event(), "block_ip", "203.0.113.7")
        base = {"method": "ids:approve_action", "data": {"action_id": action.pk}}
        self.assertEqual(
            self.post("/centrifugo/rpc/", {**base, "user": str(self.plain.pk)}).json()["error"]["code"], 403)
        self.assertEqual(
            self.post("/centrifugo/rpc/", {"user": str(self.staff.pk), "method": "ids:drop_db"}).json()["error"]["code"], 404)
        self.assertEqual(
            self.post("/centrifugo/rpc/", {"user": str(self.staff.pk), "method": "ids:approve_action", "data": {}}).json()["error"]["code"], 400)
        action.refresh_from_db()
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)

    def test_rpc_never_returns_empty_allow_response(self):
        # Boş yanıt Centrifugo'da "izin verildi" sayılır; hatalar daima açık error içermeli.
        out = self.post("/centrifugo/rpc/", {"user": "", "method": "ids:approve_action"}).json()
        self.assertIn("error", out)


class PanelTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def test_panel_requires_staff(self):
        for user in (None, self.plain):
            if user:
                self.client.force_login(user)
            resp = self.client.get("/panel/")
            self.assertEqual(resp.status_code, 302, user)
            self.assertIn("/admin/login/", resp["Location"])

    def test_panel_renders_for_staff_with_strict_csp(self):
        self.client.force_login(self.staff)
        resp = self.client.get("/panel/", HTTP_HOST="127.0.0.1:8000")
        self.assertEqual(resp.status_code, 200)
        csp = resp["Content-Security-Policy"]
        nonce = csp.split("'nonce-")[1].split("'")[0]
        body = resp.content.decode()
        self.assertGreaterEqual(body.count(f'nonce="{nonce}"'), 3)  # style + 2 script
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertNotIn("unsafe-eval", csp)
        self.assertIn("img-src data:", csp)
        self.assertIn("connect-src 'self' ws://127.0.0.1:8001", csp)
        self.assertIn("centrifuge@5.7.4", body)
        self.assertIn('integrity="sha384-', body)
        self.assertEqual(resp["Cache-Control"], "no-store")

    def test_ws_url_follows_page_host_so_cookie_reaches_centrifugo(self):
        self.client.force_login(self.staff)
        body = self.client.get("/panel/", HTTP_HOST="localhost:8000").content.decode()
        self.assertIn("ws://localhost:8001/connection/websocket", body)

    @override_settings(RT_WS_URL="wss://ids.example.test/connection/websocket")
    def test_ws_url_can_be_configured(self):
        self.client.force_login(self.staff)
        resp = self.client.get("/panel/")
        self.assertIn("connect-src 'self' wss://ids.example.test", resp["Content-Security-Policy"])

    def test_panel_never_uses_innerhtml(self):
        # Olay alanları saldırgan kontrolünde; yalnızca textContent ile basılmalı.
        from pathlib import Path

        template = Path(__file__).parent / "templates" / "core" / "panel.html"
        source = template.read_text(encoding="utf-8")
        for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            self.assertNotIn(banned, source)

    def test_snapshot_requires_staff_and_returns_json_403(self):
        resp = self.client.get("/panel/api/snapshot/")
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.json(), {"error": "yetkisiz"})
        self.client.force_login(self.plain)
        self.assertEqual(self.client.get("/panel/api/snapshot/").status_code, 403)

    def test_snapshot_lists_latest_first_in_realtime_format(self):
        self.client.force_login(self.staff)
        first = make_event("203.0.113.7")
        second = make_event("203.0.113.8")
        action = actions.propose_action(second, "block_ip", "203.0.113.8")
        data = self.client.get("/panel/api/snapshot/").json()
        self.assertEqual([e["id"] for e in data["events"]], [second.pk, first.pk])
        self.assertEqual(data["events"][0]["type"], "event")
        self.assertEqual(data["actions"][0]["id"], action.pk)
        self.assertEqual(data["actions"][0]["type"], "action")
        self.assertEqual(data["actions"][0]["status"], "pending_approval")

    def test_snapshot_does_not_leak_features(self):
        self.client.force_login(self.staff)
        Event.objects.create(
            source_ip="203.0.113.7", risk_score=0.9, risk_level="high",
            features={"secret": "internal"}, summary="<script>alert(1)</script>",
        )
        resp = self.client.get("/panel/api/snapshot/")
        self.assertEqual(resp["Content-Type"], "application/json")
        self.assertNotIn("internal", resp.content.decode())
