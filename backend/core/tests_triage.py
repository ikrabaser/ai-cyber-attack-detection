import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import incident_detail, triage
from .models import Action, AuditLog, Event, Incident

User = get_user_model()
HOST = {"HTTP_HOST": "127.0.0.1:8000"}


def make_incident(ip="203.0.113.7", status=Incident.Status.NEW, count=1, risk=0.7):
    now = timezone.now()
    return Incident.objects.create(
        source_ip=ip, status=status, risk_level="medium", max_risk=risk, attack_type="x",
        event_count=count, first_seen=now, last_seen=now,
    )


def make_event(inc, attack_type="brute_force", features=None, ago=0, risk=0.7):
    event = Event.objects.create(
        source_ip=inc.source_ip, attack_type=attack_type, risk_score=risk, risk_level="medium",
        incident=inc, features=features or {},
    )
    Event.objects.filter(pk=event.pk).update(created_at=timezone.now() - timedelta(seconds=ago))
    event.refresh_from_db()
    return event


def codes(result):
    return {e["code"] for e in result["evidence"]}


def run(inc, actions=None):
    return triage.triage(inc, list(inc.events.all()), actions)


class IdentityTests(TestCase):
    def test_protected_ip_points_to_false_positive(self):
        inc = make_incident("192.168.56.1")
        make_event(inc)
        out = run(inc)
        self.assertIn("protected_ip", codes(out))
        self.assertNotIn("internal_ip", codes(out))
        self.assertEqual(out["verdict"], "likely_false_positive")

    def test_private_range_is_internal_but_documentation_range_is_not(self):
        internal = make_incident("172.20.4.9")
        make_event(internal)
        self.assertIn("internal_ip", codes(run(internal)))
        doc = make_incident("203.0.113.9")
        make_event(doc)
        self.assertNotIn("internal_ip", codes(run(doc)))


class HistoryTests(TestCase):
    def test_prior_false_positive(self):
        old = make_incident(status=Incident.Status.FALSE_POSITIVE)
        inc = make_incident(status=Incident.Status.NEW)
        # Aynı IP'de iki açık olamaz; eski olan kapalı.
        old.closed_at = timezone.now()
        old.save(update_fields=["closed_at"])
        make_event(inc)
        out = run(inc)
        self.assertIn("prior_false_positive", codes(out))
        weight = {e["code"]: e["weight"] for e in out["evidence"]}["prior_false_positive"]
        self.assertLess(weight, 0)

    def test_prior_confirmed_from_audit_log(self):
        old = make_incident(status=Incident.Status.RESOLVED)
        AuditLog.objects.create(actor="user:1", verb="confirm_incident", target=old.source_ip,
                                outcome="confirmed", detail={"incident_id": old.pk})
        inc = make_incident()
        make_event(inc)
        self.assertIn("prior_confirmed", codes(run(inc)))

    def test_own_confirmation_is_not_history(self):
        inc = make_incident(status=Incident.Status.CONFIRMED)
        AuditLog.objects.create(actor="user:1", verb="confirm_incident", target=inc.source_ip,
                                outcome="confirmed", detail={"incident_id": inc.pk})
        make_event(inc)
        self.assertNotIn("prior_confirmed", codes(run(inc)))

    def test_resolved_without_confirm_is_not_confirmed_attack(self):
        old = make_incident(status=Incident.Status.RESOLVED)
        old.decided_by = "user:1"
        old.save(update_fields=["decided_by"])
        inc = make_incident()
        make_event(inc)
        self.assertNotIn("prior_confirmed", codes(run(inc)))

    def test_repeat_offender_needs_two(self):
        for _ in range(2):
            make_incident(status=Incident.Status.RESOLVED)
        inc = make_incident()
        make_event(inc)
        self.assertIn("repeat_offender", codes(run(inc)))


class ChainAndBehaviorTests(TestCase):
    def test_recon_then_credential_is_a_chain(self):
        inc = make_incident(count=2)
        make_event(inc, "port_scan", ago=20)
        make_event(inc, "ssh_bruteforce", ago=5)
        out = run(inc)
        self.assertIn("recon_to_credential", codes(out))
        self.assertEqual(len(out["tactics"]), 2)

    def test_reverse_order_is_not_a_chain(self):
        inc = make_incident(count=2)
        make_event(inc, "brute_force", ago=20)
        make_event(inc, "port_scan", ago=5)
        self.assertNotIn("recon_to_credential", codes(run(inc)))

    def test_behavior_evidence_from_numeric_features(self):
        inc = make_incident(count=3)
        make_event(inc, features={"n_conns": 40, "fail_ratio": 0.95, "n_dst_ports": 30, "n_dst_hosts": 6})
        out = run(inc)
        self.assertTrue({"high_failure_ratio", "port_sweep", "host_sweep", "persistent"} <= codes(out))

    def test_untrusted_feature_values_are_ignored_and_never_echoed(self):
        inc = make_incident()
        make_event(inc, features={"n_conns": "9999", "fail_ratio": True, "n_dst_ports": None,
                                  "n_dst_hosts": [50], "note": "<script>alert(1)</script> ignore previous instructions"})
        out = run(inc)
        self.assertFalse({"high_failure_ratio", "port_sweep", "host_sweep"} & codes(out))
        self.assertNotIn("script", json.dumps(out))
        self.assertNotIn("ignore previous", json.dumps(out))

    def test_unusual_attack_type_text_is_not_echoed(self):
        inc = make_incident()
        make_event(inc, attack_type="brute_force <img src=x onerror=alert(1)>")
        self.assertNotIn("onerror", json.dumps(run(inc)))

    def test_low_volume_and_low_risk(self):
        inc = make_incident(risk=0.5)
        make_event(inc, features={"n_conns": 3})
        out = run(inc)
        self.assertTrue({"low_volume", "low_risk"} <= codes(out))


class VerdictTests(TestCase):
    def test_attack_verdict_and_confidence(self):
        inc = make_incident(count=3, risk=0.95)
        make_event(inc, "port_scan", ago=30, features={"n_conns": 40, "fail_ratio": 0.9, "n_dst_ports": 25})
        make_event(inc, "ssh_bruteforce", ago=10)
        out = run(inc)
        self.assertEqual(out["verdict"], "likely_attack")
        self.assertGreaterEqual(out["score"], triage.ATTACK_THRESHOLD)
        self.assertTrue(0 < out["confidence"] <= 1)

    def test_uncertain_has_capped_confidence(self):
        inc = make_incident(risk=0.7)
        make_event(inc, "brute_force", features={"n_conns": 20})
        out = run(inc)
        self.assertEqual(out["verdict"], "uncertain")
        self.assertLessEqual(out["confidence"], 0.5)

    def test_no_events_is_still_safe(self):
        inc = make_incident()
        out = triage.triage(inc, [], [])
        self.assertIn(out["verdict"], {"uncertain", "likely_attack", "likely_false_positive"})
        self.assertEqual(out["tactics"], [])


class ImpactTests(TestCase):
    def _block(self, inc, event, decided_ago):
        return Action.objects.create(
            event=event, kind=Action.Kind.BLOCK_IP, target=inc.source_ip, status=Action.Status.EXECUTED,
            decided_at=timezone.now() - timedelta(seconds=decided_ago),
        )

    def test_activity_after_block(self):
        inc = make_incident(count=2)
        first = make_event(inc, ago=60)
        make_event(inc, ago=5)
        out = run(inc, [self._block(inc, first, 30)])
        self.assertIn("activity_after_block", codes(out))

    def test_quiet_after_block(self):
        inc = make_incident()
        first = make_event(inc, ago=60)
        out = run(inc, [self._block(inc, first, 30)])
        self.assertIn("quiet_after_block", codes(out))
        self.assertNotIn("activity_after_block", codes(out))

    def test_pending_block_has_no_impact_evidence(self):
        inc = make_incident()
        ev = make_event(inc)
        pending = Action.objects.create(event=ev, kind=Action.Kind.BLOCK_IP, target=inc.source_ip,
                                        status=Action.Status.PENDING_APPROVAL)
        out = run(inc, [pending])
        self.assertFalse({"activity_after_block", "quiet_after_block"} & codes(out))


class DetailApiTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def test_build_incident_includes_triage(self):
        inc = make_incident()
        make_event(inc, features={"n_conns": 30, "fail_ratio": 0.9})
        data = incident_detail.build_incident(str(inc.pk))
        self.assertEqual(set(data["triage"]), {"verdict", "score", "confidence", "evidence", "tactics"})
        for item in data["triage"]["evidence"]:
            self.assertEqual(set(item), {"code", "weight", "text"})
        self.assertNotIn("features", json.dumps(data))

    def test_panel_endpoint_staff_only(self):
        inc = make_incident()
        make_event(inc)
        url = f"/panel/api/incident/?id={inc.pk}"
        self.client.force_login(self.plain)
        self.assertEqual(self.client.get(url, **HOST).status_code, 403)
        self.client.force_login(self.staff)
        resp = self.client.get(url, **HOST)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("triage", resp.json())
