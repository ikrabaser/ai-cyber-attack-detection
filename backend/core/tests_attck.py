from django.test import TestCase
from django.utils import timezone

from . import realtime
from .attck import attck_for
from .models import Incident
from .tests import make_event


class AttckMappingTests(TestCase):
    def test_known_attack_types_map_to_a_technique(self):
        self.assertEqual(attck_for("port_scan"), {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"})
        self.assertEqual(attck_for("brute_force"), {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"})

    def test_unknown_attack_type_has_no_mapping(self):
        self.assertIsNone(attck_for("ssh_bruteforce"))
        self.assertIsNone(attck_for("unknown"))
        self.assertIsNone(attck_for(""))
        self.assertIsNone(attck_for(None))


class AttckInPayloadsTests(TestCase):
    def test_event_payload_carries_the_mapping(self):
        event = make_event()
        event.attack_type = "port_scan"
        event.save()
        self.assertEqual(realtime.event_payload(event)["attck"], attck_for("port_scan"))

    def test_event_payload_is_none_for_unmapped_attack_type(self):
        event = make_event()  # attack_type="ssh_bruteforce" varsayılanı, eşlemesiz
        self.assertIsNone(realtime.event_payload(event)["attck"])

    def test_incident_payload_carries_the_mapping(self):
        now = timezone.now()
        incident = Incident.objects.create(
            source_ip="203.0.113.7", attack_type="brute_force", risk_level="high",
            max_risk=0.9, first_seen=now, last_seen=now,
        )
        self.assertEqual(realtime.incident_payload(incident)["attck"], attck_for("brute_force"))
