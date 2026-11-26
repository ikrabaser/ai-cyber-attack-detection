from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from . import actions
from .attck import attck_for
from .incident_report import incident_timeline, stage_summary
from .ingest import ingest_event

IP = "203.0.113.7"


def send(ip=IP, risk=0.92, attack="port_scan"):
    return ingest_event({"source_ip": ip, "risk_score": risk, "attack_type": attack})


class IncidentTimelineTests(TestCase):
    def test_events_and_actions_in_chronological_order(self):
        first = send(attack="port_scan")
        second = send(attack="brute_force")
        incident = first.incident
        self.assertEqual(second.incident_id, incident.pk)  # aynı IP, aynı açık incident

        action = actions.propose_action(second, "block_ip", second.source_ip)

        timeline = incident_timeline(incident)
        self.assertEqual([row["type"] for row in timeline], ["event", "event", "action"])
        self.assertEqual(timeline[0]["id"], first.pk)
        self.assertEqual(timeline[1]["id"], second.pk)
        self.assertEqual(timeline[2]["id"], action.pk)

    def test_event_entries_carry_the_attck_mapping(self):
        event = send(attack="brute_force")
        timeline = incident_timeline(event.incident)
        self.assertEqual(timeline[0]["attck"], attck_for("brute_force"))

    def test_event_entries_carry_no_more_than_the_summary_prefix(self):
        event = send()
        event.summary = "x" * 1000
        event.save()
        timeline = incident_timeline(event.incident)
        self.assertEqual(len(timeline[0]["summary"]), 300)

    def test_incident_with_no_actions_still_works(self):
        event = send()
        timeline = incident_timeline(event.incident)
        self.assertEqual([row["type"] for row in timeline], ["event"])


class StageSummaryTests(TestCase):
    def test_single_attack_type_gives_one_stage(self):
        event = send(attack="port_scan")
        self.assertEqual(stage_summary(event.incident), [{"attack_type": "port_scan", "attck": attck_for("port_scan")}])

    def test_two_attack_types_in_first_seen_order(self):
        first = send(attack="port_scan")
        send(attack="brute_force")  # aynı IP, aynı açık incident
        stages = stage_summary(first.incident)
        self.assertEqual([s["attack_type"] for s in stages], ["port_scan", "brute_force"])
        self.assertEqual(stages[1]["attck"], attck_for("brute_force"))

    def test_repeated_attack_type_is_not_duplicated(self):
        first = send(attack="port_scan")
        send(attack="port_scan")
        self.assertEqual(stage_summary(first.incident), [{"attack_type": "port_scan", "attck": attck_for("port_scan")}])

    def test_order_follows_first_seen_time_not_action_order(self):
        first = send(attack="brute_force")
        second = send(attack="port_scan")
        actions.propose_action(first, "block_ip", first.source_ip)  # eylem sırası etiket sırasını değiştirmemeli
        stages = stage_summary(first.incident)
        self.assertEqual([s["attack_type"] for s in stages], ["brute_force", "port_scan"])


class ExportIncidentTimelineCommandTests(TestCase):
    def test_unknown_incident_is_a_command_error(self):
        with self.assertRaises(CommandError):
            call_command("export_incident_timeline", 999999)

    def test_text_output_mentions_the_attck_technique(self):
        event = send(attack="port_scan")
        out = StringIO()
        call_command("export_incident_timeline", event.incident_id, stdout=out)
        self.assertIn("T1046", out.getvalue())
        self.assertIn(f"Incident #{event.incident_id}", out.getvalue())

    def test_json_output_has_stages_and_timeline(self):
        import json

        event = send(attack="port_scan")
        out = StringIO()
        call_command("export_incident_timeline", event.incident_id, "--format=json", stdout=out)
        data = json.loads(out.getvalue())
        self.assertEqual(data["incident_id"], event.incident_id)
        self.assertEqual(data["stages"], [{"attack_type": "port_scan", "attck": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}}])
        self.assertEqual(len(data["timeline"]), 1)
        self.assertEqual(data["timeline"][0]["attck"]["id"], "T1046")

    def test_text_output_shows_stage_chain_when_multiple_stages(self):
        event = send(attack="port_scan")
        send(attack="brute_force")  # aynı IP, aynı incident
        out = StringIO()
        call_command("export_incident_timeline", event.incident_id, stdout=out)
        self.assertIn("port_scan [T1046] -> brute_force [T1110]", out.getvalue())

    def test_text_output_has_no_stage_line_for_a_single_stage(self):
        event = send(attack="port_scan")
        out = StringIO()
        call_command("export_incident_timeline", event.incident_id, stdout=out)
        self.assertNotIn("Aşamalar", out.getvalue())
