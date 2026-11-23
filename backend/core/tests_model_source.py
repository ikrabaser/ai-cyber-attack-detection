"""Sensör --model ile çalışırken olayın karar kaynağı (kural / kural+model / yalnızca model) panele ulaşır."""

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from . import realtime
from .ingest import ingest_event
from .models import Event

User = get_user_model()
HOST = {"HTTP_HOST": "127.0.0.1:8000"}


def body(**extra):
    base = {"source_ip": "203.0.113.7", "risk_score": 0.8, "attack_type": "port_scan"}
    base.update(extra)
    return base


@mock.patch("core.ingest.enqueue_investigation")
@mock.patch("core.realtime.publish")
class ModelSourceInPayloadTests(TestCase):
    def test_model_fields_round_trip_into_the_event_payload(self, pub, enq):
        event = ingest_event(body(
            features={"detected_by": "rules+model"}, xgb_label="port_scan", xgb_score=0.97))
        data = realtime.event_payload(Event.objects.get(pk=event.pk))
        self.assertEqual(data["detected_by"], "rules+model")
        self.assertEqual(data["xgb_label"], "port_scan")
        self.assertAlmostEqual(data["xgb_score"], 0.97)

    def test_old_events_without_model_fields_still_serialize(self, pub, enq):
        data = realtime.event_payload(ingest_event(body()))
        self.assertEqual(data["detected_by"], "")
        self.assertEqual(data["xgb_label"], "")
        self.assertIsNone(data["xgb_score"])

    def test_unknown_detected_by_is_not_passed_to_the_panel(self, pub, enq):
        for bad in ("<img src=x onerror=alert(1)>", "hacked", 5, None, ["model"]):
            with self.subTest(bad=bad):
                data = realtime.event_payload(ingest_event(body(features={"detected_by": bad})))
                self.assertEqual(data["detected_by"], "")

    def test_all_known_sources_are_accepted(self, pub, enq):
        for known in realtime.DETECTED_BY:
            with self.subTest(known=known):
                data = realtime.event_payload(ingest_event(body(features={"detected_by": known})))
                self.assertEqual(data["detected_by"], known)

    def test_event_with_non_dict_features_does_not_break_the_payload(self, pub, enq):
        event = ingest_event(body())
        event.features = ["liste"]
        self.assertEqual(realtime.event_payload(event)["detected_by"], "")


@mock.patch("core.ingest.enqueue_investigation")
@mock.patch("core.realtime.publish")
class EmitTestEventTests(TestCase):
    def run_cmd(self, *args):
        from io import StringIO
        from django.core.management import call_command
        call_command("emit_test_event", "--ip", "203.0.113.7", *args, stdout=StringIO())
        return Event.objects.latest("pk")

    def test_detected_by_option_marks_the_event(self, pub, enq):
        event = self.run_cmd("--detected-by", "model")
        self.assertEqual(realtime.event_payload(event)["detected_by"], "model")

    def test_default_event_has_no_source_mark(self, pub, enq):
        self.assertEqual(realtime.event_payload(self.run_cmd())["detected_by"], "")


class PanelShowsModelSourceTests(TestCase):
    def test_panel_template_renders_the_source_chip_under_strict_csp(self):
        staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.client.force_login(staff)
        resp = self.client.get("/panel/", **HOST)
        page = resp.content.decode()
        for needle in ("sourceChip", "Yalnızca model", "Kural + model", "Modelin görüşü"):
            self.assertIn(needle, page)
        self.assertNotIn("unsafe-inline", resp["Content-Security-Policy"])
        # kaynak adı metne değil textContent'e yazılır: panelde innerHTML ile birleştirme yok
        self.assertNotIn("innerHTML", page.split("const sourceChip", 1)[1].split("const fmtTime", 1)[0])
