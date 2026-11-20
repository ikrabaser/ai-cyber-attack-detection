import json
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from . import views_panel

User = get_user_model()
URL = "/panel/api/ml/"


class MlReportEndpointTests(TestCase):
    def setUp(self):
        views_panel._ml_report.cache_clear()
        self.addCleanup(views_panel._ml_report.cache_clear)
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("user", password="x")

    def test_anonymous_and_non_staff_get_403_json(self):
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.client.force_login(self.plain)
        resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp["Content-Type"], "application/json")

    def test_staff_gets_report_and_post_is_rejected(self):
        self.client.force_login(self.staff)
        resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Cache-Control"], "no-store")
        for key in ("classes", "split", "xgb", "rules", "importance", "port_scan_ports", "generated"):
            self.assertIn(key, resp.json())
        self.assertEqual(self.client.post(URL).status_code, 405)

    def test_missing_report_is_404_json(self):
        self.client.force_login(self.staff)
        with mock.patch.object(views_panel, "ML_REPORT_PATH", views_panel.ML_REPORT_PATH.with_name("yok.json")):
            resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 404)
        self.assertIn("error", resp.json())

    def test_panel_config_exposes_the_url(self):
        self.client.force_login(self.staff)
        resp = self.client.get("/panel/")
        self.assertContains(resp, "/panel/api/ml/")
        self.assertContains(resp, 'data-soc-tab="ml"')


class MlReportContentTests(TestCase):
    """Dosyadaki sayılar kendi içinde tutarlı olmalı (elle düzenleme veya bozuk dışa aktarma yakalanır)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.report = json.loads(views_panel.ML_REPORT_PATH.read_text(encoding="utf-8"))

    def test_matrix_rows_add_up_to_support_and_test_counts(self):
        counts = self.report["split"]["counts"]["test"]
        for name in ("xgb", "rules"):
            part = self.report[name]
            for cls in self.report["classes"]:
                row = sum(part["matrix"][cls].values())
                self.assertEqual(row, part["per_class"][cls]["support"], (name, cls))
                self.assertEqual(row, counts[cls], (name, cls))

    def test_macro_f1_is_mean_of_class_f1(self):
        for name in ("xgb", "rules"):
            part = self.report[name]
            mean = sum(part["per_class"][c]["f1"] for c in self.report["classes"]) / len(self.report["classes"])
            self.assertAlmostEqual(part["macro_f1"], mean, places=9, msg=name)

    def test_importance_sums_to_one_and_port_bins_match(self):
        self.assertAlmostEqual(sum(g for _, g in self.report["importance"]), 1.0, places=6)
        pp = self.report["port_scan_ports"]
        self.assertEqual(len(pp["bins"]), len(pp["train"]))
        self.assertEqual(len(pp["bins"]), len(pp["test"]))
        counts = self.report["split"]["counts"]
        self.assertEqual(sum(pp["train"]), counts["train"]["port_scan"])
        self.assertEqual(sum(pp["test"]), counts["test"]["port_scan"])
