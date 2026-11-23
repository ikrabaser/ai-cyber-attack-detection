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

    def test_autoencoder_section_is_consistent(self):
        ae = self.report["autoencoder"]
        self.assertEqual(len(ae["hidden"]), 3)
        self.assertGreater(len(ae["types"]), 5)
        for row in ae["types"]:
            for key in ("rules", "xgb", "volume", "ae", "ae_strict", "auc"):
                self.assertTrue(0.0 <= row[key] <= 1.0, (row["name"], key))
            self.assertGreater(row["n"], 0)
            self.assertLessEqual(row["ae_strict"], row["ae"] + 1e-9)  # sıkı eşik alarmı artıramaz
        for key in ("rules", "xgb", "volume", "ae", "ae_strict"):
            self.assertTrue(0.0 <= ae["fpr"][key] <= 1.0)
        self.assertLess(ae["fpr"]["ae_strict"], ae["fpr"]["ae"])
        # Kurallar ve XGBoost'un yanlış alarm oranı ana bölümle aynı sayıdır (aynı test normalleri).
        self.assertAlmostEqual(ae["fpr"]["xgb"], self.report["xgb"]["fpr"], places=9)
        self.assertAlmostEqual(ae["fpr"]["rules"], self.report["rules"]["fpr"], places=9)

    def test_lab_section_hits_never_exceed_windows(self):
        lab = self.report["lab"]
        for method in lab["methods"]:
            for cls, (hit, n) in method["hits"].items():
                self.assertLessEqual(hit, n, (method["name"], cls))
                self.assertEqual(n, lab["support"][cls])
        self.assertEqual(sum(lab["support"].values()), lab["windows"])


class MlReportExtrasTests(TestCase):
    """H1 ve etiket gürültüsü bölümleri isteğe bağlı: yoksa panel gizler, varsa tutarlı olmalı."""

    def setUp(self):
        views_panel._ml_report.cache_clear()
        self.addCleanup(views_panel._ml_report.cache_clear)
        self.staff = User.objects.create_user("ops2", password="x", is_staff=True)

    def test_panel_template_has_the_extra_sections_and_stays_csp_safe(self):
        self.client.force_login(self.staff)
        resp = self.client.get("/panel/")
        for needle in ("ml-h1-table", "ml-h1-clean-table", "ml-noise-table", "renderMlExtras",
                       "Eşit yanlış alarmda karşılaştırma", "Etiket gürültüsü"):
            self.assertContains(resp, needle)
        html = resp.content.decode("utf-8")
        start = html.index("function renderMlExtras")
        block = html[start:html.index("function renderMl()", start)]
        self.assertNotIn("innerHTML", block)
        self.assertNotIn("style=", block)
        # Ondalık ayracı panelin geri kalanıyla aynı (virgül): ham toFixed çıktısı ekrana verilmez.
        self.assertIn("pct3(", block)
        self.assertNotIn("`%${", block)

    def test_endpoint_passes_the_extra_sections_through(self):
        import tempfile
        from pathlib import Path

        report = {"generated": "2026-01-01", "equal_fpr": {"targets": [0.01], "variants": {"all": [], "clean": []}},
                  "label_noise": {"suspect_ip": "172.16.0.1", "profile": {}, "rows": []}, "xgboost_version": "3.4.1"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            self.client.force_login(self.staff)
            with mock.patch.object(views_panel, "ML_REPORT_PATH", path):
                data = self.client.get(URL).json()
        self.assertEqual(data["xgboost_version"], "3.4.1")
        self.assertIn("equal_fpr", data)
        self.assertIn("label_noise", data)

    def test_shipped_report_extras_are_consistent_when_present(self):
        report = json.loads(views_panel.ML_REPORT_PATH.read_text(encoding="utf-8"))
        h1 = report.get("equal_fpr")
        if h1:
            for variant, rows in h1["variants"].items():
                self.assertEqual(len(rows), len(h1["targets"]) * len(h1["classes"]), variant)
                for row in rows:
                    self.assertGreater(row["n_pos"], 0)
                    for method in ("rules", "model"):
                        m = row[method]
                        self.assertTrue(0.0 <= m["lo"] <= m["recall"] <= m["hi"] <= 1.0, (variant, row["cls"], method))
                        self.assertLessEqual(m["fpr"], row["target"] + 1e-12)  # bütçeyi aşan nokta seçilmez
        noise = report.get("label_noise")
        if noise:
            for row in noise["rows"]:
                self.assertLessEqual(row["false_alarms"], row["normals"])
            self.assertGreaterEqual(noise["profile"]["suspects"], 0)
