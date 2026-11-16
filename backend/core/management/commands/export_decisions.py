import csv
import json

from django.core.management.base import BaseCommand, CommandError

from core.models import AuditLog

LABELS = {"attack": "attack", "false_positive": "false_positive", "unlabeled": "unlabeled"}


def _label(entry):
    """Denetim kaydından etiket: Onayla -> attack, Yanlış alarm -> false_positive, Çöz -> unlabeled."""
    if entry.verb == "confirm_incident":
        return LABELS["attack"]
    if entry.verb == "close_incident":
        return LABELS["false_positive"] if entry.outcome == "false_positive" else LABELS["unlabeled"]
    return None


class Command(BaseCommand):
    help = (
        "İnsan kararlarını (karar anındaki triage özeti + etiket) ML için dışa aktarır.\n"
        "Etiket: Onayla = attack, Yanlış alarm = false_positive. Çöz tek başına etiket sayılmaz (varsayılan: dışarıda).\n"
        "Aynı incident için birden fazla etiketli karar varsa en son olan geçerlidir. IP ve karar veren kullanıcı yazılmaz."
    )

    def add_arguments(self, parser):
        parser.add_argument("--format", choices=["jsonl", "csv"], default="jsonl")
        parser.add_argument("--out", help="Dosya yolu (verilmezse ekrana yazılır)")
        parser.add_argument("--include-unlabeled", action="store_true",
                            help="Çöz ile kapatılanları da (etiket: unlabeled) yaz")

    def _rows(self, include_unlabeled):
        entries = AuditLog.objects.filter(verb__in=["confirm_incident", "close_incident"]).order_by("id")
        latest = {}
        for entry in entries:
            snap = (entry.detail or {}).get("triage")
            incident_id = (entry.detail or {}).get("incident_id")
            label = _label(entry)
            if not snap or incident_id is None or label is None:
                continue  # hareketsizlik kapanışı gibi insan kararı olmayanlar
            if label == "unlabeled":
                # Önce Onayla denmişse o etiket zaten var; Çöz onu bozmaz.
                if incident_id in latest and latest[incident_id]["label"] != "unlabeled":
                    continue
                if not include_unlabeled:
                    continue
            latest[incident_id] = {
                "incident_id": incident_id,
                "decided_at": entry.created_at.isoformat(),
                "label": label,
                "verdict": snap.get("verdict"),
                "score": snap.get("score"),
                "confidence": snap.get("confidence"),
                "status_before": (snap.get("incident") or {}).get("status_before"),
                "event_count": (snap.get("incident") or {}).get("event_count"),
                "max_risk": (snap.get("incident") or {}).get("max_risk"),
                "risk_level": (snap.get("incident") or {}).get("risk_level"),
                "tactics": snap.get("tactics") or [],
                "evidence": {e["code"]: e["weight"] for e in snap.get("evidence") or []},
            }
        return list(latest.values())

    def handle(self, *args, **opts):
        rows = self._rows(opts["include_unlabeled"])
        try:
            out = open(opts["out"], "w", encoding="utf-8", newline="") if opts["out"] else self.stdout
        except OSError as exc:
            raise CommandError(f"Dosya açılamadı: {exc}")
        try:
            if opts["format"] == "jsonl":
                for row in rows:
                    out.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                codes = sorted({code for row in rows for code in row["evidence"]})
                base = ["incident_id", "decided_at", "label", "verdict", "score", "confidence", "status_before",
                        "event_count", "max_risk", "risk_level"]
                writer = csv.writer(out)
                writer.writerow(base + [f"e_{c}" for c in codes])
                for row in rows:
                    writer.writerow([row[k] for k in base] + [row["evidence"].get(c, 0) for c in codes])
        finally:
            if opts["out"]:
                out.close()
        if opts["out"]:
            self.stdout.write(self.style.SUCCESS(f"{len(rows)} karar yazıldı: {opts['out']}"))
