import json

from django.core.management.base import BaseCommand, CommandError

from core.incident_report import incident_timeline, stage_summary
from core.models import Incident


def _jsonable(row):
    out = dict(row)
    out["at"] = row["at"].isoformat()
    return out


class Command(BaseCommand):
    help = (
        "Bir incident'in olay + eylem zaman çizelgesini yazar (olay raporunun ilk küçük parçası). "
        "Yalnızca var olan kayıtları zaman sırasına göre listeler, yorum eklemez."
    )

    def add_arguments(self, parser):
        parser.add_argument("incident_id", type=int)
        parser.add_argument("--format", choices=["text", "json"], default="text")

    def handle(self, *args, **opts):
        try:
            incident = Incident.objects.get(pk=opts["incident_id"])
        except Incident.DoesNotExist:
            raise CommandError(f"Incident #{opts['incident_id']} yok.")

        timeline = incident_timeline(incident)
        stages = stage_summary(incident)

        if opts["format"] == "json":
            out = {
                "incident_id": incident.pk,
                "stages": stages,
                "timeline": [_jsonable(r) for r in timeline],
            }
            self.stdout.write(json.dumps(out, ensure_ascii=False, indent=2))
            return

        self.stdout.write(f"Incident #{incident.pk} · {incident.source_ip} · {incident.status}")
        stage_text = " -> ".join(
            f"{s['attack_type']} [{s['attck']['id']}]" if s["attck"] else s["attack_type"] for s in stages
        )
        if len(stages) > 1:
            self.stdout.write(f"  Aşamalar (sıra, zincir iddiası değil): {stage_text}")
        for row in timeline:
            when = row["at"].strftime("%Y-%m-%d %H:%M:%S")
            if row["type"] == "event":
                technique = f" [{row['attck']['id']}]" if row["attck"] else ""
                self.stdout.write(
                    f"  {when}  olay #{row['id']:<5} {row['attack_type']}{technique} "
                    f"risk={row['risk_score']:.2f} ({row['risk_level']}) · {row['status']}"
                )
            else:
                self.stdout.write(
                    f"  {when}  eylem #{row['id']:<4} {row['kind']} -> {row['target']} "
                    f"· {row['status']} (öneren: {row['proposed_by']})"
                )
