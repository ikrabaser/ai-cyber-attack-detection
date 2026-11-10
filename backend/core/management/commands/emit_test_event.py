from django.core.management.base import BaseCommand, CommandError

from core.ingest import IngestError, ingest_event


class Command(BaseCommand):
    help = (
        "Sensör yokken boru hattını denemek için sahte bir olay üretir "
        "(olay -> kuyruk -> agent -> eylem -> panel)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--ip", required=True, help="Kaynak IP (korumalı IP verirsen reddedilme akışını görürsün)")
        parser.add_argument("--risk", type=float, default=0.92)
        parser.add_argument("--attack", default="ssh_bruteforce")
        parser.add_argument("--target", default="web-01")

    def handle(self, *args, **opts):
        try:
            event = ingest_event(
                {
                    "source_ip": opts["ip"],
                    "target_host": opts["target"],
                    "attack_type": opts["attack"],
                    "xgb_label": opts["attack"],
                    "xgb_score": opts["risk"],
                    "risk_score": opts["risk"],
                    "summary": "emit_test_event ile üretilen sahte olay",
                }
            )
        except IngestError as exc:
            raise CommandError(str(exc))
        if event is None:
            self.stdout.write("Risk eşiğin altında, olay üretilmedi.")
        else:
            self.stdout.write(self.style.SUCCESS(f"Olay oluşturuldu: #{event.pk} ({event.risk_level})"))
