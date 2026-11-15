from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "E-posta ayarlarını denemek için tek bir test e-postası gönderir. "
        "Bildirim akışından farklı olarak hatayı yutmaz, nedenini açıkça yazar."
    )

    def handle(self, *args, **opts):
        recipients = list(settings.NOTIFY_EMAIL_TO)
        if not recipients:
            raise CommandError("NOTIFY_EMAIL_TO boş. .env içine alıcı adresini yaz.")
        if not settings.EMAIL_HOST:
            self.stdout.write(self.style.WARNING(
                "EMAIL_HOST boş: e-posta gönderilmeyecek, aşağıda konsola yazılacak."))
        try:
            send_mail(
                "[IDS] Test e-postası",
                "Bu, saldırı tespit sisteminin bildirim ayarlarını denemek için gönderilen bir test e-postasıdır.",
                settings.NOTIFY_EMAIL_FROM,
                recipients,
                fail_silently=False,
            )
        except Exception as exc:  # noqa: BLE001 - nedenini kullanıcıya göstermek istiyoruz
            raise CommandError(f"Gönderilemedi: {type(exc).__name__}: {exc}")
        self.stdout.write(self.style.SUCCESS(f"Gönderildi: {len(recipients)} alıcı"))
