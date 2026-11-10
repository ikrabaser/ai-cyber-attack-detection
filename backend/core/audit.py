from .models import AuditLog


def record(actor, verb, target="", outcome="ok", **detail):
    """Denetim kaydı yaz. Reddedilen/korumalı denemeler de buraya düşer."""
    return AuditLog.objects.create(
        actor=str(actor), verb=verb, target=str(target), outcome=outcome, detail=detail
    )
