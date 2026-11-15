import logging

from django.db import transaction

from . import realtime
from .models import AuditLog

log = logging.getLogger(__name__)


def _publish_step(entry):
    try:
        realtime.publish(realtime.CHANNEL_PIPELINE, realtime.pipeline_payload(entry))
    except Exception:  # noqa: BLE001 - canlı akış hiçbir zaman asıl işi bozmamalı
        log.exception("Akış adımı yayınlanamadı")


def record(actor, verb, target="", outcome="ok", **detail):
    """Denetim kaydı yaz. Reddedilen/korumalı denemeler de buraya düşer.

    Kayıt, işlem tamamlandıktan sonra panelin canlı akışına da yayınlanır.
    """
    entry = AuditLog.objects.create(
        actor=str(actor), verb=verb, target=str(target), outcome=outcome, detail=detail
    )
    transaction.on_commit(lambda: _publish_step(entry))
    return entry
