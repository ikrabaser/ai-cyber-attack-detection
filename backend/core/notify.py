"""E-posta bildirimi: insan kararı bekleyen veya korumalı hedef yüzünden reddedilen eylemler.

Tasarım kuralları
- Bildirim ana akışı ASLA bozmaz: SMTP hatası loglanır ve denetim kaydına yazılır, istisna yükselmez.
- E-posta yalnızca haber verir, karar vermez: içinde onay bağlantısı yok, onay paneldeki staff oturumundan gelir.
- Olay alanları (özet, log alıntıları) saldırgan kontrolünde olabilir; e-postaya konmaz. Konan alanlar
  (saldırı türü, hedef) yine de temizlenir: satır sonu ve garip karakterler atılır, uzunluk sınırlanır.
- Korumalı hedef reddi sensör her pencerede tekrarlayabilir; aynı hedef için bekleme süresi uygulanır.
- NOTIFY_EMAIL_TO boşsa bildirim kapalıdır.
"""

import logging
import re

from django.conf import settings
from django.core.cache import cache
from django.core.mail import send_mail
from django.utils import timezone

from . import audit
from .models import Action

log = logging.getLogger(__name__)

# Serbest metin (saldırı türü): yalnızca harf, rakam, nokta, tire, boşluk. ":" ve "/" yok, yani
# tıklanabilir bağlantı ya da "Başlık: değer" gibi taklitler e-postaya giremez.
_UNSAFE_TEXT = re.compile(r"[^\w.\- ]", re.UNICODE)
# Hedef (IP veya host adı): IPv6 için ":" gerekir, "/" gerekmez.
_UNSAFE_TARGET = re.compile(r"[^\w.:\-]", re.UNICODE)


def _clean(value, limit=64):
    """Saldırgan kontrollü olabilecek kısa alanları e-postaya koymadan önce temizle."""
    return _UNSAFE_TEXT.sub("_", str(value or "")).strip()[:limit]


def _clean_target(value, limit=255):
    return _UNSAFE_TARGET.sub("_", str(value or "")).strip()[:limit]


def enabled():
    return bool(settings.NOTIFY_EMAIL_TO)


def _ttl_text(seconds):
    if not seconds:
        return ""
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes} dk" if not rest else f"{minutes} dk {rest} sn"


def _panel_url():
    return settings.PANEL_BASE_URL.rstrip("/") + "/panel/"


def _lines(action, event):
    lines = [
        f"Eylem: {action.get_kind_display()}",
        f"Hedef: {_clean_target(action.target)}",
    ]
    if event is not None:
        lines.append(f"Saldırı türü: {_clean(event.attack_type)}")
        lines.append(f"Risk: {event.risk_score:.2f} ({event.get_risk_level_display()})")
    ttl = _ttl_text(action.ttl_seconds)
    if ttl:
        lines.append(f"Önerilen engel süresi: {ttl}")
    if action.approval_deadline:
        deadline = timezone.localtime(action.approval_deadline)
        lines.append(f"Onay için son zaman: {deadline:%H:%M} ({settings.TIME_ZONE})")
    return lines


def build_message(action):
    """(konu, gövde) döner. Eylem durumuna göre iki tür bildirim vardır."""
    event = action.event
    risk = f" (risk {event.risk_score:.2f})" if event is not None else ""
    target = _clean_target(action.target)

    if action.status == Action.Status.REFUSED:
        subject = f"[IDS] Korumalı hedef için öneri reddedildi: {target}"
        intro = (
            "Korumalı bir IP veya host için müdahale önerildi ve sistem bunu reddetti. "
            "Genellikle ya yanlış alarmdır (kendi tarama aracın gibi) ya da korumalı bir "
            "makinenin saldırı kaynağı göründüğü gerçek bir olaydır. Hiçbir önlem uygulanmadı."
        )
    else:
        subject = f"[IDS] Onay bekliyor: {action.get_kind_display()} {target}{risk}"
        intro = "İnsan kararı bekleyen yeni bir müdahale önerisi var."

    body = "\n".join(
        [
            intro,
            "",
            *_lines(action, event),
            "",
            f"Panel: {_panel_url()}",
            "",
            "Bu e-posta otomatik gönderildi ve yalnızca bilgi verir. Karar panelden, "
            "oturum açmış bir yönetici tarafından verilir; e-postadaki hiçbir şey eylemi onaylamaz.",
        ]
    )
    return subject, body


def _in_cooldown(action):
    """Aynı hedef için reddedilen eylem bildirimi bekleme süresinde mi? (ilk çağrıda süreyi başlatır)"""
    seconds = settings.NOTIFY_REFUSED_COOLDOWN_SECONDS
    if seconds <= 0:
        return False
    key = f"notify:refused:{action.kind}:{_clean_target(action.target)}"
    return not cache.add(key, 1, timeout=seconds)


def notify_action(action_id):
    """İlgili eylem için e-posta gönder. Hiçbir koşulda istisna yükseltmez."""
    if not enabled():
        return False
    try:
        action = Action.objects.select_related("event").get(pk=action_id)
        if action.status not in {Action.Status.PENDING_APPROVAL, Action.Status.REFUSED}:
            return False
        if action.status == Action.Status.REFUSED and _in_cooldown(action):
            audit.record("system", "send_notification", action.target, "skipped",
                         reason="bekleme süresi", action_id=action.pk)
            return False

        subject, body = build_message(action)
        send_mail(subject, body, settings.NOTIFY_EMAIL_FROM, list(settings.NOTIFY_EMAIL_TO),
                  fail_silently=False)
        audit.record("system", "send_notification", action.target, "sent",
                     action_id=action.pk, recipients=len(settings.NOTIFY_EMAIL_TO))
        return True
    except Exception as exc:  # noqa: BLE001 - bildirim akışı bozmamalı
        log.warning("Bildirim gönderilemedi (eylem %s): %s", action_id, exc)
        try:
            audit.record("system", "send_notification", "", "failed",
                         action_id=action_id, error=type(exc).__name__)
        except Exception:  # noqa: BLE001
            log.exception("Bildirim hatası denetim kaydına yazılamadı")
        return False
