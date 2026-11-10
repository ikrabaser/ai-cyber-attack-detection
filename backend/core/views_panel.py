"""Canlı panel: tek sayfa + başlangıç verisi (snapshot) uç noktası.

Panel yalnızca `is_staff` kullanıcılara açıktır. Sayfa yüklenince snapshot ile
son olaylar/eylemler alınır; sonrası Centrifugo üzerinden canlı akar. Onay, red
ve geri alma butonları Centrifugo RPC'sini (`ids:*`) kullanır, yani karar yine
doğrulanmış staff oturumundan ve politika katmanından (core.actions) geçer.

Güvenlik: olay alanları (özet, saldırı türü, hedef...) saldırgan kontrolünde
olabilir. Şablon bunları yalnızca `textContent` ile basar; ayrıca sıkı bir CSP
(nonce'lu script/style, dış bağlantı yalnızca Centrifugo) gönderilir.
"""

import secrets
from functools import wraps
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from . import realtime
from .models import Action, Event

SNAPSHOT_EVENTS = 50
SNAPSHOT_ACTIONS = 100

# Sürüm sabitli ve bütünlük (SRI) hash'li: CDN değişse bile farklı bir dosya çalışmaz.
CENTRIFUGE_SRC = "https://cdn.jsdelivr.net/npm/centrifuge@5.7.4/dist/centrifuge.js"
CENTRIFUGE_SRI = "sha384-Iz2tPn0Bdkrz7y4HN3TY1XBlxpW+TjRqSbTJc2ENckVFOGn9tDUNezcC3CF5pO+h"

MODE_LABELS = {
    "advise": "Öneri modu: hiçbir şey otomatik yapılmaz",
    "dry_run": "Kuru çalıştırma: otomatik eylemler uygulanmaz, kaydedilir",
    "enforce": "Uygulama: düşük riskli eylemler otomatik uygulanır",
}


def _staff_json(view):
    """Oturum yoksa yönlendirme yerine JSON 403 döner (fetch için)."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not (user.is_authenticated and user.is_active and user.is_staff):
            return JsonResponse({"error": "yetkisiz"}, status=403)
        return view(request, *args, **kwargs)

    return wrapper


def _ws_url(request):
    """Tarayıcının Centrifugo'ya bağlanacağı adres.

    Çerez ana makine adına bağlıdır (port'a değil). Sayfa `127.0.0.1` ile açıldıysa
    WebSocket de `127.0.0.1`'e gitmeli ki oturum çerezi connect proxy'ye ulaşsın;
    bu yüzden ana makine adı istekten türetilir.
    """
    configured = getattr(settings, "RT_WS_URL", "")
    if configured:
        return configured
    host = urlsplit(f"//{request.get_host()}").hostname or "localhost"
    if ":" in host:  # IPv6
        host = f"[{host}]"
    scheme = "wss" if request.is_secure() else "ws"
    return f"{scheme}://{host}:{settings.RT_PUBLIC_PORT}/connection/websocket"


def _csp(nonce, ws_url):
    parts = urlsplit(ws_url)
    ws_origin = f"{parts.scheme}://{parts.netloc}"
    return "; ".join(
        [
            "default-src 'none'",
            f"script-src 'nonce-{nonce}' https://cdn.jsdelivr.net",
            f"style-src 'nonce-{nonce}'",
            f"connect-src 'self' {ws_origin}",
            "img-src data:",  # boş favicon (data:,) için
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ]
    )


@require_GET
@staff_member_required
def panel(request):
    nonce = secrets.token_urlsafe(16)
    ws_url = _ws_url(request)
    mode = settings.AUTO_REMEDIATION_MODE
    context = {
        "csp_nonce": nonce,
        "centrifuge_src": CENTRIFUGE_SRC,
        "centrifuge_sri": CENTRIFUGE_SRI,
        "mode": mode,
        "mode_label": MODE_LABELS.get(mode, mode),
        "username": request.user.get_username(),
        "config": {
            "wsUrl": ws_url,
            "snapshotUrl": "/panel/api/snapshot/",
            "channels": [realtime.CHANNEL_FEED, realtime.CHANNEL_ACTIONS],
        },
    }
    response = render(request, "core/panel.html", context)
    response["Content-Security-Policy"] = _csp(nonce, ws_url)
    response["Cache-Control"] = "no-store"
    return response


@require_GET
@_staff_json
def snapshot(request):
    events = Event.objects.order_by("-id")[:SNAPSHOT_EVENTS]
    actions = Action.objects.order_by("-id")[:SNAPSHOT_ACTIONS]
    response = JsonResponse(
        {
            "events": [realtime.event_payload(e) for e in events],
            "actions": [realtime.action_payload(a) for a in actions],
        }
    )
    response["Cache-Control"] = "no-store"
    return response
