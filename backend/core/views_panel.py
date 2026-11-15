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
from functools import lru_cache, wraps
from pathlib import Path
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from . import event_filters, realtime, source_detail, stats
from .models import Action, Event

SNAPSHOT_EVENTS = 50
SNAPSHOT_ACTIONS = 100

# İstemci kütüphanesi dış CDN'den değil, depodaki dosyadan (core/vendor/) sunulur: panel internetsiz
# de çalışır, CSP'de dış script kaynağı gerekmez. Dosya npm paketinin `dist/centrifuge.js`'idir;
# SRI hash'i bozulmaya karşı tarayıcıda da kontrol edilir (testler hash'i dosyayla karşılaştırır).
CENTRIFUGE_VERSION = "5.7.4"
CENTRIFUGE_FILE = Path(__file__).resolve().parent / "vendor" / f"centrifuge-{CENTRIFUGE_VERSION}.js"
CENTRIFUGE_URL = f"/panel/vendor/centrifuge-{CENTRIFUGE_VERSION}.js"
CENTRIFUGE_SRI = "sha384-Iz2tPn0Bdkrz7y4HN3TY1XBlxpW+TjRqSbTJc2ENckVFOGn9tDUNezcC3CF5pO+h"

# Grafikler için Chart.js, aynı yöntemle (npm paketinin `dist/chart.umd.js`'i, MIT lisanslı).
CHART_VERSION = "4.6.1"
CHART_FILE = Path(__file__).resolve().parent / "vendor" / f"chart-{CHART_VERSION}.umd.js"
CHART_URL = f"/panel/vendor/chart-{CHART_VERSION}.umd.js"
CHART_SRI = "sha384-lm7tNiW/3uF4tLujoEeoR94zIODe3hCWqRtW0UgxpQE3QslzOhlD22UqQk1tSBhB"

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
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}'",
            f"connect-src 'self' {ws_origin}",
            "img-src data:",  # boş favicon (data:,) için
            "base-uri 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ]
    )


@lru_cache(maxsize=4)
def _vendor_bytes(path):
    return path.read_bytes()


def _serve_vendor(path, name):
    """Vendored kütüphane dosyası. Herkese açık bir kütüphane kodudur; panel verisi içermez."""
    try:
        body = _vendor_bytes(path)
    except OSError:
        raise Http404(f"{name} dosyası bulunamadı")
    response = HttpResponse(body, content_type="text/javascript; charset=utf-8")
    response["Cache-Control"] = "public, max-age=86400"
    return response


@require_GET
def centrifuge_js(request):
    return _serve_vendor(CENTRIFUGE_FILE, "centrifuge-js")


@require_GET
def chart_js(request):
    return _serve_vendor(CHART_FILE, "chart.js")


@require_GET
@staff_member_required
def panel(request):
    nonce = secrets.token_urlsafe(16)
    ws_url = _ws_url(request)
    mode = settings.AUTO_REMEDIATION_MODE
    context = {
        "csp_nonce": nonce,
        "centrifuge_src": CENTRIFUGE_URL,
        "centrifuge_sri": CENTRIFUGE_SRI,
        "chart_src": CHART_URL,
        "chart_sri": CHART_SRI,
        "mode": mode,
        "mode_label": MODE_LABELS.get(mode, mode),
        "username": request.user.get_username(),
        "config": {
            "wsUrl": ws_url,
            "snapshotUrl": "/panel/api/snapshot/",
            "statsUrl": "/panel/api/stats/",
            "eventsUrl": "/panel/api/events/",
            "sourceUrl": "/panel/api/source/",
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


@require_GET
@_staff_json
def stats_view(request):
    """Grafikler için özet sayılar. Yalnızca sayı ve kısa etiket döner; özet/özellik alanları yok."""
    range_key = request.GET.get("range", stats.DEFAULT_RANGE)
    if range_key not in stats.RANGES:
        return JsonResponse({"error": "geçersiz aralık"}, status=400)
    response = JsonResponse(stats.build_stats(range_key))
    response["Cache-Control"] = "no-store"
    return response


@require_GET
@_staff_json
def events_view(request):
    """Filtrelenmiş olay listesi (en yeni önce). Alanlar canlı akıştakiyle aynı biçimdedir."""
    try:
        filters = event_filters.parse(request.GET)
    except event_filters.FilterError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    matching = event_filters.apply(Event.objects.all(), filters)
    items = matching.order_by("-id")[: event_filters.LIMIT]
    response = JsonResponse(
        {
            "events": [realtime.event_payload(e) for e in items],
            "total": matching.count(),
            "limit": event_filters.LIMIT,
        }
    )
    response["Cache-Control"] = "no-store"
    return response


@require_GET
@_staff_json
def source_view(request):
    """Bir kaynak IP'nin zaman çizelgesi: özet, olaylar (eskiden yeniye), eşikler, ilgili eylemler."""
    try:
        data = source_detail.build_source(request.GET.get("ip"))
    except source_detail.SourceError as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    response = JsonResponse(data)
    response["Cache-Control"] = "no-store"
    return response
