"""Panel grafikleri için özet sayılar.

Yalnızca sayı ve kısa etiket üretir; olayın özeti ve özellikleri (saldırgan kontrolündeki
metin) buradan hiç geçmez. Zaman kovaları sunucuda sıfırlarla doldurulur, böylece
grafik boş dakikalarda da kesintisiz görünür.
"""

from datetime import datetime, time, timedelta, timezone as dt_timezone

from django.db.models import Count, Max, Q
from django.db.models.functions import TruncDate, TruncHour, TruncMinute
from django.utils import timezone

from .models import Action, Event

# anahtar -> (kova türü, kova sayısı, kova uzunluğu saniye, Django Trunc işlevi)
# 7 günlük görünüm gün kovasıdır; gün uzunluğu yaz saati yüzünden sabit olmadığı için
# o kovalar saniye değil tarih aritmetiğiyle doldurulur.
RANGES = {
    "1h": {"bucket": "minute", "count": 60, "step": 60, "trunc": TruncMinute},
    "24h": {"bucket": "hour", "count": 24, "step": 3600, "trunc": TruncHour},
    "7d": {"bucket": "day", "count": 7, "step": None, "trunc": TruncDate},
}
DEFAULT_RANGE = "24h"
TOP_ATTACK_TYPES = 8
TOP_SOURCES = 5
OTHER_LABEL = "diğer"


def _bucket_starts(spec, now):
    """(başlangıç anı, kova anahtarları, istemciye giden zaman etiketleri) döner."""
    count = spec["count"]
    if spec["bucket"] == "day":
        today = timezone.localtime(now).date()
        days = [today - timedelta(days=i) for i in range(count - 1, -1, -1)]
        since = timezone.make_aware(datetime.combine(days[0], time.min))
        return since, days, [d.isoformat() for d in days]

    local = timezone.localtime(now)
    if spec["bucket"] == "minute":
        local = local.replace(second=0, microsecond=0)
    else:
        local = local.replace(minute=0, second=0, microsecond=0)
    # Aritmetik epoch saniyesi üzerinden yapılır: yerel saat aritmetiği yaz saati
    # geçişinde kayabilir, epoch kayamaz.
    end_ts = int(local.timestamp())
    stamps = [end_ts - spec["step"] * i for i in range(count - 1, -1, -1)]
    labels = [datetime.fromtimestamp(t, tz=dt_timezone.utc).isoformat() for t in stamps]
    since = datetime.fromtimestamp(stamps[0], tz=dt_timezone.utc)
    return since, stamps, labels


def _bucket_key(spec, value):
    return value if spec["bucket"] == "day" else int(value.timestamp())


def build_stats(range_key=DEFAULT_RANGE, now=None):
    spec = RANGES[range_key]
    now = now or timezone.now()
    since, keys, labels = _bucket_starts(spec, now)

    events = Event.objects.filter(created_at__gte=since)

    # Zaman serisi: kova başına düzeye göre olay sayısı (eksik kovalar sıfır).
    series = {key: {"low": 0, "medium": 0, "high": 0} for key in keys}
    rows = (
        events.annotate(bucket=spec["trunc"]("created_at"))
        .order_by()
        .values("bucket", "risk_level")
        .annotate(n=Count("id"))
    )
    for row in rows:
        counts = series.get(_bucket_key(spec, row["bucket"]))
        if counts is not None and row["risk_level"] in counts:
            counts[row["risk_level"]] += row["n"]
    timeline = [{"t": label, **series[key]} for key, label in zip(keys, labels)]

    totals = events.aggregate(events=Count("id"), high_events=Count("id", filter=Q(risk_level="high")))

    # Saldırı türleri: ilk N ayrı, kalanı tek "diğer" satırı (yanıt boyutu sınırlı kalır).
    type_rows = list(
        events.order_by().values("attack_type").annotate(n=Count("id")).order_by("-n", "attack_type")
    )
    attack_types = [{"name": r["attack_type"], "count": r["n"]} for r in type_rows[:TOP_ATTACK_TYPES]]
    rest = sum(r["n"] for r in type_rows[TOP_ATTACK_TYPES:])
    if rest:
        attack_types.append({"name": OTHER_LABEL, "count": rest, "other": True})

    sources = (
        events.order_by()
        .values("source_ip")
        .annotate(n=Count("id"), max_risk=Max("risk_score"))
        .order_by("-n", "source_ip")[:TOP_SOURCES]
    )
    top_sources = [
        {"ip": r["source_ip"], "count": r["n"], "max_risk": round(r["max_risk"], 3)} for r in sources
    ]

    status_rows = (
        Action.objects.filter(created_at__gte=since)
        .order_by()
        .values("status")
        .annotate(n=Count("id"))
        .order_by("-n", "status")
    )
    action_statuses = [{"status": r["status"], "count": r["n"]} for r in status_rows]

    return {
        "range": range_key,
        "bucket": spec["bucket"],
        "since": since.isoformat(),
        "generated_at": now.isoformat(),
        "totals": {
            "events": totals["events"],
            "high_events": totals["high_events"],
            # Aralıktan bağımsız, şu anki durum (panelin kartlarıyla aynı tanım).
            "pending_actions": Action.objects.filter(status=Action.Status.PENDING_APPROVAL)
            .filter(Q(approval_deadline__isnull=True) | Q(approval_deadline__gt=now))
            .count(),
            "active_blocks": Action.objects.filter(
                status=Action.Status.EXECUTED, kind=Action.Kind.BLOCK_IP, effect_expires_at__gt=now
            ).count(),
        },
        "timeline": timeline,
        "attack_types": attack_types,
        "top_sources": top_sources,
        "action_statuses": action_statuses,
    }
