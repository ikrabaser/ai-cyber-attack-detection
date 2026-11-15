"""Panelin olay filtreleri: sorgu parametrelerini doğrular ve Event sorgusuna uygular.

Parametreler kullanıcıdan (staff) gelse de sıkı doğrulanır: IP öneki yalnızca IP'de geçebilecek
karakterlerden oluşur (LIKE joker karakteri geçemez), düzey ve aralık sabit listeden seçilir.
"""

import re
from datetime import timedelta

from django.utils import timezone

LIMIT = 100

IP_PREFIX_RE = re.compile(r"^[0-9a-f:.]{1,45}$")
LEVELS = ("low", "medium", "high")  # düşükten yükseğe
RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
MAX_ATTACK_TYPE_LENGTH = 64  # models.Event.attack_type ile aynı


class FilterError(ValueError):
    """Geçersiz filtre parametresi (istemciye 400 olarak döner)."""


def parse(params):
    ip = (params.get("ip") or "").strip().lower()
    if ip and not IP_PREFIX_RE.match(ip):
        raise FilterError("geçersiz IP öneki")

    attack_type = (params.get("attack_type") or "").strip()
    if len(attack_type) > MAX_ATTACK_TYPE_LENGTH:
        raise FilterError("saldırı türü çok uzun")

    min_level = params.get("min_level") or ""
    if min_level and min_level not in LEVELS:
        raise FilterError("geçersiz düzey")

    time_range = params.get("range") or "all"
    if time_range != "all" and time_range not in RANGES:
        raise FilterError("geçersiz zaman aralığı")

    return {"ip": ip, "attack_type": attack_type, "min_level": min_level, "range": time_range}


def apply(queryset, filters, now=None):
    if filters["ip"]:
        queryset = queryset.filter(source_ip__startswith=filters["ip"])
    if filters["attack_type"]:
        queryset = queryset.filter(attack_type=filters["attack_type"])
    if filters["min_level"]:
        queryset = queryset.filter(risk_level__in=LEVELS[LEVELS.index(filters["min_level"]) :])
    if filters["range"] != "all":
        since = (now or timezone.now()) - RANGES[filters["range"]]
        queryset = queryset.filter(created_at__gte=since)
    return queryset
