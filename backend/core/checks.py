"""Başlangıç denetimleri: örnek ya da zayıf sırlarla, korumasız yapılandırmayla çalışmayı görünür kılar.

`.env.example` içindeki "degistir-beni..." değerleri herkesçe bilinir. Bu değerler (ya da çok kısa sırlar) kullanılıyorsa
`manage.py runserver`/`check` uyarı verir; DEBUG kapalıyken (SECRETS_STRICT) hata verir. Mesajlar sırrın KENDİSİNİ yazmaz, yalnızca adını.
"""

import ipaddress

from django.conf import settings
from django.core.checks import Error, Warning, register

PLACEHOLDER_MARK = "degistir-beni"
MIN_LENGTH = 16

# (ayar adı, .env anahtarı)
SECRET_SETTINGS = (
    ("SENSOR_API_TOKEN", "SENSOR_API_TOKEN"),
    ("RT_PROXY_SECRET", "RT_PROXY_SECRET"),
    ("RT_API_KEY", "RT_API_KEY"),
    ("SECRET_KEY", "DJANGO_SECRET_KEY"),
)


def _problem(value):
    if PLACEHOLDER_MARK in value.lower():
        return "placeholder", "örnek (herkesçe bilinen) bir değer"
    if len(value) < MIN_LENGTH:
        return "short", f"çok kısa (en az {MIN_LENGTH} karakter olmalı)"
    return None


@register()
def check_secrets(app_configs, **kwargs):
    issues = []
    strict = getattr(settings, "SECRETS_STRICT", True)
    level = Error if strict else Warning
    for setting, env_key in SECRET_SETTINGS:
        value = getattr(settings, setting, "") or ""
        if not value:
            continue  # boş: uç nokta kapalı kalır (güvenli varsayılan), uyarı gerekmez
        problem = _problem(value)
        if problem:
            code, why = problem
            issues.append(level(
                f"{env_key} {why}.",
                hint=f".env içinde {env_key} için uzun, rastgele bir değer kullan (örn. python -c \"import secrets; print(secrets.token_urlsafe(32))\").",
                id=f"core.{'E' if strict else 'W'}001",
            ))
    return issues


AUTO_MODES = {"dry_run", "enforce"}


@register()
def check_protected_ips(app_configs, **kwargs):
    """Korumalı IP listesi: geçersiz girdi her öneriyi bozar, boş liste otomatik kademede tehlikelidir."""
    issues = []
    entries = list(getattr(settings, "PROTECTED_IPS", None) or [])
    for raw in entries:
        try:
            ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            issues.append(Error(
                f"PROTECTED_IPS içinde geçersiz değer: {raw!r}.",
                hint="Her girdi bir IP ya da CIDR olmalı (örn. 192.168.56.1 veya 10.77.0.0/24).",
                id="core.E003",
            ))
    mode = getattr(settings, "AUTO_REMEDIATION_MODE", "advise")
    if not entries and mode in AUTO_MODES:
        strict = getattr(settings, "SECRETS_STRICT", True)
        issues.append((Error if strict else Warning)(
            f"AUTO_REMEDIATION_MODE={mode} iken PROTECTED_IPS boş: ağ geçidi, DNS ve sensör engellenebilir.",
            hint=".env içinde PROTECTED_IPS'e bu makinelerin adreslerini yaz (saldırı testi yaptığın saldırgan VM'inkini yazma).",
            id=f"core.{'E' if strict else 'W'}002",
        ))
    return issues


@register()
def check_threat_intel_bad_ips(app_configs, **kwargs):
    """Bilinen kötü IP listesi yalnızca ipucu gösterir (bkz. threat_intel.py): hatalı girdi hiçbir eylemi
    engellemez ya da otomatik onaylamaz, bu yüzden her zaman uyarıdır (Error değil)."""
    issues = []
    for raw in getattr(settings, "THREAT_INTEL_BAD_IPS", None) or []:
        try:
            ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            issues.append(Warning(
                f"THREAT_INTEL_BAD_IPS içinde geçersiz değer: {raw!r}, yoksayılır.",
                hint="Her girdi bir IP ya da CIDR olmalı (örn. 203.0.113.7 veya 198.51.100.0/24).",
                id="core.W003",
            ))
    return issues
