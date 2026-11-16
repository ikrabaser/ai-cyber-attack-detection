"""Başlangıç denetimleri: örnek ya da zayıf sırlarla çalışmayı görünür kılar.

`.env.example` içindeki "degistir-beni..." değerleri herkesçe bilinir. Bu değerler (ya da çok kısa sırlar) kullanılıyorsa
`manage.py runserver`/`check` uyarı verir; DEBUG kapalıyken (SECRETS_STRICT) hata verir. Mesajlar sırrın KENDİSİNİ yazmaz, yalnızca adını.
"""

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
