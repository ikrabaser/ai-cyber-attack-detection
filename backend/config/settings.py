import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None):
    return os.environ.get(name, default)


def env_bool(name, default=False):
    return str(env(name, default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default=""):
    return [x.strip() for x in str(env(name, default)).split(",") if x.strip()]


# --- Temel Django ---------------------------------------------------------

DEBUG = env_bool("DJANGO_DEBUG", False)
SECRET_KEY = env("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-key"
    else:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY tanımlı olmalı.")

ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,backend")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", "")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Procrastinate, görev tanımlarını bulan uygulamalardan ÖNCE gelmeli.
    "procrastinate.contrib.django",
    "core",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env("POSTGRES_DB", "ids"),
        "USER": env("POSTGRES_USER", "ids"),
        "PASSWORD": env("POSTGRES_PASSWORD", ""),
        "HOST": env("POSTGRES_HOST", "localhost"),
        "PORT": env("POSTGRES_PORT", "5432"),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]

LANGUAGE_CODE = "tr"
TIME_ZONE = "Europe/Istanbul"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
}

# --- Gerçek zamanlı katman (Centrifugo) -----------------------------------

# Backend -> Centrifugo yayını (sunucu API'si)
RT_API_URL = env("RT_API_URL", "http://centrifugo:8000/api")
RT_API_KEY = env("RT_API_KEY", "")
# Centrifugo -> backend proxy isteklerinde doğrulanan ortak sır.
# Boşsa proxy uç noktaları her isteği reddeder (güvenli varsayılan).
RT_PROXY_SECRET = env("RT_PROXY_SECRET", "")

# --- Sensör girişi --------------------------------------------------------

# POST /api/events/ için Bearer token. Boşsa uç nokta her isteği reddeder.
SENSOR_API_TOKEN = env("SENSOR_API_TOKEN", "")

# --- Risk eşikleri --------------------------------------------------------

RISK_LOW_THRESHOLD = float(env("RISK_LOW_THRESHOLD", "0.5"))  # altı: olay üretilmez
RISK_MEDIUM_THRESHOLD = float(env("RISK_MEDIUM_THRESHOLD", "0.7"))
RISK_HIGH_THRESHOLD = float(env("RISK_HIGH_THRESHOLD", "0.9"))
if not (0 <= RISK_LOW_THRESHOLD <= RISK_MEDIUM_THRESHOLD <= RISK_HIGH_THRESHOLD <= 1):
    raise ImproperlyConfigured("Risk eşikleri 0 <= düşük <= orta <= yüksek <= 1 olmalı.")

# --- Müdahale politikası --------------------------------------------------

PROTECTED_IPS = env_list("PROTECTED_IPS", "")
PROTECTED_HOSTS = env_list("PROTECTED_HOSTS", "")

AUTO_REMEDIATION_MODE = env("AUTO_REMEDIATION_MODE", "advise")
if AUTO_REMEDIATION_MODE not in {"advise", "dry_run", "enforce"}:
    raise ImproperlyConfigured("AUTO_REMEDIATION_MODE: advise | dry_run | enforce olmalı.")

AUTO_BLOCK_TTL_SECONDS = int(env("AUTO_BLOCK_TTL_SECONDS", "600"))
MAX_AUTO_BLOCK_TTL_SECONDS = int(env("MAX_AUTO_BLOCK_TTL_SECONDS", "3600"))
APPROVAL_TTL_SECONDS = int(env("APPROVAL_TTL_SECONDS", "1800"))

# config_fix eylemi için serbest komut yok; yalnızca önceden tanımlı düzeltmeler.
ALLOWED_CONFIG_FIXES = env_list("ALLOWED_CONFIG_FIXES", "ssh_disable_password_auth")

# Takılabilir parçalar (nokta ile ayrılmış sınıf yolu)
FIREWALL_BACKEND = env("FIREWALL_BACKEND", "core.firewall.LogOnlyBackend")
AGENT_BACKEND = env("AGENT_BACKEND", "core.agent.RuleAgent")
