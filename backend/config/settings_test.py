"""Testler için ayarlar: Postgres ve Procrastinate gerektirmez (sqlite, bellekte).

Çalıştır:  python manage.py test --settings=config.settings_test
Procrastinate görev kuyruğu bu ayarlarda yüklenmez; kuyruğa atma testlerde taklit edilir.
Gerçek kuyruk davranışı docker compose ile denenir.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-key")

from .settings import *  # noqa: E402,F401,F403

INSTALLED_APPS = [a for a in INSTALLED_APPS if a != "procrastinate.contrib.django"]  # noqa: F405
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

RT_PROXY_SECRET = "test-proxy-secret"
RT_API_KEY = "test-api-key"
SENSOR_API_TOKEN = "test-sensor-token"
PROTECTED_IPS = ["192.168.56.1", "192.168.56.10", "10.0.0.0/24"]
PROTECTED_HOSTS = ["sensor", "gateway"]
AUTO_REMEDIATION_MODE = "advise"
