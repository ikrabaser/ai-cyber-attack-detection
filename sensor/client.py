"""Tespiti backend'e gönderir (Kademe 3): Detection -> JSON -> POST /api/events/.

Yalnızca standart kütüphane. Backend'in beklediği alanlar `backend/core/ingest.py` içinde.
"""

import json
import urllib.error
import urllib.request

from features import FEATURES

DEFAULT_URL = "http://localhost:8000/api/events/"


def build_event(det):
    """Detection -> backend'in kabul ettiği JSON gövdesi."""
    features = {name: det.row[name] for name in FEATURES}
    features["window_start"] = det.window_start
    features["top_port"] = det.row["top_port"]
    return {
        "source_ip": det.src_ip,
        "target_host": det.row["top_dst_host"],
        "attack_type": det.attack_type,
        "risk_score": round(det.risk_score, 4),
        "summary": "; ".join(det.reasons),
        "features": features,
    }


def send_event(url, token, payload, timeout=5):
    """(HTTP durum kodu, cevap sözlüğü) döner. 4xx/5xx istisna FIRLATMAZ: çağıran karar verir.

    Backend'e hiç ulaşılamazsa (bağlantı reddi, zaman aşımı) urllib.error.URLError fırlar.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    try:
        body = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        body = {"error": raw[:200].decode("utf-8", "replace")}
    return status, body
