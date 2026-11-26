"""Elle yapıştırılan bir IP/CIDR listesini THREAT_INTEL_BAD_IPS formatına çevirir.

Hiçbir dosyaya yazmaz, veritabanına dokunmaz; yalnızca metni ayrıştırıp
doğrular ve normalize eder (bkz. management/commands/normalize_threat_intel_ips.py).
Geçersiz girdi sessizce atılmaz: ayrı listede döner ki komut bunu bildirsin.
"""

import ipaddress
import re


def split_tokens(text):
    """Virgül, yeni satır ya da boşlukla ayrılmış serbest metni tek tek girdilere böler."""
    return [t for t in re.split(r"[,\s]+", text) if t]


def _normalize_one(raw):
    """(canonical_str, None) geçerliyse; (None, None) boş/yorum satırıysa; (None, raw) geçersizse."""
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None, None
    if "/" in raw:
        try:
            return str(ipaddress.ip_network(raw, strict=False)), None
        except ValueError:
            return None, raw
    try:
        return str(ipaddress.ip_address(raw)), None
    except ValueError:
        return None, raw


def normalize_list(tokens):
    """Sırayı koruyarak tekrarsız geçerli girdiler ve ayrı bir geçersiz girdi listesi döner."""
    valid, invalid, seen = [], [], set()
    for raw in tokens:
        ok, bad = _normalize_one(raw)
        if bad is not None:
            invalid.append(bad)
        elif ok is not None and ok not in seen:
            seen.add(ok)
            valid.append(ok)
    return valid, invalid
