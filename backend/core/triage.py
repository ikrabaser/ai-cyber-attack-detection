"""Triage: bir incident için "bu gerçek mi?" sorusuna kanıt toplar.

Kural tabanlı, deterministik ve yalnızca kendi verimizi kullanır (dış servis yok). Her kanıtın bir ağırlığı vardır:
artı değer saldırı yönünde, eksi değer yanlış alarm yönünde, 0 yalnızca bilgidir. Toplam puan bir ÖNERİ üretir;
karar yine insanındır (core.incidents.decide). Claude ajanı geldiğinde aynı kanıtı hazır alıp üstüne akıl yürütür.

Güvenlik: Event.features ve attack_type saldırgan kontrolünde olabilir. Kanıt metinlerine bunlardan yalnızca sayıya
çevrilmiş değerler ve bizim sabit etiketlerimiz girer; serbest metin hiçbir zaman çıktıya taşınmaz.
"""

import ipaddress

from django.db.models import Count, Q

from .models import Action, AuditLog, Incident
from .protection import is_protected_ip

# Kanıt ağırlıkları (artı: saldırı yönünde, eksi: yanlış alarm yönünde).
W_PROTECTED = -3
W_INTERNAL = -1
W_PRIOR_FALSE_POSITIVE = -2
W_PRIOR_CONFIRMED = 3
W_REPEAT = 1
W_CHAIN = 3
W_FAIL_RATIO = 1
W_PORT_SWEEP = 1
W_HOST_SWEEP = 1
W_PERSISTENT = 1
W_LOW_VOLUME = -1
W_HIGH_RISK = 1
W_LOW_RISK = -1
W_ACTIVITY_AFTER_BLOCK = 2

ATTACK_THRESHOLD = 4
FALSE_POSITIVE_THRESHOLD = -2

# Yalnızca RFC1918 özel ağlar "iç ağ" sayılır. Python'un is_private'ı belgeleme aralıklarını (203.0.113.0/24) da
# kapsadığı için kullanılmıyor.
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]

# Sensörün saldırı türlerini ATT&CK taktiğine eşler (türün içinde geçen sabit anahtar sözcükle).
_TACTICS = (
    ("scan", "recon", "Keşif (T1046)"),
    ("brute", "credential", "Kimlik bilgisi erişimi (T1110)"),
    ("dos", "impact", "Etki (T1498)"),
)


def _is_internal(ip):
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def _num(value):
    """features içinden yalnızca gerçek sayıları al (bool ve metin hariç)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return value


def _max_feature(events, name):
    values = [_num((e.features or {}).get(name)) for e in events]
    values = [v for v in values if v is not None]
    return max(values) if values else None


def _stage_order(events):
    """Olayların taktik sırası (ilk görülme sırasına göre, tekrarsız)."""
    seen = []
    for event in sorted(events, key=lambda e: (e.created_at, e.pk)):
        kind = str(event.attack_type or "").lower()
        for key, code, label in _TACTICS:
            if key in kind and code not in [c for c, _ in seen]:
                seen.append((code, label))
    return seen


def _item(code, weight, text):
    return {"code": code, "weight": weight, "text": text}


def _history(incident):
    """Aynı IP'nin bu incident dışındaki geçmişi."""
    rows = (
        Incident.objects.filter(source_ip=incident.source_ip)
        .exclude(pk=incident.pk)
        .aggregate(
            total=Count("pk"),
            false_positive=Count("pk", filter=Q(status=Incident.Status.FALSE_POSITIVE)),
        )
    )
    # "Saldırıyı onayla" kararı denetim kaydında kalır; incident sonradan Çöz ile kapansa da saldırı sayılır.
    rows["confirmed"] = (
        AuditLog.objects.filter(verb="confirm_incident", target=incident.source_ip)
        .exclude(detail__incident_id=incident.pk)
        .count()
    )
    return rows


def triage(incident, events, actions=None):
    """`events`: incident'in olayları (en çok MAX_EVENTS), `actions`: ona bağlı eylemler."""
    events = list(events)
    actions = list(actions) if actions is not None else []
    evidence = []

    # 1) Kimlik: korumalı / iç ağ
    if is_protected_ip(incident.source_ip):
        evidence.append(_item("protected_ip", W_PROTECTED,
                              "Kaynak korumalı listede (ağ geçidi, DNS, sensör gibi); büyük olasılıkla bizim altyapımız."))
    elif _is_internal(incident.source_ip):
        evidence.append(_item("internal_ip", W_INTERNAL,
                              "Kaynak iç ağdan (özel adres). İç taramalar sık yanlış alarm olur, ama yanal hareket de olabilir."))

    # 2) Geçmiş
    hist = _history(incident)
    if hist["false_positive"]:
        evidence.append(_item("prior_false_positive", W_PRIOR_FALSE_POSITIVE,
                              f"Bu IP daha önce {hist['false_positive']} kez yanlış alarm olarak kapatıldı."))
    if hist["confirmed"]:
        evidence.append(_item("prior_confirmed", W_PRIOR_CONFIRMED,
                              f"Bu IP daha önce {hist['confirmed']} kez gerçek saldırı olarak onaylandı."))
    other = max(0, hist["total"] - hist["false_positive"] - hist["confirmed"])
    if other >= 2:
        evidence.append(_item("repeat_offender", W_REPEAT,
                              f"Bu IP daha önce {other} ayrı incident üretti (tekrarlayan kaynak)."))

    # 3) Zincir (ATT&CK taktikleri)
    stages = _stage_order(events)
    tactics = [label for _, label in stages]
    codes = [code for code, _ in stages]
    if "recon" in codes and "credential" in codes and codes.index("recon") < codes.index("credential"):
        evidence.append(_item("recon_to_credential", W_CHAIN,
                              "Aynı IP önce keşif (tarama), sonra kimlik bilgisi denemesi yaptı: saldırı zinciri."))
    elif tactics:
        evidence.append(_item("tactics", 0, "Gözlenen taktik: " + ", ".join(tactics) + "."))

    # 4) Davranış (yalnızca sayısal özelliklerden türetilen özet)
    fail_ratio = _max_feature(events, "fail_ratio")
    n_conns = _max_feature(events, "n_conns")
    ports = _max_feature(events, "n_dst_ports")
    hosts = _max_feature(events, "n_dst_hosts")
    if fail_ratio is not None and fail_ratio >= 0.8 and (n_conns or 0) >= 10:
        evidence.append(_item("high_failure_ratio", W_FAIL_RATIO,
                              f"Bir pencerede bağlantıların %{round(fail_ratio * 100)}'i başarısız oldu (pencere başına en çok {int(n_conns)} bağlantı)."))
    if ports is not None and ports >= 15:
        evidence.append(_item("port_sweep", W_PORT_SWEEP, f"Tek pencerede {int(ports)} farklı porta dokundu."))
    if hosts is not None and hosts >= 5:
        evidence.append(_item("host_sweep", W_HOST_SWEEP, f"Tek pencerede {int(hosts)} farklı makineye dokundu."))
    if incident.event_count >= 3:
        evidence.append(_item("persistent", W_PERSISTENT,
                              f"{incident.event_count} ayrı pencerede devam etti (ısrarlı)."))
    elif incident.event_count == 1 and n_conns is not None and n_conns <= 5:
        evidence.append(_item("low_volume", W_LOW_VOLUME,
                              f"Tek pencere ve yalnızca {int(n_conns)} bağlantı: düşük hacim."))

    # 5) Model riski
    if incident.max_risk >= 0.85:
        evidence.append(_item("high_risk", W_HIGH_RISK, f"En yüksek risk skoru yüksek ({incident.max_risk:.2f})."))
    elif incident.max_risk <= 0.55:
        evidence.append(_item("low_risk", W_LOW_RISK, f"En yüksek risk skoru düşük ({incident.max_risk:.2f})."))

    # 6) Engel sonrası etki
    blocks = [a for a in actions
              if a.kind == Action.Kind.BLOCK_IP and a.decided_at
              and a.status in (Action.Status.EXECUTED, Action.Status.ROLLED_BACK)]
    if blocks:
        applied = min(a.decided_at for a in blocks)
        after = sum(1 for e in events if e.created_at > applied)
        if after:
            evidence.append(_item("activity_after_block", W_ACTIVITY_AFTER_BLOCK,
                                  f"IP engellendikten sonra {after} yeni olay geldi: engel durdurmadı ya da başka yol var."))
        else:
            evidence.append(_item("quiet_after_block", 0, "IP engellendikten sonra yeni olay gelmedi."))

    score = sum(item["weight"] for item in evidence)
    if score >= ATTACK_THRESHOLD:
        verdict = "likely_attack"
    elif score <= FALSE_POSITIVE_THRESHOLD:
        verdict = "likely_false_positive"
    else:
        verdict = "uncertain"
    confidence = round(min(1.0, abs(score) / 8), 2) if verdict != "uncertain" else round(min(0.5, abs(score) / 8), 2)
    return {
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "evidence": evidence,
        "tactics": tactics,
    }


SNAPSHOT_VERSION = 1
SNAPSHOT_EVENTS = 100
SNAPSHOT_ACTIONS = 50


def snapshot(incident):
    """Karar anının kaydı: öneri + kanıt kodları/ağırlıkları + incident'in o anki özeti.

    Denetim kaydına yazılır; sonradan hesaplanmaz, çünkü incident ve kanıtlar zamanla değişir. Böylece her insan kararı,
    "karar anında bilinen kanıt + insan etiketi" çiftine dönüşür (ileride model eğitimi/kalibrasyonu için). Metin ve serbest
    alan taşımaz: yalnızca sabit kodlar, sayılar ve bizim etiketlerimiz.
    """
    events = list(incident.events.order_by("-created_at", "-id")[:SNAPSHOT_EVENTS])
    actions = list(Action.objects.filter(event__incident=incident).order_by("-id")[:SNAPSHOT_ACTIONS])
    result = triage(incident, events, actions)
    return {
        "version": SNAPSHOT_VERSION,
        "verdict": result["verdict"],
        "score": result["score"],
        "confidence": result["confidence"],
        "evidence": [{"code": e["code"], "weight": e["weight"]} for e in result["evidence"]],
        "tactics": result["tactics"],
        "incident": {
            "status_before": incident.status,
            "event_count": incident.event_count,
            "max_risk": incident.max_risk,
            "risk_level": incident.risk_level,
        },
    }
