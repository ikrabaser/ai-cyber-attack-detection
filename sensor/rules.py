"""Kural tabanlı risk skoru (Kademe 3). Henüz model yok: kurallar elle yazılmış ve okunabilir.

Neden önce kurallar? (1) Modellerin ölçülebilir bir kıyas noktası olur: "model, basit kurallardan
daha iyi mi?". (2) Sensör -> backend -> panel hattını modelden bağımsız olarak uçtan uca
kurmuş oluruz. (3) Bir saldırının veride neye benzediğini kendi gözümüzle yazmak, sonra
modelin neyi öğrendiğini anlamamızı kolaylaştırır.

Her kural bir özellik satırına (Kademe 2) bakar, tetiklenirse (skor, nedenler) döner:

  port_scan    : bir pencerede çok sayıda FARKLI porta dokunmak.
                 skor = 0,55 + 0,25 x port bolluğu + 0,20 x başarısız oran
  brute_force  : bir giriş servisine (SSH, RDP...) kısa sürede çok sayıda bağlantı.
                 skor = 0,50 + 0,20 x bağlantı bolluğu

Tek pencere kanıtı zayıf olabilir (brute force'un ilk penceresi ~0,53). Ama saldırı sürdükçe
şüphe artmalı: aynı kaynakta aynı kural ART ARDA pencerelerde tetikleniyorsa her ardışık
pencere skora +0,10 ekler (en fazla +0,40). Buna "ısrar (persistence)" bonusu diyoruz.

Kurallar bilerek SÜREYE (mean_duration) bakmaz: Kademe 2'de gördük, tek bir uzun meşru bağlantı
ortalamayı şişirip yanlış alarm üretiyordu.
"""

from dataclasses import dataclass, field

from features import WINDOW_SECONDS

# Kimlik doğrulama isteyen servisler: brute force bunlara karşı yapılır.
AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}

SCAN_MIN_PORTS = 10          # bir pencerede bu kadar farklı port: tarama şüphesi
SCAN_FULL_AT_EXTRA = 30      # 10 + 30 = 40 port ve üstünde "port bolluğu" tam sayılır

BRUTE_MIN_CONNS = 8          # penceredeki en az bağlantı sayısı
BRUTE_MIN_PORT_SHARE = 0.9   # bağlantıların en az %90'ı aynı giriş servisine
BRUTE_FULL_AT_EXTRA = 12     # 8 + 12 = 20 bağlantı ve üstünde "bolluk" tam sayılır

STREAK_BONUS = 0.10
STREAK_BONUS_MAX = 0.40

# Backend'in risk düzeyi eşikleriyle aynı olmalı (backend/config/settings.py).
MEDIUM_AT, HIGH_AT = 0.7, 0.9


def level_for(score):
    return "high" if score >= HIGH_AT else "medium" if score >= MEDIUM_AT else "low"


@dataclass
class Detection:
    src_ip: str
    window_start: int
    attack_type: str
    risk_score: float
    reasons: list = field(default_factory=list)
    row: dict = field(default_factory=dict)

    @property
    def level(self):
        return level_for(self.risk_score)


def port_scan(row):
    """Tetiklenirse (temel skor, nedenler), aksi halde None."""
    ports = row["n_dst_ports"]
    if ports < SCAN_MIN_PORTS:
        return None
    abundance = min(1.0, (ports - SCAN_MIN_PORTS) / SCAN_FULL_AT_EXTRA)
    score = 0.55 + 0.25 * abundance + 0.20 * row["fail_ratio"]
    return score, [
        f"{row['n_conns']} bağlantıyla {ports} farklı porta dokundu",
        f"bağlantıların %{row['fail_ratio'] * 100:.0f}'i başarısız",
    ]


def brute_force(row):
    port = row["top_port"]
    if (port not in AUTH_PORTS
            or row["top_port_share"] < BRUTE_MIN_PORT_SHARE
            or row["n_conns"] < BRUTE_MIN_CONNS):
        return None
    abundance = min(1.0, (row["n_conns"] - BRUTE_MIN_CONNS) / BRUTE_FULL_AT_EXTRA)
    score = 0.50 + 0.20 * abundance
    return score, [
        f"{AUTH_PORTS[port]} ({port}) servisine {row['n_conns']} bağlantı "
        f"(bağlantıların %{row['top_port_share'] * 100:.0f}'i aynı porta)",
    ]


RULES = {"port_scan": port_scan, "brute_force": brute_force}


def detect(rows, window=WINDOW_SECONDS):
    """Özellik satırlarını (zamana göre sıralı) tarar, tetiklenen kurallar için Detection döndürür.

    Her (kaynak, pencere) için en fazla bir sonuç: tetiklenen kuralların en yüksek skorlusu.
    """
    streaks = {}  # (kaynak, kural) -> (son pencere başlangıcı, ardışık sayısı)
    detections = []

    for row in rows:
        best = None
        for name, rule in RULES.items():
            key = (row["src_ip"], name)
            hit = rule(row)
            if hit is None:
                streaks.pop(key, None)  # kural sustu: ısrar zinciri bozuldu
                continue

            base, reasons = hit
            prev = streaks.get(key)
            consecutive = prev is not None and row["window_start"] == prev[0] + window
            count = prev[1] + 1 if consecutive else 1
            streaks[key] = (row["window_start"], count)

            bonus = min(STREAK_BONUS_MAX, STREAK_BONUS * (count - 1))
            score = min(1.0, base + bonus)
            if count > 1:
                reasons = [*reasons, f"{count}. ardışık pencere (+{bonus:.2f})"]
            if best is None or score > best.risk_score:
                best = Detection(row["src_ip"], row["window_start"], name, score, reasons, row)

        if best is not None:
            detections.append(best)
    return detections
