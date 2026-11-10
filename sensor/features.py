"""Bağlantı kayıtlarından (conn.log) zaman penceresi başına özellik çıkarır (Kademe 2).

Fikir: tek bir bağlantı çoğu zaman masum görünür. Saldırı, aynı kaynağın kısa sürede
yaptığı bağlantıların TOPLU davranışında ortaya çıkar. Bu yüzden kayıtları
(kaynak IP, zaman penceresi) çiftine göre gruplayıp her grup için birkaç sayı hesaplıyoruz.
Bir grup = modelin göreceği tek bir "örnek" (satır).

Önemli: eğitimde de canlı sistemde de AYNI fonksiyonu kullanacağız. Özellikler iki yerde
farklı hesaplanırsa model eğitimde öğrendiğini canlıda tanıyamaz ("train/serve skew").
"""

from collections import Counter, defaultdict

WINDOW_SECONDS = 10

# Başarısız sayılan bağlantı durumları: cevap yok (S0), reddedildi (REJ), yarım kalıp RST ile
# kesilen (RSTOS0, RSTRH). Port taraması bunlardan çok üretir, normal trafik çok az.
FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH"}

# Modelin göreceği sütunlar (sıra sabit; CSV ve model bu sıraya güvenecek).
FEATURES = [
    "n_conns",         # pencerede kaç bağlantı kurdu
    "n_dst_ports",     # kaç FARKLI hedef porta dokundu (tarama: çok, brute force: 1)
    "n_dst_hosts",     # kaç FARKLI hedef makineye dokundu (ağ taraması: çok)
    "fail_ratio",      # bağlantıların kaçta kaçı başarısız (0-1)
    "mean_duration",   # ortalama bağlantı süresi (sn); cevap yoksa süre 0 sayılır
    "mean_bytes",      # bağlantı başına ortalama toplam bayt (gönderilen + alınan)
    "top_port_share",  # bağlantıların kaçta kaçı en çok vurulan porta (1.0: hep aynı porta)
]


def window_start(ts, size=WINDOW_SECONDS):
    """Zamanı pencere başlangıcına yuvarlar. Pencereler sabit ve üst üste binmez (tumbling).

    Örnek (size=10): 1794301207.3 -> 1794301200
    Sınırdaki bir saldırı iki pencereye bölünebilir; kayan (sliding) pencere bunu çözer
    ama şimdilik basit tutuyoruz.
    """
    return int(ts // size) * size


def compute_features(conns):
    """Aynı kaynağın aynı penceredeki bağlantıları -> özellik sözlüğü."""
    n = len(conns)
    if n == 0:
        raise ValueError("boş bağlantı listesi için özellik hesaplanamaz")

    ports = Counter(c["id.resp_p"] for c in conns)
    failed = sum(1 for c in conns if c["conn_state"] in FAILED_STATES)
    # Zeek cevap gelmeyen bağlantılarda süre/bayt yazmaz (None). Bunu 0 sayıyoruz:
    # "bağlantı hiç yaşamadı, hiç veri akmadı".
    durations = [c.get("duration") or 0.0 for c in conns]
    total_bytes = [(c.get("orig_bytes") or 0) + (c.get("resp_bytes") or 0) for c in conns]

    return {
        "n_conns": n,
        "n_dst_ports": len(ports),
        "n_dst_hosts": len({c["id.resp_h"] for c in conns}),
        "fail_ratio": failed / n,
        "mean_duration": sum(durations) / n,
        "mean_bytes": sum(total_bytes) / n,
        "top_port_share": max(ports.values()) / n,
    }


def extract(records, window=WINDOW_SECONDS):
    """Kayıtları (kaynak IP, pencere) ile gruplayıp her grup için bir satır döndürür.

    Dönen satırlar zamana, sonra kaynağa göre sıralıdır:
        {"src_ip": ..., "window_start": ..., "n_conns": ..., ...}
    """
    groups = defaultdict(list)
    for r in records:
        groups[(r["id.orig_h"], window_start(r["ts"], window))].append(r)

    rows = []
    for (src_ip, start), conns in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        rows.append({"src_ip": src_ip, "window_start": start, **compute_features(conns)})
    return rows
