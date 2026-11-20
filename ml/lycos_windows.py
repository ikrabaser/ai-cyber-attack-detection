"""LycoS-IDS2017 akışlarını sensörün (kaynak IP, 10 sn) pencerelerine çevirir (ML-1).

    python lycos_windows.py <lycos-csv-klasörü> --out data/windows_lycos.csv

Neden böyle: modelleri CIC-IDS2017 üzerinde eğitip kendi sensörümüzde (Zeek) kullanacağız. Özellikler
iki yerde farklı hesaplanırsa model canlıda öğrendiğini tanımaz (train/serve skew). Bu yüzden pencere ve
özellik hesabını burada yeniden YAZMIYORUZ: her LycoS akışını Zeek conn.log kaydına benzeyen bir sözlüğe
çevirip sensörün `features.extract` fonksiyonuna veriyoruz.

Alan eşlemesi (LycoS -> Zeek conn.log):
    src_addr, dst_addr, dst_port  -> id.orig_h, id.resp_h, id.resp_p
    timestamp (mikrosaniye)       -> ts (saniye)
    flow_duration (mikrosaniye)   -> duration (saniye)
    fwd_pkt_len_tot / bwd_pkt_len_tot -> orig_bytes / resp_bytes (yük baytı)
    bayraklar + paket sayıları    -> conn_state (aşağıya bak)

Bilinen sınırlama: Zeek'in `conn_state` değeri LycoS'ta yok. `state_from_flags` bunu bayraklardan
YAKLAŞIK üretir; yalnızca `fail_ratio` için gereken "başarısız mı" ayrımı korunur.

Etiket: pencerenin etiketi, içindeki akışların en çok görülen etiketidir. `label_share` o etiketin payıdır
(1.0 = pencere saf). Sınırdaki karışık pencereleri ML-2'de bu sütunla ayıklarız.
"""

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "sensor"))

from features import FEATURES, WINDOW_SECONDS, extract, window_start  # noqa: E402

COLUMNS = ["day", "src_ip", "window_start", *FEATURES, "top_port", "top_dst_host", "label", "label_share",
           "n_flows"]

# Dosyadan yalnızca bunlar okunur (her dosya yüzlerce MB; gereksiz sütun belleği şişirir).
USE_COLS = ["src_addr", "dst_addr", "dst_port", "ip_prot", "timestamp", "flow_duration",
            "fwd_pkt_cnt", "bwd_pkt_cnt", "fwd_pkt_len_tot", "bwd_pkt_len_tot",
            "flag_SYN", "flag_rst", "label"]

TCP = 6
CHUNK_SECONDS = 3600  # 10 sn'nin katı olmalı: pencere iki parçaya bölünmesin.


def state_from_flags(flow):
    """Akışın "başarısız" olup olmadığını Zeek conn_state diliyle söyler: "S0", "REJ" ya da "SF".

    - Hiç cevap paketi yok (bwd_pkt_cnt == 0)            -> "S0"  (cevap gelmedi)
    - TCP, SYN var, RST var, toplam <= 2 paket           -> "REJ" (SYN'e RST ile cevaplandı: kapalı port)
    - diğer her şey                                      -> "SF"  (normal bitti)

    Port taraması bu yüzden yüksek `fail_ratio` üretir (LycoS PortScan akışları: 1 SYN + 1 RST).
    Veri aktarıp sonra RST ile biten uzun bağlantılar "başarısız" sayılmaz: toplam paket sınırı bunun için.
    """
    if flow["bwd_pkt_cnt"] == 0:
        return "S0"
    if (flow["ip_prot"] == TCP and flow["flag_SYN"] > 0 and flow["flag_rst"] > 0
            and flow["fwd_pkt_cnt"] + flow["bwd_pkt_cnt"] <= 2):
        return "REJ"
    return "SF"


def flow_to_record(flow):
    """Bir LycoS akışı (sözlük) -> sensörün `extract` fonksiyonunun beklediği Zeek tarzı kayıt."""
    return {
        "ts": flow["timestamp"] / 1e6,
        "id.orig_h": flow["src_addr"],
        "id.resp_h": flow["dst_addr"],
        "id.resp_p": int(flow["dst_port"]),
        "duration": flow["flow_duration"] / 1e6,
        "orig_bytes": flow["fwd_pkt_len_tot"],
        "resp_bytes": flow["bwd_pkt_len_tot"],
        "conn_state": state_from_flags(flow),
    }


def window_labels(flows, window=WINDOW_SECONDS):
    """(kaynak IP, pencere) -> (en çok görülen etiket, payı, akış sayısı)."""
    counts = {}
    for f in flows:
        key = (f["src_addr"], window_start(f["timestamp"] / 1e6, window))
        counts.setdefault(key, Counter())[f["label"]] += 1
    out = {}
    for key, c in counts.items():
        label, n = c.most_common(1)[0]
        total = sum(c.values())
        out[key] = (label, n / total, total)
    return out


def windows_from_flows(flows, day, window=WINDOW_SECONDS):
    """Akış sözlükleri listesi -> etiketli pencere satırları (COLUMNS sırasıyla sözlük)."""
    labels = window_labels(flows, window)
    rows = []
    for row in extract([flow_to_record(f) for f in flows], window=window):
        label, share, n = labels[(row["src_ip"], row["window_start"])]
        rows.append({"day": day, "src_ip": row["src_ip"], "window_start": row["window_start"],
                     **{k: row[k] for k in FEATURES}, "top_port": row["top_port"],
                     "top_dst_host": row["top_dst_host"], "label": label, "label_share": round(share, 4),
                     "n_flows": n})
    return rows


def windows_from_frame(frame, day, window=WINDOW_SECONDS, chunk=CHUNK_SECONDS):
    """pandas DataFrame (bir günün akışları) -> pencere satırları, saat saat işlenir.

    Bir günde 1 milyondan fazla akış olabilir; hepsini sözlüğe çevirmek belleği şişirir. Akışları
    zamana göre sıralayıp `chunk` saniyelik dilimlere bölüyoruz. Dilim sınırı pencere sınırıyla
    çakıştığı için (3600, 10'a bölünür) hiçbir pencere ikiye bölünmez.
    """
    if chunk % window:
        raise ValueError("chunk, window'un katı olmalı")
    frame = frame.sort_values("timestamp", kind="stable")
    slot = (frame["timestamp"] // 1_000_000 // chunk).to_numpy()
    rows = []
    for s in sorted(set(slot)):
        part = frame[slot == s]
        rows.extend(windows_from_flows(part.to_dict("records"), day, window))
    return rows


def day_name(path):
    """`Tuesday-WorkingHours.pcap_lycos.csv` -> `Tuesday`."""
    return Path(path).name.split("-")[0]


def build(csv_dir, out_path, window=WINDOW_SECONDS):
    import pandas as pd  # içe aktarma burada: testler pandas'sız da çalışsın

    files = sorted(Path(csv_dir).glob("*-WorkingHours.pcap_lycos.csv"))
    if not files:
        raise SystemExit(f"{csv_dir} içinde *-WorkingHours.pcap_lycos.csv bulunamadı")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = Counter()
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        for path in files:
            day = day_name(path)
            frame = pd.read_csv(path, usecols=USE_COLS)
            rows = windows_from_frame(frame, day, window)
            writer.writerows(rows)
            counts = Counter(r["label"] for r in rows)
            total.update(counts)
            print(f"{day}: {len(frame)} akış -> {len(rows)} pencere  {dict(counts)}", flush=True)
    print(f"\nyazıldı: {out_path}  (toplam {sum(total.values())} pencere)")
    return total


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv_dir", help="LycoS *.pcap_lycos.csv dosyalarının klasörü")
    ap.add_argument("--out", default="data/windows_lycos.csv")
    ap.add_argument("--window", type=int, default=WINDOW_SECONDS)
    args = ap.parse_args(argv)
    build(args.csv_dir, args.out, args.window)


if __name__ == "__main__":
    main()
