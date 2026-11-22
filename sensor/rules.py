"""Kural tabanlı risk skoru (Kademe 3). Henüz model yok: kurallar elle yazılmış ve okunabilir.

Neden önce kurallar? (1) Modellerin ölçülebilir bir kıyas noktası olur: "model, basit kurallardan
daha iyi mi?". (2) Sensör -> backend -> panel hattını modelden bağımsız olarak uçtan uca
kurmuş oluruz. (3) Bir saldırının veride neye benzediğini kendi gözümüzle yazmak, sonra
modelin neyi öğrendiğini anlamamızı kolaylaştırır.

Her kural bir özellik satırına (Kademe 2) bakar, tetiklenirse (skor, nedenler) döner:

  port_scan    : bir pencerede çok sayıda FARKLI porta dokunmak.
                 skor = 0,55 + 0,25 x port bolluğu + 0,20 x başarısız oran
  brute_force  : iki kanıttan biri (ikisi de varsa yüksek skorlu olan):
                 (a) bir giriş servisine (SSH, RDP...) kısa sürede çok sayıda BAĞLANTI.
                     skor = 0,50 + 0,20 x bağlantı bolluğu
                 (b) Zeek ssh.log'a göre çok sayıda BAŞARISIZ PAROLA DENEMESİ. Hydra gibi araçlar bir
                     bağlantıdan birkaç deneme yapar; (a) bunu göremez, (b) doğrudan sayar.
                     skor = 0,60 + 0,20 x deneme bolluğu (doğrudan kanıt: taban daha yüksek)

Tek pencere kanıtı zayıf olabilir (brute force'un ilk penceresi ~0,53). Ama saldırı sürdükçe
şüphe artmalı: aynı kaynakta aynı kural tekrar tekrar tetikleniyorsa her tekrar skora +0,10
ekler (en fazla +0,40). Buna "ısrar (persistence)" bonusu diyoruz. Tekrarlar peş peşe olmak
zorunda değil: araya o kaynaktan HİÇ kayıt gelmeyen pencereler girebilir (en çok 9 pencere = 90 sn),
çünkü Hydra gibi araçlar bağlantıyı uzun açık tutar ve Zeek bağlantıyı BAŞLADIĞI pencereye yazar:
200 sn'lik bir saldırı 40-60 sn arayla 5 ayrı patlama gibi görünür. Araya o kaynaktan kuralı
tetiklemeyen bir kayıt girerse (kaynak o pencerede başka türlü davrandı) zincir yine kopar.

İsteğe bağlı ikinci sinyal: eğitilmiş XGBoost modeli (`tree_model.py`, `Detector(model=...)`). Kurallara
EK olarak çalışır, onların yerini almaz: (1) kural tetiklendiyse karar kuralındır (model yalnızca "aynı
fikirde" ya da "başka tür öneriyor" notu ekler); (2) kural tetiklenmedi ama model bir saldırı sınıfını
yeterince emin (varsayılan olasılık >= 0,90) görüyorsa "yalnızca model" tespiti üretilir. Böyle tespitin
skoru en çok MODEL_ONLY_MAX (0,85) olur: kural kanıtı olmadan "high" çıkmaz. Neden böyle? Laboratuvarda
brute force'u modelin hiç yakalayamadığı (0/4), kuralların ssh.log ile 4/4 yakaladığı görüldü; port taramasında
ise ikisi de iyi. Model olmadan davranış tamamen aynı kalır.

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

SSH_MIN_FAILED = 10          # bir pencerede en az bu kadar başarısız SSH parola denemesi
SSH_FULL_AT_EXTRA = 20       # 10 + 20 = 30 deneme ve üstünde "bolluk" tam sayılır

STREAK_MAX_GAP_WINDOWS = 9   # iki tetiklenme arası en çok bu kadar pencere (varsayılan 10 sn: 90 sn) geçebilir

STREAK_BONUS = 0.10
STREAK_BONUS_MAX = 0.40

MODEL_MIN_PROB = 0.90        # model bir saldırı sınıfını en az bu olasılıkla görürse "model sinyali" sayılır
MODEL_BASE_SCORE = 0.50      # eşikte (p = MODEL_MIN_PROB) yalnızca-model skoru
MODEL_SCORE_SPAN = 0.30      # p = 1,0'da skor 0,50 + 0,30 = 0,80
MODEL_ONLY_MAX = 0.85        # kural kanıtı yoksa (ısrar bonusu dahil) skor bunu geçemez -> "high" olmaz

# Backend'in risk düzeyi eşikleriyle aynı olmalı (backend/config/settings.py).
MEDIUM_AT, HIGH_AT = 0.7, 0.9


def level_for(score):
    # Backend skoru 4 hanede yuvarlanmış alır (client.build_event); aynı yuvarlama, yoksa 0,7 + 0,2 gibi
    # kayan nokta toplamları (0,8999999...) eşiğin hemen altında kalıp sensörde "medium", backend'de "high" olurdu.
    score = round(score, 4)
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


def _brute_by_connections(row):
    port = row["top_port"]
    if (port not in AUTH_PORTS
            or row["top_port_share"] < BRUTE_MIN_PORT_SHARE
            or row["n_conns"] < BRUTE_MIN_CONNS):
        return None
    abundance = min(1.0, (row["n_conns"] - BRUTE_MIN_CONNS) / BRUTE_FULL_AT_EXTRA)
    return 0.50 + 0.20 * abundance, [
        f"{AUTH_PORTS[port]} ({port}) servisine {row['n_conns']} bağlantı "
        f"(bağlantıların %{row['top_port_share'] * 100:.0f}'i aynı porta)",
    ]


def _brute_by_failed_auth(row):
    failed = row.get("ssh_failed_auth", 0)
    if failed < SSH_MIN_FAILED:
        return None
    abundance = min(1.0, (failed - SSH_MIN_FAILED) / SSH_FULL_AT_EXTRA)
    return 0.60 + 0.20 * abundance, [
        f"{failed} başarısız SSH parola denemesi (Zeek ssh.log), {row['n_conns']} bağlantıda",
    ]


def brute_force(row):
    hits = [h for h in (_brute_by_connections(row), _brute_by_failed_auth(row)) if h]
    return max(hits, key=lambda h: h[0]) if hits else None


RULES = {"port_scan": port_scan, "brute_force": brute_force}


class Detector:
    """Özellik satırlarını TEK TEK alıp ısrar (persistence) zincirini kendisi tutan dedektör.

    `detect` dosyanın tamamını tarar; canlı izleme ise pencereler kapandıkça satır verir. İkisi de
    aynı sınıfı kullanır, bu yüzden aynı trafikte aynı skoru üretir. Satırlar zamana göre
    sıralı verilmelidir.
    """

    def __init__(self, window=WINDOW_SECONDS, model=None, model_threshold=MODEL_MIN_PROB):
        if not 0.0 < model_threshold < 1.0:
            raise ValueError("model_threshold 0 ile 1 arasında olmalı")
        self.window = window
        self.model = model  # `tree_model.TreeModel` ya da None (yalnızca kurallar)
        self.model_threshold = model_threshold
        self.streaks = {}  # (kaynak, kural | "model") -> (son tetiklenen pencere başlangıcı, tetiklenme sayısı)

    def _streak(self, key, window_start):
        """Israr zincirini bir adım ilerletir; (tetiklenme sayısı, bonus) döner."""
        prev = self.streaks.get(key)
        gap = window_start - prev[0] if prev is not None else None
        continues = gap is not None and 0 < gap <= STREAK_MAX_GAP_WINDOWS * self.window
        count = prev[1] + 1 if continues else 1
        self.streaks[key] = (window_start, count)
        return count, min(STREAK_BONUS_MAX, STREAK_BONUS * (count - 1))

    def _rules(self, row):
        best = None
        for name, rule in RULES.items():
            key = (row["src_ip"], name)
            hit = rule(row)
            if hit is None:
                self.streaks.pop(key, None)  # kural sustu: ısrar zinciri bozuldu
                continue

            base, reasons = hit
            count, bonus = self._streak(key, row["window_start"])
            score = min(1.0, base + bonus)
            if count > 1:
                reasons = [*reasons, f"{count}. tetiklenen pencere (+{bonus:.2f})"]
            if best is None or score > best.risk_score:
                best = Detection(row["src_ip"], row["window_start"], name, score, reasons, row)
        return best

    def _model_signal(self, row):
        """Model bir saldırı sınıfını yeterince emin görüyorsa (sınıf, olasılık), yoksa None."""
        proba = self.model.predict_proba(row)
        cls = max(proba, key=proba.get)
        if cls == "normal" or proba[cls] < self.model_threshold:
            self.streaks.pop((row["src_ip"], "model"), None)
            return None
        return cls, proba[cls]

    def feed(self, row):
        """Bir satır -> o (kaynak, pencere) için en yüksek skorlu tespit, yoksa None.

        Model yoksa yalnızca kurallara bakılır. Model varsa: kural tetiklendiyse karar kuralındır (nota
        modelin görüşü eklenir); tetiklenmediyse ve model emin bir saldırı görüyorsa "yalnızca model"
        tespiti üretilir (skoru MODEL_ONLY_MAX ile sınırlı).
        """
        best = self._rules(row)
        if self.model is None:
            return best

        signal = self._model_signal(row)
        if signal is None:
            return best
        cls, p = signal
        count, bonus = self._streak((row["src_ip"], "model"), row["window_start"])
        if best is not None:
            note = (f"model de aynı fikirde ({cls}, olasılık {p:.2f})" if best.attack_type == cls
                    else f"model farklı tür öneriyor: {cls} (olasılık {p:.2f})")
            best.reasons.append(note)
            return best

        base = MODEL_BASE_SCORE + MODEL_SCORE_SPAN * (p - self.model_threshold) / (1.0 - self.model_threshold)
        score = min(MODEL_ONLY_MAX, base + bonus)
        reasons = [f"yalnızca model: {cls} olasılığı {p:.2f}, kurallar tetiklenmedi"]
        if count > 1:
            reasons.append(f"model {count}. pencerede ısrar ediyor (+{bonus:.2f})")
        return Detection(row["src_ip"], row["window_start"], cls, score, reasons, row)


def detect(rows, window=WINDOW_SECONDS, model=None, model_threshold=MODEL_MIN_PROB):
    """Özellik satırlarını (zamana göre sıralı) tarar, tetiklenen kurallar için Detection döndürür.

    Her (kaynak, pencere) için en fazla bir sonuç: tetiklenen kuralların en yüksek skorlusu.
    """
    detector = Detector(window, model, model_threshold)
    found = []
    for row in rows:
        det = detector.feed(row)
        if det is not None:
            found.append(det)
    return found
