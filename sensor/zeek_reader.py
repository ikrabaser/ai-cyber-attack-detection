"""Zeek günlük (log) dosyalarını okur. Yalnızca standart kütüphane kullanır.

Zeek varsayılan olarak sekmeyle ayrılmış (TSV) bir metin dosyası yazar:

    #separator \\x09
    #set_separator  ,
    #empty_field    (empty)
    #unset_field    -
    #path           conn
    #fields         ts      uid     id.orig_h   id.orig_p   ...
    #types          time    string  addr        port        ...
    1731229200.12   CAbc..  192.168.56.50   51044   ...
    #close          2026-11-10-09-05-00

- "#fields" sütun adlarını, "#types" her sütunun Zeek türünü söyler.
- Değeri olmayan alan "-" (unset) yazılır. Bunu Python'da None yapıyoruz.
- Boş küme/metin "(empty)" yazılır.

Zeek isterse JSON da yazabilir (her satır bir JSON nesnesi). İkisini de okuyoruz.
"""

import json

# conn_state alanının anlamları (Zeek dokümantasyonundan, kısaltılmış).
# Saldırı türlerini ayırt etmede en bilgi verici alanlardan biridir.
CONN_STATE_ACIKLAMA = {
    "S0": "SYN gönderildi, cevap yok (kapalı/filtreli port taraması sık görülür)",
    "S1": "Bağlantı kuruldu, henüz kapanmadı",
    "SF": "Normal kuruldu ve normal kapandı",
    "REJ": "Bağlantı reddedildi (hedef RST döndü: port kapalı)",
    "S2": "Kuruldu, kaynak kapatmaya çalıştı, hedeften cevap yok",
    "S3": "Kuruldu, hedef kapatmaya çalıştı, kaynaktan cevap yok",
    "RSTO": "Kuruldu, kaynak RST ile iptal etti",
    "RSTR": "Kuruldu, hedef RST ile iptal etti",
    "RSTOS0": "Kaynak SYN'den sonra RST gönderdi, hedeften SYN-ACK görülmedi",
    "RSTRH": "Hedef SYN-ACK'ten sonra RST gönderdi, kaynaktan SYN görülmedi",
    "SH": "Kaynak SYN'den sonra FIN gönderdi (yarı açık)",
    "SHR": "Hedef SYN-ACK'ten sonra FIN gönderdi (yarı açık)",
    "OTH": "Başlangıç görülmedi (kayıt ortasından yakalanmış trafik)",
}


def _convert(value, zeek_type, unset, empty, set_sep):
    """Tek bir hücreyi Zeek türüne göre Python değerine çevirir."""
    if value == unset:
        return None
    is_collection = zeek_type.startswith(("set[", "vector["))
    if value == empty:
        return [] if is_collection else ""
    if zeek_type in ("time", "interval", "double"):
        return float(value)
    if zeek_type in ("count", "int", "port"):
        return int(value)
    if zeek_type == "bool":
        return value == "T"
    if is_collection:
        return value.split(set_sep)
    return value  # string, addr, enum, subnet...: metin olarak kalır


class LineParser:
    """Zeek log satırlarını tek tek çözer; başlık (#fields, #types ...) durumunu kendisi tutar.

    `read_log` dosyayı baştan sona okurken, canlı izleme (follow.py) ise dosyaya eklenen satırları
    geldikçe vermek için aynı sınıfı kullanır: böylece iki yol aynı biçimi aynı şekilde çözer.
    """

    def __init__(self, label="log"):
        self.label = label  # hata mesajlarında dosya adı yerine yazılır
        self.sep, self.set_sep, self.empty, self.unset = "\t", ",", "(empty)", "-"
        self.fields, self.types = [], []

    def parse(self, raw, lineno=0):
        """Bir satır -> kayıt sözlüğü; başlık, yorum ya da boş satırsa None."""
        line = raw.rstrip("\n").rstrip("\r")
        if not line:
            return None
        where = f"{self.label}:{lineno}"

        if line.startswith("#"):
            if line.startswith("#separator"):
                # "#separator \x09": ayraç, ters eğik çizgili kaçışla yazılır
                self.sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            else:
                name, _, rest = line[1:].partition(self.sep)
                if name == "set_separator":
                    self.set_sep = rest
                elif name == "empty_field":
                    self.empty = rest
                elif name == "unset_field":
                    self.unset = rest
                elif name == "fields":
                    self.fields = rest.split(self.sep)
                elif name == "types":
                    self.types = rest.split(self.sep)
            return None

        if line.startswith("{"):  # JSON biçimi
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{where}: geçersiz JSON satırı ({exc})") from exc

        if not self.fields or len(self.fields) != len(self.types):
            raise ValueError(f"{where}: veri satırından önce #fields/#types başlığı yok")
        values = line.split(self.sep)
        if len(values) != len(self.fields):
            raise ValueError(f"{where}: {len(self.fields)} sütun bekleniyordu, {len(values)} geldi")
        return {
            name: _convert(value, ztype, self.unset, self.empty, self.set_sep)
            for name, ztype, value in zip(self.fields, self.types, values)
        }


def read_log(path):
    """Bir Zeek log dosyasındaki her kaydı sözlük olarak sırayla verir (yield).

    Dosyayı tek seferde belleğe almaz; satır satır okur, büyük dosyalarda da çalışır.
    Beklenmeyen biçimde bir satır görürse ValueError ile dosya adı ve satır numarasını söyler.
    """
    parser = LineParser(str(path))
    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            record = parser.parse(raw, lineno)
            if record is not None:
                yield record
