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


def read_log(path):
    """Bir Zeek log dosyasındaki her kaydı sözlük olarak sırayla verir (yield).

    Dosyayı tek seferde belleğe almaz; satır satır okur, büyük dosyalarda da çalışır.
    Beklenmeyen biçimde bir satır görürse ValueError ile dosya adı ve satır numarasını söyler.
    """
    sep, set_sep, empty, unset = "\t", ",", "(empty)", "-"
    fields, types = [], []

    with open(path, encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.rstrip("\n").rstrip("\r")
            if not line:
                continue

            if line.startswith("#"):
                if line.startswith("#separator"):
                    # "#separator \x09": ayraç, ters eğik çizgili kaçışla yazılır
                    sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
                else:
                    name, _, rest = line[1:].partition(sep)
                    if name == "set_separator":
                        set_sep = rest
                    elif name == "empty_field":
                        empty = rest
                    elif name == "unset_field":
                        unset = rest
                    elif name == "fields":
                        fields = rest.split(sep)
                    elif name == "types":
                        types = rest.split(sep)
                continue

            if line.startswith("{"):  # JSON biçimi
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{lineno}: geçersiz JSON satırı ({exc})") from exc
                continue

            if not fields or len(fields) != len(types):
                raise ValueError(f"{path}:{lineno}: veri satırından önce #fields/#types başlığı yok")
            values = line.split(sep)
            if len(values) != len(fields):
                raise ValueError(
                    f"{path}:{lineno}: {len(fields)} sütun bekleniyordu, {len(values)} geldi"
                )
            yield {
                name: _convert(value, ztype, unset, empty, set_sep)
                for name, ztype, value in zip(fields, types, values)
            }
