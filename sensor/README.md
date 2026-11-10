# Sensör katmanı

Trafikten (Zeek) olay üretip backend'e (`POST /api/events/`) gönderecek parça. Kademe kademe
ilerliyoruz; her kademede çalışan ve anlaşılır bir şey var.

| Kademe | Konu | Durum |
|---|---|---|
| 1 | Zeek `conn.log` okumak | tamam |
| 2 | Özellik çıkarma (zaman penceresi başına sayılar) | tamam |
| 3 | Kural tabanlı skor → backend → panel | **tamam** |
| 4 | Lab + gerçek saldırılar, etiketli veri | |
| 5 | XGBoost | |
| 6 | Autoencoder | |
| 7 | Karar tablosu ve eşikler | |

## Kademe 1: conn.log nedir?

Zeek ağ trafiğini dinler ve **her bağlantı için tek satırlık bir özet** yazar: `conn.log`. İçerik
(paket içeriği) değil, bağlantının "künyesi". Modellerimizin girdisi bu künyelerden türeyecek.

Önemli alanlar:

| Alan | Anlamı |
|---|---|
| `ts` | Bağlantının başladığı an (Unix zamanı) |
| `id.orig_h` / `id.orig_p` | Bağlantıyı başlatanın IP'si ve portu |
| `id.resp_h` / `id.resp_p` | Cevap verenin IP'si ve portu (hedef servis) |
| `proto`, `service` | `tcp`/`udp`; Zeek'in tanıdığı servis (`http`, `ssh`, `dns`...) |
| `duration` | Bağlantı süresi (sn). Cevap gelmediyse boş (`-`) |
| `orig_bytes` / `resp_bytes` | Kaynağın / hedefin gönderdiği veri miktarı |
| `conn_state` | Bağlantı nasıl sonlandı (aşağıda) |
| `history` | TCP bayrak geçmişi (S=SYN, h=SYN-ACK, A=ACK, D=veri, F=FIN, R=RST; büyük harf=kaynak) |
| `orig_pkts` / `resp_pkts` | Paket sayıları |

`conn_state` saldırı ayırt etmede çok işe yarar: port taraması çok sayıda `REJ` (port kapalı) ve
`S0` (cevap yok) üretir; normal trafik çoğunlukla `SF`'dir.

## Dene

Python 3 yeterli, kurulum yok:

```bash
cd sensor
python read_conn_log.py sample/conn.log          # özet
python read_conn_log.py sample/conn.log -n 60    # ilk 60 kaydı göster
python -m unittest                               # testler
```

`sample/conn.log` **sentetik**: Zeek'in gerçek biçiminde elle kurgulanmış 3 dakikalık bir senaryo.

- 0-180. sn: `192.168.56.50` normal istemci (web + DNS, bir de meşru SSH oturumu)
- 60. sn: `192.168.56.200` saldırgan, `web-01`'e 40 portluk SYN taraması
- 90-150. sn: aynı saldırgan `web-01:22`'ye SSH brute force (saniyede ~1 deneme)

Çıktıda saldırganın bağlantı ve port sayısının normal istemciden ne kadar farklı olduğuna bak.
Ama dikkat: tarama ile brute force **aynı IP'den**, bu yüzden "IP başına toplam" ikisini ayıramıyor.
Kademe 2'nin konusu tam olarak bu: zamanı pencerelere bölüp her pencere için ayrı sayılar çıkarmak.

## Kademe 2: pencere başına özellikler

Tek bir bağlantı çoğu zaman masum görünür; saldırı, aynı kaynağın kısa sürede yaptığı
bağlantıların **toplu davranışında** belli olur. Bu yüzden kayıtları **(kaynak IP, 10 sn'lik pencere)**
çiftine göre gruplayıp her grup için 7 sayı hesaplıyoruz. Bir grup = modelin göreceği bir örnek (satır).

| Özellik | Anlamı | Neyi ele verir |
|---|---|---|
| `n_conns` | pencerede bağlantı sayısı | hız: tarama ve brute force çok bağlantı kurar |
| `n_dst_ports` | farklı hedef port sayısı | port taraması |
| `n_dst_hosts` | farklı hedef makine sayısı | ağ taraması (şimdilik hep 1-2) |
| `fail_ratio` | başarısız bağlantı oranı (`S0`, `REJ`, `RSTOS0`, `RSTRH`) | tarama çok başarısız bağlantı üretir |
| `mean_duration` | ortalama süre (cevap yoksa 0 sayılır) | taramada ~0, brute force'ta ~1,5 sn |
| `mean_bytes` | bağlantı başına ortalama bayt | veri akmayan bağlantılar |
| `top_port_share` | en çok vurulan porta düşen pay | brute force: hep aynı port (%100) |

```bash
python extract_features.py sample/conn.log                 # tabloyu göster
python extract_features.py sample/conn.log -w 5            # 5 sn'lik pencereler
python extract_features.py sample/conn.log --csv out.csv   # CSV'ye yaz (Kademe 5'te modele girecek)
```

### Çıktıyı okumak

Örnek çıktıda (25 satır) üç farklı "parmak izi" var:

| Kim | bağl. | port | başarısız | süre | port payı | Yorum |
|---|---|---|---|---|---|---|
| normal istemci | 2-5 | 2 | %0 | 0,1-0,8 sn | %40-67 | dns + http, sakin |
| saldırgan, 12:01:00 | **40** | **40** | **%95** | 0 | %2 | port taraması |
| saldırgan, 12:01:30 ve sonrası | **9-11** | **1** | %0 | ~1,5 sn | **%100** | SSH brute force |

Kademe 1'de aynı IP'den geldiği için ayıramadığımız tarama ile brute force artık tablonun farklı
sütunlarında ayrışıyor: taramayı `n_dst_ports` ve `fail_ratio`, brute force'u `top_port_share` ve
`n_conns` ele veriyor. Modeller bu ayrımı kendileri öğrenecek.

Dikkat edilecek iki nokta:

- **Ortalama aykırı değerlerden etkilenir.** 12:00:30 penceresinde normal istemcinin meşru, uzun
  SSH oturumu `mean_duration`'ı 9,5 sn'ye çıkarıyor ve 3 porta dokunmuş görünüyor. Böyle durumlar
  yanlış alarmın tohumudur; gerçek veride bunları görüp özellikleri iyileştireceğiz.
- **Aynı fonksiyon her yerde.** Eğitimde de canlıda da özellikler `features.py` ile hesaplanır.
  İki yerde farklı hesaplanırsa model canlıda öğrendiğini tanıyamaz.

Sabit pencerelerin bir zayıflığı: sınırda başlayan bir saldırı iki pencereye bölünür. Kayan pencere
bunu çözer; şimdilik basit tutuyoruz.

## Kademe 3: kural tabanlı skor → backend → panel

Modeller gelmeden önce hattı uçtan uca kuruyoruz. Karar verici şimdilik elle yazılmış, okunabilir
**iki kural** (`rules.py`); modeller geldiğinde aynı hatta takılacak ve kurallar onlar için kıyas noktası olacak.

| Kural | Ne zaman tetiklenir | Temel skor |
|---|---|---|
| `port_scan` | pencerede ≥ 10 farklı port | 0,55 + 0,25 × port bolluğu + 0,20 × başarısız oran |
| `brute_force` | ≥ 8 bağlantı, ≥ %90'ı aynı giriş servisine (SSH, RDP, FTP, Telnet, VNC) | 0,50 + 0,20 × bağlantı bolluğu |

**Israr (persistence) bonusu:** Tek pencere zayıf kanıt olabilir (brute force'un ilk penceresi 0,53).
Aynı kaynakta aynı kural **art arda** pencerelerde tetiklenirse her ardışık pencere +0,10 ekler (en fazla +0,40);
araya sessiz bir pencere girerse zincir kopar. Böylece saldırı sürdükçe risk tırmanır.

Kurallar bilerek `mean_duration`'a bakmaz (Kademe 2'deki 9,5 sn'lik aykırı değer yüzünden).

```bash
python detect.py sample/conn.log                         # tespitleri göster, hiçbir şey göndermez
export SENSOR_API_TOKEN=...                              # backend .env'deki ile aynı
python detect.py sample/conn.log --send                  # backend'e gönder
python detect.py sample/conn.log --send --delay 1        # 1 sn arayla, panelde canlı izlemek için
```

Örnek çıktıda 25 pencereden **7 tespit** çıkar, hepsi saldırgan `192.168.56.200`'den:

| Pencere | Kural | Risk | Düzey |
|---|---|---|---|
| 12:01:00 | port_scan | 0,99 | high |
| 12:01:30 → 12:02:20 | brute_force | 0,53 → 0,65 → 0,72 → 0,83 → 0,93 → 0,93 | low → … → high |

Normal istemci (`192.168.56.50`) hiç işaretlenmez; 12:00:30'daki uzun meşru SSH oturumu dahil.

**Backend tarafı:** Sensör aynı saldırgan için her pencerede yeni olay üretir. Bu yüzden
`propose_action` artık `block_ip` / `isolate_host` için hedefte **geçerli bir eylem** (bekleyen öneri,
süresi dolmamış önlem, TTL penceresindeki kuru çalıştırma) varsa yenisini açmaz, mevcut olanı döndürür ve
denetim kaydına `deduplicated` yazar. Örnek senaryoda 7 olay → panelde **tek** onay bekleyen engel.
Bilinen sınır: iki istek tam aynı anda gelirse veritabanı kısıtı olmadığı için çift kayıt mümkün.

## Dosyalar

- `zeek_reader.py`: Zeek TSV (varsayılan) ve JSON biçimini okuyan, bağımlılıksız okuyucu.
- `read_conn_log.py`: dosyayı özetleyen komut (Kademe 1).
- `features.py`: pencere başına 7 özelliği hesaplayan fonksiyonlar (Kademe 2).
- `extract_features.py`: özellik tablosunu gösteren / CSV'ye yazan komut (Kademe 2).
- `rules.py`: iki kural + ısrar bonusu (Kademe 3).
- `client.py`: tespiti backend'in JSON biçimine çevirir ve `POST /api/events/` ile yollar (Kademe 3).
- `detect.py`: conn.log → özellik → kural → (isteğe bağlı) backend komutu (Kademe 3).
- `sample/conn.log`: sentetik örnek.
- `test_zeek_reader.py`, `test_features.py`, `test_rules.py`, `test_client.py`: testler (49).
