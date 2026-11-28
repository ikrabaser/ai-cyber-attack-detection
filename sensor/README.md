# Sensör katmanı

Trafikten (Zeek) olay üretip backend'e (`POST /api/events/`) gönderecek parça. Kademe kademe
ilerliyoruz; her kademede çalışan ve anlaşılır bir şey var.

| Kademe | Konu | Durum |
|---|---|---|
| 1 | Zeek `conn.log` okumak | tamam |
| 2 | Özellik çıkarma (zaman penceresi başına sayılar) | tamam |
| 3 | Kural tabanlı skor → backend → panel | **tamam** |
| 4 | Lab + gerçek saldırılar, etiketli veri | **tamam** (`lab/` çalıştırıldı, ilk ölçüm 17 Kasım 2026) |
| 5 | XGBoost | **tamam** |
| 6 | Autoencoder | **tamam** |
| 7 | Karar tablosu ve eşikler | **tamam** |

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
| `brute_force` (bağlantı) | ≥ 8 bağlantı, ≥ %90'ı aynı giriş servisine (SSH, RDP, FTP, Telnet, VNC) | 0,50 + 0,20 × bağlantı bolluğu |
| `brute_force` (parola) | pencerede ≥ 10 **başarısız SSH parola denemesi** (Zeek `ssh.log`) | 0,60 + 0,20 × deneme bolluğu (30 denemede tam) |

İki brute force kanıtından yüksek skorlu olan kullanılır. İkincisi laboratuvarda gerekti: Hydra bir SSH
bağlantısından 5 parola dener (`ssh.log`'da `auth_attempts=5`), 202 sn'lik koşu `conn.log`'da yalnızca 21
bağlantı olarak göründü ve 10 sn'de en çok 5 bağlantı verdi. Bağlantı sayan kural (eşik 8) bunu hiç
yakalamadı; parola denemelerini doğrudan sayan kural yakalar.

**`ssh.log` nasıl kullanılır:** `conn.log`'un yanında `ssh.log` varsa otomatik okunur (`--ssh-log YOL` ile
başka dosya, `--no-ssh` ile kapatma). Başarısız deneme = `auth_attempts`, bağlantı başarıyla bittiyse bir
eksiği (son deneme doğruydu). Toplam, pencerenin `ssh_failed_auth` alanına yazılır. Bu alan **modelin girdisi
(FEATURES) değildir**, yalnızca kurallara ve olay ayrıntısına gider: model sütunları sabit kalır, ayrıca
CIC-IDS2017'de karşılığı yok. ssh.log yokken alan 0'dır ve davranış eskisiyle aynıdır.

**Israr (persistence) bonusu:** Tek pencere zayıf kanıt olabilir (brute force'un ilk penceresi 0,53).
Aynı kaynakta aynı kural tekrar tetiklenirse her tekrar +0,10 ekler (en fazla +0,40). Tekrarlar peş peşe
olmak zorunda değil: iki tetiklenme arasında o kaynaktan hiç kayıt gelmeyen en çok 9 pencere (90 sn) geçebilir.
Neden: Hydra bağlantıyı 9-40 sn açık tutar ve Zeek bağlantıyı **başladığı** pencereye yazar; lab'daki 200 sn'lik
koşu 40-60 sn arayla 5 ayrı patlama gibi göründü ve ardışıklık isteyen zincir hiç kurulmadı (4 pencere de 0,70'te
kaldı). Araya o kaynaktan kuralı tetiklemeyen bir kayıt girerse (kaynak o pencerede başka türlü davrandı) zincir
yine kopar. Böylece saldırı sürdükçe risk tırmanır. Düzey eşikleri backend'le aynı yuvarlamayla (4 hane) hesaplanır.

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
İki olay aynı anda işlenirse (birden fazla worker) PostgreSQL danışma kilidi, aynı hedef için tek eylem açılmasını sağlar (`core.actions._lock_target`).

## Canlı izleme (`--follow`)

Toplu modda dosya bir kez okunur. `--follow` dosyayı `tail -f` gibi takip eder; her 10 saniyelik
pencere bittikten sonra değerlendirilir ve tespit varsa hemen backend'e gider. Panelde saldırı,
saldırı sürerken görünür.

```bash
python detect.py ../lab/data/conn.log --follow --send       # yalnızca YENİ kayıtları izler
python detect.py ../lab/data/conn.log --follow --send -v    # kural tetiklenmeyen pencereleri de yazar
python detect.py ../lab/data/conn.log --follow --from-start # dosyada zaten olanları da işler
```

Nasıl çalışır ve neye dikkat etmeli:

- **Gecikme:** Zeek bir bağlantıyı bitince yazar ve `ts` bağlantının BAŞLANGICIDIR; uzun bir bağlantı
  kendi penceresi geçtikten sonra gelir. Bu yüzden pencere bitiminden `--grace` sn (varsayılan 8) sonra
  kapanır. Tespit en geç yaklaşık `pencere + grace` = 18 sn sonra panelde olur.
- **Geç kalan kayıt:** Pencere kapandıktan sonra gelen kayıt atılır ve çıkışta sayılır
  (`N kayıt geç geldiği için atlandı`). Bu sayı sıfırdan belirgin büyükse `--grace` artırılmalı.
- **Aynı sonuç:** Canlı mod `Detector` sınıfını (kurallar + ısrar bonusu) toplu modla paylaşır. Örnek
  `sample/conn.log` canlı akıtıldığında toplu moddaki aynı 7 tespit çıkar (`test_follow.py`).
- **Saat farkı sorun değil:** Pencerenin bitip bitmediği, kayıtların kendi zamanı ile izleyicinin
  saati arasındaki farktan öğrenilir; Zeek konteyneri ve Windows saati farklı olsa da çalışır.
- **Backend kapalıysa:** İzleme durmaz; o olay atlanır ve "gönderilemedi" diye sayılır. Token
  reddedilirse (401) durur.
- **Zeek yeniden başlarsa:** Dosya kısalırsa (Zeek `conn.log`'u sıfırlar) baştan okunur.
- **Durdurma:** Ctrl+C; çıkışta özet yazılır, kapanmamış pencereler gönderilmez.

## Modeli ikinci sinyal olarak kullanmak (`--model`)

Eğitilmiş XGBoost modeli (`ml/`) kurallara EK olarak çalışabilir. Sensör xgboost kurmaz: model
`ml/export_model.py` ile küçük bir JSON'a çevrilir (`models/xgb.json`, 600 ağaç, ~200 KB), `tree_model.py`
ağaçları standart kütüphaneyle gezer (XGBoost'la aynı olasılıkları verdiği `ml/test_export_model.py` ile sınanır).

    python detect.py sample/conn.log --model models/xgb.json
    python detect.py lab/data/conn.log --follow --send --model models/xgb.json --model-threshold 0.9

Karar kuralları:

- **Kural tetiklendiyse karar kuralındır.** Skor değişmez; nedenlere "model de aynı fikirde" ya da
  "model farklı tür öneriyor" notu eklenir.
- **Kural susmuş, model bir saldırı sınıfını `--model-threshold` (varsayılan 0,90) üstünde olasılıkla
  görüyorsa** "yalnızca model" tespiti çıkar. Skoru 0,50 (eşikte) ile 0,80 (olasılık 1,0) arasındadır, ısrar
  bonusu dahil en çok 0,85: yani kural kanıtı olmadan **"high" çıkmaz**.
- Modelin **"brute_force"** demesi yalnızca giriş servisi portlarında (21, 22, 23, 3389, 5900) sinyal sayılır:
  model "çok bağlantı, tek port" örüntüsünü başka bir porta (örn. DNS 53) da brute force sanabiliyor. Bu gerekçe
  alan bilgisine dayanır (brute force bir kimlik doğrulama servisine yapılır), eşik taramasıyla bulunmadı.
- Model yoksa davranış öncekiyle birebir aynıdır.

Kararın kaynağı panele de gider: olay gövdesinde `features.detected_by` (`rules`, `rules+model`, `model`) ve modelin
kendi görüşü (`xgb_label`, `xgb_score`) bulunur. Panelde tablodaki risk rozetinin yanında "Yalnızca model" ya da
"Kural + model" rozeti, olay çekmecesinde "Modelin görüşü" satırı görünür. Sensör `--model` olmadan çalışıyorsa
rozet çıkmaz. Denemek için: `docker compose exec backend python manage.py emit_test_event --ip 203.0.113.7 --detected-by model`.

Neden kuralların yerine geçmiyor? Laboratuvarda brute force'u model yakalayamadı (0/4), ssh.log'lu kurallar 4/4
yakaladı. Model ise kuralların kaçırdığı bazı taramaları/brute force pencerelerini yakalıyor. CIC test
pencerelerinde (tek pencere, ısrar bonusu yok, `ssh.log` yok) ölçüm:

| Eşik | Tarama (30) | Brute force (281) | Normalde yanlış alarm (29.289) |
| --- | --- | --- | --- |
| yalnızca kurallar | 24 | 242 | 7 |
| + model, 0,99 | 27 | 274 | 9 |
| + model, 0,95 | 29 | 274 | 18 |
| + model, 0,90 (varsayılan) | 30 | 274 | 18 |
| + model, 0,50 | 30 | 274 | 25 |

Dikkat: tarama sınıfı test kümesinde yalnızca 30 pencere; sonuçlar kaba bir işarettir, kesin başarı değildir.
Modelin yeniden üretimi: `cd ml; python train_xgb.py data/windows_lycos.csv --save data/xgb.json; python export_model.py data/xgb.json ../sensor/models/xgb.json`.

## Dosyalar

- `zeek_reader.py`: Zeek TSV (varsayılan) ve JSON biçimini okuyan, bağımlılıksız okuyucu.
- `read_conn_log.py`: dosyayı özetleyen komut (Kademe 1).
- `features.py`: pencere başına 7 özelliği hesaplayan fonksiyonlar (Kademe 2).
- `extract_features.py`: özellik tablosunu gösteren / CSV'ye yazan komut (Kademe 2).
- `rules.py`: kurallar (port taraması, brute force: bağlantı ve parola kanıtı) + ısrar bonusu (Kademe 3).
- `client.py`: tespiti backend'in JSON biçimine çevirir ve `POST /api/events/` ile yollar (Kademe 3).
- `detect.py`: conn.log → özellik → kural → (isteğe bağlı) backend komutu (Kademe 3); `--follow` ile canlı.
- `tree_model.py`: XGBoost modelini XGBoost'suz çalıştıran ağaç yorumlayıcısı; `models/xgb.json`: dışa aktarılmış model.
- `follow.py`: dosyayı takip eden `tail_records` ve pencereleri kapatan `LiveMonitor` (canlı izleme).
- `sample/conn.log`: sentetik örnek.
- `test_zeek_reader.py`, `test_features.py`, `test_rules.py`, `test_client.py`, `test_follow.py`, `test_model.py`: testler.
