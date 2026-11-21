# ML katmanı

Sensörün kurallarının yanına makine öğrenmesi modelleri (XGBoost, Autoencoder, LSTM) koyuyoruz.
Modeller **sensörle aynı 7 özelliği** (`sensor/features.py`) kullanır; böylece eğitimde öğrendiği
canlıda da geçerli olur.

| Kademe | Konu | Durum |
|---|---|---|
| ML-1 | LycoS-IDS2017 akışlarını (kaynak IP, 10 sn) pencerelerine çevirmek | **tamam** |
| ML-2 | Zamana göre eğitim/test bölmesi, kural tabanlı kıyas, metrikler | **tamam** |
| ML-3 | XGBoost | **tamam** |
| ML-4 | Lab pencerelerinde dış doğrulama | **tamam** |
| ML-5 | Autoencoder (bilinmeyen saldırı) | **tamam** |
| ML-6 | LSTM | |
| ML-7 | Sensöre bağlamak | |

## ML-1: veri hazırlığı

CIC-IDS2017'nin `MachineLearningCVE` CSV'lerinde kaynak IP ve zaman yok; pencere kuramayız. Bu yüzden
IP ve mikrosaniye zaman damgası içeren **LycoS-IDS2017** (aynı trafiğin düzeltilmiş akış çıkarımı) kullanılır.

```
python lycos_windows.py <lycos-ids2017 klasörü> --out data/windows_lycos.csv
```

Klasörde `*-WorkingHours.pcap_lycos.csv` dosyaları aranır. Çıktı sütunları:
`day, src_ip, window_start, <7 özellik>, top_port, top_dst_host, label, label_share, n_flows`
(`top_port` ve `top_dst_host` model girdisi değil; kurallar `top_port`a bakar).

- Özellik hesabı burada yeniden yazılmadı: her akış Zeek `conn.log` kaydına benzeyen bir sözlüğe çevrilip
  sensörün `features.extract` fonksiyonundan geçer.
- `conn_state` LycoS'ta yok; bayraklardan yaklaşık üretilir (`state_from_flags`). Yalnızca `fail_ratio` için
  gereken "başarısız mı" ayrımı korunur.
- `label` pencerenin en çok görülen akış etiketidir, `label_share` payıdır. Karışık pencereler
  (`label_share < 1`) ML-2'de ayıklanır.
- Veri ve çıktı git'e girmez (`ml/data/`).

Testler (pandas gerekir, yoksa ilgili testler atlanır):

```
cd ml
python -m unittest
```

## ML-2: bölme, metrikler, kural kıyası

```
python dataset.py data/windows_lycos.csv      # bölme özeti
python baseline.py data/windows_lycos.csv     # sensörün kuralları aynı pencerelerde
```

- `dataset.py`: sınıflar normal / port_scan / brute_force (FTP+SSH-Patator birleşik). Bölme **zamana göre**:
  her saldırı etiketi kendi zaman çizgisinde (ilk %60 train, 60 sn gap, kalanı test); normal trafik gün gün.
  DoS, web saldırıları, bot ve karışık pencereler (`label_share < 1`) dışarıda kalır.
- `metrics.py`: karışıklık matrisi, precision / recall / F1, macro-F1, FPR; elle yazıldı, hepsi matristen türer.
- `baseline.py`: `sensor/rules.py` aynen çalıştırılır (tüm pencereler zamana göre beslenir, ısrar bonusu
  için). CIC'te ssh.log olmadığından `ssh_failed_auth = 0` verilir.

## ML-3: XGBoost

```
pip install -r requirements.txt
python train_xgb.py data/windows_lycos.csv --save data/xgb.json
```

Aynı bölme, aynı metrikler, kurallarla yan yana. Girdi yalnızca sensörün 7 özelliği (IP ve port model girdisi
değil). Sınıf dengesizliği için örnek ağırlığı (`balanced_weights`); hiperparametreler sabit ve ayarlanmadı,
çünkü test setine bakarak ayar yapmak testi "görülmemiş" olmaktan çıkarır.

## Panelde görmek: Model değerlendirmesi sekmesi

```
python export_report.py data/windows_lycos.csv --out ../backend/core/ml_report.json
```

Betik aynı bölmeyi, aynı modeli ve kuralları çalıştırıp sonuçları küçük bir JSON'a yazar
(`backend/core/ml_report.json`). Panelin "Model değerlendirmesi" sekmesi bu dosyayı yalnızca staff'a
`/panel/api/ml/` ile sunar. Sekme **çevrimdışı** sonucu gösterir; canlı kararlar hâlâ kurallardan gelir.
Veri veya model değişirse dosya yeniden üretilir.

## ML-4: Lab doğrulaması

```
python lab_eval.py ../lab/data/conn.log ../lab/data/runs.jsonl --train data/windows_lycos.csv
```

CIC'te eğitilen model (ML-3 ile aynı sabit parametreler) ve kurallar, kendi lab'ımızda gerçek nmap/Hydra ile
üretilen, hiç görülmemiş trafiğe verilir. Etiketin kaynağı koşu günlüğüdür. Kurallar hem ssh.log ile hem
onsuz ölçülür; model ile adil kıyas "ssh.log yok" olandır. Lab örneği küçüktür, sonuç işaret olarak okunmalıdır.

### Lab sonucu (2026-11-21, tek temiz koşu)

Koşular: 2 normal (2 dk), 1 nmap taraması (1-100 port, `-T2`), 1 Hydra SSH (4 iş parçacığı); koşular
birbirine karışmadan arka arkaya, 33 tam pencere ölçüldü (yarım pencereler ve koşu dışı 2 pencere hariç).

| | normal (22) | port tarama (7) | kaba kuvvet (4) |
|---|---|---|---|
| XGBoost | 22/22 | 7/7 | 0/4 |
| Kurallar (ssh.log ile) | 22/22 | 7/7 | 4/4 |
| Kurallar (ssh.log olmadan) | 22/22 | 7/7 | 0/4 |

Yanlış alarm yok. Port tarama CIC'ten kendi lab'ımıza aktarıldı. Kaba kuvvet aktarılmadı ve nedeni veride
görülüyor: Hydra bir SSH bağlantısında birkaç parola dener, `conn.log`'ta pencere başına 1-4 uzun bağlantı
kalır (normal bir SSH oturumundan ayırt edilemez). Asıl kanıt `ssh.log`'taki başarısız deneme sayısıdır;
modelin girdisinde bu yoktur ve CIC'te ssh.log da yoktur. Örnek çok küçüktür (4 kaba kuvvet penceresi),
sonuç bir işarettir. Ham lab dosyaları `.gitignore`'dadır; çalıştırmak için `lab/README.md`.

## ML-5: Autoencoder

```
python autoencoder.py data/windows_lycos.csv
```

Yalnızca normal pencerelerle eğitilen küçük bir sinir ağı (7 → 5 → 3 → 5 → 7, scikit-learn `MLPRegressor`).
Girdiyi tekrar kurmaya çalışır; normali iyi kurar, öğrenmediği trafiği kuramaz ve hatası büyür. Hata
eşiğin üstündeyse alarm. Eşik, eğitim normallerinin zamanca son %20'sindeki hatanın yüzdeliğidir (%99 ve %99,9),
test setine bakılarak seçilmez. Sinir ağı başlangıca duyarlı olduğundan 5 tohumla çalışır; AUC için ortalama ve
en kötü/en iyi değer verilir. Mimari sonuçlara bakılmadan sabitlendi; iki ek mimari yalnızca duyarlılık
denemesi olarak bakıldı ve sonuçlar mimariye duyarlıdır (özellikle DoS türlerinde), bu yüzden tek sayıya
güvenilmez.

Karşılaştırma, aynı pencerelerde (test normal 29 289, yanlış alarm oranı: kurallar %0,02, XGBoost %0,12,
autoencoder p99 %0,98, p99,9 %0,11). Alarm verilen pencere oranı:

| tür | n | kurallar | XGBoost | yalnızca n_conns eşiği (p99) | AE p99 | AE p99,9 |
|---|---|---|---|---|---|---|
| ddos | 119 | 0,00 | 0,00 | 0,98 | 1,00 | 0,66 |
| dos_hulk | 84 | 0,00 | 0,00 | 0,86 | 0,90 | 0,81 |
| dos_goldeneye | 35 | 0,00 | 0,00 | 0,06 | 0,87 | 0,10 |
| dos_slowloris | 136 | 0,00 | 0,01 | 0,00 | 0,69 | 0,38 |
| portscan (test) | 30 | 0,80 | 1,00 | 0,80 | 0,83 | 0,80 |
| ssh_patator (test) | 140 | 0,74 | 0,96 | 0,00 | 0,00 | 0,00 |
| ftp_patator (test) | 141 | 0,99 | 0,99 | 0,00 | 0,00 | 0,00 |
| web saldırıları, bot, slowhttptest | 12-330 | ~0 | ~0 | ~0 | ~0 | ~0 |

Okuma: kurallar ve XGBoost tarama ve kaba kuvvette güçlü, DoS ailesini hiç yakalamıyor; autoencoder DoS
ailesini yakalıyor, ama kaba kuvveti göremiyor (bağlantı düzeyinde normal görünür). Yani üç yöntem birbirini
tamamlıyor. Dürüst notlar: (1) en basit rakip olan "bağlantı sayısı eşiği" DDoS ve Hulk'ta autoencoder kadar
iyidir; autoencoder'ın asıl katkısı çok özelliği birlikte görmesiyle GoldenEye ve Slowloris'te ortaya çıkar.
(2) %1 yanlış alarm bütçesi canlıda çok alarm demektir; %0,1'e inince DoS yakalama oranı düşer. (3) Web
saldırıları, bot ve slowhttptest bu 7 bağlantı özelliğiyle normalden ayrılamıyor (bot pencereleri normalden bile
"daha normal"); yük (HTTP içeriği) görünmeden bu mümkün değil. (4) Heartbleed ve SQL injection 12 pencere,
sonuçları işaret.
