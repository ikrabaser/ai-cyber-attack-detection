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

## ML-7: Modeli sensöre bağlamak

Eğitilmiş XGBoost, canlı sensörde kurallara ek ikinci sinyal olarak çalışabilir (`sensor/detect.py --model`).
Sensör xgboost kurmadığı için model önce küçük bir JSON'a çevrilir:

    python export_model.py data/xgb.json ../sensor/models/xgb.json

`sensor/tree_model.py` bu JSON'daki ağaçları standart kütüphaneyle gezip XGBoost'la aynı olasılıkları üretir
(`test_export_model.py`: toy veride en çok 1e-5 fark; gerçek modelde 3000 pencerede en çok 2e-7). Karar kuralları
ve ölçüm tablosu için `sensor/README.md`. Kısaca: kural tetiklenirse karar kuralındır, kural susup model >= 0,90
emin ise skoru en çok 0,85 olan "yalnızca model" tespiti çıkar. Tek pencerede kural + model, taramada 24 → 30 / 30,
brute force'ta 242 → 274 / 281 yakalar; normalde yanlış alarm 7 → 18 (29.289 pencere; modelin brute_force'u yalnızca giriş portlarında sayılır).

## ML-8: Etiket gürültüsü deneyi (172.16.0.1)

CIC-IDS2017'de bütün saldırılar tek adresten gelir (172.16.0.1, güvenlik duvarının NAT adresi). Aynı adresten
"benign" etiketli 103 pencere de var. XGBoost'un yanlış alarmlarının çoğu bu adresten çıktığı için sorduk:
bunlar gerçekten model hatası mı, yoksa etiket hatası mı?

    python label_noise.py data/windows_lycos.csv

Bu pencerelerin profili normal pencerelerden belirgin biçimde farklı: bağlantıların **hepsi başarısız** olanlar %64
(diğer normallerde %5,2); hepsi başarısız ve **hiç bayt akmayanlar** %21 (diğerlerinde %0,18); %58'i aynı adresin
bir saldırı penceresine 5 dakikadan yakın. Yani tarama/saldırı kuyruğuna benziyorlar.

| Yöntem | Değerlendirme | Yanlış alarm | FPR % | Tarama P | Tarama R | macro-F1 |
| --- | --- | --- | --- | --- | --- | --- |
| kurallar | tüm test (29.289 normal) | 7 | 0,024 | 0,80 | 0,80 | 0,908 |
| kurallar | şüpheliler hariç (29.205) | 0 | 0,000 | 1,00 | 0,80 | 0,938 |
| XGBoost | tüm test | 31 | 0,106 | 0,58 | 0,97 | 0,897 |
| XGBoost | şüpheliler hariç | 12 | 0,041 | 0,88 | 0,97 | 0,964 |
| XGBoost (şüpheliler eğitimden de çıkarıldı) | tüm test | 35 | 0,119 | 0,57 | 0,97 | 0,893 |
| XGBoost (şüpheliler eğitimden de çıkarıldı) | şüpheliler hariç | 16 | 0,055 | 0,85 | 0,97 | 0,957 |

(XGBoost satırları İkra'nın makinesindeki çıktıdan; kurallar her ortamda aynı.)

Okuma:
- Şüpheli pencereler değerlendirmeden çıkınca modelin yanlış alarmı 31 → 12'ye, kuralların 7 → 0'a düşüyor.
  Yani yanlış alarmın yarısından fazlası (kurallarda hepsi) bu adresten. Bu bulgu iki ortamda da (bizim
  sandbox'ta 35 → 16) ve 10 farklı rastgele tohumda (14-18 aralığı) tekrarlandı: sağlam.
- Şüphelileri EĞİTİMDEN de çıkarmanın etkisi sağlam DEĞİL. Sandbox'ta (xgboost 3.4.1) 10 tohumun hepsinde
  yanlış alarm azaldı (35 → 30), ama İkra'nın makinesinde arttı (31 → 35). Aynı veri ve aynı sabit
  parametreler, farklı sonuç: XGBoost sürümü/platformu farkı. Bu yüzden "eğitimdeki etiket gürültüsü modeli
  bozuyor" demek için henüz kanıt yok. Not: model sonuçları sürüme göre birkaç yanlış alarm oynayabilir;
  sensöre giren model `sensor/models/xgb.json` dosyasıdır (yeniden eğitim aynı ağaçları vermeyebilir).
- Hiçbir şey kanıtlanmadı: pcap olmadan bu pencerelerin saldırı olduğunu söyleyemeyiz, sadece etiketin
  güvenilmez olduğuna dair güçlü bir işaret var. Pencereler yeniden etiketlenmedi.
- Kalan 12-16 yanlış alarm başka kaynaklardan (örneğin DNS sunucusu 192.168.10.3'ün 53. porta 12 bağlantısı
  "brute_force" görülmüş): bunlar gerçek model hatası.
- Tarama sınıfı testte yalnızca 30 pencere; precision/recall oynak, kesin sonuç değil.

## ML-9: H1, eşit yanlış alarm oranında karşılaştırma

Bugüne dek kıyas "her yöntem kendi eşiğinde" yapıldı: kuralların yanlış alarmı %0,02, modelinki %0,1. Fazla alarm veren
yöntem doğal olarak daha çok saldırı yakalar, bu adil değil. `equal_fpr.py` yanlış alarm oranını sabitler ve o
orandaki yakalama oranına (recall, Wilson %95 güven aralığıyla) bakar:

    python equal_fpr.py data/windows_lycos.csv

Her sınıf için pencereye skor: model = sınıfın olasılığı; kurallar = o sınıfta tetiklenen kuralın risk skoru (ısrar
bonusu dahil, tetiklenmediyse 0). CIC'de ssh.log yok, kuralların parola kanıtı kullanılamıyor.

Sandbox çıktısı (xgboost 3.4.1; senin makinende birkaç pencere oynayabilir). Recall [güven aralığı]:

| Sınıf | Normalde izin verilen yanlış alarm | Kurallar | XGBoost |
| --- | --- | --- | --- |
| port_scan (30 pencere) | %0,02 | 0,80 [0,63-0,90] | 0,33 [0,19-0,51] |
| port_scan | %0,05 | 0,80 | 0,97 [0,83-0,99] |
| port_scan | %0,10 ve üstü | 0,80 | 1,00 [0,89-1,00] |
| brute_force (281 pencere) | %0,02 | 0,86 [0,82-0,90] | 0,97 [0,94-0,99] |
| brute_force | %0,10 | 0,86 | 0,97 |
| brute_force | %1 | 0,86 | 0,98 [0,96-0,99] |

Okuma (dürüst sınırlarla):
- **brute_force:** model aynı ya da daha az yanlış alarmda belirgin biçimde daha çok yakalıyor, güven aralıkları
  ayrık. Ama CIC'de kurallar ssh.log'suz; labda tablo ters (model 0/4, ssh.log'lu kurallar 4/4), yani bu üstünlük
  veri setine özgü olabilir.
- **port_scan:** çok sıkı bütçede (%0,02) kurallar iyi, model kötü; %0,05 ve üstünde model önde, ama 30 pencerede
  güven aralıkları çakışıyor: "model daha iyi" diyemeyiz, "kuralların kaçırdığı bir kısmı modelin bulduğu" doğru.
- Kural eğrisi seyrek (skorlar birkaç değer alıyor): kurallar bütçe artınca recall kazanamaz (0,80'de takılır).
  Eşiklerini (SCAN_MIN_PORTS vb.) değiştirmek ayrı bir deney; burada kurallar sabit.
- Aynı analiz 172.16.0.1'in "benign" pencereleri dışarıda tekrarlandığında model her bütçede port_scan'de 1,00'a
  çıkıyor (kural 0,80). Bu pencerelerin etiketi şüpheli (ML-8), bu yüzden bu satırı ana sonuç yapmadık.
- Sonuç: H1 ("model, kurallardan eşit yanlış alarmda daha iyi") brute_force için CIC'de destekleniyor, port_scan için
  belirsiz, labda desteklenmiyor. Kısacası "iki yöntem birbirini tamamlıyor" bulgusu duruyor.
