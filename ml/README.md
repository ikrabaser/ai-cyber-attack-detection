# ML katmanı

Sensörün kurallarının yanına makine öğrenmesi modelleri (XGBoost, Autoencoder, LSTM) koyuyoruz.
Modeller **sensörle aynı 7 özelliği** (`sensor/features.py`) kullanır; böylece eğitimde öğrendiği
canlıda da geçerli olur.

| Kademe | Konu | Durum |
|---|---|---|
| ML-1 | LycoS-IDS2017 akışlarını (kaynak IP, 10 sn) pencerelerine çevirmek | **tamam** |
| ML-2 | Zamana göre eğitim/test bölmesi, kural tabanlı kıyas, metrikler | **tamam** |
| ML-3 | XGBoost | **tamam** |
| ML-4 | Lab pencerelerinde dış doğrulama | |
| ML-5 | Autoencoder | |
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
