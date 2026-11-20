# ML katmanı

Sensörün kurallarının yanına makine öğrenmesi modelleri (XGBoost, Autoencoder, LSTM) koyuyoruz.
Modeller **sensörle aynı 7 özelliği** (`sensor/features.py`) kullanır; böylece eğitimde öğrendiği
canlıda da geçerli olur.

| Kademe | Konu | Durum |
|---|---|---|
| ML-1 | LycoS-IDS2017 akışlarını (kaynak IP, 10 sn) pencerelerine çevirmek | **tamam** |
| ML-2 | Zamana göre eğitim/test bölmesi, kural tabanlı kıyas, metrikler | |
| ML-3 | XGBoost | |
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
`day, src_ip, window_start, <7 özellik>, label, label_share, n_flows`.

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
