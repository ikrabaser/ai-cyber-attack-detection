# Laboratuvar (Faz 2)

İzole bir Docker ağında hedef, saldırgan ve normal trafik üretici; Zeek hedefin ağ arayüzünü dinleyip
`conn.log` yazar. Amaç: gerçek araçlarla (nmap, Hydra) etiketli trafik üretmek ve kuralların bu trafiğe ne
yaptığını ölçmek. Tasarım ve gerekçe Docs raporundaki "Docker laboratuvarı tasarımı" bölümünde.

```
saldırgan  10.77.0.20 ─┐
                       ├─> hedef 10.77.0.10 (SSH + web) <── Zeek (aynı ağ arayüzü) ──> data/conn.log
normal     10.77.0.30 ─┘
```

## Güvenlik

- `labnet` ağı `internal: true`: konteynerler internete ve ana makine ağına çıkamaz. Hiçbir servis `ports:` yayınlamaz.
- Koşu betikleri yalnızca özel (RFC 1918) IPv4 adreslerine trafik üretir; `8.8.8.8` gibi bir adres reddedilir.
- Hedefteki `labuser / lab123` zayıf parola bilerek vardır ve yalnızca bu izole ağda yaşar.
- `lab/test_compose_safety.py` bu kuralları denetler.

## Çalıştırma (repo kökünden, PowerShell, tek tek)

1. Kur ve başlat (ilk seferde imajlar indirilir, birkaç dakika sürer):
```powershell
docker compose -f lab/docker-compose.lab.yml up -d --build
```
2. **İzolasyonu doğrula.** İlki başarısız olmalı (`Network is unreachable` ya da zaman aşımı), ikincisi çalışmalı:
```powershell
docker compose -f lab/docker-compose.lab.yml exec attacker ping -c 1 -W 2 1.1.1.1
```
```powershell
docker compose -f lab/docker-compose.lab.yml exec attacker ping -c 1 -W 2 10.77.0.10
```
3. Koşular. Her koşu `lab/data/runs.jsonl`'a bir satır yazar:
```powershell
docker compose -f lab/docker-compose.lab.yml exec attacker python3 /lab/attack.py scan
```
```powershell
docker compose -f lab/docker-compose.lab.yml exec attacker python3 /lab/attack.py brute
```
```powershell
docker compose -f lab/docker-compose.lab.yml exec normal python3 /lab/normal_traffic.py --seconds 120
```
Karışık senaryo: önce normal trafiği arka planda başlat (`exec -d normal ...`), sonra saldırıyı çalıştır.
Seçenekler: `scan --timing 2` (daha yavaş tarama), `brute --threads 1` (daha yavaş parola denemesi).

4. Zeek'in logu kapatması için durdur (log tamponu dosyaya bu sırada yazılır):
```powershell
docker compose -f lab/docker-compose.lab.yml stop zeek
```
`lab/data/` içinde `conn.log` ve `runs.jsonl` olmalı.

5. Etiketle ve koşu başına ölçüm özetini gör:
```powershell
python lab/label_windows.py lab/data/conn.log lab/data/runs.jsonl --out lab/data/windows.csv
```
Özet her koşu için pencere sayısını, yarım (boundary) pencereleri, kuralın tetiklediği pencereleri ve ilk
tespite kadar geçen süreyi verir. `windows.csv` etiketli satırlardır (model eğitimi için ham veri).

6. İstersen aynı log'u panele gönder (sensör ana makinede çalışır, lab ağına girmez):
```powershell
python sensor/detect.py lab/data/conn.log --send
```

**Canlı izleme (saldırı sürerken panelde):** Zeek çalışırken, ayrı bir PowerShell penceresinde sensörü
`--follow` ile başlat; sonra saldırıyı çalıştır. `-v` kural tetiklenmeyen pencereleri de yazar, böylece
sensörün trafiği gördüğünü anlarsın:
```powershell
$env:SENSOR_API_TOKEN = (Select-String -Path .env -Pattern '^SENSOR_API_TOKEN=(.*)$').Matches.Groups[1].Value
```
```powershell
python sensor/detect.py lab/data/conn.log --follow --send -v
```
Her pencere 10 sn + 8 sn bekleme sonrası değerlendirilir, yani tespit saldırıdan ~20 sn içinde panelde olur
(ayrıntı: `sensor/README.md`). Önce şunu doğrula: Zeek `conn.log`'a ne kadar hızlı yazıyor? Bir saldırı
sürerken ayrı pencerede `Get-Content lab/data/conn.log -Wait -Tail 3` satırların hemen düşüp düşmediğini
gösterir. Zeek log'u tamponluyorsa tespit gecikir; bu durumda gecikmeyi ölçüp rapora yaz.

7. Bitince kapat (`-v` yok: `data/` klasöründeki dosyalar kalır):
```powershell
docker compose -f lab/docker-compose.lab.yml down
```

## Dosyalar

- `docker-compose.lab.yml`: ağ ve dört servis (hedef, Zeek, saldırgan, normal trafik).
- `target/`: Debian + OpenSSH + nginx. `attacker/`: nmap, Hydra, `attack.py`, `wordlist.txt` (105 parola, doğrusu 89. sırada).
- `normal/normal_traffic.py`: rastgele aralıklarla web isteği (%80) ve gerçek SSH girişi (%20).
- `common/runlog.py`: koşu günlüğü (JSONL); `common/netguard.py`: hedef koruması.
- `label_windows.py`: pencere etiketleme ve özet. Etiketin tek kaynağı koşu günlüğüdür.
- Testler: `cd lab; python -m unittest` (Docker gerekmez).

## Bilinenler ve sınırlar

- Zeek imajı varsayılan `zeek/zeek:lts`. İndirilemezse `$env:ZEEK_IMAGE="zeek/zeek:latest"` ile deneyin.
- Zeek logunu hedefin arayüzünden okur; trafik hedefe gelip gidenle sınırlıdır (saldırgan ile normal istemci
  arasındaki trafik görülmez). Bu lab için yeterli.
- Sensör şimdilik dosyayı bir kez okur (canlı izleme yok). Lab ölçümü için bu yeterli; canlı izleme sonraki adım.
- Pencereler sabit 10 sn'dir; koşunun başı ve sonu pencere sınırına denk gelmez, bu yüzden `boundary=1` satırlar olur.
