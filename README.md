# Yapay Zeka Destekli Siber Saldırı Tespit ve Müdahale Sistemi

Bitirme projesi çekirdeği: canlı trafik izleme, model tabanlı risk skoru, olay kuyruğu,
agent ile inceleme, **kademeli ve geri alınabilir** müdahale, gerçek zamanlı panel.
Saldırı testleri yalnızca **kendi izole lab ağında** yapılır.

## Mimari

```
[Saldırgan VM] ──test saldırısı──▶ [Hedef VM] ──ayna trafik──▶ [Sensör VM: Zeek]
                                                                    │ conn.log
                                                                    ▼
                                        [Özellik çıkarma + modeller: XGBoost + Autoencoder (+ LSTM)]
                                                                    │ risk skoru >= eşik
                                                                    ▼  POST /api/events/
┌────────────────────────────── backend (Django) ──────────────────────────────┐
│ ingest ─▶ Event + denetim kaydı ─▶ Procrastinate görevi (Postgres kuyruğu)    │
│                                          │                                    │
│                              worker: agent.investigate(event)                 │
│                                          │ propose_action                     │
│                              core.actions (politika katmanı)                  │
│        korumalı IP · kademe · TTL · onay · geri alma · denetim kaydı          │
└───────────────┬───────────────────────────────────────────────▲───────────────┘
                │ yayın (HTTP API, X-API-Key)                   │ proxy: connect/refresh/
                ▼                                               │ subscribe/rpc (ortak sır)
          [Centrifugo] ◀──────── WebSocket ────────▶ [Panel (staff oturumu, cookie)]
```

## Teknoloji

| Katman | Seçim |
|---|---|
| Trafik görünürlüğü | Zeek (`conn.log`) |
| Modeller | XGBoost (bilinen saldırılar) + Autoencoder (bilinmeyen) + LSTM (en son) |
| Backend | Django 6.1.3 (güvenlik düzeltmeli sürüm, `requirements.txt` içinde `>=6.1.3,<6.2`), PostgreSQL 17 |
| Kuyruk | Procrastinate (Postgres üzerinde, Django entegrasyonu) |
| Gerçek zamanlı | Centrifugo v6, **proxy ile kimlik doğrulama** (JWT yok) |
| Agent | `core/agent.py` arayüzü; şimdilik `RuleAgent` yer tutucu, sonra Claude Agent SDK |
| Çalıştırma | Docker Compose |

## Güvenlik kuralları (kodda, agent'ın erişemediği yerde)

- **Korumalı IP/host listesi** (`PROTECTED_IPS`, `PROTECTED_HOSTS`): hem önerirken hem uygularken
  kontrol edilir, ayrıştırılamayan IP korumalı sayılır, reddedilen denemeler denetim kaydına yazılır.
- **Kademe** (`AUTO_REMEDIATION_MODE`): `advise` (hepsi onay bekler) → `dry_run` → `enforce`.
  Host izolasyonu ve yapılandırma düzeltmesi her kademede insan onayı ister.
- **Geri alınabilirlik:** her IP engeli TTL'li; süre dolunca `expire_actions` (dakikada bir) kaldırır.
  Onay bekleyen eylemler `APPROVAL_TTL_SECONDS` sonra düşer. Elle geri alma RPC'si var.
- **Onay kararı agent'tan gelmez:** Centrifugo RPC → doğrulanmış `is_staff` kullanıcı.
- **Prompt injection:** `Event.features` ve `summary` saldırgan kontrolünde olabilir; agent'a veri
  olarak verilmeli. Serbest komut yok, `config_fix` yalnızca izin listesindeki düzeltmeleri kabul eder.
- Proxy uç noktaları ortak sır ister; sır tanımlı değilse hepsi kapalıdır. Sensör girişi Bearer token ister.

## Çalıştırma

```bash
cp .env.example .env          # tüm "degistir-beni" değerlerini değiştir
docker compose up --build
docker compose exec backend python manage.py createsuperuser   # is_staff = panel kullanıcısı
```

- **Canlı panel:** http://localhost:8000/panel/ (yalnızca `is_staff` kullanıcı; giriş admin sayfasından)
- Django admin: http://localhost:8000/admin/ (olaylar, eylemler, **denetim kaydı**)
- Centrifugo: ws://localhost:8001/connection/websocket (panel `localhost:8000` üzerinden bağlanmalı,
  çerez aynı host'ta paylaşılır; `allowed_origins` `centrifugo/config.json` içinde)

### Panel

Tek sayfa, Django'dan servis edilir. Açılınca son olaylar/eylemler yüklenir, sonrası Centrifugo
üzerinden canlı akar (yenileme gerekmez).

- **Onay bekleyen eylemler** kartlarında Onayla / Reddet. Host izolasyonu ve yapılandırma düzeltmesi
  için onay iki tıklamalı ("Emin misin?"). Uygulanmış engel ve izolasyonlarda **Geri al**.
- Butonlar `ids:approve_action`, `ids:reject_action`, `ids:rollback_action` RPC'lerini çağırır; karar
  yine doğrulanmış `is_staff` oturumundan ve `core.actions` politika katmanından geçer.
- Olay alanları saldırgan kontrolünde olabileceği için yalnızca `textContent` ile basılır; sayfa
  nonce'lu sıkı bir CSP ile gelir (dış bağlantı yalnızca Centrifugo).
- İstemci kütüphanesi (`centrifuge-js 5.7.4`) CDN'den, sürüm ve bütünlük (SRI) hash'i sabitlenmiş
  olarak yüklenir; internet gerekir. Yüklenemezse panel bunu bir uyarıyla bildirir.
- İsteğe bağlı ortam değişkenleri: `RT_SESSION_TTL_SECONDS` (varsayılan 300; oturum iptalinin
  bağlantıyı kapatma süresi), `RT_PUBLIC_PORT` (8001), `RT_WS_URL` (boşsa sayfanın ana makine adından türetilir).

### Boru hattını sensör olmadan deneme

```bash
# Normal bir saldırgan IP'si: agent engel önerir, advise kademesinde onay bekler
docker compose exec backend python manage.py emit_test_event --ip 203.0.113.7 --risk 0.92
# Korumalı IP: eylem REFUSED olur, denetim kaydında görünür
docker compose exec backend python manage.py emit_test_event --ip 192.168.56.10 --risk 0.95
```

Admin'de Event, Action ve AuditLog'u kontrol et. `AUTO_REMEDIATION_MODE=dry_run` yapıp
`docker compose up -d` ile yeniden başlatınca aynı olayın otomatik "kuru çalıştırma" olduğunu görürsün.

### Testler

```bash
cd backend
pip install -r requirements.txt
python manage.py test --settings=config.settings_test   # 60 test, Postgres gerekmez
```

## Doğrulananlar ve doğrulanmayanlar

Gerçek Centrifugo 6.9.7 + PostgreSQL + Procrastinate worker + Chromium ile uçtan uca denendi:
connect/subscribe/rpc proxy sırları, refresh proxy'de Cookie iletimi ve iptal edilen oturumun
bağlantıyı kapatması, canlı olay/eylem akışı, onay/red/geri alma, korumalı IP'nin reddi ve
saldırgan kontrollü metinlerin (HTML/script) etkisiz kalması.

Henüz denenmeyenler:

1. **Panelin CDN betiği:** `centrifuge-js` SRI hash'i npm paketinden hesaplandı, CDN'e test ortamından
   erişilemedi. Panelde "Centrifuge istemcisi yüklenemedi" uyarısı çıkarsa nedeni budur (internet
   veya hash).
2. **Gerçek ağ trafiği:** olaylar şimdilik `emit_test_event` ile üretiliyor; sensör, modeller ve
   gerçek güvenlik duvarı arka ucu yok.

## Sonraki adımlar

1. Lab: izole VM'ler, Zeek, `conn.log` → özellik çıkarma → `POST /api/events/`.
   Kademe kademe ilerliyor, bkz. [`sensor/README.md`](sensor/README.md) (Kademe 1: `conn.log` okuyucu, Kademe 2: pencere başına özellikler, Kademe 3: kural tabanlı skor ve backend'e gönderim hazır).
2. XGBoost baseline, ardından Autoencoder; karar tablosu ve eşikler (PR eğrisi).
3. Claude agent: `core/agent.py` içindeki `RuleAgent` yerine, araçları `core.actions` üzerinden geçen agent.
4. Gerçek güvenlik duvarı arka ucu (lab ağ geçidi) ve kontrollü saldırı senaryoları ile ölçüm.
