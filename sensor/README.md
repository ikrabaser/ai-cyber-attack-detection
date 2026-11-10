# Sensör katmanı

Trafikten (Zeek) olay üretip backend'e (`POST /api/events/`) gönderecek parça. Kademe kademe
ilerliyoruz; her kademede çalışan ve anlaşılır bir şey var.

| Kademe | Konu | Durum |
|---|---|---|
| 1 | Zeek `conn.log` okumak | **bu klasör** |
| 2 | Özellik çıkarma (zaman penceresi başına sayılar) | sırada |
| 3 | Kural tabanlı skor → backend → panel | |
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
python -m unittest -v                            # 10 test
```

`sample/conn.log` **sentetik**: Zeek'in gerçek biçiminde elle kurgulanmış 3 dakikalık bir senaryo.

- 0-180. sn: `192.168.56.50` normal istemci (web + DNS, bir de meşru SSH oturumu)
- 60. sn: `192.168.56.200` saldırgan, `web-01`'e 40 portluk SYN taraması
- 90-150. sn: aynı saldırgan `web-01:22`'ye SSH brute force (saniyede ~1 deneme)

Çıktıda saldırganın bağlantı ve port sayısının normal istemciden ne kadar farklı olduğuna bak.
Ama dikkat: tarama ile brute force **aynı IP'den**, bu yüzden "IP başına toplam" ikisini ayıramıyor.
Kademe 2'nin konusu tam olarak bu: zamanı pencerelere bölüp her pencere için ayrı sayılar çıkarmak.

## Dosyalar

- `zeek_reader.py`: Zeek TSV (varsayılan) ve JSON biçimini okuyan, bağımlılıksız okuyucu.
- `read_conn_log.py`: dosyayı özetleyen komut.
- `sample/conn.log`: sentetik örnek.
- `test_zeek_reader.py`: testler.
