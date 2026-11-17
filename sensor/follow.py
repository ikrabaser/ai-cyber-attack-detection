"""Canlı izleme: conn.log'a eklenen kayıtları takip eder, pencereler kapandıkça değerlendirir.

Toplu modda (detect.py dosya) dosya bir kez baştan sona okunur. Canlı modda iki sorun çıkar:

1. Dosya büyümeye devam eder. `tail_records` bunu `tail -f` gibi takip eder: yeni satırları verir,
   yarım yazılmış son satırı bekletir, dosya kısalırsa (Zeek yeniden başlatıldı) baştan okur.

2. Bir pencerenin ne zaman BİTTİĞİ belli değildir. Zeek bir bağlantıyı biter bitmez yazar ama
   `ts` bağlantının BAŞLANGICIDIR; uzun süren bir bağlantı kaydı, kendi penceresi geçtikten sonra
   gelir. Bu yüzden pencere, bitiminden `grace` saniye sonra kapatılır ve o zamana kadar gelen
   kayıtlar sayılır. Geç kalan kayıt atılır ve sayılır (`late`). Sonuç: toplu moddaki özellikler
   canlıda aynı olur, yalnızca grace'ten sonra gelen kayıtlar farkı yaratır.

Saat: pencerenin kapanıp kapanmadığına kayıtların kendi zamanından (`ts`) karar veririz, ama
trafik kesilince zaman durmasın diye kayıt zamanını duvar saatiyle ilerletiriz. `offset` =
şimdiye kadar görülen en büyük (ts - duvar saati). İzleyici ile Zeek farklı saatte olsa bile
fark offset'e girer ve sorun olmaz.
"""

import os
import time
from collections import defaultdict

from features import WINDOW_SECONDS, extract, window_start
from rules import Detector
from zeek_reader import LineParser


def tail_records(path, poll=0.5, from_start=False, sleep=time.sleep, stop=lambda: False, on_error=None):
    """Dosyaya eklenen kayıtları sırayla verir; yeni veri yoksa her turda None verir (zaman tiki).

    from_start=False: izleme başladığında dosyada ZATEN olan kayıtlar atlanır (başlıklar okunur,
    kayıtlar verilmez). Sonradan oluşan ya da kısalıp yeniden başlayan dosya her zaman baştan okunur.
    on_error: bozuk satırda çağrılır (ValueError); verilmezse hata fırlatılır.
    """
    existed_at_start = os.path.exists(path)
    handle, parser, pos, lineno, skip = None, None, 0, 0, False
    try:
        while not stop():
            if handle is not None:
                try:
                    truncated = os.path.getsize(path) < pos
                except OSError:  # dosya silindi
                    truncated = True
                if truncated:
                    handle.close()
                    handle = None

            if handle is None:
                if not os.path.exists(path):
                    yield None
                    sleep(poll)
                    continue
                # Dosya izleme başlarken varsa ve baştan okuma istenmediyse ilk turda kayıtları atla.
                skip = existed_at_start and not from_start
                existed_at_start = False  # bundan sonra açılan dosya yenidir: tamamı okunur
                handle = open(path, "rb")
                parser, pos, lineno = LineParser(str(path)), 0, 0

            while True:
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):  # yarım satır: Zeek henüz bitirmedi, sonra tekrar dene
                    handle.seek(pos)
                    break
                pos += len(line)
                lineno += 1
                try:
                    record = parser.parse(line.decode("utf-8"), lineno)
                except ValueError as exc:  # UnicodeDecodeError de ValueError'dır
                    if on_error is None:
                        raise
                    on_error(exc)
                    continue
                if record is not None and not skip:
                    yield record
            skip = False
            yield None
            sleep(poll)
    finally:
        if handle is not None:
            handle.close()


class LiveMonitor:
    """Kayıtları pencerelere biriktirir; süresi dolan pencereleri sırayla kapatıp kurallara verir."""

    def __init__(self, window=WINDOW_SECONDS, grace=8.0, clock=time.monotonic):
        self.window = window
        self.grace = grace
        self.clock = clock
        self.detector = Detector(window)
        self.pending = defaultdict(list)  # pencere başlangıcı -> o penceredeki bağlantılar
        self.closed_through = None        # kapanan en son pencerenin başlangıcı
        self.offset = None                # en büyük (kayıt zamanı - duvar saati)
        self.rows = 0                     # değerlendirilen (kaynak, pencere) sayısı
        self.detections = 0
        self.late = 0                     # penceresi kapandıktan sonra gelen, atılan kayıtlar
        self.bad_lines = 0

    def add(self, record):
        ts = record["ts"]
        diff = ts - self.clock()
        if self.offset is None or diff > self.offset:
            self.offset = diff
        start = window_start(ts, self.window)
        if self.closed_through is not None and start <= self.closed_through:
            self.late += 1
            return
        self.pending[start].append(record)

    def close_ready(self):
        """Süresi dolan pencereleri kapatır. [(özellik satırı, Detection ya da None)] döndürür."""
        if self.offset is None:
            return []
        watermark = self.clock() + self.offset
        ready = sorted(s for s in self.pending if s + self.window + self.grace <= watermark)
        results = []
        for start in ready:
            self.closed_through = start
            for row in extract(self.pending.pop(start), self.window):
                det = self.detector.feed(row)
                self.rows += 1
                self.detections += det is not None
                results.append((row, det))
        return results
