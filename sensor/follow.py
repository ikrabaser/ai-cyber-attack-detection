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


class LogTail:
    """Bir log dosyasını `tail -f` gibi izler. `read_new()` her çağrıda yeni kayıtları liste olarak verir.

    from_start=False: izleme başladığında dosyada ZATEN olan kayıtlar atlanır (başlıklar okunur,
    kayıtlar verilmez). Sonradan oluşan ya da kısalıp yeniden başlayan dosya her zaman baştan okunur.
    Yarım satır bekletilir. on_error: bozuk satırda çağrılır (ValueError); verilmezse hata fırlatılır.
    """

    def __init__(self, path, from_start=False, on_error=None):
        self.path = path
        self.on_error = on_error
        self._skip_first = not from_start and os.path.exists(path)
        self._handle = None
        self._parser = None
        self._pos = 0
        self._lineno = 0

    def close(self):
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def read_new(self):
        if self._handle is not None:
            try:
                truncated = os.path.getsize(self.path) < self._pos
            except OSError:  # dosya silindi
                truncated = True
            if truncated:
                self.close()

        skip = False
        if self._handle is None:
            if not os.path.exists(self.path):
                return []
            skip = self._skip_first   # izleme başlarken vardı ve baştan okuma istenmedi: ilk turda atla
            self._skip_first = False  # bundan sonra açılan dosya yenidir: tamamı okunur
            self._handle = open(self.path, "rb")
            self._parser, self._pos, self._lineno = LineParser(str(self.path)), 0, 0

        records = []
        while True:
            line = self._handle.readline()
            if not line:
                break
            if not line.endswith(b"\n"):  # yarım satır: Zeek henüz bitirmedi, sonra tekrar dene
                self._handle.seek(self._pos)
                break
            self._pos += len(line)
            self._lineno += 1
            try:
                record = self._parser.parse(line.decode("utf-8"), self._lineno)
            except ValueError as exc:  # UnicodeDecodeError de ValueError'dır
                if self.on_error is None:
                    raise
                self.on_error(exc)
                continue
            if record is not None and not skip:
                records.append(record)
        return records


def tail_records(path, poll=0.5, from_start=False, sleep=time.sleep, stop=lambda: False, on_error=None):
    """`LogTail` üstüne kurulu üreteç: kayıtları sırayla verir; yeni veri yoksa her turda None verir."""
    tail = LogTail(path, from_start, on_error)
    try:
        while not stop():
            yield from tail.read_new()
            yield None
            sleep(poll)
    finally:
        tail.close()


class _Bucket:
    """Bir pencerede biriken kayıtlar: bağlantılar (conn.log) ve SSH kayıtları (ssh.log)."""

    def __init__(self):
        self.conns = []
        self.ssh = []


class LiveMonitor:
    """Kayıtları pencerelere biriktirir; süresi dolan pencereleri sırayla kapatıp kurallara verir."""

    def __init__(self, window=WINDOW_SECONDS, grace=8.0, clock=time.monotonic, model=None, model_threshold=None):
        self.window = window
        self.grace = grace
        self.clock = clock
        extra = {} if model_threshold is None else {"model_threshold": model_threshold}
        self.detector = Detector(window, model=model, **extra)
        self.pending = defaultdict(_Bucket)  # pencere başlangıcı -> o penceredeki kayıtlar
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
        self.pending[start].conns.append(record)

    def add_ssh(self, record):
        """ssh.log kaydı (başarısız parola denemesi sayısı için). Pencere saatini ilerletmez."""
        start = window_start(record["ts"], self.window)
        if self.closed_through is not None and start <= self.closed_through:
            self.late += 1
            return
        self.pending[start].ssh.append(record)

    def close_ready(self):
        """Süresi dolan pencereleri kapatır. [(özellik satırı, Detection ya da None)] döndürür."""
        if self.offset is None:
            return []
        watermark = self.clock() + self.offset
        ready = sorted(s for s in self.pending if s + self.window + self.grace <= watermark)
        results = []
        for start in ready:
            self.closed_through = start
            bucket = self.pending.pop(start)
            for row in extract(bucket.conns, self.window, bucket.ssh):
                det = self.detector.feed(row)
                self.rows += 1
                self.detections += det is not None
                results.append((row, det))
        return results
