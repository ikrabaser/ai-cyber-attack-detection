"""`sensor/` klasörünü içe aktarma yoluna ekler (features, rules oradan gelir)."""

import sys
from pathlib import Path

SENSOR = str(Path(__file__).resolve().parent.parent / "sensor")
if SENSOR not in sys.path:
    sys.path.insert(0, SENSOR)
