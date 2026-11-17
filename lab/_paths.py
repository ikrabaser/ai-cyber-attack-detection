"""Testler için: konteynerde düz bir klasörde duran modülleri depo düzeninden içe aktarılabilir yapar."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for sub in ("common", "attacker", "normal"):
    sys.path.insert(0, str(HERE / sub))
sys.path.insert(0, str(HERE.parent / "sensor"))
