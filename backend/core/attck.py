"""MITRE ATT&CK eşlemesi (statik, yalnızca bilgilendirici).

Sensörün kural adından (saldırı türü) bir teknik kimliğine bakar; hiçbir eylemi
etkilemez, karar vermez. İleride korelasyon ve olay raporu katmanında aynı
eşlemeyi kullanmak için burada tutuluyor (bkz. plan Faz C: "Korelasyon ve MITRE
ATT&CK").
"""

ATTCK_TECHNIQUES = {
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
}


def attck_for(attack_type):
    """Eşleşme varsa {"id", "name", "tactic"} sözlüğü, yoksa None."""
    return ATTCK_TECHNIQUES.get(str(attack_type or "")) or None
