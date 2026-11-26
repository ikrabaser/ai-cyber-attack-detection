import sys

from django.core.management.base import BaseCommand

from core.threat_intel_list import normalize_list, split_tokens


class Command(BaseCommand):
    help = (
        "Elle yapıştırılan bir IP/CIDR listesini THREAT_INTEL_BAD_IPS .env satırına çevirir: "
        "geçersiz girdiler atlanır ve uyarı olarak bildirilir, tekrarlar silinir, sıra korunur. "
        "Hiçbir dosyaya yazmaz; yalnızca .env'e elle yapıştırılacak satırı stdout'a basar."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "entries",
            nargs="*",
            help=(
                "IP/CIDR'ler (virgül, boşluk ya da yeni satırla ayrılmış, birden çok argüman olabilir). "
                "Hiç verilmezse stdin'den okunur: yapıştır, sonra Ctrl+D "
                "(Windows PowerShell'de Ctrl+Z, Enter)."
            ),
        )

    def handle(self, *args, **opts):
        raw_text = " ".join(opts["entries"]) if opts["entries"] else sys.stdin.read()
        valid, invalid = normalize_list(split_tokens(raw_text))

        for bad in invalid:
            self.stderr.write(self.style.WARNING(f"Atlandı (geçersiz IP/CIDR): {bad!r}"))

        if not valid:
            self.stdout.write(self.style.WARNING("Geçerli hiçbir girdi yok."))
            return

        self.stdout.write(f"THREAT_INTEL_BAD_IPS={','.join(valid)}")
