from rich.console import Console
from rich.table import Table


class NmapRenderer:
    def __init__(self):
        self.console = Console()

    def _section_start(self, title):
        self.console.print()
        self.console.print("╔══════════════════════════════════════════════════════╗")
        self.console.print(f"║ {title:^52} ║")
        self.console.print("╚══════════════════════════════════════════════════════╝")
        self.console.print()

    def _section_end(self, title):
        self.console.print()
        self.console.print("──────────────────────────────────────────────────────")
        self.console.print(f"END OF {title}")
        self.console.print("──────────────────────────────────────────────────────")

    def display(self, scan_result):
        console = self.console

        self._section_start("NMAP DISCOVERY")

        for asset in scan_result.assets:
            console.print("[bold]Host Information[/bold]")
            console.print("──────────────────────────────────────────────────────")
            console.print(f"Host         : {asset.host}")
            console.print(f"Status       : {asset.status or 'Unknown'}")
            console.print(f"Hostname     : {asset.hostname or 'Not resolved'}")

            if asset.mac_address:
                console.print(f"MAC Address  : {asset.mac_address}")

            if asset.vendor:
                console.print(f"Vendor       : {asset.vendor}")

            if asset.os_name:
                console.print(f"OS           : {asset.os_name}")

            if asset.os_accuracy:
                console.print(f"OS Accuracy  : {asset.os_accuracy}%")

            console.print()
            console.print("[bold]Open Ports[/bold]")

            table = Table(show_header=True, header_style="bold", expand=False)
            table.add_column("PORT", justify="right")
            table.add_column("STATE")
            table.add_column("SERVICE")
            table.add_column("VERSION")

            for port in asset.open_ports:
                product = port.product or ""
                version = port.version or ""
                service_version = f"{product} {version}".strip()

                table.add_row(
                    str(port.number),
                    port.state or "unknown",
                    port.service or "",
                    service_version,
                )

            console.print(table)

        hosts_discovered = len(scan_result.assets)
        open_ports = sum(len(asset.open_ports) for asset in scan_result.assets)

        console.print()
        console.print("[bold]Nmap Discovery Summary[/bold]")
        console.print("──────────────────────────────────────────────────────")
        console.print(f"Hosts discovered : {hosts_discovered}")
        console.print(f"Open ports       : {open_ports}")

        self._section_end("NMAP DISCOVERY")
