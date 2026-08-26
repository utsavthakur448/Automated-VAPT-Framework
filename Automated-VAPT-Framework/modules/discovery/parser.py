from core.asset import Asset, Port
from core.scan_result import ScanResult


class NmapParser:
    def parse(self, scan_result, target):
        result = ScanResult(target=target)

        for host in scan_result.get("scan", {}):
            host_data = scan_result["scan"][host]

            hostname = self._extract_hostname(host_data)
            addresses = host_data.get("addresses", {})
            mac_address = addresses.get("mac", "")

            vendor_data = host_data.get("vendor", {})
            vendor = vendor_data.get(mac_address, "")

            status = host_data.get("status", {}).get("state", "unknown")
            os_data = self._extract_os(host_data)
            uptime = host_data.get("uptime", {}).get("seconds", 0)

            asset = Asset(
                host=host,
                status=status,
                hostname=hostname,
                mac_address=mac_address,
                vendor=vendor,
                os_name=os_data["name"],
                os_family=os_data["family"],
                os_generation=os_data["generation"],
                os_accuracy=os_data["accuracy"],
                uptime_seconds=int(uptime or 0),
            )

            tcp_ports = host_data.get("tcp", {})

            for port_number, port_data in tcp_ports.items():
                port = Port(
                    number=port_number,
                    protocol="tcp",
                    state=port_data.get("state", "unknown"),
                    service=port_data.get("name", "unknown"),
                    product=port_data.get("product", ""),
                    version=port_data.get("version", ""),
                    cpe=port_data.get("cpe", ""),
                    reason=port_data.get("reason", ""),
                    extra_info=port_data.get("extrainfo", ""),
                )

                asset.add_port(port)

            result.add_asset(asset)

        return result

    def _extract_hostname(self, host_data):
        hostnames = host_data.get("hostnames", [])

        for hostname in hostnames:
            name = hostname.get("name", "")

            if name:
                return name

        return ""

    def _extract_os(self, host_data):
        os_matches = host_data.get("osmatch", [])

        if not os_matches:
            return {
                "name": "",
                "family": "",
                "generation": "",
                "accuracy": "",
            }

        match = os_matches[0]
        osclass = match.get("osclass", [])

        if osclass:
            first_class = osclass[0]

            return {
                "name": match.get("name", ""),
                "family": first_class.get("osfamily", ""),
                "generation": first_class.get("osgen", ""),
                "accuracy": match.get("accuracy", ""),
            }

        return {
            "name": match.get("name", ""),
            "family": "",
            "generation": "",
            "accuracy": match.get("accuracy", ""),
        }
