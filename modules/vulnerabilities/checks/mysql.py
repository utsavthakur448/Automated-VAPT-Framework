from modules.vulnerabilities.models import Finding


def check_mysql(asset, port):
    if (
        port.number != 3306
        or port.service != "mysql"
        or port.product.lower() != "mysql"
        or not port.version
    ):
        return None

    return Finding(
        title="MySQL Database Service Detected",
        severity="INFO",
        description=(
            "A MySQL database service was detected. Database services should "
            "not normally be directly exposed to untrusted networks."
        ),
        host=asset.host,
        port=port.number,
        service=port.service,
        product=port.product,
        version=port.version,
        cpe=port.cpe,
        evidence=f"Nmap detected {port.product} {port.version} on {asset.host}:{port.number}.",
        remediation=(
            "Restrict MySQL access to trusted hosts or networks, use firewall "
            "rules, disable unnecessary remote access, and maintain supported "
            "security updates."
        ),
    )
