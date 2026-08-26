from modules.vulnerabilities.models import Finding


def check_apache(asset, port):
    if port.service != "http" or port.product.lower() != "apache httpd" or port.version != "2.2.8":
        return None

    return Finding(
        title="Apache HTTP Server 2.2.8 Detected",
        severity="HIGH",
        description=(
            "The target is running an outdated Apache HTTP Server release. "
            "This version should be reviewed for known security issues and "
            "supported upgrade paths."
        ),
        host=asset.host,
        port=port.number,
        service=port.service,
        product=port.product,
        version=port.version,
        cpe=port.cpe,
        evidence=f"Nmap detected {port.product} {port.version} on {asset.host}:{port.number}.",
        remediation=(
            "Upgrade Apache HTTP Server to a supported and fully patched release. "
            "Remove or disable unnecessary modules."
        ),
    )
