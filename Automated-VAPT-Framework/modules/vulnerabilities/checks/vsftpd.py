from modules.vulnerabilities.models import Finding


def check_vsftpd(asset, port):
    if (
        port.number != 21
        or port.service != "ftp"
        or port.product.lower() != "vsftpd"
        or port.version != "2.3.4"
    ):
        return None

    return Finding(
        title="vsftpd 2.3.4 Vulnerable Version Detected",
        severity="CRITICAL",
        description=(
            "The detected FTP service is running vsftpd 2.3.4, "
            "a historically vulnerable version."
        ),
        host=asset.host,
        port=port.number,
        service=port.service,
        product=port.product,
        version=port.version,
        cpe=port.cpe,
        evidence=f"Nmap detected {port.product} {port.version} on {asset.host}:{port.number}.",
        remediation=(
            "Upgrade to a supported and patched vsftpd release or remove "
            "the service if it is not required."
        ),
        references=["CVE-2011-2523"],
    )
