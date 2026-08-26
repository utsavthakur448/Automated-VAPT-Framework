from modules.vulnerabilities.models import Finding


def check_samba(asset, port):
    if port.service != "netbios-ssn" or port.product.lower() != "samba smbd" or port.number not in (139, 445):
        return None

    version = port.version.strip() or "Unknown"

    return Finding(
        title="Samba SMB Service Detected",
        severity="INFO",
        description=(
            "A Samba SMB service was detected. The available Nmap service "
            "information does not provide a sufficiently precise Samba "
            "version for reliable CVE correlation."
        ),
        host=asset.host,
        port=port.number,
        service=port.service,
        product=port.product,
        version=version,
        cpe=port.cpe,
        detection="SERVICE_DETECTION",
        confidence="LOW",
        evidence=f"Nmap detected {port.product} {version} on {asset.host}:{port.number}.",
        remediation=(
            "Verify whether SMB is required. Restrict SMB access to trusted "
            "networks, disable unnecessary SMB services, and maintain Samba "
            "security updates."
        ),
    )
