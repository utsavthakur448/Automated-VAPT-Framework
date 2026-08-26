from modules.vulnerabilities.models import Finding


def check_unrealircd(asset, port):
    if port.number != 6667 or port.service != "irc" or port.product.lower() != "unrealircd":
        return None

    version = port.version.strip()

    if version:
        title = "UnrealIRCd Service Detected"
        description = (
            "An UnrealIRCd IRC service was detected. An exact version was "
            "identified and can be evaluated against known vulnerability records."
        )
        confidence = "MEDIUM"
    else:
        title = "UnrealIRCd Service Detected"
        description = (
            "An UnrealIRCd IRC service was detected, but Nmap did not identify "
            "an exact version. Reliable CVE correlation therefore cannot be "
            "performed from the current evidence."
        )
        confidence = "LOW"

    return Finding(
        title=title,
        severity="INFO",
        description=description,
        host=asset.host,
        port=port.number,
        service=port.service,
        product=port.product,
        version=version,
        cpe=port.cpe,
        detection="SERVICE_DETECTION",
        confidence=confidence,
        evidence=f"Nmap detected {port.product} {version or 'unknown version'} on {asset.host}:{port.number}.",
        remediation=(
            "Disable the IRC service if it is not required. If it is required, "
            "restrict access to trusted networks and upgrade to a supported "
            "and patched release."
        ),
    )
