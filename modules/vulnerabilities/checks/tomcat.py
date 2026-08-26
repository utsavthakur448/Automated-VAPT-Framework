from modules.vulnerabilities.models import Finding


def check_tomcat(asset, port):
    if port.number != 8180 or port.service != "http" or "tomcat" not in port.product.lower():
        return None

    version = port.version.strip()

    if version:
        description = (
            "An Apache Tomcat service was detected and a version was identified. "
            "The version can be evaluated against known vulnerability records."
        )
        confidence = "MEDIUM"
    else:
        description = (
            "An Apache Tomcat service was detected, but Nmap did not identify "
            "an exact Tomcat version. Reliable CVE correlation cannot be "
            "performed from the current evidence."
        )
        confidence = "LOW"

    return Finding(
        title="Apache Tomcat Service Detected",
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
            "Upgrade Tomcat to a supported and patched release. Disable "
            "unnecessary applications and restrict administrative interfaces."
        ),
    )
