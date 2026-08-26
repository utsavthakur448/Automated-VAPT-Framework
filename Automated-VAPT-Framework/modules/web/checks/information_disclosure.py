import re

from modules.vulnerabilities.models import Finding


def _is_meaningful_server_header(server):
    """Determine whether a Server header contains meaningful technology information."""

    if not server:
        return False

    value = server.strip()

    if not value:
        return False

    suspicious_patterns = [
        r";", r"--", r"\bDELETE\b", r"\bSELECT\b", r"\bINSERT\b",
        r"\bUPDATE\b", r"\bDROP\b", r"\bUNION\b", r"<script",
        r"</script", r"javascript:", r"\.\./", r"['\"]\s*OR\s*['\"]?1"
    ]

    if any(re.search(pattern, value, re.IGNORECASE) for pattern in suspicious_patterns):
        return False

    known_servers = [
        r"\bapache\b", r"\bnginx\b", r"\bmicrosoft-iis\b", r"\biis\b",
        r"\blighttpd\b", r"\bcaddy\b", r"\bgunicorn\b", r"\buvicorn\b",
        r"\bopenresty\b", r"\bcloudflare\b", r"\bcloudfront\b",
        r"\btomcat\b", r"\bcoyote\b", r"\bjetty\b", r"\bnode\.?js\b",
        r"\bexpress\b", r"\bcherokee\b", r"\btraefik\b"
    ]

    if any(re.search(pattern, value, re.IGNORECASE) for pattern in known_servers):
        return True

    return bool(
        re.match(
            r"^[A-Za-z][A-Za-z0-9._-]*(?:/[0-9][A-Za-z0-9._-]*)?(?:\s+.*)?$",
            value
        )
    )


def _is_meaningful_powered_by(powered_by):
    """Validate X-Powered-By before reporting technology disclosure."""

    if not powered_by:
        return False

    value = powered_by.strip()

    if not value:
        return False

    suspicious_patterns = [
        r";", r"--", r"\bDELETE\b", r"\bSELECT\b", r"\bINSERT\b",
        r"\bUPDATE\b", r"\bDROP\b", r"\bUNION\b", r"<script",
        r"</script", r"javascript:"
    ]

    return not any(
        re.search(pattern, value, re.IGNORECASE)
        for pattern in suspicious_patterns
    )


def check_information_disclosure(asset, port, response):
    """
    Detect technology and version information exposed by an HTTP response.

    This check is passive and does not exploit the target.
    """

    findings = []

    # ==================================================
    # SERVER HEADER
    # ==================================================

    server = response.headers.get("server", "")

    if _is_meaningful_server_header(server):
        findings.append(
            Finding(
                title="Web Server Version Disclosure",
                severity="LOW",
                description=(
                    "The HTTP Server header exposes web server technology "
                    "and/or version information."
                ),
                host=asset.host,
                port=port.number,
                service=port.service,
                product=port.product,
                version=port.version,
                evidence=f"HTTP Server header: {server}",
                remediation=(
                    "Configure the web server to minimize unnecessary "
                    "technology and version information in HTTP response headers."
                )
            )
        )

    # ==================================================
    # X-POWERED-BY
    # ==================================================

    powered_by = response.headers.get("x-powered-by", "")

    if _is_meaningful_powered_by(powered_by):
        findings.append(
            Finding(
                title="X-Powered-By Technology Disclosure",
                severity="LOW",
                description=(
                    "The application exposes technology information through "
                    "the X-Powered-By HTTP response header."
                ),
                host=asset.host,
                port=port.number,
                service=port.service,
                product=port.product,
                version=port.version,
                evidence=f"X-Powered-By header: {powered_by}",
                remediation=(
                    "Remove or minimize the X-Powered-By header where practical."
                )
            )
        )

    return findings
