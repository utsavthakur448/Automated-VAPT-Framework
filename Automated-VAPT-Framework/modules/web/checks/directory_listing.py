from modules.vulnerabilities.models import Finding


DIRECTORY_PATHS = ["/", "/images/", "/uploads/", "/files/", "/backup/", "/assets/"]


def is_directory_listing(response):
    """Detect common directory-index pages."""

    if not response or response.error:
        return False

    if response.status_code != 200 or not response.body:
        return False

    body_lower = response.body.lower()

    markers = [
        "<title>index of ",
        "<h1>index of ",
        "directory listing for",
        "parent directory"
    ]

    return any(marker in body_lower for marker in markers)


def check_directory_listing(asset, port, scanner):
    """Check selected common paths for directory listing exposure."""

    findings = []

    for path in DIRECTORY_PATHS:
        response = scanner.scan_path(
            asset.host,
            port.number,
            path
        )

        if not response or not is_directory_listing(response):
            continue

        findings.append(
            Finding(
                title="Directory Listing Enabled",
                severity="MEDIUM",
                description=(
                    "The web server appears to expose a browsable "
                    "directory listing."
                ),
                host=asset.host,
                port=port.number,
                service=port.service,
                product=port.product,
                version=port.version,
                evidence=f"Directory listing detected at {response.url}",
                remediation=(
                    "Disable directory indexing unless it is explicitly "
                    "required. Configure the web server to serve an index "
                    "page or return an appropriate access response."
                )
            )
        )

    return findings
