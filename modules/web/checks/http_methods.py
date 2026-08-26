from modules.vulnerabilities.models import Finding


RISKY_METHODS = {
    "TRACE": {
        "severity": "LOW",
        "title": "HTTP TRACE Method Enabled",
        "description": (
            "The web server advertises the HTTP TRACE method. TRACE is "
            "generally unnecessary for normal web application operation "
            "and can increase exposure to cross-site tracing style attacks."
        ),
        "remediation": "Disable HTTP TRACE unless it is explicitly required."
    },
    "PUT": {
        "severity": "MEDIUM",
        "title": "HTTP PUT Method Advertised",
        "description": (
            "The web server advertises the HTTP PUT method. PUT can allow "
            "clients to create or replace resources when insufficiently restricted."
        ),
        "remediation": (
            "Disable PUT where it is not required and ensure authorization "
            "controls are enforced for APIs that legitimately use it."
        )
    },
    "DELETE": {
        "severity": "MEDIUM",
        "title": "HTTP DELETE Method Advertised",
        "description": (
            "The web server advertises the HTTP DELETE method. DELETE can "
            "allow clients to remove resources when insufficiently restricted."
        ),
        "remediation": (
            "Disable DELETE where it is not required and enforce authorization "
            "for APIs that use it."
        )
    }
}


def check_http_methods(scanner, host, port, use_https=False):
    """
    Safely inspect HTTP methods advertised by the server.

    Uses OPTIONS only. No resource-changing HTTP methods are sent.
    """

    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}/"

    response = scanner.options_url(url)

    if not response or response.error:
        return []

    allow_header = response.headers.get("allow", "")

    if not allow_header:
        return []

    methods = {
        method.strip().upper()
        for method in allow_header.split(",")
        if method.strip()
    }

    findings = []

    for method, metadata in RISKY_METHODS.items():
        if method not in methods:
            continue

        findings.append(
            Finding(
                title=metadata["title"],
                severity=metadata["severity"],
                description=metadata["description"],
                host=host,
                port=port,
                service="http",
                evidence=f"Allow header: {allow_header}",
                remediation=metadata["remediation"]
            )
        )

    return findings
