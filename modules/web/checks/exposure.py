from modules.vulnerabilities.models import Finding


EXPOSED_PATHS = {
    "/robots.txt": {
        "title": "Robots.txt Accessible",
        "severity": "INFO",
        "description": (
            "The robots.txt file is publicly accessible. It may reveal "
            "application paths or areas that site administrators intended "
            "search engines to avoid indexing."
        ),
        "remediation": (
            "Review robots.txt contents and ensure it does not disclose "
            "sensitive application paths."
        )
    },
    "/sitemap.xml": {
        "title": "Sitemap Accessible",
        "severity": "INFO",
        "description": (
            "A publicly accessible sitemap was detected. Sitemaps can "
            "reveal application routes and content structure."
        ),
        "remediation": (
            "Review the sitemap and ensure that sensitive or administrative "
            "paths are not unnecessarily listed."
        )
    },
    "/server-status": {
        "title": "Apache Server Status Accessible",
        "severity": "MEDIUM",
        "description": (
            "The Apache server-status endpoint appears to be publicly "
            "accessible. Such endpoints may disclose operational information "
            "about the web server."
        ),
        "remediation": (
            "Restrict server-status access to trusted administrative hosts "
            "or disable it when it is not required."
        )
    },
    "/server-info": {
        "title": "Apache Server Info Accessible",
        "severity": "MEDIUM",
        "description": (
            "The Apache server-info endpoint appears to be publicly "
            "accessible and may disclose server configuration information."
        ),
        "remediation": (
            "Restrict server-info access to trusted administrative hosts "
            "or disable the module when it is not required."
        )
    }
}


def check_sensitive_exposure(scanner, host, port, use_https=False):
    """
    Check selected public web paths for potentially sensitive
    information exposure.

    This check does not attempt authentication bypass or
    access-control circumvention.
    """

    findings = []

    for path, metadata in EXPOSED_PATHS.items():
        response = scanner.scan_path(
            host,
            port,
            path,
            use_https=use_https
        )

        if not response or response.error:
            continue

        if response.status_code != 200:
            continue

        findings.append(
            Finding(
                title=metadata["title"],
                severity=metadata["severity"],
                description=metadata["description"],
                host=host,
                port=port,
                service="http",
                evidence=(
                    f"Publicly accessible URL: {response.url}; "
                    f"HTTP status: {response.status_code}"
                ),
                remediation=metadata["remediation"]
            )
        )

    return findings
