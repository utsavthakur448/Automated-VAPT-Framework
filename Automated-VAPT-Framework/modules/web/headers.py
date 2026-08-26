SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Content-Security-Policy Missing",
        "severity": "LOW",
        "description": (
            "The web application does not appear to define a "
            "Content-Security-Policy header. CSP can reduce the impact "
            "of certain content injection and cross-site scripting attacks."
        ),
        "remediation": (
            "Implement a restrictive Content-Security-Policy appropriate "
            "for the application."
        )
    },
    "x-frame-options": {
        "title": "X-Frame-Options Header Missing",
        "severity": "LOW",
        "description": (
            "The web server does not appear to define an X-Frame-Options "
            "header. This may allow the application to be embedded in "
            "frames and can increase clickjacking risk."
        ),
        "remediation": (
            "Configure X-Frame-Options or an appropriate frame-ancestors "
            "directive in CSP."
        )
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options Header Missing",
        "severity": "LOW",
        "description": (
            "The web server does not appear to define the "
            "X-Content-Type-Options header."
        ),
        "remediation": "Set X-Content-Type-Options to nosniff."
    },
    "referrer-policy": {
        "title": "Referrer-Policy Header Missing",
        "severity": "LOW",
        "description": (
            "The web application does not appear to define a "
            "Referrer-Policy header."
        ),
        "remediation": (
            "Configure an appropriate Referrer-Policy for the application."
        )
    },
    "permissions-policy": {
        "title": "Permissions-Policy Header Missing",
        "severity": "LOW",
        "description": (
            "The web application does not appear to define a "
            "Permissions-Policy header."
        ),
        "remediation": (
            "Configure Permissions-Policy to restrict unnecessary "
            "browser capabilities."
        )
    },
    "strict-transport-security": {
        "title": "HSTS Header Missing",
        "severity": "LOW",
        "description": (
            "The HTTPS response does not appear to define "
            "Strict-Transport-Security."
        ),
        "remediation": (
            "When HTTPS is fully deployed, configure "
            "Strict-Transport-Security with an appropriate max-age "
            "and deployment policy."
        )
    }
}


def check_security_headers(response):
    findings = []
    headers = response.headers
    is_https = response.url.lower().startswith("https://")

    for header, metadata in SECURITY_HEADERS.items():
        if header == "strict-transport-security" and not is_https:
            continue

        if header not in headers:
            findings.append({
                "title": metadata["title"],
                "severity": metadata["severity"],
                "description": metadata["description"],
                "header": header,
                "remediation": metadata["remediation"]
            })

    return findings
