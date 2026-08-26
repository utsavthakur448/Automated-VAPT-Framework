from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from modules.vulnerabilities.models import Finding


def check_reflected_xss(scanner, url, parameter="q"):
    """
    Passive/safe reflected-XSS indicator.

    Sends a unique harmless marker and checks whether the application
    reflects that marker in the response.

    Reflection alone is NOT proof of exploitable XSS.
    """

    marker = "NEXUS_XSS_TEST_7F3A"
    parsed = urlparse(url)

    query = parse_qs(parsed.query, keep_blank_values=True)
    query[parameter] = [marker]

    new_query = urlencode(query, doseq=True)

    test_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    response = scanner.scan_url(test_url)

    if not response or response.error:
        return None

    if marker not in response.body:
        return None

    return Finding(
        title="Potential Reflected XSS",
        severity="MEDIUM",
        description=(
            "A unique test marker supplied through an HTTP parameter was "
            "reflected in the response. Reflection alone does not prove "
            "exploitable cross-site scripting and requires manual validation."
        ),
        host=parsed.hostname or "",
        service="http",
        evidence=(
            f"Parameter: {parameter}; marker reflected in HTTP response "
            f"from {response.url}"
        ),
        remediation=(
            "Validate and contextually encode untrusted input before rendering "
            "it in HTML, JavaScript, CSS, or other executable contexts."
        )
    )
