from modules.vulnerabilities.models import Finding


def check_authentication(response, host, port):
    """
    Passive authentication and session-security checks.

    No credentials are submitted and no authentication bypass is attempted.
    """

    findings = []

    if not response or response.error:
        return findings

    headers = response.headers

    # -----------------------------------------
    # HTTP BASIC AUTHENTICATION
    # -----------------------------------------

    www_authenticate = headers.get("www-authenticate", "")

    if www_authenticate:
        findings.append(
            Finding(
                title="HTTP Authentication Challenge Exposed",
                severity="INFO",
                description=(
                    "The server exposes an HTTP authentication challenge "
                    "through the WWW-Authenticate header."
                ),
                host=host,
                port=port,
                service="http",
                evidence=f"WWW-Authenticate: {www_authenticate}",
                remediation=(
                    "Review whether HTTP authentication is required and "
                    "ensure authentication credentials are protected by HTTPS."
                )
            )
        )

    # -----------------------------------------
    # COOKIE SECURITY
    # -----------------------------------------

    set_cookie = headers.get("set-cookie", "")

    if not set_cookie:
        return findings

    cookie_lower = set_cookie.lower()

    # HttpOnly
    if "httponly" not in cookie_lower:
        findings.append(
            Finding(
                title="Session Cookie Missing HttpOnly",
                severity="LOW",
                description=(
                    "A session-related cookie was observed without the "
                    "HttpOnly attribute. This may increase exposure to "
                    "client-side script access if an XSS vulnerability exists."
                ),
                host=host,
                port=port,
                service="http",
                evidence=f"Set-Cookie: {set_cookie}",
                remediation=(
                    "Set the HttpOnly attribute on session cookies where "
                    "client-side JavaScript does not require access."
                )
            )
        )

    # Secure
    if response.url.lower().startswith("https://") and "secure" not in cookie_lower:
        findings.append(
            Finding(
                title="HTTPS Cookie Missing Secure Flag",
                severity="LOW",
                description=(
                    "A cookie was observed over HTTPS without the Secure attribute."
                ),
                host=host,
                port=port,
                service="https",
                evidence=f"Set-Cookie: {set_cookie}",
                remediation=(
                    "Set the Secure attribute on cookies that should only "
                    "be transmitted over HTTPS."
                )
            )
        )

    # SameSite
    if "samesite" not in cookie_lower:
        findings.append(
            Finding(
                title="Cookie Missing SameSite Attribute",
                severity="LOW",
                description=(
                    "A cookie was observed without an explicit SameSite attribute."
                ),
                host=host,
                port=port,
                service="http",
                evidence=f"Set-Cookie: {set_cookie}",
                remediation=(
                    "Configure an appropriate SameSite policy such as Lax or "
                    "Strict where compatible with application behavior."
                )
            )
        )

    return findings
