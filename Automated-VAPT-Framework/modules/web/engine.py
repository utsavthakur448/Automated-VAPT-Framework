from urllib.parse import urlparse

from modules.web.scanner import WebScanner
from modules.web.headers import check_security_headers
from modules.web.checks.information_disclosure import check_information_disclosure
from modules.web.checks.directory_listing import check_directory_listing
from modules.web.checks.xss import check_reflected_xss
from modules.web.checks.sqli import check_sql_error
from modules.web.checks.http_methods import check_http_methods
from modules.web.checks.exposure import check_sensitive_exposure
from modules.web.checks.authentication import check_authentication


class WebSecurityEngine:

    def __init__(self, timeout=10, verify_ssl=False):
        self.scanner = WebScanner(timeout=timeout, verify_ssl=verify_ssl)

    def scan(self, asset, port, target_url=None):
        findings = []
        host = asset.host
        port_number = port.number

        # Only HTTP / HTTPS services
        if port.service not in ("http", "https", "ssl/https"):
            return findings

        # Determine target scheme and path
        target_scheme = None
        target_path = "/"

        if target_url:
            parsed = urlparse(target_url)

            if parsed.scheme.lower() in ("http", "https"):
                target_scheme = parsed.scheme.lower()

            if parsed.path:
                target_path = parsed.path

            if parsed.query:
                target_path += "?" + parsed.query

        # Determine port scheme
        try:
            numeric_port = int(port_number)
        except (TypeError, ValueError):
            numeric_port = 0

        port_scheme = "https" if numeric_port == 443 else "http"

        # Select HTTPS
        use_https = numeric_port == 443 or target_scheme == "https"

        # Initial web request
        if target_url:
            parsed = urlparse(target_url)
            target_host = parsed.hostname or host

            if (
                target_scheme == port_scheme
                or (target_scheme == "https" and numeric_port == 443)
            ):
                response_url = target_url
            else:
                response_url = (
                    f"{port_scheme}://{target_host}:{port_number}{target_path}"
                )

            response = self.scanner.scan_url(response_url)
        else:
            response = self.scanner.scan(
                host=host,
                port=port_number,
                use_https=use_https,
                path=target_path
            )

        if response.error:
            return findings

        # Security headers
        header_results = check_security_headers(response)
        findings.extend(self._convert_header_findings(header_results, asset, port))

        # Information disclosure
        information_results = check_information_disclosure(
            asset, port, response
        )
        findings.extend(self._ensure_list(information_results))

        # Directory listing
        directory_results = check_directory_listing(
            asset, port, self.scanner
        )
        findings.extend(self._ensure_list(directory_results))

        # Reflected XSS
        xss_url = f"{response.url}?q=test"
        xss_result = check_reflected_xss(self.scanner, xss_url)
        findings.extend(self._ensure_list(xss_result))

        # SQL error detection
        sqli_url = f"{response.url}?id=1"
        sqli_result = check_sql_error(self.scanner, sqli_url)
        findings.extend(self._ensure_list(sqli_result))

        # HTTP methods
        method_results = check_http_methods(
            self.scanner,
            host,
            port_number,
            use_https=use_https
        )
        findings.extend(self._ensure_list(method_results))

        # Sensitive file exposure
        exposure_results = check_sensitive_exposure(
            self.scanner,
            host,
            port_number,
            use_https=use_https
        )
        findings.extend(self._ensure_list(exposure_results))

        # Authentication / session checks
        authentication_results = check_authentication(
            response,
            host,
            port_number
        )
        findings.extend(self._ensure_list(authentication_results))

        return findings

    def _ensure_list(self, value):
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]

    def _convert_header_findings(self, results, asset, port):
        from modules.vulnerabilities.models import Finding

        findings = []

        for item in results or []:
            if isinstance(item, Finding):
                findings.append(item)
                continue

            finding = Finding(
                title=item.get("title", "Web Security Header Issue"),
                severity=item.get("severity", "LOW"),
                description=item.get("description", ""),
                host=asset.host,
                port=port.number,
                service=port.service,
                product=port.product,
                version=port.version,
                cpe=port.cpe,
                evidence=f"Missing or insecure header: {item.get('header', '')}",
                remediation=item.get("remediation", "")
            )

            findings.append(finding)

        return findings
