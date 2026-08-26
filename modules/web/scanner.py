import re
import time
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from modules.web.models import WebResponse


class WebScanner:

    def __init__(self, timeout=10, verify_ssl=False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _resolve_scheme(self, port, use_https=None):
        """Determine the HTTP scheme."""

        if use_https is not None:
            return "https" if use_https else "http"

        try:
            port_number = int(port)
        except (TypeError, ValueError):
            port_number = 0

        return "https" if port_number == 443 else "http"

    def scan(self, host, port, use_https=None, path="/"):
        """Scan a host/port."""

        scheme = self._resolve_scheme(port, use_https)
        path = path or "/"

        if not path.startswith("/"):
            path = "/" + path

        url = f"{scheme}://{host}:{port}{path}"
        return self.scan_url(url)

    def scan_url(self, url):
        try:
            start = time.time()

            with warnings.catch_warnings():
                if not self.verify_ssl:
                    warnings.simplefilter(
                        "ignore",
                        InsecureRequestWarning
                    )

                response = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    headers={"User-Agent": "NEXUS-VAPT/0.1"}
                )

            elapsed = time.time() - start

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            body = response.text
            title = self.extract_title(body)
            technologies = self.detect_technologies(body, headers)

            return WebResponse(
                url=response.url,
                status_code=response.status_code,
                reason=response.reason or "",
                headers=headers,
                server=headers.get("server", ""),
                content_type=headers.get("content-type", ""),
                title=title,
                technologies=technologies,
                response_time=round(elapsed, 3),
                body=body
            )

        except requests.RequestException as exc:
            return WebResponse(url=url, error=str(exc))

    def scan_path(self, host, port, path="/", use_https=None):
        return self.scan(
            host=host,
            port=port,
            use_https=use_https,
            path=path
        )

    def options_url(self, url):
        try:
            with warnings.catch_warnings():
                if not self.verify_ssl:
                    warnings.simplefilter(
                        "ignore",
                        InsecureRequestWarning
                    )

                response = requests.options(
                    url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                    headers={"User-Agent": "NEXUS-VAPT/0.1"}
                )

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            return WebResponse(
                url=response.url,
                status_code=response.status_code,
                reason=response.reason or "",
                headers=headers,
                server=headers.get("server", ""),
                content_type=headers.get("content-type", "")
            )

        except requests.RequestException as exc:
            return WebResponse(url=url, error=str(exc))

    def extract_title(self, html):
        if not html:
            return ""

        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL
        )

        if not match:
            return ""

        return " ".join(match.group(1).split())

    def detect_technologies(self, body, headers):
        technologies = []

        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        body_lower = body[:50000].lower() if body else ""

        if "apache" in server:
            technologies.append("Apache HTTP Server")

        if "nginx" in server:
            technologies.append("Nginx")

        if "microsoft-iis" in server:
            technologies.append("Microsoft IIS")

        if (
            "php" in server
            or "php" in powered_by
            or ".php" in body_lower
        ):
            technologies.append("PHP")

        if "express" in powered_by:
            technologies.append("Express")

        if "tomcat" in server or "coyote" in server:
            technologies.append("Apache Tomcat")

        if (
            "wp-content" in body_lower
            or "wordpress" in body_lower
        ):
            technologies.append("WordPress")

        return list(dict.fromkeys(technologies))
