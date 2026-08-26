class WebFingerprint:

    def analyze(self, response):
        return {
            "server": response.server,
            "powered_by": response.headers.get("x-powered-by", ""),
            "content_type": response.content_type,
            "title": response.title,
            "technologies": list(response.technologies),
            "cookies": self.extract_cookies(response),
            "interesting_headers": self.extract_interesting_headers(response)
        }

    def extract_cookies(self, response):
        raw_cookie = response.headers.get("set-cookie", "")

        if not raw_cookie:
            return []

        cookies = []

        for cookie in raw_cookie.split(","):
            name = cookie.split("=", 1)[0].strip()

            if name:
                cookies.append(name)

        return list(dict.fromkeys(cookies))

    def extract_interesting_headers(self, response):
        interesting = {}

        headers_to_check = [
            "server",
            "x-powered-by",
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
            "access-control-allow-origin"
        ]

        for header in headers_to_check:
            value = response.headers.get(header)

            if value:
                interesting[header] = value

        return interesting
