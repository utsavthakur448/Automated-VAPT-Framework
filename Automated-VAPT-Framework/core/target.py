import ipaddress
import re
from urllib.parse import urlparse


class Target:
    @classmethod
    def create(cls, value, target_type):
        target = cls()
        target.value = value
        target.target_type = target_type
        return target

    @staticmethod
    def validate(value):
        """
        Validate an assessment target.

        Supported:
        - IPv4 addresses
        - IPv6 addresses
        - localhost
        - Local hostnames containing a dot
        - HTTP URLs
        - HTTPS URLs

        Returns:
            True  -> valid
            False -> invalid
        """
        if value is None:
            return False

        value = str(value).strip()

        if not value:
            return False

        # URL
        parsed = urlparse(value)

        if parsed.scheme:
            if parsed.scheme.lower() not in ("http", "https"):
                return False

            if not parsed.hostname:
                return False

            return Target.validate_hostname_or_ip(parsed.hostname)

        # IP / hostname
        return Target.validate_hostname_or_ip(value)

    @staticmethod
    def validate_hostname_or_ip(value):
        if not value:
            return False

        value = value.strip()

        # IP address
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass

        # Localhost
        if value.lower() == "localhost":
            return True

        # Hostname length
        if len(value) > 253:
            return False

        # Invalid characters
        if " " in value or "/" in value or "\\" in value:
            return False

        # FQDN / domain-style hostname
        hostname_pattern = re.compile(
            r"^(?=.{1,253}$)"
            r"(?:"
            r"[A-Za-z0-9]"
            r"[A-Za-z0-9-]{0,61}"
            r"[A-Za-z0-9]"
            r"\."
            r")+"
            r"[A-Za-z]{2,63}$"
        )

        if hostname_pattern.match(value):
            return True

        # Allowed single-label local hostnames
        allowed_local_hosts = {
            "localhost",
            "kali",
            "metasploitable",
            "target",
            "server",
            "client",
        }

        if value.lower() in allowed_local_hosts:
            return True

        return False
