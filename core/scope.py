import ipaddress


class ScopeManager:
    def __init__(self, config):
        self.allowed_targets = config.get("allowed_targets", [])
        self.excluded_targets = config.get("excluded_targets", [])

    def validate(self, target):
        return self.is_allowed(target)

    def is_allowed(self, target):
        target = str(target).strip()

        # Excluded targets always win
        if self._matches_scope(target, self.excluded_targets):
            return False

        # Empty allow list = unrestricted
        if not self.allowed_targets:
            return True

        # Target must match allow list
        return self._matches_scope(target, self.allowed_targets)

    def _matches_scope(self, target, scope_entries):
        for entry in scope_entries:
            if not entry:
                continue

            entry = str(entry).strip()

            if not entry:
                continue

            # Exact string match
            if target.lower() == entry.lower():
                return True

            # Target as IP
            try:
                target_ip = ipaddress.ip_address(target)
            except ValueError:
                target_ip = None

            # Entry as IP or network
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(entry, strict=False)

                    if target_ip is not None and target_ip in network:
                        return True
                else:
                    entry_ip = ipaddress.ip_address(entry)

                    if target_ip is not None and target_ip == entry_ip:
                        return True

            except ValueError:
                pass

        return False
