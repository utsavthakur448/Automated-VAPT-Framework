from copy import deepcopy

from modules.vulnerabilities.database import VULNERABILITY_DATABASE
from modules.vulnerabilities.version import version_in_range, package_version_at_least
from modules.risk.severity import calculate_severity, calculate_priority


class VulnerabilityEngine:

    def __init__(self):
        self.checks = []

    def register_check(self, check):
        self.checks.append(check)

    # --------------------------------------------------
    # CPE MATCHING
    # --------------------------------------------------

    def cpe_matches(self, finding_cpe, database_cpe):
        """Determine whether a finding CPE matches a vulnerability database CPE."""
        if not finding_cpe or not database_cpe:
            return False

        if finding_cpe == database_cpe:
            return True

        return finding_cpe.startswith(database_cpe + ":")

    # --------------------------------------------------
    # CVE MATCHING
    # --------------------------------------------------

    def match_cves(self, finding):
        """Return all vulnerability database records matching the finding."""
        matches = []

        if not finding.cpe:
            return matches

        for vulnerability in VULNERABILITY_DATABASE:
            database_cpe = vulnerability.get("cpe", "")

            if not self.cpe_matches(finding.cpe, database_cpe):
                continue

            match_type = vulnerability.get("match_type", "VERSION")

            # PACKAGE VERSION MATCH
            if match_type == "PACKAGE":
                fixed_version = vulnerability.get("fixed_version")

                if not fixed_version:
                    continue

                if not package_version_at_least(
                    finding.version,
                    fixed_version
                ):
                    matches.append(vulnerability)

                continue

            # NORMAL VERSION RANGE MATCH
            affected_versions = vulnerability.get("affected_versions", [])

            for affected in affected_versions:
                minimum = affected.get("min")
                maximum = affected.get("max")

                if version_in_range(
                    finding.version,
                    minimum,
                    maximum
                ):
                    matches.append(vulnerability)
                    break

        return matches

    # --------------------------------------------------
    # BUILD FINAL FINDING
    # --------------------------------------------------

    def build_finding(self, original, vulnerability):
        """Convert a basic service finding into a vulnerability finding."""

        original.title = vulnerability.get("title", original.title)
        original.cve = vulnerability.get("cve", "")
        original.cvss = vulnerability.get("cvss", 0.0)
        original.severity = calculate_severity(original.cvss)
        original.priority = calculate_priority(
            original.severity,
            original.cvss
        )

        # DETECTION METHOD
        match_type = vulnerability.get("match_type", "VERSION")
        original.detection = (
            "PACKAGE_VERSION_MATCH"
            if match_type == "PACKAGE"
            else "VERSION_MATCH"
        )

        # CONFIDENCE
        original.confidence = "MEDIUM"

        # DESCRIPTION
        original.description = vulnerability.get(
            "description",
            original.description
        )

        # REMEDIATION
        original.remediation = vulnerability.get(
            "remediation",
            original.remediation
        )

        # REFERENCES
        references = vulnerability.get("references")

        if references:
            original.references = list(references)

        return original

    # --------------------------------------------------
    # MAIN VULNERABILITY SCAN
    # --------------------------------------------------

    def scan(self, scan_result):
        findings = []

        for asset in scan_result.assets:
            for port in asset.open_ports:
                for check in self.checks:
                    base_finding = check(asset, port)

                    if not base_finding:
                        continue

                    # FIND ALL CVE MATCHES
                    matches = self.match_cves(base_finding)

                    # NO CVE MATCH
                    if not matches:
                        findings.append(base_finding)

                    # ONE OR MORE CVE MATCHES
                    else:
                        for vulnerability in matches:
                            finding = self.build_finding(
                                self._copy_finding(base_finding),
                                vulnerability
                            )
                            findings.append(finding)

                    # Only the first matching service check handles this port.
                    # This will be redesigned in Milestone 4.
                    break

        return findings

    # --------------------------------------------------
    # SAFE FINDING COPY
    # --------------------------------------------------

    def _copy_finding(self, finding):
        """Create an independent copy for multiple CVE findings."""
        return deepcopy(finding)
