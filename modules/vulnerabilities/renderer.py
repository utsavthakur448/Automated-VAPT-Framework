from rich.console import Console


class VulnerabilityRenderer:

    def __init__(self):
        self.console = Console()

    # ======================================================
    # SECTION HEADER
    # ======================================================

    def _section_start(self, title):
        self.console.print()
        self.console.print("╔══════════════════════════════════════════════════════╗")
        self.console.print(f"║ {title:^52} ║")
        self.console.print("╚══════════════════════════════════════════════════════╝")
        self.console.print()

    # ======================================================
    # SECTION FOOTER
    # ======================================================

    def _section_end(self, title):
        self.console.print()
        self.console.print("──────────────────────────────────────────────────────")
        self.console.print(f"END OF {title}")
        self.console.print("──────────────────────────────────────────────────────")

    # ======================================================
    # DISPLAY VULNERABILITY RESULTS
    # ======================================================

    def display(self, findings):
        self._section_start("VULNERABILITY ASSESSMENT")

        if not findings:
            self.console.print("No vulnerabilities detected.")
            self._section_end("VULNERABILITY ASSESSMENT")
            return

        for finding in findings:
            severity = (finding.severity or "INFO").upper()

            self.console.print(f"[{severity}] {finding.title}")

            location = finding.host or "Unknown"

            if finding.port:
                location += f":{finding.port}/tcp"

            self.console.print(f"           Host       : {location}")

            if finding.cve:
                self.console.print(f"           CVE        : {finding.cve}")

            if finding.cvss:
                self.console.print(f"           CVSS       : {finding.cvss}")

            if finding.detection:
                self.console.print(
                    f"           Detection  : {finding.detection}"
                )

            if finding.confidence:
                self.console.print(
                    f"           Confidence : {finding.confidence}"
                )

            if finding.priority:
                self.console.print(
                    f"           Priority   : {finding.priority}"
                )

            self.console.print()

        # ==================================================
        # SEVERITY SUMMARY
        # ==================================================

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        counts = {severity: 0 for severity in severity_order}

        for finding in findings:
            severity = (finding.severity or "INFO").upper()

            if severity in counts:
                counts[severity] += 1

        self.console.print("Severity Summary")
        self.console.print("──────────────────────────────────────────────────────")

        for severity in severity_order:
            self.console.print(f"{severity:<9}: {counts[severity]}")

        self.console.print()
        self.console.print(f"Total Network Findings : {len(findings)}")

        self._section_end("VULNERABILITY ASSESSMENT")
