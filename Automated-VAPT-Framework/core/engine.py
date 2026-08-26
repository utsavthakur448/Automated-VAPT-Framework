from urllib.parse import urlparse

from core.target import Target
from core.scope import ScopeManager

from modules.discovery.nmap_scanner import NmapScanner
from modules.discovery.parser import NmapParser
from modules.discovery.renderer import NmapRenderer

from modules.vulnerabilities.engine import VulnerabilityEngine
from modules.vulnerabilities.renderer import VulnerabilityRenderer

from modules.vulnerabilities.checks.vsftpd import check_vsftpd
from modules.vulnerabilities.checks.apache import check_apache
from modules.vulnerabilities.checks.samba import check_samba
from modules.vulnerabilities.checks.mysql import check_mysql
from modules.vulnerabilities.checks.unrealircd import check_unrealircd
from modules.vulnerabilities.checks.tomcat import check_tomcat

from modules.web.engine import WebSecurityEngine
from modules.risk.prioritizer import RiskPrioritizer


class VAPTFramework:

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

        # Scope management
        self.scope_manager = ScopeManager(config.get("scope", {}))

        # Module configuration
        self.module_config = config.get("modules", {})

        self.discovery_enabled = self.module_config.get("discovery", True)
        self.web_scanner_enabled = self.module_config.get("web_scanner", True)
        self.network_scanner_enabled = self.module_config.get("network_scanner", True)
        self.validation_enabled = self.module_config.get("validation", True)
        self.reporter_enabled = self.module_config.get("reporter", True)

        # Discovery
        self.nmap_scanner = NmapScanner()
        self.nmap_parser = NmapParser()
        self.nmap_renderer = NmapRenderer()

        # Vulnerability engine
        self.vulnerability_engine = VulnerabilityEngine()

        self.vulnerability_engine.register_check(check_vsftpd)
        self.vulnerability_engine.register_check(check_apache)
        self.vulnerability_engine.register_check(check_samba)
        self.vulnerability_engine.register_check(check_mysql)
        self.vulnerability_engine.register_check(check_unrealircd)
        self.vulnerability_engine.register_check(check_tomcat)

        self.vulnerability_renderer = VulnerabilityRenderer()

        # Web security engine
        scan_config = config.get("scan", {})
        web_timeout = scan_config.get("timeout", 10)
        self.web_engine = WebSecurityEngine(timeout=web_timeout)

        # Risk prioritizer
        self.risk_prioritizer = RiskPrioritizer()

    # Main assessment
    def run_assessment(self, target_value):
        original_target = target_value.strip()

        self.logger.info(
            "Assessment started | Target: %s",
            original_target
        )

        # Target validation
        if self.validation_enabled:
            if not Target.validate(original_target):
                self.logger.error(
                    "Invalid target rejected | Target: %s",
                    original_target
                )
                raise ValueError(
                    f"Invalid target: {original_target}. "
                    "Target must be a valid IP address, hostname, "
                    "or HTTP/HTTPS URL."
                )

            self.logger.info(
                "Target validation successful | Target: %s",
                original_target
            )
        else:
            self.logger.warning("Target validation module disabled")

        # Parse target
        parsed_url = urlparse(original_target)

        # Target type
        if (
            parsed_url.scheme.lower() in ("http", "https")
            and parsed_url.hostname
        ):
            nmap_target = parsed_url.hostname
            web_target = original_target
            target_type = "web"
        else:
            nmap_target = original_target
            web_target = None
            target_type = "network"

        self.logger.info(
            "Target classified | Type: %s | Nmap Target: %s",
            target_type,
            nmap_target
        )

        # Create target
        target = Target.create(original_target, target_type)

        self.logger.info(
            "Target registered | Type: %s | Target: %s",
            target_type,
            original_target
        )

        # Scope validation
        if self.validation_enabled:
            if not self.scope_manager.validate(original_target):
                self.logger.error(
                    "Target rejected by scope policy | Target: %s",
                    original_target
                )
                raise ValueError(
                    "Target is outside the configured assessment scope."
                )

            self.logger.info(
                "Target scope validation successful | Target: %s",
                original_target
            )
        else:
            self.logger.warning(
                "Scope validation skipped because validation module is disabled"
            )

        # Nmap discovery
        scan_result = None

        if self.discovery_enabled:
            self.logger.info(
                "Nmap discovery started | Target: %s",
                nmap_target
            )

            raw_result = self.nmap_scanner.scan(nmap_target)
            scan_result = self.nmap_parser.parse(raw_result, nmap_target)

            hosts_discovered = len(scan_result.assets)
            open_ports = sum(
                len(asset.open_ports)
                for asset in scan_result.assets
            )

            self.logger.info(
                "Nmap discovery completed | Hosts: %s | Open Ports: %s",
                hosts_discovered,
                open_ports
            )

            self.nmap_renderer.display(scan_result)
        else:
            self.logger.info(
                "Nmap discovery skipped | Discovery module disabled"
            )

        # Network vulnerability detection
        network_findings = []

        if self.network_scanner_enabled and scan_result is not None:
            self.logger.info("Network vulnerability assessment started")

            network_findings = self.vulnerability_engine.scan(scan_result)

            self.logger.info(
                "Network vulnerability assessment completed | Findings: %s",
                len(network_findings)
            )

            self.vulnerability_renderer.display(network_findings)

        elif not self.network_scanner_enabled:
            self.logger.info(
                "Network vulnerability assessment skipped | "
                "Network scanner module disabled"
            )
        else:
            self.logger.warning(
                "Network vulnerability assessment skipped | "
                "Discovery module disabled"
            )

        # Web security assessment
        web_findings = []

        if self.web_scanner_enabled and scan_result is not None:
            self.logger.info("Web security assessment started")

            for asset in scan_result.assets:
                for port in asset.open_ports:
                    if port.service not in (
                        "http",
                        "https",
                        "ssl/https"
                    ):
                        continue

                    findings = self.web_engine.scan(
                        asset,
                        port,
                        web_target
                    )

                    if findings:
                        web_findings.extend(findings)

            self.logger.info(
                "Web security assessment completed | Findings: %s",
                len(web_findings)
            )

        elif not self.web_scanner_enabled:
            self.logger.info(
                "Web security assessment skipped | "
                "Web scanner module disabled"
            )
        else:
            self.logger.warning(
                "Web security assessment skipped | "
                "Discovery module disabled"
            )

        # Web results
        if self.web_scanner_enabled:
            self.display_web_findings(web_findings)

        # Combine findings
        all_findings = network_findings + web_findings

        self.logger.info(
            "Findings combined | Network: %s | Web: %s | Total: %s",
            len(network_findings),
            len(web_findings),
            len(all_findings)
        )

        # Risk assessment
        self.logger.info(
            "Risk assessment started | Total Findings: %s",
            len(all_findings)
        )

        risk_summary = self.risk_prioritizer.calculate_summary(all_findings)
        prioritized_findings = self.risk_prioritizer.prioritize(all_findings)

        self.logger.info(
            "Risk assessment completed | Risk: %s | Score: %s",
            risk_summary.get("risk_rating", "UNKNOWN"),
            risk_summary.get("risk_score", 0.0)
        )

        # Display risk
        self.display_risk_assessment(
            risk_summary,
            prioritized_findings
        )

        # Complete
        self.logger.info(
            "Assessment completed successfully | Target: %s | Total Findings: %s",
            original_target,
            len(all_findings)
        )

        return {
            "scan_result": scan_result,
            "findings": all_findings,
            "network_findings": network_findings,
            "web_findings": web_findings,
            "risk_summary": risk_summary,
            "prioritized_findings": prioritized_findings
        }

    # Web findings display
    def display_web_findings(self, findings):
        from rich.console import Console

        console = Console()

        console.print()
        console.print("╔══════════════════════════════════════════════════════╗")
        console.print("║              WEB SECURITY ASSESSMENT                 ║")
        console.print("╚══════════════════════════════════════════════════════╝")
        console.print()

        if not findings:
            console.print("No web security findings detected.")
            console.print()
            console.print("──────────────────────────────────────────────────────")
            console.print("END OF WEB SECURITY ASSESSMENT")
            console.print("──────────────────────────────────────────────────────")
            return

        for finding in findings:
            severity = (finding.severity or "INFO").upper()

            console.print(f"[{severity}] {finding.title}")

            host = finding.host or "Unknown"

            if finding.port:
                host = f"{host}:{finding.port}/tcp"

            console.print(f"           Host       : {host}")

            if finding.cve:
                console.print(f"           CVE        : {finding.cve}")

            if finding.cvss:
                console.print(f"           CVSS       : {finding.cvss}")

            if finding.detection:
                console.print(
                    f"           Detection  : {finding.detection}"
                )

            if finding.confidence:
                console.print(
                    f"           Confidence : {finding.confidence}"
                )

            if finding.evidence:
                console.print(
                    f"           Evidence   : {finding.evidence}"
                )

            console.print()

        # Severity summary
        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ]

        counts = {severity: 0 for severity in severity_order}

        for finding in findings:
            severity = (finding.severity or "INFO").upper()

            if severity in counts:
                counts[severity] += 1

        console.print("Web Severity Summary")
        console.print("──────────────────────────────────────────────────────")

        for severity in severity_order:
            console.print(f"{severity:<9}: {counts[severity]}")

        console.print()
        console.print(f"Total Web Findings : {len(findings)}")
        console.print()
        console.print("──────────────────────────────────────────────────────")
        console.print("END OF WEB SECURITY ASSESSMENT")
        console.print("──────────────────────────────────────────────────────")

    # Final risk assessment
    def display_risk_assessment(self, risk_summary, prioritized_findings):
        from rich.console import Console

        console = Console()

        console.print()
        console.print("╔══════════════════════════════════════════════════════╗")
        console.print("║                 FINAL RISK ASSESSMENT                ║")
        console.print("╚══════════════════════════════════════════════════════╝")
        console.print()

        # Risk overview
        console.print("Risk Overview")
        console.print("──────────────────────────────────────────────────────")

        overall_risk = risk_summary.get("risk_rating", "UNKNOWN")
        risk_score = risk_summary.get("risk_score", 0.0)
        total_findings = risk_summary.get("total_findings", 0)

        console.print(f"Overall Risk       : {overall_risk}")
        console.print(f"Risk Score         : {risk_score}")
        console.print(f"Total Findings     : {total_findings}")

        # Severity distribution
        console.print()
        console.print("Severity Distribution")
        console.print("──────────────────────────────────────────────────────")

        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ]

        severity_counts = risk_summary.get("severity_counts", {})

        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            console.print(f"{severity:<18}: {count}")

        # Interpretation
        console.print()
        console.print("Risk Interpretation")
        console.print("──────────────────────────────────────────────────────")

        interpretations = {
            "CRITICAL": (
                "Critical security risk detected. "
                "Immediate remediation is recommended "
                "for critical findings."
            ),
            "HIGH": (
                "High security risk detected. "
                "High-severity findings should be "
                "addressed as a priority."
            ),
            "MEDIUM": (
                "Moderate security risk detected. "
                "Medium-severity findings should be "
                "reviewed and remediated."
            ),
            "LOW": (
                "Low security risk detected. "
                "The identified findings should be "
                "addressed during routine hardening."
            ),
            "NO FINDINGS": (
                "No security findings were identified "
                "during the assessment."
            ),
            "INFORMATIONAL": (
                "Only informational findings were "
                "identified during the assessment."
            )
        }

        interpretation = interpretations.get(
            overall_risk,
            "Risk level could not be determined."
        )

        console.print(interpretation)

        # Top priorities
        console.print()
        console.print("Top Priorities")
        console.print("──────────────────────────────────────────────────────")

        if not prioritized_findings:
            console.print("No prioritized findings.")
        else:
            top_findings = prioritized_findings[:5]

            for index, item in enumerate(top_findings, start=1):
                if not isinstance(item, dict):
                    continue

                finding = item.get("finding")
                risk_score_value = item.get("risk_score", 0.0)
                priority = item.get(
                    "priority",
                    "INFORMATIONAL"
                )

                if finding is None:
                    continue

                title = getattr(
                    finding,
                    "title",
                    "Unknown Finding"
                )

                host = getattr(
                    finding,
                    "host",
                    "Unknown"
                )

                port = getattr(finding, "port", None)
                cve = getattr(finding, "cve", "")
                cvss = getattr(finding, "cvss", None)

                location = str(host or "Unknown")

                if port:
                    location += f":{port}/tcp"

                console.print(f"\n{index}. {title}")
                console.print(f"   Host       : {location}")

                if cve:
                    console.print(f"   CVE        : {cve}")

                if cvss not in (None, "", 0, 0.0):
                    console.print(f"   CVSS       : {cvss}")

                console.print(f"   Risk Score : {risk_score_value}")
                console.print(f"   Priority   : {priority}")

        console.print()
        console.print("──────────────────────────────────────────────────────")
        console.print("END OF FINAL RISK ASSESSMENT")
        console.print("──────────────────────────────────────────────────────")
