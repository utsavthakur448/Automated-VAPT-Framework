class RiskAssessor:
    def assess(self, finding):
        cvss = finding.cvss

        if cvss >= 9.0:
            return "IMMEDIATE"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        if cvss > 0:
            return "LOW"

        return "INFORMATIONAL"

    def assess_all(self, findings):
        for finding in findings:
            finding.priority = self.assess(finding)

        return findings
