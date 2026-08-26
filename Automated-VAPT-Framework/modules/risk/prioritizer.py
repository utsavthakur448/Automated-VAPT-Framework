from collections import Counter


SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 0,
}

PRIORITY_MAP = {
    "CRITICAL": "IMMEDIATE",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
}


class RiskPrioritizer:
    def calculate_finding_risk(self, finding):
        severity = (finding.severity or "INFO").upper()
        cvss = float(finding.cvss or 0.0)
        weight = SEVERITY_WEIGHTS.get(severity, 0)

        score = (weight * 0.4 + cvss * 0.6) if cvss > 0 else float(weight)
        return round(score, 2)

    def prioritize(self, findings):
        prioritized = []

        for finding in findings:
            severity = (finding.severity or "INFO").upper()
            prioritized.append({
                "finding": finding,
                "risk_score": self.calculate_finding_risk(finding),
                "priority": PRIORITY_MAP.get(severity, "INFORMATIONAL"),
            })

        prioritized.sort(key=lambda item: item["risk_score"], reverse=True)
        return prioritized

    def calculate_summary(self, findings):
        if not findings:
            return {
                "risk_score": 0.0,
                "risk_rating": "NO FINDINGS",
                "total_findings": 0,
                "severity_counts": {},
            }

        severity_counts = Counter(
            (finding.severity or "INFO").upper()
            for finding in findings
        )

        cvss_scores = [
            float(finding.cvss or 0.0)
            for finding in findings
            if float(finding.cvss or 0.0) > 0
        ]

        if cvss_scores:
            overall_score = max(cvss_scores)
        else:
            overall_score = max(
                (
                    SEVERITY_WEIGHTS.get(
                        (finding.severity or "INFO").upper(),
                        0,
                    )
                    for finding in findings
                ),
                default=0.0,
            )

        return {
            "risk_score": round(overall_score, 2),
            "risk_rating": self.rating_from_score(overall_score),
            "total_findings": len(findings),
            "severity_counts": dict(severity_counts),
        }

    def rating_from_score(self, score):
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "INFORMATIONAL"
