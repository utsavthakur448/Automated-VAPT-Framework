from dataclasses import dataclass, field
from typing import Dict


@dataclass
class Evidence:
    finding_title: str
    target: str
    method: str = "GET"
    url: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    response_excerpt: str = ""
    detection: str = ""
    confidence: str = "MEDIUM"


class EvidenceCollector:
    def collect_web_evidence(self, finding, response=None, detection="WEB_CHECK", confidence="MEDIUM"):
        evidence = Evidence(
            finding_title=finding.title,
            target=f"{finding.host}:{finding.port}",
            detection=detection,
            confidence=confidence,
        )

        if response:
            evidence.url = response.url
            evidence.status_code = response.status_code
            evidence.headers = dict(response.headers)
            evidence.response_excerpt = (response.body or "")[:500]

        return evidence

    def format_evidence(self, evidence):
        lines = [
            f"Finding: {evidence.finding_title}",
            f"Target: {evidence.target}",
            f"Detection: {evidence.detection}",
            f"Confidence: {evidence.confidence}",
        ]

        if evidence.url:
            lines.append(f"URL: {evidence.url}")

        if evidence.status_code:
            lines.append(f"HTTP Status: {evidence.status_code}")

        if evidence.headers:
            lines.append("Response Headers:")
            lines.extend(
                f"  {key}: {value}"
                for key, value in evidence.headers.items()
            )

        if evidence.response_excerpt:
            lines.extend([
                "Response Excerpt:",
                evidence.response_excerpt,
            ])

        return "\n".join(lines)
