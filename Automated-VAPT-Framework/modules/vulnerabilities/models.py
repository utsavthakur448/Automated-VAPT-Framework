from dataclasses import dataclass, field
from typing import List

@dataclass
class Finding:
    title: str
    severity: str
    description: str
    host: str

    port: int = 0
    service: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""

    cve: str = ""
    cvss: float = 0.0
    priority: str = ""

    detection: str = ""
    confidence: str = ""
    evidence: str = ""
    remediation: str = ""

    references: List[str] = field(default_factory=list)
