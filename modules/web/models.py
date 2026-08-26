from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class WebResponse:
    url: str
    status_code: int = 0
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    server: str = ""
    content_type: str = ""
    title: str = ""
    technologies: List[str] = field(default_factory=list)
    response_time: float = 0.0
    body: str = ""
    error: str = ""
