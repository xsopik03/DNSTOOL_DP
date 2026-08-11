from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IssueFinding:
    vuln_code: str
    severity: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_code": self.vuln_code,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
        }
