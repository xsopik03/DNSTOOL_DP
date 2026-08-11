from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedCheckResult:
    test_code: str
    name: str
    severity: str
    outcome: Any
    source: str
    source_id: str | None
    provider_status: Any
    message: str | None
    catalog_info: str | None
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        outcome = self.outcome.value if hasattr(self.outcome, "value") else self.outcome
        return {
            "testCode": self.test_code,
            "name": self.name,
            "severity": self.severity,
            "outcome": outcome,
            "source": self.source,
            "sourceId": self.source_id,
            "providerStatus": self.provider_status,
            "message": self.message,
            "catalogInfo": self.catalog_info,
            "details": self.details,
        }
