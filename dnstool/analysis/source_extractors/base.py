from __future__ import annotations

from typing import Any, Optional

from ...check_normalization import normalize_provider_outcome
from ...models.checks import NormalizedCheckResult


_SEVERITY_MAP = {
    "CRITICAL": "ERROR",
    "HIGH": "ERROR",
    "MEDIUM": "WARNING",
    "LOW": "WARNING",
    "INFO": "INFO",
}


def _runtime_severity(severity: str) -> str:
    return _SEVERITY_MAP.get(str(severity or "").strip().upper(), "WARNING")


class BaseSourceAnalyzer:
    source_name: str = ""

    def analyze(
        self,
        domain: str,
        raw_output: dict[str, Any],
        source_client: Any = None,
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        raise NotImplementedError()

    def _build_result(
        self,
        test_code: str,
        name: str,
        severity: str,
        info: str,
        source_id: str,
        provider_status: Any,
        provider_name: Any,
        provider_message: Any,
    ) -> Optional[dict[str, Any]]:
        message_text = str(provider_message or "").strip() or None
        outcome = normalize_provider_outcome(
            self.source_name,
            provider_status,
            message_text,
            zonemaster_notice_actionable=False,
        )

        details = {
            "evidenceSource": self.source_name,
            "source": self.source_name,
            "sourceId": str(source_id),
            "providerStatus": provider_status,
            "providerName": provider_name,
        }
        if message_text:
            details["providerMessage"] = message_text

        return NormalizedCheckResult(
            test_code=test_code,
            name=name,
            severity=_runtime_severity(severity),
            outcome=outcome,
            source=self.source_name,
            source_id=str(source_id),
            provider_status=provider_status,
            message=message_text,
            catalog_info=info,
            details=details,
        ).to_dict()