from __future__ import annotations

from enum import Enum
from typing import Any

from .models.checks import NormalizedCheckResult


class CheckOutcome(str, Enum):
    PASS = "pass"
    WARNING = "warning"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    INFO = "info"
    ERROR = "error"


_ACTIONABLE_OUTCOMES = {CheckOutcome.WARNING.value, CheckOutcome.FAIL.value}


NormalizedCheck = NormalizedCheckResult


def is_actionable_outcome(outcome: str) -> bool:
    return str(outcome or "").strip().lower() in _ACTIONABLE_OUTCOMES


def normalize_provider_outcome(
    source: str,
    provider_status: Any,
    provider_message: Any,
    *,
    zonemaster_notice_actionable: bool = False,
) -> CheckOutcome:
    message_text = str(provider_message or "").strip().lower()
    if _is_not_applicable_message(message_text):
        return CheckOutcome.NOT_APPLICABLE

    source_key = str(source or "").strip().lower()

    if source_key == "intodns":
        return _normalize_intodns_status(provider_status)
    if source_key == "mxtoolbox":
        return _normalize_mxtoolbox_status(provider_status)
    if source_key == "zonemaster":
        return _normalize_zonemaster_status(provider_status, notice_actionable=zonemaster_notice_actionable)

    return _normalize_generic_status(provider_status)


def local_issue_outcome_from_severity(severity: Any) -> CheckOutcome:
    sev = str(severity or "").strip().upper()
    if sev == "ERROR":
        return CheckOutcome.FAIL
    if sev == "WARNING":
        return CheckOutcome.WARNING
    if sev == "INFO":
        return CheckOutcome.INFO
    return CheckOutcome.WARNING


def _is_not_applicable_message(message_text: str) -> bool:
    if not message_text:
        return False
    return "not applicable" in message_text or "dnssec not enabled" in message_text


def _normalize_intodns_status(provider_status: Any) -> CheckOutcome:
    if isinstance(provider_status, str):
        token = provider_status.strip().lower()
        if token in {"1", "pass", "passed", "ok", "true"}:
            return CheckOutcome.PASS
        if token in {"0", "warning", "warnings", "warn"}:
            return CheckOutcome.WARNING
        if token in {"-1", "fail", "failed", "not_passed", "false"}:
            return CheckOutcome.FAIL
        if token in {"5", "n/a", "na", "not_applicable"}:
            return CheckOutcome.NOT_APPLICABLE

    if isinstance(provider_status, bool):
        return CheckOutcome.PASS if provider_status else CheckOutcome.FAIL

    if isinstance(provider_status, (int, float)):
        if int(provider_status) == 1:
            return CheckOutcome.PASS
        if int(provider_status) == 0:
            return CheckOutcome.WARNING
        if int(provider_status) == -1:
            return CheckOutcome.FAIL
        if int(provider_status) == 5:
            return CheckOutcome.NOT_APPLICABLE

    return _normalize_generic_status(provider_status)


def _normalize_mxtoolbox_status(provider_status: Any) -> CheckOutcome:
    token = str(provider_status or "").strip().lower()
    mapping = {
        "passed": CheckOutcome.PASS,
        "pass": CheckOutcome.PASS,
        "success": CheckOutcome.PASS,
        "ok": CheckOutcome.PASS,
        "warnings": CheckOutcome.WARNING,
        "warning": CheckOutcome.WARNING,
        "warn": CheckOutcome.WARNING,
        "failed": CheckOutcome.FAIL,
        "fail": CheckOutcome.FAIL,
        "timeouts": CheckOutcome.ERROR,
        "timeout": CheckOutcome.ERROR,
        "error": CheckOutcome.ERROR,
    }
    return mapping.get(token, _normalize_generic_status(provider_status))


def _normalize_zonemaster_status(provider_status: Any, *, notice_actionable: bool) -> CheckOutcome:
    tokens = _status_tokens(provider_status)

    if any(token in tokens for token in {"critical", "error", "fatal", "failure", "failed"}):
        return CheckOutcome.FAIL
    if "warning" in tokens:
        return CheckOutcome.WARNING
    if "notice" in tokens:
        return CheckOutcome.WARNING if notice_actionable else CheckOutcome.INFO
    if "info" in tokens:
        return CheckOutcome.PASS

    return CheckOutcome.INFO


def _normalize_generic_status(provider_status: Any) -> CheckOutcome:
    if isinstance(provider_status, bool):
        return CheckOutcome.PASS if provider_status else CheckOutcome.FAIL

    token = str(provider_status or "").strip().lower()
    if token in {"", "none", "null", "unknown"}:
        return CheckOutcome.INFO
    if token in {"pass", "passed", "success", "ok", "true", "1"}:
        return CheckOutcome.PASS
    if token in {"warning", "warnings", "warn", "0"}:
        return CheckOutcome.WARNING
    if token in {"fail", "failed", "not_passed", "false", "-1"}:
        return CheckOutcome.FAIL
    if token in {"not_applicable", "n/a", "na"}:
        return CheckOutcome.NOT_APPLICABLE
    if token in {"error", "timeout", "timeouts", "exception"}:
        return CheckOutcome.ERROR

    return CheckOutcome.INFO


def _status_tokens(provider_status: Any) -> set[str]:
    if isinstance(provider_status, (list, tuple, set)):
        text = ",".join(str(item or "") for item in provider_status)
    else:
        text = str(provider_status or "")

    normalized = text.replace("|", ",").replace(";", ",")
    tokens = {token.strip().lower() for token in normalized.split(",") if token.strip()}
    return tokens
