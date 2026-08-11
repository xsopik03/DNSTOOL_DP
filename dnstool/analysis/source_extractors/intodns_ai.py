from __future__ import annotations

from typing import Any

from .base import BaseSourceAnalyzer


class IntoDnsAiSourceAnalyzer(BaseSourceAnalyzer):
    source_name = "intodns_ai"

    def analyze(self, domain: str, raw_output: dict[str, Any], source_client: Any = None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        checks = self._checks_by_id(raw_output)
        results = [
            result
            for result in (
                self._analyze_has_soa_record(checks),
                self._analyze_soa_format(checks),
                self._analyze_soa_timers(checks),
                self._analyze_dnssec_valid(checks),
                self._analyze_rrsig_not_expiring(checks),
                self._analyze_nsec3_rfc9276(checks),
                self._analyze_ds_digest_modern(checks),
                self._analyze_mx_ptr(checks),
                self._analyze_mx_fcrdns(checks),
                self._analyze_mx_dnssec_valid(checks),
                self._analyze_chain_of_trust_complete(checks),
                self._analyze_rrsig_ttl_safe(checks),
            )
            if result is not None
        ]
        recognized = [str(r.get("sourceId") or "") for r in results if r.get("sourceId")]
        return results, recognized, []

    def _walk_checks(self, value: Any):
        if isinstance(value, dict):
            checks = value.get("checks")
            if isinstance(checks, list):
                for item in checks:
                    if isinstance(item, dict) and item.get("id"):
                        yield item
            for item in value.values():
                yield from self._walk_checks(item)
            return
        if isinstance(value, list):
            for item in value:
                yield from self._walk_checks(item)

    def _checks_by_id(self, raw_output: dict[str, Any]) -> dict[str, dict[str, Any]]:
        report = raw_output.get("report") if isinstance(raw_output, dict) else None
        by_id: dict[str, dict[str, Any]] = {}
        if not isinstance(report, dict):
            return by_id
        for check in self._walk_checks(report):
            source_id = str(check.get("id") or "").strip()
            if source_id:
                by_id[source_id] = check
        return by_id

    def _result_from_check(self, checks: dict[str, dict[str, Any]], source_id: str, test_code: str, name: str, severity: str, info: str = ""):
        check = checks.get(source_id)
        if check is None:
            return None
        provider_status = check.get("status")
        if provider_status in (None, ""):
            provider_status = "pass" if check.get("passed") else "not_passed"
        return self._build_result(test_code, name, severity, info, source_id, provider_status, check.get("name"), check.get("details"))

    def _analyze_has_soa_record(self, checks):
        return self._result_from_check(checks, "has_soa_record",
            "PTV-DNS-SOA-PRESENT", "SOA record is present", "CRITICAL",
            "Checks that the zone publishes a Start of Authority record.")

    def _analyze_soa_format(self, checks):
        return self._result_from_check(checks, "soa_format",
            "PTV-DNS-SOA-SERIAL-FORMAT-VALID", "SOA serial format is valid", "MEDIUM",
            "Checks the syntax and sanity of the SOA serial value.")

    def _analyze_soa_timers(self, checks):
        return self._result_from_check(checks, "soa_timers",
            "PTV-DNS-SOA-TIMERS-VALID", "SOA timers are valid", "MEDIUM",
            "Checks the SOA refresh, retry and expire timer values.")

    def _analyze_dnssec_valid(self, checks):
        return self._result_from_check(checks, "dnssec_valid",
            "PTV-DNS-DNSSEC-VALID", "DNSSEC validation succeeds", "CRITICAL",
            "Performs provider-level validation of the signed zone rather than only checking that DS/DNSKEY records exist.")

    def _analyze_rrsig_not_expiring(self, checks):
        return self._result_from_check(checks, "rrsig_not_expiring",
            "PTV-DNS-DNSSEC-RRSIG-LIFETIME-VALID", "RRSIG lifetime is valid", "HIGH",
            "Checks whether DNSSEC signatures are valid for an appropriate time period and are not expired or dangerously close to expiry.")

    def _analyze_nsec3_rfc9276(self, checks):
        return self._result_from_check(checks, "nsec3_rfc9276",
            "PTV-DNS-DNSSEC-NSEC3-PARAMS-VALID", "NSEC3 parameters are acceptable", "MEDIUM",
            "Checks NSEC3 configuration when the zone uses NSEC3; the test is not applicable to zones using NSEC.")

    def _analyze_ds_digest_modern(self, checks):
        return self._result_from_check(checks, "ds_digest_modern",
            "PTV-DNS-DNSSEC-DS-DIGEST-SECURE", "DS digest algorithm is acceptable", "HIGH",
            "Checks whether the DS record uses a currently acceptable digest algorithm.")

    def _analyze_mx_ptr(self, checks):
        return self._result_from_check(checks, "mx_ptr",
            "PTV-DNS-MX-PTR-PRESENT", "Mail server addresses have PTR records", "MEDIUM",
            "Checks whether IP addresses of published mail exchangers have reverse DNS PTR records.")

    def _analyze_mx_fcrdns(self, checks):
        return self._result_from_check(checks, "mx_fcrdns",
            "PTV-DNS-MX-FCRDNS", "Mail servers have forward-confirmed reverse DNS", "MEDIUM",
            "Checks whether mail server reverse names resolve back to the corresponding server addresses.")

    def _analyze_mx_dnssec_valid(self, checks):
        return self._result_from_check(checks, "mx_dnssec_valid",
            "PTV-DNS-MX-DNSSEC-VALID", "DNSSEC validation succeeds for MX target domains", "MEDIUM",
            "Checks DNSSEC validity of the domains used as mail exchanger targets when DNSSEC is applicable.")

    def _analyze_chain_of_trust_complete(self, checks):
        return self._result_from_check(checks, "chain_of_trust_complete",
            "PTV-DNS-DNSSEC-CHAIN-COMPLETE", "DNSSEC chain of trust is complete", "CRITICAL",
            "Checks the delegated chain of trust rather than only the local DS-to-DNSKEY relationship.")

    def _analyze_rrsig_ttl_safe(self, checks):
        return self._result_from_check(checks, "rrsig_ttl_safe",
            "PTV-DNS-DNSSEC-RRSIG-TTL-SAFE", "RRset TTL is safe for RRSIG validity", "MEDIUM",
            "Checks that DNS TTL values do not create an unsafe relationship with the validity interval of DNSSEC signatures.")