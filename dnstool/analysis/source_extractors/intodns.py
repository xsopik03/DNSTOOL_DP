from __future__ import annotations

from typing import Any

from .base import BaseSourceAnalyzer


class IntoDnsSourceAnalyzer(BaseSourceAnalyzer):
    source_name = "intodns"

    def analyze(self, domain: str, raw_output: dict[str, Any], source_client: Any = None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        if source_client is None:
            return [], [], []

        cache: dict[str, dict[str, Any] | None] = {}
        results = [
            result
            for result in (
                self._analyze_all_authority_hosts_has_same_soa(domain, raw_output, source_client, cache),
                self._analyze_mname_term_is_real_authority_host(domain, raw_output, source_client, cache),
                self._analyze_target_hosts_with_resolvable_ips(domain, raw_output, source_client, cache),
                self._analyze_duplicated_records(domain, raw_output, source_client, cache),
                self._analyze_no_records_points_to_cname(domain, raw_output, source_client, cache),
                self._analyze_records_hosts_can_send_emails(domain, raw_output, source_client, cache),
                self._analyze_subdomain_policy_term(domain, raw_output, source_client, cache),
                self._analyze_rua_and_ruf_terms(domain, raw_output, source_client, cache),
                self._analyze_fo_term(domain, raw_output, source_client, cache),
            )
            if result is not None
        ]
        recognized = [str(r.get("sourceId") or "") for r in results if r.get("sourceId")]
        return results, recognized, []

    def _response_for(self, domain: str, raw_output: dict[str, Any], source_client: Any, cache: dict[str, dict[str, Any] | None], source_id: str):
        if source_id not in cache:
            cache[source_id] = source_client.run_documented_test(domain, source_id, raw_output)
        return cache[source_id]

    def _result_from_response(self, domain: str, raw_output: dict[str, Any], source_client: Any, cache: dict[str, dict[str, Any] | None], source_id: str, test_code: str, name: str, severity: str, info: str = ""):
        response = self._response_for(domain, raw_output, source_client, cache, source_id)
        if not isinstance(response, dict):
            return None
        provider_status = response.get("test-status")
        provider_message = "; ".join(response.get("test-warning-messages", []) or [])
        return self._build_result(
            test_code, name, severity, info, source_id,
            provider_status,
            response.get("test-name") or source_id,
            provider_message,
        )

    def _analyze_all_authority_hosts_has_same_soa(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "All authority hosts has the same SOA test (2)",
            "PTV-DNS-SOA-CONSISTENT", "SOA data are consistent across authoritative servers", "HIGH",
            "Checks that authoritative servers return a consistent SOA record for the same zone.")

    def _analyze_mname_term_is_real_authority_host(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "The term mname is real authority hosts test (9)",
            "PTV-DNS-SOA-MNAME-AUTHORITATIVE", "SOA MNAME identifies an authoritative server", "HIGH",
            "Checks that the SOA MNAME value points to a real authoritative name server for the zone.")

    def _analyze_target_hosts_with_resolvable_ips(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Target hosts with resolvable IPs test (16)",
            "PTV-DNS-MX-TARGET-RESOLVABLE", "MX targets are resolvable", "HIGH",
            "Checks that hostnames referenced by MX records resolve to usable IP addresses.")

    def _analyze_duplicated_records(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Duplicated records test (17)",
            "PTV-DNS-MX-NO-DUPLICATES", "MX records are not duplicated", "MEDIUM",
            "Checks for redundant duplicate MX records pointing to the same mail exchanger.")

    def _analyze_no_records_points_to_cname(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "No records points to CNAME test (18)",
            "PTV-DNS-MX-NO-CNAME", "MX targets are not CNAME aliases", "HIGH",
            "Checks that MX records point directly to mail exchanger hostnames rather than CNAME aliases.")

    def _analyze_records_hosts_can_send_emails(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Records hosts can send emails test (22)",
            "PTV-DNS-SPF-MECHANISMS-VALID", "SPF mechanisms are valid", "HIGH",
            "Checks whether mechanisms and referenced hosts used by the SPF policy are valid.")

    def _analyze_subdomain_policy_term(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Subdomain policy term test (27)",
            "PTV-DNS-DMARC-SUBDOMAIN-POLICY-VALID", "DMARC subdomain policy is valid", "MEDIUM",
            "Checks the optional sp tag and its allowed policy values.")

    def _analyze_rua_and_ruf_terms(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Rua and Ruf terms test (29)",
            "PTV-DNS-DMARC-REPORT-URIS-VALID", "DMARC reporting URIs are valid", "MEDIUM",
            "Checks the syntax of rua and ruf reporting destination URIs when present.")

    def _analyze_fo_term(self, domain, raw_output, source_client, cache):
        return self._result_from_response(domain, raw_output, source_client, cache,
            "Fo term test (30)",
            "PTV-DNS-DMARC-FO-VALID", "DMARC failure reporting option is valid", "LOW",
            "Checks the optional fo tag and verifies that its value follows the supported DMARC failure-reporting syntax.")