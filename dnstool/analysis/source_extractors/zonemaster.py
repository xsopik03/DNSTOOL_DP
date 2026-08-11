from __future__ import annotations

from typing import Any

from .base import BaseSourceAnalyzer


class ZonemasterSourceAnalyzer(BaseSourceAnalyzer):
    source_name = "zonemaster"

    def analyze(self, domain: str, raw_output: dict[str, Any], source_client: Any = None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        events = self._events_by_testcase(raw_output)
        results = [
            result
            for result in (
                self._analyze_delegation01(events),
                self._analyze_nameserver06(events),
                self._analyze_delegation05(events),
                self._analyze_nameserver03(events),
                self._analyze_consistency04(events),
                self._analyze_basic01(events),
                self._analyze_delegation07(events),
                self._analyze_delegation03(events),
                self._analyze_delegation02(events),
                self._analyze_consistency05(events),
                self._analyze_nameserver02(events),
                self._analyze_nameserver07(events),
                self._analyze_address03(events),
                self._analyze_nameserver04(events),
                self._analyze_zone10(events),
                self._analyze_zone07(events),
                self._analyze_syntax06(events),
                self._analyze_syntax08(events),
                self._analyze_dnssec10(events),
            )
            if result is not None
        ]
        recognized = [str(r.get("sourceId") or "") for r in results if r.get("sourceId")]
        return results, recognized, []

    @staticmethod
    def _events_by_testcase(raw_output: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
        results = raw_output.get("results") if isinstance(raw_output, dict) else None
        by_testcase: dict[str, list[dict[str, Any]]] = {}
        if not isinstance(results, list):
            return by_testcase
        for item in results:
            if not isinstance(item, dict):
                continue
            testcase = str(item.get("testcase") or "").strip()
            if testcase:
                by_testcase.setdefault(testcase, []).append(item)
        return by_testcase

    def _result_from_testcase(self, events: dict[str, list[dict[str, Any]]], source_id: str, test_code: str, name: str, severity: str, info: str = ""):
        matches = events.get(source_id, [])
        if not matches:
            return None
        first = matches[0]
        message = "\n".join(str(item.get("message") or "").strip() for item in matches if str(item.get("message") or "").strip())
        status = ", ".join(sorted({str(item.get("level") or "").strip() for item in matches if str(item.get("level") or "").strip()}))
        return self._build_result(test_code, name, severity, info, source_id, status, first.get("module"), message)

    def _analyze_delegation01(self, events):
        return self._result_from_testcase(events, "Delegation01",
            "PTV-DNS-NS-MIN-COUNT", "Sufficient number of authoritative name servers", "MEDIUM",
            "Checks that the zone has enough authoritative name servers for basic redundancy.")

    def _analyze_nameserver06(self, events):
        return self._result_from_testcase(events, "Nameserver06",
            "PTV-DNS-NS-RESOLVABLE", "Name server hostnames are resolvable", "HIGH",
            "Checks that every authoritative name server hostname resolves to an IP address.")

    def _analyze_delegation05(self, events):
        return self._result_from_testcase(events, "Delegation05",
            "PTV-DNS-NS-NO-CNAME", "NS targets are not CNAME aliases", "HIGH",
            "Checks that NS records point directly to hostnames and not to CNAME aliases.")

    def _analyze_nameserver03(self, events):
        return self._result_from_testcase(events, "Nameserver03",
            "PTV-DNS-NS-AXFR-DISABLED", "Unauthorized zone transfer is disabled", "HIGH",
            "Checks that an unrestricted AXFR zone transfer cannot be performed against authoritative name servers.")

    def _analyze_consistency04(self, events):
        return self._result_from_testcase(events, "Consistency04",
            "PTV-DNS-NS-SET-CONSISTENT", "NS set is consistent across authoritative servers", "HIGH",
            "Checks that authoritative servers return the same NS set for the zone.")

    def _analyze_basic01(self, events):
        return self._result_from_testcase(events, "Basic01",
            "PTV-DNS-PARENT-EXISTS", "Parent DNS zone exists", "HIGH",
            "Checks that the tested domain has a valid parent zone in the DNS hierarchy.")

    def _analyze_delegation07(self, events):
        return self._result_from_testcase(events, "Delegation07",
            "PTV-DNS-DELEGATION-GLUE-NAMES-IN-CHILD", "Parent glue names are present in child zone", "HIGH",
            "Checks that names referenced by parent-side glue are also represented consistently in the delegated child zone.")

    def _analyze_delegation03(self, events):
        return self._result_from_testcase(events, "Delegation03",
            "PTV-DNS-DELEGATION-REFERRAL-NOT-TRUNCATED", "Delegation referral is not truncated", "MEDIUM",
            "Checks that a referral response is small enough to be delivered correctly without problematic truncation.")

    def _analyze_delegation02(self, events):
        return self._result_from_testcase(events, "Delegation02",
            "PTV-DNS-NS-DISTINCT-IP", "Name servers use distinct IP addresses", "MEDIUM",
            "Checks that authoritative name servers do not all resolve to the same IP address, preserving basic redundancy.")

    def _analyze_consistency05(self, events):
        return self._result_from_testcase(events, "Consistency05",
            "PTV-DNS-NS-GLUE-CONSISTENT", "Glue and authoritative address data are consistent", "HIGH",
            "Checks that IP addresses provided as glue agree with address data returned by the authoritative zone.")

    def _analyze_nameserver02(self, events):
        return self._result_from_testcase(events, "Nameserver02",
            "PTV-DNS-NS-EDNS-SUPPORTED", "Authoritative servers support EDNS", "MEDIUM",
            "Checks whether authoritative name servers correctly support EDNS functionality used by modern DNS clients.")

    def _analyze_nameserver07(self, events):
        return self._result_from_testcase(events, "Nameserver07",
            "PTV-DNS-NS-NO-UPWARD-REFERRAL", "Authoritative servers do not return upward referrals", "HIGH",
            "Checks that an authoritative server does not incorrectly refer a client back toward a parent zone.")

    def _analyze_address03(self, events):
        return self._result_from_testcase(events, "Address03",
            "PTV-DNS-NS-FCRDNS", "Name server reverse DNS matches forward name", "LOW",
            "Checks forward-confirmed reverse DNS consistency for authoritative name server addresses.")

    def _analyze_nameserver04(self, events):
        return self._result_from_testcase(events, "Nameserver04",
            "PTV-DNS-NS-SOURCE-ADDRESS-CONSISTENT", "DNS response source address is consistent", "MEDIUM",
            "Checks that replies from an authoritative server originate from the expected address.")

    def _analyze_zone10(self, events):
        return self._result_from_testcase(events, "Zone10",
            "PTV-DNS-SOA-SINGLE-RECORD", "Only one SOA record is returned", "HIGH",
            "Checks that authoritative servers do not return multiple SOA records for the zone.")

    def _analyze_zone07(self, events):
        return self._result_from_testcase(events, "Zone07",
            "PTV-DNS-SOA-MNAME-NO-CNAME", "SOA MNAME is not a CNAME alias", "MEDIUM",
            "Checks that the primary server specified by SOA MNAME is a canonical hostname rather than an alias.")

    def _analyze_syntax06(self, events):
        return self._result_from_testcase(events, "Syntax06",
            "PTV-DNS-SOA-RNAME-SYNTAX-VALID", "SOA RNAME syntax is valid", "MEDIUM",
            "Checks that the responsible-person field in the SOA record uses valid DNS presentation syntax.")

    def _analyze_syntax08(self, events):
        return self._result_from_testcase(events, "Syntax08",
            "PTV-DNS-MX-NAME-SYNTAX-VALID", "MX target names are syntactically valid", "HIGH",
            "Checks that hostnames referenced by MX records have valid hostname syntax.")

    def _analyze_dnssec10(self, events):
        return self._result_from_testcase(events, "DNSSEC10",
            "PTV-DNS-DNSSEC-NSEC-PRESENT", "Signed zone publishes authenticated denial records", "HIGH",
            "Checks that a DNSSEC-signed zone contains NSEC or NSEC3 records required for authenticated denial of existence.")