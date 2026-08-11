from __future__ import annotations

from typing import Any

from .base import BaseSourceAnalyzer


class MxToolboxSourceAnalyzer(BaseSourceAnalyzer):
    source_name = "mxtoolbox"

    def analyze(self, domain: str, raw_output: dict[str, Any], source_client: Any = None) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        if source_client is None:
            return [], [], []

        diagnostics = source_client.query_dns_diagnostics(domain)
        items = self._items_by_id(diagnostics)
        results = [
            result
            for result in (
                self._analyze_301(items),
                self._analyze_303(items),
                self._analyze_300(items),
                self._analyze_371(items),
                self._analyze_506(items),
                self._analyze_312(items),
                self._analyze_314(items),
                self._analyze_437(items),
                self._analyze_439(items),
                self._analyze_511(items),
                self._analyze_477(items),
                self._analyze_504(items),
                self._analyze_420(items),
                self._analyze_418(items),
            )
            if result is not None
        ]
        recognized = [str(r.get("sourceId") or "") for r in results if r.get("sourceId")]
        return results, recognized, []

    @staticmethod
    def _items_by_id(diagnostics: dict[str, Any]) -> dict[str, dict[str, Any]]:
        items_by_id: dict[str, dict[str, Any]] = {}
        if not isinstance(diagnostics, dict):
            return items_by_id
        for bucket_name, items in diagnostics.items():
            bucket = str(bucket_name or "").strip().lower()
            if bucket not in {"passed", "warnings", "warning", "failed", "timeouts", "timeout"}:
                continue
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                source_id = str(item.get("ID") or "").strip()
                if source_id:
                    enriched = dict(item)
                    if bucket == "warning":
                        bucket = "warnings"
                    if bucket == "timeout":
                        bucket = "timeouts"
                    enriched["_bucket"] = bucket
                    items_by_id[source_id] = enriched
        return items_by_id

    def _result_from_item(self, items: dict[str, dict[str, Any]], source_id: str, test_code: str, name: str, severity: str, info: str = ""):
        item = items.get(source_id)
        if item is None:
            return None
        bucket = str(item.get("_bucket") or "").strip().lower()
        return self._build_result(test_code, name, severity, info, source_id, bucket, item.get("Name"), item.get("Info"))

    def _analyze_301(self, items):
        return self._result_from_item(items, "301",
            "PTV-DNS-NS-RESPONSIVE", "All authoritative name servers respond", "HIGH",
            "Checks that all configured authoritative name servers respond to DNS queries.")

    def _analyze_303(self, items):
        return self._result_from_item(items, "303",
            "PTV-DNS-NS-AUTHORITATIVE", "Name servers are authoritative", "CRITICAL",
            "Checks that configured name servers answer authoritatively for the tested zone.")

    def _analyze_300(self, items):
        return self._result_from_item(items, "300",
            "PTV-DNS-NS-PARENT-CHILD-CONSISTENT", "Parent and child NS sets are consistent", "HIGH",
            "Checks that NS records at the parent delegation correspond to the NS records published by the child zone.")

    def _analyze_371(self, items):
        return self._result_from_item(items, "371",
            "PTV-DNS-NS-NO-OPEN-RECURSION", "Authoritative servers are not open resolvers", "HIGH",
            "Checks that authoritative name servers do not provide unrestricted recursive resolution.")

    def _analyze_506(self, items):
        return self._result_from_item(items, "506",
            "PTV-DNS-DOMAIN-RESOLVES", "Domain resolves successfully", "CRITICAL",
            "Checks that the tested domain returns a usable DNS response and is not completely unresolvable.")

    def _analyze_312(self, items):
        return self._result_from_item(items, "312",
            "PTV-DNS-NS-PUBLIC-IP", "Name servers use publicly reachable addresses", "HIGH",
            "Checks that authoritative name servers are not configured with private or otherwise non-public IP addresses.")

    def _analyze_314(self, items):
        return self._result_from_item(items, "314",
            "PTV-DNS-SOA-MNAME-IN-PARENT", "SOA primary server is represented in parent delegation", "MEDIUM",
            "Checks whether the primary server named in SOA is also represented appropriately in the parent-side delegation.")

    def _analyze_437(self, items):
        return self._result_from_item(items, "437",
            "PTV-DNS-SPF-NO-RECURSIVE-LOOP", "SPF has no recursive include loop", "HIGH",
            "Checks whether include/redirect processing creates a recursive SPF dependency loop.")

    def _analyze_439(self, items):
        return self._result_from_item(items, "439",
            "PTV-DNS-SPF-NO-DUPLICATE-INCLUDE", "SPF has no duplicate include", "LOW",
            "Checks whether the same include target is unnecessarily repeated in the SPF policy.")

    def _analyze_511(self, items):
        return self._result_from_item(items, "511",
            "PTV-DNS-SPF-VOID-LOOKUPS-VALID", "SPF void lookup limit is respected", "HIGH",
            "Checks that SPF evaluation does not exceed the permitted number of DNS lookups returning no useful answer.")

    def _analyze_477(self, items):
        return self._result_from_item(items, "477",
            "PTV-DNS-SPF-ALL-POSITION-VALID", "No mechanisms occur after the all mechanism", "MEDIUM",
            "Checks for SPF terms placed after an all mechanism, where they would have no effective meaning.")

    def _analyze_504(self, items):
        return self._result_from_item(items, "504",
            "PTV-DNS-DMARC-EXTERNAL-REPORT-AUTH", "External DMARC report destinations are authorized", "MEDIUM",
            "Checks authorization when DMARC aggregate or failure reports are sent to an external domain.")

    def _analyze_420(self, items):
        return self._result_from_item(items, "420",
            "PTV-DNS-SPF-MX-LOOKUP-LIMIT", "SPF MX expansion limit is respected", "HIGH",
            "Checks that SPF evaluation through the mx mechanism does not expand to an excessive number of MX address records.")

    def _analyze_418(self, items):
        return self._result_from_item(items, "418",
            "PTV-DNS-SPF-NO-NULL-LOOKUPS", "SPF contains no null DNS lookup terms", "MEDIUM",
            "Checks for malformed SPF terms that cause invalid or empty DNS lookups.")