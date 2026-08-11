import csv
import copy
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import IO, Any, Optional

from ptlibs.ptprinthelper import ptprint

from .analysis.record_analyzer import RecordAnalyzer
from .analysis.security_analyzer import SecurityAnalyzer
from .analysis.source_extractors import build_source_analyzers
from .check_normalization import CheckOutcome, is_actionable_outcome, local_issue_outcome_from_severity
from .config import AppConfig
from .models.checks import NormalizedCheckResult
from .models.dns_records import DnsData
from .sources.intodns_ai import IntoDnsAiSource
from .sources.intodns import IntoDnsSource
from .sources.mxtoolbox import MxToolboxSource
from .sources.zonemaster import ZonemasterSource
from .util.dns_enricher import enrich_dns_data

logger = logging.getLogger(__name__)

_SEVERITY_BULLET = {
    "ERROR": "VULN",
    "WARNING": "WARNING",
    "INFO": "INFO",
}


class Controller:
    def __init__(self, config: AppConfig, jsonlib, json_mode: bool = False) -> None:
        self.config = config
        self.jsonlib = jsonlib
        self.json_mode = json_mode
        self.sources = {
            "zonemaster": ZonemasterSource(config.zonemaster),
            "intodns": IntoDnsSource(config.intodns),
            "intodns_ai": IntoDnsAiSource(config.intodns_ai),
            "mxtoolbox": MxToolboxSource(config.mxtoolbox),
        }
        self.analyzers = [RecordAnalyzer(), SecurityAnalyzer()]
        self.source_analyzers = build_source_analyzers()

    def run_analysis(
        self,
        domain: str,
        source: Optional[str] = None,
        json_file: Optional[IO[str]] = None,
        csv_file: Optional[IO[str]] = None,
        debug_raw_output_file: Optional[IO[str]] = None,
    ) -> dict:

        source_label = source or "all"
        logger.info("Starting analysis for domain: %s using source: %s", domain, source_label)

        selected_sources, selection_error = self._resolve_selected_sources(source)
        dns_data = self._empty_dns_data(domain)
        analysis_dns_data = self._empty_dns_data(domain)
        source_dns_data: dict[str, DnsData] = {}
        source_raw_output: dict[str, dict] = {}
        source_status: dict[str, str] = {}
        source_errors: dict[str, str] = {}
        checks: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        fatal_error: Optional[str] = None

        if selection_error is not None:
            fatal_error = selection_error
            if not self.json_mode:
                logger.warning(fatal_error)
        else:
            fetch_started = time.perf_counter()
            self._log_stage(f"Fetching DNS data from {len(selected_sources)} source(s) asynchronously...")
            source_dns_data, source_raw_output, source_status, source_errors = self._fetch_sources_async(
                domain=domain,
                selected_sources=selected_sources,
            )
            self._log_stage(f"Fetch phase finished in {time.perf_counter() - fetch_started:.2f}s.")

            normalize_started = time.perf_counter()
            self._log_stage("Normalizing DNS records across selected sources...")
            dns_data, _, _ = self._merge_dns_sources(
                domain=domain,
                source_dns_data=source_dns_data,
                source_order=selected_sources,
            )
            self._log_stage(f"Normalization finished in {time.perf_counter() - normalize_started:.2f}s.")

            analysis_dns_data = copy.deepcopy(dns_data)
            enrich_started = time.perf_counter()
            self._log_stage("Running unified DNS enrichment...")
            try:
                analysis_dns_data = enrich_dns_data(analysis_dns_data)
                dns_data = copy.deepcopy(analysis_dns_data)
            except Exception as exc:
                if not self.json_mode:
                    logger.warning("DNS enrichment failed for %s in unified mode: %s", domain, exc)
                source_errors["enrichment"] = f"Unified enrichment failed: {exc}"
            self._log_stage(f"Enrichment phase finished in {time.perf_counter() - enrich_started:.2f}s.")

            if not source_dns_data:
                fatal_error = f"No source data fetched for {domain}."
            elif not any(status != "error" for status in source_status.values()):
                fatal_error = f"All selected sources failed for {domain}."

        if fatal_error is None:
            source_checks, _, _ = self._run_source_analyzers(
                domain=domain,
                source_raw_output=source_raw_output,
            )
            checks.extend(source_checks)

        self.jsonlib.add_properties(
            {
                "domain": domain,
                "source": source_label,
                "sourceMode": "all" if source is None else "single",
                "selectedSources": selected_sources,
                "dnsData": self._dns_data_to_dict(dns_data),
                "checks": checks,
            }
        )

        if debug_raw_output_file is not None:
            debug_payload = {
                "mode": "all" if source is None else "single",
                "selectedSources": selected_sources,
                "rawBySource": source_raw_output,
                "checks": checks,
            }
            json.dump(debug_payload, debug_raw_output_file, indent=2, ensure_ascii=False)
            debug_raw_output_file.write("\n")

        if fatal_error is None:
            self._print_records(dns_data)

            self._log_stage("Running analyzers on unified DNS data...")
            for analyzer in self.analyzers:
                try:
                    analyzer_issues = analyzer.analyze(analysis_dns_data)
                except Exception as exc:
                    fatal_error = f"{analyzer.__class__.__name__} failed for {domain}: {exc}"
                    if not self.json_mode:
                        logger.exception("Analyzer failed for %s", domain)
                    continue

                if not isinstance(analyzer_issues, list):
                    fatal_error = f"{analyzer.__class__.__name__} returned malformed issue data for {domain}"
                    if not self.json_mode:
                        logger.warning("Malformed analyzer output for %s: %r", domain, analyzer_issues)
                    continue

                for issue in analyzer_issues:
                    normalized_issue = self._normalize_issue(issue)
                    issues.append(normalized_issue)

            local_checks = [self._normalized_check_from_local_issue(item) for item in issues]
            checks.extend(local_checks)

            self._print_source_test_results(source_checks=checks)
        elif not self.json_mode:
            ptprint(f"Error: {fatal_error}", "ERROR", True, colortext=True, newline_above=True)

        self.jsonlib.add_properties({"checks": checks})
        self._add_discovered_domain_nodes(domain, dns_data)

        vulnerabilities = self._build_vulnerabilities_from_checks(checks)
        for vuln in vulnerabilities:
            self.jsonlib.add_vulnerability(
                vuln_code=vuln["vulnCode"],
                description=vuln.get("description"),
                severity=vuln.get("severity"),
                details=vuln.get("details", {}),
            )

        issues = [
            {
                "vuln_code": vuln["vulnCode"],
                "severity": vuln.get("severity"),
                "message": vuln.get("description"),
                "details": vuln.get("details", {}),
            }
            for vuln in vulnerabilities
        ]

        status = "error" if fatal_error else "finished"
        message = fatal_error or f"Analysis completed for {domain}"
        self.jsonlib.set_status(status)
        self.jsonlib.set_message(message)

        output = self.jsonlib.get_result_json()
        if json_file is not None:
            json_file.write(output)
            json_file.write("\n")
            json_file.flush()

        if csv_file is not None:
            self._write_csv(
                csv_file,
                domain=domain,
                source=source_label,
                dns_data=dns_data,
                issues=issues,
            )

        return {"status": status, "message": message, "issues": issues}

    def _fetch_sources_async(
        self,
        domain: str,
        selected_sources: list[str],
    ) -> tuple[dict[str, DnsData], dict[str, dict], dict[str, str], dict[str, str]]:
        source_dns_data: dict[str, DnsData] = {}
        source_raw_output: dict[str, dict] = {}
        source_status: dict[str, str] = {}
        source_errors: dict[str, str] = {}

        if not selected_sources:
            return source_dns_data, source_raw_output, source_status, source_errors

        max_workers = max(1, len(selected_sources))
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="dnstool-source") as executor:
            future_to_source = {}
            for source_name in selected_sources:
                self._log_stage(f"Starting fetch from source: {source_name}")
                future = executor.submit(
                    self._fetch_source_data,
                    domain,
                    source_name,
                    self.sources[source_name],
                )
                future_to_source[future] = source_name

            for future in as_completed(future_to_source):
                source_name = future_to_source[future]
                try:
                    fetched_dns_data, fetched_raw_output, source_error = future.result()
                except Exception as exc:
                    source_error = f"{source_name} source worker failed for {domain}: {exc}"
                    fetched_dns_data = self._empty_dns_data(domain)
                    fetched_raw_output = self._normalize_raw_output(
                        source_name,
                        {},
                        status="error",
                        message=source_error,
                    )
                    logger.exception("Unexpected worker failure for source %s", source_name)

                source_dns_data[source_name] = fetched_dns_data
                source_raw_output[source_name] = fetched_raw_output
                source_status[source_name] = str(fetched_raw_output.get("status", "ok"))
                if source_error is not None:
                    source_errors[source_name] = source_error

                self._log_stage(
                    f"Source {source_name} finished with status {source_status[source_name]}."
                )

        return source_dns_data, source_raw_output, source_status, source_errors

    def _log_stage(self, message: str) -> None:
        logger.info(message)
        if not self.json_mode:
            ptprint(message, "INFO", True, colortext=True)

    def _run_source_analyzers(
        self,
        domain: str,
        source_raw_output: dict[str, dict],
    ) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, list[str]]]:
        checks: list[dict[str, Any]] = []
        recognized: dict[str, list[str]] = {}
        unknown: dict[str, list[str]] = {}

        for source_name, raw_output in source_raw_output.items():
            analyzer = self.source_analyzers.get(source_name)
            if analyzer is None or not isinstance(raw_output, dict):
                continue

            source_checks, recognized_ids, unknown_ids = analyzer.analyze(
                domain=domain,
                raw_output=raw_output,
                source_client=self.sources.get(source_name),
            )
            checks.extend(source_checks)
            if recognized_ids:
                recognized[source_name] = recognized_ids
            if unknown_ids:
                unknown[source_name] = unknown_ids

        return checks, recognized, unknown

    def _resolve_selected_sources(self, source: Optional[str]) -> tuple[list[str], Optional[str]]:
        if source is None:
            return list(self.sources.keys()), None
        if source not in self.sources:
            return [], f"Unknown source: {source}"
        return [source], None

    def _fetch_source_data(self, domain: str, source_name: str, source_impl) -> tuple[DnsData, dict, Optional[str]]:
        try:
            fetched_dns_data, fetched_raw_output = source_impl.fetch_dns_data(domain)
        except Exception as exc:
            message = f"{source_name} source failed for {domain}: {exc}"
            raw_output = self._normalize_raw_output(source_name, {}, status="error", message=message)
            if not self.json_mode:
                logger.exception("Source fetch failed for %s using %s", domain, source_name)
            return self._empty_dns_data(domain), raw_output, message

        raw_output = self._normalize_raw_output(source_name, fetched_raw_output)
        if isinstance(fetched_dns_data, DnsData):
            return fetched_dns_data, raw_output, None

        message = f"{source_name} source returned malformed DNS data for {domain}"
        raw_output = self._normalize_raw_output(source_name, raw_output, status="error", message=message)
        if not self.json_mode:
            logger.warning("Malformed DNS data returned by %s for %s: %r", source_name, domain, fetched_dns_data)
        return self._empty_dns_data(domain), raw_output, message

    @staticmethod
    def _empty_dns_data(domain: str) -> DnsData:
        return DnsData(
            domain=domain,
            a_records=[],
            aaaa_records=[],
            cname_records=[],
            mx_records=[],
            ns_records=[],
            txt_records=[],
            spf_records=[],
            dmarc_records=[],
            dkim_records=[],
            ds_records=[],
            dnskey_records=[],
            svcb_records=[],
            https_records=[],
        )

    @staticmethod
    def _normalize_raw_output(source: str, raw_output: Any, status: Optional[str] = None, message: Optional[str] = None) -> dict:
        if isinstance(raw_output, dict):
            normalized = dict(raw_output)
        else:
            normalized = {
                "source": source,
                "type": type(raw_output).__name__,
                "records": {},
            }

        normalized.setdefault("source", source)
        normalized.setdefault("records", {})
        normalized["status"] = status or str(normalized.get("status") or "ok")
        if message is not None:
            normalized["message"] = message
        return normalized

    def _merge_dns_sources(
        self,
        domain: str,
        source_dns_data: dict[str, DnsData],
        source_order: list[str],
    ) -> tuple[DnsData, dict[str, list[dict]], dict[str, list[dict]]]:
        merged_specs = [
            ("A", "a_records", lambda r: self._norm_name(r.name), lambda r: self._norm_addr(r.address), lambda r: r.address, "address"),
            ("AAAA", "aaaa_records", lambda r: self._norm_name(r.name), lambda r: self._norm_addr(r.address), lambda r: r.address, "address"),
            ("CNAME", "cname_records", lambda r: self._norm_name(r.name), lambda r: self._norm_host(r.target), lambda r: r.target, "target"),
            ("MX", "mx_records", lambda r: (self._norm_name(r.name), int(r.preference)), lambda r: self._norm_host(r.exchange), lambda r: f"{int(r.preference)} {r.exchange}", "exchange"),
            ("NS", "ns_records", lambda r: self._norm_name(r.name), lambda r: self._norm_host(r.host), lambda r: r.host, "host"),
            ("TXT", "txt_records", lambda r: self._norm_name(r.name), lambda r: str(r.text), lambda r: r.text, "text"),
        ]

        contributions: dict[str, list[dict]] = {}
        unified = self._empty_dns_data(domain)

        for record_type, attr_name, slot_key_fn, value_key_fn, value_display_fn, _value_attr in merged_specs:
            merged_map: dict[tuple, dict] = {}

            for source_name in source_order:
                dns_data = source_dns_data.get(source_name)
                if dns_data is None:
                    continue
                records = getattr(dns_data, attr_name, [])
                for record in records:
                    slot_key = slot_key_fn(record)
                    value_key = value_key_fn(record)
                    row_key = (slot_key, value_key)

                    existing = merged_map.get(row_key)
                    if existing is None:
                        merged_map[row_key] = {
                            "record": record,
                            "sources": {source_name},
                            "ttl": getattr(record, "ttl", None),
                            "slotKey": slot_key,
                            "valueKey": value_key,
                        }
                    else:
                        existing["sources"].add(source_name)
                        if existing["ttl"] is None and getattr(record, "ttl", None) is not None:
                            existing["ttl"] = getattr(record, "ttl", None)

            merged_entries = list(merged_map.values())
            merged_entries.sort(key=lambda item: (str(item["slotKey"]), str(item["valueKey"])))

            record_list = []
            contribution_rows: list[dict] = []
            for entry in merged_entries:
                record = copy.deepcopy(entry["record"])
                if hasattr(record, "ttl"):
                    setattr(record, "ttl", entry["ttl"])
                record_list.append(record)

                contribution_rows.append(
                    {
                        "name": getattr(record, "name", ""),
                        "value": value_display_fn(record),
                        "ttl": getattr(record, "ttl", None),
                        "sources": sorted(list(entry["sources"])),
                    }
                )

            setattr(unified, attr_name, record_list)
            contributions[record_type] = contribution_rows

        return unified, contributions, {}

    @staticmethod
    def _norm_name(value: Any) -> str:
        return str(value or "").strip().lower().rstrip(".")

    @staticmethod
    def _norm_host(value: Any) -> str:
        return str(value or "").strip().lower().rstrip(".")

    @staticmethod
    def _norm_addr(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _normalize_issue(issue: Any) -> dict:
        if not isinstance(issue, dict):
            return {
                "vuln_code": "PTV-DNS-GEN-ERR",
                "severity": "WARNING",
                "message": f"Unexpected analyzer output: {issue!r}",
                "details": {},
            }

        details = issue.get("details", {})
        if not isinstance(details, dict):
            details = {"value": details}

        return {
            "vuln_code": issue.get("vuln_code") or "PTV-DNS-GEN-ERR",
            "severity": issue.get("severity") or "WARNING",
            "message": issue.get("message") or "Unexpected analyzer output.",
            "details": details,
        }

    @staticmethod
    def _dns_data_to_dict(dns_data):
        return {
            "domain": dns_data.domain,
            "a_records": [vars(record) for record in dns_data.a_records],
            "aaaa_records": [vars(record) for record in dns_data.aaaa_records],
            "cname_records": [vars(record) for record in dns_data.cname_records],
            "mx_records": [vars(record) for record in dns_data.mx_records],
            "ns_records": [vars(record) for record in dns_data.ns_records],
            "txt_records": [vars(record) for record in dns_data.txt_records],
            "spf_records": [vars(record) for record in dns_data.spf_records],
            "dmarc_records": [vars(record) for record in dns_data.dmarc_records],
            "dkim_records": [vars(record) for record in dns_data.dkim_records],
            "ds_records": [vars(record) for record in dns_data.ds_records],
            "dnskey_records": [vars(record) for record in dns_data.dnskey_records],
            "svcb_records": [vars(record) for record in dns_data.svcb_records],
            "https_records": [vars(record) for record in dns_data.https_records],
        }

    def _print_records(self, dns_data) -> None:
        human = not self.json_mode

        def _section(title, records, fmt):
            ptprint(f"{title}:", "TITLE", human, colortext=True, newline_above=True)
            if records:
                for rec in records:
                    ptprint(fmt(rec), "TEXT", human, indent=4)
            else:
                ptprint("(none)", "TEXT", human, indent=4)

        _section("A Records",    dns_data.a_records,    lambda r: r.address)
        _section("AAAA Records", dns_data.aaaa_records, lambda r: r.address)
        _section("NS Records",   dns_data.ns_records,   lambda r: r.host)
        _section("MX Records",   dns_data.mx_records,   lambda r: f"{r.preference} {r.exchange}")
        _section("TXT Records",  dns_data.txt_records,  lambda r: r.text)
        _section("CNAME Records",dns_data.cname_records,lambda r: f"{r.name} -> {r.target}")
        _section("SPF Records",  dns_data.spf_records,  lambda r: r.text)
        _section("DMARC Records",dns_data.dmarc_records,lambda r: r.text)
        _section("DKIM Records", dns_data.dkim_records, lambda r: f"{r.selector}: {r.text}")
        _section("DS Records",   dns_data.ds_records,   lambda r: f"{r.key_tag} {r.algorithm} {r.digest_type} {r.digest}")
        _section("DNSKEY Records", dns_data.dnskey_records, lambda r: f"{r.flags} {r.protocol} {r.algorithm}")
        _section("SVCB Records", dns_data.svcb_records, lambda r: f"{r.priority} {r.target} {r.params}")
        _section("HTTPS Records", dns_data.https_records, lambda r: f"{r.priority} {r.target} {r.params}")

    def _print_source_test_results(
        self,
        *,
        source_checks: list[dict[str, Any]],
    ) -> None:
        human = not self.json_mode
        passed = [item for item in source_checks if item.get("outcome") == CheckOutcome.PASS.value]
        not_applicable = [item for item in source_checks if item.get("outcome") == CheckOutcome.NOT_APPLICABLE.value]
        actionable = [item for item in source_checks if item.get("outcome") in {CheckOutcome.WARNING.value, CheckOutcome.FAIL.value}]

        if passed:
            ptprint("Passed checks:", "TITLE", human, colortext=True, newline_above=True)
            for item in passed:
                ptprint(item.get("name", ""), "OK", human, indent=4)

        if not_applicable:
            ptprint("Not applicable checks:", "TITLE", human, colortext=True, newline_above=True)
            for item in not_applicable:
                ptprint(item.get("name", ""), "INFO", human, indent=4)

        if actionable:
            ptprint("Issues found:", "TITLE", human, colortext=True, newline_above=True)
            for issue in actionable:
                bullet = _SEVERITY_BULLET.get(str(issue.get("severity") or "").upper(), "INFO")
                is_external = str(issue.get("source") or "").strip().lower() != "local"
                text = (issue.get("catalogInfo") if is_external else None) or issue.get("message") or issue.get("name") or ""
                ptprint(text, bullet, human, indent=4)

    def _normalized_check_from_local_issue(self, issue: dict[str, Any]) -> dict[str, Any]:
        details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
        source_id = str(details.get("legacy_vuln_code") or issue.get("vuln_code") or "").strip() or None
        catalog_info = details.get("catalogInfo")
        outcome = local_issue_outcome_from_severity(issue.get("severity"))
        check = NormalizedCheckResult(
            test_code=str(issue.get("vuln_code") or "PTV-DNS-GEN-ERR"),
            name=str(issue.get("message") or "Unexpected analyzer output."),
            severity=str(issue.get("severity") or "WARNING"),
            outcome=outcome,
            source="local",
            source_id=source_id,
            provider_status=issue.get("severity"),
            message=str(issue.get("message") or "Unexpected analyzer output."),
            catalog_info=catalog_info,
            details={
                "evidenceSource": "local",
                "source": "local",
                "sourceId": source_id,
                **details,
            },
        )
        return check.to_dict()


    @staticmethod
    def _vulnerability_description_from_check(check: dict[str, Any]) -> str:
        message = str(check.get("message") or "").strip()
        if message:
            return message
        name = str(check.get("name") or "").strip()
        if name:
            return f"Check failed: {name}"
        return "DNS check reported an issue."

    def _build_vulnerabilities_from_checks(self, checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_code: dict[str, dict[str, Any]] = {}

        for check in checks:
            outcome = str(check.get("outcome") or "").strip().lower()
            if not is_actionable_outcome(outcome):
                continue

            vuln_code = str(check.get("testCode") or "").strip()
            if not vuln_code:
                continue

            evidence = {
                "test_code": check.get("testCode"),
                "outcome": check.get("outcome"),
                "severity": check.get("severity"),
                "source": check.get("source"),
                "source_id": check.get("sourceId"),
                "provider_status": check.get("providerStatus"),
                "message": check.get("message"),
                "details": check.get("details", {}),
            }

            item = by_code.get(vuln_code)
            if item is None:
                by_code[vuln_code] = {
                    "vulnCode": vuln_code,
                    "description": self._vulnerability_description_from_check(check),
                    "severity": check.get("severity"),
                    "details": {"sources": [evidence]},
                }
            else:
                item["details"]["sources"].append(evidence)

        return list(by_code.values())

    @staticmethod
    def _collect_discovered_domain_names(target_domain: str, dns_data: DnsData) -> list[str]:
        target = str(target_domain or "").strip().lower().rstrip(".")
        discovered: set[str] = set()

        def add_candidate(value: str) -> None:
            host = str(value or "").strip().lower().rstrip(".")
            if not host or host == target:
                return
            if not host.endswith(f".{target}"):
                return
            discovered.add(host)

        for record in dns_data.mx_records:
            add_candidate(getattr(record, "exchange", ""))
        for record in dns_data.cname_records:
            add_candidate(getattr(record, "target", ""))
        for record in dns_data.ns_records:
            add_candidate(getattr(record, "host", ""))

        return sorted(discovered)

    def _add_discovered_domain_nodes(self, target_domain: str, dns_data: DnsData) -> None:
        for hostname in self._collect_discovered_domain_names(target_domain, dns_data):
            node = self.jsonlib.create_node_object("domain", properties={"name": hostname})
            if isinstance(node, dict):
                self.jsonlib.add_node(node)

    @staticmethod
    def _write_csv(
        csv_file: IO[str],
        domain: str,
        source: str,
        dns_data,
        issues: list[dict],
    ) -> None:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "domain",
                "source",
                "row_type",
                "record_type",
                "name",
                "value",
                "ttl",
                "severity",
                "vuln_code",
                "message",
                "details",
            ],
        )
        writer.writeheader()

        def write_record_rows(record_type: str, records: list, value_attr: str) -> None:
            for record in records:
                writer.writerow(
                    {
                        "domain": domain,
                        "source": source,
                        "row_type": "record",
                        "record_type": record_type,
                        "name": getattr(record, "name", ""),
                        "value": getattr(record, value_attr, ""),
                        "ttl": getattr(record, "ttl", ""),
                        "severity": "",
                        "vuln_code": "",
                        "message": "",
                        "details": "",
                    }
                )

        write_record_rows("A", dns_data.a_records, "address")
        write_record_rows("AAAA", dns_data.aaaa_records, "address")
        write_record_rows("NS", dns_data.ns_records, "host")
        write_record_rows("TXT", dns_data.txt_records, "text")
        write_record_rows("CNAME", dns_data.cname_records, "target")
        write_record_rows("SPF", dns_data.spf_records, "text")
        write_record_rows("DMARC", dns_data.dmarc_records, "text")

        for record in dns_data.mx_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "MX",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.preference} {record.exchange}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for record in dns_data.dkim_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "DKIM",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.selector}: {record.text}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for record in dns_data.ds_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "DS",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.key_tag} {record.algorithm} {record.digest_type} {record.digest}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for record in dns_data.dnskey_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "DNSKEY",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.flags} {record.protocol} {record.algorithm}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for record in dns_data.svcb_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "SVCB",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.priority} {record.target} {record.params}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for record in dns_data.https_records:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "record",
                    "record_type": "HTTPS",
                    "name": getattr(record, "name", ""),
                    "value": f"{record.priority} {record.target} {record.params}",
                    "ttl": getattr(record, "ttl", ""),
                    "severity": "",
                    "vuln_code": "",
                    "message": "",
                    "details": "",
                }
            )

        for issue in issues:
            writer.writerow(
                {
                    "domain": domain,
                    "source": source,
                    "row_type": "issue",
                    "record_type": "",
                    "name": "",
                    "value": "",
                    "ttl": "",
                    "severity": issue.get("severity", ""),
                    "vuln_code": issue.get("vuln_code", ""),
                    "message": issue.get("message", ""),
                    "details": json.dumps(issue.get("details", {}), ensure_ascii=False),
                }
            )

        csv_file.flush()
