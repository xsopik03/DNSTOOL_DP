from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ..config import IntoDnsAiConfig
from ..models.dns_records import (
    ARecord,
    AAAARecord,
    CNAMERecord,
    DnsData,
    MXRecord,
    NSRecord,
    TXTRecord,
)
from ..util.http_client import HttpClient
from .base_source import BaseSource

logger = logging.getLogger(__name__)


class IntoDnsAiSource(BaseSource):
    def __init__(self, config: IntoDnsAiConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.http = HttpClient(timeout=config.request_timeout)

    def fetch_dns_data(self, domain: str) -> Tuple[DnsData, Dict[str, Any]]:
        logger.info("IntoDnsAiSource: fetching report for %s", domain)

        report = self._get_everything_report(domain)
        record_map = self._extract_record_map(report)

        dns_data = DnsData(
            domain=domain,
            a_records=self._map_a(domain, record_map.get("A", [])),
            aaaa_records=self._map_aaaa(domain, record_map.get("AAAA", [])),
            cname_records=self._map_cname(domain, record_map.get("CNAME", [])),
            mx_records=self._map_mx(domain, record_map.get("MX", [])),
            ns_records=self._map_ns(domain, record_map.get("NS", [])),
            txt_records=self._map_txt(domain, record_map.get("TXT", [])),
            spf_records=[],
            dmarc_records=[],
            dkim_records=[],
            ds_records=[],
            dnskey_records=[],
            svcb_records=[],
            https_records=[],
        )

        raw_result: Dict[str, Any] = {
            "source": "intodns_ai",
            "endpoint": "/report/everything",
            "status": "ok",
            "domain": domain,
            "report": report,
            "records": record_map,
            "summary": self._summarize_report(report),
        }

        logger.info(
            "IntoDnsAiSource: %s -> A=%d, AAAA=%d, MX=%d, NS=%d, TXT=%d, CNAME=%d",
            domain,
            len(dns_data.a_records),
            len(dns_data.aaaa_records),
            len(dns_data.mx_records),
            len(dns_data.ns_records),
            len(dns_data.txt_records),
            len(dns_data.cname_records),
        )

        return dns_data, raw_result

    def _get_everything_report(self, domain: str) -> Dict[str, Any]:
        url = f"{self.base_url}/report/everything"
        params = {
            "domain": domain,
            "format": "json",
        }
        headers = {
            "Accept": "application/json",
        }

        try:
            resp = self.http.get(url, params=params, headers=headers)
            payload = resp.json()
        except Exception as exc:
            logger.warning("IntoDnsAiSource: report fetch failed for %s: %s", domain, exc)
            raise

        if not isinstance(payload, dict):
            raise RuntimeError(f"IntoDNS.ai report returned unexpected payload type: {type(payload).__name__}")

        return payload

    def _extract_record_map(self, report: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        record_map: Dict[str, List[Dict[str, Any]]] = {key: [] for key in ("A", "AAAA", "CNAME", "MX", "NS", "TXT")}
        containers = self._candidate_record_containers(report)

        for container in containers:
            for record_type in record_map.keys():
                if record_map[record_type]:
                    continue
                items = self._coerce_record_items(container, record_type)
                if items:
                    record_map[record_type] = items

        return record_map

    def _candidate_record_containers(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []

        for path in (
            ("sections", "dns", "records"),
            ("machineReadable", "dns", "records"),
            ("evidence", "dns", "records"),
            ("dns", "records"),
            ("records",),
            ("sections", "records"),
            ("machineReadable", "records"),
        ):
            container = self._walk_path(report, path)
            if isinstance(container, dict):
                candidates.append(container)

        candidates.extend(self._discover_record_containers(report))

        unique: List[Dict[str, Any]] = []
        seen: set[int] = set()
        for container in candidates:
            container_id = id(container)
            if container_id in seen:
                continue
            seen.add(container_id)
            unique.append(container)

        return unique

    def _discover_record_containers(self, value: Any) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []

        if not isinstance(value, dict):
            return found

        record_type_keys = {"a", "aaaa", "cname", "mx", "ns", "txt"}
        lower_keys = {str(key).lower() for key in value.keys()}
        if lower_keys.intersection(record_type_keys) and any(isinstance(item, (list, dict, str)) for item in value.values()):
            found.append(value)

        for item in value.values():
            if isinstance(item, dict):
                found.extend(self._discover_record_containers(item))

        return found

    @staticmethod
    def _walk_path(value: Any, path: tuple[str, ...]) -> Any:
        current = value
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    @staticmethod
    def _coerce_record_items(container: Dict[str, Any], record_type: str) -> List[Dict[str, Any]]:
        for key in (record_type, record_type.lower()):
            value = container.get(key)
            if value is None:
                continue

            if isinstance(value, list):
                return [item if isinstance(item, dict) else {"value": item} for item in value]

            if isinstance(value, dict):
                nested = value.get("records")
                if isinstance(nested, list):
                    return [item if isinstance(item, dict) else {"value": item} for item in nested]

                if all(not isinstance(item, (list, dict)) for item in value.values()):
                    return [value]

            if isinstance(value, str):
                return [{"value": value}]

        return []

    @staticmethod
    def _first_value(record: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = record.get(key)
            if value not in (None, ""):
                return value
        return None

    @staticmethod
    def _name_for_record(record: Dict[str, Any], fallback: str) -> str:
        value = IntoDnsAiSource._first_value(record, "name", "host", "hostname", "domain")
        return str(value or fallback)

    @staticmethod
    def _ttl_for_record(record: Dict[str, Any]) -> Optional[int]:
        ttl = IntoDnsAiSource._first_value(record, "ttl", "TTL")
        if ttl is None:
            return None
        try:
            return int(ttl)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _string_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value).strip()

    @staticmethod
    def _parse_mx_value(record: Dict[str, Any]) -> tuple[int, str]:
        preference_value = IntoDnsAiSource._first_value(record, "preference", "priority", "Pref", "level")
        exchange_value = IntoDnsAiSource._first_value(record, "exchange", "target", "host", "value", "data")

        if isinstance(exchange_value, str):
            match = re.match(r"^(\d+)\s+(.+)$", exchange_value.strip())
            if match and preference_value is None:
                preference_value = match.group(1)
                exchange_value = match.group(2)

        try:
            preference = int(preference_value) if preference_value is not None else 10
        except (TypeError, ValueError):
            preference = 10

        exchange = IntoDnsAiSource._string_value(exchange_value)
        if exchange == ".":
            return preference, exchange
        return preference, exchange.rstrip(".")

    def _map_a(self, fallback: str, records: List[Dict[str, Any]]) -> List[ARecord]:
        mapped: List[ARecord] = []
        for record in records:
            value = self._first_value(record, "value", "data", "address", "ip")
            if not value:
                continue
            mapped.append(ARecord(name=self._name_for_record(record, fallback), address=self._string_value(value), ttl=self._ttl_for_record(record)))
        return mapped

    def _map_aaaa(self, fallback: str, records: List[Dict[str, Any]]) -> List[AAAARecord]:
        mapped: List[AAAARecord] = []
        for record in records:
            value = self._first_value(record, "value", "data", "address", "ip", "ipv6")
            if not value:
                continue
            mapped.append(AAAARecord(name=self._name_for_record(record, fallback), address=self._string_value(value), ttl=self._ttl_for_record(record)))
        return mapped

    def _map_cname(self, fallback: str, records: List[Dict[str, Any]]) -> List[CNAMERecord]:
        mapped: List[CNAMERecord] = []
        for record in records:
            value = self._first_value(record, "value", "data", "target", "cname")
            if not value:
                continue
            mapped.append(CNAMERecord(name=self._name_for_record(record, fallback), target=self._string_value(value).rstrip("."), ttl=self._ttl_for_record(record)))
        return mapped

    def _map_mx(self, fallback: str, records: List[Dict[str, Any]]) -> List[MXRecord]:
        mapped: List[MXRecord] = []
        for record in records:
            preference, exchange = self._parse_mx_value(record)
            if not exchange:
                continue
            mapped.append(MXRecord(name=self._name_for_record(record, fallback), exchange=exchange, preference=preference, ttl=self._ttl_for_record(record)))
        return mapped

    def _map_ns(self, fallback: str, records: List[Dict[str, Any]]) -> List[NSRecord]:
        mapped: List[NSRecord] = []
        for record in records:
            value = self._first_value(record, "value", "data", "host", "target", "ns")
            if not value:
                continue
            mapped.append(NSRecord(name=self._name_for_record(record, fallback), host=self._string_value(value).rstrip("."), ttl=self._ttl_for_record(record)))
        return mapped

    def _map_txt(self, fallback: str, records: List[Dict[str, Any]]) -> List[TXTRecord]:
        mapped: List[TXTRecord] = []
        for record in records:
            value = self._first_value(record, "text", "value", "data", "txt", "record")
            if value is None:
                continue

            if isinstance(value, list):
                text = "".join(self._string_value(item) for item in value)
            else:
                text = self._string_value(value)

            if not text:
                continue

            mapped.append(TXTRecord(name=self._name_for_record(record, fallback), text=text, ttl=self._ttl_for_record(record)))
        return mapped

    @staticmethod
    def _summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for key in ("domain", "timestamp", "generatedAt", "score", "maxScore", "percentage", "grade"):
            if key in report:
                summary[key] = report.get(key)
        if "gradeInfo" in report:
            summary["gradeInfo"] = report.get("gradeInfo")
        if "categories" in report:
            summary["categories"] = report.get("categories")
        if "issues" in report:
            issues = report.get("issues")
            summary["issueCount"] = len(issues) if isinstance(issues, list) else None
        if "recommendations" in report:
            recommendations = report.get("recommendations")
            summary["recommendationCount"] = len(recommendations) if isinstance(recommendations, list) else None
        return summary