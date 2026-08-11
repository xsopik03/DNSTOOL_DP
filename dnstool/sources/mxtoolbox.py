from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

import requests

from ..config import MxToolboxConfig
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


class MxToolboxSource(BaseSource):
    def __init__(self, config: MxToolboxConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.http = HttpClient(timeout=config.request_timeout)

    def fetch_dns_data(self, domain: str) -> Tuple[DnsData, Dict[str, Any]]:
        if not self.config.api_key:
            logger.info("MXToolbox API key is not configured, returning empty source payload for %s", domain)
            return self._empty_dns_data(domain), {
                "source": "mxtoolbox",
                "status": "skipped",
                "reason": "MXTOOLBOX_API_KEY not set",
                "records": {},
            }

        headers = {
            "Authorization": self.config.api_key,
            "Accept": "application/json",
        }

        raw_records: Dict[str, Any] = {}
        for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
            raw_records[rtype] = self._query_records(domain, rtype, headers)

        dns_data = DnsData(
            domain=domain,
            a_records=self._map_a(raw_records.get("A", []), domain),
            aaaa_records=self._map_aaaa(raw_records.get("AAAA", []), domain),
            cname_records=self._map_cname(raw_records.get("CNAME", []), domain),
            mx_records=self._map_mx(raw_records.get("MX", []), domain),
            ns_records=self._map_ns(raw_records.get("NS", []), domain),
            txt_records=self._map_txt(raw_records.get("TXT", []), domain),
            spf_records=[],
            dmarc_records=[],
            dkim_records=[],
            ds_records=[],
            dnskey_records=[],
            svcb_records=[],
            https_records=[],
        )

        return dns_data, {
            "source": "mxtoolbox",
            "status": "ok",
            "records": raw_records,
        }

    def query_dns_diagnostics(self, domain: str) -> Dict[str, Any]:
        if not self.config.api_key:
            return {}

        headers = {
            "Authorization": self.config.api_key,
            "Accept": "application/json",
        }
        commands = ("dns", "spf", "dmarc")
        merged = {"Passed": [], "Warnings": [], "Failed": []}
        seen_ids_by_bucket: dict[str, set[str]] = {"Passed": set(), "Warnings": set(), "Failed": set()}

        for command in commands:
            payload = self._query_diagnostics_command(domain, command, headers)
            if not isinstance(payload, dict):
                continue
            for bucket in ("Passed", "Warnings", "Failed"):
                items = payload.get(bucket)
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    source_id = str(item.get("ID") or "").strip()
                    if source_id and source_id in seen_ids_by_bucket[bucket]:
                        continue
                    if source_id:
                        seen_ids_by_bucket[bucket].add(source_id)
                    merged[bucket].append(item)

        if any(merged[bucket] for bucket in ("Passed", "Warnings", "Failed")):
            return merged
        return {}

    def _query_diagnostics_command(self, domain: str, command: str, headers: Dict[str, str]) -> Dict[str, Any]:
        command = command.lower().strip()
        if not command:
            return {}

        candidates = [
            (f"{self.base_url}/Lookup/{command}/", {"argument": domain}),
            (f"https://mxtoolbox.com/api/v1/lookup/{command}/{domain}", None),
        ]

        for url, params in candidates:
            try:
                response = self.http.get(url, headers=headers, params=params)
                payload = response.json()
            except requests.HTTPError as exc:
                logger.warning("MXToolbox %s diagnostics failed for %s at %s: %s", command, domain, url, exc)
                continue
            except Exception as exc:
                logger.warning("MXToolbox %s diagnostics failed for %s at %s: %s", command, domain, url, exc)
                continue

            if isinstance(payload, dict) and any(key in payload for key in ("Passed", "Warnings", "Failed")):
                return payload

        return {}

    def _query_records(self, domain: str, rtype: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        command_map = {
            "A": "a",
            "AAAA": "aaaa",
            "NS": "ns",
            "MX": "mx",
            "TXT": "txt",
            "CNAME": "cname",
        }
        command = command_map.get(rtype, rtype.lower())
        url = f"{self.base_url}/Lookup/{command}/"
        try:
            response = self.http.get(url, headers=headers, params={"argument": domain})
            payload = response.json()
        except requests.HTTPError as exc:
            response = exc.response
            body = ""
            if response is not None:
                try:
                    body = response.text[:500]
                except Exception:
                    body = "<unavailable>"
            logger.warning(
                "MXToolbox query failed for %s %s: %s%s",
                domain,
                rtype,
                exc,
                f" response_body={body}" if body else "",
            )
            return []
        except Exception as exc:
            logger.warning("MXToolbox query failed for %s %s: %s", domain, rtype, exc)
            return []

        if not isinstance(payload, dict):
            logger.warning("MXToolbox query returned non-object payload for %s %s", domain, rtype)
            return []

        records = payload.get("Information") or payload.get("Records") or payload.get("records")
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]

        if isinstance(records, dict):
            return [records]

        return []

    @staticmethod
    def _extract_name(record: Dict[str, Any], fallback: str) -> str:
        return str(record.get("Name") or record.get("Host") or record.get("name") or fallback)

    @staticmethod
    def _extract_first(record: Dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = record.get(key)
            if value not in (None, ""):
                return value
        return None

    @staticmethod
    def _extract_ttl(record: Dict[str, Any]):
        ttl = record.get("TTL") or record.get("ttl")
        try:
            if ttl is None:
                return None
            if isinstance(ttl, (int, float)):
                return int(ttl)
            ttl_text = str(ttl).strip().lower()
            if ttl_text.isdigit():
                return int(ttl_text)
            match = re.match(r"^(\d+)\s*(sec|secs|second|seconds|min|mins|minute|minutes|hr|hrs|hour|hours|day|days)$", ttl_text)
            if not match:
                return None
            amount = int(match.group(1))
            unit = match.group(2)
            if unit.startswith("sec"):
                return amount
            if unit.startswith("min"):
                return amount * 60
            if unit.startswith("hr") or unit.startswith("hour"):
                return amount * 3600
            if unit.startswith("day"):
                return amount * 86400
            return None
        except (TypeError, ValueError):
            return None

    def _map_a(self, records: List[Dict[str, Any]], fallback: str) -> List[ARecord]:
        mapped: List[ARecord] = []
        for record in records:
            value = self._extract_first(record, "IP Address", "Address", "Data", "value")
            if not value:
                continue
            mapped.append(
                ARecord(
                    name=self._extract_name(record, fallback),
                    address=str(value),
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

    def _map_aaaa(self, records: List[Dict[str, Any]], fallback: str) -> List[AAAARecord]:
        mapped: List[AAAARecord] = []
        for record in records:
            value = self._extract_first(record, "IPv6 Address", "IP Address", "Address", "Data", "value")
            if not value:
                continue
            mapped.append(
                AAAARecord(
                    name=self._extract_name(record, fallback),
                    address=str(value),
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

    def _map_ns(self, records: List[Dict[str, Any]], fallback: str) -> List[NSRecord]:
        mapped: List[NSRecord] = []
        for record in records:
            value = self._extract_first(record, "Domain Name", "Name Server", "Host", "Target", "Data", "value")
            if not value:
                continue
            mapped.append(
                NSRecord(
                    name=self._extract_name(record, fallback),
                    host=str(value),
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

    def _map_mx(self, records: List[Dict[str, Any]], fallback: str) -> List[MXRecord]:
        mapped: List[MXRecord] = []
        for record in records:
            exchange = self._extract_first(record, "Hostname", "Mail Server", "Exchange", "Data", "value")
            if not exchange:
                continue
            preference = self._extract_first(record, "Pref", "Preference", "Preference Value", "PreferenceNumber") or 10
            try:
                pref_int = int(preference)
            except (TypeError, ValueError):
                pref_int = 10
            mapped.append(
                MXRecord(
                    name=self._extract_name(record, fallback),
                    exchange=str(exchange),
                    preference=pref_int,
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

    def _map_txt(self, records: List[Dict[str, Any]], fallback: str) -> List[TXTRecord]:
        mapped: List[TXTRecord] = []
        for record in records:
            value = self._extract_first(record, "Record", "Text", "Data", "value")
            if value is None:
                continue
            mapped.append(
                TXTRecord(
                    name=self._extract_name(record, fallback),
                    text=str(value),
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

    def _map_cname(self, records: List[Dict[str, Any]], fallback: str) -> List[CNAMERecord]:
        mapped: List[CNAMERecord] = []
        for record in records:
            value = self._extract_first(record, "Canonical Name", "Domain Name", "Hostname", "Target", "Data", "value")
            if not value:
                continue
            mapped.append(
                CNAMERecord(
                    name=self._extract_name(record, fallback),
                    target=str(value),
                    ttl=self._extract_ttl(record),
                )
            )
        return mapped

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
