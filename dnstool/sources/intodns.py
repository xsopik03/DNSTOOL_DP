from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

from ..config import IntoDnsConfig
from ..models.dns_records import (
    DnsData,
    ARecord,
    AAAARecord,
    MXRecord,
    NSRecord,
    TXTRecord,
    CNAMERecord,
)
from ..util.http_client import HttpClient
from .base_source import BaseSource

logger = logging.getLogger(__name__)


_INTODNS_TEST_SPECS = {
    "All authority hosts has the same SOA test (2)": {"type": "GENERAL", "test_name": "all-authority-hosts-has-same-soa"},
    "The term mname is real authority hosts test (9)": {"type": "SOA", "test_name": "mname-term-is-real-authority-host"},
    "Target hosts with resolvable IPs test (16)": {"type": "MX", "test_name": "target-hosts-with-resolvable-ips"},
    "Duplicated records test (17)": {"type": "MX", "test_name": "duplicated-records"},
    "No records points to CNAME test (18)": {"type": "MX", "test_name": "no-records-points-to-cname"},
    "Records hosts can send emails test (22)": {"type": "SPF", "test_name": "records-hosts-can-send-emails"},
    "Subdomain policy term test (27)": {"type": "DMARC", "test_name": "subdomain-policy-term"},
    "Rua and Ruf terms test (29)": {"type": "DMARC", "test_name": "rua-and-ruf-terms"},
    "Fo term test (30)": {"type": "DMARC", "test_name": "fo-term"},
}


class IntoDnsSource(BaseSource):

    def __init__(self, config: IntoDnsConfig) -> None:
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.http = HttpClient(timeout=config.request_timeout)

    def fetch_dns_data(self, domain: str) -> Tuple[DnsData, Dict[str, Any]]:
        logger.info("IntoDnsSource: fetching DNS data for %s", domain)

        authority_hosts = self._get_authority_hosts(domain)
        name_server = authority_hosts[0]["host"] if authority_hosts else None

        raw_records: Dict[str, List[Dict[str, Any]]] = {}

        for rtype in ["A", "AAAA", "NS", "MX", "TXT", "CNAME"]:
            raw_records[rtype] = self._get_records(domain, rtype, name_server=name_server)

        dns_data = DnsData(
            domain=domain,
            a_records=self._map_a(raw_records.get("A", [])),
            aaaa_records=self._map_aaaa(raw_records.get("AAAA", [])),
            mx_records=self._map_mx(raw_records.get("MX", [])),
            ns_records=self._map_ns(raw_records.get("NS", [])),
            txt_records=self._map_txt(raw_records.get("TXT", [])),
            cname_records=self._map_cname(raw_records.get("CNAME", [])),
            spf_records=[],
            dmarc_records=[],
            dkim_records=[],
            ds_records=[],
            dnskey_records=[],
            svcb_records=[],
            https_records=[],
        )

        raw_result: Dict[str, Any] = {
            "authority_hosts": authority_hosts,
            "records": raw_records,
        }

        logger.info(
            "IntoDnsSource: %s -> A=%d, AAAA=%d, MX=%d, NS=%d, TXT=%d, CNAME=%d",
            domain,
            len(dns_data.a_records),
            len(dns_data.aaaa_records),
            len(dns_data.mx_records),
            len(dns_data.ns_records),
            len(dns_data.txt_records),
            len(dns_data.cname_records),
        )

        return dns_data, raw_result

    def _get_authority_hosts(self, domain: str) -> List[Dict[str, Any]]:

        url = f"{self.base_url}/get-dns-hosts"
        params = {
            "host": domain,
            "wants-trace": 0,
        }
        headers = {
            "X-Accept-Language": self.config.language,
        }

        try:
            resp = self.http.get(url, params=params, headers=headers)
            data = resp.json()
        except Exception as exc:
            logger.warning("IntoDnsSource: get-dns-hosts failed for %s: %s", domain, exc)
            return []

        hosts = data.get("authority-hosts", [])
        if not isinstance(hosts, list):
            logger.warning("IntoDnsSource: authority-hosts not a list: %r", hosts)
            return []

        return hosts

    def _get_records(
        self,
        host: str,
        rtype: str,
        name_server: str | None = None,
    ) -> List[Dict[str, Any]]:

        url = f"{self.base_url}/get-dns-records"
        params: Dict[str, Any] = {
            "host": host,
            "type": rtype,
        }
        if name_server:
            params["name-server"] = name_server

        headers = {
            "X-Accept-Language": self.config.language,
        }

        try:
            resp = self.http.get(url, params=params, headers=headers)
            data = resp.json()
        except Exception as exc:
            logger.warning("IntoDnsSource: get-dns-records [%s] failed for %s: %s", rtype, host, exc)
            return []

        if not isinstance(data, list):
            logger.warning("IntoDnsSource: get-dns-records [%s] not a list: %r", rtype, data)
            return []

        return data

    def run_documented_test(self, domain: str, source_id: str, raw_output: Dict[str, Any]) -> Dict[str, Any] | None:
        spec = _INTODNS_TEST_SPECS.get(source_id)
        if spec is None:
            return None

        authority_hosts = raw_output.get("authority_hosts") if isinstance(raw_output, dict) else []
        raw_records = raw_output.get("records") if isinstance(raw_output, dict) else {}
        if not isinstance(authority_hosts, list):
            authority_hosts = []
        if not isinstance(raw_records, dict):
            raw_records = {}

        name_server = authority_hosts[0].get("host") if authority_hosts and isinstance(authority_hosts[0], dict) else None
        soa_records = self._get_records(domain, "SOA", name_server=name_server)
        mx_records = [record for record in raw_records.get("MX", []) if isinstance(record, dict) and record.get("value")]
        spf_record = self._get_spf_record(domain, name_server)
        dmarc_record = self._get_dmarc_record(domain, name_server)
        test_params = self._test_params_for_source_id(source_id, authority_hosts, soa_records, mx_records, spf_record, dmarc_record)
        if test_params is None:
            return None

        return self._run_test(domain, name_server, str(spec["type"]), str(spec["test_name"]), test_params)

    @staticmethod
    def _test_params_for_source_id(
        source_id: str,
        authority_hosts: List[Dict[str, Any]],
        soa_records: List[Dict[str, Any]],
        mx_records: List[Dict[str, Any]],
        spf_record: Dict[str, Any] | None,
        dmarc_record: Dict[str, Any] | None,
    ) -> Dict[str, Any] | None:
        if source_id == "All authority hosts has the same SOA test (2)":
            return {"mode": "auto"}
        if source_id == "The term mname is real authority hosts test (9)":
            if not soa_records:
                return None
            return {"records": [soa_records[0]], "authority-hosts": authority_hosts}
        if source_id in {
            "Target hosts with resolvable IPs test (16)",
            "Duplicated records test (17)",
            "No records points to CNAME test (18)",
        }:
            if not mx_records:
                return None
            return {"records": mx_records}
        if source_id == "Records hosts can send emails test (22)":
            if not spf_record or not mx_records:
                return None
            return {"mode": "mx", "records": [spf_record], "mx-records": mx_records}
        if source_id in {
            "Subdomain policy term test (27)",
            "Rua and Ruf terms test (29)",
            "Fo term test (30)",
        }:
            if not dmarc_record:
                return None
            return {"records": [dmarc_record]}
        return {}

    def _run_test(
        self,
        domain: str,
        name_server: str | None,
        test_type: str,
        test_name: str,
        test_params: Dict[str, Any],
    ) -> Dict[str, Any] | None:
        url = f"{self.base_url}/run-test"
        payload: Dict[str, Any] = {
            "host": domain,
            "type": test_type,
            "test-name": test_name,
            "test-params": test_params,
        }
        if name_server:
            payload["target-hostname"] = name_server

        headers = {
            "X-Accept-Language": self.config.language,
            "Content-Type": "application/json",
        }

        try:
            resp = self.http.post(url, json=payload, headers=headers)
            data = resp.json()
        except Exception as exc:
            logger.warning("IntoDnsSource: run-test [%s/%s] failed for %s: %s", test_type, test_name, domain, exc)
            return None

        if not isinstance(data, dict):
            return None

        data.setdefault("test-name", test_name)
        return data

    def _get_spf_record(self, domain: str, name_server: str | None) -> Dict[str, Any] | None:
        url = f"{self.base_url}/get-spf-record"
        params: Dict[str, Any] = {"host": domain}
        if name_server:
            params["name-server"] = name_server
        try:
            resp = self.http.get(url, params=params, headers={"X-Accept-Language": self.config.language})
            data = resp.json()
        except Exception:
            return None
        if isinstance(data, dict) and data.get("record"):
            return data
        return None

    def _get_dmarc_record(self, domain: str, name_server: str | None) -> Dict[str, Any] | None:
        url = f"{self.base_url}/get-dmarc-record"
        params: Dict[str, Any] = {"host": domain}
        if name_server:
            params["name-server"] = name_server
        try:
            resp = self.http.get(url, params=params, headers={"X-Accept-Language": self.config.language})
            data = resp.json()
        except Exception:
            return None
        if isinstance(data, dict) and data.get("record"):
            return data
        return None

    @staticmethod
    def _map_a(records: List[Dict[str, Any]]) -> List[ARecord]:
        result: List[ARecord] = []
        for rec in records:
            value = rec.get("value")
            if not value:
                continue
            result.append(
                ARecord(
                    name=rec.get("host", ""),
                    address=value,
                    ttl=rec.get("ttl"),
                )
            )
        return result

    @staticmethod
    def _map_aaaa(records: List[Dict[str, Any]]) -> List[AAAARecord]:
        result: List[AAAARecord] = []
        for rec in records:
            value = rec.get("value")
            if not value:
                continue
            result.append(
                AAAARecord(
                    name=rec.get("host", ""),
                    address=value,
                    ttl=rec.get("ttl"),
                )
            )
        return result

    @staticmethod
    def _map_ns(records: List[Dict[str, Any]]) -> List[NSRecord]:
        result: List[NSRecord] = []
        for rec in records:
            value = rec.get("value")
            if not value:
                continue
            result.append(
                NSRecord(
                    name=rec.get("host", ""),
                    host=value,
                    ttl=rec.get("ttl"),
                )
            )
        return result

    @staticmethod
    def _map_mx(records: List[Dict[str, Any]]) -> List[MXRecord]:
        result: List[MXRecord] = []
        for rec in records:
            value = rec.get("value")
            if not value:
                continue
            preference = rec.get("level")
            try:
                pref_int = int(preference) if preference is not None else 10
            except (TypeError, ValueError):
                pref_int = 10
            result.append(
                MXRecord(
                    name=rec.get("host", ""),
                    exchange=value,
                    preference=pref_int,
                    ttl=rec.get("ttl"),
                )
            )
        return result

    @staticmethod
    def _map_txt(records: List[Dict[str, Any]]) -> List[TXTRecord]:
        result: List[TXTRecord] = []
        for rec in records:
            value = rec.get("value")
            if value is None:
                continue
            result.append(
                TXTRecord(
                    name=rec.get("host", ""),
                    text=str(value),
                    ttl=rec.get("ttl"),
                )
            )
        return result

    @staticmethod
    def _map_cname(records: List[Dict[str, Any]]) -> List[CNAMERecord]:
        result: List[CNAMERecord] = []
        for rec in records:
            value = rec.get("value")
            if not value:
                continue
            result.append(
                CNAMERecord(
                    name=rec.get("host", ""),
                    target=value,
                    ttl=rec.get("ttl"),
                )
            )
        return result

