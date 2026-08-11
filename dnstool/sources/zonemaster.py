from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from ..config import ZonemasterConfig
from ..models.dns_records import (
    DnsData,
    ARecord,
    AAAARecord,
    NSRecord,
)
from ..util.http_client import HttpClient
from .base_source import BaseSource

logger = logging.getLogger(__name__)


class ZonemasterSource(BaseSource):
    def __init__(self, config: ZonemasterConfig) -> None:
        self.config = config
        self.http = HttpClient(timeout=config.request_timeout)
        self._rpc_id: int = 0

    def fetch_dns_data(self, domain: str) -> Tuple[DnsData, Dict[str, Any]]:
        logger.info("Fetching DNS data for domain %s via Zonemaster", domain)

        test_id = self._start_test(domain)

        self._wait_until_finished(test_id)

        test_result = self._get_test_results(test_id)
        logger.debug(
            "Zonemaster test_result for %s: keys=%s",
            domain,
            list(test_result.keys()),
        )

        a_records, aaaa_records = self._get_host_records(domain)

        ns_records = self._get_parent_ns(domain)

        dns_data = DnsData(
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=[],
            ns_records=ns_records,
            txt_records=[],
            cname_records=[],
            spf_records=[],
            dmarc_records=[],
            dkim_records=[],
            ds_records=[],
            dnskey_records=[],
            svcb_records=[],
            https_records=[],
        )

        logger.info(
            "Assembled DnsData for %s: A=%d, AAAA=%d, NS=%d",
            domain,
            len(a_records),
            len(aaaa_records),
            len(ns_records),
        )
        return dns_data, test_result


    def _rpc_call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        self._rpc_id += 1
        rpc_id = self._rpc_id

        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        url = self.config.base_url.rstrip("/")
        logger.debug("JSON-RPC request %s: %s", method, payload)

        resp = self.http.post(url, json=payload)
        data = resp.json()

        logger.debug("JSON-RPC response for %s: %s", method, data)

        if "error" in data and data["error"] is not None:
            err = data["error"]
            logger.error("Zonemaster RPC error in %s: %s", method, err)
            raise RuntimeError(f"Zonemaster RPC error calling {method}: {err}")

        if "result" not in data:
            raise RuntimeError(f"Zonemaster RPC response missing 'result' for method {method}")

        return data["result"]

    def _start_test(self, domain: str) -> str:

        params: Dict[str, Any] = {
            "domain": domain,
            "ipv4": True,
            "ipv6": True,
            "profile": "default",
            "client_id": "python-dnstool",
            "client_version": "0.1.0",
            "priority": 10,
            "queue": 0,
            "nameservers": [],
            "ds_info": [],
            "language": self.config.language,
        }

        result = self._rpc_call("start_domain_test", params=params)
        test_id = str(result)
        logger.info("Zonemaster start_domain_test for %s -> test_id=%s", domain, test_id)
        return test_id

    def _test_progress(self, test_id: str) -> int:

        params = {"test_id": test_id}
        result = self._rpc_call("test_progress", params=params)

        try:
            progress = int(result)
        except (TypeError, ValueError):
            raise RuntimeError(f"Unexpected progress value from Zonemaster: {result!r}")

        return progress

    def _wait_until_finished(self, test_id: str) -> None:

        for attempt in range(1, self.config.max_poll_attempts + 1):
            progress = self._test_progress(test_id)
            logger.debug(
                "Zonemaster test_progress for %s: %d%% (attempt %d/%d)",
                test_id,
                progress,
                attempt,
                self.config.max_poll_attempts,
            )

            if progress >= 100:
                logger.info("Zonemaster test %s finished", test_id)
                return

            time.sleep(self.config.poll_interval_seconds)

        raise TimeoutError(f"Zonemaster test {test_id} did not finish in time")

    def _get_test_results(self, test_id: str) -> Dict[str, Any]:

        params = {
            "id": test_id,
            "language": self.config.language,
        }
        result = self._rpc_call("get_test_results", params=params)
        return result

    def _get_host_records(self, domain: str) -> Tuple[List[ARecord], List[AAAARecord]]:

        try:
            result = self._rpc_call("get_host_by_name", params={"hostname": domain})
        except Exception as exc:
            logger.warning("get_host_by_name failed for %s: %s", domain, exc)
            return [], []

        a_records: List[ARecord] = []
        aaaa_records: List[AAAARecord] = []

        if not isinstance(result, list):
            logger.warning("Unexpected get_host_by_name result format: %r", result)
            return [], []

        for item in result:
            if not isinstance(item, dict):
                continue
            for name, ip in item.items():
                if not isinstance(ip, str):
                    continue

                if ":" in ip:
                    if ip != "0.0.0.0":
                        aaaa_records.append(AAAARecord(name=name, address=ip))
                else:
                    if ip != "0.0.0.0":
                        a_records.append(ARecord(name=name, address=ip))

        return a_records, aaaa_records

    def _get_parent_ns(self, domain: str) -> List[NSRecord]:

        try:
            result = self._rpc_call(
                "get_data_from_parent_zone",
                params={
                    "domain": domain,
                    "language": self.config.language,
                },
            )
        except Exception as exc:
            logger.warning("get_data_from_parent_zone failed for %s: %s", domain, exc)
            return []

        ns_list = result.get("ns_list", [])
        ns_records: List[NSRecord] = []

        if not isinstance(ns_list, list):
            logger.warning(
                "Unexpected ns_list format in get_data_from_parent_zone: %r", ns_list
            )
            return []

        for ns_obj in ns_list:
            if not isinstance(ns_obj, dict):
                continue

            ns_name = ns_obj.get("ns")
            if not ns_name:
                continue

            ns_records.append(NSRecord(name=domain, host=ns_name))

        return ns_records
