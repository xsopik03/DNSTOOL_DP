from __future__ import annotations

import base64
import ipaddress
import re
from typing import Any, Dict, List, Optional

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from ..models.dns_records import DnsData
from ..models.findings import IssueFinding
from .base_analyzer import BaseAnalyzer


_VALID_DMARC_POLICIES = {"none", "quarantine", "reject"}
_WEAK_DNSSEC_ALGOS = {1, 3, 5, 6, 7}
_DS_DIGEST_ALGOS = {
    1: "SHA1",
    2: "SHA256",
    4: "SHA384",
}


def _parse_tag_record(record_text: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for item in record_text.split(";"):
        entry = item.strip()
        if not entry or "=" not in entry:
            continue
        key, value = entry.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags


def _estimate_spf_dns_lookup_count(spf_text: str) -> int:
    text = f" {spf_text.lower()} "
    count = 0
    count += len(re.findall(r"\sinclude:", text))
    count += len(re.findall(r"\sexists:", text))
    count += len(re.findall(r"\sredirect=", text))
    count += len(re.findall(r"\sa(?=[:/?\s]|$)", text))
    count += len(re.findall(r"\smx(?=[:/?\s]|$)", text))
    count += len(re.findall(r"\sptr(?=[:/?\s]|$)", text))
    return count


def _dkim_key_size_bits(tag_p: str) -> Optional[int]:
    key_material = "".join(tag_p.split())
    if not key_material:
        return None

    remainder = len(key_material) % 4
    if remainder:
        key_material += "=" * (4 - remainder)

    try:
        raw = base64.b64decode(key_material, validate=True)
        return len(raw) * 8
    except Exception:
        return None


def _tokenize_svc_params(params: str) -> List[str]:
    if not params:
        return []
    return re.findall(r"(?:[^\s\"]+|\"[^\"]*\")+", params.strip())


def _parse_svc_params(params: str) -> Dict[str, List[str]]:
    parsed: Dict[str, List[str]] = {}
    for token in _tokenize_svc_params(params):
        if "=" in token:
            key, value = token.split("=", 1)
        else:
            key, value = token, ""
        key = key.strip().lower()
        value = value.strip().strip('"')
        parsed.setdefault(key, []).append(value)
    return parsed


def _normalize_svc_params(params: Any) -> Dict[str, List[str]]:
    def _to_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        if hasattr(value, "to_text"):
            try:
                return value.to_text()
            except Exception:
                return str(value)
        return str(value)

    if params is None:
        return {}

    if isinstance(params, str):
        return _parse_svc_params(params)

    items_obj = None
    if isinstance(params, dict):
        items_obj = params.items()
    elif hasattr(params, "items"):
        try:
            items_obj = params.items()
        except Exception:
            items_obj = None

    if items_obj is not None:
        parsed: Dict[str, List[str]] = {}
        for raw_key, raw_value in items_obj:
            key = _to_text(raw_key).strip().lower()
            if not key:
                continue

            values: List[str]
            if isinstance(raw_value, (list, tuple, set)):
                values = [_to_text(item).strip().strip('"') for item in raw_value]
            else:
                values = [_to_text(raw_value).strip().strip('"')]

            if not values:
                values = [""]

            parsed.setdefault(key, []).extend(values)
        return parsed

    
    return _parse_svc_params(_to_text(params))


def _is_dmarc_name(name: str, domain: str) -> bool:
    return name.lower().rstrip(".") == f"_dmarc.{domain}".lower().rstrip(".")


def _looks_like_dmarc(text: str) -> bool:
    lower = text.lower()
    return "dmarc" in lower or any(tag in lower for tag in ("p=", "rua=", "ruf=", "adkim=", "aspf=", "pct="))


def _dmarc_candidate_records(dns_data: DnsData) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []

    for txt in dns_data.txt_records:
        name = txt.name
        text = txt.text.strip()
        if _is_dmarc_name(name, dns_data.domain) and text:
            candidates.append({"name": txt.name, "text": text})

    for dmarc in dns_data.dmarc_records:
        text = dmarc.text.strip()
        if text:
            candidates.append({"name": dmarc.name, "text": text})

    unique: Dict[tuple[str, str], Dict[str, str]] = {}
    for item in candidates:
        key = (item["name"].lower().rstrip("."), item["text"])
        unique[key] = item

    return list(unique.values())


def _is_dkim_name(name: str, domain: str) -> bool:
    normalized = name.lower().rstrip(".")
    suffix = f"._domainkey.{domain}".lower().rstrip(".")
    return normalized.endswith(suffix)


def _extract_dkim_selector(name: str, domain: str) -> str:
    normalized = name.rstrip(".")
    suffix = f"._domainkey.{domain}".rstrip(".")
    if normalized.lower().endswith(suffix.lower()):
        selector = normalized[: -len(suffix)].rstrip(".")
        return selector or "<unknown>"
    return "<unknown>"


def _dkim_candidate_records(dns_data: DnsData) -> List[Dict[str, str]]:
    candidates: List[Dict[str, str]] = []

    for txt in dns_data.txt_records:
        name = txt.name
        text = txt.text.strip()
        if _is_dkim_name(name, dns_data.domain) and text:
            selector = _extract_dkim_selector(txt.name, dns_data.domain)
            candidates.append({"name": txt.name, "selector": selector, "text": text})

    for dkim in dns_data.dkim_records:
        text = dkim.text.strip()
        if text:
            candidates.append({"name": dkim.name, "selector": dkim.selector, "text": text})

    unique: Dict[tuple[str, str], Dict[str, str]] = {}
    for item in candidates:
        key = (item["name"].lower().rstrip("."), item["text"])
        unique[key] = item

    return list(unique.values())


def _valid_ip_list(value: str, version: int) -> bool:
    if not value:
        return False
    for part in value.split(","):
        token = part.strip()
        try:
            addr = ipaddress.ip_address(token)
            if version == 4 and addr.version != 4:
                return False
            if version == 6 and addr.version != 6:
                return False
        except ValueError:
            return False
    return True


def _dnssec_consistency(dns_data: DnsData) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "validated": False,
        "errors": [],
        "matched_ds": 0,
        "unmatched_ds": 0,
    }

    if not dns_data.ds_records or not dns_data.dnskey_records:
        return result

    try:
        name = dns.name.from_text(dns_data.domain)
    except Exception as exc:
        result["errors"].append(f"Failed to parse domain as DNS name: {exc}")
        return result

    key_candidates = []
    for key in dns_data.dnskey_records:
        try:
            rdata = dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DNSKEY,
                f"{key.flags} {key.protocol} {key.algorithm} {key.key}",
            )
            key_candidates.append({"record": key, "rdata": rdata, "key_tag": dns.dnssec.key_id(rdata)})
        except Exception as exc:
            result["errors"].append(f"Failed to parse DNSKEY record: {exc}")

    if not key_candidates:
        return result

    for ds in dns_data.ds_records:
        digest_algo = _DS_DIGEST_ALGOS.get(ds.digest_type)
        if not digest_algo:
            result["errors"].append(f"Unsupported DS digest type {ds.digest_type}.")
            result["unmatched_ds"] += 1
            continue

        matched = False
        for candidate in key_candidates:
            key_rdata = candidate["rdata"]
            key_tag = candidate["key_tag"]

            if key_tag != ds.key_tag:
                continue

            try:
                computed_ds = dns.dnssec.make_ds(name, key_rdata, digest_algo)
                computed_digest = computed_ds.digest.hex().lower()
                expected_digest = ds.digest.lower()
                if computed_digest == expected_digest and int(computed_ds.algorithm) == ds.algorithm:
                    matched = True
                    break
            except Exception as exc:
                result["errors"].append(f"Failed DS validation calculation: {exc}")

        if matched:
            result["matched_ds"] += 1
        else:
            result["unmatched_ds"] += 1

    result["validated"] = True
    return result


class SecurityAnalyzer(BaseAnalyzer):
    def analyze(self, dns_data: DnsData) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        domain = dns_data.domain

        if len(dns_data.spf_records) > 1:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-SPF-SINGLE-RECORD",
                    severity="ERROR",
                    message=f"Domain {domain} has multiple SPF records.",
                    details={"count": len(dns_data.spf_records)},
                ).to_dict()
            )

        if dns_data.spf_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-SPF-PRESENT",
                    severity="INFO",
                    message=f"SPF record is present for {domain}.",
                    details={},
                ).to_dict()
            )

        if not dns_data.spf_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-SPF-PRESENT",
                    severity="WARNING",
                    message=f"Domain {domain} has no SPF record.",
                    details={},
                ).to_dict()
            )
        else:
            for spf in dns_data.spf_records:
                lower = spf.text.lower().strip()

                
                if not lower.startswith("v=spf1"):
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SPF-VERSION-VALID",
                            severity="WARNING",
                            message=f"SPF record for {domain} does not start with v=spf1.",
                            details={"record": spf.text},
                        ).to_dict()
                    )

                all_match = re.search(r"(?:^|\s)([+\-~?])all(?:\s|$)", lower)
                
                if not all_match:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SPF-POLICY-NOT-PERMISSIVE",
                            severity="WARNING",
                            message=f"SPF record for {domain} has no explicit all mechanism policy.",
                            details={"record": spf.text},
                        ).to_dict()
                    )
                
                elif all_match.group(1) in {"+", "?"}:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SPF-POLICY-NOT-PERMISSIVE",
                            severity="WARNING",
                            message=f"SPF record for {domain} uses permissive all mechanism ({all_match.group(1)}all).",
                            details={"record": spf.text},
                        ).to_dict()
                    )

                if re.search(r"(?:^|\s)ptr(?=[:/?\s]|$)", lower):
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SPF-PTR-NOT-USED",
                            severity="INFO",
                            message=f"SPF record for {domain} uses deprecated PTR mechanism.",
                            details={"record": spf.text},
                        ).to_dict()
                    )

                lookup_count = _estimate_spf_dns_lookup_count(lower)
                
                if lookup_count > 10:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SPF-DNS-LOOKUP-ESTIMATE",
                            severity="WARNING",
                            message=f"SPF record for {domain} likely exceeds DNS lookup limit (>{10}).",
                            details={"record": spf.text, "estimated_dns_lookups": lookup_count},
                        ).to_dict()
                    )

        dmarc_candidates = _dmarc_candidate_records(dns_data)
        dmarc_like_candidates = [item for item in dmarc_candidates if _looks_like_dmarc(item["text"])]

        if dmarc_like_candidates:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DMARC-PRESENT",
                    severity="INFO",
                    message=f"DMARC record is present for {domain}.",
                    details={"record": dmarc_like_candidates[0]["text"], "name": dmarc_like_candidates[0]["name"]},
                ).to_dict()
            )

        if len(dmarc_like_candidates) > 1:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DMARC-SINGLE-RECORD",
                    severity="ERROR",
                    message=f"Domain {domain} has multiple DMARC/DMARC-like TXT records on _dmarc host.",
                    details={"count": len(dmarc_like_candidates)},
                ).to_dict()
            )

        if not dmarc_like_candidates:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DMARC-PRESENT",
                    severity="WARNING",
                    message=f"Domain {domain} has no DMARC record.",
                    details={},
                ).to_dict()
            )
        else:
            for dmarc in dmarc_like_candidates:
                lower = dmarc["text"].lower()
                tags = _parse_tag_record(dmarc["text"])

                
                if tags.get("v", "").lower() != "dmarc1":
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-CORE-VALID",
                            severity="WARNING",
                            message=f"DMARC record for {domain} has invalid or missing version tag.",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )

                policy = tags.get("p", "").lower()
                
                if not policy:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-CORE-VALID",
                            severity="WARNING",
                            message=f"DMARC record for {domain} is missing required p= policy.",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )
                
                elif policy not in _VALID_DMARC_POLICIES:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-CORE-VALID",
                            severity="WARNING",
                            message=f"DMARC record for {domain} has unsupported p= policy value '{policy}'.",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )

                
                if "p=none" in lower:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-POLICY-ENFORCED",
                            severity="INFO",
                            message=f"DMARC policy for {domain} is monitor-only (p=none).",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )
                elif policy in {"quarantine", "reject"}:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-POLICY-ENFORCED",
                            severity="WARNING",
                            message=f"DMARC is not monitor-only",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )

                pct = tags.get("pct")
                if pct is not None:
                    try:
                        pct_num = int(pct)
                        if not (0 <= pct_num <= 100):
                            issues.append(
                                IssueFinding(
                                    vuln_code="PTV-DNS-DMARC-CORE-VALID",
                                    severity="WARNING",
                                    message=f"DMARC record for {domain} has pct outside valid range 0-100 (pct={pct_num}).",
                                    details={"record": dmarc["text"], "name": dmarc["name"]},
                                ).to_dict()
                            )
                        elif pct_num < 100:
                            issues.append(
                                IssueFinding(
                                    vuln_code="PTV-DNS-DMARC-LEGACY-PCT-REDUCED",
                                    severity="INFO",
                                    message=f"DMARC policy for {domain} applies only to {pct_num}% of messages (pct={pct_num}).",
                                    details={"record": dmarc["text"], "name": dmarc["name"]},
                                ).to_dict()
                            )
                    
                    except ValueError:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-DMARC-CORE-VALID",
                                severity="WARNING",
                                message=f"DMARC record for {domain} has non-numeric pct value.",
                                details={"record": dmarc["text"], "name": dmarc["name"]},
                            ).to_dict()
                        )

                for align_tag in ("adkim", "aspf"):
                    value = tags.get(align_tag)
                    
                    if value and value.lower() not in {"r", "s"}:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-DMARC-CORE-VALID",
                                severity="WARNING",
                                message=f"DMARC record for {domain} has invalid {align_tag}={value} value.",
                                details={"record": dmarc["text"], "name": dmarc["name"]},
                            ).to_dict()
                        )

                
                if "rua" not in tags:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DMARC-RUA-PRESENT",
                            severity="INFO",
                            message=f"DMARC record for {domain} does not define rua= aggregate reporting destination.",
                            details={"record": dmarc["text"], "name": dmarc["name"]},
                        ).to_dict()
                    )

        dkim_candidates = _dkim_candidate_records(dns_data)

        if dkim_candidates:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DKIM-DISCOVERED",
                    severity="INFO",
                    message=f"DKIM record discovered on tested selectors",
                    details={"checked_selectors": ["default", "selector1", "selector2", "google", "k1", "s1"]},
                ).to_dict()
            )

        if not dkim_candidates:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DKIM-DISCOVERED",
                    severity="INFO",
                    message=f"No DKIM record discovered for {domain} using common selectors.",
                    details={"checked_selectors": ["default", "selector1", "selector2", "google", "k1", "s1"]},
                ).to_dict()
            )
        else:
            valid_dkim_count = 0
            for dkim in dkim_candidates:
                tags = _parse_tag_record(dkim["text"])
                version = tags.get("v", "").lower()
                
                if version and version != "dkim1":
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DKIM-RECORD-VALID",
                            severity="WARNING",
                            message=f"DKIM record ({dkim['selector']}) for {domain} has unexpected version tag.",
                            details={"record": dkim["text"], "name": dkim["name"]},
                        ).to_dict()
                    )

                public_key = tags.get("p")
                if public_key is None or public_key == "":
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DKIM-RECORD-VALID",
                            severity="WARNING",
                            message=f"DKIM record ({dkim['selector']}) for {domain} has missing/empty p= public key.",
                            details={"record": dkim["text"], "name": dkim["name"]},
                        ).to_dict()
                    )
                else:
                    key_bits = _dkim_key_size_bits(public_key)
                    if key_bits is None:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-DKIM-RECORD-VALID",
                                severity="WARNING",
                                message=f"DKIM record ({dkim['selector']}) for {domain} has invalid base64 public key in p= tag.",
                                details={"record": dkim["text"], "name": dkim["name"]},
                            ).to_dict()
                        )
                    elif key_bits < 1024:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-DKIM-WEA",
                                severity="WARNING",
                                message=f"DKIM record ({dkim['selector']}) for {domain} uses weak key length ({key_bits} bits).",
                                details={"record": dkim["text"], "name": dkim["name"], "key_bits": key_bits},
                            ).to_dict()
                        )
                    
                    elif key_bits == 1024:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-DKIM-WEA",
                                severity="INFO",
                                message=f"DKIM record ({dkim['selector']}) for {domain} uses 1024-bit key; 2048+ is recommended.",
                                details={"record": dkim["text"], "name": dkim["name"], "key_bits": key_bits},
                            ).to_dict()
                        )
                    else:
                        valid_dkim_count += 1

                t_value = tags.get("t", "").lower()
                t_flags = {flag.strip() for flag in re.split(r"[:,]", t_value) if flag.strip()}
                if "y" in t_flags:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-DKIM-NOT-TESTING",
                            severity="INFO",
                            message=f"DKIM record ({dkim['selector']}) for {domain} is in testing mode (t=y).",
                            details={"record": dkim["text"], "name": dkim["name"]},
                        ).to_dict()
                    )

            if valid_dkim_count > 0:
                issues.append(
                    IssueFinding(
                        vuln_code="PTV-DNS-DKIM-RECORD-VALID",
                        severity="INFO",
                        message=f"DKIM record structure/public key is valid",
                        details={"valid_records": valid_dkim_count},
                    ).to_dict()
                )

        if not dns_data.ds_records and not dns_data.dnskey_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DNSSEC-PRESENT",
                    severity="WARNING",
                    message=f"No DNSSEC DS/DNSKEY records detected for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DNSSEC-PRESENT",
                    severity="INFO",
                    message=f"DNSSEC DS/DNSKEY material is present.",
                    details={},
                ).to_dict()
            )
        
        if dns_data.ds_records and not dns_data.dnskey_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DNSSEC-DS-DNSKEY-CONSISTENT",
                    severity="WARNING",
                    message=f"DS records exist for {domain} but no DNSKEY was retrieved.",
                    details={},
                ).to_dict()
            )
        
        elif dns_data.dnskey_records and not dns_data.ds_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DNSSEC-DS-DNSKEY-CONSISTENT",
                    severity="INFO",
                    message=f"DNSKEY records were found for {domain}, but no DS records were detected at parent side.",
                    details={},
                ).to_dict()
            )

        if dns_data.dnskey_records:
            
            if not any(rec.flags == 257 for rec in dns_data.dnskey_records):
                issues.append(
                    IssueFinding(
                        vuln_code="PTV-DNS-DNSSEC-ALGORITHM-SECURE",
                        severity="INFO",
                        message=f"No KSK-like DNSKEY (flag 257) detected for {domain}.",
                        details={},
                    ).to_dict()
                )

            weak_algorithms = sorted(
                {rec.algorithm for rec in dns_data.dnskey_records if rec.algorithm in _WEAK_DNSSEC_ALGOS}
            )
            
            if weak_algorithms:
                issues.append(
                    IssueFinding(
                        vuln_code="PTV-DNS-DNSSEC-ALGORITHM-SECURE",
                        severity="WARNING",
                        message=f"Weak or deprecated DNSSEC algorithm(s) detected for {domain}: {', '.join(map(str, weak_algorithms))}.",
                        details={"algorithms": weak_algorithms},
                    ).to_dict()
                )

        dnssec_consistency = _dnssec_consistency(dns_data)
        if dnssec_consistency.get("validated"):
            
            if dnssec_consistency.get("unmatched_ds", 0) > 0:
                issues.append(
                    IssueFinding(
                        vuln_code="PTV-DNS-DNSSEC-DS-DNSKEY-CONSISTENT",
                        severity="WARNING",
                        message=(
                            f"DNSSEC DS↔DNSKEY mismatch detected for {domain}: "
                            f"{dnssec_consistency.get('unmatched_ds', 0)} DS record(s) could not be validated."
                        ),
                        details=dnssec_consistency,
                    ).to_dict()
                )
        elif dns_data.ds_records and dns_data.dnskey_records:
            
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-DNSSEC-DS-DNSKEY-CONSISTENT",
                    severity="INFO",
                    message=f"DNSSEC DS↔DNSKEY consistency check for {domain} could not be completed.",
                    details=dnssec_consistency,
                ).to_dict()
            )

        if not dns_data.svcb_records and not dns_data.https_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-SVCBHTTPS-PRESENT",
                    severity="INFO",
                    message=f"No SVCB/HTTPS records detected for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-SVCBHTTPS-PRESENT",
                    severity="INFO",
                    message=f"SVCB/HTTPS record is present",
                    details={},
                ).to_dict()
            )
            svc_like = list(dns_data.svcb_records) + list(dns_data.https_records)
            for record in svc_like:
                parsed_params = _normalize_svc_params(record.params)
                record_type = "HTTPS" if record in dns_data.https_records else "SVCB"
                details_payload = {
                    "priority": record.priority,
                    "target": record.target,
                    "params": parsed_params,
                }

                if record.priority == 0 and record.target.strip() == "":
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                            severity="WARNING",
                            message=f"{record_type} alias-mode record for {domain} has empty target.",
                            details=details_payload,
                        ).to_dict()
                    )

                if record.priority == 0 and record.target.strip() == ".":
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SVCBHTTPS-SPECIAL-CONFIG",
                            severity="INFO",
                            message=f"{record_type} alias-mode record for {domain} uses '.' target (special configuration; verify manually).",
                            details=details_payload,
                        ).to_dict()
                    )

                duplicate_keys = sorted([key for key, values in parsed_params.items() if len(values) > 1])
               
                if duplicate_keys:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                            severity="WARNING",
                            message=f"{record_type} record for {domain} has duplicate SvcParam key(s): {', '.join(duplicate_keys)}.",
                            details=details_payload,
                        ).to_dict()
                    )

                if "no-default-alpn" in parsed_params and "alpn" not in parsed_params:
                    issues.append(
                        IssueFinding(
                            vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                            severity="WARNING",
                            message=f"{record_type} record for {domain} uses no-default-alpn without alpn.",
                            details=details_payload,
                        ).to_dict()
                    )

                if "port" in parsed_params:
                    port_value = parsed_params["port"][0]
                    try:
                        port = int(port_value)
                        
                        if not (1 <= port <= 65535):
                            raise ValueError("out of range")
                    except ValueError:
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                                severity="WARNING",
                                message=f"{record_type} record for {domain} has invalid port parameter '{port_value}'.",
                                details=details_payload,
                            ).to_dict()
                        )

                if "ipv4hint" in parsed_params:
                    value = parsed_params["ipv4hint"][0]
                    
                    if not _valid_ip_list(value, version=4):
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                                severity="WARNING",
                                message=f"{record_type} record for {domain} has invalid ipv4hint value.",
                                details=details_payload,
                            ).to_dict()
                        )

                if "ipv6hint" in parsed_params:
                    value = parsed_params["ipv6hint"][0]
                    
                    if not _valid_ip_list(value, version=6):
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                                severity="WARNING",
                                message=f"{record_type} record for {domain} has invalid ipv6hint value.",
                                details=details_payload,
                            ).to_dict()
                        )

                if "ech" in parsed_params or "echconfig" in parsed_params:
                    key = "ech" if "ech" in parsed_params else "echconfig"
                    value = parsed_params[key][0]
                    
                    if value == "":
                        issues.append(
                            IssueFinding(
                                vuln_code="PTV-DNS-SVCBHTTPS-PARAMS-VALID",
                                severity="WARNING",
                                message=f"{record_type} record for {domain} has empty {key} parameter.",
                                details=details_payload,
                            ).to_dict()
                        )

        return issues