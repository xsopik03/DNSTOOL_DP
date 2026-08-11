from __future__ import annotations

import base64
import re
from typing import Iterable, List, Callable, TypeVar

import dns.exception
import dns.resolver

from ..models.dns_records import (
    ARecord,
    AAAARecord,
    CNAMERecord,
    DKIMRecord,
    DMARCRecord,
    DNSKEYRecord,
    DSRecord,
    DnsData,
    HTTPSRecord,
    MXRecord,
    NSRecord,
    SPFRecord,
    SVCBRecord,
    TXTRecord,
)

_COMMON_DKIM_SELECTORS = (
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "s1",
)

_SVC_PARAM_KEY_NAMES = {
    "0": "mandatory",
    "1": "alpn",
    "2": "no-default-alpn",
    "3": "port",
    "4": "ipv4hint",
    "5": "ech",
    "6": "ipv6hint",
}

T = TypeVar("T")


def enrich_dns_data(dns_data: DnsData, timeout: int = 5) -> DnsData:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    _fill_core_records(dns_data, resolver)
    _fill_spf_records(dns_data)
    _fill_dmarc_records(dns_data, resolver)
    _fill_dkim_records(dns_data, resolver, _COMMON_DKIM_SELECTORS)
    _fill_ds_records(dns_data, resolver)
    _fill_dnskey_records(dns_data, resolver)
    _fill_svcb_records(dns_data, resolver)
    _fill_https_records(dns_data, resolver)

    return dns_data


def _merge_records(records: List[T], key_fn: Callable[[T], tuple]) -> List[T]:
    merged: dict[tuple, T] = {}
    for record in records:
        key = key_fn(record)
        existing = merged.get(key)
        if existing is None:
            merged[key] = record
            continue

        if getattr(existing, "ttl", None) is None and getattr(record, "ttl", None) is not None:
            setattr(existing, "ttl", getattr(record, "ttl"))

    return list(merged.values())


def _resolve_records(resolver: dns.resolver.Resolver, name: str, rtype: str):
    try:
        return resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        dns.exception.DNSException,
    ):
        return None


def _fill_core_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    domain = dns_data.domain

    _fill_a_records(dns_data, resolver, domain)
    _fill_aaaa_records(dns_data, resolver, domain)
    _fill_ns_records(dns_data, resolver, domain)
    _fill_mx_records(dns_data, resolver, domain)
    _fill_txt_records(dns_data, resolver, domain)
    _fill_cname_records(dns_data, resolver, domain)

    dns_data.a_records = _merge_records(
        dns_data.a_records,
        lambda r: (r.name.lower().rstrip("."), r.address),
    )
    dns_data.aaaa_records = _merge_records(
        dns_data.aaaa_records,
        lambda r: (r.name.lower().rstrip("."), r.address),
    )
    dns_data.ns_records = _merge_records(
        dns_data.ns_records,
        lambda r: (r.name.lower().rstrip("."), r.host.lower().rstrip(".")),
    )
    dns_data.mx_records = _merge_records(
        dns_data.mx_records,
        lambda r: (r.name.lower().rstrip("."), r.exchange.lower().rstrip("."), r.preference),
    )
    dns_data.txt_records = _merge_records(
        dns_data.txt_records,
        lambda r: (r.name.lower().rstrip("."), r.text),
    )
    dns_data.cname_records = _merge_records(
        dns_data.cname_records,
        lambda r: (r.name.lower().rstrip("."), r.target.lower().rstrip(".")),
    )


def _fill_a_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "A")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        address = _as_text(getattr(rdata, "address", None))
        if address:
            dns_data.a_records.append(ARecord(name=name, address=address, ttl=ttl))


def _fill_aaaa_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "AAAA")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        address = _as_text(getattr(rdata, "address", None))
        if address:
            dns_data.aaaa_records.append(AAAARecord(name=name, address=address, ttl=ttl))


def _fill_ns_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "NS")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        host = _as_text(getattr(rdata, "target", None) or getattr(rdata, "to_text", lambda: "")())
        host = host.rstrip(".")
        if host:
            dns_data.ns_records.append(NSRecord(name=name, host=host, ttl=ttl))


def _fill_mx_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "MX")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        exchange = _as_text(getattr(rdata, "exchange", None)).rstrip(".")
        preference = int(getattr(rdata, "preference", 0))
        if exchange:
            dns_data.mx_records.append(MXRecord(name=name, exchange=exchange, preference=preference, ttl=ttl))


def _fill_txt_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "TXT")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        text = _txt_strings(rdata).strip()
        if text:
            dns_data.txt_records.append(TXTRecord(name=name, text=text, ttl=ttl))


def _fill_cname_records(dns_data: DnsData, resolver: dns.resolver.Resolver, name: str) -> None:
    answers = _resolve_records(resolver, name, "CNAME")
    if not answers:
        return
    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        target = _as_text(getattr(rdata, "target", None)).rstrip(".")
        if target:
            dns_data.cname_records.append(CNAMERecord(name=name, target=target, ttl=ttl))


def _txt_strings(rdata) -> str:
    return "".join(
        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
        for part in getattr(rdata, "strings", [])
    )


def _as_text(value) -> str:
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


def _as_dnskey_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if hasattr(value, "to_text"):
        return value.to_text()
    return str(value)


def _as_digest_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _safe_text(value) -> str:
    text = _as_text(value).strip()
    if re.match(r"^<[^>]+object at 0x[0-9a-fA-F]+>$", text):
        return ""
    return text


def _normalize_svc_param_items(params) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}

    items_obj = None
    if isinstance(params, dict):
        items_obj = params.items()
    elif hasattr(params, "items"):
        try:
            items_obj = params.items()
        except Exception:
            items_obj = None

    if items_obj is None:
        return normalized

    for raw_key, raw_value in items_obj:
        key = _safe_text(raw_key).lower()
        key = _SVC_PARAM_KEY_NAMES.get(key, key)
        if not key:
            continue

        if isinstance(raw_value, (list, tuple, set)):
            values = [_safe_text(item).strip().strip('"') for item in raw_value]
        else:
            values = [_safe_text(raw_value).strip().strip('"')]

        normalized.setdefault(key, []).extend(values if values else [""])

    return normalized


def _svc_params_to_text(params) -> str:
    if params is None:
        return ""

    if isinstance(params, str):
        return params

    normalized = _normalize_svc_param_items(params)
    if normalized:
        parts: list[str] = []
        for key in sorted(normalized.keys()):
            for value in normalized[key]:
                if value == "" and key in {"no-default-alpn"}:
                    parts.append(key)
                elif value == "":
                    parts.append(f'{key}=""')
                else:
                    parts.append(f'{key}="{value}"')
        return " ".join(parts)

    return _safe_text(params)


def _fill_spf_records(dns_data: DnsData) -> None:
    if dns_data.spf_records:
        return

    for txt in dns_data.txt_records:
        text = txt.text.strip()
        if text.lower().startswith("v=spf1"):
            dns_data.spf_records.append(SPFRecord(name=txt.name, text=text, ttl=txt.ttl))


def _fill_dmarc_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    qname = f"_dmarc.{dns_data.domain}"
    answers = _resolve_records(resolver, qname, "TXT")
    if not answers:
        return

    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        text = _txt_strings(rdata).strip()
        if not text:
            continue

        if not any(
            rec.name.lower().rstrip(".") == qname.lower().rstrip(".") and rec.text == text
            for rec in dns_data.txt_records
        ):
            dns_data.txt_records.append(TXTRecord(name=qname, text=text, ttl=ttl))

        if text.lower().startswith("v=dmarc1") and not any(
            rec.name.lower().rstrip(".") == qname.lower().rstrip(".") and rec.text == text
            for rec in dns_data.dmarc_records
        ):
            dns_data.dmarc_records.append(DMARCRecord(name=qname, text=text, ttl=ttl))


def _fill_dkim_records(dns_data: DnsData, resolver: dns.resolver.Resolver, selectors: Iterable[str]) -> None:
    for selector in selectors:
        qname = f"{selector}._domainkey.{dns_data.domain}"
        answers = _resolve_records(resolver, qname, "TXT")
        if not answers:
            continue

        ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
        for rdata in answers:
            text = _txt_strings(rdata).strip()
            if not text:
                continue

            if not any(
                rec.name.lower().rstrip(".") == qname.lower().rstrip(".") and rec.text == text
                for rec in dns_data.txt_records
            ):
                dns_data.txt_records.append(TXTRecord(name=qname, text=text, ttl=ttl))

            if text.lower().startswith("v=dkim1") and not any(
                rec.name.lower().rstrip(".") == qname.lower().rstrip(".") and rec.text == text
                for rec in dns_data.dkim_records
            ):
                dns_data.dkim_records.append(
                    DKIMRecord(name=qname, selector=selector, text=text, ttl=ttl)
                )


def _fill_ds_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    if dns_data.ds_records:
        return

    answers = _resolve_records(resolver, dns_data.domain, "DS")
    if not answers:
        return

    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        dns_data.ds_records.append(
            DSRecord(
                name=dns_data.domain,
                key_tag=int(rdata.key_tag),
                algorithm=int(rdata.algorithm),
                digest_type=int(rdata.digest_type),
                digest=_as_digest_text(rdata.digest),
                ttl=ttl,
            )
        )


def _fill_dnskey_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    if dns_data.dnskey_records:
        return

    answers = _resolve_records(resolver, dns_data.domain, "DNSKEY")
    if not answers:
        return

    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        dns_data.dnskey_records.append(
            DNSKEYRecord(
                name=dns_data.domain,
                flags=int(rdata.flags),
                protocol=int(rdata.protocol),
                algorithm=int(rdata.algorithm),
                key=_as_dnskey_text(rdata.key),
                ttl=ttl,
            )
        )


def _fill_svcb_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    if dns_data.svcb_records:
        return

    answers = _resolve_records(resolver, dns_data.domain, "SVCB")
    if not answers:
        return

    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        dns_data.svcb_records.append(
            SVCBRecord(
                name=dns_data.domain,
                priority=int(rdata.priority),
                target=_as_text(rdata.target),
                params=_svc_params_to_text(getattr(rdata, "params", None)),
                ttl=ttl,
            )
        )


def _fill_https_records(dns_data: DnsData, resolver: dns.resolver.Resolver) -> None:
    if dns_data.https_records:
        return

    answers = _resolve_records(resolver, dns_data.domain, "HTTPS")
    if not answers:
        return

    ttl = getattr(getattr(answers, "rrset", None), "ttl", None)
    for rdata in answers:
        dns_data.https_records.append(
            HTTPSRecord(
                name=dns_data.domain,
                priority=int(rdata.priority),
                target=_as_text(rdata.target),
                params=_svc_params_to_text(getattr(rdata, "params", None)),
                ttl=ttl,
            )
        )
