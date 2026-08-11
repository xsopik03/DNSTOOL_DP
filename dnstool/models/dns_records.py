from dataclasses import dataclass
from typing import Optional, List

@dataclass
class ARecord:
    name: str
    address: str
    ttl: Optional[int] = None

@dataclass
class AAAARecord:
    name: str
    address: str
    ttl: Optional[int] = None

@dataclass
class CNAMERecord:
    name: str
    target: str
    ttl: Optional[int] = None   

@dataclass
class MXRecord:
    name: str
    exchange: str
    preference: int
    ttl: Optional[int] = None

@dataclass
class NSRecord:
    name: str
    host: str
    ttl: Optional[int] = None

@dataclass
class TXTRecord:
    name: str
    text: str
    ttl: Optional[int] = None


@dataclass
class SPFRecord:
    name: str
    text: str
    ttl: Optional[int] = None


@dataclass
class DMARCRecord:
    name: str
    text: str
    ttl: Optional[int] = None


@dataclass
class DKIMRecord:
    name: str
    selector: str
    text: str
    ttl: Optional[int] = None


@dataclass
class DSRecord:
    name: str
    key_tag: int
    algorithm: int
    digest_type: int
    digest: str
    ttl: Optional[int] = None


@dataclass
class DNSKEYRecord:
    name: str
    flags: int
    protocol: int
    algorithm: int
    key: str
    ttl: Optional[int] = None


@dataclass
class SVCBRecord:
    name: str
    priority: int
    target: str
    params: str
    ttl: Optional[int] = None


@dataclass
class HTTPSRecord:
    name: str
    priority: int
    target: str
    params: str
    ttl: Optional[int] = None

@dataclass
class DnsData:
    domain: str
    a_records: List[ARecord]
    aaaa_records: List[AAAARecord]
    cname_records: List[CNAMERecord]
    mx_records: List[MXRecord]
    ns_records: List[NSRecord]
    txt_records: List[TXTRecord]
    spf_records: List[SPFRecord]
    dmarc_records: List[DMARCRecord]
    dkim_records: List[DKIMRecord]
    ds_records: List[DSRecord]
    dnskey_records: List[DNSKEYRecord]
    svcb_records: List[SVCBRecord]
    https_records: List[HTTPSRecord]