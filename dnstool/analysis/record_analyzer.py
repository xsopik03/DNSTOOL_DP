from typing import List, Dict, Any
from ..models.dns_records import DnsData
from ..models.findings import IssueFinding
from .base_analyzer import BaseAnalyzer

class RecordAnalyzer(BaseAnalyzer):
    def analyze(self, dns_data: DnsData) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        domain = dns_data.domain

        if dns_data.a_records or dns_data.aaaa_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-ADDRESS-PRESENT",
                    severity="INFO",
                    message=f"A or AAAA records are present for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-ADDRESS-PRESENT",
                    severity="ERROR",
                    message=f"Domain {domain} is missing both A and AAAA records.",
                    details={},
                ).to_dict()
            )

        if dns_data.ns_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-NS-PRESENT",
                    severity="INFO",
                    message=f"NS records are present for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-NS-PRESENT",
                    severity="ERROR",
                    message=f"Domain {domain} is missing NS records.",
                    details={},
                ).to_dict()
            )

        if dns_data.mx_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-MX-PRESENT",
                    severity="INFO",
                    message=f"MX records are present for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-MX-PRESENT",
                    severity="WARNING",
                    message=f"Domain {domain} has no MX records. It is likely not set up to receive email.",
                    details={},
                ).to_dict()
            )

        if dns_data.txt_records:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-TXT-PRESENT",
                    severity="INFO",
                    message=f"TXT records are present for {domain}.",
                    details={},
                ).to_dict()
            )
        else:
            issues.append(
                IssueFinding(
                    vuln_code="PTV-DNS-TXT-PRESENT",
                    severity="INFO",
                    message=f"Domain {domain} has no TXT records.",
                    details={},
                ).to_dict()
            )

        return issues