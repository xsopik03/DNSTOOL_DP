from abc import ABC, abstractmethod
from ..models.dns_records import DnsData
from typing import Tuple, Dict, Any


class BaseSource(ABC):
    @abstractmethod
    def fetch_dns_data(self, domain: str) -> Tuple[DnsData, Dict[str, Any]]:
        pass
