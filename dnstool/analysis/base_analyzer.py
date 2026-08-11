from abc import ABC, abstractmethod
from typing import List, Dict, Any
from ..models.dns_records import DnsData


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, dns_data: DnsData) -> List[Dict[str, Any]]:
        raise NotImplementedError
