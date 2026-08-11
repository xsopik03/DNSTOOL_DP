from typing import Optional, Any, Dict
import logging
import requests

logger = logging.getLogger(__name__)

class HttpClient:
    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self._session = requests.Session()

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        logger.debug("Sending GET request to %s %s", url, kwargs)
        resp = self._session.get(url, timeout=self.timeout, **kwargs)
        resp.raise_for_status()
        return resp
    
    def post(self, url: str, json: Optional[Dict[str, Any]] = None, **kwargs: Any) -> requests.Response:
        logger.debug("Sending POST request to %s %s", url, kwargs)
        resp = self._session.post(url, json=json, timeout=self.timeout, **kwargs)
        resp.raise_for_status()
        return resp
