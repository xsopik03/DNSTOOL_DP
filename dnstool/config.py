from dataclasses import dataclass
import os

@dataclass
class ZonemasterConfig:
    base_url: str = "https://zonemaster.net/api"
    request_timeout: int = 30
    poll_interval_seconds: int = 3
    max_poll_attempts: int = 20
    language: str = "en"

@dataclass
class IntoDnsConfig:
    base_url: str = "https://intodns.io/api/v1"
    request_timeout: int = 30
    language: str = "en"


@dataclass
class IntoDnsAiConfig:
    base_url: str = "https://intodns.ai/api"
    request_timeout: int = 30
    language: str = "en"


@dataclass
class MxToolboxConfig:
    base_url: str = "https://api.mxtoolbox.com/api/v1"
    request_timeout: int = 30
    api_key: str = "aac7e992-a6e1-4352-8fa7-605aa5aca3a9"

@dataclass
class AppConfig:
    zonemaster: ZonemasterConfig
    intodns: IntoDnsConfig
    intodns_ai: IntoDnsAiConfig
    mxtoolbox: MxToolboxConfig
    default_output_format: str = "json"

    @classmethod
    def from_env(cls) -> "AppConfig":
        zm_base_url = os.getenv("ZONEMASTER_API_BASE_URL","https://zonemaster.net/api")
        zm_timeout = int(os.getenv("ZONEMASTER_API_TIMEOUT", "30"))
        zm_poll_interval = int(os.getenv("ZONEMASTER_API_POLL_INTERVAL", "3"))
        zm_max_poll = int(os.getenv("ZONEMASTER_API_MAX_POLL", "20"))
        zm_language = os.getenv("ZONEMASTER_API_LANGUAGE", "en")

        intodns_base_url = os.getenv("INTODNS_API_BASE_URL", "https://intodns.io/api/v1")
        intodns_timeout = int(os.getenv("INTODNS_API_TIMEOUT", "30"))
        intodns_language = os.getenv("INTODNS_API_LANGUAGE", "en")

        intodns_ai_base_url = os.getenv("INTODNS_AI_API_BASE_URL", "https://intodns.ai/api")
        intodns_ai_timeout = int(os.getenv("INTODNS_AI_API_TIMEOUT", "30"))
        intodns_ai_language = os.getenv("INTODNS_AI_API_LANGUAGE", "en")

        mxtoolbox_base_url = os.getenv("MXTOOLBOX_API_BASE_URL", "https://api.mxtoolbox.com/api/v1")
        mxtoolbox_timeout = int(os.getenv("MXTOOLBOX_API_TIMEOUT", "30"))
        mxtoolbox_api_key = os.getenv("MXTOOLBOX_API_KEY", MxToolboxConfig.api_key)

        return cls(
            zonemaster=ZonemasterConfig(
                base_url=zm_base_url,
                request_timeout=zm_timeout,
                poll_interval_seconds=zm_poll_interval,
                max_poll_attempts=zm_max_poll,
                language=zm_language,
            ),
            intodns=IntoDnsConfig(
                base_url=intodns_base_url,
                request_timeout=intodns_timeout,
                language=intodns_language,
            ),
            intodns_ai=IntoDnsAiConfig(
                base_url=intodns_ai_base_url,
                request_timeout=intodns_ai_timeout,
                language=intodns_ai_language,
            ),
            mxtoolbox=MxToolboxConfig(
                base_url=mxtoolbox_base_url,
                request_timeout=mxtoolbox_timeout,
                api_key=mxtoolbox_api_key,
            ),
            default_output_format=os.getenv("DNSTOOL_OUTPUT_FORMAT", "json"),
        )