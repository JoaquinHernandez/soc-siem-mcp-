import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Server Config
    MCP_TRANSPORT: str = os.getenv("MCP_TRANSPORT", "sse")
    MCP_PORT: int = int(os.getenv("MCP_PORT", 8000))
    MCP_HOST: str = os.getenv("MCP_HOST", "0.0.0.0")

    # Threat Intel
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # Sentinel
    SENTINEL_WORKSPACE_ID: str = os.getenv("SENTINEL_WORKSPACE_ID", "")
    SENTINEL_TENANT_ID: str = os.getenv("SENTINEL_TENANT_ID", "")
    SENTINEL_CLIENT_ID: str = os.getenv("SENTINEL_CLIENT_ID", "")
    SENTINEL_CLIENT_SECRET: str = os.getenv("SENTINEL_CLIENT_SECRET", "")

    # Splunk
    SPLUNK_HOST: str = os.getenv("SPLUNK_HOST", "")
    SPLUNK_PORT: str = os.getenv("SPLUNK_PORT", "8089")
    SPLUNK_TOKEN: str = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_VERIFY_SSL: bool = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    # Wazuh
    WAZUH_API_HOST: str = os.getenv("WAZUH_API_HOST", "")
    WAZUH_API_PORT: str = os.getenv("WAZUH_API_PORT", "55000")
    WAZUH_USER: str = os.getenv("WAZUH_USER", "")
    WAZUH_PASSWORD: str = os.getenv("WAZUH_PASSWORD", "")
    WAZUH_VERIFY_SSL: bool = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

    # QRadar
    QRADAR_HOST: str = os.getenv("QRADAR_HOST", "")
    QRADAR_SEC_TOKEN: str = os.getenv("QRADAR_SEC_TOKEN", "")
    QRADAR_VERIFY_SSL: bool = os.getenv("QRADAR_VERIFY_SSL", "false").lower() == "true"

    # Securonix
    SECURONIX_HOST: str = os.getenv("SECURONIX_HOST", "")
    SECURONIX_API_TOKEN: str = os.getenv("SECURONIX_API_TOKEN", "")

settings = Settings()
