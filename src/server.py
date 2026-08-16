import asyncio
import httpx
from mcp.server.fastmcp import FastMCP
from src.config import settings
from src.adapters import (
    query_sentinel,
    query_splunk,
    query_wazuh,
    query_qradar,
    query_securonix
)

mcp = FastMCP("SOC-ThreatHunter-SIEM-MCP")

# =======================================================
# TOOL 1: GLOBAL IOC HUNTING ACROSS ALL SIEMS
# =======================================================
@mcp.tool()
async def hunt_ioc_across_all_siems(indicator: str, ioc_type: str = "ip", timeframe: str = "-24h") -> dict:
    """
    Simultaneously hunt for an IP, domain, hash, or username across Azure Sentinel,
    Splunk, Wazuh, QRadar, and Securonix to locate threat actors.
    """
    sentinel_kql = f"search in (DeviceNetworkEvents, DeviceFileEvents, SigninLogs) '{indicator}' | take 20"
    splunk_spl = f"'{indicator}' | head 20"
    qradar_aql = f"SELECT * FROM events WHERE UTF8(payload) LIKE '%{indicator}%' LAST 24 HOURS"
    securonix_spot = f"index = activity and query = {indicator}"

    results = await asyncio.gather(
        query_sentinel(sentinel_kql),
        query_splunk(splunk_spl, earliest_time=timeframe),
        query_wazuh(indicator),
        query_qradar(qradar_aql),
        query_securonix(securonix_spot),
        return_exceptions=True
    )

    return {
        "indicator": indicator,
        "ioc_type": ioc_type,
        "sentinel": results[0] if not isinstance(results[0], Exception) else str(results[0]),
        "splunk": results[1] if not isinstance(results[1], Exception) else str(results[1]),
        "wazuh": results[2] if not isinstance(results[2], Exception) else str(results[2]),
        "qradar": results[3] if not isinstance(results[3], Exception) else str(results[3]),
        "securonix": results[4] if not isinstance(results[4], Exception) else str(results[4]),
    }

# =======================================================
# TOOL 2: CTI & THREAT ACTOR ENRICHMENT
# =======================================================
@mcp.tool()
async def enrich_and_attribute_actor(ioc: str, ioc_type: str = "ip") -> dict:
    """
    Enriches an indicator against VirusTotal / CTI to identify malicious reputation,
    associated APT threat groups, and campaign tags.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured"}

    url = (
        f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        if ioc_type == "ip"
        else f"https://www.virustotal.com/api/v3/files/{ioc}"
    )
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=10.0)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                return {
                    "indicator": ioc,
                    "malicious_score": data.get("last_analysis_stats", {}).get("malicious", 0),
                    "reputation": data.get("reputation", 0),
                    "threat_actor_tags": data.get("tags", [])[:10],
                    "as_owner": data.get("as_owner", "N/A")
                }
            return {"indicator": ioc, "message": "No CTI record found."}
    except Exception as e:
        return {"error": str(e)}

# =======================================================
# TOOL 3: MITRE ATT&CK TTP HUNTING
# =======================================================
@mcp.tool()
async def hunt_mitre_technique(mitre_id: str, platform: str = "sentinel") -> dict:
    """
    Executes behavioral hunts for MITRE ATT&CK techniques:
    - T1059.001 (PowerShell Execution)
    - T1003 (OS Credential Dumping / LSASS)
    - T1078 (Valid Accounts / Suspicious Signins)
    """
    ttp_kql = {
        "T1059.001": "DeviceProcessEvents | where FileName in~ ('powershell.exe', 'pwsh.exe') and ProcessCommandLine has_any ('-enc', '-encodedcommand', 'bypass') | take 20",
        "T1003": "DeviceProcessEvents | where FileName in~ ('mimikatz.exe', 'procdump.exe') or ProcessCommandLine has 'lsass' | take 20",
        "T1078": "SigninLogs | where ResultType == 0 and NetworkLocationDetails contains 'Unknown' | take 20"
    }

    query = ttp_kql.get(mitre_id)
    if not query:
        return {"error": f"Technique {mitre_id} not mapped in hunt table."}

    if platform.lower() == "sentinel":
        return await query_sentinel(query)
    else:
        return {"error": f"Platform '{platform}' not yet supported for automated TTP mapping."}

# =======================================================
# RUN ENTRYPOINT
# =======================================================
if __name__ == "__main__":
    if settings.MCP_TRANSPORT == "sse":
        mcp.run(transport="sse", host=settings.MCP_HOST, port=settings.MCP_PORT)
    else:
        mcp.run(transport="stdio")
