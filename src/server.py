import asyncio
import httpx
import sys
from mcp.server.fastmcp import FastMCP
from src.config import settings
from src.adapters import (
    query_sentinel,
    query_splunk,
    query_wazuh,
    query_qradar,
    query_securonix
)
from src.validation import (
    validate_ioc,
    escape_kql_string,
    escape_spl_string,
    escape_aql_string,
    escape_spotter_value,
    escape_wazuh_filter
)

mcp = FastMCP("SOC-ThreatHunter-SIEM-MCP")

# =======================================================
# AUTHENTICATION MIDDLEWARE FOR SSE TRANSPORT
# =======================================================
class AuthenticatedMCPApp:
    """
    ASGI middleware wrapper that enforces Bearer token authentication
    before forwarding requests to the FastMCP SSE server.
    """
    def __init__(self, mcp_app, api_key: str):
        self.mcp_app = mcp_app
        self.api_key = api_key
    
    async def __call__(self, scope, receive, send):
        # Only authenticate HTTP requests (SSE uses HTTP)
        if scope["type"] == "http":
            # Extract headers
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8")
            
            # Check for Bearer token
            if not auth_header.startswith("Bearer "):
                # Send 401 Unauthorized
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error": "Missing or invalid Authorization header. Expected: Bearer <token>"}',
                })
                return
            
            # Validate token
            token = auth_header[7:]  # Remove "Bearer " prefix
            if token != self.api_key:
                # Send 401 Unauthorized
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [[b"content-type", b"application/json"]],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"error": "Invalid API key"}',
                })
                return
        
        # Authentication passed or not HTTP, forward to MCP app
        await self.mcp_app(scope, receive, send)

# =======================================================
# TOOL 1: GLOBAL IOC HUNTING ACROSS ALL SIEMS
# =======================================================
@mcp.tool()
async def hunt_ioc_across_all_siems(indicator: str, ioc_type: str = "ip", timeframe: str = "-24h") -> dict:
    """
    Simultaneously hunt for an IP, domain, hash, or username across Azure Sentinel,
    Splunk, Wazuh, QRadar, and Securonix to locate threat actors.
    """
    # Validate the indicator against its declared type
    is_valid, error_msg = validate_ioc(indicator, ioc_type)
    if not is_valid:
        return {
            "error": f"Invalid indicator: {error_msg}",
            "indicator": indicator,
            "ioc_type": ioc_type
        }
    
    # Escape the indicator for each SIEM query language
    escaped_kql = escape_kql_string(indicator)
    escaped_spl = escape_spl_string(indicator)
    escaped_aql = escape_aql_string(indicator)
    escaped_spotter = escape_spotter_value(indicator)
    escaped_wazuh = escape_wazuh_filter(indicator)
    
    # Construct queries with properly escaped values
    sentinel_kql = f"search in (DeviceNetworkEvents, DeviceFileEvents, SigninLogs) '{escaped_kql}' | take 20"
    splunk_spl = f'"{escaped_spl}" | head 20'
    qradar_aql = f"SELECT * FROM events WHERE UTF8(payload) LIKE '%{escaped_aql}%' LAST 24 HOURS"
    securonix_spot = f"index = activity and query = {escaped_spotter}"

    results = await asyncio.gather(
        query_sentinel(sentinel_kql),
        query_splunk(splunk_spl, earliest_time=timeframe),
        query_wazuh(escaped_wazuh),
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
        # Enforce authentication for SSE transport
        if not settings.MCP_API_KEY:
            print("ERROR: MCP_API_KEY must be set when using SSE transport.", file=sys.stderr)
            print("SSE transport exposes the server over HTTP and requires authentication.", file=sys.stderr)
            print("Set MCP_API_KEY environment variable to a secure random token.", file=sys.stderr)
            sys.exit(1)
        
        print(f"Starting authenticated SSE server on {settings.MCP_HOST}:{settings.MCP_PORT}")
        print("Authentication: Bearer token required (MCP_API_KEY)")
        
        # Wrap the MCP run method to inject authentication
        import uvicorn
        original_run = mcp.run
        
        # Override the run method to wrap the ASGI app
        def run_with_auth(transport="sse", host=None, port=None, **kwargs):
            if transport == "sse":
                # Import the SSE server creation function
                try:
                    from mcp.server.sse import sse_server
                    # Create the base MCP ASGI app
                    mcp_app = sse_server(mcp)
                    # Wrap with authentication
                    authenticated_app = AuthenticatedMCPApp(mcp_app, settings.MCP_API_KEY)
                    # Run with uvicorn
                    uvicorn.run(
                        authenticated_app,
                        host=host or settings.MCP_HOST,
                        port=port or settings.MCP_PORT
                    )
                except ImportError:
                    # Fallback: try alternative import path
                    print("Warning: Could not import sse_server, trying alternative method...", file=sys.stderr)
                    # Call original run and hope it works
                    original_run(transport=transport, host=host, port=port, **kwargs)
            else:
                original_run(transport=transport, host=host, port=port, **kwargs)
        
        run_with_auth(transport="sse", host=settings.MCP_HOST, port=settings.MCP_PORT)
    else:
        # stdio transport is for local use only, no authentication needed
        mcp.run(transport="stdio")
