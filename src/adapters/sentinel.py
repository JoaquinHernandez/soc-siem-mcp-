import httpx
from src.config import settings

async def get_azure_token() -> str:
    """Authenticates against Microsoft Entra ID via Client Credentials."""
    if not (settings.SENTINEL_TENANT_ID and settings.SENTINEL_CLIENT_ID and settings.SENTINEL_CLIENT_SECRET):
        return ""
    
    url = f"https://login.microsoftonline.com/{settings.SENTINEL_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": settings.SENTINEL_CLIENT_ID,
        "client_secret": settings.SENTINEL_CLIENT_SECRET,
        "scope": "https://api.loganalytics.io/.default"
    }
    async with httpx.AsyncClient() as client:
        res = await client.post(url, data=data, timeout=10.0)
        return res.json().get("access_token", "")

async def query_sentinel(kql: str, timespan: str = "P1D") -> dict:
    if not settings.SENTINEL_WORKSPACE_ID:
        return {"status": "unconfigured", "data": []}
    
    token = await get_azure_token()
    if not token:
        return {"status": "auth_failed", "error": "Could not obtain Azure Entra ID token"}

    url = f"https://api.loganalytics.io/v1/workspaces/{settings.SENTINEL_WORKSPACE_ID}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"query": kql, "timespan": timespan}
    
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, headers=headers, timeout=25.0)
            data = res.json()
            tables = data.get("tables", [])
            if not tables:
                return {"status": "success", "count": 0, "rows": []}
            
            columns = [c["name"] for c in tables[0].get("columns", [])]
            rows = [dict(zip(columns, row)) for row in tables[0].get("rows", [])]
            return {"status": "success", "count": len(rows), "rows": rows[:20]}
    except Exception as e:
        return {"status": "error", "error": str(e)}
