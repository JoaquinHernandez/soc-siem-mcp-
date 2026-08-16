import httpx
from src.config import settings

async def get_wazuh_jwt() -> str:
    url = f"https://{settings.WAZUH_API_HOST}:{settings.WAZUH_API_PORT}/security/user/authenticate"
    try:
        async with httpx.AsyncClient(verify=settings.WAZUH_VERIFY_SSL) as client:
            res = await client.post(url, auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD), timeout=10.0)
            return res.json().get("data", {}).get("token", "")
    except Exception:
        return ""

async def query_wazuh(search_term: str) -> dict:
    if not settings.WAZUH_API_HOST:
        return {"status": "unconfigured", "data": []}
    
    jwt = await get_wazuh_jwt()
    if not jwt:
        return {"status": "auth_failed", "error": "Wazuh JWT authentication failed"}

    url = f"https://{settings.WAZUH_API_HOST}:{settings.WAZUH_API_PORT}/alerts"
    headers = {"Authorization": f"Bearer {jwt}"}
    params = {"q": f"data.srcip={search_term}", "limit": 15}

    try:
        async with httpx.AsyncClient(verify=settings.WAZUH_VERIFY_SSL) as client:
            res = await client.get(url, params=params, headers=headers, timeout=15.0)
            data = res.json().get("data", {})
            return {"status": "success", "items": data.get("affected_items", [])}
    except Exception as e:
        return {"status": "error", "error": str(e)}
