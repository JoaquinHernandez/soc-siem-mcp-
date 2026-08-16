import httpx
from src.config import settings

async def query_qradar(aql: str) -> dict:
    if not (settings.QRADAR_HOST and settings.QRADAR_SEC_TOKEN):
        return {"status": "unconfigured", "data": []}

    url = f"https://{settings.QRADAR_HOST}/api/ariel/searches"
    headers = {
        "SEC": settings.QRADAR_SEC_TOKEN,
        "Version": "19.0",
        "Accept": "application/json"
    }
    
    try:
        async with httpx.AsyncClient(verify=settings.QRADAR_VERIFY_SSL) as client:
            res = await client.post(url, params={"query_expression": aql}, headers=headers, timeout=20.0)
            return {"status": "search_dispatched", "response": res.json()}
    except Exception as e:
        return {"status": "error", "error": str(e)}
