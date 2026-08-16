import httpx
from src.config import settings

async def query_securonix(spotter_query: str) -> dict:
    if not (settings.SECURONIX_HOST and settings.SECURONIX_API_TOKEN):
        return {"status": "unconfigured", "data": []}

    url = f"https://{settings.SECURONIX_HOST}/ws/spotter/query"
    headers = {"token": settings.SECURONIX_API_TOKEN}
    payload = {"query": spotter_query}

    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(url, json=payload, headers=headers, timeout=20.0)
            return {"status": "success", "results": res.json()}
    except Exception as e:
        return {"status": "error", "error": str(e)}
