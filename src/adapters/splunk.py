import httpx
from src.config import settings

async def query_splunk(spl: str, earliest_time: str = "-24h") -> dict:
    if not (settings.SPLUNK_HOST and settings.SPLUNK_TOKEN):
        return {"status": "unconfigured", "data": []}

    url = f"https://{settings.SPLUNK_HOST}:{settings.SPLUNK_PORT}/services/search/v2/jobs/export"
    headers = {"Authorization": f"Splunk {settings.SPLUNK_TOKEN}"}
    params = {
        "search": f"search {spl}" if not spl.strip().startswith("search") else spl,
        "earliest_time": earliest_time,
        "output_mode": "json"
    }

    try:
        async with httpx.AsyncClient(verify=settings.SPLUNK_VERIFY_SSL) as client:
            res = await client.post(url, params=params, headers=headers, timeout=30.0)
            lines = [l for l in res.text.splitlines() if l.strip()]
            return {"status": "success", "count": len(lines), "raw_matches": lines[:15]}
    except Exception as e:
        return {"status": "error", "error": str(e)}
