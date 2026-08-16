# soc-siem-mcp-

soc-siem-mcp/
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
└── src/
    ├── __init__.py
    ├── config.py
    ├── server.py
    └── adapters/
        ├── __init__.py
        ├── sentinel.py
        ├── splunk.py
        ├── wazuh.py
        ├── qradar.py
        └── securonix.py

        mcp>=1.0.0
fastmcp>=0.1.0
httpx>=0.27.0
pydantic>=2.0.0
pydantic-settings>=2.0.0
python-dotenv>=1.0.0
uvicorn>=0.30.0
