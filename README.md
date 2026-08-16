# soc-siem-mcp-
# 🛡️ SOC & Threat Hunting Unified SIEM MCP Gateway

A Model Context Protocol (MCP) server that empowers AI Assistants (**Claude, ChatGPT, Gemini, and AI Aura**) to perform SOC operations, investigate alerts, and hunt malicious actors across **Azure Sentinel, Splunk, Wazuh, IBM QRadar, and Securonix**.

---

## 🚀 Features

- **Cross-SIEM IOC Hunting:** Fan-out queries across all SIEM engines simultaneously to detect lateral movement.
- **MITRE ATT&CK Behavioral Hunts:** Pre-mapped hunts for techniques like PowerShell obfuscation (`T1059.001`) and LSASS dumping (`T1003`).
- **CTI & Threat Actor Attribution:** Automatic threat scoring and APT group tagging via VirusTotal.
- **Dual Transport:** Supports **stdio** (Claude Desktop) and **SSE / HTTP** (ChatGPT, Gemini, AI Aura).

---

## 🛠️ Quickstart

### 1. Clone & Setup
```bash
git clone [https://github.com/](https://github.com/)<your-username>/soc-siem-mcp.git
cd soc-siem-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env****


Run with Docker
Bash
docker-compose up --build -d
