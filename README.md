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

ChatGPT / AI Aura / Gemini
Run the server in SSE mode (MCP_TRANSPORT=sse on port 8000).

Expose the port (or use Cloudflare Tunnel/ngrok).

Connect your assistant to: https://<your-domain>/sse (or import /openapi.json into Custom GPT Actions).


---

### 9. Git Commands to Push to GitHub

Run these commands in your project root directory:

```bash
# 1. Initialize git
git init -b main

# 2. Add all files
git add .

# 3. Create initial commit
git commit -m "feat: initial release of SOC Threat Hunting SIEM MCP Gateway"

# 4. Link to your GitHub repository
git remote add origin https://github.com/<your-username>/soc-siem-mcp.git

# 5. Push to GitHub
git push -u origin main
