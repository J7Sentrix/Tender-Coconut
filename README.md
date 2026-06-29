# 🥥 Tender Coconut

> **AI Security Assessment & Adversarial Vulnerability Auditing Framework**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform: Linux/WSL](https://img.shields.io/badge/platform-Linux%20%7C%20WSL-informational.svg)](https://learn.microsoft.com/en-us/windows/wsl/)
[![LLM Engines](https://img.shields.io/badge/engines-Claude%20%7C%20Gemini%20%7C%20Grok%20%7C%20Ollama-green.svg)](#api-setup-guide)

---

Tender Coconut is a **terminal-based, AI-driven security assessment framework** built for red teams, DevSecOps engineers, and AI security researchers. It systematically audits **AI agents, LLM integrations, and Model Context Protocol (MCP) deployments** against a curated library of modern adversarial vulnerabilities — from prompt injection and context amnesia to supply chain typosquatting and cryptographic decay.

Unlike static scanners, Tender Coconut routes its findings through your chosen LLM engine (Claude, Gemini, Grok, or local Ollama) for **AI-interpreted severity analysis and context-aware remediation guidance**.

---

## Table of Contents

- [What Tender Coconut Detects](#what-tender-coconut-detects)
- [Architecture](#architecture)
- [Prerequisites & Installation](#prerequisites--installation)
  - [Linux (Debian / Ubuntu / Kali)](#linux-debian--ubuntu--kali)
  - [Windows Subsystem for Linux (WSL)](#windows-subsystem-for-linux-wsl)
- [API Setup Guide](#api-setup-guide)
  - [Anthropic Claude](#anthropic-claude)
  - [Google Gemini](#google-gemini)
  - [xAI Grok](#xai-grok)
  - [Ollama (Local / Offline)](#ollama-local--offline)
- [Usage](#usage)
  - [Run All Modules](#run-all-modules)
  - [Targeted Module Scans](#targeted-module-scans)
  - [Choosing an LLM Engine](#choosing-an-llm-engine)
  - [Report Output](#report-output)
- [Module Reference](#module-reference)
- [Project Structure](#project-structure)
- [Responsible Use](#responsible-use)
- [Contributing](#contributing)
- [License](#license)

---

## What Tender Coconut Detects

Tender Coconut maps directly to the adversarial vulnerability taxonomy shown below. Each module targets a distinct attack surface in modern AI deployments:

| Module Key | Scanner | Vulnerabilities Covered |
|:---:|:---|:---|
| `mcp` | MCP Protocol Audit | Unauthenticated SSE streams, tool enumeration leakage, zero-auth JSON-RPC endpoints, prompt injection via MCP prompt templates |
| `prompt` | Prompt Robustness | Direct injection, indirect injection via documents/JSON/email, role-play jailbreaks, Base64/hex/leetspeak encoding attacks, system prompt leakage |
| `context` | Context Boundary | Instruction amnesia under context flooding, late-turn override, incremental compliance escalation, fake compression directives |
| `supply` | Supply Chain | PyPI/npm typosquatting, slow-burn dependency poisoning, phantom packages (dependency confusion), obfuscated package names |
| `crypto` | Crypto Creep | MD5/SHA-1 usage, RSA < 2048-bit, RC4/DES, hardcoded secrets, JWT `none` algorithm, weak PBKDF2 iterations, deprecated TLS versions |

---

## Architecture

```
tender_coconut/
├── tender_coconut.py        # CLI entry point (Click)
├── core/
│   └── config.py            # API key management & LLM client factories
├── modules/
│   ├── mcp_audit.py         # MCP endpoint discovery & auth audit
│   ├── prompt_robustness.py # 15-test prompt injection battery
│   ├── context_boundary.py  # Multi-turn context retention tests
│   ├── supply_chain_check.py# Dependency & typosquat scanner
│   └── crypto_creep.py      # Cryptographic weakness static analysis
├── reports/                 # Auto-generated JSON scan reports
├── tests/                   # Unit tests
└── requirements.txt
```

Each scanning module:
1. **Runs autonomous probes** against the target (HTTP, static analysis, pattern matching)
2. **Collects structured findings** with severity classifications
3. **Sends findings to the selected LLM engine** for contextual analysis and remediation advice
4. **Returns a normalized result dict** that feeds the summary table and JSON report

---

## Prerequisites & Installation

### Linux (Debian / Ubuntu / Kali)

**1. System dependencies**

```bash
sudo apt update && sudo apt install -y \
    python3 python3-pip python3-venv \
    git curl nmap
```

**2. Clone the repository**

```bash
git clone https://github.com/J7Sentrix/tender-coconut.git
cd tender-coconut
```

**3. Create and activate a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**4. Install Python dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**5. Verify installation**

```bash
python tender_coconut.py list-engines
```

---

### Windows Subsystem for Linux (WSL)

WSL2 with Ubuntu 22.04 LTS is the recommended Windows environment.

**1. Enable WSL2 (PowerShell — run as Administrator)**

```powershell
wsl --install -d Ubuntu-22.04
wsl --set-default-version 2
```

Restart your machine when prompted, then open the Ubuntu terminal.

**2. Inside your WSL Ubuntu terminal**

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git curl
```

**3. Clone, create venv, and install**

```bash
git clone https://github.com/J7Sentrix/tender-coconut.git
cd tender-coconut
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**4. Windows Defender / Firewall note**

If Tender Coconut's network probes are blocked, add a Windows Defender Firewall rule for your WSL IP range, or run scans from within the WSL environment where host firewall rules don't apply.

---

## API Setup Guide

Tender Coconut reads credentials from **environment variables**. Never hardcode keys in source files.

Create a `.env` file in the project root (already in `.gitignore`):

```bash
touch .env
chmod 600 .env
```

---

### Anthropic Claude

1. Get your key at [console.anthropic.com](https://console.anthropic.com/settings/keys)
2. Add to `.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

3. Load and verify:

```bash
source .env
python tender_coconut.py list-engines
# Should show ✔ next to "claude"
```

---

### Google Gemini

1. Get your key at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Add to `.env`:

```bash
GOOGLE_API_KEY=AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

---

### xAI Grok

1. Get your key at [console.x.ai](https://console.x.ai)
2. Add to `.env`:

```bash
XAI_API_KEY=xai-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Grok uses an OpenAI-compatible endpoint. No additional client library is needed beyond `openai`.

---

### Ollama (Local / Offline)

Ollama lets you run models entirely offline — no API key required.

**1. Install Ollama**

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

**2. Pull a model**

```bash
ollama pull llama3        # 8B parameter default
# or
ollama pull mistral       # 7B alternative
ollama pull codellama     # Code-focused model
```

**3. Set host (optional — defaults to localhost)**

```bash
# For default local setup, nothing is required.
# For a remote Ollama server:
export OLLAMA_HOST=http://192.168.1.100:11434
```

**4. Verify Ollama is running**

```bash
ollama list
curl http://localhost:11434/api/tags
```

---

### Loading environment variables

Source your `.env` file before running scans:

```bash
source .env

# Or use a tool like direnv for automatic loading:
# sudo apt install direnv && direnv allow
```

---

## Usage

### Run All Modules

Full assessment against a local AI deployment:

```bash
python tender_coconut.py scan \
    --target http://localhost:3000 \
    --modules all \
    --engine claude
```

---

### Targeted Module Scans

Run only specific modules by passing comma-separated keys:

```bash
# MCP endpoint audit only
python tender_coconut.py scan -t http://localhost:3000 -m mcp -e claude

# Prompt injection + context boundary (no network scanning)
python tender_coconut.py scan -t http://api.example.com -m prompt,context -e gemini

# Supply chain audit using local Ollama model
python tender_coconut.py scan -t http://localhost:8000 -m supply -e ollama --model mistral

# Crypto audit with verbose output and saved report
python tender_coconut.py scan \
    -t https://my-ai-app.example.com \
    -m crypto \
    -e claude \
    --verbose \
    --output reports/crypto_audit_$(date +%Y%m%d).json
```

---

### Choosing an LLM Engine

```bash
# List all engines and their configuration status
python tender_coconut.py list-engines

# Use Grok for analysis with a specific model override
python tender_coconut.py scan -t http://target.local -m all -e grok --model grok-2-latest

# Use Ollama offline (no internet required for analysis)
python tender_coconut.py scan -t http://localhost:3000 -m mcp,crypto -e ollama --model llama3
```

---

### Report Output

All scans auto-generate a timestamped JSON report in `reports/`. To specify a custom path:

```bash
python tender_coconut.py scan \
    -t http://target.example.com \
    -m all \
    -e claude \
    --output reports/client_assessment_2026-06-28.json
```

Report structure:

```json
{
  "tool": "Tender Coconut",
  "version": "1.0.0",
  "generated_at": "2026-06-28T14:30:00Z",
  "results": {
    "mcp": {
      "status": "FAIL",
      "findings_count": 3,
      "highest_severity": "CRITICAL",
      "findings": [...],
      "ai_analysis": {
        "severity_summary": "...",
        "attack_vectors": [...],
        "remediations": [...]
      }
    }
  }
}
```

---

### List Available Modules

```bash
python tender_coconut.py list-modules
```

---

## Module Reference

### `mcp` — MCP Protocol Audit

Probes for the class of vulnerability documented by Trend Micro (2025): unprotected MCP servers accessible without authentication. Tests include:

- Scanning 10+ common MCP URL patterns (`/mcp`, `/sse`, `/mcp/tools/list`, etc.)
- Port knocking on common MCP listener ports (3000, 8000, 8080, etc.)
- Unauthenticated SSE stream detection
- `tools/list` JSON-RPC call without bearer token
- `prompts/list` inspection for injection-prone argument definitions

### `prompt` — Prompt Robustness

15-test adversarial battery covering 5 attack categories:

| Category | Tests | Examples |
|:---|:---:|:---|
| DIRECT | 5 | Classic override, ChatML injection, Base64 smuggling |
| INDIRECT | 3 | Document summarization, JSON processing, HTML comment |
| ROLEPLAY | 2 | Persona hijacking, fiction framing |
| LEAKAGE | 3 | Verbatim repeat, direct question, sentence completion |
| OBFUSCATION | 2 | Hex encoding, leetspeak substitution |

### `context` — Context Boundary

4 multi-turn conversation simulations:

- **CB-01** Context Flood: 8 filler blocks pushed between safety anchor and verification
- **CB-02** Late-Turn Override: benign conversation → trust establishment → override attempt
- **CB-03** Escalation: gradual normalization toward harmful content
- **CB-04** Compression Directive: fake `[CONTEXT COMPRESSION ACTIVE]` instruction injection

### `supply` — Supply Chain Audit

- Parses `requirements.txt`, `pyproject.toml`, `package.json`
- Matches 10 typosquat watchlist patterns (Anthropic, OpenAI, MCP, LangChain, etc.)
- PyPI metadata validation for found packages
- Phantom package detection (dependency confusion)
- Remote header version disclosure (fallback when no local files found)

### `crypto` — Crypto Creep

11 static analysis pattern categories + live TLS/JWT checks:

- MD5, SHA-1, RC4, DES/3DES usage
- Weak RSA key generation (< 2048-bit)
- Hardcoded secrets via regex heuristics
- JWT `none` algorithm and HMAC algorithm concerns
- Non-cryptographic RNG in security contexts
- Quantum-vulnerable key exchange (P-192, 1024-bit DH)
- Live TLS version negotiation check
- JWT algorithm header inspection on auth endpoints

---

## Project Structure

```
tender-coconut/
├── tender_coconut.py         # Main CLI (Click) — entry point for all commands
├── core/
│   ├── __init__.py
│   └── config.py             # TenderCoconutConfig — API key loading, client factories
│                             # Client wrappers: Anthropic, Gemini, Grok, Ollama
├── modules/
│   ├── __init__.py
│   ├── mcp_audit.py          # MCPAuditScanner
│   ├── prompt_robustness.py  # PromptRobustnessTest
│   ├── context_boundary.py   # ContextBoundaryCheck
│   ├── supply_chain_check.py # SupplyChainAuditor
│   └── crypto_creep.py       # CryptoCreepAnalyzer
├── reports/                  # Auto-generated JSON scan reports (gitignored)
├── tests/
│   ├── __init__.py
│   └── test_*.py             # Unit tests (pytest)
├── .env                      # API keys — never commit (gitignored)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Extending Tender Coconut

Adding a new module takes three steps:

**1. Create `modules/my_module.py`** with a class that accepts `(target, client, config, verbose)` and implements a `run() -> dict` method returning:

```python
{
    "status": "PASS" | "FAIL" | "WARN",
    "findings_count": int,
    "highest_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "N/A",
    "findings": [...],
    "ai_analysis": {...} | None,
}
```

**2. Register it** in `tender_coconut.py`:

```python
MODULES = {
    ...
    "mymod": ("modules.my_module", "MyModuleClass", "My Module Description"),
}
```

**3. Run it:**

```bash
python tender_coconut.py scan -t http://target -m mymod -e claude
```

---

## Responsible Use

Tender Coconut is designed for **authorized security assessments only**.

- Always obtain **explicit written permission** before scanning any system you do not own
- MCP endpoint probes and prompt injection tests may trigger security alerts or rate limits on target systems
- Supply chain scans make live queries to PyPI — use `--offline` flag (coming soon) for air-gapped environments
- Do not use Tender Coconut against production systems without a maintenance window and rollback plan
- AI-generated analysis from LLM backends is **advisory only** — validate all findings before acting

This tool is provided for **defensive research, internal red-teaming, and AI system hardening**.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for new modules.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-new-module`
3. Follow the existing module interface pattern
4. Add tests in `tests/`
5. Submit a pull request with a clear description of the new attack surface covered

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

<div align="center">
<strong>Tender Coconut</strong> — Built for AI defenders, by AI defenders.
</div>
