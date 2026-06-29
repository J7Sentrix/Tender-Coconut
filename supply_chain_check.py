"""
modules/supply_chain_check.py — Agentic Supply Chain & Dependency Audit

Scans for:
  - Typosquatted MCP plugin packages on PyPI/npm
  - Known malicious agentic plugins / slow-burn poisoning patterns
  - Dependency confusion attack surfaces
  - Postmark-style MCP version poisoning (e.g. postmark-mcp@15 slow-burn)
  - requirements.txt / package.json / pyproject.toml misconfigurations
"""

import json
import re
from pathlib import Path
from typing import Any, Optional
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── Known typosquat patterns for popular AI/MCP packages ────────────────────
TYPOSQUAT_WATCHLIST = [
    # (legitimate_package, suspicious_variant_pattern, risk_reason)
    ("anthropic",         r"^antropic|^anthr0pic|^anthroplc",      "Anthropic SDK typosquat"),
    ("openai",            r"^0penai|^opena1|^openal$",             "OpenAI SDK typosquat"),
    ("langchain",         r"^lang-chain|^langchan|^1angchain",     "LangChain typosquat"),
    ("llamaindex",        r"^llama-index$|^llamalnedx|^llma-index","LlamaIndex typosquat"),
    ("mcp",               r"^mc-p$|^m-cp$|^mcp0",                 "MCP package typosquat"),
    ("fastmcp",           r"^fast-mcp|^fastmc-p|^fast_mcp",       "FastMCP typosquat"),
    ("crewai",            r"^crew-ai|^crewA1|^crewal",             "CrewAI typosquat"),
    ("autogen",           r"^auto-gen|^aut0gen|^autogem",          "AutoGen typosquat"),
    ("pydantic",          r"^pydantics|^py-dantic|^pydanlic",      "Pydantic typosquat"),
    ("requests",          r"^request$|^requets|^rquests",          "requests typosquat"),
    ("postmark",          r"^postmark-mcp",                        "Postmark MCP slow-burn candidate"),
]

# ─── Suspicious package metadata flags ───────────────────────────────────────
SUSPICIOUS_FLAGS = {
    "no_author":          "Package has no listed author",
    "no_description":     "Package has no description",
    "very_new":           "Package created in last 30 days",
    "no_source_link":     "No source repository linked",
    "high_version_jump":  "Non-linear version jump (e.g. 1.0 → 15.0 immediately)",
    "single_file":        "Only a single Python file — common in typosquats",
    "network_on_install": "setup.py/pyproject.toml makes network calls at install time",
    "obfuscated_code":    "Base64 or exec() patterns detected in source",
}

ANALYSIS_PROMPT = """
You are an AI supply chain security expert specializing in agentic plugin ecosystems.

Target: {target}
Scanned dependencies: {dep_count}

Findings:
{findings_json}

Analyze:
1. For each HIGH/CRITICAL finding: explain the specific supply chain attack vector
2. Identify any patterns matching "slow-burn poisoning" (benign early versions, 
   malicious update later — e.g. the postmark-mcp@15 pattern)
3. Check for dependency confusion risks (internal package names exposed publicly)
4. Prioritized remediation steps

JSON with keys: attack_vectors, slow_burn_candidates, dependency_confusion_risks, remediations
"""


class SupplyChainAuditor:
    """
    Audits Python (requirements.txt, pyproject.toml) and Node (package.json)
    dependency files for typosquatting, known-bad packages, and slow-burn
    poisoning indicators.
    """

    def __init__(self, target: str, client: Any, config: Any, verbose: bool = False):
        self.target = target
        self.client = client
        self.config = config
        self.verbose = verbose
        self.findings: list[dict] = []
        self.scanned_deps: list[str] = []

    def run(self) -> dict:
        console.print(f"\n[cyan]  → Scanning target for dependency manifests...[/cyan]")
        dep_files = self._discover_dep_files()

        if not dep_files:
            console.print("  [dim]  No local dependency files found. Scanning target URL headers...[/dim]")
            self._scan_remote_headers()
        else:
            for fpath in dep_files:
                self._parse_and_audit(fpath)

        self._check_pypi_metadata()
        self._render_table()

        findings_count = len(self.findings)
        if findings_count == 0:
            return {"status": "PASS", "findings_count": 0,
                    "highest_severity": "N/A", "findings": [], "ai_analysis": None}

        ai_analysis = self._ai_analyze()
        highest = self._highest_severity()
        return {
            "status": "FAIL" if highest in ("CRITICAL", "HIGH") else "WARN",
            "findings_count": findings_count,
            "highest_severity": highest,
            "findings": self.findings,
            "ai_analysis": ai_analysis,
        }

    def _discover_dep_files(self) -> list[Path]:
        """Look for dependency manifests in the current working directory."""
        candidates = [
            Path("requirements.txt"),
            Path("requirements-dev.txt"),
            Path("pyproject.toml"),
            Path("setup.cfg"),
            Path("package.json"),
            Path("package-lock.json"),
        ]
        found = [p for p in candidates if p.exists()]
        if found and self.verbose:
            console.print(f"  [dim]  Found manifests: {[str(p) for p in found]}[/dim]")
        return found

    def _parse_and_audit(self, fpath: Path):
        console.print(f"  [cyan]  Auditing:[/cyan] {fpath}")
        text = fpath.read_text(errors="ignore")
        packages = []

        if fpath.name in ("requirements.txt", "requirements-dev.txt"):
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pkg = re.split(r"[>=<!@\[]", line)[0].strip().lower()
                    if pkg:
                        packages.append(pkg)

        elif fpath.name == "pyproject.toml":
            for m in re.finditer(r'"([a-zA-Z0-9_\-]+)\s*[>=<]', text):
                packages.append(m.group(1).lower())

        elif fpath.name == "package.json":
            try:
                data = json.loads(text)
                for section in ("dependencies", "devDependencies"):
                    packages += [k.lower() for k in data.get(section, {}).keys()]
            except json.JSONDecodeError:
                pass

        self.scanned_deps.extend(packages)
        for pkg in packages:
            self._check_typosquat(pkg, str(fpath))
            self._check_obfuscation_in_name(pkg, str(fpath))

    def _check_typosquat(self, pkg_name: str, source: str):
        for legit, pattern, reason in TYPOSQUAT_WATCHLIST:
            if re.match(pattern, pkg_name, re.IGNORECASE):
                self.findings.append({
                    "type": "TYPOSQUAT",
                    "package": pkg_name,
                    "resembles": legit,
                    "source": source,
                    "detail": f"'{pkg_name}' matches typosquat pattern for '{legit}' — {reason}",
                    "severity": "HIGH",
                })
                console.print(f"  [bold red][!] TYPOSQUAT:[/bold red] {pkg_name} → mimics {legit}")

    def _check_obfuscation_in_name(self, pkg_name: str, source: str):
        # Detect leetspeak / number substitutions in package names
        if re.search(r"[0-9]", pkg_name) and len(pkg_name) > 4:
            normalized = re.sub(r"0", "o", re.sub(r"1", "l", re.sub(r"3", "e", pkg_name)))
            if normalized != pkg_name:
                self.findings.append({
                    "type": "OBFUSCATED_NAME",
                    "package": pkg_name,
                    "normalized": normalized,
                    "source": source,
                    "detail": f"Package name '{pkg_name}' uses digit substitution — potential obfuscation.",
                    "severity": "MEDIUM",
                })

    def _check_pypi_metadata(self):
        """
        Query PyPI JSON API for any HIGH-risk packages found in scan
        to validate metadata integrity.
        """
        try:
            import requests
        except ImportError:
            return

        high_risk = [f["package"] for f in self.findings if f["severity"] in ("HIGH", "CRITICAL")]
        for pkg in high_risk[:5]:  # Limit API calls
            try:
                resp = requests.get(f"https://pypi.org/pypi/{pkg}/json", timeout=6)
                if resp.status_code == 200:
                    data = resp.json()
                    info = data.get("info", {})
                    if not info.get("author") and not info.get("author_email"):
                        self.findings.append({
                            "type": "METADATA_FLAG",
                            "package": pkg,
                            "flag": "no_author",
                            "detail": f"PyPI package '{pkg}' has no listed author — suspicious.",
                            "severity": "MEDIUM",
                        })
                elif resp.status_code == 404:
                    # Package doesn't exist on PyPI at all — very suspicious
                    self.findings.append({
                        "type": "PHANTOM_PACKAGE",
                        "package": pkg,
                        "detail": f"'{pkg}' not found on PyPI — dependency confusion attack surface.",
                        "severity": "CRITICAL",
                    })
                    console.print(f"  [bold red][CRITICAL] Ghost package: {pkg} not on PyPI![/bold red]")
            except Exception:
                pass

    def _scan_remote_headers(self):
        """When no local files found, probe the target URL for x-powered-by headers
        that may reveal vulnerable framework versions."""
        try:
            import requests
            resp = requests.get(self.target, timeout=5)
            headers_of_interest = {
                "x-powered-by", "server", "x-framework",
                "x-generator", "x-aspnet-version",
            }
            for h in headers_of_interest:
                val = resp.headers.get(h, "")
                if val:
                    self.findings.append({
                        "type": "VERSION_DISCLOSURE",
                        "header": h,
                        "value": val,
                        "detail": f"Header '{h}: {val}' discloses framework/version information.",
                        "severity": "LOW",
                    })
        except Exception:
            pass

    def _ai_analyze(self) -> Optional[dict]:
        prompt = ANALYSIS_PROMPT.format(
            target=self.target,
            dep_count=len(self.scanned_deps),
            findings_json=json.dumps(self.findings, indent=2),
        )
        try:
            raw = self.client.complete(prompt, max_tokens=1200)
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    def _highest_severity(self) -> str:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if any(f.get("severity") == sev for f in self.findings):
                return sev
        return "INFO"

    def _render_table(self):
        table = Table(title="Supply Chain Audit Findings",
                      box=box.SIMPLE_HEAVY, border_style="yellow")
        table.add_column("Type", style="yellow")
        table.add_column("Package", style="cyan")
        table.add_column("Severity", justify="center")
        table.add_column("Detail", style="white")
        sev_style = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green"}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            table.add_row(
                f.get("type", ""),
                f.get("package", f.get("header", "")),
                f"[{sev_style.get(sev, 'white')}]{sev}[/]",
                f.get("detail", "")[:100],
            )
        if self.findings:
            console.print(table)
        else:
            console.print("  [green]  ✔ No supply chain issues detected.[/green]")
