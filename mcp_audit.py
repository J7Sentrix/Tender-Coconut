"""
modules/mcp_audit.py — MCP Protocol Endpoint Discovery & Security Audit

Scans for exposed or unprotected Model Context Protocol (MCP) endpoints.
Checks for:
  - Unauthenticated SSE/HTTP MCP server exposure
  - Absence of auth headers / bearer tokens
  - Tool enumeration leakage (listing registered tools without auth)
  - Resource exposure via MCP resource primitives
  - Prompt template injection via MCP prompt endpoints
"""

import json
import socket
from typing import Any, Optional
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── Common MCP endpoint paths to probe ──────────────────────────────────────
MCP_PATHS = [
    "/mcp",
    "/mcp/v1",
    "/sse",
    "/mcp/sse",
    "/api/mcp",
    "/v1/mcp",
    "/mcp/tools/list",
    "/mcp/resources/list",
    "/mcp/prompts/list",
    "/.well-known/mcp",
]

# ─── Common unprotected MCP ports discovered in the wild ─────────────────────
COMMON_MCP_PORTS = [3000, 3001, 8000, 8080, 8443, 5000, 6000, 9000]

# ─── AI prompt for deep analysis ─────────────────────────────────────────────
ANALYSIS_PROMPT_TEMPLATE = """
You are an expert AI security auditor specializing in Model Context Protocol (MCP) security.

Below is raw scan data collected from probing MCP endpoints at target: {target}

Scan findings:
{findings_json}

Analyze these findings and provide:
1. SEVERITY assessment (CRITICAL / HIGH / MEDIUM / LOW / INFO) for each finding
2. Specific attack vectors that could be exploited
3. Immediate remediation steps
4. Whether this deployment is at risk of the "492 unprotected MCP servers" class of vulnerability 
   (as documented by Trend Micro in 2025)

Respond in structured JSON with keys: severity_summary, attack_vectors, remediations, risk_class
"""


class MCPAuditScanner:
    """
    Discovers and audits MCP server deployments for security misconfigurations.
    """

    def __init__(self, target: str, client: Any, config: Any, verbose: bool = False):
        self.target = target.rstrip("/")
        self.client = client
        self.config = config
        self.verbose = verbose
        self.findings: list[dict] = []
        self._parsed = urlparse(self.target)
        self.base_host = f"{self._parsed.scheme}://{self._parsed.netloc}"

    # ── Public entry point ─────────────────────────────────────────────────────

    def run(self) -> dict:
        console.print(f"\n[cyan]  → Target:[/cyan] {self.target}")
        console.print(f"[cyan]  → Phase 1: Endpoint Discovery[/cyan]")

        self._probe_known_paths()
        self._probe_common_ports()
        self._check_auth_exposure()
        self._check_tool_enumeration()
        self._check_prompt_injection_surface()

        if not self.findings:
            return {
                "status": "PASS",
                "findings_count": 0,
                "highest_severity": "N/A",
                "findings": [],
                "ai_analysis": None,
            }

        console.print(f"[cyan]  → Phase 2: AI-Driven Analysis ({len(self.findings)} findings)[/cyan]")
        ai_analysis = self._ai_analyze()
        self._render_findings_table()

        highest = self._highest_severity()
        return {
            "status": "FAIL" if highest in ("CRITICAL", "HIGH") else "WARN",
            "findings_count": len(self.findings),
            "highest_severity": highest,
            "findings": self.findings,
            "ai_analysis": ai_analysis,
        }

    # ── Discovery probes ───────────────────────────────────────────────────────

    def _probe_known_paths(self):
        """HTTP-probe common MCP URL patterns."""
        try:
            import requests
        except ImportError:
            console.print("[yellow]  ⚠ requests not installed — skipping HTTP probes[/yellow]")
            return

        for path in MCP_PATHS:
            url = self.base_host + path
            try:
                resp = requests.get(url, timeout=5, allow_redirects=False,
                                    headers={"User-Agent": "TenderCoconut/1.0 MCP-Auditor"})
                if resp.status_code in (200, 201, 400, 422):
                    finding = {
                        "type": "EXPOSED_ENDPOINT",
                        "url": url,
                        "http_status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "detail": f"MCP endpoint responding at {path}",
                        "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                    }
                    self.findings.append(finding)
                    console.print(
                        f"  [bold red][!] EXPOSED:[/bold red] {url}  "
                        f"[dim](HTTP {resp.status_code})[/dim]"
                    )
                elif self.verbose:
                    console.print(f"  [dim]✓ {url}  (HTTP {resp.status_code} — not exposed)[/dim]")
            except Exception as exc:
                if self.verbose:
                    console.print(f"  [dim]  {url} — {exc}[/dim]")

    def _probe_common_ports(self):
        """TCP-knock common MCP ports on the target host."""
        host = self._parsed.hostname or self.target.split("://")[-1].split("/")[0]
        for port in COMMON_MCP_PORTS:
            try:
                with socket.create_connection((host, port), timeout=2):
                    self.findings.append({
                        "type": "OPEN_PORT",
                        "host": host,
                        "port": port,
                        "detail": f"Port {port} open — potential MCP listener",
                        "severity": "MEDIUM",
                    })
                    if self.verbose:
                        console.print(f"  [yellow][+] Open port:[/yellow] {host}:{port}")
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

    def _check_auth_exposure(self):
        """
        Check whether the MCP SSE stream requires an Authorization header.
        An unprotected SSE stream allows anyone to receive real-time tool calls.
        """
        try:
            import requests
        except ImportError:
            return

        sse_urls = [self.base_host + p for p in ("/sse", "/mcp/sse", "/mcp")]
        for url in sse_urls:
            try:
                resp = requests.get(url, timeout=4, stream=True,
                                    headers={"Accept": "text/event-stream",
                                             "User-Agent": "TenderCoconut/1.0"})
                if resp.status_code == 200 and "event-stream" in resp.headers.get("Content-Type", ""):
                    self.findings.append({
                        "type": "UNAUTH_SSE_STREAM",
                        "url": url,
                        "detail": "SSE stream accessible without authentication — real-time "
                                  "tool invocations may be intercepted or injected.",
                        "severity": "CRITICAL",
                    })
                    console.print(f"  [bold red][CRITICAL] Unauthenticated SSE stream: {url}[/bold red]")
                resp.close()
            except Exception:
                pass

    def _check_tool_enumeration(self):
        """
        POST a JSON-RPC tools/list call. If it succeeds without auth,
        the server leaks its entire tool registry to unauthenticated callers.
        """
        try:
            import requests
        except ImportError:
            return

        rpc_payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        for path in ("/mcp", "/mcp/v1", "/"):
            url = self.base_host + path
            try:
                resp = requests.post(url, json=rpc_payload, timeout=5,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "TenderCoconut/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    if "result" in data and "tools" in data.get("result", {}):
                        tools = data["result"]["tools"]
                        self.findings.append({
                            "type": "TOOL_ENUMERATION_LEAK",
                            "url": url,
                            "tools_exposed": [t.get("name") for t in tools],
                            "tools_count": len(tools),
                            "detail": f"tools/list returned {len(tools)} tools without authentication.",
                            "severity": "HIGH",
                        })
                        console.print(
                            f"  [bold red][!] Tool leak:[/bold red] {len(tools)} tools "
                            f"exposed at {url}"
                        )
            except Exception:
                pass

    def _check_prompt_injection_surface(self):
        """
        Retrieve MCP prompt templates and flag any that accept unvalidated
        user-controlled arguments — a prime vector for indirect prompt injection.
        """
        try:
            import requests
        except ImportError:
            return

        rpc_payload = {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}}
        for path in ("/mcp", "/mcp/v1", "/"):
            url = self.base_host + path
            try:
                resp = requests.post(url, json=rpc_payload, timeout=5,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "TenderCoconut/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    prompts = data.get("result", {}).get("prompts", [])
                    for p in prompts:
                        args = p.get("arguments", [])
                        unvalidated = [a for a in args if not a.get("description")]
                        if unvalidated:
                            self.findings.append({
                                "type": "PROMPT_INJECTION_SURFACE",
                                "url": url,
                                "prompt_name": p.get("name"),
                                "unvalidated_args": [a.get("name") for a in unvalidated],
                                "detail": "Prompt template accepts arguments with no "
                                          "validation description — injection risk.",
                                "severity": "MEDIUM",
                            })
            except Exception:
                pass

    # ── AI Analysis ────────────────────────────────────────────────────────────

    def _ai_analyze(self) -> Optional[dict]:
        prompt = ANALYSIS_PROMPT_TEMPLATE.format(
            target=self.target,
            findings_json=json.dumps(self.findings, indent=2),
        )
        try:
            raw = self.client.complete(prompt, max_tokens=1024)
            # Strip potential markdown fences
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(raw)
        except (json.JSONDecodeError, Exception) as e:
            if self.verbose:
                console.print(f"  [dim][ai] Analysis parse error: {e}[/dim]")
            return {"raw": raw if "raw" in dir() else str(e)}

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _highest_severity(self) -> str:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in order:
            if any(f.get("severity") == sev for f in self.findings):
                return sev
        return "INFO"

    def _render_findings_table(self):
        table = Table(title="MCP Audit Findings", box=box.SIMPLE_HEAVY, border_style="red")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", justify="center")
        table.add_column("Detail", style="white")
        sev_style = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            table.add_row(
                f.get("type", ""),
                f"[{sev_style.get(sev, 'white')}]{sev}[/]",
                f.get("detail", "")[:120],
            )
        console.print(table)
