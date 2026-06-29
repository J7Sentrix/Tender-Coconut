#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           TENDER COCONUT — AI Security Assessment Tool           ║
║     Automated Adversarial Auditing for LLMs, Agents & MCP        ║
╚══════════════════════════════════════════════════════════════════╝
"""

import click
import sys
import json
import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

BANNER = """
[bold green]
  ████████╗███████╗███╗   ██╗██████╗ ███████╗██████╗ 
  ╚══██╔══╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
     ██║   █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝
     ██║   ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
     ██║   ███████╗██║ ╚████║██████╔╝███████╗██║  ██║
     ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
  [/bold green][bold cyan]
   ██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗██╗   ██╗████████╗
  ██╔════╝██╔═══██╗██╔════╝██╔═══██╗████╗  ██║██║   ██║╚══██╔══╝
  ██║     ██║   ██║██║     ██║   ██║██╔██╗ ██║██║   ██║   ██║   
  ██║     ██║   ██║██║     ██║   ██║██║╚██╗██║██║   ██║   ██║   
  ╚██████╗╚██████╔╝╚██████╗╚██████╔╝██║ ╚████║╚██████╔╝   ██║   
   ╚═════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝    ╚═╝   
  [/bold cyan]
[dim]  AI Security Assessment & Adversarial Vulnerability Auditing Framework[/dim]
[dim]  v1.0.0  |  github.com/your-org/tender-coconut[/dim]
"""

MODULES = {
    "mcp":      ("modules.mcp_audit",          "MCPAuditScanner",       "MCP Protocol Endpoint Audit"),
    "prompt":   ("modules.prompt_robustness",   "PromptRobustnessTest",  "Prompt Injection Robustness"),
    "context":  ("modules.context_boundary",    "ContextBoundaryCheck",  "Context Boundary & Instruction Amnesia"),
    "supply":   ("modules.supply_chain_check",  "SupplyChainAuditor",    "Supply Chain & Dependency Audit"),
    "crypto":   ("modules.crypto_creep",        "CryptoCreepAnalyzer",   "Cryptographic Weakness Detection"),
}


def print_banner():
    console.print(BANNER)


def get_engine_client(engine: str, config):
    """Return an initialized LLM client based on the selected engine."""
    if engine == "claude":
        return config.get_anthropic_client()
    elif engine == "gemini":
        return config.get_gemini_client()
    elif engine == "grok":
        return config.get_grok_client()
    elif engine == "ollama":
        return config.get_ollama_client()
    else:
        console.print(f"[bold red][!] Unknown engine: {engine}[/bold red]")
        sys.exit(1)


def save_report(results: dict, output_path: str):
    """Persist scan results to a JSON report file."""
    report = {
        "tool": "Tender Coconut",
        "version": "1.0.0",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "results": results,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
    console.print(f"\n[bold green][✔] Report saved to:[/bold green] {path.resolve()}")


def display_summary(all_results: dict):
    """Print a formatted summary table of all scan results."""
    table = Table(
        title="[bold white]Tender Coconut — Scan Summary[/bold white]",
        box=box.ROUNDED,
        border_style="green",
        show_lines=True,
    )
    table.add_column("Module", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Findings", justify="right")
    table.add_column("Severity", justify="center")

    severity_color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green", "INFO": "dim", "N/A": "dim"}

    for module_key, result in all_results.items():
        status = result.get("status", "UNKNOWN")
        findings = str(result.get("findings_count", 0))
        severity = result.get("highest_severity", "N/A")
        status_icon = "[bold green]✔ PASS[/bold green]" if status == "PASS" else \
                      "[bold red]✘ FAIL[/bold red]" if status == "FAIL" else \
                      "[yellow]⚠ WARN[/yellow]"
        table.add_row(
            MODULES[module_key][2] if module_key in MODULES else module_key,
            status_icon,
            findings,
            f"[{severity_color.get(severity, 'white')}]{severity}[/]",
        )
    console.print(table)


# ─── CLI Definition ───────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Tender Coconut — AI Security Assessment & Adversarial Auditing Framework."""
    if ctx.invoked_subcommand is None:
        print_banner()
        click.echo(ctx.get_help())


@cli.command("scan")
@click.option("--target", "-t", required=True,
              help="Target host/URL/endpoint to assess (e.g. http://localhost:3000).")
@click.option("--modules", "-m", default="all",
              help="Comma-separated module keys to run: mcp,prompt,context,supply,crypto or 'all'.")
@click.option("--engine", "-e", default="claude",
              type=click.Choice(["claude", "gemini", "grok", "ollama"], case_sensitive=False),
              help="LLM engine to use for AI-driven analysis.")
@click.option("--model", default=None,
              help="Override model name (e.g. claude-sonnet-4-6, gemini-1.5-pro, llama3).")
@click.option("--output", "-o", default=None,
              help="Path to save JSON report (e.g. reports/scan_result.json).")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option("--no-banner", is_flag=True, help="Suppress ASCII banner.")
def scan(target, modules, engine, model, output, verbose, no_banner):
    """
    Run an adversarial security scan against a target AI endpoint or deployment.

    Examples:\n
      tender_coconut.py scan -t http://localhost:3000 -m all -e claude\n
      tender_coconut.py scan -t http://api.example.com -m mcp,crypto -e gemini\n
      tender_coconut.py scan -t http://localhost:11434 -m prompt -e ollama --model llama3
    """
    if not no_banner:
        print_banner()

    # ── Resolve modules to run ────────────────────────────────────────────────
    if modules.strip().lower() == "all":
        selected = list(MODULES.keys())
    else:
        selected = [m.strip().lower() for m in modules.split(",")]
        invalid = [m for m in selected if m not in MODULES]
        if invalid:
            console.print(f"[bold red][!] Unknown modules: {', '.join(invalid)}[/bold red]")
            console.print(f"    Valid choices: {', '.join(MODULES.keys())}")
            sys.exit(1)

    console.print(Panel(
        f"[bold white]Target:[/bold white]  {target}\n"
        f"[bold white]Engine:[/bold white]  {engine}" + (f"  →  {model}" if model else "") + "\n"
        f"[bold white]Modules:[/bold white] {', '.join(selected)}",
        title="[bold green]⬡ Scan Configuration[/bold green]",
        border_style="green",
    ))

    # ── Load config & engine client ───────────────────────────────────────────
    try:
        from core.config import TenderCoconutConfig
        config = TenderCoconutConfig(engine=engine, model_override=model, verbose=verbose)
        client = get_engine_client(engine, config)
    except ImportError as e:
        console.print(f"[bold red][!] Config import error: {e}[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red][!] Engine initialization failed: {e}[/bold red]")
        sys.exit(1)

    all_results = {}

    # ── Execute each selected module ──────────────────────────────────────────
    for key in selected:
        module_path, class_name, display_name = MODULES[key]
        console.rule(f"[bold cyan]⬡ {display_name}[/bold cyan]")

        try:
            import importlib
            mod = importlib.import_module(module_path)
            scanner_class = getattr(mod, class_name)
            scanner = scanner_class(target=target, client=client, config=config, verbose=verbose)
            result = scanner.run()
            all_results[key] = result

            status_str = result.get("status", "UNKNOWN")
            if status_str == "PASS":
                console.print(f"  [bold green]✔ {display_name}: PASS[/bold green]")
            elif status_str == "FAIL":
                console.print(f"  [bold red]✘ {display_name}: FAIL  "
                               f"({result.get('findings_count', 0)} findings)[/bold red]")
            else:
                console.print(f"  [yellow]⚠ {display_name}: {status_str}[/yellow]")

        except ModuleNotFoundError as e:
            console.print(f"  [yellow]⚠ Module '{key}' not found: {e}[/yellow]")
            all_results[key] = {"status": "SKIP", "findings_count": 0, "highest_severity": "N/A"}
        except Exception as e:
            console.print(f"  [bold red]✘ Module '{key}' error: {e}[/bold red]")
            if verbose:
                import traceback
                traceback.print_exc()
            all_results[key] = {"status": "ERROR", "findings_count": 0, "highest_severity": "N/A",
                                 "error": str(e)}

    # ── Summary & report ──────────────────────────────────────────────────────
    console.rule("[bold white]Scan Complete[/bold white]")
    display_summary(all_results)

    if output:
        save_report(all_results, output)
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        default_out = f"reports/tc_scan_{ts}.json"
        save_report(all_results, default_out)


@cli.command("list-modules")
def list_modules():
    """List all available scanning modules."""
    print_banner()
    table = Table(title="Available Modules", box=box.SIMPLE_HEAVY, border_style="cyan")
    table.add_column("Key", style="bold yellow")
    table.add_column("Class", style="cyan")
    table.add_column("Description", style="white")
    for key, (path, cls, desc) in MODULES.items():
        table.add_row(key, cls, desc)
    console.print(table)


@cli.command("list-engines")
def list_engines():
    """Show available LLM engine backends and their configuration status."""
    print_banner()
    import os
    engines = [
        ("claude",  "Anthropic Claude",     "ANTHROPIC_API_KEY",  "claude-sonnet-4-6"),
        ("gemini",  "Google Gemini",         "GOOGLE_API_KEY",     "gemini-1.5-pro"),
        ("grok",    "xAI Grok",              "XAI_API_KEY",        "grok-2-latest"),
        ("ollama",  "Ollama (Local/Offline)", "OLLAMA_HOST",       "llama3"),
    ]
    table = Table(title="LLM Engine Backends", box=box.ROUNDED, border_style="green")
    table.add_column("Key", style="bold yellow")
    table.add_column("Provider", style="white")
    table.add_column("Env Variable", style="cyan")
    table.add_column("Default Model", style="dim")
    table.add_column("Configured", justify="center")
    for key, provider, env_var, default_model in engines:
        configured = "[bold green]✔[/bold green]" if os.environ.get(env_var) else "[red]✘[/red]"
        table.add_row(key, provider, env_var, default_model, configured)
    console.print(table)
    console.print("\n[dim]Set environment variables to configure each engine.[/dim]")


if __name__ == "__main__":
    cli()
