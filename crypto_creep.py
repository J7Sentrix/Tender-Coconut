"""
modules/crypto_creep.py — Cryptographic Weakness Detection

Scans AI agent configurations, codebases, and endpoints for:
  - Deprecated hash algorithms (MD5, SHA-1)
  - Weak RSA key sizes (< 2048-bit)
  - Hardcoded cryptographic secrets / weak keys
  - Insecure TLS configurations
  - JWT algorithm downgrade vulnerabilities (none/HS256 on asymmetric endpoints)
  - Quantum-vulnerable key exchange protocols
"""

import re
import ssl
import json
import socket
from pathlib import Path
from typing import Any, Optional
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─── Weak algorithm pattern registry ─────────────────────────────────────────
WEAK_CRYPTO_PATTERNS = [
    # (pattern_name, regex, severity, description)
    ("MD5_USAGE",
     r"\bmd5\b|\bMD5\b|hashlib\.md5|MD5Hash|createHash\(['\"]md5['\"]\)",
     "HIGH",
     "MD5 is cryptographically broken — collision attacks trivial"),

    ("SHA1_USAGE",
     r"\bsha1\b|\bsha-1\b|\bSHA1\b|\bSHA-1\b|hashlib\.sha1|createHash\(['\"]sha1['\"]\)",
     "HIGH",
     "SHA-1 deprecated; SHAttered collision proven in 2017"),

    ("WEAK_RSA_KEY",
     r"RSA\.generate\((?:512|768|1024)\)|rsa\.newkeys\((?:512|768|1024)\)|"
     r"RSA_generate_key.*?(?:512|768|1024)",
     "CRITICAL",
     "RSA key size < 2048 bits is factored easily with modern hardware"),

    ("RC4_USAGE",
     r"\bRC4\b|\brc4\b|Cipher\.new.*?ARC4|createCipheriv\(['\"]rc4['\"]\)",
     "CRITICAL",
     "RC4 is completely broken; banned in TLS since RFC 7465"),

    ("DES_USAGE",
     r"\bDES\b|\b3DES\b|\bTripleDES\b|DES\.new|createCipheriv\(['\"]des",
     "HIGH",
     "DES/3DES deprecated by NIST (Special Publication 800-131A Rev 2)"),

    ("HARDCODED_SECRET",
     r"(?:secret|api_key|password|token|private_key)\s*=\s*['\"][A-Za-z0-9+/=]{8,}['\"]",
     "CRITICAL",
     "Hardcoded credential or secret key detected in source"),

    ("JWT_NONE_ALG",
     r"algorithm\s*=\s*['\"]none['\"]|alg.*?:\s*['\"]none['\"]",
     "CRITICAL",
     "JWT 'none' algorithm allows unsigned token forgery"),

    ("JWT_WEAK_ALG",
     r"algorithm\s*=\s*['\"]HS(?:256|384|512)['\"]",
     "MEDIUM",
     "HMAC-based JWT on asymmetric endpoint allows key confusion attacks"),

    ("RANDOM_NOT_SECURE",
     r"\brandom\.random\(\)|\bMath\.random\(\)|rand\(\)|srand\(",
     "MEDIUM",
     "Non-cryptographic RNG used — predictable in security-sensitive context"),

    ("WEAK_PBKDF",
     r"PBKDF2.*?iterations\s*=\s*(?:[1-9]\d{0,3})\b",
     "HIGH",
     "PBKDF2 iteration count too low (< 10000) — brute-forceable"),

    ("QUANTUM_VULNERABLE",
     r"\bECDH\b.*?(?:P-192|P-224|secp192|secp224)|"
     r"DH_generate.*?1024",
     "MEDIUM",
     "Key exchange algorithm vulnerable to quantum Shor's algorithm"),
]

# ─── File extensions to scan ──────────────────────────────────────────────────
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".rb", ".env",
                   ".yaml", ".yml", ".toml", ".json", ".cfg", ".ini", ".conf"}

ANALYSIS_PROMPT = """
You are a cryptography security expert specializing in AI/ML infrastructure.

Target: {target}
Scan findings:
{findings_json}

For each finding:
1. Explain the exact cryptographic weakness and known exploitation techniques
2. Assess real-world exploitability in an AI agent context
3. Provide a concrete, specific code fix with the correct modern alternative
4. Flag any quantum computing timeline concerns (NIST PQC transition)

Also assess the overall cryptographic hygiene score (0-100) and whether this 
deployment meets SOC 2 / ISO 27001 cryptography controls.

JSON with keys: finding_analyses, overall_score, compliance_gaps, quantum_readiness
"""


class CryptoCreepAnalyzer:
    """
    Static analysis scanner for deprecated, weak, or misconfigured cryptographic
    primitives across AI agent codebases and configurations.
    """

    def __init__(self, target: str, client: Any, config: Any, verbose: bool = False):
        self.target = target
        self.client = client
        self.config = config
        self.verbose = verbose
        self.findings: list[dict] = []

    def run(self) -> dict:
        console.print(f"\n[cyan]  → Phase 1: Static code analysis...[/cyan]")
        files_scanned = self._scan_local_files()

        console.print(f"[cyan]  → Phase 2: TLS/SSL configuration check...[/cyan]")
        self._check_tls_config()

        console.print(f"[cyan]  → Phase 3: JWT header inspection...[/cyan]")
        self._check_jwt_exposure()

        self._render_table(files_scanned)

        if not self.findings:
            return {"status": "PASS", "findings_count": 0,
                    "highest_severity": "N/A", "findings": [], "ai_analysis": None}

        ai_analysis = self._ai_analyze()
        highest = self._highest_severity()
        return {
            "status": "FAIL" if highest in ("CRITICAL", "HIGH") else "WARN",
            "findings_count": len(self.findings),
            "highest_severity": highest,
            "findings": self.findings,
            "ai_analysis": ai_analysis,
        }

    # ── Local static analysis ──────────────────────────────────────────────────

    def _scan_local_files(self) -> int:
        root = Path(".")
        files = [f for f in root.rglob("*")
                 if f.is_file() and f.suffix in SCAN_EXTENSIONS
                 and ".git" not in f.parts
                 and "node_modules" not in f.parts
                 and "__pycache__" not in f.parts]

        count = 0
        for fpath in files:
            try:
                content = fpath.read_text(errors="ignore")
                for pattern_name, regex, severity, description in WEAK_CRYPTO_PATTERNS:
                    for m in re.finditer(regex, content, re.MULTILINE | re.IGNORECASE):
                        line_num = content[:m.start()].count("\n") + 1
                        self.findings.append({
                            "type": "STATIC_ANALYSIS",
                            "pattern": pattern_name,
                            "file": str(fpath),
                            "line": line_num,
                            "match": m.group(0)[:80],
                            "severity": severity,
                            "detail": description,
                        })
                        if self.verbose:
                            console.print(
                                f"  [red][{severity}][/red] {pattern_name} "
                                f"in {fpath}:{line_num}"
                            )
                count += 1
            except Exception:
                pass
        if self.verbose:
            console.print(f"  [dim]  Scanned {count} files.[/dim]")
        return count

    # ── TLS inspection ─────────────────────────────────────────────────────────

    def _check_tls_config(self):
        """Connect to the target and inspect TLS protocol version and cipher suite."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.target)
            if parsed.scheme not in ("https",):
                if parsed.scheme == "http":
                    self.findings.append({
                        "type": "TLS_MISSING",
                        "url": self.target,
                        "severity": "HIGH",
                        "detail": "Target uses plain HTTP — no transport encryption.",
                    })
                return

            host = parsed.hostname
            port = parsed.port or 443
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    proto = ssock.version()
                    cipher = ssock.cipher()

                    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.findings.append({
                            "type": "WEAK_TLS_VERSION",
                            "host": host,
                            "protocol": proto,
                            "severity": "HIGH",
                            "detail": f"Deprecated TLS version {proto} negotiated. Upgrade to TLS 1.3.",
                        })

                    weak_ciphers = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
                    cipher_name = cipher[0] if cipher else ""
                    for wc in weak_ciphers:
                        if wc in cipher_name.upper():
                            self.findings.append({
                                "type": "WEAK_CIPHER_SUITE",
                                "host": host,
                                "cipher": cipher_name,
                                "severity": "CRITICAL",
                                "detail": f"Weak cipher suite in use: {cipher_name}",
                            })

                    if self.verbose:
                        console.print(
                            f"  [dim]  TLS: {proto} | Cipher: {cipher_name}[/dim]"
                        )
        except (ssl.SSLError, socket.timeout, OSError) as e:
            if self.verbose:
                console.print(f"  [dim]  TLS check skipped: {e}[/dim]")

    # ── JWT header inspection ──────────────────────────────────────────────────

    def _check_jwt_exposure(self):
        """Probe for JWT-issuing endpoints and inspect token algorithm headers."""
        try:
            import requests, base64
        except ImportError:
            return

        jwt_paths = ["/token", "/auth", "/login", "/api/auth", "/oauth/token", "/auth/token"]
        dummy_payload = {"username": "test", "password": "test"}

        for path in jwt_paths:
            url = self.target.rstrip("/") + path
            try:
                resp = requests.post(url, json=dummy_payload, timeout=4)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    token = (data.get("token") or data.get("access_token")
                             or data.get("jwt") or "")
                    if token and "." in token:
                        header_b64 = token.split(".")[0]
                        # Pad for base64
                        header_b64 += "=" * (-len(header_b64) % 4)
                        try:
                            header = json.loads(base64.urlsafe_b64decode(header_b64))
                            alg = header.get("alg", "")
                            if alg.lower() == "none":
                                self.findings.append({
                                    "type": "JWT_NONE_ALG",
                                    "url": url,
                                    "severity": "CRITICAL",
                                    "detail": "JWT issued with 'none' algorithm — unsigned token forgery possible",
                                })
                            elif alg.startswith("HS"):
                                self.findings.append({
                                    "type": "JWT_WEAK_ALG",
                                    "url": url,
                                    "algorithm": alg,
                                    "severity": "MEDIUM",
                                    "detail": f"HMAC JWT ({alg}) — verify not used on asymmetric endpoint",
                                })
                        except Exception:
                            pass
            except Exception:
                pass

    # ── AI analysis ────────────────────────────────────────────────────────────

    def _ai_analyze(self) -> Optional[dict]:
        prompt = ANALYSIS_PROMPT.format(
            target=self.target,
            findings_json=json.dumps(self.findings[:20], indent=2),  # Cap to avoid token overflow
        )
        try:
            raw = self.client.complete(prompt, max_tokens=1500)
            raw = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            return json.loads(raw)
        except Exception as e:
            return {"error": str(e)}

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _highest_severity(self) -> str:
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if any(f.get("severity") == sev for f in self.findings):
                return sev
        return "INFO"

    def _render_table(self, files_scanned: int):
        if not self.findings:
            console.print(f"  [green]  ✔ No cryptographic weaknesses found in {files_scanned} files.[/green]")
            return
        table = Table(title=f"Crypto Findings ({len(self.findings)} across {files_scanned} files)",
                      box=box.SIMPLE_HEAVY, border_style="red")
        table.add_column("Type", style="yellow", width=18)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Location", style="cyan", width=30)
        table.add_column("Detail", style="white")
        sev_style = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "green"}
        for f in self.findings[:25]:  # Show top 25
            loc = f.get("file", f.get("url", f.get("host", "")))
            if f.get("line"):
                loc += f":{f['line']}"
            sev = f.get("severity", "INFO")
            table.add_row(
                f.get("type", ""),
                f"[{sev_style.get(sev, 'white')}]{sev}[/]",
                loc[-30:],
                f.get("detail", "")[:80],
            )
        console.print(table)
        if len(self.findings) > 25:
            console.print(f"  [dim]  ... and {len(self.findings) - 25} more. See JSON report.[/dim]")
