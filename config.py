"""
core/config.py — Tender Coconut Central Configuration & API Key Management

Handles secure initialization of all supported LLM backends:
  - Anthropic Claude  (ANTHROPIC_API_KEY)
  - Google Gemini     (GOOGLE_API_KEY)
  - xAI Grok          (XAI_API_KEY)
  - Ollama Local      (OLLAMA_HOST, default: http://localhost:11434)
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Optional, Any
from rich.console import Console

console = Console()

# ─── Default model identifiers per engine ─────────────────────────────────────
DEFAULT_MODELS = {
    "claude": "claude-sonnet-4-6",
    "gemini": "gemini-1.5-pro",
    "grok":   "grok-2-latest",
    "ollama": "llama3",
}

SUPPORTED_ENGINES = list(DEFAULT_MODELS.keys())


@dataclass
class TenderCoconutConfig:
    """
    Central configuration container.  Reads credentials from environment
    variables and exposes typed client factories for each LLM backend.
    """
    engine: str = "claude"
    model_override: Optional[str] = None
    verbose: bool = False

    # Internal state — populated lazily by properties
    _anthropic_key: Optional[str] = field(default=None, init=False, repr=False)
    _google_key: Optional[str]    = field(default=None, init=False, repr=False)
    _xai_key: Optional[str]       = field(default=None, init=False, repr=False)
    _ollama_host: Optional[str]   = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if self.engine not in SUPPORTED_ENGINES:
            raise ValueError(
                f"Unsupported engine '{self.engine}'. "
                f"Choose from: {', '.join(SUPPORTED_ENGINES)}"
            )
        self._load_env()
        if self.verbose:
            console.print(
                f"[dim][config] engine={self.engine}  "
                f"model={self.active_model}[/dim]"
            )

    # ── Environment loading ────────────────────────────────────────────────────

    def _load_env(self):
        self._anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        self._google_key    = os.environ.get("GOOGLE_API_KEY")
        self._xai_key       = os.environ.get("XAI_API_KEY")
        self._ollama_host   = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    # ── Active model resolution ────────────────────────────────────────────────

    @property
    def active_model(self) -> str:
        return self.model_override or DEFAULT_MODELS[self.engine]

    # ── Client factories ───────────────────────────────────────────────────────

    def get_anthropic_client(self) -> Any:
        """
        Return an initialized Anthropic client.
        Requires: pip install anthropic
        Env var:  ANTHROPIC_API_KEY
        """
        if not self._anthropic_key:
            _abort_missing_key("ANTHROPIC_API_KEY", "claude")
        try:
            import anthropic  # noqa: F401 — checked at runtime
            client = anthropic.Anthropic(api_key=self._anthropic_key)
            if self.verbose:
                console.print(f"[dim][config] Anthropic client ready "
                               f"(model: {self.active_model})[/dim]")
            return _AnthropicWrapper(client=client, model=self.active_model)
        except ImportError:
            _abort_missing_package("anthropic", "pip install anthropic")

    def get_gemini_client(self) -> Any:
        """
        Return an initialized Google Generative AI client.
        Requires: pip install google-generativeai
        Env var:  GOOGLE_API_KEY
        """
        if not self._google_key:
            _abort_missing_key("GOOGLE_API_KEY", "gemini")
        try:
            import google.generativeai as genai  # noqa: F401
            genai.configure(api_key=self._google_key)
            model = genai.GenerativeModel(self.active_model)
            if self.verbose:
                console.print(f"[dim][config] Gemini client ready "
                               f"(model: {self.active_model})[/dim]")
            return _GeminiWrapper(model=model)
        except ImportError:
            _abort_missing_package("google-generativeai", "pip install google-generativeai")

    def get_grok_client(self) -> Any:
        """
        Return an initialized xAI Grok client (OpenAI-compatible API).
        Requires: pip install openai
        Env var:  XAI_API_KEY
        """
        if not self._xai_key:
            _abort_missing_key("XAI_API_KEY", "grok")
        try:
            from openai import OpenAI  # noqa: F401
            client = OpenAI(
                api_key=self._xai_key,
                base_url="https://api.x.ai/v1",
            )
            if self.verbose:
                console.print(f"[dim][config] Grok client ready "
                               f"(model: {self.active_model})[/dim]")
            return _OpenAICompatWrapper(client=client, model=self.active_model)
        except ImportError:
            _abort_missing_package("openai", "pip install openai")

    def get_ollama_client(self) -> Any:
        """
        Return an Ollama HTTP client pointed at the local server.
        Requires: pip install ollama   (or just requests)
        Env var:  OLLAMA_HOST  (default: http://localhost:11434)
        """
        try:
            import ollama as _ollama  # noqa: F401
            if self.verbose:
                console.print(f"[dim][config] Ollama client ready "
                               f"(host: {self._ollama_host}  "
                               f"model: {self.active_model})[/dim]")
            return _OllamaWrapper(host=self._ollama_host, model=self.active_model)
        except ImportError:
            # Fallback: raw HTTP via requests
            try:
                import requests  # noqa: F401
                return _OllamaHTTPWrapper(host=self._ollama_host, model=self.active_model)
            except ImportError:
                _abort_missing_package("ollama or requests",
                                       "pip install ollama  # or: pip install requests")


# ─── Thin client wrappers ─────────────────────────────────────────────────────
# Each wrapper exposes a unified .complete(prompt: str) -> str interface
# so scanning modules remain engine-agnostic.

class _AnthropicWrapper:
    def __init__(self, client, model: str):
        self._client = client
        self.model = model

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text if response.content else ""

    def __repr__(self):
        return f"<AnthropicWrapper model={self.model}>"


class _GeminiWrapper:
    def __init__(self, model):
        self._model = model

    def complete(self, prompt: str, **_) -> str:
        response = self._model.generate_content(prompt)
        return response.text if hasattr(response, "text") else ""

    def __repr__(self):
        return f"<GeminiWrapper model={self._model.model_name}>"


class _OpenAICompatWrapper:
    """Shared wrapper for OpenAI-compatible endpoints (Grok, etc.)."""
    def __init__(self, client, model: str):
        self._client = client
        self.model = model

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content if response.choices else ""

    def __repr__(self):
        return f"<OpenAICompatWrapper model={self.model}>"


class _OllamaWrapper:
    """Uses the official ollama Python library."""
    def __init__(self, host: str, model: str):
        import ollama
        self._ollama = ollama
        self.model = model
        self.host = host

    def complete(self, prompt: str, **_) -> str:
        response = self._ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
        )
        return response["message"]["content"] if response else ""

    def __repr__(self):
        return f"<OllamaWrapper host={self.host} model={self.model}>"


class _OllamaHTTPWrapper:
    """Fallback: raw HTTP requests to Ollama API."""
    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model

    def complete(self, prompt: str, **_) -> str:
        import requests
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        resp = requests.post(f"{self.host}/api/generate", json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "")

    def __repr__(self):
        return f"<OllamaHTTPWrapper host={self.host} model={self.model}>"


# ─── Utility helpers ──────────────────────────────────────────────────────────

def _abort_missing_key(env_var: str, engine: str):
    console.print(
        f"\n[bold red][!] Missing API key: {env_var}[/bold red]\n"
        f"    Export it before running:\n"
        f"    [yellow]export {env_var}='your-key-here'[/yellow]\n"
        f"    Or add it to your [cyan].env[/cyan] file and load it "
        f"with [cyan]source .env[/cyan].\n"
    )
    sys.exit(1)


def _abort_missing_package(package: str, install_cmd: str):
    console.print(
        f"\n[bold red][!] Required package not installed: {package}[/bold red]\n"
        f"    Install it with:\n"
        f"    [yellow]{install_cmd}[/yellow]\n"
    )
    sys.exit(1)
