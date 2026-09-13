#!/usr/bin/env python3
"""
azure_ollama_client.py

ONE shared client for talking to an Ollama server, whether it runs on
localhost or on an Azure GPU VM. Every generation script in this suite
(25_generate_codellama_corpus.py, 26_generate_deepseek_corpus.py) imports
from here so the transport, retry, and controlled-generation settings live
in exactly one place.

Chapter 3, Section 3.5 requires: temperature=0, top_k=1, documented seeds,
and preservation of the exact model tag/digest. This client enforces the
first three and records the fourth into every run manifest.

WHY THIS EXISTS SEPARATELY FROM 11_generate_evasion_corpus.py:
  11_* rewrites the 23 fixed EVASION_ATTACKS (a variant generator). The
  thesis held-out corpus (Section 3.5) needs BULK, family-structured
  generation of ~500+500 (Code Llama) and ~300+300 (DeepSeek) NOVEL
  payloads. That is a different job, so it gets its own scripts and this
  shared backend.

TRANSPORT: the Ollama HTTP API is identical on localhost and on an Azure
VM -- only the host:port changes. Point --host at the VM's address (over a
private VNet, an SSH tunnel, or a locked-down NSG) and nothing else in the
pipeline changes.

  # local
  client = OllamaClient(host="localhost", port=11434)
  # Azure VM reached over an SSH tunnel (recommended -- see AZURE_RUNBOOK.md)
  client = OllamaClient(host="localhost", port=11434)   # tunnel maps it local
  # Azure VM reached directly over a private VNet address
  client = OllamaClient(host="10.0.0.4", port=11434)

SECURITY NOTE: never expose Ollama's port to the public internet. It has no
authentication. The runbook uses an SSH tunnel so the port is only ever
reachable through an authenticated SSH session.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field


@dataclass
class OllamaClient:
    host: str = "localhost"
    port: int = 11434
    scheme: str = "http"
    connect_timeout: int = 15
    request_timeout: int = 900          # 15 min ceiling for slow 13-14B models
    max_retries: int = 4
    backoff_seconds: float = 5.0
    # bearer token only if you front the VM with a reverse proxy that adds auth;
    # plain Ollama ignores it. Kept so the Azure runbook can layer auth on later.
    auth_token: str | None = None
    _resolved_digest: str = field(default="", init=False)

    # ── URLs ────────────────────────────────────────────────────────────────
    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.auth_token:
            h["Authorization"] = f"Bearer {self.auth_token}"
        return h

    # ── health / model resolution ────────────────────────────────────────────
    def check_model(self, model: str) -> dict:
        """Confirm the server is up and the model is pulled. Returns the
        matching model record (including its digest) for the run manifest."""
        try:
            req = urllib.request.Request(f"{self.base}/api/tags",
                                         headers=self._headers())
            with urllib.request.urlopen(req, timeout=self.connect_timeout) as r:
                data = json.loads(r.read())
        except Exception as e:
            raise RuntimeError(
                f"[ERROR] Cannot reach Ollama at {self.base}/api/tags.\n"
                f"  If this is an Azure VM, confirm the SSH tunnel or VNet route "
                f"is up and 'ollama serve' is running on the VM.\n"
                f"  Details: {e}"
            )
        models = data.get("models", [])
        exact = [m for m in models if m.get("name") == model]
        loose = [m for m in models if model.split(":")[0] in m.get("name", "")]
        match = (exact or loose)
        if not match:
            raise RuntimeError(
                f"[ERROR] Model '{model}' not found on {self.base}.\n"
                f"  Available: {[m.get('name') for m in models]}\n"
                f"  On the VM run:  ollama pull {model}"
            )
        rec = match[0]
        self._resolved_digest = rec.get("digest", "")
        print(f"  [OK] {self.base} reachable. Model '{rec.get('name')}' "
              f"digest={self._resolved_digest[:19] or 'unknown'}")
        return rec

    # ── generation ───────────────────────────────────────────────────────────
    def generate(self, model: str, prompt: str, system: str, seed: int) -> str:
        """One controlled generation. temperature=0, top_k=1 per Section 3.5.
        Retries transient network / 5xx errors with backoff; raises on
        exhaustion so the caller can log the failed payload rather than
        silently accept an empty one."""
        body = json.dumps({
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "seed": seed,
                "temperature": 0.0,   # Section 3.5: controlled generation
                "top_k": 1,           # Section 3.5: greedy decode
                "top_p": 1.0,
                "num_predict": 512,
            },
        }).encode("utf-8")

        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    f"{self.base}/api/generate", data=body,
                    headers=self._headers(), method="POST")
                with urllib.request.urlopen(req, timeout=self.request_timeout) as r:
                    result = json.loads(r.read())
                return result.get("response", "").strip()
            except (urllib.error.HTTPError, urllib.error.URLError,
                    TimeoutError, ConnectionError) as e:
                last_err = e
                code = getattr(e, "code", None)
                # 4xx (except 429) are our fault -- don't retry.
                if isinstance(e, urllib.error.HTTPError) and code not in (429, 500, 502, 503, 504):
                    raise RuntimeError(f"[ERROR] Ollama {code} for model {model}: {e}")
                wait = self.backoff_seconds * attempt
                print(f"  [retry {attempt}/{self.max_retries}] {type(e).__name__}"
                      f"{' '+str(code) if code else ''}; waiting {wait:.0f}s")
                time.sleep(wait)
        raise RuntimeError(
            f"[ERROR] Generation failed after {self.max_retries} attempts "
            f"against {self.base} (model {model}): {last_err}")

    @property
    def digest(self) -> str:
        return self._resolved_digest


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_fences(raw: str) -> str:
    """Remove ``` code fences and leading language hints some models emit."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = [l for l in raw.splitlines() if not l.startswith("```")]
        raw = "\n".join(lines).strip()
    return raw
