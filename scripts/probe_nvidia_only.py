#!/usr/bin/env python3
"""Probe NVIDIA NIM only (no Z.ai/OpenRouter). Usage: python scripts/probe_nvidia_only.py"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app
from app.services.llm.connectivity import probe_llm_connectivity


def main() -> int:
    app = create_app("development")
    with app.app_context():
        cfg = dict(app.config)
        cfg["LLM_SINGLE_PROVIDER"] = "nvidia"
        cfg["LLM_PROVIDER"] = "nvidia"
        cfg["ZAI_API_KEY"] = ""
        cfg["OPENROUTER_API_KEY"] = ""
        cfg["OPENROUTER_ENABLED"] = False
        cfg["LLM_SECONDARY_MODEL"] = ""
        cfg["LLM_PROBE_TIMEOUT_SECONDS"] = 45

        if not (cfg.get("NVIDIA_API_KEY") or cfg.get("LLM_API_KEY")):
            print(json.dumps({"ok": False, "error": "NVIDIA_API_KEY not set in .env"}, indent=2))
            return 1

        result = probe_llm_connectivity(cfg)
        safe = dict(result)
        print(json.dumps(safe, indent=2, default=str))
        return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
