#!/usr/bin/env python3
"""Probe Z.ai only (no NVIDIA/OpenRouter). Usage: python scripts/probe_zai_only.py"""

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
        cfg["NVIDIA_API_KEY"] = ""
        cfg["LLM_API_KEY"] = ""
        cfg["OPENROUTER_API_KEY"] = ""
        cfg["OPENROUTER_ENABLED"] = False
        cfg["LLM_SECONDARY_MODEL"] = ""
        cfg["LLM_ZAI_ONLY"] = True
        cfg["LLM_PROBE_TIMEOUT_SECONDS"] = 30
        if cfg.get("ZAI_MODEL") in (None, "", "glm-4-flash"):
            cfg["ZAI_MODEL"] = "glm-4.7-flash"

        if not (cfg.get("ZAI_API_KEY") or "").strip():
            print(json.dumps({"ok": False, "error": "ZAI_API_KEY not set in .env"}, indent=2))
            return 1

        result = probe_llm_connectivity(cfg)
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
