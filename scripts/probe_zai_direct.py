#!/usr/bin/env python3
"""Direct Z.ai chat test (minimal prompt)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app
from app.services.llm.provider import ZAIProvider


def main() -> int:
    app = create_app("development")
    with app.app_context():
        model = app.config.get("ZAI_MODEL") or "glm-4.7-flash"
        if model == "glm-4-flash":
            model = "glm-4.7-flash"
        p = ZAIProvider(
            app.config["ZAI_API_KEY"],
            model,
            app.config["ZAI_API_BASE"],
            max_tokens=32,
            timeout=30,
        )
        try:
            raw = p._complete_inner(
                "You are a helpful assistant.",
                "Reply with exactly one word: pong",
                0.0,
            )
            print(f"model={model}")
            print(f"response={raw!r}")
            ok = bool(raw and raw.strip() and raw.strip() != "{}")
            return 0 if ok else 1
        except Exception as exc:
            print(f"error={exc}")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
