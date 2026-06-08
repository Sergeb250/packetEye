"""YAML-driven rule loader."""

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def load_rules(rules_dir: Path) -> list[dict]:
    rules = []
    if not rules_dir.exists():
        return rules
    for path in sorted(rules_dir.glob("*.yaml")):
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.append(data)
        except Exception as exc:
            logger.warning("Failed to load rule %s: %s", path, exc)
    return [r for r in rules if r.get("enabled", True)]
