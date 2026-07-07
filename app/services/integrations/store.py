"""Persist integration settings (Discord webhooks, filters) in JSON."""

from __future__ import annotations

import json
import logging
import os
import threading
from copy import deepcopy
from pathlib import Path

logger = logging.getLogger(__name__)

_lock = threading.Lock()

DEFAULT_DISCORD = {
    "enabled": False,
    "url": "",
    "severities": ["high", "critical"],
    "sources": ["ml", "suricata", "correlation", "llm"],
    "ai_statuses": ["true_positive"],
    "rate_limit_per_minute": 10,
}

DEFAULT_INTEGRATIONS = {
    "webhooks": {
        "discord": deepcopy(DEFAULT_DISCORD),
    }
}

VALID_SEVERITIES = frozenset({"all", "info", "low", "medium", "high", "critical"})
VALID_SOURCES = frozenset({"all", "ml", "suricata", "correlation", "llm"})
VALID_AI_STATUSES = frozenset({
    "all", "true_positive", "true_negative", "false_positive", "benign", "open", "error",
})


def _config_path(config: dict | None = None) -> Path:
    if config and config.get("INTEGRATIONS_CONFIG_PATH"):
        return Path(config["INTEGRATIONS_CONFIG_PATH"])
    return Path(os.environ.get("INTEGRATIONS_CONFIG_PATH", "data/integrations.json"))


def mask_url(url: str) -> str:
    url = str(url or "").strip()
    if not url:
        return ""
    if len(url) <= 12:
        return "••••••••"
    return f"{url[:8]}…{url[-4:]}"


def _normalize_list(values: list | str | None, valid: frozenset[str], default: list[str]) -> list[str]:
    if not values:
        return list(default)
    if isinstance(values, str):
        values = [values]
    out = [str(v).lower().strip() for v in values if str(v).strip()]
    if "all" in out:
        return ["all"]
    cleaned = [v for v in out if v in valid]
    return cleaned or list(default)


def _merge_defaults(data: dict) -> dict:
    merged = deepcopy(DEFAULT_INTEGRATIONS)
    webhooks = data.get("webhooks") or {}
    discord = webhooks.get("discord") or {}
    for key, default in DEFAULT_DISCORD.items():
        if key in discord and discord[key] is not None:
            merged["webhooks"]["discord"][key] = discord[key]
    dc = merged["webhooks"]["discord"]
    dc["severities"] = _normalize_list(dc.get("severities"), VALID_SEVERITIES, DEFAULT_DISCORD["severities"])
    dc["sources"] = _normalize_list(dc.get("sources"), VALID_SOURCES, DEFAULT_DISCORD["sources"])
    dc["ai_statuses"] = _normalize_list(dc.get("ai_statuses"), VALID_AI_STATUSES, DEFAULT_DISCORD["ai_statuses"])
    dc["enabled"] = bool(dc.get("enabled"))
    dc["url"] = str(dc.get("url") or "").strip()
    dc["rate_limit_per_minute"] = max(1, int(dc.get("rate_limit_per_minute") or DEFAULT_DISCORD["rate_limit_per_minute"]))
    return merged


def _bootstrap_from_env(data: dict, config: dict | None) -> dict:
    """Seed Discord URL from .env when JSON has none."""
    dc = data["webhooks"]["discord"]
    env_url = ""
    if config:
        env_url = str(config.get("ALERT_WEBHOOK_URL") or "").strip()
    if not env_url:
        env_url = str(os.environ.get("ALERT_WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL") or "").strip()
    if env_url and not dc.get("url"):
        dc["url"] = env_url
        dc["enabled"] = True
        if config:
            min_sev = str(config.get("ALERT_WEBHOOK_MIN_SEVERITY") or "high").lower()
            if min_sev == "all":
                dc["severities"] = ["all"]
            elif min_sev in VALID_SEVERITIES:
                dc["severities"] = [min_sev, "critical"] if min_sev != "critical" else ["critical"]
            rate = config.get("ALERT_WEBHOOK_RATE_LIMIT")
            if rate:
                dc["rate_limit_per_minute"] = max(1, int(rate))
    return data


def load_integrations(config: dict | None = None) -> dict:
    path = _config_path(config)
    with _lock:
        if path.is_file():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    data = _merge_defaults(raw)
                else:
                    data = deepcopy(DEFAULT_INTEGRATIONS)
            except Exception as exc:
                logger.warning("Failed to load integrations config %s: %s", path, exc)
                data = deepcopy(DEFAULT_INTEGRATIONS)
        else:
            data = deepcopy(DEFAULT_INTEGRATIONS)
        data = _bootstrap_from_env(data, config)
        return data


def save_integrations(data: dict, config: dict | None = None) -> dict:
    path = _config_path(config)
    merged = _merge_defaults(data)
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        tmp.replace(path)
    return merged


def get_discord_config(config: dict | None = None) -> dict:
    return load_integrations(config)["webhooks"]["discord"]


def get_discord_public_config(config: dict | None = None) -> dict:
    dc = get_discord_config(config)
    env_url = ""
    if config:
        env_url = str(config.get("ALERT_WEBHOOK_URL") or "").strip()
    return {
        "enabled": bool(dc.get("enabled")),
        "url_configured": bool(dc.get("url")),
        "url_masked": mask_url(dc.get("url") or ""),
        "severities": dc.get("severities") or [],
        "sources": dc.get("sources") or [],
        "ai_statuses": dc.get("ai_statuses") or [],
        "rate_limit_per_minute": dc.get("rate_limit_per_minute", 10),
        "env_fallback_url": bool(env_url and not dc.get("url")),
    }


def save_discord_config(payload: dict, config: dict | None = None) -> dict:
    current = load_integrations(config)
    dc = current["webhooks"]["discord"]

    if "enabled" in payload:
        dc["enabled"] = bool(payload["enabled"])

    url = payload.get("url")
    if url is not None:
        url = str(url).strip()
        if url:
            if not url.startswith("https://"):
                raise ValueError("Webhook URL must start with https://")
            dc["url"] = url

    if "severities" in payload:
        dc["severities"] = _normalize_list(payload["severities"], VALID_SEVERITIES, DEFAULT_DISCORD["severities"])
    if "sources" in payload:
        dc["sources"] = _normalize_list(payload["sources"], VALID_SOURCES, DEFAULT_DISCORD["sources"])
    if "ai_statuses" in payload:
        dc["ai_statuses"] = _normalize_list(payload["ai_statuses"], VALID_AI_STATUSES, DEFAULT_DISCORD["ai_statuses"])
    if "rate_limit_per_minute" in payload:
        dc["rate_limit_per_minute"] = max(1, int(payload["rate_limit_per_minute"]))

    current["webhooks"]["discord"] = dc
    return save_integrations(current, config)
