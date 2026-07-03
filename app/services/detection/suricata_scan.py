"""Offline Suricata scan: replay a PCAP against the configured rules.

Runs `suricata -r <pcap>` with the custom rules saved from the dashboard's
rule editor and converts EVE alerts into packetEye findings (source=suricata).
Skips silently when Suricata is not installed — the rest of the pipeline is
unaffected.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

SCAN_TIMEOUT_SECONDS = 180


def _resolve_suricata(config: dict) -> str | None:
    binary = str(config.get("SURICATA_BIN") or "suricata")
    found = shutil.which(binary)
    if found:
        return found
    return binary if Path(binary).is_file() else None


def scan_pcap(config: dict, pcap_path: str) -> list[dict]:
    """Return Suricata alert dicts for a PCAP, or [] when unavailable."""
    if not config.get("PCAP_SURICATA_ENABLED", True):
        return []
    binary = _resolve_suricata(config)
    if not binary or not Path(pcap_path).is_file():
        return []

    with tempfile.TemporaryDirectory(prefix="pe-suricata-") as log_dir:
        cmd = [binary, "-r", str(pcap_path), "-l", log_dir]
        suricata_config = str(config.get("SURICATA_CONFIG_PATH") or "").strip()
        if suricata_config and Path(suricata_config).is_file():
            cmd += ["-c", suricata_config]
        rules = str(config.get("SURICATA_CUSTOM_RULES_PATH") or "").strip()
        if rules and Path(rules).is_file() and Path(rules).stat().st_size > 0:
            cmd += ["-S", rules]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Suricata PCAP scan timed out after %ss", SCAN_TIMEOUT_SECONDS)
            return []
        except OSError as exc:
            logger.warning("Suricata PCAP scan failed to start: %s", exc)
            return []

        if proc.returncode != 0:
            logger.warning(
                "Suricata PCAP scan exited %s: %s", proc.returncode, (proc.stderr or "")[:500]
            )
            return []

        eve = Path(log_dir) / "eve.json"
        if not eve.is_file():
            return []
        return _parse_eve_alerts(eve)


def _parse_eve_alerts(eve_path: Path, limit: int = 500) -> list[dict]:
    alerts = []
    try:
        with open(eve_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(alerts) >= limit:
                    break
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                alert = event.get("alert", {}) or {}
                alerts.append(
                    {
                        "signature": alert.get("signature", "Suricata alert"),
                        "signature_id": alert.get("signature_id"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity", 3),
                        "src_ip": event.get("src_ip"),
                        "src_port": event.get("src_port"),
                        "dst_ip": event.get("dest_ip"),
                        "dst_port": event.get("dest_port"),
                        "protocol": event.get("proto"),
                        "timestamp": event.get("timestamp"),
                    }
                )
    except OSError as exc:
        logger.warning("Could not read Suricata eve.json: %s", exc)
    return alerts


def alerts_to_findings(analysis_id: str, alerts: list[dict]) -> list:
    """Aggregate identical signatures and convert to Finding rows."""
    from app.models.analysis import Finding

    severity_map = {1: "high", 2: "medium", 3: "low"}
    by_signature: dict = {}
    for alert in alerts:
        key = alert.get("signature_id") or alert.get("signature")
        entry = by_signature.setdefault(key, {"alert": alert, "count": 0, "pairs": set()})
        entry["count"] += 1
        entry["pairs"].add((alert.get("src_ip"), alert.get("dst_ip")))

    findings = []
    for entry in by_signature.values():
        alert = entry["alert"]
        severity = severity_map.get(alert.get("severity", 3), "low")
        pairs = list(entry["pairs"])[:5]
        findings.append(
            Finding(
                analysis_id=analysis_id,
                rule_id=f"SURICATA-{alert.get('signature_id') or 'SIG'}",
                source="suricata",
                title=f"Suricata: {alert.get('signature')}",
                description=(
                    f"Signature '{alert.get('signature')}' matched {entry['count']} time(s) "
                    f"in this PCAP (category: {alert.get('category') or 'n/a'})."
                ),
                severity=severity,
                severity_score={"high": 8.0, "medium": 5.5, "low": 3.0}[severity],
                evidence={
                    "signature": alert.get("signature"),
                    "signature_id": alert.get("signature_id"),
                    "category": alert.get("category"),
                    "hit_count": entry["count"],
                    "host_pairs": [f"{s} → {d}" for s, d in pairs],
                    "src_ip": alert.get("src_ip"),
                    "dst_ip": alert.get("dst_ip"),
                    "dst_port": alert.get("dst_port"),
                    "protocol": alert.get("protocol"),
                },
                recommendation="Review the matched signature and validate traffic between the listed hosts.",
            )
        )
    return findings
