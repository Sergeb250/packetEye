"""Detection orchestrator — evaluates all YAML rules against flows."""

import ipaddress
import logging
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from app.models.analysis import Finding, Flow
from app.services.detection.ml_engine import MLEngine
from app.services.detection.rules import load_rules
from app.services.detection.scoring import severity_to_score

logger = logging.getLogger(__name__)


class WhitelistEngine:
    def __init__(self, whitelist_path: Path):
        self.cidrs = []
        self.domains = []
        self.ports = []
        if whitelist_path.exists():
            with open(whitelist_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            for cidr in data.get("cidr_ranges", []):
                try:
                    self.cidrs.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
            self.domains = data.get("domains", [])
            self.ports = data.get("ports_protocols", [])

    def is_whitelisted_flow(self, flow: dict) -> bool:
        dst = flow.get("dst_ip", "")
        try:
            ip = ipaddress.ip_address(dst)
            for net in self.cidrs:
                if ip in net:
                    return True
        except ValueError:
            pass

        for domain_pattern in self.domains:
            for host in (flow.get("dns_queries") or []) + (flow.get("http_hosts") or []):
                if self._match_domain(domain_pattern, host):
                    return True
            sni = flow.get("tls_sni")
            if sni and self._match_domain(domain_pattern, sni):
                return True

        for pp in self.ports:
            if flow.get("dst_port") == pp.get("port") and flow.get("protocol") == pp.get("protocol"):
                return True
        return False

    @staticmethod
    def _match_domain(pattern: str, domain: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return domain.endswith(suffix) or domain == pattern[2:]
        return domain == pattern


class DetectionEngine:
    def __init__(self, config: dict):
        self.config = config
        self.rules = load_rules(Path(config.get("DETECTION_RULES_DIR", "detection_rules")))
        self.whitelist = WhitelistEngine(Path(config.get("WHITELIST_PATH", "")))
        self.ml = MLEngine(
            model_path=Path(config.get("ML_MODEL_PATH", "")),
            threshold=float(config.get("ML_ANOMALY_THRESHOLD", 7.5)),
            max_flows=int(config.get("MAX_FLOWS_ML_SCORING", 50000)),
        )

    def run(self, analysis_id: str, flows: list, arp_events: list, observables: list) -> list[Finding]:
        findings = []
        flow_dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in flows]
        db_flows = Flow.query.filter_by(analysis_id=analysis_id).all()
        flow_by_key = {
            (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.protocol): f for f in db_flows
        }

        for flow in db_flows:
            fd = flow.to_dict()
            if self.config.get("WHITELIST_ENABLED", True):
                flow.is_whitelisted = self.whitelist.is_whitelisted_flow(fd)

        active_flows = [f for f in db_flows if not f.is_whitelisted]

        for rule in self.rules:
            rule_id = rule.get("id", "")
            try:
                triggered = self._evaluate_rule(rule, active_flows, arp_events, observables)
                for item in triggered:
                    finding = Finding(
                        analysis_id=analysis_id,
                        flow_id=item.get("flow_id"),
                        rule_id=rule_id,
                        source="rule",
                        title=rule.get("name", rule_id),
                        description=rule.get("description", ""),
                        severity=rule.get("severity", "medium"),
                        severity_score=severity_to_score(rule.get("severity", "medium")),
                        evidence=item.get("evidence", {}),
                        mitre_tactic=rule.get("mitre_tactic"),
                        mitre_technique=rule.get("mitre_technique"),
                        recommendation=rule.get("recommendation", ""),
                    )
                    findings.append(finding)
            except Exception as exc:
                logger.warning("Rule %s failed: %s", rule_id, exc)

        ml_input = []
        for f in active_flows:
            d = f.to_dict()
            d["id"] = f.id
            d["start_time"] = f.start_time
            d["iat_mean"] = 0
            d["iat_std"] = 0
            d["is_external_dst"] = not self._is_private(f.dst_ip)
            ml_input.append(d)

        ml_results = self.ml.score_flows(ml_input)
        for result in ml_results:
            flow = next((f for f in active_flows if f.id == result["flow_id"]), None)
            if flow:
                flow.anomaly_score = result["anomaly_score"]
            if result["flagged"]:
                findings.append(
                    Finding(
                        analysis_id=analysis_id,
                        flow_id=result["flow_id"],
                        rule_id="ML-ANOMALY-001",
                        source="ml",
                        title="ML Anomaly — outlier flow detected",
                        description=result["explanation"],
                        severity="medium",
                        severity_score=result["anomaly_score"],
                        evidence={"anomaly_score": result["anomaly_score"], "explanation": result["explanation"]},
                        mitre_tactic="TA0011 - Command and Control",
                        mitre_technique="T1071 - Application Layer Protocol",
                        recommendation="Investigate this flow's destination, timing, and payload characteristics.",
                    )
                )

        return findings

    def _evaluate_rule(self, rule, flows, arp_events, observables):
        rule_id = rule.get("id", "")
        params = rule.get("parameters", {})
        handlers = {
            "PORTSCAN-001": self._portscan_horizontal,
            "PORTSCAN-002": self._portscan_vertical,
            "BEACON-001": self._beacon,
            "BEACON-002": self._beacon_slow,
            "DNSTUNNEL-001": self._dns_payload,
            "DNSTUNNEL-002": self._dns_frequency,
            "DNSTUNNEL-003": self._dns_entropy,
            "ARPSPOOFING-001": self._arp_gratuitous,
            "ARPSPOOFING-002": self._arp_storm,
            "PORTMISMATCH-001": self._port_mismatch,
            "EXFIL-001": self._exfil,
            "LATERAL-001": self._lateral,
            "DGATOP-001": self._dga,
            "TLSNONSNI-001": self._tls_no_sni,
            "CLEARTEXT-001": self._cleartext,
            "NEWDOMAIN-001": self._new_domain,
            "LONGCONN-001": self._long_conn,
        }
        handler = handlers.get(rule_id)
        if handler:
            return handler(flows, params, arp_events, observables)
        return []

    def _portscan_horizontal(self, flows, params, arp, obs):
        window = params.get("window_seconds", 30)
        min_ports = params.get("min_ports", 50)
        results = []
        by_src_dst = defaultdict(list)
        for f in flows:
            by_src_dst[(f.src_ip, f.dst_ip)].append(f)

        for (src, dst), group in by_src_dst.items():
            if len(group) < min_ports:
                continue
            times = sorted(f.start_time for f in group if f.start_time)
            if not times:
                continue
            span = (times[-1] - times[0]).total_seconds()
            ports = set(f.dst_port for f in group)
            if len(ports) >= min_ports and span <= window:
                results.append(
                    {
                        "flow_id": group[0].id,
                        "evidence": {"src_ip": src, "dst_ip": dst, "ports_scanned": len(ports), "window_s": span},
                    }
                )
        return results

    def _portscan_vertical(self, flows, params, arp, obs):
        window = params.get("window_seconds", 60)
        min_hosts = params.get("min_hosts", 30)
        results = []
        by_src_port = defaultdict(list)
        for f in flows:
            by_src_port[(f.src_ip, f.dst_port)].append(f)

        for (src, port), group in by_src_port.items():
            dsts = set(f.dst_ip for f in group)
            if len(dsts) < min_hosts:
                continue
            times = sorted(f.start_time for f in group if f.start_time)
            if times and (times[-1] - times[0]).total_seconds() <= window:
                results.append(
                    {
                        "flow_id": group[0].id,
                        "evidence": {"src_ip": src, "port": port, "hosts_scanned": len(dsts)},
                    }
                )
        return results

    def _beacon(self, flows, params, arp, obs):
        return self._beacon_core(flows, params, max_interval=params.get("max_interval_seconds", 3600))

    def _beacon_slow(self, flows, params, arp, obs):
        p = dict(params)
        p["min_interval_seconds"] = params.get("min_interval_seconds", 1800)
        return self._beacon_core(flows, p, max_interval=86400)

    def _beacon_core(self, flows, params, max_interval):
        min_conn = params.get("min_connections", 10)
        max_jitter = params.get("max_jitter_pct", 20) / 100.0
        min_interval = params.get("min_interval_seconds", 10)
        results = []
        groups = defaultdict(list)
        for f in flows:
            if self._is_private(f.dst_ip):
                continue
            groups[(f.src_ip, f.dst_ip, f.dst_port)].append(f)

        for key, group in groups.items():
            if len(group) < min_conn:
                continue
            times = sorted(f.start_time for f in group if f.start_time)
            if len(times) < 2:
                continue
            intervals = [(times[i + 1] - times[i]).total_seconds() for i in range(len(times) - 1)]
            intervals = [i for i in intervals if min_interval <= i <= max_interval]
            if len(intervals) < min_conn - 1:
                continue
            mean_i = sum(intervals) / len(intervals)
            if mean_i == 0:
                continue
            std_i = math.sqrt(sum((x - mean_i) ** 2 for x in intervals) / len(intervals))
            cv = std_i / mean_i
            if cv <= max_jitter:
                results.append(
                    {
                        "flow_id": group[0].id,
                        "evidence": {
                            "src_ip": key[0],
                            "dst_ip": key[1],
                            "dst_port": key[2],
                            "connections": len(group),
                            "mean_interval_s": round(mean_i, 2),
                            "jitter_pct": round(cv * 100, 2),
                        },
                    }
                )
        return results

    def _dns_payload(self, flows, params, arp, obs):
        min_size = params.get("min_payload_bytes", 200)
        results = []
        for f in flows:
            if f.application_layer == "DNS" and (f.bytes_sent + f.bytes_recv) > min_size:
                results.append(
                    {
                        "flow_id": f.id,
                        "evidence": {"dns_queries": f.dns_queries, "payload_bytes": f.bytes_sent + f.bytes_recv},
                    }
                )
        return results

    def _dns_frequency(self, flows, params, arp, obs):
        threshold = params.get("queries_per_minute", 100)
        results = []
        apex_counts = defaultdict(list)
        for f in flows:
            for q in f.dns_queries or []:
                apex = ".".join(q.split(".")[-2:]) if q.count(".") >= 1 else q
                if f.start_time:
                    apex_counts[(f.src_ip, apex)].append(f.start_time)

        for (src, apex), times in apex_counts.items():
            if len(times) < threshold:
                continue
            times = sorted(times)
            span_min = max(1, (times[-1] - times[0]).total_seconds() / 60)
            rate = len(times) / span_min
            if rate >= threshold:
                results.append({"evidence": {"src_ip": src, "apex": apex, "queries_per_minute": round(rate, 1)}})
        return results

    def _dns_entropy(self, flows, params, arp, obs):
        min_entropy = params.get("min_entropy", 3.8)
        results = []
        for f in flows:
            for q in f.dns_queries or []:
                labels = q.split(".")
                if len(labels) > 2:
                    subdomain = labels[0]
                    ent = self._shannon_entropy(subdomain)
                    if ent >= min_entropy:
                        results.append({"flow_id": f.id, "evidence": {"domain": q, "entropy": round(ent, 2)}})
        return results

    def _arp_gratuitous(self, flows, params, arp, obs):
        results = []
        for event in arp:
            if event.get("op") == 1:  # request can be gratuitous
                results.append({"evidence": event})
        return results[:5]

    def _arp_storm(self, flows, params, arp, obs):
        threshold = params.get("min_replies", 50)
        window = params.get("window_seconds", 10)
        by_mac = defaultdict(list)
        for event in arp:
            if event.get("op") == 2:
                by_mac[event["sender_mac"]].append(event["timestamp"])

        results = []
        for mac, times in by_mac.items():
            times = sorted(times)
            for i in range(len(times)):
                count = sum(1 for t in times[i:] if t - times[i] <= window)
                if count >= threshold:
                    results.append({"evidence": {"mac": mac, "reply_count": count, "window_s": window}})
                    break
        return results

    def _port_mismatch(self, flows, params, arp, obs):
        results = []
        for f in flows:
            app = f.application_layer
            port = f.dst_port
            if app == "SSH" and port != 22:
                results.append({"flow_id": f.id, "evidence": {"app": app, "port": port}})
            elif app == "HTTP" and port not in (80, 443, 8080, 8000):
                results.append({"flow_id": f.id, "evidence": {"app": app, "port": port}})
            elif app == "DNS" and port != 53:
                results.append({"flow_id": f.id, "evidence": {"app": app, "port": port}})
        return results

    def _exfil(self, flows, params, arp, obs):
        multiplier = params.get("multiplier", 10)
        outbound = [f.bytes_sent for f in flows if f.bytes_sent > 0]
        if not outbound:
            return []
        mean_out = sum(outbound) / len(outbound)
        results = []
        for f in flows:
            if f.bytes_sent > mean_out * multiplier and self._is_private(f.src_ip) and not self._is_private(f.dst_ip):
                results.append(
                    {
                        "flow_id": f.id,
                        "evidence": {"bytes_sent": f.bytes_sent, "baseline_mean": round(mean_out, 0), "dst_ip": f.dst_ip},
                    }
                )
        return results

    def _lateral(self, flows, params, arp, obs):
        ports = params.get("ports", [445, 3389, 5985])
        results = []
        by_src = defaultdict(set)
        for f in flows:
            if f.dst_port in ports and self._is_private(f.src_ip) and self._is_private(f.dst_ip):
                by_src[f.src_ip].add(f.dst_ip)
        for src, dsts in by_src.items():
            if len(dsts) >= params.get("min_targets", 3):
                results.append({"evidence": {"src_ip": src, "targets": list(dsts), "ports": ports}})
        return results

    def _dga(self, flows, params, arp, obs):
        results = []
        for f in flows:
            for q in f.dns_queries or []:
                label = q.split(".")[0]
                cv_ratio = self._consonant_vowel_ratio(label)
                bigram_ent = self._bigram_entropy(label)
                if cv_ratio > params.get("min_cv_ratio", 3) or bigram_ent > params.get("min_bigram_entropy", 4.2):
                    results.append(
                        {"flow_id": f.id, "evidence": {"domain": q, "cv_ratio": round(cv_ratio, 2), "bigram_entropy": round(bigram_ent, 2)}}
                    )
        return results

    def _tls_no_sni(self, flows, params, arp, obs):
        results = []
        for f in flows:
            if f.application_layer == "TLS" and not f.tls_sni and not self._is_private(f.dst_ip):
                results.append({"flow_id": f.id, "evidence": {"dst_ip": f.dst_ip, "dst_port": f.dst_port}})
        return results

    def _cleartext(self, flows, params, arp, obs):
        results = []
        for f in flows:
            if f.application_layer == "HTTP" and f.dst_port not in (443,):
                hosts = f.http_hosts or []
                if any("login" in h.lower() or "auth" in h.lower() for h in hosts):
                    results.append({"flow_id": f.id, "evidence": {"hosts": hosts, "port": f.dst_port}})
        return results

    def _new_domain(self, flows, params, arp, obs):
        results = []
        for o in obs:
            if hasattr(o, "type") and o.type == "domain":
                whois_data = (o.enrichment_json or {}).get("whois", {})
                if whois_data.get("newly_registered"):
                    results.append({"evidence": {"domain": o.value, "creation_date": whois_data.get("creation_date")}})
        return results

    def _long_conn(self, flows, params, arp, obs):
        min_hours = params.get("min_duration_hours", 8)
        min_ms = min_hours * 3600 * 1000
        results = []
        for f in flows:
            if f.protocol == "TCP" and f.duration_ms >= min_ms:
                results.append(
                    {"flow_id": f.id, "evidence": {"duration_hours": round(f.duration_ms / 3600000, 2), "dst_ip": f.dst_ip}}
                )
        return results

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _consonant_vowel_ratio(s: str) -> float:
        vowels = set("aeiou")
        consonants = sum(1 for c in s.lower() if c.isalpha() and c not in vowels)
        vowel_count = sum(1 for c in s.lower() if c in vowels)
        return consonants / max(vowel_count, 1)

    @staticmethod
    def _bigram_entropy(s: str) -> float:
        if len(s) < 2:
            return 0.0
        bigrams = [s[i : i + 2] for i in range(len(s) - 1)]
        freq = defaultdict(int)
        for b in bigrams:
            freq[b] += 1
        total = len(bigrams)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())
