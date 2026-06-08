"""Assembles final report object for UI and export."""

from collections import Counter, defaultdict

from app.models.analysis import Analysis, Finding, Flow, Observable
from app.services.detection.scoring import compute_analysis_risk_score


class ReportBuilder:
    def build(self, analysis_id: str, executive_summary: str = "", hunt_hypotheses: list = None) -> dict:
        analysis = Analysis.query.get(analysis_id)
        flows = Flow.query.filter_by(analysis_id=analysis_id).all()
        findings = Finding.query.filter_by(analysis_id=analysis_id, is_false_positive=False).all()
        observables = Observable.query.filter_by(analysis_id=analysis_id).all()

        severity_counts = Counter(f.severity for f in findings)
        external_ips = set()
        for f in flows:
            if f.dst_ip and not _is_private(f.dst_ip):
                external_ips.add(f.dst_ip)

        protocol_counts = Counter(f.application_layer or f.protocol for f in flows)
        top_talkers = Counter()
        for f in flows:
            top_talkers[f.src_ip] += f.bytes_sent + f.bytes_recv

        dns_queries = Counter()
        for f in flows:
            for q in f.dns_queries or []:
                dns_queries[q] += 1

        geo_markers = []
        for obs in observables:
            if obs.type == "ip":
                geo = (obs.enrichment_json or {}).get("geo", {})
                if geo.get("lat") and geo.get("lon"):
                    geo_markers.append(
                        {
                            "ip": obs.value,
                            "lat": geo["lat"],
                            "lon": geo["lon"],
                            "country": geo.get("country"),
                            "is_malicious": obs.is_malicious,
                            "enrichment": obs.enrichment_json,
                        }
                    )

        timeline = defaultdict(int)
        for f in flows:
            if f.start_time:
                bucket = f.start_time.strftime("%Y-%m-%d %H:%M")
                timeline[bucket] += f.bytes_sent + f.bytes_recv

        whitelisted_count = sum(1 for f in flows if f.is_whitelisted)

        report = {
            "analysis": analysis.to_dict(),
            "executive_summary": executive_summary,
            "hunt_hypotheses": hunt_hypotheses or [],
            "risk_score": compute_analysis_risk_score(findings),
            "metrics": {
                "total_flows": len(flows),
                "whitelisted_flows": whitelisted_count,
                "unique_external_ips": len(external_ips),
                "malicious_observables": sum(1 for o in observables if o.is_malicious),
                "findings_by_severity": dict(severity_counts),
            },
            "charts": {
                "protocol_distribution": dict(protocol_counts.most_common(10)),
                "top_talkers": dict(top_talkers.most_common(10)),
                "traffic_timeline": dict(sorted(timeline.items())),
                "dns_top_domains": dict(dns_queries.most_common(20)),
                "port_heatmap": dict(Counter(f.dst_port for f in flows).most_common(20)),
            },
            "geo_markers": geo_markers,
            "findings_count": len(findings),
        }
        return report


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
