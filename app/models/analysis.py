import uuid
from datetime import datetime, timezone

from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(512), nullable=False)
    file_path = db.Column(db.String(1024), nullable=False)
    analysis_name = db.Column(db.String(256))
    analyst_notes = db.Column(db.Text)
    status = db.Column(
        db.String(32), default="queued", nullable=False
    )  # queued, parsing, enriching, analyzing, complete, failed
    progress_pct = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
    completed_at = db.Column(db.DateTime)
    total_flows = db.Column(db.Integer, default=0)
    total_findings = db.Column(db.Integer, default=0)
    risk_score = db.Column(db.Float, default=0.0)
    summary_json = db.Column(db.JSON, default=dict)
    report_json = db.Column(db.JSON, default=dict)

    flows = db.relationship("Flow", backref="analysis", lazy="dynamic", cascade="all, delete-orphan")
    observables = db.relationship(
        "Observable", backref="analysis", lazy="dynamic", cascade="all, delete-orphan"
    )
    findings = db.relationship(
        "Finding", backref="analysis", lazy="dynamic", cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "analysis_name": self.analysis_name,
            "status": self.status,
            "progress_pct": self.progress_pct,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_flows": self.total_flows,
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "summary_json": self.summary_json or {},
            "error_message": self.error_message,
        }


class Flow(db.Model):
    __tablename__ = "flows"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False, index=True)
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    dst_ip = db.Column(db.String(45), nullable=False, index=True)
    src_port = db.Column(db.Integer, default=0)
    dst_port = db.Column(db.Integer, default=0)
    protocol = db.Column(db.String(16), default="TCP")
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    duration_ms = db.Column(db.Integer, default=0)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_recv = db.Column(db.BigInteger, default=0)
    packets_sent = db.Column(db.Integer, default=0)
    packets_recv = db.Column(db.Integer, default=0)
    application_layer = db.Column(db.String(32))
    dns_queries = db.Column(db.JSON, default=list)
    http_hosts = db.Column(db.JSON, default=list)
    tls_sni = db.Column(db.String(512))
    ja3_hash = db.Column(db.String(64))
    ja3s_hash = db.Column(db.String(64))
    tls_cert_subject = db.Column(db.String(512))
    tls_cert_issuer = db.Column(db.String(512))
    tls_cert_san = db.Column(db.JSON, default=list)
    user_agents = db.Column(db.JSON, default=list)
    enrichment_json = db.Column(db.JSON, default=dict)
    anomaly_score = db.Column(db.Float, default=0.0)
    rule_flags = db.Column(db.JSON, default=list)
    severity_score = db.Column(db.Float, default=0.0)
    is_whitelisted = db.Column(db.Boolean, default=False)

    findings = db.relationship("Finding", backref="flow", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "application_layer": self.application_layer,
            "dns_queries": self.dns_queries or [],
            "http_hosts": self.http_hosts or [],
            "tls_sni": self.tls_sni,
            "ja3_hash": self.ja3_hash,
            "severity_score": self.severity_score,
            "anomaly_score": self.anomaly_score,
            "rule_flags": self.rule_flags or [],
            "is_whitelisted": self.is_whitelisted,
            "enrichment_json": self.enrichment_json or {},
        }


class Observable(db.Model):
    __tablename__ = "observables"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False, index=True)
    type = db.Column(db.String(32), nullable=False)  # ip, domain, ja3, cert_hash, url, user_agent
    value = db.Column(db.String(1024), nullable=False, index=True)
    enrichment_status = db.Column(
        db.String(16), default="pending"
    )  # pending, complete, error, cached
    enrichment_json = db.Column(db.JSON, default=dict)
    first_seen = db.Column(db.DateTime, default=utcnow)
    occurrence_count = db.Column(db.Integer, default=1)
    is_malicious = db.Column(db.Boolean, default=False)
    confidence = db.Column(db.Float, default=0.0)

    __table_args__ = (
        db.UniqueConstraint("analysis_id", "type", "value", name="uq_observable"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "enrichment_status": self.enrichment_status,
            "enrichment_json": self.enrichment_json or {},
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "occurrence_count": self.occurrence_count,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
        }


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    analysis_id = db.Column(db.String(36), db.ForeignKey("analyses.id"), nullable=False, index=True)
    flow_id = db.Column(db.String(36), db.ForeignKey("flows.id"), nullable=True)
    rule_id = db.Column(db.String(64), nullable=False)
    source = db.Column(db.String(32), default="rule")  # rule, ml, llm, ti_correlation
    title = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default="medium")
    severity_score = db.Column(db.Float, default=5.0)
    evidence = db.Column(db.JSON, default=dict)
    mitre_tactic = db.Column(db.String(128))
    mitre_technique = db.Column(db.String(128))
    recommendation = db.Column(db.Text)
    llm_explanation = db.Column(db.Text)
    llm_confidence = db.Column(db.String(16))
    is_false_positive = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "rule_id": self.rule_id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "evidence": self.evidence or {},
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "recommendation": self.recommendation,
            "llm_explanation": self.llm_explanation,
            "llm_confidence": self.llm_confidence,
            "is_false_positive": self.is_false_positive,
        }
