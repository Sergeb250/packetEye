import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    BASE_DIR = BASE_DIR
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'packeteye.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "data" / "uploads"))
    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", 500))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024

    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    CACHE_TYPE = os.environ.get("CACHE_TYPE", "RedisCache")
    CACHE_REDIS_URL = REDIS_URL
    CACHE_DEFAULT_TIMEOUT = 3600
    CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "false").lower() == "true"

    CELERY_BROKER_URL = REDIS_URL
    CELERY_RESULT_BACKEND = REDIS_URL

    LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "nvidia")
    LLM_API_KEY = os.environ.get("LLM_API_KEY") or os.environ.get("NVIDIA_API_KEY", "")
    LLM_MODEL = os.environ.get("LLM_MODEL", "deepseek-ai/deepseek-v4-pro")
    LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", 2048))
    LLM_MAX_CALLS_PER_ANALYSIS = int(os.environ.get("LLM_MAX_CALLS_PER_ANALYSIS", 25))
    LLM_ENABLED = os.environ.get("LLM_ENABLED", "true").lower() == "true"
    NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
    NVIDIA_API_BASE = os.environ.get(
        "NVIDIA_API_BASE", "https://integrate.api.nvidia.com/v1"
    )

    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    ANYRUN_API_KEY = os.environ.get("ANYRUN_API_KEY", "")
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
    OTX_API_KEY = os.environ.get("OTX_API_KEY", "")

    MAXMIND_DB_PATH = os.environ.get("MAXMIND_DB_PATH", "")

    # 0-10 anomaly scale where 5.0 == Isolation Forest decision boundary.
    # Scores are calibrated against the benign training distribution
    # (ml_models/score_calibration.json); tune with scripts/tune_threshold.py.
    ML_ANOMALY_THRESHOLD = float(os.environ.get("ML_ANOMALY_THRESHOLD", 5.0))
    ENRICHMENT_CACHE_TTL_HOURS = int(os.environ.get("ENRICHMENT_CACHE_TTL_HOURS", 24))
    MAX_FLOWS_ML_SCORING = int(os.environ.get("MAX_FLOWS_ML_SCORING", 50000))
    ML_TRAIN_ON_PCAP_FALLBACK = os.environ.get("ML_TRAIN_ON_PCAP_FALLBACK", "false").lower() == "true"
    WHITELIST_ENABLED = os.environ.get("WHITELIST_ENABLED", "true").lower() == "true"
    PCAP_RETENTION_DAYS = int(os.environ.get("PCAP_RETENTION_DAYS", 30))

    DETECTION_RULES_DIR = BASE_DIR / "detection_rules"
    WHITELIST_PATH = BASE_DIR / "whitelist" / "default_whitelist.yaml"
    ML_MODEL_PATH = BASE_DIR / "ml_models" / "isolation_forest_base.pkl"
    ML_SCALER_PATH = BASE_DIR / "ml_models" / "feature_scaler.pkl"
    ML_FEATURE_SCHEMA_PATH = BASE_DIR / "ml_models" / "feature_schema.json"
    ML_SCORE_CALIBRATION_PATH = BASE_DIR / "ml_models" / "score_calibration.json"

    LIVE_MONITOR_ENABLED = os.environ.get("LIVE_MONITOR_ENABLED", "false").lower() == "true"
    SURICATA_EVE_PATH = os.environ.get(
        "SURICATA_EVE_PATH", str(BASE_DIR / "data" / "suricata" / "eve.json")
    )
    LIVE_ALERT_RATE_LIMIT = int(os.environ.get("LIVE_ALERT_RATE_LIMIT", 60))
    LIVE_PORT_ENTROPY_WINDOW = int(os.environ.get("LIVE_PORT_ENTROPY_WINDOW", 300))
    LIVE_INGEST_SURICATA_ALERTS = os.environ.get("LIVE_INGEST_SURICATA_ALERTS", "true").lower() == "true"
    LIVE_CORRELATION_WINDOW = int(os.environ.get("LIVE_CORRELATION_WINDOW", 120))

    SURICATA_BIN = os.environ.get("SURICATA_BIN", "suricata")
    SURICATA_CONFIG_PATH = os.environ.get("SURICATA_CONFIG_PATH", "")
    SURICATA_INTERFACE = os.environ.get("SURICATA_INTERFACE", "")
    SURICATA_LOG_DIR = os.environ.get("SURICATA_LOG_DIR", str(BASE_DIR / "data" / "suricata"))
    SURICATA_CUSTOM_RULES_PATH = os.environ.get(
        "SURICATA_CUSTOM_RULES_PATH", str(BASE_DIR / "deploy" / "suricata" / "custom.rules")
    )
    SURICATA_ALLOW_LOOPBACK = os.environ.get("SURICATA_ALLOW_LOOPBACK", "false").lower() == "true"

    # Per-attempt LLM API timeout — a dead endpoint must not stall the pipeline
    LLM_TIMEOUT_SECONDS = float(os.environ.get("LLM_TIMEOUT_SECONDS", 45))

    # Replay uploaded PCAPs against the saved Suricata rules during detection
    PCAP_SURICATA_ENABLED = os.environ.get("PCAP_SURICATA_ENABLED", "true").lower() == "true"

    # Unified capture (Linux sensor): suricata (rules + EVE flows) or tcpdump
    # fallback (rotating PCAP chunks auto-analyzed by the chunk watcher).
    CAPTURE_MODE = os.environ.get("CAPTURE_MODE", "suricata")
    CAPTURE_INTERFACE = os.environ.get("CAPTURE_INTERFACE", "") or os.environ.get("SURICATA_INTERFACE", "")
    CAPTURE_STATE_DIR = os.environ.get("CAPTURE_STATE_DIR", str(BASE_DIR / "data" / "capture"))
    TCPDUMP_BIN = os.environ.get("TCPDUMP_BIN", "tcpdump")
    CAPTURE_USE_SUDO = os.environ.get("CAPTURE_USE_SUDO", "true").lower() == "true"
    # Linux default is set at runtime in resolve_tcpdump_chunk_dir() — avoids AppArmor
    # blocking tcpdump writes under $HOME. Override with TCPDUMP_CHUNK_DIR in .env.
    TCPDUMP_CHUNK_DIR = os.environ.get("TCPDUMP_CHUNK_DIR", "")
    TCPDUMP_CHUNK_SECONDS = int(os.environ.get("TCPDUMP_CHUNK_SECONDS", 300))
    TCPDUMP_CHUNK_KEEP = int(os.environ.get("TCPDUMP_CHUNK_KEEP", 10))

    # on_investigate: OSINT enrichment runs only when an analyst investigates an
    # alert/finding. bulk: legacy behavior — enrich every observable at ingest.
    ENRICHMENT_MODE = os.environ.get("ENRICHMENT_MODE", "on_investigate")
    AUTO_INVESTIGATE_LIVE = os.environ.get("AUTO_INVESTIGATE_LIVE", "false").lower() == "true"

    # Outbound alert webhooks (Discord-compatible). Empty = disabled.
    ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "") or os.environ.get("DISCORD_WEBHOOK_URL", "")
    ALERT_WEBHOOK_MIN_SEVERITY = os.environ.get("ALERT_WEBHOOK_MIN_SEVERITY", "high")
    ALERT_WEBHOOK_RATE_LIMIT = int(os.environ.get("ALERT_WEBHOOK_RATE_LIMIT", 10))  # per minute

    # SOC chatbot (reuses LLM_* provider settings)
    CHATBOT_ENABLED = os.environ.get("CHATBOT_ENABLED", "true").lower() == "true"
    CHATBOT_MAX_HISTORY = int(os.environ.get("CHATBOT_MAX_HISTORY", 10))

    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_UPLOAD = "10 per hour"


class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = "development"
    CACHE_TYPE = os.environ.get("CACHE_TYPE", "SimpleCache")
    CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "true").lower() == "true"
    LIVE_MONITOR_ENABLED = os.environ.get("LIVE_MONITOR_ENABLED", "true").lower() == "true"


class ProductionConfig(Config):
    DEBUG = False
    FLASK_ENV = "production"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    LLM_ENABLED = False
    WHITELIST_ENABLED = False
    CACHE_TYPE = "SimpleCache"
    CELERY_TASK_ALWAYS_EAGER = True
    ML_TRAIN_ON_PCAP_FALLBACK = True
    LIVE_MONITOR_ENABLED = True


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
