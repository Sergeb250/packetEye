import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _build_engine_options(database_uri: str) -> dict:
    """Pool settings sized for web workers plus the live background threads.

    SQLite :memory: is pinned to StaticPool by Flask-SQLAlchemy and rejects
    QueuePool sizing arguments, so it only gets connect_args.
    """
    connect_args = None
    if database_uri.startswith("sqlite"):
        # Busy timeout keeps concurrent live threads from dying on
        # "database is locked"; check_same_thread allows pooled connections
        # to hop between the request and monitor threads.
        connect_args = {"check_same_thread": False, "timeout": 30}
        if ":memory:" in database_uri:
            return {"connect_args": connect_args}

    options: dict = {
        "pool_size": int(os.environ.get("DB_POOL_SIZE", 10)),
        "max_overflow": int(os.environ.get("DB_MAX_OVERFLOW", 20)),
        "pool_timeout": int(os.environ.get("DB_POOL_TIMEOUT", 45)),
        "pool_recycle": int(os.environ.get("DB_POOL_RECYCLE", 1800)),
        "pool_pre_ping": os.environ.get("DB_POOL_PRE_PING", "true").lower() == "true",
    }
    if connect_args:
        options["connect_args"] = connect_args
    return options


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    BASE_DIR = BASE_DIR
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'packeteye.db'}"
    )
    SQLALCHEMY_ENGINE_OPTIONS = _build_engine_options(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    STREAM_DATA_DIR = Path(os.environ.get("STREAM_DATA_DIR", str(BASE_DIR / "data" / "streams")))
    PACKET_STREAM_ENABLED = os.environ.get("PACKET_STREAM_ENABLED", "true").lower() == "true"
    ALERT_STREAM_ENABLED = os.environ.get("ALERT_STREAM_ENABLED", "true").lower() == "true"

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

    LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "zai")
    LLM_API_KEY = os.environ.get("LLM_API_KEY") or os.environ.get("NVIDIA_API_KEY", "")
    LLM_MODEL = os.environ.get("LLM_MODEL", "minimaxai/minimax-m3")
    LLM_CHAT_MODELS = os.environ.get(
        "LLM_CHAT_MODELS",
        "minimaxai/minimax-m3,meta/llama-3.1-8b-instruct,nvidia/llama-3.1-nemotron-nano-8b-v1,deepseek-ai/deepseek-v4-pro",
    )
    LLM_REPORT_MAX_TOKENS = int(os.environ.get("LLM_REPORT_MAX_TOKENS", 2048))
    ZAI_API_KEY = os.environ.get("ZAI_API_KEY", "")
    ZAI_API_BASE = os.environ.get("ZAI_API_BASE", "https://api.z.ai/api/paas/v4/")
    ZAI_MODEL = os.environ.get("ZAI_MODEL", "glm-4.7-flash")
    # Single-provider mode: "zai", "nvidia", or empty for multi-model stack.
    LLM_SINGLE_PROVIDER = os.environ.get("LLM_SINGLE_PROVIDER", "").strip().lower()
    # Legacy aliases (prefer LLM_SINGLE_PROVIDER)
    LLM_ZAI_ONLY = os.environ.get("LLM_ZAI_ONLY", "false").lower() == "true"
    LLM_NVIDIA_ONLY = os.environ.get("LLM_NVIDIA_ONLY", "false").lower() == "true"
    NVIDIA_FALLBACK_MODEL = os.environ.get("NVIDIA_FALLBACK_MODEL", "") or LLM_MODEL
    LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", 768))
    LLM_MAX_CALLS_PER_ANALYSIS = int(os.environ.get("LLM_MAX_CALLS_PER_ANALYSIS", 25))
    LLM_ENABLED = os.environ.get("LLM_ENABLED", "true").lower() == "true"
    NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
    NVIDIA_API_BASE = os.environ.get(
        "NVIDIA_API_BASE", "https://integrate.api.nvidia.com/v1"
    )
    LLM_SECONDARY_MODEL = os.environ.get("LLM_SECONDARY_MODEL", "")
    LLM_SECONDARY_MAX_TOKENS = int(os.environ.get("LLM_SECONDARY_MAX_TOKENS", 512))
    LLM_ENSEMBLE_ENABLED = os.environ.get("LLM_ENSEMBLE_ENABLED", "true").lower() == "true"
    LLM_ENSEMBLE_PARALLEL = os.environ.get("LLM_ENSEMBLE_PARALLEL", "false").lower() == "true"
    LLM_ENSEMBLE_BIG_CONTEXT_CHARS = int(os.environ.get("LLM_ENSEMBLE_BIG_CONTEXT_CHARS", 8000))
    LLM_MAX_CONCURRENT = int(os.environ.get("LLM_MAX_CONCURRENT", "1"))
    LLM_MIN_CALL_INTERVAL_SEC = float(os.environ.get("LLM_MIN_CALL_INTERVAL_SEC", "0.75"))
    OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "deepseek/deepseek-chat")
    OPENROUTER_BASE = os.environ.get("OPENROUTER_BASE", "https://openrouter.ai/api/v1")
    OPENROUTER_MAX_TOKENS = int(os.environ.get("OPENROUTER_MAX_TOKENS", 256))
    # Set false when the OpenRouter account is out of credits — a keyed but
    # broke provider otherwise turns every live packet into a 402 retry storm.
    OPENROUTER_ENABLED = os.environ.get("OPENROUTER_ENABLED", "true").lower() == "true"

    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
    ANYRUN_API_KEY = os.environ.get("ANYRUN_API_KEY", "")
    ANYRUN_LOOKUP_DEPTH = int(os.environ.get("ANYRUN_LOOKUP_DEPTH", 180))
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")
    URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")
    OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
    GREYNOISE_API_KEY = os.environ.get("GREYNOISE_API_KEY", "")
    PULSEDIVE_API_KEY = os.environ.get("PULSEDIVE_API_KEY", "")
    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")

    AUTO_SYNC_EVE = os.environ.get("AUTO_SYNC_EVE", "true").lower() == "true"
    ALERT_ENHANCED_ANALYSIS = os.environ.get("ALERT_ENHANCED_ANALYSIS", "false").lower() == "true"
    LLM_LIVE_ALERT_SYNTHESIS = os.environ.get("LLM_LIVE_ALERT_SYNTHESIS", "false").lower() == "true"
    LLM_LIVE_PACKETS_PER_MIN = int(os.environ.get("LLM_LIVE_PACKETS_PER_MIN", 30))
    LLM_LIVE_PACKET_MIN_CONFIDENCE = float(os.environ.get("LLM_LIVE_PACKET_MIN_CONFIDENCE", 0.55))
    LLM_LIVE_TIMEOUT_SECONDS = float(os.environ.get("LLM_LIVE_TIMEOUT_SECONDS", 18))
    LLM_PROBE_TIMEOUT_SECONDS = float(os.environ.get("LLM_PROBE_TIMEOUT_SECONDS", 12))
    LLM_LIVE_PACKET_MAX_TOKENS = int(os.environ.get("LLM_LIVE_PACKET_MAX_TOKENS", 128))
    LLM_LIVE_BATCH_SIZE = int(os.environ.get("LLM_LIVE_BATCH_SIZE", 10))
    # true restores the old fan-out to every configured model per packet;
    # sequential (primary + conditional verify) is the rate-limit-safe default.
    LLM_LIVE_PARALLEL_TRIAGE = os.environ.get("LLM_LIVE_PARALLEL_TRIAGE", "false").lower() == "true"
    LIVE_ML_LAB_THRESHOLD = float(os.environ.get("LIVE_ML_LAB_THRESHOLD", 4.0))
    EVE_IMPORT_MAX_MB = int(os.environ.get("EVE_IMPORT_MAX_MB", 100))

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
    SCAPY_FLOW_IDLE_SEC = float(os.environ.get("SCAPY_FLOW_IDLE_SEC", 5))
    LIVE_ML_TCPDUMP_ENABLED = os.environ.get("LIVE_ML_TCPDUMP_ENABLED", "true").lower() == "true"
    CAPTURE_LAB_ENABLED = os.environ.get("CAPTURE_LAB_ENABLED", "false").lower() == "true"
    LAB_ROTATE_SEC = int(os.environ.get("LAB_ROTATE_SEC", 12))

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

    # Integration settings (Discord webhooks, filters) — UI writes data/integrations.json
    INTEGRATIONS_CONFIG_PATH = os.environ.get("INTEGRATIONS_CONFIG_PATH", "data/integrations.json")

    # SOC chatbot (reuses LLM_* provider settings)
    CHATBOT_ENABLED = os.environ.get("CHATBOT_ENABLED", "true").lower() == "true"
    CHATBOT_MAX_HISTORY = int(os.environ.get("CHATBOT_MAX_HISTORY", 10))
    CHATBOT_MAX_CONTEXT_CHARS = int(os.environ.get("CHATBOT_MAX_CONTEXT_CHARS", 32000))
    CHATBOT_BRIEF_MAX_TOKENS = int(os.environ.get("CHATBOT_BRIEF_MAX_TOKENS", 256))
    CHATBOT_BRIEF_MAX_CONTEXT_CHARS = int(os.environ.get("CHATBOT_BRIEF_MAX_CONTEXT_CHARS", 12000))

    # Escalation email (Google SMTP / Gmail app password)
    SMTP_ENABLED = os.environ.get("SMTP_ENABLED", "false").lower() == "true"
    SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
    SMTP_USER = os.environ.get("SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
    SMTP_FROM = os.environ.get("SMTP_FROM", "") or os.environ.get("SMTP_USER", "")
    ESCALATION_DEFAULT_TO = os.environ.get("ESCALATION_DEFAULT_TO", "")

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
    SQLALCHEMY_ENGINE_OPTIONS = _build_engine_options(SQLALCHEMY_DATABASE_URI)
    STREAM_DATA_DIR = BASE_DIR / "data" / "streams_test"
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
