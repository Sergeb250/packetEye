import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
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

    ML_ANOMALY_THRESHOLD = float(os.environ.get("ML_ANOMALY_THRESHOLD", 7.5))
    ENRICHMENT_CACHE_TTL_HOURS = int(os.environ.get("ENRICHMENT_CACHE_TTL_HOURS", 24))
    MAX_FLOWS_ML_SCORING = int(os.environ.get("MAX_FLOWS_ML_SCORING", 50000))
    WHITELIST_ENABLED = os.environ.get("WHITELIST_ENABLED", "true").lower() == "true"
    PCAP_RETENTION_DAYS = int(os.environ.get("PCAP_RETENTION_DAYS", 30))

    DETECTION_RULES_DIR = BASE_DIR / "detection_rules"
    WHITELIST_PATH = BASE_DIR / "whitelist" / "default_whitelist.yaml"
    ML_MODEL_PATH = BASE_DIR / "ml_models" / "isolation_forest_base.pkl"

    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_UPLOAD = "10 per hour"


class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = "development"
    CACHE_TYPE = os.environ.get("CACHE_TYPE", "SimpleCache")
    CELERY_TASK_ALWAYS_EAGER = os.environ.get("CELERY_TASK_ALWAYS_EAGER", "true").lower() == "true"


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


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
