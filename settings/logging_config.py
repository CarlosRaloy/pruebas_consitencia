import logging
from pathlib import Path

APP_VERSION = "0.0.1"

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


class AppVersionFilter(logging.Filter):


    def filter(self, record: logging.LogRecord) -> bool:
        record.app_version = APP_VERSION
        return True


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {
        "app_version": {
            "()": AppVersionFilter,
        },
    },
    "formatters": {
        "standard": {
            "format": "%(asctime)s | %(levelname)-8s | %(name)s | ver=%(app_version)s | %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "filters": ["app_version"],
            "formatter": "standard",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "lims.log"),
            "maxBytes": 5 * 1024 * 1024,
            "backupCount": 5,
            "encoding": "utf-8",
            "filters": ["app_version"],
            "formatter": "standard",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security.csrf": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": False,
        },
        "matplotlib.category": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": False,
        },
        "lims": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(f"lims.{name}" if name else "lims")