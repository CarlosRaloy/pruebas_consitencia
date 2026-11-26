import os
from pathlib import Path
from settings.logging_config import LOGGING

SETTINGS_DIR = Path(__file__).resolve().parent
BASE_DIR = SETTINGS_DIR.parent

def load_dotenv_strict(env_path: Path):

    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


load_dotenv_strict(BASE_DIR / ".env")

REQUIRED_ENV_VARS = [
    "SECRET_KEY",
    "ALLOWED_HOSTS",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_HOST",
]
missing_vars = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v, "").strip()]
if missing_vars:
    raise RuntimeError(
        f"[SEGURIDAD] Faltan variables obligatorias en el entorno o archivo .env: {', '.join(missing_vars)}"
    )

DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")
USE_HTTPS = os.environ.get("USE_HTTPS", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = [
    h.strip() for h in os.environ["ALLOWED_HOSTS"].split(",") if h.strip() and h.strip() != "*"
]
if not ALLOWED_HOSTS:
    raise RuntimeError("[SEGURIDAD] ALLOWED_HOSTS no puede estar vacío ni usar '*' en modo blindado.")

SECRET_KEY = os.environ["SECRET_KEY"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "__main__",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "__main__.AutoCsrfAndHeadersMiddleware",
]

ROOT_URLCONF = "__main__"
LOGIN_URL = "/login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ],
        },
    }
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["DB_NAME"],
        "USER": os.environ["DB_USER"],
        "PASSWORD": os.environ["DB_PASSWORD"],
        "HOST": os.environ["DB_HOST"],
        "PORT": os.environ.get("DB_PORT", "5432"),
        "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "600")),
        "OPTIONS": {
            "connect_timeout": 10,
        },
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_SECURE = USE_HTTPS
SESSION_COOKIE_AGE = 28800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SECURE = USE_HTTPS
CSRF_TRUSTED_ORIGINS = [
    f"{'https' if USE_HTTPS else 'http'}://{h}" for h in ALLOWED_HOSTS
]

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
SECURE_SSL_REDIRECT = USE_HTTPS
SECURE_HSTS_SECONDS = 31536000 if USE_HTTPS else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = USE_HTTPS

DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").exists() else []
STATIC_ROOT = BASE_DIR / "staticfiles"

USE_TZ = True
TIME_ZONE = os.environ.get("TIME_ZONE", "America/Mexico_City")
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGGING = LOGGING