import os
import sys
import io
import json
import math
import logging
import datetime
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import django
from django.conf import settings
from django.core.wsgi import get_wsgi_application
from django.core.management import execute_from_command_line
from django.db import models, transaction
from django.utils import timezone
from django.utils.html import escape
from django.urls import path
from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse, HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import get_token
from django.conf.urls.static import static


BASE_DIR = Path(__file__).resolve().parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(BASE_DIR / "security_audit.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("astm_security")


def load_dotenv_strict(env_path: Path):
    """Carga variables desde .env sin sobrescribir variables reales del entorno/venv."""
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

DEBUG_MODE = os.environ.get("DEBUG", "False").lower() in ("true", "1", "yes")
USE_HTTPS = os.environ.get("USE_HTTPS", "False").lower() in ("true", "1", "yes")
ALLOWED_HOSTS_LIST = [
    h.strip() for h in os.environ["ALLOWED_HOSTS"].split(",") if h.strip() and h.strip() != "*"
]
if not ALLOWED_HOSTS_LIST:
    raise RuntimeError("[SEGURIDAD] ALLOWED_HOSTS no puede estar vacío ni usar '*' en modo blindado.")
class AutoCsrfAndHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response
if not settings.configured:
    settings.configure(
        DEBUG=DEBUG_MODE,
        SECRET_KEY=os.environ["SECRET_KEY"],
        ALLOWED_HOSTS=ALLOWED_HOSTS_LIST,
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.sessions",
            "django.contrib.staticfiles",
            "__main__",
        ],
        MIDDLEWARE=[
            "django.middleware.security.SecurityMiddleware",
            "whitenoise.middleware.WhiteNoiseMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        ],
        ROOT_URLCONF=__name__,
        LOGIN_URL="/login",
        LOGIN_REDIRECT_URL="/",
        LOGOUT_REDIRECT_URL="/login",
        TEMPLATES=[
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
        ],
        DATABASES={
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
        },

        SESSION_ENGINE="django.contrib.sessions.backends.db",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=USE_HTTPS,
        SESSION_COOKIE_AGE=28800,
        SESSION_EXPIRE_AT_BROWSER_CLOSE=True,

        CSRF_COOKIE_HTTPONLY=False,
        CSRF_COOKIE_SAMESITE="Strict",
        CSRF_COOKIE_SECURE=USE_HTTPS,
        CSRF_TRUSTED_ORIGINS=[
            f"{'https' if USE_HTTPS else 'http'}://{h}" for h in ALLOWED_HOSTS_LIST
        ],

        SECURE_CONTENT_TYPE_NOSNIFF=True,
        X_FRAME_OPTIONS="DENY",
        SECURE_REFERRER_POLICY="same-origin",
        SECURE_SSL_REDIRECT=USE_HTTPS,
        SECURE_HSTS_SECONDS=31536000 if USE_HTTPS else 0,
        SECURE_HSTS_INCLUDE_SUBDOMAINS=USE_HTTPS,

        DATA_UPLOAD_MAX_MEMORY_SIZE=2621440,
        FILE_UPLOAD_MAX_MEMORY_SIZE=2621440,

        STATIC_URL="/static/",
        STATICFILES_DIRS=[BASE_DIR / "static"] if (BASE_DIR / "static").exists() else [],
        STATIC_ROOT=BASE_DIR / "staticfiles",
        USE_TZ=True,
        TIME_ZONE=os.environ.get("TIME_ZONE", "America/Mexico_City"),
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
    )

django.setup()




class AutoCsrfAndHeadersMiddleware:
    CSRF_JS_SNIPPET = b"""
<script>
(function() {
  function getCookie(name) {
    let val = null;
    if (document.cookie && document.cookie !== '') {
      for (const c of document.cookie.split(';')) {
        const trimmed = c.trim();
        if (trimmed.startsWith(name + '=')) {
          val = decodeURIComponent(trimmed.substring(name.length + 1));
          break;
        }
      }
    }
    return val;
  }
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    init = init || {};
    const method = (init.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const headers = new Headers(init.headers || {});
      if (!headers.has('X-CSRFToken')) {
        headers.set('X-CSRFToken', getCookie('csrftoken') || '');
      }
      init.headers = headers;
      init.credentials = 'same-origin';
    }
    return origFetch(input, init);
  };
})();
window.addEventListener("pagehide", function(event) {
  if (!event.persisted && navigator.sendBeacon) {
    const formData = new FormData();
    const token = getCookie("csrftoken");
    if (token) formData.append("csrfmiddlewaretoken", token);
    navigator.sendBeacon("/logout", formData);
  }
});
</script>
</body>"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response["Pragma"] = "no-cache"

        content_type = response.get("Content-Type", "")
        if "text/html" in content_type and hasattr(response, "content") and b"</body>" in response.content:
            get_token(request)  # Asegura que la cookie csrftoken se envíe al navegador
            response.content = response.content.replace(b"</body>", self.CSRF_JS_SNIPPET, 1)
            if response.has_header("Content-Length"):
                response["Content-Length"] = str(len(response.content))
        return response



class MuestraEnsayoDB(models.Model):
    num_muestra = models.CharField(max_length=50, db_index=True)
    metodo = models.CharField(max_length=100)
    observaciones = models.TextField(null=True, blank=True)
    fecha_registro = models.DateTimeField(default=timezone.now)
    datos_resumen = models.TextField()
    dictamen_grubbs = models.TextField()

    class Meta:
        app_label = "__main__"
        db_table = "muestras_ensayos"
        ordering = ["-id"]


class MetodoNormativoDB(models.Model):
    nombre = models.CharField(max_length=100, unique=True, db_index=True)
    descripcion = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        app_label = "__main__"
        db_table = "metodos_normativos"
        ordering = ["nombre"]



TABLA_MANDEL = {
    3: {'h': 1.15, 'k': {2: 1.65, 3: 1.53, 4: 1.45, 5: 1.40, 6: 1.37, 7: 1.34, 8: 1.32, 9: 1.30, 10: 1.29}},
    4: {'h': 1.42, 'k': {2: 1.76, 3: 1.59, 4: 1.50, 5: 1.44, 6: 1.40, 7: 1.37, 8: 1.35, 9: 1.33, 10: 1.31}},
    5: {'h': 1.57, 'k': {2: 1.81, 3: 1.62, 4: 1.53, 5: 1.46, 6: 1.42, 7: 1.39, 8: 1.36, 9: 1.34, 10: 1.32}},
    6: {'h': 1.66, 'k': {2: 1.85, 3: 1.64, 4: 1.54, 5: 1.48, 6: 1.43, 7: 1.40, 8: 1.37, 9: 1.35, 10: 1.33}},
    7: {'h': 1.71, 'k': {2: 1.87, 3: 1.66, 4: 1.55, 5: 1.49, 6: 1.44, 7: 1.41, 8: 1.38, 9: 1.36, 10: 1.34}},
    8: {'h': 1.75, 'k': {2: 1.88, 3: 1.67, 4: 1.56, 5: 1.50, 6: 1.45, 7: 1.41, 8: 1.38, 9: 1.36, 10: 1.34}},
    9: {'h': 1.78, 'k': {2: 1.90, 3: 1.68, 4: 1.57, 5: 1.50, 6: 1.45, 7: 1.42, 8: 1.39, 9: 1.36, 10: 1.35}},
    10: {'h': 1.80, 'k': {2: 1.90, 3: 1.68, 4: 1.57, 5: 1.50, 6: 1.46, 7: 1.42, 8: 1.39, 9: 1.37, 10: 1.35}},
    11: {'h': 1.82, 'k': {2: 1.91, 3: 1.69, 4: 1.58, 5: 1.51, 6: 1.46, 7: 1.42, 8: 1.39, 9: 1.37, 10: 1.35}},
    12: {'h': 1.83, 'k': {2: 1.92, 3: 1.69, 4: 1.58, 5: 1.51, 6: 1.46, 7: 1.42, 8: 1.40, 9: 1.37, 10: 1.35}},
    13: {'h': 1.84, 'k': {2: 1.92, 3: 1.69, 4: 1.58, 5: 1.51, 6: 1.46, 7: 1.43, 8: 1.40, 9: 1.37, 10: 1.35}},
    14: {'h': 1.85, 'k': {2: 1.92, 3: 1.70, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.37, 10: 1.35}},
    15: {'h': 1.86, 'k': {2: 1.93, 3: 1.70, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    16: {'h': 1.86, 'k': {2: 1.93, 3: 1.70, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    17: {'h': 1.87, 'k': {2: 1.93, 3: 1.70, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    18: {'h': 1.88, 'k': {2: 1.93, 3: 1.71, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    19: {'h': 1.88, 'k': {2: 1.93, 3: 1.71, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    20: {'h': 1.89, 'k': {2: 1.94, 3: 1.71, 4: 1.59, 5: 1.52, 6: 1.47, 7: 1.43, 8: 1.40, 9: 1.38, 10: 1.36}},
    21: {'h': 1.89, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.52, 6: 1.47, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    22: {'h': 1.89, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.52, 6: 1.47, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    23: {'h': 1.90, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.47, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    24: {'h': 1.90, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    25: {'h': 1.90, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    26: {'h': 1.90, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    27: {'h': 1.91, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    28: {'h': 1.91, 'k': {2: 1.94, 3: 1.71, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    29: {'h': 1.91, 'k': {2: 1.94, 3: 1.72, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
    30: {'h': 1.91, 'k': {2: 1.94, 3: 1.72, 4: 1.60, 5: 1.53, 6: 1.48, 7: 1.44, 8: 1.41, 9: 1.38, 10: 1.36}},
}

TABLA_COCHRAN = {
    2: {3: {'1%': 0.995, '5%': 0.975}, 4: {'1%': 0.979, '5%': 0.939}, 5: {'1%': 0.959, '5%': 0.906}, 6: {'1%': 0.937, '5%': 0.877}},
    3: {2: {'1%': 0.993, '5%': 0.967}, 3: {'1%': 0.942, '5%': 0.871}, 4: {'1%': 0.883, '5%': 0.798}, 5: {'1%': 0.834, '5%': 0.746}, 6: {'1%': 0.793, '5%': 0.707}},
    4: {2: {'1%': 0.968, '5%': 0.906}, 3: {'1%': 0.864, '5%': 0.768}, 4: {'1%': 0.781, '5%': 0.684}, 5: {'1%': 0.721, '5%': 0.629}, 6: {'1%': 0.676, '5%': 0.590}},
    5: {2: {'1%': 0.928, '5%': 0.841}, 3: {'1%': 0.788, '5%': 0.684}, 4: {'1%': 0.696, '5%': 0.598}, 5: {'1%': 0.633, '5%': 0.544}, 6: {'1%': 0.588, '5%': 0.506}},
    6: {2: {'1%': 0.883, '5%': 0.781}, 3: {'1%': 0.722, '5%': 0.616}, 4: {'1%': 0.626, '5%': 0.532}, 5: {'1%': 0.564, '5%': 0.480}, 6: {'1%': 0.520, '5%': 0.445}},
    7: {2: {'1%': 0.838, '5%': 0.727}, 3: {'1%': 0.664, '5%': 0.561}, 4: {'1%': 0.568, '5%': 0.480}, 5: {'1%': 0.508, '5%': 0.431}, 6: {'1%': 0.466, '5%': 0.397}},
    8: {2: {'1%': 0.794, '5%': 0.680}, 3: {'1%': 0.615, '5%': 0.516}, 4: {'1%': 0.521, '5%': 0.438}, 5: {'1%': 0.463, '5%': 0.391}, 6: {'1%': 0.423, '5%': 0.360}},
    9: {2: {'1%': 0.754, '5%': 0.638}, 3: {'1%': 0.573, '5%': 0.478}, 4: {'1%': 0.481, '5%': 0.403}, 5: {'1%': 0.425, '5%': 0.358}, 6: {'1%': 0.387, '5%': 0.329}},
    10: {2: {'1%': 0.718, '5%': 0.602}, 3: {'1%': 0.536, '5%': 0.445}, 4: {'1%': 0.447, '5%': 0.373}, 5: {'1%': 0.393, '5%': 0.331}, 6: {'1%': 0.357, '5%': 0.303}},
    11: {2: {'1%': 0.684, '5%': 0.570}, 3: {'1%': 0.504, '5%': 0.417}, 4: {'1%': 0.418, '5%': 0.348}, 5: {'1%': 0.366, '5%': 0.308}, 6: {'1%': 0.332, '5%': 0.281}},
    12: {2: {'1%': 0.653, '5%': 0.541}, 3: {'1%': 0.475, '5%': 0.392}, 4: {'1%': 0.392, '5%': 0.326}, 5: {'1%': 0.343, '5%': 0.288}, 6: {'1%': 0.310, '5%': 0.262}},
    13: {2: {'1%': 0.624, '5%': 0.515}, 3: {'1%': 0.450, '5%': 0.371}, 4: {'1%': 0.369, '5%': 0.307}, 5: {'1%': 0.322, '5%': 0.271}, 6: {'1%': 0.291, '5%': 0.243}},
    14: {2: {'1%': 0.599, '5%': 0.492}, 3: {'1%': 0.427, '5%': 0.352}, 4: {'1%': 0.349, '5%': 0.291}, 5: {'1%': 0.304, '5%': 0.255}, 6: {'1%': 0.274, '5%': 0.232}},
    15: {2: {'1%': 0.575, '5%': 0.471}, 3: {'1%': 0.407, '5%': 0.335}, 4: {'1%': 0.332, '5%': 0.276}, 5: {'1%': 0.288, '5%': 0.242}, 6: {'1%': 0.259, '5%': 0.220}},
    16: {2: {'1%': 0.553, '5%': 0.452}, 3: {'1%': 0.388, '5%': 0.319}, 4: {'1%': 0.316, '5%': 0.262}, 5: {'1%': 0.274, '5%': 0.230}, 6: {'1%': 0.246, '5%': 0.208}},
    17: {2: {'1%': 0.532, '5%': 0.434}, 3: {'1%': 0.372, '5%': 0.305}, 4: {'1%': 0.301, '5%': 0.250}, 5: {'1%': 0.261, '5%': 0.219}, 6: {'1%': 0.234, '5%': 0.198}},
    18: {2: {'1%': 0.514, '5%': 0.418}, 3: {'1%': 0.356, '5%': 0.293}, 4: {'1%': 0.288, '5%': 0.240}, 5: {'1%': 0.249, '5%': 0.209}, 6: {'1%': 0.223, '5%': 0.189}},
    19: {2: {'1%': 0.496, '5%': 0.403}, 3: {'1%': 0.343, '5%': 0.281}, 4: {'1%': 0.276, '5%': 0.230}, 5: {'1%': 0.238, '5%': 0.200}, 6: {'1%': 0.214, '5%': 0.181}},
    20: {2: {'1%': 0.480, '5%': 0.389}, 3: {'1%': 0.330, '5%': 0.270}, 4: {'1%': 0.265, '5%': 0.220}, 5: {'1%': 0.229, '5%': 0.192}, 6: {'1%': 0.205, '5%': 0.174}},
    21: {2: {'1%': 0.465, '5%': 0.377}, 3: {'1%': 0.318, '5%': 0.261}, 4: {'1%': 0.255, '5%': 0.212}, 5: {'1%': 0.220, '5%': 0.185}, 6: {'1%': 0.197, '5%': 0.167}},
    22: {2: {'1%': 0.450, '5%': 0.365}, 3: {'1%': 0.307, '5%': 0.252}, 4: {'1%': 0.246, '5%': 0.204}, 5: {'1%': 0.212, '5%': 0.178}, 6: {'1%': 0.189, '5%': 0.160}},
    23: {2: {'1%': 0.437, '5%': 0.354}, 3: {'1%': 0.297, '5%': 0.243}, 4: {'1%': 0.238, '5%': 0.197}, 5: {'1%': 0.204, '5%': 0.172}, 6: {'1%': 0.182, '5%': 0.155}},
    24: {2: {'1%': 0.425, '5%': 0.343}, 3: {'1%': 0.287, '5%': 0.235}, 4: {'1%': 0.230, '5%': 0.191}, 5: {'1%': 0.197, '5%': 0.166}, 6: {'1%': 0.176, '5%': 0.149}},
    25: {2: {'1%': 0.413, '5%': 0.334}, 3: {'1%': 0.278, '5%': 0.228}, 4: {'1%': 0.222, '5%': 0.185}, 5: {'1%': 0.190, '5%': 0.160}, 6: {'1%': 0.170, '5%': 0.144}},
    26: {2: {'1%': 0.402, '5%': 0.325}, 3: {'1%': 0.270, '5%': 0.221}, 4: {'1%': 0.215, '5%': 0.179}, 5: {'1%': 0.184, '5%': 0.155}, 6: {'1%': 0.164, '5%': 0.140}},
    27: {2: {'1%': 0.391, '5%': 0.316}, 3: {'1%': 0.262, '5%': 0.215}, 4: {'1%': 0.209, '5%': 0.173}, 5: {'1%': 0.179, '5%': 0.150}, 6: {'1%': 0.159, '5%': 0.135}},
    28: {2: {'1%': 0.382, '5%': 0.308}, 3: {'1%': 0.255, '5%': 0.209}, 4: {'1%': 0.202, '5%': 0.168}, 5: {'1%': 0.173, '5%': 0.146}, 6: {'1%': 0.154, '5%': 0.131}},
    29: {2: {'1%': 0.372, '5%': 0.300}, 3: {'1%': 0.248, '5%': 0.203}, 4: {'1%': 0.196, '5%': 0.164}, 5: {'1%': 0.168, '5%': 0.142}, 6: {'1%': 0.150, '5%': 0.127}},
    30: {2: {'1%': 0.363, '5%': 0.293}, 3: {'1%': 0.241, '5%': 0.198}, 4: {'1%': 0.191, '5%': 0.159}, 5: {'1%': 0.164, '5%': 0.138}, 6: {'1%': 0.145, '5%': 0.124}},
    31: {2: {'1%': 0.355, '5%': 0.286}, 3: {'1%': 0.235, '5%': 0.193}, 4: {'1%': 0.186, '5%': 0.155}, 5: {'1%': 0.159, '5%': 0.134}, 6: {'1%': 0.141, '5%': 0.120}},
    32: {2: {'1%': 0.347, '5%': 0.280}, 3: {'1%': 0.229, '5%': 0.188}, 4: {'1%': 0.181, '5%': 0.151}, 5: {'1%': 0.155, '5%': 0.131}, 6: {'1%': 0.138, '5%': 0.117}},
    33: {2: {'1%': 0.339, '5%': 0.273}, 3: {'1%': 0.224, '5%': 0.184}, 4: {'1%': 0.177, '5%': 0.147}, 5: {'1%': 0.151, '5%': 0.127}, 6: {'1%': 0.134, '5%': 0.114}},
    34: {2: {'1%': 0.332, '5%': 0.267}, 3: {'1%': 0.218, '5%': 0.179}, 4: {'1%': 0.172, '5%': 0.144}, 5: {'1%': 0.147, '5%': 0.124}, 6: {'1%': 0.131, '5%': 0.111}}
}

TABLA_GRUBBS = {
    3: {2: {'1%': 1.155, '5%': 1.155}},
    4: {2: {'1%': 1.496, '5%': 1.481}, 3: {'1%': 0.0000, '5%': 0.0002}},
    5: {2: {'1%': 1.764, '5%': 1.715}, 3: {'1%': 0.0018, '5%': 0.0090}},
    6: {2: {'1%': 1.973, '5%': 1.887}, 3: {'1%': 0.0116, '5%': 0.0349}},
    7: {2: {'1%': 2.139, '5%': 2.020}, 3: {'1%': 0.0308, '5%': 0.0708}},
    8: {2: {'1%': 2.274, '5%': 2.216}, 3: {'1%': 0.0563, '5%': 0.1101}},
    9: {2: {'1%': 2.387, '5%': 2.215}, 3: {'1%': 0.0851, '5%': 0.1492}},
    10: {2: {'1%': 2.482, '5%': 2.290}, 3: {'1%': 0.1150, '5%': 0.1864}},
    11: {2: {'1%': 2.564, '5%': 2.355}, 3: {'1%': 0.1448, '5%': 0.2213}},
    12: {2: {'1%': 2.636, '5%': 2.412}, 3: {'1%': 0.1738, '5%': 0.2537}},
    13: {2: {'1%': 2.699, '5%': 2.462}, 3: {'1%': 0.2016, '5%': 0.2836}},
    14: {2: {'1%': 2.755, '5%': 2.507}, 3: {'1%': 0.2280, '5%': 0.3112}},
    15: {2: {'1%': 2.806, '5%': 2.549}, 3: {'1%': 0.2530, '5%': 0.3367}},
    16: {2: {'1%': 2.852, '5%': 2.585}, 3: {'1%': 0.2767, '5%': 0.3603}},
    17: {2: {'1%': 2.894, '5%': 2.620}, 3: {'1%': 0.2990, '5%': 0.3822}},
    18: {2: {'1%': 2.932, '5%': 2.651}, 3: {'1%': 0.3200, '5%': 0.4025}},
    19: {2: {'1%': 2.968, '5%': 2.681}, 3: {'1%': 0.3398, '5%': 0.4214}},
    20: {2: {'1%': 3.001, '5%': 2.709}, 3: {'1%': 0.3585, '5%': 0.4391}},
    21: {2: {'1%': 3.031, '5%': 0.267}, 3: {'1%': 0.3761, '5%': 0.4556}},
    22: {2: {'1%': 3.060, '5%': 0.267}, 3: {'1%': 0.3927, '5%': 0.4711}},
    23: {2: {'1%': 3.087, '5%': 0.267}, 3: {'1%': 0.4085, '5%': 0.4857}},
    24: {2: {'1%': 3.112, '5%': 0.267}, 3: {'1%': 0.4234, '5%': 0.4994}},
    25: {2: {'1%': 3.135, '5%': 0.267}, 3: {'1%': 0.4376, '5%': 0.5123}},
    26: {2: {'1%': 3.157, '5%': 0.267}, 3: {'1%': 0.4510, '5%': 0.5245}},
    27: {2: {'1%': 3.178, '5%': 0.267}, 3: {'1%': 0.4638, '5%': 0.5536}},
    28: {2: {'1%': 3.199, '5%': 0.267}, 3: {'1%': 0.4759, '5%': 0.5470}},
    29: {2: {'1%': 3.218, '5%': 0.267}, 3: {'1%': 0.4875, '5%': 0.5574}},
    30: {2: {'1%': 3.236, '5%': 0.267}, 3: {'1%': 0.4985, '5%': 0.5672}},
    31: {2: {'1%': 3.253, '5%': 0.267}, 3: {'1%': 0.5091, '5%': 0.5766}},
    32: {2: {'1%': 3.270, '5%': 0.267}, 3: {'1%': 0.5192, '5%': 0.5856}},
    33: {2: {'1%': 3.286, '5%': 0.267}, 3: {'1%': 0.5288, '5%': 0.5941}},
    34: {2: {'1%': 3.301, '5%': 0.267}, 3: {'1%': 0.5381, '5%': 0.6023}},
    35: {2: {'1%': 3.316, '5%': 0.267}, 3: {'1%': 0.5469, '5%': 0.6101}},
    36: {2: {'1%': 3.330, '5%': 0.267}, 3: {'1%': 0.5554, '5%': 0.6175}},
    37: {2: {'1%': 3.343, '5%': 0.267}, 3: {'1%': 0.5636, '5%': 0.6247}},
    38: {2: {'1%': 3.356, '5%': 0.267}, 3: {'1%': 0.5724, '5%': 0.6316}},
    39: {2: {'1%': 3.369, '5%': 0.267}, 3: {'1%': 0.5789, '5%': 0.6382}},
    40: {2: {'1%': 3.381, '5%': 0.267}, 3: {'1%': 0.5862, '5%': 0.6445}}
}



def parse_json_body(request) -> dict:
    content_type = request.headers.get("Content-Type", "")
    if "application/json" not in content_type.lower():
        raise ValueError("Content-Type inválido. Se requiere application/json.")
    try:
        data = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("El cuerpo JSON está malformado.")
    if not isinstance(data, dict):
        raise ValueError("El payload JSON debe ser un objeto válido.")
    return data


def validar_participantes(participantes_raw) -> list:
    if not isinstance(participantes_raw, list) or len(participantes_raw) == 0:
        raise ValueError("Debe enviar una lista válida de participantes.")
    if len(participantes_raw) > 100:
        raise ValueError("Se excedió el límite máximo de 100 laboratorios por evaluación.")

    limpios = []
    for i, p in enumerate(participantes_raw, start=1):
        if not isinstance(p, dict):
            raise ValueError(f"Formato inválido en participante #{i}.")
        raw_vals = p.get("valores", [])
        if not isinstance(raw_vals, list) or len(raw_vals) > 50:
            raise ValueError(f"Valores inválidos o excesivos en participante #{i}.")

        valores_num = []
        for v in raw_vals:
            if v is not None and str(v).strip() != "":
                try:
                    num = float(str(v).replace(",", ".").strip())
                except (ValueError, TypeError):
                    raise ValueError(f"Valor no numérico detectado en participante #{i}.")
                if not math.isfinite(num):
                    raise ValueError(f"Valor infinito o NaN no permitido en participante #{i}.")
                valores_num.append(num)

        nombre_raw = str(p.get("participante_nombre") or p.get("nombre") or f"Lab {i}").strip()[:100]
        limpios.append({
            "participante_num": int(p.get("participante_num") or p.get("num") or i),
            "participante_nombre": nombre_raw if nombre_raw else f"Lab {i}",
            "valores": valores_num,
        })
    return limpios


def sanitizar_texto(texto, max_len=100, default="") -> str:
    if texto is None:
        return default
    limpio = str(texto).strip()[:max_len]
    return limpio if limpio else default


# ==============================================================================
# 6. LÓGICA DE CÁLCULOS ESTADÍSTICOS (ISO 5725-2)
# ==============================================================================
def calcular_estadisticos_iso(participantes_raw: list) -> dict:
    if not participantes_raw:
        raise ValueError("No se recibieron participantes.")

    puntos_grafica = []
    resumen = []
    promedios_lista = []

    for i, p in enumerate(participantes_raw, start=1):
        num_p = p.get("participante_num") or p.get("num")
        num_real = int(num_p) if (num_p is not None and int(num_p) > 0) else i

        nom_p = p.get("participante_nombre") or p.get("nombre")
        nombre = str(nom_p).strip() if (nom_p and str(nom_p).strip()) else f"Lab {num_real}"

        valores = [float(v) for v in p.get("valores", []) if v is not None and str(v).strip() != ""]

        n_i = len(valores)
        promedio_i = sum(valores) / n_i if n_i > 0 else 0.0
        producto_i = n_i * promedio_i

        varianza_i = 0.0
        desviacion_i = 0.0
        if n_i > 1:
            varianza_i = sum((x - promedio_i) ** 2 for x in valores) / (n_i - 1)
            desviacion_i = math.sqrt(varianza_i)

        promedios_lista.append(promedio_i)
        puntos_grafica.append({"x": f"{nombre}", "y": promedio_i})

        resumen.append({
            "num": num_real,
            "nombre": nombre,
            "registros": n_i,
            "valores": valores,
            "promedioNum": promedio_i,
            "promedio": f"{promedio_i:.2f}" if n_i > 0 else "-",
            "producto": f"{producto_i:.2f}" if n_i > 0 else "-",
            "desviacionNum": desviacion_i,
            "varianzaNum": varianza_i,
            "desviacion": f"{desviacion_i:.4f}" if n_i > 1 else ("0.0000" if n_i == 1 else "-"),
        })

    todos_los_valores = [val for p in resumen for val in p["valores"]]
    total_mediciones = len(todos_los_valores)
    todos_los_prom = [p["promedioNum"] for p in resumen]
    part_validos = [p for p in resumen if p["registros"] > 0]
    k = len(part_validos)

    gran_promedio = sum(p["promedioNum"] for p in part_validos) / k if k > 0 else 0.0
    suma_productos_tabla2 = sum(p["registros"] * p["promedioNum"] for p in part_validos)
    resultado_formula = (sum((p["promedioNum"] - gran_promedio) ** 2 for p in part_validos) / (k - 1)) if k > 1 else 0.0

    suma_registros = sum(p["registros"] for p in resumen)
    suma_cuadrados = sum(p["registros"] ** 2 for p in resumen)

    nj = ((suma_registros - (suma_cuadrados / suma_registros)) / (k - 1)) if (k > 1 and suma_registros > 0) else 0.0
    mj = (suma_productos_tabla2 / suma_registros) if suma_registros > 0 else 0.0
    desviacion_global = math.sqrt(resultado_formula) if resultado_formula > 0 else 0.0

    varianzas_validas = [p["varianzaNum"] for p in resumen if p["registros"] > 1]
    suma_varianzas = sum(varianzas_validas)
    raiz_suma_varianzas = math.sqrt(suma_varianzas) if suma_varianzas > 0 else 0.0
    var_max = max(varianzas_validas) if varianzas_validas else 0.0

    cochran_c = (var_max / suma_varianzas) if suma_varianzas > 0 else 0.0

    desviaciones_validas = [p["desviacionNum"] for p in resumen if p["registros"] > 1]
    promedio_desviaciones = (sum(desviaciones_validas) / len(desviaciones_validas)) if desviaciones_validas else 0.0

    tabla_k = []
    for p in resumen:
        k_val_str = "0.000" if raiz_suma_varianzas == 0 else "-"
        if p["registros"] > 1 and raiz_suma_varianzas > 0:
            k_val = (p["desviacionNum"] * math.sqrt(p["registros"])) / raiz_suma_varianzas
            k_val_str = f"{k_val:.3f}"
        tabla_k.append({"num": p["num"], "k_val": k_val_str})

    diferencias = []
    suma_ponderada_total = 0.0

    for p in part_validos:
        dif = p["promedioNum"] - gran_promedio
        ponderado = p["registros"] * (dif ** 2)
        suma_ponderada_total += ponderado

        diferencias.append({
            "num": p["num"],
            "nombre": p["nombre"],
            "registros": p["registros"],
            "promedio": p["promedio"],
            "diferencia": f"{dif:+.4f}",
            "diferenciaNum": dif,
            "ponderado": f"{ponderado:.6f}",
        })

    desviacion_diferencias = 0.0
    if len(diferencias) > 1:
        difs_num = [d["diferenciaNum"] for d in diferencias]
        prom_dif = sum(difs_num) / len(difs_num)
        var_dif = sum((d - prom_dif) ** 2 for d in difs_num) / (len(difs_num) - 1)
        desviacion_diferencias = math.sqrt(var_dif)

    s2dj = (suma_ponderada_total / (k - 1)) if k > 1 else 0.0
    denominador = sum(d["registros"] - 1 for d in resumen)
    numerador = sum((d["desviacionNum"] ** 2) * (d["registros"] - 1) for d in resumen)

    sr2j = (numerador / denominador) if denominador > 0 else 0.0
    s2lj = ((s2dj - sr2j) / nj) if (nj > 0 and s2dj >= sr2j) else 0.0
    sr_sl = (sr2j / s2lj) if s2lj > 0 else 0.0
    raiz_sr_sl = math.sqrt(sr_sl) if sr_sl > 0 else 0.0

    raiz_srj = math.sqrt(max(0, ((s2dj - sr2j) / nj) + sr2j)) if nj > 0 else 0.0
    srj2 = raiz_srj ** 2
    porc_R = (raiz_srj / mj) * 100 if mj > 0 else 0.0
    sum_s2rj = sr2j + s2lj
    raizsr2j = round(math.sqrt(sr2j), 3)

    diferencias2 = []
    for p in part_validos:
        dif = p["promedioNum"] - gran_promedio
        ponderado = p["registros"] * (dif ** 2)
        hij = (dif / desviacion_diferencias) if desviacion_diferencias > 0 else 0.0

        diferencias2.append({
            "num": p["num"],
            "nombre": p["nombre"],
            "registros": p["registros"],
            "promedio": p["promedio"],
            "diferencia": f"{dif:+.4f}",
            "diferenciaNum": dif,
            "ponderado": f"{ponderado:.6f}",
            "hij": round(hij, 4),
        })

    p_labs = k
    todas_n = [p["registros"] for p in part_validos if p["registros"] > 0]
    n_replicas = int(round(sum(todas_n) / len(todas_n))) if todas_n else 5

    h_critico = 1.0
    k_critico = 1.0

    if p_labs in TABLA_MANDEL:
        h_critico = TABLA_MANDEL[p_labs].get("h", 1.0)
        if n_replicas in TABLA_MANDEL[p_labs].get("k", {}):
            k_critico = TABLA_MANDEL[p_labs]["k"][n_replicas]

    for item in diferencias2:
        es_valido = abs(item["hij"]) <= h_critico
        item["h_critico"] = h_critico
        item["cumple"] = "CUMPLE" if es_valido else "NO CUMPLE"

    for item in tabla_k:
        try:
            val_k = float(item["k_val"])
            es_valido = val_k <= k_critico
            item["h_critico"] = k_critico
            item["cumple"] = "CUMPLE" if es_valido else "NO CUMPLE"
        except ValueError:
            item["h_critico"] = k_critico
            item["cumple"] = "-"

    cochran_5 = None
    cochran_1 = None

    if p_labs in TABLA_COCHRAN and n_replicas in TABLA_COCHRAN[p_labs]:
        cochran_5 = TABLA_COCHRAN[p_labs][n_replicas].get("5%")
        cochran_1 = TABLA_COCHRAN[p_labs][n_replicas].get("1%")

    if cochran_5 is not None:
        criterio_cochran = f"C1 < {cochran_5:.3f}"
        es_consistente = cochran_c < cochran_5
        resultado_cochran = "CONSISTENTE" if es_consistente else "NO CONSISTENTE"
    else:
        criterio_cochran = "-"
        resultado_cochran = "Sin referencia"

    promedios = [p["promedioNum"] for p in part_validos]
    desv_prom = float(np.std(promedios, ddof=1)) if len(promedios) > 1 else 0.0
    s2o = sum((p["promedioNum"] - gran_promedio) ** 2 for p in part_validos)
    promedios_ordenados = sorted(promedios)
    p_len = len(promedios_ordenados)

    promedios_valh = promedios_ordenados[:-2]
    xp_1p = (sum(promedios_valh) / (p_len - 2)) if p_len > 2 else 0.0
    s2p = sum((x - xp_1p) ** 2 for x in promedios_valh) if p_len > 2 else 0.0
    G = (s2p / s2o) if s2o > 0 else 0.0

    Gp = ((max(todos_los_prom) - gran_promedio) / desv_prom) if (desv_prom > 0 and todos_los_prom) else 0.0
    Gpmin = ((gran_promedio - min(todos_los_prom)) / desv_prom) if (desv_prom > 0 and todos_los_prom) else 0.0

    promedios_i32 = promedios_ordenados[2:]
    x1_2 = (sum(promedios_i32) / (p_len - 2)) if p_len > 2 else 0.0
    s12_2 = sum((x - x1_2) ** 2 for x in promedios_i32) if p_len > 2 else 0.0
    G2 = (s12_2 / s2o) if s2o > 0 else 0.0

    resumen_ordenado = sorted(resumen, key=lambda x: x["promedioNum"])

    crit_1_val_5 = crit_1_val_1 = crit_2_val_5 = crit_2_val_1 = None

    if p_labs in TABLA_GRUBBS:
        if 2 in TABLA_GRUBBS[p_labs]:
            crit_1_val_5 = TABLA_GRUBBS[p_labs][2].get("5%")
            crit_1_val_1 = TABLA_GRUBBS[p_labs][2].get("1%")
        if 3 in TABLA_GRUBBS[p_labs]:
            crit_2_val_5 = TABLA_GRUBBS[p_labs][3].get("5%")
            crit_2_val_1 = TABLA_GRUBBS[p_labs][3].get("1%")

    def evaluar_un_valor(g_calc, c5, c1):
        if c5 is None or c1 is None:
            return "Sin referencia", "N/A"
        if g_calc > c1:
            return "Atípico Severo (1%)", "NO CONSISTENTE"
        elif g_calc > c5:
            return "Atípico Sospechoso (5%)", "ADVERTENCIA"
        return "CONSISTENTE", "CONSISTENTE"

    def evaluar_dos_valores(g_calc, c5, c1):
        if c5 is None or c1 is None:
            return "Sin referencia", "N/A"
        if g_calc < c1:
            return "Par Atípico Severo (1%)", "NO CONSISTENTE"
        elif g_calc < c5:
            return "Par Atípico Sospechoso (5%)", "ADVERTENCIA"
        return "CONSISTENTE", "CONSISTENTE"

    evaluacion_grubbs = {
        "p_laboratorios": p_labs,
        "criticos": {
            "un_valor": {"5%": crit_1_val_5, "1%": crit_1_val_1},
            "dos_valores": {"5%": crit_2_val_5, "1%": crit_2_val_1},
        },
        "un_maximo": {
            "valor_g": round(Gp, 4),
            "dictamen": evaluar_un_valor(Gp, crit_1_val_5, crit_1_val_1)[0],
            "estado": evaluar_un_valor(Gp, crit_1_val_5, crit_1_val_1)[1],
        },
        "un_minimo": {
            "valor_g": round(Gpmin, 4),
            "dictamen": evaluar_un_valor(Gpmin, crit_1_val_5, crit_1_val_1)[0],
            "estado": evaluar_un_valor(Gpmin, crit_1_val_5, crit_1_val_1)[1],
        },
        "dos_maximos": {
            "valor_g": round(G, 4),
            "dictamen": evaluar_dos_valores(G, crit_2_val_5, crit_2_val_1)[0],
            "estado": evaluar_dos_valores(G, crit_2_val_5, crit_2_val_1)[1],
        },
        "dos_minimos": {
            "valor_g": round(G2, 4),
            "dictamen": evaluar_dos_valores(G2, crit_2_val_5, crit_2_val_1)[0],
            "estado": evaluar_dos_valores(G2, crit_2_val_5, crit_2_val_1)[1],
        },
    }

    todos_h = [p["hij"] for p in diferencias2]
    todos_k_num = []
    for p in tabla_k:
        try:
            todos_k_num.append(float(p["k_val"]))
        except ValueError:
            todos_k_num.append(0.0)

    maxh = max(todos_h) if todos_h else 0.0
    maxk = max(todos_k_num) if todos_k_num else 0.0

    return {
        "mensaje": "Cálculos realizados correctamente",
        "puntos_grafica": puntos_grafica,
        "resumen": resumen,
        "tabla_k": tabla_k,
        "diferencias": diferencias,
        "diferencias2": diferencias2,
        "h_critico": h_critico,
        "k_critico": k_critico,
        "resumen_grubbs": resumen_ordenado,
        "evaluacion_grubbs": evaluacion_grubbs,
        "suma_productos_tabla2": f"{suma_productos_tabla2:.2f}",
        "varianza": f"{resultado_formula:.6f}",
        "gran_promedio": f"{gran_promedio:.2f}",
        "minimo": f"{min(todos_los_prom):.2f}" if todos_los_prom else "-",
        "maximo": f"{max(todos_los_prom):.2f}" if todos_los_prom else "-",
        "desviacion_estandar": f"{desviacion_global:.3f}" if total_mediciones > 1 else "-",
        "formula1": f"{nj:.2f}" if total_mediciones > 1 else "-",
        "suma_mediciones": f"{sum(todos_los_valores):.2f}" if todos_los_valores else "-",
        "numero_de_registros": total_mediciones,
        "suma_varianzas": f"{suma_varianzas:.4f}" if suma_varianzas > 0 else "-",
        "raiz_suma_varianzas": f"{raiz_suma_varianzas:.4f}" if suma_varianzas > 0 else "-",
        "promedio_desviaciones": f"{promedio_desviaciones:.4f}" if desviaciones_validas else "-",
        "cochran": f"{cochran_c:.4f}" if cochran_c > 0 else "-",
        "desviacion_diferencias": f"{desviacion_diferencias:.4f}" if len(diferencias) > 1 else "-",
        "suma_ponderada": f"{suma_ponderada_total:.6f}" if part_validos else "-",
        "s2dj": f"{s2dj:.6f}" if k > 1 else "-",
        "mj": f"{mj:.2f}" if k > 1 else "-",
        "sr2j": f"{sr2j:.7f}" if k > 1 else "-",
        "raizsr2j": f"{raizsr2j:.3f}" if k > 1 else "-",
        "s2lj": f"{s2lj:.7f}" if k > 1 else "-",
        "sr_sl": f"{sr_sl:.7f}" if k > 1 else "-",
        "raiz_sr_sl": f"{raiz_sr_sl:.7f}" if k > 1 else "-",
        "raiz_srj": f"{raiz_srj:.7f}" if k > 1 else "-",
        "srj2": f"{srj2:.7f}" if k > 1 else "-",
        "porc_R": f"{porc_R:.7f}" if k > 1 else "-",
        "suma_s2rj": f"{sum_s2rj:.7f}" if k > 1 else "-",
        "cochran_critico_5": f"{cochran_5:.3f}" if cochran_5 else "-",
        "cochran_critico_1": f"{cochran_1:.3f}" if cochran_1 else "-",
        "criterio_cochran": criterio_cochran,
        "resultado_cochran": resultado_cochran,
        "criterioh": f"h < {h_critico:.3f}",
        "criteriok": f"k < {k_critico:.3f}",
        "desv_prom": f"{desv_prom:.7f}",
        "s2o": f"{s2o:.7f}",
        "xp_1p": f"{xp_1p:.7f}",
        "s2p": f"{s2p:.7f}",
        "G": f"{G:.5f}",
        "Gp": f"{Gp:.5f}",
        "Gpmin": f"{Gpmin:.5f}",
        "x1_2": f"{x1_2:.5f}",
        "s12_2": f"{s12_2:.5f}",
        "G2": f"{G2:.5f}",
        "maxh": maxh,
        "maxk": maxk,
    }


#
def crear_logo_lims():
    ruta_logo = BASE_DIR / "static" / "logo.png"
    if ruta_logo.exists():
        logo = RLImage(str(ruta_logo), width=120, height=40)
        logo.hAlign = "LEFT"
        return logo
    styles = getSampleStyleSheet()
    return Paragraph("<b>RALOY LAB</b><br/><font size=8 color='#64748b'>ISO 5725-2</font>", styles["Normal"])


def fig_to_rl_image(fig, width=520, height=130):
    img_buf = io.BytesIO()
    fig.savefig(img_buf, format="png", dpi=200, bbox_inches="tight")
    plt.close(fig)
    img_buf.seek(0)
    return RLImage(img_buf, width=width, height=height)



@require_http_methods(["GET", "POST"])
def login_view(request):
    next_raw = request.POST.get("next") or request.GET.get("next") or "/"
    if not next_raw.startswith("/") or next_raw.startswith("//"):
        next_raw = "/"

    if request.user.is_authenticated and request.method == "GET":
        return redirect(next_raw)

    error_msg = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()[:150]
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_active:
            login(request, user)
            request.session.set_expiry(0)
            logger.info("Inicio de sesión exitoso: usuario='%s'", username)
            return redirect(next_raw)
        logger.warning("Intento fallido de login: usuario='%s'", username)
        error_msg = "Usuario o contraseña incorrectos."

    get_token(request)
    return render(request, "login.html", {
        "error_msg": error_msg,
        "next_url": next_raw,
    })


@require_http_methods(["POST", "GET"])
def logout_view(request):
    if request.user.is_authenticated:
        logger.info("Cierre de sesión: usuario='%s'", request.user.username)
    logout(request)
    return redirect("/login")



@login_required
def read_index(request):
    return render(request, "index.html")


@login_required
def read_registros(request):
    return render(request, "registros.html")


@login_required
@require_http_methods(["GET"])
def obtener_registros(request):
    ensayos = (
        MuestraEnsayoDB.objects
        .only("id", "fecha_registro", "num_muestra", "metodo", "datos_resumen", "dictamen_grubbs")
        .order_by("-id")
        .iterator(chunk_size=200)
    )
    resultado = []

    for e in ensayos:
        num_labs = 0
        total_celdas = 0
        gran_prom = 0.0

        if e.datos_resumen:
            try:
                datos = json.loads(e.datos_resumen)
                if isinstance(datos, list):
                    num_labs = len(datos)
                    todos_vals = [
                        float(v)
                        for lab in datos if isinstance(lab, dict)
                        for v in (lab.get("valores") or lab.get("replicas") or lab.get("datos") or [])
                        if v is not None and str(v).strip() != ""
                    ]
                    total_celdas = len(todos_vals)
                    if total_celdas > 0:
                        gran_prom = sum(todos_vals) / total_celdas
            except Exception:
                logger.warning("Error parseando datos_resumen en registro id=%s", e.id)

        dictamen_txt = "CONFORME"
        if e.dictamen_grubbs:
            try:
                json_str_upper = e.dictamen_grubbs.upper()
                dg = json.loads(e.dictamen_grubbs)

                if total_celdas == 0 and isinstance(dg, dict):
                    total_celdas = int(dg.get("total_celdas", 0) or dg.get("num_celdas", 0))

                if isinstance(dg, dict) and dg.get("dictamen_global"):
                    dictamen_txt = str(dg["dictamen_global"]).upper()
                elif any(x in json_str_upper for x in ("NO CONFORME", "RECHAZADO", "OUTLIER")):
                    dictamen_txt = "NO CONFORME"
                elif any(x in json_str_upper for x in ("ADVERTENCIA", "STRAGGLER", "DUDOSO")):
                    dictamen_txt = "ADVERTENCIA"
            except Exception:
                logger.warning("Error parseando dictamen_grubbs en registro id=%s", e.id)

        resultado.append({
            "id": e.id,
            "fecha": e.fecha_registro.strftime("%Y-%m-%d") if e.fecha_registro else "-",
            "muestra": e.num_muestra,
            "metodo": e.metodo,
            "labs": num_labs,
            "total_celdas": total_celdas,
            "promedio": f"{gran_prom:.3f}",
            "dictamen": dictamen_txt,
        })

    return JsonResponse(resultado, safe=False)


@login_required
@require_http_methods(["POST"])
def guardar(request):
    try:
        payload = parse_json_body(request)
        participantes = validar_participantes(payload.get("participantes"))
        res = calcular_estadisticos_iso(participantes)
        return JsonResponse(res)
    except ValueError as e:
        return JsonResponse({"detail": str(e)}, status=400)
    except Exception:
        logger.exception("Error interno en /guardar por usuario='%s'", request.user.username)
        return JsonResponse({"detail": "Error interno al procesar los cálculos."}, status=500)


@login_required
@require_http_methods(["POST"])
def guardar_avanzado(request):
    try:
        payload = parse_json_body(request)
        participantes_list = validar_participantes(payload.get("participantes"))
        res_grubbs = calcular_estadisticos_iso(participantes_list)

        num_muestra = sanitizar_texto(payload.get("num_muestra") or payload.get("muestra"), max_len=50, default="S/N")
        metodo = sanitizar_texto(payload.get("metodo"), max_len=100, default="ASTM D1121")
        observaciones = sanitizar_texto(payload.get("observaciones"), max_len=2000, default="")

        num_participantes = len(participantes_list)
        total_celdas = sum(len(p.get("valores", [])) for p in participantes_list)

        texto_eval_raw = str(res_grubbs).upper()
        cochran_ok = res_grubbs.get("resultado_cochran") == "CONSISTENTE"

        eg = res_grubbs.get("evaluacion_grubbs", {})
        grubbs_no_conforme = any(isinstance(v, dict) and v.get("estado") == "NO CONFORME" for v in eg.values())
        grubbs_advertencia = any(isinstance(v, dict) and v.get("estado") == "ADVERTENCIA" for v in eg.values())

        if "NO CONFORME" in texto_eval_raw or "RECHAZADO" in texto_eval_raw or not cochran_ok or grubbs_no_conforme:
            dictamen_global = "NO CONFORME"
        elif "ADVERTENCIA" in texto_eval_raw or "STRAGGLER" in texto_eval_raw or grubbs_advertencia:
            dictamen_global = "ADVERTENCIA"
        else:
            dictamen_global = "CONFORME"

        evaluacion_completa = {
            "dictamen_global": dictamen_global,
            "num_muestra": num_muestra,
            "metodo": metodo,
            "total_celdas": total_celdas,
            "num_participantes": num_participantes,
            "grubbs": res_grubbs,
            "mandel": {"estado": dictamen_global},
            "cochran": {"estado": "CONSISTENTE" if cochran_ok else "NO CONSISTENTE"},
        }

        with transaction.atomic():
            muestra_existente = MuestraEnsayoDB.objects.filter(num_muestra=num_muestra).first()
            if muestra_existente:
                muestra_existente.metodo = metodo
                muestra_existente.datos_resumen = json.dumps(participantes_list)
                muestra_existente.observaciones = observaciones
                muestra_existente.dictamen_grubbs = json.dumps(evaluacion_completa)
                muestra_existente.save()
            else:
                MuestraEnsayoDB.objects.create(
                    num_muestra=num_muestra,
                    metodo=metodo,
                    observaciones=observaciones,
                    datos_resumen=json.dumps(participantes_list),
                    dictamen_grubbs=json.dumps(evaluacion_completa),
                )

        logger.info("Muestra guardada: muestra='%s' usuario='%s'", num_muestra, request.user.username)
        return JsonResponse({
            "status": "ok",
            "num_muestra": num_muestra,
            "metodo": metodo,
            "total_celdas": total_celdas,
            "dictamen_global": dictamen_global,
            "evaluacion": evaluacion_completa,
        })

    except ValueError as e:
        return JsonResponse({"detail": str(e)}, status=400)
    except Exception:
        logger.exception("Error interno al guardar muestra por usuario='%s'", request.user.username)
        return JsonResponse({"detail": "Error interno al guardar el registro."}, status=500)


@login_required
@require_http_methods(["POST"])
def exportar_excel(request):
    try:
        payload = parse_json_body(request)
        num_muestra = sanitizar_texto(payload.get("num_muestra"), max_len=50, default="S_N").replace("/", "_")
        metodo = sanitizar_texto(payload.get("metodo"), max_len=100, default="ASTM D1121")
        participantes = validar_participantes(payload.get("participantes"))
        res = calcular_estadisticos_iso(participantes)

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df_global = pd.DataFrame([
                {"Parámetro / Métrica Metrológica": "Número de Muestra", "Valor": num_muestra},
                {"Parámetro / Métrica Metrológica": "Método Normativo", "Valor": metodo},
                {"Parámetro / Métrica Metrológica": "Fecha de Generación", "Valor": datetime.date.today().strftime("%d/%m/%Y")},
                {"Parámetro / Métrica Metrológica": "Laboratorios Válidos (p)", "Valor": res.get("evaluacion_grubbs", {}).get("p_laboratorios", "-")},
                {"Parámetro / Métrica Metrológica": "Total de Mediciones (N)", "Valor": res.get("numero_de_registros", "-")},
                {"Parámetro / Métrica Metrológica": "Muestreo Ponderado (nj / formula1)", "Valor": res.get("formula1", "-")},
                {"Parámetro / Métrica Metrológica": "Suma Total de Mediciones", "Valor": res.get("suma_mediciones", "-")},
                {"Parámetro / Métrica Metrológica": "Suma de Productos (Tabla 2)", "Valor": res.get("suma_productos_tabla2", "-")},
                {"Parámetro / Métrica Metrológica": "Gran Promedio (mj / X̄̄)", "Valor": res.get("mj", res.get("gran_promedio", "-"))},
                {"Parámetro / Métrica Metrológica": "Promedio de Promedios", "Valor": res.get("gran_promedio", "-")},
                {"Parámetro / Métrica Metrológica": "Mínimo de Promedios", "Valor": res.get("minimo", "-")},
                {"Parámetro / Métrica Metrológica": "Máximo de Promedios", "Valor": res.get("maximo", "-")},
                {"Parámetro / Métrica Metrológica": "Varianza Global", "Valor": res.get("varianza", "-")},
                {"Parámetro / Métrica Metrológica": "Desviación Estándar Global", "Valor": res.get("desviacion_estandar", "-")},
                {"Parámetro / Métrica Metrológica": "Desviación de Promedios (np.std)", "Valor": res.get("desv_prom", "-")},
                {"Parámetro / Métrica Metrológica": "Suma de Varianzas Intralab", "Valor": res.get("suma_varianzas", "-")},
                {"Parámetro / Métrica Metrológica": "Raíz Suma de Varianzas", "Valor": res.get("raiz_suma_varianzas", "-")},
                {"Parámetro / Métrica Metrológica": "Promedio de Desviaciones", "Valor": res.get("promedio_desviaciones", "-")},
                {"Parámetro / Métrica Metrológica": "Desviación de Diferencias", "Valor": res.get("desviacion_diferencias", "-")},
                {"Parámetro / Métrica Metrológica": "Suma Ponderada (∑ n_i * diff²)", "Valor": res.get("suma_ponderada", "-")},
                {"Parámetro / Métrica Metrológica": "Varianza de Diferencias (s2dj)", "Valor": res.get("s2dj", "-")},
                {"Parámetro / Métrica Metrológica": "Varianza de Repetibilidad (sr2j)", "Valor": res.get("sr2j", "-")},
                {"Parámetro / Métrica Metrológica": "Desviación de Repetibilidad (√sr2j)", "Valor": res.get("raizsr2j", "-")},
                {"Parámetro / Métrica Metrológica": "Varianza Interlaboratorio (s2lj)", "Valor": res.get("s2lj", "-")},
                {"Parámetro / Métrica Metrológica": "Relación sr / sl", "Valor": res.get("sr_sl", "-")},
                {"Parámetro / Métrica Metrológica": "Raíz Relación sr / sl", "Valor": res.get("raiz_sr_sl", "-")},
                {"Parámetro / Métrica Metrológica": "Varianza Combinada (s²rj)", "Valor": res.get("srj2", "-")},
                {"Parámetro / Métrica Metrológica": "Desviación Combinada (√s²rj)", "Valor": res.get("raiz_srj", "-")},
                {"Parámetro / Métrica Metrológica": "Porcentaje de Reproducibilidad (%R)", "Valor": res.get("porc_R", "-")},
                {"Parámetro / Métrica Metrológica": "Suma Varianza Total (sr2j + s2lj)", "Valor": res.get("suma_s2rj", "-")},
            ])
            df_global.to_excel(writer, sheet_name="Metricas_ISO5725", index=False)

            filas_lab = [{
                "N° Lab": r["num"],
                "Laboratorio": r["nombre"],
                "Mediciones (n_i)": r["registros"],
                "Valores Brutos": ", ".join(map(str, r["valores"])),
                "Promedio Numérico": r["promedioNum"],
                "Promedio Formateado": r["promedio"],
                "Producto (n_i * X̄_i)": r["producto"],
                "Varianza (s_i²)": r["varianzaNum"],
                "Desviación Numérica (s_i)": r["desviacionNum"],
                "Desviación Formateada": r["desviacion"],
            } for r in res.get("resumen", [])]
            pd.DataFrame(filas_lab).to_excel(writer, sheet_name="Resumen_Laboratorios", index=False)

            diff2 = res.get("diferencias2", [])
            tabla_k = res.get("tabla_k", [])
            filas_mandel = []
            for i, d in enumerate(diff2):
                k_item = tabla_k[i] if i < len(tabla_k) else {}
                filas_mandel.append({
                    "N° Lab": d["num"],
                    "Laboratorio": d["nombre"],
                    "Mediciones": d["registros"],
                    "Promedio": d["promedio"],
                    "Diferencia (X̄_i - Mj)": d["diferencia"],
                    "Diferencia Numérica": d["diferenciaNum"],
                    "Ponderado [n_i*(diff)²]": d["ponderado"],
                    "Mandel h (hij)": d["hij"],
                    "Límite h Crítico": d.get("h_critico", res.get("h_critico", "-")),
                    "Dictamen Mandel h": d.get("cumple", "-"),
                    "Mandel k (val_k)": k_item.get("k_val", "-"),
                    "Límite k Crítico": k_item.get("k_critico", res.get("k_critico", "-")),
                    "Dictamen Mandel k": k_item.get("cumple", "-"),
                })
            pd.DataFrame(filas_mandel).to_excel(writer, sheet_name="Mandel_h_k", index=False)

            df_cochran = pd.DataFrame([
                {"Métrica Cochran": "Estadístico C Calculado", "Valor": res.get("cochran", "-")},
                {"Métrica Cochran": "Criterio de Evaluación", "Valor": res.get("criterio_cochran", "-")},
                {"Métrica Cochran": "Límite Crítico 5%", "Valor": res.get("cochran_critico_5", "-")},
                {"Métrica Cochran": "Límite Crítico 1%", "Valor": res.get("cochran_critico_1", "-")},
                {"Métrica Cochran": "Resultado Cochran", "Valor": res.get("resultado_cochran", "-")},
            ])
            df_cochran.to_excel(writer, sheet_name="Cochran", index=False)

            eg = res.get("evaluacion_grubbs", {})
            crit = eg.get("criticos", {})
            un_max = eg.get("un_maximo", {})
            un_min = eg.get("un_minimo", {})
            dos_max = eg.get("dos_maximos", {})
            dos_min = eg.get("dos_minimos", {})

            filas_grubbs = [
                {"Categoría": "General", "Variable": "Laboratorios (p)", "Valor Calculado": eg.get("p_laboratorios", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "General", "Variable": "Suma de Cuadrados Original (s2o)", "Valor Calculado": res.get("s2o", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "General", "Variable": "Promedio Excl. 2 Max (xp_1p)", "Valor Calculado": res.get("xp_1p", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "General", "Variable": "Suma Cuadrados Excl. 2 Max (s2p)", "Valor Calculado": res.get("s2p", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "General", "Variable": "Promedio Excl. 2 Min (x1_2)", "Valor Calculado": res.get("x1_2", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "General", "Variable": "Suma Cuadrados Excl. 2 Min (s12_2)", "Valor Calculado": res.get("s12_2", "-"), "Límite 5%": "-", "Límite 1%": "-", "Dictamen": "-", "Estado": "-"},
                {"Categoría": "Un Valor", "Variable": "Un Valor Máximo (Gp)", "Valor Calculado": res.get("Gp", un_max.get("valor_g", "-")), "Límite 5%": crit.get("un_valor", {}).get("5%", "-"), "Límite 1%": crit.get("un_valor", {}).get("1%", "-"), "Dictamen": un_max.get("dictamen", "-"), "Estado": un_max.get("estado", "-")},
                {"Categoría": "Un Valor", "Variable": "Un Valor Mínimo (Gpmin)", "Valor Calculado": res.get("Gpmin", un_min.get("valor_g", "-")), "Límite 5%": crit.get("un_valor", {}).get("5%", "-"), "Límite 1%": crit.get("un_valor", {}).get("1%", "-"), "Dictamen": un_min.get("dictamen", "-"), "Estado": un_min.get("estado", "-")},
                {"Categoría": "Dos Valores", "Variable": "Dos Valores Máximos (G)", "Valor Calculado": res.get("G", dos_max.get("valor_g", "-")), "Límite 5%": crit.get("dos_valores", {}).get("5%", "-"), "Límite 1%": crit.get("dos_valores", {}).get("1%", "-"), "Dictamen": dos_max.get("dictamen", "-"), "Estado": dos_max.get("estado", "-")},
                {"Categoría": "Dos Valores", "Variable": "Dos Valores Mínimos (G2)", "Valor Calculado": res.get("G2", dos_min.get("valor_g", "-")), "Límite 5%": crit.get("dos_valores", {}).get("5%", "-"), "Límite 1%": crit.get("dos_valores", {}).get("1%", "-"), "Dictamen": dos_min.get("dictamen", "-"), "Estado": dos_min.get("estado", "-")},
            ]
            pd.DataFrame(filas_grubbs).to_excel(writer, sheet_name="Evaluacion_Grubbs", index=False)

        output.seek(0)
        return FileResponse(
            output,
            as_attachment=True,
            filename=f"Reporte_Estadistico_Completo_{num_muestra}.xlsx",
            content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    except ValueError as e:
        return JsonResponse({"detail": str(e)}, status=400)
    except Exception:
        logger.exception("Error interno en /exportar_excel por usuario='%s'", request.user.username)
        return JsonResponse({"detail": "Error interno al generar el archivo Excel."}, status=500)


@login_required
@require_http_methods(["POST"])
def exportar_pdf(request):
    try:
        payload = parse_json_body(request)
        num_muestra_raw = sanitizar_texto(payload.get("num_muestra"), max_len=50, default="S/N")
        num_muestra_file = num_muestra_raw.replace("/", "_")
        metodo = sanitizar_texto(payload.get("metodo"), max_len=100, default="ASTM D1121")
        observaciones = sanitizar_texto(payload.get("observaciones"), max_len=2000, default="")
        participantes = validar_participantes(payload.get("participantes"))

        res_calc = calcular_estadisticos_iso(participantes)
        muestra_db = MuestraEnsayoDB.objects.filter(num_muestra=num_muestra_raw).first()

        if muestra_db and muestra_db.fecha_registro:
            fecha_emision = muestra_db.fecha_registro.strftime("%d/%m/%Y")
        else:
            fecha_emision = datetime.date.today().strftime("%d/%m/%Y")

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        story = []

        style_normal = styles["Normal"]
        style_title = styles["Title"]
        style_title.fontSize = 12
        style_title.leading = 14
        style_title.alignment = 0
        style_title.textColor = colors.HexColor("#0f172a")

        style_h3 = styles["Heading3"]
        style_h3.fontSize = 9
        style_h3.textColor = colors.HexColor("#0f172a")
        style_h3.spaceBefore = 8
        style_h3.spaceAfter = 4

        logo_drawing = crear_logo_lims()
        header_table = Table([
            [logo_drawing, Paragraph(
                f"<b>Informe de exactitud (veracidad y precisión)</b><br/><font size=8 color='#64748b'>EVALUACIÓN INTERLABORATORIO - {escape(metodo)}</font>",
                style_title)]
        ], colWidths=[160, 380])
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 4))

        obs_texto = escape(observaciones) if observaciones else "Sin observaciones"
        meta_data = [
            [Paragraph("<b>N°Lote:</b>", style_normal), escape(num_muestra_raw), Paragraph("<b>Fecha de emisión:</b>", style_normal), fecha_emision],
            [Paragraph("<b>Método:</b>", style_normal), escape(metodo), Paragraph("<b>Laboratorios (p):</b>", style_normal), str(len(participantes))],
            [Paragraph("<b>Observaciones:</b>", style_normal), Paragraph(obs_texto, style_normal), "", ""],
        ]
        t_meta = Table(meta_data, colWidths=[120, 150, 120, 150])
        t_meta.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("SPAN", (1, 2), (3, 2)),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 6))

        story.append(Paragraph("1. Resumen Estadístico por Participante", style_h3))
        t_data = [["N°", "Participantes", "n", "Promedio (Xi)", "Desv. (si)"]]
        for r in res_calc.get("resumen", []):
            t_data.append([str(r["num"]), r["nombre"], str(r["registros"]), r["promedio"], r["desviacion"]])

        t_resumen = Table(t_data, colWidths=[30, 170, 40, 100, 100, 100])
        t_resumen.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (1, 1), (1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(t_resumen)
        story.append(Spacer(1, 6))

        puntos = res_calc.get("puntos_grafica", [])
        x_labs = [p["x"] for p in puntos]
        y_vals = [p["y"] for p in puntos]
        gran_prom = float(res_calc.get("gran_promedio", 0))

        fig1, ax1 = plt.subplots(figsize=(6.5, 1.8), dpi=180)
        ax1.plot(x_labs, y_vals, marker="o", color="#2563eb", linestyle="-", linewidth=1.2, markersize=4)
        ax1.axhline(y=gran_prom, color="#dc2626", linestyle="--", linewidth=1, label=f"Gran Promedio: {gran_prom:.2f}")
        ax1.set_title("Gráfica 1: Dispersión de Mediciones Individuales", fontsize=8, fontweight="bold")
        ax1.tick_params(axis="both", labelsize=6.5)
        ax1.grid(True, linestyle=":", alpha=0.5)
        ax1.legend(fontsize=6.5, loc="upper right")

        story.append(Paragraph("2. Consistencia Gráfica de Mediciones Individuales", style_h3))
        story.append(fig_to_rl_image(fig1, width=520, height=130))
        story.append(Spacer(1, 6))

        story.append(Paragraph("3. Prueba y Consistencia Gráfica de Mandel (h & k)", style_h3))
        diff2 = res_calc.get("diferencias2", [])
        tabla_k = res_calc.get("tabla_k", [])
        h_crit = float(res_calc.get("h_critico", 1.0))
        k_crit = float(res_calc.get("k_critico", 1.0))

        labels_h = [str(item["num"]) for item in diff2]
        vals_h = [item["hij"] for item in diff2]
        colors_h = ["#ef4444" if abs(v) > h_crit else "#2563eb" for v in vals_h]

        fig_h, ax_h = plt.subplots(figsize=(6.5, 1.8), dpi=180)
        ax_h.bar(labels_h, vals_h, color=colors_h, width=0.45)
        ax_h.axhline(y=h_crit, color="#dc2626", linestyle="--", linewidth=0.9, label=f"+h crit ({h_crit})")
        ax_h.axhline(y=-h_crit, color="#dc2626", linestyle="--", linewidth=0.9, label=f"-h crit (-{h_crit})")
        ax_h.axhline(y=0, color="#64748b", linewidth=0.5)
        ax_h.set_title("Gráfica 2: Mandel h (Variabilidad Interlaboratorio)", fontsize=8, fontweight="bold")
        ax_h.tick_params(axis="both", labelsize=6.5)
        ax_h.grid(True, linestyle=":", alpha=0.5)
        ax_h.legend(fontsize=6, loc="upper right")
        story.append(fig_to_rl_image(fig_h, width=520, height=130))
        story.append(Spacer(1, 4))

        labels_k = [str(item["num"]) for item in tabla_k]
        vals_k = [float(item["k_val"]) if item["k_val"] != "-" else 0.0 for item in tabla_k]
        colors_k = ["#ef4444" if v > k_crit else "#0891b2" for v in vals_k]

        fig_k, ax_k = plt.subplots(figsize=(6.5, 1.8), dpi=180)
        ax_k.bar(labels_k, vals_k, color=colors_k, width=0.45)
        ax_k.axhline(y=k_crit, color="#dc2626", linestyle="--", linewidth=0.9, label=f"k crit ({k_crit})")
        ax_k.set_title("Gráfica 3: Mandel k (Variabilidad Intralaboratorio)", fontsize=8, fontweight="bold")
        ax_k.tick_params(axis="both", labelsize=6.5)
        ax_k.grid(True, linestyle=":", alpha=0.5)
        ax_k.legend(fontsize=6, loc="upper right")
        story.append(fig_to_rl_image(fig_k, width=520, height=130))
        story.append(Spacer(1, 6))

        story.append(Paragraph("4. Variabilidad Intralaboratorio (Cochran)", style_h3))
        resumen_list = res_calc.get("resumen", [])
        labels_cochran = [str(r["num"]) for r in resumen_list]
        varianzas_cochran = [r["varianzaNum"] for r in resumen_list]

        fig_c, ax_c = plt.subplots(figsize=(6.5, 1.8), dpi=180)
        ax_c.plot(labels_cochran, varianzas_cochran, marker="s", color="#d97706", linestyle="-", linewidth=1.2, markersize=4)
        ax_c.set_title("Gráfica 4: Distribución de Varianzas por Laboratorio (Cochran)", fontsize=8, fontweight="bold")
        ax_c.tick_params(axis="both", labelsize=6.5)
        ax_c.grid(True, linestyle=":", alpha=0.5)
        story.append(fig_to_rl_image(fig_c, width=520, height=130))
        story.append(Spacer(1, 6))

        story.append(Paragraph("5. Evaluación Completa de Outliers (Grubbs)", style_h3))
        promedios_ord = [r["promedioNum"] for r in res_calc.get("resumen_grubbs", [])]
        labels_g = [f"Lab {r['num']}" for r in res_calc.get("resumen_grubbs", [])]

        fig_g, ax_g = plt.subplots(figsize=(6.5, 1.8), dpi=180)
        ax_g.scatter(labels_g, promedios_ord, color="#7c3aed", s=25, zorder=3)
        ax_g.axhline(y=gran_prom, color="#dc2626", linestyle="--", linewidth=0.9, label=f"Promedio: {gran_prom:.2f}")
        ax_g.set_title("Gráfica 5: Dispersión Ordenada para Evaluación de Grubbs", fontsize=8, fontweight="bold")
        ax_g.tick_params(axis="both", labelsize=6.5)
        ax_g.grid(True, linestyle=":", alpha=0.5)
        ax_g.legend(fontsize=6, loc="upper left")
        story.append(fig_to_rl_image(fig_g, width=520, height=130))
        story.append(Spacer(1, 6))

        eg = res_calc.get("evaluacion_grubbs", {})
        un_max = eg.get("un_maximo", {})
        un_min = eg.get("un_minimo", {})
        dos_max = eg.get("dos_maximos", {})
        dos_min = eg.get("dos_minimos", {})
        criticos = eg.get("criticos", {})
        crit_1val_5 = criticos.get("un_valor", {}).get("5%", "-")
        crit_2val_5 = criticos.get("dos_valores", {}).get("5%", "-")
        crit_g1_txt = f"G < {crit_1val_5}" if crit_1val_5 != "-" else "G < Crit (5%)"
        crit_g2_txt = f"G2 > {crit_2val_5}" if crit_2val_5 != "-" else "G2 < Crit (5%)"

        try:
            val_h = float(res_calc.get("maxh", 0))
            crit_h = float(res_calc.get("h_critico", float("inf")))
            dictamen_mandel_h = "CONSISTENTE" if val_h <= crit_h else "NO CONSISTENTE"
        except (ValueError, TypeError):
            dictamen_mandel_h = "ERROR"

        try:
            val_k = float(res_calc.get("maxk", 0))
            dictamen_mandel_k = "CONSISTENTE" if val_k <= crit_h else "NO CONSISTENTE"
        except (ValueError, TypeError):
            dictamen_mandel_k = "ERROR"

        validaciones_data = [
            ["Prueba Estadística", "Valor Calculado", "Criterio Aceptación", "Dictamen Final"],
            ["Mandel k", str(res_calc.get("maxk", "-")), f" {res_calc.get('criteriok', 'Crit')}", dictamen_mandel_k],
            ["Mandel h", str(res_calc.get("maxh", "-")), f" {res_calc.get('criterioh', 'Crit')}", dictamen_mandel_h],
            ["Cochran C1 5%", str(res_calc.get("cochran", "-")), str(res_calc.get("criterio_cochran", "C < Crit")), str(res_calc.get("resultado_cochran", "CONFORME"))],
            ["Grubbs (1 Máximo Extremo)5%", str(un_max.get("valor_g", "-")), crit_g1_txt, str(un_max.get("dictamen", "CONSISTENTE"))],
            ["Grubbs (1 Mínimo Extremo)5%", str(un_min.get("valor_g", "-")), crit_g1_txt, str(un_min.get("dictamen", "CONSISTENTE"))],
            ["Grubbs (2 Máximos Extremos)5%", str(dos_max.get("valor_g", "-")), crit_g2_txt, str(dos_max.get("dictamen", "CONSISTENTE"))],
            ["Grubbs (2 Mínimos Extremos)5%", str(dos_min.get("valor_g", "-")), crit_g2_txt, str(dos_min.get("dictamen", "CONSISTENTE"))],
            ["%R", str(res_calc.get("porc_R", "-")), "-", "-"],
        ]

        estilos_tabla = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("ALIGN", (0, 1), (0, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]

        PALABRAS_POSITIVAS = ["CONSISTENTE", "CONFORME", "ACEPTADO", "OK"]
        PALABRAS_NEGATIVAS = ["NO CONSISTENTE", "NO CONFORME", "RECHAZADO", "ERROR"]

        for row_idx, fila in enumerate(validaciones_data[1:], start=1):
            for col_idx, valor in enumerate(fila):
                val_str = str(valor).strip().upper()
                if any(p in val_str for p in PALABRAS_NEGATIVAS):
                    estilos_tabla.append(("TEXTCOLOR", (col_idx, row_idx), (col_idx, row_idx), colors.HexColor("#dc2626")))
                    estilos_tabla.append(("FONTNAME", (col_idx, row_idx), (col_idx, row_idx), "Helvetica-Bold"))
                elif any(p in val_str for p in PALABRAS_POSITIVAS):
                    estilos_tabla.append(("TEXTCOLOR", (col_idx, row_idx), (col_idx, row_idx), colors.HexColor("#16a34a")))
                    estilos_tabla.append(("FONTNAME", (col_idx, row_idx), (col_idx, row_idx), "Helvetica-Bold"))

        t_validaciones = Table(validaciones_data, colWidths=[170, 110, 130, 130])
        t_validaciones.setStyle(TableStyle(estilos_tabla))
        story.append(t_validaciones)
        story.append(Spacer(1, 20))

        firmas_data = [
            ["__________________________________", "__________________________________"],
            ["Analista de metrologia y equipamiento", "Jefe de laboratorio y control de calidad"],
            ["Realizado por", "Aprobado por"],
        ]
        t_firmas = Table(firmas_data, colWidths=[260, 260])
        t_firmas.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#475569")),
        ]))
        story.append(t_firmas)

        doc.build(story)
        buffer.seek(0)
        return FileResponse(
            buffer,
            as_attachment=True,
            filename=f"Informe_Oficial_{num_muestra_file}.pdf",
            content_type="application/pdf",
        )
    except ValueError as e:
        return JsonResponse({"detail": str(e)}, status=400)
    except Exception:
        logger.exception("Error interno en /exportar_pdf por usuario='%s'", request.user.username)
        return JsonResponse({"detail": "Error interno al generar el reporte PDF."}, status=500)


@login_required
@require_http_methods(["GET"])
def obtener_muestra(request, num_muestra):
    muestra_clean = sanitizar_texto(num_muestra, max_len=50)
    muestra = MuestraEnsayoDB.objects.filter(num_muestra=muestra_clean).first()
    if not muestra:
        return JsonResponse({"detail": "La muestra solicitada no existe."}, status=404)

    try:
        participantes_raw = json.loads(muestra.datos_resumen)
        participantes_limpios = []

        for i, p in enumerate(participantes_raw):
            raw_valores = p.get("valores", [])
            valores_limpios = []
            for x in raw_valores:
                if x is not None and x != "":
                    val_str = str(x).replace(",", ".").strip()
                    try:
                        valores_limpios.append(float(val_str))
                    except ValueError:
                        continue

            participantes_limpios.append({
                "participante_num": p.get("participante_num", p.get("num", i + 1)),
                "participante_nombre": p.get("participante_nombre", p.get("nombre", f"Lab {i + 1}")),
                "valores": valores_limpios,
            })
    except Exception:
        logger.exception("Error deserializando muestra='%s'", muestra_clean)
        return JsonResponse({"detail": "Error interno al leer los datos de la muestra."}, status=500)

    resultado = calcular_estadisticos_iso(participantes_limpios)

    dictamen_global_guardado = "CONFORME"
    if muestra.dictamen_grubbs:
        try:
            dg = json.loads(muestra.dictamen_grubbs)
            if isinstance(dg, dict) and "dictamen_global" in dg:
                dictamen_global_guardado = dg["dictamen_global"]
        except Exception:
            pass

    resultado.update({
        "id_db": muestra.id,
        "num_muestra": muestra.num_muestra,
        "metodo": muestra.metodo,
        "dictamen_global": dictamen_global_guardado,
        "observaciones": muestra.observaciones or "",
    })

    return JsonResponse(resultado)


@login_required
@require_http_methods(["DELETE"])
def eliminar_registro(request, registro_id):
    muestra = MuestraEnsayoDB.objects.filter(id=registro_id).first()
    if not muestra:
        return JsonResponse({"detail": "El registro solicitado no existe."}, status=404)

    num_m = muestra.num_muestra
    muestra.delete()
    logger.warning("Registro eliminado: id=%s muestra='%s' usuario='%s'", registro_id, num_m, request.user.username)
    return JsonResponse({"mensaje": f"Registro {registro_id} eliminado exitosamente."})


@login_required
@require_http_methods(["GET", "POST"])
def metodos_endpoint(request):
    if request.method == "GET":
        metodos = list(MetodoNormativoDB.objects.all().values("id", "nombre"))
        if not metodos:
            metodos_default = [
                "ASTM D445", "ASTM D2896", "ASTM D5293", "ASTM D4951", "ASTM D92",
                "ASTM D1287", "ASTM D1121", "ISO 4406", "ASTM 2270", "ASTM 2265",
                "ISO 22241 ANEXO C", "ISO 22241 ANEXO E", "ISO 22241 ANEXO F",
                "ISO 22241 ANEXO H", "ISO 22241 ANEXO I", "ASTM D4684",
                "ASTM D5800 NOACK B", "ASTM D5800 NOACK C", "ASTM D892",
                "ISO 18611 ANEXO C", "ISO 18611 ANEXO D", "ISO 18611 ANEXO I",
            ]
            MetodoNormativoDB.objects.bulk_create([MetodoNormativoDB(nombre=m) for m in metodos_default])
            metodos = list(MetodoNormativoDB.objects.all().values("id", "nombre"))
        return JsonResponse(metodos, safe=False)

    elif request.method == "POST":
        try:
            payload = parse_json_body(request)
            nombre_clean = sanitizar_texto(payload.get("nombre"), max_len=100).upper()
            if not nombre_clean:
                return JsonResponse({"detail": "El nombre del método no puede estar vacío."}, status=400)

            desc_clean = sanitizar_texto(payload.get("descripcion"), max_len=255, default="")
            metodo_obj, created = MetodoNormativoDB.objects.get_or_create(
                nombre=nombre_clean,
                defaults={"descripcion": desc_clean or None},
            )
            logger.info("Método creado/consultado: nombre='%s' usuario='%s'", nombre_clean, request.user.username)
            return JsonResponse({
                "status": "created" if created else "exists",
                "id": metodo_obj.id,
                "nombre": metodo_obj.nombre,
            })
        except ValueError as e:
            return JsonResponse({"detail": str(e)}, status=400)
        except Exception:
            logger.exception("Error interno en /metodos por usuario='%s'", request.user.username)
            return JsonResponse({"detail": "Error interno al registrar el método."}, status=500)


@login_required
@require_http_methods(["DELETE"])
def eliminar_metodo(request, metodo_id):
    metodo = MetodoNormativoDB.objects.filter(id=metodo_id).first()
    if not metodo:
        return JsonResponse({"detail": "El método solicitado no existe."}, status=404)

    nombre = metodo.nombre
    metodo.delete()
    logger.warning("Método eliminado: id=%s nombre='%s' usuario='%s'", metodo_id, nombre, request.user.username)
    return JsonResponse({"status": "deleted", "id": metodo_id, "nombre": nombre})



urlpatterns = [
    path("login", login_view),
    path("logout", logout_view),
    path("", read_index),
    path("index.html", read_index),
    path("consola", read_index),
    path("registros", read_registros),
    path("registros.html", read_registros),
    path("obtener_registros", obtener_registros),
    path("guardar", guardar),
    path("guardar_avanzado", guardar_avanzado),
    path("exportar_excel", exportar_excel),
    path("exportar_pdf", exportar_pdf),
    path("obtener_muestra/<path:num_muestra>", obtener_muestra),
    path("eliminar_registro/<int:registro_id>", eliminar_registro),
    path("metodos", metodos_endpoint),
    path("metodos/<int:metodo_id>", eliminar_metodo),
]

if (BASE_DIR / "static").exists():
    urlpatterns += static(settings.STATIC_URL, document_root=BASE_DIR / "static")

application = get_wsgi_application()


if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "__main__")
    execute_from_command_line(sys.argv)
