"""Конфиг AEGIS. Переопределяется переменными окружения. Без docker."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("AEGIS_DATA", str(ROOT / "data")))
DB_PATH = DATA_DIR / "aegis.db"
USER_AGENT = os.environ.get("AEGIS_UA", "AEGIS-scanner/0.1.0 (+local; set AEGIS_UA)")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
HTTP_TIMEOUT = float(os.environ.get("AEGIS_HTTP_TIMEOUT", "15"))
MODEL = os.environ.get("AEGIS_MODEL", "gpt-oss:20b")
LLM_TIMEOUT = float(os.environ.get("AEGIS_LLM_TIMEOUT", "300"))
BIND_HOST = os.environ.get("AEGIS_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("AEGIS_PORT", "8000"))
MAX_WORKERS = int(os.environ.get("AEGIS_WORKERS", "16"))
GRAPH_DEPTH_DEFAULT = int(os.environ.get("AEGIS_GRAPH_DEPTH", "3"))
