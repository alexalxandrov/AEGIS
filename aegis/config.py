"""Конфиг AEGIS. Только stdlib. Переопределяется переменными окружения."""
import os
from pathlib import Path

DATA_DIR = Path(os.environ.get("AEGIS_DATA", "data"))
DB_PATH = DATA_DIR / "aegis.db"
USER_AGENT = os.environ.get("AEGIS_UA", "AEGIS-scanner/0.0.1 (+contact: set AEGIS_UA)")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
HTTP_TIMEOUT = float(os.environ.get("AEGIS_HTTP_TIMEOUT", "15"))
MODEL = os.environ.get("AEGIS_MODEL", "gpt-oss:20b")
LLM_TIMEOUT = float(os.environ.get("AEGIS_LLM_TIMEOUT", "300"))
