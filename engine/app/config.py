from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

ENGINE_HOST = os.getenv("ENGINE_HOST", "127.0.0.1")
ENGINE_PORT = int(os.getenv("ENGINE_PORT", "8000"))
CORS_ORIGINS = [
    o.strip()
    for o in os.getenv(
        "CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",")
    if o.strip()
]
BLOCK_SECONDS = int(os.getenv("BLOCK_SECONDS", "300"))
PATTERNS_DIR = ROOT / "patterns"
DB_PATH = DATA_DIR / "wh.db"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto").strip().lower()
