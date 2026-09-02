"""
Bridgena v1.0 — OpenAI-Compatible Bridge for arena.ai
Multi-worker · Session Keeper · Browser Bridge · Low Resource
"""
import argparse
import asyncio
import base64
import hashlib
import hmac
import html
import json
import math
import mimetypes
import os
import random
import re
import secrets
import sys
import subprocess
import os
import time
import uuid
from urllib.parse import quote
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx
from curl_cffi.requests import AsyncSession
import hashlib
import uvicorn
from fastapi import (
    Depends, FastAPI, File, Form, Header, HTTPException,
    Request, Response, UploadFile, status,
)
from fastapi.responses import (
    HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse, FileResponse
)
import glob
from fastapi.security import APIKeyHeader

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

try:
    from camoufox.async_api import AsyncCamoufox
except ImportError:
    AsyncCamoufox = None

try:
    from recaptcha_solver import get_solver
except ImportError:
    get_solver = None

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

PORT = int(os.environ.get("BRIDGENA_PORT", "8000"))
ARENA_BASE = "https://arena.ai"
# Browser UA must equal curl_cffi's chrome131 UA: Cloudflare binds cf_clearance to
# (IP, UA). Mismatch => the keeper passes while every curl request gets challenged.
KEEPER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
ARENA_MODES = ["direct-battle", "direct"]
MAX_PROMPT = 50000
COOLDOWN_SEC = 60  # 1 min soft preference only — never hard-locks accounts
REFRESH_INTERVAL = 3600

COMPACT_THRESHOLD = 30000
KEEP_RECENT_MSGS = 4

OX_BASE = "https://oxalpha.com"
OX_ENDPOINT = "/api/chat"
OX_UPSTREAM_MODEL = "z-ai/glm-5.3-flash"
OX_ALIASES = {"glm-5.3-flash", "ox-alpha"}
OX_MODEL_ID = "glm-5.3-flash"
OX_SESSION_TTL = 20 * 60

CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
MODELS_RAW_DEBUG_FILE = "models_raw_debug.json"
STATE_FILE = "state.json"
JARS_FILE = "cookie_jars.json"
LOG_FILE = "logs.jsonl"
OX_SESSION_FILE = "oxalpha_session.json"
OX_COOKIES_FILE = "oxalpha_cookies.json"
SELECTORS_FILE = "login_selectors.json"
PROFILES_DIR = "browser_profiles"

STATE_LOCK = ".state.lock"
JARS_LOCK = ".jars.lock"

KEEPER_RELOGIN_TIMEOUT = 150
KEEPER_HEALTH_INTERVAL = 600
KEEPER_ACTIVITY_MIN = 60
KEEPER_ACTIVITY_MAX = 120
KEEPER_NAV_MIN = 1200
KEEPER_NAV_MAX = 2000

GATING_TRUE_KEYS = {"isPro", "pro", "gated", "requiresPro", "isGated"}
GATING_FALSE_KEYS = {"userSelectable", "selectable", "available", "enabled"}
MAX_LOG_LINES = 3000
MAX_CONVERSATIONS = 500

dashboard_sessions: Dict[str, str] = {}  # legacy fallback only

# ============================================================
# STATELESS SIGNED SESSIONS (multi-worker safe, no Redis required)
# ============================================================

def _session_secret() -> str:
    """Stable secret derived from dashboard password."""
    try:
        pw = get_config().get("password") or "admin"
    except Exception:
        pw = "admin"
    return hashlib.sha256(f"{pw}|bridgena-session-v1".encode()).hexdigest()


def create_session_token(user: str = "admin", ttl: int = 86400 * 30) -> str:
    exp = int(time.time()) + ttl
    payload = f"{user}:{exp}"
    sig = hmac.new(_session_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def verify_session_token(token: str) -> Optional[str]:
    if not token:
        return None
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode((token + pad).encode()).decode()
        user, exp_s, sig = raw.rsplit(":", 2)
        if time.time() > int(exp_s):
            return None
        payload = f"{user}:{exp_s}"
        expect = hmac.new(_session_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(expect, sig):
            return None
        return user
    except Exception:
        return None


DEFAULT_KNOWN_MODELS = [
    {"id": "claude-3-7-sonnet-20250219", "publicName": "claude-3-7-sonnet", "organization": "Anthropic", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "claude-3-5-sonnet-20241022", "publicName": "claude-3-5-sonnet", "organization": "Anthropic", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "gpt-4o", "publicName": "gpt-4o", "organization": "OpenAI", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "gpt-4.5-preview", "publicName": "gpt-4.5-preview", "organization": "OpenAI", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "o3-mini", "publicName": "o3-mini", "organization": "OpenAI", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "o1", "publicName": "o1", "organization": "OpenAI", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "deepseek-ai/deepseek-r1", "publicName": "deepseek-r1", "organization": "DeepSeek", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "deepseek-ai/deepseek-v3", "publicName": "deepseek-v3", "organization": "DeepSeek", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "gemini-2.0-flash", "publicName": "gemini-2.0-flash", "organization": "Google", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "gemini-2.0-pro-exp-02-05", "publicName": "gemini-2.0-pro-exp", "organization": "Google", "capabilities": {"inputCapabilities": {"image": True, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "meta-llama/llama-3.3-70b-instruct", "publicName": "llama-3.3-70b-instruct", "organization": "Meta", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
    {"id": "qwen/qwen-2.5-max", "publicName": "qwen-2.5-max", "organization": "Qwen", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
]


# ============================================================
# CROSS-PROCESS FILE LOCK
# ============================================================

class FileLock:
    def __init__(self, path: str, timeout: float = 20.0, stale: float = 30.0):
        self.path, self.timeout, self.stale = path, timeout, stale
        self.fd = None

    def __enter__(self):
        start = time.time()
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, str(os.getpid()).encode())
                return self
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self.path) > self.stale:
                        os.remove(self.path)
                        continue
                except FileNotFoundError:
                    pass
                if time.time() - start > self.timeout:
                    return self
                time.sleep(0.02)

    def __exit__(self, *args):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except Exception:
                pass
            try:
                os.remove(self.path)
            except Exception:
                pass


def atomic_write(path: str, data: Any) -> None:
    tmp = f"{path}.tmp{os.getpid()}_{secrets.token_hex(4)}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# ============================================================
# LOGGING WITH ROTATION
# ============================================================

_log_counter = 0

def log(level: str, message: str) -> None:
    global _log_counter
    entry = {
        "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
        "level": level, "message": message, "pid": os.getpid(),
    }
    try:
        _log_counter += 1
        if _log_counter % 500 == 0:
            try:
                if os.path.getsize(LOG_FILE) > 400_000:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    with open(LOG_FILE, "w", encoding="utf-8") as f:
                        f.writelines(lines[-(MAX_LOG_LINES // 2):])
            except Exception:
                pass
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    print(f"[{entry['time']}] [{level:>5}] {message}", flush=True)


append_log = log


def read_logs(n: int = 150) -> list:
    try:
        with open(LOG_FILE, encoding="utf-8") as f:
            lines = f.readlines()
        return [json.loads(line) for line in lines[-n:] if line.strip()]
    except Exception:
        return []


# ============================================================
# UUID V7
# ============================================================

def uuid7() -> str:
    ts = int(time.time() * 1000)
    combined = (
        (ts << 80)
        | ((0x7000 | secrets.randbits(12)) << 64)
        | (0x8000000000000000 | secrets.randbits(62))
    )
    h = f"{combined:032x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ============================================================
# SHARED STATE (WITH IN-MEMORY CACHE)
# ============================================================

_state_cache = None
_state_cache_time = 0.0

def default_state() -> dict:
    return {
        "conversations": {}, "usage_stats": {}, "rate_buckets": {},
        "blocked_models": [], "last_refresh": 0, "refresh_started": 0,
        "keeper_pid": None, "keeper_heartbeat": 0, "keeper_status": [],
    }


def load_state() -> dict:
    global _state_cache, _state_cache_time
    now = time.time()
    if _state_cache is not None and now - _state_cache_time < 3:
        return _state_cache
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
    except Exception:
        state = {}
    for k, v in default_state().items():
        state.setdefault(k, v)
    _state_cache = state
    _state_cache_time = now
    return state


def mutate_state(fn) -> None:
    global _state_cache, _state_cache_time
    with FileLock(STATE_LOCK):
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
        for k, v in default_state().items():
            state.setdefault(k, v)
        fn(state)
        atomic_write(STATE_FILE, state)
        _state_cache = state
        _state_cache_time = time.time()


# ============================================================
# CONFIG & MODELS (WITH CACHE)
# ============================================================

_models_cache = None
_models_cache_time = 0.0

def get_config() -> dict:
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            config = json.load(f)
    except Exception:
        config = {}
    config.setdefault("password", "admin")
    config.setdefault("api_keys", [])
    config.setdefault("workers", 1)
    config.setdefault("proxies", [])  # ["http://user:pass@host:port", ...]
    return config


def save_config(config: dict) -> None:
    atomic_write(CONFIG_FILE, config)


def get_models() -> list:
    global _models_cache, _models_cache_time
    now = time.time()
    if _models_cache is not None and now - _models_cache_time < 30:
        return _models_cache
    try:
        with open(MODELS_FILE, encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list) and len(data) > 0:
                _models_cache = data
                _models_cache_time = now
                return data
    except Exception:
        pass
    return list(DEFAULT_KNOWN_MODELS)


def save_models(models: list) -> None:
    global _models_cache, _models_cache_time
    atomic_write(MODELS_FILE, models)
    _models_cache = models
    _models_cache_time = time.time()


def _truthy(v):
    return v is True or v == 1 or (isinstance(v, str) and v.lower() in ("true", "1", "yes"))

def _falsey(v):
    return v is False or v == 0 or (isinstance(v, str) and v.lower() in ("false", "0", "no"))

# IDE Update Marker
def is_model_selectable(model: dict) -> bool:
    # ============================================================
    # Exact nested capability check as requested.
    # Top-level and nested ("access"/"availability") gating flags are
    # checked with the SAME key set so a model can't slip through just
    # because Arena nested the gate one level deeper.
    # ============================================================
    def _truthy(v):
        return v is True or v == 1 or (isinstance(v, str) and v.lower() in ("true", "1", "yes"))

    def _falsey(v):
        return v is False or v == 0 or (isinstance(v, str) and v.lower() in ("false", "0", "no"))

    gated_keys = ("isPro", "pro", "isGated", "gated", "requiresPro")
    selectable_keys = ("userSelectable", "selectable", "available", "enabled")

    for key in gated_keys:
        if _truthy(model.get(key)):
            return False
    for key in selectable_keys:
        if key in model and _falsey(model[key]):
            return False

    flags = model.get("access") or model.get("availability") or {}
    if isinstance(flags, dict):
        for key in gated_keys:
            if _truthy(flags.get(key)):
                return False
        for key in selectable_keys:
            if key in flags and _falsey(flags[key]):
                return False
    return True

def get_selectable_models() -> list:
    blocked = set(load_state().get("blocked_models", []))
    seen, out = set(), []
    for model in get_models():
        name = model.get("publicName") or model.get("id") or model.get("name")
        if not name or name in blocked or name in seen:
            continue
        if not is_model_selectable(model):
            continue
        caps = (model.get("capabilities") or {}).get("outputCapabilities") or model.get("outputCapabilities") or {}
        if caps.get("text") is False:
            continue
        mc = dict(model)
        mc["publicName"] = name
        mc.setdefault("organization", "Arena")
        seen.add(name)
        out.append(mc)
    return out
# ============================================================
# COOKIE VALIDATION & JARS POOL (WITH CACHE)
# ============================================================

_jars_cache = None
_jars_cache_time = 0.0

def _validate_cookies(raw_data: Union[str, list, dict]) -> list:
    items = []
    if isinstance(raw_data, list):
        items = raw_data
    elif isinstance(raw_data, dict):
        items = raw_data.get("cookies", [raw_data])
    elif isinstance(raw_data, str):
        raw_str = raw_data.strip()
        if not raw_str:
            return []
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, list):
                items = parsed
            elif isinstance(parsed, dict):
                items = parsed.get("cookies", [parsed])
        except Exception:
            items = []
            for line in raw_str.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 7:
                    items.append({
                        "domain": parts[0], "path": parts[2],
                        "secure": parts[3].lower() == "true",
                        "expirationDate": float(parts[4]) if parts[4].replace(".", "", 1).isdigit() else None,
                        "name": parts[5], "value": parts[6], "httpOnly": False,
                    })
                elif "=" in line:
                    for p in line.split(";"):
                        if "=" in p:
                            k, v = p.strip().split("=", 1)
                            if k.lower() not in ("path", "domain", "expires", "max-age", "samesite"):
                                items.append({"name": k.strip(), "value": v.strip(), "domain": ".arena.ai", "path": "/"})
    out, seen = [], set()
    for c in items:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "").strip()
        val = str(c.get("value") or "").strip()
        if not name or not val:
            continue
        key = (name, c.get("domain", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "name": name, "value": val,
            "domain": c.get("domain") or ".arena.ai",
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
            "expirationDate": c.get("expirationDate") or c.get("expires"),
        })
    return out


def load_jars() -> list:
    global _jars_cache, _jars_cache_time
    now = time.time()
    if _jars_cache is not None and now - _jars_cache_time < 2:
        return _jars_cache
    try:
        with open(JARS_FILE, encoding="utf-8") as f:
            jars = json.load(f)
        result = jars if isinstance(jars, list) else []
    except Exception:
        result = []
    _jars_cache = result
    _jars_cache_time = now
    return result


def mutate_jars(fn) -> None:
    global _jars_cache, _jars_cache_time
    with FileLock(JARS_LOCK):
        try:
            with open(JARS_FILE, encoding="utf-8") as f:
                jars = json.load(f)
            if not isinstance(jars, list):
                jars = []
        except Exception:
            jars = []
        fn(jars)
        atomic_write(JARS_FILE, jars)
        _jars_cache = jars
        _jars_cache_time = time.time()


def _new_jar(name: str, cookies: list, email: str = "", password: str = "",
             login_method: str = "email", keeper_enabled: bool = False) -> Tuple[dict, set]:
    required = {"arena-auth-prod-v1.0", "arena-auth-prod-v1.1", "arena-auth-prod-v1", "cf_clearance"}
    found = required & {c.get("name") for c in cookies}
    jar = {
        "id": f"jar_{uuid.uuid4().hex[:10]}",
        "name": name or f"Account {time.strftime('%H:%M')}",
        "enabled": True, "cookies": cookies, "status": "ok",
        "expired": False, "limited_until": 0, "usage_count": 0,
        "last_used": 0, "created": int(time.time()),
        "login_method": login_method, "email": email, "password": password,
        "keeper_enabled": keeper_enabled, "keeper_headless": True,
        "keeper_humanize": False,
        "proxy": "",  # optional per-account: http://user:pass@host:port
    }
    mutate_jars(lambda jars: jars.append(jar))
    return jar, found


def find_cookie(cookies: list, name: str) -> str:
    for c in cookies:
        if c.get("name") == name:
            return c.get("value", "")
    return ""


def jar_has_auth(jar: dict) -> bool:
    cookies = jar.get("cookies", [])
    return bool(
        find_cookie(cookies, "arena-auth-prod-v1.0")
        or find_cookie(cookies, "arena-auth-prod-v1.1")
        or find_cookie(cookies, "arena-auth-prod-v1")
    )


def jar_has_cf(jar: dict) -> bool:
    return bool(find_cookie(jar.get("cookies", []), "cf_clearance"))

# [Antigravity IDE Verified: Fix 1 (jar_available) Applied]
def jar_available(jar: dict, now: float = None) -> bool:
    """Usable if enabled and has auth cookies OR a live keeper session.

    limited_until is ONLY a soft preference in acquire_jar scoring — it must
    never hard-block an account that still has valid cookies / a live browser.
    """
    now = now or time.time()
    if not jar.get("enabled", True):
        return False
    if jar_has_auth(jar):
        return True
    s = keeper.sessions.get(jar.get("id"))
    if s and s.running and getattr(s, "page", None) and not s.page.is_closed():
        return True
    return False


def acquire_jar(prefer_live: bool = True) -> Optional[dict]:
    """Pick the best jar for a request.

    Priority when prefer_live=True (default, needed for new chats / captcha):
      1. Enabled + auth + has a running live (headed) keeper session
      2. Enabled + auth + has any running keeper session
      3. Fully available jar (not rate-limited, has auth cookies)
      4. Last resort: any enabled jar that still has a live session

    This makes the browser-bridge path the default whenever possible so we
    never need to scrape reCAPTCHA tokens from a page that isn't attached.
    """
    now = time.time()
    chosen = {}

    def _score(j: dict) -> tuple:
        """Higher is better. Returns a sort key (prefer higher)."""
        sid = j.get("id")
        s = keeper.sessions.get(sid) if sid else None
        has_session = bool(s and s.running and getattr(s, "page", None) and not s.page.is_closed())
        is_live = has_session and (not getattr(s, "headless", True))
        healthy = bool(s and s.last_health_ok and (now - s.last_health_ok) < 900)
        available = jar_available(j, now)
        # last_used is inverted so older = higher priority
        recency = -float(j.get("last_used", 0) or 0)
        return (
            1 if (prefer_live and is_live and healthy) else 0,
            1 if (prefer_live and has_session and healthy) else 0,
            1 if available else 0,
            1 if has_session else 0,
            recency,
        )

    def pick(jars: list):
        candidates = [j for j in jars if j.get("enabled", True)]
        if not candidates:
            return
        # Sort by score descending
        candidates.sort(key=_score, reverse=True)
        best = candidates[0]
        # Only accept if it at least has auth or a live session
        sid = best.get("id")
        s = keeper.sessions.get(sid) if sid else None
        has_session = bool(s and s.running)
        if not jar_has_auth(best) and not has_session:
            # Try to find any jar that has either auth cookies or a live session
            for j in candidates[1:]:
                sj = keeper.sessions.get(j.get("id"))
                if jar_has_auth(j) or (sj and sj.running):
                    best = j
                    break
            else:
                return
        best["last_used"] = now
        best["usage_count"] = best.get("usage_count", 0) + 1
        chosen["jar"] = best

    mutate_jars(pick)
    return chosen.get("jar")


def mark_jar_status(jar_id: str, status_type: str) -> None:
    def upd(jars: list):
        for j in jars:
            if j.get("id") == jar_id:
                if status_type == "limited":
                    j["limited_until"] = time.time() + COOLDOWN_SEC
                    j["status"] = "limited"
                    log("WARN", f"Jar '{j.get('name')}' rate-limited — cooling {COOLDOWN_SEC // 60}min")
                elif status_type == "expired":
                    j["expired"] = True
                    j["status"] = "expired"
                    log("ERROR", f"Jar '{j.get('name')}' marked EXPIRED")
                elif status_type == "ok":
                    j["expired"] = False
                    j["limited_until"] = 0
                    j["status"] = "ok"
                    log("OK", f"Jar '{j.get('name')}' reset to healthy")
    mutate_jars(upd)


def build_cookie_header(jar: dict) -> str:
    cookies = jar.get("cookies", [])
    parts = []
    known = set()
    for name_key in ["cf_clearance", "arena-auth-prod-v1.0", "arena-auth-prod-v1.1", "arena-auth-prod-v1"]:
        val = find_cookie(cookies, name_key)
        if val:
            parts.append(f"{name_key}={val}")
            known.add(name_key)
    for c in cookies:
        n = c.get("name", "")
        if n and n not in known:
            parts.append(f"{n}={c.get('value', '')}")
    return "; ".join(parts)


def build_request_headers(jar: dict) -> dict:
    cookie_header = build_cookie_header(jar)
    if not cookie_header:
        raise HTTPException(status_code=500, detail="Cookie jar is empty.")
    ua = jar.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    )
    return {
        "Content-Type": "application/json", "Cookie": cookie_header,
        "Origin": ARENA_BASE, "Referer": f"{ARENA_BASE}/text/direct",
        "User-Agent": ua, "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9",
        "sec-ch-ua": '"Chromium";v="133", "Not(A:Brand";v="99"',
        "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin",
    }


# ============================================================
# PROXY SUPPORT (per-jar or global pool — fixes IP rate-limits)
# ============================================================

def _normalize_proxy(raw: str) -> Optional[str]:
    """Normalize many common proxy string formats to a URL.

    Supported:
      http://user:pass@host:port
      socks5://user:pass@host:port
      socks4://host:port
      user:pass@host:port
      host:port:user:pass          ← common provider format
      host:port:user:pass:http    ← with scheme suffix
      host:port
    """
    if not raw or not isinstance(raw, str):
        return None
    p = raw.strip().lstrip("\ufeff").strip().strip('"\'')
    # free-proxy-list CSV rows: "IP,Port,Country,Protocol,Type,Latency,…" e.g.
    #   98.188.47.150,4145,United States,SOCKS4,Anonymous,259,Unknown,"Wed, 02 Sep 2026 …"
    if "," in p and "://" not in p and "@" not in p:
        try:
            import csv as _csv
            _row = next(_csv.reader([p]))
        except Exception:
            _row = [x.strip() for x in p.split(",")]
        if len(_row) >= 2:
            _h = str(_row[0]).strip().strip('"')
            _pt = str(_row[1]).strip().strip('"')
            if _h and _pt.isdigit() and 0 < int(_pt) <= 65535 and ":" not in _h:
                _sch = "http"
                for _cell in _row[2:]:
                    _c = str(_cell).strip().strip('"').upper()
                    if _c in ("SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5H", "HTTP", "HTTPS"):
                        _sch = _c.lower()
                        break
                return f"{_sch}://{_h}:{_pt}"
    if p.count(",") == 1 and ":" not in p:          # 'ip,port' free-list format
        p = p.replace(",", ":")
    if not p or p.startswith("#") or p.startswith("//"):
        return None
    low = p.lower()
    # bare IPv6 'ip:port' would colon-split wrong; bracket it
    _parts0 = p.rsplit(":", 1)
    if ("://" not in p and "@" not in p and len(_parts0) == 2
            and _parts0[1].isdigit() and _parts0[0].count(":") == 1):
        p = f"[{_parts0[0]}]:{_parts0[1]}"

    if low.startswith("socks5h://"):
        return "socks5://" + p.split("://", 1)[1]

    if "://" in p:
        return p  # already a URL

    # user:pass@host:port
    if "@" in p:
        return "http://" + p

    parts = p.split(":")
    # host:port:user:pass  OR  host:port:user:pass:scheme
    if len(parts) >= 4:
        host, port, user, password = parts[0], parts[1], parts[2], parts[3]
        scheme = "http"
        if len(parts) >= 5 and parts[4].lower() in ("http", "https", "socks5", "socks4", "socks5h"):
            scheme = parts[4].lower().replace("socks5h", "socks5")
        if not port.isdigit() or not (0 < int(port) <= 65535):
            return None
        return f"{scheme}://{user}:{password}@{host}:{port}"

    # host:port   (incl. bracketed IPv6 [::1]:8080)
    if len(parts) == 2 and parts[1].isdigit() and 0 < int(parts[1]) <= 65535:
        return f"http://{parts[0]}:{parts[1]}"

    return None


def get_proxy_pool() -> list:
    """Load proxies from proxies.txt (preferred) and/or config.json.

    proxies.txt (same folder as main.py), one per line:
      socks5://user:pass@host:port
      http://user:pass@host:port
      socks4://host:port
      user:pass@host:port
      host:port
    Lines starting with # are ignored.
    """
    out = []
    seen = set()

    def _add(item):
        n = _normalize_proxy(item if isinstance(item, str) else str(item))
        if not n:
            return
        try:
            from urllib.parse import urlparse as _up
            _u = _up(n)
            key = f"{_u.hostname}:{_u.port or 80}"
        except Exception:
            key = n
        if key in seen:
            return
        seen.add(key)
        seen.add(n)
        out.append(n)

    # 1) proxies.txt next to the app / cwd
    for candidate in (
        "proxies.txt",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt"),
        os.path.join(os.getcwd(), "proxies.txt"),
    ):
        try:
            if os.path.isfile(candidate):
                with open(candidate, encoding="utf-8-sig", errors="ignore") as f:  # Notepad BOM safe
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        _add(ln)
                break
        except Exception:
            pass

    # 2) config.json proxies list
    try:
        cfg = get_config()
        raw = cfg.get("proxies") or cfg.get("proxy_list") or []
        if isinstance(raw, str):
            raw = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        for item in raw:
            _add(item)
    except Exception:
        pass

    return out


_proxy_rr_index = 0

def next_pool_proxy() -> Optional[str]:
    """Next proxy in round-robin order from the pool."""
    global _proxy_rr_index
    pool = get_proxy_pool()
    if not pool:
        return None
    idx = _proxy_rr_index % len(pool)
    _proxy_rr_index = idx + 1
    return pool[idx]


def assign_jar_proxy(jar_id: str, proxy_url: str) -> None:
    """Persist proxy on the jar so curl + keeper share the same exit IP."""
    def upd(jars):
        for j in jars:
            if j.get("id") == jar_id:
                j["proxy"] = proxy_url
                j["_last_proxy"] = proxy_url
                break
    try:
        mutate_jars(upd)
    except Exception:
        pass


def jar_proxy(jar: dict, *, rotate: bool = False) -> Optional[str]:
    """Sticky proxy per account; rotate to next pool entry when rotate=True.

    Same jar → same IP so cookies/cf_clearance stay valid.
    On 429 call jar_proxy(jar, rotate=True) to move that account to a new IP.
    """
    if not jar:
        return next_pool_proxy()
    pool = get_proxy_pool()

    if rotate and pool:
        cur = _normalize_proxy(jar.get("proxy") or jar.get("_last_proxy") or jar.get("_proxy_once") or "")
        try:
            idx = pool.index(cur) if cur in pool else -1
        except Exception:
            idx = -1
        chosen = pool[(idx + 1) % len(pool)]
        jar["proxy"] = chosen
        jar["_last_proxy"] = chosen
        jar["_proxy_once"] = chosen
        if jar.get("id"):
            assign_jar_proxy(jar["id"], chosen)
        return chosen

    # Sticky: explicit proxy, else assign one from pool by jar order and persist
    explicit = jar.get("proxy") or jar.get("proxy_url") or jar.get("_last_proxy") or jar.get("_proxy_once")
    chosen = _normalize_proxy(explicit) if explicit else None
    if chosen:
        return chosen
    if not pool:
        return None
    # First time: assign stable proxy by hashing jar id, persist it
    jid = str(jar.get("id") or jar.get("name") or "x")
    idx = int(hashlib.md5(jid.encode()).hexdigest()[:8], 16) % len(pool)
    chosen = pool[idx]
    jar["proxy"] = chosen
    jar["_last_proxy"] = chosen
    if jar.get("id"):
        assign_jar_proxy(jar["id"], chosen)
    return chosen


def playwright_proxy_from_url(proxy_url: str) -> Optional[dict]:
    """Convert proxy URL to Playwright proxy dict."""
    if not proxy_url:
        return None
    try:
        from urllib.parse import urlparse
        u = urlparse(proxy_url)
        server = f"{u.scheme}://{u.hostname}"
        if u.port:
            server += f":{u.port}"
        out = {"server": server}
        if u.username:
            out["username"] = u.username
        if u.password:
            out["password"] = u.password
        return out
    except Exception:
        return None



# ============================================================
# >>> PROXY FAILOVER BEGIN  (probe-before-use for free ip:port pools) <<<
# ============================================================
PROBE_TIMEOUT = 5.0
PROBE_OK_TTL = 900.0        # reuse a confirmed-healthy verdict for 15 min
PROBE_DEAD_TTL = 300.0      # re-probe a failed proxy at most once per 5 min
PROBE_BUDGET = 40           # live probes per sweep (cached verdicts are free)
PROBE_MAX_PARALLEL = 8
_proxy_probe_cache: Dict[str, Tuple[bool, float]] = {}
_proxy_latency: Dict[str, int] = {}   # host → handshake RTT (ms)
_proxy_assign_cursor = 0   # shared round-robin position for ALL pinning paths

# Upstream-degradation cooldown: when Arena's own origin is down (Cloudflare 520-527),
# every in-flight request must not spin its 6-retry budget against a dead backend.
# A single blip must NOT trip this (one slow 504 amid healthy traffic is normal):
# the gate opens only after UPSTREAM_DEGRADE_THRESHOLD hits within the window.
_upstream_degraded_until = 0.0
_upstream_hits: List[float] = []
UPSTREAM_DEGRADE_COOLDOWN = 45.0
UPSTREAM_DEGRADE_WINDOW = 60.0
UPSTREAM_DEGRADE_THRESHOLD = 3


def note_upstream_degraded(reason: str = "") -> None:
    global _upstream_degraded_until
    now = time.time()
    _upstream_hits[:] = [t for t in _upstream_hits if now - t < UPSTREAM_DEGRADE_WINDOW]
    _upstream_hits.append(now)
    if len(_upstream_hits) >= UPSTREAM_DEGRADE_THRESHOLD:
        new_until = now + UPSTREAM_DEGRADE_COOLDOWN
        if new_until > _upstream_degraded_until:
            _upstream_degraded_until = new_until
            log("WARN", f"Arena origin degraded ({len(_upstream_hits)}× 5xx/52x in "
                        f"{UPSTREAM_DEGRADE_WINDOW:.0f}s) — pausing new requests ~"
                        f"{UPSTREAM_DEGRADE_COOLDOWN:.0f}s; accounts & proxies stay healthy")


def upstream_degraded() -> Tuple[bool, float]:
    remaining = _upstream_degraded_until - time.time()
    return (remaining > 0, max(0.0, remaining))


def _rotation_mode() -> str:
    """config.json "proxy_rotation": "assignment" (default, CF-safe) | "request".
    "request" rotates the exit on EVERY pick — maximum IP spread, but it invalidates
    cf_clearance each time and the keeper must re-clear (up to one ~1-min cycle per
    request). Only flip it if Arena is IP-limiting you harder than CF is."""
    try:
        m = str(get_config().get("proxy_rotation") or "assignment").strip().lower()
        return m if m in ("assignment", "request") else "assignment"
    except Exception:
        return "assignment"


def _bump_cursor(chosen: Optional[str]) -> None:
    """Park the shared cursor just after the node we handed out, so the NEXT
    assignment (any jar, curl or keeper) lands on a different proxy. 1:1 spread,
    no md5 collisions, wraps around the pool."""
    global _proxy_assign_cursor
    if not chosen:
        return
    try:
        pool = get_proxy_pool()
        _proxy_assign_cursor = (pool.index(chosen) + 1) % len(pool) if chosen in pool else _proxy_assign_cursor + 1
    except Exception:
        _proxy_assign_cursor += 1


def _probe_hostport() -> Tuple[str, int]:
    try:
        from urllib.parse import urlparse
        u = urlparse(ARENA_BASE)
        return (u.hostname or "arena.ai"), (u.port or 443)
    except Exception:
        return "arena.ai", 443


def _socks_client_handshake(s, scheme: str, host: str, port: int, u) -> bool:
    """SOCKS4/4a/5 client handshake through an already-connected socket."""
    import socket as _sk
    import struct as _st
    from urllib.parse import unquote as _unq
    try:
        if scheme in ("socks4", "socks4a"):
            if scheme == "socks4":
                try:
                    addr = _sk.inet_aton(_sk.gethostbyname(host))     # client-side DNS
                except Exception:
                    return False
            else:
                addr = b"\x00\x00\x00\x01"                          # socks4a: resolve remotely
            user = (_unq(u.username) if u.username else "bridgena").encode("utf-8", "ignore")[:255]
            s.sendall(b"\x04\x01" + _st.pack(">H", port) + addr + user + b"\x00")
            resp = s.recv(8)
            return len(resp) == 8 and resp[0] == 0x00 and resp[1] == 0x5A
        # socks5(h): no-auth method, then IPv4 CONNECT
        s.sendall(b"\x05\x01\x00")
        g = s.recv(2)
        if len(g) < 2 or g[0] != 0x05 or g[1] != 0x00:
            return False
        try:
            ip = _sk.inet_aton(_sk.gethostbyname(host))
        except Exception:
            return False
        s.sendall(b"\x05\x01\x00\x01" + ip + _st.pack(">H", port))
        r = s.recv(4)
        return len(r) >= 4 and r[0] == 0x05 and r[1] == 0x00
    except Exception:
        return False


def _proxy_probe(proxy_url: str, timeout: float = PROBE_TIMEOUT) -> Tuple[bool, int]:
    """(alive, latency_ms) — a REAL handshake per scheme: http/https via CONNECT,
    socks4/4a/5 via native SOCKS4/SOCKS5 connect to arena.ai:443. No more blanket
    'trust socks' — free-list socks nodes are dead more often than not."""
    import base64
    import socket
    from urllib.parse import unquote, urlparse
    if not proxy_url:
        return False, -1
    t0 = time.perf_counter()
    host, port = _probe_hostport()
    try:
        u = urlparse(proxy_url if "://" in proxy_url else "http://" + proxy_url)
        scheme = (u.scheme or "http").lower()
        ph, pp = u.hostname, (u.port or 80)
        s = socket.create_connection((ph, pp), timeout=timeout)
        s.settimeout(timeout)
        try:
            if scheme in ("socks4", "socks4a", "socks5", "socks5h"):
                if not _socks_client_handshake(s, scheme, host, port, u):
                    return False, -1
            else:
                req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                if u.username:
                    pw = unquote(u.password or "")
                    tok = base64.b64encode(f"{unquote(u.username)}:{pw}".encode()).decode()
                    req += f"Proxy-Authorization: Basic {tok}\r\n"
                s.sendall((req + "\r\n").encode())
                buf = b""
                while b"\r\n\r\n" not in buf:
                    c = s.recv(2048)
                    if not c:
                        return False, -1
                    buf += c
                    if len(buf) > 16384:
                        return False, -1
                line = buf.split(b"\r\n", 1)[0].decode("latin1", "ignore")
                m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
                if not m or m.group(1) != "200":
                    code = m.group(1) if m else "?"
                    hint = " — PAYMENT REQUIRED (provider billing/quota)" if code == "402" else \
                           (" — auth failed (creds/allowlist)" if code == "407" else "")
                    log("WARN", f"proxy probe {ph}:{pp} refused CONNECT: {code}{hint}")
                    if code in ("402", "407"):
                        quarantine_proxy(proxy_url, f"CONNECT refused {code} — billing/auth, not transient")
                    return False, -1
        finally:
            try:
                s.close()
            except Exception:
                pass
        return True, int((time.perf_counter() - t0) * 1000)
    except Exception:
        return False, -1


def _proxy_tcp_probe(proxy_url: str, timeout: float = PROBE_TIMEOUT) -> bool:
    """Back-compat bool wrapper used by the picker."""
    return _proxy_probe(proxy_url, timeout)[0]


def proxy_alive(proxy_url: str, *, force: bool = False) -> bool:
    """Cached health verdict for a proxy (probe on miss)."""
    if not proxy_url:
        return False
    now = time.time()
    hit = _proxy_probe_cache.get(proxy_url)
    if hit and hit[1] > now and not force:
        return hit[0]
    ok, lat = _proxy_probe(proxy_url)
    if ok and lat >= 0:
        _proxy_latency[proxy_url] = lat
    else:
        _proxy_latency.pop(proxy_url, None)
    _proxy_probe_cache[proxy_url] = (ok, now + (PROBE_OK_TTL if ok else PROBE_DEAD_TTL))
    if ok:
        _proxy_strikes.pop(proxy_url, None)
    else:
        note_probe_failure(proxy_url)
    return ok


def mark_proxy_dead(proxy_url: str, ttl: float = PROBE_DEAD_TTL) -> None:
    if proxy_url:
        _proxy_probe_cache[proxy_url] = (False, time.time() + ttl)
        _bump_cursor(_normalize_proxy(proxy_url))  # skip dead node in future assignments

# ---- v5 QUARANTINE: a proxy that actually fails is REMOVED from proxies.txt ----
# (line moved to proxies.dead.txt, never offered again this service lifetime),
# instead of the 5-min TTL slap on the wrist. 402/407 or any runtime tunnel
# failure = instant exile; repeated raw-probe misses exile after 2 strikes.
# Kill switch: PROXY_QUARANTINE=0.  Revive:  grep -v '^#' proxies.dead.txt >> proxies.txt
PROXY_QUARANTINE   = os.environ.get("PROXY_QUARANTINE", "1").strip().lower() not in ("0", "off", "false")
PROBE_EXILE_AFTER  = 2
CURL_TTFB_TIMEOUT  = float(os.environ.get("CURL_TTFB_TIMEOUT", "45"))  # headers must arrive in 45s
_quarantine_lock   = __import__("threading").RLock()
_proxy_strikes: Dict[str, int] = {}
_QUARANTINED_KEYS: set = set()   # host:port — this process


def _proxies_file() -> Optional[str]:
    for candidate in ("proxies.txt",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt"),
                      os.path.join(os.getcwd(), "proxies.txt")):
        if os.path.isfile(candidate):
            return candidate
    return None


def _proxy_hkey(proxy_url: str) -> str:
    try:
        from urllib.parse import urlparse as _up
        u = _up(_normalize_proxy(proxy_url) or proxy_url)
        return f"{u.hostname}:{u.port or 80}"
    except Exception:
        return proxy_url


def quarantine_proxy(proxy_url: str, reason: str = "") -> None:
    """Exile a proxy: cut its line(s) from proxies.txt, append to proxies.dead.txt,
    clear every sticky pin pointing at it. Idempotent per process; thread-safe."""
    if not proxy_url:
        return
    if not PROXY_QUARANTINE:
        mark_proxy_dead(proxy_url)
        return
    key = _proxy_hkey(proxy_url)
    with _quarantine_lock:
        if key in _QUARANTINED_KEYS:
            mark_proxy_dead(proxy_url, ttl=3600.0)
            return
        _QUARANTINED_KEYS.add(key)
        moved = 0
        path = _proxies_file()
        try:
            if path:
                keep_lines, moved_lines = [], []
                with open(path, encoding="utf-8-sig", errors="ignore") as f:
                    for ln in f:
                        raw = ln.strip()
                        if raw and not raw.startswith("#") and _proxy_hkey(raw) == key:
                            moved_lines.append(raw)
                        else:
                            keep_lines.append(ln.rstrip("\n"))
                if moved_lines:
                    tmp = path + ".quarantine.tmp"
                    with open(tmp, "w", encoding="utf-8") as f:
                        f.write("\n".join(keep_lines) + ("\n" if keep_lines else ""))
                    os.replace(tmp, path)
                    dead = os.path.join(os.path.dirname(path) or ".", "proxies.dead.txt")
                    with open(dead, "a", encoding="utf-8") as f:
                        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        for ml in moved_lines:
                            f.write(f"# {stamp} {reason[:120]}\n{ml}\n")
                    moved = len(moved_lines)
        except Exception as e:
            log("WARN", f"proxies.txt quarantine write failed ({e}) — TTL-marking only")
        mark_proxy_dead(proxy_url, ttl=86400.0)
        try:
            def _unpin(jars):
                for j in jars:
                    for fld in ("proxy", "proxy_url", "_last_proxy", "_proxy_once"):
                        if j.get(fld) and _proxy_hkey(j[fld]) == key:
                            j[fld] = ""
            mutate_jars(_unpin)
        except Exception:
            pass
    log("WARN", f"proxy {key} QUARANTINED ({moved} line(s) → proxies.dead.txt): "
                f"{reason[:140]} — pool now {len(get_proxy_pool())}")


def note_probe_failure(proxy_url: str) -> None:
    if not PROXY_QUARANTINE or not proxy_url:
        return
    n = _proxy_strikes[proxy_url] = _proxy_strikes.get(proxy_url, 0) + 1
    if n >= PROBE_EXILE_AFTER:
        quarantine_proxy(proxy_url, f"CONNECT probe failed {n}× in a row")


# ---- v6 PROXY MANAGER: upload/paste parsers, health store, bulk prune ----
PROXY_HEALTH_FILE = "proxies.health.json"
_proxy_health: Dict[str, dict] = {}       # host:port → {ok, latency, checked, source}
_proxy_health_loaded = False
_proxy_check_state = {"running": False, "done": 0, "total": 0, "started": 0.0}


def _proxy_health_path() -> str:
    base = _proxies_file()
    d = os.path.dirname(os.path.abspath(base)) if base else os.getcwd()
    return os.path.join(d, PROXY_HEALTH_FILE)


def _proxy_health_load(force: bool = False) -> Dict[str, dict]:
    global _proxy_health_loaded
    if _proxy_health_loaded and not force:
        return _proxy_health
    _proxy_health_loaded = True
    try:
        with open(_proxy_health_path(), encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in (data.items()):
                if isinstance(v, dict):
                    _proxy_health[str(k)] = v
    except Exception:
        pass
    return _proxy_health


def _proxy_health_save() -> None:
    try:
        tmp = _proxy_health_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_proxy_health, f, indent=1, sort_keys=True)
        os.replace(tmp, _proxy_health_path())
    except Exception:
        pass


def _proxy_health_record(proxy_url: str, ok: bool, latency_ms: int, source: str = "probe") -> None:
    _proxy_health_load()
    key = _proxy_hkey(proxy_url)
    prev = _proxy_health.get(key) or {}
    _proxy_health[key] = {
        "ok": bool(ok),
        "latency": int(latency_ms) if (ok and latency_ms >= 0) else prev.get("latency"),
        "checked": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "fails": (int(prev.get("fails") or 0) + (0 if ok else 1)),
    }
    _proxy_health_save()


# A proxy can tunnel fine and STILL be useless: Arena's Cloudflare flags datacenter
# exits. Those get a temporary flag (skip in picks) instead of exile — the IP may be
# fine tomorrow. TTL: PROXY_FLAG_TTL seconds (default 3h).
_FLAGGED_TTL = float(os.environ.get("PROXY_FLAG_TTL", "10800"))
_flagged_exits: Dict[str, float] = {}      # host:port → expiry


def _flagged_active() -> set:
    now = time.time()
    dead = [k for k, exp in _flagged_exits.items() if exp <= now]
    for k in dead:
        _flagged_exits.pop(k, None)
    return {k for k, exp in _flagged_exits.items() if exp > now}


def note_cf_blocked_exit(proxy_url: str, reason: str = "") -> None:
    """Mark an exit as CF-flagged for Arena: skip it in picks + record in health file."""
    if not proxy_url:
        return
    key = _proxy_hkey(proxy_url)
    if not key:
        return
    _flagged_exits[key] = time.time() + _FLAGGED_TTL
    _proxy_health_load()
    h = _proxy_health.setdefault(key, {})
    h["arena"] = "blocked"
    h["blocked_reason"] = (reason or "cf-challenge")[:120]
    h["checked"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _proxy_health_save()
    log("WARN", f"exit {key} flagged as Arena-blocked (skipped {_FLAGGED_TTL/3600:.0f}h): {reason[:100]}")


def parse_proxy_blob(text: str) -> Tuple[List[str], int, int]:
    """Any paste/file: CSV free-lists, ip:port, user:pass@host:port, schemes.
    Returns (normalized urls, lines parsed, lines skipped)."""
    out, seen, parsed, skipped = [], set(), 0, 0
    for raw in (text or "").splitlines():
        ln = raw.strip().lstrip("\ufeff")
        if not ln or ln.startswith("#"):
            continue
        low = ln.lower()
        if low.startswith(("ip,port", "ip:port", "proxylist", "http://ip")) or "," in low[:8] and low[:2].isalpha() and "ip" in low.split(",")[0].lower():
            if "port" in low or "ip" in low.split(",")[0]:
                continue  # header row
        parsed += 1
        n = _normalize_proxy(ln)
        if not n:
            skipped += 1
            continue
        k = _proxy_hkey(n)
        if k in seen or not k or k == ":0":
            skipped += 1
            continue
        seen.add(k)
        out.append(n)
    return out, parsed, skipped


def _proxies_pool_write(urls: List[str]) -> None:
    """Atomic replace of the whole proxies.txt (dedup preserved order)."""
    path = _proxies_file() or os.path.join(os.getcwd(), "proxies.txt")
    tmp = path + ".manager.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u + "\n")
    os.replace(tmp, path)


def proxies_snapshot() -> List[dict]:
    _proxy_health_load()
    now = time.time()
    rows = []
    for u in get_proxy_pool():
        key = _proxy_hkey(u)
        verdict, lat = None, None
        hit = _proxy_probe_cache.get(u)
        if hit and hit[1] > now:
            verdict = bool(hit[0])
        lat = _proxy_latency.get(u)
        h = _proxy_health.get(key) or {}
        if verdict is None and "ok" in h:
            verdict = bool(h["ok"])
            lat = lat if lat is not None else h.get("latency")
        blocked = (h.get("arena") == "blocked") or (key in _flagged_active())
        st = ("blocked" if (verdict and blocked) else ("live" if verdict else "dead")) if verdict is not None else "unchecked"
        rows.append({
            "url": u, "host": key,
            "scheme": u.split("://", 1)[0] if "://" in u else "http",
            "status": st,
            "note": (h.get("blocked_reason") or "")[:60] if st == "blocked" else "",
            "latency": lat,
            "checked": h.get("checked") or "",
            "fails": int(h.get("fails") or 0),
        })
    rows.sort(key=lambda r: ({"live": 0, "unchecked": 1, "blocked": 2, "dead": 3}[r["status"]],
                             r["latency"] if isinstance(r["latency"], int) else 10**9))
    return rows


def arena_reachable(proxy_url: Optional[str], timeout: float = 12.0) -> Tuple[bool, int, str]:
    """The verdict that matters: can THIS exit actually load arena.ai like a Chrome
    would? Tunnels lie — a CONNECT-200 proxy can still stare at a Cloudflare
    challenge. curl_cffi (same impersonation as the chat path) GETs the homepage:
    200/429/404 = usable · challenge-403/503 = flagged · exception = unreachable."""
    try:
        from curl_cffi import requests as _rq
        kw = dict(impersonate="chrome131", timeout=timeout, allow_redirects=True,
                  headers={"Accept-Language": "en-US,en;q=0.9"})
        if proxy_url:
            kw["proxy"] = proxy_url
        r = _rq.get(ARENA_BASE + "/", **kw)
        body = (r.text or "")[:4096].lower()
        challenge = ("just a moment" in body or "attention required" in body
                     or "cf_chl" in body or "turnstile" in body
                     or ("cloudflare" in body and "challenge" in body))
        if challenge:
            return False, r.status_code, "cf-challenge"
        if r.status_code in (403, 503):
            return False, r.status_code, f"http {r.status_code}"
        return True, r.status_code, ""
    except Exception as e:
        return False, 0, str(e)[:100]


def _proxy_run_check() -> int:
    """Parallel sweep: real handshake (alive? fast?) + Arena reachability
    (can it load arena.ai as Chrome?). Blocked exits get CF-flagged too, so the
    picker skips them immediately. Returns #usable."""
    pool = get_proxy_pool()
    from concurrent.futures import ThreadPoolExecutor
    good = 0
    def one(p: str):
        return _proxy_probe(p, 6.0)
    with ThreadPoolExecutor(max_workers=min(32, max(4, len(pool)))) as ex:
        for u, (ok, lat) in zip(pool, ex.map(one, pool)):
            if ok and lat >= 0:
                _proxy_latency[u] = lat
            else:
                _proxy_latency.pop(u, None)
            _proxy_probe_cache[u] = (ok, time.time() + (PROBE_OK_TTL if ok else 30.0))
            _proxy_health_record(u, ok, lat)
            arena = None
            if ok:
                a_ok, a_st, a_note = arena_reachable(u)
                arena = "ok" if a_ok else "blocked"
                _proxy_health_load()
                h = _proxy_health.setdefault(_proxy_hkey(u), {})
                h["arena"] = arena
                h["arena_status"] = a_st
                if a_ok:
                    # healed: a clean scan wipes the block record + runtime flag
                    h.pop("blocked_reason", None)
                    _flagged_exits.pop(_proxy_hkey(u), None)
                else:
                    h["blocked_reason"] = a_note
                    _flagged_exits[_proxy_hkey(u)] = time.time() + _FLAGGED_TTL
                _proxy_health_save()
            if not ok:
                note_probe_failure(u)   # strike bookkeeping; 2 strikes → exile
            _proxy_check_state["done"] += 1
            good += 1 if (ok and arena == "ok") else 0
            _proxy_check_state["live"] = good
    return good


async def proxy_check_start() -> bool:
    """Kick a background sweep (one at a time)."""
    if _proxy_check_state["running"]:
        return False
    _proxy_check_state.update(running=True, done=0, live=0, total=len(get_proxy_pool()), started=time.time())
    def _job():
        try:
            live = _proxy_run_check()
            log("OK", f"proxy sweep done: {live}/{_proxy_check_state['total']} usable against Arena "
                      f"(tunnel-dead nodes got strikes; Arena-blocked exits flagged ~3h)")
        except Exception as e:
            log("WARN", f"proxy sweep crashed: {e}")
        finally:
            _proxy_check_state["running"] = False
    asyncio.ensure_future(asyncio.to_thread(_job))
    return True


def proxy_prune(mode: str, slow_ms: int = 1000) -> int:
    """mode: 'dead' | 'slow' | 'unchecked' | 'all' — cut rows from proxies.txt
    (append to proxies.dead.txt so nothing is unrecoverable)."""
    _proxy_health_load()
    now = time.time()
    pool = get_proxy_pool()

    def state_of(u):
        hit = _proxy_probe_cache.get(u)
        st = None
        if hit and hit[1] > now:
            st = "live" if hit[0] else "dead"
        else:
            h = _proxy_health.get(_proxy_hkey(u)) or {}
            if "ok" not in h:
                st = "unchecked"
            else:
                st = "live" if h.get("ok") else "dead"
        h2 = _proxy_health.get(_proxy_hkey(u)) or {}
        if st == "live" and (h2.get("arena") == "blocked" or _proxy_hkey(u) in _flagged_active()):
            st = "blocked"
        return st

    def lat_of(u):
        return _proxy_latency.get(u) or (_proxy_health.get(_proxy_hkey(u)) or {}).get("latency")

    keep: List[str] = []
    removed: List[str] = []
    for u in pool:
        st = state_of(u)
        if (mode == "all" or st == mode
                or (mode == "bad" and st in ("dead", "blocked"))
                or (mode == "slow" and isinstance(lat_of(u), int) and lat_of(u) > slow_ms)):
            removed.append(u)
        else:
            keep.append(u)
    if not removed:
        return 0
    dead_path = os.path.join(os.path.dirname(_proxies_file() or os.path.join(os.getcwd(), "x")), "proxies.dead.txt")
    try:
        with open(dead_path, "a", encoding="utf-8") as f:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            for u in removed:
                f.write(f"# {stamp} pruned:{mode}\n{u}\n")
    except Exception:
        pass
    _proxies_pool_write(keep)
    for u in removed:
        _QUARANTINED_KEYS.add(_proxy_hkey(u))
        _proxy_probe_cache[u] = (False, time.time() + 86400.0)
        _proxy_latency.pop(u, None)
    log("OK", f"proxy prune '{mode}': {len(removed)} cut from proxies.txt (kept {len(keep)})")
    return len(removed)


def proxies_revive_all() -> int:
    """Append everything from proxies.dead.txt back into the pool (dedup)."""
    base = _proxies_file() or os.path.join(os.getcwd(), "proxies.txt")
    dead_path = os.path.join(os.path.dirname(os.path.abspath(base)), "proxies.dead.txt")
    if not os.path.isfile(dead_path):
        return 0
    pool = get_proxy_pool()
    have = {_proxy_hkey(u) for u in pool}
    revived = []
    with open(dead_path, encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            n = _normalize_proxy(ln)
            k = _proxy_hkey(n) if n else ""
            if n and k not in have:
                have.add(k)
                revived.append(n)
    if revived:
        _proxies_pool_write(pool + revived)
        for n in revived:
            _QUARANTINED_KEYS.discard(_proxy_hkey(n))
            _proxy_probe_cache.pop(n, None)
        open(dead_path, "w").close()   # graveyard emptied — entries are back in play
    log("OK", f"proxy revive: {len(revived)} moved back from proxies.dead.txt")
    return len(revived)


def proxy_candidates(jar: Optional[dict], *, prefer_sticky: bool = True,
                     include_flagged: bool = False) -> List[str]:
    """Sweep order: the jar's live pin first (keeps cf_clearance valid), then the
    pool starting at the shared RR cursor. The old per-jar md5 offset collided
    (2 accounts on the same slot, pool entries left idle) — the cursor can't:
    every hand-out advances it exactly one step.
    include_flagged=True is the LAST-RESORT view: CF flags are fluid (a challenge
    now ≠ a challenge in 30s), so when nothing un-flagged remains we still rotate
    over flagged exits instead of surrendering to the direct server IP. Quarantined
    (tunnel-dead) nodes are NEVER re-admitted."""
    _q = _QUARANTINED_KEYS | (set() if include_flagged else _flagged_active())
    pool = [p for p in get_proxy_pool() if _proxy_hkey(p) not in _q]
    out: List[str] = []
    if prefer_sticky and not include_flagged:
        sticky = _normalize_proxy((jar or {}).get("proxy") or (jar or {}).get("_last_proxy") or "")
        # an exiled/flagged node must never come back via a stale jar pin
        if sticky and _proxy_hkey(sticky) not in _q:
            out.append(sticky)
    if pool:
        st = _proxy_assign_cursor % len(pool)
        ordered = [pool[(st + i) % len(pool)] for i in range(len(pool))]
        # speed-first: a freshly measured latency (from sweeps AND from real
        # streamed answers) floats that exit to the front; stable sort keeps
        # RR fairness among the ones we've never timed.
        def _k(u):
            lat = _proxy_latency.get(u)
            return (1, 0) if not isinstance(lat, int) or lat <= 0 else (0, lat)
        for c in sorted(ordered, key=_k):
            if c not in out:
                out.append(c)
    return out


def pick_live_proxy(jar: Optional[dict], *, purpose: str = "", rotate: bool = False,
                    exclude=None) -> Optional[str]:
    """Return the first proxy that actually tunnels to Arena and PIN it to the
    jar (so curl + keeper keep one exit IP). None = nothing tunnels -> go direct.
    Dead nodes cost one probe per PROBE_DEAD_TTL, not per request.
    rotate=True (429 / death / provider swap): ignore the current pin, take the
    next live entry at the shared cursor. mode="request": same for EVERY call."""
    global _proxy_assign_cursor
    mode = _rotation_mode()
    if mode == "request" and get_proxy_pool():
        _proxy_assign_cursor += 1
    cands = proxy_candidates(jar, prefer_sticky=(mode != "request" and not rotate))
    if exclude:
        cands = [c for c in cands if c not in exclude]
    if not cands:
        # everything left is CF-flagged. Going DIRECT means our datacenter server
        # IP — a far worse bet than a recently-blocked exit. One last-resort
        # rotation over the flagged ones (cursor still advances, so each attempt
        # is a different exit; any 200 we get lifts that exit's flag outright).
        cands = proxy_candidates(jar, prefer_sticky=False, include_flagged=True)
        if exclude:
            cands = [c for c in cands if c not in exclude]
        if cands:
            log("WARN", "proxy pool fully CF-flagged — last-resort rotation over flagged exits "
                        "(blocks are fluid; a delivered 200 clears the flag immediately)")
    if not cands:
        return None
    chosen = None
    try:
        from concurrent.futures import ThreadPoolExecutor
        batch = cands[:PROBE_BUDGET]
        # cheap pass: anything with a live 'ok' cache entry wins immediately, in priority order
        now = time.time()
        for c in cands:
            hit = _proxy_probe_cache.get(c)
            if hit and hit[1] > now and hit[0]:
                chosen = c
                break
        if chosen is None:
            with ThreadPoolExecutor(max_workers=min(PROBE_MAX_PARALLEL, max(1, len(batch)))) as ex:
                results = list(ex.map(lambda c: proxy_alive(c), batch))
            for c, ok in zip(batch, results):
                if ok:
                    chosen = c
                    break
            # candidates beyond the budget with a cached-ok verdict still win over nothing
            if chosen is None:
                for c in cands[PROBE_BUDGET:]:
                    hit = _proxy_probe_cache.get(c)
                    if hit and hit[1] > now and hit[0]:
                        chosen = c
                        break
    except Exception as e:
        log("WARN", f"proxy sweep failed ({e}) — trusting sticky/pool head")
        chosen = cands[0]
    jid = (jar or {}).get("id")
    if chosen:
        if jar is not None:
            jar["proxy"] = chosen
            jar["_last_proxy"] = chosen
            if jid:
                assign_jar_proxy(jid, chosen)
        _bump_cursor(chosen)   # next assignment (any jar) gets a different node
        return chosen
    if get_proxy_pool():
        log("WARN", f"[{jid or 'global'}] {len(cands)} proxy candidates probed, none tunnel to Arena "
                    f"({purpose or 'use'}) — direct egress; pinned sticky kept in case provider revives")
    return None


def _ttfb_budget(proxy: Optional[str]) -> float:
    """Adaptive first-byte budget. A stalled exit used to eat the full 45s watchdog
    on EVERY attempt (6 attempts = nearly 5 minutes of nothing). If we have a latency
    sample for this exit, its timeout scales with what it actually does when healthy;
    unknown exits still get the full budget."""
    if not proxy:
        return CURL_TTFB_TIMEOUT
    lat = _proxy_latency.get(proxy)
    if not isinstance(lat, int) or lat <= 0:
        lat = (_proxy_health.get(_proxy_hkey(proxy)) or {}).get("latency")
    if not isinstance(lat, int) or lat <= 0:
        return CURL_TTFB_TIMEOUT
    return max(12.0, min(CURL_TTFB_TIMEOUT, 3.0 + lat * 8 / 1000.0))


async def apick_live_proxy(jar: Optional[dict], *, purpose: str = "", rotate: bool = False,
                           exclude=None) -> Optional[str]:
    return await asyncio.to_thread(pick_live_proxy, jar, purpose=purpose, rotate=rotate, exclude=exclude)


async def anchor_proxy_to_keeper(jar_id, proxy):
    """Return (proxy, cycled). Align curl with the running keeper's exit IP, because
    cf_clearance is IP-bound: prefer the browser's live exit (re-pin curl to it and the
    clearance survives); only if that exit is DEAD do we cycle the keeper onto curl's new
    proxy, which re-solves the challenge there and re-harvests cookies."""
    if _rotation_mode() == "request":
        return proxy, False   # per-request rotation is intentional exit churn; don't drag curl back
    s = keeper.sessions.get(jar_id) if jar_id else None
    if not (s and getattr(s, "running", False)):
        return proxy, False
    used = getattr(s, "_used_proxy", "") or ""
    if not used or used == proxy:
        return proxy, False
    if _proxy_hkey(used) in _flagged_active():
        return proxy, False   # keeper rides a CF-flagged exit — do NOT pin curl onto it
    if await asyncio.to_thread(proxy_alive, used):
        if jar_id:
            assign_jar_proxy(jar_id, used)   # curl follows the browser; don't disturb the clearance
        return used, False
    if proxy is None:
        return None, False   # nothing healthy anywhere — direct; browser tunnel may still linger
    log("WARN", f"[{jar_id}] keeper's proxy {used.split('@')[-1]} is dead — cycling keeper onto "
                f"{proxy.split('@')[-1]} to realign IP+cookies")
    try:
        await s.restart()
        s.last_harvest_time = 0
    except Exception as e:
        log("WARN", f"[{jar_id}] keeper cycle failed: {e}")
    return proxy, True

# <<< PROXY FAILOVER END >>>


# ============================================================
# STATE HELPERS & METRICS
# ============================================================

def block_model(name: str) -> None:
    def fn(state: dict):
        if name not in state["blocked_models"]:
            state["blocked_models"].append(name)
            log("WARN", f"Model '{name}' hidden — gated on this account")
    mutate_state(fn)


def record_usage(model_name: str) -> None:
    try:
        def fn(state: dict):
            state["usage_stats"][model_name] = state["usage_stats"].get(model_name, 0) + 1
        mutate_state(fn)
    except Exception as e:
        log("WARN", f"Usage record failed: {e}")


def check_rate_limit(api_key_str: str, rpm: int) -> dict:
    now = time.time()
    result = {"ok": True, "retry": 0}
    def fn(state: dict):
        bucket = [t for t in state["rate_buckets"].get(api_key_str, []) if now - t < 60]
        if len(bucket) >= rpm:
            result["ok"] = False
            result["retry"] = max(1, int(60 - (now - min(bucket))))
        else:
            bucket.append(now)
            state["rate_buckets"][api_key_str] = bucket[-(rpm + 5):]
    mutate_state(fn)
    return result


# ============================================================
# CONVERSATION STATE & HISTORY
# ============================================================

def get_conversation(key: str) -> dict:
    state = load_state()
    conv = state.get("conversations", {}).get(key)
    if conv is None:
        conv = {}
    if "arena_id" in conv:
        old_model = conv.get("model") or "__legacy__"
        conv = {
            "arena": {old_model: {"arena_id": conv["arena_id"], "mode": conv.get("mode", "direct-battle")}},
            "model": conv.get("model"), "history": [], "user_count": 0,
        }
    conv.setdefault("arena", {})
    conv.setdefault("model", None)
    conv.setdefault("history", [])
    conv.setdefault("user_count", 0)
    conv.setdefault("compact_cache", {})
    return conv


def save_conversation(key: str, conv: dict) -> None:
    conv["updated"] = time.time()
    def fn(state: dict):
        state["conversations"][key] = conv
        if len(state["conversations"]) > MAX_CONVERSATIONS:
            items = sorted(state["conversations"].items(), key=lambda kv: kv[1].get("updated", 0))
            for k, _ in items[:len(items) - MAX_CONVERSATIONS]:
                state["conversations"].pop(k, None)
    try:
        mutate_state(fn)
    except Exception as e:
        log("WARN", f"Conversation save failed: {e}")


# ============================================================
# OX ALPHA INTEGRATION
# ============================================================

def oxalpha_models() -> list:
    return [
        {"id": OX_MODEL_ID, "publicName": "glm-5.3-flash", "organization": "Zhipu AI (via OX Alpha)",
         "owned_by": "oxalpha", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
        {"id": "ox-alpha", "publicName": "ox-alpha", "organization": "OX Alpha Direct",
         "owned_by": "oxalpha", "capabilities": {"inputCapabilities": {"image": False, "text": True}, "outputCapabilities": {"text": True}}},
    ]


def load_oxalpha_cookies() -> list:
    try:
        with open(OX_COOKIES_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def load_oxalpha_session() -> dict:
    try:
        with open(OX_SESSION_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_oxalpha_session(sess: dict) -> None:
    atomic_write(OX_SESSION_FILE, sess)


async def oxas(force: bool = False) -> dict:
    sess = load_oxalpha_session()
    now = time.time()
    if not force and sess.get("token") and (now - sess.get("updated", 0) < OX_SESSION_TTL):
        return sess
    cookies = load_oxalpha_cookies()
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Accept": "*/*", "Origin": OX_BASE, "Referer": f"{OX_BASE}/", "Cookie": cookie_str,
    }
    new_sess = {"headers": headers, "token": "valid" if cookie_str else None, "updated": now}
    save_oxalpha_session(new_sess)
    return new_sess


async def oxalpha_verify_via_browser() -> dict:
    if AsyncCamoufox is None:
        log("ERROR", "Camoufox is required for OX Alpha browser verification")
        return {}
    try:
        async with AsyncCamoufox(headless=True, humanize=False) as browser:
            page = await browser.new_page()
            existing = load_oxalpha_cookies()
            if existing:
                try:
                    await page.context.add_cookies(to_playwright_cookies(existing))
                except Exception:
                    pass
            await page.goto(f"{OX_BASE}/", wait_until="domcontentloaded")
            await asyncio.sleep(5)
            cookies = await page.context.cookies()
            simplified = [
                {"name": c["name"], "value": c["value"], "domain": c.get("domain", ""), "path": c.get("path", "/")}
                for c in cookies if c.get("name")
            ]
            atomic_write(OX_COOKIES_FILE, simplified)
            sess = {"cookies": simplified, "updated": time.time(), "token": "browser_verified"}
            save_oxalpha_session(sess)
            log("OK", f"OX Alpha verification complete ({len(simplified)} cookies)")
            return sess
    except Exception as e:
        log("ERROR", f"OX Alpha verification failed: {e}")
        return {}


async def stream_oxalpha(messages: list, model: str = OX_UPSTREAM_MODEL):
    await oxas()
    cookies = load_oxalpha_cookies()
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        "Origin": OX_BASE, "Referer": f"{OX_BASE}/", "Cookie": cookie_str,
    }
    payload = {"model": OX_UPSTREAM_MODEL, "messages": messages, "stream": True}
    url = f"{OX_BASE}{OX_ENDPOINT}"
    async with AsyncSession(impersonate="chrome131") as client:
        try:
            resp = await client.post(url, json=payload, headers=headers, stream=True, timeout=90.0)
            if resp.status_code != 200:
                body = resp.content if getattr(resp, "content", None) is not None else b""
                err_text = body.decode("utf-8", errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
                yield ("error", f"OX Alpha returned HTTP {resp.status_code}: {err_text[:200]}")
                return
            in_think = False
            buffer = b""
            async for chunk in resp.aiter_content(chunk_size=1024):
                if not chunk: continue
                buffer += chunk
                while b"\n" in buffer:
                    line_bytes, buffer = buffer.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    if line.startswith("data: "):
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            data_json = json.loads(data_str)
                            choice = data_json.get("choices", [{}])[0]
                            delta = choice.get("delta", {})
                            content_delta = delta.get("content", "")
                            reasoning = delta.get("reasoning_content", "")
                            if reasoning:
                                yield ("reasoning", reasoning)
                            if content_delta:
                                if "<think>" in content_delta:
                                    in_think = True
                                    parts = content_delta.split("<think>", 1)
                                    if parts[0]:
                                        yield ("content", parts[0])
                                    content_delta = parts[1]
                                if in_think and "</think>" in content_delta:
                                    in_think = False
                                    parts = content_delta.split("</think>", 1)
                                    if parts[0]:
                                        yield ("reasoning", parts[0])
                                    if parts[1]:
                                        yield ("content", parts[1])
                                    continue
                                if in_think:
                                    yield ("reasoning", content_delta)
                                else:
                                    yield ("content", content_delta)
                        except Exception:
                            continue
        except Exception as e:
            yield ("error", f"OX Alpha connection error: {e}")
# ============================================================
# ARENA MODEL CATALOG FETCHING (RSC PAYLOAD EXTRACTOR)
# ============================================================

async def refresh_models_via_worker(worker):
    """Fetch models using an idle worker by navigating to Arena homepage."""
    log("INFO", f"[{worker.name}] Refreshing models via worker navigation...")
    try:
        await worker.page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded", timeout=30000)
        body = await worker.page.content()
        match = re.search(r'{\"initialModels\":(\[.*?\].*?\"userSelectable\":.*?\}|\[.*?\],\"initialModel[A-Z]Id)', body, re.DOTALL)
        if not match:
            match = re.search(r'{\"initialModels\":(\[.*?\],\"initialModel[A-Z]Id|\[.*?\])', body, re.DOTALL)
        if match:
            raw_match = match.group(1)
            if raw_match.endswith(',"initialModelAId') or raw_match.endswith(',"initialModelBId'):
                raw_match = raw_match.rsplit(',', 1)[0]
            raw_json = raw_match.encode().decode('unicode_escape')
            models_data = json.loads(raw_json)

            # Always dump the raw, unfiltered payload so we can inspect the
            # exact fields Arena sends for any given model (e.g. to figure
            # out why an internal/test model like "gpt-5.4-no-system-prompt"
            # isn't being caught by is_model_selectable()).
            try:
                atomic_write(MODELS_RAW_DEBUG_FILE, models_data)
            except Exception as e:
                log("WARN", f"Failed to write raw model debug dump: {e}")

            hidden = [m.get("publicName") or m.get("id") for m in models_data if not is_model_selectable(m)]
            kept = [m.get("publicName") or m.get("id") for m in models_data if is_model_selectable(m)]
            log("INFO", f"Model filter kept={len(kept)} hidden={len(hidden)} hidden_sample={hidden[:20]}")
            
            filtered = []
            for m in models_data:
                name = m.get("publicName") or m.get("id") or m.get("name")
                if not name:
                    continue
                if not is_model_selectable(m):
                    continue
                caps = (m.get("capabilities") or {}).get("outputCapabilities") or m.get("outputCapabilities") or {}
                if caps.get("text") is False:
                    continue
                filtered.append(m)
            
            if filtered:
                save_models(filtered)
                log("OK", f"Model catalog refreshed via worker ({len(filtered)} models)")
                return filtered
        log("WARN", "Regex failed to find models in page source.")
    except Exception as e:
        log("ERROR", f"Failed to refresh models: {e}")
    return get_models()

async def refresh_model_catalog() -> dict:
    """Attempt to refresh the model catalog and return a structured result
    describing whether it actually worked and, if not, why — instead of
    silently falling back to the stale catalog with zero visibility."""
    state = load_state()
    now = time.time()
    if now - state.get("refresh_started", 0) < 30:
        return {
            "ok": False, "models": get_models(),
            "reason": "A refresh is already in progress (debounced ~30s) — try again shortly.",
        }

    def mark_start(s):
        s["refresh_started"] = now
    mutate_state(mark_start)

    fetched_models = []
    tried_any_worker = False
    try:
        # 1. Try browser-based extraction using the worker
        for jar_candidate in load_jars():
            s = keeper.sessions.get(jar_candidate.get("id"))
            if s and s.running and s.page and not s.page.is_closed():
                tried_any_worker = True
                fetched_models = await refresh_models_via_worker(s)
                if fetched_models and len(fetched_models) > 50:
                    break
    except Exception as e:
        def mark_fail_exc(s):
            s["refresh_started"] = 0
        mutate_state(mark_fail_exc)
        return {"ok": False, "models": get_models(), "reason": f"Refresh crashed: {type(e).__name__}: {e}"}

    if fetched_models and len(fetched_models) > 50:
        def mark_done(s):
            s["last_refresh"] = time.time()
            s["refresh_started"] = 0
        mutate_state(mark_done)
        return {
            "ok": True, "models": fetched_models,
            "reason": f"Refreshed successfully — {len(fetched_models)} models loaded.",
        }

    def mark_fail(s):
        s["refresh_started"] = 0
    mutate_state(mark_fail)

    if not tried_any_worker:
        reason = "No live keeper session with an open browser page was available to fetch the catalog."
    else:
        reason = "Fetched the page but couldn't extract a valid model list (regex/parse failure) — catalog left unchanged."
    return {"ok": False, "models": get_models(), "reason": reason}


async def get_initial_data() -> list:
    """Backward-compatible wrapper for callers that just want the model list
    (boot sequence, periodic refresher) without the structured result."""
    result = await refresh_model_catalog()
    return result["models"]
# ============================================================
# SESSION KEEPER — SELECTORS & HELPERS
# ============================================================

DEFAULT_SELECTORS = {
    "signin": [
        'button:has-text("Login")', 'button:has-text("Log in")', 'button:has-text("Log In")',
        'button:has-text("Sign in")', 'button:has-text("Sign In")',
        'a:has-text("Login")', 'a:has-text("Log in")', 'a:has-text("Log In")',
        'a:has-text("Sign in")', 'a:has-text("Sign In")',
        '[data-testid*="login" i]', '[data-testid*="signin" i]',
        'header button:has-text("Log in")', 'header a:has-text("Log in")',
    ],
    "email_option": [
        'button:has-text("Continue with email")', 'a:has-text("Continue with email")',
        'button:has-text("Sign in with email")', 'a:has-text("Sign in with email")',
        'button:has-text("Email")',
    ],
    "submit": [
        'button:has-text("Continue")', 'button:has-text("Log in")', 'button:has-text("Login")',
        'button:has-text("Sign in")', 'button[type="submit"]',
    ],
    "email_input": [
        'input[type="email"]', 'input[autocomplete="email"]', 'input[name="email"]',
        'input[name="username"]', 'input[id="email"]',
        'input[placeholder*="mail" i]', 'input[placeholder*="email" i]',
    ],
    "password_input": [
        'input[type="password"]', 'input[name="password"]', '#password',
        'input[placeholder*="password" i]', 'input[autocomplete="current-password"]',
    ],
    "error_markers": [
        "wrong password", "invalid credentials", "incorrect email",
        "no account found", "password is incorrect", "too many attempts",
    ],
    "sidebar_toggle": [
        "button:has(svg path[d*='19 21L5 21'])",
        "[aria-label*='sidebar' i]", "[aria-label*='menu' i]",
    ],
}


def load_selectors() -> dict:
    try:
        with open(SELECTORS_FILE, encoding="utf-8") as f:
            user = json.load(f)
        merged = {k: list(v) for k, v in DEFAULT_SELECTORS.items()}
        merged.update(user)
        return merged
    except Exception:
        return {k: list(v) for k, v in DEFAULT_SELECTORS.items()}


def to_playwright_cookies(cookies: list) -> list:
    out = []
    for c in cookies:
        name, value = c.get("name", ""), c.get("value", "")
        if not name or not value:
            continue
        item = {
            "name": name, "value": value,
            "domain": c.get("domain") or ".arena.ai",
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
        }
        exp = c.get("expirationDate") or c.get("expires")
        if exp and isinstance(exp, (int, float)) and exp > 0:
            item["expires"] = exp
        out.append(item)
    return out


class BridgeHTTPError(Exception):
    def __init__(self, status: int, body: str):
        self.status, self.body = status, body
        super().__init__(f"HTTP {status}: {body[:200]}")


class ConversationLost(Exception):
    pass


# ============================================================
# KEEPER SESSION — UNIVERSAL STEALTH BROWSER ENGINE
# ============================================================

class KeeperSession:
    """Persistent browser session for one Arena account.
    Cross-platform stealth engine compatible with Windows, macOS, Linux, and Pterodactyl/Docker containers.
    Supports Edge (fastest), Chrome, Chromium, and bundled headless binaries with humanized mouse/keyboard trajectories."""

    def __init__(self, jar: dict, headless: Optional[bool] = None, keep_forever: bool = False):
        self.jar_id = jar["id"]
        self._tried_proxies = set()   # persist across auto-retries: keeper grinds the pool
        self._direct_tried = False
        self.name = jar.get("name", self.jar_id)
        self.login_method = jar.get("login_method") or "email"
        self.email = jar.get("email") or ""
        self.password = jar.get("password") or ""
        self.user_agent = jar.get("user_agent") or None
        if headless is not None:
            self.headless = headless
        elif "keeper_headless" in jar:
            self.headless = bool(jar["keeper_headless"])
        elif os.environ.get("BRIDGENA_HEADLESS", "").lower() in ("1", "true", "yes"):
            self.headless = True
        else:
            self.headless = False
        self.keep_forever = keep_forever
        self.humanize = bool(jar.get("keeper_humanize", True))

        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self._loop_task = None
        self._action_lock = asyncio.Lock()

        self.running = False
        self.status = "stopped"
        self.error = None
        self.current_step = ""
        self.step_history = []
        self.last_activity = 0.0
        self.last_health_ok = 0.0
        self.last_nav = 0.0
        self.last_restart = 0.0
        self.fail_count = 0
        self.next_retry = 0.0
        self.relogin_count = 0
        self._nav_fail_count = 0
        self.active_requests = 0
        self._auth_sig_cache = None
        self._cur_x = 200.0
        self._cur_y = 200.0
        # Page pool for concurrent requests
        self._page_pool: list = []  # list of extra pages
        self._page_pool_lock = asyncio.Lock()
        self._max_pool_pages = 4  # max extra pages beyond self.page

    def _set_step(self, step_text: str):
        """Record and broadcast a detailed login/keeper progress step."""
        self.current_step = step_text
        entry = f"[{time.strftime('%H:%M:%S')}] {step_text}"
        self.step_history.append(entry)
        if len(self.step_history) > 40:
            self.step_history = self.step_history[-40:]
        log("INFO", f"[{self.name}] {step_text}")

    # --- Visual Cursor & Human Input ---

    async def _inject_visual_cursor(self, page):
        """Inject a visual cursor tracker into the DOM for live browser watching."""
        try:
            await page.evaluate("""() => {
                if (document.getElementById('__nx_visual_cursor')) return;
                const dot = document.createElement('div');
                dot.id = '__nx_visual_cursor';
                dot.style.cssText = 'position:fixed;width:18px;height:18px;border-radius:50%;background:rgba(239,68,68,0.85);border:2px solid #fff;box-shadow:0 0 12px rgba(239,68,68,0.9);pointer-events:none;z-index:2147483647;transition:transform 0.05s ease-out;transform:translate(-50%,-50%);left:200px;top:200px;';
                document.documentElement.appendChild(dot);
                window.addEventListener('mousemove', e => {
                    dot.style.left = e.clientX + 'px';
                    dot.style.top = e.clientY + 'px';
                });
            }""")
        except Exception:
            pass

    async def _human_move(self, page, target_x: float, target_y: float, steps: int = 14):
        """Move mouse with smooth multi-step curve to simulate authentic human movement."""
        start_x, start_y = self._cur_x, self._cur_y
        for i in range(1, steps + 1):
            t = i / steps
            ease = t * t * (3 - 2 * t)
            deviation = (math.sin(t * 3.14159)) * random.uniform(-4, 4)
            cx = start_x + (target_x - start_x) * ease + deviation
            cy = start_y + (target_y - start_y) * ease + deviation
            try:
                await page.mouse.move(cx, cy)
                await asyncio.sleep(random.uniform(0.012, 0.025))
            except Exception:
                break
        try:
            await page.mouse.move(target_x, target_y)
        except Exception:
            pass
        self._cur_x, self._cur_y = target_x, target_y
        self.last_activity = time.time()

    async def stop(self):
        self.running = False
        self._set_step("Keeper stopped")

    async def _human_click(self, page, locator, timeout_ms: int = 4000) -> bool:
        """Move cursor to element and click naturally."""
        try:
            if await locator.count() == 0:
                return False
            box = await locator.bounding_box()
            if not box:
                await locator.scroll_into_view_if_needed()
                box = await locator.bounding_box()
            if box:
                tx = box["x"] + box["width"] * random.uniform(0.35, 0.65)
                ty = box["y"] + box["height"] * random.uniform(0.35, 0.65)
                await self._human_move(page, tx, ty)
                await asyncio.sleep(random.uniform(0.05, 0.12))
                await page.mouse.down()
                await asyncio.sleep(random.uniform(0.04, 0.09))
                await page.mouse.up()
                return True
            else:
                await locator.click(timeout=timeout_ms)
                return True
        except Exception:
            try:
                await locator.click(timeout=timeout_ms, force=True)
                return True
            except Exception:
                return False

    async def _human_type(self, page, locator, text: str, instant: bool = False):
        """Click input and fill text. Uses instant fill by default for reliability."""
        await self._human_click(page, locator)
        await asyncio.sleep(0.15)
        try:
            await locator.fill("")
        except Exception:
            try:
                await page.keyboard.press("Control+A")
                await page.keyboard.press("Backspace")
            except Exception:
                pass
        # Always use instant fill for login fields - more reliable
        await locator.fill(text)
        await asyncio.sleep(0.2)

    # --- Browser Helpers ---

    async def _wait_cloudflare(self, page, timeout: int = 35000):
        try:
            await page.wait_for_function(
                "() => document.title.indexOf('Just a moment') === -1", timeout=timeout)
        except Exception:
            pass

    async def _handle_turnstile(self, page):
        try:
            for frame in page.frames:
                frame_url = (frame.url or "").lower()
                if "turnstile" in frame_url or "challenges.cloudflare.com" in frame_url:
                    btn = frame.locator('input[type="checkbox"], .cf-turnstile, #challenge-stage')
                    if await btn.count() > 0 and await btn.first.is_visible():
                        self._set_step("Interacting with Cloudflare Turnstile challenge...")
                        await self._human_click(page, btn.first)
                        await asyncio.sleep(2)
                        return True
        except Exception:
            pass
        return False

    async def solve_recaptcha_image_challenge(self) -> bool:
        """Fallback: solve a visible reCAPTCHA image challenge with ONNX models.

        Primary path is reCAPTCHA v3 token (no challenge UI). This only runs when
        an image grid challenge is already on screen. Requires models/type.onnx
        and models/grid.onnx (or BRIDGENA_CAPTCHA_MODELS dir).
        """
        if get_solver is None:
            return False
        solver = get_solver()
        if not solver.available():
            log("WARN", f"[{self.name}] ONNX captcha models not available — skip image solve")
            return False
        page = self.page
        if not page or page.is_closed():
            return False

        try:
            self._set_step("Solving reCAPTCHA image challenge (ONNX fallback)...")
            # Find the challenge iframe (bframe)
            challenge_frame = None
            for frame in page.frames:
                u = (frame.url or "").lower()
                if "recaptcha" in u and ("bframe" in u or "anchor" not in u):
                    challenge_frame = frame
                    break
            if challenge_frame is None:
                # Try clicking the anchor checkbox first to open challenge
                for frame in page.frames:
                    u = (frame.url or "").lower()
                    if "recaptcha" in u and "anchor" in u:
                        try:
                            cb = frame.locator("#recaptcha-anchor, .recaptcha-checkbox-border")
                            if await cb.count() > 0:
                                await cb.first.click(timeout=3000)
                                await asyncio.sleep(2)
                        except Exception:
                            pass
                for frame in page.frames:
                    u = (frame.url or "").lower()
                    if "recaptcha" in u and "bframe" in u:
                        challenge_frame = frame
                        break
            if challenge_frame is None:
                return False

            # Extract task text
            task = ""
            for sel in [".rc-imageselect-desc-text", ".rc-imageselect-desc", "strong"]:
                try:
                    loc = challenge_frame.locator(sel).first
                    if await loc.count() > 0:
                        task = (await loc.inner_text()).strip()
                        if task:
                            break
                except Exception:
                    continue
            if not task:
                return False

            # Detect grid size and grab image(s)
            tile_table = challenge_frame.locator("table.rc-imageselect-table-33, table.rc-imageselect-table-44, table.rc-imageselect-table")
            grid = "3x3"
            try:
                if await challenge_frame.locator("table.rc-imageselect-table-44").count() > 0:
                    grid = "4x4"
                elif await challenge_frame.locator("table.rc-imageselect-table-33").count() > 0:
                    grid = "3x3"
            except Exception:
                pass

            # Prefer full challenge image if present
            image_sources = []
            try:
                img = challenge_frame.locator(".rc-image-tile-wrapper img, img.rc-image-tile-33, img.rc-image-tile-44").first
                if await img.count() > 0:
                    src = await img.get_attribute("src")
                    if src:
                        image_sources = [src]
            except Exception:
                pass

            if not image_sources:
                # Per-tile images
                tiles = challenge_frame.locator("img.rc-image-tile-33, img.rc-image-tile-44, td img")
                n = await tiles.count()
                for i in range(min(n, 16)):
                    try:
                        src = await tiles.nth(i).get_attribute("src")
                        if src:
                            image_sources.append(src)
                    except Exception:
                        pass

            if not image_sources:
                log("WARN", f"[{self.name}] Captcha challenge found but no images")
                return False

            result = solver.recognize(task, image_sources, grid)
            if result.get("error"):
                log("WARN", f"[{self.name}] Solver error: {result['error']}")
                return False

            clicks = result.get("data") or []
            # Click matching tiles
            cells = challenge_frame.locator("td, .rc-imageselect-tile")
            cell_count = await cells.count()
            clicked = 0
            for i, should in enumerate(clicks):
                if not should or i >= cell_count:
                    continue
                try:
                    await cells.nth(i).click(timeout=2000)
                    clicked += 1
                    await asyncio.sleep(random.uniform(0.15, 0.35))
                except Exception:
                    continue

            await asyncio.sleep(0.5)
            # Verify / Next
            for sel in ["#recaptcha-verify-button", ".rc-button-default", "button"]:
                try:
                    btn = challenge_frame.locator(sel).first
                    if await btn.count() > 0 and await btn.is_visible():
                        txt = ""
                        try:
                            txt = (await btn.inner_text()).lower()
                        except Exception:
                            pass
                        if sel.startswith("#") or "verify" in txt or "next" in txt or not txt:
                            await btn.click(timeout=3000)
                            break
                except Exception:
                    continue

            await asyncio.sleep(2)
            log("OK", f"[{self.name}] Image captcha solved (task={task[:40]!r}, clicks={clicked}, grid={grid})")
            self._set_step(f"Captcha solved ({clicked} tiles)")
            return clicked > 0
        except Exception as e:
            log("WARN", f"[{self.name}] solve_recaptcha_image_challenge: {type(e).__name__}: {e}")
            return False

    async def _ensure_sidebar_cookie(self):
        """Set sidebar_state cookie so the arena.ai sidebar stays open."""
        try:
            if self.context:
                await self.context.add_cookies([
                    {"name": "sidebar_state", "value": "true",
                     "domain": ".arena.ai", "path": "/", "secure": True, "httpOnly": False},
                    {"name": "sidebar_state", "value": "true",
                     "domain": "arena.ai", "path": "/", "secure": True, "httpOnly": False},
                    {"name": "sidebar_state", "value": "true",
                     "domain": ".lmarena.ai", "path": "/", "secure": True, "httpOnly": False},
                ])
        except Exception:
            pass

    async def _verify_auth_state(self, page) -> bool:
        """Thorough check to verify whether user is genuinely logged into arena.ai."""
        try:
            # 1. If page contains expected email near footer/chip -> logged in
            if self.email:
                try:
                    email_loc = page.locator(f"text=/{re.escape(self.email)}/i").first
                    if await email_loc.count() > 0 and await email_loc.is_visible():
                        return True
                except Exception:
                    pass

            # 2. If Login button is visible on page, we are NOT logged in
            login_btn = page.locator("button:has-text('Log In'), a:has-text('Log In'), button:has-text('Sign In'), a:has-text('Sign In'), button:has-text('Login'), a:has-text('Login')").first
            if await login_btn.count() > 0 and await login_btn.is_visible():
                return False

            # If 'Log In or Create' modal is visible, we are NOT logged in
            modal_title = page.locator("text='Log In or Create'").first
            if await modal_title.count() > 0 and await modal_title.is_visible():
                return False

            # 3. Check for typical auth cookies directly in the browser context
            cookies = await page.context.cookies()
            auth_cookie_names = ["arena-auth", "arena-auth-prod-v1.0", "arena-auth-prod-v1.1", "__session", "session", "authToken", "clerk-db-jwt"]
            has_auth = any(any(n in c["name"] for n in auth_cookie_names) for c in cookies)
            if has_auth:
                return True
                
            # 4. Fallback: Check if the user profile avatar or settings button is present
            profile_btn = page.locator("button:has(svg), button[aria-label='User Profile'], button[aria-label='Settings']").last
            if await profile_btn.count() > 0 and "arena.ai" in (page.url or ""):
                return True

            # 5. Check actual unified history API status
            status_code = await page.evaluate(
                "async () => { try { const r = await fetch('/api/history/unified?limit=1', "
                "{credentials:'include'}); return r.status; } catch(e) { return 0; } }"
            )
            if status_code == 200:
                return True
                    
        except Exception:
            pass
        await self._screenshot(page, "unverified_auth_state")
        return False
    async def _screenshot(self, page, tag: str):
        try:
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", tag)[:30]
            path = f"login_debug_{self.jar_id}_{safe}_{int(time.time())}.png"
            await page.screenshot(path=path)
            log("WARN", f"[{self.name}] Debug screenshot saved: {path}")
        except Exception:
            pass

    async def _dismiss_promos(self, page):
        """Dismiss any promotional banners/ads that Arena shows (e.g. 'Get More Done With Agents').
        These banners can cover the sidebar and block the Log In button."""
        try:
            dismiss_selectors = [
                "text='Hide this'",
                "button:has-text('Hide this')",
                "a:has-text('Hide this')",
                "text='Dismiss'",
                "button:has-text('Dismiss')",
                "button:has-text('Close')",
                "button[aria-label='Close']",
                "button[aria-label='Dismiss']",
            ]
            for sel in dismiss_selectors:
                try:
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        await loc.click(timeout=3000)
                        log("INFO", f"[{self.name}] Dismissed promo banner via: {sel}")
                        await asyncio.sleep(1)
                except Exception:
                    continue
        except Exception:
            pass

    # --- Multi-Step Native Email/Password Login ---

    async def _login_email_native(self) -> Tuple[bool, str]:
        """Multi-step email + password login on arena.ai modal.
        Uses instant fill for speed and reliability.
        Handles: Log In button -> email input -> Continue with email -> password -> Login."""
        page = self.page
        if not page or page.is_closed():
            return False, "Browser page is closed"
        if not self.email or not self.password:
            return False, "No email/password credentials configured"

        await self._inject_visual_cursor(page)

        try:
            # ---- STEP 1: Navigate ----
            self._set_step("[1/6] Navigating to arena.ai...")
            await self._ensure_sidebar_cookie()
            await page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded")
            await self._wait_cloudflare(page)
            await self._handle_turnstile(page)
            await asyncio.sleep(2)

            # ---- Dismiss any promo banners blocking the UI ----
            await self._dismiss_promos(page)

            # ---- STEP 2: Open login modal ----
            self._set_step("[2/6] Locating and opening login modal...")

            # Check if login modal is already visible (email input present)
            modal_already_open = False
            for sel in ["input[placeholder='Your email']", "input[type='email']"]:
                loc = page.locator(sel).first
                try:
                    if await loc.count() > 0 and await loc.is_visible():
                        modal_already_open = True
                        break
                except Exception:
                    continue

            if not modal_already_open:
                # Check if sidebar is already open (our cookie should have done this)
                # Only try to toggle sidebar if Log In button is NOT visible
                login_visible = False
                for sel in ["button:has-text('Log In')", "a:has-text('Log In')", "button:has-text('Log in')", "a:has-text('Log in')"]:
                    try:
                        loc = page.locator(sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            login_visible = True
                            break
                    except Exception:
                        continue

                if not login_visible:
                    # Sidebar might be collapsed — try toggling it open
                    try:
                        await page.locator("button[aria-label*='sidebar' i]").first.click(timeout=3000)
                        await asyncio.sleep(1.5)
                    except Exception:
                        pass

                # Try to click Log In button in the page
                login_selectors = [
                    "button:has-text('Log In')",
                    "a:has-text('Log In')",
                    "button:has-text('Log in')",
                    "a:has-text('Log in')",
                    "button:has-text('Sign In')",
                    "a:has-text('Sign In')",
                ]
                clicked = False
                for sel in login_selectors:
                    try:
                        btn = page.locator(sel).first
                        if await btn.count() > 0:
                            await btn.click(timeout=5000, force=True)
                            clicked = True
                            self._set_step("[2/6] Clicked Log In button, waiting for modal...")
                            break
                    except Exception:
                        continue

                if not clicked:
                    # Maybe the modal is controlled via JS, try evaluating
                    try:
                        await page.evaluate("document.querySelector('button[class*=login], a[href*=login]')?.click()")
                    except Exception:
                        pass

                # Wait for the email input to appear in the modal
                try:
                    await page.wait_for_selector(
                        "input[placeholder='Your email'], input[type='email'], input[name='email']",
                        state="visible", timeout=8000
                    )
                except Exception:
                    pass
                await asyncio.sleep(1)

            # ---- STEP 3: Fill email ----
            self._set_step(f"[3/6] Entering email: {self.email}...")
            email_loc = None
            email_selectors = [
                "input[placeholder='Your email']",
                "input[type='email']",
                "input[name='email']",
                "input[placeholder*='email' i]",
                "input[name='identifier']",
            ]
            for sel in email_selectors:
                try:
                    loc = page.locator(sel).first
                    if await loc.count() > 0 and await loc.is_visible():
                        email_loc = loc
                        break
                except Exception:
                    continue

            if not email_loc:
                await self._screenshot(page, "no_email_input")
                err = "Email input field not found on login modal"
                self._set_step(f"[FAILED at Step 3] {err}")
                return False, err

            # Instant fill
            await email_loc.click()
            await asyncio.sleep(0.1)
            await email_loc.fill(self.email)
            await asyncio.sleep(0.3)
            self._set_step(f"[3/6] Email entered: {self.email}")

            # ---- STEP 4: Click "Continue with email" ----
            self._set_step("[4/6] Clicking 'Continue with email'...")

            # The arena.ai modal has a specific "Continue with email" button
            # Try multiple strategies to find and click it
            submit_clicked = False

            # Strategy 1: Try exact text match buttons
            continue_selectors = [
                "button:has-text('Continue with email')",
                "button:has-text('Continue with Email')",
                "button:text-is('Continue with email')",
            ]
            for sel in continue_selectors:
                try:
                    btn = page.locator(sel).first
                    if await btn.count() > 0 and await btn.is_visible():
                        await btn.click(timeout=5000)
                        submit_clicked = True
                        self._set_step("[4/6] Clicked 'Continue with email' button")
                        break
                except Exception:
                    continue

            # Strategy 2: Find button by searching all buttons in the modal
            if not submit_clicked:
                try:
                    buttons = page.locator("button")
                    count = await buttons.count()
                    for i in range(count):
                        btn = buttons.nth(i)
                        try:
                            txt = (await btn.inner_text()).strip().lower()
                            if "continue" in txt and "email" in txt:
                                await btn.click(timeout=5000)
                                submit_clicked = True
                                self._set_step("[4/6] Clicked continue button (text search)")
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

            # Strategy 3: Generic submit/continue buttons
            if not submit_clicked:
                for sel in ["button:has-text('Continue')", "button[type='submit']"]:
                    try:
                        btn = page.locator(sel).first
                        if await btn.count() > 0 and await btn.is_visible():
                            await btn.click(timeout=5000)
                            submit_clicked = True
                            self._set_step("[4/6] Clicked submit/continue button")
                            break
                    except Exception:
                        continue

            # Strategy 4: Press Enter as last resort
            if not submit_clicked:
                await page.keyboard.press("Enter")
                self._set_step("[4/6] Pressed Enter to submit email")

            await asyncio.sleep(3)

            # ---- Check for "Create Account" (unregistered email) ----
            try:
                create_heading = page.locator("text='Create Account'").first
                if await create_heading.count() > 0 and await create_heading.is_visible():
                    err = f"Account {self.email} is not registered on arena.ai (shows 'Create Account')"
                    self._set_step(f"[FAILED at Step 4] {err}")
                    await self._screenshot(page, "create_account_shown")
                    return False, err
            except Exception:
                pass

            # ---- STEP 5: Enter password ----
            self._set_step("[5/6] Waiting for password field...")
            pw_loc = None
            pw_deadline = time.time() + 12
            while time.time() < pw_deadline:
                for sel in ["input[type='password']", "input[name='password']", "input[placeholder*='password' i]"]:
                    try:
                        loc = page.locator(sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            pw_loc = loc
                            break
                    except Exception:
                        continue
                if pw_loc:
                    break
                await asyncio.sleep(0.5)

            if not pw_loc:
                # Maybe we're already authenticated after email?
                if await self._verify_auth_state(page):
                    self._set_step("[SUCCESS] Authenticated without password!")
                    return True, "Authenticated without password"
                await self._screenshot(page, "no_password_field")
                # Also screenshot the current page state for debugging
                try:
                    page_text = await page.inner_text("body")
                    log("WARN", f"[{self.name}] Page text after email submit: {page_text[:300]}")
                except Exception:
                    pass
                err = "Password field did not appear after email submission"
                self._set_step(f"[FAILED at Step 5] {err}")
                return False, err

            self._set_step("[5/6] Entering password...")
            await pw_loc.click()
            await asyncio.sleep(0.1)
            await pw_loc.fill(self.password)
            await asyncio.sleep(0.3)

            # ---- STEP 6: Submit password and verify ----
            self._set_step("[6/6] Submitting credentials & verifying...")

            # Arena.ai password screen has a "Login" button (not "Log In")
            login_clicked = False
            login_btn_selectors = [
                "button:has-text('Login')",
                "button:has-text('Log In')",
                "button:has-text('Log in')",
                "button:has-text('Sign In')",
                "button:has-text('Sign in')",
                "button[type='submit']",
            ]
            for sel in login_btn_selectors:
                try:
                    btn = page.locator(sel).first
                    if await btn.count() > 0 and await btn.is_visible():
                        await btn.click(timeout=5000)
                        login_clicked = True
                        self._set_step("[6/6] Clicked Login button, verifying session...")
                        break
                except Exception:
                    continue

            if not login_clicked:
                await page.keyboard.press("Enter")
                self._set_step("[6/6] Pressed Enter to submit, verifying session...")

            # Wait for authentication to complete
            auth_deadline = time.time() + 20
            while time.time() < auth_deadline:
                try:
                    if await self._verify_auth_state(page):
                        await asyncio.sleep(1)
                        await self._harvest_cookies()
                        self._set_step("[SUCCESS] Authentication successful! Session cookies saved.")
                        return True, "Login successful"
                except Exception:
                    pass

                # Also check for error messages on the page
                try:
                    for marker in ["wrong password", "invalid", "incorrect", "too many attempts"]:
                        err_el = page.locator(f"text=/{marker}/i").first
                        if await err_el.count() > 0 and await err_el.is_visible():
                            err = f"Login rejected: {marker}"
                            self._set_step(f"[FAILED at Step 6] {err}")
                            return False, err
                except Exception:
                    pass

                await asyncio.sleep(1.0)

            await self._screenshot(page, "auth_timeout")
            err = "Authentication timed out — password may be wrong or session didn't validate"
            self._set_step(f"[FAILED at Step 6] {err}")
            return False, err

        except Exception as e:
            try:
                await self._screenshot(page, "login_exception")
            except Exception:
                pass
            err = f"Login exception: {type(e).__name__}: {e}"
            self._set_step(f"[ERROR] {err}")
            return False, err

    # --- Cookie Harvesting ---

    async def _harvest_cookies(self):
        try:
            await self._ensure_sidebar_cookie()
            if not self.context:
                return
            cookies = await self.context.cookies()
            simplified = [
                {"name": c.get("name", ""), "value": c.get("value", ""),
                 "domain": c.get("domain", ""), "path": c.get("path", "/"),
                 "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                 "expirationDate": c.get("expires")}
                for c in cookies if c.get("name")
            ]
            auth_val = (find_cookie(simplified, "arena-auth-prod-v1.0")
                        or find_cookie(simplified, "arena-auth-prod-v1.1")
                        or find_cookie(simplified, "arena-auth-prod-v1") or "")
            sig = hashlib.sha256(auth_val.encode()).hexdigest()[:10] if auth_val else "none"

            def upd(jars: list):
                for j in jars:
                    if j["id"] != self.jar_id: continue
                    if simplified:
                        j["cookies"] = simplified
                        j["expired"] = False
            mutate_jars(upd)

            if sig != self._auth_sig_cache:
                log("OK", f"[{self.name}] Cookies synced (auth {'present' if auth_val else 'MISSING'})")
                self._auth_sig_cache = sig

            # Persist browser state to profile directory
            try:
                profile_dir = os.path.join(PROFILES_DIR, self.jar_id)
                os.makedirs(profile_dir, exist_ok=True)
                if self.context:
                    await self.context.storage_state(path=os.path.join(profile_dir, "state.json"))
            except Exception:
                pass
        except Exception as e:
            log("WARN", f"[{self.name}] Cookie harvest failed: {e}")

    # --- Activity & Health ---

    async def _do_activity(self):
        if self.status != "running" or self.active_requests > 0 or self._action_lock.locked():
            return
        async with self._action_lock:
            page = self.page
            if not page or page.is_closed():
                return
            try:
                size = page.viewport_size or {"width": 1920, "height": 1080}
                # Stay in the main content area (avoid sidebar on left ~300px)
                tx = random.randint(350, max(351, size["width"] - 100))
                ty = random.randint(150, max(151, size["height"] - 150))
                await self._human_move(page, tx, ty, steps=8)
                await page.mouse.wheel(0, random.randint(-50, 150))
            except Exception:
                pass

    async def check_health(self) -> bool:
        async with self._action_lock:
            try:
                page = self.page
                if not page or page.is_closed():
                    return False
                if ARENA_BASE not in (page.url or "") and self.active_requests == 0:
                    await self._ensure_sidebar_cookie()
                    await page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded")
                    await self._wait_cloudflare(page)
                if await self._verify_auth_state(page):
                    self.last_health_ok = time.time()
                    await self._harvest_cookies()
                    return True
                return False
            except Exception as e:
                self.error = f"health: {type(e).__name__}: {e}"
                return False

    # --- Relogin Flow ---

    async def relogin(self) -> bool:
        self.status = "reconnecting"
        self.error = None
        self._set_step("Starting re-login sequence...")
        try:
            return await asyncio.wait_for(self._relogin_impl(), timeout=KEEPER_RELOGIN_TIMEOUT)
        except asyncio.TimeoutError:
            self.error = f"Relogin timed out after {KEEPER_RELOGIN_TIMEOUT}s"
            self._set_step(f"[TIMEOUT] {self.error}")
            log("ERROR", f"[{self.name}] {self.error}")
            self._schedule_retry()
            return False

    async def _relogin_impl(self) -> bool:
        async with self._action_lock:
            self.status = "degraded"
            try:
                page = self.page
                if not page or page.is_closed():
                    self.error = "Page is closed — restarting browser"
                    self._set_step("Browser page was closed, restarting browser...")
                    self._schedule_retry()
                    return False

                if not (self.email and self.password):
                    self.error = "No credentials configured — enter email:password in dashboard"
                    self._set_step(f"[ERROR] {self.error}")
                    log("ERROR", f"[{self.name}] {self.error}")
                    self._schedule_retry()
                    return False

                ok, msg = await self._login_email_native()
                if ok:
                    await asyncio.sleep(2)
                    await self._harvest_cookies()
                    self.relogin_count += 1
                    self.status = "running"
                    self.fail_count = 0
                    self.next_retry = 0
                    log("OK", f"[{self.name}] ✓ Reconnected successfully via {self.login_method}")
                    return True

                self.error = msg
                log("ERROR", f"[{self.name}] Relogin failed: {msg}")
                self._schedule_retry()
                return False

            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
                self._set_step(f"[ERROR] Relogin crashed: {self.error}")
                log("ERROR", f"[{self.name}] Relogin crashed: {self.error}")
                if "TargetClosedError" in str(e):
                    asyncio.create_task(self.restart())
                else:
                    self._schedule_retry()
                return False

    def _schedule_retry(self):
        self.fail_count += 1
        delay = min(45 * (2 ** (self.fail_count - 1)), 600)
        self.next_retry = time.time() + delay
        self._set_step(f"Retry scheduled in {delay}s (attempt {self.fail_count})")

    async def poke(self):
        if not self.running:
            return
        if await self.check_health():
            return
        if time.time() >= self.next_retry:
            await self.relogin()

    # --- Bridge Page Pool & Streaming Fetch ---

    async def _acquire_page(self):
        """Get a page for a bridge request. Uses pooled tabs for concurrency."""
        async with self._page_pool_lock:
            # Try to grab an idle page from the pool
            for i, (pg, busy) in enumerate(self._page_pool):
                if not busy and pg and not pg.is_closed():
                    self._page_pool[i] = (pg, True)
                    return pg, i
            # No idle pages — create a new tab if under limit
            if len(self._page_pool) < self._max_pool_pages and self.context:
                try:
                    new_page = await self.context.new_page()
                    await new_page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded")
                    await asyncio.sleep(0.5)
                    idx = len(self._page_pool)
                    self._page_pool.append((new_page, True))
                    log("INFO", f"[{self.name}] Spawned new tab #{idx + 1} for concurrent request")
                    return new_page, idx
                except Exception as e:
                    log("WARN", f"[{self.name}] Failed to create extra tab: {e}")
            # Fallback: use main page (will still work, just shares console)
            return self.page, -1

    async def _release_page(self, idx):
        """Mark a pooled page as idle."""
        if idx >= 0:
            async with self._page_pool_lock:
                if idx < len(self._page_pool):
                    pg, _ = self._page_pool[idx]
                    self._page_pool[idx] = (pg, False)

    async def _cleanup_pool(self):
        """Close all idle pool pages (called when no active requests)."""
        async with self._page_pool_lock:
            remaining = []
            for pg, busy in self._page_pool:
                if busy:
                    remaining.append((pg, busy))
                else:
                    try:
                        if pg and not pg.is_closed():
                            await pg.close()
                    except Exception:
                        pass
            self._page_pool = remaining

    async def bridge_fetch(self, url: str, payload: dict):
        if not self.context or not self.page or self.page.is_closed():
            raise RuntimeError("Keeper browser page is closed")

        # Acquire a page (main page or a pooled tab)
        page, pool_idx = await self._acquire_page()
        req_id = uuid.uuid4().hex[:8]
        queue: asyncio.Queue = asyncio.Queue()
        meta = {}
        prefix = f"__NX{req_id}"

        def on_console(msg):
            try:
                text = msg.text
                if isinstance(text, str) and text.startswith(prefix):
                    tag = text[len(prefix)]
                    body = text[len(prefix) + 1:]
                    if tag == "S": meta["status"] = int(body)
                    elif tag == "E": meta["error"] = body
                    elif tag == "D":
                        data = json.loads(body)
                        if data is None: queue.put_nowait(None)
                        else: queue.put_nowait(data)
            except Exception:
                pass

        page.on("console", on_console)
        self.active_requests += 1
        try:
            script = """async ([url, payload, rid]) => {
                const P = s => console.log('__NX' + rid + s);
                try {
                    const r = await fetch(url, {
                        method: 'POST', credentials: 'include',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(payload)
                    });
                    P('S' + r.status);
                    if (!r.ok) { P('E' + (await r.text()).slice(0, 400)); return; }
                    const reader = r.body.getReader();
                    const dec = new TextDecoder();
                    while (true) {
                        const {done, value} = await reader.read();
                        if (done) break;
                        const text = dec.decode(value, {stream: true});
                        for (const line of text.split('\n')) {
                            if (line.trim()) P('D' + JSON.stringify(line));
                        }
                    }
                    P('D' + JSON.stringify(null));
                } catch(e) {
                    P('S500'); P('E' + e.message);
                }
            }"""
            eval_task = asyncio.create_task(page.evaluate(script, [url, payload, req_id]))
            while True:
                line = await queue.get()
                if line is None:
                    break
                yield line
            if eval_task.done() and eval_task.exception():
                raise RuntimeError(f"Bridge evaluate exception: {eval_task.exception()}")
            status_code = meta.get("status", 0)
            if status_code != 200:
                raise BridgeHTTPError(status_code, meta.get("error", ""))
        finally:
            self.active_requests -= 1
            page.remove_listener("console", on_console)
            await self._release_page(pool_idx)
            # Clean up idle pool pages when no more active requests
            if self.active_requests == 0:
                asyncio.create_task(self._cleanup_pool())

    # --- Cross-Platform Browser Lifecycle ---

    async def start(self) -> bool:
        if self.running:
            return True
            
        self.status = "starting"
        self.error = None
        self._set_step("Initializing stealth browser engine...")
        try:
            if async_playwright is not None:
                self.playwright = await async_playwright().start()
                launched = False
                
                profile_dir = os.path.join(PROFILES_DIR, self.jar_id)
                os.makedirs(profile_dir, exist_ok=True)
                
                ext_path = os.environ.get("BRIDGENA_CAPTCHA_EXT", "")
                has_ext = ext_path and os.path.exists(os.path.join(ext_path, "manifest.json"))

                common_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-software-rasterizer",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--window-size=1920,1080",
                ]

                # Per-account / pool proxy for the live browser (bypasses IP rate-limits)
                _jar_for_proxy = next((j for j in load_jars() if j.get("id") == self.jar_id), {"id": self.jar_id})
                # Sweep: sticky first if it still tunnels, else the whole pool (pinned on winner)
                self._set_step("Probing proxy pool for a live tunnel...")
                _proxy_url = await apick_live_proxy(_jar_for_proxy, purpose="keeper",
                                                     exclude=self._tried_proxies)
                if not _proxy_url and get_proxy_pool():
                    self._set_step("No proxy tunnels — browser starting on DIRECT egress (IP exposed)")
                _pw_proxy = playwright_proxy_from_url(_proxy_url) if _proxy_url else None
                self._used_proxy = _proxy_url or ""
                if _pw_proxy:
                    self._set_step(f"Browser proxy: {_proxy_url.split('@')[-1] if '@' in _proxy_url else _proxy_url}")
                    log("INFO", f"[{self.name}] Keeper using proxy {_proxy_url.split('@')[-1] if '@' in (_proxy_url or '') else _proxy_url}")

                if has_ext:
                    # Extensions require a persistent context AND cannot load under
                    # classic (old) headless mode — Chromium disables the extension
                    # system there. Chrome's "new" headless mode (--headless=new)
                    # *does* support extensions, so when a headless keeper is wanted
                    # we stay technically non-headless to Playwright (headless=False,
                    # so it doesn't inject the old-style flag) and instead push
                    # "--headless=new" ourselves as a raw arg. Visibly-headed keepers
                    # just skip that arg and get a normal window as before.
                    self._set_step(
                        f"Launching persistent context with Captcha Extension"
                        f"{' (headless=new)' if self.headless else ''}..."
                    )
                    ext_args = common_args + [
                        f"--disable-extensions-except={ext_path}",
                        f"--load-extension={ext_path}",
                    ]
                    if self.headless:
                        ext_args.append("--headless=new")
                    _pc_kw = dict(
                        user_data_dir=profile_dir,
                        headless=False,  # always False here: headlessness is via --headless=new above
                        ignore_default_args=["--disable-extensions"],
                        args=ext_args,
                        viewport={"width": 1920, "height": 1080},
                        user_agent=KEEPER_UA,  # must match curl_cffi impersonate="chrome131" — cf_clearance is UA-bound
                    )
                    if _pw_proxy:
                        _pc_kw["proxy"] = _pw_proxy
                    self.context = await self.playwright.chromium.launch_persistent_context(**_pc_kw)
                    self.browser = None
                    self.page = self.context.pages[0] if self.context.pages else await self.context.new_page()
                    launched = True
                    log("OK", f"[{self.name}] Captcha extension loaded from {ext_path}"
                              f"{' in new-headless mode' if self.headless else ' (headed window)'}")
                else:
                    if ext_path:
                        log("WARN", f"[{self.name}] BRIDGENA_CAPTCHA_EXT set but manifest.json not found in {ext_path}")
                    
                    channels_to_try = ["chromium", None, "chrome", "msedge"]
                    for channel in channels_to_try:
                        try:
                            launch_kw = {"headless": self.headless, "args": common_args}
                            if channel:
                                launch_kw["channel"] = channel
                            if _pw_proxy:
                                launch_kw["proxy"] = _pw_proxy
                            self.browser = await self.playwright.chromium.launch(**launch_kw)
                            launched = True
                            self._set_step(f"Stealth engine started ({channel or 'bundled chromium'})")
                            break
                        except Exception:
                            continue

                    if not launched:
                        for bin_path in [
                            "/usr/bin/chromium",
                            "/usr/bin/chromium-browser",
                            "/usr/bin/google-chrome",
                            "/usr/bin/google-chrome-stable",
                            "/snap/bin/chromium",
                        ]:
                            if os.path.exists(bin_path):
                                try:
                                    self.browser = await self.playwright.chromium.launch(
                                        executable_path=bin_path, headless=self.headless, args=common_args
                                    )
                                    launched = True
                                    self._set_step(f"Stealth engine started via container binary ({bin_path})")
                                    break
                                except Exception:
                                    pass

                    if not launched:
                        try:
                            self.browser = await self.playwright.firefox.launch(headless=self.headless)
                            launched = True
                            self._set_step("Stealth engine started (Firefox fallback)")
                        except Exception:
                            pass

                    if not launched and AsyncCamoufox is not None:
                        self.browser = await AsyncCamoufox(headless=self.headless).__aenter__()
                        launched = True
                        self._set_step("Stealth engine started (Camoufox fallback)")

                    if not launched:
                        self.status = "error"
                        self.error = "No browser engine found. Run 'playwright install chromium' or install Edge/Chrome."
                        self._set_step(f"ERROR: {self.error}")
                        log("ERROR", f"[{self.name}] {self.error}")
                        return False

                    self.context = await self.browser.new_context(
                        viewport={"width": 1920, "height": 1080}, screen={"width": 1920, "height": 1080},
                        user_agent=KEEPER_UA,  # must match curl_cffi impersonate="chrome131" — cf_clearance is UA-bound
                        storage_state=os.path.join(profile_dir, "state.json") if os.path.exists(os.path.join(profile_dir, "state.json")) else None,
                    )
                self.page = await self.context.new_page()
                await self.page.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
            elif AsyncCamoufox is not None:
                cm = AsyncCamoufox(headless=self.headless, humanize=False)
                self.browser = await cm.__aenter__()
                self.context = self.browser.contexts[0] if self.browser.contexts else await self.browser.new_context(
                    viewport={"width": 1920, "height": 1080}
                )
                self.page = await self.context.new_page()
                await self.page.set_viewport_size({"width": 1920, "height": 1080})
            else:
                self.status = "error"
                self.error = "No browser engine available"
                log("ERROR", f"[{self.name}] {self.error}")
                return False

            jar = next((j for j in load_jars() if j["id"] == self.jar_id), None)
            if jar and jar.get("cookies"):
                try:
                    await self.context.add_cookies(to_playwright_cookies(jar["cookies"]))
                except Exception as e:
                    log("WARN", f"[{self.name}] Cookie restore partial: {e}")

            self._set_step("Navigating to arena.ai...")
            await self._ensure_sidebar_cookie()
            await self.page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded", timeout=25000)
            await self._wait_cloudflare(self.page)
            await self._handle_turnstile(self.page)
            await self._ensure_sidebar_cookie()
            await self._inject_visual_cursor(self.page)

            # Dismiss any promo banners that might block the UI
            await self._dismiss_promos(self.page)

            self.running = True
            self._tried_proxies = set()
            self._direct_tried = False
            self.last_health_ok = 0
            self.status = "running"
            self._set_step("Keeper session active")
            log("OK", f"[{self.name}] Keeper started ({'headless' if self.headless else 'LIVE WINDOW'})")

            if not await self.check_health():
                log("WARN", f"[{self.name}] Initial health check negative — triggering relogin")
                await self.relogin()

            self._loop_task = asyncio.create_task(self._session_loop())
            return True

        except Exception as e:
            txt = f"{type(e).__name__}: {e}"
            _up = txt.upper()
            _retryable = any(k in _up for k in ("TUNNEL", "PROXY", "TIMEOUT", "ERR_", "NET::", "CONNECTION"))
            used = getattr(self, "_used_proxy", "") or ""
            if used:
                self._tried_proxies.add(used)
                quarantine_proxy(used, f"keeper {self.name}: {txt[:90]}")
            pool = get_proxy_pool() or []
            left = [c for c in pool if c not in self._tried_proxies]
            if _retryable and left:
                log("WARN", f"[{self.name}] start failed via {used.split('@')[-1]} ({txt[:110]}) — "
                            f"auto-retrying on next live proxy ({len(left)} left)")
                self._set_step(f"Proxy {used.split('@')[-1]} failed — trying next of {len(left)}…")
                self.status = "starting"
                try:
                    await self.stop()
                except Exception:
                    pass
                await asyncio.sleep(1.0)
                return await self.start()
            if _retryable and pool and not getattr(self, "_direct_tried", False):
                self._direct_tried = True
                log("WARN", f"[{self.name}] all {len(self._tried_proxies)} proxies failed to tunnel — "
                            f"one final attempt on DIRECT egress")
                self._set_step("Every proxy failed — one direct attempt (IP exposed)…")
                self.status = "starting"
                try:
                    await self.stop()
                except Exception:
                    pass
                await asyncio.sleep(1.0)
                return await self.start()
            self.status = "error"
            self.error = txt
            self._set_step(f"ERROR: Failed to start: {self.error}")
            log("ERROR", f"[{self.name}] Failed to start: {self.error}")
            return False

    async def stop(self):
        self.running = False
        if self._loop_task:
            try: self._loop_task.cancel()
            except Exception: pass
        try:
            if self.page: await self._harvest_cookies()
        except Exception: pass
        self._page_pool.clear()
        try:
            if self.context: await self.context.close()
        except Exception: pass
        try:
            if self.browser: await self.browser.close()
        except Exception: pass
        try:
            if self.playwright: await self.playwright.stop()
        except Exception: pass
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
        self.status = "stopped"
        self._set_step("Keeper stopped")
        log("INFO", f"[{self.name}] Keeper stopped")

    async def restart(self):
        self.last_restart = time.time()
        self._set_step("Restarting browser keeper...")
        log("INFO", f"[{self.name}] Restarting browser")
        resume = self.running or self.keep_forever
        await self.stop()
        if resume:
            await asyncio.sleep(2)
            await self.start()

    async def _session_loop(self):
        while self.running:
            try:
                await self._do_activity()
                if (time.time() - self.last_nav > random.uniform(KEEPER_NAV_MIN, KEEPER_NAV_MAX)
                        and self.active_requests == 0 and not self._action_lock.locked()):
                    try:
                        async with self._action_lock:
                            await self._ensure_sidebar_cookie()
                            await self.page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded", timeout=45000)
                            await self._wait_cloudflare(self.page)
                            self.last_nav = time.time()
                            self._nav_fail_count = 0
                    except Exception as e:
                        self._nav_fail_count += 1
                        if self._nav_fail_count >= 3:
                            # Not just a one-off blip anymore — the page is
                            # genuinely stuck (e.g. wedged on a Cloudflare
                            # check or a dead navigation). A single restart
                            # recovers this; tolerating it forever would leave
                            # the browser silently broken (grecaptcha never
                            # loads, chat requests fail with missing token).
                            log("WARN", f"[{self.name}] Keep-alive navigation failed {self._nav_fail_count}x in a row ({type(e).__name__}: {e}) — restarting browser")
                            self._nav_fail_count = 0
                            await self.restart()
                            continue
                        else:
                            log("WARN", f"[{self.name}] Keep-alive navigation failed ({type(e).__name__}: {e}) — will retry next cycle ({self._nav_fail_count}/3)")
                if time.time() - self.last_health_ok > KEEPER_HEALTH_INTERVAL:
                    if not await self.check_health():
                        if time.time() >= self.next_retry:
                            log("WARN", f"[{self.name}] Session disconnected — attempting relogin")
                            await self.relogin()
                await asyncio.sleep(random.uniform(KEEPER_ACTIVITY_MIN, KEEPER_ACTIVITY_MAX))
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
                log("ERROR", f"[{self.name}] Loop exception: {self.error} — restarting")
                try:
                    await self.restart()
                except Exception:
                    pass
                await asyncio.sleep(10)


# ============================================================
# SESSION KEEPER ORCHESTRATOR
# ============================================================

class SessionKeeper:
    def __init__(self):
        self.sessions: Dict[str, KeeperSession] = {}

    def status(self) -> list:
        now = time.time()
        return [
            {
                "jar_id": s.jar_id, "name": s.name, "status": s.status,
                "error": s.error, "method": s.login_method,
                "current_step": s.current_step,
                "step_history": s.step_history,
                "relogins": s.relogin_count,
                "last_activity": int(now - s.last_activity) if s.last_activity else None,
                "healthy": (now - s.last_health_ok) < 900 if s.last_health_ok else False,
                "next_retry": int(s.next_retry - now) if s.next_retry > now else 0,
                "live": not s.headless,
            }
            for s in self.sessions.values()
        ]

    async def sync(self):
        wanted = {j["id"]: j for j in load_jars() if j.get("enabled", True) and j.get("keeper_enabled")}
        for jid in list(self.sessions):
            s = self.sessions[jid]
            if jid not in wanted and not s.keep_forever:
                await s.stop()
                del self.sessions[jid]
        for jid, jar in wanted.items():
            s = self.sessions.get(jid)
            if s is None:
                s = KeeperSession(jar, headless=jar.get("keeper_headless", None))
                self.sessions[jid] = s
                asyncio.create_task(s.start())
            else:
                if (s.email != (jar.get("email") or "") or s.password != (jar.get("password") or "")
                        or s.login_method != (jar.get("login_method") or "email")):
                    s.email = jar.get("email") or ""
                    s.password = jar.get("password") or ""
                    s.login_method = jar.get("login_method") or "email"
                    s.fail_count = 0
                    s.next_retry = 0
                    log("INFO", f"[{s.name}] Credentials updated in keeper")
                if s.status == "error" and time.time() - s.last_restart > 120:
                    asyncio.create_task(s.restart())

    async def start_live(self, jar_id: str) -> tuple:
        jar = next((j for j in load_jars() if j["id"] == jar_id), None)
        if not jar:
            return False, "Account not found"
        existing = self.sessions.get(jar_id)
        if existing and existing.running:
            await existing.stop()
        s = KeeperSession(jar, headless=False, keep_forever=True)
        self.sessions[jar_id] = s
        asyncio.create_task(s.start())
        return True, f"Live browser launching for '{jar.get('name')}'"


keeper = SessionKeeper()


async def get_live_cookies(jar_id: str) -> Optional[list]:
    s = keeper.sessions.get(jar_id)
    if s and s.running and s.page and not s.page.is_closed():
        try:
            cookies = await s.page.context.cookies()
            return [
                {"name": c.get("name", ""), "value": c.get("value", ""),
                 "domain": c.get("domain", ""), "path": c.get("path", "/"),
                 "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                 "expirationDate": c.get("expires")}
                for c in cookies if c.get("name")
            ]
        except Exception:
            return None
    return None


async def keeper_election_loop():
    log("INFO", "Session keeper background supervisor active")
    while True:
        try:
            state = load_state()
            now = time.time()
            owner = state.get("keeper_pid")
            mine = owner == os.getpid()
            stale = now - state.get("keeper_heartbeat", 0) > 90
            if mine or stale or not owner:
                await keeper.sync()
                def tick(s: dict):
                    s["keeper_pid"] = os.getpid()
                    s["keeper_heartbeat"] = now
                    s["keeper_status"] = keeper.status()
                mutate_state(tick)
        except Exception as e:
            log("ERROR", f"Keeper election loop: {e}")
        await asyncio.sleep(15)


async def periodic_model_refresher():
    while True:
        await asyncio.sleep(REFRESH_INTERVAL)
        try:
            await get_initial_data()
        except Exception as e:
            log("WARN", f"Periodic model refresh: {e}")


# ============================================================
# TRANSSTREAM ENGINE & ERROR HANDLING
# ============================================================

def _friendly_arena_error(error_text: str, model_name: str) -> str:
    t = str(error_text)
    if "high demand" in t.lower():
        return f"'{model_name}' is experiencing high demand on Arena. Try again shortly."
    if "is not found for API version" in t or "not supported for generateContent" in t:
        return f"'{model_name}' is temporarily unavailable on Arena's backend."
    if t.strip().lower() in ("bad request", "400"):
        return f"Arena rejected the request for '{model_name}'. The model might be misconfigured."
    if "too long" in t.lower() or "maximum" in t.lower() or "limit" in t.lower():
        return f"Context exceeded '{model_name}'s limit. Context has been compacted — retry."
    return f"Arena upstream message for '{model_name}': {t[:400]}"


async def _parse_bridge_stream(session: KeeperSession, url: str, payload: dict, model_name: str):
    content, reasoning, error_text = "", "", None
    mode = payload.get("mode", "direct-battle")
    async for line in session.bridge_fetch(url, payload):
        line = line.strip()
        if not line:
            continue
        
        # Standard SSE format support
        if line.startswith("data: "):
            d = line[6:].strip()
            if d == "[DONE]":
                break
            try:
                parsed = json.loads(d)
                delta = parsed.get("choices", [{}])[0].get("delta", {})
                if delta.get("content"):
                    content += delta["content"]
                    yield ("content", delta["content"])
                if delta.get("reasoning_content") or delta.get("thought"):
                    t = delta.get("reasoning_content") or delta.get("thought")
                    reasoning += t
                    yield ("reasoning", t)
                continue
            except Exception:
                pass

        # Next.js / Arena RSC Stream Frame Formats
        if line.startswith("a0:") or line.startswith("0:"):
            prefix_len = 3 if line.startswith("a0:") else 2
            try:
                t = json.loads(line[prefix_len:])
                content += t
                yield ("content", t)
            except json.JSONDecodeError:
                continue
        elif line.startswith("ag:") or line.startswith("g:"):
            prefix_len = 3 if line.startswith("ag:") else 2
            try:
                t = json.loads(line[prefix_len:])
                reasoning += t
                yield ("reasoning", t)
            except json.JSONDecodeError:
                continue
        elif line.startswith("a3:") or line.startswith("3:") or line.startswith("e:"):
            prefix_len = 3 if line.startswith("a3:") else 2
            try:
                err = json.loads(line[prefix_len:])
                error_text = err if isinstance(err, str) else json.dumps(err)
            except json.JSONDecodeError:
                error_text = line[prefix_len:]
            log("ERROR", f"Arena stream error frame: {error_text}")
            yield ("error", _friendly_arena_error(error_text, model_name))
            return
        elif line.startswith("ad:") or line.startswith("d:"):
            prefix_len = 3 if line.startswith("ad:") else 2
            try:
                md = json.loads(line[prefix_len:])
                yield ("finish", md.get("finishReason", "stop"))
            except json.JSONDecodeError:
                continue
    if not content and not reasoning:
        yield ("error", _friendly_arena_error(error_text, model_name) if error_text
               else "Arena returned an empty response.")
        return
    yield ("end", {"content": content, "reasoning": reasoning, "mode": mode})


async def arena_oneoff(model_id: str, model_name: str, prompt: str, jar: dict) -> Optional[str]:
    try:
        raw_headers = build_request_headers(jar)
        headers = {k: v for k, v in raw_headers.items() if k not in ["User-Agent", "sec-ch-ua", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"]}
        base = {
            "id": str(uuid7()), "mode": "direct", "modelAId": model_id,
            "userMessageId": str(uuid7()), "modelAMessageId": str(uuid7()),
            "userMessage": {"content": prompt}, "modality": "chat",
        }
        url = f"{ARENA_BASE}/nextjs-api/stream/create-evaluation"
        text = ""
        async with AsyncSession(impersonate="chrome131") as client:
            resp = await client.post(url, json=base, headers=headers, stream=True, timeout=35.0)
            if resp.status_code != 200:
                return None
            buffer = b""
            async for chunk in resp.aiter_content(chunk_size=1024):
                if not chunk: continue
                buffer += chunk
                while b"\n" in buffer:
                    line_bytes, buffer = buffer.split(b"\n", 1)
                    line = line_bytes.decode("utf-8", errors="ignore").strip()
                    if line.startswith("a0:") or line.startswith("0:"):
                        try:
                            text += json.loads(line[line.index(":")+1:])
                        except Exception: pass
        return text.strip() or None
    except Exception:
        return None
def build_preamble(prior: list) -> str:
    lines = []
    for m in prior:
        r = m.get("role", "user")
        label = {"user": "User", "assistant": "Assistant", "system": "System"}.get(r, "User")
        lines.append(f"{label}: {m.get('content', '')}")
    return "\n\n".join(lines)


async def compact_via_arena(prior: list, model_id: str, model_name: str, jar: dict) -> Optional[str]:
    transcript = "\n\n".join(
        f"{m.get('role', 'user').capitalize()}: {m.get('content', '')}"
        for m in prior[:-KEEP_RECENT_MSGS] if m.get("content")
    )
    prompt = (
        "Summarize the following conversation into a dense, factual, compact briefing. "
        "Preserve core user goals, constraints, and pending items.\n\n"
        f"Transcript:\n{transcript}"
    )[:MAX_PROMPT - 600]
    out = await arena_oneoff(model_id, model_name, prompt, jar)
    return out.strip() if out and len(out) > 30 else None


async def generate_title(user_msg: str, assistant_reply: str) -> str:
    jar = acquire_jar()
    if jar:
        models = get_selectable_models()
        if models:
            fast_model = models[0]
            prompt = (
                "Provide a concise title (3-6 words) for this conversation. No quotes or punctuation.\n\n"
                f"User: {user_msg[:300]}\nAssistant: {assistant_reply[:300]}\n\nTitle:"
            )
            title = await arena_oneoff(fast_model["id"], fast_model.get("publicName", ""), prompt, jar)
            if title:
                cleaned = title.strip().strip("\"'`").replace("\n", " ")
                cleaned = re.sub(r"^(Title:\s*|Chat:\s*)", "", cleaned, flags=re.IGNORECASE).strip()
                if 2 <= len(cleaned) <= 60:
                    return cleaned
    words = re.sub(r"^(please\s+|can\s+you\s+|how\s+to\s+|what\s+is\s+)", "", user_msg, flags=re.IGNORECASE).strip().split()
    return " ".join(words[:6])[:48].capitalize() if words else "New chat"


# ============================================================
# MASTER CHAT ROUTER
# ============================================================

# Chat completions — classic curl_cffi path (no browser tabs)

async def _stream_via_existing_page(session, url: str, payload: dict, model_name: str):
    """POST from the keeper's already-open page (NO new tabs). Closest to official site."""
    page = session.page
    if not page or page.is_closed():
        yield ("error", "No open page on keeper")
        return
    try:
        # Ensure we're on arena so cookies/origin match
        cur = page.url or ""
        if "arena.ai" not in cur and "lmarena.ai" not in cur:
            try:
                await page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded", timeout=20000)
            except Exception:
                pass
        result = await page.evaluate(
            """async ({url, payload}) => {
                try {
                    const resp = await fetch(url, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Accept': 'text/event-stream,*/*',
                        },
                        body: JSON.stringify(payload),
                        credentials: 'include',
                    });
                    const text = await resp.text();
                    return { status: resp.status, body: text };
                } catch (e) {
                    return { status: 0, body: String(e) };
                }
            }""",
            {"url": url, "payload": payload},
        )
    except Exception as e:
        yield ("error", f"In-page fetch failed: {e}")
        return

    status = (result or {}).get("status") or 0
    body = (result or {}).get("body") or ""
    if status != 200:
        yield ("http_error", status, body)
        return

    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("data: "):
            line = line[6:].strip()
            if not line:
                continue
        colon = line.find(":")
        if colon < 0:
            continue
        prefix, payload_s = line[:colon], line[colon + 1:]
        if prefix in ("a0", "0"):
            try:
                t = json.loads(payload_s)
                if isinstance(t, str):
                    yield ("content", t)
            except json.JSONDecodeError:
                continue
        elif prefix in ("ag", "g"):
            try:
                t = json.loads(payload_s)
                if isinstance(t, str):
                    yield ("reasoning", t)
            except json.JSONDecodeError:
                continue
        elif prefix in ("a3", "3", "e"):
            try:
                err = json.loads(payload_s)
                msg = err if isinstance(err, str) else json.dumps(err)
            except json.JSONDecodeError:
                msg = payload_s
            yield ("error", f"Stream Error: {msg}")
            return
        elif prefix in ("ad", "d"):
            try:
                md = json.loads(payload_s)
                yield ("finish", md.get("finishReason", "stop"))
            except json.JSONDecodeError:
                continue


async def stream_arena_chat(model_id, model_name, prompt, attachments, conv_key, jar,
                            prior_messages=None, is_api=False, request_user_count=None):
    """Stream a chat turn using curl_cffi + jar cookies.

    Same approach as the original working code:
      - HTTP via curl_cffi (no page.evaluate / no extra tabs)
      - Cookies harvested from a live keeper when available
      - reCAPTCHA token read from a live keeper page when available
      - Jar rotation on 401/403/429
    """
    jar_id = jar["id"]
    stream_arena_chat._cleared_once = False

    def _curl_headers(j):
        headers = build_request_headers(j)
        for k in list(headers.keys()):
            if k.lower() in (
                "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
            ):
                headers.pop(k, None)
        return headers

    def _find_live_session(prefer_jar_id=None):
        """Return (jar_id, session) for a running keeper with an open page."""
        # Prefer the jar we already selected
        if prefer_jar_id:
            s = keeper.sessions.get(prefer_jar_id)
            if s and s.running and getattr(s, "page", None) and not s.page.is_closed():
                return prefer_jar_id, s
        # Any other live session
        for sid, s in list(keeper.sessions.items()):
            if s and s.running and getattr(s, "page", None) and not s.page.is_closed():
                return sid, s
        return None, None

    async def _refresh_cookies_from_live(j, jid):
        sid, s = _find_live_session(jid)
        if not s:
            return j
        try:
            now = time.time()
            last = getattr(s, "last_harvest_time", 0)
            if now - last > 60:
                await s._harvest_cookies()
                s.last_harvest_time = now
            live = await get_live_cookies(sid)
            if live:
                j = dict(j)
                j["cookies"] = live
        except Exception as e:
            log("WARN", f"Cookie harvest from live session failed: {e}")
        return j

    async def _get_recaptcha_token():
        """Primary: reCAPTCHA v3 / existing response from any live page.
        Fallback: ask the keeper to solve an image challenge if one is open.
        """
        sid, s = _find_live_session()
        if not s:
            return None
        try:
            # 1) Prefer an already-solved / v3 token
            token = await s.page.evaluate("""async () => {
                try {
                    const el = document.querySelector(
                        'textarea[name="g-recaptcha-response"], #g-recaptcha-response, textarea.g-recaptcha-response'
                    );
                    if (el && el.value && el.value.length > 20) return el.value;
                } catch (e) {}
                try {
                    if (window.grecaptcha) {
                        if (typeof grecaptcha.getResponse === 'function') {
                            const t = grecaptcha.getResponse();
                            if (t && t.length > 20) return t;
                        }
                        // reCAPTCHA v3 execute
                        let sitekey = null;
                        const node = document.querySelector('[data-sitekey]');
                        if (node) sitekey = node.getAttribute('data-sitekey');
                        if (!sitekey && window.___grecaptcha_cfg && ___grecaptcha_cfg.clients) {
                            try {
                                const clients = Object.values(___grecaptcha_cfg.clients);
                                for (const c of clients) {
                                    const k = c?.sitekey || c?.settings?.sitekey;
                                    if (k) { sitekey = k; break; }
                                }
                            } catch (e) {}
                        }
                        if (typeof grecaptcha.execute === 'function' && sitekey) {
                            try {
                                const t = await grecaptcha.execute(sitekey, {action: 'submit'});
                                if (t && t.length > 20) return t;
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
                return null;
            }""")
            if token:
                return token
        except Exception as e:
            log("WARN", f"v3 token read failed: {e}")

        # 2) Fallback: image challenge solver on the live page
        try:
            if hasattr(s, "solve_recaptcha_image_challenge"):
                ok = await s.solve_recaptcha_image_challenge()
                if ok:
                    token = await s.page.evaluate("""() => {
                        const el = document.querySelector(
                            'textarea[name="g-recaptcha-response"], #g-recaptcha-response'
                        );
                        return (el && el.value) ? el.value : null;
                    }""")
                    if token:
                        return token
        except Exception as e:
            log("WARN", f"Image captcha solve failed: {e}")
        return None

    # Fresh cookies from live keeper if possible
    jar = await _refresh_cookies_from_live(jar, jar_id)
    # NOTE: no pre-pin here anymore. jar_proxy()'s md5 hashing assigned (and
    # persisted) a pool slot per jar BEFORE the live sweep ran, so the sweep
    # short-circuited on "sticky alive" forever — that was the not-round-
    # robbing bug. Proxy selection now happens per attempt: apick_live_proxy
    # (shared RR cursor) + anchor_proxy_to_keeper (cf_clearance IP alignment).

    # Drop stale soft-limits so a previous 429 doesn't poison the pool
    def _clear_stale_limits(jars):
        now = time.time()
        for j in jars:
            if j.get("limited_until", 0) and j["limited_until"] < now + 3600:
                j["limited_until"] = 0
                if j.get("status") == "limited":
                    j["status"] = "ok"
    try:
        mutate_jars(_clear_stale_limits)
    except Exception:
        pass

    tried_jar_ids = {jar_id}
    cf_clear_attempts = 0
    same_jar_429 = 0  # consecutive 429s on current jar
    max_attempts = 6  # fixed budget — do NOT burn entire pool on IP rate-limits

    for attempt in range(max_attempts):
        conv = get_conversation(conv_key)
        model_conv = conv["arena"].get(model_name) if conv.get("model") == model_name else None
        follow = model_conv is not None
        if is_api and follow and request_user_count is not None:
            follow = request_user_count == conv.get("user_count", 0) + 1

        if follow:
            content_to_send = prompt
            base = {
                "id": model_conv["arena_id"],
                "mode": "direct",
                "modelAId": model_id,
                "userMessageId": str(uuid7()),
                "modelAMessageId": str(uuid7()),
                "modality": "chat",
            }
            url = f"{ARENA_BASE}/nextjs-api/stream/post-to-evaluation/{model_conv['arena_id']}"
        else:
            prior = list(prior_messages) if is_api else list(conv.get("history") or [])
            prior = [x for x in prior if isinstance(x, dict) and x.get("content")]
            preamble = build_preamble(prior)
            if preamble:
                content_to_send = (
                    "=== PREVIOUS CONVERSATION (context) ===\n\n"
                    f"{preamble}\n\n"
                    "=== CURRENT USER MESSAGE  REPLY TO THIS ===\n\n"
                    f"{prompt}"
                )
            else:
                content_to_send = prompt
            base = {
                "id": str(uuid7()),
                "mode": "direct-battle",
                "modelAId": model_id,
                "userMessageId": str(uuid7()),
                "modelAMessageId": str(uuid7()),
                "modality": "chat",
            }
            url = f"{ARENA_BASE}/nextjs-api/stream/create-evaluation"

            # Attach recaptcha token when a live page has one (same as old code)
            token = await _get_recaptcha_token()
            if token:
                base["recaptchaToken"] = token
                base["recaptcha"] = token
                base["captchaToken"] = token
                base["g-recaptcha-response"] = token
                log("INFO", f"[{jar_id}] recaptcha token attached ({len(token)} chars)")
            else:
                # Old code failed hard here for new chats. We still try the request —
                # many authenticated sessions work without an explicit token.
                log("WARN", f"[{jar_id}] No recaptcha token available — sending without it")

        user_message = {"content": content_to_send}
        if attachments:
            user_message["experimental_attachments"] = attachments
        base["userMessage"] = user_message

        if not jar_has_auth(jar):
            # Try another jar that has auth or a live session
            next_jar = acquire_jar(prefer_live=True)
            if next_jar and next_jar["id"] not in tried_jar_ids:
                jar = next_jar
                jar_id = jar["id"]
                tried_jar_ids.add(jar_id)
                jar = await _refresh_cookies_from_live(jar, jar_id)
                continue
            yield ("error", "502: Arena cookies expired — enable keeper and re-login for this account")
            return

        response_text = ""
        reasoning_text = ""
        error_message = None

        try:
            headers = _curl_headers(jar)
            proxy = await apick_live_proxy(jar, purpose="api")
            proxy, _cycled = await anchor_proxy_to_keeper(jar_id, proxy)
            if _cycled:
                jar = await _refresh_cookies_from_live(jar, jar_id)   # fresh clearance+auth from the new exit
            elif proxy:
                jar = dict(jar); jar["proxy"] = proxy; jar["_last_proxy"] = proxy
            if proxy:
                log("INFO", f"[{jar_id}] curl via proxy {proxy.split('@')[-1] if '@' in proxy else proxy}")
            else:
                log("WARN", f"[{jar_id}] No live proxy — using server IP (easy to rate-limit)")
            _t0 = time.monotonic()
            async with AsyncSession(impersonate="chrome131") as client:
                try:
                    post_kw = dict(json=base, headers=headers, stream=True, timeout=120.0)
                    if proxy:
                        post_kw["proxy"] = proxy
                    # TTFB watchdog: a stalled exit used to eat the full 120s and the
                    # curl error it eventually raised wasn't even recognized as proxy
                    # death. Healthy streams return headers in seconds — and a proxy
                    # with a known latency now gets a budget fit to ITS speed.
                    resp = await asyncio.wait_for(client.post(url, **post_kw), timeout=_ttfb_budget(proxy))
                except asyncio.TimeoutError:
                    if proxy:
                        quarantine_proxy(proxy, "curl: no response headers before TTFB watchdog")
                        if attempt + 1 < max_attempts:
                            log("WARN", f"[{jar_id}] curl TTFB timeout via "
                                        f"{proxy.split('@')[-1] if '@' in proxy else proxy} — quarantined, trying next")
                            continue
                    yield ("error", f"502: every proxy stalled before first byte (watchdog {CURL_TTFB_TIMEOUT:.0f}s)")
                    return
                except Exception as e:
                    _msg = str(e)
                    _low = _msg.lower()
                    _dead = ("failed to perform" in _low or "connect" in _low or "tunnel" in _low
                             or "timed out" in _low or "timeout" in _low or "reset" in _low
                             or "refused" in _low or "resolve" in _low or re.search(r"code \d+", _low) is not None)
                    if proxy and _dead:
                        quarantine_proxy(proxy, f"curl: {_msg[:90]}")
                        if attempt + 1 < max_attempts:
                            log("WARN", f"[{jar_id}] proxy {proxy.split('@')[-1] if '@' in proxy else proxy} "
                                        f"dead mid-flight — quarantined, next attempt sweeps the pool")
                            continue
                        yield ("error", f"502: Network error (all proxies down): {_msg}")
                        return
                    yield ("error", f"Network error: {_msg}")
                    return

                if resp.status_code != 200:
                    raw = b""
                    async for chunk in resp.aiter_content():
                        raw += chunk if isinstance(chunk, (bytes, bytearray)) else str(chunk).encode("utf-8", errors="ignore")
                    body = raw.decode("utf-8", errors="ignore")
                    log("ERROR", f"Status {resp.status_code}, URL {url}, Mode {base.get('mode')}, modelAId {model_id}, Body: {body[:1500]}")

                    if resp.status_code in (401, 403):
                        if "cloudflare" in body.lower() or "just a moment" in body.lower():
                            # cf_clearance is bound to IP+UA: a healthy Live Browser
                            # does NOT mean curl is cleared. One self-repair per
                            # request: cycle the keeper (it re-solves the challenge
                            # on the current exit) then re-harvest and retry.
                            if cf_clear_attempts < 1 and keeper.sessions.get(jar_id):
                                cf_clear_attempts += 1
                                s_ = keeper.sessions.get(jar_id)
                                log("WARN", f"[{jar_id}] CF challenge on curl exit "
                                            f"{proxy.split('@')[-1] if proxy else 'DIRECT'} — cycling keeper to re-clear")
                                try:
                                    await s_.restart()
                                    s_.last_harvest_time = 0
                                except Exception as e:
                                    log("WARN", f"[{jar_id}] keeper cycle failed: {e}")
                                jar = await _refresh_cookies_from_live(jar, jar_id)
                                continue
                            # keeper re-clear didn't help → this exit is flagged. Don't die here:
                            # record the flag (picker skips it for _FLAGGED_TTL) and ROTATE to the
                            # next candidate — same jar — until success or the pool is used up.
                            if proxy and attempt + 1 < max_attempts:
                                note_cf_blocked_exit(proxy, "persistent 403 challenge after keeper re-clear")
                                log("WARN", f"[{jar_id}] exit {proxy.split('@')[-1] if '@' in proxy else proxy} "
                                            f"CF-flagged — rotating to another proxy (attempt {attempt + 2}/{max_attempts})")
                                continue
                            yield ("error", "502: Arena's Cloudflare flagged every exit IP we tried "
                                            "(they get skipped for a few hours). Retry shortly, add more "
                                            "residential proxies, or solve once in Live Browser on a clean exit.")
                            return
                        # Harvest + retry same jar once, then rotate
                        jar = await _refresh_cookies_from_live(jar, jar_id)
                        if jar_has_auth(jar) and attempt == 0:
                            log("WARN", f"[{jar_id}] HTTP {resp.status_code} — harvested cookies, retrying")
                            continue
                        mark_jar_status(jar_id, "expired")
                        next_jar = acquire_jar(prefer_live=True)
                        if next_jar and next_jar["id"] not in tried_jar_ids:
                            log("WARN", f"[{jar_id}] Session expired — rotating to '{next_jar.get('name')}'")
                            jar = next_jar
                            jar_id = jar["id"]
                            tried_jar_ids.add(jar_id)
                            jar = await _refresh_cookies_from_live(jar, jar_id)
                            continue
                        yield ("error", "502: Arena session expired — no other healthy accounts left")
                        return

                    if resp.status_code == 429:
                        # IP-level limits are common: rotating every jar instantly makes it worse.
                        # Retry same jar with backoff, then at most ONE other jar.
                        same_jar_429 += 1
                        wait_s = min(8, 1.5 * same_jar_429)
                        log("WARN", f"[{jar_id}] Arena 429 — waiting {wait_s:.1f}s then retry (try {same_jar_429})")
                        # Never hard-lock the pool
                        def _soft_clear(jars):
                            for j in jars:
                                j["limited_until"] = 0
                                if j.get("status") == "limited":
                                    j["status"] = "ok"
                        mutate_jars(_soft_clear)
                        await asyncio.sleep(wait_s)
                        jar = await _refresh_cookies_from_live(jar, jar_id)
                        # refresh captcha token for next create attempt
                        if not follow:
                            token = await _get_recaptcha_token()
                            if token:
                                base["recaptchaToken"] = token
                                base["recaptcha"] = token
                                base["captchaToken"] = token
                                base["g-recaptcha-response"] = token
                        if same_jar_429 < 3:
                            jar = dict(jar)
                            nxt = await apick_live_proxy(jar, purpose="429", rotate=True)
                            if nxt:
                                log("INFO", f"[{jar_id}] 429 → rotated (probed-live) proxy {nxt.split('@')[-1] if '@' in nxt else nxt}")
                            continue  # same jar, new IP
                        # One alternate jar only
                        next_jar = acquire_jar(prefer_live=True)
                        if next_jar and next_jar["id"] not in tried_jar_ids:
                            log("WARN", f"[{jar_id}] Still 429 — one alternate jar '{next_jar.get('name')}'")
                            jar = next_jar
                            jar_id = jar["id"]
                            tried_jar_ids.add(jar_id)
                            same_jar_429 = 0
                            jar = await _refresh_cookies_from_live(jar, jar_id)
                            continue
                        yield ("error", "429: Arena is rate-limiting this IP/session. Wait 30-60s then retry — accounts are fine.")
                        return

                    if resp.status_code in (500, 502, 503, 504) or 520 <= resp.status_code <= 527:
                        # Cloudflare↔origin trouble (524 = origin >100s silent; 521/522/523 = down/SSL/unreachable).
                        # This is Arena's backend stalling — cookies, proxies and keepers are innocent.
                        # Same jar, polite backoff, bounded retries; never cycle keeper / expire jar for this.
                        note_upstream_degraded(str(resp.status_code))
                        wait_s = 2.5 * (attempt + 1)
                        log("WARN", f"[{jar_id}] Arena upstream {resp.status_code} (origin timeout/overload) — "
                                    f"backoff {wait_s:.0f}s, retry {attempt + 1}/{max_attempts}")
                        await asyncio.sleep(wait_s)
                        continue

                    # Captcha rejection — try to grab a fresh token and retry once
                    if "captcha" in body.lower() or "recaptcha" in body.lower():
                        token = await _get_recaptcha_token()
                        if token and "recaptchaToken" not in base:
                            base["recaptchaToken"] = token
                            base["recaptcha"] = token
                            base["captchaToken"] = token
                            base["g-recaptcha-response"] = token
                            log("WARN", f"[{jar_id}] Captcha rejected — retrying with fresh token")
                            continue
                        yield ("error", f"{resp.status_code}: captcha required — open Live Browser, solve captcha, retry")
                        return

                    yield ("error", f"{resp.status_code}: {body[:400] or '(empty body)'}")
                    return

                _upstream_hits.clear()   # origin is answering again — strikes forgiven
                if proxy:
                    _ms = int((time.monotonic() - _t0) * 1000)
                    if 0 < _ms < 60000:
                        # real traffic is the best health probe there is: it keeps the
                        # picker from re-probing on the next message (15-min fresh
                        # window) and teaches _ttfb_budget how fast this exit is
                        _proxy_latency[proxy] = _ms
                        _proxy_probe_cache[proxy] = (True, time.time() + PROBE_OK_TTL)
                        _proxy_health_record(proxy, True, _ms, source="stream")
                    if _proxy_hkey(proxy) in _flagged_exits:
                        _flagged_exits.pop(_proxy_hkey(proxy), None)   # 200 IS the proof: un-flag now
                        log("INFO", f"[{jar_id}] exit {proxy.split('@')[-1] if '@' in proxy else proxy} "
                                    f"delivered 200 in {_ms} ms — Arena-block flag lifted early")
                buffer = b""
                async for chunk in resp.aiter_content():
                    if not chunk:
                        continue
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", errors="ignore")
                    buffer += chunk
                    while b"\n" in buffer:
                        line_bytes, buffer = buffer.split(b"\n", 1)
                        line = line_bytes.decode("utf-8", errors="ignore").strip()
                        if not line:
                            continue
                        if line.startswith("data: "):
                            line = line[6:].strip()
                            if not line:
                                continue
                        colon = line.find(":")
                        if colon < 0:
                            continue
                        prefix, payload = line[:colon], line[colon + 1:]
                        if prefix in ("a0", "0"):
                            try:
                                t = json.loads(payload)
                                if isinstance(t, str):
                                    response_text += t
                                    yield ("content", t)
                            except json.JSONDecodeError:
                                continue
                        elif prefix in ("ag", "g"):
                            try:
                                t = json.loads(payload)
                                if isinstance(t, str):
                                    reasoning_text += t
                                    yield ("reasoning", t)
                            except json.JSONDecodeError:
                                continue
                        elif prefix in ("a3", "3", "e"):
                            try:
                                err = json.loads(payload)
                                error_message = err if isinstance(err, str) else json.dumps(err)
                            except json.JSONDecodeError:
                                error_message = payload
                            yield ("error", f"Stream Error: {error_message}")
                            return
                        elif prefix in ("ad", "d"):
                            try:
                                md = json.loads(payload)
                                yield ("finish", md.get("finishReason", "stop"))
                            except json.JSONDecodeError:
                                continue

            if not response_text and not reasoning_text:
                yield ("error", error_message or "502: Arena returned empty response")
                return

            conv2 = get_conversation(conv_key)
            conv2["arena"][model_name] = {"arena_id": base["id"], "mode": "direct"}
            conv2["model"] = model_name
            if is_api and request_user_count is not None:
                conv2["user_count"] = request_user_count
            if not is_api:
                conv2["history"].append({"role": "user", "content": prompt})
                conv2["history"].append({
                    "role": "assistant",
                    "content": response_text.strip() or reasoning_text.strip(),
                })
                conv2["history"] = conv2["history"][-200:]
            save_conversation(conv_key, conv2)
            yield ("done", {"mode": "direct", "content_len": len(response_text), "reasoning_len": len(reasoning_text)})
            return

        except ConversationLost as e:
            log("WARN", f"Upstream session lost ({str(e)[:120]})")
            conv2 = get_conversation(conv_key)
            conv2["arena"].pop(model_name, None)
            save_conversation(conv_key, conv2)
            continue
        except Exception as e:
            log("ERROR", f"[{jar_id}] stream_arena_chat exception: {type(e).__name__}: {e}")
            yield ("error", f"502: {type(e).__name__}: {e}")
            return

    yield ("error", "Arena request failed after retries. If accounts work in the browser, wait 30s and try again (IP rate-limit), or open Live Browser and send one message.")


# ============================================================
# IMAGE UPLOAD PIPELINE
# ============================================================

async def upload_image_to_arena(image_data: bytes, mime_type: str, filename: str) -> Optional[tuple]:
    jar = acquire_jar()
    if not jar:
        return None
    try:
        if not image_data or not mime_type.startswith("image/"):
            return None
        raw_headers = build_request_headers(jar)
        rh = {k: v for k, v in raw_headers.items() if k not in ["User-Agent", "sec-ch-ua", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site"]}
        rh.update({
            "Accept": "text/x-component", "Content-Type": "text/plain;charset=UTF-8",
            "Next-Action": "70cb393626e05a5f0ce7dcb46977c36c139fa85f91",
            "Referer": f"{ARENA_BASE}/?mode=direct",
        })
        async with AsyncSession(impersonate="chrome131") as client:
            response = await client.post(f"{ARENA_BASE}/?mode=direct", headers=rh, data=json.dumps([filename, mime_type]), timeout=30.0)
            if response.status_code != 200:
                return None
            upload_data = None
            for line in (response.text or "").strip().split("\n"):
                if line.startswith("1:"):
                    upload_data = json.loads(line[2:])
                    break
            if not upload_data or not upload_data.get("success"):
                return None
            upload_url = upload_data["data"]["uploadUrl"]
            key = upload_data["data"]["key"]
            response = await client.put(upload_url, data=image_data, headers={"Content-Type": mime_type}, timeout=60.0)
            if response.status_code not in (200, 201, 204):
                return None
            step3 = rh.copy()
            step3["Next-Action"] = "6064c365792a3eaf40a60a874b327fe031ea6f22d7"
            response = await client.post(f"{ARENA_BASE}/?mode=direct", headers=step3, data=json.dumps([key]), timeout=30.0)
            if response.status_code != 200:
                return None
            download_data = None
            for line in (response.text or "").strip().split("\n"):
                if line.startswith("1:"):
                    download_data = json.loads(line[2:])
                    break
            if not download_data or not download_data.get("success"):
                return None
            log("OK", f"Image written to R2 storage: {key}")
            return (key, download_data["data"]["url"])
    except Exception as e:
        log("ERROR", f"Image upload failed: {type(e).__name__}: {e}")
        return None
async def process_message_content(content, model_capabilities: dict):
    supports_images = model_capabilities.get("inputCapabilities", {}).get("image", False)
    if isinstance(content, str):
        return content, []
    if isinstance(content, list):
        text_parts, attachments = [], []
        for part in content:
            if not isinstance(part, dict):
                continue
            if part.get("type") == "text":
                text_parts.append(part.get("text", ""))
            elif part.get("type") == "image_url" and supports_images:
                image_url = part.get("image_url", {})
                url = image_url.get("url", "") if isinstance(image_url, dict) else image_url
                if url.startswith("data:"):
                    try:
                        if "," not in url:
                            continue
                        header, data = url.split(",", 1)
                        if ";" not in header or ":" not in header:
                            continue
                        mime_type = header.split(";")[0].split(":")[1]
                        if not mime_type.startswith("image/"):
                            continue
                        image_data = base64.b64decode(data)
                        if len(image_data) > 10 * 1024 * 1024:
                            continue
                        ext = mimetypes.guess_extension(mime_type) or ".png"
                        result = await upload_image_to_arena(image_data, mime_type, f"upload-{uuid.uuid4()}{ext}")
                        if result:
                            key, dl_url = result
                            attachments.append({"name": key, "contentType": mime_type, "url": dl_url})
                    except Exception as e:
                        log("WARN", f"Base64 image processing failed: {e}")
        return "\n".join(text_parts).strip(), attachments
    return str(content), []


# ============================================================
# FASTAPI APPLICATION & LIFESPAN
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(keeper_election_loop())
    asyncio.create_task(periodic_model_refresher())
    asyncio.create_task(get_initial_data())
    asyncio.create_task(auto_login_on_boot())
    yield


async def auto_login_on_boot():
    """Auto-start keeper sessions for all accounts with email+password on boot.
    Checks if already authenticated first to avoid unnecessary login.
    Works headless (no display required)."""
    await asyncio.sleep(5)  # Let the app fully start
    jars = load_jars()
    accounts_with_creds = [j for j in jars if j.get("email") and j.get("password") and j.get("enabled", True)]
    if not accounts_with_creds:
        log("INFO", "Auto-login: No accounts with credentials found, skipping")
        return

    log("INFO", f"Auto-login: Starting keeper sessions for {len(accounts_with_creds)} account(s)...")

    # Enable keeper for all accounts with credentials
    def enable_keepers(jars_list):
        for j in jars_list:
            if j.get("email") and j.get("password") and j.get("enabled", True):
                j["keeper_enabled"] = True
    mutate_jars(enable_keepers)

    # Give the election loop time to pick them up
    await asyncio.sleep(3)

    # The keeper_election_loop / sync() will now start sessions for all keeper_enabled jars
    # and the start() method already does health check + relogin if needed
    log("INFO", f"Auto-login: {len(accounts_with_creds)} account(s) queued for keeper sessions")

BUILD_STAMP = "r6.2-tailwind-fastpath"
app = FastAPI(title="Bridgena", version="1.0", lifespan=lifespan)
log("INFO", f"BRIDGENA build {BUILD_STAMP} · deep-Arena proxy verification · CF-flag rotation ON")
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


async def get_current_session(request: Request) -> Optional[str]:
    # Stateless signed cookie — works across all uvicorn workers
    sid = request.cookies.get("session_id")
    if not sid:
        return None
    user = verify_session_token(sid)
    if user:
        return user
    # Legacy in-memory fallback (single-worker only)
    if sid in dashboard_sessions:
        return dashboard_sessions[sid]
    return None


async def verify_api_key(request: Request,
                         authorization: Optional[str] = Depends(api_key_header),
                         x_api_key: Optional[str] = Header(None)) -> dict:
    # Allow authenticated web sessions to use the API without a key (multi-worker safe)
    sid = request.cookies.get("session_id")
    if sid and (verify_session_token(sid) or sid in dashboard_sessions):
        return {"name": "web-session", "rpm": 120, "key": "web-session"}

    cfg = get_config()
    keys = cfg.get("api_keys", [])
    if not keys:
        return {"name": "default", "rpm": 60}
    token = None
    if authorization:
        token = authorization[7:].strip() if authorization.startswith("Bearer ") else authorization.strip()
    elif x_api_key:
        token = x_api_key.strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing API Key")
    matched = next((k for k in keys if k.get("key") == token), None)
    if not matched:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    rpm = matched.get("rpm", 60)
    rate_res = check_rate_limit(token, rpm)
    if not rate_res["ok"]:
        raise HTTPException(status_code=429, detail=f"Rate limit of {rpm} RPM exceeded. Retry in {rate_res['retry']}s.")
    return matched


# ============================================================
# DEBUG ROUTES
# ============================================================

@app.get("/screenshots")
async def list_screenshots():
    files = glob.glob("*.png")
    files.sort(key=os.path.getmtime, reverse=True)
    html = "<h1>Screenshots</h1><ul>"
    for f in files:
        html += f'<li><a href="/screenshots/{f}">{f}</a></li>'
    html += "</ul>"
    return HTMLResponse(html)

@app.get("/screenshots/{filename}")
async def get_screenshot(filename: str):
    if not os.path.exists(filename) or not filename.endswith(".png"):
        return Response(status_code=404)
    return FileResponse(filename)

# ============================================================
# PROXY MANAGER API (Dashboard → Proxy Pool tab)
# ============================================================

@app.get("/proxies/api/snapshot")
async def proxies_api_snapshot(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    rows = proxies_snapshot()
    live = sum(1 for r in rows if r["status"] == "live")
    dead = sum(1 for r in rows if r["status"] == "dead")
    blocked = sum(1 for r in rows if r["status"] == "blocked")
    lats = sorted(r["latency"] for r in rows if isinstance(r["latency"], int) and r["latency"] >= 0)
    return {
        "rows": rows[:800], "total": len(rows), "live": live, "dead": dead, "blocked": blocked,
        "median_ms": lats[len(lats) // 2] if lats else None,
        "quarantined": len(_QUARANTINED_KEYS),
        "checking": _proxy_check_state["running"],
        "progress": {"done": _proxy_check_state["done"], "total": _proxy_check_state["total"]},
    }


@app.post("/proxies/api/check")
async def proxies_api_check(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    started = await proxy_check_start()
    return {"started": started, "already_running": not started}


@app.post("/proxies/api/upload")
async def proxies_api_upload(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="send JSON {text: ...}")
    urls, parsed, skipped = parse_proxy_blob(str(body.get("text") or ""))
    pool = get_proxy_pool()
    have = {_proxy_hkey(u) for u in pool}
    fresh = []
    for u in urls:
        k = _proxy_hkey(u)
        if k and k not in have:
            have.add(k)
            fresh.append(u)
    if fresh:
        _proxies_pool_write(pool + fresh)
        log("OK", f"proxy manager: +{len(fresh)} from upload/paste ({parsed} parsed, {skipped} skipped)")
    return {"added": len(fresh), "parsed": parsed, "skipped_dupes_or_bad": skipped,
            "total": len(get_proxy_pool())}


@app.post("/proxies/api/prune")
async def proxies_api_prune(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    mode = str(body.get("mode") or "dead")
    if mode not in ("dead", "slow", "unchecked", "blocked", "bad"):
        raise HTTPException(status_code=400, detail="mode: dead|slow|unchecked|blocked|bad")
    try:
        slow_ms = max(100, int(body.get("slow_ms") or 1000))
    except Exception:
        slow_ms = 1000
    removed = proxy_prune(mode, slow_ms)
    return {"removed": removed, "total": len(get_proxy_pool())}


@app.post("/proxies/api/remove-one")
async def proxies_api_remove_one(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="send JSON {host: 'ip:port'}")
    host = str(body.get("host") or "").strip()
    if not host:
        raise HTTPException(status_code=400)
    pool = get_proxy_pool()
    keep = [u for u in pool if _proxy_hkey(u) != host]
    if len(keep) == len(pool):
        raise HTTPException(status_code=404, detail="host not in pool")
    dead_path = os.path.join(os.path.dirname(_proxies_file() or os.path.join(os.getcwd(), "x")), "proxies.dead.txt")
    try:
        with open(dead_path, "a", encoding="utf-8") as f:
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            for u in pool:
                if _proxy_hkey(u) == host:
                    f.write(f"# {stamp} removed from UI\n{u}\n")
    except Exception:
        pass
    _proxies_pool_write(keep)
    for u in pool:
        if _proxy_hkey(u) == host:
            _QUARANTINED_KEYS.add(host)
            _proxy_probe_cache[u] = (False, time.time() + 86400.0)
            _proxy_latency.pop(u, None)
    return {"removed": len(pool) - len(keep), "total": len(keep)}


@app.post("/proxies/api/revive")
async def proxies_api_revive(request: Request):
    if not await get_current_session(request):
        raise HTTPException(status_code=401)
    return {"revived": proxies_revive_all(), "total": len(get_proxy_pool())}


# ============================================================
# ROOT ROUTE
# ============================================================

@app.get("/")
async def root(request: Request):
    if await get_current_session(request):
        return RedirectResponse(url="/chat")
    return RedirectResponse(url="/login")


# ============================================================
# OPENAI COMPATIBLE ENDPOINTS
# ============================================================

@app.get("/v1/models")
@app.get("/models")
async def list_models(_auth=Depends(verify_api_key)):
    arena_m = get_selectable_models()
    ox_m = oxalpha_models()
    data = []
    ts = int(time.time())
    for m in arena_m:
        data.append({"id": m.get("publicName"), "object": "model", "created": ts, "owned_by": m.get("organization", "arena.ai")})
    for m in ox_m:
        data.append({"id": m["id"], "object": "model", "created": ts, "owned_by": m["owned_by"]})
    return {"object": "list", "data": data}


@app.get("/v1/models/{model_id:path}")
@app.get("/models/{model_id:path}")
async def retrieve_model(model_id: str, _auth=Depends(verify_api_key)):
    models = get_selectable_models() + oxalpha_models()
    m = next((x for x in models if x.get("publicName") == model_id or x.get("id") == model_id), None)
    if not m:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    return {"id": m.get("publicName") or m.get("id"), "object": "model", "created": int(time.time()),
            "owned_by": m.get("organization") or m.get("owned_by", "arena.ai")}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request, _auth=Depends(verify_api_key)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    model_name = body.get("model")
    messages = body.get("messages", [])
    stream = body.get("stream", False)
    if not model_name:
        raise HTTPException(status_code=400, detail="Field 'model' is required")
    if not messages or not isinstance(messages, list):
        raise HTTPException(status_code=400, detail="Field 'messages' must be a non-empty list")

    # OX Alpha route
    if model_name in OX_ALIASES:
        record_usage(OX_MODEL_ID)
        
        sanitized_messages = []
        for m in messages:
            r = m.get("role", "user")
            if r == "system": r = "user"
            c = m.get("content", "")
            if not sanitized_messages:
                sanitized_messages.append({"role": r, "content": c})
            elif sanitized_messages[-1]["role"] == r:
                sanitized_messages[-1]["content"] += "\n\n" + c
            else:
                sanitized_messages.append({"role": r, "content": c})
        
        if stream:
            async def sse_gen():
                comp_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
                ts = int(time.time())
                async for t, chunk in stream_oxalpha(sanitized_messages, model=model_name):
                    if t == "content":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_name, 'choices': [{'index': 0, 'delta': {'content': chunk}, 'finish_reason': None}]})}\n\n"
                    elif t == "reasoning":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_name, 'choices': [{'index': 0, 'delta': {'reasoning_content': chunk}, 'finish_reason': None}]})}\n\n"
                    elif t == "error":
                        err_obj = {"error": {"message": str(chunk), "type": "upstream_error"}}
                        yield f"data: {json.dumps(err_obj)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    elif t == "finish":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_name, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': chunk}]})}\n\n"
                
                # If we didn't explicitly get a 'finish' tag, send a final stop
                yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_name, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                yield "data: [DONE]\n\n"
            return StreamingResponse(sse_gen(), media_type="text/event-stream")
        else:
            full_content, full_reasoning = "", ""
            async for t, chunk in stream_oxalpha(sanitized_messages, model=model_name):
                if t == "content":
                    full_content += chunk
                elif t == "reasoning":
                    full_reasoning += chunk
            return {"id": f"chatcmpl-{uuid.uuid4().hex[:12]}", "object": "chat.completion", "created": int(time.time()),
                    "model": model_name, "choices": [{"index": 0, "message": {"role": "assistant", "content": full_content, "reasoning_content": full_reasoning or None}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}

    # Arena route
    models = get_selectable_models()
    model_obj = next((m for m in models if m.get("publicName") == model_name or m.get("id") == model_name or m.get("name") == model_name), None)
    if not model_obj:
        sample_names = [m.get('publicName') or m.get('id') for m in models][:30]
        log("WARN", f"Model '{model_name}' not in catalog. Sample: {sample_names}")
        raise HTTPException(status_code=404, detail=f"Model '{model_name}' not found")
    model_id = model_obj["id"]
    model_public_name = model_obj.get("publicName", model_name)
    model_caps = model_obj.get("capabilities", {})
    _deg, _left = upstream_degraded()
    if _deg:
        # Arena's own origin is timing out (5xx/52x seen moments ago). Fail fast with a
        # clear retry-after instead of burning every account + proxy in the pool.
        raise HTTPException(
            status_code=503,
            detail=f"Arena upstream degraded (origin timeout). Retry in ~{int(_left)}s. "
                   f"Accounts/proxies are healthy — do not re-login.",
            headers={"Retry-After": str(max(5, int(_left)))},
        )
    jar = acquire_jar()
    if not jar:
        raise HTTPException(status_code=503, detail="No healthy accounts available.")
    record_usage(model_public_name)
    prior_messages = []
    last_msg = messages[-1]
    prompt_text, attachments = await process_message_content(last_msg.get("content", ""), model_caps)
    for msg in messages[:-1]:
        c_text, _ = await process_message_content(msg.get("content", ""), model_caps)
        prior_messages.append({"role": msg.get("role", "user"), "content": c_text})
    user_count = sum(1 for m in messages if m.get("role") == "user")
    req_hash = hashlib.sha256(json.dumps([m.get("content") for m in messages[:-1]], default=str).encode()).hexdigest()[:16]
    conv_key = f"api:{req_hash}"

    if stream:
        async def sse_gen():
            comp_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
            ts = int(time.time())
            try:
                async for ev in stream_arena_chat(model_id, model_public_name, prompt_text, attachments, conv_key, jar,
                                                  prior_messages=prior_messages, is_api=True, request_user_count=user_count):
                    t, v = ev
                    if t == "content":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_public_name, 'choices': [{'index': 0, 'delta': {'content': v}, 'finish_reason': None}]})}\n\n"
                    elif t == "reasoning":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_public_name, 'choices': [{'index': 0, 'delta': {'reasoning_content': v}, 'finish_reason': None}]})}\n\n"
                    elif t == "error":
                        err_obj = {"error": {"message": str(v), "type": "upstream_error"}}
                        yield f"data: {json.dumps(err_obj)}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    elif t == "finish":
                        yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_public_name, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': v}]})}\n\n"
                
                # Final chunk if no explicit finish was received
                yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_public_name, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
                yield "data: [DONE]\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'id': comp_id, 'object': 'chat.completion.chunk', 'created': ts, 'model': model_public_name, 'choices': [{'index': 0, 'delta': {'content': str(e)}, 'finish_reason': 'stop'}]})}\n\n"
                yield "data: [DONE]\n\n"
        return StreamingResponse(sse_gen(), media_type="text/event-stream")
    else:
        full_content, full_reasoning = "", ""
        async for ev in stream_arena_chat(model_id, model_public_name, prompt_text, attachments, conv_key, jar,
                                          prior_messages=prior_messages, is_api=True, request_user_count=user_count):
            t, v = ev
            if t == "content":
                full_content += v
            elif t == "reasoning":
                full_reasoning += v
            elif t == "error":
                raise HTTPException(status_code=502, detail=v)
        return {"id": f"chatcmpl-{uuid.uuid4().hex[:12]}", "object": "chat.completion", "created": int(time.time()),
                "model": model_public_name, "choices": [{"index": 0, "message": {"role": "assistant", "content": full_content, "reasoning_content": full_reasoning or None}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


# ============================================================
# ============================================================
# UI - MINIMALIST AUTHENTICATION & LOGIN (/login)
# ============================================================

LOGIN_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="bridgena-build" content="r6.2-tailwind-fastpath">
        <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena - Sign In</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,500;9..144,600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
                :root {
            --bg-base: #17131f;
            --bg-card: rgba(32,26,46,.84);
            --border: #372c55;
            --border-focus: #a78bfa;
            --text-main: #ece8f6;
            --text-muted: #a49bc4;
            --text-faint: #776e94;
            --accent: #a78bfa;
            --accent-text: #171126;
            --font-display: 'Fraunces','Iowan Old Style','Palatino Linotype','Book Antiqua',Georgia,serif;
            --font-ui: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            --hero: url('data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAwICQsJCAwLCgsODQwOEh4UEhEREiUbHBYeLCcuLisnKyoxN0Y7MTRCNCorPVM+QkhKTk9OLztWXFVMW0ZNTkv/2wBDAQ0ODhIQEiQUFCRLMisyS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0v/wgARCAQ4B4ADASIAAhEBAxEB/8QAGgABAQEBAQEBAAAAAAAAAAAAAAECAwQFBv/EABgBAQEBAQEAAAAAAAAAAAAAAAABAwIE/9oADAMBAAIQAxAAAAH8wOgAAAACoAAKEsCwUAAWgKhQAALAAAoQApFgWAAAABYAAksoCiBQlCWIAAAAAAAAAABUolLFgoACiUQAoAAWCy0CrKAFhKACyiwoBRFEoAFAAAEWCglgABBAoWAAAEUCkWACgAESgWKKRRFCqZULKFksUShVgCiRYCWIlhYBCAecdZgAAFgAWApKCKJRKAAUWAKsoAABQAAAQpKAgAWAAtJZFSkWAICgAAAASwiyqAlEUJRKEWAIAKSigCkAAqFlhZYWUCgUAAUoAFikUSgAKoBRFgUCkoARQlhFAAEWAEqkEKCURRCkUSgKRRFEqkUsVEURQKRRKKUSrEABNSiUsXMWCLAgJRFgBFh5x1kAoShFEUEoAFBAUAKQKsAoQKgsoKIoSgUAASgAEAAoSgARAAACUCFQUAEUJQAlBAsFikoRQAAAAspKAAAAoFCkBQoBRFAFlEoqUFAUAAKAAABAEWApAJQAAWQABZRKEUSgWCyrFAolgLAApFKlEqkpAEUSyrAEFSyQCAAAAlEUeUdZALBUosAVKRFhRQAACwFiqABBYCygApFhRQCBUoBYEUACFIWWApFkAAAShKBKAAAAJRFgWFAAAABQAAAAAUUAAooAApKAAFFFLKBRFApFgURQKRRARRBBYJRFEUAAABCykURSikWAomoACkUspBYVKAABAhSKIlgJQABFEVCUSwKEUeQdZAAVKAARVAAEosAAFItlhYBYFAAFikUBQCUACghZRJQAAlEoAQBRFEEAAAAAJQAlAAAAFSkKRQAAFLBQAAFAKUQCygAoFVKooAAoAAFLKClQRJSSglBZAAEUSglEUSqsoJRFRKBRKABRKKlAQKQBYCFRAhUBAoALKRURYWAAKJSxR4x1jYACgAFAAJQAAAAUAJShQAQsClAALKQAoIUAACAUQAAEoAAJQlELCURYAAAAACkKSgSkUBQQLUWFBFAAoCikoAFVFAFAKoAFFAKKKSgAAlkCkURRAFEURURRFEURRKBYFgECgKUAShFAQlhUFiACWAQBCgAoAlkCgqxRKBauG5HiHeCBQJYUVKAAAAAAAFAAstqAAKSgAAqBYALKJaSWCgFJZFlVFEpEAACFi2AAWAAAEWRYFlEUSgAFAFEKSgAAAAUAoCgKQtAFAALRRRKpFEotKRRALKRRFEUJURRFgURqEtglBZEUJRKBRAFEpKlpFgBKCoWEIgIVAIVBRAABQKRYqVCqKq5XUYuhFLBHgGvnAAAAAAAAAAAssFgoBagBVllAAAFgoIogFlECwqgLAsAAJQAACRLBYVQgAAEshSgAALLBUKBKAABSUAJQBVCUoollAFAVQoolUlUlVYqotIoSiKiLSAlAogIUigUlWJNCLCKM2yAUtMtQiiUCwlAILBLAkKiCUECxEoKWCCgUilKI0jLRZVFWWLACLILDwo185YCkWAAAAACUJQAAWFAFCkUSwUAqxYAUUAlAAAFlAhQJSRYFigAAgQCwqQAKAAAABQAAAAAUAACUAqlCkoAFEoKWihRKAostpQURRFApFEUsVEUklEUFEWrm0RQmhlqQmoSagURbGVglEqkWABEWSFiFgISAAWKsUJQVCWrFEtpKssqrFkALKRRAJUFi+CVr5gJQSiKIUgACiAAKEoAlgooCpQABZRFoFFIohSLABUKAsCiBJQBUpAIAAFBIWAtSoigKAACBSAVAoACiiKAUoigAolKKJRShVIoCilUFAojUI0JVWLAACKSNCNRZaiKItMqAIIlAoihLFS2MrTNsIQRES5ixEqUgAhZSKWWwsqJVUUKWUhRYoWwFiABUqIsFgsDwDXzFgAASlllFEABKAAQAFAAAVKFgsBVSgAsoACgASgKJQFAkURRABEoShFEURYFCUSiyhKAAApCkAWCglBRFKKQoFAUBRKKAq0KSqRSlBVFAoClBURYQBaRoZtEtEmhlUsoiURoZmkRauVEUSahFRARMpYgiQliAWKQQKCrLRFpGksURSpbEWrFCxBBQAqywgIEqgp85Zt5liAosBQsAAE1ACLBYALLAAABZQQooCgAssFAFCxRQ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FQWAIQXgAAABKAIsCwAAAAAAAqBYKlBCglgoAJQAAAAAAAWAAAAACoAFCAsAAoEKABKICpQAABZQAAAKABQgAAAAgpCgAAAAAAAAAAAAAAAAAAAAAsAACwAUAAAIsAABYLAAAAAAAAAAAAAAAAAyLyAAShKAEoABAAAFgAKQAACyksFAAABKAAAAAAAACwAAAWAABUpAAAUCWFSgAgAKAAAAVBQQCwUBC1KACFQVKJRAUAABBQAAAJQIUhQAAAAAAAAAAAAEoAAAEBaEAAAAAAAJRKAAhUFSgAAAgsoSgAGRYCCFQVKASgIWAoASgBFBAKJYACkUEoAAAAAAAAAAAAsAAAFgAAAVAABUAFShBSAAoAAAKSoAAACiAAsFgoApFgBUAAFQVBSFlhYFgFEAsFQUAAAhQAAAAACFSghQAJZFFJZFQLCqABBYoQVAABYAAFgUCUJQgAWAqEF5QgBSgEACoKAAQqUAAgLALBZQAAAQoAAAAAAAAAAAAAAAAAALAAAAsABYLLACkFAAACoAAAAAAAAUAEBQAAAAAAAAALAAAAWAAACpQAQoCCoLFJYLAWCoAFgssAgChRCwALAABAAVYLAAAAqUgBSAAyHIAAAAAUsFBCiWAFQUCUSgIUAAhQAAJQAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAEoIVKAAAAAAAoICggKAAAAAAAAAAAsAAAAAAACwWBYCykUQAAAAFgBACwAAAAAAAAoAIAACgWAsAAGQ5AAAAACgAKgsolgKJZRLCkKCLCpSLAUSgAAAAAAAAAAAAAAAAAAAAAAAAAABZRLCoKACLBQSgAAAAAAAAFBAUEABQAQFAAAASgAAAAAAAAAAAAAAAAAIACgAgAAAAAAAAAAAAAFBBChQATIQAUlgAAACgAAFgpCxSAApCpQlCURRLCgEKAAAAAAAAAAAAAQoAAAAAAAAAAFlEsAFlCUQKAAAAAgoAABCgEFgqUSwWUJQAAQoABChQCUAAAAAEKCUAAAAAAAgAAKCAAAAAABCgAAAAAAAASgAADIQAAAAAAKACAAoAAAAAAoAARQCKJQAAAAAAAAAAAAAAAAAAAALAAAoASwAAAAqCpQgssKgWCoKAAAQsABQgAKgWCoLAqCggFgssAKgBQLAqUQFgqCwKAQqCgCAAoIAAAAAAlABKBCgAAEKAAAAAAAQgQAAAAAAAAAKCALCrAAAWBYLAVBYKQoAAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAsAAAABYLLBYAAAAAAALAAAAAAAWAAAAAAUQUAAACggAFgCFirKgAAAAAgqUAAAAAILApCkKAgqAABZRLCBAAAAAAAAAAoAUlQAAAAAAAWABYFlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFgBQAAAAFgAAACKAgoEABYLAqCoKAQAWAoiwAAAAAoEsIEAAAAAAAAAAWAKAACAoIAACgBSAWCxQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICrBQAAAAAgKAACAAAAAAALAAAqURSAAAWCywAqCBAAAAAAAAAAAAoICggKCAAAAoAABZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACgAAAAUJAUKCAAAAAAAAAABSLAAAAAAAAAABBAAAAAAAAAAAAAAAoAICgAgAAKAAoAAUEABQQAAFBAAAAAAAAAAAAAAAAAAAAAAJYKAAAAAAAAAAAAAAAAAAAAAAASKAAAAKAAAAACEpQsBQAAgAAAAAAAAAAAAAAAAABLAEAAAAAAAAAAAAACgAgKACAoAIWKsolQoAAAAAAAAUEAAAAAAAAASwoAAAAAAAAAAAEolBKAAAAAAAAAAACUAAAAAAAAAAACAoIAACgBIoAoAAAAFACAAAAAAAAAAAAAAAAAAAIEAAAAAAAAEKAAAAAKAAAACAAAqxSKJZQAAACAWUIKlAEUSgAAAAAAQsoSwAoJQAAAAAAAAIKAAAAAAAAAAAAAAAAAAAAAAACAqUACAoIACkqJYKKCAoICgAgAAFBEolhaQoAAAAAAECpQAESxSwBCUAAAAAAAigAAAAAAKAAAAACAoBYCwqCgAQFgVAollAJZQlAAAAEsAKQqUEKgqUAAllBCygAAAQWUASwqUASwWCgJQAAAAAAAAQoAAEsKAAlhKICkFlApKAABCkipaQikKAQoCCpQAAAABKBFoACUBAUAElFSxFgBbLAEAAAAAAAAAAAAAAAACgAAAiwLCgAAABRLAUECglBAUEKgoAAAEsALLCkLAFABAUiwAVCgIKlBCwAKAABLAUlQAWUJQQpCpQAABLIWKqCgCCACwLACggBQAllEsqywAAoEsFiACwFICoKlAABCgAQAWgBAAUlCUBEsKgAAAAAAAAAAAAAAAAAACgAgKCAoAACywAAsAACwALFEsCwAUAACUQAFlEAAACwKgLACwCwAoCCygBFCCwLKECoLAAsCoixQloAlAhAoJYLAAFIogCwAAAAoAAoQVBQARSFiAqAAAAAAAACwKgsBYKlAAAABAAAAAAAAAAAAAAAAAAAAAAKCAAAAAoABZSLCxRKJYAAKQoJYCwAAsCwAFgpCoLLAAAAAsAAKCAsAsKBKJUBSFIBYAAAAAgCpRKAAIAAsAAAAAAKlEUiwLBZQAgCliKSrCAosAgAAAAAAAACwAAAALAAAAAAAAAAAAAAAAAAAAILKAAAAAAAAAAoICgAKBKEogFgFJQIKQsoiwAqUQAAAAABSAWAAAAAAAACoKgsACwAAAALLAIAAAAAAAAsAAAAAAAAAABYLAAAAACgAgAAAAAAAAAAAAAAAAAAAAAsAABCoKlJQAAAAAASwFEsKlAAAAAAAACygAACgQoEoiwqBQAJSAFIAAAAACwCwLCgQAAAgAKAAAAAsAAAAIAAAAAAAAAAAAFIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoJZQAAlAIoSgQqURRAAoABCkKAAAAAAAKFIUiggpAAAAAAAAAAAACwAAAALAACAFlpAACAoAIAAACggAABYAAAAAAAAFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAACFCCpQlIsAKQoIsAAFlIAUSgAAAAAAAAAKAAsCwAFlIAsAAAAAAFgAAAAAACAoAICggAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASwAAWABYKgoIABYCgABFEoAAAAAAACgKQAAAAAALAAAAAAAAAAAAIAAAAACggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAWACywAAAAAAssKlIsFlAEsKAAlAAAACUAAAAAACrFIAIsKAAAAACAoAAAIFIAAAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABC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1EVV+vtOJLIKLLBRiEEQFUs89ss8QogCEGm3MZ764a8EFUX33z33m0ADH/f/APX/APWZvtuvvklABEAAMNPINPP47gzw04QQTTTSQcQYUaPpiqly0uHPFfUQcQTww04wwywglnJgvgNDNPOTfY3+w0x/BGHPDRQRxx9nqvTRfffffPfeQQQYwe/003//AOJI4rb74xba5K4CAAQDT0l3330kV3233kV0kEH1Sya5DSAQwAEGlHX3+9/sMMdf867TwhRzSzwW0Ff8cMMONOFHhzxxyC+//JJEFX0HH333333kEEEEENf/APTrD3f/AP8A7Lr67q4IJ76gADDz3nXn1133X1nX1kX1SCQzyCRDzjDEEWG+8Nfe/wDv7B9BwsAwg4wAQgICCGqHHTXDFBRwgQM01RLPBBRBF999999999NF9pBBD/bTjX//AP8A/wD/AOvhnnvktmggjjhwRw1/c3f8/wD3EG3xACAATLywx776oMOPsMNOMOMMEEUEXBQAABSSAj5r5LpM9nuH31F3wwAzSCWEEEln3313333/AN59x9hxhJjDDX/z/wD/AP8A++u++eW++qG++CDTjLzz377xhJF18408syCC2yeC++OOOObLHf8ARX/ffbVdfUCAHvoANuusjv61pEKAfefbRGDHNBQQQQUQddfffffffTbSRQbQQ41ww1//APu/7777476L57/McMtP8sMP+sMOMHkAIIIII4YYIJLL5L4ILLPf33XHHHX313313jTDDJ7769/OsIIJAGU0HXkX20mEEEkkEkEH333X3n332m0EEEOMMM8/vuv+7775774r778NcsMf/sMv988P+8M4oIY4pL4III4IIIJIYYIIID0EVWkFHkEnEEEMALoLLbLLpKAAYwhDEEWkkGEAEU0kGEV2EGEHE3lX3nEkEEEMEP8A/vfn/v8A/q368vTvvz/yzx/+x29+5/8A/wD7f/ve+62+O++OOGWecy+sMAAAEAFRpBBFJFBBXBXPuiCOaOO++e8+cAQQc8ckBf8A4QXfTQcRSQQfXdaQQQRQQwwQ607/APuv/wDX/wD6xd3/AP8A/f8A71/x4/8A/wDP/rz7z/8A/lv/AL75ILDDj77xzzzyzzzwgAQE01m120321X/8IZ7577tvY57b7wjjrzz/AP8A+/8A/wBtB5V9NBRhFBBFBBBRFZhFBTjT/wD/ANf/AN/hBR199/5//wDww0+0yx+www5//wD7/wCzgEIQc08Qggwws8ws8844sccpx99V95V7/v8A/wD/APjDDm+bD/8AvnLvoP8A/wD/AP8A/wB99NRtxpVFB1J15RJBBRBRBBJBR9hBpB5xJR9559lf/rXPDD3jTDDDD3f3jyhABBgAhIgAAAQQwgAAAAAAA088951JDP59/wC8wwww978+ww0+ox1uAf8A/u//AP8A/ffebRWffRSSSWVURQQSQQQQQQQQQ6RQXffbff8A/P8A/rX/AKy3wwww4zw4wxQRbSVaSQQRQQRQACAAAAABAIAIPIMEf/8AvGNMMMMMMdMMsMMMMftMMMP/AP8A/wD9f/23/wD9999999xBBZBxhBBBBJBBJJPf/JNFxhJ9/wB7/wDMNf8A999NLPVNtNDBBFd9h99NtNdNB9tV9N88cIcsMcAEMASigTDDDDjDjDTHDjDHDDDDDDDF/wB++80/8/8AP3P91232212W0UEFEGEUEEl9333XPfvNP/31/wB51195tR19d9999tVt9999999d1x9999t999995c8888A88s+sSCCCKCOLDDDDDPfHHDPP/wD61/8A/wDPDfbDTD995l9x99999t9tpBBFdpR97V97/j//AI2+/wD/AN99BBpB9N99999995959999515999199999995999t8888s8M888+COCe+ueOODH/vz3/73/wDw1/7w8x76wx3/AO/3m0P3Pf8A9959lZBB9phhJV9NXD5bR1719991999VRp99px9xtd999Z9x9FRpRRBx999519x19999/wDXPPPPPPkPPPtvvvvvvnvvy2//AP8AvX+OvrDDT3rL/wD/AP8A9/8Af/S1/wCf3n12kEEEk2knHX12330EEEEX2nHH3kEFGEEEkEHkHX3lEEEX3321201H1EFH0EP/APrjZ99t987yUCCCS+e+622+62e+++++a+qCfDHPX/jT3L7/AP8A9+33/wB9/wDy/ffRQQIYSDRWeOQffcQfTQQURQdQSQQQRSQQbQQdcQcQQQUUeUfeYQQQQQSQRwwwx0efbffb0gbLAPugsojvvvvnvvikogqilvz+xx9yw24w1/8A/wB9/wDeQ3ba7UZQQQTSUaUfPQQcdTQYRSVQQQQVSQQQQYQUYUUQSQSQQQQRSSXQQQQQQQUQQQwQwwwQRwzYQQUYEKgiggksggltsogghgksgr8//wDf+8MMcMP/AP7x951V/vH9ZxpBBhB9pNdhZRRN1xBBFRV9BhBBBBBBBBNBBBBBBBBBBBBhBRBBBBBBBBB9JBDBDDBTvBDFDBBDDDCDTuGCCCCCOqeKiDW2zr3jDf8Ayw8xx+5ww7ZVfffb7fbdTYQXbZcaQaSQQQQVfRSRTSQQaRUQQQRaQVSQVbQSQQQQQQQQRQQQVQQS0/x6wUQQRRyXxwxwzywwwww0xggig0sg4l7/AJYMMO8OfsvusP8A/rDDH1d59/fd91995V5FxJF5FNBRpBV9VFd5BF519lBNJFd9BBBV5l9pJFFJBBBXtNBDP/ff9/8A4w61VffQVb/9+/zywwxww3/ggwwiig1z/wDssOsNOeusMMOMcOv/AFd/9/5hh9V99d99d9ZV15hRBJd9pd999dN19d19BNRBZNdRdNd9dPbJBJDfDvf/AO8v9/8A/wD/AAwwRZYQWe/z/wD/AP8A/wD/AP8A3z37ywwwwx//AP8ADD7DDDDjDDDDDDDrzn9r/wB/wxffadWUbffRQbdffXXfbRTVfffedffQfXdQUZeefbfXfff/AMtMMP8A/wB//wD/AP8A/wAtvfesM/28V/3X/wD/AP8A/wD7H/8A3/8A/wD/AH/+9/8Af+sMMMMMMMsMMMM9NP8Avz//AA//AP3/AN19BVR9t5hNFR19Jd1999959t99999999NNd9d9V99V/wD/AP8A73//AP3/AP8A/wD7+/8A/wD/AL3/AP8A/wC1ff8A/wD/AP8A/wD/AA9//wD/AP8A/wD/AP8A/wC/ff8ADHPLjDDDDDDX7XLjTDHjD/8A9fffcRQUdTYQSfeffefffXddQXfff/8A3333313333//AP8A/wD/AP8A/wD+/wDv7/3/AP8Asb7/AP8A/v8A/wD/AP7389/+/wD/AP8A/wAN/wD/AH/98xz/AP8Anf8A/wAcOsMMsPNMctt/8MMcdeN+sf8Aj955xNF95151p999t99dt999d9f/AKXbf/Vf/wDP/wB//wD/AO//AP8A/wB/e/8Av/33vPPv6/8A/v7/AP8A/wD/AP8A/wD+/wD/ALz/AA3/AP8A/wDzww//AOte+sPs8svf8cPf/wDr/wC0wwwwwy/2/wD331132n2W0332X22133323/13f3/v3/8A/wC//wA/+tf/AL37LTf/AI+9/wDv+/8A/wD/AP8Ajz7ae/P/AP317+/w1/6yw5+949680w/8ww4www1//wC/+88P/wDvzDDbTDDH/wA5y9fRffffffdfeeVcddedfbf41+x78Q//APtsvfu//wD/AP8A/wDrjT//AP8A8MMP/wD/AP8A/wDvDHTi6/8A/wD/AP8A+8/yww8344wwwwwwwwwwwwww37/1/wD/AP8A/wD9cvesNcMMsMNMMs/df/8A/wDWec3efffbQ8aVff8AsP8A/dXnL3T/AP20y96//wD/AD3/AA96+896y/8A/f8AzHT3q3/zrDj3rTjDDDLjHCTrDDDn7DDDDDDTDHfvf7T/AP63/wA/P9/8eMM8MMMc8uMNOPN//wD9bX9d393995N9/j//AP8APssMMPuOMNv+NOOMMPe9f/8A7zzD7/3ff/v/AK3qww47/wD/APjDDCCCTvjDDHDDXDDDDDLHDXP/AH//AP8A/wD/APv+ufPNsMc8MMNPsMMe8MMO/wDffLb/AIxY+55/+8a1+6//AOsMP+MMsMNOsMMN9s9P/wD/AKwwx6973/8ALPcJKMMP/uMMe8MMsMMMMMMsMMsMcMMsPdMNv/f/AP8A/wD/AP8A0/8Av8OOMPeMNOcudsMNsMdcOP8AvHrD9dtd71/bDrD3/wDz4x//AM8+MMMMeM8P+/8APPzDTD7/AP36wwwww6xz37w//wC8sIMMMMsNOuMMMMMMcYMMMMcMNNf/AN9D/wD3w4/434w/Xww/www43ww33/w//wCN+MP/AN//AAXf/wD/APfDf/8A43/4/wCMMMN8N8MMP+P8MMMML8MP8MMMMP8A/wD/AP8Afj//AP44www34wwgw4wwwwwwgwww3wwww//EACERAQEAAgMBAQACAwAAAAAAABEAARAgMGBAUCExcJDA/9oACAEDAQE/EP8ASue0I0R7QiI9kREezxiI9kRs9Q9RHaWPVERHN4Y849REbOLwIsYsTGMeZZnqIjRt4kRFjzTZzPSbODPXixjy7ZzO3oI4PWzMzM+SZnb04xYxG3g8WZngzp8KdbM6eZGixiNPc7Znb41mZmeZGixiNPlyODM8GZmZ6iLGI4szt07el3jM/smzgzM7ZmZnsxiLGI06MzpmZ7GeD+Af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');
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            -webkit-font-smoothing: antialiased;
        }
        .login-card {
            width: 100%;
            max-width: 400px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 40px 32px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .logo-circle {
            width: 48px;
            height: 48px;
            border-radius: 8px;
            background: var(--text-main);
            color: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 20px;
            margin-bottom: 24px;
        }
        .brand-title {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--text-main);
        }
        .brand-sub {
            font-size: 14px;
            color: var(--text-muted);
            margin-bottom: 32px;
            text-align: center;
        }
        .error-banner {
            width: 100%;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            color: #f87171;
            padding: 12px;
            border-radius: 8px;
            font-size: 13.5px;
            margin-bottom: 20px;
            text-align: center;
        }
        form { width: 100%; }
        .input-group {
            margin-bottom: 20px;
            position: relative;
        }
        .input-group label {
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: var(--text-main);
            margin-bottom: 8px;
        }
        .input-box {
            position: relative;
            display: flex;
            align-items: center;
        }
        .input-box input {
            width: 100%;
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 40px 12px 14px;
            color: var(--text-main);
            font-size: 14px;
            font-family: inherit;
            outline: none;
            transition: border-color 0.15s;
        }
        .input-box input:focus {
            border-color: var(--border-focus);
        }
        .eye-toggle {
            position: absolute;
            right: 12px;
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 4px;
        }
        .eye-toggle:hover { color: var(--text-main); }
        .btn-submit {
            width: 100%;
            background: var(--text-main);
            color: var(--bg-base);
            border: none;
            padding: 14px 16px;
            border-radius: 8px;
            font-size: 14.5px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.15s;
            font-family: inherit;
        }
        .btn-submit:hover { opacity: 0.9; }
        .footer-note {
            margin-top: 32px;
            font-size: 12px;
            color: var(--text-muted);
        }
    
        /* BRIDGENA-TAILWIND v3.2 */
        .visible{visibility:visible}.collapse{visibility:collapse}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.mx-px{margin-left:1px;margin-right:1px}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.table{display:table}.grid{display:grid}.hidden{display:none}.h-1{height:.25rem}.h-1\.5{height:.375rem}.h-3\.5{height:.875rem}.w-0{width:0}.w-1\.5{width:.375rem}.w-16{width:4rem}.w-3\.5{width:.875rem}.w-px{width:1px}.flex-1{flex:1 1 0%}.flex-shrink{flex-shrink:1}.border-collapse{border-collapse:collapse}.transform{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}@keyframes spin{to{transform:rotate(1turn)}}.animate-spin{animation:spin 1s linear infinite}.cursor-text{cursor:text}.resize{resize:both}.flex-wrap{flex-wrap:wrap}.items-center{align-items:center}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.self-stretch{align-self:stretch}.overflow-hidden{overflow:hidden}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-md{border-radius:.375rem}.border{border-width:1px}.border-amber-400\/25{border-color:rgba(251,191,36,.25)}.border-emerald-400\/25{border-color:rgba(52,211,153,.25)}.border-rose-400\/25{border-color:rgba(251,113,133,.25)}.border-white\/10{border-color:hsla(0,0%,100%,.1)}.bg-amber-400{--tw-bg-opacity:1;background-color:rgb(251 191 36/var(--tw-bg-opacity,1))}.bg-amber-400\/\[\.06\]{background-color:rgba(251,191,36,.06)}.bg-black\/25{background-color:rgba(0,0,0,.25)}.bg-emerald-400{--tw-bg-opacity:1;background-color:rgb(52 211 153/var(--tw-bg-opacity,1))}.bg-emerald-400\/\[\.06\]{background-color:rgba(52,211,153,.06)}.bg-rose-400{--tw-bg-opacity:1;background-color:rgb(251 113 133/var(--tw-bg-opacity,1))}.bg-rose-400\/15{background-color:rgba(251,113,133,.15)}.bg-rose-400\/\[\.05\]{background-color:rgba(251,113,133,.05)}.bg-rose-400\/\[\.06\]{background-color:rgba(251,113,133,.06)}.bg-slate-500{--tw-bg-opacity:1;background-color:rgb(100 116 139/var(--tw-bg-opacity,1))}.bg-white\/\[\.03\]{background-color:hsla(0,0%,100%,.03)}.bg-white\/\[\.06\]{background-color:hsla(0,0%,100%,.06)}.bg-gradient-to-b{background-image:linear-gradient(to bottom,var(--tw-gradient-stops))}.bg-gradient-to-r{background-image:linear-gradient(to right,var(--tw-gradient-stops))}.from-violet-400{--tw-gradient-from:#a78bfa var(--tw-gradient-from-position);--tw-gradient-to:rgba(167,139,250,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-violet-500{--tw-gradient-from:#8b5cf6 var(--tw-gradient-from-position);--tw-gradient-to:rgba(139,92,246,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-violet-300{--tw-gradient-to:#c4b5fd var(--tw-gradient-to-position)}.to-violet-600{--tw-gradient-to:#7c3aed var(--tw-gradient-to-position)}.p-\[3px\]{padding:3px}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2{padding-left:.5rem;padding-right:.5rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-3\.5{padding-left:.875rem;padding-right:.875rem}.px-\[18px\]{padding-left:18px;padding-right:18px}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-\[2px\]{padding-top:2px;padding-bottom:2px}.py-\[3px\]{padding-top:3px;padding-bottom:3px}.pb-1{padding-bottom:.25rem}.pt-1\.5{padding-top:.375rem}.pt-3{padding-top:.75rem}.text-center{text-align:center}.text-\[10\.5px\]{font-size:10.5px}.text-\[11\.5px\]{font-size:11.5px}.text-\[12\.5px\]{font-size:12.5px}.text-\[12px\]{font-size:12px}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.capitalize{text-transform:capitalize}.italic{font-style:italic}.tabular-nums{--tw-numeric-spacing:tabular-nums;font-variant-numeric:var(--tw-ordinal) var(--tw-slashed-zero) var(--tw-numeric-figure) var(--tw-numeric-spacing) var(--tw-numeric-fraction)}.tracking-wide{letter-spacing:.025em}.text-amber-300{--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.text-emerald-300{--tw-text-opacity:1;color:rgb(110 231 183/var(--tw-text-opacity,1))}.text-rose-300{--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.text-rose-300\/90{color:rgba(253,164,175,.9)}.text-slate-100{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.text-slate-200{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-300\/80{color:rgba(203,213,225,.8)}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-violet-50{--tw-text-opacity:1;color:rgb(245 243 255/var(--tw-text-opacity,1))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.opacity-90{opacity:.9}.shadow-\[0_8px_20px_-8px_rgba\(124\2c 58\2c 237\2c \.85\)\]{--tw-shadow:0 8px 20px -8px rgba(124,58,237,.85);--tw-shadow-colored:0 8px 20px -8px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline{outline-style:solid}.blur{--tw-blur:blur(8px)}.blur,.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-filter{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.transition{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,-webkit-backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter,-webkit-backdrop-filter;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-\[width\]{transition-property:width;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.duration-300{transition-duration:.3s}.hover\:border-rose-400\/45:hover{border-color:rgba(251,113,133,.45)}.hover\:border-white\/25:hover{border-color:hsla(0,0%,100%,.25)}.hover\:bg-rose-400\/10:hover{background-color:rgba(251,113,133,.1)}.hover\:bg-white\/\[\.06\]:hover{background-color:hsla(0,0%,100%,.06)}.hover\:bg-white\/\[\.07\]:hover{background-color:hsla(0,0%,100%,.07)}.hover\:text-rose-200:hover{--tw-text-opacity:1;color:rgb(254 205 211/var(--tw-text-opacity,1))}.hover\:text-slate-100:hover{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.hover\:text-slate-200:hover{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.hover\:text-white:hover{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.hover\:brightness-110:hover{--tw-brightness:brightness(1.1);filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.focus\:border-rose-300\/50:focus{border-color:rgba(253,164,175,.5)}.focus\:outline-none:focus{outline:2px solid transparent;outline-offset:2px}.active\:translate-y-px:active{--tw-translate-y:1px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.disabled\:cursor-wait:disabled{cursor:wait}.disabled\:opacity-70:disabled{opacity:.7}@media (min-width:768px){.md\:inline-flex{display:inline-flex}}
        /* BRIDGENA-AMETHYST-THEME v3.2 */
        /* ===== Amethyst layer ===== */
        body { font-family: var(--font-ui); background-color:#17131f;
            background-image:
                radial-gradient(1250px 720px at 10% -12%, rgba(124,58,237,.16), transparent 58%),
                radial-gradient(1100px 900px at 50% 118%, rgba(88,28,135,.20), transparent 62%),
                linear-gradient(180deg, rgba(23,19,31,.25), rgba(23,19,31,.62) 68%, rgba(23,19,31,.9)),
                var(--hero);
            background-size:cover; background-position:center; background-attachment:fixed; }
        .login-card { position:relative; z-index:1; backdrop-filter:blur(16px) saturate(1.1);
            border-radius:22px; border:1px solid #3d3160 !important;
            box-shadow:0 30px 80px -30px rgba(0,0,0,.75), inset 0 1px 0 rgba(255,255,255,.04);
            padding:44px 38px 34px; }
        .logo-circle { border-radius:17px !important; background:linear-gradient(150deg,#c4b5fd,#7c3aed) !important;
            color:#171126 !important; font-family:var(--font-display); box-shadow:0 8px 26px -10px rgba(124,58,237,.65); }
        .brand-title { font-family:var(--font-display); font-weight:500; letter-spacing:-.6px; color:var(--text-main); }
        .brand-sub { color:var(--text-muted); letter-spacing:.01em; }
        .input-box { background:rgba(19,15,28,.78); border:1px solid var(--border); border-radius:12px;
            color:var(--text-main); padding:12px 14px; transition:border-color .16s, box-shadow .16s; }
        .input-box input { background:transparent; }
        .input-box::placeholder { color:var(--text-faint); }
        .input-box:focus { border-color:#a78bfa; box-shadow:0 0 0 4px rgba(167,139,250,.13); }
        .btn-submit { background:linear-gradient(180deg,#a78bfa,#7c3aed) !important; color:#f7f4ff !important;
            border-radius:12px !important; font-weight:600; letter-spacing:.02em;
            box-shadow:0 8px 22px -10px rgba(124,58,237,.7); transition:filter .14s, transform .12s; }
        .btn-submit:hover { filter:brightness(1.08); }
        .btn-submit:active { transform:translateY(1px); }
        .error-banner { color:#f0a48f; background:rgba(239,143,125,.08); border:1px solid rgba(239,143,125,.24);
            border-radius:10px; }
        .footer-note { color:var(--text-faint); }

        </style>
</head>
<body>
    <div class="login-card">
        <div class="logo-circle">B</div>
        <div class="brand-title">Bridgena</div>
        <div class="brand-sub">Enter your password to access the workspace</div>
        __ERROR_MSG__
        <form action="/login" method="post">
            <div class="input-group">
                <label for="password">Password</label>
                <div class="input-box">
                    <input type="password" id="password" name="password" placeholder="Enter password..." required autofocus>
                    <button type="button" class="eye-toggle" onclick="togglePassword()" title="Show/Hide Password">
                        <svg id="eyeIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                    </button>
                </div>
            </div>
            <button type="submit" class="btn-submit">Sign In</button>
        </form>
        <div class="footer-note">
            <span>● Nexus Bridge v8.0</span>
        </div>
    </div>
    <script>
    function togglePassword() {
        const inp = document.getElementById('password');
        const eye = document.getElementById('eyeIcon');
        if (inp.type === 'password') {
            inp.type = 'text';
            eye.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
        } else {
            inp.type = 'password';
            eye.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
        }
    }
    </script>
</body>
</html>"""


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    if await get_current_session(request):
        return RedirectResponse(url="/chat")
    err_box = '<div class="error-banner">Incorrect password. Please try again.</div>' if error else ""
    return LOGIN_TEMPLATE.replace("__ERROR_MSG__", err_box)


@app.post("/login")
async def login_submit(response: Response, password: str = Form(...)):
    config = get_config()
    cfg_pw = config.get("password", "admin")
    if password == cfg_pw or not cfg_pw:
        session_id = create_session_token("admin")
        dashboard_sessions[session_id] = "admin"  # optional local cache
        log("INFO", "Dashboard authentication successful")
        r = RedirectResponse(url="/chat", status_code=status.HTTP_303_SEE_OTHER)
        r.set_cookie(key="session_id", value=session_id, httponly=True, samesite="lax", path="/", max_age=86400 * 30)
        return r
    log("WARN", "Failed dashboard login attempt")
    return RedirectResponse(url="/login?error=1", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
async def logout(request: Request):
    sid = request.cookies.get("session_id")
    if sid and sid in dashboard_sessions:
        del dashboard_sessions[sid]
    r = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    r.delete_cookie("session_id", path="/")
    return r


# ============================================================
# UI - MINIMALIST OPENWEBUI / CHATGPT CHAT WORKSPACE (/chat)
# ============================================================

CHAT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="bridgena-build" content="r6.2-tailwind-fastpath">
        <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,500;9..144,600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
                :root {
            --bg-base: #16121d;
            --bg-sidebar: #120f18;
            --bg-card: #1f1929;
            --bg-hover: #2a2239;
            --bg-active: #342b47;
            --border: #322848;
            --border-faint: #282138;
            --text-main: #ebe7f5;
            --text-muted: #a49bc4;
            --text-faint: #776e94;
            --accent: #a78bfa;
            --sidebar-width: 280px;
            --font-display: 'Fraunces','Iowan Old Style','Palatino Linotype','Book Antiqua',Georgia,serif;
            --font-ui: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            --hero: url('data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAwICQsJCAwLCgsODQwOEh4UEhEREiUbHBYeLCcuLisnKyoxN0Y7MTRCNCorPVM+QkhKTk9OLztWXFVMW0ZNTkv/2wBDAQ0ODhIQEiQUFCRLMisyS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0v/wgARCAQ4B4ADASIAAhEBAxEB/8QAGgABAQEBAQEBAAAAAAAAAAAAAAECAwQFBv/EABgBAQEBAQEAAAAAAAAAAAAAAAABAwIE/9oADAMBAAIQAxAAAAH8wOgAAAACoAAKEsCwUAAWgKhQAALAAAoQApFgWAAAABYAAksoCiBQlCWIAAAAAAAAAABUolLFgoACiUQAoAAWCy0CrKAFhKACyiwoBRFEoAFAAAEWCglgABBAoWAAAEUCkWACgAESgWKKRRFCqZULKFksUShVgCiRYCWIlhYBCAecdZgAAFgAWApKCKJRKAAUWAKsoAABQAAAQpKAgAWAAtJZFSkWAICgAAAASwiyqAlEUJRKEWAIAKSigCkAAqFlhZYWUCgUAAUoAFikUSgAKoBRFgUCkoARQlhFAAEWAEqkEKCURRCkUSgKRRFEqkUsVEURQKRRKKUSrEABNSiUsXMWCLAgJRFgBFh5x1kAoShFEUEoAFBAUAKQKsAoQKgsoKIoSgUAASgAEAAoSgARAAACUCFQUAEUJQAlBAsFikoRQAAAAspKAAAAoFCkBQoBRFAFlEoqUFAUAAKAAABAEWApAJQAAWQABZRKEUSgWCyrFAolgLAApFKlEqkpAEUSyrAEFSyQCAAAAlEUeUdZALBUosAVKRFhRQAACwFiqABBYCygApFhRQCBUoBYEUACFIWWApFkAAAShKBKAAAAJRFgWFAAAABQAAAAAUUAAooAApKAAFFFLKBRFApFgURQKRRARRBBYJRFEUAAABCykURSikWAomoACkUspBYVKAABAhSKIlgJQABFEVCUSwKEUeQdZAAVKAARVAAEosAAFItlhYBYFAAFikUBQCUACghZRJQAAlEoAQBRFEEAAAAAJQAlAAAAFSkKRQAAFLBQAAFAKUQCygAoFVKooAAoAAFLKClQRJSSglBZAAEUSglEUSqsoJRFRKBRKABRKKlAQKQBYCFRAhUBAoALKRURYWAAKJSxR4x1jYACgAFAAJQAAAAUAJShQAQsClAALKQAoIUAACAUQAAEoAAJQlELCURYAAAAACkKSgSkUBQQLUWFBFAAoCikoAFVFAFAKoAFFAKKKSgAAlkCkURRAFEURURRFEURRKBYFgECgKUAShFAQlhUFiACWAQBCgAoAlkCgqxRKBauG5HiHeCBQJYUVKAAAAAAAFAAstqAAKSgAAqBYALKJaSWCgFJZFlVFEpEAACFi2AAWAAAEWRYFlEUSgAFAFEKSgAAAAUAoCgKQtAFAALRRRKpFEotKRRALKRRFEUJURRFgURqEtglBZEUJRKBRAFEpKlpFgBKCoWEIgIVAIVBRAABQKRYqVCqKq5XUYuhFLBHgGvnAAAAAAAAAAAssFgoBagBVllAAAFgoIogFlECwqgLAsAAJQAACRLBYVQgAAEshSgAALLBUKBKAABSUAJQBVCUoollAFAVQoolUlUlVYqotIoSiKiLSAlAogIUigUlWJNCLCKM2yAUtMtQiiUCwlAILBLAkKiCUECxEoKWCCgUilKI0jLRZVFWWLACLILDwo185YCkWAAAAACUJQAAWFAFCkUSwUAqxYAUUAlAAAFlAhQJSRYFigAAgQCwqQAKAAAABQAAAAAUAACUAqlCkoAFEoKWihRKAostpQURRFApFEUsVEUklEUFEWrm0RQmhlqQmoSagURbGVglEqkWABEWSFiFgISAAWKsUJQVCWrFEtpKssqrFkALKRRAJUFi+CVr5gJQSiKIUgACiAAKEoAlgooCpQABZRFoFFIohSLABUKAsCiBJQBUpAIAAFBIWAtSoigKAACBSAVAoACiiKAUoigAolKKJRShVIoCilUFAojUI0JVWLAACKSNCNRZaiKItMqAIIlAoihLFS2MrTNsIQRES5ixEqUgAhZSKWWwsqJVUUKWUhRYoWwFiABUqIsFgsDwDXzFgAASlllFEABKAAQAFAAAVKFgsBVSgAsoACgASgKJQFAkURRABEoShFEURYFCUSiyhKAAApCkAWCglBRFKKQoFAUBRKKAq0KSqRSlBVFAoClBURYQBaRoZtEtEmhlUsoiURoZmkRauVEUSahFRARMpYgiQliAWKQQKCrLRFpGksURSpbEWrFCxBBQAqywgIEqgp85Zt5liAosBQsAAE1ACLBYALLAAABZQQooCgAssFAFCxRQ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FQWAIQXgAAABKAIsCwAAAAAAAqBYKlBCglgoAJQAAAAAAAWAAAAACoAFCAsAAoEKABKICpQAABZQAAAKABQgAAAAgpCgAAAAAAAAAAAAAAAAAAAAAsAACwAUAAAIsAABYLAAAAAAAAAAAAAAAAAyLyAAShKAEoABAAAFgAKQAACyksFAAABKAAAAAAAACwAAAWAABUpAAAUCWFSgAgAKAAAAVBQQCwUBC1KACFQVKJRAUAABBQAAAJQIUhQAAAAAAAAAAAAEoAAAEBaEAAAAAAAJRKAAhUFSgAAAgsoSgAGRYCCFQVKASgIWAoASgBFBAKJYACkUEoAAAAAAAAAAAAsAAAFgAAAVAABUAFShBSAAoAAAKSoAAACiAAsFgoApFgBUAAFQVBSFlhYFgFEAsFQUAAAhQAAAAACFSghQAJZFFJZFQLCqABBYoQVAABYAAFgUCUJQgAWAqEF5QgBSgEACoKAAQqUAAgLALBZQAAAQoAAAAAAAAAAAAAAAAAALAAAAsABYLLACkFAAACoAAAAAAAAUAEBQAAAAAAAAALAAAAWAAACpQAQoCCoLFJYLAWCoAFgssAgChRCwALAABAAVYLAAAAqUgBSAAyHIAAAAAUsFBCiWAFQUCUSgIUAAhQAAJQAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAEoIVKAAAAAAAoICggKAAAAAAAAAAAsAAAAAAACwWBYCykUQAAAAFgBACwAAAAAAAAoAIAACgWAsAAGQ5AAAAACgAKgsolgKJZRLCkKCLCpSLAUSgAAAAAAAAAAAAAAAAAAAAAAAAAABZRLCoKACLBQSgAAAAAAAAFBAUEABQAQFAAAASgAAAAAAAAAAAAAAAAAIACgAgAAAAAAAAAAAAAFBBChQATIQAUlgAAACgAAFgpCxSAApCpQlCURRLCgEKAAAAAAAAAAAAAQoAAAAAAAAAAFlEsAFlCUQKAAAAAgoAABCgEFgqUSwWUJQAAQoABChQCUAAAAAEKCUAAAAAAAgAAKCAAAAAABCgAAAAAAAASgAADIQAAAAAAKACAAoAAAAAAoAARQCKJQAAAAAAAAAAAAAAAAAAAALAAAoASwAAAAqCpQgssKgWCoKAAAQsABQgAKgWCoLAqCggFgssAKgBQLAqUQFgqCwKAQqCgCAAoIAAAAAAlABKBCgAAEKAAAAAAAQgQAAAAAAAAAKCALCrAAAWBYLAVBYKQoAAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAsAAAABYLLBYAAAAAAALAAAAAAAWAAAAAAUQUAAACggAFgCFirKgAAAAAgqUAAAAAILApCkKAgqAABZRLCBAAAAAAAAAAoAUlQAAAAAAAWABYFlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFgBQAAAAFgAAACKAgoEABYLAqCoKAQAWAoiwAAAAAoEsIEAAAAAAAAAAWAKAACAoIAACgBSAWCxQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICrBQAAAAAgKAACAAAAAAALAAAqURSAAAWCywAqCBAAAAAAAAAAAAoICggKCAAAAoAABZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACgAAAAUJAUKCAAAAAAAAAABSLAAAAAAAAAABBAAAAAAAAAAAAAAAoAICgAgAAKAAoAAUEABQQAAFBAAAAAAAAAAAAAAAAAAAAAAJYKAAAAAAAAAAAAAAAAAAAAAAASKAAAAKAAAAACEpQsBQAAgAAAAAAAAAAAAAAAAABLAEAAAAAAAAAAAAACgAgKACAoAIWKsolQoAAAAAAAAUEAAAAAAAAASwoAAAAAAAAAAAEolBKAAAAAAAAAAACUAAAAAAAAAAACAoIAACgBIoAoAAAAFACAAAAAAAAAAAAAAAAAAAIEAAAAAAAAEKAAAAAKAAAACAAAqxSKJZQAAACAWUIKlAEUSgAAAAAAQsoSwAoJQAAAAAAAAIKAAAAAAAAAAAAAAAAAAAAAAACAqUACAoIACkqJYKKCAoICgAgAAFBEolhaQoAAAAAAECpQAESxSwBCUAAAAAAAigAAAAAAKAAAAACAoBYCwqCgAQFgVAollAJZQlAAAAEsAKQqUEKgqUAAllBCygAAAQWUASwqUASwWCgJQAAAAAAAAQoAAEsKAAlhKICkFlApKAABCkipaQikKAQoCCpQAAAABKBFoACUBAUAElFSxFgBbLAEAAAAAAAAAAAAAAAACgAAAiwLCgAAABRLAUECglBAUEKgoAAAEsALLCkLAFABAUiwAVCgIKlBCwAKAABLAUlQAWUJQQpCpQAABLIWKqCgCCACwLACggBQAllEsqywAAoEsFiACwFICoKlAABCgAQAWgBAAUlCUBEsKgAAAAAAAAAAAAAAAAAACgAgKCAoAACywAAsAACwALFEsCwAUAACUQAFlEAAACwKgLACwCwAoCCygBFCCwLKECoLAAsCoixQloAlAhAoJYLAAFIogCwAAAAoAAoQVBQARSFiAqAAAAAAAACwKgsBYKlAAAABAAAAAAAAAAAAAAAAAAAAAAKCAAAAAoABZSLCxRKJYAAKQoJYCwAAsCwAFgpCoLLAAAAAsAAKCAsAsKBKJUBSFIBYAAAAAgCpRKAAIAAsAAAAAAKlEUiwLBZQAgCliKSrCAosAgAAAAAAAACwAAAALAAAAAAAAAAAAAAAAAAAAILKAAAAAAAAAAoICgAKBKEogFgFJQIKQsoiwAqUQAAAAABSAWAAAAAAAACoKgsACwAAAALLAIAAAAAAAAsAAAAAAAAAABYLAAAAACgAgAAAAAAAAAAAAAAAAAAAAAsAABCoKlJQAAAAAASwFEsKlAAAAAAAACygAACgQoEoiwqBQAJSAFIAAAAACwCwLCgQAAAgAKAAAAAsAAAAIAAAAAAAAAAAAFIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoJZQAAlAIoSgQqURRAAoABCkKAAAAAAAKFIUiggpAAAAAAAAAAAACwAAAALAACAFlpAACAoAIAAACggAABYAAAAAAAAFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAACFCCpQlIsAKQoIsAAFlIAUSgAAAAAAAAAKAAsCwAFlIAsAAAAAAFgAAAAAACAoAICggAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASwAAWABYKgoIABYCgABFEoAAAAAAACgKQAAAAAALAAAAAAAAAAAAIAAAAACggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAWACywAAAAAAssKlIsFlAEsKAAlAAAACUAAAAAACrFIAIsKAAAAACAoAAAIFIAAAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABC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1EVV+vtOJLIKLLBRiEEQFUs89ss8QogCEGm3MZ764a8EFUX33z33m0ADH/f/APX/APWZvtuvvklABEAAMNPINPP47gzw04QQTTTSQcQYUaPpiqly0uHPFfUQcQTww04wwywglnJgvgNDNPOTfY3+w0x/BGHPDRQRxx9nqvTRfffffPfeQQQYwe/003//AOJI4rb74xba5K4CAAQDT0l3330kV3233kV0kEH1Sya5DSAQwAEGlHX3+9/sMMdf867TwhRzSzwW0Ff8cMMONOFHhzxxyC+//JJEFX0HH333333kEEEEENf/APTrD3f/AP8A7Lr67q4IJ76gADDz3nXn1133X1nX1kX1SCQzyCRDzjDEEWG+8Nfe/wDv7B9BwsAwg4wAQgICCGqHHTXDFBRwgQM01RLPBBRBF999999999NF9pBBD/bTjX//AP8A/wD/AOvhnnvktmggjjhwRw1/c3f8/wD3EG3xACAATLywx776oMOPsMNOMOMMEEUEXBQAABSSAj5r5LpM9nuH31F3wwAzSCWEEEln3313333/AN59x9hxhJjDDX/z/wD/AP8A++u++eW++qG++CDTjLzz377xhJF18408syCC2yeC++OOOObLHf8ARX/ffbVdfUCAHvoANuusjv61pEKAfefbRGDHNBQQQQUQddfffffffTbSRQbQQ41ww1//APu/7777476L57/McMtP8sMP+sMOMHkAIIIII4YYIJLL5L4ILLPf33XHHHX313313jTDDJ7769/OsIIJAGU0HXkX20mEEEkkEkEH333X3n332m0EEEOMMM8/vuv+7775774r778NcsMf/sMv988P+8M4oIY4pL4III4IIIJIYYIIID0EVWkFHkEnEEEMALoLLbLLpKAAYwhDEEWkkGEAEU0kGEV2EGEHE3lX3nEkEEEMEP8A/vfn/v8A/q368vTvvz/yzx/+x29+5/8A/wD7f/ve+62+O++OOGWecy+sMAAAEAFRpBBFJFBBXBXPuiCOaOO++e8+cAQQc8ckBf8A4QXfTQcRSQQfXdaQQQRQQwwQ607/APuv/wDX/wD6xd3/AP8A/f8A71/x4/8A/wDP/rz7z/8A/lv/AL75ILDDj77xzzzyzzzwgAQE01m120321X/8IZ7577tvY57b7wjjrzz/AP8A+/8A/wBtB5V9NBRhFBBFBBBRFZhFBTjT/wD/ANf/AN/hBR199/5//wDww0+0yx+www5//wD7/wCzgEIQc08Qggwws8ws8844sccpx99V95V7/v8A/wD/APjDDm+bD/8AvnLvoP8A/wD/AP8A/wB99NRtxpVFB1J15RJBBRBRBBJBR9hBpB5xJR9559lf/rXPDD3jTDDDD3f3jyhABBgAhIgAAAQQwgAAAAAAA088951JDP59/wC8wwww978+ww0+ox1uAf8A/u//AP8A/ffebRWffRSSSWVURQQSQQQQQQQQQ6RQXffbff8A/P8A/rX/AKy3wwww4zw4wxQRbSVaSQQRQQRQACAAAAABAIAIPIMEf/8AvGNMMMMMMdMMsMMMMftMMMP/AP8A/wD9f/23/wD9999999xBBZBxhBBBBJBBJJPf/JNFxhJ9/wB7/wDMNf8A999NLPVNtNDBBFd9h99NtNdNB9tV9N88cIcsMcAEMASigTDDDDjDjDTHDjDHDDDDDDDF/wB++80/8/8AP3P91232212W0UEFEGEUEEl9333XPfvNP/31/wB51195tR19d9999tVt9999999d1x9999t999995c8888A88s+sSCCCKCOLDDDDDPfHHDPP/wD61/8A/wDPDfbDTD995l9x99999t9tpBBFdpR97V97/j//AI2+/wD/AN99BBpB9N99999995959999515999199999995999t8888s8M888+COCe+ueOODH/vz3/73/wDw1/7w8x76wx3/AO/3m0P3Pf8A9959lZBB9phhJV9NXD5bR1719991999VRp99px9xtd999Z9x9FRpRRBx999519x19999/wDXPPPPPPkPPPtvvvvvvnvvy2//AP8AvX+OvrDDT3rL/wD/AP8A9/8Af/S1/wCf3n12kEEEk2knHX12330EEEEX2nHH3kEFGEEEkEHkHX3lEEEX3321201H1EFH0EP/APrjZ99t987yUCCCS+e+622+62e+++++a+qCfDHPX/jT3L7/AP8A9+33/wB9/wDy/ffRQQIYSDRWeOQffcQfTQQURQdQSQQQRSQQbQQdcQcQQQUUeUfeYQQQQQSQRwwwx0efbffb0gbLAPugsojvvvvnvvikogqilvz+xx9yw24w1/8A/wB9/wDeQ3ba7UZQQQTSUaUfPQQcdTQYRSVQQQQVSQQQQYQUYUUQSQSQQQQRSSXQQQQQQQUQQQwQwwwQRwzYQQUYEKgiggksggltsogghgksgr8//wDf+8MMcMP/AP7x951V/vH9ZxpBBhB9pNdhZRRN1xBBFRV9BhBBBBBBBBNBBBBBBBBBBBBhBRBBBBBBBBB9JBDBDDBTvBDFDBBDDDCDTuGCCCCCOqeKiDW2zr3jDf8Ayw8xx+5ww7ZVfffb7fbdTYQXbZcaQaSQQQQVfRSRTSQQaRUQQQRaQVSQVbQSQQQQQQQQRQQQVQQS0/x6wUQQRRyXxwxwzywwwww0xggig0sg4l7/AJYMMO8OfsvusP8A/rDDH1d59/fd91995V5FxJF5FNBRpBV9VFd5BF519lBNJFd9BBBV5l9pJFFJBBBXtNBDP/ff9/8A4w61VffQVb/9+/zywwxww3/ggwwiig1z/wDssOsNOeusMMOMcOv/AFd/9/5hh9V99d99d9ZV15hRBJd9pd999dN19d19BNRBZNdRdNd9dPbJBJDfDvf/AO8v9/8A/wD/AAwwRZYQWe/z/wD/AP8A/wD/AP8A3z37ywwwwx//AP8ADD7DDDDjDDDDDDDrzn9r/wB/wxffadWUbffRQbdffXXfbRTVfffedffQfXdQUZeefbfXfff/AMtMMP8A/wB//wD/AP8A/wAtvfesM/28V/3X/wD/AP8A/wD7H/8A3/8A/wD/AH/+9/8Af+sMMMMMMMsMMMM9NP8Avz//AA//AP3/AN19BVR9t5hNFR19Jd1999959t99999999NNd9d9V99V/wD/AP8A73//AP3/AP8A/wD7+/8A/wD/AL3/AP8A/wC1ff8A/wD/AP8A/wD/AA9//wD/AP8A/wD/AP8A/wC/ff8ADHPLjDDDDDDX7XLjTDHjD/8A9fffcRQUdTYQSfeffefffXddQXfff/8A3333313333//AP8A/wD/AP8A/wD+/wDv7/3/AP8Asb7/AP8A/v8A/wD/AP7389/+/wD/AP8A/wAN/wD/AH/98xz/AP8Anf8A/wAcOsMMsPNMctt/8MMcdeN+sf8Aj955xNF95151p999t99dt999d9f/AKXbf/Vf/wDP/wB//wD/AO//AP8A/wB/e/8Av/33vPPv6/8A/v7/AP8A/wD/AP8A/wD+/wD/ALz/AA3/AP8A/wDzww//AOte+sPs8svf8cPf/wDr/wC0wwwwwy/2/wD331132n2W0332X22133323/13f3/v3/8A/wC//wA/+tf/AL37LTf/AI+9/wDv+/8A/wD/AP8Ajz7ae/P/AP317+/w1/6yw5+949680w/8ww4www1//wC/+88P/wDvzDDbTDDH/wA5y9fRffffffdfeeVcddedfbf41+x78Q//APtsvfu//wD/AP8A/wDrjT//AP8A8MMP/wD/AP8A/wDvDHTi6/8A/wD/AP8A+8/yww8344wwwwwwwwwwwwww37/1/wD/AP8A/wD9cvesNcMMsMNMMs/df/8A/wDWec3efffbQ8aVff8AsP8A/dXnL3T/AP20y96//wD/AD3/AA96+896y/8A/f8AzHT3q3/zrDj3rTjDDDLjHCTrDDDn7DDDDDDTDHfvf7T/AP63/wA/P9/8eMM8MMMc8uMNOPN//wD9bX9d393995N9/j//AP8APssMMPuOMNv+NOOMMPe9f/8A7zzD7/3ff/v/AK3qww47/wD/APjDDCCCTvjDDHDDXDDDDDLHDXP/AH//AP8A/wD/APv+ufPNsMc8MMNPsMMe8MMO/wDffLb/AIxY+55/+8a1+6//AOsMP+MMsMNOsMMN9s9P/wD/AKwwx6973/8ALPcJKMMP/uMMe8MMsMMMMMMsMMsMcMMsPdMNv/f/AP8A/wD/AP8A0/8Av8OOMPeMNOcudsMNsMdcOP8AvHrD9dtd71/bDrD3/wDz4x//AM8+MMMMeM8P+/8APPzDTD7/AP36wwwww6xz37w//wC8sIMMMMsNOuMMMMMMcYMMMMcMNNf/AN9D/wD3w4/434w/Xww/www43ww33/w//wCN+MP/AN//AAXf/wD/APfDf/8A43/4/wCMMMN8N8MMP+P8MMMML8MP8MMMMP8A/wD/AP8Afj//AP44www34wwgw4wwwwwwgwww3wwww//EACERAQEAAgMBAQACAwAAAAAAABEAARAgMGBAUCExcJDA/9oACAEDAQE/EP8ASue0I0R7QiI9kREezxiI9kRs9Q9RHaWPVERHN4Y849REbOLwIsYsTGMeZZnqIjRt4kRFjzTZzPSbODPXixjy7ZzO3oI4PWzMzM+SZnb04xYxG3g8WZngzp8KdbM6eZGixiNPc7Znb41mZmeZGixiNPlyODM8GZmZ6iLGI4szt07el3jM/smzgzM7ZmZnsxiLGI06MzpmZ7GeD+AfYcGZ2zMzPbjFjGn8Ys6GZmexmZ/IZ0R9LozxZnuLECSzmZmZ2/tM7PjdGeLPwYxYxYxjEzMzPhnvZ6HvIsYjGJmZnxr0Mz85FjEaZnyzM/Qaxi/qZnyrM/azP5J+UzP3v5jPin8lnTM/5wf+Dh//xAAgEQEBAAEFAQADAQAAAAAAAAARABABIDBAUGBwgJDA/9oACAECAQE/EP6iMz+uJ+MT4IiOqdE+DZnlNp0znOE9Z6hGw+qbTiIjtHGe4RER0yI6pHcZ9A42ZneRERykYMnAdFnss+O2mtprtIiIiPGZnss+Qzhm01neRERk7jMzkjqMz5+k401mbTXJGCIiIiOuzOCI4HmZ9FyzM2mszk2naI4GZ5tdZwekzMzMzMzOzXskb2d7Mzu11mPbZmZmZmeub2ZmZyzPAz6bzMzlmZmZ6LOxm11mdjPwrPGzMzMzMzMzwMzOGZmZ2M/GMzh4WZmeByMzMzMztfl3DlngcjOGZmZn5ZyzzMzgzlmZn6BwzOGZmZnDhmZy/Xv+Gn//xAArEAACAQQCAgEEAgMBAQEAAAAAAREQITFBUWEgcYEwkaGxQMHR4fDxUGD/2gAIAQEAAT8QVru6I2ex2Ln/AEC/8LbMZ+Bcfk2ffqiV+hc8GpNSOw0onQpzowaolmk8G/6N+xZL5JnqiVx3Us5/6B6M4MnuuV6ozIu6RJkf+wrXWSdi5Wizd5+Ddxzgf40Pgt2Pj8kQYuL7iwc9F0OUM9FyeCTvVL5YpIjI5UU1BFMC4pquMiuXpF710LNybCNd0nxy6KkUZF6Iw7XO6rJjORVSEiLm+qZohCLcGsUWLjxZkUxgV0PkatSKQKqOapU0LNNjLkFxWLmTRKimhqHOhw8ECXyfBg3cfQr2pBDaGrUjf4I+RId+T9mrUTvwtCQuSHVY/o/RaeFGxK9xpwJS7ENrohcoh8i9noavKpAlp4HbkacdUd0izfArXEm1i595GpRH2IvDsKFm/wDYu5IcXP2TwbE72k3Gxw1N+IErsunRFi6VmTcmxbYxO97m7nPHBzcXakeLGib/AL7P0fhZNG7n4HbfshRBqzsQPo9logYtsi5fFxc2JV+aW5ElGbiP0Wnkn4TGlGSd/YWDJEuxByXhN7pFjOrjujY1v8muGe4IvdnsdovKMXixM2fwJrbagbnPwJEEWkX2MrKIbxc6kjRFsjVuIH+DB3KhUl40bufkZZCUXI4MEdn2ND92NOwr0yzRkt6Hc/RnFWaLGK/gn70cCIojZszsQj5Hmmz3jz9no5PYqbNivR4uJDVuBZF3SIosHxTdYzRUjgSno3XfQ0Ox/ZYxkifZpmaeqQN2GRwQIcaMYyXN9FpH+TLOVJhi+5bJG2rEH7LCUotKv8jvkt8EdqDUENPGD9EIajQjZlWFCypEvsh8kW74PQUaH/6NehcxBEPodo7yQkyMy7EJJ76ErTo65FMN390SL8kRebkra/A4tdX0ZfsbUvgl6tHA+sju52fjgdtCuyz2bGdXR3FjHHEGrbOLMf24OyG40YV/g1EXHMdGx8/hCcasRnoVx4ghs97LqP8AoGmvZdDlf6NKMk3vSbRwabudGNsiIEreiJ6ZkXr/AEOxqPloTs+DRwtfk2Je/QnzqiUvPo7auROBKS8l3iUPqZ2NGXgukmovgXLkdksjZDwdmX7G1aJkycD6n5PTYn6PgeqNQ7fcVy0mrER6Luxq3yYUkW6IRNxK7lWP0eq6PvR2F+DGMESx3yTAo2JcnuaRZDwfeuUIdFRdinBD+ws0eBGxUmHSLUimGPg6NQW7FTWxLkSiuiZOEb3VKxB8UYqdCdHgi1NEEUyZzVmh0xVYH9xnJ0XI+57PdE4FjBEjRmxhCyPOIOiLH2pf7EShqdCC9Iafs+BDXBGBLkeXyRsixEeiHrCErDIsNXIhZFiDkiSIW+jBGb/BFrixRkpUO+1od3aRneBq9jKjgcK45z9x4hPdmYO12aSbsbla5Iz/AEdnF7k57IzwRa/4HLRRF7o6M+zRpd0UStFo9YOzN9kFkfs5SFLdkTqCOVbofX2HEK8l3cbTwoSLffDFYblR3Jlf9cseSHPCMTDwJb4HwTfC4Js0YeJ/oi06p+KJ2hMbVuTQ+sGIsKwruNiU3MXCJvKsyLmZlGd/7F2XWL2LGCyyuxRFnnUE+oHL16Gos/sfrY39h45X6ItG2ZOxEDc32N4jOzd7lxHZpjspLQzCwLBPBuMF0+zrJF8m8WHYta56HNVSOhQ1Bro3gcTelqOzp8Ghxrxg2ZwbNqVBnY+7Dj/ZjdENaEdCXdN07rHYqfsY1TcCgixY6IrF7mmJEEQj3RKYFgSIFSB6ErmyD4OIPZoVqRNM3gaEryd0ahGMM3g0R0bGQReCO7i4InB6IuRKsLY1Kuf9I01Tqkf+kK0ltohkaF3YfGORKz2RvA3wQh5vr8CUMhvYyXYvyRaRJ6ErLkaUxBh/Q7qyLHHGxKxFn+iGuI1Ja7g/ss3dDthL2hKbJFzzD5EpunEbF0pgREuILtL7IxEk8uRy0pRm0zBi8rqBttdsu5eictq6/IrKMmNYMq93JeEpJ6sN3Po16Fg4kyrSJS1MwREqxnIuUNWuXUDc2VkXgUaUyZ2OUphKS7tYSs3Ck1aPYrZFjRFx3b/A+sbFYyyHGD0o9jtZi7EpcEYv8k2vHwYJwe5+D5t2RLO0kqO3sm9pG1MqZJkW+iOcHHWhbjJMSuRWV/sKF3wKJu2oGW/0jI7O2xXaSy6JC5uPExakPOTXZJadwhbHbBN+jGBPkm69nkkssSbsLufgmwrejRouRRqVJkZgZPR3XRJNjJo0M2YMXFRdiV+iCOSD4PsbsexEUfdEOnUGiYpk15QqQKiGIggi1IMHoVyKRqmqarB6ZB6rFiKsvDMG0LsWbEQe7n2IcwYFRI10W5LD1I8ix3og1ogjhfIrdHukdGrkcix6Gr2HkRgf/QQvgStYahTAu5J/2RYS0NHszZF2+xpy4GpXdLz2OYmDBpSNim/GyW4aN5hcjd3kbTh8CibDcvEM2kZP+iLTrkd+uB27fQ8M/DLPOERngi1pncjsrcm/ZF3DVuSL4PnGDmLGIYlDxJMO2RaukiHCcrOOD4G5ciUsURYYUxgRixEOzFdxwJxfA7aJ4ol/4KybVmhprNj7D/FEsiTm2z+mfBrNjKFn2NJOMow+Debky2yYdnkXu4n2lOTY7xOjpXLT8Dvd5I3Fh9Eu1okvLS+5feBy9W6Gs+jWB/gu2XmyFmjoyuC84kfJh32LF0y5+jXVHiBKFKHZD6ojcUvEPAtxlDQx2WRCl2FCyJua+rmcI0LIjdI2e8kWny1RWpBH5Fm6N0atksZzSD4on+TFqfNFkn5or5RkyZOaoU+z9GSLmGR806FkVYpAli1bnIhRSKQPoWTpXIgcpKRi4HEU2aEiL8jSITLcENkGNmSD9CovR+SHHR8SReKREDRjDk1Oy77M5M9HyP5DU9GjGvgiZ0jC7IvDf3ErYO+RJc3IhLmRO8zc9Hof5OxOMlm+DZtxjsbm0vosRMxgTvKxtaNzsaeWO2bLQ9SOIclo/sSiyRi6NLsh4HO7DUzCHCj0RpqHoyy7GdyXiJRfoZXomb2N2Jx1sebXLtqUYfPobh2Itn4E4mMQTamrCNZOh3yPU5g9Y4pytmr54LsvGoE02Kz0XIltRwJ60ezKlaJMOw5gnaFk3AzMsTj2TyjRbUjWBWbS2Oxi5zyYErRrsXEuNGoILMa/9HmJFvCkn0NDcrRdO4mk+qex24IcGV6LM1kTaXTEpH0KzMnoWOyY9mmL9E8okhRkjwzodIpdCzkWTZzJgyYsJCFGIPdNjXZEQ8kbNmJVOmZMmGpFJuxuByZJMFhVQmKq6HRL7U3Y2bFaqIOCBIyQYz4QQJOC0HUU0bIkaWhkQNEEWwQIVIggmS0l1ZmaWPQ1s2PNx7IaeT+2RAlsV2Re9iHMMzbgtJyRKtoi+PkhRxRJuUQWdrz2aVscEW0KN3P0WT/0Yk3iBPiENNZHno23Fib21sxn7js7jasPDXOx3jmmNKGR2Ti0WJ2fk0Qp5G9C+FCI3eTrLG4jlD69ii7vB3BvfzR8j03sahS4N2sfBpSYv+j2zKML2J/YlkOypEi5eNiu5wb9jawKcFnf7kS7CsQk1A0oUP7kEXEs5Fmxl49E00eqLsiwlKnjRdf5LoziX0JxMUW4sJwjFtHw2RI3NnoRqODR74Em9v0NO0EXPY3EPwJ2jRzo1exsjkya7PRabYGn8nHJEO6PeDTp/VINwfJ1FHiaOjgcR2apl5Unyi/BDdjRlno2ZVOvC3yfBFVbulp48OhL5RFNEDpuirnJ7qu6dOsckCS+CCLkeF/g9VXIqRexFiKLYkQR1YwdUhR2IuRBBabmCLiSIvRo2M90aI2QJdEETc3YYlrAlLFZxEm7lwlKkQ0uII5Y0xIUmsC4FtEReYEuRndxZsOJcWEo0Yt+S7XolY/JOso2fcWV7G3OZ4LZuNyX3HKu7jFHuB8yTbojP9jmJY5TIfz2LN7dnzbQ3yrCVna4/wDmPEDvOY5MYGvl/oWG1aB8Q7kOLnGP80blJPCwZm2TcaIgTxFy109j/BMWTyREyr6XBufvBvoUP2awPNjFzEfslMtbc4G5yKyV7sZLwOLQ5Fd4phdizm4uzm4sDNdGZuYkLGD9GDGDV3jR3wLJHwe0ahGptBq475NSKH1B7F0hfoj2Ozn7j5vArK5FneiWZ+DCUo+Dbh5yMiOjB+R6HE9Ds7nZ/wBBnQ79salTJOSPg17MCU2WTBu5vkfZF7KnEDltiJvR3ETOiLR+RZgtyfJaixom/Y1DpJ+qKC4kSM0iNiwIW6fJusHdFnxlRWKbvRKmxUzY6pEUVvQvwMg24NdmzeBK4hzs1cYxfYsdEXF+SDdVi6vTSxSBoZul9kCUiUIhQQQLunTFF9sUlLIERkV4SVI4I3BD9mMES7KyI6HZXEpUIe4JazYTyuS1i102Pyx4vA3ZM+YNdmxuHonLZNoJU3JtMj9kQPVogcCdr3O+Rpw5nNzKuXBO8qCPQ4izJv29DmW08k/jgSztFo+RtTZW5ORcfsUpajujx0Yfo3uBWXZhEQrbOSHC4GkkoyJW5E4vYU5sRkf4FbFENYk4WjBO1+S5MLZlbFGxYs/uYIjTIhns6Mm7Fubis7kcSLrkxiTi9IdhZuPcC62XRhK/4IuQjZH4EW+aW0bw5E2uL9Ekx4uNY/IlpZN30ex5NJ5PmyxTZ07vosXiUNbQlv4MMhNnIseyLwtGrZH+DKNC3sWBjvBjmuWTcyL2QbHS1P0RYRwfDORfEUtuRdmRfmnVN0ZMqqmrzTsR6p+6YZsRsXVPdEYpC+TVIuQaHSKwRenqwsDUDNjUoc7OqJEHo5pqRIiSJQjRvoa/A8jU3IliyYuR8Ed3IvA+ENLQrkDJ4VFnZC4P0JcHyfJF7HbIRixaEbLwkXCTyLsxcagnnBPX+jRMTGyecYHkl4OUClqR4hDbWH7Lu2mTrjYnYldzG4gebnr8ixYaaXv8iWy1oxyyEr7M2NJPBZpohwNKNr2OWszchxDNSznk93NXuazY7SsfovbaMf4Nzplm2ouY6gbn/Ai8dEGJRb2LBEIu6axYXdzd7izmDnREdjiXBnRDc2nmi/JjNpMWtAs9GzGojQ79Gu6Lg+EN8ltSNXRn2O6wJLI1vTIsuWQYenApwskY5HLzktfUYM5Lt3Lu834HaVv9C6pwOy9/ggbsdSxxHfBn3Rf0WWiIVzLu5aHg/Z/4QNfBmkXton87o52vQ6RYV901BNoErZN8GaMf4FmDsXRHyMdI5yWo/wBHZgRrI0eqRWC5uizTYsGqIYkIQjXlYjkRauxIj4NCVWK7MDzT0aGRcgiCIwRwJdkEQdEWGrGjS7Pk/wCgj5IvwRxgVPghRJeBwQWHZHZqRZwhcxTeKJRF74Gk1kvJHYl9yNpsa5In/I88Ja5LWPgni5Nx2twSpuN2/RvBhyWwxuybGJSQsyPNrF3h22xJZTEsNqxhtj9D4aU96G4liLziw1bSInFkKcEfbsu1ycpO04GpSt/saOzgtN7GROePUCyXZA00r4J2KJ2JuR2yYsaXJDhtwPNyOxj4sKXYTcFplzJeB56MO5eTd9mryXN7E8OJjkx6dIh/4NWuTbk1YkQ5wfEIj5R9rHRaVmjyj7fBDRac2LbnowbORv7/AKFfLi44UpfcTl2Muwlfki1zBjGRGsojSPWiHdmmTBECEr2LQ6Xa9GpHE/4GrTB6/I73wQJSs0yPwMwaZ/1xfk4IuRyJEHrB+9j7xS0V3VF+qQQlZmIg9I9zIpmxh03TGTqkOkV78Vg0ZZBBs7YqaIuNXonyLBuqEqQe6ao1cVImkXOqWm5uSPBYImiV+TBsgjDN9EWF3qmB5PX5PhjRH/cke4Ensa4RFhLkhbdF8dSYGMt8jdl0K+IuaizJ+48XH1ccRhkz8D6DcO+ybbkZmNMy3Hx2MnnB7N5IZ/R8GyIjki5hxKgvuGNsbvDX2osORZ38ibH9jUaSWeU/ghxbPvBdnPsSd2hJXEnZEMwaUGguJIS1MDfLkWbIfbPd2QPH+Ru2IVFkSUXsZsh6tgx30NR2y5JxA/uXnvYr/A/dhepR3kWcC90bc3yWxgkXo3c9Nl55EPLYsF8iwvxTeIOJJSfJ2mf2axLJ4wOJ6Fd3wWNEvFoMZY75N5Ot8nzc1dwJ3M4HtJicOSehK9smoPWURrBH4Hb2dCPZrs12OLfkUTmEQPkidmWfog9neB9UzYjfB2c0TvXR7pb/ACarh8EW7M0aIuZ9kQhrsddGcUi0mxQfNIkWDXlsVMkSQQJbosiEnoggsRT2QK4sEWwQav4NGqNGhKxFri9EGFGzJxSLdnsxixogafyQiPkgjka1Bh3pFiPwNYpBF7ojMkWgaxI8y0fBJHJ2yIF2R0Rfg1e4l1YaUWE0SOxqNn5Dcq+BvtejSuSpYvZPYvuXmWSy0zHsx/R2i2JGlH9HwQnYhN20OcLA1ezFM98iTa7Fdl8CxMw5FE3UkZt9hJPEz2yMTsfFCs2xXS7C/WC0WR8z2TY1ocShXHmBqLtl5lfgfIjV/wBHSdmJNoWs/JPJm8/6Lsky++BzOS85JvKLST2M/RmdGuxDmYZiTNuTfoTzwZejGcdFqL1rZGpPujmRyyefRFh/mlnPY1DgjViLiwLds7LQ0/gyraFeBZtkcyaLIS2caf7NYRG0NTMH2Isb7IsMz0fsiPZBr/RniRKc2FacUblztnQnF/wQ/gmx2O7uTZ2o8aIpyasIikIj4px3RS7eH5MYMMvyQOzGZLybNEcEPRFjoVEejNFVZpsXgiLkUSFgyXNyb4IIIIEoFkS+xkyh6IrBCkgSIIII9DIIlj/5iREkETh2IlENkEWGrU2K2iCKNIicIwrmWWga/wCQkQ3b/kQ1kwyJ9kGTZDVIvcWeCLtk7MZG8jdlz+hxyJmHJeZRKSE7GMGHBfd0RFhKWbUEJiUvUmbwJTmyWiNnWxJLozYSc6gXAroskpx0Q7So4Emlu+kRD9igoa/Jd2t7ItGJGtRPfJZ5y9onrJEKYsaGpRdKC2qajbEpcYkSy4sJTf7ke4fIltpwK/7IhGBniwoVuTbkzkz/ANkXP5He8i9wJ/glNtmrrBi7Ri+e+aJ/cenk7Rj5GotySRKx8lh21B7k5kUtQlI17gzcxnfA4F+f2au7Mulmxayk/Z7wLYlcSM/5FKyyCH69jixMYGJxKfoSW/Z7VjLwWyKHnItDUELQ84N2JJmbj4NPA0tEX/YvvVfjZbiDi489nZBiDZqNHqufginuiyJEG4g9Fo7MC9GDAh/gaphkcGCOURbFM/ArmiNkFpMWFwRcZpmhLJAz9UVI8UiLCVriREkRgSII+whojojZBBAloh0SlEXuaGurGqQPsXMSL2QQQ2s0QQTb3ojhWIxpn6EfBoghwJMaUMi2RJKeCBdnpFoPZbQkfNh2cySUTsa7GuSW9jT5GJ+B5T0XSktmThWsXbZnORWZrs9Iv7MmVCIh4M+uzi5h3ok0pYpYsJsqB3tZf2JOYn5IR2RazQkotJD2oQv4GnKVloUP+wlmFclKnkTibzOyweoYQ4aw17F6E3NsU00JPDtJqzY1Y1n4FjohxJLyJ2h60fg29f2LfSHDtF+R0jvRI79Fh3dsCyWhQYsdMHauKxjkm/Jq72buLN1Ho0ZHglyQ1IsDwXS6PSsPkleuzPpHGzd8ERBEP0du5AsMWejUj/RfZbkky7HH5G+Rux+eRq40tYP2YscQWnEkC1DPVhpTbBY1qdm7Hwe7Ckl8n9mzDvk0hr7isc1wzs/Bu9PxVZ/s+TfR6ph1R7PZIlcSqj8U1TU0hCwRek/JvwwMQ0aFg+KfAriRBBAlyQRwRBHLrA0NVS6kiCJRAlzSIQ3GMU2RakciRBFxXwiJGR9iJIlZIQ1J8EGiJIu4I0OIgw4ILQr4M09ETqCbGKbHyf3HkbncmZmw3KG75GybyYeZFywJwyW3EmbtmXMFrGU8GoIu9Edm7OzyZX9mdCnd/Y4mYRkjMYEpTLlZSXtcDhqyIh3MpJCiIcuNEnCQ7T+RpWTebiamxFry1J1E9jiXuLIbcfoibNxyS8M7F/3Qoa/yMf5Y7pT/AOi5SsXeLDUTKvwLlk4j4LbyPWxx/gd36M50OTNkJrIiGzP+xWc0+IXFPUjvhC/Yk9CshOLLDyN3PYpasLsjk9Csoi4lojgStcV7aFE9QYVqN2uL2L5kUTcfJ+H7ItOiDIu8GRrD5IXwLPRf0YuQPEsbsrYIykdDUHMESpZgebUadHZ2NM6pFPVcjc03RmqZNU2czTXo/JsZHuaaHa1M00Kmq9eCNEWEapEEX90i9FmmzNYERNFmitcixAlcRHFMGfBq5FhISuctENqswNq4/wACRECyI5GEhqiREEQRggi+LD9fJ2QNXGuXYS7EiPka4P7GoIuJC/Rq9jZqLex2tYai3Imk0hvsbbfEDcjcjVs3/RF83G/uTJMp2IuXRqVbTE2rI2PgjUmRKVH/ADEoyP8ABE25wReIn+yLLMHLTEeCG/gStfGyFFgpf0Lv8C/4xRZtrJltoSm/P4E7e/wT7FM6LG4sxLehyrQiO/kd4dpwTrnSF79lpiTDsOVZ6Eufkhu0lzOZgcf6HZZmdDVlP3Eoi6YlKkxGDVkYUEPITtELkj7mzXo3SW3e5h3shf2Q5yJbJj0XStsmYZP/AKf0Xbzcdm9G8svAm8CF0KIfkWI/Jy0fFH0oFBCREKfsRY/CP6NZI3ORLuCJIWYGzSJV3ixq7L8WFVT9jMm8IhnzgV2KyMu5qnF7nQ5RHR/REiNU/RFpGP1Vr4olODuiFM9jHb3RUi3dXnmlp6IIcGz80+Kwe1WOc0iKL0WIEjFFT/poqRJH4olBAlIlYgXQ7mj1RKWJWsQyCCIIuX0bHiGOOCCJIsJWIIagjoSEhXEXIInQ3eIwRYa/yGRIlDGlyXZdxDjVGriV7kRBF7HQ1fhESuzeCYdJ0TaRu3DJi7Mjf/o3x9yyd/wPBDEr2yPt3Ep9md+jrB8ju/Qk3oyr5F0RF4V9GrC5CTeixCWJ+BKBqFuwjYlqEOHixieeSzaZfBJm0CxEfI0+P9kKM2Y1Cjga00WOVP8AsS0v/Qle1uSyUZ7ISs0JJ3djRdnRpa/s5WGRyP8ABEDzf8aLTsaSFxJbYv1mmeoLt9s0RiGRc2NdMebikJCgWhuzkWC0i+GLI+CTUFtIfWRr7iUKSLC/ODYuUW5ZIlYWi8sSRwvyQv8AtChPiTZ/RH3O1ejE4VMyK0cEZxHQ88ERSPZuRXzbsyXaLSRoiP8AQlfNqagfyZPRqjUO1Ni5HrikHunrArezOcmoLkIiURXPui8PZ7I4rBo9mBHsg90QhUXRGSKQKkRe0CEhUSpvwxSCKNEEWEmyKwxdUjmjU8DSg7GR6QJaIIGrkWElqkLLIspY1C9jUGWbNiRAkXDIUdjwQosQtCXJBFxJYQ/yNTfgbuN7dxrmPuS73J5J5mSVDk9jyfJ0YHFg8WEufwYsWjkjVoGbJ0oIWmYSJXl/gSWxKXAko6eJGvlsVlaG+yNjhWyuxGXiI1wQ7tfovDRCSltyK8zBCaSzHY2VxplynLZFh2dlbsykliPuNN+kLdrPZNo/5Id0pyrCU98DiI0hNb/B+iOdCTlaXIlzgtGL8CTeDEQ7oiZI4mSwlPs9KDQkufQ7Ef8AhEsh8H9jUKLMV8i7Lp9pfY/YrfB6VJezmSZPg3ZDjAiPnoam8Eb0buhtXg4Y76LRdXHpTYTh2fyTG4EptYi58GNm09HowzmWajgWBWtH5P8A0RHzgS4Q9DShju+y/wAsi9/kf3YsYEXliVzT32KF2YHT2Yy/BT8kiErjS+S8DV54I6No3JFz3TUbGMybN0jVOi48mokVqLqrv7EhejSNXpBsRDErEW7EqQ4IgykQK4kIgi4iCJtkVwkRoggggyILsNXII4EhkFjIvQlI1OCDtYi0aPwIy2R0R2QJcDS0QZOdCLmWNfgi4kRb5ElTBHycH6LRYj7H5P2Ma3Y3YeeibdE42N3zcaN2Rvk1M/Bj3Apk6THZZkVxWLNmZLWHM3/8IzFyNETsgSvZShL7kYFaeC8SyzQr/B+IIh9imPeBHdSXiL+htWi7G18cmjcRIrJGrwWlMWx2YhrAeJm4onDjYrXakaXNxqEpTH9kFkC02eSIai/9ETki2riRdqUJS1C9yTKj5FwK+XBh2H7NOxpXvLGnmSCFF5T9DWhqV+DV8vgdOf0QKy0dEaHq3+ybuDUwRcebC9Shdl94OhK8bExKXAnFy6OiY9Uno7n8ClScUmYiDN3ujcsSlwjNPRsawNcGBQmRyXYyP8kYjZcZzfJohp3VjpD6n5IkV0QleRbNDX+qQQP8EOJGQNPBZYFdwbvsj7kbFgyx9UjEixc1B6MCzcVmbIIEYUc0imBcCtJqm63pBByIWBoiSPDmbiVqEhLggSII7IpAlcSIsJSQaEkQJCMD6IHkaEriQlCEtsgStIkIQtDVjQlIlexErRgic4LhqwlBBGGIYRFYyxq0iT8lhF+ibYyTDXA8sDeIG5mGN4JXongfB3zs3aDEIdhQ9wLEGJjIvVyCFYi9jD7IZvehY8EX1dGUEaZa47PkxkjJeNSJXRELtkZkSX2F1CG8cobm8fA2tfolMKLl0paT6NLEcCsrQ52xWbUCcO6Q3NyZu5kSCTuxIhtWdvRa7u40XmGPM55JaQnZ3fYs4sNJtJPwWjmdrQ82HLcPRhmejdlgWFuGbEp7G3tjcu+TEcjmVts503R8aIs7YYrTGi/yRC6Engi+LF8aNXVj9HOzVrHY/Uz2L0WhR8n9jjtcHehR9qRJ6R+zWxYuKFqltHe0K9m4FMPoi3Rq+BLcWIH+COhIWcES4Nxsj/Y0fomysOdm7USuZEvuR8jVxq/B2RsZEXLqLZI+GPHLIXujNHFGrEQRBz4QP0fB2L0QQqX1kz1SIPikWI4ErEQyIyNUi5DTNnwbEIzSLU1RLZAkJUSuQRBAlwQJRRYEJdEdEWIaEiOKQSHKvRCUCCEUJNkEQJMagSayYIRFxq5ZkWHZcaEoRF7n7IvciHYgUjx7Z2wYbgd1Cyyw3a7uN3vYb3kYz2huLI9jNyLo1hkT7I0yPght9CyLa0QrcMlPBE2MzaT2uMi/sscEKDLvHsiVYSxsjM4IhXwS3K0X0+SFmSy3bkuaejd0ztWFDabyxqHZqehKVBec4HfGOBxKSsOTzMDu7JlvTkWXbuRKG2abi8EpkiVf9FklAovnFpFC5Em5ce4G0/jZF2tbLei6ggukrR2JiG5FdYMXixLR6PI8LD7IXRDiCIfPJF5f5IZ0WEt6ErRCfvRjJGOqRnrsn/Y5UYpbs0zCNLgxgQ241HR+DRqdEm24kUN2X3HnkiLobiVY1B6yKYtgv8EXMMiz4GRdJ4GvkavHBGedG6QvlCV5Fe/JHQ+TCEWGpuO+aQ7vQxq1zNyMiSnJjR/gfZdsjZr+uKRamjEUQ9s/dNC8OtkGTZFMU61T0YXYjdVRKx0dbPsauI0RcSIIwR9yBJCFkQkQQRcgvcgSIwJXpkibiEJEcEFh5NCqCUZorMGRHQkRcasQ3cak9nwL0P0IVLhy9C4XIvg1EFxBBoSSLxOh/oayG4LGbjaxOBsZMivaLnsWTngjq9Ek1Z3QlK5R+RKbrHAlzgtPBbsQk38EDSS7IvyWfroi+LEP5HlRoSbfRtiS5j2JLZYoY1iP/Sx9Dz7LR3pcnB34EzdvsRE9GHhX5G7y216E3PYom9hxk47JTuSahZ/olexNq3N7FldKRJT8ChbtyTe5Z2ZJnoulHZmOdjbiE4Lu7zyMpxYyrMWS83ZhnFsSxR2xGkpXx0NJQr3EoaiOYHiYzo1mzLcwxK90ex5lfcgWbYN3ujiTEcod3yegjAlNouI3eaYdjBdbonY9kaPjJxeEI38GCIxsnq4qSoVnOxu3SFYWxyxQLtHayc/9A1G5Lehfkw7n5I6de7GoGm0mXvHzRvJCinohSZ/o/YrEfJjFxeqdyj3TSvIy69jubN3IsKw6QavRXqjQyKJfikShIy8kU1RZpcjogWT9kckECQlJBECWRCuJESWmwsmWIggSIoS5EuhLohFopC0JdUaQJEXsS+RMNbM9HJAk8aGHdg9B9BWCsIu42QhK+BIamxEWwXeh8DlqCNnI8DfY3G2MxNiexseXBvml4P6Hej60diLiEyIvkd9QJXErwRbgVk7XQlJDYk3YauJWUERnAk44i5EvGdEcCUppje4Yr3bF8qSOvk4tYhyW3eTrAlaFoaWxrbLIlJ5ljcSv2PvOhKU+BqMtjUsjObexLPnRxFlBlbJJJyEoLaeEhK/J7zwTqZLro2LDekWiYy/sOIyWvk1FjWvYrKCEnpucPsvLW+ztYu4fstzJLgN3lvJui1wR0vfA1DIf2M0ef8Fj8Hf3FZiniTLxBCRvkb5Yphi1iKKRJ51+yMzZaNK4k46Fh2IFnstwLOT1c12WN32OY6LnJNnyYRDfpEpRaTUPA7j/ADJFmdoStY5NSNXsRCXI0RYVnJaOzQ1JFEvwPvIz9MQ1YghNmVO3TYrswJT8kEEdiU3VMU48EiORTAhmj0yBeiLkT4YEreiDoXVIsdH9CIsQJaOqQRsSEKmxIS6EkJISQkXaqErEQRSOiyJEYHsQJW0Jcogdh9hA1YRFhqBKhwtBjA2Iti4kRyzBKjog9oiOpGryN2YE8DlsssNjJJmTRrshrGx4HRw7YGiOMDxg3iwhcZIvcav0xLlDV75HdIS9CU9EJ30JItfIvuK2UXfYsN6Fs3CQ7LBEaMieoEpcMa1seROFLUpExec/kWpsNuVZMc5/5Em3PsW7TYaFyN3Mj+DkdvgzqF0YWR3LbIfvlMTuBSySdvkyO1mN8fka5RG4cCw4LxkXcmcmoWhOxf8A5ky2Tj9mM7Lp2/JPcdDcxOBtxDwXviS7+hv8G+RyfVEeglen49l17PuRYfKReDY7kOLEDTkREfgSFubmsMwti9wOzVrk8lr2J4H9mTHomHaGSuDV6Y9iEpI/Gz7kWp6MCyjbjAsQfDPfwYRFyCJ9kWI2ajXAuKbQ1uuz7wJQbIZh2NGQnen+R/YiBLQ6brFqRcjkgZsikSQRRUS0RajFPAlwJRlEWIuQI72xKwhGyCCER0RR0SEoPyFYJbI4OBF8WI+CCJ1RFiLEQ7CRhcsIRCGoI2RNqOArqMhoiR+xFjQajhkfcaInOzkZZs+Ljgb+RpXpjdqN/wCnITC/o1ch7yZZFiRv0ZGJWfX5IkicaErSc8iwJS4wJXnSGlmPsJc2Z6wRHsUuLHDX6IE8MWexN8X7Etv/ANIUdEa+R46E7wiVCTuWW0ONGViYt+TCdrisr50KYZz1yYVnkS0hXxIm25t6IvZSOxzl/kV1mlHIpY+4rmncSQkiFo0asrndpQmowr6LRO5Hnkx0j8cERk1ArKedCUKzu+OD4vBlCUKWsitDvJlRMxomFz3TXWjhfjgSeV9xX7ZPGRNQumRCie4IkavzA1uLGMo3MaIyFiNGbRJqyGuyG7tezsWcSdkWmLckW7ZD4Eln8EO5d20ZXBaLsfRaexWV2Ny5ZYvki5EEIibxgZeBXeBZMo93O3jg9GlIlGCLnvRNhYZA0QZciXRGqPvZGtEWRKeBjEpZ8kXseiEMczRWnYlYi9IIpGVTHZs12QIj7HVII4QlB7p+qLJHBBBHdhL7CVxK9FiiVhLkgycQQJEXEtl1xCVsCQkEjkENC+VC6CXRCPgi8EC9qEoITeDIULkd3EEaIbwelN2jDsaViOhKxHBIs7GlqE+CPuNaGm36Er7Itye0O0yfcGsy3DHHD9jjMDTkaO2Bpgu5IlYIVH7HdiS3cfIl2JcZEhKy/REO6Gj4I2kJPWRQhwReGiHhYP0JaTItnBHIksEbasNIkSUUEq6i42/gelobX+xOLJicLlGNShO6bunktdog3Lbc9GHd4GtxC5Erc+xQlzJFrof2gSd2kJWSnOkIST4IHO+GcgsJ+5h7ElOYkV3iBXTbYFJDVtDRW2qTyZhbRHP2JTamUzWoNDmJWBmDCgiLt6JmL46ML5+wlK9aHLwfs/XIzh8bQlfkRFiIVm/kemW/9N2hqbdj4D1wNPE/cWNP+hKPRuw82/8AaKCN2MNkCLTFiIdsieOi1M4J0fvoj/ma7IWhqErW3JBjtnY5bkZgjBN/YrTK+C07GYdhJZ2LMwxpezVskbPwQ/keLjR+PZ7pFuiL20NSi8DwRGT4IuR9j0NUd0pInIkRSOGZvBA8kWuyLWrHoX3LIViCJErEQLGiBrmkEIQpEEQxq5AkQoIEvyRcggSErkEGSJ6EkMgSvR2EixLLEJUJdUcjIuEkEWEELIgSImiKEi0Rrkj5IvCIhEXkaeSGoIZFyBoa4EHdci8DsNq4yVzLgb9DhsaJMbMTbHG6Oj+zHGCLiLQQ4RjcluRKwlbkXrJ8vbMJ4I2QZ/yJN4FZcjViFgbvoiWQosyLJiSklJTYbU2iBueLcDsi0fsmzVrk2svkczbJhq4m4thYE21myITbs7kWjZF8oSS49D0psRGUJyJIStFhpNuRt7vKFZcsWVj5IxJlOc9aFHN+IMIj5Iizt/RLs4FI83UDhqIfRozf4NJ/0La2hKbJOVky+iIgW7WFncHVOJXoblXE8RZo37GoV7dGveRWhyvQ3PyRfDn2JReBq0iiLrI1eERyroaxGC3s0iGRjXR6F6IWrj6fwNRaPki0b4OxJyRMNsXqCb2OZyLkTiY8Pg7mZ+4rO6ErMi9x/kj0K67EmvkahxstLmkfojEES8kGYRqCId0QNSqtFnOiLZIUf2ZSsQ5fA3jlF9kbSsQ8inY8Y9GoFkSIeCG4yXfwXQkyLEPZHFIki4ktEFpxakOKpWciRq6I6GjuCJwRbBFyIdj4LGyCOSIpBBAlYgSIEkRxQqiwTRgVCTIoYLGRA24EOSIEEEjIjIhHBJsTZLGOwidHUiXAkiRBC2RcauNcESK4+C5DSuLQx20O4ZLseV4JHcgSjI3wO10T0SS4LuUiT4IuOSkS/JEETYi3QkzeBBrgU22Q9ilqD4BKHYRRexGJFs7giW7/AARdJK5l2UDviR3aE7ShK5xCwQvYmytYbxCuxW0XTLZiwu2KXp/Alluw1lbLNSKx3RaErChsai2WSoUHC5FOksRXmU+BJ8pFhOV/kSTei5EuWoWDcrkQlv8A0RKh4Ij5ZGlCaciSjDh6Hi/4Ls3b5Jgxebeyzb/RKjNhDix8yRGVceZIb+B3ybuhLTCI6Ic/2P7G7YI+Q7RNGoviwlLjB+IFHMCs+eiGwpEdNjU3wONEfc0jcGo5He6I5J1pDysIw74HcSkg5EWsYZF40QhRPXJKixJEqRqIIhCjkeBZY4z/AERadCQlKIXZ8KD7DMzwR6ZbsWsIWWbGaIm+iOMjQ1LuYIwQNGsIxo9iOBrgUQdEWIo7/wDZIsQNQROMUgSIIg1T2L7EEWF6EGqRwISIkjkgSEiLiQkJCQ1CkgTgS0IIJdHoIJEIFASIIuQaIIvIgusexIrRcVmBWYpV4l1FENDUdjVpkjgQajZ0hcH5LxYuGg0tEfAiSluIELkPey9c2D3TGxSyIyQlsbhkvQ83G5taBq5pkWErH4II2LlEdSR9yEla5H2HwuR0JG/Yo3EuWTDY7L+iGsju8C2/MkIcZHJ2baGtnrI86gsmTZ6J2dsxBDnBHwSb7IxP4FwFDmSLQ0lPFEJRH2HFkTA7pTafRMO03zIloRKEziF0PNrWgSi3JMSuciRCFGuSEc39CSs3tSJdRzcdS3LgaSpmDG0L1IybftkTnIs4/IvVzGmYtouV7mpmB/8AjgUT0x9sXDLPKcpmYMSTtEXsRNxqXGFyRa33IatsUakVnYjmX6HwTMSNKf8AI1aE7eje7HuUxZiMEuLNqC7oRzK0O7nk/BFsfIuE49GB3ZjuCNzJeyPyx8xHoeLmNoauXebsVlBmLGBWefsXjM8F8nYjP6FYT+x1laFc0rmHSJc4FsRPo9GbkN30IiXekSdEaYs9Gc2/ohzDxSNkbIvci9iLnVftT1ukCH96Q1ogQrECyRBsgix7pHNII2QQMzBHAlF4kg0JXIEpnRAkRboSINiCkXdCTFBis7LF0RAlfAk+BQ0QYErWoS0hORDEz0LgfcEu1JBCX3IuNbGy7kzhH5EQlyfI3wZIvca+xCE50O9sDLIgsHnccFkRolbJbI5IXsbSspG36J5Jc5uNfc2Wo1K/si9tETcjkiNiXKsX+CIhoTpimLIvGfgh52xaQxTs9CSzFv2QksQf4yTOGRJKRu+LktnwXHZi+ejbEtcaduHgSbzdEK24/B7wM9lH7M+4sYd0YWBymKIm6Zq3+ycnHwO9rigoWeRZiJ5UmXXAl8f0KE5gW5V0M1HDQ6HmtcCcNNnPI2SamR3XeicSsjSzbV9MbY08Ibr+xK3tzBxJMOxwjWEjF3mfuO7g7kmXJKnC+CeBeoM7My4tiSf/AAQrrMsSYtDYrKNZFmVwXa6FfC+B5Iacb/QkoY1fB3lFz7/QntOw1EX/ANCsrCdzmwrrCHJWMkYO1iMCkRe+yNbIsYGr9iUf2fsm50ElyX2Nb5OxH2sWieRSKZ0WZOEChPJB/wBJqiUNcm9DUqdG8CwQ+vgaix9hkbeCIebkWbI7I3oa7HpkSiI+CFkhOB2ERbQ1yQiF/si4l0RGc0+KQJMixFyKIggX5H+axY93Ig4IEQiBIS1sSYkJKaEpEpEIEiJuZYEEhaUIEhXErEpDgsIIEgkYr8UK0SCsIISUdkJZG1NkbLtkNkXIudwjuBlhHRhjI0g0YJbOUalCLuRaL9hrWRuyGm/YlDuN8IcBjLsnQnfA1fs+SLH/ADFgSuNQhKVm5Cssi7WGurEsiZP2KfoS7EkZFqIsN2lUz6JtNrclg4Tgm/8AY3PE8kzd5ga6Q0TzcjMfY+xMNtjyob9k8ZNJwvQnN/8AkP7iVGYOF4Jwlf2LmPY3Lj0WTwiIT3Ao+CUlbA9nEfssjBKTKZLNt89ig1KTlXFBxb5Okdpig5V33sT4axrgnpbBMEk7NaJTUq0ZQpNQNDxsT2S1Kkyfci80vOBdSfJ6FCz+C8E26G4spE77foa8/cmyWVsV7XU4MtRjQpeDmL6THi0oVosJOGXj5uJKbfcwJ83gO40sS7GVxvU2jg+GSFiDRFvgskj7iVlKkhLBppj0pkyRcyO2jUEWLGlGDFHERxtC6HKVhpJXTkR+hlisJS1I83ls9Grl4ItOiJwf0ZEuRsXxJikK6j5NCUmiOM0ZHRA+iOBKSLdC0z2RZIi+IIIIcIapsggS+4yM8kdEOSLEWF2QQJEER6I6Fgjgj7kEEUIJXLGUJCSrCgegguCgwOkRVwm8DVJcUFNi5CopEiIi1iJ2Rc/oYkTve4lPI1BeLEEkCmbCuyWStJYsOQhYuxzV38FisMwXZFxtexxVrDiNtqZHcmX0hO/si3siKJWkhEQ8CEL5E0ETxAh5mBYgS0K7F2KCEhxxgaVrSTrCHZ/0S56eUS27kv40N3ynI3e/4FAnL4RLSvhDfA0hznQz/JL3kSw+CYWxun8Dd+0Ny1Hq+zUEzYnF7RclTcTTUJuRtamxBj5IyhWHZKcvQ5Wj/YldJKLjad152hS227CQ7IvLbayX2tkdkouXzLlkeE27LEnSdnoTctCcxaP7F9zUnsecCawK7RyKG+xu595LH6Z6ci41was5Ji0z70K+M8DUaz+CVxc1mOOxPA3Duo5PsxaZGo+w4hy5/s3g9/8AolZ3EzwpIQ5tpi+5aYyoISFFuEaxJh+BqHQlzcXwZYsJb/A1eytwQQlJpXyccoSm2xaCUsURx7M3ObLoX4MzJpEdSRhjzZkppQhWUTYvL5OtjUK69CcO4r/JGZEKLC4j2OeSDBo9MxPRi0CV+B+kPOKNcDVoIImiTRFuiLEEUjkSI4dzZFiLCUkCRBD0RNyEiNrBBu9GsEECx6Ikjg3gyInNCuMhK4lfAtGKgsBJIkRcUlgWkfIoCOVhrgWwo5EF0FESW0Z0RyQOxMIaE/ci41HYl2NC7Y3A3nkjgfI5MgiRiXsg49ljJDQmx8DbfRF5LZbgaoZcxuR/g10JXIsQe7EbQkl/2CLisuKQliSMmVliSnBDiyIzmS7ggz9hJKSL4FHFx5uIbtbobnKG+7jdpbJtlyPozFy0vgjfniB3LzbgRqY4Y2uTHY2tM1C+w40hX3cvESrYL5iWNzMxMk8IlEqYWBuYQJm76Ja/2TxDRMKPwO7sh4yr6Icoect/2Smn9ibpMbi0vtIbWUTl8JCswJyblqBNO7IQoSVvkhEOCE/cIwOnsTM2p3swSJ84FPImuxOHajllqTlL7kzaIH7Hvb0Jtq7Fj+xXx8kk7it/shZCbhxECe4EuWdfsSnA5ds8CUJQepyQ5aRhJ5Em3Y07DVlg2Q7L5II2jRkX2oNSNcr7D1BBGcCHKMWyaMjiCh2FMahE/bgUTlkTuBzAlCyWm2C9xNzmRq5b4L8FpsJnypRErsuNEdMjODZAlzI/RF5uLB8D6hjX3IcfAjaI+5AuVBYaHoj5ovRA7kDyQJQJWuJTc1BHNIGhK83I3IkQRYvogSEiBJiXUiFwrRQFZQXAjdiMNCmjgEOQsuAlImkU9MbF0QyubHcSb0JcscJSMu4zkSWSRzI2TIla7sJCUeix3Y7XSbR2cpcsLm7kbXeuBjxJfLcjGq9nZ9iQbZeBfgeRojn/AMEi2JIkWiJf/XIlEQ7CTuJQh6HKtAlYSwpFucjThYHLuYUk7HeOTWZG5dxtZuuh33sM5m3wTx8jcPKkyQ7v7G2m4xpjcRA5yxW19x20Jod1YkyT8EtrKTQ8vciKJ3wLaxwO0wTicDurNroVku9EuL/0KUJWRLTyJ9yW1slLJDSd8i7dujR2tiSzUkotlv7E2focPbE3E6YmufgcXUpp46NJ+xaRN5vIx4IZ8kdEbWBpwhqMktetE/7E5lI+D1lfkULdycHTwZfFFHyjHyPVyUtzw0LGbCduROFhW2TKmb8Ma6Z+CYi3zJKasJt2Tn0Sro9O/IvWBfsTh4+eCM3WBLHQnDszcbI1AlNlZG1ZHLOiBrY4ghsmZERcjqkQveBIa4ufECFdkSJN/B2J5tY0WhMWII9odn7LYwLrB8Hqxvoi5F4yz2N2o0iVLQXbGnGbCnMFkQRfkgt8l+L0QixAlYhn7ItDRH3IvdCTejoR4QIgSvJBH3IEiLChoSsJXFIjojg+wK6gvsZ+FC4IVnAuQrMC4IQSLvAmdGS5BYHJHBIhJZGmMD5jdyZeSbwzLBNyW8shvQ9HQrRplZkeC4crgY7BOEMbHLIlyOy7Hxsh8mSTxkky7IidERsanOj8D5yOEe8iVrq4lyL7BWkStk9WRdxBJM2Q3MUJWVLEjL+RXTNhqTgaRi5N3cgn6G4ew3a5OmTKdsbJ5ubiLkzu5MDeIUIcJxwN8Kw5+DakhyybXY73iDTTecCn/I4jEEKL29iatNkO1zuNqHKtoznGx4UI70J3shubtuRqVEmp4Mu35If+RO9Ew5blE3yrjuLqJwO2V9tFjfJzKvyNyk5kZeiMIvyPCl3E3Jtu/wCT0cmjPsWbiIvOj9loeej+qdEaFe0ScdEtvfYrtubCvnHA32NIUJdsxZ3Fu3RFsmUS12KVfYmSiRQcqUJ6lLsmWJwhNaFhzwLnQk4f/QRLj8IdvYp+wplPYm3ewk88kGhwXWy7WiED6DS1iMN39iTRIiHDPZG7oc925L/5OxXFnoh/AlmdF4nQsCvBCyhr7GLCd7CIXZF7/gSOD0ISwQiLXkiVZkWQ/VzRF5IzBFhIyJwQJQ7myBISki1zZi4lfBH3MCuO4lIk0fJvYlYQlLI+5HowI2JW6IvJBFjDsl3Ago+hbHIJX6EpEpAgUimhGBPYuYEUksF+fgyRA0UUGzd2J3JGl7lytTN7/gTcifIpI5EGrzzA5m+RzsNWWP7+WNi5ZG+BrA+BOB8ibivWD7Ek3Gi+BLkaR2XaEE+RLkhIaFsxTGO35IrMjbsJWLTDGi2OSbHblD6XJiSR2Zu4+WNXebjspvJi8WoslczmIQuCVpsSegm2+CZ4XwPjZKMfBN7z7G7XlslzYvklHCMsd1slktO4/REXnOh3aNkzFr9Dd7xA4b9aH19huY/6TIfZv/JO1MLJPXoV90v8FrJyJ3Gs960SScRewm5TE5kl9ErbFCmXj8mVyxWGrOILER7QlfJmOiLi3KvohmlcwsWE73wTC4RK7UoymTeTctDE5SHbHyJSvQn1gbu2roT6E7fJOGtE3wJXwN/ZaFsZqZ2TqbCeoZNnD9idQtEy5bFdNpxyQmv8EHmxEJM+BZibiebl/jg70hpvsaacEOZwRnZL/BhLGnwOFkXEhrNvkiNCV4GosyLf0XYldcCV8G0C+BK8Hx8ihprgtg9lpsZLtHsX2Zkhb4EuyORf8hZyP0QoghQJKCD0PWCdDXJH5L0jixFyCIOnki+JFmxB6ubIbzQ1K7If+iOBK3BHBDbF0FDRgJXkQlNEWEywJwLkJVkSbL6wJP0K4XISrQkljIk5OQglc1ZGRdkpXExZwNNZJBtkac0P5Ez0S3uiTYkhSOFQcNyNztudkjxjJ5GvYfFjd2kbcZJ5JyKYsiLSYuPkTJJtESM0JLGBTZBLBEsXBik7lhwS01Ajm2xHAnawcY+SHGBJq+htYi42WpmBpht2GvxwNPtDaZN7pwS76bIve8juuyVOCS1kLkSOGks2FxMQNp20Tv8AZPdmO0XuxolMyOzvoaN5L2MmxfZMLZPJNom483uTZZpDd/8ArCccjeZf3E08Z4NhOIwYn/kXSfI32fhCcReGKF5uTbo1Nxy0TxyJ9zFpJunkbthKOztKwsxKtgbE4atnkwpSUrYr2OXsmLzctxf9jzgi8GBvgUt2zSLTOTUnSxnNFj/rjiMDvg9kcsVnshJZFb2aZe0IwuiYhods7PnBMxDGy7UTYt/s3i4nfLHK9iZ2XzAoTcT5Gaz/AERSJTsxdNkSNoyhMoi05J0XeBLvY2zojMIhLeh979ji3F0N4ui68Qxx1ByHBDS39yLWIUcIhOY4IkSV7yJGVrsvuGN/+kaJ0K2L2ER1ajRjNjfQhfkjnAj2siQg1Lbd2REbpG5wJ3yJXGuSLG3BFFjFQaj2Q4yQR2IJCbBwwJIuJWuYJl0WLsC4CsJBrggStdEK8qCFAl+BLhEPeRKykTSE0IU0XMCvFyEVPCEqyxWxY9k3sNFuBpobu0jTbI3aGt9jdwj2HYuRyJKZFBZDVYLEJ3HPLGJnklcS/gbSzeWRi7GZNMemhu5kiDIuRkk5L8mdCTzb0JORrBbaFD18GbHYTCRezCREi9BXq1zkFb0Ql2NpLrPI3NvsQKZvomzvccvP3Y0082/QkysjSVrL0O6ItyNbA3GyxORON3GhwohEu60JzCRKiwy1gbjLG8hpZcDdpsbm5Ll4sTaY/JyE2uTKjMD44Fx/zG4f9aFOJ9Dd05LsUS5djWiZasp7OcIb1N+DtsfszkbtM2MuykTaWfgbhZlccCnKE5n/AKDCU8jcK0P+hY0aUQi7TtZZYoauxRdLlu/oeR/kt75NZNYgwrG3wWbiYQpwhNFk8E/Ir2kc2Mb9wfA/ujtG5jIpbpF9l4vvR+ibWOjV8oUtpTIolkwN7Y9cEzizE78dia3+BZmTCs8n5Cb1dGEJR7FLiRaO5BlCaeZMqMMjFriZN8HwOPghCSvInCt0Q8aeyCNJySakS1A0rWEHoKA4fJDSvo/JFuDXY1GDZoh40dcZMudcCs5FxLFZCGtO5FokQS/JGvyRG0JciVheqQQWjBEkFnYl9hiMzkakiFYi5gReSJyh9IJMk1LFBCsqK/DFB4JSRYTxZEdkic2MKxdvAlJcLC4tWRwiL2JRfAg5YQrFyZiYLBEwSIQ9cDhsa7cj4uBlkKLE9sk5MYIb0JOBLkSWxtJf5HfpFzke5ucLHbYn2NOxwdhr2SYQibrZqGTBCvIybk0ta0nUit7I5yITvgvtNsbtAj4YgtAkkuriU2FeNYhELA0TYaQ9k4zA2+PkacdfsaWDgcjvK6GsQrj0VvY71fA5TkcobHaJVybWeyEtufRh29ErGyYTSG8Q/sPkdJZpFibjzlDd9r2J7M3eCd/suti439xu0SibJ8GeILsSNuz2wj5yPMyYzl8HyTxYZKh7YsZJ2PfIsRORtJ2ULkmLCcTdyTHM8n/STw1JKyTzN+BdyTCsvuNmk3NxLbl5HgXocKLyblWLRm/AotSSUdjwLnXJlq/oWXNhTewm9Qey0dCvolbX2Y3ss+hfYntixbP6LxDEnZL2fNiw3PsWOP7JXBexOdCaSzkTuuhO9iYdnZ5G7zvsXITvLtQh6gTnP/hl2LmuRd5SXZaCHpArNp3ZEWw+BpHZOJs0NZ4LKJR1Bn2PYdgm9kG8EE72pwO2OSyIyRaxuw7YIlX/AAJOORLshcXHZbA0y/yL80yhJPBPYxekibdH6LFtotHZE2GndEEWREuyEhI4IuRByMswNdiQgkvtshIgLobUllfI2l8mFIbyJGBT+Rc6YnUXInlCoEo6C6K0SSEJdieRzoJw38C8YJC4k7jwoIn0QtISsSltERoldiVgl2N2x3u5JNxoPhfob7yPQa+Rv4Ikt8jQhJKbG23gZF+yCw1BHwWiGZwoJeBZ9CTvcXa4oCkI2LNkJrNkjkRAkkr/APo+rE/A5eBrLdhONjUHNXwSzeRpa3+iN4GjzHsh6JV/2xohslpTLuJtPF+xuM4LroRMuyXyN3bhdjhYUFZyN3iSZTcnBKh8jfN+BuYtEKBuN3HDfwNw7REGHQnCLNXkTglbJTiXf9k3UjanLj9E2g12N8cXG+CMDx2aiLiif2SswS55LadxPn7ku0OUjUJkzChSTF27STCSJe2vghq6yRKexOm3bkWNiJ+xlX0PA05gUu5ssnmUesGVq3B/0D9Ev7Hwx2wZtyTaydMuTQ3JNp2LN3/snkctCahq8Mky7i3TpC7GLoV/8id2hMmZ/dE7T/yLtIkiXORPJRaZGJ+/yJHHQhp5JFA05LR3yOcvfA3KhESrtIbPROPQ1ZKzZlfZCyNiadyFHA7JHdZogVsjsTyYWQrJ5Mhy9CRiFoSEvuKzIlDVmSyRBEiTj8EOLUizIwPo3cUo2mxzA295GvdjNT2J2sbuL2S2vklvJPFMiyKWLBexdfIhF5EmxN8CuoesCvEorhKRyJWEnwLYRRTSQK9jUIMDX0OMiTnJAs0hhRJLkbNl2hfknAmuRquh35IXyN4yNtSS2x3DyG2hlyuS4E3Vuw3aBtjnIkeyXJM5HbInOZJ+w7cQfMH4FHZnLIUYF1BxAk7jm7JiGlk8fkc8pmwgrjytpdEPOF2NLuxLED28wmSTmOyZTlSySVsMcLf8i8uWvgy/645ZHdAnZLEmR56HDss2NlKy2PkyXfgm9sjaZ/JrJl2Te5NoE7qF8HqDecUl/I3iGT9xNzfI73xBGdR+TCmHLJT5tol8k3FN+R+4G73uazYbWE/kbl3uNQ3tjbcP4P8AvZtRJqw7O5LgnjCFDmScFLHNlKfobtlT0TKtaT/kPIrHvgmejOCdcESjOhPEsZpNZNzovvA74tTMxZCyR9hdZ4IiU7Pgm6ngV56LURFxcTYS4LyiBL5FYeEemW0KG+DA4knlfkynGCLZE9L/ANJ3kTuJrZj5MSyH/GJ2aTsK62ROMpwTMxrQpqBo+42JpvBDTnYszBCbA8x5cDhsjl4E+LDanQmouXJ9DUlnD7RClyrD+yhJSLlYU40JLRbMpwO+URDVsm4dyYULI1eWxXiP/RpcEWVhy+xMS0fBCcDs70RbBaJcZIawkyLEEzky5Q49zRSLNiNENbkT0rYV9xDQk0JYbgS8CxFDRHQk+BJ2jIil4uNEkEmi2SOkNEHPZysarcjxhkuWSGdSRbJhXsRHpBJxLJiR8Rs8kNnCSbGIj4DkT3KGjDFuSY2NkmSCJwQskRcQo4MrM+ZE+7F5nJI4J0JmdGr2Ep3Ay4Txb5ILvA+IkY9SJWY9CSiEOVdwvY1zeRS4D9sNmyeNDjkk7rQ5+hww18DWr3R6GXAicyO7JJ9eicwsCdm/shPKhSz3obYfxBh2HZXSG7NE3LyPUNEw7MWMGybZuTZXuavb2POo5M2TlE3f+BWnFibrZNnb/Q3cb1CvclfLG5lvJqSb/o1gTtiY0LMEp6uYmxrBxCSNdl9M+X/gcT/gs3JbTHNpmw/Vv2K7UIY40O3oyskuFHyfEmo4Itg9/es3GpU2gncmScSXtk9wzqDXZkfJPQ82Pi6JlmuzL7ZF4WfDjMC1KgTsyTno50ezTE+TQoJLk2T2xOPehmmNlCdrS3rgeF22LJiKExhnpYw5gyUDZkToS2nYkc3idktNWGl/oi5jHA4lyY4PE9F0SxOMyuRO/E8ivYjlK2yDUbIUoj8bohGQ1MFj7PhdjT3cbWMmJiHN9ioNuRJvZE2Eh2jZdDUO3oVniRYwRc30QJT/AJIh2uJaLrWoSRECOUkS7DVtWFfCE0J0fgJdP2KTuJZFnOTogUGJLdhLj8jRuRvqw2bmRC7ci2Nf+xteScZIciRgkN2oZ7ZKW7jRE9SJ3iRqlYax82OTJvI5YuTJI42TombHyP2T9jLpeF7PklJE+xvqiEvgykRNkTcXApFIkvkV1kX5NhOSO6O0Y0kmtBZYlj8JxY3JKvQ2bU4/ZmPXaJsM0+9kzd82LG4eDstwTOTiT9scXrrokh2PXApnPyZXYm0tsZThz0JmEDbeXEDeBRdGXA39twN/YmbfgV2Tt4Jh9k3E1EyTOHJ3+DjljzaVJMNRtF8GibbE4nUEzET2Oygu7jd2jdjlCdv80i3/AFz2K3InlJSa/Y3LtsjKMK+B6jjJNiLwTJqXh4LuyfxTj9od8OxdWnORq/Y/aEWkX5il9YEpJn4GuBrg0S38CcZWjqS0ZuhXxktrQhidiY6kyhavc9i/OyVApZn0X2LHRPOBYE18iZqELEEwO0bMI3yKDXDE5dlcQVl3YVgnaCVzBseG7/em53ZBZYiw5EzV4S7GTcCht7GrT0ho0N+Ex/AaljX4IeEKVa3+Bwu2ZZnkSTZpjJNuBbMgjlSQ/RZRF8CUYEmJljBEkEQQJRHZDatg9HJ0RwSFyIvEEXOQlvgSci/8ErXyJJCtq2hvAneiUvJD2K7BpSLg0EFeJLLFCE3OBzlkVhHLYNRngkQ1vMI7iPA3fQ2eRNsTjdiOhsx/cbsNVdDX0Nh3knYd1yZZNyzoT1SSexuXcTfJMEonuxP2G4Y3e7OJbfQ5q5NiQn/6N/YUcibwhZhMSbEnokZ0GAn1L4Htqwll/ka0RPQyWoL0Ndh3r4JRtTksWCz7JCV4dx2zBN5G7FjhqGNCyNwu8Ch7JWY9jsUslxn4RLj+htTbAmloZ3sTsskm8XF2NcGdyhvcGVZfYeYG+xWmyJ+xwpWCcNZkz2J37G75uTMvuyaN8EivYyajBsbUxGBXm5n4N2MPHszhD1ySNxDT+Ddoljs/Y05uQvjRlYHhImHZQOYv+Se5F/zgmPf4HMnVHw7ExstGTRySuLcm/Rol7pfCo+OBESPIjDsKX6LtQMapn/Qh9O4hGqTYnHAiT89mNkwTaScYF+ycYsJ2eLvZhk2tgm3skVzj8k40kS56MuGKwTTUs2S0hQTh5E8aMrHCFvgXMSJAod0QnH+yDH6E5zcmp2iMSNLehpJPk1E+xMPGRgTbgjfBGIwQS1JMqRkLgfaSH8MZ6FfVxWbeCJuOyx9jNpluywsmLjcDc8v0K97kuC79EShIUYLlP4Ek/YkkRhNxNL2fAl8JF5gxlj3PuKbka1axhBgpLLyS0NnuxLE+5JksSgk/RJifI1NMJDZDfm4+ZM5uSuBtxNParNsbaVxOxKtSdsaDgiY2E+yVHobuTckmF7FC7PZDEldisGzif6OUSZwYxZ2PtYSTd34QiIWFztlmW/uPayPLk4JL8FiRu0vA7s2Hdb4HcXLfME4ejK5K72MNtsnKG4cMmM7G9CdpiyENzLL54H7Ey77JX+yYdhtv/Q5X9oaj5G+zJJN9XoxvjJJM2g2TgUq60ZG+I/yNz8jiMuC2OvuXGrxsnRwTEo1ZMXSgtw+jC7pdXg1fZK4vyJWczP7Iu5J2rxyaUYHiEQtNu35F+YN+0RGcmR9jyoY/wZ+D9Ol+bD9l7UtqkvBHJ6o3DJdi89nwTw4Ih0m1NdE2UkXPRFMmuyRZqnDNE8ZNUbHAnexN2Ji5wJuC0hYknZMWGuhOGoUCfyJw5mEMS/MCmpkSPVxZWibymShWgV9zpKF8TJi4lbXPY5agg7G48bSNXofUhz2LliGtkKbNXLhKzvAk4hsmHCaE4QrJGY5J/UDniPQrPAm7ORDLAs40S5wX2K2pI/I057MOxIS0QiNCOFcSRJbLJZILAmwSbFLFG8kkspIeQxa36HsWGN3DRZHbiB6D4DfyS/glEpom/A0QpDtwOD4H9wy2ZcqG2nkb3PwOTwZDdOTgTLLLGvY9CcnbNEnPIibkvJKnBMCPlEcYEuWJXJehu3LMRI4SknwL+iFCUwNdphDUr2RCo+XQ5ZO1xpJcsWfc7YHcdg7oyNpjd5ViZtxongbm43a6Y3D6HRxOyXku3wNjanA39yZuNyNz2Y04FMrQscE3HZ/AlPAmYInbHHzsd77HniTDw50KxeBvHJnY79WMYf2Jgfex52OYb4O1Ysn3SUzg05F8n7o/RDer9Dn/AEK19ixLUmza36MOJsfsWeZLlE2LQKOyBvpI3SY4ZowyT5P7FiPyb5OUZ+DdjYsZuZ5kTjXydcm7Ow/+ZEs2RcX6FyxXeEfZ0/odPQrMUbdj0TLuhw45Hw7SRYX/AKJ2Y85OPyTufgT4sSNruNk8E2l/einOOy8E3EnAkbu44L8zSlsn8CVv+xNNXFNRIrOxMokUVLuJPgSadhq0JqLj+wabohySRuHZfJA0rMi41gSF+BYwhRGCbzYgiUyFzcULORJRmSYsJoXoi0jTV4I7ErlyKElLJTmSDAlho9TATYOmRiwnxcgrtwizIY00hrIhU4Fr2QHfglEE/gbkcSY9DuMaZ5sh8TsGzUk2yNoTah0G5diYFT9kpIh7HIlwSbJMscyTcV6b6G2JuD8iW98CukUmK/oii2S9dlkkbFqG0dIdgssu7dhqr5PuEuWPYhGbjtzGi1jm5VhrED5aLst0Ss3yNztsbaJ+5K24JmCe7EG4o+8iwxv5JHcb0TOqZ0Jw80bveR3aHno1AtREj6d9jhu2yHF3gtqEWHno3Eyexy1yTpkfcwT+DMmoal8ibnvQs3L34HETMj/YoRkbuWtwj38Cs0z2L8cIS4z2RfKnslxH2I1GSH8os1sXb+RRPQleFfsTszezrRpiyYsTbkWRyx9i6/8ADC5JsT8Vd9RTB0fIuabzFccibb0h/o6QkiL2/I9mjFxCfR2jJDyLFiB6cHyIjZxZonvBLkm9rEG8ieh8O5lk2jNDd7EiFdZEuNNjWE2lahYIjIm2mSWV0+SXwLSRWSn8MV8yfH5EkXZAl+C+1iI3ItJCElOYGk8EK3IkhIskGyEtmV+CU0NojpA52OARvJbPYc9mFzpkTEm0Kfk3oSbjzXInQ4u7Dg+R8y4SbHda3slCG5LQQHNwOlp0TVlYbMfJjsJ7JQ+BwOFPweiSGRoP50TxRUb4ojNHk0YQ7kOwnLthifZN6JsY7NJHbISUjVj8B7MIaKbpEmP/AEc17MFx/INBxudg/kyURyN3J0TmGNuFeRvho5Mnm5NrE3JtEWJuYWrm8wM/Y3ZdE2Pk0yNf2TwZJi2jRp8jvceZRF03Qsz+zexucowiLXg+5wlGBKbiH+z8GVmRynEr4IvefgmWhOW7qjcrdFbGT9F9YHydihP/AASKJ2zUmUaG2pItCsfcdraG7R+CYUowh+sl5PUi9EpLHyLIpeablH5G3JozamdGrP4L2MTc1mK2cXpzTJnB8mifg/sd+i09GhYFngXbF0Jws3MPsf5FxyQfs9k+zDQnl4F2YfNIbwK9pRqwuXH2E4yhXm2D0jo9ChnAkh8C4DavGjo4U3FiU7k2cyxE7JlCagTSabQofsbt/ZhvYgvMHISRiglc3E1KFbLFgTUjchlchXj0OJLDRIn9kS0NqOxPuxKIcGcKCBJ0IvksslcbjJIciBDWSTY5YIXyMvkye7FmCW77ZhDgcRs3a59g8qftRyGHZkknuqbmhdGENqENqSRubUbpIhMmMkiwahmz+hX7I5EnzQTMU9QSRCOscsoEKGl8sil33MRWHCVkcUnJc0NLolf9jkaEDvsyu4JsN0mHcm08D9KRuBO3JCL/AHJfwT0Tl6P0OzNf0McTkd/ZccTY0Nz7Q+ieC0Eyfk2bsZZp/ghck5N9l1Kg+Lmcky4I03Se7kjSi35OpMG4Oj4LLuBD2xehK0pTAtXsLUDmxH2FMYInGS7EJicLafIhWtssanYkou7i2lsaSwxEknl/0RKnQnY5FbIu3YtDM4Jsd7MxGidUdjQjPscRYcZG+ju1EI9CxFJtg7PUmGPBPBPJl0TzzSTiCJ3B1B6Ru4uDZJJYtlfdl6q2OZJ4sNyv+sJ2gmETbk4NQS5jUChuC7SJ1sm/BlZJeH9yeWS5hcE4kVyE+7ELXhCcYvwYE3J0Lg8kwmhQvkXBl95wLLgTQr9De13cZpkoyJWPcbNX0S4Lpn7nXIrdlz9i5tXPwFwQmyLkJRcTSHdbZL5sRQyRYfgc2NV2PqN3guJeDKckKYJSRYN27sY7G2Z+B2n4jE3GJvXDrKJ9jZI2TemjolE3JvYnLExjfggSI4EPyDHYt9iF5J6UdsSRL+5bhfcbTLcjRYzySEiG+RskNvY7lQ3f3GJlWY8+ybkueySfye7juPkl4kdsltnEmrj5J+TgmR3Y+RM3PQ3I2210PI3cd4N2uPFxejCtcVhrRgf5PkdxuWasI1EYM2Q8ejJlzf2JChjxdyxs3omLaJgWHYsdDUGcjtHJDRBlr+xcqSZ7GLO5FrvA9QoIt7LX/AlKNCx7NdU0zQuaLsT7Ot1WaXWKdDwT2JjFyjdzEXFYWDOxM1RQmZyeyZvJjdz9nob4ZN8k2ibEsehO3Bk9EQ4k5gTPRLbmRvRNuGKOPyKN4NWMIl5ZJccTdC5k2SS0T2T9y0Y0Ssk3nAuTFbAmTzJIm2BO8Lkb7saRgYTWrCh2J2yK6JuS2S0sWE3twS9oUPcdEk9mVhStoXIkpViLCa5JPQn4E22SlliFhDG8lgesjj7pfAb6F1miQsDuyOXsbuN9jYsuOwwsyeGN2J+Rsn81Tlkkkkk+M9wN1SJpCVNCUvJn4ErEbELtGCfJLA5Essb2xzcNiV/kdDuySvom5Lc3wIew5KJJG8jT2TwyXzPI88ikm/B0POCYdjZc4LT/AGJ3J6E5uZYuYsIck4G5+CRZyuxS/Z20zsVxv4FMO5lCH9kZ36LG73NUS0O6F3Y9mrHFpY8tGjSn7izix+DWBnx8G8CtjYrbFtOHBE4L2ex3QlypPZrHyRKb46JaXvJExYS/9Mq8DtZvJmLdFsZ74HeE8okwYwTaKqRdiMuxyzRs45ouDZ7MGF34ZdxZE8o3BPiskzk3T2xYaOj7EknvQsdmbGFgljdrMmCRuH2YZPEmhR2J8D/BHY7uxEivc0PLuZXokxLN7+DcaG+iXGkTYVkCd4ICeHsndiTAn7EiZIsDYheznoUMVlJ9hXzBNtDNpcfoiNl88C2Te9hoiV2Gzyze4+CG7RI3aScwaij1HYRXI50OwdwxOOBsmHckkkvMkzWbkjY2fsbuZE4ZN6STclapd0i8MghC+RISFsxC5cTlihO0Cl2OYlJi/FFs3mD3HYOY2TG5JE8jJmw38MbvsdifuSNjdtjduzOxPPYrXgz7J6LHQpcki5mBMfs7HiqxwO7kfBr0PEjs4N3FgkmVhGLCZL2KJvMHLLr5pixghyP7QbUD/JpEWRd2I4uNb0ezoShCiRQvZ+6aErQt4ItiB6I2ouJW9DV4dy5mNrg+EMSskvyKVnKI6UDiMNdmKJv4NMlbNEQfMkzmuNDv0LIsHRyZdNk0nkXqk2po+SSSaI6JE+qZxTS5Pk9ZHdWNXPRN5Jl3PwP0O5LW9HBPQ2cFtFj1Wfk1JJui9wSTobtoTFBLgTtgTtJMOeT5Ni40fBIuQnzlCiC0KxNrCYnCJJ1AvsK+0Jt7kTyNGZLMJDHgZ9BtJcaG74J0T2O7JCRyY+1xsXEu/ZwHcZEkyN2u6IkQmTSeLGxskknw4MGsDeBZM4UFyLkZZBkSEhciJ2JNJEpY+5LY9sCST+yBRMI2p3HIypchtwSob3FjWSW1mBuCXYbnBNybjJ+wsk3fJ3JNz+jOvsbsTLgU6UEjz6PSNTFE4hmDuaWc6M6Nmhc7NYbk+YMZZ83G7ZJh5JeyXN1JK2aX3NitqmoPgRyY4Nn7FKciX3H2YRGLMbvJm6wJcOI5FE8FvZZUSGvyJRlIu7myG1N4LRhtkQpHFrNmrq5E2hyWsp9jSy2hKVS7sfoeD4Gy9rWMKD5NYO6zTo9SPVxZJP0e5oqcnRdHsRskXtmhNmhMT4E+Nlj7CLndMQfJ7Ft8E2LalGoF1YVnRKHcWEXmTNZNn2JQo7pgs/ZyJUWVwT9hNJeyUSWNkvolu6wSwhYmS05OEicCa2hPoTG+Y+40NFrtYbN5HbcdsLQ6UjQmSSVyciRiY9kySMTRuWMYnaCUKn4LGrCJ2dk+Ek8Ek84G58NHAiN6EhdFxCQkhIVngV3cY4EocMl2GOTuySH+xjsMN92GZNuhvgbZMLo3k0xY/sc7NExgteBzGPkeCfubs4g+SZo5bnJMMVpJ5NF4sb5NifEDJT2Jv5G7wWHOzKvbg0YZMv2NXuXm+yycEsRA8XbOZLR2dpGcaE4zTD4Ef9BZO2OSE9idnybzcjnNFkSlXOskWL5jAuTLF8dMi8PJw7W4HMf7JhO8PDNdDVp1omYb5INv9kL2LO2GKzszoyZJNl4PeBY2L8kHowJOTWa3nODR2hUvRHFVeFTPRNJmiP2didhNxkngTLE22SN3ZJImhO5JNoNGzMQSSTyTYmxPwJmmTSeDBCcPQmSv9k7kVibE9ybzAn1KJkmXMFp3RsTd4wZFIkK2RXE5V9EIz9xolYZd3Azwk8EyZRab4LUTRgQgbMngkTckfsmBk5JpPivZJJOyaI15THjjFMCuhIhCU0S+5gX/ACPQlInOiUlaxcsN5HyZ0dx9hhvWyb5E75G28jZNhvuB5NDckwiWlS8l17MSQTY7gb+1Jvk1CZtWN3wWuPGkckzkbtT0NkwxtwOCbdmvYybDeOTDHbFLiXyNex6uPQ+WPnJBA/uTe1p2yzIg4xfQ+SbPgv8AJ7LR2xWsY4ksJuDSix+ejeTpwiZ5cGsXIi6a9CbRhuBd3/sypwycNayTtk3zC7FYnFx3dU1cinyK/wAGWkMtNez9mTQz2qap+j2PJqkQpeDNGInikk01SaJmuDPs21T0I34WO63SG9k9kn7phdTSdjd4JRunwSxLgkT0I9jQuS57Lxm5eKJOS5MK7EgvyG3J2Y6cm7id7HaZKgTXF6ToTG73JGySUT2P0XJGyayzFJ7kmaWJvWRPgkxskkkmnB8VkTMs2KcCEmRYWaJSKzExISLPQxMZtwTfI3YdmLk8DHyf8ydxkdsDxcm2h88momm8kyfBIh6H6yJ60IQjcciNCfduCebCt30dmf7Q6YZFxYNysGuzQvSo4LQ9scaeiHCsaydcmkLNpYs3wauKCJSZMQ1YlyeyFOZF6JlvSZ0dm5N2eRvOZJzF5MJbE53bo3uBq8woYsmh3WLRYm0Cc4numNTyLd4fHJh5hihXasSpvseJSwxu2bmu+D2/9ivl07P2apNH0PViIzT7n4pk9l8nVIv5/o1RPVdj8Mjp/Q6WJJubpLG/gkmk0b0zFU4wSNkSZIIubybN3ohCEr9EWlFzI0WJWMjaRN7EkXbo2gnCHQnlkuREDsShXHpwMTInckndEjZMoz8HdJuTe48dciEZVXB/VGy1MfI2eqSSIQsQe6bN0SOhCsQJ2ohCCXElsaKypm43I3A7LDDd8jycQTwyYJGSTT3Rk3sauZZux/Y3NhGLn6E8k6j5Fik3kUNzD9H6eiZLFvg1iuR00IX5NZMmTUn3L5I4uM0Z2K+aTDPyQuU5/AhxJpQeh3cpfB6wJwYTWJMCtpiZoS6XEfkb5Jgctpj72P5Ft2gZQ5whSt+y5ub+hOHMW4IlXMpj4MLq/I2jomGYXJtR+6funRYcan5NcmNCVLroxk3YybuX2aGa7ph3VPivs90QtzY35aUildV+RXEK5s9ifJI/se7E2PRO3mk3N8CcE2JJ/IhexO3dU5J+xKkuOxgYH/EfkSdD2JOQm1JPJMu5M7pORMkTR+RL5LSTGGNuRO7kkcq6P0WPkfKdE7ZJk9EmbmDrxdz58Pdcm6ZEbkRMM90VyLiUaokITEhG/RgSEidDaWxzsrDkNyXDRkyNtE2J2iTR8EkwawMu/wDFNntmjQ+iL22ZmqHiebC7FxRRsvJhw0dOnYmkTGbi6IuaOURfkSvfAs4E4TVoYuxu2IJkm+Ypn41T9kCyN3u/sNzkl2tgvMjPSpIuhPiwnvInDuibF24JuTedi5+zJGX+jHSfIs3Y3Kwp5E5yhvvI7LoTjDY7+kNtK0KdjeL+i0LjzKVvY+lCE2lGyYUtX70TL5rfFL6OyRk8YLWimvHZulyB01Xogm/gz90tNqbGKInx7PRrs9EGeDtGHemVimBnTpsngklyXJJkUPf6JkbnEE0wE8iZ+KMiYJgkknkkk7om9yRvDJpySNsVxMGyfkyG6TsySJk3JNGiINkxSbkzTJNJlkwZJ6J8F4oV6Kip0EFxgj8Co4WJB4ckz0N2G/uSSTTkWL0eTgiaakm4yeibGjRsyZFeDGDHJinZFskJckwiHMbJcmyfkTi9MiP7F0IiHv4Lm4MWZFjWjC7P2O5gWbkmoPeTRLNTsuLrIzGMEk8fYT+wr/Bbc9QOJ+DOB/FiTd4PaIfshw3aeDUu7J/2S3ZfArmBw4Js1Ep86PYriZtDMyeBySt8k8fklTCtwTansufgTPzTOqu6p+K/Bqmia/hCPmu7CpPI+qa4poS48Pfn0elTAidk3uTXjwXNW/sbE+WYJN8+i5NhPg/JPRqxJN4J2TSSdIkk+aM7kbJtom6GzZ7N9Hokmwuq5wNqBXJkyLoTpixNJJt4T4Knus3qvYkIxTAkLgVukKci9k2JHdYb7G75E74sXbE49jfzSTQySWO9yeidGsHxT9i4pMH9mzJ8DmndNZPgm3IpduS+xsiwvd6XbzScMnLd+qISZpZp1yR16PRnLJnVxu3ZJJa2GZZO8Ce5Gx/dsl/J8XNonLnBPLZOodFLWLcExhE2mMDcOyJ52N6wS1dHyb/sXDZmzJkl8fA/X5Hq8nUQbLN2xcnrJ7uJw8oTv6E78CcPK9Ex/Q23Dctumy1putnY1XZ6is0nz/6wqYt4ze3h2TbQleicHoxoSsbJO6Yp1TLPQrGq7v4fYVnZ0/HhoTcCz0N/akpxBsngwY8Z5F6pMkmCSbCnCNj9lmMeaPNhmSfuXpaTAmbNnoRg7EeiT0bIpPjry9V3cWaIfZHLEJCFF6bJHohskm6JpMDZJPwaJ1SbkyT9j7nPRJ/R0asSYHwfstCJ9U9mL1ZNuxNobkfoam+2ImfkxENUmTXZ1sk1Y+9LR2X/APRTyctwXvYu7WOcTVG6TbkiRmMEzJr2YyT+BJtTlDawK4nufgbvmZJl4LdlovKN0mCRXsmTr8k6P2Ocyn7MXklw8ZNT+CZuoJtGyNNXJvIoPgLHdIsaqxZFTRimq5p+R0VZOj90xTXhqkizSR2pEkeDMrInT9HvA/sj2yTZsxNPVLYJp81VJoiaapJNH7Jp8mqXiC9NwfImSSdG6Xk/IzjwT/5U/InHgsM0SLNN0nyk+fPSJE6JCX2omItFxsf3Ek9kk3J0mJwTYY2TWST34fBm7JNkwQdSJ9Ddxk0mipaDBcWDs1kdj5JNXcU/Z+z8HRqaOy6NUTI87Rggm4+dk35Pk0N/Is8UV7PBJPJ80d8Ccrs0LgUy1FxO5gm0Cw8fJlSJtdLsUYNEucpdnp3kf3P0PAnbsn/Ru32MYsicxhktbG7bnQ3fFzVc0SvTVH1SPL0aHTBNPfnJ/ZoWabGQI6o/ybpi0eGkZH9hvQ8TFiRM2fs3ST7CT0Ki7p2TbFZJsSNiFXVZMUmmKSc/kRui7puvyYucG6apH3JtRY8ME38N/Q/RumjRB+xWIEj1T8C/A2NYbNEkyTcZlEkjZomCfsZNFiTs7NU3k0bpq9ZsadLRST7GhGiUJmPksbNXLCzixgtODR8DyfJE4sPJsa9Psa7wf9BrJP3NkapJsx7J7pi5HCJwdk3s7U93MGiYQnwxNSS1kgdi6yTaNGF2K5kV+iT9ilaHlOTsle/Z7zwW2LpR/mq68FSDRP0Oq68P0qz5Kuh3VqN8eEjNeDHIqT8H7EaM7NUyaJ6HmkxVYmjOJxX7k+E0zWSRVmkkknSJvReLY3NZNFzFN+Uk+Gqd+Hs2JCJOzJMDd9kwNmTokm1Ezg9UmCZrqixensk+9EzsXJ7MUtA+iaOl6YLTS3JNhO91S0GMn6FiisImw8GByJzdnNJ4UD/JeIPXg4hRS8TS3fwfo7PZg9iEr1xdn/WFMEXbEmtmppPEEOJJtNz7+i8ehJvArJ3E7WRnI9Ueb3G3Hqk2JpoQuqNxYVfk/XhNvL4M12apqnohx4rJjFJqjVPdN168PQz5FTNMIkeT3WZEZdNVdMqqzZ0yx8GPJ0x4pyqvJgismBumiSR67puqpk+SJEx+58V4IxTdzGyRsbJnNXa0nsVPR0XSHmiME0WSSeRvRqjZ6J4EN/ckWH4fkyrUveaN0UmWYO3enAybk0TYk0Mmxokw4eTrBuB4vRZJMMX4NOsnqn/QdOnbMYE+qRA6O0eho1k/I1GdHcKBOVEG4bMZMyemM1CNfI4awkKR4TiIJsfo15x9qRRGX44pIjfl3TAvDVMfXy6LAsyTzcz5fnxyI9MlxmvYh3d67kwbo7HIvB+WjR7p6J8OiG3YfVVRUYj3RuRvyinQqoVkaJfhI2SZJJRNJo6sdZGW4syT91QvQvz4daLbOtGDmiNZGzAqSbrh3uhmPmufJcnZBI5iNDyRyIm2TZsUST9jvk1SfRL+SbZosGyWeyLGGNQxbYmOUJf+l3hDx0ZPk5sfBdKLej+hvsZY5JnOODVl99iab4E9GbeE107mq4sOsX8F9xV9W8d0+KLygdGvggZ6os0iqvi1E/HVMsWaq1XbRsVEdN0R7GzdPdN0906EbFKrgnsVNUVx+eR+Lv4Yp0ZoqbLTT5ohU/VN0fon5JvTQ2J0mCcGxZvXFc4PRJKpgwTYivZzTZu6nw6EejUDo3quOzRobxVk0xczZujfBnRLXR7ZzB8XN05MiZNxn6r7P3TDPk2YOJwfHoxkmEjUu5gyzgeci90+K3g6JTX7JxA7n4R7Yr6H8JC+WS1bBLtoi1Pmk+FtGx3fk/Ga5psRsYhV3XikbrCZEjqmW8N+W6KVTLovue/C/wBjOjJf7U1AiTFJ8ZojXgx5J6pkkn6GqT4ofXmqezKFRCPRlYIpInYbHW0U/RPhlSyfQ4oj5OvDRJ+aqlopfmjp68H1SLUvM00Xg17NCpuWfo4Fk9UZs9G6JGzZh2H0Y3TNH/6M9Ekir8GVIuJJTs5Q380TRq5K+aH/ANBOTUU4M3mxOpsydUTiXt6JLx3sWbjduEXy4g7khQuzHfhm5eljDN0ebmRWN+LHZ+N2XXm9W+h6NfUzT06ZMYp8UYxO1PkeT2Jxik90km1Lx4YE6MzTGvC3Jkk2Zp8+OFRcea8N+UkiUipIsi8E+ySTRNHcb5JJHVkjZmnwJkjHgm0E/Y4Z7ySa877P+g0STT8VZP4E6+zodEqO92PcmieDLLezNLs7m5l4PimrEcU+KdHzfwm1Pk2YeZMklzKNDuh4VrmiT5H9qPhY0cGTUSa2O7sT3fg1ifk7E+aR7MZNYNE2NGq+vqYdN+GK4NU+DVNXpanqi+huuDvx0XOCbGDFGY8NyI9V4rHdFY2TT9F8F0xZx4e6fIh5+l8+KrNdk+SpMDz7oqLJ7o3Sb+M0nw/XnJNiT4pokwZp3TdcY8M+Tov0fApfAyD9UWfCI2ciI+DQjNGK8xSYYzdHcbFWLHvAnvJO0YyN9UUQJ9xRQWpmmHyWj91/QrzInSNCcK5j2aOzTf8AdPm1GrEzT4ovqaz9FIVM02T568FTH1po/DdJMC8Ms+56o6XkyIXVEaJqnerNeM0zg5H59eE0z4LwfqqPijJJpMk+KPzSST2OvdOi+6N8mq4JoqfqjNmEPPlNUuRZ6JvROmjFjRod6Tem5FuUIt7MMk3ii9weiWkTc9D1X1TFdE2LmnXNP7pqiLqu6exMRNoMZxwN9FpYo4cjnJFsmT3XY/DPkvrSOjs/oInNJ6p68fXlvw3z9NfgXJo/Blct7788m6ZZunzSxu/hjPmzWfBOiya8Nk8VYhVWaapJP0lmq6q3JoXjgnr6Cxrwb7purr/Zfx0/2Yp809k0Xmyx1JunySZPVM13YVExKkdDzTFNGssWD5saNU2ez5uIkTh8kQhUwzeTM2EOw+RfzJ+/hv6Tqz1T4+n7MFqMVN0VHki5l9UY6SfisX8JJJwSJ0Zui8WoPVf15QL6/wCqqzsTanuk1nzVZ8VZU0S1TZ+vH3SZpBfw4q812Tvx7GfoXjgRodXWXySZzVYGMX4FBfYxdmqeyacC7o/uTzkn5N8U/ZfVN8jNmzYvUi7J3s12bHZ38kQs5MGPD5839Xf0MUZ39CMF0xuX4ZIIsekIVJtk1Tvz0SN8Vgjo/wCgVnPh0T5aGaO1TBMnoXgkR44JvVU2YZnwVH+KTWb0nyknydFRVmuCxqskjfJPmzinZPdWSqO7nw2OnzR8jJM09MWCTdiT2TT2T3SaOM5EI+aOmfinGDVJ+9WxMyTDdJvROmiwovwM2axboV2L7nQvO3gzV/N/SVNfRQvB9G/oqtydDPR8UQ64o83ovDUF6ZpJaaMz5quqYpP0fY/DDNfSkbJvTdO6a8N+G/D0aoqKmj9UybpNf1SfOa838PuxMiwrbE4Nj7FT5pqnYzRgTubPwcr70+CYPdMmprMGhUwaiucUU4MGySa7r/0Vninc0m39E9U/Q6ut4ubEYf0Z19OfoLz3RMceCzRCr+KKkU2PxxV+ej0On4rofA6ap6EfFJsNkmDVyT1T14/NdXdYI+lNd035e66+hrw3Sfoe66+p3TZk9GvD9EXt4ZrqizS9NEDrYikVSvz4T2fqjFM3HfzsT4etizBoyMnurJJMfVx4Maq/4HNdUnwfgqY8MEnsg3STFiIHSa9/Q6NC4MUzSDZd5pqmyBYFcis/b6GPBZp+Bd09URFJqxeG/wCFumyaa8vdMRHhojxm9ib0yvo6MebH+qoWINU7NYMxBk9mNCpyQM91k7Pimhd10P8AJ7pg9k+EwIn4NUXg2MRqK5N+Po0RH0F9F0dNfSxWL58Nm/oZGMeb0RaP7pySP3J0dmuxfYdEfFd8G8T4apqjLwMdNV19H4qi6NE09/RtRE139aPLRcz5/JbdJJFSSeB115Lw2RX9V1TNqLk5gRJ8nVOzAj1R2wPA3JNN2NQaMYp8miRHBs9mfBE2Fmx0ySeLGxq52KnBvwRs9/Rdx0dX4aF4rzyLwzXXhFM+G6Kmz0dCik+CP1VGzTZqiU0fY6rvy1SKqxO0YMDM0Y8eG/oN38+/HRqRDPX0/wA0x9TfjmjpFdVZrxXmzo7roRrx3XBlE1kxSPdPY6WptEXopFfBkVU6I2YG50fsSlMRNXjw0bNU7M5wLMYPdfmrH4zR/wDwoJpNFVFqMczVezcnEHddeCufHgvdIvTRqi8f3WRk0/quqRB/ZxXVLov9Fuj6or/TXhqq80ex0VH57sZpqjrv6Tp3VfUdMmu/BHR6NZOvoZPQ/F8no0KrL09n6ozCNUXNe6ap+TNM/Q2R4xeafBFNeef4Oq/AlDuvHvydel458E/HPh68lk68VfXn+6L6s114MXnv6Xx5Lw7pnxmwh+MfQ7q8H9CtRY+mmfhVZNXSabJiw/dPRNquuPHZyPAzVqdHsk3amr2pmxkwhU58Yt578IPQq5Zn6K+lBrx+fDR+/oIVpFcmxjxy6bHSbUWSbGDdYrDinqmPBjrBunx4QaF9F0VV/D68H5PynxxX1TRNHmjibV1XYjnynwm3hr6iuLNd2rqrzTJ7MLFHnPhJkin7oiTTpImM9muj8v8Ahvw+PN0jz/QvHowaovDdN28ciuT3XMnyarApp7rn2Kq8FbwvRVR8k1zqi83XXh8+Hob+jrH1PVJrsfh7+nNXR068Gb+j78cE+Wc0b5+ihUns/XgqukV91v6OidTIruKz9jdLe+6dN1R+vpocR4LBFPg34b+gvoZLfRVZ8M+Kx9DR3XsVd0/FVT81ZsmuvJXMix6EZH+D1TdjfhJmkU2L6qIrv+T7Nj8lTcV14bFXVP3SaRRVmmjFI+m8moHWSSb01IvFGpItTeqaGXToqus/avdN1146pA/B0n6s+Tpvxz9Tvyj4pumpq6Po/Y+fCfH1TB6rqPLJHj9xZPfhJuur1VJJt9HX8NfRz9NfQ14I7+in0LzxVG/KTGayYJJ+/jjwRofhcx6N0913Rd0wReq14zXXi5E/papNI7+hrzXkj065fhixB81zRm6PFdGPDRJisdkfT9eWjIsjH4T8idH1fyVVS1I1XK/nX+q/o4o6+qvw1VjIFVD8/iuqz58U0clzJJj1TYppg9fwZFTX0I+j6pI66F5aNeGqfBvz2fumz48F14M6I0Px9UdNd0k9eGaYNi6r6pumCTY8014T4a8tk+EnR0a+i/5K8p+g66ox+Pz4qkV15evo7rrz+RCI5MMm1NHz45Qh1gjxjz0aOiPDo15K5v6Wq+/LJb6778l15Lyg/B+foZGe6amDXVf1RIx4b8f2LJ8eTpv6bF9XfhvxX1vX8HX0F34qjpkRJrz+fDPhjzxXXjNYtY9keEwY8JpqiEKua2Pk7+o/o+/P34x4Sd+OqMv9J0903amzA/LdMirujrvxY/5Df8FfwF5LywI7r9/Hums0Rvy68ffluuD15aH+axH0HXRuw8fQ39KBVukY/gexcUsP19B0+RYorumTs2IdcP6TpgdIrl1Sv5apgXIrPxgnx5dFzV3rqnrxt4deO/JGv5eaM34b8d1Qn534qhiJpNNeGvC9dVd66M0911Rj9nzVV+PLVOqQTR+M+G6LwQyaT56JrqkE17pPlvy1NcumKZ/hYpIvBd014+js6+rquzP0fVX/AAPf1l9fddeWj4It9Z1j6yGIdNW8Yv4bovB1Xj145rqnPkvF+GDG/p6jwvJrx90+K+x0dGfJ6Nmaa8NmfDFHX7m7+Wq/B+PHVevoPH0fdM12aJ/jbPX0pF4z/HdLc+XsRNfXjry3TdN+K68PRJ8U2b8NUf0PdGzVcV1XVNeOKa8tFvofNI8onw/ZoSmvvw9ioqbMeEEU14arFvoyZt48V1Sau58fRX8Cf4c//JkyT44or+e6Pw35rzVNeM+eRkXp+iaaMUVX4apjy2Y8JF9D5F4b8F+BKfHBoxTB6t9KPDRx5agX0EInznmnum66MUmmyafHjNx+Dq/4L8p+hP8AB19FfTvvzeRmBeM/SXn6+m+y/h+PGKKmjP1Xn6uvDfnJkZo3TRE4FWKRHhBFO6Xph3Eco14ZqzXhAya/NMkeCpJv6XHlqmKL6O6T/M39PNd035bpvwXijFUZt4/P0Vnwya+nN6brqmab6N0ZozT4po1SPrRVUXhiuvo4N3J8rRO+BEM1fz/fjNOzHY/FHqm6bNU/fnbzj6Xrz15s9/Q1/wDLQ+vpOmvNnddUmk2o/oPNUOqNmvo+/LdF+fBeGfKbkD8PdO/P4OibeX58Ireb1ZJE+Lx3TZmtjVNDMus/WzTHh8j+i/HfnDMeWTqvrzX8PX8peGvLX8K3hrxXh78d+OPCxk2e8+E/QdhYNUdVR4I7qjY/LowKmyS309eaH4aJ15WzTFUfNMqvwPwdGevoP6XdMeG/FD8F5a8X/wDLiu/psVcfQ39Pv6L83XdeJpqmMX8PXgxrxzX19BYOvoIuars+adGfNCx5/B+a7JNeOjVyYruiyaEK+yLnzTAiOabivRqNeMi+51unP0ZozY/LXnozRUx/8PP1/jw15Z/jT47r6pqvXg/D5pozRunXi8Hsk3TXjrzRbdHj6EXOj2bIv4Z8Zg9fXbEYsW3To68NG/HVVkybLmvDcCN0ikWN07pPgvLYlIqP+Hlio3x5a+s6ryfh78V4qu/p7+pn6eKKmfJd+H6pqvrxtTFNGBPnw14tfbyv9L1XZumfG38boVGhUWB134td+DO6r2R5zFdC8fmmv4Xvy9Vg15a8c+T/AIC/i68d19U9eD+ivpa8ZJFT9V9C5pN6LJ+PCLTPwSbH7NEj8NdUx56puipimqbqsnsyL6Xx4rPlmndY+wxm703esyTvyk1WabNj8deP4OiKa8X46rb4pjy119P39PHivpP6mfFeOvrb8dUf01z5+/qY8deC+jFfRoY8/Rmq+hirf0dUeb5OTKNGqa+jYnsxXPjFIrsX1uKzDPj6OPoP+YqL6U/wX9B/xWP6ePrao/D9Hqu7D8ea7rePDVYVH4N6o/o+658mZJt4Zpx4fqjp8iuzNjdG09QIzRzgYsTTBFMfw+voY8Yr8fTm3gqL6jyLzx5rwX8fdM/R9/RX8F/Q+PobNY+jrxR81dOKbpNM119RG/Jdnrx3468YsdnofVJOprv6Ejck19+Dx4bp1Xfhnw1TVF5SejY+vDH0NfT19F//AEp8Pmjpg3NN/S14ryWaaP1XP0F9JunFc2Er4PRg5NGvDDrI6aqvDVGYMYf1N+Uno0TTN4p7p6o6p1mPVJo/BZr7pqDVH68Z8Mqiro3T1/DXmjf1d/x8fyteS+rY19PVdV919iq/LJoRNqN+X6o8EeHVUZpFvKRnZv35LN6P7+HNEexYMvgeaXN2J0JGTW6vwvVUTtg95HPgriPdGY8cG6bF+KfHlnxZr6cUkX0Neev5mv4uvN+e/r7qvo7EZprs0cRRVk34R5eqfNME0RF6vxVff0UR4L7GaYyjZ68MLFd0903SVtCr7H3WKen4y4uSbo66r81Xvxz4Oucma6pPj819V34oXnr/AO+81nzn+V3Xr6qN1x5amSaT5Lwx4Pw/vxXgncdh0ZHlg1kRN6e/LLpojdcmPF2JijqqbPfm6fodd014TXfhj6kfyrfWf8Pfnf8AiNV3Tfhr6M114xTXhNNCNmK+qapjAkZ1TI/VLSQIi9MCoz91ddVvTs1ci0kDpb2K3Y7HwbplmoVNE0m58Hvz1cTgjjwVF3XRc9n4Pk1T5vTVfiuqZ/i9f/ax9LX13R/R39B+e/pLw14Rbw/Zu/4q+DqmjU6FT2aLfQfj7F4Zp+qyfFmb6pjy3XdHn6FvDp0ddGhVzSOvDdx48d+Nxfyff8DX/wBV/Xx9LHlj+BrwfVO6PQ6bpBrs0RX9+Kp+jRej8uTVPXhhQRTItnY3TYhGrEXfNFsRceh4MUXhPj/VezBJogyJcmppJu1d+OvGdfVjw9/Wj+BHhj+S/pb+tjy39JeKrJ78tfVZczeKI34Lqnwd06Nmx1QsUnzXl6o6TXFx1dI/AqW8Mefumqzc90inuqu6z0I1XfnlEOvNXVG/Hf8AInyn68fwn9V/w/f8Tfk6L6SOz3T+junrNMSqeqezVcPyY+jBsy+Kq/g66MfIj0Qc0Vc+W6aro7ozdqZrmk0dYoqsRMG6armkmTLIL+O/o5o//ix/BkmuP/j7/iY8EMn6HwevBYc0sci9muq91bNa/hfo/Xnnz/dMUkueqckX0bsa8GvL58GfNdeSp1TdZPdWa8YN+ev/AKzrb6s/R19ePpb+m/q4pJql6PBowYp9/Ld/CRUnxVIijzTPg80m1NVRGHyRNPg7O67pfOzUm/Bzav8Azo/LdYro1TuvrxYzqi8FT1VmvLX1N/Wfgv4eP5W/4evLPkvoT9F+eKv8nuiG6Oxsm0QW3T1SfC3J1Wb03XRkYzJumGLoY+6Ik17NZFT/AKDBjwmxik9CJxI5WUYYvuO5ika8maMiMGB0kR803RUXi3TVXV+S8dfyX9HX1sfyUa+jPjn+YvLFF5aNwPFd2p7NUf3rNPRs7MmKYpumL0m9c9edzQqPRuuMPw6p8jgdIsLhDHc3zSPtT0R3TVJvJs3478dYN11ReOhC+l8+KF/CYvFYNfwpj/5k/wAjX8OZIHTZsQsMityZ8MMziuhDJpqi5ojfn3XVXiTFE8QQZ6JPk6Ir+jVjGj9VnquZrrtU9wIT0Ponx5VefF2xTrwQhU3RZ88/w1TYvrx9DFYNee//AI2vpL6j8t/QXirEjx4dk7NEm6+qvrw1RmfDZJiuKdU2TzX5NFyaPg14dHZs68Lirq1M00Sdb8XXrwZrw6PY29mDZPh2J+OaL6S+pj+Avp5q/rP/AOEv4X78JF9PXlofj+qT5RDFwTejsOuM+Kpu+TCI4MeGFFdk+C8d14zS8Qdsfo9HZhmBkEXvTR7Pmt0Rum7k2MU/dJtY78MGxkdj8Pdfj6seWvpaii+nqfqfNd+Uf/A14Lz0Pxf8GaYpNHRGzfnJPh7pFVujzc/NIzTNUM1SCK6oyBefs3VH6II8N0/VF+qTVq/IqYp+K+qvhCzYfhsX4o6Z8H4q48mqq3n68d1x9PVVX15z9TfkvDdV9L58NU/f8P8AVF4ye/JeS+lo9ixR/SRiw6boqKluaO1UPHjBHh7oxKT3X4NeOjVdEmKNkUi1qYMIWCYsbERPAvR/kdvkwxCzhVXZamKT68beNvdMVzSbGa4q/DAq6r3TX0tfQX8afoR/8teOvp7o81n+OuPDZqk0/QnrzdNHr6CvR4NU1THhemqozScIwskSzfKpEexYIsZrunZgwyKYVzNxHJemvDM+GqzJH38v1TAs+O/Hf0F9XVPVV9b58dVRqP4O/rZ/hb/kapn6T/Ax6N+ex9/T9E58NCzbxj0aovDBP4pqrV4hURNLU/VFgfg79V6V/FmdU2fo9l/HVW/NeXs2a8u67pjw/XiqT4a//DT5b/i6/iKsWOjUU/NO6boq5M+HsdjXnsyz4r+idUybHJIt0wbpPhem+qItOzAsj5JZ2TVXE49d13wTcuLORXY+NFzuk+DHSabNM9eOjVHXHhv/AOhj+b3/AC9/xtGPDX0NGvDZvwz4O56I8r7ND+h8V2bGbFufwbNkXFstVZo6MX4EpN4NiJNX3gw7+GWT3SehGrkGF2K0lznxVHX1VciP7N+T+oqzX19Dfnrx9jpjx3/FdPX0df8AwN11/E3er8teH6qzfh8+CPfh8mSDUaNCzKP2e6rDM0n7GO6PmuqzRZqxxY2bjYqPVqbwLMp00ZHyOk6MFy8UwvHZNHT9GqvHj3TWRFnyQqfqiqyPq6qxfTdNfRXk/N/Sf134e/4+vp7ph/ydC81XmujVIpsdU+aYZh0tv7lz5N114apNPZotNbnoVdH/ADo8CpNNH48c0xh0ZObC8MCo+zI+DBsVnR/esrRoVV7+gv8A4UeGvp+/r+6evLHlo1/Lz/E2T9HHh8lqer/Qz4Z8fVFiiyONYMix7o728MU6JP14ZNUfgjZin6p+i8V9jNGiTFFxRjFj1XunZnz2bE7n3F4aNUjuaZVI+g69+HX8aK4NfQVd/WfnqmvGfoX/AIT+vuu/4nXhiua80eaZrr35RTddmzdj906NeCmTHZcWBDP2O8HS8Vmu63U0ec/RZ+jrxR0KmjseTD8N2R8iNSX8o+i/ra+trw14uuF4+vJ+OqR9LFd/yV9R/Uf0V5OuxdkUVOz2b8ezVV1ReOjA678cHulh1g7Nnqmq902TNNHvPlkR+jPjsjqu6P8AJq5gtFLR4RePHJryf8aKryfnI6uiEars35PP0dV1/A35vyXlb/4Hfhs12KujoWaI91WT4sXFdRV0/B+Kb+ho/ROaPx0Y7JP2QLsSyZp0L1TunQvuKnQ/0ONeCMiYlNNOckW8Vk3fJFXhE0+KfPixMa8OvB115Or7N/Sf09+D8d/Q3/CQvOab8dfU0L+Ruq8seM01428NeOz1RjI2ia+709eUximqQaEPozVUmRmaR2LF0dnqkcEHxX2Xg9Z/VNRqiIt45q8U3TR+BF5v9BmaL6L/AIUX8Efv6e/obqqq3m//AJ2frx9PH0oP/9k=');
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body {
            height: 100%;
            width: 100%;
            overflow: hidden;
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            display: flex;
            -webkit-font-smoothing: antialiased;
        }

        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.18); border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.28); }

        /* --- SIDEBAR --- */
        .sidebar {
            width: var(--sidebar-width);
            height: 100%;
            background: var(--bg-sidebar);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
            border-right: 1px solid var(--border);
            transition: margin-left 0.2s cubic-bezier(0.16, 1, 0.3, 1);
            z-index: 40;
        }
        .sidebar.collapsed {
            margin-left: calc(-1 * var(--sidebar-width));
        }
        .sidebar-header {
            padding: 14px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .sidebar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 600;
            font-size: 15px;
            color: var(--text-main);
            text-decoration: none;
        }
        .brand-icon-circle {
            width: 24px;
            height: 24px;
            border-radius: 6px;
            background: var(--text-main);
            color: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 12px;
        }
        .icon-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 6px;
            border-radius: 6px;
            transition: all 0.15s;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .icon-btn:hover {
            color: var(--text-main);
            background: var(--bg-hover);
        }

        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 0 10px 16px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .new-chat-btn {
            background: transparent;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 9px 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            font-size: 13.5px;
            font-weight: 500;
            color: var(--text-main);
            transition: background 0.15s;
        }
        .new-chat-btn:hover { background: var(--bg-hover); }

        .sidebar-search-box {
            position: relative;
            display: flex;
            align-items: center;
        }
        .sidebar-search-icon {
            position: absolute;
            left: 10px;
            color: var(--text-muted);
        }
        .sidebar-search-input {
            width: 100%;
            background: #212121;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 7px 10px 7px 30px;
            color: var(--text-main);
            font-size: 13px;
            outline: none;
        }
        .sidebar-search-input:focus { border-color: var(--text-muted); }

        .sidebar-section-title {
            font-size: 11.5px;
            font-weight: 600;
            color: var(--text-faint);
            padding: 8px 6px 2px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .chat-history-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 10px;
            border-radius: 8px;
            font-size: 13.5px;
            color: var(--text-main);
            cursor: pointer;
            transition: background 0.15s;
        }
        .chat-history-item:hover { background: var(--bg-hover); }
        .chat-history-item.active { background: var(--bg-active); }
        .chat-title-text {
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            flex: 1;
        }
        .chat-item-actions {
            display: none;
            align-items: center;
            gap: 4px;
            margin-left: 6px;
        }
        .chat-history-item:hover .chat-item-actions {
            display: flex;
        }
        .chat-action-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            cursor: pointer;
            padding: 3px;
            border-radius: 4px;
            font-size: 12px;
        }
        .chat-action-btn:hover { color: var(--text-main); background: #333; }

        .sidebar-footer {
            padding: 10px;
            border-top: 1px solid var(--border);
            position: relative;
        }
        .user-pill {
            display: flex;
            align-items: center;
            gap: 10px;
            cursor: pointer;
            padding: 6px 8px;
            border-radius: 8px;
            transition: background 0.15s;
        }
        .user-pill:hover { background: var(--bg-hover); }
        .user-avatar-badge {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: var(--text-main);
            color: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 700;
        }
        .user-name { font-size: 13.5px; font-weight: 500; }

        .user-menu-popover {
            position: absolute;
            bottom: 55px;
            left: 10px;
            width: 210px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 4px;
            display: none;
            flex-direction: column;
            box-shadow: 0 10px 30px rgba(0,0,0,0.6);
            z-index: 60;
        }
        .user-menu-popover.open { display: flex; }
        .user-menu-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 10px;
            border-radius: 6px;
            color: var(--text-main);
            text-decoration: none;
            font-size: 13.5px;
            cursor: pointer;
        }
        .user-menu-item:hover { background: var(--bg-active); }

        /* --- MAIN CHAT CONTAINER --- */
        .main-chat-container {
            flex: 1;
            height: 100%;
            display: flex;
            flex-direction: column;
            position: relative;
            overflow: hidden;
        }

        /* --- TOP NAVBAR --- */
        .top-navbar {
            padding: 10px 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-shrink: 0;
            border-bottom: 1px solid transparent;
            z-index: 20;
        }
        .model-header-wrap {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            padding: 6px 12px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 15px;
            color: var(--text-main);
            transition: background 0.15s;
            user-select: none;
        }
        .model-header-wrap:hover { background: var(--bg-card); }
        .top-right-tools {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* --- CHAT SCROLL AREA --- */
        .chat-scroll-area {
            flex: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 0 16px 140px;
            position: relative;
        }
        .chat-content-width {
            max-width: 768px;
            width: 100%;
            display: flex;
            flex-direction: column;
            flex: 1;
        }

        /* --- HERO EMPTY STATE --- */
        .hero-empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 60vh;
            width: 100%;
            margin: auto 0;
        }
        .hero-title {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 24px;
            color: var(--text-main);
            text-align: center;
            letter-spacing: -0.5px;
        }
        .hero-input-box {
            width: 100%;
            max-width: 768px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 8px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
            transition: border-color 0.15s, background 0.15s;
        }
        .hero-input-box:focus-within {
            border-color: #555555;
            background: #353535;
        }
        .hero-textarea {
            width: 100%;
            background: transparent;
            border: none;
            outline: none;
            color: var(--text-main);
            font-size: 15px;
            font-family: inherit;
            resize: none;
            line-height: 1.5;
            max-height: 200px;
        }
        .hero-textarea::placeholder { color: var(--text-muted); }
        .hero-tools-row {
            display: flex;
            justify-content: flex-end;
            align-items: center;
        }
        .send-pill-btn {
            background: var(--text-main);
            color: var(--bg-base);
            border: none;
            border-radius: 50%;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: transform 0.15s, opacity 0.15s;
        }
        .send-pill-btn:hover { transform: scale(1.05); }

        /* SUGGESTIONS GRID */
        .suggestions-wrap {
            margin-top: 28px;
            width: 100%;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 10px;
        }
        .suggest-card {
            background: transparent;
            border: 1px solid var(--border);
            padding: 12px 14px;
            border-radius: 12px;
            cursor: pointer;
            transition: background 0.15s, border-color 0.15s;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .suggest-card:hover {
            background: var(--bg-card);
            border-color: #555;
        }
        .suggest-title { font-size: 13.5px; font-weight: 500; color: var(--text-main); }
        .suggest-desc { font-size: 12px; color: var(--text-muted); }

        /* --- MESSAGES CONTAINER --- */
        .messages-container {
            display: flex;
            flex-direction: column;
            gap: 24px;
            width: 100%;
            padding-top: 20px;
        }
        .message-wrapper {
            display: flex;
            flex-direction: column;
            width: 100%;
        }
        .message-wrapper.user {
            align-items: flex-end;
        }
        .user-bubble {
            background: var(--bg-card);
            padding: 10px 16px;
            border-radius: 18px;
            max-width: 80%;
            font-size: 14.5px;
            line-height: 1.6;
            color: var(--text-main);
            white-space: pre-wrap;
            word-break: break-word;
        }

        .assistant-row {
            display: flex;
            gap: 14px;
            width: 100%;
        }
        .assistant-avatar {
            width: 28px;
            height: 28px;
            border-radius: 50%;
            background: var(--text-main);
            color: var(--bg-base);
            font-size: 13px;
            font-weight: 700;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            margin-top: 2px;
        }
        .assistant-content-col {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 8px;
            min-width: 0;
        }
        .assistant-meta {
            font-size: 13px;
            font-weight: 600;
            color: var(--text-main);
        }
        .assistant-body {
            font-size: 14.5px;
            line-height: 1.6;
            color: var(--text-main);
            word-break: break-word;
        }
        .assistant-body p { margin-bottom: 14px; }
        .assistant-body p:last-child { margin-bottom: 0; }
        .assistant-body pre {
            background: #0d0d0d;
            border: 1px solid var(--border);
            border-radius: 8px;
            margin: 14px 0;
            overflow: hidden;
        }
        .code-header-bar {
            background: #1a1a1a;
            padding: 6px 14px;
            font-size: 12px;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #282828;
        }
        .code-copy-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            font-size: 11.5px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 4px;
            font-family: inherit;
        }
        .code-copy-btn:hover { color: var(--text-main); }
        .assistant-body code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }
        .assistant-body pre code {
            display: block;
            padding: 14px;
            overflow-x: auto;
        }

        .thought-accordion {
            background: rgba(255, 255, 255, 0.03);
            border-left: 2px solid #555;
            border-radius: 0 8px 8px 0;
            margin-bottom: 14px;
            overflow: hidden;
        }
        .thought-accordion summary {
            padding: 6px 10px;
            font-size: 12.5px;
            color: var(--text-muted);
            cursor: pointer;
            font-weight: 500;
            user-select: none;
        }
        .thought-accordion summary:hover { color: var(--text-main); }
        .thought-body {
            padding: 8px 12px 10px;
            font-size: 13.5px;
            color: var(--text-muted);
            line-height: 1.5;
            white-space: pre-wrap;
            font-style: italic;
        }

        /* --- DOCKED BOTTOM COMPOSER --- */
        .docked-composer-wrap {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            padding: 10px 16px 20px;
            background: linear-gradient(180deg, transparent 0%, rgba(33, 33, 33, 0.95) 30%, var(--bg-base) 100%);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 6px;
            z-index: 30;
        }
        .stop-pill {
            display: none;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            border-radius: 20px;
            font-size: 12.5px;
            font-weight: 500;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        .stop-pill:hover { background: var(--bg-active); }
        .stop-pill.visible { display: flex; }
        .stop-dot { width: 8px; height: 8px; background: #ef4444; border-radius: 2px; }

        /* --- MODEL SELECTION MODAL --- */
        .modal-backdrop {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(2px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            padding: 16px;
        }
        .modal-backdrop.open { display: flex; }
        .modal-card {
            width: 100%;
            max-width: 520px;
            background: #212121;
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.6);
            max-height: 75vh;
        }
        .modal-search-input {
            width: 100%;
            background: #171717;
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13.5px;
            font-family: inherit;
            outline: none;
        }
        .modal-search-input:focus { border-color: var(--text-muted); }
        .modal-models-list {
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 3px;
            max-height: 380px;
        }
        .model-row-item {
            padding: 9px 12px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background 0.12s;
        }
        .model-row-item:hover { background: var(--bg-hover); }
        .model-row-item.active { background: var(--bg-active); }
        .model-row-name { font-weight: 500; font-size: 13.5px; color: var(--text-main); }
        .model-row-provider { font-size: 12px; color: var(--text-muted); }

        @media (max-width: 768px) {
            .sidebar { position: fixed; height: 100%; }
            .sidebar.collapsed { margin-left: -260px; }
        }
    
        /* BRIDGENA-TAILWIND v3.2 */
        .visible{visibility:visible}.collapse{visibility:collapse}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.mx-px{margin-left:1px;margin-right:1px}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.table{display:table}.grid{display:grid}.hidden{display:none}.h-1{height:.25rem}.h-1\.5{height:.375rem}.h-3\.5{height:.875rem}.w-0{width:0}.w-1\.5{width:.375rem}.w-16{width:4rem}.w-3\.5{width:.875rem}.w-px{width:1px}.flex-1{flex:1 1 0%}.flex-shrink{flex-shrink:1}.border-collapse{border-collapse:collapse}.transform{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}@keyframes spin{to{transform:rotate(1turn)}}.animate-spin{animation:spin 1s linear infinite}.cursor-text{cursor:text}.resize{resize:both}.flex-wrap{flex-wrap:wrap}.items-center{align-items:center}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.self-stretch{align-self:stretch}.overflow-hidden{overflow:hidden}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-md{border-radius:.375rem}.border{border-width:1px}.border-amber-400\/25{border-color:rgba(251,191,36,.25)}.border-emerald-400\/25{border-color:rgba(52,211,153,.25)}.border-rose-400\/25{border-color:rgba(251,113,133,.25)}.border-white\/10{border-color:hsla(0,0%,100%,.1)}.bg-amber-400{--tw-bg-opacity:1;background-color:rgb(251 191 36/var(--tw-bg-opacity,1))}.bg-amber-400\/\[\.06\]{background-color:rgba(251,191,36,.06)}.bg-black\/25{background-color:rgba(0,0,0,.25)}.bg-emerald-400{--tw-bg-opacity:1;background-color:rgb(52 211 153/var(--tw-bg-opacity,1))}.bg-emerald-400\/\[\.06\]{background-color:rgba(52,211,153,.06)}.bg-rose-400{--tw-bg-opacity:1;background-color:rgb(251 113 133/var(--tw-bg-opacity,1))}.bg-rose-400\/15{background-color:rgba(251,113,133,.15)}.bg-rose-400\/\[\.05\]{background-color:rgba(251,113,133,.05)}.bg-rose-400\/\[\.06\]{background-color:rgba(251,113,133,.06)}.bg-slate-500{--tw-bg-opacity:1;background-color:rgb(100 116 139/var(--tw-bg-opacity,1))}.bg-white\/\[\.03\]{background-color:hsla(0,0%,100%,.03)}.bg-white\/\[\.06\]{background-color:hsla(0,0%,100%,.06)}.bg-gradient-to-b{background-image:linear-gradient(to bottom,var(--tw-gradient-stops))}.bg-gradient-to-r{background-image:linear-gradient(to right,var(--tw-gradient-stops))}.from-violet-400{--tw-gradient-from:#a78bfa var(--tw-gradient-from-position);--tw-gradient-to:rgba(167,139,250,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-violet-500{--tw-gradient-from:#8b5cf6 var(--tw-gradient-from-position);--tw-gradient-to:rgba(139,92,246,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-violet-300{--tw-gradient-to:#c4b5fd var(--tw-gradient-to-position)}.to-violet-600{--tw-gradient-to:#7c3aed var(--tw-gradient-to-position)}.p-\[3px\]{padding:3px}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2{padding-left:.5rem;padding-right:.5rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-3\.5{padding-left:.875rem;padding-right:.875rem}.px-\[18px\]{padding-left:18px;padding-right:18px}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-\[2px\]{padding-top:2px;padding-bottom:2px}.py-\[3px\]{padding-top:3px;padding-bottom:3px}.pb-1{padding-bottom:.25rem}.pt-1\.5{padding-top:.375rem}.pt-3{padding-top:.75rem}.text-center{text-align:center}.text-\[10\.5px\]{font-size:10.5px}.text-\[11\.5px\]{font-size:11.5px}.text-\[12\.5px\]{font-size:12.5px}.text-\[12px\]{font-size:12px}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.capitalize{text-transform:capitalize}.italic{font-style:italic}.tabular-nums{--tw-numeric-spacing:tabular-nums;font-variant-numeric:var(--tw-ordinal) var(--tw-slashed-zero) var(--tw-numeric-figure) var(--tw-numeric-spacing) var(--tw-numeric-fraction)}.tracking-wide{letter-spacing:.025em}.text-amber-300{--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.text-emerald-300{--tw-text-opacity:1;color:rgb(110 231 183/var(--tw-text-opacity,1))}.text-rose-300{--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.text-rose-300\/90{color:rgba(253,164,175,.9)}.text-slate-100{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.text-slate-200{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-300\/80{color:rgba(203,213,225,.8)}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-violet-50{--tw-text-opacity:1;color:rgb(245 243 255/var(--tw-text-opacity,1))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.opacity-90{opacity:.9}.shadow-\[0_8px_20px_-8px_rgba\(124\2c 58\2c 237\2c \.85\)\]{--tw-shadow:0 8px 20px -8px rgba(124,58,237,.85);--tw-shadow-colored:0 8px 20px -8px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline{outline-style:solid}.blur{--tw-blur:blur(8px)}.blur,.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-filter{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.transition{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,-webkit-backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter,-webkit-backdrop-filter;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-\[width\]{transition-property:width;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.duration-300{transition-duration:.3s}.hover\:border-rose-400\/45:hover{border-color:rgba(251,113,133,.45)}.hover\:border-white\/25:hover{border-color:hsla(0,0%,100%,.25)}.hover\:bg-rose-400\/10:hover{background-color:rgba(251,113,133,.1)}.hover\:bg-white\/\[\.06\]:hover{background-color:hsla(0,0%,100%,.06)}.hover\:bg-white\/\[\.07\]:hover{background-color:hsla(0,0%,100%,.07)}.hover\:text-rose-200:hover{--tw-text-opacity:1;color:rgb(254 205 211/var(--tw-text-opacity,1))}.hover\:text-slate-100:hover{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.hover\:text-slate-200:hover{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.hover\:text-white:hover{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.hover\:brightness-110:hover{--tw-brightness:brightness(1.1);filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.focus\:border-rose-300\/50:focus{border-color:rgba(253,164,175,.5)}.focus\:outline-none:focus{outline:2px solid transparent;outline-offset:2px}.active\:translate-y-px:active{--tw-translate-y:1px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.disabled\:cursor-wait:disabled{cursor:wait}.disabled\:opacity-70:disabled{opacity:.7}@media (min-width:768px){.md\:inline-flex{display:inline-flex}}
        /* BRIDGENA-AMETHYST-THEME v3.2 */
        /* ===== Amethyst layer — OpenWebUI-ish ===== */
        body { font-family: var(--font-ui); background-color:#16121d;
            background-image:
                linear-gradient(180deg, rgba(19,15,26,.72), rgba(19,15,26,.84) 55%, rgba(19,15,26,.9)),
                var(--hero);
            background-size:cover; background-position:center 30%; background-attachment:fixed; }
        .sidebar, .main-chat-container, .top-navbar { position:relative; z-index:1; }
        .sidebar { background:linear-gradient(180deg, rgba(15,12,21,.82), rgba(13,10,19,.9));
            border-right:1px solid #241d33; backdrop-filter:blur(10px); }
        .brand-icon-circle { border-radius:10px !important; background:linear-gradient(150deg,#c4b5fd,#7c3aed) !important;
            color:#171126 !important; font-family:var(--font-display); box-shadow:0 5px 14px -6px rgba(124,58,237,.55); }
        .sidebar-brand b, .chat-title-text, .hero-title, .suggest-title { font-family:var(--font-display); font-weight:500; letter-spacing:-.4px; }
        .sidebar-section-title { font-family:var(--font-ui); font-weight:600; letter-spacing:.09em; text-transform:uppercase;
            font-size:10.5px; color:var(--text-faint); padding:0 10px; }
        .nav-list { gap:2px; }
        .chat-history-item { border-radius:9px; padding:8px 10px; line-height:1.35; }
        .chat-history-item:hover { background:rgba(38,30,62,.7); }
        .chat-history-item.active { background:#241d36; box-shadow:inset 0 0 0 1px #372c55; }
        .new-chat-btn { background:linear-gradient(180deg,#a78bfa,#7c3aed) !important; color:#f7f4ff !important;
            border:0 !important; border-radius:12px !important; font-weight:600; letter-spacing:.02em;
            box-shadow:0 6px 16px -8px rgba(124,58,237,.6); transition:filter .14s; }
        .new-chat-btn:hover { filter:brightness(1.08); }
        .sidebar-search-input, .sidebar-search-box { background:rgba(23,18,33,.8); border:1px solid #2c2347;
            border-radius:10px; color:var(--text-main); }
        .top-navbar { background:rgba(22,18,29,.6); backdrop-filter:blur(12px) saturate(1.1);
            border-bottom:1px solid rgba(44,35,71,.7); }
        .model-header-wrap { background:rgba(36,29,54,.6); border:1px solid #372c55; border-radius:999px; color:var(--text-main);
            transition:background .15s, border-color .15s; }
        .model-header-wrap:hover { background:#2c2346; border-color:#a78bfa; }
        .icon-btn, .chat-action-btn { background:transparent; border:0; border-radius:9px; color:var(--text-muted); }
        .icon-btn:hover, .chat-action-btn:hover { background:#241d36; color:var(--text-main); }
        .main-chat-container { background:rgba(22,18,29,.42); backdrop-filter:blur(2px); }
        .chat-scroll-area { background:transparent; }
        .messages-container, .chat-content-width { max-width:820px; margin-left:auto; margin-right:auto; }
        #messagesList { padding-bottom:26px; }
        .message-wrapper { margin:10px 0; }
        .user-bubble { background:rgba(40,32,62,.85); color:var(--text-main); border:1px solid #3b3060;
            border-radius:18px 18px 5px 18px; padding:12px 16px; line-height:1.6;
            box-shadow:0 2px 10px -4px rgba(0,0,0,.4); }
        .user-avatar-badge { background:#2e2547; color:#c4b5fd; border-radius:8px; }
        .assistant-row { background:transparent !important; border:0 !important; box-shadow:none !important; padding:6px 0; }
        .assistant-avatar { border-radius:9px !important; background:linear-gradient(150deg,#c4b5fd,#7c3aed) !important;
            color:#171126 !important; font-family:var(--font-display); box-shadow:0 4px 10px -4px rgba(124,58,237,.5); }
        .assistant-body { font-size:15.5px; line-height:1.78; color:var(--text-main); letter-spacing:.002em; }
        .assistant-body h1, .assistant-body h2, .assistant-body h3 { font-family:var(--font-display); font-weight:500;
            letter-spacing:-.3px; margin:1.4em 0 .5em; }
        .assistant-body code { background:rgba(48,38,77,.8); border:1px solid #372c55; border-radius:5px; padding:1px 6px; }
        .assistant-body pre { background:rgba(14,10,22,.85) !important; border:1px solid #2a2240; border-radius:12px; padding:14px 16px; }
        .code-copy-btn { background:#241d36; border:1px solid #372c55; border-radius:7px; color:var(--text-muted); }
        .thought-accordion { background:rgba(28,22,40,.8); border:1px solid #2e2548; border-radius:13px; overflow:hidden; }
        .thought-body { background:rgba(24,19,37,.85); border-left:2px solid #7c5cff; border-radius:0; }
        .hero-empty-state { padding-top:7vh; }
        .hero-title { font-weight:400; font-size:clamp(27px,3.4vw,38px); letter-spacing:-.9px; }
        .hero-title::after { content:""; display:block; width:46px; height:2px; margin:16px auto 0;
            background:linear-gradient(90deg,transparent,#a78bfa,transparent); }
        .suggestions-wrap { margin-top:34px; gap:12px; }
        .suggest-card { background:rgba(31,24,46,.72); border:1px solid #302650; border-radius:15px; padding:15px 17px;
            transition:transform .15s ease, border-color .15s, background .15s; }
        .suggest-card:hover { transform:translateY(-2px); border-color:#5b4797; background:#271f3d; }
        .suggest-title { font-family:var(--font-display); }
        .suggest-desc { color:var(--text-muted); line-height:1.5; }
        .hero-input-box { background:rgba(31,24,46,.78); border:1px solid #3b3060; border-radius:22px;
            box-shadow:0 18px 44px -22px rgba(0,0,0,.7); transition:border-color .16s, box-shadow .16s; }
        .hero-input-box:focus-within { border-color:#8f77e0;
            box-shadow:0 0 0 4px rgba(167,139,250,.1), 0 18px 44px -22px rgba(0,0,0,.7); }
        .hero-textarea, #dockedPromptInput { font-size:15px; line-height:1.6; background:transparent; border:0;
            box-shadow:none; outline:none; }
        .hero-textarea:focus, #dockedPromptInput:focus { border:0; box-shadow:none; outline:none; }
        .hero-textarea::placeholder, #dockedPromptInput::placeholder { color:var(--text-faint); }
        .hero-tools-row { border-top:0; }
        .docked-composer-wrap { padding:0 12px 16px; background:transparent; border:0; }
        .docked-composer-wrap .hero-input-box { border:0; background:transparent; box-shadow:none; padding:0; }
        .docked-composer-wrap .hero-input-box:focus-within { box-shadow:none; }
        #dockedComposer { max-width:820px; margin:0 auto; background:rgba(28,22,42,.8); backdrop-filter:blur(14px);
            border:1px solid #3b3060; border-radius:22px; box-shadow:0 -8px 34px -14px rgba(0,0,0,.7); }
        #dockedComposer:focus-within { border-color:#8f77e0; }
        .send-pill-btn { background:linear-gradient(180deg,#a78bfa,#7c3aed) !important; color:#f7f4ff !important;
            border-radius:11px; width:38px; height:38px; padding:0; display:inline-flex; align-items:center;
            justify-content:center; box-shadow:0 5px 14px -6px rgba(124,58,237,.6); transition:filter .14s, transform .12s; }
        .send-pill-btn:hover { filter:brightness(1.1); }
        .send-pill-btn:active { transform:scale(.94); }
        .stop-pill { background:#241d36 !important; color:var(--text-main) !important; border:1px solid #372c55;
            border-radius:11px; height:38px; }
        .stop-dot { background:#ef8f7d; }
        .modal-backdrop { background:rgba(10,8,16,.62); backdrop-filter:blur(4px); }
        .modal-card { background:#1d1729; border:1px solid #372c55; border-radius:18px;
            box-shadow:0 30px 70px -28px rgba(0,0,0,.8); }
        .modal-search-input { background:#171221; border:1px solid #2a2240; border-radius:10px; color:var(--text-main); }
        .model-row-item { border-radius:10px; }
        .model-row-item:hover { background:#241d36; }
        .model-row-item.active { background:rgba(124,58,237,.14); box-shadow:inset 0 0 0 1px rgba(167,139,250,.38); }
        .model-row-name { font-family:var(--font-display); }
        .user-pill { background:#241d36; border:1px solid #3b3060; border-radius:999px; }
        .user-menu-popover { background:#221b31; border:1px solid #372c55; border-radius:13px;
            box-shadow:0 16px 40px -14px rgba(0,0,0,.7); }
        .user-menu-item:hover { background:#2c2346; }

        /* button system: violet gradient ONLY for real primaries; ghost for secondaries */
        .btn:not(.btn-sec):not(.btn-red) {
            background:linear-gradient(180deg,#a78bfa,#7c3aed) !important;
            color:#f7f4ff !important; border:0 !important; font-weight:600;
            box-shadow:0 4px 14px -6px rgba(124,58,237,.5); }
        .btn:not(.btn-sec):not(.btn-red):hover { filter:brightness(1.09); }
        .btn-sec, .btn.btn-sec { background:#241d36 !important; color:var(--text-main) !important;
            border:1px solid #3b3060 !important; box-shadow:none !important; font-weight:500 !important;
            transition:border-color .15s, background .15s; }
        .btn-sec:hover, .btn.btn-sec:hover { border-color:#8b78cf !important; background:#2c2346 !important; }
        .btn-sec.btn-red, .btn-red { background:transparent !important; color:var(--red) !important;
            border-color:rgba(239,143,125,.22) !important; box-shadow:none !important; font-weight:500 !important; }
        .btn-sec.btn-red:hover { background:rgba(239,143,125,.09) !important; color:#f0a48f !important;
            border-color:rgba(239,143,125,.4) !important; }

        ::selection { background:rgba(167,139,250,.28); }
        ::-webkit-scrollbar { width:10px; height:10px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:#3a2f5c; border-radius:99px; border:3px solid transparent;
            background-clip:content-box; }
        ::-webkit-scrollbar-thumb:hover { background:#4c4077; border:3px solid transparent; background-clip:content-box; }

        #btToastWrap { position:fixed; right:22px; bottom:22px; z-index:999; display:flex;
            flex-direction:column; gap:10px; align-items:flex-end; pointer-events:none; }
        .bt-toast { pointer-events:auto; display:flex; align-items:flex-start; gap:10px; max-width:380px;
            padding:12px 15px; background:#241d36; border:1px solid #372c55; border-left:3px solid #8f86b4;
            border-radius:13px; box-shadow:0 16px 44px -18px rgba(0,0,0,.8); color:#ece8f6;
            font-size:13px; line-height:1.45; opacity:0; transform:translateX(16px);
            transition:opacity .22s ease, transform .22s ease; cursor:pointer; font-family:var(--font-ui); }
        .bt-toast.show { opacity:1; transform:none; }
        .bt-toast.err  { border-left-color:#ef8f7d; }
        .bt-toast.err .bt-ico { color:#ef8f7d; }
        .bt-toast.ok   { border-left-color:#8fd39a; }
        .bt-toast.ok .bt-ico { color:#8fd39a; }
        .bt-toast.warn { border-left-color:#e3c46f; }
        .bt-toast.warn .bt-ico { color:#e3c46f; }
        .bt-toast.info  { border-left-color:#a78bfa; }
        .bt-toast.info .bt-ico { color:#a78bfa; }
        .bt-toast .bt-ico { font-size:13px; line-height:1.3; }
        .bt-toast .bt-msg { word-break:break-word; }

        </style>
</head>
<body>

    <!-- SIDEBAR -->
    <aside class="sidebar" id="appSidebar">
        <div class="sidebar-header">
            <a href="/chat" class="sidebar-brand">
                <div class="brand-icon-circle">B</div>
                <span>Bridgena</span>
            </a>
            <button class="icon-btn" onclick="toggleSidebar()" title="Toggle Sidebar">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
        </div>

        <div class="sidebar-content">
            <button class="new-chat-btn" onclick="newChat()">
                <div style="display:flex;align-items:center;gap:8px">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                    <span>New Chat</span>
                </div>
                <span style="font-size:11px;color:var(--text-faint)">Ctrl+K</span>
            </button>

            <!-- SEARCH -->
            <div class="sidebar-search-box">
                <svg class="sidebar-search-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <input type="text" class="sidebar-search-input" id="chatSearchInput" placeholder="Search chats..." oninput="filterHistoryList()">
            </div>

            <!-- CHAT LIST -->
            <div class="sidebar-section-title">Recent Chats</div>
            <div class="nav-list" id="chatHistoryList"></div>
        </div>

        <div class="sidebar-footer">
            <div class="user-pill" onclick="toggleUserMenu()">
                <div class="user-avatar-badge">AD</div>
                <div class="user-name">Admin Workspace</div>
            </div>
            <div class="user-menu-popover" id="userMenuPopover">
                <a href="/dashboard" class="user-menu-item">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                    <span>Control Center</span>
                </a>
                <a href="/logout" class="user-menu-item" style="color:#ef4444">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    <span>Sign Out</span>
                </a>
            </div>
        </div>
    </aside>

    <!-- MAIN CHAT CONTAINER -->
    <main class="main-chat-container">
        <!-- TOP NAVBAR -->
        <header class="top-navbar">
            <div style="display:flex;align-items:center;gap:8px">
                <button class="icon-btn" onclick="toggleSidebar()" title="Toggle Sidebar">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
                </button>
                <div class="model-header-wrap" onclick="openModelModal()">
                    <span id="currentModelLabel">gpt-4o</span>
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </div>
            </div>

            <div class="top-right-tools">
                <button class="icon-btn" title="New Chat" onclick="newChat()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                </button>
                <button class="icon-btn" title="Control Center" onclick="location.href='/dashboard'">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                </button>
            </div>
        </header>

        <!-- CHAT SCROLL AREA -->
        <div class="chat-scroll-area" id="chatScrollArea">
            <div class="chat-content-width" id="chatContentWidth">
                
                <!-- EMPTY HERO STATE -->
                <div class="hero-empty-state" id="heroEmptyState">
                    <div class="hero-title">How can I help you today?</div>

                    <!-- HERO INPUT BOX -->
                    <div class="hero-input-box">
                        <textarea class="hero-textarea" id="heroPromptInput" rows="1" placeholder="Message Bridgena..." onkeydown="handleHeroKey(event)" oninput="autoResize(this)"></textarea>
                        <div class="hero-tools-row">
                            <button class="send-pill-btn" onclick="sendFromHero()" title="Send">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
                            </button>
                        </div>
                    </div>

                    <!-- SUGGESTIONS -->
                    <div class="suggestions-wrap">
                        <div class="suggest-card" onclick="useSuggestion('Write an async Python script demonstrating worker queue architecture')">
                            <div class="suggest-title">Write Python script</div>
                            <div class="suggest-desc">async worker queue architecture</div>
                        </div>
                        <div class="suggest-card" onclick="useSuggestion('Explain how DeepSeek R1 reasoning models work internally')">
                            <div class="suggest-title">Reasoning models</div>
                            <div class="suggest-desc">deep chain-of-thought mechanisms</div>
                        </div>
                        <div class="suggest-card" onclick="useSuggestion('Design a modern dark UI component with pure CSS and clean aesthetics')">
                            <div class="suggest-title">Design CSS component</div>
                            <div class="suggest-desc">minimalist dark mode aesthetics</div>
                        </div>
                    </div>
                </div>

                <!-- MESSAGES CONTAINER -->
                <div class="messages-container" id="messagesList" style="display:none"></div>

            </div>
        </div>

        <!-- DOCKED BOTTOM COMPOSER -->
        <div class="docked-composer-wrap" id="dockedComposer" style="display:none">
            <button class="stop-pill" id="stopPill" onclick="stopGenerating()">
                <div class="stop-dot"></div>
                <span>Stop generating</span>
            </button>
            <div class="hero-input-box">
                <textarea class="hero-textarea" id="dockedPromptInput" rows="1" placeholder="Message Bridgena..." onkeydown="handleDockedKey(event)" oninput="autoResize(this)"></textarea>
                <div class="hero-tools-row">
                    <button class="send-pill-btn" onclick="sendFromDocked()" title="Send">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
                    </button>
                </div>
            </div>
            <div style="font-size:11.5px;color:var(--text-faint);margin-top:2px">Bridgena can make mistakes. Verify important info.</div>
        </div>
    </main>

    <!-- MODEL SELECTOR MODAL -->
    <div class="modal-backdrop" id="modelModalBackdrop" onclick="closeModelModal(event)">
        <div class="modal-card" onclick="event.stopPropagation()">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <span style="font-weight:600;font-size:15px;color:var(--text-main)">Select Model (<span id="modalModelCount">0</span> available)</span>
                <button class="icon-btn" onclick="closeModelModal()">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                </button>
            </div>
            <input type="text" class="modal-search-input" id="modelSearchInput" placeholder="Search models by name or provider..." oninput="filterModelsList()">
            <div class="modal-models-list" id="modalModelsList"></div>
        </div>
    </div>

    <script>
    let currentModel = localStorage.getItem('nx_model') || 'gpt-4o';
    let availableModels = [];
    let conversations = [];
    try {
        conversations = JSON.parse(localStorage.getItem('nx_conversations') || '[]');
        if (!Array.isArray(conversations)) conversations = [];
    } catch(e) {
        conversations = [];
    }
    let currentConvId = localStorage.getItem('nx_current_id') || null;
    let abortController = null;

    // Safe Markdown Renderer with fallback
    function safeRenderMarkdown(text) {
        if (!text) return '';
        try {
            if (typeof marked !== 'undefined') {
                return marked.parse(text);
            }
        } catch(e) {}
        return escapeHtml(text).replace(/\n/g, '<br>');
    }

    function toggleSidebar() {
        document.getElementById('appSidebar').classList.toggle('collapsed');
    }

    function toggleUserMenu() {
        document.getElementById('userMenuPopover').classList.toggle('open');
    }

    function autoResize(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
    }

    function handleHeroKey(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendFromHero();
        }
    }

    function handleDockedKey(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendFromDocked();
        }
    }

    function openModelModal() {
        document.getElementById('modelModalBackdrop').classList.add('open');
        const inp = document.getElementById('modelSearchInput');
        inp.value = '';
        renderModelsList();
        setTimeout(() => inp.focus(), 50);
    }

    function closeModelModal(e) {
        document.getElementById('modelModalBackdrop').classList.remove('open');
    }

    function selectModel(modelId) {
        currentModel = modelId;
        localStorage.setItem('nx_model', modelId);
        document.getElementById('currentModelLabel').textContent = modelId;
        closeModelModal();
        renderModelsList();
    }

    async function loadModels() {
        try {
            const r = await fetch('/chat/api/models', { credentials: 'include' });
            const d = await r.json();
            if (d.data && d.data.length > 0) {
                availableModels = d.data;
                if (!availableModels.some(m => m.id === currentModel)) {
                    currentModel = availableModels[0].id;
                }
            } else {
                availableModels = [{ id: 'gpt-4o', owned_by: 'OpenAI' }];
            }
        } catch (e) {
            availableModels = [{ id: 'gpt-4o', owned_by: 'OpenAI' }];
        }
        document.getElementById('currentModelLabel').textContent = currentModel;
        document.getElementById('modalModelCount').textContent = availableModels.length;
        renderModelsList();
    }

    function renderModelsList() {
        const list = document.getElementById('modalModelsList');
        const q = (document.getElementById('modelSearchInput').value || '').toLowerCase().trim();
        const filtered = availableModels.filter(m => (m.id && m.id.toLowerCase().includes(q)) || (m.owned_by && m.owned_by.toLowerCase().includes(q)));
        
        if (filtered.length === 0) {
            list.innerHTML = `<div style="padding:14px;font-size:13px;color:var(--text-faint);text-align:center">No matching models found</div>`;
            return;
        }

        list.innerHTML = filtered.map(m => `
            <div class="model-row-item ${m.id === currentModel ? 'active' : ''}" onclick="selectModel('${escapeAttr(m.id)}')">
                <span class="model-row-name">${escapeHtml(m.id)}</span>
                <span class="model-row-provider">${escapeHtml(m.owned_by || 'Arena')}</span>
            </div>
        `).join('');
    }

    function filterModelsList() {
        renderModelsList();
    }

    function getActiveConv() {
        if (!currentConvId) return null;
        return conversations.find(c => c && c.id === currentConvId) || null;
    }

    function saveConversations() {
        try {
            localStorage.setItem('nx_conversations', JSON.stringify(conversations));
            localStorage.setItem('nx_current_id', currentConvId || '');
        } catch(e) {}
        renderHistoryList();
    }

    function newChat() {
        currentConvId = null;
        saveConversations();
        renderChatView();
        const inp = document.getElementById('heroPromptInput');
        if (inp) inp.focus();
    }

    function selectChat(id) {
        currentConvId = id;
        saveConversations();
        renderChatView();
    }

    function deleteChat(id, e) {
        if (e) e.stopPropagation();
        conversations = conversations.filter(c => c && c.id !== id);
        if (currentConvId === id) currentConvId = null;
        saveConversations();
        renderChatView();
    }

    function renameChat(id, e) {
        if (e) e.stopPropagation();
        const conv = conversations.find(c => c && c.id === id);
        if (!conv) return;
        const newTitle = prompt('Enter conversation title:', conv.title || 'New Chat');
        if (newTitle && newTitle.trim()) {
            conv.title = newTitle.trim();
            saveConversations();
        }
    }

    function filterHistoryList() {
        renderHistoryList();
    }

    function renderHistoryList() {
        const list = document.getElementById('chatHistoryList');
        const q = (document.getElementById('chatSearchInput')?.value || '').toLowerCase().trim();
        const filtered = conversations.filter(c => c && (!q || (c.title || '').toLowerCase().includes(q)));

        if (filtered.length === 0) {
            list.innerHTML = `
                <div style="padding:10px;font-size:12.5px;color:var(--text-faint);text-align:center">
                    No recent chats
                </div>
            `;
            return;
        }

        list.innerHTML = filtered.map(c => `
            <div class="chat-history-item ${c.id === currentConvId ? 'active' : ''}" onclick="selectChat('${c.id}')">
                <span class="chat-title-text">${escapeHtml(c.title || 'New Chat')}</span>
                <div class="chat-item-actions">
                    <button class="chat-action-btn" onclick="renameChat('${c.id}', event)" title="Rename">✏️</button>
                    <button class="chat-action-btn" onclick="deleteChat('${c.id}', event)" title="Delete">🗑️</button>
                </div>
            </div>
        `).join('');
    }

    function renderChatView() {
        const conv = getActiveConv();
        const hero = document.getElementById('heroEmptyState');
        const msgsList = document.getElementById('messagesList');
        const docked = document.getElementById('dockedComposer');

        if (!conv || !Array.isArray(conv.messages) || conv.messages.length === 0) {
            hero.style.display = 'flex';
            msgsList.style.display = 'none';
            docked.style.display = 'none';
            msgsList.innerHTML = '';
        } else {
            hero.style.display = 'none';
            msgsList.style.display = 'flex';
            docked.style.display = 'flex';
            renderMessages();
        }
    }

    function copyCode(btn) {
        const pre = btn.closest('pre');
        const code = pre ? pre.querySelector('code')?.innerText || '' : '';
        if (code) {
            navigator.clipboard.writeText(code);
            btn.innerHTML = '✓ Copied';
            setTimeout(() => { btn.innerHTML = 'Copy'; }, 2000);
        }
    }

    function renderMessages() {
        const conv = getActiveConv();
        if (!conv || !Array.isArray(conv.messages)) return;
        const box = document.getElementById('messagesList');
        box.innerHTML = conv.messages.map((m, idx) => {
            if (m.role === 'user') {
                return `
                    <div class="message-wrapper user">
                        <div class="user-bubble">${escapeHtml(m.content || '')}</div>
                    </div>
                `;
            } else {
                let parsed = m.content || '';
                let thoughtHtml = '';
                if (m.thought) {
                    thoughtHtml = `
                        <details class="thought-accordion" open>
                            <summary>Thinking Process</summary>
                            <div class="thought-body">${escapeHtml(m.thought)}</div>
                        </details>
                    `;
                }
                const renderedMarkdown = safeRenderMarkdown(parsed);
                return `
                    <div class="message-wrapper assistant" id="msg-${idx}">
                        <div class="assistant-row">
                            <div class="assistant-avatar">B</div>
                            <div class="assistant-content-col">
                                <div class="assistant-meta">${escapeHtml(m.model || currentModel)}</div>
                                ${thoughtHtml}
                                <div class="assistant-body">${renderedMarkdown}</div>
                            </div>
                        </div>
                    </div>
                `;
            }
        }).join('');

        box.querySelectorAll('pre').forEach(pre => {
            if (!pre.querySelector('.code-header-bar')) {
                const codeEl = pre.querySelector('code');
                const lang = (codeEl?.className?.match(/language-(\w+)/) || [, 'code'])[1];
                const header = document.createElement('div');
                header.className = 'code-header-bar';
                header.innerHTML = `<span>${escapeHtml(lang)}</span><button class="code-copy-btn" onclick="copyCode(this)"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy</button>`;
                pre.insertBefore(header, codeEl);
            }
        });

        const scrollArea = document.getElementById('chatScrollArea');
        scrollArea.scrollTop = scrollArea.scrollHeight;
    }

    function escapeHtml(str) {
        return (str || '').toString().replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function escapeAttr(str) {
        return (str || '').toString().replace(/'/g, "\'");
    }

    function useSuggestion(text) {
        const inp = document.getElementById('heroPromptInput');
        if (inp) {
            inp.value = text;
            sendFromHero();
        }
    }

    function sendFromHero() {
        const inp = document.getElementById('heroPromptInput');
        const txt = inp?.value?.trim();
        if (!txt) return;
        inp.value = '';
        inp.style.height = 'auto';
        sendMessage(txt);
    }

    function sendFromDocked() {
        const inp = document.getElementById('dockedPromptInput');
        const txt = inp?.value?.trim();
        if (!txt) return;
        inp.value = '';
        inp.style.height = 'auto';
        sendMessage(txt);
    }

    function btToast(msg, kind) {
        let w = document.getElementById('btToastWrap');
        if (!w) { w = document.createElement('div'); w.id = 'btToastWrap'; document.body.appendChild(w); }
        const el = document.createElement('div');
        el.className = 'bt-toast ' + (kind || 'info');
        el.innerHTML = '<span class="bt-ico"></span><span class="bt-msg"></span>';
        el.querySelector('.bt-ico').textContent = kind === 'err' ? '⚠' : (kind === 'ok' ? '✓' : 'ℹ');
        el.querySelector('.bt-msg').textContent = msg;
        el.onclick = () => el.remove();
        w.appendChild(el);
        while (w.children.length > 4) w.removeChild(w.firstChild);
        requestAnimationFrame(() => el.classList.add('show'));
        setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 320); },
                   kind === 'err' ? 8000 : 3800);
    }
    window.addEventListener('unhandledrejection', e => {
        const m = (e && e.reason && (e.reason.message || e.reason)) || 'unknown';
        btToast('UI error: ' + String(m).slice(0, 180), 'err');
    });

    async function sendMessage(text) {
        let conv = getActiveConv();
        if (!conv) {
            conv = {
                id: 'conv_' + Date.now(),
                title: text.slice(0, 36) + (text.length > 36 ? '...' : ''),
                messages: []
            };
            conversations.unshift(conv);
            currentConvId = conv.id;
        }

        conv.messages.push({ role: 'user', content: text });
        const assistantMsg = { role: 'assistant', content: '', thought: '', model: currentModel };
        conv.messages.push(assistantMsg);
        saveConversations();
        renderChatView();

        const stopBtn = document.getElementById('stopPill');
        if (stopBtn) stopBtn.classList.add('visible');
        
        const heroInput = document.getElementById('heroPromptInput');
        const dockedInput = document.getElementById('dockedPromptInput');
        if (heroInput) heroInput.disabled = true;
        if (dockedInput) dockedInput.disabled = true;

        abortController = new AbortController();

        try {
            const history = conv.messages.slice(0, -1).map(m => ({ role: m.role, content: m.content }));
            const r = await fetch('/v1/chat/completions', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    model: currentModel,
                    messages: history,
                    stream: true
                }),
                signal: abortController.signal
            });

            if (!r.ok) {
                const errText = await r.text();
                assistantMsg.content = '⚠️ Error (' + r.status + '): ' + errText;
                btToast('HTTP ' + r.status + ': ' + errText.slice(0, 200), 'err');
                saveConversations();
                renderMessages();
                return;
            }

            const reader = r.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buffer += decoder.decode(value, { stream: true });
                const lines = buffer.split('\n');
                buffer = lines.pop() || '';

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const dataStr = line.slice(6).trim();
                    if (dataStr === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(dataStr);
                        if (parsed.error) {
                            assistantMsg.content += '\n\n<span style="color:#ef4444">**Error**: ' + (parsed.error.message || JSON.stringify(parsed.error)) + '</span>';
                            btToast(String(parsed.error.message || 'Upstream returned an error').slice(0, 220), 'err');
                            renderMessages();
                            continue;
                        }
                        const delta = parsed.choices?.[0]?.delta;
                        if (delta?.content) {
                            assistantMsg.content += delta.content;
                        }
                        if (delta?.reasoning_content || delta?.thought) {
                            assistantMsg.thought += (delta.reasoning_content || delta.thought);
                        }
                        renderMessages();
                    } catch (e) {}
                }
            }
        } catch (e) {
            if (e.name !== 'AbortError') {
                assistantMsg.content += '\n\n*(Generation interrupted: ' + e.message + ')*';
                btToast('Generation interrupted: ' + e.message, 'err');
            }
        } finally {
            if (stopBtn) stopBtn.classList.remove('visible');
            
            const heroInput = document.getElementById('heroPromptInput');
            const dockedInput = document.getElementById('dockedPromptInput');
            if (heroInput) heroInput.disabled = false;
            if (dockedInput) dockedInput.disabled = false;

            abortController = null;
            saveConversations();
            renderMessages();
        }
    }

    function stopGenerating() {
        if (abortController) {
            abortController.abort();
            abortController = null;
        }
        const stopBtn = document.getElementById('stopPill');
        if (stopBtn) stopBtn.classList.remove('visible');
    }

    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            newChat();
        }
    });

    document.addEventListener('click', e => {
        const pop = document.getElementById('userMenuPopover');
        const pill = document.querySelector('.user-pill');
        if (pop && pop.classList.contains('open') && !pop.contains(e.target) && !pill.contains(e.target)) {
            pop.classList.remove('open');
        }
    });

    // Initialize safely
    try {
        renderHistoryList();
        renderChatView();
        loadModels();
    } catch(e) {
        console.error('Initialization error:', e);
    }
    </script>
</body>
</html>"""


@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    return HTMLResponse(CHAT_TEMPLATE)


@app.get("/chat/api/models")
async def chat_api_models(request: Request):
    if not await get_current_session(request):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    data = [{"id": m.get("publicName"), "owned_by": m.get("organization", "Arena")} for m in get_selectable_models()]
    for om in oxalpha_models():
        data.append({"id": om["id"], "owned_by": om["owned_by"]})
    jars = load_jars()
    now = time.time()
    healthy = sum(1 for j in jars if jar_available(j, now))
    return {"data": data, "jars_total": len(jars), "jars_healthy": healthy}


# ============================================================
# UI - MINIMALIST CONTROL CENTER DASHBOARD (/dashboard)
# ============================================================

DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="bridgena-build" content="r6.2-tailwind-fastpath">
        <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena - Control Center</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,300;9..144,400;9..144,500;9..144,600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
                :root {
            --bg-base: #151120;
            --bg-card: rgba(31,25,41,.88);
            --bg-hover: #261e3c;
            --border: #322848;
            --border-hover: #453a63;
            --text-main: #ece8f6;
            --text-muted: #a49bc4;
            --text-faint: #776e94;
            --accent: #a78bfa;
            --accent-text: #171126;
            --green: #8fd39a;
            --yellow: #e3c46f;
            --red: #ef8f7d;
            --blue: #9fb6e8;
            --font-display: 'Fraunces','Iowan Old Style','Palatino Linotype','Book Antiqua',Georgia,serif;
            --font-ui: 'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            --hero: url('data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAwICQsJCAwLCgsODQwOEh4UEhEREiUbHBYeLCcuLisnKyoxN0Y7MTRCNCorPVM+QkhKTk9OLztWXFVMW0ZNTkv/2wBDAQ0ODhIQEiQUFCRLMisyS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0v/wgARCAQ4B4ADASIAAhEBAxEB/8QAGgABAQEBAQEBAAAAAAAAAAAAAAECAwQFBv/EABgBAQEBAQEAAAAAAAAAAAAAAAABAwIE/9oADAMBAAIQAxAAAAH8wOgAAAACoAAKEsCwUAAWgKhQAALAAAoQApFgWAAAABYAAksoCiBQlCWIAAAAAAAAAABUolLFgoACiUQAoAAWCy0CrKAFhKACyiwoBRFEoAFAAAEWCglgABBAoWAAAEUCkWACgAESgWKKRRFCqZULKFksUShVgCiRYCWIlhYBCAecdZgAAFgAWApKCKJRKAAUWAKsoAABQAAAQpKAgAWAAtJZFSkWAICgAAAASwiyqAlEUJRKEWAIAKSigCkAAqFlhZYWUCgUAAUoAFikUSgAKoBRFgUCkoARQlhFAAEWAEqkEKCURRCkUSgKRRFEqkUsVEURQKRRKKUSrEABNSiUsXMWCLAgJRFgBFh5x1kAoShFEUEoAFBAUAKQKsAoQKgsoKIoSgUAASgAEAAoSgARAAACUCFQUAEUJQAlBAsFikoRQAAAAspKAAAAoFCkBQoBRFAFlEoqUFAUAAKAAABAEWApAJQAAWQABZRKEUSgWCyrFAolgLAApFKlEqkpAEUSyrAEFSyQCAAAAlEUeUdZALBUosAVKRFhRQAACwFiqABBYCygApFhRQCBUoBYEUACFIWWApFkAAAShKBKAAAAJRFgWFAAAABQAAAAAUUAAooAApKAAFFFLKBRFApFgURQKRRARRBBYJRFEUAAABCykURSikWAomoACkUspBYVKAABAhSKIlgJQABFEVCUSwKEUeQdZAAVKAARVAAEosAAFItlhYBYFAAFikUBQCUACghZRJQAAlEoAQBRFEEAAAAAJQAlAAAAFSkKRQAAFLBQAAFAKUQCygAoFVKooAAoAAFLKClQRJSSglBZAAEUSglEUSqsoJRFRKBRKABRKKlAQKQBYCFRAhUBAoALKRURYWAAKJSxR4x1jYACgAFAAJQAAAAUAJShQAQsClAALKQAoIUAACAUQAAEoAAJQlELCURYAAAAACkKSgSkUBQQLUWFBFAAoCikoAFVFAFAKoAFFAKKKSgAAlkCkURRAFEURURRFEURRKBYFgECgKUAShFAQlhUFiACWAQBCgAoAlkCgqxRKBauG5HiHeCBQJYUVKAAAAAAAFAAstqAAKSgAAqBYALKJaSWCgFJZFlVFEpEAACFi2AAWAAAEWRYFlEUSgAFAFEKSgAAAAUAoCgKQtAFAALRRRKpFEotKRRALKRRFEUJURRFgURqEtglBZEUJRKBRAFEpKlpFgBKCoWEIgIVAIVBRAABQKRYqVCqKq5XUYuhFLBHgGvnAAAAAAAAAAAssFgoBagBVllAAAFgoIogFlECwqgLAsAAJQAACRLBYVQgAAEshSgAALLBUKBKAABSUAJQBVCUoollAFAVQoolUlUlVYqotIoSiKiLSAlAogIUigUlWJNCLCKM2yAUtMtQiiUCwlAILBLAkKiCUECxEoKWCCgUilKI0jLRZVFWWLACLILDwo185YCkWAAAAACUJQAAWFAFCkUSwUAqxYAUUAlAAAFlAhQJSRYFigAAgQCwqQAKAAAABQAAAAAUAACUAqlCkoAFEoKWihRKAostpQURRFApFEUsVEUklEUFEWrm0RQmhlqQmoSagURbGVglEqkWABEWSFiFgISAAWKsUJQVCWrFEtpKssqrFkALKRRAJUFi+CVr5gJQSiKIUgACiAAKEoAlgooCpQABZRFoFFIohSLABUKAsCiBJQBUpAIAAFBIWAtSoigKAACBSAVAoACiiKAUoigAolKKJRShVIoCilUFAojUI0JVWLAACKSNCNRZaiKItMqAIIlAoihLFS2MrTNsIQRES5ixEqUgAhZSKWWwsqJVUUKWUhRYoWwFiABUqIsFgsDwDXzFgAASlllFEABKAAQAFAAAVKFgsBVSgAsoACgASgKJQFAkURRABEoShFEURYFCUSiyhKAAApCkAWCglBRFKKQoFAUBRKKAq0KSqRSlBVFAoClBURYQBaRoZtEtEmhlUsoiURoZmkRauVEUSahFRARMpYgiQliAWKQQKCrLRFpGksURSpbEWrFCxBBQAqywgIEqgp85Zt5liAosBQsAAE1ACLBYALLAAABZQQooCgAssFAFCxRQ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FQWAIQXgAAABKAIsCwAAAAAAAqBYKlBCglgoAJQAAAAAAAWAAAAACoAFCAsAAoEKABKICpQAABZQAAAKABQgAAAAgpCgAAAAAAAAAAAAAAAAAAAAAsAACwAUAAAIsAABYLAAAAAAAAAAAAAAAAAyLyAAShKAEoABAAAFgAKQAACyksFAAABKAAAAAAAACwAAAWAABUpAAAUCWFSgAgAKAAAAVBQQCwUBC1KACFQVKJRAUAABBQAAAJQIUhQAAAAAAAAAAAAEoAAAEBaEAAAAAAAJRKAAhUFSgAAAgsoSgAGRYCCFQVKASgIWAoASgBFBAKJYACkUEoAAAAAAAAAAAAsAAAFgAAAVAABUAFShBSAAoAAAKSoAAACiAAsFgoApFgBUAAFQVBSFlhYFgFEAsFQUAAAhQAAAAACFSghQAJZFFJZFQLCqABBYoQVAABYAAFgUCUJQgAWAqEF5QgBSgEACoKAAQqUAAgLALBZQAAAQoAAAAAAAAAAAAAAAAAALAAAAsABYLLACkFAAACoAAAAAAAAUAEBQAAAAAAAAALAAAAWAAACpQAQoCCoLFJYLAWCoAFgssAgChRCwALAABAAVYLAAAAqUgBSAAyHIAAAAAUsFBCiWAFQUCUSgIUAAhQAAJQAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAEoIVKAAAAAAAoICggKAAAAAAAAAAAsAAAAAAACwWBYCykUQAAAAFgBACwAAAAAAAAoAIAACgWAsAAGQ5AAAAACgAKgsolgKJZRLCkKCLCpSLAUSgAAAAAAAAAAAAAAAAAAAAAAAAAABZRLCoKACLBQSgAAAAAAAAFBAUEABQAQFAAAASgAAAAAAAAAAAAAAAAAIACgAgAAAAAAAAAAAAAFBBChQATIQAUlgAAACgAAFgpCxSAApCpQlCURRLCgEKAAAAAAAAAAAAAQoAAAAAAAAAAFlEsAFlCUQKAAAAAgoAABCgEFgqUSwWUJQAAQoABChQCUAAAAAEKCUAAAAAAAgAAKCAAAAAABCgAAAAAAAASgAADIQAAAAAAKACAAoAAAAAAoAARQCKJQAAAAAAAAAAAAAAAAAAAALAAAoASwAAAAqCpQgssKgWCoKAAAQsABQgAKgWCoLAqCggFgssAKgBQLAqUQFgqCwKAQqCgCAAoIAAAAAAlABKBCgAAEKAAAAAAAQgQAAAAAAAAAKCALCrAAAWBYLAVBYKQoAAAAAAAAAAAAAAAAAAAAALAAAAAAAAAAAsAAAABYLLBYAAAAAAALAAAAAAAWAAAAAAUQUAAACggAFgCFirKgAAAAAgqUAAAAAILApCkKAgqAABZRLCBAAAAAAAAAAoAUlQAAAAAAAWABYFlAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFgBQAAAAFgAAACKAgoEABYLAqCoKAQAWAoiwAAAAAoEsIEAAAAAAAAAAWAKAACAoIAACgBSAWCxQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICrBQAAAAAgKAACAAAAAAALAAAqURSAAAWCywAqCBAAAAAAAAAAAAoICggKCAAAAoAABZQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAACgAAAAUJAUKCAAAAAAAAAABSLAAAAAAAAAABBAAAAAAAAAAAAAAAoAICgAgAAKAAoAAUEABQQAAFBAAAAAAAAAAAAAAAAAAAAAAJYKAAAAAAAAAAAAAAAAAAAAAAASKAAAAKAAAAACEpQsBQAAgAAAAAAAAAAAAAAAAABLAEAAAAAAAAAAAAACgAgKACAoAIWKsolQoAAAAAAAAUEAAAAAAAAASwoAAAAAAAAAAAEolBKAAAAAAAAAAACUAAAAAAAAAAACAoIAACgBIoAoAAAAFACAAAAAAAAAAAAAAAAAAAIEAAAAAAAAEKAAAAAKAAAACAAAqxSKJZQAAACAWUIKlAEUSgAAAAAAQsoSwAoJQAAAAAAAAIKAAAAAAAAAAAAAAAAAAAAAAACAqUACAoIACkqJYKKCAoICgAgAAFBEolhaQoAAAAAAECpQAESxSwBCUAAAAAAAigAAAAAAKAAAAACAoBYCwqCgAQFgVAollAJZQlAAAAEsAKQqUEKgqUAAllBCygAAAQWUASwqUASwWCgJQAAAAAAAAQoAAEsKAAlhKICkFlApKAABCkipaQikKAQoCCpQAAAABKBFoACUBAUAElFSxFgBbLAEAAAAAAAAAAAAAAAACgAAAiwLCgAAABRLAUECglBAUEKgoAAAEsALLCkLAFABAUiwAVCgIKlBCwAKAABLAUlQAWUJQQpCpQAABLIWKqCgCCACwLACggBQAllEsqywAAoEsFiACwFICoKlAABCgAQAWgBAAUlCUBEsKgAAAAAAAAAAAAAAAAAACgAgKCAoAACywAAsAACwALFEsCwAUAACUQAFlEAAACwKgLACwCwAoCCygBFCCwLKECoLAAsCoixQloAlAhAoJYLAAFIogCwAAAAoAAoQVBQARSFiAqAAAAAAAACwKgsBYKlAAAABAAAAAAAAAAAAAAAAAAAAAAKCAAAAAoABZSLCxRKJYAAKQoJYCwAAsCwAFgpCoLLAAAAAsAAKCAsAsKBKJUBSFIBYAAAAAgCpRKAAIAAsAAAAAAKlEUiwLBZQAgCliKSrCAosAgAAAAAAAACwAAAALAAAAAAAAAAAAAAAAAAAAILKAAAAAAAAAAoICgAKBKEogFgFJQIKQsoiwAqUQAAAAABSAWAAAAAAAACoKgsACwAAAALLAIAAAAAAAAsAAAAAAAAAABYLAAAAACgAgAAAAAAAAAAAAAAAAAAAAAsAABCoKlJQAAAAAASwFEsKlAAAAAAAACygAACgQoEoiwqBQAJSAFIAAAAACwCwLCgQAAAgAKAAAAAsAAAAIAAAAAAAAAAAAFIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQoJZQAAlAIoSgQqURRAAoABCkKAAAAAAAKFIUiggpAAAAAAAAAAAACwAAAALAACAFlpAACAoAIAAACggAABYAAAAAAAAFgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWAACFCCpQlIsAKQoIsAAFlIAUSgAAAAAAAAAKAAsCwAFlIAsAAAAAAFgAAAAAACAoAICggAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASwAAWABYKgoIABYCgABFEoAAAAAAACgKQAAAAAALAAAAAAAAAAAAIAAAAACggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAWACywAAAAAAssKlIsFlAEsKAAlAAAACUAAAAAACrFIAIsKAAAAACAoAAAIFIAAAKCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABC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1EVV+vtOJLIKLLBRiEEQFUs89ss8QogCEGm3MZ764a8EFUX33z33m0ADH/f/APX/APWZvtuvvklABEAAMNPINPP47gzw04QQTTTSQcQYUaPpiqly0uHPFfUQcQTww04wwywglnJgvgNDNPOTfY3+w0x/BGHPDRQRxx9nqvTRfffffPfeQQQYwe/003//AOJI4rb74xba5K4CAAQDT0l3330kV3233kV0kEH1Sya5DSAQwAEGlHX3+9/sMMdf867TwhRzSzwW0Ff8cMMONOFHhzxxyC+//JJEFX0HH333333kEEEEENf/APTrD3f/AP8A7Lr67q4IJ76gADDz3nXn1133X1nX1kX1SCQzyCRDzjDEEWG+8Nfe/wDv7B9BwsAwg4wAQgICCGqHHTXDFBRwgQM01RLPBBRBF999999999NF9pBBD/bTjX//AP8A/wD/AOvhnnvktmggjjhwRw1/c3f8/wD3EG3xACAATLywx776oMOPsMNOMOMMEEUEXBQAABSSAj5r5LpM9nuH31F3wwAzSCWEEEln3313333/AN59x9hxhJjDDX/z/wD/AP8A++u++eW++qG++CDTjLzz377xhJF18408syCC2yeC++OOOObLHf8ARX/ffbVdfUCAHvoANuusjv61pEKAfefbRGDHNBQQQQUQddfffffffTbSRQbQQ41ww1//APu/7777476L57/McMtP8sMP+sMOMHkAIIIII4YYIJLL5L4ILLPf33XHHHX313313jTDDJ7769/OsIIJAGU0HXkX20mEEEkkEkEH333X3n332m0EEEOMMM8/vuv+7775774r778NcsMf/sMv988P+8M4oIY4pL4III4IIIJIYYIIID0EVWkFHkEnEEEMALoLLbLLpKAAYwhDEEWkkGEAEU0kGEV2EGEHE3lX3nEkEEEMEP8A/vfn/v8A/q368vTvvz/yzx/+x29+5/8A/wD7f/ve+62+O++OOGWecy+sMAAAEAFRpBBFJFBBXBXPuiCOaOO++e8+cAQQc8ckBf8A4QXfTQcRSQQfXdaQQQRQQwwQ607/APuv/wDX/wD6xd3/AP8A/f8A71/x4/8A/wDP/rz7z/8A/lv/AL75ILDDj77xzzzyzzzwgAQE01m120321X/8IZ7577tvY57b7wjjrzz/AP8A+/8A/wBtB5V9NBRhFBBFBBBRFZhFBTjT/wD/ANf/AN/hBR199/5//wDww0+0yx+www5//wD7/wCzgEIQc08Qggwws8ws8844sccpx99V95V7/v8A/wD/APjDDm+bD/8AvnLvoP8A/wD/AP8A/wB99NRtxpVFB1J15RJBBRBRBBJBR9hBpB5xJR9559lf/rXPDD3jTDDDD3f3jyhABBgAhIgAAAQQwgAAAAAAA088951JDP59/wC8wwww978+ww0+ox1uAf8A/u//AP8A/ffebRWffRSSSWVURQQSQQQQQQQQQ6RQXffbff8A/P8A/rX/AKy3wwww4zw4wxQRbSVaSQQRQQRQACAAAAABAIAIPIMEf/8AvGNMMMMMMdMMsMMMMftMMMP/AP8A/wD9f/23/wD9999999xBBZBxhBBBBJBBJJPf/JNFxhJ9/wB7/wDMNf8A999NLPVNtNDBBFd9h99NtNdNB9tV9N88cIcsMcAEMASigTDDDDjDjDTHDjDHDDDDDDDF/wB++80/8/8AP3P91232212W0UEFEGEUEEl9333XPfvNP/31/wB51195tR19d9999tVt9999999d1x9999t999995c8888A88s+sSCCCKCOLDDDDDPfHHDPP/wD61/8A/wDPDfbDTD995l9x99999t9tpBBFdpR97V97/j//AI2+/wD/AN99BBpB9N99999995959999515999199999995999t8888s8M888+COCe+ueOODH/vz3/73/wDw1/7w8x76wx3/AO/3m0P3Pf8A9959lZBB9phhJV9NXD5bR1719991999VRp99px9xtd999Z9x9FRpRRBx999519x19999/wDXPPPPPPkPPPtvvvvvvnvvy2//AP8AvX+OvrDDT3rL/wD/AP8A9/8Af/S1/wCf3n12kEEEk2knHX12330EEEEX2nHH3kEFGEEEkEHkHX3lEEEX3321201H1EFH0EP/APrjZ99t987yUCCCS+e+622+62e+++++a+qCfDHPX/jT3L7/AP8A9+33/wB9/wDy/ffRQQIYSDRWeOQffcQfTQQURQdQSQQQRSQQbQQdcQcQQQUUeUfeYQQQQQSQRwwwx0efbffb0gbLAPugsojvvvvnvvikogqilvz+xx9yw24w1/8A/wB9/wDeQ3ba7UZQQQTSUaUfPQQcdTQYRSVQQQQVSQQQQYQUYUUQSQSQQQQRSSXQQQQQQQUQQQwQwwwQRwzYQQUYEKgiggksggltsogghgksgr8//wDf+8MMcMP/AP7x951V/vH9ZxpBBhB9pNdhZRRN1xBBFRV9BhBBBBBBBBNBBBBBBBBBBBBhBRBBBBBBBBB9JBDBDDBTvBDFDBBDDDCDTuGCCCCCOqeKiDW2zr3jDf8Ayw8xx+5ww7ZVfffb7fbdTYQXbZcaQaSQQQQVfRSRTSQQaRUQQQRaQVSQVbQSQQQQQQQQRQQQVQQS0/x6wUQQRRyXxwxwzywwwww0xggig0sg4l7/AJYMMO8OfsvusP8A/rDDH1d59/fd91995V5FxJF5FNBRpBV9VFd5BF519lBNJFd9BBBV5l9pJFFJBBBXtNBDP/ff9/8A4w61VffQVb/9+/zywwxww3/ggwwiig1z/wDssOsNOeusMMOMcOv/AFd/9/5hh9V99d99d9ZV15hRBJd9pd999dN19d19BNRBZNdRdNd9dPbJBJDfDvf/AO8v9/8A/wD/AAwwRZYQWe/z/wD/AP8A/wD/AP8A3z37ywwwwx//AP8ADD7DDDDjDDDDDDDrzn9r/wB/wxffadWUbffRQbdffXXfbRTVfffedffQfXdQUZeefbfXfff/AMtMMP8A/wB//wD/AP8A/wAtvfesM/28V/3X/wD/AP8A/wD7H/8A3/8A/wD/AH/+9/8Af+sMMMMMMMsMMMM9NP8Avz//AA//AP3/AN19BVR9t5hNFR19Jd1999959t99999999NNd9d9V99V/wD/AP8A73//AP3/AP8A/wD7+/8A/wD/AL3/AP8A/wC1ff8A/wD/AP8A/wD/AA9//wD/AP8A/wD/AP8A/wC/ff8ADHPLjDDDDDDX7XLjTDHjD/8A9fffcRQUdTYQSfeffefffXddQXfff/8A3333313333//AP8A/wD/AP8A/wD+/wDv7/3/AP8Asb7/AP8A/v8A/wD/AP7389/+/wD/AP8A/wAN/wD/AH/98xz/AP8Anf8A/wAcOsMMsPNMctt/8MMcdeN+sf8Aj955xNF95151p999t99dt999d9f/AKXbf/Vf/wDP/wB//wD/AO//AP8A/wB/e/8Av/33vPPv6/8A/v7/AP8A/wD/AP8A/wD+/wD/ALz/AA3/AP8A/wDzww//AOte+sPs8svf8cPf/wDr/wC0wwwwwy/2/wD331132n2W0332X22133323/13f3/v3/8A/wC//wA/+tf/AL37LTf/AI+9/wDv+/8A/wD/AP8Ajz7ae/P/AP317+/w1/6yw5+949680w/8ww4www1//wC/+88P/wDvzDDbTDDH/wA5y9fRffffffdfeeVcddedfbf41+x78Q//APtsvfu//wD/AP8A/wDrjT//AP8A8MMP/wD/AP8A/wDvDHTi6/8A/wD/AP8A+8/yww8344wwwwwwwwwwwwww37/1/wD/AP8A/wD9cvesNcMMsMNMMs/df/8A/wDWec3efffbQ8aVff8AsP8A/dXnL3T/AP20y96//wD/AD3/AA96+896y/8A/f8AzHT3q3/zrDj3rTjDDDLjHCTrDDDn7DDDDDDTDHfvf7T/AP63/wA/P9/8eMM8MMMc8uMNOPN//wD9bX9d393995N9/j//AP8APssMMPuOMNv+NOOMMPe9f/8A7zzD7/3ff/v/AK3qww47/wD/APjDDCCCTvjDDHDDXDDDDDLHDXP/AH//AP8A/wD/APv+ufPNsMc8MMNPsMMe8MMO/wDffLb/AIxY+55/+8a1+6//AOsMP+MMsMNOsMMN9s9P/wD/AKwwx6973/8ALPcJKMMP/uMMe8MMsMMMMMMsMMsMcMMsPdMNv/f/AP8A/wD/AP8A0/8Av8OOMPeMNOcudsMNsMdcOP8AvHrD9dtd71/bDrD3/wDz4x//AM8+MMMMeM8P+/8APPzDTD7/AP36wwwww6xz37w//wC8sIMMMMsNOuMMMMMMcYMMMMcMNNf/AN9D/wD3w4/434w/Xww/www43ww33/w//wCN+MP/AN//AAXf/wD/APfDf/8A43/4/wCMMMN8N8MMP+P8MMMML8MP8MMMMP8A/wD/AP8Afj//AP44www34wwgw4wwwwwwgwww3wwww//EACERAQEAAgMBAQACAwAAAAAAABEAARAgMGBAUCExcJDA/9oACAEDAQE/EP8ASue0I0R7QiI9kREezxiI9kRs9Q9RHaWPVERHN4Y849REbOLwIsYsTGMeZZnqIjRt4kRFjzTZzPSbODPXixjy7ZzO3oI4PWzMzM+SZnb04xYxG3g8WZngzp8KdbM6eZGixiNPc7Znb41mZmeZGixiNPlyODM8GZmZ6iLGI4szt07el3jM/smzgzM7ZmZnsxiLGI06MzpmZ7GeD+Af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');
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px 32px;
            font-size: 14px;
            letter-spacing: -0.15px;
            -webkit-font-smoothing: antialiased;
        }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.12); border-radius: 4px; }

        /* HEADER */
        .dash-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 28px;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
        }
        .header-title-wrap {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-logo-circle {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            background: var(--text-main);
            color: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            font-size: 16px;
        }
        h1 { font-size: 20px; font-weight: 600; color: var(--text-main); }
        .header-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 10px 14px;
            border-radius: 8px;
            font-size: 13.5px;
            font-weight: 500;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s;
        }
        .header-btn:hover { background: var(--bg-hover); color: var(--text-main); }
        .header-btn.primary { background: var(--text-main); color: var(--bg-base); font-weight: 600; border: none; }
        .header-btn.primary:hover { opacity: 0.9; }

        /* STATS GRID */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .stat-card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            color: var(--text-muted);
            font-size: 13px;
            font-weight: 500;
        }
        .stat-card .val {
            font-size: 28px;
            font-weight: 600;
            color: var(--text-main);
            font-feature-settings: 'tnum';
        }
        .stat-card .desc {
            font-size: 12.5px;
            color: var(--text-faint);
        }

        /* TABS */
        .tabs-container {
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            overflow-x: auto;
        }
        .tab-btn {
            background: none;
            border: none;
            color: var(--text-muted);
            padding: 12px 16px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s;
            font-family: inherit;
        }
        .tab-btn:hover { color: var(--text-main); }
        .tab-btn.active { color: var(--text-main); border-bottom-color: var(--text-main); font-weight: 500; }
        .tab-content { display: none; flex-direction: column; gap: 24px; }
        .tab-content.active { display: flex; }

        /* CARDS & TABLES */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }
        .card h2 {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-main);
            margin-bottom: 16px;
        }
        .card-header-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .card-header-bar h2 { margin-bottom: 0; }

        .table-responsive { width: 100%; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; text-align: left; }
        th {
            color: var(--text-muted);
            font-weight: 500;
            font-size: 12.5px;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }
        tr:hover td { background: var(--bg-hover); }

        /* BADGES */
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11.5px;
            font-weight: 600;
            text-transform: capitalize;
        }
        .badge.ok, .badge.running { background: rgba(34, 197, 94, 0.12); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
        .badge.limited, .badge.reconnecting, .badge.starting { background: rgba(234, 179, 8, 0.12); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
        .badge.expired, .badge.error, .badge.stopped { background: rgba(239, 68, 68, 0.12); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }

        .step-pill {
            display: inline-block;
            background: #141414;
            border: 1px solid var(--border);
            color: #38bdf8;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            padding: 4px 8px;
            border-radius: 6px;
            max-width: 280px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        /* FORMS */
        .form-row { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
        input, select, textarea {
            background: var(--bg-base);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 12px 16px;
            border-radius: 8px;
            font-family: inherit;
            font-size: 14px;
            outline: none;
            transition: all 0.2s;
        }
        input:focus, select:focus, textarea:focus {
            border-color: var(--border-hover);
        }
        button.btn {
            background: var(--text-main);
            color: var(--bg-base);
            border: none;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            font-family: inherit;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        button.btn:hover { opacity: 0.9; }
        button.btn-sec { background: var(--bg-card); color: var(--text-main); border: 1px solid var(--border); }
        button.btn-sec:hover { background: var(--bg-hover); }
        button.btn-sm { padding: 6px 12px; font-size: 12.5px; border-radius: 6px; }
        button.btn-red { color: #f87171; border-color: rgba(239, 68, 68, 0.3); }
        button.btn-red:hover { background: rgba(239, 68, 68, 0.1); }

        /* LOG BOX */
        .log-box-container {
            background: #0d0d0d;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            max-height: 420px;
            overflow-y: auto;
            line-height: 1.6;
        }
        .log-line { margin-bottom: 4px; white-space: pre-wrap; word-break: break-all; }
        .log-OK { color: #4ade80; }
        .log-WARN { color: #facc15; }
        .log-ERROR { color: #f87171; }
        .log-INFO { color: #94a3b8; }

        /* TOAST NOTIFICATION */
        .toast-popup {
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #1e1e1e;
            border: 1px solid var(--border);
            color: #fff;
            padding: 12px 18px;
            border-radius: 12px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.7);
            font-size: 13.5px;
            display: none;
            align-items: center;
            gap: 10px;
            z-index: 999;
        }
        .toast-popup.show { display: flex; }

        .refresh-banner {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px 16px;
            border-radius: 10px;
            font-size: 13.5px;
            margin-bottom: 20px;
        }
        .refresh-banner.ok {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.25);
            color: #4ade80;
        }
        .refresh-banner.fail {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            color: #f87171;
        }
    
        /* BRIDGENA-TAILWIND v3.2 */
        .visible{visibility:visible}.collapse{visibility:collapse}.fixed{position:fixed}.absolute{position:absolute}.relative{position:relative}.sticky{position:sticky}.mx-px{margin-left:1px;margin-right:1px}.block{display:block}.flex{display:flex}.inline-flex{display:inline-flex}.table{display:table}.grid{display:grid}.hidden{display:none}.h-1{height:.25rem}.h-1\.5{height:.375rem}.h-3\.5{height:.875rem}.w-0{width:0}.w-1\.5{width:.375rem}.w-16{width:4rem}.w-3\.5{width:.875rem}.w-px{width:1px}.flex-1{flex:1 1 0%}.flex-shrink{flex-shrink:1}.border-collapse{border-collapse:collapse}.transform{transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}@keyframes spin{to{transform:rotate(1turn)}}.animate-spin{animation:spin 1s linear infinite}.cursor-text{cursor:text}.resize{resize:both}.flex-wrap{flex-wrap:wrap}.items-center{align-items:center}.gap-1\.5{gap:.375rem}.gap-2{gap:.5rem}.self-stretch{align-self:stretch}.overflow-hidden{overflow:hidden}.rounded-full{border-radius:9999px}.rounded-lg{border-radius:.5rem}.rounded-md{border-radius:.375rem}.border{border-width:1px}.border-amber-400\/25{border-color:rgba(251,191,36,.25)}.border-emerald-400\/25{border-color:rgba(52,211,153,.25)}.border-rose-400\/25{border-color:rgba(251,113,133,.25)}.border-white\/10{border-color:hsla(0,0%,100%,.1)}.bg-amber-400{--tw-bg-opacity:1;background-color:rgb(251 191 36/var(--tw-bg-opacity,1))}.bg-amber-400\/\[\.06\]{background-color:rgba(251,191,36,.06)}.bg-black\/25{background-color:rgba(0,0,0,.25)}.bg-emerald-400{--tw-bg-opacity:1;background-color:rgb(52 211 153/var(--tw-bg-opacity,1))}.bg-emerald-400\/\[\.06\]{background-color:rgba(52,211,153,.06)}.bg-rose-400{--tw-bg-opacity:1;background-color:rgb(251 113 133/var(--tw-bg-opacity,1))}.bg-rose-400\/15{background-color:rgba(251,113,133,.15)}.bg-rose-400\/\[\.05\]{background-color:rgba(251,113,133,.05)}.bg-rose-400\/\[\.06\]{background-color:rgba(251,113,133,.06)}.bg-slate-500{--tw-bg-opacity:1;background-color:rgb(100 116 139/var(--tw-bg-opacity,1))}.bg-white\/\[\.03\]{background-color:hsla(0,0%,100%,.03)}.bg-white\/\[\.06\]{background-color:hsla(0,0%,100%,.06)}.bg-gradient-to-b{background-image:linear-gradient(to bottom,var(--tw-gradient-stops))}.bg-gradient-to-r{background-image:linear-gradient(to right,var(--tw-gradient-stops))}.from-violet-400{--tw-gradient-from:#a78bfa var(--tw-gradient-from-position);--tw-gradient-to:rgba(167,139,250,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.from-violet-500{--tw-gradient-from:#8b5cf6 var(--tw-gradient-from-position);--tw-gradient-to:rgba(139,92,246,0) var(--tw-gradient-to-position);--tw-gradient-stops:var(--tw-gradient-from),var(--tw-gradient-to)}.to-violet-300{--tw-gradient-to:#c4b5fd var(--tw-gradient-to-position)}.to-violet-600{--tw-gradient-to:#7c3aed var(--tw-gradient-to-position)}.p-\[3px\]{padding:3px}.px-1\.5{padding-left:.375rem;padding-right:.375rem}.px-2{padding-left:.5rem;padding-right:.5rem}.px-2\.5{padding-left:.625rem;padding-right:.625rem}.px-3{padding-left:.75rem;padding-right:.75rem}.px-3\.5{padding-left:.875rem;padding-right:.875rem}.px-\[18px\]{padding-left:18px;padding-right:18px}.py-1{padding-top:.25rem;padding-bottom:.25rem}.py-1\.5{padding-top:.375rem;padding-bottom:.375rem}.py-\[2px\]{padding-top:2px;padding-bottom:2px}.py-\[3px\]{padding-top:3px;padding-bottom:3px}.pb-1{padding-bottom:.25rem}.pt-1\.5{padding-top:.375rem}.pt-3{padding-top:.75rem}.text-center{text-align:center}.text-\[10\.5px\]{font-size:10.5px}.text-\[11\.5px\]{font-size:11.5px}.text-\[12\.5px\]{font-size:12.5px}.text-\[12px\]{font-size:12px}.font-medium{font-weight:500}.font-semibold{font-weight:600}.uppercase{text-transform:uppercase}.capitalize{text-transform:capitalize}.italic{font-style:italic}.tabular-nums{--tw-numeric-spacing:tabular-nums;font-variant-numeric:var(--tw-ordinal) var(--tw-slashed-zero) var(--tw-numeric-figure) var(--tw-numeric-spacing) var(--tw-numeric-fraction)}.tracking-wide{letter-spacing:.025em}.text-amber-300{--tw-text-opacity:1;color:rgb(252 211 77/var(--tw-text-opacity,1))}.text-emerald-300{--tw-text-opacity:1;color:rgb(110 231 183/var(--tw-text-opacity,1))}.text-rose-300{--tw-text-opacity:1;color:rgb(253 164 175/var(--tw-text-opacity,1))}.text-rose-300\/90{color:rgba(253,164,175,.9)}.text-slate-100{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.text-slate-200{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.text-slate-300{--tw-text-opacity:1;color:rgb(203 213 225/var(--tw-text-opacity,1))}.text-slate-300\/80{color:rgba(203,213,225,.8)}.text-slate-400{--tw-text-opacity:1;color:rgb(148 163 184/var(--tw-text-opacity,1))}.text-violet-50{--tw-text-opacity:1;color:rgb(245 243 255/var(--tw-text-opacity,1))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.opacity-90{opacity:.9}.shadow-\[0_8px_20px_-8px_rgba\(124\2c 58\2c 237\2c \.85\)\]{--tw-shadow:0 8px 20px -8px rgba(124,58,237,.85);--tw-shadow-colored:0 8px 20px -8px var(--tw-shadow-color);box-shadow:var(--tw-ring-offset-shadow,0 0 #0000),var(--tw-ring-shadow,0 0 #0000),var(--tw-shadow)}.outline{outline-style:solid}.blur{--tw-blur:blur(8px)}.blur,.filter{filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.backdrop-filter{-webkit-backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia);backdrop-filter:var(--tw-backdrop-blur) var(--tw-backdrop-brightness) var(--tw-backdrop-contrast) var(--tw-backdrop-grayscale) var(--tw-backdrop-hue-rotate) var(--tw-backdrop-invert) var(--tw-backdrop-opacity) var(--tw-backdrop-saturate) var(--tw-backdrop-sepia)}.transition{transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,-webkit-backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter;transition-property:color,background-color,border-color,text-decoration-color,fill,stroke,opacity,box-shadow,transform,filter,backdrop-filter,-webkit-backdrop-filter;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.transition-\[width\]{transition-property:width;transition-timing-function:cubic-bezier(.4,0,.2,1);transition-duration:.15s}.duration-300{transition-duration:.3s}.hover\:border-rose-400\/45:hover{border-color:rgba(251,113,133,.45)}.hover\:border-white\/25:hover{border-color:hsla(0,0%,100%,.25)}.hover\:bg-rose-400\/10:hover{background-color:rgba(251,113,133,.1)}.hover\:bg-white\/\[\.06\]:hover{background-color:hsla(0,0%,100%,.06)}.hover\:bg-white\/\[\.07\]:hover{background-color:hsla(0,0%,100%,.07)}.hover\:text-rose-200:hover{--tw-text-opacity:1;color:rgb(254 205 211/var(--tw-text-opacity,1))}.hover\:text-slate-100:hover{--tw-text-opacity:1;color:rgb(241 245 249/var(--tw-text-opacity,1))}.hover\:text-slate-200:hover{--tw-text-opacity:1;color:rgb(226 232 240/var(--tw-text-opacity,1))}.hover\:text-white:hover{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity,1))}.hover\:brightness-110:hover{--tw-brightness:brightness(1.1);filter:var(--tw-blur) var(--tw-brightness) var(--tw-contrast) var(--tw-grayscale) var(--tw-hue-rotate) var(--tw-invert) var(--tw-saturate) var(--tw-sepia) var(--tw-drop-shadow)}.focus\:border-rose-300\/50:focus{border-color:rgba(253,164,175,.5)}.focus\:outline-none:focus{outline:2px solid transparent;outline-offset:2px}.active\:translate-y-px:active{--tw-translate-y:1px;transform:translate(var(--tw-translate-x),var(--tw-translate-y)) rotate(var(--tw-rotate)) skewX(var(--tw-skew-x)) skewY(var(--tw-skew-y)) scaleX(var(--tw-scale-x)) scaleY(var(--tw-scale-y))}.disabled\:cursor-wait:disabled{cursor:wait}.disabled\:opacity-70:disabled{opacity:.7}@media (min-width:768px){.md\:inline-flex{display:inline-flex}}
        /* BRIDGENA-AMETHYST-THEME v3.2 */
        /* ===== Amethyst layer ===== */
        body { font-family: var(--font-ui); background-color:#151120;
            background-image:
                linear-gradient(180deg, rgba(17,13,26,.84), rgba(17,13,26,.9)),
                var(--hero);
            background-size:cover; background-position:center; background-attachment:fixed; }
        body > * { position:relative; }
        .dash-header { background:rgba(22,17,34,.6); backdrop-filter:blur(12px); border-bottom:1px solid #282043; }
        .header-title-wrap h1, .header-title-wrap .brand-sub { font-family:var(--font-display); letter-spacing:-.5px; }
        .header-logo-circle { border-radius:15px !important; background:linear-gradient(150deg,#c4b5fd,#7c3aed) !important;
            color:#171126 !important; box-shadow:0 7px 20px -8px rgba(124,58,237,.6); }
        .header-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
        .header-btn { display:inline-flex; align-items:center; gap:7px; background:#1f1929; border:1px solid #322848;
            border-radius:10px; color:var(--text-main); }
        .header-btn:hover { border-color:#a78bfa; }
        .header-btn.primary { background:linear-gradient(180deg,#a78bfa,#7c3aed) !important; color:#f7f4ff !important;
            border:0; font-weight:600; box-shadow:0 6px 16px -8px rgba(124,58,237,.55); }
        .tabs-container { background:#171226; border:1px solid #2c2347; border-radius:13px; padding:4px; }
        .tab-btn { border-radius:9px; color:var(--text-muted); font-weight:500; }
        .tab-btn:hover { color:var(--text-main); }
        .tab-btn.active { background:#281f47; color:var(--text-main); box-shadow:0 1px 4px rgba(0,0,0,.4); }
        .stat-card { background:rgba(31,25,41,.82); border:1px solid #322848; border-radius:17px;
            box-shadow:0 1px 2px rgba(0,0,0,.3); transition:transform .15s, box-shadow .15s, border-color .15s; }
        .stat-card:hover { transform:translateY(-1px); border-color:#453a63; box-shadow:0 12px 30px -16px rgba(0,0,0,.6); }
        .stat-card .val { font-family:var(--font-display); font-weight:500; letter-spacing:-.6px; color:var(--text-main); }
        .stat-card .desc, .stat-card-header { color:var(--text-muted); }
        .card { background:rgba(30,24,42,.84); border:1px solid #322848; border-radius:17px;
            box-shadow:0 1px 2px rgba(0,0,0,.3); }
        .card-header-bar { border-bottom:1px solid #2c2347; }
        .card-header-bar h3, .card-header-bar h2 { font-family:var(--font-display); font-weight:500; letter-spacing:-.3px; }
        .badge.ok { color:#9ce2a2; background:rgba(143,211,154,.1); box-shadow:inset 0 0 0 1px rgba(143,211,154,.3); }
        .badge.limited { color:#e5c377; background:rgba(227,196,111,.12); box-shadow:inset 0 0 0 1px rgba(227,196,111,.32); }
        .badge.expired { color:#f0a48f; background:rgba(239,143,125,.1); box-shadow:inset 0 0 0 1px rgba(239,143,125,.28); }
        .badge.uncheckedb { color:var(--text-faint); background:rgba(255,255,255,.04);
            box-shadow:inset 0 0 0 1px var(--border); }
        .step-pill { background:rgba(24,19,36,.8); border:1px solid #2c2347; border-radius:8px; color:var(--text-muted); }
        select, input[type=text], input[type=password], input[type=number], textarea {
            background:rgba(22,17,33,.85); border:1px solid #322848; border-radius:10px; color:var(--text-main); }
        select:focus, input:focus, textarea:focus { border-color:#a78bfa; box-shadow:0 0 0 3px rgba(167,139,250,.13); outline:none; }
        table { width:100%; border-collapse:collapse; }
        th { text-align:left; font-size:11px; letter-spacing:.08em; text-transform:uppercase; color:var(--text-muted);
            padding:10px 12px; border-bottom:1px solid #322848; }
        td { padding:11px 12px; border-bottom:1px solid #282043; color:var(--text-main); }
        tbody tr:hover { background:rgba(167,139,250,.05); }
        #pxSlowMs { background:#191427; border:1px solid #322848; border-radius:8px; color:var(--text-main); }
        #pxPaste { background:rgba(22,17,33,.85); border:1px solid #322848; border-radius:12px; padding:12px 14px;
            color:var(--text-main); line-height:1.55; }
        #pxPaste:focus { border-color:#a78bfa; box-shadow:0 0 0 3px rgba(167,139,250,.13); outline:none; }
        #pxProgBar { background:linear-gradient(90deg,#7c3aed,#c4b5fd) !important; }
        #pxRows .btn { padding:4px 10px !important; font-size:12px !important; border-radius:8px !important; }
        #pxRows code { max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
            display:inline-block; vertical-align:middle; }
        .log-box-container { background:rgba(13,9,20,.88); border:1px solid #2a2240; border-radius:14px; }
        .log-line { color:#d5cee6; }
        .log-OK .level, .log-INFO .level { color:#9ccf9a; }
        .log-WARN .level { color:#e3b968; }
        .log-ERROR .level { color:#ef8f7d; }
        .refresh-banner.ok { color:#9ce2a2; background:rgba(143,211,154,.08); border:1px solid rgba(143,211,154,.24); border-radius:12px; }
        .refresh-banner.fail { color:#f0a48f; background:rgba(239,143,125,.08); border:1px solid rgba(239,143,125,.24); border-radius:12px; }

        /* button system: violet gradient ONLY for real primaries; ghost for secondaries */
        .btn:not(.btn-sec):not(.btn-red) {
            background:linear-gradient(180deg,#a78bfa,#7c3aed) !important;
            color:#f7f4ff !important; border:0 !important; font-weight:600;
            box-shadow:0 4px 14px -6px rgba(124,58,237,.5); }
        .btn:not(.btn-sec):not(.btn-red):hover { filter:brightness(1.09); }
        .btn-sec, .btn.btn-sec { background:#241d36 !important; color:var(--text-main) !important;
            border:1px solid #3b3060 !important; box-shadow:none !important; font-weight:500 !important;
            transition:border-color .15s, background .15s; }
        .btn-sec:hover, .btn.btn-sec:hover { border-color:#8b78cf !important; background:#2c2346 !important; }
        .btn-sec.btn-red, .btn-red { background:transparent !important; color:var(--red) !important;
            border-color:rgba(239,143,125,.22) !important; box-shadow:none !important; font-weight:500 !important; }
        .btn-sec.btn-red:hover { background:rgba(239,143,125,.09) !important; color:#f0a48f !important;
            border-color:rgba(239,143,125,.4) !important; }

        #btToastWrap { position:fixed; right:22px; bottom:22px; z-index:999; display:flex;
            flex-direction:column; gap:10px; align-items:flex-end; pointer-events:none; }
        .bt-toast { pointer-events:auto; display:flex; align-items:flex-start; gap:10px; max-width:380px;
            padding:12px 15px; background:#241d36; border:1px solid #372c55; border-left:3px solid #8f86b4;
            border-radius:13px; box-shadow:0 16px 44px -18px rgba(0,0,0,.8); color:#ece8f6;
            font-size:13px; line-height:1.45; opacity:0; transform:translateX(16px);
            transition:opacity .22s ease, transform .22s ease; cursor:pointer; font-family:var(--font-ui); }
        .bt-toast.show { opacity:1; transform:none; }
        .bt-toast.err  { border-left-color:#ef8f7d; }
        .bt-toast.err .bt-ico { color:#ef8f7d; }
        .bt-toast.ok   { border-left-color:#8fd39a; }
        .bt-toast.ok .bt-ico { color:#8fd39a; }
        .bt-toast.warn { border-left-color:#e3c46f; }
        .bt-toast.warn .bt-ico { color:#e3c46f; }
        .bt-toast.info  { border-left-color:#a78bfa; }
        .bt-toast.info .bt-ico { color:#a78bfa; }
        .bt-toast .bt-ico { font-size:13px; line-height:1.3; }
        .bt-toast .bt-msg { word-break:break-word; }

        ::selection { background:rgba(167,139,250,.28); }
        ::-webkit-scrollbar { width:10px; height:10px; }
        ::-webkit-scrollbar-track { background:transparent; }
        ::-webkit-scrollbar-thumb { background:#3a2f5c; border-radius:99px; border:3px solid transparent;
            background-clip:content-box; }
        ::-webkit-scrollbar-thumb:hover { background:#4c4077; border:3px solid transparent; background-clip:content-box; }

        </style>
</head>
<body>

    __REFRESH_BANNER__

    <!-- TOP HEADER -->
    <div class="dash-header">
        <div class="header-title-wrap">
            <div class="header-logo-circle">B</div>
            <div>
                <h1>Bridgena Control Center</h1>
                <div style="color:var(--text-muted);font-size:12.5px">Arena.ai Session & Account Management</div>
            </div>
        </div>
        <div class="header-actions">
            <a href="/chat" class="header-btn primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                <span>Launch Workspace</span>
            </a>
            <a href="/logout" class="header-btn">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                <span>Sign out</span>
            </a>
        </div>
    </div>

    <!-- STATS METRICS -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-card-header">
                <span>Healthy Accounts</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
            </div>
            <div class="val">__HEALTHY_JARS__ / __TOTAL_JARS__</div>
            <div class="desc">Active in pool</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-header">
                <span>Active Keepers</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            </div>
            <div class="val" id="statKeepers">__ACTIVE_KEEPERS__</div>
            <div class="desc">Browser sessions running</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-header">
                <span>Loaded Models</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
            </div>
            <div class="val">__TOTAL_MODELS__</div>
            <div class="desc">Selectable model catalog</div>
        </div>
        <div class="stat-card">
            <div class="stat-card-header">
                <span>API Keys</span>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            </div>
            <div class="val">__TOTAL_KEYS__</div>
            <div class="desc">Active gateway keys</div>
        </div>
    </div>

    <!-- TABS -->
    <div class="tabs-container">
        <button class="tab-btn active" onclick="switchTab('accounts', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
            <span>Accounts & Keepers</span>
        </button>
        <button class="tab-btn" onclick="switchTab('import', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
            <span>Import Accounts</span>
        </button>
        <button class="tab-btn" onclick="switchTab('keys', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            <span>API Keys</span>
        </button>
        <button class="tab-btn" onclick="switchTab('models', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"></polygon><polyline points="2 17 12 22 22 17"></polyline><polyline points="2 12 12 17 22 12"></polyline></svg>
            <span>Model Catalog</span>
        </button>
        <button class="tab-btn" onclick="switchTab('oxalpha', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            <span>OX Alpha Bridge</span>
        </button>
        <button class="tab-btn" onclick="switchTab('proxies', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
            <span>Proxy Pool</span>
        </button>
        <button class="tab-btn" onclick="switchTab('logs', this)">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
            <span>Live Logs</span>
        </button>
    </div>

    <!-- TAB 1: ACCOUNTS -->
    <div id="tab-accounts" class="tab-content active">
        <div class="card">
            <div class="card-header-bar">
                <h2>Account Pool & Session Keepers</h2>
                <div style="font-size:12.5px;color:var(--text-muted)">Live step updates enabled</div>
            </div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Account</th>
                            <th>Health</th>
                            <th>Keeper State & Progress</th>
                            <th>Requests</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="jarsTableBody">__JARS_ROWS__</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 2: IMPORT -->
    <div id="tab-import" class="tab-content">
        <div class="card">
            <h2>Bulk Import Accounts (Email:Password)</h2>
            <p style="color:var(--text-muted);font-size:13px;margin-bottom:14px">Paste email:password lines below. Session keeper will automatically log in using native stealth browser automation.</p>
            <form action="/jars/bulk" method="post">
                <div class="form-row">
                    <textarea name="accounts" rows="4" placeholder="user1@example.com:password123&#10;user2@example.com:password456" style="width:100%" required></textarea>
                </div>
                <div class="form-row" style="align-items:center">
                    <label style="font-size:13px;color:var(--text-muted);display:flex;align-items:center;gap:6px">
                        <input type="checkbox" name="keeper_enabled" value="1" checked> Enable Keep-Alive & Auto-Login
                    </label>
                    <div style="flex:1"></div>
                    <button type="submit" class="btn">Import Accounts</button>
                </div>
            </form>
        </div>
        <div class="card">
            <h2>Add Arena Account via Cookie File</h2>
            <form action="/jars/add" method="post" enctype="multipart/form-data">
                <div class="form-row">
                    <input type="text" name="name" placeholder="Account Label" style="flex:1">
                    <input type="file" name="cookie_file" required style="flex:1">
                    <button type="submit" class="btn">Upload Cookies (JSON / Netscape)</button>
                </div>
            </form>
        </div>
    </div>

    <!-- TAB 3: API KEYS -->
    <div id="tab-keys" class="tab-content">
        <div class="card">
            <h2>Create New API Key</h2>
            <form action="/create-key" method="post">
                <div class="form-row">
                    <input type="text" name="name" placeholder="Key Label (e.g. Production App)" required style="flex:1">
                    <input type="number" name="rpm" placeholder="Rate Limit (RPM)" value="60" required style="width:160px">
                    <button type="submit" class="btn">Generate Key</button>
                </div>
            </form>
        </div>
        <div class="card">
            <h2>Active API Keys</h2>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Label</th>
                            <th>API Key</th>
                            <th>RPM Limit</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>__KEYS_ROWS__</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 4: MODELS -->
    <div id="tab-models" class="tab-content">
        <div class="card">
            <div class="card-header-bar">
                <h2>Selectable Model Catalog</h2>
                <form action="/refresh-tokens" method="post">
                    <button type="submit" class="btn btn-sm">Refresh Catalog</button>
                </form>
            </div>
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Public Model ID</th>
                            <th>Provider / Org</th>
                            <th>Vision Support</th>
                        </tr>
                    </thead>
                    <tbody>__MODELS_ROWS__</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TAB 5: OX ALPHA -->
    <div id="tab-oxalpha" class="tab-content">
        <div class="card">
            <h2>OX Alpha Secondary Inference Bridge</h2>
            <p style="font-size:13.5px;color:var(--text-muted);margin-bottom:16px">Secondary low-latency route for <code>z-ai/glm-5.3-flash</code> and <code>ox-alpha</code> models.</p>
            <div class="form-row">
                <form action="/oxalpha/verify" method="post">
                    <button type="submit" class="btn">Verify via Browser</button>
                </form>
                <form action="/oxalpha/refresh" method="post">
                    <button type="submit" class="btn btn-sec">Force Token Refresh</button>
                </form>
            </div>
            <form action="/oxalpha/upload" method="post" enctype="multipart/form-data" style="margin-top:16px">
                <div class="form-row">
                    <input type="file" name="cookie_file" required style="flex:1">
                    <button type="submit" class="btn">Upload OX Alpha Cookies</button>
                </div>
            </form>
        </div>
    </div>

    <!-- TAB 6: LIVE LOGS -->
    <div id="tab-proxies" class="tab-content">
        <div class="card">
            <div class="card-header-bar">
                <h3>Proxy Pool</h3>
                <div class="flex flex-wrap items-center gap-2">
                    <button id="pxCheckBtn" onclick="pxCheck()" title="Handshake + live arena.ai fetch for every row"
                        class="inline-flex items-center gap-2 rounded-lg bg-gradient-to-b from-violet-400 to-violet-600 px-3.5 py-1.5 text-[12.5px] font-semibold text-violet-50 shadow-[0_8px_20px_-8px_rgba(124,58,237,.85)] transition hover:brightness-110 active:translate-y-px disabled:cursor-wait disabled:opacity-70">
                        <svg id="pxScanIco" class="h-3.5 w-3.5 opacity-90" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg>
                        <span id="pxScanTxt">Scan pool</span></button>
                    <span class="hidden md:inline-flex items-center rounded-full border border-white/10 bg-white/[.03] px-2.5 py-[3px] text-[10.5px] tracking-wide text-slate-400">tunnel + arena.ai verdict, not just ping</span>
                    <span class="flex-1"></span>
                    <div class="inline-flex items-center rounded-lg border border-rose-400/25 bg-rose-400/[.05] p-[3px] transition hover:border-rose-400/45">
                        <button onclick="pxPrune('bad')" title="Cut every row that cannot load arena.ai right now (dead + Arena-blocked)"
                            class="rounded-md px-2.5 py-1 text-[12px] font-medium text-rose-300/90 transition hover:bg-rose-400/10 hover:text-rose-200">Delete not working</button>
                        <span class="mx-px w-px self-stretch bg-rose-400/15"></span>
                        <label class="flex cursor-text items-center gap-1.5 px-1.5 text-[11.5px] text-slate-400">slower than
                            <input id="pxSlowMs" type="number" value="1000" min="100" step="100"
                                class="w-16 rounded-md border border-white/10 bg-black/25 px-1.5 py-[2px] text-center text-[11.5px] tabular-nums text-slate-200 transition focus:border-rose-300/50 focus:outline-none"> ms</label>
                        <button onclick="pxPrune('slow')" title="Delete rows over the threshold"
                            class="rounded-md px-2 py-1 text-[11.5px] text-slate-400 transition hover:bg-white/[.06] hover:text-slate-200">delete</button>
                        <span class="mx-px w-px self-stretch bg-rose-400/15"></span>
                        <button onclick="pxPrune('unchecked')" title="Delete rows never scanned"
                            class="rounded-md px-2.5 py-1 text-[12px] text-slate-300/80 transition hover:bg-white/[.06] hover:text-slate-100">Delete unchecked</button>
                    </div>
                    <button onclick="pxRevive()" title="Move everything from proxies.dead.txt back into the pool"
                        class="rounded-lg border border-white/10 bg-white/[.03] px-3 py-1.5 text-[12px] text-slate-300 transition hover:border-white/25 hover:bg-white/[.07] hover:text-white">Revive graveyard</button>
                </div>
            </div>
            <div id="pxProgWrap" style="display:none" class="px-[18px] pt-3">
                <div class="h-1 overflow-hidden rounded-full bg-white/[.06]">
                    <div id="pxProgBar" class="h-1 w-0 rounded-full bg-gradient-to-r from-violet-500 to-violet-300 transition-[width] duration-300"></div>
                </div>
                <div id="pxProgTxt" class="pt-1.5 text-[11.5px] text-slate-400">checking…</div>
            </div>
            <div id="pxSummary" class="flex flex-wrap items-center gap-1.5 px-[18px] pb-1 pt-3 text-[12px] text-slate-400">Loading…</div>
            <div style="max-height:420px;overflow:auto">
                <table>
                    <thead><tr><th>Proxy</th><th>Scheme</th><th>Verdict</th><th>Latency</th><th>Checked</th><th></th></tr></thead>
                    <tbody id="pxRows"></tbody>
                </table>
            </div>
        </div>
        <div class="card">
            <div class="card-header-bar"><h3>Add proxies</h3><span style="font-size:12px;color:var(--text-muted)">free-list CSV, ip:port, user:pass@ip:port, socks5://… — mixed is fine</span></div>
            <div style="padding:14px 18px 18px;display:flex;flex-direction:column;gap:12px">
                <textarea id="pxPaste" rows="6" placeholder="98.188.47.150,4145,United States,SOCKS4,Anonymous,259,Unknown&#10;12.34.56.78:8080&#10;user:pass@gw.provider.io:999" style="width:100%;resize:vertical;font-family:'JetBrains Mono',monospace;font-size:12.5px"></textarea>
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <label class="btn-sec btn" style="cursor:pointer">Upload .csv / .txt<input type="file" id="pxFile" accept=".txt,.csv,text/plain,text/csv" style="display:none"></label>
                    <span id="pxFileName" style="font-size:12px;color:var(--text-muted)">no file chosen</span>
                    <button class="btn" onclick="pxAdd()">Add to pool</button>
                    <span id="pxAddResult" style="font-size:12px;color:var(--text-muted)"></span>
                </div>
            </div>
        </div>
    </div>
    <div id="tab-logs" class="tab-content">
        <div class="card">
            <div class="card-header-bar">
                <h2>Live Debug Logs</h2>
                <div style="display:flex;gap:8px">
                    <button class="btn btn-sec btn-sm" onclick="copyAllLogs()">Copy Logs</button>
                    <form action="/clear-logs" method="post">
                        <button type="submit" class="btn btn-sec btn-sm">Clear Logs</button>
                    </form>
                </div>
            </div>
            <div class="log-box-container" id="logBox"></div>
        </div>
    </div>

    <!-- TOASTS -->
    <div id="btToastWrap"></div>

    <script>
        function showToast(msg, kind) {
            let w = document.getElementById('btToastWrap');
            if (!w) { w = document.createElement('div'); w.id = 'btToastWrap'; document.body.appendChild(w); }
            const el = document.createElement('div');
            el.className = 'bt-toast ' + (kind || 'info');
            el.innerHTML = '<span class="bt-ico"></span><span class="bt-msg"></span>';
            el.querySelector('.bt-ico').textContent = kind === 'err' ? '⚠' : (kind === 'ok' ? '✓' : 'ℹ');
            el.querySelector('.bt-msg').textContent = msg;
            el.onclick = () => el.remove();
            w.appendChild(el);
            while (w.children.length > 4) w.removeChild(w.firstChild);
            requestAnimationFrame(() => el.classList.add('show'));
            setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 320); },
                       kind === 'err' ? 8000 : 3800);
        }
        window.addEventListener('unhandledrejection', e => {
            const m = (e && e.reason && (e.reason.message || e.reason)) || 'unknown';
            showToast('UI error: ' + String(m).slice(0, 180), 'err');
        });
        function copyKey(keyStr) {
            navigator.clipboard.writeText(keyStr);
            showToast('API Key copied to clipboard');
        }
        function copyAllLogs() {
            const txt = document.getElementById('logBox').innerText;
            navigator.clipboard.writeText(txt);
            showToast('Logs copied to clipboard');
        }
        function switchTab(name, btn) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            if (btn) btn.classList.add('active');
            document.getElementById('tab-' + name).classList.add('active');
            if (name === 'proxies') pxRefresh();
        }

        // ===== Proxy Pool tab =====
        let _pxPoll = null;
        function pxEsc(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
        async function pxRefresh() {
            try {
                const r = await fetch('/proxies/api/snapshot');
                if (!r.ok) throw new Error('HTTP ' + r.status);
                pxRender(await r.json());
            } catch (e) {
                const el = document.getElementById('pxSummary');
                if (el) el.textContent = 'Proxy data unavailable: ' + e.message;
            }
        }
        function pxRender(d) {
            const sum = document.getElementById('pxSummary');
            const unk = (d.rows || []).filter(r => r.status === 'unchecked').length + Math.max(0, (d.total || 0) - (d.rows || 0).length);
            if (sum) {
                const chip = (dot, txt, cls) => '<span class="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-[2px] text-[11.5px] ' + cls + '">' + (dot ? '<i class="h-1.5 w-1.5 rounded-full ' + dot + '"></i>' : '') + txt + '</span>';
                sum.innerHTML = chip('', '<b class="font-semibold text-slate-100">' + d.total + '</b> in pool', 'border-white/10 bg-white/[.03]')
                    + chip('bg-emerald-400', d.live + ' usable', 'border-emerald-400/25 bg-emerald-400/[.06] text-emerald-300')
                    + (d.blocked ? chip('bg-amber-400', d.blocked + ' Arena-blocked', 'border-amber-400/25 bg-amber-400/[.06] text-amber-300') : '')
                    + (d.dead ? chip('bg-rose-400', d.dead + ' dead', 'border-rose-400/25 bg-rose-400/[.06] text-rose-300') : '')
                    + (unk ? chip('bg-slate-500', unk + ' unchecked', 'border-white/10 bg-white/[.03] text-slate-400') : '')
                    + chip('', 'median ' + (d.median_ms != null ? '<b class="tabular-nums text-slate-200">' + d.median_ms + ' ms</b>' : '—'), 'border-white/10 bg-white/[.03]')
                    + (d.quarantined ? chip('', d.quarantined + ' in graveyard', 'border-white/10 bg-white/[.03] text-slate-400') : '');
            }
            const wrap = document.getElementById('pxProgWrap');
            const btn = document.getElementById('pxCheckBtn'), ico = document.getElementById('pxScanIco'), lbl = document.getElementById('pxScanTxt');
            if (d.checking) {
                wrap.style.display = 'block';
                const p = d.progress && d.progress.total ? Math.round(100 * d.progress.done / d.progress.total) : 0;
                document.getElementById('pxProgBar').style.width = p + '%';
                document.getElementById('pxProgTxt').textContent = 'checking ' + (d.progress ? d.progress.done : 0) + '/' + (d.progress ? d.progress.total : '?') + ' — tunnel handshake, then a live arena.ai fetch through the same exit';
                if (ico) ico.classList.add('animate-spin');
                if (btn) btn.disabled = true;
                if (lbl) lbl.textContent = 'Scanning…';
                if (!_pxPoll) _pxPoll = setInterval(pxRefresh, 1200);
            } else {
                wrap.style.display = 'none';
                if (ico) ico.classList.remove('animate-spin');
                if (btn) btn.disabled = false;
                if (lbl) lbl.textContent = 'Scan pool';
                if (_pxPoll) { clearInterval(_pxPoll); _pxPoll = null; }
            }
            const tb = document.getElementById('pxRows');
            tb.innerHTML = (d.rows || []).map(function (row) {
                const badge = row.status === 'live' ? 'ok' : (row.status === 'dead' ? 'expired' : (row.status === 'blocked' ? 'limited' : 'uncheckedb'));
                const lat = (typeof row.latency === 'number' && row.latency >= 0) ? row.latency + ' ms' : '—';
                const verdict = row.status === 'live' ? 'usable' : row.status + (row.note ? ' — ' + row.note : '');
                return '<tr><td><code style="background:rgba(255,255,255,.07);padding:3px 8px;border-radius:6px;font-family:monospace;font-size:12px">' + pxEsc(row.url) + '</code></td><td>' + pxEsc(row.scheme) + '</td><td><span class="badge ' + badge + '">' + pxEsc(verdict) + '</span></td><td>' + lat + '</td><td style="color:var(--text-muted)">' + pxEsc(row.checked || '—') + '</td><td><button class="btn-sec btn btn-sm btn-red" onclick="pxRemove(&quot;' + pxEsc(row.host) + '&quot;)">Remove</button></td></tr>';
            }).join('') || '<tr><td colspan="6" style="padding:20px;color:var(--text-muted)">Pool is empty — paste or upload a list below.</td></tr>';
        }
        async function pxPost(path, body) {
            const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) });
            const j = await r.json().catch(function () { return {}; });
            if (!r.ok) throw new Error(j.detail || ('HTTP ' + r.status));
            return j;
        }
        async function pxCheck() {
            try {
                const j = await pxPost('/proxies/api/check');
                showToast(j.started ? 'Proxy sweep started' : 'Sweep already running', j.started ? 'info' : 'warn');
                if (!_pxPoll) _pxPoll = setInterval(pxRefresh, 1200);
                pxRefresh();
            } catch (e) { showToast('Check failed: ' + e.message, 'err'); }
        }
        async function pxPrune(mode) {
            try {
                const body = { mode: mode };
                if (mode === 'slow') body.slow_ms = parseInt(document.getElementById('pxSlowMs').value || '1000', 10);
                const j = await pxPost('/proxies/api/prune', body);
                showToast(j.removed ? 'Pruned ' + j.removed + ' ' + mode + ' proxies (' + j.total + ' left)' : 'Nothing matched "' + mode + '"', j.removed ? 'ok' : 'warn');
                pxRefresh();
            } catch (e) { showToast('Prune failed: ' + e.message, 'err'); }
        }
        async function pxRemove(host) {
            try {
                await pxPost('/proxies/api/remove-one', { host: host });
                showToast('Removed ' + host + ' (graveyard has it if you regret it)', 'ok');
                pxRefresh();
            } catch (e) { showToast('Remove failed: ' + e.message, 'err'); }
        }
        async function pxRevive() {
            try {
                const j = await pxPost('/proxies/api/revive');
                showToast(j.revived ? 'Revived ' + j.revived + ' proxies from graveyard' : 'Graveyard is empty', j.revived ? 'ok' : 'warn');
                pxRefresh();
            } catch (e) { showToast('Revive failed: ' + e.message, 'err'); }
        }
        async function pxAdd() {
            const ta = document.getElementById('pxPaste');
            const res = document.getElementById('pxAddResult');
            let text = ta.value || '';
            const f = document.getElementById('pxFile').files[0];
            if (f) {
                try { text += '\n' + (await f.text()); } catch (e) { showToast('File read failed: ' + e.message, 'err'); return; }
            }
            if (!text.trim()) { showToast('Nothing to add — paste lines or pick a file', 'warn'); return; }
            try {
                const j = await pxPost('/proxies/api/upload', { text: text });
                showToast('+' + j.added + ' proxies added (' + (j.skipped_dupes_or_bad || 0) + ' dupes/skipped) — pool: ' + j.total, j.added ? 'ok' : 'warn');
                if (res) res.textContent = 'pool now ' + j.total;
                ta.value = ''; document.getElementById('pxFile').value = '';
                document.getElementById('pxFileName').textContent = 'no file chosen';
                pxRefresh();
            } catch (e) { showToast('Add failed: ' + e.message, 'err'); }
        }
        document.getElementById('pxFile').addEventListener('change', function (ev) {
            const f = ev.target.files[0];
            document.getElementById('pxFileName').textContent = f ? (f.name + ' (' + Math.max(1, Math.round(f.size / 1024)) + ' KB)') : 'no file chosen';
        });

        async function triggerRelogin(jarId) {
            showToast('Re-login triggered. Polling real-time steps...');
            try {
                const formData = new FormData();
                formData.append('jar_id', jarId);
                const r = await fetch('/keeper/relogin', { method: 'POST', body: formData, credentials: 'include' });
                const d = await r.json();
                if (d.error) {
                    showToast('Relogin error: ' + d.error);
                } else {
                    showToast(d.message || 'Re-login command sent');
                }
                fetchStatus();
            } catch(e) {
                showToast('Failed to trigger relogin: ' + e.message);
            }
        }

        async function fetchLogs() {
            try {
                const r = await fetch('/debug-logs/data');
                const d = await r.json();
                const box = document.getElementById('logBox');
                box.innerHTML = (d.logs || []).map(l => '<div class="log-line log-' + l.level + '">[' + l.time + '] [' + l.level + '] ' + l.message + '</div>').join('');
                box.scrollTop = box.scrollHeight;
            } catch(e) {}
        }

        async function fetchStatus() {
            try {
                const r = await fetch('/keeper/status');
                const d = await r.json();
                window._statusErr = 0;
                if (d.sessions) {
                    if (!window._lastSt) window._lastSt = {};
                    for (const t of d.sessions) {
                        const prev = window._lastSt[t.jar_id];
                        window._lastSt[t.jar_id] = t.status;
                        if (prev && prev !== t.status) {
                            const nm = t.name || t.jar_id;
                            if (t.status === 'error')
                                showToast(nm + ': keeper failed — ' + String(t.error || t.current_step || 'see logs').slice(0, 220), 'err');
                            else if (t.status === 'running')
                                showToast(nm + ': keeper online', 'ok');
                            else if (t.status === 'stopped' && prev === 'running')
                                showToast(nm + ': keeper stopped', 'warn');
                        }
                    }
                    const running = d.sessions.filter(s => s.status === 'running').length;
                    document.getElementById('statKeepers').textContent = running;
                    for (const s of d.sessions) {
                        const stepEl = document.getElementById('step-val-' + s.jar_id);
                        if (stepEl && s.current_step) {
                            stepEl.textContent = s.current_step;
                        }
                        const badgeEl = document.getElementById('status-badge-' + s.jar_id);
                        if (badgeEl) {
                            badgeEl.className = 'badge ' + s.status;
                            badgeEl.textContent = s.status;
                        }
                    }
                }
            } catch(e) {
                if (!window._statusErr) {
                    window._statusErr = 1;
                    showToast('Dashboard lost contact with Bridgena (status poll failed)', 'err');
                }
            }
        }

        setInterval(fetchLogs, 4000);
        setInterval(fetchStatus, 1200);
        fetchLogs();
        fetchStatus();
    </script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, refresh: Optional[str] = None, refresh_msg: Optional[str] = None):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")

    banner_html = ""
    if refresh in ("ok", "fail") and refresh_msg:
        safe_msg = html.escape(refresh_msg)
        icon = "✓" if refresh == "ok" else "⚠"
        banner_html = f'<div class="refresh-banner {refresh}">{icon} Catalog refresh: {safe_msg}</div>'

    jars = load_jars()
    now = time.time()
    healthy_jars = sum(1 for j in jars if jar_available(j, now))
    active_keepers = sum(1 for s in keeper.sessions.values() if s.running)

    jars_rows = []
    for j in jars:
        st = "ok" if jar_available(j, now) else ("limited" if j.get("limited_until", 0) > now else "expired")
        ks = keeper.sessions.get(j.get("id"))
        keeper_status = '<span class="badge stopped">Disabled</span>'
        step_text = ""
        if j.get("keeper_enabled"):
            if ks:
                keeper_status = f'<span class="badge {ks.status}" id="status-badge-{j["id"]}">{ks.status}</span>'
                step_text = ks.current_step or (ks.error if ks.error else "")
            else:
                keeper_status = f'<span class="badge stopped" id="status-badge-{j["id"]}">Pending</span>'

        step_html = f'<div class="step-pill" id="step-val-{j["id"]}" title="{step_text}">{step_text or "Idle"}</div>' if step_text else f'<div class="step-pill" id="step-val-{j["id"]}">Ready</div>'

        jars_rows.append(f"""
        <tr>
            <td>
                <strong>{j.get('name', 'Account')}</strong>
                <br><small style="color:var(--text-muted)">{j.get('email') or 'No email'}</small>
            </td>
            <td><span class="badge {st}">{st}</span></td>
            <td>
                <div style="display:flex;flex-direction:column;gap:4px">
                    <div>{keeper_status}</div>
                    {step_html}
                </div>
            </td>
            <td><strong>{j.get('usage_count', 0)}</strong> reqs</td>
            <td>
                <div style="display:flex;gap:6px;flex-wrap:wrap">
                    <button type="button" class="btn btn-sm" onclick="triggerRelogin('{j['id']}')">Re-login</button>
                    <form action="/keeper/live" method="post"><input type="hidden" name="jar_id" value="{j['id']}"><button type="submit" class="btn btn-sec btn-sm">Live Browser</button></form>
                    <form action="/jars/reset" method="post"><input type="hidden" name="jar_id" value="{j['id']}"><button type="submit" class="btn btn-sec btn-sm">Reset</button></form>
                    <form action="/jars/toggle" method="post"><input type="hidden" name="jar_id" value="{j['id']}"><button type="submit" class="btn btn-sec btn-sm">{'Disable' if j.get('enabled', True) else 'Enable'}</button></form>
                    <form action="/jars/delete" method="post"><input type="hidden" name="jar_id" value="{j['id']}"><button type="submit" class="btn btn-sec btn-sm btn-red">Delete</button></form>
                </div>
            </td>
        </tr>""")

    cfg = get_config()
    keys = cfg.get("api_keys", [])
    keys_rows = []
    for k in keys:
        keys_rows.append(f"""
        <tr>
            <td><strong>{k.get('name')}</strong></td>
            <td><code style="background:rgba(255,255,255,0.07);padding:3px 8px;border-radius:6px;font-family:'JetBrains Mono',monospace;cursor:pointer" onclick="copyKey('{k.get('key')}')" title="Click to copy">{k.get('key')}</code></td>
            <td><span class="badge ok">{k.get('rpm')} RPM</span></td>
            <td><form action="/delete-key" method="post"><input type="hidden" name="key_id" value="{k['key']}"><button type="submit" class="btn btn-sec btn-sm btn-red">Revoke</button></form></td>
        </tr>""")

    models = get_selectable_models()
    models_rows = []
    for m in models:
        has_vision = '<span class="badge ok">Yes</span>' if m.get("capabilities", {}).get("inputCapabilities", {}).get("image") else '<span class="badge stopped">No</span>'
        models_rows.append(f"""
        <tr>
            <td><strong>{m.get('publicName')}</strong></td>
            <td><span style="color:var(--text-muted)">{m.get('organization')}</span></td>
            <td>{has_vision}</td>
        </tr>""")

    html_out = (
        DASHBOARD_TEMPLATE
        .replace("__REFRESH_BANNER__", banner_html)
        .replace("__HEALTHY_JARS__", str(healthy_jars))
        .replace("__TOTAL_JARS__", str(len(jars)))
        .replace("__ACTIVE_KEEPERS__", str(active_keepers))
        .replace("__TOTAL_MODELS__", str(len(models)))
        .replace("__TOTAL_KEYS__", str(len(keys)))
        .replace("__JARS_ROWS__", "".join(jars_rows) if jars_rows else "<tr><td colspan='5' style='text-align:center;color:var(--text-muted);padding:24px'>No accounts in pool</td></tr>")
        .replace("__KEYS_ROWS__", "".join(keys_rows) if keys_rows else "<tr><td colspan='4' style='text-align:center;color:var(--text-muted);padding:24px'>No API keys created</td></tr>")
        .replace("__MODELS_ROWS__", "".join(models_rows) if models_rows else "<tr><td colspan='3' style='text-align:center;color:var(--text-muted);padding:24px'>No models loaded</td></tr>")
    )
    return HTMLResponse(html_out)


# ============================================================
# API KEY & JAR POOL ACTIONS
# ============================================================

@app.post("/jars/add")
async def jars_add(request: Request, name: str = Form(""), cookie_file: UploadFile = File(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    try:
        cookies = _validate_cookies((await cookie_file.read()).decode("utf-8"))
        jar, found = _new_jar(name.strip(), cookies)
        log("OK", f"Account '{jar['name']}' added ({len(cookies)} cookies, keys: {sorted(found) or 'NONE'})")
    except Exception as e:
        log("ERROR", f"Jar upload failed: {type(e).__name__}: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/add-text")
async def jars_add_text(request: Request, name: str = Form(""), cookie_json: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    try:
        jar, found = _new_jar(name.strip(), _validate_cookies(cookie_json.strip()))
        log("OK", f"Account '{jar['name']}' added ({sorted(found) or 'NONE'})")
    except Exception as e:
        log("ERROR", f"Jar paste failed: {type(e).__name__}: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/bulk")
async def jars_bulk(request: Request, accounts: str = Form(...), keeper_enabled: Optional[str] = Form(None)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    created, skipped = 0, 0
    for line in accounts.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\s*[:|,;]\s*(.+)$", line)
        if not m:
            skipped += 1
            continue
        email, password = m.group(1), m.group(2).strip()
        name = email.split("@")[0]
        _new_jar(name, [], email=email, password=password, login_method="email", keeper_enabled=bool(keeper_enabled))
        created += 1
    log("OK", f"Bulk accounts: {created} created, {skipped} skipped (keeper={'on' if keeper_enabled else 'off'})")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/toggle")
async def jars_toggle(request: Request, jar_id: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    def fn(jars):
        for j in jars:
            if j["id"] == jar_id:
                j["enabled"] = not j.get("enabled", True)
                log("INFO", f"Account '{j.get('name')}' {'enabled' if j['enabled'] else 'disabled'}")
    mutate_jars(fn)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/reset")
async def jars_reset(request: Request, jar_id: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    mark_jar_status(jar_id, "ok")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/delete")
async def jars_delete(request: Request, jar_id: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    mutate_jars(lambda jars: jars.__setitem__(slice(None), [j for j in jars if j["id"] != jar_id]))
    log("WARN", f"Account {jar_id} deleted")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/oxalpha/upload")
async def oxalpha_upload(request: Request, cookie_file: UploadFile = File(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    try:
        cookies = _validate_cookies((await cookie_file.read()).decode("utf-8"))
        atomic_write(OX_COOKIES_FILE, cookies)
        log("OK", f"OX Alpha cookies saved ({len(cookies)})")
    except Exception as e:
        log("ERROR", f"OX cookie upload failed: {e}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/oxalpha/verify")
async def oxalpha_verify_endpoint(request: Request):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    sess = await oxalpha_verify_via_browser()
    if not sess.get("cookies"):
        log("ERROR", "OX Alpha browser verification produced no session")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/oxalpha/refresh")
async def oxalpha_refresh(request: Request):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    await oxas(force=True)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/refresh-tokens")
async def refresh_tokens(request: Request):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    result = await refresh_model_catalog()
    if result["ok"]:
        log("OK", f"Manual catalog refresh: {result['reason']}")
    else:
        log("WARN", f"Manual catalog refresh failed: {result['reason']}")
    status_flag = "ok" if result["ok"] else "fail"
    msg = quote(result["reason"])
    return RedirectResponse(
        url=f"/dashboard?refresh={status_flag}&refresh_msg={msg}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/create-key")
async def create_key(request: Request, name: str = Form(...), rpm: int = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    config = get_config()
    config["api_keys"].append({
        "name": name.strip(), "key": f"sk-lmab-{uuid.uuid4()}",
        "rpm": max(1, min(rpm, 1000)), "created": int(time.time()),
    })
    save_config(config)
    log("OK", f"API key created: {name}")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/delete-key")
async def delete_key(request: Request, key_id: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    config = get_config()
    config["api_keys"] = [k for k in config["api_keys"] if k["key"] != key_id]
    save_config(config)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/debug-logs/data")
async def debug_logs_data(request: Request):
    if not await get_current_session(request):
        return {"logs": []}
    return {"logs": read_logs(120)}


@app.get("/debug/raw-models")
async def debug_raw_models(request: Request, q: Optional[str] = None):
    """Inspect the raw, unfiltered model payload Arena returns (before our
    selectable-filter runs). Pass ?q=some-model-name to search by publicName/id.
    Requires a dashboard session — populated after the next successful
    catalog refresh (see MODELS_RAW_DEBUG_FILE)."""
    if not await get_current_session(request):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    try:
        with open(MODELS_RAW_DEBUG_FILE, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return JSONResponse(content={"error": "No raw model dump yet — trigger a catalog refresh first.", "models": []})
    if q:
        ql = q.lower()
        raw = [m for m in raw if ql in str(m.get("publicName", "")).lower() or ql in str(m.get("id", "")).lower()]
    return JSONResponse(content={"count": len(raw), "models": raw})


@app.post("/clear-logs")
async def clear_logs(request: Request):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    try:
        open(LOG_FILE, "w").close()
    except Exception:
        pass
    log("INFO", "Debug logs cleared")
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/keeper/config")
async def keeper_config(request: Request, jar_id: str = Form(...), login_method: str = Form("email"),
                        email: str = Form(""), password: str = Form(""), keeper_enabled: Optional[str] = Form(None)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    def upd(jars):
        for j in jars:
            if j["id"] == jar_id:
                j["login_method"] = "google" if login_method == "google" else "email"
                j["email"] = email.strip()
                j["password"] = password
                j["keeper_enabled"] = bool(keeper_enabled)
                log("OK", f"Keeper config saved for '{j.get('name')}' ({j['login_method']}, keep-alive={j['keeper_enabled']})")
    mutate_jars(upd)
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/keeper/live")
async def keeper_live(request: Request, jar_id: str = Form(...)):
    if not await get_current_session(request):
        return RedirectResponse(url="/login")
    ok, msg = await keeper.start_live(jar_id)
    log("INFO", f"Live browser: {msg}")
    return RedirectResponse(
        url=f"/dashboard?refresh={'ok' if ok else 'fail'}&refresh_msg={quote(msg)}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@app.post("/keeper/relogin")
async def keeper_relogin(request: Request, jar_id: str = Form(...)):
    if not await get_current_session(request):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    s = keeper.sessions.get(jar_id)
    if s and s.running:
        s.next_retry = 0
        asyncio.create_task(s.relogin())
        log("INFO", f"[{s.name}] Manual re-login triggered")
        return {"status": "ok", "message": "Relogin initiated"}
    else:
        jar = next((j for j in load_jars() if j["id"] == jar_id), None)
        if jar:
            s = KeeperSession(jar, headless=jar.get("keeper_headless", True))
            keeper.sessions[jar_id] = s
            async def start_and_relogin():
                await s.start()
                if s.running:
                    await s.relogin()
            asyncio.create_task(start_and_relogin())
            log("INFO", f"Started keeper for '{jar.get('name')}' and triggered relogin")
            return {"status": "ok", "message": "Keeper launched and relogin initiated"}
        else:
            log("WARN", "Account not found for relogin")
            return {"status": "error", "message": "Account not found"}


@app.get("/keeper/status")
async def keeper_status_api(request: Request):
    if not await get_current_session(request):
        return {"sessions": []}
    st = load_state()
    local = {s["jar_id"]: s for s in keeper.status()}
    merged = {s["jar_id"]: s for s in st.get("keeper_status", [])}
    merged.update(local)
    return {"sessions": list(merged.values()), "owner_pid": st.get("keeper_pid")}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bridgena v1.0 — Arena.ai Bridge Server")
    parser.add_argument("-w", "--workers", type=int, default=None, help="Number of uvicorn workers (default: 1, max: number of accounts)")
    parser.add_argument("-p", "--port", type=int, default=PORT, help="Port to bind")
    args = parser.parse_args()

    jars_count = len(load_jars())
    requested = args.workers if args.workers is not None else 1
    # Allow any number of requested workers, so they can share accounts
    effective_workers = max(1, requested)

    print("=" * 62)
    print("  Bridgena v1.0 — Arena.ai Bridge")
    print("=" * 62)
    print(f"  * Chat WebUI  : http://localhost:{args.port}/chat")
    print(f"  * Dashboard   : http://localhost:{args.port}/dashboard")
    print(f"  * OpenAI Base : http://localhost:{args.port}/v1")
    print(f"  * Workers     : {effective_workers} (Accounts: {jars_count})")
    print(f"  * Proxies     : {len(get_proxy_pool())} loaded (proxies.txt / config)")
    if effective_workers > 1:
        print("  ! WARNING    : workers > 1 → Live Browser / keepers only work")
        print("                 inside the process that started them.")
        print("                 For reliable captcha/live sessions use: --workers 1")
    print("=" * 62)

    if effective_workers > 1:
        module = Path(__file__).stem
        uvicorn.run(f"{module}:app", host="0.0.0.0", port=args.port, workers=effective_workers)
    else:
        uvicorn.run(app, host="0.0.0.0", port=args.port)
