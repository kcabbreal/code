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

_vnc_started = False

def start_vnc_server_linux():
    global _vnc_started
    if _vnc_started or not sys.platform.startswith("linux"):
        return
    _vnc_started = True
    os.environ["DISPLAY"] = ":99"
    
    # 1. Xvfb
    try:
        subprocess.run(["pgrep", "Xvfb"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        try:
            subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1920x1080x24", "-ac"])
            time.sleep(1)
        except FileNotFoundError:
            log("WARN", "Xvfb not found. Install with: apt-get install -y xvfb x11vnc novnc websockify")
            return

    # 2. x11vnc
    try:
        subprocess.run(["pgrep", "x11vnc"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        try:
            subprocess.Popen([
                "x11vnc", "-display", ":99", "-forever", "-shared", "-nopw",
                "-listen", "127.0.0.1", "-rfbport", "5900", "-geometry", "1920x1080"
            ])
            time.sleep(0.5)
        except FileNotFoundError:
            log("WARN", "x11vnc not found. Install with: apt-get install -y xvfb x11vnc novnc websockify")

    # 3. websockify
    try:
        subprocess.run(["pgrep", "websockify"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        try:
            subprocess.Popen(["websockify", "--web", "/usr/share/novnc", "6080", "127.0.0.1:5900"])
        except FileNotFoundError:
            log("WARN", "websockify not found. Install with: apt-get install -y xvfb x11vnc novnc websockify")

class KeeperSession:
    """Persistent browser session for one Arena account.
    Cross-platform stealth engine compatible with Windows, macOS, Linux, and Pterodactyl/Docker containers.
    Supports Edge (fastest), Chrome, Chromium, and bundled headless binaries with humanized mouse/keyboard trajectories."""

    def __init__(self, jar: dict, headless: Optional[bool] = None, keep_forever: bool = False):
        self.jar_id = jar["id"]
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
            
        start_vnc_server_linux()
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
                    self.context = await self.playwright.chromium.launch_persistent_context(
                        user_data_dir=profile_dir,
                        headless=False,  # always False here: headlessness is via --headless=new above
                        ignore_default_args=["--disable-extensions"],
                        args=ext_args,
                        viewport={"width": 1920, "height": 1080},
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"
                    )
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
                        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
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
            await self.page.goto(f"{ARENA_BASE}/", wait_until="domcontentloaded")
            await self._wait_cloudflare(self.page)
            await self._handle_turnstile(self.page)
            await self._ensure_sidebar_cookie()
            await self._inject_visual_cursor(self.page)

            # Dismiss any promo banners that might block the UI
            await self._dismiss_promos(self.page)

            self.running = True
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
            self.status = "error"
            self.error = f"{type(e).__name__}: {e}"
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

    tried_jar_ids = {jar_id}
    max_attempts = max(3, len(load_jars()) + 1)

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
            async with AsyncSession(impersonate="chrome131") as client:
                try:
                    resp = await client.post(url, json=base, headers=headers, stream=True, timeout=120.0)
                except Exception as e:
                    yield ("error", f"Network error: {str(e)}")
                    return

                if resp.status_code != 200:
                    raw = b""
                    async for chunk in resp.aiter_content():
                        raw += chunk if isinstance(chunk, (bytes, bytearray)) else str(chunk).encode("utf-8", errors="ignore")
                    body = raw.decode("utf-8", errors="ignore")
                    log("ERROR", f"Status {resp.status_code}, URL {url}, Mode {base.get('mode')}, modelAId {model_id}, Body: {body[:1500]}")

                    if resp.status_code in (401, 403):
                        if "cloudflare" in body.lower() or "just a moment" in body.lower():
                            yield ("error", "502: Cloudflare block — open Live Browser / refresh cookies for this account")
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
                        # Soft mark only — does not hard-block (see jar_available)
                        mark_jar_status(jar_id, "limited")
                        next_jar = acquire_jar(prefer_live=True)
                        if next_jar and next_jar["id"] not in tried_jar_ids:
                            log("WARN", f"[{jar_id}] Arena 429 — rotating to '{next_jar.get('name')}'")
                            jar = next_jar
                            jar_id = jar["id"]
                            tried_jar_ids.add(jar_id)
                            jar = await _refresh_cookies_from_live(jar, jar_id)
                            continue
                        # Clear ALL soft limited flags and allow one full re-pass
                        def _clear_all_limited(jars):
                            for j in jars:
                                j["limited_until"] = 0
                                if j.get("status") == "limited":
                                    j["status"] = "ok"
                        mutate_jars(_clear_all_limited)
                        if getattr(stream_arena_chat, "_cleared_once", False):
                            yield ("error", "429: Arena is rate-limiting right now. Wait 30-60s and retry.")
                            return
                        stream_arena_chat._cleared_once = True
                        log("WARN", "Cleared all soft limited flags — retrying full account pool")
                        tried_jar_ids.clear()
                        next_jar = acquire_jar(prefer_live=True)
                        if next_jar:
                            jar = next_jar
                            jar_id = jar["id"]
                            tried_jar_ids.add(jar_id)
                            jar = await _refresh_cookies_from_live(jar, jar_id)
                            continue
                        yield ("error", "429: Arena rate limit and no accounts available")
                        return

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

    yield ("error", "Arena request failed after trying all available accounts.")


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

app = FastAPI(title="Bridgena", version="1.0", lifespan=lifespan)
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

# [Antigravity IDE Verified: Fix 3 (noVNC routing) Applied]
@app.get("/vnc")
async def vnc_viewer():
    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Live Browser (noVNC)</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background: #0e0e10; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
        header { background: #18181b; color: #efefed; padding: 10px 18px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #27272a; flex-shrink: 0; }
        header .title { font-weight: 600; font-size: 14px; display: flex; align-items: center; gap: 8px; }
        header .back { color: #a1a1aa; text-decoration: none; font-size: 13px; padding: 4px 10px; border-radius: 6px; background: #27272a; transition: background 0.2s; }
        header .back:hover { background: #3f3f46; color: #fff; }
        .iframe-container { flex: 1; position: relative; width: 100%; height: 100%; background: #000; }
        iframe { width: 100%; height: 100%; border: none; }
        .fallback-msg { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #71717a; text-align: center; font-size: 14px; display: none; }
    </style>
</head>
<body>
    <header>
        <div class="title">
            <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;"></span>
            Live Browser &bull; Resolution: 1920x1080 (noVNC)
        </div>
        <a href="/dashboard" class="back">&larr; Back to Dashboard</a>
    </header>
    <div class="iframe-container">
        <iframe id="vncFrame" src=""></iframe>
        <div class="fallback-msg" id="fallbackMsg">
            Connecting to noVNC on port 6080...<br>
            If screen does not load, ensure <code>apt-get install -y xvfb x11vnc novnc websockify</code> is installed on Linux.
        </div>
    </div>
    <script>
        const host = window.location.hostname || 'localhost';
        const vncUrl = `http://${host}:6080/vnc.html?autoconnect=1&resize=scale&reconnect=1&host=${host}&port=6080`;
        const iframe = document.getElementById('vncFrame');
        iframe.src = vncUrl;
        setTimeout(() => {
            const fallback = document.getElementById('fallbackMsg');
            if (fallback) fallback.style.display = 'block';
        }, 3000);
        iframe.onload = () => {
            const fallback = document.getElementById('fallbackMsg');
            if (fallback) fallback.style.display = 'none';
        };
    </script>
</body>
</html>"""
    return HTMLResponse(html)
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
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena - Sign In</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #171717;
            --bg-card: #212121;
            --border: #333333;
            --border-focus: #555555;
            --text-main: #ececec;
            --text-muted: #a1a1aa;
            --accent: #ffffff;
            --accent-text: #000000;
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
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        :root {
            --bg-base: #212121;
            --bg-sidebar: #171717;
            --bg-card: #2f2f2f;
            --bg-hover: #2f2f2f;
            --bg-active: #424242;
            --border: #333333;
            --border-faint: #2a2a2a;
            --text-main: #ececec;
            --text-muted: #b4b4b4;
            --text-faint: #737373;
            --accent: #ffffff;
            --sidebar-width: 260px;
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
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Bridgena - Control Center</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #171717;
            --bg-card: #212121;
            --bg-hover: #2a2a2a;
            --border: #333333;
            --border-hover: #555555;
            --text-main: #ececec;
            --text-muted: #a1a1aa;
            --text-faint: #71717a;
            --accent: #ffffff;
            --accent-text: #000000;
            --green: #22c55e;
            --yellow: #eab308;
            --red: #ef4444;
            --blue: #3b82f6;
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

    <!-- TOAST POPUP -->
    <div class="toast-popup" id="toastPopup">
        <span id="toastMsg">Action completed</span>
    </div>

    <script>
        function showToast(msg) {
            const t = document.getElementById('toastPopup');
            document.getElementById('toastMsg').textContent = msg;
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 3500);
        }
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
        }

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
                if (d.sessions) {
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
            } catch(e) {}
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
            <td><code style="background:rgba(255,255,255,0.06);padding:3px 8px;border-radius:6px;font-family:'JetBrains Mono',monospace;cursor:pointer" onclick="copyKey('{k.get('key')}')" title="Click to copy">{k.get('key')}</code></td>
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
    return RedirectResponse(url="/vnc", status_code=status.HTTP_303_SEE_OTHER)


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
