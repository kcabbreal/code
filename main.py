#!/usr/bin/env python3
# ================================================================
#  BRIDGENA v4.1 — autonomous headed keeper fleet + browser-extension transport
#  modules: core · identity · pool · keepers · verification · UI · API · VNC
#  Deploy: extract and run ./launch.sh (or python3 bridgena-v4.2.2-navigation-deadlock-recovery-fix.py).
# ================================================================
import asyncio, base64, functools, hashlib, hmac, json, math, os, random
import re, secrets, socket, struct, subprocess, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse, quote, quote_plus
from io import BytesIO
import shutil

def _load_app_env():
    """Load the script-adjacent .env before adapters or settings are initialized."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(env_path):
        return
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        raise RuntimeError(
            "Found .env but python-dotenv is missing. Install it with: "
            "python3 -m pip install python-dotenv"
        ) from exc
    # Preserve literal secret values, and let process/service settings win.
    load_dotenv(dotenv_path=env_path, override=False, interpolate=False,
                encoding="utf-8-sig")


_load_app_env()

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None
try:
    from camoufox.async_api import AsyncCamoufox
except ImportError:
    AsyncCamoufox = None

try:
    import numpy as np
except ImportError:
    np = None
try:
    from PIL import Image
except ImportError:
    Image = None
try:
    import onnxruntime as ort
except ImportError:
    ort = None

def _discover_verification_factory():
    """Resolve function-, class-, and singleton-based adapter packages."""
    import importlib
    import importlib.util
    import sys
    errors = []
    # Do not accept the package's legacy image/ONNX RecaptchaSolver here. It is
    # a different component and may construct to None; only the documented
    # verification adapter API is compatible with solve(**challenge_context).
    factory_names = ("get_solver", "AuthorizedVerificationAdapter",
                     "VerificationAdapter")

    def resolve(module, requested=None):
        names = (requested,) if requested else factory_names
        for name in names:
            candidate = getattr(module, name, None)
            if callable(candidate):
                return candidate, name
        for name in ("verification_adapter", "adapter", "client"):
            instance = getattr(module, name, None)
            if instance is not None and callable(getattr(instance, "solve", None)):
                return (lambda instance=instance: instance), name
        return None, None

    # A sibling recaptcha_solver.py can coexist with a recaptcha_solver/
    # package. Python normally imports the package first, which hid the
    # documented adapter on deployed installations. Load explicit adapter
    # files before package discovery so get_solver() wins deterministically.
    sibling_dir = os.path.dirname(os.path.abspath(__file__))
    configured_file = os.environ.get("BRIDGENA_VERIFICATION_ADAPTER_FILE", "").strip()
    file_candidates = [
        configured_file,
        os.path.join(sibling_dir, "recaptcha_solver.py"),
        os.path.join(sibling_dir, "authorized_verification_adapter.py"),
    ]
    seen_files = set()
    for candidate_path in file_candidates:
        if not candidate_path:
            continue
        candidate_path = os.path.abspath(candidate_path)
        if candidate_path in seen_files or candidate_path == os.path.abspath(__file__):
            continue
        seen_files.add(candidate_path)
        if not os.path.isfile(candidate_path):
            continue
        try:
            module_name = "_bridgena_verification_adapter_" + hashlib.sha256(
                candidate_path.encode("utf-8")
            ).hexdigest()[:10]
            spec = importlib.util.spec_from_file_location(module_name, candidate_path)
            if spec is None or spec.loader is None:
                raise ImportError("could not create module spec")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            factory, resolved_name = resolve(module)
            if factory:
                return factory, None, f"{candidate_path}:{resolved_name}"
            errors.append(f"{candidate_path}=no compatible adapter factory")
        except Exception as exc:
            errors.append(f"{candidate_path}={type(exc).__name__}: {exc}")

    configured = os.environ.get("BRIDGENA_VERIFICATION_FACTORY", "").strip()
    candidates = ([configured] if configured else []) + [
        "recaptcha_solver",
        "recaptcha_solver.recaptcha_solver",
        "recaptcha_solver.solver",
        "recaptcha_solver.adapter",
        "recaptcha_solver.client",
    ]
    seen = set()
    for spec in candidates:
        if not spec or spec in seen:
            continue
        seen.add(spec)
        module_name, separator, attr = spec.partition(":")
        try:
            module = importlib.import_module(module_name)
            factory, resolved_name = resolve(module, attr if separator else None)
            if factory:
                return factory, None, f"{module_name}:{resolved_name}"
            public = [name for name in dir(module) if not name.startswith("_")][:20]
            errors.append(f"{spec}=no compatible factory (exports: {', '.join(public)})")
        except Exception as exc:
            errors.append(f"{spec}={type(exc).__name__}: {exc}")
    try:
        import pkgutil
        package = importlib.import_module("recaptcha_solver")
        package_path = getattr(package, "__path__", None)
        if package_path:
            for info in pkgutil.iter_modules(package_path):
                if not any(hint in info.name.lower() for hint in ("solver", "adapter", "client", "service")):
                    continue
                spec = f"recaptcha_solver.{info.name}"
                if spec in seen:
                    continue
                try:
                    module = importlib.import_module(f"recaptcha_solver.{info.name}")
                    factory, resolved_name = resolve(module)
                    if factory:
                        return factory, None, f"{spec}:{resolved_name}"
                except Exception as exc:
                    errors.append(f"{spec}={type(exc).__name__}: {exc}")
    except Exception as exc:
        errors.append(f"recaptcha_solver package scan={type(exc).__name__}: {exc}")
    return None, "; ".join(errors[-4:]), None


get_verification_solver, _VERIFICATION_IMPORT_ERROR, _VERIFICATION_FACTORY_SPEC = _discover_verification_factory()
if os.environ.get("BRIDGENA_VERIFICATION_ADAPTER_ENABLED", "1").lower() in {"0", "false", "no", "off"}:
    get_verification_solver = None
    _VERIFICATION_IMPORT_ERROR = "Adapter explicitly disabled by operator"
    _VERIFICATION_FACTORY_SPEC = None

# legacy global keeper UA: chrome131 on Windows — matches curl_cffi impersonate
# default so cf_clearance (UA+IP-bound) stays coherent for persona-less jars.
KEEPER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")



# ────────────────────────── module: core.py ──────────────────────────────

# ============================================================
# v2 CORE — config, constants, log bus. Stores/auth/models arrive with
# the primitives bundle (same file names, same keys: VPS drops in cleanly).
# ============================================================
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) or "."
PORT = int(os.environ.get("BRIDGENA_PORT", "8000"))
# Advertised application origin only; never used for upstream traffic or binds.
def _validated_public_url(value):
    value = value.strip()
    parsed = urlparse(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or any(ch.isspace() or ord(ch) < 32 for ch in value)
            or "\\" in value or "?" in value or "#" in value):
        raise ValueError("BRIDGENA_PUBLIC_URL must be an HTTP(S) origin without credentials, path, query, or fragment")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("BRIDGENA_PUBLIC_URL has an invalid port")
    return value.rstrip("/")

PUBLIC_APP_URL = _validated_public_url(os.environ.get(
    "BRIDGENA_PUBLIC_URL", "https://arena.itio.dpdns.org"
))
ARENA_BASE = _validated_public_url(os.environ.get(
    "BRIDGENA_ARENA_BASE", "https://arena.itio.dpdns.org"
))
_ARENA_PARSED = urlparse(ARENA_BASE)
LOCAL_UPSTREAM = (_ARENA_PARSED.hostname or "").lower() in {"localhost", "127.0.0.1", "::1"}
LOCAL_VERIFICATION_ENHANCED = LOCAL_UPSTREAM and os.environ.get(
    "BRIDGENA_LOCAL_VERIFICATION_ENHANCED", "1"
).strip().lower() in {"1", "true", "yes", "on"}
LOCAL_VERIFICATION_MAX_ROUNDS = max(
    1, min(12, int(os.environ.get("BRIDGENA_LOCAL_VERIFICATION_MAX_ROUNDS", "6")))
)
LOCAL_VERIFICATION_POLL_MS = max(
    100, min(2000, int(os.environ.get("BRIDGENA_LOCAL_VERIFICATION_POLL_MS", "300")))
)
PUBLIC_AUTH_BASE = _validated_public_url(os.environ.get(
    "BRIDGENA_PUBLIC_AUTH_BASE", ARENA_BASE
))
PUBLIC_AUTH_URL = os.environ.get("BRIDGENA_PUBLIC_AUTH_URL", f"{PUBLIC_AUTH_BASE}/?mode=direct")
ARENA_MODES = ["direct-battle", "direct"]
MAX_PROMPT = 50000
COOLDOWN_SEC = 60                 # soft preference; the pool is never hard-locked
REFRESH_INTERVAL = 3600
CURL_TTFB_TIMEOUT = int(os.environ.get("CURL_TTFB_TIMEOUT", "40"))
PROXY_FLAG_TTL = int(os.environ.get("PROXY_FLAG_TTL", "10800"))      # arena-block: ~3h, self-expiring
PROXY_QUARANTINE = int(os.environ.get("PROXY_QUARANTINE", "21600"))  # legacy compatibility; pool quarantine is non-destructive
PROXY_RECOVERY_INTERVAL_SEC = max(5.0, min(300.0, float(os.environ.get("BRIDGENA_PROXY_RECOVERY_INTERVAL_SEC", "15"))))
PROXY_RECOVERY_MAX_BACKOFF_SEC = max(PROXY_RECOVERY_INTERVAL_SEC, min(900.0, float(os.environ.get("BRIDGENA_PROXY_RECOVERY_MAX_BACKOFF_SEC", "120"))))
_FLAGGED_TTL = PROXY_FLAG_TTL     # legacy alias (primitives use it)
PROBE_OK_TTL = 900
PROBE_BUDGET = 40
PROBE_MAX_PARALLEL = 8
STRIKES_MAX = 3
MAX_CONVERSATIONS = 500

ARENA_RECAPTCHA_SITEKEY = os.environ.get("BRIDGENA_RECAPTCHA_SITEKEY",
                                         "6LeTGMcsAAAAALuIlkVwIxaAuZA8VledA6d3Nnb0")
ARENA_RECAPTCHA_V2_SITEKEY = os.environ.get("BRIDGENA_RECAPTCHA_V2_SITEKEY",
                                            "6Le3_cYsAAAAAGwWOK2RLDgNI15Bh8C0yLBOL1yL")
RECAPTCHA_ACTION = os.environ.get("BRIDGENA_RECAPTCHA_ACTION", "chat_submit")
ARENA_DIRECT_URL = os.environ.get("BRIDGENA_ARENA_DIRECT_URL", f"{ARENA_BASE}/?mode=direct")
ALLOW_CONFIGURED_RECAPTCHA_FALLBACK = os.environ.get(
    "BRIDGENA_ALLOW_RECAPTCHA_FALLBACK", "0"
).strip().lower() in {"1", "true", "yes", "on"}
REQUEST_MAX_ATTEMPTS = max(1, min(3, int(os.environ.get("BRIDGENA_REQUEST_MAX_ATTEMPTS", "1"))))
STREAM_TAIL_GRACE_MS = max(250, min(10000, int(os.environ.get("BRIDGENA_STREAM_TAIL_GRACE_MS", "1500"))))
KEEPER_WARMUP_SEC = max(0, min(60, int(os.environ.get("BRIDGENA_KEEPER_WARMUP_SEC", "3"))))
KEEPER_REQUEST_READY_SEC = max(2, min(20, int(os.environ.get("BRIDGENA_KEEPER_REQUEST_READY_SEC", "6"))))
API_DUPLICATE_WINDOW_SEC = max(0, min(60, int(os.environ.get("BRIDGENA_DUPLICATE_WINDOW_SEC", "15"))))
API_PACE_INTERVAL_SEC = max(0.0, min(5.0, float(os.environ.get("BRIDGENA_API_PACE_INTERVAL_SEC", "0.75"))))
API_PACE_MAX_WAIT_SEC = max(1.0, min(30.0, float(os.environ.get("BRIDGENA_API_PACE_MAX_WAIT_SEC", "8"))))
CONVERSATION_MIN_GAP_SEC = max(0.0, min(5.0, float(os.environ.get("BRIDGENA_CONVERSATION_MIN_GAP_SEC", "0.9"))))
UPSTREAM_429_COOLDOWN_SEC = max(5.0, min(300.0, float(os.environ.get("BRIDGENA_UPSTREAM_429_COOLDOWN_SEC", "45"))))
UPSTREAM_429_FIRST_BACKOFF_SEC = max(1.0, min(30.0, float(os.environ.get("BRIDGENA_UPSTREAM_429_FIRST_BACKOFF_SEC", "5"))))
UPSTREAM_429_INLINE_WAIT_MAX_SEC = max(1.0, min(60.0, float(os.environ.get("BRIDGENA_UPSTREAM_429_INLINE_WAIT_MAX_SEC", "12"))))
UPSTREAM_429_SAME_ACCOUNT_RETRIES = max(0, min(3, int(os.environ.get("BRIDGENA_UPSTREAM_429_SAME_ACCOUNT_RETRIES", "1"))))
UPSTREAM_429_STRIKE_RESET_SEC = max(15.0, min(900.0, float(os.environ.get("BRIDGENA_UPSTREAM_429_STRIKE_RESET_SEC", "120"))))
VERIFICATION_TIMEOUT_SEC = max(5, min(180, int(os.environ.get("BRIDGENA_VERIFICATION_TIMEOUT", "90"))))
VERIFICATION_MIN_TOKEN_LEN = max(
    32, min(512, int(os.environ.get("BRIDGENA_VERIFICATION_MIN_TOKEN_LEN", "80")))
)
KEEPER_CONCURRENCY_HARD_CAP = max(
    1, min(128, int(os.environ.get("BRIDGENA_KEEPER_CONCURRENCY_HARD_CAP", "64")))
)
_KEEPER_START_CONCURRENCY_CONFIG = os.environ.get(
    "BRIDGENA_KEEPER_START_CONCURRENCY", "auto"
).strip().lower()
_KEEPER_LOGIN_CONCURRENCY_CONFIG = os.environ.get(
    "BRIDGENA_KEEPER_LOGIN_CONCURRENCY", "auto"
).strip().lower()

# Resolved against the live bootable-account count before keeper.sync().
KEEPER_START_CONCURRENCY = 1
KEEPER_LOGIN_CONCURRENCY = 1

API_TURN_CONCURRENCY = max(
    1, min(128, int(os.environ.get("BRIDGENA_API_TURN_CONCURRENCY", "32")))
)
_keeper_start_gate = asyncio.Semaphore(KEEPER_START_CONCURRENCY)
_keeper_login_gate = asyncio.Semaphore(KEEPER_LOGIN_CONCURRENCY)


def _resolve_keeper_concurrency(raw: str, account_count: int) -> int:
    account_count = max(1, int(account_count or 1))
    raw = str(raw or "auto").strip().lower()
    if raw in {"", "auto", "dynamic", "accounts", "0"}:
        requested = account_count
    else:
        try:
            requested = max(1, int(raw))
        except Exception:
            requested = account_count
    return max(1, min(account_count, requested, KEEPER_CONCURRENCY_HARD_CAP))


def _configure_keeper_concurrency(account_count: int) -> tuple:
    """Match keeper startup/login concurrency to the current account fleet."""
    global KEEPER_START_CONCURRENCY, KEEPER_LOGIN_CONCURRENCY
    global _keeper_start_gate, _keeper_login_gate

    count = max(1, int(account_count or 1))
    starts = _resolve_keeper_concurrency(_KEEPER_START_CONCURRENCY_CONFIG, count)
    logins = _resolve_keeper_concurrency(_KEEPER_LOGIN_CONCURRENCY_CONFIG, count)

    if starts != KEEPER_START_CONCURRENCY:
        KEEPER_START_CONCURRENCY = starts
        _keeper_start_gate = asyncio.Semaphore(starts)
    if logins != KEEPER_LOGIN_CONCURRENCY:
        KEEPER_LOGIN_CONCURRENCY = logins
        _keeper_login_gate = asyncio.Semaphore(logins)

    return starts, logins

BUILD_STAMP = os.environ.get("BRIDGENA_BUILD", "v4.2.2-navigation-deadlock-recovery-fix")
DURABLE_WRITES = os.environ.get("BRIDGENA_DURABLE_WRITES", "1").strip().lower() in {"1", "true", "yes", "on"}

CONFIG_FILE = "config.json"
MODELS_FILE = "models.json"
MODELS_RAW_DEBUG_FILE = "models_raw_debug.json"
STATE_FILE = "state.json"
JARS_FILE = "cookie_jars.json"
LOG_FILE = "logs.jsonl"
PROXIES_FILE = "proxies.txt"
DEAD_FILE = "proxies.dead.txt"
PROXY_HEALTH_FILE = "proxies.health.json"
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

OX_BASE = "https://oxalpha.com"
OX_ENDPOINT = "/api/chat"
OX_UPSTREAM_MODEL = "z-ai/glm-5.3-flash"
OX_ALIASES = {"glm-5.3-flash", "ox-alpha"}
OX_MODEL_ID = "glm-5.3-flash"
OX_SESSION_TTL = 20 * 60


# ---------------- log bus ----------------
class LogBus:
    def __init__(self, path: str = LOG_FILE, ring: int = 400):
        import queue, threading
        self.path, self.ring, self._mu = path, [], threading.Lock()
        self.subs: list = []
        self._disk_queue = queue.Queue(maxsize=8192)
        self._disk_io_mu = threading.Lock()
        self._closed = threading.Event()
        self._writer = threading.Thread(target=self._write_loop, name="bridgena-log-writer", daemon=True)
        self._writer.start()

    def _write_loop(self) -> None:
        import queue
        pending = []
        while not self._closed.is_set() or not self._disk_queue.empty():
            with self._disk_io_mu:
                try:
                    pending.append(self._disk_queue.get(timeout=.25))
                    while len(pending) < 256:
                        pending.append(self._disk_queue.get_nowait())
                except queue.Empty:
                    pass
                if pending:
                    try:
                        with open(self.path, "a", encoding="utf-8") as stream:
                            stream.write("".join(pending))
                    except OSError:
                        pass
                    pending.clear()

    def close(self) -> None:
        self._closed.set()
        if self._writer.is_alive():
            self._writer.join(timeout=2)

    def clear(self) -> None:
        """Atomically discard the in-memory ring and every queued disk entry."""
        import queue
        with self._disk_io_mu:
            while True:
                try:
                    self._disk_queue.get_nowait()
                except queue.Empty:
                    break
            try:
                with open(self.path, "w", encoding="utf-8"):
                    pass
            except OSError:
                pass
        with self._mu:
            self.ring.clear()

    def log(self, level: str, msg: str) -> None:
        import json, queue, time
        now = time.time()
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        print(line, flush=True)
        try:
            self._disk_queue.put_nowait(json.dumps({"t": now, "lvl": level, "m": msg}) + "\n")
        except queue.Full:
            pass
        with self._mu:
            self.ring.append({"t": now, "lvl": level, "m": msg, "line": line})
            del self.ring[:-400]
        for q in list(self.subs):
            try:
                q.put_nowait(line)
            except Exception:
                pass

    def tail(self, n: int = 200):
        with self._mu:
            return list(self.ring[-n:])


LOG = LogBus()


def log(level: str, msg: str) -> None:
    LOG.log(level, msg)


def redact(s) -> str:
    """creds never travel to logs or UI: scrub user:pass@ wherever it appears."""
    import re
    return re.sub(r"([A-Za-z0-9+._%-]{1,64}):([A-Za-z0-9+._%-]{1,64})@", "***:***@", str(s)) if s else s


def read_json(path: str, default):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (json.JSONDecodeError, OSError):
        try:
            os.replace(path, path + f".corrupt.{int(__import__('time').time())}")
        except OSError:
            pass
        return default


_FILE_THREAD_LOCKS: Dict[str, threading.RLock] = {}
_FILE_THREAD_LOCKS_GUARD = threading.Lock()


class FileLock:
    """Dual-use lock: `with FileLock(p):` AND @FileLock(p) decorator form.
    Thread lock always; flock best-effort for cross-worker sanity."""
    def __init__(self, path: str, timeout: float = 10.0):
        self.path, self.timeout = path, timeout
        lock_key = os.path.abspath(path)
        with _FILE_THREAD_LOCKS_GUARD:
            self._mu = _FILE_THREAD_LOCKS.setdefault(lock_key, threading.RLock())
        self._fd = None

    def _acquire_fd(self):
        import time
        import fcntl
        try:
            self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR)
        except OSError:
            self._fd = None
            return
        deadline = time.time() + self.timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.time() > deadline:
                    self._release_fd()
                    raise TimeoutError(f"timed out acquiring file lock: {self.path}")
                time.sleep(0.05)

    def _release_fd(self):
        import fcntl
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self):
        self._mu.acquire()
        self._acquire_fd()
        return self

    def __exit__(self, *a):
        self._release_fd()
        self._mu.release()

    def __call__(self, fn):
        import functools

        @functools.wraps(fn)
        def wrapped(*a, **kw):
            with self:
                return fn(*a, **kw)
        return wrapped


# ────────────────────── module: recaptcha_vision.py ─────────────────────────

# ============================================================
# v2 VISION SOLVER — local ONNX neural inference engine for visual
# reCAPTCHA image challenges (type.onnx for 3x3/individual tiles,
# grid.onnx for 4x4 challenges). Auto-creates models directory
# and copies from root if needed.
# ============================================================

DEFAULT_GRID_META = {
    "schema_version": 1,
    "format": "selected16",
    "task": "multi_type_grid16",
    "model_name": "efficientnet_b1",
    "image_size": 240,
    "output": "logits_by_type",
    "n_types": 11,
    "label_types": [
        "bicycles", "buses", "chimney", "crosswalks", "hydrants",
        "motorcycles", "parkingmeter", "stairs", "taxi", "tractors", "trafficlights"
    ],
    "type_to_index": {
        "bicycles": 0, "buses": 1, "chimney": 2, "crosswalks": 3, "hydrants": 4,
        "motorcycles": 5, "parkingmeter": 6, "stairs": 7, "taxi": 8, "tractors": 9,
        "trafficlights": 10
    },
    "thresholds_by_type": {
        "bicycles": [0.968, 0.78, 0.858, 0.982, 0.679, 0.657, 0.552, 0.905, 0.619, 0.637, 0.598, 0.633, 0.819, 0.859, 0.645, 0.784],
        "buses": [0.925, 0.872, 0.708, 0.894, 0.529, 0.701, 0.123, 0.802, 0.783, 0.614, 0.35, 0.807, 0.863, 0.839, 0.689, 0.642],
        "chimney": [0.916, 0.729, 0.827, 0.808, 0.917, 0.69, 0.556, 0.922, 0.837, 0.702, 0.812, 0.747, 0.977, 0.944, 0.872, 0.966],
        "crosswalks": [0.966, 0.53, 0.966, 0.856, 0.766, 0.583, 0.485, 0.748, 0.639, 0.858, 0.683, 0.799, 0.928, 0.732, 0.767, 0.793],
        "hydrants": [0.656, 0.435, 0.686, 0.88, 0.691, 0.56, 0.433, 0.497, 0.48, 0.66, 0.401, 0.428, 0.745, 0.45, 0.608, 0.581],
        "motorcycles": [0.923, 0.728, 0.869, 0.74, 0.712, 0.679, 0.571, 0.674, 0.899, 0.713, 0.515, 0.727, 0.751, 0.81, 0.361, 0.573],
        "parkingmeter": [0.778, 0.97, 0.882, 0.926, 0.863, 0.85, 0.866, 0.855, 0.928, 0.555, 0.535, 0.951, 0.94, 0.466, 0.769, 0.941],
        "stairs": [0.904, 0.767, 0.729, 0.971, 0.476, 0.474, 0.577, 0.755, 0.526, 0.591, 0.702, 0.873, 0.893, 0.772, 0.553, 0.842],
        "taxi": [0.935, 0.633, 0.725, 0.897, 0.578, 0.403, 0.418, 0.58, 0.689, 0.547, 0.435, 0.501, 0.678, 0.588, 0.209, 0.65],
        "tractors": [0.916, 0.759, 0.713, 0.863, 0.798, 0.304, 0.298, 0.574, 0.57, 0.194, 0.587, 0.617, 0.708, 0.587, 0.374, 0.34],
        "trafficlights": [0.913, 0.846, 0.827, 0.913, 0.684, 0.533, 0.532, 0.873, 0.713, 0.506, 0.725, 0.79, 0.884, 0.827, 0.904, 0.805]
    }
}

RECAPTCHA_THR = {
    "type": {
        "default": 0.50,
        "hydrants": 0.139,
        "bridges": 0.191,
        "boats": 0.047,
        "cars": 0.994,
        "crosswalks": 0.136,
        "taxi": 0.862,
        "bicycles": 0.065,
        "trafficlights": 0.137,
        "motorcycles": 0.154,
        "stairs": 0.075,
        "mountains": 0.061,
        "tractors": 0.015,
        "buses": 0.618,
        "palm": 0.01,
        "parkingmeter": 0.001,
        "chimney": 0.006,
    }
}

RECAPTCHA_TYPE_INDEX = {
    "boats": 0, "motorcycles": 1, "palm": 2, "parkingmeter": 3, "stairs": 4,
    "taxi": 5, "tractors": 6, "bicycles": 7, "cars": 8, "hydrants": 9,
    "crosswalks": 10, "buses": 11, "trafficlights": 12, "bridges": 13,
    "chimney": 14, "mountains": 15,
}

RECAPTCHA_ALIAS = {
    "fire": "hydrants", "firehydrant": "hydrants", "fire_hydrant": "hydrants", "hydrant": "hydrants",
    "bicycle": "bicycles", "bike": "bicycles",
    "boat": "boats",
    "bridge": "bridges",
    "bus": "buses",
    "car": "cars",
    "chimney": "chimney", "chimneys": "chimney",
    "crosswalk": "crosswalks", "zebra": "crosswalks", "pedestrian": "crosswalks",
    "motorcycle": "motorcycles",
    "mountain": "mountains",
    "palm": "palm",
    "parkingmeter": "parkingmeter", "parking": "parkingmeter",
    "stairs": "stairs", "stair": "stairs",
    "taxi": "taxi", "taxis": "taxi",
    "tractors": "tractors", "tractor": "tractors",
    "traffic": "trafficlights", "trafficlight": "trafficlights", "traffic_light": "trafficlights",
    "trafficlights": "trafficlights", "traffic_lights": "trafficlights",
}

RECAPTCHA_KNOWN = set([
    "bicycles", "boats", "bridges", "buses", "cars", "chimney", "crosswalks", "hydrants",
    "motorcycles", "mountains", "palm", "parkingmeter", "stairs", "taxi", "tractors",
    "trafficlights"
])


def extract_captcha_label(txt: str) -> str:
    txt = str(txt or "").lower().strip()
    match = re.search(r'with\s+(?:an?\s+)?([a-z_]+)', txt)
    if match:
        return match.group(1)
    return txt.split()[-1] if txt.split() else ""


def normalize_captcha_label(raw: str) -> Optional[str]:
    if not raw:
        return None
    raw = raw.lower().strip()
    basic = RECAPTCHA_ALIAS.get(raw, raw if raw.endswith('s') else raw + 's')
    return basic if basic in RECAPTCHA_KNOWN else None


# Backward-compatible aliases for recaptcha_solver / server.py
THR = RECAPTCHA_THR
TYPE_INDEX = RECAPTCHA_TYPE_INDEX
ALIAS = RECAPTCHA_ALIAS
KNOWN = RECAPTCHA_KNOWN
extract_label = extract_captcha_label
normalize_label = normalize_captcha_label


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def ensure_models_dir(base_dir: Optional[str] = None) -> str:
    """Ensure the models directory exists. If model files (type.onnx, grid.onnx,
    grid.meta.json) are found in the root directory rather than /models/, copy
    them to /models/. If grid.meta.json is missing, generate it automatically."""
    base = base_dir or BASE_DIR or "."
    models_dir = os.environ.get("BRIDGENA_CAPTCHA_MODELS") or os.path.join(base, "models")
    try:
        os.makedirs(models_dir, exist_ok=True)
    except Exception as e:
        log("WARN", f"ensure_models_dir: could not create directory '{models_dir}': {e}")
        return models_dir

    parent = os.path.dirname(os.path.abspath(base))
    for fn in ("type.onnx", "grid.onnx", "grid.meta.json"):
        dst = os.path.join(models_dir, fn)
        if not os.path.exists(dst):
            candidates = [
                os.path.join(base, fn),
                os.path.join(parent, fn),
                os.path.join(parent, "models", fn),
                os.path.join(".", fn),
                os.path.join("models", fn),
            ]
            found = False
            for src_cand in candidates:
                cand_abs = os.path.abspath(src_cand)
                dst_abs = os.path.abspath(dst)
                if cand_abs != dst_abs and os.path.exists(cand_abs):
                    try:
                        shutil.copy2(cand_abs, dst)
                        log("OK", f"Copied model asset '{fn}' from '{cand_abs}' to '{models_dir}'")
                        found = True
                        break
                    except Exception as ce:
                        log("WARN", f"Failed copying '{fn}' from '{cand_abs}' to '{models_dir}': {ce}")
            if not found and fn == "grid.meta.json":
                try:
                    with open(dst, "w", encoding="utf-8") as f:
                        json.dump(DEFAULT_GRID_META, f, indent=2)
                    log("OK", f"Generated default '{dst}'")
                except Exception as ge:
                    log("WARN", f"Failed generating '{dst}': {ge}")
    return models_dir


class RecaptchaSolver:
    """Local ONNX neural solver for visual reCAPTCHA challenges."""

    def __init__(self, models_dir: Optional[str] = None):
        self.models_dir = ensure_models_dir(models_dir or BASE_DIR)
        self.type_session = None
        self.grid_session = None
        self.grid_meta = None

    def _resolve_file(self, filename: str) -> str:
        p1 = os.path.join(self.models_dir, filename)
        if os.path.exists(p1):
            return p1
        p2 = os.path.join(BASE_DIR, filename)
        if os.path.exists(p2):
            return p2
        return p1

    def available(self) -> bool:
        """Return True if ONNX Runtime, Pillow, and neural models are present."""
        if ort is None or Image is None or np is None:
            return False
        has_type = os.path.exists(self._resolve_file("type.onnx"))
        has_grid = os.path.exists(self._resolve_file("grid.onnx"))
        return bool(has_type and has_grid)

    def _load_type_session(self):
        if self.type_session is None:
            if ort is None:
                raise RuntimeError("onnxruntime is not installed")
            model_path = self._resolve_file("type.onnx")
            self.type_session = ort.InferenceSession(model_path)
        return self.type_session

    def _load_grid_session(self):
        if self.grid_session is None:
            if ort is None:
                raise RuntimeError("onnxruntime is not installed")
            model_path = self._resolve_file("grid.onnx")
            self.grid_session = ort.InferenceSession(model_path)
        return self.grid_session

    def _load_grid_meta(self) -> dict:
        if self.grid_meta is None:
            meta_path = self._resolve_file("grid.meta.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        self.grid_meta = json.load(f)
                except Exception:
                    self.grid_meta = DEFAULT_GRID_META
            else:
                self.grid_meta = DEFAULT_GRID_META
        return self.grid_meta

    def _img_to_tensor(self, img: Any, size: int):
        img = img.convert("RGB").resize((size, size))
        data = np.array(img, dtype=np.float32) / 255.0
        mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
        std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
        data = (data - mean) / std
        data = np.transpose(data, (2, 0, 1))
        return np.expand_dims(data, axis=0)

    def _split_3x3(self, base_img: Any) -> list:
        tiles = []
        width, height = base_img.size
        tile_w, tile_h = width // 3, height // 3
        for r in range(3):
            for c in range(3):
                left = c * tile_w
                upper = r * tile_h
                tile = base_img.crop((left, upper, left + tile_w, upper + tile_h))
                tiles.append(tile)
        return tiles

    def _load_image(self, source: Any) -> Any:
        if Image is None:
            raise RuntimeError("Pillow is not installed")
        if isinstance(source, Image.Image):
            return source
        if isinstance(source, bytes):
            return Image.open(BytesIO(source))
        if isinstance(source, str):
            if source.startswith("data:image/"):
                base64_str = source.split(",", 1)[1] if "," in source else source
                return Image.open(BytesIO(base64.b64decode(base64_str)))
            if source.startswith("http://") or source.startswith("https://"):
                import urllib.request
                req = urllib.request.Request(source, headers={"User-Agent": KEEPER_UA})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    return Image.open(BytesIO(resp.read()))
            if os.path.exists(source):
                return Image.open(source)
            if len(source) > 100:
                try:
                    return Image.open(BytesIO(base64.b64decode(source)))
                except Exception:
                    pass
        raise ValueError(f"Unsupported image source: {type(source)}")

    def recognize(self, task: str, image_sources: list, grid: Optional[str] = "3x3", randomize_20pct: bool = False) -> dict:
        """Classify visual challenge tiles or grid against the target task prompt."""
        if not task or not image_sources:
            return {"error": "bad_payload"}

        raw = extract_captcha_label(task)
        label = normalize_captcha_label(raw)
        if not label:
            return {"error": f"unsupported_label:{raw}"}

        variant = "grid" if grid == "4x4" else "type"

        try:
            if variant == "grid":
                base = self._load_image(image_sources[0])
                meta = self._load_grid_meta()
                grid_size = meta.get("image_size", 240)
                tensors = [self._img_to_tensor(base, grid_size)]
            elif grid == "3x3":
                base = self._load_image(image_sources[0])
                tiles = self._split_3x3(base)
                tensors = [self._img_to_tensor(tile, 100) for tile in tiles]
            else:
                im_objs = [self._load_image(src) for src in image_sources]
                tensors = [self._img_to_tensor(im, 100) for im in im_objs]

            if variant == "type":
                thr = RECAPTCHA_THR["type"].get(label, RECAPTCHA_THR["type"]["default"])
                idx = RECAPTCHA_TYPE_INDEX.get(label)
                if idx is None:
                    return {"error": f"unknown_class_in_type_model:{label}"}

                sess = self._load_type_session()
                input_name = sess.get_inputs()[0].name
                outs = [sess.run(None, {input_name: t})[0] for t in tensors]
                probs = [sigmoid(float(o[0][idx])) for o in outs]
                data = [p > thr for p in probs]
                return {
                    "data": data,
                    "indices": [i for i, v in enumerate(data) if v],
                    "label": label,
                    "probs": probs
                }

            # 4x4 Grid inference
            grid_meta = self._load_grid_meta()
            class_idx = grid_meta.get("type_to_index", {}).get(label)
            if class_idx is None:
                return {"error": f"unknown_class_in_grid_model:{label}"}

            thr16 = grid_meta.get("thresholds_by_type", {}).get(label)
            if not isinstance(thr16, list) or len(thr16) != 16:
                return {"error": f"bad_thresholds_for_grid_model:{label}"}

            sess = self._load_grid_session()
            input_name = sess.get_inputs()[0].name
            out = sess.run(None, {input_name: tensors[0]})[0]
            logits = out.flatten()
            HW = 16
            base_idx = class_idx * HW
            probs16 = [sigmoid(float(logits[base_idx + i])) for i in range(HW)]
            data = [probs16[i] > (thr16[i] if thr16[i] is not None else 0.5) for i in range(16)]

            if randomize_20pct and random.random() < 0.20:
                new_data = []
                for i, v in enumerate(data):
                    p = probs16[i]
                    if not v:
                        new_data.append(random.random() < p)
                    else:
                        flip_prob = (1 - p) / 2
                        new_data.append(not (random.random() < flip_prob))
                data = new_data

            if grid == "4x4":
                count = sum(1 for v in data if v)
                first_idx = next((i for i, v in enumerate(data) if v), -1)
                if count == 1:
                    best_idx, best_p = -1, -float('inf')
                    for i, p in enumerate(probs16):
                        if i != first_idx and math.isfinite(p) and p > best_p:
                            best_p, best_idx = p, i
                    if best_idx != -1:
                        data[best_idx] = True

            return {
                "data": data,
                "indices": [i for i, v in enumerate(data) if v],
                "label": label,
                "probs": probs16
            }
        except Exception as exc:
            return {"error": f"inference_exception:{type(exc).__name__}:{exc}"}


_global_solver: Optional[RecaptchaSolver] = None


def get_solver(models_dir: Optional[str] = None) -> RecaptchaSolver:
    """Return the global singleton RecaptchaSolver instance."""
    global _global_solver
    if _global_solver is None:
        _global_solver = RecaptchaSolver(models_dir=models_dir)
    return _global_solver


def model_name(m) -> str:
    """Return the label a human actually sees in Arena's model picker."""
    if isinstance(m, str):
        return m
    for key in (
        "uiName", "displayName", "modelDisplayName", "display_name",
        "label", "title", "publicName", "name", "id",
    ):
        value = str(m.get(key) or "").strip()
        if value:
            return value
    return ""


def _model_aliases(m) -> list[str]:
    if isinstance(m, str):
        return [m]
    out = []
    for key in (
        "uiName", "displayName", "modelDisplayName", "display_name",
        "label", "title", "publicName", "name", "id",
    ):
        value = str(m.get(key) or "").strip()
        if value and value not in out:
            out.append(value)
    return out


def canonical_public_model_name(value: str) -> str:
    """Map a cached slug/internal id to the current Arena display label."""
    raw = str(value or "auto").strip() or "auto"
    if raw == "auto":
        return raw
    wanted = _model_key(raw)
    for item in get_models():
        aliases = _model_aliases(item)
        if raw in aliases or wanted in {_model_key(x) for x in aliases}:
            return model_name(item) or raw
    return raw


def _model_key(value: str) -> str:
    """Canonical comparison key for Arena display labels and API slugs."""
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")


# Captured from Arena's working direct-chat client on 2026-09-03. These are
# compatibility pins, not substitutes for catalog refresh: a JSON environment
# override lets an operator update a changed UUID without editing this file.
_VERIFIED_MODEL_IDS = {
    "gemini-3-8-flash-high": "01a0681c-b561-76b6-b338-a44ff0cff460",
    "minimax-m3": "019e809d-f62d-7192-bb7f-1657e066b5f2",
}
try:
    _VERIFIED_MODEL_IDS.update({
        _model_key(k): str(v) for k, v in
        json.loads(os.environ.get("BRIDGENA_MODEL_ID_OVERRIDES", "{}")).items()
    })
except Exception:
    pass


def resolve_model_id(public_name: str, jar: Optional[dict] = None) -> str:
    """Resolve Arena's public label to the internal UUID required by the
    create-evaluation contract. Sending a label here currently produces an
    opaque upstream 500, while Arena's own client always sends the UUID."""
    wanted = _model_key(public_name)
    # The shared catalog is replaced atomically by the latest successful live
    # refresh. It must outrank compatibility pins because Arena rotates UUIDs.
    for item in get_models():
        if not isinstance(item, dict):
            continue
        labels = _model_aliases(item)
        if public_name in labels or wanted in {_model_key(x) for x in labels if x}:
            return item.get("id") or item.get("name") or public_name
    if wanted in _VERIFIED_MODEL_IDS:
        return _VERIFIED_MODEL_IDS[wanted]
    jar_map = (jar or {}).get("model_map", {})
    mapped = jar_map.get(public_name)
    if not mapped:
        mapped = next((v for k, v in jar_map.items() if _model_key(k) == wanted), None)
    if mapped:
        return mapped
    return public_name


HEALTH_TRUST_SEC = 6 * 3600  # how long a persisted sweep verdict stays believable across restarts


# ────────────────────────── module: identity.py ──────────────────────────────

# ============================================================
# v2 IDENTITY — device personas, bound PER JAR, coherent across every
# layer that touches the network: curl headers, keeper browser, recaptcha
# mint. Rotating identity per-REQUEST is how accounts die (cf_clearance and
# Google both correlate UA across the session); rotating per-IDENTITY is
# what makes the fleet look like a crowd. One jar = one device, always.
# ============================================================
import hashlib, random


class Persona:
    def __init__(self, key, label, family, ua, platform, ch_ua=None, accept=None,
                 accept_lang="en-US,en;q=0.9", locale="en-US", tz="America/Los_Angeles",
                 viewport=(1512, 982), dpr=2.0, touch=False, webgl=None, mobile=False, tablet=False):
        self.key, self.label, self.family = key, label, family
        self.ua, self.platform, self.ch_ua = ua, platform, ch_ua
        self.accept = accept or "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        self.accept_lang, self.locale, self.tz = accept_lang, locale, tz
        self.viewport, self.dpr, self.touch = viewport, dpr, touch
        self.webgl = webgl or ("Apple GPU" if family == "safari" else "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Laptop GPU Direct3D11)")
        self.mobile, self.tablet = mobile, tablet

    def __repr__(self):
        return f"<Persona {self.key}>"


_CHROME_VER = "131.0.0.0"

PERSONAS = {
    "iphone15": Persona(
        "iphone15", "iPhone 15 · Safari", "safari",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "iOS", viewport=(393, 852), dpr=3.0, touch=True, mobile=True, accept_lang="en-US,en;q=0.9"),
    "macbook": Persona(
        "macbook", "MacBook Pro · Safari", "safari",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "macOS", viewport=(1512, 982), dpr=2.0, accept_lang="en-US,en;q=0.9",
        webgl="Apple M2 GPU"),
    "win11": Persona(
        "win11", "Windows 11 · Chrome", "chrome",
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{_CHROME_VER} Safari/537.36",
        "Windows", ch_ua=f'"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        viewport=(1920, 1080), dpr=1.0),
    "ubuntu": Persona(
        "ubuntu", "Ubuntu 24.04 · Chromium", "chrome",
        f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{_CHROME_VER} Safari/537.36",
        "Linux", ch_ua=f'"Chromium";v="131", "Not_A Brand";v="24"',
        viewport=(1600, 900), dpr=1.0, accept_lang="en-US,en;q=0.9",
        webgl="ANGLE (Mesa, llvmpipe (LLVM 16.0.6 256 bits), OpenGL 4.5)"),
    "pixel8": Persona(
        "pixel8", "Pixel 8 · Chrome", "chrome",
        f"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{_CHROME_VER} Mobile Safari/537.36",
        "Android", ch_ua=f'"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        viewport=(412, 915), dpr=2.625, touch=True, mobile=True),
    "ipad": Persona(
        "ipad", "iPad Pro · Safari", "safari",
        "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "iOS", viewport=(1024, 1366), dpr=2.0, touch=True, tablet=True),
}
PERSONA_KEYS = list(PERSONAS.keys())


def _hash_slot(jar_id: str, mod: int) -> int:
    return int(hashlib.md5(str(jar_id).encode()).hexdigest(), 16) % mod


def persona_for(jar: dict) -> Persona:
    """Stable binding: preserve a supported explicit choice; otherwise use the
    real deployment family (Linux Chromium). Never invent a random device."""
    key = jar.get("persona")
    if key not in PERSONAS:
        key = "ubuntu"
        jar["persona"] = key
    return PERSONAS[key]


def curl_headers(p: Persona, *, cookie: str, json_body: bool = False) -> dict:
    """Header set for the request transport. Chrome family gets sec-ch-ua
    triplets; safari/firefox families must NOT (presence alone is a tell)."""
    h = {
        "User-Agent": p.ua,
        "Accept": "application/json, text/plain, */*" if json_body else p.accept,
        "Accept-Language": p.accept_lang,
        "Origin": "",   # filled by caller (arena base)
        "Referer": "",  # ditto
        "Cookie": cookie,
        "Connection": "keep-alive",
        "sec-fetch-dest": "empty" if json_body else "document",
        "sec-fetch-mode": "cors" if json_body else "navigate",
        "sec-fetch-site": "same-origin",
        "priority": "u=1, i",
    }
    if p.family == "chrome":
        brand = "Chromium"
        h["sec-ch-ua"] = p.ch_ua or f'"Chromium";v="131", "Not_A Brand";v="24"'
        h["sec-ch-ua-mobile"] = "?1" if p.mobile else "?0"
        h["sec-ch-ua-platform"] = f'"{p.platform}"'
        h["sec-ch-ua-full-version-list"] = h["sec-ch-ua"]
    elif p.family == "safari":
        h["Sec-Fetch-User"] = "?1"
    return h


def playwright_context_args(p: Persona) -> dict:
    """Keeper browser options that make Playwright's context present as this device."""
    args = {
        "user_agent": p.ua,
        "viewport": {"width": p.viewport[0], "height": p.viewport[1]},
        "device_scale_factor": p.dpr,
        "has_touch": p.touch,
        "is_mobile": p.mobile,
        "is_tablet": p.tablet,
        "locale": p.locale,
        "timezone_id": p.tz,
        "extra_http_headers": {"Accept-Language": p.accept_lang},
    }
    return args


def stealth_init_js(p: Persona) -> str:
    """Run at document start in every keeper context: remove headless tells and
    align what JS-visible APIs say with the persona's UA (languages, vendor,
    plugins count, WebGL renderer/name). Not evasion of a check you're banned
    for — it's making an automated browser look like a normal one."""
    return """(() => {
      Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
      Object.defineProperty(navigator, 'platform', {get: () => %r});
      Object.defineProperty(navigator, 'languages', {get: () => %r});
      Object.defineProperty(navigator, 'vendor', {get: () => %r});
      Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
      Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
      Object.defineProperty(navigator, 'maxTouchPoints', {get: () => %d});
      const __fakePlugins = %s;
      Object.defineProperty(navigator, 'plugins', {get: () => __fakePlugins});
      const getParameterOrig = WebGLRenderingContext.prototype.getParameter;
      WebGLRenderingContext.prototype.getParameter = function(p) {
        if (p === 37445) return %r;                       // UNMASKED_VENDOR_WEBGL
        if (p === 37446) return %r;                       // UNMASKED_RENDERER_WEBGL
        return getParameterOrig.apply(this, arguments);
      };
      if (!window.chrome && %r) {
        window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){}};
      }
      const origQuery = navigator.permissions && navigator.permissions.query;
      if (origQuery) navigator.permissions.query = (params) =>
        params.name === 'notifications'
          ? Promise.resolve({state: Notification.permission})
          : origQuery.call(navigator.permissions, params);
    })();""" % (p.platform, [p.locale, p.locale.split("-")[0]] ,
                "Apple Computer, Inc." if p.family == "safari" else ("Google Inc." if p.family == "chrome" else ""),
                5 if p.touch else 0,
                "[{name:'PDF Viewer'},{name:'Chrome PDF Viewer'},{name:'Chromium PDF Viewer'}]",
                p.webgl, p.webgl, p.family == "chrome")


def persona_summaries() -> dict:
    return {k: {"label": v.label, "family": v.family} for k, v in PERSONAS.items()}


# ────────────────────────── module: _primitives.py ──────────────────────────────

# ============================================================
# v2 PRIMITIVES — extracted verbatim from the battle-tested build.
# These carry the R22/R26/R28/R29 semantics (truthful probe verdicts,
# chromium SOCKS-auth shim, flag-vs-exile discipline, keeper session core).
# Low-level correctness lives here; ALL policy is rewritten in pool/tokens/arena.
# ============================================================
import asyncio, base64, re, socket, struct, subprocess, random
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse
PROBE_TIMEOUT = 5.0

_SHIM_SCHEMES = ("socks5", "socks5h", "socks4", "socks4a")

_shim_state: dict = {"loop": None, "ports": {}, "servers": {}}

_probe_fail_reason: Dict[str, str] = {}   # url → human 'where it died', shown on dead rows

_QUARANTINED_KEYS: set = set()   # host:port — this process

_proxy_health: Dict[str, dict] = {}       # host:port → {ok, latency, checked, source}

_proxy_health_loaded = False

_flagged_exits: Dict[str, float] = {}      # host:port → expiry

_proxy_probe_cache: Dict[str, Tuple[bool, float]] = {}

_proxy_latency: Dict[str, int] = {}   # host → handshake RTT (ms)

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

_models_cache = None

_models_cache_time = 0.0

_upstream_hits: List[float] = []

UPSTREAM_DEGRADE_COOLDOWN = 45.0

UPSTREAM_DEGRADE_WINDOW = 60.0

UPSTREAM_DEGRADE_THRESHOLD = 3

_log_counter = 0

_state_cache = None

_state_cache_time = 0.0

_jars_cache = None

_jars_cache_time = 0.0

_proxy_rr_index = 0

_proxy_assign_cursor = 0   # shared round-robin position for ALL pinning paths

_upstream_degraded_until = 0.0

_quarantine_lock   = __import__("threading").RLock()

_proxy_strikes: Dict[str, int] = {}

_proxy_health_loaded = False

_proxy_check_state = {"running": False, "done": 0, "total": 0, "started": 0.0}

_FLAGGED_TTL = float(os.environ.get("PROXY_FLAG_TTL", "10800"))

PROBE_DEAD_TTL = 300.0      # re-probe a failed proxy at most once per 5 min

PROBE_OK_TTL = 900.0        # reuse a confirmed-healthy verdict for 15 min

PROBE_EXILE_AFTER  = 2

def _probe_hostport() -> Tuple[str, int]:
    try:
        from urllib.parse import urlparse
        u = urlparse(PUBLIC_AUTH_BASE if LOCAL_UPSTREAM else ARENA_BASE)
        return (u.hostname or "localhost"), (u.port or (443 if u.scheme == "https" else 80))
    except Exception:
        return "localhost", 6767

def _socks_client_handshake(s, scheme: str, host: str, port: int, u, why=None) -> bool:
    """SOCKS4/4a/5 client handshake through an already-connected socket.
    Pass why=[] to collect a human 'where it died' line (tcp vs greeting vs
    auth vs connect) — the pool page shows it on dead rows instead of bare
    'dead', because 'provider rejected my creds' and 'your ISP ate the
    handshake' need two different fixes and one label was lying about both."""
    import socket as _sk
    import struct as _st
    from urllib.parse import unquote as _unq
    def fail(msg):
        if why is not None:
            why.append(msg)
        return False
    try:
        if scheme in ("socks4", "socks4a"):
            if scheme == "socks4":
                try:
                    addr = _sk.inet_aton(_sk.gethostbyname(host))     # client-side DNS
                except Exception:
                    return fail("local DNS failed for the target (socks4 is IP-mode; use socks4a/5h)")
            else:
                addr = b"\x00\x00\x00\x01"                          # socks4a: resolve remotely
            user = (_unq(u.username) if u.username else "bridgena").encode("utf-8", "ignore")[:255]
            s.sendall(b"\x04\x01" + _st.pack(">H", port) + addr + user + b"\x00")
            resp = s.recv(8)
            if len(resp) == 8 and resp[0] == 0x00 and resp[1] == 0x5A:
                return True
            return fail("socks4 refused (code %d)" % (resp[1] if len(resp) > 1 else 0xFF))
        # socks5(h): offer RFC-1929 username/password when creds are present,
        # no-auth otherwise; then CONNECT.
        if u.username or u.password:
            s.sendall(b"\x05\x02\x02\x00")
        else:
            s.sendall(b"\x05\x01\x00")
        try:
            g = s.recv(2)
        except (_sk.timeout, TimeoutError):
            return fail("gateway answered TCP but never spoke SOCKS — a middlebox/ISP is killing the handshake; the provider itself never rejected anything")
        if not g or len(g) < 2:
            return fail("gateway closed mid-greeting (its edge firewall dropped us — check plan/IP-allowlist at the provider)")
        if g[0] != 0x05:
            return fail("non-SOCKS reply 0x%02x — something else owns this port" % g[0])
        if g[1] == 0xFF:
            return fail("server rejected every auth method we offered")
        if g[1] == 0x02:
            if not (u.username or u.password):
                return fail("server demands username/password auth — no creds in the pool line")
            user = (_unq(u.username or "")).encode("utf-8", "ignore")[:255]
            pw = (_unq(u.password or "")).encode("utf-8", "ignore")[:255]
            s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            a = s.recv(2)
            if len(a) < 2 or a[0] != 0x01 or a[1] != 0x00:
                return fail("auth REJECTED — wrong creds, or this server's IP is not in the provider's allowlist")
        elif g[1] != 0x00:
            return fail("unexpected method selection 0x%02x" % g[1])
        # CONNECT: socks5h resolves remotely (domain ATYPE); plain socks5 tries
        # local DNS like curl — but a DNS hiccup must not stamp a healthy exit
        # dead, so fall back to domain CONNECT on failure.
        ip4 = None
        if scheme != "socks5h":
            try:
                ip4 = _sk.inet_aton(_sk.gethostbyname(host))
            except Exception:
                ip4 = None
        if ip4 is not None:
            s.sendall(b"\x05\x01\x00\x01" + ip4 + _st.pack(">H", port))
        else:
            hb = host.encode("ascii", "ignore")[:255]
            if not hb:
                return fail("no CONNECT target")
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + _st.pack(">H", port))
        r = s.recv(4)
        if not (len(r) >= 4 and r[0] == 0x05 and r[1] == 0x00):
            return fail("gateway refused CONNECT to the target (SOCKS reply %s)" % (r[1] if len(r) >= 2 else "?"))
        # Drain BND.ADDR+BND.PORT like a complete client (a server that only
        # answers the 4-byte header still passes: short timeout, ignore error).
        try:
            s.settimeout(0.4)
            if r[3] == 0x01:
                s.recv(6)
            elif r[3] == 0x03:
                n = s.recv(1)
                if n:
                    s.recv(n[0] + 2)
            elif r[3] == 0x04:
                s.recv(18)
        except Exception:
            pass
        return True
    except Exception as e:
        return fail("handshake error (%s)" % type(e).__name__)

def _proxy_probe(proxy_url: str, timeout: float = PROBE_TIMEOUT) -> Tuple[bool, int]:
    """(alive, latency_ms) — a REAL handshake per scheme: http/https via CONNECT,
    socks4/4a/5 via native SOCKS4/SOCKS5 connect to localhost:6767. Every failure
    records WHERE it died in _probe_fail_reason so the pool page can tell an ISP
    black-hole from a bad-creds rejection from a billing refusal — each needs a
    different fix, and bare 'dead' blamed the wrong party for months."""
    import base64
    import socket
    from urllib.parse import unquote, urlparse
    if not proxy_url:
        return False, -1
    t0 = time.perf_counter()
    host, port = _probe_hostport()
    why: List[str] = []
    try:
        u = urlparse(proxy_url if "://" in proxy_url else "http://" + proxy_url)
        scheme = (u.scheme or "http").lower()
        ph, pp = u.hostname, (u.port or 80)
    except Exception:
        _probe_fail_reason[proxy_url] = "unparseable pool line"
        return False, -1
    try:
        s = socket.create_connection((ph, pp), timeout=timeout)
    except socket.gaierror:
        _probe_fail_reason[proxy_url] = "proxy hostname did not resolve ON THIS SERVER (local DNS; the provider never saw a packet)"
        return False, -1
    except (socket.timeout, TimeoutError):
        _probe_fail_reason[proxy_url] = "TCP to %s:%s black-holed (no SYN-ACK) — a firewall/ISP between this server and the gateway; the proxy itself is healthy" % (ph, pp)
        return False, -1
    except ConnectionRefusedError:
        _probe_fail_reason[proxy_url] = "TCP %s:%s refused — host is up, port closed for this source (plan/IP-allowlist on the provider side)" % (ph, pp)
        return False, -1
    except Exception as e:
        _probe_fail_reason[proxy_url] = "TCP unreachable from this server (%s)" % type(e).__name__
        return False, -1
    try:
        s.settimeout(timeout)
        try:
            if scheme in ("socks4", "socks4a", "socks5", "socks5h"):
                if not _socks_client_handshake(s, scheme, host, port, u, why):
                    _probe_fail_reason[proxy_url] = why[0] if why else "SOCKS handshake failed"
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
                        _probe_fail_reason[proxy_url] = "http proxy closed during CONNECT (its edge dropped us mid-handshake)"
                        return False, -1
                    buf += c
                    if len(buf) > 16384:
                        _probe_fail_reason[proxy_url] = "http proxy babbled >16KB before answering CONNECT"
                        return False, -1
                line = buf.split(b"\r\n", 1)[0].decode("latin1", "ignore")
                m = re.match(r"HTTP/[\d.]+\s+(\d+)", line)
                if not m or m.group(1) != "200":
                    code = m.group(1) if m else "?"
                    if code == "407":
                        _probe_fail_reason[proxy_url] = "proxy auth rejected (HTTP 407) — wrong creds, or this server's IP is not allowed"
                    elif code == "402":
                        _probe_fail_reason[proxy_url] = "provider says payment required (HTTP 402) — billing/quota, not a tunnel fault"
                    else:
                        _probe_fail_reason[proxy_url] = "CONNECT refused by proxy (HTTP %s)" % code
                    hint = " — PAYMENT REQUIRED (provider billing/quota)" if code == "402" else \
                           (" — auth failed (creds/allowlist)" if code == "407" else "")
                    log("WARN", f"proxy probe {ph}:{pp} refused CONNECT: {code}{hint}")
                    if code in ("402", "407"):
                        quarantine_proxy(proxy_url, f"CONNECT refused {code} — billing/auth, not transient")
                    return False, -1

            # CONNECT alone only proves that the gateway accepted a tunnel.
            # Complete TLS and request an actual upstream resource so scans do
            # not report a dead or intercepted exit as usable.
            try:
                target = urlparse(PUBLIC_AUTH_BASE if LOCAL_UPSTREAM else ARENA_BASE)
                s.settimeout(timeout)
                transport = s
                if (target.scheme or "https").lower() == "https":
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    transport = ctx.wrap_socket(s, server_hostname=host)
                    transport.settimeout(timeout)
                path = (target.path or "/").rstrip("/") + "/robots.txt"
                req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: Bridgena-Proxy-Probe/2\r\nAccept: */*\r\n"
                       "Connection: close\r\n\r\n")
                transport.sendall(req.encode("ascii", "ignore"))
                response = b""
                while b"\r\n" not in response and len(response) < 8192:
                    chunk = transport.recv(2048)
                    if not chunk:
                        break
                    response += chunk
                first = response.split(b"\r\n", 1)[0].decode("latin1", "ignore")
                status_match = re.match(r"HTTP/[\d.]+\s+(\d+)", first)
                status_code = int(status_match.group(1)) if status_match else 0
                if not status_code:
                    _probe_fail_reason[proxy_url] = "tunnel opened but upstream returned no HTTP response"
                    return False, -1
                if status_code in (403, 407, 429) or status_code >= 500:
                    _probe_fail_reason[proxy_url] = f"upstream HTTP {status_code} through tunnel"
                    return False, -1
            except Exception as verify_error:
                _probe_fail_reason[proxy_url] = f"tunnel opened but TLS/HTTP validation failed ({type(verify_error).__name__})"
                return False, -1
        finally:
            try:
                s.close()
            except Exception:
                pass
        _probe_fail_reason.pop(proxy_url, None)
        return True, int((time.perf_counter() - t0) * 1000)
    except Exception as e:
        _probe_fail_reason[proxy_url] = "probe error (%s)" % type(e).__name__
        return False, -1

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

    # socks5h:// is PRESERVED. The suffix is the ONE signal that means
    # "resolve the target at the gateway" — libcurl and the raw probe honor it,
    # and it is what protects authenticated-proxy users from a poisoned local
    # resolver (an app host resolving localhost:6767 itself can hand the gateway a
    # sinkhole IP, which comes back as a fatal-looking (97)/(4) that was never
    # the proxy's fault). Only the Playwright dict re-maps it; Chromium's
    # socks5:// already sends domains — see playwright_proxy_from_url.

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
            scheme = parts[4].lower()
        if not port.isdigit() or not (0 < int(port) <= 65535):
            return None
        return f"{scheme}://{user}:{password}@{host}:{port}"

    # host:port   (incl. bracketed IPv6 [::1]:8080)
    if len(parts) == 2 and parts[1].isdigit() and 0 < int(parts[1]) <= 65535:
        return f"http://{parts[0]}:{parts[1]}"

    return None

def _proxy_hkey(proxy_url: str) -> str:
    try:
        from urllib.parse import urlparse as _up
        u = _up(_normalize_proxy(proxy_url) or proxy_url)
        return f"{u.hostname}:{u.port or 80}"
    except Exception:
        return proxy_url


def _is_loopback_proxy(proxy_url: str) -> bool:
    try:
        host = (urlparse(_normalize_proxy(proxy_url) or proxy_url).hostname or "").lower()
        return host in {"localhost", "127.0.0.1", "::1"}
    except Exception:
        return False


def _is_local_proxy_shim(proxy_url: str) -> bool:
    """Return True for intentional local proxy listeners."""
    return _is_loopback_proxy(proxy_url)

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
        # Loopback proxy listeners are valid in Bridgena. They are commonly
        # local SOCKS shims that forward to distinct upstream exits.
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

def _shim_ensure_loop():
    if _shim_state["loop"] is not None:
        return _shim_state["loop"]
    import threading as _th
    lock = _shim_state.setdefault("lock", _th.Lock())
    with lock:
        if _shim_state["loop"] is None:
            def _run():
                lp = asyncio.new_event_loop()
                asyncio.set_event_loop(lp)
                _shim_state["loop"] = lp
                lp.run_forever()
            _th.Thread(target=_run, daemon=True, name="px-shim").start()
            for _ in range(200):
                if _shim_state["loop"] is not None:
                    break
                time.sleep(0.02)
    return _shim_state["loop"]

def _shim_upstream_connect(up_url: str, host: str, port: int):
    """blocking: connect + full SOCKS handshake toward host:port; return the
    connected, ready-to-relay socket (or raise — the browser gets a clean
    failure reply and the pool row gets a human reason)."""
    import socket as _sk
    from urllib.parse import urlparse
    pu = _normalize_proxy(up_url) or up_url
    u = urlparse(pu)
    s = _sk.create_connection((u.hostname, u.port or 1080), timeout=15)
    try:
        s.settimeout(15)
        eff = (u.scheme or "socks5").lower()
        if eff in ("socks5", "socks5h"):
            # browser gave us a hostname? keep it remote (domain CONNECT) —
            # this host's resolver is exactly what we do NOT trust. literal
            # IPs take the fast IPv4 path (no resolver round-trip).
            import ipaddress
            try:
                ipaddress.ip_address(host)
                eff = "socks5"
            except ValueError:
                eff = "socks5h"
        if not _socks_client_handshake(s, eff, host, port, u):
            raise RuntimeError("upstream socks handshake refused")
        s.settimeout(None)
        return s
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        raise

async def _shim_pump(a, b):
    try:
        while True:
            d = await a.read(65536)
            if not d:
                break
            b.write(d)
            await b.drain()
    except Exception:
        pass
    try:
        b.close()
    except Exception:
        pass

async def _shim_handle(rd, wr, up_url):
    import struct
    import ipaddress
    u_wr = None
    try:
        hdr = await rd.readexactly(2)
        if hdr[0] != 0x05:
            wr.close()
            return
        await rd.readexactly(hdr[1])               # methods — we answer no-auth;
        wr.write(b"\x05\x00")                     #   real auth happens upstream
        await wr.drain()
        req = await rd.readexactly(4)              # VER CMD RSV ATYP
        if req[1] != 0x01:                         # CONNECT only; UDP associate -> 0x07,
            wr.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")   # browser falls back to TCP
            await wr.drain()
            wr.close()
            return
        atyp = req[3]
        if atyp == 0x01:
            host = str(ipaddress.IPv4Address(await rd.readexactly(4)))
        elif atyp == 0x03:
            ln = (await rd.readexactly(1))[0]
            host = (await rd.readexactly(ln)).decode("ascii", "ignore")
        elif atyp == 0x04:
            host = str(ipaddress.IPv6Address(await rd.readexactly(16)))
        else:
            wr.close()
            return
        port = struct.unpack(">H", await rd.readexactly(2))[0]
        loop = asyncio.get_running_loop()
        try:
            s = await loop.run_in_executor(None, _shim_upstream_connect, up_url, host, port)
        except Exception as e:
            _probe_fail_reason[up_url] = "shim: upstream refused CONNECT (%s) — line intact, not a tunnel death" % type(e).__name__
            wr.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await wr.drain()
            wr.close()
            return
        wr.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        await wr.drain()
        up_rd, u_wr = await asyncio.open_connection(sock=s)
        await asyncio.gather(_shim_pump(rd, u_wr), _shim_pump(up_rd, wr))
    except Exception:
        pass
    finally:
        for w in (wr, u_wr):
            try:
                w.close()
            except Exception:
                pass

async def _shim_open_listener(pu):
    import functools
    srv = await asyncio.start_server(functools.partial(_shim_handle, up_url=pu), "127.0.0.1", 0)
    _shim_state["servers"][pu] = srv
    return srv.sockets[0].getsockname()[1]

def shim_proxy_for(proxy_url: str) -> Optional[str]:
    """Browser-safe localhost relay URL for an authenticated socks line;
    None when no shim is needed (unauth / http) — caller then proceeds as
    before."""
    try:
        from urllib.parse import urlparse
        pu = _normalize_proxy(proxy_url) or proxy_url
        u = urlparse(pu)
        if (u.scheme or "") not in _SHIM_SCHEMES or not u.username:
            return None
    except Exception:
        return None
    lp = _shim_ensure_loop()
    if lp is None:
        return None
    lock = _shim_state.setdefault("lock", __import__("threading").Lock())
    with lock:
        port = _shim_state["ports"].get(pu)
        if port is None:
            try:
                fut = asyncio.run_coroutine_threadsafe(_shim_open_listener(pu), lp)
                port = fut.result(timeout=10)
            except Exception:
                port = None
            if not port:
                return None
            _shim_state["ports"][pu] = port
    return f"socks5://127.0.0.1:{port}"

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


def _api_key_hash(raw: str) -> str:
    return hashlib.sha256(str(raw).encode("utf-8")).hexdigest()


def _normalize_api_key_records(config: dict) -> bool:
    """Migrate legacy plaintext API keys to stable hashed records in-place."""
    changed = False
    records = config.setdefault("api_keys", [])
    for record in records:
        if not isinstance(record, dict):
            continue
        raw = record.get("key")
        if raw and not record.get("key_hash"):
            record["key_hash"] = _api_key_hash(raw)
            record["prefix"] = str(raw)[:14]
            record.pop("key", None)
            changed = True
        if not record.get("id"):
            record["id"] = "key_" + secrets.token_hex(8)
            changed = True
        if not record.get("prefix"):
            record["prefix"] = "sk-void-…"
            changed = True
    return changed

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


def _catalog_names(models: list) -> list[str]:
    out, seen = [], set()
    for m in models or []:
        try:
            n = model_name(m).strip()
        except Exception:
            n = str((m or {}).get("name") or (m or {}).get("publicName") or (m or {}).get("id") or "").strip() if isinstance(m, dict) else str(m).strip()
        if n and n not in seen:
            seen.add(n); out.append(n)
    return out

def _valid_model_catalog(models: list) -> bool:
    # Arena's public catalog size changes over time; requiring >50 made valid
    # refreshes look like failures and left models.json stale. Validate shape
    # and a small non-empty unique-name floor instead.
    floor = max(1, int(os.getenv("BRIDGENA_MODEL_REFRESH_MIN", "3") or 3))
    return isinstance(models, list) and len(_catalog_names(models)) >= floor

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

# API admission readiness is stronger than "browser process exists".
# A keeper must have passed an authenticated Enterprise-V3 preflight before
# external API traffic can be assigned to it.
# This is a browser-client readiness LEASE, not a reCAPTCHA token lifetime.
# A 10-minute all-at-once expiry caused healthy fleets to collapse to 0/2
# between scheduler sweeps, so the default is longer and renewals are staggered.
_API_VERIFICATION_TTL = max(180.0, float(os.environ.get("BRIDGENA_VERIFICATION_READY_TTL", "1800")))
_API_PREFERRED_KEEPERS_CONFIG = os.environ.get(
    "BRIDGENA_MIN_VERIFIED_KEEPERS", "auto"
).strip().lower()
_API_PREFERRED_EXITS_CONFIG = os.environ.get(
    "BRIDGENA_MIN_VERIFIED_EXITS", "auto"
).strip().lower()

# Runtime admission remains degraded-capacity tolerant. Preferred capacity now
# follows the actual account fleet; one healthy keeper/exit can still serve.
_API_ADMISSION_MIN_KEEPERS = max(1, min(2, int(os.environ.get("BRIDGENA_ADMISSION_MIN_KEEPERS", "1"))))
_API_ADMISSION_MIN_EXITS = max(1, min(2, int(os.environ.get("BRIDGENA_ADMISSION_MIN_EXITS", "1"))))
_API_READY_RECOVERY_WAIT_SEC = max(5.0, min(20.0, float(os.environ.get("BRIDGENA_API_READY_RECOVERY_WAIT_SEC", "20"))))

_API_FAILURE_QUARANTINE_S = max(15.0, float(os.environ.get("BRIDGENA_FAILURE_QUARANTINE_S", "90")))
_api_verified_keepers: Dict[str, float] = {}
_api_keeper_quarantine_until: Dict[str, float] = {}
_api_ready_event = asyncio.Event()
_verification_wakeup_event = asyncio.Event()
_initial_verification_sweep_done = asyncio.Event()
_keeper_fleet_launch_event = asyncio.Event()
_verification_preflight_retry_after: Dict[str, float] = {}
_keeper_recovery_attempts: Dict[str, int] = {}
_keeper_recovery_restart_after = max(2, min(6, int(os.environ.get("BRIDGENA_KEEPER_RECOVERY_RESTART_AFTER", "2"))))
_keeper_recovery_retry_sec = max(2.0, min(30.0, float(os.environ.get("BRIDGENA_KEEPER_RECOVERY_RETRY_SEC", "5"))))
_keeper_recovery_gate = asyncio.Semaphore(max(1, min(4, int(os.environ.get("BRIDGENA_KEEPER_RECOVERY_PARALLEL", "3")))))
TRANSPORT_FAILURE_QUARANTINE_SEC = max(8.0, min(120.0, float(os.environ.get("BRIDGENA_TRANSPORT_FAILURE_QUARANTINE_SEC", "30"))))
BOUND_KEEPER_RECOVERY_WAIT_SEC = max(2.0, min(30.0, float(os.environ.get("BRIDGENA_BOUND_KEEPER_RECOVERY_WAIT_SEC", "14"))))
_transport_recovery_tasks: Dict[str, asyncio.Task] = {}
_reliability_window = deque(maxlen=max(20, min(500, int(os.environ.get("BRIDGENA_RELIABILITY_WINDOW", "100")))))
_reliability_guard = threading.Lock()
_RELIABILITY_TARGET = max(0.1, min(1.0, float(os.environ.get("BRIDGENA_RELIABILITY_TARGET", "0.70"))))
TRANSPORT_PROBE_TIMEOUT_MS = max(1200, min(10000, int(os.environ.get("BRIDGENA_TRANSPORT_PROBE_TIMEOUT_MS", "4500"))))
TRANSPORT_PROBE_EVERY_REQUEST = os.environ.get("BRIDGENA_TRANSPORT_PROBE_EVERY_REQUEST", "1").strip().lower() not in ("0", "false", "no", "off")
TRANSPORT_PROBE_FRESH_SEC = max(0.0, min(60.0, float(os.environ.get("BRIDGENA_TRANSPORT_PROBE_FRESH_SEC", "4"))))
PREDISPATCH_RECOVERY_WAIT_SEC = max(4.0, min(30.0, float(os.environ.get("BRIDGENA_PREDISPATCH_RECOVERY_WAIT_SEC", "16"))))
ACCOUNT_FAILOVER_MAX = max(0, min(6, int(os.environ.get("BRIDGENA_ACCOUNT_FAILOVER_MAX", "3"))))
FIRST_ASSISTANT_RESPONSE_SEC = max(1.0, min(30.0, float(os.environ.get("BRIDGENA_FIRST_ASSISTANT_RESPONSE_SEC", "5"))))
from contextlib import asynccontextmanager

# Keeper lanes and proxy-exit lanes are separate capacity constraints. Several
# keepers can legitimately share one configured SOCKS exit; cap simultaneous
# long-lived browser streams on that shared exit so one tunnel is not
# oversubscribed by otherwise-independent keeper workers.
EXIT_STREAM_CONCURRENCY = max(1, min(8, int(os.environ.get("BRIDGENA_EXIT_STREAM_CONCURRENCY", "2"))))
EXIT_STREAM_WAIT_SEC = max(1.0, min(30.0, float(os.environ.get("BRIDGENA_EXIT_STREAM_WAIT_SEC", "8"))))
_exit_stream_lanes = {}

def _exit_stream_lane(proxy):
    key = _proxy_hkey(proxy) if proxy else "direct"
    lane = _exit_stream_lanes.get(key)
    if lane is None:
        lane = asyncio.Semaphore(EXIT_STREAM_CONCURRENCY)
        _exit_stream_lanes[key] = lane
    return key, lane

@asynccontextmanager
async def _browser_transport_guard(session, proxy, jar_name=""):
    key, lane = _exit_stream_lane(proxy)
    t0 = time.monotonic()
    acquired = False
    try:
        try:
            await asyncio.wait_for(lane.acquire(), timeout=EXIT_STREAM_WAIT_SEC)
            acquired = True
        except asyncio.TimeoutError:
            raise RuntimeError(
                f"shared exit {key} saturated; no stream lane within {EXIT_STREAM_WAIT_SEC:.1f}s"
            )
        waited = time.monotonic() - t0
        if waited >= 0.05:
            log("INFO", f"[{jar_name}] shared-exit stream lane acquired · exit {key} · "
                        f"wait {waited:.2f}s · limit {EXIT_STREAM_CONCURRENCY}")
        async with session._action_lock:
            yield key
    finally:
        if acquired:
            lane.release()
REQUIRE_PROVIDER_FINISH = os.environ.get("BRIDGENA_REQUIRE_PROVIDER_FINISH", "1").strip().lower() not in ("0", "false", "no", "off")
ARENA_UI_STREAM_RECOVERY = os.environ.get("BRIDGENA_ARENA_UI_STREAM_RECOVERY", "1").strip().lower() not in ("0", "false", "no", "off")
ARENA_UI_RECOVERY_TIMEOUT_SEC = max(5.0, min(60.0, float(os.environ.get("BRIDGENA_ARENA_UI_RECOVERY_TIMEOUT_SEC", "30"))))
ARENA_HISTORY_RECOVERY_LIMIT = max(5, min(200, int(os.environ.get("BRIDGENA_ARENA_HISTORY_RECOVERY_LIMIT", "120"))))
ARENA_HISTORY_POLL_SEC = max(0.25, min(3.0, float(os.environ.get("BRIDGENA_ARENA_HISTORY_POLL_SEC", "0.65"))))
ARENA_HISTORY_STABLE_POLLS = max(2, min(8, int(os.environ.get("BRIDGENA_ARENA_HISTORY_STABLE_POLLS", "3"))))
ARENA_SALVAGE_QUICK_SEC = max(1.0, min(8.0, float(os.environ.get("BRIDGENA_ARENA_SALVAGE_QUICK_SEC", "3"))))
ARENA_POST_RESTART_SALVAGE_SEC = max(5.0, min(45.0, float(os.environ.get("BRIDGENA_ARENA_POST_RESTART_SALVAGE_SEC", "22"))))
ARENA_DELIVERED_WAIT_SEC = max(8.0, min(90.0, float(os.environ.get("BRIDGENA_ARENA_DELIVERED_WAIT_SEC", "40"))))
DUPLICATE_ACK_RECOVERY_BUDGET_SEC = max(8.0, min(45.0, float(os.environ.get("BRIDGENA_DUPLICATE_ACK_RECOVERY_BUDGET_SEC", "24"))))
FOLLOWUP_HTTP0_FINAL_RECOVERY_SEC = max(4.0, min(30.0, float(os.environ.get("BRIDGENA_FOLLOWUP_HTTP0_FINAL_RECOVERY_SEC", "12"))))
ARENA_SALVAGE_RECOVERY_WAIT_SEC = max(5.0, min(40.0, float(os.environ.get("BRIDGENA_ARENA_SALVAGE_RECOVERY_WAIT_SEC", "18"))))
UNDELIVERED_ENVELOPE_RETRY_MAX = max(0, min(2, int(os.environ.get("BRIDGENA_UNDELIVERED_ENVELOPE_RETRY_MAX", "1"))))
BOUND_VERIFICATION_READY_WAIT_SEC = max(5.0, min(90.0, float(os.environ.get("BRIDGENA_BOUND_VERIFICATION_READY_WAIT_SEC", "40"))))
THROTTLE_THREAD_REHOME = os.environ.get("BRIDGENA_THROTTLE_THREAD_REHOME", "1").strip().lower() not in ("0", "false", "no", "off")
CONTEXT_CAPSULE_MAX_CHARS = max(4000, min(MAX_PROMPT, int(os.environ.get("BRIDGENA_CONTEXT_CAPSULE_MAX_CHARS", str(min(MAX_PROMPT, 60000))))))
_thread_rehome_stats = {"armed": 0, "activated": 0, "inline": 0, "completed": 0, "missing_context": 0}
_thread_rehome_guard = threading.Lock()

def _bump_thread_rehome(key: str) -> None:
    with _thread_rehome_guard:
        _thread_rehome_stats[key] = int(_thread_rehome_stats.get(key, 0)) + 1

def _thread_rehome_snapshot() -> dict:
    with _thread_rehome_guard:
        return dict(_thread_rehome_stats)

_undelivered_retry_stats = {"attempted": 0, "succeeded": 0, "suppressed_trace_found": 0, "exhausted": 0}
_undelivered_retry_guard = threading.Lock()

def _bump_undelivered_retry(key: str) -> None:
    with _undelivered_retry_guard:
        _undelivered_retry_stats[key] = int(_undelivered_retry_stats.get(key, 0)) + 1

def _undelivered_retry_snapshot() -> dict:
    with _undelivered_retry_guard:
        return dict(_undelivered_retry_stats)

ARENA_UI_RECOVERY_STABLE_SEC = max(0.8, min(6.0, float(os.environ.get("BRIDGENA_ARENA_UI_RECOVERY_STABLE_SEC", "1.8"))))
ARENA_UI_STALE_GENERATING_ACCEPT_SEC = max(3.0, min(15.0, float(os.environ.get("BRIDGENA_UI_STALE_GENERATING_ACCEPT_SEC", "6.0"))))
PARTIAL_TERMINAL_MIN_CHARS = max(24, min(2000, int(os.environ.get("BRIDGENA_PARTIAL_TERMINAL_MIN_CHARS", "64"))))
_arena_ui_recovery_stats = {"attempted": 0, "recovered": 0, "history_api_recovered": 0, "history_api_match": 0, "history_index_waits": 0, "ui_recovered": 0, "post_restart_attempted": 0, "post_restart_recovered": 0, "recovery_wait_timeout": 0, "not_found": 0, "incomplete": 0, "navigation_failed": 0}
_arena_ui_recovery_stats_guard = threading.Lock()

def _bump_arena_ui_recovery(key: str) -> None:
    with _arena_ui_recovery_stats_guard:
        _arena_ui_recovery_stats[key] = int(_arena_ui_recovery_stats.get(key, 0)) + 1

def _arena_ui_recovery_snapshot() -> dict:
    with _arena_ui_recovery_stats_guard:
        return dict(_arena_ui_recovery_stats)

_account_failover_stats = {"attempted": 0, "successful_handoff": 0, "exhausted": 0, "session_401": 0, "predispatch": 0, "keeper_unready": 0}
_account_failover_stats_lock = threading.Lock()

def _bump_account_failover(key: str) -> None:
    with _account_failover_stats_lock:
        _account_failover_stats[key] = int(_account_failover_stats.get(key, 0)) + 1

def _account_failover_snapshot() -> dict:
    with _account_failover_stats_lock:
        return dict(_account_failover_stats)

_transport_guard_stats = {"probe_ok": 0, "probe_fail": 0, "recovered_before_post": 0, "recovery_timeout": 0}
_transport_guard_stats_lock = threading.Lock()

def _bump_transport_guard(key: str) -> None:
    with _transport_guard_stats_lock:
        _transport_guard_stats[key] = int(_transport_guard_stats.get(key, 0)) + 1

def _transport_guard_snapshot() -> dict:
    with _transport_guard_stats_lock:
        return dict(_transport_guard_stats)


def _record_reliability_outcome(success: bool, reason: str = "") -> dict:
    with _reliability_guard:
        _reliability_window.append((bool(success), str(reason or "")))
        total = len(_reliability_window)
        passed = sum(1 for ok, _ in _reliability_window if ok)
    rate = (passed / total) if total else 0.0
    if total >= 5:
        level = "OK" if rate >= _RELIABILITY_TARGET else "WARN"
        log(level, f"Reliability SLO · last {total} request(s) · success {rate*100:.1f}% · "
                   f"target {_RELIABILITY_TARGET*100:.0f}% · {'PASS' if rate >= _RELIABILITY_TARGET else 'BELOW TARGET'}")
    return {"sample": total, "successes": passed, "success_rate": round(rate, 4), "target": _RELIABILITY_TARGET}

def _reliability_snapshot() -> dict:
    with _reliability_guard:
        rows = list(_reliability_window)
    total = len(rows)
    passed = sum(1 for ok, _ in rows if ok)
    failures = {}
    for ok, reason in rows:
        if ok:
            continue
        key = str(reason or "unknown")
        failures[key] = failures.get(key, 0) + 1
    rate = (passed / total) if total else None
    return {"sample": total, "successes": passed,
            "success_rate": (round(rate, 4) if rate is not None else None),
            "target": _RELIABILITY_TARGET,
            "target_met": (bool(rate is not None and rate >= _RELIABILITY_TARGET)),
            "failures_by_reason": failures,
            "transport_guard": _transport_guard_snapshot(),
            "account_failover": _account_failover_snapshot(),
            "arena_ui_recovery": _arena_ui_recovery_snapshot(),
            "confirmed_absence_retry": _undelivered_retry_snapshot(),
            "thread_rehome": _thread_rehome_snapshot()}


def _bootable_keeper_jars(jars: Optional[List[dict]] = None) -> List[dict]:
    rows = list(jars if jars is not None else load_jars())
    return [
        j for j in rows
        if j.get("enabled", True)
        and ((j.get("email") and j.get("password")) or jar_has_auth(j))
    ]


def _configured_distinct_proxy_count() -> int:
    seen = set()
    try:
        for raw in get_proxy_pool():
            proxy = _normalize_proxy(raw)
            if not proxy:
                continue
            key = _proxy_hkey(proxy)
            if key:
                seen.add(key)
    except Exception:
        return 0
    return len(seen)


def _resolve_preferred_target(raw: str, auto_value: int) -> int:
    auto_value = max(1, int(auto_value or 1))
    raw = str(raw or "auto").strip().lower()
    if raw in {"", "auto", "dynamic", "accounts", "0"}:
        return auto_value
    try:
        return max(1, min(int(raw), auto_value))
    except Exception:
        return auto_value


def _api_preferred_targets() -> tuple:
    bootable = len(_bootable_keeper_jars())
    keeper_target = _resolve_preferred_target(
        _API_PREFERRED_KEEPERS_CONFIG, max(1, bootable)
    )
    proxy_count = _configured_distinct_proxy_count()
    auto_exit_target = 1 if proxy_count <= 0 else min(max(1, bootable), proxy_count)
    exit_target = _resolve_preferred_target(
        _API_PREFERRED_EXITS_CONFIG, max(1, auto_exit_target)
    )
    return keeper_target, exit_target


def _verification_refresh_age(sid: str) -> float:
    """Deterministically stagger lease refresh across the keeper fleet.

    Each keeper renews around 55-72% through its lease, preventing the whole
    fleet from expiring/rechecking in one synchronized wave.
    """
    sid = str(sid or "")
    digest = hashlib.sha256(sid.encode("utf-8")).digest()
    frac = int.from_bytes(digest[:2], "big") / 65535.0
    return _API_VERIFICATION_TTL * (0.55 + 0.17 * frac)


def _api_keeper_lease_age(sid: Optional[str]) -> float:
    if not sid:
        return float("inf")
    ts = _api_verified_keepers.get(str(sid), 0.0)
    if not ts:
        return float("inf")
    return max(0.0, time.monotonic() - ts)


def _api_keeper_needs_refresh(sid: Optional[str]) -> bool:
    if not sid:
        return True
    sid = str(sid)
    return _api_keeper_lease_age(sid) >= _verification_refresh_age(sid)


def _wake_verification_scheduler() -> None:
    try:
        _verification_wakeup_event.set()
    except Exception:
        pass


def _api_keeper_verified(sid: Optional[str]) -> bool:
    if not sid:
        return False
    sid = str(sid)
    if time.monotonic() < _api_keeper_quarantine_until.get(sid, 0.0):
        return False
    ts = _api_verified_keepers.get(sid, 0.0)
    return bool(ts and (time.monotonic() - ts) <= _API_VERIFICATION_TTL)

def _api_keeper_exit_key(sid: str) -> str:
    s = keeper.sessions.get(str(sid))
    raw = getattr(s, "_used_proxy", "") if s else ""
    return _proxy_hkey(raw) if raw else f"direct:{sid}"

def _verified_exit_count() -> int:
    return len({_api_keeper_exit_key(sid) for sid in _api_verified_keepers if _api_keeper_verified(sid)})

def _quarantine_api_keeper(sid: Optional[str], reason: str, seconds: Optional[float] = None) -> None:
    if not sid:
        return
    sid = str(sid)
    _api_verified_keepers.pop(sid, None)
    _api_keeper_quarantine_until[sid] = time.monotonic() + float(seconds or _API_FAILURE_QUARANTINE_S)
    _refresh_api_ready_event()
    _wake_verification_scheduler()
    log("WARN", f"[{sid}] API keeper quarantined · {reason} · {int(seconds or _API_FAILURE_QUARANTINE_S)}s")

def _verified_keeper_count() -> int:
    now = time.monotonic()
    stale = [sid for sid, ts in _api_verified_keepers.items()
             if not ts or (now - ts) > _API_VERIFICATION_TTL]
    for sid in stale:
        _api_verified_keepers.pop(sid, None)
    return sum(1 for sid in _api_verified_keepers if keeper_session_ready(keeper.sessions.get(sid)))

def _refresh_api_ready_event() -> None:
    verified = _verified_keeper_count()
    exits = _verified_exit_count()
    enough_keepers = verified >= _API_ADMISSION_MIN_KEEPERS
    enough_exits = exits >= _API_ADMISSION_MIN_EXITS
    if bool(get_models()) and enough_keepers and enough_exits:
        _api_ready_event.set()
    else:
        _api_ready_event.clear()

def _mark_api_keeper_unready(sid: Optional[str], reason: str = "") -> None:
    if sid:
        _api_verified_keepers.pop(str(sid), None)
    _refresh_api_ready_event()
    _wake_verification_scheduler()
    if reason and sid:
        log("WARN", f"[{sid}] API readiness revoked · {reason}")

def keeper_session_ready(session, *, warmed: bool = True) -> bool:
    """True only when a keeper is safe to receive API/token work."""
    if not (session and session.running and getattr(session, "status", "") == "running"):
        return False
    page = getattr(session, "page", None)
    if not page or page.is_closed():
        return False
    return not warmed or time.monotonic() >= getattr(session, "ready_at", 0.0)

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
    if keeper_session_ready(s):
        return True
    return False

def to_playwright_cookies(cookies: list) -> list:
    out = []
    for c in cookies:
        name, value = c.get("name", ""), c.get("value", "")
        if not name or not value:
            continue
        item = {
            "name": name, "value": value,
            "domain": c.get("domain") or "localhost",
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
        }
        exp = c.get("expirationDate") or c.get("expires")
        if exp and isinstance(exp, (int, float)) and exp > 0:
            item["expires"] = exp
        out.append(item)
    return out

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

def default_state() -> dict:
    return {
        "conversations": {}, "usage_stats": {}, "rate_buckets": {},
        "blocked_models": [], "last_refresh": 0, "refresh_started": 0,
        "keeper_pid": None, "keeper_heartbeat": 0, "keeper_status": [],
    }

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

def _proxy_health_path() -> str:
    base = _proxies_file()
    d = os.path.dirname(os.path.abspath(base)) if base else os.getcwd()
    return os.path.join(d, PROXY_HEALTH_FILE)

def playwright_proxy_from_url(proxy_url: str) -> Optional[dict]:
    """Convert proxy URL to Playwright proxy dict.

    Authenticated SOCKS lines are routed through the local shim (Chromium cannot
    send SOCKS credentials at all); HTTP proxies keep Playwright-native
    username/password.
    """
    if not proxy_url:
        return None
    try:
        from urllib.parse import urlparse
        u = urlparse(proxy_url)
        if (u.scheme or "") in _SHIM_SCHEMES and u.username:
            sh = shim_proxy_for(proxy_url)
            if sh:
                out = {"server": sh}
                if LOCAL_UPSTREAM:
                    out["bypass"] = "localhost,127.0.0.1,[::1]"
                return out
            log("WARN", f"socks shim unavailable for {u.hostname}:{u.port} — browser goes direct (curl path still uses the proxy)")
            return None
        # Chromium speaks "socks5://" (which for Chromium = send the hostname,
        # resolve at gateway) and knows no "socks5h". Map the scheme name here,
        # semantics already match.
        _sch = (u.scheme or "").lower()
        if _sch == "socks5h":
            _sch = "socks5"
        server = f"{_sch}://{u.hostname}"
        if u.port:
            server += f":{u.port}"
        out = {"server": server}
        if u.username:
            out["username"] = u.username
        if u.password:
            out["password"] = u.password
        if LOCAL_UPSTREAM:
            out["bypass"] = "localhost,127.0.0.1,[::1]"
        return out
    except Exception:
        return None

def atomic_write(path: str, data: Any) -> None:
    tmp = f"{path}.tmp{os.getpid()}_{secrets.token_hex(4)}"
    try:
        with open(tmp, "w", encoding="utf-8") as stream:
            json.dump(data, stream, separators=(",", ":"), ensure_ascii=False)
            if DURABLE_WRITES:
                stream.flush()
                os.fsync(stream.fileno())
        os.replace(tmp, path)
        if DURABLE_WRITES:
            try:
                directory_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass

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

async def get_initial_data() -> list:
    """Backward-compatible wrapper for callers that just want the model list
    (boot sequence, periodic refresher) without the structured result."""
    result = await refresh_model_catalog()
    return result["models"]

async def refresh_models_via_worker(worker):
    """Refresh Arena's model catalog from live Next.js/Flight state.

    v4.1.4 deliberately scans several page-state representations instead of
    assuming `initialModels` lives in one exact serialized location.
    """
    log("INFO", f"[{worker.name}] Refreshing models via live browser state...")
    try:
        async with worker._action_lock:
            await worker.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=30000)
            try:
                await worker.page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception:
                pass

            body = await worker.page.content()
            try:
                flight_obj = await worker.page.evaluate("() => self.__next_f || []")
            except Exception:
                flight_obj = []
            try:
                script_texts = await worker.page.evaluate(
                    "() => Array.from(document.scripts).map(s => s.textContent || '').filter(Boolean)"
                )
            except Exception:
                script_texts = []

        import html as _model_html

        def _balanced_arrays_after_key(src: str, keys=("initialModels", "models")):
            if not src:
                return []
            found = []
            for key in keys:
                for needle in (f'"{key}"', f"'{key}'"):
                    pos = 0
                    while True:
                        pos = src.find(needle, pos)
                        if pos < 0:
                            break
                        start = src.find("[", pos + len(needle))
                        if start < 0:
                            break
                        depth = 0
                        quoted = False
                        quote_ch = ""
                        escaped = False
                        for i in range(start, len(src)):
                            ch = src[i]
                            if quoted:
                                if escaped:
                                    escaped = False
                                elif ch == "\\":
                                    escaped = True
                                elif ch == quote_ch:
                                    quoted = False
                            elif ch in ('"', "'"):
                                quoted = True
                                quote_ch = ch
                            elif ch == "[":
                                depth += 1
                            elif ch == "]":
                                depth -= 1
                                if depth == 0:
                                    raw = src[start:i+1]
                                    try:
                                        value = json.loads(raw)
                                        if isinstance(value, list):
                                            found.append(value)
                                    except Exception:
                                        pass
                                    break
                        pos += len(needle)
            return found

        def _looks_like_model_entry(v):
            if not isinstance(v, dict):
                return False
            ident = (
                v.get("id") or v.get("publicName") or v.get("displayName")
                or v.get("modelDisplayName") or v.get("label") or v.get("name")
            )
            if not isinstance(ident, str) or not ident.strip():
                return False
            return any(k in v for k in (
                "publicName", "displayName", "modelDisplayName", "display_name",
                "label", "title", "organization", "capabilities", "provider",
                "modelOrganization", "access", "availability", "outputCapabilities"
            )) or ("model" in str(v.get("type", "")).lower())

        def _candidate_score(arr):
            if not isinstance(arr, list) or not arr:
                return 0
            dicts = [x for x in arr if isinstance(x, dict)]
            if not dicts:
                return 0
            good = sum(1 for x in dicts if _looks_like_model_entry(x))
            # Weight both absolute size and model-entry density.
            return good * 1000 + int((good / max(1, len(dicts))) * 100)

        candidates = []

        # Direct Python object from __next_f, recursively inspected.
        def _walk(obj, depth=0):
            if depth > 12:
                return
            if isinstance(obj, list):
                if obj:
                    candidates.append(("flight-object", obj))
                for x in obj:
                    _walk(x, depth + 1)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    if k in ("initialModels", "models") and isinstance(v, list):
                        candidates.append((f"flight-key:{k}", v))
                    _walk(v, depth + 1)
            elif isinstance(obj, str) and len(obj) > 80:
                for arr in _balanced_arrays_after_key(obj):
                    candidates.append(("flight-string", arr))
                # Some Flight entries themselves contain JSON strings.
                try:
                    parsed = json.loads(obj)
                except Exception:
                    parsed = None
                if parsed is not None and parsed is not obj:
                    _walk(parsed, depth + 1)

        _walk(flight_obj)

        sources = [("html", body), ("html-unescaped", _model_html.unescape(body))]
        for i, s in enumerate(script_texts or []):
            sources.append((f"script-{i}", s))

        for label, src in sources:
            if not src:
                continue
            variants = [src]
            if '\\"' in src:
                variants.append(src.replace('\\"', '"').replace('\\\\', '\\'))
            for variant in variants:
                for arr in _balanced_arrays_after_key(variant):
                    candidates.append((label, arr))

        # Last-resort scan of JSON script blocks: recursively discover arrays
        # containing model-shaped objects even if Arena renamed `initialModels`.
        for i, s in enumerate(script_texts or []):
            st = (s or "").strip()
            if not st or st[0] not in "[{":
                continue
            try:
                parsed = json.loads(st)
            except Exception:
                continue
            def _collect_json(obj, depth=0):
                if depth > 10:
                    return
                if isinstance(obj, list):
                    if _candidate_score(obj):
                        candidates.append((f"json-script-{i}", obj))
                    for x in obj:
                        _collect_json(x, depth+1)
                elif isinstance(obj, dict):
                    for v in obj.values():
                        _collect_json(v, depth+1)
            _collect_json(parsed)

        candidates = [(label, arr) for label, arr in candidates if _candidate_score(arr) > 0]
        candidates.sort(key=lambda item: _candidate_score(item[1]), reverse=True)

        if not candidates:
            log("WARN", f"[{worker.name}] Model refresh found no model-shaped arrays in Flight/HTML/scripts")
            return []

        source_label, models_data = candidates[0]
        log("INFO", f"[{worker.name}] Model extractor selected {source_label} · raw entries {len(models_data)} · candidates {len(candidates)}")

        try:
            atomic_write(MODELS_RAW_DEBUG_FILE, models_data)
        except Exception as e:
            log("WARN", f"Failed to write raw model debug dump: {e}")

        # Learn the names Arena actually renders in its model picker. Catalog
        # `id` / `publicName` values are not guaranteed to be selectable UI
        # strings (e.g. `glm-5.2` vs `glm-5.2 (max)`).
        ui_labels = []
        try:
            async with worker._action_lock:
                page = worker.page
                trigger = await page.evaluate("""
                () => {
                  const vis = e => {
                    if (!e) return false;
                    const r=e.getBoundingClientRect(),s=getComputedStyle(e);
                    return r.width>4 && r.height>4 && s.display!=='none' && s.visibility!=='hidden';
                  };
                  const txt=e=>(e.innerText||e.textContent||'').trim();
                  const nodes=[...document.querySelectorAll('button,[role="button"]')].filter(vis);
                  const scored=nodes.map((e,i)=>{
                    const blob=((e.getAttribute('aria-label')||'')+' '+(e.getAttribute('data-testid')||'')+' '+txt(e)).toLowerCase();
                    let score=0;
                    if(/select model|choose model|model selector/.test(blob))score+=100;
                    if(/\\bmodel\\b/.test(blob))score+=50;
                    if(e.getAttribute('aria-haspopup'))score+=15;
                    if(/^(max|auto|battle|side by side)$/i.test(txt(e)))score+=12;
                    return {i,score};
                  }).sort((a,b)=>b.score-a.score);
                  return scored[0] && scored[0].score>=12 ? scored[0].i : -1;
                }
                """)
                if isinstance(trigger, int) and trigger >= 0:
                    buttons = page.locator('button,[role="button"]')
                    if trigger < await buttons.count():
                        await buttons.nth(trigger).click(timeout=3000)
                        await page.wait_for_timeout(450)
                        ui_labels = await page.evaluate("""
                        () => {
                          const vis=e=>{
                            if(!e)return false;
                            const r=e.getBoundingClientRect(),s=getComputedStyle(e);
                            return r.width>4&&r.height>4&&s.display!=='none'&&s.visibility!=='hidden';
                          };
                          const clean=s=>(s||'').replace(/\\s+/g,' ').trim();
                          const sels=[
                            '[role="option"]','[role="menuitem"]','[role="menuitemradio"]',
                            '[role="listbox"] button','[role="menu"] button',
                            '[data-radix-popper-content-wrapper] button',
                            '[data-radix-popper-content-wrapper] [role="option"]',
                            '[data-radix-popper-content-wrapper] [role="menuitem"]'
                          ];
                          const out=[];
                          for(const sel of sels){
                            for(const e of document.querySelectorAll(sel)){
                              if(!vis(e))continue;
                              const t=clean(e.innerText||e.textContent);
                              if(!t||t.length>140)continue;
                              if(/^(search|close|cancel|manage|learn more)$/i.test(t))continue;
                              if(!out.includes(t))out.push(t);
                            }
                          }
                          return out.slice(0,1000);
                        }
                        """)
                        try:
                            await page.keyboard.press("Escape")
                        except Exception:
                            pass
        except Exception as e:
            log("WARN", f"[{worker.name}] Arena UI model-label scan skipped: {type(e).__name__}: {e}")

        def _ui_key(s: str) -> str:
            s = str(s or "").strip().lower()
            s = re.sub(r"[^a-z0-9]+", " ", s)
            return re.sub(r"\\s+", " ", s).strip()

        def _base_ui_key(s: str) -> str:
            # Parenthetical Arena tier suffixes such as "(max)" should not stop
            # us matching the catalog slug to the visible picker label.
            s = re.sub(r"\\s*\\([^)]*\\)\\s*$", "", str(s or "")).strip()
            return _ui_key(s)

        if ui_labels:
            normalized_ui = [(label, _ui_key(label), _base_ui_key(label)) for label in ui_labels]
            matched = 0
            for m in models_data:
                if not isinstance(m, dict):
                    continue
                aliases = []
                for key in ("displayName","modelDisplayName","display_name","label","title","publicName","name","id"):
                    value = str(m.get(key) or "").strip()
                    if value and value not in aliases:
                        aliases.append(value)
                best = None
                best_score = -1
                for alias in aliases:
                    ak, ab = _ui_key(alias), _base_ui_key(alias)
                    if not ak:
                        continue
                    for label, lk, lb in normalized_ui:
                        score = -1
                        if ak == lk:
                            score = 1000
                        elif ab and ab == lb:
                            score = 950
                        elif lk.startswith(ak + " ") or ak.startswith(lk + " "):
                            score = 800
                        elif lb.startswith(ab + " ") or ab.startswith(lb + " "):
                            score = 760
                        if score > best_score:
                            best_score, best = score, label
                if best and best_score >= 760:
                    m["uiName"] = best
                    matched += 1
            log("INFO", f"[{worker.name}] Arena UI model labels learned · visible={len(ui_labels)} · matched={matched}")
        else:
            log("WARN", f"[{worker.name}] Arena UI model-label scan found no visible picker entries")

        filtered = []
        hidden = []
        for m in models_data:
            if not isinstance(m, dict):
                continue
            name = model_name(m) or m.get("id") or m.get("name")
            if not name:
                continue
            if not is_model_selectable(m):
                hidden.append(name)
                continue
            caps = (m.get("capabilities") or {}).get("outputCapabilities") or m.get("outputCapabilities") or {}
            if isinstance(caps, dict) and caps.get("text") is False:
                hidden.append(name)
                continue
            filtered.append(m)

        # De-duplicate by canonical name while preserving current catalog order.
        deduped, seen = [], set()
        for m in filtered:
            n = model_name(m).strip()
            if n and n not in seen:
                seen.add(n)
                deduped.append(m)

        log("INFO", f"Model filter kept={len(deduped)} hidden={len(hidden)} hidden_sample={hidden[:20]}")

        if not _valid_model_catalog(deduped):
            log("WARN", f"Model extractor produced only {len(_catalog_names(deduped))} usable unique model(s); current catalog retained")
            return []

        before = set(_catalog_names(get_models()))
        after = set(_catalog_names(deduped))
        save_models(deduped)
        added = sorted(after - before)
        removed = sorted(before - after)
        log("OK", f"Model catalog refreshed via worker ({len(after)} unique models · +{len(added)} / -{len(removed)})")
        if added:
            log("INFO", f"Model catalog added sample: {added[:20]}")
        if removed:
            log("INFO", f"Model catalog removed sample: {removed[:20]}")
        return deduped

    except Exception as e:
        log("ERROR", f"Failed to refresh models: {type(e).__name__}: {e}")
        return []

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

def _proxies_file() -> Optional[str]:
    for candidate in ("proxies.txt",
                      os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt"),
                      os.path.join(os.getcwd(), "proxies.txt")):
        if os.path.isfile(candidate):
            return candidate
    return None

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

def save_conversation_ui_url(key: str, model_name: str, ui_url: str) -> None:
    """Cache a browser-visible Arena thread URL discovered during recovery."""
    ui_url = str(ui_url or "").strip()
    if not ui_url:
        return
    def fn(state: dict):
        conv = state.get("conversations", {}).get(key)
        if not isinstance(conv, dict):
            return
        arena = conv.get("arena")
        if not isinstance(arena, dict):
            return
        model_state = arena.get(model_name)
        if not isinstance(model_state, dict):
            return
        model_state["ui_url"] = ui_url[:1000]
        conv["updated"] = time.time()
    try:
        mutate_state(fn)
    except Exception as exc:
        log("WARN", f"Conversation UI URL cache failed: {type(exc).__name__}: {exc}")


def _trim_context_capsule(value: str) -> str:
    value = str(value or "").strip()
    if len(value) <= CONTEXT_CAPSULE_MAX_CHARS:
        return value
    tail = value[-CONTEXT_CAPSULE_MAX_CHARS:]
    cut = tail.find("\n\n")
    return tail[cut + 2:] if cut >= 0 else tail


def save_context_capsule(chat_id: str, model_name: str, transcript: str,
                         *, source: str = "client-transcript") -> None:
    """Persist private continuity context for upstream thread replacement.

    This is server-side state only. Nothing is appended to the assistant's
    visible stream, so there are no magic <context> tags that can leak into the
    customer's answer or confuse tool/JSON output.
    """
    transcript = _trim_context_capsule(transcript)
    if not transcript:
        return

    def fn(state: dict):
        convs = state.setdefault("conversations", {})
        conv = convs.setdefault(chat_id, {"arena": {}, "updated": time.time()})
        capsules = conv.setdefault("context_capsules", {})
        capsules[model_name] = {
            "text": transcript,
            "source": str(source or "unknown")[:80],
            "updated": time.time(),
        }
        conv["updated"] = time.time()

    try:
        mutate_state(fn)
    except Exception as exc:
        log("WARN", f"Context capsule save failed: {type(exc).__name__}: {exc}")


def load_context_capsule(chat_id: str, model_name: str) -> str:
    conv = get_conversation(chat_id) or {}
    row = (conv.get("context_capsules") or {}).get(model_name) or {}
    return _trim_context_capsule(row.get("text") or "")


def append_context_capsule_answer(chat_id: str, model_name: str,
                                  base_transcript: str, answer: str) -> None:
    answer = str(answer or "").strip()
    if not answer:
        return
    base = str(base_transcript or load_context_capsule(chat_id, model_name) or "").strip()
    rendered = (base + "\n\nAssistant: " + answer).strip() if base else ("Assistant: " + answer)
    save_context_capsule(chat_id, model_name, rendered, source="completed-turn")


def arm_throttle_thread_rehome(chat_id: str, model_name: str, jar_id: str,
                               delay_sec: float, context_text: str) -> bool:
    """Mark the bound upstream conversation for replacement AFTER cooldown.

    We preserve the same model and same configured account. This does not use a
    fresh thread to bypass an active throttle: the rehome becomes eligible only
    after the upstream cooldown/Retry-After has elapsed.
    """
    context_text = _trim_context_capsule(context_text or load_context_capsule(chat_id, model_name))
    if not context_text:
        _bump_thread_rehome("missing_context")
        return False

    save_context_capsule(chat_id, model_name, context_text, source="throttle-rehome")
    not_before = time.time() + max(0.0, float(delay_sec or 0.0))

    def fn(state: dict):
        conv = state.setdefault("conversations", {}).setdefault(
            chat_id, {"arena": {}, "updated": time.time()}
        )
        old = ((conv.get("arena") or {}).get(model_name) or {})
        rehomes = conv.setdefault("thread_rehome", {})
        rehomes[model_name] = {
            "reason": "upstream-rate-limit",
            "jar_id": str(jar_id or old.get("jar_id") or ""),
            "old_arena_id": str(old.get("arena_id") or ""),
            "not_before": not_before,
            "armed": time.time(),
            "model": model_name,
        }
        conv["updated"] = time.time()

    try:
        mutate_state(fn)
        _bump_thread_rehome("armed")
        log("WARN", f"Thread rehome armed · {str(chat_id)[:10]}… · model {model_name} · "
                    f"same account {str(jar_id)[:10]}… · eligible in {max(0.0, delay_sec):.1f}s")
        return True
    except Exception as exc:
        log("WARN", f"Thread rehome arm failed: {type(exc).__name__}: {exc}")
        return False


def get_throttle_thread_rehome(chat_id: str, model_name: str) -> Optional[dict]:
    conv = get_conversation(chat_id) or {}
    row = (conv.get("thread_rehome") or {}).get(model_name)
    return dict(row) if isinstance(row, dict) else None


def clear_throttle_thread_rehome(chat_id: str, model_name: str) -> None:
    def fn(state: dict):
        conv = state.get("conversations", {}).get(chat_id)
        if not isinstance(conv, dict):
            return
        rehomes = conv.get("thread_rehome")
        if isinstance(rehomes, dict):
            rehomes.pop(model_name, None)
        conv["updated"] = time.time()
    try:
        mutate_state(fn)
    except Exception:
        pass


def clear_conversation_model(key: str, model_name: str) -> None:
    """Remove only a stale upstream binding; never touch browser-local text."""
    def fn(state: dict):
        conv = state.get("conversations", {}).get(key)
        if not isinstance(conv, dict):
            return
        arena = conv.get("arena")
        if isinstance(arena, dict):
            arena.pop(model_name, None)
        if conv.get("model") == model_name:
            conv["model"] = None
        conv["updated"] = time.time()
    try:
        mutate_state(fn)
    except Exception as e:
        log("WARN", f"Conversation binding clear failed: {e}")

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

_captcha_failed_jars: dict = {}

def acquire_jar(prefer_live: bool = True, exclude: Optional[set] = None) -> Optional[dict]:
    """Pick the best jar for a request.

    Priority when prefer_live=True (default, needed for new chats / captcha):
      1. Not recently rejected by reCAPTCHA on its exit IP
      2. Enabled + auth + has a running live (headed) keeper session
      3. Enabled + auth + has any running keeper session
      4. Fully available jar (not rate-limited, has auth cookies)
      5. Last resort: any enabled jar that still has a live session

    This makes the browser-bridge path the default whenever possible so we
    never need to scrape reCAPTCHA tokens from a page that isn't attached.
    """
    now = time.time()
    chosen = {}

    def _score(j: dict) -> tuple:
        """Higher is better. Returns a sort key (prefer higher)."""
        sid = j.get("id")
        s = keeper.sessions.get(sid) if sid else None
        has_session = keeper_session_ready(s)
        is_live = has_session and (not getattr(s, "headless", True))
        healthy = bool(s and s.last_health_ok and (now - s.last_health_ok) < 900)
        available = jar_available(j, now)
        captcha_clean = 1 if (now - _captcha_failed_jars.get(sid, 0.0) > 300) else 0
        api_verified = 1 if _api_keeper_verified(sid) else 0
        idle = 1 if (not s or not getattr(s, "_action_lock", None) or not s._action_lock.locked()) else 0
        active = int(getattr(s, "active_requests", 0) or 0) if s else 0
        load_score = -active
        # last_used is inverted so older = higher priority
        recency = -float(j.get("last_used", 0) or 0)
        return (
            api_verified,
            captcha_clean,
            idle,
            1 if (prefer_live and is_live and healthy) else 0,
            1 if (prefer_live and has_session and healthy) else 0,
            1 if available else 0,
            1 if has_session else 0,
            load_score,
            recency,
        )

    def pick(jars: list):
        candidates = [j for j in jars if j.get("enabled", True) and (not exclude or j.get("id") not in exclude)]
        if not candidates:
            return
        # Sort by score descending
        candidates.sort(key=_score, reverse=True)
        best = candidates[0]
        # Only accept if it at least has auth or a live session
        sid = best.get("id")
        s = keeper.sessions.get(sid) if sid else None
        has_session = keeper_session_ready(s)
        if _api_ready_event.is_set() and not _api_keeper_verified(sid):
            verified = [j for j in candidates
                        if _api_keeper_verified(j.get("id"))
                        and keeper_session_ready(keeper.sessions.get(j.get("id")))
                        and not (getattr(keeper.sessions.get(j.get("id")), "_action_lock", None)
                                 and keeper.sessions.get(j.get("id"))._action_lock.locked())]
            if verified:
                best = sorted(verified, key=_score, reverse=True)[0]
                sid = best.get("id")
                s = keeper.sessions.get(sid) if sid else None
                has_session = keeper_session_ready(s)
        if not jar_has_auth(best) and not has_session:
            # Try to find any jar that has either auth cookies or a live session
            for j in candidates[1:]:
                sj = keeper.sessions.get(j.get("id"))
                if jar_has_auth(j) or keeper_session_ready(sj):
                    best = j
                    break
            else:
                return
        best["last_used"] = now
        best["usage_count"] = best.get("usage_count", 0) + 1
        chosen["jar"] = best

    mutate_jars(pick)
    return chosen.get("jar")

def acquire_ready_jar(exclude: Optional[set] = None) -> Optional[dict]:
    """Select a different authenticated keeper that is ready right now."""
    now = time.time()
    excluded = set(exclude or ())
    candidates = []
    for jar in load_jars():
        sid = jar.get("id")
        if (not sid or sid in excluded or not jar.get("enabled", True)
                or not jar_has_auth(jar)):
            continue
        session = keeper.sessions.get(sid)
        if not keeper_session_ready(session):
            continue
        if getattr(session, "_action_lock", None) and session._action_lock.locked():
            continue
        if time.monotonic() < _api_keeper_quarantine_until.get(str(sid), 0.0):
            continue
        if not _api_keeper_verified(sid):
            continue
        candidates.append(jar)
    if not candidates:
        return None
    candidates.sort(key=lambda jar: (
        0 if now - _captcha_failed_jars.get(jar.get("id"), 0.0) > 300 else 1,
        int(getattr(keeper.sessions.get(jar.get("id")), "active_requests", 0) or 0),
        float(jar.get("last_used", 0) or 0),
    ))
    selected = candidates[0]
    selected_id = selected["id"]

    def mark_used(jars):
        for jar in jars:
            if jar.get("id") == selected_id:
                jar["last_used"] = now
                jar["usage_count"] = int(jar.get("usage_count", 0) or 0) + 1
                break
    mutate_jars(mark_used)
    return selected

async def allocate_unique_keeper_proxies(jars: Optional[List[dict]] = None) -> dict:
    """Pre-allocate distinct healthy upstream proxies to keeper accounts.

    This runs before keeper browsers launch so stale sticky assignments cannot
    collapse several accounts onto one local SOCKS shim. The configured pool is
    deduplicated by normalized upstream proxy, fully probed once, and distinct
    healthy proxies are assigned across enabled keeper accounts whenever enough
    capacity exists.

    Returns allocation diagnostics; proxy credentials are never logged.
    """
    jars = list(jars or load_jars())
    keepers = [
        j for j in jars
        if j.get("enabled", True)
        and j.get("keeper_enabled", True)
        and ((j.get("email") and j.get("password")) or jar_has_auth(j))
    ]

    raw_pool = get_proxy_pool()
    normalized_pool: List[str] = []
    seen = set()
    for raw in raw_pool:
        proxy = _normalize_proxy(raw)
        if not proxy:
            continue
        key = _proxy_hkey(proxy)
        if key in seen or key in _QUARANTINED_KEYS:
            continue
        seen.add(key)
        normalized_pool.append(proxy)

    stats = {
        "configured": len(raw_pool),
        "unique": len(normalized_pool),
        "live": 0,
        "keepers": len(keepers),
        "distinct_assigned": 0,
    }

    if not keepers or not normalized_pool:
        log("WARN", f"Proxy allocator · configured {len(raw_pool)} · unique {len(normalized_pool)} · "
                    f"keepers {len(keepers)} · nothing to allocate")
        return stats

    # Probe the whole configured pool once at startup. This is intentionally
    # different from request-time bounded probing: startup has time to establish
    # the actual capacity map before any browser is pinned to an exit.
    loop = asyncio.get_running_loop()

    def _probe_all():
        results = []
        workers = max(1, min(PROBE_MAX_PARALLEL, len(normalized_pool)))
        with _cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_proxy_probe, proxy): proxy for proxy in normalized_pool}
            for future in _cf.as_completed(futs):
                proxy = futs[future]
                try:
                    ok, ms = future.result()
                except Exception:
                    ok, ms = False, -1
                results.append((proxy, bool(ok), int(ms or -1)))
        return results

    try:
        probe_results = await loop.run_in_executor(None, _probe_all)
    except Exception as exc:
        log("WARN", f"Proxy allocator · full-pool probe failed: {redact(str(exc))}")
        probe_results = []

    now = time.time()
    live: List[str] = []
    for proxy, ok, ms in probe_results:
        _proxy_probe_cache[proxy] = (
            ok,
            now + (PROBE_OK_TTL if ok else 120),
        )
        _proxy_health_record(proxy, ok, ms if ms > 0 else 0, source="startup-allocator")
        if ok and _proxy_hkey(proxy) not in _flagged_and_quarantined(False):
            if ms > 0:
                _proxy_latency[proxy] = ms
            live.append(proxy)

    # Prefer lower-latency exits, but allocation is one-pass and unique: unlike
    # request-time selection, sorting cannot cause every keeper to reuse #1.
    live.sort(key=lambda proxy: (
        _proxy_latency.get(proxy, 10**9),
        _proxy_hkey(proxy),
    ))
    stats["live"] = len(live)

    if not live:
        log("WARN", f"Proxy allocator · configured {len(raw_pool)} · unique {len(normalized_pool)} · "
                    f"live 0 · keepers {len(keepers)}")
        return stats

    # Preserve an existing sticky assignment only when it is live and unique.
    # Duplicate sticky pins are deliberately broken when spare live exits exist.
    assigned: Dict[str, str] = {}
    used = set()
    keeper_ids = {j.get("id") for j in keepers}

    for jar in keepers:
        sid = jar.get("id")
        sticky = _normalize_proxy(jar.get("proxy") or jar.get("_last_proxy") or "")
        if not sid or not sticky or sticky not in live or sticky in used:
            continue
        assigned[sid] = sticky
        used.add(sticky)

    remaining = [proxy for proxy in live if proxy not in used]
    rr = 0
    for jar in keepers:
        sid = jar.get("id")
        if not sid or sid in assigned:
            continue
        if remaining:
            chosen = remaining.pop(0)
        else:
            # If there are fewer healthy exits than keepers, reuse is explicit
            # and evenly distributed instead of silently collapsing onto one.
            chosen = live[rr % len(live)]
            rr += 1
        assigned[sid] = chosen
        used.add(chosen)

    # Persist the allocation atomically in one jars mutation.
    def _persist(jars_list):
        for jar in jars_list:
            sid = jar.get("id")
            if sid in assigned:
                jar["proxy"] = assigned[sid]
                jar["_last_proxy"] = assigned[sid]
    mutate_jars(_persist)

    distinct = len(set(assigned.values()))
    stats["distinct_assigned"] = distinct
    log("INFO", f"Proxy allocator · configured {len(raw_pool)} · unique {len(normalized_pool)} · "
                f"live {len(live)} · keepers {len(keepers)} · distinct assigned {distinct}")

    # Log only opaque upstream identity + eventual local shim endpoint.
    for jar in keepers:
        sid = jar.get("id")
        proxy = assigned.get(sid)
        if not proxy:
            continue
        label = jar.get("label") or jar.get("email") or sid
        opaque = _proxy_hkey(proxy)[:10]
        try:
            shim = shim_proxy_for(proxy) or "direct-upstream"
        except Exception:
            shim = "shim-unavailable"
        log("INFO", f"[{redact(str(label))}] proxy allocation · upstream {opaque}… · route {redact(str(shim))}")

    if len(live) >= len(keepers) and distinct < len(keepers):
        log("WARN", f"Proxy allocator invariant failed · {len(live)} live exits for {len(keepers)} keepers "
                    f"but only {distinct} distinct assignments")
    elif len(live) < len(keepers):
        log("WARN", f"Proxy allocator capacity shortfall · {len(live)} live exits for {len(keepers)} keepers; "
                    "some sharing is unavoidable")

    return stats


async def rebind_keeper_fleet_to_proxy_pool(reason: str = "proxy pool changed") -> dict:
    """Allocate current live proxies, then restart only keepers whose route changed.

    Chromium's proxy is fixed at browser-context launch. Updating jar["proxy"]
    alone does not move an already-running keeper, so a route change has to be
    applied with a controlled browser restart.
    """
    stats = await allocate_unique_keeper_proxies(load_jars())

    jars = {j.get("id"): j for j in load_jars()}
    changed = []
    unchanged = []

    for jid, session in list(keeper.sessions.items()):
        jar = jars.get(jid) or {}
        desired = _normalize_proxy(jar.get("proxy") or jar.get("_last_proxy") or "") or ""
        current = _normalize_proxy(getattr(session, "_used_proxy", "") or "") or ""

        if desired and desired != current:
            changed.append((jid, session, current, desired))
        else:
            unchanged.append(jid)

    if not changed:
        log("INFO", f"Proxy rebind · {reason} · no keeper restart required · "
                    f"distinct assigned {stats.get('distinct_assigned', 0)}")
        stats["keepers_restarting"] = 0
        stats["keepers_unchanged"] = len(unchanged)
        return stats

    log("INFO", f"Proxy rebind · {reason} · applying {len(changed)} changed keeper route(s)")

    # Restarts are intentionally bounded. Persistent Chromium startup is heavy
    # and restarting the whole fleet in one burst makes auth hydration flaky.
    restart_gate = asyncio.Semaphore(2)

    async def _apply(item):
        jid, session, current, desired = item
        async with restart_gate:
            try:
                session._tried_proxies.clear()
                session._direct_tried = False
                log("INFO", f"[{session.name}] proxy route changed · "
                            f"{_proxy_hkey(current) if current else 'direct'} → {_proxy_hkey(desired)} · restarting keeper")
                await session.restart()
                return True
            except Exception as exc:
                log("ERROR", f"[{session.name}] proxy rebind restart failed: {type(exc).__name__}: {exc}")
                return False

    results = await asyncio.gather(*(_apply(item) for item in changed), return_exceptions=False)
    applied = sum(1 for ok in results if ok)

    stats["keepers_restarting"] = len(changed)
    stats["keepers_rebound"] = applied
    stats["keepers_unchanged"] = len(unchanged)

    log("OK", f"Proxy rebind complete · {applied}/{len(changed)} keeper route changes applied · "
              f"distinct assigned {stats.get('distinct_assigned', 0)}")
    return stats


async def auto_login_on_boot():
    """Auto-start exactly one keeper for every enabled bootable account."""
    await asyncio.sleep(1)
    jars = load_jars()
    bootable = _bootable_keeper_jars(jars)
    if not bootable:
        log("INFO", "Auto-login: No bootable account sessions found, skipping")
        return

    starts, logins = _configure_keeper_concurrency(len(bootable))
    log("INFO", f"Auto-login: fleet target {len(bootable)} keeper(s) from "
                f"{len(bootable)} bootable account(s) · parallel starts {starts} · "
                f"parallel logins {logins}")

    # Cookie imports are authenticated sessions too; keep them alive after reboot.
    bootable_ids = {j.get("id") for j in bootable}
    def enable_keepers(jars_list):
        for j in jars_list:
            if j.get("id") in bootable_ids:
                j["keeper_enabled"] = True
    mutate_jars(enable_keepers)

    # Allocate the complete proxy pool before any keeper browser is launched.
    # Reload jars after enabling keepers so the allocator sees current state.
    await allocate_unique_keeper_proxies(load_jars())

    # Do not wait for the supervisor's next 15-second tick. Register every
    # session immediately; sync() starts browsers as background tasks.
    await keeper.sync()
    _keeper_fleet_launch_event.set()
    log("INFO", f"Auto-login: {len(bootable)} keeper session(s) launched · startup verification barrier released")

def uuid7() -> str:
    ts = int(time.time() * 1000)
    combined = (
        (ts << 80)
        | ((0x7000 | secrets.randbits(12)) << 64)
        | (0x8000000000000000 | secrets.randbits(62))
    )
    h = f"{combined:032x}"
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

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
                                items.append({"name": k.strip(), "value": v.strip(), "domain": "localhost", "path": "/"})
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
            "domain": c.get("domain") or "localhost",
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure", True)),
            "httpOnly": bool(c.get("httpOnly", False)),
            "expirationDate": c.get("expirationDate") or c.get("expires"),
        })
    return out

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
        try:
            _proxy_health_load()
            _hh = _proxy_health.get(_proxy_hkey(proxy_url))
            if _hh and _hh.pop("probe_note", None) is not None:
                _proxy_health_save()
        except Exception:
            pass
    else:
        note_probe_failure(proxy_url)
        try:
            _r = _probe_fail_reason.get(proxy_url, "")
            if _r:
                _proxy_health_load()
                _proxy_health.setdefault(_proxy_hkey(proxy_url), {})["probe_note"] = _r[:160]
                _proxy_health_save()
        except Exception:
            pass
    return ok

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

def note_probe_failure(proxy_url: str) -> None:
    if not PROXY_QUARANTINE or not proxy_url:
        return
    n = _proxy_strikes[proxy_url] = _proxy_strikes.get(proxy_url, 0) + 1
    if n >= PROBE_EXILE_AFTER:
        quarantine_proxy(proxy_url, f"CONNECT probe failed {n}× in a row")

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
        # Speed matters — but not more than IP spread. Reorder ONLY the head
        # window the picker will actually take from (fastest-of-the-next-8),
        # then let the cursor park after it. A GLOBAL latency sort used to
        # float the single fastest exit to the front of EVERY candidate list,
        # which collapsed the pool: 20 live proxies, all traffic (and every
        # 429 retry) on one exit IP.
        _w = PROBE_MAX_PARALLEL
        _head, _rest = ordered[:_w], ordered[_w:]
        def _k(u):
            lat = _proxy_latency.get(u)
            return (1, 0) if not isinstance(lat, int) or lat <= 0 else (0, lat)
        for c in sorted(_head, key=_k) + _rest:
            if c not in out:
                out.append(c)
    return out

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
                if _valid_model_catalog(fetched_models):
                    break
    except Exception as e:
        def mark_fail_exc(s):
            s["refresh_started"] = 0
        mutate_state(mark_fail_exc)
        return {"ok": False, "models": get_models(), "reason": f"Refresh crashed: {type(e).__name__}: {e}"}

    if _valid_model_catalog(fetched_models):
        def mark_done(s):
            s["last_refresh"] = time.time()
            s["refresh_started"] = 0
        mutate_state(mark_done)
        return {
            "ok": True, "models": fetched_models,
            "reason": f"Refreshed successfully — {len(_catalog_names(fetched_models))} unique models loaded.",
        }

    def mark_fail(s):
        s["refresh_started"] = 0
    mutate_state(mark_fail)

    if not tried_any_worker:
        reason = "No live keeper session with an open browser page was available to fetch the catalog."
    else:
        reason = "Fetched the page but could not extract a valid model catalog — existing models.json was preserved."
    return {"ok": False, "models": get_models(), "reason": reason}

class BridgeHTTPError(Exception):
    def __init__(self, status: int, body: str, *, frame_count: int = 0,
                 response_started: bool = False, stream_error: bool = False,
                 finish_seen: bool = False, stop_reason: str = "",
                 retry_after: str = ""):
        self.status = int(status or 0)
        self.body = str(body or "")
        self.frame_count = int(frame_count or 0)
        self.response_started = bool(response_started)
        self.stream_error = bool(stream_error)
        self.finish_seen = bool(finish_seen)
        self.stop_reason = str(stop_reason or "")
        self.retry_after = str(retry_after or "")
        super().__init__(f"HTTP {self.status}: {self.body[:200]}")

class ConversationLost(Exception):
    pass

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
        self.persona = PERSONAS.get(jar.get("persona")) or persona_for(jar)
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
        self._relogin_lock = asyncio.Lock()

        self.running = False
        self.status = "stopped"
        self.error = None
        self.current_step = ""
        self.step_history = []
        self.last_activity = 0.0
        self.last_health_ok = 0.0
        self.last_public_auth_check = 0.0
        self.last_nav = 0.0
        self.last_restart = 0.0
        self.last_transport_ok = 0.0
        self.last_transport_probe = 0.0
        self.transport_fail_streak = 0
        self.last_transport_probe_error = ""
        self.ready_at = float("inf")
        self.fail_count = 0
        self.next_retry = 0.0
        self.relogin_count = 0
        self._nav_fail_count = 0
        self.active_requests = 0
        self._auth_sig_cache = None
        self._public_cookie_snapshot = []
        self._cur_x = 200.0
        self._cur_y = 200.0
        # Page pool for concurrent requests
        self._page_pool: list = []  # list of extra pages
        self._page_pool_lock = asyncio.Lock()
        # The warmed main page is a single transport lane. With extra tabs
        # disabled, concurrent callers must queue here rather than all sharing
        # one page/console/fetch context simultaneously.
        self._main_page_lane = asyncio.Lock()
        # Serialize through the keeper page unless an operator explicitly opts
        # into extra tabs after validating upstream capacity.
        self._max_pool_pages = max(0, min(4, int(os.environ.get("BRIDGENA_KEEPER_EXTRA_PAGES", "0"))))

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

    async def _navigate_resilient(self, page, url: str, timeout: int = 60000) -> bool:
        """Commit the Arena document quickly; slow third-party assets are non-blocking."""
        last_error = None
        try:
            await page.goto(url, wait_until="commit", timeout=min(15000, timeout))
        except Exception as exc:
            last_error = exc
            try:
                target = urlparse(url)
                current = urlparse(page.url or "")
                if current.hostname != target.hostname:
                    raise last_error
            except Exception:
                raise last_error

        try:
            await page.wait_for_load_state("domcontentloaded", timeout=min(6000, timeout))
        except Exception:
            log("WARN", f"[{self.name}] Navigation committed; domcontentloaded still pending — continuing startup")
        return True

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

    async def solve_recaptcha_image_challenge(self, max_rounds: int = 4) -> bool:
        """Fallback: solve a visible reCAPTCHA image challenge with ONNX models.

        Primary path is reCAPTCHA v3 token (no challenge UI). This only runs when
        an image grid challenge is already on screen or after v2 escalation.
        """
        solver = get_solver()
        if not solver or not solver.available():
            log("WARN", f"[{self.name}] ONNX captcha solver not available — skip image solve")
            return False
        page = self.page
        if not page or page.is_closed():
            return False

        try:
            self._set_step("Solving reCAPTCHA image challenge (ONNX fallback)...")
            solved_any = False

            for round_idx in range(max_rounds):
                # 1. Check if already solved (aria-checked or response textarea filled)
                for f in page.frames:
                    try:
                        checked = await f.locator("#recaptcha-anchor[aria-checked='true'], .recaptcha-checkbox[aria-checked='true']").count()
                        if checked > 0:
                            log("OK", f"[{self.name}] reCAPTCHA anchor verified (aria-checked=true)")
                            self._set_step("reCAPTCHA challenge solved")
                            return True
                    except Exception:
                        pass

                tok_check = await page.evaluate("""() => {
                    const el = document.querySelector('textarea[name="g-recaptcha-response"], #g-recaptcha-response');
                    return (el && el.value && el.value.length > 20) ? el.value : null;
                }""")
                if tok_check:
                    log("OK", f"[{self.name}] reCAPTCHA response token present in DOM ({len(tok_check)} chars)")
                    self._set_step("reCAPTCHA response verified")
                    return True

                # 2. Find the challenge iframe (bframe)
                challenge_frame = None
                for frame in page.frames:
                    u = (frame.url or "").lower()
                    if "recaptcha" in u and "bframe" in u:
                        challenge_frame = frame
                        break

                if challenge_frame is None:
                    # Try clicking the anchor checkbox to reveal/mount challenge
                    for frame in page.frames:
                        u = (frame.url or "").lower()
                        if "recaptcha" in u and ("anchor" in u or "bframe" not in u):
                            try:
                                cb = frame.locator("#recaptcha-anchor, .recaptcha-checkbox-border")
                                if await cb.count() > 0 and await cb.first.is_visible():
                                    await cb.first.click(timeout=3000)
                                    await asyncio.sleep(2.0)
                                    break
                            except Exception:
                                pass
                    for frame in page.frames:
                        u = (frame.url or "").lower()
                        if "recaptcha" in u and "bframe" in u:
                            challenge_frame = frame
                            break

                if challenge_frame is None:
                    if round_idx == 0:
                        log("WARN", f"[{self.name}] No reCAPTCHA challenge bframe found on page")
                    break

                await asyncio.sleep(1.0)

                # 3. Extract task description
                task = ""
                for sel in [".rc-imageselect-desc-wrapper", ".rc-imageselect-desc-text", ".rc-imageselect-desc", "strong"]:
                    try:
                        loc = challenge_frame.locator(sel).first
                        if await loc.count() > 0:
                            task = (await loc.inner_text()).strip()
                            if task:
                                break
                    except Exception:
                        continue

                if not task:
                    if solved_any:
                        return True
                    break

                # 4. Detect grid size
                grid = "3x3"
                try:
                    if await challenge_frame.locator("table.rc-imageselect-table-44").count() > 0:
                        grid = "4x4"
                    elif await challenge_frame.locator("table.rc-imageselect-table-33").count() > 0:
                        grid = "3x3"
                except Exception:
                    pass

                # 5. Extract image: prefer direct element screenshot for maximum reliability
                image_sources = []
                try:
                    target_img = challenge_frame.locator(".rc-image-tile-wrapper img, #rc-imageselect-target img, table.rc-imageselect-table-33, table.rc-imageselect-table-44").first
                    if await target_img.count() > 0 and await target_img.is_visible():
                        img_bytes = await target_img.screenshot()
                        if img_bytes and len(img_bytes) > 100:
                            image_sources = [img_bytes]
                except Exception as ie:
                    log("WARN", f"[{self.name}] Screenshot tile extraction failed: {ie}")

                if not image_sources:
                    try:
                        img = challenge_frame.locator(".rc-image-tile-wrapper img, img.rc-image-tile-33, img.rc-image-tile-44").first
                        if await img.count() > 0:
                            src = await img.get_attribute("src")
                            if src:
                                image_sources = [src]
                    except Exception:
                        pass

                if not image_sources:
                    # Per-tile images fallback
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
                    log("WARN", f"[{self.name}] Captcha challenge found but could not extract images (round {round_idx+1})")
                    break

                # 6. Run ONNX recognition
                result = solver.recognize(task, image_sources, grid, randomize_20pct=False)
                if result.get("error"):
                    log("WARN", f"[{self.name}] Solver error: {result['error']}")
                    break

                clicks = result.get("data") or []
                cells = challenge_frame.locator(".rc-imageselect-tile, td.rc-imageselect-tile, table tr td")
                cell_count = await cells.count()
                clicked = 0
                for i, should in enumerate(clicks):
                    if not should or i >= cell_count:
                        continue
                    try:
                        await cells.nth(i).click(timeout=2000)
                        clicked += 1
                        await asyncio.sleep(random.uniform(0.18, 0.32))
                    except Exception:
                        continue

                await asyncio.sleep(0.6)
                # 7. Click Verify / Next button
                for sel in ["#recaptcha-verify-button", ".rc-button-default", "button#recaptcha-verify-button", "button"]:
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

                solved_any = True
                await asyncio.sleep(2.0)
                log("OK", f"[{self.name}] Image captcha round {round_idx+1} answered (task={task[:35]!r}, clicks={clicked}, grid={grid})")
                self._set_step(f"Captcha round {round_idx+1} submitted ({clicked} tiles)")

            # Final check for token / aria-checked
            for f in page.frames:
                try:
                    if await f.locator("#recaptcha-anchor[aria-checked='true']").count() > 0:
                        return True
                except Exception:
                    pass
            tok_final = await page.evaluate("""() => {
                const el = document.querySelector('textarea[name="g-recaptcha-response"], #g-recaptcha-response');
                return (el && el.value && el.value.length > 20) ? el.value : null;
            }""")
            if tok_final:
                return True
            log("WARN", f"[{self.name}] image challenge rounds submitted but no verified token/checkmark was observed")
            return False
        except Exception as e:
            log("WARN", f"[{self.name}] solve_recaptcha_image_challenge: {type(e).__name__}: {e}")
            return False

    async def _ensure_sidebar_cookie(self):
        """Set sidebar_state cookie so the localhost:6767 sidebar stays open."""
        try:
            if self.context:
                await self.context.add_cookies([
                    {"name": "sidebar_state", "value": "true",
                     "domain": "localhost", "path": "/", "secure": False, "httpOnly": False},
                ])
        except Exception:
            pass

    async def _verify_auth_state(self, page) -> bool:
        """Verify public authentication without trusting transient hydration UI."""
        try:
            # The account identity rendered by the application is strongest.
            if self.email:
                try:
                    email_loc = page.locator(f"text=/{re.escape(self.email)}/i").first
                    if await email_loc.count() > 0 and await email_loc.is_visible():
                        return True
                except Exception:
                    pass

            cookies = await page.context.cookies([page.url])
            auth_cookie_names = (
                "arena-auth", "arena-auth-prod-v1.0", "arena-auth-prod-v1.1",
                "__session", "authToken", "clerk-db-jwt",
            )
            has_auth_cookie = any(
                any(marker.lower() in str(cookie.get("name", "")).lower()
                    for marker in auth_cookie_names)
                for cookie in cookies
            )

            # A 200 history response is considered authenticated only when the
            # browser also holds the account cookie. This prevents public/empty
            # 200 responses from creating false-positive keeper readiness.
            status_code = await page.evaluate(
                "async () => { try { const r = await fetch('/api/history/unified?limit=1', "
                "{credentials:'include'}); return r.status; } catch(e) { return 0; } }"
            )
            if status_code == 200 and has_auth_cookie:
                return True

            login_btn = page.locator("button:has-text('Log In'), a:has-text('Log In'), button:has-text('Sign In'), a:has-text('Sign In'), button:has-text('Login'), a:has-text('Login')").first
            if await login_btn.count() > 0 and await login_btn.is_visible():
                return False

            modal_title = page.locator("text='Log In or Create'").first
            if await modal_title.count() > 0 and await modal_title.is_visible():
                return False

            if has_auth_cookie:
                return True

            # Never use the old button:has(svg) fallback: nearly every logged-
            # out page has icon buttons. Only explicit account controls count.
            profile_btn = page.locator(
                "button[aria-label*='profile' i], button[aria-label*='account' i], "
                "[data-testid*='user-menu' i], [data-testid*='profile-menu' i]"
            ).first
            if await profile_btn.count() > 0 and any(
                    origin in (page.url or "") for origin in (ARENA_BASE, PUBLIC_AUTH_BASE)):
                return True

        except Exception:
            pass
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
        """Authenticate on the public application before activating the local mirror.
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
            self._set_step("[1/6] Navigating to public authentication...")
            await self._navigate_resilient(page, f"{PUBLIC_AUTH_BASE}/", timeout=60000)
            await self._wait_cloudflare(page)
            await self._handle_turnstile(page)
            await asyncio.sleep(2)

            if await self._verify_auth_state(page):
                await self._harvest_cookies()
                self._set_step("[SUCCESS] Existing public session is authenticated")
                return True, "Existing session authenticated"

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

            # The localhost:6767 modal has a specific "Continue with email" button
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
                    err = f"Account {self.email} is not registered on localhost:6767 (shows 'Create Account')"
                    self._set_step(f"[FAILED at Step 4] {err}")
                    await self._screenshot(page, "create_account_shown")
                    return False, err
            except Exception:
                pass

            # ---- STEP 5: Enter password ----
            self._set_step("[5/6] Waiting for password field...")
            pw_loc = None
            pw_deadline = time.time() + 12
            next_auth_probe = 0.0
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
                if time.time() >= next_auth_probe:
                    next_auth_probe = time.time() + 1.0
                    if await self._verify_auth_state(page):
                        await self._harvest_cookies()
                        self._set_step("[SUCCESS] Email flow authenticated without a password step")
                        return True, "Authenticated without password"
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

            # localhost:6767 password screen has a "Login" button (not "Log In")
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
            if not self.context:
                return
            # Persist only the public authenticated jar. Local mirror cookies
            # are derived copies and must never overwrite the source snapshot.
            cookies = await self.context.cookies([PUBLIC_AUTH_BASE])
            simplified = [
                {"name": c.get("name", ""), "value": c.get("value", ""),
                 "domain": c.get("domain", ""), "path": c.get("path", "/"),
                 "secure": c.get("secure", False), "httpOnly": c.get("httpOnly", False),
                 "sameSite": c.get("sameSite"), "expirationDate": c.get("expires")}
                for c in cookies if c.get("name")
            ]
            auth_val = (find_cookie(simplified, "arena-auth-prod-v1.0")
                        or find_cookie(simplified, "arena-auth-prod-v1.1")
                        or find_cookie(simplified, "arena-auth-prod-v1") or "")
            if auth_val:
                self._public_cookie_snapshot = simplified
            sig = hashlib.sha256(auth_val.encode()).hexdigest()[:10] if auth_val else "none"

            def upd(jars: list):
                for j in jars:
                    if j["id"] != self.jar_id: continue
                    # Never replace a previously authenticated jar with public,
                    # logged-out cookies from a failed or half-rendered login.
                    if simplified and auth_val:
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

    async def _activate_local_mirror(self) -> bool:
        """Clone the authenticated public jar into localhost scope and switch pages."""
        if not self.context or not self.page:
            return False
        if ARENA_BASE.rstrip("/") == PUBLIC_AUTH_BASE.rstrip("/"):
            # Authentication already occurred on the target origin. Rewriting
            # cookies here can alter their paths and navigating again races
            # with the application hydration that just completed.
            self.last_nav = time.time()
            self.last_health_ok = time.time()
            self.last_public_auth_check = time.time()
            return True
        source = self._public_cookie_snapshot
        if not source:
            jar = next((j for j in load_jars() if j.get("id") == self.jar_id), None)
            source = list((jar or {}).get("cookies") or [])
        if not source:
            self.error = "Public authentication produced no cookies"
            return False

        local_cookies = []
        for cookie in source:
            name, value = cookie.get("name"), cookie.get("value")
            if not name or not value:
                continue
            item = {
                "name": name,
                "value": value,
                "url": ARENA_BASE,
                "httpOnly": bool(cookie.get("httpOnly", False)),
                "secure": _ARENA_PARSED.scheme == "https",
                "sameSite": (cookie.get("sameSite")
                             if cookie.get("sameSite") in {"Strict", "Lax"}
                             or (_ARENA_PARSED.scheme == "https" and cookie.get("sameSite") == "None")
                             else "Lax"),
            }
            expires = cookie.get("expirationDate") or cookie.get("expires")
            if isinstance(expires, (int, float)) and expires > 0:
                item["expires"] = expires
            local_cookies.append(item)

        await self.context.add_cookies(local_cookies)
        self._set_step(f"Injected {len(local_cookies)} authenticated cookies into local mirror")
        await self._navigate_resilient(self.page, ARENA_DIRECT_URL, timeout=45000)
        await self.page.wait_for_load_state("domcontentloaded")
        await self._ensure_sidebar_cookie()
        self.last_nav = time.time()
        # Startup just verified the public session. Do not immediately run a
        # second health check against the mirror page.
        self.last_health_ok = time.time()
        self.last_public_auth_check = time.time()
        return True

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
                # The mirror is the transport page, not the source of truth for
                # public login state. Verify public auth in a short-lived tab so
                # mirror UI state cannot trigger a false relogin or disturb an
                # otherwise ready request page.
                if LOCAL_UPSTREAM:
                    probe = None
                    try:
                        probe = await self.context.new_page()
                        await self._navigate_resilient(probe, PUBLIC_AUTH_URL, timeout=45000)
                        await self._wait_cloudflare(probe)
                        healthy = await self._verify_auth_state(probe)
                        self.last_public_auth_check = time.time()
                        if healthy:
                            self.last_health_ok = time.time()
                            await self._harvest_cookies()
                        return healthy
                    finally:
                        if probe is not None:
                            try:
                                await probe.close()
                            except Exception:
                                pass
                if ARENA_BASE not in (page.url or "") and self.active_requests == 0:
                    await self._ensure_sidebar_cookie()
                    await page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded")
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
        # Collapse duplicate supervisor/manual relogin triggers for this
        # account and cap simultaneous public login flows across the fleet.
        async with self._relogin_lock:
            async with _keeper_login_gate:
                return await self._relogin_once()

    async def _relogin_once(self) -> bool:
        self.ready_at = float("inf")
        self.status = "reconnecting"
        self.error = None
        self._set_step("Starting re-login sequence...")
        try:
            return await asyncio.wait_for(self._relogin_impl(), timeout=KEEPER_RELOGIN_TIMEOUT)
        except asyncio.TimeoutError:
            self.error = f"Relogin timed out after {KEEPER_RELOGIN_TIMEOUT}s"
            self.status = "degraded"
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
                    if not await self._activate_local_mirror():
                        self.error = self.error or "Failed to activate local mirror"
                        self._schedule_retry()
                        return False
                    self.relogin_count += 1
                    self.status = "running"
                    self.fail_count = 0
                    self.next_retry = 0
                    self.ready_at = time.monotonic() + KEEPER_WARMUP_SEC
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
                    await new_page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded")
                    await asyncio.sleep(0.5)
                    idx = len(self._page_pool)
                    self._page_pool.append((new_page, True))
                    log("INFO", f"[{self.name}] Spawned new tab #{idx + 1} for concurrent request")
                    return new_page, idx
                except Exception as e:
                    log("WARN", f"[{self.name}] Failed to create extra tab: {e}")
            # Stable main-page lane. Never hand the same browser page to two
            # simultaneous bridge_fetch calls: doing that mixes console events,
            # fetch state and navigation/session activity.
            await self._main_page_lane.acquire()
            return self.page, -1

    async def _release_page(self, idx):
        """Mark a pooled page as idle, or release the warmed main-page lane."""
        if idx >= 0:
            async with self._page_pool_lock:
                if idx < len(self._page_pool):
                    pg, _ = self._page_pool[idx]
                    self._page_pool[idx] = (pg, False)
        elif self._main_page_lane.locked():
            self._main_page_lane.release()

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

    async def probe_transport(self, *, force: bool = False) -> tuple:
        """Check whether the keeper browser can currently reach Arena.

        This is a harmless same-origin HEAD request. Any HTTP response proves
        the browser/proxy route is alive; no model prompt or evaluation is sent.
        """
        if not self.context or not self.page or self.page.is_closed() or not self.running:
            self.last_transport_probe_error = "keeper browser unavailable"
            return False, 0, self.last_transport_probe_error

        now = time.monotonic()
        if (not force and not TRANSPORT_PROBE_EVERY_REQUEST
                and self.last_transport_ok
                and now - self.last_transport_ok <= TRANSPORT_PROBE_FRESH_SEC):
            return True, 200, "recent-ok"

        async with self._action_lock:
            page = self.page
            if not page or page.is_closed():
                self.last_transport_probe_error = "keeper page closed"
                return False, 0, self.last_transport_probe_error
            self.last_transport_probe = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    page.evaluate("""async ([url, timeoutMs]) => {
                      const ctl = new AbortController();
                      const timer = setTimeout(() => ctl.abort(), timeoutMs);
                      try {
                        const r = await fetch(url, {
                          method: 'HEAD',
                          credentials: 'include',
                          cache: 'no-store',
                          redirect: 'follow',
                          signal: ctl.signal
                        });
                        return {ok:true, status:r.status, online:navigator.onLine};
                      } catch (e) {
                        return {
                          ok:false,
                          status:0,
                          online:navigator.onLine,
                          error:String((e && e.message) || e || 'transport probe failed')
                        };
                      } finally {
                        clearTimeout(timer);
                      }
                    }""", [ARENA_BASE + "/", TRANSPORT_PROBE_TIMEOUT_MS]),
                    timeout=(TRANSPORT_PROBE_TIMEOUT_MS / 1000.0) + 1.5,
                )
            except Exception as exc:
                self.transport_fail_streak += 1
                self.last_transport_probe_error = f"{type(exc).__name__}: {redact(str(exc))[:140]}"
                return False, 0, self.last_transport_probe_error

        ok = bool(isinstance(result, dict) and result.get("ok") and int(result.get("status") or 0) > 0)
        status_code = int((result or {}).get("status") or 0) if isinstance(result, dict) else 0
        if ok:
            self.last_transport_ok = time.monotonic()
            self.transport_fail_streak = 0
            self.last_transport_probe_error = ""
            return True, status_code, ""

        self.transport_fail_streak += 1
        self.last_transport_probe_error = str((result or {}).get("error") or "route probe failed")[:180]
        return False, status_code, self.last_transport_probe_error


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
                        elif isinstance(data, dict) and "line" in data:
                            queue.put_nowait((data.get("i"), data.get("line")))
                        else:
                            queue.put_nowait((None, data))
            except Exception:
                pass

        page.on("console", on_console)
        self.active_requests += 1
        try:
            script = """async ([url, payload, rid, action, tailGraceMs]) => {
                const P = s => console.log('__NX' + rid + s);
                const captured = [];
                let responseStatus = 0;
                let responseStarted = false;
                let protocolFinished = false;
                let stopReason = 'not-started';
                const emit = line => {
                    const i = captured.length;
                    captured.push(line);
                    P('D' + JSON.stringify({i, line}));
                };
                try {
                    const r = await fetch(url, {
                        method: 'POST', credentials: 'include',
                        headers: {
                          'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(payload)
                    });
                    responseStarted = true;
                    responseStatus = r.status;
                    stopReason = 'eof';
                    P('S' + r.status);
                    if (!r.ok) {
                        const error = (await r.text()).slice(0, 400);
                        P('E' + error); P('Dnull');
                        return {status: r.status, error, lines: captured,
                                responseStarted: true, streamError: false,
                                finishSeen: false, stopReason: 'http-error',
                                retryAfter: r.headers.get('retry-after') || ''};
                    }
                    const reader = r.body.getReader();
                    const dec = new TextDecoder();
                    let buffer = '';
                    const readWithGrace = () => new Promise((resolve, reject) => {
                        // Some providers emit their final text delta after the
                        // finish metadata. Drain for a real quiet window so a
                        // trailing word or punctuation chunk is not clipped.
                        const timer = setTimeout(() => resolve({graceExpired: true}), tailGraceMs);
                        reader.read().then(
                            value => { clearTimeout(timer); resolve(value); },
                            error => { clearTimeout(timer); reject(error); }
                        );
                    });
                    while (true) {
                        const packet = protocolFinished ? await readWithGrace() : await reader.read();
                        if (packet.graceExpired) {
                            stopReason = 'post-finish-timeout';
                            try { await reader.cancel(); } catch (_) {}
                            break;
                        }
                        const {done, value} = packet;
                        if (value) buffer += dec.decode(value, {stream: true});
                        if (done) buffer += dec.decode();
                        const parts = buffer.split(/\\r?\\n/);
                        buffer = parts.pop() || '';
                        for (const line of parts) {
                            if (line.trim()) {
                                emit(line);
                                const t = line.trim();
                                if (/^(ad|b|c|d|e):/.test(t) ||
                                    /^data:\\s*\\{.*\\"type\\"\\s*:\\s*\\"(?:finish|finish-step|finish-message|message-stop|done)\\"/.test(t)) {
                                    protocolFinished = true;
                                }
                            }
                        }
                        if (done) break;
                    }
                    if (buffer.trim()) emit(buffer);
                    P('D' + JSON.stringify(null));
                    return {status: r.status, error: '', lines: captured,
                            responseStarted: true, streamError: false,
                            finishSeen: protocolFinished, stopReason,
                            retryAfter: r.headers.get('retry-after') || ''};
                } catch(e) {
                    const message = String((e && e.message) || e || 'browser transport error');
                    P('S' + responseStatus); P('E' + message); P('Dnull');
                    return {status: responseStatus, error: message, lines: captured,
                            responseStarted, streamError: responseStarted,
                            finishSeen: protocolFinished,
                            stopReason: responseStarted ? 'stream-error' : 'fetch-error'};
                }
            }"""
            _bridge_started_at = time.monotonic()
            eval_task = asyncio.create_task(asyncio.wait_for(page.evaluate(
                script, [url, payload, req_id, RECAPTCHA_ACTION, STREAM_TAIL_GRACE_MS]
            ), timeout=180.0))
            # Navigation can destroy evaluate before its console sentinel.
            # Always wake the consumer; the result supplies any missing frames.
            eval_task.add_done_callback(lambda task: queue.put_nowait(None))
            # Console delivery is fast but may skip an event under load. Keep
            # indexed frames ordered: later chunks wait behind a gap until the
            # page result supplies the missing frame at EOF. This prevents a
            # recovered middle delta from being appended as a fake tail.
            pending_lines = {}
            next_index = 0
            while True:
                packet = await queue.get()
                if packet is None:
                    break
                index, line = packet
                if isinstance(index, int):
                    pending_lines[index] = line
                    while next_index in pending_lines:
                        yield pending_lines.pop(next_index)
                        next_index += 1
                else:
                    yield line
            try:
                result = await eval_task
            except Exception as _bridge_eval_exc:
                _elapsed = time.monotonic() - _bridge_started_at
                try:
                    _page_closed = bool(page.is_closed())
                except Exception:
                    _page_closed = True
                try:
                    _page_url = str(page.url or "")[:180]
                except Exception:
                    _page_url = "<unavailable>"
                log("WARN", f"[{self.name}] bridge evaluate terminated · elapsed {_elapsed:.2f}s · "
                            f"page_closed={_page_closed} · page={_page_url} · "
                            f"active_requests={self.active_requests} · "
                            f"{type(_bridge_eval_exc).__name__}: {str(_bridge_eval_exc)[:220]}")
                raise
            if eval_task.exception():
                raise RuntimeError(f"Bridge evaluate exception: {eval_task.exception()}")
            # Console delivery can drop messages under load. The page retains
            # the exact same response lines, so fill any index gaps and flush
            # them in original order—no second POST and no duplicated chunks.
            if isinstance(result, dict):
                for index, line in enumerate(result.get("lines") or []):
                    if index >= next_index:
                        pending_lines.setdefault(index, line)
                while next_index in pending_lines:
                    yield pending_lines.pop(next_index)
                    next_index += 1
            status_code = (result.get("status") if isinstance(result, dict) else None) or meta.get("status", 0)
            error_body = (result.get("error") if isinstance(result, dict) else None) or meta.get("error", "")
            if isinstance(result, dict):
                frame_count = len(result.get("lines") or [])
                response_started = bool(result.get("responseStarted"))
                retry_after = str(result.get("retryAfter") or "")
                if response_started and status_code:
                    self.last_transport_ok = time.monotonic()
                    self.transport_fail_streak = 0
                    self.last_transport_probe_error = ""
                elif not response_started and not status_code:
                    self.transport_fail_streak += 1
                stream_error = bool(result.get("streamError"))
                finish_seen = bool(result.get("finishSeen"))
                stop_reason = str(result.get("stopReason") or "unknown")

                # Privacy-safe stream forensics: record frame *shape*, never payload text.
                # This is intentionally diagnostic-only and must not alter decoding.
                _raw_lines = list(result.get("lines") or [])
                _frame_kinds = {}
                _tail_shapes = []
                for _raw in _raw_lines:
                    _s = str(_raw or "").strip()
                    _prefix = "plain"
                    _etype = ""
                    if ":" in _s:
                        _candidate = _s.split(":", 1)[0].strip()
                        if 0 < len(_candidate) <= 24:
                            _prefix = _candidate
                    _m = re.search(r'["\\\'](?:type|event)["\\\']\\s*:\\s*["\\\']([^"\\\']{1,48})', _s)
                    if _m:
                        _etype = _m.group(1)
                    _key = f"{_prefix}/{_etype}" if _etype else _prefix
                    _frame_kinds[_key] = _frame_kinds.get(_key, 0) + 1
                    _tail_shapes.append(f"{_key}@{len(_s)}")
                _tail_shapes = _tail_shapes[-12:]
                _kind_summary = ",".join(f"{k}={v}" for k, v in sorted(_frame_kinds.items())[:20]) or "none"
                _tail_summary = " | ".join(_tail_shapes) or "none"
                _elapsed = time.monotonic() - _bridge_started_at
                try:
                    _page_closed = bool(page.is_closed())
                except Exception:
                    _page_closed = True
                try:
                    _page_url = str(page.url or "")[:160]
                except Exception:
                    _page_url = "<unavailable>"

                if status_code == 200 and (stream_error or not finish_seen):
                    log("WARN", f"[{self.name}] stream forensics · elapsed {_elapsed:.2f}s · "
                                f"stop={stop_reason} · error={stream_error} · finish={finish_seen} · "
                                f"page_closed={_page_closed} · page={_page_url} · "
                                f"kinds[{_kind_summary}] · tail[{_tail_summary}]")

                if status_code == 200 and stream_error and finish_seen:
                    # The provider already emitted its semantic terminal frame.
                    # A TCP/browser error while draining the post-finish quiet
                    # window must not turn a completed answer into a 502.
                    log("WARN", f"[{self.name}] stream audit · HTTP 200 · frames {frame_count} · "
                                f"finish yes · transport dropped after protocol finish · accepting completed stream")
                elif status_code == 200 and stream_error:
                    log("WARN", f"[{self.name}] stream audit · HTTP 200 · frames {frame_count} · "
                                f"finish no · stream interrupted: {error_body[:220]}")
                elif status_code == 200:
                    log("INFO", f"[{self.name}] stream audit · HTTP 200 · frames {frame_count} · "
                                f"finish {'yes' if finish_seen else 'no'} · stop {stop_reason}")
                else:
                    phase = "after response" if response_started else "before response"
                    log("WARN", f"[{self.name}] stream audit · HTTP {status_code or 0} · {phase} · "
                                f"frames {frame_count} · body: {error_body[:300]}")

                if status_code == 200 and stream_error and not finish_seen:
                    raise BridgeHTTPError(
                        200, error_body or "browser response stream interrupted",
                        frame_count=frame_count, response_started=True,
                        stream_error=True, finish_seen=False, stop_reason=stop_reason,
                        retry_after=retry_after,
                    )
                if status_code == 200 and REQUIRE_PROVIDER_FINISH and not finish_seen:
                    # A natural reader EOF is a valid terminal condition for providers
                    # that close their stream without emitting Arena's usual explicit
                    # finish metadata. Do not manufacture a mid-stream failure from a
                    # clean transport close; the caller still requires decodable semantic
                    # output before it can report success. Interrupted/error drains remain
                    # failures and continue through the salvage path below.
                    if stop_reason == "eof" and not stream_error:
                        log("WARN", f"[{self.name}] stream audit · HTTP 200 clean EOF without explicit provider finish · "
                                    f"frames {frame_count} · accepting transport terminal; semantic-output guard remains active")
                    else:
                        log("WARN", f"[{self.name}] stream audit · HTTP 200 ended without provider finish · "
                                    f"frames {frame_count} · stop {stop_reason}")
                        raise BridgeHTTPError(
                            200, "Arena response ended without a provider finish event",
                            frame_count=frame_count, response_started=True,
                            stream_error=True, finish_seen=False,
                            stop_reason=(stop_reason or "eof-without-finish"),
                            retry_after=retry_after,
                        )
                if status_code != 200:
                    raise BridgeHTTPError(
                        status_code, error_body,
                        frame_count=frame_count, response_started=response_started,
                        stream_error=stream_error, finish_seen=finish_seen,
                        stop_reason=stop_reason, retry_after=retry_after,
                    )
            elif status_code != 200:
                raise BridgeHTTPError(status_code, error_body)
        finally:
            if 'eval_task' in locals():
                if not eval_task.done():
                    eval_task.cancel()
                await asyncio.gather(eval_task, return_exceptions=True)
            self.active_requests -= 1
            page.remove_listener("console", on_console)
            await self._release_page(pool_idx)
            # Clean up idle pool pages when no more active requests
            if self.active_requests == 0:
                asyncio.create_task(self._cleanup_pool())

    # --- Cross-Platform Browser Lifecycle ---

    async def start(self) -> bool:
        # Browser launches are memory-heavy and simultaneous profile startup
        # makes public auth hydration unreliable. Bound fleet startup while
        # keeping every account registered and independently recoverable.
        async with _keeper_start_gate:
            return await self._start_impl()

    async def _start_impl(self) -> bool:
        if self.running:
            return True
            
        self.ready_at = float("inf")
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
                        f"Launching persistent headed context with Bridgena v4 Extension"
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
                        user_agent=self.user_agent or KEEPER_UA,  # persona-bound; cf_clearance is UA+IP-bound
                    )
                    if _pw_proxy:
                        _local_proxy = dict(_pw_proxy)
                        existing_bypass = str(_local_proxy.get("bypass") or "").strip()
                        local_bypass = "localhost,127.0.0.1,[::1]"
                        _local_proxy["bypass"] = ",".join(x for x in (existing_bypass, local_bypass) if x)
                        _pc_kw["proxy"] = _local_proxy
                    self.context = await self.playwright.chromium.launch_persistent_context(**_pc_kw)
                    self.browser = None
                    self.page = self.context.pages[0] if self.context.pages else await self.context.new_page()
                    launched = True
                    log("OK", f"[{self.name}] Bridgena v4 extension loaded from {ext_path}"
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
                        user_agent=self.user_agent or KEEPER_UA,  # persona-bound; cf_clearance is UA+IP-bound
                        storage_state=os.path.join(profile_dir, "state.json") if os.path.exists(os.path.join(profile_dir, "state.json")) else None,
                    )
                self.page = await self.context.new_page()
                await self.page.add_init_script(stealth_init_js(self.persona))
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

            self._set_step("Checking public authentication...")
            await self._navigate_resilient(self.page, PUBLIC_AUTH_URL, timeout=60000)
            await self._wait_cloudflare(self.page)
            await self._handle_turnstile(self.page)
            await self._inject_visual_cursor(self.page)

            # Dismiss any promo banners that might block the UI
            await self._dismiss_promos(self.page)

            self.running = True
            self._tried_proxies = set()
            self._direct_tried = False
            self.last_health_ok = 0
            self.status = "authenticating"
            self._set_step("Keeper session active")
            log("OK", f"[{self.name}] Keeper started ({'headless' if self.headless else 'LIVE WINDOW'})")

            if await self._verify_auth_state(self.page):
                self.last_public_auth_check = time.time()
                await self._harvest_cookies()
                if not await self._activate_local_mirror():
                    self.status = "degraded"
                    log("WARN", f"[{self.name}] Public session valid but local cookie injection failed")
                else:
                    self.ready_at = time.monotonic() + KEEPER_WARMUP_SEC
                    self.status = "running"
            else:
                log("WARN", f"[{self.name}] Initial health check negative — triggering relogin")
                await self.relogin()

            if self.status != "running":
                self.ready_at = float("inf")
            if self.status == "running" and KEEPER_WARMUP_SEC:
                log("INFO", f"[{self.name}] Keeper warm-up gate {KEEPER_WARMUP_SEC}s before parallel verification preflight")

            self._loop_task = asyncio.create_task(self._session_loop())
            return True

        except Exception as e:
            txt = f"{type(e).__name__}: {e}"
            _up = txt.upper()
            _retryable = any(k in _up for k in ("TUNNEL", "PROXY", "TIMEOUT", "ERR_", "NET::", "CONNECTION"))
            used = getattr(self, "_used_proxy", "") or ""
            # A browser CAPABILITY error ("does not support socks5 proxy auth…")
            # means our launch shape was wrong, not that the exit is dead —
            # exiling on it once ate an entire authenticated pool in 9 seconds.
            _cap_err = "does not support socks5 proxy authentication" in txt.lower()
            _local_route_err = bool(LOCAL_UPSTREAM and
                                    (ARENA_BASE in txt or "localhost:6767" in txt))
            if used:
                if _local_route_err:
                    _probe_fail_reason[used] = "local mirror routing failed (upstream proxy NOT exiled)"
                    log("WARN", f"[{self.name}] local mirror navigation failed; upstream proxy kept healthy")
                else:
                    self._tried_proxies.add(used)
                if _cap_err:
                    _probe_fail_reason[used] = "keeper shim bypassed: browser capability error (proxy NOT exiled)"
                    log("WARN", f"[{self.name}] {used.split('@')[-1]} kept in pool — Chromium capability error, not a dead proxy")
                elif not _local_route_err:
                    # ERR_NETWORK_CHANGED is a Chromium/network-stack transition,
                    # not proof that the shared upstream proxy is dead. Exiling a
                    # shared exit here can destabilize other live keepers that are
                    # already using it. Treat transient browser/network failures as
                    # strikes and reserve hard quarantine for explicit tunnel/proxy
                    # refusal classes.
                    _low = txt.lower()
                    _transient_net = any(k in _low for k in (
                        "err_network_changed",
                        "err_network_io_suspended",
                        "err_internet_disconnected",
                        "err_connection_reset",
                        "err_connection_closed",
                        "err_timed_out",
                        "timeout",
                    ))
                    _hard_proxy = any(k in _low for k in (
                        "err_proxy_connection_failed",
                        "err_tunnel_connection_failed",
                        "proxy connection failed",
                        "tunnel connection failed",
                        "connection refused",
                        "connect refused",
                        "authentication failed",
                        "proxy authentication",
                    ))
                    if _transient_net and not _hard_proxy:
                        strike_proxy(used, f"keeper transient browser network failure: {txt[:90]}")
                        _probe_fail_reason[used] = "transient keeper network change; exit retained pending strike threshold"
                        log("WARN", f"[{self.name}] transient network change on shared exit "
                                    f"{used.split('@')[-1]} — strike recorded, proxy retained")
                    elif _hard_proxy:
                        quarantine_proxy(used, f"keeper hard proxy/tunnel failure: {txt[:90]}")
                    else:
                        # Unknown browser startup failures are not strong enough
                        # evidence to globally exile a shared exit. Record a strike.
                        strike_proxy(used, f"keeper startup failure: {txt[:90]}")
                        log("WARN", f"[{self.name}] ambiguous keeper startup failure on "
                                    f"{used.split('@')[-1]} — strike recorded, proxy retained")
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
        self.ready_at = float("inf")
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
        while self.running and not _initial_verification_sweep_done.is_set():
            try:
                await asyncio.wait_for(_initial_verification_sweep_done.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                raise

        while self.running:
            try:
                await self._do_activity()
                if (time.time() - self.last_nav > random.uniform(KEEPER_NAV_MIN, KEEPER_NAV_MAX)
                        and self.active_requests == 0 and not self._action_lock.locked()):
                    try:
                        async with self._action_lock:
                            await self._ensure_sidebar_cookie()
                            await self.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=45000)
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

class SessionKeeper:
    def __init__(self):
        self.sessions: Dict[str, KeeperSession] = {}
        self._tasks: set = set()

    def _spawn(self, coro, label: str):
        task = asyncio.create_task(coro, name=f"keeper:{label}")
        self._tasks.add(task)
        def finished(done):
            self._tasks.discard(done)
            if done.cancelled():
                return
            try:
                error = done.exception()
            except Exception:
                error = None
            if error:
                log("ERROR", f"Keeper task {label} failed: {type(error).__name__}: {error}")
        task.add_done_callback(finished)
        return task

    def status(self) -> list:
        now = time.time()
        return [
            {
                "jar_id": s.jar_id, "name": s.name, "status": s.status,
                "ready": keeper_session_ready(s),
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
                _v4_headed = bool(globals().get("V4_TRANSPORT") == "extension"
                                  and globals().get("V4_AUTO_ATTACH_KEEPERS", False))
                s = KeeperSession(jar, headless=False if _v4_headed else jar.get("keeper_headless", None))
                self.sessions[jid] = s
                self._spawn(s.start(), f"start:{jid[:8]}")
            else:
                if (globals().get("V4_TRANSPORT") == "extension"
                        and globals().get("V4_AUTO_ATTACH_KEEPERS", False)
                        and s.headless):
                    log("INFO", f"[{s.name}] v4 extension transport requires headed keeper · restarting visible")
                    s.headless = False
                    self._spawn(s.restart(), f"v4-headed:{jid[:8]}")
                if (s.email != (jar.get("email") or "") or s.password != (jar.get("password") or "")
                        or s.login_method != (jar.get("login_method") or "email")):
                    s.email = jar.get("email") or ""
                    s.password = jar.get("password") or ""
                    s.login_method = jar.get("login_method") or "email"
                    s.fail_count = 0
                    s.next_retry = 0
                    log("INFO", f"[{s.name}] Credentials updated in keeper")
                if s.status == "error" and time.time() - s.last_restart > 120:
                    self._spawn(s.restart(), f"restart:{jid[:8]}")

    async def start_live(self, jar_id: str) -> tuple:
        jar = next((j for j in load_jars() if j["id"] == jar_id), None)
        if not jar:
            return False, "Account not found"
        existing = self.sessions.get(jar_id)
        if existing and existing.running:
            await existing.stop()
        s = KeeperSession(jar, headless=False, keep_forever=True)
        self.sessions[jar_id] = s
        self._spawn(s.start(), f"live:{jar_id[:8]}")
        return True, f"Live browser launching for '{jar.get('name')}'"

    async def close(self):
        sessions = list(self.sessions.values())
        if sessions:
            await asyncio.gather(*(session.stop() for session in sessions), return_exceptions=True)
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
        self._tasks.clear()
        self.sessions.clear()

keeper = SessionKeeper()


# ────────────────────────── module: pool.py ──────────────────────────────

# ============================================================
# v2 POOL — proxy policy layer (rewritten).
# Principles (each earned in production, preserved here):
#  • CONNECT-level liveness is not truth: probes go all the way to ARENA.
#  • Destination weather ≠ death: arena-blocked exits are FLAGGED (~3h,
#    self-expiring, cleared early by a delivered 200) — never exiled.
#  • Tunnel-dead lines get STRIKES (timeouts vary), auth/conn-refusal die
#    immediately with a human reason recorded (never a bare "dead").
#  • Dead lines are REMOVED from proxies.txt into proxies.dead.txt (not TTL).
#  • A 200 from real traffic is the best probe there is — it heals caches.
#  • Fairness: one shared rotation cursor; nobody hogs the only live exit.
# ============================================================
import concurrent.futures as _cf
import os, time
from typing import Dict, List, Optional, Tuple

_proxy_strikes: Dict[str, int] = {}
_proxy_recovery_due: Dict[str, float] = {}
_proxy_recovery_failures: Dict[str, int] = {}
_proxy_quarantine_reason: Dict[str, str] = {}
_pick_ctr = 0
import threading as _th
_pick_mu = _th.Lock()
_proxy_sweep_mu = _th.Lock()


def _pool_lines() -> List[str]:
    return list(get_proxy_pool())


def pool_save(lines: List[str]) -> None:
    """Rewrite proxies.txt atomically. config.json proxies stay as fallback."""
    path = _proxies_file() or os.path.join(".", "proxies.txt")
    tmp = path + f".tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))
    os.replace(tmp, path)
    _pool_cache_clear()


def _pool_cache_clear():
    # get_proxy_pool caches; the legacy loader re-stats the file per call, but
    # nudge any memoized copy to refresh on the next read.
    try:
        get_proxy_pool.__dict__.pop("_cache", None)
    except Exception:
        pass


def _append_dead(line: str, reason: str) -> None:
    try:
        with open(DEAD_FILE, "a", encoding="utf-8") as f:
            f.write(f"{line}  # {redact(reason)[:160]}\n")
    except OSError:
        pass


def quarantine_proxy(proxy_url: str, reason: str = "") -> None:
    """Open a recoverable circuit without deleting the proxy from configuration."""
    key = _proxy_hkey(proxy_url)
    norm = _normalize_proxy(proxy_url) or proxy_url
    _QUARANTINED_KEYS.add(key)
    _proxy_quarantine_reason[key] = redact(reason or "temporarily unavailable")[:160]
    failures = _proxy_recovery_failures.get(key, 0)
    delay = min(PROXY_RECOVERY_MAX_BACKOFF_SEC,
                PROXY_RECOVERY_INTERVAL_SEC * (2 ** min(failures, 4)))
    _proxy_recovery_due[key] = time.time() + delay
    _proxy_probe_cache[norm] = (False, time.time() + min(delay, 30.0))
    log("WARN", f"proxy circuit opened: {key} — retained in pool · recovery probe in {delay:.0f}s · "
                f"{_proxy_quarantine_reason[key]}")


def strike_proxy(proxy_url: str, reason: str = "") -> bool:
    """Soft failure: accumulate strikes; threshold opens a recoverable circuit."""
    key = _proxy_hkey(proxy_url)
    _proxy_strikes[key] = _proxy_strikes.get(key, 0) + 1
    if _proxy_strikes[key] >= STRIKES_MAX:
        quarantine_proxy(proxy_url, f"{STRIKES_MAX} strikes: {reason}")
        return True
    log("WARN", f"exit {key}: {redact(reason)[:80]} "
                f"(strike {_proxy_strikes[key]}/{STRIKES_MAX}; retained)")
    return False


def clear_strikes(proxy_url: str) -> None:
    key = _proxy_hkey(proxy_url)
    _proxy_strikes.pop(key, None)
    _proxy_recovery_failures.pop(key, None)
    _proxy_recovery_due.pop(key, None)
    _proxy_quarantine_reason.pop(key, None)
    _QUARANTINED_KEYS.discard(key)


def _proxy_from_key(hkey: str) -> Optional[str]:
    for raw in _pool_lines():
        if not raw.strip() or raw.startswith("#"):
            continue
        norm = _normalize_proxy(raw) or raw
        if _proxy_hkey(norm) == hkey:
            return norm
    try:
        for raw in (get_config().get("proxies") or []):
            norm = _normalize_proxy(raw) or raw
            if _proxy_hkey(norm) == hkey:
                return norm
    except Exception:
        pass
    return None


def _recover_proxy_once(proxy_url: str) -> bool:
    """Probe a circuit-open exit and automatically heal it in place."""
    norm = _normalize_proxy(proxy_url) or proxy_url
    key = _proxy_hkey(norm)
    try:
        ok, ms = _proxy_probe(norm)
    except Exception as exc:
        ok, ms = False, -1
        _probe_fail_reason[norm] = f"recovery probe exception: {type(exc).__name__}: {exc}"

    now = time.time()
    if ok:
        _proxy_probe_cache[norm] = (True, now + PROBE_OK_TTL)
        _proxy_latency[norm] = max(int(ms or 0), 1)
        _proxy_health_record(norm, True, max(int(ms or 0), 1), source="auto-recovery")
        _QUARANTINED_KEYS.discard(key)
        _proxy_strikes.pop(key, None)
        _proxy_recovery_due.pop(key, None)
        _proxy_recovery_failures.pop(key, None)
        _proxy_quarantine_reason.pop(key, None)
        _flagged_exits.pop(key, None)
        log("OK", f"proxy recovered automatically: {key} · Arena probe {max(int(ms or 0), 1)}ms · re-admitted")
        return True

    failures = _proxy_recovery_failures.get(key, 0) + 1
    _proxy_recovery_failures[key] = failures
    delay = min(PROXY_RECOVERY_MAX_BACKOFF_SEC,
                PROXY_RECOVERY_INTERVAL_SEC * (2 ** min(failures, 4)))
    _proxy_recovery_due[key] = now + delay
    _proxy_probe_cache[norm] = (False, now + min(delay, 30.0))
    why = _probe_fail_reason.get(norm, "Arena probe failed")
    log("WARN", f"proxy recovery pending: {key} · attempt {failures} failed · "
                f"next probe in {delay:.0f}s · {redact(why)[:100]}")
    return False


async def proxy_recovery_loop() -> None:
    """Continuously heal circuit-open proxies. Never deletes pool entries."""
    log("INFO", f"Proxy auto-recovery · interval {PROXY_RECOVERY_INTERVAL_SEC:.0f}s · "
                f"max backoff {PROXY_RECOVERY_MAX_BACKOFF_SEC:.0f}s · non-destructive")
    while True:
        try:
            now = time.time()
            due = []
            for key in list(_QUARANTINED_KEYS):
                if _proxy_recovery_due.get(key, 0.0) <= now:
                    proxy = _proxy_from_key(key)
                    if proxy:
                        due.append(proxy)
                    else:
                        _proxy_recovery_due[key] = now + PROXY_RECOVERY_MAX_BACKOFF_SEC
            if due:
                loop = asyncio.get_running_loop()
                await asyncio.gather(*[
                    loop.run_in_executor(None, _recover_proxy_once, proxy)
                    for proxy in due[:PROBE_MAX_PARALLEL]
                ], return_exceptions=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log("WARN", f"proxy auto-recovery loop recovered from {type(exc).__name__}: "
                        f"{redact(str(exc))[:140]}")
        await asyncio.sleep(min(PROXY_RECOVERY_INTERVAL_SEC, 15.0))


# ---------- picker ----------
def _flagged_and_quarantined(include_flagged: bool) -> set:
    _proxy_health_load()
    bad = set(_QUARANTINED_KEYS)
    if not include_flagged:
        bad |= _flagged_active()
    return bad


async def apick_live_proxy(jar: Optional[dict], *, purpose: str = "", rotate: bool = False,
                           include_flagged: bool = False,
                           exclude: Optional[set] = None) -> Optional[str]:
    """Rotation-aware pick among exits PROVEN to tunnel to arena recently.
    Unknown lines are probed inside a per-cycle budget, never blocking traffic."""
    if LOCAL_UPSTREAM and purpose == "api":
        return None
    assignment_mode = _rotation_mode() == "assignment"
    excluded = set(exclude or ())
    cands = [c for c in proxy_candidates(jar, prefer_sticky=assignment_mode and not rotate)
             if c not in excluded and _proxy_hkey(c) not in excluded]
    if not cands:
        return None
    bad = _flagged_and_quarantined(include_flagged)
    now = time.time()
    live, unknown = [], []
    for c in cands:
        k = _proxy_hkey(c)
        if k in bad or c in bad:
            continue
        cached = _proxy_probe_cache.get(c)
        if cached and cached[0] and cached[1] > now:
            live.append(c)
        elif cached and (not cached[0]) and cached[1] > now:
            continue  # known-dead, don't re-probe inside its fresh-negative window
        else:
            unknown.append(c)
    if unknown:
        budget = min(len(unknown), PROBE_BUDGET)
        loop = __import__("asyncio").get_running_loop()
        def _probe_batch():
            with _cf.ThreadPoolExecutor(max_workers=PROBE_MAX_PARALLEL) as ex:
                futs = {ex.submit(_proxy_probe, u): u for u in unknown[:budget]}
                for fu in _cf.as_completed(futs):
                    u = futs[fu]
                    try:
                        ok, ms = fu.result()
                    except Exception:
                        ok, ms = False, -1
                    _proxy_probe_cache[u] = (bool(ok), (now + PROBE_OK_TTL) if ok else (now + 120))
                    if ok:
                        _proxy_latency[u] = max(ms, 1)
                    _proxy_health_record(u, bool(ok), ms if ms > 0 else 0, source=f"pick:{purpose}" if purpose else "pick")
        try:
            await loop.run_in_executor(None, _probe_batch)
        except Exception:
            pass
        for c in list(unknown):
            cached = _proxy_probe_cache.get(c)
            if cached and cached[0] and cached[1] > now and _proxy_hkey(c) not in _flagged_and_quarantined(include_flagged):
                live.append(c)
    if not live:
        if not include_flagged and cands:
            # fluid last resort: cycle flagged exits (blocks move; a 200 un-flags)
            return await apick_live_proxy(jar, purpose=purpose or "last-resort", rotate=rotate,
                                          include_flagged=True, exclude=excluded)
        return None
    if purpose == "keeper":
        current_id = (jar or {}).get("id")
        reserved = set()
        for sid, session in keeper.sessions.items():
            if sid == current_id:
                continue
            used_proxy = _normalize_proxy(getattr(session, "_used_proxy", "") or "")
            if used_proxy:
                reserved.add(used_proxy)
        unreserved = [candidate for candidate in live if candidate not in reserved]
        # Prefer one exit per keeper while capacity exists. If the pool is
        # smaller than the fleet, sharing remains an explicit last resort.
        if unreserved:
            live = unreserved
    if assignment_mode and not rotate and jar is not None:
        pinned = _normalize_proxy(jar.get("proxy") or "") or None
        if pinned and pinned in live:
            if jar.get("id"):
                await anchor_proxy_to_keeper(jar["id"], pinned)
            return pinned
    n = len(live)
    with _pick_mu:
        global _pick_ctr
        _pick_ctr = (_pick_ctr + 1) % n
        chosen = live[_pick_ctr]
    _bump_cursor(chosen)
    if jar is not None and jar.get("id"):
        if assignment_mode:
            assign_jar_proxy(jar["id"], chosen)
        try:
            await anchor_proxy_to_keeper(jar["id"], chosen)
        except Exception:
            pass
    return chosen


# ---------- sweep (Scan pool) ----------
def _sweep_all_impl() -> dict:
    now = time.time()
    lines = _pool_lines()
    stats = {"total": len(lines), "alive": 0, "flagged": 0, "dead": 0}
    if not lines:
        return stats

    def one(u: str):
        norm = _normalize_proxy(u) or u
        ok, ms = _proxy_probe(norm)
        return norm, ok, ms

    with _cf.ThreadPoolExecutor(max_workers=PROBE_MAX_PARALLEL) as ex:
        futs = [ex.submit(one, l) for l in lines if l.strip() and not l.startswith("#")]
        for fu in _cf.as_completed(futs):
            try:
                norm, ok, ms = fu.result()
            except Exception:
                continue
            key = _proxy_hkey(norm)
            if ok:
                stats["alive"] += 1
                _proxy_probe_cache[norm] = (True, time.time() + PROBE_OK_TTL)
                _proxy_latency[norm] = max(ms, 1)
                _proxy_health_record(norm, True, ms, source="sweep")
                _proxy_strikes.pop(key, None)
                _proxy_recovery_failures.pop(key, None)
                _proxy_recovery_due.pop(key, None)
                _proxy_quarantine_reason.pop(key, None)
                if key in _QUARANTINED_KEYS:
                    _QUARANTINED_KEYS.discard(key)
                    log("OK", f"proxy sweep recovered circuit-open exit: {key} · re-admitted")
                if key in _flagged_exits:
                    _flagged_exits.pop(key, None)   # alive on arena again — un-flag
            else:
                why = _probe_fail_reason.get(norm, "")
                _proxy_probe_cache[norm] = (False, time.time() + 300)
                if "refused" in why.lower() or "dns" in why.lower() or "black-holed" in why.lower():
                    stats["dead"] += 1
                    strike_proxy(norm, why or "probe failed")
                else:
                    stats["flagged"] += 1
                    note_cf_blocked_exit(norm, why or "arena unreachable")
    log("OK", f"proxy sweep done: {stats['alive']}/{stats['total']} usable against Arena "
             f"(tunnel-dead nodes got strikes; Arena-blocked exits flagged ~3h)")
    return stats


def sweep_all() -> dict:
    """Run at most one full pool scan per process."""
    if not _proxy_sweep_mu.acquire(blocking=False):
        return {"running": True, "total": len(_pool_lines()), "alive": 0,
                "flagged": 0, "dead": 0}
    try:
        return _sweep_all_impl()
    finally:
        _proxy_sweep_mu.release()


# ---------- ingest / prune / revive ----------
def _parse_proxy_line_loose(raw: str) -> Optional[str]:
    """Best-effort proxy parser. Credentials are optional."""
    if raw is None:
        return None
    line = str(raw).strip().lstrip("\ufeff").strip().strip('"\'')
    if not line or line.startswith("#") or line.startswith("//"):
        return None
    line = re.sub(r"^\s*(?:[-*•]\s+|\d+[.)]\s+)", "", line).strip()
    n = _normalize_proxy(line)
    if n:
        return n
    schemes=("socks5h","socks5","socks4a","socks4","https","http")
    low=line.lower()
    scheme=next((x for x in schemes if re.search(rf"(?<![a-z0-9]){re.escape(x)}(?![a-z0-9])",low)),"http")
    fields=[x for x in re.split(r"[\s|;,]+",line) if x]
    if len(fields)>=3:
        if fields[0].lower() in schemes and fields[2].isdigit():
            return _normalize_proxy(f"{fields[0].lower()}://{fields[1]}:{fields[2]}")
        if fields[1].isdigit() and fields[2].lower() in schemes:
            return _normalize_proxy(f"{fields[2].lower()}://{fields[0]}:{fields[1]}")
    if len(fields)>=2 and fields[1].isdigit():
        return _normalize_proxy(f"{scheme}://{fields[0]}:{fields[1]}")
    m=re.fullmatch(r"(?P<host>\[[0-9a-fA-F:]+\]|[^:\s]+):(?P<port>\d{1,5}):(?P<scheme>socks5h|socks5|socks4a|socks4|https|http)",line,flags=re.I)
    if m and 0<int(m.group('port'))<=65535:
        return _normalize_proxy(f"{m.group('scheme').lower()}://{m.group('host')}:{m.group('port')}")
    hp=re.search(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\[[0-9a-fA-F:]+\]):(?P<port>\d{1,5})(?!\d)",line)
    if hp:
        port=int(hp.group('port')); host=hp.group('host')
        if 0<port<=65535:
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",host) and any(int(x)>255 for x in host.split('.')):
                return None
            return _normalize_proxy(f"{scheme}://{host}:{port}")
    return None


def _split_proxy_blob(text: str) -> List[str]:
    if not text:
        return []
    raw_lines=[x.strip() for x in str(text).replace("\r","\n").split("\n") if x.strip()]
    out=[]
    for line in raw_lines:
        if line.startswith("#") or line.startswith("//"):
            continue
        hits=re.findall(r"(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@\s]+@)?(?:\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.-]+\.[A-Za-z]{2,}):\d{1,5}",line)
        if len(hits)>=2 and ',' not in line:
            out.extend(hits)
        else:
            out.append(line)
    return out


def parse_upload(text: str) -> Tuple[List[str], int, int]:
    """Parse pasted/uploaded proxy lists. Authentication is optional."""
    import csv as _csv, io as _io
    source_lines=_split_proxy_blob(text)
    out=[]; skipped=0; hinted=0; unresolved=[]
    for line in source_lines:
        n=_parse_proxy_line_loose(line)
        if n: out.append(n)
        else: unresolved.append(line)
    csvish=[line for line in unresolved if ',' in line]
    skipped += len([line for line in unresolved if ',' not in line])
    if csvish:
        try: rows=list(_csv.reader(_io.StringIO("\n".join(csvish)),skipinitialspace=True))
        except Exception: rows=[]
        header=[str(x).strip().lower() for x in rows[0]] if rows else []
        known={"host","ip","ip address","ip_address","proxy","proxy address","server","port","proxy port","username","user","password","pass","type","scheme","protocol","proxy type"}
        has_header=any(x in known for x in header)
        idx={name:i for i,name in enumerate(header)} if has_header else {}
        body=rows[1:] if has_header else rows
        for row in body:
            row=[str(x).strip() for x in row]
            if not row: skipped+=1; continue
            def col(*names):
                for name in names:
                    if name in idx and idx[name]<len(row): return row[idx[name]]
                return ""
            if has_header:
                host=col("host","ip","ip address","ip_address","proxy","proxy address","server")
                port=col("port","proxy port"); user=col("username","user"); pw=col("password","pass")
                typ=(col("type","scheme","protocol","proxy type") or "http").lower()
            else:
                host=row[0] if len(row)>0 else ""; port=row[1] if len(row)>1 else ""
                typ=row[2].lower() if len(row)==3 and row[2].lower() in ("http","https","socks4","socks4a","socks5","socks5h") else (row[4].lower() if len(row)>=5 else "http")
                user=row[2] if len(row)>=4 else ""; pw=row[3] if len(row)>=4 else ""
                if len(row)==3 and row[2].lower() in ("http","https","socks4","socks4a","socks5","socks5h"): user=""
            if not host or not str(port).isdigit() or not (0<int(port)<=65535):
                n=_parse_proxy_line_loose(','.join(row))
                if n: out.append(n)
                else: skipped+=1
                continue
            if typ not in ("http","https","socks4","socks4a","socks5","socks5h"):
                typ="http"; hinted+=1
            if user:
                from urllib.parse import quote as _q
                auth=f"{_q(user,safe='')}:{_q(pw or '',safe='')}@"
            else: auth=""
            out.append(f"{typ}://{auth}{host}:{port}")
    seen=set(); dedup=[]
    for candidate in out:
        n=_normalize_proxy(candidate)
        if not n:
            skipped+=1
            continue
        # Accept local proxy shims, including socks5h://127.0.0.1:<port>.
        key=n.strip().lower()
        if key not in seen:
            seen.add(key)
            dedup.append(n)
    return dedup, skipped, hinted


def upload_pool(text: str) -> dict:
    new, skipped, hinted = parse_upload(text)
    cur = _pool_lines()
    cur_keys = {(_normalize_proxy(l) or l).strip().lower() for l in cur if l.strip()}
    add = [u for u in new if (_normalize_proxy(u) or u).strip().lower() not in cur_keys]
    merged = cur + add
    pool_save(merged)
    log("OK", f"proxy manager: +{len(add)} from upload/paste ({len(new)} parsed, {skipped} skipped, {max(0, len(new)-len(add))} duplicates, {sum(1 for u in add if _is_local_proxy_shim(u))} local shims, {hinted} protocol hints)")
    return {
        "added": len(add),
        "parsed": len(new),
        "skipped": skipped,
        "duplicates": max(0, len(new) - len(add)),
        "hinted": hinted,
        "local_shims": sum(1 for u in add if _is_local_proxy_shim(u)),
    }


def prune_bad() -> int:
    """Non-destructive prune: circuit-break bad exits and let auto-recovery heal them."""
    affected = 0
    for l in _pool_lines():
        if not l.strip() or l.startswith("#"):
            continue
        norm = _normalize_proxy(l) or l
        k = _proxy_hkey(norm)
        cached = _proxy_probe_cache.get(norm)
        if (k in _QUARANTINED_KEYS or
                _proxy_strikes.get(k, 0) >= STRIKES_MAX or
                (cached and not cached[0])):
            if k not in _QUARANTINED_KEYS:
                quarantine_proxy(norm, "marked bad by proxy manager")
            affected += 1
    log("OK", f"proxy prune 'bad': {affected} circuit-open · 0 deleted · auto-recovery active")
    return affected


def remove_one(hkey: str) -> int:
    lines = _pool_lines()
    keep = [l for l in lines if _proxy_hkey(_normalize_proxy(l) or l) != hkey]
    if len(keep) == len(lines):
        return 0
    pool_save(keep)
    _QUARANTINED_KEYS.add(hkey)
    return len(lines) - len(keep)


def delete_all_proxies() -> dict:
    """Clear the active pool, retaining a timestamped recovery snapshot."""
    lines = [line for line in _pool_lines() if line.strip() and not line.startswith("#")]
    if not lines:
        return {"removed": 0, "backup": None}
    source = _proxies_file() or os.path.join(".", PROXIES_FILE)
    backup = os.path.join(os.path.dirname(source) or ".",
                          f"proxies.deleted.{int(time.time())}.txt")
    try:
        shutil.copyfile(source, backup)
    except OSError:
        backup = None
    pool_save([])
    cfg = get_config()
    if cfg.get("proxies"):
        cfg["proxies"] = []
        save_config(cfg)
    _proxy_probe_cache.clear()
    _proxy_latency.clear()
    _proxy_strikes.clear()
    _flagged_exits.clear()
    log("WARN", f"proxy manager: deleted all {len(lines)} active proxies"
        + (f" · backup {os.path.basename(backup)}" if backup else ""))
    return {"removed": len(lines), "backup": os.path.basename(backup) if backup else None}


def revive_one(hkey: str) -> dict:
    """Pull lines back from proxies.dead.txt into the pool, clearing verdicts."""
    revived, kept_dead = [], []
    try:
        with open(DEAD_FILE, encoding="utf-8") as f:
            for raw in f.read().splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                norm = _normalize_proxy(line) or line
                if hkey in ("*", _proxy_hkey(norm)):
                    revived.append(norm)
                else:
                    kept_dead.append(raw)
    except FileNotFoundError:
        return {"revived": 0, "why": "no dead file"}
    cur = _pool_lines()
    cur_keys = {_proxy_hkey(_normalize_proxy(l) or l) for l in cur}
    added = 0
    for u in revived:
        if _proxy_hkey(u) not in cur_keys:
            cur.append(u); cur_keys.add(_proxy_hkey(u)); added += 1
        k = _proxy_hkey(u)
        _QUARANTINED_KEYS.discard(k)
        _flagged_exits.pop(k, None)
        _proxy_strikes.pop(k, None)
        _proxy_probe_cache.pop(u, None)
    pool_save(cur)
    tmp = DEAD_FILE + f".tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(kept_dead) + ("\n" if kept_dead else ""))
    os.replace(tmp, DEAD_FILE)
    log("OK", f"revive {hkey}: {added} back in pool")
    return {"revived": added}


def snapshot_rows() -> List[dict]:
    """Row-per-exit truth for the pool page: verdict column names WHERE it dies."""
    _proxy_health_load()  # verdicts must survive a restart: hydrate from proxies.health.json once
    now = time.time()
    flagged = _flagged_active()
    rows = []
    seen = set()
    for l in _pool_lines():
        if not l.strip() or l.startswith("#"):
            continue
        norm = _normalize_proxy(l) or l
        k = _proxy_hkey(norm)
        if k in seen:
            continue
        seen.add(k)
        verdict, why = "unknown", ""
        cached = _proxy_probe_cache.get(norm)
        if k in _QUARANTINED_KEYS or _proxy_strikes.get(k, 0) >= STRIKES_MAX:
            verdict, why = "recovering", (_proxy_quarantine_reason.get(k) or _probe_fail_reason.get(norm, "temporarily circuit-open"))
        elif k in flagged:
            exp = int(_flagged_exits.get(k, now) - now)
            why = f"flagged ~{exp}s left: " + (_probe_fail_reason.get(norm) or "arena refused CONNECT")
            verdict = "arena-blocked"
        elif cached and cached[1] > now:
            verdict = "alive" if cached[0] else "unreachable"
            if not cached[0]:
                why = _probe_fail_reason.get(norm, "")
        h = _proxy_health.get(k) or _proxy_health.get(norm) or {}
        if verdict == "unknown" and h:  # verdicts survive restarts: trust the last sweep while fresh
            try:
                _fresh = (now - time.mktime(time.strptime(h.get("checked", ""), "%Y-%m-%d %H:%M:%S"))) < HEALTH_TRUST_SEC
            except Exception:
                _fresh = False
            if _fresh:
                verdict = "alive" if h.get("ok") else "unreachable"
                if not h.get("ok"):
                    why = f"failed {h.get('source', 'last')} sweep · strikes {h.get('fails', 0)}"
        rows.append({"key": k, "display": k, "scheme": (urlparse(norm).scheme if "://" in norm else "?"),
                     "verdict": verdict, "why": redact(why)[:140],
                     "latency": _proxy_latency.get(norm) or _proxy_latency.get(k) or (h.get("latency") if h.get("ok") else None),
                     "checked": h.get("checked"), "source": h.get("source", ""),
                     "strikes": _proxy_strikes.get(k, 0)})
    rows.sort(key=lambda r: (r["verdict"] != "alive", r["verdict"] != "arena-blocked", r["key"]))
    return rows


# ────────────────────────── module: tokens.py ──────────────────────────────

# ============================================================
# v2 TOKENS — reCAPTCHA protocol layer.
# The wire truth (mined from arena's live bundle 2026-09-03):
#   • body keys are recaptchaV3Token / recaptchaV2Token (NOT "recaptchaToken")
#   • V3: grecaptcha.enterprise.ready(() => execute(SITEKEY, {action})) —
#     POSITIONAL call shape; object form throws 'No reCAPTCHA clients exist.'
#   • on recaptcha_validation_failed the SITE escalates to a V2 checkbox
#     challenge; the client then retries with recaptchaV2Token and V3 nulled.
# Minting happens ONLY on a keeper page (same origin + same exit IP as the
# eventual request — Google correlates IP and UA between mint and verify).
# ============================================================
import asyncio, time  # noqa

RC_MINT_JS = r"""async (OPTS) => {
                const FALLBACK = String(OPTS?.fallbackSitekey || '');
                const ALLOW_FALLBACK = !!OPTS?.allowConfiguredFallback;
                const ACTION = String(OPTS?.action || 'chat_submit');
                const validKey = (v) => typeof v === 'string' && /^6[0-9A-Za-z_-]{30,}$/.test(v);
                const hint = (v) => validKey(v) ? `${v.slice(0, 8)}…${v.slice(-4)}` : 'none';
                const g = window.grecaptcha;
                if (!g) return {err: 'no grecaptcha object on keeper page (arena widget script not on this URL?)'};
                // Never read a token from response fields/getResponse here.
                // Arena may already have consumed it while the DOM retains the
                // value, and replaying that stale token deterministically fails
                // validation. Primary V3 tokens must always come from execute().
                let sitekey = null;
                let source = null;
                const node = document.querySelector('[data-sitekey]');
                if (node && validKey(node.getAttribute('data-sitekey'))) {
                    sitekey = node.getAttribute('data-sitekey'); source = 'data-sitekey';
                }
                if (!sitekey) {
                    for (const script of [...document.scripts]) {
                        try {
                            const render = new URL(script.src, location.href).searchParams.get('render');
                            if (validKey(render) && render !== 'explicit') {
                                sitekey = render; source = 'api.js?render'; break;
                            }
                        } catch (e) {}
                    }
                }
                if (!sitekey) {
                    for (const frame of [...document.querySelectorAll('iframe[src]')]) {
                        try {
                            const key = new URL(frame.src, location.href).searchParams.get('k');
                            if (validKey(key)) { sitekey = key; source = 'recaptcha-iframe'; break; }
                        } catch (e) {}
                    }
                }
                if (!sitekey && window.___grecaptcha_cfg && ___grecaptcha_cfg.clients) {
                    try {
                        const seen = new WeakSet();
                        const scan = (value, depth = 0) => {
                            if (validKey(value)) return value;
                            if (!value || typeof value !== 'object' || depth > 7 || seen.has(value)) return null;
                            seen.add(value);
                            for (const [name, child] of Object.entries(value)) {
                                if (/token|response/i.test(name)) continue;
                                const found = scan(child, depth + 1);
                                if (found) return found;
                            }
                            return null;
                        };
                        for (const c of Object.values(___grecaptcha_cfg.clients)) {
                            const k = scan(c);
                            if (k) { sitekey = k; source = 'grecaptcha-client'; break; }
                        }
                    } catch (e) {}
                }
                const KEY = sitekey || (ALLOW_FALLBACK ? FALLBACK : '');
                source = source || (ALLOW_FALLBACK ? 'configured-fallback' : 'none');
                if (!validKey(KEY)) return {err: 'no valid site key discovered', source, keyHint: hint(KEY), action: ACTION};
                const ex = (a1, a2) => new Promise((res2, rej2) => {
                    const fail = setTimeout(() => rej2(new Error('execute-timeout (12s)')), 12000);
                    const go = () => {
                        if (!g.enterprise || typeof g.enterprise.execute !== 'function') {
                            clearTimeout(fail); rej2(new Error('no enterprise.execute after ready')); return;
                        }
                        let p;
                        try { p = g.enterprise.execute(a1, a2); }
                        catch (e) { clearTimeout(fail); rej2(e); return; }
                        Promise.resolve(p).then(v => { clearTimeout(fail); res2(v); },
                                                 e2 => { clearTimeout(fail); rej2(e2); });
                    };
                    // the page ships a ready-shim: 'no execute' may just be pre-hydration
                    try { (g.enterprise && g.enterprise.ready) ? g.enterprise.ready(go) : go(); }
                    catch (e) { clearTimeout(fail); rej2(e); }
                });
                try {
                    // arena's own shape (proven against the live page 2026-09-03):
                    // POSITIONAL (sitekey, {action}) inside enterprise.ready. The object
                    // form throws 'No reCAPTCHA clients exist.' on this widget build.
                    const tok = await ex(KEY, {action: ACTION});
                    if (tok && tok.length > 20) return {token: tok, source, keyHint: hint(KEY), action: ACTION};
                    return {err: 'enterprise.execute resolved empty (Google scored this session low — image challenge may follow)', source, keyHint: hint(KEY), action: ACTION};
                } catch (e1) {
                    // The object-form enterprise call is known-bad on the current
                    // live widget and only adds another full timeout. Skip it.
                    try {
                        if ((!g.enterprise || typeof g.enterprise.execute !== 'function')
                            && typeof g.execute === 'function') {
                            const t3 = await Promise.race([
                                g.execute(KEY, {action: ACTION}),
                                new Promise((_, r) => setTimeout(() => r(new Error('v3-timeout')), 5000))
                            ]);
                            if (t3 && t3.length > 20) return {token: t3, source, keyHint: hint(KEY), action: ACTION};
                        }
                    } catch (e3) {}
                    return {err: 'execute failed: ' + String(e1).slice(0, 160), source, keyHint: hint(KEY), action: ACTION};
                }
            }"""

RC_V2_WIDGET_JS = """async (SITE) => {
  // mount a V2 checkbox under the escalation sitekey in the viewport corner
  try {
    let host = document.getElementById('bgn-v2-host');
    if (host) {
      host.remove();
    }
    host = document.createElement('div');
    host.id = 'bgn-v2-host';
    host.className = 'recaptcha-v2-container g-recaptcha';
    host.style.cssText = 'position:fixed;bottom:12px;right:12px;width:304px;height:78px;z-index:2147483647;opacity:1;background:#1a1a1a;border-radius:4px;box-shadow:0 0 10px rgba(0,0,0,0.3);';
    document.body.appendChild(host);

    window.__bgnV2Token = null;
    window.__bgnV2Done = false;
    window.__bgnV2Err = null;
    const api = (window.grecaptcha && window.grecaptcha.enterprise) ? grecaptcha.enterprise : grecaptcha;
    window.__bgnV2 = api.render(host, {
      sitekey: SITE,
      size: 'normal',
      theme: 'dark',
      callback: (tok) => { window.__bgnV2Done = true; window.__bgnV2Token = tok; },
      'error-callback': () => { window.__bgnV2Err = 'widget-error'; },
      'expired-callback': () => { window.__bgnV2Done = false; window.__bgnV2Token = null; }
    });
    return {ok: true};
  } catch (e) { return {ok: false, err: String(e).slice(0, 160)}; }
}"""

RC_V2_READ_JS = """() => {
  try {
    if (window.__bgnV2Err) return '__ERR__' + window.__bgnV2Err;
    if (window.__bgnV2Token && typeof window.__bgnV2Token === 'string' && window.__bgnV2Token.length > 20) {
      return window.__bgnV2Token;
    }
    const api = (window.grecaptcha && window.grecaptcha.enterprise) ? grecaptcha.enterprise : grecaptcha;
    if (window.__bgnV2 !== undefined && typeof api.getResponse === 'function') {
      const t = api.getResponse(window.__bgnV2);
      if (t && t.length > 20) return t;
    }
    const host = document.getElementById('bgn-v2-host');
    if (host) {
      const el = host.querySelector('textarea[name="g-recaptcha-response"]');
      if (el && el.value && el.value.length > 20) return el.value;
    }
    const anyEl = document.querySelector('textarea[name="g-recaptcha-response"]');
    if (anyEl && anyEl.value && anyEl.value.length > 20) return anyEl.value;
    return null;
  } catch (e) { return null; }
}"""

RC_V2_CLEAR_JS = """() => {
  try {
    window.__bgnV2Token = null;
    window.__bgnV2Done = false;
    window.__bgnV2Err = null;
    const api = (window.grecaptcha && window.grecaptcha.enterprise) ? grecaptcha.enterprise : grecaptcha;
    if (window.__bgnV2 !== undefined && typeof api.reset === 'function') {
      try { api.reset(window.__bgnV2); } catch(e) {}
    }
    document.querySelectorAll('textarea[name="g-recaptcha-response"]').forEach(el => {
      el.value = '';
      el.innerHTML = '';
    });
  } catch (e) {}
}"""

_mint_last_no_session = 0.0
_verification_adapter_warned_at = 0.0


def _verification_token_ok(token) -> bool:
    """Reject empty, truncated, placeholder, or obviously synthetic tokens."""
    if not isinstance(token, str):
        return False
    value = token.strip()
    if len(value) < VERIFICATION_MIN_TOKEN_LEN or any(ch.isspace() for ch in value):
        return False
    lowered = value.lower()
    return not any(marker in lowered for marker in (
        "fixture", "placeholder", "dummy-token", "test-token", "example-token",
    ))


def _externally_reachable_proxy(session) -> Optional[str]:
    """Return the keeper's route, unwrapping a managed shim when possible.

    If the route is an externally managed localhost tunnel, preserve it instead
    of silently switching the adapter to direct egress. The adapter can then
    either use that local route or reject it explicitly.
    """
    candidate = getattr(session, "_used_proxy", None) or None
    if not candidate:
        return None
    try:
        parsed = urlparse(candidate)
        if (parsed.hostname or "").lower() not in {"localhost", "127.0.0.1", "::1"}:
            return candidate
        for upstream, local_port in (_shim_state.get("ports") or {}).items():
            if parsed.port == local_port:
                return upstream
    except Exception:
        pass
    return candidate


_verification_adapter_bad_shapes = 0
_verification_adapter_disabled_until = 0.0
VERIFICATION_ADAPTER_BAD_SHAPE_LIMIT = max(1, min(5, int(os.environ.get("BRIDGENA_VERIFICATION_ADAPTER_BAD_SHAPE_LIMIT", "1"))))

async def _solve_with_verification_adapter(challenge_type: str, session,
                                            site_key: str, action: Optional[str] = None):
    """Request a token from the optional async verification adapter.

    Cookie values and tokens are deliberately excluded from logs. The bundled
    ONNX get_solver() remains independent from the adapter factory alias.
    """
    global _verification_adapter_warned_at
    global _verification_adapter_bad_shapes, _verification_adapter_disabled_until

    now_mono = time.monotonic()
    if now_mono < _verification_adapter_disabled_until:
        return None

    if get_verification_solver is None:
        now = time.time()
        if now - _verification_adapter_warned_at > 300:
            _verification_adapter_warned_at = now
            log("WARN", "optional verification adapter unavailable; using keeper-native verification"
                + (f": {_VERIFICATION_IMPORT_ERROR}" if _VERIFICATION_IMPORT_ERROR else
                   ": recaptcha_solver.py was not found beside bridgena.py"))
        return None
    try:
        factory_result = get_verification_solver()
        solver = await factory_result if hasattr(factory_result, "__await__") else factory_result
        if solver is None or not hasattr(solver, "solve"):
            log("WARN", "verification adapter unavailable: factory returned no solver")
            return None

        cookie_map = {}
        if LOCAL_UPSTREAM and getattr(session, "_public_cookie_snapshot", None):
            for cookie in session._public_cookie_snapshot:
                name, value = cookie.get("name"), cookie.get("value")
                if name and value:
                    cookie_map[name] = value
        elif getattr(session, "context", None):
            for cookie in await session.context.cookies([ARENA_BASE]):
                name, value = cookie.get("name"), cookie.get("value")
                if name and value:
                    cookie_map[name] = value

        persona = getattr(session, "persona", None)
        user_agent = (getattr(persona, "ua", None)
                      or getattr(session, "user_agent", None)
                      or KEEPER_UA)
        proxy = _externally_reachable_proxy(session)
        page_url = PUBLIC_AUTH_BASE if LOCAL_UPSTREAM else (
            getattr(getattr(session, "page", None), "url", None) or ARENA_BASE
        )
        if not LOCAL_UPSTREAM and not str(page_url).startswith(ARENA_BASE):
            page_url = ARENA_BASE

        proxy_kind = ("local-route" if proxy and _is_loopback_proxy(proxy)
                      else "upstream" if proxy else "direct")
        log("INFO", f"verification adapter request · type {challenge_type}"
            f" · origin {urlparse(page_url).hostname or 'unknown'}"
            f" · proxy {proxy_kind} · cookies {len(cookie_map)}")

        solve_result = solver.solve(
            challenge_type=challenge_type,
            site_key=site_key,
            page_url=page_url,
            action=action,
            enterprise=True,
            user_agent=user_agent,
            proxy=proxy,
            cookies=cookie_map,
            timeout=VERIFICATION_TIMEOUT_SEC,
        )
        result = (await asyncio.wait_for(solve_result, timeout=VERIFICATION_TIMEOUT_SEC + 5)
                  if hasattr(solve_result, "__await__") else solve_result)
        token = result.get("token") if isinstance(result, dict) and result.get("ok") else None
        if _verification_token_ok(token):
            _verification_adapter_bad_shapes = 0
            log("OK", "verification adapter completed"
                + f" · provider {result.get('provider', 'wrapper')}"
                + f" · task {str(result.get('task_id') or '-')[:12]}"
                + f" · {int(result.get('elapsed_ms') or 0)}ms")
            return token
        if isinstance(token, str):
            _verification_adapter_bad_shapes += 1
            log("WARN", "verification adapter returned an invalid token shape"
                + f" ({len(token)} chars; minimum {VERIFICATION_MIN_TOKEN_LEN})")
            if _verification_adapter_bad_shapes >= VERIFICATION_ADAPTER_BAD_SHAPE_LIMIT:
                _verification_adapter_disabled_until = time.monotonic() + 300.0
                log("WARN", f"verification adapter circuit-open for 300s after {_verification_adapter_bad_shapes} invalid token shape(s); "
                            "keeper-native verification will be used")
            return None
        error = result.get("error") if isinstance(result, dict) else "invalid adapter response"
        log("WARN", f"verification adapter failed: {str(error)[:180]}")
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log("WARN", f"verification adapter error: {type(exc).__name__}: {str(exc)[:180]}")
    return None


def _find_session(jar_id=None):
    """Same contract as the legacy helper: (sid, session) for a RUNNING keeper
    whose page is alive; prefer this jar's own keeper (its exit is where the
    token must be minted)."""
    try:
        sessions = keeper.sessions
    except Exception:
        return None, None
    if jar_id:
        s = sessions.get(jar_id)
        if keeper_session_ready(s):
            return jar_id, s
        # A token from some other account/browser/exit is not a fallback: it is
        # cryptographically and behaviorally the wrong identity for this jar.
        return None, None
    for sid, s in list(sessions.items()):
        if keeper_session_ready(s):
            return sid, s
    return None, None


_V3_MINT_FAILURES: Dict[str, dict] = {}

def _set_v3_mint_failure(jar_id, reason: str, *, stage: str = "unknown") -> None:
    key = str(jar_id or "")
    _V3_MINT_FAILURES[key] = {
        "reason": str(reason or "unknown")[:500],
        "stage": str(stage or "unknown")[:80],
        "ts": time.time(),
    }

def _clear_v3_mint_failure(jar_id) -> None:
    _V3_MINT_FAILURES.pop(str(jar_id or ""), None)

def _get_v3_mint_failure(jar_id) -> dict:
    return dict(_V3_MINT_FAILURES.get(str(jar_id or ""), {}))


async def mint_v3(jar_id=None):
    """Primary token: evaluate grecaptcha v3 on a live keeper page. If v3 bypass
    fails or produces no token, automatically falls back to visual image challenge solving."""
    global _mint_last_no_session
    sid, s = _find_session(jar_id)
    _clear_v3_mint_failure(jar_id)
    if not s:
        _set_v3_mint_failure(jar_id, "no live keeper session", stage="session_lookup")
        now = time.time()
        if now - _mint_last_no_session > 60:
            _mint_last_no_session = now
            log("WARN", "recaptcha token: no live keeper session — tokens are minted from a browser "
                        "on the SAME exit; enable keepers (Pool page) or open Live Browser")
        return None
    try:
        async with s._action_lock:
            adapter_token = await _solve_with_verification_adapter(
                "enterprise_v3", s, ARENA_RECAPTCHA_SITEKEY, RECAPTCHA_ACTION
            )
            if adapter_token:
                _clear_v3_mint_failure(jar_id)
                return adapter_token

            # Avoid unnecessary navigation: if this keeper already has a live
            # grecaptcha client, use it in-place. Navigation is the dominant source
            # of ERR_NETWORK_CHANGED / destroyed execution contexts on tunnel churn.
            try:
                has_grecaptcha = bool(await s.page.evaluate(
                    "() => !!(window.grecaptcha && (window.grecaptcha.enterprise || window.grecaptcha.execute))"
                ))
            except Exception:
                has_grecaptcha = False

            if not has_grecaptcha and "mode=direct" not in (s.page.url or ""):
                try:
                    await s.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=15000)
                except Exception as nav_exc:
                    if "ERR_NETWORK_CHANGED" not in str(nav_exc):
                        _set_v3_mint_failure(jar_id, f"keeper navigation failed: {type(nav_exc).__name__}: {nav_exc}", stage="navigation")
                        raise
                    log("WARN", f"[{sid}] keeper navigation saw network change; retrying once after route settles")
                    await asyncio.sleep(0.75)
                    await s.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=15000)
                s.last_nav = time.time()

            if not LOCAL_VERIFICATION_ENHANCED:
                try:
                    if hasattr(s, "_human_move") and s.page:
                        size = s.page.viewport_size or {"width": 1920, "height": 1080}
                        tx = random.randint(350, max(351, size.get("width", 1920) - 150))
                        ty = random.randint(200, max(201, size.get("height", 1080) - 200))
                        await s._human_move(s.page, tx, ty, steps=random.randint(4, 7))
                except Exception:
                    pass

            v3_token = None
            try:
                await s.page.wait_for_function(
                    "() => !!(window.grecaptcha && (window.grecaptcha.enterprise || window.grecaptcha.execute))",
                    timeout=8000,
                )
                res = await s.page.evaluate(RC_MINT_JS, {
                    "fallbackSitekey": ARENA_RECAPTCHA_SITEKEY,
                    "allowConfiguredFallback": ALLOW_CONFIGURED_RECAPTCHA_FALLBACK,
                    "action": RECAPTCHA_ACTION,
                })
                if _verification_token_ok(res):
                    v3_token = res
                elif isinstance(res, dict) and _verification_token_ok(res.get("token")):
                    log("OK", "recaptcha v3 token minted via " + str(res.get("source", "unknown"))
                        + " · key " + str(res.get("keyHint", "unknown"))
                        + " · action " + str(res.get("action", RECAPTCHA_ACTION)))
                    v3_token = res["token"]
                else:
                    why = res.get("err") if isinstance(res, dict) else "evaluate returned nothing"
                    _set_v3_mint_failure(jar_id, str(why), stage="enterprise_execute")
                    log("WARN", f"recaptcha v3 unavailable ({why})")
            except Exception as v3_err:
                _set_v3_mint_failure(jar_id, f"{type(v3_err).__name__}: {v3_err}", stage="enterprise_execute")
                log("WARN", f"recaptcha v3 evaluate timed out/failed: {v3_err}")

            if v3_token:
                _clear_v3_mint_failure(jar_id)
                return v3_token
            if not _get_v3_mint_failure(jar_id):
                _set_v3_mint_failure(jar_id, "enterprise execute produced no usable token", stage="enterprise_execute")
            return None

    except Exception as e:
        _set_v3_mint_failure(jar_id, f"{type(e).__name__}: {e}", stage="browser_transaction")
        log("WARN", f"recaptcha token: browser transaction failed: {type(e).__name__}: {e}")
    return None


async def mint_v2_escalation(jar_id=None, settle_s: float = 20.0):
    """Escalate V2 verification.

    Localhost uses the authorized deterministic v3.1 flow:
    mount -> click -> inspect -> solve -> verify.
    """
    sid, s = _find_session(jar_id)
    if not s:
        log("WARN", "verification V2 escalation skipped — no live keeper session")
        return None

    try:
        async with s._action_lock:
            adapter_token = await _solve_with_verification_adapter(
                "recaptcha_enterprise_v2", s, ARENA_RECAPTCHA_V2_SITEKEY
            )
        if adapter_token:
            return adapter_token
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log("WARN", f"[{sid}] verification adapter preflight failed: {type(exc).__name__}: {exc}")

    if not LOCAL_VERIFICATION_ENHANCED:
        return await _mint_v2_escalation_legacy(jar_id, settle_s)

    solver = get_solver() if "get_solver" in globals() else None
    has_onnx = bool(solver and solver.available())

    async with s._action_lock:
        try:
            try:
                await s.page.evaluate(RC_V2_CLEAR_JS)
            except Exception:
                pass

            mount = await s.page.evaluate(RC_V2_WIDGET_JS, ARENA_RECAPTCHA_V2_SITEKEY)
            if not (isinstance(mount, dict) and mount.get("ok")):
                err = mount.get("err") if isinstance(mount, dict) else mount
                log("WARN", f"[{sid}] local verification: V2 mount failed: {err}")
                return None

            clicked = False
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not clicked:
                for frame in s.page.frames:
                    try:
                        cb = frame.locator("#recaptcha-anchor, .recaptcha-checkbox-border").first
                        if await cb.count() and await cb.is_visible():
                            await cb.click(timeout=1500)
                            clicked = True
                            break
                    except Exception:
                        continue
                if not clicked:
                    await asyncio.sleep(LOCAL_VERIFICATION_POLL_MS / 1000.0)

            if not clicked:
                log("WARN", f"[{sid}] local verification: mounted widget but anchor never became clickable")
                return None

            await asyncio.sleep(LOCAL_VERIFICATION_POLL_MS / 1000.0)
            tok = await s.page.evaluate(RC_V2_READ_JS)
            if _verification_token_ok(tok) and not str(tok).startswith("__ERR__"):
                log("OK", f"[{sid}] local verification: V2 auto-pass token captured ({len(tok)} chars)")
                return tok
            if tok and not str(tok).startswith("__ERR__"):
                log("WARN", f"[{sid}] local verification: ignored invalid V2 token shape ({len(str(tok))} chars)")

            if not has_onnx:
                log("WARN", f"[{sid}] local verification: interactive challenge shown but ONNX solver unavailable")
                return None

            solved = await s.solve_recaptcha_image_challenge(
                max_rounds=LOCAL_VERIFICATION_MAX_ROUNDS
            )
            if not solved:
                log("WARN", f"[{sid}] local verification: image solver ended without verified state")
                return None

            verify_deadline = time.monotonic() + max(2.0, min(float(settle_s), 20.0))
            while time.monotonic() < verify_deadline:
                tok = await s.page.evaluate(RC_V2_READ_JS)
                if tok:
                    if str(tok).startswith("__ERR__"):
                        log("WARN", f"[{sid}] local verification widget error: {tok}")
                        return None
                    if _verification_token_ok(tok):
                        log("OK", f"[{sid}] local verification: V2 token verified ({len(tok)} chars)")
                        return tok
                    log("WARN", f"[{sid}] local verification: ignored invalid V2 token shape ({len(str(tok))} chars)")
                await asyncio.sleep(LOCAL_VERIFICATION_POLL_MS / 1000.0)

            log("WARN", f"[{sid}] local verification: solver completed but no token appeared")
            return None
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log("WARN", f"[{sid}] local verification escalation failed: {type(exc).__name__}: {exc}")
            return None


async def _mint_v2_escalation_legacy(jar_id=None, settle_s: float = 20.0):
    """Run legacy V2 escalation as one locked browser transaction."""
    sid, s = _find_session(jar_id)
    if not s:
        return None
    async with s._action_lock:
        return await _mint_v2_escalation_legacy_inner(jar_id, settle_s)


async def _mint_v2_escalation_legacy_inner(jar_id=None, settle_s: float = 20.0):
    """Baseline-compatible V2 escalation retained outside localhost."""
    sid, s = _find_session(jar_id)
    if not s:
        return None
    try:
        solver = get_solver() if "get_solver" in globals() else None
        has_onnx = bool(solver and solver.available())
        ext_path = os.environ.get("BRIDGENA_CAPTCHA_EXT", "")
        has_ext = bool(ext_path and os.path.exists(os.path.join(ext_path, "manifest.json")))

        await s.page.evaluate(RC_V2_CLEAR_JS)
        mount = await s.page.evaluate(RC_V2_WIDGET_JS, ARENA_RECAPTCHA_V2_SITEKEY)
        if not (isinstance(mount, dict) and mount.get("ok")):
            if ARENA_RECAPTCHA_SITEKEY != ARENA_RECAPTCHA_V2_SITEKEY:
                mount = await s.page.evaluate(RC_V2_WIDGET_JS, ARENA_RECAPTCHA_SITEKEY)
            if not (isinstance(mount, dict) and mount.get("ok")):
                return None

        clicked = False
        for _ in range(5):
            await asyncio.sleep(0.5)
            for frame in s.page.frames:
                try:
                    cb = frame.locator("#recaptcha-anchor, .recaptcha-checkbox-border").first
                    if await cb.count() and await cb.is_visible():
                        await cb.click(timeout=2000)
                        clicked = True
                        break
                except Exception:
                    continue
            if clicked:
                break
        if not clicked:
            return None

        await asyncio.sleep(1.2)
        tok = await s.page.evaluate(RC_V2_READ_JS)
        if _verification_token_ok(tok) and not str(tok).startswith("__ERR__"):
            return tok

        if has_onnx and hasattr(s, "solve_recaptcha_image_challenge"):
            await s.solve_recaptcha_image_challenge()
        elif not has_ext:
            return None

        deadline = time.time() + min(settle_s, 20.0 if has_onnx else 15.0)
        while time.time() < deadline:
            tok = await s.page.evaluate(RC_V2_READ_JS)
            if tok:
                if str(tok).startswith("__ERR__"):
                    return None
                if _verification_token_ok(tok):
                    return tok
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log("WARN", f"legacy V2 escalation error: {type(exc).__name__}: {exc}")
    return None


# ────────────────────────── module: arena.py ──────────────────────────────

# ============================================================
# v2 ARENA ENGINE — one request pipeline, a real verdict taxonomy, and the
# token protocol that the LIVE schema demands (recaptchaV3Token /
# recaptchaV2Token — 'recaptchaToken' is not a field this API reads).
#
# Failure classes are handled by WHOSE FAULT it is:
#   TUNNEL     exit connected but arena refused CONNECT   → flag exit, rotate, jar untouched
#   CHALLENGE  cloudflare interstitial                    → one keeper re-clear, then rotate exit
#   RECAPTCHA  validation failed                          → keep jar HEALTHY; escalate V2; stop clean
#   RATELIMIT  429                                        → same-jar backoff, soft, never hard-lock
#   UPSTREAM   5xx/52x                                    → backoff; origin's problem, nobody's fault
#   SESSION    401/403 auth-only                           → the ONE path allowed to expire a jar
# ============================================================
import asyncio, json, time
from typing import Optional

try:
    from curl_cffi.requests import AsyncSession
except Exception:
    AsyncSession = None

IMPERSONATE_BY_FAMILY = {"chrome": "chrome131", "safari": "safari17_0", "firefox": "firefox133"}
_impersonate_warned = set()


def impersonate_for(p) -> str:
    alias = IMPERSONATE_BY_FAMILY.get(p.family, "chrome131")
    return alias


def bind_persona(jar: dict) -> "Persona":
    """Deterministic per-jar device identity; also stamps user_agent so every
    legacy code path (headers, keeper, relogin) presents the SAME device."""
    p = persona_for(jar)
    jar["persona"] = p.key
    jar["user_agent"] = p.ua
    return p


def _cookie_header(jar: dict) -> str:
    return build_cookie_header(jar)


def _headers_for(jar: dict, p, json_body: bool) -> dict:
    h = {"User-Agent": p.ua, "Accept": "application/json, text/plain, */*" if json_body else p.accept,
         "Accept-Language": p.accept_lang, "Origin": ARENA_BASE,
         "Referer": f"{ARENA_BASE}/text/direct", "Content-Type": "application/json" if json_body else None,
         "Cookie": _cookie_header(jar)}
    if p.family == "chrome":
        h["sec-ch-ua"] = p.ch_ua
        h["sec-ch-ua-mobile"] = "?1" if p.mobile else "?0"
        h["sec-ch-ua-platform"] = f'"{p.platform}"'
    for k in [k for k, v in h.items() if v is None]:
        h.pop(k)
    return h


async def _live_cookies(jar: dict) -> dict:
    """Refresh cookies from this jar's live keeper when it has harvested newer ones."""
    try:
        s = keeper.sessions.get(jar.get("id"))
        if s and getattr(s, "running", False) and getattr(s, "context", None):
            live = await s.context.cookies()
            if live:
                jar = dict(jar)
                jar["cookies"] = [dict(c) for c in live]
    except Exception:
        pass
    return jar


def _classify(status: int, body: str) -> str:
    low = (body or "").lower()
    if status == 200:
        return "OK"
    if status in (401, 403):
        if "cloudflare" in low or "just a moment" in low or "cf-chl" in low:
            return "CHALLENGE"
        if "captcha" in low or "recaptcha" in low:
            return "RECAPTCHA"
        return "SESSION" if status == 401 or "auth" in low else "RECAPTCHA"  # conservative: unknown 403s never burn jars
    # Arena's live client uses a specific 429 {"error":"prompt failed"} as
    # the signal to mount the Enterprise checkbox and retry with recaptchaV2Token.
    # Other 429 responses remain ordinary throttling.
    if status == 429:
        if "prompt failed" in low:
            return "RECAPTCHA"
        return "RATELIMIT"
    if status >= 500 or 520 <= status <= 527:
        return "UPSTREAM"
    return "UNKNOWN"


def _attach_v3(base: dict, tok: str) -> None:
    base["recaptchaV3Token"] = tok
    base.pop("recaptchaV2Token", None)


def _attach_v2(base: dict, tok: str) -> None:
    base["recaptchaV2Token"] = tok
    base.pop("recaptchaV3Token", None)


def _events_from_stream_data(data) -> list:
    """Normalize common provider/SSE envelopes to Bridgena events."""
    out = []
    if isinstance(data, list):
        for item in data:
            out.extend(_events_from_stream_data(item))
        return out
    if not isinstance(data, dict):
        return out

    kind = str(data.get("type") or data.get("event") or "").lower().replace("_", "-")
    if kind in ("error", "error-message") or data.get("error"):
        err = data.get("error") or data.get("message") or "Provider stream error"
        if isinstance(err, dict):
            err = err.get("message") or err.get("detail") or json.dumps(err, ensure_ascii=False)
        return [("error", str(err))]

    # OpenAI-compatible chunks.
    choices = data.get("choices")
    if isinstance(choices, list):
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") or choice.get("message") or {}
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str) and content:
                    out.append(("content", content))
                reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                if isinstance(reasoning, str) and reasoning:
                    out.append(("reasoning", reasoning))
        return out

    # Gemini generateContent chunks.
    candidates = data.get("candidates")
    if isinstance(candidates, list):
        for candidate in candidates:
            content = candidate.get("content", {}) if isinstance(candidate, dict) else {}
            for part in content.get("parts", []) if isinstance(content, dict) else []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    out.append(("content", part["text"]))
        return out

    # Anthropic content_block_delta and AI SDK UI-message events.
    delta = data.get("delta")
    if isinstance(delta, dict):
        delta_kind = str(delta.get("type") or kind).lower().replace("_", "-")
        value = delta.get("text")
        if not isinstance(value, str):
            value = delta.get("content")
        if not isinstance(value, str):
            value = delta.get("value")
        if isinstance(value, str) and value:
            out.append(("reasoning" if "thinking" in delta_kind or "reasoning" in delta_kind else "content", value))
            # Do not return here: some providers place text + metadata/data in
            # the same envelope and both need to be inspected.

    # AI SDK UIMessageStream parts and provider wrappers.
    parts = data.get("parts")
    if isinstance(parts, list):
        for part in parts:
            if not isinstance(part, dict):
                continue
            pkind = str(part.get("type") or "").lower().replace("_", "-")
            ptext = part.get("text")
            if not isinstance(ptext, str):
                ptext = part.get("content")
            if isinstance(ptext, str) and ptext:
                out.append(("reasoning" if "reasoning" in pkind or "thinking" in pkind else "content", ptext))

    message = data.get("message")
    if isinstance(message, dict):
        mcontent = message.get("content")
        if isinstance(mcontent, str) and mcontent:
            out.append(("content", mcontent))
        elif isinstance(mcontent, list):
            for item in mcontent:
                if isinstance(item, dict):
                    itype = str(item.get("type") or "").lower()
                    itext = item.get("text")
                    if isinstance(itext, str) and itext:
                        out.append(("reasoning" if "thinking" in itype else "content", itext))

    value = delta if isinstance(delta, str) else data.get("text")
    if not isinstance(value, str):
        value = data.get("content")
    if kind in ("text-delta", "content-block-delta", "content", "token", "message") and isinstance(value, str):
        out.append(("content", value))
    elif kind in ("reasoning", "reasoning-delta", "thinking", "thinking-delta") and isinstance(value, str):
        out.append(("reasoning", value))
    elif kind in ("finish", "finish-step", "finish-message", "message-stop", "done"):
        out.append(("done", kind))
    elif isinstance(data.get("data"), (dict, list)):
        out.extend(_events_from_stream_data(data["data"]))
    return out


def _stream_scalar_text(value):
    """Extract text from common provider payload fragments without flattening metadata."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        chunks = []
        for item in value:
            if isinstance(item, str):
                chunks.append(item)
            elif isinstance(item, dict):
                t = item.get("text")
                if isinstance(t, str):
                    chunks.append(t)
        return "".join(chunks)
    if isinstance(value, dict):
        for key in ("text", "value", "content"):
            v = value.get(key)
            if isinstance(v, str):
                return v
    return ""


def _stream_events_from_prefixed(prefix: str, payload):
    """Decode Vercel AI SDK / Arena prefixed data-stream frames.

    Supports both the classic numeric protocol and Arena's `a*` variants.
    Unknown metadata/tool frames are deliberately ignored rather than treated
    as malformed text.
    """
    p = str(prefix or "").strip().lower()
    events = []

    # Arena/Vercel text and reasoning delta frames.
    if p in ("0", "a0"):
        if isinstance(payload, str):
            return [("content", payload)]
        return _events_from_stream_data(payload)

    if p in ("g", "ag"):
        if isinstance(payload, str):
            return [("reasoning", payload)]
        return _events_from_stream_data(payload)

    # Structured data frames can themselves contain provider-native deltas.
    if p in ("2", "a2"):
        return _events_from_stream_data(payload)

    # Classic data-stream error frame.
    if p in ("3", "error"):
        if isinstance(payload, dict):
            msg = payload.get("message") or payload.get("error") or payload.get("detail")
        else:
            msg = payload
        return [("error", str(msg or "Provider stream error"))]

    # Finish-message / finish-step variants. Some adapters attach final text.
    if p in ("b", "c", "d", "e", "ad"):
        nested = _events_from_stream_data(payload)
        contentish = [ev for ev in nested if ev[0] in ("content", "reasoning", "error")]
        if contentish:
            events.extend(contentish)
        if not any(ev[0] == "error" for ev in events):
            events.append(("done", p))
        return events

    # AI SDK metadata/tool frames: 8=data annotation, 9=tool call,
    # a=tool result. They are not assistant text and should not poison parsing.
    if p in ("8", "9", "a"):
        return _events_from_stream_data(payload)

    # A few provider adapters use named prefixes.
    if p in ("text", "text-delta", "content", "content-delta"):
        t = _stream_scalar_text(payload)
        return [("content", t)] if t else _events_from_stream_data(payload)

    if p in ("reasoning", "reasoning-delta", "thinking", "thinking-delta"):
        t = _stream_scalar_text(payload)
        return [("reasoning", t)] if t else _events_from_stream_data(payload)

    return _events_from_stream_data(payload)


def _parse_stream_events(line: str):
    """Return *all* semantic events encoded by one upstream line.

    The previous decoder collapsed each frame to a single event. Models that
    package reasoning + text, or several deltas in one JSON envelope, therefore
    lost content. This decoder preserves ordering and all deltas.
    """
    raw = str(line or "").strip()
    if not raw or raw.startswith(":"):
        return []

    # SSE event-name lines carry no payload themselves.
    if raw.startswith("event:"):
        return []

    if raw.startswith("data:"):
        raw = raw[5:].strip()

    if not raw:
        return []
    if raw == "[DONE]":
        return [("done", "stop")]

    # Normal JSON SSE used by OpenAI/Anthropic/Gemini/AI SDK UI streams.
    if raw[:1] in ("{", "["):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return _events_from_stream_data(parsed)

    colon = raw.find(":")
    if colon < 0:
        return []

    prefix, payload_raw = raw[:colon], raw[colon + 1:]
    try:
        payload = json.loads(payload_raw)
    except json.JSONDecodeError:
        payload = payload_raw

    return _stream_events_from_prefixed(prefix, payload)


class _StreamDeltaNormalizer:
    """Normalize delta-style and snapshot-style provider streams.

    Some models emit true deltas ("Hel" + "lo"), while others repeatedly emit
    the entire accumulated text ("Hel", "Hello", "Hello world"). This class
    converts both into monotonic deltas so OpenAI/Anthropic clients never see
    duplicated growing snapshots.
    """
    def __init__(self):
        self.content_seen = ""
        self.reasoning_seen = ""

    @staticmethod
    def _delta(previous: str, incoming: str):
        if not incoming:
            return ""
        if not previous:
            return incoming

        # Snapshot grows from the previous value.
        if incoming.startswith(previous):
            return incoming[len(previous):]

        # Exact replay/duplicate frame.
        if incoming == previous or previous.endswith(incoming):
            return ""

        # Find the largest suffix/prefix overlap to suppress retransmitted tails.
        max_overlap = min(len(previous), len(incoming), 4096)
        for n in range(max_overlap, 0, -1):
            if previous[-n:] == incoming[:n]:
                return incoming[n:]

        return incoming

    def normalize(self, kind: str, value):
        if kind not in ("content", "reasoning"):
            return kind, value
        incoming = str(value or "")
        if kind == "content":
            delta = self._delta(self.content_seen, incoming)
            if incoming.startswith(self.content_seen):
                self.content_seen = incoming
            else:
                self.content_seen += delta
            return kind, delta
        delta = self._delta(self.reasoning_seen, incoming)
        if incoming.startswith(self.reasoning_seen):
            self.reasoning_seen = incoming
        else:
            self.reasoning_seen += delta
        return kind, delta


def _collapse_stream_events(events: list):
    if not events:
        return None
    for kind, value in events:
        if kind == "error":
            return kind, value
    for target in ("content", "reasoning"):
        values = [str(value) for kind, value in events if kind == target and value is not None]
        if values:
            return target, "".join(values)
    return next(((kind, value) for kind, value in events if kind == "done"), None)


def _parse_stream_line(line: str):
    """Normalize Arena/Vercel, OpenAI, Anthropic and Gemini stream frames."""
    line = str(line or "").strip()
    if line.startswith("data:"):
        line = line[5:].strip()
    if not line or line.startswith("event:") or line.startswith(":"):
        return None
    if line == "[DONE]":
        return ("done", "stop")

    # Plain JSON SSE payloads used by OpenAI, Anthropic and Gemini adapters.
    if line[:1] in ("{", "["):
        try:
            return _collapse_stream_events(_events_from_stream_data(json.loads(line)))
        except json.JSONDecodeError:
            return None

    colon = line.find(":")
    if colon < 0:
        return None
    prefix, payload = line[:colon], line[colon + 1:]
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        parsed = payload

    if prefix in ("a0", "0"):
        if isinstance(parsed, str):
            return ("content", parsed)
        return _collapse_stream_events(_events_from_stream_data(parsed))
    if prefix in ("ag", "g"):
        if isinstance(parsed, str):
            return ("reasoning", parsed)
        return _collapse_stream_events(_events_from_stream_data(parsed))
    if prefix in ("a2", "2"):
        return _collapse_stream_events(_events_from_stream_data(parsed))
    if prefix in ("3", "error"):
        message = parsed.get("message") if isinstance(parsed, dict) else parsed
        return ("error", str(message or "Provider stream error"))
    if prefix in ("ad", "d", "e"):
        # Most finish frames contain metadata only, but some adapters attach a
        # final delta to the terminal envelope. Preserve that text; bridge_fetch
        # already owns transport termination and run_turn emits the final done.
        terminal_event = _collapse_stream_events(_events_from_stream_data(parsed))
        if terminal_event and terminal_event[0] in ("content", "reasoning", "error"):
            return terminal_event
        if isinstance(parsed, dict):
            for key in ("text", "content", "delta"):
                value = parsed.get(key)
                if isinstance(value, str) and value:
                    return ("content", value)
        return ("done", payload)
    return None


_browser_turn_gate = asyncio.Semaphore(API_TURN_CONCURRENCY)
_conversation_turn_locks: Dict[str, asyncio.Lock] = {}
_conversation_turn_locks_guard = threading.Lock()

_tenant_pace_locks: Dict[str, asyncio.Lock] = {}
_tenant_pace_next: Dict[str, float] = {}
_tenant_pace_guard = threading.Lock()
_conversation_next_start: Dict[str, float] = {}
_model_rate_limit_until: Dict[str, float] = {}
_model_rate_limit_state: Dict[str, dict] = {}
_model_rate_limit_guard = threading.Lock()

def _model_rate_limit_remaining(model_name: str) -> float:
    key = str(model_name or "auto").strip().lower()
    with _model_rate_limit_guard:
        until = _model_rate_limit_until.get(key, 0.0)
    return max(0.0, until - time.monotonic())

def _parse_retry_after_seconds(value: str) -> Optional[float]:
    value = str(value or "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except Exception:
        return None

def _mark_model_rate_limited(model_name: str, seconds: float = None) -> float:
    """Adaptive throttle lease.

    A single transient 429 gets a short pause. Repeated 429s back off
    exponentially up to the historical configured ceiling. If Arena supplies
    Retry-After, that value wins.
    """
    key = str(model_name or "auto").strip().lower()
    now = time.monotonic()
    with _model_rate_limit_guard:
        state = dict(_model_rate_limit_state.get(key) or {})
        last = float(state.get("last", 0.0) or 0.0)
        strikes = int(state.get("strikes", 0) or 0)
        if not last or now - last > UPSTREAM_429_STRIKE_RESET_SEC:
            strikes = 0
        strikes += 1
        if seconds is None:
            duration = min(
                UPSTREAM_429_COOLDOWN_SEC,
                UPSTREAM_429_FIRST_BACKOFF_SEC * (2 ** max(0, strikes - 1)),
            )
        else:
            duration = max(1.0, min(float(seconds), 300.0))
        until = now + max(1.0, duration)
        _model_rate_limit_state[key] = {"strikes": strikes, "last": now}
        _model_rate_limit_until[key] = max(_model_rate_limit_until.get(key, 0.0), until)
    return max(0.0, until - time.monotonic())

def _clear_model_rate_limit(model_name: str):
    key = str(model_name or "auto").strip().lower()
    with _model_rate_limit_guard:
        _model_rate_limit_until.pop(key, None)
        _model_rate_limit_state.pop(key, None)

async def _wait_if_model_rate_limited(model_name: str):
    """Absorb short upstream cooldowns inside the request instead of making the
    customer manually retry. Long cooldowns still return 429 promptly.
    """
    remaining = _model_rate_limit_remaining(model_name)
    if remaining <= 0:
        return
    if remaining <= UPSTREAM_429_INLINE_WAIT_MAX_SEC:
        log("INFO", f"Model throttle wait · {model_name} · sleeping {remaining:.1f}s before dispatch")
        await asyncio.sleep(remaining + 0.05)
        return
    retry_after = max(1, int(remaining + 0.999))
    raise HTTPException(
        status_code=429,
        detail=f"Model '{model_name}' is temporarily rate-limited upstream. Retry in about {retry_after}s.",
        headers={"Retry-After": str(retry_after)},
    )


def _tenant_pace_lock(tenant_id: str) -> asyncio.Lock:
    key = str(tenant_id or "anonymous")
    with _tenant_pace_guard:
        lock = _tenant_pace_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _tenant_pace_locks[key] = lock
        return lock

async def _pace_api_request(tenant_id: str) -> float:
    """Smooth bursty clients instead of letting them hammer the upstream.

    Returns seconds waited. Requests wait up to API_PACE_MAX_WAIT_SEC; only a
    truly excessive queue gets a local 429 with Retry-After.
    """
    if API_PACE_INTERVAL_SEC <= 0:
        return 0.0
    key = str(tenant_id or "anonymous")
    async with _tenant_pace_lock(key):
        now = time.monotonic()
        due = max(now, _tenant_pace_next.get(key, now))
        wait = max(0.0, due - now)
        if wait > API_PACE_MAX_WAIT_SEC:
            raise HTTPException(
                status_code=429,
                detail=f"Too many requests queued for this API key. Retry in {max(1, int(wait))}s.",
                headers={"Retry-After": str(max(1, int(wait)))},
            )
        if wait:
            log("INFO", f"API admission pacing · tenant {key[:10]}… · delaying {wait:.2f}s")
            await asyncio.sleep(wait)
        _tenant_pace_next[key] = time.monotonic() + API_PACE_INTERVAL_SEC
        return wait


def _conversation_gate(chat_id: str) -> asyncio.Lock:
    """Serialize only writes to one exact stateful Arena conversation."""
    key = str(chat_id or "anonymous")
    with _conversation_turn_locks_guard:
        lock = _conversation_turn_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _conversation_turn_locks[key] = lock
        return lock


async def run_turn(chat_id: str, prompt: str, model_name: str,
                   attachments: Optional[list] = None, jar_hint: Optional[str] = None,
                   system_prompt: str = "", tenant_id: str = "anonymous",
                   handoff_prompt: str = ""):
    """Coordinate one logical turn with bounded account failover.

    Account failover is deliberately conservative:
      * allowed before the model POST is sent;
      * allowed after an explicit LOGIN_GATE/401 that returned no stream frames;
      * never used for 429 throttling, reCAPTCHA/verification rejection,
        or after any model stream has started.

    Existing Arena conversations remain pinned during normal operation. If the
    bound account fails before generation, Bridgena may rebuild the thread on a
    different healthy configured account using the client-provided transcript.
    It never performs this handoff after partial model output has started.
    """
    # Keep a private continuity capsule up to date from the transcript the
    # client already supplied. This is more reliable than asking the model to
    # emit hidden context markers after every response.
    if handoff_prompt:
        save_context_capsule(chat_id, model_name, handoff_prompt, source="client-transcript")

    async with _conversation_gate(chat_id):
        if CONVERSATION_MIN_GAP_SEC > 0:
            now = time.monotonic()
            due = _conversation_next_start.get(str(chat_id), now)
            if due > now:
                wait = due - now
                log("INFO", f"conversation pacing · {str(chat_id)[:10]}… · delaying {wait:.2f}s")
                await asyncio.sleep(wait)
            _conversation_next_start[str(chat_id)] = time.monotonic() + CONVERSATION_MIN_GAP_SEC

        async with _browser_turn_gate:
            excluded = set()
            next_hint = jar_hint
            failovers = 0
            same_account_429_retries = 0
            undelivered_envelope_retries = 0
            retry_envelope_ids = None
            active_prompt = prompt
            active_system_prompt = system_prompt
            migrated_thread = False
            throttle_rehome_active = False
            continuity_context = handoff_prompt or load_context_capsule(chat_id, model_name)

            pending_rehome = get_throttle_thread_rehome(chat_id, model_name)
            if THROTTLE_THREAD_REHOME and pending_rehome:
                not_before = float(pending_rehome.get("not_before") or 0.0)
                if time.time() >= not_before:
                    continuity_context = handoff_prompt or load_context_capsule(chat_id, model_name)
                    if continuity_context:
                        clear_conversation_model(chat_id, model_name)
                        active_prompt = continuity_context
                        next_hint = str(pending_rehome.get("jar_id") or jar_hint or "") or None
                        migrated_thread = True
                        throttle_rehome_active = True
                        _bump_thread_rehome("activated")
                        log("WARN", f"Thread rehome activated · rebuilding {str(chat_id)[:10]}… "
                                    f"as a fresh Arena chat · same model {model_name} · same account")
                    else:
                        _bump_thread_rehome("missing_context")

            while True:
                turn = _run_turn_impl(
                    chat_id, active_prompt, model_name, attachments, next_hint,
                    system_prompt=active_system_prompt,
                    exclude_jars=excluded,
                    retry_envelope_ids=retry_envelope_ids,
                )
                retry_info = None
                emitted_user_output = False
                attempt_answer = ""
                saw_done = False
                try:
                    async for kind, payload in turn:
                        if kind in ("retry-account", "retry-same-account", "retry-undelivered"):
                            retry_info = payload if isinstance(payload, dict) else {"reason": str(payload)}
                            retry_info["_kind"] = kind
                            break
                        emitted_user_output = True
                        if kind == "content" and isinstance(payload, str):
                            attempt_answer += payload
                        elif kind == "done":
                            saw_done = True
                        yield kind, payload
                finally:
                    await turn.aclose()

                if not retry_info:
                    if saw_done and attempt_answer:
                        append_context_capsule_answer(
                            chat_id, model_name,
                            continuity_context or handoff_prompt,
                            attempt_answer,
                        )
                    if throttle_rehome_active and saw_done:
                        clear_throttle_thread_rehome(chat_id, model_name)
                        _bump_thread_rehome("completed")
                        log("OK", f"Thread rehome completed · {str(chat_id)[:10]}… · "
                                  f"same model {model_name}")
                    return

                if retry_info.get("_kind") == "retry-undelivered":
                    failed_id = str(retry_info.get("jar_id") or "")
                    failed_name = str(retry_info.get("jar_name") or failed_id or "unknown")
                    envelope = retry_info.get("envelope_ids") if isinstance(retry_info.get("envelope_ids"), dict) else None
                    reason = str(retry_info.get("reason") or "delivery could not be confirmed")

                    if undelivered_envelope_retries >= UNDELIVERED_ENVELOPE_RETRY_MAX or not envelope:
                        _bump_undelivered_retry("exhausted")
                        yield ("error", "502: The upstream delivery could not be confirmed after route recovery. "
                                        "Bridgena did not keep resending the same turn.")
                        return

                    undelivered_envelope_retries += 1
                    _bump_undelivered_retry("attempted")
                    retry_envelope_ids = dict(envelope)
                    next_hint = failed_id or next_hint

                    log("WARN", f"[{failed_name}] confirmed-absence retry "
                                f"{undelivered_envelope_retries}/{UNDELIVERED_ENVELOPE_RETRY_MAX} · "
                                f"reusing exact message IDs · {reason}")
                    # The same keeper may still be coming back from the HTTP-0
                    # repair that triggered this retry. Nudge the readiness loop;
                    # _run_turn_impl will wait for verification admission before
                    # it mints a token or replays these exact IDs.
                    _wake_verification_scheduler()
                    continue

                if retry_info.get("_kind") == "retry-same-account":
                    failed_id = str(retry_info.get("jar_id") or "")
                    failed_name = str(retry_info.get("jar_name") or failed_id or "unknown")
                    delay = max(0.0, float(retry_info.get("delay") or 0.0))
                    reason = str(retry_info.get("reason") or "upstream throttle")
                    if same_account_429_retries >= UPSTREAM_429_SAME_ACCOUNT_RETRIES:
                        retry_after = max(1, int(delay + 0.999))
                        yield ("error", f"429: Arena is still throttling model '{model_name}'. "
                                        f"Retry in about {retry_after}s.")
                        return
                    if delay > UPSTREAM_429_INLINE_WAIT_MAX_SEC:
                        retry_after = max(1, int(delay + 0.999))
                        if bool(retry_info.get("rehome_thread")) and THROTTLE_THREAD_REHOME:
                            continuity_context = handoff_prompt or load_context_capsule(chat_id, model_name)
                            arm_throttle_thread_rehome(
                                chat_id, model_name, failed_id, delay, continuity_context,
                            )
                            yield ("error", f"429: Arena is rate-limiting model '{model_name}'. "
                                            f"Retry in about {retry_after}s. A fresh same-model thread with preserved "
                                            "context is armed for the next eligible attempt.")
                        else:
                            yield ("error", f"429: Arena is rate-limiting model '{model_name}'. "
                                            f"Retry in about {retry_after}s.")
                        return
                    same_account_429_retries += 1
                    rehome_thread = bool(retry_info.get("rehome_thread"))
                    log("WARN", f"[{failed_name}] same-account throttle recovery "
                                f"{same_account_429_retries}/{UPSTREAM_429_SAME_ACCOUNT_RETRIES} · "
                                f"waiting {delay:.1f}s · {'new thread after cooldown · ' if rehome_thread else ''}{reason}")
                    if delay > 0:
                        await asyncio.sleep(delay + 0.05)

                    next_hint = failed_id or next_hint
                    if rehome_thread and THROTTLE_THREAD_REHOME:
                        continuity_context = handoff_prompt or load_context_capsule(chat_id, model_name)
                        if continuity_context:
                            clear_conversation_model(chat_id, model_name)
                            active_prompt = continuity_context
                            active_system_prompt = system_prompt
                            migrated_thread = True
                            throttle_rehome_active = True
                            clear_throttle_thread_rehome(chat_id, model_name)
                            _bump_thread_rehome("inline")
                            log("WARN", f"[{failed_name}] throttle cooldown elapsed · "
                                        f"starting fresh Arena chat with preserved context · same model {model_name}")
                        else:
                            _bump_thread_rehome("missing_context")
                    continue

                # A real account handoff must start with a fresh envelope.
                retry_envelope_ids = None
                failed_id = str(retry_info.get("jar_id") or "")
                failed_name = str(retry_info.get("jar_name") or failed_id or "unknown")
                reason = str(retry_info.get("reason") or "account unavailable")
                migrate_thread = bool(retry_info.get("migrate_thread"))
                if failed_id:
                    excluded.add(failed_id)

                if migrate_thread:
                    if not handoff_prompt:
                        log("WARN", f"Thread handoff unavailable · no client transcript · {failed_name}: {reason}")
                        yield ("error", "503: This Arena thread's account failed, and the client did not provide "
                                        "enough conversation history to rebuild it safely on another account.")
                        return
                    clear_conversation_model(chat_id, model_name)
                    active_prompt = handoff_prompt
                    active_system_prompt = system_prompt
                    migrated_thread = True
                    log("WARN", f"Thread handoff armed · rebuilding {str(chat_id)[:10]}… as a new Arena conversation "
                                f"on another healthy account · {reason}")

                # Internal failover events are only valid before user-visible
                # stream output. Be defensive if a future code path violates it.
                if emitted_user_output:
                    log("ERROR", f"Account failover suppressed after output began · {failed_name} · {reason}")
                    yield ("error", "502: Account failover was suppressed because the upstream response had already started.")
                    return

                if failovers >= ACCOUNT_FAILOVER_MAX:
                    _bump_account_failover("exhausted")
                    log("WARN", f"Account failover exhausted · tried {len(excluded)} account(s) · last {failed_name}: {reason}")
                    yield ("error", f"503: No healthy configured account was available after {len(excluded)} attempt(s). "
                                    "Failed keepers are being recovered in the background.")
                    return

                nxt = acquire_ready_jar(exclude=excluded)
                if not nxt:
                    _bump_account_failover("exhausted")
                    log("WARN", f"Account failover stopped · no alternate ready keeper · last {failed_name}: {reason}")
                    yield ("error", "503: The selected account failed and no other verified keeper is ready right now. "
                                    "Recovery is running in the background.")
                    return

                failovers += 1
                _bump_account_failover("attempted")
                _bump_account_failover("successful_handoff")
                next_hint = nxt.get("id")
                log("WARN", f"Account failover {failovers}/{ACCOUNT_FAILOVER_MAX} · "
                            f"{failed_name} → {nxt.get('name')} · "
                            f"{'thread handoff · ' if migrate_thread else ''}{reason}")




def _stream_recovery_suffix(partial: str, recovered: str) -> tuple:
    """Return (safe_suffix, confidence).

    Streaming clients cannot retract already-emitted text, so recovery only
    appends text when the Arena UI copy is demonstrably the same answer.
    """
    partial = str(partial or "")
    recovered = str(recovered or "")
    if not recovered:
        return "", 0.0
    if not partial:
        return recovered, 1.0
    if recovered.startswith(partial):
        return recovered[len(partial):], 1.0
    if partial == recovered:
        return "", 1.0

    # Find the longest suffix(partial) == prefix(recovered). This handles a
    # dropped/repeated transport frame near the break point.
    max_overlap = min(len(partial), len(recovered))
    for n in range(max_overlap, max(8, min(64, max_overlap // 4)) - 1, -1):
        if partial[-n:] == recovered[:n]:
            return recovered[n:], min(0.98, n / max(1, min(len(partial), 128)))

    # A full UI answer can occasionally wrap the partial answer with a tiny
    # prefix (e.g. a model label). Accept only a strong containment match.
    idx = recovered.find(partial)
    if 0 <= idx <= 80:
        return recovered[idx + len(partial):], 0.94

    return "", 0.0


async def _arena_history_probe(page, *, arena_id: str, model_message_id: str,
                               user_prompt: str, partial_text: str) -> dict:
    """Inspect Arena's authenticated unified history without resubmitting anything.

    The response shape has changed over time, so matching intentionally walks the
    JSON generically instead of hard-coding one schema. We score nested objects by:
      - exact evaluation/session id
      - exact model message id
      - the user's prompt
      - the already-streamed assistant prefix

    If the history payload contains assistant text directly, return it. Otherwise
    return the best chat URL/id so UI recovery can open the exact conversation.
    """
    try:
        return await page.evaluate(
            r"""async ([limit, arenaId, messageId, prompt, partial]) => {
              const norm = s => String(s ?? '').replace(/\s+/g, ' ').trim();
              const low = s => norm(s).toLowerCase();
              const promptN = norm(prompt).slice(0, 240);
              const partialN = norm(partial).slice(0, 240);
              const promptL = promptN.toLowerCase();
              const partialL = partialN.toLowerCase();
              const arenaL = String(arenaId || '').toLowerCase();
              const messageL = String(messageId || '').toLowerCase();

              let r;
              try {
                r = await fetch('/api/history/unified?limit=' + encodeURIComponent(limit), {
                  credentials: 'include',
                  cache: 'no-store',
                  headers: {'Accept': 'application/json'}
                });
              } catch (e) {
                return {ok:false,status:0,error:String(e && e.message || e)};
              }
              if (!r.ok) {
                return {ok:false,status:r.status,error:(await r.text()).slice(0,500)};
              }

              let data;
              try { data = await r.json(); }
              catch(e) { return {ok:false,status:r.status,error:'history JSON parse failed'}; }

              const roots = [];
              const seen = new WeakSet();

              function scalarText(v) {
                if (typeof v === 'string') return norm(v);
                if (Array.isArray(v)) {
                  return v.map(x => {
                    if (typeof x === 'string') return x;
                    if (x && typeof x === 'object') {
                      return x.text || x.content || x.value || '';
                    }
                    return '';
                  }).filter(Boolean).join('');
                }
                if (v && typeof v === 'object') {
                  return norm(v.text || v.content || v.value || '');
                }
                return '';
              }

              function roleOf(o) {
                if (!o || typeof o !== 'object') return '';
                return low(
                  o.role || o.author || o.sender || o.type || o.message_type ||
                  o.messageType || o.source || o.owner || ''
                );
              }

              function collectAssistant(o, depth=0, out=[]) {
                if (!o || depth > 9) return out;
                if (Array.isArray(o)) {
                  for (const x of o) collectAssistant(x, depth+1, out);
                  return out;
                }
                if (typeof o !== 'object') return out;

                const role = roleOf(o);
                if (/(assistant|model|bot)/.test(role) && !/(user|human)/.test(role)) {
                  for (const k of ['content','text','response','answer','output','markdown','message']) {
                    const t = scalarText(o[k]);
                    if (t && t.length >= 2) out.push(t);
                  }
                }

                for (const [k,v] of Object.entries(o)) {
                  if (['cookies','token','password','authorization'].includes(String(k).toLowerCase())) continue;
                  if (v && typeof v === 'object') collectAssistant(v, depth+1, out);
                }
                return out;
              }

              // Provider-specific history payloads do not always annotate model
              // output with role=assistant. Once an object is proven to belong to
              // this exact evaluation/message ID, inspect response-shaped fields
              // directly. User/input/prompt fields are deliberately excluded so a
              // duplicate ACK cannot be "recovered" as the user's own message.
              function collectExactIdResponseText(o, depth=0, out=[]) {
                if (!o || depth > 10) return out;
                if (Array.isArray(o)) {
                  for (const x of o) collectExactIdResponseText(x, depth+1, out);
                  return out;
                }
                if (typeof o !== 'object') return out;

                for (const [k,v] of Object.entries(o)) {
                  const kl = String(k).toLowerCase();
                  if (/(cookie|token|password|authorization|prompt|input|user|human|request)/.test(kl)) continue;

                  const responseLike = /(^|_)(response|answer|output|completion|assistant|model)(_|$)/.test(kl)
                    || /^(text|content|markdown)$/.test(kl)
                    || /(modela|modelb).*(response|output|answer|text|content)/.test(kl);
                  if (responseLike) {
                    const t = scalarText(v);
                    if (t && t.length >= 2 && (!promptL || !t.toLowerCase().startsWith(promptL))) out.push(t);
                  }
                  if (v && typeof v === 'object') collectExactIdResponseText(v, depth+1, out);
                }
                return out;
              }

              function findRoute(o, depth=0) {
                if (!o || depth > 6) return '';
                if (Array.isArray(o)) {
                  for (const x of o) {
                    const q = findRoute(x, depth+1);
                    if (q) return q;
                  }
                  return '';
                }
                if (typeof o !== 'object') return '';

                const directKeys = [
                  'url','href','path','chat_url','chatUrl','conversation_url',
                  'conversationUrl','route','pathname'
                ];
                for (const k of directKeys) {
                  const v = o[k];
                  if (typeof v === 'string' && v.trim()) {
                    const s = v.trim();
                    if (s.startsWith('/') || /^https?:\/\//i.test(s)) return s;
                  }
                }
                for (const v of Object.values(o)) {
                  if (v && typeof v === 'object') {
                    const q = findRoute(v, depth+1);
                    if (q) return q;
                  }
                }
                return '';
              }

              function explicitComplete(o) {
                let complete = null;
                function walk(v, depth=0) {
                  if (!v || depth > 6 || complete !== null) return;
                  if (Array.isArray(v)) {
                    for (const x of v) walk(x, depth+1);
                    return;
                  }
                  if (typeof v !== 'object') return;
                  for (const [k,val] of Object.entries(v)) {
                    const kl = String(k).toLowerCase();
                    if (['isgenerating','generating','streaming','is_streaming','inprogress','in_progress'].includes(kl)) {
                      if (val === false || val === 0) complete = true;
                      if (val === true || val === 1) complete = false;
                    }
                    if (['complete','completed','finished','done','iscomplete','is_complete'].includes(kl)) {
                      if (val === true || val === 1) complete = true;
                    }
                    if (['status','state'].includes(kl) && typeof val === 'string') {
                      const s = val.toLowerCase();
                      if (/(complete|completed|finished|done|success|succeeded)/.test(s)) complete = true;
                      if (/(generating|streaming|pending|running|in.progress)/.test(s)) complete = false;
                    }
                    if (val && typeof val === 'object') walk(val, depth+1);
                  }
                }
                walk(o);
                return complete;
              }

              function scoreObject(o) {
                let blob = '';
                try { blob = JSON.stringify(o).slice(0, 180000).toLowerCase(); }
                catch(e) { return 0; }

                let score = 0;
                if (arenaL && blob.includes(arenaL)) score += 12000;
                if (messageL && blob.includes(messageL)) score += 15000;
                if (promptL && blob.includes(promptL)) score += 6500;
                if (partialL && blob.includes(partialL)) score += 9000;

                if (promptL) {
                  const words = promptL.split(/\s+/).filter(x => x.length >= 4).slice(0,16);
                  for (const w of words) if (blob.includes(w)) score += 90;
                }
                return score;
              }

              function walk(v, path=[], depth=0) {
                if (!v || depth > 10) return;
                if (Array.isArray(v)) {
                  for (let i=0;i<v.length;i++) walk(v[i], path.concat(i), depth+1);
                  return;
                }
                if (typeof v !== 'object') return;
                if (seen.has(v)) return;
                seen.add(v);

                const score = scoreObject(v);
                if (score > 0) {
                  let assistants = collectAssistant(v);
                  let exactBlob = '';
                  try { exactBlob = JSON.stringify(v).toLowerCase(); } catch(e) {}
                  const exactIdMatch = !!(
                    (arenaL && exactBlob.includes(arenaL)) ||
                    (messageL && exactBlob.includes(messageL))
                  );
                  if (exactIdMatch) {
                    assistants = assistants.concat(collectExactIdResponseText(v));
                  }
                  let bestText = '';
                  for (const t of assistants) {
                    const tn = norm(t);
                    let local = 0;
                    if (partialL && tn.toLowerCase().includes(partialL)) local += 10000;
                    if (tn.length > bestText.length) local += Math.min(4000, tn.length);
                    const oldLocal = bestText ? Math.min(4000, bestText.length) : 0;
                    if (!bestText || local > oldLocal) bestText = tn;
                  }
                  roots.push({
                    score,
                    path: path.join('.'),
                    text: bestText,
                    route: findRoute(v),
                    complete: explicitComplete(v)
                  });
                }

                for (const [k,val] of Object.entries(v)) {
                  if (val && typeof val === 'object') walk(val, path.concat(k), depth+1);
                }
              }

              walk(data);
              roots.sort((a,b) => {
                const ax = a.score + (a.text ? Math.min(6000,a.text.length) : 0) + (a.route ? 500 : 0);
                const bx = b.score + (b.text ? Math.min(6000,b.text.length) : 0) + (b.route ? 500 : 0);
                return bx - ax;
              });

              const best = roots[0] || null;
              return {
                ok:true,
                status:r.status,
                matched:!!best,
                score:best ? best.score : 0,
                text:best ? best.text : '',
                route:best ? best.route : '',
                complete:best ? best.complete : null,
                path:best ? best.path : '',
                candidateCount:roots.length,
                exactIdMatched:!!(best && ((arenaL && best.score >= 12000) || (messageL && best.score >= 15000)))
              };
            }""",
            [
                ARENA_HISTORY_RECOVERY_LIMIT,
                str(arena_id or ""),
                str(model_message_id or ""),
                str(user_prompt or ""),
                str(partial_text or ""),
            ],
        )
    except Exception as exc:
        return {"ok": False, "status": 0,
                "error": f"{type(exc).__name__}: {redact(str(exc))[:200]}"}


async def _arena_ui_stream_recover(session, *, arena_id: str, model_message_id: str,
                                   user_prompt: str, partial_text: str = "",
                                   cached_url: str = "",
                                   timeout_sec: Optional[float] = None) -> dict:
    """Recover a broken stream from Arena history/UI without replaying the prompt.

    Recovery is intentionally patient. Arena can persist/index a just-created
    conversation a few seconds after the streaming fetch breaks. Previous builds
    checked history once and immediately failed if the row was not visible yet.

    Stage 1:
      Poll authenticated /api/history/unified for the exact evaluation/message/
      prompt. If history already contains the final assistant text, return it.

    Stage 2:
      Open the best matching chat route (or Search Chats), wait for the matching
      assistant bubble to stop changing, then return only once the text is stable.
    """
    if not ARENA_UI_STREAM_RECOVERY:
        return {"ok": False, "reason": "disabled", "trace_found": None}
    if not session or not getattr(session, "context", None):
        return {"ok": False, "reason": "no keeper context", "trace_found": None}

    _bump_arena_ui_recovery("attempted")
    name = getattr(session, "name", "keeper")
    page = None
    search_term = " ".join(str(user_prompt or "").split())[:240]
    prompt_probe = search_term[:96]
    partial_probe = str(partial_text or "")[:180]
    effective_timeout = max(
        1.0,
        min(60.0, float(timeout_sec if timeout_sec is not None else ARENA_UI_RECOVERY_TIMEOUT_SEC))
    )
    deadline = time.monotonic() + effective_timeout

    extract_js = r"""([messageId, promptProbe, partialProbe]) => {
      const visible = el => {
        if (!el || !(el instanceof Element)) return false;
        const r = el.getBoundingClientRect();
        const s = getComputedStyle(el);
        return r.width > 2 && r.height > 2 && s.display !== 'none' && s.visibility !== 'hidden';
      };
      const txt = el => (el && (el.innerText || el.textContent) || '').trim();
      const clean = s => String(s || '').replace(/\s+/g, ' ').trim();
      const all = [...document.querySelectorAll('body *')].filter(visible);
      const candidates = [];

      const push = (el, score) => {
        const t = txt(el);
        if (!t || t.length > 120000) return;
        if (promptProbe && clean(t).includes(clean(promptProbe)) &&
            t.length < Math.max(320, promptProbe.length * 3)) return;
        candidates.push({el,t,score});
      };

      if (messageId) {
        const safe = CSS.escape(messageId);
        for (const el of document.querySelectorAll(
          `[data-message-id*="${safe}"],[id*="${safe}"],[data-id*="${safe}"]`
        )) push(el, 15000 - txt(el).length / 1000);
      }

      if (partialProbe) {
        const needle = clean(partialProbe.slice(0, 120));
        for (const el of all) {
          const t = clean(txt(el));
          if (needle && t.includes(needle) && t.length >= needle.length)
            push(el, 12000 - Math.min(9000, t.length));
        }
      }

      for (const el of all) {
        const sig = clean([
          el.getAttribute('data-message-author-role'),
          el.getAttribute('data-role'),
          el.getAttribute('data-testid'),
          el.getAttribute('aria-label'),
          el.className
        ].join(' ')).toLowerCase();
        if (/(assistant|model-message|modelresponse|model-response|response-message|chat-message-assistant)/.test(sig))
          push(el, 7000 + Math.min(2500, txt(el).length / 10));
      }

      if (promptProbe) {
        const needle = clean(promptProbe);
        let userIndex = -1;
        for (let i=0;i<all.length;i++) {
          const t = clean(txt(all[i]));
          if (t === needle || (t.includes(needle) && t.length <= needle.length + 220))
            userIndex = i;
        }
        if (userIndex >= 0) {
          for (let i=userIndex+1;i<all.length;i++) {
            const el=all[i], t=txt(el);
            if (!t || t.length < 2 || t.length > 60000) continue;
            const sig=clean([el.tagName,el.getAttribute('role'),el.getAttribute('data-testid'),el.className].join(' ')).toLowerCase();
            if (/(article|message|assistant|markdown|prose)/.test(sig))
              push(el, 3500 + Math.min(1400,t.length/20));
          }
        }
      }

      candidates.sort((a,b)=>b.score-a.score || a.t.length-b.t.length);
      const chosen=candidates[0]||null;

      const generating=[...document.querySelectorAll('button,[role=button],[aria-label],[data-state]')]
        .filter(visible).some(el=>{
          const s=clean([txt(el),el.getAttribute('aria-label'),el.getAttribute('data-state')].join(' ')).toLowerCase();
          return /(stop generating|stop response|cancel generation|generating|streaming)/.test(s);
        });

      return {
        text:chosen?chosen.t:'',
        generating,
        url:location.href,
        title:document.title,
        candidateCount:candidates.length
      };
    }"""

    async with session._action_lock:
        try:
            page = await session.context.new_page()

            # Establish authenticated Arena origin before calling relative APIs.
            initial = cached_url or f"{PUBLIC_AUTH_BASE.rstrip('/')}/"
            try:
                await session._navigate_resilient(page, initial, timeout=12000)
            except Exception:
                try:
                    await page.goto(initial, wait_until="commit", timeout=12000)
                except Exception:
                    pass

            # ---------- Stage 1: authenticated history API ----------
            hist_last_text = ""
            hist_stable_polls = 0
            best_route = cached_url or ""
            history_match_logged = False
            history_phase_deadline = min(
                deadline,
                time.monotonic() + max(1.0, effective_timeout * 0.62)
            )

            while time.monotonic() < history_phase_deadline:
                probe = await _arena_history_probe(
                    page,
                    arena_id=arena_id,
                    model_message_id=model_message_id,
                    user_prompt=user_prompt,
                    partial_text=partial_text,
                )

                if probe.get("matched"):
                    if not history_match_logged:
                        history_match_logged = True
                        _bump_arena_ui_recovery("history_api_match")
                        log("INFO", f"[{name}] Arena history recovery · matching chat appeared · "
                                    f"score {probe.get('score')} · candidates {probe.get('candidateCount')}")
                    route = str(probe.get("route") or "")
                    if route:
                        best_route = route

                    current = str(probe.get("text") or "").strip()
                    suffix, confidence = _stream_recovery_suffix(partial_text, current)

                    if current:
                        if current == hist_last_text:
                            hist_stable_polls += 1
                        else:
                            hist_last_text = current
                            hist_stable_polls = 1

                        explicit_complete = probe.get("complete") is True
                        stable_complete = hist_stable_polls >= ARENA_HISTORY_STABLE_POLLS

                        if (not partial_text or confidence >= 0.90) and (explicit_complete or stable_complete):
                            _bump_arena_ui_recovery("recovered")
                            _bump_arena_ui_recovery("history_api_recovered")
                            log("OK", f"[{name}] Arena history API recovery · recovered {len(current)} chars · "
                                      f"stable polls {hist_stable_polls} · explicit complete {explicit_complete}")
                            return {
                                "ok": True,
                                "text": current,
                                "suffix": suffix,
                                "confidence": confidence,
                                "url": best_route or page.url,
                                "complete": True,
                                "source": "history-api",
                                "trace_found": True,
                            }
                else:
                    _bump_arena_ui_recovery("history_index_waits")

                await asyncio.sleep(ARENA_HISTORY_POLL_SEC)

            # ---------- Stage 2: exact route or Search Chats UI ----------
            def absolute_route(route: str) -> str:
                route = str(route or "").strip()
                if not route:
                    return ""
                if route.startswith("http://") or route.startswith("https://"):
                    return route
                if route.startswith("/"):
                    return PUBLIC_AUTH_BASE.rstrip("/") + route
                return ""

            direct_url = absolute_route(best_route)
            if direct_url:
                try:
                    await session._navigate_resilient(page, direct_url, timeout=12000)
                    await asyncio.sleep(0.8)
                except Exception:
                    pass

            # If the direct route did not expose our prompt/partial, use Arena's
            # Search Chats page. Crucially, do NOT fail on the first empty result:
            # keep polling because fresh conversations can appear after indexing.
            body_text = ""
            try:
                body_text = await page.locator("body").inner_text(timeout=1200)
            except Exception:
                pass

            if not body_text or (
                prompt_probe and prompt_probe not in body_text and
                partial_probe and partial_probe not in body_text
            ):
                history_url = f"{PUBLIC_AUTH_BASE.rstrip('/')}/history/search"
                try:
                    ok = await session._navigate_resilient(page, history_url, timeout=12000)
                    if not ok:
                        _bump_arena_ui_recovery("navigation_failed")
                except Exception:
                    _bump_arena_ui_recovery("navigation_failed")

                try:
                    await session._dismiss_promos(page)
                except Exception:
                    pass

                clicked = False
                search_attempt = 0

                while time.monotonic() < deadline and not clicked:
                    search_attempt += 1

                    # Direct evaluation/session id link if rendered.
                    if arena_id:
                        try:
                            by_id = page.locator(
                                f'a[href*="{arena_id}"],button[data-href*="{arena_id}"],'
                                f'[data-id*="{arena_id}"]'
                            ).first
                            if await by_id.count() > 0 and await by_id.is_visible():
                                await by_id.click(timeout=2500)
                                clicked = True
                                break
                        except Exception:
                            pass

                    if search_term:
                        try:
                            search = page.locator(
                                "input[placeholder*='Search your chats' i],"
                                "input[placeholder*='Search' i],"
                                "input[type='search']"
                            ).first
                            if await search.count() > 0:
                                # Re-fill periodically because the app can replace
                                # the search input during hydration.
                                await search.fill(search_term)
                                try:
                                    await search.press("Enter")
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    await asyncio.sleep(min(0.9, ARENA_HISTORY_POLL_SEC + 0.2))

                    try:
                        result = await page.evaluate(r"""([arenaId,prompt,partial])=>{
                          const norm=s=>String(s||'').toLowerCase().replace(/\s+/g,' ').trim();
                          const p=norm(prompt), q=norm(partial);
                          const words=p.split(' ').filter(w=>w.length>2).slice(0,16);
                          let best=null;
                          for(const el of document.querySelectorAll('a[href],button,[role=button],[data-id]')){
                            const r=el.getBoundingClientRect(),cs=getComputedStyle(el);
                            if(r.width<2||r.height<2||cs.display==='none'||cs.visibility==='hidden')continue;
                            const href=String(el.getAttribute('href')||el.getAttribute('data-href')||'');
                            const id=String(el.getAttribute('data-id')||'');
                            const t=norm(el.innerText||el.textContent||'');
                            let score=0;
                            if(arenaId&&(href.includes(arenaId)||id.includes(arenaId)))score+=20000;
                            if(p&&t.includes(p))score+=7000;
                            if(q&&t.includes(q))score+=8000;
                            for(const w of words)if(t.includes(w))score+=130;
                            if(/history|chat|conversation|evaluation/.test(href))score+=100;
                            if(!best||score>best.score)best={el,score,href,text:t};
                          }
                          if(best&&best.score>=260){
                            best.el.click();
                            return {clicked:true,score:best.score,href:best.href,text:best.text};
                          }
                          return {clicked:false,score:best?best.score:0};
                        }""", [arena_id, search_term, partial_probe])
                        clicked = bool(result and result.get("clicked"))
                    except Exception:
                        clicked = False

                    if not clicked and search_attempt % 4 == 0:
                        # Give the Search page a chance to refresh its indexed
                        # results without losing the authenticated context.
                        try:
                            await page.reload(wait_until="commit", timeout=7000)
                            await asyncio.sleep(0.45)
                        except Exception:
                            pass

                if not clicked:
                    _bump_arena_ui_recovery("not_found")
                    return {
                        "ok": False,
                        "reason": "matching Arena chat did not become visible before recovery deadline",
                        "trace_found": bool(history_match_logged),
                    }

                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=5000)
                except Exception:
                    pass
                await asyncio.sleep(0.55)

            # ---------- Stage 3: wait for the assistant bubble to stabilize ----------
            best_text = hist_last_text or ""
            stable_since = 0.0
            last_text = None
            best_url = page.url

            while time.monotonic() < deadline:
                try:
                    snap = await page.evaluate(
                        extract_js,
                        [str(model_message_id or ""), prompt_probe, partial_probe],
                    )
                except Exception as exc:
                    return {
                        "ok": False,
                        "reason": f"UI extraction failed: {type(exc).__name__}",
                        "text": best_text,
                        "url": best_url,
                        "trace_found": bool(history_match_logged or best_text),
                    }

                current = str((snap or {}).get("text") or "").strip()
                generating = bool((snap or {}).get("generating"))
                best_url = str((snap or {}).get("url") or page.url or best_url)

                if current and len(current) >= len(best_text):
                    best_text = current

                if current and current == last_text:
                    if not stable_since:
                        stable_since = time.monotonic()
                else:
                    stable_since = time.monotonic()
                    last_text = current

                stable_for = time.monotonic() - stable_since if current else 0.0
                suffix, confidence = _stream_recovery_suffix(partial_text, current)

                ui_complete = current and (not generating) and stable_for >= ARENA_UI_RECOVERY_STABLE_SEC
                stale_generating_complete = (
                    current and generating and
                    stable_for >= ARENA_UI_STALE_GENERATING_ACCEPT_SEC and
                    len(current) >= max(24, len(str(partial_text or "")))
                )
                if ui_complete or stale_generating_complete:
                    if not partial_text or confidence >= 0.90:
                        _bump_arena_ui_recovery("recovered")
                        _bump_arena_ui_recovery("ui_recovered")
                        source = "ui-stable-stale-generating" if stale_generating_complete else "ui"
                        if stale_generating_complete:
                            log("WARN", f"[{name}] Arena UI generating marker remained set, but exact assistant text "
                                        f"was unchanged for {stable_for:.1f}s; accepting stabilized recovery")
                        log("OK", f"[{name}] Arena UI stream recovery · recovered {len(current)} chars · "
                                  f"stable {stable_for:.1f}s · {best_url}")
                        return {
                            "ok": True,
                            "text": current,
                            "suffix": suffix,
                            "confidence": confidence,
                            "url": best_url,
                            "complete": True,
                            "source": source,
                            "trace_found": True,
                        }

                await asyncio.sleep(0.4)

            if best_text:
                _bump_arena_ui_recovery("incomplete")
                return {
                    "ok": False,
                    "reason": "Arena response was found but did not reach a confirmed stable completed state",
                    "text": best_text,
                    "url": best_url,
                    "trace_found": True,
                }

            _bump_arena_ui_recovery("not_found")
            return {"ok": False, "reason": "assistant response not visible in Arena history/UI", "trace_found": bool(history_match_logged)}

        finally:
            if page is not None:
                try:
                    await page.close()
                except Exception:
                    pass


async def _attempt_ui_stream_salvage(*, session, chat_id: str, model_name: str,
                                     arena_id: str, model_message_id: str,
                                     user_prompt: str, partial_text: str,
                                     jar: dict, proxy: Optional[str],
                                     cached_url: str = "",
                                     timeout_sec: Optional[float] = None,
                                     stage: str = "initial") -> dict:
    """Wrapper that persists recovered bindings/URLs but never replays a prompt."""
    if not ARENA_UI_STREAM_RECOVERY:
        return {"ok": False, "reason": "disabled"}

    log("WARN", f"[{jar.get('name')}] stream salvage · stage {stage} · "
                f"history/UI timeout {float(timeout_sec if timeout_sec is not None else ARENA_UI_RECOVERY_TIMEOUT_SEC):.1f}s")
    result = await _arena_ui_stream_recover(
        session,
        arena_id=arena_id,
        model_message_id=model_message_id,
        user_prompt=user_prompt,
        partial_text=partial_text,
        cached_url=cached_url,
        timeout_sec=timeout_sec,
    )

    if result.get("ok") or result.get("trace_found"):
        # Once authenticated history/UI proves this evaluation exists, persist
        # the binding even if the model is still generating. Completion and
        # delivery are separate facts: keeping the binding lets later recovery
        # resume the exact turn instead of rediscovering it from scratch.
        conv_now = get_conversation(chat_id) or {}
        conv_now["model"] = model_name
        conv_now["arena"] = dict(conv_now.get("arena") or {})
        conv_now["arena"][model_name] = {
            "arena_id": arena_id,
            "mode": "direct",
            "jar_id": jar.get("id"),
            "proxy": proxy,
            "ui_url": result.get("url") or cached_url or "",
        }
        save_conversation(chat_id, conv_now)
        if result.get("url"):
            save_conversation_ui_url(chat_id, model_name, result["url"])
        if result.get("trace_found") and not result.get("ok"):
            log("INFO", f"[{jar.get('name')}] Arena delivery confirmed; persisted in-progress evaluation binding {str(arena_id)[:12]}…")
    if not result.get("ok"):
        log("WARN", f"[{jar.get('name')}] Arena stream salvage failed · "
                    f"{result.get('reason') or 'unknown'} · "
                    f"best chars {len(str(result.get('text') or ''))} · "
                    f"url {str(result.get('url') or '')[:180]}")

    return result


async def _recover_keeper_before_salvage(sid: str, *, reason: str,
                                         timeout_sec: float = None) -> bool:
    """Repair a dead keeper route before trying Arena history again.

    The prior implementation spent the entire history-recovery window using the
    browser context whose route had just failed, then restarted it only after
    salvage gave up. That made HTTP-0 recovery structurally unlikely to work.

    This helper reuses the existing same-account/same-route recovery worker,
    waits for the replacement browser to become verified and route-healthy,
    then returns so salvage can run in that NEW authenticated context.
    """
    sid = str(sid or "")
    if not sid:
        return False

    wait_for = max(
        3.0,
        min(45.0, float(timeout_sec if timeout_sec is not None else ARENA_SALVAGE_RECOVERY_WAIT_SEC))
    )
    _schedule_transport_recovery(sid, reason)

    task = _transport_recovery_tasks.get(sid)
    if task:
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=wait_for)
        except asyncio.TimeoutError:
            _bump_arena_ui_recovery("recovery_wait_timeout")
            log("WARN", f"[{sid}] salvage recovery wait timed out after {wait_for:.1f}s")
        except Exception as exc:
            log("WARN", f"[{sid}] salvage recovery task failed · "
                        f"{type(exc).__name__}: {redact(str(exc))[:180]}")

    session = keeper.sessions.get(sid)
    if not keeper_session_ready(session):
        return False

    # The recovery worker normally verifies this already. Probe once more here
    # because this request is about to depend on the recovered browser.
    try:
        route_ok, route_status, route_detail = await session.probe_transport(force=True)
    except Exception as exc:
        log("WARN", f"[{getattr(session, 'name', sid)}] post-restart salvage probe failed · "
                    f"{type(exc).__name__}: {redact(str(exc))[:160]}")
        return False

    if not route_ok:
        log("WARN", f"[{getattr(session, 'name', sid)}] post-restart salvage route still unhealthy · "
                    f"{redact(route_detail)[:160]}")
        return False

    log("OK", f"[{getattr(session, 'name', sid)}] salvage browser recovered · route HTTP {route_status}")
    return True


async def _ensure_predispatch_transport(jar: dict, *, wait_for_recovery: bool = True) -> bool:
    """Do not submit a model POST through a keeper whose browser route is dead.

    On a failed harmless probe we recover the same keeper, wait for readmission,
    then probe once more. This prevents a large class of avoidable HTTP-0
    failures without replaying a user prompt.
    """
    sid = str(jar.get("id") or "")
    session = keeper.sessions.get(sid)
    if not sid or not keeper_session_ready(session):
        return False

    ok, status_code, detail = await session.probe_transport(force=TRANSPORT_PROBE_EVERY_REQUEST)
    if ok:
        _bump_transport_guard("probe_ok")
        return True

    _bump_transport_guard("probe_fail")
    log("WARN", f"[{jar.get('name')}] pre-dispatch transport probe failed · "
                f"status {status_code or 0} · {redact(detail)[:160]} · recovering before POST")
    _quarantine_api_keeper(sid, "pre-dispatch route probe failed", TRANSPORT_FAILURE_QUARANTINE_SEC)
    _schedule_transport_recovery(sid, "pre-dispatch route probe failed")

    if not wait_for_recovery:
        return False

    deadline = time.monotonic() + PREDISPATCH_RECOVERY_WAIT_SEC
    while time.monotonic() < deadline:
        task = _transport_recovery_tasks.get(sid)
        if task and task.done():
            await asyncio.gather(task, return_exceptions=True)
        session = keeper.sessions.get(sid)
        if (_api_keeper_verified(sid) and keeper_session_ready(session)):
            ok2, status2, detail2 = await session.probe_transport(force=True)
            if ok2:
                _bump_transport_guard("recovered_before_post")
                log("OK", f"[{jar.get('name')}] pre-dispatch transport recovered · "
                          f"HTTP {status2} route probe · continuing original request")
                return True
            detail = detail2
        await asyncio.sleep(0.5)

    _bump_transport_guard("recovery_timeout")
    log("WARN", f"[{jar.get('name')}] pre-dispatch transport recovery timed out · "
                f"request was never sent upstream")
    return False


async def _run_turn_impl(chat_id: str, prompt: str, model_name: str,
                   attachments: Optional[list] = None, jar_hint: Optional[str] = None,
                   system_prompt: str = "", exclude_jars: Optional[set] = None,
                   retry_envelope_ids: Optional[dict] = None):
    """Async generator yielding ('content'|'reasoning'|'error'|'done', text).
    One bounded attempt budget over the PROVEN exit pool; jars survive every
    failure class except true session death."""
    if AsyncSession is None:
        yield ("error", "500: curl_cffi missing in this environment — pip install curl_cffi")
        return
    conv = get_conversation(chat_id) or {}
    mc = conv.get("arena", {}).get(model_name) if conv.get("model") == model_name else None
    max_attempts = REQUEST_MAX_ATTEMPTS
    route_fails: list = []
    cf_clear_attempts = 0
    same_jar_429 = 0
    rc_attempts: Dict[str, int] = {}
    excluded = set(exclude_jars or ())
    tried = set(excluded)
    bound_jar_id = (mc or {}).get("jar_id")
    wanted_jar_id = jar_hint or bound_jar_id
    jar = (next((j for j in load_jars()
                 if j.get("id") == wanted_jar_id
                 and j.get("id") not in excluded
                 and j.get("enabled", True)), None)
           if wanted_jar_id else acquire_jar(prefer_live=True, exclude=excluded))
    if bound_jar_id and not jar:
        yield ("retry-account", {
            "jar_id": bound_jar_id, "jar_name": bound_jar_id,
            "reason": "bound account is unavailable before dispatch",
            "migrate_thread": True,
        })
        return
    if not jar and jar_hint and not bound_jar_id:
        jar = acquire_jar(prefer_live=True, exclude=excluded)
    if not jar:
        yield ("error", "502: No jar with valid cookies/session — upload cookies or enable a keeper")
        return
    tried.add(jar["id"])

    # Existing Arena conversations must stay on their original authenticated
    # keeper/route. If that keeper is quarantined, actively repair it and wait
    # briefly instead of knowingly sending another request through the same
    # broken browser transport.
    if bound_jar_id:
        sid = str(jar.get("id") or "")
        quarantine_until = _api_keeper_quarantine_until.get(sid, 0.0)
        if sid and time.monotonic() < quarantine_until:
            _schedule_transport_recovery(sid, "bound conversation requested during quarantine")
            deadline = time.monotonic() + BOUND_KEEPER_RECOVERY_WAIT_SEC
            log("INFO", f"[{jar.get('name')}] bound conversation waiting up to "
                        f"{BOUND_KEEPER_RECOVERY_WAIT_SEC:.0f}s for same-keeper recovery")
            while time.monotonic() < deadline:
                if (_api_keeper_verified(sid)
                        and keeper_session_ready(keeper.sessions.get(sid))):
                    break
                await asyncio.sleep(0.5)
            if not (_api_keeper_verified(sid)
                    and keeper_session_ready(keeper.sessions.get(sid))):
                yield ("retry-account", {
                    "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                    "reason": "bound keeper did not recover before dispatch",
                    "migrate_thread": True,
                })
                return

    # Startup used to race chat: requests reached Arena with `token no` while
    # all keepers were still launching, producing opaque 500s. Trigger sync and
    # wait briefly for this exact jar's page instead of sending invalid traffic.
    if not _find_session(jar.get("id"))[1]:
        await keeper.sync()
        deadline = time.monotonic() + KEEPER_REQUEST_READY_SEC
        while time.monotonic() < deadline and not _find_session(jar.get("id"))[1]:
            s_wait = keeper.sessions.get(jar.get("id"))
            if s_wait and s_wait.status == "error":
                break
            await asyncio.sleep(0.5)
    if not _find_session(jar.get("id"))[1]:
        s_wait = keeper.sessions.get(jar.get("id"))
        detail = redact(getattr(s_wait, "error", "") or getattr(s_wait, "current_step", "") or "keeper is still starting")
        if not bound_jar_id:
            _bump_account_failover("keeper_unready")
            _verification_preflight_retry_after[str(jar.get("id"))] = 0.0
            yield ("retry-account", {
                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                "reason": f"keeper not ready: {detail}",
            })
            return
        yield ("retry-account", {
            "jar_id": jar.get("id"), "jar_name": jar.get("name"),
            "reason": f"bound keeper not ready before dispatch: {detail}",
            "migrate_thread": True,
        })
        return

    # A bound conversation (and especially an exact-ID confirmed-absence retry)
    # must not mint or POST merely because the browser process exists. The
    # verification lease is the request-admission truth. After a transport
    # restart the quarantine timer can expire before Enterprise execute is
    # usable again; without this gate the retry races readiness recovery and
    # can navigate the same keeper while it is being refreshed/relogged.
    if bound_jar_id or retry_envelope_ids:
        sid = str(jar.get("id") or "")
        wait_reason = "exact-ID retry" if retry_envelope_ids else "bound conversation"
        deadline = time.monotonic() + BOUND_VERIFICATION_READY_WAIT_SEC
        announced = False
        while time.monotonic() < deadline:
            session = keeper.sessions.get(sid)
            transport_task = _transport_recovery_tasks.get(sid)
            transport_busy = bool(transport_task and not transport_task.done())
            relogin_lock = getattr(session, "_relogin_lock", None) if session else None
            relogin_busy = bool(relogin_lock and relogin_lock.locked())
            ready = bool(
                _api_keeper_verified(sid)
                and keeper_session_ready(session)
                and not transport_busy
                and not relogin_busy
                and getattr(session, "status", "") == "running"
            )
            if ready:
                break
            if not announced:
                announced = True
                log("INFO", f"[{jar.get('name')}] {wait_reason} waiting up to "
                            f"{BOUND_VERIFICATION_READY_WAIT_SEC:.0f}s for same-keeper verification readiness")
            _wake_verification_scheduler()
            await asyncio.sleep(0.5)
        else:
            session = keeper.sessions.get(sid)
            state = getattr(session, "status", "missing") if session else "missing"
            transport_task = _transport_recovery_tasks.get(sid)
            transport_busy = bool(transport_task and not transport_task.done())
            relogin_lock = getattr(session, "_relogin_lock", None) if session else None
            relogin_busy = bool(relogin_lock and relogin_lock.locked())
            log("WARN", f"[{jar.get('name')}] {wait_reason} withheld before token mint · "
                        f"verification_ready={_api_keeper_verified(sid)} · status={state} · "
                        f"transport_recovery={transport_busy} · relogin={relogin_busy}")
            if retry_envelope_ids:
                yield ("error", "503: The original turn was not replayed because its bound keeper is still "
                                "recovering verification readiness. Bridgena preserved the exact evaluation/message IDs; "
                                "retry after the same keeper is readmitted.")
                return
            yield ("retry-account", {
                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                "reason": "bound keeper verification readiness did not recover before dispatch",
                "migrate_thread": True,
            })
            return

    # Catch dead SOCKS/browser routes before minting a token or submitting a
    # model request. New/unbound chats fail over immediately while the broken
    # keeper recovers in the background. Bound chats wait for the same keeper.
    if not await _ensure_predispatch_transport(jar, wait_for_recovery=bool(bound_jar_id)):
        if not bound_jar_id:
            _bump_account_failover("predispatch")
            yield ("retry-account", {
                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                "reason": "pre-dispatch browser route failed before model POST",
            })
            return
        yield ("retry-account", {
            "jar_id": jar.get("id"), "jar_name": jar.get("name"),
            "reason": "bound keeper route failed before model POST",
            "migrate_thread": True,
        })
        return

    response_text = ""
    reasoning_text = ""
    pending_v2_token = None
    # A server-requested V2 escalation is a protocol continuation, not a general
    # transport retry. Reserve exactly one extra loop slot so the harvested V2
    # token can actually be sent even when BRIDGENA_REQUEST_MAX_ATTEMPTS=1.
    # The bonus slot is inaccessible unless pending_v2_token was produced by the
    # immediately preceding verification rejection, so other failure classes do
    # not silently gain an extra retry.
    for attempt in range(max_attempts + 1):
        if attempt >= max_attempts and not pending_v2_token:
            break
        p = bind_persona(jar)
        jar = await _live_cookies(jar)
        if not jar_has_auth(jar):
            if mc:
                yield ("retry-account", {
                    "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                    "reason": "bound account lost authentication before model POST",
                    "migrate_thread": True,
                })
                return
            _bump_account_failover("keeper_unready")
            yield ("retry-account", {
                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                "reason": "account has no usable authenticated cookies",
            })
            return
        model_id = resolve_model_id(model_name, jar)
        if not re.fullmatch(r"[0-9a-fA-F-]{32,36}", str(model_id)):
            if not mc:
                yield ("retry-account", {
                    "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                    "reason": f"model '{model_name}' is unavailable in this account's catalog",
                })
                return
            yield ("retry-account", {
                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                "reason": f"bound account cannot resolve model '{model_name}'",
                "migrate_thread": True,
            })
            return
        base = {"mode": "direct-battle", "modelAId": model_id, "modality": "chat"}
        follow_url = None
        if mc and mc.get("arena_id"):
            # post-to-evaluation is not a minimal "conversation id + text"
            # endpoint. Arena expects a complete new message envelope for every
            # continuation, with fresh message UUIDs and the selected model.
            # `mode` belongs to create-evaluation and is intentionally omitted
            # from this follow-up body, matching the live client contract.
            base = {
                "id": mc["arena_id"],
                "modelAId": model_id,
                "userMessageId": str((retry_envelope_ids or {}).get("userMessageId") or uuid7()),
                "modelAMessageId": str((retry_envelope_ids or {}).get("modelAMessageId") or uuid7()),
                "modality": "chat",
            }
            follow_url = f"{ARENA_BASE}/nextjs-api/stream/post-to-evaluation/{mc['arena_id']}"
        else:
            base.update({
                "id": str((retry_envelope_ids or {}).get("id") or uuid7()),
                "userMessageId": str((retry_envelope_ids or {}).get("userMessageId") or uuid7()),
                "modelAMessageId": str((retry_envelope_ids or {}).get("modelAMessageId") or uuid7()),
            })
        turn_content = prompt
        if not mc and system_prompt:
            turn_content = f"{system_prompt.strip()}\n\n{prompt}".strip()
        content = turn_content if len(turn_content) <= MAX_PROMPT else turn_content[:MAX_PROMPT]
        # These apparently optional fields are always emitted by Arena's live
        # client. Its follow-up validator returns a generic 500 when they are
        # absent, so preserve the exact captured envelope even when both empty.
        user_message = {
            "content": content,
            "experimental_attachments": attachments or [],
            "metadata": {},
        }
        base["userMessage"] = user_message
        log("INFO", f"[{jar.get('name')}] outbound {'follow-up' if follow_url else 'create'} envelope · "
                    f"content string {len(content)} chars · attachments {len(attachments or [])}")
        if retry_envelope_ids:
            log("WARN", f"[{jar.get('name')}] outbound envelope is a confirmed-absence retry · "
                        f"reusing id {str(base.get('id'))[:12]}… · "
                        f"userMessageId {str(base.get('userMessageId'))[:12]}… · "
                        f"modelMessageId {str(base.get('modelAMessageId'))[:12]}…")

        if pending_v2_token:
            _attach_v2(base, pending_v2_token)
            tok = pending_v2_token
            pending_v2_token = None
            log("INFO", f"[{jar.get('name')}] Using harvested V2 escalation token ({len(tok)} chars) — skipping V3 minting")
        else:
            tok = await mint_v3(jar.get("id"))
            if not tok:
                # The live Arena client does NOT proactively render V2 when
                # enterprise.execute() fails. V2 is mounted only after an
                # upstream verification-escalation response.
                log("WARN", f"[{jar.get('name')}] V3 token unavailable — no request sent; "
                            "V2 escalation is server-triggered and was not launched proactively")
            else:
                _attach_v3(base, tok)

        if not tok and not base.get("recaptchaV2Token") and not base.get("recaptchaV3Token"):
            mint_diag = _get_v3_mint_failure(jar.get("id"))
            mint_stage = mint_diag.get("stage") or "unknown"
            mint_reason = mint_diag.get("reason") or "no detailed mint failure was captured"
            log("WARN", f"[{jar.get('name')}] V3 mint failed before dispatch · stage {mint_stage} · {mint_reason}")
            yield ("error", "503: Verification token preparation failed before upstream dispatch. "
                            f"stage={mint_stage}; reason={mint_reason}. No Arena request was sent.")
            return
        # Live wire invariant: normal requests contain V3 only; challenge retries
        # contain V2 only. Never send both fields together.
        if base.get("recaptchaV2Token"):
            base.pop("recaptchaV3Token", None)
        elif base.get("recaptchaV3Token"):
            base.pop("recaptchaV2Token", None)

        url = follow_url or f"{ARENA_BASE}/nextjs-api/stream/create-evaluation"
        # Existing Arena conversations are session-bound. Restore the exact exit
        # that created the thread before the normal sticky picker runs.
        bound_proxy = (_normalize_proxy(mc.get("proxy"))
                       if (not LOCAL_UPSTREAM and mc and mc.get("proxy")
                           and _rotation_mode() == "assignment") else None)
        if bound_proxy:
            if not await asyncio.to_thread(proxy_alive, bound_proxy):
                _schedule_transport_recovery(jar.get("id"), "bound exit unavailable before dispatch")
                yield ("retry-account", {
                    "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                    "reason": "bound account exit is unavailable before model POST",
                    "migrate_thread": True,
                })
                return
            proxy = bound_proxy
        else:
            proxy = await apick_live_proxy(jar, purpose="api")
        if LOCAL_UPSTREAM:
            proxy, cycled = None, False
        else:
            proxy, cycled = await anchor_proxy_to_keeper(jar.get("id"), proxy)
        if cycled:
            jar = await _live_cookies(jar)
        if proxy:
            log("INFO", f"[{jar.get('name')}] via {p.key} persona · exit {_proxy_hkey(proxy)} · "
                        f"model {str(model_id)[:8]}… · token {'yes' if tok else 'no'}")
        elif LOCAL_UPSTREAM:
            log("INFO", f"[{jar.get('name')}] local mirror transport · outbound egress is owned by {ARENA_BASE}")
        else:
            log("WARN", f"[{jar.get('name')}] No live proxy — request will use server egress")

        # Preferred transport: execute the POST inside the already-authenticated
        # keeper origin. This preserves the exact browser cookie jar, TLS/browser
        # identity and proxy exit that minted the token. curl remains a fallback
        # only for browser-evaluation failures.
        browser_session = keeper.sessions.get(jar.get("id"))
        if keeper_session_ready(browser_session):
            try:
                log("INFO", f"[{jar.get('name')}] transport browser-origin")
                _transport_t0 = time.monotonic()
                _first_stream_frame_at = None
                _first_semantic_at = None
                _raw_frames_seen = 0
                _stream_norm = _StreamDeltaNormalizer()
                _decoded_events = 0
                _unknown_frames = 0
                _semantic_deadline = _transport_t0 + FIRST_ASSISTANT_RESPONSE_SEC

                async with _browser_transport_guard(browser_session, proxy, jar.get("name") or jar.get("id") or "keeper"):
                    _bridge_iter = browser_session.bridge_fetch(url, base)
                    try:
                        while True:
                            try:
                                if _first_semantic_at is None:
                                    remaining = _semantic_deadline - time.monotonic()
                                    if remaining <= 0:
                                        raise asyncio.TimeoutError()
                                    line = await asyncio.wait_for(
                                        _bridge_iter.__anext__(), timeout=remaining
                                    )
                                else:
                                    line = await _bridge_iter.__anext__()
                            except StopAsyncIteration:
                                break
                            except asyncio.TimeoutError:
                                elapsed = time.monotonic() - _transport_t0
                                log("WARN", f"[{jar.get('name')}] first assistant response SLA missed · "
                                            f"no decodable content/reasoning within {FIRST_ASSISTANT_RESPONSE_SEC:.1f}s · "
                                            f"raw frames {_raw_frames_seen}")
                                _quarantine_api_keeper(
                                    jar.get("id"), "first assistant response timeout",
                                    TRANSPORT_FAILURE_QUARANTINE_SEC,
                                )
                                _schedule_transport_recovery(
                                    jar.get("id"), "first assistant response timeout"
                                )
                                yield ("error",
                                       f"504: Arena did not begin a decodable assistant response within "
                                       f"{FIRST_ASSISTANT_RESPONSE_SEC:.0f}s. The keeper is being recovered.")
                                return

                            _raw_frames_seen += 1
                            if _first_stream_frame_at is None:
                                _first_stream_frame_at = time.monotonic()
                                log("INFO", f"[{jar.get('name')}] first upstream stream frame · "
                                            f"{(_first_stream_frame_at - _transport_t0):.2f}s after POST")

                            events = _parse_stream_events(str(line).strip())
                            if not events:
                                _unknown_frames += 1
                                continue

                            for kind, payload in events:
                                kind, payload = _stream_norm.normalize(kind, payload)
                                if kind in ("content", "reasoning") and not payload:
                                    continue
                                _decoded_events += 1

                                if kind in ("content", "reasoning") and _first_semantic_at is None:
                                    _first_semantic_at = time.monotonic()
                                    log("INFO", f"[{jar.get('name')}] first assistant semantic output · "
                                                f"{(_first_semantic_at - _transport_t0):.2f}s after POST")

                                if kind == "content" and isinstance(payload, str):
                                    response_text += payload
                                    yield ("content", payload)
                                elif kind == "reasoning":
                                    reasoning_chunk = payload if isinstance(payload, str) else json.dumps(payload)
                                    reasoning_text += reasoning_chunk
                                    yield ("reasoning", reasoning_chunk)
                                elif kind == "error":
                                    yield ("error", str(payload))
                                    return
                    finally:
                        try:
                            await _bridge_iter.aclose()
                        except Exception:
                            pass
                if proxy:
                    _proxy_health_record(proxy, True, 0, source="browser-stream")
                    _flagged_exits.pop(_proxy_hkey(proxy), None)
                _captcha_failed_jars.pop(jar.get("id"), None)
                _api_keeper_quarantine_until.pop(str(jar.get("id")), None)
                _api_verified_keepers[str(jar.get("id"))] = time.monotonic()
                _refresh_api_ready_event()
                if not response_text and reasoning_text:
                    # Some reasoning-only Arena adapters never emit a separate
                    # final text part. Preserve compatibility by mirroring the
                    # completed reasoning once into assistant content.
                    response_text = reasoning_text
                    yield ("content", reasoning_text)
                    log("INFO", f"[{jar.get('name')}] stream compatibility · reasoning-only model mirrored to final content")
                if not response_text:
                    log("WARN", f"[{jar.get('name')}] Arena returned HTTP 200 but no decodable text frames for {model_name}")
                    yield ("error", "502: Arena completed the stream without a text response. The model may be unavailable or using an unsupported event format.")
                    return
                if not follow_url:
                    conv2 = dict(conv)
                    conv2["model"] = model_name
                    conv2["arena"] = dict(conv2.get("arena") or {})
                    conv2["arena"][model_name] = {
                        "arena_id": base["id"], "mode": "direct",
                        "jar_id": jar.get("id"), "proxy": proxy,
                    }
                    save_conversation(chat_id, conv2)
                log("INFO", f"[{jar.get('name')}] browser stream complete · "
                            f"{(time.monotonic() - _transport_t0):.2f}s transport total · "
                            f"{len(response_text)} text chars · {_decoded_events} decoded events · "
                            f"{_unknown_frames} metadata/unknown frames")
                _clear_model_rate_limit(model_name)
                if retry_envelope_ids:
                    _bump_undelivered_retry("succeeded")
                    log("OK", f"[{jar.get('name')}] confirmed-absence retry succeeded · "
                              f"{len(response_text)} chars")
                yield ("done", response_text)
                return
            except BridgeHTTPError as e:
                if e.stream_error and e.response_started:
                    log("WARN", f"[{jar.get('name')}] browser response stream interrupted after "
                                f"{e.frame_count} frame(s) · finish {'yes' if e.finish_seen else 'no'}")
                    _quarantine_api_keeper(
                        jar.get("id"), "browser-origin mid-stream network failure",
                        TRANSPORT_FAILURE_QUARANTINE_SEC,
                    )

                    # The model may continue/finish on Arena even though our
                    # streaming fetch died. Before showing an error, open Arena's
                    # own history UI in this same authenticated keeper and recover
                    # the completed assistant bubble. NO prompt replay occurs.
                    salvage = await _attempt_ui_stream_salvage(
                        session=browser_session,
                        chat_id=chat_id,
                        model_name=model_name,
                        arena_id=str(base.get("id") or (mc or {}).get("arena_id") or ""),
                        model_message_id=str(base.get("modelAMessageId") or ""),
                        user_prompt=prompt,
                        partial_text=response_text or reasoning_text or "",
                        jar=jar,
                        proxy=proxy,
                        cached_url=str((mc or {}).get("ui_url") or ""),
                        timeout_sec=ARENA_SALVAGE_QUICK_SEC,
                        stage="quick-current-context",
                    )

                    # If the route itself died, history navigation in the same
                    # context is often doomed too. Repair FIRST, then retry
                    # salvage in the freshly-started browser context.
                    if not salvage.get("ok"):
                        _bump_arena_ui_recovery("post_restart_attempted")
                        recovered_browser = await _recover_keeper_before_salvage(
                            str(jar.get("id") or ""),
                            reason="mid-stream failure before second-stage salvage",
                            timeout_sec=ARENA_SALVAGE_RECOVERY_WAIT_SEC,
                        )
                        if recovered_browser:
                            browser_session = keeper.sessions.get(jar.get("id"))
                            salvage = await _attempt_ui_stream_salvage(
                                session=browser_session,
                                chat_id=chat_id,
                                model_name=model_name,
                                arena_id=str(base.get("id") or (mc or {}).get("arena_id") or ""),
                                model_message_id=str(base.get("modelAMessageId") or ""),
                                user_prompt=prompt,
                                partial_text=response_text or reasoning_text or "",
                                jar=jar,
                                proxy=proxy,
                                cached_url=str((mc or {}).get("ui_url") or ""),
                                timeout_sec=ARENA_POST_RESTART_SALVAGE_SEC,
                                stage="post-restart",
                            )
                            if salvage.get("ok"):
                                _bump_arena_ui_recovery("post_restart_recovered")

                    # A mid-stream browser break does not mean the Arena model stopped.
                    # If authenticated history proves the exact turn exists, give that
                    # delivered evaluation one final bounded completion window. This is
                    # recovery-only: it never resubmits the prompt.
                    if (not salvage.get("ok")) and salvage.get("trace_found"):
                        browser_session = keeper.sessions.get(jar.get("id")) or browser_session
                        log("INFO", f"[{jar.get('name')}] delivered evaluation still incomplete after route repair; "
                                    f"polling exact Arena turn for up to {ARENA_DELIVERED_WAIT_SEC:.1f}s")
                        salvage = await _attempt_ui_stream_salvage(
                            session=browser_session,
                            chat_id=chat_id,
                            model_name=model_name,
                            arena_id=str(base.get("id") or (mc or {}).get("arena_id") or ""),
                            model_message_id=str(base.get("modelAMessageId") or ""),
                            user_prompt=prompt,
                            partial_text=response_text or reasoning_text or "",
                            jar=jar,
                            proxy=proxy,
                            cached_url=str(salvage.get("url") or (mc or {}).get("ui_url") or ""),
                            timeout_sec=ARENA_DELIVERED_WAIT_SEC,
                            stage="delivered-wait",
                        )

                    if salvage.get("ok"):
                        final_text = str(salvage.get("text") or "")
                        suffix = str(salvage.get("suffix") or "")
                        if suffix:
                            response_text += suffix
                            yield ("content", suffix)
                        elif not response_text and final_text:
                            response_text = final_text
                            yield ("content", final_text)
                        else:
                            response_text = final_text or response_text

                        log("OK", f"[{jar.get('name')}] interrupted stream recovered after "
                                  f"{salvage.get('source') or 'history/UI'} salvage · "
                                  f"{len(response_text)} final chars")
                        yield ("done", response_text)
                        return

                    if response_text and len(response_text.strip()) >= PARTIAL_TERMINAL_MIN_CHARS:
                        # Degraded-success policy: Arena accepted this exact turn and the live
                        # transport already yielded meaningful semantic assistant output. If
                        # history/UI recovery cannot prove completion before its bounded
                        # deadline, do not turn useful already-delivered text into a hard API
                        # failure. Close the client stream cleanly with the captured output.
                        # The Arena binding remains persisted, so later turns still continue
                        # from the authoritative upstream thread. Tiny fragments are excluded
                        # by PARTIAL_TERMINAL_MIN_CHARS and continue to fail below.
                        log("WARN", f"[{jar.get('name')}] delivered-turn recovery exhausted, but "
                                    f"{len(response_text)} semantic chars were already streamed; "
                                    "closing as degraded terminal success and preserving Arena binding")
                        yield ("done", response_text)
                        return
                    if response_text:
                        yield ("error", "502: Arena accepted the turn and some user-visible assistant content was observed, but only a short or "
                                        "unrecoverable fragment was available when the delivered-turn recovery window expired. "
                                        "The exact Arena evaluation remains bound for subsequent continuation/recovery; "
                                        "the partial response remains visible above.")
                    elif reasoning_text:
                        yield ("error", "502: Arena accepted the turn and provider reasoning frames were observed, but no user-visible assistant "
                                        "content was recovered before the delivered-turn recovery window expired. Bridgena used the reasoning "
                                        "frames only as an internal history-matching fingerprint and did not expose them as final content. "
                                        "The exact Arena evaluation remains bound for subsequent continuation/recovery.")
                    else:
                        yield ("error", "502: Arena accepted the turn, but the browser stream was interrupted and the exact "
                                        "evaluation did not reach a confirmed completed state before the recovery window expired. "
                                        "Its Arena binding was preserved for subsequent continuation/recovery.")
                    return
                if not e.status:
                    log("WARN", f"[{jar.get('name')}] browser transport failed before an HTTP response; "
                                f"checking Arena UI before declaring failure")
                    _quarantine_api_keeper(
                        jar.get("id"), "browser-origin network failure",
                        TRANSPORT_FAILURE_QUARANTINE_SEC,
                    )

                    # `fetch()` can throw even after the POST reached Arena. The
                    # history UI is our source of truth for whether a response
                    # actually appeared; never replay the prompt just to find out.
                    # Give a still-responsive context a tiny chance to show
                    # the history row, but do NOT burn the whole salvage timeout
                    # through a route that just returned HTTP-0.
                    salvage = await _attempt_ui_stream_salvage(
                        session=browser_session,
                        chat_id=chat_id,
                        model_name=model_name,
                        arena_id=str(base.get("id") or (mc or {}).get("arena_id") or ""),
                        model_message_id=str(base.get("modelAMessageId") or ""),
                        user_prompt=prompt,
                        partial_text=response_text or reasoning_text or "",
                        jar=jar,
                        proxy=proxy,
                        cached_url=str((mc or {}).get("ui_url") or ""),
                        timeout_sec=ARENA_SALVAGE_QUICK_SEC,
                        stage="quick-http0",
                    )

                    if not salvage.get("ok"):
                        _bump_arena_ui_recovery("post_restart_attempted")
                        recovered_browser = await _recover_keeper_before_salvage(
                            str(jar.get("id") or ""),
                            reason="HTTP-0 before history salvage",
                            timeout_sec=ARENA_SALVAGE_RECOVERY_WAIT_SEC,
                        )
                        if recovered_browser:
                            browser_session = keeper.sessions.get(jar.get("id"))
                            salvage = await _attempt_ui_stream_salvage(
                                session=browser_session,
                                chat_id=chat_id,
                                model_name=model_name,
                                arena_id=str(base.get("id") or (mc or {}).get("arena_id") or ""),
                                model_message_id=str(base.get("modelAMessageId") or ""),
                                user_prompt=prompt,
                                partial_text=response_text or reasoning_text or "",
                                jar=jar,
                                proxy=proxy,
                                cached_url=str((mc or {}).get("ui_url") or ""),
                                timeout_sec=ARENA_POST_RESTART_SALVAGE_SEC,
                                stage="post-restart-http0",
                            )
                            if salvage.get("ok"):
                                _bump_arena_ui_recovery("post_restart_recovered")

                    if salvage.get("ok"):
                        final_text = str(salvage.get("text") or "")
                        suffix = str(salvage.get("suffix") or "")
                        if suffix:
                            response_text += suffix
                            yield ("content", suffix)
                        elif not response_text and final_text:
                            response_text = final_text
                            yield ("content", final_text)
                        else:
                            response_text = final_text or response_text

                        log("OK", f"[{jar.get('name')}] HTTP-0 request recovered after route repair · "
                                  f"{len(response_text)} chars · source {salvage.get('source') or 'history/UI'}")
                        yield ("done", response_text)
                        return

                    trace_found = salvage.get("trace_found")
                    if trace_found is False and not response_text and not reasoning_text:
                        # History absence after an HTTP-0 is NOT authoritative for
                        # existing Arena threads. In repeated production traces,
                        # bound follow-ups were absent from history long enough for
                        # this branch to fire, yet an exact-ID resend immediately
                        # received "Message already exists". That proves the history
                        # test can lag behind accepted follow-up delivery.
                        #
                        # Therefore:
                        #   * bound follow-up -> NEVER replay solely on history absence;
                        #     do one final exact-thread recovery pass, then return an
                        #     ambiguous-delivery error with the binding preserved.
                        #   * fresh create -> retain the existing exact-ID retry, where
                        #     Arena's duplicate evaluation ID is a clean dedupe signal.
                        if follow_url:
                            log("WARN", f"[{jar.get('name')}] HTTP-0 follow-up history miss is non-authoritative; "
                                        "replay suppressed · final exact-thread recovery")
                            browser_session = keeper.sessions.get(jar.get("id")) or browser_session
                            final_salvage = await _attempt_ui_stream_salvage(
                                session=browser_session,
                                chat_id=chat_id,
                                model_name=model_name,
                                arena_id=str((mc or {}).get("arena_id") or base.get("id") or ""),
                                model_message_id=str(base.get("modelAMessageId") or ""),
                                user_prompt=prompt,
                                partial_text=response_text or reasoning_text or "",
                                jar=jar,
                                proxy=proxy,
                                cached_url=str(salvage.get("url") or (mc or {}).get("ui_url") or ""),
                                timeout_sec=FOLLOWUP_HTTP0_FINAL_RECOVERY_SEC,
                                stage="followup-http0-final",
                            )
                            if final_salvage.get("ok"):
                                final_text = str(final_salvage.get("text") or "")
                                suffix = str(final_salvage.get("suffix") or "")
                                if suffix:
                                    response_text += suffix
                                    yield ("content", suffix)
                                elif not response_text and final_text:
                                    response_text = final_text
                                    yield ("content", final_text)
                                else:
                                    response_text = final_text or response_text
                                log("OK", f"[{jar.get('name')}] HTTP-0 follow-up recovered without replay · "
                                          f"{len(response_text)} chars · source {final_salvage.get('source') or 'history/UI'}")
                                yield ("done", response_text)
                                return

                            # Persist the already-bound thread exactly as-is. Do not
                            # convert a delayed history index into a duplicate POST.
                            log("WARN", f"[{jar.get('name')}] HTTP-0 follow-up remained absent from history after "
                                        f"{FOLLOWUP_HTTP0_FINAL_RECOVERY_SEC:.1f}s final recovery; replay suppressed")
                            yield ("error", "502: The bound Arena follow-up lost its browser transport before an HTTP "
                                            "response was observed. Arena history had not indexed the exact message before "
                                            "the bounded recovery deadline, so Bridgena preserved the existing thread and "
                                            "suppressed replay rather than risking a duplicate follow-up.")
                            return

                        # Fresh create only: reuse the SAME IDs rather than minting
                        # new message IDs. If the original create POST was accepted
                        # but indexing lagged, the duplicate evaluation ID gives the
                        # upstream a deterministic dedupe signal.
                        yield ("retry-undelivered", {
                            "jar_id": jar.get("id"),
                            "jar_name": jar.get("name"),
                            "reason": "no Arena history trace after same-keeper route recovery (fresh create only)",
                            "envelope_ids": {
                                "id": str(base.get("id") or ""),
                                "userMessageId": str(base.get("userMessageId") or ""),
                                "modelAMessageId": str(base.get("modelAMessageId") or ""),
                            },
                        })
                        return

                    if trace_found:
                        _bump_undelivered_retry("suppressed_trace_found")
                        log("WARN", f"[{jar.get('name')}] resend suppressed · Arena history/UI contains "
                                    "evidence of the turn even though no completed answer was recovered")

                    # Keep the existing 5-second minimum for very fast failures;
                    # normally the foreground repair+salvage path is longer.
                    elapsed = time.monotonic() - _transport_t0
                    remaining = FIRST_ASSISTANT_RESPONSE_SEC - elapsed
                    if remaining > 0:
                        await asyncio.sleep(remaining)

                    yield ("error", "502: The browser route failed before a response was observed. Bridgena "
                                    "restarted the same bound keeper and checked Arena history, but delivery remained "
                                    "ambiguous so the turn was not resent.")
                    return
                else:
                    verdict = _classify(e.status, e.body)
                    log("WARN", f"[{jar.get('name')}] browser-origin HTTP {e.status} (verdict={verdict}): {e.body[:250]}")

                    # A failed POST may already have been processed. Do not turn
                    # it into a new conversation or replay it automatically.
                    #
                    # An exact-ID retry can legitimately receive HTTP 400
                    # "Evaluation session ... already exists." That is not a bad
                    # client request: it is positive evidence that the original
                    # create-evaluation POST reached Arena. Treat the duplicate as
                    # a delivery ACK, persist the thread binding, and recover the
                    # existing answer from Arena history/UI. Never mint a new ID
                    # for this logical turn.
                    _body_low = (e.body or "").lower()
                    _duplicate_create_ack = bool(
                        e.status == 400 and not follow_url and retry_envelope_ids
                        and "evaluation session" in _body_low and "already exists" in _body_low
                    )
                    _duplicate_message_ack = bool(
                        e.status == 400 and follow_url and retry_envelope_ids
                        and "message already exists" in _body_low
                        and "evaluation session" in _body_low
                    )
                    if _duplicate_create_ack or _duplicate_message_ack:
                        existing_id = str(base.get("id") or (mc or {}).get("arena_id") or "")
                        ack_kind = "follow-up message" if _duplicate_message_ack else "create ID"
                        log("OK", f"[{jar.get('name')}] duplicate {ack_kind} acknowledged by Arena · "
                                  f"evaluation {existing_id[:12]}… · reconciling existing turn")
                        _bump_undelivered_retry("duplicate_message_ack" if _duplicate_message_ack else "duplicate_ack")

                        # The HTTP 400 duplicate ACK came back through this exact
                        # browser-origin transport, so the keeper/route is alive enough
                        # to reach Arena. Restarting it here used to destroy useful page
                        # state and consumed ~50s before history was polled again.
                        # Treat the ACK as authoritative delivery proof, persist the
                        # binding immediately, and reconcile under ONE bounded deadline.
                        conv2 = dict(conv)
                        conv2["model"] = model_name
                        conv2["arena"] = dict(conv2.get("arena") or {})
                        conv2["arena"][model_name] = {
                            "arena_id": existing_id, "mode": "direct",
                            "jar_id": jar.get("id"), "proxy": proxy,
                        }
                        save_conversation(chat_id, conv2)

                        ack_deadline = time.monotonic() + DUPLICATE_ACK_RECOVERY_BUDGET_SEC

                        def _ack_remaining(default: float = 0.0) -> float:
                            remaining = ack_deadline - time.monotonic()
                            return max(default, remaining)

                        # First use a short current-context/history pass. Because the
                        # duplicate ACK itself proves delivery, there is no reason to
                        # spend the full post-restart salvage timeout here.
                        first_wait = min(8.0, max(1.0, ack_deadline - time.monotonic()))
                        log("INFO", f"[{jar.get('name')}] duplicate ACK proves delivery · "
                                    f"single reconciliation budget {DUPLICATE_ACK_RECOVERY_BUDGET_SEC:.1f}s · "
                                    f"evaluation {existing_id[:12]}…")
                        salvage = await _attempt_ui_stream_salvage(
                            session=browser_session,
                            chat_id=chat_id,
                            model_name=model_name,
                            arena_id=existing_id,
                            model_message_id=str(base.get("modelAMessageId") or ""),
                            user_prompt=prompt,
                            partial_text=response_text or reasoning_text or "",
                            jar=jar,
                            proxy=proxy,
                            cached_url=str((mc or {}).get("ui_url") or ""),
                            timeout_sec=first_wait,
                            stage="duplicate-ack-fast",
                        )

                        # If indexing/generation is still catching up, spend only the
                        # REMAINDER of the same budget polling the exact persisted turn.
                        # Never restart the keeper and never resubmit the prompt here.
                        if not salvage.get("ok"):
                            remaining = ack_deadline - time.monotonic()
                            if remaining > 0.75:
                                browser_session = keeper.sessions.get(jar.get("id")) or browser_session
                                log("INFO", f"[{jar.get('name')}] duplicate turn not visible yet; "
                                            f"polling persisted evaluation for remaining {remaining:.1f}s")
                                salvage = await _attempt_ui_stream_salvage(
                                    session=browser_session,
                                    chat_id=chat_id,
                                    model_name=model_name,
                                    arena_id=existing_id,
                                    model_message_id=str(base.get("modelAMessageId") or ""),
                                    user_prompt=prompt,
                                    partial_text=response_text or reasoning_text or "",
                                    jar=jar,
                                    proxy=proxy,
                                    cached_url=str(salvage.get("url") or (mc or {}).get("ui_url") or ""),
                                    timeout_sec=remaining,
                                    stage="duplicate-ack-budget",
                                )

                        if salvage.get("ok"):
                            final_text = str(salvage.get("text") or "")
                            suffix = str(salvage.get("suffix") or "")
                            if suffix:
                                response_text += suffix
                                yield ("content", suffix)
                            elif not response_text and final_text:
                                response_text = final_text
                                yield ("content", final_text)
                            else:
                                response_text = final_text or response_text
                            log("OK", f"[{jar.get('name')}] duplicate {'message' if _duplicate_message_ack else 'ID'} turn recovered · "
                                      f"{len(response_text)} chars · source {salvage.get('source') or 'history/UI'}")
                            yield ("done", response_text)
                            return

                        # Delivery is known; returning within the client-facing budget is
                        # preferable to keeping the SSE request open until the caller
                        # disconnects. The persisted binding prevents this turn from
                        # being mistaken for a fresh create on the next request.
                        log("WARN", f"[{jar.get('name')}] duplicate {'follow-up message' if _duplicate_message_ack else 'create'} "
                                    f"delivery confirmed but answer not reconciled within {DUPLICATE_ACK_RECOVERY_BUDGET_SEC:.1f}s; "
                                    "binding preserved and replay suppressed")
                        yield ("error", "502: Arena confirmed that this exact message/evaluation already exists, so the "
                                        "original turn was delivered. Bridgena preserved the existing evaluation binding and "
                                        "suppressed replay, but the completed answer was not visible before the bounded "
                                        "duplicate-reconciliation deadline.")
                        return

                    if verdict == "SESSION":
                        _quarantine_api_keeper(jar.get("id"), "upstream session/login gate", 180.0)
                        browser_session.status = "degraded"
                        browser_session.ready_at = float("inf")
                        browser_session.error = "Upstream rejected authentication; recovery scheduled"
                        _schedule_transport_recovery(jar.get("id"), "upstream LOGIN_GATE/session rejection")

                        # An explicit 401/LOGIN_GATE with zero stream frames is
                        # a definitive no-generation result. For a NEW Arena
                        # conversation it is safe to try another configured
                        # authenticated account automatically.
                        if int(getattr(e, "frame_count", 0) or 0) == 0:
                            _bump_account_failover("session_401")
                            yield ("retry-account", {
                                "jar_id": jar.get("id"), "jar_name": jar.get("name"),
                                "reason": "upstream LOGIN_GATE / session rejected before generation",
                                "migrate_thread": bool(mc),
                            })
                            return

                        yield ("error", "401: Upstream rejected the session after response activity began; "
                                        "automatic account handoff was suppressed.")
                        return

                    if verdict == "PROMPT":
                        log("WARN", f"[{jar.get('name')}] Arena rejected prompt before streaming (HTTP {e.status}) — no retry or rotation")
                        yield ("error", "422: Arena rejected this prompt before generation. Bridgena did not retry or rotate accounts; shorten the request or remove unsupported tool/system payloads.")
                        return

                    if verdict == "RATELIMIT":
                        explicit_retry = _parse_retry_after_seconds(getattr(e, "retry_after", ""))
                        cooldown = _mark_model_rate_limited(model_name, explicit_retry)
                        retry_after = max(1, int(cooldown + 0.999))
                        log("WARN", f"[{jar.get('name')}] upstream throttle (HTTP {e.status}) · "
                                    f"cooldown {cooldown:.1f}s · retry-after "
                                    f"{getattr(e, 'retry_after', '') or 'adaptive'} · same-account only")
                        if int(getattr(e, "frame_count", 0) or 0) == 0:
                            continuity = load_context_capsule(chat_id, model_name)
                            arm_throttle_thread_rehome(
                                chat_id, model_name, str(jar.get("id") or ""),
                                cooldown, continuity,
                            )
                            yield ("retry-same-account", {
                                "jar_id": jar.get("id"),
                                "jar_name": jar.get("name"),
                                "delay": cooldown,
                                "reason": "definitive zero-frame HTTP 429",
                                "rehome_thread": True,
                            })
                            return
                        yield ("error", f"429: Arena returned Too Many Requests for model '{model_name}'. "
                                        f"Retry in about {retry_after}s.")
                        return

                    if verdict == "UPSTREAM":
                        yield ("error", "502: Upstream request failed; it was not replayed because delivery may have occurred.")
                        return

                    if verdict == "RECAPTCHA":
                        failed_jar_id = jar.get("id")
                        _captcha_failed_jars[failed_jar_id] = time.time()

                        # A request-level verification rejection is not proof that
                        # the authenticated keeper/account is dead. The old v3.8.0
                        # path quarantined the keeper for 45 seconds, which could
                        # collapse fleet capacity after one rejected request.
                        #
                        # Keep the existing verification/escalation behavior
                        # unchanged, but make keeper lifecycle non-destructive:
                        # revoke only the API readiness lease and hand the browser
                        # to the normal transport/readiness recovery machinery.
                        _mark_api_keeper_unready(
                            failed_jar_id,
                            "upstream verification rejection; scheduling local readiness recovery",
                        )

                        if rc_attempts.get(failed_jar_id, 0) < 1:
                            rc_attempts[failed_jar_id] = rc_attempts.get(failed_jar_id, 0) + 1
                            reason = ("server requested V2 escalation"
                                      if e.status == 429 and "prompt failed" in (e.body or "").lower()
                                      else "V3 verification rejected")
                            log("WARN", f"[{jar.get('name')}] {reason} (HTTP {e.status}) — starting Enterprise V2 challenge")
                            esc = await mint_v2_escalation(failed_jar_id, settle_s=20.0)
                            if esc:
                                pending_v2_token = esc
                                log("OK", f"[{jar.get('name')}] V2 escalation token attached — retrying SAME jar via dedicated verification continuation")
                                # Do not tie this continuation to the generic request
                                # attempt budget. The loop reserves one V2-only slot.
                                continue

                        # Do not exile the keeper. Start ordinary local recovery so
                        # the next request can use it again as soon as browser/auth/
                        # route readiness is healthy. No cross-account replay is
                        # introduced here.
                        try:
                            _api_keeper_quarantine_until.pop(str(failed_jar_id), None)
                            _verification_preflight_retry_after.pop(str(failed_jar_id), None)
                            _schedule_transport_recovery(
                                str(failed_jar_id),
                                "post-rejection local keeper recovery",
                            )
                            _wake_verification_scheduler()
                        except Exception as recovery_exc:
                            log("WARN", f"[{jar.get('name')}] post-rejection recovery scheduling failed · "
                                        f"{type(recovery_exc).__name__}: {redact(str(recovery_exc))[:160]}")

                        if mc:
                            clear_conversation_model(chat_id, model_name)

                        log("WARN", f"[{jar.get('name')}] Arena verification rejected (HTTP {e.status}); "
                                    "keeper retained and local recovery started")
                        rejection = (e.body or "").strip().replace("\n", " ")[:220]
                        yield ("error",
                               "503: Arena rejected verification for this request and the same-keeper continuation did not complete. "
                               "The keeper was retained and local readiness recovery was started; no cross-account replay was attempted."
                               + (f" Upstream: {rejection}" if rejection else ""))
                        return

                    if e.status == 400 and "user message is invalid" in (e.body or "").lower():
                        yield ("error", "400: Arena rejected the message content. Send plain text or supported text content parts; images and unsupported multimodal parts are not accepted by this bridge yet.")
                        return
                    yield ("error", f"{e.status or 502}: Arena browser-origin request failed: {e.body[:350] or 'empty response'}")
                    return
            except Exception as browser_e:
                log("WARN", f"[{jar.get('name')}] browser-origin failed ({type(browser_e).__name__}: {browser_e}); delivery uncertain — no account failover")
                yield ("error", "502: Browser request was interrupted before a reliable HTTP response. Retry the request.")
                return

        headers = _headers_for(jar, p, json_body=True)
        kw = dict(json=base, headers=headers, stream=True, timeout=120.0)
        if proxy:
            kw["proxy"] = proxy
        t0 = time.monotonic()
        try:
            try:
                sess = AsyncSession(impersonate=impersonate_for(p))
            except Exception:
                if p.family not in _impersonate_warned:
                    _impersonate_warned.add(p.family)
                    log("WARN", f"curl_cffi has no '{impersonate_for(p)}' alias here — chrome131 fallback for {p.family}")
                sess = AsyncSession(impersonate="chrome131")
            async with sess as client:
                try:
                    resp = await asyncio.wait_for(client.post(url, **kw), timeout=_ttfb_budget(proxy))
                except Exception as post_e:
                    msg = str(post_e)
                    lowm = msg.lower()
                    if proxy and ("cannot complete socks" in lowm or "(97)" in msg or "(96)" in msg or "timed out" in lowm or "timeout" in lowm
                                  or "reset" in lowm or "refused" in lowm or "resolve" in lowm):
                        if "(97)" in msg or "(96)" in msg or "socks" in lowm:
                            note_cf_blocked_exit(proxy, f"socks reply while routing to arena: {msg[-60:].split('@')[-1]}")
                            route_fails.append((_proxy_hkey(proxy), msg[-60:].split("@")[-1]))
                            if attempt + 1 < max_attempts:
                                log("WARN", f"[{jar.get('name')}] exit can't route to arena (socks reply) — rotating; proxy NOT exiled")
                                continue
                            hosts = " · ".join(dict.fromkeys(h for h, _ in route_fails)) or "the pool"
                            warp_only = bool(route_fails) and all(h.startswith(("127.0.0.1:", "[::1]:", "localhost:")) for h, _ in route_fails)
                            why = ("WARP-only pool: localhost:6767's edge routinely rejects Cloudflare's own egress IPs — expected, not fixable from here"
                                   if warp_only else "the gateways answered 'can't route' — localhost:6767 is rejecting these exits' egress IPs right now")
                            yield ("error", f"503: {hosts} — {len(route_fails)} exit(s) connected+authed but none could route ({why}). "
                                            "Nothing exiled; flags self-expire (~3h). 'Scan pool' re-probes now.")
                            return
                        quarantine_proxy(proxy, f"curl: {msg[:90]}")
                        if attempt + 1 < max_attempts:
                            continue
                        yield ("error", f"502: Network error (all proxies down): {msg[:200]}")
                        return
                    yield ("error", f"Network error: {msg[:220]}")
                    return

                verdict = _classify(resp.status_code, "")
                if resp.status_code != 200:
                    raw = b""
                    async for chunk in resp.aiter_content():
                        raw += chunk if isinstance(chunk, (bytes, bytearray)) else str(chunk).encode("utf-8", "ignore")
                        if len(raw) > 40000:
                            break
                    body = raw.decode("utf-8", "ignore")
                    verdict = _classify(resp.status_code, body)
                    level = "WARN" if 400 <= resp.status_code < 500 else "ERROR"
                    log(level, f"Status {resp.status_code}, URL {url}, Body: {body[:600]}")

                    if resp.status_code == 404 and "model not found" in body.lower() and mc:
                        clear_conversation_model(chat_id, model_name)
                        mc = None
                        conv = {}
                        response_text = ""
                        reasoning_text = ""
                        log("WARN", f"[{jar.get('name')}] stale Arena thread/model binding cleared — rebuilding as create-evaluation")
                        if attempt + 1 < max_attempts:
                            continue

                    if resp.status_code == 400 and "user message is invalid" in body.lower() and mc:
                        clear_conversation_model(chat_id, model_name)
                        mc = None
                        conv = {}
                        response_text = ""
                        reasoning_text = ""
                        log("WARN", f"[{jar.get('name')}] follow-up envelope rejected — rebuilding once as create-evaluation")
                        if attempt + 1 < max_attempts:
                            continue

                    if verdict == "CHALLENGE":
                        if cf_clear_attempts < 1 and keeper.sessions.get(jar.get("id")):
                            cf_clear_attempts += 1
                            try:
                                s_ = keeper.sessions[jar["id"]]
                                await s_.restart()
                                s_.last_harvest_time = 0
                            except Exception:
                                pass
                            jar = await _live_cookies(jar)
                            continue
                        if proxy and attempt + 1 < max_attempts:
                            note_cf_blocked_exit(proxy, "persistent 403 challenge after keeper re-clear")
                            if mc:
                                yield ("error", "403: This thread's bound exit is Arena-blocked. Start a new Bridgena thread to select another healthy exit.")
                                return
                            continue
                        yield ("error", "502: Arena's Cloudflare flagged every exit we tried — retry shortly or add residential lines.")
                        return

                    if verdict == "RECAPTCHA":
                        failed_jar_id = jar.get("id")
                        _captcha_failed_jars[failed_jar_id] = time.time()
                        if rc_attempts.get(failed_jar_id, 0) < 1:
                            rc_attempts[failed_jar_id] = rc_attempts.get(failed_jar_id, 0) + 1
                            reason = ("server requested V2 escalation"
                                      if resp.status_code == 429 and "prompt failed" in body.lower()
                                      else "V3 verification rejected")
                            log("WARN", f"[{jar.get('name')}] {reason} (HTTP {resp.status_code}) — starting Enterprise V2 challenge")
                            esc = await mint_v2_escalation(failed_jar_id, settle_s=20.0)
                            if esc:
                                _attach_v2(base, esc)
                                log("OK", f"[{jar.get('name')}] V2 token harvested ({len(esc)} chars) — retrying SAME jar with V2 only")
                                continue
                        if mc:
                            clear_conversation_model(chat_id, model_name)
                            mc = None
                            conv = {}
                            response_text = ""
                            reasoning_text = ""
                        # Verification rejection is intentionally NOT a
                        # cross-account failover condition. Keep recovery local
                        # and non-destructive.
                        _mark_api_keeper_unready(
                            failed_jar_id,
                            "verification rejection; local readiness recovery requested",
                        )
                        try:
                            _api_keeper_quarantine_until.pop(str(failed_jar_id), None)
                            _verification_preflight_retry_after.pop(str(failed_jar_id), None)
                            _schedule_transport_recovery(
                                str(failed_jar_id),
                                "post-rejection local keeper recovery",
                            )
                            _wake_verification_scheduler()
                        except Exception:
                            pass
                        log("WARN", f"[{jar.get('name')}] verification unresolved — keeper retained; local recovery started")
                        yield ("error", "503: Arena rejected verification for this request. "
                                        "The keeper was retained and local readiness recovery was started; "
                                        "no cross-account replay was attempted.")
                        return

                    if verdict == "PROMPT":
                        log("WARN", f"[{jar.get('name')}] Arena rejected prompt before streaming — no retry or rotation")
                        yield ("error", "422: Arena rejected this prompt before generation. Bridgena did not retry or rotate accounts; shorten the request or remove unsupported tool/system payloads.")
                        return

                    if verdict == "RATELIMIT":
                        explicit_retry = _parse_retry_after_seconds(
                            (resp.headers or {}).get("retry-after", "")
                            if getattr(resp, "headers", None) is not None else ""
                        )
                        cooldown = _mark_model_rate_limited(model_name, explicit_retry)
                        retry_after = max(1, int(cooldown + 0.999))
                        log("WARN", f"[{jar.get('name')}] upstream prompt throttle · "
                                    f"cooldown {cooldown:.1f}s · same-account only")
                        continuity = load_context_capsule(chat_id, model_name)
                        arm_throttle_thread_rehome(
                            chat_id, model_name, str(jar.get("id") or ""),
                            cooldown, continuity,
                        )
                        yield ("retry-same-account", {
                            "jar_id": jar.get("id"),
                            "jar_name": jar.get("name"),
                            "delay": cooldown,
                            "reason": "definitive HTTP 429 from curl transport",
                            "rehome_thread": True,
                        })
                        return

                    if verdict == "UPSTREAM":
                        note_upstream_degraded(str(resp.status_code))
                        await asyncio.sleep(2.5 * (attempt + 1))
                        continue

                    if verdict == "SESSION":
                        jar = await _live_cookies(jar)
                        if jar_has_auth(jar) and attempt == 0:
                            continue
                        mark_jar_status(jar["id"], "expired")
                        if mc:
                            yield ("error", "409: This Arena thread's original session expired. Start a new Bridgena thread.")
                            return
                        nxt = acquire_jar(prefer_live=True, exclude=tried)
                        if nxt and nxt["id"] not in tried:
                            log("WARN", f"session expired — rotating to '{nxt.get('name')}'")
                            jar, _ = nxt, tried.add(nxt["id"])
                            continue
                        yield ("error", "502: Arena session expired — no other healthy accounts left")
                        return

                    yield ("error", f"{resp.status_code}: {body[:400] or '(empty body)'}")
                    return

                # ---------- 200: heal caches, stream ----------
                _upstream_hits.clear()
                if proxy:
                    ms = int((time.monotonic() - t0) * 1000)
                    if 0 < ms < 60000:
                        _proxy_latency[proxy] = ms
                        _proxy_probe_cache[proxy] = (True, time.time() + PROBE_OK_TTL)
                        _proxy_health_record(proxy, True, ms, source="stream")
                    _flagged_exits.pop(_proxy_hkey(proxy), None)
                buffer = b""
                async for chunk in resp.aiter_content():
                    if not chunk:
                        continue
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8", "ignore")
                    buffer += chunk
                    while b"\n" in buffer:
                        lb, buffer = buffer.split(b"\n", 1)
                        ev = _parse_stream_line(lb.decode("utf-8", "ignore").strip())
                        if not ev:
                            continue
                        kind, payload = ev
                        if kind == "content" and isinstance(payload, str):
                            response_text += payload
                            yield ("content", payload)
                        elif kind == "reasoning":
                            t = payload if isinstance(payload, str) else json.dumps(payload)
                            reasoning_text += t
                            yield ("reasoning", t)
                        elif kind == "error":
                            yield ("error", str(payload))
                            return
                if buffer.strip():
                    ev = _parse_stream_line(buffer.decode("utf-8", "ignore").strip())
                    if ev:
                        kind, payload = ev
                        if kind == "content" and isinstance(payload, str):
                            response_text += payload
                            yield ("content", payload)
                        elif kind == "reasoning":
                            t = payload if isinstance(payload, str) else json.dumps(payload)
                            reasoning_text += t
                            yield ("reasoning", t)
                        elif kind == "error":
                            yield ("error", str(payload))
                            return
                if not response_text and reasoning_text:
                    response_text = reasoning_text
                    yield ("content", reasoning_text)
                if not response_text:
                    log("WARN", f"[{jar.get('name')}] Arena returned HTTP 200 but no decodable text frames for {model_name}")
                    yield ("error", "502: Arena completed the stream without a text response. The model may be unavailable or using an unsupported event format.")
                    return
                # remember the conversation for follow-ups
                if not follow_url:
                    conv2 = dict(conv)
                    conv2["model"] = model_name
                    conv2["arena"] = dict(conv2.get("arena") or {})
                    conv2["arena"][model_name] = {
                        "arena_id": base["id"], "mode": "direct",
                        "jar_id": jar.get("id"), "proxy": proxy,
                    }
                    save_conversation(chat_id, conv2)
                yield ("done", response_text)
                return
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log("ERROR", f"arena engine unexpected: {type(e).__name__}: {e}")
            yield ("error", f"500: bridge error: {type(e).__name__}: {e}")
            return
    yield ("error", "503: exhausted attempt budget across exits — nothing exiled; try 'Scan pool'")


# ────────────────────────── module: pages.py ──────────────────────────────

# ============================================================
# v2 PAGES — the "Bridgena Operations" design system.
# Authored here (no framework, no blob): build-time CSS, injected inline,
# works on partial deploys and offline browsers. Dark-first, light via
# [data-theme=light]. Grid texture + hairline glow, Space Grotesk display,
# IBM Plex Mono for anything a machine produced.
# ============================================================
import html as _html
import json as _json
import time

def esc(s) -> str:
    return _html.escape(str(s), quote=True)


CSS = """
:root{
  --bg:#0B0E14; --bg2:#0E1220; --panel:#11151F; --panel2:#151A27; --hair:rgba(255,255,255,.07);
  --ink:#E8ECF4; --ink2:#8A93A6; --ink3:#5A6377;
  --amber:#FFB454; --amber-ink:#221603; --teal:#3BD6B4; --red:#FF6B6B; --blue:#7AA2FF;
  --ok:var(--teal); --warn:var(--amber); --bad:var(--red);
  --r-lg:14px; --r-md:10px; --r-sm:7px;
  --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --disp:'Space Grotesk','Inter',system-ui,sans-serif;
  --grid:repeating-linear-gradient(90deg,rgba(255,255,255,.024) 0 1px,transparent 1px 44px),
         repeating-linear-gradient(0deg,rgba(255,255,255,.024) 0 1px,transparent 1px 44px);
}
[data-theme=light]{
  --bg:#F4F5F8; --bg2:#FFFFFF; --panel:#FFFFFF; --panel2:#F7F8FB; --hair:rgba(15,20,32,.10);
  --ink:#141926; --ink2:#5A6377; --ink3:#9AA3B5;
  --amber:#B4690E; --amber-ink:#FFF7EA; --teal:#0C7F63; --red:#C03A3A; --blue:#2D5BD6;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:15px/1.55 var(--disp);-webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;background:var(--grid);pointer-events:none;z-index:0}
::selection{background:color-mix(in srgb,var(--amber) 30%,transparent)}
a{color:var(--amber);text-decoration:none} a:hover{text-decoration:underline}
.topbar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:14px;padding:10px 22px;
  background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(14px);border-bottom:1px solid var(--hair)}
.brand{display:flex;align-items:baseline;gap:9px;font-weight:700;letter-spacing:.4px}
.brand .dot{width:9px;height:9px;border-radius:50%;background:var(--amber);box-shadow:0 0 14px var(--amber);align-self:center}
.brand small{font:500 11px var(--mono);color:var(--ink3);letter-spacing:1px;text-transform:uppercase}
.spacer{flex:1}
.chip{font:500 11px/1 var(--mono);letter-spacing:.6px;text-transform:uppercase;color:var(--ink2);
  border:1px solid var(--hair);border-radius:999px;padding:6px 11px;background:var(--panel)}
.chip.live{color:var(--teal);border-color:color-mix(in srgb,var(--teal) 35%,transparent)}
.btn{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--hair);background:var(--panel);color:var(--ink);
  font:600 13px var(--disp);padding:8px 14px;border-radius:var(--r-sm);cursor:pointer;transition:transform .06s ease,background .15s,border-color .15s}
.btn:hover{background:var(--panel2);border-color:color-mix(in srgb,var(--ink3) 40%,transparent)}
.btn:active{transform:translateY(1px)}
.btn.primary{background:var(--amber);color:var(--amber-ink);border-color:transparent}
.btn.primary:hover{filter:brightness(1.07)}
.btn.danger{color:var(--red);border-color:color-mix(in srgb,var(--red) 34%,transparent)}
.btn.ghost{background:transparent}
.btn.sm{padding:5px 10px;font-size:12px}
.btn:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
input,textarea,select{background:var(--bg2);border:1px solid var(--hair);border-radius:var(--r-sm);color:var(--ink);
  font:400 14px/1.5 var(--mono);padding:9px 12px;width:100%}
textarea{resize:vertical;min-height:96px}
label{display:block;font:600 11px var(--mono);letter-spacing:1.2px;text-transform:uppercase;color:var(--ink2);margin:14px 0 6px}
.card{position:relative;background:var(--panel);border:1px solid var(--hair);border-radius:var(--r-lg);padding:20px}
.card::before{content:"";position:absolute;inset:0 0 auto;border-radius:var(--r-lg) var(--r-lg) 0 0;height:1px;
  background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--amber) 55%,transparent) 30%,color-mix(in srgb,var(--teal) 45%,transparent) 60%,transparent)}
.card h3{margin:0 0 14px;font:600 15px var(--disp);display:flex;align-items:center;gap:9px}
.grid{display:grid;gap:16px}
.metrics{grid-template-columns:repeat(4,1fr)}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(2,1fr)}}
.metric{padding:16px 18px}
.metric .k{font:500 11px var(--mono);letter-spacing:1.2px;text-transform:uppercase;color:var(--ink2)}
.metric .v{font:700 34px/1.1 var(--disp);margin-top:6px;font-variant-numeric:tabular-nums}
.metric .s{font:400 12px var(--mono);color:var(--ink3);margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{font:600 11px var(--mono);text-transform:uppercase;letter-spacing:1px;color:var(--ink2);text-align:left;padding:8px 10px;border-bottom:1px solid var(--hair)}
td{padding:8px 10px;border-bottom:1px solid color-mix(in srgb,var(--hair) 55%,transparent);font-variant-numeric:tabular-nums}
tr:hover td{background:color-mix(in srgb,var(--panel2) 60%,transparent)}
td .mono,.mono{font-family:var(--mono);font-size:12.5px}
.pill{display:inline-block;font:600 10.5px var(--mono);letter-spacing:.8px;text-transform:uppercase;
  padding:3px 9px;border-radius:999px;border:1px solid transparent}
.pill.ok{color:var(--teal);background:color-mix(in srgb,var(--teal) 12%,transparent);border-color:color-mix(in srgb,var(--teal) 30%,transparent)}
.pill.warn{color:var(--amber);background:color-mix(in srgb,var(--amber) 12%,transparent);border-color:color-mix(in srgb,var(--amber) 30%,transparent)}
.pill.bad{color:var(--red);background:color-mix(in srgb,var(--red) 12%,transparent);border-color:color-mix(in srgb,var(--red) 30%,transparent)}
.pill.idle{color:var(--ink2);border-color:var(--hair)}
.bar{height:5px;border-radius:3px;background:var(--panel2);overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;background:linear-gradient(90deg,var(--teal),var(--amber))}
.dotlive{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--teal);box-shadow:0 0 0 0 color-mix(in srgb,var(--teal) 60%,transparent);animation:pulse 2.2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--teal) 55%,transparent)}70%{box-shadow:0 0 0 7px transparent}100%{box-shadow:0 0 0 0 transparent}}
.console{background:#07090E;border:1px solid var(--hair);border-radius:var(--r-md);padding:12px 14px;height:340px;overflow:auto;
  font:400 12px/1.75 var(--mono);color:#C7D0E0}
[data-theme=light] .console{background:#10131B}
.console .WARN{color:var(--amber)} .console .ERROR{color:var(--red)} .console .OK{color:var(--teal)}
.shell{display:grid;grid-template-columns:216px 1fr;min-height:calc(100vh - 49px);position:relative;z-index:1}
.rail{border-right:1px solid var(--hair);padding:22px 12px;display:flex;flex-direction:column;gap:4px}
.rail a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r-sm);color:var(--ink2);font:600 13px var(--disp)}
.rail a:hover{background:var(--panel);color:var(--ink);text-decoration:none}
.rail a.on{background:var(--panel2);color:var(--ink)} .rail a.on::before{content:"";width:3px;height:16px;border-radius:2px;background:var(--amber);margin-left:-6px}
.main{padding:26px 30px;max-width:1280px;width:100%}
.pagehead{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:20px}
.pagehead h1{margin:0;font-size:26px;letter-spacing:-.4px}
.pagehead p{margin:4px 0 0;color:var(--ink2);font-size:13.5px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.split{display:grid;grid-template-columns:1.5fr 1fr;gap:16px}
@media(max-width:1000px){.split{grid-template-columns:1fr}}
/* login */
.authwrap{min-height:100vh;display:grid;grid-template-columns:1.1fr .9fr;position:relative;z-index:1}
@media(max-width:900px){.authwrap{grid-template-columns:1fr}.authplate{display:none}}
.authplate{display:flex;flex-direction:column;justify-content:space-between;padding:44px;border-right:1px solid var(--hair)}
.authplate .big{font:700 40px/1.15 var(--disp);letter-spacing:-1px;max-width:16ch}
.authplate .big em{font-style:normal;color:var(--amber)}
.authside{display:flex;align-items:center;justify-content:center;padding:32px}
.authcard{width:min(420px,100%)}
.err{color:var(--red);font:500 13px var(--mono);min-height:18px;margin-top:10px}
/* chat */
.chatgrid{display:grid;grid-template-columns:250px 1fr 340px;height:calc(100vh - 49px);min-height:0}
@media(max-width:1180px){.chatgrid{grid-template-columns:1fr}.chatrail,.chatside{display:none}}
.chatside{border-right:1px solid var(--hair);padding:14px;display:flex;flex-direction:column;gap:8px;overflow:auto}
.chatside .chatitem{padding:9px 11px;border-radius:var(--r-sm);cursor:pointer;color:var(--ink2);font:500 13px var(--disp);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border:1px solid transparent}
.chatside .chatitem:hover{background:var(--panel)} .chatside .chatitem.on{background:var(--panel2);color:var(--ink);border-color:var(--hair)}
.chatmain{display:flex;flex-direction:column;min-width:0}
.transcript{flex:1;overflow:auto;padding:26px 8%;display:flex;flex-direction:column;gap:16px}
.bubble{max-width:78%;padding:12px 16px;border-radius:14px;font-size:15px;line-height:1.6;white-space:pre-wrap;word-wrap:break-word}
.bubble.user{align-self:flex-end;background:color-mix(in srgb,var(--amber) 14%,var(--panel));border:1px solid color-mix(in srgb,var(--amber) 26%,transparent);border-bottom-right-radius:4px}
.bubble.ai{align-self:flex-start;background:var(--panel);border:1px solid var(--hair);border-bottom-left-radius:4px}
.bubble.ai .who,.bubble.user .who{display:block;font:600 10px var(--mono);letter-spacing:1.2px;text-transform:uppercase;color:var(--ink3);margin-bottom:6px}
.bubble pre{background:#07090E;border:1px solid var(--hair);border-radius:8px;padding:10px 12px;overflow:auto;font:400 12.5px/1.6 var(--mono)}
.bubble pre code{background:transparent;padding:0;color:inherit}
.bubble code{background:var(--panel2);border:1px solid var(--hair);border-radius:4px;padding:1px 5px;font:400 13px var(--mono)}
.composer{border-top:1px solid var(--hair);padding:14px 8% 18px;display:flex;gap:10px;align-items:flex-end;background:color-mix(in srgb,var(--bg) 70%,transparent)}
.composer textarea{min-height:48px;max-height:180px}
.chatrail{border-left:1px solid var(--hair);display:flex;flex-direction:column;padding:14px;gap:12px;overflow:auto}
.kv{display:flex;justify-content:space-between;font:400 12.5px var(--mono);color:var(--ink2);padding:5px 0;border-bottom:1px dashed color-mix(in srgb,var(--hair) 70%,transparent)}
.kv b{color:var(--ink);font-weight:600}
select.model{appearance:none}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(80px);background:var(--panel2);border:1px solid var(--hair);
  border-radius:999px;padding:10px 18px;font:500 13px var(--disp);opacity:0;transition:.25s;z-index:99;box-shadow:0 10px 40px rgba(0,0,0,.4)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.muted{color:var(--ink3)} .small{font-size:12.5px}
"""

# shadcn/ui zinc tokens and component geometry, compiled into the single-file
# server build. shadcn components are source-owned rather than a runtime CDN;
# these overrides keep the deployment self-contained while applying the same
# primitives consistently across login, operations, tables, forms and logs.
CSS += """
:root{--bg:#09090b;--bg2:#09090b;--panel:#0c0c0e;--panel2:#18181b;--hair:#27272a;
 --ink:#fafafa;--ink2:#a1a1aa;--ink3:#71717a;--amber:#fafafa;--amber-ink:#09090b;
 --teal:#4ade80;--red:#f87171;--blue:#a1a1aa;--r-lg:10px;--r-md:8px;--r-sm:7px;
 --disp:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
 --mono:"SFMono-Regular",Consolas,"Liberation Mono",monospace;--grid:none}
[data-theme=light]{--bg:#fff;--bg2:#fff;--panel:#fff;--panel2:#f4f4f5;--hair:#e4e4e7;
 --ink:#09090b;--ink2:#71717a;--ink3:#a1a1aa;--amber:#18181b;--amber-ink:#fafafa;
 --teal:#16a34a;--red:#dc2626;--blue:#71717a}
body{letter-spacing:-.005em}body::before{display:none}a{color:inherit}
.topbar{height:57px;padding:0 20px;background:color-mix(in srgb,var(--bg) 92%,transparent);border-color:var(--hair);backdrop-filter:blur(16px)}
.brand{font-size:14px;letter-spacing:-.02em}.brand .dot{width:22px;height:22px;border-radius:7px;background:var(--ink);box-shadow:none;position:relative}
.brand .dot::after{content:"B";position:absolute;inset:0;display:grid;place-items:center;color:var(--bg);font-size:10px;font-weight:800}
.brand small{font-family:var(--mono);font-size:10px;letter-spacing:0;color:var(--ink3);text-transform:none}
.chip{font:500 11px var(--disp);letter-spacing:0;text-transform:none;padding:5px 9px;background:transparent}.dotlive{width:6px;height:6px;box-shadow:none;animation:none}
.btn{min-height:36px;padding:7px 12px;background:var(--bg);border-color:var(--hair);font:500 13px var(--disp);border-radius:7px;box-shadow:0 1px 2px rgba(0,0,0,.14)}
.btn:hover{background:var(--panel2);border-color:var(--hair);text-decoration:none}.btn.primary{background:var(--ink);color:var(--bg);border-color:var(--ink)}
.btn.ghost{box-shadow:none;background:transparent}.btn.sm{min-height:32px;padding:5px 9px}
input,textarea,select{background:var(--bg);border-color:var(--hair);font:400 13px/1.5 var(--disp);border-radius:7px;min-height:38px}
label{font:500 13px var(--disp);letter-spacing:0;text-transform:none;color:var(--ink);margin:15px 0 6px}
.shell{grid-template-columns:232px minmax(0,1fr);min-height:calc(100vh - 57px)}
.rail{background:var(--panel);padding:18px 10px;border-color:var(--hair);gap:2px}.rail::before{content:"Workspace";padding:0 10px 10px;color:var(--ink3);font-size:11px;font-weight:500}
.rail a{padding:8px 10px;border-radius:7px;color:var(--ink2);font:500 13px var(--disp)}.rail a:hover{background:var(--panel2);color:var(--ink)}
.rail a.on{background:var(--panel2);color:var(--ink)}.rail a.on::before{display:none}
.main{max-width:1480px;padding:32px 36px 60px}.pagehead{align-items:center;margin-bottom:24px}.pagehead h1{font-size:24px;letter-spacing:-.035em;font-weight:650}.pagehead p{font-size:13px}
.grid{gap:12px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.card{background:var(--panel);border-color:var(--hair);border-radius:10px;padding:18px;box-shadow:0 1px 2px rgba(0,0,0,.08)}
.card::before{display:none}.card h3{font:600 14px var(--disp);letter-spacing:-.01em}.metric{padding:17px}.metric .k{font:500 12px var(--disp);letter-spacing:0;text-transform:none;color:var(--ink2)}
.metric .v{font:650 29px/1.15 var(--disp);letter-spacing:-.04em;margin-top:13px}.metric .s{font:400 11px var(--disp);margin-top:5px}
th{font:500 11px var(--disp);letter-spacing:0;text-transform:none;color:var(--ink3);padding:9px 10px}td{font-size:13px;padding:10px;border-color:var(--hair)}tr:hover td{background:var(--panel2)}
.pill{font:550 10px var(--disp);letter-spacing:0;text-transform:none;padding:3px 8px}.bar{background:var(--panel2)}.bar i{background:var(--ink)}
.console{background:#050506;border-color:var(--hair);font:400 11px/1.7 var(--mono);color:#d4d4d8;border-radius:8px}
[data-theme=light] .console{background:#fafafa;color:#27272a}.split{gap:12px}
.authwrap{display:block;background:var(--bg)}.authplate{display:none}.authside{min-height:100vh;padding:24px}.authcard{width:min(390px,100%);background:transparent;border:0;box-shadow:none;padding:24px}
.authcard::before{display:none}.authcard::after{content:"Access the Bridgena control plane";display:block;color:var(--ink3);font-size:12px;text-align:center;margin-top:18px}
.authcard h3{font-size:23px;justify-content:center;letter-spacing:-.035em;margin-bottom:26px}.err{text-align:center;font-family:var(--disp);font-size:12px}
@media(max-width:900px){.shell{grid-template-columns:1fr}.rail{display:none}.main{padding:24px 16px}.metrics{grid-template-columns:repeat(2,1fr)}}
@media(max-width:560px){.metrics{grid-template-columns:1fr}.topbar .chip,.topbar .brand small{display:none}.pagehead{align-items:flex-start;flex-direction:column}}
"""

# v2.16 visual pass — quieter Vercel-like surfaces, stronger hierarchy and
# denser operational information without changing any dashboard behavior.
CSS += """
:root{--shadow-sm:0 1px 2px rgba(0,0,0,.18);--shadow-lg:0 20px 55px rgba(0,0,0,.24)}
html{background:var(--bg)}body{min-height:100vh;background:
 radial-gradient(900px 440px at 64% -180px,color-mix(in srgb,var(--ink) 5%,transparent),transparent 70%),var(--bg)}
.topbar{height:64px;padding:0 24px;border-bottom:1px solid color-mix(in srgb,var(--hair) 82%,transparent)}
.brand{gap:10px}.brand .dot{width:28px;height:28px;border-radius:9px}.brand .dot::after{font-size:11px}
.brand small{padding-left:2px}.chip.live{border:0;background:color-mix(in srgb,var(--teal) 9%,transparent);color:var(--teal);padding:6px 10px}
.shell{grid-template-columns:248px minmax(0,1fr);min-height:calc(100vh - 64px)}
.rail{position:sticky;top:64px;height:calc(100vh - 64px);padding:20px 12px;background:color-mix(in srgb,var(--panel) 76%,transparent)}
.rail::before{padding:0 12px 12px;text-transform:uppercase;letter-spacing:.08em;font-size:10px}
.rail a{min-height:38px;padding:9px 12px;border-radius:8px}.rail a.on{box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--hair) 76%,transparent)}
.main{padding:40px 44px 72px;max-width:1560px}.pagehead{margin-bottom:28px}.pagehead h1{font-size:28px;font-weight:680;letter-spacing:-.045em}.pagehead p{margin-top:6px;color:var(--ink2)}
.card{border-color:color-mix(in srgb,var(--hair) 78%,transparent);border-radius:12px;box-shadow:var(--shadow-sm);background:color-mix(in srgb,var(--panel) 94%,transparent)}
.metric{min-height:126px;display:flex;flex-direction:column;justify-content:space-between}.metric .v{font-size:34px}.metric .s{color:var(--ink3)}
.btn{border-radius:8px;transition:background .15s,border-color .15s,transform .12s,box-shadow .15s}.btn:hover{box-shadow:0 1px 4px rgba(0,0,0,.16)}
table{border-spacing:0}th{height:40px}td{height:46px}.console{height:390px;box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}
@media(max-width:900px){.topbar{padding:0 14px}.main{padding:28px 18px 56px}.shell{grid-template-columns:1fr}}
"""

# v2.33 control-plane redesign: one restrained visual language shared with
# chat, with Open WebUI density and Vercel-style operational hierarchy.
CSS += """
:root{--bg:#080808;--bg2:#0b0b0b;--panel:#0d0d0d;--panel2:#151515;--hair:#252525;
 --ink:#f5f5f5;--ink2:#a3a3a3;--ink3:#666;--teal:#34d399;--amber:#fbbf24;--red:#fb7185}
[data-theme=light]{--bg:#fff;--bg2:#fff;--panel:#fff;--panel2:#f7f7f7;--hair:#e7e7e7;
 --ink:#111;--ink2:#666;--ink3:#9a9a9a;--teal:#059669;--amber:#b45309;--red:#e11d48}
body{background:var(--bg)}.topbar{height:62px;padding:0 26px;background:color-mix(in srgb,var(--bg) 94%,transparent)}
.topbar .brand .dot{border:1px solid var(--hair);background:var(--ink);box-shadow:0 0 0 4px color-mix(in srgb,var(--ink) 5%,transparent)}
.shell{grid-template-columns:238px minmax(0,1fr);min-height:calc(100vh - 62px)}
.rail{top:62px;height:calc(100vh - 62px);padding:20px 10px;background:var(--bg);border-color:var(--hair)}
.rail::before{content:"Control plane"}.rail a{font-size:13px;min-height:40px;padding:10px 12px;color:var(--ink2)}
.rail a.on{background:var(--panel2);box-shadow:none;color:var(--ink)}
.main{max-width:1440px;padding:42px 48px 80px}.pagehead{padding-bottom:22px;border-bottom:1px solid var(--hair)}
.pagehead h1{font-size:30px}.pagehead p{font-size:13px;max-width:680px}.metrics{gap:14px}
.card{background:var(--panel);border-radius:12px;box-shadow:none}.card:hover{border-color:color-mix(in srgb,var(--hair) 65%,var(--ink3))}
.metric{min-height:142px;padding:20px}.metric .k{display:flex;align-items:center;gap:8px}.metric .k::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ink3)}
.metric:nth-child(1) .k::before,.metric:nth-child(3) .k::before{background:var(--teal)}
.metric:nth-child(2) .k::before{background:var(--amber)}.metric .v{font-size:38px;margin-top:18px}
.btn{border-radius:8px;box-shadow:none}.btn.primary{background:var(--ink);color:var(--bg)}
.console{background:#050505;border-radius:10px}.split{grid-template-columns:minmax(0,1.35fr) minmax(360px,.65fr);gap:14px}
@media(max-width:1050px){.split{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
@media(max-width:900px){.shell{grid-template-columns:1fr}.main{padding:28px 18px 60px}}
@media(max-width:560px){.metrics{grid-template-columns:1fr}.main{padding-inline:14px}.pagehead{border-bottom:0}}
"""

JS_THEME = """
(function(){try{var t=localStorage.getItem('bgn.theme');if(t)document.documentElement.dataset.theme=t;}catch(e){}})();
function bgnToggleTheme(){var h=document.documentElement;var n=(h.dataset.theme==='light')?'':'light';h.dataset.theme=n;try{localStorage.setItem('bgn.theme',n)}catch(e){}}
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show')},2600)}
"""


def page(title: str, body: str, active: str = "", *, raw_js: str = "", wide=False) -> str:
    nav = ""
    if active or title:
        items = [("Dashboard", "/dashboard", "dash"), ("Proxy Pool", "/pool", "pool"),
                 ("Accounts", "/jars", "jars"), ("Models", "/models-page", "models"),
                 ("API Keys", "/api-keys", "keys"),
                 ("Live Chat", "/chat", "chat"), ("Errors", "/errors", "errors"),
                 ("Logs", "/logs", "logs")]
        nav = '<div class="rail">' + "".join(
            f'<a href="{href}" class="{"on" if k==active else ""}">{lbl}</a>' for lbl, href, k in items) + "</div>"
    main_open = '<div class="shell">' + nav + '<div class="main">' + body + "</div></div>"
    content = main_open if nav else body
    wide_style = ' style="margin:0 auto;padding-top:26px;max-width:1280px"' if (not nav and not wide) else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Bridgena</title>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body>
<header class="topbar"><div class="brand"><span class="dot"></span>Bridgena <small id="build">{esc(BUILD_STAMP)}</small></div>
<div class="spacer"></div>
<span class="chip live"><span class="dotlive"></span>&nbsp;live</span>
<button class="btn sm ghost" onclick="bgnToggleTheme()" title="Toggle theme">◐ theme</button>
<a class="btn sm ghost" href="/logout">sign out</a></header>
<div{wide_style}>
{content}
</div>
<div id="toast-stack" class="toast-stack"></div>
<script>{JS_THEME}{raw_js}</script></body></html>"""


def login_page(err: str = "") -> str:
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · Bridgena</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body><div class="authwrap">
<div class="authplate"><div class="brand"><span class="dot"></span>Bridgena <small>operations</small></div>
  <div><div class="big">The control room for your <em>Arena fleet</em>.</div>
  <p class="muted small" style="margin-top:14px;max-width:40ch">Keeper sessions, per-exit verdicts, recaptcha protocol, one file to run.</p></div>
  <p class="muted mono" style="font-size:11px">{esc(BUILD_STAMP)}</p></div>
<div class="authside"><form class="card authcard" method="post" action="/login">
  <h3>Sign in</h3><label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" placeholder="••••••••">
  <button class="btn primary" style="width:100%;justify-content:center;margin-top:18px">Enter →</button>
  <div class="err">{esc(err)}</div>
  <button type="button" class="btn sm ghost" style="position:absolute;top:14px;right:14px" onclick="bgnToggleTheme()">◐</button>
</form></div></div><script>{JS_THEME}</script></body></html>"""


def _verdict_pill(v: str) -> str:
    cls = {"alive": "ok", "arena-blocked": "warn", "dead": "bad", "unreachable": "bad", "unknown": "idle"}.get(v, "idle")
    return f'<span class="pill {cls}">{esc(v)}</span>'


def dashboard_page(overview: dict) -> str:
    rows_pool = "".join(
        f"<tr><td class=mono>{esc(r['display'])}</td><td>{_verdict_pill(r['verdict'])}</td>"
        f"<td>{esc(r['why']) or '<span class=muted>—</span>'}</td>"
        f"<td><div class=bar><i style='width:{min(100, int((r['latency'] or 1200)/12))}%'></i></div></td></tr>"
        for r in overview["pool"][:8]) or '<tr><td colspan=4 class=muted>No pool lines — go to Proxy Pool.</td></tr>'
    jrows = "".join(
        f"<tr><td>{esc(j['name'])}</td><td><span class='mono' style='font-size:12px'>{esc(j.get('persona','—'))}</span></td>"
        f"<td>{'<span class=pill ok>live</span>' if j['id'] in overview['live_ids'] else '<span class=pill idle>dark</span>'}</td>"
        f"<td>{_verdict_pill('alive' if j['ok'] else ('warn' and 'arena-blocked' if j.get('limited') else 'dead'))}</td></tr>"
        for j in overview["jars"]) or '<tr><td colspan=4 class=muted>No jars yet.</td></tr>'
    m = overview["metrics"]
    logl = "".join(f'<div class="{esc(x["lvl"])}">{esc(x["line"])}</div>' for x in overview["logtail"])
    return page("Dashboard", f"""
<div class="pagehead"><div><span class="pill ok" style="margin-bottom:12px">All systems monitored</span><h1>Bridgena Control Plane</h1><p>Live infrastructure, keeper health, model availability, and verified exit telemetry in one workspace.</p></div>
<div class="row"><button class="btn" onclick="act('/proxies/api/check','POST')">Run network scan</button>
<button class="btn primary" onclick="location='/chat'">Launch chat&nbsp; ↗</button></div></div>
<div class="grid metrics">
 <div class="card metric"><div class="k">Verified exits</div><div class="v" style="color:var(--teal)">{m['alive']}<span class="muted" style="font-size:18px"> / {m['pool_total']}</span></div><div class="s">TLS and upstream response confirmed</div></div>
 <div class="card metric"><div class="k">Restricted exits</div><div class="v" style="color:var(--amber)">{m['flagged']}</div><div class="s">Temporarily held outside rotation</div></div>
 <div class="card metric"><div class="k">Account fleet</div><div class="v">{m['jars_ok']}<span class="muted" style="font-size:18px"> / {m['jars_total']}</span></div><div class="s">{m['keepers_live']} browser keepers currently live</div></div>
 <div class="card metric"><div class="k">Available models</div><div class="v">{m['models']}</div><div class="s">Published through the unified API</div></div></div>
<div class="split" style="margin-top:16px">
 <div class="card"><h3>Network health <span class="spacer"></span><a class="small" href="/pool">View all ↗</a></h3>
  <table><thead><tr><th>exit</th><th>verdict</th><th>why</th><th>latency</th></tr></thead><tbody>{rows_pool}</tbody></table></div>
 <div class="card"><h3>Keeper fleet <a class="spacer" style="flex:1"></a><a class="small" href="/jars">Manage ↗</a></h3>
  <table><thead><tr><th>jar</th><th>device persona</th><th>keeper</th><th>health</th></tr></thead><tbody>{jrows}</tbody></table></div>
</div>
<div class="card" style="margin-top:16px"><h3>Runtime activity <span class="spacer" style="flex:1"></span><span class="mono small muted">live tail</span></h3>
  <div class="console" id="cons">{logl}</div></div>""", active="dash", raw_js="""
async function act(u,method){try{const r=await fetch(u,{method:method||'GET'});toast('done: '+(await r.text()).slice(0,80))}catch(e){toast('error: '+e)}}
function consRefresh(){fetch('/debug-logs/data').then(r=>r.json()).then(d=>{var c=document.getElementById('cons');if(!c)return;
 c.innerHTML=d.map(x=>'<div class="'+(x.lvl||'INFO')+'">'+(x.line||x.message||'')+'</div>').join('');c.scrollTop=c.scrollHeight;}).catch(()=>{})}
setInterval(consRefresh,4000);""")


def api_keys_page(records: list) -> str:
    rows = "".join(
        f"<tr><td><b>{esc(record.get('name') or 'Unnamed key')}</b></td>"
        f"<td class=mono>{esc(record.get('prefix') or 'sk-void-…')}••••••</td>"
        f"<td>{int(record.get('rpm') or 60)} RPM</td>"
        f"<td>{time.strftime('%Y-%m-%d %H:%M', time.localtime(record.get('created') or 0)) if record.get('created') else '—'}</td>"
        f"<td><form method=post action=/delete-key onsubmit=\"return confirm('Revoke this API key?')\">"
        f"<input type=hidden name=key_id value=\"{esc(record.get('id') or '')}\">"
        f"<button class='btn sm' type=submit>Revoke</button></form></td></tr>"
        for record in records if isinstance(record, dict)
    ) or '<tr><td colspan=5 class=muted>No API keys yet.</td></tr>'
    return page("API Keys", f"""
<div class=pagehead><div><h1>API Keys</h1><p>Create credentials for OpenAI-compatible clients. Secrets are displayed once.</p></div></div>
<div class=split>
 <div class=card><h3>Create key</h3>
  <form method=post action=/create-key>
   <label for=key-name>Name</label><input id=key-name name=name required maxlength=80 placeholder="Windows stream test">
   <label for=key-rpm>Rate limit</label><input id=key-rpm name=rpm type=number min=1 max=1000 value=60 required>
   <button class='btn primary' type=submit style='margin-top:16px'>Generate API key</button>
  </form>
 </div>
 <div class=card><h3>Security</h3><p class=muted>Only a SHA-256 verifier and short prefix are stored. Copy a new secret before leaving its confirmation page. Revocation takes effect immediately.</p></div>
</div>
<div class=card style='margin-top:16px'><h3>Active keys</h3>
 <table><thead><tr><th>Name</th><th>Prefix</th><th>Limit</th><th>Created</th><th></th></tr></thead><tbody>{rows}</tbody></table>
</div>
""", "keys")


def api_key_created_page(name: str, raw_key: str) -> str:
    token_json = json.dumps(raw_key)
    return page("API key created", f"""
<div style='max-width:760px;margin:40px auto'>
 <div class=card><span class='pill ok'>Created</span><h1 style='margin:16px 0 8px'>Save this key now</h1>
 <p class=muted>This is the only time the full secret for <b>{esc(name)}</b> will be displayed.</p>
 <div class=card style='margin-top:18px;background:var(--panel2)'><code id=created-key style='font-size:14px;word-break:break-all'>{esc(raw_key)}</code></div>
 <div class=row style='margin-top:18px'><button class='btn primary' onclick='copyCreatedKey()'>Copy key</button><a class=btn href=/api-keys>Done</a></div>
 </div>
</div>
""", "keys", raw_js=f"""async function copyCreatedKey(){{try{{await navigator.clipboard.writeText({token_json});toast('API key copied')}}catch(e){{toast('Copy failed — select it manually')}}}}""")


def pool_page(rows: list, stats: dict) -> str:
    body=''.join(f"<tr><td class='mono'>{esc(r['display'])}</td><td class='muted'>{esc(r.get('scheme',''))}</td><td>{_verdict_pill(r['verdict'])}</td><td class='muted' style='max-width:360px'>{esc(r['why']) or '—'}</td><td>{esc(r['latency']) if r['latency'] else '<span class=muted>—</span>'}{'ms' if r['latency'] else ''}</td><td><form method='post' action='/proxies/api/remove-one'><input type='hidden' name='key' value='{esc(r['key'])}'><button class='btn sm ghost'>Remove</button></form></td></tr>" for r in rows) or "<tr><td colspan='6' class='empty'>No proxies configured yet.</td></tr>"
    content=f'''<div class="pagehead"><div><div class="eyebrow">Network</div><h1>Proxy pool</h1><p>Manage configured upstream routes and see current transport health.</p></div><div class="actionbar"><span class="badge-num">{stats['total']} configured</span><span class="pill ok">{stats['alive']} alive</span><span class="pill warn">{stats['flagged']} restricted</span><button class="btn" onclick="scan()">Scan pool</button></div></div><div class="proxy-add"><section class="card"><div class="row"><div><div class="eyebrow">Inventory</div><h3 style="margin:2px 0 14px">Configured exits</h3></div><span class="spacer"></span><input id="proxyFilter" placeholder="Filter exits…" style="width:220px" oninput="filterRows()"></div><div class="table-wrap"><table id="proxyTable"><thead><tr><th>Exit</th><th>Scheme</th><th>State</th><th>Diagnosis</th><th>RTT</th><th></th></tr></thead><tbody>{body}</tbody></table></div></section><aside class="card"><div class="tabs" role="tablist"><button class="tab on" type="button" data-tab="add" onclick="switchProxyTab('add')">Add</button><button class="tab" type="button" data-tab="formats" onclick="switchProxyTab('formats')">Formats</button><button class="tab" type="button" data-tab="maint" onclick="switchProxyTab('maint')">Maintenance</button></div><div class="tab-panel" data-panel="add"><div class="eyebrow" style="margin-top:18px">Add capacity</div><h3 style="margin:2px 0 14px">Add proxies</h3><form id="proxyAddForm" data-native="1"><div class="dropbox"><label for="proxyText" style="margin-top:0">Paste proxies</label><textarea id="proxyText" name="text" placeholder="1.2.3.4:8080&#10;socks5://1.2.3.4:1080&#10;host:port:user:pass&#10;&#10;Or CSV: Host,Port,Username,Password,Type"></textarea><div class="helper">Credentials are optional. Accepts host:port, scheme://host:port, host:port:user:pass, full URLs, whitespace exports, or headered CSV.</div></div><label for="proxyFile">Or upload a text / CSV file</label><input id="proxyFile" type="file" accept=".txt,.csv,text/plain,text/csv"><div class="actionbar" style="margin-top:12px"><button class="btn primary" type="submit">Add proxies</button><button class="btn ghost" type="button" onclick="clearProxyForm()">Clear</button></div></form></div><div class="tab-panel" data-panel="formats" hidden><div class="eyebrow" style="margin-top:18px">Accepted input</div><h3 style="margin:2px 0 12px">Flexible parser</h3><div class="console" style="height:auto;max-height:none;padding:12px">1.2.3.4:8080<br>socks5://1.2.3.4:1080<br>SOCKS5 1.2.3.4 1080<br>1.2.3.4 1080 SOCKS5<br>1.2.3.4,1080,SOCKS5</div></div><div class="tab-panel" data-panel="maint" hidden><div class="eyebrow" style="margin-top:18px">Maintenance</div><h3 style="margin:2px 0 14px">Pool actions</h3><div class="actionbar"><button class="btn sm" onclick="poolAction('/proxies/api/prune','Pruning unhealthy exits…')">Prune dead</button><button class="btn sm ghost" onclick="poolAction('/proxies/api/revive','Reviving saved exits…')">Revive all</button><button class="btn sm danger" onclick="deleteAll()">Delete all</button></div></div></aside></div>'''
    js=r'''function switchProxyTab(name){document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('on',b.dataset.tab===name));document.querySelectorAll('[data-panel]').forEach(p=>p.hidden=p.dataset.panel!==name)}function filterRows(){const q=document.getElementById('proxyFilter').value.toLowerCase();document.querySelectorAll('#proxyTable tbody tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')}function clearProxyForm(){document.getElementById('proxyText').value='';document.getElementById('proxyFile').value=''}document.getElementById('proxyAddForm').addEventListener('submit',async e=>{e.preventDefault();const text=document.getElementById('proxyText').value,file=document.getElementById('proxyFile').files[0];if(!text.trim()&&!file){bgnToast('Paste proxies or choose a file first','warn');return}const t=bgnToast('Parsing and merging proxies…','loading');try{const fd=new FormData();fd.append('text',text);if(file)fd.append('file',file);const r=await fetch('/proxies/api/upload',{method:'POST',body:fd,credentials:'same-origin'}),d=await bgnJson(r);if(!r.ok)throw new Error(bgnResultMessage(d,'Upload failed'));const message='Added '+d.added+' · parsed '+d.parsed+' · local shims '+(d.local_shims||0)+' · distinct assigned '+(d.distinct_assigned||0)+' · keepers rebound '+(d.keepers_rebound||0)+' · skipped '+d.skipped;bgnToastUpdate(t,message,d.added>0?'ok':'warn',d.added>0?'Proxies added':'Nothing new added');if(d.added>0)bgnReload(message,'ok','Proxies added',1800)}catch(err){bgnToastUpdate(t,err.message||String(err),'error')}});async function scan(){const t=bgnToast('Scanning the proxy pool…','loading');try{const r=await fetch('/proxies/api/check',{method:'POST'}),d=await bgnJson(r);if(!r.ok)throw new Error(bgnResultMessage(d,'Scan failed'));if(d.running){bgnToastUpdate(t,'A scan is already running','warn');return}bgnToastUpdate(t,d.alive+' of '+d.total+' exits are healthy','ok','Scan complete');bgnReload(d.alive+' of '+d.total+' exits are healthy','ok','Scan complete',1200)}catch(e){bgnToastUpdate(t,e.message||String(e),'error')}}async function poolAction(url,msg){const t=bgnToast(msg,'loading');try{const r=await fetch(url,{method:'POST'}),d=await bgnJson(r);if(!r.ok)throw new Error(bgnResultMessage(d,'Action failed'));bgnToastUpdate(t,bgnResultMessage(d),'ok');bgnReload(bgnResultMessage(d),'ok','Done',1200)}catch(e){bgnToastUpdate(t,e.message||String(e),'error')}}async function deleteAll(){if(!confirm('Delete every active proxy? A recovery snapshot will be retained.'))return;const t=bgnToast('Deleting active proxies…','loading');try{const r=await fetch('/proxies/api/delete-all',{method:'POST'}),d=await bgnJson(r);if(!r.ok)throw new Error(bgnResultMessage(d,'Delete failed'));bgnToastUpdate(t,'Deleted '+d.removed+' proxies','ok');bgnReload('Deleted '+d.removed+' proxies','ok','Pool cleared',1200)}catch(e){bgnToastUpdate(t,e.message||String(e),'error')}}'''
    return page('Network', content, 'pool', js)

def jars_page(jars: list) -> str:
    cards = ""
    for j in jars:
        pills = []
        pills.append('<span class="pill ok">auth</span>' if j.get("has_auth") else '<span class="pill bad">no auth</span>')
        pills.append('<span class="dotlive" title="keeper live"></span>' if j.get("keeper_live") else '<span class="pill idle">keeper off</span>' if j.get("keeper_enabled") else '<span class="pill idle">no keeper</span>')
        if j.get("expired"):
            pills.append('<span class="pill bad">expired</span>')
        cards += f"""<div class="card" style="padding:16px"><div class="row"><b>{esc(j['name'])}</b><span class=spacer style="flex:1"></span>{''.join(pills)}</div>
<div class="kv"><span>persona</span><b>{esc(j.get('persona') or '—')}</b></div>
<div class="kv"><span>last used</span><b>{esc(j.get('last_used_str') or '—')}</b></div>
<div class="row" style="margin-top:12px"><form method=post action=/jars/reset style=margin:0><input type=hidden name=jar_id value="{esc(j['id'])}"><button class="btn sm">Reset</button></form>
<form method=post action=/keeper/live style=margin:0><input type=hidden name=jar_id value="{esc(j['id'])}"><input type=hidden name=on value="{ '0' if j.get('keeper_enabled') else '1'}"><button class="btn sm">{'Stop keeper' if j.get('keeper_enabled') else 'Start keeper'}</button></form>
<form method=post action=/jars/toggle style=margin:0><input type=hidden name=jar_id value="{esc(j['id'])}"><button class="btn sm ghost">{'Disable' if j.get('enabled', True) else 'Enable'}</button></form>
<form method=post action=/jars/persona style=margin:0><input type=hidden name=jar_id value="{esc(j['id'])}"><select name=key style="width:auto;padding:5px 8px;font-size:12px">{''.join(f'<option value="{esc(k)}" ' + ('selected' if j.get('persona')==k else '') + f'>{esc(l)}</option>' for k,l in j.get('_personas'))}</select><button class="btn sm ghost">bind</button></form></div></div>"""
    return page("Accounts", f"""<div class="pagehead"><div><h1>Accounts</h1><p>one device persona per account — headers, keeper and token minting stay coherent</p></div>
<div class="row"><a class="btn" href="/jars/upload">＋ Add account</a></div></div>
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(340px,1fr))">{cards or '<div class="card muted">No jars yet.</div>'}</div>""", active="jars")



def jars_upload_page() -> str:
    return page("Add account", r"""
<div class="pagehead">
  <div>
    <div class="eyebrow">Accounts</div>
    <h1>Add account</h1>
    <p>Import an authenticated Arena cookie export, or add an account with email/password credentials.</p>
  </div>
  <div class="row"><a class="btn ghost" href="/jars">← Accounts</a></div>
</div>

<div class="tabbar" style="margin-bottom:18px">
  <button class="tab on" type="button" data-jtab="cookies" onclick="switchJarTab('cookies')">Cookie JSON</button>
  <button class="tab" type="button" data-jtab="credentials" onclick="switchJarTab('credentials')">Email : password</button>
</div>

<div data-jpanel="cookies">
  <div class="card" style="max-width:760px">
    <div class="eyebrow">Authenticated cookie import</div>
    <h3 style="margin:4px 0 8px">Upload a .txt / .json cookie export</h3>
    <p class="muted" style="margin-top:0">
      The file may contain a JSON cookie array, <code>{"cookies":[...]}</code>, Netscape cookie text,
      or a pasted cookie JSON payload.
    </p>

    <form method="post" action="/jars/add" enctype="multipart/form-data" class="stack" style="gap:14px">
      <label>Account name <span class="muted">(optional)</span>
        <input name="name" placeholder="e.g. Arena account 8">
      </label>
      <label>Cookie file
        <input name="cookie_file" type="file" accept=".txt,.json,application/json,text/plain" required>
      </label>
      <button class="btn primary" type="submit">Import cookies and start keeper</button>
    </form>

    <div class="divider" style="margin:22px 0"></div>

    <form method="post" action="/jars/add-text" class="stack" style="gap:14px">
      <label>Account name <span class="muted">(optional)</span>
        <input name="name" placeholder="e.g. Arena account 8">
      </label>
      <label>Paste cookie JSON
        <textarea name="cookie_json" rows="10" spellcheck="false"
          placeholder='[{"name":"...","value":"...","domain":".arena.ai","path":"/"}]' required></textarea>
      </label>
      <button class="btn" type="submit">Import pasted cookies and start keeper</button>
    </form>
  </div>
</div>

<div data-jpanel="credentials" hidden>
  <div class="card" style="max-width:760px">
    <div class="eyebrow">Credential account</div>
    <h3 style="margin:4px 0 8px">Add email:password credentials</h3>
    <p class="muted" style="margin-top:0">
      One account per line. The first <code>:</code> separates the email from the password,
      so passwords may contain additional colons. Passwords are never written to the runtime log.
    </p>
    <form method="post" action="/jars/add-credentials" class="stack" style="gap:14px">
      <label>Display name <span class="muted">(optional; used only for a single line)</span>
        <input name="name" placeholder="e.g. Main Arena account">
      </label>
      <label>Credentials
        <textarea name="credentials" rows="8" spellcheck="false"
          placeholder="email@example.com:password" required></textarea>
      </label>
      <button class="btn primary" type="submit">Add account and start keeper</button>
    </form>
  </div>
</div>
""", active="jars", raw_js=r"""
function switchJarTab(name){
  document.querySelectorAll('[data-jtab]').forEach(b=>b.classList.toggle('on',b.dataset.jtab===name));
  document.querySelectorAll('[data-jpanel]').forEach(p=>p.hidden=p.dataset.jpanel!==name);
}
""")




def errors_page() -> str:
    rows = _recent_private_errors(120)
    body_rows = "".join(
        "<tr data-error-id='" + esc(str(row.get("id") or "")) + "'>"
        "<td><button class='btn sm ghost mono' type='button' onclick=\"lookupError('" +
        esc(str(row.get("id") or "")) + "')\">" + esc(str(row.get("id") or "")) + "</button></td>"
        "<td class='muted'>" + esc(str(row.get("time") or "")) + "</td>"
        "<td><span class='pill " + ("bad" if int(row.get("status") or 500) >= 500 else "warn") + "'>" +
        esc(str(row.get("status") or "")) + "</span></td>"
        "<td>" + esc(str(row.get("source") or "")) + "</td>"
        "<td class='mono muted'>" + esc(str(row.get("path") or "")) + "</td>"
        "</tr>"
        for row in rows
    ) or "<tr><td colspan='5' class='empty'>No customer-facing errors recorded yet.</td></tr>"

    return page("Errors", f"""
<div class="pagehead">
  <div>
    <div class="eyebrow">Support diagnostics</div>
    <h1>Error lookup</h1>
    <p>Customers only see a friendly Error ID. The implementation details stay here.</p>
  </div>
  <div class="row">
    <button class="btn ghost" onclick="location.reload()">Refresh</button>
  </div>
</div>

<div class="card" style="margin-bottom:16px">
  <div class="row" style="align-items:end">
    <label style="flex:1;max-width:620px">Error ID
      <input id="errorLookup" class="mono" placeholder="ERR-185049-A1B2C3D4"
             autocomplete="off" spellcheck="false">
    </label>
    <button class="btn primary" type="button" onclick="lookupError()">Look up</button>
  </div>
</div>

<div id="errorDetail" class="card" style="display:none;margin-bottom:16px"></div>

<div class="card">
  <div class="row" style="margin-bottom:14px">
    <div>
      <div class="eyebrow">Recent</div>
      <h3 style="margin:2px 0 0">Customer-facing errors</h3>
    </div>
    <span class="spacer"></span>
    <span class="pill">{len(rows)} shown</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Error ID</th><th>Time</th><th>HTTP</th><th>Source</th><th>Path</th></tr></thead>
      <tbody>{body_rows}</tbody>
    </table>
  </div>
</div>
""", active="errors", raw_js=r"""
const eEsc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function lookupError(forced=''){
  const input=document.getElementById('errorLookup'),id=(forced||input.value||'').trim();
  if(!id){bgnToast('Enter an Error ID first','warn');return}
  input.value=id;
  const pending=bgnToast('Looking up '+id+'…','loading');
  try{
    const r=await fetch('/errors/api/'+encodeURIComponent(id),{cache:'no-store',credentials:'same-origin'});
    const d=await r.json();
    if(!r.ok)throw new Error(d.detail||'Error ID not found');
    const box=document.getElementById('errorDetail'),x=d.error||{};
    const ctx=x.context&&Object.keys(x.context).length
      ?'<pre><code>'+eEsc(JSON.stringify(x.context,null,2))+'</code></pre>'
      :'<div class="muted">No additional context captured.</div>';
    box.innerHTML=
      '<div class="row"><div><div class="eyebrow">Nerd details</div><h3 class="mono" style="margin:2px 0 6px">'+eEsc(x.id)+'</h3></div>'+
      '<span class="spacer"></span><span class="pill '+((x.status||500)>=500?'bad':'warn')+'">HTTP '+eEsc(x.status)+'</span></div>'+
      '<div class="kv"><span>Time</span><b>'+eEsc(x.time)+'</b></div>'+
      '<div class="kv"><span>Source</span><b class="mono">'+eEsc(x.source)+'</b></div>'+
      '<div class="kv"><span>Protocol</span><b>'+eEsc(x.protocol||'—')+'</b></div>'+
      '<div class="kv"><span>Request</span><b class="mono">'+eEsc((x.method||'')+' '+(x.path||''))+'</b></div>'+
      (x.exception_type?'<div class="kv"><span>Exception</span><b class="mono">'+eEsc(x.exception_type)+'</b></div>':'')+
      '<div style="margin-top:16px"><div class="eyebrow">Internal detail</div><pre><code>'+eEsc(x.detail||'')+'</code></pre></div>'+
      '<div style="margin-top:16px"><div class="eyebrow">Context</div>'+ctx+'</div>';
    box.style.display='block';
    box.scrollIntoView({behavior:'smooth',block:'start'});
    bgnToastUpdate(pending,'Found '+id,'ok','Error found');
  }catch(err){
    bgnToastUpdate(pending,err.message||String(err),'error','Lookup failed');
  }
}
document.getElementById('errorLookup').addEventListener('keydown',e=>{
  if(e.key==='Enter'){e.preventDefault();lookupError()}
});
const q=new URLSearchParams(location.search).get('id');
if(q){document.getElementById('errorLookup').value=q;lookupError(q)}
""")



def logs_page(tail: list) -> str:
    lines = "".join(f'<div class="{esc(x["lvl"])}">{esc(x["line"])}</div>' for x in tail)
    return page("Logs", f"""<div class="pagehead"><div><h1>System Log</h1><p>ring buffer · auto-scroll</p></div>
<div class=row><button class="btn danger" onclick="fetch('/clear-logs',{{method:'POST'}}).then(()=>location.reload())">Clear</button></div></div>
<div class="card"><div class="console" id="c" style="height:calc(100vh - 240px)">{lines}</div></div>""", active="logs", raw_js="""
function f(){fetch('/debug-logs/data').then(r=>r.json()).then(d=>{var c=document.getElementById('c');c.innerHTML=d.map(x=>'<div class="'+(x.lvl||'INFO')+'">'+(x.line||'')+'</div>').join('');c.scrollTop=c.scrollHeight})}setInterval(f,2500);""")


def models_page(models: list, blocked: list) -> str:
    def _row(m):
        name = esc(m.get("name") or "")
        mid = esc((m.get("id") or "")[:22])
        is_b = m.get("name") in blocked
        pill = '<span class="pill bad">blocked</span>' if is_b else '<span class="pill ok">selectable</span>'
        act = "unblock" if is_b else "block"
        return ("<tr><td>" + name + '</td><td class="mono muted">' + mid + "</td><td>" + pill +
                '</td><td><form method="post" action="/models/block" style="margin:0">' +
                '<input type="hidden" name="name" value="' + name + '">' +
                "<button class='btn sm ghost'>" + act + "</button></form></td></tr>")
    rows = "".join(_row(m) for m in models[:400])
    return page("Models", '<div class="pagehead"><div><h1>Model Catalog</h1><p>' + str(len(models)) +
                " known · " + str(len(blocked)) + ' blocked on this account set</p></div>' +
                """<div class="row"><button class="btn" id="refreshModels" onclick="refreshModelsNow()">↻ Refresh</button></div></div>
<div class="card"><input id="q" placeholder="filter…" oninput="flt()" style="margin-bottom:12px">
<table><thead><tr><th>name</th><th>arena id</th><th>state</th><th></th></tr></thead><tbody id="tb">""" +
                rows + """</tbody></table></div>""", active="models", raw_js="""
function flt(){var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#tb tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}
async function refreshModelsNow(){
 const b=document.getElementById('refreshModels'); b.disabled=true; b.textContent='Refreshing…';
 try{
   const r=await fetch('/models/refresh',{method:'POST',headers:{'Accept':'application/json'}});
   const j=await r.json();
   if(!r.ok || !j.ok) throw new Error(j.reason||('HTTP '+r.status));
   if(typeof toast==='function') toast(j.reason||'Model catalog refreshed');
   setTimeout(()=>location.reload(),250);
 }catch(e){
   b.disabled=false; b.textContent='↻ Refresh';
   if(typeof toast==='function') toast('Refresh failed: '+(e.message||e)); else alert('Refresh failed: '+(e.message||e));
 }
}""")


def _legacy_chat_page(models: list, default_model: str) -> str:
    public_names = [model_name(m) for m in models if model_name(m)]
    public_default = canonical_public_model_name(default_model)
    opts = "".join(f'<option value="{esc(n)}"{" selected" if n==public_default else ""}>{esc(n)}</option>' for n in public_names[:300]) or '<option>auto</option>'
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bridgena · Live Chat</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>{CSS}</style></head><body>
<header class="topbar"><div class="brand"><span class="dot"></span>Bridgena <small>live</small></div><div class="spacer"></div>
<select class="btn sm model" id="model" style="width:auto">{opts}</select>
<span class="chip" id="jar">jar: auto</span>
<button class="btn sm ghost" onclick="bgnToggleTheme()">◐</button><a class="btn sm ghost" href="/dashboard">← ops</a></header>
<div class="chatgrid">
<aside class="chatside"><div class="row"><b class="small" style="flex:1">Threads</b><button class="btn sm ghost" onclick="newChat()">＋</button></div>
<div id="chats"></div></aside>
<main class="chatmain"><div class="transcript" id="t">
 <div class="bubble ai"><span class="who">bridgena</span>Fleet chat — messages route through a live jar, a proven exit and a keeper-minted recaptcha token. Say something.</div>
</div>
<div class="composer"><textarea id="in" placeholder="Message the arena…  (⌘/Ctrl+Enter to send)" onkeydown="if((event.metaKey||event.ctrlKey)&&event.key==='Enter')send()"></textarea>
<button class="btn primary" id="go" onclick="send()">Send</button></div></main>
<aside class="chatrail"><div class="card" style="padding:14px"><h3 style="margin-bottom:8px">Session</h3>
<div class="kv"><span>status</span><b id="st">idle</b></div><div class="kv"><span>exit</span><b id="ex">—</b></div>
<div class="kv"><span>token</span><b id="tk">—</b></div><div class="kv"><span>persona</span><b id="ps">—</b></div></div>
<div class="card" style="padding:14px;flex:1;min-height:120px"><h3 style="margin-bottom:8px">Signal</h3>
<div class="console" id="lc" style="height:100%;max-height:calc(100vh - 420px)"></div></div></aside></div>
<div id="toast-stack" class="toast-stack"></div>
<script>
{JS_THEME}
let chat_id = localStorage.getItem('bgn.chat') || ('c-' + Math.random().toString(36).slice(2,10));
let busy = false;
function md(s){{return s.replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]))
 .replace(/```([\\s\\S]*?)```/g,(m,x)=>'<pre><code>'+x+'</code></pre>')
 .replace(/`([^`\\n]+)`/g,'<code>$1</code>')
 .replace(/\\*\\*([^*\\n]+)\\*\\*/g,'<b>$1</b>')}}
function add(who,txt){{const t=document.getElementById('t');const d=document.createElement('div');d.className='bubble '+who;
 d.innerHTML='<span class=who>'+who+'</span>'+md(txt);t.appendChild(d);t.scrollTop=t.scrollHeight;return d}}
function localChats(){{try{{return JSON.parse(localStorage.getItem('bgn.localChats.v1')||'{{}}')}}catch(e){{return {{}}}}}}
function saveLocal(role,content){{const all=localChats(),c=all[chat_id]||(all[chat_id]={{messages:[],updated:0}});c.messages=(c.messages||[]).concat([{{role,content}}]).slice(-200);c.updated=Date.now();c.title=c.title||(role==='user'?content.slice(0,44):chat_id);const ids=Object.keys(all).sort((a,b)=>(all[b].updated||0)-(all[a].updated||0)).slice(0,50),keep={{}};ids.forEach(id=>keep[id]=all[id]);localStorage.setItem('bgn.localChats.v1',JSON.stringify(keep))}}
function refreshChats(){{const d=localChats();document.getElementById('chats').innerHTML=Object.keys(d).sort((a,b)=>(d[b].updated||0)-(d[a].updated||0)).map(id=>'<div class="chatitem'+(id===chat_id?' on':'')+'" onclick="openChat(\\''+id+'\\')">'+md(d[id].title||id)+'</div>').join('')}}
function openChat(id){{chat_id=id;localStorage.setItem('bgn.chat',id);document.getElementById('t').innerHTML='';refreshChats();const c=localChats()[id];if(c)(c.messages||[]).forEach(m=>add(m.role==='user'?'user':'ai',m.content))}}
function newChat(){{chat_id='c-'+Math.random().toString(36).slice(2,10);localStorage.setItem('bgn.chat',chat_id);
 document.getElementById('t').innerHTML='';refreshChats()}}
async function send(){{if(busy)return;const inp=document.getElementById('in');const text=inp.value.trim();if(!text)return;
 busy=true;inp.value='';document.getElementById('go').disabled=true;document.getElementById('st').textContent='streaming';
 add('user',text);saveLocal('user',text);const holder=add('ai','…');let acc='';
 try{{const r=await fetch('/v1/chat/completions',{{method:'POST',headers:{{'Content-Type':'application/json'}},
  body:JSON.stringify({{model:document.getElementById('model').value,messages:[{{role:'user',content:text}}],stream:true,chat_id:chat_id}})}});
  if(!r.ok){{throw new Error('HTTP '+r.status+': '+await r.text())}}
  const rd=r.body.getReader(),dec=new TextDecoder();let buf='';
  while(true){{const {{done,value}}=await rd.read();if(done)break;buf+=dec.decode(value,{{stream:true}});
   let nl;while((nl=buf.indexOf('\\n'))>=0){{const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1);
    if(line.startsWith('data: ')){{const p=line.slice(6);if(p==='[DONE]')continue;let j;try{{j=JSON.parse(p)}}catch(e){{continue}}
     if(j.error){{throw new Error(j.error.message||'Bridgena stream error')}}
     const d=j.choices&&j.choices[0]&&j.choices[0].delta&&j.choices[0].delta.content;if(d){{acc+=d;holder.innerHTML='<span class=who>ai</span>'+md(acc);document.getElementById('t').scrollTop=1e9}}}}}}}}
  if(!acc){{holder.innerHTML='<span class=who>ai</span><i class=muted>empty response</i>'}}
  if(acc)saveLocal('assistant',acc);document.getElementById('st').textContent='done';
 }}catch(e){{holder.innerHTML='<span class=who>ai</span>'+(acc?md(acc)+'<div style=color:var(--red);margin-top:8px>'+String(e)+'</div>':'<span style=color:var(--red)>'+String(e)+'</span>');if(acc)saveLocal('assistant',acc);document.getElementById('st').textContent='error'}}
 busy=false;document.getElementById('go').disabled=false;refreshChats()}}
setInterval(()=>{{fetch('/debug-logs/data').then(r=>r.json()).then(d=>{{const c=document.getElementById('lc');
 c.innerHTML=d.slice(-40).map(x=>'<div class="'+(x.lvl||'INFO')+'">'+(x.line||'')+'</div>').join('');c.scrollTop=c.scrollHeight;
 const last=d.filter(x=>/via .* persona/.test(x.m||'')).pop();if(last){{const m=(last.m||'').match(/via (\\S+) persona · exit (\\S+) · token (\\w+)/);
  if(m){{document.getElementById('ps').textContent=m[1];document.getElementById('ex').textContent=m[2];document.getElementById('tk').textContent=m[3]}}}}}}).catch(()=>{{}})}},3000);
refreshChats();openChat(chat_id);
</script></body></html>"""


def chat_page(models: list, default_model: str) -> str:
    """Modern, dependency-free shadcn-inspired chat shell.

    Bridgena ships as one Python file, so these are native components rather
    than a React build; the visual tokens and interaction model match the
    shadcn/Vercel family without adding a fragile CDN/runtime dependency.
    """
    names = [model_name(m) for m in models if model_name(m)]
    payload = _json.dumps(names, ensure_ascii=False).replace("</", "<\\/")
    selected_name = canonical_public_model_name(default_model or (names[0] if names else "auto"))
    selected = _json.dumps(selected_name, ensure_ascii=False)
    template = r'''<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bridgena</title>
<style>
:root{--bg:#fff;--panel:#fafafa;--soft:#f4f4f5;--line:#e4e4e7;--text:#09090b;--muted:#71717a;--hover:#f4f4f5;--accent:#18181b;--danger:#dc2626;--success:#16a34a;--shadow:0 12px 34px rgba(0,0,0,.12)}
[data-theme=dark]{--bg:#09090b;--panel:#0d0d0f;--soft:#18181b;--line:#27272a;--text:#fafafa;--muted:#a1a1aa;--hover:#18181b;--accent:#fafafa;--danger:#f87171;--success:#4ade80;--shadow:0 18px 50px rgba(0,0,0,.55)}
*{box-sizing:border-box}html,body{margin:0;height:100%;overflow:hidden}body{background:var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
button,input,textarea{font:inherit}button{color:inherit}.icon{width:17px;height:17px;display:block}.app{height:100%;display:grid;grid-template-columns:260px minmax(0,1fr)}
.sidebar{background:var(--panel);border-right:1px solid var(--line);display:flex;flex-direction:column;min-width:0}.sidehead{height:60px;padding:0 14px;display:flex;align-items:center;gap:10px}.mark{width:28px;height:28px;border-radius:8px;background:var(--text);color:var(--bg);display:grid;place-items:center;font-weight:750;font-size:12px}.wordmark{font-weight:650;letter-spacing:-.02em}.sidebody{padding:8px;overflow:auto;flex:1}.newbtn,.ghost,.modelbtn{border:1px solid var(--line);background:var(--bg);border-radius:8px;cursor:pointer;transition:.15s}.newbtn{height:38px;width:100%;display:flex;align-items:center;justify-content:center;gap:8px;font-weight:550}.newbtn:hover,.ghost:hover,.modelbtn:hover{background:var(--hover)}.sectionlabel{padding:22px 8px 7px;color:var(--muted);font-size:11px;font-weight:600}.thread{width:100%;border:0;background:transparent;color:var(--muted);padding:8px 10px;border-radius:7px;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}.thread:hover{background:var(--hover);color:var(--text)}.thread.on{background:var(--soft);color:var(--text);font-weight:520}.sidefoot{padding:10px;border-top:1px solid var(--line)}.ops{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:7px;color:var(--muted);text-decoration:none}.ops:hover{background:var(--hover);color:var(--text)}
.main{min-width:0;display:flex;flex-direction:column}.top{height:60px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 18px;gap:10px}.mobile{display:none}.modelwrap{position:relative}.modelbtn{height:36px;max-width:min(440px,55vw);display:flex;align-items:center;gap:8px;padding:0 11px;font-weight:550}.modelbtn span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.chev{color:var(--muted)}.status{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}.statusdot{width:7px;height:7px;border-radius:50%;background:#a1a1aa}.statusdot.busy{background:#f59e0b;box-shadow:0 0 0 4px color-mix(in srgb,#f59e0b 15%,transparent)}.statusdot.ok{background:var(--success)}.statusdot.err{background:var(--danger)}.ghost{width:36px;height:36px;display:grid;place-items:center}
.picker{position:absolute;z-index:30;top:42px;left:0;width:min(480px,calc(100vw - 32px));background:var(--bg);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow);overflow:hidden;display:none}.picker.open{display:block}.searchbox{padding:9px;border-bottom:1px solid var(--line)}.searchbox input{width:100%;height:36px;background:transparent;color:var(--text);border:0;outline:0;padding:0 8px}.modellist{max-height:340px;overflow:auto;padding:5px}.modelopt{width:100%;border:0;background:transparent;color:var(--text);border-radius:6px;padding:9px 10px;text-align:left;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.modelopt:hover,.modelopt.on{background:var(--hover)}.emptymodels{padding:22px;text-align:center;color:var(--muted)}
.scroll{flex:1;overflow:auto;scroll-behavior:smooth}.conversation{width:min(800px,100%);margin:0 auto;padding:34px 24px 150px}.welcome{min-height:58vh;display:grid;place-items:center;text-align:center}.welcome h1{font-size:28px;line-height:1.15;letter-spacing:-.04em;margin:0 0 9px}.welcome p{color:var(--muted);margin:0;max-width:470px}.msg{display:grid;grid-template-columns:30px minmax(0,1fr);gap:13px;margin:0 0 30px}.avatar{width:28px;height:28px;border:1px solid var(--line);border-radius:8px;display:grid;place-items:center;font-size:11px;font-weight:700;background:var(--soft)}.msg.user .avatar{background:var(--text);color:var(--bg);border-color:var(--text)}.msghead{font-size:13px;font-weight:650;margin:3px 0 6px}.msgbody{font-size:15px;line-height:1.75;white-space:pre-wrap;overflow-wrap:anywhere}.msgbody pre{background:var(--soft);border:1px solid var(--line);border-radius:9px;padding:13px;overflow:auto;font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace}.msgbody code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--soft);border-radius:4px;padding:2px 4px}.msgbody pre code{padding:0}.thinking{color:var(--muted)}.errorbox{color:var(--danger);background:color-mix(in srgb,var(--danger) 7%,transparent);border:1px solid color-mix(in srgb,var(--danger) 25%,var(--line));padding:11px 13px;border-radius:8px;white-space:pre-wrap}
.dock{position:absolute;left:260px;right:0;bottom:0;padding:26px 20px 18px;background:linear-gradient(transparent,var(--bg) 35%)}.compose{width:min(800px,100%);margin:auto;border:1px solid var(--line);background:var(--bg);border-radius:14px;box-shadow:0 8px 30px rgba(0,0,0,.08);padding:11px 11px 9px}.compose:focus-within{border-color:color-mix(in srgb,var(--text) 35%,var(--line));box-shadow:0 8px 34px rgba(0,0,0,.1)}textarea{display:block;width:100%;height:44px;max-height:180px;resize:none;border:0;outline:0;background:transparent;color:var(--text);padding:4px 5px;line-height:1.5}.composefoot{display:flex;align-items:center;gap:8px}.hint{color:var(--muted);font-size:11px;margin-left:4px}.send{margin-left:auto;width:34px;height:34px;border:0;border-radius:9px;background:var(--text);color:var(--bg);display:grid;place-items:center;cursor:pointer}.send:disabled{opacity:.35;cursor:not-allowed}.runtime{width:min(800px,100%);margin:7px auto 0;color:var(--muted);font-size:11px;text-align:center}.runtime details{text-align:left}.runtime pre{max-height:160px;overflow:auto;background:var(--soft);border:1px solid var(--line);padding:10px;border-radius:8px;white-space:pre-wrap}
/* v2.16 chat polish + correct nested flex scrolling */
.app{grid-template-columns:280px minmax(0,1fr)}
.sidebar{background:color-mix(in srgb,var(--panel) 88%,transparent)}
.sidehead{height:64px;padding:0 16px}.mark{border-radius:9px}.sidebody{padding:10px}.newbtn{height:40px;border-radius:9px;box-shadow:0 1px 2px rgba(0,0,0,.12)}
.thread{padding:9px 11px}.sidefoot{padding:12px}.ops{padding:10px 11px}
.main{position:relative;min-height:0;overflow:hidden;background:radial-gradient(800px 400px at 50% -220px,color-mix(in srgb,var(--text) 6%,transparent),transparent 75%),var(--bg)}
.top{height:64px;padding:0 22px;background:color-mix(in srgb,var(--bg) 86%,transparent);backdrop-filter:blur(18px)}
.modelbtn{border:0;background:transparent;box-shadow:none;font-weight:600}.modelbtn:hover{background:var(--hover)}
.scroll{min-height:0;overscroll-behavior:contain;scrollbar-gutter:stable}
.conversation{width:min(860px,100%);padding:48px 28px 190px}.welcome{min-height:calc(100vh - 280px)}.welcome h1{font-size:34px;font-weight:680}
.msg{grid-template-columns:32px minmax(0,1fr);gap:14px;margin-bottom:34px}.avatar{width:30px;height:30px;border-radius:9px}.msgbody{font-size:15px;line-height:1.8}
.msg.user{margin-left:12%}.msg.user>div:last-child{background:var(--soft);border:1px solid var(--line);border-radius:14px;padding:12px 15px}.msg.user .msghead{display:none}
.dock{left:280px;padding:46px 20px 18px;background:linear-gradient(transparent,var(--bg) 42%);pointer-events:none}.compose,.runtime{pointer-events:auto}
.compose{width:min(860px,100%);border-radius:16px;padding:13px 13px 10px;box-shadow:0 14px 45px rgba(0,0,0,.16)}.compose:focus-within{box-shadow:0 16px 50px rgba(0,0,0,.2),0 0 0 1px color-mix(in srgb,var(--text) 12%,transparent)}
.send{border-radius:10px}.runtime{width:min(860px,100%)}
@media(max-width:760px){.app{grid-template-columns:1fr}.sidebar{position:fixed;z-index:50;inset:0 auto 0 0;width:280px;transform:translateX(-100%);transition:.2s;box-shadow:var(--shadow)}.sidebar.open{transform:none}.mobile{display:grid}.top{padding:0 12px}.dock{left:0;padding-inline:12px}.conversation{padding:30px 18px 180px}.status span{display:none}.modelbtn{max-width:54vw}.msg.user{margin-left:4%}}
/* Open WebUI-inspired workspace */
:root{--bg:#fff;--panel:#f8f8f8;--soft:#f2f2f2;--line:#e8e8e8;--text:#111;--muted:#707070;--hover:#ededed}
[data-theme=dark]{--bg:#0b0b0b;--panel:#111;--soft:#191919;--line:#282828;--text:#f4f4f4;--muted:#999;--hover:#1d1d1d}
.app{grid-template-columns:270px minmax(0,1fr)}.sidebar{background:var(--panel);border-color:var(--line)}
.sidehead{height:62px;padding:0 18px}.mark{width:30px;height:30px;border-radius:10px;box-shadow:0 0 0 4px color-mix(in srgb,var(--text) 5%,transparent)}
.wordmark{font-size:15px;font-weight:680}.sidebody{padding:8px 10px}.newbtn{justify-content:flex-start;padding:0 13px;border:0;background:transparent;box-shadow:none}
.newbtn:hover{background:var(--hover)}.sectionlabel{text-transform:uppercase;letter-spacing:.08em;font-size:10px;padding:24px 11px 8px}
.thread{font-size:13px;padding:9px 11px}.sidefoot{padding:10px}.ops{font-size:13px}
.top{height:62px;border-color:var(--line);padding:0 22px;background:color-mix(in srgb,var(--bg) 92%,transparent)}
.main{background:var(--bg)}.conversation{width:min(900px,100%);padding:54px 30px 210px}.welcome{min-height:calc(100vh - 310px)}
.welcome h1{font-size:32px;font-weight:650}.welcome p{font-size:14px}.msg{grid-template-columns:34px minmax(0,1fr);margin-bottom:38px}
.avatar{width:32px;height:32px;border-radius:10px}.msg.user{display:flex;justify-content:flex-end;margin-left:24%}.msg.user .avatar{display:none}
.msg.user>div:last-child{max-width:80%;background:var(--soft);border:0;border-radius:18px;padding:10px 15px}.msgbody{line-height:1.8}
.dock{left:270px;padding:64px 20px 20px;background:linear-gradient(transparent,var(--bg) 48%)}
.compose{width:min(900px,100%);border-radius:22px;padding:14px 14px 11px;border-color:var(--line);box-shadow:0 8px 32px rgba(0,0,0,.16)}
.compose:focus-within{border-color:color-mix(in srgb,var(--text) 25%,var(--line));box-shadow:0 10px 38px rgba(0,0,0,.2)}
.send{border-radius:50%;width:34px;height:34px}.picker{border-radius:14px;background:var(--panel)}
.promptgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:28px auto 0;max-width:600px}.promptchip{border:1px solid var(--line);background:var(--panel);color:var(--muted);padding:12px 14px;border-radius:12px;text-align:left;cursor:pointer}.promptchip:hover{background:var(--hover);color:var(--text)}
.runtime-drawer{position:fixed;z-index:70;top:76px;right:16px;bottom:16px;width:min(540px,calc(100vw - 32px));padding:14px;background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);opacity:0;pointer-events:none;transform:translateX(calc(100% + 32px));transition:opacity .18s ease,transform .18s ease}
.runtime-drawer.open{opacity:1;pointer-events:auto;transform:none}.drawerhead{height:34px;display:flex;align-items:center;justify-content:space-between;font-weight:650}.drawerhead .ghost{width:30px;height:30px}.runtime-drawer pre{height:calc(100% - 42px);margin:8px 0 0;padding:12px;overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:10px;color:var(--muted);white-space:pre-wrap;font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
@media(max-width:760px){.app{grid-template-columns:1fr}.dock{left:0}.promptgrid{grid-template-columns:1fr}.msg.user{margin-left:8%}.conversation{padding-inline:16px}}
</style></head><body><div class="app">
<aside class="sidebar" id="sidebar"><div class="sidehead"><div class="mark">B</div><div class="wordmark">Bridgena</div></div><div class="sidebody"><button class="newbtn" onclick="newChat()">＋ New chat</button><div class="sectionlabel">Recent</div><div id="threads"></div></div><div class="sidefoot"><a class="ops" href="/dashboard">⚙ Operations</a></div></aside>
<main class="main"><header class="top"><button class="ghost mobile" onclick="toggleSidebar()">☰</button><div class="modelwrap"><button class="modelbtn" id="modelBtn" onclick="togglePicker()"><span id="modelLabel"></span><span class="chev">⌄</span></button><div class="picker" id="picker"><div class="searchbox"><input id="modelSearch" placeholder="Search models…" autocomplete="off"></div><div class="modellist" id="modelList"></div></div></div><div class="status"><i class="statusdot" id="statusDot"></i><span id="statusText">Ready</span></div><button class="ghost" onclick="toggleRuntime()" title="Runtime signal">⌁</button><button class="ghost" onclick="toggleTheme()" title="Toggle theme">◐</button></header>
<div class="scroll" id="scroll"><div class="conversation" id="conversation"><div class="welcome" id="welcome"><div><div class="mark" style="margin:0 auto 18px;width:42px;height:42px">B</div><h1>What are we building?</h1><p>Choose a model and start a conversation with your Bridgena workspace.</p><div class="promptgrid"><button class="promptchip" onclick="usePrompt('Explain this code and identify reliability risks')">Review code</button><button class="promptchip" onclick="usePrompt('Help me debug a failed API request')">Debug a request</button><button class="promptchip" onclick="usePrompt('Design a production rollout plan')">Plan a rollout</button><button class="promptchip" onclick="usePrompt('Summarize the latest runtime signals')">Inspect runtime</button></div></div></div></div></div>
<div class="dock"><div class="compose"><textarea id="input" rows="1" placeholder="Message Bridgena"></textarea><div class="composefoot"><span class="hint">Enter to send · Shift+Enter for newline</span><button class="send" id="send" onclick="sendMessage()" aria-label="Send">↑</button></div></div></div></main></div>
<aside class="runtime-drawer" id="runtimeDrawer"><div class="drawerhead"><span>Runtime signal</span><button class="ghost" onclick="toggleRuntime()" aria-label="Close runtime">×</button></div><pre id="signal">Waiting for activity…</pre></aside>
<script>
const MODELS=__MODELS_JSON__, DEFAULT_MODEL=__DEFAULT_MODEL__;
let model=localStorage.getItem('bgn.model')||DEFAULT_MODEL, chatId=localStorage.getItem('bgn.chat')||makeId(), busy=false;
const $=id=>document.getElementById(id), escHtml=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function makeId(){return 'c-'+Math.random().toString(36).slice(2,10)}
function toggleSidebar(){ $('sidebar').classList.toggle('open') }
function toggleRuntime(){ $('runtimeDrawer').classList.toggle('open') }
function toggleTheme(){const root=document.documentElement,d=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=d;localStorage.setItem('bgn.theme',d)}
document.documentElement.dataset.theme=localStorage.getItem('bgn.theme')||((matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light');
function togglePicker(force){const p=$('picker'),open=force===undefined?!p.classList.contains('open'):force;p.classList.toggle('open',open);if(open){$('modelSearch').value='';renderModels('');setTimeout(()=>$('modelSearch').focus(),0)}}
function renderModels(q){q=(q||'').toLowerCase();const rows=MODELS.filter(x=>x.toLowerCase().includes(q)).slice(0,150);$('modelList').innerHTML=rows.length?rows.map(x=>'<button class="modelopt '+(x===model?'on':'')+'" data-model="'+escHtml(x)+'">'+escHtml(x)+'</button>').join(''):'<div class="emptymodels">No models found</div>';document.querySelectorAll('.modelopt').forEach(b=>b.onclick=()=>selectModel(b.dataset.model))}
function selectModel(x){model=x;$('modelLabel').textContent=x;localStorage.setItem('bgn.model',x);togglePicker(false)}
$('modelSearch').addEventListener('input',e=>renderModels(e.target.value));document.addEventListener('click',e=>{if(!e.target.closest('.modelwrap'))togglePicker(false)});selectModel(MODELS.includes(model)?model:(MODELS[0]||DEFAULT_MODEL));
function md(s){return escHtml(s).replace(/```([\s\S]*?)```/g,'<pre><code>$1</code></pre>').replace(/`([^`\n]+)`/g,'<code>$1</code>').replace(/\*\*([^*\n]+)\*\*/g,'<strong>$1</strong>')}
function clearWelcome(){$('welcome')?.remove()}
function addMessage(role,text,kind){clearWelcome();const row=document.createElement('article');row.className='msg '+role;row.innerHTML='<div class="avatar">'+(role==='user'?'Y':'B')+'</div><div><div class="msghead">'+(role==='user'?'You':'Bridgena')+'</div><div class="msgbody '+(kind||'')+'"></div></div>';const body=row.querySelector('.msgbody');body.innerHTML=kind==='error'?'<div class="errorbox">'+escHtml(text)+'</div>':md(text);$('conversation').appendChild(row);$('scroll').scrollTop=$('scroll').scrollHeight;return body}
function setStatus(label,state){$('statusText').textContent=label;$('statusDot').className='statusdot '+(state||'')}
function localChats(){try{return JSON.parse(localStorage.getItem('bgn.localChats.v1')||'{}')}catch(e){return {}}}
function writeLocalChats(all){const ids=Object.keys(all).sort((a,b)=>(all[b].updated||0)-(all[a].updated||0)).slice(0,50),keep={};ids.forEach(id=>keep[id]=all[id]);try{localStorage.setItem('bgn.localChats.v1',JSON.stringify(keep))}catch(e){}}
function saveLocalMessage(role,content){const all=localChats(),c=all[chatId]||(all[chatId]={messages:[],updated:0});c.messages=(c.messages||[]).concat([{role,content}]).slice(-200);c.updated=Date.now();c.title=c.title||(role==='user'?content.slice(0,44):chatId);writeLocalChats(all)}
function loadThreads(){const d=localChats(),rows=Object.keys(d).sort((a,b)=>(d[b].updated||0)-(d[a].updated||0));$('threads').innerHTML=rows.map(id=>'<button class="thread '+(id===chatId?'on':'')+'" data-id="'+escHtml(id)+'">'+escHtml(d[id].title||id)+'</button>').join('');document.querySelectorAll('.thread').forEach(b=>b.onclick=()=>openChat(b.dataset.id))}
function openChat(id){chatId=id;localStorage.setItem('bgn.chat',id);$('conversation').innerHTML='';const c=localChats()[id];if(!c||!(c.messages||[]).length){showWelcome()}else c.messages.forEach(m=>addMessage(m.role==='user'?'user':'ai',m.content));loadThreads();$('sidebar').classList.remove('open')}
function showWelcome(){$('conversation').innerHTML='<div class="welcome" id="welcome"><div><div class="mark" style="margin:0 auto 18px;width:42px;height:42px">B</div><h1>What are we building?</h1><p>Choose a model and start a conversation with your Bridgena workspace.</p><div class="promptgrid"><button class="promptchip" onclick="usePrompt(\'Explain this code and identify reliability risks\')">Review code</button><button class="promptchip" onclick="usePrompt(\'Help me debug a failed API request\')">Debug a request</button></div></div></div>'}
function usePrompt(text){$('input').value=text;$('input').dispatchEvent(new Event('input'));$('input').focus()}
function newChat(){chatId=makeId();localStorage.setItem('bgn.chat',chatId);showWelcome();loadThreads();$('sidebar').classList.remove('open');$('input').focus()}
async function sendMessage(){if(busy)return;const input=$('input'),text=input.value.trim();if(!text)return;busy=true;input.value='';input.style.height='44px';$('send').disabled=true;setStatus('Generating','busy');addMessage('user',text);saveLocalMessage('user',text);const out=addMessage('ai','Thinking…','thinking');let acc='';try{const history=((localChats()[chatId]||{}).messages||[]).slice(-16).map(m=>({role:m.role,content:m.content}));const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model,messages:history.length?history:[{role:'user',content:text}],stream:true,chat_id:chatId})});if(!r.ok)throw new Error('HTTP '+r.status+': '+await r.text());const rd=r.body.getReader(),dec=new TextDecoder();let buf='';while(true){const {done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});let nl;while((nl=buf.indexOf('\n'))>=0){const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1);if(!line.startsWith('data: '))continue;const p=line.slice(6);if(p==='[DONE]')continue;let j;try{j=JSON.parse(p)}catch(e){continue}if(j.error)throw new Error(j.error.message||'Bridge stream error');const d=j.choices?.[0]?.delta?.content;if(d){acc+=d;out.classList.remove('thinking');out.innerHTML=md(acc);$('scroll').scrollTop=$('scroll').scrollHeight}}}if(!acc)throw new Error('Arena returned an empty response');saveLocalMessage('assistant',acc);setStatus('Ready','ok')}catch(e){out.classList.remove('thinking');const err='<div class="errorbox">'+escHtml(e.message||e)+'</div>';out.innerHTML=acc?md(acc)+err:err;if(acc)saveLocalMessage('assistant',acc);setStatus('Error','err')}finally{busy=false;$('send').disabled=false;loadThreads()}}
const input=$('input');input.addEventListener('input',()=>{input.style.height='auto';input.style.height=Math.min(input.scrollHeight,180)+'px'});input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}});
setInterval(()=>fetch('/debug-logs/data').then(r=>r.json()).then(d=>{$('signal').textContent=d.slice(-18).map(x=>x.line||x.m||'').join('\n')}).catch(()=>{}),3000);
loadThreads();openChat(chatId);
</script></body></html>'''
    return template.replace("__MODELS_JSON__", payload).replace("__DEFAULT_MODEL__", selected)



# ============================================================
# BRIDGENA v3 CANONICAL CONTROL PLANE
# ============================================================
V3_CSS = r'''
:root{--bg:#09090b;--surface:#0c0c0e;--surface2:#111113;--surface3:#18181b;--line:#27272a;--line2:#323236;--text:#fafafa;--muted:#a1a1aa;--dim:#71717a;--ok:#4ade80;--warn:#fbbf24;--bad:#fb7185;--info:#60a5fa;--radius:12px;--sans:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace}
[data-theme=light]{--bg:#fff;--surface:#fff;--surface2:#fafafa;--surface3:#f4f4f5;--line:#e4e4e7;--line2:#d4d4d8;--text:#09090b;--muted:#71717a;--dim:#a1a1aa;--ok:#16a34a;--warn:#b45309;--bad:#e11d48;--info:#2563eb}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text)}body{font:14px/1.55 var(--sans);-webkit-font-smoothing:antialiased}a{color:inherit;text-decoration:none}button,input,textarea,select{font:inherit}.topbar{position:sticky;top:0;z-index:50;height:60px;display:flex;align-items:center;gap:12px;padding:0 18px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:10px;font-weight:680;letter-spacing:-.025em}.brand .dot{width:28px;height:28px;border-radius:9px;background:var(--text);color:var(--bg);display:grid;place-items:center;font-size:11px}.brand .dot:after{content:"B"}.brand small{font:500 10px var(--mono);color:var(--dim)}.spacer{flex:1}.shell{display:grid;grid-template-columns:232px minmax(0,1fr);min-height:calc(100vh - 60px)}.rail{position:sticky;top:60px;height:calc(100vh - 60px);border-right:1px solid var(--line);padding:16px 10px;background:var(--bg)}.rail .rail-label{padding:5px 10px 10px;font-size:10px;color:var(--dim);font-weight:650;text-transform:uppercase;letter-spacing:.08em}.rail a{display:flex;align-items:center;min-height:38px;padding:9px 11px;border-radius:8px;color:var(--muted);font-weight:540}.rail a:hover,.rail a.on{background:var(--surface3);color:var(--text)}.main{width:100%;max-width:1520px;padding:34px 38px 72px;min-width:0}.pagehead{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;padding-bottom:22px;margin-bottom:20px;border-bottom:1px solid var(--line)}.pagehead h1{font-size:28px;line-height:1.1;letter-spacing:-.045em;margin:0;font-weight:690}.pagehead p{color:var(--muted);margin:7px 0 0;max-width:720px}.grid{display:grid;gap:12px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.split{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(320px,.65fr);gap:12px}.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:17px;box-shadow:0 1px 2px rgba(0,0,0,.08);min-width:0}.card h3{font-size:13px;margin:0 0 13px;font-weight:650;display:flex;align-items:center;gap:8px}.metric{min-height:124px;display:flex;flex-direction:column;justify-content:space-between}.metric .k{color:var(--muted);font-size:12px;font-weight:550}.metric .v{font-size:33px;line-height:1;font-weight:690;letter-spacing:-.045em}.metric .s{font-size:11px;color:var(--dim)}.row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:35px;border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:8px;padding:7px 11px;cursor:pointer;font-weight:550;box-shadow:0 1px 2px rgba(0,0,0,.08)}.btn:hover{background:var(--surface3)}.btn.primary{background:var(--text);color:var(--bg);border-color:var(--text)}.btn.danger{color:var(--bad)}.btn.ghost{background:transparent;box-shadow:none}.btn.sm{min-height:31px;padding:5px 9px;font-size:12px}.chip,.pill{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 8px;font-size:10px;font-weight:650}.pill.ok,.chip.live{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 26%,var(--line));background:color-mix(in srgb,var(--ok) 7%,transparent)}.pill.warn{color:var(--warn)}.pill.bad{color:var(--bad)}.pill.idle{color:var(--dim)}.dotlive{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--ok)}table{width:100%;border-collapse:collapse}th{text-align:left;color:var(--dim);font-size:10px;font-weight:650;text-transform:uppercase;letter-spacing:.05em;padding:9px;border-bottom:1px solid var(--line)}td{padding:10px 9px;border-bottom:1px solid var(--line);font-size:12.5px;vertical-align:middle}tr:last-child td{border-bottom:0}tr:hover td{background:var(--surface2)}.mono{font-family:var(--mono);font-size:11.5px}.muted{color:var(--muted)}.small{font-size:12px}input,textarea,select{width:100%;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 10px;outline:0}input:focus,textarea:focus,select:focus{border-color:var(--line2);box-shadow:0 0 0 3px color-mix(in srgb,var(--text) 6%,transparent)}textarea{resize:vertical;min-height:100px}label{display:block;font-size:12px;font-weight:600;margin:13px 0 6px}.kv{display:flex;justify-content:space-between;gap:20px;padding:7px 0;border-bottom:1px dashed var(--line);font-size:12px;color:var(--muted)}.kv b{color:var(--text)}.console{height:360px;overflow:auto;background:#050505;border:1px solid var(--line);border-radius:9px;padding:12px;font:11px/1.7 var(--mono);color:#d4d4d8}[data-theme=light] .console{background:#fafafa;color:#27272a}.console .WARN{color:var(--warn)}.console .ERROR{color:var(--bad)}.console .OK{color:var(--ok)}.bar{width:78px;height:5px;background:var(--surface3);border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:var(--text)}.toast{position:fixed;z-index:100;left:50%;bottom:24px;transform:translate(-50%,20px);opacity:0;pointer-events:none;background:var(--text);color:var(--bg);border-radius:999px;padding:9px 13px;font-size:12px;transition:.18s}.toast.show{opacity:1;transform:translate(-50%,0)}.auth{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(900px 500px at 50% -250px,color-mix(in srgb,var(--text) 8%,transparent),transparent 75%)}.authbox{width:min(390px,100%)}.authlogo{width:42px;height:42px;margin:0 auto 18px;border-radius:12px;background:var(--text);color:var(--bg);display:grid;place-items:center;font-weight:800}.auth h1{text-align:center;font-size:25px;letter-spacing:-.04em;margin:0}.auth p{text-align:center;color:var(--muted);margin:8px 0 24px}.err{color:var(--bad);font-size:12px;text-align:center;min-height:18px;margin-top:12px}.v3-health{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:11px}.v3-health i{width:7px;height:7px;border-radius:50%;background:var(--ok)}@media(max-width:1000px){.metrics{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}}@media(max-width:760px){.shell{grid-template-columns:1fr}.rail{display:none}.main{padding:24px 14px 52px}.topbar{padding:0 12px}.metrics{grid-template-columns:1fr}.pagehead{align-items:flex-start;flex-direction:column}}
/* v3.5 control-plane redesign */
.toast-stack{position:fixed;z-index:5000;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px;width:min(390px,calc(100vw - 28px));pointer-events:none}.toast-stack .toast{position:relative;left:auto;bottom:auto;transform:translateY(10px) scale(.985);opacity:0;pointer-events:auto;background:color-mix(in srgb,var(--surface) 96%,transparent);color:var(--text);border:1px solid var(--line2);border-radius:12px;padding:12px 14px;box-shadow:0 18px 50px rgba(0,0,0,.28);font-size:12.5px;transition:.2s;display:grid;grid-template-columns:8px minmax(0,1fr) auto;gap:10px;align-items:start;backdrop-filter:blur(18px)}.toast-stack .toast.show{opacity:1;transform:none}.toast-dot{width:8px;height:8px;border-radius:50%;margin-top:5px;background:var(--info)}.toast.ok .toast-dot{background:var(--ok)}.toast.warn .toast-dot{background:var(--warn)}.toast.error .toast-dot{background:var(--bad)}.toast.loading .toast-dot{animation:bgnpulse .8s infinite alternate}@keyframes bgnpulse{to{opacity:.25;transform:scale(.75)}}.toast-title{font-weight:650;line-height:1.25}.toast-msg{color:var(--muted);margin-top:2px;line-height:1.4;word-break:break-word}.toast-close{border:0;background:transparent;color:var(--dim);cursor:pointer;padding:0 2px;font-size:15px}.eyebrow{font-size:10px;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);font-weight:700}.hero{border:1px solid var(--line);border-radius:16px;padding:24px;background:linear-gradient(145deg,color-mix(in srgb,var(--surface2) 92%,transparent),var(--surface));position:relative;overflow:hidden}.hero:after{content:"";position:absolute;width:360px;height:360px;border-radius:50%;right:-180px;top:-220px;background:radial-gradient(circle,color-mix(in srgb,var(--info) 13%,transparent),transparent 68%);pointer-events:none}.hero h1{font-size:32px;letter-spacing:-.05em;margin:3px 0 8px;line-height:1.05}.hero p{max-width:700px;color:var(--muted);margin:0}.hero-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}.status-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:12px}.status-card{border:1px solid var(--line);background:var(--surface);border-radius:12px;padding:14px}.status-card .label{font-size:11px;color:var(--muted);display:flex;justify-content:space-between;gap:12px}.status-card .num{font-size:27px;font-weight:700;letter-spacing:-.04em;margin-top:8px}.status-card .meta{font-size:10.5px;color:var(--dim);margin-top:4px}.section-grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(300px,.55fr);gap:12px;margin-top:12px}.quick-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.quick{display:block;border:1px solid var(--line);border-radius:10px;padding:13px;background:var(--surface2);transition:.16s}.quick:hover{border-color:var(--line2);background:var(--surface3);transform:translateY(-1px)}.quick b{display:block;font-size:12px}.quick span{display:block;color:var(--dim);font-size:10.5px;margin-top:3px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}.table-wrap table{min-width:680px}.empty{padding:30px;text-align:center;color:var(--muted)}.proxy-add{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:12px}.dropbox{border:1px dashed var(--line2);border-radius:12px;padding:14px;background:var(--surface2)}.dropbox textarea{min-height:220px;background:var(--surface)}.helper{font-size:10.5px;color:var(--dim);margin-top:7px}.actionbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.badge-num{font:650 10px var(--mono);padding:3px 7px;border-radius:999px;background:var(--surface3);color:var(--muted)}@media(max-width:1000px){.status-strip{grid-template-columns:repeat(2,1fr)}.section-grid,.proxy-add{grid-template-columns:1fr}}@media(max-width:640px){.status-strip{grid-template-columns:1fr}.hero{padding:19px}.hero h1{font-size:27px}.quick-grid{grid-template-columns:1fr}.toast-stack{right:14px;bottom:14px}}

/* v3.5.2 shadcn-like control primitives */
.btn{appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;height:36px;padding:0 14px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text);font-size:12px;font-weight:560;line-height:1;white-space:nowrap;cursor:pointer;box-shadow:0 1px 2px rgba(0,0,0,.12);transition:background .14s,border-color .14s,box-shadow .14s,transform .06s}.btn:hover{background:var(--surface3)}.btn:active{transform:translateY(1px)}.btn:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:none;box-shadow:0 0 0 2px var(--bg),0 0 0 4px color-mix(in srgb,var(--text) 24%,transparent)}.btn:disabled{opacity:.5;pointer-events:none}.btn.primary{background:var(--text);border-color:var(--text);color:var(--bg)}.btn.primary:hover{opacity:.92}.btn.ghost{border-color:transparent;background:transparent;box-shadow:none}.btn.ghost:hover{background:var(--surface3)}.btn.danger{background:var(--bad);border-color:var(--bad);color:#fff}.btn.sm{height:30px;padding:0 10px;font-size:11px;border-radius:6px}
input,textarea,select{width:100%;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--text);padding:8px 10px;font-size:12px;box-shadow:0 1px 2px rgba(0,0,0,.08)}input{height:36px}textarea{min-height:110px;resize:vertical}select{height:36px}.tabs{display:inline-flex;align-items:center;height:36px;padding:3px;background:var(--surface3);border-radius:8px;border:1px solid var(--line);gap:2px}.tab{height:28px;padding:0 11px;border:0;border-radius:6px;background:transparent;color:var(--muted);font-size:11px;font-weight:560;cursor:pointer}.tab:hover{color:var(--text)}.tab.on{background:var(--bg);color:var(--text);box-shadow:0 1px 2px rgba(0,0,0,.22)}.tab-panel[hidden]{display:none!important}
'''
V3_THEME_JS = r'''function bgnToggleTheme(){const r=document.documentElement,n=r.dataset.theme==='light'?'dark':'light';r.dataset.theme=n;localStorage.setItem('bgn.theme',n)}document.documentElement.dataset.theme=localStorage.getItem('bgn.theme')||'dark';
function bgnToast(message,type='ok',title=''){const stack=document.getElementById('toast-stack')||(()=>{const s=document.createElement('div');s.id='toast-stack';s.className='toast-stack';document.body.appendChild(s);return s})();const t=document.createElement('div'),msg=String(message??'').trim()||'Done',label=title||({ok:'Done',error:'Something went wrong',warn:'Notice',loading:'Working…'}[type]||'Notice');t.className='toast '+type;t.innerHTML='<i class="toast-dot"></i><div><div class="toast-title"></div><div class="toast-msg"></div></div><button class="toast-close" aria-label="Dismiss">×</button>';t.querySelector('.toast-title').textContent=label;t.querySelector('.toast-msg').textContent=msg;t.querySelector('.toast-close').onclick=()=>{t.classList.remove('show');setTimeout(()=>t.remove(),180)};stack.appendChild(t);requestAnimationFrame(()=>t.classList.add('show'));if(type!=='loading'){const ttl=type==='error'?12000:type==='warn'?9000:8000;setTimeout(()=>{if(t.isConnected){t.classList.remove('show');setTimeout(()=>t.remove(),180)}},ttl)}return t}
function toast(m,type='ok'){return bgnToast(m,type)}function bgnToastUpdate(t,message,type='ok',title=''){if(!t||!t.isConnected)return bgnToast(message,type,title);t.className='toast '+type;t.querySelector('.toast-title').textContent=title||({ok:'Done',error:'Something went wrong',warn:'Notice'}[type]||'Done');t.querySelector('.toast-msg').textContent=String(message||'Done');if(type!=='loading'){const ttl=type==='error'?12000:type==='warn'?9000:8000;setTimeout(()=>{if(t.isConnected){t.classList.remove('show');setTimeout(()=>t.remove(),180)}},ttl)}return t}
function bgnFlash(message,type='ok',title=''){try{sessionStorage.setItem('bgn.flash',JSON.stringify({message:String(message||''),type,title,at:Date.now()}))}catch(e){}}
function bgnReload(message,type='ok',title='',delay=900){bgnFlash(message,type,title);setTimeout(()=>location.reload(),Math.max(1800,delay))}
document.addEventListener('DOMContentLoaded',()=>{try{const raw=sessionStorage.getItem('bgn.flash');if(!raw)return;sessionStorage.removeItem('bgn.flash');const f=JSON.parse(raw);if(Date.now()-(f.at||0)<15000)bgnToast(f.message,f.type||'ok',f.title||'')}catch(e){}});
async function bgnJson(r){const ct=r.headers.get('content-type')||'';if(ct.includes('application/json'))return await r.json();return {message:(await r.text()).trim()}}function bgnResultMessage(d,fallback='Saved'){if(!d)return fallback;if(d.detail)return typeof d.detail==='string'?d.detail:JSON.stringify(d.detail);if(d.message)return d.message;const parts=[];for(const [k,v] of Object.entries(d)){if(v===null||v===undefined||typeof v==='object')continue;parts.push(k.replaceAll('_',' ')+' '+v)}return parts.join(' · ')||fallback}
document.addEventListener('submit',async e=>{const f=e.target;if(!(f instanceof HTMLFormElement)||f.dataset.native==='1'||(f.method||'get').toLowerCase()==='get')return;if(!f.action.startsWith(location.origin))return;e.preventDefault();const submit=e.submitter;if(submit)submit.disabled=true;const pending=bgnToast('Sending request…','loading');try{const r=await fetch(f.action,{method:(f.method||'POST').toUpperCase(),body:new FormData(f),credentials:'same-origin'});if(!r.ok){const d=await bgnJson(r);throw new Error(bgnResultMessage(d,'HTTP '+r.status))}if(r.redirected){bgnToastUpdate(pending,'Changes saved','ok');bgnFlash('Changes saved','ok');setTimeout(()=>{location.href=r.url},900);return}const d=await bgnJson(r);bgnToastUpdate(pending,bgnResultMessage(d),'ok');if(f.dataset.reload!=='0')bgnReload(bgnResultMessage(d),'ok','',900)}catch(err){bgnToastUpdate(pending,err.message||String(err),'error')}finally{if(submit)submit.disabled=false}});window.addEventListener('unhandledrejection',e=>{if(e.reason&&e.reason.message)bgnToast(e.reason.message,'error')});'''

def page(title: str, content: str, active: str = "", raw_js: str = "", wide: bool = False) -> str:
    nav=[('dash','/dashboard','Overview'),('chat','/chat','Chat'),('browser','/browser-view','Browser'),('pool','/pool','Network'),('jars','/jars','Accounts'),('models','/models-page','Models'),('keys','/api-keys','API keys'),('errors','/errors','Errors'),('logs','/logs','Logs')]
    links=''.join(f'<a class="{"on" if active==k else ""}" href="{h}">{esc(l)}</a>' for k,h,l in nav)
    return f'''<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>{esc(title)} · Bridgena</title><style>{V3_CSS}</style></head><body><header class="topbar"><a class="brand" href="/dashboard"><span class="dot"></span><span>Bridgena</span><small>{esc(BUILD_STAMP)}</small></a><div class="spacer"></div><div class="v3-health"><i></i><span>control plane online</span></div><button class="btn sm ghost" onclick="bgnToggleTheme()">◐</button><a class="btn sm ghost" href="/logout">Sign out</a></header><div class="shell"><aside class="rail"><div class="rail-label">Workspace</div>{links}</aside><main class="main">{content}</main></div><div id="toast-stack" class="toast-stack"></div><script>{V3_THEME_JS}{raw_js}</script></body></html>'''

def login_page(err: str = "") -> str:
    return f'''<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Bridgena</title><style>{V3_CSS}</style></head><body><div class="auth"><div class="authbox"><div class="authlogo">B</div><h1>Bridgena</h1><p>Sign in to the v3 control plane.</p><form class="card" method="post" action="/login" data-native="1"><label for="p">Dashboard password</label><input id="p" name="password" type="password" autocomplete="current-password" autofocus><button class="btn primary" style="width:100%;margin-top:14px">Continue</button><div class="err">{esc(err)}</div></form><div style="text-align:center;margin-top:14px"><button class="btn sm ghost" onclick="bgnToggleTheme()">◐ Theme</button></div></div></div><script>{V3_THEME_JS}</script></body></html>'''

def dashboard_page(overview: dict) -> str:
    m=overview['metrics']; pool=overview.get('pool') or []; jars=overview.get('jars') or []
    distinct_routes=len({_normalize_proxy(j.get('proxy') or '') for j in jars if _normalize_proxy(j.get('proxy') or '')})
    prow=''.join(f"<tr><td class='mono'>{esc(r.get('display') or '—')}</td><td>{_verdict_pill(r.get('verdict','unknown'))}</td><td class='muted'>{esc(r.get('latency') or '—')}{'ms' if r.get('latency') else ''}</td><td class='muted'>{esc((r.get('why') or '—')[:90])}</td></tr>" for r in pool[:8]) or "<tr><td colspan='4' class='empty'>No proxy telemetry yet.</td></tr>"
    jrows=''.join("<tr><td><b>"+esc(j.get('name') or j.get('email') or 'Account')+"</b></td><td class='muted'>"+esc(j.get('persona') or 'default')+"</td><td>"+("<span class='pill ok'>authenticated</span>" if jar_has_auth(j) and not j.get('expired') else "<span class='pill bad'>attention</span>")+"</td><td class='mono muted'>"+esc((_proxy_hkey(_normalize_proxy(j.get('proxy') or ''))[:9]+'…') if j.get('proxy') else '—')+"</td></tr>" for j in jars[:8]) or "<tr><td colspan='4' class='empty'>No accounts configured.</td></tr>"
    logl=''.join(f"<div class='{esc(x.get('lvl','INFO'))}'>{esc(x.get('line') or x.get('message') or '')}</div>" for x in overview.get('logtail',[])[-35:])
    content = f'''<div class="hero"><div class="eyebrow">Operations workspace</div><h1>Bridgena control plane</h1><p>Request health, keeper fleet, network capacity, models and API access in one operational workspace.</p><div class="hero-actions"><a class="btn primary" href="/chat">Open chat</a><a class="btn" href="/pool">Manage network</a><a class="btn" href="/browser-view">Inspect browsers</a><button class="btn ghost" onclick="refreshOverview()">Refresh telemetry</button></div></div>
<div class="status-strip"><div class="status-card"><div class="label"><span>Healthy exits</span><span class="pill ok">network</span></div><div class="num">{m['alive']}</div><div class="meta">{m['pool_total']} configured · {m['flagged']} restricted</div></div><div class="status-card"><div class="label"><span>Keeper fleet</span><span class="pill {'ok' if m['keepers_live'] else 'warn'}">browser</span></div><div class="num">{m['keepers_live']}</div><div class="meta">{m['jars_ok']} authenticated of {m['jars_total']} accounts</div></div><div class="status-card"><div class="label"><span>Distinct routes</span><span class="pill ok">allocation</span></div><div class="num">{distinct_routes}</div><div class="meta">assigned across current accounts</div></div><div class="status-card"><div class="label"><span>Models</span><span class="pill ok">catalog</span></div><div class="num">{m['models']}</div><div class="meta">published through the compatibility API</div></div></div>
<div class="section-grid"><section class="card"><div class="row"><div><div class="eyebrow">Network</div><h3 style="margin:2px 0 14px">Exit health</h3></div><span class="spacer"></span><a class="btn sm ghost" href="/pool">View all →</a></div><div class="table-wrap"><table><thead><tr><th>Exit</th><th>State</th><th>RTT</th><th>Diagnosis</th></tr></thead><tbody>{prow}</tbody></table></div></section><section class="card"><div class="eyebrow">Shortcuts</div><h3 style="margin:2px 0 14px">Quick actions</h3><div class="quick-grid"><a class="quick" href="/pool"><b>Add proxies</b><span>Paste, upload and validate exits</span></a><a class="quick" href="/jars"><b>Accounts</b><span>Manage keepers and personas</span></a><a class="quick" href="/api-keys"><b>API keys</b><span>Create and revoke credentials</span></a><a class="quick" href="/models-page"><b>Models</b><span>Inspect compatibility catalog</span></a></div><div class="kv" style="margin-top:14px"><span>Healthy ratio</span><b>{m['alive']}/{m['pool_total']}</b></div><div class="kv"><span>Authenticated accounts</span><b>{m['jars_ok']}/{m['jars_total']}</b></div><div class="kv"><span>Distinct routes</span><b>{distinct_routes}</b></div></section></div>
<div class="section-grid"><section class="card"><div class="row"><div><div class="eyebrow">Accounts</div><h3 style="margin:2px 0 14px">Keeper fleet</h3></div><span class="spacer"></span><a class="btn sm ghost" href="/jars">Manage →</a></div><div class="table-wrap"><table><thead><tr><th>Account</th><th>Persona</th><th>Auth</th><th>Route ID</th></tr></thead><tbody>{jrows}</tbody></table></div></section><section class="card"><div class="row"><div><div class="eyebrow">Runtime</div><h3 style="margin:2px 0 14px">Recent activity</h3></div><span class="spacer"></span><a class="btn sm ghost" href="/logs">Logs →</a></div><div class="console" id="cons" style="height:300px">{logl}</div></section></div>'''
    js=r'''async function refreshOverview(){const t=bgnToast('Refreshing telemetry…','loading');try{const r=await fetch('/proxies/api/snapshot',{cache:'no-store'});if(!r.ok)throw new Error('Telemetry refresh failed');const d=await r.json();bgnToastUpdate(t,'Received '+d.length+' network rows','ok');setTimeout(()=>location.reload(),500)}catch(e){bgnToastUpdate(t,e.message||String(e),'error')}}async function consRefresh(){try{const r=await fetch('/debug-logs/data',{cache:'no-store'});if(!r.ok)return;const d=await r.json(),c=document.getElementById('cons');c.innerHTML=d.slice(-35).map(x=>'<div class="'+(x.lvl||'INFO')+'">'+String(x.line||x.message||'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]))+'</div>').join('');c.scrollTop=c.scrollHeight}catch(e){}}setInterval(consRefresh,3500);'''
    return page('Overview', content, 'dash', js)

def chat_page(models: list, default_model: str) -> str:
    names=[m.get('name','') for m in models if isinstance(m,dict) and m.get('name')]
    mj=_json.dumps(names,ensure_ascii=False).replace('</','<\\/')
    dj=_json.dumps(default_model or (names[0] if names else 'auto'),ensure_ascii=False)
    template=r'''<!doctype html><html data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Chat · Bridgena</title><style>
:root{--bg:#09090b;--side:#0d0d0f;--soft:#18181b;--line:#27272a;--text:#fafafa;--muted:#a1a1aa;--dim:#71717a;--ok:#4ade80;--bad:#fb7185;--warn:#fbbf24}[data-theme=light]{--bg:#fff;--side:#fafafa;--soft:#f4f4f5;--line:#e4e4e7;--text:#09090b;--muted:#71717a;--dim:#a1a1aa;--ok:#16a34a;--bad:#e11d48;--warn:#b45309}*{box-sizing:border-box}html,body{margin:0;height:100%;overflow:hidden;background:var(--bg);color:var(--text);font:14px/1.6 Inter,ui-sans-serif,system-ui,sans-serif}button,input,textarea{font:inherit}.app{height:100%;display:grid;grid-template-columns:260px minmax(0,1fr)}.side{display:flex;flex-direction:column;border-right:1px solid var(--line);background:var(--side);min-width:0}.sidehead{height:60px;display:flex;align-items:center;gap:10px;padding:0 14px}.logo{width:30px;height:30px;border-radius:9px;background:var(--text);color:var(--bg);display:grid;place-items:center;font-size:11px;font-weight:800}.sidebody{flex:1;overflow:auto;padding:8px}.new,.thread,.ghost,.modelbtn,.chipbtn{border:0;color:inherit;cursor:pointer}.new{width:100%;height:39px;border-radius:8px;text-align:left;padding:0 11px;background:transparent}.new:hover,.thread:hover,.ghost:hover,.modelbtn:hover,.chipbtn:hover{background:var(--soft)}.label{padding:22px 10px 8px;color:var(--dim);text-transform:uppercase;font-size:10px;font-weight:650;letter-spacing:.07em}.thread{width:100%;display:flex;background:transparent;border-radius:8px;padding:9px 10px;color:var(--muted);text-align:left}.thread span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.thread.on{background:var(--soft);color:var(--text)}.sidefoot{padding:9px;border-top:1px solid var(--line)}.sidefoot a{display:block;color:var(--muted);text-decoration:none;padding:9px 10px;border-radius:8px}.sidefoot a:hover{background:var(--soft);color:var(--text)}.main{min-width:0;min-height:0;display:flex;flex-direction:column}.top{height:60px;display:flex;align-items:center;gap:8px;padding:0 16px;border-bottom:1px solid var(--line)}.modelwrap{position:relative}.modelbtn{height:36px;max-width:min(480px,60vw);border-radius:8px;padding:0 10px;background:transparent;font-weight:620;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.status{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--muted);font-size:11px}.status i{width:7px;height:7px;border-radius:50%;background:var(--ok)}.ghost{width:35px;height:35px;border-radius:8px;background:transparent}.picker{display:none;position:absolute;top:42px;left:0;z-index:40;width:min(500px,calc(100vw - 30px));background:var(--bg);border:1px solid var(--line);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.35);overflow:hidden}.picker.open{display:block}.picker input{width:100%;height:42px;border:0;border-bottom:1px solid var(--line);outline:0;background:transparent;color:var(--text);padding:0 12px}.modellist{max-height:360px;overflow:auto;padding:5px}.modelopt{width:100%;border:0;border-radius:7px;background:transparent;color:var(--text);padding:9px 10px;text-align:left;cursor:pointer}.modelopt:hover,.modelopt.on{background:var(--soft)}.scroll{flex:1;min-height:0;overflow:auto;overscroll-behavior:contain}.conversation{width:min(900px,100%);margin:0 auto;padding:42px 24px 205px}.welcome{min-height:58vh;display:grid;place-items:center;text-align:center}.welcome h1{font-size:32px;letter-spacing:-.045em;margin:0 0 8px}.welcome p{margin:0;color:var(--muted)}.suggestions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-top:24px;width:min(580px,100%)}.chipbtn{padding:11px 13px;text-align:left;border:1px solid var(--line);border-radius:10px;background:transparent;color:var(--muted)}.msg{display:grid;grid-template-columns:32px minmax(0,1fr);gap:13px;margin-bottom:34px}.avatar{width:31px;height:31px;border-radius:9px;background:var(--soft);display:grid;place-items:center;font-size:10px;font-weight:800}.msg.user{display:flex;justify-content:flex-end;margin-left:18%}.msg.user .avatar,.msg.user .head{display:none}.msg.user .body{max-width:82%;padding:10px 14px;border-radius:17px;background:var(--soft)}.head{font-size:11px;color:var(--dim);margin-bottom:5px;font-weight:650}.body{font-size:15px;line-height:1.78;word-break:break-word}.body pre{overflow:auto;background:#050505;border:1px solid var(--line);border-radius:9px;padding:12px;font:12px/1.6 ui-monospace,monospace}.body code{font-family:ui-monospace,monospace;background:var(--soft);border-radius:5px;padding:1px 4px}.body pre code{background:none;padding:0}.reason{margin:0 0 12px;color:var(--muted);font-size:12px;border-left:2px solid var(--line);padding-left:10px;white-space:pre-wrap}.error{color:var(--bad)}.dock{position:fixed;left:260px;right:0;bottom:0;padding:54px 18px 18px;background:linear-gradient(transparent,var(--bg) 48%);pointer-events:none}.compose{pointer-events:auto;width:min(900px,100%);margin:0 auto;border:1px solid var(--line);border-radius:20px;background:var(--bg);padding:12px;box-shadow:0 10px 36px rgba(0,0,0,.2)}.compose textarea{width:100%;min-height:44px;max-height:190px;resize:none;border:0;outline:0;background:transparent;color:var(--text);padding:4px}.composefoot{display:flex;align-items:center;color:var(--dim);font-size:10px}.send{margin-left:auto;width:34px;height:34px;border:0;border-radius:50%;background:var(--text);color:var(--bg);cursor:pointer}.send.stop{background:var(--bad);color:#fff}.runtime{position:fixed;z-index:70;top:72px;right:14px;bottom:14px;width:min(520px,calc(100vw - 28px));background:var(--side);border:1px solid var(--line);border-radius:13px;box-shadow:0 24px 70px rgba(0,0,0,.4);padding:12px;display:none}.runtime.open{display:flex;flex-direction:column}.runtime pre{flex:1;overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;color:var(--muted);white-space:pre-wrap;font:11px/1.5 ui-monospace,monospace}.mobile{display:none}@media(max-width:760px){.app{grid-template-columns:1fr}.side{position:fixed;inset:0 auto 0 0;width:260px;z-index:90;transform:translateX(-100%);transition:.18s}.side.open{transform:none}.mobile{display:block}.dock{left:0}.conversation{padding:28px 15px 190px}.suggestions{grid-template-columns:1fr}.msg.user{margin-left:5%}}
</style></head><body><div class=app><aside class=side id=side><div class=sidehead><div class=logo>B</div><b>Bridgena</b></div><div class=sidebody><button class=new onclick="newChat()">＋ New chat</button><div class=label>Recent</div><div id=threads></div></div><div class=sidefoot><a href="/dashboard">← Control plane</a></div></aside><main class=main><header class=top><button class="ghost mobile" onclick="side.classList.toggle('open')">☰</button><div class=modelwrap><button class=modelbtn id=modelBtn onclick="togglePicker()">Model</button><div class=picker id=picker><input id=modelSearch placeholder="Search models"><div class=modellist id=modelList></div></div></div><div class=status><i id=statusDot></i><span id=statusText>Ready</span></div><button class=ghost onclick="toggleRuntime()">⌁</button><button class=ghost onclick="toggleTheme()">◐</button></header><div class=scroll id=scroll><div class=conversation id=conversation></div></div><div class=dock><div class=compose><textarea id=input placeholder="Message Bridgena"></textarea><div class=composefoot><span>Enter to send · Shift+Enter newline</span><button class=send id=send onclick="sendOrStop()">↑</button></div></div></div></main></div><aside class=runtime id=runtime><div style="display:flex;align-items:center"><b>Runtime signal</b><button class=ghost style="margin-left:auto" onclick="toggleRuntime()">×</button></div><pre id=signal>Waiting for activity…</pre></aside><script>
const MODELS=__MODELS__,DEFAULT_MODEL=__DEFAULT__,$=id=>document.getElementById(id),side=$('side');let controller=null,busy=false,model=localStorage.getItem('bgn.v3.model')||DEFAULT_MODEL,chatId=localStorage.getItem('bgn.v3.chat')||newId();function newId(){return 'c-'+crypto.getRandomValues(new Uint32Array(2)).join('-')}function store(){try{return JSON.parse(localStorage.getItem('bgn.v3.chats')||'{}')}catch(e){return {}}}function saveStore(v){localStorage.setItem('bgn.v3.chats',JSON.stringify(v))}function current(){const s=store();return s[chatId]||{id:chatId,title:'New chat',messages:[],updated:Date.now()}}function saveCurrent(c){const s=store();s[chatId]=c;saveStore(s);localStorage.setItem('bgn.v3.chat',chatId);renderThreads()}function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function md(s){let x=esc(s);x=x.replace(/```([\s\S]*?)```/g,(_,b)=>'<pre><code>'+b+'</code></pre>');x=x.replace(/`([^`]+)`/g,'<code>$1</code>');x=x.replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>');return x.replace(/\n/g,'<br>')}function renderThreads(){const s=store(),items=Object.values(s).sort((a,b)=>(b.updated||0)-(a.updated||0)).slice(0,60);$('threads').innerHTML=items.map(c=>'<button class="thread '+(c.id===chatId?'on':'')+'" onclick="openChat(\''+c.id.replace(/'/g,'')+'\')"><span>'+esc(c.title||'New chat')+'</span></button>').join('')}function openChat(id){chatId=id;localStorage.setItem('bgn.v3.chat',id);renderConversation();renderThreads();side.classList.remove('open')}function newChat(){chatId=newId();saveCurrent({id:chatId,title:'New chat',messages:[],updated:Date.now()});renderConversation()}function renderConversation(){const c=current(),root=$('conversation');root.innerHTML='';if(!c.messages.length){root.innerHTML='<div class=welcome><div><div class=logo style="margin:0 auto 16px;width:42px;height:42px">B</div><h1>How can I help?</h1><p>Chat through the same v3 compatibility surface your clients use.</p><div class=suggestions><button class=chipbtn onclick="usePrompt(\'Review this code and identify reliability risks\')">Review code</button><button class=chipbtn onclick="usePrompt(\'Help me diagnose a failed request\')">Diagnose a request</button></div></div></div>';return}c.messages.forEach(m=>appendRendered(m.role,m.content,m.reasoning||''));scrollBottom(false)}function appendRendered(role,content,reasoning=''){const root=$('conversation'),w=root.querySelector('.welcome');if(w)w.remove();const d=document.createElement('div');d.className='msg '+role;d.innerHTML='<div class=avatar>'+(role==='user'?'U':'B')+'</div><div><div class=head>'+(role==='user'?'You':'Bridgena')+'</div><div class=body>'+(reasoning?'<div class=reason>'+esc(reasoning)+'</div>':'')+md(content)+'</div></div>';root.appendChild(d);return d.querySelector('.body')}function setStatus(t,state='ok'){$('statusText').textContent=t;$('statusDot').style.background=state==='bad'?'var(--bad)':state==='busy'?'var(--warn)':'var(--ok)'}function scrollBottom(s=true){$('scroll').scrollTo({top:$('scroll').scrollHeight,behavior:s?'smooth':'auto'})}function toggleTheme(){const r=document.documentElement,n=r.dataset.theme==='light'?'dark':'light';r.dataset.theme=n;localStorage.setItem('bgn.theme',n)}document.documentElement.dataset.theme=localStorage.getItem('bgn.theme')||'dark';function togglePicker(){$('picker').classList.toggle('open');if($('picker').classList.contains('open')){$('modelSearch').value='';renderModels('');$('modelSearch').focus()}}function renderModels(q=''){const x=q.toLowerCase(),arr=MODELS.filter(m=>m.toLowerCase().includes(x)).slice(0,250);$('modelList').innerHTML=arr.map(m=>'<button class="modelopt '+(m===model?'on':'')+'" data-m="'+esc(m)+'">'+esc(m)+'</button>').join('')||'<div style="padding:20px;color:var(--muted)">No matching models</div>';document.querySelectorAll('.modelopt').forEach(b=>b.onclick=()=>{model=b.dataset.m;localStorage.setItem('bgn.v3.model',model);$('modelBtn').textContent=model;$('picker').classList.remove('open')})}$('modelSearch').addEventListener('input',e=>renderModels(e.target.value));$('modelBtn').textContent=model;renderModels('');function usePrompt(s){$('input').value=s;$('input').focus();autoSize()}function autoSize(){const t=$('input');t.style.height='44px';t.style.height=Math.min(190,t.scrollHeight)+'px'}$('input').addEventListener('input',autoSize);$('input').addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendOrStop()}});function toggleRuntime(){$('runtime').classList.toggle('open')}async function refreshSignal(){try{const r=await fetch('/debug-logs/data',{cache:'no-store'});if(!r.ok)return;const d=await r.json();$('signal').textContent=d.slice(-120).map(x=>x.line||x.message||'').join('\n')}catch(e){}}setInterval(refreshSignal,2500);function saveMsg(role,content,reasoning=''){const c=current();c.messages.push({role,content,reasoning,ts:Date.now()});if(c.title==='New chat'&&role==='user')c.title=content.replace(/\s+/g,' ').slice(0,48)||'New chat';c.updated=Date.now();saveCurrent(c)}function sendOrStop(){if(busy){controller?.abort();return}sendMessage()}async function sendMessage(){const input=$('input'),text=input.value.trim();if(!text)return;busy=true;controller=new AbortController();input.value='';autoSize();$('send').textContent='■';$('send').classList.add('stop');setStatus('Generating','busy');saveMsg('user',text);appendRendered('user',text);const body=appendRendered('assistant','');let acc='',reason='';scrollBottom();try{const c=current();const messages=c.messages.slice(-24).map(m=>({role:m.role==='assistant'?'assistant':'user',content:m.content}));const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},signal:controller.signal,body:JSON.stringify({model,messages,stream:true,chat_id:chatId,stream_options:{include_usage:true}})});if(!r.ok)throw new Error('HTTP '+r.status+': '+await r.text());const rd=r.body.getReader(),dec=new TextDecoder();let buf='';while(true){const {done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});let cut;while((cut=buf.indexOf('\n'))>=0){const line=buf.slice(0,cut).trim();buf=buf.slice(cut+1);if(!line.startsWith('data: '))continue;const raw=line.slice(6);if(raw==='[DONE]')continue;let j;try{j=JSON.parse(raw)}catch(e){continue}if(j.error)throw new Error(j.error.message||'Bridge stream error');const d=j.choices?.[0]?.delta||{};if(d.reasoning_content)reason+=d.reasoning_content;if(d.content)acc+=d.content;body.innerHTML=(reason?'<div class=reason>'+esc(reason)+'</div>':'')+md(acc);scrollBottom(false)}}if(!acc)throw new Error('The upstream completed without assistant content.');saveMsg('assistant',acc,reason);setStatus('Ready')}catch(e){if(e.name==='AbortError'){body.innerHTML=(reason?'<div class=reason>'+esc(reason)+'</div>':'')+md(acc||'Generation stopped.');if(acc)saveMsg('assistant',acc,reason);setStatus('Stopped')}else{const err='<div class=error>'+esc(e.message||e)+'</div>';if(acc||reason){body.innerHTML=(reason?'<div class=reason>'+esc(reason)+'</div>':'')+md(acc)+err;if(acc)saveMsg('assistant',acc,reason)}else{body.innerHTML=err}setStatus('Error','bad')}}finally{busy=false;controller=null;$('send').textContent='↑';$('send').classList.remove('stop');renderThreads()}}renderThreads();renderConversation();refreshSignal();document.addEventListener('click',e=>{if(!$('picker').contains(e.target)&&e.target!==$('modelBtn'))$('picker').classList.remove('open')});
</script></body></html>'''
    return template.replace('__MODELS__',mj).replace('__DEFAULT__',dj)


# ────────────────────────── module: api.py ──────────────────────────────

# ============================================================
# v2 API — FastAPI surface. Every legacy route kept (the VPS bookmarks
# them); chat page talks to /v1/chat/completions exactly like external
# OpenAI clients do — one protocol, one engine behind both.
# ============================================================
import asyncio, json, os, time
from contextlib import asynccontextmanager
from typing import Optional

import glob
from fastapi import FastAPI, File, Form, Request, HTTPException, UploadFile, status, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse, Response
from fastapi.security import APIKeyHeader

app = FastAPI(title="Bridgena", version="4.0.0")

# ---------- v3 optional VNC integration ----------
_V3_VNC_PROCS=[]
_V3_VNC_DISPLAY=os.environ.get('BRIDGENA_VNC_DISPLAY',':99')
_V3_VNC_PORT=int(os.environ.get('BRIDGENA_VNC_PORT','5900'))
_V3_VNC_ENABLED=os.environ.get('BRIDGENA_VNC','0').lower() in ('1','true','yes','on')
_V3_NOVNC_ROOTS=('/usr/share/novnc','/opt/novnc')
async def _v3_vnc_start():
    if not _V3_VNC_ENABLED:return False,'disabled'
    import shutil as _shutil,subprocess as _subprocess
    xvfb,x11vnc=_shutil.which('Xvfb'),_shutil.which('x11vnc')
    if not xvfb or not x11vnc:
        log('WARN','v3 VNC requested but Xvfb/x11vnc are not installed');return False,'missing dependencies'
    display_num=_V3_VNC_DISPLAY.lstrip(':').split('.')[0]
    try:
        if not os.path.exists(f'/tmp/.X11-unix/X{display_num}'):
            _V3_VNC_PROCS.append(_subprocess.Popen([xvfb,_V3_VNC_DISPLAY,'-screen','0',os.environ.get('BRIDGENA_VNC_SCREEN','1440x900x24'),'-nolisten','tcp','-ac'],stdout=_subprocess.DEVNULL,stderr=_subprocess.DEVNULL));await asyncio.sleep(.35)
        os.environ['DISPLAY']=_V3_VNC_DISPLAY
        _V3_VNC_PROCS.append(_subprocess.Popen([x11vnc,'-display',_V3_VNC_DISPLAY,'-rfbport',str(_V3_VNC_PORT),'-localhost','-forever','-shared','-nopw','-noxdamage'],stdout=_subprocess.DEVNULL,stderr=_subprocess.DEVNULL))
        log('OK',f'v3 VNC display {_V3_VNC_DISPLAY} ready on localhost:{_V3_VNC_PORT}');return True,'ready'
    except Exception as exc:
        log('ERROR',f'v3 VNC start failed: {type(exc).__name__}: {exc}');return False,str(exc)
async def _v3_vnc_stop():
    processes=list(reversed(_V3_VNC_PROCS))
    for p in processes:
        try:
            if p.poll() is None:p.terminate()
        except Exception:pass
    for p in processes:
        try:
            if p.poll() is None:await asyncio.to_thread(p.wait,5)
        except Exception:
            try:p.kill()
            except Exception:pass
    _V3_VNC_PROCS.clear()
def _v3_novnc_root():
    for root in _V3_NOVNC_ROOTS:
        if os.path.isfile(os.path.join(root,'vnc.html')):return root
    return None
@app.websocket('/vnc/ws')
async def v3_vnc_ws(ws: WebSocket):
    if not verify_session_token(ws.cookies.get('session_id','')):
        await ws.close(code=4401);return
    origin=ws.headers.get('origin','')
    if origin and urlparse(origin).netloc != ws.headers.get('host',''):
        await ws.close(code=4403);return
    if not _V3_VNC_ENABLED:
        await ws.close(code=4404);return
    try: reader,writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',_V3_VNC_PORT),timeout=5)
    except Exception:
        await ws.close(code=1013);return
    await ws.accept()
    async def c2v():
        try:
            while True:
                msg=await ws.receive()
                if msg.get('type')=='websocket.disconnect':break
                data=msg.get('bytes')
                if data is None and msg.get('text') is not None:data=msg['text'].encode('latin1','ignore')
                if data:writer.write(data);await writer.drain()
        finally:
            try:writer.close()
            except Exception:pass
    async def v2c():
        try:
            while True:
                data=await reader.read(65536)
                if not data:break
                await ws.send_bytes(data)
        finally:
            try:await ws.close()
            except Exception:pass
    tasks=[asyncio.create_task(c2v(),name='vnc-browser-to-server'),asyncio.create_task(v2c(),name='vnc-server-to-browser')]
    try:
        _,pending=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        for task in pending:task.cancel()
        await asyncio.gather(*pending,return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        try:writer.close();await writer.wait_closed()
        except Exception:pass
@app.get('/vnc',response_class=HTMLResponse)
async def v3_vnc_page(request: Request):
    g=await _page_guard(request)
    if g:return g
    root=_v3_novnc_root()
    if not _V3_VNC_ENABLED:return HTMLResponse(page('VNC','<div class=pagehead><div><h1>VNC console</h1><p>Optional real VNC for headed keeper sessions.</p></div></div><div class=card><h3>Disabled</h3><p class=muted>Set <code>BRIDGENA_VNC=1</code> and install the bundled VNC dependencies. The Browser Observer works without them.</p><a class="btn primary" href="/browser-view">Open Browser Observer</a></div>','browser'))
    if not root:return HTMLResponse(page('VNC','<div class=pagehead><div><h1>VNC console</h1><p>VNC is enabled, but noVNC web assets were not found.</p></div></div><div class=card><p class=muted>Install the <code>novnc</code> system package and restart Bridgena.</p><a class=btn href="/browser-view">Browser Observer</a></div>','browser'))
    return HTMLResponse('''<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>VNC · Bridgena</title><style>html,body{margin:0;width:100%;height:100%;background:#09090b}iframe{border:0;width:100%;height:100%}</style></head><body><iframe src="/novnc/vnc.html?autoconnect=1&resize=scale&path=vnc%2Fws"></iframe></body></html>''')

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
_dashboard_sessions: dict = {}
_recent_api_requests: dict = {}
_recent_api_requests_lock = threading.Lock()
_duplicate_notices: dict = {}
_login_failures: dict = {}
_login_failures_lock = threading.Lock()


_ERROR_EVENTS_FILE = os.environ.get("BRIDGENA_ERROR_EVENTS_FILE", "errors.jsonl").strip() or "errors.jsonl"
_ERROR_EVENTS_MAX = max(100, min(5000, int(os.environ.get("BRIDGENA_ERROR_EVENTS_MAX", "1000"))))
_error_events = deque(maxlen=_ERROR_EVENTS_MAX)
_error_events_lock = threading.Lock()

_PUBLIC_ERROR_VARIANTS = {
    "auth": (
        "Your API key couldn't get past the bouncer. Error ID: {id}",
        "The velvet rope said nope. Error ID: {id}",
        "Our tiny security guard couldn't verify this request. Error ID: {id}",
    ),
    "rate": (
        "The request queue is doing cardio right now. Error ID: {id}",
        "The response hamsters need a tiny cooldown. Error ID: {id}",
        "Too many pigeons arrived at once. Error ID: {id}",
    ),
    "request": (
        "That request confused the carrier pigeon. Error ID: {id}",
        "Our message sorter couldn't make sense of that envelope. Error ID: {id}",
        "The request took a wrong turn at the post office. Error ID: {id}",
    ),
    "server": (
        "The carrier pigeon streaming your response died! Error ID: {id}",
        "A tiny internet gremlin dropped your response. Error ID: {id}",
        "The response hamster tripped over a cable. Error ID: {id}",
        "Our packet train missed its station. Error ID: {id}",
        "One of the server goblins misplaced your message. Error ID: {id}",
        "The response conveyor belt made an unexpected noise. Error ID: {id}",
    ),
}


def _safe_internal_error_detail(value: Any) -> str:
    """Keep useful operator diagnostics without persisting obvious secrets."""
    if isinstance(value, (dict, list, tuple)):
        try:
            raw = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            raw = str(value)
    else:
        raw = str(value or "")
    raw = redact(raw)
    # Second line of defense for credentials that may not match redact().
    raw = re.sub(r'(?i)(authorization\s*[:=]\s*)(bearer\s+)?[^\s,;"]+', r'\1[redacted]', raw)
    raw = re.sub(r'(?i)((?:api[_-]?key|password|passwd|secret|token)\s*[:=]\s*)[^\s,;"]+', r'\1[redacted]', raw)
    raw = re.sub(r'(?i)(https?://[^:/\s]+:)[^@\s]+@', r'\1[redacted]@', raw)
    return raw[:12000]


def _new_error_id() -> str:
    stamp = time.strftime("%H%M%S", time.localtime())
    suffix = secrets.token_hex(4).upper()
    return f"ERR-{stamp}-{suffix}"


def _public_error_category(status_code: int) -> str:
    status_code = int(status_code or 500)
    if status_code in (401, 403):
        return "auth"
    if status_code == 429:
        return "rate"
    if 400 <= status_code < 500:
        return "request"
    return "server"


def _public_error_phrase(error_id: str, status_code: int) -> str:
    variants = _PUBLIC_ERROR_VARIANTS[_public_error_category(status_code)]
    # Stable phrase for a given Error ID; screenshots and support chats match.
    pick = int(hashlib.sha256(error_id.encode("utf-8")).hexdigest()[:8], 16) % len(variants)
    return variants[pick].format(id=error_id)


def _load_error_events() -> None:
    if not os.path.isfile(_ERROR_EVENTS_FILE):
        return
    try:
        with open(_ERROR_EVENTS_FILE, "r", encoding="utf-8") as fh:
            rows = fh.readlines()[-_ERROR_EVENTS_MAX:]
        with _error_events_lock:
            for line in rows:
                try:
                    row = json.loads(line)
                    if isinstance(row, dict) and row.get("id"):
                        _error_events.append(row)
                except Exception:
                    continue
    except Exception as exc:
        log("WARN", f"Error registry load failed: {type(exc).__name__}: {exc}")


def _persist_error_event(row: dict) -> None:
    try:
        parent = os.path.dirname(os.path.abspath(_ERROR_EVENTS_FILE))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(_ERROR_EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        # Cheap bounded persistence: compact once the file grows much larger
        # than the configured ring. Errors are infrequent, so no hot-path cost.
        try:
            if os.path.getsize(_ERROR_EVENTS_FILE) > 8 * 1024 * 1024:
                with _error_events_lock:
                    snapshot = list(_error_events)
                tmp = _ERROR_EVENTS_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    for item in snapshot:
                        fh.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
                os.replace(tmp, _ERROR_EVENTS_FILE)
        except Exception:
            pass
    except Exception as exc:
        log("WARN", f"Error registry persist failed: {type(exc).__name__}: {exc}")


def _register_private_error(*, status_code: int, detail: Any, source: str,
                            path: str = "", method: str = "",
                            protocol: str = "", context: Optional[dict] = None,
                            exception_type: str = "") -> tuple:
    error_id = _new_error_id()
    safe_detail = _safe_internal_error_detail(detail)
    safe_context = {}
    for key, value in (context or {}).items():
        # Never persist prompts, API keys, cookies, or full auth headers.
        if str(key).lower() in {
            "prompt", "messages", "cookies", "authorization", "api_key",
            "password", "token", "recaptchav3token", "recaptchav2token",
        }:
            continue
        safe_context[str(key)[:80]] = _safe_internal_error_detail(value)[:2000]

    row = {
        "id": error_id,
        "ts": time.time(),
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "status": int(status_code or 500),
        "source": str(source or "api")[:120],
        "protocol": str(protocol or "")[:80],
        "method": str(method or "")[:16],
        "path": str(path or "")[:500],
        "exception_type": str(exception_type or "")[:160],
        "detail": safe_detail,
        "context": safe_context,
    }
    with _error_events_lock:
        _error_events.append(row)
    _persist_error_event(row)
    log("WARN", f"Customer error {error_id} · HTTP {row['status']} · {row['source']} · "
                f"{row['method']} {row['path']} · internal: {safe_detail[:260]}")
    return error_id, _public_error_phrase(error_id, row["status"])


def _find_private_error(error_id: str) -> Optional[dict]:
    needle = str(error_id or "").strip().upper()
    if not needle:
        return None
    with _error_events_lock:
        for row in reversed(_error_events):
            if str(row.get("id") or "").upper() == needle:
                return dict(row)
    return None


def _recent_private_errors(limit: int = 100) -> list:
    with _error_events_lock:
        return [dict(x) for x in list(_error_events)[-max(1, min(500, limit)):]][::-1]


def _retry_after_from_internal_error(detail: Any) -> Optional[int]:
    m = re.search(r"(?i)retry\s+in\s+(?:about\s+)?(\d+)s", str(detail or ""))
    if not m:
        return None
    try:
        return max(1, min(3600, int(m.group(1))))
    except Exception:
        return None


def _status_from_internal_error(detail: Any, default: int = 502) -> int:
    match = re.match(r"^\s*(\d{3})\s*:", str(detail or ""))
    if match:
        value = int(match.group(1))
        if 400 <= value <= 599:
            return value
    return int(default)


def _is_public_inference_path(path: str) -> bool:
    path = str(path or "")
    return (
        path.startswith("/v1/")
        or path in {"/chat/completions", "/messages", "/models"}
        or path.startswith("/models/")
    )


def _openai_public_error(status_code: int, detail: Any, *, source: str,
                         path: str = "/v1/chat/completions",
                         context: Optional[dict] = None,
                         exception_type: str = "") -> tuple:
    error_id, message = _register_private_error(
        status_code=status_code,
        detail=detail,
        source=source,
        path=path,
        method="POST",
        protocol="openai",
        context=context,
        exception_type=exception_type,
    )
    return error_id, message


def _anthropic_public_error(status_code: int, detail: Any, *, source: str,
                            path: str = "/v1/messages",
                            context: Optional[dict] = None,
                            exception_type: str = "") -> tuple:
    error_id, message = _register_private_error(
        status_code=status_code,
        detail=detail,
        source=source,
        path=path,
        method="POST",
        protocol="anthropic",
        context=context,
        exception_type=exception_type,
    )
    return error_id, message


_load_error_events()


@app.exception_handler(HTTPException)
async def bridgena_http_exception_handler(request: Request, exc: HTTPException):
    path = request.url.path
    if _is_public_inference_path(path):
        protocol = "anthropic" if path in {"/v1/messages", "/messages", "/v1/messages/count_tokens"} else "openai"
        error_id, message = _register_private_error(
            status_code=exc.status_code,
            detail=exc.detail,
            source="http_exception",
            path=path,
            method=request.method,
            protocol=protocol,
            context={"retry_after": (exc.headers or {}).get("Retry-After", "")},
            exception_type="HTTPException",
        )
        headers = dict(exc.headers or {})
        headers["X-Bridgena-Error-ID"] = error_id
        headers["Cache-Control"] = "no-store"

        if protocol == "anthropic":
            return JSONResponse(
                {
                    "type": "error",
                    "error": {"type": "api_error", "message": message},
                    "error_id": error_id,
                },
                status_code=exc.status_code,
                headers=headers,
            )

        return JSONResponse(
            {
                "error": {
                    "message": message,
                    "type": "api_error" if exc.status_code >= 500 else "invalid_request_error",
                    "code": error_id,
                },
                "error_id": error_id,
            },
            status_code=exc.status_code,
            headers=headers,
        )

    # Preserve detailed control-plane diagnostics for authenticated operators.
    return JSONResponse(
        {"detail": exc.detail},
        status_code=exc.status_code,
        headers=exc.headers,
    )


@app.middleware("http")
async def bridgena_delivery_headers(request: Request, call_next):
    """Prevent stale UI assets and intermediary buffering of streamed deltas."""
    response = await call_next(request)
    content_type = (response.headers.get("content-type") or "").lower()
    if "text/html" in content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["CDN-Cache-Control"] = "no-store"
        response.headers["Cloudflare-CDN-Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    elif "text/event-stream" in content_type:
        response.headers["Cache-Control"] = "no-cache, no-transform"
        response.headers["CDN-Cache-Control"] = "no-store"
        response.headers["Cloudflare-CDN-Cache-Control"] = "no-store"
        response.headers["X-Accel-Buffering"] = "no"
    return response


async def _current_session(request: Request) -> Optional[str]:
    sid = request.cookies.get("session_id")
    if sid:
        return verify_session_token(sid)
    return None


async def _page_guard(request: Request) -> Optional[RedirectResponse]:
    if not await _current_session(request):
        return RedirectResponse(url="/login")
    return None


def _whoami(request: Request) -> str:
    return "admin"


async def _require_key(request: Request) -> Optional[dict]:
    if await _current_session(request):
        return {"name": "web-session", "rpm": 120, "key": "web-session"}
    hdr = request.headers.get("authorization", "")
    key = (hdr[7:].strip() if hdr.lower().startswith("bearer ")
           else request.headers.get("x-api-key", "").strip()
           or request.query_params.get("api_key", ""))
    cfg = get_config()
    if _normalize_api_key_records(cfg):
        save_config(cfg)
    supplied_hash = _api_key_hash(key) if key else ""
    for k in cfg.get("api_keys", []):
        if k.get("key_hash") and hmac.compare_digest(str(k["key_hash"]), supplied_hash):
            rpm = int(k.get("rpm", 60))
            rl = check_rate_limit(k.get("id") or supplied_hash, rpm)
            if rl.get("limited"):
                raise HTTPException(status_code=429, detail=rl.get("detail", "rate-limited"))
            return k
    if key:
        raise HTTPException(status_code=401, detail="invalid api key")
    raise HTTPException(status_code=401, detail="missing api key")



# ---------- v3 control-plane security / telemetry ----------
_V3_CONTROL_PREFIXES=('/proxies/api','/jars/','/keeper/','/models/block','/create-key','/delete-key','/clear-logs','/debug-logs/data','/errors','/debug/raw-models','/control/api','/screenshots','/browser-view','/vnc','/refresh-tokens','/oxalpha/')
_V3_PUBLIC_PATHS={'/login','/logout','/healthz','/v1/models','/models','/v1/chat/completions','/chat/completions','/v1/messages','/messages'}
@app.middleware('http')
async def v3_control_plane_middleware(request: Request,call_next):
    started=time.perf_counter();rid=request.headers.get('x-request-id') or ('req_'+secrets.token_hex(6));path=request.url.path
    if path not in _V3_PUBLIC_PATHS and any(path.startswith(p) for p in _V3_CONTROL_PREFIXES):
        if not await _current_session(request):return JSONResponse({'detail':'dashboard session required'},status_code=401)
        if request.method not in ('GET','HEAD','OPTIONS'):
            origin=request.headers.get('origin')
            if origin:
                if urlparse(origin).netloc != request.headers.get('host',''):return JSONResponse({'detail':'cross-origin control-plane mutation rejected'},status_code=403)
    response=await call_next(request);response.headers['X-Bridgena-Request-ID']=rid;response.headers['X-Bridgena-Version']=BUILD_STAMP;response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='SAMEORIGIN';response.headers['Referrer-Policy']='same-origin';response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()';response.headers['Server-Timing']=f"app;dur={(time.perf_counter()-started)*1000:.1f}";return response

# ---------- pages ----------
@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return login_page()


@app.post("/login")
async def login_post(request: Request, password: str = Form("")):
    cfg = get_config()
    peer = request.client.host if request.client else "unknown"
    now = time.time()
    with _login_failures_lock:
        attempts = [stamp for stamp in _login_failures.get(peer, []) if now - stamp < 300]
        _login_failures[peer] = attempts
    if len(attempts) >= 8:
        return HTMLResponse(login_page("Too many attempts. Wait five minutes."), status_code=429)
    expected = str(cfg.get("password", "admin"))
    if password and hmac.compare_digest(str(password), expected):
        with _login_failures_lock:
            _login_failures.pop(peer, None)
        tok = create_session_token("admin")
        resp = RedirectResponse(url="/dashboard", status_code=303)
        forwarded_https = request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https"
        resp.set_cookie("session_id", tok, httponly=True,
                        secure=request.url.scheme == "https" or forwarded_https,
                        samesite="lax", max_age=86400 * 30, path="/")
        log("OK", "dashboard login")
        return resp
    with _login_failures_lock:
        _login_failures.setdefault(peer, []).append(now)
    return HTMLResponse(login_page("Incorrect password."), status_code=401)


@app.get("/logout")
async def logout(request: Request):
    r = RedirectResponse(url="/login", status_code=303)
    r.delete_cookie("session_id")
    return r


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    jars = load_jars()
    live = {sid for sid, session in keeper.sessions.items()
            if keeper_session_ready(session)}
    rows = snapshot_rows()
    flags = _flagged_active()
    overview = {
        "metrics": {
            "pool_total": len([l for l in _pool_lines() if l.strip() and not l.startswith("#")]),
            "alive": sum(1 for r in rows if r["verdict"] == "alive"),
            "flagged": len(flags),
            "jars_total": len(jars),
            "jars_ok": sum(1 for j in jars if jar_has_auth(j) and not j.get("expired")),
            "keepers_live": len(live), "models": len(get_models()),
        },
        "pool": rows, "live_ids": live,
        "jars": [{**j, "ok": not j.get("expired"), "limited": bool(j.get("limited_until", 0) and j["limited_until"] > time.time())}
                 for j in jars],
        "logtail": LOG.tail(60),
    }
    return dashboard_page(overview)


@app.get("/pool", response_class=HTMLResponse)
async def pool_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    rows = snapshot_rows()
    stats = {"total": len(rows), "alive": sum(1 for r in rows if r["verdict"] == "alive"),
             "flagged": sum(1 for r in rows if r["verdict"] == "arena-blocked")}
    return pool_page(rows, stats)


@app.get("/jars", response_class=HTMLResponse)
async def jars_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    personas = [(k, v["label"]) for k, v in persona_summaries().items()]
    live = set(keeper.sessions.keys())
    jars = [{**j, "has_auth": jar_has_auth(j), "keeper_live": j.get("id") in live,
             "keeper_enabled": bool(j.get("keeper_enabled")),
             "last_used_str": time.strftime("%Y-%m-%d %H:%M", time.localtime(j["last_used"])) if j.get("last_used") else None,
             "_personas": personas} for j in load_jars()]
    return jars_page(jars)


@app.get("/jars/upload", response_class=HTMLResponse)
async def jars_upload_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    return jars_upload_page()


@app.get("/errors", response_class=HTMLResponse)
async def errors_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    return errors_page()


@app.get("/errors/api/{error_id}")
async def errors_lookup_api(request: Request, error_id: str):
    if not await _current_session(request):
        raise HTTPException(status_code=401, detail="dashboard session required")
    row = _find_private_error(error_id)
    if not row:
        raise HTTPException(status_code=404, detail="Error ID not found")
    return JSONResponse({"ok": True, "error": row}, headers={"Cache-Control": "no-store"})


@app.get("/errors/api")
async def errors_recent_api(request: Request, limit: int = 100):
    if not await _current_session(request):
        raise HTTPException(status_code=401, detail="dashboard session required")
    return JSONResponse(
        {"ok": True, "errors": _recent_private_errors(limit)},
        headers={"Cache-Control": "no-store"},
    )


@app.get("/logs", response_class=HTMLResponse)
async def logs_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    return logs_page(LOG.tail(300))


@app.get("/models-page", response_class=HTMLResponse)
async def models_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    state = load_state()
    return models_page(get_models(), state.get("blocked_models", []))


@app.get("/api-keys", response_class=HTMLResponse)
async def api_keys_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    config = get_config()
    if _normalize_api_key_records(config):
        save_config(config)
    return api_keys_page(config.get("api_keys", []))


@app.get("/chat", response_class=HTMLResponse)
async def chat_view(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    state = load_state()
    blocked = state.get("blocked_models", [])
    models = [{"name": model_name(m), "id": m.get("id") if isinstance(m, dict) else None,
               "org": (m.get("organization") or "") if isinstance(m, dict) else ""}
              for m in get_models() if model_name(m) not in blocked]
    return chat_page(models, models[0]["name"] if models else "")



@app.get('/control/api/status')
async def v3_control_status(request: Request):
    if not await _current_session(request):raise HTTPException(status_code=401,detail='dashboard session required')
    jars=load_jars();return JSONResponse({'build':BUILD_STAMP,'upstream':ARENA_BASE,'local_upstream':LOCAL_UPSTREAM,'models':len(get_models()),'accounts':len(jars),'keepers':keeper.status(),'vnc':{'enabled':_V3_VNC_ENABLED,'display':_V3_VNC_DISPLAY if _V3_VNC_ENABLED else None,'novnc_assets':bool(_v3_novnc_root())},'time':int(time.time())})

# ---------- chat history (page) ----------
@app.get("/chat/api/chats")
async def chats_list():
    # Chat content is intentionally kept in the user's browser, never state.json.
    return JSONResponse([])


@app.get("/chat/api/history")
async def chat_history(chat_id: str = ""):
    return JSONResponse([])


@app.get("/chat/api/models")
async def chat_models():
    state = load_state()
    blocked = state.get("blocked_models", [])
    return JSONResponse([model_name(m) for m in get_models() if model_name(m) not in blocked][:400])


# ---------- OpenAI-compatible surface ----------
def _sse(obj) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


def _openai_text_content(value) -> str:
    """Normalize OpenAI string and multipart content without logging content."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("type") in ("text", "input_text"):
                text = item.get("text", "")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(part for part in parts if part)
    if isinstance(value, dict):
        text = value.get("text") or value.get("content") or ""
        return text if isinstance(text, str) else ""
    return ""


def _last_openai_user_prompt(body: dict) -> str:
    messages = body.get("messages") or []
    prompts = [_openai_text_content(message.get("content", ""))
               for message in messages
               if isinstance(message, dict) and message.get("role") == "user"]
    return prompts[-1].strip() if prompts else ""


def _openai_system_context(body: dict) -> str:
    parts = []
    direct = _openai_text_content(body.get("system", "")).strip()
    if direct:
        parts.append(direct)
    for message in body.get("messages") or []:
        if not isinstance(message, dict) or message.get("role") != "system":
            continue
        value = _openai_text_content(message.get("content", "")).strip()
        if value and value not in parts:
            parts.append(value)
    return "\n\n".join(parts)


def _disposable_context_prompt(body: dict) -> str:
    """Build a bounded, non-recursive transcript for one disposable Arena evaluation.

    Browser keepers/auth/proxies remain persistent, but every API message gets a
    fresh Arena evaluation. Conversation continuity therefore comes exclusively
    from the client-supplied transcript. System messages stay in system_prompt
    and are not duplicated here.

    The newest user message is always preserved and clearly separated. Recent
    history is retained verbatim (subject to the hard MAX_PROMPT envelope); when
    older history cannot fit, it is omitted with a neutral marker rather than
    recursively embedding an earlier Bridgena capsule.
    """
    messages = body.get("messages") or []
    rows = []
    newest_user_index = -1
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "user":
            value = _openai_text_content(message.get("content", "")).strip()
            if value:
                newest_user_index = i

    if newest_user_index < 0:
        return ""

    newest = _openai_text_content(messages[newest_user_index].get("content", "")).strip()
    if not newest:
        return ""

    for i, message in enumerate(messages[:newest_user_index]):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role in ("system", "developer"):
            # These belong to the higher-priority system context, not transcript text.
            continue
        value = _openai_text_content(message.get("content", "")).strip()
        if not value:
            continue
        label = {
            "user": "User",
            "assistant": "Assistant",
            "tool": "Tool",
            "function": "Tool",
        }.get(role, role.title() or "Message")
        rows.append(f"{label}:\n{value}")

    # A genuinely new conversation should enter Arena exactly as the user's
    # newest turn. The history capsule is only needed when we are rebuilding an
    # existing client transcript into a fresh Arena conversation.
    if not rows:
        return newest[-MAX_PROMPT:]

    prefix = (
        "Previous messages from this same conversation are provided below. "
        "Use them only as conversation history and continue naturally. "
        "Do not mention that the history was supplied separately.\n\n"
        "--- BEGIN PREVIOUS CONVERSATION ---\n"
    )
    suffix = (
        "\n--- END PREVIOUS CONVERSATION ---\n\n"
        "Reply to the newest user message below.\n\n"
        "Newest user message:\nUser:\n"
    )

    # Reserve the newest turn first. It is the one piece that must never be lost.
    fixed = prefix + suffix + newest
    if len(fixed) >= MAX_PROMPT:
        room = max(1, MAX_PROMPT - len(suffix) - 256)
        return (suffix + newest[-room:])[-MAX_PROMPT:]

    budget = MAX_PROMPT - len(prefix) - len(suffix) - len(newest)
    kept = []
    used = 0
    omitted = 0

    # Prefer the most recent transcript while preserving complete message blocks.
    for row in reversed(rows):
        cost = len(row) + 2
        if used + cost <= budget:
            kept.append(row)
            used += cost
        else:
            omitted += 1

    kept.reverse()
    history = "\n\n".join(kept)
    if omitted:
        marker = f"[{omitted} older message(s) omitted to fit the context budget.]"
        if len(marker) + 2 <= max(0, budget - len(history)):
            history = (marker + ("\n\n" + history if history else ""))
        elif history:
            # Make room for the marker without sacrificing the newest user turn.
            history = marker + "\n\n" + history[-max(0, budget - len(marker) - 2):]

    return (prefix + history + suffix + newest)[:MAX_PROMPT]


def _format_conversation_prompt(body: dict) -> str:
    return _disposable_context_prompt(body)


def _anthropic_prompt(body: dict) -> str:
    return _disposable_context_prompt(body)


def _disposable_chat_id(prefix: str = "api") -> str:
    """Unique logical id per API message: guarantees create-evaluation semantics."""
    return f"{prefix}-ephemeral-{uuid7()}"


def _anthropic_system_context(body: dict) -> str:
    return _openai_text_content(body.get("system", "")).strip()


def _failover_handoff_prompt(body: dict) -> str:
    """Render client-visible conversation history for emergency thread handoff.

    This is never used for an ordinary Arena follow-up. It is used only when the
    original bound account is unusable before generation (or explicitly returns
    LOGIN_GATE with zero stream frames) and Bridgena must create a replacement
    Arena conversation on another configured account.
    """
    rows = []
    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "system":
            continue
        value = _openai_text_content(message.get("content", "")).strip()
        if not value:
            continue
        label = {
            "user": "User",
            "assistant": "Assistant",
            "tool": "Tool",
            "developer": "Developer",
        }.get(role, role.title() or "Message")
        rows.append(f"{label}: {value}")

    rendered = "\n\n".join(rows).strip()
    if len(rendered) <= MAX_PROMPT:
        return rendered

    # Preserve the newest context when the client transcript is enormous.
    tail = rendered[-MAX_PROMPT:]
    cut = tail.find("\n\n")
    return tail[cut + 2:] if cut >= 0 else tail


def _tenant_identity(keyinfo: Optional[dict]) -> str:
    """Opaque tenant identity; never use the plaintext API key."""
    k = keyinfo or {}
    raw = str(k.get("id") or k.get("key_hash") or k.get("name") or "anonymous")
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:20]


def _first_user_text(body: dict) -> str:
    for message in body.get("messages") or []:
        if isinstance(message, dict) and message.get("role") == "user":
            value = _openai_text_content(message.get("content", "")).strip()
            if value:
                return value
    return ""


def _latest_user_text(body: dict) -> str:
    """Newest user turn only, for an already-bound Arena conversation."""
    for message in reversed(body.get("messages") or []):
        if isinstance(message, dict) and str(message.get("role") or "").lower() == "user":
            value = _openai_text_content(message.get("content", "")).strip()
            if value:
                return value
    return ""


def _logical_chat_id(body: dict, keyinfo: Optional[dict], prefix: str = "api") -> str:
    """Stable, tenant-scoped conversation identity for clients without chat_id.

    Explicit client thread identifiers win. Otherwise derive an opaque stable id
    from tenant + model + initial system/user context, mirroring the behavior of
    the older working bridge while preventing cross-user collisions.
    """
    tenant = _tenant_identity(keyinfo)
    explicit = body.get("chat_id") or body.get("conversation_id") or body.get("thread_id")
    metadata = body.get("metadata")
    if not explicit and isinstance(metadata, dict):
        explicit = metadata.get("thread_id") or metadata.get("conversation_id") or metadata.get("session_id")
    if explicit:
        seed = f"{tenant}\\0explicit\\0{explicit}"
    else:
        model = str(body.get("model") or "auto")
        system = _openai_system_context(body) or _anthropic_system_context(body)
        first_user = _first_user_text(body)
        seed = f"{tenant}\\0{model}\\0{system}\\0{first_user}"
    digest = hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()[:32]
    return f"{prefix}-{digest}"

def _anthropic_sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def _rough_tokens(text: str) -> int:
    # Usage is informational; the upstream protocol does not expose tokenizer
    # counts. A conservative character heuristic is preferable to claiming an
    # exact provider count.
    return max(0, math.ceil(len(text or "") / 4))


def _api_request_fingerprint(body: dict, keyinfo: Optional[dict], prompt: str) -> str:
    """Hash the complete message context; never retain or log its contents."""
    identity = str((keyinfo or {}).get("id") or (keyinfo or {}).get("name") or "anonymous")
    model = str(body.get("model") or "auto")
    request_context = {
        "system": body.get("system"),
        "messages": body.get("messages"),
        "tools": body.get("tools"),
        "tool_choice": body.get("tool_choice"),
    }
    try:
        context = json.dumps(request_context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        context = prompt
    return hashlib.sha256(
        (identity + "\0" + model + "\0" + context).encode("utf-8", "ignore")
    ).hexdigest()


def _reserve_api_request(body: dict, keyinfo: Optional[dict], prompt: str) -> tuple[bool, int]:
    """Reject exact rapid duplicates before they create another upstream job."""
    if not API_DUPLICATE_WINDOW_SEC:
        return True, 0
    fingerprint = _api_request_fingerprint(body, keyinfo, prompt)
    now = time.monotonic()
    with _recent_api_requests_lock:
        cutoff = now - API_DUPLICATE_WINDOW_SEC
        for old_fp, seen_at in list(_recent_api_requests.items()):
            if seen_at < cutoff:
                _recent_api_requests.pop(old_fp, None)
                _duplicate_notices.pop(old_fp, None)
        previous = _recent_api_requests.get(fingerprint, 0.0)
        if previous >= cutoff:
            count = int(_duplicate_notices.get(fingerprint, 0)) + 1
            _duplicate_notices[fingerprint] = count
            return False, count
        _recent_api_requests[fingerprint] = now
        _duplicate_notices[fingerprint] = 0
    return True, 0


def _release_api_request(body: dict, keyinfo: Optional[dict], prompt: str) -> None:
    """Release a request reservation when its stream/response has terminated.

    Duplicate suppression is for genuinely overlapping jobs, not for blocking a
    client's legitimate retry for 15 seconds after a terminal 4xx/5xx.
    """
    if not API_DUPLICATE_WINDOW_SEC:
        return
    fp = _api_request_fingerprint(body, keyinfo, prompt)
    with _recent_api_requests_lock:
        _recent_api_requests.pop(fp, None)
        _duplicate_notices.pop(fp, None)



# ============================================================================
# Bridgena v4 browser-extension transport
# ============================================================================
# The headed browser owns Arena UI interaction and response rendering. Python
# owns API compatibility, scheduling and SSE translation. The extension never
# needs to understand provider-specific private stream frames.
V4_TRANSPORT = os.environ.get("BRIDGENA_V4_TRANSPORT", "extension").strip().lower()
V4_FALLBACK_LEGACY = os.environ.get("BRIDGENA_V4_FALLBACK_LEGACY", "0").strip().lower() in {"1","true","yes","on"}
# v4.1.2: use one control-plane token for the bundled extension workers.
# If the operator did not provide one, generate an ephemeral token and inject it
# into the bundled MV3 service worker before Chromium starts. This prevents a
# stale/empty extension token from silently producing connected workers=0.
import secrets as _v4_secrets
V4_EXTENSION_TOKEN = os.environ.get("BRIDGENA_V4_EXTENSION_TOKEN", "").strip() or _v4_secrets.token_urlsafe(24)
V4_FIRST_TOKEN_SEC = max(5.0, min(180.0, float(os.environ.get("BRIDGENA_V4_FIRST_TOKEN_SEC", "45"))))
V4_IDLE_STREAM_SEC = max(5.0, min(180.0, float(os.environ.get("BRIDGENA_V4_IDLE_STREAM_SEC", "30"))))
V4_JOB_MAX_SEC = max(30.0, min(900.0, float(os.environ.get("BRIDGENA_V4_JOB_MAX_SEC", "300"))))
V4_AUTOLAUNCH = os.environ.get("BRIDGENA_V4_AUTOLAUNCH", "0").strip().lower() in {"1","true","yes","on"}
V4_AUTO_ATTACH_KEEPERS = os.environ.get("BRIDGENA_V4_AUTO_ATTACH_KEEPERS", "1").strip().lower() in {"1","true","yes","on"}
V4_CHROME_BIN = os.environ.get("BRIDGENA_V4_CHROME_BIN", "").strip()
V4_PROFILE_DIR = os.environ.get("BRIDGENA_V4_PROFILE_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser-profile"))
V4_EXTENSION_DIR = os.environ.get("BRIDGENA_V4_EXTENSION_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "extension"))
V4_BROWSER_PROXY = os.environ.get("BRIDGENA_V4_BROWSER_PROXY", "").strip()

# v4.2: logical API conversations stay attached to their real Arena chat.
# Only opaque ids, worker ids and Arena URLs are persisted -- never prompt text.
V4_SESSION_TTL_SEC = max(300.0, min(7*24*3600.0, float(os.environ.get("BRIDGENA_V4_SESSION_TTL_SEC", "21600"))))
V4_SESSION_MAX = max(32, min(10000, int(os.environ.get("BRIDGENA_V4_SESSION_MAX", "2000"))))
V4_SESSION_FILE = os.environ.get(
    "BRIDGENA_V4_SESSION_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "v4_sessions.json"),
)
_v4_sessions: Dict[str, dict] = {}
_v4_sessions_guard = threading.Lock()

def _v4_sessions_load() -> None:
    try:
        if not os.path.isfile(V4_SESSION_FILE):
            return
        with open(V4_SESSION_FILE, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        now = time.time()
        if isinstance(raw, dict):
            with _v4_sessions_guard:
                for cid, item in raw.items():
                    if not isinstance(item, dict):
                        continue
                    updated = float(item.get("updated") or 0)
                    if updated and now - updated <= V4_SESSION_TTL_SEC:
                        _v4_sessions[str(cid)] = {
                            "worker_id": str(item.get("worker_id") or ""),
                            "url": str(item.get("url") or ""),
                            "model": str(item.get("model") or "auto"),
                            "updated": updated,
                        }
        if _v4_sessions:
            log("INFO", f"v4 sticky sessions restored · {len(_v4_sessions)} binding(s)")
    except Exception as exc:
        log("WARN", f"v4 sticky session restore skipped: {type(exc).__name__}: {redact(str(exc))[:140]}")

def _v4_sessions_persist_locked() -> None:
    try:
        os.makedirs(os.path.dirname(os.path.abspath(V4_SESSION_FILE)), exist_ok=True)
        tmp = V4_SESSION_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(_v4_sessions, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, V4_SESSION_FILE)
    except Exception as exc:
        log("WARN", f"v4 sticky session persist skipped: {type(exc).__name__}: {redact(str(exc))[:140]}")

def _v4_session_get(chat_id: str, model: str) -> Optional[dict]:
    now = time.time()
    key = str(chat_id)
    with _v4_sessions_guard:
        item = _v4_sessions.get(key)
        if not item:
            return None
        expired = now - float(item.get("updated") or 0) > V4_SESSION_TTL_SEC
        mismatch = str(item.get("model") or "auto") != str(model or "auto")
        if expired or mismatch:
            _v4_sessions.pop(key, None)
            _v4_sessions_persist_locked()
            return None
        return dict(item)

def _v4_session_bind(chat_id: str, worker_id: str, url: str, model: str) -> None:
    key = str(chat_id)
    if not key or not worker_id:
        return
    safe_url = str(url or "")
    if safe_url and not (safe_url.startswith("https://arena.ai/") or safe_url.startswith("https://www.arena.ai/")):
        safe_url = ""
    with _v4_sessions_guard:
        _v4_sessions[key] = {
            "worker_id": str(worker_id),
            "url": safe_url,
            "model": str(model or "auto"),
            "updated": time.time(),
        }
        if len(_v4_sessions) > V4_SESSION_MAX:
            victims = sorted(_v4_sessions.items(), key=lambda kv: float(kv[1].get("updated") or 0))
            for old_key, _ in victims[:len(_v4_sessions)-V4_SESSION_MAX]:
                _v4_sessions.pop(old_key, None)
        _v4_sessions_persist_locked()

def _v4_session_drop(chat_id: str, reason: str = "") -> None:
    key = str(chat_id)
    removed = None
    with _v4_sessions_guard:
        removed = _v4_sessions.pop(key, None)
        if removed is not None:
            _v4_sessions_persist_locked()
    if removed is not None:
        log("INFO", f"v4 sticky session released · {key[:18]}…" + (f" · {reason}" if reason else ""))

_v4_sessions_load()

# v4.1.4: the authenticated keeper fleet *is* the headed extension worker fleet.
# Force the bundled extension path before any bootstrap work. A bootstrap
# preparation error must never resurrect a stale legacy extension path.
def _v4_prepare_bundled_extension():
    manifest_path=os.path.join(V4_EXTENSION_DIR, "manifest.json")
    sw_path=os.path.join(V4_EXTENSION_DIR, "service-worker.js")
    if not os.path.isfile(manifest_path):
        log("WARN", f"v4 bundled extension manifest missing: {V4_EXTENSION_DIR}")
        return False
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest=json.load(fh)
        hp=list(manifest.get("host_permissions") or [])
        for pat in ("https://arena.ai/*", "https://*.arena.ai/*",
                    "http://127.0.0.1/*", "http://localhost/*"):
            if pat not in hp:
                hp.append(pat)
        manifest["host_permissions"]=hp
        perms=list(manifest.get("permissions") or [])
        if "debugger" not in perms:
            perms.append("debugger")
        manifest["permissions"]=perms
        manifest["version"]="4.2.2"
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
            fh.write("\n")

        ws_url=os.environ.get(
            "BRIDGENA_V4_EXTENSION_WS_URL",
            f"ws://127.0.0.1:{PORT}/v4/extension/ws"
        ).strip()

        sw_template = r"""const BOOT = __BOOT__;
let ws=null,reconnectTimer=null,pingTimer=null,currentRequest=null;
let pendingJob=null,pendingTabId=null,currentPhase="",lastDispatchAt=0;

async function dispatchJob(tab,job,reason="server"){
  if(!tab?.id||!job)return false;
  pendingTabId=tab.id;
  lastDispatchAt=Date.now();
  send({
    type:"trace",request_id:job.request_id,
    stage:"sw-dispatch",reason,tab_id:tab.id
  });
  try{
    await chrome.tabs.sendMessage(tab.id,{type:"BRIDGENA_SEND",job});
    return true;
  }catch(e){
    send({
      type:"trace",request_id:job.request_id,
      stage:"sw-dispatch-failed",reason,
      message:String(e?.message||e).slice(0,160)
    });
    return false;
  }
}

async function cfg() {
  const saved=await chrome.storage.local.get({workerId:"",proxyLabel:""});
  if(!saved.workerId) {
    saved.workerId="keeper-"+crypto.randomUUID();
    await chrome.storage.local.set({workerId:saved.workerId});
  }
  return {wsUrl:BOOT.wsUrl,token:BOOT.token,workerId:saved.workerId,proxyLabel:saved.proxyLabel||""};
}
function send(obj){if(ws&&ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(obj));}
async function activeArenaTab(){
  let tabs=await chrome.tabs.query({url:["https://arena.ai/*","https://*.arena.ai/*"]});
  if(tabs.length)return tabs[0];
  return await chrome.tabs.create({url:"https://arena.ai/",active:true});
}
async function connect(){
  clearTimeout(reconnectTimer);
  const c=await cfg();
  const url=c.wsUrl+(c.wsUrl.includes("?")?"&":"?")+"token="+encodeURIComponent(c.token||"");
  try{ws=new WebSocket(url);}catch(e){reconnectTimer=setTimeout(connect,1500);return;}
  ws.onopen=()=>{send({type:"hello",worker_id:c.workerId,ready:true,proxy:c.proxyLabel||"",user_agent:navigator.userAgent});
    clearInterval(pingTimer);pingTimer=setInterval(()=>send({type:"heartbeat",ts:Date.now(),request_id:currentRequest||""}),15000);};
  ws.onmessage=async(ev)=>{let m;try{m=JSON.parse(ev.data)}catch{return}
    if(m.type==="send_message"){
      currentRequest=m.request_id;
      pendingJob=m;
      currentPhase="dispatch";
      let tab=await activeArenaTab();
      const ok=await dispatchJob(tab,m,"server");
      if(!ok){
        try{
          await chrome.tabs.reload(tab.id);
          setTimeout(async()=>{
            const retry=await dispatchJob(tab,m,"reload-retry");
            if(!retry)send({type:"error",request_id:m.request_id,message:"content script unavailable after reload"});
          },1800);
        }catch(x){
          send({type:"error",request_id:m.request_id,message:String(x)});
        }
      }
    }
    else if(m.type==="cancel"){
      let tab=await activeArenaTab();
      chrome.tabs.sendMessage(tab.id,{type:"BRIDGENA_CANCEL",request_id:m.request_id}).catch(()=>{});
      if(currentRequest===m.request_id){
        currentRequest=null;pendingJob=null;pendingTabId=null;currentPhase="";
      }
    }
  };
  ws.onclose=()=>{clearInterval(pingTimer);reconnectTimer=setTimeout(connect,1500);};
  ws.onerror=()=>{try{ws.close()}catch{}};
}
async function nativeSubmit(tabId,msg){
  if(!tabId)throw new Error("native submit has no tab id");
  const target={tabId};
  let attached=false;
  try{
    await chrome.debugger.attach(target,"1.3");
    attached=true;

    // Prefer the actual visible Send control when content script supplied its
    // viewport center. This is a browser-level input event, not a DOM event.
    if(Number.isFinite(msg.x)&&Number.isFinite(msg.y)){
      await chrome.debugger.sendCommand(target,"Input.dispatchMouseEvent",{
        type:"mouseMoved",x:msg.x,y:msg.y,button:"none"
      });
      await chrome.debugger.sendCommand(target,"Input.dispatchMouseEvent",{
        type:"mousePressed",x:msg.x,y:msg.y,button:"left",buttons:1,clickCount:1
      });
      await chrome.debugger.sendCommand(target,"Input.dispatchMouseEvent",{
        type:"mouseReleased",x:msg.x,y:msg.y,button:"left",buttons:0,clickCount:1
      });
      return {ok:true,method:"cdp-click"};
    }

    // Fallback to native Enter in the focused composer.
    await chrome.debugger.sendCommand(target,"Input.dispatchKeyEvent",{
      type:"rawKeyDown",key:"Enter",code:"Enter",
      windowsVirtualKeyCode:13,nativeVirtualKeyCode:13
    });
    await chrome.debugger.sendCommand(target,"Input.dispatchKeyEvent",{
      type:"keyUp",key:"Enter",code:"Enter",
      windowsVirtualKeyCode:13,nativeVirtualKeyCode:13
    });
    return {ok:true,method:"cdp-enter"};
  }finally{
    if(attached){
      try{await chrome.debugger.detach(target)}catch{}
    }
  }
}

chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{
  if(!msg||!msg.type)return;

  // Local lifecycle messages stay inside the extension. They let the service
  // worker recover only navigation that happened BEFORE prompt submission.
  if(msg.type==="BRIDGENA_PHASE_LOCAL"){
    if(msg.request_id&&msg.request_id===currentRequest){
      currentPhase=String(msg.phase||"");
    }
    return;
  }

  if(msg.type==="BRIDGENA_CONTENT_READY_LOCAL"){
    const tabId=sender?.tab?.id;
    const canResume=!!(
      pendingJob && currentRequest===pendingJob.request_id &&
      tabId && (pendingTabId===null||pendingTabId===tabId) &&
      currentPhase==="pre_navigation" &&
      Date.now()-lastDispatchAt>300
    );
    if(canResume){
      const recovered={...pendingJob,_navigation_recovered:true};
      setTimeout(()=>dispatchJob({id:tabId},recovered,"post-navigation-resume"),120);
    }
    return;
  }

  if(msg.type==="BRIDGENA_NATIVE_SUBMIT_LOCAL"){
    nativeSubmit(sender?.tab?.id,msg)
      .then(r=>sendResponse(r))
      .catch(e=>sendResponse({ok:false,error:String(e?.message||e)}));
    return true;
  }

  if(msg.type.startsWith("BRIDGENA_")){
    let out={...msg};delete out.type;
    send({type:msg.type.replace("BRIDGENA_","").toLowerCase(),...out});
    if(
      msg.type==="BRIDGENA_DONE"||
      msg.type==="BRIDGENA_ERROR"||
      msg.type==="BRIDGENA_CHALLENGE"||
      msg.type==="BRIDGENA_LOGIN_REQUIRED"
    ){
      if(!msg.request_id||msg.request_id===currentRequest){
        currentRequest=null;pendingJob=null;pendingTabId=null;currentPhase="";
      }
    }
  }
});
chrome.runtime.onInstalled.addListener(()=>connect());
chrome.runtime.onStartup.addListener(()=>connect());
connect();
"""
        boot=json.dumps({"wsUrl":ws_url,"token":V4_EXTENSION_TOKEN}, separators=(",",":"))
        sw_source=sw_template.replace("__BOOT__", boot)
        with open(sw_path, "w", encoding="utf-8") as fh:
            fh.write(sw_source)

        # v4.1.7: Arena normally keeps invisible reCAPTCHA/Enterprise iframes in
        # the DOM. Those are transport prerequisites, not interactive challenge
        # screens. Rebuild the content script with challenge detection based on
        # visible challenge UI instead of the mere presence of a reCAPTCHA URL.
        content_path=os.path.join(V4_EXTENSION_DIR, "arena-content.js")
        content_source=r"""let active=null;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function visible(el){
  if(!el)return false;
  const r=el.getBoundingClientRect(),s=getComputedStyle(el);
  if(s.visibility==="hidden"||s.display==="none"||Number(s.opacity||1)===0)return false;
  return r.width>=4&&r.height>=4;
}
function txt(el){return (el?.innerText||el?.textContent||"").trim()}
function emit(type,request_id,extra={}){chrome.runtime.sendMessage({type:"BRIDGENA_"+type.toUpperCase(),request_id,...extra}).catch(()=>{})}
function trace(id,stage,extra={}){emit("trace",id,{stage,...extra})}
function phase(id,value){
  chrome.runtime.sendMessage({
    type:"BRIDGENA_PHASE_LOCAL",request_id:id,phase:String(value||"")
  }).catch(()=>{});
}

function challengePresent(){
  const frameChallenge=[...document.querySelectorAll("iframe")].some(f=>{
    const src=(f.src||"").toLowerCase(),title=(f.title||"").toLowerCase();
    if(!/(recaptcha|captcha|challenge|turnstile)/i.test(src+" "+title)||!visible(f))return false;
    const r=f.getBoundingClientRect();
    if(r.width<180||r.height<80)return false;
    return /bframe|challenge|verify|captcha/i.test(src+" "+title)||r.height>=180;
  });
  const textChallenge=[...document.querySelectorAll('[role="dialog"],[aria-modal="true"],main,section,form,body>div')].some(el=>{
    if(!visible(el))return false;
    const t=txt(el).replace(/\s+/g," ").trim();
    return !!t&&t.length<700&&/verify you are human|verification required|complete the security check|prove you are human|checking your browser/i.test(t);
  });
  return frameChallenge||textChallenge;
}

function loginRequired(){
  return [...document.querySelectorAll('button,a,[role="button"]')].some(x=>{
    if(!visible(x))return false;
    const t=txt(x).replace(/\s+/g," ").trim(),a=(x.getAttribute("aria-label")||"").trim();
    return /^(sign in|log in|login)$/i.test(t)||/^(sign in|log in|login)$/i.test(a);
  });
}

function domRoots(){
  const roots=[document],seen=new Set([document]);
  const queue=[document.documentElement];
  while(queue.length){
    const node=queue.shift();
    if(!node||!node.querySelectorAll)continue;
    for(const el of node.querySelectorAll('*')){
      if(el.shadowRoot&&!seen.has(el.shadowRoot)){
        seen.add(el.shadowRoot);
        roots.push(el.shadowRoot);
        queue.push(el.shadowRoot);
      }
    }
  }
  return roots;
}

function composer(){
  const selectors=[
    'textarea[placeholder*="ask" i]',
    'textarea[placeholder*="message" i]',
    'textarea[placeholder*="prompt" i]',
    'textarea',
    '[contenteditable="true"][role="textbox"]',
    '[contenteditable="true"]'
  ];
  let all=[];
  for(const root of domRoots()){
    for(const s of selectors){
      try{all.push(...root.querySelectorAll(s))}catch{}
    }
  }
  all=[...new Set(all)].filter(visible);
  all.sort((a,b)=>{
    // Prefer a visible composer lower in the viewport and associated with a
    // form/send control over incidental textareas in dialogs/settings.
    const af=!!a.closest?.('form'),bf=!!b.closest?.('form');
    if(af!==bf)return bf-af;
    return b.getBoundingClientRect().top-a.getBoundingClientRect().top;
  });
  return all[0]||null;
}

async function waitForComposer(timeoutMs=12000,id=null,stage="composer-wait"){
  const started=Date.now();
  let lastDiag=0;
  while(Date.now()-started<timeoutMs){
    const c=composer();
    if(c)return c;
    const now=Date.now();
    if(id&&now-lastDiag>1800){
      lastDiag=now;
      trace(id,stage,{
        elapsed_ms:now-started,
        href:location.href,
        readyState:document.readyState,
        login_required:loginRequired(),
        challenge:challengePresent()
      });
    }
    await sleep(120);
  }
  return null;
}

async function frameOrTimer(maxWait=100){
  return await Promise.race([
    new Promise(resolve=>{
      try{
        requestAnimationFrame(()=>requestAnimationFrame(()=>resolve("raf")));
      }catch{resolve("no-raf")}
    }),
    sleep(maxWait).then(()=>"timer")
  ]);
}

async function settleUi(ms=500,id=null,stage="ui-settle"){
  const started=Date.now();
  let rafTicks=0,timerFallbacks=0;
  while(Date.now()-started<ms){
    const mode=await frameOrTimer(Math.min(120,Math.max(40,ms)));
    if(mode==="raf")rafTicks++;else timerFallbacks++;
    await sleep(20);
  }
  if(id&&timerFallbacks){
    trace(id,stage,{
      elapsed_ms:Date.now()-started,
      raf_ticks:rafTicks,
      timer_fallbacks:timerFallbacks,
      visibility:document.visibilityState
    });
  }
}

function validArenaUrl(value){
  try{
    const u=new URL(String(value||""),location.href);
    return u.protocol==="https:" && (u.hostname==="arena.ai"||u.hostname.endsWith(".arena.ai"));
  }catch{return false}
}

async function restoreSession(url,id){
  if(!validArenaUrl(url))return false;
  const target=new URL(url,location.href).href;
  if(location.href!==target){
    trace(id,"session-navigate",{from:location.href,to:target});
    location.assign(target);
    const c=await waitForComposer(12000,id,"session-restore-wait");
    if(!c)return false;
  }else{
    const c=await waitForComposer(5000,id,"session-current-wait");
    if(!c)return false;
  }
  await settleUi(450);
  trace(id,"session-resumed",{url:location.href});
  return true;
}

function promptFragments(prompt){
  const p=normalizedText(prompt);
  if(!p)return [];
  if(p.length<=32)return [p];

  const out=[];
  const add=s=>{
    s=normalizedText(s);
    if(s.length>=18&&!out.includes(s))out.push(s);
  };
  add(p.slice(0,Math.min(96,p.length)));
  add(p.slice(Math.max(0,p.length-96)));

  // Recovery/context capsules end with the newest user turn. Including a
  // fragment around that marker makes acknowledgement survive UI truncation
  // of the older history while still binding the evidence to this request.
  const marker=p.toLowerCase().lastIndexOf("newest user message:");
  if(marker>=0)add(p.slice(marker,Math.min(p.length,marker+160)));
  return out;
}

function promptMatchesText(text,prompt){
  const t=normalizedText(text),p=normalizedText(prompt);
  if(!t||!p)return false;
  if(p.length<=32)return t===p || t.endsWith(p);

  const probes=promptFragments(p);
  if(!probes.length)return false;
  const hits=probes.filter(x=>t.includes(x)).length;
  // Long payloads require two independent fragments when available, which
  // prevents a generic page container from becoming "proof" of submission.
  return hits>=Math.min(2,probes.length);
}

function transcriptBoundaries(){
  const selector=[
    '[data-message-author-role="user"]','[data-message-author-role="assistant"]',
    '[data-role="user"]','[data-role="assistant"]',
    '[data-author="user"]','[data-author="assistant"]',
    '[data-testid*="user" i]','[data-testid*="assistant" i]',
    '[data-testid*="message" i]','[class*="message" i]','[class*="bubble" i]',
    'article','[role="article"]'
  ].join(',');
  const raw=[...document.querySelectorAll(selector)].filter(el=>{
    if(!visible(el)||el===document.body||el===document.documentElement||el.tagName==='MAIN')return false;
    if(el.closest('nav,aside,[role="navigation"],form'))return false;
    if(el.matches('textarea,input,[contenteditable="true"]')||
       el.querySelector('textarea,input,[contenteditable="true"]'))return false;
    return !!normalizedText(txt(el));
  });
  return raw.filter(el=>!raw.some(other=>other!==el&&el.contains(other)));
}

function conversationMessageCount(){
  return transcriptBoundaries().length;
}

function renderedPromptBoundaryCount(prompt){
  const p=normalizedText(prompt);
  if(!p)return 0;
  const main=document.querySelector('main')||document.body;
  let raw=transcriptBoundaries().filter(el=>main.contains(el)&&promptMatchesText(txt(el),p));

  // Arena occasionally changes the message wrapper class. Fall back to
  // compact visible descendants of <main>, but never forms/navigation or
  // giant conversation containers.
  if(!raw.length){
    const maxLen=Math.max(260,Math.min(9000,p.length+700));
    const generic=[...main.querySelectorAll('div,p,section,li')].filter(el=>{
      if(!visible(el)||el.closest('nav,aside,[role="navigation"],form'))return false;
      if(el.matches('textarea,input,[contenteditable="true"],button')||
         el.querySelector('textarea,input,[contenteditable="true"]'))return false;
      const t=normalizedText(txt(el));
      return !!t&&t.length<=maxLen&&promptMatchesText(t,p);
    });
    raw=generic.filter(el=>!generic.some(other=>other!==el&&el.contains(other)));
  }
  return raw.length;
}

function committedPromptCount(prompt){
  return renderedPromptBoundaryCount(prompt);
}

function submitControl(c){
  const form=c?.closest("form");
  if(form){
    const b=[...form.querySelectorAll('button,input[type="submit"]')].find(x=>
      visible(x)&&!x.disabled&&(x.type==="submit"||/send|submit/i.test((x.getAttribute("aria-label")||"")+" "+txt(x)))
    );
    if(b)return b;
  }
  const buttons=[...document.querySelectorAll('button,[role="button"]')].filter(x=>visible(x)&&!x.disabled);
  return buttons.find(b=>/send|submit/i.test((b.getAttribute("aria-label")||"")+" "+(b.getAttribute("data-testid")||"")+" "+txt(b)));
}

function stopButton(){
  return [...document.querySelectorAll('button,[role="button"]')].find(b=>
    visible(b)&&/stop|cancel generation|stop generating/i.test(
      (b.getAttribute('aria-label')||'')+' '+(b.getAttribute('data-testid')||'')+' '+txt(b)
    )
  );
}

async function setValue(el,value,id){
  el.focus();
  await sleep(60);

  if(el.tagName==='TEXTAREA'||el.tagName==='INPUT'){
    // React controlled inputs need the native prototype setter, followed by
    // an input transaction. Using el.value directly can leave React state at
    // the old/empty value even though the DOM visibly contains text.
    const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
    const desc=Object.getOwnPropertyDescriptor(proto,'value');
    if(desc?.set)desc.set.call(el,"");
    else el.value="";
    el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'deleteContentBackward',data:null}));
    await sleep(30);
    if(desc?.set)desc.set.call(el,value);
    else el.value=value;
    el.dispatchEvent(new InputEvent('beforeinput',{bubbles:true,cancelable:true,inputType:'insertText',data:value}));
    el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));
    el.dispatchEvent(new Event('change',{bubbles:true}));
  }else{
    // Arena's richer editors are happiest when text is inserted through the
    // browser's editing command, because it updates the editor's internal
    // document model in addition to the visible DOM.
    try{
      const sel=getSelection(),range=document.createRange();
      range.selectNodeContents(el);
      sel.removeAllRanges();sel.addRange(range);
      document.execCommand("delete",false,null);
      await sleep(20);
      document.execCommand("insertText",false,value);
    }catch{
      el.textContent="";
      el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'deleteContentBackward',data:null}));
      el.textContent=value;
      el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));
    }
  }

  await sleep(120);
  trace(id,"editor-state-synced",{
    tag:el.tagName,
    value_chars:composerValue(el).length,
    form:!!el.closest("form")
  });
}

async function clickNewChat(id=null){
  const c=[...document.querySelectorAll('button,a,[role="button"]')].find(x=>
    visible(x)&&/new chat|new conversation|start new/i.test((x.getAttribute("aria-label")||"")+" "+txt(x))
  );
  if(!c)return false;
  if(id)trace(id,"fresh-chat-click",{
    href:location.href,
    visibility:document.visibilityState,
    label:(c.getAttribute("aria-label")||txt(c)).slice(0,100)
  });
  c.click();
  await settleUi(350,id,"fresh-chat-settle");
  return true;
}

function blankChatShell(){
  const c=composer();
  if(!c||stopButton())return false;
  if(conversationMessageCount()>0)return false;
  if(assistantCandidates("").length>0)return false;

  // Extra semantic-role guard in case Arena changed generic message wrappers.
  const explicit=document.querySelectorAll(
    '[data-message-author-role="user"],[data-message-author-role="assistant"],'+
    '[data-role="user"],[data-role="assistant"],[data-author="user"],[data-author="assistant"]'
  );
  return explicit.length===0;
}

async function selectModel(model){
  if(!model||model==='auto')return true;
  const clean=s=>(s||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
  const base=s=>clean(String(s||'').replace(/\s*\([^)]*\)\s*$/,''));
  const wanted=clean(model),wantedBase=base(model);

  const current=[...document.querySelectorAll('button,[role="button"]')].find(x=>{
    if(!visible(x))return false;
    const t=txt(x).trim();
    return clean(t)===wanted || base(t)===wantedBase;
  });
  if(current)return true;

  const triggers=[...document.querySelectorAll('button,[role="button"]')].filter(visible);
  const trigger=triggers.find(x=>/select model|choose model|model selector/i.test(
    (x.getAttribute('aria-label')||'')+' '+(x.getAttribute('data-testid')||'')+' '+txt(x)
  ))||triggers.find(x=>/\bmodel\b/i.test(
    (x.getAttribute('aria-label')||'')+' '+(x.getAttribute('data-testid')||'')+' '+txt(x)
  ))||triggers.find(x=>/^(max|auto|battle|side by side)$/i.test(txt(x).trim()));

  if(!trigger)return false;
  trigger.click();await sleep(450);

  const nodes=[...document.querySelectorAll(
    '[role="option"],[role="menuitem"],[role="menuitemradio"],[role="listbox"] button,[role="menu"] button,li,button'
  )].filter(visible);

  const exact=nodes.find(x=>clean(txt(x))===wanted);
  const baseExact=nodes.filter(x=>base(txt(x))===wantedBase);
  const prefix=nodes.filter(x=>{
    const t=clean(txt(x)),b=base(txt(x));
    return t.startsWith(wanted+' ')||wanted.startsWith(t+' ')||
           b.startsWith(wantedBase+' ')||wantedBase.startsWith(b+' ');
  });

  const opt=exact || (baseExact.length===1?baseExact[0]:null) || (prefix.length===1?prefix[0]:null);
  if(opt){opt.click();await sleep(400);return true}
  try{document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',code:'Escape',bubbles:true}))}catch{}
  return false;
}

async function selectModelStable(model,id){
  if(!model||model==='auto')return true;
  for(let attempt=1;attempt<=3;attempt++){
    // Do not manipulate the model menu while Arena is between route renders.
    await waitForComposer(attempt===1?8000:5000,id,"pre-model-composer-wait");
    await settleUi(attempt===1?300:550);

    const ok=await selectModel(model);
    trace(id,"model-selection-attempt",{attempt,ok,model});
    if(ok){
      await settleUi(650);
      return true;
    }

    // A failed lookup may have left a menu/popover open.
    try{
      document.dispatchEvent(new KeyboardEvent('keydown',{
        key:'Escape',code:'Escape',bubbles:true,cancelable:true
      }));
    }catch{}
    await sleep(350*attempt);
  }
  return false;
}

function normalizedText(s){
  return String(s||"").replace(/\s+/g," ").trim();
}
function promptProbe(prompt){
  const p=normalizedText(prompt);
  if(!p)return "";
  // Long enough to avoid accidental overlap with a normal answer, short
  // enough to survive UI wrapping/whitespace changes.
  return p.slice(0,Math.min(180,p.length));
}
function contaminatedByPrompt(text,prompt){
  const t=normalizedText(text),probe=promptProbe(prompt);
  if(!t)return true;
  if(probe&&t.includes(probe))return true;
  // Bridgena's context capsule markers must never be surfaced as assistant
  // output even if a parent chat container is accidentally considered.
  if(/Previous messages from this same conversation are provided below/i.test(t))return true;
  if(/--- BEGIN PREVIOUS CONVERSATION ---/i.test(t))return true;
  if(/Reply to the newest user message below/i.test(t))return true;
  if(/Newest user message:/i.test(t))return true;
  return false;
}
function excludedResponseNode(el,prompt){
  if(!el||!visible(el))return true;
  if(el.closest('nav,aside,[data-sidebar],[role="navigation"],form'))return true;
  if(el.matches('textarea,input,[contenteditable="true"]')||el.querySelector('textarea,input,[contenteditable="true"]'))return true;
  const t=normalizedText(txt(el));
  if(!t||contaminatedByPrompt(t,prompt))return true;
  return false;
}

function explicitAssistantCandidates(prompt=""){
  const selectors=[
    '[data-message-author-role="assistant"]',
    '[data-role="assistant"]',
    '[data-author="assistant"]',
    '[data-testid*="assistant" i]',
    '[aria-label*="assistant" i]'
  ];
  const out=[],seen=new Set();
  for(const s of selectors){
    for(const el of document.querySelectorAll(s)){
      if(seen.has(el)||excludedResponseNode(el,prompt))continue;
      const v=txt(el);
      if(!v||contaminatedByPrompt(v,prompt))continue;
      seen.add(el);out.push({el,text:v});
    }
  }
  return out;
}

function assistantCandidates(prompt=""){
  // Diagnostics only: explicit assistant-semantic nodes. Generic article/
  // markdown/message containers are intentionally excluded here because they
  // can contain both the user prompt and the assistant region.
  return explicitAssistantCandidates(prompt);
}

function assistantSnapshot(prompt=""){
  const a=explicitAssistantCandidates(prompt);
  return a.length?a[a.length-1].text:"";
}

function chatRoot(c){
  const attached=(c&&c.isConnected)?c:null;
  const fromComposer=attached?.closest('main');
  return (fromComposer&&fromComposer.isConnected?fromComposer:null)||document.querySelector('main')||document.body;
}

function responseTracker(c,prompt,id){
  const root=chatRoot(c);
  const baselineNodes=new WeakSet();
  for(const el of root.querySelectorAll('*'))baselineNodes.add(el);

  let bestEl=null,bestText="",lastMutation=Date.now(),mutations=0;
  const explicitSelector='[data-message-author-role="assistant"],[data-role="assistant"],[data-author="assistant"],[data-testid*="assistant" i],[aria-label*="assistant" i]';
  const genericSelector='article,[role="article"],[data-testid*="message" i],[class*="message" i],[class*="prose" i],[class*="markdown" i]';

  const semanticStrength=el=>{
    if(el.matches(explicitSelector))return 3;
    if(el.closest(explicitSelector))return 2;
    if(el.matches(genericSelector))return 1;
    return 0;
  };

  const score=(el,t,isNew)=>{
    let s=Math.min(t.length,4000);
    const sem=semanticStrength(el);
    s+=sem*2500;
    if(isNew)s+=1800;
    // Prefer leaf-ish response regions over giant conversation wrappers.
    const childText=[...el.children].reduce((n,ch)=>n+normalizedText(txt(ch)).length,0);
    if(childText<t.length*0.9)s+=500;
    const r=el.getBoundingClientRect();
    if(r.top>0)s+=Math.min(300,r.top/5);
    return s;
  };

  const consider=el=>{
    if(!(el instanceof Element)||!root.contains(el))return;
    // Do not climb arbitrary parents anymore. Only inspect the changed/new
    // element itself and the nearest message-like boundary. This prevents a
    // mutation inside the user message from promoting the whole chat wrapper.
    const boundary=el.closest(explicitSelector+','+genericSelector);
    const chain=[el,boundary].filter((x,i,a)=>x&&a.indexOf(x)===i);
    for(const x of chain){
      if(!root.contains(x)||excludedResponseNode(x,prompt))continue;
      const t=normalizedText(txt(x));
      if(!t||contaminatedByPrompt(t,prompt))continue;

      const isNew=!baselineNodes.has(x);
      const sem=semanticStrength(x);
      // Generic nodes are eligible only when they were created after submit.
      // Existing generic wrappers are too ambiguous to classify safely.
      if(sem<2&&!isNew)continue;

      const s=score(x,t,isNew);
      const currentScore=bestEl?score(bestEl,bestText,!baselineNodes.has(bestEl)):-1;
      if(s>currentScore){
        bestEl=x;bestText=t;
      }else if(x===bestEl&&t!==bestText){
        bestText=t;
      }
    }
  };

  const mo=new MutationObserver(ms=>{
    mutations+=ms.length;lastMutation=Date.now();
    for(const m of ms){
      if(m.type==="characterData"){
        consider(m.target.parentElement);
      }else{
        for(const n of m.addedNodes){
          if(n.nodeType===1){
            consider(n);
            // A newly inserted message shell may already contain the real
            // assistant body by the time MutationObserver runs.
            for(const d of n.querySelectorAll?.(explicitSelector+','+genericSelector)||[])consider(d);
          }
        }
        // Only reconsider the target if it has explicit assistant semantics.
        if(m.target instanceof Element && (m.target.matches(explicitSelector)||m.target.closest(explicitSelector))){
          consider(m.target);
        }
      }
    }
  });
  mo.observe(root,{subtree:true,childList:true,characterData:true});
  trace(id,"response-observer-started",{root:root.tagName,mode:"assistant-boundary"});

  return {
    snapshot(){
      const explicit=assistantSnapshot(prompt);
      if(explicit&&!contaminatedByPrompt(explicit,prompt)){
        if(!bestText||explicit.length>=bestText.length)return explicit;
      }
      if(bestEl&&root.contains(bestEl)&&visible(bestEl)){
        const live=normalizedText(txt(bestEl));
        if(live&&!contaminatedByPrompt(live,prompt))bestText=live;
      }
      return contaminatedByPrompt(bestText,prompt)?"":bestText;
    },
    stats(){
      return {
        mutations,
        best_chars:bestText.length,
        idle_ms:Date.now()-lastMutation,
        best_semantic:bestEl?semanticStrength(bestEl):0
      };
    },
    stop(){try{mo.disconnect()}catch{}}
  };
}
function bodyHasPrompt(prompt){
  return committedPromptCount(prompt)>0;
}
function composerValue(c){return (c?.value??c?.innerText??c?.textContent??"").trim()}

function visibleUserMessageCount(){
  const sels=[
    '[data-message-author-role="user"]',
    '[data-role="user"]',
    '[data-author="user"]',
    '[data-testid*="user" i]'
  ];
  const seen=new Set();
  for(const s of sels){
    for(const e of document.querySelectorAll(s)){
      if(visible(e))seen.add(e);
    }
  }
  return seen.size;
}

async function nativeSubmit(el,id){
  try{
    let x=null,y=null;
    if(el&&visible(el)){
      el.scrollIntoView({block:'center',inline:'center'});
      await sleep(40);
      const r=el.getBoundingClientRect();
      x=r.left+r.width/2;
      y=r.top+r.height/2;
    }
    const result=await chrome.runtime.sendMessage({
      type:"BRIDGENA_NATIVE_SUBMIT_LOCAL",
      request_id:id,
      x,y
    });
    trace(id,"submit-native-cdp",{
      ok:!!result?.ok,
      method:result?.method||"",
      error:String(result?.error||"").slice(0,140)
    });
    return !!result?.ok;
  }catch(e){
    trace(id,"submit-native-cdp-error",{message:String(e?.message||e).slice(0,140)});
    return false;
  }
}

function realClick(el,id){
  if(!el)return false;
  try{
    el.scrollIntoView({block:'center',inline:'center'});
    const r=el.getBoundingClientRect();
    const x=r.left+r.width/2,y=r.top+r.height/2;
    const common={bubbles:true,cancelable:true,composed:true,clientX:x,clientY:y,button:0};
    el.dispatchEvent(new PointerEvent('pointerdown',{...common,buttons:1,pointerId:1,pointerType:'mouse',isPrimary:true}));
    el.dispatchEvent(new MouseEvent('mousedown',{...common,buttons:1}));
    el.dispatchEvent(new PointerEvent('pointerup',{...common,buttons:0,pointerId:1,pointerType:'mouse',isPrimary:true}));
    el.dispatchEvent(new MouseEvent('mouseup',{...common,buttons:0}));
    el.dispatchEvent(new MouseEvent('click',{...common,buttons:0}));
    try{el.click()}catch{}
    trace(id,"submit-real-click",{
      tag:el.tagName,
      label:(el.getAttribute("aria-label")||txt(el)).slice(0,120),
      disabled:!!el.disabled
    });
    return true;
  }catch(e){
    trace(id,"submit-real-click-error",{message:String(e?.message||e).slice(0,120)});
    return false;
  }
}

async function submitPrompt(c,payload,id){
  const startHref=location.href;
  const startCommitted=committedPromptCount(payload);
  const startMessages=conversationMessageCount();
  const startUsers=visibleUserMessageCount();
  const startAssistants=assistantCandidates(payload).length;
  const startGenerating=!!stopButton();

  await setValue(c,payload,id);
  const initialButton=submitControl(c);
  trace(id,"prompt-inserted",{
    composer:c.tagName,
    chars:payload.length,
    value_chars:composerValue(c).length,
    send_found:!!initialButton,
    send_disabled:!!initialButton?.disabled,
    send_label:initialButton?(initialButton.getAttribute("aria-label")||txt(initialButton)).slice(0,100):"",
    baseline_messages:startMessages,
    baseline_users:startUsers,
    baseline_assistants:startAssistants
  });

  const evidence=()=>{
    const liveComposer=(c&&c.isConnected)?c:composer();
    const committedNow=committedPromptCount(payload);
    const messageNow=conversationMessageCount();
    const userNow=visibleUserMessageCount();
    const assistantNow=assistantCandidates(payload).length;
    const generatingNow=!!stopButton();

    const committed=committedNow>startCommitted;
    const newMessage=messageNow>startMessages;
    const newUser=userNow>startUsers;
    const assistant=assistantNow>startAssistants;
    const generating=!startGenerating&&generatingNow;
    const cleared=liveComposer?composerValue(liveComposer).length===0:false;
    const hrefChanged=location.href!==startHref;

    // Strong acknowledgement is explicitly a before/after transition. Existing
    // assistant messages in a sticky chat are never allowed to count.
    const strong=committed||newUser||assistant||generating||(cleared&&newMessage);
    return {
      strong,committed,newMessage,newUser,assistant,generating,cleared,hrefChanged,
      committed_count:committedNow,message_count:messageNow,user_count:userNow,
      assistant_count:assistantNow
    };
  };

  const waitStrong=async(ms,stage)=>{
    const deadline=Date.now()+ms;
    let lastDiag=0;
    while(Date.now()<deadline){
      await sleep(140);
      const e=evidence();
      if(e.strong){
        trace(id,stage,e);
        return true;
      }
      if(challengePresent()||loginRequired())return false;
      if(Date.now()-lastDiag>2200){
        lastDiag=Date.now();
        trace(id,"submission-ack-wait",{
          stage,
          committed:e.committed,newMessage:e.newMessage,newUser:e.newUser,
          assistant:e.assistant,generating:e.generating,cleared:e.cleared,
          hrefChanged:e.hrefChanged
        });
      }
    }
    return false;
  };

  trace(id,"submit-enter-keydown",{form:!!c.closest("form")});
  c.focus();
  c.dispatchEvent(new KeyboardEvent('keydown',{
    key:'Enter',code:'Enter',keyCode:13,which:13,
    bubbles:true,cancelable:true,composed:true,
    ctrlKey:false,shiftKey:false,altKey:false,metaKey:false
  }));
  await sleep(80);
  c.dispatchEvent(new KeyboardEvent('keyup',{
    key:'Enter',code:'Enter',keyCode:13,which:13,
    bubbles:true,cancelable:true,composed:true
  }));

  if(await waitStrong(4200,"submission-confirmed"))return true;

  // A route change + cleared composer is ambiguous: a new chat shell may have
  // been created without the generation being accepted. Do not blindly replay
  // the prompt. Give the live DOM several seconds to produce a committed user
  // message or generation signal first.
  let e=evidence();
  if(e.cleared&&e.hrefChanged){
    trace(id,"submission-route-ambiguous",e);
    if(await waitStrong(12000,"submission-confirmed-delayed"))return true;
    trace(id,"submission-ambiguous-no-ack",evidence());
    return false;
  }

  // Synthetic Enter genuinely did nothing and the text is still in the
  // composer, so a browser-level click is safe as a fallback.
  let liveComposer=(c&&c.isConnected)?c:composer();
  const clickTarget=submitControl(liveComposer);
  if(liveComposer&&composerValue(liveComposer)&&clickTarget&&!clickTarget.disabled){
    await nativeSubmit(clickTarget,id);
    if(await waitStrong(4200,"submission-confirmed-native"))return true;

    e=evidence();
    if(e.cleared&&e.hrefChanged){
      if(await waitStrong(9000,"submission-confirmed-native-delayed"))return true;
      trace(id,"submission-native-ambiguous-no-ack",evidence());
      return false;
    }

    realClick(clickTarget,id);
    if(await waitStrong(2600,"submission-confirmed-click"))return true;
  }else if(liveComposer&&composerValue(liveComposer)){
    liveComposer.focus();
    await nativeSubmit(null,id);
    if(await waitStrong(3200,"submission-confirmed-native-enter"))return true;
  }

  liveComposer=(liveComposer&&liveComposer.isConnected)?liveComposer:composer();
  const form=liveComposer?.closest("form");
  if(liveComposer&&composerValue(liveComposer)&&form&&typeof form.requestSubmit==="function"){
    trace(id,"submit-fallback-requestSubmit");
    try{
      const submitter=[...form.querySelectorAll('button,input[type="submit"]')]
        .find(x=>!x.disabled&&(x.type==="submit"||/send|submit/i.test((x.getAttribute("aria-label")||"")+" "+txt(x))));
      form.requestSubmit(submitter||undefined);
    }catch(err){
      trace(id,"requestSubmit-error",{message:String(err?.message||err).slice(0,120)});
    }
    if(await waitStrong(2600,"submission-confirmed-fallback"))return true;
  }

  const finalComposer=(liveComposer&&liveComposer.isConnected)?liveComposer:composer();
  const finalButton=submitControl(finalComposer);
  const finalEvidence=evidence();
  trace(id,"submission-unconfirmed",{
    value_chars:finalComposer?composerValue(finalComposer).length:0,
    committed_delta:committedPromptCount(payload)-startCommitted,
    message_delta:conversationMessageCount()-startMessages,
    user_delta:visibleUserMessageCount()-startUsers,
    assistant_delta:assistantCandidates(payload).length-startAssistants,
    send_found:!!finalButton,
    send_disabled:!!finalButton?.disabled,
    href_changed:location.href!==startHref,
    generating:!!stopButton(),
    challenge:challengePresent(),
    login_required:loginRequired(),
    strong:finalEvidence.strong
  });
  return false;
}

async function run(job){
  if(active){emit('error',job.request_id,{message:'worker already has an active job'});return}
  active={id:job.request_id,last:'',cancel:false};
  try{
    trace(job.request_id,"job-received",{
      model:job.model||"auto",
      navigation_recovered:!!job._navigation_recovered,
      visibility:document.visibilityState,
      href:location.href
    });
    phase(job.request_id,"started");
    if(loginRequired()){trace(job.request_id,"login-required");emit('login_required',job.request_id);return}
    if(challengePresent()){trace(job.request_id,"challenge-visible");emit('challenge',job.request_id);return}

    let usingSession=!!job.reuse_session;
    if(usingSession){
      const resumed=await restoreSession(job.session_url,job.request_id);
      if(!resumed){
        trace(job.request_id,"session-restore-failed",{url:job.session_url||""});
        usingSession=false;
      }
    }

    if(!usingSession){
      trace(job.request_id,"fresh-chat-preflight",{
        blank_shell:blankChatShell(),
        navigation_recovered:!!job._navigation_recovered,
        messages:conversationMessageCount(),
        href:location.href
      });

      if(blankChatShell()){
        // Fresh keeper startup already gives us an empty Arena conversation.
        // Clicking "New chat" here only adds a navigation/rerender failure
        // surface and provides no isolation benefit.
        trace(job.request_id,"fresh-chat",{
          clicked:false,reused_blank:true,
          recovery:!!job.reuse_session,
          navigation_recovered:!!job._navigation_recovered
        });
      }else{
        phase(job.request_id,"pre_navigation");
        const nc=await clickNewChat(job.request_id);
        trace(job.request_id,"fresh-chat",{
          clicked:nc,reused_blank:false,
          recovery:!!job.reuse_session,
          navigation_recovered:!!job._navigation_recovered
        });
        phase(job.request_id,"post_navigation");

        let postFresh=await waitForComposer(10000,job.request_id,"post-fresh-chat-wait");
        if(!postFresh&&nc){
          await settleUi(650,job.request_id,"fresh-chat-retry-settle");
          phase(job.request_id,"pre_navigation");
          const nc2=await clickNewChat(job.request_id);
          trace(job.request_id,"fresh-chat-retry",{clicked:nc2});
          phase(job.request_id,"post_navigation");
          postFresh=await waitForComposer(8000,job.request_id,"post-fresh-chat-retry-wait");
        }
      }
    }

    // A resumed Arena chat already owns its model. On a fresh/rebuilt chat we
    // select it exactly once. Python invalidates a sticky session if the client
    // changes models.
    let modelOk=true;
    if(!usingSession){
      modelOk=await selectModelStable(job.model,job.request_id);
      trace(job.request_id,"model-selection",{ok:modelOk,model:job.model||"auto"});
    }else{
      trace(job.request_id,"model-selection-skipped-session",{model:job.model||"auto"});
    }
    if(job.model&&job.model!=="auto"&&!modelOk){
      trace(job.request_id,"model-selection-unresolved",{model:job.model});
      throw new Error("Arena requested model could not be selected");
    }

    let c=await waitForComposer(12000,job.request_id,"post-model-composer-wait");
    if(!c){
      try{
        document.dispatchEvent(new KeyboardEvent('keydown',{
          key:'Escape',code:'Escape',bubbles:true,cancelable:true
        }));
      }catch{}
      await settleUi(700);
      c=await waitForComposer(6000,job.request_id,"composer-recovery-wait");
    }
    if(!c){
      trace(job.request_id,"composer-missing",{
        href:location.href,readyState:document.readyState,
        login_required:loginRequired(),challenge:challengePresent(),usingSession
      });
      throw new Error('Arena composer not found');
    }
    trace(job.request_id,"composer-found",{
      tag:c.tagName,placeholder:c.getAttribute("placeholder")||"",
      form:!!c.closest("form"),usingSession
    });

    const basePrompt=usingSession?job.prompt:(job.recovery_prompt||job.prompt);
    const payload=((!usingSession&&job.system_prompt)?('System instructions:\n'+job.system_prompt+'\n\n'):'')+basePrompt;
    const baseline=assistantSnapshot(payload);
    let tracker=responseTracker(c,payload,job.request_id);
    phase(job.request_id,"pre_submit");
    const submitted=await submitPrompt(c,payload,job.request_id);
    if(!submitted){
      tracker.stop();
      if(challengePresent()){
        trace(job.request_id,"challenge-during-submit");
        emit('challenge',job.request_id);
        return;
      }
      if(loginRequired()){
        trace(job.request_id,"login-required-during-submit");
        emit('login_required',job.request_id);
        return;
      }
      if(usingSession)throw new Error("Arena session submit could not be strongly confirmed");
      throw new Error("Arena prompt could not be strongly confirmed as submitted");
    }

    phase(job.request_id,"submitted");
    // Capture the real Arena conversation as soon as a committed submit exists.
    emit('session_update',job.request_id,{chat_id:job.chat_id||"",url:location.href,model:job.model||"auto"});

    // A first submit may replace the whole route/main. Never reattach the
    // mutation observer through a stale textarea from the previous React tree.
    tracker.stop();
    const liveComposer=await waitForComposer(2500,job.request_id,"post-submit-live-root-wait");
    tracker=responseTracker(liveComposer&&liveComposer.isConnected?liveComposer:null,payload,job.request_id);
    trace(job.request_id,"response-observer-rebased",{
      live_composer:!!(liveComposer&&liveComposer.isConnected),
      href:location.href
    });

    emit('accepted',job.request_id);
    trace(job.request_id,"accepted",{baseline_chars:baseline.length,using_session:usingSession});

    let lastChange=Date.now(),seen=false,startedGenerating=false,lastDiag=Date.now();
    let generationStoppedAt=0,lastGenerating=false,completionProbeAt=0;
    const COMPLETE_TEXT_IDLE_MS=2800;
    const COMPLETE_MUTATION_IDLE_MS=1400;
    const COMPLETE_STOP_GRACE_MS=2200;

    while(!active.cancel){
      if(challengePresent()){trace(job.request_id,"challenge-during-job");emit('challenge',job.request_id);return}

      const generating=!!stopButton();
      if(generating&&!startedGenerating){
        startedGenerating=true;
        trace(job.request_id,"generation-started");
      }
      if(lastGenerating&&!generating){
        generationStoppedAt=Date.now();
        trace(job.request_id,"generation-stop-observed");
      }else if(generating){
        generationStoppedAt=0;
      }
      lastGenerating=generating;

      const cur=tracker.snapshot();
      if(Date.now()-lastDiag>3000){
        const st=tracker.stats();
        trace(job.request_id,"response-observer",{
          mutations:st.mutations,
          best_chars:st.best_chars,
          generating,
          text_idle_ms:Date.now()-lastChange,
          mutation_idle_ms:st.idle_ms
        });
        lastDiag=Date.now();
      }

      if(cur&&cur!==baseline){
        if(!seen){
          seen=true;
          trace(job.request_id,"assistant-found",{
            chars:cur.length,
            candidates:assistantCandidates(payload).length
          });
        }

        if(cur.startsWith(active.last)){
          const d=cur.slice(active.last.length);
          if(d){
            active.last=cur;
            lastChange=Date.now();
            completionProbeAt=0;
            emit('delta',job.request_id,{text:d});
          }
        }else if(!active.last){
          active.last=cur;
          lastChange=Date.now();
          completionProbeAt=0;
          emit('delta',job.request_id,{text:cur});
        }else if(cur!==active.last){
          let n=0,lim=Math.min(active.last.length,cur.length);
          while(n<lim&&active.last[n]===cur[n])n++;
          if(n>=Math.min(24,active.last.length)){
            const d=cur.slice(n);
            active.last=cur;
            lastChange=Date.now();
            completionProbeAt=0;
            if(d)emit('delta',job.request_id,{text:d});
          }
        }
      }

      if(seen&&!generating){
        const now=Date.now();
        const st=tracker.stats();
        const textIdle=now-lastChange;
        const mutationIdle=st.idle_ms;
        const stopGrace=!startedGenerating || (generationStoppedAt>0 && now-generationStoppedAt>=COMPLETE_STOP_GRACE_MS);

        if(
          textIdle>=COMPLETE_TEXT_IDLE_MS &&
          mutationIdle>=COMPLETE_MUTATION_IDLE_MS &&
          stopGrace
        ){
          // One extra delayed snapshot guards against Arena briefly removing
          // its Stop control between token batches / DOM rerenders.
          if(!completionProbeAt){
            completionProbeAt=now;
            trace(job.request_id,"completion-candidate",{
              chars:active.last.length,
              text_idle_ms:textIdle,
              mutation_idle_ms:mutationIdle,
              stop_grace_ms:generationStoppedAt?now-generationStoppedAt:null
            });
          }else if(now-completionProbeAt>=700){
            const finalSnapshot=tracker.snapshot();
            if(finalSnapshot&&finalSnapshot!==active.last){
              if(finalSnapshot.startsWith(active.last)){
                const d=finalSnapshot.slice(active.last.length);
                active.last=finalSnapshot;
                lastChange=Date.now();
                completionProbeAt=0;
                if(d)emit('delta',job.request_id,{text:d});
              }else{
                completionProbeAt=0;
                lastChange=Date.now();
              }
            }else{
              const finalStats=tracker.stats();
              if(
                Date.now()-lastChange>=COMPLETE_TEXT_IDLE_MS &&
                finalStats.idle_ms>=COMPLETE_MUTATION_IDLE_MS
              ){
                trace(job.request_id,"done",{
                  chars:active.last.length,
                  text_idle_ms:Date.now()-lastChange,
                  mutation_idle_ms:finalStats.idle_ms,
                  completion_grace:true
                });
                tracker.stop();
                emit('session_update',job.request_id,{chat_id:job.chat_id||"",url:location.href,model:job.model||"auto"});
                emit('done',job.request_id,{text:active.last});
                return;
              }
            }
          }
        }else{
          completionProbeAt=0;
        }
      }else{
        completionProbeAt=0;
      }

      if(startedGenerating&&!seen&&Date.now()-lastChange>8000){
        const st=tracker.stats();
        trace(job.request_id,"generation-without-visible-response",{
          mutations:st.mutations,
          best_chars:st.best_chars
        });
        lastChange=Date.now();
      }
      await sleep(180);
    }
    tracker.stop();
    throw new Error('job cancelled');
  }catch(e){
    trace(job.request_id,"job-error",{message:String(e?.message||e).slice(0,250)});
    emit('error',job.request_id,{message:String(e?.message||e)})
  }finally{active=null}
}

chrome.runtime.onMessage.addListener((m)=>{
  if(m?.type==='BRIDGENA_SEND')run(m.job);
  else if(m?.type==='BRIDGENA_CANCEL'&&active?.id===m.request_id)active.cancel=true
});

setTimeout(()=>{
  chrome.runtime.sendMessage({
    type:"BRIDGENA_CONTENT_READY_LOCAL",
    href:location.href,
    visibility:document.visibilityState
  }).catch(()=>{});
},80);

function publishState(){
  const challenge=challengePresent(),login=loginRequired(),ready=!challenge&&!login&&!!composer();
  emit('worker_state','',{ready,login_required:login,challenge});
}
setTimeout(publishState,1200);
setInterval(publishState,5000);
"""
        with open(content_path, "w", encoding="utf-8") as fh:
            fh.write(content_source)

        token_mode="configured" if os.environ.get("BRIDGENA_V4_EXTENSION_TOKEN") else "ephemeral"
        log("INFO", f"v4 worker bootstrap synchronized · ws={ws_url} · token={token_mode} · storage-safe · native-editor + navigation-deadlock recovery v4.2.2")
        return True
    except Exception as exc:
        log("WARN", f"v4 extension bootstrap preparation failed: {type(exc).__name__}: {redact(str(exc))[:180]}")
        return False

if V4_TRANSPORT == "extension" and V4_AUTO_ATTACH_KEEPERS:
    os.environ["BRIDGENA_CAPTCHA_EXT"] = V4_EXTENSION_DIR
    log("INFO", f"v4 extension injection path forced to bundled worker: {V4_EXTENSION_DIR}")
    _v4_prepare_bundled_extension()

_v4_workers: Dict[str, dict] = {}
_v4_jobs: Dict[str, asyncio.Queue] = {}
_v4_worker_lock = asyncio.Lock()
_v4_model_stats: Dict[str, dict] = {}
_v4_browser_process = None


def _v4_stat(model: str) -> dict:
    key = str(model or "auto")
    return _v4_model_stats.setdefault(key, {"ok":0,"fail":0,"ttfb":deque(maxlen=40),"duration":deque(maxlen=40)})


def _v4_worker_score(worker: dict, model: str) -> float:
    # v4.1.6: a connected local extension worker is schedulable unless there is
    # a concrete reason not to use it. The content-script `ready` bit is
    # advisory because Arena page transitions can transiently publish
    # ready=false even after the keeper/browser has passed server readiness.
    if worker.get("busy") or worker.get("ws") is None:
        return -1e9
    if worker.get("challenge") or worker.get("login_required"):
        return -1e9
    last_seen = float(worker.get("last_seen") or 0)
    if last_seen and (time.monotonic() - last_seen) > 45.0:
        return -1e9
    score = 100.0
    if not worker.get("ready"):
        score -= 8.0
    score -= min(30.0, float(worker.get("latency_ms") or 0) / 100.0)
    score -= min(25.0, float(worker.get("recent_errors") or 0) * 5.0)
    seen = (worker.get("models") or {}).get(str(model), {})
    if seen:
        ok=float(seen.get("ok") or 0); fail=float(seen.get("fail") or 0)
        total=ok+fail
        if total:
            score += 20.0*(ok/total) - 15.0*(fail/total)
        score -= min(20.0, float(seen.get("avg_ttfb_ms") or 0)/1000.0)
    # Prefer the longest-idle healthy worker to distribute wear/load.
    score += min(10.0, max(0.0, time.monotonic()-float(worker.get("last_used") or 0))/30.0)
    return score


async def _v4_pick_worker(model: str, wait_sec: float = 20.0,
                          preferred_worker_id: str = "", preferred_only: bool = False) -> Optional[dict]:
    deadline=time.monotonic()+max(0.1, wait_sec)
    preferred_worker_id=str(preferred_worker_id or "")
    while time.monotonic() < deadline:
        async with _v4_worker_lock:
            if preferred_worker_id:
                preferred=_v4_workers.get(preferred_worker_id)
                if preferred and _v4_worker_score(preferred, model) > -1e8:
                    preferred["busy"]=True
                    preferred["last_used"]=time.monotonic()
                    return preferred
                if preferred_only:
                    candidates=[]
                else:
                    candidates=sorted(_v4_workers.values(), key=lambda w:_v4_worker_score(w, model), reverse=True)
            else:
                candidates=sorted(_v4_workers.values(), key=lambda w:_v4_worker_score(w, model), reverse=True)
            if candidates and _v4_worker_score(candidates[0], model) > -1e8:
                worker=candidates[0]
                worker["busy"]=True
                worker["last_used"]=time.monotonic()
                return worker
        await asyncio.sleep(0.15)
    return None


async def _v4_release_worker(worker_id: str, *, success: bool, model: str, ttfb: Optional[float]=None, duration: Optional[float]=None):
    async with _v4_worker_lock:
        worker=_v4_workers.get(worker_id)
        if not worker: return
        worker["busy"]=False
        worker["last_success"] = time.time() if success else worker.get("last_success",0)
        worker["recent_errors"] = max(0, int(worker.get("recent_errors") or 0) - 1) if success else min(20, int(worker.get("recent_errors") or 0)+1)
        ms=worker.setdefault("models",{}).setdefault(str(model), {"ok":0,"fail":0,"avg_ttfb_ms":0.0})
        ms["ok" if success else "fail"] += 1
        if success and ttfb is not None:
            old=float(ms.get("avg_ttfb_ms") or 0.0)
            ms["avg_ttfb_ms"] = (old*0.8 + ttfb*1000*0.2) if old else ttfb*1000
    stat=_v4_stat(model)
    stat["ok" if success else "fail"] += 1
    if ttfb is not None: stat["ttfb"].append(ttfb)
    if duration is not None: stat["duration"].append(duration)


async def _v4_extension_run_turn(chat_id: str, prompt: str, model_name: str,
                                 attachments=None, system_prompt: str="",
                                 tenant_id: str="", handoff_prompt: str="",
                                 turn_prompt: str=""):
    session=_v4_session_get(chat_id, model_name)
    worker=None
    if session and session.get("worker_id"):
        worker=await _v4_pick_worker(
            model_name, wait_sec=12.0,
            preferred_worker_id=str(session.get("worker_id") or ""),
            preferred_only=True,
        )
        if not worker:
            _v4_session_drop(chat_id, "bound worker unavailable; rebuilding from client transcript")
            session=None
    if not worker:
        worker=await _v4_pick_worker(model_name, wait_sec=20.0)
    if not worker:
        if V4_FALLBACK_LEGACY:
            async for item in run_turn(chat_id, prompt, model_name, attachments=attachments,
                                       system_prompt=system_prompt, tenant_id=tenant_id,
                                       handoff_prompt=handoff_prompt):
                yield item
            return
        yield ("error", "503: no healthy headed-browser extension worker became available within 20s")
        return

    worker_id=str(worker["id"])
    request_id="v4-"+uuid7()
    q=asyncio.Queue(maxsize=512)
    _v4_jobs[request_id]=q
    started=time.monotonic(); first=None; success=False; accumulated=""
    try:
        reuse_session=bool(session)
        effective_prompt=(turn_prompt or prompt) if reuse_session else (handoff_prompt or prompt)
        payload={
            "type":"send_message", "request_id":request_id,
            "chat_id":chat_id, "model":model_name,
            "prompt":effective_prompt,
            "recovery_prompt":handoff_prompt or prompt,
            "system_prompt":system_prompt or "",
            "fresh_chat":not reuse_session, "disposable":False,
            "reuse_session":reuse_session,
            "session_url":str((session or {}).get("url") or ""),
        }
        log("INFO", f"v4 job dispatch · {request_id[-12:]} · worker={worker_id} · model={model_name} · "
                    f"session={'resume' if reuse_session else 'new'} · chat={str(chat_id)[:18]}…")
        await worker["ws"].send_json(payload)
        first_deadline=started+V4_FIRST_TOKEN_SEC
        hard_deadline=started+V4_JOB_MAX_SEC
        last_activity=started
        while True:
            now=time.monotonic()
            if now >= hard_deadline:
                try: await worker["ws"].send_json({"type":"cancel","request_id":request_id})
                except Exception: pass
                yield ("error", f"504: headed-browser job exceeded {V4_JOB_MAX_SEC:.0f}s")
                return
            timeout=min(1.0, hard_deadline-now)
            try:
                event=await asyncio.wait_for(q.get(), timeout=timeout)
            except asyncio.TimeoutError:
                now=time.monotonic()
                if first is None and now >= first_deadline:
                    try: await worker["ws"].send_json({"type":"cancel","request_id":request_id})
                    except Exception: pass
                    yield ("error", f"504: headed-browser worker produced no assistant output within {V4_FIRST_TOKEN_SEC:.0f}s")
                    return
                if first is not None and now-last_activity >= V4_IDLE_STREAM_SEC:
                    try: await worker["ws"].send_json({"type":"cancel","request_id":request_id})
                    except Exception: pass
                    yield ("error", f"504: headed-browser response stalled for {V4_IDLE_STREAM_SEC:.0f}s")
                    return
                continue
            et=str(event.get("type") or "")
            last_activity=time.monotonic()
            if et == "trace":
                stage=str(event.get("stage") or "?")
                extras={k:v for k,v in event.items() if k not in {"type","request_id","stage"}}
                log("INFO", f"v4 job trace · {request_id[-12:]} · {stage}" + (f" · {redact(str(extras))[:260]}" if extras else ""))
                continue
            if et == "accepted":
                log("INFO", f"v4 job accepted · {request_id[-12:]} · worker={worker_id}")
                continue
            if et == "session_update":
                session_url=str(event.get("url") or "")
                _v4_session_bind(chat_id, worker_id, session_url, model_name)
                log("INFO", f"v4 sticky session bound · {str(chat_id)[:18]}… · worker={worker_id} · "
                            f"url={'yes' if session_url else 'same-tab'}")
                continue
            if et in {"state","heartbeat"}:
                continue
            if et == "challenge":
                # The extension pauses the job and reports the browser state. It
                # does not implement challenge-solving logic here.
                yield ("error", "503: headed browser requires interactive verification before this request can continue")
                return
            if et == "login_required":
                yield ("error", "503: headed browser profile is not logged in to Arena")
                return
            if et == "delta":
                piece=str(event.get("text") or "")
                if piece:
                    if first is None:
                        first=time.monotonic()
                        log("OK", f"v4 first assistant output · {request_id[-12:]} · {first-started:.2f}s")
                    accumulated += piece
                    yield ("content", piece)
                continue
            if et == "reasoning_delta":
                piece=str(event.get("text") or "")
                if piece:
                    if first is None: first=time.monotonic()
                    yield ("reasoning", piece)
                continue
            if et == "done":
                final=str(event.get("text") or "")
                if final.startswith(accumulated) and len(final)>len(accumulated):
                    tail=final[len(accumulated):]
                    accumulated+=tail
                    yield ("content", tail)
                success=True
                log("OK", f"v4 job complete · {request_id[-12:]} · chars={len(accumulated or final)} · {time.monotonic()-started:.2f}s")
                yield ("done", accumulated or final)
                return
            if et == "error":
                message=str(event.get("message") or "unknown extension error")[:500]
                if reuse_session and any(token in message.lower() for token in (
                    "session", "composer not found", "requested model could not be selected"
                )):
                    _v4_session_drop(chat_id, "session UI became unusable")
                yield ("error", "502: headed-browser worker: "+message)
                return
    except (WebSocketDisconnect, RuntimeError) as exc:
        yield ("error", f"502: headed-browser worker disconnected: {type(exc).__name__}")
    except Exception as exc:
        yield ("error", f"502: headed-browser transport error: {type(exc).__name__}: {redact(str(exc))[:240]}")
    finally:
        _v4_jobs.pop(request_id, None)
        await _v4_release_worker(worker_id, success=success, model=model_name,
                                 ttfb=(first-started) if first else None,
                                 duration=time.monotonic()-started)


async def _api_run_turn(chat_id: str, prompt: str, model_name: str, **kwargs):
    if V4_TRANSPORT == "extension":
        async for item in _v4_extension_run_turn(chat_id, prompt, model_name, **kwargs):
            yield item
    else:
        legacy_kwargs=dict(kwargs)
        legacy_kwargs.pop("turn_prompt", None)
        async for item in run_turn(chat_id, prompt, model_name, **legacy_kwargs):
            yield item


@app.websocket("/v4/extension/ws")
async def v4_extension_ws(ws: WebSocket):
    token=ws.query_params.get("token", "")
    peer=getattr(getattr(ws, "client", None), "host", "?")
    origin=str(ws.headers.get("origin") or "")[:160]
    _loopback_peer = str(peer) in {"127.0.0.1", "::1", "localhost"}
    if V4_EXTENSION_TOKEN and not hmac.compare_digest(token, V4_EXTENSION_TOKEN):
        if not _loopback_peer:
            log("WARN", f"v4 extension socket rejected · peer={peer} · origin={origin or '-'} · token mismatch")
            await ws.close(code=4403)
            return
        log("WARN", f"v4 extension socket accepted from loopback with stale token · peer={peer} · origin={origin or '-'}")
    await ws.accept()
    worker_id=None
    try:
        try:
            hello=await asyncio.wait_for(ws.receive_json(), timeout=10.0)
        except asyncio.TimeoutError:
            log("WARN", f"v4 extension socket accepted but hello timed out · peer={peer} · origin={origin or '-'}")
            await ws.close(code=4408)
            return
        if hello.get("type") != "hello":
            log("WARN", f"v4 extension socket malformed hello · peer={peer} · type={str(hello.get('type') or '-')[:40]}")
            await ws.close(code=4400); return
        worker_id=str(hello.get("worker_id") or ("browser-"+uuid7()[:8]))
        async with _v4_worker_lock:
            _v4_workers[worker_id]={
                "id":worker_id,"ws":ws,"ready":bool(hello.get("ready",True)),"busy":False,
                "challenge":False,"login_required":False,"recent_errors":0,"last_used":0.0,
                "connected_at":time.monotonic(),"last_seen":time.monotonic(),
                "latency_ms":float(hello.get("latency_ms") or 0),
                "proxy":str(hello.get("proxy") or ""),"models":{},
                "user_agent":str(hello.get("user_agent") or "")[:240],
            }
        log("OK", f"v4 extension worker connected · {worker_id}")
        await ws.send_json({"type":"hello_ack","worker_id":worker_id,"build":BUILD_STAMP})
        while True:
            msg=await ws.receive_json()
            et=str(msg.get("type") or "")
            async with _v4_worker_lock:
                worker=_v4_workers.get(worker_id)
                if worker:
                    worker["last_seen"]=time.monotonic()
                    if et == "worker_state":
                        old_ready=bool(worker.get("ready"))
                        old_challenge=bool(worker.get("challenge"))
                        old_login=bool(worker.get("login_required"))
                        worker["ready"]=bool(msg.get("ready", worker.get("ready")))
                        worker["challenge"]=bool(msg.get("challenge",False))
                        worker["login_required"]=bool(msg.get("login_required",False))
                        worker["latency_ms"]=float(msg.get("latency_ms") or worker.get("latency_ms") or 0)
                        if (old_ready != worker["ready"] or
                            old_challenge != worker["challenge"] or
                            old_login != worker["login_required"]):
                            log("INFO", f"v4 worker state · {worker_id} · ready={worker['ready']} · challenge={worker['challenge']} · login_required={worker['login_required']}")
            rid=str(msg.get("request_id") or "")
            q=_v4_jobs.get(rid)
            if q:
                try: q.put_nowait(msg)
                except asyncio.QueueFull:
                    log("WARN", f"v4 job queue full · {rid[-8:]}")
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception as exc:
        log("WARN", f"v4 extension socket ended · {worker_id or '?'} · {type(exc).__name__}: {redact(str(exc))[:160]}")
    finally:
        if worker_id:
            async with _v4_worker_lock:
                current=_v4_workers.get(worker_id)
                if current and current.get("ws") is ws:
                    _v4_workers.pop(worker_id,None)
            log("WARN", f"v4 extension worker disconnected · {worker_id}")


@app.get("/v4/workers")
async def v4_workers(request: Request):
    await _require_admin(request)
    async with _v4_worker_lock:
        rows=[]
        for w in _v4_workers.values():
            rows.append({k:v for k,v in w.items() if k not in {"ws"}})
    stats={}
    for model,s in _v4_model_stats.items():
        stats[model]={"ok":s["ok"],"fail":s["fail"],
                      "median_ttfb":sorted(s["ttfb"])[len(s["ttfb"])//2] if s["ttfb"] else None,
                      "median_duration":sorted(s["duration"])[len(s["duration"])//2] if s["duration"] else None}
    with _v4_sessions_guard:
        session_count=len(_v4_sessions)
    return JSONResponse({"build":BUILD_STAMP,"transport":V4_TRANSPORT,"workers":rows,"models":stats,
                         "sticky_sessions":session_count})


@app.get("/v4/sessions")
async def v4_sessions(request: Request):
    await _require_admin(request)
    now=time.time()
    with _v4_sessions_guard:
        rows=[{
            "chat_id":cid[:24] + ("…" if len(cid)>24 else ""),
            "worker_id":str(item.get("worker_id") or ""),
            "model":str(item.get("model") or "auto"),
            "has_url":bool(item.get("url")),
            "age_sec":max(0, int(now-float(item.get("updated") or now))),
        } for cid,item in _v4_sessions.items()]
    rows.sort(key=lambda x:x["age_sec"])
    return JSONResponse({"build":BUILD_STAMP,"ttl_sec":V4_SESSION_TTL_SEC,"count":len(rows),"sessions":rows})


def _v4_find_chrome() -> Optional[str]:
    if V4_CHROME_BIN and os.path.isfile(V4_CHROME_BIN): return V4_CHROME_BIN
    for name in ("google-chrome-stable","google-chrome","chromium","chromium-browser"):
        found=shutil.which(name)
        if found: return found
    return None


def _v4_launch_browser_once():
    global _v4_browser_process
    if _v4_browser_process and _v4_browser_process.poll() is None:
        return _v4_browser_process
    chrome=_v4_find_chrome()
    if not chrome:
        log("WARN","v4 autolaunch requested but Chrome/Chromium was not found")
        return None
    os.makedirs(V4_PROFILE_DIR,exist_ok=True)
    args=[chrome, f"--user-data-dir={V4_PROFILE_DIR}", f"--load-extension={V4_EXTENSION_DIR}",
          f"--disable-extensions-except={V4_EXTENSION_DIR}", "--no-first-run", "--no-default-browser-check",
          "--start-maximized", "https://arena.ai/"]
    # Proxy assignment is browser-lifetime scoped. Never switch it under an
    # active job; drain/restart the worker to rotate exits cleanly.
    if V4_BROWSER_PROXY:
        args.insert(-1, f"--proxy-server={V4_BROWSER_PROXY}")
    env=os.environ.copy()
    _v4_browser_process=subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    log("OK", f"v4 headed browser launched · pid {_v4_browser_process.pid} · profile {V4_PROFILE_DIR}")
    return _v4_browser_process

async def openai_stream(body: dict, keyinfo: dict):
    prompt = _format_conversation_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    model = canonical_public_model_name(body.get("model", "auto"))
    body["model"] = model
    # v4.2: stable tenant-scoped id binds follow-up API turns to the same real
    # Arena conversation. No prompt/response content is stored in the binding.
    chat_id = _logical_chat_id(body, keyinfo, "api")
    turn_prompt = _latest_user_text(body)
    tenant_id = _tenant_identity(keyinfo)
    system_prompt = _openai_system_context(body)

    created = int(time.time())
    rid = "chatcmpl-" + uuid7()[:23]
    include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
    input_text = "\n".join(
        _openai_text_content(message.get("content", ""))
        for message in body.get("messages") or [] if isinstance(message, dict)
    )

    def chunk(delta, finish=None):
        return _sse({"id": rid, "object": "chat.completion.chunk", "created": created, "model": model,
                     "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})

    async def gen():
        acc = ""
        reasoning_acc = ""
        content_chunks = 0
        reasoning_chunks = 0
        terminal_sent = False
        outcome = "complete"
        try:
            yield chunk({"role": "assistant"})
            async for kind, payload in _api_run_turn(chat_id, prompt, model,
                                                attachments=body.get("attachments"),
                                                system_prompt=system_prompt,
                                                tenant_id=tenant_id,
                                                handoff_prompt=prompt,
                                                turn_prompt=turn_prompt):
                if kind == "content":
                    acc += payload
                    content_chunks += 1
                    yield chunk({"content": payload})
                elif kind == "reasoning":
                    reasoning_piece = payload if isinstance(payload, str) else str(payload or "")
                    reasoning_acc += reasoning_piece
                    reasoning_chunks += 1
                    yield chunk({"reasoning_content": payload})
                elif kind == "error":
                    outcome = "partial-upstream-error" if content_chunks > 0 else "upstream-error"
                    status_code = _status_from_internal_error(payload, 502)
                    error_id, public_message = _openai_public_error(
                        status_code,
                        payload,
                        source="openai_stream",
                        context={
                            "model": model,
                            "chat_id": str(chat_id)[:120],
                            "partial_chars": len(acc),
                            "content_chunks": content_chunks,
                            "reasoning_chars": len(reasoning_acc),
                            "reasoning_chunks": reasoning_chunks,
                        },
                    )
                    public_error = {
                        "message": public_message,
                        "type": "api_error",
                        "code": error_id,
                        "partial_response_preserved": bool(content_chunks > 0),
                        "partial_chars": len(acc),
                    }
                    retry_after = _retry_after_from_internal_error(payload)
                    if retry_after:
                        public_error["retry_after"] = retry_after
                        public_error["retryable"] = True
                    yield _sse({"error": public_error})
                    # The partial assistant deltas (if any) have already been
                    # emitted. Send a normal terminal choice after the error so
                    # clients leave their generating state without discarding
                    # those earlier deltas.
                    yield chunk({}, finish="stop")
                    yield "data: [DONE]\n\n"
                    terminal_sent = True
                    return
                elif kind == "done":
                    # run_turn carries its complete accumulated text in the
                    # terminal event. Repair a missing suffix if an adapter
                    # delivered a final delta only in its terminal envelope.
                    complete = payload if isinstance(payload, str) else ""
                    if complete.startswith(acc) and len(complete) > len(acc):
                        tail = complete[len(acc):]
                        acc += tail
                        content_chunks += 1
                        yield chunk({"content": tail})
                    break
            yield chunk({}, finish="stop")
            if include_usage:
                prompt_tokens = _rough_tokens(input_text)
                completion_tokens = _rough_tokens(acc)
                yield _sse({
                    "id": rid, "object": "chat.completion.chunk", "created": created, "model": model,
                    "choices": [],
                    "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                              "total_tokens": prompt_tokens + completion_tokens},
                })
            yield "data: [DONE]\n\n"
            terminal_sent = True
        except Exception as e:
            outcome = "bridge-exception"
            error_id, public_message = _openai_public_error(
                500,
                f"{type(e).__name__}: {e}",
                source="openai_stream_exception",
                context={
                    "model": model,
                    "chat_id": str(chat_id)[:120],
                    "partial_chars": len(acc),
                    "content_chunks": content_chunks,
                },
                exception_type=type(e).__name__,
            )
            yield _sse({"error": {
                "message": public_message,
                "type": "api_error",
                "code": error_id,
            }})
            yield chunk({}, finish="stop")
            yield "data: [DONE]\n\n"
            terminal_sent = True
            return
        finally:
            _release_api_request(body, keyinfo, prompt)
            _record_reliability_outcome(
                bool(outcome == "complete" and terminal_sent and content_chunks > 0),
                outcome,
            )
            if terminal_sent:
                log("INFO", f"OpenAI stream {rid[-8:]} delivered · outcome {outcome} · "
                            f"content {content_chunks} chunks/{len(acc)} chars · terminal yes")
            else:
                log("WARN", f"OpenAI stream {rid[-8:]} disconnected before terminal · outcome {outcome} · "
                            f"content {content_chunks} chunks/{len(acc)} chars")
    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


async def _force_capacity_recovery_cycle(deadline: float, *, aggressive: bool = False) -> None:
    """Best-effort capacity repair used by API admission.

    This does not submit/replay user prompts. It only:
      * force-probes circuit-open exits without waiting for background backoff;
      * clears stale keeper retry timers so readiness can be rechecked now;
      * wakes the verification scheduler;
      * starts bounded same-keeper transport recovery for broken browser sessions.
    """
    # 1) Force-probe every circuit-open proxy now. The background loop may be
    # sleeping in exponential backoff, but an API request should get one fresh
    # recovery attempt within its own bounded 20s admission budget.
    qkeys = list(_QUARANTINED_KEYS)
    qproxies = [p for p in (_proxy_from_key(k) for k in qkeys) if p]
    if qproxies and time.monotonic() < deadline:
        try:
            loop = asyncio.get_running_loop()
            budget = max(0.5, min(4.0, deadline - time.monotonic()))
            await asyncio.wait_for(
                asyncio.gather(*[
                    loop.run_in_executor(None, _recover_proxy_once, proxy)
                    for proxy in qproxies[:max(1, PROBE_MAX_PARALLEL)]
                ], return_exceptions=True),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            log("WARN", f"API emergency proxy recovery recovered from {type(exc).__name__}: "
                        f"{redact(str(exc))[:120]}")

    # 2) Make all authenticated keepers immediately eligible for readiness work.
    now = time.monotonic()
    jars = {
        str(j.get("id")): j
        for j in load_jars()
        if j.get("id") and j.get("enabled", True) and jar_has_auth(j)
    }
    for sid in jars:
        _verification_preflight_retry_after.pop(sid, None)
        # Expire only API-level quarantine. Browser/session health is still checked
        # before any keeper is admitted.
        if _api_keeper_quarantine_until.get(sid, 0.0) > now:
            _api_keeper_quarantine_until.pop(sid, None)

    _wake_verification_scheduler()

    # 3) If capacity is still zero, actively repair a small bounded cohort rather
    # than merely waiting for the background scheduler. Existing recovery workers
    # are de-duplicated by _schedule_transport_recovery().
    if aggressive and _verified_keeper_count() == 0 and time.monotonic() < deadline:
        try:
            await keeper.sync()
        except Exception:
            pass
        launched = 0
        for sid in jars:
            if launched >= 3:
                break
            session = keeper.sessions.get(sid)
            if not session:
                continue
            if keeper_session_ready(session, warmed=False):
                # A running keeper may only need its readiness lease refreshed.
                _wake_verification_scheduler()
                continue
            existing = _transport_recovery_tasks.get(sid)
            if existing and not existing.done():
                continue
            _schedule_transport_recovery(sid, "API admission emergency capacity recovery")
            launched += 1


async def _require_api_ready():
    # v4 extension transport has its own capacity signal. Do not gate headed-browser
    # jobs on legacy Playwright keeper readiness. Wait up to the same bounded 20s
    # admission window for a connected, ready extension worker instead.
    if V4_TRANSPORT == "extension":
        deadline = time.monotonic() + min(_API_READY_RECOVERY_WAIT_SEC, 20.0)
        while time.monotonic() < deadline:
            if get_models():
                async with _v4_worker_lock:
                    if any(_v4_worker_score(w, "auto") > -1e8 for w in _v4_workers.values()):
                        return
            await asyncio.sleep(0.15)
        async with _v4_worker_lock:
            connected = len(_v4_workers)
            ready = sum(1 for w in _v4_workers.values() if _v4_worker_score(w, "auto") > -1e8)
            advisory_ready = sum(1 for w in _v4_workers.values() if w.get("ready"))
            challenged = sum(1 for w in _v4_workers.values() if w.get("challenge"))
            login_required = sum(1 for w in _v4_workers.values() if w.get("login_required"))
        raise HTTPException(
            status_code=503,
            detail=(f"Bridgena v4 headed-browser capacity unavailable after "
                    f"{min(_API_READY_RECOVERY_WAIT_SEC, 20.0):.0f}s: "
                    f"connected workers={connected}, schedulable workers={ready}, "
                    f"advisory-ready={advisory_ready}, challenged={challenged}, login-required={login_required}."),
            headers={"Retry-After": "1"},
        )

    models_ready = bool(get_models())

    # During cold startup, briefly wait for the first usable keeper instead of
    # making the customer manually retry while the parallel cohort is already
    # coming online.
    if not _initial_verification_sweep_done.is_set():
        _wake_verification_scheduler()
        try:
            await asyncio.wait_for(
                _initial_verification_sweep_done.wait(),
                timeout=min(_API_READY_RECOVERY_WAIT_SEC, 20.0),
            )
        except asyncio.TimeoutError:
            pass

    _refresh_api_ready_event()
    if models_ready and _api_ready_event.is_set():
        return

    # A zero-ready transition can happen while leases are being refreshed or a
    # keeper is restarting. Wake the cohort immediately and hold admission for
    # a few seconds; most recoveries are faster than a customer retry roundtrip.
    _wake_verification_scheduler()
    deadline = time.monotonic() + _API_READY_RECOVERY_WAIT_SEC
    last_verified = -1
    last_exits = -1
    last_force = 0.0
    force_round = 0
    while time.monotonic() < deadline:
        _refresh_api_ready_event()
        if bool(get_models()) and _api_ready_event.is_set():
            verified = _verified_keeper_count()
            exits = _verified_exit_count()
            log("OK", f"API admission recovered inline · verified keepers {verified} · exits {exits} · "
                      f"after {force_round} active recovery round(s)")
            return

        verified = _verified_keeper_count()
        exits = _verified_exit_count()
        now = time.monotonic()

        # Actively repair capacity every ~2.5s inside the request's own bounded
        # recovery budget. This is intentionally more aggressive than the
        # background loops when the fleet has zero usable capacity.
        if force_round == 0 or (now - last_force) >= 2.5:
            force_round += 1
            last_force = now
            await _force_capacity_recovery_cycle(
                deadline, aggressive=(verified == 0 or exits == 0)
            )
            _refresh_api_ready_event()
            if bool(get_models()) and _api_ready_event.is_set():
                verified = _verified_keeper_count()
                exits = _verified_exit_count()
                log("OK", f"API admission recovered during active repair · "
                          f"verified keepers {verified} · exits {exits} · round {force_round}")
                return

        verified = _verified_keeper_count()
        exits = _verified_exit_count()
        if verified != last_verified or exits != last_exits:
            preferred_keepers, preferred_exits = _api_preferred_targets()
            remaining = max(0.0, deadline - time.monotonic())
            log("INFO", f"API admission active recovery · verified {verified} · exits {exits} · "
                        f"target {_API_ADMISSION_MIN_KEEPERS}/{_API_ADMISSION_MIN_EXITS} · "
                        f"preferred {preferred_keepers}/{preferred_exits} · {remaining:.1f}s left")
            last_verified, last_exits = verified, exits
        await asyncio.sleep(0.25)

    verified = _verified_keeper_count()
    exits = _verified_exit_count()
    preferred_keepers, preferred_exits = _api_preferred_targets()
    raise HTTPException(
        status_code=503,
        detail=(f"Bridgena runtime capacity is temporarily unavailable after "
                f"{_API_READY_RECOVERY_WAIT_SEC:.0f}s active recovery: "
                f"usable keepers={verified}, usable exits={exits}, "
                f"preferred capacity={preferred_keepers}/{preferred_exits}."),
        headers={"Retry-After": "1"},
    )

@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request):
    await _require_api_ready()
    keyinfo = await _require_key(request)
    body = await request.json()
    body["model"] = canonical_public_model_name(body.get("model", "auto"))
    prompt = _format_conversation_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    messages = body.get("messages") or []
    await _wait_if_model_rate_limited(body.get("model", "auto"))
    log("INFO", f"OpenAI request · model {str(body.get('model') or 'auto')[:80]} · "
                f"messages {len(messages) if isinstance(messages, list) else 0} · "
                f"tools {len(body.get('tools') or []) if isinstance(body.get('tools') or [], list) else 0} · "
                f"max_tokens {body.get('max_tokens') or body.get('max_completion_tokens') or 'default'} · "
                f"usage {'yes' if (body.get('stream_options') or {}).get('include_usage') else 'no'}")
    await _pace_api_request(_tenant_identity(keyinfo))
    reserved, duplicate_count = _reserve_api_request(body, keyinfo, prompt)
    if not reserved:
        if duplicate_count == 1:
            log("INFO", f"duplicate API retries suppressed · model {str(body.get('model') or 'auto')[:80]} · "
                        f"content {len(prompt)} chars · window {API_DUPLICATE_WINDOW_SEC}s")
        raise HTTPException(status_code=429, detail="An identical request is already in flight. Wait for it to finish before retrying.", headers={"Retry-After": "2"})
    if not body.get("stream", True):
        out = {"id": "chatcmpl-" + uuid7()[:23], "object": "chat.completion", "created": int(time.time()),
               "model": body.get("model", "auto"), "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}
        acc = ""
        try:
            chat_id = _logical_chat_id(body, keyinfo, "api")
            turn_prompt = _latest_user_text(body)
            async for kind, payload in _api_run_turn(chat_id, prompt,
                                                body.get("model", "auto"),
                                                attachments=body.get("attachments"),
                                                system_prompt=_openai_system_context(body),
                                                tenant_id=_tenant_identity(keyinfo),
                                                handoff_prompt=prompt,
                                                turn_prompt=turn_prompt):
                if kind == "content":
                    acc += payload
                elif kind == "error":
                    raise HTTPException(status_code=502, detail=payload)
            out["choices"][0]["message"]["content"] = acc
            return JSONResponse(out)
        finally:
            _release_api_request(body, keyinfo, prompt)
    return await openai_stream(body, keyinfo)


def _anthropic_error(status: int, message: str, error_type: str = "invalid_request_error",
                     *, source: str = "anthropic_local_error"):
    error_id, public_message = _anthropic_public_error(
        status, message, source=source
    )
    return JSONResponse({
        "type": "error",
        "error": {"type": error_type, "message": public_message},
        "error_id": error_id,
    }, status_code=status, headers={"X-Bridgena-Error-ID": error_id, "Cache-Control": "no-store"})


async def _native_anthropic_request(request: Request, endpoint: str):
    """Forward the native protocol unchanged to Anthropic's official API.

    Client gateway credentials are checked locally and never forwarded.
    Provider credentials must be supplied by the operator, outside this file.
    """
    provider_key = os.environ.get("BRIDGENA_ANTHROPIC_API_KEY", "").strip()
    if not provider_key:
        return _anthropic_error(503, "Native Anthropic routing requires BRIDGENA_ANTHROPIC_API_KEY.", "api_error", source="native_anthropic_config")
    try:
        import httpx
    except ImportError:
        return _anthropic_error(503, "Native Anthropic routing requires the httpx package.", "api_error", source="native_anthropic_dependency")
    headers = {
        "x-api-key": provider_key,
        "anthropic-version": request.headers.get("anthropic-version", "2023-06-01"),
        "content-type": "application/json",
    }
    if request.headers.get("anthropic-beta"):
        headers["anthropic-beta"] = request.headers["anthropic-beta"]
    client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=10.0),
                               follow_redirects=False)
    response = None
    try:
        outgoing = client.build_request("POST", "https://api.anthropic.com/v1/" + endpoint,
                                        headers=headers, content=await request.body(),
                                        params=request.query_params.multi_items())
        response = await client.send(outgoing, stream=True)
        response_headers = {k: v for k, v in response.headers.items()
                            if k in {"content-type", "request-id", "retry-after"}
                            or k.startswith("anthropic-ratelimit-")}
        response_headers["cache-control"] = "no-store"
        response_headers["x-accel-buffering"] = "no"
        if response.status_code >= 400 or "text/event-stream" not in response.headers.get("content-type", ""):
            data = await response.aread()
            return Response(content=data, status_code=response.status_code, headers=response_headers)

        async def forward():
            try:
                async for chunk in response.aiter_bytes():
                    yield chunk
            except httpx.HTTPError as exc:
                error_id, public_message = _anthropic_public_error(
                    502,
                    f"Provider stream interrupted: {type(exc).__name__}: {exc}",
                    source="native_anthropic_stream",
                    exception_type=type(exc).__name__,
                )
                yield _anthropic_sse("error", {
                    "type": "error",
                    "error": {"type": "api_error", "message": public_message},
                    "error_id": error_id,
                }).encode("utf-8")
            finally:
                await response.aclose()
                await client.aclose()

        # Ownership transfers to the streaming response, including disconnect cleanup.
        stream_response = StreamingResponse(forward(), status_code=response.status_code,
                                            headers=response_headers)
        handed_off = True
        return stream_response
    except httpx.HTTPError:
        return _anthropic_error(502, "Provider connection failed; no automatic replay attempted.", "api_error", source="native_anthropic_connection")
    finally:
        if not locals().get("handed_off", False):
            if response is not None:
                await response.aclose()
            await client.aclose()


@app.post("/v1/messages/count_tokens")
async def anthropic_count_tokens(request: Request):
    await _require_key(request)
    return await _native_anthropic_request(request, "messages/count_tokens")


@app.post("/v1/messages")
@app.post("/messages")
async def anthropic_messages(request: Request):
    await _require_api_ready()
    """Native Anthropic Messages surface for clients that should not traverse
    an OpenAI-to-Anthropic stream converter."""
    keyinfo = await _require_key(request)
    if os.environ.get("BRIDGENA_ANTHROPIC_API_KEY", "").strip():
        return await _native_anthropic_request(request, "messages")
    body = await request.json()
    if body.get("tools") or body.get("tool_choice") or body.get("thinking") or any(
        isinstance(block, dict) and block.get("type") not in {"text"}
        for message in body.get("messages", []) if isinstance(message, dict)
        for block in (message.get("content") if isinstance(message.get("content"), list) else [])
    ):
        return _anthropic_error(400,
            "Browser text mode cannot preserve tools, thinking, or non-text blocks. "
            "Configure BRIDGENA_ANTHROPIC_API_KEY for native Claude Code requests.")
    prompt = _anthropic_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    model = canonical_public_model_name(body.get("model", "auto"))
    body["model"] = model
    await _wait_if_model_rate_limited(model)
    await _pace_api_request(_tenant_identity(keyinfo))
    reserved, duplicate_count = _reserve_api_request(body, keyinfo, prompt)
    if not reserved:
        if duplicate_count == 1:
            log("INFO", f"duplicate Anthropic API retries suppressed · model {str(body.get('model') or 'auto')[:80]} · "
                        f"content {len(prompt)} chars · window {API_DUPLICATE_WINDOW_SEC}s")
        raise HTTPException(status_code=409, detail="duplicate request suppressed; reuse the original stream")

    chat_id = _logical_chat_id(body, keyinfo, "anthropic")
    turn_prompt = _latest_user_text(body)
    tenant_id = _tenant_identity(keyinfo)
    system_prompt = _anthropic_system_context(body)
    message_id = "msg_" + uuid7().replace("-", "")
    input_tokens = _rough_tokens(prompt)

    if not body.get("stream", False):
        acc = ""
        try:
            async for kind, payload in _api_run_turn(chat_id, prompt, model,
                                                attachments=body.get("attachments"),
                                                system_prompt=system_prompt,
                                                tenant_id=tenant_id,
                                                handoff_prompt=prompt,
                                                turn_prompt=turn_prompt):
                if kind in ("content", "reasoning") and isinstance(payload, str):
                    acc += payload
                elif kind == "error":
                    raise HTTPException(status_code=502, detail=payload)
            return JSONResponse({
                "id": message_id, "type": "message", "role": "assistant", "model": model,
                "content": [{"type": "text", "text": acc}], "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": input_tokens, "output_tokens": _rough_tokens(acc)},
            })
        finally:
            _release_api_request(body, keyinfo, prompt)

    async def gen():
        acc = ""
        chunks = 0
        terminal_sent = False
        outcome = "complete"
        try:
            yield _anthropic_sse("message_start", {"type": "message_start", "message": {
                "id": message_id, "type": "message", "role": "assistant", "model": model,
                "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": input_tokens, "output_tokens": 0},
            }})
            yield _anthropic_sse("content_block_start", {"type": "content_block_start", "index": 0,
                                                          "content_block": {"type": "text", "text": ""}})
            async for kind, payload in _api_run_turn(chat_id, prompt, model,
                                                attachments=body.get("attachments"),
                                                system_prompt=system_prompt,
                                                tenant_id=tenant_id,
                                                handoff_prompt=prompt,
                                                turn_prompt=turn_prompt):
                if kind in ("content", "reasoning") and isinstance(payload, str):
                    acc += payload
                    chunks += 1
                    yield _anthropic_sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                                  "delta": {"type": "text_delta", "text": payload}})
                elif kind == "error":
                    outcome = "upstream-error"
                    status_code = _status_from_internal_error(payload, 502)
                    error_id, public_message = _anthropic_public_error(
                        status_code,
                        payload,
                        source="anthropic_stream",
                        context={
                            "model": model,
                            "chat_id": str(chat_id)[:120],
                            "partial_chars": len(acc),
                            "chunks": chunks,
                        },
                    )
                    anth_error = {
                        "type": "error",
                        "error": {"type": "api_error", "message": public_message},
                        "error_id": error_id,
                    }
                    retry_after = _retry_after_from_internal_error(payload)
                    if retry_after:
                        anth_error["retry_after"] = retry_after
                        anth_error["retryable"] = True
                    yield _anthropic_sse("error", anth_error)
                    # Some desktop clients wait for the ordinary terminal
                    # sequence even after receiving an error event.
                    yield _anthropic_sse("content_block_stop", {
                        "type": "content_block_stop", "index": 0
                    })
                    yield _anthropic_sse("message_delta", {
                        "type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                        "usage": {"output_tokens": _rough_tokens(acc)},
                    })
                    yield _anthropic_sse("message_stop", {"type": "message_stop"})
                    terminal_sent = True
                    return
                elif kind == "done":
                    complete = payload if isinstance(payload, str) else ""
                    if complete.startswith(acc) and len(complete) > len(acc):
                        tail = complete[len(acc):]
                        acc += tail
                        chunks += 1
                        yield _anthropic_sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                                      "delta": {"type": "text_delta", "text": tail}})
                    break
            yield _anthropic_sse("content_block_stop", {"type": "content_block_stop", "index": 0})
            yield _anthropic_sse("message_delta", {"type": "message_delta",
                                                    "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                                                    "usage": {"output_tokens": _rough_tokens(acc)}})
            yield _anthropic_sse("message_stop", {"type": "message_stop"})
            terminal_sent = True
        except Exception as e:
            outcome = "bridge-exception"
            error_id, public_message = _anthropic_public_error(
                500,
                f"{type(e).__name__}: {e}",
                source="anthropic_stream_exception",
                context={
                    "model": model,
                    "chat_id": str(chat_id)[:120],
                    "partial_chars": len(acc),
                    "chunks": chunks,
                },
                exception_type=type(e).__name__,
            )
            yield _anthropic_sse("error", {
                "type": "error",
                "error": {"type": "api_error", "message": public_message},
                "error_id": error_id,
            })
        finally:
            _release_api_request(body, keyinfo, prompt)
            _record_reliability_outcome(
                bool(outcome == "complete" and terminal_sent and chunks > 0),
                outcome,
            )
            level = "INFO" if terminal_sent or outcome == "upstream-error" else "WARN"
            log(level, f"Anthropic stream {message_id[-8:]} delivered · outcome {outcome} · "
                       f"content {chunks} chunks/{len(acc)} chars · terminal {'yes' if terminal_sent else 'no'}")

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/v1/models")
@app.get("/models")
async def models_api():
    state = load_state()
    blocked = state.get("blocked_models", [])
    now = int(time.time())
    data, seen = [], set()
    for m in get_models():
        public = model_name(m).strip()
        if not public or public in blocked or public in seen:
            continue
        seen.add(public)
        data.append({
            "id": public,
            "object": "model",
            "created": now,
            "owned_by": "arena",
        })
    return JSONResponse({"object": "list", "data": data})


@app.get("/v1/models/{model_id:path}")
@app.get("/models/{model_id:path}")
async def model_one(model_id: str):
    public = canonical_public_model_name(model_id)
    for m in get_models():
        if model_name(m) == public:
            return JSONResponse({"id": public, "object": "model", "owned_by": "arena"})
    raise HTTPException(status_code=404, detail="unknown model")


# ---------- pool api ----------
@app.get("/proxies/api/snapshot")
async def proxies_snapshot():
    return JSONResponse(snapshot_rows())


@app.post("/proxies/api/check")
async def proxies_check():
    loop = asyncio.get_running_loop()
    stats = await loop.run_in_executor(None, sweep_all)
    try:
        rebind = await rebind_keeper_fleet_to_proxy_pool("proxy sweep")
        stats["distinct_assigned"] = rebind.get("distinct_assigned", 0)
        stats["keepers_rebound"] = rebind.get("keepers_rebound", 0)
    except Exception as exc:
        log("ERROR", f"Proxy sweep succeeded, but keeper rebind failed: {type(exc).__name__}: {exc}")
        stats["rebind_error"] = f"{type(exc).__name__}: {exc}"
    return JSONResponse(stats)


@app.post("/proxies/api/upload")
async def proxies_upload(request: Request):
    form = await request.form()
    chunks = []
    txt = form.get("text")
    if txt:
        chunks.append(str(txt))
    uploaded = form.get("file")
    if uploaded is not None and hasattr(uploaded, "read"):
        try:
            raw = await uploaded.read()
            if raw:
                chunks.append(raw.decode("utf-8-sig", "replace"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not read proxy file: {exc}")
    payload = "\n".join(chunks).strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Paste at least one proxy or upload a .txt/.csv file.")
    result = upload_pool(payload)
    result["total"] = len(_pool_lines())
    if result["parsed"] == 0:
        raise HTTPException(status_code=400, detail="No valid proxies were parsed. Credentials are optional: use host:port, scheme://host:port, host:port:user:pass, or headered CSV.")

    # If capacity changed while Bridgena is already running, merely saving the
    # list is not enough: existing Chromium contexts keep their launch-time
    # proxy forever. Allocate the new pool and rebind the running keeper fleet.
    if result.get("added", 0) > 0:
        try:
            rebind = await rebind_keeper_fleet_to_proxy_pool("proxy upload")
            result["live"] = rebind.get("live", 0)
            result["distinct_assigned"] = rebind.get("distinct_assigned", 0)
            result["keepers_rebound"] = rebind.get("keepers_rebound", 0)
        except Exception as exc:
            log("ERROR", f"Proxy upload saved, but live keeper rebind failed: {type(exc).__name__}: {exc}")
            result["rebind_error"] = f"{type(exc).__name__}: {exc}"

    return JSONResponse(result)

@app.post("/proxies/api/prune")
async def proxies_prune():
    return JSONResponse({"cut": prune_bad()})


@app.post("/proxies/api/remove-one")
async def proxies_remove_one(key: str = Form(...)):
    return JSONResponse({"removed": remove_one(key)})


@app.post("/proxies/api/delete-all")
async def proxies_delete_all(request: Request):
    if not await _current_session(request):
        raise HTTPException(status_code=401, detail="dashboard session required")
    return JSONResponse(delete_all_proxies())


@app.post("/proxies/api/revive")
async def proxies_revive(key: str = Form("*")):
    return JSONResponse(revive_one(key))


# ---------- jars api ----------
@app.post("/jars/reset")
async def jar_reset(request: Request, jar_id: str = Form(...)):
    mark_jar_status(jar_id, "ok")
    return RedirectResponse(url="/jars", status_code=303)


@app.post("/jars/toggle")
async def jar_toggle(request: Request, jar_id: str = Form(...)):
    def fn(jars):
        for j in jars:
            if j.get("id") == jar_id:
                j["enabled"] = not j.get("enabled", True)
    mutate_jars(fn)
    return RedirectResponse(url="/jars", status_code=303)


@app.post("/jars/persona")
async def jar_persona(request: Request, jar_id: str = Form(...), key: str = Form("")):
    def fn(jars):
        for j in jars:
            if j.get("id") == jar_id and key in PERSONAS:
                j["persona"] = key
                j["user_agent"] = PERSONAS[key].ua
                log("OK", f"jar '{j.get('name')}' bound to device persona {PERSONAS[key].label}")
    mutate_jars(fn)
    return RedirectResponse(url="/jars", status_code=303)


@app.post("/jars/delete")
async def jar_delete(request: Request, jar_id: str = Form(...)):
    def fn(jars):
        jars[:] = [j for j in jars if j.get("id") != jar_id]
    mutate_jars(fn)
    return RedirectResponse(url="/jars", status_code=303)


@app.post("/jars/bulk")
async def jars_bulk(request: Request, accounts: str = Form(...)):
    added = 0
    for block in accounts.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        try:
            data = json.loads(block)
            cookies = data if isinstance(data, list) else data.get("cookies", [])
            name = (data.get("name") if isinstance(data, dict) else "") or f"jar_{uuid7()[:8]}"
            _new_jar(name, cookies)
            added += 1
        except Exception as e:
            log("WARN", f"bulk parse: {e}")
    log("OK", f"jars: +{added}")
    return RedirectResponse(url="/jars", status_code=303)


@app.post("/models/block")
async def models_block(name: str = Form(...)):
    state = load_state()
    if name in state.get("blocked_models", []):
        def fn(s):
            s["blocked_models"] = [m for m in s.get("blocked_models", []) if m != name]
        mutate_state(fn)
        log("OK", f"Model '{name}' unblocked")
    else:
        block_model(name)
    return RedirectResponse(url="/models-page", status_code=303)


# ---------- logs ----------
@app.get("/debug-logs/data")
async def debug_logs():
    return JSONResponse(LOG.tail(500))


@app.post("/clear-logs")
async def clear_logs():
    await asyncio.to_thread(LOG.clear)
    return JSONResponse({"ok": True})


@app.get("/healthz")
async def healthz():
    rows = snapshot_rows()
    jars = load_jars()
    browser_ready_ids = [
        j.get("id") for j in jars
        if j.get("enabled", True) and jar_has_auth(j)
        and keeper_session_ready(keeper.sessions.get(j.get("id")))
    ]
    verification_ready_ids = [sid for sid in browser_ready_ids if _api_keeper_verified(sid)]
    ready_keepers = len(browser_ready_ids)
    verification_ready_keepers = len(verification_ready_ids)
    verification_ready_exits = len({_api_keeper_exit_key(sid) for sid in verification_ready_ids})
    _refresh_api_ready_event()
    bootable_count = len(_bootable_keeper_jars())
    preferred_keepers, preferred_exits = _api_preferred_targets() if bootable_count else (0, 0)
    return JSONResponse({"ok": True, "build": BUILD_STAMP, "version": "3.7.13",
                         "models": len(get_models()),
                         "bootable_accounts": bootable_count,
                         "keeper_fleet_target": bootable_count,
                         "keeper_sessions_registered": len(keeper.sessions),
                         "keeper_start_concurrency": KEEPER_START_CONCURRENCY,
                         "keeper_login_concurrency": KEEPER_LOGIN_CONCURRENCY,
                         "preferred_verified_keepers": preferred_keepers,
                         "preferred_distinct_exits": preferred_exits,
                         "pool_alive": sum(1 for r in rows if r["verdict"] == "alive"),
                         "jars_ok": sum(1 for j in load_jars() if jar_has_auth(j) and not j.get("expired")),
                         "keepers_live": sum(1 for session in keeper.sessions.values()
                                             if keeper_session_ready(session)),
                         "api_ready": bool(_api_ready_event.is_set()),
                         "ready_authenticated_keepers": ready_keepers,
                         "browser_ready_authenticated_keepers": ready_keepers,
                         "verification_ready_keepers": verification_ready_keepers,
                         "verification_ready_exits": verification_ready_exits,
                         "global_concurrency": API_TURN_CONCURRENCY,
                         "per_api_concurrency": "unlimited",
                         "configured_proxies": len(get_proxy_pool()),
                         "distinct_keeper_routes": len({
                             _normalize_proxy(getattr(s, "_used_proxy", "") or "")
                             for s in keeper.sessions.values()
                             if _normalize_proxy(getattr(s, "_used_proxy", "") or "")
                         }),
                         "estimated_browser_lanes":
                             sum(1 + int(getattr(s, "_max_pool_pages", 0) or 0)
                                 for s in keeper.sessions.values()
                                 if keeper_session_ready(s)),
                         "verification_adapter": bool(get_verification_solver),
                         "reliability": _reliability_snapshot(),
                         "vnc_enabled": _V3_VNC_ENABLED})


@app.get("/control/api/keeper-diagnostics")
async def keeper_diagnostics(request: Request):
    """Operator-only, bounded, read-only diagnostics with no secret values."""
    if not await _current_session(request):
        raise HTTPException(status_code=401, detail="dashboard session required")
    script = """() => {
        const api = window.grecaptcha && window.grecaptcha.enterprise;
        return {
            document_complete: document.readyState === 'complete',
            enterprise_present: !!api,
            ready_function: typeof api?.ready === 'function',
            execute_function: typeof api?.execute === 'function',
            render_function: typeof api?.render === 'function',
            site_key_elements: document.querySelectorAll('[data-sitekey]').length,
            response_fields: document.querySelectorAll('[name="g-recaptcha-response"]').length
        };
    }"""
    gate = asyncio.Semaphore(3)
    async def inspect_session(sid, session):
        row = {"keeper_id": sid, "state": session.status,
               "ready": keeper_session_ready(session)}
        deadline = getattr(session, "ready_at", float("inf"))
        row["warmup_remaining_seconds"] = (
            max(0, math.ceil(deadline - time.monotonic())) if math.isfinite(deadline) else None)
        if not keeper_session_ready(session, warmed=False):
            row["inspection"] = "not_initialized"
            return row
        if session.active_requests or session._action_lock.locked():
            row["inspection"] = "busy"
            return row
        async with gate:
            try:
                await asyncio.wait_for(session._action_lock.acquire(), timeout=0.1)
            except asyncio.TimeoutError:
                row["inspection"] = "busy"
                return row
            try:
                data = await asyncio.wait_for(session.page.evaluate(script), timeout=3)
                # Never trust arbitrary page-returned values in a diagnostic export.
                row["browser"] = {
                    key: data[key] for key in (
                        "document_complete", "enterprise_present", "ready_function",
                        "execute_function", "render_function", "site_key_elements",
                        "response_fields"
                    ) if isinstance(data, dict) and type(data.get(key)) in (bool, int)
                }
                row["inspection"] = "complete"
            except Exception as exc:
                row["inspection"] = type(exc).__name__
            finally:
                session._action_lock.release()
        return row
    rows = await asyncio.gather(*(inspect_session(sid, session)
                                  for sid, session in list(keeper.sessions.items())))
    return JSONResponse({"build": BUILD_STAMP, "keepers": rows},
                        headers={"Cache-Control": "no-store"})


@app.get("/readyz")
async def readyz():
    models_ready = bool(get_models())
    jars = load_jars()
    browser_ready_ids = []
    for jar in jars:
        sid = jar.get("id")
        if jar.get("enabled", True) and jar_has_auth(jar) and keeper_session_ready(keeper.sessions.get(sid)):
            browser_ready_ids.append(sid)
    verification_ready_ids = [sid for sid in browser_ready_ids if _api_keeper_verified(sid)]
    _refresh_api_ready_event()
    ready = models_ready and bool(_api_ready_event.is_set())
    return JSONResponse({"ready": ready, "build": BUILD_STAMP,
                         "checks": {"models": models_ready,
                                    "authenticated_keeper": bool(browser_ready_ids),
                                    "ready_authenticated_keepers": len(browser_ready_ids),
                                    "verification_ready_keeper": bool(verification_ready_ids),
                                    "verification_ready_keepers": len(verification_ready_ids),
                                    "verification_ready_exits": len({_api_keeper_exit_key(sid) for sid in verification_ready_ids}),
                                    "global_concurrency": API_TURN_CONCURRENCY,
                                    "per_api_concurrency": "unlimited",
                                    "estimated_browser_lanes":
                                        sum(1 + int(getattr(s, "_max_pool_pages", 0) or 0)
                                            for s in keeper.sessions.values()
                                            if keeper_session_ready(s))}},
                        status_code=200 if ready else 503)


# ---------- misc legacy shims ----------
@app.get("/debug/raw-models")
async def raw_models():
    return JSONResponse(read_json(MODELS_RAW_DEBUG_FILE, []))


@app.post("/models/refresh")
async def models_refresh_api(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    result = await refresh_model_catalog()
    code = 200 if result.get("ok") else 503
    log("OK" if result.get("ok") else "WARN", f"Models-page refresh: {result.get('reason','unknown result')}")
    return JSONResponse(result, status_code=code, headers={"Cache-Control":"no-store"})


@app.post("/keeper/config")
async def keeper_config():
    asyncio.create_task(_kick_refresh())
    return JSONResponse({"queued": True})


async def _kick_refresh():
    await refresh_model_catalog()
    return True


@app.post("/keeper/live")
async def keeper_live(request: Request, jar_id: str = Form(...), on: str = Form("1")):
    want = on in ("1", "true", "on")
    def fn(jars):
        for j in jars:
            if j.get("id") == jar_id:
                j["keeper_enabled"] = want
    mutate_jars(fn)
    log("OK", f"keeper {'enabled' if want else 'disabled'} for jar {jar_id[:8]}")
    return RedirectResponse(url="/jars", status_code=303)


@app.get("/keeper/status")
async def keeper_status():
    return JSONResponse(keeper.status())


# ---------- keys ----------
@app.post("/create-key")
async def create_key(request: Request, name: str = Form(...), rpm: int = Form(...)):
    g = await _page_guard(request)
    if g:
        return g
    config = get_config()
    _normalize_api_key_records(config)
    raw_key = "sk-void-" + secrets.token_urlsafe(32)
    clean_name = name.strip() or "API key"
    config.setdefault("api_keys", []).append({
        "id": "key_" + secrets.token_hex(8),
        "name": clean_name,
        "key_hash": _api_key_hash(raw_key),
        "prefix": raw_key[:14],
        "rpm": max(1, min(rpm, 1000)),
        "created": int(time.time()),
    })
    save_config(config)
    log("OK", f"API key created: {clean_name}")
    return HTMLResponse(api_key_created_page(clean_name, raw_key))


@app.post("/delete-key")
async def delete_key(request: Request, key_id: str = Form(...)):
    g = await _page_guard(request)
    if g:
        return g
    config = get_config()
    _normalize_api_key_records(config)
    before = len(config.get("api_keys", []))
    config["api_keys"] = [k for k in config.get("api_keys", []) if k.get("id") != key_id]
    save_config(config)
    if len(config["api_keys"]) != before:
        log("OK", f"API key revoked: {key_id}")
    return RedirectResponse(url="/api-keys", status_code=status.HTTP_303_SEE_OTHER)


# ---------- jars add (cookie file / paste / credentials) ----------
async def _activate_new_keeper(jar_id: str) -> None:
    """Allocate a stable route and register a newly-added account immediately."""
    try:
        _configure_keeper_concurrency(len(_bootable_keeper_jars()))
        await allocate_unique_keeper_proxies(load_jars())
        await keeper.sync()
        _keeper_fleet_launch_event.set()
        _verification_preflight_retry_after.pop(str(jar_id), None)
        _keeper_recovery_attempts.pop(str(jar_id), None)
        log("INFO", f"[{jar_id}] account queued for keeper startup + readiness recovery")
    except Exception as exc:
        log("WARN", f"[{jar_id}] account saved but keeper activation failed: "
                    f"{type(exc).__name__}: {redact(str(exc))[:160]}")


@app.post("/jars/add")
async def jars_add(request: Request, name: str = Form(""), cookie_file: UploadFile = File(...)):
    g = await _page_guard(request)
    if g:
        return g
    try:
        raw = (await cookie_file.read()).decode("utf-8-sig")
        cookies = _validate_cookies(raw)
        if not cookies:
            raise ValueError("No valid cookies were found in the uploaded file")
        jar, found = _new_jar(name.strip(), cookies, keeper_enabled=True)
        log("OK", f"Account '{jar['name']}' imported ({len(cookies)} cookies; "
                  f"auth markers {len(found)})")
        await _activate_new_keeper(jar["id"])
    except Exception as e:
        log("ERROR", f"Jar upload failed: {type(e).__name__}: {redact(str(e))[:180]}")
        return RedirectResponse(url="/jars/upload", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/jars", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/add-text")
async def jars_add_text(request: Request, name: str = Form(""), cookie_json: str = Form(...)):
    g = await _page_guard(request)
    if g:
        return g
    try:
        cookies = _validate_cookies(cookie_json.strip())
        if not cookies:
            raise ValueError("No valid cookies were found in the pasted payload")
        jar, found = _new_jar(name.strip(), cookies, keeper_enabled=True)
        log("OK", f"Account '{jar['name']}' imported from pasted cookies "
                  f"({len(cookies)} cookies; auth markers {len(found)})")
        await _activate_new_keeper(jar["id"])
    except Exception as e:
        log("ERROR", f"Jar paste failed: {type(e).__name__}: {redact(str(e))[:180]}")
        return RedirectResponse(url="/jars/upload", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/jars", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/add-credentials")
async def jars_add_credentials(request: Request, name: str = Form(""), credentials: str = Form(...)):
    g = await _page_guard(request)
    if g:
        return g

    parsed = []
    for lineno, raw_line in enumerate(credentials.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            log("WARN", f"Credential import skipped line {lineno}: expected email:password")
            continue
        email, password = line.split(":", 1)
        email, password = email.strip(), password.strip()
        if not email or not password or "@" not in email:
            log("WARN", f"Credential import skipped line {lineno}: invalid email/password shape")
            continue
        parsed.append((email, password))

    if not parsed:
        log("ERROR", "Credential import failed: no valid email:password entries")
        return RedirectResponse(url="/jars/upload", status_code=status.HTTP_303_SEE_OTHER)

    created = []
    for idx, (email, password) in enumerate(parsed):
        display = name.strip() if len(parsed) == 1 and name.strip() else email.split("@", 1)[0]
        jar, _ = _new_jar(
            display,
            [],
            email=email,
            password=password,
            login_method="email",
            keeper_enabled=True,
        )
        created.append(jar["id"])
        log("OK", f"Credential account '{jar['name']}' added · email {redact(email)} · keeper enabled")

    # One allocation/sync pass for the whole imported batch.
    try:
        _configure_keeper_concurrency(len(_bootable_keeper_jars()))
        await allocate_unique_keeper_proxies(load_jars())
        await keeper.sync()
        _keeper_fleet_launch_event.set()
        for jar_id in created:
            _verification_preflight_retry_after.pop(jar_id, None)
            _keeper_recovery_attempts.pop(jar_id, None)
        log("OK", f"Credential import complete · {len(created)} keeper(s) queued")
    except Exception as exc:
        log("WARN", f"Credential accounts saved but keeper activation failed: "
                    f"{type(exc).__name__}: {redact(str(exc))[:160]}")

    return RedirectResponse(url="/jars", status_code=status.HTTP_303_SEE_OTHER)


# ---------- keeper relogin ----------
@app.post("/keeper/relogin")
async def keeper_relogin(request: Request, jar_id: str = Form(...)):
    g = await _page_guard(request)
    if g:
        return JSONResponse(status_code=401, content={"error": "unauthorized"})
    s = keeper.sessions.get(jar_id)
    if s and s.running:
        s.next_retry = 0
        asyncio.create_task(s.relogin())
        log("INFO", f"[{s.name}] Manual re-login triggered")
        return {"status": "ok", "message": "Relogin initiated"}
    jar = next((j for j in load_jars() if j["id"] == jar_id), None)
    if not jar:
        return JSONResponse(status_code=404, content={"error": "unknown jar"})
    s = KeeperSession(jar, headless=jar.get("keeper_headless", True))
    keeper.sessions[jar_id] = s

    async def start_and_relogin():
        await s.start()
        if s.running:
            await s.relogin()
    asyncio.create_task(start_and_relogin())
    log("INFO", f"Started keeper for '{jar.get('name')}' and triggered relogin")
    return {"status": "ok", "message": "Keeper launched and relogin initiated"}


# ---------- catalog ----------
@app.post("/refresh-tokens")
async def refresh_tokens(request: Request):
    g = await _page_guard(request)
    if g:
        return g
    result = await refresh_model_catalog()
    if result["ok"]:
        log("OK", f"Manual catalog refresh: {result['reason']}")
    else:
        log("WARN", f"Manual catalog refresh failed: {result['reason']}")
    return RedirectResponse(url=f"/dashboard?refresh={'ok' if result['ok'] else 'fail'}&refresh_msg={quote(result['reason'])}",
                            status_code=status.HTTP_303_SEE_OTHER)


# ---------- oxalpha (legacy direct transport — retired in v2) ----------
@app.post("/oxalpha/upload")
async def oxalpha_upload(request: Request, cookie_file: UploadFile = File(...)):
    g = await _page_guard(request)
    if g:
        return g
    try:
        cookies = _validate_cookies((await cookie_file.read()).decode("utf-8"))
        atomic_write(OX_COOKIES_FILE, cookies)
        log("OK", f"OX Alpha cookies saved ({len(cookies)})")
    except Exception as e:
        log("ERROR", f"OX cookie upload failed: {e}")
    return RedirectResponse(url="/jars", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/oxalpha/verify")
@app.post("/oxalpha/refresh")
async def oxalpha_retired(request: Request):
    return JSONResponse(status_code=410, content={
        "error": "gone", "detail": "oxalpha direct transport retired in v2 — keeper jars own auth now (see /jars)"})



# ---------- v3 live browser observer ----------
@app.get("/browser-view", response_class=HTMLResponse)
async def browser_view(request: Request):
    """Operator-only live keeper observer. Uses Playwright screenshots so the
    control plane does not require a second browser, X11 server, or VNC daemon."""
    g = await _page_guard(request)
    if g:
        return g
    return HTMLResponse("""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bridgena · Browser Observer</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#09090b;color:#fafafa;font-family:Inter,system-ui,sans-serif}
header{height:64px;display:flex;align-items:center;gap:12px;padding:0 22px;border-bottom:1px solid #27272a}
header b{font-size:14px}.muted{color:#a1a1aa}.wrap{padding:22px;display:grid;grid-template-columns:260px 1fr;gap:16px;height:calc(100vh - 64px)}
.panel{border:1px solid #27272a;border-radius:12px;background:#0c0c0e;overflow:hidden}
.side{padding:12px;overflow:auto}.session{width:100%;text-align:left;padding:10px;margin-bottom:7px;border:1px solid #27272a;border-radius:8px;background:#18181b;color:#fafafa;cursor:pointer}
.session:hover,.session.on{background:#27272a}.viewer{display:flex;flex-direction:column;min-width:0}
.toolbar{padding:10px 12px;border-bottom:1px solid #27272a;display:flex;justify-content:space-between}
.stage{flex:1;display:grid;place-items:center;overflow:auto;background:#050506}
.stage img{max-width:100%;max-height:100%;object-fit:contain}.empty{color:#71717a}
@media(max-width:800px){.wrap{grid-template-columns:1fr}.side{max-height:180px}}
</style></head>
<body><header><b>Bridgena</b><span class="muted">/ Browser Observer</span><span style="flex:1"></span><a style="color:#fafafa" href="/vnc">VNC</a><a style="color:#fafafa;margin-left:12px" href="/dashboard">Dashboard</a></header>
<div class="wrap"><div class="panel side" id="sessions"></div>
<div class="panel viewer"><div class="toolbar"><span id="title">Select a keeper</span><span class="muted" id="status">idle</span></div>
<div class="stage"><div class="empty" id="empty">No keeper selected.</div><img id="screen" hidden></div></div></div>
<script>
let selected=null, timer=null;
async function loadSessions(){
  const r=await fetch('/keeper/status',{cache:'no-store'}); const d=await r.json();
  const root=document.getElementById('sessions'); root.innerHTML='';
  const sessions=Array.isArray(d)?d:(d.sessions||Object.values(d||{}));
  if(!sessions.length){root.innerHTML='<div class="muted">No live keepers.</div>';return}
  sessions.forEach((s,i)=>{
    const id=s.jar_id||s.id||s.name; const b=document.createElement('button');
    b.className='session'+(selected===id?' on':''); b.textContent=(s.name||id||('Keeper '+(i+1)))+' · '+(s.status||'unknown');
    b.onclick=()=>selectKeeper(id,s.name||id); root.appendChild(b);
  });
}
function selectKeeper(id,name){
  selected=id; document.getElementById('title').textContent=name; document.getElementById('empty').hidden=true;
  document.getElementById('screen').hidden=false; refresh(); loadSessions();
}
async function refresh(){
  if(document.hidden||!selected)return;
  const img=document.getElementById('screen'), st=document.getElementById('status');
  st.textContent='refreshing';
  img.src='/keeper/screenshot/'+encodeURIComponent(selected)+'?t='+Date.now();
  img.onload=()=>st.textContent='live · '+new Date().toLocaleTimeString();
  img.onerror=()=>st.textContent='keeper unavailable';
}
setInterval(()=>{if(!document.hidden)loadSessions()},4000); setInterval(refresh,1500); loadSessions();
</script></body></html>""")


@app.get("/keeper/screenshot/{jar_id}")
async def keeper_screenshot(request: Request, jar_id: str):
    """Return an in-memory screenshot of a live keeper page."""
    if not await _current_session(request):
        raise HTTPException(status_code=401, detail="dashboard session required")
    session = keeper.sessions.get(jar_id)
    if not session or not session.running or not session.page or session.page.is_closed():
        raise HTTPException(status_code=404, detail="keeper page unavailable")
    if session.active_requests > 0 or session._action_lock.locked():
        raise HTTPException(status_code=409, detail="keeper busy with API traffic")
    try:
        async with session._action_lock:
            png = await asyncio.wait_for(
                session.page.screenshot(type="png", animations="disabled"), timeout=6)
        return Response(content=png, media_type="image/png",
                        headers={"Cache-Control": "no-store, max-age=0"})
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"screenshot unavailable: {type(exc).__name__}")


# ---------- screenshots ----------
@app.get("/screenshots")
async def list_screenshots(request: Request):
    files = sorted(glob.glob("*.png"), key=os.path.getmtime, reverse=True)  # keeper writes to cwd, legacy convention
    cards = "".join(
        f'<a class="card" href="/screenshots/{quote(os.path.basename(filename))}">'
        f'<img src="/screenshots/{quote(os.path.basename(filename))}" loading="lazy" alt="Keeper screenshot" '
        f'style="display:block;width:100%;aspect-ratio:16/9;object-fit:cover;border-radius:8px;background:var(--surface3)">'
        f'<div class="mono muted" style="padding-top:9px;overflow:hidden;text-overflow:ellipsis">{esc(os.path.basename(filename))}</div></a>'
        for filename in files[:200]
    ) or '<div class="card muted">No screenshots available.</div>'
    content = (f'<div class="pagehead"><div><h1>Keeper screenshots</h1><p>Saved browser captures for visual diagnosis.</p></div>'
               f'<a class="btn primary" href="/browser-view">Open live observer</a></div>'
               f'<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(280px,1fr))">{cards}</div>')
    return HTMLResponse(page("Screenshots", content, "browser"))


@app.get("/screenshots/{filename}")
async def screenshot_file(request: Request, filename: str):
    p = os.path.basename(filename)
    if not os.path.isfile(p):
        raise HTTPException(status_code=404)
    return FileResponse(p, media_type="image/png")



try:
    from fastapi.staticfiles import StaticFiles as _V3StaticFiles
    _v3_root=_v3_novnc_root()
    if _v3_root:app.mount('/novnc',_V3StaticFiles(directory=_v3_root,html=True),name='novnc')
except Exception as _v3_static_exc:
    log('WARN',f'noVNC static mount unavailable: {type(_v3_static_exc).__name__}')

# ---------- startup ----------
async def _preflight_one_keeper(sid: str, session, jar: dict) -> tuple:
    """Check that the authenticated keeper's Enterprise verification client is loaded."""
    name = getattr(session, "name", sid)
    try:
        async with session._action_lock:
            page = session.page
            if not page or page.is_closed():
                return sid, False
            state = await asyncio.wait_for(page.evaluate("""async () => {
              const until = Date.now() + 8000;
              while (Date.now() < until) {
                const g = window.grecaptcha;
                const e = g && g.enterprise;
                if (e && typeof e.ready === 'function' && typeof e.execute === 'function') {
                  try {
                    await new Promise((resolve, reject) => {
                      let done = false;
                      const timer = setTimeout(() => {
                        if (!done) reject(new Error('ready-timeout'));
                      }, 3000);
                      e.ready(() => {
                        if (!done) {
                          done = true;
                          clearTimeout(timer);
                          resolve();
                        }
                      });
                    });
                    return {ready:true, enterprise:true, execute:true};
                  } catch (_) {}
                }
                await new Promise(r => setTimeout(r, 250));
              }
              const g = window.grecaptcha;
              const e = g && g.enterprise;
              return {
                ready:false,
                enterprise:!!e,
                execute:!!(e && typeof e.execute === 'function')
              };
            }"""), timeout=10.0)

        ok = bool(isinstance(state, dict) and state.get("ready"))
        if ok:
            _api_verified_keepers[sid] = time.monotonic()
            _api_keeper_quarantine_until.pop(sid, None)
            _keeper_recovery_attempts.pop(sid, None)
            log("OK", f"[{name}] verification client ready · Enterprise execute available")
            return sid, True

        log("WARN", f"[{name}] verification client not ready · "
                    f"enterprise={bool((state or {}).get('enterprise'))} "
                    f"execute={bool((state or {}).get('execute'))}")
        return sid, False

    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log("WARN", f"[{name}] verification client readiness failed · "
                    f"{type(exc).__name__}: {redact(str(exc))[:160]}")
        return sid, False


def _schedule_transport_recovery(sid: Optional[str], reason: str) -> None:
    sid = str(sid or "")
    if not sid:
        return
    existing = _transport_recovery_tasks.get(sid)
    if existing and not existing.done():
        return

    async def worker():
        try:
            session = keeper.sessions.get(sid)
            if not session:
                await keeper.sync()
                session = keeper.sessions.get(sid)
            if not session:
                log("WARN", f"[{sid}] transport recovery · keeper session unavailable")
                return

            log("INFO", f"[{getattr(session, 'name', sid)}] transport recovery · restarting same keeper · {reason}")
            async with _keeper_recovery_gate:
                _mark_api_keeper_unready(sid, "transport recovery")
                await session.restart()

            # Wait for the restarted page + warmup, then re-run the normal
            # browser-client readiness check. No user prompt is replayed.
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline:
                if keeper_session_ready(session):
                    break
                await asyncio.sleep(0.5)

            jar = next((j for j in load_jars() if str(j.get("id")) == sid), None)
            if jar and keeper_session_ready(session):
                _, verification_ok = await _preflight_one_keeper(sid, session, jar)
                route_ok, route_status, route_detail = await session.probe_transport(force=True)
                if verification_ok and route_ok:
                    _api_keeper_quarantine_until.pop(sid, None)
                    _refresh_api_ready_event()
                    log("OK", f"[{getattr(session, 'name', sid)}] transport recovery complete · "
                              f"keeper readmitted · route HTTP {route_status}")
                    return
                if not route_ok:
                    _mark_api_keeper_unready(sid, "recovery route probe still failing")
                    log("WARN", f"[{getattr(session, 'name', sid)}] transport recovery route probe failed · "
                                f"{redact(route_detail)[:160]}")

            log("WARN", f"[{getattr(session, 'name', sid)}] transport recovery incomplete · "
                        "readiness loop will continue repairing it")
            _verification_preflight_retry_after[sid] = time.monotonic() + 3.0

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log("WARN", f"[{sid}] transport recovery failed · "
                        f"{type(exc).__name__}: {redact(str(exc))[:180]}")
            _verification_preflight_retry_after[sid] = time.monotonic() + 5.0
        finally:
            _transport_recovery_tasks.pop(sid, None)

    _transport_recovery_tasks[sid] = asyncio.create_task(
        worker(), name=f"transport-recovery-{sid[:8]}"
    )



async def _recover_unready_keeper(sid: str, session, jar: dict) -> bool:
    """Actively recover a keeper whose verification client did not become ready.

    Recovery is intentionally local to this authenticated browser:
      1) refresh/re-enter the official Arena page and re-check auth;
      2) after repeated failed warmups, restart that keeper on its sticky route.
    It does not generate a prompt or solve an interactive challenge.
    """
    sid = str(sid)
    name = getattr(session, "name", sid)
    attempt = int(_keeper_recovery_attempts.get(sid, 0)) + 1
    _keeper_recovery_attempts[sid] = attempt

    async with _keeper_recovery_gate:
        try:
            if not keeper_session_ready(session, warmed=False):
                log("WARN", f"[{name}] readiness recovery · browser not healthy enough; restarting keeper")
                _mark_api_keeper_unready(sid, "recovery restart")
                await session.restart()
                _verification_preflight_retry_after[sid] = time.monotonic() + KEEPER_WARMUP_SEC + 2.0
                _keeper_recovery_attempts[sid] = 0
                return True

            if attempt < _keeper_recovery_restart_after:
                log("INFO", f"[{name}] readiness recovery · soft refresh {attempt}/{_keeper_recovery_restart_after - 1}")
                async with session._action_lock:
                    page = session.page
                    if not page or page.is_closed():
                        raise RuntimeError("keeper page is closed")
                    # Re-enter the normal authenticated Arena origin. Using the
                    # session helper preserves its existing route/persona state.
                    await session._navigate_resilient(page, PUBLIC_AUTH_URL, timeout=15000)
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    auth_ok = await session._verify_auth_state(page)
                    if auth_ok:
                        session.last_public_auth_check = time.time()
                        try:
                            await session._harvest_cookies()
                        except Exception:
                            pass
                    else:
                        log("WARN", f"[{name}] readiness recovery · auth check failed; scheduling relogin")
                        session.next_retry = 0
                if not auth_ok:
                    await session.relogin()
                # A keeper is not really recovered if verification JS is alive
                # but the browser route cannot reach Arena.
                route_ok, route_status, route_detail = await session.probe_transport(force=True)
                if route_ok:
                    log("INFO", f"[{name}] readiness recovery · route probe HTTP {route_status}")
                else:
                    log("WARN", f"[{name}] readiness recovery · route probe failed · "
                                f"{redact(route_detail)[:150]}")
                _verification_preflight_retry_after[sid] = time.monotonic() + _keeper_recovery_retry_sec
                return True

            # Passive checks + a soft refresh both failed: rebuild the browser
            # context. restart() retains the jar's sticky proxy assignment.
            log("WARN", f"[{name}] readiness recovery · still unready after {attempt} checks · restarting keeper")
            _mark_api_keeper_unready(sid, "verification client recovery")
            _verification_preflight_retry_after[sid] = time.monotonic() + KEEPER_WARMUP_SEC + 3.0
            _keeper_recovery_attempts[sid] = 0
            await session.restart()
            return True

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log("WARN", f"[{name}] readiness recovery failed · "
                        f"{type(exc).__name__}: {redact(str(exc))[:180]}")
            _verification_preflight_retry_after[sid] = time.monotonic() + max(8.0, _keeper_recovery_retry_sec)
            return False



async def _api_verification_readiness_loop():
    """Bring the whole authenticated keeper fleet to browser verification-ready."""
    initial_done = False
    announced_ready = False

    try:
        await asyncio.wait_for(_keeper_fleet_launch_event.wait(), timeout=30.0)
    except asyncio.TimeoutError:
        log("WARN", "Verification startup · keeper registration timed out; using available fleet")

    while True:
        try:
            jars_by_id = {
                str(j.get("id") or ""): j
                for j in load_jars()
                if j.get("id") and j.get("enabled", True) and jar_has_auth(j)
            }

            if not initial_done and jars_by_id:
                deadline = time.monotonic() + 75.0
                last_ready = -1
                while time.monotonic() < deadline:
                    ready_ids = [
                        sid for sid in jars_by_id
                        if keeper_session_ready(keeper.sessions.get(sid))
                    ]
                    if len(ready_ids) != last_ready:
                        log("INFO", f"Verification startup cohort · browser-ready {len(ready_ids)}/{len(jars_by_id)}")
                        last_ready = len(ready_ids)
                    if len(ready_ids) == len(jars_by_id):
                        break
                    await asyncio.sleep(0.25)

            now = time.monotonic()
            eligible = []
            for sid, jar in jars_by_id.items():
                currently_verified = _api_keeper_verified(sid)
                needs_refresh = _api_keeper_needs_refresh(sid)
                if currently_verified and not needs_refresh:
                    continue
                if now < _api_keeper_quarantine_until.get(sid, 0.0):
                    continue
                if now < _verification_preflight_retry_after.get(sid, 0.0):
                    continue
                session = keeper.sessions.get(sid)
                if not keeper_session_ready(session):
                    continue
                if session.active_requests:
                    continue
                # Carry whether the old lease is still valid. A proactive
                # renewal miss should not disrupt a working keeper.
                eligible.append((sid, session, jar, currently_verified))

            if eligible:
                names = ", ".join(getattr(sess, "name", sid) for sid, sess, _, _ in eligible)
                refreshes = sum(1 for _, _, _, was_valid in eligible if was_valid)
                log("INFO", f"Verification cohort · checking {len(eligible)} keeper(s) concurrently · "
                            f"{refreshes} proactive refresh(es) · {names}")
                results = await asyncio.gather(
                    *(_preflight_one_keeper(sid, session, jar)
                      for sid, session, jar, _ in eligible),
                    return_exceptions=False,
                )
                passed = 0
                failed = []
                soft_refresh_failed = []
                eligible_by_sid = {
                    sid: (session, jar, was_valid)
                    for sid, session, jar, was_valid in eligible
                }
                for sid, ok in results:
                    if ok:
                        passed += 1
                        _verification_preflight_retry_after.pop(sid, None)
                    else:
                        session, jar, was_valid = eligible_by_sid[sid]
                        if was_valid and _api_keeper_verified(sid):
                            # The old lease is still valid. Do not restart a
                            # working browser just because one proactive probe
                            # missed; retry the renewal shortly.
                            soft_refresh_failed.append((sid, session, jar))
                            _verification_preflight_retry_after[sid] = time.monotonic() + 8.0
                        else:
                            failed.append((sid, session, jar))

                log("INFO", f"Verification cohort · pass {passed}/{len(results)}"
                            + (f" · soft-renewal misses {len(soft_refresh_failed)}"
                               if soft_refresh_failed else ""))

                if soft_refresh_failed:
                    names = ", ".join(getattr(session, "name", sid)
                                      for sid, session, _ in soft_refresh_failed)
                    log("WARN", f"Verification lease refresh missed on still-valid keeper(s) · "
                                f"retrying without restart · {names}")

                if failed:
                    names = ", ".join(getattr(session, "name", sid) for sid, session, _ in failed)
                    log("WARN", f"Verification recovery · actively recovering {len(failed)} keeper(s) · {names}")
                    await asyncio.gather(
                        *(_recover_unready_keeper(sid, session, jar)
                          for sid, session, jar in failed),
                        return_exceptions=False,
                    )

            _refresh_api_ready_event()

            if not initial_done:
                initial_done = True
                _initial_verification_sweep_done.set()
                log("INFO", "Verification startup cohort · initial sweep complete · background keeper activity enabled")

            verified = _verified_keeper_count()
            ready_count = sum(
                1 for sid in jars_by_id
                if keeper_session_ready(keeper.sessions.get(sid))
            )

            if _api_ready_event.is_set():
                if not announced_ready:
                    log("OK", f"API READY · verification clients {verified}/{ready_count or len(jars_by_id)}"
                              f" · distinct exits {_verified_exit_count()}")
                    announced_ready = True
            else:
                announced_ready = False

            # A partially-ready fleet is a recovery condition, not a steady
            # state. Also wake instantly when request admission detects 0 ready
            # capacity rather than sleeping through a customer request.
            target_count = len(jars_by_id)
            sleep_for = 8.0 if target_count and verified >= target_count else 2.0
            try:
                await asyncio.wait_for(_verification_wakeup_event.wait(), timeout=sleep_for)
            except asyncio.TimeoutError:
                pass
            finally:
                _verification_wakeup_event.clear()

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not initial_done:
                initial_done = True
                _initial_verification_sweep_done.set()
            log("WARN", f"Verification cohort scheduler recovered from "
                        f"{type(exc).__name__}: {redact(str(exc))[:160]}")
            await asyncio.sleep(2.0)

def jars_have_creds() -> bool:
    # Historical function name retained for lifespan compatibility.
    return bool(_bootable_keeper_jars())
@asynccontextmanager
async def _lifespan(app):
    await _v3_vnc_start()
    def _remove_legacy_transcripts(state):
        state.pop("chats", None)
    mutate_state(_remove_legacy_transcripts)
    def _normalize_personas(jars):
        for jar in jars:
            if jar.get("persona") not in PERSONAS:
                jar["persona"] = "ubuntu"
                jar["user_agent"] = PERSONAS["ubuntu"].ua
    mutate_jars(_normalize_personas)
    _bootable_count = len(_bootable_keeper_jars())
    if _bootable_count:
        _configure_keeper_concurrency(_bootable_count)
    tasks = [asyncio.create_task(keeper_election_loop(), name="keeper-election"),
             asyncio.create_task(periodic_model_refresher(), name="model-refresher"),
             asyncio.create_task(get_initial_data(), name="initial-catalog"),
             asyncio.create_task(proxy_recovery_loop(), name="proxy-auto-recovery")]
    if jars_have_creds():
        tasks.append(asyncio.create_task(auto_login_on_boot(), name="auto-login"))
        tasks.append(asyncio.create_task(_api_verification_readiness_loop(), name="verification-readiness"))
    app.state.background_tasks = tasks
    app.state.ready_at = time.time()
    log("INFO", f"BRIDGENA build {BUILD_STAMP} · v4 browser-extension control plane · legacy fallback retained")
    log("INFO", f"v4 transport · {V4_TRANSPORT} · legacy fallback {'on' if V4_FALLBACK_LEGACY else 'off'}")
    if V4_TRANSPORT == "extension" and V4_AUTO_ATTACH_KEEPERS:
        log("OK", f"v4 keeper mode · autonomous headed browsers ON · bundled extension {V4_EXTENSION_DIR}")
        log("INFO", "v4 keeper mode · existing account cookies + sticky proxy assignment reused automatically")

    if V4_AUTOLAUNCH and not V4_AUTO_ATTACH_KEEPERS:
        try: _v4_launch_browser_once()
        except Exception as exc: log("WARN", f"v4 browser autolaunch failed · {type(exc).__name__}: {redact(str(exc))[:160]}")
    log("INFO", "Conversation mode · sticky Arena chat sessions · bounded history capsule only for rebuild/recovery")
    log("INFO", "Keeper rejection policy · non-destructive local recovery · no 45s API exile")
    log("INFO", f"Multi-user scheduler · global slots {API_TURN_CONCURRENCY} · "
                f"per-API concurrency unlimited · upstream attempts {REQUEST_MAX_ATTEMPTS}")
    _fleet_target = len(_bootable_keeper_jars())
    _preferred_keepers, _preferred_exits = _api_preferred_targets() if _fleet_target else (0, 0)
    log("INFO", f"Keeper fleet · bootable accounts {_fleet_target} · target keepers {_fleet_target} · "
                f"parallel starts {KEEPER_START_CONCURRENCY} · parallel logins {KEEPER_LOGIN_CONCURRENCY} · "
                f"hard concurrency cap {KEEPER_CONCURRENCY_HARD_CAP}")
    log("INFO", f"Keeper recovery · soft refresh then restart after {_keeper_recovery_restart_after} failed readiness checks · parallel {_keeper_recovery_gate._value}")
    log("INFO", f"Transport recovery · same-keeper restart ON · quarantine {TRANSPORT_FAILURE_QUARANTINE_SEC:.0f}s · bound wait {BOUND_KEEPER_RECOVERY_WAIT_SEC:.0f}s")
    log("INFO", f"Pre-dispatch transport guard · HEAD probe every request {'ON' if TRANSPORT_PROBE_EVERY_REQUEST else 'OFF'} · timeout {TRANSPORT_PROBE_TIMEOUT_MS}ms · recovery wait {PREDISPATCH_RECOVERY_WAIT_SEC:.0f}s")
    log("INFO", f"Account failover · max {ACCOUNT_FAILOVER_MAX} alternate keeper(s) · thread handoff ON for pre-generation account/session failures · 429+verification+partial-stream excluded")
    log("INFO", f"Stream completion policy · first assistant output <= {FIRST_ASSISTANT_RESPONSE_SEC:.1f}s · provider finish required {'ON' if REQUIRE_PROVIDER_FINISH else 'OFF'} · partial UI preservation ON")
    log("INFO", f"Arena stream salvage · {'ON' if ARENA_UI_STREAM_RECOVERY else 'OFF'} · "
                f"quick {ARENA_SALVAGE_QUICK_SEC:.0f}s current-context check → same-keeper route repair → "
                f"{ARENA_POST_RESTART_SALVAGE_SEC:.0f}s post-restart history/UI salvage · no prompt replay")
    log("INFO", f"Confirmed-absence resend · max {UNDELIVERED_ENVELOPE_RETRY_MAX} · "
                "HTTP-0 + zero output + post-restart history trace absent only · exact message IDs reused")
    log("INFO", f"Throttle thread rehome · {'ON' if THROTTLE_THREAD_REHOME else 'OFF'} · "
                f"same model/account · server-side context capsule <= {CONTEXT_CAPSULE_MAX_CHARS} chars · "
                "upstream Retry-After is always respected")
    log("INFO", f"Customer error privacy · opaque friendly messages ON · private registry {_ERROR_EVENTS_FILE} · Errors tab enabled")
    log("INFO", f"Readiness leases · TTL {_API_VERIFICATION_TTL:.0f}s · staggered proactive renewal 55-72% · "
                f"admission {_API_ADMISSION_MIN_KEEPERS} keeper/{_API_ADMISSION_MIN_EXITS} exit · "
                f"preferred {_preferred_keepers}/{_preferred_exits} · inline wait {_API_READY_RECOVERY_WAIT_SEC:.0f}s")
    log("INFO", f"Reliability SLO · rolling window {_reliability_window.maxlen} · target {_RELIABILITY_TARGET*100:.0f}%")
    log("INFO", f"Admission pacing · per-key interval {API_PACE_INTERVAL_SEC:.2f}s · conversation gap {CONVERSATION_MIN_GAP_SEC:.2f}s · max queued wait {API_PACE_MAX_WAIT_SEC:.1f}s")
    log("INFO", "Stream decoder · Arena/Vercel classic + AI SDK UIMessage + OpenAI + Anthropic + Gemini · snapshot de-dup ON")
    log("INFO", f"Upstream 429 policy · adaptive backoff {UPSTREAM_429_FIRST_BACKOFF_SEC:.0f}s→"
                f"{UPSTREAM_429_COOLDOWN_SEC:.0f}s · inline wait <= {UPSTREAM_429_INLINE_WAIT_MAX_SEC:.0f}s · "
                f"same-account retries {UPSTREAM_429_SAME_ACCOUNT_RETRIES} · Retry-After honored · no route/account rotation")
    log("INFO", "Capacity target · queued multi-user admission · one stable browser transport lane per keeper")
    log("INFO", "Proxy allocator · full-pool startup scan + distinct keeper assignment enabled")
    log("INFO", "Proxy lifecycle · non-destructive circuit breaker · auto-recovery + automatic re-admission · no automatic deletion")
    if get_verification_solver:
        log("OK", f"Verification adapter factory loaded: {_VERIFICATION_FACTORY_SPEC}")
    else:
        log("WARN", "Optional verification adapter not installed; keeper-native verification remains active"
            + (f": {_VERIFICATION_IMPORT_ERROR}" if _VERIFICATION_IMPORT_ERROR else ""))
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await keeper.close()
        await _v3_vnc_stop()
        LOG.close()


app.router.lifespan_context = _lifespan  # starlette late-bind



# ================================================================
#  ENTRY — one file, uvicorn; multi-worker keeps the legacy election via state.json
# ================================================================
def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Bridgena v4.2 sticky Arena session bridge")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--workers", type=int, default=int(os.environ.get("BRIDGENA_WORKERS", "1")))
    args = ap.parse_args()
    jars_count = len([j for j in load_jars() if not j.get("expired")])
    print("=" * 62)
    print("  BRIDGENA v4.2 — Sticky Arena Session Bridge (" + BUILD_STAMP + ")")
    print("=" * 62)
    print(f"  * Live Chat   : {PUBLIC_APP_URL}/chat")
    print(f"  * Dashboard   : {PUBLIC_APP_URL}/dashboard")
    print(f"  * OpenAI Base : {PUBLIC_APP_URL}/v1")
    print(f"  * Local port  : {args.port} (public URL requires reverse proxy/TLS)")
    print(f"  * Workers     : {args.workers} (healthy accounts: {jars_count})")
    print(f"  * Exits       : {len([l for l in _pool_lines() if l.strip()])} in proxies.txt")
    if args.workers > 1:
        print("  ! workers>1: keepers run in the leader elected via state.json only")
    print("=" * 62)
    try:
        import uvicorn
    except ImportError:
        print("pip install uvicorn (or run behind any ASGI server: app object = `app`)")
        raise SystemExit(2)
    if args.workers > 1:
        module = os.path.splitext(os.path.basename(__file__))[0]
        uvicorn.run(f"{module}:app", host="0.0.0.0", port=args.port, workers=args.workers)
    else:
        uvicorn.run(app, host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    _cli()
