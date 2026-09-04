#!/usr/bin/env python3
# ================================================================
#  BRIDGENA v2 — single-file arena bridge (built from v2/ at build time)
#  modules: core · identity · primitives · pool · tokens · arena · pages · api
#  Deploy: replace main.py, restart. Same files, same env, same API keys.
# ================================================================
import asyncio, base64, functools, hashlib, hmac, json, math, os, random
import re, secrets, socket, struct, subprocess, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlparse, quote, quote_plus
from io import BytesIO
import shutil

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
ARENA_BASE = os.environ.get("BRIDGENA_ARENA_BASE", "https://arena.ai")
ARENA_MODES = ["direct-battle", "direct"]
MAX_PROMPT = 50000
COOLDOWN_SEC = 60                 # soft preference; the pool is never hard-locked
REFRESH_INTERVAL = 3600
CURL_TTFB_TIMEOUT = int(os.environ.get("CURL_TTFB_TIMEOUT", "40"))
PROXY_FLAG_TTL = int(os.environ.get("PROXY_FLAG_TTL", "10800"))      # arena-block: ~3h, self-expiring
PROXY_QUARANTINE = int(os.environ.get("PROXY_QUARANTINE", "21600"))  # dead-tunnel exile: 6h
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
REQUEST_MAX_ATTEMPTS = max(1, min(5, int(os.environ.get("BRIDGENA_REQUEST_MAX_ATTEMPTS", "3"))))
STREAM_TAIL_GRACE_MS = max(5000, min(60000, int(os.environ.get("BRIDGENA_STREAM_TAIL_GRACE_MS", "30000"))))
KEEPER_WARMUP_SEC = max(0, min(60, int(os.environ.get("BRIDGENA_KEEPER_WARMUP_SEC", "15"))))
API_DUPLICATE_WINDOW_SEC = max(0, min(60, int(os.environ.get("BRIDGENA_DUPLICATE_WINDOW_SEC", "15"))))

BUILD_STAMP = os.environ.get("BRIDGENA_BUILD", "v2.32-newapi-usage")

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
        import threading
        self.path, self.ring, self._mu = path, [], threading.Lock()
        self.subs: list = []

    def log(self, level: str, msg: str) -> None:
        import json, time
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        print(line, flush=True)
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"t": time.time(), "lvl": level, "m": msg}) + "\n")
        except OSError:
            pass
        with self._mu:
            self.ring.append({"t": time.time(), "lvl": level, "m": msg, "line": line})
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


class FileLock:
    """Dual-use lock: `with FileLock(p):` AND @FileLock(p) decorator form.
    Thread lock always; flock best-effort for cross-worker sanity."""
    def __init__(self, path: str, timeout: float = 10.0):
        self.path, self.timeout = path, timeout
        import threading
        self._mu = threading.Lock()
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
                    return               # degraded: thread lock already held
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

    """Arena catalog entries carry publicName/id; OpenAI surface needs one canonical name."""
    if isinstance(m, str):
        return m
    return m.get("name") or m.get("publicName") or m.get("id") or ""


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
        labels = (item.get("name"), item.get("publicName"), item.get("id"))
        if public_name in labels or wanted in {_model_key(x) for x in labels if x}:
            return item.get("id") or public_name
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
        u = urlparse(ARENA_BASE)
        return (u.hostname or "arena.ai"), (u.port or 443)
    except Exception:
        return "arena.ai", 443

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
    socks4/4a/5 via native SOCKS4/SOCKS5 connect to arena.ai:443. Every failure
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
    # resolver (an app host resolving arena.ai itself can hand the gateway a
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
                return {"server": sh}
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
        return out
    except Exception:
        return None

def atomic_write(path: str, data: Any) -> None:
    tmp = f"{path}.tmp{os.getpid()}_{secrets.token_hex(4)}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

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
    """Fetch models from Arena's Next.js page/Flight state using a live keeper."""
    log("INFO", f"[{worker.name}] Refreshing models via worker navigation...")
    try:
        async with worker._action_lock:
            await worker.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=30000)
            await worker.page.wait_for_load_state("domcontentloaded")
            body = await worker.page.content()
            try:
                flight = await worker.page.evaluate("() => JSON.stringify(self.__next_f || [])")
            except Exception:
                flight = ""

        def _array_after_key(src: str):
            """Extract nested JSON safely; a non-greedy regex truncates on the
            first capability array/object inside initialModels."""
            if not src:
                return None
            for needle in ('"initialModels"', "'initialModels'"):
                pos = src.find(needle)
                while pos >= 0:
                    start = src.find("[", pos + len(needle))
                    if start < 0:
                        break
                    depth, quoted, escaped = 0, False, False
                    for i in range(start, len(src)):
                        ch = src[i]
                        if quoted:
                            if escaped:
                                escaped = False
                            elif ch == "\\":
                                escaped = True
                            elif ch == '"':
                                quoted = False
                        elif ch == '"':
                            quoted = True
                        elif ch == "[":
                            depth += 1
                        elif ch == "]":
                            depth -= 1
                            if depth == 0:
                                try:
                                    value = json.loads(src[start:i + 1])
                                    if isinstance(value, list):
                                        return value
                                except Exception:
                                    break
                    pos = src.find(needle, pos + len(needle))
            return None

        import html as _model_html
        sources = [body, _model_html.unescape(body), flight]
        sources += [s.replace('\\"', '"').replace('\\\\', '\\')
                    for s in list(sources) if s]
        models_data = next((v for v in (_array_after_key(s) for s in sources) if v), None)
        if models_data:

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
        log("WARN", "Could not find a balanced initialModels array in page/Flight source.")
    except Exception as e:
        log("ERROR", f"Failed to refresh models: {e}")
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
        has_session = bool(s and s.running and getattr(s, "page", None) and not s.page.is_closed())
        is_live = has_session and (not getattr(s, "headless", True))
        healthy = bool(s and s.last_health_ok and (now - s.last_health_ok) < 900)
        available = jar_available(j, now)
        captcha_clean = 1 if (now - _captcha_failed_jars.get(sid, 0.0) > 300) else 0
        # last_used is inverted so older = higher priority
        recency = -float(j.get("last_used", 0) or 0)
        return (
            captcha_clean,
            1 if (prefer_live and is_live and healthy) else 0,
            1 if (prefer_live and has_session and healthy) else 0,
            1 if available else 0,
            1 if has_session else 0,
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
    # Do not wait for the supervisor's next 15-second tick. Register every
    # session immediately; sync() starts browsers as background tasks.
    await keeper.sync()
    log("INFO", f"Auto-login: {len(accounts_with_creds)} keeper session(s) launched")

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

class BridgeHTTPError(Exception):
    def __init__(self, status: int, body: str):
        self.status, self.body = status, body
        super().__init__(f"HTTP {status}: {body[:200]}")

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

        self.running = False
        self.status = "stopped"
        self.error = None
        self.current_step = ""
        self.step_history = []
        self.last_activity = 0.0
        self.last_health_ok = 0.0
        self.last_nav = 0.0
        self.last_restart = 0.0
        self.ready_at = 0.0
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
        # Serialize through the keeper page unless an operator explicitly opts
        # into extra tabs after validating upstream capacity.
        self._max_pool_pages = max(0, min(2, int(os.environ.get("BRIDGENA_KEEPER_EXTRA_PAGES", "0"))))

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
            return bool(tok_final or solved_any)
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
                    await new_page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded")
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
                    P('S' + r.status);
                    if (!r.ok) {
                        const error = (await r.text()).slice(0, 400);
                        P('E' + error); P('Dnull');
                        return {status: r.status, error, lines: captured};
                    }
                    const reader = r.body.getReader();
                    const dec = new TextDecoder();
                    let buffer = '';
                    let protocolFinished = false;
                    let stopReason = 'eof';
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
                                if (/^(ad|d|e):/.test(line.trim())) protocolFinished = true;
                            }
                        }
                        if (done) break;
                    }
                    if (buffer.trim()) emit(buffer);
                    P('D' + JSON.stringify(null));
                    return {status: r.status, error: '', lines: captured,
                            finishSeen: protocolFinished, stopReason};
                } catch(e) {
                    P('S500'); P('E' + e.message); P('Dnull');
                    return {status: 500, error: String(e.message || e), lines: captured};
                }
            }"""
            eval_task = asyncio.create_task(page.evaluate(
                script, [url, payload, req_id, RECAPTCHA_ACTION, STREAM_TAIL_GRACE_MS]
            ))
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
            result = await eval_task
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
                if status_code == 200:
                    log("INFO", f"[{self.name}] stream audit · HTTP 200 · frames {frame_count} · "
                                f"finish {'yes' if result.get('finishSeen') else 'no'} · "
                                f"stop {result.get('stopReason') or 'unknown'}")
                else:
                    log("WARN", f"[{self.name}] stream audit · HTTP {status_code or 0} rejected before stream · frames {frame_count} · body: {error_body[:300]}")
            if status_code != 200:
                raise BridgeHTTPError(status_code, error_body)
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
                        user_agent=self.user_agent or KEEPER_UA,  # persona-bound; cf_clearance is UA+IP-bound
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

            self._set_step("Navigating to arena.ai...")
            await self._ensure_sidebar_cookie()
            await self.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=25000)
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

            self.ready_at = time.monotonic() + KEEPER_WARMUP_SEC
            if KEEPER_WARMUP_SEC:
                log("INFO", f"[{self.name}] Keeper warm-up gate {KEEPER_WARMUP_SEC}s before API traffic")

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
            if used:
                self._tried_proxies.add(used)
                if _cap_err:
                    _probe_fail_reason[used] = "keeper shim bypassed: browser capability error (proxy NOT exiled)"
                    log("WARN", f"[{self.name}] {used.split('@')[-1]} kept in pool — Chromium capability error, not a dead proxy")
                else:
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
_pick_ctr = 0
import threading as _th
_pick_mu = _th.Lock()


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
    """Tunnel-dead: cut from the pool, park in proxies.dead.txt with reason."""
    key = _proxy_hkey(proxy_url)
    _QUARANTINED_KEYS.add(key)
    try:
        raw = proxy_url if proxy_url.startswith(("socks", "http")) else _normalize_proxy(proxy_url) or proxy_url
        _append_dead(raw, reason or "quarantined")
        lines = _pool_lines()
        keep = [l for l in lines if _proxy_hkey(_normalize_proxy(l) or l) != key]
        if len(keep) != len(lines):
            pool_save(keep)
        cfg = get_config()
        px = cfg.get("proxies") or []
        px2 = [l for l in px if _proxy_hkey(_normalize_proxy(l) or l) != key]
        if len(px2) != len(px):
            cfg["proxies"] = px2
            save_config(cfg)
        _flagged_exits.pop(key, None)
        _proxy_strikes.pop(key, None)
        log("WARN", f"proxy quarantined: {key} — {redact(reason)[:120]}")
    except Exception as e:
        log("WARN", f"quarantine bookkeeping failed for {key}: {type(e).__name__}: {e}")


def strike_proxy(proxy_url: str, reason: str = "") -> bool:
    """Timeout/soft-failure: one strike; quarantine only at STRIKES_MAX."""
    key = _proxy_hkey(proxy_url)
    _proxy_strikes[key] = _proxy_strikes.get(key, 0) + 1
    if _proxy_strikes[key] >= STRIKES_MAX:
        quarantine_proxy(proxy_url, f"{STRIKES_MAX} strikes: {reason}")
        return True
    log("WARN", f"exit {key}: {redact(reason)[:80]} (strike {_proxy_strikes[key]}/{STRIKES_MAX})")
    return False


def clear_strikes(proxy_url: str) -> None:
    _proxy_strikes.pop(_proxy_hkey(proxy_url), None)


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
def sweep_all() -> dict:
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


# ---------- ingest / prune / revive ----------
def parse_upload(text: str) -> Tuple[List[str], int, int]:
    """Accepts plain lines AND headered CSV exports (R10 rules):
    'Host,Port,Username,Password[,Type]' rows become scheme://u:p@host:port."""
    import csv as _csv, io as _io
    lines = [l.strip() for l in text.replace("\r", "").splitlines() if l.strip() and not l.strip().startswith("#")]
    out, skipped, hinted = [], 0, 0
    looks_csv = lines and ("," in lines[0]) and ("|" not in lines[0])
    if looks_csv:
        rows = list(_csv.reader(_io.StringIO("\n".join(lines)), skipinitialspace=True))
        head = [h.strip().lower() for h in rows[0]] if rows else []
        idx = {k: i for i, k in enumerate(head)}
        has_head = any(k in idx for k in ("host", "ip address", "ip_address", "proxy address"))
        body = rows[1:] if has_head else rows
        for r in body:
            if not r:
                skipped += 1; continue
            def col(*names, default=""):
                for nm in names:
                    if nm in idx and idx[nm] < len(r):
                        return r[idx[nm]].strip()
                return default
            host = col("host", "ip address", "ip_address", "proxy address", "ip")
            port = col("port", "proxy port")
            user = col("username", "user", "proxy username")
            pw = col("password", "pass", "proxy password")
            typ = (col("type", "scheme", "proxy type", default="http") or "http").lower()
            if not (host and str(port).isdigit()):
                alt = _normalize_proxy(",".join(r)) if r and ":" in r[0] and not host else None
                if alt:
                    out.append(alt); continue
                skipped += 1; continue
            if typ not in ("socks5", "socks5h", "socks4", "socks4a", "http", "https"):
                hinted += 1
                typ = "http"
            auth = f"{user}:{pw}@" if user else ""
            out.append(f"{typ}://{auth}{host}:{port}")
        if not out:
            # headered export failed to map — fall through to plain-line parse
            lines = [l for l in text.replace("\r", "").splitlines() if l.strip() and not l.strip().startswith("#")]
    for l in lines if not looks_csv or not out else []:
        n = _normalize_proxy(l)
        if n:
            out.append(n)
        else:
            skipped += 1
    seen, dedup = set(), []
    for u in out:
        k = _proxy_hkey(u) or u
        if k not in seen:
            seen.add(k); dedup.append(u)
    return dedup, skipped, hinted


def upload_pool(text: str) -> dict:
    new, skipped, hinted = parse_upload(text)
    cur = _pool_lines()
    cur_keys = {_proxy_hkey(_normalize_proxy(l) or l) for l in cur if l.strip()}
    add = [u for u in new if _proxy_hkey(u) not in cur_keys]
    merged = cur + add
    pool_save(merged)
    log("OK", f"proxy manager: +{len(add)} from upload/paste ({len(new)} parsed, {skipped} skipped, {hinted} with list hints)")
    return {"added": len(add), "parsed": len(new), "skipped": skipped, "hinted": hinted}


def prune_bad() -> int:
    """Cut lines whose verdicts say they're unusable (quarantined or flagged-dead strikes)."""
    bad = set(_QUARANTINED_KEYS)
    lines = _pool_lines()
    keep = []
    cut = 0
    for l in lines:
        if not l.strip() or l.startswith("#"):
            continue
        norm = _normalize_proxy(l) or l
        k = _proxy_hkey(norm)
        if k in bad or _proxy_strikes.get(k, 0) >= STRIKES_MAX or (norm in _proxy_probe_cache and not _proxy_probe_cache[norm][0]):
            _append_dead(norm, "pruned by verdict")
            cut += 1
        else:
            keep.append(l)
    if cut:
        pool_save(keep)
    log("OK", f"proxy prune 'bad': {cut} cut from proxies.txt (kept {len(keep)})")
    return cut


def remove_one(hkey: str) -> int:
    lines = _pool_lines()
    keep = [l for l in lines if _proxy_hkey(_normalize_proxy(l) or l) != hkey]
    if len(keep) == len(lines):
        return 0
    pool_save(keep)
    _QUARANTINED_KEYS.add(hkey)
    return len(lines) - len(keep)


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
            verdict, why = "dead", _probe_fail_reason.get(norm, _probe_fail_reason.get(norm, "quarantined"))
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
                    try {
                        const t2 = await ex({sitekey: KEY, action: ACTION});
                        if (t2 && t2.length > 20) return {token: t2, source, keyHint: hint(KEY), action: ACTION};
                    } catch (e2) {}
                    try {
                        if (typeof g.execute === 'function') {
                            const t3 = await Promise.race([g.execute(KEY, {action: ACTION}),
                                                           new Promise((_, r) => setTimeout(() => r(new Error('v3-timeout')), 8000))]);
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

_mint_last_no_session = 0.0


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
        if (s and s.running and getattr(s, "page", None) and not s.page.is_closed()
                and time.monotonic() >= getattr(s, "ready_at", 0.0)):
            return jar_id, s
        # A token from some other account/browser/exit is not a fallback: it is
        # cryptographically and behaviorally the wrong identity for this jar.
        return None, None
    for sid, s in list(sessions.items()):
        if (s and s.running and getattr(s, "page", None) and not s.page.is_closed()
                and time.monotonic() >= getattr(s, "ready_at", 0.0)):
            return sid, s
    return None, None


async def mint_v3(jar_id=None):
    """Primary token: evaluate grecaptcha v3 on a live keeper page. If v3 bypass
    fails or produces no token, automatically falls back to visual image challenge solving."""
    global _mint_last_no_session
    sid, s = _find_session(jar_id)
    if not s:
        now = time.time()
        if now - _mint_last_no_session > 60:
            _mint_last_no_session = now
            log("WARN", "recaptcha token: no live keeper session — tokens are minted from a browser "
                        "on the SAME exit; enable keepers (Pool page) or open Live Browser")
        return None
    try:
        async with s._action_lock:
            # The live client loads enterprise reCAPTCHA on the direct-chat
            # route. Stabilize there, then evaluate in the same locked browser
            # transaction so catalog/health navigation cannot destroy context.
            if "mode=direct" not in (s.page.url or ""):
                await s.page.goto(ARENA_DIRECT_URL, wait_until="domcontentloaded", timeout=30000)
                await s.page.wait_for_load_state("domcontentloaded")
                s.last_nav = time.time()

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
                    "allowConfiguredFallback": True,
                    "action": RECAPTCHA_ACTION,
                })
                if isinstance(res, str) and len(res) > 20:
                    v3_token = res
                elif isinstance(res, dict) and isinstance(res.get("token"), str) and len(res["token"]) > 20:
                    log("OK", "recaptcha v3 token minted via " + str(res.get("source", "unknown"))
                        + " · key " + str(res.get("keyHint", "unknown"))
                        + " · action " + str(res.get("action", RECAPTCHA_ACTION)))
                    v3_token = res["token"]
                else:
                    why = res.get("err") if isinstance(res, dict) else "evaluate returned nothing"
                    log("WARN", f"recaptcha v3 bypass unavailable ({why}) — triggering image solver fallback")
            except Exception as v3_err:
                log("WARN", f"recaptcha v3 evaluate timed out/failed: {v3_err} — triggering image solver fallback")

            if v3_token:
                return v3_token
            return None

    except Exception as e:
        log("WARN", f"recaptcha token: browser transaction failed: {type(e).__name__}: {e}")
    return None


async def mint_v2_escalation(jar_id=None, settle_s: float = 20.0):
    """The path arena's OWN client uses after recaptcha_validation_failed:
    mount the V2 checkbox, let the keeper's ONNX grid solver or extension work it,
    harvest the response. Returns token or None.
    CRITICAL: Must fail fast if checkbox cannot be clicked or if no solver is available,
    to prevent client connection timeouts."""
    sid, s = _find_session(jar_id)
    if not s:
        log("WARN", "recaptcha token: V2 escalation skipped — no live keeper session")
        return None
    try:
        # Check if ONNX solver or extension is present
        solver = get_solver() if "get_solver" in globals() else None
        has_onnx = bool(solver and solver.available())
        ext_path = os.environ.get("BRIDGENA_CAPTCHA_EXT", "")
        has_ext = bool(ext_path and os.path.exists(os.path.join(ext_path, "manifest.json")))

        # Check if already solved or present
        tok = await s.page.evaluate(RC_V2_READ_JS)
        if tok and not str(tok).startswith("__ERR__"):
            log("OK", f"recaptcha V2 token already present ({len(tok)} chars)")
            return tok

        # If solver is available, attempt to solve any challenge frame already open
        if has_onnx and hasattr(s, "solve_recaptcha_image_challenge"):
            if await s.solve_recaptcha_image_challenge():
                tok = await s.page.evaluate(RC_V2_READ_JS)
                if tok and not str(tok).startswith("__ERR__"):
                    log("OK", f"recaptcha V2 token harvested via ONNX solver ({len(tok)} chars)")
                    return tok

        # 1. Mount V2 checkbox widget with verified Arena V2 escalation sitekey
        mount = await s.page.evaluate(RC_V2_WIDGET_JS, ARENA_RECAPTCHA_V2_SITEKEY)
        if not (isinstance(mount, dict) and mount.get("ok")):
            log("WARN", f"recaptcha token: V2 mount failed: {(mount or {}).get('err') if isinstance(mount, dict) else mount}")
            if ARENA_RECAPTCHA_SITEKEY != ARENA_RECAPTCHA_V2_SITEKEY:
                mount2 = await s.page.evaluate(RC_V2_WIDGET_JS, ARENA_RECAPTCHA_SITEKEY)
                if not (isinstance(mount2, dict) and mount2.get("ok")):
                    return None

        # 2. Click the checkbox across all frames (give iframe up to 2.5s to mount)
        clicked = False
        for _ in range(5):
            await asyncio.sleep(0.5)
            for frame in s.page.frames:
                try:
                    cb = frame.locator("#recaptcha-anchor, .recaptcha-checkbox-border")
                    if await cb.count() > 0 and await cb.first.is_visible():
                        await cb.first.click(timeout=2000)
                        clicked = True
                        break
                except Exception:
                    continue
            if clicked:
                break

        # FAST-FAIL 1: If no checkbox was clicked, there is NO challenge to solve
        if not clicked:
            log("WARN", f"[{sid}] recaptcha token: V2 escalation skipped — no visible checkbox anchor on keeper page")
            return None

        # 3. Check for instant auto-pass checkmark
        await asyncio.sleep(1.2)
        tok = await s.page.evaluate(RC_V2_READ_JS)
        if tok and not str(tok).startswith("__ERR__"):
            log("OK", f"recaptcha V2 token harvested from auto-pass checkmark ({len(tok)} chars)")
            return tok

        # FAST-FAIL 2: If neither ONNX solver nor browser extension is present, fail fast
        if not has_onnx and not has_ext:
            await asyncio.sleep(1.0)
            tok = await s.page.evaluate(RC_V2_READ_JS)
            if tok and not str(tok).startswith("__ERR__"):
                log("OK", f"recaptcha V2 token harvested ({len(tok)} chars)")
                return tok
            log("WARN", f"[{sid}] reCAPTCHA challenge presented but ONNX solver/extension not available — failing fast to rotate account")
            return None

        # 4. Solver or extension is available: run solver
        if has_onnx and hasattr(s, "solve_recaptcha_image_challenge"):
            await s.solve_recaptcha_image_challenge()

        max_wait = min(settle_s, 20.0 if has_onnx else 15.0)
        deadline = time.time() + max_wait
        while time.time() < deadline:
            tok = await s.page.evaluate(RC_V2_READ_JS)
            if tok:
                if str(tok).startswith("__ERR__"):
                    log("WARN", f"[{sid}] reCAPTCHA widget reported error: {tok}")
                    return None
                log("OK", f"recaptcha V2 token harvested ({len(tok)} chars)")
                return tok
            await asyncio.sleep(1.0)
        log("WARN", f"recaptcha token: V2 challenge did not complete in window (clicked={clicked}, solver={has_onnx or has_ext})")
        return None
    except Exception as e:
        log("WARN", f"recaptcha token: V2 escalation error: {type(e).__name__}: {e}")
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
    if status == 429:
        if "prompt failed" in low or "captcha" in low or "recaptcha" in low:
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
        value = delta.get("text") or delta.get("content")
        if isinstance(value, str) and value:
            out.append(("reasoning" if "thinking" in delta_kind or "reasoning" in delta_kind else "content", value))
            return out

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


async def run_turn(chat_id: str, prompt: str, model_name: str,
                   attachments: Optional[list] = None, jar_hint: Optional[str] = None):
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
    rc_attempts = 0
    tried = set()
    bound_jar_id = (mc or {}).get("jar_id")
    wanted_jar_id = jar_hint or bound_jar_id
    jar = (next((j for j in load_jars()
                 if j.get("id") == wanted_jar_id and j.get("enabled", True)), None)
           if wanted_jar_id else acquire_jar(prefer_live=True))
    if bound_jar_id and not jar:
        yield ("error", "409: This Arena thread's original jar is unavailable. Start a new Bridgena thread instead of replaying its ID through another account.")
        return
    if not jar and jar_hint:
        jar = acquire_jar(prefer_live=True)
    if not jar:
        yield ("error", "502: No jar with valid cookies/session — upload cookies or enable a keeper")
        return
    tried.add(jar["id"])

    # Startup used to race chat: requests reached Arena with `token no` while
    # all keepers were still launching, producing opaque 500s. Trigger sync and
    # wait briefly for this exact jar's page instead of sending invalid traffic.
    if not _find_session(jar.get("id"))[1]:
        await keeper.sync()
        deadline = time.monotonic() + 35.0
        while time.monotonic() < deadline and not _find_session(jar.get("id"))[1]:
            s_wait = keeper.sessions.get(jar.get("id"))
            if s_wait and s_wait.status == "error":
                break
            await asyncio.sleep(0.5)
    if not _find_session(jar.get("id"))[1]:
        s_wait = keeper.sessions.get(jar.get("id"))
        detail = redact(getattr(s_wait, "error", "") or getattr(s_wait, "current_step", "") or "keeper is still starting")
        yield ("error", f"503: The selected account has no ready same-exit keeper ({detail}). Check Accounts, then retry.")
        return
    response_text = ""
    reasoning_text = ""
    pending_v2_token = None
    for attempt in range(max_attempts):
        p = bind_persona(jar)
        jar = await _live_cookies(jar)
        if not jar_has_auth(jar):
            if mc:
                yield ("error", "409: This Arena thread lost its original authenticated jar. Start a new Bridgena thread.")
                return
            nxt = acquire_jar(prefer_live=True, exclude=tried)
            if nxt and nxt["id"] not in tried:
                jar, _ = nxt, tried.add(nxt["id"])
                continue
            yield ("error", "502: Arena session expired — no other authenticated account")
            return
        model_id = resolve_model_id(model_name, jar)
        if not re.fullmatch(r"[0-9a-fA-F-]{32,36}", str(model_id)):
            yield ("error", f"422: Model '{model_name}' has no Arena UUID in the catalog. Refresh Models after a keeper is live, then retry.")
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
                "userMessageId": str(uuid7()),
                "modelAMessageId": str(uuid7()),
                "modality": "chat",
            }
            follow_url = f"{ARENA_BASE}/nextjs-api/stream/post-to-evaluation/{mc['arena_id']}"
        else:
            base.update({"id": str(uuid7()), "userMessageId": str(uuid7()),
                         "modelAMessageId": str(uuid7())})
        content = prompt if len(prompt) <= MAX_PROMPT else prompt[:MAX_PROMPT]
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

        if pending_v2_token:
            _attach_v2(base, pending_v2_token)
            tok = pending_v2_token
            pending_v2_token = None
            log("INFO", f"[{jar.get('name')}] Using harvested V2 escalation token ({len(tok)} chars) — skipping V3 minting")
        else:
            tok = await mint_v3(jar.get("id"))
            if not tok:
                log("INFO", f"[{jar.get('name')}] Minting v3 token unavailable — attempting v2 escalation challenge fallback")
                tok = await mint_v2_escalation(jar.get("id"), settle_s=20.0)
                if tok:
                    _attach_v2(base, tok)
            else:
                _attach_v3(base, tok)

        if not tok and not base.get("recaptchaV2Token") and not base.get("recaptchaV3Token"):
            yield ("error", "503: The same-exit keeper is live but could not mint or solve a reCAPTCHA token. "
                            "No request was sent to Arena; inspect keeper status/models and retry.")
            return
        url = follow_url or f"{ARENA_BASE}/nextjs-api/stream/create-evaluation"
        # Existing Arena conversations are session-bound. Restore the exact exit
        # that created the thread before the normal sticky picker runs.
        bound_proxy = (_normalize_proxy(mc.get("proxy"))
                       if mc and mc.get("proxy") and _rotation_mode() == "assignment" else None)
        if bound_proxy:
            if not await asyncio.to_thread(proxy_alive, bound_proxy):
                yield ("error", "409: This Arena thread's original exit is unavailable. Start a new Bridgena thread; its conversation ID cannot safely move to another IP.")
                return
            proxy = bound_proxy
        else:
            proxy = await apick_live_proxy(jar, purpose="api")
        proxy, cycled = await anchor_proxy_to_keeper(jar.get("id"), proxy)
        if cycled:
            jar = await _live_cookies(jar)
        if proxy:
            log("INFO", f"[{jar.get('name')}] via {p.key} persona · exit {_proxy_hkey(proxy)} · "
                        f"model {str(model_id)[:8]}… · token {'yes' if tok else 'no'}")
        else:
            log("WARN", f"[{jar.get('name')}] No live proxy — using server IP (easy to rate-limit)")

        # Preferred transport: execute the POST inside the already-authenticated
        # keeper origin. This preserves the exact browser cookie jar, TLS/browser
        # identity and proxy exit that minted the token. curl remains a fallback
        # only for browser-evaluation failures.
        browser_session = keeper.sessions.get(jar.get("id"))
        if browser_session and browser_session.running and browser_session.page:
            try:
                log("INFO", f"[{jar.get('name')}] transport browser-origin")
                async with browser_session._action_lock:
                    async for line in browser_session.bridge_fetch(url, base):
                        ev = _parse_stream_line(str(line).strip())
                        if not ev:
                            continue
                        kind, payload = ev
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
                if proxy:
                    _proxy_health_record(proxy, True, 0, source="browser-stream")
                    _flagged_exits.pop(_proxy_hkey(proxy), None)
                _captcha_failed_jars.pop(jar.get("id"), None)
                if not response_text and reasoning_text:
                    response_text = reasoning_text
                    yield ("content", reasoning_text)
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
                yield ("done", response_text)
                return
            except BridgeHTTPError as e:
                verdict = _classify(e.status, e.body)
                log("WARN", f"[{jar.get('name')}] browser-origin HTTP {e.status} (verdict={verdict}): {e.body[:250]}")

                # If a follow-up request failed on post-to-evaluation with non-captcha error (400, 404, 500):
                # Clear the stale Arena thread and rebuild as a fresh create-evaluation turn
                if mc and verdict != "RECAPTCHA":
                    clear_conversation_model(chat_id, model_name)
                    mc = None
                    conv = {}
                    response_text = ""
                    reasoning_text = ""
                    log("WARN", f"[{jar.get('name')}] follow-up rejected by Arena (HTTP {e.status}) — rebuilding as fresh create-evaluation")
                    if attempt + 1 < max_attempts:
                        continue

                if verdict == "PROMPT":
                    log("WARN", f"[{jar.get('name')}] Arena rejected prompt before streaming (HTTP {e.status}) — no retry or rotation")
                    yield ("error", "422: Arena rejected this prompt before generation. Bridgena did not retry or rotate accounts; shorten the request or remove unsupported tool/system payloads.")
                    return

                if verdict == "RATELIMIT":
                    if not mc and attempt + 1 < max_attempts:
                        nxt = acquire_jar(prefer_live=True, exclude=tried)
                        if nxt and nxt["id"] not in tried:
                            jar, _ = nxt, tried.add(nxt["id"])
                            log("WARN", f"[{jar.get('name')}] model rate-limited (HTTP 429) — rotating account to try remaining quota")
                            continue
                    log("WARN", f"[{jar.get('name')}] upstream prompt throttle (HTTP {e.status}) — request stopped; no account rotation")
                    yield ("error", f"429: Arena returned Too Many Requests for model '{model_name}'. This model is currently rate-limited upstream on Arena; wait 30-60s or select another model in your chat.")
                    return

                if verdict == "UPSTREAM" and attempt + 1 < max_attempts:
                    await asyncio.sleep(min(5.0, 1.0 + attempt))
                    continue

                if verdict == "RECAPTCHA":
                    _captcha_failed_jars[jar.get("id")] = time.time()
                    if rc_attempts < 2:
                        rc_attempts += 1
                        log("WARN", f"[{jar.get('name')}] Arena verification rejected token (HTTP {e.status}) — escalating to V2 challenge solver")
                        esc = await mint_v2_escalation(jar.get("id"), settle_s=20.0)
                        if esc:
                            pending_v2_token = esc
                            log("OK", f"[{jar.get('name')}] V2 escalation token attached — retrying SAME jar")
                            if attempt + 1 < max_attempts:
                                continue
                    if mc:
                        clear_conversation_model(chat_id, model_name)
                        mc = None
                        conv = {}
                        response_text = ""
                        reasoning_text = ""
                        log("WARN", f"[{jar.get('name')}] follow-up verification failed — rebuilding as fresh create-evaluation")
                        if attempt + 1 < max_attempts:
                            continue
                    if not mc and attempt + 1 < max_attempts:
                        nxt = acquire_jar(prefer_live=True, exclude=tried)
                        if nxt and nxt["id"] not in tried:
                            jar, _ = nxt, tried.add(nxt["id"])
                            log("INFO", f"[{jar.get('name')}] Rotating to live account after captcha rejection on previous exit")
                            continue
                    log("WARN", f"[{jar.get('name')}] Arena verification rejected (HTTP {e.status}) and escalation failed")
                    yield ("error", "403: Arena rejected this session's verification token. The request was stopped without repeated retries; wait briefly and try a new chat.")
                    return

                if e.status == 400 and "user message is invalid" in (e.body or "").lower():
                    yield ("error", "400: Arena rejected the message content. Send plain text or supported text content parts; images and unsupported multimodal parts are not accepted by this bridge yet.")
                    return
                yield ("error", f"{e.status or 502}: Arena browser-origin request failed: {e.body[:350] or 'empty response'}")
                return
            except Exception as browser_e:
                log("WARN", f"[{jar.get('name')}] browser-origin unavailable ({type(browser_e).__name__}: {browser_e}) — curl fallback")

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
                            why = ("WARP-only pool: arena.ai's edge routinely rejects Cloudflare's own egress IPs — expected, not fixable from here"
                                   if warp_only else "the gateways answered 'can't route' — arena.ai is rejecting these exits' egress IPs right now")
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
                        if rc_attempts < 2:
                            rc_attempts += 1
                            esc = await mint_v2_escalation(jar.get("id"), settle_s=20.0)
                            if esc:
                                _attach_v2(base, esc)
                                log("WARN", f"[{jar.get('name')}] V2 escalation token attached — retrying SAME jar")
                                continue
                            fresh = await mint_v3(jar.get("id"))
                            if fresh:
                                _attach_v3(base, fresh)
                                log("WARN", f"[{jar.get('name')}] recaptcha rejected — fresh V3 token, retrying SAME jar")
                                continue
                        log("WARN", f"[{jar.get('name')}] recaptcha unresolved — jar KEPT HEALTHY (starvation is our bug, not their death)")
                        yield ("error", "403: arena's recaptcha check rejected us and the keeper could not mint a token on this exit. "
                                        "Jars were NOT expired. Fix order: keeper live on this exit → solver models present "
                                        "(recaptcha_solver.py + models/ + onnxruntime) → 'recaptcha token:' WARN says which link.")
                        return

                    if verdict == "PROMPT":
                        log("WARN", f"[{jar.get('name')}] Arena rejected prompt before streaming — no retry or rotation")
                        yield ("error", "422: Arena rejected this prompt before generation. Bridgena did not retry or rotate accounts; shorten the request or remove unsupported tool/system payloads.")
                        return

                    if verdict == "RATELIMIT":
                        log("WARN", f"[{jar.get('name')}] upstream prompt throttle — request stopped; no account rotation")
                        yield ("error", "429: Arena throttled or rejected this prompt. No account rotation was attempted; wait 30-60 seconds, then retry or start a new chat.")
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
                 ("Live Chat", "/chat", "chat"), ("Logs", "/logs", "logs")]
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
<div id="toast" class="toast"></div>
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
<div class="pagehead"><div><h1>Operations</h1><p>fleet status at a glance — full controls live in the rail</p></div>
<div class="row"><button class="btn" onclick="act('/proxies/api/check','POST')">⚡ Scan pool</button>
<button class="btn primary" onclick="location='/chat'">Open chat →</button></div></div>
<div class="grid metrics">
 <div class="card metric"><div class="k">exits alive</div><div class="v" style="color:var(--teal)">{m['alive']}<span class="muted" style="font-size:18px">/{m['pool_total']}</span></div><div class="s">proven to arena.ai</div></div>
 <div class="card metric"><div class="k">flagged</div><div class="v" style="color:var(--amber)">{m['flagged']}</div><div class="s">arena-blocked, self-expire ~3h</div></div>
 <div class="card metric"><div class="k">accounts</div><div class="v">{m['jars_ok']}<span class="muted" style="font-size:18px">/{m['jars_total']}</span></div><div class="s">healthy · {m['keepers_live']} keepers live</div></div>
 <div class="card metric"><div class="k">models</div><div class="v">{m['models']}</div><div class="s">selectable in fleet</div></div></div>
<div class="split" style="margin-top:16px">
 <div class="card"><h3>Top exits <span class="spacer"></span><a class="small" href="/pool">manage →</a></h3>
  <table><thead><tr><th>exit</th><th>verdict</th><th>why</th><th>latency</th></tr></thead><tbody>{rows_pool}</tbody></table></div>
 <div class="card"><h3>Accounts <a class="spacer" style="flex:1"></a><a class="small" href="/jars">manage →</a></h3>
  <table><thead><tr><th>jar</th><th>device persona</th><th>keeper</th><th>health</th></tr></thead><tbody>{jrows}</tbody></table></div>
</div>
<div class="card" style="margin-top:16px"><h3>Recent signal <span class="spacer" style="flex:1"></span><span class="mono small muted">tail ·500</span></h3>
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
    body = "".join(
        f"<tr><td class=mono>{esc(r['display'])}</td><td class=muted>{esc(r.get('scheme',''))}</td>"
        f"<td>{_verdict_pill(r['verdict'])}</td><td class=muted style='max-width:340px'>{esc(r['why']) or '—'}</td>"
        f"<td>{esc(r['latency']) if r['latency'] else '<span class=muted>—</span>'}{'ms' if r['latency'] else ''}</td>"
        f"<td class=muted>{esc(r['source'] or '')}</td>"
        f"<td><div class=row><form method=post action=/proxies/api/remove-one style=margin:0><input type=hidden name=key value='{esc(r['key'])}'><button class='btn sm ghost' title='remove'>✕</button></form></div></td></tr>"
        for r in rows) or '<tr><td colspan=7 class=muted>Empty pool.</td></tr>'
    return page("Proxy Pool", f"""
<div class="pagehead"><div><h1>Exit Pool</h1><p>{stats['alive']} alive · {stats['flagged']} arena-blocked · {stats['total']} lines — verdicts from real handshakes against arena.ai:443</p></div>
<div class="row"><button class="btn" onclick="scan()">⚡ Scan pool</button><span id="sc" class="small muted"></span></div></div>
<div class="split">
<div class="card"><table><thead><tr><th>exit (host:port)</th><th>scheme</th><th>verdict</th><th>diagnosis</th><th>rtt</th><th>seen by</th><th></th></tr></thead><tbody>{body}</tbody></table></div>
<div class="card"><h3>Add exits</h3>
<form method=post action=/proxies/api/upload><label>paste lines or a headered CSV export</label>
<textarea name=text placeholder="socks5h://user:pass@host:port&#10;Host,Port,Username,Password,Type&#10;..." style="min-height:180px"></textarea>
<div class="row" style="margin-top:12px"><button class="btn primary">Merge →</button>
<button type="button" class="btn danger" onclick="act('/proxies/api/prune','POST')">Prune dead</button>
<button type="button" class="btn ghost" onclick="act('/proxies/api/revive','POST')">Revive all</button></div></form>
<p class="small muted" style="margin-top:14px">Prune cuts only lines whose verdicts say tunnel-dead (strikes ×{esc(3)}). Arena-blocked exits are flagged, never exiled — flags self-expire (~3h) and a delivered 200 clears them instantly.</p></div>
</div>""", active="pool", raw_js="""
async function scan(){var s=document.getElementById('sc');s.textContent='scanning…';try{const r=await fetch('/proxies/api/check',{method:'POST'});
const d=await r.json();s.textContent=d.alive+'/'+d.total+' usable';setTimeout(()=>location.reload(),900)}catch(e){s.textContent='scan failed: '+e}}
async function act(u,m){try{const r=await fetch(u,{method:m});toast((await r.text()).slice(0,90));setTimeout(()=>location.reload(),700)}catch(e){toast('error')}}""")


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
<div class="row"><a class="btn" href="/jars/upload">＋ Add cookies</a></div></div>
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(340px,1fr))">{cards or '<div class="card muted">No jars yet.</div>'}</div>""", active="jars")


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
                """<div class="row"><button class="btn" onclick="fetch('/keeper/config',{method:'POST'}).then(()=>toast('refresh queued'))">↻ Refresh</button></div></div>
<div class="card"><input id="q" placeholder="filter…" oninput="flt()" style="margin-bottom:12px">
<table><thead><tr><th>name</th><th>arena id</th><th>state</th><th></th></tr></thead><tbody id="tb">""" +
                rows + """</tbody></table></div>""", active="models", raw_js="""
function flt(){var q=document.getElementById('q').value.toLowerCase();
document.querySelectorAll('#tb tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}""")


def _legacy_chat_page(models: list, default_model: str) -> str:
    opts = "".join(f'<option value="{esc(m["name"])}"{" selected" if m["name"]==default_model else ""}>{esc(m["name"])}</option>' for m in models[:300]) or '<option>gpt-4.1</option>'
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
<div id="toast" class="toast"></div>
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
 }}catch(e){{holder.innerHTML='<span class=who>ai</span><span style=color:var(--red)>'+String(e)+'</span>';document.getElementById('st').textContent='error'}}
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
    names = [m.get("name", "") for m in models if m.get("name")]
    payload = _json.dumps(names, ensure_ascii=False).replace("</", "<\\/")
    selected = _json.dumps(default_model or (names[0] if names else "auto"), ensure_ascii=False)
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
</style></head><body><div class="app">
<aside class="sidebar" id="sidebar"><div class="sidehead"><div class="mark">B</div><div class="wordmark">Bridgena</div></div><div class="sidebody"><button class="newbtn" onclick="newChat()">＋ New chat</button><div class="sectionlabel">Recent</div><div id="threads"></div></div><div class="sidefoot"><a class="ops" href="/dashboard">⚙ Operations</a></div></aside>
<main class="main"><header class="top"><button class="ghost mobile" onclick="toggleSidebar()">☰</button><div class="modelwrap"><button class="modelbtn" id="modelBtn" onclick="togglePicker()"><span id="modelLabel"></span><span class="chev">⌄</span></button><div class="picker" id="picker"><div class="searchbox"><input id="modelSearch" placeholder="Search models…" autocomplete="off"></div><div class="modellist" id="modelList"></div></div></div><div class="status"><i class="statusdot" id="statusDot"></i><span id="statusText">Ready</span></div><button class="ghost" onclick="toggleTheme()" title="Toggle theme">◐</button></header>
<div class="scroll" id="scroll"><div class="conversation" id="conversation"><div class="welcome" id="welcome"><div><div class="mark" style="margin:0 auto 18px;width:38px;height:38px">B</div><h1>How can I help?</h1><p>Choose an Arena model and start a conversation. Bridgena keeps the account, browser identity, and exit aligned for the thread.</p></div></div></div></div>
<div class="dock"><div class="compose"><textarea id="input" rows="1" placeholder="Message Bridgena"></textarea><div class="composefoot"><span class="hint">Enter to send · Shift+Enter for newline</span><button class="send" id="send" onclick="sendMessage()" aria-label="Send">↑</button></div></div><div class="runtime"><details><summary>Runtime signal</summary><pre id="signal">Waiting for activity…</pre></details></div></div></main></div>
<script>
const MODELS=__MODELS_JSON__, DEFAULT_MODEL=__DEFAULT_MODEL__;
let model=localStorage.getItem('bgn.model')||DEFAULT_MODEL, chatId=localStorage.getItem('bgn.chat')||makeId(), busy=false;
const $=id=>document.getElementById(id), escHtml=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function makeId(){return 'c-'+Math.random().toString(36).slice(2,10)}
function toggleSidebar(){ $('sidebar').classList.toggle('open') }
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
function showWelcome(){$('conversation').innerHTML='<div class="welcome" id="welcome"><div><div class="mark" style="margin:0 auto 18px;width:38px;height:38px">B</div><h1>How can I help?</h1><p>Choose an Arena model and start a conversation.</p></div></div>'}
function newChat(){chatId=makeId();localStorage.setItem('bgn.chat',chatId);showWelcome();loadThreads();$('sidebar').classList.remove('open');$('input').focus()}
async function sendMessage(){if(busy)return;const input=$('input'),text=input.value.trim();if(!text)return;busy=true;input.value='';input.style.height='44px';$('send').disabled=true;setStatus('Generating','busy');addMessage('user',text);saveLocalMessage('user',text);const out=addMessage('ai','Thinking…','thinking');let acc='';try{const history=((localChats()[chatId]||{}).messages||[]).slice(-16).map(m=>({role:m.role,content:m.content}));const r=await fetch('/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model,messages:history.length?history:[{role:'user',content:text}],stream:true,chat_id:chatId})});if(!r.ok)throw new Error('HTTP '+r.status+': '+await r.text());const rd=r.body.getReader(),dec=new TextDecoder();let buf='';while(true){const {done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});let nl;while((nl=buf.indexOf('\n'))>=0){const line=buf.slice(0,nl).trim();buf=buf.slice(nl+1);if(!line.startsWith('data: '))continue;const p=line.slice(6);if(p==='[DONE]')continue;let j;try{j=JSON.parse(p)}catch(e){continue}if(j.error)throw new Error(j.error.message||'Bridge stream error');const d=j.choices?.[0]?.delta?.content;if(d){acc+=d;out.classList.remove('thinking');out.innerHTML=md(acc);$('scroll').scrollTop=$('scroll').scrollHeight}}}if(!acc)throw new Error('Arena returned an empty response');saveLocalMessage('assistant',acc);setStatus('Ready','ok')}catch(e){out.classList.remove('thinking');out.innerHTML='<div class="errorbox">'+escHtml(e.message||e)+'</div>';setStatus('Error','err')}finally{busy=false;$('send').disabled=false;loadThreads()}}
const input=$('input');input.addEventListener('input',()=>{input.style.height='auto';input.style.height=Math.min(input.scrollHeight,180)+'px'});input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}});
setInterval(()=>fetch('/debug-logs/data').then(r=>r.json()).then(d=>{$('signal').textContent=d.slice(-18).map(x=>x.line||x.m||'').join('\n')}).catch(()=>{}),3000);
loadThreads();openChat(chatId);
</script></body></html>'''
    return template.replace("__MODELS_JSON__", payload).replace("__DEFAULT_MODEL__", selected)


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
from fastapi import FastAPI, File, Form, Request, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.security import APIKeyHeader

app = FastAPI(title="Bridgena", version="2.0")
_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)
_dashboard_sessions: dict = {}
_recent_api_requests: dict = {}
_recent_api_requests_lock = threading.Lock()
_duplicate_notices: dict = {}


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


# ---------- pages ----------
@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return login_page()


@app.post("/login")
async def login_post(request: Request, password: str = Form("")):
    cfg = get_config()
    if password and password == cfg.get("password", "admin"):
        tok = create_session_token("admin")
        resp = RedirectResponse(url="/dashboard", status_code=303)
        resp.set_cookie("session_id", tok, httponly=True, samesite="lax", max_age=86400 * 30)
        log("OK", "dashboard login")
        return resp
    return login_page("wrong password")


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
    live = set(keeper.sessions.keys())
    rows = snapshot_rows()
    flags = _flagged_active()
    overview = {
        "metrics": {
            "pool_total": len([l for l in _pool_lines() if l.strip() and not l.startswith("#")]),
            "alive": sum(1 for r in rows if r["verdict"] == "alive"),
            "flagged": len(flags),
            "jars_total": len(jars), "jars_ok": sum(1 for j in jars if not j.get("expired")),
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
@app.get("/jars/upload", response_class=HTMLResponse)
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
    return prompts[-1] if prompts else ""


def _format_conversation_prompt(body: dict) -> str:
    """Format conversation messages into a coherent prompt with full dialogue history."""
    messages = body.get("messages") or []
    if not messages:
        return _last_openai_user_prompt(body)
    if len(messages) == 1 and isinstance(messages[0], dict) and messages[0].get("role") == "user":
        return _openai_text_content(messages[0].get("content", ""))
    lines = []
    system = _openai_text_content(body.get("system", ""))
    if system:
        lines.append("System:\n" + system)
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = (m.get("role") or "").lower()
        text = _openai_text_content(m.get("content", "")).strip()
        if not text:
            continue
        if role == "system":
            lines.append(f"System:\n{text}")
        elif role == "assistant":
            lines.append(f"Assistant:\n{text}")
        else:
            lines.append(f"User:\n{text}")
    return "\n\n".join(lines) if lines else _last_openai_user_prompt(body)


def _anthropic_prompt(body: dict) -> str:
    """Flatten Anthropic message blocks into one stateless Arena turn."""
    lines = []
    system = _openai_text_content(body.get("system", ""))
    if system:
        lines.append("System:\n" + system)
    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            continue
        text = _openai_text_content(message.get("content", ""))
        if text:
            role = "Assistant" if message.get("role") == "assistant" else "User"
            lines.append(f"{role}:\n{text}")
    return "\n\n".join(lines)


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


async def openai_stream(body: dict, keyinfo: dict):
    prompt = _format_conversation_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    model = body.get("model", "auto")
    # A caller-supplied opaque thread id preserves Arena context without storing
    # prompt or response content. One-off API calls receive a random id.
    chat_id = body.get("chat_id") or ("api-" + uuid7())

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
        content_chunks = 0
        terminal_sent = False
        outcome = "complete"
        try:
            yield chunk({"role": "assistant"})
            async for kind, payload in run_turn(chat_id, prompt, model,
                                                attachments=body.get("attachments")):
                if kind == "content":
                    acc += payload
                    content_chunks += 1
                    yield chunk({"content": payload})
                elif kind == "reasoning":
                    yield chunk({"reasoning_content": payload})
                elif kind == "error":
                    outcome = "upstream-error"
                    yield _sse({"error": {"message": payload}})
                    # New API's OpenAI-stream translator does not consider a
                    # top-level error plus [DONE] terminal by itself. Emit the
                    # ordinary terminal choice as well so downstream Claude
                    # clients always leave their generating state.
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
            yield _sse({"error": {"message": f"{type(e).__name__}: {e}"}})
            yield chunk({}, finish="stop")
            yield "data: [DONE]\n\n"
            terminal_sent = True
            return
        finally:
            if terminal_sent:
                log("INFO", f"OpenAI stream {rid[-8:]} delivered · outcome {outcome} · "
                            f"content {content_chunks} chunks/{len(acc)} chars · terminal yes")
            else:
                log("WARN", f"OpenAI stream {rid[-8:]} disconnected before terminal · outcome {outcome} · "
                            f"content {content_chunks} chunks/{len(acc)} chars")
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request):
    keyinfo = await _require_key(request)
    body = await request.json()
    prompt = _format_conversation_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    messages = body.get("messages") or []
    log("INFO", f"OpenAI request · model {str(body.get('model') or 'auto')[:80]} · "
                f"messages {len(messages) if isinstance(messages, list) else 0} · "
                f"tools {len(body.get('tools') or []) if isinstance(body.get('tools') or [], list) else 0} · "
                f"max_tokens {body.get('max_tokens') or body.get('max_completion_tokens') or 'default'} · "
                f"usage {'yes' if (body.get('stream_options') or {}).get('include_usage') else 'no'}")
    reserved, duplicate_count = _reserve_api_request(body, keyinfo, prompt)
    if not reserved:
        if duplicate_count == 1:
            log("INFO", f"duplicate API retries suppressed · model {str(body.get('model') or 'auto')[:80]} · "
                        f"content {len(prompt)} chars · window {API_DUPLICATE_WINDOW_SEC}s")
        raise HTTPException(status_code=409, detail="duplicate request suppressed; reuse the original stream")
    if not body.get("stream", True):
        out = {"id": "chatcmpl-" + uuid7()[:23], "object": "chat.completion", "created": int(time.time()),
               "model": body.get("model", "auto"), "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]}
        acc = ""
        async for kind, payload in run_turn(body.get("chat_id") or ("api-" + uuid7()), prompt,
                                            body.get("model", "auto"), attachments=body.get("attachments")):
            if kind == "content":
                acc += payload
            elif kind == "error":
                raise HTTPException(status_code=502, detail=payload)
        out["choices"][0]["message"]["content"] = acc
        return JSONResponse(out)
    return await openai_stream(body, keyinfo)


@app.post("/v1/messages")
@app.post("/messages")
async def anthropic_messages(request: Request):
    """Native Anthropic Messages surface for clients that should not traverse
    an OpenAI-to-Anthropic stream converter."""
    keyinfo = await _require_key(request)
    body = await request.json()
    prompt = _anthropic_prompt(body)
    if not prompt:
        raise HTTPException(status_code=400, detail="no user message")
    reserved, duplicate_count = _reserve_api_request(body, keyinfo, prompt)
    if not reserved:
        if duplicate_count == 1:
            log("INFO", f"duplicate Anthropic API retries suppressed · model {str(body.get('model') or 'auto')[:80]} · "
                        f"content {len(prompt)} chars · window {API_DUPLICATE_WINDOW_SEC}s")
        raise HTTPException(status_code=409, detail="duplicate request suppressed; reuse the original stream")

    model = body.get("model", "auto")
    chat_id = body.get("chat_id") or ("anthropic-" + uuid7())
    message_id = "msg_" + uuid7().replace("-", "")
    input_tokens = _rough_tokens(prompt)

    if not body.get("stream", False):
        acc = ""
        async for kind, payload in run_turn(chat_id, prompt, model,
                                            attachments=body.get("attachments")):
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
            async for kind, payload in run_turn(chat_id, prompt, model,
                                                attachments=body.get("attachments")):
                if kind in ("content", "reasoning") and isinstance(payload, str):
                    acc += payload
                    chunks += 1
                    yield _anthropic_sse("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                                  "delta": {"type": "text_delta", "text": payload}})
                elif kind == "error":
                    outcome = "upstream-error"
                    yield _anthropic_sse("error", {"type": "error", "error": {
                        "type": "api_error", "message": payload,
                    }})
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
            yield _anthropic_sse("error", {"type": "error", "error": {
                "type": "api_error", "message": f"{type(e).__name__}: {e}",
            }})
        finally:
            level = "INFO" if terminal_sent or outcome == "upstream-error" else "WARN"
            log(level, f"Anthropic stream {message_id[-8:]} delivered · outcome {outcome} · "
                       f"content {chunks} chunks/{len(acc)} chars · terminal {'yes' if terminal_sent else 'no'}")

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/v1/models")
@app.get("/models")
async def models_api():
    state = load_state()
    blocked = state.get("blocked_models", [])
    data = [{"id": model_name(m), "object": "model", "created": int(time.time()), "owned_by": "arena-bridge",
             "arena_id": m.get("id") if isinstance(m, dict) else None} for m in get_models() if model_name(m) not in blocked]
    return JSONResponse({"object": "list", "data": data})


@app.get("/v1/models/{model_id:path}")
@app.get("/models/{model_id:path}")
async def model_one(model_id: str):
    for m in get_models():
        if model_name(m) == model_id or (isinstance(m, dict) and m.get("id") == model_id):
            return JSONResponse({"id": m.get("name"), "object": "model", "owned_by": "arena-bridge"})
    raise HTTPException(status_code=404, detail="unknown model")


# ---------- pool api ----------
@app.get("/proxies/api/snapshot")
async def proxies_snapshot():
    return JSONResponse(snapshot_rows())


@app.post("/proxies/api/check")
async def proxies_check():
    loop = asyncio.get_running_loop()
    stats = await loop.run_in_executor(None, sweep_all)
    return JSONResponse(stats)


@app.post("/proxies/api/upload")
async def proxies_upload(request: Request):
    form = await request.form()
    txt = form.get("text") or ""
    return JSONResponse(upload_pool(str(txt)))


@app.post("/proxies/api/prune")
async def proxies_prune():
    return JSONResponse({"cut": prune_bad()})


@app.post("/proxies/api/remove-one")
async def proxies_remove_one(key: str = Form(...)):
    return JSONResponse({"removed": remove_one(key)})


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
    try:
        open(LOG_FILE, "w").close()
    except OSError:
        pass
    with LOG._mu:
        LOG.ring.clear()
    return JSONResponse({"ok": True})


@app.get("/healthz")
async def healthz():
    rows = snapshot_rows()
    return JSONResponse({"ok": True, "build": BUILD_STAMP, "models": len(get_models()),
                         "pool_alive": sum(1 for r in rows if r["verdict"] == "alive"),
                         "jars_ok": sum(1 for j in load_jars() if jar_has_auth(j) and not j.get("expired")),
                         "keepers_live": len(keeper.sessions)})


# ---------- misc legacy shims ----------
@app.get("/debug/raw-models")
async def raw_models():
    return JSONResponse(read_json(MODELS_RAW_DEBUG_FILE, []))


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


# ---------- jars add (cookie file / paste) ----------
@app.post("/jars/add")
async def jars_add(request: Request, name: str = Form(""), cookie_file: UploadFile = File(...)):
    g = await _page_guard(request)
    if g:
        return g
    try:
        cookies = _validate_cookies((await cookie_file.read()).decode("utf-8"))
        jar, found = _new_jar(name.strip(), cookies)
        log("OK", f"Account '{jar['name']}' added ({len(cookies)} cookies, keys: {sorted(found) or 'NONE'})")
    except Exception as e:
        log("ERROR", f"Jar upload failed: {type(e).__name__}: {e}")
    return RedirectResponse(url="/jars", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/jars/add-text")
async def jars_add_text(request: Request, name: str = Form(""), cookie_json: str = Form(...)):
    g = await _page_guard(request)
    if g:
        return g
    try:
        jar, found = _new_jar(name.strip(), _validate_cookies(cookie_json.strip()))
        log("OK", f"Account '{jar['name']}' added ({sorted(found) or 'NONE'})")
    except Exception as e:
        log("ERROR", f"Jar paste failed: {type(e).__name__}: {e}")
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


# ---------- screenshots ----------
@app.get("/screenshots")
async def list_screenshots():
    files = sorted(glob.glob("*.png"), key=os.path.getmtime, reverse=True)  # keeper writes to cwd, legacy convention
    body = "".join(f'<li><a href="/screenshots/{os.path.basename(f)}">{os.path.basename(f)}</a></li>' for f in files[:200])
    return HTMLResponse(f"<h1>Screenshots</h1><ul>{body}</ul>")


@app.get("/screenshots/{filename}")
async def screenshot_file(filename: str):
    p = os.path.basename(filename)
    if not os.path.isfile(p):
        raise HTTPException(status_code=404)
    return FileResponse(p, media_type="image/png")


# ---------- startup ----------
def jars_have_creds() -> bool:
    return any(j.get("email") and j.get("password") and j.get("enabled", True) for j in load_jars())
@asynccontextmanager
async def _lifespan(app):
    def _remove_legacy_transcripts(state):
        state.pop("chats", None)
    mutate_state(_remove_legacy_transcripts)
    def _normalize_personas(jars):
        for jar in jars:
            if jar.get("persona") not in PERSONAS:
                jar["persona"] = "ubuntu"
                jar["user_agent"] = PERSONAS["ubuntu"].ua
    mutate_jars(_normalize_personas)
    tasks = [asyncio.create_task(keeper_election_loop()),
             asyncio.create_task(periodic_model_refresher()),
             asyncio.create_task(get_initial_data())]
    if jars_have_creds():
        tasks.append(asyncio.create_task(auto_login_on_boot()))
    log("INFO", f"BRIDGENA build {BUILD_STAMP} · v2 engine · recaptcha V3/V2 protocol ON")
    yield
    for t in tasks:
        t.cancel()


app.router.lifespan_context = _lifespan  # starlette late-bind



# ================================================================
#  ENTRY — one file, uvicorn; multi-worker keeps the legacy election via state.json
# ================================================================
def _cli():
    import argparse
    ap = argparse.ArgumentParser(description="Bridgena v2")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--workers", type=int, default=int(os.environ.get("BRIDGENA_WORKERS", "1")))
    args = ap.parse_args()
    jars_count = len([j for j in load_jars() if not j.get("expired")])
    print("=" * 62)
    print("  BRIDGENA v2 — Arena Bridge (" + BUILD_STAMP + ")")
    print("=" * 62)
    print(f"  * Live Chat   : http://localhost:{args.port}/chat")
    print(f"  * Dashboard   : http://localhost:{args.port}/dashboard")
    print(f"  * OpenAI Base : http://localhost:{args.port}/v1")
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
