#!/usr/bin/env python3
"""
Probe2 — расширенный тестер VLESS / Trojan / Hysteria2.

Задачи:
  • Прямая проверка «базовой» доступности (max.ru, vk.com, wb.ru, ozon.ru).
  • Загрузка списков: сначала direct; при сбое — через кэш рабочих конфигов
    (если max+vk с direct проходят — считаем, что интернет есть, а листы режутся).
  • Кэш рабочих конфигов на диск после каждой успешной проверки.
  • Реестр probe2_registry.json: рейтинг, last_checked, next_check_at; рабочие
    чаще (по умолч. 15 мин); мёртвые — backoff (база ×2^(N−1), напр. 24ч→48→96…).
  • Рейтинг: число успешных проверок целевых сайтов + задержка (ipify).
  • Через прокси: t.me, youtube.com, instagram.com.
  • Настройки: config.yaml рядом со скриптом (или --config PATH); CLI переопределяет YAML.

"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

# ── Windows: UTF-8 + ANSI escape codes ─────────────────────────────────
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace"
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace"
    )
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

try:
    import requests
except ImportError:
    requests = None


# ── ANSI Colors ─────────────────────────────────────────────────────────
class C:
    RST = "\033[0m"
    B = "\033[1m"
    D = "\033[2m"
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    CY = "\033[96m"
    W = "\033[97m"


_print_lock = threading.Lock()
_cache_lock = threading.Lock()

_IS_WIN = sys.platform == "win32"
_SUBPROCESS_EXTRA: dict = {}
if _IS_WIN:
    _SUBPROCESS_EXTRA["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

_pending_cache_urls: List[str] = []
_pending_cache_lock = threading.Lock()

_dead_endpoints: set = set()
_dead_endpoints_lock = threading.Lock()


def _log(icon: str, color: str, msg: str):
    with _print_lock:
        print(f"  {color}{icon}{C.RST} {msg}", flush=True)


def log_info(msg: str):
    _log("•", C.CY, msg)


def log_ok(msg: str):
    _log("✓", C.G, msg)


def log_fail(msg: str):
    _log("✗", C.R, msg)


def log_warn(msg: str):
    _log("!", C.Y, msg)


def log_traceback(label: str = ""):
    with _print_lock:
        if label:
            print(f"  {C.R}✗ {label}{C.RST}", flush=True)
        for line in traceback.format_exc().splitlines():
            print(f"    {C.D}{line}{C.RST}", flush=True)


def log_sub(msg: str):
    with _print_lock:
        print(f"    {C.D}{msg}{C.RST}", flush=True)


def banner():
    print(f"""
  {C.CY}{C.B}╔════════════════════════════════════════════════════════╗
  ║            P R O B E 2  (extended)                 ║
  ╚════════════════════════════════════════════════════════╝{C.RST}
""", flush=True)


def hr():
    with _print_lock:
        print(f"  {C.D}{chr(0x2500) * 57}{C.RST}", flush=True)


# Прямая проверка «всё ли ок с точки зрения RU/доступа»
HEALTH_URLS: List[str] = [
    "https://max.ru",
    "https://vk.com",
    "https://wb.ru",
    "https://www.ozon.ru",
]

# Проверка именно через тестируемый прокси
CONTENT_PROBE_URLS: List[str] = [
    "https://t.me",
    "https://www.youtube.com",
    "https://www.instagram.com/",
]

SPEED_TEST_URL: str = "https://speed.cloudflare.com/__down?bytes=524288"
SPEED_TEST_ENABLED: bool = True

CONFIGS_SOURCE_URLS: List[str] = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_YAML = "config.yaml"
DEFAULT_CACHE_NAME = "probe2_cache.json"
DEFAULT_RESULTS_JSON = "probe2_results.json"
DEFAULT_REGISTRY_NAME = "probe2_registry.json"

REGISTRY_VERSION = 2
_registry_lock = threading.Lock()

# Подставляются из config.yaml в main(); функции читают .get с запасным дефолтом
_ACTIVE_TIMEOUTS: Dict[str, float] = {
    "direct_health_sec": 10.0,
    "subscription_fetch_direct_sec": 35.0,
    "subscription_fetch_via_proxy_sec": 45.0,
    "singbox_startup_sec": 14.0,
    "probe_extended_sec": 22.0,
    "content_probe_per_url_sec": 12.0,
    "ipify_sec": 4.0,
    "speed_test_sec": 10.0,
    "webhook_post_sec": 25.0,
}


def _timeout(key: str, default: float) -> float:
    try:
        return float(_ACTIVE_TIMEOUTS.get(key, default))
    except (TypeError, ValueError):
        return default


def default_config_path() -> str:
    return os.path.join(SCRIPT_DIR, DEFAULT_CONFIG_YAML)


def strip_config_argv(argv: List[str]) -> Tuple[Optional[str], List[str]]:
    """Выделяет --config PATH из argv; остальное отдаёт в argparse."""
    out = list(argv)
    cfg_path: Optional[str] = None
    i = 0
    while i < len(out):
        if out[i] == "--config" and i + 1 < len(out):
            cfg_path = out[i + 1]
            del out[i : i + 2]
            continue
        if out[i].startswith("--config="):
            cfg_path = out[i].split("=", 1)[1]
            del out[i]
            continue
        i += 1
    return cfg_path, out


def load_probe2_yaml(path: str) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    try:
        import yaml as _yaml
    except ImportError:
        print(
            "Установите PyYAML: pip install pyyaml (нужен для config.yaml)",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = _yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"config.yaml: {e}", file=sys.stderr)
        sys.exit(1)


def apply_urls_from_yaml(ycfg: dict) -> None:
    global HEALTH_URLS, CONTENT_PROBE_URLS, CONFIGS_SOURCE_URLS
    global SPEED_TEST_URL, SPEED_TEST_ENABLED
    u = ycfg.get("urls") or {}
    h = u.get("health")
    if isinstance(h, list) and h:
        HEALTH_URLS = [str(x) for x in h if x]
    c = u.get("content_probe")
    if isinstance(c, list) and c:
        CONTENT_PROBE_URLS = [str(x) for x in c if x]
    s = u.get("subscription_sources")
    if isinstance(s, list) and s:
        CONFIGS_SOURCE_URLS = [str(x) for x in s if x]
    st = ycfg.get("speed_test") or {}
    if st.get("url"):
        SPEED_TEST_URL = str(st["url"])
    if "enabled" in st:
        SPEED_TEST_ENABLED = bool(st["enabled"])


def apply_timeouts_from_yaml(ycfg: dict) -> None:
    global _ACTIVE_TIMEOUTS
    base = dict(_ACTIVE_TIMEOUTS)
    raw = ycfg.get("timeouts") or {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if v is None:
                continue
            try:
                base[str(k)] = float(v)
            except (TypeError, ValueError):
                pass
    _ACTIVE_TIMEOUTS = base


def _yaml_str_or_none(v) -> Optional[str]:
    """YAML часто даёт int/float там, где нужна строка (например api_key: 1234)."""
    if v is None:
        return None
    return str(v).strip() or None


def yaml_to_parser_defaults(ycfg: dict) -> dict:
    """Значения по умолчанию для argparse (до переопределения флагами CLI)."""
    ycfg = ycfg or {}
    probe = ycfg.get("probe") or {}
    reg = ycfg.get("registry") or {}
    paths = ycfg.get("paths") or {}
    out = ycfg.get("output") or {}
    wh = ycfg.get("webhook") or {}
    fe = ycfg.get("fetch") or {}
    sb = ycfg.get("singbox") or {}
    return {
        "workers": int(probe.get("workers", 32)),
        "max_ping": int(probe.get("max_ping_ms", 0)),
        "icmp": bool(probe.get("icmp", False)),
        "json": bool(probe.get("json_stdout", False)),
        "cache": paths.get("cache"),
        "wait_fail": float(fe.get("wait_fail_sec", 0.0)),
        "post_results": wh.get("url"),
        "results_json": paths.get("results_json"),
        "no_singbox_download": not bool(sb.get("auto_download", True)),
        "no_registry": not bool(reg.get("enabled", True)),
        "registry": reg.get("path"),
        "interval_ok": float(reg.get("interval_ok_sec", 900.0)),
        "interval_dead": float(reg.get("interval_dead_sec", 86400.0)),
        "interval_dead_max": float(
            reg.get("interval_dead_max_sec", 86400.0 * 30)
        ),
        "dead_backoff_mult": float(reg.get("dead_backoff_mult", 2.0)),
        "no_dead_backoff": not bool(reg.get("dead_backoff", True)),
        "no_smart_schedule": not bool(reg.get("smart_schedule", True)),
        "result_txt": str(out.get("working_list_file", "result2.txt")),
        "webhook_timeout": float(wh.get("timeout_sec", 25.0)),
        "report_url": (ycfg.get("report") or {}).get("url"),
        "report_provider_id": (ycfg.get("report") or {}).get("provider_id"),
        # YAML может распарсить числовой ключ как int — HTTP-заголовки только str/bytes
        "report_api_key": _yaml_str_or_none(
            (ycfg.get("report") or {}).get("api_key")
        ),
        "loop": int(probe.get("loop_sec", 0)),
    }


# ═══════════════════════════════════════════════════════════════════════
#  Parsing (как в probe_tester)
# ═══════════════════════════════════════════════════════════════════════

def cfg_unique_key(cfg: dict) -> tuple:
    uid = cfg.get("uuid") or cfg.get("password") or ""
    return (cfg["protocol"], uid, cfg["host"], cfg["port"])


def unique_configs(configs: List[dict]) -> List[dict]:
    seen: set = set()
    out: List[dict] = []
    for cfg in configs:
        key = cfg_unique_key(cfg)
        if key not in seen:
            seen.add(key)
            out.append(cfg)
    return out


def _parse_proto_url(url: str, scheme: str, cred_key: str) -> Optional[dict]:
    url = url.strip()
    if not url.lower().startswith(f"{scheme}://"):
        return None
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != scheme:
            return None
        if "@" not in parsed.netloc:
            return None
        cred, host_port = parsed.netloc.split("@", 1)
        cred = urllib.parse.unquote(cred)
        if ":" in host_port:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = host_port, 443
        params = urllib.parse.parse_qs(parsed.query)
        name = urllib.parse.unquote(parsed.fragment or "")
        result = {
            "protocol": scheme,
            "host": host,
            "port": port,
            "params": params,
            "name": name or host,
            "_raw_url": url,
        }
        result[cred_key] = cred
        return result
    except Exception:
        return None


def parse_vless(url: str) -> Optional[dict]:
    return _parse_proto_url(url, "vless", "uuid")


def parse_trojan(url: str) -> Optional[dict]:
    return _parse_proto_url(url, "trojan", "password")


def parse_hysteria2(url: str) -> Optional[dict]:
    return _parse_proto_url(url, "hysteria2", "password")


def parse_config(url: str) -> Optional[dict]:
    for parser in (parse_vless, parse_trojan, parse_hysteria2):
        cfg = parser(url.strip())
        if cfg:
            return cfg
    return None


def parse_subscription(text: str) -> List[dict]:
    text = text.strip()
    if re.match(r"^[A-Za-z0-9+/=]+$", text.replace("\n", "")):
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        except Exception:
            lines = text.splitlines()
    else:
        lines = [l.strip() for l in text.splitlines() if l.strip()]

    configs = []
    for line in lines:
        if line.startswith("http"):
            continue
        cfg = parse_config(line)
        if cfg:
            configs.append(cfg)
    return configs


# ═══════════════════════════════════════════════════════════════════════
#  Network / geo
# ═══════════════════════════════════════════════════════════════════════

def _get_param(params: dict, key: str, default: str = "") -> str:
    v = params.get(key, [default])
    return (v[0] if v else default) or default


def country_code_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


_COUNTRY_NAMES: Dict[str, str] = {
    "DE": "Germany", "NL": "Netherlands", "FI": "Finland", "SE": "Sweden",
    "US": "USA", "GB": "UK", "FR": "France", "RU": "Russia",
    "CA": "Canada", "AU": "Australia", "JP": "Japan", "SG": "Singapore",
    "KR": "Korea", "IN": "India", "BR": "Brazil", "TR": "Turkey",
    "PL": "Poland", "CZ": "Czechia", "AT": "Austria", "CH": "Switzerland",
    "IT": "Italy", "ES": "Spain", "UA": "Ukraine", "KZ": "Kazakhstan",
    "BG": "Bulgaria", "RO": "Romania", "HU": "Hungary", "IE": "Ireland",
    "NO": "Norway", "DK": "Denmark", "LT": "Lithuania", "LV": "Latvia",
    "EE": "Estonia", "MD": "Moldova", "GE": "Georgia", "AZ": "Azerbaijan",
    "AM": "Armenia", "BY": "Belarus", "HK": "Hong Kong", "TW": "Taiwan",
    "LU": "Luxembourg", "BE": "Belgium", "PT": "Portugal", "GR": "Greece",
    "IL": "Israel", "AE": "UAE", "ZA": "South Africa", "AR": "Argentina",
    "MX": "Mexico", "CL": "Chile", "CO": "Colombia", "ID": "Indonesia",
    "TH": "Thailand", "VN": "Vietnam", "PH": "Philippines", "MY": "Malaysia",
}


def _pretty_config_name(
    r: dict,
    index: int,
    total: int,
    brand: str = "VPN",
) -> str:
    in_geo = r.get("input_geo") or {}
    out_geo = r.get("output_geo") or {}
    in_cc = in_geo.get("countryCode", "")
    out_cc = out_geo.get("countryCode", "")

    in_flag = country_code_to_flag(in_cc)
    out_flag = country_code_to_flag(out_cc)

    country = (
        _COUNTRY_NAMES.get(out_cc, out_geo.get("country", ""))
        or _COUNTRY_NAMES.get(in_cc, in_geo.get("country", ""))
    )

    if in_cc and out_cc and in_cc != out_cc:
        flags = f"{in_flag}\u2192{out_flag}"
    elif out_flag:
        flags = out_flag
    elif in_flag:
        flags = in_flag
    else:
        flags = ""

    speed = r.get("speed_mbps")
    spd_tag = f" {speed:.0f}M" if speed and speed >= 1 else ""

    num = f"#{index:0{len(str(total))}d}"

    parts = [p for p in (flags, country, f"{brand} {num}{spd_tag}") if p]
    return " ".join(parts)


_dns_cache: Dict[str, Optional[str]] = {}
_dns_cache_lock = threading.Lock()


def resolve_host(host: str) -> Optional[str]:
    with _dns_cache_lock:
        if host in _dns_cache:
            return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = None
    with _dns_cache_lock:
        _dns_cache[host] = ip
    return ip


_geo_cache: Dict[str, dict] = {}
_geo_cache_lock = threading.Lock()


def get_geo(ip: str) -> dict:
    if not requests:
        return {}
    with _geo_cache_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp",
            timeout=4,
        )
        data = r.json() if r.status_code == 200 else {}
    except Exception:
        data = {}
    with _geo_cache_lock:
        _geo_cache[ip] = data
    return data


def run_icmp_ping(host: str, count: int = 3) -> Optional[float]:
    import platform
    ip = resolve_host(host) or host
    flag = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        out = subprocess.run(
            ["ping", flag, str(count), ip],
            capture_output=True, text=True, timeout=10,
            **_SUBPROCESS_EXTRA,
        )
        if out.returncode == 0 and out.stdout:
            ms = re.findall(r"(\d+\.?\d*)\s*ms", out.stdout)
            if ms:
                return round(float(ms[-1]), 1)
    except Exception:
        pass
    return None


def http_probe_ok(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return False
    return resp.status_code < 500


def _check_one_health(url: str, timeout: float) -> Tuple[str, bool]:
    try:
        r = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "probe2/1.0"},
        )
        return url, http_probe_ok(r)
    except Exception:
        return url, False


def check_direct_health(
    urls: List[str], timeout: Optional[float] = None,
) -> Dict[str, bool]:
    """Прямой HTTP(S) без прокси. OK = ответ получен и status < 500. Параллельно."""
    if timeout is None:
        timeout = _timeout("direct_health_sec", 10.0)
    if not requests:
        return {u: False for u in urls}
    out: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        futs = {pool.submit(_check_one_health, u, timeout): u for u in urls}
        for fut in as_completed(futs):
            url, ok = fut.result()
            out[url] = ok
    return out


def baseline_internet_ok(health: Dict[str, bool]) -> bool:
    """Если max и vk с direct открываются — считаем, что есть «базовый» выход."""
    return health.get("https://max.ru", False) and health.get(
        "https://vk.com", False
    )


# ═══════════════════════════════════════════════════════════════════════
#  Cache
# ═══════════════════════════════════════════════════════════════════════

def cache_path(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    return os.path.join(SCRIPT_DIR, DEFAULT_CACHE_NAME)


def load_cache_entries(path: str) -> List[str]:
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        urls = data.get("raw_urls") or data.get("urls") or []
        if isinstance(urls, list):
            return [str(x) for x in urls if x]
    except Exception:
        pass
    return []


def save_cache_merge(path: str, new_urls: List[str]) -> None:
    existing = set(load_cache_entries(path))
    for u in new_urls:
        if u:
            existing.add(u)
    payload = {
        "version": 1,
        "updated": time.time(),
        "raw_urls": sorted(existing),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        log_traceback(f"save_cache_merge({path})")


def append_cache_raw_url(path: str, raw_url: str) -> None:
    if not raw_url:
        return
    with _pending_cache_lock:
        _pending_cache_urls.append(raw_url)


def flush_pending_cache(path: str) -> None:
    with _pending_cache_lock:
        if not _pending_cache_urls:
            return
        batch = list(_pending_cache_urls)
        _pending_cache_urls.clear()
    with _cache_lock:
        save_cache_merge(path, batch)


def cache_to_configs(path: str) -> List[dict]:
    cfgs: List[dict] = []
    for u in load_cache_entries(path):
        c = parse_config(u)
        if c:
            cfgs.append(c)
    return unique_configs(cfgs)


# ═══════════════════════════════════════════════════════════════════════
#  Registry (локальный рейтинг + умное расписание проверок)
# ═══════════════════════════════════════════════════════════════════════

def registry_path(explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit
    return os.path.join(SCRIPT_DIR, DEFAULT_REGISTRY_NAME)


def config_registry_key(cfg: dict) -> str:
    return "|".join(str(x) for x in cfg_unique_key(cfg))


def load_registry(path: str) -> dict:
    if not os.path.isfile(path):
        return {"version": REGISTRY_VERSION, "updated": 0.0, "entries": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ent = data.get("entries")
        if not isinstance(ent, dict):
            ent = {}
        return {
            "version": int(data.get("version", REGISTRY_VERSION)),
            "updated": float(data.get("updated", 0)),
            "entries": ent,
        }
    except Exception:
        log_traceback(f"load_registry({path})")
        return {"version": REGISTRY_VERSION, "updated": 0.0, "entries": {}}


def save_registry(path: str, registry: dict) -> None:
    payload = {
        "version": REGISTRY_VERSION,
        "updated": time.time(),
        "entries": registry.get("entries") or {},
    }
    try:
        with _registry_lock:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        log_traceback(f"save_registry({path})")


def is_config_due(
    cfg: dict, entries: dict, now: float, force_all: bool,
) -> bool:
    if force_all:
        return True
    key = config_registry_key(cfg)
    row = entries.get(key)
    if not isinstance(row, dict):
        return True
    nxt = row.get("next_check_at")
    try:
        return float(nxt) <= now
    except (TypeError, ValueError):
        return True


def split_configs_by_schedule(
    candidates: List[dict],
    registry: dict,
    now: float,
    force_all: bool,
) -> Tuple[List[Tuple[int, dict]], int]:
    """Возвращает список (индекс, cfg) к проверке сейчас и число пропущенных."""
    entries = registry.get("entries") or {}
    to_test: List[Tuple[int, dict]] = []
    skipped = 0
    for i, cfg in enumerate(candidates):
        if is_config_due(cfg, entries, now, force_all):
            to_test.append((i, cfg))
        else:
            skipped += 1
    return to_test, skipped


def registry_entry_from_result(
    r: dict,
    now: float,
    interval_ok: float,
    interval_dead: float,
    prev_entry: Optional[dict] = None,
    dead_backoff: bool = True,
    interval_dead_max: float = 86400 * 30,
    dead_backoff_multiplier: float = 2.0,
) -> dict:
    ok = bool(r.get("proxy_ok"))
    cfg = r["config"]
    raw = cfg.get("_raw_url") or config_to_url(cfg) or ""
    probes = r.get("content_probes") or {}
    if isinstance(probes, dict):
        ser_probes = {str(k): bool(v) for k, v in probes.items()}
    else:
        ser_probes = {}

    if ok:
        streak = 0
        nxt = now + interval_ok
        dead_delay_sec: Optional[float] = None
    else:
        prev = prev_entry if isinstance(prev_entry, dict) else {}
        prev_streak = int(prev.get("consecutive_failures", 0) or 0)
        was_dead = bool(prev and not prev.get("last_proxy_ok"))
        streak = (prev_streak + 1) if was_dead else 1
        bm = max(1.0, float(dead_backoff_multiplier))
        mult = bm ** max(0, streak - 1)
        if dead_backoff:
            delay = min(interval_dead * mult, max(interval_dead, interval_dead_max))
            dead_delay_sec = delay
            nxt = now + delay
        else:
            dead_delay_sec = interval_dead
            nxt = now + interval_dead

    return {
        "raw_url": raw,
        "last_proxy_ok": ok,
        "last_rating": r.get("rating"),
        "last_tcp_ms": r.get("tcp_ms"),
        "last_speed_mbps": r.get("speed_mbps"),
        "last_content_hits": int(r.get("content_hits", 0)),
        "last_content_probes": ser_probes,
        "last_checked": now,
        "next_check_at": nxt,
        "consecutive_failures": streak,
        "dead_next_delay_sec": dead_delay_sec,
        "last_error": (r.get("error") or "") or "",
        "last_output_ip": r.get("output_ip"),
        "last_input_geo": r.get("input_geo") or {},
        "last_output_geo": r.get("output_geo") or {},
    }


def apply_results_to_registry(
    registry: dict,
    results: List[dict],
    now: float,
    interval_ok: float,
    interval_dead: float,
    dead_backoff: bool = True,
    interval_dead_max: float = 86400 * 30,
    dead_backoff_multiplier: float = 2.0,
) -> None:
    entries = registry.setdefault("entries", {})
    for r in results:
        if r.get("from_registry_cache"):
            continue
        cfg = r.get("config")
        if not cfg:
            continue
        key = config_registry_key(cfg)
        prev = entries.get(key)
        prev_entry = prev if isinstance(prev, dict) else None
        entries[key] = registry_entry_from_result(
            r,
            now,
            interval_ok,
            interval_dead,
            prev_entry=prev_entry,
            dead_backoff=dead_backoff,
            interval_dead_max=interval_dead_max,
            dead_backoff_multiplier=dead_backoff_multiplier,
        )


def result_from_registry_entry(cfg: dict, entry: dict) -> dict:
    """Собирает результат для UI/result2 из последней записи реестра."""
    raw_url = entry.get("raw_url") or cfg.get("_raw_url") or config_to_url(cfg)
    cfg_m = cfg
    if raw_url and not cfg.get("_raw_url"):
        cfg_m = dict(cfg)
        cfg_m["_raw_url"] = raw_url
    return {
        "config": cfg_m,
        "input_ip": resolve_host(cfg_m["host"]) or cfg_m["host"],
        "input_geo": entry.get("last_input_geo") or {},
        "output_ip": entry.get("last_output_ip"),
        "output_geo": entry.get("last_output_geo") or {},
        "ping_ms": entry.get("last_tcp_ms"),
        "tcp_ms": entry.get("last_tcp_ms"),
        "proxy_ok": bool(entry.get("last_proxy_ok")),
        "error": entry.get("last_error") or None,
        "content_probes": entry.get("last_content_probes") or {},
        "content_hits": int(entry.get("last_content_hits", 0)),
        "speed_mbps": entry.get("last_speed_mbps"),
        "rating": entry.get("last_rating"),
        "from_registry_cache": True,
    }


def fill_skipped_results_from_registry(
    candidates: List[dict],
    registry: dict,
    tested_indices: set,
) -> List[Optional[dict]]:
    """Длина len(candidates); на пропущенных индексах — снимок из реестра или заглушка."""
    entries = registry.get("entries") or {}
    out: List[Optional[dict]] = [None] * len(candidates)
    for i, cfg in enumerate(candidates):
        if i in tested_indices:
            continue
        key = config_registry_key(cfg)
        row = entries.get(key)
        if isinstance(row, dict) and row.get("last_checked"):
            out[i] = result_from_registry_entry(cfg, row)
        else:
            out[i] = {
                "config": cfg,
                "input_ip": resolve_host(cfg["host"]) or cfg["host"],
                "input_geo": {},
                "output_ip": None,
                "output_geo": {},
                "ping_ms": None,
                "tcp_ms": None,
                "proxy_ok": False,
                "error": "нет данных в реестре",
                "content_probes": {},
                "content_hits": 0,
                "speed_mbps": None,
                "rating": None,
                "from_registry_cache": True,
            }
    return out


# ═══════════════════════════════════════════════════════════════════════
#  sing-box
# ═══════════════════════════════════════════════════════════════════════

_SINGBOX_AUTO_DOWNLOAD = True
_SINGBOX_FETCH_QUIET = False
_singbox_path_cached: Optional[str] = None


def set_singbox_auto_download(enabled: bool) -> None:
    global _SINGBOX_AUTO_DOWNLOAD
    _SINGBOX_AUTO_DOWNLOAD = enabled


def set_singbox_fetch_quiet(quiet: bool) -> None:
    global _SINGBOX_FETCH_QUIET
    _SINGBOX_FETCH_QUIET = quiet


def _ensure_executable(path: str) -> bool:
    """Try to make *path* executable; return True if it already is or was fixed."""
    if os.access(path, os.X_OK):
        return True
    try:
        os.chmod(path, os.stat(path).st_mode | 0o111)
        return os.access(path, os.X_OK)
    except OSError:
        return False


def find_singbox() -> Optional[str]:
    global _singbox_path_cached
    if _singbox_path_cached is not None:
        return _singbox_path_cached
    name = "sing-box.exe" if sys.platform == "win32" else "sing-box"
    for candidate in ("sing-box", name):
        if shutil.which(candidate):
            _singbox_path_cached = candidate
            return candidate
    script_dir = SCRIPT_DIR
    for d in (script_dir, os.path.join(script_dir, "bin")):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            if _IS_WIN or _ensure_executable(p):
                _singbox_path_cached = p
                return p
            log_warn(
                f"sing-box найден ({p}), но нет прав на запуск — "
                f"выполните: chmod +x \"{p}\""
            )
    if _SINGBOX_AUTO_DOWNLOAD:
        try:
            import singbox_download as _sbd
            got = _sbd.ensure_singbox(script_dir, quiet=_SINGBOX_FETCH_QUIET)
            if got and os.path.isfile(got):
                if _IS_WIN or _ensure_executable(got):
                    _singbox_path_cached = got
                    return got
                log_warn(
                    f"sing-box скачан ({got}), но chmod не удался — "
                    f"выполните: chmod +x \"{got}\""
                )
            elif got is None and not _SINGBOX_FETCH_QUIET:
                log_fail("sing-box: автозагрузка не удалась (см. выше)")
        except Exception:
            if not _SINGBOX_FETCH_QUIET:
                log_traceback("sing-box: ошибка автозагрузки")
    return None


def config_to_url(cfg: dict, fragment: str = "") -> str:
    params = cfg.get("params", {})
    host, port = cfg["host"], cfg["port"]
    query_pairs = []
    for k in sorted(params):
        vals = params[k]
        if vals and str(vals[0]):
            query_pairs.append((k, vals[0]))
    query = urllib.parse.urlencode(query_pairs, safe="") if query_pairs else ""
    frag = urllib.parse.quote(fragment or cfg.get("name") or host, safe="")
    if cfg["protocol"] == "vless":
        netloc = f"{cfg['uuid']}@{host}:{port}"
    elif cfg["protocol"] in ("trojan", "hysteria2"):
        pw = urllib.parse.quote(cfg["password"], safe="")
        netloc = f"{pw}@{host}:{port}"
    else:
        return ""
    url = f"{cfg['protocol']}://{netloc}"
    if query:
        url += "?" + query
    if frag:
        url += "#" + frag
    return url


def cfg_to_singbox_outbound(cfg: dict) -> Optional[dict]:
    params = cfg.get("params", {})
    host, port = cfg["host"], cfg["port"]
    transport_type = _get_param(params, "type", "tcp").lower()
    sni = _get_param(params, "sni") or _get_param(params, "host") or host
    insecure = (
        _get_param(params, "insecure", "0") in ("1", "true")
        or _get_param(params, "allowInsecure", "0") in ("1", "true")
    )
    path = urllib.parse.unquote(_get_param(params, "path", "/"))
    ws_host = _get_param(params, "host") or host
    fp = _get_param(params, "fp", "chrome")
    alpn_raw = _get_param(params, "alpn", "h2,http/1.1")
    alpn = (
        [x.strip() for x in alpn_raw.split(",") if x.strip()]
        if alpn_raw else ["h2", "http/1.1"]
    )
    security = _get_param(params, "security", "tls").lower()
    tls_enabled = cfg["protocol"] == "hysteria2" or security in ("tls", "reality")
    tls_cfg = {
        "enabled": tls_enabled,
        "server_name": sni,
        "insecure": insecure,
        "alpn": alpn,
    }
    if fp:
        tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        pbk = _get_param(params, "pbk")
        sid = _get_param(params, "sid")
        if pbk:
            tls_cfg["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": sid or "0123456789abcdef",
            }
    transport: dict = {}
    if transport_type == "ws":
        transport = {
            "type": "ws",
            "path": path or "/",
            "headers": {"Host": ws_host},
        }
    elif transport_type == "grpc":
        transport = {
            "type": "grpc",
            "service_name": _get_param(params, "serviceName", "") or "grpc",
        }
    if cfg["protocol"] == "vless":
        out = {
            "type": "vless", "tag": "proxy",
            "server": host, "server_port": port,
            "uuid": cfg["uuid"], "tls": tls_cfg,
        }
        flow = _get_param(params, "flow")
        if flow:
            out["flow"] = flow
        if transport:
            out["transport"] = transport
        return out
    if cfg["protocol"] == "trojan":
        out = {
            "type": "trojan", "tag": "proxy",
            "server": host, "server_port": port,
            "password": cfg["password"], "tls": tls_cfg,
        }
        if transport:
            out["transport"] = transport
        return out
    if cfg["protocol"] == "hysteria2":
        return {
            "type": "hysteria2", "tag": "proxy",
            "server": host, "server_port": port,
            "password": cfg["password"], "tls": tls_cfg,
        }
    return None


def _safe_mkdtemp() -> str:
    """Create a temp dir that works on regular Linux, Kali, and Termux."""
    prefix = os.environ.get("PREFIX", "")
    if "com.termux" in prefix:
        termux_tmp = os.path.join(prefix, "tmp")
        if os.path.isdir(termux_tmp) and os.access(termux_tmp, os.W_OK):
            return tempfile.mkdtemp(dir=termux_tmp)
    return tempfile.mkdtemp()


_port_lock = threading.Lock()
_port_counter = 21000


def _next_port() -> int:
    global _port_counter
    with _port_lock:
        _port_counter += 1
        if _port_counter > 60000:
            _port_counter = 21000
        return _port_counter


def _build_sb_config(proxy_port: int, outbound: dict) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed", "tag": "in",
            "listen": "127.0.0.1", "listen_port": proxy_port,
        }],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"outbound": "proxy", "protocol": "tcp"}],
            "final": "proxy",
        },
    }


@contextmanager
def singbox_proxy_session(
    cfg: dict, startup_timeout: float = 12.0,
) -> Iterator[Tuple[subprocess.Popen, str]]:
    singbox = find_singbox()
    if not singbox:
        raise RuntimeError("sing-box not found")
    outbound = cfg_to_singbox_outbound(cfg)
    if not outbound:
        raise RuntimeError("bad config")
    proxy_port = _next_port()
    tmpdir = _safe_mkdtemp()
    config_path = os.path.join(tmpdir, "config.json")
    proc: Optional[subprocess.Popen] = None
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(_build_sb_config(proxy_port, outbound), f, separators=(",", ":"))
        try:
            proc = subprocess.Popen(
                [singbox, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=tmpdir,
                **_SUBPROCESS_EXTRA,
            )
        except PermissionError:
            raise RuntimeError(
                f"Permission denied: нет прав на запуск sing-box "
                f"({singbox}). Выполните: chmod +x \"{singbox}\""
            )
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        deadline = time.monotonic() + startup_timeout
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = ""
                if proc.stderr:
                    err = proc.stderr.read().decode("utf-8", errors="ignore")
                raise RuntimeError(err[:300].strip() or "sing-box exited")
            try:
                r = requests.get(
                    "https://api.ipify.org",
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=_timeout("ipify_sec", 4.0),
                )
                if r.status_code == 200 and r.text.strip():
                    ready = True
                    break
            except Exception:
                pass
            time.sleep(0.1)
        if not ready:
            raise RuntimeError("proxy startup timeout")
        yield proc, proxy_url
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(tmpdir, ignore_errors=True)


def fetch_url_text_direct(
    url: str, timeout: Optional[float] = None,
) -> Optional[str]:
    if timeout is None:
        timeout = _timeout("subscription_fetch_direct_sec", 35.0)
    if not requests:
        return None
    try:
        r = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "probe2/1.0"},
        )
        if r.status_code == 200 and r.text:
            return r.text
    except Exception:
        pass
    return None


def fetch_url_text_via_cfg(
    cfg: dict, url: str, timeout: Optional[float] = None,
) -> Optional[str]:
    if timeout is None:
        timeout = _timeout("subscription_fetch_via_proxy_sec", 45.0)
    if not requests:
        return None
    try:
        st = _timeout("singbox_startup_sec", 14.0)
        with singbox_proxy_session(cfg, startup_timeout=st) as (_p, proxy_url):
            r = requests.get(
                url, timeout=timeout, allow_redirects=True,
                proxies={"http": proxy_url, "https": proxy_url},
                headers={"User-Agent": "probe2/1.0"},
            )
            if r.status_code == 200 and r.text:
                return r.text
    except Exception:
        pass
    return None


def smart_fetch_subscription(
    url: str,
    cache_cfgs: List[dict],
    health: Dict[str, bool],
    wait_on_total_fail: float = 0.0,
) -> Tuple[Optional[str], str]:
    """
    Возвращает (text, mode): mode in ('direct', 'proxy_cache', 'fail').
    Если direct упал, но max+vk ок — перебираем кэш-конфиги.
    Если совсем ничего — опциональная пауза wait_on_total_fail.
    """
    text = fetch_url_text_direct(url)
    if text:
        return text, "direct"
    if not baseline_internet_ok(health) or not cache_cfgs:
        if wait_on_total_fail > 0:
            log_warn(
                f"Пауза {wait_on_total_fail:.0f} с "
                f"(нет direct-листа / "
                f"нет базы max+vk)"
            )
            time.sleep(wait_on_total_fail)
        return None, "fail"
    for i, c in enumerate(cache_cfgs):
        log_sub(f"proxy fetch [{i + 1}/{len(cache_cfgs)}] {url[:60]}...")
        text = fetch_url_text_via_cfg(c, url)
        if text:
            return text, "proxy_cache"
    if wait_on_total_fail > 0:
        log_warn(
            f"Пауза {wait_on_total_fail:.0f} с "
            f"(все попытки "
            f"загрузки провалились)"
        )
        time.sleep(wait_on_total_fail)
    return None, "fail"


def measure_download_speed(
    proxy_url: str,
    session: Optional[requests.Session] = None,
    url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> Optional[float]:
    """Download a payload through proxy and return speed in Mbps, or None on failure.
    Timer starts AFTER headers received (before body) to measure pure transfer rate."""
    if not requests or not SPEED_TEST_ENABLED:
        return None
    if url is None:
        url = SPEED_TEST_URL
    if timeout is None:
        timeout = _timeout("speed_test_sec", 10.0)
    proxies = {"http": proxy_url, "https": proxy_url}
    requester = session or requests
    try:
        r = requester.get(
            url, timeout=timeout, proxies=proxies,
            headers={"User-Agent": "probe2/1.0"},
            stream=True,
        )
        if r.status_code != 200:
            return None
        total_bytes = 0
        start = time.perf_counter()
        for chunk in r.iter_content(chunk_size=32768):
            total_bytes += len(chunk)
        elapsed = time.perf_counter() - start
        if elapsed <= 0 or total_bytes == 0:
            return None
        return round(total_bytes * 8 / elapsed / 1_000_000, 2)
    except Exception:
        return None


def _probe_one_content(
    url: str, proxies: dict, per_url_timeout: float,
) -> Tuple[str, bool]:
    try:
        r = requests.get(
            url, timeout=per_url_timeout, allow_redirects=True,
            proxies=proxies,
            headers={"User-Agent": "Mozilla/5.0 probe2"},
        )
        return url, http_probe_ok(r)
    except Exception:
        return url, False


def probe_content_through_proxy(
    proxy_url: str, urls: List[str], per_url_timeout: Optional[float] = None,
) -> Dict[str, bool]:
    if per_url_timeout is None:
        per_url_timeout = _timeout("content_probe_per_url_sec", 12.0)
    proxies = {"http": proxy_url, "https": proxy_url}
    out: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        futs = {
            pool.submit(_probe_one_content, u, proxies, per_url_timeout): u
            for u in urls
        }
        for fut in as_completed(futs):
            url, ok = fut.result()
            out[url] = ok
    return out


def test_via_proxy_extended(
    cfg: dict,
    timeout: Optional[float] = None,
    content_urls: Optional[List[str]] = None,
) -> Tuple[
    Optional[str],
    Optional[float],
    Optional[str],
    Dict[str, bool],
    int,
    Optional[float],
]:
    """
    exit_ip, tcp_ms (ipify), err, probe_map, success_count, speed_mbps
    """
    if timeout is None:
        timeout = _timeout("probe_extended_sec", 22.0)
    content_urls = content_urls or CONTENT_PROBE_URLS
    singbox = find_singbox()
    if not singbox:
        return None, None, "sing-box not found", {}, 0, None
    outbound = cfg_to_singbox_outbound(cfg)
    if not outbound:
        return None, None, "bad config", {}, 0, None
    proxy_port = _next_port()
    sb_config = _build_sb_config(proxy_port, outbound)
    tmpdir = _safe_mkdtemp()
    config_path = os.path.join(tmpdir, "config.json")
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(sb_config, f, separators=(",", ":"))
        try:
            proc = subprocess.Popen(
                [singbox, "run", "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                cwd=tmpdir,
                **_SUBPROCESS_EXTRA,
            )
        except PermissionError:
            return (
                None, None,
                f"Permission denied: chmod +x \"{singbox}\"",
                {}, 0, None,
            )
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        proxies_dict = {"http": proxy_url, "https": proxy_url}
        exit_ip = None
        tcp_ms = None
        err_msg = None
        probes: Dict[str, bool] = {u: False for u in content_urls}
        deadline = time.monotonic() + timeout

        sess = requests.Session()
        sess.proxies.update(proxies_dict)
        sess.headers["User-Agent"] = "probe2/1.0"
        ipify_timeout = _timeout("ipify_sec", 4.0)

        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr = (
                    proc.stderr.read().decode("utf-8", errors="ignore")
                    if proc.stderr else ""
                )
                err_msg = stderr[:200].strip() or "sing-box exited"
                break
            try:
                r = sess.get("https://api.ipify.org", timeout=ipify_timeout)
                if r.status_code == 200:
                    exit_ip = r.text.strip()
                break
            except Exception:
                pass
            time.sleep(0.1)

        if exit_ip:
            try:
                start = time.perf_counter()
                r2 = sess.get("https://api.ipify.org", timeout=ipify_timeout)
                tcp_ms = round((time.perf_counter() - start) * 1000, 1)
            except Exception:
                pass

        if err_msg is None and exit_ip is None and proc.poll() is None:
            err_msg = "timeout"

        speed_mbps: Optional[float] = None
        if exit_ip:
            probes = probe_content_through_proxy(proxy_url, content_urls)
            speed_mbps = measure_download_speed(proxy_url, session=sess)

        sess.close()
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass

        hits = sum(1 for v in probes.values() if v)
        return exit_ip, tcp_ms, err_msg, probes, hits, speed_mbps
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def compute_rating(
    hits: int,
    tcp_ms: Optional[float],
    speed_mbps: Optional[float] = None,
) -> float:
    """Выше лучше: больше успешных сайтов, выше скорость, ниже задержка."""
    ms = tcp_ms if tcp_ms is not None else 9999.0
    spd = speed_mbps if speed_mbps is not None else 0.0
    return float(hits) * 10000.0 + spd * 100.0 - ms


def _fmt_ping(ms) -> str:
    if ms is None:
        return f"{C.D}     ---{C.RST}"
    txt = f"{ms:>6.1f}ms"
    if ms < 100:
        return f"{C.G}{txt}{C.RST}"
    if ms < 300:
        return f"{C.Y}{txt}{C.RST}"
    return f"{C.R}{txt}{C.RST}"


def _fmt_duration(sec: float) -> str:
    sec = int(sec)
    if sec < 60:
        return f"{sec} с"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m} мин {s} с" if s else f"{m} мин"
    h, m = divmod(m, 60)
    return f"{h} ч {m} мин" if m else f"{h} ч"


def _fmt_speed(mbps) -> str:
    if mbps is None:
        return f"{C.D}   ---{C.RST}"
    txt = f"{mbps:>5.1f}M"
    if mbps >= 20:
        return f"{C.G}{txt}{C.RST}"
    if mbps >= 5:
        return f"{C.Y}{txt}{C.RST}"
    return f"{C.R}{txt}{C.RST}"


def _fmt_flags(r: dict) -> str:
    in_cc = (r.get("input_geo") or {}).get("countryCode", "")
    out_cc = (r.get("output_geo") or {}).get("countryCode", "")
    f_in = country_code_to_flag(in_cc) or "?"
    f_out = country_code_to_flag(out_cc) or "?"
    if r.get("proxy_ok"):
        return f"{f_in}→{f_out}"
    return f"{f_in}→{C.D}?{C.RST}"


def _endpoint_key(cfg: dict) -> str:
    return f"{cfg['host']}:{cfg['port']}"


def _mark_dead_endpoint(cfg: dict) -> None:
    key = _endpoint_key(cfg)
    with _dead_endpoints_lock:
        _dead_endpoints.add(key)


def _is_endpoint_dead(cfg: dict) -> bool:
    key = _endpoint_key(cfg)
    with _dead_endpoints_lock:
        return key in _dead_endpoints


def reset_dead_endpoints() -> None:
    with _dead_endpoints_lock:
        _dead_endpoints.clear()


def test_config(
    cfg: dict,
    use_icmp: bool = False,
    cache_file: Optional[str] = None,
) -> dict:
    host = cfg["host"]
    input_ip = resolve_host(host) or host

    if _is_endpoint_dead(cfg):
        return {
            "config": cfg,
            "input_ip": input_ip,
            "input_geo": get_geo(input_ip) if input_ip else {},
            "output_ip": None,
            "output_geo": {},
            "ping_ms": None,
            "tcp_ms": None,
            "proxy_ok": False,
            "error": f"skip: {_endpoint_key(cfg)} уже недоступен",
            "content_probes": {},
            "content_hits": 0,
            "speed_mbps": None,
            "rating": None,
        }

    exit_ip, proxy_tcp_ms, err, probes, hits, speed_mbps = test_via_proxy_extended(cfg)
    result: dict = {
        "config": cfg,
        "input_ip": input_ip,
        "input_geo": get_geo(input_ip) if input_ip else {},
        "output_ip": exit_ip,
        "output_geo": get_geo(exit_ip) if exit_ip else {},
        "ping_ms": None,
        "tcp_ms": proxy_tcp_ms,
        "proxy_ok": bool(exit_ip),
        "error": err,
        "content_probes": probes,
        "content_hits": hits,
        "speed_mbps": speed_mbps,
        "rating": compute_rating(hits, proxy_tcp_ms, speed_mbps) if exit_ip else None,
    }
    if use_icmp:
        result["ping_ms"] = run_icmp_ping(host)
    if result["ping_ms"] is None and result["tcp_ms"] is not None:
        result["ping_ms"] = result["tcp_ms"]

    if result["proxy_ok"]:
        raw = cfg.get("_raw_url") or ""
        if not raw:
            raw = config_to_url(cfg) or ""
        if raw and cache_file:
            append_cache_raw_url(cache_file, raw)
    else:
        _mark_dead_endpoint(cfg)

    return result


def print_result_line(r: dict, check_order: int, total: int):
    """check_order — порядковый номер завершённой проверки (1…total), не индекс в списке конфигов."""
    cfg = r["config"]
    proto = cfg["protocol"]
    addr = f"{cfg['host']}:{cfg['port']}"
    if len(addr) > 25:
        addr = addr[:22] + "..."
    ok = r.get("proxy_ok")
    if r.get("from_registry_cache"):
        icon = f"{C.D}◌{C.RST}" if ok else f"{C.D}·{C.RST}"
    else:
        icon = f"{C.G}✓{C.RST}" if ok else f"{C.R}✗{C.RST}"
    ping = r.get("tcp_ms") or r.get("ping_ms")
    spd = r.get("speed_mbps")
    flags = _fmt_flags(r)
    idx_w = len(str(total))
    hits = r.get("content_hits", 0)
    n_content = len(CONTENT_PROBE_URLS)
    rating = r.get("rating")
    rat_s = f"{rating:>9.0f}" if rating is not None else f"{C.D}      ---{C.RST}"

    line = (
        f"  {C.D}[{check_order:>{idx_w}}/{total}]{C.RST} "
        f"{icon} {_fmt_ping(ping)} {_fmt_speed(spd)}  "
        f"{C.B}{hits}/{n_content}{C.RST} "
        f"rt:{rat_s}  "
        f"{C.B}{proto:<8}{C.RST} "
        f"{addr:<23} "
        f"{flags}"
    )
    if not ok and r.get("error"):
        err = r["error"]
        if len(err) > 32:
            err = err[:29] + "..."
        line += f"  {C.D}({err}){C.RST}"
    if r.get("from_registry_cache"):
        line += f"  {C.D}реестр{C.RST}"
    with _print_lock:
        print(line, flush=True)


def print_summary(
    total_configs: int,
    results: List[dict],
    max_ping: int,
    saved_count: int,
    health: Dict[str, bool],
    retested_count: Optional[int] = None,
    registry_cached_count: Optional[int] = None,
    working_list_label: str = "result2.txt",
    named_working: Optional[List[Tuple[str, dict]]] = None,
):
    completed = len(results)
    ok = sum(1 for r in results if r.get("proxy_ok"))
    fail = completed - ok

    print()
    hr()
    if (
        retested_count is not None
        and registry_cached_count is not None
        and (retested_count or registry_cached_count)
    ):
        print(
            f"  {C.CY}{C.B}РАСПИСАНИЕ{C.RST}  "
            f"перепроверено: {C.W}{retested_count}{C.RST}, "
            f"из реестра: {C.D}{registry_cached_count}{C.RST}"
        )
        hr()
    print(f"  {C.CY}{C.B}ПРЯМОЙ КАНАЛ{C.RST} (direct)")
    hr()
    for u, h in health.items():
        st = f"{C.G}OK{C.RST}" if h else f"{C.R}fail{C.RST}"
        short = u.replace("https://", "")[:40]
        print(f"  {short:<42} {st}")
    hr()
    print(f"  {C.CY}{C.B}ИТОГИ ПРОВЕРКИ{C.RST}")
    hr()
    tested_str = str(total_configs)
    if completed < total_configs:
        tested_str += f" {C.D}(завершено {completed}){C.RST}"
    print(f"  Всего:         {C.W}{C.B}{tested_str}{C.RST}")
    print(f"  Рабочих:       {C.G}{ok}{C.RST}")
    print(f"  Нерабочих:     {C.R}{fail}{C.RST}")
    speeds = [
        r.get("speed_mbps") for r in results
        if r.get("proxy_ok") and r.get("speed_mbps") is not None
    ]
    if speeds:
        max_spd = round(max(speeds), 1)
        avg_spd = round(sum(speeds) / len(speeds), 1)
        print(f"  Макс. скорость: {C.G}{max_spd} Mbps{C.RST}")
        print(f"  Средн. скорость:{C.Y}{avg_spd} Mbps{C.RST}")
    if max_ping:
        print(f"  Фильтр ping:    ≤ {max_ping} мс")
    hr()

    if named_working:
        print(f"  {C.CY}{C.B}ТОП РАБОЧИХ{C.RST} ({len(named_working)} шт.)")
        hr()
        for name, r in named_working:
            ping = r.get("tcp_ms") or r.get("ping_ms")
            spd = r.get("speed_mbps")
            hits = r.get("content_hits", 0)
            addr = f"{r['config']['host']}:{r['config']['port']}"
            if len(addr) > 22:
                addr = addr[:19] + "..."
            print(
                f"  {C.G}✓{C.RST} {_fmt_ping(ping)} {_fmt_speed(spd)} "
                f"{C.B}{hits}/{len(CONTENT_PROBE_URLS)}{C.RST}  "
                f"{addr:<22} {C.W}{name}{C.RST}"
            )
        hr()

    print(
        f"  {C.G}Сохранено {saved_count} URL → {working_list_label}{C.RST}"
    )
    hr()
    print()


def post_results_webhook(
    url: str, payload: dict, timeout: Optional[float] = None,
) -> Tuple[bool, str]:
    """Returns (success, detail_message)."""
    if timeout is None:
        timeout = _timeout("webhook_post_sec", 25.0)
    if not requests:
        return False, "requests не установлен"
    try:
        r = requests.post(
            url, json=payload, timeout=timeout,
            headers={"User-Agent": "probe2-results/1.0"},
        )
        if r.status_code < 400:
            return True, f"HTTP {r.status_code}"
        body = r.text[:500] if r.text else ""
        return False, f"HTTP {r.status_code}: {body}"
    except Exception as exc:
        return False, f"{exc}\n{traceback.format_exc()}"


def build_results_payload(
    health: Dict[str, bool],
    results: List[dict],
    sorted_working: List[dict],
) -> dict:
    return {
        "ts": time.time(),
        "direct_health": health,
        "summary": {
            "total": len(results),
            "proxy_ok": sum(1 for r in results if r.get("proxy_ok")),
        },
        "top": [
            {
                "host": r["config"]["host"],
                "port": r["config"]["port"],
                "protocol": r["config"]["protocol"],
                "tcp_ms": r.get("tcp_ms"),
                "speed_mbps": r.get("speed_mbps"),
                "content_hits": r.get("content_hits"),
                "rating": r.get("rating"),
                "raw_url": r["config"].get("_raw_url")
                or config_to_url(r["config"]),
            }
            for r in sorted_working[:50]
        ],
    }


def build_site_report_payload(
    provider_id: int,
    results: List[dict],
    device_info: Optional[str] = None,
    brand: str = "VPN",
) -> dict:
    working = [r for r in results if r.get("proxy_ok")]
    working.sort(
        key=lambda r: r.get("rating") if r.get("rating") is not None else -1e9,
        reverse=True,
    )
    items = []
    w_idx = 0
    for r in results:
        cfg = r.get("config") or {}
        if r.get("proxy_ok"):
            w_idx += 1
            name = _pretty_config_name(r, w_idx, len(working), brand=brand)
            raw = config_to_url(cfg, fragment=name)
        else:
            raw = cfg.get("_raw_url") or config_to_url(cfg)
        items.append({
            "raw_url": raw or "",
            "rating": r.get("rating"),
            "tcp_ms": r.get("tcp_ms"),
            "speed_mbps": r.get("speed_mbps"),
            "content_hits": int(r.get("content_hits", 0)),
            "proxy_ok": bool(r.get("proxy_ok")),
        })
    payload: dict = {
        "provider_id": provider_id,
        "results": items,
    }
    if device_info:
        payload["device_info"] = device_info
    return payload


def post_report_to_site(
    url: str,
    api_key: Optional[str],
    payload: dict,
    timeout: Optional[float] = None,
) -> Tuple[bool, str]:
    """Returns (success, detail_message)."""
    if timeout is None:
        timeout = _timeout("webhook_post_sec", 25.0)
    if not requests:
        return False, "requests не установлен"
    key = "" if api_key is None else str(api_key)
    try:
        r = requests.post(
            url,
            json=payload,
            timeout=timeout,
            headers={
                "User-Agent": "probe2-report/1.0",
                "X-API-Key": key,
            },
        )
        if r.status_code < 400:
            return True, f"HTTP {r.status_code}"
        body = r.text[:500] if r.text else ""
        return False, f"HTTP {r.status_code}: {body}"
    except Exception as exc:
        return False, f"{exc}\n{traceback.format_exc()}"


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def _resolve_input_source(args: argparse.Namespace, ycfg: dict) -> Tuple[str, Optional[str]]:
    """
    Возвращает (kind, value): kind in ('url', 'file', 'default_sources');
    value — URL или путь к файлу для первых двух.
    """
    if getattr(args, "url", None):
        return "url", args.url
    if getattr(args, "file", None):
        return "file", args.file
    inp = ycfg.get("input") or {}
    mode = str(inp.get("mode") or "default_sources").strip().lower()
    if mode == "file" and inp.get("file"):
        return "file", str(inp["file"])
    if mode in ("single_url", "url") and inp.get("single_url"):
        return "url", str(inp["single_url"])
    return "default_sources", None


def main():
    cfg_argv, argv_rest = strip_config_argv(sys.argv[1:])
    yaml_path = cfg_argv or default_config_path()
    file_cfg = load_probe2_yaml(yaml_path)
    apply_urls_from_yaml(file_cfg)
    apply_timeouts_from_yaml(file_cfg)
    ydef = yaml_to_parser_defaults(file_cfg)

    parser = argparse.ArgumentParser(
        description=(
            "Probe2 — health, smart fetch, cache, rating, content probes. "
            f"Настройки: {DEFAULT_CONFIG_YAML} (или --config PATH до остальных аргументов)"
        ),
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "Дублирует путь к YAML (удобно в help); реально путь читается "
            "из argv до parse — укажите --config первым"
        ),
    )
    parser.add_argument("url", nargs="?", help="vless:// / trojan:// / hysteria2://")
    parser.add_argument("-f", "--file", help="Файл с конфигами")
    parser.add_argument("-i", "--icmp", action="store_true", help="ICMP ping")
    parser.add_argument("-j", "--json", action="store_true", help="Вывод JSON в stdout")
    parser.add_argument(
        "-w", "--workers", type=int,
        help="Потоки (см. config.yaml probe.workers)",
    )
    parser.add_argument(
        "-p", "--max-ping", type=int, dest="max_ping",
        help="Макс. tcp_ms для списка рабочих (0 = нет)",
    )
    parser.add_argument(
        "--cache", default=None,
        help=f"Кэш URL (по умолч. {DEFAULT_CACHE_NAME} рядом со скриптом)",
    )
    parser.add_argument(
        "--wait-fail", type=float, dest="wait_fail",
        help="Сек паузы если загрузка листов полностью провалилась",
    )
    parser.add_argument(
        "--post-results",
        default=None, dest="post_results",
        help="POST JSON на URL",
    )
    parser.add_argument(
        "--webhook-timeout", type=float, dest="webhook_timeout",
        help="Таймаут POST webhook (сек)",
    )
    parser.add_argument(
        "--results-json",
        default=None, dest="results_json",
        help="Полный путь к JSON результатов",
    )
    parser.add_argument(
        "--result-txt",
        default=None, dest="result_txt",
        help="Имя или путь файла со списком рабочих URL (см. output.working_list_file)",
    )
    parser.add_argument(
        "--no-singbox-download",
        action="store_true",
        help="Не скачивать sing-box в bin рядом со скриптом",
    )
    parser.add_argument(
        "--no-registry",
        action="store_true",
        help="Выключить реестр и умное расписание",
    )
    parser.add_argument(
        "--registry",
        default=None,
        help=f"JSON реестра (по умолч. {DEFAULT_REGISTRY_NAME} рядом со скриптом)",
    )
    parser.add_argument(
        "--interval-ok",
        type=float,
        help="Сек до следующей проверки рабочего (registry.interval_ok_sec)",
    )
    parser.add_argument(
        "--interval-dead",
        type=float,
        help="Базовая пауза для мёртвого / фикс при --no-dead-backoff",
    )
    parser.add_argument(
        "--interval-dead-max",
        type=float, dest="interval_dead_max",
        help="Потолок backoff для мёртвого (сек)",
    )
    parser.add_argument(
        "--dead-backoff-mult",
        type=float, dest="dead_backoff_mult",
        help="Множитель серии неудач",
    )
    parser.add_argument(
        "--no-dead-backoff",
        action="store_true",
        help="Без удваивания паузы для мёртвых",
    )
    parser.add_argument(
        "--no-smart-schedule",
        action="store_true",
        help="Проверять все конфиги каждый запуск",
    )
    parser.add_argument(
        "--loop", type=int, default=0, metavar="SEC",
        help="Повторять проверку каждые SEC секунд (0 = однократно)",
    )
    parser.set_defaults(**ydef)
    args = parser.parse_args(argv_rest)

    set_singbox_auto_download(not args.no_singbox_download)
    set_singbox_fetch_quiet(args.json)

    if not args.json:
        banner()
        if os.path.isfile(yaml_path):
            log_sub(f"config: {yaml_path}")

    if not requests:
        log_fail("pip install requests")
        sys.exit(1)
    if not find_singbox():
        log_fail("sing-box не найден")
        sys.exit(1)

    cache_file = cache_path(args.cache)
    registry_file: Optional[str] = None
    if args.no_registry:
        registry_file = None
    elif args.registry:
        registry_file = args.registry
    else:
        registry_file = registry_path(None)

    loop_sec = max(0, int(args.loop))
    cycle_num = 0

    if loop_sec and not args.json:
        log_info(
            f"Режим цикла: каждые {loop_sec} с  "
            f"({loop_sec // 60} мин) — Ctrl+C для выхода"
        )

    while True:
        cycle_num += 1
        if loop_sec and cycle_num > 1 and not args.json:
            print()
            hr()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S")
            log_info(f"Цикл #{cycle_num}  ({now_str})")
            hr()

        try:
            _exit = _run_cycle(args, file_cfg, cache_file, registry_file)
        except KeyboardInterrupt:
            log_warn("Остановлено пользователем")
            sys.exit(0)
        except Exception:
            log_traceback("Ошибка цикла проверки")
            _exit = 1

        if not loop_sec:
            sys.exit(_exit)

        if not args.json:
            _fmt_interval = _fmt_duration(loop_sec)
            next_str = time.strftime(
                "%H:%M:%S", time.localtime(time.time() + loop_sec)
            )
            log_info(
                f"Следующий цикл через {_fmt_interval}  "
                f"(~{next_str}) — Ctrl+C для выхода"
            )
        try:
            time.sleep(loop_sec)
        except KeyboardInterrupt:
            log_warn("Остановлено пользователем")
            sys.exit(0)


def _run_cycle(
    args: argparse.Namespace,
    file_cfg: dict,
    cache_file: str,
    registry_file: Optional[str],
) -> int:
    """One probe cycle. Returns exit code (0 ok, 130 interrupted)."""
    reset_dead_endpoints()

    log_info("Проверка direct: max / vk / wb / ozon...")
    health = check_direct_health(HEALTH_URLS)
    for u, h in health.items():
        log_sub(f"{u} → {'OK' if h else 'fail'}")
    if baseline_internet_ok(health):
        log_ok("База max+vk: direct доступен")
    else:
        log_warn(
            "Без max+vk на direct — загрузка листов через кэш не включится"
        )

    cache_cfgs = cache_to_configs(cache_file)
    if cache_cfgs:
        log_info(f"Кэш: {len(cache_cfgs)} конфиг(ов) для fallback-загрузки")

    inp_kind, inp_val = _resolve_input_source(args, file_cfg)
    configs: List[dict] = []
    if inp_kind == "url":
        assert inp_val is not None
        cfg = parse_config(inp_val)
        if not cfg:
            log_fail("Не удалось распарсить URL")
            return 1
        configs = [cfg]
    elif inp_kind == "file":
        assert inp_val is not None
        try:
            with open(inp_val, "r", encoding="utf-8") as f:
                text = f.read()
        except Exception as e:
            log_fail(str(e))
            return 1
        configs = parse_subscription(text)
        if not configs:
            log_fail("В файле нет конфигов")
            return 1
    else:
        log_info(
            f"Загрузка {len(CONFIGS_SOURCE_URLS)} источников (параллельно)..."
        )
        all_cfgs: List[dict] = []
        direct_results: Dict[str, Optional[str]] = {}
        with ThreadPoolExecutor(max_workers=min(len(CONFIGS_SOURCE_URLS), 8)) as pool:
            futs = {
                pool.submit(fetch_url_text_direct, src): src
                for src in CONFIGS_SOURCE_URLS
            }
            for fut in as_completed(futs):
                src = futs[fut]
                direct_results[src] = fut.result()

        failed_sources: List[str] = []
        for src in CONFIGS_SOURCE_URLS:
            short = src.rsplit("/", 1)[-1]
            body = direct_results.get(src)
            if body:
                part = parse_subscription(body)
                col = f"{C.G}{len(part)}{C.RST}" if part else f"{C.D}0{C.RST}"
                log_sub(f"{short:<42} {'direct':<12} → {col}")
                all_cfgs.extend(part)
            else:
                failed_sources.append(src)

        if failed_sources and baseline_internet_ok(health) and cache_cfgs:
            for src in failed_sources:
                short = src.rsplit("/", 1)[-1]
                body, mode = smart_fetch_subscription(
                    src, cache_cfgs, health, wait_on_total_fail=args.wait_fail
                )
                if body:
                    part = parse_subscription(body)
                    col = f"{C.G}{len(part)}{C.RST}" if part else f"{C.D}0{C.RST}"
                    log_sub(f"{short:<42} {mode:<12} → {col}")
                    all_cfgs.extend(part)
                else:
                    log_sub(f"{short:<42} {C.R}fail{C.RST}")
        elif failed_sources:
            for src in failed_sources:
                short = src.rsplit("/", 1)[-1]
                log_sub(f"{short:<42} {C.R}fail{C.RST}")

        configs = unique_configs(all_cfgs)
        if not configs:
            log_fail("Нет конфигов после загрузки")
            return 1

    configs = unique_configs(configs)
    total = len(configs)
    workers = max(1, min(args.workers, 24))

    registry: dict = {"entries": {}}
    now = time.time()
    use_registry = registry_file is not None
    if use_registry:
        registry = load_registry(registry_file)
    force_all = args.no_smart_schedule or not use_registry
    interval_ok = max(60.0, float(args.interval_ok))
    interval_dead = max(60.0, float(args.interval_dead))
    interval_dead_max = max(interval_dead, float(args.interval_dead_max))
    dead_backoff_mult = max(1.0, float(args.dead_backoff_mult))
    dead_backoff = not args.no_dead_backoff

    to_test: List[Tuple[int, dict]]
    if use_registry:
        to_test, _ = split_configs_by_schedule(
            configs, registry, now, force_all
        )
    else:
        to_test = [(i, c) for i, c in enumerate(configs)]
    tested_indices = {i for i, _ in to_test}
    retested_n = len(tested_indices)
    registry_cached_n = total - retested_n

    if not args.json:
        print()
        if use_registry and not force_all:
            if dead_backoff:
                dead_desc = (
                    f"мёртвые backoff: база {interval_dead:.0f} с, "
                    f"×{dead_backoff_mult:g}, max {interval_dead_max:.0f} с"
                )
            else:
                dead_desc = f"мёртвые каждые {interval_dead:.0f} с (без backoff)"
            log_info(
                f"Конфигов: {C.W}{total}{C.RST} — "
                f"к перепроверке: {C.W}{retested_n}{C.RST}, "
                f"из реестра: {C.D}{registry_cached_n}{C.RST} "
                f"(рабочие каждые {interval_ok:.0f} с; {dead_desc})"
            )
        else:
            log_info(
                f"Проверка {C.W}{total}{C.RST} конфигов, "
                f"{workers} потоков; "
                f"sites: t.me, youtube, instagram"
            )
        hr()

    results: List[Optional[dict]] = [None] * total
    interrupted = False

    try:
        if to_test:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(test_config, cfg, args.icmp, cache_file): idx
                    for idx, cfg in to_test
                }
                check_order = 0
                for fut in as_completed(futures):
                    idx = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        log_traceback(
                            f"test_config {configs[idx]['host']}:{configs[idx]['port']}"
                        )
                        r = {
                            "config": configs[idx],
                            "input_ip": resolve_host(configs[idx]["host"])
                            or configs[idx]["host"],
                            "input_geo": {},
                            "output_ip": None,
                            "output_geo": {},
                            "ping_ms": None,
                            "tcp_ms": None,
                            "proxy_ok": False,
                            "error": str(e),
                            "content_probes": {},
                            "content_hits": 0,
                            "speed_mbps": None,
                            "rating": None,
                        }
                    results[idx] = r
                    check_order += 1
                    if not args.json:
                        print_result_line(r, check_order, retested_n)
        elif use_registry and not args.json:
            log_warn(
                "Сейчас ни один конфиг не в окне перепроверки — "
                "итоги и список рабочих из реестра"
            )

        filled = fill_skipped_results_from_registry(
            configs, registry, tested_indices
        )
        for i in range(total):
            if i not in tested_indices:
                results[i] = filled[i]
    except KeyboardInterrupt:
        log_warn("Прервано")
        interrupted = True
        try:
            filled_ki = fill_skipped_results_from_registry(
                configs, registry, tested_indices
            )
            for i in range(total):
                if i < len(results) and results[i] is None:
                    results[i] = filled_ki[i]
        except Exception:
            pass

    results = [r for r in results if r is not None]

    flush_pending_cache(cache_file)

    if use_registry and registry_file and not interrupted:
        apply_results_to_registry(
            registry,
            results,
            now,
            interval_ok,
            interval_dead,
            dead_backoff=dead_backoff,
            interval_dead_max=interval_dead_max,
            dead_backoff_multiplier=dead_backoff_mult,
        )
        save_registry(registry_file, registry)

    def sort_key(r: dict):
        rat = r.get("rating")
        if rat is not None:
            return (0, -rat, r.get("tcp_ms") or 1e9)
        p = r.get("tcp_ms") or r.get("ping_ms")
        return (1, 0, p if p is not None else 1e9)

    sorted_results = sorted(results, key=sort_key)

    working = [r for r in sorted_results if r.get("proxy_ok")]
    if args.max_ping:
        working = [
            r for r in working
            if (r.get("tcp_ms") or r.get("ping_ms") or 0) <= args.max_ping
        ]

    brand = file_cfg.get("output", {}).get("brand", "VPN")
    url_lines: List[str] = []
    named_working: List[Tuple[str, dict]] = []
    for i, r in enumerate(working, 1):
        name = _pretty_config_name(r, i, len(working), brand=brand)
        u = config_to_url(r["config"], fragment=name)
        if u:
            url_lines.append(u)
            named_working.append((name, r))

    rf = getattr(args, "result_txt", None) or "result2.txt"
    if os.path.isabs(rf):
        result_path = rf
    else:
        result_path = os.path.join(os.getcwd(), rf)
    try:
        with open(result_path, "w", encoding="utf-8") as f:
            f.write("\n".join(url_lines))
    except Exception:
        log_traceback(f"Запись {result_path}")

    paths_fc = file_cfg.get("paths") or {}
    out_fc = file_cfg.get("output") or {}
    if args.results_json:
        results_json_path = args.results_json
    elif paths_fc.get("results_json"):
        results_json_path = str(paths_fc["results_json"])
    else:
        bn = out_fc.get("results_json_basename", DEFAULT_RESULTS_JSON)
        results_json_path = os.path.join(os.getcwd(), str(bn))
    payload = build_results_payload(health, results, working)
    try:
        with open(results_json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        log_traceback(f"Запись {results_json_path}")

    if args.post_results:
        wh_ok, wh_detail = post_results_webhook(
            args.post_results, payload, timeout=args.webhook_timeout,
        )
        if wh_ok:
            log_ok("POST результатов: OK")
        else:
            log_fail(f"POST результатов: {wh_detail}")

    report_url = getattr(args, "report_url", None)
    report_pid = getattr(args, "report_provider_id", None)
    report_key = getattr(args, "report_api_key", None)
    if report_url and report_pid and report_key:
        site_payload = build_site_report_payload(
            int(report_pid), sorted_results,
            device_info=socket.gethostname(),
            brand=brand,
        )
        rpt_ok, rpt_detail = post_report_to_site(
            report_url, report_key, site_payload,
            timeout=args.webhook_timeout,
        )
        if rpt_ok:
            n = len(site_payload.get("results") or [])
            log_ok(f"Отчёт на сайт: OK ({n} конфигов)")
        else:
            log_fail(f"Отчёт на сайт: {rpt_detail}")

    if not args.json:
        print_summary(
            total,
            results,
            args.max_ping,
            len(url_lines),
            health,
            retested_count=retested_n if use_registry else None,
            registry_cached_count=registry_cached_n if use_registry else None,
            working_list_label=os.path.basename(result_path),
            named_working=named_working,
        )

    if args.json:
        out = []
        for r in sorted_results:
            out.append({
                "config": {
                    "protocol": r["config"]["protocol"],
                    "host": r["config"]["host"],
                    "port": r["config"]["port"],
                    "name": r["config"].get("name"),
                    "raw_url": r["config"].get("_raw_url") or config_to_url(r["config"]),
                },
                "input_ip": r["input_ip"],
                "input_geo": r["input_geo"],
                "output_ip": r.get("output_ip"),
                "output_geo": r.get("output_geo"),
                "proxy_ok": r.get("proxy_ok"),
                "error": r.get("error"),
                "ping_ms": r["ping_ms"],
                "tcp_ms": r["tcp_ms"],
                "speed_mbps": r.get("speed_mbps"),
                "content_probes": r.get("content_probes"),
                "content_hits": r.get("content_hits"),
                "rating": r.get("rating"),
                "from_registry_cache": r.get("from_registry_cache", False),
            })
        print(json.dumps(out, ensure_ascii=False, indent=2))

    return 130 if interrupted else 0


if __name__ == "__main__":
    main()
