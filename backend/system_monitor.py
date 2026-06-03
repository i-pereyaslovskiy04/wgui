import logging
import os
import subprocess
import threading
import time
from typing import Optional

log = logging.getLogger(__name__)

try:
    import psutil as _psutil
    _PSUTIL_OK = True
except ImportError:
    _psutil = None
    _PSUTIL_OK = False
    log.error("psutil not installed — system metrics unavailable. Run: pip install psutil>=5.9.0")

_INTERVAL   = 60   # seconds between collections
_ONLINE_SEC = 180  # WG handshake age threshold for "online"
_WG_IFACE   = os.getenv("WG_INTERFACE", "wg0")

_lock: threading.Lock = threading.Lock()
_snapshot: Optional[dict] = None


def get_snapshot() -> Optional[dict]:
    with _lock:
        return _snapshot


# ── Collectors ────────────────────────────────────────────────────────────────

def _collect_cpu() -> dict:
    if not _PSUTIL_OK:
        return {"percent": 0.0}
    return {"percent": round(_psutil.cpu_percent(interval=None), 1)}


def _collect_memory() -> dict:
    if not _PSUTIL_OK:
        return {"used": 0, "total": 0, "percent": 0.0}
    m = _psutil.virtual_memory()
    return {"used": m.used, "total": m.total, "percent": round(m.percent, 1)}


def _collect_disk() -> dict:
    if not _PSUTIL_OK:
        return {"used": 0, "total": 0, "percent": 0.0}
    try:
        d = _psutil.disk_usage("/")
        return {"used": d.used, "total": d.total, "percent": round(d.percent, 1)}
    except Exception:
        return {"used": 0, "total": 0, "percent": 0.0}


def _collect_uptime() -> int:
    if not _PSUTIL_OK:
        return 0
    return int(time.time() - _psutil.boot_time())


def _collect_wg() -> dict:
    base = {"interface": _WG_IFACE, "online_peers": 0, "total_peers": 0}
    try:
        r = subprocess.run(
            ["wg", "show", _WG_IFACE, "dump"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return base
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        peer_lines = lines[1:]  # first line = interface info
        now    = int(time.time())
        total  = len(peer_lines)
        online = 0
        for line in peer_lines:
            parts = line.split("\t")
            if len(parts) >= 5:
                try:
                    lh = int(parts[4])
                    if lh and (now - lh) < _ONLINE_SEC:
                        online += 1
                except (ValueError, IndexError):
                    pass
        return {"interface": _WG_IFACE, "online_peers": online, "total_peers": total}
    except Exception as e:
        log.debug("SystemMonitor: wg collect: %s", e)
        return base


def _collect_net() -> dict:
    try:
        if not _PSUTIL_OK:
            return {"rx_bytes": 0, "tx_bytes": 0}
        counters = _psutil.net_io_counters(pernic=True)
        ifc = counters.get(_WG_IFACE)
        if ifc is None:
            return {"rx_bytes": 0, "tx_bytes": 0}
        return {"rx_bytes": ifc.bytes_recv, "tx_bytes": ifc.bytes_sent}
    except Exception as e:
        log.debug("SystemMonitor: net collect: %s", e)
        return {"rx_bytes": 0, "tx_bytes": 0}


def _collect() -> dict:
    return {
        "cpu":            _collect_cpu(),
        "memory":         _collect_memory(),
        "disk":           _collect_disk(),
        "uptime_seconds": _collect_uptime(),
        "wireguard":      _collect_wg(),
        "network":        _collect_net(),
        "updated_at":     int(time.time()),
    }


# ── Worker ────────────────────────────────────────────────────────────────────

class SystemMonitorWorker:
    """Background thread: collects system metrics every _INTERVAL seconds."""

    def __init__(self) -> None:
        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="system-monitor",
        )

    def start(self) -> None:
        self._thread.start()
        log.info("SystemMonitorWorker started (interval=%ds)", _INTERVAL)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=_INTERVAL + 5)
        log.info("SystemMonitorWorker stopped")

    def _run(self) -> None:
        if _PSUTIL_OK:
            _psutil.cpu_percent(interval=None)  # prime the counter
        time.sleep(1)                            # wait for a meaningful 1s window
        self._tick()
        while not self._stop.wait(_INTERVAL):
            self._tick()

    def _tick(self) -> None:
        global _snapshot
        try:
            data = _collect()
            with _lock:
                _snapshot = data
            log.debug(
                "SystemMonitor: snapshot updated — cpu=%.1f%% mem=%.1f%%",
                data["cpu"]["percent"], data["memory"]["percent"],
            )
        except Exception:
            log.exception("SystemMonitor: unexpected error in _tick")
