import logging
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

_INTERVAL = 60  # seconds between collections

_lock: threading.Lock = threading.Lock()
_snapshot: Optional[dict] = None


def get_snapshot() -> Optional[dict]:
    with _lock:
        return _snapshot


# ── Collectors ────────────────────────────────────────────────────────────────

def _collect_cpu() -> dict:
    if not _PSUTIL_OK:
        return {"percent": 0.0, "count": 0}
    return {
        "percent": round(_psutil.cpu_percent(interval=None), 1),
        "count":   _psutil.cpu_count(logical=True) or 0,
    }


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


def _collect() -> dict:
    return {
        "cpu":            _collect_cpu(),
        "memory":         _collect_memory(),
        "disk":           _collect_disk(),
        "uptime_seconds": _collect_uptime(),
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
