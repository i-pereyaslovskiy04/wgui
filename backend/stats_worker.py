import logging
import threading

from storage import update_device_stats
from wireguard import WireGuardError, get_peer_stats

log = logging.getLogger(__name__)

_INTERVAL = 60  # seconds between polls


class StatsWorker:
    """Background thread: polls `wg show dump` every _INTERVAL seconds and
    accumulates per-device RX/TX counters in data.json via update_device_stats()."""

    def __init__(self) -> None:
        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="stats-worker"
        )

    def start(self) -> None:
        self._thread.start()
        log.info("StatsWorker started (interval=%ds)", _INTERVAL)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=_INTERVAL + 5)
        log.info("StatsWorker stopped")

    # ── internal ──────────────────────────────────────────────────────────────

    def _run(self) -> None:
        self._tick()                       # immediate baseline on startup
        while not self._stop.wait(_INTERVAL):
            self._tick()

    def _tick(self) -> None:
        try:
            peer_stats = get_peer_stats()
            if not peer_stats:
                return
            n = update_device_stats(peer_stats)
            log.debug("StatsWorker: updated %d device(s)", n)
        except WireGuardError as e:
            log.warning("StatsWorker: wg error — %s", e)
        except Exception:
            log.exception("StatsWorker: unexpected error in _tick")
