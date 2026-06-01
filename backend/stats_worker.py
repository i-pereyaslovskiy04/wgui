import logging
import threading
import time

from storage import get_data, set_user_active, update_device_stats
from wireguard import WireGuardError, disable_peer, get_peer_stats

log = logging.getLogger(__name__)

_INTERVAL = 60  # seconds between polls


def _check_subscriptions() -> None:
    """Disable all devices for users whose time-based subscription has expired."""
    now = int(time.time())
    data = get_data()
    for username, udata in data["users"].items():
        sub = udata.get("subscription", {})
        if sub.get("type") != "time":
            continue
        if not sub.get("active", True):
            continue  # already disabled
        if now <= sub.get("expires_at", 0):
            continue  # still valid
        # Subscription expired — disable all peers for this user
        devices = udata.get("devices", [])
        for dev in devices:
            pub_key = dev.get("public_key", "")
            if pub_key:
                try:
                    disable_peer(pub_key)
                except WireGuardError as e:
                    log.warning(
                        "StatsWorker: failed to disable peer '%s' (user '%s'): %s",
                        dev.get("name"), username, e,
                    )
        set_user_active(username, False)
        log.info("StatsWorker: subscription expired → user disabled: %s", username)


class StatsWorker:
    """Background thread: polls `wg show dump` every _INTERVAL seconds,
    accumulates per-device RX/TX counters, and enforces subscription expiry."""

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
            if peer_stats:
                n = update_device_stats(peer_stats)
                log.debug("StatsWorker: updated %d device(s)", n)
        except WireGuardError as e:
            log.warning("StatsWorker: wg error — %s", e)
        except Exception:
            log.exception("StatsWorker: unexpected error in _tick (stats)")
        try:
            _check_subscriptions()
        except Exception:
            log.exception("StatsWorker: unexpected error in _check_subscriptions")
