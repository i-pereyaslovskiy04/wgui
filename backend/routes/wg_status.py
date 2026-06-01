import logging
import time

from fastapi import APIRouter

from storage import get_data
from wireguard import WireGuardError, get_peer_stats

log = logging.getLogger(__name__)
router = APIRouter()

_ONLINE_SEC = 120   # < 2 min  → online
_RECENT_SEC = 600   # < 10 min → recently active


def _classify(last_handshake: int, now: int) -> tuple[str, int | None]:
    """Return (status, seconds_ago | None).  Status: 'online' | 'recent' | 'offline'."""
    if not last_handshake:
        return "offline", None
    secs = max(0, now - last_handshake)
    if secs < _ONLINE_SEC:
        return "online", secs
    if secs < _RECENT_SEC:
        return "recent", secs
    return "offline", secs


@router.get("/status")
def wireguard_status():
    """
    Real-time WireGuard peer stats.
    No DB, no cache — computed on every request from `wg show dump`.
    """
    now = int(time.time())

    try:
        raw_stats = get_peer_stats()
    except WireGuardError as e:
        log.warning(f"WireGuard stats unavailable: {e}")
        raw_stats = {}

    data = get_data()
    peers      = []
    online_list = []

    _EMPTY_SUB = {"type": "unlimited", "expires_at": 0, "active": True}

    for username, udata in data["users"].items():
        user_sub = udata.get("subscription", _EMPTY_SUB)
        for dev in udata.get("devices", []):
            pub_key = dev.get("public_key") or ""
            wg      = raw_stats.get(pub_key, {})

            status, secs_ago = _classify(wg.get("last_handshake", 0), now)

            peer = {
                "id":                     dev.get("id", ""),
                "name":                   dev.get("name", ""),
                "user":                   username,
                "ip":                     dev.get("ip", ""),
                "status":                 status,
                "online":                 status == "online",
                "last_handshake_seconds": secs_ago,
                "rx_bytes":               wg.get("rx_bytes", 0),
                "tx_bytes":               wg.get("tx_bytes", 0),
                "stats":        dev.get("stats", {"total_rx": 0, "total_tx": 0, "last_seen": 0}),
                "subscription": user_sub,
            }
            peers.append(peer)

            if status == "online":
                online_list.append({"name": dev.get("name", ""), "user": username})

    online_count = len(online_list)
    log.debug(f"wireguard_status: {online_count}/{len(peers)} online")

    return {
        "ok": True,
        "data": {
            "online_devices": online_count,
            "total_devices":  len(peers),
            "peers":          peers,
            "online_list":    online_list,
        },
    }
