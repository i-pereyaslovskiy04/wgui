"""
Public user API — authenticated by per-user secret token (no admin credentials required).

All routes are unauthenticated at the HTTP level (excluded from auth middleware).
Authorization is enforced by the user_token path parameter.

Security guarantees:
- private_key and psk are never returned in JSON; only present inside .conf files.
- The username is always derived server-side from the token; clients cannot spoof it.
- Other users' data is never accessible.
- Subscription management (type/expires_at) is admin-only and not exposed here.
"""
import logging
import os
import re
import time
import uuid
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from storage import (
    CONFIGS_DIR,
    commit_device,
    delete_device_atomic,
    find_user_by_token,
    release_ip,
    reserve_ip,
)
from wireguard import (
    WireGuardError,
    add_peer,
    build_client_config,
    generate_keypair,
    generate_preshared_key,
    get_peer_stats,
    remove_peer,
)

log = logging.getLogger(__name__)
router = APIRouter()

_NAME_RE    = re.compile(r"^[a-z0-9_-]{1,32}$")
_ONLINE_SEC = 120
_RECENT_SEC = 600


# ── Helpers ───────────────────────────────────────────────────────────────────

class CreateDeviceBody(BaseModel):
    name: str


def _lookup(token: str) -> tuple[str, dict]:
    """Resolve token → (username, udata). Raises 404 on miss."""
    result = find_user_by_token(token)
    if not result:
        raise HTTPException(404, "Not found")
    return result


def _sub_ok(udata: dict) -> bool:
    """True when the subscription allows full access (create devices / download configs)."""
    sub = udata.get("subscription", {})
    t   = sub.get("type", "unlimited")
    if t == "disabled":
        return False
    if t == "unlimited":
        return True
    return bool(sub.get("active")) and sub.get("expires_at", 0) > int(time.time())


def _sub_status(sub: dict) -> str:
    """'unlimited' | 'active' | 'expired' | 'disabled'"""
    t = sub.get("type", "unlimited")
    if t == "disabled":
        return "disabled"
    if t == "unlimited":
        return "unlimited"
    if sub.get("active") and sub.get("expires_at", 0) > int(time.time()):
        return "active"
    return "expired"


def _agg_stats(udata: dict) -> dict:
    rx = sum(d.get("stats", {}).get("total_rx", 0) for d in udata.get("devices", []))
    tx = sum(d.get("stats", {}).get("total_tx", 0) for d in udata.get("devices", []))
    return {"total_rx": rx, "total_tx": tx, "total": rx + tx}


def _wg_status_map(udata: dict) -> dict[str, dict]:
    """Return {device_id: {status, last_handshake_seconds}} from live wg show."""
    try:
        peer_stats = get_peer_stats()
    except Exception:
        return {}
    now    = int(time.time())
    result = {}
    for dev in udata.get("devices", []):
        pub_key = dev.get("public_key", "")
        if not pub_key or pub_key not in peer_stats:
            continue
        lh  = peer_stats[pub_key].get("last_handshake", 0)
        age = now - lh if lh else None
        if not lh:
            status = "offline"
        elif age < _ONLINE_SEC:
            status = "online"
        elif age < _RECENT_SEC:
            status = "recent"
        else:
            status = "offline"
        result[dev["id"]] = {"status": status, "last_handshake_seconds": age}
    return result


def _safe_config_path(device: dict) -> Path:
    """Resolve config path with traversal guard."""
    path = (CONFIGS_DIR / device.get("config_file", "")).resolve()
    if not str(path).startswith(str(CONFIGS_DIR.resolve())):
        raise HTTPException(403, "Forbidden")
    return path


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/{token}")
def get_user_info(token: str):
    username, udata = _lookup(token)
    sub    = udata.get("subscription", {"type": "unlimited", "expires_at": 0, "active": True})
    wg_map = _wg_status_map(udata)

    devices = []
    for d in udata.get("devices", []):
        did   = d.get("id", "")
        wg    = wg_map.get(did, {"status": "offline", "last_handshake_seconds": None})
        devices.append({
            "id":                     did,
            "name":                   d.get("name", ""),
            "ip":                     d.get("ip", ""),
            "status":                 wg["status"],
            "last_handshake_seconds": wg["last_handshake_seconds"],
            "stats":                  d.get("stats", {"total_rx": 0, "total_tx": 0}),
            # private_key and psk intentionally omitted
        })

    return {
        "ok": True,
        "data": {
            "username":    username,
            "subscription": sub,
            "sub_status":  _sub_status(sub),
            "stats":       _agg_stats(udata),
            "devices":     devices,
        },
    }


@router.post("/{token}/devices", status_code=201)
def create_device(token: str, body: CreateDeviceBody):
    username, udata = _lookup(token)

    if not _sub_ok(udata):
        raise HTTPException(403, "Subscription inactive — cannot create devices")

    device_name = body.name.strip().lower()
    if not _NAME_RE.match(device_name):
        raise HTTPException(400, "Device name must be 1–32 characters: lowercase letters, digits, dash, or underscore")

    if any(d["name"] == device_name for d in udata.get("devices", [])):
        raise HTTPException(409, f"Device '{device_name}' already exists")

    priv_key, pub_key = generate_keypair()
    psk              = generate_preshared_key()
    device_id        = str(uuid.uuid4())
    config_filename  = f"{username}-{device_id}.conf"
    config_path      = CONFIGS_DIR / config_filename

    ip = reserve_ip()
    peer_added     = False
    config_written = False

    try:
        add_peer(pub_key, ip, psk)
        peer_added = True

        _tmp = config_path.with_suffix(".tmp")
        try:
            _tmp.write_text(build_client_config(priv_key, ip, psk), encoding="utf-8")
            os.replace(_tmp, config_path)
            config_written = True
        except OSError:
            _tmp.unlink(missing_ok=True)
            raise

        device = {
            "id":          device_id,
            "name":        device_name,
            "ip":          ip,
            "public_key":  pub_key,
            "config_file": config_filename,
        }
        commit_device(username, device)

    except Exception as exc:
        log.error("Public: device creation failed — user=%s device=%s: %s", username, device_name, exc)
        release_ip(ip)
        if peer_added:
            remove_peer(pub_key)
        if config_written:
            config_path.unlink(missing_ok=True)

        if isinstance(exc, WireGuardError):
            raise HTTPException(503, f"WireGuard error: {exc}")
        if isinstance(exc, ValueError):
            raise HTTPException(409, str(exc))
        raise HTTPException(500, f"Failed to create device: {exc}")

    log.info("Public: device created — user=%s device=%s ip=%s", username, device_name, ip)
    return {"ok": True, "data": {"id": device_id, "name": device_name, "ip": ip}}


@router.get("/{token}/devices/{device_id}/config")
def download_config(token: str, device_id: str):
    username, udata = _lookup(token)

    if not _sub_ok(udata):
        raise HTTPException(403, "Subscription inactive")

    device = next((d for d in udata.get("devices", []) if d.get("id") == device_id), None)
    if not device:
        raise HTTPException(404, "Device not found")

    config_path = _safe_config_path(device)
    if not config_path.exists():
        raise HTTPException(404, "Config file not found on disk")

    filename = f"{username}-{device['name']}.conf"
    return FileResponse(
        config_path,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{token}/devices/{device_id}/qr")
def get_device_qr(token: str, device_id: str):
    username, udata = _lookup(token)

    if not _sub_ok(udata):
        raise HTTPException(403, "Subscription inactive")

    device = next((d for d in udata.get("devices", []) if d.get("id") == device_id), None)
    if not device:
        raise HTTPException(404, "Device not found")

    config_path = _safe_config_path(device)
    if not config_path.exists():
        raise HTTPException(404, "Config file not found on disk")

    config_content = config_path.read_text(encoding="utf-8")

    try:
        import qrcode
        import qrcode.image.svg

        img    = qrcode.make(config_content, image_factory=qrcode.image.svg.SvgImage)
        stream = BytesIO()
        img.save(stream)
        return Response(content=stream.getvalue(), media_type="image/svg+xml")
    except ImportError:
        raise HTTPException(501, "QR generation unavailable — install qrcode package")


@router.delete("/{token}/devices/{device_id}", status_code=200)
def delete_device(token: str, device_id: str):
    username, udata = _lookup(token)

    device = next((d for d in udata.get("devices", []) if d.get("id") == device_id), None)
    if not device:
        raise HTTPException(404, "Device not found")

    if device.get("public_key"):
        remove_peer(device["public_key"])

    try:
        delete_device_atomic(username, device_id)
    except KeyError as e:
        raise HTTPException(404, str(e))

    (CONFIGS_DIR / device.get("config_file", "")).unlink(missing_ok=True)
    log.info("Public: device deleted — user=%s device=%s", username, device.get("name"))
    return {"ok": True, "data": {"deleted": True}}
