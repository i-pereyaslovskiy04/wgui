import logging
import os
import re
import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from storage import (
    CONFIGS_DIR,
    commit_device,
    create_user_atomic,
    delete_device_atomic,
    delete_user_atomic,
    get_data,
    release_ip,
    reserve_ip,
)
from wireguard import (
    WireGuardError,
    add_peer,
    build_client_config,
    generate_keypair,
    generate_preshared_key,
    remove_peer,
)

log = logging.getLogger(__name__)
router = APIRouter()

_NAME_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def _ok(data=None) -> dict:
    return {"ok": True, "data": data}


def _validate_name(name: str, label: str) -> str:
    name = name.strip().lower()
    if not _NAME_RE.match(name):
        raise HTTPException(
            400,
            f"{label} must be 1–32 characters: lowercase letters, digits, dash, or underscore",
        )
    return name


class CreateUserBody(BaseModel):
    name: str


class CreateDeviceBody(BaseModel):
    name: str


# ── Users ──────────────────────────────────────────────────────────────────────

_EMPTY_SUB = {"type": "unlimited", "expires_at": 0, "active": True}


def _agg_stats(udata: dict) -> dict:
    rx = sum(d.get("stats", {}).get("total_rx", 0) for d in udata.get("devices", []))
    tx = sum(d.get("stats", {}).get("total_tx", 0) for d in udata.get("devices", []))
    return {"total_rx": rx, "total_tx": tx, "total": rx + tx}


@router.get("")
def list_users():
    data = get_data()
    users = [
        {
            "name":         n,
            "device_count": len(u.get("devices", [])),
            "subscription": u.get("subscription", _EMPTY_SUB),
            "stats":        _agg_stats(u),
        }
        for n, u in data["users"].items()
    ]
    return _ok(users)


@router.post("", status_code=201)
def create_user(body: CreateUserBody):
    name = _validate_name(body.name, "Username")
    try:
        create_user_atomic(name)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _ok({"name": name, "devices": []})


@router.get("/{user}")
def get_user(user: str):
    data = get_data()
    if user not in data["users"]:
        raise HTTPException(404, "User not found")
    udata        = data["users"][user]
    subscription = udata.get("subscription", _EMPTY_SUB)
    devices = [
        {"id": d["id"], "name": d["name"], "ip": d["ip"]}
        for d in udata.get("devices", [])
    ]
    return _ok({"name": user, "subscription": subscription, "devices": devices, "stats": _agg_stats(udata)})


@router.delete("/{user}")
def delete_user(user: str):
    # Read device list before any deletion so we have the public keys for cleanup.
    data = get_data()
    if user not in data["users"]:
        raise HTTPException(404, "User not found")
    devices = list(data["users"][user].get("devices", []))

    # Step 1: remove all WireGuard peers BEFORE the IPs are freed in JSON.
    # This closes the race where a concurrent create_device could grab a
    # just-freed IP while the old WireGuard peer still holds it.
    for dev in devices:
        if dev.get("public_key"):
            remove_peer(dev["public_key"])

    # Step 2: commit deletion to JSON (atomically frees all IPs).
    try:
        delete_user_atomic(user)
    except KeyError as e:
        raise HTTPException(404, str(e))

    # Step 3: remove config files.
    for dev in devices:
        (CONFIGS_DIR / dev.get("config_file", "")).unlink(missing_ok=True)

    log.info(f"User deleted: {user}")
    return _ok({"deleted": True})


# ── Devices ────────────────────────────────────────────────────────────────────

@router.post("/{user}/devices", status_code=201)
def create_device(user: str, body: CreateDeviceBody):
    device_name = _validate_name(body.name, "Device name")

    # Fast pre-check (no lock) — catches obvious conflicts cheaply.
    # The definitive duplicate-check happens inside commit_device under the lock.
    data = get_data()
    if user not in data["users"]:
        raise HTTPException(404, "User not found")
    if any(d["name"] == device_name for d in data["users"][user].get("devices", [])):
        raise HTTPException(409, f"Device '{device_name}' already exists for user '{user}'")

    priv_key, pub_key = generate_keypair()
    psk            = generate_preshared_key()
    device_id      = str(uuid.uuid4())
    config_filename = f"{user}-{device_id}.conf"
    config_path    = CONFIGS_DIR / config_filename

    # ── Phase 1: reserve IP (atomic, prevents double-alloc) ──────────────────
    ip = reserve_ip()

    peer_added     = False
    config_written = False

    try:
        # ── Phase 2: add WireGuard peer ────────────────────────────────────────
        # Returns False (dev mode) or True (added). Raises WireGuardError on failure.
        add_peer(pub_key, ip, psk)
        peer_added = True

        # ── Phase 3: write config file atomically ─────────────────────────────
        # Write to a .tmp file first, then os.replace() — a crash mid-write
        # leaves the .tmp orphan, never a corrupt final config.
        _tmp = config_path.with_suffix(".tmp")
        try:
            _tmp.write_text(build_client_config(priv_key, ip, psk), encoding="utf-8")
            os.replace(_tmp, config_path)
            config_written = True
        except OSError:
            _tmp.unlink(missing_ok=True)
            raise

        # ── Phase 4: commit to JSON (atomic) ──────────────────────────────────
        # Promotes ip from '__reserved__' → 'user/device' and appends device record.
        device = {
            "id":          device_id,
            "name":        device_name,
            "ip":          ip,
            "public_key":  pub_key,
            "config_file": config_filename,
        }
        commit_device(user, device)

    except Exception as exc:
        # ── Rollback ──────────────────────────────────────────────────────────
        log.error(f"Device creation failed — user={user} device={device_name}: {exc}")
        release_ip(ip)
        if peer_added:
            remove_peer(pub_key)
        if config_written:
            config_path.unlink(missing_ok=True)

        if isinstance(exc, WireGuardError):
            raise HTTPException(503, f"WireGuard error: {exc}")
        if isinstance(exc, ValueError):
            raise HTTPException(409, str(exc))
        if isinstance(exc, KeyError):
            raise HTTPException(404, str(exc))
        raise HTTPException(500, f"Failed to create device: {exc}")

    log.info(f"Device created: user={user} device={device_name} ip={ip}")
    return _ok({"id": device_id, "name": device_name, "ip": ip})


@router.delete("/{user}/devices/{device_id}")
def delete_device(user: str, device_id: str):
    # Read device record before removal so we have the public key for cleanup.
    data = get_data()
    if user not in data["users"]:
        raise HTTPException(404, "User not found")
    device = next(
        (d for d in data["users"][user].get("devices", []) if d.get("id") == device_id),
        None,
    )
    if not device:
        raise HTTPException(404, "Device not found")

    # Step 1: remove WireGuard peer BEFORE the IP is freed in JSON.
    if device.get("public_key"):
        remove_peer(device["public_key"])

    # Step 2: commit deletion to JSON (atomically frees the IP).
    try:
        delete_device_atomic(user, device_id)
    except KeyError as e:
        raise HTTPException(404, str(e))

    (CONFIGS_DIR / device.get("config_file", "")).unlink(missing_ok=True)
    log.info(f"Device deleted: user={user} device={device.get('name')}")
    return _ok({"deleted": True})
