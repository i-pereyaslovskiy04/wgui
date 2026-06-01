import json
import logging
import os
import threading
from pathlib import Path

log = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
DATA_FILE    = PROJECT_ROOT / "data" / "data.json"
CONFIGS_DIR  = PROJECT_ROOT / "configs"

_lock = threading.Lock()

_EMPTY_DATA: dict = {"users": {}, "ip_pool": {"next": 10, "used": {}}}


# ── Internal ──────────────────────────────────────────────────────────────────

def _validate_schema(data: object) -> None:
    if not isinstance(data, dict):
        raise ValueError("Root must be a JSON object")
    if not isinstance(data.get("users"), dict):
        raise ValueError("'users' must be a JSON object")
    if not isinstance(data.get("ip_pool"), dict):
        raise ValueError("'ip_pool' must be a JSON object")
    for uname, udata in data["users"].items():
        if not isinstance(udata, dict):
            raise ValueError(f"User '{uname}' value must be a JSON object")
        if "devices" in udata and not isinstance(udata["devices"], list):
            raise ValueError(f"User '{uname}' devices must be a JSON array")


def _cleanup_reserved(data: dict) -> int:
    """
    Remove stale '__reserved__' entries from ip_pool.used.

    Any '__reserved__' value that survives a restart is a crash artifact:
    legitimate reservations only exist for the lifetime of an in-flight
    create_device request, which the OS kills when the process exits.
    Returns the number of entries removed.
    """
    used = data["ip_pool"].get("used", {})
    stale = [ip for ip, val in used.items() if val == "__reserved__"]
    for ip in stale:
        del used[ip]
    return len(stale)


def _migrate(data: dict) -> bool:
    """Apply forward-compatible schema migrations in-place. Returns True if modified."""
    dirty = False
    pool = data.setdefault("ip_pool", {"next": 10})

    # v1 → v2: add ip_pool.used by scanning existing devices
    if "used" not in pool:
        used: dict[str, str] = {}
        for uname, udata in data.get("users", {}).items():
            for dev in udata.get("devices", []):
                if isinstance(dev, dict) and "ip" in dev:
                    used[dev["ip"]] = f"{uname}/{dev.get('name', '?')}"
        pool["used"] = used
        dirty = True
        log.info(f"Migration: reconstructed ip_pool.used ({len(used)} entries)")

    # Ensure every user has a 'devices' list
    for uname, udata in data.get("users", {}).items():
        if not isinstance(udata.get("devices"), list):
            udata["devices"] = []
            dirty = True
            log.warning(f"Migration: repaired missing devices list for user '{uname}'")

    return dirty


def _read() -> dict:
    """Read data.json, validate schema, and return dict. Raises on any error."""
    try:
        raw = DATA_FILE.read_text(encoding="utf-8")
    except OSError as e:
        raise RuntimeError(f"Cannot read data.json: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"data.json contains invalid JSON: {e}") from e

    _validate_schema(data)
    return data


def _write_safe(data: dict) -> None:
    """
    Atomic write: serialise to a .tmp file, fsync, then os.replace() into place.
    On POSIX, os.replace() is a single atomic rename syscall.
    """
    tmp = DATA_FILE.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, DATA_FILE)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


# ── Bootstrap ─────────────────────────────────────────────────────────────────

def init_storage() -> None:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIGS_DIR.mkdir(parents=True, exist_ok=True)

    if not DATA_FILE.exists():
        _write_safe(dict(_EMPTY_DATA))
        log.info("Created new data.json")
        return

    with _lock:
        data = _read()  # raises loudly if corrupt — intentional

        dirty = _migrate(data)

        # Remove stale __reserved__ entries left by a previous crash.
        # Safe to do unconditionally: no in-flight requests exist at startup.
        removed = _cleanup_reserved(data)
        if removed:
            dirty = True
            log.warning(
                f"Startup cleanup: removed {removed} stale __reserved__ "
                f"IP reservation(s) from a previous crash"
            )

        if dirty:
            _write_safe(data)

        # Emit a concise state summary for operational visibility
        user_count   = len(data["users"])
        device_count = sum(len(u.get("devices", [])) for u in data["users"].values())
        used_count   = len(data["ip_pool"].get("used", {}))
        log.info(
            f"Storage ready — users={user_count} devices={device_count} "
            f"used_ips={used_count}/244"
        )


# ── Read-only helpers ─────────────────────────────────────────────────────────

def get_data() -> dict:
    with _lock:
        return _read()


def find_device(device_id: str) -> tuple[str, dict] | None:
    """Return (username, device_dict) or None."""
    with _lock:
        data = _read()
        for username, udata in data["users"].items():
            for dev in udata.get("devices", []):
                if dev.get("id") == device_id:
                    return username, dev
    return None


# ── User operations ───────────────────────────────────────────────────────────

def create_user_atomic(name: str) -> None:
    """Raises ValueError if the user already exists."""
    with _lock:
        data = _read()
        if name in data["users"]:
            raise ValueError(f"User '{name}' already exists")
        data["users"][name] = {"devices": []}
        _write_safe(data)
        log.info(f"User created: {name}")


def delete_user_atomic(name: str) -> list[dict]:
    """
    Delete user and all their devices in one atomic write.
    Returns the list of removed device records (for external WG/file cleanup).
    Raises KeyError if user not found.
    """
    with _lock:
        data = _read()
        if name not in data["users"]:
            raise KeyError(f"User '{name}' not found")
        devices = list(data["users"][name].get("devices", []))
        used = data["ip_pool"].setdefault("used", {})
        for dev in devices:
            used.pop(dev.get("ip", ""), None)
        del data["users"][name]
        _write_safe(data)
        log.info(f"User deleted: {name} ({len(devices)} device(s))")
        return devices


# ── IP pool ───────────────────────────────────────────────────────────────────

def reserve_ip() -> str:
    """
    Find the first free IP in 10.66.66.10–254 and atomically mark it
    '__reserved__' in ip_pool.used to prevent concurrent double-allocation.
    Raises RuntimeError if all IPs are taken.
    """
    with _lock:
        data = _read()
        used = data["ip_pool"].setdefault("used", {})
        for n in range(10, 255):
            ip = f"10.66.66.{n}"
            if ip not in used:
                used[ip] = "__reserved__"
                data["ip_pool"]["next"] = n + 1
                _write_safe(data)
                log.debug(f"IP reserved: {ip}")
                return ip
        raise RuntimeError("IP pool exhausted — all 10.66.66.10–254 addresses are in use")


def release_ip(ip: str) -> None:
    """Remove IP from ip_pool.used (cleanup on failed device creation)."""
    with _lock:
        data = _read()
        removed = data["ip_pool"].setdefault("used", {}).pop(ip, None)
        if removed is not None:
            _write_safe(data)
            log.debug(f"IP released: {ip}")


# ── Device operations ─────────────────────────────────────────────────────────

def commit_device(username: str, device: dict) -> None:
    """
    Atomically:
    - promote ip_pool.used[ip] from '__reserved__' to 'user/device'
    - append device to user's devices list

    Raises KeyError if user not found, ValueError on duplicate device name.
    """
    with _lock:
        data = _read()
        if username not in data["users"]:
            raise KeyError(f"User '{username}' not found")
        devices = data["users"][username].get("devices", [])
        if any(d["name"] == device["name"] for d in devices):
            raise ValueError(f"Device '{device['name']}' already exists")
        ip = device.get("ip", "")
        data["ip_pool"].setdefault("used", {})[ip] = f"{username}/{device['name']}"
        devices.append(device)
        data["users"][username]["devices"] = devices
        _write_safe(data)
        log.info(f"Device committed: user={username} name={device['name']} ip={ip}")


def delete_device_atomic(username: str, device_id: str) -> dict:
    """
    Atomically remove device from user's list and free its IP.
    Returns the removed device record.
    Raises KeyError if user or device not found.
    """
    with _lock:
        data = _read()
        if username not in data["users"]:
            raise KeyError(f"User '{username}' not found")
        devices = data["users"][username].get("devices", [])
        device = next((d for d in devices if d.get("id") == device_id), None)
        if not device:
            raise KeyError(f"Device id='{device_id}' not found for user '{username}'")
        data["ip_pool"].setdefault("used", {}).pop(device.get("ip", ""), None)
        data["users"][username]["devices"] = [d for d in devices if d.get("id") != device_id]
        _write_safe(data)
        log.info(f"Device deleted: user={username} name={device.get('name')} ip={device.get('ip')}")
        return device
