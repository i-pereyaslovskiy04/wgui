import logging
import os
import subprocess

log = logging.getLogger(__name__)

WG_INTERFACE   = os.getenv("WG_INTERFACE",   "wg0")
SERVER_PUBLIC_KEY = os.getenv("SERVER_PUBLIC_KEY", "")
SERVER_ENDPOINT   = os.getenv("SERVER_ENDPOINT",   "your-server:51820")
DNS            = os.getenv("DNS",            "8.8.8.8")

_TIMEOUT = 10  # seconds for any wg subprocess


class WireGuardError(Exception):
    """wg binary is present but a command failed."""


# ── Key generation ────────────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Return (private_key, public_key).
    Uses wg binary when available; falls back to Python cryptography library.
    Raises WireGuardError if wg exists but key generation fails.
    """
    try:
        priv = subprocess.check_output(
            ["wg", "genkey"], stderr=subprocess.DEVNULL, timeout=_TIMEOUT,
        ).decode().strip()
        pub = subprocess.check_output(
            ["wg", "pubkey"], input=priv.encode(),
            stderr=subprocess.DEVNULL, timeout=_TIMEOUT,
        ).decode().strip()
        log.debug("Keypair generated via wg")
        return priv, pub
    except FileNotFoundError:
        log.warning("wg binary not found — using Python crypto for key generation (dev mode)")
        return _python_keypair()
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        log.error(f"wg genkey/pubkey failed: {stderr!r}")
        raise WireGuardError("Failed to generate WireGuard keypair") from e
    except subprocess.TimeoutExpired:
        log.error("wg genkey timed out")
        raise WireGuardError("wg genkey timed out")


def _python_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    import base64
    key  = X25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes_raw()).decode()
    pub  = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    return priv, pub


# ── Peer management ───────────────────────────────────────────────────────────

def add_peer(public_key: str, ip: str) -> bool:
    """
    Add peer to the WireGuard interface.

    Returns True  — peer was added successfully.
    Returns False — wg binary not found (dev mode, non-fatal).
    Raises WireGuardError — wg is installed but the command failed.
    """
    try:
        subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", public_key,
             "allowed-ips", f"{ip}/32"],
            check=True, capture_output=True, timeout=_TIMEOUT,
        )
        log.info(f"wg: peer added — pubkey={public_key[:8]}… ip={ip}")
        _save_config()
        return True
    except FileNotFoundError:
        log.warning(f"wg not found — peer NOT added to interface (dev mode) ip={ip}")
        return False
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        log.error(f"wg set peer FAILED — pubkey={public_key[:8]}… ip={ip} stderr={stderr!r}")
        raise WireGuardError(f"wg set peer failed: {stderr}") from e
    except subprocess.TimeoutExpired:
        log.error(f"wg set peer TIMED OUT — ip={ip}")
        raise WireGuardError("wg set peer timed out")


def remove_peer(public_key: str) -> None:
    """
    Remove peer from the WireGuard interface.
    Logs errors but never raises — peer removal is always best-effort so that
    device records can still be cleaned up from JSON even if wg is unreachable.
    """
    try:
        subprocess.run(
            ["wg", "set", WG_INTERFACE, "peer", public_key, "remove"],
            check=True, capture_output=True, timeout=_TIMEOUT,
        )
        log.info(f"wg: peer removed — pubkey={public_key[:8]}…")
        _save_config()
    except FileNotFoundError:
        log.debug("wg not found — peer removal skipped (dev mode)")
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        log.warning(
            f"wg remove peer failed (non-fatal, device will still be deleted from JSON) "
            f"— pubkey={public_key[:8]}… stderr={stderr!r}"
        )
    except subprocess.TimeoutExpired:
        log.warning(
            f"wg remove peer timed out (non-fatal) — pubkey={public_key[:8]}…"
        )


def _save_config() -> None:
    """Persist wg0 state to its config file. Best-effort; never raises."""
    try:
        subprocess.run(
            ["wg-quick", "save", WG_INTERFACE],
            capture_output=True, timeout=_TIMEOUT,
        )
        log.debug(f"wg-quick save {WG_INTERFACE}")
    except Exception as e:
        log.debug(f"wg-quick save skipped: {e}")


# ── Config generation ─────────────────────────────────────────────────────────

def build_client_config(private_key: str, ip: str) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {ip}/32\n"
        f"DNS = {DNS}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {SERVER_PUBLIC_KEY}\n"
        f"Endpoint = {SERVER_ENDPOINT}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )
