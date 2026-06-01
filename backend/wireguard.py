import base64
import logging
import os
import subprocess

log = logging.getLogger(__name__)

WG_INTERFACE      = os.getenv("WG_INTERFACE",      "wg0")
SERVER_PUBLIC_KEY = os.getenv("SERVER_PUBLIC_KEY",  "")
SERVER_ENDPOINT   = os.getenv("SERVER_ENDPOINT",    "")
DNS               = os.getenv("DNS",                "1.1.1.1,1.0.0.1")

_TIMEOUT = 10


class WireGuardError(Exception):
    """wg binary is present but a command failed."""


# ── Key / PSK generation ──────────────────────────────────────────────────────

def generate_keypair() -> tuple[str, str]:
    """
    Return (private_key, public_key).
    Uses wg binary when available; falls back to Python cryptography library.
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


def generate_preshared_key() -> str:
    """
    Generate a WireGuard preshared key.
    Uses `wg genpsk` when available; falls back to os.urandom(32).
    """
    try:
        psk = subprocess.check_output(
            ["wg", "genpsk"], stderr=subprocess.DEVNULL, timeout=_TIMEOUT,
        ).decode().strip()
        log.debug("PSK generated via wg genpsk")
        return psk
    except FileNotFoundError:
        psk = base64.b64encode(os.urandom(32)).decode()
        log.debug("PSK generated via os.urandom (dev mode)")
        return psk
    except subprocess.CalledProcessError as e:
        raise WireGuardError("wg genpsk failed") from e
    except subprocess.TimeoutExpired:
        raise WireGuardError("wg genpsk timed out")


def _python_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    key  = X25519PrivateKey.generate()
    priv = base64.b64encode(key.private_bytes_raw()).decode()
    pub  = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    return priv, pub


# ── Server state ──────────────────────────────────────────────────────────────

def _get_listen_port() -> int:
    """
    Read actual listen port from `wg show {WG_INTERFACE} listen-port`.
    This is the single source of truth for the server port.
    Falls back to the port in SERVER_ENDPOINT env var when wg is unavailable (dev mode).
    Raises RuntimeError if port cannot be determined by either method.
    """
    try:
        out = subprocess.check_output(
            ["wg", "show", WG_INTERFACE, "listen-port"],
            stderr=subprocess.DEVNULL, timeout=_TIMEOUT,
        ).decode().strip()
        port = int(out)
        log.debug(f"wg listen-port (live): {port}")
        return port
    except FileNotFoundError:
        pass  # wg not installed — fall through to env fallback
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log.warning(f"wg show listen-port failed: {e}")
    except ValueError as e:
        log.warning(f"wg show listen-port returned non-integer output: {e}")

    # Fallback: parse port from SERVER_ENDPOINT (dev / offline mode only)
    raw = SERVER_ENDPOINT
    if raw and ":" in raw:
        try:
            port = int(raw.rsplit(":", 1)[1])
            log.warning(
                f"Using fallback listen port from SERVER_ENDPOINT: {port} "
                "(wg show unavailable — verify this matches the server's actual listen-port)"
            )
            return port
        except ValueError:
            pass

    raise RuntimeError(
        "Cannot determine server listen port. "
        "Set SERVER_ENDPOINT=host:port in .env, or ensure the wg binary can reach the interface."
    )


def get_live_endpoint() -> str:
    """
    Build endpoint as `host:port`.
    Host is taken from SERVER_ENDPOINT (env var, strip any port suffix).
    Port is read from `wg show` (live server state) with env fallback.
    """
    if not SERVER_ENDPOINT:
        raise RuntimeError("SERVER_ENDPOINT is not configured in .env")
    host = SERVER_ENDPOINT.rsplit(":", 1)[0]
    port = _get_listen_port()
    endpoint = f"{host}:{port}"
    log.debug(f"Endpoint resolved: {endpoint}")
    return endpoint


def _derive_ipv6(ipv4: str) -> str:
    """Derive paired IPv6 address from IPv4: 10.66.66.X → fd42:42:42::X"""
    last = ipv4.rsplit(".", 1)[1]
    return f"fd42:42:42::{last}"


# ── Live peer statistics ──────────────────────────────────────────────────────

def get_peer_stats() -> dict[str, dict]:
    """
    Run `wg show <WG_INTERFACE> dump` and return per-peer stats keyed by public key.

    Each value dict contains:
        last_handshake  — Unix timestamp (int), 0 if no handshake ever
        rx_bytes        — bytes received by the server from this peer
        tx_bytes        — bytes sent by the server to this peer
        endpoint        — "host:port" string or None

    Returns an empty dict when wg binary is not installed (dev mode).
    Raises WireGuardError when wg is present but the command fails.

    `wg show <iface> dump` format (tab-separated):
      Line 0 (interface): priv-key  pub-key  listen-port  fwmark
      Lines 1+ (peers):   pub-key   psk   endpoint   allowed-ips
                          latest-handshake   transfer-rx   transfer-tx
                          persistent-keepalive
    """
    try:
        raw = subprocess.check_output(
            ["wg", "show", WG_INTERFACE, "dump"],
            stderr=subprocess.DEVNULL, timeout=_TIMEOUT,
        ).decode().strip()
    except FileNotFoundError:
        log.debug("wg not found — returning empty peer stats (dev mode)")
        return {}
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or b"").decode(errors="replace").strip()
        raise WireGuardError(f"wg show dump failed: {stderr}") from e
    except subprocess.TimeoutExpired:
        raise WireGuardError("wg show dump timed out")

    peers: dict[str, dict] = {}
    lines = raw.splitlines()

    # Skip the first line (interface line: private-key, public-key, port, fwmark)
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue

        pub_key  = parts[0]
        endpoint = parts[2]
        try:    last_hs = int(parts[4])
        except ValueError: last_hs = 0
        try:    rx = int(parts[5])
        except ValueError: rx = 0
        try:    tx = int(parts[6])
        except ValueError: tx = 0

        peers[pub_key] = {
            "last_handshake": last_hs,
            "rx_bytes":       rx,
            "tx_bytes":       tx,
            "endpoint":       endpoint if endpoint not in ("(none)", "") else None,
        }
        log.debug(f"peer {pub_key[:8]}… hs={last_hs} rx={rx} tx={tx}")

    log.debug(f"get_peer_stats: {len(peers)} peer(s) parsed")
    return peers


# ── Peer management ───────────────────────────────────────────────────────────

def add_peer(public_key: str, ip: str, psk: str) -> bool:
    """
    Add peer to the WireGuard interface.
    Sets dual-stack allowed-ips (IPv4/32 + IPv6/128) and PSK via stdin.

    Returns True  — peer added successfully.
    Returns False — wg binary not found (dev mode, non-fatal).
    Raises WireGuardError — wg is installed but the command failed.
    """
    ipv6 = _derive_ipv6(ip)
    try:
        subprocess.run(
            [
                "wg", "set", WG_INTERFACE, "peer", public_key,
                "allowed-ips", f"{ip}/32,{ipv6}/128",
                "preshared-key", "/dev/stdin",
            ],
            input=psk.encode(),
            check=True, capture_output=True, timeout=_TIMEOUT,
        )
        log.info(
            f"wg: peer added — pubkey={public_key[:8]}… "
            f"ip={ip} ipv6={ipv6} psk=yes"
        )
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
    Never raises — peer removal is always best-effort so that device records
    can still be cleaned up from JSON even if wg is unreachable.
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
        log.warning(f"wg remove peer timed out (non-fatal) — pubkey={public_key[:8]}…")


def _save_config() -> None:
    """Persist wg0 state to its config file. Best-effort; never raises."""
    try:
        subprocess.run(
            ["wg-quick", "save", WG_INTERFACE],
            capture_output=True, timeout=_TIMEOUT,
        )
        log.debug(f"wg-quick save {WG_INTERFACE}")
    except Exception as e:
        log.warning(f"wg-quick save failed: {e}")


# ── Config generation ─────────────────────────────────────────────────────────

def build_client_config(private_key: str, ip: str, psk: str) -> str:
    """
    Generate a WireGuard client config that is 1:1 consistent with the server peer.

    Consistency guarantees:
    - Address:       IPv4/32 + derived IPv6/128  (matches server allowed-ips exactly)
    - Endpoint:      host from SERVER_ENDPOINT + port from `wg show` (live server truth)
    - PresharedKey:  included iff psk is non-empty (mirrors server peer state)
    - AllowedIPs:    0.0.0.0/0,::/0  (full tunnel, both stacks)

    Raises RuntimeError on any missing or invalid server configuration.
    """
    if not SERVER_PUBLIC_KEY:
        raise RuntimeError(
            "SERVER_PUBLIC_KEY is not configured in .env — cannot build client config"
        )
    if not psk:
        raise RuntimeError(
            "PSK must be non-empty — server peer requires PresharedKey"
        )

    ipv6     = _derive_ipv6(ip)
    endpoint = get_live_endpoint()

    # Strict pre-flight validation before writing any file
    host, _, port_str = endpoint.rpartition(":")
    if not host:
        raise RuntimeError(f"Endpoint has no host: {endpoint!r}")
    try:
        int(port_str)
    except ValueError:
        raise RuntimeError(f"Endpoint has non-numeric port: {endpoint!r}")

    log.debug(
        f"Client config — ip={ip} ipv6={ipv6} endpoint={endpoint} "
        f"psk=yes server_pub={SERVER_PUBLIC_KEY[:8]}…"
    )

    return "\n".join([
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {ip}/32,{ipv6}/128",
        f"DNS = {DNS}",
        "",
        "[Peer]",
        f"PublicKey = {SERVER_PUBLIC_KEY}",
        f"PresharedKey = {psk}",
        f"Endpoint = {endpoint}",
        "AllowedIPs = 0.0.0.0/0,::/0",
        "PersistentKeepalive = 25",
    ]) + "\n"
