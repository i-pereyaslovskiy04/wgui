import base64
import io
import json
import logging
import re
import struct
import zlib

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from storage import CONFIGS_DIR, find_device

log = logging.getLogger(__name__)
router = APIRouter()

_EMPTY_VALUE_RE   = re.compile(r"^[A-Za-z0-9]+\s*=\s*$")
_SENSITIVE_KEY_RE = re.compile(r"(?i)^(PrivateKey|PresharedKey)\s*=")

try:
    import qrcode as _qrcode
    _QR_OK = True
except ImportError:
    _qrcode = None
    _QR_OK  = False
    log.warning("qrcode not installed — QR endpoint unavailable. Run: pip install 'qrcode[pil]>=7.4.2'")


# ── WireGuard config helpers ──────────────────────────────────────────────────

def _normalize_wg_config(text: str) -> str:
    """Strip BOM, normalize line endings, remove empty-value lines and trailing spaces.

    The file on disk is never modified; this operates on the in-memory copy.
    """
    text = text.lstrip("﻿")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    for line in text.split("\n"):
        line = line.rstrip()
        if _EMPTY_VALUE_RE.match(line):
            continue
        lines.append(line)
    return "\n".join(lines).strip() + "\n"


def _parse_wg_meta(text: str) -> dict:
    """Extract host, port, dns1, dns2 from a WireGuard config for the Amnezia wrapper."""
    meta = {"host": "", "port": 51820, "dns1": "1.1.1.1", "dns2": "8.8.8.8"}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().lower()
        val = val.strip()

        if key == "dns" and val:
            parts = [d.strip() for d in val.split(",") if d.strip()]
            if parts:
                meta["dns1"] = parts[0]
            if len(parts) > 1:
                meta["dns2"] = parts[1]

        elif key == "endpoint" and val:
            if val.startswith("["):
                bracket = val.rfind("]")
                if bracket >= 0:
                    meta["host"] = val[:bracket + 1]
                    rest = val[bracket + 1:]
                    if rest.startswith(":"):
                        try:
                            meta["port"] = int(rest[1:])
                        except ValueError:
                            pass
            elif ":" in val:
                host, _, port_str = val.rpartition(":")
                meta["host"] = host
                try:
                    meta["port"] = int(port_str)
                except ValueError:
                    pass

    return meta


def _build_amnezia_vpn_url(wg_config: str, description: str = "WireGuard") -> str:
    """Build a vpn://... import URL for Amnezia VPN (plain WireGuard container).

    Encoding pipeline (matches Amnezia client source / config-decoder):
        JSON → zlib(level=8) with 4-byte big-endian uncompressed-size prefix
             → base64url (no padding) → "vpn://" prefix

    The container type "amnezia-wireguard" tells Amnezia VPN to use a plain
    WireGuard tunnel without any AmneziaWG obfuscation parameters.
    """
    meta = _parse_wg_meta(wg_config)

    profile = {
        "defaultContainer": "amnezia-wireguard",
        "description":      description,
        "dns1":             meta["dns1"],
        "dns2":             meta["dns2"],
        "hostName":         meta["host"],
        "port":             meta["port"],
        "containers": [
            {
                "container": "amnezia-wireguard",
                "wireguard": {
                    "last_config":        wg_config,
                    "isThirdPartyConfig": True,
                },
            }
        ],
    }

    json_bytes  = json.dumps(profile, ensure_ascii=False).encode("utf-8")
    log.debug("QR JSON preview: %s", json_bytes[:150].decode("utf-8", errors="replace"))
    compressed  = zlib.compress(json_bytes, level=8)
    # Qt qCompress format: 4-byte big-endian uncompressed size + zlib stream
    qcompress   = struct.pack(">I", len(json_bytes)) + compressed
    b64         = base64.urlsafe_b64encode(qcompress).rstrip(b"=").decode("ascii")
    return f"vpn://{b64}"


# ── Route helpers ─────────────────────────────────────────────────────────────

def _resolve_config(device_id: str) -> tuple[str, dict, object]:
    """Lookup device + path-traversal guard. Returns (username, device, config_path)."""
    result = find_device(device_id)
    if not result:
        raise HTTPException(404, "Device not found")
    username, device = result
    config_file = (CONFIGS_DIR / device.get("config_file", "")).resolve()
    if not str(config_file).startswith(str(CONFIGS_DIR.resolve())):
        raise HTTPException(403, "Forbidden")
    if not config_file.exists():
        raise HTTPException(404, "Config file not found on disk")
    return username, device, config_file


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/{device_id}/config")
def download_config(device_id: str):
    username, device, config_file = _resolve_config(device_id)
    filename = f"{username}-{device['name']}.conf"
    return FileResponse(
        config_file,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{device_id}/qr")
def device_qr(device_id: str):
    """Return a PNG QR code containing an Amnezia VPN vpn://... import URL.

    The QR encodes a plain WireGuard profile (amnezia-wireguard container) so
    that Amnezia VPN imports it as a standard WireGuard tunnel with no obfuscation.
    The .conf file on disk is never modified.
    """
    if not _QR_OK:
        raise HTTPException(503, "QR generation unavailable — qrcode[pil] not installed")

    username, device, config_file = _resolve_config(device_id)
    raw         = config_file.read_text(encoding="utf-8")
    normalized  = _normalize_wg_config(raw)
    description = f"{username} — {device.get('name', device_id)}"
    vpn_url     = _build_amnezia_vpn_url(normalized, description=description)

    log.debug(
        "QR(amnezia-wireguard): user=%s device=%s raw=%d norm=%d vpn_url=%d chars",
        username, device.get("name"), len(raw), len(normalized), len(vpn_url),
    )

    qr = _qrcode.QRCode(
        error_correction=_qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(vpn_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")
