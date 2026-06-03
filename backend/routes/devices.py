import io
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, StreamingResponse

from storage import CONFIGS_DIR, find_device

log = logging.getLogger(__name__)
router = APIRouter()

try:
    import qrcode as _qrcode
    _QR_OK = True
except ImportError:
    _qrcode = None
    _QR_OK = False
    log.warning("qrcode not installed — QR endpoint unavailable. Run: pip install 'qrcode[pil]>=7.4.2'")


def _resolve_config(device_id: str) -> tuple[str, dict, object]:
    """Shared lookup + path-traversal guard. Returns (username, device, config_path)."""
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
    if not _QR_OK:
        raise HTTPException(503, "QR generation unavailable — qrcode[pil] not installed")

    _, _, config_file = _resolve_config(device_id)
    content = config_file.read_text(encoding="utf-8")

    img = _qrcode.make(content)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")
