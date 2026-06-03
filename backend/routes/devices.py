import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from storage import CONFIGS_DIR, find_device

log = logging.getLogger(__name__)
router = APIRouter()


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


@router.get("/{device_id}/config")
def download_config(device_id: str):
    username, device, config_file = _resolve_config(device_id)
    filename = f"{username}-{device['name']}.conf"
    return FileResponse(
        config_file,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{device_id}/config-text")
def get_config_text(device_id: str):
    """Return the raw WireGuard .conf as plain text for clipboard copy.

    Uses the same auth and path-traversal checks as /config.
    The file on disk is never modified.
    """
    _, _, config_file = _resolve_config(device_id)
    text = config_file.read_text(encoding="utf-8")
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")
