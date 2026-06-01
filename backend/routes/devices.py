from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from storage import CONFIGS_DIR, find_device

router = APIRouter()


@router.get("/{device_id}/config")
def download_config(device_id: str):
    result = find_device(device_id)
    if not result:
        raise HTTPException(404, "Device not found")

    username, device = result
    config_file = (CONFIGS_DIR / device.get("config_file", "")).resolve()

    # Path-traversal guard — config_file must be inside CONFIGS_DIR
    if not str(config_file).startswith(str(CONFIGS_DIR.resolve())):
        raise HTTPException(403, "Forbidden")

    if not config_file.exists():
        raise HTTPException(404, "Config file not found on disk")

    filename = f"{username}-{device['name']}.conf"
    return FileResponse(
        config_file,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
