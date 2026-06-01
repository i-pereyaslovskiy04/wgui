import logging
import os

from fastapi import APIRouter

log = logging.getLogger(__name__)
router = APIRouter()

_ENV_KEYS = {
    "android_play_store": "ANDROID_PLAY_STORE_URL",
    "android_apk":        "ANDROID_APK_URL",
    "windows_exe":        "WINDOWS_EXE_URL",
    "github_repo":        "GITHUB_REPO_URL",
}


@router.get("")
def get_downloads():
    """Return only the download URLs that are configured in the environment."""
    urls: dict[str, str] = {}
    for key, env_var in _ENV_KEYS.items():
        val = os.getenv(env_var, "").strip()
        if val:
            urls[key] = val

    log.debug(f"Downloads endpoint: returning {list(urls.keys())}")
    return {"ok": True, "data": urls}
