from fastapi import APIRouter
from system_monitor import get_snapshot

router = APIRouter()


@router.get("/status")
def system_status():
    snap = get_snapshot()
    return {"ok": True, "data": snap}
