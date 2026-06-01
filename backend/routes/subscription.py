import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from storage import update_device_subscription
from wireguard import WireGuardError, disable_peer, enable_peer

log = logging.getLogger(__name__)
router = APIRouter()


class SubscriptionUpdate(BaseModel):
    type: str
    expires_at: int = 0


@router.patch("/{device_id}/subscription")
def update_subscription(device_id: str, body: SubscriptionUpdate):
    if body.type not in ("time", "unlimited"):
        raise HTTPException(400, "type must be 'time' or 'unlimited'")
    if body.type == "time" and body.expires_at <= 0:
        raise HTTPException(400, "expires_at must be a positive Unix timestamp")

    try:
        _username, device = update_device_subscription(device_id, body.type, body.expires_at)
    except KeyError as e:
        raise HTTPException(404, str(e))

    sub     = device.get("subscription", {})
    pub_key = device.get("public_key", "")
    ip      = device.get("ip", "")

    if pub_key:
        if sub.get("active", True) and ip:
            try:
                enable_peer(pub_key, ip)
            except WireGuardError as e:
                log.warning("update_subscription: enable_peer failed for '%s': %s", device.get("name"), e)
        elif not sub.get("active", True):
            try:
                disable_peer(pub_key)
            except WireGuardError as e:
                log.warning("update_subscription: disable_peer failed for '%s': %s", device.get("name"), e)

    return {"ok": True, "data": device}
