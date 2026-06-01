import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from storage import update_user_subscription
from wireguard import WireGuardError, disable_peer, enable_peer

log = logging.getLogger(__name__)
router = APIRouter()


class SubscriptionUpdate(BaseModel):
    type: str
    expires_at: int = 0


@router.patch("/{username}/subscription")
def update_subscription(username: str, body: SubscriptionUpdate):
    if body.type not in ("time", "unlimited", "disabled"):
        raise HTTPException(400, "type must be 'time', 'unlimited', or 'disabled'")
    if body.type == "time" and body.expires_at <= 0:
        raise HTTPException(400, "expires_at must be a positive Unix timestamp")

    try:
        udata = update_user_subscription(username, body.type, body.expires_at)
    except KeyError as e:
        raise HTTPException(404, str(e))

    sub     = udata.get("subscription", {})
    devices = udata.get("devices", [])
    active  = sub.get("active", True)

    for dev in devices:
        pub_key = dev.get("public_key", "")
        ip      = dev.get("ip", "")
        if not pub_key:
            continue
        if active and ip:
            try:
                enable_peer(pub_key, ip)
            except WireGuardError as e:
                log.warning(
                    "update_subscription: enable_peer failed for device '%s' (user '%s'): %s",
                    dev.get("name"), username, e,
                )
        else:
            try:
                disable_peer(pub_key)
            except WireGuardError as e:
                log.warning(
                    "update_subscription: disable_peer failed for device '%s' (user '%s'): %s",
                    dev.get("name"), username, e,
                )

    return {"ok": True, "data": {"subscription": sub}}
