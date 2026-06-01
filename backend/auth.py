import os
import uuid
from datetime import datetime, timedelta

_tokens: dict[str, datetime] = {}
TOKEN_TTL_HOURS = 24


def create_token() -> str:
    token = str(uuid.uuid4())
    _tokens[token] = datetime.utcnow() + timedelta(hours=TOKEN_TTL_HOURS)
    return token


def verify_token(token: str) -> bool:
    exp = _tokens.get(token)
    if not exp:
        return False
    if datetime.utcnow() > exp:
        del _tokens[token]
        return False
    return True


def check_password(password: str) -> bool:
    admin_pw = os.getenv("ADMIN_PASSWORD", "changeme123")
    return password == admin_pw
