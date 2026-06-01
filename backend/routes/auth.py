from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from auth import check_password, create_token

router = APIRouter()


class LoginBody(BaseModel):
    password: str


@router.post("/login")
def login(body: LoginBody):
    if not check_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    return {"ok": True, "data": {"token": create_token()}}
