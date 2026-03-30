from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Response

from app.security import COOKIE_MAX_AGE, COOKIE_NAME, auth_enabled, is_valid_login_token, make_session_cookie_value

router = APIRouter(prefix="/api/auth", tags=["auth"])


class TokenLoginPayload(BaseModel):
    token: str


@router.post("/login")
def login_with_token(payload: TokenLoginPayload, response: Response):
    if auth_enabled() and not is_valid_login_token(payload.token):
        raise HTTPException(status_code=401, detail="Token 无效")

    response.set_cookie(
        key=COOKIE_NAME,
        value=make_session_cookie_value(),
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return {"success": True}


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"success": True}


@router.get("/status")
def auth_status():
    return {"enabled": auth_enabled()}
