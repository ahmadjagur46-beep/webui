"""WebUI-level account login / register / logout (multi-tenant).

Separate from MyXL OTP login (which is at /login). End-users register a
webui account first, then inside their session they OTP-login their own
MyXL number(s).
"""
from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, Response

from webui.users import (
    COOKIE_NAME, SESSION_MAX_AGE,
    authenticate, change_password, create_user, get_user, make_session_token, load_users,
)
from webui.deps import get_templates, render

router = APIRouter()


def _render(request: Request, template: str, **ctx):
    templates = get_templates(request)
    base = {"request": request, "active_user": None, "accounts": [], "webui_user": None}
    base.update(ctx)
    return templates.TemplateResponse(request, template, base)


@router.get("/u/login")
def login_page(request: Request, error: str | None = None, info: str | None = None,
               username: str | None = None, next: str | None = None):
    users_count = len(load_users())
    return _render(request, "webui_login.html",
                   mode="login", error=error, info=info,
                   username=username or "", next=(next or "/"),
                   users_count=users_count)


@router.post("/u/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 next: str = Form("/")):
    u = authenticate(username, password)
    if not u:
        from webui import admin as admin_mod
        ip = getattr(request.state, "client_ip", "-")
        admin_mod.record_login_fail(username, ip)
        admin_mod.log_event("login_fail", username, ip, "wrong credentials")
        return _render(request, "webui_login.html",
                       mode="login",
                       error="Username atau password salah.",
                       username=username, next=next,
                       users_count=len(load_users()))
    from webui import admin as admin_mod
    ip = getattr(request.state, "client_ip", "-")
    if admin_mod.is_banned(u["username"]):
        admin_mod.log_event("login_fail", u["username"], ip, "banned account")
        return _render(request, "webui_login.html",
                       mode="login",
                       error="Akun lu kena BAN. Hubungi admin.",
                       username=username, next=next,
                       users_count=len(load_users()))
    ok_lock, lock_msg = admin_mod.check_login_lock(username, ip)
    if not ok_lock:
        admin_mod.log_event("login_fail", username, ip, "rate limited")
        return _render(request, "webui_login.html",
                       mode="login", error=lock_msg,
                       username=username, next=next,
                       users_count=len(load_users()))
    admin_mod.record_login_ok(username, ip)
    admin_mod.log_event("login_ok", u["username"], ip, "login success")
    token = make_session_token(u["username"])
    resp = RedirectResponse(url=next or "/", status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME, value=token,
        max_age=SESSION_MAX_AGE, httponly=True,
        samesite="lax", secure=request.url.scheme == "https",
    )
    return resp


@router.get("/u/register")
def register_page(request: Request, error: str | None = None, info: str | None = None,
                  username: str | None = None):
    return _render(request, "webui_login.html",
                   mode="register", error=error, info=info,
                   username=username or "", next="/",
                   users_count=len(load_users()))


@router.post("/u/register")
def register_submit(request: Request, username: str = Form(...), password: str = Form(...),
                    password_confirm: str = Form(...)):
    if password != password_confirm:
        return _render(request, "webui_login.html",
                       mode="register",
                       error="Password tidak cocok.",
                       username=username, next="/",
                       users_count=len(load_users()))
    ok, err = create_user(username, password)
    if not ok:
        return _render(request, "webui_login.html",
                       mode="register",
                       error=err, username=username, next="/",
                       users_count=len(load_users()))
    token = make_session_token(username)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME, value=token,
        max_age=SESSION_MAX_AGE, httponly=True,
        samesite="lax", secure=request.url.scheme == "https",
    )
    return resp


@router.post("/u/logout")
@router.get("/u/logout")
def logout(request: Request):
    resp = RedirectResponse(url="/u/login", status_code=303)
    resp.delete_cookie(key=COOKIE_NAME)
    return resp


@router.get("/u/account")
def account_page(request: Request, msg: str | None = None, error: str | None = None):
    webui_user = getattr(request.state, "webui_user", None)
    if not webui_user:
        return RedirectResponse(url="/u/login", status_code=303)
    user = get_user(webui_user["username"]) or webui_user
    chat_id = user.get("telegram_chat_id")
    return render(
        request, "webui_account.html",
        username=user["username"],
        has_telegram=chat_id is not None,
        telegram_chat_id=chat_id or "",
        success="Password berhasil diubah." if msg == "ok" else None,
        error=error,
    )


@router.post("/u/account/password")
def account_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
):
    webui_user = getattr(request.state, "webui_user", None)
    if not webui_user:
        return RedirectResponse(url="/u/login", status_code=303)

    username = webui_user["username"]
    user = get_user(username) or webui_user
    chat_id = user.get("telegram_chat_id")

    if new_password != new_password_confirm:
        return render(
            request, "webui_account.html",
            username=username,
            has_telegram=chat_id is not None,
            telegram_chat_id=chat_id or "",
            error="Password baru tidak cocok.",
        )

    ok, err = change_password(username, current_password, new_password)
    if not ok:
        return render(
            request, "webui_account.html",
            username=username,
            has_telegram=chat_id is not None,
            telegram_chat_id=chat_id or "",
            error=err,
        )

    return RedirectResponse(url="/u/account?msg=ok", status_code=303)
