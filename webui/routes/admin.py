"""Admin panel routes: members, login log, kick/ban, shared data editor, admin aliases. Admin-only."""
import json

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse

from webui import admin as admin_mod
from webui.deps import render, get_active_user_safe
from webui.users import load_users
from webui.storage import get_storage
from webui.storage.backend import SHARED_HOT, SHARED_HOT2

router = APIRouter()

SHARED_KEYS = {"hot": SHARED_HOT, "hot2": SHARED_HOT2}


def _admin_guard(request: Request):
    """Return (webui_user, None) if admin; (None, error_response) otherwise."""
    token = request.cookies.get("mecli_session")
    from webui.users import parse_session_token
    uname = parse_session_token(token)
    if not uname or not admin_mod.is_admin(uname):
        return None, render(request, "error.html", title="Akses ditolak",
                            message="Halaman ini khusus admin.", active_user=get_active_user_safe())
    return uname, None


@router.get("/admin")
def admin_home(request: Request):
    uname, err = _admin_guard(request)
    if err:
        return err
    members = admin_mod.list_members()
    logs = admin_mod.read_log(120)
    state = admin_mod._load_state()
    return render(request, "tools/admin.html", title="Admin Panel",
                  members=members, logs=logs, me=uname,
                  epoch=state.get("session_epoch", {}),
                  aliases=state.get("admins", []),
                  active_user=get_active_user_safe())


@router.post("/admin/kick")
def admin_kick(request: Request, username: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    if username == uname:
        return RedirectResponse(url="/admin", status_code=303)
    admin_mod.kick_user(username)
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/ban")
def admin_ban(request: Request, username: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    if username == uname:
        return RedirectResponse(url="/admin", status_code=303)
    admin_mod.ban_user(username)
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/unban")
def admin_unban(request: Request, username: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    admin_mod.unban_user(username)
    return RedirectResponse(url="/admin", status_code=303)


# ============================ ADMIN ALIASES ============================

@router.post("/admin/alias/add")
def admin_alias_add(request: Request, username: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    if not admin_mod.add_admin(username):
        return render(request, "error.html", title="Gagal",
                      message="Username invalid / root admin gak bisa diubah.")
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/alias/remove")
def admin_alias_remove(request: Request, username: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    admin_mod.remove_admin(username)
    return RedirectResponse(url="/admin", status_code=303)


# ============================ DECOY PUSH ============================
# Salin decoy admin (builtin + custom) ke SEMUA member — konsisten dengan
# prinsip "admin ubah, member ikut".

@router.post("/admin/decoy/push")
def admin_decoy_push(request: Request):
    uname, err = _admin_guard(request)
    if err:
        return err
    from webui.storage.tenant import current_storage_username, read_user_text
    from webui.storage.backend import USER_DECOY_DIR
    storage = get_storage()
    token = current_storage_username.set(uname)
    try:
        keys = [k for k in storage.list_blobs(uname, f"{USER_DECOY_DIR}/") if k.endswith(".json")]
        payloads = {k: read_user_text(k) for k in keys}
    finally:
        current_storage_username.reset(token)
    pushed = 0
    for u in load_users():
        target = u.get("username")
        if not target or target == uname:
            continue
        for k, raw in payloads.items():
            if raw is not None:
                storage.put_blob(target, k, raw)
                pushed += 1
    return RedirectResponse(url=f"/admin?msg=Decoy+ke-push+ke+semua+member+({pushed}+file)", status_code=303)


# ============================ SHARED DATA EDITOR ============================
# Edit file shared (hot.json, hot2.json, dst) — semua member baca dari sini,
# jadi ubah di sini = berubah juga di halaman member.

@router.get("/admin/data")
def admin_data(request: Request, key: str = "", msg: str = ""):
    uname, err = _admin_guard(request)
    if err:
        return err
    storage = get_storage()
    files = sorted(storage.list_blobs(None, "shared/"))
    selected = key if key in files else (files[0] if files else "")
    content = storage.get_blob(None, selected) or "" if selected else ""
    parsed = None
    pretty = content
    if content:
        try:
            parsed = json.loads(content)
            pretty = json.dumps(parsed, indent=2, ensure_ascii=False)
        except Exception:
            parsed = None
    return render(request, "tools/admin_data.html", title="Data Shared",
                  files=files, selected=selected, content=pretty,
                  is_json=parsed is not None, msg=msg, me=uname,
                  active_user=get_active_user_safe())


@router.post("/admin/data/save")
def admin_data_save(request: Request, key: str = Form(...), content: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    files = get_storage().list_blobs(None, "shared/")
    if key not in files:
        return render(request, "error.html", title="Key invalid",
                      message=f"'{key}' bukan file shared yang valid.")
    try:
        json.loads(content)  # validate before write
    except Exception as e:
        return render(request, "error.html", title="JSON invalid",
                      message=f"Gak disimpan (biar data member gak rusak): {e}")
    get_storage().put_blob(None, key, content)
    return RedirectResponse(url=f"/admin/data?key={key}&msg=Tersimpan", status_code=303)


@router.post("/admin/data/new")
def admin_data_new(request: Request, name: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    name = name.strip().lstrip("/").removeprefix("shared/")
    if not name or "/" in name or ".." in name or not name.endswith(".json"):
        return render(request, "error.html", title="Nama invalid",
                      message="Pakai nama sederhana, harus .json. Contoh: pulsa-decoy.json")
    key = f"shared/{name}"
    if key not in get_storage().list_blobs(None, "shared/"):
        get_storage().put_blob(None, key, "[]")
    return RedirectResponse(url=f"/admin/data?key={key}&msg=File+baru+dibuat", status_code=303)


@router.post("/admin/data/delete")
def admin_data_delete(request: Request, key: str = Form(...)):
    uname, err = _admin_guard(request)
    if err:
        return err
    if key in (SHARED_HOT, SHARED_HOT2):
        return render(request, "error.html", title="Dilarang",
                      message=f"{key} dipakai halaman Hot/Hot-2. Kosongin isinya jadi [] aja, jangan dihapus.")
    files = get_storage().list_blobs(None, "shared/")
    if key in files:
        get_storage().delete_blob(None, key)
    return RedirectResponse(url="/admin/data?msg=File+dihapus", status_code=303)
