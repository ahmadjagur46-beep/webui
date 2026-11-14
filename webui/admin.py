"""Admin panel: session list, login log, kick/ban. Plus rate limiting & bans.

Design:
- Bans & kick revocation live in webui_data/admin_state.json (users.json is
  schema-locked by sqlite save_users; keeping admin state separate avoids
  schema churn). Banned flag is ALSO written into the users table row so a
  banned user cannot re-register the same username.
- Login attempts are rate-limited per-IP AND per-username (5 fails -> 15 min
  lockout) to stop credential stuffing.
- Login log (webui_data/login_log.jsonl, capped ~5000 lines) records every
  login success/fail with IP + UA.
- Sessions: cookie tokens are itsdangerous-signed; "kick" works by storing a
  per-user `session_epoch` in admin_state; middleware bumps it on kick so all
  existing cookies for that user fail (epoch embedded in token payload).
"""
import json
import time
from pathlib import Path

from webui.users import WEBUI_DATA, load_users, save_users

STATE_FILE = WEBUI_DATA / "admin_state.json"
LOG_FILE = WEBUI_DATA / "login_log.jsonl"
LOG_MAX_LINES = 5000

ADMIN_USERS = ("ahmadjagur",)

MAX_FAILS = 5
LOCKOUT_SECS = 15 * 60


def _load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"banned": [], "session_epoch": {}, "login_fail": {}, "admins": []}


def _save_state(state: dict) -> None:
    WEBUI_DATA.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def list_admins() -> list[str]:
    s = _load_state().get("admins", [])
    return [a for a in s if a != "ahmadjagur"]  # root admin fixed


def add_admin(username: str) -> bool:
    username = (username or "").lower().strip()
    if not username or username == "ahmadjagur":
        return False
    state = _load_state()
    if username not in state.setdefault("admins", []):
        state["admins"].append(username)
    _save_state(state)
    log_event("admin_add", username, "-", "granted admin by root")
    return True


def remove_admin(username: str) -> bool:
    username = (username or "").lower().strip()
    if not username or username == "ahmadjagur":
        return False
    state = _load_state()
    state["admins"] = [a for a in state.get("admins", []) if a != username]
    _save_state(state)
    log_event("admin_remove", username, "-", "revoked admin by root")
    return True


def is_admin(username: str | None) -> bool:
    if not username:
        return False
    if username in ADMIN_USERS:
        return True
    return username in _load_state().get("admins", [])


def is_banned(username: str) -> bool:
    state = _load_state()
    if username in state.get("banned", []):
        return True
    u = next((x for x in load_users() if x.get("username") == username), None)
    return bool(u and u.get("is_banned"))


def ban_user(username: str) -> bool:
    username = (username or "").lower().strip()
    if not username:
        return False
    state = _load_state()
    if username not in state["banned"]:
        state["banned"].append(username)
    state.setdefault("session_epoch", {})[username] = time.time()
    _save_state(state)
    users = load_users()
    for u in users:
        if u.get("username") == username:
            u["is_banned"] = True
    save_users(users)
    log_event("ban", username, "-", "banned by admin")
    return True


def unban_user(username: str) -> bool:
    username = (username or "").lower().strip()
    state = _load_state()
    state["banned"] = [b for b in state.get("banned", []) if b != username]
    _save_state(state)
    users = load_users()
    for u in users:
        if u.get("username") == username:
            u["is_banned"] = False
    save_users(users)
    log_event("unban", username, "-", "unbanned by admin")
    return True


def kick_user(username: str) -> bool:
    """Invalidate all existing session cookies for this user via epoch bump."""
    username = (username or "").lower().strip()
    state = _load_state()
    state.setdefault("session_epoch", {})[username] = time.time()
    _save_state(state)
    log_event("kick", username, "-", "kicked by admin")
    return True


def get_epoch(username: str) -> float:
    return _load_state().get("session_epoch", {}).get(username, 0)


def check_login_lock(username: str, ip: str) -> tuple[bool, str]:
    """Return (allowed, message). Rate-limits by username+IP."""
    state = _load_state()
    fails = state.get("login_fail", {})
    key = f"{username}|{ip}"
    rec = fails.get(key)
    if rec and rec["count"] >= MAX_FAILS and time.time() - rec["last"] < LOCKOUT_SECS:
        wait = int((LOCKOUT_SECS - (time.time() - rec["last"])) // 60) + 1
        return False, f"Terlalu banyak percobaan gagal. Coba lagi dalam ~{wait} menit."
    return True, ""


def record_login_fail(username: str, ip: str) -> None:
    state = _load_state()
    fails = state.setdefault("login_fail", {})
    key = f"{username}|{ip}"
    rec = fails.get(key) or {"count": 0, "last": 0}
    if time.time() - rec["last"] > LOCKOUT_SECS:
        rec["count"] = 0
    rec["count"] += 1
    rec["last"] = time.time()
    fails[key] = rec
    _save_state(state)


def record_login_ok(username: str, ip: str) -> None:
    state = _load_state()
    state.get("login_fail", {}).pop(f"{username}|{ip}", None)
    _save_state(state)


def log_event(kind: str, username: str, ip: str, detail: str) -> None:
    """Append one line to login_log.jsonl (kind: login_ok/login_fail/kick/ban/unban/register)."""
    import datetime
    line = json.dumps({
        "ts": int(time.time()),
        "ts_human": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "kind": kind,
        "username": username,
        "ip": ip,
        "detail": detail,
    })
    try:
        WEBUI_DATA.mkdir(exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
        # cap size
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 800_000:
            lines = LOG_FILE.read_text().splitlines()[-LOG_MAX_LINES:]
            LOG_FILE.write_text("\n".join(lines) + "\n")
    except Exception:
        pass


def read_log(limit: int = 200) -> list[dict]:
    try:
        lines = LOG_FILE.read_text().splitlines()[-limit:]
        out = []
        for ln in reversed(lines):  # newest first
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return out
    except Exception:
        return []


def list_members() -> list[dict]:
    from webui.storage import get_storage
    state = _load_state()
    storage = get_storage()
    out = []
    for u in load_users():
        uname = u.get("username", "")
        try:
            accs = storage.list_blobs(uname, "")
            has_xl = any("refresh-tokens" in a for a in accs)
        except Exception:
            has_xl = False
        out.append({
            "username": uname,
            "created_at": u.get("created_at", 0),
            "banned": uname in state.get("banned", []) or bool(u.get("is_banned")),
            "has_xl_session": has_xl,
            "telegram": bool(u.get("telegram_chat_id")),
        })
    return out
