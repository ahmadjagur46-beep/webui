import json
import time
import datetime
import base64
import hashlib
from fastapi import APIRouter, Request, Form, Query
from fastapi.responses import RedirectResponse

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from app.client.engsel import get_package, get_family, send_api_request, unsubscribe
from app.service.auth import AuthInstance
from webui.deps import render, get_active_user_safe, list_accounts
from webui.routes.decoy_settings import (
    BUILTIN_SLOTS,
    list_custom_decoys,
    list_builtin_decoys,
    _load_json,
    _save_json,
    USER_DECOY_DIR,
)
from webui.storage.tenant import read_user_json, write_user_json

router = APIRouter()


# ============================ HELPER: GET ALL DECOYS ============================

def _load_all_decoys() -> dict:
    """Return dict of all decoys (builtin + custom) keyed by their internal key."""
    out = {}
    for b in list_builtin_decoys():
        key = b["key"]
        data = b.get("data", {})
        if data:
            out[key] = {"key": key, **data, "is_builtin": True}
    for c in list_custom_decoys():
        name = c["name"]
        out[name] = {"key": name, **c["data"], "is_builtin": False}
    return out


def _filter_decoys(decoys: dict, query: str) -> list:
    q = (query or "").strip().lower()
    out = []
    for key, item in decoys.items():
        if not isinstance(item, dict):
            continue
        name = str(item.get("option_name", item.get("family_name", key))).lower()
        code = str(item.get("family_code", item.get("variant_code", item.get("option_code", "")))).lower()
        if q and (q not in name and q not in key and q not in code):
            continue
        out.append({"key": key, **item})
    return out


# ============================ DECOY SEARCH ============================

@router.get("/decoy/search")
def decoy_search_get(request: Request, q: str | None = Query(None)):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    decoys = _load_all_decoys()
    results = _filter_decoys(decoys, q) if q else list(decoys.values())
    return render(request, "tools/decoy_search.html", title="Decoy Search", results=results, query=q, active_user=user)


@router.post("/decoy/search")
def decoy_search_post(request: Request, query: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    decoys = _load_all_decoys()
    results = _filter_decoys(decoys, query) if query else list(decoys.values())
    return render(request, "tools/decoy_search.html", title="Decoy Search", results=results, query=query, active_user=user)


# ============================ REAL DECOY FINDER ============================

@router.get("/decoy/finder")
def decoy_finder_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/decoy_finder.html", title="Real Decoy Finder", output=None, family_code="", option_code="", active_user=user)


@router.post("/decoy/finder")
async def decoy_finder_post(request: Request, action: str = Form("search"), family_code: str = Form(""), option_code: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")

    form = await request.form()
    action = form.get("action", "search")
    fam_in = form.get("family_code", "").strip()
    opt_in = form.get("option_code", "").strip()

    output_html = ""
    saved_msg = ""

    if action == "save_decoy":
        decoy_key = form.get("decoy_key", "").strip().lower()
        opt_name = form.get("opt_name", "").strip()
        fc = form.get("fam_code", "").strip()
        vc = form.get("var_code", "").strip()
        oc = form.get("opt_code", "").strip()
        price = form.get("price", "1000")
        if decoy_key and oc:
            data = {
                "family_name": opt_name,
                "family_code": fc,
                "variant_code": vc,
                "option_code": oc,
                "is_enterprise": False,
                "migration_type": "NONE",
                "order": 1,
                "price": int(price) if str(price).isdigit() else 1000,
                "option_name": opt_name,
                "base_method": "balance",
            }
            _save_json(f"{USER_DECOY_DIR}/custom-{decoy_key}.json", data)
            saved_msg = f"<div style='background:rgba(16,185,129,0.2);border:1px solid #10b981;color:#10b981;padding:10px;border-radius:6px;margin-bottom:12px;font-size:12px;'><b>Berhasil!</b> Decoy '{opt_name}' disimpan & siap dipakai.</div>"
        else:
            saved_msg = "<div style='background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;margin-bottom:12px;font-size:12px;'><b>Gagal:</b> Data decoy tidak lengkap.</div>"
        return render(request, "tools/decoy_finder.html", title="Real Decoy Finder", output=saved_msg, family_code=fam_in, option_code=opt_in, active_user=user)

    if opt_in:
        try:
            pkg = get_package(AuthInstance.api_key, user["tokens"], opt_in)
            if pkg and pkg.get("package_option"):
                opt = pkg["package_option"]
                opt_name = opt.get("name", "Paket Option Asli")
                real_price = opt.get("price", 1000)
                var_code = opt.get("variant_code", "")
                fam_code = opt.get("family_code", "")
                safe_key = f"decoy_opt_{int(time.time())}"
                output_html = f"""
                <div style='background:rgba(3,7,18,0.9);border-left:4px solid #10b981;margin:10px 0;padding:12px;border-radius:8px;border:1px solid var(--border-color);word-break:break-all;'>
                    <h5 style='margin:0;color:var(--text-main);font-size:13px;'>{opt_name}</h5>
                    <p style='color:var(--text-muted);font-size:11px;margin:4px 0;'>Option Code: <b style='color:#a3e635;'>{opt_in}</b></p>
                    <p style='color:var(--text-muted);font-size:11px;margin:0 0 8px 0;'>Harga: <b>Rp {real_price:,}</b> | <span style='color:#10b981;font-weight:bold;'>Aktif & Usable</span></p>
                    <form method='POST'>
                        <input type='hidden' name='action' value='save_decoy'>
                        <input type='hidden' name='decoy_key' value='{safe_key}'>
                        <input type='hidden' name='opt_name' value='{opt_name}'>
                        <input type='hidden' name='fam_code' value='{fam_code}'>
                        <input type='hidden' name='var_code' value='{var_code}'>
                        <input type='hidden' name='opt_code' value='{opt_in}'>
                        <input type='hidden' name='price' value='{real_price}'>
                        <button type='submit' style='width:100%;background:linear-gradient(135deg,#10b981 0%,#047857 100%);color:white;border:none;padding:10px;border-radius:6px;font-weight:bold;font-size:12px;cursor:pointer;'>💾 Simpan Decoy Aktif</button>
                    </form>
                </div>"""
            else:
                output_html = "<div style='background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;font-size:12px;'>Option code tidak ditemukan di backend API.</div>"
        except Exception as e:
            output_html = f"<div style='background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;font-size:12px;'>Error API: {str(e)}</div>"

    elif fam_in:
        try:
            data = get_family(AuthInstance.api_key, user["tokens"], fam_in, False, None)
            if data and isinstance(data, dict) and ("package_variants" in data or "package_family" in data):
                fam_name = data.get("package_family", {}).get("name", "Family Asli")
                variants = data.get("package_variants", [])
                output_html = f"<h4 style='color:var(--accent-blue);font-size:13px;margin-bottom:10px;'>✨ Family: {fam_name}</h4>"
                for v in variants:
                    v_name = v.get("name", "-")
                    v_code = v.get("variant_code", "-")
                    output_html += f"<div style='margin:8px 0;padding:10px;background:rgba(3,7,18,0.7);border:1px solid var(--border-color);border-radius:6px;'><b>{v_name}</b> <span style='color:#a3e635;font-size:11px;'>({v_code})</span></div>"
            else:
                output_html = "<div style='background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;font-size:12px;'>Family code tidak valid atau tidak ditemukan.</div>"
        except Exception as e:
            output_html = f"<div style='background:rgba(239,68,68,0.2);border:1px solid #ef4444;color:#ef4444;padding:10px;border-radius:6px;font-size:12px;'>Error API: {str(e)}</div>"

    return render(request, "tools/decoy_finder.html", title="Real Decoy Finder", output=output_html, family_code=fam_in, option_code=opt_in, active_user=user)


# ============================ CUSTOM API EXECUTION (TEMBAK PATH) ============================

@router.get("/tools/api-exec")
def api_exec_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/api_exec.html", title="Custom API Execution", response_text="", form_data={}, active_user=user)


@router.post("/tools/api-exec")
async def api_exec_post(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")

    form = await request.form()
    api_method = form.get("api_method", "POST")
    api_path = form.get("api_path", "api/v8/packages/quota-details")
    api_payload = form.get("api_payload", "{}")
    form_data = {"api_method": api_method, "api_path": api_path, "api_payload": api_payload}

    response_text = ""
    try:
        payload_dict = json.loads(api_payload) if api_payload.strip() else {}
        id_tok = user["tokens"].get("id_token", "")
        res = send_api_request(AuthInstance.api_key, api_path.strip(), payload_dict, id_tok, api_method.strip().upper())
        response_text = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        response_text = json.dumps({"error": str(e)}, indent=2, ensure_ascii=False)

    return render(request, "tools/api_exec.html", title="Custom API Execution", response_text=response_text, form_data=form_data, active_user=user)


# ============================ STORE FINDER (CARI TOKO) ============================

@router.get("/tools/store-finder")
def store_finder_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/store_finder.html", title="Cari Toko", output="", active_user=user)


@router.post("/tools/store-finder")
def store_finder_post(request: Request, lat: str = Form(""), lon: str = Form(""), radius: str = Form("5000")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if lat.strip() and lon.strip():
        try:
            payload = {"latitude": float(lat), "longitude": float(lon), "radius": int(radius)}
            res = send_api_request(AuthInstance.api_key, "api/v8/stores/nearby", payload, user["tokens"]["id_token"], "POST")
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/store_finder.html", title="Cari Toko", output=output, active_user=user)


# ============================ CIRCLE NET ============================

@router.get("/tools/circle-net")
def circle_net(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    try:
        res = send_api_request(AuthInstance.api_key, "api/v8/circle-net", {}, user["tokens"]["id_token"], "POST")
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = f"Error: {str(e)}"
    return render(request, "tools/circle_net.html", title="Circle Net", output=output, active_user=user)


# ============================ TRANSFER PULSA ============================

@router.get("/tools/transfer-pulsa")
def transfer_pulsa_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/transfer_pulsa.html", title="Transfer Pulsa", output="", active_user=user)


@router.post("/tools/transfer-pulsa")
def transfer_pulsa_post(request: Request, destination_msisdn: str = Form(""), amount: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if destination_msisdn.strip() and amount.strip():
        try:
            res = send_api_request(
                AuthInstance.api_key,
                "api/v8/balance/transfer",
                {"destination_msisdn": destination_msisdn.strip(), "amount": int(amount) if amount.isdigit() else 0},
                user["tokens"]["id_token"],
                "POST",
            )
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/transfer_pulsa.html", title="Transfer Pulsa", output=output, destination_msisdn=destination_msisdn, amount=amount, active_user=user)


# ============================ REGISTER FEATURE (NIK/KK) ============================

@router.get("/tools/register-feature")
def register_feature_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/register_feature.html", title="Register Kartu", output="", active_user=user)


@router.post("/tools/register-feature")
def register_feature_post(request: Request, nik: str = Form(""), kk: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if nik.strip() and kk.strip():
        try:
            res = send_api_request(AuthInstance.api_key, "api/v8/account/register", {"nik": nik.strip(), "kk": kk.strip()}, user["tokens"]["id_token"], "POST")
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/register_feature.html", title="Register Kartu", output=output, nik=nik, kk=kk, active_user=user)


# ============================ VALIDATE FEATURE ============================

@router.get("/tools/validate-feature")
def validate_feature_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/validate_feature.html", title="Validate Data", output="", active_user=user)


@router.post("/tools/validate-feature")
def validate_feature_post(request: Request, validation_code: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if validation_code.strip():
        try:
            res = send_api_request(AuthInstance.api_key, "api/v8/account/validate", {"code": validation_code.strip()}, user["tokens"]["id_token"], "POST")
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/validate_feature.html", title="Validate Data", output=output, validation_code=validation_code, active_user=user)


# ============================ PUK CORE ============================

@router.get("/tools/puk-core")
def puk_core(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    try:
        res = send_api_request(AuthInstance.api_key, "api/v8/profile/puk", {}, user["tokens"]["id_token"], "POST")
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = f"Error: {str(e)}"
    return render(request, "tools/puk_core.html", title="PUK Core", output=output, active_user=user)


# ============================ SIDOMPUL CHECK ============================

@router.get("/tools/sidompul")
def sidompul_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/sidompul.html", title="Sidompul Server Check", output="", active_user=user)


@router.post("/tools/sidompul")
def sidompul_post(request: Request, msisdn: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if msisdn.strip():
        try:
            res = send_api_request(AuthInstance.api_key, "api/v8/sidompul/check", {"msisdn": msisdn.strip()}, user["tokens"]["id_token"], "POST")
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/sidompul.html", title="Sidompul Server Check", output=output, msisdn=msisdn, active_user=user)


# ============================ AKUN DB ============================

@router.get("/tools/akun-db")
def akun_db(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    accounts = list_accounts()
    return render(request, "tools/akun_db.html", title="Database Akun", accounts=accounts, active_user=user)


# ============================ GET BANNERS ============================

@router.get("/tools/banners")
def get_banners(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    try:
        res = send_api_request(AuthInstance.api_key, "api/v8/configs/store/segments", {"is_enterprise": False, "lang": "en"}, user["tokens"]["id_token"], "POST")
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = f"Error: {str(e)}"
    return render(request, "tools/raw_json.html", title="Get Banners", output=output, active_user=user)


# ============================ GET SEGMENTS SFY ============================

@router.get("/tools/segments-sfy")
def get_segments_sfy(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    try:
        # Old app used dashboard/api/v8/segments with access_token in payload
        res = send_api_request(
            AuthInstance.api_key,
            "dashboard/api/v8/segments",
            {"access_token": user["tokens"].get("access_token", "")},
            user["tokens"]["id_token"],
            "POST",
        )
        output = json.dumps(res, indent=2, ensure_ascii=False)
    except Exception as e:
        output = f"Error: {str(e)}"
    return render(request, "tools/raw_json.html", title="Get Segments SFY", output=output, active_user=user)


# ============================ FAMILY BROWSER ============================

@router.get("/tools/family-browser")
def family_browser_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/family_browser.html", title="Family Browser", output="", active_user=user)


@router.post("/tools/family-browser")
def family_browser_post(request: Request, family_code: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if family_code.strip():
        try:
            data = get_family(AuthInstance.api_key, user["tokens"], family_code.strip())
            output = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/family_browser.html", title="Family Browser", output=output, family_code=family_code, active_user=user)


# ============================ UNSUBSCRIBE ============================

@router.get("/tools/unsubscribe")
def unsubscribe_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    return render(request, "tools/unsubscribe.html", title="Unsubscribe", output="", active_user=user)


@router.post("/tools/unsubscribe")
def unsubscribe_post(request: Request, quota_code: str = Form(""), product_domain: str = Form(""), product_subscription_type: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    output = ""
    if quota_code.strip() and product_domain.strip() and product_subscription_type.strip():
        try:
            res = unsubscribe(AuthInstance.api_key, user["tokens"], quota_code.strip(), product_domain.strip(), product_subscription_type.strip())
            output = json.dumps(res, indent=2, ensure_ascii=False)
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/unsubscribe.html", title="Unsubscribe", output=output, quota_code=quota_code, product_domain=product_domain, product_subscription_type=product_subscription_type, active_user=user)


# ============================ SAVED PACKAGES ============================

@router.get("/tools/saved-packages")
def saved_packages_get(request: Request):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    saved = read_user_json("saved_packages.json", default={})
    return render(request, "tools/saved_packages.html", title="Saved Packages", saved=saved, active_user=user)


@router.post("/tools/saved-packages")
def saved_packages_post(request: Request, action: str = Form(""), option_code: str = Form(""), family_code: str = Form(""), custom_name: str = Form("")):
    user = get_active_user_safe()
    if not user:
        return render(request, "error.html", title="Login dulu", message="Belum ada akun aktif.")
    saved = read_user_json("saved_packages.json", default={})
    if action == "add" and (option_code.strip() or family_code.strip()):
        key = option_code.strip() or family_code.strip()
        saved[key] = {
            "option_code": option_code.strip(),
            "family_code": family_code.strip(),
            "custom_name": custom_name.strip(),
            "saved_at": datetime.datetime.now().isoformat(),
        }
        write_user_json("saved_packages.json", saved)
    elif action == "delete" and option_code.strip():
        saved.pop(option_code.strip(), None)
        write_user_json("saved_packages.json", saved)
    return RedirectResponse(url="/tools/saved-packages", status_code=303)


# ============================ XDATA DECRYPTER ============================

@router.get("/tools/xdata")
def xdata_get(request: Request):
    user = get_active_user_safe()
    return render(request, "tools/xdata.html", title="Decrypt Xdata", output=None, xdata="", xtime="", active_user=user)


@router.post("/tools/xdata")
def xdata_post(request: Request, xdata: str = Form(""), xtime: str = Form("")):
    from app.service.crypto_helper import XDATA_KEY
    user = get_active_user_safe()
    output = None
    xd = xdata.strip()
    xt = xtime.strip()
    if xd and xt:
        try:
            ct = base64.urlsafe_b64decode(xd + "=" * ((4 - len(xd) % 4) % 4))
            last_err = None
            for cand in (xt, str(int(xt) * 1000) if xt.isdigit() else None):
                if cand is None:
                    continue
                iv = hashlib.sha256(cand.encode()).hexdigest()[:16].encode()
                try:
                    pt = unpad(AES.new((XDATA_KEY or "").encode(), AES.MODE_CBC, iv).decrypt(ct), 16)
                    output = json.dumps(json.loads(pt), indent=2, ensure_ascii=False)
                    break
                except Exception as e:
                    last_err = e
            if output is None:
                output = f"Error: {last_err}"
        except Exception as e:
            output = f"Error: {str(e)}"
    return render(request, "tools/xdata.html", title="Decrypt Xdata", output=output, xdata=xd, xtime=xt, active_user=user)
