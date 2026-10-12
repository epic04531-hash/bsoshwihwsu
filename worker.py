# -*- coding: utf-8 -*-
"""
2FA Worker — Flask-сервис на Railway.
POST /get-link  { cookie, method, secret }  → { link }
Получает ссылку Persona за 30–120 секунд, поддерживает аккаунты с 2FA.
"""
import os
import re
import json
import time
import logging
import concurrent.futures as _futures

import requests as _requests
from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright

# ─────────────────────────────── настройки ────────────────────────────────── #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

WORKER_SECRET   = os.environ.get("WORKER_SECRET", "mysecret")
DEADLINE        = int(os.environ.get("DEADLINE", 120))   # макс. секунд на попытку
BATCH_SIZE      = int(os.environ.get("BATCH_SIZE", 25))  # параллельных запросов
PAUSE_2FA       = float(os.environ.get("PAUSE_2FA", 2.0))# пауза при 403+2FA
PAUSE_429       = float(os.environ.get("PAUSE_429", 0.5))# пауза при 429

_TARGET_URL = (
    "https://apis.roblox.com/age-verification-service/v1"
    "/persona-id-verification/start-verification"
)
_BODY = {"generateLink": True, "ageEstimation": True, "parentVerification": False}
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
    ),
    "Content-Type": "application/json;charset=utf-8",
    "Origin": "https://www.roblox.com",
    "Referer": "https://www.roblox.com/my/account#!/info",
}

app = Flask(__name__)


# ══════════════════════════ утилиты поиска ссылки ══════════════════════════ #

def _find_link_json(obj, _depth=0):
    """Рекурсивный поиск Persona-ссылки в JSON-объекте."""
    if _depth > 12 or not obj:
        return None
    if isinstance(obj, str):
        if obj.startswith("http") and ("withpersona.com" in obj or "persona.com" in obj):
            return obj
        return None
    if isinstance(obj, list):
        for item in obj:
            r = _find_link_json(item, _depth + 1)
            if r:
                return r
        return None
    if isinstance(obj, dict):
        # прямые известные ключи
        for key in ("verificationUrl", "redirectUrl", "url", "link",
                    "personaUrl", "inquiryUrl", "sessionUrl", "verifyUrl",
                    "inquiryLink", "personaLink"):
            val = obj.get(key, "")
            if isinstance(val, str) and val.startswith("http") and (
                    "withpersona.com" in val or "persona.com" in val):
                return val
        # строим по inq_id — только короткая ссылка без session-token (не протухает)
        inq_id = (obj.get("inquiryId") or obj.get("inquiry_id")
                  or obj.get("inqId") or obj.get("sessionIdentifier"))
        if isinstance(inq_id, str) and inq_id.startswith("inq_"):
            return "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        # глубже
        for val in obj.values():
            r = _find_link_json(val, _depth + 1)
            if r:
                return r
    return None


_RE_FULL_LINK   = re.compile(r'https://[^\s"\'\\]+withpersona\.com[^\s"\'\\]*inquiry-id=(inq_[A-Za-z0-9]+)')
_RE_INQ_ID      = re.compile(r'inquiry-id=(inq_[A-Za-z0-9]+)')
_RE_INQ_RAW     = re.compile(r'"(inq_[A-Za-z0-9]{10,})"')


def extract_link(body: str) -> str | None:
    """Ищет Persona-ссылку сначала в JSON, потом в сыром тексте."""
    if not body:
        return None
    # попытка JSON
    try:
        data = json.loads(body)
        link = _find_link_json(data)
        if link:
            return link
    except Exception:
        pass
    # regex: полная ссылка — берём только inq_id, без session-token
    m = _RE_FULL_LINK.search(body)
    if m:
        return "https://inquiry.withpersona.com/verify?inquiry-id=" + m.group(1)
    # regex: inquiry-id=inq_...
    m = _RE_INQ_ID.search(body)
    if m:
        return "https://inquiry.withpersona.com/verify?inquiry-id=" + m.group(1)
    # regex: "inq_..." в JSON
    m = _RE_INQ_RAW.search(body)
    if m:
        return "https://inquiry.withpersona.com/verify?inquiry-id=inq_" + m.group(1)
    return None


# ══════════════════════════════ Python API метод ════════════════════════════ #

def _build_session(cookie: str) -> _requests.Session:
    """
    Один persistent Session с большим connection pool'ом.
    Критично для скорости: Session() каждый раз = новый TLS handshake (сотни мс),
    а 25 параллельных потоков на одном пуле без этого фактически сериализуются.
    """
    s = _requests.Session()
    s.cookies[".ROBLOSECURITY"] = cookie
    s.headers.update(_HEADERS)
    adapter = _requests.adapters.HTTPAdapter(
        pool_connections=BATCH_SIZE * 2,
        pool_maxsize=BATCH_SIZE * 2,
        max_retries=0,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _get_csrf(session: _requests.Session) -> tuple[str | None, str | None]:
    """Возвращает (csrf_token, link_or_None). link — если с 1-го запроса уже пришла ссылка."""
    try:
        r = session.post(_TARGET_URL, json=_BODY, timeout=6)
        if r.status_code == 200:
            link = extract_link(r.text)
            if link:
                return None, link
        csrf = r.headers.get("x-csrf-token")
        return csrf, None
    except Exception as e:
        logging.warning("_get_csrf error: %s", e)
        return None, None


def _one_request(session: _requests.Session, csrf: str, req_no: int = 0) -> dict:
    try:
        r = session.post(_TARGET_URL, json=_BODY, timeout=6,
                          headers={"x-csrf-token": csrf})
        link = extract_link(r.text) if r.status_code == 200 else None

        # ── лог КАЖДОЙ попытки, чтобы видеть, не теряется ли ссылка ────────
        if link:
            logging.info("  req#%d → 200 LINK: %s", req_no, link)
        elif r.status_code == 200:
            # статус 200, но ссылка не распозналась — показываем сырой body
            logging.warning("  req#%d → 200 NO-LINK, body=%s", req_no, r.text[:300])
        elif r.status_code == 403:
            ch = r.headers.get("rblx-challenge-type", "")
            logging.info("  req#%d → 403 challenge=%s", req_no, ch)
        elif r.status_code == 429:
            logging.info("  req#%d → 429 rate-limit", req_no)
        else:
            logging.info("  req#%d → %d body=%s", req_no, r.status_code, r.text[:150])

        return {
            "status": r.status_code,
            "link": link,
            "challenge": r.headers.get("rblx-challenge-type", ""),
            "new_csrf": r.headers.get("x-csrf-token"),
        }
    except Exception as e:
        logging.warning("  req#%d → ERROR %s", req_no, e)
        return {"status": 0, "link": None, "challenge": "", "new_csrf": None, "err": str(e)}


def run_api(cookie: str) -> str | None:
    """
    Основной метод: параллельные Python-запросы.
    Работает для аккаунтов БЕЗ 2FA (~2 сек) и С 2FA (бот долбит, пока юзер подтверждает).
    """
    deadline = time.time() + DEADLINE
    csrf = None
    consecutive_429 = 0
    session = _build_session(cookie)

    with _futures.ThreadPoolExecutor(max_workers=BATCH_SIZE) as pool:
        while time.time() < deadline:

            # ── получаем CSRF ──────────────────────────────────────────────
            if not csrf:
                csrf, early_link = _get_csrf(session)
                if early_link:
                    logging.info("Early link (no CSRF step): %s", early_link)
                    return early_link
                if not csrf:
                    logging.warning("Нет CSRF — жду 1с")
                    time.sleep(1)
                    continue

            # ── батч параллельных запросов (один общий Session+pool) ────────
            batch_no = getattr(run_api, "_batch_no", 0) + 1
            run_api._batch_no = batch_no
            base = batch_no * BATCH_SIZE
            futs = [pool.submit(_one_request, session, csrf, base + i)
                    for i in range(BATCH_SIZE)]
            results = [f.result() for f in _futures.as_completed(futs, timeout=8)]

            statuses = [r["status"] for r in results]
            found_links = [r["link"] for r in results if r.get("link")]
            elapsed  = deadline - time.time()
            logging.info(
                "batch#%d | statuses=%s | links_found=%d | осталось=%.0fс",
                batch_no, statuses, len(found_links), elapsed,
            )

            got_2fa  = False
            got_429  = False
            need_csrf = False

            for r in results:
                if r.get("link"):
                    logging.info("LINK FOUND (api): %s", r['link'])
                    return r["link"]

                st = r["status"]
                if st == 200:
                    # 200 но без ссылки — пробуем ещё
                    pass
                elif st == 403:
                    ch = r.get("challenge", "")
                    if "twostepverification" in ch.lower():
                        got_2fa = True
                    else:
                        need_csrf = True  # CSRF протух
                elif st == 429:
                    got_429 = True
                    consecutive_429 += 1
                elif st == 0:
                    pass  # сетевая ошибка

                # обновляем CSRF если вернулся новый
                if r.get("new_csrf"):
                    csrf = r["new_csrf"]

            if need_csrf:
                logging.info("403 без 2FA — обновляю CSRF")
                csrf = None
                continue

            if got_2fa:
                consecutive_429 = 0
                logging.info("403+2FA — ждём подтверждения юзера, пауза %.1fс", PAUSE_2FA)
                time.sleep(PAUSE_2FA)
            elif got_429:
                logging.warning("429 (подряд %d) — пауза %.1fс", consecutive_429, PAUSE_429 * consecutive_429)
                time.sleep(PAUSE_429 * min(consecutive_429, 6))
            else:
                consecutive_429 = 0

    logging.warning("run_api: дедлайн %dс истёк — ссылка не найдена", DEADLINE)
    return None


# ══════════════════════════ Playwright (резервный) ══════════════════════════ #
# Используется только если run_api ничего не вернул за DEADLINE.
# Открывает браузер, логинит через cookie, запускает JS-батч.

_JS_BATCH = r"""
async (count) => {
  const URL  = 'https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification';
  const BODY = JSON.stringify({ generateLink: true, ageEstimation: true, parentVerification: false });

  const findLink = (text) => {
    let obj = null;
    try { obj = JSON.parse(text); } catch(e) {}
    const walk = (o, d) => {
      if (!o || typeof o !== 'object' || d > 10) return null;
      for (const k of Object.keys(o)) {
        const v = o[k];
        if (typeof v === 'string') {
          if ((v.includes('withpersona.com') || v.includes('persona.com')) && v.startsWith('http')) return v;
          if (v.startsWith('inq_') && v.length > 10) {
            return 'https://inquiry.withpersona.com/verify?inquiry-id=' + v;
          }
        }
      }
      for (const k of Object.keys(o)) {
        if (typeof o[k] === 'object') { const r = walk(o[k], d + 1); if (r) return r; }
      }
      return null;
    };
    if (obj) { const r = walk(obj, 0); if (r) return r; }
    const m = text.match(/https:\/\/[^\s"'\\]+withpersona\.com[^\s"'\\]*inquiry-id=[^\s"'\\&]+/);
    return m ? m[0] : null;
  };

  if (!window.__csrf) {
    try {
      const r0 = await fetch(URL, { method:'POST', credentials:'include',
        headers:{'Content-Type':'application/json;charset=utf-8'}, body: BODY });
      const c = r0.headers.get('x-csrf-token');
      if (c) { window.__csrf = c; }
      else {
        const t = await r0.text();
        const lnk = findLink(t);
        if (lnk) return [{ status: r0.status, link: lnk, challenge: '' }];
      }
    } catch(e) {}
  }
  if (!window.__csrf) return [];

  const one = async () => {
    try {
      const r = await fetch(URL, { method:'POST', credentials:'include',
        headers:{'Content-Type':'application/json;charset=utf-8','x-csrf-token': window.__csrf}, body: BODY });
      const nc = r.headers.get('x-csrf-token');
      if (nc) window.__csrf = nc;
      const text = await r.text();
      return { status: r.status, link: findLink(text),
               challenge: r.headers.get('rblx-challenge-type') || '' };
    } catch(e) {
      return { status: 0, link: null, challenge: '' };
    }
  };
  return await Promise.all(Array.from({ length: count }, () => one()));
}
"""


def _launch_browser():
    p = sync_playwright().__enter__()
    browser = p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
              "--disable-setuid-sandbox", "--single-process", "--no-zygote"],
    )
    return p, browser


def _make_page(browser, cookie: str):
    ctx = browser.new_context(
        user_agent=_HEADERS["User-Agent"],
        viewport={"width": 1280, "height": 800},
    )
    ctx.add_cookies([{
        "name": ".ROBLOSECURITY", "value": cookie,
        "domain": ".roblox.com", "path": "/",
    }])
    page = ctx.new_page()
    page.goto("https://www.roblox.com/my/account#!/info",
              wait_until="domcontentloaded", timeout=30_000)
    page.wait_for_timeout(1_500)
    # кнопка Continue если есть
    try:
        btn = page.wait_for_selector(
            "button:has-text('Continue'), [data-testid='continue-button']",
            timeout=4_000, state="visible",
        )
        if btn:
            btn.click()
            page.wait_for_timeout(800)
    except Exception:
        pass
    return page, ctx


def run_playwright(cookie: str) -> str | None:
    """Резервный метод через браузер — нужен если Python-запросы не могут пройти."""
    p = pw = ctx = page = None
    try:
        p, browser = _launch_browser()
        page, ctx = _make_page(browser, cookie)

        deadline = time.time() + DEADLINE
        consecutive_errors = 0

        while time.time() < deadline:
            try:
                results = page.evaluate(_JS_BATCH, BATCH_SIZE)
            except Exception as e:
                consecutive_errors += 1
                logging.warning("JS error #%d: %s", consecutive_errors, e)
                if consecutive_errors >= 3:
                    logging.warning("Пересоздаю контекст")
                    try:
                        ctx.close()
                    except Exception:
                        pass
                    page, ctx = _make_page(browser, cookie)
                    consecutive_errors = 0
                else:
                    try:
                        page.evaluate("() => { window.__csrf = null; }")
                        page.goto("https://www.roblox.com/my/account#!/info",
                                  wait_until="domcontentloaded", timeout=20_000)
                        page.wait_for_timeout(1_000)
                    except Exception:
                        pass
                continue

            if not results:
                page.wait_for_timeout(500)
                continue

            consecutive_errors = 0
            got_2fa = False

            logging.info("pw batch | statuses=%s", [r.get("status") for r in results])

            for i, r in enumerate(results):
                if r.get("link"):
                    logging.info("  pw req#%d → LINK: %s", i, r['link'])
                    return r["link"]
                if r.get("status") == 200:
                    logging.warning("  pw req#%d → 200 NO-LINK", i)
                if r.get("status") == 403 and "twostepverification" in r.get("challenge", "").lower():
                    got_2fa = True

            if got_2fa:
                page.wait_for_timeout(int(PAUSE_2FA * 1000))
            else:
                page.wait_for_timeout(200)

    except Exception as e:
        logging.error("run_playwright error: %s", e)
    finally:
        for obj in (ctx, ):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass
        try:
            if p:
                p.__exit__(None, None, None)
        except Exception:
            pass

    return None


# ══════════════════════════════════ Flask API ═══════════════════════════════ #

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "deadline": DEADLINE, "batch": BATCH_SIZE})


@app.route("/get-link", methods=["POST"])
def get_link():
    # авторизация
    data   = request.get_json(silent=True) or {}
    secret = request.headers.get("X-Secret") or data.get("secret", "")
    if secret != WORKER_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    cookie = data.get("cookie", "").strip()
    method = data.get("method", "camera").strip()

    if not cookie:
        return jsonify({"error": "cookie required"}), 400

    logging.info("=" * 60)
    logging.info("TASK START | method=%s | cookie_len=%d", method, len(cookie))
    t0 = time.time()

    # ── 1. Python API (быстро, без браузера) ──────────────────────────────
    link = run_api(cookie)

    # ── 2. Playwright (если API не справился) ─────────────────────────────
    if not link:
        logging.info("API не дал ссылку за %ds — пробую Playwright", DEADLINE)
        link = run_playwright(cookie)

    elapsed = round(time.time() - t0)
    if link:
        logging.info("TASK SUCCESS in %ds | FINAL LINK: %s", elapsed, link)
        logging.info("=" * 60)
        return jsonify({"link": link, "elapsed": elapsed})
    else:
        logging.error("TASK FAIL after %ds | ни один запрос не дал ссылку", elapsed)
        logging.info("=" * 60)
        return jsonify({"error": "failed to get link", "elapsed": elapsed}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
