# -*- coding: utf-8 -*-
"""
2FA Worker — запускается на отдельных Railway аккаунтах.
Принимает POST /get-link с cookie и method, возвращает ссылку.
"""
import os
import re
import json
import logging
import threading
import time
from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

WORKER_SECRET = os.environ.get("WORKER_SECRET", "mysecret")  # защита от чужих запросов

# ===== ПРОКСИ =====
_PROXY_LIST = [
    "dc.decodo.com:10001:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10002:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10003:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10004:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10005:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10006:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10007:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10008:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10009:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10010:spv4yuud2r:5vdwAL4mymi+f83XtV",
    "dc.decodo.com:10001:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10002:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10003:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10004:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10005:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10006:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10007:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10008:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10009:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10010:sp3g12m118:~A1rRln78IYeemro5q",
    "dc.decodo.com:10001:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10002:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10003:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10004:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10005:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10006:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10007:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10008:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10009:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10010:spxl7cd51h:=j70U8vw9ySLeizfkW",
    "dc.decodo.com:10001:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10002:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10003:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10004:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10005:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10006:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10007:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10008:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10009:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10010:sp5xvqyhjn:d0u5Gfkqr=qK93HtUu",
    "dc.decodo.com:10001:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10002:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10003:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10004:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10005:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10006:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10007:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10008:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10009:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10010:sphz054mdr:a0efg1NruE=d9NsM5k",
    "dc.decodo.com:10001:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10002:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10003:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10004:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10005:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10006:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10007:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10008:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10009:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
    "dc.decodo.com:10010:sp13uinlcj:3lS0aw8eHMcJr~tm4v",
]
_proxy_index = 0
_proxy_lock = threading.Lock()

def get_proxy_url():
    global _proxy_index
    with _proxy_lock:
        entry = _PROXY_LIST[_proxy_index % len(_PROXY_LIST)]
        _proxy_index += 1
    host, port, user, passwd = entry.split(":")
    return {
        "server": f"http://{host}:{port}",
        "username": user,
        "password": passwd,
    }


# ===== ИЗВЛЕЧЕНИЕ ССЫЛКИ =====

def extract_link_from_api(data):
    if not isinstance(data, dict):
        return None
    for key in ["verificationUrl", "redirectUrl", "url", "link",
                "personaUrl", "inquiryUrl", "sessionUrl", "verifyUrl",
                "inquiryLink", "personaLink"]:
        val = data.get(key, "")
        if val and isinstance(val, str) and val.startswith("http"):
            if "withpersona.com" in val or "persona.com" in val:
                return val
    inq_id = (data.get("inquiryId") or data.get("inquiry_id")
              or data.get("sessionIdentifier") or data.get("inqId"))
    session_token = (data.get("sessionToken") or data.get("session_token")
                     or data.get("sessionKey"))
    if inq_id and str(inq_id).startswith("inq_"):
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + str(inq_id)
        if session_token:
            link += "&session-token=" + str(session_token)
        return link

    def find_deep(obj):
        if isinstance(obj, str):
            if ("withpersona.com" in obj or "persona.com" in obj) and obj.startswith("http"):
                return obj
            return None
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and v.startswith("http"):
                    if "withpersona.com" in v or "persona.com" in v:
                        return v
                if isinstance(v, str) and v.startswith("inq_") and len(v) > 10:
                    tok = obj.get("sessionToken") or obj.get("session_token") or ""
                    lnk = "https://inquiry.withpersona.com/verify?inquiry-id=" + v
                    if tok:
                        lnk += "&session-token=" + tok
                    return lnk
            for v in obj.values():
                r = find_deep(v)
                if r:
                    return r
        elif isinstance(obj, list):
            for item in obj:
                r = find_deep(item)
                if r:
                    return r
        return None

    return find_deep(data)


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
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        if tok_m:
            link += "&session-token=" + tok_m.group(1)
        return link
    m = re.search(r'"inq_([A-Za-z0-9]{10,})"', body)
    if m:
        inq_id = "inq_" + m.group(1)
        tok_m = re.search(r'"sessionToken"\s*:\s*"([^"]{20,})"', body)
        if not tok_m:
            tok_m = re.search(r'"session[_-]?[Tt]oken"\s*:\s*"([^"]{20,})"', body)
        link = "https://inquiry.withpersona.com/verify?inquiry-id=" + inq_id
        if tok_m:
            link += "&session-token=" + tok_m.group(1)
        return link
    return None


# ===== БЫСТРЫЙ API (БЕЗ 2FA) =====

import requests as _requests

def run_fast_api(cookie: str, method: str) -> str | None:
    """Быстрый метод через прямой API запрос — работает без 2FA, ~2 секунды."""
    try:
        url = "https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification"
        body = {"generateLink": True, "ageEstimation": True, "parentVerification": False}

        proxy = get_proxy_url()
        proxy_url = proxy["server"].replace("http://", f"http://{proxy['username']}:{proxy['password']}@")
        proxies = {"http": proxy_url, "https": proxy_url}

        s = _requests.Session()
        s.cookies[".ROBLOSECURITY"] = cookie
        s.proxies.update(proxies)
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Content-Type": "application/json;charset=utf-8",
            "Origin": "https://www.roblox.com",
            "Referer": "https://www.roblox.com/my/account#!/info",
        })

        # Шаг 1: получаем CSRF
        r1 = s.post(url, json=body, timeout=15)
        logging.info("Fast API step1: %d", r1.status_code)
        if r1.status_code == 200:
            link = extract_link_from_api(r1.json()) or extract_link_from_raw(r1.text)
            if link:
                return link

        csrf = r1.headers.get("x-csrf-token")
        if not csrf:
            return None

        # Шаг 2: с CSRF
        s.headers["x-csrf-token"] = csrf
        r2 = s.post(url, json=body, timeout=15)
        logging.info("Fast API step2: %d body=%s", r2.status_code, r2.text[:300])
        if r2.status_code == 200:
            return extract_link_from_api(r2.json()) or extract_link_from_raw(r2.text)

        return None
    except Exception as e:
        logging.error("Fast API error: %s", e)
        return None


# ===== БЕЗ 2FA ВОРКЕР =====

def run_no2fa_worker(cookie: str, method: str) -> str | None:
    """Для аккаунтов без 2FA: заходим на страницу, кликаем Continue, делаем API запрос."""
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                    "--single-process",
                    "--no-zygote",
                ]
            )
            page, ctx = _make_page(browser, cookie)
            # _make_page уже кликает Continue если есть

            # Делаем один батч запросов через JS (CSRF получается автоматически)
            JS_SINGLE = """
async () => {
  const URL_TARGET = 'https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification';
  const BODY = JSON.stringify({ generateLink: true, ageEstimation: true, parentVerification: false });

  const send = (csrf) => fetch(URL_TARGET, {
    method: 'POST', credentials: 'include',
    headers: {
      'Content-Type': 'application/json;charset=utf-8',
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
    },
    body: BODY,
  });

  const findLink = (text) => {
    try {
      const data = JSON.parse(text);
      const walk = (obj, d) => {
        if (!obj || typeof obj !== 'object' || d > 10) return null;
        for (const k of Object.keys(obj)) {
          const v = obj[k];
          if (typeof v === 'string') {
            if ((v.includes('withpersona.com') || v.includes('persona.com')) && v.startsWith('http')) return v;
            if (v.startsWith('inq_') && v.length > 10) {
              const tok = obj['sessionToken'] || obj['session_token'] || '';
              return 'https://inquiry.withpersona.com/verify?inquiry-id=' + v + (tok ? '&session-token=' + tok : '');
            }
          }
          if (typeof obj[k] === 'object') { const r = walk(obj[k], d+1); if (r) return r; }
        }
        return null;
      };
      return walk(data, 0);
    } catch(e) {
      const m = text.match(/https:\\/\\/[^\\s"']+withpersona\\.com[^\\s"']*inquiry-id=[^\\s"'&]+/);
      return m ? m[0] : null;
    }
  };

  // 1й запрос — получаем CSRF
  let r = await send(null);
  const csrf = r.headers.get('x-csrf-token');
  console.log('step1:', r.status, 'csrf:', csrf);
  if (!csrf) {
    const t = await r.text();
    return { status: r.status, body: t, link: findLink(t) };
  }

  // 2й запрос — с CSRF
  r = await send(csrf);
  const text = await r.text();
  console.log('step2:', r.status, text.slice(0, 200));
  return { status: r.status, body: text, link: findLink(text) };
}
"""
            try:
                result = page.evaluate(JS_SINGLE)
                logging.info("no2fa result: status=%s link=%s body=%s",
                             result.get("status"), result.get("link"), result.get("body", "")[:200])
                link = result.get("link")
                if not link and result.get("status") == 200:
                    link = extract_link_from_api(json.loads(result["body"])) if result.get("body") else None
                    link = link or extract_link_from_raw(result.get("body", ""))
            except Exception as e:
                logging.error("no2fa JS error: %s", e)
                link = None
            finally:
                try: ctx.close()
                except Exception: pass
                browser.close()

            return link
    except Exception as e:
        logging.error("run_no2fa_worker error: %s", e)
        return None


# ===== 2FA ВОРКЕР =====

# JS который делает один запрос и возвращает статус + body + ссылку если нашлась
JS_SINGLE_REQUEST = """
async () => {
  const URL_TARGET = 'https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification';
  const BODY = JSON.stringify({ generateLink: true, ageEstimation: true, parentVerification: false });

  // Получаем CSRF если нет
  if (!window.__csrf) {
    try {
      const r0 = await fetch(URL_TARGET, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
        body: BODY,
      });
      const c = r0.headers.get('x-csrf-token');
      if (c) window.__csrf = c;
    } catch(e) {}
  }

  const csrf = window.__csrf;
  if (!csrf) return { status: 0, body: 'no_csrf', challengeType: '', link: null };

  try {
    const r = await fetch(URL_TARGET, {
      method: 'POST', credentials: 'include',
      headers: {
        'Content-Type': 'application/json;charset=utf-8',
        'x-csrf-token': csrf,
      },
      body: BODY,
    });

    const newCsrf = r.headers.get('x-csrf-token');
    if (newCsrf) window.__csrf = newCsrf;

    const text = await r.text();
    const ctype = r.headers.get('rblx-challenge-type') || '';

    // Ищем ссылку прямо здесь в JS
    let link = null;
    try {
      const data = JSON.parse(text);
      const find = (obj) => {
        if (!obj || typeof obj !== 'object') return null;
        for (const k of Object.keys(obj)) {
          const v = obj[k];
          if (typeof v === 'string') {
            if (v.includes('withpersona.com') || v.includes('persona.com')) return v;
            if (typeof v === 'string' && v.startsWith('inq_') && v.length > 10) {
              const tok = obj['sessionToken'] || obj['session_token'] || '';
              let lnk = 'https://inquiry.withpersona.com/verify?inquiry-id=' + v;
              if (tok) lnk += '&session-token=' + tok;
              return lnk;
            }
          } else if (typeof v === 'object') {
            const res = find(v);
            if (res) return res;
          }
        }
        return null;
      };
      link = find(data);
    } catch(e) {
      // Ищем в сыром тексте
      const m = text.match(/https:\\/\\/[^\\s"'\\\\]+withpersona\\.com[^\\s"'\\\\]*inquiry-id=[^\\s"'\\\\&]+/);
      if (m) link = m[0];
    }

    return { status: r.status, body: text, challengeType: ctype, link: link };
  } catch(e) {
    return { status: 0, body: String(e), challengeType: '', link: null };
  }
}
"""

# JS батч — N параллельных запросов, CSRF получаем один раз глобально
JS_FETCH_BATCH = """
async (count) => {
  const URL_TARGET = 'https://apis.roblox.com/age-verification-service/v1/persona-id-verification/start-verification';
  const BODY = JSON.stringify({ generateLink: true, ageEstimation: true, parentVerification: false });

  // Глубокий поиск ссылки — обходит весь JSON рекурсивно
  const findLink = (text) => {
    let parsed = null;
    try { parsed = JSON.parse(text); } catch(e) {}
    if (parsed) {
      const walk = (obj, depth) => {
        if (!obj || typeof obj !== 'object' || depth > 10) return null;
        if (Array.isArray(obj)) {
          for (const item of obj) { const r = walk(item, depth+1); if (r) return r; }
          return null;
        }
        for (const k of Object.keys(obj)) {
          const v = obj[k];
          if (typeof v === 'string') {
            if ((v.includes('withpersona.com') || v.includes('persona.com')) && v.startsWith('http')) return v;
            if (v.startsWith('inq_') && v.length > 10) {
              const tok = obj['sessionToken'] || obj['session_token'] || obj['sessionKey'] || '';
              let lnk = 'https://inquiry.withpersona.com/verify?inquiry-id=' + v;
              if (tok) lnk += '&session-token=' + tok;
              return lnk;
            }
          }
        }
        for (const k of Object.keys(obj)) {
          if (typeof obj[k] === 'object') { const r = walk(obj[k], depth+1); if (r) return r; }
        }
        return null;
      };
      const found = walk(parsed, 0);
      if (found) return found;
    }
    const m1 = text.match(/https:\\/\\/[^\\s"'\\\\]+withpersona\\.com[^\\s"'\\\\]*inquiry-id=[^\\s"'\\\\&]+(?:&[^\\s"'\\\\]*)?/);
    if (m1) return m1[0].replace(/\\\\+$/, '');
    const m2 = text.match(/"(inq_[A-Za-z0-9]{10,})"/);
    if (m2) {
      const m3 = text.match(/"session[Tt]oken"\\s*:\\s*"([^"]{20,})"/);
      return 'https://inquiry.withpersona.com/verify?inquiry-id=' + m2[1] + (m3 ? '&session-token=' + m3[1] : '');
    }
    return null;
  };

  // Получаем CSRF один раз глобально (точный паттерн из консоли)
  if (!window.__csrf) {
    try {
      const r0 = await fetch(URL_TARGET, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
        body: BODY,
      });
      const c = r0.headers.get('x-csrf-token');
      console.log('CSRF fetch: status=' + r0.status + ' csrf=' + c);
      if (c) {
        window.__csrf = c;
      } else {
        // Вдруг 200 без CSRF — проверяем тело
        const t = await r0.text();
        console.log('No CSRF, body:', t.slice(0, 200));
        const lnk = findLink(t);
        if (lnk) return [{ status: r0.status, body: t, challengeType: '', link: lnk }];
      }
    } catch(e) {
      console.log('CSRF fetch error:', e);
    }
  }

  const csrf = window.__csrf;
  if (!csrf) {
    console.log('ERROR: no CSRF token available');
    return [];
  }

  // Все count задач делают по 1 рабочему запросу с CSRF
  const oneTask = async () => {
    try {
      const r = await fetch(URL_TARGET, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json;charset=utf-8',
          'x-csrf-token': csrf,
        },
        body: BODY,
      });
      // Если вернулся новый CSRF — обновляем
      const newCsrf = r.headers.get('x-csrf-token');
      if (newCsrf && newCsrf !== csrf) window.__csrf = newCsrf;

      const text = await r.text();
      const link = findLink(text);
      console.log('req:', r.status, link ? 'LINK!' : '');
      return {
        status: r.status,
        body: text,
        challengeType: r.headers.get('rblx-challenge-type') || '',
        link,
      };
    } catch(e) {
      return { status: 0, body: String(e), challengeType: '', link: null };
    }
  };

  // Все count запросов параллельно — каждый делает 1 рабочий запрос
  const tasks = Array.from({ length: count }, () => oneTask());
  return await Promise.all(tasks);
}
"""

BATCH_SIZE         = 15    # 15 параллельных запросов за итерацию ≈ 500 req/min
PAUSE_NORMAL       = 0.0   # без паузы — максимальная скорость
PAUSE_2FA_WAIT     = 3.0
PAUSE_429          = 1.0   # при 429 — быстрая смена прокси
DEADLINE           = 86400  # 24 часа — лимит по кол-ву запросов, не по времени
MAX_ERRORS         = 3     # при 3 ошибках подряд — перезагрузка
ROTATE_PROXY_EVERY = 10    # менять прокси каждые N батчей
MAX_TOTAL_REQUESTS = 150000  # максимум 150 000 запросов на аккаунт


def _click_continue_if_present(page):
    """Кликает кнопку Continue ('Use an ID to verify your birthday') если она есть."""
    try:
        # Ждём до 4 секунд появления кнопки
        btn = page.wait_for_selector(
            "button:has-text('Continue'), "
            "a:has-text('Continue'), "
            "[data-testid='continue-button'], "
            ".birthday-verification-continue button, "
            "button.btn-cta-md:has-text('Continue')",
            timeout=4000,
            state="visible",
        )
        if btn:
            logging.info("Найдена кнопка Continue — кликаю")
            btn.click()
            page.wait_for_timeout(1000)
            logging.info("Continue нажата")
    except Exception:
        pass  # Кнопки нет — всё ок, продолжаем


def _make_page(browser, cookie: str):
    """Создаёт новый контекст с новым прокси и возвращает страницу."""
    proxy = get_proxy_url()
    logging.info("Новый прокси: %s", proxy["server"])
    ctx = browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        viewport={"width": 1280, "height": 800},
        proxy=proxy,
    )
    ctx.add_cookies([{
        "name": ".ROBLOSECURITY",
        "value": cookie,
        "domain": ".roblox.com",
        "path": "/",
    }])
    page = ctx.new_page()
    page.goto("https://www.roblox.com/my/account#!/info",
              wait_until="domcontentloaded", timeout=30000)
    page.wait_for_timeout(1500)
    _click_continue_if_present(page)
    return page, ctx


def _safe_reload(page, cookie: str):
    """Перезагружает страницу и сбрасывает CSRF в JS."""
    try:
        logging.info("Перезагружаю страницу...")
        page.evaluate("() => { window.__csrf = null; }")
        page.goto("https://www.roblox.com/my/account#!/info",
                  wait_until="domcontentloaded", timeout=20000)
        page.wait_for_timeout(1000)
        _click_continue_if_present(page)
        logging.info("Страница перезагружена.")
    except Exception as e:
        logging.warning("Ошибка при перезагрузке: %s", e)


def _recover(browser, ctx, cookie: str):
    """Полная пересоздание контекста при критической ошибке."""
    try:
        ctx.close()
    except Exception:
        pass
    try:
        return _make_page(browser, cookie)
    except Exception as e:
        logging.error("Ошибка восстановления контекста: %s", e)
        raise


def run_2fa_worker(cookie: str, method: str) -> str | None:
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                    "--single-process",
                    "--no-zygote",
                ]
            )
            page, ctx = _make_page(browser, cookie)

            start            = time.time()
            iteration        = 0
            total_requests   = 0
            consecutive_errors = 0
            consecutive_429  = 0
            consecutive_net_errors = 0  # ошибки сети (status=0)

            while time.time() - start < DEADLINE:
                # ── лимит запросов ──────────────────────────────────────────
                if total_requests >= MAX_TOTAL_REQUESTS:
                    logging.info("Лимит %d запросов достигнут — стоп.", MAX_TOTAL_REQUESTS)
                    break

                # ── страница закрылась ──────────────────────────────────────
                if page.is_closed():
                    logging.warning("Страница закрылась — пересоздаю контекст")
                    try:
                        page, ctx = _recover(browser, ctx, cookie)
                        consecutive_errors = 0
                        consecutive_net_errors = 0
                    except Exception:
                        time.sleep(1)
                    continue

                iteration += 1

                # ── плановая ротация прокси ─────────────────────────────────
                if iteration % ROTATE_PROXY_EVERY == 0:
                    logging.info("Плановая ротация прокси (batch #%d)", iteration)
                    try:
                        page, ctx = _recover(browser, ctx, cookie)
                        consecutive_429 = 0
                    except Exception as e:
                        logging.error("Ошибка ротации прокси: %s", e)
                    continue

                # ── выполняем батч запросов ─────────────────────────────────
                try:
                    results = page.evaluate(JS_FETCH_BATCH, BATCH_SIZE)
                except Exception as e:
                    consecutive_errors += 1
                    logging.warning("Ошибка evaluate #%d: %s", consecutive_errors, e)
                    if consecutive_errors >= MAX_ERRORS:
                        logging.warning("Много ошибок evaluate — полное восстановление")
                        try:
                            page, ctx = _recover(browser, ctx, cookie)
                        except Exception:
                            pass
                        consecutive_errors = 0
                        consecutive_net_errors = 0
                    else:
                        # Сначала пробуем просто перезагрузить страницу
                        _safe_reload(page, cookie)
                    continue

                # ── пустой ответ ────────────────────────────────────────────
                if not results:
                    consecutive_errors += 1
                    logging.warning("Пустой результат батча #%d", consecutive_errors)
                    if consecutive_errors >= MAX_ERRORS:
                        logging.warning("Пустые результаты — меняю контекст")
                        try:
                            page, ctx = _recover(browser, ctx, cookie)
                        except Exception:
                            pass
                        consecutive_errors = 0
                    else:
                        _safe_reload(page, cookie)
                    continue

                consecutive_errors = 0
                total_requests += len(results)
                elapsed = time.time() - start
                rps     = total_requests / elapsed if elapsed > 0 else 0
                logging.info(
                    "batch#%d | total=%d/150000 | %.1f req/sec | statuses=%s",
                    iteration, total_requests, rps,
                    [r.get("status") for r in results]
                )

                got_429  = False
                got_2fa  = False
                all_zero = True

                for r in results:
                    status = r.get("status")
                    body   = r.get("body", "")
                    ctype  = r.get("challengeType") or ""
                    link   = r.get("link")

                    if status != 0:
                        all_zero = False

                    # ── ссылка найдена ──────────────────────────────────────
                    if link:
                        logging.info("LINK FOUND (JS): %s", link)
                        try:
                            ctx.close()
                        except Exception:
                            pass
                        browser.close()
                        return link

                    if status == 200:
                        logging.info("status=200 body=%s", body[:500])
                        try:
                            py_link = extract_link_from_api(json.loads(body))
                        except Exception:
                            py_link = None
                        py_link = py_link or extract_link_from_raw(body)
                        if py_link:
                            logging.info("LINK FOUND (Python): %s", py_link)
                            try:
                                ctx.close()
                            except Exception:
                                pass
                            browser.close()
                            return py_link
                        else:
                            logging.warning("status=200 но ссылка не найдена! body=%s", body[:300])

                    elif status == 429:
                        got_429 = True
                        consecutive_429 += 1
                        logging.warning("429 rate limit! (подряд: %d)", consecutive_429)

                    elif status == 403:
                        if "twostepverification" in ctype.lower():
                            got_2fa = True
                            logging.info("403 + 2FA — ждём подтверждения...")
                        else:
                            logging.warning("403 без 2FA, ctype=%s body=%s", ctype, body[:150])

                    elif status == 0:
                        logging.warning("Сетевая ошибка запроса: %s", body[:80])

                # ── все запросы упали с сетевой ошибкой ────────────────────
                if all_zero:
                    consecutive_net_errors += 1
                    logging.warning("Все %d запросов упали (сеть). Подряд: %d",
                                    BATCH_SIZE, consecutive_net_errors)
                    if consecutive_net_errors >= 2:
                        logging.warning("Перезагружаю страницу из-за сетевых ошибок")
                        _safe_reload(page, cookie)
                        consecutive_net_errors = 0
                    else:
                        page.wait_for_timeout(300)
                else:
                    consecutive_net_errors = 0

                # ── паузы по типу ответа ────────────────────────────────────
                if got_2fa:
                    page.wait_for_timeout(int(PAUSE_2FA_WAIT * 1000))

                elif got_429:
                    if consecutive_429 >= 2:
                        logging.warning("429 подряд %d — меняю прокси немедленно!", consecutive_429)
                        try:
                            page, ctx = _recover(browser, ctx, cookie)
                            consecutive_429 = 0
                        except Exception as e:
                            logging.error("Ошибка смены прокси: %s", e)
                    else:
                        page.wait_for_timeout(int(PAUSE_429 * 1000))

                else:
                    consecutive_429 = 0
                    if PAUSE_NORMAL > 0:
                        page.wait_for_timeout(int(PAUSE_NORMAL * 1000))

            try:
                ctx.close()
            except Exception:
                pass
            browser.close()

    except Exception as e:
        logging.error("Worker error: %s", e)

    return None


# ===== FLASK API =====

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/get-link", methods=["POST"])
def get_link():
    """2FA режим — сначала пробуем быстрый API, потом Playwright с батчами."""
    secret = request.headers.get("X-Secret") or request.json.get("secret", "")
    if secret != WORKER_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    cookie = data.get("cookie", "").strip()
    method = data.get("method", "camera").strip()

    if not cookie:
        return jsonify({"error": "cookie required"}), 400

    logging.info("New task: method=%s cookie=%.20s...", method, cookie)

    # 1. Быстрый прямой API (без браузера)
    link = run_fast_api(cookie, method)
    if link:
        logging.info("Fast API succeeded!")
        return jsonify({"link": link})

    # 2. Без 2FA — браузер, клик Continue, один запрос
    link = run_no2fa_worker(cookie, method)
    if link:
        logging.info("No-2FA worker succeeded!")
        return jsonify({"link": link})

    # 3. Если не вышло — запускаем Playwright с батчами (для 2FA аккаунтов)
    link = run_2fa_worker(cookie, method)

    if link:
        return jsonify({"link": link})
    else:
        return jsonify({"error": "failed to get link"}), 500


@app.route("/get-link-fast", methods=["POST"])
def get_link_fast():
    """Быстрый метод без 2FA — только API запрос, ~2 секунды."""
    secret = request.headers.get("X-Secret") or request.json.get("secret", "")
    if secret != WORKER_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    cookie = data.get("cookie", "").strip()
    method = data.get("method", "camera").strip()

    if not cookie:
        return jsonify({"error": "cookie required"}), 400

    logging.info("Fast task: method=%s cookie=%.20s...", method, cookie)

    link = run_fast_api(cookie, method)

    if link:
        return jsonify({"link": link})
    else:
        return jsonify({"error": "failed to get link"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
