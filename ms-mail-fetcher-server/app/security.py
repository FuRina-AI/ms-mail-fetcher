import hashlib
import hmac
import html
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

CONFIG_FILE_NAME = "server.config.json"
COOKIE_NAME = "msmf_session"
COOKIE_MAX_AGE = 60 * 60 * 24 * 30


def _resolve_config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / CONFIG_FILE_NAME
    return Path(__file__).resolve().parent.parent / CONFIG_FILE_NAME


def load_auth_token() -> str:
    env_token = os.getenv("MSMF_AUTH_TOKEN") or os.getenv("AUTH_TOKEN")
    if env_token:
        return str(env_token)

    config_path = _resolve_config_path()
    if not config_path.exists():
        return ""

    try:
        with config_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return str(data.get("auth_token") or data.get("access_token") or "")
    except Exception:
        return ""

    return ""


def auth_enabled() -> bool:
    return bool(load_auth_token())


def _session_value_for(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"v1:{digest}"


def make_session_cookie_value() -> str:
    token = load_auth_token()
    return _session_value_for(token) if token else ""


def is_valid_login_token(candidate: str) -> bool:
    token = load_auth_token()
    if not token:
        return True
    return hmac.compare_digest(str(candidate).encode("utf-8"), token.encode("utf-8"))


def is_valid_session_cookie(candidate: str | None) -> bool:
    token = load_auth_token()
    if not token:
        return True
    if not candidate:
        return False
    return hmac.compare_digest(str(candidate), _session_value_for(token))


def build_login_page(next_path: str = "/", error_message: str = "") -> str:
    safe_next = next_path or "/"
    next_json = json.dumps(safe_next, ensure_ascii=False)
    safe_error = html.escape(error_message)
    return f'''<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>MS Mail Fetcher 登录</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ margin: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }}
    .wrap {{ min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px; box-sizing: border-box; }}
    .card {{ width: 100%; max-width: 420px; background: rgba(15, 23, 42, 0.86); border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 18px; padding: 28px; box-shadow: 0 20px 40px rgba(0,0,0,0.35); backdrop-filter: blur(8px); }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    p {{ margin: 0 0 20px; color: #94a3b8; line-height: 1.6; }}
    label {{ display: block; margin-bottom: 8px; font-size: 14px; color: #cbd5e1; }}
    input {{ width: 100%; box-sizing: border-box; padding: 12px 14px; border-radius: 12px; border: 1px solid #334155; background: #0b1220; color: #f8fafc; font-size: 15px; outline: none; }}
    input:focus {{ border-color: #6366f1; box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2); }}
    button {{ width: 100%; margin-top: 16px; border: 0; border-radius: 12px; background: linear-gradient(135deg, #4f46e5, #7c3aed); color: white; padding: 12px 14px; font-size: 15px; font-weight: 600; cursor: pointer; }}
    button:disabled {{ opacity: 0.7; cursor: wait; }}
    .msg {{ min-height: 22px; margin-top: 12px; font-size: 14px; color: #fca5a5; }}
    .hint {{ margin-top: 18px; font-size: 12px; color: #64748b; text-align: center; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>MS Mail Fetcher</h1>
      <p>此页面已启用 token 登录保护。输入访问 token 后即可进入面板。</p>
      <form id="login-form">
        <label for="token">访问 Token</label>
        <input id="token" name="token" type="password" autocomplete="current-password" placeholder="请输入 token" required />
        <button id="submit-btn" type="submit">登录</button>
        <div id="msg" class="msg">{safe_error}</div>
      </form>
      <div class="hint">登录成功后会写入会话 Cookie，可直接在浏览器继续访问。</div>
    </div>
  </div>
  <script>
    const nextPath = {next_json};
    const form = document.getElementById('login-form');
    const msg = document.getElementById('msg');
    const btn = document.getElementById('submit-btn');
    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      msg.textContent = '';
      btn.disabled = true;
      try {{
        const token = document.getElementById('token').value;
        const res = await fetch('/api/auth/login', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          credentials: 'same-origin',
          body: JSON.stringify({{ token }})
        }});
        const data = await res.json().catch(() => ({{}}));
        if (!res.ok) {{
          throw new Error(data.detail || data.message || '登录失败');
        }}
        window.location.replace(nextPath || '/');
      }} catch (err) {{
        msg.textContent = err?.message || '登录失败';
      }} finally {{
        btn.disabled = false;
      }}
    }});
  </script>
</body>
</html>'''


def build_login_redirect(path: str) -> str:
    target = path or "/"
    return f"/login?next={quote(target, safe='/%?=&-_.!~*\'()#')}"
