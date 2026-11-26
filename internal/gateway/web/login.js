(() => {
  'use strict';

  const form = document.getElementById('login-form');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  const error = document.getElementById('login-error');
  const submit = document.getElementById('login-button');
  const toggle = document.getElementById('toggle-password');
  const themeToggle = document.getElementById('auth-theme-toggle');

  let turnstileConfig = null;
  let turnstileToken = '';
  let turnstileWidget = null;
  let turnstileLoadPromise = null;

  function safeStorageGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function safeStorageSet(key, val) {
    try { localStorage.setItem(key, val); } catch { /* ignore */ }
  }

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
  }

  function applyTheme(theme) {
    const dark = theme === 'dark';
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    safeStorageSet('gateway-theme', dark ? 'dark' : 'light');
    if (themeToggle) {
      themeToggle.setAttribute('aria-label', dark ? '切换浅色模式' : '切换深色模式');
      themeToggle.setAttribute('title', dark ? '切换浅色模式' : '切换深色模式');
      themeToggle.innerHTML = `<i data-lucide="${dark ? 'sun' : 'moon'}"></i>`;
    }
    window.lucide?.createIcons();
    if (turnstileConfig?.enabled && window.turnstile) mountTurnstile();
  }

  function loadTurnstileScript() {
    if (window.turnstile?.render) return Promise.resolve();
    if (turnstileLoadPromise) return turnstileLoadPromise;
    turnstileLoadPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      s.onload = () => (window.turnstile?.render ? resolve() : reject(new Error('turnstile unavailable')));
      s.onerror = () => { turnstileLoadPromise = null; reject(new Error('turnstile script load failed')); };
      document.head.append(s);
    });
    return turnstileLoadPromise;
  }

  function mountTurnstile() {
    if (!turnstileConfig?.enabled || !window.turnstile?.render) return false;
    const box = document.getElementById('login-turnstile');
    box.hidden = false;
    if (turnstileWidget !== null) {
      try { window.turnstile.remove(turnstileWidget); } catch { /* ignore */ }
    }
    turnstileWidget = null;
    turnstileToken = '';
    try {
      turnstileWidget = window.turnstile.render('#login-turnstile-widget', {
        sitekey: turnstileConfig.site_key,
        action: 'login',
        size: window.innerWidth < 400 ? 'compact' : 'normal',
        theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
        callback: (token) => {
          turnstileToken = token;
          error.hidden = true;
        },
        'expired-callback': () => { turnstileToken = ''; },
        'error-callback': (code) => {
          turnstileToken = '';
          const suffix = code ? `（错误码 ${code}）` : '';
          showError(`人机验证组件加载异常${suffix}，请刷新页面或检查网络后重试`);
        }
      });
      return true;
    } catch {
      showError('人机验证组件渲染失败，请刷新页面后重试');
      return false;
    }
  }

  async function loadTurnstile() {
    try {
      const response = await fetch('/_admin/api/turnstile/public', { credentials: 'same-origin' });
      turnstileConfig = response.ok ? await response.json() : null;
      if (!turnstileConfig?.enabled) return;
      document.getElementById('login-turnstile').hidden = false;
      await loadTurnstileScript();
      mountTurnstile();
    } catch {
      if (turnstileConfig?.enabled) {
        showError('Cloudflare 人机验证脚本加载失败，请检查网络连接后刷新页面');
      }
    }
  }

  applyTheme(safeStorageGet('gateway-theme') === 'dark' ? 'dark' : 'light');
  themeToggle?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  loadTurnstile();

  toggle.addEventListener('click', () => {
    const reveal = password.type === 'password';
    password.type = reveal ? 'text' : 'password';
    toggle.setAttribute('aria-pressed', String(reveal));
    toggle.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码');
    toggle.setAttribute('title', reveal ? '隐藏密码' : '显示密码');
    toggle.innerHTML = `<i data-lucide="${reveal ? 'eye-off' : 'eye'}"></i>`;
    window.lucide?.createIcons();
    password.focus();
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    username.classList.remove('is-invalid');
    password.classList.remove('is-invalid');
    username.removeAttribute('aria-invalid');
    password.removeAttribute('aria-invalid');

    if (!username.value.trim()) {
      username.classList.add('is-invalid');
      username.setAttribute('aria-invalid', 'true');
      showError('请输入管理员用户名');
      username.focus();
      return;
    }
    if (!password.value) {
      password.classList.add('is-invalid');
      password.setAttribute('aria-invalid', 'true');
      showError('请输入管理员密码');
      password.focus();
      return;
    }
    if (turnstileConfig?.enabled && !turnstileToken) {
      showError('请先完成上方人机验证后再登录');
      return;
    }

    submit.disabled = true;
    submit.querySelector('span').textContent = '正在验证…';
    try {
      const response = await fetch('/_admin/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.value.trim(),
          password: password.value,
          turnstile_token: turnstileToken
        })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const failure = new Error(payload.error || '登录失败');
        failure.retryAfter = Number(response.headers.get('Retry-After')) || 0;
        throw failure;
      }
      window.location.replace('/panel');
    } catch (failure) {
      const msg = String(failure?.message || '');
      const retryHours = Math.max(1, Math.ceil((failure.retryAfter || 0) / 3600));
      if (msg === 'invalid username or password') {
        password.value = '';
        password.classList.add('is-invalid');
        password.setAttribute('aria-invalid', 'true');
        showError('用户名或密码错误');
        password.focus();
      } else if (msg === 'too many login attempts') {
        showError(`当前 IP 触发防爆破保护，请在约 ${retryHours} 小时后再试`);
      } else if (msg === 'human verification failed') {
        showError('人机验证未通过，请重新完成验证');
      } else {
        showError('暂时无法登录，请稍后重试');
      }
      if (turnstileConfig?.enabled && window.turnstile) mountTurnstile();
    } finally {
      submit.disabled = false;
      submit.querySelector('span').textContent = '登录控制台';
    }
  });
})();
