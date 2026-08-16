(() => {
  'use strict';

  const form = document.getElementById('login-form');
  const username = document.getElementById('username');
  const password = document.getElementById('password');
  const error = document.getElementById('login-error');
  const submit = document.getElementById('login-button');
  const toggle = document.getElementById('toggle-password');
  window.lucide?.createIcons();

  let turnstileConfig = null;
  let turnstileToken = '';
  let turnstileWidget = null;

  function mountTurnstile() {
    if (!turnstileConfig?.enabled || !window.turnstile) return;
    const box = document.getElementById('login-turnstile');
    box.hidden = false;
    if (turnstileWidget !== null) window.turnstile.remove(turnstileWidget);
    turnstileToken = '';
    turnstileWidget = window.turnstile.render('#login-turnstile-widget', {
      sitekey: turnstileConfig.site_key,
      action: 'login',
      theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
      callback: (token) => { turnstileToken = token; },
      'expired-callback': () => { turnstileToken = ''; },
      'error-callback': () => { turnstileToken = ''; }
    });
  }

  async function loadTurnstile() {
    try {
      const response = await fetch('/_admin/api/turnstile/public', { credentials: 'same-origin' });
      turnstileConfig = response.ok ? await response.json() : null;
      if (!turnstileConfig?.enabled) return;
      const deadline = Date.now() + 6000;
      const wait = () => {
        if (window.turnstile) { mountTurnstile(); return; }
        if (Date.now() < deadline) window.setTimeout(wait, 100);
      };
      wait();
    } catch (_) { turnstileConfig = null; }
  }

  loadTurnstile();

  toggle.addEventListener('click', () => {
    const reveal = password.type === 'password';
    password.type = reveal ? 'text' : 'password';
    toggle.setAttribute('aria-label', reveal ? '隐藏密码' : '显示密码');
    toggle.setAttribute('title', reveal ? '隐藏密码' : '显示密码');
    toggle.innerHTML = `<i data-lucide="${reveal ? 'eye-off' : 'eye'}"></i>`;
    window.lucide?.createIcons();
    password.focus();
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    if (!form.reportValidity()) return;
    submit.disabled = true;
    submit.querySelector('span').textContent = '登录中';
    try {
      const response = await fetch('/_admin/api/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value.trim(), password: password.value, turnstile_token: turnstileToken })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const failure = new Error(payload.error || '登录失败');
        failure.retryAfter = Number(response.headers.get('Retry-After')) || 0;
        throw failure;
      }
      window.location.replace('/panel');
    } catch (failure) {
      password.value = '';
      const retryHours = Math.max(1, Math.ceil((failure.retryAfter || 0) / 3600));
      error.textContent = failure.message === 'invalid username or password' ? '用户名或密码错误' :
        failure.message === 'too many login attempts' ? `该 IP 已被暂时封禁，请在约 ${retryHours} 小时后再试` :
        failure.message === 'human verification failed' ? '人机验证未通过，请重新完成验证' : '暂时无法登录';
      error.hidden = false;
      password.focus();
    } finally {
      submit.disabled = false;
      submit.querySelector('span').textContent = '登录';
    }
  });
})();
