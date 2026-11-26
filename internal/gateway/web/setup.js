(() => {
  'use strict';

  const form = document.getElementById('setup-form');
  const username = document.getElementById('setup-username');
  const setupTokenField = document.getElementById('setup-token-field');
  const setupTokenInput = document.getElementById('setup-token');
  const password = document.getElementById('setup-password');
  const confirmation = document.getElementById('setup-confirm-password');
  const error = document.getElementById('setup-error');
  const submit = document.getElementById('setup-button');
  const toggle = document.getElementById('toggle-setup-password');
  const themeToggle = document.getElementById('auth-theme-toggle');
  const checkLength = document.getElementById('check-length');
  const checkMatch = document.getElementById('check-match');

  let prevLenOk = null;
  let prevMatchOk = null;
  const setupTokenRequired = document.body.dataset.setupTokenRequired === 'true';
  if (setupTokenRequired && setupTokenField) {
    setupTokenField.hidden = false;
    if (setupTokenInput) setupTokenInput.required = true;
  }

  function safeStorageGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function safeStorageSet(key, val) {
    try { localStorage.setItem(key, val); } catch { /* ignore */ }
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
  }

  function utf8ByteLength(value) {
    return new TextEncoder().encode(String(value || '')).length;
  }

  function updatePasswordChecks() {
    const byteLen = utf8ByteLength(password.value);
    const lenOk = password.value.length >= 12 && byteLen <= 72;
    const matchOk = password.value.length > 0 && password.value === confirmation.value;
    let iconsChanged = false;
    checkLength.classList.toggle('pass', lenOk);
    const lenSpan = checkLength.querySelector('span');
    if (lenSpan) lenSpan.textContent = `密码至少 12 个字符且不超过 72 字节（当前 ${password.value.length} 字符 / ${byteLen} 字节）`;
    if (prevLenOk !== lenOk) {
      prevLenOk = lenOk;
      const oldIcon = checkLength.querySelector('svg, i');
      const icon = document.createElement('i');
      icon.dataset.lucide = lenOk ? 'check-circle-2' : 'circle';
      if (oldIcon) oldIcon.replaceWith(icon);
      else checkLength.prepend(icon);
      iconsChanged = true;
    }
    checkMatch.classList.toggle('pass', matchOk);
    if (prevMatchOk !== matchOk) {
      prevMatchOk = matchOk;
      const oldIcon = checkMatch.querySelector('svg, i');
      const icon = document.createElement('i');
      icon.dataset.lucide = matchOk ? 'check-circle-2' : 'circle';
      if (oldIcon) oldIcon.replaceWith(icon);
      else checkMatch.prepend(icon);
      iconsChanged = true;
    }
    if (iconsChanged) window.lucide?.createIcons();
  }

  applyTheme(safeStorageGet('gateway-theme') === 'dark' ? 'dark' : 'light');
  themeToggle?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  password.addEventListener('input', updatePasswordChecks);
  confirmation.addEventListener('input', updatePasswordChecks);
  updatePasswordChecks();

  toggle?.addEventListener('click', () => {
    const reveal = password.type === 'password';
    password.type = reveal ? 'text' : 'password';
    confirmation.type = reveal ? 'text' : 'password';
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
    [username, password, confirmation, setupTokenInput].filter(Boolean).forEach((input) => {
      input.classList.remove('is-invalid');
      input.removeAttribute('aria-invalid');
    });

    const trimmedUser = username.value.trim();
    if (!trimmedUser || utf8ByteLength(trimmedUser) > 64 || /[\r\n\x00|]/.test(trimmedUser)) {
      username.classList.add('is-invalid');
      username.setAttribute('aria-invalid', 'true');
      error.textContent = '用户名需为 1-64 字节的安全字符';
      error.hidden = false;
      username.focus();
      return;
    }
    if (setupTokenField && !setupTokenField.hidden && !setupTokenInput?.value.trim()) {
      setupTokenInput?.classList.add('is-invalid');
      setupTokenInput?.setAttribute('aria-invalid', 'true');
      error.textContent = '请输入初始化令牌（ADMIN_SETUP_TOKEN）';
      error.hidden = false;
      setupTokenInput?.focus();
      return;
    }
    if (password.value.length < 12 || utf8ByteLength(password.value) > 72) {
      password.classList.add('is-invalid');
      password.setAttribute('aria-invalid', 'true');
      error.textContent = '密码需至少 12 个字符且不超过 72 字节';
      error.hidden = false;
      password.focus();
      return;
    }
    if (password.value !== confirmation.value) {
      confirmation.classList.add('is-invalid');
      confirmation.setAttribute('aria-invalid', 'true');
      error.textContent = '两次输入的密码不一致';
      error.hidden = false;
      confirmation.focus();
      return;
    }

    submit.disabled = true;
    submit.querySelector('span').textContent = '正在初始化…';
    try {
      const body = {
        username: trimmedUser,
        password: password.value,
        confirm_password: confirmation.value
      };
      const tok = setupTokenInput?.value.trim() || '';
      if (tok) body.setup_token = tok;
      const response = await fetch('/_admin/api/setup', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'setup failed');
      window.location.replace('/panel');
    } catch (failure) {
      const msg = String(failure?.message || '');
      if (msg.includes('setup token')) {
        if (setupTokenField) setupTokenField.hidden = false;
        setupTokenInput?.classList.add('is-invalid');
        setupTokenInput?.setAttribute('aria-invalid', 'true');
        error.textContent = '初始化令牌无效，请填写服务器配置的 ADMIN_SETUP_TOKEN';
        setupTokenInput?.focus();
      } else if (msg === 'administrator already configured') {
        error.textContent = '管理员已经完成初始化，请前往登录页';
      } else if (msg.includes('username')) {
        username.classList.add('is-invalid');
        username.setAttribute('aria-invalid', 'true');
        error.textContent = '用户名需为 1-64 字节的安全字符';
        username.focus();
      } else if (msg.includes('72')) {
        password.classList.add('is-invalid');
        error.textContent = '密码需至少 12 个字符且不超过 72 字节';
      } else {
        error.textContent = '初始化失败，请检查输入后重试';
      }
      error.hidden = false;
    } finally {
      submit.disabled = false;
      submit.querySelector('span').textContent = '完成初始化并进入控制台';
    }
  });
})();
