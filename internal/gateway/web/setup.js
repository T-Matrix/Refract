(() => {
  'use strict';
  const form = document.getElementById('setup-form');
  const username = document.getElementById('setup-username');
  const password = document.getElementById('setup-password');
  const confirmation = document.getElementById('setup-confirm-password');
  const error = document.getElementById('setup-error');
  const submit = document.getElementById('setup-button');
  window.lucide?.createIcons();

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    if (!form.reportValidity()) return;
    if (password.value !== confirmation.value) {
      error.textContent = '两次输入的密码不一致';
      error.hidden = false;
      confirmation.focus();
      return;
    }
    submit.disabled = true;
    submit.querySelector('span').textContent = '初始化中';
    try {
      const response = await fetch('/_admin/api/setup', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.value.trim(), password: password.value, confirm_password: confirmation.value })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'setup failed');
      window.location.replace('/panel');
    } catch (failure) {
      error.textContent = failure.message === 'administrator already configured' ? '管理员已经配置，请前往登录页' : '初始化失败，请检查输入后重试';
      error.hidden = false;
    } finally {
      submit.disabled = false;
      submit.querySelector('span').textContent = '完成安装';
    }
  });
})();
