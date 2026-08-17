(() => {
  'use strict';

  const copyButton = document.getElementById('copy-endpoint');
  const entryCopyButton = document.getElementById('copy-entry-action');
  const entryCopyLabel = document.getElementById('copy-entry-label');
  const copyLabel = document.getElementById('copy-label');
  const copyFeedback = document.getElementById('copy-feedback');
  const endpointValue = document.getElementById('endpoint-value');
  const originLabel = document.getElementById('origin-label');
  const headerStatus = document.getElementById('header-status');
  const headerStatusLabel = document.getElementById('header-status-label');
  const gatewayStatus = document.getElementById('gateway-status');
  const serviceState = document.getElementById('service-state');
  const gatewayVersion = document.getElementById('gateway-version');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const exampleTarget = 'https://emby.example.com:8096';
  let publicBaseURL = window.location.origin;
  let proxyExample = `${publicBaseURL}/${exampleTarget}`;
  let copyResetTimer;
  let entryCopyResetTimer;
  let healthTimer;

  endpointValue.textContent = proxyExample;
  originLabel.textContent = publicBaseURL;
  document.getElementById('current-year').textContent = String(new Date().getFullYear());

  async function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(value);
      return;
    }
    const input = document.createElement('textarea');
    input.value = value;
    input.setAttribute('readonly', '');
    input.style.position = 'fixed';
    input.style.opacity = '0';
    document.body.append(input);
    input.select();
    const copied = document.execCommand('copy');
    input.remove();
    if (!copied) throw new Error('copy failed');
  }

  copyButton.addEventListener('click', async () => {
    clearTimeout(copyResetTimer);
    try {
      await copyText(proxyExample);
      copyButton.classList.add('is-copied');
      copyLabel.textContent = '已复制';
      copyFeedback.textContent = '示例地址已复制';
    } catch {
      copyButton.classList.remove('is-copied');
      copyLabel.textContent = '复制';
      copyFeedback.textContent = '复制失败，请长按地址复制';
    }
    copyResetTimer = window.setTimeout(() => {
      copyButton.classList.remove('is-copied');
      copyLabel.textContent = '复制';
      copyFeedback.textContent = '';
    }, 2400);
  });

  entryCopyButton.addEventListener('click', async () => {
    clearTimeout(entryCopyResetTimer);
    try {
      await copyText(proxyExample);
      entryCopyButton.classList.add('is-copied');
      entryCopyLabel.textContent = '已复制';
    } catch {
      entryCopyButton.classList.remove('is-copied');
      entryCopyLabel.textContent = '复制失败';
    }
    entryCopyResetTimer = window.setTimeout(() => {
      entryCopyButton.classList.remove('is-copied');
      entryCopyLabel.textContent = '复制示例';
    }, 2400);
  });

  function renderHealth(ok, version = '') {
    const state = ok ? 'online' : 'offline';
    headerStatus.dataset.state = state;
    gatewayStatus.dataset.state = state;
    headerStatusLabel.textContent = ok ? '服务正常' : '暂时不可用';
    gatewayStatus.textContent = ok ? '服务正常' : '状态异常';
    serviceState.textContent = ok ? '在线' : '异常';
    gatewayVersion.textContent = version ? `v${String(version).replace(/^v/, '')}` : '--';
  }

  function renderPublicBaseURL(value) {
    try {
      const parsed = new URL(String(value || ''));
      if (!['http:', 'https:'].includes(parsed.protocol)) return;
      parsed.pathname = parsed.pathname.replace(/\/+$/, '');
      parsed.search = '';
      parsed.hash = '';
      publicBaseURL = parsed.toString().replace(/\/+$/, '');
      proxyExample = `${publicBaseURL}/${exampleTarget}`;
      endpointValue.textContent = proxyExample;
      originLabel.textContent = publicBaseURL;
    } catch {
      // Keep the current origin fallback when the server has no configured public URL.
    }
  }

  async function refreshHealth() {
    try {
      const response = await fetch('/_gateway/health', { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('health unavailable');
      const payload = await response.json();
      renderPublicBaseURL(payload.public_base_url);
      renderHealth(Boolean(payload.ok), payload.version || '');
    } catch {
      renderHealth(false);
    }
  }

  function scheduleHealthRefresh() {
    clearInterval(healthTimer);
    healthTimer = window.setInterval(refreshHealth, 60_000);
  }

  const danmakuMessages = [
    '播放继续', '连接稳定', '加载很快', '线路正常', '流畅播放', '服务在线',
    '跳转已接管', '多后端就绪', '正在连接上游', '推流顺畅', '感谢使用', '保持简单', 'Refract'
  ];
  const danmakuColors = [
    '#d4626c', '#1f78a4', '#438b62', '#168f88', '#b44d5d',
    '#8062b3', '#bf6a3c', '#4d68ba', '#a76f1f'
  ];

  function initializeAmbientDanmaku() {
    const layer = document.getElementById('ambient-danmaku');
    let timer;

    function clearDanmaku() {
      clearTimeout(timer);
      layer.replaceChildren();
    }

    function spawnDanmaku(preRoll = false) {
      if (reducedMotion.matches || document.visibilityState !== 'visible') return;
      const item = document.createElement('span');
      const mobile = window.innerWidth <= 720;
      const duration = 16 + Math.random() * 22;
      const delay = preRoll ? -(Math.random() * duration) : Math.random() * 2.5;
      const opacity = (mobile ? 0.1 : 0.16) + Math.random() * (mobile ? 0.08 : 0.1);
      item.textContent = danmakuMessages[Math.floor(Math.random() * danmakuMessages.length)];
      item.style.setProperty('--danmaku-top', `${4 + Math.random() * 90}%`);
      item.style.setProperty('--danmaku-size', `${12 + Math.random() * (mobile ? 6 : 12)}px`);
      item.style.setProperty('--danmaku-color', danmakuColors[Math.floor(Math.random() * danmakuColors.length)]);
      item.style.setProperty('--danmaku-opacity', opacity.toFixed(2));
      item.style.setProperty('--danmaku-duration', `${duration}s`);
      item.style.setProperty('--danmaku-delay', `${delay}s`);
      layer.append(item);
      item.addEventListener('animationend', () => item.remove(), { once: true });
      if (layer.childElementCount > 32) layer.firstElementChild?.remove();
    }

    function tick() {
      spawnDanmaku();
      const baseInterval = window.innerWidth <= 720 ? 900 : 500;
      timer = window.setTimeout(tick, baseInterval + Math.random() * baseInterval * 2);
    }

    function start() {
      if (reducedMotion.matches) return;
      const initial = window.innerWidth <= 720 ? 5 : 9;
      for (let index = 0; index < initial; index += 1) spawnDanmaku(true);
      tick();
    }

    reducedMotion.addEventListener('change', () => {
      clearDanmaku();
      start();
    });
    document.addEventListener('visibilitychange', () => {
      clearTimeout(timer);
      if (document.visibilityState === 'visible') start();
    });
    start();
  }

  function initializePointerTilt() {
    document.querySelectorAll('.pointer-tilt').forEach((card) => {
      const maxTilt = Number(card.dataset.maxTilt) || 5;
      let animationFrame;

      function resetTilt() {
        cancelAnimationFrame(animationFrame);
        card.classList.remove('is-tilting');
        card.style.setProperty('--tilt-x', '0deg');
        card.style.setProperty('--tilt-y', '0deg');
      }

      card.addEventListener('pointermove', (event) => {
        if (reducedMotion.matches || event.pointerType === 'touch') return;
        const rect = card.getBoundingClientRect();
        const xRatio = (event.clientX - rect.left) / rect.width - 0.5;
        const yRatio = (event.clientY - rect.top) / rect.height - 0.5;
        cancelAnimationFrame(animationFrame);
        animationFrame = requestAnimationFrame(() => {
          card.classList.add('is-tilting');
          card.style.setProperty('--tilt-x', `${(-yRatio * maxTilt * 2).toFixed(2)}deg`);
          card.style.setProperty('--tilt-y', `${(xRatio * maxTilt * 2).toFixed(2)}deg`);
        });
      });
      card.addEventListener('pointerleave', resetTilt);
      card.addEventListener('pointercancel', resetTilt);
      reducedMotion.addEventListener('change', resetTilt);
    });
  }

  refreshHealth();
  scheduleHealthRefresh();
  initializeAmbientDanmaku();
  initializePointerTilt();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshHealth();
  });
})();
