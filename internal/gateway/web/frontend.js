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
  const healthSection = document.getElementById('emby-health-section');
  const healthGroups = document.getElementById('health-groups');
  const healthUpdated = document.getElementById('health-updated');
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

  function relativeTime(seconds) {
    const delta = Math.max(0, Math.floor(Date.now() / 1000) - Number(seconds));
    if (delta < 60) return '刚刚';
    if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`;
    if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`;
    return `${Math.floor(delta / 86400)} 天前`;
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
    healthTimer = window.setInterval(() => {
      refreshHealth();
      refreshEmbyHealth();
    }, 60_000);
  }

  function publicAvailability(value) {
    return value === null || value === undefined ? '—' : `${Number(value).toFixed(1)}%`;
  }

  function renderEmbyHealth(snapshot) {
    const groups = Array.isArray(snapshot?.groups) ? snapshot.groups : [];
    healthSection.hidden = groups.length === 0;
    if (!groups.length) {
      healthGroups.replaceChildren();
      healthUpdated.textContent = '暂无公开监测服务器';
      return;
    }
    const statusLabels = { online: '在线', offline: '离线', unknown: '待检测' };
    const fragment = document.createDocumentFragment();
    groups.forEach((group) => {
      const section = document.createElement('section');
      section.className = 'public-health-group';
      const heading = document.createElement('h3');
      heading.textContent = group.name;
      section.append(heading);
      (Array.isArray(group.servers) ? group.servers : []).forEach((server) => {
        const row = document.createElement('article');
        row.className = 'public-health-server';
        const identity = document.createElement('div');
        identity.className = 'public-health-identity';
        const name = document.createElement('strong');
        name.textContent = server.name;
        if (server.line_name) {
          const line = document.createElement('small');
          line.className = 'public-health-line';
          line.textContent = server.line_name;
          identity.append(line);
        }
        if (server.note) {
          const note = document.createElement('small');
          note.className = 'public-health-note';
          note.textContent = server.note;
          identity.append(note);
        }
        const checked = document.createElement('small');
        checked.className = 'public-health-checked';
        checked.textContent = server.last_checked_at ? `最近检测 ${relativeTime(server.last_checked_at)}` : '尚未检测';
        identity.prepend(name);
        identity.append(checked);
        const status = document.createElement('span');
        status.className = 'public-health-status';
        status.dataset.state = statusLabels[server.status] ? server.status : 'unknown';
        status.textContent = statusLabels[server.status] || '待检测';
        const metrics = document.createElement('div');
        metrics.className = 'public-health-metrics';
        [
          ['延迟', server.last_checked_at ? `${Number(server.latency_ms) || 0} ms` : '—'],
          ['24 小时', publicAvailability(server.availability_24h)],
          ['7 天', publicAvailability(server.availability_7d)],
          ['30 天', publicAvailability(server.availability_30d)]
        ].forEach(([label, value]) => {
          const metric = document.createElement('div');
          metric.className = 'public-health-metric';
          const metricLabel = document.createElement('small');
          metricLabel.textContent = label;
          const metricValue = document.createElement('strong');
          metricValue.textContent = value;
          metric.append(metricLabel, metricValue);
          metrics.append(metric);
        });
        row.append(identity, status, metrics);
        section.append(row);
      });
      fragment.append(section);
    });
    healthGroups.replaceChildren(fragment);
    healthUpdated.textContent = snapshot.updated_at ? `更新于 ${relativeTime(snapshot.updated_at)}` : '已更新';
  }

  async function refreshEmbyHealth() {
    try {
      const response = await fetch('/_gateway/emby-health', { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (!response.ok) throw new Error('health unavailable');
      renderEmbyHealth(await response.json());
    } catch {
      if (healthGroups.childElementCount === 0) healthUpdated.textContent = '状态暂时不可用';
    }
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
  refreshEmbyHealth();
  scheduleHealthRefresh();
  initializeAmbientDanmaku();
  initializePointerTilt();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      refreshHealth();
      refreshEmbyHealth();
    }
  });
})();
