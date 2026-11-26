(() => {
  'use strict';

  const prismCard = document.getElementById('prism-card');
  const beamTrack = document.getElementById('beam-track');
  const beamTargetHost = document.getElementById('beam-target-host');
  const modeSwitch = document.getElementById('mode-switch');
  const modeIndicator = document.getElementById('mode-indicator');
  const presetRow = document.getElementById('preset-row');
  const composerGuide = document.getElementById('composer-guide');
  const originRow = document.getElementById('origin-row');
  const originInput = document.getElementById('origin-input');
  const originClear = document.getElementById('origin-clear');
  const originMeta = document.getElementById('origin-meta');
  const originLabel = document.getElementById('origin-label');
  const urlSlash = document.getElementById('url-slash');
  const targetLabel = document.getElementById('target-label');
  const outputBar = document.getElementById('output-bar');
  const outputBadge = document.getElementById('output-badge');
  const outputHint = document.getElementById('output-hint');
  const copyButton = document.getElementById('copy-endpoint');
  const copyLabel = document.getElementById('copy-label');
  const copyFeedback = document.getElementById('copy-feedback');
  const headerStatus = document.getElementById('header-status');
  const headerStatusLabel = document.getElementById('header-status-label');
  const controllerStatus = document.getElementById('controller-status');
  const controllerStatusLabel = document.getElementById('controller-status-label');
  const ctrlArchNodes = document.getElementById('ctrl-arch-nodes');
  const ctrlPlaneTabs = document.getElementById('ctrl-plane-tabs');
  const ctrlPlaneDesc = document.getElementById('ctrl-plane-desc');
  const geoNotice = document.getElementById('geo-notice');
  const geoNoticeRegion = document.getElementById('geo-notice-region');
  const geoNoticeDesc = document.getElementById('geo-notice-desc');
  const gatewayStatus = document.getElementById('gateway-status');
  const gatewayTitle = document.getElementById('gateway-title');
  const gatewayVersion = document.getElementById('gateway-version');
  const edgeLineBar = document.getElementById('edge-line-bar');
  const edgeLinePills = document.getElementById('edge-line-pills');
  const edgeNodesSection = document.getElementById('edge-nodes-section');
  const edgeNodesGroups = document.getElementById('edge-nodes-groups');
  const edgeNodesSummaryPill = document.getElementById('edge-nodes-summary-pill');
  const edgeNodesUpdated = document.getElementById('edge-nodes-updated');
  const healthSection = document.getElementById('emby-health-section');
  const healthAnchor = document.getElementById('health-anchor');
  const healthNavCount = document.getElementById('health-nav-count');
  const healthGroups = document.getElementById('health-groups');
  const healthUpdated = document.getElementById('health-updated');
  const healthSummaryPill = document.getElementById('health-summary-pill');
  const featureCaption = document.getElementById('feature-caption');
  const themeToggle = document.getElementById('theme-toggle');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  const defaultOrigin = 'https://emby.example.com:8096';
  const featureCopy = {
    routing: '保留原始方法、Range 分片与 WebSocket 通道，无需为每台服务器单独配置反代。',
    signing: '自动改写 302 跳转、HLS 播放清单与 Emby 媒体地址，CDN 推流通过短期 HMAC 签名无缝放行。',
    protection: '内置 DNS 固定防 SSRF、黑白名单域名与播放器策略、每日开放时段及单 IP 聚合限速。'
  };
  const ctrlPlaneCopy = {
    edge: '一机多域、Auto-TLS 自动签发与 DNS-01 泛域名托管，SSE 毫秒级热同步并支持断网 Fail-Open。',
    waf: '可视化流图编排地区、播放器、IP/CIDR、路径特征与时段策略，按域名精准绑定并支持轨迹模拟。',
    observe: '实时追踪在线观影片名与码率，支持一键强制断开并阻断重连；聚合来源 IP 与 Emby 源站探针。'
  };

  let publicBaseURL = window.location.origin;
  let fallbackBaseURL = window.location.origin;
  let gatewayRole = document.body.dataset.role || 'standalone';
  let hasDefaultUpstream = false;
  let healthState = { ok: false, version: '', role: gatewayRole, onlineNodes: 0, nodeName: '', draining: false };
  let edgeNodes = [];
  let embyOnline = 0;
  let embyTotal = 0;
  let selectedEdgeNodeID = '';
  let currentMode = 'full';
  let currentProxyURL = `${publicBaseURL}/${defaultOrigin}`;
  let copyTimer = 0;
  let pulseTimer = 0;
  let healthTimer = 0;
  let refreshSeq = 0;

  function safeStorageGet(key) {
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function safeStorageSet(key, val) {
    try { localStorage.setItem(key, val); } catch { /* private mode */ }
  }

  /* -------------------- Theme Persistence -------------------- */

  function applyTheme(theme) {
    const dark = theme === 'dark';
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    safeStorageSet('gateway-theme', dark ? 'dark' : 'light');
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', dark ? '#090b10' : '#f8f9fb');
    if (themeToggle) {
      themeToggle.setAttribute('aria-label', dark ? '切换浅色模式' : '切换深色模式');
      themeToggle.setAttribute('title', dark ? '切换浅色模式' : '切换深色模式');
    }
  }

  applyTheme(safeStorageGet('gateway-theme') === 'dark' ? 'dark' : 'light');
  themeToggle?.addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  /* -------------------- Interactive Optical Pulse -------------------- */

  function triggerBeamPulse() {
    if (!beamTrack || reducedMotion.matches) return;
    beamTrack.classList.remove('is-pulsing');
    void beamTrack.offsetWidth;
    beamTrack.classList.add('is-pulsing');
    clearTimeout(pulseTimer);
    pulseTimer = window.setTimeout(() => beamTrack.classList.remove('is-pulsing'), 780);
  }

  /* -------------------- Mode Switch & Live URL Composer -------------------- */

  function syncModeIndicator() {
    if (!modeSwitch || !modeIndicator) return;
    const active = modeSwitch.querySelector('button.active:not([hidden])');
    if (!active || active.offsetWidth <= 0) {
      modeIndicator.classList.remove('ready');
      return;
    }
    modeIndicator.style.width = `${active.offsetWidth}px`;
    modeIndicator.style.height = `${active.offsetHeight}px`;
    modeIndicator.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop}px)`;
    modeIndicator.classList.add('ready');
  }

  function syncDirectModeAvailability(available) {
    hasDefaultUpstream = Boolean(available);
    const directBtn = modeSwitch?.querySelector('button[data-mode="direct"]');
    const fullBtn = modeSwitch?.querySelector('button[data-mode="full"]');
    if (directBtn) {
      directBtn.hidden = !hasDefaultUpstream;
      directBtn.disabled = !hasDefaultUpstream;
    }
    if (!hasDefaultUpstream && currentMode === 'direct') {
      currentMode = 'full';
      modeSwitch?.querySelectorAll('button').forEach((b) => {
        const active = b === fullBtn;
        b.classList.toggle('active', active);
        b.setAttribute('aria-selected', String(active));
      });
      updateEndpointPreview(false);
    }
    requestAnimationFrame(syncModeIndicator);
  }

  function rawOriginValue() {
    return String(originInput?.value || '').trim();
  }

  function unwrapGatewayPrefix(raw) {
    const bases = [publicBaseURL, fallbackBaseURL, window.location.origin].filter(Boolean);
    for (const base of bases) {
      const prefix = `${base.replace(/\/+$/, '')}/`;
      if (raw.toLowerCase().startsWith(prefix.toLowerCase())) {
        const inner = raw.slice(prefix.length).trim();
        if (/^https?:\/\//i.test(inner)) return inner;
      }
    }
    return raw;
  }

  function normalizedOrigin() {
    const raw = unwrapGatewayPrefix(rawOriginValue());
    if (!raw) return defaultOrigin;
    if (/^https?:?\/{0,2}$/i.test(raw)) return raw;
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    return withScheme.replace(/\/+$/, '');
  }

  function parseValidOrigin(target) {
    try {
      if (/\s/.test(target)) return null;
      const parsed = new URL(target);
      if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) return null;
      const host = parsed.hostname.toLowerCase();
      if (host !== 'localhost' && !host.includes('.') && !host.includes(':')) return null;
      return parsed;
    } catch {
      return null;
    }
  }

  function isExampleHostname(hostname) {
    const host = String(hostname || '').toLowerCase();
    return host === 'example.com' || host.endsWith('.example.com');
  }

  function setOriginMeta(text, tone) {
    if (!originMeta) return;
    originMeta.textContent = text;
    originMeta.classList.toggle('is-idle', tone === 'idle');
    originMeta.classList.toggle('is-valid', tone === 'valid');
    originMeta.classList.toggle('is-warn', tone === 'warn');
  }

  function setOutputStatus(badge, hint, tone) {
    if (outputBadge) {
      outputBadge.textContent = badge;
      outputBadge.classList.toggle('is-custom', tone === 'custom');
      outputBadge.classList.toggle('is-warn', tone === 'warn');
    }
    if (outputHint) outputHint.textContent = hint;
    outputBar?.classList.toggle('is-ready', tone === 'custom');
  }

  function nudgeOriginInput() {
    if (!originRow) return;
    originRow.classList.remove('is-nudge');
    void originRow.offsetWidth;
    originRow.classList.add('is-nudge');
    originInput?.focus();
  }

  function updateEndpointPreview(pulse = false) {
    originLabel.textContent = publicBaseURL;
    if (currentMode === 'direct') {
      currentProxyURL = publicBaseURL;
      urlSlash.hidden = true;
      targetLabel.hidden = true;
      targetLabel.classList.remove('is-placeholder');
      originRow.hidden = true;
      presetRow.hidden = true;
      if (composerGuide) composerGuide.hidden = true;
      beamTargetHost.textContent = '默认上游';
      setOutputStatus('直连入口', '复制后直接填入 Emby / 播放器服务器地址即可', 'custom');
    } else {
      const raw = rawOriginValue();
      const hasInput = raw.length > 0;
      const target = normalizedOrigin();
      const parsed = parseValidOrigin(target);
      currentProxyURL = `${publicBaseURL}/${target}`;
      urlSlash.hidden = false;
      targetLabel.hidden = false;
      targetLabel.textContent = target;
      targetLabel.classList.toggle('is-placeholder', !hasInput);
      originRow.hidden = false;
      presetRow.hidden = false;
      if (composerGuide) composerGuide.hidden = false;
      if (originClear) originClear.hidden = !hasInput;

      if (!hasInput) {
        setOriginMeta('支持直接输入', 'idle');
        setOutputStatus('示例预览', '输入上方源站地址后将实时替换', 'idle');
        beamTargetHost.textContent = 'emby.example.com';
      } else if (parsed) {
        const proto = parsed.protocol.replace(':', '').toUpperCase();
        const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
        setOriginMeta(`${proto} · ${port}`, 'valid');
        beamTargetHost.textContent = parsed.hostname || '目标源站';
        if (isExampleHostname(parsed.hostname)) {
          setOutputStatus('示例模板', '将上方地址替换为你的真实源站即可使用', 'idle');
        } else {
          setOutputStatus('已自动生成', '复制后直接填入 Emby / 播放器服务器地址即可', 'custom');
        }
      } else {
        setOriginMeta('待补全地址', 'warn');
        setOutputStatus('待补全', '请输入完整的源站域名或 IP（可省略 https://）', 'warn');
        beamTargetHost.textContent = '目标源站';
      }
    }
    if (pulse) triggerBeamPulse();
  }

  modeSwitch?.querySelectorAll('button[data-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.dataset.mode === currentMode) return;
      currentMode = btn.dataset.mode;
      modeSwitch.querySelectorAll('button').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('active', active);
        b.setAttribute('aria-selected', String(active));
      });
      syncModeIndicator();
      updateEndpointPreview(true);
    });
  });

  presetRow?.querySelectorAll('.preset-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      presetRow.querySelectorAll('.preset-chip').forEach((c) => c.classList.toggle('active', c === chip));
      originInput.value = chip.dataset.preset;
      updateEndpointPreview(true);
      originInput.focus();
      originInput.select();
    });
  });

  originInput?.addEventListener('input', () => {
    const val = rawOriginValue();
    presetRow?.querySelectorAll('.preset-chip').forEach((c) => c.classList.toggle('active', c.dataset.preset === val));
    updateEndpointPreview(false);
  });

  originInput?.addEventListener('paste', () => {
    window.setTimeout(() => {
      const raw = rawOriginValue();
      const unwrapped = unwrapGatewayPrefix(raw);
      if (unwrapped !== raw) originInput.value = unwrapped;
      const val = rawOriginValue();
      presetRow?.querySelectorAll('.preset-chip').forEach((c) => c.classList.toggle('active', c.dataset.preset === val));
      updateEndpointPreview(Boolean(val));
    }, 0);
  });

  originRow?.addEventListener('click', (e) => {
    if (e.target.closest('button')) return;
    originInput?.focus();
  });

  originClear?.addEventListener('click', () => {
    if (!originInput) return;
    originInput.value = '';
    presetRow?.querySelectorAll('.preset-chip').forEach((c) => c.classList.remove('active'));
    updateEndpointPreview(false);
    originInput.focus();
  });

  /* -------------------- Copy Interaction -------------------- */

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

  copyButton?.addEventListener('click', async () => {
    clearTimeout(copyTimer);
    const raw = rawOriginValue();
    const parsed = currentMode === 'full' ? parseValidOrigin(normalizedOrigin()) : null;
    copyFeedback.classList.remove('is-tip', 'is-error');
    if (currentMode === 'full' && raw && !parsed) {
      copyFeedback.classList.add('is-error');
      copyFeedback.textContent = '源站地址尚未填写完整，请输入有效域名或 IP 后再复制';
      nudgeOriginInput();
      copyTimer = window.setTimeout(() => {
        copyFeedback.classList.remove('is-tip', 'is-error');
        copyFeedback.textContent = '';
      }, 3200);
      return;
    }
    triggerBeamPulse();
    const isExampleCopy = currentMode === 'full' && (!raw || (parsed && isExampleHostname(parsed.hostname)));
    try {
      await copyText(currentProxyURL);
      copyButton.classList.add('is-copied');
      outputBar.classList.add('is-copied');
      copyLabel.textContent = '已复制';
      if (isExampleCopy) {
        copyFeedback.classList.add('is-tip');
        copyFeedback.textContent = '已复制示例地址；在上方输入你的真实源站地址即可自动生成专属入口';
        if (!raw) nudgeOriginInput();
      } else {
        copyFeedback.textContent = '反代入口已复制，直接填入 Emby / 播放器服务器地址即可';
      }
    } catch {
      copyButton.classList.remove('is-copied');
      outputBar.classList.remove('is-copied');
      copyLabel.textContent = '复制入口';
      copyFeedback.classList.add('is-error');
      copyFeedback.textContent = '复制失败，请手动选中地址复制';
    }
    copyTimer = window.setTimeout(() => {
      copyButton.classList.remove('is-copied');
      outputBar.classList.remove('is-copied');
      copyLabel.textContent = '复制入口';
      copyFeedback.classList.remove('is-tip', 'is-error');
      copyFeedback.textContent = '';
    }, isExampleCopy ? 4200 : 2800);
  });

  /* -------------------- Interactive Feature Pills -------------------- */

  document.querySelectorAll('.feature-pill').forEach((pill) => {
    const activate = () => {
      const key = pill.dataset.feature;
      if (!featureCopy[key] || pill.classList.contains('active')) return;
      document.querySelectorAll('.feature-pill').forEach((p) => {
        const active = p === pill;
        p.classList.toggle('active', active);
        p.setAttribute('aria-selected', String(active));
      });
      featureCaption.classList.add('swapping');
      window.setTimeout(() => {
        featureCaption.textContent = featureCopy[key];
        featureCaption.classList.remove('swapping');
      }, 130);
    };
    pill.addEventListener('click', activate);
    pill.addEventListener('pointerenter', (e) => { if (e.pointerType !== 'touch') activate(); });
  });

  /* -------------------- Cursor Spotlight & Subtle Card Physics -------------------- */

  function initInteractiveLight() {
    let targetX = window.innerWidth * 0.5;
    let targetY = window.innerHeight * 0.28;
    let curX = targetX;
    let curY = targetY;
    let rafId = 0;

    const animateSpotlight = () => {
      curX += (targetX - curX) * 0.12;
      curY += (targetY - curY) * 0.12;
      document.documentElement.style.setProperty('--spot-x', `${curX.toFixed(1)}px`);
      document.documentElement.style.setProperty('--spot-y', `${curY.toFixed(1)}px`);
      if (Math.abs(targetX - curX) > 0.5 || Math.abs(targetY - curY) > 0.5) {
        rafId = requestAnimationFrame(animateSpotlight);
      } else {
        rafId = 0;
      }
    };

    window.addEventListener('pointermove', (e) => {
      if (reducedMotion.matches || e.pointerType === 'touch') return;
      targetX = e.clientX;
      targetY = e.clientY;
      if (!rafId) rafId = requestAnimationFrame(animateSpotlight);
    }, { passive: true });

    if (prismCard) {
      let cardRaf = 0;
      prismCard.addEventListener('pointermove', (e) => {
        if (reducedMotion.matches || e.pointerType === 'touch') return;
        const rect = prismCard.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        const rx = ((y / rect.height) - 0.5) * -3.2;
        const ry = ((x / rect.width) - 0.5) * 3.2;
        cancelAnimationFrame(cardRaf);
        cardRaf = requestAnimationFrame(() => {
          prismCard.classList.add('is-tilting');
          prismCard.style.setProperty('--card-x', `${x.toFixed(1)}px`);
          prismCard.style.setProperty('--card-y', `${y.toFixed(1)}px`);
          prismCard.style.setProperty('--tilt-x', `${rx.toFixed(2)}deg`);
          prismCard.style.setProperty('--tilt-y', `${ry.toFixed(2)}deg`);
        });
      });
      const resetCard = () => {
        cancelAnimationFrame(cardRaf);
        prismCard.classList.remove('is-tilting');
        prismCard.style.setProperty('--tilt-x', '0deg');
        prismCard.style.setProperty('--tilt-y', '0deg');
      };
      prismCard.addEventListener('pointerleave', resetCard);
      prismCard.addEventListener('pointercancel', resetCard);
    }
  }

  /* -------------------- Live Health & Public Emby Status -------------------- */

  function relativeTime(seconds) {
    const ts = Number(seconds);
    if (!Number.isFinite(ts) || ts <= 0) return '刚刚';
    const delta = Math.max(0, Math.floor(Date.now() / 1000) - ts);
    if (delta < 60) return '刚刚';
    if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`;
    if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`;
    return `${Math.floor(delta / 86400)} 天前`;
  }

  const countryNames = {
    CN: '中国大陆', HK: '中国香港', TW: '中国台湾', MO: '中国澳门',
    SG: '新加坡', JP: '日本', KR: '韩国', US: '美国', GB: '英国',
    DE: '德国', FR: '法国', NL: '荷兰', CA: '加拿大', AU: '澳大利亚',
    RU: '俄罗斯', IN: '印度', MY: '马来西亚', TH: '泰国', VN: '越南'
  };

  function renderGeoNotice(blocked, country, message) {
    if (!geoNotice || !geoNoticeDesc) return;
    if (!blocked || gatewayRole === 'controller') {
      geoNotice.hidden = true;
      return;
    }
    const code = String(country || '').trim().toUpperCase();
    const label = code ? (countryNames[code] ? `${countryNames[code]} (${code})` : code) : '';
    if (geoNoticeRegion) {
      geoNoticeRegion.textContent = label ? `当前地区：${label}` : '';
      geoNoticeRegion.hidden = !label;
    }
    const customMsg = String(message || '').trim();
    const isGeneric = !customMsg || customMsg === 'blocked by WAF rule' || customMsg === 'region is blocked by access policy';
    const regionPhrase = label ? `（${label}）` : '';
    const baseText = `检测到你当前的访问地区${regionPhrase}不在本线路允许范围内，可正常浏览本页，但实际反代与媒体播放请求将被拦截。`;
    geoNoticeDesc.textContent = isGeneric ? baseText : `${baseText} 策略提示：${customMsg}`;
    geoNotice.hidden = false;
  }

  function syncHealthAnchor() {
    if (!healthAnchor || !healthNavCount) return;
    if (gatewayRole === 'controller') {
      healthAnchor.hidden = true;
      return;
    }
    if (edgeNodes.length > 0) {
      healthAnchor.href = '#edge-nodes-section';
      healthAnchor.hidden = false;
      healthNavCount.textContent = `${edgeNodes.length} 条在线线路`;
      return;
    }
    if (gatewayRole === 'standalone' && embyTotal > 0) {
      healthAnchor.href = '#emby-health-section';
      healthAnchor.hidden = false;
      healthNavCount.textContent = `${embyOnline}/${embyTotal} 节点在线`;
      return;
    }
    healthAnchor.hidden = true;
  }

  function syncHeaderStatus() {
    const isAgent = gatewayRole === 'agent';
    const isController = gatewayRole === 'controller';
    document.body.dataset.role = gatewayRole;
    document.querySelectorAll('[data-admin-link]').forEach((el) => { el.hidden = isAgent; });
    const state = !healthState.ok ? 'offline' : (isAgent && healthState.draining ? 'checking' : 'online');
    headerStatus.dataset.state = state;
    gatewayStatus.dataset.state = state;
    if (controllerStatus) controllerStatus.dataset.state = state;
    if (!healthState.ok) {
      headerStatusLabel.textContent = '服务暂时不可用';
      if (controllerStatusLabel) controllerStatusLabel.textContent = '主控服务暂时不可用';
      if (ctrlArchNodes) ctrlArchNodes.textContent = '等待服务恢复';
    } else if (isController) {
      const ctrlText = healthState.onlineNodes > 0
        ? `主控运行正常 · ${healthState.onlineNodes} 个边缘节点在线`
        : '主控运行正常 · 等待边缘节点接入';
      headerStatusLabel.textContent = ctrlText;
      if (controllerStatusLabel) controllerStatusLabel.textContent = ctrlText;
      if (ctrlArchNodes) ctrlArchNodes.textContent = healthState.onlineNodes > 0 ? `${healthState.onlineNodes} 个在线节点` : '集群控制面就绪';
    } else if (isAgent && healthState.draining) {
      headerStatusLabel.textContent = healthState.nodeName ? `边缘节点维护中 · ${healthState.nodeName}` : '边缘节点维护中';
    } else if (edgeNodes.length > 0) {
      headerStatusLabel.textContent = `多线路集群在线 · ${edgeNodes.length} 条可用线路`;
    } else if (isAgent) {
      headerStatusLabel.textContent = healthState.nodeName ? `边缘节点在线 · ${healthState.nodeName}` : '边缘节点在线运行中';
      if (gatewayTitle && healthState.nodeName && !selectedEdgeNodeID) gatewayTitle.textContent = healthState.nodeName;
    } else {
      headerStatusLabel.textContent = '网关在线运行中';
    }
    if (healthState.version) gatewayVersion.textContent = `v${String(healthState.version).replace(/^v/, '')}`;
  }

  function renderHealth(ok, version = '', role = '', onlineNodes = 0, nodeName = '', draining = false, geoBlocked = false, geoCountry = '', geoMessage = '') {
    if (role) gatewayRole = role;
    healthState = {
      ok: Boolean(ok),
      version: version || healthState.version,
      role: gatewayRole,
      onlineNodes: Number(onlineNodes) || 0,
      nodeName: nodeName || healthState.nodeName,
      draining: Boolean(draining)
    };
    syncHeaderStatus();
    syncHealthAnchor();
    renderGeoNotice(Boolean(geoBlocked), geoCountry, geoMessage);
  }

  function sanitizePublicOrigin(value) {
    try {
      const parsed = new URL(String(value || ''));
      if (!['http:', 'https:'].includes(parsed.protocol)) return '';
      parsed.pathname = parsed.pathname.replace(/\/+$/, '');
      parsed.search = '';
      parsed.hash = '';
      return parsed.toString().replace(/\/+$/, '');
    } catch {
      return '';
    }
  }

  function renderPublicBaseURL(value) {
    const clean = sanitizePublicOrigin(value);
    if (!clean) return;
    fallbackBaseURL = clean;
    if (!selectedEdgeNodeID) {
      publicBaseURL = fallbackBaseURL;
      updateEndpointPreview(false);
    }
  }

  function selectEdgeNode(node, pulse = false) {
    if (!node) return;
    selectedEdgeNodeID = node.id;
    const cleanURL = sanitizePublicOrigin(node.public_url);
    publicBaseURL = cleanURL || fallbackBaseURL;
    if (gatewayTitle) {
      gatewayTitle.textContent = node.name || 'Refract';
      gatewayTitle.title = node.name || 'Refract';
    }
    if ('has_default_upstream' in node) {
      syncDirectModeAvailability(Boolean(node.has_default_upstream));
    }
    edgeLinePills?.querySelectorAll('.edge-line-pill').forEach((btn) => {
      const active = btn.dataset.nodeId === selectedEdgeNodeID;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    edgeNodesGroups?.querySelectorAll('[data-edge-card-id]').forEach((card) => {
      const active = card.dataset.edgeCardId === selectedEdgeNodeID;
      card.classList.toggle('is-selected-edge', active);
      const useBtn = card.querySelector('.edge-use-btn');
      if (useBtn) {
        useBtn.classList.toggle('active', active);
        useBtn.setAttribute('aria-pressed', String(active));
        useBtn.textContent = active ? '当前线路' : '使用此线路';
      }
    });
    updateEndpointPreview(pulse);
  }

  function renderEdgeNodesShowcase(list) {
    if (!edgeNodesSection || !edgeNodesGroups) return;
    const hasNodes = list.length > 0;
    edgeNodesSection.hidden = !hasNodes;
    if (!hasNodes) {
      edgeNodesGroups.classList.remove('is-single-group');
      edgeNodesGroups.replaceChildren();
      syncHealthAnchor();
      return;
    }
    const grouped = new Map();
    let latestSeen = 0;
    let totalHealthyNodes = 0;
    list.forEach((node) => {
      const key = String(node.group_name || '').trim() || '可用边缘线路';
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(node);
      if (Number(node.last_seen) > latestSeen) latestSeen = Number(node.last_seen);
      totalHealthyNodes += Math.max(1, Number(node.healthy_nodes) || 1);
    });
    edgeNodesGroups.classList.toggle('is-single-group', grouped.size === 1);

    const frag = document.createDocumentFragment();
    grouped.forEach((items, groupName) => {
      const section = document.createElement('section');
      section.className = 'public-health-group';
      const head = document.createElement('div');
      head.className = 'public-health-group-head';
      const h3 = document.createElement('h3');
      h3.textContent = groupName;
      const count = document.createElement('span');
      count.textContent = `${items.length} 条在线`;
      head.append(h3, count);
      section.append(head);

      items.forEach((node) => {
        const isActive = node.id === selectedEdgeNodeID;
        const row = document.createElement('article');
        row.className = `public-health-server${isActive ? ' is-selected-edge' : ''}`;
        row.dataset.edgeCardId = node.id;

        const top = document.createElement('div');
        top.className = 'public-health-top';
        const id = document.createElement('div');
        id.className = 'public-health-identity';
        const name = document.createElement('strong');
        name.textContent = node.name || node.public_url;
        id.append(name);

        let hostLabel = String(node.public_url || '').replace(/^https?:\/\//i, '').replace(/\/+$/, '');
        try { hostLabel = new URL(node.public_url).host || hostLabel; } catch { /* keep raw */ }

        const tags = document.createElement('div');
        tags.className = 'public-health-tags';
        if (node.region) {
          const t = document.createElement('span');
          t.className = 'public-tag line';
          t.textContent = node.region;
          tags.append(t);
        }
        if (hostLabel && hostLabel !== node.name) {
          const t = document.createElement('span');
          t.className = 'public-tag';
          t.textContent = hostLabel;
          tags.append(t);
        }
        if (tags.childElementCount) id.append(tags);

        const checked = document.createElement('small');
        checked.className = 'public-health-checked';
        checked.textContent = node.last_seen ? `最近心跳 ${relativeTime(node.last_seen)}` : '实时在线';
        id.append(checked);

        const actions = document.createElement('div');
        actions.className = 'public-edge-actions';
        const useBtn = document.createElement('button');
        useBtn.type = 'button';
        useBtn.className = `edge-use-btn${isActive ? ' active' : ''}`;
        useBtn.setAttribute('aria-pressed', String(isActive));
        useBtn.textContent = isActive ? '当前线路' : '使用此线路';
        useBtn.addEventListener('click', () => {
          selectEdgeNode(node, true);
          prismCard?.scrollIntoView({ behavior: reducedMotion.matches ? 'auto' : 'smooth', block: 'center' });
        });
        const st = document.createElement('span');
        st.className = 'public-health-status';
        st.dataset.state = node.draining ? 'draining' : (node.online === false ? 'offline' : 'online');
        st.textContent = node.draining ? '维护中' : (node.online === false ? '离线' : '在线');
        actions.append(useBtn, st);
        top.append(id, actions);

        const healthyCount = Math.max(1, Number(node.healthy_nodes) || 1);
        const totalCount = Math.max(healthyCount, Number(node.total_nodes) || healthyCount);
        const versionText = node.version ? `v${String(node.version).replace(/^v/, '')}` : '—';
        const metrics = document.createElement('div');
        metrics.className = 'public-health-metrics';
        [
          { label: '入口域名', text: hostLabel || '—' },
          { label: '在线节点', text: `${healthyCount} / ${totalCount}` },
          { label: '当前并发', text: `${Number(node.active_requests) || 0}` },
          { label: '节点版本', text: versionText }
        ].forEach((m) => {
          const box = document.createElement('div');
          box.className = 'public-health-metric';
          const lbl = document.createElement('small');
          lbl.textContent = m.label;
          const val = document.createElement('strong');
          val.textContent = m.text;
          val.title = m.text;
          box.append(lbl, val);
          metrics.append(box);
        });
        row.append(top, metrics);
        section.append(row);
      });
      frag.append(section);
    });

    edgeNodesGroups.replaceChildren(frag);
    if (edgeNodesSummaryPill) edgeNodesSummaryPill.textContent = `${list.length} 条线路 · ${totalHealthyNodes} 个节点在线`;
    if (edgeNodesUpdated) edgeNodesUpdated.textContent = latestSeen ? `更新于 ${relativeTime(latestSeen)}` : '实时同步';
    syncHealthAnchor();
  }

  function renderEdgeNodes(payload) {
    const list = Array.isArray(payload?.nodes) ? payload.nodes : [];
    if (payload?.role) gatewayRole = payload.role;
    edgeNodes = list;
    if (!edgeLineBar || !edgeLinePills) return;
    if (!list.length) {
      edgeLineBar.hidden = true;
      edgeLinePills.replaceChildren();
      selectedEdgeNodeID = '';
      publicBaseURL = fallbackBaseURL;
      if (gatewayTitle) gatewayTitle.textContent = 'Refract';
      renderEdgeNodesShowcase([]);
      updateEndpointPreview(false);
      syncHeaderStatus();
      return;
    }
    edgeLineBar.hidden = false;
    const active = list.find((n) => n.id === selectedEdgeNodeID) || list[0];
    const frag = document.createDocumentFragment();
    list.forEach((node) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `edge-line-pill${node.id === active.id ? ' active' : ''}`;
      btn.dataset.nodeId = node.id;
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', String(node.id === active.id));
      const dot = document.createElement('span');
      dot.className = 'edge-line-dot';
      dot.setAttribute('aria-hidden', 'true');
      const name = document.createElement('span');
      name.textContent = node.name;
      btn.append(dot, name);
      if (node.group_name) {
        const grp = document.createElement('span');
        grp.className = 'edge-line-group';
        grp.textContent = node.group_name;
        btn.append(grp);
      }
      btn.addEventListener('click', () => selectEdgeNode(node, true));
      frag.append(btn);
    });
    edgeLinePills.replaceChildren(frag);
    selectEdgeNode(active, false);
    renderEdgeNodesShowcase(list);
    syncHeaderStatus();
  }

  async function refreshEdgeNodes(seq) {
    try {
      const res = await fetch('/_gateway/nodes', { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (!res.ok) return;
      const payload = await res.json();
      if (seq !== refreshSeq) return;
      renderEdgeNodes(payload);
    } catch { /* ignore */ }
  }

  async function refreshHealth(seq) {
    try {
      const res = await fetch('/_gateway/health', { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error('health unavailable');
      const payload = await res.json();
      if (seq !== refreshSeq) return;
      renderPublicBaseURL(payload.public_base_url);
      if (!selectedEdgeNodeID && 'has_default_upstream' in payload) {
        syncDirectModeAvailability(Boolean(payload.has_default_upstream));
      }
      renderHealth(
        Boolean(payload.ok),
        payload.version || '',
        payload.role || gatewayRole,
        Number(payload.online_nodes) || 0,
        payload.node_name || '',
        Boolean(payload.draining),
        Boolean(payload.geo_blocked),
        payload.geo_country || '',
        payload.geo_message || ''
      );
    } catch {
      if (seq !== refreshSeq) return;
      // Preserve last known gatewayRole on transient network failure so Agent never reveals admin links.
      renderHealth(false, '', gatewayRole, 0, '', false, false, '', '');
    }
  }

  function renderEmbyHealth(snapshot) {
    const groups = Array.isArray(snapshot?.groups) ? snapshot.groups : [];
    const hasGroups = groups.length > 0;
    healthSection.hidden = !hasGroups;
    if (!hasGroups) {
      embyOnline = 0;
      embyTotal = 0;
      healthGroups.classList.remove('is-single-group');
      healthGroups.replaceChildren();
      syncHealthAnchor();
      return;
    }
    healthGroups.classList.toggle('is-single-group', groups.length === 1);

    let total = 0;
    let online = 0;
    const statusLabels = { online: '在线', offline: '离线', unknown: '待检测' };
    const frag = document.createDocumentFragment();

    groups.forEach((group) => {
      const servers = Array.isArray(group.servers) ? group.servers : [];
      const groupOnline = servers.filter((s) => s.status === 'online').length;
      total += servers.length;
      online += groupOnline;

      const section = document.createElement('section');
      section.className = 'public-health-group';
      const head = document.createElement('div');
      head.className = 'public-health-group-head';
      const h3 = document.createElement('h3');
      h3.textContent = group.name;
      const count = document.createElement('span');
      count.textContent = `${groupOnline} / ${servers.length} 在线`;
      head.append(h3, count);
      section.append(head);

      servers.forEach((s) => {
        const row = document.createElement('article');
        row.className = 'public-health-server';
        const top = document.createElement('div');
        top.className = 'public-health-top';
        const id = document.createElement('div');
        id.className = 'public-health-identity';
        const name = document.createElement('strong');
        name.textContent = s.name;
        id.append(name);
        if (s.line_name || s.note) {
          const tags = document.createElement('div');
          tags.className = 'public-health-tags';
          if (s.line_name) { const t = document.createElement('span'); t.className = 'public-tag line'; t.textContent = s.line_name; tags.append(t); }
          if (s.note) { const t = document.createElement('span'); t.className = 'public-tag'; t.textContent = s.note; tags.append(t); }
          id.append(tags);
        }
        const checked = document.createElement('small');
        checked.className = 'public-health-checked';
        checked.textContent = s.last_checked_at ? `最近检测 ${relativeTime(s.last_checked_at)}` : '尚未检测';
        id.append(checked);

        const st = document.createElement('span');
        st.className = 'public-health-status';
        st.dataset.state = statusLabels[s.status] ? s.status : 'unknown';
        st.textContent = statusLabels[s.status] || '待检测';
        top.append(id, st);

        const metrics = document.createElement('div');
        metrics.className = 'public-health-metrics';
        [
          { label: '延迟', text: s.last_checked_at ? `${Number(s.latency_ms) || 0} ms` : '—', pct: null },
          { label: '24 小时', pct: s.availability_24h ?? null },
          { label: '7 天', pct: s.availability_7d ?? null },
          { label: '30 天', pct: s.availability_30d ?? null }
        ].forEach((m) => {
          const box = document.createElement('div');
          box.className = 'public-health-metric';
          const lbl = document.createElement('small');
          lbl.textContent = m.label;
          const val = document.createElement('strong');
          val.textContent = m.text !== undefined ? m.text : (m.pct === null ? '—' : `${Number(m.pct).toFixed(1)}%`);
          box.append(lbl, val);
          if (m.pct !== null) {
            const pct = Math.max(0, Math.min(100, Number(m.pct)));
            const bar = document.createElement('div');
            bar.className = 'public-sla-bar';
            const fill = document.createElement('div');
            fill.className = `public-sla-fill${pct < 90 ? ' bad' : pct < 99 ? ' warn' : ''}`;
            fill.style.width = `${pct}%`;
            bar.append(fill);
            box.append(bar);
          }
          metrics.append(box);
        });
        row.append(top, metrics);
        section.append(row);
      });
      frag.append(section);
    });

    healthGroups.replaceChildren(frag);
    embyOnline = online;
    embyTotal = total;
    if (healthSummaryPill) healthSummaryPill.textContent = `${online} / ${total} 在线`;
    healthUpdated.textContent = snapshot.updated_at ? `更新于 ${relativeTime(snapshot.updated_at)}` : '已更新';
    syncHealthAnchor();
  }

  async function refreshEmbyHealth(seq) {
    try {
      const res = await fetch('/_gateway/emby-health', { cache: 'no-store', headers: { Accept: 'application/json' } });
      if (!res.ok) throw new Error('unavailable');
      const payload = await res.json();
      if (seq !== refreshSeq) return;
      renderEmbyHealth(payload);
    } catch { /* ignore */ }
  }

  async function refreshAll() {
    const seq = ++refreshSeq;
    await refreshHealth(seq);
    if (seq !== refreshSeq) return;
    if (gatewayRole === 'standalone') {
      await Promise.all([refreshEdgeNodes(seq), refreshEmbyHealth(seq)]);
    } else if (healthSection) {
      healthSection.hidden = true;
      embyOnline = 0;
      embyTotal = 0;
      syncHealthAnchor();
    }
  }

  ctrlPlaneTabs?.querySelectorAll('[data-ctrl-plane]').forEach((tab) => {
    tab.addEventListener('click', () => {
      const key = tab.dataset.ctrlPlane || 'edge';
      ctrlPlaneTabs.querySelectorAll('[data-ctrl-plane]').forEach((btn) => {
        const active = btn === tab;
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-selected', String(active));
      });
      if (ctrlPlaneDesc && ctrlPlaneCopy[key]) {
        ctrlPlaneDesc.textContent = ctrlPlaneCopy[key];
      }
    });
  });

  document.getElementById('current-year').textContent = String(new Date().getFullYear());
  syncDirectModeAvailability(false);
  updateEndpointPreview(false);
  requestAnimationFrame(syncModeIndicator);
  window.addEventListener('resize', syncModeIndicator);
  initInteractiveLight();
  refreshAll();
  healthTimer = window.setInterval(refreshAll, 30_000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') refreshAll();
  });
})();
