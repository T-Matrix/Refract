(() => {
  'use strict';

  const applicationTimeZone = 'Asia/Shanghai';
  function safeStorageGet(key) {
    try { return window.localStorage.getItem(key); } catch { return null; }
  }
  function safeStorageSet(key, value) {
    try { window.localStorage.setItem(key, value); } catch { /* ignore private mode quota */ }
  }

  const state = {
    snapshot: null,
    geography: null,
    overviewPeriod: '24h',
    overviewChart: null,
    geoChart: null,
    geoMapPromise: null,
    geoFeaturesPromise: null,
    geoFeatures: null,
    geoMode: (safeStorageGet('gateway-geo-mode') === '2d' ? '2d' : '3d'),
    geoView: { center: [0, 0], zoom: 1.08 },
    geoChartEventsBound: false,
    geoWheelBound: false,
    geoTab: 'regions',
    geographyPromise: null,
    geoReqSeq: 0,
    view: 'overview',
    settingsSection: 'settings-runtime',
    dashboardTimer: null,
    dashboardPromise: null,
    dashboardReqKey: '',
    dashboardReqSeq: 0,
    liveTimer: null,
    liveRefreshing: false,
    updateTimer: null,
    policy: null,
    busyNodeIDs: new Set(),
    busyDomainIDs: new Set(),
    lastDrawerTrigger: new Map(),
    connectionsData: [],
    connectionsQuery: '',
    watchingActive: [],
    watchingHistory: [],
    watchingSummary: null,
    watchingQuery: '',
    watchingPromise: null,
    lastWatchingCount: -1,
    lastWatchingRefresh: 0,
    role: 'standalone',
    publicPortalEnabled: true,
    nodeScope: '',
    nodesData: [],
    nodesSummary: null,
    nodesQuery: '',
    nodesFilter: 'all',
    nodeEditingID: null,
    nodeDeploy: null,
    nodeDeployTab: 'oneclick',
    nodesPromise: null,
    lastNodesRefresh: 0,
    discovery: null,
    discoveryTab: 'oneclick',
    domainsData: [],
    domainsSummary: null,
    domainsCFEnabled: false,
    domainsCFRoot: '',
    domainsAxisNowEnabled: false,
    domainsAxisNowProviderType: '',
    domainsAxisNowDefaultZone: '',
    domainsAxisNowProviders: [],
    domainsQuery: '',
    domainsFilter: 'all',
    domainEditingID: null,
    domainBoundNodeIDs: [],
    domainBoundWAFIDs: [],
    domainNodeSpeeds: {},
    domainSmartDNSDraft: null,
    domainWizardStep: 1,
    domainsPromise: null,
    lastDomainsRefresh: 0,
    wafRules: [],
    wafSummary: null,
    wafRulesPromise: null,
    targetsQuery: '',
    embyHealthServers: [],
    embyProbeSettings: { default_retry_count: 2, default_retry_delay_sec: 2, probe_timeout_sec: 8 },
    embyCardWindows: {},
    embyHealthFilter: 'all',
    embyHealthQuery: '',
    embyHealthEditingID: null,
    embyHealthTimer: null,
    auditEntries: [],
    auditFilter: 'all',
    auditQuery: '',
    requestPage: 1,
    requestPageSize: 20,
    requestStatus: '',
    requestHost: '',
    requestClientIP: '',
    requestTotalPages: 1,
    requestLoading: false,
    requestsReqSeq: 0,
    telegram: null,
    cloudflareDNS: null,
    cloudflareFailoverDraft: [],
    axisnowDNS: null,
    axisnowMeta: null,
    dnsHubTab: 'profiles',
    smartDNSProfiles: [],
    smartDNSProfilesPromise: null,
    lastDNSRefresh: 0,
    dnsProfileEditingID: null,
    dnsProfileDraft: null,
    dnsBindProfile: null,
    turnstile: null,
    turnstileWidget: null,
    turnstileToken: '',
    turnstileDirty: false,
    turnstileSaving: false,
    userNavigatedBeforeSession: false,
    runtimeConfig: null,
    report: null,
    reportPeriod: '24h',
    reportLiveChart: null,
    reportTrendChart: null,
    reportRegionChart: null,
    liveSeries: [],
    backups: null,
    update: null,
    currentRelease: null,
    branding: null,
    layoutRefreshFrame: 0,
    reportLiveFrame: 0,
    geoZoomFrame: 0,
    geoPendingZoom: 1,
    lastConnectionsRefresh: 0,
    lastPolicyRefresh: 0,
    commandFocusIndex: 0
  };

  let confirmResolver = null;
  let navIndicatorRefresh = null;
  let viewTransitionSequence = 0;
  let hostFilterTimer = null;
  const scriptLoads = new Map();

  const viewMeta = {
    overview: ['运行概览', '实时吞吐量、地域分布与上游流量态势', 'layout-dashboard', '实时监控'],
    watching: ['正在观看', '全集群实时影视播放识别、画质进度监控与观影历史记录', 'tv', '实时监控'],
    connections: ['实时连接', '监控当前活动客户端并支持即时断开', 'radio-tower', '实时监控'],
    requests: ['请求日志', '脱敏后的最近 7 天访问日志与明细检查', 'scroll-text', '实时监控'],
    nodes: ['边缘节点', '免域名接入边缘机器池、月流量保护与一键远程升级', 'network', '节点与域名'],
    domains: ['域名入口', '主控统一编排域名、绑定承载节点、自动签发 HTTPS 证书与分流方案', 'globe', '节点与域名'],
    dns: ['DNS 与分流', '统一编排地区 / 运营商分流方案、管理 AxisNow 与 Cloudflare 凭证并一键绑定域名', 'waypoints', '节点与域名'],
    targets: ['上游域名', '自动发现的上游域名、延迟统计与快捷管控', 'server', '节点与域名'],
    'emby-health': ['Emby 探针', '类似 Uptime 的 Emby / Jellyfin 服务器存活性监测、心跳历史条与 30 天在线率', 'heart-pulse', '实时监控'],
    reports: ['统计报表', '24 小时至 90 天趋势分析、排行与 CSV 导出', 'chart-no-axes-combined', '节点与域名'],
    rules: ['WAF 防护', '可视化拖拽连线编排与域名精准绑定，支持通用反代目标域名、IP、地区、路径与客户端防护', 'shield-check', '节点与域名'],
    audit: ['审计日志', '近 90 天管理员登录与配置变更记录', 'list-checks', '平台管理'],
    backups: ['备份与恢复', '自动定时备份策略与 SQLite 一致性快照管理', 'database-backup', '平台管理'],
    settings: ['系统设置', '运行配置、安全态势、品牌外观、通知与凭据', 'settings', '平台管理']
  };

  const settingsMeta = {
    'settings-runtime': ['运行配置', '上游路由、代理行为、回源 IP 偏好、超时、并发与限速参数', 'server-cog'],
    'settings-security': ['安全态势', '核心强制防护策略与安全拦截计数', 'shield-check'],
    'settings-branding': ['品牌外观', '同步首页与管理控制台的自定义站点头像', 'image'],
    'settings-telegram': ['Telegram 告警与日报', '北京时间每日日报与节点实时事件告警推送', 'send'],
    'settings-turnstile': ['Cloudflare 人机验证', '登录页人机校验与上线前配置自测', 'badge-check'],
    'settings-password': ['修改密码', '更新管理员登录密码并重置会话', 'key-round']
  };

  const auditActionLabels = {
    'account.setup': '初始化管理员',
    'session.login': '管理员登录',
    'session.logout': '退出登录',
    'account.password': '修改密码',
    'policy.mode': '切换域名模式',
    'policy.rule.create': '添加域名规则',
    'policy.rule.delete': '删除域名规则',
    'policy.rule.quota': '调整域名额度',
    'policy.rule.quota.reset': '重置域名用量',
    'policy.domain.quick': '快捷域名管控',
    'policy.schedule': '修改开放时段',
    'policy.player.mode': '切换播放器模式',
    'policy.player.rule.create': '添加播放器规则',
    'policy.player.rule.delete': '删除播放器规则',
    'policy.client_access': '更新 IP 与地区策略',
    'emby_health.server.create': '添加监测服务器',
    'emby_health.server.update': '更新监测服务器',
    'emby_health.server.delete': '删除监测服务器',
    'emby_health.server.check': '手动探测 Emby',
    'connection.terminate': '断开实时连接',
    'telegram.settings': '修改 Telegram 配置',
    'telegram.test': '测试 Telegram 发送',
    'turnstile.settings': '修改 Turnstile 配置',
    'turnstile.test': '自测 Turnstile',
    'backup.auto': '自动定时备份',
    'backup.create': '创建手动备份',
    'backup.import': '导入备份快照',
    'backup.restore': '恢复数据库备份',
    'backup.delete': '删除备份文件',
    'backup.settings': '修改备份策略',
    'system.configuration': '修改运行配置',
    'system.portal': '切换公开选线门户',
    'system.update': '触发面板更新',
    'branding.avatar': '更新站点头像',
    'edge_node.create': '添加边缘节点',
    'edge_node.update': '更新边缘节点配置',
    'edge_node.delete': '删除边缘节点',
    'edge_node.rotate_token': '轮换节点注册凭证',
    'edge_node.enroll': '边缘节点注册入网',
    'edge_node.discovery': '修改集群自动接入设置',
    'edge_node.discovery.rotate': '轮换集群 Discovery Token',
    'edge_node.discovery_enroll': '边缘节点免域名自动入网',
    'edge_node.upgrade': '远程升级边缘节点',
    'edge_domain.create': '创建域名入口',
    'edge_domain.update': '更新域名入口配置',
    'edge_domain.delete': '删除域名入口',
    'edge_domain.issue_cert': '触发主控证书签发',
    'edge_domain.cert_issued': '主控 DNS-01 证书签发成功',
    'edge_domain.cert_upload': '上传自定义域名证书',
    'edge_domain.sync_dns': '手动同步域名 DNS',
    'node.quota.auto_drain': '节点月流量超额自动停流',
    'dns.settings': '修改 Cloudflare DNS 配置',
    'dns.test': '测试 Cloudflare DNS 连通',
    'dns.sync': '手动全量同步 DNS',
    'dns.failover': 'DNS 故障自动切线',
    'axisnow_dns.update': '修改 AxisNow 智能 DNS 配置',
    'axisnow_dns.sync': '手动同步 AxisNow 智能 DNS',
    'dns.smart_switch': '智能 DNS 线路自动切换',
    'smart_dns_profile.create': '创建智能分流方案',
    'smart_dns_profile.update': '更新智能分流方案',
    'smart_dns_profile.delete': '删除智能分流方案',
    'smart_dns_profile.bind': '绑定分流方案域名',
    'smart_dns_profile.sync': '同步分流方案解析',
    'dns.cname_cutover': '智能 DNS 切换 CNAME',
    'waf_rule.create': '创建 WAF 防护规则',
    'waf_rule.update': '更新 WAF 防护规则',
    'waf_rule.delete': '删除 WAF 防护规则'
  };

  const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const utf8ByteLength = (value) => new TextEncoder().encode(String(value || '')).length;

  function showFormError(el, message) {
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function dnsModeLabel(mode) {
    const labels = {
      manual: '手动解析',
      cloudflare_failover: 'CF 主备切线',
      cloudflare_all: 'CF 多机同步',
      axisnow_smart: 'AxisNow 智能分流'
    };
    return labels[mode] || mode || '手动解析';
  }

  /* -------------------- Formatting & DOM Helpers -------------------- */

  function formatBytes(value) {
    let size = Number(value) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let index = 0;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
    return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
  }

  function formatNumber(value) { return new Intl.NumberFormat('zh-CN').format(Number(value) || 0); }

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[ch]);
  }

  function formatTime(seconds) {
    if (!seconds) return '—';
    return new Date(Number(seconds) * 1000).toLocaleString('zh-CN', { hour12: false, timeZone: applicationTimeZone });
  }

  function formatDuration(milliseconds) {
    const seconds = Math.max(0, Math.floor((Number(milliseconds) || 0) / 1000));
    if (seconds < 60) return `${seconds} 秒`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分 ${seconds % 60} 秒`;
    return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分`;
  }

  function relativeTime(seconds) {
    const delta = Math.max(0, Math.floor(Date.now() / 1000) - Number(seconds));
    if (delta < 60) return '刚刚';
    if (delta < 3600) return `${Math.floor(delta / 60)} 分钟前`;
    if (delta < 86400) return `${Math.floor(delta / 3600)} 小时前`;
    return `${Math.floor(delta / 86400)} 天前`;
  }

  function formatUptime(seconds) {
    const total = Number(seconds) || 0;
    if (total < 3600) return `运行 ${Math.max(1, Math.floor(total / 60))} 分钟`;
    if (total < 86400) return `运行 ${Math.floor(total / 3600)} 小时`;
    return `运行 ${Math.floor(total / 86400)} 天`;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function refreshIcons() { window.lucide?.createIcons(); }

  /* -------------------- API & Dynamic Script Loading -------------------- */

  async function api(path, options = {}) {
    const response = await fetch(path, { credentials: 'same-origin', ...options });
    if (response.status === 401) {
      window.location.replace('/login');
      throw new Error('authentication required');
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || 'request failed');
    return payload;
  }

  function jsonOptions(method, body) {
    return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  }

  function loadPanelScript(src) {
    if (scriptLoads.has(src)) return scriptLoads.get(src);
    const script = document.createElement('script');
    const request = new Promise((resolve, reject) => {
      const fail = () => {
        window.clearTimeout(timeout);
        script.onload = script.onerror = null;
        script.remove();
        scriptLoads.delete(src);
        reject(new Error('script unavailable'));
      };
      const timeout = window.setTimeout(fail, 12000);
      script.async = true;
      script.src = src;
      script.onload = () => {
        window.clearTimeout(timeout);
        script.onload = script.onerror = null;
        resolve();
      };
      script.onerror = fail;
      document.head.append(script);
    });
    scriptLoads.set(src, request);
    return request;
  }

  async function ensureEcharts() {
    const src = '/_admin/assets/echarts.min.js';
    if (!window.echarts) await loadPanelScript(src);
    if (!window.echarts) {
      scriptLoads.delete(src);
      throw new Error('charts unavailable');
    }
  }

  /* -------------------- Toast Notifications -------------------- */

  function toast(message, variant = 'success') {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;
    const item = el('div', `toast-item ${variant}`);
    const iconName = variant === 'error'
      ? 'alert-circle'
      : variant === 'warn'
        ? 'alert-triangle'
        : variant === 'info'
          ? 'info'
          : 'check-circle-2';
    const icon = document.createElement('i');
    icon.dataset.lucide = iconName;
    item.append(icon, el('span', '', message));
    stack.append(item);
    refreshIcons();
    while (stack.childElementCount > 4) stack.firstElementChild?.remove();
    window.setTimeout(() => {
      item.classList.add('closing');
      window.setTimeout(() => item.remove(), 190);
    }, 2800);
  }

  /* -------------------- Drawers, Custom Selects & Confirmation Modal -------------------- */

  const cselectState = {
    active: null,
    popover: null,
    focusedIndex: -1,
    globalsBound: false
  };

  const cselectChevronSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
  const cselectCheckSVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
  const nativeSelectValueDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  const nativeSelectIdxDesc = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'selectedIndex');

  function closeActiveCustomSelect(restoreFocus = false) {
    const prev = cselectState.active;
    if (!prev) return;
    cselectState.active = null;
    cselectState.focusedIndex = -1;
    prev.trigger.classList.remove('open');
    prev.trigger.setAttribute('aria-expanded', 'false');
    if (cselectState.popover) {
      cselectState.popover.remove();
      cselectState.popover = null;
    }
    if (restoreFocus && !prev.trigger.disabled) {
      prev.trigger.focus();
    }
  }

  function positionCustomSelectPopover() {
    const active = cselectState.active;
    const pop = cselectState.popover;
    if (!active || !pop) return;
    const rect = active.trigger.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      closeActiveCustomSelect(false);
      return;
    }
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const gap = 6;
    const minW = Math.max(rect.width, 148);
    const maxW = Math.min(Math.max(minW, 320), vw - 20);
    pop.style.minWidth = `${Math.round(minW)}px`;
    pop.style.maxWidth = `${Math.round(maxW)}px`;

    const popHeight = Math.min(pop.scrollHeight || 220, Math.min(268, Math.floor(vh * 0.42)));
    const spaceBelow = vh - rect.bottom - gap - 10;
    const spaceAbove = rect.top - gap - 10;
    const openUp = spaceBelow < popHeight && spaceAbove > spaceBelow;
    pop.classList.toggle('is-up', openUp);

    const top = openUp
      ? Math.max(10, rect.top - gap - popHeight)
      : Math.min(vh - popHeight - 10, rect.bottom + gap);
    const actualWidth = Math.max(minW, pop.offsetWidth || minW);
    const left = Math.max(10, Math.min(rect.left, vw - actualWidth - 10));
    pop.style.top = `${Math.round(top)}px`;
    pop.style.left = `${Math.round(left)}px`;
  }

  function highlightCustomSelectOption(index) {
    const pop = cselectState.popover;
    if (!pop) return;
    const opts = Array.from(pop.querySelectorAll('.cselect-option:not(:disabled)'));
    if (!opts.length) return;
    const next = ((index % opts.length) + opts.length) % opts.length;
    cselectState.focusedIndex = next;
    opts.forEach((btn, idx) => btn.classList.toggle('focused', idx === next));
    opts[next].scrollIntoView({ block: 'nearest' });
  }

  function openCustomSelect(ctx) {
    if (ctx.select.disabled || ctx.select.hidden) return;
    if (cselectState.active === ctx) {
      closeActiveCustomSelect(false);
      return;
    }
    closeActiveCustomSelect(false);
    bindCustomSelectGlobals();

    const pop = document.createElement('div');
    pop.className = 'cselect-popover';
    pop.setAttribute('role', 'listbox');
    const options = Array.from(ctx.select.options);
    let selectedEnabledIdx = -1;
    let enabledCounter = 0;
    let lastGroupLabel = '';

    options.forEach((opt) => {
      const grpLabel = opt.parentElement?.tagName === 'OPTGROUP' ? (opt.parentElement.label || '') : '';
      if (grpLabel && grpLabel !== lastGroupLabel) {
        lastGroupLabel = grpLabel;
        pop.append(el('div', 'cselect-group-label', grpLabel));
      } else if (!grpLabel) {
        lastGroupLabel = '';
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cselect-option';
      btn.setAttribute('role', 'option');
      const isSelected = opt.value === ctx.select.value;
      btn.setAttribute('aria-selected', String(isSelected));
      if (isSelected) btn.classList.add('selected');
      if (opt.disabled) {
        btn.disabled = true;
      } else {
        if (isSelected) selectedEnabledIdx = enabledCounter;
        enabledCounter++;
      }

      const txt = el('span', 'cselect-option-text', opt.textContent || opt.label || '');
      btn.append(txt);
      if (isSelected) {
        const chk = el('span', 'cselect-check');
        chk.innerHTML = cselectCheckSVG;
        btn.append(chk);
      }

      btn.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        const changed = ctx.select.value !== opt.value;
        ctx.select.value = opt.value;
        ctx.sync();
        closeActiveCustomSelect(true);
        if (changed) {
          ctx.select.dispatchEvent(new Event('input', { bubbles: true }));
          ctx.select.dispatchEvent(new Event('change', { bubbles: true }));
        }
      });
      pop.append(btn);
    });

    document.body.append(pop);
    cselectState.active = ctx;
    cselectState.popover = pop;
    cselectState.focusedIndex = selectedEnabledIdx >= 0 ? selectedEnabledIdx : 0;
    ctx.trigger.classList.add('open');
    ctx.trigger.setAttribute('aria-expanded', 'true');
    positionCustomSelectPopover();
    if (selectedEnabledIdx >= 0) {
      highlightCustomSelectOption(selectedEnabledIdx);
    }
  }

  function bindCustomSelectGlobals() {
    if (cselectState.globalsBound) return;
    cselectState.globalsBound = true;
    document.addEventListener('pointerdown', (e) => {
      if (!cselectState.active) return;
      if (cselectState.active.wrap.contains(e.target)) return;
      if (cselectState.popover && cselectState.popover.contains(e.target)) return;
      closeActiveCustomSelect(false);
    });
    window.addEventListener('resize', () => {
      if (cselectState.active) positionCustomSelectPopover();
    });
    window.addEventListener('scroll', (e) => {
      if (!cselectState.active) return;
      if (cselectState.popover && (e.target === cselectState.popover || cselectState.popover.contains(e.target))) return;
      closeActiveCustomSelect(false);
    }, true);
  }

  function enhanceCustomSelect(select) {
    if (!select || select.dataset.cselectBound === '1') return;
    if (!select.parentNode) return;
    select.dataset.cselectBound = '1';

    const wrap = document.createElement('div');
    wrap.className = 'cselect-wrap';
    if (select.classList.contains('node-scope-select')) {
      wrap.classList.add('is-scope');
    } else if (
      select.classList.contains('compact-select') ||
      select.id === 'report-export-kind' ||
      select.closest('.pagination-controls') ||
      select.closest('.failover-add-node-bar') ||
      select.closest('.smart-line-card')
    ) {
      wrap.classList.add('is-compact');
    }

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'cselect-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    if (select.id) trigger.dataset.forSelect = select.id;

    const labelSpan = el('span', 'cselect-label', '');
    const chevronSpan = el('span', 'cselect-chevron');
    chevronSpan.innerHTML = cselectChevronSVG;
    trigger.append(labelSpan, chevronSpan);

    select.parentNode.insertBefore(wrap, select);
    wrap.append(select, trigger);
    select.classList.add('cselect-native');
    select.tabIndex = -1;

    const ctx = {
      select,
      wrap,
      trigger,
      labelSpan,
      sync() {
        wrap.hidden = select.hidden;
        trigger.disabled = select.disabled;
        const selected = select.options[select.selectedIndex] || select.options[0];
        labelSpan.textContent = selected ? (selected.textContent || selected.label || '') : '请选择';
        trigger.title = labelSpan.textContent;
      }
    };

    // Intercept programmatic .value and .selectedIndex updates transparently
    if (nativeSelectValueDesc && nativeSelectValueDesc.get && nativeSelectValueDesc.set) {
      Object.defineProperty(select, 'value', {
        configurable: true,
        get() { return nativeSelectValueDesc.get.call(this); },
        set(v) {
          nativeSelectValueDesc.set.call(this, v);
          ctx.sync();
        }
      });
    }
    if (nativeSelectIdxDesc && nativeSelectIdxDesc.get && nativeSelectIdxDesc.set) {
      Object.defineProperty(select, 'selectedIndex', {
        configurable: true,
        get() { return nativeSelectIdxDesc.get.call(this); },
        set(v) {
          nativeSelectIdxDesc.set.call(this, v);
          ctx.sync();
        }
      });
    }

    const observer = new MutationObserver(() => ctx.sync());
    observer.observe(select, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'hidden'] });

    select.addEventListener('change', () => ctx.sync());
    select.addEventListener('focus', () => { if (!trigger.disabled) trigger.focus(); });

    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openCustomSelect(ctx);
    });

    trigger.addEventListener('keydown', (e) => {
      const isOpen = cselectState.active === ctx;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (!isOpen) openCustomSelect(ctx);
        else highlightCustomSelectOption(cselectState.focusedIndex + 1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (!isOpen) openCustomSelect(ctx);
        else highlightCustomSelectOption(cselectState.focusedIndex - 1);
      } else if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        if (!isOpen) {
          openCustomSelect(ctx);
        } else if (cselectState.popover) {
          const opts = Array.from(cselectState.popover.querySelectorAll('.cselect-option:not(:disabled)'));
          const chosen = opts[cselectState.focusedIndex];
          if (chosen) chosen.click();
          else closeActiveCustomSelect(true);
        }
      } else if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        e.stopPropagation();
        closeActiveCustomSelect(true);
      } else if (e.key === 'Tab' && isOpen) {
        closeActiveCustomSelect(false);
      }
    });

    ctx.sync();
  }

  function enhanceAllCustomSelects(root = document) {
    root.querySelectorAll('select').forEach((sel) => enhanceCustomSelect(sel));
  }

  function openDrawer(id) {
    const root = document.getElementById(id);
    if (!root) return;
    if (!root.classList.contains('open') && document.activeElement instanceof HTMLElement && !root.contains(document.activeElement)) {
      state.lastDrawerTrigger.set(id, document.activeElement);
    }
    closeActiveCustomSelect(false);
    root.classList.add('open');
    root.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    enhanceAllCustomSelects(root);
    refreshIcons();
    const panel = root.querySelector('.drawer-panel');
    if (panel) {
      if (!panel.hasAttribute('tabindex')) panel.setAttribute('tabindex', '-1');
      if (!root.contains(document.activeElement)) {
        const firstField = [...panel.querySelectorAll('input:not([type="hidden"]):not(:disabled), select:not(:disabled), textarea:not(:disabled)')].find((n) => n.offsetParent !== null);
        const firstBtn = [...panel.querySelectorAll('button:not(:disabled)')].find((n) => n.offsetParent !== null);
        (firstField || firstBtn || panel).focus({ preventScroll: true });
      }
    }
  }

  function closeDrawer(id) {
    const root = document.getElementById(id);
    if (!root) return;
    const wasOpen = root.classList.contains('open');
    closeActiveCustomSelect(false);
    root.classList.remove('open');
    root.setAttribute('aria-hidden', 'true');
    if (!document.querySelector('.drawer-root.open')) {
      document.body.classList.remove('modal-open');
    }
    if (wasOpen) {
      const trigger = state.lastDrawerTrigger.get(id);
      state.lastDrawerTrigger.delete(id);
      if (trigger && trigger.isConnected) {
        trigger.focus({ preventScroll: true });
      }
    }
  }

  function settleConfirmation(confirmed) {
    if (!confirmResolver) return;
    const resolve = confirmResolver;
    confirmResolver = null;
    const dialog = document.getElementById('confirm-dialog');
    if (dialog.open) dialog.close();
    resolve(confirmed);
  }

  function confirmAction({ title, message, confirmLabel = '确认', icon = 'triangle-alert', danger = false }) {
    if (confirmResolver) settleConfirmation(false);
    const dialog = document.getElementById('confirm-dialog');
    const accept = document.getElementById('confirm-accept');
    document.getElementById('confirm-title').textContent = title;
    document.getElementById('confirm-message').textContent = message;
    document.getElementById('confirm-icon').innerHTML = `<i data-lucide="${icon}"></i>`;
    accept.textContent = confirmLabel;
    accept.className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;
    dialog.classList.toggle('danger', danger);
    refreshIcons();
    return new Promise((resolve) => {
      confirmResolver = resolve;
      dialog.showModal();
      window.requestAnimationFrame(() => document.getElementById('confirm-cancel').focus());
    });
  }

  /* -------------------- Sliding Controls & Nav Indicator -------------------- */

  function syncSegmented(container) {
    if (!container) return;
    let indicator = container.querySelector('.segmented-indicator');
    if (!indicator) {
      indicator = el('span', 'segmented-indicator');
      indicator.setAttribute('aria-hidden', 'true');
      container.prepend(indicator);
    }
    const active = container.querySelector('button.active');
    if (!active) {
      indicator.classList.remove('ready');
      return;
    }
    const cRect = container.getBoundingClientRect();
    const aRect = active.getBoundingClientRect();
    if (aRect.width <= 0) return;
    const left = aRect.left - cRect.left + container.scrollLeft;
    const top = aRect.top - cRect.top + container.scrollTop;
    indicator.style.width = `${aRect.width}px`;
    indicator.style.height = `${aRect.height}px`;
    indicator.style.transform = `translate(${left}px, ${top}px)`;
    indicator.classList.add('ready');
  }

  function setupSegmentedControls() {
    document.querySelectorAll('.segmented').forEach((container) => {
      if (container.dataset.segBound) { syncSegmented(container); return; }
      container.dataset.segBound = '1';
      const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => syncSegmented(container));
      ro?.observe(container);
      container.addEventListener('scroll', () => syncSegmented(container), { passive: true });
      syncSegmented(container);
    });
  }

  function setupNavIndicator() {
    const nav = document.querySelector('.sidebar-nav');
    const pill = document.getElementById('nav-active-pill');
    const hoverPill = document.getElementById('nav-hover-pill');
    const tooltip = document.getElementById('sidebar-tooltip');
    if (!nav || !pill) return;
    if (navIndicatorRefresh) { navIndicatorRefresh(); return; }
    let frame = 0;
    const measure = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const active = nav.querySelector('.nav-item.active');
        if (!active) { pill.hidden = true; pill.classList.remove('ready'); return; }
        const nRect = nav.getBoundingClientRect();
        const aRect = active.getBoundingClientRect();
        if (aRect.width <= 0) { pill.hidden = true; pill.classList.remove('ready'); return; }
        pill.style.transform = `translate(${aRect.left - nRect.left + nav.scrollLeft}px, ${aRect.top - nRect.top + nav.scrollTop}px)`;
        pill.style.width = `${aRect.width}px`;
        pill.style.height = `${aRect.height}px`;
        if (pill.hidden) {
          pill.hidden = false;
          requestAnimationFrame(() => pill.classList.add('ready'));
        }
      });
    };

    const showHover = (item) => {
      const canHoverActiveSettings = state.role === 'controller' && state.view === 'audit' && item.dataset.view === 'settings';
      if (hoverPill && (!item.classList.contains('active') || canHoverActiveSettings)) {
        const nRect = nav.getBoundingClientRect();
        const iRect = item.getBoundingClientRect();
        hoverPill.style.transform = `translate(${iRect.left - nRect.left + nav.scrollLeft}px, ${iRect.top - nRect.top + nav.scrollTop}px)`;
        hoverPill.style.width = `${iRect.width}px`;
        hoverPill.style.height = `${iRect.height}px`;
        hoverPill.classList.add('visible');
      } else if (hoverPill) {
        hoverPill.classList.remove('visible');
      }
      if (tooltip && document.body.classList.contains('sidebar-collapsed') && window.innerWidth > 860) {
        const label = item.querySelector('span')?.textContent || item.title || '';
        if (label) {
          const iRect = item.getBoundingClientRect();
          tooltip.textContent = label;
          tooltip.style.left = `${iRect.right + 12}px`;
          tooltip.style.top = `${iRect.top + iRect.height / 2}px`;
          tooltip.hidden = false;
          requestAnimationFrame(() => tooltip.classList.add('visible'));
        }
      }
    };

    const hideHover = () => {
      hoverPill?.classList.remove('visible');
      if (tooltip) { tooltip.classList.remove('visible'); tooltip.hidden = true; }
    };

    nav.querySelectorAll('.nav-item').forEach((item) => {
      item.addEventListener('mouseenter', () => showHover(item));
      item.addEventListener('focus', () => showHover(item));
      item.addEventListener('blur', hideHover);
    });
    nav.addEventListener('mouseleave', hideHover);

    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure);
    ro?.observe(nav);
    nav.addEventListener('scroll', () => { measure(); hideHover(); }, { passive: true });
    window.addEventListener('resize', measure);
    navIndicatorRefresh = measure;
    measure();
  }

  function scheduleLayoutRefresh() {
    if (state.layoutRefreshFrame) return;
    state.layoutRefreshFrame = requestAnimationFrame(() => {
      state.layoutRefreshFrame = 0;
      navIndicatorRefresh?.();
      document.querySelectorAll('.segmented').forEach(syncSegmented);
      if (state.view === 'overview') {
        state.overviewChart?.resize();
        if (state.geoMode === '3d') geoGlobe.resize();
        else state.geoChart?.resize();
      }
      if (state.view === 'reports') resizeReportCharts();
    });
  }

  /* -------------------- Shared Palette & Chart Helpers -------------------- */

  function chartPalette() {
    const s = getComputedStyle(document.documentElement);
    const dark = document.documentElement.dataset.theme === 'dark';
    return {
      dark,
      text: s.getPropertyValue('--text-primary').trim(),
      muted: s.getPropertyValue('--text-muted').trim(),
      border: s.getPropertyValue('--border-default').trim(),
      surface: s.getPropertyValue('--bg-surface').trim(),
      accent: s.getPropertyValue('--accent').trim(),
      sky: s.getPropertyValue('--sky').trim(),
      emerald: s.getPropertyValue('--emerald').trim(),
      amber: s.getPropertyValue('--amber').trim(),
      rose: s.getPropertyValue('--rose').trim()
    };
  }

  function areaChartBase(p) {
    return {
      animation: false,
      textStyle: { color: p.text, fontFamily: 'Inter, -apple-system, sans-serif', fontSize: 11.5 },
      tooltip: {
        trigger: 'axis', confine: true, transitionDuration: 0, renderMode: 'richText',
        backgroundColor: p.surface, borderColor: p.border, borderWidth: 1,
        textStyle: { color: p.text, fontSize: 12 },
        axisPointer: { type: 'line', lineStyle: { color: p.border, type: 'dashed' } }
      },
      legend: { top: 6, right: 10, textStyle: { color: p.muted, fontSize: 11 }, itemWidth: 10, itemHeight: 10, icon: 'roundRect' },
      grid: { left: 60, right: 16, top: 38, bottom: 28 },
      xAxis: {
        type: 'category', boundaryGap: false,
        axisLine: { lineStyle: { color: p.border } },
        axisLabel: { color: p.muted, fontSize: 10.5 },
        axisTick: { show: false }
      },
      yAxis: {
        type: 'value', min: 0, splitNumber: 4,
        axisLabel: { color: p.muted, fontSize: 10.5, formatter: (v) => formatBytes(v) },
        splitLine: { lineStyle: { color: p.border, type: 'dashed' } }
      }
    };
  }

  /* -------------------- Domain & Player Quick Actions -------------------- */

  function domainMatchesRule(domain, rule) {
    const host = String(domain || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    const suffix = String(rule?.domain_suffix || '').toLowerCase().replace(/^\.+|\.+$/g, '');
    return Boolean(host && suffix && (host === suffix || host.endsWith(`.${suffix}`)));
  }

  function domainAction(domain) {
    const policy = state.policy || { mode: 'off', rules: [] };
    const rules = policy.rules || [];
    if (policy.mode === 'blacklist') {
      return rules.some((rule) => rule.action === 'deny' && domainMatchesRule(domain, rule)) ? 'allow' : 'block';
    }
    if (policy.mode === 'whitelist') {
      return rules.some((rule) => rule.action === 'allow' && domainMatchesRule(domain, rule)) ? 'block' : 'allow';
    }
    return 'block';
  }

  function domainActionButton(domain) {
    if (state.role === 'controller') return null;
    const access = domainAction(domain);
    const label = access === 'block' ? '屏蔽' : '放行';
    const button = el('button', `btn btn-sm ${access === 'block' ? 'btn-danger-soft' : 'btn-emerald-soft'}`);
    button.type = 'button';
    button.title = `${label} ${domain}`;
    button.setAttribute('aria-label', `${label}域名 ${domain}`);
    const icon = document.createElement('i');
    icon.dataset.lucide = access === 'block' ? 'shield-ban' : 'shield-check';
    button.append(icon, el('span', '', label));
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      updateDomainAccess(domain, access, button);
    });
    return button;
  }

  async function updateDomainAccess(domain, access, button) {
    button.disabled = true;
    try {
      const policy = await api('/_admin/api/rules/domain', jsonOptions('PUT', { domain, access }));
      renderPolicy(policy);
      toast(access === 'block' ? `${domain} 已加入屏蔽` : `${domain} 已放行`);
    } catch {
      button.disabled = false;
      toast('域名规则更新失败', 'error');
    }
  }

  function requestDeviceLabel(log) {
    const name = String(log.device_name || '').trim();
    const client = String(log.client_name || '').trim();
    const id = String(log.device_id || '').trim();
    if (!name && !client && !id) return '';
    const identity = name || id;
    return client && client !== name ? `${identity} · ${client}` : identity;
  }

  function requestPlayerAction(log) {
    if (state.role === 'controller') return null;
    const playerName = String(log.client_name || '').trim();
    if (!playerName) return null;
    const playerPolicy = state.policy?.player_policy || { mode: 'off', rules: [] };
    const mode = playerPolicy.mode;
    const modeLabel = mode === 'blacklist' ? '黑名单' : mode === 'whitelist' ? '白名单' : '';
    if (mode === 'off') return null;
    const existing = (playerPolicy.rules || []).find((rule) => rule.enabled !== false && rule.player_name?.toLowerCase() === playerName.toLowerCase());
    if (existing) {
      const badge = el('span', 'badge badge-accent');
      const icon = document.createElement('i');
      icon.dataset.lucide = 'shield-check';
      badge.append(icon, el('span', '', `已在${modeLabel}`));
      return badge;
    }
    const button = el('button', `btn btn-sm ${mode === 'whitelist' ? 'btn-emerald-soft' : 'btn-danger-soft'}`);
    button.type = 'button';
    button.title = `将 ${playerName} 加入播放器${modeLabel}`;
    const icon = document.createElement('i');
    icon.dataset.lucide = mode === 'whitelist' ? 'shield-check' : 'shield-ban';
    button.append(icon, el('span', '', `加入${modeLabel}`));
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      addPlayerRuleFromRequest(log, button);
    });
    return button;
  }

  async function addPlayerRuleFromRequest(log, button) {
    const playerName = String(log.client_name || '').trim();
    const playerPolicy = state.policy?.player_policy || { mode: 'off', rules: [] };
    if (!playerName || !['blacklist', 'whitelist'].includes(playerPolicy.mode)) {
      toast('请先在访问策略中选择播放器黑名单或白名单模式', 'info');
      return;
    }
    button.disabled = true;
    try {
      const updated = await api('/_admin/api/player-rules', jsonOptions('POST', { player_name: playerName }));
      state.policy.player_policy = updated;
      renderPolicy(state.policy);
      if (state.view === 'requests') refreshRequests().catch(() => {});
      toast(updated.mode === 'blacklist' ? `${playerName} 已加入播放器黑名单` : `${playerName} 已加入播放器白名单`);
    } catch (failure) {
      button.disabled = false;
      toast(failure.message === 'select blacklist or whitelist mode first' ? '请先选择播放器名单模式' : '播放器规则保存失败', 'error');
    }
  }

  function jumpToHostLogs(host) {
    state.requestHost = host;
    state.requestStatus = '';
    const hostInput = document.getElementById('request-host-filter');
    if (hostInput) hostInput.value = host;
    updateRequestClearButton();
    switchView('requests');
  }

  /* -------------------- Overview Rendering -------------------- */

  function overviewPeriodLabel() {
    return ({ '24h': '24 小时', '7d': '7 天', '30d': '30 天' })[state.overviewPeriod] || '24 小时';
  }

  function renderOverviewTrendChart(points) {
    const container = document.getElementById('overview-trend-chart');
    const empty = document.getElementById('chart-empty');
    if (!container || state.view !== 'overview') return;
    if (!points?.length) {
      empty.hidden = false;
      state.overviewChart?.clear();
      return;
    }
    empty.hidden = true;
    ensureEcharts().then(() => {
      if (state.view !== 'overview') return;
      if (!state.overviewChart) state.overviewChart = window.echarts.init(container, null, { renderer: 'canvas' });
      const p = chartPalette();
      const option = areaChartBase(p);
      const short = state.overviewPeriod === '24h';
      option.xAxis.data = points.map((pt) => new Date(pt.timestamp * 1000).toLocaleString('zh-CN', short ?
        { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: applicationTimeZone } :
        { month: '2-digit', day: '2-digit', hour: '2-digit', hour12: false, timeZone: applicationTimeZone }));
      option.tooltip.valueFormatter = (value) => formatBytes(value);
      option.series = [
        {
          name: '下行流量', type: 'line', smooth: 0.25, showSymbol: false,
          data: points.map((pt) => Number(pt.bytes_out) || 0),
          lineStyle: { width: 2, color: p.accent }, itemStyle: { color: p.accent },
          areaStyle: { color: p.dark ? 'rgba(129,140,248,0.16)' : 'rgba(79,70,229,0.1)' }
        },
        {
          name: '上传流量', type: 'line', smooth: 0.25, showSymbol: false,
          data: points.map((pt) => Number(pt.bytes_in) || 0),
          lineStyle: { width: 1.8, color: p.emerald }, itemStyle: { color: p.emerald },
          areaStyle: { color: p.dark ? 'rgba(52,211,153,0.1)' : 'rgba(5,150,105,0.07)' }
        }
      ];
      state.overviewChart.setOption(option, true);
      state.overviewChart.resize();
    }).catch(() => {});
  }

  function renderCompactTargets(targets) {
    const container = document.getElementById('overview-targets');
    if (!targets?.length) {
      container.replaceChildren(el('div', 'empty-state', ''));
      container.firstElementChild.append(el('strong', '', '暂无活跃后端'), el('p', '', state.role === 'controller' ? '产生代理访问后将展示热门源站流量与延迟排行。' : '产生代理访问后将展示热门后端与快捷管控。'));
      return;
    }
    const fragment = document.createDocumentFragment();
    targets.slice(0, 5).forEach((target) => {
      const row = el('div', 'compact-row');
      const main = el('div', 'compact-row-main');
      const displayName = String(target.emby_server_name || '').trim() || target.host;
      main.append(el('span', 'cell-primary', displayName));
      const meta = el('div', 'cell-meta-row');
      if (displayName !== target.host) meta.append(el('span', 'cell-secondary mono', target.host));
      if (target.emby_line_name) meta.append(el('span', 'meta-tag accent', target.emby_line_name));
      if (target.emby_note) meta.append(el('span', 'meta-tag', target.emby_note));
      meta.append(el('span', 'cell-secondary num', `${formatNumber(target.requests)} 次请求 · ${target.avg_latency_ms} ms`));
      main.append(meta);

      const side = el('div', 'compact-row-side');
      side.append(el('span', 'mono cell-primary', formatBytes(target.bytes_out)));
      const actionBtn = domainActionButton(target.domain);
      if (actionBtn) {
        side.append(actionBtn);
      } else {
        const logsBtn = el('button', 'btn btn-secondary btn-sm');
        logsBtn.type = 'button';
        logsBtn.innerHTML = '<i data-lucide="scroll-text"></i><span>日志</span>';
        logsBtn.addEventListener('click', (event) => {
          event.stopPropagation();
          jumpToHostLogs(target.host);
        });
        side.append(logsBtn);
      }
      row.append(main, side);
      fragment.append(row);
    });
    container.replaceChildren(fragment);
    refreshIcons();
  }

  function renderCompactRequests(logs) {
    const container = document.getElementById('overview-requests');
    if (!logs?.length) {
      container.replaceChildren(el('div', 'empty-state', ''));
      container.firstElementChild.append(el('strong', '', '暂无最近请求'), el('p', '', '代理记录将自动脱敏后展示在此。'));
      return;
    }
    const fragment = document.createDocumentFragment();
    logs.slice(0, 5).forEach((log) => {
      const row = el('div', 'compact-row');
      row.style.cursor = 'pointer';
      row.addEventListener('click', () => openRequestDetailDrawer(log));

      const main = el('div', 'compact-row-main');
      const displayName = String(log.emby_server_name || '').trim() || log.host;
      const top = el('div', 'cell-meta-row');
      top.append(el('span', 'meta-tag mono', log.method), el('span', 'cell-primary', displayName));
      if (log.emby_line_name) top.append(el('span', 'meta-tag accent', log.emby_line_name));
      main.append(top);
      main.append(el('span', 'cell-secondary mono', log.path));
      const devLabel = requestDeviceLabel(log);
      if (devLabel) main.append(el('span', 'cell-secondary', `设备：${devLabel}`));

      const side = el('div', 'compact-row-side');
      const statusBadge = el('span', `badge mono ${log.status >= 400 ? 'badge-rose' : 'badge-emerald'}`, `${log.status} · ${log.duration_ms}ms`);
      side.append(statusBadge);
      const playerAct = requestPlayerAction(log);
      if (playerAct) side.append(playerAct);
      row.append(main, side);
      fragment.append(row);
    });
    container.replaceChildren(fragment);
    refreshIcons();
  }

  function renderPulseSummary() {
    const waf = state.wafSummary;
    const elWafEn = document.getElementById('pulse-waf-enabled');
    const elWafGl = document.getElementById('pulse-waf-global');
    const elWafDom = document.getElementById('pulse-waf-domains');
    if (waf) {
      if (elWafEn) elWafEn.textContent = `${formatNumber(waf.enabled)} / ${formatNumber(waf.total)} 条`;
      if (elWafGl) elWafGl.textContent = `${formatNumber(waf.global)} 条`;
      if (elWafDom) elWafDom.textContent = `${formatNumber(waf.bound_domains)} 个`;
    }
    if (state.snapshot) {
      const activeTargets = (state.snapshot.active_targets || []).length;
      const elTargets = document.getElementById('pulse-active-targets');
      if (elTargets) elTargets.textContent = `${formatNumber(activeTargets)} 个`;
      const dropped = Number(state.snapshot.dropped_logs) || 0;
      const elTel = document.getElementById('pulse-telemetry');
      if (elTel) elTel.textContent = dropped ? `已丢弃 ${formatNumber(dropped)} 条` : '正常（无丢弃）';
    }
  }

  function render(snapshot) {
    state.snapshot = snapshot;
    const periodLabel = overviewPeriodLabel();
    document.getElementById('metric-requests-label').textContent = `${periodLabel}请求`;
    document.getElementById('metric-traffic-label').textContent = `${periodLabel}下行`;
    document.getElementById('metric-targets-period').textContent = `最近 ${periodLabel}`;
    document.getElementById('overview-chart-period').textContent = `最近 ${periodLabel} 上下行与请求波动`;
    document.getElementById('metric-requests').textContent = formatNumber(snapshot.requests_24h);
    document.getElementById('metric-active').textContent = `${formatNumber(snapshot.active_requests)} 个活跃连接`;
    document.getElementById('metric-traffic').textContent = formatBytes(snapshot.bytes_out_24h);
    document.getElementById('metric-upload-period').textContent = `上传 ${formatBytes(snapshot.bytes_in_24h)}`;
    document.getElementById('metric-targets').textContent = formatNumber(snapshot.targets_24h);
    document.getElementById('metric-errors').textContent = formatNumber(snapshot.errors_24h);
    document.getElementById('metric-blocked').textContent = `${formatNumber(snapshot.blocked_total)} 次安全拦截`;
    document.getElementById('uptime-label').textContent = formatUptime(snapshot.uptime_seconds);
    document.getElementById('security-blocked').textContent = formatNumber(snapshot.blocked_total);
    document.getElementById('security-dropped').textContent = formatNumber(snapshot.dropped_logs);
    renderPulseSummary();
    if (state.view === 'overview') {
      renderCompactTargets(snapshot.targets);
      renderCompactRequests(snapshot.recent);
      renderOverviewTrendChart(snapshot.timeline);
    } else if (state.view === 'targets') {
      renderTargets(snapshot.targets);
    }
  }

  function renderLive(live) {
    const up = Math.max(0, Number(live.upload_bps) || 0);
    const down = Math.max(0, Number(live.download_bps) || 0);
    const activeCount = Number(live.active_requests) || 0;
    state.liveSeries.push({ timestamp: Date.now(), upload: up, download: down });
    if (state.liveSeries.length > 60) state.liveSeries.splice(0, state.liveSeries.length - 60);

    const upText = `${formatBytes(up)}/s`;
    const downText = `${formatBytes(down)}/s`;
    document.getElementById('live-upload').textContent = upText;
    document.getElementById('live-download').textContent = downText;
    document.getElementById('live-upload-total').textContent = `本次运行 ${formatBytes(live.upload_total)}`;
    document.getElementById('live-download-total').textContent = `本次运行 ${formatBytes(live.download_total)}`;
    document.getElementById('metric-active').textContent = `${formatNumber(activeCount)} 个活跃连接`;
    document.getElementById('topbar-up').textContent = `↑ ${upText}`;
    document.getElementById('topbar-down').textContent = `↓ ${downText}`;
    document.getElementById('conn-kpi-up').textContent = upText;
    document.getElementById('conn-kpi-down').textContent = downText;
    document.getElementById('conn-kpi-count').textContent = formatNumber(activeCount);

    const navBadge = document.getElementById('nav-conn-badge');
    if (navBadge) {
      navBadge.hidden = activeCount <= 0;
      navBadge.textContent = String(activeCount);
    }
    const watchCount = Number(live.watching_count) || 0;
    const watchBadge = document.getElementById('nav-watch-badge');
    if (watchBadge) {
      watchBadge.hidden = watchCount <= 0;
      watchBadge.textContent = String(watchCount);
    }
    const prevWatchCount = state.lastWatchingCount;
    state.lastWatchingCount = watchCount;
    if (prevWatchCount !== -1 && watchCount !== prevWatchCount) {
      if (state.view === 'overview' || state.view === 'watching') {
        refreshWatching().catch(() => {});
      }
    }
    if (Array.isArray(live.active_targets)) {
      document.getElementById('pulse-active-targets').textContent = `${formatNumber(live.active_targets.length)} 个`;
    }
    if (state.view === 'reports' && !state.reportLiveFrame) {
      state.reportLiveFrame = requestAnimationFrame(() => {
        state.reportLiveFrame = 0;
        if (state.view === 'reports') renderReportLiveChart();
      });
    }
  }

  /* -------------------- Geography 3D Dot-Matrix Globe & 2D Map -------------------- */

  const nodeRegionGeoTable = [
    [['tokyo', 'japan', '日本', '东京', 'osaka', '大阪', 'iij', 'softbank', 'jp'], [139.69, 35.69, 'Tokyo']],
    [['frankfurt', 'germany', '德国', '法兰克福', '9929', 'de'], [8.68, 50.11, 'Frankfurt']],
    [['singapore', '新加坡', 'sg'], [103.82, 1.35, 'Singapore']],
    [['hong kong', 'hongkong', '香港', 'hk'], [114.17, 22.32, 'Hong Kong']],
    [['taipei', 'taiwan', '台湾', '台北', 'tw'], [121.56, 25.03, 'Taipei']],
    [['seoul', 'korea', '韩国', '首尔', 'kr'], [126.98, 37.56, 'Seoul']],
    [['los angeles', 'la', '洛杉矶', 'san jose', '圣何塞', 'us-west', '美西', 'california'], [-118.24, 34.05, 'Los Angeles']],
    [['seattle', '西雅图'], [-122.33, 47.61, 'Seattle']],
    [['new york', '纽约', 'us-east', '美东', 'virginia'], [-74.01, 40.71, 'New York']],
    [['dallas', '达拉斯', 'chicago', '芝加哥', 'us', '美国', 'racknerd'], [-96.80, 32.78, 'United States']],
    [['london', 'uk', '英国', '伦敦', 'gb'], [-0.12, 51.51, 'London']],
    [['amsterdam', 'netherlands', '荷兰', '阿姆斯特丹', 'nl'], [4.90, 52.37, 'Amsterdam']],
    [['paris', 'france', '法国', '巴黎', 'fr'], [2.35, 48.86, 'Paris']],
    [['sydney', 'australia', '澳洲', '澳大利亚', '悉尼', 'au'], [151.21, -33.87, 'Sydney']],
    [['shanghai', '上海'], [121.47, 31.23, 'Shanghai']],
    [['beijing', '北京'], [116.41, 39.90, 'Beijing']],
    [['guangzhou', '广州', 'shenzhen', '深圳'], [113.26, 23.13, 'Guangzhou']],
    [['china', '中国', 'cn'], [116.41, 35.86, 'China']]
  ];

  function resolveNodeGeoCoord(node) {
    const haystack = `${node?.region || ''} ${node?.name || ''} ${node?.group_name || ''}`.toLowerCase();
    for (const [keys, coord] of nodeRegionGeoTable) {
      if (keys.some((k) => haystack.includes(k))) return coord;
    }
    return null;
  }

  function mapPalette() {
    const dark = document.documentElement.dataset.theme === 'dark';
    return dark ? {
      area: '#181c27', border: '#2c3345', activeLow: '#2b3366', activeHigh: '#818cf8',
      point: '#34d399', pointBorder: '#064e3b', tooltip: '#161a24', tooltipText: '#f1f5f9', tooltipBorder: '#2c3345'
    } : {
      area: '#eef1f6', border: '#d5dce8', activeLow: '#c7d2fe', activeHigh: '#4f46e5',
      point: '#059669', pointBorder: '#ffffff', tooltip: '#ffffff', tooltipText: '#0f172a', tooltipBorder: '#e2e6ef'
    };
  }

  function ensureGeoFeatures() {
    if (state.geoFeatures) return Promise.resolve(state.geoFeatures);
    if (!state.geoFeaturesPromise) {
      state.geoFeaturesPromise = Promise.all([
        fetch('/_admin/assets/world-geo.json', { credentials: 'same-origin' }).then((r) => {
          if (!r.ok) throw new Error('world map unavailable');
          return r.json();
        }),
        fetch('/_admin/assets/china-provinces.json', { credentials: 'same-origin' }).then((r) => {
          if (!r.ok) throw new Error('china map unavailable');
          return r.json();
        })
      ]).then(([world, china]) => {
        const features = (world.features || []).filter((f) => f?.properties?.name !== 'China');
        features.push(...(china.features || []));
        state.geoFeatures = features;
        return features;
      }).catch((failure) => {
        state.geoFeaturesPromise = null;
        throw failure;
      });
    }
    return state.geoFeaturesPromise;
  }

  function ensureGeographyMap() {
    if (window.echarts?.getMap('refract-world')) return Promise.resolve();
    if (!state.geoMapPromise) {
      state.geoMapPromise = Promise.all([
        ensureEcharts(),
        ensureGeoFeatures()
      ]).then(([, features]) => {
        window.echarts.registerMap('refract-world', { type: 'FeatureCollection', features });
      }).catch((failure) => {
        state.geoMapPromise = null;
        throw failure;
      });
    }
    return state.geoMapPromise;
  }

  const WORLD_COUNTRY_ZH = {
    'Afghanistan': '阿富汗', 'Albania': '阿尔巴尼亚', 'Algeria': '阿尔及利亚', 'Angola': '安哥拉',
    'Argentina': '阿根廷', 'Armenia': '亚美尼亚', 'Australia': '澳大利亚', 'Austria': '奥地利',
    'Azerbaijan': '阿塞拜疆', 'Bangladesh': '孟加拉国', 'Belarus': '白俄罗斯', 'Belgium': '比利时',
    'Belize': '伯利兹', 'Benin': '贝宁', 'Bhutan': '不丹', 'Bolivia': '玻利维亚',
    'Bosnia and Herzegovina': '波黑', 'Botswana': '博茨瓦纳', 'Brazil': '巴西', 'Brunei': '文莱',
    'Bulgaria': '保加利亚', 'Burkina Faso': '布基纳法索', 'Burundi': '布隆迪', 'Cambodia': '柬埔寨',
    'Cameroon': '喀麦隆', 'Canada': '加拿大', 'Central African Republic': '中非', 'Chad': '乍得',
    'Chile': '智利', 'China': '中国', 'Colombia': '哥伦比亚', 'Costa Rica': '哥斯达黎加',
    'Croatia': '克罗地亚', 'Cuba': '古巴', 'Cyprus': '塞浦路斯', 'Czech Republic': '捷克',
    'Democratic Republic of the Congo': '刚果（金）', 'Denmark': '丹麦', 'Djibouti': '吉布提',
    'Dominican Republic': '多米尼加', 'East Timor': '东帝汶', 'Ecuador': '厄瓜多尔', 'Egypt': '埃及',
    'El Salvador': '萨尔瓦多', 'Equatorial Guinea': '赤道几内亚', 'Eritrea': '厄立特里亚',
    'Estonia': '爱沙尼亚', 'Ethiopia': '埃塞俄比亚', 'Fiji': '斐济', 'Finland': '芬兰',
    'France': '法国', 'Gabon': '加蓬', 'Gambia': '冈比亚', 'Georgia': '格鲁吉亚',
    'Germany': '德国', 'Ghana': '加纳', 'Greece': '希腊', 'Guatemala': '危地马拉',
    'Guinea': '几内亚', 'Guinea Bissau': '几内亚比绍', 'Guyana': '圭亚那', 'Haiti': '海地',
    'Honduras': '洪都拉斯', 'Hungary': '匈牙利', 'Iceland': '冰岛', 'India': '印度',
    'Indonesia': '印度尼西亚', 'Iran': '伊朗', 'Iraq': '伊拉克', 'Ireland': '爱尔兰',
    'Israel': '以色列', 'Italy': '意大利', 'Ivory Coast': '科特迪瓦', 'Jamaica': '牙买加',
    'Japan': '日本', 'Jordan': '约旦', 'Kashmir': '克什米尔', 'Kazakhstan': '哈萨克斯坦',
    'Kenya': '肯尼亚', 'Kosovo': '科索沃', 'Kuwait': '科威特', 'Kyrgyzstan': '吉尔吉斯斯坦',
    'Laos': '老挝', 'Latvia': '拉脱维亚', 'Lebanon': '黎巴嫩', 'Lesotho': '莱索托',
    'Liberia': '利比里亚', 'Libya': '利比亚', 'Lithuania': '立陶宛', 'Luxembourg': '卢森堡',
    'Macedonia': '北马其顿', 'Madagascar': '马达加斯加', 'Malawi': '马拉维', 'Malaysia': '马来西亚',
    'Mali': '马里', 'Mauritania': '毛里塔尼亚', 'Mexico': '墨西哥', 'Moldova': '摩尔多瓦',
    'Mongolia': '蒙古', 'Montenegro': '黑山', 'Morocco': '摩洛哥', 'Mozambique': '莫桑比克',
    'Myanmar': '缅甸', 'Namibia': '纳米比亚', 'Nepal': '尼泊尔', 'Netherlands': '荷兰',
    'New Zealand': '新西兰', 'Nicaragua': '尼加拉瓜', 'Niger': '尼日尔', 'Nigeria': '尼日利亚',
    'North Korea': '朝鲜', 'Northern Cyprus': '北塞浦路斯', 'Norway': '挪威', 'Oman': '阿曼',
    'Pakistan': '巴基斯坦', 'Panama': '巴拿马', 'Papua New Guinea': '巴布亚新几内亚',
    'Paraguay': '巴拉圭', 'Peru': '秘鲁', 'Philippines': '菲律宾', 'Poland': '波兰',
    'Portugal': '葡萄牙', 'Qatar': '卡塔尔', 'Republic of Serbia': '塞尔维亚',
    'Republic of the Congo': '刚果（布）', 'Romania': '罗马尼亚', 'Russia': '俄罗斯',
    'Rwanda': '卢旺达', 'Saudi Arabia': '沙特阿拉伯', 'Senegal': '塞内加尔',
    'Sierra Leone': '塞拉利昂', 'Slovakia': '斯洛伐克', 'Slovenia': '斯洛文尼亚',
    'Solomon Islands': '所罗门群岛', 'Somalia': '索马里', 'Somaliland': '索马里兰',
    'South Africa': '南非', 'South Korea': '韩国', 'South Sudan': '南苏丹', 'Spain': '西班牙',
    'Sri Lanka': '斯里兰卡', 'Sudan': '苏丹', 'Suriname': '苏里南', 'Swaziland': '斯威士兰',
    'Sweden': '瑞典', 'Switzerland': '瑞士', 'Syria': '叙利亚', 'Tajikistan': '塔吉克斯坦',
    'Thailand': '泰国', 'The Bahamas': '巴哈马', 'Togo': '多哥', 'Trinidad and Tobago': '特立尼达和多巴哥',
    'Tunisia': '突尼斯', 'Turkey': '土耳其', 'Turkmenistan': '土库曼斯坦', 'Uganda': '乌干达',
    'Ukraine': '乌克兰', 'United Arab Emirates': '阿联酋', 'United Kingdom': '英国',
    'United Republic of Tanzania': '坦桑尼亚', 'United States of America': '美国', 'Uruguay': '乌拉圭',
    'Uzbekistan': '乌兹别克斯坦', 'Vanuatu': '瓦努阿图', 'Venezuela': '委内瑞拉', 'Vietnam': '越南',
    'Western Sahara': '西撒哈拉', 'Yemen': '也门', 'Zambia': '赞比亚', 'Zimbabwe': '津巴布韦'
  };

  function localizeGeoName(mapName) {
    if (!mapName) return '';
    return WORLD_COUNTRY_ZH[mapName] || mapName;
  }

  function shortProvinceName(name) {
    return String(name || '')
      .replace(/(维吾尔自治区|回族自治区|壮族自治区|自治区|特别行政区|省|市)$/, '');
  }

  const GLOBE_BASE_LABELS = [
    // Tier 1: Global major countries (visible from default zoom)
    { lon: 104.5, lat: 35.8, label: '中国', minZoom: 0.7, maxZoom: 1.26, priority: 10 },
    { lon: 94.0, lat: 62.5, label: '俄罗斯', minZoom: 0.7, priority: 9 },
    { lon: 103.8, lat: 46.8, label: '蒙古', minZoom: 0.7, priority: 8 },
    { lon: 138.2, lat: 36.2, label: '日本', minZoom: 0.7, priority: 9 },
    { lon: 127.8, lat: 36.3, label: '韩国', minZoom: 0.7, priority: 7 },
    { lon: 79.0, lat: 22.0, label: '印度', minZoom: 0.7, priority: 9 },
    { lon: 67.5, lat: 48.0, label: '哈萨克斯坦', minZoom: 0.7, priority: 7 },
    { lon: 101.0, lat: 15.6, label: '泰国', minZoom: 0.7, priority: 7 },
    { lon: 106.8, lat: 15.8, label: '越南', minZoom: 0.7, priority: 6 },
    { lon: 114.5, lat: -1.8, label: '印度尼西亚', minZoom: 0.7, priority: 7 },
    { lon: 122.2, lat: 12.6, label: '菲律宾', minZoom: 0.7, priority: 6 },
    { lon: 134.0, lat: -25.0, label: '澳大利亚', minZoom: 0.7, priority: 9 },
    { lon: 172.5, lat: -41.5, label: '新西兰', minZoom: 0.7, priority: 6 },
    { lon: 10.4, lat: 51.2, label: '德国', minZoom: 0.7, priority: 8 },
    { lon: 2.3, lat: 46.6, label: '法国', minZoom: 0.7, priority: 8 },
    { lon: -2.4, lat: 54.0, label: '英国', minZoom: 0.7, priority: 8 },
    { lon: 12.6, lat: 42.6, label: '意大利', minZoom: 0.7, priority: 7 },
    { lon: -3.7, lat: 40.3, label: '西班牙', minZoom: 0.7, priority: 7 },
    { lon: 19.4, lat: 52.0, label: '波兰', minZoom: 0.85, priority: 6 },
    { lon: 31.2, lat: 49.0, label: '乌克兰', minZoom: 0.7, priority: 7 },
    { lon: 35.2, lat: 39.0, label: '土耳其', minZoom: 0.7, priority: 7 },
    { lon: 44.5, lat: 24.0, label: '沙特阿拉伯', minZoom: 0.7, priority: 7 },
    { lon: 53.7, lat: 32.5, label: '伊朗', minZoom: 0.7, priority: 7 },
    { lon: 69.5, lat: 30.0, label: '巴基斯坦', minZoom: 0.85, priority: 6 },
    { lon: 30.5, lat: 26.8, label: '埃及', minZoom: 0.7, priority: 7 },
    { lon: 24.0, lat: -29.0, label: '南非', minZoom: 0.7, priority: 7 },
    { lon: 8.6, lat: 9.2, label: '尼日利亚', minZoom: 0.7, priority: 6 },
    { lon: -98.5, lat: 39.5, label: '美国', minZoom: 0.7, priority: 10 },
    { lon: -106.0, lat: 57.0, label: '加拿大', minZoom: 0.7, priority: 9 },
    { lon: -102.5, lat: 23.6, label: '墨西哥', minZoom: 0.7, priority: 8 },
    { lon: -51.9, lat: -10.5, label: '巴西', minZoom: 0.7, priority: 9 },
    { lon: -64.0, lat: -35.0, label: '阿根廷', minZoom: 0.7, priority: 8 },
    { lon: -42.0, lat: 72.0, label: '格陵兰', minZoom: 0.7, priority: 7 },
    // Tier 2: Secondary countries (revealed smoothly on zoom-in)
    { lon: 103.8, lat: 1.35, label: '新加坡', minZoom: 1.15, priority: 6 },
    { lon: 102.0, lat: 4.2, label: '马来西亚', minZoom: 1.15, priority: 5 },
    { lon: 96.5, lat: 21.5, label: '缅甸', minZoom: 1.15, priority: 5 },
    { lon: 127.0, lat: 40.0, label: '朝鲜', minZoom: 1.22, priority: 5 },
    { lon: 15.5, lat: 62.5, label: '瑞典', minZoom: 1.1, priority: 5 },
    { lon: 8.5, lat: 61.5, label: '挪威', minZoom: 1.15, priority: 5 },
    { lon: 26.0, lat: 63.0, label: '芬兰', minZoom: 1.15, priority: 5 },
    { lon: 5.3, lat: 52.3, label: '荷兰', minZoom: 1.35, priority: 5 },
    { lon: 8.2, lat: 46.8, label: '瑞士', minZoom: 1.35, priority: 5 },
    { lon: 22.0, lat: 39.2, label: '希腊', minZoom: 1.25, priority: 5 },
    { lon: 54.4, lat: 24.0, label: '阿联酋', minZoom: 1.2, priority: 5 },
    { lon: 64.5, lat: 41.3, label: '乌兹别克斯坦', minZoom: 1.25, priority: 4 },
    { lon: -74.0, lat: 4.5, label: '哥伦比亚', minZoom: 1.15, priority: 5 },
    { lon: -75.0, lat: -9.5, label: '秘鲁', minZoom: 1.15, priority: 5 },
    { lon: -70.6, lat: -33.5, label: '智利', minZoom: 1.15, priority: 5 },
    { lon: 3.0, lat: 28.0, label: '阿尔及利亚', minZoom: 1.05, priority: 5 },
    { lon: -6.5, lat: 32.0, label: '摩洛哥', minZoom: 1.15, priority: 5 },
    { lon: 38.0, lat: 1.0, label: '肯尼亚', minZoom: 1.15, priority: 5 }
  ];

  const geoGlobe = {
    canvas: null,
    ctx: null,
    ready: false,
    building: false,
    eventsBound: false,
    rafId: 0,
    width: 0,
    height: 0,
    dpr: 1,
    rotLon: 104 * Math.PI / 180,
    rotLat: 26 * Math.PI / 180,
    velLon: 0,
    velLat: 0,
    zoom: 1.08,
    autoRotate: true,
    dragging: false,
    hovering: false,
    lastPointerX: 0,
    lastPointerY: 0,
    pointerX: -1,
    pointerY: -1,
    maskW: 1440,
    maskH: 720,
    maskData: null,
    featureNames: [],
    vectorFeatures: [],
    mapLabels: [],
    regionHeatByName: new Map(),
    regionMetaByName: new Map(),
    maxRequests: 1,
    visitors: [],
    nodes: [],
    hoveredFeatureName: '',
    projectedPins: [],
    lastTime: 0,
    _px: new Float32Array(2048),
    _py: new Float32Array(2048),
    _pz: new Float32Array(2048),

    ensureScratch(n) {
      if (this._px.length >= n) return;
      const cap = Math.max(n, this._px.length * 2);
      this._px = new Float32Array(cap);
      this._py = new Float32Array(cap);
      this._pz = new Float32Array(cap);
    },

    lonLatToVec(lonDeg, latDeg) {
      const lon = lonDeg * Math.PI / 180;
      const lat = latDeg * Math.PI / 180;
      const cl = Math.cos(lat);
      return { x: cl * Math.sin(lon), y: Math.sin(lat), z: cl * Math.cos(lon) };
    },

    projectUnit(ux, uy, uz, sinLon, cosLon, sinLat, cosLat) {
      // Rotate longitude by -rotLon around Y, then latitude by +rotLat around X
      const x1 = ux * cosLon - uz * sinLon;
      const z1 = ux * sinLon + uz * cosLon;
      const y2 = uy * cosLat - z1 * sinLat;
      const z2 = uy * sinLat + z1 * cosLat;
      return { x: x1, y: y2, z: z2 };
    },

    compileRing(rawRing) {
      if (!Array.isArray(rawRing) || rawRing.length < 3) return null;
      // Mild spatial decimation (0.10 deg) for large rings while preserving small islands & borders verbatim
      const pts = [];
      const thresh = rawRing.length > 18 ? 0.10 : 0;
      let lastLon = 999;
      let lastLat = 999;
      const len = rawRing.length;
      const endIdx = (rawRing[0][0] === rawRing[len - 1][0] && rawRing[0][1] === rawRing[len - 1][1]) ? len - 1 : len;
      for (let i = 0; i < endIdx; i += 1) {
        const lon = Number(rawRing[i][0]);
        const lat = Number(rawRing[i][1]);
        if (!Number.isFinite(lon) || !Number.isFinite(lat)) continue;
        if (thresh > 0 && pts.length > 0 && i < endIdx - 1) {
          if (Math.abs(lon - lastLon) < thresh && Math.abs(lat - lastLat) < thresh) continue;
        }
        pts.push(lon, lat);
        lastLon = lon;
        lastLat = lat;
      }
      const count = pts.length >> 1;
      if (count < 3) return null;

      const coords = new Float32Array(count * 3);
      let sx = 0, sy = 0, sz = 0;
      for (let i = 0; i < count; i += 1) {
        const lon = pts[i * 2] * Math.PI / 180;
        const lat = pts[i * 2 + 1] * Math.PI / 180;
        const cl = Math.cos(lat);
        const ux = cl * Math.sin(lon);
        const uy = Math.sin(lat);
        const uz = cl * Math.cos(lon);
        coords[i * 3] = ux;
        coords[i * 3 + 1] = uy;
        coords[i * 3 + 2] = uz;
        sx += ux;
        sy += uy;
        sz += uz;
      }
      const sl = Math.hypot(sx, sy, sz) || 1;
      const bx = sx / sl;
      const by = sy / sl;
      const bz = sz / sl;
      let minDot = 1;
      for (let i = 0; i < count; i += 1) {
        const dot = coords[i * 3] * bx + coords[i * 3 + 1] * by + coords[i * 3 + 2] * bz;
        if (dot < minDot) minDot = dot;
      }
      const sinR = minDot > 0.15 ? Math.sqrt(Math.max(0, 1 - minDot * minDot)) : 1.05;
      return { coords, count, bx, by, bz, sinR };
    },

    buildFromFeatures(features) {
      if (this.ready || this.building || !Array.isArray(features) || !features.length) return;
      this.building = true;
      const W = this.maskW;
      const H = this.maskH;
      const off = document.createElement('canvas');
      off.width = W;
      off.height = H;
      const octx = off.getContext('2d', { willReadFrequently: true });
      octx.imageSmoothingEnabled = false;
      octx.clearRect(0, 0, W, H);

      const names = [''];
      const vectorFeatures = [];
      const labels = GLOBE_BASE_LABELS.map((item) => ({
        ...item,
        vec: this.lonLatToVec(item.lon, item.lat)
      }));

      const drawMaskRing = (ring) => {
        if (!Array.isArray(ring) || ring.length < 3) return;
        for (let i = 0; i < ring.length; i += 1) {
          const pt = ring[i];
          const x = ((Number(pt[0]) + 180) / 360) * W;
          const y = ((90 - Number(pt[1])) / 180) * H;
          if (i === 0) octx.moveTo(x, y);
          else octx.lineTo(x, y);
        }
        octx.closePath();
      };

      features.forEach((feat) => {
        const geom = feat?.geometry;
        if (!geom || !geom.coordinates) return;
        const props = feat?.properties || {};
        const name = String(props.name || '');
        const isChina = Boolean(props.adcode);
        const isDashLine = isChina && !name;

        let fid = 0;
        if (!isDashLine && name) {
          fid = names.length;
          names.push(name);
          octx.fillStyle = `rgb(${fid & 255}, ${(fid >> 8) & 255}, 128)`;
          octx.beginPath();
          if (geom.type === 'Polygon') {
            geom.coordinates.forEach(drawMaskRing);
          } else if (geom.type === 'MultiPolygon') {
            geom.coordinates.forEach((poly) => poly.forEach(drawMaskRing));
          }
          octx.fill('evenodd');
        }

        // Compile vector polygons + bounding spheres for 60FPS orthographic rendering
        const rawPolys = geom.type === 'MultiPolygon' ? geom.coordinates : [geom.coordinates];
        const compiledPolys = [];
        let fx = 0, fy = 0, fz = 0, ringCount = 0;
        for (let p = 0; p < rawPolys.length; p += 1) {
          const rawRings = rawPolys[p];
          if (!Array.isArray(rawRings) || !rawRings.length) continue;
          const rings = [];
          for (let r = 0; r < rawRings.length; r += 1) {
            const compiled = this.compileRing(rawRings[r]);
            if (compiled) {
              rings.push(compiled);
              fx += compiled.bx;
              fy += compiled.by;
              fz += compiled.bz;
              ringCount += 1;
            }
          }
          if (rings.length) compiledPolys.push(rings);
        }
        if (compiledPolys.length) {
          const fl = Math.hypot(fx, fy, fz) || 1;
          fx /= fl; fy /= fl; fz /= fl;
          let maxSin = 0;
          if (ringCount === 1) {
            maxSin = compiledPolys[0][0].sinR;
          } else {
            let minDot = 1;
            for (let p = 0; p < compiledPolys.length; p += 1) {
              const rings = compiledPolys[p];
              for (let r = 0; r < rings.length; r += 1) {
                const c = rings[r].coords;
                for (let k = 0; k < c.length; k += 3) {
                  const dot = c[k] * fx + c[k + 1] * fy + c[k + 2] * fz;
                  if (dot < minDot) minDot = dot;
                }
              }
            }
            maxSin = minDot > 0.15 ? Math.sqrt(Math.max(0, 1 - minDot * minDot)) : 1.05;
          }
          vectorFeatures.push({
            fid,
            name,
            displayName: localizeGeoName(name),
            isChina,
            isDashLine,
            polygons: compiledPolys,
            bx: fx,
            by: fy,
            bz: fz,
            sinR: maxSin
          });
        }

        // Register zoomed-in Chinese province labels using GeoJSON centroids
        if (isChina && name) {
          const cpt = Array.isArray(props.centroid) ? props.centroid : props.center;
          if (Array.isArray(cpt) && cpt.length >= 2) {
            const lon = Number(cpt[0]);
            const lat = Number(cpt[1]);
            if (Number.isFinite(lon) && Number.isFinite(lat)) {
              const shortLabel = shortProvinceName(name);
              const major = ['北京', '上海', '广东', '四川', '新疆', '西藏', '内蒙古', '黑龙江', '台湾', '香港'].includes(shortLabel);
              labels.push({
                lon,
                lat,
                label: shortLabel,
                mapName: name,
                isProvince: true,
                minZoom: major ? 1.24 : 1.48,
                priority: major ? 6.5 : 4.5,
                vec: this.lonLatToVec(lon, lat)
              });
            }
          }
        }
      });

      this.maskData = octx.getImageData(0, 0, W, H).data;
      this.featureNames = names;
      this.vectorFeatures = vectorFeatures;
      this.mapLabels = labels;
      this.ready = true;
      this.building = false;
      this.syncData();
      this.syncNodes();
    },

    syncData() {
      const geo = state.geography || { regions: [], ips: [] };
      const regions = Array.isArray(geo.regions) ? geo.regions : [];
      const ips = Array.isArray(geo.ips) ? geo.ips : [];
      const heat = new Map();
      const meta = new Map();
      let maxReq = 1;
      regions.forEach((r) => {
        const reqs = Number(r.requests) || 0;
        if (reqs > maxReq) maxReq = reqs;
        if (r.map_name) {
          heat.set(r.map_name, reqs);
          meta.set(r.map_name, r);
        }
      });
      this.maxRequests = maxReq;
      this.regionHeatByName = heat;
      this.regionMetaByName = meta;
      this.visitors = ips
        .filter((i) => i.country_code && Number.isFinite(Number(i.latitude)) && Number.isFinite(Number(i.longitude)))
        .slice(0, 80)
        .map((i) => ({
          ...i,
          lon: Number(i.longitude),
          lat: Number(i.latitude),
          vec: this.lonLatToVec(Number(i.longitude), Number(i.latitude))
        }));
      if (this.ready && state.view === 'overview' && state.geoMode === '3d') this.draw(performance.now());
    },

    syncNodes() {
      const list = Array.isArray(state.nodesData) ? state.nodesData : [];
      const mapped = [];
      const seen = new Map();
      list.forEach((n) => {
        const coord = resolveNodeGeoCoord(n);
        if (!coord) return;
        const key = `${coord[0]},${coord[1]}`;
        const jitter = (seen.get(key) || 0) * 1.8;
        seen.set(key, (seen.get(key) || 0) + 1);
        const lon = coord[0] + jitter;
        const lat = coord[1] + (jitter ? jitter * 0.45 : 0);
        mapped.push({
          id: n.id,
          name: n.name || coord[2],
          region: n.region || coord[2],
          status: n.status || 'offline',
          downloadBPS: Number(n.metrics?.download_bps) || 0,
          activeRequests: Number(n.metrics?.active_requests) || 0,
          lon,
          lat,
          vec: this.lonLatToVec(lon, lat)
        });
      });
      this.nodes = mapped;
      if (this.ready && state.view === 'overview' && state.geoMode === '3d') this.draw(performance.now());
    },

    resize() {
      const canvas = document.getElementById('geography-globe');
      const vp = document.getElementById('geo-map-viewport');
      if (!canvas || !vp) return;
      const rect = vp.getBoundingClientRect();
      if (rect.width < 40 || rect.height < 40) return;
      this.canvas = canvas;
      this.ctx = canvas.getContext('2d');
      this.dpr = Math.min(window.devicePixelRatio || 1, 2);
      this.width = Math.round(rect.width);
      this.height = Math.round(rect.height);
      canvas.width = Math.round(this.width * this.dpr);
      canvas.height = Math.round(this.height * this.dpr);
      if (this.ready && state.geoMode === '3d') this.draw(performance.now());
    },

    bindEvents() {
      if (this.eventsBound) return;
      const canvas = document.getElementById('geography-globe');
      if (!canvas) return;
      this.eventsBound = true;

      canvas.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0) return;
        this.dragging = true;
        this.velLon = 0;
        this.velLat = 0;
        this.lastPointerX = ev.clientX;
        this.lastPointerY = ev.clientY;
        canvas.classList.add('is-dragging');
        canvas.setPointerCapture?.(ev.pointerId);
        this.hideTooltip();
      });

      canvas.addEventListener('pointermove', (ev) => {
        const rect = canvas.getBoundingClientRect();
        this.pointerX = ev.clientX - rect.left;
        this.pointerY = ev.clientY - rect.top;
        this.hovering = true;
        if (this.dragging) {
          const dx = ev.clientX - this.lastPointerX;
          const dy = ev.clientY - this.lastPointerY;
          this.lastPointerX = ev.clientX;
          this.lastPointerY = ev.clientY;
          const sens = 0.0056 / Math.max(0.75, this.zoom);
          this.velLon = -dx * sens;
          this.velLat = dy * sens;
          this.rotLon += this.velLon;
          this.rotLat = Math.max(-1.28, Math.min(1.28, this.rotLat + this.velLat));
          this.hideTooltip();
          return;
        }
        this.updateHover(this.pointerX, this.pointerY);
      });

      const endDrag = () => {
        if (!this.dragging) return;
        this.dragging = false;
        canvas.classList.remove('is-dragging');
      };
      canvas.addEventListener('pointerup', endDrag);
      canvas.addEventListener('pointercancel', endDrag);
      canvas.addEventListener('pointerleave', () => {
        this.hovering = false;
        this.hoveredFeatureName = '';
        this.pointerX = -1;
        this.pointerY = -1;
        endDrag();
        this.hideTooltip();
      });

      canvas.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const factor = ev.deltaY < 0 ? 1.12 : 0.89;
        this.zoomBy(factor);
        if (this.hovering && !this.dragging && this.pointerX >= 0) {
          this.updateHover(this.pointerX, this.pointerY);
        }
      }, { passive: false });
    },

    zoomBy(factor) {
      this.zoom = Math.max(0.72, Math.min(3.6, this.zoom * factor));
      if (this.ready) this.draw(performance.now());
    },

    resetView() {
      this.rotLon = 104 * Math.PI / 180;
      this.rotLat = 26 * Math.PI / 180;
      this.velLon = 0;
      this.velLat = 0;
      this.zoom = 1.08;
      if (this.ready) this.draw(performance.now());
    },

    toggleAutoRotate() {
      this.autoRotate = !this.autoRotate;
      const btn = document.getElementById('map-autorotate');
      if (btn) {
        btn.classList.toggle('active', this.autoRotate);
        btn.setAttribute('aria-pressed', String(this.autoRotate));
      }
    },

    hideTooltip() {
      const tip = document.getElementById('geo-globe-tooltip');
      if (tip) tip.hidden = true;
    },

    showTooltip(x, y, title, lines) {
      const tip = document.getElementById('geo-globe-tooltip');
      if (!tip) return;
      const frag = document.createDocumentFragment();
      frag.append(el('strong', '', title));
      lines.forEach((line) => { if (line) frag.append(el('span', '', line)); });
      tip.replaceChildren(frag);
      tip.hidden = false;
      const tw = tip.offsetWidth || 180;
      const th = tip.offsetHeight || 56;
      const left = Math.max(10, Math.min(this.width - tw - 12, x + 14));
      const top = Math.max(10, Math.min(this.height - th - 12, y - th - 10 < 10 ? y + 16 : y - th - 10));
      tip.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
    },

    updateHover(mx, my) {
      if (!this.ready || this.width < 40) return;
      // 1. Check projected Edge Node & Visitor IP pins first
      for (const pin of this.projectedPins) {
        const dist = Math.hypot(mx - pin.sx, my - pin.sy);
        if (dist <= pin.hitR) {
          this.hoveredFeatureName = '';
          if (pin.kind === 'node') {
            const stText = pin.data.status === 'online' ? '在线运行' : pin.data.status === 'draining' ? '维护排空' : '离线';
            this.showTooltip(mx, my, `边缘节点 · ${pin.data.name}`, [
              `地区：${pin.data.region} · ${stText}`,
              `实时下行 ${formatBytes(pin.data.downloadBPS)}/s · ${formatNumber(pin.data.activeRequests)} 活跃连接`
            ]);
          } else {
            const v = pin.data;
            this.showTooltip(mx, my, v.ip, [
              v.label || v.country_code,
              `最大下行 ${formatBytes(v.peak_bps)}/s · ${formatNumber(v.requests)} 次请求`
            ]);
          }
          return;
        }
      }

      // 2. Inverse orthographic projection -> O(1) high-res 1440x720 mask lookup
      const cx = this.width / 2;
      const cy = this.height / 2;
      const R = Math.min(this.width, this.height) * 0.42 * this.zoom;
      const nx = (mx - cx) / R;
      const ny = -(my - cy) / R;
      const r2 = nx * nx + ny * ny;
      if (r2 > 1 || !this.maskData) {
        this.hoveredFeatureName = '';
        this.hideTooltip();
        return;
      }
      const nz = Math.sqrt(1 - r2);
      const sinLat = Math.sin(this.rotLat);
      const cosLat = Math.cos(this.rotLat);
      const sinLon = Math.sin(this.rotLon);
      const cosLon = Math.cos(this.rotLon);
      // Inverse of projectUnit
      const uy = ny * cosLat + nz * sinLat;
      const z1 = -ny * sinLat + nz * cosLat;
      const ux = nx * cosLon + z1 * sinLon;
      const uz = -nx * sinLon + z1 * cosLon;
      const latDeg = Math.asin(Math.max(-1, Math.min(1, uy))) * 180 / Math.PI;
      const lonDeg = Math.atan2(ux, uz) * 180 / Math.PI;
      const px = Math.max(0, Math.min(this.maskW - 1, Math.floor(((lonDeg + 180) / 360) * this.maskW)));
      const py = Math.max(0, Math.min(this.maskH - 1, Math.floor(((90 - latDeg) / 180) * this.maskH)));
      const offIdx = (py * this.maskW + px) * 4;
      if (this.maskData[offIdx + 3] > 180 && this.maskData[offIdx + 2] > 64) {
        const fid = this.maskData[offIdx] + (this.maskData[offIdx + 1] << 8);
        const mapName = this.featureNames[fid] || '';
        if (fid > 0 && mapName) {
          this.hoveredFeatureName = mapName;
          const displayName = localizeGeoName(mapName);
          const info = this.regionMetaByName.get(mapName);
          if (info) {
            this.showTooltip(mx, my, info.label || displayName, [
              `${formatNumber(info.requests)} 次请求 · ${formatNumber(info.unique_ips)} 个独立 IP`,
              `峰值速率 ${formatBytes(info.peak_bps)}/s · 下行 ${formatBytes(info.bytes_out)}`
            ]);
          } else {
            const subtitle = WORLD_COUNTRY_ZH[mapName] ? `${mapName} · 当前统计周期暂无访客流量` : '当前统计周期暂无访客流量';
            this.showTooltip(mx, my, displayName, [subtitle]);
          }
          return;
        }
      }
      this.hoveredFeatureName = '';
      this.hideTooltip();
    },

    // Trace one spherical ring onto ctx for FILL (with exact horizon-arc closure) or STROKE (front edges only)
    traceRing(ctx, ring, cx, cy, R, sinLon, cosLon, sinLat, cosLat, forFill) {
      // Exact bounding-sphere culling (every world/China ring has angular radius < 37 deg)
      const bz1 = ring.bx * sinLon + ring.bz * cosLon;
      const bz2 = ring.by * sinLat + bz1 * cosLat;
      if (bz2 < -ring.sinR - 0.015) return false;

      const n = ring.count;
      const coords = ring.coords;

      // Ultra-fast path: entire ring guaranteed strictly on front hemisphere
      if (bz2 > ring.sinR + 0.015) {
        for (let i = 0; i < n; i += 1) {
          const ux = coords[i * 3];
          const uy = coords[i * 3 + 1];
          const uz = coords[i * 3 + 2];
          const x1 = ux * cosLon - uz * sinLon;
          const z1 = ux * sinLon + uz * cosLon;
          const y2 = uy * cosLat - z1 * sinLat;
          const sx = cx + x1 * R;
          const sy = cy - y2 * R;
          if (i === 0) ctx.moveTo(sx, sy);
          else ctx.lineTo(sx, sy);
        }
        ctx.closePath();
        return true;
      }

      // Project into reusable zero-GC scratch arrays to classify front/back/crossing
      this.ensureScratch(n);
      const px = this._px;
      const py = this._py;
      const pz = this._pz;
      let anyFront = false;
      let firstBack = -1;
      for (let i = 0; i < n; i += 1) {
        const ux = coords[i * 3];
        const uy = coords[i * 3 + 1];
        const uz = coords[i * 3 + 2];
        const x1 = ux * cosLon - uz * sinLon;
        const z1 = ux * sinLon + uz * cosLon;
        const y2 = uy * cosLat - z1 * sinLat;
        const z2 = uy * sinLat + z1 * cosLat;
        px[i] = x1;
        py[i] = y2;
        pz[i] = z2;
        if (z2 >= 0) anyFront = true;
        else if (firstBack === -1) firstBack = i;
      }
      if (!anyFront) return false;

      // Entire ring ended up on front hemisphere
      if (firstBack === -1) {
        ctx.moveTo(cx + px[0] * R, cy - py[0] * R);
        for (let i = 1; i < n; i += 1) ctx.lineTo(cx + px[i] * R, cy - py[i] * R);
        ctx.closePath();
        return true;
      }

      // Crossing ring: start from guaranteed back-hemisphere vertex `firstBack`
      if (forFill) {
        let hasStarted = false;
        let firstEnterAng = 0;
        let lastExitAng = 0;
        for (let step = 0; step < n; step += 1) {
          const a = (firstBack + step) % n;
          const b = (a + 1) % n;
          const za = pz[a];
          const zb = pz[b];
          if (za < 0 && zb >= 0) {
            const t = za / (za - zb);
            let hx = px[a] + (px[b] - px[a]) * t;
            let hy = py[a] + (py[b] - py[a]) * t;
            const hl = Math.hypot(hx, hy) || 1;
            hx /= hl; hy /= hl;
            const enterAng = Math.atan2(-hy, hx);
            if (!hasStarted) {
              ctx.moveTo(cx + hx * R, cy - hy * R);
              firstEnterAng = enterAng;
              hasStarted = true;
            } else {
              let delta = enterAng - lastExitAng;
              while (delta > Math.PI) delta -= Math.PI * 2;
              while (delta < -Math.PI) delta += Math.PI * 2;
              ctx.arc(cx, cy, R, lastExitAng, enterAng, delta < 0);
            }
            ctx.lineTo(cx + px[b] * R, cy - py[b] * R);
          } else if (za >= 0 && zb >= 0) {
            ctx.lineTo(cx + px[b] * R, cy - py[b] * R);
          } else if (za >= 0 && zb < 0) {
            const t = za / (za - zb);
            let hx = px[a] + (px[b] - px[a]) * t;
            let hy = py[a] + (py[b] - py[a]) * t;
            const hl = Math.hypot(hx, hy) || 1;
            hx /= hl; hy /= hl;
            ctx.lineTo(cx + hx * R, cy - hy * R);
            lastExitAng = Math.atan2(-hy, hx);
          }
        }
        if (hasStarted) {
          let delta = firstEnterAng - lastExitAng;
          while (delta > Math.PI) delta -= Math.PI * 2;
          while (delta < -Math.PI) delta += Math.PI * 2;
          ctx.arc(cx, cy, R, lastExitAng, firstEnterAng, delta < 0);
          ctx.closePath();
          return true;
        }
        return false;
      }

      // Stroke-only path: draw ONLY real front-hemisphere border edges (never the limb arc)
      let drew = false;
      for (let step = 0; step < n; step += 1) {
        const a = (firstBack + step) % n;
        const b = (a + 1) % n;
        const za = pz[a];
        const zb = pz[b];
        if (za < 0 && zb >= 0) {
          const t = za / (za - zb);
          let hx = px[a] + (px[b] - px[a]) * t;
          let hy = py[a] + (py[b] - py[a]) * t;
          const hl = Math.hypot(hx, hy) || 1;
          hx /= hl; hy /= hl;
          ctx.moveTo(cx + hx * R, cy - hy * R);
          ctx.lineTo(cx + px[b] * R, cy - py[b] * R);
          drew = true;
        } else if (za >= 0 && zb >= 0) {
          ctx.lineTo(cx + px[b] * R, cy - py[b] * R);
          drew = true;
        } else if (za >= 0 && zb < 0) {
          const t = za / (za - zb);
          let hx = px[a] + (px[b] - px[a]) * t;
          let hy = py[a] + (py[b] - py[a]) * t;
          const hl = Math.hypot(hx, hy) || 1;
          hx /= hl; hy /= hl;
          ctx.lineTo(cx + hx * R, cy - hy * R);
          drew = true;
        }
      }
      return drew;
    },

    heatFillColor(ratio, dark) {
      const t = Math.max(0, Math.min(1, ratio));
      if (dark) {
        // Deep indigo (#2b3975) -> bright luminous indigo-sky (#6366f1 -> #38bdf8)
        const r = Math.round(45 + t * 54);
        const g = Math.round(62 + t * 116);
        const b = Math.round(128 + t * 118);
        return `rgb(${r}, ${g}, ${b})`;
      }
      // Crisp soft periwinkle (#c7d2fe) -> rich indigo (#4f46e5)
      const r = Math.round(199 - t * 120);
      const g = Math.round(210 - t * 140);
      const b = Math.round(254 - t * 25);
      return `rgb(${r}, ${g}, ${b})`;
    },

    draw(ts) {
      if (!this.ctx || !this.ready || this.width < 40 || this.height < 40) return;
      const ctx = this.ctx;
      const dark = document.documentElement.dataset.theme === 'dark';
      const W = this.width;
      const H = this.height;
      const cx = W / 2;
      const cy = H / 2;
      const R = Math.min(W, H) * 0.42 * this.zoom;

      ctx.save();
      ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);

      // 1. Atmospheric halo outside the Earth
      const halo = ctx.createRadialGradient(cx, cy, R * 0.86, cx, cy, R * 1.16);
      if (dark) {
        halo.addColorStop(0, 'rgba(99, 102, 241, 0.24)');
        halo.addColorStop(0.55, 'rgba(56, 189, 248, 0.08)');
        halo.addColorStop(1, 'rgba(9, 12, 20, 0)');
      } else {
        halo.addColorStop(0, 'rgba(79, 70, 229, 0.14)');
        halo.addColorStop(0.58, 'rgba(56, 189, 248, 0.05)');
        halo.addColorStop(1, 'rgba(255, 255, 255, 0)');
      }
      ctx.fillStyle = halo;
      ctx.beginPath();
      ctx.arc(cx, cy, R * 1.16, 0, Math.PI * 2);
      ctx.fill();

      // 2. Sphere ocean body with clean cartographic contrast against landmasses
      const sphereGrad = ctx.createRadialGradient(cx - R * 0.34, cy - R * 0.32, R * 0.08, cx, cy, R);
      if (dark) {
        sphereGrad.addColorStop(0, '#162440');
        sphereGrad.addColorStop(0.58, '#0d162a');
        sphereGrad.addColorStop(1, '#070c18');
      } else {
        sphereGrad.addColorStop(0, '#eef4fd');
        sphereGrad.addColorStop(0.58, '#dde8fa');
        sphereGrad.addColorStop(1, '#c3d5f2');
      }
      ctx.fillStyle = sphereGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();

      // Clip inside sphere for graticule + vector countries/provinces + 3D shading
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.clip();

      const sinLon = Math.sin(this.rotLon);
      const cosLon = Math.cos(this.rotLon);
      const sinLat = Math.sin(this.rotLat);
      const cosLat = Math.cos(this.rotLat);

      // 3. Geodesic latitude/longitude graticule (underneath landmasses)
      ctx.strokeStyle = dark ? 'rgba(148, 163, 184, 0.11)' : 'rgba(79, 70, 229, 0.11)';
      ctx.lineWidth = 0.75;
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let started = false;
        for (let lon = -180; lon <= 180; lon += 5) {
          const v = this.lonLatToVec(lon, lat);
          const p = this.projectUnit(v.x, v.y, v.z, sinLon, cosLon, sinLat, cosLat);
          if (p.z > 0) {
            const sx = cx + p.x * R;
            const sy = cy - p.y * R;
            if (!started) { ctx.moveTo(sx, sy); started = true; }
            else ctx.lineTo(sx, sy);
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }
      for (let lon = -180; lon < 180; lon += 30) {
        ctx.beginPath();
        let started = false;
        for (let lat = -84; lat <= 84; lat += 5) {
          const v = this.lonLatToVec(lon, lat);
          const p = this.projectUnit(v.x, v.y, v.z, sinLon, cosLon, sinLat, cosLat);
          if (p.z > 0) {
            const sx = cx + p.x * R;
            const sy = cy - p.y * R;
            if (!started) { ctx.moveTo(sx, sy); started = true; }
            else ctx.lineTo(sx, sy);
          } else {
            started = false;
          }
        }
        ctx.stroke();
      }

      // 4. High-Detail 3D Vector Countries & Chinese Provinces
      const feats = this.vectorFeatures;
      const heat = this.regionHeatByName;
      const maxReq = Math.max(1, this.maxRequests);
      const logMax = Math.log10(maxReq + 1);
      const hoverName = this.hoveredFeatureName;
      const baseLandFill = dark ? '#202e4a' : '#fafcff';
      const chinaLandFill = dark ? '#233352' : '#f5f8ff';
      const visibleFeats = [];
      const hoveredFeats = [];

      // Pass 4a: Solid filled polygons (culling back-hemisphere features in O(1))
      for (let i = 0; i < feats.length; i += 1) {
        const f = feats[i];
        const fz1 = f.bx * sinLon + f.bz * cosLon;
        const fz2 = f.by * sinLat + fz1 * cosLat;
        if (fz2 < -f.sinR - 0.02) continue;

        if (f.isDashLine) {
          ctx.fillStyle = dark ? 'rgba(148, 163, 184, 0.36)' : 'rgba(71, 85, 105, 0.48)';
          ctx.beginPath();
          let any = false;
          for (let p = 0; p < f.polygons.length; p += 1) {
            const rings = f.polygons[p];
            for (let r = 0; r < rings.length; r += 1) {
              if (this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, true)) any = true;
            }
          }
          if (any) ctx.fill();
          continue;
        }

        const reqs = heat.get(f.name) || 0;
        ctx.beginPath();
        let drewAny = false;
        for (let p = 0; p < f.polygons.length; p += 1) {
          const rings = f.polygons[p];
          for (let r = 0; r < rings.length; r += 1) {
            if (this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, true)) drewAny = true;
          }
        }
        if (!drewAny) continue;

        visibleFeats.push(f);
        if (hoverName && f.name === hoverName) hoveredFeats.push(f);

        if (reqs > 0) {
          const ratio = Math.min(1, Math.log10(reqs + 1) / logMax);
          ctx.fillStyle = this.heatFillColor(ratio, dark);
        } else {
          ctx.fillStyle = f.isChina ? chinaLandFill : baseLandFill;
        }
        ctx.fill('evenodd');
      }

      // Pass 4b: Crisp hierarchical borders (Chinese provincial lines + international borders)
      const zoomSqrt = Math.sqrt(Math.max(0.75, this.zoom));
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';

      // China provincial borders (fine, sharp, unobstructed)
      ctx.strokeStyle = dark ? 'rgba(148, 163, 184, 0.34)' : 'rgba(100, 116, 139, 0.44)';
      ctx.lineWidth = Math.min(1.15, 0.65 * zoomSqrt);
      ctx.beginPath();
      for (let i = 0; i < visibleFeats.length; i += 1) {
        const f = visibleFeats[i];
        if (!f.isChina) continue;
        for (let p = 0; p < f.polygons.length; p += 1) {
          const rings = f.polygons[p];
          for (let r = 0; r < rings.length; r += 1) {
            this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, false);
          }
        }
      }
      ctx.stroke();

      // International borders & coastlines (crisp primary separation)
      ctx.strokeStyle = dark ? 'rgba(186, 206, 236, 0.46)' : 'rgba(71, 85, 105, 0.56)';
      ctx.lineWidth = Math.min(1.45, 0.85 * zoomSqrt);
      ctx.beginPath();
      for (let i = 0; i < visibleFeats.length; i += 1) {
        const f = visibleFeats[i];
        if (f.isChina) continue;
        for (let p = 0; p < f.polygons.length; p += 1) {
          const rings = f.polygons[p];
          for (let r = 0; r < rings.length; r += 1) {
            this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, false);
          }
        }
      }
      ctx.stroke();

      // Pass 4c: Hovered Country / Province highlight on top of all borders
      if (hoveredFeats.length) {
        ctx.fillStyle = dark ? 'rgba(56, 189, 248, 0.34)' : 'rgba(79, 70, 229, 0.22)';
        ctx.beginPath();
        for (let i = 0; i < hoveredFeats.length; i += 1) {
          const f = hoveredFeats[i];
          for (let p = 0; p < f.polygons.length; p += 1) {
            const rings = f.polygons[p];
            for (let r = 0; r < rings.length; r += 1) {
              this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, true);
            }
          }
        }
        ctx.fill('evenodd');

        ctx.strokeStyle = dark ? '#38bdf8' : '#4f46e5';
        ctx.lineWidth = Math.min(2.2, 1.55 * zoomSqrt);
        ctx.beginPath();
        for (let i = 0; i < hoveredFeats.length; i += 1) {
          const f = hoveredFeats[i];
          for (let p = 0; p < f.polygons.length; p += 1) {
            const rings = f.polygons[p];
            for (let r = 0; r < rings.length; r += 1) {
              this.traceRing(ctx, rings[r], cx, cy, R, sinLon, cosLon, sinLat, cosLat, false);
            }
          }
        }
        ctx.stroke();
      }

      // 5. Spherical 3D lighting & curvature vignette over landmass + ocean
      const shadeGrad = ctx.createRadialGradient(cx - R * 0.32, cy - R * 0.30, R * 0.08, cx, cy, R);
      if (dark) {
        shadeGrad.addColorStop(0, 'rgba(186, 230, 253, 0.07)');
        shadeGrad.addColorStop(0.58, 'rgba(15, 23, 42, 0)');
        shadeGrad.addColorStop(0.86, 'rgba(2, 6, 23, 0.22)');
        shadeGrad.addColorStop(1, 'rgba(2, 6, 23, 0.48)');
      } else {
        shadeGrad.addColorStop(0, 'rgba(255, 255, 255, 0.16)');
        shadeGrad.addColorStop(0.62, 'rgba(255, 255, 255, 0)');
        shadeGrad.addColorStop(0.88, 'rgba(30, 58, 138, 0.07)');
        shadeGrad.addColorStop(1, 'rgba(30, 58, 138, 0.18)');
      }
      ctx.fillStyle = shadeGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore(); // End sphere clip

      // Crisp sphere limb outline
      ctx.strokeStyle = dark ? 'rgba(129, 140, 248, 0.36)' : 'rgba(79, 70, 229, 0.26)';
      ctx.lineWidth = 1.3;
      ctx.beginPath();
      ctx.arc(cx, cy, R, 0, Math.PI * 2);
      ctx.stroke();

      // 6. 3D Great-Circle Traffic Arcs (Visitors -> Online Edge Nodes)
      const onlineNodes = this.nodes.filter((n) => n.status === 'online');
      const pulsePhase = ((ts || 0) * 0.00055) % 1;
      if (onlineNodes.length && this.visitors.length) {
        const arcCount = Math.min(12, this.visitors.length);
        for (let i = 0; i < arcCount; i += 1) {
          const v = this.visitors[i];
          const targetNode = onlineNodes[i % onlineNodes.length];
          const steps = 26;
          ctx.beginPath();
          let started = false;
          let pulsePt = null;
          const phase = (pulsePhase + i * 0.17) % 1;
          for (let s = 0; s <= steps; s += 1) {
            const t = s / steps;
            let ix = v.vec.x * (1 - t) + targetNode.vec.x * t;
            let iy = v.vec.y * (1 - t) + targetNode.vec.y * t;
            let iz = v.vec.z * (1 - t) + targetNode.vec.z * t;
            const len = Math.hypot(ix, iy, iz) || 1;
            const alt = 1 + 0.14 * Math.sin(Math.PI * t);
            ix = (ix / len) * alt;
            iy = (iy / len) * alt;
            iz = (iz / len) * alt;
            const p = this.projectUnit(ix, iy, iz, sinLon, cosLon, sinLat, cosLat);
            if (p.z > -0.05) {
              const sx = cx + p.x * R;
              const sy = cy - p.y * R;
              if (!started) { ctx.moveTo(sx, sy); started = true; }
              else ctx.lineTo(sx, sy);
              if (Math.abs(t - phase) < 0.045) pulsePt = { sx, sy };
            } else {
              started = false;
            }
          }
          ctx.strokeStyle = dark ? 'rgba(52, 211, 153, 0.42)' : 'rgba(14, 165, 233, 0.42)';
          ctx.lineWidth = 1.3;
          ctx.stroke();
          if (pulsePt) {
            ctx.fillStyle = dark ? '#34d399' : '#0284c7';
            ctx.beginPath();
            ctx.arc(pulsePt.sx, pulsePt.sy, 2.6, 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }

      // 7. Visitor Beacons & Edge Node Markers (front hemisphere) + occupied rects for label collision avoidance
      const projectedPins = [];
      const occupiedRects = [];
      const ringWave = ((ts || 0) * 0.0009) % 1;

      this.visitors.forEach((v) => {
        const p = this.projectUnit(v.vec.x, v.vec.y, v.vec.z, sinLon, cosLon, sinLat, cosLat);
        if (p.z <= 0.02) return;
        const sx = cx + p.x * R;
        const sy = cy - p.y * R;
        const r = Math.max(3.2, Math.min(7.5, 3 + Math.log10((Number(v.peak_bps) || 0) + 1) * 0.55));
        ctx.strokeStyle = dark ? `rgba(52, 211, 153, ${(0.55 * (1 - ringWave)).toFixed(2)})` : `rgba(5, 150, 105, ${(0.5 * (1 - ringWave)).toFixed(2)})`;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(sx, sy, r + ringWave * 10, 0, Math.PI * 2);
        ctx.stroke();
        ctx.fillStyle = dark ? '#34d399' : '#059669';
        ctx.beginPath();
        ctx.arc(sx, sy, r, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = dark ? '#064e3b' : '#ffffff';
        ctx.lineWidth = 1.3;
        ctx.stroke();
        projectedPins.push({ kind: 'visitor', sx, sy, hitR: r + 7, data: v });
        occupiedRects.push({ x1: sx - r - 4, y1: sy - r - 4, x2: sx + r + 4, y2: sy + r + 4 });
      });

      this.nodes.forEach((n) => {
        const p = this.projectUnit(n.vec.x, n.vec.y, n.vec.z, sinLon, cosLon, sinLat, cosLat);
        if (p.z <= 0.04) return;
        const sx = cx + p.x * R;
        const sy = cy - p.y * R;
        const isOnline = n.status === 'online';
        const coreColor = isOnline ? (dark ? '#818cf8' : '#4f46e5') : '#94a3b8';

        if (isOnline) {
          ctx.strokeStyle = dark ? `rgba(129, 140, 248, ${(0.62 * (1 - ringWave)).toFixed(2)})` : `rgba(79, 70, 229, ${(0.52 * (1 - ringWave)).toFixed(2)})`;
          ctx.lineWidth = 1.4;
          ctx.beginPath();
          ctx.arc(sx, sy, 5 + ringWave * 13, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.fillStyle = coreColor;
        ctx.beginPath();
        ctx.arc(sx, sy, 4.6, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = dark ? '#0f172a' : '#ffffff';
        ctx.lineWidth = 1.6;
        ctx.stroke();

        // Crisp node label pill
        ctx.font = '600 11px -apple-system, BlinkMacSystemFont, "Inter", sans-serif';
        const label = n.name;
        const tw = ctx.measureText(label).width;
        const lx = sx + 8;
        const ly = sy - 10;
        const padX = 6;
        const pillW = tw + padX * 2;
        const pillH = 20;
        ctx.fillStyle = dark ? 'rgba(15, 23, 42, 0.88)' : 'rgba(255, 255, 255, 0.94)';
        ctx.strokeStyle = dark ? 'rgba(129, 140, 248, 0.48)' : 'rgba(79, 70, 229, 0.32)';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(lx, ly, pillW, pillH, 6);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = dark ? '#f1f5f9' : '#1e293b';
        ctx.fillText(label, lx + padX, ly + 13.5);

        projectedPins.push({ kind: 'node', sx, sy, hitR: 15, data: n });
        occupiedRects.push({ x1: sx - 8, y1: ly - 4, x2: lx + pillW + 6, y2: ly + pillH + 4 });
      });

      // 8. Collision-Free Cartographic Chinese Labels (major countries + zoomed-in Chinese provinces)
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, R - 2, 0, Math.PI * 2);
      ctx.clip();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const curZoom = this.zoom;
      const candidates = [];
      for (let i = 0; i < this.mapLabels.length; i += 1) {
        const item = this.mapLabels[i];
        if (curZoom < (item.minZoom || 0.7)) continue;
        if (item.maxZoom && curZoom > item.maxZoom) continue;
        const p = this.projectUnit(item.vec.x, item.vec.y, item.vec.z, sinLon, cosLon, sinLat, cosLat);
        if (p.z <= 0.34) continue;
        const sx = cx + p.x * R;
        const sy = cy - p.y * R;
        if (sx < 12 || sx > W - 12 || sy < 12 || sy > H - 12) continue;
        const isHot = item.mapName && (heat.get(item.mapName) || 0) > 0;
        const isHovered = item.mapName && hoverName === item.mapName;
        candidates.push({
          item,
          sx,
          sy,
          z: p.z,
          score: (isHovered ? 50 : 0) + (isHot ? 15 : 0) + (item.priority || 5) + p.z
        });
      }
      candidates.sort((a, b) => b.score - a.score);

      for (let i = 0; i < candidates.length; i += 1) {
        const c = candidates[i];
        const isProv = Boolean(c.item.isProvince);
        const fontSize = isProv ? 10 : (c.item.priority >= 9 ? 11 : 10);
        ctx.font = `${c.item.priority >= 9 ? '600' : '500'} ${fontSize}px -apple-system, BlinkMacSystemFont, "PingFang SC", "Inter", sans-serif`;
        const tw = ctx.measureText(c.item.label).width;
        const pad = isProv ? 4 : 6;
        const rect = {
          x1: c.sx - tw / 2 - pad,
          y1: c.sy - fontSize / 2 - 3,
          x2: c.sx + tw / 2 + pad,
          y2: c.sy + fontSize / 2 + 3
        };
        let collides = false;
        for (let k = 0; k < occupiedRects.length; k += 1) {
          const r = occupiedRects[k];
          if (rect.x1 < r.x2 && rect.x2 > r.x1 && rect.y1 < r.y2 && rect.y2 > r.y1) {
            collides = true;
            break;
          }
        }
        if (collides) continue;
        occupiedRects.push(rect);

        const alpha = Math.min(1, (c.z - 0.34) / 0.30) * (isProv ? 0.84 : 0.88);
        ctx.lineWidth = 2.6;
        ctx.lineJoin = 'round';
        ctx.strokeStyle = dark
          ? `rgba(11, 18, 34, ${(alpha * 0.92).toFixed(2)})`
          : `rgba(250, 252, 255, ${(alpha * 0.95).toFixed(2)})`;
        ctx.strokeText(c.item.label, c.sx, c.sy);
        ctx.fillStyle = dark
          ? (isProv ? `rgba(203, 213, 225, ${alpha.toFixed(2)})` : `rgba(226, 232, 240, ${alpha.toFixed(2)})`)
          : (isProv ? `rgba(51, 65, 85, ${alpha.toFixed(2)})` : `rgba(30, 41, 59, ${alpha.toFixed(2)})`);
        ctx.fillText(c.item.label, c.sx, c.sy);
      }
      ctx.restore();

      this.projectedPins = projectedPins;
      ctx.restore();
    },

    tick(ts) {
      if (state.view !== 'overview' || state.geoMode !== '3d' || document.hidden) {
        this.rafId = 0;
        return;
      }
      const dt = this.lastTime ? Math.min(48, ts - this.lastTime) : 16;
      this.lastTime = ts;
      if (!this.dragging) {
        if (Math.abs(this.velLon) > 0.0001 || Math.abs(this.velLat) > 0.0001) {
          this.rotLon += this.velLon;
          this.rotLat = Math.max(-1.28, Math.min(1.28, this.rotLat + this.velLat));
          this.velLon *= 0.92;
          this.velLat *= 0.92;
        } else if (this.autoRotate && !this.hovering) {
          this.rotLon += 0.00016 * dt;
        }
      }
      this.draw(ts);
      this.rafId = requestAnimationFrame((nextTs) => this.tick(nextTs));
    },

    start() {
      this.bindEvents();
      this.resize();
      if (!this.ready) {
        const empty = document.getElementById('geography-empty');
        if (empty) { empty.hidden = false; empty.textContent = '正在构建 3D 矢量地球…'; }
        ensureGeoFeatures().then((features) => {
          this.buildFromFeatures(features);
          if (empty && state.geoMode === '3d') empty.hidden = true;
          this.resize();
          if (state.view === 'overview' && state.geoMode === '3d' && !this.rafId) {
            this.lastTime = 0;
            this.rafId = requestAnimationFrame((ts) => this.tick(ts));
          }
        }).catch(() => {
          if (empty) { empty.hidden = false; empty.textContent = '地球模型资源加载失败'; }
        });
        return;
      }
      const empty = document.getElementById('geography-empty');
      if (empty) empty.hidden = true;
      if (!this.rafId && state.view === 'overview' && state.geoMode === '3d' && !document.hidden) {
        this.lastTime = 0;
        this.rafId = requestAnimationFrame((ts) => this.tick(ts));
      }
    },

    stop() {
      if (this.rafId) {
        cancelAnimationFrame(this.rafId);
        this.rafId = 0;
      }
      this.hideTooltip();
    }
  };

  function setGeoMode(mode, persist = true) {
    const next = mode === '2d' ? '2d' : '3d';
    state.geoMode = next;
    if (persist) safeStorageSet('gateway-geo-mode', next);
    document.querySelectorAll('[data-geo-mode]').forEach((btn) => {
      const active = btn.dataset.geoMode === next;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    syncSegmented(document.getElementById('geo-mode-control'));
    const vp = document.getElementById('geo-map-viewport');
    const globeCanvas = document.getElementById('geography-globe');
    const flatMap = document.getElementById('geography-map');
    const autoBtn = document.getElementById('map-autorotate');
    const hint = document.getElementById('geo-mode-hint');
    if (vp) vp.classList.toggle('is-globe-mode', next === '3d');
    if (globeCanvas) globeCanvas.hidden = next !== '3d';
    if (flatMap) flatMap.hidden = next !== '2d';
    if (autoBtn) autoBtn.hidden = next !== '3d';
    if (hint) hint.textContent = next === '3d' ? '拖拽旋转 · 滚轮缩放' : '拖拽平移 · 滚轮缩放';
    if (next === '3d') {
      geoGlobe.start();
    } else {
      geoGlobe.stop();
      renderGeographyMap2D();
    }
  }

  function renderGeographyMap() {
    if (state.view !== 'overview') return;
    if (state.geoMode === '3d') {
      geoGlobe.syncData();
      geoGlobe.syncNodes();
      geoGlobe.start();
      return;
    }
    renderGeographyMap2D();
  }

  function renderGeographyMap2D() {
    const container = document.getElementById('geography-map');
    const empty = document.getElementById('geography-empty');
    if (!container || state.view !== 'overview' || state.geoMode !== '2d') return;
    ensureGeographyMap().then(() => {
      if (state.view !== 'overview' || state.geoMode !== '2d') return;
      if (!state.geoChart) state.geoChart = window.echarts.init(container, null, { renderer: 'canvas' });
      if (!state.geoChartEventsBound) {
        state.geoChart.on('georoam', () => {
          const geo = state.geoChart?.getOption()?.geo?.[0];
          if (!geo) return;
          const center = Array.isArray(geo.center) && geo.center.length === 2 && geo.center.every((v) => Number.isFinite(Number(v)))
            ? [Number(geo.center[0]), Number(geo.center[1])] : null;
          const zoom = Number(geo.zoom);
          if (Number.isFinite(zoom) && zoom > 0) state.geoView.zoom = zoom;
          state.geoView.center = center;
        });
        state.geoChartEventsBound = true;
      }
      if (!state.geoWheelBound) {
        container.addEventListener('wheel', (event) => {
          event.preventDefault();
          queueGeographyZoom(event.deltaY < 0 ? 1.18 : 0.85);
        }, { passive: false });
        state.geoWheelBound = true;
      }
      const geography = state.geography || { regions: [], ips: [] };
      const regions = geography.regions || [];
      const ips = geography.ips || [];
      const p = mapPalette();
      const maximum = Math.max(1, ...regions.map((r) => Number(r.requests) || 0));
      const regionData = regions.map((r) => ({
        name: r.map_name, value: Number(r.requests) || 0, label: r.label,
        peak: Number(r.peak_bps) || 0, uniqueIPs: Number(r.unique_ips) || 0
      }));
      const ipData = ips.filter((i) => i.country_code && Number.isFinite(Number(i.latitude)) && Number.isFinite(Number(i.longitude))).map((i) => ({
        name: i.ip, value: [Number(i.longitude), Number(i.latitude), Number(i.peak_bps) || 0],
        label: i.label, requests: Number(i.requests) || 0, bytesOut: Number(i.bytes_out) || 0
      }));
      empty.hidden = ipData.length > 0;
      empty.textContent = ipData.length ? '' : '暂无已定位的请求来源';
      const option = {
        animation: false,
        backgroundColor: 'transparent',
        tooltip: {
          trigger: 'item', confine: true, transitionDuration: 0, renderMode: 'richText',
          backgroundColor: p.tooltip, borderColor: p.tooltipBorder, borderWidth: 1,
          textStyle: { color: p.tooltipText, fontSize: 12 },
          formatter: (params) => {
            const d = params.data || {};
            if (params.seriesType === 'scatter') {
              return `${d.name || ''}\n${d.label || ''}\n最大下行 ${formatBytes(d.value?.[2])}/s\n${formatNumber(d.requests)} 次请求 · ${formatBytes(d.bytesOut)}`;
            }
            if (!d.label) return localizeGeoName(params.name || '');
            return `${d.label}\n${formatNumber(d.value)} 次请求\n${formatNumber(d.uniqueIPs)} 个 IP · 最大 ${formatBytes(d.peak)}/s`;
          }
        },
        visualMap: { show: false, min: 0, max: maximum, seriesIndex: 0, inRange: { color: [p.activeLow, p.activeHigh] } },
        geo: {
          map: 'refract-world', roam: 'move', zoom: state.geoView.zoom, center: state.geoView.center,
          scaleLimit: { min: 0.75, max: 12 }, layoutCenter: ['50%', '50%'], layoutSize: '108%',
          itemStyle: { areaColor: p.area, borderColor: p.border, borderWidth: 0.65 },
          emphasis: { itemStyle: { areaColor: p.activeLow, borderColor: p.activeHigh } },
          select: { disabled: true }
        },
        series: [
          { name: '请求地域', type: 'map', map: 'refract-world', geoIndex: 0, data: regionData, selectedMode: false },
          {
            name: '请求 IP', type: 'scatter', coordinateSystem: 'geo', data: ipData, z: 3,
            symbolSize: (v) => Math.max(7, Math.min(20, 7 + Math.log10((Number(v?.[2]) || 0) + 1) * 1.7)),
            itemStyle: { color: p.point, borderColor: p.pointBorder, borderWidth: 1.5, opacity: 0.92 },
            emphasis: { scale: 1.25 }
          }
        ]
      };
      if (state.geoChart.getOption()?.geo?.length) {
        state.geoChart.setOption({
          animation: option.animation, backgroundColor: option.backgroundColor,
          tooltip: option.tooltip, visualMap: option.visualMap,
          geo: { roam: 'move', itemStyle: option.geo.itemStyle, emphasis: option.geo.emphasis },
          series: option.series
        });
      } else {
        state.geoChart.setOption(option, true);
      }
      state.geoChart.resize();
    }).catch(() => {
      empty.hidden = false;
      empty.textContent = '地图资源加载失败';
    });
  }

  function renderGeography(geography) {
    state.geography = geography;
    const regions = geography?.regions || [];
    const ips = geography?.ips || [];
    document.getElementById('geo-located').textContent = formatNumber(geography?.located_ips);
    document.getElementById('geo-unlocated').textContent = `${formatNumber(geography?.unlocated_ips)} 个等待定位`;
    document.getElementById('geo-regions').textContent = formatNumber(regions.length);
    document.getElementById('geo-located-badge').textContent = `已定位 ${formatNumber(geography?.located_ips)} IP`;
    document.getElementById('geo-regions-badge').textContent = `${formatNumber(regions.length)} 个地域`;
    document.getElementById('geo-peak').textContent = `${formatBytes(regions[0]?.peak_bps)}/s`;
    document.getElementById('geo-peak-place').textContent = regions[0]?.label || '暂无数据';

    const top = document.getElementById('geo-top-regions');
    if (!regions.length) {
      top.replaceChildren(el('p', 'field-hint', '暂无地域数据'));
    } else {
      const f = document.createDocumentFragment();
      regions.slice(0, 5).forEach((r) => {
        const row = el('div', 'geo-rank-row');
        row.append(el('span', '', r.label), el('strong', '', `${formatBytes(r.peak_bps)}/s`));
        f.append(row);
      });
      top.replaceChildren(f);
    }

    document.getElementById('region-table-count').textContent = formatNumber(regions.length);
    const regionBody = document.getElementById('regions-table');
    const regionEmpty = document.getElementById('regions-empty');
    if (!regions.length) { regionBody.replaceChildren(); regionEmpty.hidden = false; }
    else {
      regionEmpty.hidden = true;
      const f = document.createDocumentFragment();
      regions.forEach((r) => {
        const row = document.createElement('tr');
        [el('td', 'cell-primary', r.label), el('td', 'num-col', formatNumber(r.unique_ips)),
          el('td', 'num-col', formatNumber(r.requests)), el('td', 'num-col', formatBytes(r.bytes_out)),
          el('td', 'num-col mono', `${formatBytes(r.peak_bps)}/s`)].forEach((c) => row.append(c));
        f.append(row);
      });
      regionBody.replaceChildren(f);
    }

    document.getElementById('ip-table-count').textContent = formatNumber(ips.length);
    const ipBody = document.getElementById('geo-ips-table');
    const ipEmpty = document.getElementById('geo-ips-empty');
    if (!ips.length) { ipBody.replaceChildren(); ipEmpty.hidden = false; }
    else {
      ipEmpty.hidden = true;
      const f = document.createDocumentFragment();
      ips.forEach((i) => {
        const row = document.createElement('tr');
        [el('td', 'mono cell-primary', i.ip), el('td', '', i.label || '未知'),
          el('td', 'num-col', formatNumber(i.requests)),
          el('td', 'num-col mono', `${formatBytes(i.peak_bps)}/s`)].forEach((c) => row.append(c));
        f.append(row);
      });
      ipBody.replaceChildren(f);
    }
    syncSegmented(document.getElementById('geo-table-tabs'));
    renderGeographyMap();
  }

  async function refreshGeography() {
    const period = state.overviewPeriod;
    if (state.geographyPromise && state.geographyReqPeriod === period) return state.geographyPromise;
    const seq = ++state.geoReqSeq;
    state.geographyReqPeriod = period;
    const req = api(`/_admin/api/geography?period=${encodeURIComponent(period)}`).then((geography) => {
      if (seq === state.geoReqSeq && period === state.overviewPeriod) {
        renderGeography(geography);
      }
      return geography;
    });
    state.geographyPromise = req;
    try { return await req; } finally {
      if (state.geographyPromise === req) {
        state.geographyPromise = null;
        state.geographyReqPeriod = '';
      }
    }
  }

  function zoomGeographyMap(factor) {
    if (state.geoMode === '3d') {
      geoGlobe.zoomBy(factor);
      return;
    }
    if (!state.geoChart) return;
    const currentZoom = Number(state.geoView.zoom) || 1.08;
    const nextZoom = Math.max(0.75, Math.min(12, currentZoom * factor));
    if (nextZoom === currentZoom) return;
    state.geoView.zoom = nextZoom;
    state.geoChart.setOption({ geo: { center: state.geoView.center, zoom: nextZoom } }, { lazyUpdate: true });
  }

  function queueGeographyZoom(factor) {
    state.geoPendingZoom *= factor;
    if (state.geoZoomFrame) return;
    state.geoZoomFrame = requestAnimationFrame(() => {
      state.geoZoomFrame = 0;
      const f = state.geoPendingZoom;
      state.geoPendingZoom = 1;
      zoomGeographyMap(f);
    });
  }

  function resetGeographyMap() {
    if (state.geoMode === '3d') {
      geoGlobe.resetView();
      return;
    }
    if (!state.geoChart) return;
    state.geoPendingZoom = 1;
    state.geoView = { center: [0, 0], zoom: 1.08 };
    state.geoChart.setOption({ geo: { center: [0, 0], zoom: 1.08 } }, { lazyUpdate: true });
  }

  /* -------------------- Live Now Playing & Watch History -------------------- */

  function formatPlaybackClock(seconds) {
    const s = Math.max(0, Math.floor(Number(seconds) || 0));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
  }

  function formatWatchingTitle(item) {
    const series = String(item.series_name || '').trim();
    const title = String(item.title || '').trim() || `媒体 #${item.item_id || '?'}`;
    const sNum = Number(item.season_number) || 0;
    const eNum = Number(item.episode_number) || 0;
    const year = Number(item.production_year) || 0;
    const epCode = (sNum > 0 && eNum > 0)
      ? `S${String(sNum).padStart(2, '0')}E${String(eNum).padStart(2, '0')}`
      : (eNum > 0 ? `E${String(eNum).padStart(2, '0')}` : '');
    if (series) {
      const subParts = [];
      if (epCode) subParts.push(epCode);
      if (title && title.toLowerCase() !== series.toLowerCase()) subParts.push(title);
      return { main: series, sub: subParts.join(' · ') || '剧集播放中', epCode };
    }
    return { main: title, sub: year > 0 ? `${year} 年` : (item.media_type === 'Movie' ? '电影' : ''), epCode };
  }

  function mediaTypeMeta(mediaType) {
    switch (mediaType) {
      case 'Episode': return { label: '剧集', icon: 'tv', cls: 'episode' };
      case 'Movie': return { label: '电影', icon: 'film', cls: 'movie' };
      case 'Audio': return { label: '音频', icon: 'music', cls: 'audio' };
      case 'TvChannel': return { label: '直播', icon: 'radio', cls: 'video' };
      default: return { label: '视频', icon: 'clapperboard', cls: 'video' };
    }
  }

  function playMethodLabel(method) {
    switch (String(method || '').toLowerCase()) {
      case 'directplay': return '直连播放';
      case 'directstream': return '直接串流';
      case 'transcode': return '转码播放';
      default: return '';
    }
  }

  function renderOverviewWatchingStrip(active) {
    const card = document.getElementById('overview-watching-card');
    const strip = document.getElementById('overview-watching-strip');
    const badge = document.getElementById('overview-watching-badge');
    if (!card || !strip) return;
    if (!active.length) {
      card.hidden = true;
      strip.replaceChildren();
      return;
    }
    card.hidden = false;
    if (badge) badge.querySelector('span:last-child').textContent = `${formatNumber(active.length)} 路播放中`;
    const frag = document.createDocumentFragment();
    active.slice(0, 6).forEach((s) => {
      const disp = formatWatchingTitle(s);
      const pill = el('div', 'overview-watch-pill');
      pill.addEventListener('click', () => switchView('watching'));
      const top = el('div', 'overview-watch-top');
      top.append(
        el('span', 'overview-watch-title', disp.epCode ? `${disp.main} · ${disp.epCode}` : disp.main),
        el('span', `badge ${s.paused ? 'badge-amber' : 'badge-emerald'}`, s.paused ? '已暂停' : `${formatBytes(s.download_bps)}/s`)
      );
      const meta = el('div', 'overview-watch-meta');
      const who = s.user_name || s.device_name || s.client_ip;
      meta.append(el('span', '', who));
      if (s.client_name) meta.append(el('span', 'meta-tag accent', s.client_name));
      if (s.video_quality) meta.append(el('span', 'meta-tag', s.video_quality));
      if (s.node_name) meta.append(el('span', 'meta-tag', s.node_name));
      const track = el('div', 'watching-progress-track');
      const fill = el('div', `watching-progress-fill${s.paused ? (s.duration_sec > 0 ? ' is-paused' : ' is-paused is-indeterminate') : (s.duration_sec > 0 ? '' : ' is-live')}`);
      if (s.duration_sec > 0) fill.style.width = `${Math.max(3, Math.min(100, Number(s.progress_pct) || 0))}%`;
      track.append(fill);
      pill.append(top, meta, track);
      frag.append(pill);
    });
    strip.replaceChildren(frag);
    refreshIcons();
  }

  function renderWatching(payload) {
    const active = Array.isArray(payload?.active) ? payload.active : [];
    const history = Array.isArray(payload?.history) ? payload.history : [];
    const summary = payload?.summary || { watching_count: active.length, unique_users: active.length, total_download_bps: 0, history_24h: 0 };
    state.watchingActive = active;
    state.watchingHistory = history;
    state.watchingSummary = summary;
    state.lastWatchingCount = active.length;

    const navBadge = document.getElementById('nav-watch-badge');
    if (navBadge) {
      navBadge.hidden = active.length <= 0;
      navBadge.textContent = String(active.length);
    }
    renderOverviewWatchingStrip(active);

    const kpiActive = document.getElementById('watch-kpi-active');
    if (kpiActive) kpiActive.textContent = formatNumber(summary.watching_count);
    const kpiUsers = document.getElementById('watch-kpi-users');
    if (kpiUsers) kpiUsers.textContent = `${formatNumber(summary.unique_users)} 位观众在线`;
    const kpiBps = document.getElementById('watch-kpi-bps');
    if (kpiBps) kpiBps.textContent = `${formatBytes(summary.total_download_bps)}/s`;
    const kpi24h = document.getElementById('watch-kpi-24h');
    if (kpi24h) kpi24h.textContent = formatNumber(summary.history_24h);

    const q = state.watchingQuery.trim().toLowerCase();
    const matchesQuery = (r) => {
      if (!q) return true;
      return `${r.title || ''} ${r.series_name || ''} ${r.user_name || ''} ${r.client_name || ''} ${r.device_name || ''} ${r.client_ip || ''} ${r.location || ''} ${r.node_name || ''} ${r.upstream_host || ''} ${r.emby_server_name || ''} ${r.video_quality || ''}`.toLowerCase().includes(q);
    };

    // 1. Active Now Playing Cards
    const filteredActive = active.filter(matchesQuery);
    const activeBadge = document.getElementById('watching-active-badge');
    if (activeBadge) activeBadge.querySelector('span:last-child').textContent = `${formatNumber(filteredActive.length)} 路播放中`;
    const grid = document.getElementById('watching-active-grid');
    const activeEmpty = document.getElementById('watching-active-empty');
    if (grid && activeEmpty) {
      if (!filteredActive.length) {
        grid.hidden = true;
        grid.replaceChildren();
        activeEmpty.hidden = false;
      } else {
        grid.hidden = false;
        activeEmpty.hidden = true;
        const frag = document.createDocumentFragment();
        filteredActive.forEach((s) => {
          const card = el('article', 'watching-card');
          const disp = formatWatchingTitle(s);
          const mMeta = mediaTypeMeta(s.media_type);

          const head = el('div', 'watching-card-head');
          const iconBox = el('span', `watching-media-icon ${mMeta.cls}`);
          iconBox.innerHTML = `<i data-lucide="${mMeta.icon}"></i>`;
          const titleBox = el('div', 'watching-card-titlebox');
          const titleRow = el('div', 'watching-card-title-row');
          titleRow.append(
            el('span', 'watching-card-title', disp.main),
            el('span', `badge ${s.paused ? 'badge-amber' : 'badge-emerald'}`, s.paused ? '已暂停' : '播放中')
          );
          titleBox.append(titleRow);
          if (disp.sub) titleBox.append(el('span', 'watching-card-sub', disp.sub));
          const tags = el('div', 'watching-card-tags');
          tags.append(el('span', 'meta-tag', mMeta.label));
          if (s.video_quality) tags.append(el('span', 'meta-tag accent', s.video_quality));
          const pm = playMethodLabel(s.play_method);
          if (pm) tags.append(el('span', 'meta-tag', pm));
          if (s.node_name) tags.append(el('span', 'meta-tag', s.node_name));
          titleBox.append(tags);
          head.append(iconBox, titleBox);
          card.append(head);

          // Progress bar
          const prog = el('div', 'watching-progress-block');
          const labels = el('div', 'watching-progress-labels');
          if (s.duration_sec > 0) {
            labels.append(
              el('span', 'mono', `${formatPlaybackClock(s.position_sec)} / ${formatPlaybackClock(s.duration_sec)}`),
              el('span', 'mono', `${Number(s.progress_pct) || 0}%`)
            );
          } else {
            labels.append(
              el('span', '', s.paused ? '已暂停缓冲' : '实时推流播放中'),
              el('span', '', s.started_at ? `开始于 ${relativeTime(s.started_at)}` : '')
            );
          }
          const track = el('div', 'watching-progress-track');
          const fill = el('div', `watching-progress-fill${s.paused ? (s.duration_sec > 0 ? ' is-paused' : ' is-paused is-indeterminate') : (s.duration_sec > 0 ? '' : ' is-live')}`);
          if (s.duration_sec > 0) fill.style.width = `${Math.max(3, Math.min(100, Number(s.progress_pct) || 0))}%`;
          track.append(fill);
          prog.append(labels, track);
          card.append(prog);

          // Viewer info strip
          const viewer = el('div', 'watching-viewer-row');
          const whoText = [s.user_name, s.device_name].filter(Boolean).join(' · ') || '匿名观众';
          const whoItem = el('span', 'watching-viewer-item');
          whoItem.innerHTML = `<i data-lucide="user"></i><span>${escapeHTML(whoText)}</span>`;
          viewer.append(whoItem);
          if (s.client_name) {
            const pItem = el('span', 'watching-viewer-item');
            pItem.innerHTML = `<i data-lucide="monitor-play"></i><span>${escapeHTML(s.client_name)}</span>`;
            viewer.append(pItem);
          }
          const ipItem = el('span', 'watching-viewer-item');
          const ipDesc = s.location ? `${s.location} · ${s.client_ip}` : s.client_ip;
          ipItem.innerHTML = `<i data-lucide="map-pin"></i><span class="mono">${escapeHTML(ipDesc)}</span>`;
          viewer.append(ipItem);
          const srvItem = el('span', 'watching-viewer-item');
          srvItem.innerHTML = `<i data-lucide="server"></i><span>${escapeHTML(s.emby_server_name || s.upstream_host)}</span>`;
          viewer.append(srvItem);
          card.append(viewer);

          // Footer speed + terminate action
          const foot = el('div', 'watching-card-foot');
          const spd = el('div', 'watching-speed-group');
          spd.append(
            el('span', 'watching-speed-rate', `↓ ${formatBytes(s.download_bps)}/s`),
            el('span', '', `已播 ${formatBytes(s.bytes_out)}`)
          );
          foot.append(spd);
          if (s.session_key || s.flow_id) {
            const stopBtn = el('button', 'btn btn-danger-soft btn-sm');
            stopBtn.type = 'button';
            stopBtn.innerHTML = '<i data-lucide="square"></i><span>断开播放</span>';
            stopBtn.addEventListener('click', () => terminatePlaybackSession(s, stopBtn));
            foot.append(stopBtn);
          } else {
            foot.append(el('span', 'field-hint', `活跃 ${relativeTime(s.last_seen_at)}`));
          }
          card.append(foot);
          frag.append(card);
        });
        grid.replaceChildren(frag);
      }
    }

    // 2. Watch History Table
    const filteredHist = history.filter(matchesQuery);
    const histBadge = document.getElementById('watching-history-count');
    if (histBadge) histBadge.textContent = `${formatNumber(filteredHist.length)} 条记录`;
    const histBody = document.getElementById('watching-history-table');
    const histEmpty = document.getElementById('watching-history-empty');
    if (histBody && histEmpty) {
      if (!filteredHist.length) {
        histBody.replaceChildren();
        histEmpty.hidden = false;
      } else {
        histEmpty.hidden = true;
        const frag = document.createDocumentFragment();
        filteredHist.forEach((h) => {
          const row = document.createElement('tr');
          const disp = formatWatchingTitle(h);
          const mMeta = mediaTypeMeta(h.media_type);

          const mediaCell = el('td');
          const mediaStack = el('div', 'cell-stack');
          const mediaHead = el('div', 'cell-meta-row');
          mediaHead.append(el('span', 'cell-primary', disp.main), el('span', 'meta-tag', mMeta.label));
          mediaStack.append(mediaHead);
          if (disp.sub) mediaStack.append(el('span', 'cell-secondary', disp.sub));
          mediaCell.append(mediaStack);

          const viewerCell = el('td');
          const viewerStack = el('div', 'cell-stack');
          viewerStack.append(
            el('span', 'cell-primary', [h.user_name, h.device_name].filter(Boolean).join(' · ') || h.client_ip),
            el('span', 'cell-secondary mono', h.location ? `${h.location} · ${h.client_ip}` : h.client_ip)
          );
          viewerCell.append(viewerStack);

          const specCell = el('td');
          const specRow = el('div', 'cell-meta-row');
          if (h.client_name) specRow.append(el('span', 'meta-tag accent', h.client_name));
          if (h.video_quality) specRow.append(el('span', 'meta-tag', h.video_quality));
          const pm = playMethodLabel(h.play_method);
          if (pm) specRow.append(el('span', 'meta-tag', pm));
          if (!specRow.childElementCount) specRow.append(el('span', 'cell-secondary', '—'));
          specCell.append(specRow);

          const nodeCell = el('td');
          const nodeStack = el('div', 'cell-stack');
          nodeStack.append(
            el('span', 'cell-primary', h.node_name || '本机节点'),
            el('span', 'cell-secondary mono', h.emby_server_name || h.upstream_host)
          );
          nodeCell.append(nodeStack);

          const statCell = el('td', 'num-col');
          const statStack = el('div', 'cell-stack');
          const progText = h.duration_sec > 0 ? `${formatPlaybackClock(h.position_sec)} / ${formatPlaybackClock(h.duration_sec)} (${h.progress_pct || 0}%)` : '流媒体播放';
          statStack.append(
            el('span', 'cell-primary mono', formatBytes(h.bytes_out)),
            el('span', 'cell-secondary mono', progText)
          );
          statCell.append(statStack);

          const timeCell = el('td', 'num-col cell-secondary mono', relativeTime(h.last_seen_at));
          timeCell.title = formatTime(h.last_seen_at);

          row.append(mediaCell, viewerCell, specCell, nodeCell, statCell, timeCell);
          frag.append(row);
        });
        histBody.replaceChildren(frag);
      }
    }
    refreshIcons();
  }

  async function refreshWatching() {
    const scope = state.nodeScope || '';
    if (state.watchingPromise && state.watchingReqScope === scope) return state.watchingPromise;
    const qs = scope ? `?node_id=${encodeURIComponent(scope)}` : '';
    state.watchingReqScope = scope;
    const req = api(`/_admin/api/playbacks${qs}`).then((payload) => {
      if (scope === (state.nodeScope || '')) renderWatching(payload);
      return payload;
    });
    state.watchingPromise = req;
    try { return await req; } finally {
      if (state.watchingPromise === req) {
        state.watchingPromise = null;
        state.watchingReqScope = '';
      }
    }
  }

  async function terminatePlaybackSession(session, button) {
    const disp = formatWatchingTitle(session);
    const confirmed = await confirmAction({
      title: '断开当前播放流',
      message: `将立即终止 ${session.user_name || session.client_ip} 观看「${disp.main}」（${session.node_name || '当前节点'}）的全部推流连接，并在 60 秒内拦截播放器自动重连。`,
      confirmLabel: '确认断开', icon: 'square', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      await api('/_admin/api/playbacks/terminate', jsonOptions('POST', {
        session_key: session.session_key || '',
        node_id: session.node_id || '',
        flow_id: session.flow_id || ''
      }));
      toast('已强制断开播放（60 秒内拦截自动重连）');
      await Promise.all([refreshWatching(), refreshConnections().catch(() => {})]);
    } catch (failure) {
      button.disabled = false;
      toast(failure.message === 'playback session not found' || failure.message === 'connection not found' ? '播放流已自然结束' : '断开播放失败', 'error');
    }
  }

  /* -------------------- Live Connections -------------------- */

  function renderConnections(payload) {
    state.connectionsData = payload?.connections || [];
    const query = state.connectionsQuery.trim().toLowerCase();
    const list = state.connectionsData.filter((c) => {
      if (!query) return true;
      return `${c.client_ip} ${c.location} ${c.host} ${c.path} ${c.client_name} ${c.category} ${c.node_name || ''}`.toLowerCase().includes(query);
    });
    const badge = document.getElementById('connection-count');
    badge.querySelector('span:last-child').textContent = `${formatNumber(list.length)} 个连接`;
    const body = document.getElementById('connections-table');
    const empty = document.getElementById('connections-empty');
    if (!list.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const f = document.createDocumentFragment();
    list.forEach((c) => {
      const row = document.createElement('tr');
      const client = el('td');
      const clientStack = el('div', 'cell-stack');
      const clientHead = el('div', 'cell-meta-row');
      clientHead.append(el('span', 'cell-primary mono', c.client_ip));
      if (c.node_name && (state.nodesData.length > 0 || (c.node_id && c.node_id !== 'local'))) {
        clientHead.append(el('span', 'meta-tag', c.node_name));
      }
      clientStack.append(clientHead, el('span', 'cell-secondary', c.location || c.user_agent || '位置查询中'));
      client.append(clientStack);

      const target = el('td');
      const targetStack = el('div', 'cell-stack');
      if (c.media_title) {
        const mediaHead = el('div', 'cell-meta-row');
        mediaHead.append(el('span', 'cell-primary', c.host), el('span', 'meta-tag accent', c.media_subtitle ? `${c.media_title} · ${c.media_subtitle}` : c.media_title));
        targetStack.append(mediaHead);
      } else {
        targetStack.append(el('span', 'cell-primary', c.host));
      }
      targetStack.append(el('span', 'cell-secondary mono', `${c.method} ${c.path}`));
      target.append(targetStack);

      const playerCell = el('td');
      const playerRow = el('div', 'cell-meta-row');
      if (c.client_name) playerRow.append(el('span', 'meta-tag accent', c.client_name));
      if (c.category) playerRow.append(el('span', 'meta-tag', c.category));
      if (!playerRow.childElementCount) playerRow.append(el('span', 'cell-secondary', '—'));
      playerCell.append(playerRow);

      const actions = el('td', 'actions-col');
      const group = el('div', 'row-actions');
      const domAct = domainActionButton(c.domain);
      if (domAct) group.append(domAct);
      const term = el('button', 'icon-btn danger');
      term.type = 'button'; term.title = '断开连接';
      term.setAttribute('aria-label', `断开 ${c.client_ip} 到 ${c.host} 的连接`);
      term.innerHTML = '<i data-lucide="square"></i>';
      term.addEventListener('click', () => terminateConnection(c, term));
      group.append(term);
      actions.append(group);

      [client, target, playerCell,
        el('td', 'num-col mono', `${formatBytes(c.upload_bps)}/s`),
        el('td', 'num-col mono', `${formatBytes(c.download_bps)}/s`),
        el('td', 'num-col mono', `${formatBytes(c.upload_total)} / ${formatBytes(c.download_total)}`),
        el('td', 'num-col', formatDuration(c.duration_ms)),
        actions].forEach((cell) => row.append(cell));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  async function refreshConnections() {
    const qs = state.nodeScope ? `?node_id=${encodeURIComponent(state.nodeScope)}` : '';
    renderConnections(await api(`/_admin/api/connections${qs}`));
  }

  async function terminateConnection(connection, button) {
    const nodeLabel = connection.node_name ? `（${connection.node_name}）` : '';
    const confirmed = await confirmAction({
      title: '断开当前连接',
      message: `${connection.client_ip} 到 ${connection.host}${nodeLabel} 的传输将立即终止。`,
      confirmLabel: '确认断开', icon: 'square', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      const nodeQS = connection.node_id ? `?node_id=${encodeURIComponent(connection.node_id)}` : '';
      await api(`/_admin/api/connections/${encodeURIComponent(connection.id)}${nodeQS}`, { method: 'DELETE' });
      toast('连接已断开');
      await refreshConnections();
    } catch (failure) {
      button.disabled = false;
      toast(failure.message === 'connection not found' ? '连接已自然结束' : '断开连接失败', 'error');
    }
  }

  /* -------------------- Request Logs & Detail Drawer -------------------- */

  function updateRequestClearButton() {
    const clearBtn = document.getElementById('request-filter-clear');
    if (clearBtn) clearBtn.hidden = !(state.requestStatus || state.requestHost || state.requestClientIP);
  }

  function jumpToClientIPLogs(ip) {
    const clean = String(ip || '').trim();
    if (!clean) return;
    state.requestClientIP = clean;
    const ipInput = document.getElementById('request-ip-filter');
    if (ipInput) ipInput.value = clean;
    if (state.view === 'requests') {
      refreshRequests(1).catch(() => toast('来源 IP 筛选失败', 'error'));
    } else {
      switchView('requests');
    }
  }

  function openRequestDetailDrawer(log) {
    const body = document.getElementById('request-drawer-body');
    const footer = document.getElementById('request-drawer-footer');
    const displayName = String(log.emby_server_name || '').trim() || log.host;
    document.getElementById('request-drawer-title').textContent = displayName;
    document.getElementById('request-drawer-subtitle').textContent = `${log.method} · HTTP ${log.status} · ${formatTime(log.timestamp)}`;

    const list = el('dl', 'detail-kv-list');
    const entries = [
      ['时间', formatTime(log.timestamp)],
      ['来源 IP', log.client_ip || '—'],
      ...(log.location ? [['归属地', log.location]] : []),
      ['边缘节点', log.node_name || (log.node_id === 'local' || !log.node_id ? '本机节点' : log.node_id)],
      ['请求方法', log.method],
      ['响应状态', `HTTP ${log.status}`],
      ['响应耗时', `${log.duration_ms} ms`],
      ['目标主机', `${log.scheme ? `${log.scheme}://` : ''}${log.host}`],
      ['脱敏路径', log.path || '/'],
      ['流分类', log.category || '—'],
      ['上传 / 下行', `${formatBytes(log.bytes_in)} / ${formatBytes(log.bytes_out)}`],
      ...(state.role !== 'controller' || log.emby_group_name || log.emby_line_name || log.emby_note ? [
        ['Emby 分组', log.emby_group_name || '—'],
        ['Emby 线路', log.emby_line_name || '—'],
        ['Emby 备注', log.emby_note || '—']
      ] : []),
      ['播放器名称', log.client_name || '未识别'],
      ['设备名称', log.device_name || '—'],
      ['设备 ID', log.device_id || '—']
    ];
    entries.forEach(([k, v]) => {
      const row = el('div', 'detail-kv');
      row.append(el('dt', '', k), el('dd', ['来源 IP', '目标主机', '脱敏路径', '设备 ID', '响应耗时', '上传 / 下行'].includes(k) ? 'mono' : '', String(v)));
      list.append(row);
    });
    body.replaceChildren(list);

    footer.replaceChildren();
    if (log.client_ip && log.client_ip !== 'unknown') {
      const filterIPBtn = el('button', 'btn btn-secondary btn-sm');
      filterIPBtn.type = 'button';
      filterIPBtn.innerHTML = '<i data-lucide="map-pin"></i><span>筛选此 IP 日志</span>';
      filterIPBtn.addEventListener('click', () => {
        closeDrawer('request-drawer');
        jumpToClientIPLogs(log.client_ip);
      });
      footer.append(filterIPBtn);
    }
    const filterHostBtn = el('button', 'btn btn-secondary btn-sm');
    filterHostBtn.type = 'button';
    filterHostBtn.innerHTML = '<i data-lucide="filter"></i><span>筛选此主机日志</span>';
    filterHostBtn.addEventListener('click', () => {
      closeDrawer('request-drawer');
      jumpToHostLogs(log.host);
    });
    footer.append(filterHostBtn);
    const drawerPlayerAct = requestPlayerAction(log);
    if (drawerPlayerAct) footer.append(drawerPlayerAct);
    openDrawer('request-drawer');
  }

  function renderRequestFilters(statuses) {
    const container = document.getElementById('request-status-filters');
    const items = Array.isArray(statuses) ? statuses : [];
    const allCount = items.reduce((t, i) => t + (Number(i.count) || 0), 0);
    const options = [{ status: '', label: '全部', count: allCount }, ...items.map((i) => ({
      status: String(i.status), label: String(i.status), count: Number(i.count) || 0
    }))];
    if (state.requestStatus && !options.some((o) => o.status === state.requestStatus)) {
      options.push({ status: state.requestStatus, label: state.requestStatus, count: 0 });
    }
    const f = document.createDocumentFragment();
    options.forEach((o) => {
      const active = o.status === state.requestStatus;
      const btn = el('button', active ? 'active' : '');
      btn.type = 'button';
      btn.dataset.requestStatus = o.status;
      btn.setAttribute('aria-pressed', String(active));
      btn.disabled = state.requestLoading;
      btn.append(el('span', '', o.label), el('small', '', formatNumber(o.count)));
      f.append(btn);
    });
    const indicator = container.querySelector('.segmented-indicator') || el('span', 'segmented-indicator');
    indicator.setAttribute('aria-hidden', 'true');
    container.replaceChildren(indicator, f);
    syncSegmented(container);
  }

  function setRequestLoading(loading) {
    state.requestLoading = loading;
    document.getElementById('view-requests').setAttribute('aria-busy', String(loading));
    document.querySelectorAll('#request-status-filters button').forEach((b) => { b.disabled = loading; });
    document.getElementById('request-page-previous').disabled = loading || state.requestPage <= 1;
    document.getElementById('request-page-next').disabled = loading || state.requestPage >= state.requestTotalPages;
  }

  function renderRequests(payload) {
    const logs = payload?.logs || [];
    const dropped = Number(payload?.dropped) || 0;
    const body = document.getElementById('requests-table');
    const empty = document.getElementById('requests-empty');
    state.requestPage = Number(payload?.page) || 1;
    state.requestPageSize = Number(payload?.page_size) || 20;
    state.requestTotalPages = Math.max(1, Number(payload?.total_pages) || 1);
    renderRequestFilters(payload?.statuses);
    updateRequestClearButton();
    document.getElementById('request-total-label').textContent = `共 ${formatNumber(payload?.total)} 条`;
    document.getElementById('dropped-label').textContent = dropped ? `${formatNumber(dropped)} 条丢弃` : '无丢弃';
    document.getElementById('request-page-label').textContent = `第 ${formatNumber(state.requestPage)} / ${formatNumber(state.requestTotalPages)} 页 · 每页 ${formatNumber(state.requestPageSize)} 条`;
    document.getElementById('request-page-previous').disabled = state.requestPage <= 1;
    document.getElementById('request-page-next').disabled = state.requestPage >= state.requestTotalPages;
    if (!logs.length) {
      body.replaceChildren();
      document.getElementById('requests-empty-title').textContent = state.requestStatus || state.requestHost || state.requestClientIP ? '当前筛选条件下暂无请求记录' : '暂无请求记录';
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    const f = document.createDocumentFragment();
    logs.forEach((log) => {
      const row = document.createElement('tr');
      row.className = 'clickable';
      row.addEventListener('click', () => openRequestDetailDrawer(log));

      const ipCell = el('td', 'nowrap');
      const ipStack = el('div', 'cell-stack');
      ipStack.append(el('span', 'cell-primary mono', log.client_ip || '—'));
      if (log.location) ipStack.append(el('span', 'cell-secondary', log.location));
      ipCell.append(ipStack);

      const target = el('td');
      const stack = el('div', 'cell-stack');
      const displayName = String(log.emby_server_name || '').trim() || log.host;
      const metaRow = el('div', 'cell-meta-row');
      metaRow.append(el('span', 'cell-primary', displayName));
      if (displayName !== log.host) metaRow.append(el('span', 'cell-secondary mono', log.host));
      if (log.node_name && (state.nodesData.length > 0 || (log.node_id && log.node_id !== 'local'))) {
        metaRow.append(el('span', 'meta-tag', log.node_name));
      }
      if (log.emby_line_name) metaRow.append(el('span', 'meta-tag accent', log.emby_line_name));
      if (log.emby_note) metaRow.append(el('span', 'meta-tag', log.emby_note));
      stack.append(metaRow, el('span', 'cell-secondary mono', log.path));
      const devLabel = requestDeviceLabel(log);
      if (devLabel) stack.append(el('span', 'cell-secondary', `设备：${devLabel}`));
      target.append(stack);

      const statusCell = el('td');
      statusCell.append(el('span', `badge mono ${log.status >= 400 ? 'badge-rose' : log.status >= 300 ? 'badge-amber' : 'badge-emerald'}`, String(log.status)));

      const actions = el('td', 'actions-col');
      const actRow = el('div', 'row-actions');
      const rowPlayerAct = requestPlayerAction(log);
      if (rowPlayerAct) actRow.append(rowPlayerAct);
      const inspect = el('button', 'icon-btn');
      inspect.type = 'button'; inspect.title = '查看详情'; inspect.setAttribute('aria-label', '查看详情');
      inspect.innerHTML = '<i data-lucide="panel-right-open"></i>';
      inspect.addEventListener('click', (e) => { e.stopPropagation(); openRequestDetailDrawer(log); });
      actRow.append(inspect);
      actions.append(actRow);

      [el('td', 'mono cell-secondary', formatTime(log.timestamp)),
        ipCell,
        el('td', 'mono cell-primary', log.method),
        target,
        el('td', '', log.category || '—'),
        statusCell,
        el('td', 'num-col mono', formatBytes(log.bytes_out)),
        el('td', 'num-col mono', `${log.duration_ms} ms`),
        actions].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  async function refreshRequests(page = state.requestPage) {
    const seq = ++state.requestsReqSeq;
    state.requestPage = Math.max(1, Number(page) || 1);
    setRequestLoading(true);
    const params = new URLSearchParams({
      page: String(state.requestPage),
      page_size: String(state.requestPageSize)
    });
    if (state.requestStatus) params.set('status', state.requestStatus);
    if (state.requestHost.trim()) params.set('host', state.requestHost.trim());
    if (state.requestClientIP.trim()) params.set('client_ip', state.requestClientIP.trim());
    if (state.nodeScope) params.set('node_id', state.nodeScope);
    try {
      const payload = await api(`/_admin/api/requests?${params}`);
      if (seq === state.requestsReqSeq) renderRequests(payload);
      return payload;
    } finally {
      if (seq === state.requestsReqSeq) setRequestLoading(false);
    }
  }

  /* -------------------- Edge Nodes Cluster -------------------- */

  async function copyPlainText(text, successMsg = '已复制到剪贴板') {
    const value = String(text || '');
    if (!value) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const host = document.querySelector('dialog[open]') || document.body;
        const input = document.createElement('textarea');
        input.value = value;
        input.className = 'sr-only';
        input.setAttribute('readonly', '');
        host.append(input);
        input.focus({ preventScroll: true });
        input.select();
        const copied = document.execCommand('copy');
        input.remove();
        if (!copied) throw new Error('execCommand copy failed');
      }
      toast(successMsg);
    } catch {
      toast('复制失败，请手动选中复制', 'error');
    }
  }

  function applyControllerRoleUI() {
    const isController = state.role === 'controller';
    document.body.classList.toggle('mode-controller', isController);
    const tabLabel = document.getElementById('settings-runtime-tab-label');
    const cardTitle = document.getElementById('runtime-card-title');
    const cardSub = document.getElementById('runtime-card-subtitle');
    if (isController) {
      if (tabLabel) tabLabel.textContent = '集群默认';
      if (cardTitle) cardTitle.textContent = '集群默认配置模板';
      if (cardSub) cardSub.textContent = '修改功能开关与核心代理参数后自动热同步至全部继承全局的边缘节点，不中断现有连接';
      settingsMeta['settings-runtime'] = ['集群默认模板', '全局热开关、默认限速并发与节点通用参数', 'server-cog'];
    } else {
      if (tabLabel) tabLabel.textContent = '运行配置';
      if (cardTitle) cardTitle.textContent = '运行配置';
      if (cardSub) cardSub.textContent = '修改功能开关与核心代理参数后支持热重载实时生效，不中断现有连接；保存前自动校验并备份上一份可用配置';
      settingsMeta['settings-runtime'] = ['运行配置', '上游路由、代理行为、超时、并发与限速参数', 'server-cog'];
    }
    const portalToggle = document.getElementById('runtime-public-portal');
    if (portalToggle) portalToggle.checked = Boolean(state.publicPortalEnabled);
    updateRoleBadge();
    syncNodeScopeSelect();
    renderDomainFlowStrip();
    setupNavIndicator();
  }

  async function togglePublicPortal(input) {
    const nextValue = Boolean(input.checked);
    const row = input.closest('.toggle-row');
    input.disabled = true;
    if (row) row.classList.add('is-saving');
    try {
      const saved = await api('/_admin/api/portal', jsonOptions('PUT', { public_portal_enabled: nextValue }));
      state.publicPortalEnabled = Boolean(saved.public_portal_enabled);
      input.checked = state.publicPortalEnabled;
      if (row) {
        row.classList.remove('is-saving');
        row.classList.add('is-applied');
        window.setTimeout(() => row.classList.remove('is-applied'), 680);
      }
      toast(state.publicPortalEnabled ? '已对外开放公开选线门户（/）' : '已关闭公开门户，访问首页将跳转登录页');
    } catch {
      input.checked = Boolean(state.publicPortalEnabled);
      toast('公开门户开关切换失败', 'error');
    } finally {
      input.disabled = false;
      if (row) row.classList.remove('is-saving');
    }
  }

  function updateRoleBadge() {
    const badge = document.getElementById('gateway-role-badge');
    const summary = state.nodesSummary;
    const isController = state.role === 'controller';
    if (!badge) return;
    const label = badge.querySelector('span:last-child');
    if (!label) return;
    if (isController) {
      label.textContent = summary && summary.total > 0 ? `主控在线 · ${summary.online}/${summary.total} 节点` : '主控模式';
    } else if (summary && summary.total > 0) {
      label.textContent = `网关在线 · ${summary.online}/${summary.total} 节点`;
    } else {
      label.textContent = '网关在线';
    }
  }

  function syncNodeScopeSelect() {
    const select = document.getElementById('node-scope-select');
    if (!select) return;
    const supportsScope = ['overview', 'watching', 'connections', 'requests'].includes(state.view);
    const hasNodes = state.nodesData.length > 0;
    select.hidden = !(supportsScope && hasNodes);
    if (!hasNodes) {
      state.nodeScope = '';
      return;
    }
    const previous = state.nodeScope;
    const frag = document.createDocumentFragment();
    const allOpt = document.createElement('option');
    allOpt.value = '';
    allOpt.textContent = '全部节点（集群汇总）';
    frag.append(allOpt);
    if (state.role !== 'controller') {
      const localOpt = document.createElement('option');
      localOpt.value = 'local';
      localOpt.textContent = '本机节点';
      frag.append(localOpt);
    }
    state.nodesData.forEach((n) => {
      const opt = document.createElement('option');
      opt.value = n.id;
      const statusText = n.status === 'online' ? '在线' : n.status === 'draining' ? '维护' : n.status === 'pending' ? '待接入' : '离线';
      opt.textContent = `${n.name} (${statusText})`;
      frag.append(opt);
    });
    select.replaceChildren(frag);
    const valid = previous === '' || (previous === 'local' && state.role !== 'controller') || state.nodesData.some((n) => n.id === previous);
    state.nodeScope = valid ? previous : '';
    select.value = state.nodeScope;
  }

  function countNodeOverrides(overrides) {
    if (!overrides || typeof overrides !== 'object') return 0;
    return Object.keys(overrides).filter((k) => overrides[k] !== null && overrides[k] !== undefined && overrides[k] !== '').length;
  }

  function renderNodes(payload) {
    if (payload?.role) state.role = payload.role;
    const nodes = Array.isArray(payload?.nodes) ? payload.nodes : [];
    const summary = payload?.summary || { total: nodes.length, online: 0, offline: 0, pending: 0, draining: 0, synced: 0, total_upload_bps: 0, total_download_bps: 0, active_requests: 0 };
    state.nodesData = nodes;
    state.nodesSummary = summary;
    geoGlobe.syncNodes();

    const navBadge = document.getElementById('nav-nodes-badge');
    if (navBadge) {
      navBadge.textContent = String(summary.online);
      navBadge.hidden = summary.total === 0;
    }
    updateRoleBadge();
    syncNodeScopeSelect();
    renderDomainFlowStrip();

    document.getElementById('nodes-kpi-online').textContent = `${formatNumber(summary.online)} / ${formatNumber(summary.total)}`;
    const offlineTotal = (Number(summary.offline) || 0) + (Number(summary.pending) || 0);
    document.getElementById('nodes-kpi-sub').textContent = summary.total === 0
      ? '等待边缘节点接入'
      : `离线 ${offlineTotal}${summary.draining ? ` · 维护 ${summary.draining}` : ''}`;
    const clusterDownBPS = summary.has_nic_metrics ? Number(summary.total_nic_rx_bps) || 0 : Number(summary.total_download_bps) || 0;
    const clusterUpBPS = summary.has_nic_metrics ? Number(summary.total_nic_tx_bps) || 0 : Number(summary.total_upload_bps) || 0;
    document.getElementById('nodes-kpi-down').textContent = `${formatBytes(clusterDownBPS)}/s`;
    document.getElementById('nodes-kpi-up').textContent = `上传 ${formatBytes(clusterUpBPS)}/s`;
    document.getElementById('nodes-kpi-active').textContent = formatNumber(summary.active_requests);

    const q = state.nodesQuery.trim().toLowerCase();
    const filtered = nodes.filter((n) => {
      if (state.nodesFilter === 'online' && !['online', 'draining'].includes(n.status)) return false;
      if (state.nodesFilter === 'offline' && !['offline', 'pending'].includes(n.status)) return false;
      if (!q) return true;
      const doms = Array.isArray(n.assigned_domains) ? n.assigned_domains.join(' ') : '';
      return `${n.name} ${n.group_name} ${n.region} ${n.effective_ipv4} ${n.effective_ipv6} ${doms} ${n.hostname} ${n.id}`.toLowerCase().includes(q);
    });

    const body = document.getElementById('nodes-table');
    const empty = document.getElementById('nodes-empty');
    if (!filtered.length) {
      body.replaceChildren();
      empty.hidden = false;
      return;
    }
    empty.hidden = true;

    const statusMeta = {
      online: ['badge-emerald', '在线', true],
      draining: ['badge-amber', '维护排空', false],
      pending: ['badge-rose', '离线', false],
      offline: ['badge-rose', '离线', false]
    };
    const f = document.createDocumentFragment();
    filtered.forEach((n) => {
      const row = document.createElement('tr');
      const metrics = n.metrics || {};

      // 1. Node Identity, IP & Assigned Domains (clean 2 lines)
      const identityCell = el('td');
      const idStack = el('div', 'cell-stack');
      const headRow = el('div', 'cell-meta-row');
      headRow.append(el('span', 'cell-primary', n.name));
      const locText = [n.group_name, n.region].filter(Boolean).join(' · ');
      if (locText) headRow.append(el('span', 'node-sub-inline', locText));
      idStack.append(headRow);

      const secondRow = el('div', 'node-ip-row');
      const primaryIP = n.effective_ipv4 || n.effective_ipv6;
      if (primaryIP) {
        const ipBtn = el('button', 'node-url-copy');
        ipBtn.type = 'button';
        ipBtn.title = `点击复制公网 IP${n.effective_ipv4 && n.effective_ipv6 ? ` (IPv6: ${n.effective_ipv6})` : ''}`;
        ipBtn.innerHTML = `<i data-lucide="copy"></i><span>${escapeHTML(primaryIP)}</span>`;
        ipBtn.addEventListener('click', () => copyPlainText(primaryIP, `已复制 ${n.name} IP：${primaryIP}`));
        secondRow.append(ipBtn);
      }
      const assigned = Array.isArray(n.assigned_domains) ? n.assigned_domains : [];
      if (assigned.length) {
        assigned.slice(0, 2).forEach((d) => secondRow.append(el('span', 'meta-tag accent', d)));
        if (assigned.length > 2) {
          const more = el('span', 'meta-tag', `+${assigned.length - 2}`);
          more.title = assigned.join(', ');
          secondRow.append(more);
        }
      } else {
        secondRow.append(el('span', 'cell-secondary', '未绑域名'));
      }
      idStack.append(secondRow);
      identityCell.append(idStack);

      // 2. Status + compact version / abnormal indicator only
      const statusCell = el('td');
      const statusStack = el('div', 'cell-stack');
      const statusTop = el('div', 'cell-meta-row');
      const [cls, label, pulse] = statusMeta[n.status] || ['', n.status, false];
      const stBadge = el('span', `badge ${cls}`);
      if (pulse) {
        const dot = el('span', 'status-dot pulse');
        dot.setAttribute('aria-hidden', 'true');
        stBadge.append(dot);
      }
      stBadge.append(document.createTextNode(label));
      const techTip = [
        n.connected ? 'SSE 已连接' : '心跳保活',
        n.last_seen_at ? `上报于 ${relativeTime(n.last_seen_at)}` : '',
        n.arch || '',
        n.hostname || ''
      ].filter(Boolean).join(' · ');
      if (techTip) stBadge.title = techTip;
      statusTop.append(stBadge);
      if (n.status === 'online' && !n.synced) {
        statusTop.append(el('span', 'badge badge-amber', '同步中'));
      }
      if (n.upgrade_available) {
        statusTop.append(el('span', 'badge badge-amber', '可升级'));
      }

      let subText = n.agent_version ? `v${String(n.agent_version).replace(/^v/, '')}` : '—';
      if (n.status === 'pending') {
        subText = n.enroll_expires_at ? `未接入 · Token 截止 ${formatTime(n.enroll_expires_at)}` : '未接入';
      } else if (n.status === 'offline' && n.last_seen_at) {
        subText = `离线 · ${relativeTime(n.last_seen_at)}`;
      }
      const subEl = el('span', 'cell-secondary mono node-status-sub', subText);
      if (techTip) subEl.title = techTip;
      statusStack.append(statusTop, subEl);
      statusCell.append(statusStack);

      // 3. Monthly Quota
      const quotaCell = el('td', 'node-quota-cell');
      if (Array.isArray(n.nic_interfaces) && n.nic_interfaces.length) {
        const dirLabel = n.quota_direction === 'both' ? '双向（上传+下载）' : '仅出站（上传）';
        quotaCell.title = `主网卡：${n.nic_interfaces.join(', ')} · ${dirLabel}`;
      }
      const quotaStack = el('div', 'cell-stack');
      const quotaGB = Number(n.monthly_quota_gb) || 0;
      const usedBytes = Number(n.monthly_used_bytes) || 0;
      if (quotaGB > 0) {
        const pct = Math.max(0, Number(n.monthly_usage_pct) || 0);
        const pctLabel = `${Math.min(999, pct).toFixed(pct >= 10 ? 0 : 1)}%`;
        const quotaHead = el('div', 'cell-meta-row');
        quotaHead.append(
          el('span', 'cell-primary mono', `${formatBytes(usedBytes)} / ${quotaGB} GB`),
          el('span', `meta-tag ${pct >= 100 ? 'rose' : pct >= 80 ? 'amber' : ''}`, pctLabel)
        );
        const track = el('div', 'node-quota-track');
        const fill = el('div', `node-quota-fill${pct >= 100 ? ' danger' : pct >= 80 ? ' warn' : ''}`);
        fill.style.width = `${Math.min(100, pct).toFixed(1)}%`;
        track.append(fill);
        const resetText = `每月 ${n.quota_reset_day || 1} 日重置${n.quota_auto_drained ? ' · 已停流' : ''}`;
        quotaStack.append(quotaHead, track, el('span', 'cell-secondary', resetText));
      } else {
        quotaStack.append(
          el('span', 'cell-primary mono', formatBytes(usedBytes)),
          el('span', 'cell-secondary', '不限额')
        );
      }
      quotaCell.append(quotaStack);

      // 4. Live Throughput + Active Connections (merged)
      const rateCell = el('td', 'num-col mono');
      const nic = metrics.nic_traffic;
      const hasNIC = Boolean(nic && Array.isArray(nic.interfaces) && nic.interfaces.length);
      const downBPS = hasNIC ? Number(nic.rx_bps) || 0 : Number(metrics.download_bps) || 0;
      const upBPS = hasNIC ? Number(nic.tx_bps) || 0 : Number(metrics.upload_bps) || 0;
      if (hasNIC) {
        rateCell.title = `主网卡 (${nic.interfaces.join(', ')}) 实时速率 · 下载 ↓ ${formatBytes(downBPS)}/s · 上传 ↑ ${formatBytes(upBPS)}/s`;
      }
      const rateStack = el('div', 'cell-stack');
      rateStack.append(
        el('span', 'cell-primary nowrap', `↓ ${formatBytes(downBPS)}/s · ↑ ${formatBytes(upBPS)}/s`),
        el('span', 'cell-secondary', `${formatNumber(metrics.active_requests || 0)} 活跃连接`)
      );
      rateCell.append(rateStack);

      // 5. Actions
      const actions = el('td', 'actions-col');
      const group = el('div', 'row-actions');
      const editBtn = el('button', 'icon-btn');
      editBtn.type = 'button'; editBtn.title = '配置节点'; editBtn.setAttribute('aria-label', '配置节点');
      editBtn.innerHTML = '<i data-lucide="sliders-horizontal"></i>';
      editBtn.addEventListener('click', () => openNodeDrawerForEdit(n));

      const upgradeBtn = el('button', 'icon-btn');
      upgradeBtn.type = 'button';
      upgradeBtn.disabled = !['online', 'draining'].includes(n.status);
      upgradeBtn.title = n.upgrade_available ? '远程升级 Agent 至主控最新二进制' : '向在线节点推送远程升级校验';
      upgradeBtn.setAttribute('aria-label', upgradeBtn.title);
      upgradeBtn.innerHTML = '<i data-lucide="circle-arrow-up"></i>';
      upgradeBtn.addEventListener('click', () => upgradeSingleNode(n, upgradeBtn));

      const deployBtn = el('button', 'icon-btn');
      deployBtn.type = 'button'; deployBtn.title = '生成一键部署命令 / 轮换 Token'; deployBtn.setAttribute('aria-label', deployBtn.title);
      deployBtn.innerHTML = '<i data-lucide="terminal"></i>';
      deployBtn.addEventListener('click', () => rotateNodeToken(n, deployBtn));

      const drainBtn = el('button', `icon-btn${n.draining ? ' danger' : ''}`);
      drainBtn.type = 'button'; drainBtn.title = n.draining ? '恢复接流' : '进入维护排空模式'; drainBtn.setAttribute('aria-label', drainBtn.title);
      drainBtn.innerHTML = `<i data-lucide="${n.draining ? 'play' : 'pause'}"></i>`;
      drainBtn.addEventListener('click', () => toggleNodeDrain(n, drainBtn));

      const delBtn = el('button', 'icon-btn danger');
      delBtn.type = 'button'; delBtn.title = '删除节点'; delBtn.setAttribute('aria-label', '删除节点');
      delBtn.innerHTML = '<i data-lucide="trash-2"></i>';
      delBtn.addEventListener('click', () => deleteEdgeNode(n, delBtn));

      group.append(editBtn, upgradeBtn, deployBtn, drainBtn, delBtn);
      actions.append(group);

      [identityCell, statusCell, quotaCell, rateCell, actions].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  async function refreshNodes() {
    if (state.nodesPromise) return state.nodesPromise;
    const req = api('/_admin/api/nodes').then((payload) => {
      renderNodes(payload);
      return payload;
    });
    state.nodesPromise = req;
    try { return await req; } finally {
      if (state.nodesPromise === req) state.nodesPromise = null;
    }
  }

  function triStateValue(val) {
    if (val === true) return 'true';
    if (val === false) return 'false';
    return 'inherit';
  }

  function parseTriState(val) {
    if (val === 'true') return true;
    if (val === 'false') return false;
    return undefined;
  }

  function openNodeDrawerForCreate() {
    state.nodeEditingID = null;
    document.getElementById('node-drawer-title').textContent = '手动添加边缘节点';
    document.getElementById('node-drawer-subtitle').textContent = '无需填写域名；创建后生成单节点接入命令，上线后在「域名入口」按需绑定';
    document.getElementById('node-form-submit').innerHTML = '<i data-lucide="plus"></i><span>创建并生成部署命令</span>';
    document.getElementById('node-name').value = '';
    document.getElementById('node-group').value = '';
    document.getElementById('node-region').value = '';
    document.getElementById('node-draining').checked = false;
    document.getElementById('node-ov-ip-mode').value = '';
    document.getElementById('node-quota-gb').value = '';
    document.getElementById('node-quota-reset-day').value = '1';
    document.getElementById('node-quota-direction').value = 'out';
    document.getElementById('node-quota-auto-drain').checked = true;
    document.getElementById('node-manual-ipv4').value = '';
    document.getElementById('node-manual-ipv6').value = '';
    const netFold = document.getElementById('node-network-fold');
    if (netFold) netFold.open = false;
    document.getElementById('node-form-error').hidden = true;
    openDrawer('node-drawer');
    window.setTimeout(() => document.getElementById('node-name').focus(), 40);
  }

  function openNodeDrawerForEdit(node) {
    state.nodeEditingID = node.id;
    const ov = node.overrides || {};
    document.getElementById('node-drawer-title').textContent = `配置节点 · ${node.name}`;
    document.getElementById('node-drawer-subtitle').textContent = '修改后实时热下发至该边缘机器，域名与限速请在「域名入口」管理';
    document.getElementById('node-form-submit').innerHTML = '<i data-lucide="zap"></i><span>保存并热下发</span>';
    document.getElementById('node-name').value = node.name || '';
    document.getElementById('node-group').value = node.group_name || '';
    document.getElementById('node-region').value = node.region || '';
    document.getElementById('node-draining').checked = Boolean(node.draining);
    document.getElementById('node-ov-ip-mode').value = ov.upstream_ip_mode || '';
    document.getElementById('node-quota-gb').value = Number(node.monthly_quota_gb) > 0 ? String(node.monthly_quota_gb) : '';
    document.getElementById('node-quota-reset-day').value = String(node.quota_reset_day || 1);
    document.getElementById('node-quota-direction').value = node.quota_direction || 'out';
    document.getElementById('node-quota-auto-drain').checked = node.quota_auto_drain !== false;
    document.getElementById('node-manual-ipv4').value = node.manual_ipv4 || '';
    document.getElementById('node-manual-ipv6').value = node.manual_ipv6 || '';
    const netFold = document.getElementById('node-network-fold');
    if (netFold) netFold.open = Boolean(node.manual_ipv4 || node.manual_ipv6 || ov.upstream_ip_mode);
    document.getElementById('node-form-error').hidden = true;
    openDrawer('node-drawer');
  }

  function buildNodePayloadFromForm() {
    const existing = state.nodeEditingID ? (state.nodesData || []).find((n) => n.id === state.nodeEditingID) : null;
    const overrides = existing && existing.overrides && typeof existing.overrides === 'object' ? { ...existing.overrides } : {};
    const ipModeRaw = document.getElementById('node-ov-ip-mode').value.trim();
    if (ipModeRaw !== '') overrides.upstream_ip_mode = ipModeRaw;
    else delete overrides.upstream_ip_mode;

    const quotaRaw = document.getElementById('node-quota-gb').value.trim();
    const resetDayRaw = Number(document.getElementById('node-quota-reset-day').value) || 1;
    return {
      name: document.getElementById('node-name').value.trim(),
      group_name: document.getElementById('node-group').value.trim(),
      region: document.getElementById('node-region').value.trim(),
      public_url: existing?.public_url || '',
      public_visible: existing ? existing.public_visible !== false : true,
      draining: document.getElementById('node-draining').checked,
      overrides,
      monthly_quota_gb: quotaRaw === '' ? 0 : Number(quotaRaw),
      quota_reset_day: Math.max(1, Math.min(28, Math.round(resetDayRaw))),
      quota_direction: document.getElementById('node-quota-direction').value || 'out',
      quota_auto_drain: document.getElementById('node-quota-auto-drain').checked,
      dns_sync_enabled: existing ? Boolean(existing.dns_sync_enabled) : false,
      dns_ip_mode: existing?.dns_ip_mode || 'auto',
      manual_ipv4: document.getElementById('node-manual-ipv4').value.trim(),
      manual_ipv6: document.getElementById('node-manual-ipv6').value.trim()
    };
  }

  async function saveEdgeNode(e) {
    e.preventDefault();
    const form = e.currentTarget;
    const errEl = document.getElementById('node-form-error');
    errEl.hidden = true;
    if (!form.reportValidity()) return;
    const payload = buildNodePayloadFromForm();
    const submit = document.getElementById('node-form-submit');
    submit.disabled = true;
    try {
      if (state.nodeEditingID) {
        await api(`/_admin/api/nodes/${encodeURIComponent(state.nodeEditingID)}`, jsonOptions('PUT', payload));
        closeDrawer('node-drawer');
        await refreshNodes();
        toast(`节点「${payload.name}」配置已热下发`);
      } else {
        const created = await api('/_admin/api/nodes', jsonOptions('POST', payload));
        closeDrawer('node-drawer');
        await refreshNodes();
        toast(`节点「${payload.name}」已创建`);
        if (created?.deploy) openNodeDeployDialog(created.node, created.deploy);
      }
    } catch (failure) {
      errEl.textContent = failure.message || '节点保存失败，请检查入口地址与覆写参数';
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  function renderDeployTab(tab) {
    state.nodeDeployTab = tab;
    const deploy = state.nodeDeploy;
    if (!deploy) return;
    document.querySelectorAll('#deploy-tabs button').forEach((btn) => {
      const active = btn.dataset.deployTab === tab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    const map = {
      oneclick: deploy.one_click_auto_tls || deploy.systemd_command,
      'oneclick-proxy': deploy.one_click_proxy || deploy.systemd_command,
      docker: deploy.docker_command,
      caddy: deploy.caddy_block,
      cli: deploy.cli_command
    };
    const notes = {
      oneclick: '自动从主控下载对应架构二进制并校验 SHA-256、注册 systemd 并直听 80/443 自动申请 Let\'s Encrypt 证书；以后在面板直接修改域名即可免 SSH 热切换生效。',
      'oneclick-proxy': '一键安装并仅监听 127.0.0.1:8080，适用于该机器已有 Caddy / Nginx 占用 80/443 端口的场景。',
      docker: '容器模式内置自动 HTTPS（需宿主机 80/443 端口空闲），域名修改同样由主控自动热下发。',
      caddy: '前置反代模式配套的 5 行 Caddy 配置片段；若使用 Nginx，请务必配置 merge_slashes off; 且 proxy_pass 不带末尾斜杠。',
      cli: '适合本地快速调试或多端口模拟测试的单行启动命令。'
    };
    document.getElementById('deploy-code-content').textContent = map[tab] || '';
    const noteEl = document.getElementById('deploy-tab-note');
    if (noteEl) noteEl.textContent = notes[tab] || '';
    syncSegmented(document.getElementById('deploy-tabs'));
  }

  function openNodeDeployDialog(node, deploy) {
    state.nodeDeploy = deploy;
    document.getElementById('node-deploy-title').textContent = `部署节点 · ${node.name}`;
    document.getElementById('node-deploy-subtitle').textContent = `一次性 Token 有效期至 ${formatTime(deploy.enroll_expires_at)}，注册完成后自动失效`;
    document.getElementById('deploy-token-value').textContent = deploy.enroll_token || '';
    const dialog = document.getElementById('node-deploy-dialog');
    if (!dialog.open) dialog.showModal();
    renderDeployTab('oneclick');
    refreshIcons();
  }

  async function rotateNodeToken(node, button) {
    if (state.busyNodeIDs.has(node.id)) return;
    let revoke = false;
    if (node.enrolled) {
      const confirmed = await confirmAction({
        title: `重新生成「${node.name}」部署凭证`,
        message: '将签发一个新的 15 分钟一次性注册 Token，并吊销该节点当前的旧密钥，需在目标机器重新注册接入。',
        confirmLabel: '轮换并生成命令', icon: 'terminal', danger: true
      });
      if (!confirmed) return;
      revoke = true;
    }
    state.busyNodeIDs.add(node.id);
    if (button) button.disabled = true;
    try {
      const res = await api(`/_admin/api/nodes/${encodeURIComponent(node.id)}/rotate-token`, jsonOptions('POST', { revoke_existing: revoke }));
      await refreshNodes();
      if (res?.deploy) openNodeDeployDialog(res.node || node, res.deploy);
    } catch {
      toast('生成部署凭证失败', 'error');
    } finally {
      state.busyNodeIDs.delete(node.id);
      if (button) button.disabled = false;
    }
  }

  async function toggleNodeDrain(node, button) {
    if (state.busyNodeIDs.has(node.id)) return;
    const nextDraining = !node.draining;
    state.busyNodeIDs.add(node.id);
    button.disabled = true;
    try {
      await api(`/_admin/api/nodes/${encodeURIComponent(node.id)}`, jsonOptions('PUT', {
        name: node.name,
        group_name: node.group_name,
        region: node.region,
        public_url: node.public_url,
        public_visible: node.public_visible,
        draining: nextDraining,
        overrides: node.overrides || {},
        monthly_quota_gb: Number(node.monthly_quota_gb) || 0,
        quota_reset_day: Number(node.quota_reset_day) || 1,
        quota_direction: node.quota_direction || 'out',
        quota_auto_drain: node.quota_auto_drain !== false,
        dns_sync_enabled: Boolean(node.dns_sync_enabled),
        dns_ip_mode: node.dns_ip_mode || 'auto',
        manual_ipv4: node.manual_ipv4 || '',
        manual_ipv6: node.manual_ipv6 || ''
      }));
      await refreshNodes();
      toast(nextDraining ? `节点「${node.name}」已进入维护排空模式` : `节点「${node.name}」已恢复接流`);
    } catch {
      toast('节点状态切换失败', 'error');
    } finally {
      state.busyNodeIDs.delete(node.id);
      button.disabled = false;
    }
  }

  async function upgradeSingleNode(node, button) {
    if (state.busyNodeIDs.has(node.id)) return;
    const confirmed = await confirmAction({
      title: `远程升级节点「${node.name}」`,
      message: '将通知该 Agent 从主控下载对应架构的最新二进制并校验 SHA-256；若已是最新则自动跳过，升级后由 systemd 自动重启接入。',
      confirmLabel: '推送升级', icon: 'circle-arrow-up'
    });
    if (!confirmed) return;
    state.busyNodeIDs.add(node.id);
    button.disabled = true;
    try {
      await api(`/_admin/api/nodes/${encodeURIComponent(node.id)}/upgrade`, jsonOptions('POST', {}));
      toast(`已向「${node.name}」推送远程升级指令`);
    } catch (failure) {
      toast(failure.message === 'edge node is offline' ? '该节点当前离线，无法推送升级' : '升级指令发送失败', 'error');
    } finally {
      state.busyNodeIDs.delete(node.id);
      button.disabled = false;
    }
  }

  async function upgradeAllOnlineNodes(button) {
    const onlineCount = state.nodesData.filter((n) => ['online', 'draining'].includes(n.status)).length;
    if (onlineCount === 0) {
      toast('当前没有在线的边缘节点', 'info');
      return;
    }
    const confirmed = await confirmAction({
      title: `一键远程升级全部 ${onlineCount} 个在线节点`,
      message: '主控将通过 SSE 通知全部在线节点校验并拉取最新二进制；已是最新版本的节点会自动跳过，无需重启。',
      confirmLabel: '全部推送升级', icon: 'circle-arrow-up'
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      const res = await api('/_admin/api/nodes/upgrade-all', jsonOptions('POST', {}));
      toast(`已向 ${Number(res.triggered) || 0} 个在线节点推送升级指令`);
    } catch {
      toast('批量升级指令发送失败', 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function deleteEdgeNode(node, button) {
    const confirmed = await confirmAction({
      title: `删除节点「${node.name}」`,
      message: '删除后该节点将被立即断开控制通道且无法再同步配置（历史请求日志仍会保留）。',
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      await api(`/_admin/api/nodes/${encodeURIComponent(node.id)}`, { method: 'DELETE' });
      await refreshNodes();
      toast(`节点「${node.name}」已删除`);
    } catch {
      button.disabled = false;
      toast('删除节点失败', 'error');
    }
  }

  /* -------------------- Cluster Discovery One-Click Install -------------------- */

  function renderDiscoveryTab(tab) {
    state.discoveryTab = tab;
    const cmds = state.discovery?.commands || {};
    document.querySelectorAll('#disc-tabs button').forEach((btn) => {
      const active = btn.dataset.discTab === tab;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    const map = {
      oneclick: cmds.one_click_auto_tls || '',
      'oneclick-proxy': cmds.one_click_proxy || '',
      docker: cmds.docker_command || '',
      cli: cmds.cli_command || ''
    };
    const notes = {
      oneclick: '自动下载对应架构二进制、校验 SHA-256、安装 systemd 并监听 80/443；无需绑定域名，入网后前往「域名入口」勾选该节点即自动热下发证书与路由。',
      'oneclick-proxy': '一键安装并监听 127.0.0.1:8080，适用于该机器已有 Caddy / Nginx 占用 80/443 的场景。',
      docker: '容器模式免域名自动注册入网，支持主控多域名 SNI 热下发证书。',
      cli: '适合本地多端口模拟调试的单行免域名入网命令。'
    };
    const box = document.getElementById('disc-code-content');
    if (box) box.textContent = map[tab] || '';
    const note = document.getElementById('disc-tab-note');
    if (note) note.textContent = notes[tab] || '';
    syncSegmented(document.getElementById('disc-tabs'));
  }

  function renderDiscoveryModal(data) {
    state.discovery = data;
    document.getElementById('disc-enabled').checked = Boolean(data.enabled);
    document.getElementById('disc-default-group').value = data.default_group || '';
    document.getElementById('disc-default-region').value = data.default_region || '';
    document.getElementById('disc-token-value').textContent = data.token || '';
    const disabledWarn = document.getElementById('disc-disabled-warning');
    if (disabledWarn) disabledWarn.hidden = Boolean(data.enabled);
    renderDiscoveryTab(state.discoveryTab || 'oneclick');
    refreshIcons();
  }

  async function openDiscoveryDialog() {
    try {
      const data = await api('/_admin/api/nodes/discovery');
      renderDiscoveryModal(data);
      const dialog = document.getElementById('discovery-dialog');
      if (!dialog.open) dialog.showModal();
      syncSegmented(document.getElementById('disc-tabs'));
    } catch {
      toast('加载集群接入配置失败', 'error');
    }
  }

  async function saveDiscoverySettings(button) {
    button.disabled = true;
    try {
      const data = await api('/_admin/api/nodes/discovery', jsonOptions('PUT', {
        enabled: document.getElementById('disc-enabled').checked,
        default_group: document.getElementById('disc-default-group').value.trim(),
        default_region: document.getElementById('disc-default-region').value.trim()
      }));
      renderDiscoveryModal(data);
      toast('集群自动接入设置已保存');
    } catch {
      toast('保存集群接入设置失败', 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function rotateDiscoveryToken(button) {
    const dialog = document.getElementById('discovery-dialog');
    if (dialog.open) dialog.close();
    const confirmed = await confirmAction({
      title: '轮换集群 Discovery Token',
      message: '轮换后旧的一键接入命令将失效，已成功入网的边缘节点继续正常工作不受影响。',
      confirmLabel: '确认轮换', icon: 'refresh-cw', danger: true
    });
    if (!confirmed) {
      dialog.showModal();
      syncSegmented(document.getElementById('disc-tabs'));
      return;
    }
    button.disabled = true;
    try {
      const data = await api('/_admin/api/nodes/discovery/rotate', jsonOptions('POST', {}));
      renderDiscoveryModal(data);
      dialog.showModal();
      syncSegmented(document.getElementById('disc-tabs'));
      toast('集群 Discovery Token 已轮换');
    } catch {
      toast('Token 轮换失败', 'error');
      dialog.showModal();
      syncSegmented(document.getElementById('disc-tabs'));
    } finally {
      button.disabled = false;
    }
  }

  /* -------------------- Managed Edge Domains (OpenFlare-style) -------------------- */

  function normalizeDomainHostInput(raw) {
    let v = String(raw || '').trim().toLowerCase();
    v = v.replace(/^https?:\/\//i, '');
    v = v.split(/[/?#]/)[0];
    if (!v.startsWith('[')) {
      const colonIdx = v.lastIndexOf(':');
      if (colonIdx > 0 && /^\d+$/.test(v.slice(colonIdx + 1))) {
        v = v.slice(0, colonIdx);
      }
    }
    return v.replace(/\.+$/, '');
  }

  function getDomainTLSMode() {
    return document.querySelector('input[name="domain-tls-mode"]:checked')?.value || 'auto';
  }

  function setDomainTLSMode(mode) {
    const target = ['auto', 'manual', 'external'].includes(mode) ? mode : 'auto';
    document.querySelectorAll('input[name="domain-tls-mode"]').forEach((r) => { r.checked = r.value === target; });
  }

  function getDomainDNSMode() {
    return document.querySelector('input[name="domain-dns-mode"]:checked')?.value || 'manual';
  }

  function setDomainDNSMode(mode) {
    const target = ['manual', 'cloudflare_all', 'cloudflare_failover', 'axisnow_smart'].includes(mode) ? mode : 'manual';
    document.querySelectorAll('input[name="domain-dns-mode"]').forEach((r) => { r.checked = r.value === target; });
  }

  function renderDomainFlowStrip() {
    const step1 = document.getElementById('domain-flow-step-1');
    const step2 = document.getElementById('domain-flow-step-2');
    const step3 = document.getElementById('domain-flow-step-3');
    const nodesHint = document.getElementById('domain-flow-nodes-hint');
    const domHint = document.getElementById('domain-flow-domains-hint');
    const tlsHint = document.getElementById('domain-flow-tls-hint');
    if (!step1 || !step2 || !step3) return;

    const totalNodes = state.nodesSummary?.total ?? state.nodesData.length;
    const onlineNodes = state.nodesSummary?.online ?? state.nodesData.filter((n) => n.status === 'online').length;
    const totalDomains = state.domainsSummary?.total ?? state.domainsData.length;
    const enabledDomains = state.domainsSummary?.enabled ?? state.domainsData.filter((d) => d.enabled).length;
    const certsReady = state.domainsSummary?.certs_ready ?? 0;

    step1.classList.toggle('is-ready', onlineNodes > 0);
    if (nodesHint) {
      nodesHint.textContent = totalNodes > 0
        ? `当前已有 ${onlineNodes} / ${totalNodes} 台边缘机器在线，可随时勾选绑定域名`
        : '还没有在线机器，请先到「边缘节点」复制免域名一键接入命令';
    }

    step2.classList.toggle('is-ready', enabledDomains > 0);
    if (domHint) {
      domHint.textContent = totalDomains > 0
        ? `已编排 ${totalDomains} 个域名（${enabledDomains} 个运行中），仅下发给选中的机器`
        : '只下发给勾选的机器，未选中的机器不会部署此域名';
    }

    step3.classList.toggle('is-ready', state.domainsCFEnabled || state.domainsAxisNowEnabled || certsReady > 0);
    if (tlsHint) {
      if (state.domainsAxisNowEnabled && state.domainsCFEnabled) {
        tlsHint.textContent = `AxisNow 智能 DNS + Cloudflare (${state.domainsCFRoot || 'Zone'}) 已就绪：按线路智能分流并自动签发证书`;
      } else if (state.domainsAxisNowEnabled) {
        tlsHint.textContent = 'AxisNow 智能 DNS 已就绪：支持按地区/运营商分流并自动开启 HTTPS';
      } else if (state.domainsCFEnabled) {
        tlsHint.textContent = `Cloudflare (${state.domainsCFRoot || 'Zone'}) 已就绪：自动维护解析并由主控统一签发证书`;
      } else {
        tlsHint.textContent = '未配 Cloudflare 时也可直接手动填 A 记录指向选中机器，自动开启 HTTPS';
      }
    }
  }

  function renderDomains(payload) {
    const domains = Array.isArray(payload?.domains) ? payload.domains : [];
    const summary = payload?.summary || { total: domains.length, enabled: 0, certs_ready: 0, dns_managed: 0, bound_nodes: 0 };
    state.domainsData = domains;
    state.domainsSummary = summary;
    state.domainsCFEnabled = Boolean(payload?.cf_enabled);
    state.domainsCFRoot = payload?.cf_root_domain || '';
    if (payload && 'axisnow_enabled' in payload) {
      state.domainsAxisNowEnabled = Boolean(payload.axisnow_enabled);
      state.domainsAxisNowProviderType = payload.axisnow_provider_type || '';
      state.domainsAxisNowDefaultZone = payload.axisnow_default_zone || '';
      if (Array.isArray(payload.axisnow_providers)) state.domainsAxisNowProviders = payload.axisnow_providers;
    }

    const navBadge = document.getElementById('nav-domains-badge');
    if (navBadge) {
      navBadge.textContent = String(summary.enabled);
      navBadge.hidden = summary.total === 0;
    }

    document.getElementById('domains-kpi-total').textContent = formatNumber(summary.total);
    document.getElementById('domains-kpi-enabled').textContent = `${formatNumber(summary.enabled)} 个运行中`;
    document.getElementById('domains-kpi-certs').textContent = formatNumber(summary.certs_ready);
    document.getElementById('domains-kpi-dns').textContent = formatNumber(summary.dns_managed);
    const dnsStatusParts = [];
    if (state.domainsAxisNowEnabled) dnsStatusParts.push('AxisNow 智能 DNS');
    if (state.domainsCFEnabled) dnsStatusParts.push(`CF (${state.domainsCFRoot || 'Zone'})`);
    document.getElementById('domains-kpi-cf-status').textContent = dnsStatusParts.length
      ? `${dnsStatusParts.join(' + ')} 已就绪`
      : '尚未配置自动/智能 DNS';
    document.getElementById('domains-kpi-nodes').textContent = formatNumber(summary.bound_nodes);

    const anBadge = document.getElementById('domains-axisnow-badge');
    if (anBadge) {
      anBadge.hidden = !state.domainsAxisNowEnabled;
      anBadge.textContent = `智能 DNS 已就绪${state.domainsAxisNowDefaultZone ? ` (${state.domainsAxisNowDefaultZone})` : ''}`;
      anBadge.className = 'badge badge-emerald';
    }
    const cfBadge = document.getElementById('domains-cf-badge');
    if (cfBadge) {
      cfBadge.textContent = state.domainsCFEnabled
        ? `Cloudflare 已连接 (${state.domainsCFRoot || 'Zone'})`
        : 'Cloudflare 未配置（支持手动解析 + 自动 HTTPS）';
      cfBadge.className = `badge ${state.domainsCFEnabled ? 'badge-emerald' : ''}`;
    }

    renderDomainFlowStrip();

    const q = state.domainsQuery.trim().toLowerCase();
    const filtered = domains.filter((d) => {
      if (state.domainsFilter === 'enabled' && !d.enabled) return false;
      if (state.domainsFilter === 'disabled' && d.enabled) return false;
      if (state.domainsFilter === 'cf' && d.dns_mode === 'manual') return false;
      if (!q) return true;
      const nodeNames = (d.bound_nodes || []).map((n) => n.name).join(' ');
      return `${d.domain} ${d.name} ${d.note} ${nodeNames}`.toLowerCase().includes(q);
    });

    const body = document.getElementById('domains-table');
    const empty = document.getElementById('domains-empty');
    if (!filtered.length) {
      body.replaceChildren();
      empty.hidden = false;
      return;
    }
    empty.hidden = true;

    const f = document.createDocumentFragment();
    filtered.forEach((d) => {
      const row = document.createElement('tr');

      // 1. Domain & Display Name
      const domCell = el('td');
      const domStack = el('div', 'cell-stack');
      const domHead = el('div', 'cell-meta-row');
      if (d.domain.startsWith('*.')) {
        domHead.append(el('span', 'cell-primary mono', d.domain));
      } else {
        const copyBtn = el('button', 'node-url-copy');
        copyBtn.type = 'button';
        copyBtn.title = '点击复制 HTTPS 入口地址';
        copyBtn.innerHTML = `<i data-lucide="copy"></i><strong class="cell-primary mono">${escapeHTML(d.domain)}</strong>`;
        copyBtn.addEventListener('click', () => copyPlainText(`https://${d.domain}`, `已复制 https://${d.domain}`));
        domHead.append(copyBtn);
      }
      if (d.public_visible && !d.domain.startsWith('*.')) {
        domHead.append(el('span', 'meta-tag accent', '公开门户'));
      }
      if (d.overrides?.max_download_mbps_per_ip !== undefined && d.overrides?.max_download_mbps_per_ip !== null) {
        const mbps = Number(d.overrides.max_download_mbps_per_ip);
        domHead.append(el('span', 'meta-tag sky', mbps > 0 ? `限速 ${mbps}M` : '不限速'));
      }
      if (d.overrides?.trust_proxy_headers === true) {
        const cdnTag = el('span', 'meta-tag emerald', 'CDN 真实 IP');
        const cidrs = String(d.overrides.trusted_proxy_cidrs || '').trim();
        const hdr = String(d.overrides.real_ip_header || '').trim();
        const isAny = cidrs.includes('0.0.0.0/0');
        cdnTag.title = `前置 CDN 真实 IP 解析已开启 · ${isAny ? '信任所有回源节点' : (cidrs ? `可信节点：${cidrs}` : '仅内网代理')}${hdr ? ` · 优先头：${hdr}` : ''}`;
        domHead.append(cdnTag);
      }
      const subParts = [d.name !== d.domain ? d.name : '', d.note].filter(Boolean);
      domStack.append(domHead);
      if (subParts.length) {
        domStack.append(el('span', 'cell-secondary', subParts.join(' · ')));
      }
      const boundWAF = Array.isArray(d.bound_waf_rules) ? d.bound_waf_rules : [];
      if (boundWAF.length) {
        const wafRow = el('div', 'cell-meta-row');
        boundWAF.forEach((wr) => {
          const pill = el('span', `meta-tag ${wr.enabled ? 'accent' : ''}`);
          pill.innerHTML = `<i data-lucide="shield-check"></i><span>${escapeHTML(wr.name)}${wr.enabled ? '' : ' (已停用)'}</span>`;
          wafRow.append(pill);
        });
        domStack.append(wafRow);
      }
      const ovCount = countNodeOverrides(d.overrides);
      const nodeLimCount = d.node_limits ? Object.keys(d.node_limits).length : 0;
      if (ovCount > 0 || nodeLimCount > 0) {
        const metaParts = [];
        if (d.overrides?.max_concurrent_per_ip) metaParts.push(`单 IP 并发 ${d.overrides.max_concurrent_per_ip}`);
        if (nodeLimCount > 0) metaParts.push(`${nodeLimCount} 台单机限速`);
        if (!metaParts.length && ovCount > 0) metaParts.push(`含 ${ovCount} 项反代覆写`);
        domStack.append(el('span', 'cell-secondary', metaParts.join(' · ')));
      }
      domCell.append(domStack);

      // 2. Bound Nodes
      const nodesCell = el('td');
      const boundNodes = Array.isArray(d.bound_nodes) ? d.bound_nodes : [];
      if (!boundNodes.length) {
        nodesCell.append(el('span', 'badge badge-amber', '未选机器'));
      } else {
        const wrap = el('div', 'domain-node-badges');
        boundNodes.forEach((bn, idx) => {
          const pill = el('span', `domain-node-pill ${bn.status}`);
          const prefix = d.dns_mode === 'cloudflare_failover' ? `#${idx + 1} ` : '';
          const star = bn.active_dns ? ' ★' : '';
          const speedTag = bn.speed_limit_mbps !== undefined && bn.speed_limit_mbps !== null
            ? (Number(bn.speed_limit_mbps) > 0 ? ` · ${bn.speed_limit_mbps}M` : ' · 不限')
            : '';
          pill.textContent = `${prefix}${bn.name}${speedTag}${star}`;
          pill.title = `${bn.name} (${bn.status})${bn.effective_ipv4 ? ` · ${bn.effective_ipv4}` : ''}${speedTag ? ` · 单机限速${speedTag}` : ''}${bn.active_dns ? ' · 当前 DNS 指向' : ''}`;
          wrap.append(pill);
        });
        nodesCell.append(wrap);
      }

      // 3. DNS Mode
      const dnsCell = el('td');
      const dnsStack = el('div', 'cell-stack');
      const dnsTips = [];
      if (d.dns_mode === 'manual') {
        dnsStack.append(el('span', 'badge', '手动解析'));
        const ips = boundNodes.map((bn) => bn.effective_ipv4 || bn.effective_ipv6).filter(Boolean);
        if (d.dns_last_error) {
          dnsStack.append(el('span', 'cell-secondary', `异常：${d.dns_last_error}`));
        } else if (ips.length === 1) {
          dnsStack.append(el('span', 'cell-secondary mono', `指向 ${ips[0]}`));
        } else if (ips.length > 1) {
          dnsStack.append(el('span', 'cell-secondary', `指向 ${ips.length} 台机器`));
        } else if (!boundNodes.length) {
          dnsStack.append(el('span', 'cell-secondary', '请先选择部署机器'));
        }
      } else if (d.dns_mode === 'axisnow_smart') {
        const smart = d.smart_dns || {};
        const lines = Array.isArray(smart.lines) ? smart.lines : [];
        const errLineCount = lines.filter((l) => l.status === 'error').length;
        const headRow = el('div', 'cell-meta-row');
        const modeTitle = smart.profile_name
          ? `方案 · ${smart.profile_name}`
          : '智能分流';
        headRow.append(el('span', 'badge badge-emerald', modeTitle));
        if (smart.auto_cf_cname && !smart.cf_cname_synced && smart.cf_cname_status === 'pending') {
          headRow.append(el('span', 'meta-tag amber', '等待切 CNAME'));
        } else if (smart.auto_cf_cname && !smart.cf_cname_synced && smart.cf_cname_status === 'error') {
          headRow.append(el('span', 'meta-tag rose', 'CF CNAME 异常'));
        }
        if (errLineCount > 0) {
          headRow.append(el('span', 'meta-tag rose', `${errLineCount} 线异常`));
        }
        dnsStack.append(headRow);

        if (d.dns_last_error) {
          dnsStack.append(el('span', 'cell-secondary', `异常：${d.dns_last_error}`));
        } else if (smart.auto_cf_cname && !smart.cf_cname_synced && (smart.cf_cname_status === 'pending' || smart.cf_cname_status === 'error') && smart.cf_cname_status_note) {
          dnsStack.append(el('span', 'cell-secondary', smart.cf_cname_status_note));
        } else if (!smart.auto_cf_cname && smart.routing_domain_host) {
          const cpCname = el('button', 'node-url-copy');
          cpCname.type = 'button';
          cpCname.title = '点击复制 AxisNow 调度域名（CNAME 目标）';
          cpCname.innerHTML = `<i data-lucide="copy"></i><span class="cell-secondary mono">${escapeHTML(smart.routing_domain_host)}</span>`;
          cpCname.addEventListener('click', () => copyPlainText(smart.routing_domain_host, `已复制 CNAME 目标：${smart.routing_domain_host}`));
          dnsStack.append(cpCname);
        } else if (lines.length > 0) {
          dnsStack.append(el('span', 'cell-secondary', `${lines.length} 条分流线路${smart.cf_cname_synced ? ' · CF 托管' : ''}`));
        } else {
          dnsStack.append(el('span', 'cell-secondary', '待同步分流线路'));
        }

        if (smart.routing_domain_host) dnsTips.push(`CNAME：${smart.routing_domain_host}`);
        if (lines.length) {
          const nodeNameMap = new Map(boundNodes.map((bn) => [bn.id, bn.name]));
          const lineSummaries = lines.map((ln) => {
            const targetNames = (ln.active_node_ids?.length ? ln.active_node_ids : (ln.node_ids || []))
              .map((nid) => nodeNameMap.get(nid) || nid)
              .slice(0, 2)
              .join('/');
            return `${ln.label || ln.geo_isp}→${targetNames || '未选'}`;
          });
          dnsTips.push(`线路：${lineSummaries.join(' / ')}`);
        }
        if (smart.cf_cname_status_note) dnsTips.push(smart.cf_cname_status_note);
      } else if (d.dns_mode === 'cloudflare_failover') {
        dnsStack.append(el('span', 'badge badge-sky', 'CF 主备切线'));
        if (d.dns_last_error) {
          dnsStack.append(el('span', 'cell-secondary', `异常：${d.dns_last_error}`));
        } else if (d.dns_active_node_name) {
          dnsStack.append(el('span', 'cell-secondary', `当前：${d.dns_active_node_name}`));
        }
      } else {
        dnsStack.append(el('span', 'badge badge-accent', 'CF 多机同步'));
        if (d.dns_last_error) {
          dnsStack.append(el('span', 'cell-secondary', `异常：${d.dns_last_error}`));
        } else {
          dnsStack.append(el('span', 'cell-secondary', `${d.healthy_node_count}/${d.total_node_count} 在线同步`));
        }
      }
      if (d.dns_last_error) dnsTips.push(`异常：${d.dns_last_error}`);
      if (d.dns_last_sync_at) dnsTips.push(`同步于 ${relativeTime(d.dns_last_sync_at)}`);
      if (dnsTips.length) dnsStack.title = dnsTips.join('\n');
      dnsCell.append(dnsStack);

      // 4. HTTPS Cert Status
      const certCell = el('td');
      const certStack = el('div', 'cell-stack');
      const daysLeft = d.cert_not_after ? Math.max(0, Math.floor((Number(d.cert_not_after) - Date.now() / 1000) / 86400)) : 0;
      if (d.cert_status === 'ready') {
        certStack.append(el('span', `badge ${daysLeft < 14 ? 'badge-amber' : 'badge-emerald'}`, daysLeft ? `HTTPS 就绪 · ${daysLeft}天` : 'HTTPS 已就绪'));
        certStack.append(el('span', 'cell-secondary', d.cert_issuer || '主控统一下发'));
      } else if (d.cert_status === 'issuing') {
        certStack.append(el('span', 'badge badge-sky', '自动签发中…'));
        certStack.append(el('span', 'cell-secondary', '完成后自动推送选中机器'));
      } else if (d.cert_status === 'error') {
        const errBadge = el('span', 'badge badge-rose', '证书异常');
        errBadge.title = d.cert_error || '';
        certStack.append(errBadge, el('span', 'cell-secondary', (d.cert_error || '').slice(0, 36)));
      } else if (d.cert_status === 'agent_auto') {
        certStack.append(el('span', 'badge badge-accent', '自动 HTTPS'));
        certStack.append(el('span', 'cell-secondary', '由选中机器自动签发'));
      } else if (d.cert_status === 'external') {
        certStack.append(el('span', 'badge', '前置反代托管'));
      } else {
        certStack.append(el('span', 'badge', '等待生效'));
        certStack.append(el('span', 'cell-secondary', d.cert_strategy === 'controller_dns01' ? '主控自动签发待触发' : '等待选择机器'));
      }
      certCell.append(certStack);

      // 5. Status
      const statusCell = el('td');
      statusCell.append(el('span', `badge ${d.enabled ? 'badge-emerald' : ''}`, d.enabled ? '运行中' : '已停用'));

      // 6. Actions
      const actions = el('td', 'actions-col');
      const actRow = el('div', 'row-actions');

      const editBtn = el('button', 'icon-btn');
      editBtn.type = 'button'; editBtn.title = '配置域名、部署机器与 HTTPS'; editBtn.setAttribute('aria-label', editBtn.title);
      editBtn.innerHTML = '<i data-lucide="sliders-horizontal"></i>';
      editBtn.addEventListener('click', () => openDomainDrawerForEdit(d));
      actRow.append(editBtn);

      if (d.tls_mode === 'auto' && d.cert_strategy === 'controller_dns01') {
        const certBtn = el('button', 'icon-btn');
        certBtn.type = 'button'; certBtn.title = '立即通过 Cloudflare DNS-01 申请/续期证书'; certBtn.setAttribute('aria-label', certBtn.title);
        certBtn.innerHTML = '<i data-lucide="shield-check"></i>';
        certBtn.addEventListener('click', () => issueDomainCert(d, certBtn));
        actRow.append(certBtn);
      }

      if (d.dns_mode !== 'manual') {
        const dnsBtn = el('button', 'icon-btn');
        dnsBtn.type = 'button'; dnsBtn.title = d.dns_mode === 'axisnow_smart' ? '立即同步 AxisNow 智能 DNS 线路' : '立即同步 Cloudflare DNS 解析'; dnsBtn.setAttribute('aria-label', dnsBtn.title);
        dnsBtn.innerHTML = '<i data-lucide="refresh-cw"></i>';
        dnsBtn.addEventListener('click', () => syncDomainDNS(d, dnsBtn));
        actRow.append(dnsBtn);
      }

      const delBtn = el('button', 'icon-btn danger');
      delBtn.type = 'button'; delBtn.title = '删除域名'; delBtn.setAttribute('aria-label', '删除域名');
      delBtn.innerHTML = '<i data-lucide="trash-2"></i>';
      delBtn.addEventListener('click', () => deleteEdgeDomain(d, delBtn));
      actRow.append(delBtn);

      actions.append(actRow);
      [domCell, nodesCell, dnsCell, certCell, statusCell, actions].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  async function refreshDomains() {
    if (state.domainsPromise) return state.domainsPromise;
    const req = (async () => {
      if (!state.nodesData.length) {
        await refreshNodes().catch(() => {});
      }
      const payload = await api('/_admin/api/domains');
      renderDomains(payload);
      return payload;
    })();
    state.domainsPromise = req;
    try { return await req; } finally {
      if (state.domainsPromise === req) state.domainsPromise = null;
    }
  }

  function updateDomainHostPreview() {
    const raw = document.getElementById('domain-host')?.value || '';
    const host = normalizeDomainHostInput(raw);
    const previewEl = document.getElementById('domain-preview-text');
    const tagEl = document.getElementById('domain-preview-tag');
    if (previewEl) {
      if (!host) {
        previewEl.textContent = 'https://your-domain.example.com';
      } else if (host.startsWith('*.')) {
        previewEl.textContent = `https://任意子域名.${host.slice(2)}`;
      } else {
        previewEl.textContent = `https://${host}`;
      }
    }
    if (tagEl) {
      if (host.startsWith('*.')) {
        tagEl.textContent = '泛域名入口';
        tagEl.className = 'badge badge-sky';
      } else if (host) {
        tagEl.textContent = '单域名入口';
        tagEl.className = 'badge badge-accent';
      } else {
        tagEl.textContent = '单域名 / 泛域名';
        tagEl.className = 'badge';
      }
    }
    updateDomainStep3UI();
  }

  function renderDomainNodePicker() {
    const grid = document.getElementById('domain-node-grid');
    const emptyEl = document.getElementById('domain-node-empty');
    const countBadge = document.getElementById('domain-picker-count');
    const stepCount = document.getElementById('domain-step-node-count');
    const priorityBox = document.getElementById('domain-priority-box');
    const priorityList = document.getElementById('domain-bound-nodes');
    if (!grid) return;

    const nodes = state.nodesData || [];
    const selected = state.domainBoundNodeIDs || [];
    const nodeByID = new Map(nodes.map((n) => [n.id, n]));

    if (countBadge) {
      countBadge.textContent = `已选 ${selected.length} / ${nodes.length} 台`;
      countBadge.className = `badge ${selected.length ? 'badge-accent' : ''}`;
    }
    if (stepCount) {
      stepCount.textContent = String(selected.length);
    }

    if (!nodes.length) {
      grid.replaceChildren();
      if (emptyEl) emptyEl.hidden = false;
      if (priorityBox) priorityBox.hidden = true;
      updateDomainStep3UI();
      return;
    }
    if (emptyEl) emptyEl.hidden = true;

    const frag = document.createDocumentFragment();
    nodes.forEach((n) => {
      const idx = selected.indexOf(n.id);
      const isSelected = idx !== -1;
      const card = el('button', `domain-node-card${isSelected ? ' selected' : ''}`);
      card.type = 'button';
      card.setAttribute('aria-pressed', String(isSelected));

      const check = el('span', 'domain-node-check');
      check.innerHTML = '<i data-lucide="check"></i>';

      const body = el('div', 'domain-node-card-body');
      const top = el('div', 'domain-node-card-top');
      const nameWrap = el('div', 'domain-node-card-name');
      const dotClass = n.status === 'online' ? 'status-dot' : n.status === 'draining' ? 'status-dot amber' : n.status === 'offline' ? 'status-dot rose' : 'status-dot muted';
      nameWrap.append(el('span', dotClass), el('span', '', n.name || n.id));

      const tagText = isSelected
        ? (selected.length > 1 ? `#${idx + 1} ${idx === 0 ? '主用' : '备用'}` : '已选部署')
        : '不部署';
      top.append(nameWrap, el('span', 'domain-node-card-tag', tagText));

      const meta = el('div', 'domain-node-card-meta');
      const statusLabel = n.status === 'online' ? '在线' : n.status === 'draining' ? '维护排空' : '离线';
      const loc = [n.group_name, n.region].filter(Boolean).join(' · ');
      const ip = n.effective_ipv4 || n.effective_ipv6 || '未上报 IP';
      meta.append(el('span', '', statusLabel));
      if (loc) meta.append(el('span', '', loc));
      meta.append(el('span', 'mono', ip));

      body.append(top, meta);
      card.append(check, body);
      card.addEventListener('click', () => {
        const pos = state.domainBoundNodeIDs.indexOf(n.id);
        if (pos >= 0) {
          state.domainBoundNodeIDs.splice(pos, 1);
        } else {
          state.domainBoundNodeIDs.push(n.id);
        }
        renderDomainNodePicker();
      });
      frag.append(card);
    });
    grid.replaceChildren(frag);

    if (priorityBox && priorityList) {
      priorityBox.hidden = selected.length === 0;
      const hintEl = document.getElementById('domain-priority-hint');
      if (hintEl) {
        hintEl.textContent = selected.length >= 2
          ? '（留空跟随本域名限速，可用 ↑/↓ 调整主备切线优先级）'
          : '（留空跟随上方本域名限速，填 0 表示该机器在此域名不限速）';
      }
      if (selected.length >= 1) {
        const domainSpeedRaw = (document.getElementById('domain-ov-speed')?.value || '').trim();
        const placeholderText = domainSpeedRaw !== ''
          ? (Number(domainSpeedRaw) > 0 ? `跟随域名 (${domainSpeedRaw}M)` : '跟随域名 (不限)')
          : '跟随本域名';
        const pFrag = document.createDocumentFragment();
        selected.forEach((nid, idx) => {
          const n = nodeByID.get(nid);
          const row = el('div', 'domain-bound-row');

          const info = el('div', 'domain-bound-row-info');
          if (selected.length >= 2) {
            info.append(el('span', `badge ${idx === 0 ? 'badge-emerald' : ''}`, `#${idx + 1}`));
          }
          const dotClass = n?.status === 'online' ? 'status-dot' : n?.status === 'draining' ? 'status-dot amber' : n?.status === 'offline' ? 'status-dot rose' : 'status-dot muted';
          info.append(el('span', dotClass));
          const nameCol = el('div', 'domain-bound-row-name');
          nameCol.append(el('strong', '', n ? n.name : nid));
          const subText = [n?.region, n?.effective_ipv4 || n?.effective_ipv6].filter(Boolean).join(' · ') || '边缘节点';
          nameCol.append(el('small', 'mono', subText));
          info.append(nameCol);

          const controls = el('div', 'domain-bound-row-controls');
          const speedWrap = el('div', 'input-with-unit domain-node-speed-input');
          const speedInput = document.createElement('input');
          speedInput.type = 'number';
          speedInput.min = '0';
          speedInput.max = '100000';
          speedInput.placeholder = placeholderText;
          speedInput.ariaLabel = `${n ? n.name : nid} 单 IP 限速 (Mbps)`;
          speedInput.dataset.domainNodeSpeed = nid;
          speedInput.value = state.domainNodeSpeeds[nid] ?? '';
          speedInput.addEventListener('input', (ev) => {
            const val = ev.currentTarget.value.trim();
            if (val === '') {
              delete state.domainNodeSpeeds[nid];
            } else {
              state.domainNodeSpeeds[nid] = val;
            }
            updateDomainStep3UI();
          });
          speedWrap.append(speedInput, el('span', 'input-unit', 'Mbps'));
          controls.append(speedWrap);

          const orderGroup = el('div', 'domain-bound-order-btns');
          if (selected.length >= 2) {
            const upBtn = el('button', 'icon-btn');
            upBtn.type = 'button'; upBtn.title = '提高主备优先级'; upBtn.setAttribute('aria-label', '提高主备优先级'); upBtn.disabled = idx === 0;
            upBtn.innerHTML = '<i data-lucide="arrow-up"></i>';
            upBtn.addEventListener('click', () => {
              if (idx <= 0) return;
              [state.domainBoundNodeIDs[idx - 1], state.domainBoundNodeIDs[idx]] = [state.domainBoundNodeIDs[idx], state.domainBoundNodeIDs[idx - 1]];
              renderDomainNodePicker();
            });
            const downBtn = el('button', 'icon-btn');
            downBtn.type = 'button'; downBtn.title = '降低主备优先级'; downBtn.setAttribute('aria-label', '降低主备优先级'); downBtn.disabled = idx === selected.length - 1;
            downBtn.innerHTML = '<i data-lucide="arrow-down"></i>';
            downBtn.addEventListener('click', () => {
              if (idx >= selected.length - 1) return;
              [state.domainBoundNodeIDs[idx + 1], state.domainBoundNodeIDs[idx]] = [state.domainBoundNodeIDs[idx], state.domainBoundNodeIDs[idx + 1]];
              renderDomainNodePicker();
            });
            orderGroup.append(upBtn, downBtn);
          }
          const rmBtn = el('button', 'icon-btn danger');
          rmBtn.type = 'button'; rmBtn.title = '取消勾选该机器'; rmBtn.setAttribute('aria-label', '取消勾选该机器');
          rmBtn.innerHTML = '<i data-lucide="x"></i>';
          rmBtn.addEventListener('click', () => {
            state.domainBoundNodeIDs.splice(idx, 1);
            renderDomainNodePicker();
          });
          orderGroup.append(rmBtn);
          controls.append(orderGroup);

          row.append(info, controls);
          pFrag.append(row);
        });
        priorityList.replaceChildren(pFrag);
      } else {
        priorityList.replaceChildren();
      }
    }

    refreshIcons();
    updateDomainStep3UI();
  }

  function updateDomainStep3UI() {
    const tlsMode = getDomainTLSMode();
    const dnsMode = getDomainDNSMode();
    const hostVal = normalizeDomainHostInput(document.getElementById('domain-host')?.value || '');
    const selectedIDs = state.domainBoundNodeIDs || [];
    const nodeByID = new Map((state.nodesData || []).map((n) => [n.id, n]));
    const selectedNodes = selectedIDs.map((id) => nodeByID.get(id)).filter(Boolean);

    // 1. HTTPS manual PEM box & plain-Chinese strategy banner
    const manualBox = document.getElementById('domain-manual-cert-box');
    const tlsCallout = document.getElementById('domain-tls-callout');
    const hint = document.getElementById('domain-tls-hint');
    if (manualBox) manualBox.hidden = tlsMode !== 'manual';

    let tlsSummaryLabel = '自动 HTTPS';
    if (hint && tlsCallout) {
      tlsCallout.className = 'domain-callout';
      if (tlsMode === 'manual') {
        tlsSummaryLabel = '自定义证书';
        tlsCallout.classList.add('is-sky');
        hint.textContent = '证书私钥由主控 AES-256-GCM 加密保存，仅推送给上一步勾选的机器。';
      } else if (tlsMode === 'external') {
        tlsSummaryLabel = '前置反代 HTTPS';
        hint.textContent = '适合节点前面已经套了 Caddy / Nginx 终止 HTTPS 的场景，Agent 直接按域名匹配流量。';
      } else {
        const root = state.domainsCFRoot.toLowerCase();
        const base = hostVal.replace(/^\*\./, '');
        const cfMatch = state.domainsCFEnabled && root && (base === root || base.endsWith(`.${root}`));
        if (cfMatch) {
          tlsSummaryLabel = '主控自动签发 HTTPS';
          tlsCallout.classList.add('is-emerald');
          hint.textContent = `已匹配 Cloudflare 根域名（${root}）：主控将自动申请证书并统一加密推送给全部选中机器（支持泛域名与多机共享）。`;
        } else if (hostVal.startsWith('*.')) {
          tlsSummaryLabel = '泛域名需 CF 或上传证书';
          tlsCallout.classList.add('is-amber');
          hint.textContent = '泛域名 (*.xxx) 自动申请需要配置 Cloudflare DNS；若暂不配 CF，请改为「上传已有证书」。';
        } else {
          tlsSummaryLabel = '节点自动 HTTPS';
          tlsCallout.classList.add('is-emerald');
          hint.textContent = '只要把域名解析到选中机器的 IP，各选中节点就会自动申请并续期 Let\'s Encrypt 免费证书，无需额外配置。';
        }
      }
    }

    // 2. DNS mode conditional blocks
    const manualGuide = document.getElementById('domain-manual-dns-guide');
    const manualRecords = document.getElementById('domain-manual-dns-records');
    const cfOptionsRow = document.getElementById('domain-cf-options-row');
    const cfUnconfiguredTip = document.getElementById('domain-cf-unconfigured-tip');
    const smartBox = document.getElementById('domain-smart-dns-box');
    const anUnconfiguredTip = document.getElementById('domain-axisnow-unconfigured-tip');

    const isCFMode = dnsMode === 'cloudflare_all' || dnsMode === 'cloudflare_failover';
    const isSmartMode = dnsMode === 'axisnow_smart';
    if (manualGuide) manualGuide.hidden = dnsMode !== 'manual';
    if (cfOptionsRow) cfOptionsRow.hidden = !isCFMode;
    if (cfUnconfiguredTip) cfUnconfiguredTip.hidden = state.domainsCFEnabled || !isCFMode;
    if (smartBox) smartBox.hidden = !isSmartMode;
    if (anUnconfiguredTip) anUnconfiguredTip.hidden = state.domainsAxisNowEnabled || !isSmartMode;
    if (isSmartMode) {
      renderDomainSmartProfilePicker();
    }

    if (manualRecords && dnsMode === 'manual') {
      const recFrag = document.createDocumentFragment();
      const displayHost = hostVal || '你的域名';
      if (!selectedNodes.length) {
        recFrag.append(el('span', 'field-hint', '上一步暂未勾选机器；勾选后这里会自动列出需要指向的 A / AAAA 记录与一键复制按钮。'));
      } else {
        selectedNodes.forEach((n) => {
          const ip = n.effective_ipv4 || n.effective_ipv6;
          const recType = n.effective_ipv4 ? 'A' : (n.effective_ipv6 ? 'AAAA' : 'A');
          const row = el('div', 'domain-dns-record-row');
          const left = el('div', 'domain-dns-record-left');
          left.append(
            el('span', 'badge badge-sky', recType),
            el('code', '', displayHost),
            el('span', 'domain-summary-sep', '→'),
            el('code', '', ip || '待节点上报公网 IP'),
            el('span', 'field-hint', `(${n.name})`)
          );
          row.append(left);
          if (ip) {
            const cp = el('button', 'btn btn-ghost btn-sm', '复制 IP');
            cp.type = 'button';
            cp.addEventListener('click', () => copyPlainText(ip, `已复制 ${n.name} 的 IP：${ip}`));
            row.append(cp);
          }
          recFrag.append(row);
        });
      }
      manualRecords.replaceChildren(recFrag);
    }

    // 3. Live Summary Pipeline
    const summaryEl = document.getElementById('domain-summary-pipeline');
    if (summaryEl) {
      const pickedProf = (state.smartDNSProfiles || []).find((p) => p.id === state.domainSmartDNSDraft?.profile_id);
      const dnsLabel = dnsMode === 'axisnow_smart'
        ? (pickedProf ? `分流方案：${pickedProf.name}` : `AxisNow 智能分流 (${(state.domainSmartDNSDraft?.lines || []).length || 1} 线)`)
        : dnsMode === 'cloudflare_failover'
          ? 'CF 主备自动切线'
          : dnsMode === 'cloudflare_all'
            ? 'CF 多机同步'
            : '手动解析';
      const nodesLabel = selectedNodes.length
        ? (selectedNodes.length <= 2
          ? selectedNodes.map((n) => n.name).join(' + ')
          : `${selectedNodes[0].name} 等 ${selectedNodes.length} 台机器`)
        : '暂未选择机器';
      const domSpeedRaw = (document.getElementById('domain-ov-speed')?.value || '').trim();
      const nodeOverrideCnt = selectedIDs.filter((id) => (state.domainNodeSpeeds[id] ?? '') !== '').length;
      let speedLabel = '限速继承全局';
      if (domSpeedRaw !== '') {
        const v = Number(domSpeedRaw);
        speedLabel = v > 0 ? `限速 ${v} Mbps` : '强制不限速';
        if (nodeOverrideCnt > 0) speedLabel += ` · ${nodeOverrideCnt} 台单机覆写`;
      } else if (nodeOverrideCnt > 0) {
        speedLabel = `${nodeOverrideCnt} 台单机限速`;
      }
      const wafCount = (state.domainBoundWAFIDs || []).length;
      const summaryChildren = [
        el('span', 'badge badge-accent', hostVal || '未填域名'),
        el('span', 'domain-summary-sep', '→'),
        el('span', `badge ${selectedNodes.length ? 'badge-emerald' : 'badge-amber'}`, nodesLabel),
        el('span', 'domain-summary-sep', '→'),
        el('span', 'badge', speedLabel),
        el('span', 'domain-summary-sep', '→'),
        el('span', 'badge badge-sky', dnsLabel),
        el('span', 'domain-summary-sep', '→'),
        el('span', 'badge', tlsSummaryLabel)
      ];
      if (wafCount > 0) {
        summaryChildren.push(
          el('span', 'domain-summary-sep', '→'),
          el('span', 'badge badge-emerald', `WAF ${wafCount} 条`)
        );
      }
      const cdnMode = document.getElementById('domain-cdn-mode')?.value || 'inherit';
      if (cdnMode === 'cidrs' || cdnMode === 'any') {
        summaryChildren.push(
          el('span', 'domain-summary-sep', '→'),
          el('span', 'badge badge-emerald', cdnMode === 'any' ? 'CDN 真实 IP (全回源)' : 'CDN 真实 IP')
        );
      }
      summaryEl.replaceChildren(...summaryChildren);
    }
    syncDomainCDNUI();
    renderDomainWAFPicker();
  }

  const DOMAIN_CDN_CF_CIDRS = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'
  ];
  const DOMAIN_CDN_LAN_CIDRS = ['127.0.0.1/32', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

  function isWildcardCDNList(raw) {
    const tokens = String(raw || '').split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    return tokens.length > 0 && tokens.includes('0.0.0.0/0') && tokens.every((t) => t === '0.0.0.0/0' || t === '::/0');
  }

  function syncDomainCDNUI() {
    const mode = document.getElementById('domain-cdn-mode')?.value || 'inherit';
    const opts = document.getElementById('domain-cdn-options');
    const cidrsWrap = document.getElementById('domain-cdn-cidrs-wrap');
    const anyCallout = document.getElementById('domain-cdn-any-callout');
    const badge = document.getElementById('domain-cdn-status-badge');
    const isEnabled = mode === 'cidrs' || mode === 'any';
    if (opts) opts.hidden = !isEnabled;
    if (cidrsWrap) cidrsWrap.hidden = mode !== 'cidrs';
    if (anyCallout) anyCallout.hidden = mode !== 'any';
    if (badge) {
      if (mode === 'cidrs') {
        const cnt = (document.getElementById('domain-ov-trusted-cidrs')?.value || '').split(/[\s,;]+/).filter(Boolean).length;
        badge.className = 'badge badge-emerald';
        badge.textContent = cnt ? `已启用 · ${cnt} 条可信网段` : '已启用 · 待填节点 IP';
      } else if (mode === 'any') {
        badge.className = 'badge badge-amber';
        badge.textContent = '已启用 · 信任全部回源';
      } else if (mode === 'off') {
        badge.className = 'badge';
        badge.textContent = '强制直连模式';
      } else {
        badge.className = 'badge';
        badge.textContent = '跟随节点默认';
      }
    }
  }

  function appendDomainCDNCIDRs(list) {
    const ta = document.getElementById('domain-ov-trusted-cidrs');
    if (!ta) return;
    const cur = ta.value.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
    const seen = new Set(cur);
    list.forEach((item) => {
      if (!seen.has(item)) {
        seen.add(item);
        cur.push(item);
      }
    });
    ta.value = cur.join('\n');
    syncDomainCDNUI();
  }

  function renderDomainWAFPicker() {
    const globalWrap = document.getElementById('domain-waf-global-hint');
    const picker = document.getElementById('domain-waf-picker');
    const emptyHint = document.getElementById('domain-waf-empty-hint');
    if (!picker) return;

    const rules = Array.isArray(state.wafRules) ? state.wafRules : [];
    const globalRules = rules.filter((r) => r.enabled && r.is_global);
    const domainRules = rules.filter((r) => !r.is_global);
    const selected = state.domainBoundWAFIDs || [];

    if (globalWrap) {
      globalWrap.hidden = globalRules.length === 0;
      if (globalRules.length) {
        const gFrag = document.createDocumentFragment();
        globalRules.forEach((r) => {
          const b = el('span', 'badge badge-emerald');
          b.innerHTML = `<i data-lucide="shield-check"></i><span>全局生效：${escapeHTML(r.name)}</span>`;
          gFrag.append(b);
        });
        globalWrap.replaceChildren(gFrag);
      } else {
        globalWrap.replaceChildren();
      }
    }

    if (!domainRules.length) {
      picker.replaceChildren();
      if (emptyHint) emptyHint.hidden = false;
      refreshIcons();
      return;
    }
    if (emptyHint) emptyHint.hidden = true;

    const frag = document.createDocumentFragment();
    domainRules.forEach((r) => {
      const idx = selected.indexOf(r.id);
      const isSelected = idx !== -1;
      const chip = el('button', `domain-waf-chip${isSelected ? ' selected' : ''}`);
      chip.type = 'button';
      chip.setAttribute('aria-pressed', String(isSelected));
      chip.title = r.summary || r.description || r.name;
      if (isSelected) {
        chip.append(el('span', 'domain-waf-chip-order', String(idx + 1)));
      }
      const icon = document.createElement('i');
      icon.dataset.lucide = 'workflow';
      chip.append(icon, el('span', '', `${r.name}${r.enabled ? '' : ' (已停用)'}`));
      chip.addEventListener('click', () => {
        const pos = state.domainBoundWAFIDs.indexOf(r.id);
        if (pos >= 0) state.domainBoundWAFIDs.splice(pos, 1);
        else state.domainBoundWAFIDs.push(r.id);
        updateDomainStep3UI();
      });
      frag.append(chip);
    });
    picker.replaceChildren(frag);
    refreshIcons();
  }

  function formatAxisNowProviderType(type) {
    const map = {
      'alibaba-cloud': '阿里云 DNS',
      'aws-route53': 'AWS Route 53',
      dnspod: 'DNSPod',
      'dnspod-intl': 'DNSPod 国际版',
      'huawei-cloud': '华为云 DNS',
      cloudflare: 'Cloudflare',
      cloudns: 'ClouDNS'
    };
    return map[type] || type || 'DNS 提供商';
  }

  function buildAxisNowProviderChoices(providers) {
    const out = [];
    (Array.isArray(providers) ? providers : []).forEach((p) => {
      if (p.provider_source === 'platform' && Array.isArray(p.zones) && p.zones.length) {
        p.zones.forEach((z) => {
          out.push({
            key: `${p.uuid}|${z.uuid}`,
            provider_uuid: p.uuid,
            provider_source: 'platform',
            provider_type: p.type,
            zone_uuid: z.uuid,
            zone_name: z.zone || z.name || '',
            zone_plan: z.plan || 'free',
            label: `[免费托管] ${formatAxisNowProviderType(p.type)} · ${z.zone || z.name}${z.plan ? ` (${z.plan})` : ''}`
          });
        });
      } else {
        out.push({
          key: `${p.uuid}|`,
          provider_uuid: p.uuid,
          provider_source: p.provider_source || 'self-hosted',
          provider_type: p.type,
          zone_uuid: '',
          zone_name: '',
          zone_plan: '',
          label: `[${p.provider_source === 'platform' ? '免费托管' : '自有 DNS'}] ${p.name || formatAxisNowProviderType(p.type)} (${formatAxisNowProviderType(p.type)})`
        });
      }
    });
    return out;
  }

  async function ensureAxisNowMetadata(force = false) {
    if (!force && state.axisnowMeta?.providers?.length) return state.axisnowMeta;
    try {
      const meta = await api(`/_admin/api/axisnow-dns/metadata${force ? '?refresh=1' : ''}`);
      state.axisnowMeta = meta;
      return meta;
    } catch {
      return state.axisnowMeta;
    }
  }

  const GEO_ISP_KEY_ZH = {
    default: '默认兜底线路',
    region: '按地区',
    isp: '按运营商',
    otherIsp: '其他运营商',
    global: '海外 / 全球',
    searchEngine: '搜索引擎',
    chinaRegion: '中国大陆',
    china: '中国大陆',
    domestic: '中国大陆',
    overseas: '海外地区',
    oversea: '海外地区',
    chinaTelecom: '中国电信',
    telecom: '中国电信',
    chinaUnicom: '中国联通',
    unicom: '中国联通',
    chinaMobile: '中国移动',
    mobile: '中国移动',
    chinaEducationNetwork: '中国教育网',
    educationNetwork: '中国教育网',
    tietong: '中国铁通',
    broadcasting: '中国广电',
    drpeng: '鹏博士 / 长城宽带',
    baidu: '百度爬虫',
    google: 'Google 爬虫',
    bing: '必应爬虫',
    sogou: '搜狗爬虫',
    qihoo: '360 爬虫',
    youdao: '有道爬虫',
    asia: '亚洲',
    asiaEast: '东亚',
    asiaCentral: '中亚',
    asiaSouth: '南亚',
    asiaMiddleEast: '中东',
    europe: '欧洲',
    northAmerica: '北美洲',
    southAmerica: '南美洲',
    oceania: '大洋洲',
    africa: '非洲',
    antarctica: '南极洲',
    hongKong: '中国香港',
    taiwan: '中国台湾',
    macao: '中国澳门',
    singapore: '新加坡',
    republicKorea: '韩国',
    southKorea: '韩国',
    northKorea: '朝鲜',
    myanmarBurma: '缅甸',
    unitedStates: '美国',
    unitedStatesOfAmerica: '美国',
    unitedKingdom: '英国',
    unitedArabEmirates: '阿联酋',
    hashemiteKingdomJordan: '约旦',
    beijing: '北京', tianjin: '天津', shanghai: '上海', chongqing: '重庆',
    hebei: '河北', shanxi: '山西', liaoning: '辽宁', jilin: '吉林', heilongjiang: '黑龙江',
    jiangsu: '江苏', zhejiang: '浙江', anhui: '安徽', fujian: '福建', jiangxi: '江西',
    shandong: '山东', henan: '河南', hubei: '湖北', hunan: '湖南', guangdong: '广东',
    hainan: '海南', sichuan: '四川', guizhou: '贵州', yunnan: '云南', shaanxi: '陕西',
    gansu: '甘肃', qinghai: '青海', innerMongolia: '内蒙古', guangxi: '广西',
    tibet: '西藏', ningxia: '宁夏', xinjiang: '新疆'
  };

  function localizeGeoISPDisplayName(rawDisplayName, value) {
    const raw = String(rawDisplayName || '').trim();
    if (!raw) return String(value || '');
    if (!raw.startsWith('multilanguage.')) return raw;
    const key = raw.split('.').pop() || '';
    if (GEO_ISP_KEY_ZH[key]) return GEO_ISP_KEY_ZH[key];
    // Convert camelCase key to Title Case and look up in our global 170-country Chinese table
    const spaced = key.replace(/([a-z])([A-Z])/g, '$1 $2');
    const titled = spaced.replace(/\b\w/g, (c) => c.toUpperCase());
    if (WORLD_COUNTRY_ZH[titled]) return WORLD_COUNTRY_ZH[titled];
    return titled || String(value || raw);
  }

  function getGeoISPOptionsForProvider(providerType, zonePlan = '') {
    const groups = state.axisnowMeta?.providers || [];
    const wanted = providerType || state.domainsAxisNowProviderType || 'alibaba-cloud';
    const match = groups.find((g) => g.provider_type === wanted) || groups[0];
    const planList = match?.list || [];
    const pickedPlan = (zonePlan && planList.find((pl) => pl.provider_plan === zonePlan)) || planList[0];
    const options = pickedPlan?.options || [];
    const flatGroups = [];
    const labelByValue = new Map([['default', '默认兜底线路']]);
    const walk = (items, groupName) => {
      const bucket = [];
      (items || []).forEach((it) => {
        if (!it) return;
        const localized = localizeGeoISPDisplayName(it.displayName, it.value);
        if (Array.isArray(it.children) && it.children.length) {
          if (!it.disabled && it.value) {
            bucket.push({ value: it.value, label: localized });
            labelByValue.set(it.value, localized);
          }
          walk(it.children, localized || groupName);
        } else if (!it.disabled && it.value) {
          bucket.push({ value: it.value, label: localized });
          labelByValue.set(it.value, localized);
        }
      });
      if (bucket.length) flatGroups.push({ group: groupName || '常用线路', items: bucket });
    };
    walk(options, '基础线路');
    return { providerType: match?.provider_type || wanted, groups: flatGroups, labelByValue };
  }

  function ensureSmartDNSDraft(existingSmart, fallbackNodeIDs) {
    const baseNodes = Array.isArray(fallbackNodeIDs) ? [...fallbackNodeIDs] : [];
    const src = existingSmart && typeof existingSmart === 'object' ? existingSmart : {};
    const lines = Array.isArray(src.lines) && src.lines.length
      ? src.lines.map((l) => ({
          id: l.id || '',
          geo_isp: l.geo_isp || 'default',
          label: l.label || (l.geo_isp === 'default' ? '默认兜底线路' : l.geo_isp || ''),
          node_ids: Array.isArray(l.node_ids) ? [...l.node_ids] : [],
          election_strategy: l.election_strategy === 'random' ? 'random' : 'priority_order',
          ip_quantity: Math.max(1, Number(l.ip_quantity) || 1),
          auto_pause_on_empty: l.geo_isp !== 'default' && l.auto_pause_on_empty !== false,
          enabled: l.enabled !== false || l.geo_isp === 'default',
          axisnow_rule_uuid: l.axisnow_rule_uuid || '',
          active_node_ids: Array.isArray(l.active_node_ids) ? [...l.active_node_ids] : [],
          active_ips: Array.isArray(l.active_ips) ? [...l.active_ips] : [],
          status: l.status || '',
          last_error: l.last_error || ''
        }))
      : [{
          id: 'ln_default',
          geo_isp: 'default',
          label: '默认兜底线路',
          node_ids: baseNodes,
          election_strategy: 'priority_order',
          ip_quantity: 1,
          auto_pause_on_empty: false,
          enabled: true
        }];
    if (!lines.some((l) => l.geo_isp === 'default')) {
      lines.unshift({
        id: 'ln_default',
        geo_isp: 'default',
        label: '默认兜底线路',
        node_ids: baseNodes,
        election_strategy: 'priority_order',
        ip_quantity: 1,
        auto_pause_on_empty: false,
        enabled: true
      });
    }
    return {
      profile_id: src.profile_id || '',
      profile_name: src.profile_name || '',
      provider_uuid: src.provider_uuid || '',
      provider_source: src.provider_source || 'platform',
      provider_type: src.provider_type || state.domainsAxisNowProviderType || 'alibaba-cloud',
      zone_uuid: src.zone_uuid || '',
      zone_name: src.zone_name || '',
      zone_plan: src.zone_plan || '',
      routing_domain_uuid: src.routing_domain_uuid || '',
      routing_domain_host: src.routing_domain_host || '',
      auto_cf_cname: src.auto_cf_cname !== undefined ? Boolean(src.auto_cf_cname) : state.domainsCFEnabled,
      cf_cname_synced: Boolean(src.cf_cname_synced),
      cf_cname_status: src.cf_cname_status || '',
      cf_cname_status_note: src.cf_cname_status_note || '',
      lines
    };
  }

  function buildSmartDNSPresetLines(kind, providerType, poolNodeIDs) {
    const poolNodes = Array.isArray(poolNodeIDs) && poolNodeIDs.length
      ? [...poolNodeIDs]
      : (state.nodesData || []).map((n) => n.id);
    const nodeByID = new Map((state.nodesData || []).map((n) => [n.id, n]));
    const pickMatching = (re) => {
      const matched = poolNodes.filter((id) => {
        const n = nodeByID.get(id);
        return n && re.test(`${n.name} ${n.region} ${n.group_name || ''}`);
      });
      const rest = poolNodes.filter((id) => !matched.includes(id));
      return [...matched, ...rest];
    };
    const pType = providerType || state.domainsAxisNowProviderType || 'alibaba-cloud';
    if (kind === 'cn3') {
      const isDNSPod = pType === 'dnspod';
      return [
        { id: 'ln_default', geo_isp: 'default', label: '默认兜底线路', node_ids: [...poolNodes], election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: false, enabled: true },
        { id: '', geo_isp: isDNSPod ? '10=0' : 'telecom', label: '中国电信', node_ids: pickMatching(/cn2|gia|电信|ct|9929|us|sg|hk/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true },
        { id: '', geo_isp: isDNSPod ? '10=1' : 'unicom', label: '中国联通', node_ids: pickMatching(/9929|联通|cu|de|德国|jp/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true },
        { id: '', geo_isp: isDNSPod ? '10=3' : 'mobile', label: '中国移动', node_ids: pickMatching(/cmi|iij|移动|cmcc|jp|日本|hk|sg/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true }
      ];
    }
    if (pType === 'aws-route53') {
      return [
        { id: 'ln_default', geo_isp: 'default', label: '默认兜底线路', node_ids: [...poolNodes], election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: false, enabled: true },
        { id: '', geo_isp: 'AS-CN', label: '中国大陆', node_ids: pickMatching(/9929|cn2|iij|jp|hk|sg|de/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true },
        { id: '', geo_isp: 'EU', label: '欧洲', node_ids: pickMatching(/de|德国|eu|uk|nl|fr/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true },
        { id: '', geo_isp: 'AS', label: '亚洲', node_ids: pickMatching(/jp|日本|sg|hk|kr/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true }
      ];
    }
    const isDNSPod = pType === 'dnspod';
    return [
      { id: 'ln_default', geo_isp: 'default', label: '国内默认线路', node_ids: pickMatching(/9929|cn2|iij|jp|hk|sg|de/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: false, enabled: true },
      { id: '', geo_isp: isDNSPod ? '3=0' : 'oversea', label: '海外地区', node_ids: pickMatching(/us|eu|de|jp|sg|uk/i), election_strategy: 'priority_order', ip_quantity: 1, auto_pause_on_empty: true, enabled: true }
    ];
  }

  /* ---- Simplified 1-click Profile Picker inside Domain Drawer Step 3 ---- */
  function renderDomainSmartProfilePicker() {
    const picker = document.getElementById('domain-smart-profile-picker');
    const emptyEl = document.getElementById('domain-smart-profile-empty');
    const previewEl = document.getElementById('domain-smart-profile-preview');
    const hostInput = document.getElementById('domain-smart-routing-host');
    const hostHint = document.getElementById('domain-smart-cname-hint');
    const cfToggle = document.getElementById('domain-smart-auto-cf-cname');
    if (!picker) return;

    const draft = ensureSmartDNSDraft(state.domainSmartDNSDraft, state.domainBoundNodeIDs);
    state.domainSmartDNSDraft = draft;
    const profiles = Array.isArray(state.smartDNSProfiles) ? state.smartDNSProfiles : [];
    const nodeByID = new Map((state.nodesData || []).map((n) => [n.id, n]));

    if (!draft.profile_id && profiles.length && !(state.domainEditingID && draft.lines?.length > 1)) {
      draft.profile_id = profiles[0].id;
      draft.profile_name = profiles[0].name;
      if (profiles[0].auto_cf_cname !== undefined) draft.auto_cf_cname = Boolean(profiles[0].auto_cf_cname);
    }

    if (hostInput && document.activeElement !== hostInput) hostInput.value = draft.routing_domain_host || '';
    if (cfToggle) cfToggle.checked = Boolean(draft.auto_cf_cname);
    if (hostHint) {
      const cfSuffix = draft.cf_cname_synced
        ? '（Cloudflare CNAME 已生效）'
        : (draft.auto_cf_cname && draft.cf_cname_status === 'pending'
          ? `（${draft.cf_cname_status_note || '等待 AxisNow 解析生效后自动切换 Cloudflare CNAME'}）`
          : (draft.auto_cf_cname && draft.cf_cname_status === 'error'
            ? `（Cloudflare CNAME 异常：${draft.cf_cname_status_note || '请检查配置与权限'}）`
            : ''));
      hostHint.textContent = draft.routing_domain_host
        ? `当前调度域名：${draft.routing_domain_host}${cfSuffix}`
        : '平台托管模式：留空将自动复用同一分流方案的共享 CNAME 调度域（节省 AxisNow 免费配额）';
    }

    if (!profiles.length) {
      picker.replaceChildren();
      if (emptyEl) emptyEl.hidden = false;
      if (previewEl) previewEl.hidden = true;
      refreshIcons();
      return;
    }
    if (emptyEl) emptyEl.hidden = true;

    const frag = document.createDocumentFragment();
    profiles.forEach((p) => {
      const selected = draft.profile_id === p.id;
      const card = el('button', `domain-smart-profile-card${selected ? ' selected' : ''}`);
      card.type = 'button';
      card.setAttribute('role', 'radio');
      card.setAttribute('aria-checked', String(selected));
      const top = el('div', 'domain-smart-profile-card-top');
      top.append(
        el('strong', '', p.name),
        el('span', `badge ${selected ? 'badge-accent' : ''}`, `${(p.lines || []).length} 条线路`)
      );
      const lineNames = (p.lines || []).map((l) => l.label || l.geo_isp).slice(0, 4).join(' / ');
      card.append(top, el('small', '', p.description || `包含：${lineNames || '默认兜底线路'}`));
      card.addEventListener('click', () => {
        draft.profile_id = p.id;
        draft.profile_name = p.name;
        draft.auto_cf_cname = Boolean(p.auto_cf_cname);
        renderDomainSmartProfilePicker();
        updateDomainStep3UI();
      });
      frag.append(card);
    });
    picker.replaceChildren(frag);

    const chosen = profiles.find((p) => p.id === draft.profile_id);
    if (previewEl) {
      if (!chosen) {
        previewEl.hidden = true;
      } else {
        previewEl.hidden = false;
        const pFrag = document.createDocumentFragment();
        const head = el('div', 'cell-meta-row');
        head.append(
          el('strong', '', `已选方案「${chosen.name}」分流明细`),
          el('span', 'badge badge-sky', chosen.zone_name ? `${formatAxisNowProviderType(chosen.provider_type)} · ${chosen.zone_name}` : '跟随默认调度域')
        );
        pFrag.append(head);
        (chosen.lines || []).forEach((ln) => {
          const row = el('div', 'dns-profile-line-row');
          const lbl = el('span', 'dns-profile-line-label', `${ln.label || ln.geo_isp} (${ln.geo_isp})`);
          const nWrap = el('div', 'dns-profile-line-nodes');
          const nList = (ln.node_ids || []).map((id, i) => {
            const n = nodeByID.get(id);
            return `#${i + 1} ${n ? n.name : id}`;
          });
          nWrap.append(el('span', '', nList.length ? nList.join(' → ') : '未指定节点'));
          row.append(lbl, nWrap);
          pFrag.append(row);
        });
        previewEl.replaceChildren(pFrag);
      }
    }
    refreshIcons();
  }

  /* ==================== DEDICATED DNS & ROUTING HUB ==================== */

  function setDNSHubTab(tab, { refreshProviders = true } = {}) {
    const next = ['profiles', 'domains', 'providers'].includes(tab) ? tab : 'profiles';
    state.dnsHubTab = next;
    document.querySelectorAll('#dns-hub-tabs button').forEach((btn) => {
      const active = btn.dataset.dnsTab === next;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    syncSegmented(document.getElementById('dns-hub-tabs'));
    ['profiles', 'domains', 'providers'].forEach((k) => {
      const pane = document.getElementById(`dns-pane-${k}`);
      if (pane) pane.hidden = k !== next;
    });
    const quickBtn = document.getElementById('dns-quick-cn3-btn');
    const createBtn = document.getElementById('dns-create-profile-btn');
    if (quickBtn) quickBtn.hidden = next !== 'profiles';
    if (createBtn) createBtn.hidden = next !== 'profiles';
    if (next === 'providers' && refreshProviders) {
      Promise.all([refreshAxisNowDNS().catch(() => {}), refreshCloudflareDNS().catch(() => {})]);
    }
    if (next === 'domains') {
      renderDNSDomainsTable();
    }
    refreshIcons();
  }

  async function openDNSHubTab(tab = 'profiles') {
    state.dnsHubTab = ['profiles', 'domains', 'providers'].includes(tab) ? tab : 'profiles';
    if (state.view === 'dns') {
      setDNSHubTab(state.dnsHubTab, { refreshProviders: true });
      return;
    }
    await switchView('dns');
  }

  async function refreshSmartDNSProfiles() {
    if (state.smartDNSProfilesPromise) return state.smartDNSProfilesPromise;
    const req = api('/_admin/api/smart-dns-profiles').then((payload) => {
      state.smartDNSProfiles = Array.isArray(payload?.profiles) ? payload.profiles : [];
      state.domainsAxisNowEnabled = Boolean(payload?.axisnow_enabled);
      state.domainsAxisNowProviderType = payload?.axisnow_provider_type || '';
      state.domainsAxisNowDefaultZone = payload?.axisnow_default_zone || '';
      if (Array.isArray(payload?.axisnow_providers)) state.domainsAxisNowProviders = payload.axisnow_providers;
      state.domainsCFEnabled = Boolean(payload?.cf_enabled);
      state.domainsCFRoot = payload?.cf_root_domain || '';
      const navBadge = document.getElementById('nav-dns-badge');
      if (navBadge) {
        navBadge.textContent = String(state.smartDNSProfiles.length);
        navBadge.hidden = state.smartDNSProfiles.length === 0;
      }
      if (state.view === 'dns') renderDNSHub();
      return payload;
    });
    state.smartDNSProfilesPromise = req;
    try { return await req; } finally {
      if (state.smartDNSProfilesPromise === req) state.smartDNSProfilesPromise = null;
    }
  }

  function renderDNSHub() {
    const profiles = state.smartDNSProfiles || [];
    const domains = state.domainsData || [];
    const nodeByID = new Map((state.nodesData || []).map((n) => [n.id, n]));
    const boundDomainCount = domains.filter((d) => d.dns_mode === 'axisnow_smart' && d.smart_dns?.profile_id).length;
    const managedCount = domains.filter((d) => d.dns_mode !== 'manual').length;

    const kProf = document.getElementById('dns-kpi-profiles');
    if (kProf) kProf.textContent = formatNumber(profiles.length);
    const kProfSub = document.getElementById('dns-kpi-profiles-sub');
    if (kProfSub) kProfSub.textContent = boundDomainCount ? `已绑定 ${boundDomainCount} 个反代域名` : '建好方案即可一键绑定域名';

    const kDom = document.getElementById('dns-kpi-domains');
    if (kDom) kDom.textContent = formatNumber(managedCount);
    const kDomSub = document.getElementById('dns-kpi-domains-sub');
    if (kDomSub) kDomSub.textContent = `全部域名共 ${formatNumber(domains.length)} 个`;

    const kAn = document.getElementById('dns-kpi-axisnow');
    if (kAn) kAn.textContent = state.domainsAxisNowEnabled ? '已连接' : '未启用';
    const kAnSub = document.getElementById('dns-kpi-axisnow-sub');
    if (kAnSub) {
      kAnSub.textContent = state.domainsAxisNowEnabled
        ? `${formatAxisNowProviderType(state.domainsAxisNowProviderType)}${state.domainsAxisNowDefaultZone ? ` · ${state.domainsAxisNowDefaultZone}` : ''}`
        : '前往「服务商接入」填 Token';
    }

    const kCF = document.getElementById('dns-kpi-cf');
    if (kCF) kCF.textContent = state.domainsCFEnabled ? '已连接' : '未启用';
    const kCFSub = document.getElementById('dns-kpi-cf-sub');
    if (kCFSub) {
      kCFSub.textContent = state.domainsCFEnabled
        ? `根域：${state.domainsCFRoot || 'Zone 已就绪'}`
        : '配置后支持自动灰云 CNAME 与证书';
    }

    const grid = document.getElementById('dns-profiles-grid');
    const empty = document.getElementById('dns-profiles-empty');
    if (grid && empty) {
      if (!profiles.length) {
        grid.replaceChildren();
        grid.hidden = true;
        empty.hidden = false;
      } else {
        grid.hidden = false;
        empty.hidden = true;
        const frag = document.createDocumentFragment();
        profiles.forEach((p) => {
          const card = el('article', 'dns-profile-card');
          const head = el('div', 'dns-profile-head');
          const titleWrap = el('div', 'dns-profile-title-wrap');
          const titleRow = el('div', 'dns-profile-title-row');
          titleRow.append(
            el('strong', '', p.name),
            el('span', 'badge badge-accent', `${(p.lines || []).length} 条线路`)
          );
          if (p.zone_name) {
            titleRow.append(el('span', 'meta-tag sky', `${formatAxisNowProviderType(p.provider_type)} · ${p.zone_name}`));
          } else {
            titleRow.append(el('span', 'meta-tag', '跟随默认调度域'));
          }
          if (p.auto_cf_cname) {
            titleRow.append(el('span', 'meta-tag', '自动 CF CNAME'));
          }
          titleWrap.append(titleRow);
          if (p.description) titleWrap.append(el('small', '', p.description));

          const headActs = el('div', 'row-actions');
          const editBtn = el('button', 'icon-btn');
          editBtn.type = 'button'; editBtn.title = '编辑此分流方案'; editBtn.setAttribute('aria-label', '编辑此分流方案');
          editBtn.innerHTML = '<i data-lucide="sliders-horizontal"></i>';
          editBtn.addEventListener('click', () => openDNSProfileDrawer({ profile: p }));
          const delBtn = el('button', 'icon-btn danger');
          delBtn.type = 'button'; delBtn.title = '删除分流方案'; delBtn.setAttribute('aria-label', '删除分流方案');
          delBtn.innerHTML = '<i data-lucide="trash-2"></i>';
          delBtn.addEventListener('click', () => deleteDNSProfile(p, delBtn));
          headActs.append(editBtn, delBtn);
          head.append(titleWrap, headActs);

          // Routing lines breakdown
          const linesBox = el('div', 'dns-profile-lines');
          (p.lines || []).forEach((ln) => {
            const row = el('div', 'dns-profile-line-row');
            const left = el('span', 'dns-profile-line-label');
            left.append(
              el('span', `badge ${ln.geo_isp === 'default' ? 'badge-accent' : ''}`, ln.label || ln.geo_isp),
              el('span', 'cell-secondary mono', ln.geo_isp)
            );
            const right = el('div', 'dns-profile-line-nodes');
            if (!ln.node_ids?.length) {
              right.append(el('span', 'cell-secondary', '未选节点'));
            } else {
              ln.node_ids.forEach((nid, idx) => {
                const n = nodeByID.get(nid);
                const chip = el('span', 'smart-dns-table-chip');
                const dotCls = n?.status === 'online' ? 'status-dot' : n?.status === 'draining' ? 'status-dot amber' : 'status-dot rose';
                chip.append(el('span', dotCls), el('span', '', `#${idx + 1} ${n ? n.name : nid}`));
                right.append(chip);
              });
            }
            row.append(left, right);
            linesBox.append(row);
          });

          // Bound domains pills
          const boundRow = el('div', 'dns-profile-bound-row');
          const boundList = Array.isArray(p.bound_domains) ? p.bound_domains : [];
          if (!boundList.length) {
            boundRow.append(el('span', '', '暂未绑定域名 · 点击下方「绑定域名」即可生效'));
          } else {
            boundRow.append(el('span', '', `已绑定 ${boundList.length} 个域名：`));
            boundList.forEach((bd) => {
              const hasErr = Boolean(bd.dns_last_error || bd.cf_cname_status === 'error');
              const isPending = !hasErr && Boolean(bd.auto_cf_cname && !bd.cf_cname_synced && bd.cf_cname_status === 'pending');
              const badgeCls = hasErr ? 'badge-rose' : isPending ? 'badge-amber' : 'badge-emerald';
              const label = isPending ? `${bd.domain} · 待切 CNAME` : bd.domain;
              const b = el('span', `badge ${badgeCls}`, label);
              const tipParts = [
                bd.routing_domain_host ? `CNAME → ${bd.routing_domain_host}` : '',
                bd.cf_cname_status_note || '',
                bd.dns_last_error ? `异常：${bd.dns_last_error}` : ''
              ].filter(Boolean);
              if (tipParts.length) b.title = tipParts.join(' · ');
              boundRow.append(b);
            });
          }

          // Footer CTA bar
          const foot = el('div', 'dns-profile-foot');
          const footLeft = el('div', 'surface-tools');
          const bindBtn = el('button', 'btn btn-primary btn-sm', '');
          bindBtn.type = 'button';
          bindBtn.innerHTML = `<i data-lucide="link-2"></i><span>绑定域名 (${boundList.length})</span>`;
          bindBtn.addEventListener('click', () => openDNSBindDialog(p));

          const editCta = el('button', 'btn btn-secondary btn-sm', '');
          editCta.type = 'button';
          editCta.innerHTML = '<i data-lucide="sliders-horizontal"></i><span>编排线路</span>';
          editCta.addEventListener('click', () => openDNSProfileDrawer({ profile: p }));
          footLeft.append(bindBtn, editCta);

          if (boundList.length > 0) {
            const syncBtn = el('button', 'btn btn-ghost btn-sm', '');
            syncBtn.type = 'button';
            syncBtn.innerHTML = '<i data-lucide="refresh-cw"></i><span>同步已绑域名</span>';
            syncBtn.addEventListener('click', () => syncDNSProfileNow(p, syncBtn));
            foot.append(footLeft, syncBtn);
          } else {
            foot.append(footLeft, el('span', 'cell-secondary', `更新于 ${relativeTime(p.updated_at)}`));
          }

          card.append(head, linesBox, boundRow, foot);
          frag.append(card);
        });
        grid.replaceChildren(frag);
      }
    }

    renderDNSDomainsTable();
    refreshIcons();
  }

  function renderDNSDomainsTable() {
    const tbody = document.getElementById('dns-domains-table');
    const empty = document.getElementById('dns-domains-empty');
    if (!tbody || !empty) return;
    const domains = state.domainsData || [];
    if (!domains.length) {
      tbody.replaceChildren();
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    const frag = document.createDocumentFragment();
    domains.forEach((d) => {
      const tr = document.createElement('tr');
      const domTd = el('td');
      const domStack = el('div', 'cell-stack');
      domStack.append(el('strong', 'cell-primary mono', d.domain));
      if (d.name && d.name !== d.domain) domStack.append(el('span', 'cell-secondary', d.name));
      domTd.append(domStack);

      const modeTd = el('td');
      if (d.dns_mode === 'axisnow_smart') {
        const name = d.smart_dns?.profile_name;
        modeTd.append(el('span', 'badge badge-emerald', name ? `分流方案 · ${name}` : 'AxisNow 智能分流'));
      } else if (d.dns_mode === 'cloudflare_failover') {
        modeTd.append(el('span', 'badge badge-sky', 'CF 主备切线'));
      } else if (d.dns_mode === 'cloudflare_all') {
        modeTd.append(el('span', 'badge badge-accent', 'CF 多机同步'));
      } else {
        modeTd.append(el('span', 'badge', '手动解析'));
      }

      const detailTd = el('td');
      const dStack = el('div', 'cell-stack');
      if (d.dns_mode === 'axisnow_smart') {
        const smart = d.smart_dns || {};
        if (smart.routing_domain_host) {
          dStack.append(el('span', 'cell-secondary mono', `CNAME → ${smart.routing_domain_host}`));
        }
        if (smart.auto_cf_cname && !smart.cf_cname_synced && (smart.cf_cname_status === 'pending' || smart.cf_cname_status === 'error')) {
          const defaultNote = smart.cf_cname_status === 'error'
            ? 'Cloudflare CNAME 切换异常，请检查 Cloudflare 配置与权限'
            : '等待 AxisNow 解析生效后自动切换 Cloudflare CNAME';
          const noteSpan = el('span', 'cell-secondary', smart.cf_cname_status_note || defaultNote);
          noteSpan.title = noteSpan.textContent;
          dStack.append(noteSpan);
        }
        const lines = smart.lines || [];
        if (lines.length) {
          const wrap = el('div', 'smart-dns-table-lines');
          const nodeNameMap = new Map((d.bound_nodes || []).map((bn) => [bn.id, bn.name]));
          lines.slice(0, 4).forEach((ln) => {
            const names = (ln.active_node_ids?.length ? ln.active_node_ids : (ln.node_ids || []))
              .map((nid) => nodeNameMap.get(nid) || nid).slice(0, 2).join('/');
            const cls = ln.status === 'error' ? ' is-error' : ln.status === 'paused' ? ' is-paused' : '';
            const chip = el('span', `smart-dns-table-chip${cls}`, `${ln.label || ln.geo_isp}→${names || '未选'}`);
            chip.title = ln.last_error || `${ln.label || ln.geo_isp} (${ln.geo_isp})${ln.active_ips?.length ? ` · ${ln.active_ips.join(', ')}` : ''}`;
            wrap.append(chip);
          });
          dStack.append(wrap);
        }
      } else if (d.dns_active_node_name) {
        dStack.append(el('span', 'cell-secondary', `主用指向：${d.dns_active_node_name}`));
      } else {
        dStack.append(el('span', 'cell-secondary', `已绑 ${d.healthy_node_count}/${d.total_node_count} 台在线机器`));
      }
      detailTd.append(dStack);

      const stTd = el('td');
      if (d.dns_last_error) {
        const eb = el('span', 'badge badge-rose', '同步异常');
        eb.title = d.dns_last_error;
        stTd.append(eb);
      } else if (d.dns_mode === 'axisnow_smart' && d.smart_dns?.auto_cf_cname && !d.smart_dns?.cf_cname_synced && d.smart_dns?.cf_cname_status === 'error') {
        const eb = el('span', 'badge badge-rose', 'CF CNAME 异常');
        eb.title = d.smart_dns.cf_cname_status_note || 'Cloudflare CNAME 切换失败，请检查配置与权限';
        stTd.append(eb);
      } else if (d.dns_mode === 'axisnow_smart' && d.smart_dns?.auto_cf_cname && !d.smart_dns?.cf_cname_synced && d.smart_dns?.cf_cname_status === 'pending') {
        const pb = el('span', 'badge badge-amber', '等待生效切 CNAME');
        pb.title = d.smart_dns.cf_cname_status_note || '公网 DNS 尚未解析出有效 IP，暂保留原 Cloudflare 记录，生效后将自动切换';
        stTd.append(pb);
      } else if (d.dns_last_sync_at) {
        stTd.append(el('span', 'badge badge-emerald', relativeTime(d.dns_last_sync_at)));
      } else {
        stTd.append(el('span', 'cell-secondary', d.dns_mode === 'manual' ? '手动维护' : '等待同步'));
      }

      const actTd = el('td', 'actions-col');
      const actRow = el('div', 'row-actions');
      const cfgBtn = el('button', 'btn btn-secondary btn-sm', '切换解析');
      cfgBtn.type = 'button';
      cfgBtn.addEventListener('click', async () => {
        await openDomainDrawerForEdit(d);
        setDomainWizardStep(3, { skipValidate: true });
      });
      actRow.append(cfgBtn);
      if (d.dns_mode !== 'manual') {
        const sBtn = el('button', 'icon-btn');
        sBtn.type = 'button'; sBtn.title = '立即同步 DNS'; sBtn.setAttribute('aria-label', '立即同步 DNS');
        sBtn.innerHTML = '<i data-lucide="refresh-cw"></i>';
        sBtn.addEventListener('click', () => syncDomainDNS(d, sBtn));
        actRow.append(sBtn);
      }
      actTd.append(actRow);
      tr.append(domTd, modeTd, detailTd, stTd, actTd);
      frag.append(tr);
    });
    tbody.replaceChildren(frag);
    refreshIcons();
  }

  /* ---- Wide Smart DNS Profile Editor Drawer ---- */
  async function openDNSProfileDrawer({ profile = null, preset = '' } = {}) {
    await Promise.all([
      state.nodesData.length ? Promise.resolve() : refreshNodes().catch(() => {}),
      ensureAxisNowMetadata(false)
    ]);
    state.dnsProfileEditingID = profile ? profile.id : null;
    const pType = profile?.provider_type || state.domainsAxisNowProviderType || 'alibaba-cloud';
    const initialLines = profile?.lines?.length
      ? profile.lines.map((l) => ({
          id: l.id || '',
          geo_isp: l.geo_isp || 'default',
          label: l.label || l.geo_isp || '默认兜底线路',
          node_ids: Array.isArray(l.node_ids) ? [...l.node_ids] : [],
          election_strategy: l.election_strategy === 'random' ? 'random' : 'priority_order',
          ip_quantity: Math.max(1, Number(l.ip_quantity) || 1),
          auto_pause_on_empty: l.geo_isp !== 'default' && l.auto_pause_on_empty !== false,
          enabled: l.enabled !== false || l.geo_isp === 'default'
        }))
      : (preset
        ? buildSmartDNSPresetLines(preset, pType, [])
        : [{
            id: 'ln_default',
            geo_isp: 'default',
            label: '默认兜底线路',
            node_ids: (state.nodesData || []).map((n) => n.id),
            election_strategy: 'priority_order',
            ip_quantity: 1,
            auto_pause_on_empty: false,
            enabled: true
          }]);

    state.dnsProfileDraft = {
      name: profile ? profile.name : (preset === 'cn3' ? '中国三网优化' : preset === 'geo' ? '海内外就近分流' : ''),
      description: profile ? (profile.description || '') : (preset === 'cn3' ? '按电信 / 联通 / 移动分别解析最优节点，故障自动切线' : ''),
      provider_uuid: profile?.provider_uuid || '',
      provider_source: profile?.provider_source || 'platform',
      provider_type: pType,
      zone_uuid: profile?.zone_uuid || '',
      zone_name: profile?.zone_name || '',
      zone_plan: profile?.zone_plan || '',
      auto_cf_cname: profile ? Boolean(profile.auto_cf_cname) : true,
      lines: initialLines
    };

    document.getElementById('dns-prof-drawer-title').textContent = profile ? `编辑分流方案 · ${profile.name}` : '新建智能分流方案';
    document.getElementById('dns-prof-drawer-subtitle').textContent = profile
      ? '修改保存后会自动热同步到所有已绑定该方案的反代域名'
      : '先编排好地区与运营商分流规则，保存后可随时绑定到任意域名';
    document.getElementById('dns-prof-name').value = state.dnsProfileDraft.name;
    document.getElementById('dns-prof-desc').value = state.dnsProfileDraft.description;
    document.getElementById('dns-prof-auto-cf').checked = state.dnsProfileDraft.auto_cf_cname;
    document.getElementById('dns-prof-error').hidden = true;

    renderDNSProfileEditor();
    openDrawer('dns-profile-drawer');
    window.setTimeout(() => document.getElementById('dns-prof-name')?.focus(), 60);
  }

  function renderDNSProfileEditor() {
    const listEl = document.getElementById('dns-prof-lines-list');
    const provSel = document.getElementById('dns-prof-provider');
    const draft = state.dnsProfileDraft;
    if (!listEl || !draft) return;

    const choices = buildAxisNowProviderChoices(state.domainsAxisNowProviders);
    if (provSel) {
      const curKey = draft.provider_uuid ? `${draft.provider_uuid}|${draft.zone_uuid || ''}` : '';
      const pFrag = document.createDocumentFragment();
      const defOpt = document.createElement('option');
      defOpt.value = '';
      defOpt.textContent = state.domainsAxisNowDefaultZone
        ? `跟随系统默认（${formatAxisNowProviderType(state.domainsAxisNowProviderType)} · ${state.domainsAxisNowDefaultZone}）`
        : '跟随系统默认调度域';
      pFrag.append(defOpt);
      choices.forEach((c) => {
        const opt = document.createElement('option');
        opt.value = c.key;
        opt.textContent = c.label;
        pFrag.append(opt);
      });
      provSel.replaceChildren(pFrag);
      provSel.value = choices.some((c) => c.key === curKey) ? curKey : '';
    }

    const effectiveProviderType = draft.provider_type || state.domainsAxisNowProviderType || 'alibaba-cloud';
    const geoCatalog = getGeoISPOptionsForProvider(effectiveProviderType, draft.zone_plan);
    const allNodes = state.nodesData || [];
    const frag = document.createDocumentFragment();

    draft.lines.forEach((line, lineIdx) => {
      const isDefault = line.geo_isp === 'default';
      const card = el('div', `smart-line-card${isDefault ? ' is-default' : ''}`);

      const top = el('div', 'smart-line-top');
      const geoWrap = el('div', 'smart-line-geo-wrap');
      if (isDefault) {
        geoWrap.append(el('span', 'badge badge-accent', '默认兜底线路 (default)'));
      } else {
        const geoSel = document.createElement('select');
        geoSel.setAttribute('aria-label', '选择地区或运营商线路');
        let matchedOpt = false;
        geoCatalog.groups.forEach((grp) => {
          const og = document.createElement('optgroup');
          og.label = grp.group;
          grp.items.forEach((it) => {
            if (it.value === 'default') return;
            const opt = document.createElement('option');
            opt.value = it.value;
            opt.textContent = `${it.label} (${it.value})`;
            if (it.value === line.geo_isp) matchedOpt = true;
            og.append(opt);
          });
          if (og.children.length) geoSel.append(og);
        });
        const customOpt = document.createElement('option');
        customOpt.value = '__custom__';
        customOpt.textContent = '自定义线路代码…';
        geoSel.append(customOpt);
        geoSel.value = matchedOpt ? line.geo_isp : '__custom__';

        const customInput = document.createElement('input');
        customInput.type = 'text';
        customInput.placeholder = '输入 AxisNow geo_isp 代码';
        customInput.value = matchedOpt ? '' : (line.geo_isp || '');
        customInput.hidden = matchedOpt;
        customInput.addEventListener('input', (ev) => {
          const v = ev.currentTarget.value.trim();
          line.geo_isp = v;
          line.label = geoCatalog.labelByValue.get(v) || v || '自定义线路';
        });

        geoSel.addEventListener('change', (ev) => {
          const v = ev.currentTarget.value;
          if (v === '__custom__') {
            customInput.hidden = false;
            customInput.value = line.geo_isp === '__custom__' ? '' : (line.geo_isp || '');
            customInput.focus();
          } else {
            customInput.hidden = true;
            line.geo_isp = v;
            line.label = geoCatalog.labelByValue.get(v) || v;
          }
        });
        geoWrap.append(geoSel, customInput);
      }

      const stratWrap = el('div', 'smart-line-strategy-wrap');
      const stratSel = document.createElement('select');
      stratSel.setAttribute('aria-label', '选择调度策略');
      [
        ['priority_order', '主备按序切线'],
        ['random', '多 IP 轮询']
      ].forEach(([val, txt]) => {
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = txt;
        stratSel.append(opt);
      });
      stratSel.value = line.election_strategy === 'random' ? 'random' : 'priority_order';
      stratSel.addEventListener('change', (ev) => {
        line.election_strategy = ev.currentTarget.value;
        if (line.election_strategy === 'random' && line.ip_quantity < 2 && line.node_ids.length >= 2) {
          line.ip_quantity = line.node_ids.length;
        }
        renderDNSProfileEditor();
      });

      const qtyWrap = el('label', 'smart-line-qty');
      const qtyInput = document.createElement('input');
      qtyInput.type = 'number';
      qtyInput.min = '1';
      qtyInput.max = '50';
      qtyInput.value = String(line.ip_quantity || 1);
      qtyInput.addEventListener('input', (ev) => {
        line.ip_quantity = Math.max(1, Math.min(50, Number(ev.currentTarget.value) || 1));
      });
      qtyWrap.append(el('span', '', '返回'), qtyInput, el('span', '', 'IP'));
      stratWrap.append(stratSel, qtyWrap);

      if (!isDefault) {
        const delBtn = el('button', 'icon-btn danger');
        delBtn.type = 'button';
        delBtn.title = '删除此线路';
        delBtn.setAttribute('aria-label', '删除此线路');
        delBtn.innerHTML = '<i data-lucide="trash-2"></i>';
        delBtn.addEventListener('click', () => {
          draft.lines.splice(lineIdx, 1);
          renderDNSProfileEditor();
        });
        stratWrap.append(delBtn);
      }
      top.append(geoWrap, stratWrap);

      const nodesRow = el('div', 'smart-line-nodes');
      if (!allNodes.length) {
        nodesRow.append(el('span', 'field-hint', '暂无边缘节点，请先在「边缘节点」接入机器'));
      } else {
        const selectedSet = new Set(line.node_ids);
        const orderedNodes = [
          ...line.node_ids.map((id) => allNodes.find((n) => n.id === id)).filter(Boolean),
          ...allNodes.filter((n) => !selectedSet.has(n.id))
        ];
        orderedNodes.forEach((n) => {
          const rank = line.node_ids.indexOf(n.id);
          const selected = rank >= 0;
          const chip = el('div', `smart-node-chip${selected ? ' selected' : ''}`);
          chip.setAttribute('role', 'button');
          chip.tabIndex = 0;
          const hasV4 = Boolean(n.effective_ipv4);
          chip.title = hasV4
            ? `${n.name} (${n.effective_ipv4}) · 点击${selected ? '移除' : '加入此线路'}`
            : `${n.name} 暂无公网 IPv4（AxisNow 仅支持 A/IPv4）`;
          if (selected) chip.append(el('span', 'smart-node-chip-rank', `#${rank + 1}`));
          const dotCls = n.status === 'online' ? 'status-dot' : n.status === 'draining' ? 'status-dot amber' : 'status-dot rose';
          chip.append(el('span', dotCls), el('span', '', `${n.name}${hasV4 ? '' : ' (无v4)'}`));

          const toggleNode = () => {
            const pos = line.node_ids.indexOf(n.id);
            if (pos >= 0) line.node_ids.splice(pos, 1);
            else line.node_ids.push(n.id);
            renderDNSProfileEditor();
          };
          chip.addEventListener('click', toggleNode);
          chip.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggleNode(); }
          });
          if (selected && line.node_ids.length > 1 && rank > 0) {
            const upBtn = el('span', 'smart-node-chip-move', '←');
            upBtn.title = '提高优先级';
            upBtn.addEventListener('click', (ev) => {
              ev.stopPropagation();
              [line.node_ids[rank - 1], line.node_ids[rank]] = [line.node_ids[rank], line.node_ids[rank - 1]];
              renderDNSProfileEditor();
            });
            chip.append(upBtn);
          }
          nodesRow.append(chip);
        });
      }

      const foot = el('div', 'smart-line-foot');
      if (!isDefault) {
        const cbLabel = el('label', 'smart-line-check');
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = Boolean(line.auto_pause_on_empty);
        cb.addEventListener('change', (ev) => { line.auto_pause_on_empty = ev.currentTarget.checked; });
        cbLabel.append(cb, el('span', '', '该线路节点全不可用时自动暂停并回退默认线路'));
        foot.append(cbLabel);
      } else {
        foot.append(el('span', '', '兜底线路：所有未命中专属线路的访客或回退流量均走此线路'));
      }
      card.append(top, nodesRow, foot);
      frag.append(card);
    });

    listEl.replaceChildren(frag);
    enhanceAllCustomSelects(listEl);
    refreshIcons();
  }

  async function saveDNSProfile(e) {
    e.preventDefault();
    const errEl = document.getElementById('dns-prof-error');
    const submit = document.getElementById('dns-prof-submit');
    errEl.hidden = true;
    const draft = state.dnsProfileDraft;
    if (!draft) return;

    const name = (document.getElementById('dns-prof-name')?.value || '').trim();
    if (!name) {
      showFormError(errEl, '请填写分流方案名称，例如「中国三网优化」');
      document.getElementById('dns-prof-name')?.focus();
      return;
    }
    const cleanLines = (draft.lines || []).filter((l) => (l.geo_isp || '').trim() !== '');
    const defLine = cleanLines.find((l) => l.geo_isp === 'default');
    if (!defLine || !defLine.node_ids.length) {
      showFormError(errEl, '请至少为「默认兜底线路」选择一台边缘节点');
      return;
    }

    const payload = {
      name,
      description: (document.getElementById('dns-prof-desc')?.value || '').trim(),
      provider_uuid: draft.provider_uuid || '',
      provider_source: draft.provider_source || 'platform',
      provider_type: draft.provider_type || '',
      zone_uuid: draft.zone_uuid || '',
      zone_name: draft.zone_name || '',
      zone_plan: draft.zone_plan || '',
      auto_cf_cname: Boolean(document.getElementById('dns-prof-auto-cf')?.checked),
      lines: cleanLines.map((l) => ({
        id: l.id || '',
        geo_isp: String(l.geo_isp || '').trim(),
        label: String(l.label || '').trim(),
        node_ids: Array.isArray(l.node_ids) ? [...l.node_ids] : [],
        election_strategy: l.election_strategy === 'random' ? 'random' : 'priority_order',
        ip_quantity: Math.max(1, Math.min(50, Number(l.ip_quantity) || 1)),
        auto_pause_on_empty: l.geo_isp !== 'default' && Boolean(l.auto_pause_on_empty),
        enabled: l.enabled !== false || l.geo_isp === 'default'
      }))
    };

    submit.disabled = true;
    try {
      if (state.dnsProfileEditingID) {
        await api(`/_admin/api/smart-dns-profiles/${encodeURIComponent(state.dnsProfileEditingID)}`, jsonOptions('PUT', payload));
        toast(`分流方案「${name}」已保存并热同步已绑定域名`);
      } else {
        await api('/_admin/api/smart-dns-profiles', jsonOptions('POST', payload));
        toast(`分流方案「${name}」已创建，现在可以随时一键绑定域名`);
      }
      closeDrawer('dns-profile-drawer');
      await Promise.all([refreshSmartDNSProfiles(), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
    } catch (failure) {
      showFormError(errEl, failure.message || '保存分流方案失败');
    } finally {
      submit.disabled = false;
    }
  }

  async function deleteDNSProfile(prof, button) {
    const boundCnt = (prof.bound_domains || []).length;
    const confirmed = await confirmAction({
      title: `删除分流方案「${prof.name}」`,
      message: boundCnt
        ? `当前有 ${boundCnt} 个域名正在使用此方案。删除方案后这些域名会自动保留现有线路快照，不会中断线上 DNS 解析。`
        : '确认删除此智能分流方案？删除后不可恢复。',
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      await api(`/_admin/api/smart-dns-profiles/${encodeURIComponent(prof.id)}`, { method: 'DELETE' });
      toast(`已删除分流方案「${prof.name}」`);
      await Promise.all([refreshSmartDNSProfiles(), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
    } catch (failure) {
      button.disabled = false;
      toast(failure.message || '删除分流方案失败', 'error');
    }
  }

  async function syncDNSProfileNow(prof, button) {
    button.disabled = true;
    try {
      const res = await api(`/_admin/api/smart-dns-profiles/${encodeURIComponent(prof.id)}/sync`, jsonOptions('POST', {}));
      toast(`方案「${prof.name}」已同步 ${res.synced_domains || 0} 个绑定域名`);
      await Promise.all([refreshSmartDNSProfiles(), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
    } catch (failure) {
      toast(failure.message || '同步失败', 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function openDNSBindDialog(prof) {
    let loadFailed = false;
    if (!state.domainsData.length) {
      try { await refreshDomains(); } catch { loadFailed = true; }
    }
    state.dnsBindProfile = prof;
    const dlg = document.getElementById('dns-bind-dialog');
    const list = document.getElementById('dns-bind-list');
    const empty = document.getElementById('dns-bind-empty');
    const errEl = document.getElementById('dns-bind-error');
    const submitBtn = document.getElementById('dns-bind-submit');
    if (!dlg || !list) return;
    errEl.hidden = true;
    document.getElementById('dns-bind-title').textContent = `绑定域名 · ${prof.name}`;

    const domains = state.domainsData || [];
    if (loadFailed) {
      list.replaceChildren();
      if (empty) empty.hidden = true;
      errEl.textContent = '域名列表加载失败，请关闭弹窗并刷新页面后重试（已禁止提交以防误清空绑定）';
      errEl.hidden = false;
      if (submitBtn) submitBtn.disabled = true;
    } else if (!domains.length) {
      list.replaceChildren();
      if (empty) empty.hidden = false;
      if (submitBtn) submitBtn.disabled = true;
    } else {
      if (empty) empty.hidden = true;
      if (submitBtn) submitBtn.disabled = false;
      const frag = document.createDocumentFragment();
      domains.forEach((d) => {
        const isBoundHere = d.dns_mode === 'axisnow_smart' && d.smart_dns?.profile_id === prof.id;
        const item = el('label', 'dns-bind-item');
        const left = el('div', 'dns-bind-item-left');
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = d.id;
        cb.checked = isBoundHere;
        const copy = el('div', 'dns-bind-item-copy');
        copy.append(el('strong', 'mono', d.domain));
        const curText = isBoundHere
          ? '当前已绑定此方案'
          : (d.dns_mode === 'axisnow_smart' && d.smart_dns?.profile_name
            ? `当前绑定：${d.smart_dns.profile_name}`
            : `当前：${dnsModeLabel(d.dns_mode)}`);
        copy.append(el('small', '', curText));
        left.append(cb, copy);
        item.append(left, el('span', `badge ${d.enabled ? 'badge-emerald' : ''}`, d.enabled ? '运行中' : '已停用'));
        frag.append(item);
      });
      list.replaceChildren(frag);
    }
    dlg.showModal();
  }

  async function saveDNSBindDomains() {
    const prof = state.dnsBindProfile;
    const dlg = document.getElementById('dns-bind-dialog');
    const errEl = document.getElementById('dns-bind-error');
    const submit = document.getElementById('dns-bind-submit');
    if (!prof || !dlg) return;
    errEl.hidden = true;
    const ids = Array.from(document.querySelectorAll('#dns-bind-list input[type="checkbox"]:checked')).map((el) => el.value);
    submit.disabled = true;
    try {
      await api(`/_admin/api/smart-dns-profiles/${encodeURIComponent(prof.id)}/bind-domains`, jsonOptions('POST', { domain_ids: ids }));
      dlg.close();
      toast(`已更新方案「${prof.name}」的域名绑定（共 ${ids.length} 个）`);
      await Promise.all([refreshSmartDNSProfiles(), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
    } catch (failure) {
      errEl.textContent = failure.message || '绑定域名失败';
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  function setDomainWizardStep(step, { skipValidate = false } = {}) {
    const target = Math.max(1, Math.min(3, Number(step) || 1));
    const errEl = document.getElementById('domain-form-error');
    if (errEl) errEl.hidden = true;

    if (!skipValidate && target > 1 && state.domainWizardStep === 1) {
      const host = normalizeDomainHostInput(document.getElementById('domain-host')?.value || '');
      if (!host) {
        if (errEl) {
          errEl.textContent = '请先填写对外访问域名，例如 play.emby.example.com';
          errEl.hidden = false;
        }
        document.getElementById('domain-host')?.focus();
        return false;
      }
    }

    state.domainWizardStep = target;
    document.querySelectorAll('#domain-wizard-steps .domain-wizard-tab').forEach((btn) => {
      const s = Number(btn.dataset.domainStep);
      const isActive = s === target;
      const isDone = s < target || (Boolean(state.domainEditingID) && !isActive);
      btn.classList.toggle('active', isActive);
      btn.classList.toggle('done', isDone);
      btn.setAttribute('aria-selected', String(isActive));
    });

    [1, 2, 3].forEach((s) => {
      const pane = document.getElementById(`domain-step-${s}`);
      if (pane) pane.hidden = s !== target;
    });

    const prevBtn = document.getElementById('domain-step-prev');
    const nextBtn = document.getElementById('domain-step-next');
    const submitBtn = document.getElementById('domain-form-submit');
    if (prevBtn) prevBtn.hidden = target === 1;
    if (nextBtn) {
      nextBtn.hidden = target === 3;
      const nextSpan = nextBtn.querySelector('span');
      if (nextSpan) {
        nextSpan.textContent = target === 1 ? '下一步：机器与限速' : '下一步：解析与 HTTPS';
      }
    }
    if (submitBtn) {
      const hideSubmit = !state.domainEditingID && target !== 3;
      submitBtn.hidden = hideSubmit;
      submitBtn.disabled = hideSubmit;
    }

    if (target === 2) renderDomainNodePicker();
    if (target === 3) updateDomainStep3UI();
    const scrollBody = document.getElementById('domain-drawer-body');
    if (scrollBody) scrollBody.scrollTop = 0;
    refreshIcons();
    return true;
  }

  async function openDomainDrawerForCreate() {
    const preloads = [];
    if (!state.nodesData.length) preloads.push(refreshNodes().catch(() => {}));
    if (!state.wafRules.length) preloads.push(refreshWAFRules().catch(() => {}));
    preloads.push(refreshSmartDNSProfiles().catch(() => {}));
    if (preloads.length) await Promise.all(preloads);
    state.domainEditingID = null;
    state.domainBoundNodeIDs = [];
    state.domainBoundWAFIDs = [];
    state.domainNodeSpeeds = {};
    state.domainSmartDNSDraft = ensureSmartDNSDraft(null, []);
    document.getElementById('domain-drawer-title').textContent = '添加反代域名';
    document.getElementById('domain-drawer-subtitle').textContent = '三步完成：填写域名 → 勾选部署机器与限速 → 自动开启 HTTPS 与解析';
    document.getElementById('domain-form-submit').innerHTML = '<i data-lucide="zap"></i><span>创建并下发到选中机器</span>';
    document.getElementById('domain-host').value = '';
    document.getElementById('domain-name').value = '';
    document.getElementById('domain-note').value = '';
    document.getElementById('domain-enabled').checked = true;
    document.getElementById('domain-public-visible').checked = true;
    setDomainDNSMode(state.domainsCFEnabled ? 'cloudflare_failover' : 'manual');
    document.getElementById('domain-dns-ip-mode').value = 'auto';
    document.getElementById('domain-dns-proxied').value = 'inherit';
    setDomainTLSMode('auto');
    document.getElementById('domain-cert-pem').value = '';
    document.getElementById('domain-key-pem').value = '';
    document.getElementById('domain-cert-existing-hint').textContent = '请粘贴完整 PEM 证书链与私钥';
    document.getElementById('domain-ov-default-upstream').value = '';
    document.getElementById('domain-ov-unsigned').value = 'inherit';
    document.getElementById('domain-ov-passip').value = 'inherit';
    document.getElementById('domain-ov-nocache').value = 'inherit';
    document.getElementById('domain-ov-ip-mode').value = '';
    document.getElementById('domain-ov-speed').value = '';
    document.getElementById('domain-ov-ip-conc').value = '';
    document.getElementById('domain-ov-global-conc').value = '';
    const cdnModeEl = document.getElementById('domain-cdn-mode');
    if (cdnModeEl) cdnModeEl.value = 'inherit';
    const cdnCidrsEl = document.getElementById('domain-ov-trusted-cidrs');
    if (cdnCidrsEl) cdnCidrsEl.value = '';
    const cdnHdrEl = document.getElementById('domain-ov-real-ip-header');
    if (cdnHdrEl) cdnHdrEl.value = '';
    const fold = document.getElementById('domain-override-fold');
    if (fold) fold.open = false;
    document.getElementById('domain-form-error').hidden = true;
    renderDomainNodePicker();
    updateDomainHostPreview();
    setDomainWizardStep(1, { skipValidate: true });
    openDrawer('domain-drawer');
    document.getElementById('domain-host')?.focus({ preventScroll: true });
  }

  async function openDomainDrawerForEdit(dom) {
    const preloads = [];
    if (!state.nodesData.length) preloads.push(refreshNodes().catch(() => {}));
    if (!state.wafRules.length) preloads.push(refreshWAFRules().catch(() => {}));
    preloads.push(refreshSmartDNSProfiles().catch(() => {}));
    if (preloads.length) await Promise.all(preloads);
    state.domainEditingID = dom.id;
    state.domainBoundNodeIDs = Array.isArray(dom.node_ids) ? [...dom.node_ids] : [];
    state.domainBoundWAFIDs = Array.isArray(dom.waf_rule_ids) ? [...dom.waf_rule_ids] : [];
    state.domainNodeSpeeds = {};
    state.domainSmartDNSDraft = ensureSmartDNSDraft(dom.smart_dns, state.domainBoundNodeIDs);
    if (dom.node_limits && typeof dom.node_limits === 'object') {
      Object.entries(dom.node_limits).forEach(([nid, lim]) => {
        if (lim && lim.max_download_mbps_per_ip !== undefined && lim.max_download_mbps_per_ip !== null) {
          state.domainNodeSpeeds[nid] = String(lim.max_download_mbps_per_ip);
        }
      });
    }
    const ov = dom.overrides || {};
    document.getElementById('domain-drawer-title').textContent = `配置域名 · ${dom.domain}`;
    document.getElementById('domain-drawer-subtitle').textContent = '点击顶部标签可直接跳转修改，保存后瞬间热同步至选中机器';
    document.getElementById('domain-form-submit').innerHTML = '<i data-lucide="zap"></i><span>保存并热同步</span>';
    document.getElementById('domain-host').value = dom.domain || '';
    document.getElementById('domain-name').value = dom.name || '';
    document.getElementById('domain-note').value = dom.note || '';
    document.getElementById('domain-enabled').checked = dom.enabled !== false;
    document.getElementById('domain-public-visible').checked = dom.public_visible !== false;
    setDomainDNSMode(dom.dns_mode || 'manual');
    document.getElementById('domain-dns-ip-mode').value = dom.dns_ip_mode || 'auto';
    document.getElementById('domain-dns-proxied').value = dom.dns_proxied || 'inherit';
    setDomainTLSMode(dom.tls_mode || 'auto');
    document.getElementById('domain-cert-pem').value = '';
    document.getElementById('domain-key-pem').value = '';
    document.getElementById('domain-cert-existing-hint').textContent = dom.has_certificate
      ? `当前已保存有效证书（${dom.cert_issuer || '已加密'}），留空则保持现有证书不变`
      : '请粘贴完整 PEM 证书链与私钥';
    document.getElementById('domain-ov-default-upstream').value = ov.default_upstream || '';
    document.getElementById('domain-ov-unsigned').value = triStateValue(ov.allow_unsigned_targets);
    document.getElementById('domain-ov-passip').value = triStateValue(ov.pass_client_ip);
    document.getElementById('domain-ov-nocache').value = triStateValue(ov.disable_cache);
    document.getElementById('domain-ov-ip-mode').value = ov.upstream_ip_mode || '';
    document.getElementById('domain-ov-speed').value = ov.max_download_mbps_per_ip !== undefined && ov.max_download_mbps_per_ip !== null ? String(ov.max_download_mbps_per_ip) : '';
    document.getElementById('domain-ov-ip-conc').value = ov.max_concurrent_per_ip !== undefined && ov.max_concurrent_per_ip !== null ? String(ov.max_concurrent_per_ip) : '';
    document.getElementById('domain-ov-global-conc').value = ov.max_concurrent_requests !== undefined && ov.max_concurrent_requests !== null ? String(ov.max_concurrent_requests) : '';
    const cdnModeEl = document.getElementById('domain-cdn-mode');
    const cdnCidrsEl = document.getElementById('domain-ov-trusted-cidrs');
    const cdnHdrEl = document.getElementById('domain-ov-real-ip-header');
    if (cdnModeEl) {
      if (ov.trust_proxy_headers === true) {
        cdnModeEl.value = isWildcardCDNList(ov.trusted_proxy_cidrs) ? 'any' : 'cidrs';
      } else if (ov.trust_proxy_headers === false) {
        cdnModeEl.value = 'off';
      } else {
        cdnModeEl.value = 'inherit';
      }
    }
    if (cdnCidrsEl) {
      cdnCidrsEl.value = (ov.trust_proxy_headers === true && !isWildcardCDNList(ov.trusted_proxy_cidrs))
        ? String(ov.trusted_proxy_cidrs || '').split(/[\s,;]+/).filter(Boolean).join('\n')
        : '';
    }
    if (cdnHdrEl) {
      const hdrVal = String(ov.real_ip_header || '').trim();
      if (hdrVal && !Array.from(cdnHdrEl.options).some((o) => o.value === hdrVal)) {
        const opt = document.createElement('option');
        opt.value = hdrVal;
        opt.textContent = `${hdrVal}（自定义头）`;
        cdnHdrEl.append(opt);
      }
      cdnHdrEl.value = hdrVal;
    }
    syncDomainCDNUI();
    const hasStep3Advanced = Boolean(
      ov.default_upstream || ov.upstream_ip_mode || ov.max_concurrent_requests !== undefined ||
      ov.allow_unsigned_targets !== undefined || ov.pass_client_ip !== undefined || ov.disable_cache !== undefined ||
      dom.enabled === false || dom.public_visible === false
    );
    const fold = document.getElementById('domain-override-fold');
    if (fold) fold.open = hasStep3Advanced;
    document.getElementById('domain-form-error').hidden = true;
    renderDomainNodePicker();
    updateDomainHostPreview();
    setDomainWizardStep(2, { skipValidate: true });
    openDrawer('domain-drawer');
  }

  async function saveEdgeDomain(e) {
    e.preventDefault();
    if (!state.domainEditingID && state.domainWizardStep < 3) {
      if (Date.now() - (state.domainStepAdvanceAt || 0) > 300) {
        state.domainStepAdvanceAt = Date.now();
        setDomainWizardStep(state.domainWizardStep + 1);
      }
      return;
    }
    const errEl = document.getElementById('domain-form-error');
    errEl.hidden = true;

    const hostInput = document.getElementById('domain-host');
    const cleanHost = normalizeDomainHostInput(hostInput?.value || '');
    if (!cleanHost) {
      setDomainWizardStep(1, { skipValidate: true });
      showFormError(errEl, '请先填写对外访问域名，例如 play.emby.example.com');
      hostInput?.focus();
      return;
    }
    if (hostInput) hostInput.value = cleanHost;

    const overrides = {};
    const unsigned = parseTriState(document.getElementById('domain-ov-unsigned').value);
    const passIP = parseTriState(document.getElementById('domain-ov-passip').value);
    const noCache = parseTriState(document.getElementById('domain-ov-nocache').value);
    if (unsigned !== undefined) overrides.allow_unsigned_targets = unsigned;
    if (passIP !== undefined) overrides.pass_client_ip = passIP;
    if (noCache !== undefined) overrides.disable_cache = noCache;
    const ipMode = document.getElementById('domain-ov-ip-mode').value.trim();
    const defaultUp = document.getElementById('domain-ov-default-upstream').value.trim();
    const speedRaw = document.getElementById('domain-ov-speed').value.trim();
    const ipConcRaw = document.getElementById('domain-ov-ip-conc').value.trim();
    const globalConcRaw = document.getElementById('domain-ov-global-conc').value.trim();
    if (ipMode !== '') overrides.upstream_ip_mode = ipMode;
    if (defaultUp !== '') overrides.default_upstream = defaultUp;
    if (speedRaw !== '') overrides.max_download_mbps_per_ip = Number(speedRaw);
    if (ipConcRaw !== '') overrides.max_concurrent_per_ip = Number(ipConcRaw);
    if (globalConcRaw !== '') overrides.max_concurrent_requests = Number(globalConcRaw);

    const cdnMode = document.getElementById('domain-cdn-mode')?.value || 'inherit';
    const cdnCidrsRaw = (document.getElementById('domain-ov-trusted-cidrs')?.value || '').trim();
    const cdnHdrRaw = (document.getElementById('domain-ov-real-ip-header')?.value || '').trim();
    if (cdnMode === 'off') {
      overrides.trust_proxy_headers = false;
    } else if (cdnMode === 'any') {
      overrides.trust_proxy_headers = true;
      overrides.trusted_proxy_cidrs = '0.0.0.0/0, ::/0';
      if (cdnHdrRaw !== '') overrides.real_ip_header = cdnHdrRaw;
    } else if (cdnMode === 'cidrs') {
      if (!cdnCidrsRaw) {
        setDomainWizardStep(3, { skipValidate: true });
        showFormError(errEl, '请至少填写一个可信 CDN 回源节点 IP 或 CIDR 网段，或改选「信任所有回源节点」');
        document.getElementById('domain-ov-trusted-cidrs')?.focus();
        return;
      }
      overrides.trust_proxy_headers = true;
      overrides.trusted_proxy_cidrs = cdnCidrsRaw;
      if (cdnHdrRaw !== '') overrides.real_ip_header = cdnHdrRaw;
    }

    const nodeLimits = {};
    (state.domainBoundNodeIDs || []).forEach((nid) => {
      const raw = (state.domainNodeSpeeds[nid] ?? '').trim();
      if (raw !== '') {
        nodeLimits[nid] = { max_download_mbps_per_ip: Number(raw) };
      }
    });

    const dnsMode = getDomainDNSMode();
    let smartPayload;
    if (dnsMode === 'axisnow_smart') {
      const draft = ensureSmartDNSDraft(state.domainSmartDNSDraft, state.domainBoundNodeIDs);
      const pickedProf = (state.smartDNSProfiles || []).find((p) => p.id === draft.profile_id);
      if (pickedProf) {
        smartPayload = {
          profile_id: pickedProf.id,
          profile_name: pickedProf.name,
          routing_domain_uuid: draft.routing_domain_uuid || '',
          routing_domain_host: (document.getElementById('domain-smart-routing-host')?.value || '').trim(),
          auto_cf_cname: Boolean(document.getElementById('domain-smart-auto-cf-cname')?.checked)
        };
      } else {
        const cleanLines = (draft.lines || []).filter((l) => (l.geo_isp || '').trim() !== '');
        const defLine = cleanLines.find((l) => l.geo_isp === 'default');
        if (!cleanLines.length || !defLine || !defLine.node_ids.length) {
          showFormError(errEl, '请先选择一个智能分流方案（可前往「DNS 与分流」新建方案）');
          return;
        }
        smartPayload = {
          provider_uuid: draft.provider_uuid || '',
          provider_source: draft.provider_source || 'platform',
          provider_type: draft.provider_type || '',
          zone_uuid: draft.zone_uuid || '',
          zone_name: draft.zone_name || '',
          zone_plan: draft.zone_plan || '',
          routing_domain_uuid: draft.routing_domain_uuid || '',
          routing_domain_host: (document.getElementById('domain-smart-routing-host')?.value || '').trim(),
          auto_cf_cname: Boolean(document.getElementById('domain-smart-auto-cf-cname')?.checked),
          lines: cleanLines
        };
      }
    }

    const payload = {
      domain: cleanHost,
      name: document.getElementById('domain-name').value.trim(),
      note: document.getElementById('domain-note').value.trim(),
      enabled: document.getElementById('domain-enabled').checked,
      public_visible: document.getElementById('domain-public-visible').checked,
      node_ids: [...(state.domainBoundNodeIDs || [])],
      dns_mode: dnsMode,
      dns_ip_mode: document.getElementById('domain-dns-ip-mode').value,
      dns_proxied: document.getElementById('domain-dns-proxied').value,
      tls_mode: getDomainTLSMode(),
      cert_pem: document.getElementById('domain-cert-pem').value.trim(),
      key_pem: document.getElementById('domain-key-pem').value.trim(),
      overrides,
      node_limits: nodeLimits,
      waf_rule_ids: [...(state.domainBoundWAFIDs || [])],
      ...(smartPayload ? { smart_dns: smartPayload } : {})
    };

    const submit = document.getElementById('domain-form-submit');
    submit.disabled = true;
    try {
      if (state.domainEditingID) {
        await api(`/_admin/api/domains/${encodeURIComponent(state.domainEditingID)}`, jsonOptions('PUT', payload));
        toast(`域名「${payload.domain}」已热同步至选中机器`);
      } else {
        await api('/_admin/api/domains', jsonOptions('POST', payload));
        toast(`域名「${payload.domain}」已创建并下发`);
      }
      closeDrawer('domain-drawer');
      await Promise.all([refreshDomains(), refreshNodes(), refreshSmartDNSProfiles().catch(() => {}), refreshWAFRules().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
    } catch (failure) {
      showFormError(errEl, failure.message || '域名保存失败，请检查域名格式、证书或覆写参数');
    } finally {
      submit.disabled = false;
    }
  }

  async function issueDomainCert(dom, button) {
    if (state.busyDomainIDs.has(dom.id)) return;
    state.busyDomainIDs.add(dom.id);
    button.disabled = true;
    try {
      await api(`/_admin/api/domains/${encodeURIComponent(dom.id)}/issue-cert`, jsonOptions('POST', {}));
      toast(`已启动「${dom.domain}」Cloudflare DNS-01 证书签发任务`, 'info');
      await refreshDomains();
    } catch (failure) {
      toast(failure.message || '触发证书签发失败', 'error');
    } finally {
      state.busyDomainIDs.delete(dom.id);
      button.disabled = false;
    }
  }

  async function syncDomainDNS(dom, button) {
    if (state.busyDomainIDs.has(dom.id)) return;
    state.busyDomainIDs.add(dom.id);
    button.disabled = true;
    button.querySelector('svg')?.classList.add('spinning');
    try {
      await api(`/_admin/api/domains/${encodeURIComponent(dom.id)}/sync-dns`, jsonOptions('POST', {}));
      await Promise.all([refreshDomains(), refreshSmartDNSProfiles().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast(dom.dns_mode === 'axisnow_smart' ? `域名「${dom.domain}」AxisNow 智能 DNS 线路已同步` : `域名「${dom.domain}」Cloudflare DNS 已同步`);
    } catch (failure) {
      toast(failure.message || 'DNS 同步失败', 'error');
    } finally {
      state.busyDomainIDs.delete(dom.id);
      button.disabled = false;
      button.querySelector('svg')?.classList.remove('spinning');
    }
  }

  async function deleteEdgeDomain(dom, button) {
    if (state.busyDomainIDs.has(dom.id)) return;
    const confirmed = await confirmAction({
      title: `删除域名「${dom.domain}」`,
      message: '删除后已绑定的边缘节点会立即卸载该域名与证书，若开启了 Cloudflare 自动解析将同步清理对应 DNS 记录。',
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    state.busyDomainIDs.add(dom.id);
    button.disabled = true;
    try {
      await api(`/_admin/api/domains/${encodeURIComponent(dom.id)}`, { method: 'DELETE' });
      await Promise.all([refreshDomains(), refreshNodes(), refreshSmartDNSProfiles().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast(`域名「${dom.domain}」已删除并从节点卸载`);
    } catch {
      button.disabled = false;
      toast('删除域名失败', 'error');
    } finally {
      state.busyDomainIDs.delete(dom.id);
    }
  }

  /* -------------------- Discovered Targets -------------------- */

  function renderTargets(targets) {
    const all = Array.isArray(targets) ? targets : [];
    const totalReq = all.reduce((s, t) => s + (Number(t.requests) || 0), 0);
    const totalBytes = all.reduce((s, t) => s + (Number(t.bytes_out) || 0), 0);
    const totalErr = all.reduce((s, t) => s + (Number(t.errors) || 0), 0);
    document.getElementById('targets-kpi-count').textContent = formatNumber(all.length);
    document.getElementById('targets-kpi-req').textContent = formatNumber(totalReq);
    document.getElementById('targets-kpi-bytes').textContent = formatBytes(totalBytes);
    document.getElementById('targets-kpi-err').textContent = formatNumber(totalErr);

    const q = state.targetsQuery.trim().toLowerCase();
    const filtered = all.filter((t) => !q || `${t.host} ${t.domain} ${t.emby_server_name || ''} ${t.emby_line_name || ''} ${t.emby_note || ''}`.toLowerCase().includes(q));
    document.getElementById('target-count').textContent = `${formatNumber(filtered.length)} 个后端`;
    const body = document.getElementById('targets-table');
    const empty = document.getElementById('targets-empty');
    if (!filtered.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const f = document.createDocumentFragment();
    filtered.forEach((t) => {
      const row = document.createElement('tr');
      const host = el('td');
      const stack = el('div', 'cell-stack');
      const displayName = String(t.emby_server_name || '').trim() || t.host;
      stack.append(el('span', 'cell-primary', displayName));
      const meta = el('div', 'cell-meta-row');
      if (displayName !== t.host) meta.append(el('span', 'cell-secondary mono', t.host));
      if (t.emby_line_name) meta.append(el('span', 'meta-tag accent', t.emby_line_name));
      if (t.emby_note) meta.append(el('span', 'meta-tag', t.emby_note));
      if (meta.childElementCount) stack.append(meta);
      host.append(stack);

      const actions = el('td', 'actions-col');
      const actRow = el('div', 'row-actions');
      const logBtn = el('button', 'btn btn-secondary btn-sm');
      logBtn.type = 'button';
      logBtn.innerHTML = '<i data-lucide="scroll-text"></i><span>日志</span>';
      logBtn.addEventListener('click', () => jumpToHostLogs(t.host));
      actRow.append(logBtn);
      const domAct = domainActionButton(t.domain);
      if (domAct) actRow.append(domAct);
      actions.append(actRow);

      [host,
        el('td', 'num-col', formatNumber(t.requests)),
        el('td', 'num-col mono', formatBytes(t.bytes_out)),
        el('td', 'num-col', formatNumber(t.errors)),
        el('td', 'num-col mono', `${t.avg_latency_ms} ms`),
        el('td', 'cell-secondary', relativeTime(t.last_seen)),
        actions].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  /* -------------------- Emby Health Monitoring (with Drawer) -------------------- */

  function renderSlaCell(value) {
    const td = el('td');
    if (value === null || value === undefined) {
      td.append(el('span', 'cell-secondary mono', '—'));
      return td;
    }
    const pct = Math.max(0, Math.min(100, Number(value)));
    const meter = el('div', 'sla-meter');
    meter.append(el('strong', '', `${pct.toFixed(1)}%`));
    const track = el('div', 'sla-track');
    const fill = el('div', `sla-fill${pct < 90 ? ' bad' : pct < 99 ? ' warn' : ''}`);
    fill.style.width = `${pct}%`;
    track.append(fill);
    meter.append(track);
    td.append(meter);
    return td;
  }

  function formatProbeTime(ts) {
    if (!ts) return '—';
    return new Date(Number(ts) * 1000).toLocaleString('zh-CN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZone: applicationTimeZone
    });
  }

  function formatUptimePct2(value) {
    if (value === null || value === undefined || Number.isNaN(Number(value))) return '—';
    const num = Math.max(0, Math.min(100, Number(value)));
    return `${num.toFixed(2)}%`;
  }

  function formatLatencyCompact(ms) {
    if (ms === null || ms === undefined || Number.isNaN(Number(ms)) || Number(ms) <= 0) return '—';
    const v = Number(ms);
    if (v >= 1000) {
      return `${(v / 1000).toFixed(2).replace(/\.?0+$/, '')} s`;
    }
    return `${Math.round(v)} ms`;
  }

  function createSVGEl(tag, attrs = {}) {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, String(v)));
    return node;
  }

  function buildUptimeRing(pctNum) {
    const tone = pctNum === null ? 'is-muted' : pctNum < 90 ? 'is-bad' : pctNum < 99 ? 'is-warn' : '';
    const wrap = el('div', `uptime-ring-wrap ${tone}`.trim());
    const radius = 9;
    const circumference = 2 * Math.PI * radius;
    const ratio = pctNum === null ? 0 : Math.max(0, Math.min(1, pctNum / 100));
    const offset = circumference * (1 - ratio);

    const svg = createSVGEl('svg', { class: 'uptime-ring-svg', viewBox: '0 0 24 24', 'aria-hidden': 'true' });
    svg.append(
      createSVGEl('circle', { class: 'uptime-ring-track', cx: 12, cy: 12, r: radius }),
      createSVGEl('circle', {
        class: 'uptime-ring-arc',
        cx: 12,
        cy: 12,
        r: radius,
        transform: 'rotate(-90 12 12)',
        'stroke-dasharray': circumference.toFixed(2),
        'stroke-dashoffset': offset.toFixed(2)
      })
    );
    wrap.append(svg, el('span', 'uptime-pct', pctNum === null ? '—' : formatUptimePct2(pctNum)));
    return wrap;
  }

  function buildLatencyAreaChart(server, checks, onHoverPoint) {
    const box = el('div', 'uptime-chart-box');
    const valid = checks.filter((pt) => pt && pt.checked_at);
    const yAxis = el('div', 'uptime-chart-yaxis');
    const xAxis = el('div', 'uptime-chart-xaxis');

    if (!valid.length) {
      yAxis.append(el('span', '', '—'), el('span', '', '—'), el('span', '', '—'));
      const empty = el('div', 'uptime-chart-empty', server.enabled ? '等待采集心跳数据…' : '已暂停监测');
      box.append(yAxis, empty, xAxis);
      return box;
    }

    const latencies = valid.map((pt) => Math.max(0, Number(pt.latency_ms) || 0));
    const okLatencies = valid.filter((pt) => pt.success && Number(pt.latency_ms) > 0).map((pt) => Number(pt.latency_ms));
    const refVals = okLatencies.length ? okLatencies : latencies;
    let rawMin = Math.min(...refVals);
    let rawMax = Math.max(...refVals);
    if (rawMax <= rawMin) {
      const pad = Math.max(8, Math.round(rawMax * 0.2) || 10);
      rawMin = Math.max(0, rawMin - pad);
      rawMax = rawMax + pad;
    } else {
      const span = rawMax - rawMin;
      rawMin = Math.max(0, rawMin - span * 0.12);
      rawMax = rawMax + span * 0.12;
    }
    const rawMid = (rawMin + rawMax) / 2;

    yAxis.append(
      el('span', '', formatLatencyCompact(rawMax)),
      el('span', '', formatLatencyCompact(rawMid)),
      el('span', '', formatLatencyCompact(rawMin))
    );

    const W = 280;
    const H = 120;
    const padT = 8;
    const padB = 8;
    const plotH = H - padT - padB;
    const yOf = (val) => {
      const clamped = Math.max(rawMin, Math.min(rawMax, val));
      const ratio = (clamped - rawMin) / Math.max(1e-6, rawMax - rawMin);
      return padT + plotH * (1 - ratio);
    };

    const coords = valid.map((pt, i) => {
      const x = valid.length === 1 ? W / 2 : (i / (valid.length - 1)) * W;
      const y = yOf(Number(pt.latency_ms) || 0);
      return { x, y, pt };
    });

    const latestPt = valid[valid.length - 1];
    const lineTone = !latestPt.success ? 'is-bad' : ((latestPt.retries_used > 0 || latestPt.latency_ms >= 2000) ? 'is-warn' : '');
    const strokeHex = lineTone === 'is-bad' ? '#ef4444' : lineTone === 'is-warn' ? '#f59e0b' : '#10b981';

    const plot = el('div', 'uptime-chart-plot');
    const svg = createSVGEl('svg', { class: 'uptime-chart-svg', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
    const gradId = `emby-grad-${server.id}-${valid.length}`;
    const defs = createSVGEl('defs');
    const grad = createSVGEl('linearGradient', { id: gradId, x1: '0', y1: '0', x2: '0', y2: '1' });
    grad.append(
      createSVGEl('stop', { offset: '0%', 'stop-color': strokeHex, 'stop-opacity': '0.24' }),
      createSVGEl('stop', { offset: '100%', 'stop-color': strokeHex, 'stop-opacity': '0.01' })
    );
    defs.append(grad);
    svg.append(defs);

    // Subtle horizontal gridlines
    [padT, padT + plotH / 2, H - padB].forEach((gy) => {
      svg.append(createSVGEl('line', { class: 'uptime-chart-gridline', x1: 0, y1: gy.toFixed(1), x2: W, y2: gy.toFixed(1) }));
    });

    let lineD = '';
    let areaD = '';
    if (coords.length === 1) {
      const y = coords[0].y.toFixed(1);
      lineD = `M 0 ${y} L ${W} ${y}`;
      areaD = `M 0 ${y} L ${W} ${y} L ${W} ${H - padB} L 0 ${H - padB} Z`;
    } else {
      lineD = coords.map((c, idx) => `${idx === 0 ? 'M' : 'L'} ${c.x.toFixed(1)} ${c.y.toFixed(1)}`).join(' ');
      areaD = `${lineD} L ${coords[coords.length - 1].x.toFixed(1)} ${H - padB} L ${coords[0].x.toFixed(1)} ${H - padB} Z`;
    }

    svg.append(
      createSVGEl('path', { d: areaD, fill: `url(#${gradId})` }),
      createSVGEl('path', { class: `uptime-chart-line ${lineTone}`.trim(), d: lineD })
    );

    const hoverLine = createSVGEl('line', { class: 'uptime-chart-hover-line', x1: 0, y1: padT, x2: 0, y2: H - padB, visibility: 'hidden' });
    const hoverDot = createSVGEl('circle', { class: `uptime-chart-hover-dot ${lineTone}`.trim(), cx: 0, cy: 0, r: 3.5, visibility: 'hidden' });
    svg.append(hoverLine, hoverDot);

    svg.addEventListener('mousemove', (e) => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width) return;
      const relX = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
      const idx = coords.length === 1 ? 0 : Math.round(relX * (coords.length - 1));
      const hit = coords[idx];
      if (!hit) return;
      hoverLine.setAttribute('x1', hit.x.toFixed(1));
      hoverLine.setAttribute('x2', hit.x.toFixed(1));
      hoverLine.setAttribute('visibility', 'visible');
      hoverDot.setAttribute('cx', hit.x.toFixed(1));
      hoverDot.setAttribute('cy', hit.y.toFixed(1));
      const ptTone = !hit.pt.success ? 'is-bad' : ((hit.pt.retries_used > 0 || hit.pt.latency_ms >= 2000) ? 'is-warn' : '');
      hoverDot.setAttribute('class', `uptime-chart-hover-dot ${ptTone}`.trim());
      hoverDot.setAttribute('visibility', 'visible');
      if (onHoverPoint) onHoverPoint(hit.pt);
    });
    svg.addEventListener('mouseleave', () => {
      hoverLine.setAttribute('visibility', 'hidden');
      hoverDot.setAttribute('visibility', 'hidden');
      if (onHoverPoint) onHoverPoint(null);
    });

    plot.append(svg);

    // 3 evenly spaced X-axis timestamps for clean square-card fit
    const labelCount = Math.min(3, valid.length);
    for (let i = 0; i < labelCount; i += 1) {
      const idx = labelCount === 1 ? 0 : Math.round((i / (labelCount - 1)) * (valid.length - 1));
      xAxis.append(el('span', '', formatProbeTime(valid[idx].checked_at)));
    }

    box.append(yAxis, plot, xAxis);
    return box;
  }

  function renderProbePolicyHint() {
    const elHint = document.getElementById('emby-probe-policy-hint');
    if (!elHint) return;
    const cfg = state.embyProbeSettings || { default_retry_count: 2, default_retry_delay_sec: 2, probe_timeout_sec: 8 };
    elHint.textContent = cfg.default_retry_count > 0
      ? `每分钟自动探测 · 失败重试 ${cfg.default_retry_count} 次（间隔 ${cfg.default_retry_delay_sec}s · 超时 ${cfg.probe_timeout_sec}s）`
      : `每分钟自动探测 · 失败不重试（超时 ${cfg.probe_timeout_sec}s）`;
  }

  function renderEmbyHealth(servers) {
    state.embyHealthServers = Array.isArray(servers) ? servers : [];
    const all = state.embyHealthServers;
    renderProbePolicyHint();

    const enabledCount = all.filter((s) => s.enabled).length;
    const onlineServers = all.filter((s) => s.status === 'online');
    const onlineCount = onlineServers.length;
    const offlineCount = all.filter((s) => s.status === 'offline').length;
    const slaVals = all.map((s) => s.availability_24h).filter((v) => v !== null && v !== undefined).map(Number);
    const avgSla = slaVals.length ? `${(slaVals.reduce((a, b) => a + b, 0) / slaVals.length).toFixed(2)}%` : '—';
    const latVals = onlineServers.map((s) => Number(s.latency_ms) || 0).filter((v) => v > 0);
    const avgLat = latVals.length ? formatLatencyCompact(latVals.reduce((a, b) => a + b, 0) / latVals.length) : '—';

    document.getElementById('health-kpi-total').textContent = formatNumber(all.length);
    document.getElementById('health-kpi-enabled').textContent = `${formatNumber(enabledCount)} 台监测中`;
    document.getElementById('health-kpi-online').textContent = formatNumber(onlineCount);
    const avgLatEl = document.getElementById('health-kpi-avg-latency');
    if (avgLatEl) avgLatEl.textContent = `平均延迟 ${avgLat}`;
    document.getElementById('health-kpi-offline').textContent = formatNumber(offlineCount);
    document.getElementById('health-kpi-sla').textContent = avgSla;

    const q = state.embyHealthQuery.trim().toLowerCase();
    const list = all.filter((s) => {
      if (state.embyHealthFilter !== 'all' && s.status !== state.embyHealthFilter) return false;
      if (!q) return true;
      return `${s.group_name} ${s.name} ${s.line_name || ''} ${s.note || ''} ${s.base_url}`.toLowerCase().includes(q);
    });

    document.getElementById('emby-health-count').textContent = `${formatNumber(list.length)} 台`;
    const board = document.getElementById('emby-uptime-board');
    const empty = document.getElementById('emby-health-empty');
    if (!list.length) {
      board.replaceChildren();
      empty.hidden = false;
      document.getElementById('emby-health-updated').textContent = all.length ? '筛选无匹配项' : '尚无检测记录';
      return;
    }
    empty.hidden = true;

    const groups = new Map();
    let latestCheck = 0;
    list.forEach((s) => {
      latestCheck = Math.max(latestCheck, Number(s.last_checked_at) || 0);
      const key = s.group_name || 'Emby 服务器';
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(s);
    });

    const frag = document.createDocumentFragment();
    const BAR_SLOTS = 60;
    const WINDOWS = [100, 50, 25, 10];

    groups.forEach((items, groupName) => {
      const grp = el('section', 'uptime-group');
      if (groups.size > 1) {
        const head = el('div', 'uptime-group-head');
        const grpOnline = items.filter((i) => i.status === 'online').length;
        const grpTitle = el('div', 'uptime-group-title');
        grpTitle.append(el('span', '', groupName));
        head.append(grpTitle, el('span', 'uptime-group-summary', `${grpOnline}/${items.length} 在线`));
        grp.append(head);
      }

      const grid = el('div', 'uptime-grid');
      items.forEach((s) => {
        const allChecks = Array.isArray(s.recent_checks) ? s.recent_checks : [];
        let selectedWin = state.embyCardWindows[s.id] || 100;
        if (!WINDOWS.includes(selectedWin)) selectedWin = 100;

        const card = el('article', `uptime-card${s.status === 'offline' ? ' is-offline' : s.status === 'disabled' ? ' is-disabled' : ''}`);
        const effPath = s.effective_probe_path || s.probe_path || '/emby/System/Info/Public';
        const retryVal = Number.isFinite(Number(s.retry_count)) ? Number(s.retry_count) : 2;
        const tooltipParts = [`${s.base_url}${effPath}`];
        if (s.server_version) tooltipParts.push(`Emby v${String(s.server_version).replace(/^v/i, '')}`);
        tooltipParts.push(retryVal > 0 ? `失败重试 ${retryVal} 次` : '不重试');
        if (s.note) tooltipParts.push(s.note);

        // Top Header: Status Icon + Name + Hover Actions + Circular Progress Ring
        const top = el('div', 'uptime-card-top');
        const titleRow = el('div', 'uptime-title-row');
        const iconTone = s.status === 'online' ? '' : s.status === 'offline' ? 'is-offline' : s.status === 'unknown' ? 'is-unknown' : 'is-disabled';
        const lucideIcon = s.status === 'online' ? 'check-circle-2' : s.status === 'offline' ? 'x-circle' : s.status === 'disabled' ? 'pause-circle' : 'clock';
        const statusIco = el('span', `uptime-status-ico ${iconTone}`.trim());
        statusIco.innerHTML = `<i data-lucide="${lucideIcon}"></i>`;
        const nameEl = el('strong', 'uptime-name', s.name);
        nameEl.title = tooltipParts.join(' · ');
        titleRow.append(statusIco, nameEl);

        const actions = el('div', 'uptime-card-actions');
        const check = el('button', 'icon-btn');
        check.type = 'button'; check.title = '立即检测'; check.setAttribute('aria-label', '立即检测'); check.disabled = !s.enabled;
        check.innerHTML = '<i data-lucide="refresh-cw"></i>';
        check.addEventListener('click', () => checkEmbyHealth(s, check));

        const edit = el('button', 'icon-btn');
        edit.type = 'button'; edit.title = '编辑'; edit.setAttribute('aria-label', '编辑');
        edit.innerHTML = '<i data-lucide="pencil"></i>';
        edit.addEventListener('click', () => openEmbyDrawerForEdit(s));

        const toggle = el('button', 'icon-btn');
        toggle.type = 'button'; toggle.title = s.enabled ? '停用' : '启用'; toggle.setAttribute('aria-label', toggle.title);
        toggle.innerHTML = `<i data-lucide="${s.enabled ? 'pause' : 'play'}"></i>`;
        toggle.addEventListener('click', () => toggleEmbyHealth(s, toggle));

        const remove = el('button', 'icon-btn danger');
        remove.type = 'button'; remove.title = '删除'; remove.setAttribute('aria-label', '删除');
        remove.innerHTML = '<i data-lucide="trash-2"></i>';
        remove.addEventListener('click', () => deleteEmbyHealth(s, remove));
        actions.append(check, edit, toggle, remove);

        const ringSlot = el('div');
        top.append(titleRow, actions, ringSlot);

        // Strip Block: LT/AL + Inline Legend/Hover Readout + Dense 60-slot Heartbeat Strip
        const stripBlock = el('div', 'uptime-strip-block');
        const metaLine = el('div', 'uptime-meta-line');
        const ltAlWrap = el('div', 'uptime-lt-al');
        const ltVal = el('b', '', '—');
        const alVal = el('b', '', '—');
        const ltKv = el('span', 'uptime-kv');
        ltKv.append('LT:', ltVal);
        const alKv = el('span', 'uptime-kv');
        alKv.append('AL:', alVal);
        ltAlWrap.append(ltKv, alKv);

        const legendEl = el('div', 'uptime-inline-legend');
        [
          ['is-up', '在线'],
          ['is-warn', '重试'],
          ['is-down', '离线']
        ].forEach(([cls, lbl]) => {
          const item = el('span', 'uptime-leg-item');
          item.append(el('i', `uptime-leg-dot ${cls}`), lbl);
          legendEl.append(item);
        });
        const hoverReadout = el('span', 'uptime-hover-readout');
        hoverReadout.hidden = true;
        metaLine.append(ltAlWrap, legendEl, hoverReadout);

        const showHover = (pt) => {
          if (!pt) {
            hoverReadout.hidden = true;
            legendEl.hidden = false;
            return;
          }
          const retryNote = pt.retries_used > 0 ? ` · 重试${pt.retries_used}次` : '';
          hoverReadout.textContent = `${formatProbeTime(pt.checked_at)} · ${pt.status_code || '超时'} · ${formatLatencyCompact(pt.latency_ms)}${retryNote}`;
          legendEl.hidden = true;
          hoverReadout.hidden = false;
        };

        const bars = el('div', 'uptime-bars');
        const barChecks = allChecks.slice(-BAR_SLOTS);
        const padCount = Math.max(0, BAR_SLOTS - barChecks.length);
        for (let i = 0; i < padCount; i += 1) {
          bars.append(el('span', 'uptime-bar is-empty'));
        }
        barChecks.forEach((pt) => {
          const isUp = Boolean(pt.success);
          const tone = !isUp ? 'is-down' : ((pt.retries_used > 0 || Number(pt.latency_ms) >= 2000) ? 'is-warn' : 'is-up');
          const bar = el('span', `uptime-bar ${tone}`);
          const retryNote = pt.retries_used > 0 ? `（重试 ${pt.retries_used} 次后成功）` : '';
          bar.title = `${formatProbeTime(pt.checked_at)} · ${isUp ? '在线' : '离线'} · ${pt.status_code ? `HTTP ${pt.status_code}` : '超时'} · ${formatLatencyCompact(pt.latency_ms)}${retryNote}`;
          bar.addEventListener('mouseenter', () => showHover(pt));
          bars.append(bar);
        });
        bars.addEventListener('mouseleave', () => showHover(null));
        stripBlock.append(metaLine, bars);

        // Window Switcher + Chart Slot
        const winSwitch = el('div', 'uptime-win-switch');
        winSwitch.setAttribute('role', 'tablist');
        const chartSlot = el('div', 'uptime-chart-slot');

        const updateWindowView = (winSize) => {
          selectedWin = winSize;
          state.embyCardWindows[s.id] = winSize;
          winSwitch.querySelectorAll('.uptime-win-btn').forEach((b) => {
            const active = Number(b.dataset.win) === winSize;
            b.classList.toggle('active', active);
            b.setAttribute('aria-selected', String(active));
          });
          const slice = allChecks.slice(-winSize);
          // Uptime % over selected window (fallback to 24h SLA if slice empty)
          let pctNum = null;
          if (slice.length > 0) {
            const okCount = slice.filter((pt) => pt.success).length;
            pctNum = (okCount / slice.length) * 100;
          } else if (s.availability_24h !== null && s.availability_24h !== undefined) {
            pctNum = Number(s.availability_24h);
          }
          const ring = buildUptimeRing(pctNum);
          ring.title = `窗口在线率（${slice.length} 次） · 24h ${formatUptimePct2(s.availability_24h)} · 30天 ${formatUptimePct2(s.availability_30d)}`;
          ringSlot.replaceChildren(ring);

          // LT & AL over selected window
          const latest = slice.length ? slice[slice.length - 1] : null;
          if (!s.enabled) {
            ltVal.textContent = '停用';
            ltVal.className = 'is-muted';
          } else if (latest) {
            ltVal.textContent = latest.success ? formatLatencyCompact(latest.latency_ms) : '离线';
            ltVal.className = !latest.success ? 'is-bad' : ((latest.retries_used > 0 || latest.latency_ms >= 2000) ? 'is-warn' : '');
          } else {
            ltVal.textContent = '—';
            ltVal.className = 'is-muted';
          }
          const okSliceLats = slice.filter((pt) => pt.success && Number(pt.latency_ms) > 0).map((pt) => Number(pt.latency_ms));
          if (okSliceLats.length) {
            const avg = okSliceLats.reduce((a, b) => a + b, 0) / okSliceLats.length;
            alVal.textContent = formatLatencyCompact(avg);
            alVal.className = avg >= 2000 ? 'is-warn' : '';
          } else {
            alVal.textContent = '—';
            alVal.className = 'is-muted';
          }

          chartSlot.replaceChildren(buildLatencyAreaChart(s, slice, showHover));
        };

        WINDOWS.forEach((w) => {
          const btn = el('button', `uptime-win-btn${w === selectedWin ? ' active' : ''}`, `近 ${w} 次`);
          btn.type = 'button';
          btn.dataset.win = String(w);
          btn.setAttribute('role', 'tab');
          btn.setAttribute('aria-selected', String(w === selectedWin));
          btn.addEventListener('click', () => updateWindowView(w));
          winSwitch.append(btn);
        });

        updateWindowView(selectedWin);
        card.append(top, stripBlock, winSwitch, chartSlot);
        grid.append(card);
      });

      grp.append(grid);
      frag.append(grp);
    });

    board.replaceChildren(frag);
    document.getElementById('emby-health-updated').textContent = latestCheck ? `最近探测 ${relativeTime(latestCheck)}` : '尚无检测记录';
    refreshIcons();
  }

  async function refreshEmbyHealth() {
    const [servers, settings] = await Promise.all([
      api('/_admin/api/emby-health'),
      api('/_admin/api/emby-health/settings').catch(() => state.embyProbeSettings)
    ]);
    if (settings) state.embyProbeSettings = settings;
    renderEmbyHealth(servers);
  }

  function openEmbySettingsDrawer() {
    const cfg = state.embyProbeSettings || { default_retry_count: 2, default_retry_delay_sec: 2, probe_timeout_sec: 8 };
    document.getElementById('emby-cfg-retry-count').value = String(cfg.default_retry_count ?? 2);
    document.getElementById('emby-cfg-retry-delay').value = String(cfg.default_retry_delay_sec ?? 2);
    document.getElementById('emby-cfg-timeout').value = String(cfg.probe_timeout_sec ?? 8);
    document.getElementById('emby-cfg-apply-all').checked = true;
    document.getElementById('emby-settings-error').hidden = true;
    openDrawer('emby-settings-drawer');
  }

  async function saveEmbyProbeSettings(event) {
    event.preventDefault();
    const errEl = document.getElementById('emby-settings-error');
    errEl.hidden = true;
    const submit = document.getElementById('emby-settings-submit');
    submit.disabled = true;
    try {
      const saved = await api('/_admin/api/emby-health/settings', jsonOptions('PUT', {
        default_retry_count: Number(document.getElementById('emby-cfg-retry-count').value),
        default_retry_delay_sec: Number(document.getElementById('emby-cfg-retry-delay').value),
        probe_timeout_sec: Number(document.getElementById('emby-cfg-timeout').value),
        apply_to_all: document.getElementById('emby-cfg-apply-all').checked
      }));
      state.embyProbeSettings = saved;
      closeDrawer('emby-settings-drawer');
      await refreshEmbyHealth();
      toast('探测重试策略已保存');
    } catch (failure) {
      errEl.textContent = failure?.message || '保存失败，请检查参数范围';
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  function openEmbyDrawerForCreate() {
    state.embyHealthEditingID = null;
    const cfg = state.embyProbeSettings || { default_retry_count: 2, default_retry_delay_sec: 2 };
    document.getElementById('emby-health-form').reset();
    document.getElementById('emby-health-group').value = 'Emby 服务器';
    document.getElementById('emby-health-probe-path').value = '';
    document.getElementById('emby-health-retry-count').value = String(cfg.default_retry_count ?? 2);
    document.getElementById('emby-health-retry-delay').value = String(cfg.default_retry_delay_sec ?? 2);
    document.getElementById('emby-health-enabled').checked = true;
    document.getElementById('emby-health-form-title').textContent = '添加探针服务器';
    document.getElementById('emby-health-submit').innerHTML = '<i data-lucide="plus"></i><span>添加服务器</span>';
    document.getElementById('emby-health-error').hidden = true;
    openDrawer('emby-drawer');
    window.setTimeout(() => document.getElementById('emby-health-name').focus(), 100);
  }

  function openEmbyDrawerForEdit(server) {
    state.embyHealthEditingID = server.id;
    document.getElementById('emby-health-group').value = server.group_name;
    document.getElementById('emby-health-name').value = server.name;
    document.getElementById('emby-health-line').value = server.line_name || '';
    document.getElementById('emby-health-url').value = server.base_url;
    document.getElementById('emby-health-probe-path').value = server.probe_path || '';
    document.getElementById('emby-health-retry-count').value = String(server.retry_count ?? 2);
    document.getElementById('emby-health-retry-delay').value = String(server.retry_delay_sec ?? 2);
    document.getElementById('emby-health-note').value = server.note || '';
    document.getElementById('emby-health-enabled').checked = server.enabled;
    document.getElementById('emby-health-form-title').textContent = '编辑探针服务器';
    document.getElementById('emby-health-submit').innerHTML = '<i data-lucide="save"></i><span>保存修改</span>';
    document.getElementById('emby-health-error').hidden = true;
    openDrawer('emby-drawer');
    window.setTimeout(() => document.getElementById('emby-health-name').focus(), 100);
  }

  function openEmbyBatchDrawer() {
    document.getElementById('emby-batch-form').reset();
    document.getElementById('emby-batch-group').value = 'Emby 服务器';
    document.getElementById('emby-batch-error').hidden = true;
    openDrawer('emby-batch-drawer');
    window.setTimeout(() => document.getElementById('emby-batch-urls').focus(), 100);
  }

  async function submitEmbyBatchImport(event) {
    event.preventDefault();
    const error = document.getElementById('emby-batch-error');
    error.hidden = true;
    const rawText = document.getElementById('emby-batch-urls').value || '';
    // Split on newlines, whitespace, or glued https:// / http:// boundaries.
    const normalizedText = rawText.replace(/(?<!^|\s)(https?:\/\/)/gi, ' $1');
    const urls = normalizedText.split(/[\s,，;；]+/).map((s) => s.trim()).filter(Boolean);
    if (!urls.length) {
      error.textContent = '请至少粘贴一个 Emby 服务器地址';
      error.hidden = false;
      return;
    }
    const submit = document.getElementById('emby-batch-submit');
    submit.disabled = true;
    try {
      const res = await api('/_admin/api/emby-health/batch', jsonOptions('POST', {
        group_name: document.getElementById('emby-batch-group').value.trim() || 'Emby 服务器',
        probe_path: document.getElementById('emby-batch-probe-path').value.trim(),
        enabled: true,
        urls
      }));
      closeDrawer('emby-batch-drawer');
      if (Array.isArray(res.servers)) renderEmbyHealth(res.servers);
      else await refreshEmbyHealth();
      const parts = [`新增 ${res.created || 0} 台`];
      if (res.skipped) parts.push(`跳过重复 ${res.skipped} 台`);
      if (Array.isArray(res.invalid) && res.invalid.length) parts.push(`无效 ${res.invalid.length} 条`);
      toast(`批量导入完成：${parts.join('，')}，正在执行首轮探测…`);
      window.setTimeout(() => { if (state.view === 'emby-health') refreshEmbyHealth().catch(() => {}); }, 3500);
    } catch (failure) {
      error.textContent = failure?.message || '批量导入失败，请检查地址格式';
      error.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  async function checkAllEmbyHealth() {
    const btn = document.getElementById('emby-health-check-all-btn');
    if (btn) {
      btn.disabled = true;
      btn.querySelector('svg')?.classList.add('spinning');
    }
    try {
      const servers = await api('/_admin/api/emby-health/check-all', jsonOptions('POST', {}));
      renderEmbyHealth(servers);
      toast('全部服务器探测完成');
    } catch {
      toast('批量探测失败，请稍后重试', 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.querySelector('svg')?.classList.remove('spinning');
      }
    }
  }

  async function saveEmbyHealth(event) {
    event.preventDefault();
    const error = document.getElementById('emby-health-error');
    error.hidden = true;
    let rawURL = document.getElementById('emby-health-url').value.trim();
    if (rawURL && !rawURL.includes('://')) rawURL = `https://${rawURL}`;
    const server = {
      group_name: document.getElementById('emby-health-group').value.trim(),
      name: document.getElementById('emby-health-name').value.trim(),
      line_name: document.getElementById('emby-health-line').value.trim(),
      base_url: rawURL,
      probe_path: document.getElementById('emby-health-probe-path').value.trim(),
      retry_count: Number(document.getElementById('emby-health-retry-count').value),
      retry_delay_sec: Number(document.getElementById('emby-health-retry-delay').value),
      note: document.getElementById('emby-health-note').value.trim(),
      enabled: document.getElementById('emby-health-enabled').checked
    };
    const submit = document.getElementById('emby-health-submit');
    submit.disabled = true;
    try {
      const editingID = state.embyHealthEditingID;
      await api(editingID ? `/_admin/api/emby-health/${editingID}` : '/_admin/api/emby-health', jsonOptions(editingID ? 'PUT' : 'POST', server));
      closeDrawer('emby-drawer');
      state.embyHealthEditingID = null;
      await refreshEmbyHealth();
      toast(editingID ? '探针服务器已更新' : '探针服务器已添加，正在探测…');
      window.setTimeout(() => { if (state.view === 'emby-health') refreshEmbyHealth().catch(() => {}); }, 2500);
    } catch (failure) {
      const messages = {
        'invalid group name': '请输入有效的分组名称',
        'invalid server name': '请输入有效的服务器名称',
        'invalid server URL': '请输入有效的服务器地址',
        'invalid probe path': '探测路径格式无效，请以 / 开头且不包含空格或查询参数',
        'probe path cannot contain dot segments': '探测路径不能包含 . 或 ..',
        'server URL must be an HTTP(S) base URL without credentials, query, or fragment': '地址必须是 HTTP(S) 基础地址，不能包含账号、查询参数或片段',
        'maximum monitored server count reached': '最多只能监测 200 台服务器'
      };
      error.textContent = messages[failure.message] || '保存失败，请检查输入后重试';
      error.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  async function checkEmbyHealth(server, button) {
    button.disabled = true;
    button.querySelector('svg')?.classList.add('spinning');
    try {
      await api(`/_admin/api/emby-health/${server.id}/check`, { method: 'POST' });
      await refreshEmbyHealth();
      toast(`${server.name} 探测完成`);
    } catch {
      toast('探测请求失败', 'error');
    } finally {
      button.disabled = false;
      button.querySelector('svg')?.classList.remove('spinning');
    }
  }

  async function toggleEmbyHealth(server, button) {
    if (button) button.disabled = true;
    try {
      await api(`/_admin/api/emby-health/${server.id}`, jsonOptions('PUT', {
        group_name: server.group_name, name: server.name, line_name: server.line_name || '',
        note: server.note || '', base_url: server.base_url, probe_path: server.probe_path || '',
        retry_count: Number(server.retry_count ?? 2), retry_delay_sec: Number(server.retry_delay_sec ?? 2),
        enabled: !server.enabled
      }));
      await refreshEmbyHealth();
      toast(server.enabled ? '已停用探测' : '已启用探测');
    } catch { toast('服务器状态更新失败', 'error'); }
    finally { if (button) button.disabled = false; }
  }

  async function deleteEmbyHealth(server, button) {
    const confirmed = await confirmAction({
      title: '删除监测服务器',
      message: `删除「${server.group_name} / ${server.name}」后，其历史探测样本也将一并移除。`,
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    if (button) button.disabled = true;
    try {
      await api(`/_admin/api/emby-health/${server.id}`, { method: 'DELETE' });
      await refreshEmbyHealth();
      toast('监测服务器已删除');
    } catch {
      if (button) button.disabled = false;
      toast('服务器删除失败', 'error');
    }
  }

  /* -------------------- Analytics & Reports -------------------- */

  function renderReportLiveChart() {
    const container = document.getElementById('report-live-chart');
    if (!container || state.view !== 'reports' || !window.echarts) return;
    if (!state.reportLiveChart) state.reportLiveChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const p = chartPalette();
    const option = areaChartBase(p);
    option.xAxis.data = state.liveSeries.map((pt) => new Date(pt.timestamp).toLocaleTimeString('zh-CN', {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: applicationTimeZone
    }));
    option.yAxis.axisLabel.formatter = (v) => `${formatBytes(v)}/s`;
    if (!state.liveSeries.some((pt) => pt.upload > 0 || pt.download > 0)) { option.yAxis.max = 1; option.yAxis.splitNumber = 1; }
    option.tooltip.valueFormatter = (v) => `${formatBytes(v)}/s`;
    option.series = [
      { name: '上传', type: 'line', smooth: 0.2, showSymbol: false, data: state.liveSeries.map((pt) => pt.upload), lineStyle: { width: 2, color: p.emerald }, itemStyle: { color: p.emerald }, areaStyle: { color: p.dark ? 'rgba(52,211,153,0.1)' : 'rgba(5,150,105,0.08)' } },
      { name: '下载', type: 'line', smooth: 0.2, showSymbol: false, data: state.liveSeries.map((pt) => pt.download), lineStyle: { width: 2, color: p.sky }, itemStyle: { color: p.sky }, areaStyle: { color: p.dark ? 'rgba(56,189,248,0.12)' : 'rgba(2,132,199,0.09)' } }
    ];
    state.reportLiveChart.setOption(option, true);
  }

  function renderReportTrendChart(report) {
    const container = document.getElementById('report-trend-chart');
    if (!container || !window.echarts) return;
    if (!state.reportTrendChart) state.reportTrendChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const p = chartPalette();
    const option = areaChartBase(p);
    const points = report.timeline || [];
    const shortPeriod = Number(report.period_hours) <= 24;
    option.title = points.length ? undefined : { text: '暂无流量数据', left: 'center', top: 'middle', textStyle: { color: p.muted, fontSize: 12.5, fontWeight: 400 } };
    option.xAxis.data = points.map((pt) => new Date(pt.timestamp * 1000).toLocaleString('zh-CN', shortPeriod ?
      { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: applicationTimeZone } :
      { month: '2-digit', day: '2-digit', timeZone: applicationTimeZone }));
    option.tooltip.valueFormatter = (v) => formatBytes(v);
    option.series = [
      { name: '上传', type: 'line', smooth: 0.2, showSymbol: false, data: points.map((pt) => Number(pt.bytes_in) || 0), lineStyle: { width: 2, color: p.emerald }, itemStyle: { color: p.emerald } },
      { name: '下载', type: 'line', smooth: 0.2, showSymbol: false, data: points.map((pt) => Number(pt.bytes_out) || 0), lineStyle: { width: 2, color: p.accent }, itemStyle: { color: p.accent }, areaStyle: { color: p.dark ? 'rgba(129,140,248,0.14)' : 'rgba(79,70,229,0.09)' } }
    ];
    state.reportTrendChart.setOption(option, true);
  }

  function renderReportRegionChart(regions) {
    const container = document.getElementById('report-region-chart');
    if (!container || !window.echarts) return;
    if (!state.reportRegionChart) state.reportRegionChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const p = chartPalette();
    const visible = (regions || []).slice(0, 8).map((r) => ({ name: r.label, value: Number(r.bytes_out) || 0 }));
    const remainder = (regions || []).slice(8).reduce((t, r) => t + (Number(r.bytes_out) || 0), 0);
    if (remainder > 0) visible.push({ name: '其他', value: remainder });
    state.reportRegionChart.setOption({
      animation: false,
      title: visible.length ? undefined : { text: '暂无地域数据', left: 'center', top: 'middle', textStyle: { color: p.muted, fontSize: 12.5, fontWeight: 400 } },
      color: [p.accent, p.sky, p.emerald, p.amber, p.rose, '#06b6d4', '#8b5cf6', '#64748b', '#ec4899'],
      tooltip: {
        trigger: 'item', confine: true, transitionDuration: 0, renderMode: 'richText',
        backgroundColor: p.surface, borderColor: p.border, textStyle: { color: p.text, fontSize: 12 },
        formatter: (params) => `${params.name || ''}\n${formatBytes(params.value)} · ${params.percent}%`
      },
      legend: { type: 'scroll', orient: 'vertical', top: 'middle', right: 8, textStyle: { color: p.muted, fontSize: 11 }, itemWidth: 10, itemHeight: 10, icon: 'roundRect' },
      series: [{ type: 'pie', radius: ['48%', '72%'], center: ['36%', '50%'], itemStyle: { borderColor: p.surface, borderWidth: 2 }, label: { show: false }, data: visible }]
    }, true);
  }

  function resizeReportCharts() {
    [state.reportLiveChart, state.reportTrendChart, state.reportRegionChart].forEach((c) => c?.resize());
  }

  function redrawReportCharts() {
    if (state.view !== 'reports') return;
    if (!window.echarts) {
      ensureEcharts().then(redrawReportCharts).catch(() => toast('图表引擎加载失败', 'error'));
      return;
    }
    renderReportLiveChart();
    if (state.report) {
      renderReportTrendChart(state.report);
      renderReportRegionChart(state.report.regions);
    }
    requestAnimationFrame(resizeReportCharts);
  }

  function renderReport(report) {
    state.report = report;
    const labels = { '24h': '最近 24 小时统计汇总', '7d': '最近 7 天统计汇总', '30d': '最近 30 天统计汇总', '90d': '最近 90 天统计汇总' };
    document.getElementById('report-period-label').textContent = labels[state.reportPeriod];
    document.getElementById('report-trend-label').textContent = Number(report.period_hours) <= 24 ? '按小时聚合' : Number(report.period_hours) <= 168 ? '每 6 小时聚合' : '按天聚合';
    document.getElementById('report-requests').textContent = formatNumber(report.requests);
    document.getElementById('report-download').textContent = formatBytes(report.bytes_out);
    document.getElementById('report-upload').textContent = `上传 ${formatBytes(report.bytes_in)}`;
    document.getElementById('report-targets').textContent = formatNumber(report.targets_count);
    document.getElementById('report-errors').textContent = formatNumber(report.errors);
    const errorRate = Number(report.requests) > 0 ? Number(report.errors) / Number(report.requests) * 100 : 0;
    document.getElementById('report-error-rate').textContent = `错误率 ${errorRate.toFixed(errorRate >= 10 ? 0 : 1)}%`;
    document.getElementById('report-target-total').textContent = `合计 ${formatBytes(report.bytes_out)}`;
    const historical = Number(report.unattributed_bytes_out) || 0;
    document.getElementById('report-client-total').textContent = historical > 0
      ? `合计 ${formatBytes(report.bytes_out)} · 含 ${formatBytes(historical)} 历史未归属`
      : `合计 ${formatBytes(report.bytes_out)}`;

    const targetBody = document.getElementById('report-targets-table');
    const targetEmpty = document.getElementById('report-targets-empty');
    if (!report.top_targets?.length) { targetBody.replaceChildren(); targetEmpty.hidden = false; }
    else {
      targetEmpty.hidden = true;
      const f = document.createDocumentFragment();
      report.top_targets.forEach((t) => {
        const row = document.createElement('tr');
        const host = el('td');
        const stack = el('div', 'cell-stack');
        const name = String(t.emby_server_name || '').trim() || t.host;
        stack.append(el('span', 'cell-primary', name));
        if (name !== t.host || t.emby_line_name) {
          const meta = el('div', 'cell-meta-row');
          if (name !== t.host) meta.append(el('span', 'cell-secondary mono', t.host));
          if (t.emby_line_name) meta.append(el('span', 'meta-tag accent', t.emby_line_name));
          stack.append(meta);
        }
        host.append(stack);
        [host, el('td', 'num-col', formatNumber(t.requests)), el('td', 'num-col mono', formatBytes(t.bytes_out)),
          el('td', 'num-col', formatNumber(t.errors)), el('td', 'num-col mono', `${t.avg_latency_ms} ms`)].forEach((c) => row.append(c));
        f.append(row);
      });
      targetBody.replaceChildren(f);
    }

    const clientBody = document.getElementById('report-clients-table');
    const clientEmpty = document.getElementById('report-clients-empty');
    if (!report.top_clients?.length) { clientBody.replaceChildren(); clientEmpty.hidden = false; }
    else {
      clientEmpty.hidden = true;
      const f = document.createDocumentFragment();
      report.top_clients.forEach((c) => {
        const row = document.createElement('tr');
        [el('td', 'mono cell-primary', c.ip), el('td', '', c.label || '未定位'),
          el('td', 'num-col', formatNumber(c.requests)), el('td', 'num-col mono', formatBytes(c.bytes_out)),
          el('td', 'num-col mono', c.ip === '-' ? '—' : `${formatBytes(c.peak_bps)}/s`)].forEach((cell) => row.append(cell));
        f.append(row);
      });
      clientBody.replaceChildren(f);
    }

    const regionBody = document.getElementById('report-regions-table');
    const regionEmpty = document.getElementById('report-regions-empty');
    if (!report.regions?.length) { regionBody.replaceChildren(); regionEmpty.hidden = false; }
    else {
      regionEmpty.hidden = true;
      const f = document.createDocumentFragment();
      report.regions.slice(0, 20).forEach((r) => {
        const row = document.createElement('tr');
        [el('td', 'cell-primary', r.label), el('td', 'num-col', formatNumber(r.unique_ips)),
          el('td', 'num-col mono', formatBytes(r.bytes_out)), el('td', 'num-col mono', `${formatBytes(r.peak_bps)}/s`)].forEach((c) => row.append(c));
        f.append(row);
      });
      regionBody.replaceChildren(f);
    }
    redrawReportCharts();
  }

  async function refreshReport() {
    renderReport(await api(`/_admin/api/reports?period=${encodeURIComponent(state.reportPeriod)}`));
  }

  /* -------------------- Visual DAG WAF Flow Editor (OpenFlare-Style) -------------------- */

  const wafNodeMeta = {
    start: { label: '请求入口', icon: 'play-circle', tone: 'accent', isMatch: false },
    host_match: { label: '目标域名匹配', icon: 'globe', tone: 'accent', isMatch: true },
    ip_match: { label: 'IP / CIDR 匹配', icon: 'network', tone: 'sky', isMatch: true },
    geo_match: { label: '国家 / 地区匹配', icon: 'globe-2', tone: 'emerald', isMatch: true },
    path_match: { label: '路径 / 攻击特征', icon: 'shield-alert', tone: 'amber', isMatch: true },
    player_match: { label: '客户端 / 播放器', icon: 'tv', tone: 'accent', isMatch: true },
    schedule_match: { label: '开放时段匹配', icon: 'clock-3', tone: 'accent', isMatch: true },
    pass: { label: '放行通过', icon: 'check-circle-2', tone: 'emerald', isMatch: false },
    block: { label: '拦截阻断', icon: 'shield-ban', tone: 'rose', isMatch: false }
  };

  function buildWAFTemplate(key) {
    if (key === 'proxy_host_allow') {
      return {
        name: '通用反代目标域名白名单',
        description: '仅允许路径拼接反代指定的上游目标域名（含子域名），防止通用反代被陌生人滥用',
        nodes: [
          { id: 'n_start', type: 'start', label: '请求入口', x: 60, y: 170, config: {} },
          { id: 'n_host', type: 'host_match', label: '允许反代的目标域名', x: 340, y: 155, config: { hosts: ['emby.example.com', 'media.example.com'] } },
          { id: 'n_pass', type: 'pass', label: '放行通过', x: 640, y: 80, config: {} },
          { id: 'n_block', type: 'block', label: '拦截未授权目标', x: 640, y: 245, config: { status_code: 403, message: 'upstream host blocked by WAF' } }
        ],
        edges: [
          { id: 'e_1', source: 'n_start', source_port: 'next', target: 'n_host' },
          { id: 'e_2', source: 'n_host', source_port: 'true', target: 'n_pass' },
          { id: 'e_3', source: 'n_host', source_port: 'false', target: 'n_block' }
        ]
      };
    }
    if (key === 'geo_only') {
      return {
        name: '仅放行亚太/中国地区',
        description: '仅允许中国大陆、港澳台、新加坡与日本地区访问，其余拦截 403',
        nodes: [
          { id: 'n_start', type: 'start', label: '请求入口', x: 60, y: 170, config: {} },
          { id: 'n_geo', type: 'geo_match', label: '亚太/中国地区', x: 340, y: 155, config: { countries: ['CN', 'HK', 'TW', 'MO', 'SG', 'JP'], match_unknown_geo: true } },
          { id: 'n_pass', type: 'pass', label: '放行通过', x: 640, y: 80, config: {} },
          { id: 'n_block', type: 'block', label: '拦截非目标地区', x: 640, y: 245, config: { status_code: 403, message: 'region blocked by WAF' } }
        ],
        edges: [
          { id: 'e_1', source: 'n_start', source_port: 'next', target: 'n_geo' },
          { id: 'e_2', source: 'n_geo', source_port: 'true', target: 'n_pass' },
          { id: 'e_3', source: 'n_geo', source_port: 'false', target: 'n_block' }
        ]
      };
    }
    if (key === 'ip_whitelist_scan') {
      return {
        name: 'IP 白名单 + 防扫描拦截',
        description: '受信任 IP 直接放行，其余请求过滤常见敏感路径扫描器',
        nodes: [
          { id: 'n_start', type: 'start', label: '请求入口', x: 50, y: 185, config: {} },
          { id: 'n_ip', type: 'ip_match', label: '信任 IP 白名单', x: 320, y: 170, config: { ips: ['127.0.0.1/32', '10.0.0.0/8'] } },
          { id: 'n_path', type: 'path_match', label: '常见扫描特征', x: 610, y: 245, config: { match_mode: 'contains', patterns: ['/.env', '/.git', 'wp-admin', 'wp-login', '../', '/phpmyadmin'] } },
          { id: 'n_pass', type: 'pass', label: '放行通过', x: 910, y: 110, config: {} },
          { id: 'n_block', type: 'block', label: '拦截扫描请求', x: 910, y: 275, config: { status_code: 403, message: 'suspicious path blocked' } }
        ],
        edges: [
          { id: 'e_1', source: 'n_start', source_port: 'next', target: 'n_ip' },
          { id: 'e_2', source: 'n_ip', source_port: 'true', target: 'n_pass' },
          { id: 'e_3', source: 'n_ip', source_port: 'false', target: 'n_path' },
          { id: 'e_4', source: 'n_path', source_port: 'true', target: 'n_block' },
          { id: 'e_5', source: 'n_path', source_port: 'false', target: 'n_pass' }
        ]
      };
    }
    if (key === 'schedule_player') {
      return {
        name: '定时开放 + 客户端限制',
        description: '仅在北京时间 09:00–23:00 放行指定 Emby 客户端',
        nodes: [
          { id: 'n_start', type: 'start', label: '请求入口', x: 50, y: 185, config: {} },
          { id: 'n_sched', type: 'schedule_match', label: '每日开放时段', x: 320, y: 170, config: { schedule_start: '09:00', schedule_end: '23:00' } },
          { id: 'n_player', type: 'player_match', label: '允许的播放器', x: 610, y: 95, config: { patterns: ['Infuse', 'Hills', 'Emby', 'VidHub', 'SenPlayer'] } },
          { id: 'n_pass', type: 'pass', label: '放行通过', x: 910, y: 75, config: {} },
          { id: 'n_block', type: 'block', label: '拒绝访问', x: 910, y: 255, config: { status_code: 403, message: 'access denied by schedule or client policy' } }
        ],
        edges: [
          { id: 'e_1', source: 'n_start', source_port: 'next', target: 'n_sched' },
          { id: 'e_2', source: 'n_sched', source_port: 'true', target: 'n_player' },
          { id: 'e_3', source: 'n_sched', source_port: 'false', target: 'n_block' },
          { id: 'e_4', source: 'n_player', source_port: 'true', target: 'n_pass' },
          { id: 'e_5', source: 'n_player', source_port: 'false', target: 'n_block' }
        ]
      };
    }
    return {
      name: '新建 WAF 规则',
      description: '',
      nodes: [
        { id: 'n_start', type: 'start', label: '请求入口', x: 80, y: 170, config: {} },
        { id: 'n_pass', type: 'pass', label: '放行通过', x: 400, y: 170, config: {} }
      ],
      edges: [
        { id: 'e_1', source: 'n_start', source_port: 'next', target: 'n_pass' }
      ]
    };
  }

  function renderWAFRules(payload) {
    const rules = Array.isArray(payload?.rules) ? payload.rules : [];
    const summary = payload?.summary || { total: rules.length, enabled: 0, global: 0, bound_domains: 0 };
    state.wafRules = rules;
    state.wafSummary = summary;
    renderPulseSummary();

    const kpiTotal = document.getElementById('waf-kpi-total');
    if (kpiTotal) kpiTotal.textContent = formatNumber(summary.total);
    const kpiEn = document.getElementById('waf-kpi-enabled');
    if (kpiEn) kpiEn.textContent = `${formatNumber(summary.enabled)} 条启用中`;
    const kpiGlobal = document.getElementById('waf-kpi-global');
    if (kpiGlobal) kpiGlobal.textContent = formatNumber(summary.global);
    const kpiDom = document.getElementById('waf-kpi-domains');
    if (kpiDom) kpiDom.textContent = formatNumber(summary.bound_domains);

    const body = document.getElementById('waf-rules-table');
    const empty = document.getElementById('waf-rules-empty');
    if (!body || !empty) return;
    if (!rules.length) {
      body.replaceChildren();
      empty.hidden = false;
      renderDomainWAFPicker();
      return;
    }
    empty.hidden = true;

    const frag = document.createDocumentFragment();
    rules.forEach((r) => {
      const row = document.createElement('tr');

      // 1. Name, description & visual flow summary
      const nameCell = el('td');
      const nameStack = el('div', 'cell-stack');
      const head = el('div', 'cell-meta-row');
      head.append(el('span', 'cell-primary', r.name), el('span', 'meta-tag', `${r.node_count || r.graph?.nodes?.length || 0} 节点`));
      nameStack.append(head);
      if (r.summary) {
        const sumEl = el('span', 'waf-flow-summary', r.summary);
        sumEl.title = r.summary;
        nameStack.append(sumEl);
      }
      if (r.description) nameStack.append(el('span', 'cell-secondary', r.description));
      nameCell.append(nameStack);

      // 2. Scope / Bound Domains
      const scopeCell = el('td');
      const scopeStack = el('div', 'cell-stack');
      if (r.is_global) {
        scopeStack.append(el('span', 'badge badge-emerald', '全局自动生效'));
        scopeStack.append(el('span', 'cell-secondary', '优先对所有域名执行'));
      } else {
        const bound = Array.isArray(r.bound_domains) ? r.bound_domains : [];
        if (!bound.length) {
          scopeStack.append(el('span', 'badge', '按域名绑定'));
          scopeStack.append(el('span', 'cell-secondary', '可在「域名入口」勾选绑定'));
        } else {
          const wrap = el('div', 'cell-meta-row');
          bound.slice(0, 3).forEach((bd) => wrap.append(el('span', 'meta-tag accent', bd.domain)));
          if (bound.length > 3) wrap.append(el('span', 'meta-tag', `+${bound.length - 3}`));
          scopeStack.append(wrap);
          scopeStack.append(el('span', 'cell-secondary', `已绑定 ${bound.length} 个域名`));
        }
      }
      scopeCell.append(scopeStack);

      // 3. Enabled switch
      const statusCell = el('td');
      const sw = el('label', 'switch');
      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.checked = Boolean(r.enabled);
      chk.ariaLabel = `切换规则 ${r.name} 启用状态`;
      chk.addEventListener('change', () => toggleWAFRuleEnabled(r, chk));
      sw.append(chk, el('span', 'switch-track'), el('span', '', r.enabled ? '启用' : '停用'));
      statusCell.append(sw);

      // 4. Actions
      const actCell = el('td', 'actions-col');
      const actRow = el('div', 'row-actions');
      const editBtn = el('button', 'btn btn-secondary btn-sm');
      editBtn.type = 'button';
      editBtn.innerHTML = '<i data-lucide="workflow"></i><span>可视化编排</span>';
      editBtn.addEventListener('click', () => wafEditor.openForEdit(r));

      const dupBtn = el('button', 'icon-btn');
      dupBtn.type = 'button'; dupBtn.title = '复制规则到新画布'; dupBtn.setAttribute('aria-label', '复制规则到新画布');
      dupBtn.innerHTML = '<i data-lucide="copy"></i>';
      dupBtn.addEventListener('click', () => wafEditor.openDuplicate(r));

      const delBtn = el('button', 'icon-btn danger');
      delBtn.type = 'button'; delBtn.title = '删除 WAF 规则'; delBtn.setAttribute('aria-label', '删除 WAF 规则');
      delBtn.innerHTML = '<i data-lucide="trash-2"></i>';
      delBtn.addEventListener('click', () => deleteWAFRule(r, delBtn));

      actRow.append(editBtn, dupBtn, delBtn);
      actCell.append(actRow);

      row.append(nameCell, scopeCell, statusCell, actCell);
      frag.append(row);
    });
    body.replaceChildren(frag);
    refreshIcons();
    renderDomainWAFPicker();
  }

  async function refreshWAFRules() {
    if (state.wafRulesPromise) return state.wafRulesPromise;
    const req = api('/_admin/api/waf-rules').then((payload) => {
      renderWAFRules(payload);
      return payload;
    });
    state.wafRulesPromise = req;
    try { return await req; } finally {
      if (state.wafRulesPromise === req) state.wafRulesPromise = null;
    }
  }

  async function toggleWAFRuleEnabled(rule, checkbox) {
    checkbox.disabled = true;
    try {
      await api(`/_admin/api/waf-rules/${encodeURIComponent(rule.id)}`, jsonOptions('PUT', {
        name: rule.name,
        description: rule.description,
        enabled: checkbox.checked,
        is_global: rule.is_global,
        graph: rule.graph
      }));
      await Promise.all([refreshWAFRules(), refreshDomains().catch(() => {})]);
      toast(`WAF 规则「${rule.name}」已${checkbox.checked ? '启用' : '停用'}并热同步`);
    } catch (failure) {
      checkbox.checked = !checkbox.checked;
      toast(failure.message || '切换 WAF 规则状态失败', 'error');
    } finally {
      checkbox.disabled = false;
    }
  }

  async function deleteWAFRule(rule, button) {
    const confirmed = await confirmAction({
      title: `删除 WAF 规则「${rule.name}」`,
      message: '删除后将自动从所有已绑定的域名解绑，并立即热同步至全部边缘机器。',
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      await api(`/_admin/api/waf-rules/${encodeURIComponent(rule.id)}`, { method: 'DELETE' });
      await Promise.all([refreshWAFRules(), refreshDomains().catch(() => {})]);
      toast(`WAF 规则「${rule.name}」已删除`);
    } catch {
      button.disabled = false;
      toast('删除 WAF 规则失败', 'error');
    }
  }

  const wafEditor = {
    editingID: null,
    enabled: true,
    description: '',
    boundDomains: [],
    nodes: [],
    edges: [],
    selectedNodeID: null,
    selectedEdgeID: null,
    panX: 30,
    panY: 30,
    zoom: 1,
    traceNodes: new Set(),
    traceEdges: new Set(),
    traceBlocked: false,
    drag: null,
    seq: 10,
    eventsBound: false,
    detectedPlayers: [],
    playerPresets: ['SenPlayer', 'Infuse', 'VidHub', 'Yamby', 'Hills', 'RodelPlayer', 'CapyPlayer', 'Forward', 'AfuseKt', 'Fileball', 'Emby', 'Jellyfin'],
    detectedPlayersLoaded: false,
    detectedPlayersLoading: false,

    async loadDetectedPlayers(force = false) {
      if (this.detectedPlayersLoading) return;
      if (this.detectedPlayersLoaded && !force) return;
      this.detectedPlayersLoading = true;
      const selNode = this.nodes.find((n) => n.id === this.selectedNodeID);
      if (selNode && selNode.type === 'player_match') this.renderInspector();
      try {
        const res = await api('/_admin/api/waf-rules/detected-players');
        this.detectedPlayers = Array.isArray(res?.players) ? res.players : [];
        if (Array.isArray(res?.presets) && res.presets.length) {
          this.playerPresets = res.presets;
        }
        this.detectedPlayersLoaded = true;
      } catch {
        // Keep previously loaded list or presets on transient error
      } finally {
        this.detectedPlayersLoading = false;
        const curNode = this.nodes.find((n) => n.id === this.selectedNodeID);
        if (curNode && curNode.type === 'player_match') this.renderInspector();
      }
    },

    nextID(prefix) {
      this.seq += 1;
      return `${prefix}_${Date.now().toString(36).slice(-4)}_${this.seq}`;
    },

    clearTrace() {
      this.traceNodes.clear();
      this.traceEdges.clear();
      this.traceBlocked = false;
      const resBadge = document.getElementById('waf-sim-result');
      if (resBadge) resBadge.hidden = true;
    },

    openForCreate(templateKey = 'blank') {
      const tpl = buildWAFTemplate(templateKey);
      this.editingID = null;
      this.enabled = true;
      this.description = tpl.description || '';
      this.boundDomains = [];
      this.nodes = structuredClone(tpl.nodes);
      this.edges = structuredClone(tpl.edges);
      this.selectedNodeID = this.nodes.find((n) => n.type !== 'start')?.id || 'n_start';
      this.selectedEdgeID = null;
      this.clearTrace();
      document.getElementById('waf-rule-name').value = tpl.name;
      document.getElementById('waf-rule-global').checked = false;
      document.getElementById('waf-template-select').value = '';
      document.getElementById('waf-sim-bar').hidden = true;
      this.bindCanvasEvents();
      this.loadDetectedPlayers(true);
      openDrawer('waf-editor-drawer');
      requestAnimationFrame(() => {
        this.render();
        this.fitView();
      });
    },

    openForEdit(rule) {
      this.editingID = rule.id;
      this.enabled = rule.enabled !== false;
      this.description = rule.description || '';
      this.boundDomains = Array.isArray(rule.bound_domains) ? rule.bound_domains : [];
      const g = rule.graph || buildWAFTemplate('blank');
      this.nodes = structuredClone(Array.isArray(g.nodes) ? g.nodes : []);
      this.edges = structuredClone(Array.isArray(g.edges) ? g.edges : []);
      this.selectedNodeID = null;
      this.selectedEdgeID = null;
      this.clearTrace();
      document.getElementById('waf-rule-name').value = rule.name || '';
      document.getElementById('waf-rule-global').checked = Boolean(rule.is_global);
      document.getElementById('waf-template-select').value = '';
      document.getElementById('waf-sim-bar').hidden = true;
      this.bindCanvasEvents();
      this.loadDetectedPlayers(true);
      openDrawer('waf-editor-drawer');
      requestAnimationFrame(() => {
        this.render();
        this.fitView();
      });
    },

    openDuplicate(rule) {
      this.openForEdit(rule);
      this.editingID = null;
      this.boundDomains = [];
      document.getElementById('waf-rule-name').value = `${rule.name} (副本)`;
    },

    applyTemplate(key) {
      if (!key) return;
      const tpl = buildWAFTemplate(key);
      this.nodes = structuredClone(tpl.nodes);
      this.edges = structuredClone(tpl.edges);
      this.selectedNodeID = this.nodes.find((n) => n.type !== 'start')?.id || null;
      this.selectedEdgeID = null;
      this.clearTrace();
      const nameInput = document.getElementById('waf-rule-name');
      if (nameInput && (!nameInput.value.trim() || nameInput.value.trim() === '新建 WAF 规则')) {
        nameInput.value = tpl.name;
      }
      if (!this.description && tpl.description) this.description = tpl.description;
      this.render();
      this.fitView();
    },

    addNode(type, pos = null) {
      const meta = wafNodeMeta[type];
      if (!meta || type === 'start') return null;
      const wrap = document.getElementById('waf-canvas-wrap');
      const rect = wrap ? wrap.getBoundingClientRect() : { width: 720, height: 480 };
      const jitter = (this.nodes.length % 5) * 28;
      const cx = pos && Number.isFinite(pos.x)
        ? Math.round(pos.x)
        : Math.round(((rect.width * 0.48 - this.panX) / this.zoom) - 109 + jitter);
      const cy = pos && Number.isFinite(pos.y)
        ? Math.round(pos.y)
        : Math.round(((rect.height * 0.45 - this.panY) / this.zoom) - 52 + jitter);
      const cfg = {};
      if (type === 'host_match') cfg.hosts = ['emby.example.com'];
      if (type === 'ip_match') cfg.ips = ['1.2.3.4'];
      if (type === 'geo_match') { cfg.countries = ['CN']; cfg.match_unknown_geo = false; }
      if (type === 'path_match') { cfg.match_mode = 'contains'; cfg.patterns = ['/.env', 'wp-admin']; }
      if (type === 'player_match') cfg.patterns = ['Infuse'];
      if (type === 'schedule_match') { cfg.schedule_start = '09:00'; cfg.schedule_end = '23:00'; }
      if (type === 'block') { cfg.status_code = 403; cfg.message = 'blocked by WAF rule'; }
      const node = { id: this.nextID('n'), type, label: meta.label, x: Math.max(12, cx), y: Math.max(12, cy), config: cfg };
      this.nodes.push(node);
      this.selectedNodeID = node.id;
      this.selectedEdgeID = null;
      this.clearTrace();
      this.render();
      const card = document.querySelector(`.waf-node[data-node-id="${CSS.escape(node.id)}"]`);
      if (card) {
        card.classList.add('just-dropped');
        card.addEventListener('animationend', () => card.classList.remove('just-dropped'), { once: true });
      }
      return node;
    },

    startPaletteDrag(type, sourceEl, ev) {
      if (!wafNodeMeta[type] || type === 'start' || ev.button !== 0) return;
      ev.preventDefault();
      this.cancelPaletteDrag();
      this.drag = {
        mode: 'palette',
        type,
        sourceEl,
        startX: ev.clientX,
        startY: ev.clientY,
        started: false,
        overCanvas: false,
        ghostEl: null
      };
    },

    cancelPaletteDrag() {
      if (this.drag && this.drag.mode === 'palette') {
        if (this.drag.ghostEl) this.drag.ghostEl.remove();
        if (this.drag.sourceEl) this.drag.sourceEl.classList.remove('is-dragging');
        this.drag = null;
      }
      document.body.classList.remove('waf-palette-dragging');
      document.getElementById('waf-canvas-wrap')?.classList.remove('is-drop-ready');
    },

    cancelActiveDrag() {
      if (!this.drag) return;
      const mode = this.drag.mode;
      if (mode === 'palette') {
        this.cancelPaletteDrag();
        return;
      }
      this.drag = null;
      const wrap = document.getElementById('waf-canvas-wrap');
      wrap?.classList.remove('is-panning', 'is-connecting', 'is-drop-ready');
      document.querySelectorAll('.waf-port.port-in.drop-ready').forEach((elP) => elP.classList.remove('drop-ready'));
      if (mode === 'wire') this.renderEdgesOnly();
    },

    removeNode(id) {
      const target = this.nodes.find((n) => n.id === id);
      if (!target || target.type === 'start') return;
      this.nodes = this.nodes.filter((n) => n.id !== id);
      this.edges = this.edges.filter((e) => e.source !== id && e.target !== id);
      if (this.selectedNodeID === id) this.selectedNodeID = null;
      this.clearTrace();
      this.render();
    },

    removeEdge(id) {
      this.edges = this.edges.filter((e) => e.id !== id);
      if (this.selectedEdgeID === id) this.selectedEdgeID = null;
      this.clearTrace();
      this.render();
    },

    connect(sourceID, sourcePort, targetID) {
      if (!sourceID || !targetID || sourceID === targetID) return;
      const targetNode = this.nodes.find((n) => n.id === targetID);
      if (!targetNode || targetNode.type === 'start') {
        toast('不能将连线指回「请求入口」', 'error');
        return;
      }
      // Replace any existing edge from the same (source, sourcePort)
      this.edges = this.edges.filter((e) => !(e.source === sourceID && e.source_port === sourcePort));
      this.edges.push({ id: this.nextID('e'), source: sourceID, source_port: sourcePort, target: targetID });
      this.selectedEdgeID = null;
      this.clearTrace();
      this.render();
    },

    nodeSummaryText(node) {
      const c = node.config || {};
      switch (node.type) {
        case 'start': return '所有进入该规则的 HTTP 请求';
        case 'pass': return '通过当前规则并放行请求';
        case 'block': return `返回 HTTP ${c.status_code || 403} · ${c.message || '拦截'}`;
        case 'host_match': {
          const list = Array.isArray(c.hosts) ? c.hosts.filter(Boolean) : [];
          if (!list.length) return '未配置目标域名';
          return list.slice(0, 2).join(', ') + (list.length > 2 ? ` (+${list.length - 2})` : '');
        }
        case 'ip_match': {
          const list = Array.isArray(c.ips) ? c.ips.filter(Boolean) : [];
          if (!list.length) return '未配置 IP / CIDR';
          return list.slice(0, 2).join(', ') + (list.length > 2 ? ` (+${list.length - 2})` : '');
        }
        case 'geo_match': {
          const list = Array.isArray(c.countries) ? c.countries.filter(Boolean) : [];
          if (!list.length) return c.match_unknown_geo ? '仅匹配未知地区' : '未选择国家/地区';
          return list.slice(0, 6).join(', ') + (list.length > 6 ? ` (+${list.length - 6})` : '');
        }
        case 'path_match': {
          const list = Array.isArray(c.patterns) ? c.patterns.filter(Boolean) : [];
          const mLabel = c.match_mode === 'regex' ? '正则' : c.match_mode === 'prefix' ? '前缀' : '包含';
          if (!list.length) return `${mLabel} · 未填特征`;
          return `${mLabel}：${list.slice(0, 2).join(', ')}${list.length > 2 ? ` (+${list.length - 2})` : ''}`;
        }
        case 'player_match': {
          const list = Array.isArray(c.patterns) ? c.patterns.filter(Boolean) : [];
          if (!list.length) return '未填客户端/UA关键词';
          return list.slice(0, 3).join(', ') + (list.length > 3 ? ` (+${list.length - 3})` : '');
        }
        case 'schedule_match':
          return `北京时间 ${c.schedule_start || '09:00'} – ${c.schedule_end || '23:00'}`;
        default:
          return '';
      }
    },

    validateGraph() {
      const start = this.nodes.find((n) => n.type === 'start');
      if (!start) return { ok: false, message: '缺少「请求入口」节点' };
      const byID = new Map(this.nodes.map((n) => [n.id, n]));
      const outMap = new Map();
      const adj = new Map(this.nodes.map((n) => [n.id, []]));
      for (const e of this.edges) {
        if (!byID.has(e.source) || !byID.has(e.target)) continue;
        outMap.set(`${e.source}:${e.source_port}`, e.target);
        adj.get(e.source).push(e.target);
      }
      // Cycle check
      const color = new Map();
      const dfs = (u) => {
        color.set(u, 1);
        for (const v of adj.get(u) || []) {
          if (color.get(v) === 1) return true;
          if (!color.get(v) && dfs(v)) return true;
        }
        color.set(u, 2);
        return false;
      };
      for (const n of this.nodes) {
        if (!color.get(n.id) && dfs(n.id)) return { ok: false, message: '规则图存在循环连线，请断开闭环' };
      }
      // Reachability & dangling branch check
      const visited = new Set([start.id]);
      const q = [start.id];
      while (q.length) {
        const u = q.shift();
        const node = byID.get(u);
        if (!node) continue;
        if (node.type === 'start' && !outMap.has(`${u}:next`)) {
          return { ok: false, message: '请从「请求入口」右侧圆点拖线连接到下一个节点' };
        }
        if (wafNodeMeta[node.type]?.isMatch) {
          if (!outMap.has(`${u}:true`)) return { ok: false, message: `节点「${node.label}」的「命中」分支尚未连线` };
          if (!outMap.has(`${u}:false`)) return { ok: false, message: `节点「${node.label}」的「未命中」分支尚未连线` };
          const c = node.config || {};
          if (node.type === 'host_match' && !(c.hosts || []).filter(Boolean).length) return { ok: false, message: `节点「${node.label}」请至少填写 1 个目标域名` };
          if (node.type === 'ip_match' && !(c.ips || []).filter(Boolean).length) return { ok: false, message: `节点「${node.label}」请至少填写 1 条 IP/CIDR` };
          if (node.type === 'geo_match' && !(c.countries || []).filter(Boolean).length && !c.match_unknown_geo) return { ok: false, message: `节点「${node.label}」请至少选择 1 个国家/地区` };
          if (node.type === 'path_match' && !(c.patterns || []).filter(Boolean).length) return { ok: false, message: `节点「${node.label}」请至少填写 1 条路径特征` };
          if (node.type === 'player_match' && !(c.patterns || []).filter(Boolean).length) return { ok: false, message: `节点「${node.label}」请至少填写 1 个客户端关键词` };
        }
        for (const v of adj.get(u) || []) {
          if (!visited.has(v)) { visited.add(v); q.push(v); }
        }
      }
      return { ok: true, message: '规则图有效，可直接保存并热下发' };
    },

    autoLayout() {
      const start = this.nodes.find((n) => n.type === 'start');
      if (!start) return;
      const depth = new Map([[start.id, 0]]);
      const q = [start.id];
      while (q.length) {
        const u = q.shift();
        const d = depth.get(u);
        this.edges.filter((e) => e.source === u).forEach((e) => {
          const prev = depth.get(e.target);
          if (prev === undefined || d + 1 > prev) {
            if (d + 1 <= this.nodes.length) {
              depth.set(e.target, d + 1);
              q.push(e.target);
            }
          }
        });
      }
      const cols = new Map();
      this.nodes.forEach((n) => {
        const col = depth.has(n.id) ? depth.get(n.id) : 1;
        if (!cols.has(col)) cols.set(col, []);
        cols.get(col).push(n);
      });
      const maxRows = Math.max(1, ...Array.from(cols.values()).map((arr) => arr.length));
      cols.forEach((arr, col) => {
        const yOffset = ((maxRows - arr.length) * 168) / 2;
        arr.forEach((n, rowIdx) => {
          n.x = Math.round(56 + col * 292);
          n.y = Math.round(64 + yOffset + rowIdx * 168);
        });
      });
      this.render();
      this.fitView();
    },

    setTransform(panX, panY, zoom) {
      this.panX = panX;
      this.panY = panY;
      this.zoom = Math.max(0.35, Math.min(2.0, zoom));
      const stage = document.getElementById('waf-stage');
      if (stage) stage.style.transform = `translate(${Math.round(this.panX)}px, ${Math.round(this.panY)}px) scale(${this.zoom})`;
      const zLabel = document.getElementById('waf-zoom-label');
      if (zLabel) zLabel.textContent = `${Math.round(this.zoom * 100)}%`;
    },

    zoomAt(targetZoom, clientX = null, clientY = null) {
      const wrap = document.getElementById('waf-canvas-wrap');
      if (!wrap) return;
      const rect = wrap.getBoundingClientRect();
      const px = Number.isFinite(clientX) ? clientX - rect.left : rect.width / 2;
      const py = Number.isFinite(clientY) ? clientY - rect.top : rect.height / 2;
      const oldZoom = this.zoom || 1;
      const clamped = Math.max(0.35, Math.min(2.0, targetZoom));
      if (Math.abs(clamped - oldZoom) < 0.0005) return;
      const ratio = clamped / oldZoom;
      this.setTransform(px - (px - this.panX) * ratio, py - (py - this.panY) * ratio, clamped);
    },

    fitView() {
      const wrap = document.getElementById('waf-canvas-wrap');
      if (!wrap || !this.nodes.length) return;
      const rect = wrap.getBoundingClientRect();
      if (rect.width < 100 || rect.height < 100) return;
      let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
      this.nodes.forEach((n) => {
        minX = Math.min(minX, n.x);
        minY = Math.min(minY, n.y);
        maxX = Math.max(maxX, n.x + 220);
        maxY = Math.max(maxY, n.y + 135);
      });
      const contentW = Math.max(240, maxX - minX);
      const contentH = Math.max(160, maxY - minY);
      const pad = 56;
      const scale = Math.min(1, Math.max(0.55, Math.min((rect.width - pad * 2) / contentW, (rect.height - pad * 2) / contentH)));
      const panX = (rect.width - contentW * scale) / 2 - minX * scale;
      const panY = (rect.height - contentH * scale) / 2 - minY * scale;
      this.setTransform(panX, panY, scale);
    },

    getPortCenter(nodeID, port) {
      const node = this.nodes.find((n) => n.id === nodeID);
      if (!node) return { x: 0, y: 0 };
      const nodeEl = document.querySelector(`.waf-node[data-node-id="${CSS.escape(nodeID)}"]`);
      if (port === 'in') {
        return { x: node.x - 1, y: node.y + 22 };
      }
      if (nodeEl) {
        const portEl = nodeEl.querySelector(`.waf-port[data-port="${CSS.escape(port)}"]`);
        const rowEl = portEl?.closest('.waf-port-row');
        if (rowEl) {
          return {
            x: node.x + nodeEl.offsetWidth + 1,
            y: node.y + rowEl.offsetTop + rowEl.offsetHeight / 2
          };
        }
        return { x: node.x + nodeEl.offsetWidth + 1, y: node.y + nodeEl.offsetHeight - 16 };
      }
      return { x: node.x + 219, y: node.y + (port === 'false' ? 105 : 78) };
    },

    bezierPath(x1, y1, x2, y2) {
      const dx = Math.max(54, Math.abs(x2 - x1) * 0.48);
      return `M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${(x1 + dx).toFixed(1)} ${y1.toFixed(1)}, ${(x2 - dx).toFixed(1)} ${y2.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;
    },

    renderEdgesOnly() {
      const svg = document.getElementById('waf-edges-layer');
      const badgesWrap = document.getElementById('waf-edge-badges');
      if (!svg || !badgesWrap) return;
      const ns = 'http://www.w3.org/2000/svg';
      const svgFrag = document.createDocumentFragment();
      const badgeFrag = document.createDocumentFragment();

      this.edges.forEach((edge) => {
        const p1 = this.getPortCenter(edge.source, edge.source_port);
        const p2 = this.getPortCenter(edge.target, 'in');
        const d = this.bezierPath(p1.x, p1.y, p2.x, p2.y);

        const hit = document.createElementNS(ns, 'path');
        hit.setAttribute('d', d);
        hit.setAttribute('class', 'waf-edge-hit');
        hit.addEventListener('pointerdown', (ev) => {
          ev.stopPropagation();
        });
        hit.addEventListener('click', (ev) => {
          ev.stopPropagation();
          if (this.selectedEdgeID === edge.id) {
            this.removeEdge(edge.id);
            return;
          }
          this.selectedEdgeID = edge.id;
          this.selectedNodeID = null;
          document.querySelectorAll('.waf-node.selected').forEach((n) => n.classList.remove('selected'));
          this.renderEdgesOnly();
          this.renderInspector();
        });
        hit.addEventListener('dblclick', (ev) => {
          ev.stopPropagation();
          this.removeEdge(edge.id);
        });
        hit.addEventListener('contextmenu', (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          this.removeEdge(edge.id);
        });

        const path = document.createElementNS(ns, 'path');
        path.setAttribute('d', d);
        const cls = ['waf-edge-path', `port-${edge.source_port}`];
        if (this.selectedEdgeID === edge.id) cls.push('selected');
        if (this.traceEdges.has(edge.id)) cls.push('traced');
        path.setAttribute('class', cls.join(' '));
        svgFrag.append(hit, path);

        // Midpoint 1-click disconnect badge for every edge (including start -> next)
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        const isSel = this.selectedEdgeID === edge.id;
        const portText = edge.source_port === 'true' ? '命中' : edge.source_port === 'false' ? '未命中' : '';
        const b = el('button', `waf-edge-badge port-${edge.source_port}${isSel ? ' selected' : ''}`);
        b.type = 'button';
        b.style.left = `${mx.toFixed(1)}px`;
        b.style.top = `${my.toFixed(1)}px`;
        if (isSel) {
          b.append(el('span', '', '断开连线'), el('span', 'waf-edge-x', '×'));
        } else if (portText) {
          b.append(el('span', '', portText), el('span', 'waf-edge-x', '×'));
        } else {
          b.append(el('span', 'waf-edge-x', '×'));
        }
        b.title = '点击断开此连线';
        b.setAttribute('aria-label', portText ? `断开${portText}连线` : '断开连线');
        b.addEventListener('pointerdown', (ev) => {
          ev.stopPropagation();
        });
        b.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this.removeEdge(edge.id);
        });
        badgeFrag.append(b);
      });

      if (this.drag && this.drag.mode === 'wire') {
        const draft = document.createElementNS(ns, 'path');
        draft.setAttribute('d', this.bezierPath(this.drag.x1, this.drag.y1, this.drag.x2, this.drag.y2));
        draft.setAttribute('class', 'waf-edge-draft');
        svgFrag.append(draft);
      }

      svg.replaceChildren(svgFrag);
      badgesWrap.replaceChildren(badgeFrag);
    },

    renderStatusBar() {
      const bar = document.getElementById('waf-canvas-status');
      const txt = document.getElementById('waf-canvas-status-text');
      if (!bar || !txt) return;
      const v = this.validateGraph();
      bar.classList.toggle('has-error', !v.ok);
      const nextIconName = v.ok ? 'check-circle-2' : 'alert-triangle';
      if (bar.dataset.statusIcon !== nextIconName) {
        bar.dataset.statusIcon = nextIconName;
        const oldIcon = bar.querySelector('i, svg');
        const fresh = document.createElement('i');
        fresh.setAttribute('data-lucide', nextIconName);
        if (oldIcon) oldIcon.replaceWith(fresh);
        else bar.prepend(fresh);
        refreshIcons();
      }
      txt.textContent = v.message;
    },

    render() {
      const nodesLayer = document.getElementById('waf-nodes-layer');
      if (!nodesLayer) return;
      const wiredPorts = new Set(this.edges.map((e) => `${e.source}:${e.source_port}`));
      const frag = document.createDocumentFragment();

      this.nodes.forEach((node) => {
        const meta = wafNodeMeta[node.type] || { label: node.type, icon: 'circle', tone: 'accent', isMatch: false };
        const card = el('div', `waf-node type-${node.type}`);
        card.dataset.nodeId = node.id;
        card.style.left = `${Math.round(node.x)}px`;
        card.style.top = `${Math.round(node.y)}px`;
        if (this.selectedNodeID === node.id) card.classList.add('selected');
        if (this.traceNodes.has(node.id)) {
          if (node.type === 'block') card.classList.add('traced-blocked');
          else if (node.type === 'pass') card.classList.add('traced-passed');
          else card.classList.add('traced');
        }

        if (node.type !== 'start') {
          const inPort = el('div', 'waf-port port-in');
          inPort.dataset.port = 'in';
          inPort.dataset.nodeId = node.id;
          inPort.title = '拖线到此处连接输入';
          card.append(inPort);
        }

        const head = el('div', 'waf-node-head');
        const iconWrap = el('span', `waf-palette-icon ${meta.tone}`);
        iconWrap.innerHTML = `<i data-lucide="${meta.icon}"></i>`;
        head.append(iconWrap, el('span', 'waf-node-title', node.label || meta.label));
        if (node.type !== 'start') {
          const del = el('button', 'waf-node-del');
          del.type = 'button'; del.title = '删除节点'; del.setAttribute('aria-label', '删除节点');
          del.innerHTML = '<i data-lucide="x"></i>';
          del.addEventListener('pointerdown', (ev) => ev.stopPropagation());
          del.addEventListener('click', (ev) => { ev.stopPropagation(); this.removeNode(node.id); });
          head.append(del);
        }
        card.append(head);

        const body = el('div', 'waf-node-body', this.nodeSummaryText(node));
        card.append(body);

        if (node.type === 'start' || meta.isMatch) {
          const ports = el('div', 'waf-node-ports');
          const defs = node.type === 'start'
            ? [{ port: 'next', label: '流出' }]
            : [{ port: 'true', label: '命中' }, { port: 'false', label: '未命中' }];
          defs.forEach((def) => {
            const pr = el('div', `waf-port-row port-${def.port}`);
            pr.append(el('span', '', def.label));
            const dot = el('div', `waf-port port-out port-${def.port}${wiredPorts.has(`${node.id}:${def.port}`) ? ' wired' : ''}`);
            dot.dataset.port = def.port;
            dot.dataset.nodeId = node.id;
            dot.title = `按住拖出「${def.label}」连线`;
            dot.addEventListener('pointerdown', (ev) => {
              if (ev.button !== 0) return;
              ev.stopPropagation();
              ev.preventDefault();
              const p1 = this.getPortCenter(node.id, def.port);
              this.drag = { mode: 'wire', sourceID: node.id, sourcePort: def.port, x1: p1.x, y1: p1.y, x2: p1.x, y2: p1.y, pointerId: ev.pointerId };
              document.getElementById('waf-canvas-wrap')?.classList.add('is-connecting');
              document.querySelectorAll('.waf-port.port-in').forEach((elPort) => {
                if (elPort.dataset.nodeId !== node.id) elPort.classList.add('drop-ready');
              });
              this.renderEdgesOnly();
            });
            pr.append(dot);
            ports.append(pr);
          });
          card.append(ports);
        }

        card.addEventListener('pointerdown', (ev) => {
          if (ev.button !== 0) return;
          if (ev.target.closest('.waf-port') || ev.target.closest('.waf-node-del')) return;
          ev.stopPropagation();
          this.selectedNodeID = node.id;
          this.selectedEdgeID = null;
          this.drag = {
            mode: 'node',
            nodeID: node.id,
            startClientX: ev.clientX,
            startClientY: ev.clientY,
            origX: node.x,
            origY: node.y
          };
          document.querySelectorAll('.waf-node').forEach((elN) => elN.classList.toggle('selected', elN.dataset.nodeId === node.id));
          this.renderEdgesOnly();
          this.renderInspector();
        });

        frag.append(card);
      });

      nodesLayer.replaceChildren(frag);
      this.setTransform(this.panX, this.panY, this.zoom);
      this.renderEdgesOnly();
      this.renderStatusBar();
      this.renderInspector();
      refreshIcons();
    },

    renderInspector() {
      const panel = document.getElementById('waf-inspector');
      if (!panel) return;
      const node = this.nodes.find((n) => n.id === this.selectedNodeID);

      if (!node && this.selectedEdgeID) {
        const edge = this.edges.find((e) => e.id === this.selectedEdgeID);
        if (edge) {
          const src = this.nodes.find((n) => n.id === edge.source);
          const dst = this.nodes.find((n) => n.id === edge.target);
          const pName = edge.source_port === 'true' ? '命中分支' : edge.source_port === 'false' ? '未命中分支' : '入口流出';
          const frag = document.createDocumentFragment();
          const head = el('div', 'waf-inspector-head');
          head.append(el('strong', '', '连线属性'), el('span', 'badge badge-rose', pName));
          frag.append(head);

          const info = el('div', 'waf-wire-item');
          info.append(el('span', '', `${src ? src.label : edge.source} → ${dst ? dst.label : edge.target}`));
          frag.append(info);

          const delBtn = el('button', 'btn btn-danger-soft btn-sm btn-block');
          delBtn.type = 'button';
          delBtn.innerHTML = '<i data-lucide="unlink"></i><span>断开此连线</span>';
          delBtn.addEventListener('click', () => this.removeEdge(edge.id));
          frag.append(delBtn);

          frag.append(el('p', 'field-hint', '也可直接点击连线上的 × 标签、右键连线或按 Delete / Backspace 键快速断开。'));
          panel.replaceChildren(frag);
          refreshIcons();
          return;
        }
      }

      if (!node) {
        const frag = document.createDocumentFragment();
        const head = el('div', 'waf-inspector-head');
        head.append(el('strong', '', '规则概览与校验'), el('span', 'badge', `${this.nodes.length} 节点`));
        frag.append(head);

        const descField = el('div', 'field');
        descField.append(el('label', 'field-label', '规则说明（可选）'));
        const ta = document.createElement('textarea');
        ta.rows = 3;
        ta.maxLength = 200;
        ta.placeholder = '例如：仅允许亚太地区访问，并拦截 .env 扫描';
        ta.value = this.description || '';
        ta.addEventListener('input', (ev) => { this.description = ev.currentTarget.value; });
        descField.append(ta);
        frag.append(descField);

        const v = this.validateGraph();
        const statusBox = el('div', `domain-callout ${v.ok ? 'is-emerald' : 'is-amber'}`);
        statusBox.innerHTML = `<i data-lucide="${v.ok ? 'check-circle-2' : 'alert-triangle'}"></i><div class="domain-callout-body"><strong>${v.ok ? '规则图校验通过' : '尚有待补全连线'}</strong><span>${escapeHTML(v.message)}</span></div>`;
        frag.append(statusBox);

        if (this.boundDomains.length) {
          const domField = el('div', 'field');
          domField.append(el('span', 'field-label', `已绑定域名（${this.boundDomains.length}）`));
          const wrap = el('div', 'cell-meta-row');
          this.boundDomains.forEach((bd) => wrap.append(el('span', 'meta-tag accent', bd.domain)));
          domField.append(wrap);
          frag.append(domField);
        }

        frag.append(el('p', 'field-hint', '点击画布上的任意节点即可编辑匹配条件、状态码或断开连线。'));
        panel.replaceChildren(frag);
        refreshIcons();
        return;
      }

      const meta = wafNodeMeta[node.type] || { label: node.type };
      if (!node.config) node.config = {};
      const frag = document.createDocumentFragment();
      const head = el('div', 'waf-inspector-head');
      const kindBadge = node.type === 'start' ? '请求入口' : (meta.isMatch ? '条件判断' : '终结动作');
      head.append(el('strong', '', meta.label), el('span', 'badge', kindBadge));
      frag.append(head);

      // Editable node title
      const labelField = el('div', 'field');
      labelField.append(el('label', 'field-label', '节点名称'));
      const labelInput = document.createElement('input');
      labelInput.type = 'text'; labelInput.maxLength = 48;
      labelInput.value = node.label || meta.label;
      labelInput.addEventListener('input', (ev) => {
        node.label = ev.currentTarget.value;
        const cardTitle = document.querySelector(`.waf-node[data-node-id="${CSS.escape(node.id)}"] .waf-node-title`);
        if (cardTitle) cardTitle.textContent = node.label || meta.label;
        this.renderStatusBar();
      });
      labelField.append(labelInput);
      frag.append(labelField);

      const syncNodeBody = () => {
        this.clearTrace();
        const b = document.querySelector(`.waf-node[data-node-id="${CSS.escape(node.id)}"] .waf-node-body`);
        if (b) b.textContent = this.nodeSummaryText(node);
        this.renderStatusBar();
      };

      if (node.type === 'host_match') {
        const f = el('div', 'field');
        f.append(el('label', 'field-label', '目标域名 / 后缀列表（每行一条）'));
        const ta = document.createElement('textarea');
        ta.rows = 5;
        ta.placeholder = 'emby.example.com\n*.media.org\ncdn.example.net';
        ta.value = (node.config.hosts || []).join('\n');
        ta.addEventListener('input', (ev) => {
          node.config.hosts = ev.currentTarget.value.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
          syncNodeBody();
        });
        f.append(ta, el('span', 'field-hint', '适配通用反代路径格式（如 /https/目标域名/...），匹配该域名自身及所有子域名；命中走「命中」分支。'));
        frag.append(f);
      } else if (node.type === 'ip_match') {
        const f = el('div', 'field');
        f.append(el('label', 'field-label', 'IP 或 CIDR 列表（每行一条）'));
        const ta = document.createElement('textarea');
        ta.rows = 5;
        ta.placeholder = '1.2.3.4\n203.0.113.0/24\n2001:db8::/32';
        ta.value = (node.config.ips || []).join('\n');
        ta.addEventListener('input', (ev) => {
          node.config.ips = ev.currentTarget.value.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
          syncNodeBody();
        });
        f.append(ta, el('span', 'field-hint', '客户端 IP 落在列表内时走「命中」分支，否则走「未命中」分支。'));
        frag.append(f);
      } else if (node.type === 'geo_match') {
        const chipField = el('div', 'field');
        chipField.append(el('span', 'field-label', '快捷勾选国家 / 地区'));
        const chips = el('div', 'chip-grid');
        const quickCodes = [['CN', '中国大陆'], ['HK', '香港'], ['TW', '台湾'], ['MO', '澳门'], ['SG', '新加坡'], ['JP', '日本'], ['KR', '韩国'], ['US', '美国'], ['GB', '英国'], ['DE', '德国']];
        const codeInput = document.createElement('input');
        codeInput.type = 'text';
        codeInput.placeholder = 'CN, HK, TW, SG, JP';
        codeInput.value = (node.config.countries || []).join(', ');
        const syncChips = () => {
          const active = new Set(node.config.countries || []);
          chips.querySelectorAll('.chip-toggle').forEach((b) => b.classList.toggle('active', active.has(b.dataset.code)));
        };
        quickCodes.forEach(([code, cn]) => {
          const btn = el('button', 'chip-toggle', `${code} ${cn}`);
          btn.type = 'button'; btn.dataset.code = code;
          btn.addEventListener('click', () => {
            const cur = new Set(node.config.countries || []);
            if (cur.has(code)) cur.delete(code); else cur.add(code);
            node.config.countries = Array.from(cur);
            codeInput.value = node.config.countries.join(', ');
            syncChips();
            syncNodeBody();
          });
          chips.append(btn);
        });
        syncChips();
        chipField.append(chips);
        frag.append(chipField);

        const isoField = el('div', 'field');
        isoField.append(el('label', 'field-label', 'ISO 两位国家代码'));
        codeInput.addEventListener('input', (ev) => {
          node.config.countries = parseCountryCodesInput(ev.currentTarget.value);
          syncChips();
          syncNodeBody();
        });
        isoField.append(codeInput);
        frag.append(isoField);

        const swWrap = el('div', 'toggle-list');
        const swRow = el('div', 'toggle-row');
        const swCopy = el('div', 'toggle-row-copy');
        swCopy.append(el('strong', '', '未知地区视为命中'), el('small', '', '未查到 GeoIP 或内网 IP 时归入「命中」分支'));
        const swLbl = el('label', 'switch');
        const swInp = document.createElement('input');
        swInp.type = 'checkbox'; swInp.checked = Boolean(node.config.match_unknown_geo);
        swInp.addEventListener('change', (ev) => { node.config.match_unknown_geo = ev.currentTarget.checked; syncNodeBody(); });
        swLbl.append(swInp, el('span', 'switch-track'));
        swRow.append(swCopy, swLbl);
        swWrap.append(swRow);
        frag.append(swWrap);
      } else if (node.type === 'path_match') {
        const modeField = el('div', 'field');
        modeField.append(el('label', 'field-label', '匹配方式'));
        const sel = document.createElement('select');
        [['contains', '包含子串（不区分大小写）'], ['prefix', '路径前缀匹配'], ['regex', '正则表达式 (RE2)']].forEach(([v, t]) => {
          const o = document.createElement('option'); o.value = v; o.textContent = t; sel.append(o);
        });
        sel.value = node.config.match_mode || 'contains';
        sel.addEventListener('change', (ev) => { node.config.match_mode = ev.currentTarget.value; syncNodeBody(); });
        modeField.append(sel);
        frag.append(modeField);

        const patField = el('div', 'field');
        patField.append(el('label', 'field-label', '路径 / 攻击特征（每行一条）'));
        const ta = document.createElement('textarea');
        ta.rows = 5;
        ta.placeholder = '/.env\n/.git\nwp-admin\n../';
        ta.value = (node.config.patterns || []).join('\n');
        ta.addEventListener('input', (ev) => {
          node.config.patterns = ev.currentTarget.value.split(/[\r\n]+/).map((s) => s.trim()).filter(Boolean);
          syncNodeBody();
        });
        const presetBar = el('div', 'chip-grid');
        const presets = [
          ['防敏感扫描', ['/.env', '/.git', 'wp-admin', 'wp-login', '/phpmyadmin']],
          ['防路径穿越 / XSS', ['../', '..\\', '<script', 'union select']]
        ];
        presets.forEach(([title, list]) => {
          const b = el('button', 'chip-toggle', `+ ${title}`);
          b.type = 'button';
          b.addEventListener('click', () => {
            const merged = [...new Set([...(node.config.patterns || []), ...list])];
            node.config.patterns = merged;
            ta.value = merged.join('\n');
            syncNodeBody();
          });
          presetBar.append(b);
        });
        patField.append(presetBar, ta);
        frag.append(patField);
      } else if (node.type === 'player_match') {
        if (!this.detectedPlayersLoaded && !this.detectedPlayersLoading) {
          this.loadDetectedPlayers(false);
        }
        const ta = document.createElement('textarea');
        ta.rows = 5;
        ta.placeholder = 'SenPlayer\nInfuse\nHills\nRodelPlayer\nEmby';
        ta.value = (node.config.patterns || []).join('\n');

        const chipButtons = [];
        const hasPatternCI = (name) => {
          const target = String(name || '').trim().toLowerCase();
          if (!target) return false;
          return (node.config.patterns || []).some((p) => String(p || '').trim().toLowerCase() === target);
        };
        const syncPlayerChips = () => {
          chipButtons.forEach(({ btn, name }) => {
            btn.classList.toggle('active', hasPatternCI(name));
          });
        };
        const togglePlayerPattern = (name) => {
          const clean = String(name || '').trim();
          if (!clean) return;
          const lower = clean.toLowerCase();
          const cur = Array.isArray(node.config.patterns) ? [...node.config.patterns] : [];
          const idx = cur.findIndex((p) => String(p || '').trim().toLowerCase() === lower);
          if (idx >= 0) cur.splice(idx, 1);
          else cur.push(clean);
          node.config.patterns = cur;
          ta.value = cur.join('\n');
          syncPlayerChips();
          syncNodeBody();
        };
        const formatCompactCount = (n) => {
          const num = Number(n) || 0;
          if (num >= 10000) return `${(num / 1000).toFixed(1)}k`;
          if (num >= 1000) return `${(num / 1000).toFixed(1)}k`;
          return String(num);
        };

        // Live detected players from panel telemetry & active connections
        const detSec = el('div', 'waf-player-section');
        const detHead = el('div', 'waf-player-head');
        detHead.append(el('span', 'field-label', `面板已记录的播放器${this.detectedPlayers.length ? `（${this.detectedPlayers.length}）` : ''}`));
        const detActs = el('div', 'waf-player-head-actions');
        if (this.detectedPlayers.length > 0) {
          const addAllBtn = el('button', 'waf-player-mini-btn', '全选');
          addAllBtn.type = 'button';
          addAllBtn.title = '将全部已探测到的播放器加入列表';
          addAllBtn.addEventListener('click', () => {
            const cur = Array.isArray(node.config.patterns) ? [...node.config.patterns] : [];
            const seen = new Set(cur.map((p) => String(p || '').trim().toLowerCase()));
            this.detectedPlayers.forEach((p) => {
              const nm = String(p.name || '').trim();
              if (nm && !seen.has(nm.toLowerCase())) {
                seen.add(nm.toLowerCase());
                cur.push(nm);
              }
            });
            node.config.patterns = cur;
            ta.value = cur.join('\n');
            syncPlayerChips();
            syncNodeBody();
          });
          detActs.append(addAllBtn);
        }
        const refreshBtn = el('button', 'waf-player-mini-btn');
        refreshBtn.type = 'button';
        refreshBtn.disabled = this.detectedPlayersLoading;
        refreshBtn.innerHTML = `<i data-lucide="refresh-cw"></i><span>${this.detectedPlayersLoading ? '探测中…' : '刷新探测'}</span>`;
        refreshBtn.addEventListener('click', () => this.loadDetectedPlayers(true));
        detActs.append(refreshBtn);
        detHead.append(detActs);
        detSec.append(detHead);

        const detectedNamesLower = new Set();
        if (this.detectedPlayers.length > 0) {
          const detChips = el('div', 'waf-player-chips');
          this.detectedPlayers.forEach((p) => {
            const name = String(p.name || '').trim();
            if (!name) return;
            detectedNamesLower.add(name.toLowerCase());
            const btn = el('button', 'waf-player-chip');
            btn.type = 'button';
            btn.title = p.active
              ? `${name} · 当前在线播放中 · 近30天 ${formatNumber(p.requests || 0)} 次请求`
              : `${name} · 近30天 ${formatNumber(p.requests || 0)} 次请求 · 最近活跃 ${relativeTime(p.last_seen)}`;
            if (p.active) btn.append(el('span', 'waf-player-live-dot'));
            btn.append(el('span', '', name));
            if (Number(p.requests) > 0) {
              btn.append(el('span', 'waf-player-count', formatCompactCount(p.requests)));
            }
            btn.addEventListener('click', () => togglePlayerPattern(name));
            chipButtons.push({ btn, name });
            detChips.append(btn);
          });
          detSec.append(detChips);
        } else {
          detSec.append(el('div', 'waf-player-empty', this.detectedPlayersLoading
            ? '正在实时扫描面板请求与播放记录中的播放器…'
            : '暂未探测到历史播放器记录，有客户端通过网关播放后将自动出现在这里。'));
        }
        frag.append(detSec);

        // Common Emby / Jellyfin presets (excluding ones already listed above)
        const extraPresets = (this.playerPresets || []).filter((nm) => !detectedNamesLower.has(String(nm || '').toLowerCase()));
        if (extraPresets.length > 0) {
          const preSec = el('div', 'waf-player-section');
          preSec.append(el('span', 'field-label', '常用播放器快捷勾选'));
          const preChips = el('div', 'waf-player-chips');
          extraPresets.forEach((name) => {
            const btn = el('button', 'waf-player-chip', name);
            btn.type = 'button';
            btn.addEventListener('click', () => togglePlayerPattern(name));
            chipButtons.push({ btn, name });
            preChips.append(btn);
          });
          preSec.append(preChips);
          frag.append(preSec);
        }

        const f = el('div', 'field');
        f.append(el('label', 'field-label', '播放器 / User-Agent 关键词（每行一条）'));
        ta.addEventListener('input', (ev) => {
          node.config.patterns = ev.currentTarget.value.split(/[\r\n,;]+/).map((s) => s.trim()).filter(Boolean);
          syncPlayerChips();
          syncNodeBody();
        });
        syncPlayerChips();
        f.append(ta, el('span', 'field-hint', '不区分大小写，同时匹配 Emby 客户端名称与 User-Agent；仅作用于反代与播放请求，不会拦截浏览器打开线路首页。'));
        frag.append(f);
      } else if (node.type === 'schedule_match') {
        const grid = el('div', 'form-grid-2');
        const f1 = el('div', 'field');
        f1.append(el('label', 'field-label', '开始时间'));
        const t1 = document.createElement('input');
        t1.type = 'time'; t1.value = node.config.schedule_start || '09:00';
        t1.addEventListener('input', (ev) => { node.config.schedule_start = ev.currentTarget.value; syncNodeBody(); });
        f1.append(t1);
        const f2 = el('div', 'field');
        f2.append(el('label', 'field-label', '结束时间'));
        const t2 = document.createElement('input');
        t2.type = 'time'; t2.value = node.config.schedule_end || '23:00';
        t2.addEventListener('input', (ev) => { node.config.schedule_end = ev.currentTarget.value; syncNodeBody(); });
        f2.append(t2);
        grid.append(f1, f2);
        frag.append(grid, el('span', 'field-hint', '按北京时间 (Asia/Shanghai) 判断，支持跨午夜（如 20:00 – 06:00）。时段内走「命中」，时段外走「未命中」。'));
      } else if (node.type === 'block') {
        const codeField = el('div', 'field');
        codeField.append(el('label', 'field-label', '拦截返回状态码'));
        const sel = document.createElement('select');
        [[403, '403 Forbidden（默认拒绝）'], [404, '404 Not Found（隐身伪装）'], [429, '429 Too Many Requests'], [451, '451 Unavailable For Legal Reasons']].forEach(([code, text]) => {
          const o = document.createElement('option'); o.value = String(code); o.textContent = text; sel.append(o);
        });
        sel.value = String(node.config.status_code || 403);
        sel.addEventListener('change', (ev) => { node.config.status_code = Number(ev.currentTarget.value) || 403; syncNodeBody(); });
        codeField.append(sel);
        frag.append(codeField);

        const msgField = el('div', 'field');
        msgField.append(el('label', 'field-label', '自定义拦截提示'));
        const msgInput = document.createElement('input');
        msgInput.type = 'text'; msgInput.maxLength = 200;
        msgInput.value = node.config.message || 'blocked by WAF rule';
        msgInput.addEventListener('input', (ev) => { node.config.message = ev.currentTarget.value; syncNodeBody(); });
        msgField.append(msgInput);
        frag.append(msgField);
      } else {
        frag.append(el('p', 'field-hint', node.type === 'start'
          ? '每条 WAF 规则唯一的请求入口，从右侧圆点拖线连接到第一个判断或动作节点。'
          : '请求到达「放行通过」节点后结束当前规则，并继续后续规则或转发至上游源站。'));
      }

      // Connected outgoing wires
      const outEdges = this.edges.filter((e) => e.source === node.id);
      if (outEdges.length) {
        const wField = el('div', 'field');
        wField.append(el('span', 'field-label', '当前连线'));
        outEdges.forEach((e) => {
          const dst = this.nodes.find((n) => n.id === e.target);
          const pName = e.source_port === 'true' ? '命中' : e.source_port === 'false' ? '未命中' : '流出';
          const row = el('div', 'waf-wire-item');
          row.append(el('span', '', `${pName} → ${dst ? dst.label : e.target}`));
          const rm = el('button', 'btn btn-ghost btn-sm', '断开');
          rm.type = 'button';
          rm.addEventListener('click', () => this.removeEdge(e.id));
          row.append(rm);
          wField.append(row);
        });
        frag.append(wField);
      }

      if (node.type !== 'start') {
        const delBtn = el('button', 'btn btn-danger-soft btn-sm btn-block');
        delBtn.type = 'button';
        delBtn.innerHTML = '<i data-lucide="trash-2"></i><span>删除此节点</span>';
        delBtn.addEventListener('click', () => this.removeNode(node.id));
        frag.append(delBtn);
      }

      panel.replaceChildren(frag);
      enhanceAllCustomSelects(panel);
      refreshIcons();
    },

    bindCanvasEvents() {
      if (this.eventsBound) return;
      this.eventsBound = true;
      const wrap = document.getElementById('waf-canvas-wrap');
      if (!wrap) return;

      wrap.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0) return;
        if (ev.target.closest('.waf-node') || ev.target.closest('.waf-edge-badge') || ev.target.closest('.waf-edge-hit') || ev.target.closest('.waf-sim-bar') || ev.target.closest('.waf-canvas-zoom') || ev.target.closest('.waf-canvas-status')) return;
        this.selectedNodeID = null;
        this.selectedEdgeID = null;
        this.drag = { mode: 'pan', startX: ev.clientX, startY: ev.clientY, origPanX: this.panX, origPanY: this.panY };
        wrap.classList.add('is-panning');
        document.querySelectorAll('.waf-node.selected').forEach((n) => n.classList.remove('selected'));
        this.renderEdgesOnly();
        this.renderInspector();
      });

      window.addEventListener('pointermove', (ev) => {
        if (!this.drag) return;
        if (this.drag.mode === 'pan') {
          this.setTransform(this.drag.origPanX + (ev.clientX - this.drag.startX), this.drag.origPanY + (ev.clientY - this.drag.startY), this.zoom);
        } else if (this.drag.mode === 'node') {
          const node = this.nodes.find((n) => n.id === this.drag.nodeID);
          if (!node) return;
          node.x = Math.max(0, Math.round(this.drag.origX + (ev.clientX - this.drag.startClientX) / this.zoom));
          node.y = Math.max(0, Math.round(this.drag.origY + (ev.clientY - this.drag.startClientY) / this.zoom));
          const card = document.querySelector(`.waf-node[data-node-id="${CSS.escape(node.id)}"]`);
          if (card) { card.style.left = `${node.x}px`; card.style.top = `${node.y}px`; }
          this.renderEdgesOnly();
        } else if (this.drag.mode === 'wire') {
          const stage = document.getElementById('waf-stage');
          if (!stage) return;
          const sr = stage.getBoundingClientRect();
          this.drag.x2 = (ev.clientX - sr.left) / this.zoom;
          this.drag.y2 = (ev.clientY - sr.top) / this.zoom;
          this.renderEdgesOnly();
        } else if (this.drag.mode === 'palette') {
          if (!this.drag.started) {
            if (Math.hypot(ev.clientX - this.drag.startX, ev.clientY - this.drag.startY) < 5) return;
            this.drag.started = true;
            this.drag.sourceEl?.classList.add('is-dragging');
            document.body.classList.add('waf-palette-dragging');
            const meta = wafNodeMeta[this.drag.type] || { label: this.drag.type, icon: 'circle', tone: 'accent' };
            const ghost = el('div', 'waf-drag-ghost');
            const gHead = el('div', 'waf-drag-ghost-head');
            const gIcon = el('span', `waf-palette-icon ${meta.tone}`);
            gIcon.innerHTML = `<i data-lucide="${meta.icon}"></i>`;
            gHead.append(gIcon, el('span', '', meta.label));
            const gFoot = el('div', 'waf-drag-ghost-foot', '移至右侧画布松开投放');
            ghost.append(gHead, gFoot);
            document.body.append(ghost);
            this.drag.ghostEl = ghost;
            refreshIcons();
          }
          const rect = wrap.getBoundingClientRect();
          const inside = ev.clientX >= rect.left && ev.clientX <= rect.right && ev.clientY >= rect.top && ev.clientY <= rect.bottom;
          this.drag.overCanvas = inside;
          wrap.classList.toggle('is-drop-ready', inside);
          if (this.drag.ghostEl) {
            this.drag.ghostEl.style.transform = `translate(${Math.round(ev.clientX - 106)}px, ${Math.round(ev.clientY - 26)}px)`;
            this.drag.ghostEl.classList.toggle('over-canvas', inside);
            const foot = this.drag.ghostEl.querySelector('.waf-drag-ghost-foot');
            if (foot) foot.textContent = inside ? '松开鼠标放置到此处' : '移至右侧画布松开投放';
          }
        }
      });

      window.addEventListener('pointerup', (ev) => {
        if (!this.drag) return;
        const d = this.drag;
        if (d.mode === 'palette') {
          const dropType = d.type;
          const shouldDrop = d.started && d.overCanvas;
          this.cancelPaletteDrag();
          if (shouldDrop) {
            const rect = wrap.getBoundingClientRect();
            const stageX = Math.round(((ev.clientX - rect.left - this.panX) / this.zoom - 109) / 10) * 10;
            const stageY = Math.round(((ev.clientY - rect.top - this.panY) / this.zoom - 36) / 10) * 10;
            this.addNode(dropType, { x: Math.max(12, stageX), y: Math.max(12, stageY) });
          }
          return;
        }
        this.drag = null;
        wrap.classList.remove('is-panning', 'is-connecting');
        document.querySelectorAll('.waf-port.port-in.drop-ready').forEach((elP) => elP.classList.remove('drop-ready'));
        if (d.mode === 'wire') {
          const hitEl = document.elementFromPoint(ev.clientX, ev.clientY);
          const targetNodeEl = hitEl?.closest('.waf-port.port-in') || hitEl?.closest('.waf-node');
          const targetID = targetNodeEl?.dataset?.nodeId;
          if (targetID && targetID !== d.sourceID) {
            this.connect(d.sourceID, d.sourcePort, targetID);
          } else {
            this.renderEdgesOnly();
          }
        }
      });

      window.addEventListener('pointercancel', () => {
        if (this.drag) this.cancelActiveDrag();
      });

      wrap.addEventListener('wheel', (ev) => {
        if (ev.target.closest('.waf-sim-bar')) return;
        ev.preventDefault();
        let dy = ev.deltaY;
        if (ev.deltaMode === 1) dy *= 32;
        else if (ev.deltaMode === 2) dy *= 240;
        dy = Math.max(-240, Math.min(240, dy));
        if (!dy) return;
        const speed = ev.ctrlKey || ev.metaKey ? 0.0085 : 0.0014;
        const factor = Math.exp(-dy * speed);
        this.zoomAt(this.zoom * factor, ev.clientX, ev.clientY);
      }, { passive: false });
    },

    async runSimulation() {
      const btn = document.getElementById('waf-sim-run-btn');
      const resBadge = document.getElementById('waf-sim-result');
      const v = this.validateGraph();
      if (!v.ok) {
        toast(v.message, 'error');
        return;
      }
      if (btn) btn.disabled = true;
      try {
        const res = await api('/_admin/api/waf-rules/simulate', jsonOptions('POST', {
          name: document.getElementById('waf-rule-name').value.trim() || '模拟测试',
          graph: { nodes: this.nodes, edges: this.edges },
          target_host: document.getElementById('waf-sim-host')?.value.trim() || '',
          client_ip: document.getElementById('waf-sim-ip').value.trim(),
          country_code: document.getElementById('waf-sim-country').value.trim().toUpperCase(),
          path: document.getElementById('waf-sim-path').value.trim() || '/',
          user_agent: document.getElementById('waf-sim-ua').value.trim(),
          client_name: document.getElementById('waf-sim-ua').value.trim()
        }));
        this.traceNodes = new Set(res.trace_nodes || []);
        this.traceEdges = new Set(res.trace_edges || []);
        this.traceBlocked = Boolean(res.blocked);
        this.render();
        if (resBadge) {
          resBadge.hidden = false;
          resBadge.className = `badge ${res.blocked ? 'badge-rose' : 'badge-emerald'}`;
          resBadge.textContent = res.blocked
            ? `拦截 HTTP ${res.status_code || 403}`
            : '放行通过';
        }
      } catch (failure) {
        toast(failure.message || '模拟测试失败', 'error');
      } finally {
        if (btn) btn.disabled = false;
      }
    },

    async save() {
      const name = (document.getElementById('waf-rule-name')?.value || '').trim();
      if (!name) {
        toast('请先填写 WAF 规则名称', 'error');
        document.getElementById('waf-rule-name')?.focus();
        return;
      }
      const v = this.validateGraph();
      if (!v.ok) {
        toast(v.message, 'error');
        return;
      }
      const btn = document.getElementById('waf-save-btn');
      btn.disabled = true;
      const payload = {
        name,
        description: this.description.trim(),
        enabled: this.enabled,
        is_global: document.getElementById('waf-rule-global').checked,
        graph: { nodes: this.nodes, edges: this.edges }
      };
      try {
        if (this.editingID) {
          await api(`/_admin/api/waf-rules/${encodeURIComponent(this.editingID)}`, jsonOptions('PUT', payload));
          toast(`WAF 规则「${name}」已保存并热下发`);
        } else {
          await api('/_admin/api/waf-rules', jsonOptions('POST', payload));
          toast(`WAF 规则「${name}」已创建并热下发`);
        }
        closeDrawer('waf-editor-drawer');
        await Promise.all([refreshWAFRules(), refreshDomains().catch(() => {})]);
      } catch (failure) {
        toast(failure.message || '保存 WAF 规则失败', 'error');
      } finally {
        btn.disabled = false;
      }
    }
  };

  function parseCountryCodesInput(raw) {
    return [...new Set(String(raw || '').toUpperCase().split(/[\s,;，；]+/).map((s) => s.trim()).filter((s) => /^[A-Z]{2}$/.test(s)))];
  }

  function renderPolicy(policy) {
    state.policy = policy;
    if (state.snapshot && state.view === 'overview') {
      renderCompactTargets(state.snapshot.targets);
      renderCompactRequests(state.snapshot.recent);
    }
    if (state.snapshot && state.view === 'targets') renderTargets(state.snapshot.targets);
    renderPulseSummary();
  }

  /* -------------------- Audit Logs -------------------- */

  function renderAudit(payload) {
    if (payload) state.auditEntries = payload.entries || [];
    const q = state.auditQuery.trim().toLowerCase();
    const list = state.auditEntries.filter((e) => {
      if (state.auditFilter === 'success' && !e.success) return false;
      if (state.auditFilter === 'failed' && e.success) return false;
      if (!q) return true;
      const label = auditActionLabels[e.action] || e.action;
      return `${e.username} ${e.client_ip} ${label} ${e.action} ${e.resource} ${e.detail}`.toLowerCase().includes(q);
    });
    document.getElementById('audit-count').textContent = `${formatNumber(list.length)} 条记录`;
    const body = document.getElementById('audit-table');
    const empty = document.getElementById('audit-empty');
    if (!list.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const f = document.createDocumentFragment();
    list.forEach((e) => {
      const row = document.createElement('tr');
      const resCell = el('td');
      resCell.append(el('span', `badge ${e.success ? 'badge-emerald' : 'badge-rose'}`, e.success ? '成功' : '失败'));
      [el('td', 'mono cell-secondary nowrap', formatTime(e.timestamp)),
        el('td', 'cell-primary nowrap', e.username || '未知'),
        el('td', 'mono nowrap', e.client_ip || '—'),
        el('td', 'nowrap', auditActionLabels[e.action] || e.action),
        el('td', 'mono cell-secondary nowrap', e.resource || '—'),
        el('td', 'cell-secondary', e.detail || '—'),
        resCell].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
  }

  async function refreshAudit() { renderAudit(await api('/_admin/api/audit?limit=200')); }

  /* -------------------- Backups & Recovery -------------------- */

  const backupKindLabels = { manual: ['手动', 'badge-accent'], auto: ['自动', 'badge-sky'], safety: ['安全快照', 'badge-amber'], import: ['外部导入', ''] };

  function renderBackups(snapshot) {
    state.backups = snapshot;
    const config = snapshot?.config || { enabled: true, hour: 3, retention: 7 };
    const files = snapshot?.files || [];
    document.getElementById('backup-enabled').checked = Boolean(config.enabled);
    document.getElementById('backup-hour').value = String(config.hour ?? 3);
    document.getElementById('backup-retention').value = String(config.retention ?? 7);
    document.getElementById('backup-next-run').textContent = snapshot?.next_run ? `下次自动备份：${formatTime(snapshot.next_run)}` : '自动备份未排程';
    document.getElementById('backup-count').textContent = `${formatNumber(files.length)} 个备份`;

    const body = document.getElementById('backups-table');
    const empty = document.getElementById('backups-empty');
    if (!files.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const f = document.createDocumentFragment();
    files.forEach((file) => {
      const row = document.createElement('tr');
      const [kindText, kindCls] = backupKindLabels[file.kind] || [file.kind, ''];
      const kindCell = el('td');
      kindCell.append(el('span', `badge ${kindCls}`, kindText));

      const actions = el('td', 'actions-col');
      const group = el('div', 'row-actions');
      const dl = el('a', 'icon-btn');
      dl.href = `/_admin/api/backups/${encodeURIComponent(file.name)}/download`;
      dl.title = '下载备份'; dl.setAttribute('aria-label', '下载备份'); dl.innerHTML = '<i data-lucide="download"></i>';
      const restore = el('button', 'icon-btn');
      restore.type = 'button'; restore.title = '从此快照恢复'; restore.setAttribute('aria-label', '从此快照恢复');
      restore.innerHTML = '<i data-lucide="history"></i>';
      restore.addEventListener('click', () => restoreBackup(file, restore));
      const del = el('button', 'icon-btn danger');
      del.type = 'button'; del.title = '删除备份'; del.setAttribute('aria-label', '删除备份');
      del.innerHTML = '<i data-lucide="trash-2"></i>';
      del.addEventListener('click', () => deleteBackup(file, del));
      group.append(dl, restore, del);
      actions.append(group);

      [el('td', 'mono cell-primary', file.name), kindCell, el('td', 'num-col mono', formatBytes(file.size)),
        el('td', 'mono cell-secondary', formatTime(file.created_at)), actions].forEach((c) => row.append(c));
      f.append(row);
    });
    body.replaceChildren(f);
    refreshIcons();
  }

  async function refreshBackups() { renderBackups(await api('/_admin/api/backups')); }

  async function restoreBackup(file, button) {
    const confirmed = await confirmAction({
      title: '恢复数据库快照',
      message: `将使用 ${file.name} 替换当前数据库。系统会在覆盖前自动创建一份安全快照。`,
      confirmLabel: '确认恢复', icon: 'history', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      renderBackups(await api(`/_admin/api/backups/${encodeURIComponent(file.name)}/restore`, jsonOptions('POST', {})));
      toast('数据库备份已恢复');
    } catch {
      button.disabled = false;
      toast('备份恢复失败', 'error');
      return;
    }
    Promise.all([refresh(false, false), refreshAudit()]).catch(() => {});
  }

  async function deleteBackup(file, button) {
    const confirmed = await confirmAction({
      title: '删除备份文件',
      message: `${file.name} 删除后将无法找回。`,
      confirmLabel: '确认删除', icon: 'trash-2', danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      renderBackups(await api(`/_admin/api/backups/${encodeURIComponent(file.name)}/delete`, { method: 'DELETE' }));
      toast('备份文件已删除');
    } catch {
      button.disabled = false;
      toast('备份删除失败', 'error');
    }
  }

  /* -------------------- Settings: Runtime, Branding, Telegram, Turnstile -------------------- */

  const RUNTIME_TOGGLES = [
    { id: 'runtime-public-proxy', field: 'allow_unsigned_targets', label: '通用开放反代模式' },
    { id: 'runtime-pass-ip', field: 'pass_client_ip', label: '透传客户端真实 IP' },
    { id: 'runtime-disable-cache', field: 'disable_cache', label: '禁用上游响应缓存' }
  ];
  let runtimeToggleBusy = false;

  function runtimeSettingsFromView(config) {
    return {
      default_upstream: String(config.default_upstream || ''),
      allowed_upstreams: String(config.allowed_upstreams || ''),
      allow_unsigned_targets: Boolean(config.allow_unsigned_targets),
      pass_client_ip: Boolean(config.pass_client_ip),
      disable_cache: Boolean(config.disable_cache),
      rewrite_max_bytes: Number(config.rewrite_max_bytes || 8388608),
      dns_cache_ttl_seconds: Number(config.dns_cache_ttl_seconds ?? 60),
      dial_timeout_seconds: Number(config.dial_timeout_seconds ?? 15),
      response_header_timeout_seconds: Number(config.response_header_timeout_seconds ?? 60),
      max_concurrent_requests: Number(config.max_concurrent_requests ?? 256),
      max_concurrent_per_ip: Number(config.max_concurrent_per_ip ?? 64),
      max_download_mbps_per_ip: Number(config.max_download_mbps_per_ip ?? 0),
      upstream_ip_mode: String(config.upstream_ip_mode || 'auto')
    };
  }

  function updateRuntimeConfigStatus(config) {
    const status = document.getElementById('runtime-config-status');
    const pending = Boolean(config.restart_pending);
    const hotReload = config.hot_reload !== false;
    status.className = `badge ${pending ? 'badge-amber' : (hotReload || config.restart_on_save) ? 'badge-emerald' : ''}`;
    status.innerHTML = pending
      ? '<i data-lucide="rotate-cw"></i>正在重启'
      : hotReload
        ? '<i data-lucide="zap"></i>热重载 · 实时生效'
        : config.restart_on_save
          ? '<i data-lucide="badge-check"></i>保存后自动重启生效'
          : '<i data-lucide="clock-3"></i>保存后需手动重启';
    const submitLabel = document.querySelector('#runtime-config-submit span');
    if (submitLabel) submitLabel.textContent = hotReload ? '保存并热应用' : '保存并应用配置';
    const footerHint = document.getElementById('runtime-footer-hint');
    if (footerHint) {
      footerHint.textContent = hotReload
        ? '所有参数支持无感热重载，保存后实时生效且不中断现有连接'
        : config.restart_on_save
          ? '配置保存后将自动重启服务以应用变更'
          : '配置保存后需手动重启服务生效';
    }
    refreshIcons();
  }

  function setRuntimeTogglesDisabled(disabled) {
    RUNTIME_TOGGLES.forEach(({ id }) => {
      const input = document.getElementById(id);
      if (input) input.disabled = disabled;
    });
  }

  function renderRuntimeConfig(config) {
    state.runtimeConfig = config;
    document.getElementById('runtime-public-url').value = config.public_base_url || '';
    document.getElementById('runtime-default-upstream').value = config.default_upstream || '';
    document.getElementById('runtime-allowed-upstreams').value = String(config.allowed_upstreams || '').split(',').map((s) => s.trim()).filter(Boolean).join('\n');
    document.getElementById('runtime-public-proxy').checked = Boolean(config.allow_unsigned_targets);
    document.getElementById('runtime-pass-ip').checked = Boolean(config.pass_client_ip);
    document.getElementById('runtime-disable-cache').checked = Boolean(config.disable_cache);
    document.getElementById('runtime-rewrite-mb').value = String(Math.max(1, Math.round(Number(config.rewrite_max_bytes || 8388608) / 1048576)));
    document.getElementById('runtime-dns-ttl').value = String(config.dns_cache_ttl_seconds ?? 60);
    document.getElementById('runtime-dial-timeout').value = String(config.dial_timeout_seconds ?? 15);
    document.getElementById('runtime-response-timeout').value = String(config.response_header_timeout_seconds ?? 60);
    document.getElementById('runtime-global-limit').value = String(config.max_concurrent_requests ?? 256);
    document.getElementById('runtime-ip-limit').value = String(config.max_concurrent_per_ip ?? 64);
    document.getElementById('runtime-ip-speed-limit').value = String(config.max_download_mbps_per_ip ?? 0);
    const ipModeSel = document.getElementById('runtime-upstream-ip-mode');
    if (ipModeSel) ipModeSel.value = config.upstream_ip_mode || 'auto';
    setRuntimeTogglesDisabled(false);
    updateRuntimeConfigStatus(config);
  }

  async function toggleRuntimeFeature(input, field, label) {
    if (!state.runtimeConfig || state.runtimeConfig.hot_reload === false) return;
    if (runtimeToggleBusy) {
      input.checked = Boolean(state.runtimeConfig[field]);
      return;
    }
    const nextValue = Boolean(input.checked);
    const row = input.closest('.toggle-row');
    const error = document.getElementById('runtime-config-error');
    if (error) error.hidden = true;
    runtimeToggleBusy = true;
    setRuntimeTogglesDisabled(true);
    if (row) row.classList.add('is-saving');
    try {
      const payload = { ...runtimeSettingsFromView(state.runtimeConfig), [field]: nextValue };
      const saved = await api('/_admin/api/runtime-config', jsonOptions('PUT', payload));
      state.runtimeConfig = saved;
      RUNTIME_TOGGLES.forEach(({ id, field: key }) => {
        const el = document.getElementById(id);
        if (el) el.checked = Boolean(saved[key]);
      });
      updateRuntimeConfigStatus(saved);
      if (row) {
        row.classList.remove('is-saving');
        row.classList.add('is-applied');
        window.setTimeout(() => row.classList.remove('is-applied'), 680);
      }
      toast(`已${saved[field] ? '开启' : '关闭'}${label} · 已热生效`);
    } catch {
      input.checked = Boolean(state.runtimeConfig[field]);
      toast(`${label}热切换失败，请稍后重试`, 'error');
    } finally {
      runtimeToggleBusy = false;
      setRuntimeTogglesDisabled(false);
      if (row) row.classList.remove('is-saving');
    }
  }

  async function refreshRuntimeConfig() { renderRuntimeConfig(await api('/_admin/api/runtime-config')); }

  function runtimeConfigPayload() {
    const allowed = document.getElementById('runtime-allowed-upstreams').value.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean).join(',');
    return {
      default_upstream: document.getElementById('runtime-default-upstream').value.trim(),
      allowed_upstreams: allowed,
      allow_unsigned_targets: document.getElementById('runtime-public-proxy').checked,
      pass_client_ip: document.getElementById('runtime-pass-ip').checked,
      disable_cache: document.getElementById('runtime-disable-cache').checked,
      rewrite_max_bytes: Number(document.getElementById('runtime-rewrite-mb').value) * 1048576,
      dns_cache_ttl_seconds: Number(document.getElementById('runtime-dns-ttl').value),
      dial_timeout_seconds: Number(document.getElementById('runtime-dial-timeout').value),
      response_header_timeout_seconds: Number(document.getElementById('runtime-response-timeout').value),
      max_concurrent_requests: Number(document.getElementById('runtime-global-limit').value),
      max_concurrent_per_ip: Number(document.getElementById('runtime-ip-limit').value),
      max_download_mbps_per_ip: Number(document.getElementById('runtime-ip-speed-limit').value),
      upstream_ip_mode: document.getElementById('runtime-upstream-ip-mode')?.value || 'auto'
    };
  }

  async function waitForRuntimeRestart() {
    await new Promise((r) => window.setTimeout(r, 2500));
    for (let i = 0; i < 40; i += 1) {
      try {
        const res = await fetch('/_admin/api/runtime-config', { credentials: 'same-origin', cache: 'no-store' });
        if (res.ok) { window.location.replace('/panel?configured=1#settings-runtime'); return; }
      } catch { /* restarting */ }
      await new Promise((r) => window.setTimeout(r, 1500));
    }
    toast('服务仍在重启，请稍后刷新页面', 'info');
  }

  function renderBranding(view) {
    state.branding = view || { custom: false, updated_at: 0 };
    const avatarURL = `/_gateway/avatar?v=${Number(state.branding.updated_at) || Date.now()}`;
    document.querySelectorAll('img[src^="/_gateway/avatar"]').forEach((img) => { img.src = avatarURL; });
    document.querySelectorAll('link[rel~="icon"][href^="/_gateway/avatar"]').forEach((link) => { link.href = avatarURL; });
    const badge = document.getElementById('branding-status');
    badge.className = `badge ${state.branding.custom ? 'badge-emerald' : ''}`;
    badge.innerHTML = `<i data-lucide="${state.branding.custom ? 'badge-check' : 'image'}"></i>${state.branding.custom ? '自定义头像' : '默认头像'}`;
    document.getElementById('branding-avatar-reset').disabled = !state.branding.custom;
    refreshIcons();
  }

  async function refreshBranding() { renderBranding(await api('/_admin/api/branding')); }

  function selectBrandingFile(input) {
    const file = input.files?.[0];
    const error = document.getElementById('branding-error');
    const status = document.getElementById('branding-file-status');
    const save = document.getElementById('branding-avatar-save');
    error.hidden = true;
    save.disabled = true;
    if (!file) { status.textContent = '尚未选择新图片'; return; }
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type) || file.size <= 0 || file.size > 512 * 1024) {
      input.value = '';
      status.textContent = '尚未选择新图片';
      error.textContent = '请选择不超过 512 KiB 的 PNG、JPEG 或 WebP 图片';
      error.hidden = false;
      return;
    }
    status.textContent = `待上传：${file.name}（${formatBytes(file.size)}）`;
    save.disabled = false;
  }

  async function saveBrandingAvatar() {
    const input = document.getElementById('branding-avatar-file');
    const file = input.files?.[0];
    if (!file) return;
    const btn = document.getElementById('branding-avatar-save');
    const error = document.getElementById('branding-error');
    const form = new FormData();
    form.append('avatar', file, file.name);
    btn.disabled = true;
    error.hidden = true;
    try {
      renderBranding(await api('/_admin/api/branding', { method: 'POST', body: form }));
      input.value = '';
      document.getElementById('branding-file-status').textContent = '头像已上传并同步至全站';
      toast('站点头像已更新');
    } catch {
      error.textContent = '头像上传失败，请确认图片格式与体积符合要求';
      error.hidden = false;
      btn.disabled = false;
    }
  }

  async function resetBrandingAvatar() {
    const confirmed = await confirmAction({
      title: '恢复默认头像',
      message: '首页、登录页和管理控制台将恢复为 Refract 默认头像。',
      confirmLabel: '恢复默认', icon: 'rotate-ccw'
    });
    if (!confirmed) return;
    const btn = document.getElementById('branding-avatar-reset');
    btn.disabled = true;
    try {
      renderBranding(await api('/_admin/api/branding', { method: 'DELETE' }));
      document.getElementById('branding-avatar-file').value = '';
      document.getElementById('branding-file-status').textContent = '已恢复默认头像';
      toast('已恢复默认头像');
    } catch {
      btn.disabled = false;
      toast('恢复默认头像失败', 'error');
    }
  }

  function renderTelegram(config) {
    state.telegram = config;
    document.getElementById('telegram-enabled').checked = Boolean(config.enabled);
    document.getElementById('telegram-chat').value = config.chat_id || '';
    document.getElementById('telegram-hour').value = String(config.send_hour ?? 9);
    document.getElementById('telegram-token').value = '';
    document.getElementById('telegram-token-status').textContent = config.token_set ? 'Bot Token 已加密保存，留空将保持原密钥不变' : '尚未配置 Bot Token';
    const alerts = config.alerts || {};
    const elOff = document.getElementById('tg-alert-offline');
    if (elOff) elOff.checked = alerts.node_offline_enabled !== false;
    const elSec = document.getElementById('tg-alert-offline-sec');
    if (elSec) elSec.value = String(alerts.offline_threshold_sec ?? 60);
    const elQuota = document.getElementById('tg-alert-quota');
    if (elQuota) elQuota.checked = alerts.node_quota_enabled !== false;
    const elTls = document.getElementById('tg-alert-tls');
    if (elTls) elTls.checked = alerts.node_tls_enabled !== false;
    const elFail = document.getElementById('tg-alert-failover');
    if (elFail) elFail.checked = alerts.dns_failover_enabled !== false;
  }

  async function saveTelegram(showNotice) {
    const error = document.getElementById('telegram-error');
    error.hidden = true;
    const form = document.getElementById('telegram-form');
    if (!form.reportValidity()) throw new Error('invalid form');
    const config = await api('/_admin/api/telegram', jsonOptions('PUT', {
      enabled: document.getElementById('telegram-enabled').checked,
      bot_token: document.getElementById('telegram-token').value.trim(),
      chat_id: document.getElementById('telegram-chat').value.trim(),
      send_hour: Number(document.getElementById('telegram-hour').value),
      alerts: {
        node_offline_enabled: Boolean(document.getElementById('tg-alert-offline')?.checked),
        offline_threshold_sec: Math.max(15, Math.min(3600, Number(document.getElementById('tg-alert-offline-sec')?.value) || 60)),
        node_quota_enabled: Boolean(document.getElementById('tg-alert-quota')?.checked),
        node_tls_enabled: Boolean(document.getElementById('tg-alert-tls')?.checked),
        dns_failover_enabled: Boolean(document.getElementById('tg-alert-failover')?.checked)
      }
    }));
    renderTelegram(config);
    if (showNotice) toast('Telegram 日报与实时告警配置已保存');
  }

  /* -------------------- Cloudflare DNS & Failover Groups -------------------- */

  function renderFailoverGroupsList() {
    const container = document.getElementById('cf-failover-list');
    const empty = document.getElementById('cf-failover-empty');
    if (!container) return;
    const groups = state.cloudflareFailoverDraft || [];
    if (empty) empty.hidden = groups.length > 0;
    const nodeNameByID = new Map(state.nodesData.map((n) => [n.id, n.name]));
    const f = document.createDocumentFragment();

    groups.forEach((group, idx) => {
      const card = el('div', 'failover-card');
      const head = el('div', 'failover-card-head');
      const statusWrap = el('div', 'cell-meta-row');
      statusWrap.append(el('strong', '', `切线组 #${idx + 1}`));
      if (group.active_node_id) {
        const activeLabel = group.active_node_name || nodeNameByID.get(group.active_node_id) || group.active_node_id;
        statusWrap.append(el('span', 'badge badge-emerald', `当前指向：${activeLabel}`));
      }
      if (group.last_error) {
        statusWrap.append(el('span', 'badge badge-rose', group.last_error));
      } else if (group.last_switched_at) {
        statusWrap.append(el('span', 'field-hint', `上次切换 ${relativeTime(group.last_switched_at)}`));
      }
      const removeGroupBtn = el('button', 'icon-btn danger');
      removeGroupBtn.type = 'button';
      removeGroupBtn.title = '删除此切线组';
      removeGroupBtn.setAttribute('aria-label', '删除此切线组');
      removeGroupBtn.innerHTML = '<i data-lucide="trash-2"></i>';
      removeGroupBtn.addEventListener('click', () => {
        state.cloudflareFailoverDraft.splice(idx, 1);
        renderFailoverGroupsList();
      });
      head.append(statusWrap, removeGroupBtn);

      const grid = el('div', 'form-grid-3');
      const nameField = el('div', 'field');
      nameField.append(el('label', 'field-label', '切线组名称'));
      const nameInput = document.createElement('input');
      nameInput.type = 'text'; nameInput.maxLength = 64; nameInput.placeholder = '例如：主播放入口';
      nameInput.value = group.name || '';
      nameInput.addEventListener('input', (ev) => { group.name = ev.currentTarget.value; });
      nameField.append(nameInput);

      const hostField = el('div', 'field');
      hostField.append(el('label', 'field-label', '统一入口域名'));
      const hostInput = document.createElement('input');
      hostInput.type = 'text'; hostInput.maxLength = 253; hostInput.placeholder = '例如：play.example.com';
      hostInput.value = group.hostname || '';
      hostInput.addEventListener('input', (ev) => { group.hostname = ev.currentTarget.value; });
      hostField.append(hostInput);

      const modeField = el('div', 'field');
      modeField.append(el('label', 'field-label', '解析地址族'));
      const modeSel = document.createElement('select');
      [['auto', '自动 (A+AAAA)'], ['ipv4', '仅 IPv4 (A)'], ['ipv6', '仅 IPv6 (AAAA)'], ['dual', '强制双栈']].forEach(([val, txt]) => {
        const opt = document.createElement('option');
        opt.value = val; opt.textContent = txt;
        modeSel.append(opt);
      });
      modeSel.value = group.ip_mode || 'auto';
      modeSel.addEventListener('change', (ev) => { group.ip_mode = ev.currentTarget.value; });
      modeField.append(modeSel);
      grid.append(nameField, hostField, modeField);

      const priorityWrap = el('div', 'field');
      priorityWrap.append(el('span', 'field-label', '故障切换优先级（从左到右依次优选）'));
      const chipRow = el('div', 'failover-node-row');
      const nodeIDs = Array.isArray(group.node_ids) ? group.node_ids : [];
      if (!nodeIDs.length) {
        chipRow.append(el('span', 'field-hint', '请从下方添加至少 1 个边缘节点'));
      } else {
        nodeIDs.forEach((nid, nIdx) => {
          const chip = el('span', `failover-node-chip${group.active_node_id === nid ? ' is-active' : ''}`);
          chip.append(el('span', '', `${nIdx + 1}. ${nodeNameByID.get(nid) || nid}`));
          if (nIdx > 0) {
            const leftBtn = el('button', 'failover-chip-btn', '←');
            leftBtn.type = 'button'; leftBtn.title = '提高优先级';
            leftBtn.addEventListener('click', () => {
              [group.node_ids[nIdx - 1], group.node_ids[nIdx]] = [group.node_ids[nIdx], group.node_ids[nIdx - 1]];
              renderFailoverGroupsList();
            });
            chip.append(leftBtn);
          }
          if (nIdx < nodeIDs.length - 1) {
            const rightBtn = el('button', 'failover-chip-btn', '→');
            rightBtn.type = 'button'; rightBtn.title = '降低优先级';
            rightBtn.addEventListener('click', () => {
              [group.node_ids[nIdx + 1], group.node_ids[nIdx]] = [group.node_ids[nIdx], group.node_ids[nIdx + 1]];
              renderFailoverGroupsList();
            });
            chip.append(rightBtn);
          }
          const delNodeBtn = el('button', 'failover-chip-btn', '×');
          delNodeBtn.type = 'button'; delNodeBtn.title = '移出切线组';
          delNodeBtn.addEventListener('click', () => {
            group.node_ids.splice(nIdx, 1);
            renderFailoverGroupsList();
          });
          chip.append(delNodeBtn);
          chipRow.append(chip);
        });
      }

      const addBar = el('div', 'failover-add-node-bar');
      const nodeSelect = document.createElement('select');
      const available = state.nodesData.filter((n) => !nodeIDs.includes(n.id));
      if (!available.length) {
        const opt = document.createElement('option');
        opt.value = ''; opt.textContent = state.nodesData.length ? '所有节点已加入' : '暂无可用边缘节点';
        nodeSelect.append(opt);
        nodeSelect.disabled = true;
      } else {
        available.forEach((n) => {
          const opt = document.createElement('option');
          opt.value = n.id;
          const meta = n.effective_ipv4 || n.effective_ipv6 || n.region || n.public_url;
          opt.textContent = meta ? `${n.name} (${meta})` : n.name;
          nodeSelect.append(opt);
        });
      }
      const addBtn = el('button', 'btn btn-secondary btn-sm');
      addBtn.type = 'button';
      addBtn.disabled = !available.length;
      addBtn.innerHTML = '<i data-lucide="plus"></i><span>加入优先级队列</span>';
      addBtn.addEventListener('click', () => {
        if (!nodeSelect.value) return;
        group.node_ids = [...nodeIDs, nodeSelect.value];
        renderFailoverGroupsList();
      });
      addBar.append(nodeSelect, addBtn);
      priorityWrap.append(chipRow, addBar);

      card.append(head, grid, priorityWrap);
      f.append(card);
    });
    container.replaceChildren(f);
    enhanceAllCustomSelects(container);
    refreshIcons();
  }

  function renderCloudflareDNS(settings) {
    state.cloudflareDNS = settings || { enabled: false, token_set: false, zone_id: '', root_domain: '', proxied: false, ttl: 60, failover_groups: [] };
    state.cloudflareFailoverDraft = (state.cloudflareDNS.failover_groups || []).map((g) => ({
      ...g,
      node_ids: Array.isArray(g.node_ids) ? [...g.node_ids] : []
    }));
    document.getElementById('cf-dns-enabled').checked = Boolean(state.cloudflareDNS.enabled);
    document.getElementById('cf-dns-token').value = '';
    document.getElementById('cf-dns-token-status').textContent = state.cloudflareDNS.token_set
      ? 'Cloudflare API Token 已加密保存，留空将保持原 Token 不变'
      : '尚未配置 API Token，保存时使用 AES-256-GCM 加密存储';
    document.getElementById('cf-dns-root-domain').value = state.cloudflareDNS.root_domain || '';
    document.getElementById('cf-dns-zone-id').value = state.cloudflareDNS.zone_id || '';
    document.getElementById('cf-dns-ttl').value = String(state.cloudflareDNS.ttl || 60);
    document.getElementById('cf-dns-proxied').checked = Boolean(state.cloudflareDNS.proxied);

    const statusBadge = document.getElementById('cf-dns-status');
    if (statusBadge) {
      statusBadge.className = `badge ${state.cloudflareDNS.enabled ? (state.cloudflareDNS.last_error ? 'badge-amber' : 'badge-emerald') : ''}`;
      statusBadge.innerHTML = `<i data-lucide="${state.cloudflareDNS.enabled ? 'cloud' : 'cloud-off'}"></i>${state.cloudflareDNS.enabled ? (state.cloudflareDNS.last_error ? '同步异常' : '联动已启用') : '未启用'}`;
    }
    const syncMeta = document.getElementById('cf-dns-sync-meta');
    if (syncMeta) {
      if (state.cloudflareDNS.last_error) {
        syncMeta.textContent = `最近异常：${state.cloudflareDNS.last_error}`;
      } else if (state.cloudflareDNS.last_sync_at) {
        syncMeta.textContent = `最近成功同步：${formatTime(state.cloudflareDNS.last_sync_at)}`;
      } else {
        syncMeta.textContent = '尚未执行过 DNS 同步';
      }
    }
    renderFailoverGroupsList();
    refreshIcons();
  }

  async function refreshCloudflareDNS() {
    if (!state.nodesData.length) {
      await refreshNodes().catch(() => {});
    }
    renderCloudflareDNS(await api('/_admin/api/cloudflare-dns'));
  }

  async function saveCloudflareDNS(e) {
    if (e) e.preventDefault();
    const errEl = document.getElementById('cf-dns-error');
    const submit = document.getElementById('cf-dns-submit');
    errEl.hidden = true;
    const payload = {
      enabled: document.getElementById('cf-dns-enabled').checked,
      api_token: document.getElementById('cf-dns-token').value.trim(),
      root_domain: document.getElementById('cf-dns-root-domain').value.trim(),
      zone_id: document.getElementById('cf-dns-zone-id').value.trim(),
      ttl: Number(document.getElementById('cf-dns-ttl').value) || 60,
      proxied: document.getElementById('cf-dns-proxied').checked,
      failover_groups: (state.cloudflareFailoverDraft || []).map((g) => ({
        id: g.id || '',
        name: String(g.name || '').trim(),
        hostname: String(g.hostname || '').trim(),
        node_ids: Array.isArray(g.node_ids) ? g.node_ids : [],
        ip_mode: g.ip_mode || 'auto'
      }))
    };
    submit.disabled = true;
    try {
      const saved = await api('/_admin/api/cloudflare-dns', jsonOptions('PUT', payload));
      renderCloudflareDNS(saved);
      await Promise.all([refreshSmartDNSProfiles().catch(() => {}), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast('Cloudflare DNS 配置已保存');
    } catch (failure) {
      errEl.textContent = failure.message || 'Cloudflare DNS 配置无效，请检查字段';
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  async function testCloudflareDNS(button) {
    const errEl = document.getElementById('cf-dns-error');
    errEl.hidden = true;
    button.disabled = true;
    try {
      const res = await api('/_admin/api/cloudflare-dns/test', jsonOptions('POST', {
        api_token: document.getElementById('cf-dns-token').value.trim(),
        root_domain: document.getElementById('cf-dns-root-domain').value.trim(),
        zone_id: document.getElementById('cf-dns-zone-id').value.trim()
      }));
      if (res.zone_id) document.getElementById('cf-dns-zone-id').value = res.zone_id;
      if (res.root_domain && !document.getElementById('cf-dns-root-domain').value.trim()) {
        document.getElementById('cf-dns-root-domain').value = res.root_domain;
      }
      toast(`Cloudflare 连通正常：${res.root_domain} (${res.zone_id})`);
    } catch (failure) {
      errEl.textContent = failure.message || 'Cloudflare API 连通测试失败';
      errEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  }

  async function syncCloudflareDNSNow(button) {
    const errEl = document.getElementById('cf-dns-error');
    errEl.hidden = true;
    button.disabled = true;
    try {
      const res = await api('/_admin/api/cloudflare-dns/sync', jsonOptions('POST', {}));
      if (res.settings) renderCloudflareDNS(res.settings);
      await Promise.all([refreshSmartDNSProfiles().catch(() => {}), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast(`DNS 同步完成：已同步 ${res.synced_nodes || 0} 个节点、${res.synced_groups || 0} 个切线组`);
    } catch (failure) {
      errEl.textContent = failure.message || 'DNS 同步失败';
      errEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  }

  function renderAxisNowDNS(settings, { preserveInputs = false } = {}) {
    state.axisnowDNS = settings || { enabled: false, token_set: false, api_base: 'https://api.axisnow.io/client/v1', cached_providers: [] };
    const s = state.axisnowDNS;
    const enEl = document.getElementById('axisnow-dns-enabled');
    if (enEl && !preserveInputs) enEl.checked = Boolean(s.enabled);
    const tokEl = document.getElementById('axisnow-dns-token');
    if (tokEl && !preserveInputs) tokEl.value = '';
    const tokSt = document.getElementById('axisnow-dns-token-status');
    if (tokSt) {
      tokSt.textContent = s.token_set
        ? 'AxisNow API Token 已加密保存，留空将保持原 Token 不变'
        : '尚未配置 API Token，保存时使用 AES-256-GCM 加密存储';
    }
    const baseEl = document.getElementById('axisnow-api-base');
    if (baseEl && !preserveInputs) baseEl.value = s.api_base || 'https://api.axisnow.io/client/v1';

    const statusBadge = document.getElementById('axisnow-dns-status');
    if (statusBadge) {
      statusBadge.className = `badge ${s.enabled ? (s.last_error ? 'badge-amber' : 'badge-emerald') : ''}`;
      statusBadge.innerHTML = `<i data-lucide="waypoints"></i>${s.enabled ? (s.last_error ? '同步异常' : '智能 DNS 已启用') : '未启用'}`;
    }
    const tokenMeta = document.getElementById('axisnow-token-meta');
    if (tokenMeta) {
      tokenMeta.textContent = s.token_name
        ? `令牌：${s.token_name}${s.tenant_uuid ? ` · 租户 ${s.tenant_uuid.slice(0, 8)}…` : ''}`
        : (s.token_set ? '已保存 Token，点击「测试连通」刷新调度域列表' : '尚未验证连通');
    }
    const syncMeta = document.getElementById('axisnow-dns-sync-meta');
    if (syncMeta) {
      if (s.last_error) syncMeta.textContent = `最近异常：${s.last_error}`;
      else if (s.last_sync_at) syncMeta.textContent = `最近成功同步：${formatTime(s.last_sync_at)}`;
      else syncMeta.textContent = '尚未执行过智能 DNS 同步';
    }

    const choices = buildAxisNowProviderChoices(s.cached_providers);
    const sel = document.getElementById('axisnow-provider-select');
    if (sel) {
      const frag = document.createDocumentFragment();
      if (!choices.length) {
        const emptyOpt = document.createElement('option');
        emptyOpt.value = '';
        emptyOpt.textContent = '尚未拉取，请填写 Token 并点击下方「测试连通并拉取调度域」';
        frag.append(emptyOpt);
      } else {
        choices.forEach((c) => {
          const opt = document.createElement('option');
          opt.value = c.key;
          opt.textContent = c.label;
          frag.append(opt);
        });
      }
      sel.replaceChildren(frag);
      const curKey = s.default_provider_uuid ? `${s.default_provider_uuid}|${s.default_zone_uuid || ''}` : '';
      if (choices.some((c) => c.key === curKey)) sel.value = curKey;
      else if (choices.length) sel.value = choices[0].key;
    }

    const preview = document.getElementById('axisnow-providers-preview');
    if (preview) {
      if (!choices.length) {
        preview.replaceChildren(el('span', 'field-hint', '暂无已发现的托管调度域或自有 DNS 提供商。'));
      } else {
        const pFrag = document.createDocumentFragment();
        choices.forEach((c) => {
          const pill = el('div', 'smart-provider-pill');
          pill.append(
            el('span', `badge ${c.provider_source === 'platform' ? 'badge-emerald' : 'badge-sky'}`, c.provider_source === 'platform' ? '免费托管' : '自有 DNS'),
            el('strong', '', formatAxisNowProviderType(c.provider_type)),
            el('small', '', c.zone_name || c.provider_uuid.slice(0, 8))
          );
          pFrag.append(pill);
        });
        preview.replaceChildren(pFrag);
      }
    }
    const metaSt = document.getElementById('axisnow-meta-status');
    if (metaSt && state.axisnowMeta) {
      const cnt = (state.axisnowMeta.providers || []).length;
      metaSt.textContent = state.axisnowMeta.source === 'live'
        ? `已实时拉取 ${cnt} 类 DNS 提供商线路字典（同步于 ${formatTime(state.axisnowMeta.fetched_at)}）`
        : `当前使用内置常用线路字典（${cnt} 类，连通 AxisNow 后将自动同步全量最新线路）`;
    }
    refreshIcons();
  }

  async function refreshAxisNowDNS() {
    const [settings] = await Promise.all([
      api('/_admin/api/axisnow-dns'),
      ensureAxisNowMetadata(false)
    ]);
    renderAxisNowDNS(settings);
  }

  async function saveAxisNowDNS(e) {
    if (e) e.preventDefault();
    const errEl = document.getElementById('axisnow-dns-error');
    const submit = document.getElementById('axisnow-dns-submit');
    errEl.hidden = true;
    const choices = buildAxisNowProviderChoices(state.axisnowDNS?.cached_providers);
    const pickedKey = document.getElementById('axisnow-provider-select')?.value || '';
    const picked = choices.find((c) => c.key === pickedKey);
    const payload = {
      enabled: Boolean(document.getElementById('axisnow-dns-enabled')?.checked),
      token: (document.getElementById('axisnow-dns-token')?.value || '').trim(),
      api_base: (document.getElementById('axisnow-api-base')?.value || '').trim(),
      default_provider_uuid: picked?.provider_uuid || state.axisnowDNS?.default_provider_uuid || '',
      default_provider_source: picked?.provider_source || state.axisnowDNS?.default_provider_source || 'platform',
      default_provider_type: picked?.provider_type || state.axisnowDNS?.default_provider_type || '',
      default_zone_uuid: picked?.zone_uuid || state.axisnowDNS?.default_zone_uuid || '',
      default_zone_name: picked?.zone_name || state.axisnowDNS?.default_zone_name || '',
      default_zone_plan: picked?.zone_plan || state.axisnowDNS?.default_zone_plan || '',
      token_name: state.axisnowDNS?.token_name || '',
      tenant_uuid: state.axisnowDNS?.tenant_uuid || '',
      cached_providers: state.axisnowDNS?.cached_providers || []
    };
    submit.disabled = true;
    try {
      const saved = await api('/_admin/api/axisnow-dns', jsonOptions('PUT', payload));
      renderAxisNowDNS(saved);
      await Promise.all([refreshSmartDNSProfiles().catch(() => {}), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast('AxisNow 智能 DNS 配置已保存');
    } catch (failure) {
      errEl.textContent = failure.message || 'AxisNow 智能 DNS 保存失败';
      errEl.hidden = false;
    } finally {
      submit.disabled = false;
    }
  }

  async function testAxisNowDNS(button) {
    const errEl = document.getElementById('axisnow-dns-error');
    errEl.hidden = true;
    button.disabled = true;
    try {
      const res = await api('/_admin/api/axisnow-dns/test', jsonOptions('POST', {
        token: (document.getElementById('axisnow-dns-token')?.value || '').trim(),
        api_base: (document.getElementById('axisnow-api-base')?.value || '').trim()
      }));
      state.axisnowDNS = {
        ...(state.axisnowDNS || {}),
        token_name: res.token_name || '',
        tenant_uuid: res.tenant_uuid || '',
        cached_providers: Array.isArray(res.providers) ? res.providers : []
      };
      renderAxisNowDNS(state.axisnowDNS, { preserveInputs: true });
      await ensureAxisNowMetadata(true);
      renderAxisNowDNS(state.axisnowDNS, { preserveInputs: true });
      const choices = buildAxisNowProviderChoices(res.providers);
      toast(`AxisNow 连通成功（令牌：${res.token_name || 'OK'}），已拉取 ${choices.length} 个可用调度域`);
    } catch (failure) {
      errEl.textContent = failure.message || 'AxisNow API 连通测试失败，请检查令牌权限或网络';
      errEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  }

  async function syncAxisNowDNSNow(button) {
    const errEl = document.getElementById('axisnow-dns-error');
    errEl.hidden = true;
    button.disabled = true;
    try {
      const res = await api('/_admin/api/axisnow-dns/sync', jsonOptions('POST', {}));
      await Promise.all([refreshAxisNowDNS(), refreshSmartDNSProfiles().catch(() => {}), refreshDomains().catch(() => {})]);
      if (state.view === 'dns') renderDNSHub();
      toast(`智能 DNS 同步完成：已同步 ${res.synced_domains || 0} 个域名`);
    } catch (failure) {
      errEl.textContent = failure.message || '智能 DNS 同步失败';
      errEl.hidden = false;
    } finally {
      button.disabled = false;
    }
  }

  function resetTurnstileWidget() {
    if (state.turnstileWidget !== null && window.turnstile) {
      try { window.turnstile.remove(state.turnstileWidget); } catch { /* ignore stale widget */ }
    }
    state.turnstileWidget = null;
    state.turnstileToken = '';
    document.getElementById('turnstile-config-widget-slot')?.replaceChildren();
  }

  function mountTurnstileConfigWidget() {
    if (!state.turnstile?.site_key || !window.turnstile) return false;
    resetTurnstileWidget();
    document.getElementById('turnstile-config-widget').hidden = false;
    try {
      state.turnstileWidget = window.turnstile.render('#turnstile-config-widget-slot', {
        sitekey: state.turnstile.site_key,
        action: 'config_test',
        theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
        callback: (token) => {
          state.turnstileToken = token;
          const err = document.getElementById('turnstile-error');
          if (err) err.hidden = true;
        },
        'expired-callback': () => { state.turnstileToken = ''; },
        'error-callback': (code) => {
          state.turnstileToken = '';
          const err = document.getElementById('turnstile-error');
          if (err) {
            const detail = code ? `（错误码 ${code}）` : '';
            err.textContent = `Cloudflare 验证组件加载异常${detail}，请确认已在 Cloudflare Turnstile 后台将 ${window.location.hostname} 添加到允许的域名列表`;
            err.hidden = false;
          }
        }
      });
      return true;
    } catch {
      state.turnstileWidget = null;
      return false;
    }
  }

  async function waitForTurnstileConfigWidget() {
    if (!state.turnstile?.site_key || state.view !== 'settings' || state.settingsSection !== 'settings-turnstile') return;
    const src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    try {
      if (!window.turnstile) await loadPanelScript(src);
      if (!window.turnstile?.render) { scriptLoads.delete(src); throw new Error('unavailable'); }
      if (state.view === 'settings' && state.settingsSection === 'settings-turnstile') mountTurnstileConfigWidget();
    } catch {
      if (state.view !== 'settings' || state.settingsSection !== 'settings-turnstile') return;
      const err = document.getElementById('turnstile-error');
      err.textContent = 'Turnstile 脚本加载失败，请检查网络后重试';
      err.hidden = false;
    }
  }

  function renderTurnstile(config) {
    state.turnstile = config || { enabled: false, tested: false, site_key: '', hostname: '', secret_set: false };
    state.turnstileDirty = false;
    document.getElementById('turnstile-site-key').value = state.turnstile.site_key || '';
    document.getElementById('turnstile-secret').value = '';
    document.getElementById('turnstile-secret-status').textContent = state.turnstile.secret_set ? 'Secret key 已加密保存，留空保持不变' : '尚未配置';
    const enabled = document.getElementById('turnstile-enabled');
    enabled.checked = Boolean(state.turnstile.enabled);
    enabled.disabled = !state.turnstile.tested;

    const hasKeys = Boolean(state.turnstile.site_key && state.turnstile.secret_set);
    document.getElementById('ts-step-1').classList.toggle('done', hasKeys);
    document.getElementById('ts-step-2').classList.toggle('done', Boolean(state.turnstile.tested));
    document.getElementById('ts-step-3').classList.toggle('done', Boolean(state.turnstile.enabled));

    const hint = document.getElementById('turnstile-toggle-hint');
    if (hint) {
      if (state.turnstile.enabled) {
        hint.textContent = `已启用（绑定域名 ${state.turnstile.hostname || window.location.hostname}）：登录页将强制执行人机验证。`;
      } else if (state.turnstile.tested) {
        hint.textContent = '配置自测已通过，点击右侧开关即可立即启用登录页人机验证。';
      } else if (hasKeys) {
        hint.textContent = `密钥已保存（绑定域名 ${state.turnstile.hostname || window.location.hostname}）。请先完成上方 Cloudflare 验证并点击「执行配置自测」，自测通过后自动解锁此开关。`;
      } else {
        hint.textContent = '请先填写 Site key 和 Secret key 并点击「保存配置」，完成自测后才能开启。';
      }
    }

    const status = document.getElementById('turnstile-status');
    status.className = `badge ${state.turnstile.enabled ? 'badge-emerald' : state.turnstile.tested ? 'badge-accent' : ''}`;
    status.innerHTML = `<i data-lucide="${state.turnstile.enabled ? 'shield-check' : state.turnstile.tested ? 'badge-check' : 'shield-off'}"></i>${state.turnstile.enabled ? '已启用' : state.turnstile.tested ? '已通过自测' : '未启用'}`;
    document.getElementById('turnstile-config-widget').hidden = !state.turnstile.site_key;
    resetTurnstileWidget();
    if (state.turnstile.site_key) waitForTurnstileConfigWidget();
    refreshIcons();
  }

  async function refreshTurnstile() { renderTurnstile(await api('/_admin/api/turnstile')); }

  async function saveTurnstile(enabledOverride) {
    const enabled = typeof enabledOverride === 'boolean' ? enabledOverride : document.getElementById('turnstile-enabled').checked;
    const config = await api('/_admin/api/turnstile', jsonOptions('PUT', {
      enabled,
      site_key: document.getElementById('turnstile-site-key').value.trim(),
      secret: document.getElementById('turnstile-secret').value.trim()
    }));
    renderTurnstile(config);
    return config;
  }

  /* -------------------- Version & Self-Update -------------------- */

  function renderUpdateStatus(status) {
    if (!status) return;
    state.update = status;
    const btn = document.getElementById('update-button');
    const dot = document.getElementById('update-dot');
    const current = String(status.current_version || '');
    document.getElementById('current-version').textContent = current ? `v${current.replace(/^v/, '')}` : 'Version';
    const available = Boolean(status.update_available);
    const updating = Boolean(status.updating);
    dot.hidden = !available || updating;
    btn.classList.toggle('available', available && !updating);
    btn.disabled = updating;
    btn.title = updating ? `正在更新到 ${status.latest_version}` : available ? `发现新版本 ${status.latest_version}` : '查看 Refract 版本与更新日志';
  }

  async function refreshUpdateStatus(force = false) {
    const status = await api(`/_admin/api/update${force ? '?force=1' : ''}`);
    renderUpdateStatus(status);
    return status;
  }

  function formatReleaseDate(value) {
    if (!value) return '';
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return '';
    return `发布于 ${d.toLocaleString('zh-CN', { hour12: false, timeZone: applicationTimeZone })}`;
  }

  function cleanReleaseText(value) {
    return String(value || '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').replace(/\*\*([^*]+)\*\*/g, '$1').replace(/`([^`]+)`/g, '$1').trim();
  }

  function renderReleaseNotes(container, markdown, emptyMessage = '本版本没有提供更新日志。') {
    container.replaceChildren();
    const lines = String(markdown || '').replace(/\r/g, '').split('\n');
    let list = null; let listType = ''; let codeLines = null;
    const flushCode = () => {
      if (codeLines === null) return;
      const pre = document.createElement('pre');
      pre.textContent = codeLines.join('\n').trim();
      if (pre.textContent) container.append(pre);
      codeLines = null;
    };
    lines.forEach((rawLine) => {
      const line = rawLine.trim();
      if (line.startsWith('```')) { if (codeLines === null) { list = null; codeLines = []; } else flushCode(); return; }
      if (codeLines !== null) { codeLines.push(rawLine); return; }
      if (!line) { list = null; listType = ''; return; }
      const heading = line.match(/^#{1,4}\s+(.+)$/);
      if (heading) { list = null; container.append(el('h4', '', cleanReleaseText(heading[1]))); return; }
      const unordered = line.match(/^[-*]\s+(.+)$/);
      const ordered = line.match(/^\d+[.)]\s+(.+)$/);
      if (unordered || ordered) {
        const nextType = ordered ? 'ol' : 'ul';
        if (!list || listType !== nextType) { list = document.createElement(nextType); listType = nextType; container.append(list); }
        list.append(el('li', '', cleanReleaseText((unordered || ordered)[1])));
        return;
      }
      list = null; listType = '';
      container.append(el('p', '', cleanReleaseText(line)));
    });
    flushCode();
    if (!container.childElementCount) container.append(el('p', '', emptyMessage));
  }

  function updateDiagnosticDetails(reason) {
    const details = {
      maintenance_service_required: ['旧版部署缺少维护服务', '运行下方命令可补装受限维护通道并重启服务，不会修改代理配置。'],
      native_systemd_required: ['当前部署不支持面板更新', 'Docker 部署不会向容器暴露宿主机控制权限，请使用下方一键升级命令更新。'],
      linux_required: ['当前系统不支持面板更新', '面板自动更新仅支持 Linux VPS 环境。'],
      unsupported_architecture: ['当前架构不支持面板更新', '面板自动更新仅支持 Linux amd64 与 arm64。'],
      executable_unavailable: ['无法定位运行程序', '当前进程无法安全定位自身程序文件，请使用一键升级命令。'],
      health_check_unavailable: ['健康检查配置不可用', '服务监听地址无法生成本机健康检查地址，请检查部署配置。'],
      systemd_run_required: ['缺少 systemd-run', '系统缺少自动更新所需的 systemd-run 组件。'],
      release_assets_missing: ['当前 Release 不完整', '最新版缺少适用于当前架构的程序文件或 SHA256 校验清单。']
    };
    return details[reason] || ['面板更新暂不可用', '当前部署未通过自动更新环境检查，请使用一键升级命令。'];
  }

  function applyCurrentRelease(notes) {
    state.currentRelease = notes;
    const version = String(notes.version || state.update?.current_version || '');
    document.getElementById('current-release-title').textContent = notes.name || `Refract ${version}`;
    document.getElementById('current-release-badge').textContent = version || '当前';
    document.getElementById('current-release-date').textContent = formatReleaseDate(notes.published_at);
    renderReleaseNotes(document.getElementById('current-release-notes'), notes.notes);
  }

  async function openVersionDialog() {
    const status = state.update || {};
    const current = String(status.current_version || '');
    const available = Boolean(status.update_available);
    const dialog = document.getElementById('version-dialog');
    document.getElementById('version-dialog-summary').textContent = status.updating ? `正在更新到 ${status.latest_version}` :
      available ? `发现新版本 ${status.latest_version}` : '版本详情与官方更新日志';
    document.getElementById('current-release-title').textContent = `Refract ${current}`;
    document.getElementById('current-release-badge').textContent = current || '当前';
    document.getElementById('current-release-date').textContent = '';
    renderReleaseNotes(document.getElementById('current-release-notes'), '', '正在加载更新日志…');

    const latestSection = document.getElementById('latest-release-section');
    latestSection.hidden = !available;
    if (available) {
      document.getElementById('latest-release-title').textContent = status.latest_name || `Refract ${status.latest_version}`;
      document.getElementById('latest-release-date').textContent = formatReleaseDate(status.latest_published_at);
      renderReleaseNotes(document.getElementById('latest-release-notes'), status.latest_notes, '新版本暂未提供更新说明。');
    }

    const reason = String(status.auto_update_reason || '');
    const diag = document.getElementById('update-diagnostic');
    diag.hidden = !reason;
    if (reason) {
      const [t, m] = updateDiagnosticDetails(reason);
      document.getElementById('update-diagnostic-title').textContent = t;
      document.getElementById('update-diagnostic-message').textContent = m;
      const cmd = String(status.recovery_command || '');
      document.getElementById('update-recovery-row').hidden = !cmd;
      document.getElementById('update-recovery-command').textContent = cmd;
    }

    document.getElementById('version-update-button').hidden = !(available && status.auto_update_supported && !status.updating);
    const releaseLink = document.getElementById('release-page-link');
    let safeReleaseURL = 'https://github.com/T-Matrix/Refract/releases';
    if (status.release_url) {
      try {
        const parsed = new URL(status.release_url);
        if (parsed.protocol === 'https:') safeReleaseURL = parsed.href;
      } catch { /* fallback to default */ }
    }
    if (releaseLink) releaseLink.href = safeReleaseURL;
    refreshIcons();
    if (!dialog.open) dialog.showModal();

    if (state.currentRelease?.version === current) { applyCurrentRelease(state.currentRelease); return; }
    if (status.latest_version === current && (status.latest_notes || status.latest_name)) {
      applyCurrentRelease({ version: current, name: status.latest_name, notes: status.latest_notes, published_at: status.latest_published_at, release_url: status.release_url });
      return;
    }
    try { applyCurrentRelease(await api('/_admin/api/update/notes')); }
    catch { renderReleaseNotes(document.getElementById('current-release-notes'), '', '当前版本更新日志暂时无法获取。'); }
  }

  async function waitForUpdatedVersion(version) {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      await new Promise((r) => window.setTimeout(r, 1500));
      try {
        const res = await fetch('/_admin/api/session', { credentials: 'same-origin', cache: 'no-store' });
        if (!res.ok) continue;
        const session = await res.json();
        if (session.version === version) {
          window.location.replace(`/panel?updated=${encodeURIComponent(version)}#${encodeURIComponent(state.view || 'overview')}`);
          return;
        }
      } catch { /* restarting */ }
    }
    toast('更新任务仍在执行，请稍后刷新页面', 'info');
  }

  async function startPanelUpdate() {
    const status = state.update;
    if (!status?.update_available) return;
    if (!status.auto_update_supported) { toast(updateDiagnosticDetails(status.auto_update_reason)[0], 'info'); return; }
    const vd = document.getElementById('version-dialog');
    if (vd.open) vd.close();
    const confirmed = await confirmAction({
      title: `更新到 Refract ${status.latest_version}`,
      message: '更新包将从官方 GitHub Release 下载并校验 SHA256。服务将短暂重启，失败自动回滚。',
      confirmLabel: '立即更新', icon: 'circle-arrow-up'
    });
    if (!confirmed) return;
    document.getElementById('update-button').disabled = true;
    try {
      const next = await api('/_admin/api/update', jsonOptions('POST', { version: status.latest_version }));
      renderUpdateStatus(next);
      toast(`正在更新到 Refract ${status.latest_version}`, 'info');
      await waitForUpdatedVersion(status.latest_version);
    } catch {
      document.getElementById('update-button').disabled = false;
      toast('更新启动失败，请稍后重试', 'error');
      refreshUpdateStatus(true).catch(() => {});
    }
  }

  /* -------------------- Navigation, Refresh & Theme -------------------- */

  async function refreshDashboard() {
    const reqKey = `${state.overviewPeriod}|${state.nodeScope}`;
    if (state.dashboardPromise && state.dashboardReqKey === reqKey) return state.dashboardPromise;
    const seq = ++state.dashboardReqSeq;
    const params = new URLSearchParams({ period: state.overviewPeriod });
    if (state.nodeScope) params.set('node_id', state.nodeScope);
    const req = api(`/_admin/api/dashboard?${params}`).then((s) => {
      if (seq === state.dashboardReqSeq) render(s);
      return s;
    });
    state.dashboardPromise = req;
    state.dashboardReqKey = reqKey;
    try { return await req; } finally {
      if (state.dashboardPromise === req) {
        state.dashboardPromise = null;
        state.dashboardReqKey = '';
      }
    }
  }

  async function refresh(showNotice = false, refreshView = true) {
    const button = document.getElementById('refresh-button');
    if (showNotice) { button.disabled = true; button.querySelector('svg')?.classList.add('spinning'); }
    try {
      const tasks = [refreshDashboard(), api('/_admin/api/policy').then(renderPolicy), refreshWAFRules(), refreshNodes(), refreshDomains(), refreshWatching()];
      if (state.view === 'overview') tasks.push(refreshGeography());
      if (refreshView) {
        const map = {
          requests: () => refreshRequests(state.requestPage),
          connections: refreshConnections,
          dns: () => Promise.all([refreshSmartDNSProfiles(), ...(state.dnsHubTab === 'providers' ? [refreshAxisNowDNS().catch(() => {}), refreshCloudflareDNS().catch(() => {})] : [])]),
          'emby-health': refreshEmbyHealth,
          reports: refreshReport,
          audit: refreshAudit,
          backups: refreshBackups
        };
        if (hasOwn(map, state.view)) tasks.push(map[state.view]());
      }
      const results = await Promise.allSettled(tasks);
      const failure = results.find((r) => r.status === 'rejected');
      if (failure) throw failure.reason;
      if (showNotice) toast('数据已同步');
    } catch (failure) {
      if (failure.message !== 'authentication required') toast('数据刷新失败', 'error');
    } finally {
      if (showNotice) { button.disabled = false; button.querySelector('svg')?.classList.remove('spinning'); }
    }
  }

  async function refreshLive() {
    if (state.liveRefreshing || document.hidden) return;
    state.liveRefreshing = true;
    try {
      const qs = state.nodeScope ? `?node_id=${encodeURIComponent(state.nodeScope)}` : '';
      const live = await api(`/_admin/api/live${qs}`);
      renderLive(live);
      const now = Date.now();
      if (state.view === 'watching' && now - state.lastWatchingRefresh >= 3000) {
        state.lastWatchingRefresh = now;
        await refreshWatching();
      }
      if (state.view === 'connections' && now - state.lastConnectionsRefresh >= 3000) {
        state.lastConnectionsRefresh = now;
        await refreshConnections();
      }
      if (state.view === 'nodes' && !document.getElementById('node-drawer')?.classList.contains('open') && state.busyNodeIDs.size === 0 && now - state.lastNodesRefresh >= 4000) {
        state.lastNodesRefresh = now;
        await refreshNodes();
      }
      if (state.view === 'domains' && !document.getElementById('domain-drawer')?.classList.contains('open') && state.busyDomainIDs.size === 0 && now - state.lastDomainsRefresh >= 5000) {
        state.lastDomainsRefresh = now;
        await refreshDomains();
      }
      if (state.view === 'dns' && state.dnsHubTab !== 'providers' && !document.querySelector('.drawer-root.open, dialog[open]') && now - state.lastDNSRefresh >= 8000) {
        state.lastDNSRefresh = now;
        await Promise.all([refreshSmartDNSProfiles().catch(() => {}), refreshDomains().catch(() => {})]);
        if (state.view === 'dns') renderDNSHub();
      }
      if (state.view === 'rules' && !document.getElementById('waf-editor-drawer')?.classList.contains('open') && now - state.lastPolicyRefresh >= 6000) {
        state.lastPolicyRefresh = now;
        await refreshWAFRules();
      }
    } catch { /* dashboard handles auth */ } finally { state.liveRefreshing = false; }
  }

  function renderSettingsSection() {
    if (!hasOwn(settingsMeta, state.settingsSection)) state.settingsSection = 'settings-runtime';
    if (state.settingsSection !== 'settings-turnstile') resetTurnstileWidget();
    document.querySelectorAll('.settings-panel').forEach((p) => { p.hidden = p.id !== state.settingsSection; });
    document.querySelectorAll('.settings-tab').forEach((t) => {
      const active = t.dataset.settingsSection === state.settingsSection;
      t.classList.toggle('active', active);
      t.setAttribute('aria-pressed', String(active));
    });
  }

  async function openSettingsSection(section) {
    if (section === 'settings-cloudflare' || section === 'settings-axisnow') {
      await openDNSHubTab('providers');
      return;
    }
    if (!hasOwn(settingsMeta, section)) return;
    state.settingsSection = section;
    await switchView('settings');
  }

  async function switchView(view) {
    if (!hasOwn(viewMeta, view)) return;
    const seq = ++viewTransitionSequence;
    if (view !== 'settings') resetTurnstileWidget();
    state.view = view;
    clearInterval(state.embyHealthTimer);
    state.embyHealthTimer = null;

    if (view === 'settings') renderSettingsSection();
    const base = viewMeta[view];
    const meta = view === 'settings' ? settingsMeta[state.settingsSection] : base;

    const navView = state.role === 'controller' && view === 'audit' ? 'settings' : view;
    document.querySelectorAll('.nav-item[data-view]').forEach((n) => n.classList.toggle('active', n.dataset.view === navView));
    document.getElementById('breadcrumb-domain').textContent = state.role === 'controller' && view === 'audit' ? '系统设置' : base[3];
    document.getElementById('breadcrumb-page').textContent = meta[0];
    document.getElementById('page-title').textContent = meta[0];
    document.getElementById('page-subtitle').textContent = meta[1];
    document.getElementById('page-heading-icon').innerHTML = `<i data-lucide="${meta[2]}"></i>`;

    setupNavIndicator();
    window.history.replaceState(null, '', `/panel#${view === 'settings' ? state.settingsSection : view}`);
    setMobileSidebar(false);
    closeCommandPalette();
    window.scrollTo({ top: 0, behavior: 'instant' });
    refreshIcons();

    if (seq !== viewTransitionSequence) return;
    document.querySelectorAll('.view').forEach((node) => {
      const active = node.id === `view-${view}`;
      node.classList.toggle('active', active);
      node.inert = !active;
    });
    requestAnimationFrame(() => document.querySelectorAll('.segmented').forEach(syncSegmented));

    if (view === 'overview') {
      if (state.snapshot) {
        renderCompactTargets(state.snapshot.targets);
        renderCompactRequests(state.snapshot.recent);
        requestAnimationFrame(() => { renderOverviewTrendChart(state.snapshot.timeline); setGeoMode(state.geoMode, false); });
      } else {
        requestAnimationFrame(() => setGeoMode(state.geoMode, false));
      }
      if (!state.geography) refreshGeography().catch(() => {});
    } else {
      geoGlobe.stop();
    }
    syncNodeScopeSelect();
    if (view === 'nodes') refreshNodes().catch(() => toast('边缘节点加载失败', 'error'));
    if (view === 'domains') {
      Promise.all([refreshNodes().catch(() => {}), refreshWAFRules().catch(() => {}), refreshSmartDNSProfiles().catch(() => {}), refreshDomains()]).catch(() => toast('域名入口加载失败', 'error'));
    }
    if (view === 'dns') {
      setDNSHubTab(state.dnsHubTab, { refreshProviders: true });
      Promise.all([
        refreshNodes().catch(() => {}),
        refreshDomains().catch(() => {}),
        refreshSmartDNSProfiles(),
        ensureAxisNowMetadata(false).catch(() => {})
      ]).then(() => {
        if (seq !== viewTransitionSequence || state.view !== 'dns') return;
        renderDNSHub();
        setDNSHubTab(state.dnsHubTab, { refreshProviders: false });
      }).catch(() => toast('DNS 与分流数据加载失败', 'error'));
    }
    if (view === 'targets' && state.snapshot) renderTargets(state.snapshot.targets);
    if (view === 'watching') refreshWatching().catch(() => toast('播放状态加载失败', 'error'));
    if (view === 'connections') refreshConnections().catch(() => toast('实时连接加载失败', 'error'));
    if (view === 'emby-health') {
      refreshEmbyHealth().catch(() => toast('Emby 探针加载失败', 'error'));
      state.embyHealthTimer = window.setInterval(() => { if (!document.hidden) refreshEmbyHealth().catch(() => {}); }, 15_000);
    }
    if (view === 'requests') refreshRequests(1).catch(() => toast('请求日志加载失败', 'error'));
    if (view === 'reports') {
      refreshReport().catch(() => toast('统计报表加载失败', 'error'));
      requestAnimationFrame(redrawReportCharts);
    }
    if (view === 'rules') {
      refreshWAFRules().catch(() => toast('WAF 规则加载失败', 'error'));
    }
    if (view === 'audit') refreshAudit().catch(() => toast('审计日志加载失败', 'error'));
    if (view === 'backups') refreshBackups().catch(() => toast('备份列表加载失败', 'error'));
    if (view === 'settings') {
      if (state.settingsSection === 'settings-branding') refreshBranding().catch(() => toast('品牌外观加载失败', 'error'));
      if (state.settingsSection === 'settings-runtime') refreshRuntimeConfig().catch(() => toast('运行配置加载失败', 'error'));
      if (state.settingsSection === 'settings-telegram') api('/_admin/api/telegram').then(renderTelegram).catch(() => toast('Telegram 配置加载失败', 'error'));
      if (state.settingsSection === 'settings-turnstile') refreshTurnstile().catch(() => toast('Turnstile 配置加载失败', 'error'));
    }
  }

  function setTheme(theme, { skipRedraw = false } = {}) {
    const dark = theme === 'dark';
    document.documentElement.dataset.theme = dark ? 'dark' : 'light';
    safeStorageSet('gateway-theme', dark ? 'dark' : 'light');
    const btn = document.getElementById('theme-button');
    btn.setAttribute('aria-label', dark ? '切换浅色模式' : '切换深色模式');
    btn.setAttribute('title', dark ? '切换浅色模式' : '切换深色模式');
    btn.innerHTML = `<i data-lucide="${dark ? 'sun' : 'moon'}"></i>`;
    refreshIcons();
    if (skipRedraw) return;
    if (state.snapshot && state.view === 'overview') requestAnimationFrame(() => renderOverviewTrendChart(state.snapshot.timeline));
    if (state.view === 'overview') requestAnimationFrame(renderGeographyMap);
    if (state.view === 'reports') requestAnimationFrame(redrawReportCharts);
    if (state.turnstile?.site_key && !state.turnstileDirty && !document.getElementById('turnstile-config-widget')?.hidden && state.view === 'settings' && state.settingsSection === 'settings-turnstile' && window.turnstile) {
      mountTurnstileConfigWidget();
    }
  }

  function setSidebarCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    safeStorageSet('gateway-sidebar-collapsed', String(collapsed));
    const btn = document.getElementById('sidebar-collapse');
    btn.setAttribute('aria-expanded', String(!collapsed));
    btn.setAttribute('aria-label', collapsed ? '展开侧栏' : '折叠侧栏');
    btn.setAttribute('title', collapsed ? '展开侧栏' : '折叠侧栏');
    btn.innerHTML = `<i data-lucide="${collapsed ? 'panel-left-open' : 'panel-left-close'}"></i>`;
    refreshIcons();
    window.setTimeout(scheduleLayoutRefresh, 260);
  }

  function setMobileSidebar(open) {
    document.body.classList.toggle('sidebar-open', open);
    document.getElementById('mobile-menu-button').setAttribute('aria-expanded', String(open));
    document.getElementById('sidebar-scrim').hidden = !open;
  }

  function setFullWidth(enabled) {
    const workspace = document.querySelector('.workspace');
    const btn = document.getElementById('full-width-button');
    workspace.classList.toggle('full-width', enabled);
    safeStorageSet('gateway-full-width', String(enabled));
    btn.setAttribute('aria-pressed', String(enabled));
    btn.setAttribute('aria-label', enabled ? '恢复居中宽度' : '切换全宽布局');
    btn.setAttribute('title', enabled ? '恢复居中宽度' : '切换全宽布局');
    btn.innerHTML = `<i data-lucide="${enabled ? 'minimize-2' : 'maximize-2'}"></i>`;
    refreshIcons();
    scheduleLayoutRefresh();
  }

  /* -------------------- Command Palette (Keyboard Navigable) -------------------- */

  function visibleCommandItems() {
    return [...document.querySelectorAll('#command-list .command-item')].filter((b) => !b.hidden);
  }

  function highlightCommandItem(index) {
    const items = visibleCommandItems();
    items.forEach((b) => b.classList.remove('focused'));
    if (!items.length) { state.commandFocusIndex = -1; return; }
    const clamped = ((index % items.length) + items.length) % items.length;
    state.commandFocusIndex = clamped;
    items[clamped].classList.add('focused');
    items[clamped].scrollIntoView({ block: 'nearest' });
  }

  function filterCommandItems(query) {
    const needle = query.trim().toLowerCase();
    let visible = 0;
    document.querySelectorAll('#command-list .command-item').forEach((btn) => {
      if (state.role === 'controller' && btn.classList.contains('controller-hide')) {
        btn.hidden = true;
        return;
      }
      const text = `${btn.dataset.commandSearch || ''} ${btn.textContent || ''}`.toLowerCase();
      const match = !needle || text.includes(needle);
      btn.hidden = !match;
      if (match) visible += 1;
    });
    document.querySelectorAll('#command-list .command-group-label').forEach((label) => {
      let next = label.nextElementSibling;
      let hasVisible = false;
      while (next && !next.classList.contains('command-group-label') && next.id !== 'command-empty') {
        if (!next.hidden) hasVisible = true;
        next = next.nextElementSibling;
      }
      label.hidden = !hasVisible;
    });
    document.getElementById('command-empty').hidden = visible !== 0;
    highlightCommandItem(0);
  }

  function openCommandPalette() {
    const dialog = document.getElementById('command-dialog');
    const input = document.getElementById('command-input');
    input.value = '';
    filterCommandItems('');
    if (!dialog.open) dialog.showModal();
    refreshIcons();
    window.setTimeout(() => input.focus(), 0);
  }

  function closeCommandPalette() {
    const dialog = document.getElementById('command-dialog');
    if (dialog.open) dialog.close();
  }

  function runCommandAction(action) {
    closeCommandPalette();
    if (action === 'refresh') refresh(true);
    else if (action === 'theme') setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    else if (action === 'add-node') switchView('nodes').then(openDiscoveryDialog);
    else if (action === 'add-domain') switchView('domains').then(openDomainDrawerForCreate);
    else if (action === 'add-emby') switchView('emby-health').then(openEmbyDrawerForCreate);
    else if (action === 'version') openVersionDialog();
  }

  /* -------------------- Password Live Validation -------------------- */

  function updatePasswordFormChecks() {
    const next = document.getElementById('new-password').value;
    const confirm = document.getElementById('confirm-password').value;
    const byteLen = utf8ByteLength(next);
    const lenOk = next.length >= 12 && byteLen <= 72;
    const matchOk = next.length > 0 && next === confirm;
    const lenEl = document.getElementById('pw-check-len');
    const matchEl = document.getElementById('pw-check-match');
    lenEl.classList.toggle('pass', lenOk);
    lenEl.innerHTML = `<i data-lucide="${lenOk ? 'check-circle-2' : 'circle'}"></i><span>新密码至少 12 个字符且不超过 72 字节（当前 ${next.length} 字符 / ${byteLen} 字节）</span>`;
    matchEl.classList.toggle('pass', matchOk);
    matchEl.innerHTML = `<i data-lucide="${matchOk ? 'check-circle-2' : 'circle'}"></i><span>两次输入的新密码保持一致</span>`;
    refreshIcons();
  }

  /* -------------------- Bootstrap & Event Bindings -------------------- */

  function resolveInitialRoute(role) {
    const initialHash = window.location.hash.slice(1);
    const controllerHiddenViews = new Set(['targets', 'reports']);
    if (initialHash === 'settings-cloudflare' || initialHash === 'settings-axisnow') {
      return { view: 'dns', dnsTab: 'providers' };
    }
    if (hasOwn(settingsMeta, initialHash) && !(role === 'controller' && initialHash === 'settings-security')) {
      return { view: 'settings', settingsSection: initialHash };
    }
    if (hasOwn(viewMeta, initialHash) && !(role === 'controller' && controllerHiddenViews.has(initialHash))) {
      return { view: initialHash };
    }
    return { view: 'overview' };
  }

  function applyRouteShellSync(route) {
    const view = route.view || 'overview';
    state.view = view;
    if (route.settingsSection) state.settingsSection = route.settingsSection;
    if (route.dnsTab) state.dnsHubTab = route.dnsTab;
    if (view === 'settings') renderSettingsSection();
    if (view === 'dns') {
      const next = ['profiles', 'domains', 'providers'].includes(state.dnsHubTab) ? state.dnsHubTab : 'profiles';
      state.dnsHubTab = next;
      document.querySelectorAll('#dns-hub-tabs button').forEach((btn) => {
        const active = btn.dataset.dnsTab === next;
        btn.classList.toggle('active', active);
        btn.setAttribute('aria-selected', String(active));
      });
      ['profiles', 'domains', 'providers'].forEach((k) => {
        const pane = document.getElementById(`dns-pane-${k}`);
        if (pane) pane.hidden = k !== next;
      });
      const quickBtn = document.getElementById('dns-quick-cn3-btn');
      const createBtn = document.getElementById('dns-create-profile-btn');
      if (quickBtn) quickBtn.hidden = next !== 'profiles';
      if (createBtn) createBtn.hidden = next !== 'profiles';
    }
    const base = viewMeta[view] || viewMeta.overview;
    const meta = view === 'settings' ? (settingsMeta[state.settingsSection] || base) : base;
    const navView = state.role === 'controller' && view === 'audit' ? 'settings' : view;
    document.querySelectorAll('.nav-item[data-view]').forEach((n) => n.classList.toggle('active', n.dataset.view === navView));
    document.querySelectorAll('.view').forEach((node) => {
      const active = node.id === `view-${view}`;
      node.classList.toggle('active', active);
      node.inert = !active;
    });
    document.getElementById('breadcrumb-domain').textContent = state.role === 'controller' && view === 'audit' ? '系统设置' : base[3];
    document.getElementById('breadcrumb-page').textContent = meta[0];
    document.getElementById('page-title').textContent = meta[0];
    document.getElementById('page-subtitle').textContent = meta[1];
    document.getElementById('page-heading-icon').innerHTML = `<i data-lucide="${meta[2]}"></i>`;
  }

  async function initialize() {
    const sessionRequest = api('/_admin/api/session');

    // Synchronously apply server-injected role and URL hash view BEFORE first paint/await to prevent any FOUC.
    state.role = document.body.dataset.role || (document.body.classList.contains('mode-controller') ? 'controller' : 'standalone');
    applyControllerRoleUI();
    applyRouteShellSync(resolveInitialRoute(state.role));

    document.body.classList.add('boot-no-transition');
    setTheme(safeStorageGet('gateway-theme') === 'dark' ? 'dark' : 'light', { skipRedraw: true });
    setSidebarCollapsed(safeStorageGet('gateway-sidebar-collapsed') === 'true');
    setFullWidth(safeStorageGet('gateway-full-width') === 'true');
    requestAnimationFrame(() => document.body.classList.remove('boot-no-transition'));
    document.getElementById('command-modifier').textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl+';

    const tgHour = document.getElementById('telegram-hour');
    const bkHour = document.getElementById('backup-hour');
    for (let h = 0; h < 24; h += 1) {
      const opt = document.createElement('option');
      opt.value = String(h);
      opt.textContent = `${String(h).padStart(2, '0')}:00`;
      tgHour.append(opt);
      bkHour.append(opt.cloneNode(true));
    }

    setupNavIndicator();
    setupSegmentedControls();

    // Navigation & Shell Events
    document.querySelectorAll('.nav-item[data-view]').forEach((b) => b.addEventListener('click', () => { state.userNavigatedBeforeSession = true; switchView(b.dataset.view); }));
    document.querySelectorAll('[data-go-view]').forEach((b) => b.addEventListener('click', () => { state.userNavigatedBeforeSession = true; switchView(b.dataset.goView); }));
    document.querySelectorAll('[data-go-settings]').forEach((b) => b.addEventListener('click', () => { state.userNavigatedBeforeSession = true; openSettingsSection(b.dataset.goSettings); }));
    document.querySelectorAll('.settings-tab').forEach((b) => b.addEventListener('click', () => { state.userNavigatedBeforeSession = true; openSettingsSection(b.dataset.settingsSection); }));
    document.getElementById('sidebar-collapse').addEventListener('click', () => setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed')));
    document.getElementById('mobile-menu-button').addEventListener('click', () => setMobileSidebar(!document.body.classList.contains('sidebar-open')));
    document.getElementById('sidebar-scrim').addEventListener('click', () => setMobileSidebar(false));
    document.getElementById('full-width-button').addEventListener('click', () => setFullWidth(!document.querySelector('.workspace').classList.contains('full-width')));
    document.getElementById('theme-button').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
    document.getElementById('refresh-button').addEventListener('click', () => refresh(true));
    document.getElementById('logout-button').addEventListener('click', async () => {
      try { await api('/_admin/api/logout', jsonOptions('POST', {})); } finally { window.location.replace('/login'); }
    });

    // Drawers
    document.querySelectorAll('[data-close-drawer]').forEach((btn) => btn.addEventListener('click', () => closeDrawer(btn.dataset.closeDrawer)));

    // Overview Geography Tabs & Period
    document.querySelectorAll('[data-geo-tab]').forEach((btn) => btn.addEventListener('click', () => {
      const tab = btn.dataset.geoTab;
      state.geoTab = tab;
      document.querySelectorAll('[data-geo-tab]').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('active', active);
        b.setAttribute('aria-selected', String(active));
      });
      document.getElementById('geo-tab-regions').hidden = tab !== 'regions';
      document.getElementById('geo-tab-ips').hidden = tab !== 'ips';
      document.getElementById('geo-detail-hint').textContent = tab === 'regions' ? '按最大下行速度排序' : '合并同一客户端 IP 并发下行速率';
      syncSegmented(document.getElementById('geo-table-tabs'));
    }));

    document.querySelectorAll('[data-geo-period]').forEach((btn) => btn.addEventListener('click', async () => {
      if (btn.disabled || btn.dataset.geoPeriod === state.overviewPeriod) return;
      const periodBtns = [...document.querySelectorAll('[data-geo-period]')];
      const prev = state.overviewPeriod;
      state.overviewPeriod = btn.dataset.geoPeriod;
      periodBtns.forEach((i) => {
        const a = i === btn;
        i.classList.toggle('active', a);
        i.setAttribute('aria-pressed', String(a));
        i.disabled = true;
      });
      syncSegmented(btn.closest('.segmented'));
      try {
        await Promise.all([refreshDashboard(), refreshGeography()]);
        toast(`已切换至最近 ${overviewPeriodLabel()}`);
      } catch {
        state.overviewPeriod = prev;
        periodBtns.forEach((i) => {
          const a = i.dataset.geoPeriod === prev;
          i.classList.toggle('active', a);
          i.setAttribute('aria-pressed', String(a));
        });
        syncSegmented(btn.closest('.segmented'));
        toast('概览周期加载失败', 'error');
      } finally {
        periodBtns.forEach((i) => { i.disabled = false; });
      }
    }));

    document.querySelectorAll('[data-geo-mode]').forEach((btn) => btn.addEventListener('click', () => {
      setGeoMode(btn.dataset.geoMode, true);
    }));
    document.getElementById('map-autorotate')?.addEventListener('click', () => geoGlobe.toggleAutoRotate());
    document.getElementById('map-zoom-in').addEventListener('click', () => zoomGeographyMap(1.28));
    document.getElementById('map-zoom-out').addEventListener('click', () => zoomGeographyMap(0.78));
    document.getElementById('map-reset').addEventListener('click', resetGeographyMap);
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) geoGlobe.stop();
      else if (state.view === 'overview' && state.geoMode === '3d') geoGlobe.start();
    });

    // Connections & Targets Search
    document.getElementById('connections-search').addEventListener('input', (e) => {
      state.connectionsQuery = e.currentTarget.value;
      renderConnections({ connections: state.connectionsData });
    });
    document.getElementById('targets-search').addEventListener('input', (e) => {
      state.targetsQuery = e.currentTarget.value;
      if (state.snapshot) renderTargets(state.snapshot.targets);
    });

    // Emby Health Controls
    document.getElementById('emby-health-add-btn').addEventListener('click', openEmbyDrawerForCreate);
    document.getElementById('emby-health-settings-btn')?.addEventListener('click', openEmbySettingsDrawer);
    document.getElementById('emby-health-batch-btn')?.addEventListener('click', openEmbyBatchDrawer);
    document.getElementById('emby-health-check-all-btn')?.addEventListener('click', checkAllEmbyHealth);
    document.getElementById('emby-health-form').addEventListener('submit', saveEmbyHealth);
    document.getElementById('emby-settings-form')?.addEventListener('submit', saveEmbyProbeSettings);
    document.getElementById('emby-batch-form')?.addEventListener('submit', submitEmbyBatchImport);
    document.querySelectorAll('#emby-probe-presets .probe-preset-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        const input = document.getElementById('emby-health-probe-path');
        if (input) {
          input.value = chip.dataset.probePath || '';
          input.focus();
        }
      });
    });
    document.querySelectorAll('[data-health-filter]').forEach((btn) => btn.addEventListener('click', () => {
      state.embyHealthFilter = btn.dataset.healthFilter;
      document.querySelectorAll('[data-health-filter]').forEach((b) => {
        const a = b === btn;
        b.classList.toggle('active', a);
        b.setAttribute('aria-pressed', String(a));
      });
      syncSegmented(document.getElementById('emby-health-status-filter'));
      renderEmbyHealth(state.embyHealthServers);
    }));
    document.getElementById('emby-health-search').addEventListener('input', (e) => {
      state.embyHealthQuery = e.currentTarget.value;
      renderEmbyHealth(state.embyHealthServers);
    });

    // Requests Filters & Pagination
    document.getElementById('request-status-filters').addEventListener('click', (event) => {
      const btn = event.target.closest('button[data-request-status]');
      if (!btn || btn.disabled || btn.dataset.requestStatus === state.requestStatus) return;
      state.requestStatus = btn.dataset.requestStatus;
      document.querySelectorAll('#request-status-filters button').forEach((item) => {
        const active = item === btn;
        item.classList.toggle('active', active);
        item.setAttribute('aria-pressed', String(active));
      });
      syncSegmented(document.getElementById('request-status-filters'));
      refreshRequests(1).catch(() => toast('日志筛选失败', 'error'));
    });

    const hostInput = document.getElementById('request-host-filter');
    const ipInput = document.getElementById('request-ip-filter');
    let ipFilterTimer = null;
    hostInput.addEventListener('input', () => {
      clearTimeout(hostFilterTimer);
      hostFilterTimer = window.setTimeout(() => {
        if (state.requestHost !== hostInput.value.trim()) {
          state.requestHost = hostInput.value.trim();
          refreshRequests(1).catch(() => toast('域名筛选失败', 'error'));
        }
      }, 360);
    });
    hostInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        clearTimeout(hostFilterTimer);
        state.requestHost = hostInput.value.trim();
        refreshRequests(1).catch(() => toast('域名筛选失败', 'error'));
      }
    });
    ipInput?.addEventListener('input', () => {
      clearTimeout(ipFilterTimer);
      ipFilterTimer = window.setTimeout(() => {
        if (state.requestClientIP !== ipInput.value.trim()) {
          state.requestClientIP = ipInput.value.trim();
          refreshRequests(1).catch(() => toast('来源 IP 筛选失败', 'error'));
        }
      }, 360);
    });
    ipInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        clearTimeout(ipFilterTimer);
        state.requestClientIP = ipInput.value.trim();
        refreshRequests(1).catch(() => toast('来源 IP 筛选失败', 'error'));
      }
    });
    document.getElementById('request-filter-clear').addEventListener('click', () => {
      state.requestStatus = '';
      state.requestHost = '';
      state.requestClientIP = '';
      hostInput.value = '';
      if (ipInput) ipInput.value = '';
      refreshRequests(1).catch(() => toast('重置筛选失败', 'error'));
    });
    document.getElementById('request-page-size').addEventListener('change', (e) => {
      state.requestPageSize = Number(e.currentTarget.value) || 20;
      refreshRequests(1).catch(() => toast('切换分页大小失败', 'error'));
    });
    document.getElementById('request-page-previous').addEventListener('click', () => {
      if (state.requestPage > 1) refreshRequests(state.requestPage - 1).catch(() => toast('上一页加载失败', 'error'));
    });
    document.getElementById('request-page-next').addEventListener('click', () => {
      if (state.requestPage < state.requestTotalPages) refreshRequests(state.requestPage + 1).catch(() => toast('下一页加载失败', 'error'));
    });

    // Reports Period & Export
    document.querySelectorAll('[data-report-period]').forEach((btn) => btn.addEventListener('click', async () => {
      if (btn.dataset.reportPeriod === state.reportPeriod) return;
      const prev = state.reportPeriod;
      state.reportPeriod = btn.dataset.reportPeriod;
      document.querySelectorAll('[data-report-period]').forEach((i) => {
        const a = i === btn;
        i.classList.toggle('active', a);
        i.setAttribute('aria-pressed', String(a));
      });
      syncSegmented(btn.closest('.segmented'));
      btn.disabled = true;
      try { await refreshReport(); }
      catch {
        state.reportPeriod = prev;
        document.querySelectorAll('[data-report-period]').forEach((i) => {
          const a = i.dataset.reportPeriod === prev;
          i.classList.toggle('active', a);
          i.setAttribute('aria-pressed', String(a));
        });
        syncSegmented(btn.closest('.segmented'));
        toast('统计报表加载失败', 'error');
      } finally { btn.disabled = false; }
    }));
    document.getElementById('report-export').addEventListener('click', () => {
      const kind = document.getElementById('report-export-kind').value;
      const link = document.createElement('a');
      link.href = `/_admin/api/reports/export?period=${encodeURIComponent(state.reportPeriod)}&kind=${encodeURIComponent(kind)}`;
      link.download = '';
      document.body.append(link);
      link.click();
      link.remove();
      toast('已开始导出 CSV 报表', 'info');
    });

    // Audit Filters
    document.querySelectorAll('[data-audit-result]').forEach((btn) => btn.addEventListener('click', () => {
      state.auditFilter = btn.dataset.auditResult;
      document.querySelectorAll('[data-audit-result]').forEach((b) => {
        const a = b === btn;
        b.classList.toggle('active', a);
        b.setAttribute('aria-pressed', String(a));
      });
      syncSegmented(document.getElementById('audit-result-filter'));
      renderAudit();
    }));
    document.getElementById('audit-search').addEventListener('input', (e) => {
      state.auditQuery = e.currentTarget.value;
      renderAudit();
    });

    // Backups Forms
    document.getElementById('backup-config-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const error = document.getElementById('backup-config-error');
      error.hidden = true;
      if (!form.checkValidity()) {
        form.reportValidity();
        return;
      }
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        await api('/_admin/api/backups/config', jsonOptions('PUT', {
          enabled: document.getElementById('backup-enabled').checked,
          hour: Number(document.getElementById('backup-hour').value),
          retention: Number(document.getElementById('backup-retention').value)
        }));
        await refreshBackups();
        toast('自动备份策略已保存');
      } catch {
        error.textContent = '备份策略保存失败，请检查执行时间与保留数量（1-30）';
        error.hidden = false;
      } finally { submit.disabled = false; }
    });
    document.getElementById('backup-create').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try { renderBackups(await api('/_admin/api/backups', jsonOptions('POST', {}))); toast('数据库快照已创建'); }
      catch { toast('快照创建失败', 'error'); }
      finally { btn.disabled = false; }
    });
    document.getElementById('backup-import').addEventListener('change', async (e) => {
      const input = e.currentTarget;
      const file = input.files?.[0];
      if (!file) return;
      const form = new FormData();
      form.append('backup', file, file.name);
      input.disabled = true;
      try { renderBackups(await api('/_admin/api/backups/import', { method: 'POST', body: form })); toast('外部备份已导入'); }
      catch { toast('备份导入失败，请确认文件为有效 SQLite 数据库', 'error'); }
      finally { input.value = ''; input.disabled = false; }
    });

    // Settings Forms
    RUNTIME_TOGGLES.forEach(({ id, field, label }) => {
      const input = document.getElementById(id);
      if (input) input.addEventListener('change', () => toggleRuntimeFeature(input, field, label));
    });

    document.getElementById('runtime-config-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const error = document.getElementById('runtime-config-error');
      error.hidden = true;
      if (!form.checkValidity()) {
        const fold = document.getElementById('runtime-advanced-fold');
        if (fold) fold.open = true;
        form.reportValidity();
        return;
      }
      const payload = runtimeConfigPayload();
      if (payload.max_concurrent_per_ip > payload.max_concurrent_requests) {
        error.textContent = '单 IP 最大并发不能大于全局最大并发';
        error.hidden = false;
        document.getElementById('runtime-ip-limit').focus();
        return;
      }
      const hotReload = state.runtimeConfig?.hot_reload !== false;
      if (!hotReload) {
        const confirmed = await confirmAction({
          title: '保存运行配置',
          message: state.runtimeConfig?.restart_on_save
            ? '配置通过校验后服务将自动重启，当前连接会短暂中断；上一份可用配置已自动保留用于回退。'
            : '配置将写入安全覆盖文件，手动重启 Refract 服务后生效。',
          confirmLabel: state.runtimeConfig?.restart_on_save ? '保存并重启' : '保存配置',
          icon: 'server-cog'
        });
        if (!confirmed) return;
      }
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      setRuntimeTogglesDisabled(true);
      try {
        const saved = await api('/_admin/api/runtime-config', jsonOptions('PUT', payload));
        renderRuntimeConfig(saved);
        if (saved.restart_pending) {
          toast('配置已保存，服务正在重启…', 'info');
          await waitForRuntimeRestart();
        } else if (saved.hot_reload !== false) {
          toast('运行配置已热重载并实时生效');
        } else {
          toast('配置已保存，重启服务后生效');
        }
      } catch {
        error.textContent = '配置保存失败，请检查上游地址格式、超时、并发及限速数值';
        error.hidden = false;
      } finally {
        submit.disabled = false;
        setRuntimeTogglesDisabled(false);
      }
    });

    document.getElementById('branding-avatar-file').addEventListener('change', (e) => selectBrandingFile(e.currentTarget));
    document.getElementById('branding-avatar-save').addEventListener('click', saveBrandingAvatar);
    document.getElementById('branding-avatar-reset').addEventListener('click', resetBrandingAvatar);

    document.getElementById('telegram-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const submit = e.currentTarget.querySelector('button[type="submit"]');
      if (submit) submit.disabled = true;
      try { await saveTelegram(true); }
      catch (failure) {
        if (failure?.message === 'invalid form') return;
        const err = document.getElementById('telegram-error');
        err.textContent = failure?.message || 'Telegram 配置无效，请检查 Bot Token 与 Chat ID';
        err.hidden = false;
      }
      finally { if (submit) submit.disabled = false; }
    });
    document.getElementById('telegram-test').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try { await saveTelegram(false); await api('/_admin/api/telegram/test', jsonOptions('POST', {})); toast('测试消息已发送至 Telegram'); }
      catch (failure) {
        if (failure?.message === 'invalid form') return;
        const err = document.getElementById('telegram-error');
        err.textContent = failure?.message || '测试发送失败，请检查 Bot Token、Chat ID 及网络连通性';
        err.hidden = false;
      }
      finally { btn.disabled = false; }
    });

    document.querySelectorAll('#turnstile-site-key, #turnstile-secret').forEach((input) => input.addEventListener('input', () => {
      if (!state.turnstile) return;
      state.turnstileDirty = true;
      state.turnstile.tested = false;
      state.turnstileToken = '';
      document.getElementById('turnstile-enabled').checked = false;
      document.getElementById('turnstile-enabled').disabled = true;
      document.getElementById('ts-step-2').classList.remove('done');
      document.getElementById('ts-step-3').classList.remove('done');
      const hint = document.getElementById('turnstile-toggle-hint');
      if (hint) hint.textContent = '密钥已修改，请先点击「保存配置」，保存后完成自测再开启。';
      const status = document.getElementById('turnstile-status');
      status.className = 'badge badge-amber';
      status.innerHTML = '<i data-lucide="rotate-cw"></i>已修改，需保存后重新自测';
      document.getElementById('turnstile-config-widget').hidden = true;
      resetTurnstileWidget();
      refreshIcons();
    }));

    document.getElementById('turnstile-toggle-row')?.addEventListener('click', (e) => {
      const toggle = document.getElementById('turnstile-enabled');
      if (!toggle || !toggle.disabled || state.turnstileSaving) return;
      e.preventDefault();
      if (state.turnstileDirty) {
        toast('密钥已修改，请先点击「保存配置」', 'warn');
        document.querySelector('#turnstile-form button[type="submit"]')?.focus();
        return;
      }
      const hasKeys = Boolean(state.turnstile?.site_key && state.turnstile?.secret_set);
      toast(hasKeys ? '请先完成上方 Cloudflare 验证并点击「执行配置自测」，自测通过后即可开启' : '请先填写并保存 Site key 和 Secret key', 'warn');
      const target = hasKeys ? document.getElementById('turnstile-test') : document.getElementById('turnstile-site-key');
      target?.focus();
    });

    document.getElementById('turnstile-enabled')?.addEventListener('change', async (e) => {
      const toggle = e.currentTarget;
      if (toggle.disabled || state.turnstileSaving) return;
      const error = document.getElementById('turnstile-error');
      error.hidden = true;
      state.turnstileSaving = true;
      toggle.disabled = true;
      try {
        const updated = await saveTurnstile(toggle.checked);
        toast(updated.enabled ? '已启用登录页人机验证' : '已关闭登录页人机验证');
      } catch (failure) {
        toggle.checked = Boolean(state.turnstile?.enabled);
        error.textContent = failure?.message || '切换 Turnstile 状态失败';
        error.hidden = false;
      } finally {
        state.turnstileSaving = false;
        toggle.disabled = !state.turnstile?.tested;
      }
    });

    document.getElementById('turnstile-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const error = document.getElementById('turnstile-error');
      error.hidden = true;
      const submit = e.currentTarget.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const saved = await saveTurnstile();
        toast(saved.tested ? 'Turnstile 配置已保存' : '密钥已保存，请完成上方验证并点击「执行配置自测」');
      } catch (failure) {
        error.textContent = String(failure?.message || '').includes('self-test') ? '请先保存关闭状态的密钥，再完成上方配置自测' : (failure?.message || 'Turnstile 配置无效');
        error.hidden = false;
      } finally { submit.disabled = false; }
    });

    document.getElementById('turnstile-test').addEventListener('click', async (e) => {
      const error = document.getElementById('turnstile-error');
      error.hidden = true;
      if (!state.turnstile?.site_key || !state.turnstile?.secret_set || !state.turnstile?.hostname) {
        error.textContent = '请先填写并保存 Site key 和 Secret key'; error.hidden = false; return;
      }
      if (document.getElementById('turnstile-site-key').value.trim() !== state.turnstile.site_key || document.getElementById('turnstile-secret').value.trim()) {
        error.textContent = '密钥已修改，请先点击「保存配置」'; error.hidden = false; return;
      }
      if (!state.turnstileToken) {
        error.textContent = '请先完成上方 Cloudflare 验证组件'; error.hidden = false; return;
      }
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        renderTurnstile(await api('/_admin/api/turnstile/test', jsonOptions('POST', { token: state.turnstileToken })));
        toast('配置自测通过，现在可点击开关开启登录人机验证');
      } catch (failure) {
        error.textContent = failure?.message || '配置自测失败，请确认 Site key、Secret key 及绑定域名正确';
        error.hidden = false;
        if (!mountTurnstileConfigWidget()) waitForTurnstileConfigWidget();
      } finally { btn.disabled = false; }
    });

    document.getElementById('new-password').addEventListener('input', updatePasswordFormChecks);
    document.getElementById('confirm-password').addEventListener('input', updatePasswordFormChecks);
    document.getElementById('password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = e.currentTarget;
      const current = document.getElementById('current-password');
      const next = document.getElementById('new-password');
      const confirm = document.getElementById('confirm-password');
      const error = document.getElementById('password-error');
      error.hidden = true;
      if (!form.reportValidity()) return;
      if (next.value.length < 12 || utf8ByteLength(next.value) > 72) {
        error.textContent = '新密码需至少 12 个字符且不超过 72 字节';
        error.hidden = false;
        return;
      }
      if (next.value !== confirm.value) { error.textContent = '两次输入的新密码不一致'; error.hidden = false; return; }
      const submit = form.querySelector('button[type="submit"]');
      if (submit) submit.disabled = true;
      try {
        await api('/_admin/api/password', jsonOptions('POST', { current_password: current.value, new_password: next.value }));
        window.location.replace('/login');
      } catch (failure) {
        error.textContent = failure.message === 'current password is incorrect' ? '当前密码不正确' :
          failure.message.includes('72') ? '新密码需至少 12 个字符且不超过 72 字节' : '密码更新失败';
        error.hidden = false;
      } finally {
        if (submit) submit.disabled = false;
      }
    });

    // Edge Nodes & Controller Slim Events
    document.getElementById('runtime-public-portal')?.addEventListener('change', (e) => togglePublicPortal(e.currentTarget));
    document.getElementById('overview-export-btn')?.addEventListener('click', () => {
      const kind = document.getElementById('overview-export-kind')?.value || 'traffic';
      const link = document.createElement('a');
      link.href = `/_admin/api/reports/export?period=${encodeURIComponent(state.overviewPeriod)}&kind=${encodeURIComponent(kind)}`;
      link.download = '';
      document.body.append(link);
      link.click();
      link.remove();
      toast('已开始导出 CSV 报表', 'info');
    });
    document.getElementById('watching-search')?.addEventListener('input', (e) => {
      state.watchingQuery = e.currentTarget.value;
      renderWatching({ summary: state.watchingSummary, active: state.watchingActive, history: state.watchingHistory });
    });
    document.getElementById('node-scope-select').addEventListener('change', (e) => {
      state.nodeScope = e.currentTarget.value;
      refreshDashboard().catch(() => {});
      refreshLive();
      if (state.view === 'watching' || state.view === 'overview') refreshWatching().catch(() => {});
      if (state.view === 'connections') refreshConnections().catch(() => {});
      if (state.view === 'requests') refreshRequests(1).catch(() => {});
    });
    document.getElementById('nodes-discovery-btn')?.addEventListener('click', openDiscoveryDialog);
    document.getElementById('nodes-upgrade-all-btn')?.addEventListener('click', (e) => upgradeAllOnlineNodes(e.currentTarget));
    document.getElementById('nodes-add-btn').addEventListener('click', openNodeDrawerForCreate);
    document.getElementById('nodes-empty-add-btn').addEventListener('click', openDiscoveryDialog);

    // Cluster Discovery Modal Events
    const discDialog = document.getElementById('discovery-dialog');
    document.getElementById('discovery-dialog-close')?.addEventListener('click', () => discDialog.close());
    document.getElementById('disc-done-btn')?.addEventListener('click', () => discDialog.close());
    discDialog?.addEventListener('click', (e) => { if (e.target === discDialog) discDialog.close(); });
    document.querySelectorAll('#disc-tabs button').forEach((btn) => btn.addEventListener('click', () => renderDiscoveryTab(btn.dataset.discTab)));
    document.getElementById('disc-copy-cmd')?.addEventListener('click', () => copyPlainText(document.getElementById('disc-code-content').textContent, '集群一键接入命令已复制'));
    document.getElementById('disc-save-btn')?.addEventListener('click', (e) => saveDiscoverySettings(e.currentTarget));
    document.getElementById('disc-rotate-btn')?.addEventListener('click', (e) => rotateDiscoveryToken(e.currentTarget));

    // Managed Edge Domains Events
    document.getElementById('domains-add-btn')?.addEventListener('click', openDomainDrawerForCreate);
    document.getElementById('domains-empty-add-btn')?.addEventListener('click', openDomainDrawerForCreate);
    document.getElementById('domain-flow-quick-add')?.addEventListener('click', openDomainDrawerForCreate);
    document.getElementById('domain-flow-go-nodes')?.addEventListener('click', () => switchView('nodes'));
    document.getElementById('domain-go-nodes-btn')?.addEventListener('click', () => {
      closeDrawer('domain-drawer');
      switchView('nodes');
    });
    document.getElementById('domain-go-waf-btn')?.addEventListener('click', () => {
      closeDrawer('domain-drawer');
      switchView('rules');
    });

    // Visual WAF DAG Rules Events
    document.getElementById('waf-create-btn')?.addEventListener('click', () => wafEditor.openForCreate('blank'));
    document.querySelectorAll('[data-waf-quick-tpl]').forEach((btn) => {
      btn.addEventListener('click', () => wafEditor.openForCreate(btn.dataset.wafQuickTpl));
    });
    document.querySelectorAll('[data-waf-add-node]').forEach((btn) => {
      btn.addEventListener('pointerdown', (ev) => {
        if (ev.pointerType === 'touch' || window.matchMedia('(max-width: 980px)').matches) return;
        wafEditor.startPaletteDrag(btn.dataset.wafAddNode, btn, ev);
      });
      // Keyboard Enter/Space always adds; narrow screens or touch devices also support tap-to-add
      btn.addEventListener('click', (ev) => {
        if (ev.detail === 0 || window.matchMedia('(max-width: 980px), (pointer: coarse)').matches) {
          wafEditor.addNode(btn.dataset.wafAddNode);
        }
      });
    });
    document.getElementById('waf-template-select')?.addEventListener('change', (e) => {
      const val = e.currentTarget.value;
      if (val) {
        wafEditor.applyTemplate(val);
        e.currentTarget.value = '';
      }
    });
    document.getElementById('waf-auto-layout-btn')?.addEventListener('click', () => wafEditor.autoLayout());
    document.getElementById('waf-zoom-in')?.addEventListener('click', () => wafEditor.zoomAt(wafEditor.zoom * 1.15));
    document.getElementById('waf-zoom-out')?.addEventListener('click', () => wafEditor.zoomAt(wafEditor.zoom / 1.15));
    document.getElementById('waf-zoom-fit')?.addEventListener('click', () => wafEditor.fitView());
    document.getElementById('waf-sim-toggle-btn')?.addEventListener('click', () => {
      const bar = document.getElementById('waf-sim-bar');
      if (!bar) return;
      bar.hidden = !bar.hidden;
      if (bar.hidden) { wafEditor.clearTrace(); wafEditor.render(); }
    });
    document.getElementById('waf-sim-close-btn')?.addEventListener('click', () => {
      const bar = document.getElementById('waf-sim-bar');
      if (bar) bar.hidden = true;
      wafEditor.clearTrace();
      wafEditor.render();
    });
    document.getElementById('waf-sim-run-btn')?.addEventListener('click', () => wafEditor.runSimulation());
    document.getElementById('waf-save-btn')?.addEventListener('click', () => wafEditor.save());
    document.querySelectorAll('[data-go-cf-settings]').forEach((btn) => btn.addEventListener('click', () => {
      closeDrawer('domain-drawer');
      openDNSHubTab('providers');
    }));
    document.querySelectorAll('[data-go-axisnow-settings]').forEach((btn) => btn.addEventListener('click', () => {
      closeDrawer('domain-drawer');
      openDNSHubTab('providers');
    }));
    document.querySelectorAll('[data-go-dns-tab]').forEach((btn) => btn.addEventListener('click', () => {
      openDNSHubTab(btn.dataset.goDnsTab || 'profiles');
    }));
    document.querySelectorAll('[data-dns-jump]').forEach((btn) => btn.addEventListener('click', () => {
      setDNSHubTab(btn.dataset.dnsJump || 'providers');
    }));
    document.querySelectorAll('#dns-hub-tabs button').forEach((btn) => btn.addEventListener('click', () => {
      setDNSHubTab(btn.dataset.dnsTab || 'profiles');
    }));
    document.getElementById('domain-go-dns-profiles-btn')?.addEventListener('click', () => {
      closeDrawer('domain-drawer');
      openDNSHubTab('profiles');
    });
    document.getElementById('domain-smart-create-jump')?.addEventListener('click', async () => {
      closeDrawer('domain-drawer');
      await openDNSHubTab('profiles');
      await refreshSmartDNSProfiles().catch(() => {});
      openDNSProfileDrawer({ preset: 'cn3' });
    });
    document.getElementById('domain-smart-routing-host')?.addEventListener('input', (ev) => {
      if (state.domainSmartDNSDraft) state.domainSmartDNSDraft.routing_domain_host = ev.currentTarget.value.trim();
    });
    document.getElementById('domain-smart-auto-cf-cname')?.addEventListener('change', (ev) => {
      if (state.domainSmartDNSDraft) state.domainSmartDNSDraft.auto_cf_cname = ev.currentTarget.checked;
    });

    // Dedicated DNS & Routing Hub Events
    document.getElementById('dns-create-profile-btn')?.addEventListener('click', () => openDNSProfileDrawer({}));
    document.getElementById('dns-quick-cn3-btn')?.addEventListener('click', () => openDNSProfileDrawer({ preset: 'cn3' }));
    document.getElementById('dns-empty-cn3-btn')?.addEventListener('click', () => openDNSProfileDrawer({ preset: 'cn3' }));
    document.getElementById('dns-empty-geo-btn')?.addEventListener('click', () => openDNSProfileDrawer({ preset: 'geo' }));
    document.getElementById('dns-profile-form')?.addEventListener('submit', saveDNSProfile);
    document.getElementById('dns-prof-provider')?.addEventListener('change', (ev) => {
      if (!state.dnsProfileDraft) return;
      const val = ev.currentTarget.value;
      if (!val) {
        state.dnsProfileDraft.provider_uuid = '';
        state.dnsProfileDraft.provider_source = 'platform';
        state.dnsProfileDraft.provider_type = state.domainsAxisNowProviderType || 'alibaba-cloud';
        state.dnsProfileDraft.zone_uuid = '';
        state.dnsProfileDraft.zone_name = '';
        state.dnsProfileDraft.zone_plan = '';
      } else {
        const picked = buildAxisNowProviderChoices(state.domainsAxisNowProviders).find((c) => c.key === val);
        if (picked) {
          state.dnsProfileDraft.provider_uuid = picked.provider_uuid;
          state.dnsProfileDraft.provider_source = picked.provider_source;
          state.dnsProfileDraft.provider_type = picked.provider_type;
          state.dnsProfileDraft.zone_uuid = picked.zone_uuid;
          state.dnsProfileDraft.zone_name = picked.zone_name;
          state.dnsProfileDraft.zone_plan = picked.zone_plan;
          if (picked.provider_source === 'self-hosted') {
            state.dnsProfileDraft.auto_cf_cname = false;
            const cfEl = document.getElementById('dns-prof-auto-cf');
            if (cfEl) cfEl.checked = false;
          }
        }
      }
      renderDNSProfileEditor();
    });
    document.getElementById('dns-prof-preset-cn3')?.addEventListener('click', () => {
      if (!state.dnsProfileDraft) return;
      state.dnsProfileDraft.lines = buildSmartDNSPresetLines('cn3', state.dnsProfileDraft.provider_type, []);
      if (!document.getElementById('dns-prof-name').value.trim()) document.getElementById('dns-prof-name').value = '中国三网优化';
      renderDNSProfileEditor();
      toast('已载入中国三网分流预设');
    });
    document.getElementById('dns-prof-preset-geo')?.addEventListener('click', () => {
      if (!state.dnsProfileDraft) return;
      state.dnsProfileDraft.lines = buildSmartDNSPresetLines('geo', state.dnsProfileDraft.provider_type, []);
      if (!document.getElementById('dns-prof-name').value.trim()) document.getElementById('dns-prof-name').value = '海内外就近分流';
      renderDNSProfileEditor();
      toast('已载入海内外分流预设');
    });
    document.getElementById('dns-prof-add-line')?.addEventListener('click', () => {
      const draft = state.dnsProfileDraft;
      if (!draft) return;
      const used = new Set(draft.lines.map((l) => l.geo_isp));
      const cat = getGeoISPOptionsForProvider(draft.provider_type);
      let nextGeo = '';
      let nextLabel = '新线路';
      for (const grp of cat.groups) {
        const hit = grp.items.find((it) => it.value !== 'default' && !used.has(it.value));
        if (hit) { nextGeo = hit.value; nextLabel = hit.label; break; }
      }
      draft.lines.push({
        id: '',
        geo_isp: nextGeo || 'telecom',
        label: nextLabel,
        node_ids: (state.nodesData || []).slice(0, 1).map((n) => n.id),
        election_strategy: 'priority_order',
        ip_quantity: 1,
        auto_pause_on_empty: true,
        enabled: true
      });
      renderDNSProfileEditor();
    });
    const dnsBindDlg = document.getElementById('dns-bind-dialog');
    document.getElementById('dns-bind-close')?.addEventListener('click', () => dnsBindDlg?.close());
    document.getElementById('dns-bind-cancel')?.addEventListener('click', () => dnsBindDlg?.close());
    dnsBindDlg?.addEventListener('click', (e) => { if (e.target === dnsBindDlg) dnsBindDlg.close(); });
    document.getElementById('dns-bind-submit')?.addEventListener('click', saveDNSBindDomains);
    document.getElementById('domains-search')?.addEventListener('input', (e) => {
      state.domainsQuery = e.currentTarget.value;
      renderDomains({ domains: state.domainsData, summary: state.domainsSummary, cf_enabled: state.domainsCFEnabled, cf_root_domain: state.domainsCFRoot });
    });
    document.querySelectorAll('#domains-filter button').forEach((btn) => btn.addEventListener('click', () => {
      state.domainsFilter = btn.dataset.domainFilter;
      document.querySelectorAll('#domains-filter button').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('active', active);
        b.setAttribute('aria-pressed', String(active));
      });
      syncSegmented(document.getElementById('domains-filter'));
      renderDomains({ domains: state.domainsData, summary: state.domainsSummary, cf_enabled: state.domainsCFEnabled, cf_root_domain: state.domainsCFRoot });
    }));
    document.getElementById('domain-form')?.addEventListener('submit', saveEdgeDomain);
    document.getElementById('domain-form')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.repeat && !e.isComposing && !state.domainEditingID && state.domainWizardStep < 3) {
        const tag = (e.target?.tagName || '').toLowerCase();
        if (tag === 'input' && e.target.type !== 'checkbox' && e.target.type !== 'radio') {
          e.preventDefault();
          e.stopPropagation();
          if (Date.now() - (state.domainStepAdvanceAt || 0) > 300) {
            state.domainStepAdvanceAt = Date.now();
            setDomainWizardStep(state.domainWizardStep + 1);
          }
        }
      }
    });
    document.getElementById('domain-host')?.addEventListener('input', updateDomainHostPreview);
    document.querySelectorAll('#domain-wizard-steps .domain-wizard-tab').forEach((btn) => {
      btn.addEventListener('click', () => setDomainWizardStep(Number(btn.dataset.domainStep)));
    });
    document.getElementById('domain-step-prev')?.addEventListener('click', () => {
      setDomainWizardStep(state.domainWizardStep - 1, { skipValidate: true });
    });
    document.getElementById('domain-step-next')?.addEventListener('click', () => {
      setDomainWizardStep(state.domainWizardStep + 1);
    });
    document.querySelectorAll('input[name="domain-tls-mode"], input[name="domain-dns-mode"]').forEach((radio) => {
      radio.addEventListener('change', updateDomainStep3UI);
    });
    document.getElementById('domain-ov-speed')?.addEventListener('input', () => {
      const v = (document.getElementById('domain-ov-speed')?.value || '').trim();
      const ph = v !== '' ? (Number(v) > 0 ? `跟随域名 (${v}M)` : '跟随域名 (不限)') : '跟随本域名';
      document.querySelectorAll('[data-domain-node-speed]').forEach((inp) => { inp.placeholder = ph; });
      updateDomainStep3UI();
    });
    document.getElementById('domain-ov-ip-conc')?.addEventListener('input', updateDomainStep3UI);
    document.getElementById('domain-cdn-mode')?.addEventListener('change', updateDomainStep3UI);
    document.getElementById('domain-ov-trusted-cidrs')?.addEventListener('input', syncDomainCDNUI);
    document.getElementById('domain-ov-real-ip-header')?.addEventListener('change', updateDomainStep3UI);
    document.getElementById('domain-cdn-preset-cf')?.addEventListener('click', () => appendDomainCDNCIDRs(DOMAIN_CDN_CF_CIDRS));
    document.getElementById('domain-cdn-preset-lan')?.addEventListener('click', () => appendDomainCDNCIDRs(DOMAIN_CDN_LAN_CIDRS));
    document.getElementById('domain-cdn-preset-clear')?.addEventListener('click', () => {
      const ta = document.getElementById('domain-ov-trusted-cidrs');
      if (ta) ta.value = '';
      syncDomainCDNUI();
    });
    document.getElementById('domain-node-add-all-btn')?.addEventListener('click', () => {
      const onlineIDs = state.nodesData.filter((n) => n.status === 'online').map((n) => n.id);
      const targets = onlineIDs.length ? onlineIDs : state.nodesData.map((n) => n.id);
      targets.forEach((id) => {
        if (!state.domainBoundNodeIDs.includes(id)) state.domainBoundNodeIDs.push(id);
      });
      renderDomainNodePicker();
    });
    document.getElementById('domain-node-clear-btn')?.addEventListener('click', () => {
      state.domainBoundNodeIDs = [];
      renderDomainNodePicker();
    });

    // AxisNow Smart DNS Events
    document.getElementById('axisnow-dns-form')?.addEventListener('submit', saveAxisNowDNS);
    document.getElementById('axisnow-dns-test-btn')?.addEventListener('click', (e) => testAxisNowDNS(e.currentTarget));
    document.getElementById('axisnow-dns-sync-btn')?.addEventListener('click', (e) => syncAxisNowDNSNow(e.currentTarget));
    document.getElementById('axisnow-meta-refresh-btn')?.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      btn.disabled = true;
      try {
        const meta = await ensureAxisNowMetadata(true);
        renderAxisNowDNS(state.axisnowDNS, { preserveInputs: true });
        toast(meta?.source === 'live' ? '已刷新 AxisNow 最新线路字典' : '已加载内置常用线路字典（连通 AxisNow 后将同步全量）');
      } finally {
        btn.disabled = false;
      }
    });

    // Cloudflare DNS & Failover Events
    document.getElementById('cf-dns-form')?.addEventListener('submit', saveCloudflareDNS);
    document.getElementById('cf-dns-test-btn')?.addEventListener('click', (e) => testCloudflareDNS(e.currentTarget));
    document.getElementById('cf-dns-sync-btn')?.addEventListener('click', (e) => syncCloudflareDNSNow(e.currentTarget));
    document.getElementById('cf-failover-add-btn')?.addEventListener('click', () => {
      state.cloudflareFailoverDraft = [
        ...(state.cloudflareFailoverDraft || []),
        { id: '', name: '', hostname: '', node_ids: [], ip_mode: 'auto' }
      ];
      renderFailoverGroupsList();
    });
    document.getElementById('nodes-search').addEventListener('input', (e) => {
      state.nodesQuery = e.currentTarget.value;
      renderNodes({ role: state.role, nodes: state.nodesData, summary: state.nodesSummary });
    });
    document.querySelectorAll('#nodes-status-filter button').forEach((btn) => btn.addEventListener('click', () => {
      state.nodesFilter = btn.dataset.nodeFilter;
      document.querySelectorAll('#nodes-status-filter button').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('active', active);
        b.setAttribute('aria-pressed', String(active));
      });
      syncSegmented(document.getElementById('nodes-status-filter'));
      renderNodes({ role: state.role, nodes: state.nodesData, summary: state.nodesSummary });
    }));
    document.getElementById('node-form').addEventListener('submit', saveEdgeNode);
    document.querySelectorAll('#deploy-tabs button').forEach((btn) => btn.addEventListener('click', () => renderDeployTab(btn.dataset.deployTab)));
    document.getElementById('deploy-copy-cmd').addEventListener('click', () => copyPlainText(document.getElementById('deploy-code-content').textContent, '部署命令已复制'));
    document.querySelectorAll('[data-copy-target]').forEach((btn) => btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.copyTarget);
      if (target) copyPlainText(target.textContent, 'Token 已复制');
    }));
    const deployDialog = document.getElementById('node-deploy-dialog');
    document.getElementById('node-deploy-close').addEventListener('click', () => deployDialog.close());
    document.getElementById('node-deploy-done').addEventListener('click', () => deployDialog.close());
    deployDialog.addEventListener('click', (e) => { if (e.target === deployDialog) deployDialog.close(); });

    // Modals: Version, Command Palette, Confirm, Quota
    document.getElementById('update-button').addEventListener('click', openVersionDialog);
    document.getElementById('version-update-button').addEventListener('click', startPanelUpdate);
    document.getElementById('version-dialog-close').addEventListener('click', () => document.getElementById('version-dialog').close());
    document.getElementById('version-dialog').addEventListener('click', (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); });
    document.getElementById('copy-recovery-command').addEventListener('click', () => {
      copyPlainText(document.getElementById('update-recovery-command').textContent, '修复命令已复制');
    });

    document.getElementById('command-button').addEventListener('click', openCommandPalette);
    document.getElementById('command-close').addEventListener('click', closeCommandPalette);
    document.getElementById('command-input').addEventListener('input', (e) => filterCommandItems(e.currentTarget.value));
    document.getElementById('command-input').addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); closeCommandPalette(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); highlightCommandItem(state.commandFocusIndex + 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); highlightCommandItem(state.commandFocusIndex - 1); }
      else if (e.key === 'Enter') {
        const items = visibleCommandItems();
        const chosen = items[state.commandFocusIndex] || items[0];
        if (chosen) { e.preventDefault(); chosen.click(); }
      }
    });
    document.querySelectorAll('[data-command-view]').forEach((b) => b.addEventListener('click', () => switchView(b.dataset.commandView)));
    document.querySelectorAll('[data-command-action]').forEach((b) => b.addEventListener('click', () => runCommandAction(b.dataset.commandAction)));
    document.getElementById('command-dialog').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeCommandPalette(); });

    document.getElementById('confirm-cancel').addEventListener('click', () => settleConfirmation(false));
    document.getElementById('confirm-accept').addEventListener('click', () => settleConfirmation(true));
    document.getElementById('confirm-dialog').addEventListener('cancel', (e) => { e.preventDefault(); settleConfirmation(false); });
    document.getElementById('confirm-dialog').addEventListener('close', () => settleConfirmation(false));
    document.getElementById('confirm-dialog').addEventListener('click', (e) => { if (e.target === e.currentTarget) settleConfirmation(false); });

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openCommandPalette(); }
      if ((e.key === 'Delete' || e.key === 'Backspace') && document.getElementById('waf-editor-drawer')?.classList.contains('open')) {
        const tag = (e.target?.tagName || '').toLowerCase();
        if (tag !== 'input' && tag !== 'textarea' && tag !== 'select' && !e.target?.isContentEditable) {
          if (wafEditor.selectedEdgeID) {
            e.preventDefault();
            wafEditor.removeEdge(wafEditor.selectedEdgeID);
            return;
          }
          if (wafEditor.selectedNodeID) {
            const n = wafEditor.nodes.find((item) => item.id === wafEditor.selectedNodeID);
            if (n && n.type !== 'start') {
              e.preventDefault();
              wafEditor.removeNode(n.id);
              return;
            }
          }
        }
      }
      if (e.key === 'Tab' && !document.querySelector('dialog[open]')) {
        const openDrawers = [...document.querySelectorAll('.drawer-root.open')];
        const topDrawer = openDrawers[openDrawers.length - 1];
        if (topDrawer) {
          const panel = topDrawer.querySelector('.drawer-panel');
          const focusables = panel
            ? [...panel.querySelectorAll('a[href], button:not(:disabled), input:not([type="hidden"]):not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])')]
              .filter((n) => n.offsetParent !== null && !n.classList.contains('cselect-native') && n.tabIndex >= 0)
            : [];
          if (focusables.length) {
            const first = focusables[0];
            const last = focusables[focusables.length - 1];
            if (e.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) {
              e.preventDefault();
              last.focus();
            } else if (!e.shiftKey && (document.activeElement === last || !panel.contains(document.activeElement))) {
              e.preventDefault();
              first.focus();
            }
          }
        }
      }
      if (e.key === 'Escape') {
        if (wafEditor.drag) { e.preventDefault(); wafEditor.cancelActiveDrag(); return; }
        if (cselectState.active) { e.preventDefault(); closeActiveCustomSelect(true); return; }
        if (document.getElementById('confirm-dialog').open) { e.preventDefault(); settleConfirmation(false); return; }
        if (document.querySelector('dialog[open]')) return;
        const openDrawers = [...document.querySelectorAll('.drawer-root.open')];
        if (openDrawers.length) {
          e.preventDefault();
          closeDrawer(openDrawers[openDrawers.length - 1].id);
          return;
        }
        setMobileSidebar(false);
      }
    });

    enhanceAllCustomSelects();
    performance.mark('panel-interactive');
    loadPanelScript('/_admin/assets/lucide.min.js').then(() => {
      refreshIcons();
      scheduleLayoutRefresh();
    }).catch(() => {});

    try {
      const session = await sessionRequest;
      state.role = session.role || 'standalone';
      state.publicPortalEnabled = session.public_portal_enabled !== false;
      document.getElementById('account-name').textContent = session.username;
      applyControllerRoleUI();
      renderUpdateStatus({ current_version: session.version, latest_version: session.version, update_available: false });
    } catch { return; }

    const initialRoute = resolveInitialRoute(state.role);
    const controllerHiddenViews = new Set(['targets', 'reports']);
    const currentViewDisallowed = state.role === 'controller' && (controllerHiddenViews.has(state.view) || (state.view === 'settings' && state.settingsSection === 'settings-security'));
    if (!state.userNavigatedBeforeSession || currentViewDisallowed) {
      if (initialRoute.dnsTab) {
        state.dnsHubTab = initialRoute.dnsTab;
        await switchView('dns');
      } else if (initialRoute.settingsSection) {
        state.settingsSection = initialRoute.settingsSection;
        await switchView('settings');
      } else {
        await switchView(initialRoute.view);
      }
    }

    refresh(false, false);
    refreshLive();
    refreshUpdateStatus().catch(() => { document.getElementById('update-button').title = '暂时无法检查更新'; });
    state.updateTimer = window.setInterval(() => { if (!document.hidden) refreshUpdateStatus().catch(() => {}); }, 10 * 60 * 1000);
    state.dashboardTimer = window.setInterval(() => { if (!document.hidden) refreshDashboard().catch(() => {}); }, 5000);
    state.liveTimer = window.setInterval(refreshLive, 1000);
    window.addEventListener('resize', () => {
      if (window.innerWidth > 860 && document.body.classList.contains('sidebar-open')) setMobileSidebar(false);
      scheduleLayoutRefresh();
    });
  }

  initialize();
})();
