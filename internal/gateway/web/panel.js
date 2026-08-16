(() => {
  'use strict';

  const state = {
    snapshot: null, geography: null, overviewPeriod: '24h', geoChart: null, geoMapPromise: null,
    view: 'overview', dashboardTimer: null, dashboardPromise: null, liveTimer: null, liveRefreshing: false, updateTimer: null,
    policy: null, telegram: null, turnstile: null, turnstileWidget: null, turnstileToken: '',
    report: null, reportPeriod: '24h', reportLiveChart: null, reportTrendChart: null, reportRegionChart: null,
    liveSeries: [], backups: null, update: null
  };
  let confirmResolver = null;
  const viewMeta = {
    overview: ['运行概览', '通用反代实时状态', 'layout-dashboard'],
    connections: ['实时连接', '当前客户端与传输状态', 'radio-tower'],
    targets: ['后端域名', '自动发现的公网目标', 'server'],
    requests: ['请求日志', '脱敏后的最近请求', 'scroll-text'],
    reports: ['统计报表', '趋势、排行与数据导出', 'chart-no-axes-combined'],
    rules: ['访问规则', '按域名后缀控制访问', 'shield-check'],
    audit: ['审计日志', '管理操作与登录记录', 'list-checks'],
    backups: ['备份恢复', '自动备份与 SQLite 快照', 'database-backup'],
    settings: ['系统设置', '通知、认证与强制防护', 'settings']
  };

  function formatBytes(value) {
    let size = Number(value) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let index = 0;
    while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
    return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
  }

  function formatNumber(value) { return new Intl.NumberFormat('zh-CN').format(Number(value) || 0); }
  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[character]);
  }
  function formatTime(seconds) { return new Date(Number(seconds) * 1000).toLocaleString('zh-CN', { hour12: false }); }
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

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function emptyList(container, text) { container.replaceChildren(el('p', 'empty-state', text)); }

  function renderUpdateStatus(status) {
    if (!status) return;
    state.update = status;
    const button = document.getElementById('update-button');
    const dot = document.getElementById('update-dot');
    const current = String(status.current_version || '');
    document.getElementById('current-version').textContent = current ? `Version ${current}` : 'Version';
    const available = Boolean(status.update_available);
    const updating = Boolean(status.updating);
    dot.hidden = !available || updating;
    button.classList.toggle('available', available && !updating);
    button.classList.toggle('updating', updating);
    button.disabled = !available || updating;
    if (updating) {
      button.title = `正在更新到 ${status.latest_version}`;
      button.setAttribute('aria-label', button.title);
    } else if (available && status.auto_update_supported) {
      button.title = `发现 Refract ${status.latest_version}，点击更新`;
      button.setAttribute('aria-label', button.title);
    } else if (available) {
      button.title = `发现 Refract ${status.latest_version}，当前部署不支持面板更新`;
      button.setAttribute('aria-label', button.title);
    } else {
      button.title = 'Refract 已是最新版本';
      button.setAttribute('aria-label', button.title);
    }
  }

  async function refreshUpdateStatus(force = false) {
    const status = await api(`/_admin/api/update${force ? '?force=1' : ''}`);
    renderUpdateStatus(status);
    return status;
  }

  async function waitForUpdatedVersion(version) {
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => window.setTimeout(resolve, 1500));
      try {
        const response = await fetch('/_admin/api/session', { credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) continue;
        const session = await response.json();
        if (session.version === version) {
          const view = state.view || 'overview';
          window.location.replace(`/panel?updated=${encodeURIComponent(version)}#${encodeURIComponent(view)}`);
          return;
        }
      } catch (failure) { /* The service is restarting. */ }
    }
    toast('更新任务仍在执行，请稍后刷新页面');
  }

  async function startPanelUpdate() {
    const status = state.update;
    if (!status?.update_available) return;
    if (!status.auto_update_supported) {
      toast('当前部署方式暂不支持面板自动更新');
      return;
    }
    const confirmed = await confirmAction({
      title: `更新到 Refract ${status.latest_version}`,
      message: '更新包会从官方 GitHub Release 下载并校验 SHA256。服务将短暂重启，失败时自动恢复当前版本。',
      confirmLabel: '立即更新',
      icon: 'circle-arrow-up'
    });
    if (!confirmed) return;
    const button = document.getElementById('update-button');
    button.disabled = true;
    try {
      const next = await api('/_admin/api/update', jsonOptions('POST', { version: status.latest_version }));
      renderUpdateStatus(next);
      toast(`正在更新到 Refract ${status.latest_version}`);
      await waitForUpdatedVersion(status.latest_version);
    } catch (failure) {
      button.disabled = false;
      toast('更新启动失败，请稍后重试');
      refreshUpdateStatus(true).catch(() => {});
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
    accept.classList.toggle('danger', danger);
    dialog.classList.toggle('danger', danger);
    window.lucide?.createIcons();
    return new Promise((resolve) => {
      confirmResolver = resolve;
      dialog.showModal();
      window.requestAnimationFrame(() => document.getElementById('confirm-cancel').focus());
    });
  }

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

  function domainActionButton(target) {
    const access = domainAction(target.domain);
    const label = access === 'block' ? '屏蔽' : '放行';
    const button = el('button', `domain-action-button ${access}`);
    button.type = 'button';
    button.title = `${label} ${target.domain}`;
    button.setAttribute('aria-label', `${label}域名 ${target.domain}`);
    const icon = document.createElement('i');
    icon.dataset.lucide = access === 'block' ? 'shield-ban' : 'shield-check';
    button.append(icon, el('span', '', label));
    button.addEventListener('click', () => updateDomainAccess(target.domain, access, button));
    return button;
  }

  function renderCompactTargets(targets) {
    const container = document.getElementById('overview-targets');
    if (!targets?.length) return emptyList(container, '暂无后端数据');
    const fragment = document.createDocumentFragment();
    targets.slice(0, 4).forEach((target) => {
      const row = el('div', 'compact-row compact-target-row');
      const copy = el('div');
      copy.append(el('strong', '', target.host), el('small', '', `${formatNumber(target.requests)} 次请求 · ${target.avg_latency_ms} ms`));
      const actions = el('div', 'target-actions');
      actions.append(el('span', 'target-traffic', formatBytes(target.bytes_out)), domainActionButton(target));
      row.append(copy, actions);
      fragment.append(row);
    });
    container.replaceChildren(fragment);
    window.lucide?.createIcons();
  }

  function renderCompactRequests(logs) {
    const container = document.getElementById('overview-requests');
    if (!logs?.length) return emptyList(container, '暂无请求记录');
    const fragment = document.createDocumentFragment();
    logs.slice(0, 4).forEach((log) => {
      const row = el('div', 'compact-row');
      const copy = el('div');
      copy.append(el('strong', '', log.host), el('small', '', `${log.method} ${log.path}`));
      row.append(copy, el('span', '', `${log.status} · ${log.duration_ms} ms`));
      fragment.append(row);
    });
    container.replaceChildren(fragment);
  }

  function renderTargets(targets) {
    const body = document.getElementById('targets-table');
    const empty = document.getElementById('targets-empty');
    document.getElementById('target-count').textContent = `${formatNumber(targets?.length)} 个后端`;
    if (!targets?.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    targets.forEach((target) => {
      const row = document.createElement('tr');
      const host = el('td', 'host-cell');
      host.append(el('strong', '', target.host), el('small', '', `最近活动 ${relativeTime(target.last_seen)}`));
      [host, el('td', '', formatNumber(target.requests)), el('td', '', formatBytes(target.bytes_out)),
        el('td', '', formatNumber(target.errors)), el('td', '', `${target.avg_latency_ms} ms`),
        el('td', '', formatTime(target.last_seen))].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
  }

  function renderRequests(logs, dropped) {
    const body = document.getElementById('requests-table');
    const empty = document.getElementById('requests-empty');
    document.getElementById('dropped-label').textContent = dropped ? `${formatNumber(dropped)} 条写入丢弃` : '无丢弃';
    if (!logs?.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    logs.forEach((log) => {
      const row = document.createElement('tr');
      const target = el('td', 'host-cell');
      target.append(el('strong', '', log.host), el('small', '', log.path));
      const status = el('span', `status-code${log.status >= 400 ? ' error' : ''}`, String(log.status));
      const statusCell = document.createElement('td');
      statusCell.append(status);
      [el('td', '', formatTime(log.timestamp)), el('td', 'method', log.method), target,
        el('td', '', log.category), statusCell, el('td', '', formatBytes(log.bytes_out)),
        el('td', '', `${log.duration_ms} ms`)].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
  }

  function renderConnections(payload) {
    const connections = payload?.connections || [];
    const body = document.getElementById('connections-table');
    const empty = document.getElementById('connections-empty');
    document.getElementById('connection-count').lastChild.textContent = `${formatNumber(connections.length)} 个连接`;
    if (!connections.length) {
      body.replaceChildren();
      empty.hidden = false;
      return;
    }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    connections.forEach((connection) => {
      const row = document.createElement('tr');
      const client = el('td', 'connection-client');
      client.append(el('strong', 'ip-address', connection.client_ip), el('small', '', connection.location || connection.user_agent || '位置查询中'));
      const target = el('td', 'connection-target');
      target.append(el('strong', '', connection.host), el('small', '', `${connection.method} ${connection.path}`));
      const actions = el('td');
      const actionGroup = el('div', 'connection-actions');
      actionGroup.append(domainActionButton({ domain: connection.domain }));
      const terminate = el('button', 'icon-button danger-icon');
      terminate.type = 'button';
      terminate.title = '断开连接';
      terminate.setAttribute('aria-label', `断开 ${connection.client_ip} 到 ${connection.host} 的连接`);
      terminate.innerHTML = '<i data-lucide="square"></i>';
      terminate.addEventListener('click', () => terminateConnection(connection, terminate));
      actionGroup.append(terminate);
      actions.append(actionGroup);
      [client, target, el('td', 'connection-rate upload', `${formatBytes(connection.upload_bps)}/s`),
        el('td', 'connection-rate', `${formatBytes(connection.download_bps)}/s`),
        el('td', '', `${formatBytes(connection.upload_total)} / ${formatBytes(connection.download_total)}`),
        el('td', '', formatDuration(connection.duration_ms)), actions].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
    window.lucide?.createIcons();
  }

  async function refreshConnections() {
    renderConnections(await api('/_admin/api/connections'));
  }

  async function terminateConnection(connection, button) {
    const confirmed = await confirmAction({
      title: '断开当前连接',
      message: `${connection.client_ip} 到 ${connection.host} 的传输会立即终止。`,
      confirmLabel: '确认断开',
      icon: 'square',
      danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      await api(`/_admin/api/connections/${encodeURIComponent(connection.id)}`, { method: 'DELETE' });
      toast('连接已断开');
      await refreshConnections();
    } catch (failure) {
      button.disabled = false;
      toast(failure.message === 'connection not found' ? '连接已经结束' : '断开连接失败');
    }
  }

  function renderChart(points) {
    const canvas = document.getElementById('traffic-chart');
    const empty = document.getElementById('chart-empty');
    const context = canvas.getContext('2d');
    const ratio = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = Math.max(1, Math.floor(rect.width * ratio));
    canvas.height = Math.max(1, Math.floor(rect.height * ratio));
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.clearRect(0, 0, rect.width, rect.height);
    if (!points?.length) { empty.hidden = false; return; }
    empty.hidden = true;
    const style = getComputedStyle(document.documentElement);
    const muted = style.getPropertyValue('--muted').trim();
    const border = style.getPropertyValue('--border').trim();
    const accent = style.getPropertyValue('--accent').trim();
    const padding = { left: 38, right: 10, top: 12, bottom: 26 };
    const width = Math.max(1, rect.width - padding.left - padding.right);
    const height = Math.max(1, rect.height - padding.top - padding.bottom);
    const maxValue = Math.max(...points.map((item) => Number(item.bytes_out) || 0), 1);
    context.font = '11px ui-sans-serif, system-ui';
    context.lineWidth = 1;
    for (let line = 0; line <= 4; line += 1) {
      const y = padding.top + height * line / 4;
      context.strokeStyle = border;
      context.beginPath(); context.moveTo(padding.left, y); context.lineTo(padding.left + width, y); context.stroke();
      context.fillStyle = muted;
      context.textAlign = 'right';
      context.fillText(formatBytes(maxValue * (4 - line) / 4), padding.left - 7, y + 4);
    }
    const step = points.length > 1 ? width / (points.length - 1) : width;
    context.strokeStyle = accent;
    context.lineWidth = 2;
    context.beginPath();
    points.forEach((item, index) => {
      const x = padding.left + step * index;
      const y = padding.top + height - (Number(item.bytes_out) / maxValue) * height;
      if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
    });
    context.stroke();
    context.fillStyle = muted;
    context.textAlign = 'center';
    const labels = [0, Math.floor((points.length - 1) / 2), points.length - 1].filter((value, index, all) => all.indexOf(value) === index);
    labels.forEach((index) => {
      const time = new Date(points[index].timestamp * 1000).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false });
      context.fillText(time, padding.left + step * index, rect.height - 5);
    });
  }

  function analyticsPalette() {
    const style = getComputedStyle(document.documentElement);
    return {
      text: style.getPropertyValue('--text').trim(), muted: style.getPropertyValue('--muted').trim(),
      border: style.getPropertyValue('--border').trim(), panel: style.getPropertyValue('--panel').trim(),
      blue: style.getPropertyValue('--blue').trim(), green: style.getPropertyValue('--green').trim(),
      accent: style.getPropertyValue('--accent').trim(), amber: style.getPropertyValue('--amber').trim(),
      red: style.getPropertyValue('--red').trim()
    };
  }

  function reportChartBase(palette) {
    return {
      animation: false,
      textStyle: { color: palette.text, fontFamily: 'ui-sans-serif, system-ui', fontSize: 11 },
      tooltip: { trigger: 'axis', confine: true, transitionDuration: 0, backgroundColor: palette.panel, borderColor: palette.border, textStyle: { color: palette.text, fontSize: 11 } },
      legend: { top: 12, right: 14, textStyle: { color: palette.muted, fontSize: 10 }, itemWidth: 14, itemHeight: 7 },
      grid: { left: 62, right: 18, top: 48, bottom: 34 },
      xAxis: { type: 'category', boundaryGap: false, axisLine: { lineStyle: { color: palette.border } }, axisLabel: { color: palette.muted, fontSize: 10 }, axisTick: { show: false } },
      yAxis: { type: 'value', min: 0, splitNumber: 4, axisLabel: { color: palette.muted, fontSize: 10, formatter: (value) => formatBytes(value) }, splitLine: { lineStyle: { color: palette.border } } }
    };
  }

  function renderReportLiveChart() {
    const container = document.getElementById('report-live-chart');
    if (!container || state.view !== 'reports' || !window.echarts) return;
    if (!state.reportLiveChart) state.reportLiveChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const palette = analyticsPalette();
    const option = reportChartBase(palette);
    option.xAxis.data = state.liveSeries.map((point) => new Date(point.timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }));
    option.yAxis.axisLabel.formatter = (value) => `${formatBytes(value)}/s`;
    if (!state.liveSeries.some((point) => point.upload > 0 || point.download > 0)) {
      option.yAxis.max = 1;
      option.yAxis.splitNumber = 1;
    }
    option.tooltip.valueFormatter = (value) => `${formatBytes(value)}/s`;
    option.series = [
      { name: '上传', type: 'line', showSymbol: false, data: state.liveSeries.map((point) => point.upload), lineStyle: { width: 2, color: palette.green }, itemStyle: { color: palette.green } },
      { name: '下载', type: 'line', showSymbol: false, data: state.liveSeries.map((point) => point.download), lineStyle: { width: 2, color: palette.blue }, itemStyle: { color: palette.blue } }
    ];
    state.reportLiveChart.setOption(option, true);
  }

  function resizeReportCharts() {
    [state.reportLiveChart, state.reportTrendChart, state.reportRegionChart].forEach((chart) => chart?.resize());
  }

  function redrawReportCharts() {
    if (state.view !== 'reports') return;
    renderReportLiveChart();
    if (state.report) {
      renderReportTrendChart(state.report);
      renderReportRegionChart(state.report.regions);
    }
    requestAnimationFrame(resizeReportCharts);
  }

  function renderReportTrendChart(report) {
    const container = document.getElementById('report-trend-chart');
    if (!container || !window.echarts) return;
    if (!state.reportTrendChart) state.reportTrendChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const palette = analyticsPalette();
    const option = reportChartBase(palette);
    const points = report.timeline || [];
    const shortPeriod = Number(report.period_hours) <= 24;
    option.title = points.length ? undefined : { text: '暂无流量数据', left: 'center', top: 'middle', textStyle: { color: palette.muted, fontSize: 12, fontWeight: 400 } };
    option.xAxis.data = points.map((point) => new Date(point.timestamp * 1000).toLocaleString('zh-CN', shortPeriod ? { hour: '2-digit', minute: '2-digit', hour12: false } : { month: '2-digit', day: '2-digit' }));
    option.tooltip.valueFormatter = (value) => formatBytes(value);
    option.series = [
      { name: '上传', type: 'line', showSymbol: false, data: points.map((point) => Number(point.bytes_in) || 0), lineStyle: { width: 2, color: palette.green }, itemStyle: { color: palette.green } },
      { name: '下载', type: 'line', showSymbol: false, data: points.map((point) => Number(point.bytes_out) || 0), lineStyle: { width: 2, color: palette.blue }, itemStyle: { color: palette.blue } }
    ];
    state.reportTrendChart.setOption(option, true);
  }

  function renderReportRegionChart(regions) {
    const container = document.getElementById('report-region-chart');
    if (!container || !window.echarts) return;
    if (!state.reportRegionChart) state.reportRegionChart = window.echarts.init(container, null, { renderer: 'canvas' });
    const palette = analyticsPalette();
    const visible = (regions || []).slice(0, 9).map((region) => ({ name: region.label, value: Number(region.bytes_out) || 0 }));
    const remainder = (regions || []).slice(9).reduce((total, region) => total + (Number(region.bytes_out) || 0), 0);
    if (remainder > 0) visible.push({ name: '其他', value: remainder });
    state.reportRegionChart.setOption({
      animation: false,
      title: visible.length ? undefined : { text: '暂无地域数据', left: 'center', top: 'middle', textStyle: { color: palette.muted, fontSize: 12, fontWeight: 400 } },
      color: [palette.accent, palette.blue, palette.green, palette.amber, palette.red, '#06b6d4', '#ec4899', '#84cc16', '#64748b', '#a855f7'],
      tooltip: { trigger: 'item', confine: true, transitionDuration: 0, backgroundColor: palette.panel, borderColor: palette.border, textStyle: { color: palette.text, fontSize: 11 }, formatter: (params) => `${escapeHTML(params.name)}<br>${escapeHTML(formatBytes(params.value))} · ${escapeHTML(String(params.percent))}%` },
      legend: { type: 'scroll', orient: 'vertical', top: 'middle', right: 10, textStyle: { color: palette.muted, fontSize: 10 }, itemWidth: 12, itemHeight: 7 },
      series: [{ type: 'pie', radius: ['44%', '68%'], center: ['38%', '52%'], avoidLabelOverlap: true, itemStyle: { borderColor: palette.panel, borderWidth: 2 }, label: { show: false }, data: visible }]
    }, true);
  }

  function renderReport(report) {
    state.report = report;
    const labels = { '24h': '最近 24 小时', '7d': '最近 7 天', '30d': '最近 30 天', '90d': '最近 90 天' };
    document.getElementById('report-period-label').textContent = labels[state.reportPeriod];
    document.getElementById('report-trend-label').textContent = Number(report.period_hours) <= 24 ? '按小时聚合' : Number(report.period_hours) <= 168 ? '每 6 小时聚合' : '按天聚合';
    document.getElementById('report-requests').textContent = formatNumber(report.requests);
    document.getElementById('report-download').textContent = formatBytes(report.bytes_out);
    document.getElementById('report-upload').textContent = `上传 ${formatBytes(report.bytes_in)}`;
    document.getElementById('report-targets').textContent = formatNumber(report.targets_count);
    document.getElementById('report-errors').textContent = formatNumber(report.errors);
    const errorRate = Number(report.requests) > 0 ? Number(report.errors) / Number(report.requests) * 100 : 0;
    document.getElementById('report-error-rate').textContent = `错误率 ${errorRate.toFixed(errorRate >= 10 ? 0 : 1)}%`;

    const targetBody = document.getElementById('report-targets-table');
    const targetEmpty = document.getElementById('report-targets-empty');
    if (!report.top_targets?.length) { targetBody.replaceChildren(); targetEmpty.hidden = false; }
    else {
      targetEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      report.top_targets.forEach((target) => {
        const row = document.createElement('tr');
        [el('td', 'host-cell', target.host), el('td', '', formatNumber(target.requests)), el('td', '', formatBytes(target.bytes_out)),
          el('td', '', formatNumber(target.errors)), el('td', '', `${target.avg_latency_ms} ms`)].forEach((cell) => row.append(cell));
        fragment.append(row);
      });
      targetBody.replaceChildren(fragment);
    }

    const clientBody = document.getElementById('report-clients-table');
    const clientEmpty = document.getElementById('report-clients-empty');
    if (!report.top_clients?.length) { clientBody.replaceChildren(); clientEmpty.hidden = false; }
    else {
      clientEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      report.top_clients.forEach((client) => {
        const row = document.createElement('tr');
        [el('td', 'ip-address', client.ip), el('td', '', client.label || '未定位'), el('td', '', formatNumber(client.requests)),
          el('td', '', formatBytes(client.bytes_out)), el('td', 'peak-rate', `${formatBytes(client.peak_bps)}/s`)].forEach((cell) => row.append(cell));
        fragment.append(row);
      });
      clientBody.replaceChildren(fragment);
    }

    const regionBody = document.getElementById('report-regions-table');
    const regionEmpty = document.getElementById('report-regions-empty');
    if (!report.regions?.length) { regionBody.replaceChildren(); regionEmpty.hidden = false; }
    else {
      regionEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      report.regions.slice(0, 20).forEach((region) => {
        const row = document.createElement('tr');
        [el('td', '', region.label), el('td', '', formatNumber(region.unique_ips)), el('td', '', formatBytes(region.bytes_out)),
          el('td', 'peak-rate', `${formatBytes(region.peak_bps)}/s`)].forEach((cell) => row.append(cell));
        fragment.append(row);
      });
      regionBody.replaceChildren(fragment);
    }
    renderReportLiveChart();
    renderReportTrendChart(report);
    renderReportRegionChart(report.regions);
  }

  async function refreshReport() {
    renderReport(await api(`/_admin/api/reports?period=${encodeURIComponent(state.reportPeriod)}`));
  }

  function mapPalette() {
    const dark = document.documentElement.dataset.theme === 'dark';
    return dark ? {
      area: '#27272a', border: '#52525b', activeLow: '#323a66', activeHigh: '#8c85ff',
      point: '#60a5fa', pointBorder: '#bfdbfe', tooltip: '#18181b', tooltipText: '#fafafa', tooltipBorder: '#3f3f46'
    } : {
      area: '#e8edf4', border: '#b9c3d0', activeLow: '#c7d9ff', activeHigh: '#4f7df3',
      point: '#10b981', pointBorder: '#d1fae5', tooltip: '#ffffff', tooltipText: '#18181b', tooltipBorder: '#e4e4e7'
    };
  }

  async function ensureGeographyMap() {
    if (window.echarts?.getMap('refract-world')) return;
    if (!state.geoMapPromise) {
      state.geoMapPromise = Promise.all([
        fetch('/_admin/assets/world-geo.json', { credentials: 'same-origin' }).then((response) => {
          if (!response.ok) throw new Error('world map unavailable');
          return response.json();
        }),
        fetch('/_admin/assets/china-provinces.json', { credentials: 'same-origin' }).then((response) => {
          if (!response.ok) throw new Error('china map unavailable');
          return response.json();
        })
      ]).then(([world, china]) => {
        const features = (world.features || []).filter((feature) => feature?.properties?.name !== 'China');
        features.push(...(china.features || []));
        window.echarts.registerMap('refract-world', { type: 'FeatureCollection', features });
      }).catch((failure) => {
        state.geoMapPromise = null;
        throw failure;
      });
    }
    return state.geoMapPromise;
  }

  function renderGeographyMap() {
    const container = document.getElementById('geography-map');
    const empty = document.getElementById('geography-empty');
    if (!container || state.view !== 'overview') return;
    ensureGeographyMap().then(() => {
      if (!state.geoChart) state.geoChart = window.echarts.init(container, null, { renderer: 'canvas' });
      const geography = state.geography || { regions: [], ips: [] };
      const regions = geography.regions || [];
      const ips = geography.ips || [];
      const palette = mapPalette();
      const previousGeo = state.geoChart.getOption()?.geo?.[0] || {};
      const maximum = Math.max(1, ...regions.map((region) => Number(region.requests) || 0));
      const regionData = regions.map((region) => ({
        name: region.map_name,
        value: Number(region.requests) || 0,
        label: region.label,
        peak: Number(region.peak_bps) || 0,
        uniqueIPs: Number(region.unique_ips) || 0
      }));
      const ipData = ips.filter((item) => Number.isFinite(Number(item.latitude)) && Number.isFinite(Number(item.longitude))).map((item) => ({
        name: item.ip,
        value: [Number(item.longitude), Number(item.latitude), Number(item.peak_bps) || 0],
        label: item.label,
        requests: Number(item.requests) || 0,
        bytesOut: Number(item.bytes_out) || 0
      }));
      empty.hidden = ipData.length > 0;
      empty.textContent = ipData.length ? '' : '暂无已定位的请求来源';
      state.geoChart.setOption({
        animation: false,
        backgroundColor: 'transparent',
        tooltip: {
          trigger: 'item', confine: true, transitionDuration: 0,
          backgroundColor: palette.tooltip, borderColor: palette.tooltipBorder, borderWidth: 1,
          textStyle: { color: palette.tooltipText, fontSize: 12 },
          formatter: (params) => {
            const data = params.data || {};
            if (params.seriesType === 'scatter') {
              return `<strong>${escapeHTML(data.name)}</strong><br>${escapeHTML(data.label)}<br>最大下行 ${escapeHTML(formatBytes(data.value?.[2]))}/s<br>${escapeHTML(formatNumber(data.requests))} 次请求 · ${escapeHTML(formatBytes(data.bytesOut))}`;
            }
            if (!data.label) return escapeHTML(params.name || '');
            return `<strong>${escapeHTML(data.label)}</strong><br>${escapeHTML(formatNumber(data.value))} 次请求<br>${escapeHTML(formatNumber(data.uniqueIPs))} 个 IP · 最大 ${escapeHTML(formatBytes(data.peak))}/s`;
          }
        },
        visualMap: {
          show: false, min: 0, max: maximum, seriesIndex: 0,
          inRange: { color: [palette.activeLow, palette.activeHigh] }
        },
        geo: {
          map: 'refract-world', roam: true, zoom: Number(previousGeo.zoom) || 1.08, center: previousGeo.center || null,
          scaleLimit: { min: 0.75, max: 12 }, layoutCenter: ['50%', '50%'], layoutSize: '108%',
          itemStyle: { areaColor: palette.area, borderColor: palette.border, borderWidth: 0.65 },
          emphasis: { itemStyle: { areaColor: palette.activeLow, borderColor: palette.activeHigh } },
          select: { disabled: true }
        },
        series: [
          {
            name: '请求地域', type: 'map', map: 'refract-world', geoIndex: 0, data: regionData,
            selectedMode: false, emphasis: { disabled: false }
          },
          {
            name: '请求 IP', type: 'scatter', coordinateSystem: 'geo', data: ipData, z: 3,
            symbolSize: (value) => Math.max(7, Math.min(20, 7 + Math.log10((Number(value?.[2]) || 0) + 1) * 1.7)),
            itemStyle: { color: palette.point, borderColor: palette.pointBorder, borderWidth: 1.5, opacity: 0.9 },
            emphasis: { scale: 1.25 }
          }
        ]
      }, true);
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
    document.getElementById('geo-peak').textContent = `${formatBytes(regions[0]?.peak_bps)}/s`;
    document.getElementById('geo-peak-place').textContent = regions[0]?.label || '暂无数据';

    const top = document.getElementById('geo-top-regions');
    if (!regions.length) emptyList(top, '暂无地域数据');
    else {
      const fragment = document.createDocumentFragment();
      regions.slice(0, 5).forEach((region) => {
        const row = el('div', 'geo-top-row');
        row.append(el('span', '', region.label), el('strong', '', `${formatBytes(region.peak_bps)}/s`));
        fragment.append(row);
      });
      top.replaceChildren(fragment);
    }

    const regionBody = document.getElementById('regions-table');
    const regionEmpty = document.getElementById('regions-empty');
    document.getElementById('region-table-count').textContent = `${formatNumber(regions.length)} 个地域`;
    if (!regions.length) { regionBody.replaceChildren(); regionEmpty.hidden = false; }
    else {
      regionEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      regions.forEach((region) => {
        const row = document.createElement('tr');
        const place = el('td');
        const wrapper = el('span', 'geo-place');
        wrapper.append(el('i'), el('span', '', region.label));
        place.append(wrapper);
        [place, el('td', '', formatNumber(region.unique_ips)), el('td', '', formatNumber(region.requests)),
          el('td', '', formatBytes(region.bytes_out)), el('td', 'peak-rate', `${formatBytes(region.peak_bps)}/s`)].forEach((cell) => row.append(cell));
        fragment.append(row);
      });
      regionBody.replaceChildren(fragment);
    }

    const ipBody = document.getElementById('geo-ips-table');
    const ipEmpty = document.getElementById('geo-ips-empty');
    document.getElementById('ip-table-count').textContent = `${formatNumber(ips.length)} 个 IP`;
    if (!ips.length) { ipBody.replaceChildren(); ipEmpty.hidden = false; }
    else {
      ipEmpty.hidden = true;
      const fragment = document.createDocumentFragment();
      ips.forEach((item) => {
        const row = document.createElement('tr');
        [el('td', 'ip-address', item.ip), el('td', '', item.label), el('td', '', formatNumber(item.requests)),
          el('td', 'peak-rate', `${formatBytes(item.peak_bps)}/s`)].forEach((cell) => row.append(cell));
        fragment.append(row);
      });
      ipBody.replaceChildren(fragment);
    }
    renderGeographyMap();
  }

  async function refreshGeography() {
    const geography = await api(`/_admin/api/geography?period=${encodeURIComponent(state.overviewPeriod)}`);
    renderGeography(geography);
    return geography;
  }

  function zoomGeographyMap(factor) {
    if (!state.geoChart) return;
    state.geoChart.dispatchAction({
      type: 'geoRoam', componentType: 'geo', geoIndex: 0, zoom: factor,
      originX: state.geoChart.getWidth() / 2, originY: state.geoChart.getHeight() / 2
    });
  }

  function resetGeographyMap() {
    if (!state.geoChart) return;
    state.geoChart.setOption({ geo: { center: null, zoom: 1.08 } });
  }

  function renderTraffic24h(value) {
    document.getElementById('metric-traffic').textContent = formatBytes(value);
  }

  function overviewPeriodLabel() {
    return ({ '24h': '24 小时', '7d': '7 天', '30d': '30 天' })[state.overviewPeriod] || '24 小时';
  }

  function render(snapshot) {
    state.snapshot = snapshot;
    const periodLabel = overviewPeriodLabel();
    document.getElementById('metric-requests-label').textContent = `${periodLabel}请求`;
    document.getElementById('metric-traffic-label').textContent = `${periodLabel}下行`;
    document.getElementById('metric-targets-period').textContent = `最近 ${periodLabel}`;
    document.getElementById('overview-chart-period').textContent = `最近 ${periodLabel}`;
    document.getElementById('metric-requests').textContent = formatNumber(snapshot.requests_24h);
    document.getElementById('metric-active').textContent = `${formatNumber(snapshot.active_requests)} 个活跃连接`;
    renderTraffic24h(snapshot.bytes_out_24h);
    document.getElementById('metric-targets').textContent = formatNumber(snapshot.targets_24h);
    document.getElementById('metric-errors').textContent = formatNumber(snapshot.errors_24h);
    document.getElementById('metric-blocked').textContent = `${formatNumber(snapshot.blocked_total)} 次安全拦截`;
    document.getElementById('uptime-label').textContent = formatUptime(snapshot.uptime_seconds);
    document.getElementById('security-blocked').textContent = formatNumber(snapshot.blocked_total);
    document.getElementById('security-dropped').textContent = formatNumber(snapshot.dropped_logs);
    renderCompactTargets(snapshot.targets);
    renderCompactRequests(snapshot.recent);
    renderTargets(snapshot.targets);
    renderRequests(snapshot.recent, snapshot.dropped_logs);
    if (state.view === 'overview') renderChart(snapshot.timeline);
  }

  function renderLive(live) {
    state.liveSeries.push({
      timestamp: Date.now(),
      upload: Math.max(0, Number(live.upload_bps) || 0),
      download: Math.max(0, Number(live.download_bps) || 0)
    });
    if (state.liveSeries.length > 60) state.liveSeries.splice(0, state.liveSeries.length - 60);
    document.getElementById('live-upload').textContent = `${formatBytes(live.upload_bps)}/s`;
    document.getElementById('live-download').textContent = `${formatBytes(live.download_bps)}/s`;
    document.getElementById('live-upload-total').textContent = `本次运行 ${formatBytes(live.upload_total)}`;
    document.getElementById('live-download-total').textContent = `本次运行 ${formatBytes(live.download_total)}`;
    document.getElementById('metric-active').textContent = `${formatNumber(live.active_requests)} 个活跃连接`;
    if (state.view === 'reports') renderReportLiveChart();
  }

  function renderPolicy(policy) {
    state.policy = policy;
    const mode = ['blacklist', 'whitelist'].includes(policy.mode) ? policy.mode : 'off';
    document.querySelectorAll('input[name="policy-mode"]').forEach((input) => { input.checked = input.value === mode; });
    const action = mode === 'blacklist' ? 'deny' : mode === 'whitelist' ? 'allow' : '';
    const rules = (policy.rules || []).filter((rule) => rule.enabled !== false && rule.action === action);
    const modeLabel = mode === 'blacklist' ? '黑名单' : mode === 'whitelist' ? '白名单' : '关闭';
    const summary = mode === 'blacklist' ? `名单内禁止访问 · ${formatNumber(rules.length)} 个域名` :
      mode === 'whitelist' ? `仅名单内可以访问 · ${formatNumber(rules.length)} 个域名` : '全部域名放行 · 名单不参与匹配';
    document.getElementById('policy-summary').textContent = `${modeLabel} · ${summary}`;
    document.getElementById('rule-list-title').textContent = mode === 'off' ? '域名名单' : modeLabel;
    document.getElementById('rule-count').textContent = `${formatNumber(rules.length)} 个域名`;
    const domainInput = document.getElementById('rule-domain');
    const addButton = document.getElementById('rule-add');
    domainInput.disabled = mode === 'off';
    addButton.disabled = mode === 'off';
    addButton.querySelector('span').textContent = mode === 'blacklist' ? '加入黑名单' : mode === 'whitelist' ? '加入白名单' : '选择模式后添加';
    const body = document.getElementById('rules-table');
    const empty = document.getElementById('rules-empty');
    empty.textContent = mode === 'off' ? '选择黑名单或白名单模式后管理域名' : `${modeLabel}中暂无域名`;
    if (!rules.length) {
      body.replaceChildren();
      empty.hidden = false;
      if (state.snapshot) renderCompactTargets(state.snapshot.targets);
      return;
    }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    rules.forEach((rule) => {
      const row = document.createElement('tr');
      const domain = el('td', 'rule-domain', rule.domain_suffix);
      const action = document.createElement('td');
      const remove = el('button', 'icon-button danger-icon');
      remove.type = 'button';
      remove.title = '删除规则';
      remove.setAttribute('aria-label', '删除规则');
      remove.innerHTML = '<i data-lucide="trash-2"></i>';
      remove.addEventListener('click', () => deleteRule(rule.id));
      action.append(remove);
      [domain, el('td', '', formatTime(rule.created_at)), action].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
    window.lucide?.createIcons();
    if (state.snapshot) renderCompactTargets(state.snapshot.targets);
  }

  async function updateDomainAccess(domain, access, button) {
    button.disabled = true;
    try {
      const policy = await api('/_admin/api/rules/domain', jsonOptions('PUT', { domain, access }));
      renderPolicy(policy);
      toast(access === 'block' ? `${domain} 已屏蔽` : `${domain} 已放行`);
    } catch (failure) {
      button.disabled = false;
      toast('域名规则更新失败');
    }
  }

  async function deleteRule(id) {
    const confirmed = await confirmAction({
      title: '删除域名规则',
      message: '删除后，该域名将立即按照当前模式的默认策略处理。',
      confirmLabel: '确认删除',
      icon: 'trash-2',
      danger: true
    });
    if (!confirmed) return;
    try {
      renderPolicy(await api(`/_admin/api/rules/${id}`, { method: 'DELETE' }));
      toast('规则已删除');
    } catch (failure) { toast('规则删除失败'); }
  }

  const auditActionLabels = {
    'session.login': '管理员登录', 'session.logout': '退出登录', 'account.password': '修改密码',
    'policy.mode': '切换访问模式', 'policy.rule.create': '添加域名规则', 'policy.rule.delete': '删除域名规则',
    'policy.domain.quick': '快捷域名规则', 'connection.terminate': '断开实时连接',
    'telegram.settings': '修改 Telegram', 'telegram.test': '测试 Telegram',
    'backup.auto': '自动备份', 'backup.create': '创建备份', 'backup.import': '导入备份',
    'backup.restore': '恢复备份', 'backup.delete': '删除备份', 'backup.settings': '修改备份策略'
  };

  function renderAudit(payload) {
    const entries = payload?.entries || [];
    const body = document.getElementById('audit-table');
    const empty = document.getElementById('audit-empty');
    document.getElementById('audit-count').textContent = `${formatNumber(entries.length)} 条记录`;
    if (!entries.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    entries.forEach((entry) => {
      const row = document.createElement('tr');
      const result = el('span', `audit-result${entry.success ? '' : ' failed'}`, entry.success ? '成功' : '失败');
      const resultCell = document.createElement('td');
      resultCell.append(result);
      [el('td', '', formatTime(entry.timestamp)), el('td', '', entry.username || '未知'), el('td', 'ip-address', entry.client_ip || '-'),
        el('td', '', auditActionLabels[entry.action] || entry.action), el('td', '', entry.resource || '-'),
        el('td', '', entry.detail || '-'), resultCell].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
  }

  async function refreshAudit() {
    renderAudit(await api('/_admin/api/audit?limit=200'));
  }

  const backupKindLabels = { manual: '手动', auto: '自动', safety: '安全', import: '导入' };

  function renderBackups(snapshot) {
    state.backups = snapshot;
    const config = snapshot?.config || { enabled: true, hour: 3, retention: 7 };
    const files = snapshot?.files || [];
    document.getElementById('backup-enabled').checked = Boolean(config.enabled);
    document.getElementById('backup-hour').value = String(config.hour ?? 3);
    document.getElementById('backup-retention').value = String(config.retention ?? 7);
    document.getElementById('backup-next-run').textContent = snapshot?.next_run ? `下次 ${formatTime(snapshot.next_run)}` : '未安排下次备份';
    document.getElementById('backup-count').textContent = `${formatNumber(files.length)} 个备份`;
    const body = document.getElementById('backups-table');
    const empty = document.getElementById('backups-empty');
    if (!files.length) { body.replaceChildren(); empty.hidden = false; return; }
    empty.hidden = true;
    const fragment = document.createDocumentFragment();
    files.forEach((file) => {
      const row = document.createElement('tr');
      const actions = el('td');
      const group = el('div', 'backup-row-actions');
      const download = el('a', 'icon-button');
      download.href = `/_admin/api/backups/${encodeURIComponent(file.name)}/download`;
      download.title = '下载备份';
      download.setAttribute('aria-label', `下载备份 ${file.name}`);
      download.innerHTML = '<i data-lucide="download"></i>';
      const restore = el('button', 'icon-button');
      restore.type = 'button';
      restore.title = '恢复备份';
      restore.setAttribute('aria-label', `恢复备份 ${file.name}`);
      restore.innerHTML = '<i data-lucide="history"></i>';
      restore.addEventListener('click', () => restoreBackup(file, restore));
      const remove = el('button', 'icon-button danger-icon');
      remove.type = 'button';
      remove.title = '删除备份';
      remove.setAttribute('aria-label', `删除备份 ${file.name}`);
      remove.innerHTML = '<i data-lucide="trash-2"></i>';
      remove.addEventListener('click', () => deleteBackup(file, remove));
      group.append(download, restore, remove);
      actions.append(group);
      [el('td', 'backup-name', file.name), el('td', '', backupKindLabels[file.kind] || file.kind),
        el('td', '', formatBytes(file.size)), el('td', '', formatTime(file.created_at)), actions].forEach((cell) => row.append(cell));
      fragment.append(row);
    });
    body.replaceChildren(fragment);
    window.lucide?.createIcons();
  }

  async function refreshBackups() {
    renderBackups(await api('/_admin/api/backups'));
  }

  async function restoreBackup(file, button) {
    const confirmed = await confirmAction({
      title: '恢复数据库备份',
      message: `将恢复 ${file.name}，当前数据库会先自动创建安全快照。`,
      confirmLabel: '确认恢复',
      icon: 'history',
      danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      renderBackups(await api(`/_admin/api/backups/${encodeURIComponent(file.name)}/restore`, jsonOptions('POST', {})));
      toast('备份已恢复');
      await Promise.all([refresh(false), refreshAudit()]);
    } catch (failure) {
      button.disabled = false;
      toast('备份恢复失败');
    }
  }

  async function deleteBackup(file, button) {
    const confirmed = await confirmAction({
      title: '删除数据库备份',
      message: `${file.name} 删除后无法恢复。`,
      confirmLabel: '确认删除',
      icon: 'trash-2',
      danger: true
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      renderBackups(await api(`/_admin/api/backups/${encodeURIComponent(file.name)}/delete`, { method: 'DELETE' }));
      toast('备份已删除');
    } catch (failure) {
      button.disabled = false;
      toast('备份删除失败');
    }
  }

  function renderTelegram(config) {
    state.telegram = config;
    document.getElementById('telegram-enabled').checked = Boolean(config.enabled);
    document.getElementById('telegram-chat').value = config.chat_id || '';
    document.getElementById('telegram-hour').value = String(config.send_hour ?? 9);
    document.getElementById('telegram-token').value = '';
    document.getElementById('telegram-token-status').textContent = config.token_set ? 'Token 已加密保存，留空保持不变' : '尚未配置';
  }

  function resetTurnstileWidget() {
    if (state.turnstileWidget !== null && window.turnstile) {
      window.turnstile.remove(state.turnstileWidget);
    }
    state.turnstileWidget = null;
    state.turnstileToken = '';
    document.getElementById('turnstile-config-widget-slot')?.replaceChildren();
  }

  function mountTurnstileConfigWidget() {
    if (!state.turnstile?.site_key || !window.turnstile) return false;
    resetTurnstileWidget();
    document.getElementById('turnstile-config-widget').hidden = false;
    state.turnstileWidget = window.turnstile.render('#turnstile-config-widget-slot', {
      sitekey: state.turnstile.site_key,
      action: 'config_test',
      theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
      callback: (token) => { state.turnstileToken = token; },
      'expired-callback': () => { state.turnstileToken = ''; },
      'error-callback': () => { state.turnstileToken = ''; }
    });
    return true;
  }

  function waitForTurnstileConfigWidget() {
    if (mountTurnstileConfigWidget()) return;
    if (!state.turnstile?.site_key) return;
    window.setTimeout(waitForTurnstileConfigWidget, 150);
  }

  function renderTurnstile(config) {
    state.turnstile = config || { enabled: false, tested: false, site_key: '', hostname: '', secret_set: false };
    document.getElementById('turnstile-site-key').value = state.turnstile.site_key || '';
    document.getElementById('turnstile-secret').value = '';
    document.getElementById('turnstile-secret-status').textContent = state.turnstile.secret_set ? 'Secret key 已加密保存，留空保持不变' : '尚未配置';
    const enabled = document.getElementById('turnstile-enabled');
    enabled.checked = Boolean(state.turnstile.enabled);
    enabled.disabled = !state.turnstile.tested;
    const status = document.getElementById('turnstile-status');
    status.classList.toggle('muted-badge', !state.turnstile.enabled);
    status.innerHTML = `<i data-lucide="${state.turnstile.enabled ? 'shield-check' : state.turnstile.tested ? 'badge-check' : 'shield-off'}"></i>${state.turnstile.enabled ? '已启用' : state.turnstile.tested ? '已自测' : '未启用'}`;
    const widget = document.getElementById('turnstile-config-widget');
    widget.hidden = !state.turnstile.site_key;
    resetTurnstileWidget();
    if (state.turnstile.site_key) waitForTurnstileConfigWidget();
    window.lucide?.createIcons();
  }

  async function refreshTurnstile() {
    renderTurnstile(await api('/_admin/api/turnstile'));
  }

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

  async function refreshDashboard() {
    if (state.dashboardPromise) return state.dashboardPromise;
    const request = api(`/_admin/api/dashboard?period=${encodeURIComponent(state.overviewPeriod)}`).then((snapshot) => {
      render(snapshot);
      return snapshot;
    });
    state.dashboardPromise = request;
    try {
      return await request;
    } finally {
      if (state.dashboardPromise === request) state.dashboardPromise = null;
    }
  }

  async function refresh(showNotice = false) {
    const button = document.getElementById('refresh-button');
    if (showNotice) { button.disabled = true; button.querySelector('svg')?.classList.add('spinning'); }
    try {
      const [, policy, geography] = await Promise.all([
        refreshDashboard(),
        api('/_admin/api/policy'),
        api(`/_admin/api/geography?period=${encodeURIComponent(state.overviewPeriod)}`)
      ]);
      renderPolicy(policy);
      renderGeography(geography);
      if (state.view === 'requests') {
        const data = await api('/_admin/api/requests?limit=100');
        renderRequests(data.logs, data.dropped);
      }
      if (state.view === 'connections') await refreshConnections();
      if (state.view === 'reports') await refreshReport();
      if (state.view === 'audit') await refreshAudit();
      if (state.view === 'backups') await refreshBackups();
      if (showNotice) toast('数据已刷新');
    } catch (failure) {
      if (failure.message !== 'authentication required') toast('数据刷新失败');
    } finally {
      if (showNotice) { button.disabled = false; button.querySelector('svg')?.classList.remove('spinning'); }
    }
  }

  async function refreshLive() {
    if (state.liveRefreshing) return;
    state.liveRefreshing = true;
    try {
      const live = await api('/_admin/api/live');
      renderLive(live);
      if (state.view === 'connections') await refreshConnections();
    } catch (failure) { /* dashboard refresh handles session failures */ }
    finally { state.liveRefreshing = false; }
  }

  async function switchView(view) {
    if (!viewMeta[view]) return;
    state.view = view;
    document.querySelectorAll('.view').forEach((node) => node.classList.toggle('active', node.id === `view-${view}`));
    document.querySelectorAll('.nav-button').forEach((node) => node.classList.toggle('active', node.dataset.view === view));
    document.getElementById('page-title').textContent = viewMeta[view][0];
    document.getElementById('page-subtitle').textContent = viewMeta[view][1];
    document.getElementById('page-heading-icon').innerHTML = `<i data-lucide="${viewMeta[view][2]}"></i>`;
    window.history.replaceState(null, '', `/panel#${view}`);
    setMobileSidebar(false);
    closeCommandPalette();
    window.scrollTo({ top: 0, behavior: 'instant' });
    window.lucide?.createIcons();
    if (view === 'overview' && state.snapshot) requestAnimationFrame(() => {
      renderChart(state.snapshot.timeline);
      renderGeographyMap();
    });
    if (view === 'connections') refreshConnections().catch(() => toast('实时连接加载失败'));
    if (view === 'requests') api('/_admin/api/requests?limit=100').then((data) => renderRequests(data.logs, data.dropped)).catch(() => toast('日志加载失败'));
    if (view === 'reports') {
      refreshReport().catch(() => toast('统计报表加载失败'));
      requestAnimationFrame(redrawReportCharts);
    }
    if (view === 'rules') api('/_admin/api/policy').then(renderPolicy).catch(() => toast('规则加载失败'));
    if (view === 'audit') refreshAudit().catch(() => toast('审计日志加载失败'));
    if (view === 'backups') refreshBackups().catch(() => toast('备份列表加载失败'));
    if (view === 'settings') {
      api('/_admin/api/telegram').then(renderTelegram).catch(() => toast('Telegram 配置加载失败'));
      refreshTurnstile().catch(() => toast('Turnstile 配置加载失败'));
    }
  }

  let toastTimer;
  function toast(message) {
    const node = document.getElementById('toast');
    node.textContent = message;
    node.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { node.hidden = true; }, 2600);
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('gateway-theme', theme);
    const button = document.getElementById('theme-button');
    const dark = theme === 'dark';
    button.setAttribute('aria-label', dark ? '切换浅色模式' : '切换深色模式');
    button.setAttribute('title', dark ? '切换浅色模式' : '切换深色模式');
    button.innerHTML = `<i data-lucide="${dark ? 'sun' : 'moon'}"></i>`;
    window.lucide?.createIcons();
    if (state.snapshot && state.view === 'overview') requestAnimationFrame(() => renderChart(state.snapshot.timeline));
    if (state.geography && state.view === 'overview') requestAnimationFrame(renderGeographyMap);
    if (state.view === 'reports') requestAnimationFrame(redrawReportCharts);
  }

  function setSidebarCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    localStorage.setItem('gateway-sidebar-collapsed', String(collapsed));
    const button = document.getElementById('sidebar-collapse');
    button.setAttribute('aria-expanded', String(!collapsed));
    button.setAttribute('aria-label', collapsed ? '展开侧栏' : '折叠侧栏');
    button.setAttribute('title', collapsed ? '展开侧栏' : '折叠侧栏');
    button.innerHTML = `<i data-lucide="${collapsed ? 'chevron-right' : 'chevron-left'}"></i>`;
    window.lucide?.createIcons();
    window.setTimeout(() => {
      if (state.geoChart && state.view === 'overview') state.geoChart.resize();
      if (state.snapshot && state.view === 'overview') renderChart(state.snapshot.timeline);
      if (state.view === 'reports') resizeReportCharts();
    }, 220);
  }

  function setMobileSidebar(open) {
    document.body.classList.toggle('sidebar-open', open);
    const trigger = document.getElementById('mobile-menu-button');
    const scrim = document.getElementById('sidebar-scrim');
    trigger.setAttribute('aria-expanded', String(open));
    scrim.hidden = !open;
  }

  function setFullWidth(enabled) {
    const workspace = document.querySelector('.workspace');
    const button = document.getElementById('full-width-button');
    workspace.classList.toggle('full-width', enabled);
    localStorage.setItem('gateway-full-width', String(enabled));
    button.setAttribute('aria-pressed', String(enabled));
    button.setAttribute('aria-label', enabled ? '恢复内容宽度' : '切换全宽布局');
    button.setAttribute('title', enabled ? '恢复内容宽度' : '切换全宽布局');
    button.innerHTML = `<i data-lucide="${enabled ? 'minimize-2' : 'maximize-2'}"></i>`;
    window.lucide?.createIcons();
    window.setTimeout(() => {
      if (state.geoChart && state.view === 'overview') state.geoChart.resize();
      if (state.snapshot && state.view === 'overview') renderChart(state.snapshot.timeline);
      if (state.view === 'reports') resizeReportCharts();
    }, 280);
  }

  function filterCommandItems(query) {
    const needle = query.trim().toLowerCase();
    let visible = 0;
    document.querySelectorAll('[data-command-view]').forEach((button) => {
      const matches = !needle || button.dataset.commandSearch.toLowerCase().includes(needle) || button.textContent.toLowerCase().includes(needle);
      button.hidden = !matches;
      if (matches) visible += 1;
    });
    document.getElementById('command-empty').hidden = visible !== 0;
  }

  function openCommandPalette() {
    const dialog = document.getElementById('command-dialog');
    const input = document.getElementById('command-input');
    input.value = '';
    filterCommandItems('');
    if (!dialog.open) dialog.showModal();
    window.setTimeout(() => input.focus(), 0);
  }

  function closeCommandPalette() {
    const dialog = document.getElementById('command-dialog');
    if (dialog.open) dialog.close();
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
      send_hour: Number(document.getElementById('telegram-hour').value)
    }));
    renderTelegram(config);
    if (showNotice) toast('Telegram 配置已保存');
  }

  async function initialize() {
    setTheme(localStorage.getItem('gateway-theme') === 'dark' ? 'dark' : 'light');
    setSidebarCollapsed(localStorage.getItem('gateway-sidebar-collapsed') === 'true');
    setFullWidth(localStorage.getItem('gateway-full-width') === 'true');
    document.getElementById('command-modifier').textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl+';
    const hour = document.getElementById('telegram-hour');
    const backupHour = document.getElementById('backup-hour');
    for (let value = 0; value < 24; value += 1) {
      const option = document.createElement('option');
      option.value = String(value);
      option.textContent = `${String(value).padStart(2, '0')}:00`;
      hour.append(option);
      backupHour.append(option.cloneNode(true));
    }
    window.lucide?.createIcons();
    try {
      const session = await api('/_admin/api/session');
      document.getElementById('account-name').textContent = session.username;
      renderUpdateStatus({ current_version: session.version, latest_version: session.version, update_available: false });
      const avatar = document.querySelector('.avatar');
      if (!avatar.querySelector('img')) avatar.textContent = session.username.slice(0, 1).toUpperCase();
    } catch (failure) { return; }

    document.querySelectorAll('.nav-button').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
    document.querySelectorAll('[data-go-view]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.goView)));
    document.getElementById('sidebar-collapse').addEventListener('click', () => setSidebarCollapsed(!document.body.classList.contains('sidebar-collapsed')));
    document.getElementById('mobile-menu-button').addEventListener('click', () => setMobileSidebar(!document.body.classList.contains('sidebar-open')));
    document.getElementById('sidebar-scrim').addEventListener('click', () => setMobileSidebar(false));
    document.getElementById('update-button').addEventListener('click', startPanelUpdate);
    document.getElementById('full-width-button').addEventListener('click', () => setFullWidth(!document.querySelector('.workspace').classList.contains('full-width')));
    document.getElementById('command-button').addEventListener('click', openCommandPalette);
    document.getElementById('command-close').addEventListener('click', closeCommandPalette);
    document.getElementById('command-input').addEventListener('input', (event) => filterCommandItems(event.currentTarget.value));
    document.getElementById('command-input').addEventListener('keydown', (event) => {
      if (event.key !== 'Enter') return;
      const first = [...document.querySelectorAll('[data-command-view]')].find((button) => !button.hidden);
      if (first) { event.preventDefault(); first.click(); }
    });
    document.querySelectorAll('[data-command-view]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.commandView)));
    document.getElementById('command-dialog').addEventListener('click', (event) => {
      if (event.target === event.currentTarget) closeCommandPalette();
    });
    document.getElementById('confirm-cancel').addEventListener('click', () => settleConfirmation(false));
    document.getElementById('confirm-accept').addEventListener('click', () => settleConfirmation(true));
    document.getElementById('confirm-dialog').addEventListener('cancel', (event) => {
      event.preventDefault();
      settleConfirmation(false);
    });
    document.getElementById('confirm-dialog').addEventListener('close', () => settleConfirmation(false));
    document.getElementById('confirm-dialog').addEventListener('click', (event) => {
      if (event.target === event.currentTarget) settleConfirmation(false);
    });
    document.addEventListener('keydown', (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        openCommandPalette();
      }
      if (event.key === 'Escape') {
        if (document.getElementById('confirm-dialog').open) {
          event.preventDefault();
          settleConfirmation(false);
        }
        setMobileSidebar(false);
      }
    });
    document.getElementById('refresh-button').addEventListener('click', () => refresh(true));
    document.querySelectorAll('[data-geo-period]').forEach((button) => button.addEventListener('click', async () => {
      if (button.dataset.geoPeriod === state.overviewPeriod) return;
      const previous = state.overviewPeriod;
      state.overviewPeriod = button.dataset.geoPeriod;
      document.querySelectorAll('[data-geo-period]').forEach((item) => {
        item.classList.toggle('active', item === button);
        item.setAttribute('aria-pressed', String(item === button));
      });
      button.disabled = true;
      try {
        const [snapshot, geography] = await Promise.all([refreshDashboard(), refreshGeography()]);
        render(snapshot);
        renderGeography(geography);
        toast('概览周期已切换');
      }
      catch (failure) {
        state.overviewPeriod = previous;
        document.querySelectorAll('[data-geo-period]').forEach((item) => {
          const active = item.dataset.geoPeriod === previous;
          item.classList.toggle('active', active);
          item.setAttribute('aria-pressed', String(active));
        });
        toast('概览周期加载失败');
      }
      finally { button.disabled = false; }
    }));
    document.querySelectorAll('[data-report-period]').forEach((button) => button.addEventListener('click', async () => {
      if (button.dataset.reportPeriod === state.reportPeriod) return;
      const previous = state.reportPeriod;
      state.reportPeriod = button.dataset.reportPeriod;
      document.querySelectorAll('[data-report-period]').forEach((item) => {
        item.classList.toggle('active', item === button);
        item.setAttribute('aria-pressed', String(item === button));
      });
      button.disabled = true;
      try { await refreshReport(); }
      catch (failure) {
        state.reportPeriod = previous;
        document.querySelectorAll('[data-report-period]').forEach((item) => {
          const active = item.dataset.reportPeriod === previous;
          item.classList.toggle('active', active);
          item.setAttribute('aria-pressed', String(active));
        });
        toast('统计报表加载失败');
      } finally { button.disabled = false; }
    }));
    document.getElementById('report-export').addEventListener('click', () => {
      const kind = document.getElementById('report-export-kind').value;
      const link = document.createElement('a');
      link.href = `/_admin/api/reports/export?period=${encodeURIComponent(state.reportPeriod)}&kind=${encodeURIComponent(kind)}`;
      link.download = '';
      document.body.append(link);
      link.click();
      link.remove();
    });
    document.getElementById('map-zoom-in').addEventListener('click', () => zoomGeographyMap(1.28));
    document.getElementById('map-zoom-out').addEventListener('click', () => zoomGeographyMap(0.78));
    document.getElementById('map-reset').addEventListener('click', resetGeographyMap);
    document.getElementById('theme-button').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
    document.getElementById('logout-button').addEventListener('click', async () => {
      try { await api('/_admin/api/logout', jsonOptions('POST', {})); } finally { window.location.replace('/login'); }
    });
    document.querySelectorAll('input[name="policy-mode"]').forEach((input) => input.addEventListener('change', async (event) => {
      if (!event.currentTarget.checked) return;
      const previousMode = state.policy?.mode || 'off';
      const mode = event.currentTarget.value;
      try {
        renderPolicy(await api('/_admin/api/policy', jsonOptions('PUT', { mode })));
        toast(mode === 'blacklist' ? '已切换到黑名单模式' : mode === 'whitelist' ? '已切换到白名单模式' : '访问规则已关闭');
      } catch (failure) {
        document.querySelector(`input[name="policy-mode"][value="${previousMode}"]`).checked = true;
        toast('规则模式更新失败');
      }
    }));
    document.getElementById('rule-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const error = document.getElementById('rule-error');
      error.hidden = true;
      try {
        const policy = await api('/_admin/api/rules', jsonOptions('POST', {
          domain_suffix: document.getElementById('rule-domain').value.trim()
        }));
        renderPolicy(policy);
        form.reset();
        toast(state.policy.mode === 'blacklist' ? '已加入黑名单' : '已加入白名单');
      } catch (failure) {
        error.textContent = failure.message === 'select blacklist or whitelist mode first' ? '请先选择黑名单或白名单模式' : '请输入有效的域名后缀';
        error.hidden = false;
      }
    });
    document.getElementById('telegram-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      try { await saveTelegram(true); }
      catch (failure) { const error = document.getElementById('telegram-error'); error.textContent = 'Telegram 配置无效'; error.hidden = false; }
    });
    document.getElementById('telegram-test').addEventListener('click', async (event) => {
      event.currentTarget.disabled = true;
      try { await saveTelegram(false); await api('/_admin/api/telegram/test', jsonOptions('POST', {})); toast('测试消息已发送'); }
      catch (failure) { const error = document.getElementById('telegram-error'); error.textContent = '测试发送失败，请检查 Token 和 Chat ID'; error.hidden = false; }
      finally { event.currentTarget.disabled = false; }
    });
    document.querySelectorAll('#turnstile-site-key, #turnstile-secret').forEach((input) => input.addEventListener('input', () => {
      if (!state.turnstile) return;
      state.turnstile.tested = false;
      state.turnstileToken = '';
      document.getElementById('turnstile-enabled').checked = false;
      document.getElementById('turnstile-enabled').disabled = true;
      document.getElementById('turnstile-status').className = 'security-badge muted-badge';
      document.getElementById('turnstile-status').innerHTML = '<i data-lucide="rotate-cw"></i>需要重新自测';
      document.getElementById('turnstile-config-widget').hidden = true;
      resetTurnstileWidget();
      window.lucide?.createIcons();
    }));
    document.getElementById('turnstile-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const error = document.getElementById('turnstile-error');
      error.hidden = true;
      const submit = event.currentTarget.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        await saveTurnstile();
        toast('Turnstile 配置已保存');
      } catch (failure) {
        error.textContent = failure.message.includes('self-test') ? '请先保存关闭状态的配置，再完成配置自测' : 'Turnstile 配置无效';
        error.hidden = false;
      } finally { submit.disabled = false; }
    });
    document.getElementById('turnstile-test').addEventListener('click', async (event) => {
      const error = document.getElementById('turnstile-error');
      error.hidden = true;
      if (!state.turnstile?.site_key || !state.turnstile?.secret_set || !state.turnstile?.hostname) {
        error.textContent = '请先填写并保存 Site key 和 Secret key';
        error.hidden = false;
        return;
      }
      if (document.getElementById('turnstile-site-key').value.trim() !== state.turnstile.site_key ||
          document.getElementById('turnstile-secret').value.trim()) {
        error.textContent = '配置已修改，请先保存配置';
        error.hidden = false;
        return;
      }
      if (!state.turnstileToken) {
        error.textContent = '请先完成下方 Cloudflare 验证';
        error.hidden = false;
        return;
      }
      event.currentTarget.disabled = true;
      try {
        renderTurnstile(await api('/_admin/api/turnstile/test', jsonOptions('POST', { token: state.turnstileToken })));
        toast('配置自测通过，现在可以启用登录验证');
      } catch (failure) {
        error.textContent = '配置自测失败，请检查 Site key、Secret key 和域名';
        error.hidden = false;
        resetTurnstileWidget();
      } finally { event.currentTarget.disabled = false; }
    });
    document.getElementById('backup-config-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const error = document.getElementById('backup-config-error');
      error.hidden = true;
      if (!form.reportValidity()) return;
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
      } catch (failure) {
        error.textContent = '备份策略保存失败，请检查执行时间和保留数量';
        error.hidden = false;
      } finally { submit.disabled = false; }
    });
    document.getElementById('backup-create').addEventListener('click', async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        renderBackups(await api('/_admin/api/backups', jsonOptions('POST', {})));
        toast('数据库备份已创建');
      } catch (failure) { toast('数据库备份创建失败'); }
      finally { button.disabled = false; }
    });
    document.getElementById('backup-import').addEventListener('change', async (event) => {
      const input = event.currentTarget;
      const file = input.files?.[0];
      if (!file) return;
      const form = new FormData();
      form.append('backup', file, file.name);
      input.disabled = true;
      try {
        renderBackups(await api('/_admin/api/backups/import', { method: 'POST', body: form }));
        toast('备份文件已导入');
      } catch (failure) { toast('备份导入失败，请确认文件有效'); }
      finally {
        input.value = '';
        input.disabled = false;
      }
    });
    document.getElementById('password-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const current = document.getElementById('current-password');
      const next = document.getElementById('new-password');
      const confirm = document.getElementById('confirm-password');
      const error = document.getElementById('password-error');
      error.hidden = true;
      if (!event.currentTarget.reportValidity()) return;
      if (next.value !== confirm.value) { error.textContent = '两次输入的新密码不一致'; error.hidden = false; return; }
      try {
        await api('/_admin/api/password', jsonOptions('POST', { current_password: current.value, new_password: next.value }));
        window.location.replace('/login');
      } catch (failure) {
        error.textContent = failure.message === 'current password is incorrect' ? '当前密码不正确' :
          failure.message.includes('12-128') ? '新密码至少需要 12 个字符' : '密码更新失败';
        error.hidden = false;
      }
    });
    const initialView = window.location.hash.slice(1);
    if (viewMeta[initialView]) await switchView(initialView);
    await refresh(false);
    await refreshLive();
    refreshUpdateStatus().catch(() => {
      document.getElementById('update-button').title = '暂时无法检查更新';
    });
    state.updateTimer = window.setInterval(() => refreshUpdateStatus().catch(() => {}), 10 * 60 * 1000);
    state.dashboardTimer = window.setInterval(() => refreshDashboard().catch(() => {}), 1000);
    state.liveTimer = window.setInterval(refreshLive, 1000);
    window.addEventListener('resize', () => {
      if (window.innerWidth > 840 && document.body.classList.contains('sidebar-open')) setMobileSidebar(false);
      if (state.snapshot && state.view === 'overview') renderChart(state.snapshot.timeline);
      if (state.geoChart && state.view === 'overview') state.geoChart.resize();
      if (state.view === 'reports') resizeReportCharts();
    });
  }

  initialize();
})();
