/* MTProto Proxy Monitor — frontend logic */

const $ = id => document.getElementById(id);
const MH = 90;       // max history points
const MAX_LINES = 300;
let autoScrollEnabled = true;
let userScrolledUp = false;
let pollIntervalMs = 3000;
let pollLoop = null;
let pollInFlight = false;
let pollingPaused = false;
let lastSuccessAt = 0;
let hasPollError = false;
let lastData = null; // store last API response for tooltips

const tt = $('chartTooltip');
function showTooltip(e, canvas, padLeft, dataArr, formatCb) {
  if (!dataArr || !dataArr.length) return;
  const r = canvas.getBoundingClientRect();
  const px = e.clientX - r.left;
  // Account for padding left in responsive coordinates
  const pL = (padLeft / canvas.width) * r.width;
  if (px < pL) { tt.classList.remove('visible'); return; }

  const cw = r.width - pL;
  const step = cw / (MH - 1);
  const idx = Math.round((px - pL) / step);
  const off = MH - dataArr.length;
  const dataIdx = idx - off;

  if (dataIdx < 0 || dataIdx >= dataArr.length) { tt.classList.remove('visible'); return; }

  const item = dataArr[dataIdx];
  const d = new Date(item.ts);
  const tStr = d.getHours().toString().padStart(2, '0') + ':' +
               d.getMinutes().toString().padStart(2, '0') + ':' +
               d.getSeconds().toString().padStart(2, '0');

  tt.innerHTML = `<div class="tooltip-ts">${tStr}</div>` + formatCb(item);
  
  // Position tooltip safely
  let tx = e.clientX + 15;
  let ty = e.clientY + 15;
  if (tx + 120 > window.innerWidth) tx = e.clientX - 130;
  if (ty + 50 > window.innerHeight) ty = e.clientY - 60;
  
  tt.style.left = tx + 'px';
  tt.style.top = ty + 'px';
  tt.classList.add('visible');
}

function hideTooltip() { tt.classList.remove('visible'); }

const logFilters = { error: true, warn: true, stats: true };
let logSearchTerm = '';
const appRoot = document.querySelector('.app');

// ── Gauges ──
function setGauge(arcId, pctId, val) {
  $(arcId).style.strokeDashoffset = 94.2 - (94.2 * val / 100);
  $(pctId).textContent = val + '%';
}

// ── Network chart ──
const canvas = $('netChart');
const ctx = canvas.getContext('2d');

function resizeCanvas() {
  const r = canvas.parentElement.getBoundingClientRect();
  canvas.width = r.width * 2;
  canvas.height = r.height * 2;
  ctx.setTransform(2, 0, 0, 2, 0, 0);
}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

function drawNetChart() {
  if (!lastData || !lastData.net_history) return;
  const data = lastData.net_history;
  const w = canvas.width / 2, h = canvas.height / 2;
  ctx.clearRect(0, 0, w, h);
  if (data.length < 2) return;

  let peak = 4096;
  for (let i = 0; i < data.length; i++) {
    if (data[i].rx > peak) peak = data[i].rx;
    if (data[i].tx > peak) peak = data[i].tx;
  }
  peak *= 1.2;

  const PAD = 42;           // left padding for Y-axis labels
  const PAD_TOP = 4;        // top padding so labels don't clip
  const PAD_BOT = 18;       // bottom padding for X-axis labels
  const cw = w - PAD;
  const ch = h - PAD_TOP - PAD_BOT;
  const step = cw / (MH - 1);

  // Y-axis grid + labels
  ctx.font = '9px Inter, sans-serif';
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';

  for (let i = 0; i <= 4; i++) {
    const frac = i / 4;
    const y = PAD_TOP + ch * (1 - frac);
    ctx.strokeStyle = 'rgba(247,164,29,0.05)';
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    ctx.moveTo(PAD, y);
    ctx.lineTo(w, y);
    ctx.stroke();
    if (i > 0) {
      ctx.fillStyle = 'rgba(124,134,152,0.6)';
      ctx.fillText(fmtShort(peak * frac), PAD - 5, y);
    }
  }

  // X-axis labels
  ctx.textAlign = 'left';
  ctx.textBaseline = 'bottom';
  ctx.fillStyle = 'rgba(124,134,152,0.6)';
  
  const oldest = new Date(data[0].ts);
  const newest = new Date(data[data.length - 1].ts);
  
  function fTime(d) { return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0'); }
  ctx.fillText(fTime(oldest), PAD, h - 3);
  ctx.textAlign = 'right';
  ctx.fillText(fTime(newest), w, h - 3);

  function drawLine(key, color) {
    const off = MH - data.length;
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    data.forEach((item, i) => {
      const v = item[key];
      const x = PAD + (off + i) * step;
      const y = PAD_TOP + ch - (v / peak) * ch;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
    // gradient fill
    const c = color.match(/[\d.]+/g);
    const grad = ctx.createLinearGradient(0, PAD_TOP, 0, PAD_TOP + ch);
    grad.addColorStop(0, `rgba(${c[0]},${c[1]},${c[2]},0.1)`);
    grad.addColorStop(1, 'transparent');
    ctx.lineTo(PAD + (off + data.length - 1) * step, PAD_TOP + ch);
    ctx.lineTo(PAD + off * step, PAD_TOP + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
  }

  drawLine('tx', 'rgb(247,164,29)');
  drawLine('rx', 'rgb(52,211,153)');
}

canvas.addEventListener('mousemove', e => {
  showTooltip(e, canvas, 42, lastData?.net_history, item => 
    `<div class="tooltip-val" style="color:var(--green)">RX: ${fmt(item.rx)}</div><div class="tooltip-val" style="color:var(--zig)">TX: ${fmt(item.tx)}</div>`
  );
});
canvas.addEventListener('mouseleave', hideTooltip);

// ── Sparkline with Y-axis ──
function drawSpark(canvasId, data, color, maxVal, unit) {
  const c = document.getElementById(canvasId);
  if (!c) return;
  const x = c.getContext('2d');
  const r = c.parentElement.getBoundingClientRect();
  c.width = r.width * 2;
  c.height = r.height * 2;
  x.setTransform(2, 0, 0, 2, 0, 0);

  const w = r.width, h = r.height;
  if (!data || data.length < 2) return;

  let peak = maxVal;
  if (!peak) {
    peak = 1;
    for (let i = 0; i < data.length; i++) {
      if (data[i].v > peak) peak = data[i].v;
    }
  }
  peak *= 1.2;

  const PAD = 32;       // left padding
  const PAD_TOP = 6;    // top padding
  const cw = w - PAD;
  const ch = h - PAD_TOP;
  const step = cw / (MH - 1);
  const off = MH - data.length;

  x.clearRect(0, 0, w, h);

  // Y-axis ticks
  const ticks = unit === '%' ? [0, 50, 100] : [0, peak * 0.5, peak];
  x.font = '8px Inter, sans-serif';
  x.textAlign = 'right';
  x.textBaseline = 'middle';

  for (const tv of ticks) {
    const frac = tv / peak;
    const y = PAD_TOP + ch * (1 - frac);
    x.strokeStyle = 'rgba(247,164,29,0.05)';
    x.lineWidth = 0.5;
    x.beginPath();
    x.moveTo(PAD, y);
    x.lineTo(w, y);
    x.stroke();
    if (tv > 0) {
      x.fillStyle = 'rgba(124,134,152,0.5)';
      x.fillText(unit === '%' ? tv + '%' : tv.toFixed(0), PAD - 4, y);
    }
  }

  // Data line
  x.beginPath();
  x.strokeStyle = color;
  x.lineWidth = 1.5;
  x.lineJoin = 'round';
  data.forEach((item, i) => {
    const px = PAD + (off + i) * step;
    const py = PAD_TOP + ch - (item.v / peak) * ch;
    i === 0 ? x.moveTo(px, py) : x.lineTo(px, py);
  });
  x.stroke();

  // Fill
  const cc = color.match(/[\d.]+/g);
  const grad = x.createLinearGradient(0, PAD_TOP, 0, h);
  grad.addColorStop(0, `rgba(${cc[0]},${cc[1]},${cc[2]},0.08)`);
  grad.addColorStop(1, 'transparent');
  x.lineTo(PAD + (off + data.length - 1) * step, h);
  x.lineTo(PAD + off * step, h);
  x.closePath();
  x.fillStyle = grad;
  x.fill();
}

const cpuCanvas = $('cpuSpark');
if (cpuCanvas) {
  cpuCanvas.addEventListener('mousemove', e => showTooltip(e, cpuCanvas, 32, lastData?.cpu_history, item => `<div class="tooltip-val" style="color:var(--zig)">Util: ${item.v}%</div>`));
  cpuCanvas.addEventListener('mouseleave', hideTooltip);
}
const memCanvas = $('memSpark');
if (memCanvas) {
  memCanvas.addEventListener('mousemove', e => showTooltip(e, memCanvas, 32, lastData?.mem_history, item => `<div class="tooltip-val" style="color:var(--purple)">Mem: ${item.v}%</div>`));
  memCanvas.addEventListener('mouseleave', hideTooltip);
}

// ── Formatters ──
function fmt(b) {
  if (b < 1024) return b.toFixed(0) + ' B/s';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB/s';
  return (b / 1048576).toFixed(1) + ' MB/s';
}
function fmtShort(b) {
  if (b < 1024) return b.toFixed(0) + ' B';
  if (b < 1048576) return (b / 1024).toFixed(0) + ' KB';
  return (b / 1048576).toFixed(1) + ' MB';
}
function fmtT(b) {
  if (b < 1073741824) return (b / 1048576).toFixed(0) + ' MB';
  return (b / 1073741824).toFixed(1) + ' GB';
}

function shortProxyLink(link) {
  if (!link) return 'link unavailable';
  if (link.length <= 88) return link;
  return link.slice(0, 52) + '…' + link.slice(-32);
}

async function copyText(text) {
  if (!text) return false;

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) {}

  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'absolute';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  ta.setSelectionRange(0, text.length);

  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (_) {
    ok = false;
  }

  document.body.removeChild(ta);
  return ok;
}

function renderUsers(users) {
  const card = $('usersCard');
  if (!card) return;

  const meta = $('usersMeta');
  const note = $('usersNote');
  const list = $('usersList');
  card.style.display = '';

  const items = (users && Array.isArray(users.items)) ? users.items : [];
  const total = Number(users?.total || 0);
  const directTotal = Number(users?.direct_total || 0);

  meta.textContent = total + ' users · direct ' + directTotal;

  if (!users?.links_ready) {
    note.textContent = 'Set [server].public_ip in config.toml to generate copyable links.';
  } else {
    note.textContent = 'Links: ' + users.server + ':' + users.port + ' · tls_domain=' + (users.tls_domain || '—');
  }

  if (items.length === 0) {
    list.innerHTML = '<div class="user-empty">No users configured in [access.users].</div>';
    return;
  }

  list.innerHTML = items.map((u) => {
    const tg = u.tg_link || '';
    const tme = u.tme_link || '';
    const preview = shortProxyLink(tg || tme);
    const routeClass = u.direct ? 'direct' : 'default';
    const routeLabel = u.direct ? 'direct' : 'default';
    const tgData = encodeURIComponent(tg);
    const tmeData = encodeURIComponent(tme);
    return '<div class="user-row">' +
      '<div class="user-name">' + esc(u.name || 'user') + '</div>' +
      '<div class="route-badge ' + routeClass + '">' + routeLabel + '</div>' +
      '<div class="user-link" title="' + esc(tg || tme || 'link unavailable') + '">' + esc(preview) + '</div>' +
      '<div class="user-actions">' +
      '<button class="ui-btn user-copy" type="button" data-link="' + tgData + '"' + (tg ? '' : ' disabled') + '>Copy tg://</button>' +
      '<button class="ui-btn user-copy" type="button" data-link="' + tmeData + '"' + (tme ? '' : ' disabled') + '>Copy t.me</button>' +
      '</div>' +
      '</div>';
  }).join('');

  list.querySelectorAll('.user-copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const encoded = btn.dataset.link || '';
      if (!encoded) return;

      const link = decodeURIComponent(encoded);
      const original = btn.textContent;
      const ok = await copyText(link);
      btn.textContent = ok ? 'Copied' : 'Failed';
      btn.classList.toggle('active', ok);
      setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove('active');
      }, 1100);
    });
  });
}

// ── Polling ──
async function poll() {
  const r = await fetch('/api/stats', { cache: 'no-store' });
  if (!r.ok) throw new Error('stats request failed: ' + r.status);
  const d = await r.json();

  lastData = d;

  // CPU
  setGauge('cpuArc', 'cpuPct', d.cpu);
  $('cpuVal').innerHTML = d.cpu + '<span style="font-size:18px;font-weight:400">%</span>';
  // Memory
  setGauge('memArc', 'memPct', d.mem_pct);
  $('memVal').innerHTML = d.mem_used + '<span style="font-size:14px;font-weight:400"> MB</span>';
  $('memSub').textContent = d.mem_used + ' / ' + d.mem_total + ' MB';

  // Sparklines
  if (d.cpu_history) drawSpark('cpuSpark', d.cpu_history, 'rgb(247,164,29)', 100, '%');
  if (d.mem_history) drawSpark('memSpark', d.mem_history, 'rgb(167,139,250)', 100, '%');

  // Network
  drawNetChart();
  $('rxRate').textContent = fmt(d.net_rx);
  $('txRate').textContent = fmt(d.net_tx);
  $('rxTotal').textContent = fmtT(d.net_rx_total);
  $('txTotal').textContent = fmtT(d.net_tx_total);

  // Server
  $('srvUptime').textContent = d.uptime;
  const pi = d.proxy_info || {};
  $('proxyUp').textContent = pi.uptime || '—';
  $('proxyPid').textContent = pi.pid || '—';
  $('proxyRss').textContent = (pi.rss_mb || 0) + ' MB';
  $('statusBadge').className = pi.online ? 'badge' : 'badge off';

  // Proxy stats
  const p = d.proxy || {};
  $('pxActive').textContent = p.active || 0;
  $('pxMax').textContent = p.max || 0;
  $('pxHs').textContent = p.hs_inflight || 0;
  $('pxTotal').textContent = (p.total || 0).toLocaleString();
  const drp = p.rate_drops || 0;
  $('pxDrops').textContent = drp;
  $('pxDrops').style.color = drp > 0 ? 'var(--amber)' : 'var(--text-muted)';
  $('pxDropLbl').textContent = 'rate +' + drp + ' · cap +' + (p.cap_drops || 0) + ' · hs_t +' + (p.hs_timeout || 0);

  // AmneziaWG tunnel
  const awg = d.awg;
  const tc = $('tunnelCard');
  if (!awg) {
    tc.style.display = 'none';
  } else {
    tc.style.display = '';
    const badge = $('awgBadge');
    if (awg.active) {
      badge.className = 'badge';
      $('awgStatus').textContent = 'Active';
    } else {
      badge.className = 'badge off';
      $('awgStatus').textContent = awg.reason || 'Down';
    }
    $('awgEndpoint').textContent = awg.endpoint || '—';
    $('awgHandshake').textContent = awg.handshake || '—';
    $('awgRx').textContent = awg.rx || '—';
    $('awgTx').textContent = awg.tx || '—';
  }

  // Masking health
  const masking = d.masking;
  const mc = $('maskingCard');
  if (!masking) {
    mc.style.display = 'none';
  } else {
    mc.style.display = '';

    const maskBadge = $('maskBadge');
    if (!masking.enabled) {
      maskBadge.className = 'badge off';
      $('maskStatus').textContent = 'Disabled';
    } else if (masking.mode === 'remote') {
      maskBadge.className = 'badge';
      $('maskStatus').textContent = 'Remote mode';
    } else if (masking.healthy) {
      maskBadge.className = 'badge';
      $('maskStatus').textContent = 'Healthy';
    } else {
      maskBadge.className = 'badge off';
      $('maskStatus').textContent = 'Degraded';
    }

    let modeText = masking.mode || '—';
    if (masking.mode === 'remote') {
      modeText = 'remote (' + (masking.tls_domain || '—') + ':443)';
    } else if (masking.mode === 'local' && masking.using_netns) {
      modeText = 'local (netns)';
    } else if (masking.mode === 'local') {
      modeText = 'local';
    }
    $('maskMode').textContent = modeText;

    let endpointText = masking.target || '—';
    if (masking.mode === 'local') {
      if (masking.endpoint_ok === true) {
        endpointText += ' (OK)';
      } else if (masking.endpoint_ok === false) {
        endpointText += ' (DOWN)';
      }
    }
    $('maskTarget').textContent = endpointText;

    const nginxState = (masking.nginx_active ? 'active' : 'down') + ' / ' +
      (masking.nginx_enabled ? 'enabled' : 'disabled');
    $('maskNginx').textContent = nginxState;

    const timerState = (masking.health_timer_active ? 'active' : 'down') + ' / ' +
      (masking.health_timer_enabled ? 'enabled' : 'disabled');
    $('maskTimer').textContent = timerState;
  }

  renderUsers(d.users || null);
}

function setDataBadge(state, text) {
  $('dataBadge').className = 'badge data-badge ' + state;
  $('dataBadgeText').textContent = text;
}

function setStaleMode(stale) {
  appRoot.classList.toggle('stale', stale);
}

function updateFreshness() {
  if (!lastSuccessAt) {
    $('lastUpdate').textContent = 'never';
  } else {
    const age = Math.floor((Date.now() - lastSuccessAt) / 1000);
    $('lastUpdate').textContent = age <= 0 ? 'just now' : age + 's ago';
  }

  if (pollingPaused) {
    setDataBadge('paused', 'Paused');
    setStaleMode(false);
    return;
  }

  if (!lastSuccessAt) {
    if (hasPollError) {
      setDataBadge('stale', 'Data delayed');
      setStaleMode(true);
    } else {
      setDataBadge('syncing', 'Syncing...');
      setStaleMode(false);
    }
    return;
  }

  const age = Math.floor((Date.now() - lastSuccessAt) / 1000);
  const staleThreshold = Math.max(8, Math.ceil((pollIntervalMs / 1000) * 2));
  const stale = hasPollError || age > staleThreshold;
  setDataBadge(stale ? 'stale' : 'ok', stale ? 'Data delayed' : 'Live');
  setStaleMode(stale);
}

function updatePollControls() {
  $('pollToggle').textContent = pollingPaused ? 'Resume' : 'Pause';
  $('pollToggle').classList.toggle('active', !pollingPaused);
}

async function runPoll() {
  if (pollInFlight || pollingPaused) return;
  pollInFlight = true;
  try {
    await poll();
    hasPollError = false;
    lastSuccessAt = Date.now();
  } catch (e) {
    hasPollError = true;
    console.error(e);
  } finally {
    pollInFlight = false;
    updateFreshness();
  }
}

function restartPollingLoop() {
  if (pollLoop) clearInterval(pollLoop);
  if (pollingPaused) {
    pollLoop = null;
    return;
  }
  pollLoop = setInterval(runPoll, pollIntervalMs);
}

function setPollingPaused(paused) {
  pollingPaused = paused;
  updatePollControls();
  restartPollingLoop();
  if (!pollingPaused) runPoll();
  updateFreshness();
}

$('pollInterval').value = String(pollIntervalMs);
$('pollInterval').addEventListener('change', (ev) => {
  const v = Number(ev.target.value);
  if (!v || v === pollIntervalMs) return;
  pollIntervalMs = v;
  restartPollingLoop();
  updateFreshness();
});

$('pollToggle').addEventListener('click', () => {
  setPollingPaused(!pollingPaused);
});

updatePollControls();
updateFreshness();
runPoll();
restartPollingLoop();
setInterval(updateFreshness, 1000);

// ── Live logs ──
const logsBody = $('logsBody');
const logSearchInput = $('logSearch');
const autoScrollBtn = $('autoScrollBtn');
const jumpLatestBtn = $('jumpLatestBtn');
const logFilterButtons = Array.from(document.querySelectorAll('.log-filter'));

function isNearBottom() {
  return logsBody.scrollTop + logsBody.clientHeight >= logsBody.scrollHeight - 40;
}

function jumpToLatest() {
  logsBody.scrollTop = logsBody.scrollHeight;
  userScrolledUp = false;
}

function updateAutoScrollButton() {
  autoScrollBtn.textContent = autoScrollEnabled ? 'Auto-scroll: on' : 'Auto-scroll: off';
  autoScrollBtn.classList.toggle('active', autoScrollEnabled);
}

function shouldShowLine(el) {
  const cls = el.dataset.cls || 'info';
  if (Object.prototype.hasOwnProperty.call(logFilters, cls) && !logFilters[cls]) return false;
  if (!logSearchTerm) return true;
  return (el.dataset.msg || '').includes(logSearchTerm) || (el.dataset.ts || '').includes(logSearchTerm);
}

function applyLineFilter(el) {
  el.style.display = shouldShowLine(el) ? '' : 'none';
}

function applyAllLogFilters() {
  for (const el of logsBody.children) applyLineFilter(el);
}

logsBody.addEventListener('scroll', () => {
  if (!autoScrollEnabled) return;
  userScrolledUp = !isNearBottom();
});

logFilterButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    const k = btn.dataset.filter;
    logFilters[k] = !logFilters[k];
    btn.classList.toggle('active', logFilters[k]);
    applyAllLogFilters();
  });
});

logSearchInput.addEventListener('input', () => {
  logSearchTerm = logSearchInput.value.trim().toLowerCase();
  applyAllLogFilters();
});

autoScrollBtn.addEventListener('click', () => {
  autoScrollEnabled = !autoScrollEnabled;
  if (autoScrollEnabled) jumpToLatest();
  updateAutoScrollButton();
});

jumpLatestBtn.addEventListener('click', jumpToLatest);
updateAutoScrollButton();

function addLine(d, anim) {
  const cls = d.cls || 'info';
  const ts = d.ts || '';
  const msg = d.text || '';
  const el = document.createElement('div');
  el.className = 'log-line ' + cls + (anim ? ' fresh' : '');
  el.dataset.cls = cls;
  el.dataset.ts = ts.toLowerCase();
  el.dataset.msg = msg.toLowerCase();
  el.innerHTML = '<span class="log-ts">' + esc(ts) + '</span><span class="log-msg">' + esc(msg) + '</span>';
  logsBody.appendChild(el);
  applyLineFilter(el);
  while (logsBody.children.length > MAX_LINES) logsBody.removeChild(logsBody.firstChild);
  if (autoScrollEnabled && !userScrolledUp) jumpToLatest();
  if (anim) setTimeout(() => el.classList.remove('fresh'), 300);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(proto + '://' + location.host + '/ws/logs');
  let initialBacklog = true;

  ws.onopen = () => {
    $('wsDot').className = 'ws-dot on';
    $('wsLabel').textContent = 'live';
  };
  ws.onclose = () => {
    $('wsDot').className = 'ws-dot off';
    $('wsLabel').textContent = 'reconnecting…';
    setTimeout(connectWS, 3000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    addLine(d, !initialBacklog);
    if (initialBacklog) setTimeout(() => { initialBacklog = false; }, 500);
  };
}
connectWS();
