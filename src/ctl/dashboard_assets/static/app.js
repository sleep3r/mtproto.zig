/* MTProto Proxy Dashboard — frontend logic */

const $ = id => document.getElementById(id);

// ── Icon set (inline SVG, currentColor, 24×24, butt caps / miter joins, angular
// Zig-echo geometry) — replaces every emoji used as an icon. ──
const ICON = {
  'qr-share': '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M3 3 H9 V9 H3 Z"/><path d="M15 3 H21 V9 H15 Z"/><path d="M3 15 H9 V21 H3 Z"/><path d="M15 15 H18 V18 H15 Z"/><path d="M21 15 V21 H18"/><path d="M15 21 H15.01"/></svg>',
  'copy': '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M9 9 H20 V20 H9 Z"/><path d="M5 15 H4 V4 H15 V5"/></svg>',
  'delete': '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M4 6 H20"/><path d="M9 6 V4 H15 V6"/><path d="M6 6 L7 20 H17 L18 6"/><path d="M10 10 V16 M14 10 V16"/></svg>',
  'plus': '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M12 5 V19 M5 12 H19"/></svg>',
  'chevron-down': '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="butt" stroke-linejoin="miter"><polyline points="7,10 12,15 17,10"/></svg>',
  'pause': '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M8 5 V19 M16 5 V19"/></svg>',
  'play': '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M7 5 L19 12 L7 19 Z"/></svg>',
  'search': '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M5 5 H15 V15 H5 Z"/><path d="M15 15 L20 20"/></svg>',
  'autoscroll': '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><polyline points="6,5 12,11 18,5"/><polyline points="6,11 12,17 18,11"/><path d="M5 20 H19"/></svg>',
  'jump-latest': '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M12 4 V16"/><polyline points="6,11 12,17 18,11"/><path d="M5 20 H19"/></svg>',
  'arrow-down': '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="butt" stroke-linejoin="miter"><path d="M12 4 V18"/><polyline points="6,12 12,18 18,12"/></svg>',
  'arrow-up': '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="butt" stroke-linejoin="miter"><path d="M12 20 V6"/><polyline points="6,12 12,6 18,12"/></svg>',
  'warning': '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="butt" stroke-linejoin="miter"><path d="M12 3 L22 20 H2 Z"/><path d="M12 10 V15"/><path d="M12 17.5 V17.6"/></svg>',
  'send-plane': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M21 3 L3 11 L10 13 L12 20 Z"/><path d="M21 3 L10 13"/></svg>',
  'lang-globe': '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="butt" stroke-linejoin="miter"><path d="M4 6 H20 V18 H4 Z"/><path d="M4 12 H20"/><path d="M12 6 C9 9 9 15 12 18 C15 15 15 9 12 6 Z"/></svg>'
};

// ── i18n (EN/RU) ──────────────────────────────────────────────
// Prose, labels and buttons are translated; technical proper nouns (MiddleProxy,
// socks5, Nginx, RX/TX) stay as-is — that's normal bilingual UI, not code-switching.
const I18N = {
  en: {
    'header.refresh': 'Refresh', 'header.uptime': 'Uptime', 'header.lastUpdate': 'Last update',
    'card.cpu': 'CPU', 'card.cpuSub': 'utilization', 'card.memory': 'Memory', 'card.network': 'Network Throughput',
    'stats.activeOf': 'Active /', 'stats.handshakes': 'Handshakes', 'stats.total': 'Total Connections',
    'users.title': 'Users', 'users.add': '+ Add User', 'users.who': 'Who is this for?',
    'users.secret': 'Secret', 'users.secretHint': '(leave empty to auto-generate)',
    'users.namePh': 'e.g. Мама, dad, work', 'users.secretPh': "Leave blank — we'll create one for you",
    'btn.create': 'Create', 'btn.cancel': 'Cancel', 'btn.apply': 'Apply', 'btn.pin': 'Pin', 'btn.setTarget': 'Set target', 'btn.delete': 'Delete', 'btn.close': 'Close',
    'routing.title': 'Routing & Upstream', 'routing.upstream': 'Upstream', 'routing.tunnelPin': 'Tunnel pin',
    'routing.proxyHost': 'Proxy host', 'routing.port': 'Port', 'routing.user': 'User', 'routing.pass': 'Pass', 'routing.target': 'Target', 'routing.policy': 'Policy',
    'mask.title': 'Masking', 'mask.mode': 'Mode', 'mask.endpoint': 'Endpoint', 'mask.timer': 'Health Timer',
    'egress.title': 'Tunnel Quality', 'egress.interface': 'Interface', 'egress.status': 'Status',
    'egress.rtt': 'RTT', 'egress.loss': 'Loss', 'egress.handshake': 'Handshake', 'egress.quality': 'Quality',
    'egress.good': 'Good', 'egress.degraded': 'Degraded', 'egress.poor': 'Poor', 'egress.up': 'Up', 'egress.down': 'Down', 'egress.unknown': 'Unknown',
    'egress.primary': 'primary', 'egress.bottleneck': 'Tunnel is the bottleneck',
    'egress.notMonitored': 'Not monitored (not in tunnel mode)',
    'logs.title': 'Live Logs', 'logs.error': 'Error', 'logs.warn': 'Warn', 'logs.stats': 'Stats', 'logs.searchPh': 'Search logs', 'logs.jumpLatest': 'Jump to latest',
    'modal.deleteUser': 'Delete User', 'modal.deleteTunnel': 'Delete Tunnel', 'modal.restartNote': 'The proxy will be restarted to apply changes.',
    'share.subtitle': 'Point their phone camera at this code to connect.', 'share.copyLink': 'Copy link', 'share.send': 'Send', 'share.with': 'Share with',
    'status.online': 'Online', 'status.offline': 'Offline', 'status.stuck': 'Stuck',
    'status.healthy': 'Healthy', 'status.needsAttention': 'Needs attention', 'status.disabled': 'Disabled', 'status.remoteMode': 'Remote mode', 'status.endpointOk': 'OK', 'status.endpointDown': 'not responding',
    'hero.checking': 'Checking…', 'hero.offline': "Your proxy is offline — friends can't connect until it's back.",
    'hero.stalled': 'Your proxy is running but not responding — it looks stuck. Restarting usually fixes this.',
    'hero.idle': 'Your proxy is online and ready. No one is connected yet — share a link to get started.',
    'hero.busy': "Everything's working. {n} connected right now.",
    'hero.vChecking': 'Checking…', 'hero.vOffline': 'Offline', 'hero.vStalled': 'Stalled', 'hero.vIdle': 'All quiet — idle', 'hero.vBusy': 'Busy — {n} connected',
    'hero.connected': 'Connected', 'hero.uptimeLbl': 'Uptime',
    'toast.connected': 'Someone just connected through your proxy.',
    'toast.linkCopied': 'Link copied — send it to someone you love.',
    'autoscroll.on': 'Auto-scroll: on', 'autoscroll.off': 'Auto-scroll: off', 'btn.pause': 'Pause', 'btn.resume': 'Resume',
  },
  ru: {
    'header.refresh': 'Обновление', 'header.uptime': 'Аптайм', 'header.lastUpdate': 'Обновлено',
    'card.cpu': 'CPU', 'card.cpuSub': 'загрузка', 'card.memory': 'Память', 'card.network': 'Сетевой трафик',
    'stats.activeOf': 'Активно /', 'stats.handshakes': 'Подключаются', 'stats.total': 'Всего подключений',
    'users.title': 'Пользователи', 'users.add': '+ Добавить', 'users.who': 'Для кого это?',
    'users.secret': 'Секрет', 'users.secretHint': '(пусто — сгенерируем сами)',
    'users.namePh': 'напр. Мама, папа, работа', 'users.secretPh': 'Оставьте пустым — создадим сами',
    'btn.create': 'Создать', 'btn.cancel': 'Отмена', 'btn.apply': 'Применить', 'btn.pin': 'Закрепить', 'btn.setTarget': 'Задать', 'btn.delete': 'Удалить', 'btn.close': 'Закрыть',
    'routing.title': 'Маршрутизация и выход', 'routing.upstream': 'Выход', 'routing.tunnelPin': 'Туннель',
    'routing.proxyHost': 'Хост прокси', 'routing.port': 'Порт', 'routing.user': 'Логин', 'routing.pass': 'Пароль', 'routing.target': 'Цель', 'routing.policy': 'Политика',
    'mask.title': 'Маскировка', 'mask.mode': 'Режим', 'mask.endpoint': 'Эндпоинт', 'mask.timer': 'Таймер проверки',
    'egress.title': 'Качество туннеля', 'egress.interface': 'Интерфейс', 'egress.status': 'Статус',
    'egress.rtt': 'RTT', 'egress.loss': 'Потери', 'egress.handshake': 'Хендшейк', 'egress.quality': 'Качество',
    'egress.good': 'Хорошо', 'egress.degraded': 'Деградация', 'egress.poor': 'Плохо', 'egress.up': 'Включён', 'egress.down': 'Отключён', 'egress.unknown': 'Неизвестно',
    'egress.primary': 'основной', 'egress.bottleneck': 'Туннель — узкое место',
    'egress.notMonitored': 'Не отслеживается (не режим туннеля)',
    'logs.title': 'Логи', 'logs.error': 'Ошибки', 'logs.warn': 'Предупр.', 'logs.stats': 'Статы', 'logs.searchPh': 'Поиск в логах', 'logs.jumpLatest': 'К последним',
    'modal.deleteUser': 'Удалить пользователя', 'modal.deleteTunnel': 'Удалить туннель', 'modal.restartNote': 'Прокси будет перезапущен для применения изменений.',
    'share.subtitle': 'Наведите камеру их телефона на этот код, чтобы подключиться.', 'share.copyLink': 'Скопировать ссылку', 'share.send': 'Отправить', 'share.with': 'Поделиться с',
    'status.online': 'Онлайн', 'status.offline': 'Офлайн', 'status.stuck': 'Завис',
    'status.healthy': 'Здоров', 'status.needsAttention': 'Требует внимания', 'status.disabled': 'Выключено', 'status.remoteMode': 'Удалённый режим', 'status.endpointOk': 'OK', 'status.endpointDown': 'не отвечает',
    'hero.checking': 'Проверка…', 'hero.offline': 'Прокси офлайн — близкие не смогут подключиться, пока он не запустится.',
    'hero.stalled': 'Прокси запущен, но не отвечает — похоже, завис. Обычно помогает перезапуск.',
    'hero.idle': 'Прокси онлайн и готов. Пока никто не подключён — поделитесь ссылкой, чтобы начать.',
    'hero.busy': 'Всё работает. Сейчас подключено: {n}.',
    'hero.vChecking': 'Проверка…', 'hero.vOffline': 'Офлайн', 'hero.vStalled': 'Завис', 'hero.vIdle': 'Тишина — простой', 'hero.vBusy': 'Активно — {n} на связи',
    'hero.connected': 'Подключено', 'hero.uptimeLbl': 'Аптайм',
    'toast.connected': 'Кто-то только что подключился через ваш прокси.',
    'toast.linkCopied': 'Ссылка скопирована — отправьте близкому.',
    'autoscroll.on': 'Автопрокрутка: вкл', 'autoscroll.off': 'Автопрокрутка: выкл', 'btn.pause': 'Пауза', 'btn.resume': 'Продолжить',
  },
};
let LANG = localStorage.getItem('dashLang') || 'en';
function t(k) { return (I18N[LANG] && I18N[LANG][k]) || (I18N.en && I18N.en[k]) || k; }
function applyStaticI18n() {
  document.documentElement.setAttribute('lang', LANG);
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.getAttribute('data-i18n')); });
  document.querySelectorAll('[data-i18n-ph]').forEach(el => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
  const tg = $('langToggle');
  if (tg) {
    const cells = tg.querySelectorAll('.lang-cell');
    if (cells.length) cells.forEach((c) => c.classList.toggle('on', c.dataset.lang === LANG));
    else tg.textContent = (LANG === 'ru') ? 'EN' : 'RU';
  }
}
function setLang(l) { LANG = (l === 'ru') ? 'ru' : 'en'; localStorage.setItem('dashLang', LANG); applyStaticI18n(); }
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
let currentRouting = null;
let lastEgress = null; // store last /api/egress response for re-render on lang toggle

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

function formatHistoryWindowLabel() {
  const seconds = Math.round((MH * pollIntervalMs) / 1000);
  if (seconds >= 240) return 'LAST ' + Math.round(seconds / 60) + 'M';
  if (seconds >= 90) return 'LAST ' + Math.round(seconds / 60) + ' MIN';
  return 'LAST ' + seconds + 'S';
}

function updateNetworkWindowLabel() {
  const el = document.querySelector('.net-window');
  if (el) el.textContent = formatHistoryWindowLabel();
}

// ── Gauges ──
function setGauge(arcId, pctId, val) {
  // 270° arc (gap at the bottom) on a r=15 circle: full circumference ≈ 94.25,
  // 270° ≈ 70.69. The arc is rotated -via CSS- so the gap sits at 6 o'clock.
  const ARC = 70.69;
  const v = Math.max(0, Math.min(100, Number(val) || 0));
  $(arcId).style.strokeDasharray = (ARC * v / 100).toFixed(2) + ' 94.25';
  // Signal-threshold colour ramp — the full-saturation amber stays reserved for
  // the status hero, so the dial earns its colour from the value band instead.
  const col = v < 60 ? 'var(--signal-go)' : (v < 85 ? 'var(--signal-caution)' : 'var(--signal-stop)');
  $(arcId).style.stroke = col;
  $(pctId).textContent = val;   // unit "%" is a separate .gauge-unit element
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
  resizeCanvas();   // self-size each draw (like the sparklines) so the chart is
                    // robust to first-paint timing and container width changes
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
    ctx.strokeStyle = 'rgba(39,47,56,0.8)';
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
  drawLine('rx', 'rgb(92,130,201)');
}

canvas.addEventListener('mousemove', e => {
  showTooltip(e, canvas, 42, lastData?.net_history, item => 
    `<div class="tooltip-val" style="color:var(--blue)">RX: ${fmt(item.rx)}</div><div class="tooltip-val" style="color:var(--zig)">TX: ${fmt(item.tx)}</div>`
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

  const PAD = 2;        // no axis labels (Paper-clean trace) → minimal left gutter
  const PAD_TOP = 6;    // top padding
  const cw = w - PAD;
  const ch = h - PAD_TOP;
  const step = cw / (MH - 1);
  const off = MH - data.length;

  x.clearRect(0, 0, w, h);

  // Paper sparkline: a clean seismograph trace with one faint baseline rule —
  // no Y-axis ticks/labels (those "100%/50%" marks floated in the empty cell).
  x.strokeStyle = 'rgba(39,47,56,0.8)';
  x.lineWidth = 1;
  x.beginPath();
  x.moveTo(PAD, PAD_TOP + ch);
  x.lineTo(w, PAD_TOP + ch);
  x.stroke();

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
  cpuCanvas.addEventListener('mousemove', e => showTooltip(e, cpuCanvas, 32, lastData?.cpu_history, item => `<div class="tooltip-val" style="color:var(--text)">Util: ${item.v}%</div>`));
  cpuCanvas.addEventListener('mouseleave', hideTooltip);
}
const memCanvas = $('memSpark');
if (memCanvas) {
  memCanvas.addEventListener('mousemove', e => showTooltip(e, memCanvas, 32, lastData?.mem_history, item => `<div class="tooltip-val" style="color:var(--text)">Mem: ${item.v}%</div>`));
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

// ── User Management ──

let pendingDeleteUser = null;
let pendingDeleteTunnel = null;
let pendingToggleUser = null;

function showToast(msg, type) {
  const el = document.createElement('div');
  el.className = 'toast ' + (type || 'info');
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

// One plain-language verdict at the top of the page — the answer to the only
// question most people open the dashboard to ask: "is everything OK?"
function setStatusHero(online, active, state) {
  const el = $('statusHero'), icon = $('statusHeroIcon'), txt = $('statusHeroText'), sub = $('statusHeroSub');
  if (!el) return;
  // Paper hero: fixed surface-1 panel; only the signal square (#statusHeroIcon,
  // background:currentColor) + verdict take the state colour. Short verdict on top,
  // descriptive sub-line beneath (the right-side figures are filled in poll()).
  el.style.background = '';
  if (icon) icon.textContent = '';
  let color, signalColor, verdict, subline;
  if (!online) {
    color = 'var(--signal-stop)'; signalColor = color; verdict = t('hero.vOffline'); subline = t('hero.offline');
  } else if (state === 'stalled') {
    color = 'var(--signal-caution)'; signalColor = color; verdict = t('hero.vStalled'); subline = t('hero.stalled');
  } else if (active > 0) {
    color = 'var(--accent)'; signalColor = 'var(--signal-go)'; verdict = t('hero.vBusy').replace('{n}', active); subline = t('hero.busy').replace('{n}', active);
  } else {
    color = 'var(--signal-go)'; signalColor = color; verdict = t('hero.vIdle'); subline = t('hero.idle');
  }
  el.style.color = color;
  el.style.setProperty('--hero-signal-color', signalColor);
  txt.textContent = verdict;
  if (sub) sub.textContent = subline;
}

// The "share with someone you love" moment: a scannable QR + one-tap send.
function closeShareModal() {
  const o = document.getElementById('shareModalOverlay');
  if (o) o.remove();
}
function openShareModal(name, link) {
  closeShareModal();
  const overlay = document.createElement('div');
  overlay.id = 'shareModalOverlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:1000;';
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeShareModal(); });
  const box = document.createElement('div');
  box.style.cssText = 'background:var(--bg-card,#16181d);border:1px solid var(--border,#333);border-radius:14px;padding:22px;max-width:340px;text-align:center;color:var(--text,#eee);font-family:inherit;';
  box.innerHTML =
    '<div style="font-size:16px;font-weight:700;margin-bottom:4px;">' + t('share.with') + ' ' + esc(name || 'this person') + '</div>' +
    '<div style="font-size:13px;color:var(--text-muted,#999);margin-bottom:14px;">' + t('share.subtitle') + '</div>' +
    '<img src="/api/qr?text=' + encodeURIComponent(link) + '" alt="QR code" style="width:240px;height:240px;background:#fff;border-radius:10px;padding:8px;box-sizing:border-box;" />' +
    '<div style="display:flex;gap:8px;margin-top:16px;">' +
    '<button class="ui-btn" id="shareCopyBtn" style="flex:1;">' + t('share.copyLink') + '</button>' +
    '<button class="ui-btn" id="shareSendBtn" style="flex:1;">' + t('share.send') + '</button>' +
    '</div>' +
    '<button class="ui-btn" id="shareCloseBtn" style="margin-top:10px;width:100%;">' + t('btn.close') + '</button>';
  overlay.appendChild(box);
  document.body.appendChild(overlay);
  document.getElementById('shareCopyBtn').addEventListener('click', async () => {
    await copyText(link);
    showToast(t('toast.linkCopied'), 'success');
  });
  document.getElementById('shareSendBtn').addEventListener('click', () => {
    if (navigator.share) {
      navigator.share({ title: 'Telegram proxy', text: 'Tap to connect to Telegram — I set this up for you:', url: link }).catch(() => {});
    } else {
      copyText(link);
      showToast('Link copied — paste it to share.', 'success');
    }
  });
  document.getElementById('shareCloseBtn').addEventListener('click', closeShareModal);
}

async function apiCall(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await r.json();
  if (!r.ok || !data.ok) {
    throw new Error(data.error || 'request failed');
  }
  return data;
}

function setupAddUserForm() {
  const btn = $('addUserBtn');
  const form = $('addUserForm');
  const nameInput = $('newUserName');
  const secretInput = $('newUserSecret');
  const submitBtn = $('addUserSubmit');
  const cancelBtn = $('addUserCancel');
  const status = $('addUserStatus');

  btn.addEventListener('click', () => {
    form.style.display = form.style.display === 'none' ? '' : 'none';
    if (form.style.display !== 'none') {
      nameInput.value = '';
      secretInput.value = '';
      status.textContent = '';
      nameInput.focus();
    }
  });

  cancelBtn.addEventListener('click', () => {
    form.style.display = 'none';
    status.textContent = '';
  });

  async function doAdd() {
    const name = nameInput.value.trim();
    const secret = secretInput.value.trim();
    if (!name) {
      status.textContent = 'Username is required';
      status.className = 'form-status error';
      return;
    }

    submitBtn.disabled = true;
    status.textContent = 'Creating user & restarting proxy...';
    status.className = 'form-status info';

    try {
      const data = await apiCall('/api/users/add', { name, secret: secret || undefined });
      showToast(`Done! Here is ${data.label || data.name}'s connection — send it to them now.`, 'success');
      form.style.display = 'none';
      _users_cache_bust();
      await runPoll();
      // End the create flow in the share moment: open the QR modal for the new user
      // (names are restricted to [a-zA-Z0-9_-], so the selector needs no escaping).
      const shareBtn = document.querySelector('.user-share[data-name="' + data.name + '"]');
      if (shareBtn && !shareBtn.disabled) shareBtn.click();
    } catch (e) {
      status.textContent = e.message;
      status.className = 'form-status error';
    } finally {
      submitBtn.disabled = false;
    }
  }

  submitBtn.addEventListener('click', doAdd);
  nameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAdd(); });
  secretInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAdd(); });
}

function setupDeleteModal() {
  const modal = $('deleteModal');
  const confirmBtn = $('deleteConfirm');
  const cancelBtn = $('deleteCancel');

  cancelBtn.addEventListener('click', () => {
    modal.style.display = 'none';
    pendingDeleteUser = null;
  });

  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.style.display = 'none';
      pendingDeleteUser = null;
    }
  });

  confirmBtn.addEventListener('click', async () => {
    if (!pendingDeleteUser) return;
    confirmBtn.disabled = true;
    try {
      await apiCall('/api/users/remove', { name: pendingDeleteUser });
      showToast(`User "${pendingDeleteUser}" deleted. Proxy restarted.`, 'success');
      _users_cache_bust();
      await runPoll();
    } catch (e) {
      showToast('Delete failed: ' + e.message, 'error');
    } finally {
      confirmBtn.disabled = false;
      modal.style.display = 'none';
      pendingDeleteUser = null;
    }
  });
}

function showDeleteModal(name) {
  pendingDeleteUser = name;
  $('deleteUserName').textContent = name;
  $('deleteModal').style.display = '';
  $('deleteConfirm').focus();
}

function setupTunnelDeleteModal() {
  const modal = $('deleteTunnelModal');
  const confirmBtn = $('deleteTunnelConfirm');
  const cancelBtn = $('deleteTunnelCancel');
  if (!modal || !confirmBtn || !cancelBtn) return;

  const close = () => {
    modal.style.display = 'none';
    pendingDeleteTunnel = null;
  };

  cancelBtn.addEventListener('click', close);

  modal.addEventListener('click', (e) => {
    if (e.target === modal) close();
  });

  modal.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
  });

  confirmBtn.addEventListener('click', async () => {
    if (!pendingDeleteTunnel) return;
    const iface = pendingDeleteTunnel;
    confirmBtn.disabled = true;
    setRoutingAction('Deleting tunnel ' + iface + '…');
    try {
      const data = await apiCall('/api/routing/tunnel-delete', { interface: iface });
      const left = Array.isArray(data.remaining_pool) ? data.remaining_pool.length : 0;
      const msg = data.removed_last
        ? ('Tunnel ' + iface + ' deleted. No tunnels left; upstream switched to auto.')
        : ('Tunnel ' + iface + ' deleted. ' + left + ' tunnel(s) remain.');
      showToast(msg, 'success');
      setRoutingAction(msg, 'ok');
      await runPoll();
    } catch (e) {
      setRoutingAction('Delete failed: ' + e.message, 'error');
      showToast('Delete failed: ' + e.message, 'error');
    } finally {
      confirmBtn.disabled = false;
      close();
    }
  });
}

function showTunnelDeleteModal(iface) {
  pendingDeleteTunnel = iface;
  $('deleteTunnelName').textContent = iface;
  $('deleteTunnelModal').style.display = '';
  $('deleteTunnelConfirm').focus();
}

async function toggleDirect(name, newDirect) {
  try {
    await apiCall('/api/users/direct', { name, direct: newDirect });
    showToast(`User "${name}" is now ${newDirect ? 'direct' : 'default'}. Proxy restarted.`, 'success');
    _users_cache_bust();
    await runPoll();
  } catch (e) {
    showToast('Failed: ' + e.message, 'error');
  }
}

async function toggleUserEnabled(name, newEnabled) {
  try {
    await apiCall('/api/users/toggle', { name, enabled: newEnabled });
    showToast(`User "${name}" ${newEnabled ? 'enabled' : 'disabled'}. Proxy restarted.`, 'success');
    _users_cache_bust();
    await runPoll();
  } catch (e) {
    showToast('Failed: ' + e.message, 'error');
  }
}

function _users_cache_bust() {
  // Force next poll to show fresh data
  if (lastData && lastData.users) {
    lastData.users = null;
  }
}

function renderUsers(users, perUserActive, proxyStats) {
  const card = $('usersCard');
  if (!card) return;
  const pua = perUserActive || {};
  const ps = proxyStats || {};

  const meta = $('usersMeta');
  const note = $('usersNote');
  const list = $('usersList');
  card.style.display = '';

  const items = (users && Array.isArray(users.items)) ? users.items : [];
  const total = Number(users?.total || 0);
  const directTotal = Number(users?.direct_total || 0);
  const disabledTotal = Number(users?.disabled_total || 0);
  const usersActiveTotal = Number(ps.users_active_total || Object.values(pua).reduce((acc, v) => acc + Number(v || 0), 0));
  const activeTotal = Number(ps.active || 0);
  const unassignedActive = Number(ps.unassigned_active || Math.max(activeTotal - usersActiveTotal, 0));

  let metaText = total + ' users · direct ' + directTotal;
  if (disabledTotal > 0) metaText += ' · disabled ' + disabledTotal;
  if (activeTotal > 0 || usersActiveTotal > 0) {
    metaText += ' · sessions ' + usersActiveTotal + '/' + activeTotal;
    if (unassignedActive > 0) metaText += ' · unassigned ' + unassignedActive;
  }
  meta.textContent = metaText;

  if (!users?.links_ready) {
    note.textContent = "We couldn't detect your server's public IP, so connection links aren't ready yet. Add your server's IP in the config and the links will appear.";
  } else {
    note.textContent = users.server + ':' + users.port + ' · tls_domain=' + (users.tls_domain || '—');
  }

  if (items.length === 0) {
    list.innerHTML = '<div class="user-empty">No users configured in [access.users].</div>';
    return;
  }

  list.innerHTML = items.map((u) => {
    const isEnabled = u.enabled !== false;
    const tg = u.tg_link || '';
    const tme = u.tme_link || '';
    const preview = isEnabled ? shortProxyLink(tg || tme) : 'disabled';
    const tgData = encodeURIComponent(tg);
    const tmeData = encodeURIComponent(tme);
    const userName = esc(u.name || 'user');
    const displayName = esc(u.label || u.name || 'user');
    const rowClass = isEnabled ? 'user-row' : 'user-row disabled';
    const sessions = Number(pua[u.name] || 0);
    const sessionsBadge = isEnabled
      ? '<span class="user-sessions' + (sessions > 0 ? '' : ' zero') + '">' + sessions + '</span>'
      : '';

    // Enable/disable toggle switch
    const toggleSwitch = '<label class="user-toggle-switch" title="' + (isEnabled ? 'Disable user' : 'Enable user') + '">' +
      '<input type="checkbox" class="user-enabled-toggle" data-user="' + userName + '"' + (isEnabled ? ' checked' : '') + '>' +
      '<span class="user-toggle-slider"></span>' +
      '</label>';

    const directToggle = !isEnabled ? '' : (u.direct
      ? '<button class="ui-btn user-direct-toggle on" type="button" data-user="' + userName + '" data-direct="false" title="Switch to default route">direct</button>'
      : '<button class="ui-btn user-direct-toggle" type="button" data-user="' + userName + '" data-direct="true" title="Switch to direct route">default</button>');

    return '<div class="' + rowClass + '">' +
      '<div class="user-name">' + toggleSwitch + '<span class="user-name-text">' + displayName + '</span>' + sessionsBadge + '</div>' +
      '<div class="user-route">' + directToggle + '</div>' +
      '<div class="user-link" title="' + esc(tg || tme || (isEnabled ? 'link unavailable' : 'disabled')) + '">' + esc(preview) + '</div>' +
      '<div class="user-actions">' +
      '<button class="ui-btn user-share" type="button" data-link="' + tmeData + '" data-name="' + userName + '" data-label="' + displayName + '"' + (tme && isEnabled ? '' : ' disabled') + ' title="Share via QR">' + ICON['qr-share'] + '</button>' +
      '<button class="ui-btn user-copy" type="button" data-link="' + tgData + '"' + (tg && isEnabled ? '' : ' disabled') + ' title="Copy tg:// link">tg://</button>' +
      '<button class="ui-btn user-copy" type="button" data-link="' + tmeData + '"' + (tme && isEnabled ? '' : ' disabled') + ' title="Copy t.me link">t.me</button>' +
      '<button class="ui-btn danger user-delete" type="button" data-user="' + userName + '" title="Delete user">' + ICON['delete'] + '</button>' +
      '</div>' +
      '</div>';
  }).join('');

  // Copy buttons
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

  // Share buttons → QR modal (the "send it to someone you love" moment)
  list.querySelectorAll('.user-share').forEach((btn) => {
    btn.addEventListener('click', () => {
      const link = decodeURIComponent(btn.dataset.link || '');
      if (link) openShareModal(btn.dataset.label || btn.dataset.name || '', link);
    });
  });

  // Enable/disable toggles
  list.querySelectorAll('.user-enabled-toggle').forEach((cb) => {
    cb.addEventListener('change', () => {
      const name = cb.dataset.user;
      toggleUserEnabled(name, cb.checked);
    });
  });

  // Direct toggle buttons
  list.querySelectorAll('.user-direct-toggle').forEach((btn) => {
    btn.addEventListener('click', () => {
      const name = btn.dataset.user;
      const newDirect = btn.dataset.direct === 'true';
      toggleDirect(name, newDirect);
    });
  });

  // Delete buttons
  list.querySelectorAll('.user-delete').forEach((btn) => {
    btn.addEventListener('click', () => {
      showDeleteModal(btn.dataset.user);
    });
  });
}

function setRoutingAction(msg, cls) {
  const note = $('routingActionNote');
  if (!note) return;
  note.textContent = msg || '';
  note.className = 'routing-action-note' + (cls ? (' ' + cls) : '');
}

function setMiddleProxyButton(enabled, pending) {
  const middleBtn = $('routingMiddleBtn');
  if (!middleBtn) return;
  const on = Boolean(enabled);
  const label = middleBtn.querySelector('.routing-toggle-text');
  if (label) label.textContent = on ? 'On' : 'Off';
  else middleBtn.textContent = on ? 'On' : 'Off';
  middleBtn.classList.toggle('active', on);
  middleBtn.classList.toggle('is-pending', Boolean(pending));
  middleBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
  middleBtn.setAttribute('aria-busy', pending ? 'true' : 'false');
}

function setupRoutingControls() {
  const middleBtn = $('routingMiddleBtn');
  const upstreamSelect = $('routingUpstreamSelect');
  const upstreamApply = $('routingUpstreamApply');
  const tunnelIfaceSelect = $('routingTunnelIfaceSelect');
  const tunnelIfaceApply = $('routingTunnelIfaceApply');
  const proxyHostInput = $('routingProxyHost');
  const proxyPortInput = $('routingProxyPort');
  const proxyUserInput = $('routingProxyUser');
  const proxyPassInput = $('routingProxyPass');
  const proxyApply = $('routingProxyApply');
  if (!middleBtn || !upstreamSelect || !upstreamApply) return;

  async function commitMiddleProxyToggle() {
    if (!currentRouting || middleBtn.dataset.pending === '1') return;

    const previous = Boolean(currentRouting.middle_proxy_enabled);
    const target = !previous;
    middleBtn.dataset.pending = '1';
    middleBtn.dataset.target = target ? '1' : '0';
    currentRouting.middle_proxy_enabled = target;
    setMiddleProxyButton(target, true);
    setRoutingAction('');

    try {
      const data = await apiCall('/api/routing/middle', { enabled: target });
      currentRouting.middle_proxy_enabled = Boolean(data.enabled);
      setMiddleProxyButton(currentRouting.middle_proxy_enabled, false);
      setRoutingAction('MiddleProxy ' + (data.enabled ? 'enabled' : 'disabled') + '. Proxy restarted.', 'ok');
      showToast('MiddleProxy ' + (data.enabled ? 'enabled' : 'disabled') + '. Proxy restarted.', 'success');
      await runPoll();
    } catch (e) {
      currentRouting.middle_proxy_enabled = previous;
      setMiddleProxyButton(previous, false);
      setRoutingAction('Failed: ' + e.message, 'error');
      showToast('Failed: ' + e.message, 'error');
    } finally {
      delete middleBtn.dataset.pending;
      delete middleBtn.dataset.target;
      setMiddleProxyButton(Boolean(currentRouting && currentRouting.middle_proxy_enabled), false);
    }
  }

  middleBtn.addEventListener('pointerdown', (event) => {
    if (event.button !== undefined && event.button !== 0) return;
    event.preventDefault();
    middleBtn.focus({ preventScroll: true });
    void commitMiddleProxyToggle();
  });

  middleBtn.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    void commitMiddleProxyToggle();
  });

  upstreamApply.addEventListener('click', async () => {
    if (!currentRouting) return;

    const nextType = String(upstreamSelect.value || '').toLowerCase();
    if (!nextType) return;

    if (nextType === String(currentRouting.upstream_type || '').toLowerCase()) {
      setRoutingAction('Upstream is already set to ' + nextType + '.');
      return;
    }

    upstreamApply.disabled = true;
    upstreamSelect.disabled = true;
    setRoutingAction('Switching upstream to ' + nextType + '…');

    try {
      const data = await apiCall('/api/routing/upstream', { type: nextType });
      const warn = data.warning ? (' Warning: ' + data.warning) : '';
      setRoutingAction('Upstream switched to ' + data.type + '. Proxy restarted.' + warn, data.warning ? '' : 'ok');
      showToast('Upstream switched to ' + data.type + '. Proxy restarted.', 'success');
      await runPoll();
    } catch (e) {
      setRoutingAction('Failed: ' + e.message, 'error');
      showToast('Failed: ' + e.message, 'error');
    } finally {
      upstreamApply.disabled = false;
      upstreamSelect.disabled = false;
    }
  });
  upstreamSelect.addEventListener('change', () => {
    if (!upstreamApply.disabled) upstreamApply.click();
  });

  if (tunnelIfaceApply && tunnelIfaceSelect) {
    tunnelIfaceApply.addEventListener('click', async () => {
      if (!currentRouting) return;

      const iface = String(tunnelIfaceSelect.value || '').trim();
      const currentPinned = String(currentRouting.pinned_tunnel_interface || '');
      if (iface === currentPinned) {
        setRoutingAction(iface ? ('Tunnel interface is already pinned to ' + iface + '.') : 'Tunnel pool is already in priority-auto mode.');
        return;
      }

      tunnelIfaceApply.disabled = true;
      tunnelIfaceSelect.disabled = true;
      setRoutingAction(iface ? ('Pinning tunnel interface to ' + iface + '…') : 'Clearing tunnel pin…');

      try {
        const data = await apiCall('/api/routing/tunnel-interface', iface ? { interface: iface } : { clear: true });
        const msg = data.pinned_interface
          ? ('Tunnel pinned to ' + data.pinned_interface + '. Controller checked pool.')
          : 'Tunnel pin cleared. Priority auto-failback restored.';
        setRoutingAction(msg, data.controller_ok ? 'ok' : '');
        showToast(msg, 'success');
        await runPoll();
      } catch (e) {
        setRoutingAction('Failed: ' + e.message, 'error');
        showToast('Failed: ' + e.message, 'error');
      } finally {
        tunnelIfaceApply.disabled = false;
        tunnelIfaceSelect.disabled = false;
      }
    });
    tunnelIfaceSelect.addEventListener('change', () => {
      if (!tunnelIfaceApply.disabled) tunnelIfaceApply.click();
    });
  }

  if (proxyApply && proxyHostInput && proxyPortInput && proxyUserInput && proxyPassInput) {
    proxyApply.addEventListener('click', async () => {
      if (!currentRouting) return;

      const proxyType = String(currentRouting.upstream_type || '').toLowerCase();
      if (proxyType !== 'socks5' && proxyType !== 'http') {
        setRoutingAction('Proxy target can be set only for socks5/http upstream.', 'error');
        return;
      }

      const host = String(proxyHostInput.value || '').trim();
      const port = Number(proxyPortInput.value || 0);
      const username = String(proxyUserInput.value || '');
      const password = String(proxyPassInput.value || '');
      if (!host) {
        setRoutingAction('Proxy host is required.', 'error');
        return;
      }
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        setRoutingAction('Proxy port must be 1..65535.', 'error');
        return;
      }
      if (username.includes('\n') || username.includes('\r') || password.includes('\n') || password.includes('\r')) {
        setRoutingAction('Username/password must not contain newlines.', 'error');
        return;
      }

      proxyApply.disabled = true;
      proxyHostInput.disabled = true;
      proxyPortInput.disabled = true;
      proxyUserInput.disabled = true;
      proxyPassInput.disabled = true;
      setRoutingAction('Updating ' + proxyType + ' target…');

      try {
        const data = await apiCall('/api/routing/proxy-target', { type: proxyType, host, port, username, password });
        setRoutingAction('Updated ' + data.type + ' target to ' + data.host + ':' + data.port + '. Proxy restarted.', 'ok');
        showToast('Updated ' + data.type + ' target. Proxy restarted.', 'success');
        await runPoll();
      } catch (e) {
        setRoutingAction('Failed: ' + e.message, 'error');
        showToast('Failed: ' + e.message, 'error');
      } finally {
        proxyApply.disabled = false;
        proxyHostInput.disabled = false;
        proxyPortInput.disabled = false;
        proxyUserInput.disabled = false;
        proxyPassInput.disabled = false;
      }
    });
  }
}

function renderRouting(routing) {
  const card = $('routingCard');
  if (!card) return;

  if (!routing) {
    currentRouting = null;
    card.style.display = 'none';
    return;
  }

  currentRouting = routing;
  card.style.display = '';

  const middleBtn = $('routingMiddleBtn');
  if (middleBtn) {
    const pending = middleBtn.dataset.pending === '1';
    const pendingTarget = middleBtn.dataset.target === '1';
    setMiddleProxyButton(pending ? pendingTarget : Boolean(routing.middle_proxy_enabled), pending);
  }

  const upstreamSelect = $('routingUpstreamSelect');
  const upstreamType = String(routing.upstream_type || 'auto').toLowerCase();
  if (upstreamSelect) {
    upstreamSelect.value = upstreamType;
  }

  const tunnelCtl = $('routingTunnelCtl');
  const tunnelSelect = $('routingTunnelIfaceSelect');
  const tunnelApplyBtn = $('routingTunnelIfaceApply');
  if (tunnelCtl && tunnelSelect) {
    if (upstreamType === 'tunnel') {
      tunnelCtl.style.display = '';
      const choices = Array.isArray(routing.tunnel_pool)
        ? routing.tunnel_pool
        : [];
      const selectedIface = String(
        routing.pinned_tunnel_interface ||
        routing.active_tunnel_interface ||
        routing.selected_tunnel_interface ||
        ''
      );
      const seen = new Set();
      const options = [''];

      if (selectedIface && choices.includes(selectedIface)) {
        seen.add(selectedIface);
        options.push(selectedIface);
      }

      choices.forEach((iface) => {
        const v = String(iface || '').trim();
        if (!v || seen.has(v)) return;
        seen.add(v);
        options.push(v);
      });

      if (options.length <= 1 && !choices.length) {
        tunnelSelect.innerHTML = '<option value="">no interfaces</option>';
        tunnelSelect.value = '';
        tunnelSelect.disabled = true;
        if (tunnelApplyBtn) tunnelApplyBtn.disabled = true;
      } else {
        tunnelSelect.disabled = false;
        if (tunnelApplyBtn) tunnelApplyBtn.disabled = false;
        tunnelSelect.innerHTML = options
          .map((iface) => iface
            ? '<option value="' + esc(iface) + '">' + esc(iface) + '</option>'
            : '<option value="">priority auto</option>')
          .join('');
        tunnelSelect.value = selectedIface || '';
      }
    } else {
      tunnelCtl.style.display = 'none';
    }
  }

  const proxyCtl = $('routingProxyCtl');
  const proxyHost = $('routingProxyHost');
  const proxyPort = $('routingProxyPort');
  const proxyUser = $('routingProxyUser');
  const proxyPass = $('routingProxyPass');
  const proxyHostLabel = $('routingProxyHostLabel');
  if (proxyCtl && proxyHost && proxyPort && proxyUser && proxyPass && proxyHostLabel) {
    if (upstreamType === 'socks5' || upstreamType === 'http') {
      proxyCtl.style.display = '';
      const cfg = upstreamType === 'socks5'
        ? (routing.upstream_socks5 || {})
        : (routing.upstream_http || {});
      const host = String(cfg.host || '');
      const port = Number(cfg.port || 0);
      const username = String(cfg.username || '');
      const password = String(cfg.password || '');

      proxyHostLabel.textContent = upstreamType + ' host';
      proxyHost.placeholder = upstreamType === 'socks5' ? '127.0.0.1' : '127.0.0.1';
      proxyPort.placeholder = upstreamType === 'socks5' ? '1080' : '8080';
      // Don't overwrite inputs while user is typing (fix for field reset bug)
      const proxyInputs = [proxyHost, proxyPort, proxyUser, proxyPass];
      const anyFocused = proxyInputs.some(el => el === document.activeElement);
      if (!anyFocused) {
        proxyHost.value = host;
        proxyPort.value = port > 0 ? String(port) : '';
        proxyUser.value = username;
        proxyPass.value = password;
      }
    } else {
      proxyCtl.style.display = 'none';
    }
  }

  const badge = $('routingBadge');
  if (routing.healthy) {
    badge.className = 'badge';
    $('routingStatus').textContent = t('status.healthy');
  } else {
    badge.className = 'badge off';
    $('routingStatus').textContent = t('status.needsAttention');
  }

  $('routingMiddle').textContent = routing.middle_proxy_enabled ? 'enabled' : 'disabled';
  $('routingUpstream').textContent = upstreamType || '—';
  const tunnelTarget = routing.primary_tunnel && routing.primary_tunnel.endpoint
    ? routing.primary_tunnel.endpoint
    : '';
  $('routingTarget').textContent = (upstreamType === 'tunnel' && tunnelTarget)
    ? tunnelTarget
    : (routing.upstream_target || '—');

  const policy = routing.policy || {};
  const poolTotal = Array.isArray(routing.tunnel_pool)
    ? routing.tunnel_pool.length
    : Number(routing.detected_tunnels || 0);
  const poolHealthy = Number(
    routing.healthy_tunnels != null
      ? routing.healthy_tunnels
      : (routing.active_tunnels != null ? routing.active_tunnels : 0)
  );
  const poolTxt = poolTotal > 0 ? (poolHealthy + '/' + poolTotal) : routing.pool_status;
  const policyTxt = (policy.rule_ok ? 'rule ok' : 'rule missing') +
    (poolTxt
      ? (' · pool ' + poolTxt)
      : (' · ' + (policy.route_ok ? 'route ok' : 'route missing')));
  $('routingPolicy').innerHTML = '<span class="signal-sq"></span>' + esc(policyTxt);

  const list = $('routingTunnelsList');
  const tunnels = Array.isArray(routing.tunnels) ? routing.tunnels : [];
  if (!tunnels.length) {
    list.innerHTML = '<div class="routing-empty">No tunnel interfaces detected.</div>';
    return;
  }

  const selected = routing.active_tunnel_interface || routing.selected_tunnel_interface || '';
  const pinned = routing.pinned_tunnel_interface || '';

  list.innerHTML = tunnels.map((t) => {
    const iface = String(t.interface || '—');
    const isSelected = upstreamType === 'tunnel' && iface === selected;
    const isPinned = pinned && iface === pinned;
    const inPool = Boolean(t.in_pool);
    const state = t.healthy ? 'healthy' : (t.active ? 'active' : (t.link_up ? 'up' : 'down'));
    const stateClass = t.healthy ? 'on' : (t.active || t.link_up ? 'mid' : 'off');

    const meta = [];
    if (inPool) meta.push('pool');
    if (t.config_present && !inPool) meta.push('config');
    if (isPinned) meta.push('pinned');
    if (t.tool && t.tool !== '-') meta.push(String(t.tool));
    if (t.endpoint) meta.push(String(t.endpoint));
    if (t.handshake) meta.push('hs: ' + String(t.handshake));
    if (t.probe) meta.push(String(t.probe));
    if (!meta.length) meta.push(String(t.reason || '—'));

    const xfer = '↓ ' + String(t.rx || '—') + ' · ↑ ' + String(t.tx || '—');
    const canDelete = inPool || t.config_present || t.link_up || iface.startsWith('awg') || iface.startsWith('wg');

    return '<div class="routing-row">' +
      '<div class="routing-row-top">' +
        '<div class="routing-iface"><span class="routing-iface-name">' + esc(iface) + '</span>' +
        (isSelected ? '<span class="routing-tag">active</span>' : '') +
        (isPinned ? '<span class="routing-tag">pinned</span>' : '') +
        '</div>' +
        '<div class="routing-state ' + stateClass + '">' + esc(state) + '</div>' +
      '</div>' +
      '<div class="routing-row-bottom">' +
        '<div class="routing-meta" title="' + esc(meta.join(' · ')) + '">' + esc(meta.join(' · ')) + '</div>' +
        '<div class="routing-xfer">' + esc(xfer) + '</div>' +
      '</div>' +
      (canDelete
        ? '<div class="routing-actions"><button class="ui-btn danger routing-delete" type="button" data-iface="' + esc(iface) + '" aria-label="Delete tunnel ' + esc(iface) + '">' + ICON['delete'] + '</button></div>'
        : '') +
      '</div>';
  }).join('');

  list.querySelectorAll('.routing-delete').forEach((btn) => {
    btn.addEventListener('click', () => {
      const iface = String(btn.dataset.iface || '').trim();
      if (iface) showTunnelDeleteModal(iface);
    });
  });
}

// ── Egress / tunnel quality ──
function fmtHandshakeAge(sec) {
  if (sec === null || sec === undefined) return '—';
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec / 60) + 'm';
  return Math.floor(sec / 3600) + 'h';
}

function renderEgress(egress, opts) {
  const options = opts || {};
  if (!options.transient) lastEgress = egress;
  const card = $('egressCard');
  if (!card) return;

  if (!egress || !egress.tunnels || egress.tunnels.length === 0) {
    if (!options.transient) card.style.display = 'none';
    return;
  }

  card.style.display = '';

  const tunnels = egress.tunnels || [];
  const degradedCount = tunnels.filter((tun) => tun && (tun.quality === 'degraded' || tun.quality === 'poor')).length;
  const downCount = tunnels.filter((tun) => tun && tun.quality === 'down').length;
  const summaryText = tunnels.length
    ? (tunnels.length + ' · ' + (degradedCount
      ? (degradedCount + ' degraded')
      : (downCount ? (downCount + ' down') : 'healthy')))
    : '—';
  const summaryEl = $('egressSummary');
  if (summaryEl) summaryEl.textContent = summaryText || '—';

  const list = $('egressList');
  if (!list) return;

  list.innerHTML = tunnels.map((tun) => {
    const iface = esc(tun.interface || '—');
    const isPrimary = tun.is_primary;
    const quality = tun.quality || 'unknown';
    const rttText = tun.rtt_ms !== null && tun.rtt_ms !== undefined
      ? tun.rtt_ms.toFixed(1) + ' ms'
      : '—';
    const lossText = tun.packet_loss_pct !== null && tun.packet_loss_pct !== undefined
      ? tun.packet_loss_pct.toFixed(1) + '%'
      : '—';
    const hsText = fmtHandshakeAge(tun.handshake_age_sec);

    // Color code quality (good, degraded, poor, up, down, unknown)
    const qualityClass = 'egress-quality-' + quality;
    const qualityLabel = t('egress.' + quality) || quality;
    const _barPct = { good: 22, degraded: 72, poor: 92, up: 10, down: 100, unknown: 8 };
    const barPct = _barPct[quality] != null ? _barPct[quality] : 8;

    // "Tunnel is the bottleneck" hint when quality is degraded/poor.
    const isBottleneck = quality === 'degraded' || quality === 'poor';
    const bottleneck = isBottleneck
      ? '<div class="egress-bottleneck" title="' + t('egress.bottleneck') + '">' + ICON['warning'] + '<span>' + t('egress.bottleneck') + '</span></div>'
      : '';

    return '<div class="egress-row' + (isBottleneck ? ' is-bottleneck' : '') + ' q-' + quality + '">' +
      '<div class="egress-row-top">' +
        '<div class="egress-iface q-' + quality + '"><span class="signal-sq"></span><span class="egress-iface-name">' + iface + '</span>' +
        (isPrimary ? '<span class="routing-tag">' + t('egress.primary') + '</span>' : '') +
        '</div>' +
        '<div class="egress-quality ' + qualityClass + '">' + qualityLabel + '</div>' +
      '</div>' +
      '<div class="egress-metrics"><div class="egress-stats">' + rttText + ' · ' + lossText + ' loss · hs ' + hsText + '</div></div>' +
      '<div class="egress-bar"><div class="egress-bar-fill q-' + quality + '" style="width:' + barPct + '%"></div></div>' +
      bottleneck +
      '</div>';
  }).join('');
}

function renderEgressFromRouting(routing) {
  // Only surface tunnel/egress UI when egress actually goes through a tunnel. In
  // direct/socks5/http modes _routing_status still reports a placeholder awg0 probe
  // (the default interface, shown "down"), which otherwise flashed an orange tunnel
  // card on every poll until the async /api/egress (which knows the mode isn't tunnel)
  // cleared it again.
  if (!routing || String(routing.upstream_type || '').toLowerCase() !== 'tunnel') return;
  if (lastEgress && Array.isArray(lastEgress.tunnels) && lastEgress.tunnels.length) return;
  const tunnels = routing && Array.isArray(routing.tunnels) ? routing.tunnels : [];
  if (!tunnels.length) return;

  const fallbackEgress = {
    ok: true,
    primary_interface: routing.active_tunnel_interface || routing.selected_tunnel_interface || '',
    tunnels: tunnels.map((tun) => {
      const iface = String(tun.interface || '—');
      return {
        interface: iface,
        up: Boolean(tun.link_up || tun.active || tun.healthy),
        handshake_age_sec: null,
        rtt_ms: null,
        packet_loss_pct: null,
        quality: tun.healthy ? 'good' : ((tun.link_up || tun.active) ? 'up' : 'down'),
        is_primary: iface === (routing.active_tunnel_interface || routing.selected_tunnel_interface || ''),
      };
    }),
  };
  renderEgress(fallbackEgress, { transient: true });
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
  if (d.cpu_history) drawSpark('cpuSpark', d.cpu_history, 'rgb(154,163,174)', 100, '%');
  if (d.mem_history) drawSpark('memSpark', d.mem_history, 'rgb(154,163,174)', 100, '%');

  // Network
  drawNetChart();
  $('rxRate').textContent = fmt(d.net_rx);
  $('txRate').textContent = fmt(d.net_tx);
  $('rxTotal').textContent = fmtT(d.net_rx_total);
  $('txTotal').textContent = fmtT(d.net_tx_total);

  // Server
  const pi = d.proxy_info || {};
  const proxyUpEl = $('proxyUp');
  if (proxyUpEl) proxyUpEl.textContent = !pi.online ? t('status.offline') : (pi.state === 'stalled' ? t('status.stuck') : t('status.online'));
  const pidEl = $('proxyPid');
  if (pidEl) pidEl.textContent = pi.pid || '—';
  const rssEl = $('proxyRss');
  if (rssEl) rssEl.textContent = (pi.rss_mb || 0) + ' MB';
  const uptimeEl = $('proxyUptime');
  if (uptimeEl) uptimeEl.textContent = pi.uptime || d.uptime || '—';
  const statusBadgeEl = $('statusBadge');
  if (statusBadgeEl) statusBadgeEl.className = pi.online ? 'badge' : 'badge off';

  // Proxy stats
  const p = d.proxy || {};
  const _act = p.active || 0;
  // Celebrate the moment a real person first comes online through this proxy.
  if (window._prevActive != null && window._prevActive === 0 && _act > 0) {
    showToast(t('toast.connected'), 'success');
  }
  window._prevActive = _act;
  setStatusHero(pi.online, _act, pi.state);
  // hero right-side figures (Paper parity)
  const _hc = $('heroConnected'); if (_hc) _hc.textContent = _act;
  const _hu = $('heroUptime'); if (_hu) _hu.textContent = pi.uptime || d.uptime || '—';
  // CPU masthead "peak N%" (Paper parity)
  const _cp = $('cpuPeak');
  if (_cp) { const _pk = Math.max(Number(d.cpu) || 0, ...((d.cpu_history || []).map((p) => Number(p.v) || 0))); _cp.textContent = Math.round(_pk) + '%'; }
  $('pxActive').textContent = _act;
  $('pxMax').textContent = p.max || 0;
  $('pxHs').textContent = p.hs_inflight || 0;
  $('pxTotal').textContent = (p.total || 0).toLocaleString();
  const drp = p.rate_drops || 0;
  $('pxDrops').textContent = drp;
  $('pxDrops').style.color = drp > 0 ? 'var(--amber)' : 'var(--text-muted)';
  $('pxDrops').title = "Blocked connection attempts. Some of these are normal — it's your proxy turning away scanners and abuse. A steady small number is healthy.";
  $('pxDropLbl').textContent = 'rate +' + drp + ' · cap +' + (p.cap_drops || 0) + ' · hs_t +' + (p.hs_timeout || 0);


  // Version
  const vEl = $('dashboardVersion');
  if (vEl && d.proxy_version) {
    vEl.textContent = 'v' + d.proxy_version;
  }

  renderRouting(d.routing || null);
  renderEgressFromRouting(d.routing || null);

  // Egress / tunnel quality — fire-and-forget so a slow server-side ping/wg probe
  // never blocks rendering of the already-fetched masking/users data or stalls the
  // poll cycle. The card updates whenever this resolves.
  fetch('/api/egress', { cache: 'no-store' })
    .then((r) => (r.ok ? r.json() : null))
    .then((egressData) => { if (egressData && egressData.ok) renderEgress(egressData); })
    .catch(() => {}); // silent; egress monitoring is optional

  // Masking health
  const masking = d.masking;
  const mc = $('maskingCard');
  if (!masking) {
    mc.style.display = 'none';
  } else {
    mc.style.display = '';

    const maskBadge = $('maskBadge');
    const maskStatus = $('maskStatus');
    const maskModeName = masking.enabled ? 'FakeTLS' : t('status.disabled');
    if (!masking.enabled) {
      maskBadge.className = 'badge off';
      maskStatus.textContent = maskModeName;
    } else if (masking.mode === 'remote') {
      maskBadge.className = 'badge';
      maskStatus.textContent = maskModeName;
    } else if (masking.healthy) {
      maskBadge.className = 'badge';
      maskStatus.textContent = maskModeName;
    } else {
      maskBadge.className = 'badge off';
      maskStatus.textContent = maskModeName;
    }

    const protectedText = LANG === 'ru' ? 'Защищено' : 'Protected';
    const disabledText = LANG === 'ru' ? 'Выключено' : 'Disabled';
    const activeText = LANG === 'ru' ? 'Активен' : 'Active';
    const downText = LANG === 'ru' ? 'Отключён' : 'Down';
    const timerOkText = LANG === 'ru' ? 'OK · каждые 30с' : 'OK · every 30s';
    const modeText = masking.enabled
      ? '<span class="signal-sq"></span>' + protectedText
      : '<span class="signal-sq"></span>' + disabledText;
    $('maskMode').innerHTML = modeText;

    let endpointText = masking.tls_domain ? (masking.tls_domain + ':' + (masking.port || 443)) : (masking.target || '—');
    $('maskTarget').textContent = endpointText;

    const nginxState = masking.nginx_active
      ? '<span class="signal-sq"></span>' + activeText
      : '<span class="signal-sq"></span>' + downText;
    $('maskNginx').innerHTML = nginxState;

    const timerState = masking.health_timer_active ? timerOkText : downText;
    $('maskTimer').textContent = timerState;
  }

  renderUsers(d.users || null, (d.proxy || {}).per_user_active || {}, d.proxy || {});
}

function setDataBadge(state, text) {
  $('dataBadge').className = 'badge data-badge ' + state;
  $('dataBadgeText').textContent = text;
}

function setStaleMode(stale) {
  appRoot.classList.toggle('stale', stale);
}

function updateFreshness() {
  const lastUpdateEl = $('lastUpdate');
  if (!lastSuccessAt) {
    if (lastUpdateEl) lastUpdateEl.textContent = 'never';
  } else {
    const age = Math.floor((Date.now() - lastSuccessAt) / 1000);
    if (lastUpdateEl) lastUpdateEl.textContent = age <= 0 ? 'just now' : age + 's ago';
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
  const btn = $('pollToggle');
  // .icon-btn hides text (font-size:0); show a play/pause SVG instead.
  btn.innerHTML = pollingPaused ? ICON.play : ICON.pause;
  btn.title = pollingPaused ? t('btn.resume') : t('btn.pause');
  btn.setAttribute('aria-label', btn.title);
  btn.classList.toggle('active', !pollingPaused);
}

async function runPoll() {
  if (pollInFlight || pollingPaused) return;
  pollInFlight = true;
  try {
    await poll();
    hasPollError = false;
    lastSuccessAt = Date.now();
    appRoot.classList.remove('is-loading');
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
  updateNetworkWindowLabel();
  restartPollingLoop();
  updateFreshness();
});

$('pollToggle').addEventListener('click', () => {
  setPollingPaused(!pollingPaused);
});

// Language toggle (EN/RU) — defaults to the browser language, persists the choice.
const langToggleBtn = $('langToggle');
if (langToggleBtn) {
  langToggleBtn.addEventListener('click', () => {
    setLang(LANG === 'ru' ? 'en' : 'ru');
    updatePollControls();
    updateAutoScrollButton();
    if (lastEgress) renderEgress(lastEgress);
  });
}
applyStaticI18n();

updateNetworkWindowLabel();
updatePollControls();
updateFreshness();
setupAddUserForm();
setupDeleteModal();
setupTunnelDeleteModal();
setupRoutingControls();
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
  if (!autoScrollBtn) return;
  const label = autoScrollBtn.querySelector('.log-ctl-label');
  if (label) label.textContent = 'Auto-scroll';
  else autoScrollBtn.textContent = 'Auto-scroll';
  autoScrollBtn.classList.toggle('active', autoScrollEnabled);
  autoScrollBtn.setAttribute('aria-pressed', autoScrollEnabled ? 'true' : 'false');
  autoScrollBtn.setAttribute('aria-label', autoScrollEnabled ? 'Auto-scroll on' : 'Auto-scroll off');
  autoScrollBtn.title = autoScrollEnabled ? 'Auto-scroll on' : 'Auto-scroll off';
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

if (autoScrollBtn) {
  autoScrollBtn.addEventListener('click', () => {
    autoScrollEnabled = !autoScrollEnabled;
    if (autoScrollEnabled) jumpToLatest();
    updateAutoScrollButton();
  });
}

if (jumpLatestBtn) jumpLatestBtn.addEventListener('click', jumpToLatest);
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
  // textContent->innerHTML escapes & < > but NOT quotes; escape them too so the
  // result is safe to interpolate into double/single-quoted HTML attributes
  // (e.g. data-user="..."), preventing attribute-injection XSS.
  return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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
