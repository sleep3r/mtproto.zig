// Exercise the shipped polling/rendering code without browsers, timers or real probes.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const source = fs.readFileSync(__dirname + '/static/app.js', 'utf8');

function harness() {
  const nodes = new Map();
  function $(id) {
    if (!nodes.has(id)) nodes.set(id, {
      style: { setProperty() {} }, textContent: '', innerHTML: '', title: '', hidden: false, disabled: false,
      classList: { toggle() {}, remove() {} }, querySelectorAll() { return []; },
      setAttribute() {},
    });
    return nodes.get(id);
  }
  const context = {
    $, console, Date, LANG: 'en', lastData: null, lastSuccessAt: 0,
    hasPollError: false, pollInFlight: false, pollingPaused: false, pollIntervalMs: 3000,
    appRoot: $('app'), window: {}, document: { querySelectorAll() { return []; } },
    t: key => key, esc: String, fmt: String, fmtT: String,
    setGauge() {}, drawSpark() {}, drawNetChart() {},
    renderRouting() {}, renderTraffic() {},
    lastEgress: { ok: true, stale: true },
    showToast() {},
    fetch: async url => url === '/api/stats' ? { ok: true, json: async () => context.data } : { ok: false },
  };
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf('function setStatusHero('), source.indexOf('function closeShareModal(')), context);
  vm.runInContext(source.slice(source.indexOf('function fmtHandshakeAge('), source.indexOf('// ── Polling')), context);
  vm.runInContext(source.slice(source.indexOf('function renderUsers('), source.indexOf('function setRoutingAction(')), context);
  vm.runInContext(source.slice(source.indexOf('async function poll()'), source.indexOf('function restartPollingLoop()')), context);
  context.data = {
    errors: ['Invalid TOML at line 2'], config_error: 'Invalid TOML at line 2',
    cpu: 37, mem_used: 256, mem_total: 1024, mem_pct: 25, net_rx: 10, net_tx: 20,
    net_rx_total: 100, net_tx_total: 200, proxy: { active: 7, total: 80 },
    proxy_info: { online: true, state: 'unknown', pid: 42, rss_mb: 12, uptime: '1h' },
    users: null, routing: null, masking: null, traffic: null,
  };
  return context;
}

test('config errors do not freeze CPU/process updates and clear after repair', async () => {
  const c = harness();
  await c.runPoll();
  assert.match(c.$('cpuVal').innerHTML, /37/);
  assert.equal(c.$('proxyPid').textContent, 42);
  assert.equal(c.$('configError').hidden, false);
  assert.match(c.$('configError').textContent, /line 2/);
  assert.equal(c.$('addUserBtn').disabled, true);
  assert.equal(c.lastEgress, null);
  assert.equal(c.$('egressCard').style.display, 'none');
  assert.equal(c.$('statusHeroText').textContent, 'hero.vUnknown');
  assert.equal(c.$('usersMeta').textContent, '—');
  assert.equal(c.hasPollError, false);
  assert.ok(c.lastSuccessAt > 0);

  c.data = { ...c.data, errors: [], config_error: null, cpu: 41,
    users: { items: [], total: 0, links_ready: true } };
  await c.runPoll();
  assert.match(c.$('cpuVal').innerHTML, /41/);
  assert.equal(c.$('configError').hidden, true);
  assert.equal(c.$('addUserBtn').disabled, false);
});

test('transport errors still mark polling failed', async () => {
  const c = harness();
  c.console = { error() {} };
  c.fetch = async () => ({ ok: false, status: 503 });
  await c.runPoll();
  assert.equal(c.hasPollError, true);
  assert.equal(c.lastSuccessAt, 0);
});
