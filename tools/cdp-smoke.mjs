/*
 * Dev-only UI smoke test over the Chrome DevTools Protocol.
 * Requires a headless Chrome started with --remote-debugging-port=9222.
 *
 *   node tools/cdp-smoke.mjs <url> <expected-file-name> <screenshot-name> [width] [height]
 */
import fs from 'node:fs';

const url = process.argv[2];
const expectedFile = process.argv[3];
const shotName = process.argv[4] || 'smoke.png';
const width = Number(process.argv[5] || 1600);
const height = Number(process.argv[6] || 1000);
if (!url || !expectedFile) {
  console.error('usage: node tools/cdp-smoke.mjs <url> <expected-file-name> <shot> [w] [h]');
  process.exit(2);
}
const port = process.env.CDP_PORT || '9222';
const base = `http://127.0.0.1:${port}`;
const target = await (await fetch(base + '/json/new?about:blank', { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let nextId = 1;
const pending = new Map();
const errors = [];
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const p = pending.get(m.id); pending.delete(m.id);
    m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result);
  } else if (m.method === 'Runtime.exceptionThrown') {
    errors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  } else if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
    errors.push(m.params.args.map(a => a.value ?? a.description ?? '').join(' '));
  } else if (m.method === 'Log.entryAdded' && m.params.entry.level === 'error') {
    const t = m.params.entry.text;
    if (!t.includes('favicon')) errors.push(t);
  }
};
const cmd = (method, params = {}) => new Promise((res, rej) => {
  const id = nextId++; pending.set(id, { resolve: res, reject: rej });
  ws.send(JSON.stringify({ id, method, params }));
});
const evaluate = async (expression) => {
  const r = await cmd('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
  return r.result.value;
};
const waitFor = async (expr, timeout = 20000) => {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await evaluate(expr)) return;
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error('timeout: ' + expr);
};

await cmd('Page.enable');
await cmd('Runtime.enable');
await cmd('Log.enable');
await cmd('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
await cmd('Page.navigate', { url });

await waitFor(`(() => document.querySelector('#fileName')?.textContent === ${JSON.stringify(expectedFile)} && document.querySelectorAll('#hexWindow .hex-row').length > 0)()`);
await new Promise(r => setTimeout(r, 500));

const result = {};
result.file = await evaluate(`document.querySelector('#fileName').textContent`);
result.chips = await evaluate(`document.querySelector('#chips').innerText.replace(/\\n/g, ' | ')`);
result.sectionCount = await evaluate(`document.querySelectorAll('.sec-item').length`);
result.legendCount = await evaluate(`document.querySelectorAll('.legend-item').length`);
result.mapBlocks = await evaluate(`document.querySelectorAll('.map-block').length`);
result.hexRows = await evaluate(`document.querySelectorAll('#hexWindow .hex-row').length`);
result.inspectorTitle = await evaluate(`document.querySelector('.insp-title')?.textContent`);
result.headerFields = await evaluate(`(() => {
  document.querySelector('.tab[data-tab="struct"]').click();
  return Object.fromEntries([...document.querySelectorAll('.hdr-row')].map(r => [r.querySelector('.k').textContent, r.querySelector('.v').textContent]));
})()`);
result.hasUndefined = Object.values(result.headerFields).some(v => v.includes('undefined'));

// Layout minimap + selected-region / persistent region background + map-click flash.
result.initialLanes = await evaluate(`({
  activeLanes: document.querySelectorAll('#hexWindow .lay-gap.active').length,
  activeOffBgs: document.querySelectorAll('#hexWindow .off.active').length,
  selectedMini: document.querySelectorAll('.mini-block.selected').length,
  selectedMiniStart: document.querySelector('.mini-block.selected')?.dataset.start
})`);
result.miniBlocks = await evaluate(`document.querySelectorAll('#hexMinimapBlocks .mini-block').length`);
const readUnderlay = `(() => ({
  mode: document.querySelector('#underlaySwitch button.on')?.dataset.underlay,
  lanes: document.querySelectorAll('#hexWindow .lay-gap.on').length,
  activeLanes: document.querySelectorAll('#hexWindow .lay-gap.active').length,
  offBgs: document.querySelectorAll('#hexWindow .off.on').length,
  activeOffBgs: document.querySelectorAll('#hexWindow .off.active').length,
  byteTints: document.querySelectorAll('#hexWindow .b.lay-on, #hexWindow .b.flash-lay').length
}))()`;
result.underlayInitial = await evaluate(readUnderlay);
result.underlayAll = await evaluate(`(() => {
  document.querySelector('#underlaySwitch button[data-underlay="all"]').click();
  return ${readUnderlay};
})()`);
await new Promise(r => setTimeout(r, 200));
{
  const { data } = await cmd('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(shotName.replace(/\.png$/, '') + '-layer.png', Buffer.from(data, 'base64'));
}
result.underlayNone = await evaluate(`(() => {
  document.querySelector('#underlaySwitch button[data-underlay="none"]').click();
  return ${readUnderlay};
})()`);
result.underlaySelected = await evaluate(`(() => {
  document.querySelector('#underlaySwitch button[data-underlay="selected"]').click();
  return ${readUnderlay};
})()`);
result.mapClick = await evaluate(`(() => {
  const blocks = [...document.querySelectorAll('.map-block')];
  const target = blocks.find(b => b.querySelector('.lbl')?.textContent.trim() === '.text');
  if (!target) return null;
  target.click();
  return {
    start: Number(target.dataset.start),
    inspector: document.querySelector('.insp-title')?.textContent,
    flashLanes: document.querySelectorAll('#hexWindow .lay-gap.flash').length,
    flashOffBgs: document.querySelectorAll('#hexWindow .off.flash').length,
    activeTop: document.querySelectorAll('.map-block.active').length,
    activeMini: document.querySelectorAll('.mini-block.active').length
  };
})()`);
await new Promise(r => setTimeout(r, 300));
if (result.mapClick) {
  result.miniClick = await evaluate(`(() => {
    const target = [...document.querySelectorAll('#hexMinimapBlocks .mini-block')]
      .find(b => Number(b.dataset.start) === ${Number(result.mapClick.start)});
    if (!target) return null;
    target.click();
    return {
      inspector: document.querySelector('.insp-title')?.textContent,
      flashLanes: document.querySelectorAll('#hexWindow .lay-gap.flash').length,
      flashOffBgs: document.querySelectorAll('#hexWindow .off.flash').length,
      activeMini: document.querySelectorAll('.mini-block.active').length
    };
  })()`);
}
{
  const { data } = await cmd('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(shotName.replace(/\.png$/, '') + '-map.png', Buffer.from(data, 'base64'));
}

// Clicking a section must select the whole section, not one byte.
result.textSection = await evaluate(`(() => {
  document.querySelector('.tab[data-tab="inspect"]').click();
  const el = [...document.querySelectorAll('.sec-item')].find(e => e.querySelector('.name')?.textContent.trim() === '.text');
  if (!el) return null;
  el.click();
  return {
    title: document.querySelector('.insp-title')?.textContent,
    desc: document.querySelector('.insp-desc')?.textContent,
    selectedCells: document.querySelectorAll('#hexWindow .b.sel').length,
    selectedRows: document.querySelectorAll('#hexWindow .hex-row.row-sel').length,
    miniSelected: document.querySelectorAll('.mini-block.selected').length,
    miniSelectedStart: document.querySelector('.mini-block.selected')?.dataset.start,
    activeSection: document.querySelector('.sec-item.active .name')?.textContent
  };
})()`);
await new Promise(r => setTimeout(r, 300));
{
  const { data } = await cmd('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(shotName.replace(/\.png$/, '') + '-section.png', Buffer.from(data, 'base64'));
}

// NOBITS handling.
result.bss = await evaluate(`(() => {
  document.querySelector('.tab[data-tab="inspect"]').click();
  const el = [...document.querySelectorAll('.sec-item')].find(e => e.querySelector('.name')?.textContent.trim() === '.bss');
  if (!el) return null;
  el.click();
  return document.querySelector('.insp-desc')?.textContent || '';
})()`);
await new Promise(r => setTimeout(r, 250));
result.bssMiniSelected = await evaluate(`document.querySelectorAll('.mini-block.selected').length`);

// Semantic legend mode.
result.roleLegend = await evaluate(`(() => {
  document.querySelector('#modeSwitch button[data-mode="role"]').click();
  return document.querySelectorAll('.legend-item').length;
})()`);

const { data } = await cmd('Page.captureScreenshot', { format: 'png' });
fs.writeFileSync(shotName, Buffer.from(data, 'base64'));

console.log(JSON.stringify({ result, errors }, null, 2));
ws.close();
await fetch(base + '/json/close/' + target.id);
if (errors.length || result.hasUndefined || result.file !== expectedFile) process.exit(1);
if (!result.textSection || result.textSection.title !== '.text' ||
  !(result.textSection.desc || '').includes('已选中整个节') ||
  !(result.textSection.selectedRows > 0)) {
  console.error('section selection check failed', result.textSection);
  process.exit(1);
}
if (!(result.miniBlocks > 0) ||
  !(result.initialLanes.activeLanes > 0) || !(result.initialLanes.activeOffBgs > 0) ||
  !(result.initialLanes.selectedMini === 1) ||
  !(result.textSection && result.textSection.miniSelected === 1 && Number(result.textSection.miniSelectedStart) === 8912) ||
  !(result.bssMiniSelected === 0) ||
  !(result.underlayInitial.mode === 'selected') ||
  !(result.underlayInitial.activeLanes > 0) || !(result.underlayInitial.activeOffBgs > 0) ||
  !(result.underlayAll.mode === 'all') ||
  !(result.underlayAll.lanes > 0) || !(result.underlayAll.offBgs > 0) ||
  !(result.underlayAll.activeLanes > 0) || !(result.underlayAll.activeOffBgs > 0) ||
  !(result.underlayAll.byteTints === 0) ||
  !(result.underlayNone.mode === 'none') ||
  !(result.underlayNone.lanes === 0) || !(result.underlayNone.activeLanes === 0) ||
  !(result.underlayNone.offBgs === 0) || !(result.underlayNone.activeOffBgs === 0) ||
  !(result.underlaySelected.mode === 'selected') ||
  !(result.underlaySelected.activeLanes > 0) || !(result.underlaySelected.lanes === 0) ||
  !result.mapClick || !(result.mapClick.flashLanes > 0) || !(result.mapClick.flashOffBgs > 0) ||
  !(result.mapClick.activeTop > 0) || !(result.mapClick.activeMini > 0) ||
  !result.miniClick || !(result.miniClick.flashLanes > 0) || !(result.miniClick.flashOffBgs > 0) ||
  !(result.miniClick.activeMini > 0)) {
  console.error('layout layer check failed', {
    miniBlocks: result.miniBlocks,
    underlayInitial: result.underlayInitial,
    underlayAll: result.underlayAll,
    underlayNone: result.underlayNone,
    underlaySelected: result.underlaySelected,
    mapClick: result.mapClick
  });
  process.exit(1);
}
