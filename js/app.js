/* ELF Autopsy — browser UI */
(function () {
  'use strict';

  const P = window.ElfParser;
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  const ROW_BYTES = 16;
  const ROW_H = 26.6; // must match --row-h in style.css

  const state = {
    model: null,
    fileName: '',
    fileSize: 0,
    colorMode: 'kind',
    filter: null,
    selected: null,
    sectionFocus: null,
    activeSection: null,
    hoverSeg: null,
    underlayMode: 'selected',
    layoutFlash: null,
    layoutFlashTimer: 0,
    activeLayout: null,
    rowCount: 0,
    renderStart: -1,
    renderEnd: -1,
    scrollRaf: 0,
    symbolRanges: [],
    symFilter: '',
    symLimit: 300,
    relLimit: 300,
    sectionFilter: '',
    tab: 'inspect'
  };

  const els = {};
  let toastTimer = 0;

  /* ------------------------------------------------------------------ *
   * Boot
   * ------------------------------------------------------------------ */

  function init() {
    cacheEls();
    bindEvents();
    const params = new URLSearchParams(location.search);
    const auto = params.get('auto');
    if (auto) loadAuto(auto);
    else if (params.get('demo') === '1') loadDemo();
  }

  function cacheEls() {
    const ids = [
      'empty', 'workspace', 'fileStatus', 'fileName', 'chips', 'demoBtn', 'openBtn',
      'fileInput', 'overview', 'fileBadge', 'sectionCount', 'sectionList', 'sectionSearch',
      'legend', 'legendHelp', 'clearFilter', 'filemap', 'mapInfo', 'mapScaleEnd',
      'modeSwitch', 'jumpInput', 'jumpBtn', 'hexHeadBytes', 'hexScroll', 'hexSpacer',
      'hexWindow', 'statusOffset', 'statusSection', 'statusField', 'tabs', 'tabInspect',
      'tabStruct', 'structScroll', 'structCount', 'tooltip', 'toast', 'dropOverlay',
      'dropHero', 'heroOpenBtn', 'mapHint', 'underlaySwitch', 'hexCard', 'hexMinimap',
      'hexMinimapBlocks', 'hexMinimapView'
    ];
    for (const id of ids) els[id] = document.getElementById(id);
  }

  function bindEvents() {
    els.openBtn.addEventListener('click', openFilePicker);
    els.heroOpenBtn.addEventListener('click', openFilePicker);
    els.dropHero.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      openFilePicker();
    });
    els.demoBtn.addEventListener('click', loadDemo);
    els.fileInput.addEventListener('change', () => {
      const f = els.fileInput.files && els.fileInput.files[0];
      if (f) loadFile(f);
    });

    els.modeSwitch.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-mode]');
      if (!b) return;
      setColorMode(b.dataset.mode);
    });
    els.underlaySwitch.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-underlay]');
      if (b) setUnderlayMode(b.dataset.underlay);
    });

    els.jumpBtn.addEventListener('click', doJump);
    els.jumpInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doJump();
    });

    els.tabs.addEventListener('click', (e) => {
      const b = e.target.closest('.tab[data-tab]');
      if (b) setTab(b.dataset.tab);
    });

    els.legend.addEventListener('click', (e) => {
      const b = e.target.closest('[data-key]');
      if (!b) return;
      const key = b.dataset.key;
      state.filter = state.filter === key ? null : key;
      renderLegend();
      renderRows(true);
      hideHover();
    });
    els.clearFilter.addEventListener('click', () => {
      state.filter = null;
      renderLegend();
      renderRows(true);
    });

    els.sectionList.addEventListener('click', (e) => {
      const b = e.target.closest('[data-sec]');
      if (!b) return;
      selectSection(Number(b.dataset.sec));
    });
    els.sectionSearch.addEventListener('input', () => {
      state.sectionFilter = els.sectionSearch.value;
      renderSectionList();
    });

    els.filemap.addEventListener('click', (e) => {
      const b = e.target.closest('[data-block]');
      if (!b) return;
      focusLayoutBlock(layoutBlockFromElement(b));
    });
    els.filemap.addEventListener('mouseover', (e) => {
      const b = e.target.closest('[data-block]');
      if (b) showLayoutTooltip(layoutBlockFromElement(b), e);
    });
    els.filemap.addEventListener('mousemove', (e) => {
      if (els.tooltip.classList.contains('show')) positionTooltip(e.clientX, e.clientY);
    });
    els.filemap.addEventListener('mouseleave', hideTooltip);

    els.hexMinimapBlocks.addEventListener('click', (e) => {
      const b = e.target.closest('[data-block]');
      if (!b) return;
      focusLayoutBlock(layoutBlockFromElement(b));
    });
    els.hexMinimapBlocks.addEventListener('mouseover', (e) => {
      const b = e.target.closest('[data-block]');
      if (b) showLayoutTooltip(layoutBlockFromElement(b), e);
    });
    els.hexMinimapBlocks.addEventListener('mousemove', (e) => {
      if (els.tooltip.classList.contains('show')) positionTooltip(e.clientX, e.clientY);
    });
    els.hexMinimapBlocks.addEventListener('mouseleave', hideTooltip);

    els.hexScroll.addEventListener('scroll', () => {
      if (state.scrollRaf) return;
      state.scrollRaf = requestAnimationFrame(() => {
        state.scrollRaf = 0;
        renderRows();
        updateMinimapViewport();
        hideHover();
      });
    }, { passive: true });

    els.hexScroll.addEventListener('mouseover', (e) => {
      const t = e.target.closest('[data-o]');
      if (!t) return;
      hoverByte(Number(t.dataset.o), e);
    });
    els.hexScroll.addEventListener('mousemove', (e) => {
      if (state.hoverSeg) positionTooltip(e.clientX, e.clientY);
    });
    els.hexScroll.addEventListener('mouseleave', hideHover);
    els.hexScroll.addEventListener('click', (e) => {
      const t = e.target.closest('[data-o]');
      if (!t) return;
      selectByte(Number(t.dataset.o));
    });

    els.tabInspect.addEventListener('click', (e) => {
      const b = e.target.closest('[data-act]');
      if (b) handleAction(b.dataset.act, b);
    });

    els.structScroll.addEventListener('click', (e) => {
      const b = e.target.closest('[data-act]');
      if (b) handleStructAction(b.dataset.act, b);
    });
    els.structScroll.addEventListener('input', (e) => {
      if (e.target.id === 'symSearch') {
        state.symFilter = e.target.value;
        state.symLimit = 300;
        renderSymbolList();
      }
    });

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        openFilePicker();
      } else if (e.key === 'Escape') {
        if (state.filter) {
          state.filter = null;
          renderLegend();
          renderRows(true);
        }
      }
    });

    // Drag & drop
    let dragDepth = 0;
    window.addEventListener('dragenter', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth++;
      els.dropOverlay.classList.add('show');
    });
    window.addEventListener('dragover', (e) => {
      if (hasFiles(e)) e.preventDefault();
    });
    window.addEventListener('dragleave', (e) => {
      if (!hasFiles(e) && !e.relatedTarget) return;
      dragDepth = Math.max(0, dragDepth - 1);
      if (!dragDepth) els.dropOverlay.classList.remove('show');
    });
    window.addEventListener('drop', (e) => {
      if (!hasFiles(e)) return;
      e.preventDefault();
      dragDepth = 0;
      els.dropOverlay.classList.remove('show');
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) loadFile(f);
    });

    if (window.ResizeObserver) {
      new ResizeObserver(() => {
        if (state.model) {
          renderRows(true);
          updateMinimapViewport();
        }
      }).observe(els.hexScroll);
    } else {
      window.addEventListener('resize', () => state.model && renderRows(true));
    }
  }

  function hasFiles(e) {
    return e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
  }

  function openFilePicker() {
    els.fileInput.value = '';
    els.fileInput.click();
  }

  /* ------------------------------------------------------------------ *
   * Loading
   * ------------------------------------------------------------------ */

  async function loadFile(file) {
    try {
      const buffer = await file.arrayBuffer();
      loadBuffer(buffer, file.name || 'unnamed.elf');
    } catch (err) {
      toast('读取文件失败：' + (err && err.message ? err.message : err));
    }
  }

  async function loadAuto(url) {
    try {
      const resp = await fetch(url, { cache: 'no-store' });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const buffer = await resp.arrayBuffer();
      loadBuffer(buffer, url.split('/').pop() || 'sample.elf');
    } catch (err) {
      toast('自动载入失败：' + err.message);
    }
  }

  function loadBuffer(buffer, name) {
    const model = P.parse(buffer);
    if (!model.valid) {
      toast('无法解析：' + (model.errors[0] || '未知错误'));
      return;
    }

    state.model = model;
    state.fileName = name || 'unnamed.elf';
    state.fileSize = model.fileSize;
    state.selected = null;
    state.sectionFocus = null;
    state.activeSection = null;
    state.filter = null;
    state.colorMode = 'kind';
    state.hoverSeg = null;
    state.underlayMode = 'selected';
    state.layoutFlash = null;
    state.activeLayout = null;
    clearTimeout(state.layoutFlashTimer);
    state.layoutFlashTimer = 0;
    updateUnderlayButtons();
    state.symFilter = '';
    state.symLimit = 300;
    state.relLimit = 300;
    state.sectionFilter = '';
    state.rowCount = Math.ceil(model.fileSize / ROW_BYTES);
    state.renderStart = -1;
    state.renderEnd = -1;
    state.symbolRanges = model.annotations.filter(a => a.entryType === 'symbol-range' && a.ref);

    els.empty.hidden = true;
    els.workspace.hidden = false;
    els.sectionSearch.value = '';
    els.jumpInput.value = '';
    $$('#modeSwitch button').forEach(b => b.classList.toggle('on', b.dataset.mode === 'kind'));

    renderChips();
    renderOverview();
    renderSectionList();
    renderLegend();
    renderMap();
    renderMinimap();
    setupHex();
    renderStructure();
    setTab('inspect');

    // Select the four magic bytes by default.
    const magicSeg = model.annotations[0];
    const magicLen = magicSeg ? Math.min(magicSeg.end, model.fileSize) : Math.min(4, model.fileSize);
    setSelection(0, magicLen, { focus: 0, scroll: false, keepTab: true });
    requestAnimationFrame(() => {
      renderRows(true);
      updateMinimapViewport();
    });
  }

  async function loadDemo() {
    const b64 = window.ELF_DEMO_B64;
    if (b64) {
      try {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        loadBuffer(bytes.buffer, 'demo.elf');
      } catch (err) {
        toast('示例载入失败：' + err.message);
      }
      return;
    }
    // Served copy: use the bundled sample as a demo.
    try {
      const resp = await fetch('samples/demo.elf', { cache: 'no-store' });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const buffer = await resp.arrayBuffer();
      loadBuffer(buffer, 'demo.elf');
    } catch (err) {
      toast('示例只在通过本地服务器打开时可用；你也可以直接把任意 ELF 文件拖进来。');
    }
  }

  /* ------------------------------------------------------------------ *
   * Overview / chips
   * ------------------------------------------------------------------ */

  function renderChips() {
    const m = state.model;
    const h = m.header;
    els.fileName.textContent = state.fileName;
    els.fileName.classList.add('loaded');
    els.fileName.title = state.fileName;
    const endian = m.littleEndian ? '小端 LE' : '大端 BE';
    const typeLabel = h.type === 3 ? 'PIE / 共享对象'
      : h.type === 2 ? '可执行文件'
        : h.type === 1 ? '可重定位目标'
          : h.type === 4 ? '核心转储' : '未知类型';
    els.chips.innerHTML = `
      <span class="chip type" title="${esc(m.typeLabel)}"><b>${esc(m.typeName)}</b> ${esc(typeLabel)}</span>
      <span class="chip machine" title="${esc(m.machineName)}"><b>${esc(shortMachine(m.machineName))}</b> · ${m.classBits}-bit</span>
      <span class="chip endian"><span class="dot"></span>${endian}</span>
      <span class="chip" title="程序入口点"><b>entry</b> 0x${hexNum(h.entry)}</span>
      <span class="chip"><b>${m.sections.length}</b> 节</span>
      <span class="chip"><b>${m.programHeaders.length}</b> 程序头</span>
    `;
  }

  function renderOverview() {
    const m = state.model;
    const h = m.header;
    els.fileBadge.textContent = 'ELF' + m.classBits;
    els.sectionCount.textContent = m.sections.length;
    const buildId = m.notes.find(n => n.name === 'GNU' && n.type === 3);
    const deps = m.needed && m.needed.length
      ? `<div class="ov-deps"><b>DT_NEEDED 依赖</b><br>${m.needed.map(d => `<span>${esc(d)}</span>`).join('')}</div>`
      : '';
    const warnCount = m.warnings.length;
    const warn = warnCount ? `<div class="ov-warn"><b>⚠ ${warnCount} 条解析提示</b>${m.warnings.slice(0, 3).map(w => esc(w)).join('<br>')}${warnCount > 3 ? '<br>…' : ''}</div>` : '';
    const kinds = Object.entries(m.stats.kinds)
      .filter(([k, v]) => v > 0 && k !== 'gap')
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7);
    const total = kinds.reduce((a, b) => a + b[1], 0) || 1;
    const strip = kinds.length ? `<div class="ov-strip">${kinds.map(([k, v]) => {
      const info = P.KIND_INFO[k] || { label: k, color: '#64748b' };
      return `<i style="--c:${info.color};width:${(v / total * 100).toFixed(2)}%" title="${esc(info.label)} ${fmtBytes(v)}"></i>`;
    }).join('')}</div>` : '';

    els.overview.innerHTML = `
      <div class="file-big"><strong title="${esc(state.fileName)}">${esc(state.fileName)}</strong><span>${fmtBytes(m.fileSize)}</span></div>
      <div class="ov-grid">
        <div class="ov-cell"><span>类型</span><b title="${esc(m.typeLabel)}">${esc(m.typeName)}</b></div>
        <div class="ov-cell"><span>架构</span><b>${esc(m.machineName)}</b></div>
        <div class="ov-cell"><span>格式</span><b>ELF${m.classBits} · ${m.littleEndian ? '小端' : '大端'}</b></div>
        <div class="ov-cell"><span>入口点</span><b class="accent">0x${hexNum(h.entry)}</b></div>
        <div class="ov-cell"><span>节 / 程序头</span><b>${m.sections.length} / ${m.programHeaders.length}</b></div>
        <div class="ov-cell"><span>符号 / 重定位</span><b>${m.symbols.length} / ${m.relocs.length}</b></div>
        <div class="ov-cell"><span>动态项 / Note</span><b>${m.dynamic.length} / ${m.notes.length}</b></div>
        <div class="ov-cell"><span>符号表</span><b>${m.isStripped ? '已剥离' : '.symtab 存在'}</b></div>
        ${buildId ? `<div class="ov-cell full"><span>Build ID</span><b title="${esc(buildId.descText)}">${esc(buildId.descText || '—')}</b></div>` : ''}
      </div>
      ${strip}
      ${deps}
      ${warn}
    `;
  }

  /* ------------------------------------------------------------------ *
   * Sections
   * ------------------------------------------------------------------ */

  function renderSectionList() {
    const m = state.model;
    const q = state.sectionFilter.trim().toLowerCase();
    const list = m.sections.filter(s => {
      if (!q) return true;
      return (s.name || '').toLowerCase().includes(q) || s.typeName.toLowerCase().includes(q);
    });
    if (!list.length) {
      els.sectionList.innerHTML = `<div class="legend-empty" style="padding:10px">没有匹配的节</div>`;
      return;
    }
    els.sectionList.innerHTML = list.map(s => {
      const info = P.KIND_INFO[s.kind] || { color: '#64748b' };
      const active = state.activeSection === s.index ? ' active' : '';
      const nobits = s.type === 8 ? ' · NOBITS' : '';
      return `<button class="sec-item${active}" data-sec="${s.index}" style="--c:${info.color}" title="${esc(s.typeName)} · ${s.size} B">
        <span class="dot"></span>
        <span class="name">${esc(s.name || '[' + s.index + ']')}</span>
        <span class="size">${fmtBytes(s.size)}</span>
        <span class="meta">${esc(s.typeName)} · off 0x${hexNum(s.offset)}${nobits}</span>
      </button>`;
    }).join('');
  }

  function updateSectionActive() {
    $$('.sec-item', els.sectionList).forEach(el => {
      el.classList.toggle('active', Number(el.dataset.sec) === state.activeSection);
    });
  }

  /* ------------------------------------------------------------------ *
   * Legend
   * ------------------------------------------------------------------ */

  function roleStats() {
    const out = {};
    for (const seg of state.model.annotations) {
      out[seg.role] = (out[seg.role] || 0) + (seg.end - seg.start);
    }
    return out;
  }

  function legendEntries() {
    const m = state.model;
    if (state.colorMode === 'kind') {
      return Object.entries(m.stats.kinds)
        .filter(([k, v]) => v > 0 && k !== 'bss')
        .map(([key, bytes]) => ({ key, bytes, info: P.KIND_INFO[key] || { label: key, color: '#64748b', desc: '' } }))
        .sort((a, b) => b.bytes - a.bytes);
    }
    return Object.entries(roleStats())
      .filter(([k, v]) => v > 0)
      .map(([key, bytes]) => ({ key, bytes, info: P.ROLE_INFO[key] || { label: key, color: '#64748b', desc: '' } }))
      .filter(e => e.info)
      .sort((a, b) => b.bytes - a.bytes);
  }

  function renderLegend() {
    const entries = legendEntries();
    if (state.filter && !entries.some(e => e.key === state.filter)) state.filter = null;
    els.legend.innerHTML = entries.map(e => `
      <button class="legend-item${state.filter === e.key ? ' on' : ''}" data-key="${esc(e.key)}" style="--c:${e.info.color}" title="${esc(e.info.desc || '')}">
        <span class="sw"></span>${esc(e.info.label)}<span class="num">${shortBytes(e.bytes)}</span>
      </button>
    `).join('') || `<span class="legend-empty">暂无数据</span>`;
    els.legendHelp.textContent = state.colorMode === 'kind'
      ? '字节图例和节列表使用字节类别色；顶部文件布局与右侧缩略图使用独立的布局色。点击图例可筛选字节。'
      : '字段语义色只作用于十六进制视图；节列表使用字节类别色，文件布局与缩略图使用独立布局色。';
    els.clearFilter.hidden = !state.filter;
  }

  /* ------------------------------------------------------------------ *
   * File map
   * ------------------------------------------------------------------ */

  // Layout colors are deliberately independent from the byte-category colors.
  // Adjacent sections get distinct hues so the region underlay is readable.
  const LAYOUT_PALETTE = [
    '#2dd4bf', '#f6c453', '#f2789f', '#a78bfa',
    '#34d399', '#fb923c', '#60a5fa', '#f472b6',
    '#a3e635', '#fca5a5', '#22d3ee', '#c084fc',
    '#facc15', '#86efac', '#5b8def', '#f0abfc'
  ];
  const LAYOUT_STRUCTURE_COLORS = {
    ehdr: '#8b5cf6',
    phdr: '#38bdf8',
    shdr: '#2dd4bf',
    gap: '#334155'
  };

  function layoutColor(block) {
    if (!block) return '#64748b';
    if (LAYOUT_STRUCTURE_COLORS[block.kind]) return LAYOUT_STRUCTURE_COLORS[block.kind];
    if (block.sectionIndex != null) {
      return LAYOUT_PALETTE[(block.sectionIndex - 1 + LAYOUT_PALETTE.length * 10) % LAYOUT_PALETTE.length];
    }
    return '#64748b';
  }

  function layoutBlockAt(off) {
    const blocks = state.model?.layoutBlocks || [];
    let lo = 0, hi = blocks.length - 1, ans = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (blocks[mid].start <= off) { ans = blocks[mid]; lo = mid + 1; }
      else hi = mid - 1;
    }
    return ans && off < ans.end ? ans : null;
  }

  function selectedLayoutBlock() {
    if (!state.model || !state.selected) return null;
    return layoutBlockAt(state.selected.focus);
  }

  function layoutBlockFromElement(el) {
    if (!el) return null;
    const blocks = state.model?.layoutBlocks || [];
    const index = Number(el.dataset.block);
    if (Number.isInteger(index) && blocks[index]) return blocks[index];
    const start = Number(el.dataset.start);
    const end = Number(el.dataset.end);
    return blocks.find(b => b.start === start && b.end === end) || null;
  }

  function renderMap() {
    const m = state.model;
    const blocks = m.layoutBlocks || [];
    els.filemap.innerHTML = blocks.map((b, i) => {
      const info = P.KIND_INFO[b.kind] || { label: b.kind };
      const color = layoutColor(b);
      const pct = (b.end - b.start) / m.fileSize;
      const label = pct > 0.045 ? `<span class="lbl">${esc(b.label || info.label)}</span>` : '';
      const active = state.activeLayout && state.activeLayout.start === b.start && state.activeLayout.end === b.end ? ' active' : '';
      return `<button class="map-block${b.kind === 'gap' ? ' gap' : ''}${active}" data-block="${i}" data-start="${b.start}" data-end="${b.end}"
        style="flex-grow:${Math.max(1, b.end - b.start)};--c:${color}"
        title="${esc(b.label || '')} · 0x${hexNum(b.start)}–0x${hexNum(b.end)}">${label}</button>`;
    }).join('');
    els.mapInfo.textContent = `${blocks.length} 个区域 · ${fmtBytes(m.fileSize)}`;
    els.mapScaleEnd.textContent = '0x' + hexNum(m.fileSize);
  }

  function renderMinimap() {
    const m = state.model;
    if (!m) return;
    const blocks = m.layoutBlocks || [];
    const selected = selectedLayoutBlock();
    els.hexMinimapBlocks.innerHTML = blocks.map((b, i) => {
      const info = P.KIND_INFO[b.kind] || { label: b.kind };
      const color = layoutColor(b);
      const active = state.activeLayout && state.activeLayout.start === b.start && state.activeLayout.end === b.end ? ' active' : '';
      const isSelected = selected && selected.start === b.start && selected.end === b.end ? ' selected' : '';
      return `<button class="mini-block${active}${isSelected}" data-block="${i}" data-start="${b.start}" data-end="${b.end}"
        style="flex-grow:${Math.max(1, b.end - b.start)};--c:${color}"
        title="${esc(b.label || info.label)} · 0x${hexNum(b.start)}–0x${hexNum(b.end)}"
        aria-label="${esc(b.label || info.label)}"></button>`;
    }).join('');
    updateMinimapViewport();
  }

  function updateMinimapSelection() {
    if (!state.model) return;
    const selected = selectedLayoutBlock();
    $$('.mini-block', els.hexMinimapBlocks).forEach(el => {
      const match = selected && Number(el.dataset.start) === selected.start && Number(el.dataset.end) === selected.end;
      el.classList.toggle('selected', !!match);
    });
  }

  function updateMinimapViewport() {
    if (!state.model || !els.hexMinimapView) return;
    const total = els.hexScroll.scrollHeight;
    const viewH = els.hexScroll.clientHeight;
    if (!total || !viewH) {
      els.hexMinimapView.style.height = '0%';
      return;
    }
    const top = Math.max(0, els.hexScroll.scrollTop);
    const topPct = Math.min(100, (top / total) * 100);
    const heightPct = Math.min(100 - topPct, (viewH / total) * 100);
    els.hexMinimapView.style.top = topPct + '%';
    els.hexMinimapView.style.height = Math.max(0.4, heightPct) + '%';
  }

  function updateActiveLayoutClasses() {
    const active = state.activeLayout;
    $$('.map-block, .mini-block').forEach(el => {
      const match = active && Number(el.dataset.start) === active.start && Number(el.dataset.end) === active.end;
      el.classList.toggle('active', !!match);
    });
  }

  function showLayoutTooltip(block, e) {
    if (!block) return;
    const info = P.KIND_INFO[block.kind] || { label: block.kind };
    const size = block.end - block.start;
    const pct = ((size / state.model.fileSize) * 100).toFixed(pctDigits(size / state.model.fileSize));
    const html = `
      <div class="tt-kicker"><span class="sw" style="--c:${layoutColor(block)}"></span>文件布局<span class="r">${pct}%</span></div>
      <div class="tt-title">${esc(block.label || info.label)}</div>
      <div class="tt-desc">${esc(info.desc || '')}</div>
      <div class="tt-meta"><span>0x${hexNum(block.start)} – 0x${hexNum(block.end)}</span><span><b>${fmtBytes(size)}</b></span></div>
    `;
    els.tooltip.innerHTML = html;
    els.tooltip.classList.add('show');
    positionTooltip(e.clientX, e.clientY);
  }

  function focusLayoutBlock(block) {
    if (!block) return;
    hideTooltip();
    state.activeLayout = { start: block.start, end: block.end };
    updateActiveLayoutClasses();
    if (block.sectionIndex != null && state.model.sections[block.sectionIndex]) {
      selectSection(block.sectionIndex);
    } else {
      setSelection(block.start, Math.min(block.start + 1, state.model.fileSize),
        { focus: block.start, scroll: true });
    }
    flashLayoutBlock(block);
  }

  function flashLayoutBlock(block) {
    clearTimeout(state.layoutFlashTimer);
    state.layoutFlash = { start: block.start, end: block.end, color: layoutColor(block) };
    renderRows(true);
    state.layoutFlashTimer = setTimeout(() => {
      state.layoutFlash = null;
      renderRows(true);
    }, 2200);
  }

  function updateUnderlayButtons() {
    $$('#underlaySwitch button[data-underlay]').forEach(b => {
      const on = b.dataset.underlay === state.underlayMode;
      b.classList.toggle('on', on);
      b.setAttribute('aria-pressed', String(on));
    });
  }

  function setUnderlayMode(mode) {
    if (!['all', 'selected', 'none'].includes(mode)) return;
    state.underlayMode = mode;
    updateUnderlayButtons();
    renderRows(true);
  }

  /* ------------------------------------------------------------------ *
   * Hex view
   * ------------------------------------------------------------------ */

  function setupHex() {
    const m = state.model;
    els.hexSpacer.style.height = (state.rowCount * ROW_H) + 'px';
    els.hexScroll.scrollTop = 0;
    els.hexHeadBytes.innerHTML = Array.from({ length: ROW_BYTES }, (_, i) =>
      `<span>${i.toString(16).toUpperCase().padStart(2, '0')}</span>`).join('');
    els.hexWindow.innerHTML = '';
    state.renderStart = -1;
    state.renderEnd = -1;
    renderRows(true);
    updateMinimapViewport();
  }

  function renderRows(force) {
    if (!state.model) return;
    const viewport = els.hexScroll;
    const height = viewport.clientHeight || 420;
    const first = Math.floor((viewport.scrollTop || 0) / ROW_H);
    const visible = Math.ceil(height / ROW_H) + 1;
    const start = Math.max(0, first - 6);
    const end = Math.min(state.rowCount, first + visible + 6);
    if (!force && start === state.renderStart && end === state.renderEnd) return;
    state.renderStart = start;
    state.renderEnd = end;
    els.hexWindow.style.top = (start * ROW_H) + 'px';
    let html = '';
    for (let row = start; row < end; row++) html += renderHexRow(row);
    els.hexWindow.innerHTML = html;
  }

  function renderHexRow(row) {
    const m = state.model;
    const base = row * ROW_BYTES;
    const bytes = m.bytes;
    const sel = state.selected;
    // A whole section (or another large range) gets a quiet row wash instead
    // of an outline on every byte, which would turn the hex view into a grid.
    const largeSelection = sel && (sel.end - sel.start) > 64;
    const rowSelected = largeSelection && base < sel.end && base + ROW_BYTES > sel.start;
    const flash = state.layoutFlash;
    const rowInFlash = flash && base < flash.end && base + ROW_BYTES > flash.start;
    const rowBlock = layoutBlockAt(base);
    const selectedBlock = selectedLayoutBlock();
    const rowIsSelectedRegion = selectedBlock &&
      base < selectedBlock.end && base + ROW_BYTES > selectedBlock.start;
    let laneCls = '';
    let laneColor = 'transparent';
    if (state.underlayMode !== 'none') {
      if (rowInFlash) {
        laneCls = ' flash';
        laneColor = flash.color;
      } else if (rowIsSelectedRegion) {
        laneCls = ' active';
        laneColor = layoutColor(selectedBlock);
      } else if (state.underlayMode === 'all' && rowBlock) {
        laneCls = ' on';
        laneColor = layoutColor(rowBlock);
      }
    }
    let cells = '';
    let ascii = '';
    for (let i = 0; i < ROW_BYTES; i++) {
      const off = base + i;
      if (off >= m.fileSize) {
        cells += '<span class="b empty"></span>';
        ascii += '<span class="a"></span>';
        continue;
      }
      const seg = segAt(off);
      const info = state.colorMode === 'kind'
        ? (P.KIND_INFO[seg.kind] || { color: '#64748b' })
        : (P.ROLE_INFO[seg.role] || { color: '#64748b' });
      const key = state.colorMode === 'kind' ? seg.kind : seg.role;
      let cls = 'b';
      if (seg.start === off) cls += ' s';
      if (state.filter && key !== state.filter) cls += ' dim';
      if (state.hoverSeg && state.hoverSeg.id === seg.id) cls += ' hl';
      if (sel && off >= sel.start && off < sel.end) {
        if (!largeSelection) cls += ' sel';
        if (off === sel.start || off === sel.end - 1) cls += ' sel-edge';
      }
      const byte = bytes[off].toString(16).padStart(2, '0').toUpperCase();
      cells += `<span class="${cls}" data-o="${off}" data-s="${seg.id}" data-k="${seg.kind}" style="--c:${info.color}">${byte}</span>`;

      let acl = 'a';
      if (state.filter && key !== state.filter) acl += ' dim';
      if (state.hoverSeg && state.hoverSeg.id === seg.id) acl += ' hl';
      if (sel && !largeSelection && off >= sel.start && off < sel.end) acl += ' sel';
      const c = bytes[off];
      const ch = c >= 32 && c <= 126 ? esc(String.fromCharCode(c)) : (c === 32 ? '&nbsp;' : '·');
      ascii += `<span class="${acl}" data-o="${off}" data-s="${seg.id}" data-k="${seg.kind}" style="--c:${info.color}">${ch}</span>`;
    }
    return `<div class="hex-row${rowSelected ? ' row-sel' : ''}" data-row="${row}">
      <span class="off${laneCls}" style="--lay:${laneColor}">${hexNum(base, 8)}</span>
      <span class="bytes-wrap"><span class="bytes">${cells}</span><span class="lay-gap${laneCls}" style="--lay:${laneColor}"></span></span>
      <span class="ascii">${ascii}</span>
    </div>`;
  }

  function hoverByte(off, e) {
    if (!state.model) return;
    const seg = segAt(off);
    if (!seg) return;
    if (!state.hoverSeg || state.hoverSeg.id !== seg.id) {
      $$('.hl', els.hexWindow).forEach(el => el.classList.remove('hl'));
      state.hoverSeg = seg;
      $$(`[data-s="${seg.id}"]`, els.hexWindow).forEach(el => el.classList.add('hl'));
    }
    setStatus(off);
    showHexTooltip(seg, off, e);
  }

  function hideHover() {
    if (!state.hoverSeg) {
      hideTooltip();
      return;
    }
    state.hoverSeg = null;
    $$('.hl', els.hexWindow).forEach(el => el.classList.remove('hl'));
    hideTooltip();
    setStatus(state.selected ? state.selected.focus : null);
  }

  function showHexTooltip(seg, off, e) {
    const v = displayForSegment(seg);
    let fieldLine = '';
    if (seg.entryType && seg.entryBase != null && seg.entryType !== 'symbol-range') {
      const f = P.fieldForEntryOffset(seg.entryType, state.model.classBits, off - seg.entryBase);
      if (f) fieldLine = f.label;
    }
    const sec = seg.sectionIndex != null ? state.model.sections[seg.sectionIndex] : sectionAtOffset(off);
    const info = state.colorMode === 'kind'
      ? (P.KIND_INFO[seg.kind] || {})
      : (P.ROLE_INFO[seg.role] || {});
    const role = P.ROLE_INFO[seg.role] || {};
    let fields = '';
    if (v.fields && v.fields.length) {
      fields = `<div class="tt-fields">${v.fields.map(([k, val]) =>
        `<span>${esc(k)}</span><b>${esc(val)}</b>`).join('')}</div>`;
    }
    const html = `
      <div class="tt-kicker"><span class="sw" style="--c:${info.color || '#64748b'}"></span>${esc(info.label || seg.kind)}${sec ? ' · ' + esc(sec.name) : ''}<span class="r">0x${hexNum(off)}</span></div>
      <div class="tt-title">${esc(v.title)}</div>
      ${v.value ? `<div class="tt-value">${esc(v.value)}</div>` : ''}
      ${v.desc ? `<div class="tt-desc">${esc(v.desc)}</div>` : ''}
      ${fieldLine ? `<div class="tt-meta">字段 <b>${esc(fieldLine)}</b> · 段长 ${seg.end - seg.start} B</div>` : ''}
      ${fields}
      <div class="tt-meta"><span>字节 0x${hexNum(seg.start)}–0x${hexNum(seg.end)}</span><span>${role.label || ''}</span></div>
    `;
    els.tooltip.innerHTML = html;
    els.tooltip.classList.add('show');
    positionTooltip(e.clientX, e.clientY);
  }

  function positionTooltip(x, y) {
    const tt = els.tooltip;
    const w = tt.offsetWidth;
    const h = tt.offsetHeight;
    let left = x + 16;
    let top = y + 18;
    if (left + w > window.innerWidth - 10) left = x - w - 16;
    if (top + h > window.innerHeight - 10) top = y - h - 16;
    left = Math.max(8, left);
    top = Math.max(8, top);
    tt.style.left = left + 'px';
    tt.style.top = top + 'px';
  }

  function hideTooltip() {
    els.tooltip.classList.remove('show');
  }

  function displayForSegment(seg) {
    if (seg.field) {
      return { title: seg.field, value: seg.valueText || '', desc: seg.desc || '', fields: [] };
    }
    if (seg.entryType === 'symbol' && seg.ref) {
      const s = seg.ref;
      return {
        title: s.name || '(未命名符号)',
        value: `${s.typeName.replace('STT_', '')} · ${s.bindName.replace('STB_', '')}${s.defined ? '' : ' · UND'}`,
        desc: s.defined ? `符号值 0x${hexNum(s.value)}，大小 ${fmtBytes(s.size)}，位于 ${s.shndxName}。` : '这是一个未定义（外部引用）符号，等待动态链接器解析。',
        fields: [
          ['值', '0x' + hexNum(s.value)],
          ['大小', fmtBytes(s.size)],
          ['所在节', s.shndxName || '—']
        ]
      };
    }
    if (seg.entryType === 'symbol-range' && seg.ref) {
      const s = seg.ref;
      return {
        title: s.name || '(未命名符号)',
        value: `${s.typeName.replace('STT_', '')} · ${s.bindName.replace('STB_', '')}`,
        desc: `函数/数据的符号范围，大小 ${fmtBytes(s.rangeSize || s.size)}，值 0x${hexNum(s.value)}。`,
        fields: []
      };
    }
    if ((seg.entryType === 'reloc' || seg.entryType === 'rela' || seg.entryType === 'rel') && seg.ref) {
      const r = seg.ref;
      return {
        title: r.typeName,
        value: `目标 0x${hexNum(r.offset)}`,
        desc: r.target && r.target.section ? `作用于节 ${r.target.section.name}。` : '链接/装载时需要修补的位置。',
        fields: [
          ['符号', r.symbolName || '—'],
          ['加数', relocAddendText(r)]
        ]
      };
    }
    if (seg.entryType === 'dyn' && seg.ref) {
      const d = seg.ref;
      return {
        title: d.tagName,
        value: d.stringValue || ('0x' + hexNum(d.value)),
        desc: d.stringValue ? '动态链接器读取的字符串值。' : '动态链接项的数值。',
        fields: []
      };
    }
    if (seg.entryType === 'rela' || seg.entryType === 'rel') {
      return { title: seg.title, value: '', desc: seg.desc || '', fields: [] };
    }
    return {
      title: seg.title || '未命名',
      value: seg.valueText || '',
      desc: seg.desc || '',
      fields: []
    };
  }

  /* ------------------------------------------------------------------ *
   * Selection / navigation
   * ------------------------------------------------------------------ */

  function segAt(off) {
    const a = state.model && state.model.annotations;
    if (!a || !a.length || off < 0 || off >= state.model.fileSize) return null;
    let lo = 0, hi = a.length - 1, ans = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (a[mid].start <= off) { ans = a[mid]; lo = mid + 1; }
      else hi = mid - 1;
    }
    return ans && off < ans.end ? ans : null;
  }

  function sectionAtOffset(off) {
    if (!state.model) return null;
    for (const s of state.model.sections) {
      if (s.fileRange && off >= s.fileRange.start && off < s.fileRange.end) return s;
    }
    return null;
  }

  function sectionAtVaddr(addr) {
    if (!state.model) return null;
    for (const s of state.model.sections) {
      if (addr >= s.addr && addr < s.addr + (s.size || 0)) return s;
    }
    return null;
  }

  function symbolRangeAt(off) {
    const list = state.symbolRanges;
    if (!list.length) return null;
    let lo = 0, hi = list.length - 1, ans = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (list[mid].start <= off) { ans = list[mid]; lo = mid + 1; }
      else hi = mid - 1;
    }
    return ans && off < ans.end ? ans : null;
  }

  function selectByte(off, scroll) {
    if (!state.model || off < 0 || off >= state.model.fileSize) return;
    const seg = segAt(off);
    let start = off;
    let end = off + 1;
    if (seg && (seg.end - seg.start) <= 2048) {
      start = seg.start;
      end = seg.end;
    }
    setSelection(start, end, { focus: off, scroll: !!scroll });
  }

  function setSelection(start, end, opts) {
    opts = opts || {};
    if (!state.model) return;
    start = clamp(start, 0, state.model.fileSize - 1);
    end = clamp(end == null ? start + 1 : end, start + 1, state.model.fileSize);
    const focus = clamp(opts.focus == null ? start : opts.focus, start, end - 1);
    state.selected = { start, end, focus };
    state.sectionFocus = null;
    const sec = sectionAtOffset(start);
    state.activeSection = sec ? sec.index : null;
    if (opts.scroll) scrollToOffset(start);
    renderRows(true);
    updateMinimapSelection();
    renderInspector();
    updateSectionActive();
    setStatus(focus);
    if (!opts.keepTab) setTab('inspect');
  }

  function scrollToOffset(off) {
    const row = Math.floor(off / ROW_BYTES);
    const target = row * ROW_H - Math.max(0, (els.hexScroll.clientHeight - ROW_H) / 2);
    els.hexScroll.scrollTop = Math.max(0, target);
    renderRows(true);
    updateMinimapViewport();
  }

  function selectSection(index) {
    const sec = state.model && state.model.sections[index];
    if (!sec) return;
    state.activeSection = index;
    if (sec.fileRange) {
      setSelection(sec.fileRange.start, sec.fileRange.end,
        { focus: sec.fileRange.start, scroll: true });
      state.sectionFocus = sec;
      state.activeSection = index;
      renderInspector();
      updateSectionActive();
    } else {
      // NOBITS sections have no bytes in the file. Keep the hex view where it
      // is and explain the section in the inspector instead of jumping to an
      // offset that belongs to some unrelated section.
      state.selected = null;
      state.sectionFocus = sec;
      updateMinimapSelection();
      renderInspector();
      updateSectionActive();
      setTab('inspect');
      setStatus(null);
    }
  }

  function selectEntry(kind, index) {
    const m = state.model;
    if (!m) return;
    let start = 0, end = 1, focus = 0;
    if (kind === 'ph') {
      const p = m.programHeaders[index];
      if (!p) return;
      start = p.base; end = p.base + p.entsize; focus = start;
    } else if (kind === 'sh') {
      const s = m.sections[index];
      if (!s) return;
      start = s.headerOffset; end = start + s.entsize; focus = start;
    } else if (kind === 'sym') {
      const s = m.symbols[index];
      if (!s) return;
      const sec = m.sections.find(x => x.name === s.table);
      const ent = sec && sec.entsize ? sec.entsize : (m.classBits === 64 ? 24 : 16);
      start = s.base; end = start + ent; focus = start;
    } else if (kind === 'reloc') {
      const r = m.relocs[index];
      if (!r) return;
      const ent = r.rela ? (m.classBits === 64 ? 24 : 12) : (m.classBits === 64 ? 16 : 8);
      start = r.base; end = start + ent; focus = start;
    } else if (kind === 'dyn') {
      const d = m.dynamic[index];
      if (!d) return;
      const ent = m.classBits === 64 ? 16 : 8;
      start = d.base; end = start + ent; focus = start;
    } else if (kind === 'note') {
      const n = m.notes[index];
      if (!n) return;
      start = n.offset;
      end = Math.min((n.descEnd + 3) & ~3, m.fileSize);
      focus = n.offset;
    }
    setSelection(start, end, { focus, scroll: true });
  }

  function goToSymbolContent(sym) {
    if (!sym || sym.fileOffset == null) {
      toast('该符号没有对应的文件内容（未定义或位于 NOBITS 节）。');
      return;
    }
    const seg = segAt(sym.fileOffset);
    if (seg && seg.entryType === 'symbol-range' && seg.end - seg.start <= 2048) {
      setSelection(seg.start, seg.end, { focus: sym.fileOffset, scroll: true });
    } else {
      setSelection(sym.fileOffset, sym.fileOffset + 1, { focus: sym.fileOffset, scroll: true });
    }
  }

  function goToSectionContent(sec) {
    if (!sec) return;
    if (sec.fileRange) {
      selectSection(sec.index);
    } else {
      toast('该节是 NOBITS，在文件中没有字节。');
    }
  }

  function goToRelocTarget(rel) {
    if (!rel || !rel.target) return;
    let off = null;
    if (rel.target.kind === 'section') {
      const sec = rel.target.section;
      off = sec.offset + rel.offset;
    } else {
      const sec = sectionAtVaddr(rel.target.vaddr);
      if (sec) off = sec.offset + (rel.target.vaddr - sec.addr);
    }
    if (off == null || off < 0 || off >= state.model.fileSize) {
      toast('重定位目标不在任何有文件内容的节中。');
      return;
    }
    selectByte(off, true);
  }

  /* ------------------------------------------------------------------ *
   * Inspector
   * ------------------------------------------------------------------ */

  function renderInspector() {
    if (!state.model) return;
    if (state.sectionFocus) {
      const sec = state.sectionFocus;
      els.tabInspect.innerHTML = sec.fileRange ? sectionSelectionHTML(sec) : sectionOnlyHTML(sec);
      return;
    }
    const sel = state.selected;
    if (!sel) {
      els.tabInspect.innerHTML = emptyInspectorHTML();
      return;
    }
    const { start, end, focus } = sel;
    const seg = segAt(focus) || segAt(start);
    if (!seg) {
      els.tabInspect.innerHTML = emptyInspectorHTML();
      return;
    }
    const kindInfo = P.KIND_INFO[seg.kind] || { label: seg.kind, color: '#64748b' };
    const roleInfo = P.ROLE_INFO[seg.role] || { label: seg.role, color: '#64748b' };
    const sec = seg.sectionIndex != null ? state.model.sections[seg.sectionIndex] : sectionAtOffset(focus);
    const display = displayForSegment(seg);
    const isRange = end - start > 1;
    const entryField = seg.entryType && seg.entryBase != null && seg.entryType !== 'symbol-range'
      ? P.fieldForEntryOffset(seg.entryType, state.model.classBits, focus - seg.entryBase) : null;
    const shdrSec = findShdrAt(focus);
    const phdr = findPhdrAt(focus);
    const note = findNoteAt(focus);
    const symRange = symbolRangeAt(focus);

    let html = `
      <div class="insp-kicker">
        <span class="pill" style="--c:${kindInfo.color}">${esc(kindInfo.label)}</span>
        <span>0x${hexNum(start)}${end - start > 1 ? ' – 0x' + hexNum(end - 1) : ''}</span>
        <span class="r">${isRange ? fmtBytes(end - start) : '1 B'}</span>
      </div>
      <div class="insp-title">${esc(display.title)}</div>
      ${display.value ? `<div class="insp-value">${esc(display.value)}</div>` : ''}
      ${display.desc ? `<div class="insp-desc">${esc(display.desc)}</div>` : ''}
      <div class="tagrow">
        <span class="tag"><i class="sw" style="--c:${roleInfo.color}"></i>${esc(roleInfo.label)}</span>
        ${sec ? `<span class="tag mono" style="--c:${kindInfo.color}">${esc(sec.name)}</span>` : ''}
        ${seg.field ? `<span class="tag mono">${esc(seg.field)}</span>` : ''}
        ${isRange ? `<span class="tag mono">${end - start} 字节</span>` : ''}
      </div>
    `;

    if (entryField) {
      html += `<div class="field-hint">当前字节属于字段 <b>${esc(entryField.label)}</b> · 偏移 +${focus - seg.entryBase} B</div>`;
    }

    if (seg.entryType === 'symbol-range' && seg.ref) {
      html += symbolBlockHTML(seg.ref, '符号范围');
    } else if (seg.entryType === 'symbol' && seg.ref) {
      html += symbolBlockHTML(seg.ref, '符号条目');
    } else if ((seg.entryType === 'reloc' || seg.entryType === 'rela' || seg.entryType === 'rel') && seg.ref) {
      html += relocBlockHTML(seg.ref);
    } else if (seg.entryType === 'dyn' && seg.ref) {
      html += dynBlockHTML(seg.ref);
    }

    if (shdrSec) html += shdrBlockHTML(shdrSec, seg);
    if (phdr) html += phdrBlockHTML(phdr, seg);
    if (note) html += noteBlockHTML(note, seg);
    if (sec) html += sectionBlockHTML(sec);
    if (!sec && symRange) html += symbolBlockHTML(symRange.ref, '所在符号');

    html += `<div class="insp-section">
      <div class="panel-title">字节内容 <span class="right">0x${hexNum(start)}</span></div>
      ${bytesPreviewHTML(start, end)}
    </div>`;

    els.tabInspect.innerHTML = html;
  }

  function emptyInspectorHTML() {
    return `<div class="insp-empty">
      <div class="glyph">◈</div>
      <h3>点击任意字节</h3>
      <p>查看它属于哪个字段、值代表什么，以及所在的节、符号与重定位。</p>
      <div class="field-hint" style="justify-content:center">悬停预览 · 点击锁定</div>
    </div>`;
  }

  function sectionSelectionHTML(sec) {
    const info = P.KIND_INFO[sec.kind] || { label: sec.kind, color: '#64748b' };
    const start = sec.fileRange.start;
    const end = sec.fileRange.end;
    return `
      <div class="insp-kicker">
        <span class="pill" style="--c:${info.color}">${esc(info.label)}</span>
        <span>0x${hexNum(start)} – 0x${hexNum(end - 1)}</span>
        <span class="r">${fmtBytes(end - start)}</span>
      </div>
      <div class="insp-title">${esc(sec.name || '[' + sec.index + ']')}</div>
      <div class="insp-desc">已选中整个节：文件偏移 0x${hexNum(start)}，共 ${fmtBytes(end - start)}。在十六进制视图中点击任意字节，可继续查看更细的字段/符号解释。</div>
      <div class="tagrow">
        <span class="tag mono">${esc(sec.typeName)}</span>
        <span class="tag mono">${esc(sec.flagsText)}</span>
        <span class="tag mono">节 [${sec.index}]</span>
      </div>
      ${sectionBlockHTML(sec)}
      <div class="insp-section">
        <div class="panel-title">节内容预览 <span class="right">前 ${Math.min(64, end - start)} B</span></div>
        ${bytesPreviewHTML(start, Math.min(end, start + 64))}
      </div>`;
  }

  function sectionOnlyHTML(sec) {
    const info = P.KIND_INFO[sec.kind] || { label: sec.kind, color: '#64748b' };
    return `
      <div class="insp-kicker"><span class="pill" style="--c:${info.color}">${esc(info.label)}</span><span>NOBITS</span></div>
      <div class="insp-title">${esc(sec.name)}</div>
      <div class="insp-desc">该节类型为 SHT_NOBITS，在文件中不占用任何字节；载入内存时由 0 填充。它的“大小”是运行时占用的内存大小。十六进制视图保持当前位置。</div>
      ${sectionBlockHTML(sec, true)}
      <div class="insp-section">
        <div class="panel-title">运行时信息</div>
        <dl class="kvlist">
          <div class="kvrow"><dt>虚拟地址</dt><dd>0x${hexNum(sec.addr)}</dd></div>
          <div class="kvrow"><dt>内存大小</dt><dd>${fmtBytes(sec.size)}</dd></div>
          <div class="kvrow"><dt>文件偏移</dt><dd>0x${hexNum(sec.offset)}（无内容）</dd></div>
        </dl>
      </div>`;
  }

  function symbolBlockHTML(sym, label) {
    if (!sym) return '';
    const sec = state.model.sections.find(s => s.name === sym.table);
    const ent = sec && sec.entsize ? sec.entsize : (state.model.classBits === 64 ? 24 : 16);
    return `<div class="block">
      <div class="block-head">
        <h4>${esc(label || '符号')}</h4>
        <span class="mini">${esc(sym.table)} #${sym.index}</span>
      </div>
      <div class="block-body">
        <div class="symbol-name">${esc(sym.name || '(未命名)')}</div>
        <div class="symbol-meta" style="margin-top:4px">${esc(sym.typeName)} · ${esc(sym.bindName)} · ${esc(sym.visName)}</div>
        <dl class="kvlist" style="margin-top:8px">
          <div class="kvrow"><dt>符号值</dt><dd class="num">0x${hexNum(sym.value)}</dd></div>
          <div class="kvrow"><dt>大小</dt><dd>${sym.size ? fmtBytes(sym.size) : '未知 (0)'}</dd></div>
          <div class="kvrow"><dt>所在节</dt><dd>${esc(sym.shndxName || '—')}</dd></div>
          <div class="kvrow"><dt>文件偏移</dt><dd>${sym.fileOffset != null ? '0x' + hexNum(sym.fileOffset) : '—'}</dd></div>
          <div class="kvrow"><dt>条目位置</dt><dd>0x${hexNum(sym.base)} · ${ent} B</dd></div>
        </dl>
        <div class="btnrow">
          <button class="chip-btn" data-act="sel-sym" data-i="${sym.globalIndex != null ? sym.globalIndex : state.model.symbols.indexOf(sym)}">选中符号条目</button>
          ${sym.fileOffset != null ? `<button class="chip-btn" data-act="goto-sym" data-i="${sym.globalIndex != null ? sym.globalIndex : state.model.symbols.indexOf(sym)}">定位符号内容</button>` : ''}
        </div>
      </div>
    </div>`;
  }

  function relocBlockHTML(rel) {
    const target = rel.target && rel.target.section
      ? `${rel.target.section.name} @ 0x${hexNum(rel.target.vaddr)}`
      : (rel.target ? '0x' + hexNum(rel.target.vaddr) : '—');
    return `<div class="block">
      <div class="block-head"><h4>重定位条目</h4><span class="mini">${esc(rel.table)} #${rel.index}</span></div>
      <div class="block-body">
        <dl class="kvlist">
          <div class="kvrow"><dt>类型</dt><dd>${esc(rel.typeName)} <span style="color:#5d7189">(${rel.type})</span></dd></div>
          <div class="kvrow"><dt>r_offset</dt><dd class="num">0x${hexNum(rel.offset)}</dd></div>
          <div class="kvrow"><dt>符号</dt><dd>${esc(rel.symbolName || '—')}</dd></div>
          <div class="kvrow"><dt>加数</dt><dd>${esc(relocAddendText(rel))}</dd></div>
          <div class="kvrow"><dt>目标</dt><dd>${esc(target)}</dd></div>
        </dl>
        <div class="btnrow">
          <button class="chip-btn" data-act="sel-reloc" data-i="${rel.globalIndex}">选中重定位条目</button>
          <button class="chip-btn" data-act="goto-reloc" data-i="${rel.globalIndex}">定位目标位置</button>
        </div>
      </div>
    </div>`;
  }

  function dynBlockHTML(d) {
    return `<div class="block">
      <div class="block-head"><h4>动态链接项</h4><span class="mini">${esc(d.table)} #${d.index}</span></div>
      <div class="block-body">
        <dl class="kvlist">
          <div class="kvrow"><dt>d_tag</dt><dd>${esc(d.tagName)} <span style="color:#5d7189">(${'0x' + d.tag.toString(16)})</span></dd></div>
          <div class="kvrow"><dt>d_val</dt><dd>0x${hexNum(d.value)} <span style="color:#5d7189">(${fmtNum(d.value)})</span></dd></div>
          ${d.stringValue ? `<div class="kvrow"><dt>字符串</dt><dd>${esc(d.stringValue)}</dd></div>` : ''}
          ${d.flags1 && d.flags1.length ? `<div class="kvrow"><dt>FLAGS_1</dt><dd>${esc(d.flags1.join(' | '))}</dd></div>` : ''}
        </dl>
        <div class="btnrow"><button class="chip-btn" data-act="sel-dyn" data-i="${d.globalIndex}">选中动态项</button></div>
      </div>
    </div>`;
  }

  function shdrBlockHTML(sec) {
    const isSelHeader = state.selected && state.selected.start >= sec.headerOffset &&
      state.selected.start < sec.headerOffset + sec.entsize;
    return `<div class="block">
      <div class="block-head"><h4>节头</h4><span class="mini">[${sec.index}] ${esc(sec.name || '')}</span></div>
      <div class="block-body">
        <dl class="kvlist">
          <div class="kvrow"><dt>sh_type</dt><dd>${esc(sec.typeName)} (${'0x' + sec.type.toString(16)})</dd></div>
          <div class="kvrow"><dt>sh_flags</dt><dd>${esc(sec.flagsText)}</dd></div>
          <div class="kvrow"><dt>sh_addr</dt><dd>0x${hexNum(sec.addr)}</dd></div>
          <div class="kvrow"><dt>sh_offset</dt><dd>0x${hexNum(sec.offset)}</dd></div>
          <div class="kvrow"><dt>sh_size</dt><dd>${fmtBytes(sec.size)}</dd></div>
          <div class="kvrow"><dt>sh_link / info</dt><dd>${sec.link} / ${sec.info}</dd></div>
        </dl>
        <div class="btnrow">
          ${!isSelHeader ? `<button class="chip-btn" data-act="sel-shdr" data-i="${sec.index}">选中节头结构</button>` : ''}
          <button class="chip-btn" data-act="goto-section" data-i="${sec.index}">定位节内容</button>
        </div>
      </div>
    </div>`;
  }

  function phdrBlockHTML(p) {
    const isSel = state.selected && state.selected.start >= p.base &&
      state.selected.start < p.base + p.entsize;
    return `<div class="block">
      <div class="block-head"><h4>程序头</h4><span class="mini">#${p.index} ${esc(p.typeName)}</span></div>
      <div class="block-body">
        <dl class="kvlist">
          <div class="kvrow"><dt>权限</dt><dd>${esc(p.flagsText)}</dd></div>
          <div class="kvrow"><dt>文件范围</dt><dd>0x${hexNum(p.offset)} · ${fmtBytes(p.filesz)}</dd></div>
          <div class="kvrow"><dt>虚拟地址</dt><dd>0x${hexNum(p.vaddr)} · ${fmtBytes(p.memsz)}</dd></div>
          <div class="kvrow"><dt>对齐</dt><dd>0x${hexNum(p.align)}</dd></div>
        </dl>
        <div class="btnrow">
          ${!isSel ? `<button class="chip-btn" data-act="sel-phdr" data-i="${p.index}">选中程序头结构</button>` : ''}
          <button class="chip-btn" data-act="goto-phcontent" data-i="${p.index}">定位段内容</button>
        </div>
      </div>
    </div>`;
  }

  function noteBlockHTML(note) {
    return `<div class="block">
      <div class="block-head"><h4>Note 附注</h4><span class="mini">${esc(note.section)}</span></div>
      <div class="block-body">
        <dl class="kvlist">
          <div class="kvrow"><dt>名称空间</dt><dd>${esc(note.name || '—')}</dd></div>
          <div class="kvrow"><dt>类型</dt><dd>${esc(note.typeName)} (${note.type})</dd></div>
          <div class="kvrow"><dt>长度</dt><dd>name ${note.namesz} B · desc ${note.descsz} B</dd></div>
        </dl>
        ${note.descText ? `<div class="note-preview" style="margin-top:8px">${esc(note.descText)}</div>` : ''}
        <div class="btnrow"><button class="chip-btn" data-act="sel-note" data-i="${note.index}">选中整条 Note</button></div>
      </div>
    </div>`;
  }

  function sectionBlockHTML(sec) {
    if (!sec) return '';
    const info = P.KIND_INFO[sec.kind] || { color: '#64748b', label: sec.kind };
    return `<div class="block">
      <div class="block-head">
        <h4>所在节</h4>
        <span class="mini">${esc(sec.typeName)}</span>
        <span class="spacer"></span>
        <span class="mini" style="color:${info.color}">${esc(info.label)}</span>
      </div>
      <div class="block-body">
        <div style="display:flex;align-items:center;gap:7px">
          <span class="sw" style="--c:${info.color};width:8px;height:8px"></span>
          <span class="symbol-name" style="color:#d9ecff">${esc(sec.name)}</span>
        </div>
        <dl class="kvlist" style="margin-top:8px">
          <div class="kvrow"><dt>标志</dt><dd>${esc(sec.flagsText)} <span style="color:#5d7189">${esc(sec.flags ? '0x' + sec.flags.toString(16) : '')}</span></dd></div>
          <div class="kvrow"><dt>地址</dt><dd>0x${hexNum(sec.addr)}</dd></div>
          <div class="kvrow"><dt>文件偏移</dt><dd>0x${hexNum(sec.offset)}</dd></div>
          <div class="kvrow"><dt>大小</dt><dd>${fmtBytes(sec.size)}</dd></div>
          <div class="kvrow"><dt>对齐 / 条目</dt><dd>${sec.addralign || 0} / ${sec.entsize || 0} B</dd></div>
        </dl>
        <div class="btnrow">
          <button class="chip-btn" data-act="sel-shdr" data-i="${sec.index}">选中节头结构</button>
          ${sec.fileRange ? `<button class="chip-btn" data-act="goto-section" data-i="${sec.index}">定位节内容</button>` : ''}
        </div>
      </div>
    </div>`;
  }

  function bytesPreviewHTML(start, end) {
    const m = state.model;
    const limit = Math.min(end, start + 64);
    const bytes = m.bytes.subarray(start, limit);
    const parts = [];
    let ascii = '';
    for (let i = 0; i < bytes.length; i++) {
      parts.push(bytes[i].toString(16).padStart(2, '0').toUpperCase());
      const c = bytes[i];
      ascii += c >= 32 && c <= 126 ? esc(String.fromCharCode(c)) : '·';
    }
    const line = parts.map((p, i) => (i % 16 === 15 && i !== parts.length - 1 ? p + '<br>' : p)).join(' ');
    const more = end - start > bytes.length ? `<span class="more"> … 还有 ${fmtBytes(end - start - bytes.length)}</span>` : '';
    return `<div class="bytes-preview"><div class="hexline">${line}</div><div class="asciiline">${ascii}${more}</div></div>`;
  }

  /* ------------------------------------------------------------------ *
   * Structure tab
   * ------------------------------------------------------------------ */

  function renderStructure() {
    const m = state.model;
    const total = m.headerFields.length + m.programHeaders.length + m.sections.length +
      m.symbols.length + m.relocs.length + m.dynamic.length + m.notes.length;
    els.structCount.textContent = fmtNum(total);

    const headerRows = m.headerFields.map(f => `
      <div class="hdr-row" data-act="field" data-start="${f.start}" data-size="${f.size}" title="${esc(f.desc)}">
        <span class="k">${esc(f.label)}</span>
        <span class="v">${esc(f.valueText)}</span>
      </div>`).join('');

    const phRows = m.programHeaders.map(p => `
      <div class="struct-row ph-row" role="button" tabindex="0" data-act="sel-phdr" data-i="${p.index}">
        <div class="top">
          <span class="idx">#${String(p.index).padStart(2, '0')}</span>
          <span class="name">${esc(p.typeName)}</span>
          <span class="flags">${esc(p.flagsText)}</span>
          <button class="jumpbtn" data-act="goto-phcontent" data-i="${p.index}" title="定位段内容">↗</button>
        </div>
        <div class="bottom">off <b>0x${hexNum(p.offset)}</b> · va <b>0x${hexNum(p.vaddr)}</b> · ${fmtBytes(p.filesz)} / ${fmtBytes(p.memsz)}</div>
      </div>`).join('');

    const shRows = m.sections.map(s => {
      const info = P.KIND_INFO[s.kind] || { color: '#64748b' };
      return `<div class="struct-row sh-row" role="button" tabindex="0" data-act="sel-shdr" data-i="${s.index}">
        <div class="top">
          <span class="dot" style="width:6px;height:6px;border-radius:2px;background:${info.color};flex:0 0 auto"></span>
          <span class="idx">[${s.index}]</span>
          <span class="name">${esc(s.name || '(无名)')}</span>
          <button class="jumpbtn" data-act="goto-section" data-i="${s.index}" title="定位节内容">↗</button>
        </div>
        <div class="bottom">${esc(s.typeName)} · addr <b>0x${hexNum(s.addr)}</b> · off <b>0x${hexNum(s.offset)}</b> · ${fmtBytes(s.size)}</div>
      </div>`;
    }).join('');

    const relRows = m.relocs.length
      ? `<div id="relList">${renderRelocRows()}</div>`
      : `<div class="empty-row">没有重定位表</div>`;
    const dynRows = m.dynamic.length
      ? m.dynamic.slice(0, 400).map(d => `
        <div class="struct-row dyn-row" role="button" tabindex="0" data-act="sel-dyn" data-i="${d.globalIndex}">
          <div class="top"><span class="tag">${esc(d.tagName)}</span></div>
          <div class="bottom"><span class="val">${esc(d.stringValue || '0x' + hexNum(d.value))}</span></div>
        </div>`).join('')
      : `<div class="empty-row">没有动态链接表</div>`;
    const noteRows = m.notes.length
      ? m.notes.map(n => `
        <div class="struct-row note-row" role="button" tabindex="0" data-act="sel-note" data-i="${n.index}">
          <div class="top"><span class="name">${esc(n.name || '—')}</span><span class="type">${esc(n.typeName)}</span></div>
          <div class="bottom">${esc(n.descText || n.descHex || '')}</div>
        </div>`).join('')
      : `<div class="empty-row">没有 Note</div>`;

    els.structScroll.innerHTML = `
      ${acc('ELF 头', `${m.headerFields.length} 字段`, headerRows, true)}
      ${acc('程序头表', `${m.programHeaders.length} 条`, phRows || '<div class="empty-row">没有程序头</div>', false)}
      ${acc('节头表', `${m.sections.length} 条`, shRows, false)}
      ${acc('符号表', `${m.symbols.length} 个`, `
        <input class="struct-search" id="symSearch" placeholder="按名称 / 所属节过滤符号…" value="${esc(state.symFilter)}" autocomplete="off">
        <div id="symList"></div>`, false)}
      ${acc('重定位', `${m.relocs.length} 条`, relRows, false)}
      ${acc('动态链接', `${m.dynamic.length} 条`, dynRows, false)}
      ${acc('Note 附注', `${m.notes.length} 条`, noteRows, false)}
    `;
    renderSymbolList();
  }

  function acc(title, count, body, open) {
    return `<details class="acc"${open ? ' open' : ''}>
      <summary>${esc(title)}<span class="num">${esc(count)}</span></summary>
      <div class="acc-body">${body}</div>
    </details>`;
  }

  function renderSymbolList() {
    const host = document.getElementById('symList');
    if (!host) return;
    const m = state.model;
    const q = state.symFilter.trim().toLowerCase();
    let list = m.symbols;
    if (q) {
      list = list.filter(s =>
        (s.name || '').toLowerCase().includes(q) ||
        (s.shndxName || '').toLowerCase().includes(q) ||
        (s.typeName || '').toLowerCase().includes(q) ||
        (s.bindName || '').toLowerCase().includes(q));
    }
    const shown = list.slice(0, state.symLimit);
    host.innerHTML = shown.map(symRowHTML).join('') || '<div class="empty-row">没有匹配的符号</div>';
    if (list.length > shown.length) {
      host.innerHTML += `<button class="more-row" data-act="more-sym">显示更多（剩余 ${fmtNum(list.length - shown.length)} 个）</button>`;
    }
  }

  function symRowHTML(s) {
    const idx = s.globalIndex != null ? s.globalIndex : state.model.symbols.indexOf(s);
    const loc = s.fileOffset != null ? 'off 0x' + hexNum(s.fileOffset) : (s.defined ? '无文件内容' : 'UND');
    return `<div class="struct-row sym-row" role="button" tabindex="0" data-act="sel-sym" data-i="${idx}">
      <div class="top">
        <span class="idx">${s.index}</span>
        <span class="name">${esc(s.name || '(空)')}</span>
        <span class="bind">${esc(s.typeName.replace('STT_', ''))} · ${esc(s.bindName.replace('STB_', ''))}</span>
        ${s.fileOffset != null ? `<button class="jumpbtn" data-act="goto-sym" data-i="${idx}" title="定位符号内容">↗</button>` : ''}
      </div>
      <div class="bottom"><b>0x${hexNum(s.value)}</b> · ${s.size ? fmtBytes(s.size) : '0 B'} · ${esc(s.shndxName)} · ${esc(s.table)}</div>
    </div>`;
  }

  function renderRelocRows() {
    const m = state.model;
    const shown = m.relocs.slice(0, state.relLimit);
    let html = shown.map(r => `
      <div class="struct-row rel-row" role="button" tabindex="0" data-act="sel-reloc" data-i="${r.globalIndex}">
        <div class="top">
          <span class="type">${esc(r.typeName)}</span>
          <button class="jumpbtn" data-act="goto-reloc" data-i="${r.globalIndex}" title="定位目标">↗</button>
        </div>
        <div class="bottom">off <b>0x${hexNum(r.offset)}</b> · <span class="sym">${esc(r.symbolName || '—')}</span>${r.addend != null ? ' · addend ' + esc(relocAddendText(r)) : ''}</div>
      </div>`).join('');
    if (m.relocs.length > shown.length) {
      html += `<button class="more-row" data-act="more-reloc">显示更多（剩余 ${fmtNum(m.relocs.length - shown.length)} 条）</button>`;
    }
    return html;
  }

  function updateRelocList() {
    const host = document.getElementById('relList');
    if (host) host.innerHTML = renderRelocRows();
  }

  /* ------------------------------------------------------------------ *
   * Actions
   * ------------------------------------------------------------------ */

  function handleAction(act, el) {
    const i = Number(el.dataset.i);
    const m = state.model;
    if (!m) return;
    switch (act) {
      case 'sel-sym': selectEntry('sym', i); break;
      case 'goto-sym': goToSymbolContent(m.symbols[i]); break;
      case 'sel-reloc': selectEntry('reloc', i); break;
      case 'goto-reloc': goToRelocTarget(m.relocs[i]); break;
      case 'sel-dyn': selectEntry('dyn', i); break;
      case 'sel-note': selectEntry('note', i); break;
      case 'sel-shdr': selectEntry('sh', i); break;
      case 'sel-phdr': selectEntry('ph', i); break;
      case 'goto-section': goToSectionContent(m.sections[i]); break;
      case 'goto-phcontent': {
        const p = m.programHeaders[i];
        if (!p || !p.filesz) { toast('该程序头没有文件内容。'); break; }
        const off = Math.min(p.offset, m.fileSize - 1);
        selectByte(off, true);
        break;
      }
    }
  }

  function handleStructAction(act, el) {
    const m = state.model;
    if (!m) return;
    const i = Number(el.dataset.i);
    switch (act) {
      case 'field': {
        const start = Number(el.dataset.start);
        const size = Number(el.dataset.size);
        setSelection(start, start + size, { focus: start, scroll: true });
        break;
      }
      case 'sel-sym': selectEntry('sym', i); break;
      case 'goto-sym': goToSymbolContent(m.symbols[i]); break;
      case 'sel-reloc': selectEntry('reloc', i); break;
      case 'goto-reloc': goToRelocTarget(m.relocs[i]); break;
      case 'sel-dyn': selectEntry('dyn', i); break;
      case 'sel-note': selectEntry('note', i); break;
      case 'sel-shdr': selectEntry('sh', i); break;
      case 'sel-phdr': selectEntry('ph', i); break;
      case 'goto-section': goToSectionContent(m.sections[i]); break;
      case 'goto-phcontent': handleAction('goto-phcontent', el); break;
      case 'more-sym':
        state.symLimit += 300;
        renderSymbolList();
        break;
      case 'more-reloc':
        state.relLimit += 300;
        updateRelocList();
        break;
    }
  }

  function doJump() {
    if (!state.model) return;
    const raw = els.jumpInput.value.trim().replace(/[_\s,]/g, '');
    if (!raw) return;
    let text = raw;
    if (text.toLowerCase().startsWith('0x')) text = text.slice(2);
    if (!/^[0-9a-f]+$/i.test(text)) {
      toast('偏移格式无效，请输入十六进制数字（如 46b0）。');
      return;
    }
    const off = parseInt(text, 16);
    if (!Number.isFinite(off)) {
      toast('偏移格式无效。');
      return;
    }
    if (off >= state.model.fileSize) {
      toast(`偏移 0x${hexNum(off)} 超出文件大小（0x${hexNum(state.model.fileSize)}）。`);
      return;
    }
    selectByte(off, true);
  }

  /* ------------------------------------------------------------------ *
   * UI helpers
   * ------------------------------------------------------------------ */

  function setColorMode(mode) {
    if (mode !== 'kind' && mode !== 'role') return;
    if (state.colorMode === mode) return;
    state.colorMode = mode;
    state.filter = null;
    $$('#modeSwitch button').forEach(b => b.classList.toggle('on', b.dataset.mode === mode));
    renderLegend();
    renderRows(true);
    hideHover();
  }

  function setTab(name) {
    state.tab = name;
    $$('.tab', els.tabs).forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    els.tabInspect.hidden = name !== 'inspect';
    els.tabStruct.hidden = name !== 'struct';
  }

  function setStatus(off) {
    if (!state.model) return;
    if (off == null || off < 0 || off >= state.model.fileSize) {
      els.statusOffset.textContent = '偏移 —';
      els.statusSection.textContent = '—';
      els.statusField.textContent = '—';
      return;
    }
    const seg = segAt(off);
    const sec = seg && seg.sectionIndex != null ? state.model.sections[seg.sectionIndex] : sectionAtOffset(off);
    els.statusOffset.textContent = '偏移 0x' + hexNum(off);
    els.statusSection.textContent = sec ? sec.name : (seg && seg.kind === 'ehdr' ? 'ELF 头' : '—');
    let field = '';
    if (seg) {
      if (seg.field) field = seg.field;
      else if (seg.entryType && seg.entryBase != null && seg.entryType !== 'symbol-range') {
        const f = P.fieldForEntryOffset(seg.entryType, state.model.classBits, off - seg.entryBase);
        if (f) field = f.label;
      }
      if (!field) field = seg.title || '';
    }
    els.statusField.textContent = field || '—';
  }

  function toast(message, ok) {
    els.toast.textContent = message;
    els.toast.classList.toggle('ok', !!ok);
    els.toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => els.toast.classList.remove('show'), 4200);
  }

  function findShdrAt(off) {
    const m = state.model;
    for (const s of m.sections) {
      if (off >= s.headerOffset && off < s.headerOffset + s.entsize) return s;
    }
    return null;
  }

  function findPhdrAt(off) {
    const m = state.model;
    for (const p of m.programHeaders) {
      if (off >= p.base && off < p.base + p.entsize) return p;
    }
    return null;
  }

  function findNoteAt(off) {
    const m = state.model;
    for (const n of m.notes) {
      const end = (n.descEnd + 3) & ~3;
      if (off >= n.offset && off < end) return n;
    }
    return null;
  }

  /* ------------------------------------------------------------------ *
   * Formatting
   * ------------------------------------------------------------------ */

  function hexNum(n, width) {
    if (typeof n === 'bigint') return n.toString(16);
    if (!Number.isFinite(n)) return '—';
    let s = Math.max(0, Math.trunc(n)).toString(16).toUpperCase();
    if (width) s = s.padStart(width, '0');
    return s;
  }

  function shortMachine(name) {
    const map = {
      EM_386: 'i386', EM_X86_64: 'x86-64', EM_AARCH64: 'AArch64',
      EM_ARM: 'ARM', EM_RISCV: 'RISC-V', EM_PPC: 'PowerPC', EM_PPC64: 'PPC64',
      EM_MIPS: 'MIPS', EM_S390: 's390', EM_SPARC: 'SPARC',
      EM_SPARCV9: 'SPARCv9', EM_IA_64: 'IA-64', EM_LOONGARCH: 'LoongArch',
      EM_ALPHA: 'Alpha', EM_SH: 'SuperH', EM_M68K: 'm68k', EM_AVR: 'AVR'
    };
    return map[name] || name.replace(/^EM_/, '');
  }

  function fmtNum(n) {
    return Number(n).toLocaleString('en-US');
  }

  function fmtBytes(n) {
    if (n == null || !Number.isFinite(n)) return '—';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) {
      const v = n / 1024;
      return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} KiB`;
    }
    const v = n / (1024 * 1024);
    return `${v >= 100 ? v.toFixed(0) : v.toFixed(2)} MiB`;
  }

  function shortBytes(n) {
    if (n < 1024) return n + 'B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n / 1024 >= 100 ? 0 : 1) + 'K';
    return (n / (1024 * 1024)).toFixed(2) + 'M';
  }

  function pctDigits(ratio) {
    return ratio < 0.001 ? 2 : ratio < 0.01 ? 1 : 0;
  }

  function relocAddendText(r) {
    if (r.addend == null) return '—';
    if (r.addendBig != null) {
      const big = r.addendBig;
      const neg = big < 0n;
      return (neg ? '-' : '') + '0x' + (neg ? (-big) : big).toString(16);
    }
    return (r.addend < 0 ? '-' : '') + '0x' + Math.abs(r.addend).toString(16);
  }

  function isExecSection(sec) {
    return sec && (sec.flags & 0x4);
  }

  function clamp(n, lo, hi) {
    return Math.max(lo, Math.min(hi, n));
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  /* ------------------------------------------------------------------ */

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
