'use strict';
/* code-analyzer v3 — the evaluation page: a conversation with the agent on the left, the list on the right.
 * Every step also has a button, so the page works with the model lane off.
 * All server data is untrusted (paths, messages, source lines): it reaches the page only through
 * textContent / createTextNode / setAttribute.  No HTML strings are ever parsed. */

const $ = (id) => document.getElementById(id);

// -- vocabulary -------------------------------------------------------------------------------
const LEVEL_TEXT = { error: 'Error', warning: 'Warning', style: 'Style', information: 'Information', unmapped: '未分级' };
const BASIS = {
  'native-exact': ['原生', '依据：工具原生等级，精确映射'],
  'evaluator-rule': ['规则', '依据：评估员确认的分级规则'],
  analyst: ['人工', '依据：分析员采纳'],
  proposed: ['建议', '依据：建议规则，未生效，需人工核实'],
  'ai-proposed': ['AI', '依据：AI 建议，未生效'],
};
const SFR_BASIS = {
  family: '缺陷族直接相关（强）', tsfi: 'TSFI 可达（强）', analyst: '分析员指定（强）', 'ai-confirmed': 'AI 已确认（强）',
  keyword: '路径或函数名关键词（弱）', 'module-default': 'TOE 模块默认关联（弱）',
};
const STRONG_SFR = new Set(['family', 'tsfi', 'analyst', 'ai-confirmed']);
const STATUS = { open: '未处置', confirmed: '确认', false_positive: '误报', not_exploitable: '不可利用', needs_test: '需测试' };
const PARTS = { main: '主分区', unmapped: '未分级（需人工核实）', below: '低于阈值' };
const PROFILE_STATUS = { builtin: '内置', draft: '草稿', confirmed: '已确认' };
const CONF = { client: '客户·仅本地 GPU', public: '公开代码' };
const BLOCK_KIND = {
  event: '事件', job: '任务', summary: '清单', status: '标记', export: '导出', profile: '档案',
  user: '评估员', queued: '排队', agent: 'agent', tool: '工具', approval: '批准卡', error: '出错',
};
const JOB_KIND = { static: '跑工具', extract: '档案抽取', reindex: '重建清单' };
const JOB_STATUS = { running: '运行中', finished: '已完成', failed: '失败', stopped: '已停止' };
const WHY = { level: '等级', strong_sfr: '强 SFR 关联', tsfi_near: '靠近 TSFI', security_family: '安全相关缺陷族',
  engines_agree: '多引擎一致', build_aware: '构建感知' };
const TOOLS = ['cppcheck', 'flawfinder', 'splint'];
const ROLES = { security_target: 'Security Target', test_plan: '测试计划' };
const TABS = ['list', 'evidence', 'profile', 'coverage', 'tasks'];
const LAST_KEY = 'code-analyzer.lastEvaluation';
const MAX_DOCUMENT = 64 * 1024 * 1024;
const BLANK_FILTERS = { level: '', module: '', sfr: '', status: '', path: '', sort: 'priority' };

// -- the one state object -----------------------------------------------------------------------
const S = {
  app: null,          // GET /api/state
  id: null,           // the open evaluation
  ev: null,           // GET /api/e/<id>
  tab: 'list',
  stream: null,
  blockIds: new Set(),
  jobStatus: new Map(),
  filters: { ...BLANK_FILTERS },
  pages: { main: 1, unmapped: 1 },
  picked: new Set(),  // unmapped entries ticked for 采纳建议等级
  listEls: null,      // {main, unmapped} section elements while 清单 is shown
  acceptBtn: null,
  exportOpen: false,
  exportResult: null,
  pvId: null,         // the entry shown in 证据
  pv: null,           // GET /pvs/<pv_id>
  source: null,
  sourceLine: 0,
  radius: 12,
  srcEl: null,
  tools: new Set(),
  runBtn: null,
  jobsEl: null,
  toml: '',
  tomlSha: '',
  tomlDirty: false,
  tomlError: '',
  confirmBy: '',
  docs: [],
  extractJob: '',
  busy: false,        // a conversation turn is running
  live: null,         // {el, textEl, text, note}: the reply streaming in
  typingAt: 0,
  approvalEls: new Map(),  // approval id -> the element holding its buttons
};

// -- plumbing -----------------------------------------------------------------------------------
async function api(path, opts = {}) {
  const init = { method: 'GET', credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (opts.raw !== undefined) {
    Object.assign(init, { method: 'POST', body: opts.raw });
    Object.assign(init.headers, { 'Content-Type': 'application/octet-stream' }, opts.headers);
  } else if (opts.body !== undefined) {
    Object.assign(init, { method: 'POST', body: JSON.stringify(opts.body) });
    init.headers['Content-Type'] = 'application/json';
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw apiError(0, '无法连接 code-analyzer 服务，请确认它仍在运行。');
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) throw apiError(res.status, (data && data.error) || `请求失败（HTTP ${res.status}）`);
  return data;
}

function apiError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

const post = (path, body = {}) => api(path, { body });
const ep = (tail) => `/api/e/${encodeURIComponent(S.id)}${tail}`;

async function act(fn) {
  try {
    return await fn();
  } catch (e) {
    toast(e.message);
    return undefined;
  }
}

const PROPS = new Set(['value', 'checked', 'disabled', 'hidden']);

/** h('tag', {class, on: {event: fn}, attr: value}, ...children) — strings become text nodes. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === 'on') for (const [type, fn] of Object.entries(value)) el.addEventListener(type, fn);
    else if (key === 'class') el.className = value;
    else if (PROPS.has(key)) el[key] = value;
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  return add(el, children);
}

function add(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

function fill(el, ...children) {
  el.replaceChildren();
  return add(el, children);
}

function selectEl(options, value, onChange, attrs = {}) {
  const el = h('select', { ...attrs, on: { change: (ev) => onChange(ev.target.value) } },
    options.map(([v, text]) => h('option', { value: v }, text)));
  el.value = value;
  return el;
}

const button = (text, onClick, cls = 'btn', attrs = {}) =>
  h('button', { class: cls, type: 'button', ...attrs, on: { click: onClick } }, text);

function section(title, body, extra) {
  return h('section', { class: 'section' },
    h('div', { class: 'section-head' }, h('h3', null, title), extra),
    h('div', { class: 'section-body' }, body));
}

function toast(message, kind = 'error') {
  const box = $('toasts');
  const item = h('div', { class: `toast ${kind}`, role: kind === 'error' ? 'alert' : 'status' },
    h('span', { class: 'toast-text' }, message));
  item.appendChild(button('×', () => item.remove(), 'toast-close', { 'aria-label': '关闭提示' }));
  box.appendChild(item);
  while (box.children.length > 3) box.firstElementChild.remove();
  if (kind !== 'error') setTimeout(() => item.remove(), 4000);
}

function remember(id) {
  try { localStorage.setItem(LAST_KEY, id); } catch (e) { /* storage unavailable: nothing to remember */ }
}

function recall() {
  try { return localStorage.getItem(LAST_KEY); } catch (e) { return null; }
}

// -- formatting ---------------------------------------------------------------------------------
const short = (sha) => String(sha || '').slice(0, 12);
const pad = (n) => String(n).padStart(2, '0');

function fmtTime(at) {
  const d = new Date(at);
  if (!at || Number.isNaN(d.getTime())) return String(at || '');
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function fmtElapsed(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  const m = Math.floor(s / 60);
  if (m >= 60) return `${Math.floor(m / 60)} 小时 ${m % 60} 分`;
  return m ? `${m} 分 ${s % 60} 秒` : `${s} 秒`;
}

function levelLabel(level) {
  if (level === 'unmapped') return LEVEL_TEXT.unmapped;
  const found = S.ev && (S.ev.profile.levels || []).find((l) => l.id === level);
  return (found && found.label) || LEVEL_TEXT[level] || String(level || '—');
}

const levelChip = (level) =>
  h('span', { class: `lv ${LEVEL_TEXT[level] ? `lv-${level}` : 'lv-other'}` }, levelLabel(level));

function basisMark(basis) {
  const b = BASIS[basis];
  return b ? h('span', { class: 'basis', title: b[1] }, b[0]) : null;
}

function levelCell(r) {
  return [levelChip(r.level), basisMark(r.level_basis),
    r.level === 'unmapped' && r.proposed_level ? h('span', { class: 'proposed' }, `建议: ${levelLabel(r.proposed_level)}`) : null];
}

function sfrTags(list, max = 2) {
  const items = [...(list || [])].sort((a, b) => STRONG_SFR.has(b.basis) - STRONG_SFR.has(a.basis));
  const tags = items.slice(0, max).map((s) => h('span', {
    class: STRONG_SFR.has(s.basis) ? 'sfr' : 'sfr weak', title: `${s.id} · ${SFR_BASIS[s.basis] || s.basis}`,
  }, s.id));
  if (items.length > max) {
    tags.push(h('span', { class: 'faint small', title: items.slice(max).map((s) => s.id).join('、') }, `+${items.length - max}`));
  }
  return tags.length ? tags : h('span', { class: 'faint' }, '—');
}

const toolsText = (tools) => (Array.isArray(tools) ? tools : String(tools || '').split(',')).filter(Boolean).join('、');
const pathText = (r) => `${r.path}:${r.line_start}`;
const pathCell = (text) => h('td', { class: 'cell-path', title: text }, h('bdi', null, text));
const whenEnter = (fn) => (ev) => { if (ev.key === 'Enter' && ev.target === ev.currentTarget) fn(); };

function levelTotals(byLevel) {
  const rank = (id) => ({ error: 4, warning: 3, style: 2, information: 1 })[id] || 0;
  return Object.entries(byLevel || {}).sort((a, b) => rank(b[0]) - rank(a[0]))
    .map(([level, n]) => h('span', null, levelChip(level), ` ${n}`));
}

// -- picker: no evaluation open -----------------------------------------------------------------
async function showPicker(auto = false) {
  closeStream();
  Object.assign(S, { id: null, ev: null, listEls: null, jobsEl: null, srcEl: null });
  $('workspace').hidden = true;
  $('switch-eval').hidden = true;
  fill($('eval-head'));
  fill($('badges'));
  fill($('stages'));
  document.title = 'code-analyzer · 评估';
  const picker = $('picker');
  try {
    S.app = await api('/api/state');
  } catch (e) {
    picker.hidden = false;
    fill(picker, h('div', { class: 'empty' }, h('p', null, '无法载入评估列表：'), h('p', { class: 'error-box' }, e.message)));
    return;
  }
  const last = auto ? recall() : null;
  if (last && S.app.evaluations.some((e) => e.id === last)) {
    openEval(last);
    return;
  }
  picker.hidden = false;
  renderPicker(picker);
}

function renderPicker(picker) {
  const evs = S.app.evaluations;
  const rows = evs.map((e) => h('tr', {
    class: 'clickable', tabindex: 0, on: { click: () => openEval(e.id), keydown: whenEnter(() => openEval(e.id)) },
  },
  h('td', null, h('div', null, e.name), h('div', { class: 'small muted' }, CONF[e.confidentiality] || e.confidentiality, ' · ', fmtTime(e.created_at))),
  pathCell(e.source),
  h('td', null, e.profile.name, ' ', h('span', { class: `badge ${e.profile.status}` }, PROFILE_STATUS[e.profile.status] || e.profile.status)),
  h('td', { class: 'nowrap small' }, e.counts ? `主分区 ${e.counts.partition_main} · 未分级 ${e.counts.partition_unmapped}` : '尚未跑工具',
    e.running_job ? h('div', { class: 'muted' }, `${JOB_KIND[e.running_job.kind] || e.running_job.kind} 运行中`) : null)));
  const list = evs.length
    ? h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
      h('thead', null, h('tr', null, ['评估', '源码', '档案', '清单'].map((t) => h('th', { scope: 'col' }, t)))),
      h('tbody', null, rows)))
    : h('p', { class: 'empty' }, '还没有评估。用右侧的表单新建一个。');
  const settings = S.app.settings || {};
  fill(picker, h('div', { class: 'picker-inner' },
    h('div', { class: 'card' }, h('h3', null, '打开评估'), list),
    h('div', { class: 'card' }, h('h3', null, '新建评估'), newEvalForm(),
      h('p', { class: 'settings' }, `本地模型 ${settings.model_name || '—'} · ${settings.local_model || '—'}`, h('br'),
        `数据目录 ${settings.data_root || '—'}`))));
}

function newEvalForm() {
  const source = h('input', { type: 'text', required: true, placeholder: '/home/…/source-tree', spellcheck: 'false', autocomplete: 'off' });
  const radio = (value, text) => h('label', { class: 'check' },
    h('input', { type: 'radio', name: 'confidentiality', value, checked: value === 'client' }), text);
  const profiles = S.app.builtin_profiles || [];
  const profile = selectEl(profiles.map((p) => [p, p]), profiles[0] || '', () => {});
  const form = h('form', { class: 'stack', on: { submit: async (ev) => {
    ev.preventDefault();
    const confidentiality = form.querySelector('input[name="confidentiality"]:checked').value;
    const res = await act(() => post('/api/evaluations', { source: source.value.trim(), confidentiality, profile: profile.value }));
    if (res) openEval(res.id);
  } } },
  h('label', { class: 'field' }, '源码路径（绝对路径）', source),
  h('div', { class: 'field', role: 'radiogroup', 'aria-label': '机密性' }, '机密性',
    h('div', { class: 'row center' }, radio('client', CONF.client), radio('public', CONF.public))),
  h('label', { class: 'field' }, '档案（内置，之后可在「档案」页更换或上传）', profile),
  h('div', null, h('button', { class: 'btn primary', type: 'submit' }, '创建并打开')));
  return form;
}

// -- one evaluation -----------------------------------------------------------------------------
async function openEval(id) {
  closeStream();
  Object.assign(S, {
    id, ev: null, filters: { ...BLANK_FILTERS }, pages: { main: 1, unmapped: 1 }, picked: new Set(),
    exportOpen: false, exportResult: null, pvId: null, pv: null, source: null, toml: '', tomlSha: '',
    tomlDirty: false, tomlError: '', docs: [], extractJob: '', blockIds: new Set(), jobStatus: new Map(),
    busy: false, live: null, typingAt: 0, approvalEls: new Map(),
  });
  $('picker').hidden = true;
  $('workspace').hidden = false;
  $('switch-eval').hidden = false;
  if (!(await loadEval())) {
    showPicker(false);
    return;
  }
  remember(id);
  openStream();
}

async function loadEval() {
  const id = S.id;
  const data = await act(() => api(ep('')));
  if (!data || id !== S.id) return false;
  S.ev = data;
  S.busy = Boolean(data.agent && data.agent.busy);
  for (const job of data.jobs) S.jobStatus.set(job.id, job.status);
  renderTop();
  renderTimeline();
  renderComposer();
  if (!panelBusy()) renderTab();
  return true;
}

/** True while the analyst is typing in the panel: a background refresh must not wipe that. */
function panelBusy() {
  const a = document.activeElement;
  return Boolean(a && $('panel').contains(a) && (a.tagName === 'TEXTAREA' || (a.tagName === 'INPUT' && a.type === 'text')));
}

function renderTop() {
  const { evaluation: e, profile: p, triage, jobs } = S.ev;
  document.title = `${e.name} · code-analyzer`;
  fill($('eval-head'), h('span', { class: 'eval-name', title: e.name }, e.name),
    h('span', { class: 'eval-source', title: e.source }, h('bdi', null, e.source)));
  const settings = (S.app && S.app.settings) || {};
  fill($('badges'),
    h('span', { class: `badge ${p.status}`, title: `sha256 ${p.sha256}` }, `档案 ${p.name} · ${PROFILE_STATUS[p.status] || p.status}`),
    h('span', { class: `badge ${e.confidentiality === 'client' ? 'client' : 'public'}` }, CONF[e.confidentiality] || e.confidentiality),
    settings.model_name ? h('span', { class: 'badge model', title: settings.local_model }, `本地 GPU · ${settings.model_name}`) : null);
  const running = jobs.find((j) => j.status === 'running');
  const tools = running && running.kind === 'static';
  const stage = (name, cls, state) => h('li', { class: cls }, h('span', { class: 'stage-name' }, name),
    state ? h('span', { class: 'stage-state' }, state) : null);
  fill($('stages'),
    stage('档案', p.status === 'confirmed' ? 'done' : 'current', PROFILE_STATUS[p.status] || p.status),
    stage('工具', tools ? 'running' : triage ? 'done' : '', tools ? '运行中' : triage ? '' : '未运行'),
    stage('AI 审查', 'off', '未接入'),
    stage('清单', triage ? 'done' : '', triage ? `${triage.listed} 条` : '—'));
  $('tab-tasks').classList.toggle('busy', Boolean(running));
}

// -- timeline -----------------------------------------------------------------------------------
function renderTimeline() {
  S.blockIds = new Set();
  S.approvalEls = new Map();
  S.live = null;
  fill($('timeline'));
  appendBlocks(S.ev.blocks);
}

function appendBlocks(blocks) {
  const box = $('timeline');
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 48;
  for (const b of blocks) {
    if (S.blockIds.has(b.id)) continue;
    S.blockIds.add(b.id);
    if (S.live && (b.kind === 'agent' || b.kind === 'tool' || b.kind === 'approval')) clearLive();
    const item = blockItem(b);
    if (S.live) box.insertBefore(item, S.live.el); else box.appendChild(item);
  }
  if (stick) box.scrollTop = box.scrollHeight;
}

function blockItem(b) {
  const kind = BLOCK_KIND[b.kind] ? b.kind : 'event';
  const refs = b.refs || {};
  const links = [];
  if (typeof refs.pv === 'string') links.push(button(`查看 ${refs.pv}`, () => openPv(refs.pv), 'btn small ghost'));
  const card = refs.card && typeof refs.card === 'object' ? refs.card : null;
  if (refs.call || refs.job || (card && card.kind === 'job')) links.push(button('查看任务', () => setTab('tasks'), 'btn small ghost'));
  if (refs.export || (card && card.kind === 'export')) links.push(button('查看导出', () => { S.exportOpen = true; setTab('list'); }, 'btn small ghost'));
  if (card && card.kind === 'profile') links.push(button('查看档案', () => setTab('profile'), 'btn small ghost'));
  let body = null;
  if (kind === 'agent') body = agentText(b.detail || '');
  else if (kind === 'tool') body = b.detail ? h('details', { class: 'tool-result' }, h('summary', null, '工具结果'), h('pre', null, b.detail)) : null;
  else if (b.detail) body = h('div', { class: 'block-detail' }, b.detail);
  const meta = [refs.calls ? `调用 ${refs.calls}` : '', typeof refs.meta === 'string' ? refs.meta : ''].filter(Boolean).join(' · ');
  if (kind === 'status' && typeof refs.approval === 'string') closeApproval(refs.approval, b.title);
  return h('li', { class: `block k-${kind}` },
    h('div', { class: 'block-head' },
      h('span', { class: 'block-kind' }, BLOCK_KIND[kind]),
      h('span', { class: 'block-title' }, kind === 'agent' ? '' : b.title),
      h('time', { class: 'block-at', datetime: b.at }, fmtTime(b.at))),
    body,
    meta ? h('div', { class: 'block-detail faint' }, meta) : null,
    kind === 'approval' ? approvalActions(b) : null,
    links.length ? h('div', { class: 'block-refs' }, links) : null);
}

/** The agent's words as text; ``` fences become monospace blocks.  Nothing is parsed as HTML. */
function agentText(text) {
  const box = h('div', { class: 'agent-text' });
  const parts = String(text).split(/^```[^\n]*\n?/m);
  parts.forEach((part, i) => {
    const chunk = i % 2 ? part.replace(/\n$/, '') : part.replace(/^\n+|\n+$/g, '');
    if (chunk) box.appendChild(i % 2 ? h('pre', { class: 'agent-code' }, chunk) : h('p', null, inline(chunk)));
  });
  return box;
}

/** **bold**, `code` and PV-0042 inside the agent's prose, built as nodes (never as HTML). */
function inline(text) {
  return String(text).split(/(\*\*[^*\n]+\*\*|`[^`\n]+`|\bPV-\d{4,}\b)/).map((part, i) => {
    if (!(i % 2)) return part;
    if (part.startsWith('**')) return h('strong', null, inline(part.slice(2, -2)));
    if (part.startsWith('`')) return h('code', null, part.slice(1, -1));
    return h('a', { href: '#', class: 'pv-link', on: { click: (ev) => { ev.preventDefault(); openPv(part); } } }, part);
  });
}

// -- approval cards: only these buttons approve; typed text never does --------------------------
function approvalActions(b) {
  const refs = b.refs || {};
  const id = String(refs.approval || '');
  const pending = ((S.ev && S.ev.approvals) || []).find((a) => a.approval_id === id);
  const args = refs.arguments && typeof refs.arguments === 'object' ? JSON.stringify(refs.arguments, null, 1) : '';
  const box = h('div', { class: 'approval' },
    args ? h('pre', { class: 'approval-args' }, `${refs.tool || ''} ${args}`) : null);
  if (!pending) {
    box.appendChild(h('div', { class: 'approval-state faint' }, '已处理或已失效'));
    return box;
  }
  const actions = h('div', { class: 'approval-actions' },
    button('批准', () => decide(pending, 'approve', actions), 'btn small primary'),
    button('拒绝', () => decide(pending, 'reject', actions), 'btn small'),
    h('span', { class: 'faint', 'data-expires': String(pending.expires_at) }, expiresText(pending.expires_at)));
  S.approvalEls.set(id, actions);
  box.appendChild(actions);
  return box;
}

/** A card shown while the page is open is pending until a status block says otherwise. */
function pendingFromBlock(b) {
  const refs = b.refs || {};
  const id = String(refs.approval || '');
  if (!id || !refs.sha || S.ev.approvals.some((a) => a.approval_id === id)) return;
  S.ev.approvals.push({ approval_id: id, sha: refs.sha, tool: refs.tool, arguments: refs.arguments,
    expires_at: Number(refs.expires_at) || Date.now() / 1000 + 1800 });
}

function expiresText(epoch) {
  const left = Number(epoch) - Date.now() / 1000;
  return left > 0 ? `${fmtElapsed(left)}后失效` : '已失效';
}

async function decide(card, decision, actions) {
  for (const el of actions.querySelectorAll('button')) el.disabled = true;
  const out = await act(() => post(ep(`/approvals/${encodeURIComponent(card.approval_id)}/decide`),
    { decision, sha: card.sha }));
  if (!out) {
    for (const el of actions.querySelectorAll('button')) el.disabled = false;
    return;
  }
  closeApproval(card.approval_id, decision === 'approve' ? '已批准' : '已拒绝');
  if (out.card && out.card.kind === 'export') { S.exportResult = out.card.export; S.exportOpen = true; }
  if (out.result) toast(String(out.result), 'info');
}

function closeApproval(id, text) {
  if (S.ev) S.ev.approvals = (S.ev.approvals || []).filter((a) => a.approval_id !== id);
  const actions = S.approvalEls.get(id);
  if (!actions) return;
  S.approvalEls.delete(id);
  fill(actions, h('span', { class: 'approval-state faint' }, text));
}

// -- the conversation ---------------------------------------------------------------------------
function renderComposer() {
  const agent = (S.ev && S.ev.agent) || { available: false, reason: '' };
  const input = $('composer-input');
  const send = $('composer-send');
  input.disabled = !agent.available;
  send.disabled = !agent.available;
  input.placeholder = agent.available
    ? (S.busy ? 'agent 正在回答；现在发送会排队到本回合之后' : `和 agent 说话（${agent.model || '本地模型'}）。Enter 发送，Shift+Enter 换行`)
    : (agent.reason || '模型通道不可用；每一步都可以用按钮完成。');
  $('composer-stop').hidden = !S.busy;
}

function setBusy(busy) {
  S.busy = busy;
  if (S.ev && S.ev.agent) S.ev.agent.busy = busy;
  // The final block can reach the page just after "end": keep the streamed text until it does.
  if (!busy && S.live) {
    const live = S.live;
    live.done = true;
    if (!live.text) clearLive();
    else setTimeout(() => { if (S.live === live) clearLive(); }, 5000);
  }
  renderComposer();
}

async function say(ev) {
  if (ev) ev.preventDefault();
  const input = $('composer-input');
  const text = input.value.trim();
  if (!text || input.disabled) return;
  const out = await act(() => post(ep('/say'), { text }));
  if (!out) return;
  input.value = '';
  if (!out.queued) setBusy(true);
}

function composerKeys(ev) {
  if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing && ev.keyCode !== 229) say(ev);
}

function typing() {
  const now = Date.now();
  if (!S.id || now - S.typingAt < 2000 || $('composer-input').disabled) return;
  S.typingAt = now;
  post(ep('/typing')).catch(() => { /* a lost typing note only lets background work resume sooner */ });
}

async function interrupt() {
  await act(() => post(ep('/interrupt')));
}

/** The reply as it streams: one provisional item at the end of the timeline, replaced by the real block. */
function onDelta(d) {
  if (!d || !S.ev) return;
  if (d.kind === 'end') { setBusy(false); return; }
  if (!S.busy) setBusy(true);
  if (S.live && S.live.done) clearLive();
  if (!S.live) {
    const textEl = h('div', { class: 'agent-text live-text' });
    const note = h('div', { class: 'block-detail faint' }, '');
    const el = h('li', { class: 'block k-agent live' },
      h('div', { class: 'block-head' }, h('span', { class: 'block-kind' }, 'agent'),
        h('span', { class: 'block-title' }, ''), h('span', { class: 'block-at' }, '回答中…')),
      textEl, note);
    S.live = { el, textEl, note, text: '' };
    $('timeline').appendChild(el);
  }
  if (d.kind === 'text') {
    S.live.text += d.text || '';
    S.live.textEl.textContent = S.live.text;
  } else if (d.kind === 'reasoning') {
    S.live.note.textContent = '思考中…';
  } else if (d.kind === 'tool') {
    S.live.note.textContent = `准备调用 ${d.text || '工具'}…`;
  }
  const box = $('timeline');
  if (box.scrollHeight - box.scrollTop - box.clientHeight < 120) box.scrollTop = box.scrollHeight;
}

function clearLive() {
  if (S.live) S.live.el.remove();
  S.live = null;
}

// -- live updates -------------------------------------------------------------------------------
function openStream() {
  const last = Math.max(0, ...S.ev.blocks.map((b) => Number(b.id) || 0));
  const es = new EventSource(ep(`/stream?after=${last}`));
  S.stream = es;
  const parse = (ev) => { try { return JSON.parse(ev.data); } catch (e) { return null; } };
  es.addEventListener('block', (ev) => {
    const b = parse(ev);
    if (b && S.ev && S.stream === es && !S.blockIds.has(b.id)) {
      S.ev.blocks.push(b);
      if (b.kind === 'approval') pendingFromBlock(b);
      appendBlocks([b]);
    }
  });
  es.addEventListener('delta', (ev) => {
    if (S.stream === es) onDelta(parse(ev));
  });
  es.addEventListener('job', (ev) => {
    const job = parse(ev);
    if (job && S.stream === es) upsertJob(job);
  });
  es.addEventListener('triage', (ev) => {
    const t = parse(ev);
    if (!t || !S.ev || S.stream !== es) return;
    S.ev.triage = Object.keys(t).length ? t : null;
    renderTop();
    if (S.tab === 'coverage') renderTab();
    else if (S.tab === 'list') refreshList();
  });
  es.addEventListener('error', () => {
    if (es.readyState === EventSource.CLOSED && S.stream === es) toast('实时连接已断开；刷新页面可重新连接。');
  });
}

function closeStream() {
  if (S.stream) S.stream.close();
  S.stream = null;
}

function upsertJob(job) {
  if (!S.ev) return;
  const i = S.ev.jobs.findIndex((j) => j.id === job.id);
  if (i >= 0) S.ev.jobs[i] = job; else S.ev.jobs.push(job);
  const was = S.jobStatus.get(job.id);
  S.jobStatus.set(job.id, job.status);
  renderTop();
  renderJobs();
  if (was === 'running' && job.status !== 'running') {
    const text = `${JOB_KIND[job.kind] || job.kind} ${job.id}：${JOB_STATUS[job.status] || job.status}`;
    toast(job.status === 'failed' ? `${text}${job.error ? ` — ${job.error}` : ''}` : text, job.status === 'failed' ? 'error' : 'info');
    loadEval();
  }
}

// -- tabs ---------------------------------------------------------------------------------------
function setTab(tab) {
  S.tab = tab;
  renderTab();
  $('panel').scrollTop = 0;
}

function renderTab() {
  for (const b of document.querySelectorAll('#tabs [role="tab"]')) {
    const on = b.dataset.tab === S.tab;
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  }
  const panel = $('panel');
  panel.setAttribute('aria-labelledby', `tab-${S.tab}`);
  Object.assign(S, { listEls: null, acceptBtn: null, srcEl: null, jobsEl: null, runBtn: null });
  ({ list: renderList, evidence: renderEvidence, profile: renderProfile, coverage: renderCoverage, tasks: renderTasks })[S.tab](panel);
}

function tabKeys(ev) {
  const i = TABS.indexOf(S.tab);
  const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: TABS.length - 1 }[ev.key];
  if (next === undefined) return;
  ev.preventDefault();
  setTab(TABS[(next + TABS.length) % TABS.length]);
  $(`tab-${S.tab}`).focus();
}

const noList = (message) => h('div', { class: 'empty' }, h('p', null, '还没有清单。'),
  h('p', { class: 'small' }, message), button('去跑工具', () => setTab('tasks'), 'btn primary'));

// -- 清单 ---------------------------------------------------------------------------------------
function renderList(panel) {
  const p = S.ev.profile;
  const f = S.filters;
  const filter = (key, label, options) => h('label', { class: 'field' }, label,
    selectEl([['', '全部'], ...options], f[key], (v) => { f[key] = v; applyFilters(); }));
  const path = h('input', { type: 'text', value: f.path, placeholder: '如 src/boot/*', spellcheck: 'false' });
  const exportBox = h('div', { hidden: !S.exportOpen });
  const toolbar = h('form', { class: 'toolbar filters', on: { submit: (ev) => { ev.preventDefault(); f.path = path.value.trim(); applyFilters(); } } },
    filter('level', '等级', [...p.levels.map((l) => [l.id, l.label || l.id]), ['unmapped', LEVEL_TEXT.unmapped]]),
    filter('module', 'TOE 模块', p.toe_modules.map((m) => [m.id, m.id])),
    filter('sfr', 'SFR', p.sfr.map((s) => [s.id, s.id])),
    filter('status', '状态', Object.entries(STATUS)),
    h('label', { class: 'field' }, '路径（glob）', path),
    h('label', { class: 'field' }, '排序', selectEl([['priority', '优先级'], ['level', '等级'], ['path', '路径']], f.sort,
      (v) => { f.sort = v; applyFilters(); })),
    h('button', { class: 'btn', type: 'submit' }, '筛选'),
    button('清除', () => { S.filters = { ...BLANK_FILTERS }; S.pages = { main: 1, unmapped: 1 }; renderList(panel); }, 'btn ghost'),
    h('span', { class: 'spacer' }),
    button('导出…', (ev) => {
      S.exportOpen = !S.exportOpen;
      exportBox.hidden = !S.exportOpen;
      ev.currentTarget.setAttribute('aria-expanded', String(S.exportOpen));
    }, 'btn', { 'aria-expanded': String(S.exportOpen) }));
  renderExport(exportBox);
  S.listEls = { main: h('section', { class: 'section' }), unmapped: h('section', { class: 'section' }) };
  fill(panel, toolbar, exportBox, S.listEls.main, S.listEls.unmapped);
  refreshList();
}

function applyFilters() {
  S.pages = { main: 1, unmapped: 1 };
  S.picked.clear();
  refreshList();
}

function refreshList() {
  if (!S.listEls) return;
  if (!S.ev.triage) {  // nothing indexed yet: say so without asking the server for a 409
    const running = S.ev.jobs.some((j) => j.status === 'running');
    fill(S.listEls.main, noList(running ? '工具正在运行，结束后清单自动出现。' : '先跑一次工具（只占 CPU），清单由工具结果生成。'));
    S.listEls.unmapped.hidden = true;
    return;
  }
  loadPart('main');
  loadPart('unmapped');
}

async function loadPart(part) {
  const els = S.listEls;
  const q = new URLSearchParams({ partition: part, page: String(S.pages[part]), sort: S.filters.sort });
  for (const key of ['level', 'module', 'sfr', 'status', 'path']) if (S.filters[key]) q.set(key, S.filters[key]);
  let res;
  try {
    res = await api(ep(`/pvs?${q}`));
  } catch (e) {
    if (els !== S.listEls) return;
    if (e.status === 409) {
      fill(els.main, noList(e.message));
      els.unmapped.hidden = true;
    } else {
      toast(e.message);
    }
    return;
  }
  if (els !== S.listEls) return;
  const pages = Math.max(1, Math.ceil(res.total / res.page_size));
  if (S.pages[part] > pages) {
    S.pages[part] = pages;
    loadPart(part);
    return;
  }
  els[part].hidden = false;
  fill(els[part], partSection(part, res, pages));
}

function partSection(part, res, pages) {
  const unmapped = part === 'unmapped';
  let accept = null;
  if (unmapped) {
    accept = button('', acceptProposed, 'btn small');
    S.acceptBtn = accept;
    updateAccept();
  }
  const head = h('div', { class: 'section-head' }, h('h3', null, PARTS[part]),
    h('span', { class: 'totals' }, `共 ${res.total} 条`, levelTotals(res.by_level)), h('span', { class: 'spacer' }), accept);
  if (!res.rows.length) {
    return [head, h('p', { class: 'empty' }, res.total ? '这一页没有条目。' : unmapped ? '没有需要人工核实的条目。' : '没有符合条件的条目。')];
  }
  const tbody = h('tbody', null, res.rows.map((r) => pvRow(r, unmapped)));
  const all = unmapped ? h('input', { type: 'checkbox', 'aria-label': '全选本页有建议等级的条目', on: { change: (ev) => {
    for (const box of tbody.querySelectorAll('input[type="checkbox"]')) {
      box.checked = ev.target.checked;
      box.dispatchEvent(new Event('change'));
    }
  } } }) : null;
  const cols = ['条目', '标题', '模块', 'SFR', '等级', '位置', '引擎', '状态', '优先级'];
  const table = h('table', { class: 'grid' },
    h('thead', null, h('tr', null, unmapped ? h('th', { scope: 'col' }, all) : null,
      cols.map((c) => h('th', { scope: 'col', class: c === '优先级' ? 'num' : null }, c)))), tbody);
  const go = (n) => { S.pages[part] = n; loadPart(part); };
  const pager = h('div', { class: 'pager' },
    button('‹ 上一页', () => go(res.page - 1), 'btn small', { disabled: res.page <= 1 }),
    h('span', null, `第 ${res.page} / ${pages} 页 · 每页 ${res.page_size} 条`),
    button('下一页 ›', () => go(res.page + 1), 'btn small', { disabled: res.page >= pages }));
  return [head, h('div', { class: 'table-wrap' }, table), pager];
}

function pvRow(r, unmapped) {
  const open = () => openPv(r.pv_id);
  const tr = h('tr', { class: `clickable${S.pvId === r.pv_id ? ' selected' : ''}`, tabindex: 0, on: { click: open, keydown: whenEnter(open) } });
  const inert = { click: (ev) => ev.stopPropagation() };
  const title = h('td', { class: 'cell-title' }, h('span', { class: 'fn' }, r.function || r.path.split('/').pop()),
    h('span', { class: 'sub' }, r.family || '—', r.members > 1 ? ` · ${r.members} 个发现` : ''));
  const sel = selectEl(Object.entries(STATUS), r.status, (v) => openNoteRow(r, tr, sel, v),
    { class: 'small', 'aria-label': `${r.pv_id} 状态` });
  return add(tr, [
    unmapped ? h('td', { on: inert }, r.proposed_level ? h('input', {
      type: 'checkbox', checked: S.picked.has(r.pv_id), 'aria-label': `选择 ${r.pv_id}`,
      on: { change: (ev) => { if (ev.target.checked) S.picked.add(r.pv_id); else S.picked.delete(r.pv_id); updateAccept(); } },
    }) : null) : null,
    h('td', { class: 'cell-id' }, r.pv_id),
    title,
    h('td', { class: 'nowrap' }, r.module || '—'),
    h('td', { class: 'cell-sfr' }, sfrTags(r.sfr)),
    h('td', { class: 'nowrap' }, levelCell(r)),
    pathCell(pathText(r)),
    h('td', { class: 'cell-tools' }, toolsText(r.tools)),
    h('td', { class: 'nowrap', on: inert }, sel, r.note ? h('span', { class: 'row-note', title: r.note }, r.note) : null),
    h('td', { class: 'num' }, r.priority),
  ]);
}

/** A status change asks for an optional note in a row under the entry, then saves both. */
function openNoteRow(r, tr, sel, status) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('note-row')) next.remove();
  const note = h('input', { type: 'text', class: 'small', value: r.note || '', placeholder: '备注（可选）', 'aria-label': `${r.pv_id} 备注` });
  const cancel = () => { sel.value = r.status; row.remove(); sel.focus(); };
  const save = async () => {
    if (await saveStatus(r.pv_id, status, note.value.trim())) loadPart(r.partition);
  };
  note.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); save(); }
    if (ev.key === 'Escape') cancel();
  });
  const row = h('tr', { class: 'note-row' }, h('td', { colspan: tr.children.length },
    h('div', { class: 'row center' }, `${r.pv_id} 标为「${STATUS[status]}」`, note,
      button('保存', save, 'btn small primary'), button('取消', cancel, 'btn small ghost'))));
  tr.after(row);
  note.focus();
}

async function saveStatus(pvId, status, note) {
  const res = await act(() => post(ep(`/pvs/${encodeURIComponent(pvId)}/status`), { status, note }));
  if (!res) return false;
  if (S.pv && S.pv.pv.pv_id === pvId) Object.assign(S.pv.pv, { status, note });
  toast(`${pvId} 已标为「${STATUS[status]}」`, 'info');
  return true;
}

function updateAccept() {
  if (!S.acceptBtn) return;
  S.acceptBtn.disabled = !S.picked.size;
  S.acceptBtn.textContent = `采纳建议等级（${S.picked.size}）`;
}

async function acceptProposed() {
  const res = await act(() => post(ep('/pvs/accept_proposed'), { pv_ids: [...S.picked] }));
  if (!res) return;
  toast(`已采纳 ${res.accepted} 条的建议等级，已移入主分区。`, 'info');
  S.picked.clear();
  refreshList();
}

function renderExport(box) {
  const variant = (value, text) => h('label', { class: 'check' },
    h('input', { type: 'radio', name: 'export-variant', value, checked: value === 'internal' }), text);
  const format = (value) => h('label', { class: 'check' }, h('input', { type: 'checkbox', value, checked: true }), value);
  const form = h('form', { class: 'stack', on: { submit: async (ev) => {
    ev.preventDefault();
    const formats = [...form.querySelectorAll('input[type="checkbox"]:checked')].map((i) => i.value);
    const chosen = form.querySelector('input[name="export-variant"]:checked').value;
    if (!formats.length) { toast('至少选一种格式。'); return; }
    const res = await act(() => post(ep('/export'), { variant: chosen, formats }));
    if (!res) return;
    S.exportResult = res.export;
    renderExport(box);
  } } },
  h('div', { class: 'row center' }, h('span', { class: 'muted small' }, '版本'),
    variant('internal', '内部版（含源码摘录）'), variant('shareable', '可分享版（扣留摘录，做泄露复验）')),
  h('div', { class: 'row center' }, h('span', { class: 'muted small' }, '格式'), ['xlsx', 'md', 'csv'].map(format),
    h('span', { class: 'spacer' }), h('button', { class: 'btn primary', type: 'submit' }, '生成导出')));
  const x = S.exportResult;
  const result = x ? h('div', { class: 'stack' },
    h('p', null, `导出 ${x.id} · 泄露复验：`, h('span', { class: x.leak_check === 'passed' ? 'ok-text' : 'error-text' },
      x.leak_check === 'passed' ? '通过' : String(x.leak_check))),
    h('ul', { class: 'list-plain' }, x.files.map((f) => h('li', null,
      h('a', { href: ep(`/exports/${encodeURIComponent(x.id)}/${encodeURIComponent(f.name)}`), download: f.name }, f.name),
      h('span', { class: 'muted small' }, ` · ${f.bytes} 字节 · sha256 ${short(f.sha256)}`))))) : null;
  fill(box, section('导出清单', [form, result]));
}

// -- 证据 ---------------------------------------------------------------------------------------
async function openPv(pvId) {
  S.pvId = pvId;
  setTab('evidence');
  const res = await act(() => api(ep(`/pvs/${encodeURIComponent(pvId)}`)));
  if (!res || S.pvId !== pvId) return;
  Object.assign(S, { pv: res, source: res.source, sourceLine: Number(res.pv.line_start) || 1, radius: 12 });
  if (S.tab === 'evidence') renderTab();
}

function renderEvidence(panel) {
  if (!S.pvId) {
    fill(panel, h('p', { class: 'empty' }, '在「清单」中点击一个条目，这里会显示它的证据。'));
    return;
  }
  if (!S.pv || S.pv.pv.pv_id !== S.pvId) {
    fill(panel, h('p', { class: 'empty' }, `正在载入 ${S.pvId}…`));
    return;
  }
  const { pv, members } = S.pv;
  const fact = (label, ...value) => [h('dt', null, label), h('dd', null, value)];
  const facts = h('dl', { class: 'facts' },
    fact('分区', PARTS[pv.partition] || pv.partition),
    fact('等级', levelCell(pv)),
    fact('TOE 模块', pv.module || '—'),
    fact('SFR', sfrTags(pv.sfr, Infinity)),
    fact('位置', h('span', { class: 'mono' }, `${pv.path}:${pv.line_start}${pv.line_end !== pv.line_start ? `–${pv.line_end}` : ''}`)),
    fact('函数', h('span', { class: 'mono' }, pv.function || '—')),
    fact('缺陷族', pv.family || '—'),
    fact('引擎', toolsText(pv.tools)),
    fact('状态', STATUS[pv.status] || pv.status, pv.note ? h('span', { class: 'muted' }, ` — ${pv.note}`) : null));
  const status = selectEl(Object.entries(STATUS), pv.status, () => {}, { 'aria-label': '状态' });
  const note = h('input', { type: 'text', value: pv.note || '', placeholder: '备注（可选）', 'aria-label': '备注' });
  const dispose = h('form', { class: 'row', on: { submit: async (ev) => {
    ev.preventDefault();
    if (await saveStatus(pv.pv_id, status.value, note.value.trim())) renderTab();
  } } }, h('label', { class: 'field' }, '处置', status), h('label', { class: 'field spacer' }, '备注', note),
  h('button', { class: 'btn primary', type: 'submit' }, '保存'));
  fill(panel,
    section(`${pv.pv_id} · ${pv.family || ''} ${pv.function || ''}`, [facts, dispose],
      button('‹ 回到清单', () => setTab('list'), 'btn small ghost')),
    section('优先级构成', whyList(pv)),
    section(`成员发现（${members.length}）`, membersTable(members)),
    section('源码', sourcePanel()));
}

function whyList(pv) {
  const parts = Object.entries(pv.priority_why || {});
  return h('dl', { class: 'why' },
    parts.map(([key, n]) => [h('dt', null, WHY[key] || key), h('dd', { class: n ? null : 'zero' }, `+${n}`)]),
    h('dt', { class: 'total' }, '优先级'), h('dd', { class: 'total' }, pv.priority));
}

function membersTable(members) {
  const cols = ['引擎', '规则', '行', '等级', '原始严重度', 'CWE', '消息', '上下文'];
  return h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
    h('thead', null, h('tr', null, cols.map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, members.map((m) => {
      const line = parseInt(m.line, 10) || 0;
      return h('tr', null,
        h('td', { class: 'nowrap' }, m.tool),
        h('td', { class: 'cell-id' }, m.rule_id),
        h('td', { class: 'nowrap' }, line
          ? button(`${m.line}${m.column ? `:${m.column}` : ''}`, () => loadSource(line), 'btn small ghost', { title: '在源码中定位' })
          : m.line),
        h('td', null, m.review_level ? levelChip(m.review_level) : '—'),
        h('td', { class: 'nowrap' }, m.original_severity || '—'),
        h('td', { class: 'nowrap' }, m.cwe || '—'),
        h('td', { class: 'cell-msg' }, m.message),
        h('td', { class: 'small muted' }, m.evidence_context || '—'));
    }))));
}

function sourcePanel() {
  const radius = selectEl([6, 12, 20, 40].map((n) => [String(n), `上下 ${n} 行`]), String(S.radius),
    (v) => { S.radius = Number(v); loadSource(S.sourceLine); }, { class: 'small', 'aria-label': '显示范围' });
  S.srcEl = h('div');
  drawSource();
  return [h('div', { class: 'row center' }, h('span', { class: 'mono' }, S.source ? S.source.path : S.pv.pv.path),
    h('span', { class: 'spacer' }), radius), S.srcEl];
}

function drawSource() {
  const src = S.source;
  if (!S.srcEl || !src) return;
  const marks = new Set(S.pv.members.map((m) => parseInt(m.line, 10)));
  const box = h('div', { class: 'source', tabindex: 0, 'aria-label': `源码 ${src.path}` }, h('table', null, h('tbody', null,
    src.lines.map((l) => h('tr', { class: l.marked || marks.has(l.n) ? 'marked' : null, 'data-n': l.n },
      h('td', { class: 'src-n' }, l.n), h('td', null, l.text))))));
  fill(S.srcEl, src.lines.length ? box : h('p', { class: 'empty' }, '这个文件在该范围内没有内容。'));
  requestAnimationFrame(() => {
    const row = box.querySelector(`tr[data-n="${Number(S.sourceLine)}"]`);
    if (row) box.scrollTop = Math.max(0, row.offsetTop - box.clientHeight / 3);
  });
}

async function loadSource(line) {
  const pv = S.pv;
  const q = new URLSearchParams({ path: pv.pv.path, line: String(line), radius: String(S.radius) });
  const res = await act(() => api(ep(`/source?${q}`)));
  if (!res || S.pv !== pv) return;
  Object.assign(S, { source: res, sourceLine: line });
  drawSource();
}

// -- 档案 ---------------------------------------------------------------------------------------
function renderProfile(panel) {
  const p = S.ev.profile;
  if (S.tomlSha !== p.sha256 && !S.tomlDirty) Object.assign(S, { toml: p.text, tomlSha: p.sha256 });
  const builtins = S.app ? S.app.builtin_profiles : [];
  const builtin = selectEl(builtins.map((b) => [b, b]), builtins.includes(p.name) ? p.name : builtins[0], () => {},
    { 'aria-label': '内置档案' });
  const by = h('input', { type: 'text', value: S.confirmBy, placeholder: '确认人姓名', 'aria-label': '确认人',
    on: { input: (ev) => { S.confirmBy = ev.target.value; } } });
  const confirm = p.status === 'confirmed'
    ? h('p', { class: 'ok-text' }, '档案已确认。再改动会生成新的草稿版本，需要重新确认。')
    : h('form', { class: 'row', on: { submit: (ev) => { ev.preventDefault(); confirmProfile(); } } },
      h('label', { class: 'field' }, '确认人', by),
      h('button', { class: 'btn primary', type: 'submit' }, '确认档案'),
      h('span', { class: 'muted small' }, p.status === 'builtin' ? '内置档案会先复制进本评估，再标为已确认。' : '确认后按此档案重算分级和清单。'));
  fill(panel,
    section('档案', [
      h('p', null, h('b', null, p.name), ' ', h('span', { class: `badge ${p.status}` }, PROFILE_STATUS[p.status] || p.status),
        h('span', { class: 'muted small mono' }, `  sha256 ${short(p.sha256)}`)),
      h('div', { class: 'row' }, h('label', { class: 'field' }, '内置档案', builtin),
        button('使用内置档案', () => useBuiltin(builtin.value))),
      confirm,
      h('p', { class: 'note' }, '更换或确认档案后，如果已经跑过工具，清单会按新档案自动重建（见「任务」）。'),
    ]),
    h('div', { class: 'two-col' },
      section(`SFR（${p.sfr.length}）`, h('ul', { class: 'list-plain' },
        p.sfr.map((s) => h('li', null, h('span', { class: 'mono' }, s.id), s.title ? h('span', { class: 'muted' }, ` — ${s.title}`) : null)))),
      section(`等级（${p.levels.length}）`, h('ul', { class: 'list-plain' },
        [...p.levels].sort((a, b) => (b.rank || 0) - (a.rank || 0)).map((l) => h('li', null, levelChip(l.id),
          h('span', { class: 'muted small' }, ` 秩 ${l.rank}`), l.description ? h('div', { class: 'small muted' }, l.description) : null))))),
    section(`TOE 模块（${p.toe_modules.length}）`, [
      h('ul', { class: 'list-plain' }, p.toe_modules.map((m) => h('li', null, h('b', null, m.id), ' ',
        h('span', { class: 'mono muted' }, (m.paths || []).join('  '))))),
      p.excludes.length ? h('h4', null, '排除') : null,
      p.excludes.length ? h('ul', { class: 'list-plain' }, p.excludes.map((x) => h('li', null,
        h('span', { class: 'mono' }, (x.paths || []).join('  ')), x.reason ? h('span', { class: 'muted' }, ` — ${x.reason}`) : null))) : null,
    ]),
    section(`分级规则（${p.grading_rules.length}）`, rulesTable(p.grading_rules)),
    section('上传 TOML', tomlEditor()),
    section('从文档抽取档案', documentsForm()));
}

function rulesTable(rules) {
  const match = (m) => Object.entries(m || {}).map(([k, v]) =>
    `${k} = ${Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : v}`).join('；') || '（任意）';
  return h('div', { class: 'table-wrap' }, h('table', { class: 'grid' },
    h('thead', null, h('tr', null, ['匹配', '等级', '依据'].map((c) => h('th', { scope: 'col' }, c)))),
    h('tbody', null, rules.map((r) => h('tr', null,
      h('td', { class: 'mono' }, match(r.match)),
      h('td', null, levelChip(r.level)),
      h('td', { class: 'small' }, BASIS[r.basis] ? BASIS[r.basis][1].replace('依据：', '') : r.basis))))));
}

function tomlEditor() {
  const area = h('textarea', { class: 'toml', spellcheck: 'false', 'aria-label': '档案 TOML', value: S.toml,
    on: { input: (ev) => { S.toml = ev.target.value; S.tomlDirty = true; } } });
  const file = h('input', { type: 'file', accept: '.toml,text/plain', 'aria-label': '从文件载入 TOML', on: { change: async (ev) => {
    const chosen = ev.target.files[0];
    if (!chosen) return;
    Object.assign(S, { toml: await chosen.text(), tomlDirty: true });
    area.value = S.toml;
  } } });
  const error = h('pre', { class: 'error-box', hidden: !S.tomlError }, S.tomlError);
  const save = async () => {
    try {
      const res = await post(ep('/profile'), { toml: area.value });
      Object.assign(S, { tomlError: '', tomlDirty: false });
      toast(`已保存为档案草稿 ${res.profile.name}`, 'info');
      loadEval();
    } catch (e) {
      S.tomlError = e.message;
      fill(error, e.message);
      error.hidden = false;
    }
  };
  return [h('p', { class: 'muted small' }, '下面是当前档案的 TOML。可以直接编辑，或从文件载入；保存时先校验，通过后成为下一版草稿。'),
    h('div', { class: 'row center' }, h('label', { class: 'field' }, '从文件载入', file)), area, error,
    h('div', { class: 'row center' }, button('校验并保存', save, 'btn primary'),
      button('还原为当前档案', () => { Object.assign(S, { toml: S.ev.profile.text, tomlDirty: false, tomlError: '' }); renderTab(); }, 'btn ghost'))];
}

async function useBuiltin(name) {
  const res = await act(() => post(ep('/profile'), { builtin: name }));
  if (!res) return;
  S.tomlDirty = false;
  toast(`已使用内置档案 ${res.profile.name}`, 'info');
  loadEval();
}

async function confirmProfile() {
  if (!S.confirmBy.trim()) {
    toast('请先填写确认人姓名。');
    return;
  }
  const res = await act(() => post(ep('/profile/confirm'), { by: S.confirmBy.trim() }));
  if (!res) return;
  toast(`档案 ${res.profile.name} 已确认`, 'info');
  loadEval();
}

function documentsForm() {
  const file = h('input', { type: 'file', accept: '.pdf,.docx', 'aria-label': '选择文档' });
  const role = selectEl(Object.entries(ROLES), 'security_target', () => {}, { 'aria-label': '文档角色' });
  const upload = async () => {
    const chosen = file.files[0];
    if (!chosen) { toast('请先选择一个 .pdf 或 .docx 文件。'); return; }
    if (chosen.size > MAX_DOCUMENT) { toast('文件超过 64 MB 上限。'); return; }
    // Header values must be Latin-1; a non-ASCII name travels percent-encoded.
    const name = /^[\x20-\x7e]*$/.test(chosen.name) ? chosen.name : encodeURIComponent(chosen.name);
    const res = await act(() => api(ep('/documents'), { raw: chosen, headers: { 'X-Filename': name, 'X-Role': role.value } }));
    if (!res) return;
    S.docs.push(res.document);
    file.value = '';
    toast(`已上传 ${res.document.name}`, 'info');
    renderTab();
  };
  const extract = async () => {
    try {
      const res = await post(ep('/extract'), {});
      S.extractJob = res.job.id;
      upsertJob(res.job);
      renderTab();
    } catch (e) {
      toast(e.status === 409 ? '已有任务在运行，请等它结束或先停止。' : e.message);
    }
  };
  return [
    h('p', { class: 'muted small' }, '上传 Security Target 和测试计划（pdf 或 docx，≤64 MB），再从中抽取一版档案草稿。'),
    h('div', { class: 'row' }, h('label', { class: 'field' }, '文档', file), h('label', { class: 'field' }, '角色', role),
      button('上传', upload)),
    S.docs.length ? h('ul', { class: 'list-plain' }, S.docs.map((d) => h('li', null, d.name,
      h('span', { class: 'muted small' }, ` · ${ROLES[d.role] || d.role || ''} · sha256 ${short(d.sha256)}`)))) : null,
    h('div', { class: 'row center' }, button('从文档抽取档案', extract, 'btn primary'),
      h('span', { class: 'muted small' }, '在本地 GPU 上运行，可能需要数分钟；进度见「任务」。结果是一版草稿，逐项核对后再确认。')),
    S.extractJob ? h('p', { class: 'note' }, `抽取任务 ${S.extractJob} 已开始。`, button('查看任务', () => setTab('tasks'), 'btn small ghost')) : null,
  ];
}

// -- 覆盖 ---------------------------------------------------------------------------------------
function renderCoverage(panel) {
  const t = S.ev.triage;
  if (!t) {
    fill(panel, noList('跑完工具后，这里显示分诊守恒：TOE 内的每个簇都落在主分区、未分级或低于阈值之一。'));
    return;
  }
  const sum = t.partition_main + t.partition_unmapped + t.partition_below;
  const stat = (value, label) => h('div', { class: 'stat' }, h('div', { class: 'stat-value' }, value), h('div', { class: 'stat-label' }, label));
  fill(panel,
    section('分诊守恒', [
      h('p', { class: 'equation' }, 'TOE 内 ', h('b', null, t.in_toe), ' = 主分区 ', h('b', null, t.partition_main),
        ' + 未分级 ', h('b', null, t.partition_unmapped), ' + 低于阈值 ', h('b', null, t.partition_below), '  ',
        sum === t.in_toe ? h('span', { class: 'ok-text' }, '✓ 守恒') : h('span', { class: 'error-text' }, `✗ 相差 ${t.in_toe - sum}`)),
      h('p', { class: 'muted' }, `另有 TOE 外 ${t.outside_toe} 个簇；共 ${t.clusters} 个簇，来自 ${t.findings} 条发现。`),
      h('div', { class: 'stats' }, stat(t.findings, '发现'), stat(t.clusters, '簇'), stat(t.in_toe, 'TOE 内'),
        stat(t.outside_toe, 'TOE 外'), stat(t.listed, '列入清单'), stat(t.kept, '保持编号'), stat(t.new, '新增编号'),
        stat(t.retired, '退役编号')),
    ]),
    h('p', { class: 'note' }, 'SFR × TOE 模块的覆盖矩阵、未审列表和接地失败率，会在接入 AI 审查后出现在这里。'));
}

// -- 任务 ---------------------------------------------------------------------------------------
function renderTasks(panel) {
  const running = S.ev.jobs.some((j) => j.status === 'running');
  const boxes = TOOLS.map((tool) => h('label', { class: 'check' }, h('input', {
    type: 'checkbox', checked: S.tools.has(tool),
    on: { change: (ev) => { if (ev.target.checked) S.tools.add(tool); else S.tools.delete(tool); } },
  }), tool));
  S.runBtn = button('跑工具', runTools, 'btn primary', { disabled: running });
  S.jobsEl = h('div');
  fill(panel,
    section('跑工具', [
      h('p', { class: 'muted small' }, '不勾选则跑全部可用工具。只用 CPU；结束后清单自动更新。'),
      h('div', { class: 'row center' }, boxes, h('span', { class: 'spacer' }), S.runBtn),
    ]),
    section('任务', S.jobsEl));
  renderJobs();
}

async function runTools() {
  try {
    const res = await post(ep('/run_tools'), S.tools.size ? { tools: TOOLS.filter((t) => S.tools.has(t)) } : {});
    upsertJob(res.job);
    toast(`任务 ${res.job.id} 已开始`, 'info');
  } catch (e) {
    toast(e.status === 409 ? '已有任务在运行，请等它结束或先停止。' : e.message);
  }
}

async function stopJob(id) {
  const res = await act(() => post(ep(`/jobs/${encodeURIComponent(id)}/stop`), {}));
  if (res) upsertJob(res.job);
}

function renderJobs() {
  const box = S.jobsEl;
  if (!box || !S.ev) return;
  if (S.runBtn) S.runBtn.disabled = S.ev.jobs.some((j) => j.status === 'running');
  const num = (id) => Number(String(id).replace(/\D/g, '')) || 0;
  const jobs = [...S.ev.jobs].sort((a, b) => num(b.id) - num(a.id));
  if (!jobs.length) {
    fill(box, h('p', { class: 'empty' }, '本次服务运行以来还没有任务。'));
    return;
  }
  const old = new Map([...box.querySelectorAll('.job')].map((el) => [el.dataset.job, el]));
  fill(box, jobs.map((j) => jobCard(j, old.get(j.id))));
}

function jobCard(j, previous) {
  const prevLog = previous && previous.querySelector('.progress');
  const follow = !prevLog || prevLog.scrollHeight - prevLog.scrollTop - prevLog.clientHeight < 24;
  const running = j.status === 'running';
  const log = h('pre', { class: 'progress', tabindex: 0, 'aria-label': `任务 ${j.id} 输出` },
    (j.progress || []).join('\n') || '（暂无输出）');
  const card = h('article', { class: 'job', 'data-job': j.id },
    h('div', { class: 'job-head' },
      h('span', { class: 'job-title' }, `${JOB_KIND[j.kind] || j.kind} ${j.id}`),
      h('span', { class: `st st-${JOB_STATUS[j.status] ? j.status : 'stopped'}` }, JOB_STATUS[j.status] || j.status),
      h('span', { class: 'job-meta' }, `开始 ${fmtTime(j.started_at)} · 用时 `,
        h('span', { 'data-started': running ? j.started_at : null }, fmtElapsed(j.elapsed_seconds)),
        j.exit_code !== null && j.exit_code !== undefined ? ` · 退出码 ${j.exit_code}` : '',
        j.call_id ? ` · ${j.call_id}` : ''),
      h('span', { class: 'spacer' }),
      running ? button('停止', () => stopJob(j.id), 'btn small danger') : null),
    j.error ? h('pre', { class: 'error-box' }, j.error) : null,
    log);
  requestAnimationFrame(() => { log.scrollTop = follow ? log.scrollHeight : prevLog.scrollTop; });
  return card;
}

/** Running jobs count their time locally between server events. */
function tick() {
  for (const el of document.querySelectorAll('[data-started]')) {
    const started = Date.parse(el.dataset.started);
    if (!Number.isNaN(started)) el.textContent = fmtElapsed((Date.now() - started) / 1000);
  }
  for (const el of document.querySelectorAll('[data-expires]')) {
    el.textContent = expiresText(el.dataset.expires);
    if (Number(el.dataset.expires) <= Date.now() / 1000) {
      for (const b of el.parentElement.querySelectorAll('button')) b.disabled = true;
    }
  }
}

// -- start --------------------------------------------------------------------------------------
function init() {
  $('switch-eval').addEventListener('click', () => showPicker(false));
  $('tabs').addEventListener('click', (ev) => {
    const tab = ev.target.closest('[role="tab"]');
    if (tab) setTab(tab.dataset.tab);
  });
  $('tabs').addEventListener('keydown', tabKeys);
  $('composer').addEventListener('submit', say);
  $('composer-input').addEventListener('keydown', composerKeys);
  $('composer-input').addEventListener('input', typing);
  $('composer-stop').addEventListener('click', interrupt);
  setInterval(tick, 1000);
  showPicker(true);
}

init();
