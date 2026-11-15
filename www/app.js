/* ==================================================================
   SENTINEL // LINUX IR CONSOLE  —  前端控制台
   ================================================================== */
'use strict';

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));
const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const state = {
  taskId: null, cursor: 0, mode: null, running: false,
  findings: [], modules: [], checks: [], checkMap: {}, modState: {},
  filter: 'all', moduleFilter: 'all', keyword: '',
  logCount: 0, startAt: 0, progress: 0, doneTotal: 0, checkTotal: 0,
  expanded: {}, domCount: 0, renderKey: '',
  pollTimer: null, clockTimer: null, depTimer: null,
  sysinfo: {}, depOk: true,
  backendVersion: '', caps: [],
  savedReports: [], loadedName: '',
  dirty: { stats: false, modules: false, findings: false },
};

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function fmt(s) { return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>'); }
function fmtClock(sec) {
  const m = Math.floor(sec / 60), s = Math.floor(sec % 60);
  return String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}
function fmtStamp(sec) {
  const m = Math.floor(sec / 60), s = Math.floor(sec % 60), c = Math.floor((sec % 1) * 100);
  return '[' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0') + '.' + String(c).padStart(2, '0') + ']';
}
async function api(path, opts) {
  const r = await fetch(path, opts);
  let j;
  try { j = await r.json(); } catch (e) {
    const e0 = new Error('服务响应异常 (' + r.status + ')'); e0.status = r.status; throw e0;
  }
  if (!r.ok) {
    const e1 = new Error(j.error || ('HTTP ' + r.status));
    e1.status = r.status; e1.body = j; throw e1;
  }
  return j;
}
/* 旧版后端提示：常见于旧的控制台窗口没关，新页面请求被旧进程接走 */
function showCompatHint(msg) {
  if (msg) $('#compatText').textContent = msg;
  $('#compatBar').hidden = false;
}
function isStaleBackend(e) {
  return e && (e.status === 404 || /unknown endpoint|HTTP 404/i.test(e.message || ''));
}
function setLaunchBusy(busy) {
  ['#btnScanTop', '#btnDemo'].forEach(s => { const el = $(s); if (el) el.disabled = busy; });
}
function toast(msg, kind = '') {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast ' + kind;
  t.hidden = false;
  clearTimeout(t._tm);
  t._tm = setTimeout(() => { t.hidden = true; }, 4200);
}
function hint(msg, kind = '') {
  const h = $('#formHint');
  if (!h) { if (msg) toast(msg, kind); return; }
  h.textContent = msg || '';
  h.className = 'form-hint ' + kind;
}

/* ------------------------------------------------------------------ 初始化 */
async function init() {
  bindUI();
  try {
    const d = await api('/api/checks');
    state.modules = d.modules;
    state.checks = d.checks;
    $('#checkCount').textContent = d.checks.length;
    $('#moduleCount').textContent = d.modules.length;
    $('#helpCheckCount').textContent = d.checks.length;
    $('#moduleProgress').textContent = `0 / ${d.checks.length}`;
    state.checkTotal = d.checks.length;
    state.checkMap = Object.fromEntries(d.checks.map(c => [c.id, c]));
    $('#progressSub').textContent = `共 ${d.checks.length} 项只读检查 · ${d.modules.length} 个模块 · 覆盖 CTF 常见后门 / 挖矿 / 勒索 / 权限 / Web 中间件考点`;
    renderModules();
    const sel = $('#moduleFilter');
    d.modules.forEach(m => {
      const o = document.createElement('option');
      o.value = m.id; o.textContent = m.name;
      sel.appendChild(o);
    });
  } catch (e) {
    toast('检查项清单加载失败：' + e.message, 'err');
  }
  try {
    const s = await api('/api/status');
    state.depOk = s.paramiko;
    state.backendVersion = s.version || '未知';
    state.caps = s.capabilities || [];
    if (!state.caps.includes('save')) {
      showCompatHint(`当前后端是旧版本（v${state.backendVersion}），缺少「结果存档」接口。请关闭所有旧的 SENTINEL 控制台窗口，重新运行 start.bat 后刷新本页；本次仍可将报告导出到本地。`);
    }
    if (!s.paramiko) {
      $('#engineText').textContent = '依赖安装中';
      $('#engineStatus .dot').className = 'dot dot-amber';
      hint('SSH 依赖 paramiko 正在自动安装，演示模式可立即使用。', 'warn');
      state.depTimer = setInterval(checkDependency, 3000);
    }
  } catch (e) { /* 服务不可达时静默 */ }

  // 仅恢复非敏感字段
  ['fHost', 'fPort', 'fUser'].forEach(id => {
    const v = localStorage.getItem('sentinel.' + id);
    if (v) $('#' + id).value = v;
  });

  // 操作入口固定在 sticky 顶栏，天然不受分辨率 / 浏览器缩放影响
}

async function checkDependency() {
  try {
    const s = await api('/api/status');
    state.depOk = s.paramiko;
    if (s.paramiko) {
      clearInterval(state.depTimer);
      $('#engineText').textContent = '引擎在线';
      $('#engineStatus .dot').className = 'dot dot-green';
      hint('');
    } else if (s.dependency && s.dependency.state === 'failed') {
      clearInterval(state.depTimer);
      $('#engineText').textContent = '依赖异常';
      $('#engineStatus .dot').className = 'dot dot-red';
      hint('paramiko 自动安装失败，请手动执行 pip install paramiko 后重启服务。', 'err');
    }
  } catch (e) { /* ignore */ }
}

function bindUI() {
  $('#btnScanTop').addEventListener('click', () => start('live'));
  $('#compatClose').addEventListener('click', () => { $('#compatBar').hidden = true; });
  $('#btnDemo').addEventListener('click', () => start('demo'));
  $('#btnStop').addEventListener('click', stop);
  $('#helpBtn').addEventListener('click', () => { $('#helpModal').hidden = false; });
  $('#helpClose').addEventListener('click', () => { $('#helpModal').hidden = true; });
  $('#helpModal').addEventListener('click', (e) => { if (e.target.id === 'helpModal') $('#helpModal').hidden = true; });
  $('#archiveModal').addEventListener('click', (e) => { if (e.target.id === 'archiveModal') $('#archiveModal').hidden = true; });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { $('#helpModal').hidden = true; $('#archiveModal').hidden = true; }
  });
  $('#pwEye').addEventListener('click', () => {
    const p = $('#fPass');
    p.type = p.type === 'password' ? 'text' : 'password';
    $('#pwEye').textContent = p.type === 'password' ? '◉' : '◎';
  });
  $$('.form input').forEach(el => el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !state.running) start('live');
  }));
  ['fHost', 'fPort', 'fUser'].forEach(id => {
    $('#' + id).addEventListener('change', () => localStorage.setItem('sentinel.' + id, $('#' + id).value.trim()));
  });

  $('#btnClearLog').addEventListener('click', () => {
    $('#logBody').innerHTML = '';
    state.logCount = 0;
    $('#logCount').textContent = '0 LINES';
  });
  $('#btnToggleLog').addEventListener('click', (e) => {
    const t = $('#terminal');
    t.classList.toggle('collapsed');
    e.target.textContent = t.classList.contains('collapsed') ? '展开' : '收起';
  });

  $('#filterChips').addEventListener('click', (e) => {
    const b = e.target.closest('.chip');
    if (!b) return;
    $$('.chip').forEach(c => c.classList.remove('active'));
    b.classList.add('active');
    state.filter = b.dataset.sev;
    renderFindings(false);
  });
  $('#moduleFilter').addEventListener('change', (e) => { state.moduleFilter = e.target.value; renderFindings(false); });
  $('#searchInput').addEventListener('input', (e) => { state.keyword = e.target.value.trim().toLowerCase(); renderFindings(false); });
  $('#btnMd').addEventListener('click', () => exportReport('md'));
  $('#btnJson').addEventListener('click', () => exportReport('json'));
  $('#btnPrint').addEventListener('click', () => window.print());
  $('#btnArchive').addEventListener('click', openArchive);
  $('#btnSaveNow').addEventListener('click', saveResult);
  $('#btnRefreshArc').addEventListener('click', refreshArchive);
  $('#archiveClose').addEventListener('click', () => { $('#archiveModal').hidden = true; });
  $('#importFile').addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) importLocalFile(f);
    e.target.value = '';
  });
  $('#archiveList').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-act]');
    if (!b) return;
    const row = b.closest('.arc-row');
    const item = state.savedReports[Number(row && row.dataset.i)];
    if (!item) return;
    if (b.dataset.act === 'load') return loadFromServer(item.name);
    if (b.dataset.act === 'del') {
      if (b.dataset.confirm !== '1') {
        b.dataset.confirm = '1'; b.textContent = '确认删除';
        setTimeout(() => { if (b.isConnected) { b.dataset.confirm = ''; b.textContent = '删除'; } }, 4000);
        return;
      }
      deleteArchive(item.name);
    }
  });
}

/* ------------------------------------------------------------------ 模块列表 */
function renderModules() {
  const box = $('#moduleList');
  box.innerHTML = state.modules.map(m => {
    const st = state.modState[m.id] || {};
    const cls = st.status === 'running' ? 'running' : (st.status === 'done' ? 'done' + (st.found ? ' alert' : '') : '');
    const total = state.checks.filter(c => c.module === m.id).length;
    const label = st.status === 'running' ? '排查中'
      : st.status === 'done' ? (st.found ? `<b class="has">${st.found} 项</b>` : '<b>通过</b>')
      : `${st.checked || 0}/${total}`;
    return `<div class="mod-row ${cls}" data-mod="${m.id}" title="${esc(m.name)}">
      <span class="mod-code">${esc(m.code)}</span>
      <span class="mod-name">${esc(m.name)}</span>
      <span class="mod-stat">${label}</span>
      <span class="mod-led"></span>
    </div>`;
  }).join('');
}

/* ------------------------------------------------------------------ 启动 / 停止 */
async function start(mode) {
  if (state.running) return;
  let payload = {};
  if (mode === 'live') {
    const host = $('#fHost').value.trim(), port = $('#fPort').value.trim() || '22';
    const user = $('#fUser').value.trim(), password = $('#fPass').value;
    const sudo_password = $('#fSudo').value;
    if (!host || !user || !password) {
      hint('请填写目标 IP、账号与登录密码。', 'err');
      toast('缺少连接参数：IP / 账号 / 密码为必填项', 'err');
      return;
    }
    payload = { host, port, user, password, sudo_password };
  }
  setLaunchBusy(true);
  hint('正在建立会话…', '');
  try {
    const r = await api(mode === 'live' ? '/api/scan' : '/api/demo', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(mode === 'live' ? payload : {}),
    });
    resetState(mode, r.task_id);
    beginPolling();
    if (mode === 'live') {
      // 保留输入框中的登录口令，便于对同一目标重复排查
      hint('连接已建立，正在执行只读排查…', 'ok');
    } else {
      hint('演示模式运行中：内置靶机数据重放完整排查流程。', 'ok');
    }
  } catch (e) {
    setLaunchBusy(false);
    hint('启动失败：' + e.message, 'err');
    toast('启动失败：' + e.message, 'err');
  }
}

function resetState(mode, taskId) {
  stopPolling();
  state.taskId = taskId; state.mode = mode; state.cursor = 0;
  state.running = true; state.findings = []; state.modState = {};
  state.progress = 0; state.doneTotal = 0; state.startAt = Date.now();
  state.expanded = {}; state.domCount = 0; state.renderKey = ''; state.sysinfo = {};
  state.loadedName = '';
  state.dirty = { stats: false, modules: false, findings: false };
  state.filter = 'all'; state.moduleFilter = 'all'; state.keyword = '';
  $$('.chip').forEach(c => c.classList.toggle('active', c.dataset.sev === 'all'));
  $('#moduleFilter').value = 'all'; $('#searchInput').value = '';
  $('#logBody').innerHTML = ''; state.logCount = 0; $('#logCount').textContent = '0 LINES';
  $('#terminal').classList.remove('collapsed'); $('#btnToggleLog').textContent = '收起';
  $('#findings').innerHTML = '';
  renderModules(); renderStats(); renderFindings(false);
  $('#progressFill').style.width = '0%'; $('#progressPct').textContent = '0%';
  $('#progressLabel').textContent = '排查启动中 · 正在建立 SSH 会话';
  $('#scanState').textContent = '排查中 / SCANNING';
  $('#engineText').textContent = '排查进行中';
  $('#engineStatus .dot').className = 'dot dot-amber';
  $('#btnStop').disabled = false;
  $('#tElapsed').textContent = '00:00';
  $('#tRoot').textContent = '连接中'; $('#tRoot').className = 'priv-badge';
  $('#tOs').textContent = mode === 'demo' ? '演示靶机 · 正在采集基线…' : '正在建立连接…';
  $('#tKernel').textContent = '—'; $('#tIdentity').textContent = '—';
  state.clockTimer = setInterval(() => {
    $('#tElapsed').textContent = fmtClock((Date.now() - state.startAt) / 1000);
  }, 500);
}

async function stop() {
  if (!state.taskId) return;
  try { await api('/api/stop', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: state.taskId }) }); }
  catch (e) { /* ignore */ }
  toast('已发送终止指令，将在当前检查项结束后停止', 'warn');
}

function beginPolling() {
  stopPolling();
  state.pollTimer = setInterval(poll, 220);
  poll();
}
function stopPolling() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = null;
}

async function poll() {
  if (!state.taskId) return;
  try {
    const r = await api(`/api/events?id=${encodeURIComponent(state.taskId)}&cursor=${state.cursor}`);
    state.cursor = r.cursor;
    if (r.events && r.events.length) {
      r.events.forEach(handleEvent);
      if (state.dirty.stats) { renderStats(); state.dirty.stats = false; }
      if (state.dirty.modules) { renderModules(); state.dirty.modules = false; }
      if (state.dirty.findings) { renderFindings(true); state.dirty.findings = false; }
    }
    if (r.status !== 'running') finish(r.status);
  } catch (e) {
    stopPolling();
    finish('error', e.message);
  }
}

function finish(status, msg) {
  stopPolling();
  clearInterval(state.clockTimer);
  state.running = false;
  setLaunchBusy(false); $('#btnStop').disabled = true;
  $('#scanState').textContent = status === 'error' ? '异常中断 / ERROR' : '排查完成 / COMPLETE';
  $('#engineText').textContent = status === 'error' ? '引擎异常' : '引擎在线';
  $('#engineStatus .dot').className = 'dot ' + (status === 'error' ? 'dot-red' : 'dot-green');
  Object.keys(state.modState).forEach(k => { if (state.modState[k].status === 'running') state.modState[k].status = 'done'; });
  renderModules();
  if (status === 'error') {
    hint('任务中断：' + (msg || '连接失败，请检查参数与网络'), 'err');
    toast('排查中断，请查看作战日志中的错误信息', 'err');
  } else {
    hint('排查完成：发现 ' + state.findings.length + ' 项问题，可导出完整报告。', 'ok');
    toast(`排查完成 · ${state.findings.length} 项发现 · 报告已生成`, state.findings.length ? 'warn' : 'ok');
  }
}

/* ------------------------------------------------------------------ 事件处理 */
const LV = { info: ['INFO', 'info'], ok: ['OK', 'ok'], warn: ['WARN', 'warn'], err: ['ERR', 'err'], cmd: ['CMD', 'cmd'], sys: ['SYS', 'sys'] };

function handleEvent(e) {
  const d = e.data || {};
  switch (e.type) {
    case 'log': addLog(e.t, d.level || 'info', d.text || ''); break;
    case 'phase': addLog(e.t, 'sys', d.text || ''); break;
    case 'sysinfo': applySysinfo(d); break;
    case 'check_start': {
      const m = state.modState[d.module] || (state.modState[d.module] = { status: 'pending', checked: 0, found: 0 });
      m.status = 'running';
      state.dirty.modules = true;
      $('#progressLabel').textContent = `正在排查 [${String(d.index).padStart(2, '0')}/${d.total}] ${d.name}`;
      break;
    }
    case 'check_done': {
      const m = state.modState[d.module] || (state.modState[d.module] = { status: 'done', checked: 0, found: 0 });
      m.status = 'done'; m.checked = (m.checked || 0) + 1; m.found = (m.found || 0) + (d.count || 0);
      state.dirty.modules = true;
      break;
    }
    case 'finding': {
      state.findings.push(d);
      state.dirty.stats = true; state.dirty.findings = true;
      addLog(e.t, 'warn', `⚠ [${SEV_CN[d.severity] || '提示'}] ${d.title}`);
      break;
    }
    case 'pass': break;
    case 'progress': {
      state.progress = d.pct || 0; state.doneTotal = d.done || 0;
      $('#progressFill').style.width = state.progress + '%';
      $('#progressPct').textContent = Math.round(state.progress) + '%';
      $('#moduleProgress').textContent = `${d.done} / ${d.total}`;
      state.checkTotal = d.total;
      break;
    }
    case 'done': {
      $('#progressFill').style.width = '100%';
      $('#progressPct').textContent = '100%';
      $('#progressLabel').textContent = d.error ? '任务异常中断' : `排查完成 · ${d.checks || state.checkTotal || state.checks.length} 项检查 · 发现 ${d.findings || state.findings.length} 项问题 · 用时 ${d.duration || 0}s`;
      if (d.error) addLog(e.t, 'err', d.error);
      break;
    }
  }
}

function addLog(t, level, text) {
  const body = $('#logBody');
  const term = $('#terminal');
  const stick = term.scrollHeight - term.scrollTop - term.clientHeight < 90;
  const lv = LV[level] || LV.info;
  const row = document.createElement('div');
  row.className = 'log-line ' + (['warn', 'err', 'ok'].includes(level) ? level : '');
  row.innerHTML = `<span class="log-t">${fmtStamp(t || 0)}</span><span class="log-lv lv-${level === 'cmd' ? 'cmd' : level}">${lv[0]}</span><span class="log-msg">${esc(text)}</span>`;
  body.appendChild(row);
  state.logCount++;
  if (state.logCount > 420) { body.removeChild(body.firstChild); state.logCount--; }
  $('#logCount').textContent = state.logCount + ' LINES';
  if (stick) term.scrollTop = term.scrollHeight;
}

function applySysinfo(d) {
  state.sysinfo = d;
  $('#tOs').textContent = d.os || '未知系统';
  $('#tOs').title = d.os_full || '';
  $('#tKernel').textContent = (d.kernel || '—').slice(0, 70);
  $('#tKernel').title = d.kernel || '';
  $('#tIdentity').textContent = (d.identity || '—').slice(0, 60);
  const r = $('#tRoot');
  if (state.mode === 'demo') { r.textContent = 'DEMO / 提权成功'; r.className = 'priv-badge demo'; }
  else if (d.root) { r.textContent = 'ROOT ✓'; r.className = 'priv-badge yes'; }
  else { r.textContent = '非 ROOT'; r.className = 'priv-badge no'; }
  addLog(0.1, 'ok', `目标画像已建立：${d.os || 'unknown'} · ${d.root ? 'root 上下文' : '权限受限'}`);
}

/* ------------------------------------------------------------------ 统计 */
function renderStats() {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  state.findings.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
  const total = state.findings.length;
  Object.keys(c).forEach(k => {
    const el = $(`.stat-num[data-sev="${k}"]`);
    if (el) {
      el.textContent = c[k];
      const bar = el.parentElement.querySelector('.stat-bar i');
      if (bar) bar.style.width = (total ? Math.min(100, c[k] / total * 100 * 2.2) : 0) + '%';
    }
  });
  $('#statTotal').textContent = total;
  $('#statTotal').parentElement.querySelector('.stat-bar i').style.width = (total ? Math.min(100, total * 8) : 0) + '%';
  $('#resultCount').textContent = total + ' 项';
  if (!state.running && !state.taskId) $('#progressLabel').textContent = '排查进度 · 等待启动';
}

/* ------------------------------------------------------------------ 发现清单 */
function currentList() {
  return state.findings.filter(f => {
    if (state.filter !== 'all' && f.severity !== state.filter) return false;
    if (state.moduleFilter !== 'all' && f.module !== state.moduleFilter) return false;
    if (state.keyword) {
      const m = methodOf(f);
      const hay = [f.title, f.summary, f.evidence, f.tag, f.check, (f.fix || []).join(' '),
                    m && m.intro, m && m.judge, (m && m.cmds || []).join(' ')].join(' ').toLowerCase();
      if (hay.indexOf(state.keyword) < 0) return false;
    }
    return true;
  });
}

function renderFindings(incremental) {
  const box = $('#findings');
  const list = currentList();
  const base = [state.filter, state.moduleFilter, state.keyword].join('|');
  const key = base + '|' + list.length;
  if (!list.length) {
    state.domCount = 0; state.renderKey = key;
    box.innerHTML = `<div class="empty-state" id="emptyState">
      <div class="radar"><i></i><i></i><i></i><span></span></div>
      <div class="empty-title">${state.findings.length ? '当前筛选无匹配结果' : (state.running ? '正在排查，等待发现…' : '等待排查结果')}</div>
      <div class="empty-desc">${state.findings.length ? '试试切换严重级别、模块或清空搜索关键词' : '发现的问题将在此逐条列出：简明说明 · 排查方法 · 关键证据 · 整改方案（默认全部展开）<br>可按严重级别与模块筛选，用「结果存档」保存 / 加载，或导出完整应急响应报告'}</div>
    </div>`;
    return;
  }
  // 完全没有变化：不重绘，避免动画闪烁与展开状态丢失
  if (incremental && state.renderKey === key && list.length === state.domCount) return;
  // 筛选条件未变且只是新增发现：增量追加
  if (incremental && state.renderKey === base + '|' + state.domCount &&
      list.length > state.domCount && !box.querySelector('.empty-state, .no-match')) {
    for (let i = state.domCount; i < list.length; i++) box.appendChild(cardNode(list[i], i));
    state.domCount = list.length;
    state.renderKey = key;
    return;
  }
  state.renderKey = key;
  state.domCount = list.length;
  box.innerHTML = '';
  list.forEach((f, i) => box.appendChild(cardNode(f, i)));
}

/* 排查方法永远存在：优先用「产出该条关键证据」的命令；缺失时用可执行的只读复核命令兜底 */
function methodOf(f) {
  const m = f.method || (state.checkMap[f.id] && state.checkMap[f.id].method);
  if (m && Array.isArray(m.cmds) && m.cmds.length) return m;
  const first = (f.evidence || '').split('\n').find(x => x.trim().length > 3) || '';
  const token = (first.match(/[A-Za-z0-9_\-./]{4,40}/) || ['passwd'])[0];
  return {
    intro: (m && m.intro) || '依据关键证据中的路径、账号或进程特征在目标主机做只读复核。',
    cmds: [
      'ps auxww; ss -tunap',
      `grep -RniF -- '${token}' /etc /var/log /var/www 2>/dev/null | head -50`,
      'crontab -l; systemctl list-units --type=service --state=running',
    ],
    cmds_all: (m && m.cmds_all) || [],
    judge: (m && m.judge) || '输出与关键证据一致即命中；建议用当前版本重新执行一次排查以补齐取证命令。',
    inferred: false,
    source_note: (m && m.source_note) || '外部/旧版报告未附带原始取证命令，以下为通用复核命令',
  };
}

/* 排查方法：只列出产出关键证据的只读命令，格式与「整改方案」一致 */
function methodHtml(m) {
  const cmds = (m.cmds && m.cmds.length) ? m.cmds : ['ps auxww; ss -tunap'];
  return `<ol class="f-fix f-method-list">${cmds.map(c => `<li><code>${esc(c)}</code></li>`).join('')}</ol>`;
}

const TOGGLE_LABELS = { method: '排查方法', ev: '关键证据', fix: '整改方案' };

function cardNode(f, i) {
  const key = (f.id || '') + '#' + i;
  // 三段内容默认全部展开
  const ex = state.expanded[key] || { method: true, ev: true, fix: true };
  state.expanded[key] = ex;
  const mod = state.modules.find(m => m.id === f.module);
  const div = document.createElement('div');
  div.className = 'finding sev-' + (f.severity || 'info');
  div.dataset.key = key;
  const toggles = Object.keys(TOGGLE_LABELS).map(act =>
    `<button class="f-toggle ${ex[act] ? 'on' : ''}" data-act="${act}">${ex[act] ? '▾' : '▸'} ${TOGGLE_LABELS[act]}</button>`).join('');
  div.innerHTML = `
    <div class="finding-top">
      <span class="sev-badge">${SEV_CN[f.severity] || '提示'} ${String(f.severity || 'info').toUpperCase()}</span>
      <span class="f-mod">${esc(mod ? mod.name : (f.module || '—'))}</span>
      <span class="f-tag"># ${esc(f.tag || '通用')}</span>
      <span class="f-idx">F-${String(i + 1).padStart(2, '0')}</span>
    </div>
    <div class="finding-title">${esc(f.title || '未命名发现')}</div>
    <div class="finding-summary">${esc(f.summary || '')}</div>
    <div class="finding-actions">
      ${toggles}
      <span class="f-check" title="所属检查项">${esc(f.check || f.id || '')}</span>
    </div>
    <div class="f-section f-method-sec ${ex.method ? 'open' : ''}">
      <div class="f-label">METHOD / 排查方法</div>
      ${methodHtml(methodOf(f))}
    </div>
    <div class="f-section f-ev ${ex.ev ? 'open' : ''}">
      <div class="f-label">EVIDENCE / 关键证据</div>
      <pre class="f-evidence">${esc(f.evidence || '（无输出证据）')}</pre>
    </div>
    <div class="f-section f-fix-sec ${ex.fix ? 'open' : ''}">
      <div class="f-label">REMEDIATION / 整改方案</div>
      <ol class="f-fix">${(f.fix || []).map(s => `<li>${fmt(s)}</li>`).join('') || '<li>人工复核该项配置并按需收敛权限</li>'}</ol>
    </div>`;
  div.querySelectorAll('.f-toggle').forEach(b => b.addEventListener('click', () => {
    const act = b.dataset.act;
    ex[act] = !ex[act];
    b.classList.toggle('on', ex[act]);
    b.textContent = `${ex[act] ? '▾' : '▸'} ${TOGGLE_LABELS[act]}`;
    const sec = div.querySelector(act === 'method' ? '.f-method-sec' : act === 'ev' ? '.f-ev' : '.f-fix-sec');
    sec.classList.toggle('open', ex[act]);
  }));
  return div;
}

/* ------------------------------------------------------------------ 导出 */
async function exportReport(format) {
  if (!state.taskId) { toast('请先执行一次排查或演示模式', 'warn'); return; }
  try {
    const r = await fetch(`/api/report?id=${encodeURIComponent(state.taskId)}&format=${format}`);
    if (!r.ok) throw new Error('报告生成失败');
    const blob = await r.blob();
    const ts = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
    const host = (state.sysinfo.host_conn || $('#fHost').value || 'target').replace(/[^\w.\-]/g, '_');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `SENTINEL_IR_${host}_${ts}.${format === 'md' ? 'md' : 'json'}`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 3000);
    toast('报告已导出：' + a.download, 'ok');
  } catch (e) { toast('导出失败：' + e.message, 'err'); }
}

/* ------------------------------------------------------------------ 结果存档 */
function updateArcCurrent() {
  const el = $('#arcCurrent');
  if (!state.taskId) {
    el.textContent = '尚未产生排查结果';
    $('#btnSaveNow').disabled = true;
    return;
  }
  $('#btnSaveNow').disabled = false;
  const host = state.sysinfo.host_conn || $('#fHost').value.trim() || 'target';
  const mode = state.mode === 'demo' ? '演示模式' : state.mode === 'loaded' ? '已加载存档' : '实机排查';
  el.textContent = `${host} · ${state.findings.length} 项发现 · ${mode}`;
}

async function openArchive() {
  $('#archiveModal').hidden = false;
  updateArcCurrent();
  await refreshArchive();
}

async function refreshArchive() {
  const box = $('#archiveList');
  box.innerHTML = '<div class="arc-empty">正在读取存档列表…</div>';
  try {
    const r = await api('/api/saves');
    state.savedReports = r.reports || [];
    $('#arcCount').textContent = state.savedReports.length;
    if (!state.savedReports.length) {
      box.innerHTML = '<div class="arc-empty">暂无存档。完成一次排查后点「保存当前结果」即可创建。</div>';
      return;
    }
    box.innerHTML = state.savedReports.map((x, i) => `
      <div class="arc-row" data-i="${i}">
        <span class="arc-ico">▣</span>
        <div class="arc-info">
          <div class="arc-name" title="${esc(x.name)}">${esc(x.name)}</div>
          <div class="arc-meta">${esc(x.generated || x.mtime)} · ${esc(x.target)} · 发现 <b>${x.findings}</b> 项（严重 ${x.critical}） · ${(x.size / 1024).toFixed(1)} KB${x.broken ? ' · 文件损坏' : ''}</div>
        </div>
        <div class="arc-btns">
          <button class="mini-btn" data-act="load">加载</button>
          <button class="mini-btn arc-del" data-act="del">删除</button>
        </div>
      </div>`).join('');
  } catch (e) {
    if (isStaleBackend(e)) {
      box.innerHTML = '<div class="arc-empty">服务端存档接口不可用（后端为旧版本）。请关闭所有旧的控制台窗口，重新运行 start.bat 后刷新本页。</div>';
      showCompatHint();
    } else {
      box.innerHTML = `<div class="arc-empty">读取失败：${esc(e.message)}</div>`;
    }
  }
}

/* 旧版后端没有 /api/save 时，降级为把完整 JSON 报告下载到本地，保证「保存」动作不白点 */
async function saveReportLocally() {
  const r = await fetch(`/api/report?id=${encodeURIComponent(state.taskId)}`);
  if (!r.ok) throw new Error('报告生成失败 (HTTP ' + r.status + ')');
  const blob = await r.blob();
  const ts = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
  const host = (state.sysinfo.host_conn || $('#fHost').value || 'target').replace(/[^\w.\-]/g, '_');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `SENTINEL_${ts}_${host}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
  return a.download;
}

async function saveResult() {
  if (!state.taskId) { toast('请先执行一次排查或演示模式', 'warn'); return; }
  const btn = $('#btnSaveNow');
  btn.disabled = true; btn.textContent = '保存中…';
  try {
    const r = await api('/api/save', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: state.taskId }),
    });
    toast(`已保存：${r.name}（${r.findings} 项发现）`, 'ok');
    await refreshArchive();
  } catch (e) {
    if (isStaleBackend(e)) {
      showCompatHint('保存接口返回旧版后端的响应：请关闭所有旧的控制台窗口，重新运行 start.bat 后刷新本页，即可使用服务端存档。本次已改为下载报告到本地。');
      try {
        const name = await saveReportLocally();
        toast(`已下载到本地：${name}（重启后端后可写入 reports/ 存档）`, 'warn');
      } catch (e2) {
        toast('保存失败：' + e.message + '；本地导出也失败：' + e2.message, 'err');
      }
    } else {
      toast('保存失败：' + e.message, 'err');
    }
  } finally {
    btn.disabled = false; btn.textContent = '▣ 保存当前结果';
  }
}

async function deleteArchive(name) {
  try {
    await api('/api/save/delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    toast('已删除存档：' + name, 'ok');
    await refreshArchive();
  } catch (e) { toast('删除失败：' + e.message, 'err'); }
}

async function loadFromServer(name) {
  try {
    const r = await api('/api/load?name=' + encodeURIComponent(name));
    applyLoadedReport(r.report, r.task_id, name);
    toast('已加载存档：' + name, 'ok');
    $('#archiveModal').hidden = true;
  } catch (e) {
    if (isStaleBackend(e)) showCompatHint();
    toast('加载失败：' + e.message, 'err');
  }
}

async function importLocalFile(file) {
  let obj;
  try { obj = JSON.parse(await file.text()); }
  catch (e) { toast('文件不是合法 JSON：' + e.message, 'err'); return; }
  try {
    const r = await api('/api/import', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(obj),
    });
    applyLoadedReport(r.report, r.task_id, file.name);
    toast('已导入报告：' + file.name, 'ok');
    $('#archiveModal').hidden = true;
  } catch (e) {
    if (isStaleBackend(e)) showCompatHint();
    toast('导入失败：' + e.message, 'err');
  }
}

function applyLoadedReport(report, taskId, label) {
  stopPolling();
  clearInterval(state.clockTimer);
  state.taskId = taskId;
  state.mode = 'loaded';
  state.running = false;
  state.cursor = 0;
  state.loadedName = label;
  state.findings = Array.isArray(report.findings) ? report.findings : [];
  state.sysinfo = report.sysinfo || {};
  if (report.modules && report.modules.length) state.modules = report.modules;
  state.expanded = {}; state.domCount = 0; state.renderKey = '';
  state.filter = 'all'; state.moduleFilter = 'all'; state.keyword = '';
  $$('.chip').forEach(c => c.classList.toggle('active', c.dataset.sev === 'all'));
  $('#moduleFilter').value = 'all'; $('#searchInput').value = '';

  state.modState = {};
  const passes = report.passed || [];
  state.modules.forEach(m => {
    state.modState[m.id] = {
      status: 'done',
      checked: state.checks.filter(c => c.module === m.id).length,
      found: 0,
    };
  });
  state.findings.forEach(f => {
    const m = state.modState[f.module];
    if (m) m.found = (m.found || 0) + 1;
  });

  $('#logBody').innerHTML = ''; state.logCount = 0;
  addLog(0, 'sys', '已加载应急响应结果：' + label);
  addLog(0, 'ok', `还原 ${state.findings.length} 项发现 / ${passes.length} 项已通过检查 / ${state.modules.length} 个模块`);
  if (report.generated) addLog(0, 'info', '报告生成时间：' + report.generated);

  if (Object.keys(state.sysinfo).length) applySysinfo(state.sysinfo);
  else { $('#tOs').textContent = label; $('#tRoot').textContent = '已加载'; }

  state.checkTotal = (report.stats && report.stats.checks) || state.checkTotal || state.checks.length;
  state.progress = 100; state.doneTotal = state.checkTotal;
  $('#progressFill').style.width = '100%';
  $('#progressPct').textContent = '100%';
  $('#progressLabel').textContent = `已加载存档 · ${state.checkTotal} 项检查 · ${state.findings.length} 项发现`;
  $('#moduleProgress').textContent = `${state.checkTotal} / ${state.checkTotal}`;
  $('#scanState').textContent = '已加载存档 / LOADED';
  $('#tElapsed').textContent = fmtClock(report.duration || 0);
  setLaunchBusy(false); $('#btnStop').disabled = true;
  $('#engineText').textContent = '引擎在线';
  $('#engineStatus .dot').className = 'dot dot-green';
  $('#terminal').classList.remove('collapsed'); $('#btnToggleLog').textContent = '收起';

  renderModules(); renderStats(); renderFindings(false);
  hint(`已加载 ${label} · ${state.findings.length} 项发现，可继续筛选与导出。`, 'ok');
}

document.addEventListener('DOMContentLoaded', init);
