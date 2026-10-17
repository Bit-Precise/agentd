const $ = (selector) => document.querySelector(selector);
const model = {user: null, csrf: '', data: null, page: 'overview', tab: 'grants', workspace: '', query: '', loading: false, refreshing: false, lastSync: null};
const pages = {
  overview: ['总览', 'WORKSPACE OVERVIEW', '了解服务、设备与访问连接的最新状态。'],
  agents: ['Agents', 'AGENT DIRECTORY', '审核提供能力，观察设备状态与连接。'],
  services: ['服务发布', 'PUBLISHED SERVICES', '由 Agent 声明的服务，在批准后按授权范围开放。'],
  egress: ['出口路由', 'EGRESS ROUTES', '将获准的 TLS 域名请求交给指定 Agent。'],
  access: ['权限与成员', 'ACCESS MANAGEMENT', '管理访问授权、设备注册凭据与工作空间成员。'],
  audit: ['审计日志', 'ACTIVITY & AUDIT', '追踪资源变更、批准与撤销操作。'],
};
const roleNames = {owner: '所有者', maintainer: '维护者', developer: '开发者', guest: '访客', ingress: '访问端', access: '访问端', provider: '提供方', serve: '服务发布', egress: '域名出口'};

function h(tag, className = '', ...children) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}
function button(label, action, kind = 'secondary', small = false) {
  const element = h('button', `button ${kind}${small ? ' small' : ''}`, label);
  element.type = 'button';
  element.addEventListener('click', action);
  return element;
}
function badge(label, kind = 'neutral') { return h('span', `badge ${kind}`, label); }
function cell(title, subtitle = '', icon = '') {
  const text = h('div', '', h('div', 'cell-title', title), subtitle ? h('div', 'cell-subtitle', subtitle) : null);
  return icon ? h('div', 'name-cell', h('span', 'object-icon', icon), text) : text;
}
function actions(...items) { return h('div', 'actions', items); }
function empty(title, description, action) { return h('div', 'empty', h('div', 'empty-icon', '◇'), h('h3', '', title), h('p', '', description), action); }
function panel(title, subtitle, body, action) {
  return h('section', 'panel', h('div', 'panel-heading', h('div', '', h('h3', '', title), h('p', 'panel-subtitle', subtitle)), action), body);
}
function table(headers, rows, emptyContent) {
  if (!rows.length) return emptyContent || empty('暂无记录', '符合当前工作空间与搜索条件的记录会显示在这里。');
  return h('div', 'table-wrap', h('table', '', h('thead', '', h('tr', '', headers.map((label) => h('th', '', label)))), h('tbody', '', rows.map((columns) => h('tr', '', columns.map((value) => h('td', '', value)))))));
}
function notice(text) { return h('div', 'notice', h('span', 'notice-icon', 'ⓘ'), h('span', '', text)); }
function list(name) { return Array.isArray(model.data?.[name]) ? model.data[name] : []; }
function workspaceName(id) { return list('workspaces').find((w) => w.id === id)?.name || id || '—'; }
function userName(id) { return list('users').find((u) => u.id === id)?.name || id || '—'; }
function agentName(id) { return list('agents').find((a) => a.id === id)?.name || id || '—'; }
function actorName(id) { return userName(id || model.user?.id); }
function resourceName(id) { return [...list('services'), ...list('egressRoutes'), ...list('agents'), ...list('workspaces'), ...list('users')].find((r) => r.id === id)?.name || id || '—'; }
function scoped(items) { return items.filter(inWorkspace); }
function inWorkspace(item) {
  if (!model.workspace) return true;
  const p = item.principal || {};
  const id = item.workspaceId || p.workspaceId;
  if (id) return id === model.workspace;
  const name = item.workspace || p.workspace;
  if (name) return name === workspaceName(model.workspace) || name === model.workspace;
  const agent = list('agents').find((a) => a.id === (item.agentId || p.agentId));
  return agent?.workspaceId === model.workspace;
}
function matches(...values) { return !model.query || values.flat().filter(Boolean).join(' ').toLocaleLowerCase().includes(model.query); }
function date(value) { const d = new Date(value); return Number.isFinite(d.getTime()) && d.getFullYear() > 1970 ? d : null; }
function time(value) { return date(value)?.toLocaleString('zh-CN', {month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false}) || '—'; }
function fullTime(value) { return date(value)?.toLocaleString('zh-CN', {hour12: false}) || '—'; }
function shortID(value) { return value ? String(value).slice(0, 12) : '—'; }
function isLive(connection) { return !['closed', 'revoked', 'expired', 'offline'].includes(connection.status); }
function connectionsFor(agent) { return list('connections').filter((c) => (c.agentId || c.principal?.agentId) === agent.id && isLive(c)); }
function needsApproval(agent) { return agent.pendingApproval || ['pending', 'pending_approval'].includes(agent.status); }
function agentStateBadge(agent) { return actions(badge(...agentHealth(agent)), agent.pendingApproval && !['pending', 'pending_approval'].includes(agent.status) ? badge('配置待批准', 'warn') : null); }
function agentHealth(agent) {
  if (['revoked', 'disabled'].includes(agent.status)) return ['已撤销', 'bad'];
  if (['pending', 'pending_approval'].includes(agent.status)) return ['待批准', 'warn'];
  if (date(agent.approval?.expiresAt) && date(agent.approval.expiresAt) <= new Date()) return ['批准已过期', 'warn'];
  if (connectionsFor(agent).length) return ['在线', 'good'];
  return ['离线', 'neutral'];
}
function grantHealth(grant) {
  if (grant.revoked) return ['已撤销', 'neutral'];
  if (!date(grant.expiresAt) || date(grant.expiresAt) <= new Date()) return ['已到期', 'neutral'];
  if (date(grant.startsAt) > new Date()) return ['未开始', 'info'];
  return ['生效中', 'good'];
}
function activeGrants(id) { return list('grants').filter((g) => g.resourceId === id && grantHealth(g)[1] === 'good'); }
function canManage(workspaceID = model.workspace) {
  if (model.user?.admin) return true;
  return list('memberships').some((m) => m.userId === model.user?.id && (!workspaceID || m.workspaceId === workspaceID) && ['owner', 'maintainer'].includes(m.role));
}
function canEnroll(workspaceID = model.workspace) { return model.user?.admin || list('memberships').some((m) => m.userId === model.user?.id && (!workspaceID || m.workspaceId === workspaceID)); }
function canManageResource(type, id) {
  const resource = list(type === 'service' ? 'services' : 'egressRoutes').find((r) => r.id === id);
  if (!resource) return false;
  if (canManage(resource.workspaceId)) return true;
  return type === 'service' && list('memberships').some((m) => m.workspaceId === resource.workspaceId && m.userId === model.user?.id && m.role === 'developer') && list('agents').some((a) => a.id === resource.agentId && a.userId === model.user?.id);
}
function canGrantInWorkspace(workspaceID) { return canManage(workspaceID) || list('services').some((s) => s.workspaceId === workspaceID && canManageResource('service', s.id)); }
function ruleText(rule) {
  if (!rule) return '未声明目标';
  const domain = rule.domain?.exact || (rule.domain?.suffix ? `*.${rule.domain.suffix}（包含主域）` : '未指定域名');
  return `${domain} · ${(rule.ports || []).join(', ') || '所有端口'} · ${(rule.protocol || 'tls').toUpperCase()}`;
}
function agentRoles(agent) {
  return [['ingress', '访问端'], ['serve', '服务发布'], ['egress', '域名出口']].filter(([key]) => agent.desired?.[key]?.enabled).map(([, label]) => label);
}
function caps(values) { return h('div', 'capabilities', values.length ? values.map((value) => h('span', 'capability', value)) : h('span', 'cell-subtitle', '未启用业务角色')); }
function subjectName(grant) {
  if (grant.subjectType === 'anonymous') return '匿名访问者';
  if (grant.subjectType === 'workspace') return `${workspaceName(grant.subjectId)} 的成员`;
  return userName(grant.subjectId);
}

async function api(path, options = {}) {
  const mutation = options.method && options.method !== 'GET';
  const headers = {'Accept': 'application/json'};
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (mutation && model.csrf) headers['X-CSRF-Token'] = model.csrf;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`/api/v1${path}`, {method: options.method || 'GET', credentials: 'same-origin', cache: 'no-store', headers, signal: controller.signal, body: options.body === undefined ? undefined : JSON.stringify(options.body)});
    let data = null;
    if (response.status !== 204) {
      const text = await response.text();
      if (text) { try { data = JSON.parse(text); } catch { throw new Error('服务器返回了无法识别的响应。请稍后重试。'); } }
    }
    if (!response.ok) {
      if (response.status === 401 && path !== '/login' && path !== '/me') showLogin('登录已过期，请重新登录。');
      const detail = typeof data?.error === 'string' ? data.error : data?.error?.message || data?.message;
      throw new Error(detail || ({401: '访问令牌无效或已过期。', 403: '当前身份没有执行此操作的权限。', 404: '资源不存在或已被移除。', 409: '资源状态已变化，请刷新后重试。'}[response.status]) || `请求失败（${response.status}），请稍后重试。`);
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('请求超时，请检查连接后重试。');
    if (error instanceof TypeError) throw new Error('无法连接服务器，请检查网络连接。');
    throw error;
  } finally { clearTimeout(timeout); }
}

function showLogin(message = '') {
  model.user = null; model.csrf = ''; model.data = null; model.query = '';
  $('#search').value = '';
  if ($('#modal').open) $('#modal').close();
  $('#content').replaceChildren(); $('#login-token').value = '';
  $('#boot').hidden = true; $('#app').hidden = true; $('#login').hidden = false;
  $('#login-error').textContent = message; $('#login-error').hidden = !message;
}
async function authenticated(result) {
  if (!result?.user || !result.csrfToken) throw new Error('登录响应不完整，请重试。');
  model.user = result.user; model.csrf = result.csrfToken;
  $('#login-token').value = '';
  const returnTo = new URLSearchParams(location.search).get('returnTo');
  if (returnTo?.startsWith('/auth/authorize?')) {
    const target = new URL(returnTo, location.origin);
    if (target.origin === location.origin && target.pathname === '/auth/authorize') { location.replace(target.href); return; }
  }
  $('#boot').hidden = true; $('#login').hidden = true; $('#app').hidden = false;
  $('#user-name').textContent = result.user.name || '用户';
  $('#user-avatar').textContent = String(result.user.name || 'U').slice(0, 1).toUpperCase();
  $('#instance-host').textContent = location.host;
  await refresh();
}
async function refresh(quiet = false) {
  if (!model.user || model.refreshing) return;
  model.refreshing = true; model.loading = !model.data;
  $('#refresh').disabled = true;
  if (model.loading) render();
  try {
    const data = await api('/state');
    if (!model.user) return;
    model.data = data || {};
    if (data?.user) model.user = data.user;
    model.lastSync = new Date(); model.loading = false;
    $('#page-error').hidden = true;
    syncWorkspaceSelect(); render();
    $('#sync-status').textContent = `已同步 · ${model.lastSync.toLocaleTimeString('zh-CN', {hour12: false})} · 每 10 秒更新`;
    $('#revision').textContent = `REV ${model.data.revision ?? '—'}`;
  } catch (error) {
    if (!model.user) return;
    model.loading = false;
    $('#page-error').textContent = `${error.message}${model.data ? ' 当前显示上次成功同步的数据。' : ''}`;
    $('#page-error').hidden = false;
    $('#sync-status').textContent = model.data ? '连接暂不可用 · 数据可能已过时' : '未能加载状态';
    if (!quiet || !model.data) render();
  } finally { model.refreshing = false; $('#refresh').disabled = false; }
}
function syncWorkspaceSelect() {
  if (model.workspace && !list('workspaces').some((w) => w.id === model.workspace)) model.workspace = '';
  const select = $('#workspace-select'); select.replaceChildren();
  select.add(new Option('全部 Workspace', ''));
  for (const workspace of list('workspaces')) select.add(new Option(workspace.name, workspace.id));
  select.value = model.workspace;
}
function setPage() {
  const page = location.hash.slice(1).split('?')[0] || 'overview';
  model.page = pages[page] ? page : 'overview';
  model.query = ''; $('#search').value = '';
  render();
}
function render() {
  if (!model.user) return;
  const [title, eyebrow, description] = pages[model.page];
  $('#page-title').textContent = title; $('#page-eyebrow').textContent = eyebrow; $('#page-description').textContent = description;
  document.title = `${title} · agents`;
  document.querySelectorAll('[data-page]').forEach((link) => { const active = link.dataset.page === model.page; link.classList.toggle('active', active); if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); });
  const pending = scoped(list('agents')).filter(needsApproval).length;
  $('#agent-badge').textContent = pending; $('#agent-badge').hidden = !pending;
  renderPrimary();
  if (model.loading) { $('#content').replaceChildren(h('div', 'loading-panel', [0, 1, 2, 3].map(() => h('div', 'skeleton')))); return; }
  if (!model.data) { $('#content').replaceChildren(empty('状态尚未加载', '请确认服务运行正常，然后重新加载。', button('重新加载', () => refresh(), 'primary'))); return; }
  const content = {overview: renderOverview, agents: renderAgents, services: renderServices, egress: renderEgress, access: renderAccess, audit: renderAudit}[model.page]();
  $('#content').replaceChildren(...(Array.isArray(content) ? content : [content]));
}
function renderPrimary() {
  const action = $('#primary-action'); action.hidden = true; action.onclick = null;
  if (!model.data) return;
  let label, run;
  if (['overview', 'agents'].includes(model.page) && canEnroll()) { label = '+ 注册密钥'; run = enrollmentForm; }
  if (model.page === 'egress' && canManage()) { label = '+ 创建路由'; run = egressForm; }
  if (model.page === 'access') {
    const selected = {grants: ['+ 添加授权', grantForm], keys: ['+ 注册密钥', enrollmentForm], members: ['+ 添加成员', membershipForm], workspaces: ['+ 创建 Workspace', workspaceForm], users: ['+ 创建用户', userForm]}[model.tab];
    if (['workspaces', 'users'].includes(model.tab) && !model.user.admin) return;
    if (model.tab === 'members' && !canManage()) return;
    if (model.tab === 'keys' && !canEnroll()) return;
    if (model.tab === 'grants' && !list('workspaces').some((w) => (!model.workspace || w.id === model.workspace) && canGrantInWorkspace(w.id))) return;
    [label, run] = selected;
  }
  if (run) { action.hidden = false; action.textContent = label; action.onclick = () => run(); }
}

function renderOverview() {
  const agents = scoped(list('agents')), services = scoped(list('services')), routes = scoped(list('egressRoutes'));
  const pending = agents.filter(needsApproval);
  const connected = agents.filter((a) => agentHealth(a)[1] === 'good').length;
  const flows = scoped(list('flows'));
  const metric = (title, number, foot, symbol) => h('div', 'metric', h('div', 'metric-top', title, h('span', 'metric-icon', symbol)), h('div', 'metric-number', number), h('div', 'metric-foot', foot));
  const metrics = h('div', 'metrics', metric('在线 Agents', connected, `${agents.length} 个已注册 · ${pending.length} 个待批准`, '⌘'), metric('已发布服务', services.filter((s) => s.enabled).length, `${services.length} 个服务 · ${services.filter((s) => activeGrants(s.id).length).length} 个具有有效授权`, '◈'), metric('出口路由', routes.filter((r) => r.enabled).length, '按域名和指定 Agent 选择出口', '⇄'), metric('活动流', flows.length, `${scoped(list('connections')).filter(isLive).length} 条在线承载连接`, '↗'));
  const agentRows = agents.filter((a) => matches(a.name, a.workspace, userName(a.userId))).sort((a, b) => Number(needsApproval(b)) - Number(needsApproval(a))).slice(0, 5).map((a) => [cell(a.name, workspaceName(a.workspaceId), '⌘'), agentStateBadge(a), caps(agentRoles(a)), button('查看', () => agentDetails(a), 'ghost', true)]);
  const recent = auditRecords().slice(0, 4);
  const recentBody = recent.length ? h('div', 'section-list', recent.map((event) => h('div', 'list-row', h('span', 'object-icon', '≡'), h('div', 'list-body', h('div', 'cell-title', event.action), h('p', '', `${actorName(event.actorId)} · ${resourceName(event.resourceId)}`)), h('span', 'list-time', time(event.at))))) : empty('暂无操作记录', '创建资源、批准与撤销操作会记录在这里。');
  const rows = flows.filter((f) => matches(f.purpose, f.resourceId, f.resource, f.agentId)).slice(0, 8).map((f) => [cell(roleNames[f.purpose] || f.purpose || '业务流', shortID(f.flowId || f.id)), resourceName(f.resourceId || f.resource), agentName(f.agentId || f.principal?.agentId), badge('传输中', 'good'), time(f.expiresAt || f.deadline)]);
  const result = [metrics];
  if (!list('workspaces').length) result.push(notice('从创建工作空间开始，再分配成员、生成注册密钥并连接你的 Agent。'));
  else if (pending.length) result.push(notice(`有 ${pending.length} 个 Agent 等待批准。请先核对其声明的本地服务与出口目标范围。`));
  result.push(h('div', 'grid-two', panel('Agent 状态', '设备身份与实际在线连接分别展示', table(['Agent', '状态', '声明角色', ''], agentRows, empty('还没有 Agent', '生成注册密钥后，在设备上完成 agentd 注册。', canManage() ? button('创建注册密钥', enrollmentForm, 'primary') : null)), button('查看全部 →', () => location.hash = 'agents', 'ghost', true)), panel('最近操作', '资源管理与访问策略变更', recentBody, button('全部日志 →', () => location.hash = 'audit', 'ghost', true))));
  result.push(panel('活动流', '当前正在转发的请求与连接', table(['用途 / 流 ID', '资源', '提供方', '状态', '截止时间'], rows, empty('当前没有活动流', '服务访问或出口请求建立后，对应业务流会显示在这里。'))));
  return result;
}
function renderAgents() {
  const agents = scoped(list('agents')).filter((a) => matches(a.name, a.id, workspaceName(a.workspaceId), userName(a.userId), a.status));
  const rows = agents.map((a) => [cell(a.name, shortID(a.id), '⌘'), workspaceName(a.workspaceId), caps(agentRoles(a)), agentStateBadge(a), time(a.approval?.expiresAt), actions(
    button('查看', () => agentDetails(a), 'secondary', true),
    canManage(a.workspaceId) && needsApproval(a) ? button('审核', () => agentDetails(a), 'primary', true) : null,
    canManage(a.workspaceId) && a.status !== 'revoked' ? button('撤销', () => confirmMutation(`撤销 ${a.name}`, '该 Agent 将失去连接与提供业务的资格。请确认当前服务可以中断。', `/agents/${encodeURIComponent(a.id)}/revoke`, 'POST'), 'danger', true) : null,
  )]);
  return panel('已注册 Agents', `${agents.length} 个设备 / profile`, table(['Agent', '工作空间', '声明能力', '状态', '批准期限', '操作'], rows, empty('还没有注册的 Agent', '注册密钥用于设备首次接入。设备提交期望配置后，会出现在本列表中。', canManage() ? button('创建注册密钥', enrollmentForm, 'primary') : null)));
}
function renderServices() {
  const services = scoped(list('services')).filter((s) => matches(s.name, s.hostname, agentName(s.agentId), workspaceName(s.workspaceId)));
  const rows = services.map((s) => {
    const agent = list('agents').find((a) => a.id === s.agentId);
    const health = !s.enabled ? ['已停用', 'neutral'] : !agent || agentHealth(agent)[1] !== 'good' ? ['提供方离线', 'warn'] : !activeGrants(s.id).length ? ['等待授权', 'warn'] : ['可用', 'good'];
    const controls = !canManageResource('service', s.id) ? '只读' : s.enabled
      ? actions(button('授权', () => grantForm(s, 'service'), 'secondary', true), button('停用', () => confirmMutation(`停用 ${s.name}`, '该服务将停止发布，访问此服务的用户会受到影响。', `/services/${encodeURIComponent(s.id)}`, 'DELETE', '确认停用'), 'danger', true))
      : button('启用', () => enableResource('services', s.id, s.name), 'primary', true);
    return [cell(s.name, workspaceName(s.workspaceId), '◈'), serviceLink(s.hostname), agentName(s.agentId), badge(...health), `${activeGrants(s.id).length} 条有效授权`, controls];
  });
  return [notice('服务源站由 agentd 的本地配置声明。控制台管理发布状态与访问授权，不直接改写设备上的源站地址。'), panel('已发布服务', `${services.length} 个服务 · 分享不会改变资源归属`, table(['服务', '访问地址', '提供方', '状态', '访问范围', '操作'], rows, empty('还没有发布的服务', '在 Agent 的配置中启用 serve 并声明本地服务，注册与批准后即可在这里管理。')))];
}
function serviceLink(hostname) {
  try {
    const host = new URL(`https://${hostname}`);
    if (host.host !== String(hostname).toLowerCase() || host.username || host.password || host.pathname !== '/' || host.search || host.hash) throw new Error();
    const url = new URL(model.data.serverURL || location.origin);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
    url.hostname = host.hostname; url.pathname = '/'; url.search = ''; url.hash = ''; url.username = ''; url.password = '';
    const link = h('a', 'resource-link', url.host, ' ↗'); link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; return link;
  } catch { return h('span', 'cell-mono', hostname || '尚未分配'); }
}
function renderEgress() {
  const routes = scoped(list('egressRoutes')).filter((r) => matches(r.name, ruleText(r.rule), agentName(r.agentId), workspaceName(r.workspaceId)));
  return [notice('域名路由与使用授权分别管理。路由存在并不自动授予访问权；出口离线时不会改走其他设备。'), panel('域名出口规则', `${routes.length} 条规则 · 目标网站 TLS 保持端到端`, table(['规则 / 域名', '指定出口', '优先级', '状态', '授权', '操作'], routes.map((r) => {
    const agent = list('agents').find((a) => a.id === r.agentId);
    const health = !r.enabled ? ['已停用', 'neutral'] : agent ? agentHealth(agent) : ['出口不可用', 'warn'];
    const controls = !canManage(r.workspaceId) ? '只读' : r.enabled
      ? actions(button('授权', () => grantForm(r, 'egress'), 'secondary', true), button('停用', () => confirmMutation(`停用 ${r.name}`, '该规则将暂停选择出口。依赖此规则的访问会受到影响，可在之后重新启用。', `/egress-routes/${encodeURIComponent(r.id)}`, 'DELETE', '确认停用'), 'danger', true))
      : button('启用', () => enableResource('egress-routes', r.id, r.name), 'primary', true);
    return [cell(r.name, ruleText(r.rule), '⇄'), cell(agentName(r.agentId), workspaceName(r.workspaceId)), String(r.priority ?? 0), badge(...health), `${activeGrants(r.id).length} 条有效`, controls];
  }), empty('还没有出口路由', '先批准提供出口能力的 Agent，再创建域名到该 Agent 的规则。', canManage() ? button('创建出口路由', egressForm, 'primary') : null)))];
}
function renderAccess() {
  const labels = [['grants', '访问授权'], ['keys', '注册密钥'], ['members', '成员'], ['workspaces', '工作空间'], ['users', '用户']];
  const tabs = h('div', 'tabs'); tabs.setAttribute('role', 'tablist'); tabs.setAttribute('aria-label', '权限管理分类');
  for (const [key, label] of labels) {
    const tab = h('button', `tab${model.tab === key ? ' active' : ''}`, label); tab.type = 'button'; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-selected', String(model.tab === key));
    tab.addEventListener('click', () => { model.tab = key; model.query = ''; $('#search').value = ''; render(); }); tabs.append(tab);
  }
  return [tabs, {grants: renderGrants, keys: renderKeys, members: renderMembers, workspaces: renderWorkspaces, users: renderUsers}[model.tab]()];
}
function renderGrants() {
  const grants = scoped(list('grants')).filter((g) => matches(resourceName(g.resourceId), subjectName(g), workspaceName(g.workspaceId)));
  return panel('访问授权', '多条有效授权按并集生效；登录会话不会延长授权期限', table(['资源', '授权对象', '开始时间', '截止时间', '状态', '操作'], grants.map((g) => [cell(resourceName(g.resourceId), `${g.resourceType === 'service' ? 'Web 服务' : 'TLS 出口'} · ${workspaceName(g.workspaceId)}`), subjectName(g), time(g.startsAt), time(g.expiresAt), badge(...grantHealth(g)), !g.revoked && canManage(g.workspaceId) ? button('撤销', () => confirmMutation('撤销访问授权', '将移除这一授权来源；访客仍命中其他有效授权时，可以继续访问。', `/grants/${encodeURIComponent(g.id)}`, 'DELETE'), 'danger', true) : '—']), empty('还没有访问授权', '选择服务或出口规则，为指定用户、工作空间成员或匿名访客设置有效期限。', canManage() ? button('添加授权', () => grantForm(), 'primary') : null)));
}
function renderKeys() {
  const keys = scoped(list('enrollmentKeys')).filter((k) => matches(k.id, userName(k.userId), workspaceName(k.workspaceId), k.roles));
  return panel('设备注册密钥', '完整令牌仅在创建成功时显示一次', table(['密钥 / 工作空间', '注册用户', '允许角色', '使用情况', '截止时间', '状态', '操作'], keys.map((k) => {
    const health = k.revoked ? ['已撤销', 'neutral'] : date(k.expiresAt) <= new Date() ? ['已到期', 'neutral'] : k.uses >= k.maxUses ? ['已用尽', 'neutral'] : ['可使用', 'good'];
    return [cell(shortID(k.id), workspaceName(k.workspaceId)), userName(k.userId), caps((k.roles || []).map((r) => roleNames[r] || r)), `${k.uses || 0} / ${k.maxUses}`, time(k.expiresAt), badge(...health), !k.revoked && canManage(k.workspaceId) ? button('撤销', () => confirmMutation('撤销注册密钥', '此密钥将不能用于后续注册。已经注册的 Agent 需在设备页面单独管理。', `/enrollment-keys/${encodeURIComponent(k.id)}`, 'DELETE'), 'danger', true) : '—'];
  }), empty('还没有注册密钥', '为指定工作空间与用户创建限时、限次的设备注册密钥。', canManage() ? button('创建注册密钥', enrollmentForm, 'primary') : null)));
}
function renderMembers() {
  const members = scoped(list('memberships')).filter((m) => matches(userName(m.userId), workspaceName(m.workspaceId), roleNames[m.role]));
  return panel('工作空间成员', '同一用户在不同 Workspace 的角色相互独立', table(['用户', '工作空间', '角色'], members.map((m) => [cell(userName(m.userId), shortID(m.userId), '♧'), workspaceName(m.workspaceId), badge(roleNames[m.role] || m.role, m.role === 'owner' ? 'good' : 'neutral')]), empty('还没有成员记录', '将实例用户添加到工作空间，并分配适当的管理角色。', canManage() ? button('添加成员', membershipForm, 'primary') : null)));
}
function renderWorkspaces() {
  const workspaces = list('workspaces').filter((w) => (!model.workspace || w.id === model.workspace) && matches(w.name, w.id));
  return panel('工作空间', '资源归属、设备注册与访问策略的管理边界', table(['工作空间', '成员', 'Agents', '服务', '创建时间'], workspaces.map((w) => [cell(w.name, shortID(w.id), '▦'), String(list('memberships').filter((m) => m.workspaceId === w.id).length), String(list('agents').filter((a) => a.workspaceId === w.id).length), String(list('services').filter((s) => s.workspaceId === w.id).length), time(w.createdAt)]), empty('还没有工作空间', '创建第一个 Workspace，开始组织设备、服务与成员。', model.user.admin ? button('创建 Workspace', workspaceForm, 'primary') : null)));
}
function renderUsers() {
  const users = list('users').filter((u) => (!model.workspace || list('memberships').some((m) => m.workspaceId === model.workspace && m.userId === u.id)) && matches(u.name, u.id));
  return panel('实例用户', '用户可以加入多个工作空间；新令牌仅在签发成功时显示一次', table(['用户', '身份', '工作空间', '状态', '创建时间', '操作'], users.map((u) => [cell(u.name, shortID(u.id), '♧'), u.admin ? badge('实例管理员', 'info') : badge('用户'), list('memberships').filter((m) => m.userId === u.id).map((m) => workspaceName(m.workspaceId)).join('、') || '未加入', u.disabled ? badge('已停用', 'neutral') : badge('有效', 'good'), time(u.createdAt), !u.disabled && (model.user.admin || u.id === model.user.id) ? button('更新令牌', () => userTokenForm(u), 'secondary', true) : '—']), empty('没有匹配的用户', '用户是实例级身份；切换到全部 Workspace 可查看尚未加入成员组的用户。', model.user.admin ? button('创建用户', userForm, 'primary') : null)));
}
function auditRecords() {
  return list('audit').filter((event) => {
    if (!matches(event.action, event.detail, actorName(event.actorId), resourceName(event.resourceId))) return false;
    if (!model.workspace) return true;
    if (event.workspaceId) return event.workspaceId === model.workspace;
    if (event.resourceId === model.workspace) return true;
    return [...list('agents'), ...list('services'), ...list('egressRoutes'), ...list('grants'), ...list('enrollmentKeys')].some((r) => r.id === event.resourceId && r.workspaceId === model.workspace);
  }).sort((a, b) => (date(b.at)?.getTime() || 0) - (date(a.at)?.getTime() || 0));
}
function renderAudit() {
  const events = auditRecords();
  return panel('操作记录', `${events.length} 条记录${model.workspace ? ' · 实例级记录请切换到全部 Workspace' : ''}`, table(['时间', '操作者', '操作', '资源', '详情'], events.map((event) => [h('span', 'cell-mono', fullTime(event.at)), actorName(event.actorId), cell(event.action), cell(resourceName(event.resourceId), shortID(event.resourceId)), h('div', 'wrap muted', typeof event.detail === 'string' ? event.detail : JSON.stringify(event.detail || '—'))]), empty('暂无审计记录', '资源创建、批准、授权与撤销操作会出现在这里。')));
}

let modalCleanup = null;
let modalBusy = false;
function openModal(title, description = '') {
  if (modalCleanup) { modalCleanup(); modalCleanup = null; }
  $('#modal-title').textContent = title;
  $('#modal-body').replaceChildren();
  if (description) $('#modal-body').append(h('p', 'modal-description', description));
  if (!$('#modal').open) $('#modal').showModal();
  return $('#modal-body');
}
function closeModal() { if (!modalBusy) $('#modal').close(); }
$('#modal').addEventListener('cancel', (event) => { if (modalBusy) event.preventDefault(); });
$('#modal').addEventListener('close', () => { if (modalCleanup) modalCleanup(); modalCleanup = null; $('#modal-body').replaceChildren(); });
$('#modal-close').addEventListener('click', closeModal);
function field(label, control, hint = '') {
  const id = `field-${++field.counter}`; control.id = id;
  const title = h('label', 'field-label', label); title.htmlFor = id;
  return h('div', 'field', title, control, hint ? h('span', 'field-hint', hint) : null);
}
field.counter = 0;
function input(type = 'text', value = '', required = true) {
  const control = h('input'); control.type = type; control.value = value; control.required = required; control.autocomplete = 'off';
  if (type === 'text') control.maxLength = 200;
  return control;
}
function select(options, value = '') {
  const control = h('select'); control.required = true;
  for (const [key, label] of options) control.add(new Option(label, key));
  if (value) control.value = value;
  return control;
}
function workspaceSelect(value = '', permission = canManage) {
  return select([['', '请选择工作空间'], ...list('workspaces').filter((w) => permission(w.id)).map((w) => [w.id, w.name])], value || model.workspace || (list('workspaces').length === 1 ? list('workspaces')[0].id : ''));
}
function localTime(hours = 0) {
  const d = new Date(Date.now() + hours * 3600000); d.setSeconds(0, 0);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function iso(control) { const value = date(control.value); if (!value) throw new Error('请输入有效的日期与时间。'); return value.toISOString(); }
function formDialog(title, description, fields, submit, options = {}) {
  const body = openModal(title, description);
  const form = h('form'); const error = h('div', 'form-error'); error.hidden = true; error.setAttribute('role', 'alert');
  const primary = h('button', `button ${options.danger ? 'danger' : 'primary'}`, options.label || '保存'); primary.type = 'submit';
  form.append(...fields, error, h('div', 'form-actions', button('取消', closeModal, 'secondary'), primary)); body.append(form);
  let busy = false;
  form.addEventListener('submit', async (event) => {
    event.preventDefault(); if (busy) return; busy = true; modalBusy = true; error.hidden = true; primary.disabled = true; primary.textContent = '正在提交…'; $('#modal-close').disabled = true;
    try {
      const result = await submit();
      await refresh(true);
      if (!model.user) return;
      modalBusy = false;
      if (options.success) options.success(result); else { closeModal(); toast(options.message || '操作已完成'); }
    } catch (e) { error.textContent = e.message; error.hidden = false; }
    finally { busy = false; modalBusy = false; $('#modal-close').disabled = false; primary.disabled = false; primary.textContent = options.label || '保存'; }
  });
  queueMicrotask(() => form.querySelector('input, select, button')?.focus());
  return form;
}
function confirmMutation(title, description, path, method, label = '确认撤销') {
  formDialog(title, description, [], () => api(path, {method}), {label, danger: true});
}
function enableResource(type, id, name) {
  formDialog(`启用 ${name}`, '恢复该资源的启用状态；实际访问仍需提供方在线并命中当前有效授权。', [], () => api(`/${type}/${encodeURIComponent(id)}/enable`, {method: 'POST'}), {label: '确认启用', message: '资源已启用'});
}
function workspaceForm() {
  const name = input(); name.placeholder = '例如 design-team';
  formDialog('创建工作空间', '为一组成员、设备和服务建立独立的管理空间。', [field('工作空间名称', name)], () => api('/workspaces', {method: 'POST', body: {name: name.value.trim()}}), {label: '创建 Workspace'});
}
function userForm() {
  const name = input(); name.placeholder = '用户名称';
  formDialog('创建用户', '创建实例用户并生成一次性显示的登录令牌。之后可以将用户添加到工作空间。', [field('用户名称', name)], () => api('/users', {method: 'POST', body: {name: name.value.trim()}}), {label: '创建用户', success: (result) => secretModal('用户已创建', result.token, `用户：${result.user?.name || name.value}`, 'agentd-user-token.txt')});
}
function userTokenForm(user) {
  formDialog(`更新 ${user.name} 的令牌`, '重签后旧用户 Bearer 令牌立即失效，请同步更新使用它的调用方。已有浏览器会话仍按原截止时间有效；新令牌仅显示一次。', [], () => api(`/users/${encodeURIComponent(user.id)}/token`, {method: 'POST'}), {label: '确认更新令牌', success: (result) => secretModal('新用户令牌已签发', result.token, `用户：${user.name}`, 'agentd-user-token.txt')});
}
function membershipForm() {
  const workspace = workspaceSelect(), user = select([['', '请选择用户'], ...list('users').filter((u) => !u.disabled).map((u) => [u.id, u.name])]);
  const role = select(['developer', 'guest', 'maintainer', 'owner'].map((r) => [r, roleNames[r]]));
  formDialog('添加工作空间成员', '成员角色控制管理权限；使用服务与出口仍需匹配访问授权。', [field('工作空间', workspace), field('用户', user), field('角色', role)], () => api('/memberships', {method: 'POST', body: {workspaceId: workspace.value, userId: user.value, role: role.value}}), {label: '添加成员'});
}
function enrollmentForm() {
  const workspace = workspaceSelect('', canEnroll), user = select([['', '请选择注册用户']]);
  const updateUsers = () => {
    const existing = user.value; user.replaceChildren(); user.add(new Option('请选择注册用户', ''));
    const ids = new Set(list('memberships').filter((m) => m.workspaceId === workspace.value).map((m) => m.userId));
    for (const u of list('users').filter((u) => ids.has(u.id) && !u.disabled && (canManage(workspace.value) || u.id === model.user.id))) user.add(new Option(u.name, u.id));
    if (ids.has(existing)) user.value = existing; else if (ids.has(model.user.id)) user.value = model.user.id;
  };
  workspace.addEventListener('change', updateUsers); updateUsers();
  const checks = ['ingress', 'serve', 'egress'].map((role) => { const box = input('checkbox', role, false); box.checked = role === 'ingress'; return {role, box}; });
  const roles = h('div', 'field', h('div', 'field-label', '允许注册的角色'), h('div', 'checkbox-row', checks.map(({role, box}) => h('label', 'checkbox-label', box, roleNames[role]))));
  const auto = input('checkbox', '', false);
  const updateRoles = () => {
    const guest = list('memberships').some((m) => m.workspaceId === workspace.value && m.userId === user.value && m.role === 'guest');
    for (const {role, box} of checks) { box.disabled = guest && role !== 'ingress'; if (box.disabled) box.checked = false; }
    auto.disabled = !canManage(workspace.value); if (auto.disabled) auto.checked = false;
  };
  workspace.addEventListener('change', updateRoles); user.addEventListener('change', updateRoles); updateRoles();
  const uses = input('number', '1'); uses.min = '1'; uses.max = '1000';
  const expires = input('datetime-local', localTime(24));
  formDialog('创建设备注册密钥', '密钥仅允许在指定范围内注册设备，不授予对其他服务的访问权。', [field('工作空间', workspace), field('注册用户', user, '用户需要先加入所选工作空间。'), roles, h('div', 'split-form', field('最多使用次数', uses), field('失效时间', expires)), h('div', 'field', h('label', 'checkbox-label', auto, '自动批准声明范围内的能力'), h('span', 'field-hint', '未勾选时，设备注册后需要管理员审核。'))], () => {
    const roles = checks.filter(({box}) => box.checked).map(({role}) => role);
    if (!roles.length) throw new Error('至少选择一个允许注册的角色。');
    if (date(expires.value) <= new Date()) throw new Error('失效时间必须晚于当前时间。');
    return api('/enrollment-keys', {method: 'POST', body: {workspaceId: workspace.value, userId: user.value, roles, autoApprove: auto.checked, maxUses: Number(uses.value), expiresAt: iso(expires)}});
  }, {label: '生成注册密钥', success: (result) => secretModal('注册密钥已生成', result.token, `${workspaceName(workspace.value)} · ${userName(user.value)}`, 'agentd-enrollment-key.txt')});
}
function egressForm() {
  const workspace = workspaceSelect(), agent = select([['', '请选择出口 Agent']]);
  const capabilityHint = h('div', 'notice');
  const updateHint = () => { const a = list('agents').find((a) => a.id === agent.value); capabilityHint.textContent = a ? `该 Agent 声明的允许目标：${(a.desired?.egress?.allow || []).map(ruleText).join('；') || '无'}` : '选择已获准的出口 Agent。目标范围还会经过提供方本地校验。'; };
  const updateAgents = () => { agent.replaceChildren(); agent.add(new Option('请选择出口 Agent', '')); for (const a of list('agents').filter((a) => a.workspaceId === workspace.value && !['pending', 'pending_approval', 'revoked', 'disabled'].includes(a.status) && a.desired?.egress?.enabled)) agent.add(new Option(a.name, a.id)); updateHint(); };
  workspace.addEventListener('change', updateAgents); agent.addEventListener('change', updateHint); updateAgents();
  const name = input(), domain = input(), match = select([['exact', '精确域名'], ['suffix', '域名及其子域']]), ports = input('text', '443'), priority = input('number', '100');
  name.placeholder = '例如 company-oa'; domain.placeholder = '例如 oa.example.com'; priority.min = '0'; priority.max = '1000000';
  formDialog('创建出口路由', '将一个获准的 TLS 域名范围绑定到指定 Agent。创建后还需添加使用授权。', [h('div', 'split-form', field('工作空间', workspace), field('出口 Agent', agent)), capabilityHint, field('规则名称', name), h('div', 'split-form', field('匹配方式', match), field('目标域名', domain)), h('div', 'split-form', field('TCP 端口', ports, '多个端口以逗号分隔。'), field('优先级', priority)), notice('协议：TCP 上的 TLS。不会允许任意明文 TCP 或 UDP 流量。')], () => {
    const values = ports.value.split(/[,，]/).map((p) => Number(p.trim()));
    if (!values.length || values.some((p) => !Number.isInteger(p) || p < 1 || p > 65535) || new Set(values).size !== values.length) throw new Error('端口应为 1–65535 的整数，且不能重复。');
    return api('/egress-routes', {method: 'POST', body: {workspaceId: workspace.value, agentId: agent.value, name: name.value.trim(), rule: {domain: {[match.value]: domain.value.trim()}, ports: values, protocol: 'tls'}, priority: Number(priority.value), enabled: true}});
  }, {label: '创建路由'});
}
function grantForm(resource, resourceType) {
  const workspace = workspaceSelect(resource?.workspaceId, canGrantInWorkspace), target = select([['', '请选择资源']]);
  const subjectType = select([['user', '指定用户'], ['workspace', 'Workspace 成员'], ['anonymous', '匿名访问者']]);
  const subject = select([['', '请选择授权对象']]);
  const updateSubject = () => {
    const existing = subject.value; subject.replaceChildren(); subject.disabled = subjectType.value === 'anonymous'; subject.required = !subject.disabled;
    if (subject.disabled) { subject.add(new Option('任何人，无需登录', '')); return; }
    subject.add(new Option('请选择授权对象', ''));
    const egress = target.value.startsWith('egress:') || !canManage(workspace.value);
    const members = new Set(list('memberships').filter((m) => m.workspaceId === workspace.value).map((m) => m.userId));
    const candidates = list(subjectType.value === 'user' ? 'users' : 'workspaces').filter((item) => !item.disabled && (!egress || (subjectType.value === 'user' ? members.has(item.id) : item.id === workspace.value)));
    for (const item of candidates) subject.add(new Option(item.name, item.id));
    if ([...subject.options].some((o) => o.value === existing)) subject.value = existing;
  };
  const updateResourceType = () => {
    const egress = target.value.startsWith('egress:') || !canManage(workspace.value);
    const option = [...subjectType.options].find((o) => o.value === 'anonymous'); option.disabled = egress;
    if (egress && subjectType.value === 'anonymous') subjectType.value = 'user';
    updateSubject();
  };
  const updateTargets = () => {
    target.replaceChildren(); target.add(new Option('请选择资源', ''));
    for (const [type, name] of [['service', 'services'], ['egress', 'egressRoutes']]) for (const r of list(name).filter((r) => r.workspaceId === workspace.value && r.enabled && canManageResource(type, r.id))) target.add(new Option(`${type === 'service' ? '服务' : '出口'} · ${r.name}`, `${type}:${r.id}`));
    if (resource) target.value = `${resourceType}:${resource.id}`;
    updateResourceType();
  };
  workspace.addEventListener('change', updateTargets); target.addEventListener('change', updateResourceType); subjectType.addEventListener('change', updateSubject); updateTargets();
  const starts = input('datetime-local', localTime()), expires = input('datetime-local', localTime(24));
  formDialog('添加访问授权', '授权只适用于所选资源。Web 服务可分享给其他工作空间，出口仅允许当前工作空间主体。', [field('资源所属工作空间', workspace), field('服务或出口规则', target), h('div', 'split-form', field('授权对象类型', subjectType), field('授权对象', subject)), h('div', 'split-form', field('开始时间', starts), field('截止时间', expires))], () => {
    if (date(expires.value) <= date(starts.value)) throw new Error('截止时间必须晚于开始时间。');
    const split = target.value.indexOf(':');
    return api('/grants', {method: 'POST', body: {workspaceId: workspace.value, resourceType: target.value.slice(0, split), resourceId: target.value.slice(split + 1), subjectType: subjectType.value, subjectId: subjectType.value === 'anonymous' ? '' : subject.value, startsAt: iso(starts), expiresAt: iso(expires)}});
  }, {label: '添加授权'});
}
function agentDetails(agent) {
  const desired = agent.desired || {};
  const sections = [h('div', 'detail-row', h('strong', '', `${agent.name} · ${workspaceName(agent.workspaceId)}`), h('span', '', `注册用户：${userName(agent.userId)} · ${agentHealth(agent)[0]}`)), h('div', 'field', h('div', 'field-label', '声明角色'), caps(agentRoles(agent)))];
  if (desired.serve?.enabled) sections.push(h('h3', '', '本地服务'), h('div', 'detail-list', (desired.serve.services || []).map((s) => h('div', 'detail-row', h('strong', '', s.name), h('span', '', s.origin)))));
  if (desired.egress?.enabled) {
    sections.push(h('h3', '', '允许的出口目标'), h('div', 'detail-list', (desired.egress.allow || []).length ? desired.egress.allow.map((r) => h('div', 'detail-row', ruleText(r))) : notice('未声明允许目标。')));
    if (desired.egress.deny?.length) sections.push(h('h3', '', '明确拒绝'), h('div', 'detail-list', desired.egress.deny.map((r) => h('div', 'detail-row danger-text', ruleText(r)))));
  }
  if (desired.ingress?.enabled) sections.push(h('h3', '', '本机访问范围'), h('div', 'detail-list', (desired.ingress.routes || []).map((r) => h('div', 'detail-row', ruleText(r)))));
  if (needsApproval(agent) && canManage(agent.workspaceId)) {
    formDialog('审核 Agent 能力', '请核对声明的服务源站和出口范围。批准仅允许该设备提供这些能力，不会自动授予其他用户访问权。', sections, () => api(`/agents/${encodeURIComponent(agent.id)}/approve`, {method: 'POST'}), {label: '批准声明的能力', message: 'Agent 已批准'});
  } else {
    const body = openModal('Agent 详情', `注册 ID：${agent.id}`); body.append(...sections, h('div', 'detail-row', h('strong', '', '当前批准'), h('span', '', `Revision ${agent.approval?.revision || '—'} · 截止 ${fullTime(agent.approval?.expiresAt)}`)), h('div', 'form-actions', button('关闭', closeModal, 'primary')));
  }
}
function secretModal(title, token, subtitle, filename) {
  const body = openModal(title, subtitle);
  if (typeof token !== 'string' || !token) { body.append(notice('服务器没有返回令牌。请联系管理员核查，不要重复创建同名资源。')); return; }
  let secret = token;
  const display = h('textarea', 'token-box'); display.readOnly = true; display.value = secret; display.setAttribute('aria-label', '一次性显示的令牌'); display.spellcheck = false;
  body.append(notice('完整令牌仅显示这一次。关闭后无法再次查看，请妥善保存并仅交给指定使用者。'), display, h('div', 'token-actions', button('复制令牌', async () => { try { await navigator.clipboard.writeText(secret); toast('令牌已复制'); } catch { display.focus(); display.select(); toast('无法自动复制，请手动复制选中的令牌'); } }, 'primary'), button('下载令牌', () => { const url = URL.createObjectURL(new Blob([secret + '\n'], {type: 'text/plain;charset=utf-8'})); const link = h('a'); link.href = url; link.download = filename; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); })), h('div', 'form-actions', button('已保存，关闭', closeModal, 'secondary')));
  modalCleanup = () => { secret = ''; display.value = ''; };
}
let toastTimer;
function toast(message) { clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').hidden = false; toastTimer = setTimeout(() => { $('#toast').hidden = true; $('#toast').textContent = ''; }, 4000); }

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const token = $('#login-token').value.trim(); if (!token) return;
  $('#login-submit').disabled = true; $('#login-submit').textContent = '正在登录…'; $('#login-error').hidden = true;
  try { const result = await api('/login', {method: 'POST', body: {token}}); $('#login-token').value = ''; await authenticated(result); }
  catch (error) { $('#login-error').textContent = error.message; $('#login-error').hidden = false; }
  finally { $('#login-token').value = ''; $('#login-submit').disabled = false; $('#login-submit').textContent = '登录 →'; }
});
$('#logout').addEventListener('click', async () => {
  $('#logout').disabled = true;
  try { await api('/logout', {method: 'POST'}); showLogin(); }
  catch (error) { toast(error.message); }
  finally { $('#logout').disabled = false; }
});
$('#refresh').addEventListener('click', () => refresh());
$('#workspace-select').addEventListener('change', (event) => { model.workspace = event.target.value; model.query = ''; $('#search').value = ''; render(); });
$('#search').addEventListener('input', (event) => { model.query = event.target.value.trim().toLocaleLowerCase(); render(); });
window.addEventListener('hashchange', setPage);
document.addEventListener('visibilitychange', () => { if (!document.hidden && model.user) refresh(true); });
setInterval(() => { if (!document.hidden && model.user && !$('#modal').open) refresh(true); }, 10000);
setPage();
try { const result = await api('/me'); await authenticated(result); }
catch { showLogin(); }
