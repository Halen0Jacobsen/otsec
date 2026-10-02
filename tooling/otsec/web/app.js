const $ = id => document.getElementById(id);
const el = (tag, text, className) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (className) n.className = className; return n; };
let data, view = 'overview';
const toolName = id => data?.tools.find(t => t.id === id)?.name || id;
const scoped = rows => rows.filter(row => !$('scope').value || row.environment === $('scope').value || row.name === $('scope').value);
const badge = (text, style = '') => el('span', text, `tag ${style}`);
const date = value => new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString();
function empty(root, title, description) { const box = el('div', undefined, 'empty'); box.append(el('h3', title), el('p', description)); root.append(box); }
function table(id, rows, fields, title = 'No records yet', description = 'Import evidence for this environment to populate this view.') {
  const root = $(id); root.replaceChildren();
  if (!rows.length) { empty(root, title, description); return; }
  const table = el('table'), head = el('thead'), heading = el('tr'), body = el('tbody');
  fields.forEach(([name]) => { const th = el('th', name); th.scope = 'col'; heading.append(th); }); head.append(heading);
  rows.forEach(row => { const tr = el('tr'); fields.forEach(([, field]) => { const td = el('td'); const value = typeof field === 'function' ? field(row) : row[field]; if (value instanceof Node) td.append(value); else td.textContent = value ?? ''; tr.append(td); }); body.append(tr); });
  table.append(head, body); root.append(table);
}
function button(text, handler, className = 'secondary') { const b = el('button', text, className); b.type = 'button'; b.addEventListener('click', handler); return b; }
function go(next) {
  view = next;
  const titles = {overview:['Overview','Security overview','Your environments, evidence and next actions in one place.'],monitor:['Environments','Environments & assets','Define operating boundaries and review passive network evidence.'],findings:['Findings','Application findings','Review imported tool results and recommended fixes.'],tools:['Integrations','Tool integrations','Connect your workflow to open source network and Java security tools.'],activity:['Plans & audit','Plans & audit','Review action proposals, policy decisions and operator history.']};
  $('view-label').textContent = titles[next][0];
  $('view-title').textContent = titles[next][1];
  $('view-description').textContent = titles[next][2];
  document.querySelectorAll('[data-page]').forEach(page => { page.hidden = page.dataset.page !== next; });
  document.querySelectorAll('.navigation [data-view]').forEach(b => { if (b.dataset.view === next) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  window.scrollTo({top: 0, behavior: 'instant'});
}
function options(select, choices, placeholder) {
  const current = select.value; select.replaceChildren();
  if (placeholder) select.append(new Option(placeholder, ''));
  choices.forEach(([label, value]) => select.append(new Option(label, value)));
  if ([...select.options].some(o => o.value === current)) select.value = current;
}
function openDialog(id, tool) {
  if (!data) return;
  const dialog = $(id);
  dialog.querySelectorAll('.form-error').forEach(p => { p.textContent = ''; });
  document.querySelectorAll('.environment-select').forEach(select => { if ($('scope').value) select.value = $('scope').value; });
  if (id === 'import-dialog') { if (tool) $('import-tool').value = tool; importHelp(); }
  dialog.showModal();
}
function details(title, entries, links = []) {
  $('detail-title').textContent = title;
  const root = $('detail-content'); root.replaceChildren();
  entries.forEach(([name, value]) => { const block = el('div', undefined, 'detail-block'); block.append(el('h3', name), el('p', value || 'Not supplied by the source report.')); root.append(block); });
  links.filter(([, url]) => /^https:\/\//.test(url)).forEach(([name, url]) => { const p = el('p'), link = el('a', name); link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer'; p.append(link); root.append(p); });
  $('detail-dialog').showModal();
}
function importHelp() {
  const tool = data.tools.find(t => t.id === $('import-tool').value);
  const zeek = tool?.id === 'zeek';
  $('import-help').textContent = zeek ? 'Zeek JSONL conn.log. Each connection must include an endpoint within the environment CIDR.' : `${tool?.report_format || ''} report. ${tool?.setup || ''}`;
  $('application-label').hidden = zeek;
  $('import-form').elements.application.required = !zeek;
}
function renderFindings() {
  if (!data) return;
  const term = $('finding-search').value.toLowerCase();
  const rows = scoped(data.findings).filter(row => (!$('severity').value || row.severity === $('severity').value) && (!$('finding-tool').value || row.tool === $('finding-tool').value) && [row.title, row.application, row.rule, row.resource].join(' ').toLowerCase().includes(term));
  const rank = {CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5}; rows.sort((a,b) => rank[a.severity] - rank[b.severity]);
  $('finding-count').textContent = `${rows.length} shown from the latest 500 findings · ${data.counts.findings} stored across all environments`;
  table('finding-table', rows, [['Severity', row => badge(row.severity, row.severity.toLowerCase())], ['Finding', row => button(row.title, () => details(row.title, [['Severity / source', `${row.severity} / ${toolName(row.tool)}`], ['Environment / application', `${row.environment} / ${row.application}`], ['Resource', row.resource], ['Rule', row.rule], ['Description', row.description], ['Recommended action', row.solution], ['Imported', date(row.imported_at)]]), 'text-button')], ['Application', 'application'], ['Environment', 'environment'], ['Tool', row => toolName(row.tool)]], 'No matching findings', 'Import a supported report, or clear the severity, tool and search filters. Empty results do not establish that an application is secure.');
}
function renderTools() {
  if (!data) return;
  const root = $('tool-list'); root.replaceChildren();
  const term = $('tool-search').value.toLowerCase();
  const tools = data.tools.filter(t => (!$('tool-category').value || t.category === $('tool-category').value) && [t.name,t.description,t.capability].join(' ').toLowerCase().includes(term));
  tools.forEach(tool => {
    const row = el('article', undefined, 'integration-row'), identity = el('div'), summary = el('div'), state = el('div'), actions = el('div', undefined, 'integration-actions');
    const ready = tool.status === 'report-import' || tool.id === 'zeek';
    identity.append(el('h3', tool.name), el('span', tool.category, 'caption'));
    summary.append(el('p', tool.description || ({zeek:'Passive network observations and asset discovery.',malcolm:'Network traffic analysis and investigation.',arkime:'Packet capture search and investigation.',wazuh:'Endpoint security alerts and monitoring.',custom:'Your own remediation proposals.'}[tool.id] || tool.capability)));
    state.append(badge(ready ? 'Import ready' : tool.status === 'plan-only' ? 'Proposals only' : 'Planned', ready ? 'ready' : ''), el('p', tool.report_format || (tool.id === 'zeek' ? 'JSONL connections' : 'Connector pending'), 'caption'));
    actions.append(button('Setup & details', () => details(tool.name, [['Purpose', tool.description || tool.capability], ['Supported input', tool.report_format || (tool.id === 'zeek' ? 'Zeek JSONL conn.log' : 'No report importer yet')], ['Setup', tool.setup || (tool.id === 'zeek' ? 'Export JSON-format conn.log from your Zeek sensor and import the file. Sensor management remains external.' : 'This connector is planned. No external service connection is configured.')], ['Execution', 'External tools run separately. This workspace imports evidence and creates proposals.']], [['Official documentation', tool.docs], ['Repository', tool.repository]]), 'quiet'));
    if (ready) actions.append(button('Import', () => openDialog('import-dialog', tool.id)));
    row.append(identity, summary, state, actions); root.append(row);
  });
  if (!tools.length) empty(root, 'No matching integrations', 'Clear the search or select another category.');
}
function render() {
  options($('scope'), data.environments.map(e => [e.name,e.name]), 'All environments');
  document.querySelectorAll('.environment-select').forEach(select => options(select, data.environments.map(e => [e.name,e.name]), 'Choose an environment'));
  options($('import-tool'), data.tools.filter(t => t.status === 'report-import' || t.id === 'zeek').map(t => [t.name,t.id]));
  options($('finding-tool'), data.tools.filter(t => t.status === 'report-import').map(t => [t.name,t.id]), 'All tools');
  const metrics = $('metrics'); metrics.replaceChildren();
  const isFiltered = !!$('scope').value;
  [['Environments', scoped(data.environments).length, 'Separate operating policies'], ['Observed assets', isFiltered ? scoped(data.assets).length : data.counts.assets, isFiltered ? 'Within loaded inventory (up to 500)' : 'Endpoints within configured scopes'], ['Security findings', isFiltered ? scoped(data.findings).length : data.counts.findings, isFiltered ? 'Within latest 500 findings' : 'Imported evidence, review required'], ['Action proposals', isFiltered ? scoped(data.plans).length : data.counts.plans, isFiltered ? 'Within latest 100 proposals' : 'No actions executed']].forEach(([label,count,caption]) => { const card = el('article', undefined,'metric'); card.append(el('span',label),el('strong',count),el('span',caption,'caption')); metrics.append(card); });
  const root = $('environment-list'); root.replaceChildren();
  scoped(data.environments).forEach(env => { const card = el('article', undefined, 'environment'); card.append(badge(env.mode === 'production' ? 'PRODUCTION' : 'LAB',env.mode),el('h3',env.name),el('p',env.cidr,'mono'),el('p',env.mode === 'production' ? 'Passive evidence imports allowed. Active scan proposals blocked by policy.' : 'Passive evidence imports and scan proposals allowed. Execution is not connected.')); root.append(card); });
  if (!root.children.length) empty(root,'No environments yet','Use Add environment to define your first network scope.');
  table('recent-imports', scoped(data.report_imports), [['Imported',r=>date(r.imported_at)],['Tool',r=>toolName(r.tool)],['Application','application'],['Environment','environment'],['New findings','findings'],['Duplicates','duplicates']], 'Bring your tools into the workspace', 'Import a ZAP, Dependency-Check, SpotBugs, Find Security Bugs, or SonarQube report to review it here.');
  table('asset-table', scoped(data.assets), [['Address','ip'],['Environment','environment'],['Last observed',r=>date(r.last_seen)]]);
  table('observation-table', scoped(data.observations), [['Environment','environment'],['Originator','src'],['Responder','dst'],['Port','port'],['Service','service'],['Boundary',r=>badge(r.external ? 'External · review' : 'In scope',r.external?'medium':'')]]);
  table('plan-table', scoped(data.plans), [['Environment','environment'],['Tool',r=>toolName(r.tool)],['Action','action'],['Target','target'],['Decision',r=>badge(r.state === 'blocked-by-policy' ? 'Blocked by policy' : 'Proposed',r.state === 'blocked-by-policy'?'medium':'')]],'No proposals yet','Use Create proposal to prepare an action. Production scans are blocked.');
  const auditRows = data.audit.filter(row => !isFiltered || row.resource === data.environments.find(e => e.name === $('scope').value)?.id || scoped(data.plans).some(p => p.id === row.resource) || scoped(data.report_imports).some(r => r.id === row.resource));
  table('audit-table', auditRows,[['Time',r=>date(r.timestamp)],['Actor','actor'],['Action','action'],['Resource','resource'],['Result','result']],'No matching audit records','Only the latest 100 events are loaded. Environment filtering matches the currently loaded plans and imports.');
  renderFindings(); renderTools();
}
async function refresh() {
  try { const response = await fetch('/api/status'); if (!response.ok) throw new Error(); data = await response.json(); render(); $('status').textContent = `Updated ${new Date().toLocaleTimeString()} · local operator`; }
  catch { $('status').textContent = 'Unable to load workspace. Check that the local server is running.'; }
}
async function submit(form, path, body) {
  const submitButton = form.querySelector('[type=submit]'); submitButton.disabled = true; form.querySelector('.form-error').textContent = '';
  try { const response = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-OTSec-Request':'local-ui'},body:JSON.stringify(body)}); const output = await response.json(); if (!response.ok) throw new Error(output.error || 'Request failed.'); form.closest('dialog').close(); form.reset(); $('message').hidden = false; const result = output.result; $('message').textContent = result.imported !== undefined ? `Evidence imported: ${result.imported} new records; ${result.duplicates} duplicates skipped.` : result.state ? `Proposal recorded: ${result.state.replaceAll('-',' ')}. No action executed.` : `Environment ${result.name} added.`; await refresh(); }
  catch(error) { form.querySelector('.form-error').textContent = error.message; }
  finally { submitButton.disabled = false; }
}
document.querySelectorAll('[data-view]').forEach(b => b.addEventListener('click',() => go(b.dataset.view)));
document.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click',() => openDialog(b.dataset.open)));
document.querySelectorAll('[data-close]').forEach(b => b.addEventListener('click',() => b.closest('dialog').close()));
$('refresh').addEventListener('click',refresh); $('scope').addEventListener('change',render);
['finding-search','severity','finding-tool'].forEach(id => $(id).addEventListener('input',renderFindings));
['tool-search','tool-category'].forEach(id => $(id).addEventListener('input',renderTools));
$('import-tool').addEventListener('change',importHelp);
$('environment-form').addEventListener('submit',event => { event.preventDefault(); const form = event.target; submit(form,'/api/environments',Object.fromEntries(new FormData(form))); });
$('plan-form').addEventListener('submit',event => { event.preventDefault(); const form = event.target, body = Object.fromEntries(new FormData(form)); body.tool = body.action === 'scan' ? 'zaproxy' : 'custom'; submit(form,'/api/plans',body); });
$('import-form').addEventListener('submit',async event => { event.preventDefault(); const form = event.target, file = form.elements.file.files[0]; if (!file || file.size > 5*1024*1024) { form.querySelector('.form-error').textContent = 'Choose a report file up to 5 MiB.'; return; } try { const content = new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer()); await submit(form,'/api/import',{environment:form.elements.environment.value,tool:form.elements.tool.value,application:form.elements.application.value,content}); } catch { form.querySelector('.form-error').textContent = 'The report must be a UTF-8 text file.'; } });
refresh();
