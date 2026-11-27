// Static prototype generator. Reads the fixture, writes out/*.html and out/tokens.css.
// Run: node build/build.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import {
  data, esc, clean, label, attr, icon, iconSprite, hhmm, epoch, ago, when, isToday, TZ, parseAddr, addr,
  status, statusWord, statusTone, statusIcon, STATUS_ORDER, prov, wfPill, well, plain, meter, notice, fleet, ranked, BAND_ORDER,
} from './lib.mjs';
import { tokensCss } from './tokens.mjs';

const OUT = new URL('../out/', import.meta.url);
mkdirSync(new URL('assets/', OUT), { recursive: true });
const write = (name, html) => writeFileSync(new URL(name, OUT), html.replace(/[ \t]+\n/g, '\n'));

const H = data.header;
const QUOTA_WARN = 80;
const split = (s) => String(s).split(' · ');

// A control with a host tooltip. The control carries aria-describedby="<id>".
const tip = (id, text, control, cls = '') => `<span class="tipwrap${cls ? ' ' + cls : ''}">${control}<span class="tip" role="tooltip" id="${id}">${text}</span></span>`;
// The ownership note: one source for the sidebar foot and the sign-in page. The second line is shown
// as written and links to its full HTTPS address in a new tab.
const OWNER = { name: 'David Bruck', repo: 'github.com/gorban/opencode-sandbox' };
const ownership = (cls = '') => `<p class="owner${cls ? ' ' + cls : ''}"><span class="owner__line">Copyright \u00a9 ${OWNER.name}</span><a class="owner__link" href="https://${OWNER.repo}" target="_blank" rel="noopener noreferrer" data-agent-hidden>${OWNER.repo}<span class="vh"> (opens in a new tab)</span></a></p>`;
const tz = (cls = '') => `<p class="tz${cls ? ' ' + cls : ''}">${icon('clock')}<span>Times in ${TZ}</span></p>`;

// ---------------------------------------------------------------- document
const doc = ({ title, body, bodyClass = '' }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}, oc-sandbox</title>
<meta name="description" content="${esc(title)} screen of the oc-sandbox operator dashboard prototype.">
<link rel="icon" href="assets/mark.svg" type="image/svg+xml">
<link rel="stylesheet" href="tokens.css">
<link rel="stylesheet" href="app.css">
<script src="app.js" defer></script>
</head>
<body class="${bodyClass}">
${body}
</body>
</html>
`;

// ---------------------------------------------------------------- trusted chrome
const BRIDGE = {
  off: ['Agent bridge off', 'Off', false],
  on: ['Agent bridge on', 'On', true],
  pending: ['Agent request waiting', 'Request', true],
};
const brand = (href) => `<a class="brand" href="${href}">${icon('cube', 'brand__mark')}<span class="brand__name">oc-sandbox</span></a>`;
const themeBtn = () => tip('tip-theme', 'Switch between the light and dark theme. The choice lasts until you leave this page.',
  `<button type="button" class="btn btn--sm btn--ghost btn--icon" id="theme-toggle" aria-label="Switch theme" aria-describedby="tip-theme">${icon('sun', 'i--sun')}${icon('moon', 'i--moon')}</button>`, 'tipwrap--end');

const header = (bridge) => {
  const [bText, bVal, bOn] = BRIDGE[bridge];
  return `<a class="skip" href="#main">Skip to main content</a>
<header class="chrome" data-trusted aria-label="Workspace header">
  <div class="hdr">
    ${tip('tip-menu', 'Open the workspace tree and page links.', `<button type="button" class="btn btn--sm btn--ghost btn--icon hdr__menu" id="nav-toggle" aria-label="Workspace menu" aria-controls="sidebar" aria-expanded="false" aria-describedby="tip-menu">${icon('menu')}</button>`)}
    ${brand('fleet.html')}
    <div class="hdr__tiers">
      ${tip('tip-tier-a', 'Tier A. Blocking security approvals. Only you can decide them.', `<a class="tier tier--a" href="approvals.html" data-agent-hidden aria-describedby="tip-tier-a">${icon('lock')}<span class="tier__name">Approval Inbox</span><span class="tier__count num" data-count data-n="${H.approval_inbox_pending}" data-apr="${data.approval_inbox.map(aprKey).join(' ')}">${H.approval_inbox_pending}</span><span class="vh"> blocking</span></a>`)}
      ${tip('tip-tier-b', 'Tier B. Decisions that wait for you without blocking an agent.', `<a class="tier tier--b" href="inbox.html" data-agent-hidden aria-describedby="tip-tier-b">${icon('tray')}<span class="tier__name">Human Inbox</span><span class="tier__count num">${H.human_inbox_open}</span><span class="vh"> open</span></a>`)}
    </div>
    <div class="hdr__tools" role="group" aria-label="Agent bridge and display">
      <div class="bridge" id="bridge" role="group" aria-label="Agent bridge" data-bridge="${bridge}">
        ${tip('tip-bridge', 'Agent bridge. Off by default. While it is on, the root orchestrator may press the controls it can see in this tab. Protected controls still stop for your confirmation.', `<button type="button" class="btn btn--sm bridge__toggle" id="bridge-toggle" aria-pressed="${bOn}" aria-describedby="tip-bridge" data-agent-hidden>${icon('bridge')}<span class="bridge__name">Bridge</span><span class="bridge__val" id="bridge-val">${bVal}</span></button>`)}
        ${tip('tip-pause', 'Pause holds every agent request until you resume, and cancels one that is waiting. Works while the bridge is on.', `<button type="button" class="btn btn--sm btn--ghost" id="bridge-pause" aria-pressed="false" aria-disabled="${!bOn}" aria-describedby="tip-pause">${icon('pause')}<span class="hdr__t" id="bridge-pause-t">Pause</span></button>`)}
        <span class="vh" id="bridge-state" role="status">${bText}</span>
      </div>
      ${tip('tip-density', 'Comfortable sizing: larger type, spacing and targets. Lasts until you leave this page.', `<button type="button" class="btn btn--sm btn--ghost" id="density-toggle" aria-pressed="false" aria-describedby="tip-density">${icon('textsize')}<span class="hdr__t">Comfortable</span></button>`)}
      ${themeBtn()}
    </div>
  </div>
  <div class="ribbon" role="group" aria-label="Health, Tier C. Clears on its own">
    <span class="ribbon__label">${icon('pulse')}Health</span>
    <ul class="ribbon__list">
      ${H.health_ribbon.map((h) => `<li class="pill pill--${h.level}">${icon(h.level === 'warning' ? 'warn' : 'info')}<span class="vh">${h.level === 'warning' ? 'Warning' : 'Info'}: </span>${label(h.text)}</li>`).join('\n      ')}
    </ul>
  </div>
</header>`;
};

const quotaWin = (k, words, pct) => {
  const warn = pct >= QUOTA_WARN;
  return `<span class="acct__win${warn ? ' acct__win--warn' : ''}"><span class="acct__k">${k}<span class="vh"> ${words} window</span></span>${meter(pct, warn)}<span class="acct__pct num">${pct}%</span></span>`;
};
const usage = () => `<footer class="usage" data-trusted aria-label="Account usage">
  <div class="usage__head">
    <p class="usage__title">${icon('gauge')}<span>Account usage</span></p>
    <button type="button" class="usage__toggle" id="usage-toggle" aria-expanded="false" aria-controls="usage-list">${icon('gauge')}<span>Account usage</span>${icon('chevr', 'twist')}</button>
    <p class="usage__lock">${icon('lock')}<span>${esc(H.paid_fallback.label)}</span></p>
  </div>
  <ul class="usage__list" id="usage-list">
    ${H.quota.map((q) => `<li class="acct"><span class="acct__name">${label(q.account)}</span>${quotaWin('5h', '5 hour', q.window_5h_pct)}${quotaWin('7d', '7 day', q.window_7d_pct)}</li>`).join('\n    ')}
  </ul>
</footer>`;

// ---------------------------------------------------------------- pages per sandbox
const T = data.thread_example;
const EXAMPLE = T.sandbox;
const exSb = fleet.find((f) => f.addr === EXAMPLE);
const pageOf = (sb) => (sb.addr === EXAMPLE ? 'thread.html' : `thread-${sb.n}.html`);
const aprKey = (a) => `${a.request_id}@${a.revision}`;

// ---------------------------------------------------------------- what needs the operator
// Each sandbox's attention count is accounted for: approvals that target it, inbox items about it,
// then one item for unread work or a stopped agent. A decided approval leaves the count in the browser.
const need = (sb) => {
  const aprs = data.approval_inbox.filter((a) => a.target === sb.addr).map(aprKey);
  const inbox = data.human_inbox.filter((it) => it.title.startsWith(`${sb.addr}:`)).length;
  let rest = sb.attention - aprs.length - inbox, other = '';
  const unread = sb.threads.find((t) => t.unread);
  if (rest > 0 && sb.status === 'error') { other = 'Stopped with an error'; rest--; }
  else if (rest > 0 && unread) { other = `${unread.unread} unread in ${clean(unread.label)}`; rest--; }
  if (rest !== 0) throw new Error(`attention for ${sb.addr} is not accounted for`);
  return { aprs, inbox, other };
};
const why = ({ aprs, inbox, other }) => [
  aprs.length ? `${aprs.length} ${aprs.length === 1 ? 'approval' : 'approvals'}` : '',
  inbox ? `${inbox} ${inbox === 1 ? 'inbox item' : 'inbox items'}` : '', other,
].filter(Boolean).join(' · ');
// A glyph beside a numeral, no box. The glyph's shape carries the severity; assistive technology hears
// the severity and the count as two separate phrases.
const attn = (n, st, aprs = []) => {
  const tone = statusTone(st), urgent = tone === 'bad' || tone === 'caution';
  return `<span class="attn attn--${urgent ? tone : 'note'}" data-n="${n}" data-apr="${attr(aprs.join(' '))}">${icon(urgent ? statusIcon(st) : 'thread')}<span class="vh">${urgent ? `Severity: ${statusWord(st).toLowerCase()}` : 'Unread work'}. </span><span class="num" data-attn-n>${n}</span><span class="vh" data-attn-w> ${n === 1 ? 'needs' : 'need'} you</span></span>`;
};

// ---------------------------------------------------------------- sidebar tree
const treeThread = (t, sb, cur, child = false) => {
  const here = cur.sb === sb.addr && cur.thread === t.label && !child;
  const kids = t.children || [];
  const inner = `<span class="tree__twist">${kids.length ? icon('chevd') : ''}</span>${icon('thread')}<span class="tree__body"><span class="tree__name">${child ? '<span class="vh">Sub-agent thread </span>' : ''}${label(t.label)}</span></span><span class="vh"> in ${attr(sb.a.text)}</span>${t.unread ? `<span class="attn attn--plain"><span class="attn__gap"></span><span class="num">${t.unread}</span><span class="vh"> unread</span></span>` : ''}`;
  return `<li role="none"><a role="treeitem" class="tree__row"${kids.length ? ' aria-expanded="true"' : ''}${here ? ' aria-current="page"' : ''} href="${pageOf(sb)}">${inner}</a>${kids.length ? `<ul role="group">${kids.map((k) => treeThread(k, sb, cur, true)).join('')}</ul>` : ''}</li>`;
};
// Only the selected sandbox starts with its threads open; the script folds the others.
const treeSandbox = (sb, cur) => {
  const has = sb.threads.length > 0;
  const here = cur.sb === sb.addr && !cur.thread;
  const inner = `<span class="tree__twist">${has ? icon('chevd') : ''}</span><span class="tree__body"><span class="tree__name">${label(sb.a.name)}</span><span class="tree__meta"><span class="wk wk--${sb.a.kind}">${icon(sb.a.kind === 'remote' ? 'server' : 'laptop')}${label(sb.a.worker)}</span>${status(sb.status)}</span></span>${sb.attention ? attn(sb.attention, sb.status, need(sb).aprs) : ''}`;
  return `<li role="none"><a role="treeitem" class="tree__row tree__row--sb"${has ? ` aria-expanded="true"${cur.sb === sb.addr ? '' : ' data-fold'}` : ''}${here ? ' aria-current="page"' : ''} href="${pageOf(sb)}">${inner}</a>${has ? `<ul role="group">${sb.threads.map((t) => treeThread(t, sb, cur)).join('')}</ul>` : ''}</li>`;
};
// A project shows the sum of what its sandboxes need, with the glyph of the most urgent one inside it.
const TONE_RANK = ['bad', 'caution', 'ok', 'quiet'];
const projCount = (p) => {
  const inside = p.sandboxes.map((x) => fleet.find((f) => f.addr === x.addr)).filter((f) => f.attention);
  if (!inside.length) return '';
  const worst = [...inside].sort((a, b) => TONE_RANK.indexOf(statusTone(a.status)) - TONE_RANK.indexOf(statusTone(b.status)))[0];
  return attn(inside.reduce((n, f) => n + f.attention, 0), worst.status, inside.flatMap((f) => need(f).aprs));
};
const PAGES = [
  ['fleet', 'fleet.html', 'grid', 'Fleet'], ['thread', 'thread.html', 'thread', 'Thread'], ['diff', 'diff.html', 'file', 'Diff'],
  ['catalog', 'catalog.html', 'layers', 'Workflows'], ['confirm', 'confirm.html', 'lock', 'Confirm gate'], ['states', 'states.html', 'info', 'States'],
];
const sidebar = (cur) => `<nav class="side" id="sidebar" aria-label="Workspace">
  <a class="side__link" href="fleet.html"${cur.page === 'fleet' ? ' aria-current="page"' : ''}>${icon('grid')}<span>Fleet overview</span></a>
  <div class="side__scroll">
    <ul role="tree" class="tree" aria-label="Orchestrator, projects and sandboxes">
      <li role="none"><div role="treeitem" class="tree__row tree__row--root"><span class="tree__twist"></span>${icon('hub')}<span class="tree__body"><span class="tree__name">Root Orchestrator</span><span class="tree__meta"><span class="wk">pinned</span>${status(data.orchestrator.status)}</span></span></div></li>
      ${data.projects.map((p) => `<li role="none"><div role="treeitem" class="tree__row tree__row--proj" aria-expanded="true"><span class="tree__twist">${icon('chevd')}</span>${icon('folder')}<span class="tree__body"><span class="tree__name">${label(p.label)}</span></span><span class="vh"> project</span>${projCount(p)}</div>
        <ul role="group">${p.sandboxes.map((s) => treeSandbox(fleet.find((f) => f.addr === s.addr), cur)).join('')}</ul></li>`).join('\n      ')}
    </ul>
  </div>
  <div class="side__foot">
    <ul class="pages" aria-label="Pages">
      ${PAGES.map(([id, href, ic, text]) => `<li><a class="pages__link" href="${href}"${cur.nav === id ? ' aria-current="page"' : ''}>${icon(ic)}<span>${text}</span></a></li>`).join('\n      ')}
    </ul>
    <div class="profile">
      ${tip('tip-profile', 'Session menu: sign in or sign out.', `<button type="button" class="profile__btn" id="profile-toggle" aria-haspopup="menu" aria-expanded="false" aria-controls="profile-menu" aria-describedby="tip-profile">${icon('person', 'profile__av')}<span class="profile__t"><span class="profile__name">Operator</span><span class="sub">Workspace session</span></span>${icon('chevu', 'profile__chev')}</button>`, 'tipwrap--up tipwrap--block')}
      <ul class="menu" id="profile-menu" role="menu" aria-label="Session" data-agent-hidden hidden>
        <li role="none"><a role="menuitem" class="menu__item" href="signin.html" tabindex="-1">${icon('signin')}<span>Sign in</span></a></li>
        <li role="none"><a role="menuitem" class="menu__item" href="signin.html" tabindex="-1">${icon('signout')}<span>Sign out</span></a></li>
      </ul>
    </div>
    ${ownership()}
  </div>
</nav>
<div class="side-scrim" id="side-scrim" hidden></div>`;

const page = ({ file, title, cur, bridge = 'off', main, after = '', bodyClass = '' }) => write(file, doc({
  title, bodyClass: `app${bodyClass ? ' ' + bodyClass : ''}`,
  body: `${header(bridge)}
<div class="stage">
${sidebar(cur)}
${main}
${after}
</div>
${usage()}`,
}));

// ---------------------------------------------------------------- fleet table
const BAND = {
  attention: ['Needs you', 'warn'],
  degraded: ['Degraded, no action needed', 'refresh'],
  ok: ['On track or idle', 'checkc'],
};
const fleetRow = (sb) => {
  const [model, effort] = split(sb.model);
  const name = attr(sb.a.text);
  const [h0, ...hRest] = split(sb.health);
  const shown = sb.a.kind === 'remote' ? `${label(sb.a.worker)} <span class="rowlink__sep">/</span> ${label(sb.a.name)}` : label(sb.a.name);
  const where = sb.a.kind === 'remote' ? label(sb.a.worker) : 'Local';
  const grants = sb.grants.length
    ? `<ul class="grants">${sb.grants.map((g) => `<li class="grant">${label(g)}</li>`).join('')}</ul>`
    : '<span class="quiet">None</span>';
  const revoke = sb.grants.length
    ? `<div class="acts"><button type="button" class="btn btn--sm" data-revoke data-agent-confirm="Removes ${attr(sb.grants.join(' and '))} from ${name}. Its agent stops until grants are restored." aria-label="Revoke grants for ${name}">${icon('lock')}<span>Revoke grants</span></button></div>`
    : '';
  const id = `row-${sb.n}`;
  const nd = need(sb);
  const health = `<span class="c-health__t">${label(h0)}</span>${hRest.map((p) => `<span class="sub">${label(p)}</span>`).join('')}`;
  return `<tr data-row data-band="${sb.band}" data-worker="${sb.a.kind}" data-status="${sb.status}" data-attn="${sb.attention}" data-sev="${sb.sev}" data-rank="${ranked.indexOf(sb)}" data-changed="${epoch(sb.last_meaningful_change)}">
          <th scope="row" class="c-name" data-label="Sandbox"><div class="rowhead">
            ${tip(`tip-${id}`, 'Show or hide branch, model and grants.', `<button type="button" class="rowbtn" data-toggle aria-expanded="false" aria-controls="${id}" aria-label="Details for ${name}" aria-describedby="tip-${id}">${icon('chevr', 'twist')}</button>`)}
            ${icon(sb.a.kind === 'remote' ? 'server' : 'laptop', 'rowhead__i')}
            <span class="rowhead__t"><a class="rowlink" href="${pageOf(sb)}" aria-label="Open ${name}">${shown}</a><span class="sub">${label(sb.project)} / ${where}</span></span>
          </div></th>
          <td class="c-status" data-label="Status">${status(sb.status)}<span class="c-status__h">${health}</span></td>
          <td class="c-attn" data-label="Attention">${sb.attention ? `<span class="need">${attn(sb.attention, sb.status, nd.aprs)}<span class="need__why" data-why data-apr="${attr(nd.aprs.join(' '))}" data-inbox="${nd.inbox}" data-other="${attr(nd.other)}">${esc(why(nd))}</span></span><span class="quiet" data-none hidden>None</span>` : '<span class="quiet">None</span>'}</td>
          <td class="c-health" data-label="Health">${health}</td>
          <td class="c-time" data-label="Last change"><span class="num">${when(sb.last_meaningful_change)}</span><span class="sub">${ago(sb.last_meaningful_change)}</span></td>
        </tr>
        <tr class="detail" id="${id}" hidden><td colspan="5">
          <dl class="facts facts--row">
            <div class="facts__row"><dt>Branch</dt><dd>${sb.branch === '—' ? '<span class="quiet">None</span>' : label(sb.branch)}</dd></div>
            <div class="facts__row"><dt>Model</dt><dd>${model === '—' ? '<span class="quiet">None</span>' : `${label(model)}${effort ? `<span class="sub">${label(effort)}</span>` : ''}`}</dd></div>
            <div class="facts__row"><dt>Grants</dt><dd>${grants}</dd></div>
          </dl>
          ${revoke}
        </td></tr>`;
};
const count = (band) => fleet.filter((f) => f.band === band).length;
const sortTh = (key, text) => `<th scope="col" class="c-${key}" aria-sort="${key === 'attention' ? 'descending' : 'none'}"><button type="button" class="sort" data-sort="${key}"><span>${text}</span>${icon('sortboth', 'sort__i sort__i--none')}${icon('down', 'sort__i sort__i--desc')}${icon('up', 'sort__i sort__i--asc')}</button></th>`;
const SORTS = [
  ['attention:desc', 'Attention, most first'], ['attention:asc', 'Attention, fewest first'],
  ['status:asc', 'Status, most severe first'], ['status:desc', 'Status, least severe first'],
  ['name:asc', 'Sandbox, A to Z'], ['name:desc', 'Sandbox, Z to A'],
  ['changed:desc', 'Last change, newest first'], ['changed:asc', 'Last change, oldest first'],
];
const fleetTable = () => `<div class="tablewrap">
    <div class="sortpick"><label for="fleet-sort">Sort</label><select id="fleet-sort" class="select">${SORTS.map(([v, t]) => `<option value="${v}">${t}</option>`).join('')}</select></div>
    <table class="fleet" id="fleet-table">
      <caption class="vh">All sandboxes, ranked by what needs you. Column headers sort.</caption>
      <thead><tr>
        ${sortTh('name', 'Sandbox')}
        ${sortTh('status', 'Status')}
        ${sortTh('attention', 'Attention')}
        <th scope="col" class="c-health">Health</th>
        ${sortTh('changed', 'Last change')}
      </tr></thead>
      ${BAND_ORDER.map((b) => `<tbody data-band="${b}">
        <tr class="band band--${b}"><th colspan="5" scope="rowgroup">${icon(BAND[b][1])}<span>${BAND[b][0]}</span><span class="band__n num">${count(b)}</span></th></tr>
        ${ranked.filter((s) => s.band === b).map(fleetRow).join('\n        ')}
      </tbody>`).join('\n      ')}
      <tfoot><tr>
        <td colspan="5"><div class="fleet__foot"><span class="fleet__count" id="fleet-count" role="status">Showing ${fleet.length} of ${fleet.length} sandboxes</span>${tz('fleet__tz')}</div></td>
      </tr></tfoot>
    </table>
    <p class="empty" id="fleet-empty" hidden>No sandboxes match these filters. <button type="button" class="linkbtn" id="fleet-clear">Clear filters</button></p>
  </div>`;
const needYou = count('attention');
const waiting = fleet.reduce((n, f) => n + f.attention, 0);
const healthy = fleet.filter((f) => f.health === 'on track').length;
const fleetMain = (extraTop = '') => `<main id="main" class="main" tabindex="-1" aria-labelledby="page-title">
  <div class="pagehead">
    <h1 id="page-title">Fleet overview</h1>
    <ul class="sum" aria-label="Fleet summary">
      <li><span class="num">${needYou} of ${fleet.length}</span> sandboxes need you</li>
      <li><span class="num" data-count data-n="${waiting}" data-apr="${attr(fleet.flatMap((f) => need(f).aprs).join(' '))}">${waiting}</span> items waiting</li>
      <li><span class="num">${healthy}</span> healthy</li>
    </ul>
    <p class="snap">Snapshot ${icon('clock')}<time class="num" datetime="${data.now}">${hhmm(data.now)} ${TZ}</time></p>
  </div>
  ${extraTop}
  <div class="toolbar" role="group" aria-label="Filter sandboxes">
    <div class="seg" role="group" aria-label="Show">
      <button type="button" class="seg__btn" data-show="all" aria-pressed="true">All sandboxes<span class="seg__n num">${fleet.length}</span></button><button type="button" class="seg__btn" data-show="attention" aria-pressed="false">Needs attention<span class="seg__n num">${needYou}</span></button>
    </div>
    <div class="toolbar__end">
      <div class="mselect" id="status-filter">
        <button type="button" class="btn mselect__btn" id="status-btn" aria-expanded="false" aria-controls="status-menu">${icon('filter')}<span id="status-label">All statuses</span>${icon('chevd')}</button>
        <fieldset class="mselect__menu" id="status-menu" hidden>
          <legend class="vh">Show only these statuses. None ticked shows all.</legend>
          ${STATUS_ORDER.map((s) => `<label class="mcheck"><input type="checkbox" value="${s}" data-status-opt><span>${statusWord(s)}</span></label>`).join('\n          ')}
        </fieldset>
      </div>
      <label class="vh" for="fleet-worker">Worker</label>
      <select id="fleet-worker" class="select">
        <option value="all">All workers</option>
        <option value="local">Local</option>
        <option value="remote">Remote hosts</option>
      </select>
    </div>
  </div>
  ${fleetTable()}
</main>`;

page({ file: 'fleet.html', title: 'Fleet overview', cur: { page: 'fleet', nav: 'fleet' }, main: fleetMain() });

// ---------------------------------------------------------------- thread
const NOTE = {
  'TUI Input · In-Sandbox': 'Typed inside the sandbox. No operator authority.',
};
const HOSTNOTE = {
  'Sandbox-Local / Unverified': 'Host notice: shown as inert plain text. Text from inside a sandbox cannot approve a request, revoke grants or speak for the operator.',
};
const D = data.diff_example;
const toolMsg = T.messages.find((m) => m.tool);
const msgHead = (m, extra = '') => `<div class="msg__head">${prov(m.badge)}${extra}<time class="msg__time num" datetime="${data.now.slice(0, 11)}${m.time}">${m.time}</time></div>`;
const msg = (m) => {
  if (m.badge === 'Tool call') {
    return `<li class="msg msg--tool" id="${m.id}">
        ${msgHead(m)}
        <div class="tool">
          <button type="button" class="tool__btn" data-toggle aria-expanded="${!m.collapsed}" aria-controls="${m.id}-body" aria-label="Details of ${attr(m.tool)} call at ${m.time}">${icon('chevr', 'twist')}<span class="tool__name">${label(m.tool)}</span></button>
          ${well(m.summary, 'well--inline', 'span')}
        </div>
        <div class="msg__fold" id="${m.id}-body"${m.collapsed ? ' hidden' : ''}>
          <p class="sub">The summary above is the tool’s own wording. The host’s record of the change is in the diff.</p>
          <a class="btn btn--sm" href="diff.html" data-open-drawer aria-label="Open diff for this call: ${attr(m.tool)} at ${m.time}">${icon('file')}<span>Open diff for this call</span></a>
        </div>
      </li>`;
  }
  const own = m.badge === 'Operator';
  return `<li class="msg" id="${m.id}">
        ${msgHead(m, NOTE[m.badge] ? `<span class="msg__note">${NOTE[m.badge]}</span>` : '')}
        ${own ? `<div class="said" dir="auto">${esc(m.text)}</div>` : well(m.text)}
        ${HOSTNOTE[m.badge] ? `<p class="hostnote">${icon('warn')}<span>${HOSTNOTE[m.badge]}</span></p>` : ''}
      </li>`;
};
const lastMsg = T.messages[T.messages.length - 1];
const subThread = (t, sb, parent) => {
  const said = lastMsg.text.split('\n')[0].replace(/^\*\*Done\.\*\* 14 tests pass\. /, '');
  return `<li class="msg msg--sub" id="sub-thread">
        <div class="tool">
          <button type="button" class="tool__btn" data-toggle aria-expanded="false" aria-controls="sub-thread-body" aria-label="Sub-agent ${attr(t.label)}, thread details">${icon('chevr', 'twist')}${prov('Sub-agent')}<span class="tool__name">${label(t.label)}</span></button>
        </div>
        <div class="msg__fold" id="sub-thread-body" hidden>
          <p class="sub">Child of ${label(parent)} in ${attr(sb.a.text)}. The parent agent reported at <span class="num">${lastMsg.time}</span>:</p>
          ${well(said)}
          <p class="sub">The sub-agent’s own messages are not part of this prototype’s data.</p>
        </div>
        <a class="sublink" href="${pageOf(sb)}#sub-thread">${icon('thread')}<span>Open sub-agent thread</span></a>
      </li>`;
};
const threadList = (sb, th) => {
  const unreadAt = T.messages.length - th.unread;
  return `<ol class="thread">
      ${T.messages.map((m, i) => `${i === unreadAt ? `<li class="unread" id="unread"><span>${th.unread} unread</span></li>\n      ` : ''}${msg(m)}`).join('\n      ')}
      ${th.children.map((c) => subThread(c, sb, th.label)).join('\n      ')}
    </ol>`;
};

const targets = T.composer_targets.map(parseAddr);
const dupNames = targets.filter((t) => ['local', 'remote'].includes(t.kind)).map((t) => t.name).filter((n, i, a) => a.indexOf(n) !== i);
const KIND = { local: 'Local sandbox on this machine', peer: 'External peer agent', orch: 'Root orchestrator of this workspace' };
const kindText = (t) => (t.kind === 'remote' ? `Remote sandbox on ${clean(t.worker)}` : KIND[t.kind]);
const twinOf = (t) => (dupNames.includes(t.name) ? targets.find((o) => o !== t && o.name === t.name) : null);
const composer = (sb) => {
  const first = Math.max(0, targets.findIndex((t) => t.text === sb.a.text));
  const now = targets[first], twin = twinOf(now);
  return `<section class="composer" id="composer" data-agent-hidden aria-label="Message composer">
      <div class="lease" data-agent-hidden role="group" aria-label="Input Lease Bar">
        ${icon('keyboard')}<p class="lease__text"><strong>Input lease</strong> <span id="lease-state" role="status">The TUI can type here.</span></p>
        ${tip('tip-lease', 'Moves typing in this thread between the in-sandbox TUI and you. Press again to hand it back.', '<button type="button" class="btn btn--sm" id="lease-take" aria-pressed="false" aria-describedby="tip-lease">Take input control</button>', 'tipwrap--end tipwrap--up')}
      </div>
      <div class="sendto">
        <span class="sendto__k">Send to</span>
        <span class="sendto__v" id="target-now">${addr(now)}</span>
        <button type="button" class="btn btn--sm" id="target-change" aria-haspopup="dialog" aria-expanded="false" aria-controls="target-pop">Change target</button>
        <span class="twin" id="target-twin"${twin ? '' : ' hidden'}>${icon('warn')}<span id="target-twin-text">${twin ? `Not ${attr(twin.text)}, which shares the name.` : ''}</span></span>
      </div>
      <div class="tpop" id="target-pop" role="dialog" aria-label="Choose one target" hidden>
        <fieldset class="targets" id="targets">
          <legend>Send to exactly one target</legend>
          <div class="targets__grid">
          ${targets.map((t, i) => {
            const tw = twinOf(t);
            return `<label class="tgt"><input type="radio" name="target" value="t${i}"${i === first ? ' checked' : ''} data-text="${attr(t.text)}"${tw ? ` data-twin="${attr(tw.text)}"` : ''}>
            <span class="tgt__t">${addr(t)}<span class="sub">${esc(kindText(t))}</span>${tw ? `<span class="tgt__dup">${icon('warn')}Same name as ${attr(tw.text)}</span>` : ''}</span></label>`;
          }).join('\n          ')}
          </div>
        </fieldset>
      </div>
      <label class="vh" for="msg-text">Message</label>
      <textarea id="msg-text" class="input" rows="1" autocomplete="off" aria-describedby="send-hint"></textarea>
      <div class="composer__send">
        <span class="composer__keys"><label class="check"><input type="checkbox" id="send-keys" checked><span>Ctrl + Enter sends</span></label><span class="sub" id="send-hint">Enter adds a line.</span></span>
        <p class="composer__status" id="send-status" role="status"></p>
        <span class="composer__go"><span class="composer__to"><span class="composer__to-k">to</span><span id="send-target">${addr(now)}</span></span>
        <button type="button" class="btn btn--primary" id="msg-send" aria-label="Send to ${attr(now.text)}">${icon('send')}<span>Send</span></button></span>
      </div>
    </section>`;
};

// One file, one box: path, counters, numbered patch. Shared by the Diff tab and the drawer.
const diffRows = (h) => {
  const m = /@@ -(\d+),\d+ \+(\d+),\d+ @@/.exec(h.header);
  let o = Number(m[1]), n = Number(m[2]);
  return h.lines.map((l) => {
    const sign = l[0], code = l.slice(1);
    if (sign === '+') return `<tr class="diff__add"><td class="diff__n"></td><td class="diff__n num">${n++}</td><td class="diff__s">+<span class="vh"> added</span></td><td class="diff__c">${plain(code)}</td></tr>`;
    if (sign === '-') return `<tr class="diff__del"><td class="diff__n num">${o++}</td><td class="diff__n"></td><td class="diff__s">−<span class="vh"> removed</span></td><td class="diff__c">${plain(code)}</td></tr>`;
    return `<tr><td class="diff__n num">${o++}</td><td class="diff__n num">${n++}</td><td class="diff__s"></td><td class="diff__c">${plain(code)}</td></tr>`;
  }).join('\n            ');
};
const fileBox = (id, open, where) => `<section class="filebox" aria-labelledby="${id}-name">
      <h3 class="filebox__h"><button type="button" class="filebox__btn" data-toggle aria-expanded="${open}" aria-controls="${id}-body">${icon('chevd', 'fchev')}<span class="filebox__name" id="${id}-name">${label(D.file)}<span class="vh">, ${where}</span></span><span class="filebox__n"><span class="diff__plus num">+${D.added}</span><span class="vh"> added, </span><span class="diff__minus num">−${D.removed}</span><span class="vh"> removed</span></span></button></h3>
      <div class="filebox__body" id="${id}-body"${open ? '' : ' hidden'}>
        ${D.hunks.map((h) => `<div class="diff well well--frame">
          <table class="diff__t">
            <caption>${esc(h.header)}</caption>
            <thead class="vh"><tr><th scope="col">Old line</th><th scope="col">New line</th><th scope="col">Change</th><th scope="col">Code</th></tr></thead>
            <tbody>
            ${diffRows(h)}
            </tbody>
          </table>
        </div>`).join('\n        ')}
      </div>
    </section>`;
const diffDrawer = (open) => `<aside class="drawer drawer--wide" id="drawer" aria-labelledby="drawer-title"${open ? '' : ' hidden'}>
  <div class="drawer__head">
    ${icon('file')}<h2 id="drawer-title">Diff</h2>
    <button type="button" class="btn btn--sm drawer__first" id="wrap-toggle" aria-pressed="true">${icon('wrap')}<span>Wrap lines</span></button>
    <a class="btn btn--sm" href="thread.html" data-close-drawer aria-label="Close diff">${icon('close')}<span>Close</span></a>
  </div>
  <div class="drawer__body" id="drawer-body">
    <p class="diff__stat">From the ${label(toolMsg.tool)} call at <span class="num">${toolMsg.time}</span> in ${label(T.thread)}.</p>
    ${fileBox('dr-file', true, 'in the diff drawer')}
    <p class="sub">File content is agent-written. It is shown as plain text and never interpreted.</p>
  </div>
</aside>`;

// The address in a title is the same cleaned host label the page head shows.
const threadTitle = (sb) => `${sb.a.text}, sandbox thread`;
const tab = (id, text, sel) => `<button type="button" role="tab" class="tab" id="tab-${id}" data-tab="${id}" aria-selected="${sel}" aria-controls="panel-${id}"${sel ? '' : ' tabindex="-1"'}>${text}</button>`;
const threadMain = (sb) => {
  const isEx = sb.addr === EXAMPLE;
  const th = sb.threads[0];
  const facts = [status(sb.status), ...split(sb.health).filter((p) => p !== sb.status).map((p) => `<span class="sub">${label(p)}</span>`),
    `<span class="sub">${label(sb.project)}${sb.branch !== '—' ? `, branch ${label(sb.branch)}` : ''}</span>`,
    sb.model !== '—' ? `<span class="sub">${label(split(sb.model).join(', '))}</span>` : ''].join('');
  const threads = th
    ? `<div class="threadbar">
      ${icon('thread')}<h2 class="threadbar__name">${label(th.label)}</h2>
      <span class="sub">${th.unread} unread</span>
      ${isEx ? `<a class="btn btn--sm threadbar__end" href="#unread">${icon('down')}<span>Jump to unread</span></a>` : ''}
    </div>
    <div class="thread-scroll" id="thread-scroll" tabindex="0" role="log" aria-label="Transcript of ${attr(th.label)} in ${attr(sb.a.text)}">
    ${isEx ? threadList(sb, th) : notice({ ic: 'thread', title: 'Transcript not in the prototype data', body: 'The fixture holds one example transcript, in feat-dashboard. This thread exists and you can still address it below.' })}
    </div>
    ${composer(sb)}`
    : `<div class="thread-scroll">${notice({ ic: 'thread', title: 'No threads in this sandbox', body: 'A thread appears here when an agent starts work in this sandbox.' })}</div>`;
  return `<main id="main" class="main main--thread" tabindex="-1" aria-labelledby="page-title">
  <div class="pagehead pagehead--sb">
    <h1 id="page-title"><span class="vh">Sandbox </span>${addr(sb.a, ' addr--lg')}</h1>
    <div class="pagehead__facts">${facts}</div>
  </div>
  <div class="tabbar">
    <div class="tabs" role="tablist" aria-label="Sandbox detail">
      ${tab('threads', 'Threads', true)}${tab('diff', 'Diff &amp; Checkpoints', false)}${tab('terminals', 'Terminals', false)}
    </div>
    ${tz('tabbar__tz')}
  </div>
  <div class="panel panel--threads" role="tabpanel" id="panel-threads" aria-labelledby="tab-threads">
    ${threads}
  </div>
  <div class="panel" role="tabpanel" id="panel-diff" aria-labelledby="tab-diff" tabindex="0" hidden>
    ${isEx ? `<div class="panelbar"><h2>Changed files</h2><span class="sub">1 file, from the ${label(toolMsg.tool)} call at <span class="num">${toolMsg.time}</span></span><a class="btn btn--sm panelbar__end" href="diff.html" data-open-drawer aria-label="Open in drawer: changed files">${icon('file')}<span>Open in drawer</span></a></div>
    ${fileBox('tab-file', false, 'in the Diff and Checkpoints tab')}` : notice({ ic: 'file', title: 'No changed files', body: 'Files an agent changes in this sandbox are listed here, one box per file.' })}
    ${notice({ ic: 'info', title: 'No checkpoints yet', body: 'A checkpoint is saved each time the agent finishes a task. You can restore the worktree to any of them from here.' })}
  </div>
  <div class="panel" role="tabpanel" id="panel-terminals" aria-labelledby="tab-terminals" tabindex="0" hidden>
    ${notice({ ic: 'terminal', title: 'No terminal attached', body: 'Attach a terminal to watch this sandbox directly. Typing there is in-sandbox input and carries no operator authority.' })}
  </div>
</main>`;
};

page({ file: 'thread.html', title: threadTitle(exSb), cur: { sb: EXAMPLE, thread: T.thread, nav: 'thread' }, main: threadMain(exSb), after: diffDrawer(false) });
page({ file: 'diff.html', title: 'Diff drawer', cur: { sb: EXAMPLE, thread: T.thread, nav: 'diff' }, main: threadMain(exSb), after: diffDrawer(true), bodyClass: 'has-drawer has-wide-drawer' });
fleet.filter((sb) => sb.addr !== EXAMPLE).forEach((sb) => page({
  file: pageOf(sb), title: threadTitle(sb), cur: { sb: sb.addr, thread: sb.threads[0] ? sb.threads[0].label : '' }, main: threadMain(sb),
}));

// ---------------------------------------------------------------- approvals (Tier A)
const SCOPE = { allowed_models: 'Allowed models', max_concurrent: 'Max concurrent', capabilities: 'Capabilities', model: 'Model' };
const scopeVal = (v) => {
  if (Array.isArray(v)) return `<ul class="grants">${v.map((x) => `<li class="grant">${label(x)}</li>`).join('')}</ul>`;
  if (typeof v === 'number') return `<span class="num">${v}</span>`;
  return label(split(v).join(', '));
};
const known = (name) => fleet.some((f) => f.addr === name);
const requester = (r) => (r === '-o' ? prov('Orchestrator') : prov('Agent'));
const soonest = [...data.approval_inbox].sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at))[0];
const armLine = '<div class="armline" aria-hidden="true"><span class="arm"></span></div>';
const approvalItem = (a, i) => {
  const rid = attr(a.request_id);
  return `<li class="apr" data-apr="pending" data-key="${attr(aprKey(a))}" data-rev="${a.revision}">
      <h2 class="apr__h"><button type="button" class="apr__row" id="apr-${i}-btn" data-apr-toggle aria-expanded="${i === 0}" aria-controls="apr-${i}">
        ${icon('chevr', 'twist')}
        <span class="apr__main"><span class="apr__kind">${label(a.kind)}</span><span class="apr__tgt">${addr(a.target)}</span></span>
        <span class="apr__meta"><span class="sub">${label(a.request_id)}, revision <span class="num">${a.revision}</span>, expires <span class="num">${when(a.expires_at)} ${TZ}</span></span>${a === soonest ? `<span class="apr__flag">${icon('clock')}Expires first</span>` : ''}</span>
        <span class="apr__state" data-apr-state>Pending</span>
      </button></h2>
      <article class="secframe approval" id="apr-${i}" aria-label="Blocking approval ${rid}"${i ? ' hidden' : ''}>
        <div class="secframe__band">${icon('lock')}<span class="secframe__title">Blocking approval ${label(a.request_id)}</span><span class="secframe__tag">Revision <span class="num">${a.revision}</span></span></div>
        <div class="secframe__body">
          <dl class="facts">
            <div class="facts__row facts__row--wide"><dt>Operation, requested by ${requester(a.requested_by)}</dt><dd><span class="sub">Wording supplied by the requester.</span>${well(a.operation)}</dd></div>
            <div class="facts__row"><dt>Kind</dt><dd>${label(a.kind)}</dd></div>
            <div class="facts__row"><dt>Target</dt><dd>${addr(a.target)}${known(a.target) ? '' : '<span class="sub">New sandbox. It does not exist yet.</span>'}</dd></div>
            ${Object.entries(a.scope).filter(([k]) => k !== 'max_spend_usd').map(([k, v]) => `<div class="facts__row"><dt>${SCOPE[k]}</dt><dd>${scopeVal(v)}</dd></div>`).join('\n            ')}
            <div class="facts__row"><dt>Cost bound</dt><dd>${a.scope.max_spend_usd != null ? `<span><strong class="num">$${a.scope.max_spend_usd.toFixed(2)}</strong> maximum spend</span>` : '<span>None stated in this request</span>'}</dd></div>
            <div class="facts__row"><dt>Expires</dt><dd><span class="num">${when(a.expires_at)} ${TZ}</span><span class="sub">After that the request lapses and nothing changes.</span></dd></div>
            <div class="facts__row"><dt>Security change</dt><dd><ul class="delta">${a.security_delta.map((d) => `<li>${label(d)}</li>`).join('')}</ul></dd></div>
          </dl>
          ${armLine}
          <div class="secframe__act" data-acts>
            <button type="button" class="btn btn--arm" data-decide="Approved" data-rev="${a.revision}" aria-disabled="true" aria-describedby="apr-${i}-hint" aria-label="Approve revision ${a.revision} of ${rid}">${icon('lock')}<span>Approve revision ${a.revision}</span></button>
            <button type="button" class="btn" data-decide="Denied" data-rev="${a.revision}" aria-label="Deny request ${rid}">Deny</button>
            <button type="button" class="btn btn--ghost" data-decide="Deferred" aria-label="Defer request ${rid}">Defer</button>
            <p class="secframe__hint" id="apr-${i}-hint" role="status">Approve is locked for a moment after this card opens.</p>
          </div>
          <p class="sub">Approving applies exactly the scope shown here, once. Work that waits on this request stays blocked until you decide.</p>
        </div>
      </article>
    </li>`;
};
page({
  file: 'approvals.html', title: 'Approval Inbox', cur: {},
  main: `<main id="main" class="main" tabindex="-1" aria-labelledby="page-title" data-agent-hidden>
  <div class="pagehead">
    <h1 id="page-title">Approval Inbox</h1>
    <p class="pagehead__sum"><span class="tiermark tiermark--a">${icon('lock')}Tier A</span> <span id="apr-summary" role="status">${H.approval_inbox_pending} blocking security approvals. Operator only.</span></p>
    ${tz('snap')}
  </div>
  <ol class="aprs" id="aprs" aria-label="Pending approvals">
    ${data.approval_inbox.map(approvalItem).join('\n    ')}
  </ol>
</main>`,
});

// ---------------------------------------------------------------- human inbox drawer (Tier B)
const inboxOrder = [...data.human_inbox].sort((a, b) => (b.severity === 'high') - (a.severity === 'high'));
// "Open thread" resolves the sandbox the item is about, by the name its title starts with.
const itemSandbox = (it) => fleet.find((f) => it.title.startsWith(`${f.addr}:`));
const inboxAct = (it, act, j) => {
  const sb = act === 'Open thread' ? itemSandbox(it) : null;
  const cls = `btn${j === 0 ? ' btn--primary' : ''}`;
  return sb
    ? `<a class="${cls}" href="${pageOf(sb)}" aria-label="${attr(act)} for ${attr(sb.a.text)}">${esc(act)}</a>`
    : `<button type="button" class="${cls}" data-decide="${attr(act)}" aria-label="${attr(act)}, ${attr(it.title)}">${esc(act)}</button>`;
};
const inboxDrawer = () => `<aside class="drawer drawer--b" id="drawer" aria-labelledby="drawer-title" data-agent-hidden>
  <div class="drawer__head drawer__head--b">
    ${icon('tray')}<h2 id="drawer-title">Human Inbox</h2><span class="tiermark tiermark--b">Tier B</span>
    <a class="btn btn--sm drawer__first" href="fleet.html" data-close-drawer aria-label="Close inbox">${icon('close')}<span>Close</span></a>
  </div>
  <div class="drawer__body">
    <p class="sub">${H.human_inbox_open} open. None of these block an agent.</p>
    <ul class="picklist" aria-label="Open inbox items">
      ${inboxOrder.map((it, i) => `<li><button type="button" class="pick pick--b" data-pick="${it.item_id}" aria-current="${i === 0}">
        <span class="pick__title">${label(it.title)}</span>
        <span class="pick__line sub">${label(it.kind)}</span>
        ${it.severity === 'high' ? `<span class="pick__flag pick__flag--high">${icon('warn')}High</span>` : ''}
      </button></li>`).join('\n      ')}
    </ul>
    ${inboxOrder.map((it, i) => `<article class="item" id="${it.item_id}" aria-labelledby="${it.item_id}-title"${i ? ' hidden' : ''}>
      <h3 id="${it.item_id}-title">${label(it.title)}</h3>
      <dl class="facts facts--tight">
        <div class="facts__row"><dt>Kind</dt><dd>${label(it.kind)}</dd></div>
        <div class="facts__row"><dt>Severity</dt><dd>${it.severity === 'high' ? `<span class="st st--caution">${icon('warn')}<span>High</span></span>` : 'Normal'}</dd></div>
        ${itemSandbox(it) ? `<div class="facts__row"><dt>Sandbox</dt><dd>${addr(itemSandbox(it).a)}</dd></div>` : ''}
        <div class="facts__row facts__row--wide"><dt>Summary</dt><dd>${well(it.summary)}</dd></div>
      </dl>
      <div class="item__act" data-acts>
        ${it.actions.map((act, j) => inboxAct(it, act, j)).join('\n        ')}
        <p class="item__status" role="status"></p>
      </div>
    </article>`).join('\n    ')}
  </div>
</aside>`;
page({ file: 'inbox.html', title: 'Human Inbox', cur: { page: 'fleet' }, main: fleetMain(), after: inboxDrawer(), bodyClass: 'has-drawer' });

// ---------------------------------------------------------------- agent confirmation modal
const victim = fleet.find((f) => f.a.kind === 'remote' && f.a.name === exSb.a.name);
const impact = `The agent in ${victim.a.text} stops until these grants are restored.`;
const bridgeShot = (val, text, sub, tone = '') => `<li class="shot"><div class="bridge bridge--shot${tone}"><span class="btn btn--sm btn--mock bridge__toggle">${icon('bridge')}<span class="bridge__name">Bridge</span><span class="bridge__val">${val}</span></span><span class="shot__t">${text}</span></div><p class="sub">${sub}</p></li>`;
// Compact: who asks, the action, two rows, one impact line. The facts scroll; the heading and the controls do not.
const confirmModal = () => `<div class="scrim" id="confirm-scrim"></div>
<div class="confirm secframe" id="confirm" role="alertdialog" aria-labelledby="confirm-title" aria-describedby="confirm-what" data-agent-hidden>
  <div class="secframe__band">${icon('lock')}<h2 class="secframe__title" id="confirm-title">Confirm protected action</h2></div>
  <div class="confirm__body" id="confirm-what" tabindex="0" role="group" aria-label="Request details">
    <p class="confirm__who">${prov('Orchestrator')}<span>requested this action.</span></p>
    <h3 class="confirm__action">Revoke grants</h3>
    <dl class="facts facts--list">
      <div class="facts__row"><dt>Target</dt><dd>${addr(victim.a)}<span class="sub">Not ${attr(exSb.a.text)}.</span></dd></div>
      <div class="facts__row"><dt>Parameters</dt><dd><ul class="params">${victim.grants.map((g) => `<li>${label(g)}</li>`).join('')}</ul></dd></div>
    </dl>
    <p class="impact"><strong>Impact</strong> ${esc(impact)}</p>
  </div>
  ${armLine}
  <div class="confirm__foot">
    <button type="button" class="linkbtn confirm__pause" id="confirm-pause">${icon('pause')}<span>Pause bridge</span></button>
    <button type="button" class="btn" id="confirm-cancel">Cancel</button>
    <button type="button" class="btn btn--arm" id="confirm-ok" aria-disabled="true" aria-describedby="confirm-hint"><span id="confirm-ok-label">Arming…</span></button>
    <p class="vh" id="confirm-hint" role="status">Confirm is disarmed for a moment. It needs a fresh click or key press.</p>
  </div>
</div>`;
page({
  file: 'confirm.html', title: 'Agent confirmation', cur: { page: 'fleet', nav: 'confirm' }, bridge: 'pending', bodyClass: 'has-modal',
  main: fleetMain(`<section class="proto" aria-labelledby="proto-title">
    <h2 id="proto-title">Agent bridge and confirmation states</h2>
    <p class="sub" id="proto-status" role="status">A reference for this prototype page. The live control is in the workspace header.</p>
    <ul class="shots">
      ${bridgeShot('Off', 'Agent bridge off', 'Default. The orchestrator cannot drive this tab.')}
      ${bridgeShot('On', 'Agent bridge on', 'The orchestrator may press agent-visible controls.')}
      ${bridgeShot('Request', 'Agent request waiting', 'One protected press is waiting for you in the modal.', ' bridge--pending')}
      ${bridgeShot('Cooling', 'Cooling down after cancel', 'Brief. New agent requests wait until it ends.', ' bridge--cool')}
      ${bridgeShot('Paused', 'Agent bridge paused', 'You paused it. Nothing gets through until you resume.', ' bridge--paused')}
    </ul>
    <button type="button" class="btn" id="confirm-replay" data-agent-hidden>${icon('refresh')}<span>Replay the agent request</span></button>
  </section>`),
  after: confirmModal(),
});

// ---------------------------------------------------------------- workflow surface catalog
const W = Object.fromEntries(data.workflow_surfaces.map((w) => [w.kind, w]));
const spark = (vals) => {
  const max = Math.max(...vals), min = Math.min(...vals), w = 240, h = 60, pad = 4;
  const y = (v) => h - pad - ((v - 0) / max) * (h - 2 * pad);
  const pts = vals.map((v, i) => [pad + i * (w - 2 * pad) / (vals.length - 1), y(v)]);
  const [lx, ly] = pts[pts.length - 1];
  const grid = [0.25, 0.5, 0.75, 1].map((f) => `M0 ${y(max * f).toFixed(1)}H${w}`).join('');
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Line from ${vals[0]} to ${vals[vals.length - 1]}, minimum ${min}, maximum ${max}"><path class="spark__grid" d="${grid}"/><path class="spark__base" d="M0 ${h - 0.5}H${w}"/><polyline class="spark__line" points="${pts.map((p) => p.map((n) => n.toFixed(1)).join(',')).join(' ')}"/><circle class="spark__dot" cx="${lx.toFixed(1)}" cy="${ly.toFixed(1)}" r="3"/></svg>`;
};
const surface = (kind, body, attrs = '') => `<section class="surf surf--${kind}" aria-labelledby="surf-${kind}"${attrs}>
      <div class="surf__head"><h2 id="surf-${kind}" class="surf__kind">${kind}</h2>${wfPill(W[kind].provenance)}</div>
      ${body}
    </section>`;
const laneState = { ok: 'ok', stalled: 'stalled', waiting: 'waiting' };
const sp = W.sparkline_series.values;
const done = W.checklist_progress.items.filter((i) => i[1]).length;
const chipHref = { 'Open thread': 'thread.html', 'Open diff': 'diff.html', 'Open inbox item': 'inbox.html' };
page({
  file: 'catalog.html', title: 'Workflow surface catalog', cur: { nav: 'catalog' },
  main: `<main id="main" class="main" tabindex="-1" aria-labelledby="page-title">
  <div class="pagehead">
    <h1 id="page-title">Workflow surface catalog</h1>
    <p class="pagehead__sum">Eight surfaces a workflow can place in the main area. Each carries the pill that says who wrote it.</p>
  </div>
  <div class="surfs">
    ${surface('status_card', `<p class="surf__line"><span class="surf__title">${label(W.status_card.title)}</span>${status(W.status_card.status)}</p>
      ${split(W.status_card.detail).map((p) => `<span class="sub">${label(p)}</span>`).join('')}`)}
    ${surface('metric_kpi', `<p class="kpi num">${label(W.metric_kpi.value)}</p><p class="sub">${label(W.metric_kpi.label)}</p>`)}
    ${surface('kv_table', `<dl class="kv">${W.kv_table.rows.map(([k, v]) => `<div class="kv__row"><dt>${label(k)}</dt><dd class="num">${label(v)}</dd></div>`).join('')}</dl>`)}
    ${surface('lane_health_matrix', `<table class="mini lanes"><caption class="vh">Lane health</caption><thead><tr><th scope="col">Lane</th><th scope="col">State</th></tr></thead><tbody>${W.lane_health_matrix.lanes.map((l) => `<tr><th scope="row">${label(l.lane)}</th><td>${status(laneState[l.state], l.state === 'ok' ? 'OK' : statusWord(laneState[l.state]))}</td></tr>`).join('')}</tbody></table>`)}
    ${surface('timeline_log', `<ol class="trail">${W.timeline_log.events.map(([t, e]) => `<li><time class="num">${esc(t)}</time><span>${label(e)}</span></li>`).join('')}</ol>
      ${tz()}`)}
    ${surface('checklist_progress', `<div class="well well--frame"><p class="well__title">${esc(W.checklist_progress.title)}</p><ul class="checks">${W.checklist_progress.items.map(([t, d]) => `<li>[${d ? 'x' : ' '}] ${esc(t)}</li>`).join('')}</ul></div>
      <p class="sub"><span class="num">${done} of ${W.checklist_progress.items.length}</span> checked, counted by the host.</p>`)}
    ${surface('sparkline_series', `<p class="sub">${label(W.sparkline_series.label)}</p>
      ${spark(sp)}
      <dl class="legend"><div><dt>Min</dt><dd class="num">${Math.min(...sp)}</dd></div><div><dt>Max</dt><dd class="num">${Math.max(...sp)}</dd></div><div><dt>Latest</dt><dd class="num">${sp[sp.length - 1]}</dd></div></dl>`)}
    ${surface('action_chips', `<ul class="chips">${W.action_chips.chips.map((c) => `<li><a class="chip" href="${chipHref[c]}">${esc(c)}</a></li>`).join('')}</ul>
      <p class="sub">The overlay proposes these, so they are dashed and monospace. A solid button is always the host’s.</p>`, ' data-agent-hidden')}
  </div>
</main>`,
});

// ---------------------------------------------------------------- states sheet
const stale = fleet.find((f) => f.status === 'stalled');
const skelRows = `<div class="skel-rows" role="status" aria-label="Loading"><span class="skel skel--row"></span><span class="skel skel--row"></span><span class="skel skel--row skel--short"></span></div>`;
const skelMsgs = `<div role="status" aria-label="Loading"><div class="skel-msg"><span class="skel skel--badge"></span><span class="skel skel--line"></span><span class="skel skel--line skel--short"></span></div><div class="skel-msg"><span class="skel skel--badge"></span><span class="skel skel--line"></span></div></div>`;
const miniRow = (sb, extra = '') => `<div class="minirow">${addr(sb.a)}${status(sb.status)}${extra}</div>`;
const cachedAt = `<p class="cached">${icon('clock')}<span>Updated 4 min ago</span></p>`;
const miniMsg = `<div class="minimsg">${prov('Agent')}${well(T.messages[1].text.split('\n')[0])}</div>`;
const rb = (text, id, off) => `<button type="button" class="btn btn--sm" aria-label="${text}, ${id}"${off ? ' aria-disabled="true"' : ''}>${text}</button>`;
const TONE = { error: 'bad', stale: 'caution', revoked: 'bad', denied: 'bad' };
const STATES = [
  ['loading', 'Loading',
    skelRows + '<p class="sub">Loading sandboxes</p>',
    skelMsgs + '<p class="sub">Loading messages</p>'],
  ['empty', 'Empty',
    notice({ ic: 'grid', title: 'No sandboxes yet', body: 'Sandboxes appear here as soon as one is launched. Launch plans wait for you in the Approval Inbox.', actions: '<a class="btn btn--sm" href="approvals.html" data-agent-hidden aria-label="Open Approval Inbox, empty table state">Open Approval Inbox</a>' }),
    notice({ ic: 'thread', title: 'No messages in this thread', body: 'Send the first instruction from the composer below.' })],
  ['error', 'Error',
    notice({ ic: 'error', title: 'The fleet could not be loaded', body: 'The workspace service did not answer. Your sandboxes keep running.', actions: rb('Try again', 'table error state') }),
    notice({ ic: 'error', title: 'This thread could not be loaded', body: 'The sandbox did not answer. Nothing was sent or lost.', actions: rb('Try again', 'thread error state') })],
  ['stale', 'Stale',
    notice({ ic: 'clock', title: 'Live updates stopped', body: 'The rows below are the last ones received and may be out of date.', actions: rb('Refresh', 'stale table state') }) + cachedAt + miniRow(stale),
    notice({ ic: 'clock', title: 'Streaming stopped', body: 'The message below is the last one received. Newer messages may exist.', actions: rb('Refresh', 'stale thread state') }) + cachedAt + miniMsg],
  ['offline', 'Offline',
    notice({ ic: 'offline', title: 'You are offline', body: 'Showing the last data received. Actions are off until the connection returns.', actions: rb('Revoke grants', 'offline table state', true) }) + miniRow(stale),
    notice({ ic: 'offline', title: 'You are offline', body: 'You can read this thread. Messages will not send until the connection returns.', actions: rb('Send', 'offline thread state', true) }) + miniMsg],
  ['revoked', 'Revoked',
    notice({ ic: 'lock', title: 'Grants revoked', body: 'This sandbox cannot call a model or write to its worktree until you grant again.' }) + miniRow(stale),
    notice({ ic: 'lock', title: 'Grants revoked', body: 'The agent in this sandbox has stopped. The thread is read-only until you grant again.' })],
  ['denied', 'Permission denied',
    notice({ ic: 'lock', title: 'This session cannot view the fleet', body: 'Sign in again with a new bootstrap code.', actions: '<a class="btn btn--sm" href="signin.html" data-agent-hidden aria-label="Go to sign-in, table permission state">Go to sign-in</a>' }),
    notice({ ic: 'lock', title: 'This session cannot read this thread', body: 'Sign in again with a new bootstrap code.', actions: '<a class="btn btn--sm" href="signin.html" data-agent-hidden aria-label="Go to sign-in, thread permission state">Go to sign-in</a>' })],
];
const stateCard = (id, where, tone, body) => `<div class="state${tone ? ` state--${tone}` : ''}" role="group" aria-labelledby="st-${id} st-${id}-w"><p class="state__where" id="st-${id}-w">${where}</p>${body}</div>`;
page({
  file: 'states.html', title: 'States sheet', cur: { nav: 'states' },
  main: `<main id="main" class="main" tabindex="-1" aria-labelledby="page-title">
  <div class="pagehead">
    <h1 id="page-title">States sheet</h1>
    <p class="pagehead__sum">Every state the fleet table and a thread can be in, side by side, and how hostile text is held.</p>
  </div>
  <section class="sheet" aria-labelledby="sheet-states"><h2 id="sheet-states">Fleet table and thread</h2>
    ${STATES.map(([id, name, a, b]) => `<section class="pair" aria-labelledby="st-${id}">
      <h3 class="pair__name" id="st-${id}">${name}</h3>
      <div class="pair__cols">
        ${stateCard(id, 'Fleet table', TONE[id], a)}
        ${stateCard(`${id}-th`, 'Thread', TONE[id], b).replace(`st-${id}-th st-`, `st-${id} st-`)}
      </div>
    </section>`).join('\n    ')}
  </section>
  <section class="sheet" aria-labelledby="sheet-hostile"><h2 id="sheet-hostile">Hostile text</h2>
    <table class="mini mini--wide hostile">
      <caption>The same string as a host label and as untrusted content</caption>
      <thead><tr><th scope="col">In a host label: control, bidi and zero-width characters removed, direction isolated</th><th scope="col">In a well: plain text, contained, with invisible characters spelled out</th></tr></thead>
      <tbody>
        ${[...data.hostile_strings, fleet.find((f) => f.status === 'offline').addr].map((s) => `<tr><td>${label(s)}</td><td>${well(s)}</td></tr>`).join('\n        ')}
      </tbody>
    </table>
  </section>
</main>`,
});

// ---------------------------------------------------------------- sign-in
const bareHeader = () => `<a class="skip" href="#main">Skip to main content</a>
<header class="chrome chrome--bare" data-trusted aria-label="Workspace header">
  <div class="hdr">
    ${brand('index.html')}
    <div class="hdr__tools">${themeBtn()}</div>
  </div>
</header>`;
write('signin.html', doc({
  title: 'Sign in', bodyClass: 'bare',
  body: `${bareHeader()}
<main id="main" class="signin" tabindex="-1" data-agent-hidden aria-labelledby="page-title">
  <div class="seg signin__switch" role="group" aria-label="Prototype state" id="signin-switch" hidden>
    <button type="button" class="seg__btn" data-state="signin" aria-pressed="true">Code entry</button><button type="button" class="seg__btn" data-state="expired" aria-pressed="false">Session expired</button><button type="button" class="seg__btn" data-state="reconnecting" aria-pressed="false">Reconnecting</button>
  </div>
  <div class="signin__panel" data-state-panel="signin expired">
    <div class="banner" role="alert" data-state-only="expired">${icon('clock')}<div><h2 class="banner__title">Session expired</h2><p>Issue a fresh single-use bootstrap code from the host terminal.</p></div></div>
    <section class="card" aria-labelledby="page-title">
      <span class="card__key">${icon('key')}</span>
      <h1 id="page-title">Sign in to oc-sandbox</h1>
      <label class="field" for="code"><span>Bootstrap code</span>
        <input class="input input--lg" id="code" type="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" aria-describedby="code-hint code-err" data-code>
      </label>
      <p class="sub field__hint" id="code-hint">Paste the code here. It works once and expires soon after it is printed. For a fresh one, issue a new code in the host terminal that runs oc-sandbox.</p>
      <p class="field__err" id="code-err" role="alert" hidden>${icon('error')}<span>Enter the bootstrap code first.</span></p>
      <button type="button" class="btn btn--primary btn--lg" data-signin="code" data-label-expired="Sign in with new code">Sign in</button>
    </section>
  </div>
  <div class="signin__panel" data-state-panel="reconnecting">
    <section class="card" aria-labelledby="reconnecting-title">
      <span class="card__key">${icon('spinner', 'spin')}</span>
      <h2 class="card__h" id="reconnecting-title">Reconnecting to the workspace</h2>
      <p class="card__lead">Your session is still valid. No code is needed.</p>
      <button type="button" class="btn btn--lg" id="retry-now">Retry now</button>
      <p class="sub" id="retry-status" role="status"></p>
    </section>
  </div>
  ${ownership('owner--page')}
</main>`,
}));

// ---------------------------------------------------------------- index
const screens = [
  ['fleet.html', 'Fleet overview', 'Header, sidebar tree, the ranked five-column sandbox table and its filters.'],
  ['thread.html', 'Sandbox thread', 'Every provenance badge, a collapsed tool call, a sub-agent row and the pinned composer with its target picker.'],
  ['approvals.html', 'Approval Inbox, Tier A', 'Blocking approvals stacked, each opening its security frame directly beneath its row.'],
  ['inbox.html', 'Human Inbox drawer, Tier B', 'The drawer open beside the fleet, with the Tier C health ribbon in the header.'],
  ['diff.html', 'Diff drawer', 'The diff viewer open beside a thread.'],
  ['signin.html', 'Sign-in', 'Bootstrap code entry, plus session expired and reconnecting.'],
  ['confirm.html', 'Agent confirmation modal', 'An agent pressed a protected button. Includes the cooldown and the bridge Pause control.'],
  ['catalog.html', 'Workflow surface catalog', 'One example of each of the eight surfaces, each with its provenance pill.'],
  ['states.html', 'States sheet', 'Loading, empty, error, stale, offline, revoked and permission denied, for the table and the thread.'],
];
write('index.html', doc({
  title: 'All screens', bodyClass: 'bare',
  body: `${bareHeader()}
<main id="main" class="index" tabindex="-1" aria-labelledby="page-title">
  <h1 id="page-title">Operator dashboard screens</h1>
  <p class="card__lead">A static prototype. All data comes from the workspace fixture. Each sandbox in the fleet also opens its own thread page.</p>
  <ol class="index__list">
    ${screens.map(([href, t, d]) => `<li><a href="${href}">${t}</a><span class="sub">${d}</span></li>`).join('\n    ')}
  </ol>
</main>`,
}));

// ---------------------------------------------------------------- assets
writeFileSync(new URL('tokens.css', OUT), tokensCss());
writeFileSync(new URL('assets/icons.svg', OUT), iconSprite());
writeFileSync(new URL('assets/mark.svg', OUT), `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="#6b7280" stroke-width="1.5" stroke-linejoin="round"><path d="M8 1.8l5.4 3v6.4L8 14.2l-5.4-3V4.8z"/><path d="M2.6 4.8L8 7.8l5.4-3M8 7.8v6.4"/></svg>
`);
console.log('built', screens.length + 1 + fleet.length - 1, 'pages');
