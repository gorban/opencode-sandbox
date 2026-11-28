// Shared helpers for the static prototype generator: escaping, host-label
// sanitising, icons, and the small host components every screen reuses.
import { readFileSync } from 'node:fs';

export const data = JSON.parse(readFileSync(new URL('../brief/fixtures/workspace.json', import.meta.url), 'utf8'));

export const esc = (s) => String(s)
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#39;');

// Host labels: drop control, bidi-control and zero-width characters, then isolate direction.
const UNSAFE = /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
export const clean = (s) => String(s).replace(UNSAFE, '');
export const label = (s) => `<bdi>${esc(clean(s))}</bdi>`;
// Attribute-safe plain text for accessible names.
export const attr = (s) => esc(clean(s));

const ICONS = {
  lock: '<rect x="3.5" y="7.5" width="9" height="6" rx="1"/><path d="M5.5 7.5V5.5a2.500 2.500 0 0 1 5 0v2"/>',
  tray: '<path d="M2.500 9.500l1.600-5.500h7.800l1.600 5.500v3h-11z"/><path d="M2.500 9.500h3.200l.8 1.500h3l.8-1.500h3.200"/>',
  pulse: '<path d="M1.500 8.500h3l1.500-4 3 7.500 1.700-3.500h3.800"/>',
  person: '<circle cx="8" cy="5.500" r="2.500"/><path d="M3 13.500c.6-2.600 2.600-4 5-4s4.400 1.400 5 4"/>',
  hub: '<circle cx="8" cy="8" r="2"/><path d="M8 2v4M8 10v4M2 8h4M10 8h4"/>',
  link: '<path d="M6.500 9.500l3-3"/><path d="M7.200 4.600l1-1a2.600 2.600 0 0 1 3.700 3.700l-1 1"/><path d="M8.800 11.400l-1 1a2.600 2.600 0 0 1-3.700-3.700l1-1"/>',
  keyboard: '<rect x="1.500" y="4" width="13" height="8" rx="1"/><path d="M4 6.800h.01M6.700 6.800h.01M9.300 6.800h.01M12 6.800h.01M5 9.500h6"/>',
  warn: '<path d="M8 2.500l6 10.500H2z"/><path d="M8 6.500v3M8 11.200h.01"/>',
  info: '<circle cx="8" cy="8" r="5.500"/><path d="M8 7.500v3.200M8 5.300h.01"/>',
  bot: '<rect x="3" y="5.500" width="10" height="7" rx="1.500"/><path d="M8 3v2.500M6 8.500v1.200M10 8.500v1.200"/>',
  tool: '<path d="M10.500 2.500a3 3 0 0 0-2.800 4L2.500 11.700l1.800 1.800 5.200-5.200a3 3 0 0 0 4-2.800l-1.900 1.400-1.600-1.600z"/>',
  laptop: '<rect x="3" y="3.500" width="10" height="6.500" rx="1"/><path d="M1.500 12.500h13"/>',
  server: '<rect x="2.500" y="3" width="11" height="4" rx="1"/><rect x="2.500" y="9" width="11" height="4" rx="1"/><path d="M5 5h.01M5 11h.01"/>',
  at: '<circle cx="8" cy="8" r="2.300"/><path d="M10.300 5.800v3c0 1 .7 1.500 1.500 1.500 1 0 1.700-.9 1.700-2.300A5.500 5.500 0 1 0 11 12.600"/>',
  play: '<path d="M5 3.500l7 4.500-7 4.500z"/>',
  hourglass: '<path d="M4.500 2.500h7M4.500 13.500h7M5 2.500c0 3 6 3.500 6 5.500s-6 2.500-6 5.500M11 2.500c0 3-6 3.500-6 5.500s6 2.500 6 5.500"/>',
  refresh: '<path d="M13 8a5 5 0 0 1-9 3M3 8a5 5 0 0 1 9-3"/><path d="M12.500 2.500V5H10M3.500 13.500V11H6"/>',
  idle: '<circle cx="8" cy="8" r="5.500"/><path d="M5.500 8h5"/>',
  error: '<path d="M5.500 2.500h5l3 3v5l-3 3h-5l-3-3v-5z"/><path d="M6 6l4 4M10 6l-4 4"/>',
  offline: '<circle cx="8" cy="8" r="5.500"/><path d="M4.200 4.200l7.600 7.600"/>',
  check: '<path d="M3 8.500l3.200 3.200L13 5"/>',
  checkc: '<circle cx="8" cy="8" r="5.500"/><path d="M5.500 8.200l1.800 1.800 3.200-3.600"/>',
  box: '<rect x="3" y="3" width="10" height="10" rx="1"/>',
  boxcheck: '<rect x="3" y="3" width="10" height="10" rx="1"/><path d="M5.500 8.200l1.800 1.800 3.200-3.600"/>',
  chevr: '<path d="M6 3.500L10.500 8 6 12.500"/>',
  chevd: '<path d="M3.500 6L8 10.500 12.500 6"/>',
  chevu: '<path d="M3.500 10L8 5.500 12.500 10"/>',
  menu: '<path d="M2.500 4.500h11M2.500 8h11M2.500 11.500h11"/>',
  close: '<path d="M4 4l8 8M12 4l-8 8"/>',
  theme: '<circle cx="8" cy="8" r="5.500"/><path d="M8 2.500v11M8 5a3 3 0 0 1 0 6"/>',
  pause: '<path d="M5.500 3.500v9M10.500 3.500v9"/>',
  bridge: '<path d="M1.500 11.500h13M4 11.500V6.500M12 11.500V6.500M4 6.500c1.500 2.200 6.500 2.200 8 0M1.500 4.500c1.200.6 2 1.200 2.500 2M14.500 4.500c-1.200.6-2 1.200-2.500 2"/>',
  gear: '<circle cx="8" cy="8" r="2.200"/><path d="M8 1.800v2M8 12.200v2M1.800 8h2M12.200 8h2M3.600 3.600L5 5M11 11l1.400 1.400M3.600 12.400L5 11M11 5l1.400-1.400"/>',
  layers: '<path d="M8 2.500l6 3-6 3-6-3z"/><path d="M2 9.500l6 3 6-3"/>',
  file: '<path d="M4 2.500h5l3 3v8H4z"/><path d="M6.500 8.500h3M8 7v3M6.500 12h3"/>',
  terminal: '<rect x="1.500" y="3" width="13" height="10" rx="1"/><path d="M4 6.500l2 1.500-2 1.500M7.500 10h3.500"/>',
  thread: '<path d="M2.500 3.500h11v7h-6l-3 2.500v-2.500h-2z"/>',
  send: '<path d="M14 2L7.2 8.800M14 2L9.600 13.600 7.200 8.800 2.400 6.400z"/>',
  signout: '<path d="M6.500 2.500H3v11h3.500M9.500 5l3 3-3 3M12.500 8H6"/>',
  clock: '<circle cx="8" cy="8" r="5.500"/><path d="M8 5v3.200l2 1.300"/>',
  grid: '<rect x="2.500" y="2.500" width="11" height="11" rx="1"/><path d="M2.500 6.500h11M2.500 10h11M6.500 6.500v7"/>',
  spinner: '<path d="M8 2.500a5.500 5.500 0 1 1-5.500 5.500"/>',
  down: '<path d="M8 3v10M4 9l4 4 4-4"/>',
  up: '<path d="M8 13V3M4 7l4-4 4 4"/>',
  sortboth: '<path d="M5 13V3M2.8 5.2L5 3l2.2 2.2M11 3v10M8.8 10.8L11 13l2.2-2.2"/>',
  sun: '<circle cx="8" cy="8" r="2.8"/><path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M3.4 12.6l1.1-1.1M11.5 4.5l1.1-1.1"/>',
  moon: '<path d="M13 9.6A5.6 5.6 0 1 1 6.4 3 4.4 4.4 0 0 0 13 9.6z"/>',
  cube: '<path d="M8 1.8l5.4 3v6.4L8 14.2l-5.4-3V4.8z"/><path d="M2.6 4.8L8 7.8l5.4-3M8 7.8v6.4"/>',
  folder: '<path d="M2 4h4l1.4 1.6H14v6.9H2z"/>',
  gauge: '<path d="M2.4 11.6a5.6 5.6 0 1 1 11.2 0z"/><path d="M8 11.6l2.4-3.4"/>',
  signin: '<path d="M9.4 2.6H13v10.8H9.4M6.4 5l3 3-3 3M9.4 8H3"/>',
  key: '<circle cx="5.4" cy="10.6" r="2.6"/><path d="M7.3 8.7L13 3M11 5l1.6 1.6M9.2 6.8l1.2 1.2"/>',
  textsize: '<path d="M1.6 12.4l3-8 3 8M2.7 10h3.8M9.2 12.4l2.4-6 2.4 6M10 10.4h3.2"/>',
  filter: '<path d="M2.6 4h10.8M4.6 8h6.8M6.6 12h2.8"/>',
  wrap: '<path d="M2.6 4h10.8M2.6 8h8.4a2 2 0 0 1 0 4H8.6M10 10.6L8.6 12l1.4 1.4M2.6 12h3"/>',
};
const tidy = (p) => p.replace(/(\d)\.(\d)00\b/g, '$1.$2').replace(/(\d)\.500\b/g, '$1.5');
export const icon = (name, cls = '') => {
  if (!ICONS[name]) throw new Error(`no icon ${name}`);
  return `<svg class="i${cls ? ' ' + cls : ''}" viewBox="0 0 16 16" aria-hidden="true" focusable="false">${tidy(ICONS[name])}</svg>`;
};
export const iconSprite = () => `<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
${Object.entries(ICONS).map(([k, v]) => `  <symbol id="${k}" viewBox="0 0 16 16">${tidy(v)}</symbol>`).join('\n')}
</svg>
`;

// ---------- time ----------
export const NOW = data.now;
const ms = (iso) => Date.parse(iso);
export const hhmm = (iso) => iso.slice(11, 16);
export const epoch = (iso) => Math.round(ms(iso) / 1000);
export const ago = (iso) => {
  const m = Math.round((ms(NOW) - ms(iso)) / 60000);
  if (iso.slice(0, 10) !== NOW.slice(0, 10)) return 'yesterday';
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60), r = m % 60;
  return r ? `${h} h ${r} min ago` : `${h} h ago`;
};
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const TZ = 'CST';
export const isToday = (iso) => iso.slice(0, 10) === NOW.slice(0, 10);
// One format everywhere: 24-hour clock, with the date when it is not today.
export const when = (iso) => {
  if (isToday(iso)) return hhmm(iso);
  const [y, mo, d] = iso.slice(0, 10).split('-').map(Number);
  const wd = DAYS[new Date(Date.UTC(y, mo - 1, d)).getUTCDay()];
  return `${wd} ${d} ${MONTHS[mo - 1]}, ${hhmm(iso)}`;
};

// ---------- addresses ----------
// The root orchestrator is always shown by name, never by its short address.
export const parseAddr = (s) => {
  if (s === '-o') return { kind: 'orch', worker: '', name: 'ROOT', text: 'Root Orchestrator' };
  if (s.startsWith('@')) return { kind: 'peer', worker: 'peer', name: s, text: `peer / ${clean(s)}` };
  const i = s.indexOf(' / ');
  if (i > -1) {
    const worker = s.slice(0, i), name = s.slice(i + 3);
    return { kind: 'remote', worker, name, text: `${clean(worker)} / ${clean(name)}` };
  }
  return { kind: 'local', worker: 'local', name: s, text: `local / ${clean(s)}` };
};
const ADDR_ICON = { orch: 'hub', peer: 'at', remote: 'server', local: 'laptop' };
// Plain "<location> / <name>": no box. The location is quiet for local and strong for a remote host.
export const addr = (s, extra = '') => {
  const a = typeof s === 'string' ? parseAddr(s) : s;
  const ic = icon(ADDR_ICON[a.kind]);
  if (a.kind === 'orch') return `<span class="addr addr--orch${extra}">${ic}<span class="addr__n">ROOT</span></span>`;
  return `<span class="addr addr--${a.kind}${extra}">${ic}<span class="addr__w">${label(a.worker)}</span><span class="addr__sep">/</span><span class="addr__n">${label(a.name)}</span></span>`;
};

// ---------- status ----------
const STATUS = {
  running: ['play', 'ok', 'Running'],
  stalled: ['hourglass', 'caution', 'Stalled'],
  reconnecting: ['refresh', 'caution', 'Reconnecting'],
  idle: ['idle', 'quiet', 'Idle'],
  error: ['error', 'bad', 'Error'],
  offline: ['offline', 'quiet', 'Offline'],
  ok: ['checkc', 'ok', 'On track'],
  waiting: ['clock', 'quiet', 'Waiting'],
};
// Status sort order, most severe first.
export const SEVERITY = { error: 0, stalled: 1, idle: 2, reconnecting: 3, running: 4, offline: 5 };
export const STATUS_ORDER = Object.keys(SEVERITY);
export const statusTone = (key) => STATUS[key][1];
export const status = (key, text) => {
  const [ic, tone, word] = STATUS[key];
  return `<span class="st st--${tone}">${icon(ic)}<span>${esc(text || word)}</span></span>`;
};
export const statusWord = (key) => STATUS[key][2];
export const statusIcon = (key) => STATUS[key][0];

// ---------- provenance ----------
export const prov = (badge) => {
  if (badge === 'Operator') return `<span class="prov prov--op">${icon('person')}Operator</span>`;
  if (badge === 'Orchestrator -o' || badge === 'Orchestrator') return `<span class="prov prov--orch">${icon('hub')}Orchestrator</span>`;
  if (badge === 'Sub-agent') return `<span class="prov prov--agent">${icon('thread')}Sub-agent</span>`;
  if (badge.startsWith('Peer: ')) return `<span class="prov prov--peer">${icon('link')}Peer<span class="prov__seg">${label(badge.slice(6))}</span></span>`;
  if (badge === 'TUI Input · In-Sandbox') return `<span class="prov prov--tui">${icon('keyboard')}TUI Input<span class="prov__seg">In-Sandbox</span></span>`;
  if (badge === 'Sandbox-Local / Unverified') return `<span class="prov prov--unv">${icon('warn')}Sandbox-Local<span class="prov__seg">Unverified</span></span>`;
  if (badge === 'Tool call') return `<span class="prov prov--tool">${icon('tool')}Tool call</span>`;
  if (badge === 'Agent') return `<span class="prov prov--agent">${icon('bot')}Agent</span>`;
  throw new Error(`unknown badge ${badge}`);
};
export const wfPill = (p) => p === 'Deterministic Workflow'
  ? `<span class="wfp wfp--det">${icon('gear')}Deterministic Workflow</span>`
  : `<span class="wfp wfp--ovl">${icon('layers')}Orchestrator Overlay</span>`;

// Untrusted text: escaped, verbatim, contained. Never interpreted.
// Invisible and direction-changing characters are spelled out as host-drawn markers.
const HIDDEN = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;
const code = (c) => `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
export const plain = (text) => {
  const value = String(text);
  let start = 0;
  let html = '';
  for (const match of value.matchAll(HIDDEN)) {
    const character = match[0];
    html += esc(value.slice(start, match.index));
    html += `<span class="ctl"><span class="vh">invisible character </span>${code(character)}</span>`;
    start = match.index + character.length;
  }
  return html + esc(value.slice(start));
};
export const well = (text, cls = '', tag = 'div') => `<${tag} class="well${cls ? ' ' + cls : ''}" dir="auto">${plain(text)}</${tag}>`;

export const meter = (pct, warn) => `<svg class="meter${warn ? ' meter--warn' : ''}" viewBox="0 0 100 4" preserveAspectRatio="none" aria-hidden="true" focusable="false"><rect class="meter__track" width="100" height="4"/><rect class="meter__fill" width="${pct}" height="4"/></svg>`;

export const notice = ({ tone = 'quiet', ic = 'info', title, titleId = '', body = '', actions = '' }) => {
  const heading = titleId ? `<h2 class="notice__title" id="${titleId}">${title}</h2>` : `<p class="notice__title">${title}</p>`;
  const description = body ? `<p class="notice__body">${body}</p>` : '';
  const controls = actions ? `<div class="notice__actions">${actions}</div>` : '';
  return `<div class="notice notice--${tone}">${icon(ic)}<div class="notice__main">${heading}${description}${controls}</div></div>`;
};

// ---------- flattened fleet ----------
export const fleet = data.projects.flatMap((p) => p.sandboxes.map((s) => {
  const a = parseAddr(s.addr);
  const baseBand = ['reconnecting', 'offline', 'stalled', 'error'].includes(s.status) ? 'degraded' : 'ok';
  const band = s.attention > 0 ? 'attention' : baseBand;
  return { ...s, project: p.label, a, band, sev: SEVERITY[s.status] };
})).map((s, i) => ({ ...s, n: i + 1 }));
export const BAND_ORDER = ['attention', 'degraded', 'ok'];
export const ranked = [...fleet].sort((x, y) =>
  BAND_ORDER.indexOf(x.band) - BAND_ORDER.indexOf(y.band) || y.attention - x.attention || (x.attention ? x.sev - y.sev : 0) ||
  ms(y.last_meaningful_change) - ms(x.last_meaningful_change));
