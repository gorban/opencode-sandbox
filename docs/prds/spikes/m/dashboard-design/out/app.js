/* Prototype behaviour. No storage of any kind: every choice lives in memory or,
 * for filters, sort and tab, in the URL as a value from a fixed set.
 * Screens are swapped in place, so the memory below outlives a change of screen and dies with the tab. */
(function () {
  'use strict';
  var doc = document, root = doc.documentElement, body = doc.body;
  root.classList.add('js');
  /* Shared in-memory state. decisions: "<request id>@<revision>" -> Approved | Denied, set once.
   * drafts: one unsent message per destination. lease: screens where the operator holds input. */
  var S = { decisions: {}, drafts: {}, lease: {} };
  /* Everything a screen starts (document listeners, timers) ends with that screen. */
  var life = null, timers = [];
  var onDoc = function (type, fn) { doc.addEventListener(type, fn, { signal: life.signal }); };
  var later = function (fn, ms) { var t = setTimeout(fn, ms); timers.push(t); return t; };
  var go = function () {};
  var $ = function (s, el) { return (el || doc).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || doc).querySelectorAll(s)); };
  var token = function (name, fallback) {
    var v = parseFloat(getComputedStyle(root).getPropertyValue(name));
    return isNaN(v) ? fallback : v;
  };
  /* Escape closes the innermost open thing. Each closer returns true if it acted. */
  var escapers = [];
  /* The open Workspace menu sits over everything else in the stage, so Escape reaches it first. */
  var navEscape = null;

  /* ---------- tooltips: Escape dismisses until the pointer or focus moves on ---------- */
  var tipsBack = function () { root.classList.remove('tips-off'); };
  doc.addEventListener('focusin', tipsBack);
  doc.addEventListener('pointerover', function (e) { if (e.target.closest && !e.target.closest('.tipwrap:hover')) tipsBack(); });
  doc.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    root.classList.add('tips-off');
    if (navEscape && navEscape()) { e.preventDefault(); return; }
    for (var i = escapers.length - 1; i >= 0; i--) { if (escapers[i]()) { e.preventDefault(); return; } }
  });

  /* ---------- URL state: fixed keys, fixed values, nothing else ---------- */
  var ALLOWED = {
    show: ['all', 'attention'],
    worker: ['all', 'local', 'remote'],
    status: ['error', 'stalled', 'idle', 'reconnecting', 'running', 'offline'],
    sort: ['attention', 'name', 'status', 'changed'],
    dir: ['desc', 'asc'],
    tab: ['threads', 'diff', 'terminals'],
    state: ['signin', 'expired', 'reconnecting']
  };
  var MULTI = { status: true };
  function valid(key, v) {
    if (!ALLOWED[key] || typeof v !== 'string') return null;
    if (!MULTI[key]) return ALLOWED[key].indexOf(v) > -1 ? v : null;
    var parts = v.split(',').filter(function (p, i, a) { return ALLOWED[key].indexOf(p) > -1 && a.indexOf(p) === i; });
    return parts.length ? parts.join(',') : null;
  }
  function readParam(key) { return valid(key, new URLSearchParams(location.search).get(key)); }
  function writeParams(pairs) {
    var p = new URLSearchParams();
    Object.keys(pairs).forEach(function (k) {
      var v = valid(k, pairs[k]);
      if (v) p.set(k, v);
    });
    var q = p.toString().replace(/%2C/g, ',');
    history.replaceState(null, '', location.pathname + (q ? '?' + q : ''));
  }

  /* What the shared decisions change on any screen: counts, reasons and the Tier A total. */
  var gone = function (el) {
    return (el.getAttribute('data-apr') || '').split(' ').filter(function (k) { return k && S.decisions[k]; }).length;
  };
  function applyDecisions() {
    $$('.attn[data-n]').forEach(function (el) {
      var n = Number(el.getAttribute('data-n')) - gone(el);
      $('[data-attn-n]', el).textContent = String(n);
      $('[data-attn-w]', el).textContent = n === 1 ? ' needs you' : ' need you';
      el.hidden = n < 1;
    });
    $$('[data-why]').forEach(function (el) {
      var a = (el.getAttribute('data-apr') || '').split(' ').filter(Boolean).length - gone(el);
      var i = Number(el.getAttribute('data-inbox')), o = el.getAttribute('data-other'), parts = [];
      if (a) parts.push(a + (a === 1 ? ' approval' : ' approvals'));
      if (i) parts.push(i + (i === 1 ? ' inbox item' : ' inbox items'));
      if (o) parts.push(o);
      el.textContent = parts.join(' \u00b7 ');
      var none = $('[data-none]', el.closest('td'));
      if (none) none.hidden = parts.length > 0;
    });
    $$('[data-count]').forEach(function (el) { el.textContent = String(Number(el.getAttribute('data-n')) - gone(el)); });
  }

  function init() {
  escapers = [];
  navEscape = null;
  life = new AbortController();
  applyDecisions();

  /* ---------- theme and density: memory only ---------- */
  var themeBtn = $('#theme-toggle');
  if (themeBtn) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var effective = function () { return root.getAttribute('data-mode') || (mq.matches ? 'dark' : 'light'); };
    var nameTheme = function () { themeBtn.setAttribute('aria-label', 'Switch to ' + (effective() === 'dark' ? 'light' : 'dark') + ' theme'); };
    themeBtn.addEventListener('click', function () {
      root.setAttribute('data-mode', effective() === 'dark' ? 'light' : 'dark');
      nameTheme();
    });
    nameTheme();
  }
  var densityBtn = $('#density-toggle');
  if (densityBtn) {
    densityBtn.setAttribute('aria-pressed', String(root.getAttribute('data-density') === 'comfortable'));
    densityBtn.addEventListener('click', function () {
      var on = densityBtn.getAttribute('aria-pressed') !== 'true';
      densityBtn.setAttribute('aria-pressed', String(on));
      if (on) root.setAttribute('data-density', 'comfortable'); else root.removeAttribute('data-density');
    });
  }

  /* ---------- generic disclosure ---------- */
  $$('[data-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      doc.getElementById(btn.getAttribute('aria-controls')).hidden = !open;
    });
  });
  var usageBtn = $('#usage-toggle');
  if (usageBtn) {
    usageBtn.addEventListener('click', function () {
      var open = usageBtn.getAttribute('aria-expanded') !== 'true';
      usageBtn.setAttribute('aria-expanded', String(open));
      usageBtn.closest('.usage').classList.toggle('is-open', open);
    });
  }

  /* ---------- sidebar drawer on narrow screens, and the session menu ---------- */
  var navBtn = $('#nav-toggle'), side = $('#sidebar'), sideScrim = $('#side-scrim');
  if (navBtn && side) {
    /* While the menu covers the stage, what it covers leaves the tab order. Only what this menu
     * made inert is released when it closes, so a waiting confirmation keeps its own hold. */
    var held = [];
    var setNav = function (open) {
      if (open && side.inert) return;
      side.classList.toggle('is-open', open);
      sideScrim.hidden = !open;
      navBtn.setAttribute('aria-expanded', String(open));
      held.forEach(function (el) { el.inert = false; });
      held = [];
      if (open) {
        held = [$('#main'), $('#drawer')].filter(function (el) { return el && !el.inert; });
        held.forEach(function (el) { el.inert = true; });
        var first = $('a, [tabindex="0"]', side); if (first) first.focus();
      }
    };
    /* Past 60rem the sidebar is a column again, so an open menu closes and nothing stays inert. */
    var wide = window.matchMedia('(min-width: 60rem)');
    var closeIfWide = function () { if (wide.matches && side.classList.contains('is-open')) setNav(false); };
    wide.addEventListener('change', closeIfWide, { signal: life.signal });
    window.addEventListener('resize', closeIfWide, { signal: life.signal });
    navBtn.addEventListener('click', function () { setNav(!side.classList.contains('is-open')); });
    sideScrim.addEventListener('click', function () { setNav(false); });
    navEscape = function () {
      if (!side.classList.contains('is-open')) return false;
      setNav(false); navBtn.focus(); return true;
    };
  }
  var pBtn = $('#profile-toggle'), pMenu = $('#profile-menu');
  if (pBtn) {
    var pItems = $$('[role="menuitem"]', pMenu);
    var setMenu = function (open, at) {
      pMenu.hidden = !open;
      pBtn.setAttribute('aria-expanded', String(open));
      if (open) pItems[at || 0].focus();
    };
    pBtn.addEventListener('click', function () { setMenu(pMenu.hidden); });
    pBtn.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowUp') { e.preventDefault(); setMenu(true, pItems.length - 1); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); setMenu(true, 0); }
    });
    pMenu.addEventListener('keydown', function (e) {
      var i = pItems.indexOf(doc.activeElement), n = pItems.length;
      var j = e.key === 'ArrowDown' ? (i + 1) % n : e.key === 'ArrowUp' ? (i + n - 1) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
      if (j > -1) { e.preventDefault(); pItems[j].focus(); }
      else if (e.key === 'Tab') setMenu(false);
    });
    onDoc('pointerdown', function (e) { if (!pMenu.hidden && !e.target.closest('.profile')) setMenu(false); });
    escapers.push(function () {
      if (pMenu.hidden) return false;
      setMenu(false); pBtn.focus(); return true;
    });
  }

  /* ---------- tree: roving tabindex, arrows, Home and End, type-ahead ---------- */
  var tree = $('[role="tree"]');
  if (tree) {
    var items = function () {
      return $$('[role="treeitem"]', tree).filter(function (it) {
        for (var g = it.parentElement.closest('[role="group"]'); g; g = g.parentElement.closest('[role="group"]')) {
          if (g.hidden) return false;
        }
        return true;
      });
    };
    var groupOf = function (it) { var n = it.nextElementSibling; return n && n.getAttribute('role') === 'group' ? n : null; };
    var parentOf = function (it) { var g = it.parentElement.closest('[role="group"]'); return g ? g.previousElementSibling : null; };
    var setExpanded = function (it, open) {
      var g = groupOf(it);
      if (!g) return;
      it.setAttribute('aria-expanded', String(open));
      g.hidden = !open;
    };
    var focusItem = function (it) {
      $$('[role="treeitem"]', tree).forEach(function (o) { o.tabIndex = -1; });
      it.tabIndex = 0;
      it.focus();
    };
    var all = $$('[role="treeitem"]', tree);
    all.forEach(function (o) { o.tabIndex = -1; });
    (tree.querySelector('[aria-current="page"]') || all[0]).tabIndex = 0;
    $$('[data-fold]', tree).forEach(function (it) { setExpanded(it, false); });
    var typed = '', typedAt = 0;
    tree.addEventListener('click', function (e) {
      var twist = e.target.closest('.tree__twist');
      var it = e.target.closest('[role="treeitem"]');
      if (!it) return;
      if (twist && groupOf(it)) { e.preventDefault(); setExpanded(it, it.getAttribute('aria-expanded') !== 'true'); }
      else if (it.tagName !== 'A' && groupOf(it)) setExpanded(it, it.getAttribute('aria-expanded') !== 'true');
    });
    tree.addEventListener('keydown', function (e) {
      var it = e.target.closest('[role="treeitem"]');
      if (!it) return;
      var list = items(), i = list.indexOf(it), expanded = it.getAttribute('aria-expanded');
      var go = null;
      if (e.key === 'ArrowDown') go = list[i + 1];
      else if (e.key === 'ArrowUp') go = list[i - 1];
      else if (e.key === 'Home') go = list[0];
      else if (e.key === 'End') go = list[list.length - 1];
      else if (e.key === 'ArrowRight') { if (expanded === 'false') setExpanded(it, true); else if (expanded === 'true') go = list[i + 1]; }
      else if (e.key === 'ArrowLeft') { if (expanded === 'true') setExpanded(it, false); else go = parentOf(it); }
      else if ((e.key === 'Enter' || e.key === ' ') && it.tagName !== 'A') { if (expanded) setExpanded(it, expanded !== 'true'); }
      else if (e.key.length === 1 && /\S/.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) {
        var now = Date.now();
        typed = (now - typedAt > 600 ? '' : typed) + e.key.toLowerCase();
        typedAt = now;
        var rest = list.slice(i + 1).concat(list.slice(0, i + 1));
        go = rest.filter(function (o) { return $('.tree__name', o).textContent.trim().toLowerCase().indexOf(typed) === 0; })[0];
        if (!go) return;
      } else return;
      e.preventDefault();
      if (go) focusItem(go);
    });
  }

  /* ---------- fleet table: filter, sort, URL sync ---------- */
  var table = $('#fleet-table');
  if (table) {
    var bodies = $$('tbody', table);
    var rows = $$('tbody tr[data-row]', table);
    var bands = ['attention', 'degraded', 'ok'];
    var natural = { attention: 'desc', name: 'asc', status: 'asc', changed: 'desc' };
    var st = { show: readParam('show') || 'all', worker: readParam('worker') || 'all', sort: readParam('sort') || 'attention' };
    st.dir = readParam('dir') || natural[st.sort];
    st.status = (readParam('status') || '').split(',').filter(Boolean);
    var emptyMsg = $('#fleet-empty'), countMsg = $('#fleet-count'), workerSel = $('#fleet-worker'), sortSel = $('#fleet-sort');
    var statusBtn = $('#status-btn'), statusMenu = $('#status-menu'), statusLabel = $('#status-label');
    var statusOpts = $$('[data-status-opt]', statusMenu);
    var num = function (r, k) { return Number(r.getAttribute('data-' + k)); };
    var nameOf = function (r) { return $('.rowlink', r).textContent.trim().toLowerCase(); };
    var toggleOf = function (r) { return $('.rowbtn', r); };
    var detailOf = function (r) { return doc.getElementById(toggleOf(r).getAttribute('aria-controls')); };
    /* Each comparator returns the natural order for its column. */
    var cmp = {
      attention: function (a, b) { return num(a, 'rank') - num(b, 'rank'); },
      name: function (a, b) { return nameOf(a).localeCompare(nameOf(b)) || num(a, 'rank') - num(b, 'rank'); },
      status: function (a, b) { return num(a, 'sev') - num(b, 'sev') || num(a, 'rank') - num(b, 'rank'); },
      changed: function (a, b) { return num(b, 'changed') - num(a, 'changed'); }
    };
    var render = function () {
      var banded = st.sort === 'attention' && st.dir === 'desc';
      var sorted = rows.slice().sort(cmp[st.sort]);
      if (st.dir !== natural[st.sort]) sorted.reverse();
      var shown = 0;
      sorted.forEach(function (r) {
        var ok = (st.show === 'all' || r.getAttribute('data-band') === 'attention') &&
          (st.worker === 'all' || r.getAttribute('data-worker') === st.worker) &&
          (!st.status.length || st.status.indexOf(r.getAttribute('data-status')) > -1);
        var detail = detailOf(r);
        r.hidden = !ok;
        detail.hidden = !ok || toggleOf(r).getAttribute('aria-expanded') !== 'true';
        if (ok) shown++;
        var home = banded ? bodies[bands.indexOf(r.getAttribute('data-band'))] : bodies[0];
        home.appendChild(r);
        home.appendChild(detail);
      });
      bodies.forEach(function (b) {
        $('.band', b).hidden = !banded || !$$('tr[data-row]', b).some(function (r) { return !r.hidden; });
      });
      emptyMsg.hidden = shown > 0;
      countMsg.textContent = 'Showing ' + shown + ' of ' + rows.length + ' sandboxes';
      $$('[data-show]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-show') === st.show)); });
      $$('[data-sort]', table).forEach(function (b) {
        var on = b.getAttribute('data-sort') === st.sort;
        b.closest('th').setAttribute('aria-sort', on ? (st.dir === 'asc' ? 'ascending' : 'descending') : 'none');
      });
      workerSel.value = st.worker;
      sortSel.value = st.sort + ':' + st.dir;
      statusOpts.forEach(function (o) { o.checked = st.status.indexOf(o.value) > -1; });
      statusLabel.textContent = !st.status.length ? 'All statuses'
        : st.status.length === 1 ? statusOpts.filter(function (o) { return o.checked; })[0].nextElementSibling.textContent
        : st.status.length + ' statuses';
      var out = { show: st.show === 'all' ? '' : st.show, worker: st.worker === 'all' ? '' : st.worker, status: st.status.join(',') };
      if (st.sort !== 'attention' || st.dir !== 'desc') { out.sort = st.sort; if (st.dir !== natural[st.sort]) out.dir = st.dir; }
      writeParams(out);
    };
    $$('[data-show]').forEach(function (b) { b.addEventListener('click', function () { st.show = b.getAttribute('data-show'); render(); }); });
    workerSel.addEventListener('change', function () { st.worker = workerSel.value; render(); });
    /* The picker above the stacked rows and the column headers drive the same sort. */
    sortSel.addEventListener('change', function () {
      var v = sortSel.value.split(':');
      if (!cmp[v[0]]) return;
      st.sort = v[0]; st.dir = v[1] === 'asc' ? 'asc' : 'desc';
      render();
    });
    $$('[data-sort]', table).forEach(function (b) {
      b.addEventListener('click', function () {
        var key = b.getAttribute('data-sort');
        st.dir = st.sort === key ? (st.dir === 'desc' ? 'asc' : 'desc') : natural[key];
        st.sort = key;
        render();
      });
    });
    /* Status menu: ticking a box filters at once and the menu stays open. */
    var setStatusMenu = function (open) { statusMenu.hidden = !open; statusBtn.setAttribute('aria-expanded', String(open)); };
    statusBtn.addEventListener('click', function () {
      setStatusMenu(statusMenu.hidden);
      if (!statusMenu.hidden) statusOpts[0].focus();
    });
    statusMenu.addEventListener('change', function () {
      st.status = statusOpts.filter(function (o) { return o.checked; }).map(function (o) { return o.value; });
      render();
    });
    onDoc('pointerdown', function (e) { if (!statusMenu.hidden && !e.target.closest('#status-filter')) setStatusMenu(false); });
    escapers.push(function () {
      if (statusMenu.hidden) return false;
      setStatusMenu(false); statusBtn.focus(); return true;
    });
    /* Clear filters hides itself. Focus steps to the status button before the message goes, then to
     * the first restored row, so it is never left on something hidden. */
    $('#fleet-clear').addEventListener('click', function () {
      st.show = 'all'; st.worker = 'all'; st.status = [];
      statusBtn.focus();
      render();
      var first = $$('tbody tr[data-row]', table).filter(function (r) { return !r.hidden; })[0];
      if (first) $('.rowlink', first).focus();
    });
    render();

    /* Operator revoke: a second, explicit press beside the first. */
    $$('[data-revoke]', table).forEach(function (btn) {
      var name = btn.getAttribute('aria-label'), text = $('span', btn);
      btn.addEventListener('click', function () {
        var cell = btn.parentElement;
        if (!cell.classList.contains('is-armed')) {
          cell.classList.add('is-armed');
          text.textContent = 'Confirm revoke';
          btn.setAttribute('aria-label', 'Confirm: ' + name);
          var keep = doc.createElement('button');
          keep.type = 'button'; keep.className = 'btn btn--sm'; keep.textContent = 'Keep grants';
          keep.setAttribute('aria-label', 'Keep grants: cancel ' + name);
          keep.addEventListener('click', function () {
            cell.classList.remove('is-armed'); text.textContent = 'Revoke grants'; btn.setAttribute('aria-label', name); keep.remove(); btn.focus();
          });
          btn.after(keep);
        } else {
          var done = doc.createElement('span');
          done.className = 'sub'; done.setAttribute('role', 'status'); done.tabIndex = -1;
          done.textContent = 'Revoke requested. Nothing is sent in this prototype.';
          cell.replaceChildren(done);
          done.focus();
        }
      });
    });
  }

  /* ---------- tabs ---------- */
  var tablist = $('[role="tablist"]');
  if (tablist) {
    var tabs = $$('[role="tab"]', tablist);
    var selectTab = function (t, focus) {
      tabs.forEach(function (o) {
        var on = o === t;
        o.setAttribute('aria-selected', String(on));
        o.tabIndex = on ? 0 : -1;
        doc.getElementById(o.getAttribute('aria-controls')).hidden = !on;
      });
      if (focus) t.focus();
      var id = t.getAttribute('data-tab');
      writeParams({ tab: id === 'threads' ? '' : id });
    };
    tabs.forEach(function (t, i) {
      t.addEventListener('click', function () { selectTab(t); });
      t.addEventListener('keydown', function (e) {
        var j = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? tabs.length - 1 : null;
        if (j === null) return;
        e.preventDefault();
        selectTab(tabs[(j + tabs.length) % tabs.length], true);
      });
    });
    var wanted = readParam('tab');
    if (wanted) selectTab(tabs.filter(function (t) { return t.getAttribute('data-tab') === wanted; })[0]);
  }

  /* ---------- drawer: opens and closes in place, so the active tab never changes ---------- */
  var drawer = $('#drawer');
  if (drawer) {
    var opener = null;
    var setDrawer = function (open, from) {
      drawer.hidden = !open;
      body.classList.toggle('has-drawer', open);
      body.classList.toggle('has-wide-drawer', open && drawer.classList.contains('drawer--wide'));
      if (open) { opener = from || null; $('[data-close-drawer]', drawer).focus(); }
      else if (opener && doc.contains(opener) && opener.offsetParent) opener.focus();
      else $('#main').focus();
    };
    $$('[data-open-drawer]').forEach(function (el) {
      el.addEventListener('click', function (e) { e.preventDefault(); setDrawer(true, el); });
    });
    $$('[data-close-drawer]', drawer).forEach(function (el) {
      el.addEventListener('click', function (e) { e.preventDefault(); setDrawer(false); });
    });
    if (drawer.classList.contains('drawer--b')) {
      var tierB = $('.tier--b');
      tierB.addEventListener('click', function (e) { e.preventDefault(); setDrawer(true, tierB); });
    }
    escapers.push(function () {
      if (drawer.hidden) return false;
      setDrawer(false); return true;
    });
    var wrapBtn = $('#wrap-toggle');
    if (wrapBtn) {
      wrapBtn.addEventListener('click', function () {
        var on = wrapBtn.getAttribute('aria-pressed') !== 'true';
        wrapBtn.setAttribute('aria-pressed', String(on));
        drawer.classList.toggle('is-nowrap', !on);
      });
    }
  }

  /* ---------- composer: one target, shown beside Send and named by it ---------- */
  var targets = $('#targets');
  if (targets) {
    var composer = $('#composer'), pop = $('#target-pop'), change = $('#target-change');
    var sendBtn = $('#msg-send'), sendStatus = $('#send-status'), text = $('#msg-text');
    var keys = $('#send-keys'), hint = $('#send-hint');
    var picked = function () { return $('input:checked', targets); };
    var setPop = function (open) {
      pop.hidden = !open;
      change.setAttribute('aria-expanded', String(open));
      if (open) picked().focus();
    };
    /* The editor starts at one line and grows with what is typed, up to a cap. */
    var grow = function () {
      text.rows = 1;
      var cs = getComputedStyle(text);
      var lines = Math.round((text.scrollHeight - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom)) / parseFloat(cs.lineHeight));
      text.rows = Math.max(1, Math.min(token('--rows-max', 8), lines));
    };
    /* Each destination keeps its own draft. Send is off while the editor, the recipient and the
     * button's name change, and comes back only once all three agree. */
    var current = null;
    var sync = function () {
      var r = picked(), key = r.getAttribute('data-text'), chip = $('.addr', r.closest('label'));
      sendBtn.setAttribute('aria-disabled', 'true');
      if (current !== null) S.drafts[current] = text.value;
      current = key;
      text.value = S.drafts[key] || '';
      grow();
      $('#target-now').replaceChildren(chip.cloneNode(true));
      $('#send-target').replaceChildren(chip.cloneNode(true));
      var twin = r.getAttribute('data-twin');
      $('#target-twin').hidden = !twin;
      $('#target-twin-text').textContent = twin ? 'Not ' + twin + ', which shares the name.' : '';
      sendBtn.setAttribute('aria-label', 'Send to ' + key);
      sendStatus.textContent = '';
      sendBtn.setAttribute('aria-disabled', 'false');
    };
    text.addEventListener('input', function () { S.drafts[current] = text.value; grow(); });
    change.addEventListener('click', function () { setPop(pop.hidden); });
    targets.addEventListener('change', sync);
    /* A pointer choice closes the picker. Arrow keys move the choice and leave it open; Enter accepts. */
    targets.addEventListener('click', function (e) {
      if (e.detail > 0 && e.target.closest('.tgt')) { setPop(false); change.focus(); }
    });
    targets.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') { e.preventDefault(); setPop(false); change.focus(); }
    });
    onDoc('pointerdown', function (e) { if (!pop.hidden && !e.target.closest('#composer')) setPop(false); });
    escapers.push(function () {
      if (pop.hidden) return false;
      setPop(false); change.focus(); return true;
    });
    var send = function () {
      if (sendBtn.getAttribute('aria-disabled') === 'true') return;
      if (!text.value.trim()) { sendStatus.textContent = 'Write a message first.'; text.focus(); return; }
      sendStatus.textContent = 'Ready for ' + picked().getAttribute('data-text') + '. Nothing is sent in this prototype.';
      text.value = '';
      S.drafts[current] = '';
      grow();
    };
    var nameKeys = function () { hint.textContent = keys.checked ? 'Enter adds a line.' : 'Enter sends. Shift + Enter adds a line.'; };
    keys.addEventListener('change', nameKeys);
    text.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' || e.isComposing) return;
      var go = keys.checked ? (e.ctrlKey || e.metaKey) : !e.shiftKey;
      if (go) { e.preventDefault(); send(); }
    });
    sendBtn.addEventListener('click', send);
    /* Input lease: one button takes it and hands it back. */
    var leaseBtn = $('#lease-take'), leaseState = $('#lease-state'), leaseKey = location.pathname;
    var nameLease = function (say) {
      var held = !!S.lease[leaseKey];
      leaseBtn.textContent = held ? 'Release input control' : 'Take input control';
      leaseBtn.setAttribute('aria-pressed', String(held));
      var words = held ? 'You hold input.' : 'The TUI can type here.';
      if (say || leaseState.textContent !== words) leaseState.textContent = words;
    };
    leaseBtn.addEventListener('click', function () { S.lease[leaseKey] = !S.lease[leaseKey]; nameLease(true); });
    nameLease(false);
    sync(); nameKeys();
  }

  /* ---------- approvals: one open card, armed after a pause, one terminal decision per revision ---------- */
  var aprs = $('#aprs');
  if (aprs) {
    var cards = $$('.apr', aprs);
    var rowOf = function (c) { return $('[data-apr-toggle]', c); };
    var frameOf = function (c) { return $('.secframe', c); };
    var timers2 = [];
    var arm = function (c) {
      var i = cards.indexOf(c), frame = frameOf(c), btn = $('.btn--arm', c);
      clearTimeout(timers2[i]);
      if (!btn) return;
      var hint = $('.secframe__hint', c);
      btn.setAttribute('aria-disabled', 'true');
      frame.classList.remove('is-armed', 'is-arming');
      void frame.offsetWidth;
      frame.classList.add('is-arming');
      hint.textContent = 'Approve is locked for a moment after this card opens.';
      timers2[i] = later(function () {
        btn.setAttribute('aria-disabled', 'false');
        frame.classList.remove('is-arming');
        frame.classList.add('is-armed');
        hint.textContent = 'Approve is ready.';
      }, token('--dur-arm', 750));
    };
    var openCard = function (c, opts) {
      cards.forEach(function (o, i) {
        var on = o === c;
        rowOf(o).setAttribute('aria-expanded', String(on));
        frameOf(o).hidden = !on;
        if (!on) clearTimeout(timers2[i]);
      });
      if (!c) return;
      arm(c);
      if (opts && opts.scroll) c.scrollIntoView({ block: 'start' });
      if (opts && opts.focus) rowOf(c).focus({ preventScroll: true });
    };
    /* Decisions are keyed by request id and revision in the shared state, so a decided revision
     * reads the same after leaving this screen and coming back. Defer records nothing. */
    var keyOf = function (c) { return c.getAttribute('data-key'); };
    var isDecided = function (c) { return !!S.decisions[keyOf(c)]; };
    var showDecided = function (c) {
      var which = S.decisions[keyOf(c)];
      c.setAttribute('data-apr', which.toLowerCase());
      $('[data-apr-state]', c).textContent = which;
      clearTimeout(timers2[cards.indexOf(c)]);
      var note = doc.createElement('p');
      note.className = 'decided'; note.setAttribute('role', 'status');
      note.textContent = which + ' revision ' + c.getAttribute('data-rev') + '. Recorded once; it cannot be changed here. Nothing is sent in this prototype.';
      $('[data-acts]', c).replaceChildren(note);
    };
    var summarise = function () {
      var left = cards.filter(function (c) { return !isDecided(c); }).length;
      $('#apr-summary').textContent = left + (left === 1 ? ' blocking security approval.' : ' blocking security approvals.') + ' Operator only.';
    };
    cards.forEach(function (c) {
      rowOf(c).addEventListener('click', function () {
        if (rowOf(c).getAttribute('aria-expanded') === 'true') openCard(null); else openCard(c, { scroll: true });
      });
      $$('[data-decide]', c).forEach(function (btn) {
        btn.addEventListener('click', function () {
          if (isDecided(c) || btn.getAttribute('aria-disabled') === 'true') return;
          var which = btn.getAttribute('data-decide');
          if (which === 'Deferred') {
            c.setAttribute('data-apr', 'deferred');
            $('.secframe__hint', c).textContent = 'Deferred. Revision ' + c.getAttribute('data-rev') + ' stays pending.';
          } else {
            S.decisions[keyOf(c)] = which;
            showDecided(c);
            applyDecisions();
            summarise();
          }
          var next = cards.filter(function (o) { return o !== c && !isDecided(o) && o.getAttribute('data-apr') === 'pending'; })[0] ||
            cards.filter(function (o) { return o !== c && !isDecided(o); })[0];
          if (next) openCard(next, { scroll: true, focus: true });
          else rowOf(c).focus();
        });
      });
    });
    cards.filter(isDecided).forEach(showDecided);
    summarise();
    var firstOpen = cards.filter(function (c) { return !isDecided(c); })[0] || cards[0];
    cards.forEach(function (o) { rowOf(o).setAttribute('aria-expanded', String(o === firstOpen)); frameOf(o).hidden = o !== firstOpen; });
    if (!isDecided(firstOpen)) arm(firstOpen);
  }

  /* ---------- human inbox: pick an item, decide it once ---------- */
  $$('.picklist').forEach(function (list) {
    var picks = $$('[data-pick]', list);
    picks.forEach(function (p) {
      p.addEventListener('click', function () {
        picks.forEach(function (o) {
          o.setAttribute('aria-current', String(o === p));
          doc.getElementById(o.getAttribute('data-pick')).hidden = o !== p;
        });
      });
    });
  });
  $$('.item__act').forEach(function (box) {
    var done = false;
    $$('[data-decide]', box).forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (done) return;
        done = true;
        var status = $('[role="status"]', box);
        status.textContent = btn.getAttribute('data-decide') + '. Recorded once. Nothing is sent in this prototype.';
        $$('button', box).forEach(function (b) { b.remove(); });
        status.tabIndex = -1; status.focus();
      });
    });
  });

  /* ---------- agent bridge and the confirmation modal ---------- */
  var bridge = $('#bridge');
  if (bridge) {
    var bState = $('#bridge-state'), bVal = $('#bridge-val'), bToggle = $('#bridge-toggle'), bPause = $('#bridge-pause'), bPauseT = $('#bridge-pause-t');
    var modal = $('#confirm');
    var TEXT = { off: 'Agent bridge off', on: 'Agent bridge on', pending: 'Agent request waiting', cooldown: 'Cooling down after cancel', paused: 'Agent bridge paused' };
    var VAL = { off: 'Off', on: 'On', pending: 'Request', cooldown: 'Cooling', paused: 'Paused' };
    var setBridge = function (s) {
      bridge.setAttribute('data-bridge', s);
      bState.textContent = TEXT[s];
      bVal.textContent = VAL[s];
      bToggle.setAttribute('aria-pressed', String(s !== 'off'));
      bPause.setAttribute('aria-disabled', String(s === 'off'));
      bPause.setAttribute('aria-pressed', String(s === 'paused'));
      bPauseT.textContent = s === 'paused' ? 'Resume' : 'Pause';
    };
    var cancelModal = function () {};
    bToggle.addEventListener('click', function () {
      if (bridge.getAttribute('data-bridge') === 'off') setBridge('on');
      else { cancelModal('off'); setBridge('off'); }
    });
    bPause.addEventListener('click', function () {
      if (bPause.getAttribute('aria-disabled') === 'true') return;
      if (bridge.getAttribute('data-bridge') === 'paused') setBridge('on');
      else { cancelModal('paused'); setBridge('paused'); }
    });

    if (modal) {
      var ok = $('#confirm-ok'), cancel = $('#confirm-cancel'), cHint = $('#confirm-hint'), okLabel = $('#confirm-ok-label');
      var replay = $('#confirm-replay'), protoStatus = $('#proto-status');
      /* The header and footer stay live. Only the stage behind the dialog goes inert. */
      var behind = [$('#sidebar'), $('#main')];
      var armed = false, armTimer = 0, coolTimer = 0, fresh = false, lastFocus = null;
      var isOpen = function () { return !body.classList.contains('modal-closed'); };
      var open = function () {
        var s = bridge.getAttribute('data-bridge');
        if (s !== 'on' && s !== 'pending') return;
        body.classList.remove('modal-closed');
        behind.forEach(function (el) { el.inert = true; });
        armed = false; fresh = false;
        ok.setAttribute('aria-disabled', 'true');
        okLabel.textContent = 'Arming\u2026';
        cHint.textContent = 'Confirm is disarmed for a moment. It needs a fresh click or key press.';
        modal.classList.remove('is-armed', 'is-arming');
        void modal.offsetWidth;
        modal.classList.add('is-arming');
        setBridge('pending');
        cancel.focus();
        clearTimeout(armTimer);
        $('#confirm-what').scrollTop = 0;
        armTimer = later(function () {
          armed = true;
          ok.setAttribute('aria-disabled', 'false');
          modal.classList.remove('is-arming');
          modal.classList.add('is-armed');
          okLabel.textContent = 'Confirm';
          cHint.textContent = 'Confirm is ready.';
        }, token('--dur-arm', 750));
      };
      var close = function (next, message) {
        clearTimeout(armTimer);
        body.classList.add('modal-closed');
        behind.forEach(function (el) { el.inert = false; });
        if (message) protoStatus.textContent = message;
        if (next === 'cooldown') {
          setBridge('cooldown');
          replay.disabled = true;
          clearTimeout(coolTimer);
          coolTimer = later(function () {
            if (bridge.getAttribute('data-bridge') === 'cooldown') setBridge('on');
            replay.disabled = false;
          }, token('--dur-cooldown', 3000));
        } else if (next) setBridge(next);
        var back = lastFocus || replay;
        if (back.disabled) $('#main').focus(); else back.focus();
      };
      cancelModal = function (next) {
        clearTimeout(coolTimer); replay.disabled = false;
        if (isOpen()) close(next, 'Request cancelled. Nothing changed.');
      };
      cancel.addEventListener('click', function () { close('cooldown', 'Request cancelled. Nothing changed.'); });
      $('#confirm-pause').addEventListener('click', function () { bPause.click(); });
      /* A press only counts if it began after arming: no held key, no held pointer. */
      ok.addEventListener('pointerdown', function () { fresh = armed; });
      ok.addEventListener('keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && !e.repeat) fresh = armed; });
      ok.addEventListener('keyup', function (e) { if (e.key === ' ' && !fresh) e.preventDefault(); });
      ok.addEventListener('click', function (e) {
        if (!armed || !fresh) { e.preventDefault(); fresh = false; return; }
        close('on', 'Confirmed by the operator. Nothing is sent in this prototype.');
      });
      escapers.push(function () {
        if (!isOpen()) return false;
        close('cooldown', 'Request cancelled. Nothing changed.'); return true;
      });
      onDoc('visibilitychange', function () {
        if (doc.hidden && isOpen()) close('cooldown', 'Request cancelled because the view was hidden.');
      });
      replay.addEventListener('click', function () { lastFocus = replay; open(); });
      open();
    }
  }

  /* ---------- sign-in: script-handled, never a form submit ---------- */
  var sw = $('#signin-switch');
  if (sw) {
    var panels = $$('[data-state-panel]');
    var show = function (s) {
      panels.forEach(function (p) { p.hidden = p.getAttribute('data-state-panel').split(' ').indexOf(s) < 0; });
      /* Code entry and Session expired are one card under one page title; expired adds the banner. */
      $$('[data-state-only]').forEach(function (el) { el.hidden = el.getAttribute('data-state-only') !== s; });
      $$('[data-label-expired]').forEach(function (b) {
        if (!b.hasAttribute('data-label')) b.setAttribute('data-label', b.textContent);
        b.textContent = b.getAttribute(s === 'expired' ? 'data-label-expired' : 'data-label');
      });
      $$('[data-state]', sw).forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-state') === s)); });
      writeParams({ state: s === 'signin' ? '' : s });
    };
    sw.hidden = false;
    $$('[data-state]', sw).forEach(function (b) { b.addEventListener('click', function () { show(b.getAttribute('data-state')); }); });
    show(readParam('state') || 'signin');
    $$('[data-signin]').forEach(function (btn) {
      var input = doc.getElementById(btn.getAttribute('data-signin'));
      var err = doc.getElementById(input.id + '-err');
      var submit = function () {
        var empty = !input.value.trim();
        err.hidden = !empty;
        input.setAttribute('aria-invalid', String(empty));
        if (empty) { input.focus(); return; }
        input.value = '';
        go(new URL('fleet.html', location.href).pathname, true);
      };
      btn.addEventListener('click', submit);
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') submit(); });
    });
    $('#retry-now').addEventListener('click', function () { $('#retry-status').textContent = 'Still trying to reach the workspace.'; });
  }
  }

  /* ---------- changing screen without unloading: the document stays, so the memory stays ---------- */
  var here = location.pathname, asked = 0;
  var leave = function () {
    if (life) life.abort();
    timers.forEach(clearTimeout); timers = [];
  };
  go = function (path, push, hash) {
    var mine = ++asked;
    fetch(path, { credentials: 'same-origin' }).then(function (r) {
      if (!r.ok) throw new Error(String(r.status));
      return r.text();
    }).then(function (html) {
      if (mine !== asked) return;
      var next = new DOMParser().parseFromString(html, 'text/html');
      if (!next.body || !next.getElementById('main')) throw new Error('not a screen');
      leave();
      if (push) history.pushState(null, '', path + (hash || ''));
      here = location.pathname;
      doc.title = next.title;
      body.className = next.body.className;
      body.replaceChildren.apply(body, Array.prototype.slice.call(next.body.childNodes).map(function (n) { return doc.adoptNode(n); }));
      var main = doc.getElementById('main');
      main.focus({ preventScroll: true });
      init();
      var mark = hash && doc.getElementById(hash.slice(1));
      if (mark) mark.scrollIntoView(); else window.scrollTo(0, 0);
    }).catch(function () { location.assign(path + (hash || '')); });
  };
  doc.addEventListener('click', function (e) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest && e.target.closest('a[href]');
    if (!a || a.target || a.origin !== location.origin || !/\.html$/.test(a.pathname)) return;
    if (a.pathname === location.pathname && a.hash) return;
    e.preventDefault();
    go(a.pathname, true, a.hash);
  });
  window.addEventListener('popstate', function () {
    if (location.pathname !== here) go(location.pathname, false, location.hash);
  });

  init();
})();
