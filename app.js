/* 帳差查詢（手機）
 * 資料：每天 22:30 由排程電腦的 acctdiff_update.py 產生、加密後推到這個 GitHub Pages。
 * 檔案格式和 991-pages 一樣：前 12 bytes IV ＋ AES-256-GCM 密文，明文是 gzip 過的 JSON。
 * 金鑰只在連結 # 後面（瀏覽器不會送給伺服器），第一次打開後記在這支手機。
 *   data/meta.enc            { v, updatedAt, parts, diffParts }
 *   data/<v>/<前 2 碼>.enc    { <索引>: { p: 件號, o: [{ o: 商品別, h: HOPES 2F／3F（null＝沒有）, w: WES 總和, s: [[儲位, 數量]],
 *                              l: 非自動倉的 HOPES 庫位, lh: 那個庫位的 HOPES 數量, x: [[發貨單號, 數量, WORKER, 分類]]（HOPES 暫存） }] } }
 * 索引＝HMAC-SHA256(索引金鑰, 件號)，索引金鑰＝HMAC-SHA256(金鑰, INDEX_LABEL)：沒有金鑰就算不出檔名。
 */
(function () {
  'use strict';

  var INDEX_LABEL = 'acct-diff/lookup-index/v1';
  var KEY_STORE = 'acctdiff.key';
  var RECENT_KEY = 'acctdiff.recent';
  var STALE_HOURS = 26;
  var KEY_ERROR = '連結不完整或已經換過，請跟幹部要新的連結';
  var OLD_BROWSER = '這個瀏覽器太舊，請改用新版 Safari、Chrome 或 Edge';

  var $ = function (id) { return document.getElementById(id); };
  var kw = $('kw'), result = $('result'), msg = $('msg'), go = $('go');
  var keys = null, meta = null, shardCache = {}, busy = 0;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function fmt(n) { return Number(n).toLocaleString('en-US'); }
  function signed(n) { return n > 0 ? '+' + fmt(n) : fmt(n); }
  function show(text, cls) { msg.className = 'msg ' + (cls || ''); msg.textContent = text || ''; }
  function store(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* 私密瀏覽：不記 */ } }
  function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }

  /* ---------- 金鑰：#<金鑰>；沒有 # 就用這支手機記住的 ---------- */
  function keyText() {
    var h = location.hash.slice(1).split(/[/?&]/)[0].trim();
    if (h) { store(KEY_STORE, h); history.replaceState(null, '', location.pathname + location.search); return h; }
    return load(KEY_STORE) || '';
  }
  function fail(text) { var e = new Error(text); e.lock = true; return e; }

  async function importKeys(text) {
    if (!window.crypto || !crypto.subtle || !window.DecompressionStream) throw fail(OLD_BROWSER);
    if (!text) throw fail('請用幹部給的連結打開');
    var raw;
    try { raw = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4)), function (c) { return c.charCodeAt(0); }); }
    catch (e) { throw fail(KEY_ERROR); }
    if (raw.length !== 32) throw fail(KEY_ERROR);
    var hmac = { name: 'HMAC', hash: 'SHA-256' };
    var aes = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    var base = await crypto.subtle.importKey('raw', raw, hmac, false, ['sign']);
    var idx = await crypto.subtle.sign('HMAC', base, new TextEncoder().encode(INDEX_LABEL));
    return { aes: aes, index: await crypto.subtle.importKey('raw', idx, hmac, false, ['sign']) };
  }

  async function fetchJson(path, noCache) {
    var res;
    try { res = await fetch(path + (noCache ? '?t=' + Date.now() : ''), { cache: noCache ? 'no-store' : 'default' }); }
    catch (e) { throw new Error('網路不穩，請再按一次查詢'); }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('讀不到資料（' + res.status + '），請再按一次查詢');
    var bytes = new Uint8Array(await res.arrayBuffer()), plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, keys.aes, bytes.slice(12)); }
    catch (e) { throw fail(KEY_ERROR); }
    var text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    return JSON.parse(text);
  }

  async function indexOf(value) {
    var sig = await crypto.subtle.sign('HMAC', keys.index, new TextEncoder().encode(value));
    return Array.from(new Uint8Array(sig)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  /* ---------- 資料時間 ---------- */
  function renderUpdate() {
    var t = $('updTime'), st = $('updState');
    if (!meta) { t.textContent = '資料時間：還沒有資料'; st.className = 'state bad'; st.textContent = '● 讀不到資料'; return; }
    t.textContent = '資料時間：' + meta.updatedAt;
    var at = new Date(meta.updatedAt.replace(/\//g, '-').replace(' ', 'T') + ':00+08:00');
    var stale = isNaN(at) || (Date.now() - at.getTime()) > STALE_HOURS * 3600 * 1000;
    st.className = 'state ' + (stale ? 'bad' : 'ok');
    st.textContent = stale ? '● 資料沒有更新，數字可能是舊的' : '● 每天 22:30 更新';
  }

  async function loadMeta(force) {
    if (meta && !force) return meta;
    var m = await fetchJson('data/meta.enc', true);
    if (m && (!meta || m.v !== meta.v)) shardCache = {};
    meta = m;
    renderUpdate();
    return meta;
  }

  function lock(text) {
    kw.disabled = true; go.disabled = true; $('kb').disabled = true;
    result.innerHTML = '';
    $('updTime').textContent = '資料時間：—';
    $('updState').className = 'state bad'; $('updState').textContent = '● 打不開資料';
    show(text, 'err');
    if (text === KEY_ERROR) store(KEY_STORE, null);
  }

  /* ---------- 查一個件號（不含商品別） ---------- */
  async function getPart(part) {
    var h = await indexOf(part), file = h.slice(0, 2);
    if (!shardCache[file]) {
      var data = await fetchJson('data/' + encodeURIComponent(meta.v) + '/' + file + '.enc', false);
      if (data === null) {   // 剛好換新資料：重讀 meta 再試一次
        await loadMeta(true);
        data = await fetchJson('data/' + encodeURIComponent(meta.v) + '/' + file + '.enc', false);
      }
      shardCache[file] = data || {};
    }
    var rec = shardCache[file][h];
    return rec && rec.p === part ? rec : null;
  }

  function norm(v) { return String(v || '').toUpperCase().replace(/[\s\-_.]/g, ''); }

  /* 先找完全一樣的件號；找不到、又超過 1 碼，就把第一碼當商品別再找（只顯示那個商品別） */
  async function lookup(q) {
    var rec = await getPart(q);
    if (rec) return { part: q, list: rec.o, only: '' };
    if (q.length > 1) {
      var c = q.charAt(0), r2 = await getPart(q.slice(1));
      if (r2) {
        var hit = r2.o.filter(function (x) { return x.o === c; });
        if (hit.length) return { part: r2.p, list: hit, only: c, all: r2.o.length };
      }
    }
    return null;
  }

  /* ---------- 畫面 ---------- */
  function diffOf(x) { return x.w - (x.h || 0); }
  /* 非自動倉零件：HOPES 庫位不是 2F／3F，而且 WES 沒有這個商品別的庫存 → 不比對帳差，只顯示庫位 */
  function isOther(x) { return x.l != null && x.h == null && !x.s.length; }

  function diffBox(diff, label) {
    var cls = diff === 0 ? 'ok' : diff > 0 ? 'more' : 'less';
    var say = diff === 0 ? '帳一致' : diff > 0 ? 'WES 比 HOPES 多 ' + fmt(diff) : 'WES 比 HOPES 少 ' + fmt(-diff);
    return '<div class="diff ' + cls + '"><div class="label">' + esc(label) + '</div><div class="num">' + (diff === 0 ? '0' : signed(diff)) + '</div><div class="say">' + say + '</div></div>';
  }

  function susBlock(x) {
    var list = x.x || [];
    if (!list.length) return '<div class="sus-none">HOPES 沒有暫存</div>';
    var total = list.reduce(function (t, r) { return t + r[1]; }, 0);
    return '<div class="sus"><div class="sus-head"><span>HOPES 暫存 ' + list.length + ' 筆</span><b>共 ' + fmt(total) + ' pcs</b></div>' +
      list.map(function (r) {
        return '<div class="sus-row"><div class="ship">' + esc(r[0]) + '</div><div class="qty">' + fmt(r[1]) + '<small>pcs</small></div>' +
          '<div class="meta"><span>' + esc(r[2]) + '</span>' + (r[3] ? '<span class="cat">' + esc(r[3]) + '</span>' : '') + '</div></div>';
      }).join('') + '</div>';
  }

  function head(part, x) {
    return '<div class="card-head"><div class="owner"><span class="tag">' + esc(x.o) + '</span>商品別</div><div class="pno">' + esc(x.o + part) + '</div></div>';
  }

  function otherCard(part, x) {
    return '<article class="card">' + head(part, x) +
      '<div class="loc-box"><div class="k">HOPES 庫位</div><div class="v">' + esc(x.l) + '</div><div class="s">不在自動倉，不比對 WES 帳</div></div>' +
      '<div class="books one"><div class="book"><div class="k">HOPES 庫存</div><div class="v">' + fmt(x.lh || 0) + '<small>pcs</small></div></div></div>' +
      susBlock(x) + '</article>';
  }

  function card(part, x) {
    if (isOther(x)) return otherCard(part, x);
    var notes = [];
    if (x.h == null && x.l != null) notes.push('HOPES 庫位是 ' + x.l + '（不是自動倉，' + fmt(x.lh || 0) + ' pcs），可是 WES 有庫存。');
    else if (x.h == null) notes.push('HOPES（2F、3F）沒有這個零件：可能放在別的樓層，或件號、商品別不同。');
    if (!x.s.length) notes.push('WES 沒有儲位：還沒上架，或在異常區、台車上。');
    return '<article class="card">' + head(part, x) +
      diffBox(diffOf(x), '帳差（WES 總和 − HOPES 總和）') +
      '<div class="books">' +
        '<div class="book"><div class="k">WES 庫存總和</div><div class="v">' + fmt(x.w) + '<small>pcs</small></div></div>' +
        '<div class="book"><div class="k">HOPES 庫存總和</div><div class="v">' + (x.h == null ? '—' : fmt(x.h)) + '<small>pcs</small></div></div>' +
      '</div>' + susBlock(x) +
      (x.s.length ? '<details class="pos"' + (x.s.length <= 3 ? ' open' : '') + '><summary>WES 儲位 ' + x.s.length + ' 格</summary><ul class="pos-list">' +
        x.s.map(function (p) { return '<li><span>' + esc(p[0]) + '</span><b>' + fmt(p[1]) + '</b></li>'; }).join('') + '</ul></details>' : '') +
      (notes.length ? '<div class="note">' + notes.map(esc).join('<br>') + '</div>' : '') +
    '</article>';
  }

  function render(r) {
    var n = r.list.length, auto = r.list.filter(function (x) { return !isOther(x); });
    var bad = auto.filter(function (x) { return diffOf(x) !== 0; });
    show(r.only
      ? '只顯示商品別 ' + r.only + (r.all > 1 ? '（這個件號共有 ' + r.all + ' 個商品別，輸入 ' + r.part + ' 可以全部看）' : '')
      : (n > 1 ? '這個件號有 ' + n + ' 個商品別，分開列' : ''), 'info');
    var html = !auto.length
      ? '<div class="verdict other"><div class="big">非自動倉零件</div><div class="small">庫位 ' +
          esc(r.list.map(function (x) { return x.l; }).filter(function (v, i, a) { return a.indexOf(v) === i; }).join('、')) + '</div></div>'
      : bad.length
      ? '<div class="verdict hand"><div class="big">有帳差<br>把零件交給幹部</div><div class="small">' +
          (n > 1 ? '商品別 ' + bad.map(function (x) { return x.o; }).join('、') + ' 有帳差' : '帳差 ' + signed(diffOf(bad[0]))) + '</div></div>'
      : '<div class="verdict fine"><div class="big">沒有帳差</div><div class="small">不用交給幹部</div></div>';
    html += r.list.map(function (x) { return card(r.part, x); }).join('');
    if (auto.length > 1 && !r.only) {
      var sum = auto.reduce(function (t, x) { return t + diffOf(x); }, 0);
      html += '<article class="card total"><div class="card-head"><div class="owner">' + auto.length + ' 個商品別合計</div></div>' +
        diffBox(sum, '合計帳差') +
        (bad.length && sum === 0 ? '<div class="note">各商品別有差、合計剛好 0：可能是商品別放錯（同件號、不同商品別互補）。</div>' : '') +
      '</article>';
    }
    result.innerHTML = html;
  }

  /* ---------- 輸入建議（同 991 查詢頁）：2 個字以上，列出含這幾個字的件號；開頭符合排前面，最多 10 筆 ---------- */
  var SUGGEST_MIN = 2, SUGGEST_LIMIT = 10;
  var sugBox = $('suggestList'), sug = { v: '', parts: null, loading: null };

  function hideSuggest() { sugBox.hidden = true; sugBox.innerHTML = ''; }

  async function loadSuggest() {
    if (!keys || !meta) return null;
    var v = meta.v;
    if (sug.v === v && (sug.parts || sug.loading)) return sug.loading || sug.parts;
    sug.v = v; sug.parts = null;
    sug.loading = (async function () {
      try {
        var list = await fetchJson('data/' + encodeURIComponent(v) + '/parts.enc', false);
        if (sug.v === v && Array.isArray(list)) sug.parts = list;
        return sug.parts;
      } catch (e) { return null; }     // 讀不到就不顯示建議，不影響查詢
      finally { if (sug.v === v) sug.loading = null; }
    })();
    var parts = await sug.loading;
    if (parts && document.activeElement === kw) renderSuggest();
    return parts;
  }

  function findSuggest(k) {
    var parts = sug.parts || [], starts = [], middle = [], nStart = 0;
    for (var i = 0; i < parts.length; i++) {
      var at = parts[i].indexOf(k);
      if (at === 0) { nStart++; if (starts.length < SUGGEST_LIMIT) starts.push(parts[i]); }
      else if (at > 0) middle.push({ p: parts[i], at: at });
    }
    middle.sort(function (a, b) { return a.at - b.at || (a.p < b.p ? -1 : a.p > b.p ? 1 : 0); });
    var room = Math.max(0, SUGGEST_LIMIT - starts.length);
    return { starts: starts, middle: middle.slice(0, room).map(function (x) { return x.p; }), more: nStart + middle.length > SUGGEST_LIMIT };
  }

  function mark(p, k) {
    var at = p.indexOf(k);
    return at < 0 ? esc(p) : esc(p.slice(0, at)) + '<mark>' + esc(p.slice(at, at + k.length)) + '</mark>' + esc(p.slice(at + k.length));
  }

  function renderSuggest() {
    var k = norm(kw.value);
    if (k.length < SUGGEST_MIN || !sug.parts) { hideSuggest(); return; }
    var f = findSuggest(k);
    // 找不到、而且第一碼可能是商品別（例如 A9091901234）：用後面的件號再找
    if (!f.starts.length && !f.middle.length && k.length > SUGGEST_MIN && /^[A-Z]/.test(k)) { k = k.slice(1); f = findSuggest(k); }
    if (!f.starts.length && !f.middle.length) { hideSuggest(); return; }
    if (f.starts.length === 1 && !f.middle.length && f.starts[0] === k) { hideSuggest(); return; }   // 已經打完整了
    function items(list) {
      return list.map(function (p) { return '<button class="suggest-item" type="button" role="option" data-q="' + esc(p) + '">' + mark(p, k) + '</button>'; }).join('');
    }
    var html = '';
    if (f.starts.length) html += '<div class="suggest-group">開頭符合</div>' + items(f.starts);
    if (f.middle.length) html += '<div class="suggest-group">中間符合</div>' + items(f.middle);
    if (f.more) html += '<div class="suggest-more">只列前 10 筆，多打幾個字可以縮小範圍</div>';
    sugBox.innerHTML = html;
    sugBox.hidden = false;
  }

  sugBox.addEventListener('pointerdown', function (e) { e.preventDefault(); });   // 點建議時輸入框不要先失去焦點
  kw.addEventListener('focus', function () { loadSuggest(); renderSuggest(); });
  kw.addEventListener('keydown', function (e) { if (e.key === 'Escape') hideSuggest(); });
  // iPhone 按鍵盤的「✓」只是收起鍵盤：失去焦點不收清單；點輸入框和清單以外的地方才收
  document.addEventListener('click', function (e) {
    if (sugBox.hidden || sugBox.contains(e.target) || e.target.closest('.input-wrap')) return;
    hideSuggest();
  });

  async function search(raw) {
    var q = norm(raw);
    hideSuggest();
    result.innerHTML = '';
    if (!q) { show('請輸入件號', 'err'); kw.focus(); return; }
    if (!keys) return;
    kw.value = q;
    var my = ++busy;
    go.disabled = true; show('查詢中…', 'info');
    try {
      await loadMeta(true);
      if (!meta) { show('還沒有資料，請晚一點再查', 'err'); return; }
      var r = await lookup(q);
      if (my !== busy) return;
      if (!r) { show('查無件號 ' + q + '（HOPES 和 WES 都沒有）', 'err'); return; }
      saveRecent(q);
      render(r);
      kw.blur();
    } catch (e) {
      if (my !== busy) return;
      if (e.lock) lock(e.message); else show(e.message || '查詢失敗，請再按一次', 'err');
    } finally {
      if (my === busy) go.disabled = kw.disabled;
    }
  }

  $('form').addEventListener('submit', function (e) { e.preventDefault(); search(kw.value); });
  kw.addEventListener('input', function () {
    var p = this.selectionStart; this.value = this.value.toUpperCase(); try { this.setSelectionRange(p, p); } catch (e) { /* 數字鍵盤不支援 */ }
    if (!sug.parts) loadSuggest();
    renderSuggest();
  });

  /* ---------- 鍵盤：預設數字，按 ABC 換英文 ---------- */
  $('kb').addEventListener('pointerdown', function (e) { e.preventDefault(); });
  $('kb').addEventListener('click', function () {
    var toText = kw.getAttribute('inputmode') !== 'text';
    kw.setAttribute('inputmode', toText ? 'text' : 'numeric');
    this.textContent = toText ? '123' : 'ABC';
    this.setAttribute('aria-label', toText ? '切換成數字鍵盤' : '切換成英文鍵盤');
    kw.blur(); kw.focus();
  });

  /* ---------- 最近查過（只存在這支手機） ---------- */
  function getRecent() { try { return JSON.parse(load(RECENT_KEY) || '[]'); } catch (e) { return []; } }
  function saveRecent(q) {
    var list = getRecent().filter(function (x) { return x !== q; });
    list.unshift(q);
    store(RECENT_KEY, JSON.stringify(list.slice(0, 6)));
    renderRecent();
  }
  function renderRecent() {
    $('recent').innerHTML = getRecent().map(function (x) { return '<button type="button" data-q="' + esc(x) + '">' + esc(x) + '</button>'; }).join('');
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-q]');
    if (!b || kw.disabled) return;
    kw.value = b.getAttribute('data-q');
    search(kw.value);
  });

  window.addEventListener('hashchange', function () { location.reload(); });

  /* ---------- 開始 ---------- */
  (async function () {
    renderRecent();
    try {
      keys = await importKeys(keyText());
      await loadMeta(true);
    } catch (e) {
      if (e.lock) lock(e.message); else { renderUpdate(); show(e.message, 'err'); }
    }
  })();
})();
