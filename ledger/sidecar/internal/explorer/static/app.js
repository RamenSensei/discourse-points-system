// Forum Points — Public Explorer SPA.
// Vanilla JS, no framework. Reads its data from /wallet/api/v1/log/*.
// Verifies Ed25519 signatures and Merkle inclusion proofs client-side via Web Crypto.

const API   = "/wallet/api/v1";
const BASE  = "/wallet/explorer";
const $     = (s, root = document) => root.querySelector(s);
const main  = () => $("#main");

// ============================== UTILITIES ==============================

function escHTML(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
function fmtNum(n) {
  if (n == null) return "—";
  return new Intl.NumberFormat("en-US").format(n);
}
function fmtTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", " UTC");
}
function fmtTimeMs(ms) {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").replace(/\..*$/, " UTC");
}
function shortHash(h, n = 12) {
  if (!h) return "—";
  return h.length > n * 2 + 2 ? h.slice(0, n) + "…" + h.slice(-4) : h;
}
function fromHex(s) {
  if (!s) return new Uint8Array();
  if (s.length % 2) throw new Error("odd hex length");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}
function toHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}
async function sha256(...chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const buf = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}
async function apiGet(path) {
  const r = await fetch(API + path, { headers: { Accept: "application/json" } });
  if (!r.ok) {
    let body;
    try { body = await r.json(); } catch { body = { error: r.statusText }; }
    throw new Error(`HTTP ${r.status}: ${body.error || "unknown"}`);
  }
  return r.json();
}

function copyButton(text) {
  return `<button class="copy-btn" data-copy="${escHTML(text)}">Copy</button>`;
}

document.addEventListener("click", e => {
  const btn = e.target.closest(".copy-btn");
  if (!btn) return;
  navigator.clipboard.writeText(btn.dataset.copy);
  const orig = btn.textContent;
  btn.textContent = "Copied";
  setTimeout(() => (btn.textContent = orig), 1200);
});

// ============================== ROUTER ==============================

const ROUTES = [
  { rx: /^\/wallet\/explorer\/?$/,                 view: viewIndex   },
  { rx: /^\/wallet\/explorer\/tx\/([a-f0-9]{64})$/, view: viewTx,    arg: m => ({ hash: m[1] }) },
  { rx: /^\/wallet\/explorer\/leaf\/(\d+)$/,       view: viewLeaf,  arg: m => ({ idx: parseInt(m[1], 10) }) },
  { rx: /^\/wallet\/explorer\/sth\/(\d+)$/,        view: viewSTH,   arg: m => ({ size: parseInt(m[1], 10) }) },
  { rx: /^\/wallet\/explorer\/account\/(\d+)$/,    view: viewAccount, arg: m => ({ id: parseInt(m[1], 10) }) },
];

async function route() {
  const path = window.location.pathname;
  const params = new URLSearchParams(window.location.search);

  for (const r of ROUTES) {
    const m = path.match(r.rx);
    if (m) {
      const args = r.arg ? r.arg(m) : {};
      args.tab = params.get("tab");
      try {
        await r.view(args);
      } catch (e) {
        main().innerHTML = `<div class="error">${escHTML(e.message)}</div>`;
        console.error(e);
      }
      highlightNav(args.tab || "recent");
      return;
    }
  }
  main().innerHTML = `<div class="error">Not found: <code>${escHTML(path)}</code></div>`;
}

function highlightNav(tab) {
  document.querySelectorAll(".nav-item").forEach(n => {
    n.classList.toggle("active", n.dataset.tab === tab);
  });
}

function navigate(path) {
  window.history.pushState({}, "", path);
  route();
}
document.addEventListener("click", e => {
  const a = e.target.closest("a[href^='/wallet/explorer']");
  if (!a || a.target === "_blank") return;
  e.preventDefault();
  navigate(a.getAttribute("href"));
  window.scrollTo(0, 0);
});
window.addEventListener("popstate", route);

// ============================== VIEW: INDEX ==============================

async function viewIndex({ tab }) {
  if (tab === "checkpoints")  return viewCheckpoints();
  if (tab === "audit")        return viewAuditGuide();
  return viewRecent();
}

async function viewRecent() {
  main().innerHTML = `<div class="loading">Loading the latest entries…</div>`;
  const [sth, treasury, leavesResp] = await Promise.all([
    apiGet("/log/sth"),
    apiGet("/treasury"),
    apiGet("/log/leaves?from=0&to=10000"),  // fetch all; backend caps at 10k
  ]);
  const leaves = leavesResp.leaves.slice().reverse();  // newest first

  const stats = `
    <section class="stats">
      <div>
        <div class="stat__label">Tree size</div>
        <div class="stat__value">${fmtNum(sth.tree_size)}</div>
        <div class="stat__sub">${fmtTimeMs(sth.timestamp_ms)}</div>
      </div>
      <div>
        <div class="stat__label">Supply circulating</div>
        <div class="stat__value">${fmtNum(treasury.supply_circulating)}</div>
        <div class="stat__sub">cap ${fmtNum(treasury.supply_cap)} ${treasury.supply_ok ? "· conserved" : "· OUT OF BALANCE"}</div>
      </div>
      <div>
        <div class="stat__label">Treasury balance</div>
        <div class="stat__value">${fmtNum(treasury.treasury_balance)}</div>
        <div class="stat__sub">${((treasury.supply_cap - treasury.treasury_balance) / treasury.supply_cap * 100).toFixed(1)}% in circulation</div>
      </div>
      <div>
        <div class="stat__label">Current root</div>
        <div class="stat__value" style="font-family: var(--mono); font-size: 16px; word-break: break-all;">${shortHash(sth.root_hash_hex, 8)}</div>
        <div class="stat__sub">signed by admin</div>
      </div>
    </section>`;

  const rows = leaves.map(L => {
    const p = parseLeafPayload(L);
    const fromLabel = p.from_label ?? "—";
    const toLabel = p.to_label ?? "—";
    const amount = p.amount > 0 ? fmtNum(p.amount) : "—";
    const ampCls = p.amount > 0 ? "amt-pos" : "amt-zero";
    return `
      <tr class="clickable" data-href="${BASE}/tx/${L.tx_hash_hex}">
        <td><strong>#${L.leaf_index}</strong></td>
        <td>${fmtTime(L.created_at)}</td>
        <td><span class="tx-type ${escHTML(L.tx_type)}">${escHTML(L.tx_type)}</span></td>
        <td>${escHTML(fromLabel)}</td>
        <td>${escHTML(toLabel)}</td>
        <td class="right ${ampCls}">${amount}</td>
        <td class="mono">${shortHash(L.tx_hash_hex, 8)}</td>
      </tr>`;
  }).join("");

  main().innerHTML = `
    ${stats}
    <div class="page__head">
      <p class="kicker">Public Ledger</p>
      <h2 class="page__title">Recent Transactions</h2>
      <p class="dek">Every transfer of points since the genesis block, in reverse chronological order. Click any entry for its cryptographic proof of inclusion.</p>
    </div>
    <table class="table">
      <thead>
        <tr>
          <th>Leaf</th><th>When (UTC)</th><th>Type</th>
          <th>From</th><th>To</th><th class="right">Amount</th><th>tx_hash</th>
        </tr>
      </thead>
      <tbody>${rows || `<tr><td colspan="7" style="color:var(--ink-mute); padding: 2rem 0; text-align:center;">No transactions yet.</td></tr>`}</tbody>
    </table>`;

  // Row click → tx detail
  main().querySelectorAll("tr.clickable").forEach(tr => {
    tr.addEventListener("click", () => navigate(tr.dataset.href));
  });
}

// ============================== VIEW: CHECKPOINTS ==============================

async function viewCheckpoints() {
  main().innerHTML = `<div class="loading">Loading signed tree heads…</div>`;
  const resp = await apiGet("/log/checkpoints?limit=100");
  const cps = resp.checkpoints || [];
  const rows = cps.map(c => `
    <tr class="clickable" data-href="${BASE}/sth/${c.tree_size}">
      <td><strong>${c.tree_size}</strong></td>
      <td>${fmtTimeMs(c.timestamp_ms)}</td>
      <td class="mono">${shortHash(c.root_hash_hex, 10)}</td>
      <td>
        ${c.has_ots_receipt
          ? `<span class="anchor-status pending">Pending BTC</span>`
          : `<span class="anchor-status none">No anchor</span>`}
      </td>
    </tr>
  `).join("");
  main().innerHTML = `
    <div class="page__head">
      <p class="kicker">Public Ledger</p>
      <h2 class="page__title">Signed Tree Heads</h2>
      <p class="dek">Each checkpoint commits the entire ledger up to that point. Once anchored in Bitcoin, the history becomes immutable.</p>
    </div>
    <table class="table">
      <thead>
        <tr><th>Tree size</th><th>Signed at (UTC)</th><th>Root hash</th><th>BTC anchor</th></tr>
      </thead>
      <tbody>${rows || `<tr><td colspan="4" style="color:var(--ink-mute); padding: 2rem 0; text-align:center;">No checkpoints yet.</td></tr>`}</tbody>
    </table>`;
  main().querySelectorAll("tr.clickable").forEach(tr => {
    tr.addEventListener("click", () => navigate(tr.dataset.href));
  });
}

// ============================== VIEW: AUDIT GUIDE ==============================

function viewAuditGuide() {
  main().innerHTML = `
    <article class="article">
      <div class="article__head">
        <p class="article__kicker">Audit Manual</p>
        <h1 class="article__title">How to verify this ledger yourself</h1>
        <p class="article__byline">A four-step procedure that does <strong>not</strong> require trusting this server.</p>
      </div>

      <div class="section">
        <p class="kicker">Step 1</p>
        <h3>Run the verifier against the public API</h3>
        <pre>git clone &lt;repository&gt;; cd ledger/sidecar
go build ./cmd/ledger-verify
./ledger-verify -target https://forum.example.com/wallet -samples 100</pre>
        <p class="dek">The verifier replays every transaction, checks signatures and the prev-hash chain, recomputes the Merkle root, and tests random inclusion proofs.</p>
      </div>

      <div class="section">
        <p class="kicker">Step 2</p>
        <h3>Cross-check a signed tree head independently</h3>
        <p>Each STH is signed Ed25519 over the canonical string <code>fp.sth.v1|&lt;size&gt;|&lt;root&gt;|&lt;ts_ms&gt;</code>. Any Ed25519 library will verify it given the admin public key.</p>
      </div>

      <div class="section">
        <p class="kicker">Step 3</p>
        <h3>Confirm Bitcoin anchoring</h3>
        <p>Each daily checkpoint is timestamped via OpenTimestamps. Once Bitcoin confirms (typically within hours), the receipt becomes independently verifiable against the public blockchain forever — no trust in this server required.</p>
        <pre>ots upgrade checkpoint.ots
ots verify checkpoint.ots -f canonical-sth.txt</pre>
      </div>

      <div class="section">
        <p class="kicker">Step 4</p>
        <h3>Run a witness on a host you control</h3>
        <p>The witness daemon polls our log every 10 minutes, verifies each consistency proof, and latches a permanent alarm if it ever detects a rewrite or split-view attack.</p>
        <pre>./ledger-witness -target https://forum.example.com/wallet \\
                 -primary-pubkey &lt;our admin pubkey&gt; \\
                 -interval 10m</pre>
      </div>
    </article>`;
}

// ============================== VIEW: TX DETAIL ==============================

async function viewTx({ hash }) {
  main().innerHTML = `<div class="loading">Fetching transaction…</div>`;
  // We can't search by tx_hash directly via /log/leaves (it's by leaf_index).
  // Fetch all leaves and find the matching hash. Backend caps at 10k.
  const [sth, leavesResp] = await Promise.all([
    apiGet("/log/sth"),
    apiGet("/log/leaves?from=0&to=10000"),
  ]);
  const leaf = leavesResp.leaves.find(L => L.tx_hash_hex === hash);
  if (!leaf) {
    main().innerHTML = `<div class="error">Transaction <code>${escHTML(hash)}</code> not found.</div>`;
    return;
  }
  renderTxArticle(leaf, sth);
}

async function viewLeaf({ idx }) {
  main().innerHTML = `<div class="loading">Fetching leaf #${idx}…</div>`;
  const [sth, leavesResp] = await Promise.all([
    apiGet("/log/sth"),
    apiGet(`/log/leaves?from=${idx}&to=${idx + 1}`),
  ]);
  const leaf = leavesResp.leaves[0];
  if (!leaf) {
    main().innerHTML = `<div class="error">Leaf #${idx} not found.</div>`;
    return;
  }
  renderTxArticle(leaf, sth);
}

async function renderTxArticle(leaf, sth) {
  const p = parseLeafPayload(leaf);
  const headline = txHeadline(leaf, p);

  // Inclusion proof
  const proof = await apiGet(`/log/inclusion?leaf_index=${leaf.leaf_index}&tree_size=${sth.tree_size}`);

  // Permalink
  const permalink = `${window.location.origin}${BASE}/tx/${leaf.tx_hash_hex}`;

  // Earliest checkpoint covering this leaf
  const cps = (await apiGet("/log/checkpoints?limit=500")).checkpoints || [];
  const covering = cps
    .filter(c => c.tree_size >= leaf.leaf_index + 1)
    .sort((a, b) => a.tree_size - b.tree_size)[0];

  const metaRow = p.meta && Object.keys(p.meta).length > 0
    ? `<dt>Meta</dt><dd><code>${escHTML(JSON.stringify(p.meta, null, 0))}</code></dd>`
    : "";

  const prevRow = leaf.prev_hash_hex && leaf.prev_hash_hex !== "0".repeat(64)
    ? `<dt>Previous hash</dt><dd><span class="copy-row">${escHTML(leaf.prev_hash_hex)}${copyButton(leaf.prev_hash_hex)}</span></dd>`
    : "";

  main().innerHTML = `
    <article class="article">
      <div class="article__head">
        <p class="article__kicker">Transaction · Leaf #${leaf.leaf_index}</p>
        <h1 class="article__title">${headline.title}</h1>
        <p class="article__byline">${headline.byline}</p>
      </div>

      <dl class="detail-grid">
        <dt>Leaf index</dt><dd>#${leaf.leaf_index}</dd>
        <dt>Transaction hash</dt>
        <dd><span class="copy-row">${escHTML(leaf.tx_hash_hex)}${copyButton(leaf.tx_hash_hex)}</span></dd>
        <dt>Type</dt><dd class="serif"><span class="tx-type ${escHTML(leaf.tx_type)}">${escHTML(leaf.tx_type)}</span></dd>
        <dt>Committed at</dt><dd class="serif">${fmtTime(leaf.created_at)}</dd>
        ${p.amount > 0 ? `<dt>Amount</dt><dd class="big">${fmtNum(p.amount)} <span style="font-size: 14px; color: var(--ink-mute); font-style: italic;">pts</span></dd>` : ""}
        ${p.from_label ? `<dt>From</dt><dd class="serif">${escHTML(p.from_label)}</dd>` : ""}
        ${p.to_label ? `<dt>To</dt><dd class="serif">${escHTML(p.to_label)}</dd>` : ""}
        ${p.nonce != null ? `<dt>Nonce</dt><dd>${p.nonce}</dd>` : ""}
        ${metaRow}
        ${prevRow}
        <dt>Signer pubkey</dt>
        <dd><span class="copy-row">${escHTML(leaf.signer_hex)}${copyButton(leaf.signer_hex)}</span></dd>
        <dt>Signature</dt>
        <dd><span class="copy-row">${escHTML(leaf.sig_hex)}${copyButton(leaf.sig_hex)}</span></dd>
      </dl>

      <div class="section">
        <p class="kicker">Cryptographic Proof of Inclusion</p>
        <h3>Audit path against tree head at size ${sth.tree_size}</h3>
        <div class="proof-card">
          <h4>STH root we verify against</h4>
          <pre>${escHTML(sth.root_hash_hex)}</pre>
          <h4 style="margin-top:0.75rem;">Audit path (${proof.audit_path.length} hashes)</h4>
          ${proof.audit_path.length === 0
            ? `<pre>(empty — this is the only leaf in the tree)</pre>`
            : `<pre>${proof.audit_path.map(escHTML).join("\n")}</pre>`}
          <button class="action-btn" id="verify-inclusion">Verify in browser</button>
          <div class="verify-status" id="inclusion-status" style="display:none;"></div>
        </div>
      </div>

      ${covering ? `
        <div class="section">
          <p class="kicker">Earliest Tree Head Covering This Transaction</p>
          <h3>STH at size <a href="${BASE}/sth/${covering.tree_size}">${covering.tree_size}</a></h3>
          <dl class="detail-grid">
            <dt>Root hash</dt><dd>${escHTML(covering.root_hash_hex)}</dd>
            <dt>Signed at</dt><dd>${fmtTimeMs(covering.timestamp_ms)}</dd>
            <dt>Bitcoin anchor</dt>
            <dd>${covering.has_ots_receipt
              ? `<span class="anchor-status pending">OTS receipt stored · pending BTC confirmation</span>`
              : `<span class="anchor-status none">Not yet anchored</span>`}</dd>
          </dl>
        </div>
      ` : ""}

      <div class="permalink">
        <p>Permalink: <code><a href="${BASE}/tx/${leaf.tx_hash_hex}">${permalink}</a></code></p>
        <p>Raw JSON: <code><a target="_blank" href="${API}/log/leaves?from=${leaf.leaf_index}&to=${leaf.leaf_index + 1}">${API}/log/leaves?from=${leaf.leaf_index}&to=${leaf.leaf_index + 1}</a></code></p>
      </div>
    </article>`;

  // Wire the verify button
  $("#verify-inclusion").addEventListener("click", async () => {
    const status = $("#inclusion-status");
    status.style.display = "block";
    status.textContent = "Verifying…";
    status.classList.remove("fail");
    try {
      const ok = await verifyInclusion(
        leaf.tx_hash_hex,
        leaf.leaf_index,
        sth.tree_size,
        proof.audit_path,
        sth.root_hash_hex
      );
      if (ok) {
        status.textContent = `✓ Verified. This transaction is provably included in the tree of size ${sth.tree_size} with root ${shortHash(sth.root_hash_hex, 8)}.`;
      } else {
        status.classList.add("fail");
        status.textContent = "✗ Verification FAILED. The audit path does not reproduce the published root.";
      }
    } catch (e) {
      status.classList.add("fail");
      status.textContent = "✗ Error: " + e.message;
    }
  });
}

function txHeadline(leaf, p) {
  if (leaf.tx_type === "genesis") {
    return {
      title: "Genesis",
      byline: `The opening entry: <strong>${fmtNum(p.amount)}</strong> pts minted into the treasury, signed by the founding administrator key.`,
    };
  }
  if (leaf.tx_type === "rotate_key") {
    return {
      title: "Key rotation",
      byline: `An account changed its public key, signed by the previous one.`,
    };
  }
  if (leaf.tx_type === "transfer") {
    const verb = p.meta && p.meta.reward_source ? "Reward of" : "Transfer of";
    return {
      title: `${verb} ${fmtNum(p.amount)} pts`,
      byline: `From <strong>${escHTML(p.from_label || "—")}</strong> to <strong>${escHTML(p.to_label || "—")}</strong>` +
              (p.meta && p.meta.tip_target_post_id ? ` · re. post #${p.meta.tip_target_post_id}` : "") +
              `.`,
    };
  }
  return { title: leaf.tx_type, byline: "" };
}

function parseLeafPayload(leaf) {
  let payload = {};
  try {
    const b64 = leaf.payload_b64;
    const bin = atob(b64);
    payload = JSON.parse(bin);
  } catch (e) { /* ignore */ }
  const out = {
    amount: payload.amount || 0,
    nonce:  payload.nonce ?? null,
    meta:   payload.meta || null,
    from_label: null,
    to_label:   null,
  };
  if (leaf.tx_type === "genesis") {
    out.from_label = "—";
    out.to_label = "Treasury";
  } else if (leaf.tx_type === "transfer") {
    out.from_label = describeSigner(leaf, payload);
    out.to_label = payload.to_discourse_id === 0
      ? "Treasury"
      : `#${payload.to_discourse_id}` + (payload.meta?.tip_target_username ? ` (@${payload.meta.tip_target_username})` : "");
  } else if (leaf.tx_type === "rotate_key") {
    out.from_label = "(old key)";
    out.to_label = "(new key)";
  }
  return out;
}

function describeSigner(leaf, payload) {
  // We don't have a "from username" in the leaf record; fall back to short pubkey.
  // (For now — could enhance by joining against /balance/:id lookups.)
  if (leaf.signer_hex) return shortHash(leaf.signer_hex, 8);
  return "—";
}

// ============================== VIEW: STH DETAIL ==============================

async function viewSTH({ size }) {
  main().innerHTML = `<div class="loading">Fetching tree head at size ${size}…</div>`;
  const cps = (await apiGet(`/log/checkpoints?limit=500`)).checkpoints || [];
  const cp = cps.find(c => c.tree_size === size);
  if (!cp) {
    main().innerHTML = `<div class="error">No checkpoint at tree size ${size}.</div>`;
    return;
  }
  const currentSTH = await apiGet("/log/sth");
  const adminPubHex = currentSTH.admin_pubkey_hex;

  const canonical = `fp.sth.v1|${cp.tree_size}|${cp.root_hash_hex}|${cp.timestamp_ms}`;

  main().innerHTML = `
    <article class="article">
      <div class="article__head">
        <p class="article__kicker">Signed Tree Head</p>
        <h1 class="article__title">Tree head at size ${cp.tree_size}</h1>
        <p class="article__byline">Signed at <strong>${fmtTimeMs(cp.timestamp_ms)}</strong> by the system administrator.</p>
      </div>

      <dl class="detail-grid">
        <dt>Tree size</dt><dd class="big">${fmtNum(cp.tree_size)}</dd>
        <dt>Root hash</dt><dd><span class="copy-row">${escHTML(cp.root_hash_hex)}${copyButton(cp.root_hash_hex)}</span></dd>
        <dt>Timestamp (ms)</dt><dd>${cp.timestamp_ms} <span class="muted">(${fmtTimeMs(cp.timestamp_ms)})</span></dd>
        <dt>Admin signature</dt><dd><span class="copy-row">${escHTML(cp.admin_sig_hex)}${copyButton(cp.admin_sig_hex)}</span></dd>
        <dt>Admin pubkey</dt><dd><span class="copy-row">${escHTML(adminPubHex)}${copyButton(adminPubHex)}</span></dd>
      </dl>

      <div class="section">
        <p class="kicker">Cryptographic Verification</p>
        <h3>Signature over canonical bytes</h3>
        <div class="proof-card">
          <h4>Canonical message</h4>
          <pre>${escHTML(canonical)}</pre>
          <button class="action-btn" id="verify-sig">Verify signature in browser</button>
          <div class="verify-status" id="sig-status" style="display:none;"></div>
        </div>
      </div>

      <div class="section">
        <p class="kicker">Bitcoin Anchor</p>
        <h3>OpenTimestamps status</h3>
        <p class="dek">
          ${cp.has_ots_receipt
            ? "An OTS receipt has been submitted to a Bitcoin calendar. Once Bitcoin confirms, this tree head is provably anchored in the public blockchain — independently verifiable forever."
            : "No anchor yet. The next daily anchoring cycle will submit this tree head to OpenTimestamps."}
        </p>
        <div class="anchor-status ${cp.has_ots_receipt ? "pending" : "none"}">
          ${cp.has_ots_receipt ? "OTS receipt stored · pending BTC confirmation" : "Not anchored"}
        </div>
      </div>

      <div class="permalink">
        <p>Permalink: <code><a href="${BASE}/sth/${cp.tree_size}">${window.location.origin}${BASE}/sth/${cp.tree_size}</a></code></p>
      </div>
    </article>`;

  $("#verify-sig").addEventListener("click", async () => {
    const status = $("#sig-status");
    status.style.display = "block";
    status.classList.remove("fail");
    status.textContent = "Verifying…";
    try {
      const ok = await verifyEd25519(
        adminPubHex,
        new TextEncoder().encode(canonical),
        cp.admin_sig_hex
      );
      if (ok) {
        status.textContent = `✓ Signature is valid. The admin (${shortHash(adminPubHex, 6)}) committed to this exact tree head at the timestamp shown.`;
      } else {
        status.classList.add("fail");
        status.textContent = "✗ Signature is INVALID.";
      }
    } catch (e) {
      status.classList.add("fail");
      status.textContent = "✗ Error: " + e.message;
    }
  });
}

// ============================== VIEW: ACCOUNT ==============================

async function viewAccount({ id }) {
  main().innerHTML = `<div class="loading">Fetching account #${id}…</div>`;
  const [balance, history] = await Promise.all([
    apiGet(`/balance/${id}`),
    apiGet(`/history/${id}?limit=100`).catch(() => ({ entries: [] })),
  ]);
  const rows = (history.entries || []).map(e => `
    <tr class="clickable" data-href="${BASE}/leaf/${e.leaf_index}">
      <td><strong>#${e.leaf_index}</strong></td>
      <td>${fmtTime(e.created_at)}</td>
      <td><span class="tx-type ${escHTML(e.tx_type)}">${escHTML(e.tx_type)}</span></td>
      <td>${escHTML(e.kind || "—")}</td>
      <td>${escHTML(e.counterparty_name || "—")}</td>
      <td class="right amt-pos">${fmtNum(e.amount)}</td>
    </tr>
  `).join("");

  main().innerHTML = `
    <article class="article">
      <div class="article__head">
        <p class="article__kicker">Account · Discourse #${id}</p>
        <h1 class="article__title">${escHTML(balance.username || "Account #" + id)}</h1>
        <p class="article__byline">Current balance: <strong>${fmtNum(balance.balance)}</strong> pts. ${balance.activated ? "Activated." : "Not yet activated."}</p>
      </div>

      <table class="table">
        <thead>
          <tr><th>Leaf</th><th>When</th><th>Type</th><th>Direction</th><th>Counterparty</th><th class="right">Amount</th></tr>
        </thead>
        <tbody>${rows || `<tr><td colspan="6" style="color:var(--ink-mute); padding: 2rem 0; text-align:center;">No history.</td></tr>`}</tbody>
      </table>
    </article>`;

  main().querySelectorAll("tr.clickable").forEach(tr => {
    tr.addEventListener("click", () => navigate(tr.dataset.href));
  });
}

// ============================== CRYPTO: INCLUSION PROOF ==============================

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

// Mirrors internal/merkle/tree.go verifyDescend exactly:
// the proof is deepest-first; we walk top-down by recursive split, consuming
// proof elements from the END at each level.
async function verifyInclusion(txHashHex, leafIndex, treeSize, auditPathHex, expectedRootHex) {
  if (leafIndex < 0 || leafIndex >= treeSize) return false;
  const leafHash = await sha256(LEAF_PREFIX, fromHex(txHashHex));
  const proof = auditPathHex.map(fromHex);
  const result = await verifyDescend(leafHash, leafIndex, treeSize, proof);
  if (!result) return false;
  const [h, remaining] = result;
  if (remaining !== 0) return false;
  return toHex(h) === expectedRootHex;
}

async function verifyDescend(leafHash, index, size, proof) {
  if (size === 1) return [leafHash, proof.length];
  if (proof.length === 0) return null;
  const k = largestPowerOfTwoLessThan(size);
  const sibling = proof[proof.length - 1];
  const inner = proof.slice(0, -1);
  if (index < k) {
    const sub = await verifyDescend(leafHash, index, k, inner);
    if (!sub) return null;
    const h = await sha256(NODE_PREFIX, sub[0], sibling);
    return [h, sub[1]];
  }
  const sub = await verifyDescend(leafHash, index - k, size - k, inner);
  if (!sub) return null;
  const h = await sha256(NODE_PREFIX, sibling, sub[0]);
  return [h, sub[1]];
}

function largestPowerOfTwoLessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// ============================== CRYPTO: ED25519 VERIFY ==============================

async function verifyEd25519(pubHex, msgBytes, sigHex) {
  // Web Crypto's Ed25519 importKey for verification accepts the 32-byte raw pubkey.
  const pub = fromHex(pubHex);
  const key = await crypto.subtle.importKey(
    "raw",
    pub,
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify("Ed25519", key, fromHex(sigHex), msgBytes);
}

// ============================== SEARCH ==============================

$("#search-form").addEventListener("submit", e => {
  e.preventDefault();
  const q = $("#search-input").value.trim();
  if (!q) return;
  // Heuristics: 64-hex → tx_hash; "#NN" or "NN" → leaf; "@name" or numeric → account;
  // "sth NN" → STH.
  if (/^[a-f0-9]{64}$/i.test(q)) {
    return navigate(`${BASE}/tx/${q.toLowerCase()}`);
  }
  if (/^#?\d+$/.test(q)) {
    return navigate(`${BASE}/leaf/${q.replace("#", "")}`);
  }
  if (/^sth\s+\d+$/i.test(q)) {
    return navigate(`${BASE}/sth/${q.split(/\s+/)[1]}`);
  }
  // @username — we don't index usernames here; try as numeric account otherwise.
  alert(`Couldn't interpret "${q}". Try a 64-char hex tx_hash, "leaf 16", or "sth 42".`);
});

// ============================== BOOT ==============================

document.addEventListener("DOMContentLoaded", () => {
  const d = new Date();
  $("#masthead-date").textContent = d.toLocaleDateString("en-US",
    { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  route();
});
