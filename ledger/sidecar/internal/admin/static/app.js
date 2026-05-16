// Forum Points — Admin Console UI.
// Vanilla JS, no framework. Uses WebCrypto Ed25519 + PBKDF2 just like the wallet theme.

const API = "/wallet/admin/api";
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ----- utility: hex / base64 -----

function fromHex(h) {
  h = h.trim().replace(/\s+/g, "");
  if (h.length % 2) throw new Error("hex length odd");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i*2, 2), 16);
  return out;
}
function toHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2,"0")).join("");
}
function toBase64Url(b) {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/=+$/,"").replace(/\+/g,"-").replace(/\//g,"_");
}
function fmtNum(n) {
  if (n == null) return "—";
  return new Intl.NumberFormat("en-US").format(n);
}
function fmtTime(iso) {
  if (!iso) return "—";
  return iso.replace("T", " ").replace("Z", " UTC");
}

// ----- Ed25519 via WebCrypto -----
// Web Crypto's Ed25519 importKey expects PKCS#8. We wrap the raw 32-byte seed.

const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

async function ed25519FromSeed(seedBytes) {
  if (seedBytes.length !== 32) throw new Error("seed must be 32 bytes");
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seedBytes, ED25519_PKCS8_PREFIX.length);
  // import twice so we can also pull pubkey via export (one extractable, one not)
  const extr = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", extr);
  const pub = b64UrlToBytes(jwk.x);
  return { priv: extr, pub };
}
function b64UrlToBytes(s) {
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4) b += "=";
  const bin = atob(b);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Parse 64-byte Ed25519 private key (seed||pubkey) or 32-byte raw seed.
function parsePrivKey(hex) {
  const b = fromHex(hex);
  if (b.length === 32) return b;
  if (b.length === 64) return b.slice(0, 32);   // standard Ed25519 secret-key encoding
  throw new Error("expected 32 or 64 raw bytes (64 or 128 hex chars)");
}

// ----- API client -----

let CSRF_TOKEN = "";

async function api(method, path, body = null) {
  const opts = {
    method,
    credentials: "same-origin",
    headers: { "Accept": "application/json" },
  };
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && CSRF_TOKEN) {
    opts.headers["X-FP-CSRF"] = CSRF_TOKEN;
  }
  if (body !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(API + path, opts);
  let data; try { data = await resp.json(); } catch { data = null; }
  return { ok: resp.ok, status: resp.status, data };
}

// ----- LOGIN -----

async function doLogin() {
  const errEl = $("#login-error");
  errEl.textContent = "";
  const keyHex = $("#login-key").value.trim();
  if (!keyHex) { errEl.textContent = "Paste your private key first."; return; }

  let seed, keyPair;
  try {
    seed = parsePrivKey(keyHex);
    keyPair = await ed25519FromSeed(seed);
  } catch (e) {
    errEl.textContent = "Bad private key: " + e.message; return;
  }

  // Get challenge
  const ch = await api("GET", "/login-challenge");
  if (!ch.ok) { errEl.textContent = "Couldn't fetch challenge: " + (ch.data?.error || ch.status); return; }

  // Sign nonce bytes
  const nonceBytes = fromHex(ch.data.nonce_hex);
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", keyPair.priv, nonceBytes));

  // Submit
  const r = await api("POST", "/login", {
    token: ch.data.token,
    sig_hex: toHex(sig),
    pubkey_hex: toHex(keyPair.pub),
  });
  if (!r.ok) {
    errEl.textContent = "Login failed: " + (r.data?.error || r.status);
    return;
  }
  CSRF_TOKEN = r.data?.csrf_token || "";
  // Clear key from memory + DOM
  $("#login-key").value = "";
  seed.fill(0);
  bootMain(toHex(keyPair.pub));
}

async function logout() {
  await api("POST", "/logout");
  CSRF_TOKEN = "";
  location.reload();
}

// ----- main app boot -----

let CURRENT_PAGE = "dashboard";

async function bootMain(adminPubHex) {
  $("#login-view").hidden = true;
  $("#main-view").hidden = false;
  $("#me-pub").textContent = adminPubHex.slice(0, 12) + "…";
  const d = new Date();
  const fmt = d.toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" });
  const mh = $("#masthead-date");
  if (mh) mh.textContent = fmt;
  setupNav();
  await renderPage("dashboard");
}

function setupNav() {
  $$(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => renderPage(btn.dataset.route));
  });
  $("#logout-btn").addEventListener("click", logout);
}

async function renderPage(route) {
  CURRENT_PAGE = route;
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.route === route));
  $$(".page").forEach(p => p.hidden = (p.dataset.page !== route));
  switch (route) {
    case "dashboard": return renderDashboard();
    case "rewards":   return renderRewards();
    case "accounts":  return renderAccounts();
    case "txs":       return renderTxs();
    case "audit":     return renderAudit();
  }
}

// ----- DASHBOARD -----

async function renderDashboard() {
  const r = await api("GET", "/dashboard");
  if (!r.ok) return;
  const d = r.data;

  // Stats
  $("#stat-supply").textContent = fmtNum(d.supply_circulating);
  $("#stat-supply-sub").textContent =
    `cap ${fmtNum(d.supply_cap)} · ${d.supply_circulating === d.supply_cap ? "conserved" : "out of balance"}`;
  $("#stat-treasury").textContent = fmtNum(d.treasury_balance);
  const pctOut = d.supply_cap > 0 ? ((d.supply_cap - d.treasury_balance) / d.supply_cap * 100).toFixed(2) : "0";
  $("#stat-treasury-sub").textContent = `${pctOut}% in circulation`;
  $("#stat-activated").textContent = `${fmtNum(d.activated_count)} / ${fmtNum(d.account_count)}`;
  $("#stat-activated-sub").textContent = `${fmtNum(d.tx_count)} transactions of record`;

  // STH
  const sth = d.sth;
  const sthKv = $("#sth-kv");
  if (sth) {
    sthKv.innerHTML = `
      <dt>tree size</dt>    <dd>${fmtNum(sth.tree_size)}</dd>
      <dt>root hash</dt>    <dd>${sth.root_hash_hex}</dd>
      <dt>timestamp</dt>    <dd>${new Date(sth.timestamp_ms).toISOString()}</dd>
      <dt>admin pubkey</dt> <dd class="dim">${sth.admin_pubkey_hex}</dd>
    `;
    $("#sth-pill").textContent = "Live";
    $("#sth-pill").className = "pill";
    $("#sth-raw").textContent =
      `canonical = fp.sth.v1|${sth.tree_size}|${sth.root_hash_hex}|${sth.timestamp_ms}\n` +
      `signature = ${sth.admin_sig_hex}`;
  }

  // OTS
  const otsKv = $("#ots-kv");
  const otsPill = $("#ots-pill");
  otsKv.innerHTML = `
    <dt>last checkpoint</dt> <dd>${d.last_checkpoint_size ?? "(none)"}</dd>
    <dt>OTS receipt</dt>     <dd>${d.last_checkpoint_has_ots ? "stored — pending Bitcoin confirmation" : "not yet anchored"}</dd>
  `;
  if (d.last_checkpoint_has_ots) {
    otsPill.textContent = "Anchored";
    otsPill.className = "pill";
  } else {
    otsPill.textContent = "Unanchored";
    otsPill.className = "pill warn";
  }
}

// ----- REWARDS -----

async function renderRewards() {
  const r = await api("GET", "/reward-config");
  if (!r.ok) return;
  const list = $("#rewards-list");
  list.innerHTML = "";
  for (const cfg of r.data) {
    const row = document.createElement("div");
    row.className = "reward";
    const eventType = escapeHTML(cfg.event_type);
    row.innerHTML = `
      <div class="reward__name">
        ${eventType}
        <small>${describeEvent(cfg.event_type)}</small>
      </div>
      <div class="reward__amt">
        <input type="number" min="0" step="1" value="${cfg.amount}" data-field="amount">
        <span>pts</span>
      </div>
      <label class="reward__toggle">
        <input type="checkbox" ${cfg.enabled ? "checked" : ""} data-field="enabled">
        Enabled
      </label>
      <button class="reward__save" data-event="${cfg.event_type}">Save</button>
      <div class="reward__updated">Last updated ${fmtTime(cfg.updated_at)}</div>
    `;
    list.appendChild(row);
    row.querySelector(".reward__save").addEventListener("click", async () => {
      const amount = parseInt(row.querySelector('[data-field="amount"]').value, 10);
      const enabled = row.querySelector('[data-field="enabled"]').checked;
      if (!Number.isFinite(amount) || amount < 0) { alert("Amount must be ≥ 0"); return; }
      const resp = await api("POST", "/reward-config", { event_type: cfg.event_type, amount, enabled });
      if (!resp.ok) { alert("Save failed: " + (resp.data?.error || resp.status)); return; }
      renderRewards();
    });
  }
}

function describeEvent(type) {
  switch (type) {
    case "signup_bonus":    return "Paid once per Discourse user upon email activation.";
    case "first_post_ever": return "Lifetime first post bonus (across all topics).";
    case "quality_post":    return "Manually triggered (admin-tagged 'quality') per post.";
    default:                return "";
  }
}

// ----- ACCOUNTS -----

async function renderAccounts() {
  const r = await api("GET", "/accounts");
  const tbody = $("#accounts-table tbody");
  tbody.innerHTML = "";
  for (const a of r.data.accounts) {
    const tr = document.createElement("tr");
    const status = a.discourse_id === 0 ? `<span class="badge treasury">Treasury</span>`
                 : a.activated         ? `<span class="badge active">Activated</span>`
                                       : `<span class="badge pending">Pending</span>`;
    tr.innerHTML = `
      <td>${a.discourse_id}</td>
      <td>${escapeHTML(a.username)}</td>
      <td>${status}</td>
      <td class="right amt-pos">${fmtNum(a.balance)}</td>
      <td class="right">${a.nonce}</td>
      <td class="mono">${a.pubkey_hex ? a.pubkey_hex.slice(0, 16) + "…" : "—"}</td>
    `;
    tbody.appendChild(tr);
  }
}

// ----- TXS -----

async function renderTxs() {
  const r = await api("GET", "/recent-txs");
  const tbody = $("#txs-table tbody");
  tbody.innerHTML = "";
  for (const t of r.data.entries) {
    const tr = document.createElement("tr");
    const amtCls = t.tx_type === "transfer" ? "amt-pos" : "";
    const fromName = t.from_did === 0 ? "Treasury" : (t.from_name ? "@" + t.from_name : "—");
    const toName   = t.to_did === 0   ? "Treasury" : (t.to_name   ? "@" + t.to_name   : (t.to_did > 0 ? `#${t.to_did}` : "—"));
    const tag = t.reward_source ? `<small style="color:var(--ink-fade); margin-left: 0.4rem;">${escapeHTML(t.reward_source)}</small>` : "";
    tr.innerHTML = `
      <td>${t.leaf_index}</td>
      <td>${fmtTime(t.created_at)}</td>
      <td>${escapeHTML(t.tx_type)} ${tag}</td>
      <td>${escapeHTML(fromName)}</td>
      <td>${escapeHTML(toName)}</td>
      <td class="right ${amtCls}">${t.amount ? fmtNum(t.amount) : "—"}</td>
      <td class="mono">${t.tx_hash_hex.slice(0,12)}…</td>
    `;
    tbody.appendChild(tr);
  }
}

// ----- AUDIT -----

async function renderAudit() {
  await refreshAuditDigest();
  $("#audit-refresh").onclick = refreshAuditDigest;
  $("#audit-anchor").onclick = anchorDigest;
  $("#audit-copy").onclick = () => {
    const txt = $("#audit-digest").textContent;
    navigator.clipboard.writeText(txt);
    $("#audit-copy").textContent = "Copied";
    setTimeout(() => $("#audit-copy").textContent = "Copy digest", 1500);
  };
}
async function refreshAuditDigest() {
  const r = await api("GET", "/anchor-sth");
  if (!r.ok) {
    $("#audit-digest").textContent = "(error: " + (r.data?.error || r.status) + ")";
    return;
  }
  $("#audit-digest").textContent = r.data.digest_to_anchor;
}
async function anchorDigest() {
  const btn = $("#audit-anchor");
  btn.disabled = true;
  btn.textContent = "Anchoring...";
  const r = await api("POST", "/anchor-sth", {});
  btn.disabled = false;
  if (!r.ok) {
    $("#audit-digest").textContent = "(error: " + (r.data?.error || r.status) + ")";
    btn.textContent = "Anchor with OTS";
    return;
  }
  $("#audit-digest").textContent =
    `${r.data.digest_to_anchor}\nreceipt_bytes=${r.data.receipt_len}` +
    (r.data.already_anchored ? "\nstatus=already anchored" : "\nstatus=anchored");
  btn.textContent = r.data.already_anchored ? "Already anchored" : "Anchored";
  setTimeout(() => btn.textContent = "Anchor with OTS", 1800);
  await renderDashboard();
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]
  ));
}

// ----- entry -----

document.addEventListener("DOMContentLoaded", async () => {
  $("#login-btn").addEventListener("click", doLogin);
  $("#login-key").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) doLogin();
  });

  // Check if already authed
  const r = await api("GET", "/whoami");
  if (r.ok) {
    CSRF_TOKEN = r.data?.csrf_token || "";
    bootMain(r.data.admin_pubkey_hex);
  }
});
