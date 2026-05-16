export const WALLET_BASE = "/wallet/api/v1";
export const AUTH_LOGIN = "/wallet/auth/discourse/login";
export const BALANCE_CHANGED_EVENT = "fp:balance-changed";

const POINTS_FORMATTER = new Intl.NumberFormat("en-US");
const BALANCE_CACHE = new Map(); // discourse_id -> { account, ts }
const BALANCE_IN_FLIGHT = new Map(); // discourse_id -> Promise<account>
const BALANCE_BATCH_QUEUE = new Map(); // discourse_id -> { resolve, reject }
let BALANCE_BATCH_TIMER = null;
const BALANCE_CACHE_TTL_MS = 30_000;

export function formatPoints(value) {
  if (value == null || value === "") {
    return "0";
  }
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "0";
  }
  return POINTS_FORMATTER.format(n);
}

export function walletLoginUrl(returnUrl = window.location.href) {
  return `${AUTH_LOGIN}?return=${encodeURIComponent(returnUrl)}`;
}

export function walletAccountUrl(discourseId) {
  const id = Number(discourseId);
  if (!Number.isInteger(id) || id <= 0) {
    return "/wallet/explorer/";
  }
  return `/wallet/explorer/account/${id}`;
}

export function explorerTxUrl(txHashHex, leafIndex) {
  if (txHashHex) {
    return `/wallet/explorer/tx/${txHashHex}`;
  }
  return `/wallet/explorer/leaf/${leafIndex}`;
}

export function invalidateBalances(ids) {
  if (!ids || ids.length === 0) {
    BALANCE_CACHE.clear();
    BALANCE_IN_FLIGHT.clear();
    return;
  }

  for (const id of ids) {
    const normalized = Number(id);
    BALANCE_CACHE.delete(normalized);
    BALANCE_IN_FLIGHT.delete(normalized);
  }
}

export async function fetchAccount(discourseId, { force = false } = {}) {
  const id = Number(discourseId);
  if (!Number.isInteger(id) || id <= 0) {
    throw new Error("bad user id");
  }

  const now = Date.now();
  const cached = BALANCE_CACHE.get(id);
  if (!force && cached && now - cached.ts < BALANCE_CACHE_TTL_MS) {
    return cached.account;
  }

  if (BALANCE_IN_FLIGHT.has(id)) {
    return BALANCE_IN_FLIGHT.get(id);
  }

  if (force) {
    BALANCE_CACHE.delete(id);
  }

  const request = queueAccountFetch(id);

  BALANCE_IN_FLIGHT.set(id, request);

  try {
    return await request;
  } finally {
    BALANCE_IN_FLIGHT.delete(id);
  }
}

function queueAccountFetch(id) {
  return new Promise((resolve, reject) => {
    BALANCE_BATCH_QUEUE.set(id, { resolve, reject });
    if (BALANCE_BATCH_TIMER) {
      return;
    }
    BALANCE_BATCH_TIMER = setTimeout(flushAccountBatch, 0);
  });
}

async function flushAccountBatch() {
  const batch = Array.from(BALANCE_BATCH_QUEUE.entries());
  BALANCE_BATCH_QUEUE.clear();
  BALANCE_BATCH_TIMER = null;

  const ids = batch.map(([id]) => id);
  const callbacks = new Map(batch);
  try {
    const resp = await jsonFetch(`${WALLET_BASE}/balances`, {
      method: "POST",
      body: JSON.stringify({ discourse_ids: ids }),
    });
    if (!resp.ok || !Array.isArray(resp.data?.accounts)) {
      throw new Error(resp.data?.error ?? `HTTP ${resp.status}`);
    }
    const seen = new Set();
    for (const raw of resp.data.accounts) {
      const account = normalizeAccount(raw);
      seen.add(account.discourse_id);
      BALANCE_CACHE.set(account.discourse_id, { account, ts: Date.now() });
      callbacks.get(account.discourse_id)?.resolve(account);
    }
    for (const id of ids) {
      if (!seen.has(id)) {
        const account = zeroAccount(id);
        BALANCE_CACHE.set(id, { account, ts: Date.now() });
        callbacks.get(id)?.resolve(account);
      }
    }
  } catch (err) {
    await Promise.all(ids.map(async (id) => {
      try {
        callbacks.get(id)?.resolve(await fetchAccountFallback(id));
      } catch (fallbackErr) {
        callbacks.get(id)?.reject(fallbackErr || err);
      }
    }));
  }
}

async function fetchAccountFallback(id) {
  const resp = await jsonFetch(`${WALLET_BASE}/balance/${id}`);
  if (!resp.ok) {
    throw new Error(resp.data?.error ?? `HTTP ${resp.status}`);
  }
  const account = normalizeAccount({ ...resp.data, discourse_id: id });
  BALANCE_CACHE.set(id, { account, ts: Date.now() });
  return account;
}

function normalizeAccount(raw) {
  const id = Number(raw?.discourse_id);
  if (!Number.isInteger(id) || id <= 0) {
    return zeroAccount(id);
  }
  return {
    discourse_id: id,
    username: raw?.username ?? "",
    balance: raw?.balance ?? 0,
    registered: Boolean(raw?.registered),
    activated: Boolean(raw?.activated),
  };
}

function zeroAccount(id) {
  return {
    discourse_id: id,
    username: "",
    balance: 0,
    registered: false,
    activated: false,
  };
}

export async function jsonFetch(url, opts = {}) {
  const headers = {
    Accept: "application/json",
    ...(opts.body ? { "Content-Type": "application/json" } : {}),
    ...(opts.headers ?? {}),
  };

  const resp = await fetch(url, {
    credentials: "same-origin",
    ...opts,
    headers,
  });

  let data = null;
  try {
    data = await resp.json();
  } catch {
    data = null;
  }

  return { ok: resp.ok, status: resp.status, data };
}
