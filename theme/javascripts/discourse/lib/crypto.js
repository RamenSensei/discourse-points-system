// Web Crypto primitives for forum-points.
//
// Key model:
//   seed = PBKDF2(password, salt = "fp.v1." + discourse_id, iter = 600_000, hash = SHA-256, len = 32B)
//   privKey = Ed25519 seed
//   pubKey  = derived
//
// All payloads are canonical JSON matching Go server's encoding/json with
// SetEscapeHTML(false), struct field order, and alphabetically-sorted map keys.

const PBKDF2_ITERATIONS = 600_000;
const KDF_VERSION = "v1";

// -- base64 helpers (standard alphabet, padded; matches Go encoding/base64.StdEncoding) --

export function toBase64Std(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromBase64Std(s) {
  if (typeof s !== "string") {
    throw new Error("base64 input must be a string");
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s) {
  if (typeof s !== "string") {
    throw new Error("hex input must be a string");
  }
  if (s.length % 2 !== 0) throw new Error("hex length not even");
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error("invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substr(i * 2, 2), 16);
  }
  return out;
}

// -- KDF: PBKDF2-SHA256 -> 32-byte seed --

export async function deriveSeed(password, discourseId) {
  if (!password) throw new Error("empty password");
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto subtle not available; HTTPS is required");
  }
  const enc = new TextEncoder();
  const salt = enc.encode(`fp.${KDF_VERSION}.${discourseId}`);
  const passKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const seedBuf = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    passKey,
    256,
  );
  return new Uint8Array(seedBuf);
}

// -- Ed25519 keypair from 32-byte seed --
//
// Web Crypto's Ed25519 (Chrome 113+, Firefox 130+, Safari 17+) imports a raw
// 32-byte seed via PKCS#8. We wrap the seed in the minimal PKCS#8 prefix that
// RFC 8410 / RFC 5958 define for Ed25519 keys.

const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

function seedToPkcs8(seed) {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const out = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  out.set(ED25519_PKCS8_PREFIX, 0);
  out.set(seed, ED25519_PKCS8_PREFIX.length);
  return out;
}

export async function ed25519KeysFromSeed(seed) {
  if (!("subtle" in crypto)) {
    throw new Error("WebCrypto subtle not available — secure context required (HTTPS)");
  }
  // importKey for Ed25519 needs Chrome 113+/FF 130+/Safari 17+
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    seedToPkcs8(seed),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  // Derive the public key by signing a probe? No — Web Crypto doesn't expose pub from priv
  // directly. Instead, recompute the public key from the seed via a separate import:
  const pubJwk = await pubKeyFromSeed(seed);
  return { privKey: priv, pubKey: pubJwk };
}

// Compute the Ed25519 public key for a 32-byte seed.
//
// Trick: encode the seed as a SubjectPublicKeyInfo and let the browser parse it? No —
// the SPKI requires the public point, not the seed. We need real Ed25519 scalar-mult.
//
// We piggyback on `crypto.subtle.exportKey('jwk', priv)` which (per Web Crypto spec)
// returns the JWK including both d (seed) and x (public point), even though the key
// was imported as non-extractable. Wait — non-extractable forbids export. So we have
// to import the priv key as extractable in this helper, export, take the x, then drop.
async function pubKeyFromSeed(seed) {
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    seedToPkcs8(seed),
    { name: "Ed25519" },
    true, // extractable, ONLY in this short-lived scope
    ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  if (!jwk.x) throw new Error("JWK missing public x");
  // jwk.x is base64url-encoded 32-byte pubkey
  return base64UrlToBytes(jwk.x);
}

function base64UrlToBytes(s) {
  // base64url -> base64 std (re-pad)
  let b = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b.length % 4) b += "=";
  return fromBase64Std(b);
}

export async function sign(privKey, payloadBytes) {
  const sig = await crypto.subtle.sign("Ed25519", privKey, payloadBytes);
  return new Uint8Array(sig);
}

// -- canonical JSON matching Go's encoding/json defaults --
//
// Rules:
//   - struct field order is fixed by the caller building the object in declared order
//   - maps with string keys: keys sorted alphabetically
//   - SetEscapeHTML(false): &, <, > NOT escaped to \u00XX
//   - byte arrays are base64-std-encoded (Go default for []byte)
//
// JSON.stringify in V8/SpiderMonkey/JavaScriptCore preserves insertion order for
// string-keyed objects, so as long as the caller inserts in canonical order, the
// resulting bytes are deterministic.

export function canonicalJsonBytes(obj) {
  return new TextEncoder().encode(canonicalJsonString(obj));
}

export function canonicalJsonString(obj) {
  return JSON.stringify(canonicalize(obj));
}

function canonicalize(v) {
  if (v === null || v === undefined) return v;
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v instanceof Uint8Array) return toBase64Std(v);
  if (typeof v === "object") {
    // Plain object — sort keys (matches Go map<string,any> behavior)
    const sorted = {};
    for (const k of Object.keys(v).sort()) {
      sorted[k] = canonicalize(v[k]);
    }
    return sorted;
  }
  return v;
}

// canonicalJsonStruct builds an object with FIXED insertion order (for Go structs,
// which serialize fields in declared order, NOT alphabetical). Use this for the
// outer payload struct; nested map<string,any> values are canonicalized internally.
export function canonicalJsonStruct(orderedPairs) {
  const obj = {};
  for (const [k, v] of orderedPairs) {
    if (v === undefined) continue;
    obj[k] = (v instanceof Uint8Array)
      ? toBase64Std(v)
      : canonicalize(v);
  }
  return new TextEncoder().encode(JSON.stringify(obj));
}

// Encrypted-IndexedDB session cache: stores derived priv-seed for the current session
// so the user doesn't have to re-type the password on every tip click.
//
// We wrap the seed in AES-GCM under a key derived from the same password (additional
// PBKDF2 run with a different salt). On reload, the seed is unrecoverable without
// the password. Lifetime is single browser tab; closing the tab clears the cache.

const SESSION_DB = "fp-session";
const SESSION_STORE = "seed";

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(SESSION_DB, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(SESSION_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function deriveWrapKey(password, discourseId) {
  const enc = new TextEncoder();
  const salt = enc.encode(`fp.wrap.${KDF_VERSION}.${discourseId}`);
  const passKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    passKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function cacheSeed(discourseId, password, seed) {
  const wrapKey = await deriveWrapKey(password, discourseId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, seed));
  const db = await openDB();
  const tx = db.transaction(SESSION_STORE, "readwrite");
  tx.objectStore(SESSION_STORE).put({ iv, ct, ts: Date.now() }, discourseId);
  await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
  db.close();
}

export async function loadCachedSeed(discourseId, password) {
  const db = await openDB();
  const tx = db.transaction(SESSION_STORE, "readonly");
  const req = tx.objectStore(SESSION_STORE).get(discourseId);
  const stored = await new Promise((res, rej) => {
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
  db.close();
  if (!stored) return null;
  try {
    const wrapKey = await deriveWrapKey(password, discourseId);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: stored.iv }, wrapKey, stored.ct);
    return new Uint8Array(pt);
  } catch {
    return null; // wrong password or tampered
  }
}

export async function clearCachedSeed(discourseId) {
  const db = await openDB();
  const tx = db.transaction(SESSION_STORE, "readwrite");
  tx.objectStore(SESSION_STORE).delete(discourseId);
  await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = () => rej(tx.error); });
  db.close();
}
