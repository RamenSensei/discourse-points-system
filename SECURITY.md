# Security Policy

## Reporting

Do not open a public issue for a vulnerability that exposes keys, authentication
bypass, ledger forgery, or private data. Report privately to the project
maintainer for your fork or deployment.

## Secrets

Never commit:

- `.env`
- `.admin-key`
- `ADMIN_PRIV_KEY_HEX`
- Discourse API keys
- Discourse webhook secrets
- database dumps
- generated backups

The root `.gitignore` is written to exclude these by default.

## Threat Model

Defended:

- Forged user transfers: Ed25519 signatures and monotonic nonces.
- Accidental minting: fixed genesis and supply-conservation checks.
- Transaction replay: per-account nonce checks.
- Public audit drift: Merkle log, signed tree heads, and verifier CLI.
- Webhook spoofing: HMAC verification.

Not fully defended:

- Operator censorship: the operator can refuse to relay transactions.
- Admin key compromise: a leaked admin private key controls treasury actions.
- Browser compromise/XSS: a compromised browser can sign as the user.
- Split view without witnesses: run an independent witness for stronger audit.

## Production Rules

- Leave `WALLET_ALLOW_HEADER_AUTH` empty in production.
- Use HTTPS only.
- Set `ADMIN_SESSION_SECRET` to at least 32 random bytes.
- Store `ADMIN_PRIV_KEY_HEX` offline unless automatic rewards/STH signing need
  it in the sidecar environment.
- Rotate Discourse webhook and DiscourseConnect secrets after any suspected
  leak.
- Back up Postgres regularly and test restores.

## Public Data

Balances, account histories, transactions, and Merkle proofs are public by
design. Do not deploy this system if balance privacy is a requirement without
first changing the API and theme assumptions.
