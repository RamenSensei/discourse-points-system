# Forum Points Ledger

Go sidecar for a non-invasive Discourse points ledger. It runs next to a
standard `discourse_docker` install and is exposed through one nginx proxy
location, normally `/wallet/`.

## What It Provides

- Fixed-supply point ledger with Ed25519-signed transfers.
- Postgres-backed balances with a conservation invariant.
- Public balance, history, treasury, and Merkle-log APIs.
- DiscourseConnect login for wallet sessions.
- Optional Discourse webhooks for automatic rewards.
- Admin web UI with Ed25519 challenge-response login.
- Optional OpenTimestamps anchoring and witness process.

## Quick Start

```bash
cp .env.example .env
docker compose run --rm --entrypoint ledger-admin sidecar keygen
```

Paste the generated `ADMIN_PUBKEY_HEX` into `.env`. Store
`ADMIN_PRIV_KEY_HEX` in a password manager; set it in `.env` only when you need
genesis, automatic rewards, STH signing, or admin CLI actions.

```bash
docker compose up -d --build
docker compose logs -f sidecar
```

Initialize the fixed supply:

```bash
docker compose exec sidecar ledger-admin init --memo "genesis"
```

Smoke check from the host:

```bash
curl -s http://127.0.0.1:18080/api/v1/health
curl -s http://127.0.0.1:18080/api/v1/treasury
```

## Discourse Nginx Hook

For a typical `discourse_docker` standalone install, add this to
`/var/discourse/containers/app.yml` under `hooks:`.

```yaml
hooks:
  after_web_config:
    - file:
        path: /etc/nginx/conf.d/outlets/server/40-wallet.conf
        contents: |
          location /wallet/ {
            proxy_pass http://172.17.0.1:18080/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
          }
```

Then rebuild Discourse:

```bash
cd /var/discourse
./launcher rebuild app
```

If your Discourse container cannot reach `172.17.0.1`, set
`LEDGER_BIND_ADDR` in `.env` and use the matching address in `proxy_pass`.

## Discourse Settings

Enable DiscourseConnect Provider:

- `enable discourse connect provider`: true
- `discourse connect provider secrets`: map
  `forum.example.com/wallet/auth/discourse/callback*` to the
  `DISCOURSE_CONNECT_SECRET` from `.env`

Optional webhook for rewards:

- Payload URL: `https://forum.example.com/wallet/api/v1/hooks/discourse`
- Secret: `DISCOURSE_WEBHOOK_SECRET`
- Content type: `application/json`
- Events: user activation and post creation

## Public API

When mounted at `/wallet/`, these become visible under
`https://forum.example.com/wallet/...`.

| Route | Auth | Purpose |
|---|---|---|
| `GET /api/v1/health` | none | liveness |
| `GET /api/v1/balance/{id}` | none | public account balance |
| `GET /api/v1/history/{id}` | none | public account history |
| `GET /api/v1/treasury` | none | supply and treasury status |
| `GET /api/v1/me` | wallet session | current user's account |
| `POST /api/v1/me/register` | wallet session | bind wallet public key |
| `POST /api/v1/tx` | signed tx | submit transfer |
| `POST /api/v1/hooks/discourse` | webhook HMAC | automatic rewards |
| `GET /api/v1/log/*` | none | Merkle log and proofs |
| `GET /explorer/` | none | public ledger explorer |
| `GET /admin/` | admin signature | admin console |

## Operations

```bash
make test
make build
docker compose logs -f sidecar
docker compose exec postgres pg_dump -U ledger ledger > backup.sql
cd sidecar && go run ./cmd/ledger-verify -target https://forum.example.com/wallet -samples 100
```

## Security Notes

- Do not commit `.env`, `.admin-key`, database dumps, or generated private keys.
- Leave `WALLET_ALLOW_HEADER_AUTH` empty in production.
- Keep `ADMIN_PRIV_KEY_HEX` offline where possible.
- Run a witness on another host if split-view resistance matters.
- Public balance and history endpoints are intentionally public.
