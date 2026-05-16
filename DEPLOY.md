# Deployment Guide

This guide assumes a standard Discourse standalone install using
`discourse_docker`.

Replace `forum.example.com` with your forum domain.

## 1. Prepare Secrets

On a trusted machine:

```bash
cd ledger
docker compose run --rm --entrypoint ledger-admin sidecar keygen
```

Record:

- `ADMIN_PUBKEY_HEX` - public key, safe to put in `.env`
- `ADMIN_PRIV_KEY_HEX` - private key, keep offline when possible
- `REWARD_PRIV_KEY_HEX` - optional hot key for automatic rewards
- `STH_PRIV_KEY_HEX` - optional hot key for signed tree heads and OTS anchoring

On the Discourse host:

```bash
cd /opt
git clone <your-repo-url> discourse-forum-points
cd discourse-forum-points/ledger
cp .env.example .env
```

Edit `.env`:

```dotenv
PG_PASSWORD=<random 24+ char value>
FORUM_BASE_URL=https://forum.example.com
ADMIN_PUBKEY_HEX=<from keygen>
ADMIN_PRIV_KEY_HEX=<from keygen, required for genesis and auto rewards>
REWARD_PRIV_KEY_HEX=<prefer a separate reward hot key in production>
STH_PRIV_KEY_HEX=<prefer a separate STH hot key in production>
ADMIN_SESSION_SECRET=<openssl rand -hex 32>
DISCOURSE_CONNECT_SECRET=<openssl rand -hex 32>
DISCOURSE_WEBHOOK_SECRET=<openssl rand -hex 32>
OTS_CALENDAR_URL=https://a.pool.opentimestamps.org/digest
OTS_CALENDAR_ALLOWLIST=
WALLET_RATE_LIMIT_PER_MINUTE=600
WALLET_RATE_LIMIT_BURST=120
TREASURY_USERNAME=TREASURY
```

## 2. Start the Sidecar

```bash
docker compose up -d --build
docker compose logs -f sidecar
```

Expected log lines include `migrations OK` and `listening on 0.0.0.0:18080`.

Initialize the treasury:

```bash
docker compose exec sidecar ledger-admin init --memo "genesis"
```

Local check:

```bash
curl -s http://127.0.0.1:18080/api/v1/health
curl -s http://127.0.0.1:18080/api/v1/treasury
```

## 3. Add Discourse Nginx Proxy

Edit `/var/discourse/containers/app.yml`:

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
            proxy_http_version 1.1;
            proxy_set_header Connection "";
          }
```

Rebuild:

```bash
cd /var/discourse
./launcher rebuild app
```

Public check:

```bash
curl -s https://forum.example.com/wallet/api/v1/health
```

## 4. Configure DiscourseConnect

In Discourse admin:

1. Settings -> Login
2. Enable `enable discourse connect provider`
3. Add a provider secret:
   - Key: `forum.example.com/wallet/auth/discourse/callback*`
   - Value: `DISCOURSE_CONNECT_SECRET` from `.env`

Restart the sidecar if `.env` changed:

```bash
docker compose restart sidecar
```

## 5. Configure Webhooks

This is optional. It enables automatic signup and first-post rewards.

In Discourse admin:

- Payload URL: `https://forum.example.com/wallet/api/v1/hooks/discourse`
- Content type: `application/json`
- Secret: `DISCOURSE_WEBHOOK_SECRET`
- Events: user activation and post creation
- TLS verification: enabled

Click ping/test and confirm a 200 response.

## 6. Install the Theme Component

From Discourse admin:

1. Customize -> Themes -> Install
2. Install from the `theme/` directory repository, or upload a tarball:

```bash
cd theme
tar -czf /tmp/forum-points-theme.tar.gz about.json README.md common javascripts locales
```

3. Add the component to your active theme.

## 7. Verify User Flow

- Log in as a normal user.
- Visit `/wallet/auth/discourse/login` once if the wallet session is missing.
- Open a topic and confirm balances appear beside post avatars.
- Open a user card and confirm the balance badge appears.
- Tip another user's post.
- Confirm `/wallet/explorer/account/<id>` shows the transaction.
- In `/wallet/admin/`, open Audit and use "Anchor with OTS"; or run
  `docker compose exec sidecar ledger-admin anchor-sth`.

## 8. Optional Witness

Run the witness on a different host:

```bash
cd ledger/sidecar
go build -o /usr/local/bin/ledger-witness ./cmd/ledger-witness

/usr/local/bin/ledger-witness \
  -target https://forum.example.com/wallet \
  -primary-pubkey <ADMIN_PUBKEY_HEX> \
  -key /etc/forum-points-witness/witness.key \
  -state /var/lib/forum-points-witness/state.json \
  -interval 10m \
  -listen 127.0.0.1:18090
```

The witness raises a permanent alarm if the primary log rewinds, forks, or
fails consistency checks.
