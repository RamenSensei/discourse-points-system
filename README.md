# Discourse Forum Points

Open-source, non-invasive points system for Discourse.

It runs as a sidecar service next to Discourse and integrates through a
Discourse theme component. Discourse core is not patched.

## Components

- `ledger/` - Go sidecar, Postgres schema, admin CLI, public explorer, admin UI.
- `theme/` - Discourse theme component for balances, tipping, and wallet links.

## What It Does

- Maintains a fixed-supply forum points ledger.
- Uses Ed25519 signatures for transfers.
- Stores an append-only transaction log with Merkle proofs.
- Exposes public audit endpoints for balances, history, treasury status, and
  signed tree heads.
- Reuses Discourse identity through DiscourseConnect.
- Adds front-end integration through Discourse plugin outlets and theme APIs.

## Non-Goals

- This is not a cryptocurrency.
- It does not create an on-chain asset.
- It does not promise redemption, exchange value, custody, or financial return.
- It is scoped to one Discourse community per deployment.

## Repository Layout

```text
discourse-forum-points/
├── ledger/                  # backend sidecar
├── theme/                   # Discourse theme component
├── DEPLOY.md                # end-to-end deployment guide
├── SECURITY.md              # threat model and reporting guidance
├── CONTRIBUTING.md          # development and PR guidance
└── LICENSE
```

## Quick Start

```bash
cd ledger
cp .env.example .env
docker compose run --rm --entrypoint ledger-admin sidecar keygen
```

Edit `.env`, then:

```bash
docker compose up -d --build
docker compose exec sidecar ledger-admin init --memo "genesis"
```

Mount the sidecar under `/wallet/` in Discourse nginx, then install the theme
component from `theme/`.

See [DEPLOY.md](DEPLOY.md) for the full procedure.

## Defaults

- Public path: `/wallet/`
- Sidecar port: `18080`
- Default host bind: `172.17.0.1:18080` and `127.0.0.1:18080`
- Token symbol in the theme: `PTS`
- Supply cap: `50,000,000` atomic points

These defaults are source-level choices. If you change `/wallet/`, update the
sidecar static assets, cookie paths, and theme API helper consistently.

## Compatibility

The default deployment path targets a standard `discourse_docker` standalone
install. Other container networks or reverse proxies are supported, but you must
adapt the nginx proxy target and bind address.

The theme uses modern Discourse front-end APIs:

- `api.registerValueTransformer("post-menu-buttons", ...)`
- `api.renderAfterWrapperOutlet("post-avatar", ...)`
- `api.addCommunitySectionLink(...)`

Test on a staging Discourse instance before installing on production.

## Open-Source Hygiene

Never publish:

- `.env`
- `.admin-key`
- database dumps
- generated backups
- private keys
- Discourse API keys

This repository's `.gitignore` excludes those paths.
