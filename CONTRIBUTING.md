# Contributing

Thanks for improving Discourse Forum Points.

## Development Setup

Backend:

```bash
cd ledger
cp .env.example .env
docker compose up -d --build
cd sidecar
go test ./...
```

Theme:

```bash
cd theme
node --check javascripts/discourse/lib/wallet-api.js
node --check javascripts/discourse/api-initializers/forum-points.js
node test-canonical.mjs
```

## Pull Requests

- Keep Discourse integration non-invasive: no Discourse core patches.
- Keep deployment-specific settings in `.env`, Discourse admin settings, or theme settings.
- Include tests for ledger, signature, webhook, or audit behavior changes.
- Test UI changes on a staging Discourse instance when touching theme outlets.
- Do not commit generated archives, database dumps, private keys, or API keys.

## Repository Identity

The default Go module path is `github.com/forum-points/ledger` and the theme
metadata points at `github.com/forum-points/discourse-forum-points`. Forks may
keep these placeholders, but official releases under another organization should
rewrite them consistently.

## Security

Report security issues privately to the maintainer of the affected fork or
deployment. See `SECURITY.md`.
