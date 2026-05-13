# Open-Source Release Checklist

Run this before publishing a fork or release archive.

## Required

- [ ] `rg --hidden -n "ADMIN_PRIV_KEY_HEX=[0-9a-fA-F]{20,}|[A-Z_]*SECRET=[0-9a-fA-F]{32,}|PG_PASSWORD=[A-Za-z0-9+/]{32,}|api[-_]?key\\s*[:=]\\s*['\\\"]?[A-Za-z0-9_\\-]{20,}|PRIVATE KEY|BEGIN OPENSSH|ssh-rsa |sk-ssh-" . --glob '!OPEN_SOURCE_CHECKLIST.md' --glob '!.git/**'`
- [ ] `find . \( -path './.git' -o -path './.git/*' \) -prune -o \( -name ".env" -o -name ".admin-key" -o -name "*.sql" -o -name "*.tar.gz" \) -print`
- [ ] `cd ledger/sidecar && go test ./...`
- [ ] `cd theme && node --check javascripts/discourse/lib/wallet-api.js`
- [ ] `cd theme && node --check javascripts/discourse/api-initializers/forum-points.js`
- [ ] `cd theme && node test-canonical.mjs`

## Recommended

- [ ] Install the theme on a staging Discourse instance.
- [ ] Verify `/wallet/api/v1/health`, `/treasury`, `/log/sth`, and `/explorer/`.
- [ ] Test DiscourseConnect login.
- [ ] Test webhook ping.
- [ ] Test a small transfer between two non-admin users.
- [ ] Run `ledger-verify` against the public URL.
- [ ] Publish deployment-specific docs stating whether points are redeemable.
