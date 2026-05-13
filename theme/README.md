# Forum Points Theme Component

Discourse theme component for the Forum Points ledger sidecar.

## Features

- Shows public point balances on user cards.
- Shows post authors' balances beside avatars via the `post-avatar` outlet.
- Adds a post-menu tip button.
- Opens a local signing modal for transfers.
- Links to the public wallet explorer and account history.

## Required Backend

This component expects the sidecar to be mounted at `/wallet/` on the same
origin as Discourse.

Endpoints used:

- `GET /wallet/api/v1/balance/:discourse_id`
- `GET /wallet/api/v1/history/:discourse_id?limit=100`
- `GET /wallet/api/v1/me`
- `POST /wallet/api/v1/me/register`
- `POST /wallet/api/v1/tx`

## Install

From Discourse admin:

1. Admin -> Customize -> Themes -> Install
2. Choose "From a git repository" and point to this theme directory/repository,
   or upload a tarball.
3. Add the component to your active theme.

Manual tarball:

```bash
tar -czf forum-points-theme.tar.gz about.json README.md common javascripts locales
```

## Files

- `about.json` - theme metadata
- `common/common.scss` - component, modal, and table styles
- `javascripts/discourse/api-initializers/forum-points.js` - extension point registration
- `javascripts/discourse/connectors/user-card-after-metadata/forum-points-balance.gjs` - user-card balance
- `javascripts/discourse/components/post-avatar-balance.gjs` - post avatar balance
- `javascripts/discourse/components/tip-button.gjs` - post-menu tip button
- `javascripts/discourse/components/tip-modal.gjs` - local signing flow
- `javascripts/discourse/components/wallet-history-modal.gjs` - public history modal
- `javascripts/discourse/lib/crypto.js` - Web Crypto helpers
- `javascripts/discourse/lib/wallet-api.js` - API and cache helpers

## Security Model

The user's forum password is used only in the browser to derive a signing key.
It is cleared from component state after signing and is not sent to Discourse or
to the sidecar. The sidecar receives only a signed transaction payload.

Balances and histories are public because the sidecar exposes public audit
endpoints.
