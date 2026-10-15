# Basel Taxi Transfert

Public website (taxi & airport transfers from Basel) plus a small admin API, deployed as a single Cloudflare Worker with static assets and KV storage.

## Structure

- `dist/` — the site: `index.html`, icons, car photos, `dot-pattern.json` (Lottie animation)
- `worker/api.js` — Worker: serves the site, admin API, Cloudflare Access gate
- `wrangler.toml` — Worker config (assets, KV binding, Access vars)
- `design/` — design source assets

## Deploy

```bash
npx wrangler login     # once
npx wrangler deploy
```

Live: `https://transfert.basel-taxi.workers.dev`

## Admin protection (Cloudflare Access)

The worker only serves `/admin`, `/admin.html`, `?admin` and the admin API routes if the request carries a valid **Cloudflare Access JWT** (verified against your team's JWKS: signature, `iss`, `aud`, `exp`). Missing/invalid token → `403` (or a redirect to `/admin`, where Access challenges the visitor). No config → fail closed, the admin page stays `403`.

To enable it:

1. Cloudflare Zero Trust → **Access → Applications → Add an application**
   - Type: Self-hosted, path `/admin*`
   - Allow policy: only your email / identity provider user
2. Fill in `wrangler.toml`:
   ```toml
   [vars]
   ACCESS_TEAM_DOMAIN = "https://<your-team>.cloudflareaccess.com"
   ACCESS_APPLICATION_AUD = "<application audience tag>"
   ```
3. `npx wrangler deploy` again.

Never commit real tokens or secrets — the Access audience tag is not secret, but API tokens belong in `wrangler secret` / environment variables only.

## API

Public:

- `GET /api/avail` — availability flag
- `GET /api/reviews` — approved reviews
- `POST /api/review` — submit a review (requires the shared review code)

Admin only (Cloudflare Access JWT + session token):

- `POST /api/setup`, `POST /api/login`, `POST /api/logout`
- `GET /api/data`, `PUT /api/data`
- `GET /api/revcode`, `PUT /api/revcode`
- `PUT /api/avail`

## Notes

- Site copy is available in DE / FR / EN (client-side i18n in `index.html`).
- Background animation respects `prefers-reduced-motion` and degrades gracefully if the Lottie CDN is blocked.
