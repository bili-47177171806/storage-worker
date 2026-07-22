# Contributing

Thanks for considering a contribution.

## Development

1. Copy config:
   ```bash
   cp wrangler.toml.example wrangler.toml.local
   ```
2. Fill in your own bucket / signing backend (never commit this file).
3. Install Wrangler (`npm i -g wrangler` or use `npx`).
4. Put the AccessKey **Id** only:
   ```bash
   npx wrangler secret put OSS_AKID -c wrangler.toml.local
   ```
5. Deploy:
   ```bash
   npx wrangler deploy -c wrangler.toml.local
   ```

## Pull requests

- Keep environment-specific hostnames and credentials out of the diff.
- Prefer small, focused changes (routing, streaming, docs).
- Describe how you tested (e.g. `PUT /v2/upload`, `GET /images/{uuid}`).

## Code of conduct

Be respectful. Harassment or abuse is not acceptable. Maintainers may close issues or block users that violate this.
