# storage-worker

Cloudflare Worker that fronts **Aliyun OSS** (or any S3-compatible PostObject-style flow with a small signing API): legacy path-style upload/download **plus** a SEKAI-oriented v2 façade (`/v2/upload`, `/images|files|stickers/{uuid}`).

No bucket names, private endpoints, or AccessKey material are hardcoded in `worker.js`. Configure everything via Wrangler vars + secrets.

## Features

- **Legacy** `PUT /`, chunked upload, safe-path upload, `GET|HEAD|DELETE /{key}`
- **SEKAI v2** `PUT /v2/upload` → UUID + typed resolve URLs
- Streaming PostObject (avoids buffering whole files in the isolate)
- Optional **upload host** (CDN / custom domain) separate from regional GET origin
- v2 object **meta** written in the background (`waitUntil`) so upload latency stays close to legacy
- Root **API docs** as HTML / JSON / Markdown (`Accept` / `?format=`)

## Quick start

```bash
# 1. Config (gitignored)
cp wrangler.toml.example wrangler.toml.local
# edit wrangler.toml.local — your bucket, endpoint, signing backend, optional CDN host

# 2. AccessKey Id + Secret (Cloudflare secrets — never commit)
npx wrangler secret put OSS_AKID -c wrangler.toml.local
npx wrangler secret put OSS_AKS  -c wrangler.toml.local

# 3. Deploy
npx wrangler deploy -c wrangler.toml.local
```

Bind your public hostname(s) to this Worker in the Cloudflare dashboard.

## Configuration

| Binding | Required | Location | Description |
|---------|----------|----------|-------------|
| `OSS_BUCKET` | yes | `[vars]` | Bucket name |
| `OSS_ENDPOINT` | yes | `[vars]` | Regional endpoint host |
| `OSS_AKID` | yes | **secret** | AccessKey **Id** |
| `OSS_AKS` | recommended | **secret** | AccessKey **Secret** (local HMAC / PutObject) |
| `OSS_PREFIX` | no | `[vars]` | Object key prefix (default `AttachFiles`) |
| `OSS_UPLOAD_HOST` | no | `[vars]` | Upload origin; empty → regional host |
| `OSS_PUT_MODE` | no | `[vars]` | `auto` (default) / `put` / `post` |
| `SIGN_BACKEND` | no* | `[vars]` | Remote policy API if `OSS_AKS` unset |
| `PUBLIC_STORAGE_HOST` | no | `[vars]` | Docs only |
| `PUBLIC_R2_HOST` | no | `[vars]` | Docs only |

\* Required only when `OSS_AKS` is not set.

**Preferred:** set `OSS_AKS` so the Worker signs PostObject policy (or PutObject) locally — no external signer RTT.

**Legacy fallback:** without SK,

```http
GET {SIGN_BACKEND}/File/GetOssPolicy2Signature?userid={id}&bucket={bucket}
→ ["<base64-policy>","<signature>"]
```

## API (summary)

### Docs

| | |
|--|--|
| HTML | `GET /` |
| JSON | `GET /?format=json` or `Accept: application/json` |
| Markdown | `GET /?format=md` or `Accept: text/markdown` |

### SEKAI v2

```http
PUT /v2/upload
X-Filename: photo.jpg
Content-Type: image/jpeg
Content-Length: …
X-Sekai-Kind: image   # optional
```

```json
{
  "uuid": "…",
  "key": "…",
  "type": "image/jpeg",
  "size": 204.5,
  "size_bytes": 209408,
  "name": "photo.jpg",
  "kind": "image",
  "url": "/images/…"
}
```

```http
GET|HEAD /images/{uuid}
GET|HEAD /files/{uuid}
GET|HEAD /stickers/{uuid}
GET /v2/meta/{uuid}
```

Object layout (typical): `{PREFIX}/sekai/{uuid}{ext}` plus best-effort `{PREFIX}/sekai/{uuid}.json` (internal; public meta omits storage keys).

### Legacy

| Method | Path | Notes |
|--------|------|--------|
| PUT | `/` | Single object |
| PUT | `/` + chunk headers | Chunked |
| PUT | `/` + `X-Safe-Path` | Restricted prefixes |
| GET/HEAD/DELETE | `/{key}` | Proxy |
| * | `/chunked/…` | Chunked download/delete |

## Security notes

- Do **not** commit `wrangler.toml.local` or real `wrangler.toml` with production values.
- Rotate any AccessKey that was ever pasted into chat, logs, or old commits.
- Public `GET /v2/meta/{uuid}` does not return internal object keys.
- Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

## License

[AGPL-3.0-only](./LICENSE) — same family as related Nightcord client code.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).
