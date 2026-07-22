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

# 2. AccessKey Id only (never the Secret)
npx wrangler secret put OSS_AKID -c wrangler.toml.local

# 3. Deploy
npx wrangler deploy -c wrangler.toml.local
```

Bind your public hostname(s) to this Worker in the Cloudflare dashboard.

## Configuration

| Binding | Required | Location | Description |
|---------|----------|----------|-------------|
| `OSS_BUCKET` | yes | `[vars]` | Bucket name |
| `OSS_ENDPOINT` | yes | `[vars]` | Regional endpoint host, e.g. `oss-cn-hangzhou.aliyuncs.com` |
| `OSS_AKID` | yes | **secret** | AccessKey **Id** only |
| `SIGN_BACKEND` | yes | `[vars]` | Origin of policy signing API |
| `OSS_PREFIX` | no | `[vars]` | Object key prefix (default `AttachFiles` if empty) |
| `OSS_UPLOAD_HOST` | no | `[vars]` | PostObject URL origin; empty → `https://$BUCKET.$ENDPOINT` |
| `PUBLIC_STORAGE_HOST` | no | `[vars]` | Docs only |
| `PUBLIC_R2_HOST` | no | `[vars]` | Docs only |

Signing contract expected by the Worker:

```http
GET {SIGN_BACKEND}/File/GetOssPolicy2Signature?userid={id}&bucket={bucket}
```

JSON body: `["<base64-policy>","<signature>"]`.  
Policy must allow keys under your prefix (e.g. `AttachFiles/{userid}/…`).  
The AccessKey **Secret** stays on that backend.

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
