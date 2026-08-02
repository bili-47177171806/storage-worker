# storage-worker

Cloudflare Worker that fronts **Aliyun OSS**: a browser-to-storage direct-upload flow, legacy path-style upload/download, and a SEKAI-oriented v2 façade (`/v2/upload`, `/images|files|stickers/{uuid}`).

No bucket names, private endpoints, or AccessKey material are hardcoded in `worker.js`. Configure everything via Wrangler vars + secrets.

## Features

- **Legacy** `PUT /`, chunked upload, safe-path upload, `GET|HEAD|DELETE /{key}`
- **SEKAI v2 direct upload**: Worker signs, a dedicated upload gateway carries the file body to OSS, Worker confirms
- Compatible **SEKAI v2** `PUT /v2/upload` → UUID + typed resolve URLs
- Streaming PostObject (avoids buffering whole files in the isolate)
- Optional **upload host** (CDN / custom domain) separate from regional GET origin
- v2 object **meta** written in the background (`waitUntil`) so upload latency stays close to legacy
- Root **API docs** as HTML / JSON / Markdown (`Accept` / `?format=`)

## Quick start

```bash
# 1. Config (gitignored)
cp wrangler.toml.example wrangler.local.toml
# edit wrangler.local.toml — your bucket, endpoint, signing backend, optional CDN host

# 2. AccessKey Id + Secret (Cloudflare secrets — never commit)
npx wrangler secret put OSS_AKID -c wrangler.local.toml
npx wrangler secret put OSS_AKS  -c wrangler.local.toml

# 3. Deploy
npx wrangler deploy -c wrangler.local.toml
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
| `PUBLIC_UPLOAD_HOST` | direct upload | `[vars]` | Public upload gateway, for example `https://upload.example.com` |
| `UPLOAD_TOKEN_SECRET` | no | **secret** | Separate HMAC secret for completion tokens; falls back to `OSS_AKS` |
| `DIRECT_UPLOAD_OBJECT_METADATA` | no | `[vars]` | Object Metadata is enabled by default; set to `0` to use legacy JSON sidecars |
| `OSS_PUT_MODE` | no | `[vars]` | `auto` (default) / `put` / `post` |
| `SIGN_BACKEND` | no* | `[vars]` | Remote policy API if `OSS_AKS` unset |
| `PUBLIC_STORAGE_HOST` | no | `[vars]` | Docs only |
| `PUBLIC_R2_HOST` | no | `[vars]` | Docs only |
| `TERMS_URL` | no | `[vars]` | Public terms URL shown in API docs |
| `ABUSE_REPORT_EMAIL` | no | `[vars]` | Abuse contact shown in API docs / README |
| `AUTH_DB` | no** | `[[d1_databases]]` | SEKAI Pass D1 (`sekai_pass_db`); needed only for uploads > 512 MiB |

\* Required only when `OSS_AKS` is not set.
\*\* Required only if you allow uploads above the 512 MiB anonymous cap. Anonymous uploads never touch it.

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
| HTML | `GET /` with `Accept: text/html` |
| Plain text | `GET /` without an `Accept` header |
| JSON | `GET /?json` or `Accept: application/json` |
| Markdown | `GET /?markdown`, `GET /?md`, or `Accept: text/markdown` |

The legacy `?format=json`, `?format=md`, and `?format=markdown` forms remain supported.

### SEKAI v2

New clients should use the three-step direct-upload flow. Only the small init and complete
JSON requests traverse the Worker; the file body goes through the dedicated upload gateway
directly to OSS.

```http
POST /v2/upload/init
Content-Type: application/json

{"name":"photo.jpg","type":"image/jpeg","size":209408,"kind":"image"}
```

The response contains `upload.url`, `upload.fields`, and `complete_token`. Append every
field to `FormData`, append the file **last**, then POST the form to `upload.url`:

```js
const form = new FormData();
for (const [name, value] of Object.entries(init.upload.fields)) form.append(name, value);
form.append("file", file, file.name);
const uploaded = await fetch(init.upload.url, { method: "POST", body: form });
if (!uploaded.ok) throw new Error(`OSS upload failed: ${uploaded.status}`);
```

Finally confirm against OSS and receive the normal v2 response:

```http
POST /v2/upload/complete
Content-Type: application/json

{"token":"<complete_token>"}
```

`PUT /v2/upload` remains supported for existing clients:

```http
PUT /v2/upload
X-Filename: photo.jpg
Content-Type: image/jpeg
Content-Length: …
X-Sekai-Kind: image   # optional
Authorization: Bearer <sekai-pass-token>   # required only when Content-Length > 512 MiB
```

**Upload size tiers:**

| Size | Requirement |
|------|-------------|
| ≤ 512 MiB | Anonymous (aligned with Cloudflare's cacheable object limit) |
| 512 MiB – ~1GB | Valid **SEKAI Pass** access token (`Authorization: Bearer …`); missing/invalid → `401` |
| > ~1GB | Rejected → `413` |

> The hosting platform's request-body limit applies when file bytes use the compatible `PUT /v2/upload` endpoint. It does not apply to the direct-upload body because that request does not traverse the Worker.

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

## Content policy & abuse

This is an **anonymous file service**. Arbitrary file types are allowed (including
executables) — that is intentional, not an oversight. Stored objects are always served
as downloads (`Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`), never
rendered in the browser.

Illegal content is prohibited and removed on report. To report abuse, email the address in
`ABUSE_REPORT_EMAIL` (also shown in the root API docs) with the **public URL** and the
**reason**. Do **not** attach or re-upload the offending content. See the Nightcord user
terms for the governing policy.

## Security notes

- Do **not** commit `wrangler.local.toml` or real `wrangler.toml` with production values.
- Rotate any AccessKey that was ever pasted into chat, logs, or old commits.
- Public `GET /v2/meta/{uuid}` does not return internal object keys.
- Direct-upload forms are restricted to one exact object key, size, MIME type, and content disposition, and expire after two hours.
- Set `UPLOAD_TOKEN_SECRET` separately if you want completion-token rotation independent of the OSS AccessKey secret.
- Uploads over 512 MiB require a SEKAI Pass token (`AUTH_DB` binding); anonymous uploads never touch it.
- Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

## License

[AGPL-3.0-only](./LICENSE) — same family as related Nightcord client code.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).
