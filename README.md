# storage-worker

Cloudflare Worker that fronts **Aliyun OSS** for upload/API work: `storage.*` signs and confirms uploads, `upload.*` carries direct file bodies to OSS, and `r2.*` serves public media by directly reverse-proxying OSS objects.

No bucket names, private endpoints, or AccessKey material are hardcoded in `worker.js`. Configure everything via Wrangler vars + secrets.

## Features

- **SEKAI v2 direct upload**: Worker signs, a dedicated upload gateway carries the file body to OSS, Worker confirms
- **Multipart direct upload** for authenticated large-file clients
- Exact-key gallery manifest upload through `POST /v2/upload/gallery/init`
- Streaming PostObject (avoids buffering whole files in the isolate)
- Hard host separation: `storage.*` API only, `upload.*` signed upload bodies only, `r2.*` downloads only
- v2 object **meta** stored on OSS object metadata (`x-oss-meta-sekai-*`)
- Root **API docs** as HTML / JSON / Markdown (`Accept` / `?format=`)

## Quick start

```bash
# 1. Config (gitignored)
cp wrangler.toml.example wrangler.local.toml
# edit wrangler.local.toml — your bucket, endpoint, signing backend, optional CDN host

# 2. AccessKey Id + Secret (Cloudflare secrets — never commit)
npx wrangler secret put OSS_AKID -c wrangler.local.toml
npx wrangler secret put OSS_AKS  -c wrangler.local.toml
npx wrangler secret put STS_AKID -c wrangler.local.toml
npx wrangler secret put STS_AKS  -c wrangler.local.toml

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
| `MULTIPART_REQUIRE_AUTH` | no | `[vars]` | `1` by default; requires SEKAI Pass for every Multipart initialization |
| `MULTIPART_STS_ENABLED` | no | `[vars]` | Set to `1` to issue short-lived, single-object STS credentials to Multipart clients |
| `MULTIPART_RECOMMENDED_CONCURRENCY` | no | `[vars]` | Client recommendation, default `2`; higher concurrency did not improve the measured upload-gateway throughput |
| `STS_ENDPOINT` | with STS | `[vars]` | STS RPC endpoint, for example `sts.cn-qingdao.aliyuncs.com` |
| `STS_ROLE_ARN` | with STS | `[vars]` | RAM role assumed for short-lived Multipart credentials |
| `STS_AKID` / `STS_AKS` | with STS | **secret** | Parent RAM credentials used only to call `AssumeRole`; never returned to clients |
| `DIRECT_UPLOAD_MAX_BYTES` | no | `[vars]` | Single signed upload limit; defaults to and cannot exceed the upload gateway's 800 MiB ceiling |
| `MULTIPART_MAX_PART_BYTES` | no | `[vars]` | Multipart part ceiling; defaults to and cannot exceed 800 MiB (the tighter of OSS 5 GiB and the upload gateway) |
| `OSS_PUT_MODE` | no | `[vars]` | `auto` (default) / `put` / `post` |
| `SIGN_BACKEND` | no* | `[vars]` | Remote policy API if `OSS_AKS` unset |
| `PUBLIC_STORAGE_HOST` | no | `[vars]` | Docs only |
| `PUBLIC_R2_HOST` | public media | `[vars]` | Public media host that directly reverse-proxies OSS |
| `TERMS_URL` | no | `[vars]` | Public terms URL shown in API docs |
| `ABUSE_REPORT_EMAIL` | no | `[vars]` | Abuse contact shown in API docs / README |
| `AUTH_DB` | no** | `[[d1_databases]]` | SEKAI Pass D1 (`sekai_pass_db`); required for Multipart and uploads > 512 MiB |

\* Required only when `OSS_AKS` is not set.
\*\* Required if Multipart is enabled with its default auth requirement, or if you allow uploads above the 512 MiB anonymous cap.

**Preferred:** set `OSS_AKS` so the Worker signs PostObject policy (or PutObject) locally — no external signer RTT.

Without `OSS_AKS`, the Worker can still use the remote signing fallback:

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

The gallery manifest uses the same host split with an exact fixed key:

```http
POST /v2/upload/gallery/init
Content-Type: application/json

{"size":4096}
```

Append the returned fields and `manifest.json` to `FormData`, then POST it to `upload.url`.

### Multipart direct upload

Multipart is intended for SEKAI Pass clients that need resumable parts. It uses the same
Object Metadata layout as normal direct upload, but requires a valid `Authorization: Bearer`
token at initialization. The default part size is `10 MiB`; the server automatically increases
it for files that would otherwise exceed OSS's 10,000-part limit. Clients must use the returned
`part_size`; all parts except the final one must use that size. The measured default client
concurrency is `2` because this upload path is bandwidth-capped; higher concurrency did not
increase effective throughput.

```http
POST /v2/upload/multipart/init
Authorization: Bearer <sekai-pass-token>
Content-Type: application/json

{"name":"large.bin","type":"application/octet-stream","size":12582912,"kind":"file"}
```

With `MULTIPART_STS_ENABLED=1`, the response additionally provides `multipart_sts`: temporary
credentials limited to this exact object, the existing `upload_id`, the upload-gateway endpoint,
and the canonical Bucket/object key needed for OSS V1 signing. The client signs presigned URLs
locally for Multipart `UploadPart`, `CompleteMultipartUpload`, `ListParts`, and
`AbortMultipartUpload`, including `security-token` in the signed query string. Every part
request goes directly to the upload gateway, without a Worker request per batch. Credentials
expire after the STS duration; refresh them with:

```http
POST /v2/upload/multipart/credentials
Content-Type: application/json

{"token":"<multipart_token>"}
```

After direct OSS completion, ask the Worker only to verify the declared object and return the
normal v2 response:

```http
POST /v2/upload/multipart/complete
Content-Type: application/json

{"token":"<multipart_token>","completed":true}
```

The older batch URL flow remains available for clients that do not support local STS signing:

```http
POST /v2/upload/multipart/parts
Content-Type: application/json

{"token":"<multipart_token>","part_numbers":[1,2]}
```

Upload each returned byte range with `PUT`, record its `ETag` response header, then complete:

```http
POST /v2/upload/multipart/complete
Content-Type: application/json

{"token":"<multipart_token>","parts":[{"part_number":1,"etag":"\"...\""},{"part_number":2,"etag":"\"...\""}]}
```

Use `POST /v2/upload/multipart/abort` with `{ "token": "<multipart_token>" }` to cancel an
unfinished upload. The upload gateway must allow `PUT` and expose `ETag` through CORS; file
bytes do not traverse the Worker.

STS credentials are bearer credentials for one object, so `init` and `credentials` are always
`Cache-Control: no-store`. Client-side OSS V1 signing needs the Bucket in this authenticated
response; concealment is not the security boundary. The session policy is restricted to the
exact object key and does not grant Bucket listing or read access.

OSS permits 100 KiB-5 GiB non-final parts, at most 10,000 parts, and an object of about
48.8 TiB. The upload gateway is tighter at 800 MiB per request, so this deployment permits
at most 800 MiB per part and 8,388,608,000,000 bytes (about 7.63 TiB) per completed object.

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
GET|HEAD {PUBLIC_R2_HOST}/images/{uuid}
GET|HEAD {PUBLIC_R2_HOST}/files/{uuid}
GET|HEAD {PUBLIC_R2_HOST}/stickers/{uuid}
GET /v2/meta/{uuid}
```

Object layout: `{PREFIX}/sekai/{uuid}` with required `x-oss-meta-sekai-*` object metadata. `storage.*` rejects object downloads and retired PUT routes; public media must use `PUBLIC_R2_HOST`.

## Content policy & abuse

Uploads may contain arbitrary file types, including executables. Public objects are served only
through `r2.*` with `X-Content-Type-Options: nosniff`; `storage.*` never returns object bytes.

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
