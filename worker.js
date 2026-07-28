/**
 * Nightcord Storage Worker — object-storage proxy (OSS)
 *
 * Legacy API (unchanged paths):
 *   PUT /                    single / chunked / safe-path upload
 *   GET|HEAD|DELETE /{key}   object proxy
 *   GET|HEAD|DELETE /chunked/...
 *
 * SEKAI v2 facade (additive):
 *   PUT /v2/upload
 *   GET|HEAD /images/{uuid} | /files/{uuid} | /stickers/{uuid}
 *   GET /v2/meta/{uuid}
 *
 * All environment-specific values come from Worker bindings / secrets
 * (see wrangler.toml [vars] and `wrangler secret put OSS_AKID`).
 * Do not hardcode bucket names, signing backends, or AccessKey material here.
 */

import { authenticate } from "@25-ji-code-de/sekai-worker-kit";

const SAFE_USERIDS = new Set(["public", "shared", "open"]);

/** Non-secret runtime knobs that are not environment-specific. */
const CHUNK_SIZE = 10 * 1024 * 1024;
/** Anonymous ceiling, aligned with Cloudflare's 512 MB cache object limit. */
const ANON_MAX_UPLOAD_BYTES = 512 * 1024 * 1024;
/** Absolute upload ceiling for SEKAI Pass users; retained for compatibility. */
const MAX_UPLOAD_BYTES = 1048576000;
/** Extensions probed when v2 meta sidecar is missing (common first). */
const SEKAI_PROBE_EXTS = [
  "",
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".gif",
  ".bin",
  ".mp3",
  ".flac",
  ".ogg",
  ".wav",
  ".pdf",
  ".zip",
  ".mp4",
  ".webm",
];

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers":
    "Authorization, Content-Type, X-Filename, X-Chunk-Index, X-Chunk-Total, " +
    "X-File-ID, X-Original-Filename, X-File-Size, X-Safe-Path, " +
    "X-Sekai-Kind, X-Image-Width, X-Image-Height",
  "Access-Control-Expose-Headers": "WWW-Authenticate",
  "Access-Control-Max-Age": "86400",
};

const PASS_HEADERS = [
  "Content-Type", "Content-Length", "Content-Range",
  "Accept-Ranges", "Content-Disposition", "ETag", "Last-Modified",
];

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/* ═══════════════════════════════════════════════════════
 *  Config helpers
 * ═══════════════════════════════════════════════════════ */

/**
 * Required env (vars or secrets):
 *   OSS_BUCKET, OSS_ENDPOINT, OSS_AKID (secret), OSS_PREFIX
 * Prefer local signing (no external policy service):
 *   OSS_AKS (secret) — AccessKey Secret; enables HMAC policy / PutObject
 * Optional:
 *   SIGN_BACKEND — fallback only when OSS_AKS is unset
 *   OSS_UPLOAD_HOST — upload host (CDN/custom). Empty → regional OSS_HOST
 *   PUBLIC_STORAGE_HOST / PUBLIC_R2_HOST — GET / docs text only
 */
function cfg(env) {
  const e = env || {};
  const BUCKET = String(e.OSS_BUCKET || "").trim();
  const ENDPOINT = String(e.OSS_ENDPOINT || "").trim();
  const AKID = String(e.OSS_AKID || "").trim();
  const AKS = String(e.OSS_AKS || e.OSS_ACCESS_KEY_SECRET || "").trim();
  const BACKEND = String(e.SIGN_BACKEND || "").trim().replace(/\/$/, "");
  const PREFIX = String(e.OSS_PREFIX || "AttachFiles").trim() || "AttachFiles";
  const OSS_HOST = BUCKET && ENDPOINT ? `https://${BUCKET}.${ENDPOINT}` : "";
  const rawUpload = String(e.OSS_UPLOAD_HOST || e.OSS_UPLOAD_ENDPOINT || "").trim();
  const UPLOAD_HOST = rawUpload.replace(/\/$/, "") || OSS_HOST;
  // Prefer PutObject when we have SK (simpler stream, no multipart). Can force PostObject with OSS_PUT_MODE=post
  const putMode = String(e.OSS_PUT_MODE || "auto").trim().toLowerCase();
  return {
    BUCKET,
    ENDPOINT,
    AKID,
    AKS,
    BACKEND,
    PREFIX,
    OSS_HOST,
    UPLOAD_HOST,
    PUT_MODE: putMode, // auto | put | post
    CHUNK_SIZE,
    PUBLIC_STORAGE_HOST: String(e.PUBLIC_STORAGE_HOST || "").trim().replace(/\/$/, ""),
    PUBLIC_R2_HOST: String(e.PUBLIC_R2_HOST || "").trim().replace(/\/$/, ""),
    ABUSE_REPORT_EMAIL: String(e.ABUSE_REPORT_EMAIL || "").trim(),
    DELETE_ENABLED: String(e.DELETE_ENABLED || "").trim() === "1",
  };
}

/**
 * 删除是否开放。
 *
 * ── 为什么需要这个开关 ────────────────────────────────────────────
 *
 * 本 Worker **没有任何鉴权**（见 issue #3）。删除端点今天之所以打不通，
 * 是因为三个 delete 函数都要求 `SIGN_BACKEND`，而当前部署优先本地签名
 * （`OSS_AKS`），`SIGN_BACKEND` 多半没配 —— 于是全部返回 500。
 *
 * **那是意外，不是设计。** 一旦有人为了别的目的配上 `SIGN_BACKEND`，
 * 删除立刻变成无鉴权的：任何人可以删任何对象，没有任何提示。
 *
 * 这里把「意外的缓解」变成「有意的拒绝」：删除需要显式设 `DELETE_ENABLED=1`，
 * 与 `SIGN_BACKEND` 解耦。默认拒绝，且给的是 403 加一句说明，
 * 而不是一个让人以为服务坏了的 500。
 *
 * **打开它之前请先解决鉴权** —— 这个开关只是让那个决定变成显式的，
 * 它本身不提供任何身份校验。
 *
 * 当前没有任何客户端依赖删除：nightcord 的 `file-upload-service.js`
 * 里有个 `delete()` 方法，但全仓没有调用点，而且它现在必然拿到 500。
 */
function deleteAllowed(c) {
  return c.DELETE_ENABLED;
}

function configOk(c) {
  if (!(c.BUCKET && c.ENDPOINT && c.AKID && c.OSS_HOST)) return false;
  // Local SK preferred; remote SIGN_BACKEND still accepted as fallback.
  return !!(c.AKS || c.BACKEND);
}

function getSafeId(path) {
  const seg = path.split("/").find(Boolean);
  return seg && SAFE_USERIDS.has(seg) ? seg : null;
}

/* ═══════════════════════════════════════════════════════
 *  Entry
 * ═══════════════════════════════════════════════════════ */
export default {
  async fetch(req, env, ctx) {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const c = cfg(env);
    if (!configOk(c)) {
      console.error(
        "missing bindings: need OSS_BUCKET, OSS_ENDPOINT, OSS_AKID, and OSS_AKS (or SIGN_BACKEND)",
      );
      return fail(500, "Storage worker misconfigured");
    }

    const url = new URL(req.url);
    const path = url.pathname.slice(1);

    try {
      // ── Index / API docs (GET|HEAD /) ──
      if (!path && (req.method === "GET" || req.method === "HEAD")) {
        return apiIndex(req, url, c);
      }
      if ((path === "v2" || path === "v2/" || path === "docs") &&
          (req.method === "GET" || req.method === "HEAD")) {
        return apiIndex(req, url, c);
      }

      // ── SEKAI v2 routes (path-based; works on any bound host) ──
      if (path === "v2/upload" && req.method === "PUT") {
        return await putSekaiV2(req, c, ctx, env);
      }
      if (path.startsWith("v2/meta/") && (req.method === "GET" || req.method === "HEAD")) {
        const uuid = path.slice("v2/meta/".length).split("/")[0];
        return await getSekaiMeta(req, c, uuid);
      }
      {
        const m = path.match(/^(images|files|stickers)\/([^/]+)\/?$/);
        if (m && (req.method === "GET" || req.method === "HEAD")) {
          return await getSekaiObject(req, ctx, url, c, m[1], m[2]);
        }
      }

      // ── Legacy ──
      switch (req.method) {
        case "PUT": {
          if (req.headers.has("X-Chunk-Index")) return await putChunk(req, c, env);
          if (req.headers.has("X-Safe-Path")) return await putSafe(req, c, env);
          return await put(req, c, env);
        }
        case "GET":
        case "HEAD": {
          if (!path || path.length > 1024 || /\.\.|\/\/|[\x00-\x1f]/.test(path)) {
            return fail(400);
          }
          if (path.startsWith("chunked/")) {
            const inner = path.slice("chunked/".length);
            if (!inner) return fail(400);
            return await getChunked(req, ctx, url, c, inner);
          }
          return await get(req, ctx, url, c, `${c.PREFIX}/${path}`);
        }
        case "DELETE": {
          if (!path || path.length > 1024 || /\.\.|\/\/|[\x00-\x1f]/.test(path)) {
            return fail(400);
          }
          if (path.startsWith("chunked/")) {
            const inner = path.slice("chunked/".length);
            if (!inner) return fail(400);
            return await delChunked(req, ctx, url, c, inner);
          }
          if (getSafeId(path)) return await delSafe(req, ctx, url, c, path);
          return await del(req, ctx, url, c, path, `${c.PREFIX}/${path}`);
        }
        default:
          return fail(405);
      }
    } catch (e) {
      console.error("top-level error:", e);
      return fail(500);
    }
  },
};

/* ═══════════════════════════════════════════════════════
 *  API index / docs (GET /)
 * ═══════════════════════════════════════════════════════ */

/**
 * Negotiate docs representation from Accept / ?format=
 * Priority: explicit ?format= > Accept q-order heuristics
 * - markdown: text/markdown (agents)
 * - json: application/json
 * - html: default for browsers
 */
function negotiateDocsFormat(req, url) {
  const fmt = (url.searchParams.get("format") || "").toLowerCase();
  if (fmt === "md" || fmt === "markdown") return "markdown";
  if (fmt === "json") return "json";
  if (fmt === "html") return "html";

  const accept = (req.headers.get("Accept") || "").toLowerCase();
  // Prefer the most specific agent / API types before */* or html
  if (accept.includes("text/markdown")) return "markdown";
  if (accept.includes("application/json")) return "json";
  if (accept.includes("text/html")) return "html";
  // Agents sometimes send Accept: text/markdown, application/json, */*
  // Already handled. Bare */* or empty → HTML for browsers.
  return "html";
}

/** Rough token estimate for x-markdown-tokens (whitespace-split). */
function estimateMarkdownTokens(md) {
  const parts = String(md).trim().split(/\s+/).filter(Boolean);
  return parts.length;
}

function apiIndex(req, url, c) {
  const origin = url.origin;
  const format = negotiateDocsFormat(req, url);
  const storageHost = (c && c.PUBLIC_STORAGE_HOST) || origin;
  const r2Host = (c && c.PUBLIC_R2_HOST) || origin;

  const doc = {
    service: "Nightcord Storage",
    version: "2.0.0",
    description:
      "Object storage proxy with SEKAI v2 resource facade. Legacy upload paths remain; new clients should prefer /v2/upload and typed resolve URLs.",
    hosts: {
      storage: storageHost,
      r2: r2Host,
      note: "Both hosts hit this Worker when bound. Prefer the media host for public SEKAI GETs; uploads may use either host.",
    },
    sekaiv2: {
      upload: {
        method: "PUT",
        path: "/v2/upload",
        headers: {
          "X-Filename": "percent-encoded original filename (required)",
          "Content-Type": "MIME type",
          "Content-Length": "bytes",
          "X-Sekai-Kind": "image | file | sticker (optional; inferred from MIME)",
          "X-Image-Width": "optional int",
          "X-Image-Height": "optional int",
        },
        response: {
          uuid: "resource id (use as SEKAI payload)",
          key: "same as uuid",
          type: "MIME",
          size: "kilobytes (float)",
          size_bytes: "bytes",
          name: "original filename",
          kind: "image | file | sticker",
          url: "/images/{uuid} or /files/{uuid} or /stickers/{uuid}",
          w: "optional",
          h: "optional",
        },
        example: `curl -X PUT ${origin}/v2/upload -H "X-Filename: photo.jpg" -H "Content-Type: image/jpeg" --data-binary @photo.jpg`,
        limits: {
          anonymous_max_bytes: ANON_MAX_UPLOAD_BYTES,
          authenticated_max_bytes: MAX_UPLOAD_BYTES,
          note:
            "Uploads up to 512 MiB are anonymous. Larger uploads (up to ~1GB) require a " +
            "SEKAI Pass access token via 'Authorization: Bearer <token>'; without one they return 401. " +
            "Over ~1GB returns 413. Note: Cloudflare per-plan request-body limits may cap large uploads " +
            "below this (Free/Pro 100MB, Business 200MB, Enterprise 500MB default).",
        },
        auth: {
          header: "Authorization: Bearer <sekai-pass-access-token>",
          required_when: "Content-Length > 536870912 (512 MiB)",
        },
      },
      resolve: {
        methods: ["GET", "HEAD"],
        paths: [
          "/images/{uuid}",
          "/files/{uuid}",
          "/stickers/{uuid}",
        ],
        notes: [
          "UUID is a standard UUID v4 string.",
          "Objects are stored under AttachFiles/sekai/{uuid}{ext} on OSS.",
          "Public Cache-Control: immutable (long TTL) for successful GETs.",
        ],
      },
      meta: {
        method: "GET",
        path: "/v2/meta/{uuid}",
        description: "JSON metadata written at upload time (best-effort).",
      },
      message_payload: {
        image: "<$SEKAI:Image:w=…;h=…;name=…:{uuid}>",
        file: "<$SEKAI:Files:type=…;size=…;name=…:{uuid}>",
        custom_stamp: "<$SEKAI:Stamp:custom=true:{uuid}>",
      },
    },
    legacy: {
      upload: {
        method: "PUT",
        path: "/",
        headers: ["X-Filename", "Content-Type", "Content-Length"],
        optional: ["X-Safe-Path", "X-Chunk-Index / X-Chunk-Total / X-File-ID (chunked)"],
        response: { key: "{uid}/{fileUuid}.ext", url: "/{key}", size: "bytes" },
      },
      resolve: {
        methods: ["GET", "HEAD", "DELETE"],
        path: "/{key}",
        chunked: "/chunked/{inner}",
      },
    },
    caching: {
      eligible:
        "Public media (images/files/stickers, legacy keys). Exclude / and /v2/* from cache eligibility.",
      see: "Cloudflare Cache Rules on storage.* and r2.*",
    },
    policy: {
      summary:
        "Anonymous file service. Arbitrary file types are allowed (including executables). " +
        "Illegal content is prohibited and removed on report. Stored objects are served as " +
        "downloads (Content-Disposition: attachment) with X-Content-Type-Options: nosniff.",
      report:
        "Report abuse or illegal content" +
        (c && c.ABUSE_REPORT_EMAIL ? ` to ${c.ABUSE_REPORT_EMAIL}` : " via the configured abuse contact") +
        ". Include the public URL and the reason. Do NOT attach or re-upload the offending content.",
      report_email: (c && c.ABUSE_REPORT_EMAIL) || null,
      terms: "https://nightcord.de5.net (see Nightcord user terms)",
    },
    links: {
      self_html: origin + "/",
      self_json: origin + "/?format=json",
      self_markdown: origin + "/?format=md",
      sekaiv2_docs: origin + "/v2",
      accept_markdown: "Send Accept: text/markdown for this document as Markdown (agents).",
    },
  };

  const commonHeaders = {
    "Cache-Control": "public, max-age=300",
    "Access-Control-Allow-Origin": "*",
    Vary: "Accept",
  };

  if (format === "json") {
    const body = req.method === "HEAD" ? null : JSON.stringify(doc, null, 2);
    return new Response(body, {
      status: 200,
      headers: {
        ...commonHeaders,
        "Content-Type": "application/json;charset=utf-8",
      },
    });
  }

  if (format === "markdown") {
    const md = renderApiMarkdown(doc, origin);
    const tokens = estimateMarkdownTokens(md);
    return new Response(req.method === "HEAD" ? null : md, {
      status: 200,
      headers: {
        ...commonHeaders,
        "Content-Type": "text/markdown; charset=utf-8",
        "x-markdown-tokens": String(tokens),
      },
    });
  }

  // HTML default (browsers)
  return new Response(req.method === "HEAD" ? null : renderApiHtml(doc, origin), {
    status: 200,
    headers: {
      ...commonHeaders,
      "Content-Type": "text/html;charset=utf-8",
    },
  });
}

/**
 * Markdown docs for agents (Accept: text/markdown).
 * Keep structure parallel to the HTML page.
 */
function renderApiMarkdown(doc, origin) {
  const lines = [];
  lines.push(`# ${doc.service}`);
  lines.push("");
  lines.push(`> Version **${doc.version}** · API index for agents and humans`);
  lines.push("");
  lines.push(doc.description);
  lines.push("");
  lines.push("## Hosts");
  lines.push("");
  lines.push(`| Role | URL |`);
  lines.push(`|------|-----|`);
  lines.push(`| Storage (upload + legacy) | \`${doc.hosts.storage}\` |`);
  lines.push(`| R2 facade (public media) | \`${doc.hosts.r2}\` |`);
  lines.push("");
  lines.push(doc.hosts.note);
  lines.push("");
  lines.push("## SEKAI v2 (prefer this)");
  lines.push("");
  lines.push("### Upload");
  lines.push("");
  lines.push("```http");
  lines.push("PUT /v2/upload");
  lines.push("X-Filename: <percent-encoded filename>");
  lines.push("Content-Type: <mime>");
  lines.push("Content-Length: <bytes>");
  lines.push("X-Sekai-Kind: image | file | sticker   # optional");
  lines.push("X-Image-Width: <int>                 # optional");
  lines.push("X-Image-Height: <int>                # optional");
  lines.push("");
  lines.push("<raw file bytes>");
  lines.push("```");
  lines.push("");
  lines.push("**Response fields:** `uuid`, `key` (=uuid), `type`, `size` (kB), `size_bytes`, `name`, `kind`, `url`, optional `w`/`h`.");
  lines.push("");
  lines.push("**Size limits:** anonymous uploads up to **512 MiB**. Larger uploads (up to ~1GB) require a SEKAI Pass token via `Authorization: Bearer <token>` (else `401`); over ~1GB returns `413`. Cloudflare per-plan request-body limits may cap large uploads further.");
  lines.push("");
  lines.push("**Example:**");
  lines.push("");
  lines.push("```bash");
  lines.push(doc.sekaiv2.upload.example);
  lines.push("```");
  lines.push("");
  lines.push("### Resolve");
  lines.push("");
  for (const p of doc.sekaiv2.resolve.paths) {
    lines.push(`- \`GET|HEAD ${p}\``);
  }
  lines.push(`- \`GET ${doc.sekaiv2.meta.path}\` — ${doc.sekaiv2.meta.description}`);
  lines.push("");
  for (const n of doc.sekaiv2.resolve.notes) {
    lines.push(`- ${n}`);
  }
  lines.push("");
  lines.push("### SEKAI message payload examples");
  lines.push("");
  lines.push("```text");
  lines.push(doc.sekaiv2.message_payload.image);
  lines.push(doc.sekaiv2.message_payload.file);
  lines.push(doc.sekaiv2.message_payload.custom_stamp);
  lines.push("```");
  lines.push("");
  lines.push("## Legacy (still supported)");
  lines.push("");
  lines.push("- `PUT /` → `{ key, url, size }` where `key` is `{uid}/{fileUuid}.ext`");
  lines.push("- `GET|HEAD|DELETE /{key}`");
  lines.push("- Chunked: `/chunked/…`");
  lines.push("");
  lines.push("Use for older clients and historical messages. New Nightcord builds use v2.");
  lines.push("");
  lines.push("## Caching");
  lines.push("");
  lines.push(doc.caching.eligible);
  lines.push("");
  lines.push(`See: ${doc.caching.see}`);
  lines.push("");
  lines.push("## Content policy & abuse");
  lines.push("");
  lines.push(doc.policy.summary);
  lines.push("");
  lines.push(doc.policy.report);
  lines.push("");
  lines.push("## Alternate formats");
  lines.push("");
  lines.push(`| Format | How |`);
  lines.push(`|--------|-----|`);
  lines.push(`| HTML (default) | \`${origin}/\` |`);
  lines.push(`| JSON | \`${origin}/?format=json\` or \`Accept: application/json\` |`);
  lines.push(`| Markdown | \`${origin}/?format=md\` or \`Accept: text/markdown\` |`);
  lines.push("");
  lines.push("Markdown responses use `Content-Type: text/markdown` and `x-markdown-tokens`.");
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(
    "*Nightcord storage worker · SEKAI resource facade · same Worker on `storage.*` and `r2.*`*",
  );
  lines.push("");
  return lines.join("\n");
}

function renderApiHtml(doc, origin) {
  const esc = (s) =>
    String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${esc(doc.service)} API</title>
  <style>
    :root {
      --bg: #1a1625;
      --card: #2a2438;
      --text: #f0eaf8;
      --muted: #a89bb8;
      --accent: #7c6fac;
      --ok: #6bcb8a;
      --code: #16121f;
      --border: rgba(124, 111, 172, 0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Noto Sans SC", system-ui, sans-serif;
      background: radial-gradient(1200px 600px at 10% -10%, #3d2f5c 0%, var(--bg) 55%);
      color: var(--text);
      line-height: 1.55;
      padding: 32px 16px 64px;
    }
    main {
      max-width: 880px;
      margin: 0 auto;
    }
    h1 {
      font-size: 1.75rem;
      margin: 0 0 8px;
      letter-spacing: 0.02em;
    }
    .badge {
      display: inline-block;
      background: var(--accent);
      color: #fff;
      font-size: 0.75rem;
      padding: 2px 8px;
      border-radius: 999px;
      vertical-align: middle;
      margin-left: 8px;
    }
    .lead { color: var(--muted); margin: 0 0 24px; }
    section {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      margin-bottom: 16px;
    }
    h2 {
      font-size: 1.1rem;
      margin: 0 0 12px;
      color: #d4c8ff;
    }
    h3 { font-size: 0.95rem; margin: 16px 0 8px; color: #c4b5fd; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; width: 28%; }
    code, pre {
      font-family: "Cascadia Code", "Fira Code", ui-monospace, monospace;
      font-size: 0.84rem;
    }
    code {
      background: var(--code);
      padding: 1px 6px;
      border-radius: 4px;
      color: #e9d5ff;
    }
    pre {
      background: var(--code);
      padding: 12px 14px;
      border-radius: 8px;
      overflow-x: auto;
      border: 1px solid rgba(255,255,255,0.06);
      color: #e8e0f5;
    }
    .method {
      display: inline-block;
      min-width: 3.2rem;
      text-align: center;
      font-weight: 700;
      font-size: 0.72rem;
      padding: 2px 6px;
      border-radius: 4px;
      margin-right: 6px;
    }
    .put { background: #7c3aed; }
    .get { background: #059669; }
    .del { background: #b45309; }
    a { color: #c4b5fd; }
    ul { margin: 8px 0; padding-left: 1.2rem; color: var(--muted); }
    li { margin: 4px 0; }
    footer {
      margin-top: 24px;
      color: var(--muted);
      font-size: 0.85rem;
    }
    .grid {
      display: grid;
      gap: 8px;
    }
    @media (min-width: 640px) {
      .grid.two { grid-template-columns: 1fr 1fr; }
    }
    .card-mini {
      background: rgba(0,0,0,0.2);
      border-radius: 8px;
      padding: 10px 12px;
      border: 1px solid rgba(255,255,255,0.05);
    }
    .card-mini strong { display: block; margin-bottom: 4px; }
  </style>
</head>
<body>
<main>
  <h1>${esc(doc.service)} <span class="badge">v${esc(doc.version)}</span></h1>
  <p class="lead">${esc(doc.description)}</p>

  <section>
    <h2>Hosts</h2>
    <div class="grid two">
      <div class="card-mini">
        <strong>Storage (upload + legacy)</strong>
        <code>${esc(doc.hosts.storage)}</code>
      </div>
      <div class="card-mini">
        <strong>R2 facade (public media)</strong>
        <code>${esc(doc.hosts.r2)}</code>
      </div>
    </div>
    <p style="color:var(--muted);font-size:0.9rem;margin:12px 0 0">${esc(doc.hosts.note)}</p>
  </section>

  <section>
    <h2>SEKAI v2 — prefer this</h2>
    <h3><span class="method put">PUT</span><code>/v2/upload</code></h3>
    <table>
      <tr><th>Headers</th><td>
        <code>X-Filename</code>, <code>Content-Type</code>, <code>Content-Length</code><br/>
        optional: <code>X-Sekai-Kind</code>, <code>X-Image-Width</code>, <code>X-Image-Height</code><br/>
        for uploads &gt; 512 MiB: <code>Authorization: Bearer &lt;sekai-pass-token&gt;</code>
      </td></tr>
      <tr><th>Body</th><td>raw file bytes</td></tr>
      <tr><th>Limits</th><td>Anonymous &le; <strong>512 MiB</strong>. Larger (up to ~1GB) needs a SEKAI Pass token (else <code>401</code>); over ~1GB &rarr; <code>413</code>. Cloudflare per-plan request-body limits may cap large uploads further.</td></tr>
      <tr><th>Response</th><td><code>uuid</code>, <code>type</code>, <code>size</code> (kB), <code>name</code>, <code>kind</code>, <code>url</code>, optional <code>w</code>/<code>h</code></td></tr>
    </table>
    <pre>${esc(doc.sekaiv2.upload.example)}</pre>

    <h3><span class="method get">GET</span> Resolve</h3>
    <ul>
      <li><code>/images/{uuid}</code></li>
      <li><code>/files/{uuid}</code></li>
      <li><code>/stickers/{uuid}</code></li>
      <li><code>/v2/meta/{uuid}</code> — JSON metadata</li>
    </ul>

    <h3>Message payload (Nightcord / SEKAI markup)</h3>
    <pre>${esc(doc.sekaiv2.message_payload.image)}
${esc(doc.sekaiv2.message_payload.file)}
${esc(doc.sekaiv2.message_payload.custom_stamp)}</pre>
  </section>

  <section>
    <h2>Legacy — still supported</h2>
    <p><span class="method put">PUT</span><code>/</code> → <code>{ key, url, size }</code> where key is <code>{uid}/{fileUuid}.ext</code></p>
    <p><span class="method get">GET</span><span class="method del">DEL</span><code>/{key}</code> · chunked under <code>/chunked/…</code></p>
    <p style="color:var(--muted);font-size:0.9rem;margin:0">Use for older clients and historical messages. New Nightcord builds use v2.</p>
  </section>

  <section>
    <h2>Machine-readable / agents</h2>
    <p>
      <a href="${esc(origin)}/?format=json"><code>GET /?format=json</code></a>
      · <a href="${esc(origin)}/?format=md"><code>GET /?format=md</code></a>
      · <a href="${esc(origin)}/v2"><code>/v2</code></a>
    </p>
    <ul>
      <li><code>Accept: application/json</code> → JSON</li>
      <li><code>Accept: text/markdown</code> → Markdown (<code>Content-Type: text/markdown</code>, <code>x-markdown-tokens</code>)</li>
      <li>Default / browsers → HTML</li>
    </ul>
  </section>

  <section>
    <h2>Content policy &amp; abuse</h2>
    <p style="color:var(--muted);font-size:0.9rem;margin:0 0 8px">${esc(doc.policy.summary)}</p>
    <p style="color:var(--muted);font-size:0.9rem;margin:0">${esc(doc.policy.report)}</p>
  </section>

  <footer>
    Nightcord storage worker · SEKAI resource facade · same Worker on storage.* and r2.*
  </footer>
</main>
</body>
</html>`;
}

/* ═══════════════════════════════════════════════════════
 *  上传大小分档 + 鉴权
 *
 *  匿名 ≤ ANON_MAX_UPLOAD_BYTES（512 MiB，对齐 Cloudflare 缓存对象上限）。
 *  (ANON, MAX] 需要有效的 SEKAI Pass Bearer token（查 env.AUTH_DB）。
 *  > MAX 一律拒绝。
 *
 *  只读**声明大小**（Content-Length / X-File-Size），不缓冲 body。
 *  只有当声明大小超过匿名档时才碰 AUTH_DB —— 匿名小文件不产生 D1 查询。
 * ═══════════════════════════════════════════════════════ */

/**
 * @param {Request} req
 * @param {object} env  平台 bindings（大文件时需含 AUTH_DB）
 * @param {number} declaredSize  声明的字节数
 * @param {string} [invalidMsg]  非法大小时的错误文案
 * @returns {Promise<Response|null>} null 表示放行；Response 表示拒绝
 */
async function authorizeUploadSize(req, env, declaredSize, invalidMsg) {
  if (!Number.isFinite(declaredSize) || declaredSize < 0) {
    return fail(400, invalidMsg || "Invalid Content-Length");
  }
  if (declaredSize > MAX_UPLOAD_BYTES) {
    return fail(413, "Payload Too Large");
  }
  if (declaredSize <= ANON_MAX_UPLOAD_BYTES) return null; // 匿名档：不查 D1
  const user = await authenticate(req, env);
  if (!user) {
    return fail(401, "SEKAI Pass required for uploads over 512 MiB");
  }
  return null;
}

/* ═══════════════════════════════════════════════════════
 *  SEKAI v2
 * ═══════════════════════════════════════════════════════ */

function inferKind(mime, hint) {
  const h = (hint || "").toLowerCase();
  if (h === "image" || h === "file" || h === "sticker") return h;
  const m = (mime || "").toLowerCase();
  if (m.startsWith("image/")) return "image";
  return "file";
}

/**
 * Best-effort meta sidecar → AttachFiles/sekai/{uuid}.json
 * Does not throw; failures are logged only.
 */
async function persistSekaiMeta(c, meta) {
  const SEKAI_USER = "sekai";
  try {
    const metaKey = `${c.PREFIX}/${SEKAI_USER}/${meta.uuid}.json`;
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const mr = await uploadObject(c, {
      userid: SEKAI_USER,
      ossKey: metaKey,
      contentType: "application/json",
      displayName: `${meta.uuid}.json`,
      cdValue: 'inline; filename="_meta.json"',
      body: metaBytes,
      bodySize: metaBytes.byteLength,
    });
    if (!mr) {
      console.warn("v2 meta upload failed: no sign/response", meta.uuid);
      return;
    }
    if (mr.status !== 200 && mr.status !== 201) {
      const errText = await mr.text().catch(() => "");
      console.warn("v2 meta upload failed:", mr.status, errText.slice(0, 200));
    }
    await drain(mr);
  } catch (e) {
    console.warn("v2 meta upload failed:", e);
  }
}

/**
 * PUT /v2/upload
 * OSS: AttachFiles/sekai/{uuid}{ext}
 * Meta: AttachFiles/sekai/{uuid}.json (async via waitUntil — does not block 200)
 */
async function putSekaiV2(req, c, ctx, env) {
  if (!c.AKID) return fail(500, "OSS_AKID not configured");

  const encodedName = (req.headers.get("X-Filename") || "file").trim();
  const rawName = safeDecodeFilename(encodedName);
  if (!rawName) return fail(400, "Invalid X-Filename");
  const ct = req.headers.get("Content-Type") || "application/octet-stream";
  const fSizeStr = req.headers.get("Content-Length");
  if (!fSizeStr) return fail(400);
  const fileSize = parseInt(fSizeStr, 10);
  const sizeErr = await authorizeUploadSize(req, env, fileSize);
  if (sizeErr) return sizeErr;

  if (/\.\.|\/\/|[\x00-\x1f]/.test(rawName)) return fail(400);

  const kind = inferKind(ct, req.headers.get("X-Sekai-Kind"));
  const uuid = crypto.randomUUID();
  const ext = extOf(rawName);
  // OSS layout: AttachFiles/sekai/{uuid}{ext}
  // Policy/prefix user id = "sekai" (local policy allows AttachFiles/sekai/…)
  const SEKAI_USER = "sekai";
  const ossKey = `${c.PREFIX}/${SEKAI_USER}/${uuid}${ext}`;
  const display = sanitize(rawName);
  const cdValue = buildContentDisposition(display);

  const r = await uploadObject(c, {
    userid: SEKAI_USER,
    ossKey,
    contentType: ct,
    displayName: display,
    cdValue,
    body: req.body,
    bodySize: fileSize,
  });
  if (!r) return fail(502);
  if (r.status !== 200 && r.status !== 201) {
    const errText = await r.text().catch(() => "");
    console.error("OSS error (v2):", r.status, errText.slice(0, 800));
    await drain(r);
    if (r.status === 520 || r.status === 503) {
      return fail(502, `OSS temporary error (${r.status}); retry upload`);
    }
    return fail(502);
  }
  await drain(r);

  let w = parseInt(req.headers.get("X-Image-Width") || "", 10);
  let h = parseInt(req.headers.get("X-Image-Height") || "", 10);
  if (!Number.isFinite(w) || w <= 0) w = undefined;
  if (!Number.isFinite(h) || h <= 0) h = undefined;

  const sizeKb = Math.round((fileSize / 1024) * 10) / 10;
  const meta = {
    uuid,
    kind,
    type: ct,
    name: rawName,
    size_bytes: fileSize,
    size: sizeKb,
    ext,
    ossKey,
    created: new Date().toISOString(),
  };
  if (w) meta.w = w;
  if (h) meta.h = h;

  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(persistSekaiMeta(c, meta));
  } else {
    persistSekaiMeta(c, meta).catch(() => {});
  }

  const publicPath = `/${kind === "sticker" ? "stickers" : kind === "image" ? "images" : "files"}/${uuid}`;

  return ok({
    uuid,
    key: uuid,
    type: ct,
    size: sizeKb,
    size_bytes: fileSize,
    name: rawName,
    kind,
    url: publicPath,
    ...(w ? { w } : {}),
    ...(h ? { h } : {}),
  });
}

async function loadSekaiMeta(c, uuid) {
  if (!UUID_RE.test(uuid)) return null;
  const metaKey = `${c.PREFIX}/sekai/${uuid}.json`;
  const r = await fetch(`${c.OSS_HOST}/${metaKey}`);
  if (r.status === 404) {
    await drain(r);
    return null;
  }
  if (!r.ok) {
    await drain(r);
    return null;
  }
  try {
    return await r.json();
  } catch {
    return null;
  }
}

async function resolveSekaiOssKey(c, uuid) {
  const meta = await loadSekaiMeta(c, uuid);
  if (meta && meta.ossKey) return { ossKey: meta.ossKey, meta };

  // Fallback: probe common extensions in parallel when meta is missing
  const probes = await Promise.all(
    SEKAI_PROBE_EXTS.map(async (ext) => {
      const ossKey = `${c.PREFIX}/sekai/${uuid}${ext}`;
      try {
        const head = await fetch(`${c.OSS_HOST}/${ossKey}`, { method: "HEAD" });
        const ok = head.ok;
        const type = head.headers.get("Content-Type") || "application/octet-stream";
        await drain(head);
        return ok ? { ossKey, type } : null;
      } catch {
        return null;
      }
    }),
  );
  const hit = probes.find(Boolean);
  if (!hit) return null;
  return {
    ossKey: hit.ossKey,
    meta: meta || { uuid, type: hit.type },
  };
}

async function getSekaiObject(req, ctx, url, c, kind, uuid) {
  if (!UUID_RE.test(uuid)) return fail(400);

  const resolved = await resolveSekaiOssKey(c, uuid);
  if (!resolved) return fail(404);

  // Reuse legacy GET proxy against concrete ossKey
  return await get(req, ctx, url, c, resolved.ossKey);
}

async function getSekaiMeta(req, c, uuid) {
  if (!UUID_RE.test(uuid)) return fail(400);
  const meta = await loadSekaiMeta(c, uuid);
  if (!meta) return fail(404);
  if (req.method === "HEAD") {
    return new Response(null, {
      status: 200,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });
  }
  // Public clients do not need internal object keys.
  const { ossKey: _omit, ...publicMeta } = meta;
  return ok(publicMeta);
}

/* ═══════════════════════════════════════════════════════
 *  PUT — 安全路径直传
 * ═══════════════════════════════════════════════════════ */
async function putSafe(req, c, env) {
  const safePath = (req.headers.get("X-Safe-Path") || "").trim();
  const encodedName = (req.headers.get("X-Filename") || "file").trim();
  const rawName = safeDecodeFilename(encodedName);
  if (!rawName) return fail(400, "Invalid X-Filename");
  const ct = req.headers.get("Content-Type") || "application/octet-stream";
  const fSizeStr = req.headers.get("Content-Length");
  if (!fSizeStr) return fail(400);
  const fileSize = parseInt(fSizeStr, 10);
  const sizeErr = await authorizeUploadSize(req, env, fileSize);
  if (sizeErr) return sizeErr;

  const safeId = getSafeId(safePath);
  if (!safeId) {
    return new Response(
      JSON.stringify({
        error: "Forbidden: not a safe path. Use: " + [...SAFE_USERIDS].join(", "),
      }),
      {
        status: 403,
        headers: {
          "Content-Type": "application/json;charset=utf-8",
          "Access-Control-Allow-Origin": "*",
        },
      },
    );
  }

  if (/\.\.|\/\/|[\x00-\x1f]/.test(safePath)) return fail(400);
  if (/\.\.|\/\/|[\x00-\x1f]/.test(rawName)) return fail(400);
  if (!rawName || rawName === "file") return fail(400);

  const cleanSP = safePath.replace(/\/+$/, "");
  const ossKey = `${c.PREFIX}/${cleanSP}/${rawName}`;
  const display = sanitize(rawName);
  const cdValue = buildContentDisposition(display);

  const r = await uploadObject(c, {
    userid: safeId,
    ossKey,
    contentType: ct,
    displayName: display,
    cdValue,
    body: req.body,
    bodySize: fileSize,
  });
  if (!r) return fail(502);
  if (r.status !== 200 && r.status !== 201) {
    const errText = await r.text().catch(() => "");
    console.error("OSS error:", r.status, errText);
    await drain(r);
    return fail(502);
  }
  await drain(r);

  const k = ossKey.slice(c.PREFIX.length + 1);
  return ok({ key: k, url: `/${k}`, size: fileSize, safe: true });
}

/* ═══════════════════════════════════════════════════════
 *  PUT — 单文件直传 (legacy)
 * ═══════════════════════════════════════════════════════ */
async function put(req, c, env) {
  const encodedName = (req.headers.get("X-Filename") || "file").trim();
  const rawName = safeDecodeFilename(encodedName);
  if (!rawName) return fail(400, "Invalid X-Filename");
  const ct = req.headers.get("Content-Type") || "application/octet-stream";
  const fSizeStr = req.headers.get("Content-Length");
  if (!fSizeStr) return fail(400);
  const fileSize = parseInt(fSizeStr, 10);
  const sizeErr = await authorizeUploadSize(req, env, fileSize);
  if (sizeErr) return sizeErr;

  const uid = crypto.randomUUID();
  const ext = extOf(rawName);
  const ossKey = `${c.PREFIX}/${uid}/${crypto.randomUUID()}${ext}`;
  const display = sanitize(rawName);
  const cdValue = buildContentDisposition(display);

  const r = await uploadObject(c, {
    userid: uid,
    ossKey,
    contentType: ct,
    displayName: display,
    cdValue,
    body: req.body,
    bodySize: fileSize,
  });
  if (!r) return fail(502);
  if (r.status !== 200 && r.status !== 201) {
    await drain(r);
    return fail(502);
  }
  await drain(r);

  const k = ossKey.slice(c.PREFIX.length + 1);
  return ok({ key: k, url: `/${k}`, size: fileSize });
}

/* ═══════════════════════════════════════════════════════
 *  PUT — 分片上传
 * ═══════════════════════════════════════════════════════ */
async function putChunk(req, c, env) {
  const fileId = (req.headers.get("X-File-ID") || "").trim();
  const indexStr = (req.headers.get("X-Chunk-Index") || "").trim();
  const totalStr = (req.headers.get("X-Chunk-Total") || "").trim();
  const encodedName = (req.headers.get("X-Original-Filename") || "file").trim();
  const fileSizeStr = (req.headers.get("X-File-Size") || "").trim();
  const ct = req.headers.get("Content-Type") || "application/octet-stream";
  const chunkSizeStr = req.headers.get("Content-Length");

  if (!fileId || !indexStr || !totalStr || !chunkSizeStr || !fileSizeStr) return fail(400);

  const index = parseInt(indexStr, 10);
  const total = parseInt(totalStr, 10);
  const chunkSize = parseInt(chunkSizeStr, 10);
  const fileSize = parseInt(fileSizeStr, 10);

  if (isNaN(index) || isNaN(total) || isNaN(chunkSize) || isNaN(fileSize)) return fail(400);
  if (index < 0 || index >= total || total < 1 || total > 10000) return fail(400);
  // 单片本身也不能超过绝对上限（防单请求异常大）
  if (chunkSize < 0 || chunkSize > MAX_UPLOAD_BYTES) return fail(400, "Invalid size");
  // 按**总文件**大小分档鉴权：> 512 MiB 的整体上传每片都要带 SEKAI Pass
  const sizeErr = await authorizeUploadSize(req, env, fileSize, "Invalid size");
  if (sizeErr) return sizeErr;
  // Basic fileId hygiene — used in OSS keys
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(fileId)) return fail(400, "Invalid X-File-ID");

  const rawName = safeDecodeFilename(encodedName);
  if (!rawName) return fail(400, "Invalid X-Original-Filename");
  const safePath = (req.headers.get("X-Safe-Path") || "").trim();
  const safeId = safePath ? getSafeId(safePath) : null;

  const signUid = safeId || fileId;
  const basePath = safeId
    ? `${c.PREFIX}/${safePath.replace(/\/+$/, "")}`
    : `${c.PREFIX}/${fileId}`;
  const chunkKey = `${basePath}/${fileId}/${index}`;
  const display = sanitize(rawName);
  const cdValue = buildContentDisposition(display);

  const r = await uploadObject(c, {
    userid: signUid,
    ossKey: chunkKey,
    contentType: ct,
    displayName: display,
    cdValue,
    body: req.body,
    bodySize: chunkSize,
  });
  if (!r) return fail(502);
  if (r.status !== 200 && r.status !== 201) {
    await drain(r);
    return fail(502);
  }
  await drain(r);

  let metaUploaded = false;
  if (index === total - 1) {
    const meta = {
      name: rawName,
      size: fileSize,
      type: ct,
      chunks: total,
      chunkSize: c.CHUNK_SIZE,
      created: new Date().toISOString(),
      safe: !!safeId,
    };
    const metaKey = `${basePath}/${fileId}/_meta`;
    const metaBytes = new TextEncoder().encode(JSON.stringify(meta));
    const mr = await uploadObject(c, {
      userid: signUid,
      ossKey: metaKey,
      contentType: "application/json",
      displayName: "_meta",
      cdValue: 'inline; filename="_meta"',
      body: metaBytes,
      bodySize: metaBytes.byteLength,
    });
    if (mr && (mr.status === 200 || mr.status === 201)) metaUploaded = true;
    if (mr) await drain(mr);
  }

  const relKey = `${basePath.slice(c.PREFIX.length + 1)}/${fileId}`;
  return ok({
    chunkIndex: index,
    totalChunks: total,
    key: relKey,
    url: `/chunked/${relKey}`,
    done: index === total - 1,
    metaUploaded,
    safe: !!safeId,
  });
}

/* ═══════════════════════════════════════════════════════
 *  Upload (PostObject policy / PutObject V1)
 * ═══════════════════════════════════════════════════════ */

function bufToBase64(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  // chunked to avoid call-stack / argument limits
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
  }
  return btoa(s);
}

async function hmacSha1Base64(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bufToBase64(sig);
}

/** Local PostObject policy — same shape as legacy webservice. */
async function signPolicyLocal(c, userid) {
  const exp = new Date(Date.now() + 30 * 60 * 1000);
  // Aliyun accepts ISO-8601 with millis
  const expiration = exp.toISOString();
  const policyObj = {
    expiration,
    conditions: [
      ["content-length-range", 0, MAX_UPLOAD_BYTES],
      ["starts-with", "$key", `${c.PREFIX}/${userid}/`],
    ],
  };
  // Policy document must be base64 of UTF-8 JSON (compact is fine)
  const policy = bufToBase64(new TextEncoder().encode(JSON.stringify(policyObj)));
  const signature = await hmacSha1Base64(c.AKS, policy);
  return [policy, signature];
}

async function fetchSignRemote(c, userid) {
  try {
    const r = await fetch(
      `${c.BACKEND}/File/GetOssPolicy2Signature?` +
        new URLSearchParams({ userid, bucket: c.BUCKET }),
    );
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  }
}

/**
 * Returns [policy, signature] for PostObject.
 * Prefer local HMAC when OSS_AKS is set (no remote signing RTT).
 */
async function fetchSign(c, userid) {
  if (c.AKS) {
    try {
      return await signPolicyLocal(c, userid);
    } catch (e) {
      console.error("local policy sign failed:", e);
      // fall through to remote if configured
    }
  }
  if (c.BACKEND) return fetchSignRemote(c, userid);
  return null;
}

function bodyToStream(body) {
  if (!body) {
    return new ReadableStream({
      start(c) {
        c.close();
      },
    });
  }
  if (typeof body.getReader === "function" && !(body instanceof Uint8Array)) {
    return body;
  }
  if (body instanceof Uint8Array || body instanceof ArrayBuffer) {
    const u8 = body instanceof ArrayBuffer ? new Uint8Array(body) : body;
    return new ReadableStream({
      start(controller) {
        controller.enqueue(u8);
        controller.close();
      },
    });
  }
  if (typeof body[Symbol.asyncIterator] === "function") {
    return ReadableStream.from(body);
  }
  return null;
}

/**
 * PutObject with OSS V1 signature (needs OSS_AKS).
 * Streams the request body as-is — no multipart wrapper.
 * Signs CanonicalizedResource as /{bucket}/{key} (required for custom domains too).
 */
async function putObjectOSS(c, ossKey, contentType, body, bodySize) {
  const date = new Date().toUTCString();
  const ct = contentType || "application/octet-stream";
  const resource = `/${c.BUCKET}/${ossKey}`;
  const stringToSign = `PUT\n\n${ct}\n${date}\n${resource}`;
  const signature = await hmacSha1Base64(c.AKS, stringToSign);
  const stream = bodyToStream(body);
  if (!stream) throw new Error("unsupported body type for PutObject");

  const path = ossKey
    .split("/")
    .map((s) => encodeURIComponent(s))
    .join("/");
  // Prefer CDN/custom upload host; fall back to regional virtual-host URL built by caller retry.
  const base = (c.UPLOAD_HOST || c.OSS_HOST).replace(/\/$/, "");
  return fetch(`${base}/${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": ct,
      "Content-Length": String(bodySize),
      Date: date,
      Authorization: `OSS ${c.AKID}:${signature}`,
    },
    body: stream,
  });
}

/* ═══════════════════════════════════════════════════════
 *  PostObject → OSS (streaming — do NOT buffer whole file)
 * ═══════════════════════════════════════════════════════ */

function toUint8(body) {
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  return null;
}

async function postToOSSOnce(uploadHost, c, ossKey, policy, sig, contentType, displayName, cdValue, body, bodySize) {
  const boundary = "----CfWkrBnd" + crypto.randomUUID().replace(/-/g, "");
  const dashBoundary = "--" + boundary;
  const crlf = "\r\n";

  const formFields = [
    { n: "key", v: ossKey },
    { n: "policy", v: policy },
    { n: "Signature", v: sig },
    { n: "OSSAccessKeyId", v: c.AKID },
    { n: "success_action_status", v: "201" },
    { n: "Content-Disposition", v: cdValue },
  ];

  let head = "";
  for (const f of formFields) {
    head += `${dashBoundary}${crlf}Content-Disposition: form-data; name="${f.n}"${crlf}${crlf}${f.v}${crlf}`;
  }
  head += `${dashBoundary}${crlf}Content-Disposition: form-data; name="file"; filename="${displayName}"${crlf}`;
  head += `Content-Type: ${contentType}${crlf}${crlf}`;
  const tail = `${crlf}${dashBoundary}--${crlf}`;

  const enc = new TextEncoder();
  const headData = enc.encode(head);
  const tailData = enc.encode(tail);
  const totalLen = headData.byteLength + bodySize + tailData.byteLength;

  const fileStream = bodyToStream(body);
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();

  const pump = async () => {
    try {
      await writer.write(headData);
      if (fileStream) {
        const reader = fileStream.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) await writer.write(value);
        }
      }
      await writer.write(tailData);
      await writer.close();
    } catch (e) {
      console.error("postToOSS pump failed:", e && e.message ? e.message : e);
      try {
        await writer.abort(e);
      } catch {
        /* ignore */
      }
    }
  };
  pump();

  return fetch(uploadHost, {
    method: "POST",
    headers: {
      "Content-Type": `multipart/form-data; boundary=${boundary}`,
      "Content-Length": String(totalLen),
    },
    body: readable,
  });
}

async function postToOSS(c, ossKey, policy, sig, contentType, displayName, cdValue, body, bodySize) {
  const primary = c.UPLOAD_HOST || c.OSS_HOST;
  const regional = c.OSS_HOST;
  const r = await postToOSSOnce(
    primary,
    c,
    ossKey,
    policy,
    sig,
    contentType,
    displayName,
    cdValue,
    body,
    bodySize,
  );

  if ((r.status === 200 || r.status === 201) || primary === regional) {
    return r;
  }

  const buffered = toUint8(body);
  if (!buffered) {
    console.warn("postToOSS primary failed (no retry for stream):", primary, r.status);
    return r;
  }

  const errText = await r.text().catch(() => "");
  console.warn("postToOSS primary failed, retry regional:", primary, r.status, errText.slice(0, 200));
  await drain(r);

  return postToOSSOnce(
    regional,
    c,
    ossKey,
    policy,
    sig,
    contentType,
    displayName,
    cdValue,
    buffered,
    buffered.byteLength,
  );
}

/**
 * Unified upload entry used by all PUT handlers.
 *
 * With OSS_AKS:
 *  - PUT_MODE=put  → PutObject only (can be slow CF→regional; use for tests)
 *  - PUT_MODE=post → PostObject with local HMAC policy (default-ish for CF edges)
 *  - PUT_MODE=auto → PostObject (benches: CF LAX Post ≫ Put on regional; fcdata similar)
 * Without OSS_AKS: PostObject via SIGN_BACKEND (legacy).
 */
async function uploadObject(c, opts) {
  const { userid, ossKey, contentType, displayName, cdValue, body, bodySize } = opts;

  // CF-edge benches (LAX): regional PutObject was ~4× slower than PostObject.
  // Only use PutObject when explicitly requested.
  const preferPut = c.AKS && c.PUT_MODE === "put";

  const buffered = toUint8(body);

  if (preferPut) {
    try {
      const r = await putObjectOSS(c, ossKey, contentType, body, bodySize);
      if (r.status === 200 || r.status === 201) return r;

      const errText = await r.text().catch(() => "");
      console.warn("PutObject failed:", r.status, errText.slice(0, 240));
      await drain(r);

      if (!buffered) return new Response(errText, { status: r.status });

      const sign = await fetchSign(c, userid);
      if (!sign) return new Response(errText, { status: r.status });
      const [policy, sig] = sign;
      return postToOSS(
        c,
        ossKey,
        policy,
        sig,
        contentType,
        displayName,
        cdValue,
        buffered,
        buffered.byteLength,
      );
    } catch (e) {
      console.warn("PutObject error:", e && e.message ? e.message : e);
      if (!buffered) throw e;
    }
  }

  const sign = await fetchSign(c, userid);
  if (!sign) return null;
  const [policy, sig] = sign;
  return postToOSS(
    c,
    ossKey,
    policy,
    sig,
    contentType,
    displayName,
    cdValue,
    buffered || body,
    bodySize,
  );
}

/* ═══════════════════════════════════════════════════════
 *  GET | HEAD — 单文件
 * ═══════════════════════════════════════════════════════ */
async function get(req, ctx, url, c, ossKey) {
  const method = req.method;
  const isRange = req.headers.has("Range");
  const path = url.pathname.slice(1);
  const safe = !!getSafeId(path);

  const fwd = pick(req.headers, ["Range", "If-None-Match", "If-Modified-Since"]);
  const r = await fetch(`${c.OSS_HOST}/${ossKey}`, {
    method: method === "HEAD" ? "HEAD" : "GET",
    headers: fwd,
  });
  if (r.status >= 400) {
    await drain(r);
    return fail(r.status === 404 ? 404 : 502);
  }

  const h = new Headers();
  h.set(
    "Cache-Control",
    safe ? "no-cache, no-store, must-revalidate" : "public, max-age=31536000, immutable",
  );
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Expose-Headers", PASS_HEADERS.join(", "));
  for (const k of PASS_HEADERS) {
    const v = r.headers.get(k);
    if (v) h.set(k, v);
  }

  const resp = new Response(method === "HEAD" ? null : r.body, { status: r.status, headers: h });
  return resp;
}

/* ═══════════════════════════════════════════════════════
 *  GET | HEAD — 分片合并下载
 * ═══════════════════════════════════════════════════════ */
async function getChunked(req, ctx, url, c, innerPath) {
  const method = req.method;
  const isRange = req.headers.has("Range");

  const metaKey = `${c.PREFIX}/${innerPath}/_meta`;
  const metaResp = await fetch(`${c.OSS_HOST}/${metaKey}`);
  if (metaResp.status === 404) {
    await drain(metaResp);
    return fail(404);
  }
  if (!metaResp.ok) {
    await drain(metaResp);
    return fail(502);
  }
  const meta = await metaResp.json();

  const totalSize = meta.size;
  const totalChunks = meta.chunks;
  const chunkSize = meta.chunkSize;
  const display = sanitize(meta.name);
  const cdValue = buildContentDisposition(display);

  const h = new Headers();
  h.set("Content-Type", meta.type || "application/octet-stream");
  h.set("Content-Disposition", cdValue);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Expose-Headers", PASS_HEADERS.join(", "));
  h.set("Accept-Ranges", "bytes");
  h.set("Cache-Control", "public, max-age=31536000, immutable");

  if (isRange) {
    const parsed = parseRange(req.headers.get("Range"), totalSize);
    if (!parsed) {
      return new Response(null, {
        status: 416,
        headers: {
          "Content-Range": `bytes */${totalSize}`,
          "Access-Control-Allow-Origin": "*",
        },
      });
    }

    const [rangeStart, rangeEnd] = parsed;
    h.set("Content-Length", String(rangeEnd - rangeStart + 1));
    h.set("Content-Range", `bytes ${rangeStart}-${rangeEnd}/${totalSize}`);
    if (method === "HEAD") return new Response(null, { status: 206, headers: h });
    return new Response(
      createRangeStream(c, innerPath, totalChunks, chunkSize, totalSize, rangeStart, rangeEnd),
      { status: 206, headers: h },
    );
  }

  h.set("Content-Length", String(totalSize));
  if (method === "HEAD") return new Response(null, { status: 200, headers: h });
  return new Response(createFullStream(c, innerPath, totalChunks), { status: 200, headers: h });
}

function createFullStream(c, innerPath, totalChunks) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  (async () => {
    try {
      let next = fetchChunk(c, innerPath, 0);
      for (let i = 0; i < totalChunks; i++) {
        const r = await next;
        if (i + 1 < totalChunks) next = fetchChunk(c, innerPath, i + 1);
        if (!r.ok) throw new Error(`chunk ${i}: ${r.status}`);
        const reader = r.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          await writer.write(value);
        }
      }
      await writer.close();
    } catch {
      try {
        await writer.abort();
      } catch {
        /* ignore */
      }
    }
  })();
  return readable;
}

function createRangeStream(c, innerPath, totalChunks, chunkSize, totalSize, rangeStart, rangeEnd) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  (async () => {
    try {
      const startChunk = Math.floor(rangeStart / chunkSize);
      const endChunk = Math.min(Math.floor(rangeEnd / chunkSize), totalChunks - 1);
      for (let i = startChunk; i <= endChunk; i++) {
        const isLast = i === totalChunks - 1;
        const thisChunkSize = isLast ? totalSize - i * chunkSize : chunkSize;
        const chunkStart = i * chunkSize;
        const localStart = Math.max(0, rangeStart - chunkStart);
        const localEnd = Math.min(thisChunkSize - 1, rangeEnd - chunkStart);
        const needSub = localStart > 0 || localEnd < thisChunkSize - 1;
        const fh = new Headers();
        if (needSub) fh.set("Range", `bytes=${localStart}-${localEnd}`);
        const r = await fetch(`${c.OSS_HOST}/${c.PREFIX}/${innerPath}/${i}`, { headers: fh });
        if (!r.ok && r.status !== 206) throw new Error(`chunk ${i}: ${r.status}`);
        const reader = r.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          await writer.write(value);
        }
      }
      await writer.close();
    } catch {
      try {
        await writer.abort();
      } catch {
        /* ignore */
      }
    }
  })();
  return readable;
}

function fetchChunk(c, innerPath, index) {
  return fetch(`${c.OSS_HOST}/${c.PREFIX}/${innerPath}/${index}`);
}

/* ═══════════════════════════════════════════════════════
 *  DELETE
 * ═══════════════════════════════════════════════════════ */
async function delSafe(_req, ctx, url, c, path) {
  if (!deleteAllowed(c)) {
    return fail(403, "delete is disabled — set DELETE_ENABLED=1 to enable. NOTE: this endpoint has no authentication (issue #3); solve that first.");
  }
  if (!c.BACKEND) return fail(500, "SIGN_BACKEND required for delete");
  const safeId = getSafeId(path);
  const ossKey = `${c.PREFIX}/${path}`;

  const r = await fetch(`${c.BACKEND}/File/DeleteOssObject`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ userid: safeId, key: ossKey, bucket: c.BUCKET }),
  });
  let success = false;
  try {
    success = (await r.json()) == 1;
  } catch {
    /* ignore */
  }

  if (success) ctx.waitUntil(ctx.cache.purge({ pathPrefixes: [`/${path}`] }));
  return ok({ ok: success, safe: true });
}

async function del(_req, ctx, url, c, path, ossKey) {
  if (!deleteAllowed(c)) {
    return fail(403, "delete is disabled — set DELETE_ENABLED=1 to enable. NOTE: this endpoint has no authentication (issue #3); solve that first.");
  }
  if (!c.BACKEND) return fail(500, "SIGN_BACKEND required for delete");
  const uid = firstSeg(path);
  const r = await fetch(`${c.BACKEND}/File/DeleteOssObject`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ userid: uid, key: ossKey, bucket: c.BUCKET }),
  });
  let success = false;
  try {
    success = (await r.json()) == 1;
  } catch {
    /* ignore */
  }
  if (success) ctx.waitUntil(ctx.cache.purge({ pathPrefixes: [`/${path}`] }));
  return ok({ ok: success });
}

async function delChunked(_req, ctx, url, c, innerPath) {
  if (!deleteAllowed(c)) {
    return fail(403, "delete is disabled — set DELETE_ENABLED=1 to enable. NOTE: this endpoint has no authentication (issue #3); solve that first.");
  }
  if (!c.BACKEND) return fail(500, "SIGN_BACKEND required for delete");
  const safeId = getSafeId(innerPath);
  const uid = safeId || firstSeg(innerPath);
  const metaKey = `${c.PREFIX}/${innerPath}/_meta`;
  const metaResp = await fetch(`${c.OSS_HOST}/${metaKey}`);
  if (metaResp.status === 404) {
    await drain(metaResp);
    return ok({ ok: false, error: "not found" });
  }
  if (!metaResp.ok) {
    await drain(metaResp);
    return fail(502);
  }

  const meta = await metaResp.json();
  const keys = [];
  for (let i = 0; i < meta.chunks; i++) keys.push(`${c.PREFIX}/${innerPath}/${i}`);
  keys.push(metaKey);

  if (!deleteAllowed(c)) {
    return fail(403, "delete is disabled — set DELETE_ENABLED=1 to enable. NOTE: this endpoint has no authentication (issue #3); solve that first.");
  }
  if (!c.BACKEND) return fail(500, "SIGN_BACKEND required for delete");

  const results = await Promise.all(
    keys.map(async (key) => {
      try {
        const r = await fetch(`${c.BACKEND}/File/DeleteOssObject`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ userid: uid, key, bucket: c.BUCKET }),
        });
        try {
          return (await r.json()) == 1;
        } catch {
          return false;
        }
      } catch {
        return false;
      }
    }),
  );

  const allOk = results.every(Boolean);
  if (allOk) ctx.waitUntil(ctx.cache.purge({ pathPrefixes: [`/chunked/${innerPath}`] }));
  return ok({
    ok: allOk,
    deleted: results.filter(Boolean).length,
    total: keys.length,
    safe: !!safeId,
  });
}

/* ═══════════════════════════════════════════════════════
 *  工具
 * ═══════════════════════════════════════════════════════ */

/** Decode percent-encoded filenames without throwing on malformed sequences. */
function safeDecodeFilename(encoded) {
  try {
    const name = decodeURIComponent(String(encoded || "").trim() || "file");
    // Cap absurd names (path-like junk still filtered by callers)
    if (name.length > 512) return null;
    return name;
  } catch {
    return null;
  }
}

function extOf(n) {
  const i = n.lastIndexOf(".");
  return i >= 0 ? n.slice(i).toLowerCase() : "";
}
function sanitize(n) {
  // Keep word chars, dots, dashes, and non-ASCII (CJK etc.); collapse runs of _
  const cleaned = String(n || "")
    // 保留：词字符、点、连字符，以及**全部非 ASCII**（\u00a0 起，含 CJK）。
    // 反过来说，ASCII 里除词字符与 . - 之外的一切 —— 空格、引号、反斜杠、
    // 分号、斜杠、控制字符 —— 都会变成下划线。
    //
    // \u00a0 必须写成转义。写成字面量时它在编辑器里就是一个空格，
    // 读的人（包括我）会以为范围是 \u0020-\uffff，从而误判引号能通过。
    .replace(/[^\w.\-\u00a0-\uffff]/g, "_")
    .replace(/_{2,}/g, "_");
  return cleaned || "file";
}
function encRFC5987(s) {
  return encodeURIComponent(s).replace(
    /['()*]/g,
    (ch) => "%" + ch.charCodeAt(0).toString(16).toUpperCase(),
  );
}
function buildContentDisposition(d) {
  return `attachment; filename="${d.replace(/[^\x20-\x7e]/g, "_")}"; filename*=UTF-8''${encRFC5987(d)}`;
}

function parseRange(header, total) {
  if (!header) return null;
  const m = header.match(/^bytes=(\d*)-(\d*)$/);
  if (!m) return null;
  let s, e;
  if (m[1] === "" && m[2] !== "") {
    const sfx = parseInt(m[2], 10);
    if (sfx <= 0 || sfx > total) return null;
    s = total - sfx;
    e = total - 1;
  } else if (m[1] !== "" && m[2] === "") {
    s = parseInt(m[1], 10);
    if (s >= total) return null;
    e = total - 1;
  } else {
    s = parseInt(m[1], 10);
    e = parseInt(m[2], 10);
  }
  if (isNaN(s) || isNaN(e) || s < 0 || e >= total || s > e) return null;
  return [s, e];
}

function firstSeg(p) {
  return p.split("/").find(Boolean) || "0";
}
function pick(h, a) {
  const o = new Headers();
  for (const k of a) {
    const v = h.get(k);
    if (v) o.set(k, v);
  }
  return o;
}
async function drain(r) {
  try {
    await r?.body?.cancel();
  } catch {
    /* ignore */
  }
}

function ok(data) {
  return new Response(JSON.stringify(data), {
    headers: {
      "Content-Type": "application/json;charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
function fail(status, detail) {
  const msg =
    detail ||
    {
      400: "Bad Request",
      401: "Unauthorized",
      403: "Forbidden",
      404: "Not Found",
      405: "Method Not Allowed",
      413: "Payload Too Large",
      416: "Range Not Satisfiable",
      500: "Internal Server Error",
      502: "Bad Gateway",
    }[status] ||
    "Error";
  const headers = {
    "Content-Type": "application/json;charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "X-Content-Type-Options": "nosniff",
  };
  // RFC 6750 §3：Bearer 保护的资源 401 必须给挑战头，并暴露给浏览器脚本。
  if (status === 401) {
    headers["WWW-Authenticate"] = "Bearer";
    headers["Access-Control-Expose-Headers"] = "WWW-Authenticate";
  }
  return new Response(JSON.stringify({ error: msg }), { status, headers });
}

/* ═══════════════════════════════════════════════════════
 *  Named exports (tests only)
 *
 *  wrangler 只使用上面的 default export，这些具名导出不影响运行时行为，
 *  只是让 test/ 能直接测这些纯函数 —— 本仓 1600+ 行此前零测试。
 * ═══════════════════════════════════════════════════════ */
export {
  CORS_HEADERS,
  SAFE_USERIDS,
  ANON_MAX_UPLOAD_BYTES,
  MAX_UPLOAD_BYTES,
  UUID_RE,
  cfg,
  configOk,
  getSafeId,
  negotiateDocsFormat,
  estimateMarkdownTokens,
  inferKind,
  safeDecodeFilename,
  extOf,
  sanitize,
  encRFC5987,
};
