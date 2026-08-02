/*
 * Copyright (C) 2025-2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * 上传大小分档 + SEKAI Pass 鉴权。
 *
 * ── 由来 ────────────────────────────────────────────────────────
 *
 * storage-worker 是匿名文件服务（产品定位）。issue #3 把「无鉴权无限流」
 * 当漏洞写，但匿名是有意的。真正要管的是 **CF 侧成本** 与合规：
 *
 *   - 下载：Workers Caching 已压请求费
 *   - 上传：匿名放开到 Cloudflare 可缓存对象上限 512 MiB；再大要 SEKAI Pass
 *   - 绝对硬顶仍是 ~1GB（MAX_UPLOAD_BYTES，不变，PostObject policy 也用它）
 *
 * 这批测试钉的是分档函数 authorizeUploadSize 的边界，以及四条上传路径
 * 都过它 —— 漏掉任何一条，那条就退回「匿名可传到 1GB」。
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import worker, { ANON_MAX_UPLOAD_BYTES, MAX_UPLOAD_BYTES } from '../worker.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(root, 'worker.js'), 'utf8');

/**
 * 从源码里抠出 authorizeUploadSize，注入 stub 的 fail / authenticate。
 * 不手抄实现，也不真去查 D1。
 */
function loadAuthorize() {
  const m = /async function authorizeUploadSize\([\s\S]*?\n\}/.exec(src);
  assert.ok(m, '找不到 authorizeUploadSize()');
  const factory = new Function(
    'fail',
    'authenticate',
    'ANON_MAX_UPLOAD_BYTES',
    'MAX_UPLOAD_BYTES',
    `${m[0]}\nreturn authorizeUploadSize;`,
  );
  // stub fail 返回一个可辨识的形状；stub authenticate 由每个用例注入
  const calls = { authenticate: 0 };
  let authResult = null;
  const fail = (status, detail) => ({ __fail: true, status, detail });
  const authenticate = async () => {
    calls.authenticate += 1;
    return authResult;
  };
  const fn = factory(fail, authenticate, ANON_MAX_UPLOAD_BYTES, MAX_UPLOAD_BYTES);
  return {
    authorize: (req, env, size, msg) => fn(req, env, size, msg),
    calls,
    setAuthResult: (v) => { authResult = v; },
  };
}

describe('authorizeUploadSize —— 分档边界', () => {
  test('非法 / 负数大小 → 400，且不查 D1', async () => {
    const h = loadAuthorize();
    for (const bad of [NaN, -1, Infinity]) {
      const r = await h.authorize({}, {}, bad);
      assert.equal(r.status, 400, String(bad));
    }
    assert.equal(h.calls.authenticate, 0);
  });

  test('恰好等于匿名档 → 放行，不查 D1', async () => {
    const h = loadAuthorize();
    assert.equal(await h.authorize({}, {}, ANON_MAX_UPLOAD_BYTES), null);
    assert.equal(await h.authorize({}, {}, 0), null);
    assert.equal(h.calls.authenticate, 0, '匿名档不该碰 AUTH_DB');
  });

  test('匿名档 +1 且无 token → 401', async () => {
    const h = loadAuthorize();
    h.setAuthResult(null);
    const r = await h.authorize({}, {}, ANON_MAX_UPLOAD_BYTES + 1);
    assert.equal(r.status, 401);
    assert.equal(h.calls.authenticate, 1, '超匿名档必须查 token');
  });

  test('(ANON, MAX] 且 token 有效 → 放行', async () => {
    const h = loadAuthorize();
    h.setAuthResult({ id: 'u1', username: 'nao' });
    assert.equal(await h.authorize({}, {}, ANON_MAX_UPLOAD_BYTES + 1), null);
    assert.equal(await h.authorize({}, {}, MAX_UPLOAD_BYTES), null);
  });

  test('超过绝对硬顶 → 413，且不查 D1（token 也救不了）', async () => {
    const h = loadAuthorize();
    h.setAuthResult({ id: 'u1' });
    const r = await h.authorize({}, {}, MAX_UPLOAD_BYTES + 1);
    assert.equal(r.status, 413);
    assert.equal(h.calls.authenticate, 0);
  });

  test('自定义非法文案透传（putChunk 用 "Invalid size"）', async () => {
    const h = loadAuthorize();
    const r = await h.authorize({}, {}, NaN, 'Invalid size');
    assert.equal(r.detail, 'Invalid size');
  });
});

describe('四条上传路径都过 authorizeUploadSize', () => {
  /*
   * 源码守卫：漏掉任何一条，那条上传就退回「匿名可传到 1GB」。
   * 只测行为的话，某条漏了也可能因为别的原因照样绿。
   */
  test('putSekaiV2 / put / putSafe / putChunk 均调用', () => {
    for (const fnName of ['putSekaiV2', 'putSafe', 'putChunk']) {
      const re = new RegExp(`async function ${fnName}\\([\\s\\S]*?\\n\\}`, 'm');
      const body = re.exec(src)?.[0] ?? '';
      assert.match(body, /authorizeUploadSize\(/, `${fnName} 未调用 authorizeUploadSize`);
    }
    // legacy put() 名字最短，单独精确匹配避免吃到 putSafe/putChunk
    const putBody = /async function put\(req, c, env\)\{?[\s\S]*?\n\}/.exec(src)
      || /async function put\(req, c, env\) \{[\s\S]*?\n\}/.exec(src);
    assert.ok(putBody, '找不到 legacy put()');
    assert.match(putBody[0], /authorizeUploadSize\(/, 'put 未调用 authorizeUploadSize');
  });

  test('四条 put 都把 env 作为形参接住', () => {
    assert.match(src, /function putSekaiV2\(req, c, ctx, env\)/);
    assert.match(src, /function put\(req, c, env\)/);
    assert.match(src, /function putSafe\(req, c, env\)/);
    assert.match(src, /function putChunk\(req, c, env\)/);
  });
});

describe('PostObject policy 用 Worker body 端点限制', () => {
  test('content-length-range 使用 c.WORKER_UPLOAD_MAX_BYTES', () => {
    const m = /signPolicyLocal\(c, userid\)[\s\S]*?content-length-range["']?,\s*0,\s*c\.([A-Za-z_]+)/.exec(src);
    assert.ok(m, '找不到 content-length-range');
    assert.equal(m[1], 'WORKER_UPLOAD_MAX_BYTES');
  });
});

describe('worker.fetch —— 大文件上传鉴权（返回在触达 OSS 之前）', () => {
  const ENV = {
    OSS_BUCKET: 'b',
    OSS_ENDPOINT: 'oss.example',
    OSS_AKID: 'k',
    OSS_AKS: 's',
    // 无 AUTH_DB —— authenticate 无 token 时直接 null，走 401 分支
  };
  const ctx = { waitUntil: () => {} };

  function putReq(bytes, headers = {}) {
    return new Request('https://s.example/v2/upload', {
      method: 'PUT',
      headers: {
        'X-Filename': 'big.bin',
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(bytes),
        ...headers,
      },
      body: 'x', // body 不被读取；分档只看声明大小
    });
  }

  test('超过绝对硬顶 → 413', async () => {
    const res = await worker.fetch(putReq(MAX_UPLOAD_BYTES + 1), ENV, ctx);
    assert.equal(res.status, 413);
  });

  test('(ANON, MAX] 无 Authorization → 401 + WWW-Authenticate', async () => {
    const res = await worker.fetch(putReq(ANON_MAX_UPLOAD_BYTES + 1), ENV, ctx);
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('WWW-Authenticate'), 'Bearer');
    assert.ok(
      (res.headers.get('Access-Control-Expose-Headers') || '').includes('WWW-Authenticate'),
    );
  });

  test('(ANON, MAX] 带 Bearer 但无 AUTH_DB 绑定 → 仍 401（authenticate 返回 null）', async () => {
    const res = await worker.fetch(
      putReq(ANON_MAX_UPLOAD_BYTES + 1, { Authorization: 'Bearer sometoken' }),
      ENV,
      ctx,
    );
    assert.equal(res.status, 401);
  });
});
