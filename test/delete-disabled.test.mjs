/*
 * Copyright 2026 The 25-ji-code-de Team
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * 删除默认关闭 —— 而且是**有意**关的，不是碰巧。
 *
 * ── 由来 ────────────────────────────────────────────────────────
 *
 * 本 Worker 没有任何鉴权（issue #3）。删除端点今天打不通，是因为三个
 * delete 函数都要求 `SIGN_BACKEND`，而当前部署优先本地签名（`OSS_AKS`），
 * `SIGN_BACKEND` 多半没配 —— 于是全部 500。
 *
 * **那是意外，不是设计。** 一旦有人为了别的目的配上 `SIGN_BACKEND`，
 * 删除立刻变成无鉴权的：任何人可以删任何对象，没有任何提示。
 *
 * 这批测试钉的是：删除的开关是 `DELETE_ENABLED`，与 `SIGN_BACKEND` 无关。
 * 光配 `SIGN_BACKEND` 不该把删除打开。
 *
 * ── 为什么改这个不算破坏兼容 ────────────────────────────────────
 *
 * 当前没有任何客户端依赖删除：nightcord 的 `file-upload-service.js` 里有个
 * `delete()` 方法，但**全仓没有调用点**，而且它现在必然拿到 500。
 * 这次改动只是把 500 换成一个说得清楚的 403。
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = readFileSync(join(root, 'worker.js'), 'utf8');

/** 从源码里抠出 cfg()，用真实实现算配置 —— 不手抄。 */
function loadCfg() {
  const m = /function cfg\(env\) \{[\s\S]*?\n\}/.exec(src);
  assert.ok(m, '找不到 cfg()');
  // cfg 里用到的常量
  const chunk = /const CHUNK_SIZE = [^;]+;/.exec(src)?.[0] ?? 'const CHUNK_SIZE = 0;';
  return new Function(`${chunk}\n${m[0]}\nreturn cfg;`)();
}

function loadDeleteAllowed() {
  const m = /function deleteAllowed\(c\) \{[\s\S]*?\n\}/.exec(src);
  assert.ok(m, '找不到 deleteAllowed()');
  return new Function(`${m[0]}\nreturn deleteAllowed;`)();
}

const cfg = loadCfg();
const deleteAllowed = loadDeleteAllowed();

const BASE_ENV = {
  OSS_BUCKET: 'b',
  OSS_ENDPOINT: 'oss.example',
  OSS_AKID: 'k',
  OSS_AKS: 's',
};

describe('删除的开关', () => {
  test('默认关闭', () => {
    assert.equal(deleteAllowed(cfg(BASE_ENV)), false);
  });

  test('只配 SIGN_BACKEND 不会把删除打开', () => {
    /*
     * 这是整批测试的核心。改动之前，删除的准入条件**就是**有没有
     * SIGN_BACKEND —— 于是为了别的目的配上它，删除就顺带开了。
     */
    const c = cfg({ ...BASE_ENV, SIGN_BACKEND: 'https://sign.example' });
    assert.equal(c.BACKEND, 'https://sign.example', '前置条件：BACKEND 确实配上了');
    assert.equal(deleteAllowed(c), false, '配了 SIGN_BACKEND 就把删除打开了');
  });

  test('DELETE_ENABLED=1 才打开', () => {
    assert.equal(deleteAllowed(cfg({ ...BASE_ENV, DELETE_ENABLED: '1' })), true);
  });

  test('其他真值写法不算 —— 必须正好是 "1"', () => {
    // 「差不多是打开」不该算打开：这是个安全开关，模糊匹配会让人误以为关着
    for (const v of ['true', 'yes', 'on', '0', '', ' ', 'TRUE', 2]) {
      assert.equal(
        deleteAllowed(cfg({ ...BASE_ENV, DELETE_ENABLED: v })),
        false,
        `DELETE_ENABLED=${JSON.stringify(v)} 被当成了打开`,
      );
    }
  });

  test('前后空格不影响', () => {
    assert.equal(deleteAllowed(cfg({ ...BASE_ENV, DELETE_ENABLED: ' 1 ' })), true);
  });
});

describe('每条删除路径都过这个开关', () => {
  /*
   * 四个入口：delSafe / del / delChunked，以及 delChunked 里逐块删的那段。
   * 漏掉任何一条，那条路径就仍然只受 SIGN_BACKEND 约束。
   */
  test('deleteAllowed 的检查数与 SIGN_BACKEND 的检查数一致', () => {
    const guards = [...src.matchAll(/if \(!deleteAllowed\(c\)\) \{/g)].length;
    const backendChecks = [...src.matchAll(/if \(!c\.BACKEND\) return fail\(500, "SIGN_BACKEND required for delete"\);/g)].length;
    assert.ok(backendChecks >= 3, `只找到 ${backendChecks} 处 SIGN_BACKEND 检查，源码结构变了`);
    assert.equal(
      guards,
      backendChecks,
      `${backendChecks} 条删除路径，但只有 ${guards} 条过了 deleteAllowed`,
    );
  });

  test('开关排在 SIGN_BACKEND 检查之前', () => {
    /*
     * 顺序要紧：反过来的话，没配 SIGN_BACKEND 时先返回 500，
     * 调用方看到的仍然是「服务坏了」而不是「这个功能是关的」。
     */
    for (const m of src.matchAll(/if \(!c\.BACKEND\) return fail\(500, "SIGN_BACKEND required for delete"\);/g)) {
      const before = src.slice(Math.max(0, m.index - 400), m.index);
      assert.match(
        before,
        /if \(!deleteAllowed\(c\)\) \{/,
        '这处 SIGN_BACKEND 检查之前没有 deleteAllowed 开关',
      );
    }
  });

  test('拒绝时给的是 403 与可操作的说明，不是 500', () => {
    const m = /if \(!deleteAllowed\(c\)\) \{\s*return fail\(403, "([^"]+)"\);/.exec(src);
    assert.ok(m, '找不到拒绝分支');
    assert.match(m[1], /DELETE_ENABLED=1/, '没告诉人怎么打开');
    assert.match(m[1], /no authentication/i, '没说清打开之前要先解决鉴权');
  });
});
