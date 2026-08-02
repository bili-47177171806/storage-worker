/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (C) 2025-2026 The 25-ji-code-de Team
 *
 * storage-worker 的单元测试。
 *
 * 本仓 1600+ 行此前零测试。这里覆盖的是纯函数 —— 尤其是几个
 * 直接关系到安全的：路径白名单、文件名解码、sanitize、UUID 校验。
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import worker, {
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
} from '../worker.js';

describe('getSafeId —— 路径白名单', () => {
  test('接受白名单里的首段', () => {
    for (const id of SAFE_USERIDS) {
      assert.equal(getSafeId(`${id}/a/b.png`), id);
      assert.equal(getSafeId(`/${id}/a.png`), id, '前导斜杠应被忽略');
    }
  });

  test('拒绝不在白名单的首段', () => {
    assert.equal(getSafeId('private/secret.png'), null);
    assert.equal(getSafeId('admin/../public/x.png'), null);
  });

  test('只看首段 —— 白名单值出现在后面不算数', () => {
    assert.equal(getSafeId('evil/public/x.png'), null);
  });

  test('空路径返回 null', () => {
    assert.equal(getSafeId(''), null);
    assert.equal(getSafeId('/'), null);
    assert.equal(getSafeId('///'), null);
  });
});

describe('UUID_RE', () => {
  test('接受合法的 v1–v5 UUID', () => {
    assert.ok(UUID_RE.test('a1b2c3d4-5678-40ab-89ef-1234567890ab'));
    assert.ok(UUID_RE.test('A1B2C3D4-5678-40AB-89EF-1234567890AB'), '大小写不敏感');
  });

  test('拒绝畸形值与路径穿越尝试', () => {
    assert.ok(!UUID_RE.test('not-a-uuid'));
    assert.ok(!UUID_RE.test('a1b2c3d4-5678-40ab-89ef-1234567890a'), '少一位');
    assert.ok(!UUID_RE.test('../a1b2c3d4-5678-40ab-89ef-1234567890ab'));
    assert.ok(!UUID_RE.test('a1b2c3d4-5678-90ab-89ef-1234567890ab'), '版本位必须是 1-5');
    assert.ok(!UUID_RE.test('a1b2c3d4-5678-40ab-79ef-1234567890ab'), 'variant 位必须是 8/9/a/b');
  });
});

describe('safeDecodeFilename', () => {
  test('解码百分号编码', () => {
    assert.equal(safeDecodeFilename('hello%20world.png'), 'hello world.png');
    assert.equal(safeDecodeFilename('%E5%9B%BE%E7%89%87.png'), '图片.png');
  });

  test('空值回落到 file', () => {
    assert.equal(safeDecodeFilename(''), 'file');
    assert.equal(safeDecodeFilename(null), 'file');
    assert.equal(safeDecodeFilename('   '), 'file');
  });

  test('畸形编码返回 null 而不抛异常', () => {
    assert.equal(safeDecodeFilename('%'), null);
    assert.equal(safeDecodeFilename('%ZZ'), null);
  });

  test('超长文件名返回 null', () => {
    assert.equal(safeDecodeFilename('a'.repeat(513)), null);
    assert.equal(safeDecodeFilename('a'.repeat(512)).length, 512);
  });
});

describe('sanitize —— 文件名清洗', () => {
  test('保留中日韩等非 ASCII 字符', () => {
    assert.equal(sanitize('图片.png'), '图片.png');
    assert.equal(sanitize('なこ.jpg'), 'なこ.jpg');
  });

  test('替换掉路径分隔符与控制字符', () => {
    assert.ok(!sanitize('a/b.png').includes('/'));
    assert.ok(!sanitize('a\\b.png').includes('\\'));
    // 用转义写，不要写裸控制字符 —— 裸的会让整个文件被 grep/git 当成二进制
    assert.ok(!sanitize('a\u0000b.png').includes('\u0000'));
  });

  test('折叠连续下划线', () => {
    assert.ok(!/_{2,}/.test(sanitize('a///b.png')));
  });

  test('空值回落到 file', () => {
    assert.equal(sanitize(''), 'file');
    assert.equal(sanitize(null), 'file');
  });

  test('清洗后不产生路径穿越', () => {
    const result = sanitize('../../etc/passwd');
    assert.ok(!result.includes('/'));
  });

  test('双引号被清掉 —— 结果会被插进两处 filename="..."', () => {
    /*
     * sanitize 的输出有两个下游，都是把它放进引号里：
     *   buildContentDisposition → `attachment; filename="${d}"`
     *   postToOSSOnce 的 multipart → `name="file"; filename="${displayName}"`
     *
     * 后者是**签过名的 POST 表单**。一个没被清掉的 `"` 就能闭合引号
     * 往里塞参数，而那一段没有别的转义兜底。
     */
    assert.ok(!sanitize('evil".txt').includes('"'));
    const injected = sanitize('a"; filename="b.html');
    assert.ok(!injected.includes('"'), `还有引号：${injected}`);
  });

  test('ASCII 里只留词字符与 . -，其余全部替换', () => {
    /*
     * 把**边界**钉死，因为那个正则极容易读错：字符类里连字符后面跟的是
     * U+00A0（不间断空格），不是普通空格。看成普通空格就会以为范围从
     * U+0020 起，从而以为引号、分号、空格都能通过 —— 实际都会变成下划线。
     *
     * 我自己就照着抄错过一次，据此得出「引号能闭合 filename」的错误结论。
     * 所以这个文件里凡是不可见字符一律写 \u 转义，绝不写字面量 ——
     * 顺带一提，本文件此前还留着两个**裸 NUL 字节**，
     * 让 grep 与 git 把整个文件当成二进制。
     */
    for (const ch of ['a', 'Z', '0', '_', '.', '-']) {
      assert.equal(sanitize(`x${ch}y`), `x${ch}y`, `${ch} 应当保留`);
    }

    const REPLACED = [
      '\u0020', '"', "'", '\\', '/', ';', ':', '?', '*', '<', '>', '|', '&', '#',
    ];
    for (const ch of REPLACED) {
      const out = sanitize(`x${ch}y`);
      assert.equal(out, 'x_y', `${JSON.stringify(ch)} 应当被替换，得到 ${JSON.stringify(out)}`);
    }
  });

  test('非 ASCII 从 U+00A0 起全部保留', () => {
    // 边界两侧各验一个：U+007F（ASCII 末尾）应替换，U+00A0 应保留
    assert.equal(sanitize('x\u007fy'), 'x_y');
    assert.equal(sanitize('x\u00a0y'), 'x\u00a0y');
    assert.equal(sanitize('x\u00e9y'), 'x\u00e9y');
  });
});

describe('extOf', () => {
  test('取小写扩展名', () => {
    assert.equal(extOf('a.PNG'), '.png');
    assert.equal(extOf('archive.tar.gz'), '.gz');
  });

  test('无扩展名返回空串', () => {
    assert.equal(extOf('README'), '');
  });

  test('以点开头的隐藏文件整体算扩展名', () => {
    assert.equal(extOf('.gitignore'), '.gitignore');
  });
});

describe('encRFC5987', () => {
  test('转义 Content-Disposition 里会出问题的字符', () => {
    for (const ch of ["'", '(', ')', '*']) {
      assert.ok(!encRFC5987(`a${ch}b.png`).includes(ch), ch);
    }
  });

  test('非 ASCII 走百分号编码', () => {
    assert.equal(encRFC5987('图片.png'), '%E5%9B%BE%E7%89%87.png');
  });
});

describe('inferKind', () => {
  test('显式 hint 优先于 MIME', () => {
    assert.equal(inferKind('image/png', 'file'), 'file');
    assert.equal(inferKind('application/pdf', 'image'), 'image');
    assert.equal(inferKind('image/png', 'STICKER'), 'sticker', 'hint 大小写不敏感');
  });

  test('无 hint 时按 MIME 推断', () => {
    assert.equal(inferKind('image/jpeg'), 'image');
    assert.equal(inferKind('IMAGE/JPEG'), 'image', 'MIME 大小写不敏感');
    assert.equal(inferKind('application/pdf'), 'file');
  });

  test('无法识别的 hint 被忽略', () => {
    assert.equal(inferKind('image/png', 'nonsense'), 'image');
  });

  test('全空时回落到 file', () => {
    assert.equal(inferKind(), 'file');
    assert.equal(inferKind('', ''), 'file');
  });
});

describe('negotiateDocsFormat', () => {
  const req = (accept) => new Request('https://s.example/', accept ? { headers: { Accept: accept } } : {});
  const url = (qs = '') => new URL(`https://s.example/${qs}`);

  test('query 参数优先于 Accept 头', () => {
    assert.equal(negotiateDocsFormat(req('text/html'), url('?json')), 'json');
    assert.equal(negotiateDocsFormat(req('text/html'), url('?markdown')), 'markdown');
    assert.equal(negotiateDocsFormat(req('text/html'), url('?md')), 'markdown');
    assert.equal(negotiateDocsFormat(req('text/html'), url('?format=json')), 'json');
    assert.equal(negotiateDocsFormat(req('text/html'), url('?format=md')), 'markdown');
    assert.equal(negotiateDocsFormat(req('text/html'), url('?format=markdown')), 'markdown');
  });

  test('按 Accept 头协商，具体类型优先于 */*', () => {
    assert.equal(negotiateDocsFormat(req('text/markdown'), url()), 'markdown');
    assert.equal(negotiateDocsFormat(req('text/x-markdown'), url()), 'markdown');
    assert.equal(negotiateDocsFormat(req('application/json'), url()), 'json');
    assert.equal(negotiateDocsFormat(req('application/vnd.api+json'), url()), 'json');
    // agent 常发这种组合，应命中最具体的
    assert.equal(negotiateDocsFormat(req('text/markdown, application/json, */*'), url()), 'markdown');
    assert.equal(negotiateDocsFormat(req('text/markdown;q=0.5, application/json'), url()), 'json');
  });

  test('浏览器回落到 html，无 Accept 回落到纯文本', () => {
    assert.equal(negotiateDocsFormat(req('text/html,*/*'), url()), 'html');
    assert.equal(negotiateDocsFormat(req('*/*'), url()), 'html');
    assert.equal(negotiateDocsFormat(req('text/plain'), url()), 'text');
    assert.equal(negotiateDocsFormat(req(), url()), 'text');
  });
});

describe('API index representations', () => {
  const env = {
    OSS_BUCKET: 'bucket',
    OSS_ENDPOINT: 'oss.example',
    OSS_AKID: 'access-id',
    OSS_AKS: 'access-secret',
  };

  async function fetchIndex(path = '/', headers = {}) {
    return worker.fetch(
      new Request(`https://s.example${path}`, { headers }),
      env,
      { waitUntil: () => {} },
    );
  }

  test('returns plain text without Accept', async () => {
    const response = await fetchIndex();
    assert.match(response.headers.get('content-type'), /^text\/plain; charset=utf-8$/);
    assert.match(await response.text(), /^Nightcord Storage API/);
  });

  test('supports bare JSON and Markdown query aliases', async () => {
    const json = await fetchIndex('?json');
    assert.match(json.headers.get('content-type'), /^application\/json;charset=utf-8$/);
    assert.equal((await json.json()).service, 'Nightcord Storage');

    const markdown = await fetchIndex('?markdown');
    assert.match(markdown.headers.get('content-type'), /^text\/markdown; charset=utf-8$/);
    assert.match(await markdown.text(), /^# Nightcord Storage/);
  });
});

describe('estimateMarkdownTokens', () => {
  test('按空白切分计数', () => {
    assert.equal(estimateMarkdownTokens('a b c'), 3);
    assert.equal(estimateMarkdownTokens('  a \n\n b  '), 2, '折叠连续空白');
  });

  test('空串为 0', () => {
    assert.equal(estimateMarkdownTokens(''), 0);
    assert.equal(estimateMarkdownTokens('   '), 0);
  });
});

describe('cfg / configOk', () => {
  const complete = {
    OSS_BUCKET: 'b',
    OSS_ENDPOINT: 'oss-cn-hangzhou.aliyuncs.com',
    OSS_AKID: 'id',
    OSS_AKS: 'secret',
  };

  test('由 bucket + endpoint 拼出 OSS_HOST', () => {
    assert.equal(cfg(complete).OSS_HOST, 'https://b.oss-cn-hangzhou.aliyuncs.com');
  });

  test('OSS_PREFIX 缺省为 AttachFiles', () => {
    assert.equal(cfg(complete).PREFIX, 'AttachFiles');
    assert.equal(cfg({ ...complete, OSS_PREFIX: '  ' }).PREFIX, 'AttachFiles');
  });

  test('UPLOAD_HOST 缺省回落到 OSS_HOST，并去掉尾部斜杠', () => {
    assert.equal(cfg(complete).UPLOAD_HOST, 'https://b.oss-cn-hangzhou.aliyuncs.com');
    assert.equal(cfg({ ...complete, OSS_UPLOAD_HOST: 'https://cdn.x/' }).UPLOAD_HOST, 'https://cdn.x');
  });

  test('有本地 SK 时配置完整', () => {
    assert.equal(configOk(cfg(complete)), true);
  });

  test('SK 与远端签名后端都没有时配置不完整', () => {
    const { OSS_AKS, ...noSecret } = complete;
    void OSS_AKS;
    assert.equal(configOk(cfg(noSecret)), false);
    // 远端签名后端可作为 fallback
    assert.equal(configOk(cfg({ ...noSecret, SIGN_BACKEND: 'https://sign.x' })), true);
  });

  test('缺 bucket / endpoint / AKID 一律不完整', () => {
    for (const key of ['OSS_BUCKET', 'OSS_ENDPOINT', 'OSS_AKID']) {
      const partial = { ...complete, [key]: '' };
      assert.equal(configOk(cfg(partial)), false, key);
    }
  });

  test('env 为空时不抛异常', () => {
    assert.doesNotThrow(() => cfg(undefined));
    assert.equal(configOk(cfg(undefined)), false);
  });
});

describe('常量', () => {
  test('MAX_UPLOAD_BYTES 是鉴权后的绝对硬顶（约 1GB，不变）', () => {
    assert.equal(MAX_UPLOAD_BYTES, 1048576000);
  });

  test('ANON_MAX_UPLOAD_BYTES 对齐 Cloudflare 512 MiB 缓存上限', () => {
    assert.equal(ANON_MAX_UPLOAD_BYTES, 512 * 1024 * 1024);
    assert.equal(ANON_MAX_UPLOAD_BYTES, 536870912);
  });

  test('匿名档严格小于绝对硬顶 —— 否则「需 token」的档位不存在', () => {
    assert.ok(ANON_MAX_UPLOAD_BYTES < MAX_UPLOAD_BYTES);
  });

  test('CORS 允许上传所需的自定义头（含 Authorization）', () => {
    const allowed = CORS_HEADERS['Access-Control-Allow-Headers'];
    for (const h of ['Authorization', 'Content-Type']) {
      assert.ok(allowed.includes(h), h);
    }
    for (const retired of ['X-Filename', 'X-Chunk-Index', 'X-Sekai-Kind']) {
      assert.ok(!allowed.includes(retired), retired);
    }
  });

  test('CORS 暴露 WWW-Authenticate 给浏览器脚本', () => {
    assert.ok(
      (CORS_HEADERS['Access-Control-Expose-Headers'] || '').includes('WWW-Authenticate'),
    );
  });
});

describe('worker.fetch —— OPTIONS 预检', () => {
  test('返回 204 与 CORS 头', async () => {
    const response = await worker.fetch(
      new Request('https://s.example/anything', { method: 'OPTIONS' }),
      {},
      { waitUntil: () => {} },
    );
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), '*');
  });
});
