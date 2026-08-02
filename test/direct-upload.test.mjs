import { describe, test } from 'node:test';
import assert from 'node:assert/strict';

import worker from '../worker.js';

const ENV = {
  OSS_BUCKET: 'bucket',
  OSS_ENDPOINT: 'oss.example',
  OSS_AKID: 'access-id',
  OSS_AKS: 'access-secret',
  OSS_PREFIX: 'AttachFiles',
  PUBLIC_UPLOAD_HOST: 'https://upload.example.com/',
};

const LEGACY_JSON_ENV = {
  ...ENV,
  DIRECT_UPLOAD_OBJECT_METADATA: '0',
};

function jsonRequest(path, body, headers = {}) {
  return new Request(`https://storage.example.com${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
}

describe('direct upload init', () => {
  test('returns an exact-key, exact-size OSS PostObject policy', async () => {
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: 'photo.JPG',
        type: 'image/jpeg',
        size: 12345,
        kind: 'image',
        w: 800,
        h: 600,
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    const result = await response.json();

    assert.equal(result.upload.url, 'https://upload.example.com/');
    assert.equal(result.upload.method, 'POST');
    assert.equal(result.upload.fields.success_action_status, '204');
    assert.equal(result.upload.fields.OSSAccessKeyId, 'access-id');
    assert.match(result.upload.fields.key, /^AttachFiles\/sekai\/[0-9a-f-]+$/);
    assert.equal(result.upload.fields['x-oss-meta-sekai-version'], '2');
    assert.equal(result.url, `/images/${result.uuid}`);
    assert.ok(result.complete_token.includes('.'));

    const policy = JSON.parse(
      Buffer.from(result.upload.fields.policy, 'base64').toString('utf8'),
    );
    assert.deepEqual(policy.conditions[0], { key: result.upload.fields.key });
    assert.deepEqual(policy.conditions[1], ['content-length-range', 12345, 12345]);
    assert.deepEqual(policy.conditions[2], { 'Content-Type': 'image/jpeg' });
    assert.deepEqual(policy.conditions[3], {
      'Content-Disposition': result.upload.fields['Content-Disposition'],
    });
  });

  test('requires the public direct-upload host', async () => {
    const { PUBLIC_UPLOAD_HOST, ...missingHost } = ENV;
    void PUBLIC_UPLOAD_HOST;
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', { name: 'a.bin', size: 1 }),
      missingHost,
      {},
    );
    assert.equal(response.status, 501);
  });

  test('uses the existing large-upload authentication tier', async () => {
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: 'large.bin',
        type: 'application/octet-stream',
        size: 512 * 1024 * 1024 + 1,
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 401);
  });

  test('rejects a single signed upload above the 800 MiB gateway limit', async () => {
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: 'too-large.bin',
        type: 'application/octet-stream',
        size: 800 * 1024 * 1024 + 1,
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 413);
  });

  test('can explicitly roll back to the JSON sidecar layout', async () => {
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: 'photo.JPG',
        type: 'image/jpeg',
        size: 12345,
      }),
      LEGACY_JSON_ENV,
      {},
    );
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.match(result.upload.fields.key, /^AttachFiles\/sekai\/[0-9a-f-]+\.jpg$/);
    assert.equal(result.upload.fields['x-oss-meta-sekai-version'], undefined);
  });
});

describe('direct upload complete', () => {
  test('rejects a tampered completion token before contacting OSS', async () => {
    const initResponse = await worker.fetch(
      jsonRequest('/v2/upload/init', { name: 'a.bin', size: 8 }),
      ENV,
      {},
    );
    const init = await initResponse.json();
    const token = `${init.complete_token.slice(0, -1)}x`;

    const response = await worker.fetch(
      jsonRequest('/v2/upload/complete', { token }),
      ENV,
      {},
    );
    assert.equal(response.status, 400);
    assert.match((await response.json()).error, /Invalid or expired/);
  });

  test('writes metadata through waitUntil after returning the response', async () => {
    const initResponse = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: 'async.bin',
        type: 'application/octet-stream',
        size: 8,
      }),
      LEGACY_JSON_ENV,
      {},
    );
    const init = await initResponse.json();

    const originalFetch = globalThis.fetch;
    let releaseMetadata;
    const metadataGate = new Promise((resolve) => { releaseMetadata = resolve; });
    let metadataStarted;
    const metadataStartedPromise = new Promise((resolve) => { metadataStarted = resolve; });
    let backgroundTask;

    globalThis.fetch = async (_url, options = {}) => {
      if (options.method === 'HEAD') {
        return new Response(null, {
          status: 200,
          headers: {
            'Content-Length': '8',
            'Content-Type': 'application/octet-stream',
          },
        });
      }

      metadataStarted();
      if (options.body) await new Response(options.body).arrayBuffer();
      await metadataGate;
      return new Response(null, { status: 204 });
    };

    try {
      const response = await worker.fetch(
        jsonRequest('/v2/upload/complete', { token: init.complete_token }),
        LEGACY_JSON_ENV,
        { waitUntil(promise) { backgroundTask = promise; } },
      );

      assert.equal(response.status, 200);
      assert.ok(backgroundTask instanceof Promise);
      await metadataStartedPromise;
      releaseMetadata();
      await backgroundTask;
    } finally {
      releaseMetadata?.();
      globalThis.fetch = originalFetch;
    }
  });
});

describe('default OSS object metadata layout', () => {
  test('signs an extensionless key and every metadata field exactly', async () => {
    const response = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: '测试图片.PNG',
        type: 'image/png',
        size: 4096,
        kind: 'image',
        w: 320,
        h: 180,
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 200);
    const result = await response.json();
    const fields = result.upload.fields;

    assert.match(fields.key, /^AttachFiles\/sekai\/[0-9a-f-]+$/);
    assert.equal(fields['x-oss-meta-sekai-version'], '2');
    assert.equal(
      Buffer.from(fields['x-oss-meta-sekai-name'], 'base64url').toString('utf8'),
      '测试图片.PNG',
    );
    assert.equal(fields['x-oss-meta-sekai-kind'], 'image');
    assert.equal(fields['x-oss-meta-sekai-width'], '320');
    assert.equal(fields['x-oss-meta-sekai-height'], '180');

    const policy = JSON.parse(Buffer.from(fields.policy, 'base64').toString('utf8'));
    for (const [name, value] of Object.entries(fields)) {
      if (!name.startsWith('x-oss-meta-')) continue;
      assert.ok(
        policy.conditions.some((condition) => condition[name] === value),
        `${name} must be constrained by the signed policy`,
      );
    }
  });

  test('complete verifies object metadata without writing a JSON sidecar', async () => {
    const initResponse = await worker.fetch(
      jsonRequest('/v2/upload/init', {
        name: '测试.txt',
        type: 'text/plain',
        size: 12,
        kind: 'file',
      }),
      ENV,
      {},
    );
    const init = await initResponse.json();
    const fields = init.upload.fields;
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    let backgroundTask;

    globalThis.fetch = async (_url, options = {}) => {
      fetchCalls++;
      assert.equal(options.method, 'HEAD');
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': '12',
          'Content-Type': 'text/plain',
          'x-oss-meta-sekai-version': fields['x-oss-meta-sekai-version'],
          'x-oss-meta-sekai-name': fields['x-oss-meta-sekai-name'],
          'x-oss-meta-sekai-kind': fields['x-oss-meta-sekai-kind'],
          'x-oss-meta-sekai-created': fields['x-oss-meta-sekai-created'],
        },
      });
    };

    try {
      const response = await worker.fetch(
        jsonRequest('/v2/upload/complete', { token: init.complete_token }),
        ENV,
        { waitUntil(promise) { backgroundTask = promise; } },
      );
      assert.equal(response.status, 200);
      assert.equal((await response.json()).name, '测试.txt');
      assert.equal(fetchCalls, 1);
      assert.equal(backgroundTask, undefined);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('serves the existing meta response shape from object headers', async () => {
    const uuid = '01234567-89ab-4def-8123-456789abcdef';
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (_url, options = {}) => {
      assert.equal(options.method, 'HEAD');
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': '2048',
          'Content-Type': 'image/png',
          'x-oss-meta-sekai-version': '2',
          'x-oss-meta-sekai-name': Buffer.from('图片.png').toString('base64url'),
          'x-oss-meta-sekai-kind': 'image',
          'x-oss-meta-sekai-created': '1785600000',
          'x-oss-meta-sekai-width': '640',
          'x-oss-meta-sekai-height': '480',
        },
      });
    };

    try {
      const response = await worker.fetch(
        new Request(`https://storage.example.com/v2/meta/${uuid}`),
        ENV,
        {},
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), {
        uuid,
        kind: 'image',
        type: 'image/png',
        name: '图片.png',
        size_bytes: 2048,
        size: 2,
        ext: '.png',
        created: new Date(1785600000 * 1000).toISOString(),
        w: 640,
        h: 480,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
