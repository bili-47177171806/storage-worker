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
    assert.match(result.upload.fields.key, /^AttachFiles\/sekai\/[0-9a-f-]+\.jpg$/);
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
      ENV,
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
        ENV,
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
