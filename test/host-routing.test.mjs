// SPDX-License-Identifier: AGPL-3.0-only

import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker.js';

const ENV = {
  OSS_BUCKET: 'bucket',
  OSS_ENDPOINT: 'oss.example.com',
  OSS_AKID: 'access-id',
  OSS_AKS: 'access-secret',
  PUBLIC_STORAGE_HOST: 'https://storage.example.com',
  PUBLIC_UPLOAD_HOST: 'https://upload.example.com',
  PUBLIC_R2_HOST: 'https://r2.example.com',
};

describe('hostname role separation', () => {
  test('storage serves API but rejects object downloads and raw uploads', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => { throw new Error('OSS must not be contacted'); };
    try {
      const docs = await worker.fetch(
        new Request('https://storage.example.com/?json'),
        ENV,
        {},
      );
      assert.equal(docs.status, 200);

      const download = await worker.fetch(
        new Request('https://storage.example.com/public/file.bin'),
        ENV,
        {},
      );
      assert.equal(download.status, 410);

      const upload = await worker.fetch(
        new Request('https://storage.example.com/', { method: 'PUT', body: 'bytes' }),
        ENV,
        {},
      );
      assert.equal(upload.status, 410);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('upload proxies only signed upload traffic to the regional OSS origin', async () => {
    const originalFetch = globalThis.fetch;
    let proxied;
    globalThis.fetch = async (url, options = {}) => {
      proxied = { url: String(url), method: options.method };
      return new Response(null, { status: 204, headers: { ETag: 'etag' } });
    };
    try {
      const response = await worker.fetch(
        new Request('https://upload.example.com/', {
          method: 'POST',
          headers: { 'Content-Type': 'multipart/form-data; boundary=test' },
          body: '--test--',
        }),
        ENV,
        {},
      );
      assert.equal(response.status, 204);
      assert.deepEqual(proxied, {
        url: 'https://bucket.oss.example.com/',
        method: 'POST',
      });

      const api = await worker.fetch(
        new Request('https://upload.example.com/v2/upload/init', {
          method: 'POST',
          body: '{}',
        }),
        ENV,
        {},
      );
      assert.equal(api.status, 405);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('r2 serves downloads but rejects uploads', async () => {
    const uuid = '01234567-89ab-4def-8123-456789abcdef';
    const originalFetch = globalThis.fetch;
    let fetched;
    globalThis.fetch = async (url, options = {}) => {
      fetched = { url: String(url), method: options.method };
      return new Response('image', {
        headers: { 'Content-Type': 'image/png', 'Content-Length': '5' },
      });
    };
    try {
      const response = await worker.fetch(
        new Request(`https://r2.example.com/images/${uuid}`),
        ENV,
        {},
      );
      assert.equal(response.status, 200);
      assert.equal(await response.text(), 'image');
      assert.deepEqual(fetched, {
        url: `https://bucket.oss.example.com/AttachFiles/sekai/${uuid}`,
        method: 'GET',
      });

      const upload = await worker.fetch(
        new Request('https://r2.example.com/file.bin', { method: 'PUT', body: 'bytes' }),
        ENV,
        {},
      );
      assert.equal(upload.status, 405);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('gallery API returns an exact-key form targeting upload host', async () => {
    const response = await worker.fetch(
      new Request('https://storage.example.com/v2/upload/gallery/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ size: 128 }),
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.upload.url, 'https://upload.example.com/');
    assert.equal(result.upload.fields.key, 'AttachFiles/public/gallery/manifest.json');
    assert.equal(result.upload.fields['Content-Type'], 'application/json');
  });
});
