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
  MULTIPART_REQUIRE_AUTH: '0',
};

const UPLOAD_ID = 'uploadid_123456789';

function request(path, body, extraHeaders = {}) {
  return new Request(`https://storage.example.com${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });
}

async function createMultipartUpload(input = {}, env = ENV, headers = {}) {
  const originalFetch = globalThis.fetch;
  let initRequest;
  globalThis.fetch = async (url, options = {}) => {
    initRequest = { url: String(url), options };
    return new Response(
      `<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>${UPLOAD_ID}</UploadId></InitiateMultipartUploadResult>`,
      { status: 200, headers: { 'Content-Type': 'application/xml' } },
    );
  };
  try {
    const response = await worker.fetch(
      request('/v2/upload/multipart/init', {
        name: 'multipart.bin',
        type: 'application/octet-stream',
        size: 10 * 1024 * 1024 + 128,
        ...input,
      }, headers),
      env,
      {},
    );
    return { response, result: await response.json(), initRequest };
  } finally {
    globalThis.fetch = originalFetch;
  }
}

describe('multipart direct upload', () => {
  test('requires SEKAI Pass by default', async () => {
    const env = { ...ENV, MULTIPART_REQUIRE_AUTH: '1' };
    const { response, initRequest } = await createMultipartUpload({}, env);
    assert.equal(response.status, 401);
    assert.equal(initRequest, undefined);
  });

  test('initializes an extensionless object with signed object metadata', async () => {
    const { response, result, initRequest } = await createMultipartUpload({
      name: 'photo.png',
      type: 'image/png',
      kind: 'image',
      w: 320,
      h: 180,
    });

    assert.equal(response.status, 200);
    assert.match(result.uuid, /^[0-9a-f-]+$/);
    assert.equal(result.part_size, 10 * 1024 * 1024);
    assert.equal(result.part_count, 2);
    assert.ok(result.multipart_token.includes('.'));
    assert.match(initRequest.url, new RegExp(`/AttachFiles/sekai/${result.uuid}\\?uploads$`));
    assert.equal(initRequest.options.method, 'POST');
    assert.equal(initRequest.options.headers.get('x-oss-meta-sekai-version'), '2');
    assert.equal(initRequest.options.headers.get('x-oss-meta-sekai-kind'), 'image');
    assert.equal(initRequest.options.headers.get('x-oss-meta-sekai-width'), '320');
    assert.equal(initRequest.options.headers.get('x-oss-forbid-overwrite'), 'true');
    assert.match(initRequest.options.headers.get('Authorization'), /^OSS access-id:/);
  });

  test('issues short-lived PUT URLs only for declared multipart parts', async () => {
    const { result } = await createMultipartUpload();
    const response = await worker.fetch(
      request('/v2/upload/multipart/parts', {
        token: result.multipart_token,
        part_numbers: [1, 2],
      }),
      ENV,
      {},
    );
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.parts.length, 2);
    assert.equal(body.parts[0].size, 10 * 1024 * 1024);
    assert.equal(body.parts[1].size, 128);
    assert.equal(body.parts[0].upload.method, 'PUT');

    const url = new URL(body.parts[0].upload.url);
    assert.equal(url.origin, 'https://upload.example.com');
    assert.match(url.pathname, /^\/AttachFiles\/sekai\/[0-9a-f-]+$/);
    assert.equal(url.searchParams.get('partNumber'), '1');
    assert.equal(url.searchParams.get('uploadId'), UPLOAD_ID);
    assert.equal(url.searchParams.get('OSSAccessKeyId'), 'access-id');
    assert.ok(url.searchParams.get('Expires'));
    assert.ok(url.searchParams.get('Signature'));
    assert.equal(body.parts[0].upload.url.includes('bucket'), false);
  });

  test('rejects tampered tokens and invalid part numbers without signing URLs', async () => {
    const { result } = await createMultipartUpload();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => { throw new Error('must not contact OSS'); };
    try {
      const tampered = await worker.fetch(
        request('/v2/upload/multipart/parts', {
          token: `${result.multipart_token.slice(0, -1)}x`,
          part_numbers: [1],
        }),
        ENV,
        {},
      );
      assert.equal(tampered.status, 400);

      const outOfRange = await worker.fetch(
        request('/v2/upload/multipart/parts', {
          token: result.multipart_token,
          part_numbers: [3],
        }),
        ENV,
        {},
      );
      assert.equal(outOfRange.status, 400);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('sorts ETags, completes on OSS, and verifies the finished object', async () => {
    const { result, initRequest } = await createMultipartUpload();
    const headers = initRequest.options.headers;
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, options = {}) => {
      calls.push({ url: String(url), options });
      if (options.method === 'POST') {
        return new Response('<CompleteMultipartUploadResult/>', { status: 200 });
      }
      assert.equal(options.method, 'HEAD');
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': String(10 * 1024 * 1024 + 128),
          'Content-Type': 'application/octet-stream',
          'x-oss-meta-sekai-version': headers.get('x-oss-meta-sekai-version'),
          'x-oss-meta-sekai-name': headers.get('x-oss-meta-sekai-name'),
          'x-oss-meta-sekai-kind': headers.get('x-oss-meta-sekai-kind'),
          'x-oss-meta-sekai-created': headers.get('x-oss-meta-sekai-created'),
        },
      });
    };
    try {
      const response = await worker.fetch(
        request('/v2/upload/multipart/complete', {
          token: result.multipart_token,
          parts: [
            { part_number: 2, etag: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' },
            { part_number: 1, etag: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
          ],
        }),
        ENV,
        {},
      );
      assert.equal(response.status, 200);
      assert.equal((await response.json()).uuid, result.uuid);
      assert.equal(calls.length, 2);
      assert.equal(calls[0].options.method, 'POST');
      assert.match(calls[0].url, new RegExp(`uploadId=${UPLOAD_ID}$`));
      assert.match(calls[0].options.body, /<PartNumber>1<\/PartNumber><ETag>"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"<\/ETag>/);
      assert.match(calls[0].options.body, /<PartNumber>2<\/PartNumber><ETag>"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"<\/ETag>/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('aborts the OSS upload without exposing its upload ID to callers', async () => {
    const { result } = await createMultipartUpload();
    const originalFetch = globalThis.fetch;
    let abortRequest;
    globalThis.fetch = async (url, options = {}) => {
      abortRequest = { url: String(url), options };
      return new Response(null, { status: 204 });
    };
    try {
      const response = await worker.fetch(
        request('/v2/upload/multipart/abort', { token: result.multipart_token }),
        ENV,
        {},
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { aborted: true });
      assert.equal(abortRequest.options.method, 'DELETE');
      assert.match(abortRequest.url, new RegExp(`uploadId=${UPLOAD_ID}$`));
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
