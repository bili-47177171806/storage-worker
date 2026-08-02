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

const STS_ENV = {
  ...ENV,
  MULTIPART_STS_ENABLED: '1',
  STS_AKID: 'sts-access-id',
  STS_AKS: 'sts-access-secret',
  STS_ENDPOINT: 'sts.example.com',
  STS_ROLE_ARN: 'acs:ram::1234567890123456:role/oss-upload',
};

const STS_CREDENTIALS = {
  AccessKeyId: 'temporary-access-id',
  AccessKeySecret: 'temporary-access-secret',
  SecurityToken: 'temporary-security-token',
  Expiration: '2026-08-02T06:00:00Z',
};

const UPLOAD_ID = 'uploadid_123456789';
const MIB = 1024 * 1024;
const EDGE_MAX_PART_BYTES = 800 * MIB;
const MULTIPART_MAX_FILE_BYTES = EDGE_MAX_PART_BYTES * 10000;

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
  let stsRequest;
  globalThis.fetch = async (url, options = {}) => {
    if (String(url).startsWith('https://sts.example.com/')) {
      stsRequest = { url: String(url), options };
      return Response.json({ Credentials: STS_CREDENTIALS });
    }
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
    return { response, result: await response.json(), initRequest, stsRequest };
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

  test('issues per-object STS credentials for clients that sign multipart operations', async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, options = {}) => {
      calls.push({ url: String(url), options });
      if (String(url).startsWith('https://sts.example.com/')) {
        return Response.json({ Credentials: STS_CREDENTIALS });
      }
      return new Response(
        `<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>${UPLOAD_ID}</UploadId></InitiateMultipartUploadResult>`,
        { status: 200, headers: { 'Content-Type': 'application/xml' } },
      );
    };
    try {
      const response = await worker.fetch(
        request('/v2/upload/multipart/init', {
          name: 'sts.bin',
          type: 'application/octet-stream',
          size: 10 * MIB + 1,
        }),
        STS_ENV,
        {},
      );
      assert.equal(response.status, 200);
      const result = await response.json();
      assert.equal(result.recommended_concurrency, 2);
      assert.deepEqual(result.multipart_sts, {
        version: 'oss-v1-presigned-url',
        endpoint: 'https://upload.example.com',
        bucket: 'bucket',
        object_key: `AttachFiles/sekai/${result.uuid}`,
        upload_id: UPLOAD_ID,
        access_key_id: STS_CREDENTIALS.AccessKeyId,
        access_key_secret: STS_CREDENTIALS.AccessKeySecret,
        security_token: STS_CREDENTIALS.SecurityToken,
        expires_at: STS_CREDENTIALS.Expiration,
      });
      assert.equal(calls.length, 2);
      const stsUrl = new URL(calls[0].url);
      assert.equal(stsUrl.searchParams.get('Action'), 'AssumeRole');
      assert.equal(stsUrl.searchParams.get('RoleArn'), STS_ENV.STS_ROLE_ARN);
      assert.ok(stsUrl.searchParams.get('Signature'));
      const policy = JSON.parse(stsUrl.searchParams.get('Policy'));
      assert.deepEqual(policy.Statement[0].Action, [
        'oss:PutObject',
        'oss:AbortMultipartUpload',
        'oss:ListParts',
      ]);
      assert.deepEqual(policy.Statement[0].Resource, [
        `acs:oss:*:1234567890123456:bucket/AttachFiles/sekai/${result.uuid}`,
      ]);
      assert.equal(calls[1].options.method, 'POST');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('accepts the 3.12 GiB live-test file with 320 default-size parts', async () => {
    const fileSize = 3351970975;
    const { response, result } = await createMultipartUpload({
      name: 'live-replay.mp4',
      type: 'video/mp4',
      size: fileSize,
    });

    assert.equal(response.status, 200);
    assert.equal(result.part_size, 10 * MIB);
    assert.equal(result.part_count, Math.ceil(fileSize / (10 * MIB)));
    assert.equal(result.part_count, 320);
  });

  test('grows part size for objects above the 10 MiB x 10,000 boundary', async () => {
    const fileSize = 150 * 1024 * MIB;
    const { response, result } = await createMultipartUpload({ size: fileSize });

    assert.equal(response.status, 200);
    assert.equal(result.part_size, 16 * MIB);
    assert.ok(result.part_count <= 10000);
  });

  test('rejects objects above the gateway-part x OSS-part-count ceiling', async () => {
    const { response, initRequest } = await createMultipartUpload({
      size: MULTIPART_MAX_FILE_BYTES + 1,
    });

    assert.equal(response.status, 413);
    assert.equal(initRequest, undefined);
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

  test('refreshes STS credentials from a valid multipart token only', async () => {
    const { result } = await createMultipartUpload({}, STS_ENV);
    const originalFetch = globalThis.fetch;
    let stsRequest;
    globalThis.fetch = async (url) => {
      stsRequest = String(url);
      return Response.json({ Credentials: STS_CREDENTIALS });
    };
    try {
      const response = await worker.fetch(
        request('/v2/upload/multipart/credentials', { token: result.multipart_token }),
        STS_ENV,
        {},
      );
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.multipart_sts.object_key, `AttachFiles/sekai/${result.uuid}`);
      assert.equal(body.multipart_sts.access_key_secret, STS_CREDENTIALS.AccessKeySecret);
      assert.match(stsRequest, /^https:\/\/sts\.example\.com\//);

      globalThis.fetch = async () => { throw new Error('must not contact STS'); };
      const tampered = await worker.fetch(
        request('/v2/upload/multipart/credentials', {
          token: `${result.multipart_token.slice(0, -1)}x`,
        }),
        STS_ENV,
        {},
      );
      assert.equal(tampered.status, 400);
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

  test('verifies a multipart object completed directly with STS without repeating Complete', async () => {
    const { result, initRequest } = await createMultipartUpload();
    const headers = initRequest.options.headers;
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (_url, options = {}) => {
      calls++;
      assert.equal(options.method, 'HEAD');
      return new Response(null, {
        status: 200,
        headers: {
          'Content-Length': String(10 * MIB + 128),
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
          completed: true,
        }),
        ENV,
        {},
      );
      assert.equal(response.status, 200);
      assert.equal((await response.json()).uuid, result.uuid);
      assert.equal(calls, 1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('aborts the OSS upload using the signed multipart token', async () => {
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
