// http-safe.mjs 的 SSRF / 重定向 / 限额测试。
//
// 这些测试全部离线：DNS 与传输层都是注入的。要证明的事只有一件 —— 无论对方返回什么
// 花样（私网 A 记录、302 跳内网、超大响应、明文 http），这里都不会把字节读回来。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createSafeHttp,
  assertAllowedUrl,
  isPublicIp,
  isBlockedHostname,
  parseIpv6,
  SafeHttpError,
} from '../scripts/lib/http-safe.mjs';

function httpWith({ lookup, request, timeoutMs = 1000 }) {
  return createSafeHttp({
    lookupImpl: lookup || (async (host) => [{ address: '93.184.216.34', family: 4 }]),
    requestImpl: request || (async () => ({ status: 200, headers: {}, body: Buffer.from('ok') })),
    timeoutMs,
  });
}

// ── 地址分类 ──────────────────────────────────────────────────────────────

test('公网地址放行，私网/保留/文档段拒绝', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) {
    assert.equal(isPublicIp(ip), true, `${ip} 应当放行`);
  }
  for (const ip of [
    '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '127.0.0.1', '0.0.0.0',
    '169.254.169.254', '100.64.0.1', '192.0.2.1', '198.51.100.1', '203.0.113.1',
    '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '2001:db8::1',
    '64:ff9b::1.2.3.4', '2002:c0a8:0101::1', '::ffff:127.0.0.1', '2001::1',
  ]) {
    assert.equal(isPublicIp(ip), false, `${ip} 应当拒绝`);
  }
});

test('IPv6 的各种写法都能识别（压缩、展开、大小写、内嵌 IPv4）', () => {
  assert.deepEqual(parseIpv6('::1'), parseIpv6('0:0:0:0:0:0:0:1'));
  assert.deepEqual(parseIpv6('FE80::1'), parseIpv6('fe80::1'));
  assert.deepEqual(parseIpv6('::ffff:192.168.0.1'), parseIpv6('::ffff:c0a8:1'));
  assert.equal(parseIpv6('fe80::1%eth0') === null, false);
  assert.equal(isPublicIp('fe80::1%eth0'), false);
  assert.equal(parseIpv6('不是地址'), null);
});

test('主机名判据：IP 字面量、localhost 与内网后缀一律拒绝', () => {
  for (const host of ['127.0.0.1', '169.254.169.254', '[::1]', 'localhost', 'a.localhost', 'box.local', 'svc.internal', 'x.home.arpa']) {
    assert.equal(isBlockedHostname(host), true, `${host} 应当拒绝`);
  }
  for (const host of ['github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com']) {
    assert.equal(isBlockedHostname(host), false, `${host} 应当放行`);
  }
});

test('URL 形状：只允许 https、不许凭据', () => {
  assert.equal(assertAllowedUrl('https://github.com/a/b').hostname, 'github.com');
  for (const url of ['http://github.com/a/b', 'https://user:pass@github.com/a/b', 'https://169.254.169.254/x', 'ftp://github.com/a']) {
    assert.throws(() => assertAllowedUrl(url), (err) => err instanceof SafeHttpError, `${url} 应当被拒`);
  }
});

// ── DNS 校验 ──────────────────────────────────────────────────────────────

test('DNS 混进一个私网地址也拒绝（不只看第一个）', async () => {
  const http = httpWith({
    lookup: async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.7', family: 4 }],
  });
  await assert.rejects(
    http.getText('https://evil.tld/x'),
    (err) => err.code === 'blocked-address',
  );
});

test('DNS 解析失败是 dns-failed，不是放行', async () => {
  const http = httpWith({ lookup: async () => { throw new Error('ENOTFOUND'); } });
  await assert.rejects(http.getJson('https://nope.tld/x'), (err) => err.code === 'dns-failed');
});

test('连接时 pin 住已校验地址：lookup 收到的是公网列表', async () => {
  let captured = null;
  const http = httpWith({
    lookup: async () => [{ address: '93.184.216.34', family: 4 }, { address: '2606:4700::1', family: 6 }],
    request: async (opts) => {
      captured = opts;
      return { status: 200, headers: {}, body: Buffer.from('{}') };
    },
  });
  await http.getJson('https://github.com/a/b');
  assert.ok(captured && typeof captured.lookup === 'function');
  const viaAll = await new Promise((resolve, reject) => captured.lookup('github.com', { all: true }, (e, a) => (e ? reject(e) : resolve(a))));
  assert.deepEqual(viaAll.map((a) => a.address), ['93.184.216.34', '2606:4700::1']);
  const only4 = await new Promise((resolve, reject) => captured.lookup('github.com', { family: 4 }, (e, a) => (e ? reject(e) : resolve(a))));
  assert.equal(only4, '93.184.216.34');
});

// ── 重定向 ────────────────────────────────────────────────────────────────

test('重定向到内网被拒（逐跳重新校验）', async () => {
  const http = httpWith({
    request: async () => ({ status: 302, headers: { location: 'https://127.0.0.1/secret' }, body: Buffer.alloc(0) }),
  });
  await assert.rejects(http.getText('https://github.com/a'), (err) => err.code === 'blocked-host');
});

test('重定向到明文 http 被拒', async () => {
  const http = httpWith({
    request: async () => ({ status: 301, headers: { location: 'http://github.com/x' }, body: Buffer.alloc(0) }),
  });
  await assert.rejects(http.getText('https://github.com/a'), (err) => err.code === 'bad-protocol');
});

test('重定向最多 3 跳', async () => {
  let n = 0;
  const http = httpWith({
    request: async () => {
      n += 1;
      return { status: 302, headers: { location: `https://github.com/hop${n}` }, body: Buffer.alloc(0) };
    },
  });
  await assert.rejects(http.getText('https://github.com/start'), (err) => err.code === 'too-many-redirects');
});

test('跟随重定向后返回最终地址', async () => {
  const calls = [];
  const http = httpWith({
    request: async (opts) => {
      calls.push(opts.url);
      if (opts.url === 'https://github.com/a') {
        return { status: 302, headers: { location: 'https://objects.githubusercontent.com/final' }, body: Buffer.alloc(0) };
      }
      return { status: 200, headers: {}, body: Buffer.from('done') };
    },
  });
  const res = await http.getText('https://github.com/a');
  assert.equal(res.text, 'done');
  assert.equal(res.url, 'https://objects.githubusercontent.com/final');
  assert.deepEqual(calls, ['https://github.com/a', 'https://objects.githubusercontent.com/final']);
});

// ── 限额与响应 ────────────────────────────────────────────────────────────

test('超过 JSON 上限的响应被拒（即使传输实现先读完了整包）', async () => {
  const http = httpWith({
    request: async () => ({ status: 200, headers: {}, body: Buffer.alloc(1024 * 1024 + 1) }),
  });
  await assert.rejects(http.getJson('https://github.com/big.json'), (err) => err.code === 'too-large');
});

test('zip 上限 64MiB 同样生效', async () => {
  const http = httpWith({
    request: async () => ({ status: 200, headers: {}, body: Buffer.alloc(64 * 1024 * 1024 + 1) }),
  });
  await assert.rejects(http.getBuffer('https://github.com/big.zip'), (err) => err.code === 'too-large');
});

test('非 JSON 响应报 bad-json，而不是把半截文本当对象', async () => {
  const http = httpWith({
    request: async () => ({ status: 200, headers: {}, body: Buffer.from('<html>') }),
  });
  await assert.rejects(http.getJson('https://github.com/x.json'), (err) => err.code === 'bad-json');
});

test('非 200 的不可解析正文不抛 bad-json：状态码要留给调用方判', async () => {
  const http = httpWith({
    request: async () => ({ status: 503, headers: {}, body: Buffer.from('<html>网关错误</html>') }),
  });
  const res = await http.getJson('https://github.com/x.json');
  assert.equal(res.status, 503);
  assert.equal(res.json, null);
});

test('响应形状不对是 bad-response', async () => {
  const http = httpWith({ request: async () => ({ body: Buffer.alloc(0) }) });
  await assert.rejects(http.getText('https://github.com/x'), (err) => err.code === 'bad-response');
});

test('POST 带上 content-type 与 content-length', async () => {
  let seen = null;
  const http = httpWith({
    request: async (opts) => {
      seen = opts;
      return { status: 200, headers: {}, body: Buffer.from('{"ok":true}') };
    },
  });
  const res = await http.postJson('https://worker.example/auto/pr', { a: 1 }, { headers: { 'x-auto-key': 'k' } });
  assert.equal(res.json.ok, true);
  assert.equal(seen.method, 'POST');
  assert.equal(seen.headers['content-type'], 'application/json');
  assert.equal(seen.headers['content-length'], String(Buffer.byteLength('{"a":1}')));
  assert.equal(seen.headers['x-auto-key'], 'k');
});
