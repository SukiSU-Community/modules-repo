// fetch-pending-zip.mjs 的下载地址守卫测试。
//
// 这个脚本是审核流水线里**唯一**会拿「投稿方可控的文本」当 URL 去发请求的地方，
// 而它此前没有任何测试 —— 意味着 SSRF 与「扫 A 合 B」两类问题可以静默存在很久。
// 运行：node --test test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  resolveDownloadUrl,
  assertDownloadUrl,
  downloadToBuffer,
  ALLOWED_DOWNLOAD_HOSTS,
  parseArgs,
} from '../scripts/fetch-pending-zip.mjs';

const ASSET = 'a'.repeat(64) + '.zip';
const GOOD = `https://github.com/SukiSU-Community/modules-repo/releases/download/assets-v1/${ASSET}`;
const raw = (over = {}) => ({
  id: 'demo',
  releaseTag: 'assets-v1',
  assetName: ASSET,
  versions: [{ version: 'v1', versionCode: 1, zipUrl: GOOD }],
  ...over,
});

test('Worker 正常写出的条目：解析到 release 直链', () => {
  const r = resolveDownloadUrl(raw());
  assert.equal(r.url, GOOD);
  assert.equal(r.source, 'zipUrl');
  assert.equal(r.error, undefined);
});

test('只有 releaseTag+assetName 时自己拼直链', () => {
  const r = resolveDownloadUrl(
    { id: 'demo', releaseTag: 'assets-v1', assetName: ASSET, versions: [{ versionCode: 1 }] },
    { owner: 'SukiSU-Community', repo: 'modules-repo' },
  );
  assert.equal(r.url, GOOD);
  assert.equal(r.source, 'releaseTag+assetName');
});

test('元数据里什么都没给 → 明确报错而不是静默取空', () => {
  const r = resolveDownloadUrl({ id: 'demo', versions: [{ versionCode: 1 }] });
  assert.equal(r.url, '');
  assert.match(r.error, /没有 zipUrl/);
});

// ── SSRF / 协议 / 凭据 ────────────────────────────────────────────────────
for (const [name, url] of [
  ['云元数据地址', 'http://169.254.169.254/latest/meta-data/'],
  ['本地回环', 'http://127.0.0.1:6379/'],
  ['外部主机', 'https://evil.tld/payload.zip'],
  ['假域名（github.com.evil.tld）', 'https://github.com.evil.tld/a.zip'],
  ['URL 里塞凭据', 'https://github.com@evil.tld/a.zip'],
  ['明文 http', 'http://github.com/o/r/releases/download/assets-v1/x.zip'],
]) {
  test(`${name} 被拒`, () => {
    const r = resolveDownloadUrl({ id: 'd', versions: [{ versionCode: 1, zipUrl: url }] });
    assert.equal(r.url, '', `${url} 不该被放行`);
    assert.ok(r.error, '必须给出原因');
  });
}

// ── 「扫的是 A、合的是 B」─────────────────────────────────────────────────
test('直链落到的文件名与声明的 assetName 不一致 → 拒', () => {
  const url = 'https://github.com/SukiSU-Community/modules-repo/releases/download/assets-v1/' + 'b'.repeat(64) + '.zip';
  const r = resolveDownloadUrl({ releaseTag: 'assets-v1', assetName: ASSET, versions: [{ versionCode: 1, zipUrl: url }] });
  assert.equal(r.url, '');
  assert.match(r.error, /与元数据声明的 assetName/);
});

test('assetName 与 zipUrl 互相印证，却和 versions[].sha256 无关 → 一样拒', () => {
  // 手搓 pending JSON 的下一步就是这条：把 assetName 和 zipUrl 写成同一个名字，
  // 让「名字对得上」的旧判据通过，而摘要指向另一个包。三处必须钉成同一个。
  const sha = 'c'.repeat(64);
  const url = `https://github.com/SukiSU-Community/modules-repo/releases/download/assets-v1/${ASSET}`;
  const r = resolveDownloadUrl({
    releaseTag: 'assets-v1',
    assetName: ASSET,
    versions: [{ versionCode: 1, zipUrl: url, sha256: sha }],
  });
  assert.equal(r.url, '', JSON.stringify(r));
  assert.match(r.error, /内容寻址名/);
  assert.ok(r.error.includes(`${sha}.zip`), '报错里必须给出期望的那个名字');
});

test('三处一致的条目（assetName == <sha256>.zip == 直链尾巴）放行', () => {
  const sha = 'd'.repeat(64);
  const name = `${sha}.zip`;
  const url = `https://github.com/SukiSU-Community/modules-repo/releases/download/assets-v1/${name}`;
  const r = resolveDownloadUrl({ releaseTag: 'assets-v1', assetName: name, versions: [{ versionCode: 1, zipUrl: url, sha256: sha }] });
  assert.equal(r.url, url);
});

test('摘要写成别的形状（短串 / 含非十六进制字符）直接拒，不当成「没声明」放过', () => {
  for (const bad of ['d'.repeat(63), 'z'.repeat(64), 'sha256:deadbeef', '0123456789abcdef'.repeat(3)]) {
    const r = assertDownloadUrl(
      `https://github.com/o/r/releases/download/assets-v1/${'d'.repeat(64)}.zip`,
      { versions: [{ versionCode: 1, sha256: bad }] },
    );
    assert.equal(r.ok, false, `${bad} 不该被放行`);
    assert.match(r.error, /64 位十六进制/);
  }
});

test('大小写混合的摘要声明：归一化后与内容寻址名一致就放行', () => {
  const sha = 'E'.repeat(64);
  const r = assertDownloadUrl(
    `https://github.com/o/r/releases/download/assets-v1/${sha.toLowerCase()}.zip`,
    { versions: [{ versionCode: 1, sha256: sha }] },
  );
  assert.equal(r.ok, true, JSON.stringify(r));
});


test('直链不在声明的 release tag 路径下 → 拒', () => {
  const url = `https://github.com/SukiSU-Community/modules-repo/releases/download/other-tag/${ASSET}`;
  const c = assertDownloadUrl(url, { releaseTag: 'assets-v1', assetName: ASSET });
  assert.equal(c.ok, false);
  assert.match(c.error, /release tag/);
});

// ── 本地路径：CI 默认拒绝，离线自测显式开启 ──────────────────────────────
test('zipUrl 指向本地/文件路径时默认拒绝', () => {
  for (const url of ['file:///etc/passwd', '../../json/modules.json', '/etc/hosts']) {
    const r = resolveDownloadUrl({ versions: [{ versionCode: 1, zipUrl: url }] });
    assert.equal(r.url, '', `${url} 默认不该被接受`);
    assert.match(r.error, /allow-local-zipurl/);
  }
});

test('显式 --allow-local-zipurl 后 file:// 才走本地分支', () => {
  const r = resolveDownloadUrl({ versions: [{ versionCode: 1, zipUrl: 'file:///tmp/x.zip' }] }, { allowLocal: true });
  assert.equal(r.source, 'zipUrl-local');
  assert.equal(r.url, 'file:///tmp/x.zip');
});

test('parseArgs 认识 --allow-local-zipurl（默认关）', () => {
  assert.equal(parseArgs([]).allowLocal, false);
  assert.equal(parseArgs(['--allow-local-zipurl']).allowLocal, true);
});

// ── 重定向：每一跳都要重新过白名单 ───────────────────────────────────────
test('302 到 objects.githubusercontent.com 继续跟；跳到外部主机立即停', async () => {
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (u) => {
    seen.push(String(u));
    if (String(u) === GOOD) {
      return new Response(null, { status: 302, headers: { location: 'https://objects.githubusercontent.com/x.zip' } });
    }
    if (String(u).includes('objects.githubusercontent.com')) {
      return new Response(new Uint8Array([0x50, 0x4b, 0x05, 0x06]), { status: 200 });
    }
    return new Response(null, { status: 302, headers: { location: 'https://evil.tld/x.zip' } });
  };
  try {
    const buf = await downloadToBuffer(GOOD);
    assert.equal(buf[0], 0x50, '合法跳转链应取到内容');
    assert.equal(seen.length, 2);
  } finally {
    globalThis.fetch = real;
  }

  globalThis.fetch = async (u) => {
    if (String(u) === GOOD) {
      return new Response(null, { status: 302, headers: { location: 'https://evil.tld/x.zip' } });
    }
    return new Response(null, { status: 200 });
  };
  try {
    await assert.rejects(() => downloadToBuffer(GOOD), /不在允许列表/);
  } finally {
    globalThis.fetch = real;
  }
});

test('重定向无限循环时靠跳数上限熔断', async () => {
  const real = globalThis.fetch;
  let n = 0;
  globalThis.fetch = async () => {
    n++;
    return new Response(null, { status: 302, headers: { location: 'https://github.com/o/r/releases/download/assets-v1/loop.zip' } });
  };
  try {
    await assert.rejects(() => downloadToBuffer(GOOD), /重定向次数超过上限/);
    assert.ok(n <= 6, `跳数应封顶，实际请求 ${n} 次`);
  } finally {
    globalThis.fetch = real;
  }
});

test('允许列表就是这三个主机，别悄悄加宽', () => {
  assert.deepEqual(
    [...ALLOWED_DOWNLOAD_HOSTS].sort(),
    ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'],
  );
});

// 真实投稿 PR #4 就是死在这条上的：github.com 的 release 直链 302 到
// release-assets.githubusercontent.com，而当时的白名单没有它，于是所有投稿都取不到包。
// 签名直链的 path 是 /github-production-release-asset-2e/<id>/<token>?Expires=…&Signature=…，
// 尾巴不再是 <sha>.zip —— 所以中间跳只过主机/协议/凭据这三关，
// 「扫的包＝合的包」靠的是 main() 里对实下载字节做的 sha256 比对，而不是靠 URL 长相。
test('302 到 release-assets.githubusercontent.com 的签名直链要能跟到底', async () => {
  const real = globalThis.fetch;
  const signed =
    'https://release-assets.githubusercontent.com/github-production-release-asset-2e/999/deadbeef' +
    '?Expires=1791642284&Key-Pair-Id=K1&Signature=ABC%3D';
  const seen = [];
  globalThis.fetch = async (u) => {
    seen.push(String(u));
    if (String(u) === GOOD) return new Response(null, { status: 302, headers: { location: signed } });
    if (String(u).startsWith(signed)) return new Response(new Uint8Array([0x50, 0x4b, 0x05, 0x06]), { status: 200 });
    return new Response(null, { status: 404 });
  };
  try {
    const buf = await downloadToBuffer(GOOD);
    assert.equal(buf.length, 4, '签名直链这一跳必须取到内容，而不是被白名单挡掉');
    assert.equal(seen.length, 2);
  } finally {
    globalThis.fetch = real;
  }
});
