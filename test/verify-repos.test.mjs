// verify-repos.mjs 的复验判据与状态合并测试（全部离线）。
//
// 重点不是「能跑通」，而是三条容易写错的边界：
//   1. 仓库 404 / 证据消失 → 撤标（false）；
//   2. GitHub 5xx / rate limit → 保留旧状态（不能因为一次宕机撤标）；
//   3. 状态无变化时不更新 checkedAt（否则每天都会开一个只改时间戳的 PR）。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  emptyState,
  normalizeDigest,
  latestEvidenceVersion,
  parseChecksums,
  releaseHasDigest,
  licenseFromRepo,
  cleanStateEntry,
  canonicalModules,
  finalizeState,
  mergeVerifiedState,
  verifyRepoOne,
  verifyReposCore,
} from '../scripts/verify-repos.mjs';

const DIGEST = `sha256:${'a'.repeat(64)}`;
const HEX = 'a'.repeat(64);

function fakeHttp(routes) {
  const get = async (url) => {
    const r = routes[url];
    if (!r) throw new Error(`测试没有配置这个 URL：${url}`);
    if (r instanceof Error) throw r;
    const text = r.text ?? (r.json !== undefined ? JSON.stringify(r.json) : '');
    return {
      status: r.status,
      headers: r.headers || {},
      json: r.json,
      text,
      body: Buffer.from(text),
    };
  };
  return {
    getJson: get,
    getText: get,
    getBuffer: get,
    postJson: async () => { throw new Error('复验不应该发 POST'); },
    postBinary: async () => { throw new Error('复验不应该发 POST'); },
  };
}

const moduleWith = (over = {}) => ({
  id: 'demo',
  name: 'Demo',
  author: 'a',
  description: 'd',
  repoUrl: 'https://github.com/o/r',
  repoVerified: true,
  repoCheckedAt: 1000,
  versions: [{
    version: 'v1',
    versionCode: 3,
    zipUrl: 'https://github.com/o/r/releases/download/v1/x.zip',
    size: 10,
    time: '2026-01-01T00:00:00Z',
    sha256: HEX,
    repoTag: 'v1',
    repoDigest: DIGEST,
  }],
  ...over,
});

const repoOk = { status: 200, json: { license: { spdx_id: 'MIT' }, default_branch: 'main' } };
const RELEASE_URL = 'https://api.github.com/repos/o/r/releases/tags/v1';
const REPO_URL = 'https://api.github.com/repos/o/r';

test('latestEvidenceVersion：只认 versionCode 最大且带 repoDigest 的版本', () => {
  const m = {
    versions: [
      { versionCode: 9 },
      { versionCode: 5, repoDigest: DIGEST },
      { versionCode: 7, repoDigest: `sha256:${'b'.repeat(64)}` },
      { versionCode: 3, repoDigest: 'not-a-digest' },
    ],
  };
  assert.equal(latestEvidenceVersion(m).versionCode, 7);
  assert.equal(latestEvidenceVersion({ versions: [] }), null);
});

test('parseChecksums：只认 64 位摘要行，其它行忽略', () => {
  const map = parseChecksums([
    `${HEX}  module.zip`,
    `${'b'.repeat(64).toUpperCase()} *module2.zip`,
    '# 注释',
    'broken line',
    '',
  ].join('\n'));
  assert.equal(map.size, 2);
  assert.equal(map.has(HEX), true);
});

test('releaseHasDigest：digest 大小写与缺失都判对', () => {
  const rel = { assets: [{ name: 'a', digest: `sha256:${'A'.repeat(64)}` }, { name: 'b', digest: null }] };
  assert.equal(releaseHasDigest(rel, DIGEST), true);
  assert.equal(releaseHasDigest(rel, `sha256:${'b'.repeat(64)}`), false);
  assert.equal(releaseHasDigest({}, DIGEST), false);
});

test('licenseFromRepo：NOASSERTION 与空值都返回空串', () => {
  assert.equal(licenseFromRepo({ license: { spdx_id: 'MIT' } }), 'MIT');
  assert.equal(licenseFromRepo({ license: { spdx_id: 'NOASSERTION' } }), '');
  assert.equal(licenseFromRepo({}), '');
});

test('cleanStateEntry：键序固定，空值省略', () => {
  assert.deepEqual(
    cleanStateEntry({ updateJson: 'u', repoLicense: '', repoCheckedAt: 5, repoVerified: false, repoUrl: 'x' }),
    { repoUrl: 'x', repoVerified: false, repoCheckedAt: 5, updateJson: 'u' },
  );
});

test('finalizeState：没有变化时 checkedAt 不动，有变化才推进', () => {
  const prev = { checkedAt: 111, modules: { demo: { repoUrl: 'https://github.com/o/r', repoVerified: true, repoCheckedAt: 100 } } };
  const same = finalizeState(prev, { demo: { repoUrl: 'https://github.com/o/r', repoVerified: true, repoCheckedAt: 100 } }, 999);
  assert.equal(same.changed, false);
  assert.equal(same.state.checkedAt, 111);

  const changed = finalizeState(prev, { demo: { repoUrl: 'https://github.com/o/r', repoVerified: false, repoCheckedAt: 999 } }, 999);
  assert.equal(changed.changed, true);
  assert.equal(changed.state.checkedAt, 999);
  assert.equal(changed.changes[0].kind, 'verified');
});

test('mergeVerifiedState：丢掉没有 repoUrl 的模块、URL 不匹配的旧状态', () => {
  const modules = [
    { id: 'keep', repoUrl: 'https://github.com/o/keep', repoVerified: true },
    { id: 'nouj', repoUrl: '' },
  ];
  const previous = {
    checkedAt: 1,
    modules: {
      keep: { repoUrl: 'https://github.com/o/OLD', repoVerified: false, repoCheckedAt: 2 },
      gone: { repoUrl: 'https://github.com/o/gone', repoVerified: true, repoCheckedAt: 3 },
    },
  };
  const merged = mergeVerifiedState({ modules, previous, results: [], nowMs: 50 });
  // keep 的旧状态 URL 不匹配 → 丢弃；没有新结果就没有条目。gone 不在索引里 → 也丢弃。
  assert.deepEqual(Object.keys(merged.state.modules), []);
  assert.equal(merged.changed, true);
  assert.deepEqual(merged.changes.map((c) => [c.id, c.kind]), [['gone', 'removed'], ['keep', 'removed']]);
});

test('verifyRepoOne：Release 资产摘要仍匹配 → verified', async () => {
  const http = fakeHttp({
    [REPO_URL]: repoOk,
    [RELEASE_URL]: { status: 200, json: { tag_name: 'v1', assets: [{ name: 'x.zip', digest: DIGEST }] } },
  });
  const r = await verifyRepoOne({ module: moduleWith(), previous: null, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'verified');
  assert.equal(r.entry.repoVerified, true);
  assert.equal(r.entry.repoLicense, 'MIT');
  assert.equal(r.entry.repoCheckedAt, 5000);
});

test('verifyRepoOne：state 条目跟随模块的 updateJson（新增/变化/删除）', async () => {
  const http = fakeHttp({
    [REPO_URL]: repoOk,
    [RELEASE_URL]: { status: 200, json: { tag_name: 'v1', assets: [{ name: 'x.zip', digest: DIGEST }] } },
  });
  const first = await verifyRepoOne({
    module: moduleWith({ updateJson: 'https://example.com/mod.json' }),
    previous: null,
    http,
    token: 't',
    nowMs: 5000,
  });
  assert.equal(first.entry.updateJson, 'https://example.com/mod.json');

  // 复验结论没变、updateJson 变了：必须写入新值，并且推进 repoCheckedAt（否则变化会丢）。
  const second = await verifyRepoOne({
    module: moduleWith({ updateJson: 'https://example.com/mod-v2.json' }),
    previous: first.entry,
    http,
    token: 't',
    nowMs: 6000,
  });
  assert.equal(second.entry.updateJson, 'https://example.com/mod-v2.json');
  assert.equal(second.entry.repoCheckedAt, 6000);

  // 模块把 updateJson 删了：state 里也要删，不能留一个已经不存在于 module.prop 的地址。
  const third = await verifyRepoOne({
    module: moduleWith(),
    previous: second.entry,
    http,
    token: 't',
    nowMs: 7000,
  });
  assert.equal(Object.hasOwn(third.entry, 'updateJson'), false);
});

test('mergeVerifiedState：updateJson 变化也算状态变化，并给出 updateJson 差异', async () => {
  const mod = moduleWith();
  const prevEntry = {
    repoUrl: 'https://github.com/o/r',
    repoVerified: true,
    repoCheckedAt: 1000,
    repoLicense: 'MIT',
    updateJson: 'https://example.com/old.json',
  };
  const nextEntry = { ...prevEntry, repoCheckedAt: 2000, updateJson: 'https://example.com/new.json' };
  const r = mergeVerifiedState({
    modules: [mod],
    previous: { checkedAt: 1000, modules: { demo: prevEntry } },
    results: [{ id: 'demo', entry: nextEntry }],
    nowMs: 2000,
  });
  assert.equal(r.changed, true);
  assert.deepEqual(r.changes.map((c) => c.kind), ['updateJson']);
  assert.equal(r.state.modules.demo.updateJson, 'https://example.com/new.json');
  assert.equal(r.state.checkedAt, 2000);
});

test('verifyRepoOne：证据资产消失 → unverified（撤标）', async () => {
  const http = fakeHttp({
    [REPO_URL]: repoOk,
    [RELEASE_URL]: { status: 200, json: { tag_name: 'v1', assets: [{ name: 'x.zip', digest: `sha256:${'b'.repeat(64)}` }] } },
  });
  const r = await verifyRepoOne({ module: moduleWith(), previous: null, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'unverified');
  assert.equal(r.entry.repoVerified, false);
});

test('verifyRepoOne：仓库 404 → unverified', async () => {
  const http = fakeHttp({ [REPO_URL]: { status: 404, json: { message: 'Not Found' } } });
  const r = await verifyRepoOne({ module: moduleWith(), previous: null, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'unverified');
  assert.equal(r.entry.repoVerified, false);
});

test('verifyRepoOne：GitHub 5xx → preserved，旧条目原样返回', async () => {
  const previous = { repoUrl: 'https://github.com/o/r', repoVerified: true, repoCheckedAt: 1234 };
  const http = fakeHttp({ [REPO_URL]: { status: 503, json: { message: 'unavailable' } } });
  const r = await verifyRepoOne({ module: moduleWith(), previous, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'preserved');
  assert.equal(r.entry, previous);
});

test('verifyRepoOne：rate limit（403 + remaining=0）也 preserved', async () => {
  const previous = { repoUrl: 'https://github.com/o/r', repoVerified: true, repoCheckedAt: 1234 };
  const http = fakeHttp({
    [REPO_URL]: { status: 403, headers: { 'x-ratelimit-remaining': '0' }, json: { message: 'API rate limit exceeded' } },
  });
  const r = await verifyRepoOne({ module: moduleWith(), previous, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'preserved');
});

test('verifyRepoOne：checksums.txt 证据成立', async () => {
  const mod = moduleWith({
    versions: [{ versionCode: 3, repoTag: 'checksums.txt@main', repoDigest: DIGEST }],
  });
  const http = fakeHttp({
    [REPO_URL]: repoOk,
    'https://raw.githubusercontent.com/o/r/main/checksums.txt': { status: 200, text: `${HEX}  module.zip\n` },
  });
  const r = await verifyRepoOne({ module: mod, previous: null, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'verified');
});

test('verifyRepoOne：checksums.txt 里没有该摘要 → unverified', async () => {
  const mod = moduleWith({
    versions: [{ versionCode: 3, repoTag: 'checksums.txt@main', repoDigest: DIGEST }],
  });
  const http = fakeHttp({
    [REPO_URL]: repoOk,
    'https://raw.githubusercontent.com/o/r/main/checksums.txt': { status: 200, text: `${'b'.repeat(64)}  other.zip\n` },
  });
  const r = await verifyRepoOne({ module: mod, previous: null, http, token: 't', nowMs: 5000 });
  assert.equal(r.verdict, 'unverified');
});

test('verifyRepoOne：网络错误是硬失败（抛），不是 preserved', async () => {
  const http = fakeHttp({
    [REPO_URL]: Object.assign(new Error('socket hang up'), { code: 'network' }),
  });
  await assert.rejects(
    verifyRepoOne({ module: moduleWith(), previous: null, http, token: 't', nowMs: 5000 }),
    /socket hang up/,
  );
});

test('verifyReposCore：无 state 时用索引的 repoVerified 作基线，5xx 不撤标', async () => {
  const http = fakeHttp({ [REPO_URL]: { status: 502, json: {} } });
  const res = await verifyReposCore({
    modules: [moduleWith()],
    previousState: emptyState(),
    http,
    token: 't',
    nowMs: 5000,
    log: () => {},
  });
  assert.equal(res.summary.preserved, 1);
  // 空状态 → 首次写入基线，changed 为 true 是对的；关键是 5xx 没有把 repoVerified 改成 false。
  assert.equal(res.changed, true);
  assert.equal(res.state.modules.demo.repoVerified, true);
  assert.equal(res.state.modules.demo.repoCheckedAt, 1000);
});

test('canonicalModules：输入顺序不影响比较结果', () => {
  const a = canonicalModules({ b: { repoUrl: 'b', repoVerified: true, repoCheckedAt: 1 }, a: { repoUrl: 'a', repoVerified: false, repoCheckedAt: 2 } });
  const b = canonicalModules({ a: { repoUrl: 'a', repoCheckedAt: 2, repoVerified: false }, b: { repoCheckedAt: 1, repoVerified: true, repoUrl: 'b' } });
  assert.equal(JSON.stringify(a), JSON.stringify(b));
});

test('normalizeDigest：只接受 sha256:<64hex>', () => {
  assert.equal(normalizeDigest(`sha256:${'A'.repeat(64)}`), DIGEST);
  assert.equal(normalizeDigest(`${'a'.repeat(64)}`), '');
  assert.equal(normalizeDigest(''), '');
});
