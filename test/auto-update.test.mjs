// auto-update.mjs 的流程测试（全部离线，HTTP 与时钟都注入）。
//
// 覆盖三件事：
//   1. repo 路径：Release 里的新 zip → 解包读 module.prop → 上传 assets-v1 → 组装 pending；
//   2. updateJson 路径：声明值 → 下载 zip → 复核 id/versionCode → 不上传；
//   3. 上限与拒绝：一次最多 20 个模块；作者侧问题只拒绝该模块，不影响本轮其它模块。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  main,
  sha256Hex,
  pickLatestZipRelease,
  highestVersionCode,
  checkUpdateJsonUnchanged,
  buildPendingJson,
  buildVersionEntry,
  assetDownloadUrl,
  releaseEpochMs,
  MAX_MODULES_PER_RUN,
} from '../scripts/auto-update.mjs';
import { makeModuleZip } from './zip-builder.mjs';

const NOW = 1_700_000_000_000;
const DIGEST = `sha256:${'a'.repeat(64)}`;
const REPO = 'https://api.github.com/repos/o/r';

function fakeHttp(routes) {
  const get = async (url) => {
    const r = routes[url];
    if (!r) throw new Error(`测试没有配置这个 URL：${url}`);
    if (r instanceof Error) throw r;
    const text = r.text ?? (r.json !== undefined ? JSON.stringify(r.json) : '');
    return {
      status: r.status ?? 200,
      headers: r.headers || {},
      json: r.json,
      text,
      body: r.body || Buffer.from(text),
    };
  };
  return {
    getJson: get,
    getText: get,
    getBuffer: get,
    async postBinary(url) {
      const r = routes[`POST ${url}`];
      if (!r) throw new Error(`测试没有配置这个上传 URL：${url}`);
      return { status: r.status ?? 201, headers: {}, json: r.json, body: Buffer.from('') };
    },
  };
}

const baseModule = (over = {}) => ({
  id: 'demo',
  name: 'Demo',
  author: '作者',
  description: '说明',
  repoUrl: 'https://github.com/o/r',
  repoVerified: true,
  updateJson: 'https://cdn.example/up.json',
  versions: [{
    version: '1.0',
    versionCode: 4,
    zipUrl: 'https://github.com/o/r/releases/download/v1/x.zip',
    size: 1,
    time: '2026-01-01T00:00:00Z',
    sha256: 'a'.repeat(64),
    repoTag: 'v1',
    repoDigest: DIGEST,
  }],
  ...over,
});

test('pickLatestZipRelease：跳过草稿与没有 zip 的 Release，按 created_at 取最新', () => {
  const releases = [
    { tag_name: 'old', created_at: '2026-01-01T00:00:00Z', assets: [{ name: 'a.zip' }] },
    { tag_name: 'draft', draft: true, created_at: '2026-12-01T00:00:00Z', assets: [{ name: 'b.zip' }] },
    { tag_name: 'nozip', created_at: '2026-12-02T00:00:00Z', assets: [{ name: 'c.apk' }] },
    { tag_name: 'new', created_at: '2026-06-01T00:00:00Z', assets: [{ name: 'd.zip' }] },
  ];
  assert.equal(pickLatestZipRelease(releases).tag_name, 'new');
  assert.equal(pickLatestZipRelease([]), null);
});

test('highestVersionCode：只认整数，忽略坏值', () => {
  assert.equal(highestVersionCode({ versions: [{ versionCode: 3 }, { versionCode: '9' }, { versionCode: 7 }] }), 7);
  assert.equal(highestVersionCode({}), 0);
});

test('checkUpdateJsonUnchanged：从无到有、从有到无都算漂移', () => {
  assert.equal(checkUpdateJsonUnchanged({ updateJson: 'https://a' }, { updateJson: 'https://a' }).ok, true);
  assert.equal(checkUpdateJsonUnchanged({}, {}).ok, true);
  assert.equal(checkUpdateJsonUnchanged({ updateJson: 'https://a' }, {}).ok, false);
  assert.equal(checkUpdateJsonUnchanged({}, { updateJson: 'https://a' }).ok, false);
  assert.equal(checkUpdateJsonUnchanged({ updateJson: 'https://a' }, { updateJson: 'https://b' }).ok, false);
});

test('buildVersionEntry：repoTag 只在 repo 路径出现', () => {
  const repo = buildVersionEntry({ version: 'v', versionCode: 1, zipUrl: 'u', size: 1, time: 't', sha256: 'a'.repeat(64), autoVia: 'repo', repoTag: 'v1' });
  assert.equal(repo.repoTag, 'v1');
  assert.equal(repo.repoDigest, `sha256:${'a'.repeat(64)}`);
  assert.equal(repo.auto, true);
  const json = buildVersionEntry({ version: 'v', versionCode: 1, zipUrl: 'u', size: 1, time: 't', sha256: 'a'.repeat(64), autoVia: 'update-json' });
  assert.equal('repoTag' in json, false);
});

test('buildPendingJson：repo 路径带仓库声明与 assets-v1 定位，空值不写 null', () => {
  const pending = buildPendingJson({
    module: baseModule({ repoLicense: 'MIT' }),
    version: { version: '2.0', versionCode: 5, zipUrl: 'u', size: 1, time: 't', sha256: 'b'.repeat(64), repoDigest: `sha256:${'b'.repeat(64)}`, auto: true, autoVia: 'repo', repoTag: 'v2' },
    releaseTag: 'assets-v1',
    assetName: `${'b'.repeat(64)}.zip`,
    submittedAt: '2026-01-02T00:00:00Z',
    repoCheckedAt: NOW,
  });
  assert.equal(pending.repoUrl, 'https://github.com/o/r');
  assert.equal(pending.repoVerified, true);
  assert.equal(pending.repoCheckedAt, NOW);
  assert.equal(pending.storage, 'github-release-asset');
  assert.equal(pending.releaseTag, 'assets-v1');
  assert.equal(pending.assetName, `${'b'.repeat(64)}.zip`);
  assert.equal(pending.versions[0].repoTag, 'v2');
  assert.equal(Object.values(pending).includes(null), false);
  assert.equal('source' in pending, false);
});

test('buildPendingJson：update-json 路径不写 storage / 仓库声明', () => {
  const pending = buildPendingJson({
    module: { id: 'x', name: 'n', author: 'a', description: 'd', updateJson: 'https://u', repoUrl: 'https://github.com/o/r', versions: [] },
    version: { version: '1', versionCode: 1, zipUrl: 'https://cdn/z.zip', size: 1, time: 't', sha256: 'c'.repeat(64), repoDigest: `sha256:${'c'.repeat(64)}`, auto: true, autoVia: 'update-json' },
    submittedAt: 't',
    repoCheckedAt: NOW,
  });
  assert.equal(pending.updateJson, 'https://u');
  assert.equal('storage' in pending, false);
  assert.equal('repoUrl' in pending, false);
  assert.equal('repoVerified' in pending, false);
});

test('releaseEpochMs：ISO Release 时间转毫秒；坏值回落到本轮时钟', () => {
  assert.equal(releaseEpochMs({ created_at: '2026-10-01T00:00:00Z' }, NOW), Date.parse('2026-10-01T00:00:00Z'));
  assert.equal(releaseEpochMs({ published_at: '2026-10-02T00:00:00Z', created_at: '2026-10-01T00:00:00Z' }, NOW), Date.parse('2026-10-02T00:00:00Z'));
  assert.equal(releaseEpochMs({ created_at: 'not a date' }, NOW), NOW);
  assert.equal(releaseEpochMs(null, NOW), NOW);
});

test('assetDownloadUrl：按 GitHub 固定格式拼地址', () => {
  assert.equal(
    assetDownloadUrl({ owner: 'o', repo: 'r' }, 'assets-v1', 'x y.zip'),
    'https://github.com/o/r/releases/download/assets-v1/x%20y.zip',
  );
});

// ── repo 路径整流程 ──────────────────────────────────────────────────────

test('repo 路径：发现新版本 → 上传 → pending 指向 assets-v1', async () => {
  const zip = makeModuleZip({
    id: 'demo', version: '2.0', versionCode: '5', updateJson: 'https://cdn.example/up.json',
  });
  const hex = sha256Hex(zip);
  const uploadUrl = `https://uploads.github.com/repos/o/r/releases/99/assets?name=${hex}.zip`;
  const http = fakeHttp({
    [REPO]: { status: 200, json: { license: { spdx_id: 'MIT' }, default_branch: 'main' } },
    'https://api.github.com/repos/o/r/releases/tags/v1': {
      status: 200,
      json: { tag_name: 'v1', assets: [{ name: 'x.zip', digest: DIGEST }] },
    },
    'https://api.github.com/repos/o/r/releases?per_page=30': {
      status: 200,
      json: [{
        id: 1,
        tag_name: 'v2',
        created_at: '2026-10-01T00:00:00Z',
        assets: [{ name: 'x.zip', browser_download_url: 'https://github.com/o/r/releases/download/v2/x.zip', digest: `sha256:${hex}` }],
      }],
    },
    'https://github.com/o/r/releases/download/v2/x.zip': { status: 200, body: zip },
    'https://api.github.com/repos/o/r/releases/tags/assets-v1': {
      status: 200,
      json: { id: 99, tag_name: 'assets-v1', assets: [] },
    },
    [`POST ${uploadUrl}`]: {
      status: 201,
      json: { browser_download_url: `https://github.com/o/r/releases/download/assets-v1/${hex}.zip` },
    },
  });

  let prFiles = null;
  const res = await main([], { GITHUB_TOKEN: 't', WORKER_BASE: 'https://w', AUTO_PR_KEY: 'k' }, {
    index: { name: 'r', modules: [baseModule()] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    autoPr: async (p) => { prFiles = p.files; return { prUrl: 'https://github.com/o/r/pull/9' }; },
    log: () => {},
  });

  assert.equal(res.prUrl, 'https://github.com/o/r/pull/9');
  assert.deepEqual(res.submitted, [{ id: 'demo', via: 'repo', versionCode: 5 }]);
  assert.ok(prFiles);
  const pendingFile = prFiles.find((f) => f.path === 'pending/demo/5.json');
  assert.ok(pendingFile, `缺少 pending 文件：${prFiles.map((f) => f.path)}`);
  const pending = JSON.parse(pendingFile.content);
  assert.equal(pending.id, 'demo');
  assert.equal(pending.repoVerified, true);
  assert.equal(pending.repoCheckedAt, NOW);
  assert.equal(pending.repoLicense, 'MIT');
  assert.equal(pending.storage, 'github-release-asset');
  assert.equal(pending.releaseTag, 'assets-v1');
  assert.equal(pending.assetName, `${hex}.zip`);
  assert.equal(pending.versions[0].versionCode, 5);
  assert.equal(pending.versions[0].auto, true);
  assert.equal(pending.versions[0].autoVia, 'repo');
  assert.equal(pending.versions[0].repoTag, 'v2');
  assert.equal(pending.versions[0].sha256, hex);
  assert.equal(pending.versions[0].repoDigest, `sha256:${hex}`);
  assert.equal(pending.versions[0].zipUrl, `https://github.com/o/r/releases/download/assets-v1/${hex}.zip`);
  // 索引里的 time 是毫秒数字（build-index 与 validate-index 都按数字校验）。
  assert.equal(pending.versions[0].time, Date.parse('2026-10-01T00:00:00Z'));
  assert.ok(prFiles.some((f) => f.path === 'json/repo-state.json'));
  const state = JSON.parse(prFiles.find((f) => f.path === 'json/repo-state.json').content);
  assert.equal(state.modules.demo.repoVerified, true);
  assert.equal(state.modules.demo.repoCheckedAt, NOW);
  assert.equal(state.modules.demo.repoLicense, 'MIT');
});

test('repo 路径：下载字节与 Release 资产 digest 不一致 → 拒绝该模块', async () => {
  const zip = makeModuleZip({ id: 'demo', version: '2.0', versionCode: '5', updateJson: 'https://cdn.example/up.json' });
  const bad = `sha256:${'0'.repeat(64)}`;
  const http = fakeHttp({
    [REPO]: { status: 200, json: { license: { spdx_id: 'MIT' }, default_branch: 'main' } },
    'https://api.github.com/repos/o/r/releases/tags/v1': { status: 200, json: { tag_name: 'v1', assets: [{ name: 'x.zip', digest: DIGEST }] } },
    'https://api.github.com/repos/o/r/releases?per_page=30': {
      status: 200,
      json: [{
        tag_name: 'v2',
        created_at: '2026-10-01T00:00:00Z',
        assets: [{ name: 'x.zip', browser_download_url: 'https://github.com/o/r/releases/download/v2/x.zip', digest: bad }],
      }],
    },
    'https://github.com/o/r/releases/download/v2/x.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [baseModule()] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  assert.equal(res.files.filter((f) => f.path.startsWith('pending/')).length, 0);
  assert.equal(res.submitted.length, 0);
  assert.match(res.markdown, /digest/);
});

test('repo 路径 dry-run：不上传，但 pending 里的地址与真跑一致', async () => {
  const zip = makeModuleZip({ id: 'demo', version: '2.0', versionCode: '5', updateJson: 'https://cdn.example/up.json' });
  const hex = sha256Hex(zip);
  const http = fakeHttp({
    [REPO]: { status: 200, json: { license: { spdx_id: 'MIT' } } },
    'https://api.github.com/repos/o/r/releases/tags/v1': { status: 200, json: { assets: [{ name: 'x.zip', digest: DIGEST }] } },
    'https://api.github.com/repos/o/r/releases?per_page=30': {
      status: 200,
      json: [{ tag_name: 'v2', created_at: '2026-10-01T00:00:00Z', assets: [{ name: 'x.zip', browser_download_url: 'https://github.com/o/r/releases/download/v2/x.zip', digest: `sha256:${hex}` }] }],
    },
    'https://github.com/o/r/releases/download/v2/x.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [baseModule()] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  const pending = JSON.parse(res.files.find((f) => f.path === 'pending/demo/5.json').content);
  assert.equal(pending.versions[0].zipUrl, `https://github.com/o/r/releases/download/assets-v1/${hex}.zip`);
  // 索引里的 time 是毫秒数字（build-index 与 validate-index 都按数字校验）。
  assert.equal(pending.versions[0].time, Date.parse('2026-10-01T00:00:00Z'));
  assert.equal(pending.storage, 'github-release-asset');
});

// ── updateJson 路径 ──────────────────────────────────────────────────────

test('updateJson 路径：声明值驱动，包的 id/versionCode 复核通过后提交', async () => {
  const zip = makeModuleZip({ id: 'uj', version: '9.9', versionCode: '2', updateJson: 'https://cdn.example/u.json' });
  const hex = sha256Hex(zip);
  const mod = {
    id: 'uj', name: 'UJ', author: 'a', description: 'd', updateJson: 'https://cdn.example/u.json', versions: [{ versionCode: 1 }],
  };
  const http = fakeHttp({
    'https://cdn.example/u.json': {
      status: 200,
      json: { id: 'uj', version: '9.9', versionCode: 2, zipUrl: 'https://cdn.example/uj.zip' },
    },
    'https://cdn.example/uj.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [mod] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  const pending = JSON.parse(res.files.find((f) => f.path === 'pending/uj/2.json').content);
  assert.equal(pending.updateJson, 'https://cdn.example/u.json');
  assert.equal(pending.versions[0].autoVia, 'update-json');
  assert.equal(pending.versions[0].zipUrl, 'https://cdn.example/uj.zip');
  assert.equal(pending.versions[0].sha256, hex);
  assert.equal(pending.versions[0].time, NOW);
  assert.equal('storage' in pending, false);
});

test('updateJson 路径：模块本来有仓库 → pending 带上仓库头，但版本不写 repoTag', async () => {
  const zip = makeModuleZip({ id: 'uj', version: '9.9', versionCode: '2', updateJson: 'https://cdn.example/u.json' });
  const mod = {
    id: 'uj', name: 'UJ', author: 'a', description: 'd',
    repoUrl: 'https://github.com/o/r', repoVerified: false, repoCheckedAt: 1234,
    updateJson: 'https://cdn.example/u.json', versions: [{ versionCode: 1 }],
  };
  const http = fakeHttp({
    [REPO]: { status: 200, json: { license: { spdx_id: 'MIT' } } },
    'https://api.github.com/repos/o/r/releases?per_page=30': { status: 200, json: [] },
    'https://cdn.example/u.json': {
      status: 200,
      json: { id: 'uj', version: '9.9', versionCode: 2, zipUrl: 'https://cdn.example/uj.zip' },
    },
    'https://cdn.example/uj.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [mod] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  const pending = JSON.parse(res.files.find((f) => f.path === 'pending/uj/2.json').content);
  // 不带仓库头 → build-index 的「source 与 repoUrl 至少一个」会直接判这条 invalid。
  assert.equal(pending.repoUrl, 'https://github.com/o/r');
  assert.equal(pending.repoVerified, false);
  // 本轮复验刚给出的结论比索引里的旧值新（1234 是上次检查时间）。
  assert.equal(pending.repoCheckedAt, NOW);
  assert.equal('repoTag' in pending.versions[0], false);
  assert.equal('storage' in pending, false);
});

test('updateJson 路径：包内 id 不符 → 拒绝该模块，不开 PR', async () => {
  const zip = makeModuleZip({ id: 'other', version: '1', versionCode: '2', updateJson: 'https://cdn.example/u.json' });
  const mod = {
    id: 'uj', name: 'UJ', author: 'a', description: 'd', updateJson: 'https://cdn.example/u.json', versions: [{ versionCode: 1 }],
  };
  const http = fakeHttp({
    'https://cdn.example/u.json': { status: 200, json: { id: 'uj', version: '1', versionCode: 2, zipUrl: 'https://cdn.example/uj.zip' } },
    'https://cdn.example/uj.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [mod] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  assert.equal(res.files.length, 0);
  assert.equal(res.submitted.length, 0);
  assert.equal(res.prUrl, undefined);
});

test('updateJson 路径：包内 module.prop 缺 versionCode → 拒绝（无法确认包版本）', async () => {
  const zip = makeModuleZip({ id: 'uj', version: '9.9', updateJson: 'https://cdn.example/u.json' });
  const mod = {
    id: 'uj', name: 'UJ', author: 'a', description: 'd', updateJson: 'https://cdn.example/u.json', versions: [{ versionCode: 1 }],
  };
  const http = fakeHttp({
    'https://cdn.example/u.json': { status: 200, json: { id: 'uj', version: '9.9', versionCode: 2, zipUrl: 'https://cdn.example/uj.zip' } },
    'https://cdn.example/uj.zip': { status: 200, body: zip },
  });
  const res = await main([], {}, {
    index: { modules: [mod] },
    previousState: { checkedAt: 0, modules: {} },
    http,
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  assert.equal(res.files.length, 0);
  assert.equal(res.submitted.length, 0);
});

test('updateJson 路径：updateJson 里的 versionCode 回退 → 跳过', async () => {
  const mod = {
    id: 'uj', name: 'UJ', author: 'a', description: 'd', updateJson: 'https://cdn.example/u.json', versions: [{ versionCode: 5 }],
  };
  const http = fakeHttp({
    'https://cdn.example/u.json': { status: 200, json: { id: 'uj', version: '1', versionCode: 5, zipUrl: 'https://cdn.example/uj.zip' } },
  });
  const res = await main([], {}, {
    index: { modules: [mod] }, previousState: { checkedAt: 0, modules: {} }, http, now: () => NOW, assetsRepo: { owner: 'o', repo: 'r' }, githubToken: 't', dryRun: true, log: () => {},
  });
  assert.equal(res.files.length, 0);
  assert.equal(res.submitted.length, 0);
});

// ── 上限 ──────────────────────────────────────────────────────────────────

test(`一次最多提交 ${MAX_MODULES_PER_RUN} 个模块`, async () => {
  const routes = {};
  const modules = [];
  for (let i = 0; i < MAX_MODULES_PER_RUN + 1; i += 1) {
    const id = `m${i}`;
    const uj = `https://cdn.example/${id}.json`;
    const zurl = `https://cdn.example/${id}.zip`;
    const zip = makeModuleZip({ id, version: '1', versionCode: '2', updateJson: uj });
    modules.push({ id, name: id, author: 'a', description: 'd', updateJson: uj, versions: [{ versionCode: 1 }] });
    routes[uj] = { status: 200, json: { id, version: '1', versionCode: 2, zipUrl: zurl } };
    routes[zurl] = { status: 200, body: zip };
  }
  const res = await main([], {}, {
    index: { modules },
    previousState: { checkedAt: 0, modules: {} },
    http: fakeHttp(routes),
    now: () => NOW,
    assetsRepo: { owner: 'o', repo: 'r' },
    githubToken: 't',
    dryRun: true,
    log: () => {},
  });
  assert.equal(res.submitted.length, MAX_MODULES_PER_RUN);
  assert.equal(res.files.filter((f) => f.path.startsWith('pending/')).length, MAX_MODULES_PER_RUN);
});
