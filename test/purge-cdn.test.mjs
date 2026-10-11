/**
 * purge-cdn.mjs 的单测 —— 这一步是「下架到底多久到用户手里」的定义处。
 * 运行：node --test test/purge-cdn.test.mjs
 *
 * 锁三件事：目标算得对（换主机名、保留 query）、三态判得对（成功/失败/无能为力），
 * 以及**失败必须让退出码变红** —— 合并已经发生，这一步红只是告诉人「CDN 还在发旧索引」；
 * 如果它静默 0，那条下架在用户手里就等于没发生，而没人知道。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { purgeTargets, purgeAll, main, parseArgs } from '../scripts/purge-cdn.mjs';

const REPO = 'o/r';

/** 假 fetch：按 URL 前缀返回预设结果，同时把请求顺序记下来。 */
function fakeFetch(results = {}) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    const r = results[url] ?? { status: 200, body: { status: 'finished' } };
    if (r.throw) throw new Error(r.throw);
    return {
      ok: (r.status ?? 200) < 400,
      status: r.status ?? 200,
      text: async () => (typeof r.body === 'string' ? r.body : JSON.stringify(r.body)),
    };
  };
  return { impl, calls };
}

const silentLog = () => {
  const lines = [];
  return { log: { log: (s) => lines.push(String(s)), error: (s) => lines.push(String(s)), warn: (s) => lines.push(String(s)) }, lines };
};

test('purgeTargets：默认清索引与台账两份，地址按仓库与分支拼', () => {
  const t = purgeTargets({ repo: REPO });
  assert.equal(t.length, 2);
  assert.deepEqual(
    t.map((x) => x.url),
    ['https://cdn.jsdelivr.net/gh/o/r@main/json/modules.json', 'https://cdn.jsdelivr.net/gh/o/r@main/json/dispositions.json']
  );
  for (const x of t) assert.equal(x.purgeUrl, x.url.replace('https://cdn.', 'https://purge.'));
});

test('purgeTargets：没有仓库就不凭空造目标', () => {
  assert.deepEqual(purgeTargets({}), []);
  assert.deepEqual(purgeTargets({ repo: 'not-a-repo' }), []);
});

test('purgeTargets：显式文件列表覆盖默认，分支可换', () => {
  const t = purgeTargets({ repo: REPO, branch: 'next', files: ['json/x.json'] });
  assert.equal(t.length, 1);
  assert.match(t[0].url, /@next\/json\/x\.json$/);
});

test('purgeTargets：extra 里 jsDelivr 换主机名并保留 query，其它家一律标成无能为力', () => {
  const t = purgeTargets({
    repo: '',
    extra: ['https://cdn.jsdelivr.net/gh/o/r@main/json/modules.json?v=2', 'https://mirror.example.com/i.json', '不是 URL', '  '],
  });
  assert.equal(t.length, 3, '空串不该成为一个目标');
  assert.equal(t[0].purgeUrl, 'https://purge.jsdelivr.net/gh/o/r@main/json/modules.json?v=2');
  assert.equal(t[1].purgeUrl, '');
  assert.match(t[1].why, /mirror\.example\.com/);
  assert.equal(t[2].purgeUrl, '');
  assert.match(t[2].why, /不是合法 URL/);
});

test('purgeAll：finished 与 scheduled 都算发起成功', async () => {
  const targets = purgeTargets({ repo: REPO });
  const { impl, calls } = fakeFetch({
    [targets[0].purgeUrl]: { body: { status: 'finished' } },
    [targets[1].purgeUrl]: { body: { status: 'scheduled' } },
  });
  const { log } = silentLog();
  const r = await purgeAll(targets, { fetchImpl: impl, log });
  assert.equal(r.ok.length, 2);
  assert.equal(r.failed.length, 0);
  assert.equal(calls.length, 2);
  assert.ok(calls.every((c) => c.init.signal), '必须带超时，否则 CI 会挂在一次没有回音的 GET 上');
});

test('purgeAll：HTTP 不 2xx、status=error、应答不是 JSON、抛异常 —— 四种都算失败', async () => {
  const mk = (u) => [{ url: u, purgeUrl: u, how: 'jsdelivr' }];
  const cases = [
    { results: { 'https://p/1': { status: 500, body: { status: 'ok' } } } },
    { results: { 'https://p/2': { status: 200, body: { status: 'error' } } } },
    { results: { 'https://p/3': { status: 200, body: '<html>gateway</html>' } }, expectOk: true },
    { results: { 'https://p/4': { throw: 'socket hang up' } } },
  ];
  let i = 0;
  for (const c of cases) {
    i++;
    const url = `https://p/${i}`;
    const { impl } = fakeFetch(c.results);
    const { log } = silentLog();
    const r = await purgeAll(mk(url), { fetchImpl: impl, log });
    if (c.expectOk) {
      assert.equal(r.ok.length, 1, `${url} 应答不是 JSON 但 HTTP 200：按发起成功处理`);
    } else {
      assert.equal(r.failed.length, 1, `${url} 应该判失败`);
      assert.ok(r.failed[0].why, '失败要带原因');
    }
  }
});

test('purgeAll：无能为力的目标不发请求，只报出来', async () => {
  const { impl, calls } = fakeFetch({});
  const { log, lines } = silentLog();
  const r = await purgeAll([{ url: 'https://mirror/x.json', purgeUrl: '', how: 'unsupported', why: '没有通用端点' }], { fetchImpl: impl, log });
  assert.equal(calls.length, 0);
  assert.equal(r.unsupported.length, 1);
  assert.ok(lines.some((l) => l.includes('无法清除')), '必须在输出里看得见');
});

test('parseArgs：--file 可重复，--extra 逗号分隔，等号形式也认', () => {
  const o = parseArgs(['--repo', 'o/r', '--file', 'a.json', '--file=b.json', '--extra', 'x, y', '--dry-run']);
  assert.equal(o.repo, 'o/r');
  assert.deepEqual(o.file, ['a.json', 'b.json']);
  assert.deepEqual(o.extra, ['x', 'y']);
  assert.equal(o['dry-run'], true);
});

test('main：没有目标就红，而不是绿着什么都不做', async () => {
  const { impl, calls } = fakeFetch({});
  const { log } = silentLog();
  const rc = await main([], { log, fetchImpl: impl, env: {} });
  assert.equal(rc, 1);
  assert.equal(calls.length, 0);
});

test('main：dry-run 只列目标不请求', async () => {
  const { impl, calls } = fakeFetch({});
  const { log, lines } = silentLog();
  const rc = await main(['--repo', REPO, '--dry-run'], { log, fetchImpl: impl, env: {} });
  assert.equal(rc, 0);
  assert.equal(calls.length, 0);
  assert.ok(lines.some((l) => l.includes('purge.jsdelivr.net')));
});

test('main：清除失败 → 退出码 1，并给出重试办法', async () => {
  const targets = purgeTargets({ repo: REPO });
  const { impl } = fakeFetch(Object.fromEntries(targets.map((t) => [t.purgeUrl, { status: 503, body: { status: 'error' } }])));
  const { log, lines } = silentLog();
  const rc = await main(['--repo', REPO], { log, fetchImpl: impl, env: {} });
  assert.equal(rc, 1, 'CDN 还在发旧索引这件事必须看得见');
  assert.ok(lines.some((l) => l.includes('重试')), '红要带下一步怎么办');
});

test('main：成功路径 0，CDN_PURGE_URLS 里的其它家只警告不冻住流水线', async () => {
  const env = { CDN_PURGE_URLS: 'https://mirror.example.com/i.json' };
  const targets = purgeTargets({ repo: REPO, extra: [env.CDN_PURGE_URLS] });
  const { impl } = fakeFetch(Object.fromEntries(targets.filter((t) => t.purgeUrl).map((t) => [t.purgeUrl, { body: { status: 'finished' } }])));
  const { log, lines } = silentLog();
  const rc = await main([], { log, fetchImpl: impl, env: { ...env, GITHUB_REPOSITORY: REPO } });
  assert.equal(rc, 0, '清不动的镜像是运维的事，不该把已经完成的合并判成失败');
  assert.ok(lines.some((l) => l.includes('无能为力 1')));
});

test('main：目标默认从 GITHUB_REPOSITORY 来，不用在命令行上重复仓库名', async () => {
  const { impl, calls } = fakeFetch({});
  const { log } = silentLog();
  const rc = await main([], { log, fetchImpl: impl, env: { GITHUB_REPOSITORY: REPO } });
  assert.equal(rc, 0);
  assert.deepEqual(calls.map((c) => c.url), purgeTargets({ repo: REPO }).map((t) => t.purgeUrl));
});
