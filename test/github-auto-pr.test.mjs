// github.mjs 与 auto-pr.mjs 的纯函数测试。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseRepoUrl,
  repoApiUrl,
  rawFileUrl,
  githubHeaders,
} from '../scripts/lib/github.mjs';
import { checkAutoPrFiles, postAutoPr, AUTO_PR_STATE_PATH } from '../scripts/lib/auto-pr.mjs';

test('parseRepoUrl：接受归一化前的常见写法', () => {
  for (const [input, url] of [
    ['https://github.com/owner/repo', 'https://github.com/owner/repo'],
    ['https://github.com/owner/repo/', 'https://github.com/owner/repo'],
    ['https://github.com/owner/repo.git', 'https://github.com/owner/repo'],
    ['https://GitHub.com/owner/repo', 'https://github.com/owner/repo'],
  ]) {
    const r = parseRepoUrl(input);
    assert.equal(r.ok, true, `${input} 应当合法`);
    assert.equal(r.url, url);
  }
});

test('parseRepoUrl：拒绝其它主机、非 https、query、端口、凭据、多段路径', () => {
  for (const input of [
    'https://gitlab.com/owner/repo',
    'http://github.com/owner/repo',
    'https://github.com/owner/repo?x=1',
    'https://github.com/owner/repo#readme',
    'https://github.com:8443/owner/repo',
    'https://user:pass@github.com/owner/repo',
    'https://github.com/owner/repo/tree/main',
    'ftp://github.com/owner/repo',
    '',
  ]) {
    assert.equal(parseRepoUrl(input).ok, false, `${input} 应当被拒`);
  }
});

test('repoApiUrl / rawFileUrl：路径逐段编码', () => {
  assert.equal(repoApiUrl('a b', 'c'), 'https://api.github.com/repos/a%20b/c');
  assert.equal(rawFileUrl('o', 'r', 'feat/x', 'checksums.txt'),
    'https://raw.githubusercontent.com/o/r/feat/x/checksums.txt');
});

test('githubHeaders：没有 token 时不带 Authorization', () => {
  assert.equal(githubHeaders('').authorization, undefined);
  assert.equal(githubHeaders('t').authorization, 'Bearer t');
  assert.equal(githubHeaders('t', { accept: 'text/plain' }).accept, 'text/plain');
});

function pending(id, versionCode) {
  return JSON.stringify({
    id,
    name: 'n',
    author: 'a',
    description: 'd',
    versions: [{ version: 'v', versionCode, zipUrl: 'https://github.com/x/y.zip', size: 1, time: 't', sha256: '0'.repeat(64) }],
  });
}

test('checkAutoPrFiles：合法文件通过', () => {
  assert.deepEqual(checkAutoPrFiles([
    { path: 'pending/demo/5.json', content: pending('demo', 5) },
    { path: AUTO_PR_STATE_PATH, content: '{"checkedAt":1,"modules":{}}' },
  ]), []);
});

test('checkAutoPrFiles：路径、id、versionCode、大小与数量都查', () => {
  const cases = [
    [[], /非空/],
    [[{ path: 'json/modules.json', content: '{}' }], /不允许的路径/],
    [[{ path: 'pending/demo/5.json', content: pending('other', 5) }], /id 与路径不一致/],
    [[{ path: 'pending/demo/5.json', content: pending('demo', 6) }], /versionCode 与路径不一致/],
    [[{ path: 'pending/demo/5.json', content: 'not json' }], /不是合法 JSON/],
    [[{ path: AUTO_PR_STATE_PATH, content: '[]' }], /JSON 对象/],
    [[{ path: 'pending/demo/0.json', content: pending('demo', 0) }], /不允许的路径/],
    [Array.from({ length: 22 }, (_, i) => ({ path: `pending/m${i}/1.json`, content: pending(`m${i}`, 1) })), /超过 21 个上限/],
    [[{ path: 'pending/demo/5.json', content: 'x'.repeat(512 * 1024 + 1) }], /超过 524288 字节上限/],
  ];
  for (const [files, re] of cases) {
    const problems = checkAutoPrFiles(files);
    assert.ok(problems.some((p) => re.test(p)), `应当命中 ${re}，实际 ${JSON.stringify(problems)}`);
  }
});

test('postAutoPr：成功时返回 prUrl，失败时抛', async () => {
  let seen = null;
  const okHttp = {
    async postJson(url, body, opts) {
      seen = { url, body, opts };
      return { status: 200, json: { ok: true, prUrl: 'https://github.com/o/r/pull/1', branch: 'auto/x' }, body: Buffer.alloc(0) };
    },
  };
  const files = [{ path: 'pending/demo/5.json', content: pending('demo', 5) }];
  const res = await postAutoPr({
    http: okHttp, workerBase: 'https://w.example/', autoKey: 'k', title: 't', body: 'b', files,
  });
  assert.equal(res.prUrl, 'https://github.com/o/r/pull/1');
  assert.equal(seen.url, 'https://w.example/auto/pr');
  assert.equal(seen.opts.headers['x-auto-key'], 'k');
  assert.equal(seen.body.files.length, 1);

  await assert.rejects(
    postAutoPr({
      http: { async postJson() { return { status: 400, json: { error: 'bad' }, body: Buffer.from('bad') }; } },
      workerBase: 'https://w.example', autoKey: 'k', title: 't', body: 'b', files,
    }),
    /400/,
  );
  await assert.rejects(
    postAutoPr({ http: okHttp, workerBase: '', autoKey: 'k', title: 't', body: 'b', files }),
    /WORKER_BASE/,
  );
  await assert.rejects(
    postAutoPr({ http: okHttp, workerBase: 'https://w', autoKey: '', title: 't', body: 'b', files }),
    /AUTO_PR_KEY/,
  );
});
