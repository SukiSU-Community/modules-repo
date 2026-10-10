/**
 * open-index-pr.mjs 的测试。
 *
 * 取改动集那部分是**真 git 仓库**跑的：这个脚本的判断全建立在
 * 「ref 里跟踪 / 工作树里存在」这类 git 事实上，用内存对象模拟等于什么都没测
 * （上一轮 scan.mjs 的入口判据就是靠真 spawn 才暴露的，见 audit/scan-cli.test.mjs）。
 *
 * 运行：node --test test/*.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  collectChanges,
  trackedPending,
  validatePayload,
  parseArgs,
  main,
  INDEX_FILE,
} from '../scripts/open-index-pr.mjs';

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}

/** 一个带索引与两个 pending 条目的最小仓库。 */
function repoFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oip-'));
  git(dir, ['init', '-q', '-b', 'main']);
  git(dir, ['config', 'user.email', 't@t']);
  git(dir, ['config', 'user.name', 't']);
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending', 'mod_a'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending', 'mod_b'), { recursive: true });
  fs.writeFileSync(path.join(dir, INDEX_FILE), '{"modules":[]}\n');
  fs.writeFileSync(path.join(dir, 'pending/mod_a/1.json'), '{"id":"mod_a"}\n');
  fs.writeFileSync(path.join(dir, 'pending/mod_b/1.json'), '{"id":"mod_b"}\n');
  // 模板与脏文件：都不该进改动集
  fs.mkdirSync(path.join(dir, 'pending/.keep'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'pending/.example.json'), '{}\n');
  git(dir, ['add', '-A']);
  git(dir, ['commit', '-q', '-m', 'base']);
  // 把模板从跟踪里摘掉，模拟真实仓库（. 开头是模板，不参与合并）
  git(dir, ['rm', '-q', '--cached', 'pending/.example.json']);
  git(dir, ['commit', '-q', '-m', 'untrack template']);
  return dir;
}

const goodFiles = () => [
  { path: INDEX_FILE, content: '{}' },
  { path: 'pending/mod_a/1.json', content: null },
];

/* ----------------------------------------------------------- 取改动集 */

test('trackedPending：只认 pending/<id>/<versionCode>.json', () => {
  const dir = repoFixture();
  assert.deepEqual(trackedPending(dir).sort(), ['pending/mod_a/1.json', 'pending/mod_b/1.json']);
});

test('消费一个条目 + 更新索引 → 一删一改', () => {
  const dir = repoFixture();
  fs.rmSync(path.join(dir, 'pending/mod_a/1.json'));
  fs.writeFileSync(path.join(dir, INDEX_FILE), '{"modules":[{"id":"mod_a"}]}\n');
  const c = collectChanges(dir);
  assert.deepEqual(c.deleted, ['pending/mod_a/1.json']);
  const paths = c.files.map((f) => f.path).sort();
  assert.deepEqual(paths, [INDEX_FILE, 'pending/mod_a/1.json']);
  assert.equal(c.files.find((f) => f.path === 'pending/mod_a/1.json').content, null, '删除必须是 null');
});

test('工作树里的未跟踪文件绝不进改动集', () => {
  const dir = repoFixture();
  fs.mkdirSync(path.join(dir, 'pending/mod_c'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'pending/mod_c/1.json'), '{"id":"没经过审核"}\n');
  fs.mkdirSync(path.join(dir, 'pending/mod_z'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'pending/mod_z/evil.json'), 'x');
  const c = collectChanges(dir);
  assert.deepEqual(c.files, [], '索引没动、条目没删 → 没有改动集');
});

test('盖章（改内容不删文件）也算修改', () => {
  const dir = repoFixture();
  fs.writeFileSync(path.join(dir, 'pending/mod_b/1.json'), '{"id":"mod_b","audit":{"status":"auto-approved"}}\n');
  const c = collectChanges(dir);
  assert.deepEqual(c.modified, ['pending/mod_b/1.json']);
  assert.deepEqual(c.deleted, []);
});

/* ----------------------------------------------------------- 载荷自检 */

test('validatePayload：合格形状过，四类跑偏各拒一条', () => {
  const ok = { base_sha: 'f'.repeat(40), branch: 'index/rebuild-1', files: goodFiles() };
  assert.equal(validatePayload(ok), '');
  assert.match(validatePayload({ ...ok, branch: 'main' }), /branch/);
  assert.match(validatePayload({ ...ok, branch: 'index/rebuild-../x' }), /branch/);
  assert.match(validatePayload({ ...ok, base_sha: 'nope' }), /base_sha/);
  assert.match(validatePayload({ ...ok, files: [{ path: INDEX_FILE, content: '{}' }] }), /pending/);
  assert.match(validatePayload({ ...ok, files: [{ path: 'pending/mod_a/1.json', content: null }] }), /json\/modules\.json/);
  assert.match(
    validatePayload({ ...ok, files: [{ path: 'scripts/build-index.mjs', content: 'x' }, { path: INDEX_FILE, content: '{}' }, { path: 'pending/mod_a/1.json', content: null }] }),
    /允许列表/
  );
  assert.match(validatePayload({ ...ok, files: [] }), /空的/);
});

test('parseArgs：--body 能吃掉带空格的整串，且不吞下一个 flag', () => {
  const o = parseArgs(['--worker', 'https://w', '--branch', 'index/rebuild-1', '--body', '两 个 词', '--dry-run']);
  assert.equal(o.body, '两 个 词');
  assert.equal(o['dryRun'], true);
  assert.equal(o.worker, 'https://w');
});

/* ----------------------------------------------------------- main 的边界 */

function fakeLog() {
  const out = [];
  const err = [];
  return { out, err, log: (...a) => out.push(a.join(' ')), error: (...a) => err.push(a.join(' ')) };
}

test('没有 token：一个请求都不发', async () => {
  let called = 0;
  const log = fakeLog();
  const rc = await main(['--worker', 'https://w', '--branch', 'index/rebuild-1', '--base-sha', 'f'.repeat(40), '--root', repoFixture()], {
    token: '',
    log,
    fetch: async () => { called++; return new Response('{}'); },
  });
  assert.equal(rc, 1);
  assert.equal(called, 0, '不带鉴权的写仓库请求不该发出去');
  assert.match(log.err.join('\n'), /REBUILD_TOKEN/);
});

test('worker 不是 https → 拒', async () => {
  const log = fakeLog();
  const rc = await main(['--worker', 'http://w', '--branch', 'index/rebuild-1', '--base-sha', 'f'.repeat(40), '--root', repoFixture()], {
    token: 't', log, fetch: async () => new Response('{}'),
  });
  assert.equal(rc, 1);
  assert.match(log.err.join('\n'), /https/);
});

test('happy path：带上 x-rebuild-token，路径拼的是 /rebuild-index', async () => {
  const dir = repoFixture();
  fs.rmSync(path.join(dir, 'pending/mod_a/1.json'));
  fs.writeFileSync(path.join(dir, INDEX_FILE), '{"modules":[{"id":"mod_a"}]}\n');
  const outFile = path.join(dir, 'pr-url.txt');
  const seen = [];
  const log = fakeLog();
  let pr = '';
  const rc = await main(['--worker', 'https://w.example/', '--branch', 'index/rebuild-9', '--base-sha', 'f'.repeat(40), '--root', dir, '--out-file', outFile], {
    token: 'tok123',
    log,
    onPr: (p) => { pr = p; },
    fetch: async (u, init) => {
      seen.push({ u: String(u), headers: init.headers, body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ ok: true, status: 'created', pr: 'https://github.com/o/r/pull/99' }), { status: 200 });
    },
  });
  assert.equal(rc, 0, log.out.join('\n') + log.err.join('\n'));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].u, 'https://w.example/rebuild-index');
  assert.equal(seen[0].headers['x-rebuild-token'], 'tok123');
  assert.equal(seen[0].body.title, 'chore(index): rebuild after merge [skip ci]', '默认标题就得带 [skip ci]');
  assert.equal(pr, 'https://github.com/o/r/pull/99');
  // workflow 下一步靠这个文件拿 PR 号
  assert.equal(fs.readFileSync(outFile, 'utf8').trim(), 'https://github.com/o/r/pull/99');
});

test('Worker 说不行 → 退出码 1，且把 status 带出来', async () => {
  const dir = repoFixture();
  fs.rmSync(path.join(dir, 'pending/mod_a/1.json'));
  fs.writeFileSync(path.join(dir, INDEX_FILE), '{}\n');
  const log = fakeLog();
  const rc = await main(['--worker', 'https://w', '--branch', 'index/rebuild-9', '--base-sha', 'f'.repeat(40), '--root', dir], {
    token: 't',
    log,
    fetch: async () => new Response(JSON.stringify({ ok: false, status: 'unauthorized', error: 'token 不对' }), { status: 200 }),
  });
  assert.equal(rc, 1);
  assert.match(log.err.join('\n'), /unauthorized/);
});

test('--dry-run 不发请求（用来在本地看改动集）', async () => {
  const dir = repoFixture();
  fs.rmSync(path.join(dir, 'pending/mod_a/1.json'));
  fs.writeFileSync(path.join(dir, INDEX_FILE), '{}\n');
  let called = 0;
  const log = fakeLog();
  const rc = await main(['--worker', 'https://w', '--branch', 'index/rebuild-9', '--base-sha', 'f'.repeat(40), '--root', dir, '--dry-run'], {
    token: 't',
    log,
    fetch: async () => { called++; return new Response('{}'); },
  });
  assert.equal(rc, 0);
  assert.equal(called, 0);
  assert.match(log.out.join('\n'), /dry-run/);
});
