// verify-index-pr.mjs 的单测 —— 这个脚本是「索引 PR」唯一的放行依据，
// 所以测试的重点不是它能放行什么，而是它挡住了哪几种伪造。
// 运行：node --test test/verify-index-pr.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

import {
  normalizeIndex, stableStringify, diffIndexes, judgeIndexPr, commitThatAdded, parseArgs,
} from '../scripts/verify-index-pr.mjs';
import { buildIndex, markApproved } from '../scripts/build-index.mjs';

const P = (id, vc = 1, over = {}) => ({
  id, name: id, author: 'a', description: 'd',
  versions: [{ version: `v${vc}`, versionCode: vc, time: 1791600000000 + vc, zipUrl: `https://github.com/o/r/releases/download/t/${'f'.repeat(64)}.zip`, size: 10, sha256: 'f'.repeat(64) }],
  ...over,
});

const okAttest = (p) => ({ ok: true, by: `ci:approve#o/rPR7@${'a'.repeat(12)}`, at: '2026-10-10T00:00:00Z', pr: 7, headSha: 'a'.repeat(40) });

/** 造一个「合法推导」现场：base 索引 + base pending + 按批准盖章后推导出的索引 */
function fixture(entries) {
  const baseIndex = { name: 'SukiSU-Ultra Modules', lastUpdate: 1, modules: [] };
  const baseEntries = entries.map((e, i) => ({ path: `pending/${e.id}-${i + 1}.json`, entry: e }));
  const { index } = buildIndex({ index: baseIndex, entries: baseEntries.map((b) => markApproved(b.entry, { by: 'x', at: 'y' })) });
  return { baseIndex, baseEntries, actualIndex: index, deletedPaths: baseEntries.map((b) => b.path) };
}

test('正常推导：消费掉已批准条目后，索引与推导一致 → 放行', () => {
  const f = fixture([P('mod_a'), P('mod_b')]);
  const v = judgeIndexPr({ ...f, touchedPaths: [], attest: okAttest });
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.consumed.length, 2);
});

test('伪造一：改了索引但一个 pending 都没消费 → 拒（这就是手改索引）', () => {
  const f = fixture([P('mod_a')]);
  const v = judgeIndexPr({ ...f, deletedPaths: [], touchedPaths: [], attest: okAttest });
  assert.equal(v.ok, false);
  assert.match(v.reason, /手改的/);
});

test('伪造二（最关键）：删掉一个从没批准的 pending 再把条目抄进索引 → 拒', () => {
  const f = fixture([P('mod_a')]);
  // 攻击者的索引内容完全正确，缺的只是证据。放行判据必须是外部证据，不是内容像不像。
  const v = judgeIndexPr({
    ...f,
    attest: () => ({ ok: false, reason: 'PR #9 上 approve 的结论是 failure（引入提交 deadbeef）' }),
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /拿不到批准证据/);
  assert.match(v.reason, /正是要挡的路径/);
});

test('伪造三：夹带新投稿的「索引 PR」→ 拒，交回投稿扫描判定', () => {
  const f = fixture([P('mod_a')]);
  const v = judgeIndexPr({ ...f, touchedPaths: ['pending/mod_new-1.json'], attest: okAttest });
  assert.equal(v.ok, false);
  assert.match(v.reason, /不是纯索引重建/);
});

test('伪造四：删掉 base 上不存在的文件（凭空消费）→ 拒', () => {
  const f = fixture([P('mod_a')]);
  const v = judgeIndexPr({ ...f, deletedPaths: [...f.deletedPaths, 'pending/ghost-1.json'], attest: okAttest });
  assert.equal(v.ok, false);
  assert.match(v.reason, /在 base 上不存在/);
});

test('伪造五：内容像但字段被动过（verified / 少一个版本）→ 逐字段差异报出来', () => {
  const f = fixture([P('mod_a')]);
  const tampered = JSON.parse(stableStringify(f.actualIndex));
  tampered.modules[0].verified = true;
  const v = judgeIndexPr({ ...f, actualIndex: tampered, attest: okAttest });
  assert.equal(v.ok, false);
  assert.ok(v.diffs && v.diffs.length, '必须给出差异，而不是只说不相等');
  assert.match(v.diffs.join('\n'), /mod_a 内容不同/);

  const dropped = JSON.parse(stableStringify(f.actualIndex));
  dropped.modules[0].versions = [];
  assert.match(diffIndexes(f.actualIndex, dropped).join('\n'), /mod_a 内容不同/);

  const missing = JSON.parse(stableStringify(f.actualIndex));
  missing.modules = [];
  assert.match(diffIndexes(f.actualIndex, missing).join('\n'), /PR 里缺模块 mod_a/);

  const extra = JSON.parse(stableStringify(f.actualIndex));
  extra.modules.push({ ...P('mod_ghost'), id: 'mod_ghost' });
  assert.match(diffIndexes(f.actualIndex, extra).join('\n'), /PR 里多出模块 mod_ghost/);
});

test('时间戳与顺序不算差异：lastUpdate 与模块顺序变化仍判一致', () => {
  const f = fixture([P('mod_a'), P('mod_b')]);
  const moved = JSON.parse(stableStringify(f.actualIndex));
  moved.lastUpdate = 999999;
  moved.modules.reverse();
  moved.modules.forEach((m) => { m.versions = [...m.versions]; });
  assert.deepEqual(diffIndexes(f.actualIndex, moved), []);
  assert.equal(judgeIndexPr({ ...f, actualIndex: moved, attest: okAttest }).ok, true);
});

test('normalizeIndex 对空/畸形输入不抛，且 modules 一定是数组', () => {
  assert.deepEqual(normalizeIndex(null), { name: null, modules: [] });
  assert.deepEqual(normalizeIndex({}), { name: null, modules: [] });
  assert.equal(normalizeIndex({ modules: 'x' }).modules.length, 0);
});

test('stableStringify 与键顺序无关', () => {
  assert.equal(stableStringify({ a: 1, b: [1, { x: 1, y: 2 }] }), stableStringify({ b: [1, { y: 2, x: 1 }], a: 1 }));
});

test('parseArgs：--report 与 --base 都能取到，裸 flag 记 true', () => {
  const o = parseArgs(['--base', 'origin/main', '--dry-run', '--owner', 'o']);
  assert.equal(o.base, 'origin/main');
  assert.equal(o.owner, 'o');
  assert.equal(o['dry-run'], true);
});

test('main：缺 token 时拒绝判定，而不是退化成「只看内容一致」', async () => {
  const saved = process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TOKEN;
  const out = [];
  try {
    const rc = await import('../scripts/verify-index-pr.mjs').then((m) =>
      m.main(['--base', 'HEAD', '--owner', 'o', '--repo', 'r'], { log: { log: (...a) => out.push(a.join(' ')), error: (...a) => out.push('! ' + a.join(' ')) }, token: '' }));
    assert.equal(rc, 1);
    assert.match(out.join('\n'), /没有 GITHUB_TOKEN/);
  } finally { if (saved !== undefined) process.env.GITHUB_TOKEN = saved; }
});

/* ---------------------------------------------------------------- 真 git 仓库 */
// 上面全是纯函数测试。这一组故意建一个真 git 仓库、真跑 build-index.mjs，
// 因为 base/head 的 ls-tree、log -1 -- path、diff-filter 这些行为靠读代码猜最容易出现
// 「单测全绿但 CI 里永远判不过」。
const G = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });

function gitFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vip-git-'));
  G(dir, 'init', '-q', '-b', 'main');
  G(dir, 'config', 'user.name', 't');
  G(dir, 'config', 'user.email', 't@example.invalid');
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending', 'mod_a'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'json', 'modules.json'),
    JSON.stringify({ name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] }, null, 2) + '\n');
  // base 上的 pending 是**没盖过章**的：章只在索引 runner 的工作树里存在
  fs.writeFileSync(path.join(dir, 'pending', 'mod_a', '1.json'),
    JSON.stringify(P('mod_a'), null, 2) + '\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '投稿：mod_a 落到 main');
  return dir;
}

/** 复刻 index.yml 干的事：盖章 -> build-index --consume -> 提交到 PR 分支 */
function makeIndexPr(dir, { tamper = null } = {}) {
  const f = path.join(dir, 'pending', 'mod_a', '1.json');
  fs.writeFileSync(f, JSON.stringify(markApproved(JSON.parse(fs.readFileSync(f, 'utf8')), { by: 'x', at: 'y' }), null, 2) + '\n');
  const scripts = path.resolve(import.meta.dirname, '../scripts');
  execFileSync(process.execPath, [path.join(scripts, 'build-index.mjs'),
    '--pending', 'pending', '--index', 'json/modules.json', '--consume'], { cwd: dir, encoding: 'utf8' });
  if (tamper) tamper(path.join(dir, 'json', 'modules.json'));
  G(dir, 'checkout', '-qb', 'index/rebuild-1');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(index): rebuild after merge [skip ci]');
}

const quiet = () => {
  const out = [];
  const err = [];
  return { out, err, log: (...a) => out.push(a.join(' ')), error: (...a) => err.push('! ' + a.join(' ')) };
};
const allLogs = (l) => l.out.concat(l.err).join('\n');
const V = async () => import('../scripts/verify-index-pr.mjs');

test('真仓库：机器人按流程生成的索引 PR，判定为一致 → 退出 0', async () => {
  const dir = gitFixture();
  makeIndexPr(dir);
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir],
    { log, token: 't', attest: () => ({ ok: true, by: 'ci:approve#o/rPR7@aaaaaaaaaaaa', pr: 7, headSha: 'a'.repeat(40) }) });
  assert.equal(rc, 0, allLogs(log));
  assert.match(log.out.join('\n'), /索引与推导一致/);
});

test('真仓库：手改一个字段就判不一致 → 退出 1', async () => {
  const dir = gitFixture();
  makeIndexPr(dir, {
    tamper: (p) => {
      const j = JSON.parse(fs.readFileSync(p, 'utf8'));
      j.modules[0].verified = true;              // 看着完全合理的「顺手改一下」
      fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
    },
  });
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir],
    { log, token: 't', attest: () => ({ ok: true, pr: 7, headSha: 'a'.repeat(40) }) });
  assert.equal(rc, 1);
  assert.match(allLogs(log), /与推导结果不一致/);
});

test('真仓库：拿不到批准证据就不认（删掉条目再抄进索引这条路被封死）→ 退出 1', async () => {
  const dir = gitFixture();
  makeIndexPr(dir);
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir],
    { log, token: 't', attest: () => ({ ok: false, reason: 'PR #9 上 approve 的结论是 failure' }) });
  assert.equal(rc, 1);
  assert.match(allLogs(log), /拿不到批准证据/);
});

test('真仓库：只改索引不消费任何 pending → 退出 1（这就是纯手改）', async () => {
  const dir = gitFixture();
  G(dir, 'checkout', '-qb', 'index/hand-edit');
  const p = path.join(dir, 'json', 'modules.json');
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  j.modules = [{ ...P('mod_ghost'), id: 'mod_ghost' }].map((m) => ({ ...m, verified: false }));
  fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '手抄一个模块进索引');
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir],
    { log, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc, 1);
  assert.match(allLogs(log), /一个 pending 都没消费|手改的/);
});

test('真仓库：--report 里留下可复核的证据指针', async () => {
  const dir = gitFixture();
  makeIndexPr(dir);
  const report = path.join(dir, 'report.json');
  const log = quiet();
  const m = await V();
  await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir, '--report', report],
    { log, token: 't', attest: () => ({ ok: true, pr: 7, headSha: 'a'.repeat(40), commitSha: 'b'.repeat(40) }) });
  const r = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.equal(r.ok, true);
  assert.deepEqual(r.consumed, ['pending/mod_a/1.json']);
  assert.equal(r.evidences[0].pr, 7);
});
