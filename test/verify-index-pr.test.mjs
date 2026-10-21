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
  ledgerTouched, parseSeal, judgeLedgerSeal, ledgerSealEvidence, isEvidencePath,
  dispositionSubstance, parseReviews, readReviews,
} from '../scripts/verify-index-pr.mjs';
import { buildIndex, markApproved } from '../scripts/build-index.mjs';
import { parseDispositions } from '../scripts/dispositions.mjs';
import { SEAL_PENDING_BY } from '../scripts/revoke.mjs';

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

/* ------------------------------------------------------- P3：台账参与重推导 */

const revokeOf = (id, by = 'gh:t@1') => ({
  schema: 'sukisu-dispositions-v1',
  dispositions: [{ kind: 'revoke', id, reason: 'test-probe', by, at: '2026-10-11T00:00:00Z' }],
});

const SEAL_OK = {
  ok: true, reason: '测试注入的合格机器章',
  sealed: [{ sha: 'a'.repeat(40), summary: '逐字定位到 3 处 + AI 复核成立' }],
  touched: { added: [{ id: 'mod_a' }], changed: [], removed: [], any: true },
};

test('P3 判定：台账驱动型重建（没消费 pending）→ 一致且章齐才放行', () => {
  const base = { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [{ id: 'mod_a', versions: [] }] };
  const v = judgeIndexPr({
    baseIndex: base,
    actualIndex: { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
    seal: SEAL_OK,
  });
  assert.equal(v.ok, true, v.reason);
  assert.match(v.reason, /台账驱动/);
  // 结论里要看得见章钉在哪一枚提交上 —— 「推导一致」四个字不能把凭据这一格糊过去
  assert.match(v.reason, new RegExp(`机器章 1 枚，指向 ${'a'.repeat(12)}`));
});

// 这一条是 2026-10-17 那四格复现的正主：索引与推导**完全一致**（攻击者自己就能算出来），
// 缺的只是处置的凭据。缺证据必须是红，且要说清缺的是哪一半。
test('台账驱动那一支：索引算得对但没有机器章的证据 → 红（一致不等于被复核过）', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [{ id: 'mod_a', versions: [] }] };
  const v = judgeIndexPr({
    baseIndex: base,
    actualIndex: { name: 'x', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
    // 没有 seal 这个入参 —— 等价于调用方没给 --reviews，取证无从开始
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /没拿到机器章的证据/);
  assert.match(v.reason, /不按「没有台账」处理/);

  const v2 = judgeIndexPr({
    baseIndex: base,
    actualIndex: { name: 'x', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
    seal: { ok: false, reason: 'mod_x 的章指向 abcdef012345，那一枚 commit 不在这条 PR 上', sealed: [] },
  });
  assert.equal(v2.ok, false);
  assert.match(v2.reason, /那一枚 commit 不在这条 PR 上/);
});


test('P3 判定：改了台账但索引没按台账重算 → 判不一致（台账不是免检通行证）', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [{ id: 'mod_a', name: 'A', author: 'a', description: 'd', versions: [{ versionCode: 1, sha256: '1'.repeat(64) }] }] };
  const v = judgeIndexPr({
    baseIndex: base,
    actualIndex: base,                     // 索引原封不动，只是塞了台账
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /与推导结果不一致/);
});

test('P3 判定：既没消费 pending 也没改台账 → 还是「手改索引」', () => {
  const v = judgeIndexPr({
    baseIndex: { name: 'x', modules: [] }, actualIndex: { name: 'x', modules: [] },
    deletedPaths: [], touchedPaths: [], ledgerChanged: false, dispositions: [], attest: () => ({ ok: true }),
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /既没消费 pending、也没改处置台账/);
});

test('P3 判定：消费投稿 + 同时改台账 → 拒，一个 PR 只做一个决定', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [] };
  const v = judgeIndexPr({
    baseIndex: base,
    baseEntries: [{ path: 'pending/mod_a/1.json', entry: { id: 'mod_a' } }],
    actualIndex: base,
    deletedPaths: ['pending/mod_a/1.json'], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('other')), ledgerChanged: true,
    attest: () => ({ ok: true, by: 'ci:approve#o/rPR7@aaaaaaaaaaaa', pr: 7, headSha: 'a'.repeat(40) }),
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /请拆成两条/);
});

test('P3 判定：索引忠实推导但顺手改了扫描脚本 → 挡（这条封的是自动合并的夹带路径）', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [] };
  const v = judgeIndexPr({
    baseIndex: base,
    baseEntries: [{ path: 'pending/mod_a/1.json', entry: { id: 'mod_a' } }],
    actualIndex: base,
    deletedPaths: ['pending/mod_a/1.json'], touchedPaths: [],
    changedPaths: ['json/modules.json', 'pending/mod_a/1.json', 'audit/scan.mjs'],
    dispositions: [], ledgerChanged: false,
    attest: () => ({ ok: true, by: 'ci:approve#o/rPR7@aaaaaaaaaaaa', pr: 7, headSha: 'a'.repeat(40) }),
  });
  assert.equal(v.ok, false, '推导比得上也不许夹带代码改动');
  assert.match(v.reason, /audit\/scan\.mjs/);
});

test('P3 判定：白名单内的路径照常通过（pending 删除 + 索引 + 台账）', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [] };
  const v = judgeIndexPr({
    baseIndex: base,
    baseEntries: [{ path: 'pending/mod_a/1.json', entry: { id: 'mod_a' } }],
    actualIndex: base,
    deletedPaths: ['pending/mod_a/1.json'], touchedPaths: [],
    changedPaths: ['json/modules.json', 'pending/mod_a/1.json'],
    dispositions: [], ledgerChanged: false,
    attest: () => ({ ok: true, by: 'ci:approve#o/rPR7@aaaaaaaaaaaa', pr: 7, headSha: 'a'.repeat(40) }),
  });
  assert.equal(v.ok, true, v.reason);
});

// 真 git：base 上索引里已经有 mod_a，PR 只加台账并重算索引
function ledgerFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vip-ledger-'));
  G(dir, 'init', '-q', '-b', 'main');
  G(dir, 'config', 'user.name', 't');
  G(dir, 'config', 'user.email', 't@example.invalid');
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending'), { recursive: true });
  const seeded = buildIndex({ index: { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] }, entries: [P('mod_a')] }).index;
  fs.writeFileSync(path.join(dir, 'json', 'modules.json'), JSON.stringify(seeded, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'pending', '.example.json'), '[]\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'base：索引里有 mod_a');
  return dir;
}

/**
 * 真 git 走一遍**两枚提交**的盖章流程，返回 { dir, c1 }。
 *
 * C1 = 处置实体 + `by: ci:audit@pending`；C2 = 只把待盖值换成 `ci:audit@<C1>`。
 * `at` 两边写死同一个值：判定比的是实体投影（不含 by/at），真流程里 C2 也不该动时间。
 * 这一步不注任何东西 —— 它同时是 ledgerSealEvidence 真跑 `git rev-list` 与 `git show` 的证人。
 */
function makeSealedRevokePr(dir, id = 'mod_a', at = '2026-10-11T00:00:00.000Z') {
  const write = (by) => fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v1', dispositions: [{ kind: 'revoke', id, reason: 'test-probe', by, at }] }, null, 2) + '\n');
  const rebuild = () => {
    const scripts = path.resolve(import.meta.dirname, '../scripts');
    execFileSync(process.execPath, [path.join(scripts, 'build-index.mjs'),
      '--pending', 'pending', '--index', 'json/modules.json',
      '--dispositions', 'json/dispositions.json'], { cwd: dir, encoding: 'utf8' });
  };
  G(dir, 'checkout', '-qb', 'revoke/mod_a');
  write(SEAL_PENDING_BY);
  rebuild();
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(dispose): revoke mod_a（实体，待盖章）');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  write(`ci:audit@${c1}`);
  rebuild();
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(dispose): 盖上机器章');
  return { c1 };
}

/** 复核结论文件：judgeLedgerSeal 的第 ④ 条读的就是它。 */
function reviewsFile(dir, sha, ok = true) {
  const f = path.join(dir, 'reviews.json');
  fs.writeFileSync(f, JSON.stringify({ [sha]: { ok, summary: ok ? '逐字定位到 install.sh 里那 3 处' : '包里没有引用的字节' } }, null, 2) + '\n');
  return f;
}

test('P3 真仓库：两枚提交 + 复核结论齐 ⇒ 退出 0；缺结论与章指别处都是红', async () => {
  const m = await V();

  // ① 没给 --reviews —— 复核这一步没跑，必须红（而不是「这条 PR 没动台账」）
  const d1 = ledgerFixture();
  makeSealedRevokePr(d1);
  const log1 = quiet();
  const rc1 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d1],
    { log: log1, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc1, 1, allLogs(log1));
  assert.match(allLogs(log1), /没拿到机器章的证据|一个复核结论都没有/);

  // ② 结论文件说这一枚不成立 → 红，且红在第 ④ 条那一句
  const d2 = ledgerFixture();
  const r2 = makeSealedRevokePr(d2);
  const log2 = quiet();
  const rc2 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d2,
    '--reviews', reviewsFile(d2, r2.c1, false)], { log: log2, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc2, 1, allLogs(log2));
  assert.match(allLogs(log2), /复核结论不成立/);

  // ③ 三样齐 → 绿，且 report.seal 留下可复核的指针（哪一枚 commit 的章）
  const d3 = ledgerFixture();
  const r3 = makeSealedRevokePr(d3);
  const report = path.join(d3, 'r.json');
  const log3 = quiet();
  const rc3 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d3,
    '--reviews', reviewsFile(d3, r3.c1), '--report', report], { log: log3, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc3, 0, allLogs(log3));
  assert.match(allLogs(log3), /台账驱动/);
  const r = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.equal(r.seal.ok, true, 'report 里要看得见机器章的结论');
  assert.deepEqual(r.seal.sealed.map((s) => s.sha), [r3.c1], '章钉在哪一枚提交上必须写进 report');
  assert.deepEqual(r.seal.touched, { added: 1, changed: 0, removed: 0 });
  fs.rmSync(d1, { recursive: true, force: true });
  fs.rmSync(d2, { recursive: true, force: true });
  fs.rmSync(d3, { recursive: true, force: true });
});

test('P3 真仓库：章指向一枚不在这条 PR 上的提交 → 红（借别人的绿不成）', async () => {
  const dir = ledgerFixture();
  // 在 main 上另造一枚提交，拿它的 sha 当章 —— 它在 base 那一侧，rev-list base..head 列不出它
  const c1 = G(dir, 'rev-parse', 'main').trim();
  G(dir, 'checkout', '-qb', 'revoke/fake');
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v1', dispositions: [{ kind: 'revoke', id: 'mod_a', reason: 'test-probe', by: `ci:audit@${c1}`, at: '2026-10-11T00:00:00.000Z' }] }, null, 2) + '\n');
  const scripts = path.resolve(import.meta.dirname, '../scripts');
  execFileSync(process.execPath, [path.join(scripts, 'build-index.mjs'),
    '--pending', 'pending', '--index', 'json/modules.json', '--dispositions', 'json/dispositions.json'], { cwd: dir, encoding: 'utf8' });
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(dispose): 借 main 上那枚绿提交当章');
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir,
    '--reviews', reviewsFile(dir, c1)], { log, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc, 1, allLogs(log));
  assert.match(allLogs(log), /不在这条 PR 上/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('P3 真仓库：台账坏了 → 停住，不当「没有台账」把下架全放回', async () => {
  const dir = ledgerFixture();
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), '{ 坏掉的台账');
  G(dir, 'checkout', '-qb', 'revoke/bad');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(dispose): 坏台账');
  const log = quiet();
  const m = await V();
  const rc = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir],
    { log, token: 't', attest: () => ({ ok: true }) });
  assert.equal(rc, 1);
  assert.match(allLogs(log), /读不懂|不合格/);
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ------------------------------------------------------- P4：处置台账的机器章（by = ci:audit@<commit>） */

// 夹具用两个不同的 40 位十六进制 sha 当章；它们不代表任何真实提交。
const SEAL1 = 'a'.repeat(40);
const SEAL2 = 'b'.repeat(40);
const BY1 = `ci:audit@${SEAL1}`;
const BY2 = `ci:audit@${SEAL2}`;
const D = (over = {}) => ({
  kind: 'revoke', reason: 'malware', by: BY1, at: '2026-10-17T00:00:00.000Z', note: '', id: 'mod_x', ...over,
});
const HEAD2 = (over = {}) => ({
  kind: 'revoke', reason: 'malware', by: BY2, at: '2026-10-17T00:00:00.000Z', note: '', id: 'mod_y', ...over,
});
/** 章指向的那枚提交上「实体已在等着盖章」的那一份台账（judgeLedgerSeal 的第 ③ 条读它）。 */
const pendingOf = (over = {}) => ({ ...D(over), by: SEAL_PENDING_BY });
const OK_REVIEW = { [SEAL1]: { ok: true }, [SEAL2]: { ok: true } };

test('ledgerTouched：加 / 改 / 删三个方向都数得到，而只动 lastUpdate 不算实质改动', () => {
  const base = [D(), HEAD2()];
  const t0 = ledgerTouched(base, base);
  assert.equal(t0.any, false, '同一份台账不该报「动过」');

  // 只换章指向的提交 —— 选择器没变，但凭据换了：必须数成 changed
  const t1 = ledgerTouched(base, [D({ by: BY2 }), HEAD2()]);
  assert.deepEqual({ a: t1.added.length, c: t1.changed.length, r: t1.removed.length }, { a: 0, c: 1, r: 0 });
  assert.equal(t1.changed[0].from.by, BY1, 'changed 要留着改前那一份，否则「换了哪一枚章」看不出来');

  // 删掉一条 = 把人从黑名单里放出来（#35 当初就是为这一格把台账挪出机器路由）
  const t2 = ledgerTouched(base, [D()]);
  assert.deepEqual({ a: t2.added.length, c: t2.changed.length, r: t2.removed.length }, { a: 0, c: 0, r: 1 });

  const t3 = ledgerTouched([], [D()]);
  assert.deepEqual({ a: t3.added.length, r: t3.removed.length }, { a: 1, r: 0 });

  // 元数据（lastUpdate 在 parseDispositions 之后根本不留）不该被当成一次处置改动
  const t4 = ledgerTouched(parseDispositions({ schema: 'sukisu-dispositions-v1', lastUpdate: 1, dispositions: [D()] }),
    parseDispositions({ schema: 'sukisu-dispositions-v1', lastUpdate: 999, dispositions: [D()] }));
  assert.equal(t4.any, false, 'parseDispositions 的投影里没有 lastUpdate 的位置 —— 这一条是「不算实质改动」的机制，不是巧合');
});

test('parseSeal：只吃机器章与待盖值，其余形状一律 null（revoke.mjs 那一条正则复用，不另拼一份）', () => {
  assert.deepEqual(parseSeal(BY1), { pending: false, sha: SEAL1, text: BY1 });
  assert.deepEqual(parseSeal(SEAL_PENDING_BY), { pending: true, sha: '', text: SEAL_PENDING_BY });
  for (const bad of [
    'https://github.com/o/r/issues/40#issuecomment-1111111111',  // 上一版的评论 URL：人已退场
    'gh:member-one@issuecomment-1',                              // 再上一版：连 URL 都拼不出
    `ci:audit@${'a'.repeat(39)}`,                                // 短一位
    `ci:audit@${'a'.repeat(41)}`,                                // 长一位
    `ci:audit@${'g'.repeat(40)}`,                                // 不是十六进制
    `ci:audit@${'A'.repeat(40)}`,                                // 大写：git 的 sha 一律小写
    'ci:audit@head', 'ci:audit@', 'ci:audit', 'audit@' + SEAL1,
    'ci:audit@' + SEAL1 + ' 我也同意',                            // 尾巴上有字
    '',
  ]) {
    assert.equal(parseSeal(bad), null, `${JSON.stringify(bad)} 不该被当成一枚章`);
  }
});

test('dispositionSubstance：投影去掉 by / at，其余键一个都不许丢（换了实体就不算同一条决定）', () => {
  const d = D({ note: '命中两条规则', verify: 'gh api repos/o/r/commits/x/check-runs' });
  const s = dispositionSubstance(d);
  assert.equal(s.by, undefined, 'by 是章，不属于实体');
  assert.equal(s.at, undefined, 'at 是落笔时间，重写一遍就变，不能进比较');
  assert.equal(s.kind, 'revoke');
  assert.equal(s.reason, 'malware');
  assert.equal(s.id, 'mod_x');
  assert.equal(s.note, '命中两条规则', 'note 是公示页要念的话，改它=改决定，必须在投影里');
  assert.equal(s.verify, 'gh api repos/o/r/commits/x/check-runs');
  // 投影键集合是「除 by/at 之外全部键」—— 加一个新字段时它自动进比较，这里钉住这个性质：
  assert.deepEqual(Object.keys(dispositionSubstance({ ...d, brandNew: 1 })).sort(),
    [...Object.keys(s), 'brandNew'].sort());
});

test('judgeLedgerSeal：四条判据缺一即红 —— 形状、在本 PR 上、实体已在、复核成立', () => {
  const added = [D(), HEAD2()];
  const touched = { added, changed: [], removed: [], any: true };
  const ledgerAt = {
    [SEAL1]: [pendingOf()],                       // 这一枚提交上只有 mod_x 的实体在等着盖章
    [SEAL2]: [pendingOf({ id: 'mod_y' })],        // 这一枚上只有 mod_y 的
  };

  const good = judgeLedgerSeal({ touched, prCommits: [SEAL1, SEAL2], ledgerAt, reviews: OK_REVIEW });
  assert.equal(good.ok, true, good.reason);
  assert.deepEqual(good.sealed.map((s) => s.sha).sort(), [SEAL1, SEAL2], '结论里要留每枚章钉在哪');

  // ① 形状不对
  const shape = judgeLedgerSeal({
    touched: { added: [D({ by: 'https://github.com/o/r/issues/9#issuecomment-9' })], changed: [], removed: [], any: true },
    prCommits: [SEAL1], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(shape.ok, false);
  assert.match(shape.reason, /mod_x 的 by 不是机器章/);

  // ①b 待盖值不算章（C1 那一枚提交自己不该被当成已盖章）
  const unsealed = judgeLedgerSeal({
    touched: { added: [D({ by: SEAL_PENDING_BY })], changed: [], removed: [], any: true },
    prCommits: [SEAL1], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(unsealed.ok, false);
  assert.match(unsealed.reason, /还挂着待盖值/);

  // ② 章指向一枚不在本 PR 上的提交（借别人的绿）
  const elsewhere = judgeLedgerSeal({
    touched, prCommits: [SEAL2], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(elsewhere.ok, false);
  assert.match(elsewhere.reason, /mod_x 的章指向 [0-9a-f]{12}，那一枚 commit 不在这条 PR 上/);

  // ②b 那一枚提交上的台账读不出来 ⇒ 判红，不能静默当「那上面没有实体」
  const unreadable = judgeLedgerSeal({
    touched, prCommits: [SEAL1, SEAL2],
    ledgerAt: { [SEAL1]: null, [SEAL2]: ledgerAt[SEAL2] }, reviews: OK_REVIEW,
  });
  assert.equal(unreadable.ok, false);
  assert.match(unreadable.reason, /那一枚提交上的台账读不出来/);

  // ③ 那一枚提交上还没有这条处置的实体（章是后补到一条新决定上的）
  const noEntity = judgeLedgerSeal({
    touched, prCommits: [SEAL1, SEAL2],
    ledgerAt: { [SEAL1]: [], [SEAL2]: [] }, reviews: OK_REVIEW,
  });
  assert.equal(noEntity.ok, false);
  assert.match(noEntity.reason, /而那条提交上还没有这条处置的实体/);

  // ③b 实体与那枚提交上的不一致（补章顺手改了理由 —— 复核的不是这一条）
  const drifted = judgeLedgerSeal({
    touched: { added: [D({ reason: 'copyright' }), HEAD2()], changed: [], removed: [], any: true },
    prCommits: [SEAL1, SEAL2], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(drifted.ok, false);
  assert.match(drifted.reason, /实体与章指向的那条提交上的不一致/);

  // ③c 那一枚提交上的 by 不是待盖值（说明它早就被别的东西盖过，不能二次引用）
  const doubleSealed = judgeLedgerSeal({
    touched, prCommits: [SEAL1, SEAL2],
    ledgerAt: { [SEAL1]: [D()], [SEAL2]: [HEAD2()] }, reviews: OK_REVIEW,
  });
  assert.equal(doubleSealed.ok, false);
  assert.match(doubleSealed.reason, /而不是 ci:audit@pending/);

  // ④ 三条结构都对，但本次运行没给出复核结论 ⇒ 章是空壳
  const noReview = judgeLedgerSeal({ touched, prCommits: [SEAL1, SEAL2], ledgerAt, reviews: {} });
  assert.equal(noReview.ok, false);
  assert.match(noReview.reason, /这次运行没有给出复核结论/);

  // ④b 结论在，但判的是不成立
  const notOk = judgeLedgerSeal({
    touched, prCommits: [SEAL1, SEAL2], ledgerAt,
    reviews: { [SEAL1]: { ok: false, reason: '引用的那串字节在包里找不到' }, [SEAL2]: { ok: true } },
  });
  assert.equal(notOk.ok, false);
  assert.match(notOk.reason, /mod_x 的复核结论不成立：引用的那串字节在包里找不到/);

  // 章只许盖在**当时就写好**的那一条上：changed 这一支同样逐条走四条
  const chg = judgeLedgerSeal({
    touched: { added: [], changed: [{ from: D({ by: BY1 }), to: D({ by: BY2 }) }], removed: [], any: true },
    prCommits: [SEAL1, SEAL2], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(chg.ok, false, '换了指向的提交，而 SEAL2 那枚提交上没有 mod_x 这条实体的待盖版本');
  assert.match(chg.reason, /那条提交上还没有这条处置的实体/);

  // 删除：没有 by 可查，也不许由章覆盖（撤销处置要走 restore）
  const del = judgeLedgerSeal({
    touched: { added: [], changed: [], removed: [D()], any: true },
    prCommits: [SEAL1], ledgerAt, reviews: OK_REVIEW,
  });
  assert.equal(del.ok, false);
  assert.match(del.reason, /撤销处置要走 restore/);

  // 台账没实质改动：一条都不查，直接通过（只动 lastUpdate 那一格）
  const none = judgeLedgerSeal({ touched: { added: [], changed: [], removed: [], any: false } });
  assert.equal(none.ok, true);
});

/**
 * 机器章的取证现在是**纯 git、零网络**，所以这一组用注入接口逐条打失效方向；
 * 「注入的接口和真 git 不漂」这件事由上面那组 P3 真仓库用例（makeSealedRevokePr）作证。
 *
 * 换代前这里是四个打 GitHub API 的用例（评论列表、逐条回访评论、逐个查仓库权限），
 * 其中「谁算签核人」那个来源本身按请求者会变（author_association 在 workflow token 下
 * 退化成 CONTRIBUTOR，canary #58/#59）。换成绑 commit 之后，判据要的两样东西仓库里都有。
 */
const headTwo = () => parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: [D(), HEAD2()] });

test('ledgerSealEvidence：台账没实质改动时一步 git 都不跑', () => {
  let ran = 0;
  const r = ledgerSealEvidence({
    cwd: '/nowhere', baseRef: 'main',
    baseLedger: headTwo(), headLedger: headTwo(),
    deps: { prCommits: () => { ran++; return []; }, ledgerAt: () => { ran++; return []; } },
  });
  assert.equal(r.ok, true);
  assert.equal(ran, 0, '没动台账就不该去列提交');
});

test('ledgerSealEvidence：列不出这条 PR 的提交时红，且绝不说成「没动台账」', () => {
  const r = ledgerSealEvidence({
    cwd: '/nowhere', baseRef: 'main',
    baseLedger: [], headLedger: headTwo(),
    deps: { prCommits: () => { throw new Error('fatal: bad revision main..HEAD'); } },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /列不出这条 PR 的提交/);
});

test('ledgerSealEvidence：同一枚章只读一次那一枚提交上的台账', () => {
  const reads = [];
  const two = parseDispositions({
    schema: 'sukisu-dispositions-v1',
    dispositions: [D(), { ...D(), id: 'mod_w', sha256: 'c'.repeat(64) }],   // 两条处置共享同一枚章
  });
  const r = ledgerSealEvidence({
    cwd: '/nowhere', baseRef: 'main', baseLedger: [], headLedger: two,
    reviews: { [SEAL1]: { ok: true } },
    deps: { prCommits: () => [SEAL1], ledgerAt: (sha) => { reads.push(sha); return [pendingOf(), { ...pendingOf(), id: 'mod_w', sha256: 'c'.repeat(64) }]; } },
  });
  assert.equal(reads.length, 1, `一枚章读一次台账，实际读了 ${reads.length} 次`);
  assert.equal(r.ok, true, r.reason);
});

test('ledgerSealEvidence：那一枚提交上的台账读不懂 ⇒ 判红，不当成「那上面没有实体」', () => {
  const r = ledgerSealEvidence({
    cwd: '/nowhere', baseRef: 'main', baseLedger: [], headLedger: headTwo(),
    reviews: OK_REVIEW,
    deps: {
      prCommits: () => [SEAL1, SEAL2],
      ledgerAt: (sha) => { if (sha === SEAL1) throw new Error('JSON 解析失败'); return [pendingOf({ id: sha === SEAL2 ? 'mod_y' : 'mod_x' })]; },
    },
  });
  assert.equal(r.ok, false);
  assert.match(r.reason, /那一枚提交上的台账读不出来/);
});

/* ------------------------------------------- 复核结论文件（第 ④ 条的来源） */

test('parseReviews：只认 40 位小写十六进制的键，ok 不是 true 的一律不算成立', () => {
  const out = parseReviews({
    [SEAL1]: { ok: true, summary: '逐字定位到 3 处' },
    [SEAL2]: { ok: false, reason: '包里没有引用的字节' },
    [`${'d'.repeat(39)}`]: { ok: true },          // 39 位：不是 sha
    [SEAL1.toUpperCase()]: { ok: true },          // 大写：git 不长这样
    latest: { ok: true },                          // 「顺手给一个万能章」——丢掉
    '': { ok: true },
    [`${'e'.repeat(40)}`]: 'ok',                   // 值不是对象
    [`${'f'.repeat(40)}`]: null,
  });
  assert.deepEqual(Object.keys(out).sort(), [SEAL1, SEAL2].sort(), '只留两个合法的 sha 键');
  assert.equal(out[SEAL1].ok, true);
  assert.equal(out[SEAL2].ok, false, '不成立也要留在结构里，否则日志看不见是谁拒的');
  assert.deepEqual(parseReviews(null), {}, '整份文件不是对象 ⇒ 空结论，不是「全都成立」');
  assert.deepEqual(parseReviews([]), {});
});

test('readReviews：没给路径 / 读不懂 ⇒ 一条都不算成立，且把原因打在日志里', () => {
  const log = quiet();
  assert.deepEqual(readReviews(undefined, log), {});
  assert.match(allLogs(log), /没给 --reviews/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vip-reviews-'));
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, '{ 坏掉的结论');
  const log2 = quiet();
  assert.deepEqual(readReviews(bad, log2), {});
  assert.match(allLogs(log2), /读不懂/);
  const good = path.join(dir, 'good.json');
  fs.writeFileSync(good, JSON.stringify({ [SEAL1]: { ok: true, summary: 's' } }));
  assert.deepEqual(readReviews(good, quiet()), { [SEAL1]: { ok: true, summary: 's', reason: '' } });
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ---------------------------------------- evidence/** 与台账互指认（spec §7.2.9 + §8）
   这一组钉的是「白名单开了一条目录，但那条目录只在跟着一次台账改动时才生效」，
   以及证据与处置必须互相指认 —— 引用了一条不存在的证据，公示页就是在替它背书。 */

const EV_SHA = 'a'.repeat(64);
const EV = `evidence/${EV_SHA}.json`;
const LEDGER_FILE = 'json/dispositions.json';

/** 一份 head 上的台账：一条 revoke，引用 files 里那些证据文件。 */
function ledgerEv(...files) {
  return parseDispositions({
    schema: 'sukisu-dispositions-v2',
    dispositions: [{
      kind: 'revoke',
      id: 'mod_a',
      reason: 'malware',
      by: 'https://github.com/o/r/issues/33#issuecomment-1',
      at: '2026-10-17T00:00:00Z',
      ...(files.length ? { evidence: files.map((file) => ({ file })) } : {}),
    }],
  });
}

function evJudge({ changed = [LEDGER_FILE, EV], headEvidence = [EV], dispositions = ledgerEv(EV), ledgerChanged = true } = {}) {
  return judgeIndexPr({
    baseIndex: { name: 'x', lastUpdate: 0, modules: [{ id: 'mod_a', versions: [] }] },
    actualIndex: { name: 'x', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [], attest: () => ({ ok: true }),
    dispositions, ledgerChanged, seal: SEAL_OK,
    changedPaths: changed, headEvidence,
  });
}

test('evidence 文件跟着台账改动一起进 → 放行，且互指认成立', () => {
  const v = evJudge();
  assert.equal(v.ok, true, v.reason);
  assert.equal(isEvidencePath(EV), true);
  assert.equal(isEvidencePath('pending/mod_a-1.json'), false);
});

test('只加 evidence、不动台账 → 白名单拒：证据不进双签就等于往公示数据里塞材料', () => {
  const v = evJudge({ ledgerChanged: false, dispositions: ledgerEv() });
  assert.equal(v.ok, false);
  assert.match(v.reason, /除了索引还改了/);
  assert.match(v.reason, /仅当同一条 PR 改了台账/);
});

test('evidence 下的文件名形状不对 → 拒（子目录、别的后缀、不是 64 位十六进制都不行）', () => {
  // 这些名字连台账那一侧的校验都过不了（dispositions.mjs 同一个正则），所以这里的
  // `dispositions` 不带引用 —— 要测的是白名单那一层拦不拦得住，不是它能不能被引用。
  for (const bad of ['evidence/notes.md', 'evidence/a/b.json', `evidence/${'a'.repeat(63)}.json`,
    'evidence/zzzzzzzz.json']) {
    const v = evJudge({ changed: [LEDGER_FILE, bad], headEvidence: [bad], dispositions: ledgerEv() });
    assert.equal(v.ok, false, bad);
    assert.match(v.reason, /必须是 evidence\/<64 位十六进制 sha256>\.json/, bad);
  }
});

test('台账引用了 head 上不存在的证据文件 → 拒', () => {
  const v = evJudge({ headEvidence: [] });
  assert.equal(v.ok, false);
  assert.match(v.reason, /在 head 上不存在/);
});

test('head 上有证据文件却没被任何一条台账引用 → 拒（孤证据不属于任何处置）', () => {
  const v = evJudge({ changed: [LEDGER_FILE, EV], headEvidence: [EV, `evidence/${'b'.repeat(64)}.json`] });
  assert.equal(v.ok, false);
  assert.match(v.reason, /没被台账任何一条引用/);
});

test('调用方列不出 head 的 evidence/ 时不做互指认 —— 但白名单那一步照常生效', () => {
  assert.equal(evJudge({ headEvidence: null }).ok, true);
  // 反过来：headEvidence 给了 []，引用就落空，这一格不能因为「列不出来」而变成放行。
  assert.equal(evJudge({ headEvidence: [] }).ok, false);
});
