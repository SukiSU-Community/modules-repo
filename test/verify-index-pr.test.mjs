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
  ledgerTouched, parseProofUrl, judgeLedgerSeal, ledgerSealEvidence,
} from '../scripts/verify-index-pr.mjs';
import { buildIndex, markApproved } from '../scripts/build-index.mjs';
import { parseDispositions } from '../scripts/dispositions.mjs';

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
  ok: true, reason: '测试注入的合格署名',
  signers: [{ login: 'member-one', assoc: 'MEMBER', id: 1 }, { login: 'member-two', assoc: 'OWNER', id: 2 }],
  touched: { added: [{ id: 'mod_a' }], changed: [], removed: [], any: true },
};

test('P3 判定：台账驱动型重建（没消费 pending）→ 一致且有人签才放行', () => {
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
  // 结论里要看得见是谁签的 —— 「推导一致」四个字不能把署名这件事糊过去
  assert.match(v.reason, /member-one\(MEMBER\)、member-two\(OWNER\)/);
});

// 这一条是 2026-10-17 那四格复现的正主：索引与推导**完全一致**（攻击者自己就能算出来），
// 缺的只是人的署名。缺证据必须是红，且要说清缺的是哪一半。
test('台账驱动那一支：索引算得对但没有署名证据 → 红（一致不等于有人签过）', () => {
  const base = { name: 'x', lastUpdate: 0, modules: [{ id: 'mod_a', versions: [] }] };
  const v = judgeIndexPr({
    baseIndex: base,
    actualIndex: { name: 'x', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
    // 没有 seal 这个入参 —— 等价于调用方忘了传 --pr
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /没拿到署名证据/);
  assert.match(v.reason, /不按「没有台账」处理/);

  const v2 = judgeIndexPr({
    baseIndex: base,
    actualIndex: { name: 'x', lastUpdate: 0, modules: [] },
    deletedPaths: [], touchedPaths: [],
    dispositions: parseDispositions(revokeOf('mod_a')), ledgerChanged: true,
    attest: () => ({ ok: true }),
    seal: { ok: false, reason: '这条 PR 上只有 1 名有写权限的人签了', signers: [{ login: 'solo', assoc: 'MEMBER' }] },
  });
  assert.equal(v2.ok, false);
  assert.match(v2.reason, /只有 1 名有写权限的人签了/);
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

/** 复刻 revoke.mjs 干的事：只写台账 -> build-index --dispositions 重算 -> 提交成 PR 分支 */
function makeRevokePr(dir, ledger) {
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), JSON.stringify(ledger, null, 2) + '\n');
  const scripts = path.resolve(import.meta.dirname, '../scripts');
  execFileSync(process.execPath, [path.join(scripts, 'build-index.mjs'),
    '--pending', 'pending', '--index', 'json/modules.json',
    '--dispositions', 'json/dispositions.json'], { cwd: dir, encoding: 'utf8' });
  G(dir, 'checkout', '-qb', 'revoke/mod_a');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(dispose): revoke mod_a');
}

test('P3 真仓库：只改台账 + 重算索引的 PR，签齐才退出 0；没给 --pr 与签不齐都是红', async () => {
  const m = await V();

  // ① 没给 --pr —— 取证无从开始，必须红（而不是「没有台账」）
  const d1 = ledgerFixture();
  makeRevokePr(d1, revokeOf('mod_a'));
  const log1 = quiet();
  const rc1 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d1],
    { log: log1, token: 't', attest: () => ({ ok: true }), seal: undefined });
  assert.equal(rc1, 1, allLogs(log1));
  assert.match(allLogs(log1), /没拿到署名证据|--pr/);

  // ② 给了 --pr 但这条 PR 上只有一个人签 → 红
  const d2 = ledgerFixture();
  makeRevokePr(d2, revokeOf('mod_a'));
  const log2 = quiet();
  const rc2 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d2, '--pr', '9'],
    {
      log: log2, token: 't', attest: () => ({ ok: true }),
      seal: { ok: false, reason: '这条 PR 上只有 1 名有写权限的人签了（member-one(MEMBER)），少于要求的 2 名', signers: [{ login: 'member-one', assoc: 'MEMBER', id: 1 }] },
    });
  assert.equal(rc2, 1, allLogs(log2));
  assert.match(allLogs(log2), /只有 1 名有写权限的人签了/);

  // ③ 两名成员签齐 → 绿，且 report.seal 留下可复核的指针
  const d3 = ledgerFixture();
  makeRevokePr(d3, revokeOf('mod_a'));
  const report = path.join(d3, 'r.json');
  const log3 = quiet();
  const rc3 = await m.main(['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', d3, '--pr', '9', '--report', report],
    { log: log3, token: 't', attest: () => ({ ok: true }), seal: SEAL_OK });
  assert.equal(rc3, 0, allLogs(log3));
  assert.match(allLogs(log3), /台账驱动/);
  const r = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.equal(r.seal.ok, true, 'report 里要看得见署名的结论');
  assert.deepEqual(r.seal.signers.map((s) => s.login), ['member-one', 'member-two']);
  assert.deepEqual(r.seal.touched, { added: 1, changed: 0, removed: 0 });
  for (const d of [d1, d2, d3]) fs.rmSync(d, { recursive: true, force: true });
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

/* ------------------------------------------------------- P4：处置台账的署名（两名成员 + by 回访） */

const BY1 = 'https://github.com/SukiSU-Community/modules-repo/issues/40#issuecomment-1111111111';
const BY2 = 'https://github.com/other-owner/other-repo/issues/7#issuecomment-2222222222';
const D = (over = {}) => ({
  kind: 'revoke', reason: 'malware', by: BY1, at: '2026-10-17T00:00:00.000Z', note: '', id: 'mod_x', ...over,
});
const HEAD2 = (over = {}) => ({
  kind: 'revoke', reason: 'malware', by: BY2, at: '2026-10-17T00:00:00.000Z', note: '', id: 'mod_y', ...over,
});
const SIGNERS = [{ login: 'member-one', assoc: 'MEMBER', id: 10 }, { login: 'member-two', assoc: 'OWNER', id: 11 }];

test('ledgerTouched：加 / 改 / 删三个方向都数得到，而只动 lastUpdate 不算实质改动', () => {
  const base = [D(), HEAD2()];
  const t0 = ledgerTouched(base, base);
  assert.equal(t0.any, false, '同一份台账不该报「动过」');

  // 只换署名/理由 —— 选择器没变，但证人变了：必须数成 changed
  const t1 = ledgerTouched(base, [D({ by: BY2 }), HEAD2()]);
  assert.deepEqual({ a: t1.added.length, c: t1.changed.length, r: t1.removed.length }, { a: 0, c: 1, r: 0 });
  assert.equal(t1.changed[0].from.by, BY1, 'changed 要留着改前那一份，否则「换了谁的章」看不出来');

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

test('parseProofUrl：只吃点得开的评论链接，形状不对一律 null（revoke.mjs 那一条正则复用，不另拼一份）', () => {
  assert.deepEqual(parseProofUrl(BY1), {
    owner: 'SukiSU-Community', repo: 'modules-repo', issue: 40, id: 1111111111, url: BY1,
  });
  for (const bad of [
    'gh:member-one@issuecomment-1',                                  // 旧形状，浏览器里点不开
    'https://github.com/o/r/issues/1#issuecomment-',                 // 缺 id
    'https://github.com/o/r/pull/1#discussion_r1',                   // PR review 线程，不是评论指针
    'https://example.com/o/r/issues/1#issuecomment-1',               // 不是 github
    'https://github.com/o/r/issues/1#issuecomment-1 / 另一个人也同意', // 尾巴上有字
    '',
  ]) {
    assert.equal(parseProofUrl(bad), null, `${JSON.stringify(bad)} 不该被当成可复核的署名`);
  }
});

test('judgeLedgerSeal：两名成员 + 每条 by 回访得到且作者签过，缺一即红', () => {
  const added = [D(), HEAD2()];
  const touched = { added, changed: [], removed: [], any: true };
  const res = { [BY1]: { ok: true, login: 'member-one', assoc: 'MEMBER', id: 10 }, [BY2]: { ok: true, login: 'member-two', assoc: 'OWNER', id: 11 } };

  const good = judgeLedgerSeal({ touched, signers: SIGNERS, resolved: res });
  assert.equal(good.ok, true, good.reason);

  // ① 只有一签
  const one = judgeLedgerSeal({ touched, signers: [SIGNERS[0]], resolved: res });
  assert.equal(one.ok, false);
  assert.match(one.reason, /只有 1 名有写权限的人签了/);

  // ② 两签齐，但 by 指向的那个人没在这条 PR 上签
  const stranger = judgeLedgerSeal({
    touched, signers: SIGNERS,
    resolved: { [BY1]: { ok: true, login: 'someone-else', assoc: 'MEMBER', id: 9 }, [BY2]: res[BY2] },
  });
  assert.equal(stranger.ok, false);
  assert.match(stranger.reason, /mod_x 的 by 署名是 someone-else/);

  // ③ by 回访不到（404 / 网络） —— 缺证据按不合格处理
  const missing = judgeLedgerSeal({
    touched, signers: SIGNERS,
    resolved: { [BY1]: { ok: false, reason: 'HTTP 404' }, [BY2]: res[BY2] },
  });
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /mod_x 的 by 回访不到那条评论：HTTP 404/);

  // ④ by 形状就不对（复现里那格用的是编造的链接）
  const bogus = judgeLedgerSeal({
    touched: { added: [D({ by: 'https://example.com/any' })], changed: [], removed: [], any: true },
    signers: SIGNERS, resolved: {},
  });
  assert.equal(bogus.ok, false);
  assert.match(bogus.reason, /不是点得开的评论链接/);

  // ⑤ 只有删除：没有 by 可查，靠那两名成员的签覆盖，但结论里要说清这一层
  const del = judgeLedgerSeal({
    touched: { added: [], changed: [], removed: [D()], any: true }, signers: SIGNERS, resolved: {},
  });
  assert.equal(del.ok, true, del.reason);
  assert.match(del.reason, /1 条删除没有 by 可查/);

  // ⑥ 改了已有条目的署名 —— changed 也要逐条对，不能只查 added
  const chg = judgeLedgerSeal({
    touched: { added: [], changed: [{ from: D({ by: BY1 }), to: D({ by: BY2 }) }], removed: [], any: true },
    signers: [{ login: 'member-two', assoc: 'MEMBER', id: 11 }, { login: 'member-one', assoc: 'OWNER', id: 10 }],
    resolved: { [BY2]: { ok: true, login: 'member-one', assoc: 'MEMBER', id: 10 } },
  });
  assert.equal(chg.ok, true, chg.reason);
});

/**
 * 只按 URL 分派的假 GitHub API，用来验取证据那条路的形状。
 *
 * `collaborators/{login}/permission` 这一格是 2026-10-17 补的：CI 里「谁算签核人」改吃这个端点
 * （canary #59 实测 workflow token 下 `author_association` 会退化成 CONTRIBUTOR）。
 * 没在 `perms` 里点名的人一律回 `read` —— 那正是探针量到的真实形状（octocat 不是这个仓库的
 * 协作者，HTTP 200 `permission=read`，**不是 404**），所以「列出来的人才有写权限」这个前提
 * 在夹具里也是 fail closed 的。
 */
function stubFetch({ comments, byComments = {}, perms = {}, throwOn = '', failPerm = null } = {}) {
  const seen = [];
  return {
    seen,
    fetch: async (url) => {
      seen.push(String(url));
      if (throwOn && String(url).includes(throwOn)) throw new Error('HTTP 502');
      const pm = /\/collaborators\/([^/]+)\/permission/.exec(String(url).split('?')[0]);
      if (pm) {
        const login = decodeURIComponent(pm[1]);
        if (failPerm && failPerm[login]) throw new Error(`HTTP ${failPerm[login]}`);
        const permission = Object.prototype.hasOwnProperty.call(perms, login) ? perms[login] : 'read';
        return { ok: true, status: 200, json: async () => ({ permission, role_name: permission }) };
      }
      const c = /\/issues\/comments\/(\d+)$/.exec(String(url).split('?')[0]);
      if (c) {
        const rec = byComments[c[1]];
        // 真实 GitHub：取不到是 404，不是空对象
        if (!rec) return { ok: false, status: 404, json: async () => ({ message: 'Not Found' }) };
        return { ok: true, status: 200, json: async () => rec };
      }
      if (/\/issues\/\d+\/comments/.test(String(url))) return { ok: true, status: 200, json: async () => comments };
      throw new Error(`stub 没准备的端点：${url}`);
    },
  };
}
const signComment = (id, login, assoc = 'MEMBER') => ({ id, user: { login }, author_association: assoc, body: `#human-approved ${login} 同意下架` });
const WRITE = { 'member-one': 'admin', 'member-two': 'write' };

test('ledgerSealEvidence：签核人按仓库权限认，评论列表取不到时红而不是放行', async () => {
  const base = [];
  const head = parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: [D(), HEAD2()] });
  const BY_COMMENTS = {
    1111111111: { id: 1111111111, user: { login: 'member-one' }, author_association: 'MEMBER' },
    2222222222: { id: 2222222222, user: { login: 'member-two' }, author_association: 'MEMBER' },
  };

  // ① 两签齐且两条 by 都能回访到签名的人
  const okCase = stubFetch({
    comments: [signComment(10, 'member-one'), signComment(11, 'member-two')],
    byComments: BY_COMMENTS, perms: WRITE,
  });
  const r1 = await ledgerSealEvidence({
    owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: okCase,
  });
  assert.equal(r1.ok, true, r1.reason);
  assert.equal(r1.signers.length, 2);
  assert.ok(okCase.seen.some((u) => /\/repos\/o\/r\/issues\/9\/comments\?per_page=100/.test(u)), '要按这条 PR 的编号取评论，不是「最近哪条 PR」');
  assert.equal(okCase.seen.filter((u) => /\/issues\/comments\//.test(u)).length, 2, '两条 by 各回访一次');
  assert.equal(okCase.seen.filter((u) => /\/collaborators\/[^/]+\/permission/.test(u)).length, 2, '两个签核人各查一次权限');
  assert.deepEqual(Object.keys(r1.trust).sort(), ['member-one', 'member-two']);

  // ② 只有一个人签（他刷两条也只算一签 —— 去重住在 findHumanApprovals 里）
  const oneCase = stubFetch({
    comments: [signComment(10, 'member-one'), signComment(12, 'member-one'),
      { id: 13, user: { login: 'outsider' }, author_association: 'NONE', body: '#human-approved 我签了但没权限' }],
    byComments: BY_COMMENTS, perms: WRITE,
  });
  const r2 = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: oneCase });
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /只有 1 名有写权限的人签了/);

  // ③ by 指向一条不存在的评论 → 404 → 红（复现里「形状合法、内容是编的」那一格的机器版）
  const four04 = stubFetch({
    comments: [signComment(10, 'member-one'), signComment(11, 'member-two')],
    byComments: { 1111111111: BY_COMMENTS['1111111111'] }, perms: WRITE,
  });
  const r3 = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: four04 });
  assert.equal(r3.ok, false);
  assert.match(r3.reason, /mod_y 的 by 回访不到那条评论：HTTP 404/);

  // ④ 评论列表这个端点本身坏了 → 红（这里绝不退成「没有台账」）
  const broken = stubFetch({ comments: [], throwOn: '/issues/9/comments' });
  const r4 = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: broken });
  assert.equal(r4.ok, false);
  assert.match(r4.reason, /拿不到 PR #9 的评论/);

  // ⑤ 没给 --pr → 红，且不发任何请求
  const quietStub = stubFetch({ comments: [] });
  const r5 = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: undefined, baseLedger: base, headLedger: head, token: 't', deps: quietStub });
  assert.equal(r5.ok, false);
  assert.match(r5.reason, /取不到这条 PR 的编号/);
  assert.equal(quietStub.seen.length, 0, '没有 PR 编号时一个请求都不该发');

  // ⑥ 台账没动实质内容 → ok 且不去取证据（lastUpdate 那种改动不该逼人签）
  const noopStub = stubFetch({ comments: [] });
  const r6 = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: head, headLedger: head, token: 't', deps: noopStub });
  assert.equal(r6.ok, true);
  assert.equal(noopStub.seen.length, 0, '没有实质改动就不该花钱去取证据');

  // ⑦ 权限那个端点本身读不到（403/5xx）时也不许放行 —— 见下面单独那一格，
  //    它要能独立报出「红在哪一格」，所以不跟在这里。
});

/* 下面这两格各自独立成 test，是为了变异能报到**为它而设的那一格**上：
 * 混在同一格里时，前面那格的断言会先抛，读日志的人就看不见「反例被放过了」这句真正的话。 */

// ⑦⑧ 这一对是 2026-10-17 那次换来源的全部理由：assoc 是**按请求者**算的。
// canary #58/#59 线上实测：同一条评论，人的 token 读回 MEMBER，workflow 的 github.token 读回 CONTRIBUTOR。
test('ledgerSealEvidence：assoc 退化成 CONTRIBUTOR 但权限够 ⇒ 照样数得到（CI 的真实形状）', async () => {
  const base = [];
  const head = parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: [D(), HEAD2()] });
  const ciShape = stubFetch({
    comments: [signComment(10, 'member-one', 'CONTRIBUTOR'), signComment(11, 'member-two', 'CONTRIBUTOR')],
    byComments: {
      1111111111: { id: 1111111111, user: { login: 'member-one' }, author_association: 'CONTRIBUTOR' },
      2222222222: { id: 2222222222, user: { login: 'member-two' }, author_association: 'CONTRIBUTOR' },
    },
    perms: WRITE,
  });
  const r = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: ciShape });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(r.signers.map((s) => s.trust), ['permission=admin', 'permission=write'],
    '结论里要看得见权限，而不是那个会随请求者变的 assoc');
});

// 反过来那一格才证明牙在：assoc 全说 MEMBER/OWNER，但权限查出来是 read（探针里 octocat 的形状）
// ⇒ 一签都不算。少了这格，「换成查权限」可能只是换了个也会说谎的来源。
test('ledgerSealEvidence：assoc 说 MEMBER 而仓库权限只有 read ⇒ 一签都不算（octocat 形状）', async () => {
  const base = [];
  const head = parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: [D(), HEAD2()] });
  const noWrite = stubFetch({
    comments: [signComment(10, 'member-one', 'MEMBER'), signComment(11, 'member-two', 'OWNER')],
    byComments: {
      1111111111: { id: 1111111111, user: { login: 'member-one' }, author_association: 'MEMBER' },
      2222222222: { id: 2222222222, user: { login: 'member-two' }, author_association: 'OWNER' },
    },
  });
  const r = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: noWrite });
  assert.equal(r.ok, false);
  assert.match(r.reason, /只有 0 名有写权限的人签了/);
  assert.deepEqual(Object.values(r.trust).map((t) => t.permission), ['read', 'read'],
    '0 签时结论里不会写每个人的权限，但 trust 必须记着 —— 生产上就靠它解释「为什么数不到」');
});

// ⑨ 查权限这件事本身坏了 ⇒ 按不可信处理（fail closed），不是「查不到就算过」
test('ledgerSealEvidence：权限端点回 403/500 时按不可信处理', async () => {
  const base = [];
  const head = parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: [D(), HEAD2()] });
  const permBroken = stubFetch({
    comments: [signComment(10, 'member-one'), signComment(11, 'member-two')],
    byComments: {
      1111111111: { id: 1111111111, user: { login: 'member-one' }, author_association: 'MEMBER' },
      2222222222: { id: 2222222222, user: { login: 'member-two' }, author_association: 'MEMBER' },
    },
    failPerm: { 'member-one': 403, 'member-two': 500 },
  });
  const r = await ledgerSealEvidence({ owner: 'o', repo: 'r', prNumber: 9, baseLedger: base, headLedger: head, token: 't', deps: permBroken });
  assert.equal(r.ok, false);
  assert.match(r.reason, /只有 0 名有写权限的人签了/);
  for (const t of Object.values(r.trust)) {
    assert.equal(t.ok, false);
    assert.match(t.why, /查不到仓库权限：HTTP (403|500)/);
  }
});

/* 生产路径上没有人注入 deps.seal：CI 只给 --pr，取证全靠 deps.fetch。
 * 上面那批 ledgerSealEvidence 用例证明「这个函数被单独调用时判得对」，但它们不能证明
 * main() 真的会去调它 —— 那条路要是接错了，整条署名判定就是生产上的死码，而单测照样全绿。
 * 这两格把「main → 取证据 → 判定 → 日志/report 留痕」这一段钉住。 */
test('main 只给 --pr 与 deps.fetch 时真的走完取证（绿的那格）', async () => {
  const dir = ledgerFixture();
  makeRevokePr(dir, revokeOf('mod_a', BY1));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vip-seal-out-'));
  const report = path.join(out, 'r.json');
  const stub = stubFetch({
    // 用 CI 真实形状起夹具：assoc 全是 CONTRIBUTOR（workflow token 读回来就这样），
    // 权限查出来才是 admin/write —— 这两格既要证 main 真走了取证，也要证它换来源之后照样数得到。
    comments: [signComment(10, 'member-one', 'CONTRIBUTOR'), signComment(11, 'member-two', 'CONTRIBUTOR')],
    byComments: { 1111111111: { id: 1111111111, user: { login: 'member-one' }, author_association: 'CONTRIBUTOR' } },
    perms: WRITE,
  });
  const log = quiet();
  const m = await V();
  const rc = await m.main(
    ['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir, '--pr', '9', '--report', report],
    { log, token: 't', attest: () => ({ ok: true }), fetch: stub.fetch });
  assert.equal(rc, 0, allLogs(log));
  assert.ok(stub.seen.some((u) => /\/repos\/o\/r\/issues\/9\/comments\?per_page=100$/.test(u)),
    'main 要按 PR 编号取评论列表：' + stub.seen.join(' '));
  assert.ok(stub.seen.some((u) => /\/repos\/SukiSU-Community\/modules-repo\/issues\/comments\/1111111111$/.test(u)),
    'by 的回访要用 by 自己的 owner/repo，不是这条 PR 的：' + stub.seen.join(' '));
  assert.match(allLogs(log), /by 回访 \S+ → member-one\(CONTRIBUTOR\)/);
  assert.match(allLogs(log), /署名可信度 member-one → permission=admin 可信=yes/);
  assert.match(allLogs(log), /署名可信度 member-two → permission=write 可信=yes/);
  const r = JSON.parse(fs.readFileSync(report, 'utf8'));
  assert.equal(r.seal.ok, true, r.seal.reason);
  assert.equal(r.seal.signerCount, 2);
  assert.deepEqual(r.seal.resolved[BY1], { ok: true, login: 'member-one', assoc: 'CONTRIBUTOR', reason: null });
  assert.deepEqual(r.seal.trust['member-two'], { ok: true, permission: 'write', why: null });
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(out, { recursive: true, force: true });
});

test('main 只给 --pr 与 deps.fetch 时真的走完取证（by 404 的那格要红，且红在回访那一句）', async () => {
  const dir = ledgerFixture();
  makeRevokePr(dir, revokeOf('mod_a', BY1));
  const stub = stubFetch({
    comments: [signComment(10, 'member-one'), signComment(11, 'member-two')],
    byComments: {},                     // 两签齐（权限也够），但那条评论不存在
    perms: WRITE,
  });
  const log = quiet();
  const m = await V();
  const rc = await m.main(
    ['--base', 'main', '--head', 'HEAD', '--owner', 'o', '--repo', 'r', '--cwd', dir, '--pr', '9'],
    { log, token: 't', attest: () => ({ ok: true }), fetch: stub.fetch });
  assert.equal(rc, 1, allLogs(log));
  assert.equal(stub.seen.filter((u) => /\/issues\/comments\//.test(u)).length, 1, '一条 by 回访一次');
  assert.match(allLogs(log), /by 回访 \S+ → 读不到：HTTP 404/);
  assert.match(allLogs(log), /mod_a 的 by 回访不到那条评论/);
  fs.rmSync(dir, { recursive: true, force: true });
});
