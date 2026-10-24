/**
 * revoke.mjs 的单测 —— 下处置的唯一入口。
 * 运行：node --test test/revoke.test.mjs
 *
 * 这里锁的是两件事：**能不能写进去**（校验、去重、坏台账）和
 * **写进去之后索引是不是真由推导重算的**（脚本自己不碰索引内容）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { main, parseArgs, sameSelectors, buildDisposition, SEAL_PENDING_BY, MACHINE_SEAL_RE } from '../scripts/revoke.mjs';
import { buildIndex } from '../scripts/build-index.mjs';

const SHA = (c) => c.repeat(64);
// 处置指针现在是**机器章**：`ci:audit@<这一条台账 PR 上的某一枚 commit 的 sha>`。
// 旧的两版（`gh:<login>@issuecomment-<id>` 与浏览器里点得开的评论 URL）都随「本站只有机器审核」
// 退场 —— 形状与理由写在 revoke.mjs 的 MACHINE_SEAL_RE 上面。
const SEAL_SHA = 'ab'.repeat(20);                     // 40 位十六进制的夹具 sha
const BY = `ci:audit@${SEAL_SHA}`;

function sandbox({ ledger = null, modules = [] } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'revoke-'));
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending'), { recursive: true });
  const index = { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules };
  const indexPath = path.join(dir, 'json', 'modules.json');
  fs.writeFileSync(indexPath, JSON.stringify(index, null, 2) + '\n', 'utf8');
  const ledgerPath = path.join(dir, 'json', 'dispositions.json');
  if (ledger !== null) fs.writeFileSync(ledgerPath, typeof ledger === 'string' ? ledger : JSON.stringify(ledger, null, 2) + '\n', 'utf8');
  return { dir, indexPath, ledgerPath, pendingPath: path.join(dir, 'pending') };
}

/** 造一个「索引里已经有 mod_x」的沙盒（用真推导造，免得夹具和实现不一致）。 */
function sandboxWithModule(id = 'mod_x') {
  const s = sandbox();
  const seeded = buildIndex({
    index: { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] },
    entries: [{
      id, name: id, author: 'a', description: 'd',
      audit: { status: 'auto-approved', by: 'ci:x', at: '2026-10-01T00:00:00Z', risk: 'low' },
      versions: [{ version: 'v1', versionCode: 1, zipUrl: `https://e/${id}.zip`, size: 1, time: 1, sha256: SHA('c') }],
    }],
  }).index;
  fs.writeFileSync(s.indexPath, JSON.stringify(seeded, null, 2) + '\n', 'utf8');
  return s;
}

const capture = () => {
  const out = [];
  return { out, log: (...a) => out.push(a.join(' ')), error: (...a) => out.push('! ' + a.join(' ')) };
};

// 这些用例锁的是「能不能写进去」，不是 §8 固化 —— 默认 main 会去读 git 历史与 PR 评论，
// 沙盒目录既没有 main 也没有凭据，所以一律带 --no-harvest（固化那条路另有
// test/harvest-evidence.test.mjs 的三格集成用例，那里用注入的 deps.harvest 跑）。
function run(s, extraArgs, io = capture(), deps = {}) {
  return main([
    '--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath, '--no-harvest', ...extraArgs,
  ], io, deps).then((rc) => ({ rc, io }));
}

test('缺选择器 / 缺 by / reason 不在枚举 / version-code 没配 id → 退出 2 且一个字节都不写', async () => {
  const s = sandboxWithModule();
  const before = { idx: fs.readFileSync(s.indexPath, 'utf8') };
  const cases = [
    ['--kind', 'revoke', '--reason', 'malware', '--by', BY],
    ['--id', 'mod_x', '--reason', 'malware', '--by', ''],
    ['--id', 'mod_x', '--reason', '我看不惯它', '--by', BY],
    ['--id', 'mod_x', '--version-code', '1', '--reason', 'x', '--by', BY], // reason 非法，同样拒
    ['--version-code', '1', '--reason', 'malware', '--by', BY],
  ];
  for (const args of cases) {
    const { rc } = await run(s, ['--kind', 'revoke', ...args].filter((x) => x !== undefined));
    assert.equal(rc, 2, `应该拒：${args.join(' ')}`);
    assert.equal(fs.existsSync(s.ledgerPath), false, '拒写时不许建台账文件');
    assert.equal(fs.readFileSync(s.indexPath, 'utf8'), before.idx, '拒写时索引不许动');
  }
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('--dry-run：把要写的条目说清楚，但不落盘、不重算索引', async () => {
  // test-probe 只收探针命名空间里的 id（见下一条用例），所以这里造一枚探针模块。
  const s = sandboxWithModule('probe-dryrun');
  const { rc, io } = await run(s, ['--id', 'probe-dryrun', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY, '--dry-run']);
  assert.equal(rc, 0);
  assert.match(io.out.join('\n'), /--dry-run：没写任何文件/);
  assert.equal(fs.existsSync(s.ledgerPath), false);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('正常下架：写台账 -> 调 build-index 重算 -> 索引里那条真没了', async () => {
  const s = sandboxWithModule('probe-e2e');
  const { rc, io } = await run(s, ['--id', 'probe-e2e', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY, '--note', '流水线探针包'], capture());
  assert.equal(rc, 0, io.out.join('\n') + '\n' + io.out.join('\n'));

  const ledger = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8'));
  // 写入侧升 v2 是把整份文件的 schema 头一起换掉的（沙箱里那份是 v1 的历史台账）。
  // 这条断言钉的是「写出来的下一份台账必须是 v2」，而 v1 条目仍然读得动由
  // `dispositions.test.mjs` 那组兼容用例负责 —— 两边的分工别在一处重复。
  assert.equal(ledger.schema, 'sukisu-dispositions-v2');
  assert.equal(ledger.dispositions.length, 1);
  assert.equal(ledger.dispositions[0].id, 'probe-e2e');
  assert.equal(ledger.dispositions[0].kind, 'revoke');
  assert.equal(ledger.dispositions[0].by, BY, '署名必须原样落进台账');
  assert.match(ledger.dispositions[0].at, /Z$/, '写入的时间必须带时区');

  const idx = JSON.parse(fs.readFileSync(s.indexPath, 'utf8'));
  assert.deepEqual(idx.modules.map((m) => m.id), [], '索引要被 build-index 重算，不是被脚本手改');
  assert.match(io.out.join('\n'), /台账抹掉版本 1/);
  assert.match(io.out.join('\n'), /git checkout -b revoke\/probe-e2e/);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('只指到产物：抹那一条版本，模块与其它版本留着', async () => {
  const s = sandbox();
  const seeded = buildIndex({
    index: { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] },
    entries: [{
      id: 'mod_y', name: 'mod_y', author: 'a', description: 'd',
      audit: { status: 'auto-approved', by: 'ci:x', at: '2026-10-01T00:00:00Z', risk: 'low' },
      versions: [
        { version: 'v1', versionCode: 1, zipUrl: 'https://e/1.zip', size: 1, time: 1, sha256: SHA('1') },
        { version: 'v2', versionCode: 2, zipUrl: 'https://e/2.zip', size: 1, time: 2, sha256: SHA('2') },
      ],
    }],
  }).index;
  fs.writeFileSync(s.indexPath, JSON.stringify(seeded, null, 2) + '\n', 'utf8');

  const { rc } = await run(s, ['--id', 'mod_y', '--sha256', SHA('1'), '--kind', 'revoke', '--reason', 'malware', '--by', BY]);
  assert.equal(rc, 0);
  const idx = JSON.parse(fs.readFileSync(s.indexPath, 'utf8'));
  assert.deepEqual(idx.modules[0].versions.map((v) => v.versionCode), [2]);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('test-probe 不带 --sha256 → 退出 2：探针档按「这一枚包什么也不做」复核，只给 id 过不了', async () => {
  const s = sandboxWithModule('probe-nosha');
  const { rc, io } = await run(s, ['--id', 'probe-nosha', '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  assert.equal(rc, 2);
  assert.match(io.out.join('\n'), /test-probe 必须同时给 --sha256/);
  assert.equal(fs.existsSync(s.ledgerPath), false, '拒写时不许建台账文件');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('同样选择器重复下处置 → 退出 4，不写第二条', async () => {
  const s = sandboxWithModule('probe-dup');
  await run(s, ['--id', 'probe-dup', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  const before = fs.readFileSync(s.ledgerPath, 'utf8');
  const { rc, io } = await run(s, ['--id', 'probe-dup', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'malware', '--by', `ci:audit@${'cd'.repeat(20)}`], capture());
  assert.equal(rc, 4);
  assert.match(io.out.join('\n'), /已经有同样选择器的记录/);
  assert.equal(fs.readFileSync(s.ledgerPath, 'utf8'), before, '重复下处置不许往台账里堆矛盾记录');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('现有台账坏了 → 退出 3，绝不往坏文件上追加', async () => {
  const s = sandbox({ ledger: '{ 坏掉的' });
  const { rc, io } = await run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'malware', '--by', BY], capture());
  assert.equal(rc, 3);
  assert.match(io.out.join('\n'), /先修好它再来追加/);
  assert.equal(fs.readFileSync(s.ledgerPath, 'utf8'), '{ 坏掉的', '坏了的台账原样留着，等人来看');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('台账里已有的记录不会被覆盖，lastUpdate 跟着走', async () => {
  const s = sandbox({ ledger: { schema: 'sukisu-dispositions-v1', lastUpdate: 1, dispositions: [{ kind: 'revoke', id: 'other', reason: 'policy', by: BY, at: '2026-10-01T00:00:00Z' }] } });
  const at = new Date('2026-10-11T03:00:00Z');
  const rc = await main(['--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath, '--no-harvest',
    '--id', 'mod_x', '--kind', 'revoke', '--reason', 'malware', '--by', BY], capture(), { now: () => at });
  assert.equal(rc, 0);
  const ledger = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8'));
  assert.equal(ledger.dispositions.length, 2);
  assert.deepEqual(ledger.dispositions.map((d) => d.id), ['other', 'mod_x']);
  assert.equal(ledger.lastUpdate, at.getTime());
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('sameSelectors：只有选择器完全相同才算重复', () => {
  const base = { kind: 'revoke', id: 'a', reason: 'malware', by: BY, at: '2026-10-11T00:00:00Z' };
  assert.equal(sameSelectors(base, { ...base, reason: 'policy', by: 'gh:other@1' }), true, '换理由不算新处置');
  assert.equal(sameSelectors(base, { ...base, versionCode: 1 }), false, '指到版本就是另一条');
  assert.equal(sameSelectors(base, { ...base, id: 'b' }), false);
});

test('parseArgs：--dry-run 是裸 flag，不吃下一个参数', () => {
  const o = parseArgs(['--id', 'a', '--dry-run', '--reason', 'malware']);
  assert.equal(o.id, 'a');
  assert.equal(o['dry-run'], true);
  assert.equal(o.reason, 'malware');
});

/* ------------------------------------------------------------ by 指针形状 */

test('buildDisposition：只接受机器章 ci:audit@<40 位小写十六进制>，以及第一枚提交用的待盖值', () => {
  const d = buildDisposition({ reason: 'malware', by: BY, id: 'a' }, new Date('2026-10-11T00:00:00Z'));
  assert.equal(d.by, BY);
  assert.equal(d.at, '2026-10-11T00:00:00.000Z');
  // 待盖值是台账 PR **第一枚提交**的合法形状：实体先写下，第二枚提交才换成 sha。
  assert.equal(buildDisposition({ reason: 'malware', by: SEAL_PENDING_BY, id: 'a' }).by, SEAL_PENDING_BY);
  // 而它**永远不算一枚章**：待盖值若能过形状正则，判定端就会把「还没盖」读成「已盖」。
  assert.equal(MACHINE_SEAL_RE.test(SEAL_PENDING_BY), false);
});

test('buildDisposition：旧形状与手滑形状一律被拒 —— 它们要么点不开，要么根本不是章', () => {
  for (const bad of [
    'gh:someone@issuecomment-123456',                       // 第 1 版：评论 id 单独拼不出 URL
    'https://github.com/o/r/issues/33#issuecomment-123456', // 第 2 版：人工签，已随「只有机器审核」退场
    `ci:audit@${'ab'.repeat(19)}`,                          // 38 位：短一截的 sha 不是 sha
    `ci:audit@${'zz'.repeat(20)}`,                          // 非十六进制
    `ci:audit@${'AB'.repeat(20)}`,                          // 大写：git 的 sha 一律小写，认大写就是给「手打过一次」留门
    'ci:audit@head', 'ci:audit@', 'ci:audit', 'audit@' + SEAL_SHA,
    '',
  ]) {
    assert.throws(() => buildDisposition({ reason: 'malware', by: bad, id: 'a' }), /ci:audit@/, `${bad} 应该被拒`);
  }
});

test('main：--by 形状不对时退出 2，并告诉人 sha 从哪儿来，绝不落盘', async () => {
  const s = sandbox();
  const lines = [];
  const io = { log: (m) => lines.push(String(m)), error: (m) => lines.push(String(m)) };
  const rc = await main(['--id', 'mod_x', '--reason', 'malware', '--by', 'gh:me@issuecomment-9', '--ledger', s.ledgerPath, '--index', s.indexPath], io);
  assert.equal(rc, 2);
  assert.ok(lines.some((l) => l.includes(SEAL_PENDING_BY)), '报错要顺手给出两枚提交的写法，否则人只能瞎猜');
  assert.equal(fs.existsSync(s.ledgerPath), false, '一条都不该写下去');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('test-probe + 真模块 id → 退出 2：探针档的判据对真包也成立，没有命名空间就能把一枚无害的真包标成探针下架', async () => {
  const s = sandboxWithModule();
  const { rc, io } = await run(s, ['--id', 'mod_x', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  assert.equal(rc, 2);
  assert.match(io.out.join('\n'), /test-probe 只用于流水线自检留下的探针包/);
  assert.match(io.out.join('\n'), /probe- \/ e2e- \/ canary- \/ selftest-/, '报错要把认得的命名空间列出来');
  assert.match(io.out.join('\n'), /malware\|policy\|copyright/, '并告诉人真模块该用哪几个 reason');
  assert.equal(fs.existsSync(s.ledgerPath), false, '拒写时不许建台账文件');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('test-probe + probe- 前缀 + sha256 → 放行：流水线自检的探针包走得通这条窄路', async () => {
  const s = sandboxWithModule('probe-ok');
  const { rc, io } = await run(s, ['--id', 'probe-ok', '--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  assert.equal(rc, 0, io.out.join('\n'));
  const ledger = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8'));
  assert.equal(ledger.dispositions[0].reason, 'test-probe');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('test-probe 不带 --id → 退出 2：只给摘要的话台账里那条处置回访不到探针模块', async () => {
  const s = sandboxWithModule();
  const { rc, io } = await run(s, ['--sha256', SHA('c'), '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  assert.equal(rc, 2);
  assert.match(io.out.join('\n'), /test-probe 必须同时给 --id/);
  assert.equal(fs.existsSync(s.ledgerPath), false, '拒写时不许建台账文件');
  fs.rmSync(s.dir, { recursive: true, force: true });
});
