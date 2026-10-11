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

import { main, parseArgs, sameSelectors, buildDisposition } from '../scripts/revoke.mjs';
import { buildIndex } from '../scripts/build-index.mjs';

const SHA = (c) => c.repeat(64);
// 指针必须是浏览器里点得开的永久链接（带 issue 号），旧形状 gh:<login>@issuecomment-<id>
// 单独拼不出 URL —— 见 revoke.mjs 里 PROOF_URL_RE 的注释。
const BY = 'https://github.com/o/r/issues/33#issuecomment-123456';

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

function run(s, extraArgs, io = capture()) {
  const rc = main([
    '--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath, ...extraArgs,
  ], io);
  return { rc, io };
}

test('缺选择器 / 缺 by / reason 不在枚举 / version-code 没配 id → 退出 2 且一个字节都不写', () => {
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
    const { rc } = run(s, ['--kind', 'revoke', ...args].filter((x) => x !== undefined));
    assert.equal(rc, 2, `应该拒：${args.join(' ')}`);
    assert.equal(fs.existsSync(s.ledgerPath), false, '拒写时不许建台账文件');
    assert.equal(fs.readFileSync(s.indexPath, 'utf8'), before.idx, '拒写时索引不许动');
  }
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('--dry-run：把要写的条目说清楚，但不落盘、不重算索引', () => {
  const s = sandboxWithModule();
  const { rc, io } = run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'test-probe', '--by', BY, '--dry-run']);
  assert.equal(rc, 0);
  assert.match(io.out.join('\n'), /--dry-run：没写任何文件/);
  assert.equal(fs.existsSync(s.ledgerPath), false);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('正常下架：写台账 -> 调 build-index 重算 -> 索引里那条真没了', () => {
  const s = sandboxWithModule();
  const { rc, io } = run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'test-probe', '--by', BY, '--note', '流水线探针包'], capture());
  assert.equal(rc, 0, io.out.join('\n') + '\n' + io.out.join('\n'));

  const ledger = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8'));
  assert.equal(ledger.schema, 'sukisu-dispositions-v1');
  assert.equal(ledger.dispositions.length, 1);
  assert.equal(ledger.dispositions[0].id, 'mod_x');
  assert.equal(ledger.dispositions[0].kind, 'revoke');
  assert.equal(ledger.dispositions[0].by, BY, '署名必须原样落进台账');
  assert.match(ledger.dispositions[0].at, /Z$/, '写入的时间必须带时区');

  const idx = JSON.parse(fs.readFileSync(s.indexPath, 'utf8'));
  assert.deepEqual(idx.modules.map((m) => m.id), [], '索引要被 build-index 重算，不是被脚本手改');
  assert.match(io.out.join('\n'), /台账抹掉版本 1/);
  assert.match(io.out.join('\n'), /git checkout -b revoke\/mod_x/);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('只指到产物：抹那一条版本，模块与其它版本留着', () => {
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

  const { rc } = run(s, ['--id', 'mod_y', '--sha256', SHA('1'), '--kind', 'revoke', '--reason', 'malware', '--by', BY]);
  assert.equal(rc, 0);
  const idx = JSON.parse(fs.readFileSync(s.indexPath, 'utf8'));
  assert.deepEqual(idx.modules[0].versions.map((v) => v.versionCode), [2]);
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('同样选择器重复下处置 → 退出 4，不写第二条', () => {
  const s = sandboxWithModule();
  run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'test-probe', '--by', BY]);
  const before = fs.readFileSync(s.ledgerPath, 'utf8');
  const { rc, io } = run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'malware', '--by', 'https://github.com/o/r/issues/9#issuecomment-777'], capture());
  assert.equal(rc, 4);
  assert.match(io.out.join('\n'), /已经有同样选择器的记录/);
  assert.equal(fs.readFileSync(s.ledgerPath, 'utf8'), before, '重复下处置不许往台账里堆矛盾记录');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('现有台账坏了 → 退出 3，绝不往坏文件上追加', () => {
  const s = sandbox({ ledger: '{ 坏掉的' });
  const { rc, io } = run(s, ['--id', 'mod_x', '--kind', 'revoke', '--reason', 'malware', '--by', BY], capture());
  assert.equal(rc, 3);
  assert.match(io.out.join('\n'), /先修好它再来追加/);
  assert.equal(fs.readFileSync(s.ledgerPath, 'utf8'), '{ 坏掉的', '坏了的台账原样留着，等人来看');
  fs.rmSync(s.dir, { recursive: true, force: true });
});

test('台账里已有的记录不会被覆盖，lastUpdate 跟着走', () => {
  const s = sandbox({ ledger: { schema: 'sukisu-dispositions-v1', lastUpdate: 1, dispositions: [{ kind: 'revoke', id: 'other', reason: 'policy', by: BY, at: '2026-10-01T00:00:00Z' }] } });
  const at = new Date('2026-10-11T03:00:00Z');
  const rc = main(['--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath,
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

test('buildDisposition：只接受点得开的证据链接', () => {
  const d = buildDisposition({ reason: 'malware', by: BY, id: 'a' }, new Date('2026-10-11T00:00:00Z'));
  assert.equal(d.by, BY);
  assert.equal(d.at, '2026-10-11T00:00:00.000Z');
});

test('buildDisposition：旧形状 gh:<login>@issuecomment-<id> 被拒 —— 它在浏览器里点不开', () => {
  for (const bad of [
    'gh:yufengliang@issuecomment-123456',
    'https://github.com/o/r/issues/33',                 // 缺评论锚点：跳到 issue 顶部，看不到那条说明
    'https://github.com/o/r/issues/33#issuecomment-x',
    'https://evil.example.com/o/r/issues/33#issuecomment-1',
    'http://github.com/o/r/issues/33#issuecomment-1',   // 明文不算
    'https://github.com/o/r/pull/33#issuecomment-1',    // 只认 issues 路径（PR 评论也挂在 issues/<n> 下，写成 /pull/ 就是手打错了）
    '',
  ]) {
    assert.throws(() => buildDisposition({ reason: 'malware', by: bad, id: 'a' }), /issuecomment/, `${bad} 应该被拒`);
  }
});

test('main：--by 形状不对时退出 2 并告诉人 URL 怎么拿，绝不落盘', () => {
  const s = sandbox();
  const lines = [];
  const io = { log: (m) => lines.push(String(m)), error: (m) => lines.push(String(m)) };
  const rc = main(['--id', 'mod_x', '--reason', 'malware', '--by', 'gh:me@issuecomment-9', '--ledger', s.ledgerPath, '--index', s.indexPath], io);
  assert.equal(rc, 2);
  assert.ok(lines.some((l) => l.includes('html_url')), '报错要顺手给出拿 URL 的办法');
  assert.equal(fs.existsSync(s.ledgerPath), false, '一条都不该写下去');
  fs.rmSync(s.dir, { recursive: true, force: true });
});
