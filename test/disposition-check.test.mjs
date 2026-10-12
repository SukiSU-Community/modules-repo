/**
 * disposition-check.mjs 的单测 —— 三处拦截里 CI 那一道的行为。
 * 运行：node --test test/disposition-check.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { checkFiles, main, parseArgs } from '../scripts/disposition-check.mjs';

const SHA = (c) => c.repeat(64);

function tree({ ledger = null, pendings = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dispcheck-'));
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending'), { recursive: true });
  if (ledger !== null) {
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
      typeof ledger === 'string' ? ledger : JSON.stringify(ledger, null, 2) + '\n', 'utf8');
  }
  const files = [];
  for (const [rel, obj] of Object.entries(pendings)) {
    const full = path.join(dir, 'pending', rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, JSON.stringify(obj, null, 2) + '\n', 'utf8');
    files.push(`pending/${rel}`);
  }
  return { dir, files, ledgerFile: path.join(dir, 'json', 'dispositions.json') };
}

const entry = (over = {}) => ({
  id: 'demo', name: 'Demo', author: 'a', description: 'd', coolapkUid: '10086001',
  audit: { status: 'auto-approved', by: 'ci:x', at: '2026-10-11T00:00:00Z', risk: 'low' },
  versions: [{ version: 'v1', versionCode: 1, zipUrl: 'https://e/1.zip', size: 1, time: 1, sha256: SHA('a') }],
  ...over,
});

const doc = (...list) => ({ schema: 'sukisu-dispositions-v1', dispositions: list });
const stamp = { reason: 'malware', by: 'gh:t@1', at: '2026-10-11T00:00:00Z' };

test('没命中 → clear，且不算失败（台账在场但没轮到这条投稿）', () => {
  const t = tree({ ledger: doc({ kind: 'revoke', id: 'someone-else', ...stamp }), pendings: { 'demo/1.json': entry() } });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, false);
  assert.deepEqual(r.lines, []);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('命中 id → hit，并把「哪条、谁下的、什么时候」全部说清', () => {
  const t = tree({ ledger: doc({ kind: 'revoke', id: 'demo', ...stamp, note: '探针包' }), pendings: { 'demo/1.json': entry() } });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, true);
  assert.match(r.lines[0], /demo 命中 revoke（via id）/);
  assert.match(r.lines[0], /reason=malware/);
  assert.match(r.lines[0], /by=gh:t@1/);
  assert.match(r.lines[0], /note=探针包/);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('换皮重投被 sha256 那条抓住（改了 id 也没用）', () => {
  const t = tree({
    ledger: doc({ kind: 'revoke', sha256: SHA('a'), ...stamp }),
    pendings: { 'brand-new/1.json': entry({ id: 'brand-new' }) },
  });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, true);
  assert.match(r.lines[0], /via sha256/);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('按人拉黑（deny coolapkUid）命中', () => {
  const t = tree({
    ledger: doc({ kind: 'deny', coolapkUid: '10086001', ...stamp, reason: 'impersonation' }),
    pendings: { 'whatever/1.json': entry({ id: 'whatever' }) },
  });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, true);
  assert.match(r.lines[0], /via coolapkUid/);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('台账文件不存在 → 空台账、clear（项目第一天还没有处置记录）', () => {
  const t = tree({ ledger: null, pendings: { 'demo/1.json': entry() } });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, false);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('台账读不懂 → 退出 3，绝不静默当「没命中」（那等于一次坏 JSON 拆掉三道闸）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dispcheck-bad-'));
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending', 'demo'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), '{ 坏掉的台账', 'utf8');
  fs.writeFileSync(path.join(dir, 'pending', 'demo', '1.json'), JSON.stringify(entry()), 'utf8');

  const cwd = process.cwd();
  process.chdir(dir);
  let rc = 0;
  const seen = [];
  try {
    rc = main(['--file', 'pending/demo/1.json'], { log: (s) => seen.push(s), error: (s) => seen.push(s) });
  } finally {
    process.chdir(cwd);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(rc, 3);
  assert.match(seen.join('\n'), /不当「没命中」处理/);
});

test('pending 自己读不懂不算命中，也不静默放过（记数，交给 build-index 记非法条目）', () => {
  const t = tree({ ledger: doc({ kind: 'revoke', id: 'demo', ...stamp }), pendings: {} });
  fs.writeFileSync(path.join(t.dir, 'pending', 'bad.json'), 'not json', 'utf8');
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: ['pending/bad.json'] });
  assert.equal(r.hit, false);
  assert.equal(r.unreadable, 1);
  assert.match(r.lines[0], /读不懂/);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('一个文件里是数组条目：只要其中一条命中就算命中', () => {
  const t = tree({
    ledger: doc({ kind: 'revoke', id: 'bad_one', ...stamp }),
    pendings: { 'multi.json': [entry({ id: 'good_one' }), entry({ id: 'bad_one' })] },
  });
  const r = checkFiles({ cwd: t.dir, ledgerFile: t.ledgerFile, files: t.files });
  assert.equal(r.hit, true);
  assert.match(r.lines[0], /bad_one/);
  fs.rmSync(t.dir, { recursive: true, force: true });
});

test('命中只产结论、不改退出码：红由 approve 判，别让扫描作业因为黑名单而崩掉', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dispcheck-cli-'));
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'pending', 'demo'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify(doc({ kind: 'revoke', id: 'demo', ...stamp }), null, 2), 'utf8');
  fs.writeFileSync(path.join(dir, 'pending', 'demo', '1.json'), JSON.stringify(entry()), 'utf8');
  const out = path.join(dir, 'gh-output.txt');
  fs.writeFileSync(out, '', 'utf8');

  const cwd = process.cwd();
  const saved = process.env.GITHUB_OUTPUT;
  process.chdir(dir);
  process.env.GITHUB_OUTPUT = out;
  try {
    const seen = [];
    const rc = main(['--github-output', '--file', 'pending/demo/1.json'], { log: (s) => seen.push(s), error: (s) => seen.push(s) });
    assert.equal(rc, 0, '命中时这一步仍然成功');
    const written = fs.readFileSync(out, 'utf8');
    assert.match(written, /^hit=hit$/m);
    assert.match(written, /^why=.*reason=malware/m);
    assert.match(seen.join('\n'), /结果=命中/);
  } finally {
    process.chdir(cwd);
    if (saved === undefined) delete process.env.GITHUB_OUTPUT; else process.env.GITHUB_OUTPUT = saved;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('parseArgs：--file 可以重复给，--base 与 --ledger 各取一个值', () => {
  const o = parseArgs(['--base', 'abc', '--ledger', 'L', '--file', 'a.json', '--file', 'b.json', '--github-output']);
  assert.equal(o.base, 'abc');
  assert.equal(o.ledger, 'L');
  assert.deepEqual(o.files, ['a.json', 'b.json']);
  assert.equal(o.githubOutput, true);
});
