// apply-audit-bundle.mjs 的单测 —— 它是公开仓把私有审核引擎落盘的唯一入口，
// 重点验证：路径逃逸、逐文件 sha、总摘要、原子替换四道闸。
// 运行：node --test test/apply-audit-bundle.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SCRIPT = path.resolve(import.meta.dirname, '../scripts/apply-audit-bundle.mjs');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function bundleOf(files) {
  const normalized = files.map((f) => {
    const bytes = Buffer.from(f.content, 'utf8');
    return { path: f.path, mode: f.mode || '100644', sha256: sha256(bytes), content: bytes.toString('base64') };
  });
  const digest = sha256(normalized.map((f) => `${f.path}\0${f.sha256}`).join('\n'));
  return { ok: true, repo: 'SukiSU-Community/modules-backend', ref: 'main', commit: 'a'.repeat(40), files: normalized, digest };
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'apply-audit-bundle-'));
}

function run(bundle, target) {
  const dir = tmpdir();
  const bundlePath = path.join(dir, 'bundle.json');
  fs.writeFileSync(bundlePath, JSON.stringify(bundle));
  const r = spawnSync(process.execPath, [SCRIPT, bundlePath, target], { encoding: 'utf8' });
  return { ...r, stdout: r.stdout || '', stderr: r.stderr || '' };
}

test('正常包：逐文件落盘并替换旧 audit 目录', () => {
  const target = tmpdir();
  fs.mkdirSync(path.join(target, 'audit'), { recursive: true });
  fs.writeFileSync(path.join(target, 'audit', 'stale.mjs'), 'old');
  const r = run(bundleOf([
    { path: 'audit/scan.mjs', content: 'export const x = 1;\n' },
    { path: 'audit/lib/rules.mjs', content: 'export const y = 2;\n' },
  ]), target);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(path.join(target, 'audit', 'scan.mjs'), 'utf8'), 'export const x = 1;\n');
  assert.equal(fs.readFileSync(path.join(target, 'audit', 'lib', 'rules.mjs'), 'utf8'), 'export const y = 2;\n');
  assert.equal(fs.existsSync(path.join(target, 'audit', 'stale.mjs')), false, '旧目录必须被整体替换');
});

test('路径逃逸：audit/../x 被拒，旧 audit 目录保持原样', () => {
  const target = tmpdir();
  fs.mkdirSync(path.join(target, 'audit'), { recursive: true });
  fs.writeFileSync(path.join(target, 'audit', 'keep.txt'), 'keep');
  const r = run(bundleOf([{ path: 'audit/../evil.mjs', content: 'x' }]), target);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /非法路径段/);
  assert.equal(fs.readFileSync(path.join(target, 'audit', 'keep.txt'), 'utf8'), 'keep');
  assert.equal(fs.existsSync(path.join(target, 'evil.mjs')), false);
});

test('非 audit/ 前缀被拒', () => {
  const target = tmpdir();
  const r = run(bundleOf([{ path: 'scripts/scan.mjs', content: 'x' }]), target);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /不属于 audit/);
});

test('单文件 sha256 不匹配被拒', () => {
  const target = tmpdir();
  const bundle = bundleOf([{ path: 'audit/scan.mjs', content: 'good' }]);
  // 先篡改文件哈希，再把总摘要改回「自洽」——让检查落到逐文件那一道闸。
  bundle.files[0].sha256 = '0'.repeat(64);
  bundle.digest = sha256(bundle.files.map((f) => `${f.path}\0${f.sha256}`).join('\n'));
  const r = run(bundle, target);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /sha256 不匹配/);
});

test('总摘要不匹配被拒', () => {
  const target = tmpdir();
  const bundle = bundleOf([{ path: 'audit/scan.mjs', content: 'good' }]);
  bundle.digest = '0'.repeat(64);
  const r = run(bundle, target);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /总摘要不匹配/);
});

test('空包被拒', () => {
  const target = tmpdir();
  const r = run({ ok: true, files: [], digest: '' }, target);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /没有文件/);
});
