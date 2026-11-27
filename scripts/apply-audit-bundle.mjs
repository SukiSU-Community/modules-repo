#!/usr/bin/env node
// apply-audit-bundle.mjs —— 把 Worker /audit-bundle 返回的 JSON 落成仓库根 audit/ 目录。
//
// 用法：node scripts/apply-audit-bundle.mjs audit-bundle.json .
// 这个脚本只做三件事：校验路径、逐文件复核 sha256、原子替换 audit/。
// 它不联网、不执行包内代码；真正的审核在落盘之后由 audit.yml 的既有步骤执行。

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

function fail(message) {
  console.error(`apply-audit-bundle: ${message}`);
  process.exit(1);
}

function safeRelativePath(p) {
  if (typeof p !== 'string' || !p) fail('bundle 里有空路径');
  if (p.includes('\\')) fail(`路径含反斜杠：${p}`);
  if (p.startsWith('/') || /^[A-Za-z]:/.test(p)) fail(`绝对路径：${p}`);
  if (!p.startsWith('audit/')) fail(`不属于 audit/：${p}`);
  for (const seg of p.split('/')) {
    if (!seg || seg === '.' || seg === '..') fail(`非法路径段：${p}`);
  }
  return p;
}

const bundlePath = process.argv[2];
const targetRootArg = process.argv[3] || '.';
if (!bundlePath) fail('缺少 bundle 文件参数');

let bundle;
try {
  bundle = JSON.parse(fs.readFileSync(bundlePath, 'utf8'));
} catch (e) {
  fail(`读取 ${bundlePath} 失败：${e.message}`);
}
if (bundle?.ok !== true || !Array.isArray(bundle.files)) {
  fail(`bundle 不是成功结果：${JSON.stringify(bundle).slice(0, 500)}`);
}
if (bundle.files.length === 0) fail('bundle 里没有文件');
if (bundle.files.length > 2000) fail(`bundle 文件数异常：${bundle.files.length}`);

const targetRoot = path.resolve(targetRootArg);
const auditRoot = path.join(targetRoot, 'audit');
const expectedDigest = createHash('sha256')
  .update(bundle.files.map((f) => `${f.path}\0${f.sha256}`).join('\n'))
  .digest('hex');
if (bundle.digest !== expectedDigest) {
  fail(`bundle 总摘要不匹配：期望 ${bundle.digest}，实算 ${expectedDigest}`);
}

const staging = path.join(targetRoot, '.audit-bundle-staging');
fs.rmSync(staging, { recursive: true, force: true });
fs.mkdirSync(staging, { recursive: true });

try {
  for (const file of bundle.files) {
    const rel = safeRelativePath(file.path);
    const bytes = Buffer.from(String(file.content || ''), 'base64');
    const hash = createHash('sha256').update(bytes).digest('hex');
    if (hash !== file.sha256) fail(`sha256 不匹配：${rel}`);
    const out = path.join(staging, rel.slice('audit/'.length));
    if (!out.startsWith(staging + path.sep)) fail(`路径逃逸：${rel}`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, bytes);
    if (file.mode === '100755') fs.chmodSync(out, 0o755);
  }
  fs.rmSync(auditRoot, { recursive: true, force: true });
  fs.renameSync(staging, auditRoot);
} catch (e) {
  fs.rmSync(staging, { recursive: true, force: true });
  fail(e.message);
}

const total = bundle.files.reduce((n, f) => n + Buffer.byteLength(String(f.content || ''), 'base64'), 0);
console.log(`apply-audit-bundle: ${bundle.files.length} 个文件，${total} 字节，commit=${bundle.commit || '?'}, repo=${bundle.repo || '?'}`);
