#!/usr/bin/env node
/**
 * validate-index.mjs
 *
 * 校验 json/modules.json 能被我们的解析器吃下：
 *   顶层 { name, lastUpdate, modules[] }
 *   每个模块 { id, name, author, description, versions[], verified }
 *   每个版本 { version, versionCode, zipUrl(非空), size, time, sha256 }
 * 外加：id 唯一、versionCode 唯一、sha256 合法、zipUrl 非空且为 http(s)。
 *
 * 用法：node scripts/validate-index.mjs [文件路径]
 * 退出码 0 = 通过，1 = 有错误。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_INDEX = path.join(REPO_ROOT, 'json', 'modules.json');

const SHA256_RE = /^[0-9a-fA-F]{64}$/;

export function validateIndex(doc) {
  const errors = [];
  const push = (m) => errors.push(m);

  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    push('顶层必须是一个 JSON 对象');
    return { ok: false, errors, moduleCount: 0, versionCount: 0 };
  }
  if (typeof doc.name !== 'string' || doc.name.trim() === '') push('顶层缺少 name');
  if (!Array.isArray(doc.modules)) {
    push('顶层缺少 modules 数组（GitHub Pages 第一天就要返回 200，空数组也算通过）');
    return { ok: false, errors, moduleCount: 0, versionCount: 0 };
  }
  if (typeof doc.lastUpdate !== 'number') push('顶层缺少 lastUpdate（数字）');

  const seenIds = new Map();
  let versionCount = 0;

  doc.modules.forEach((m, i) => {
    const at = `modules[${i}]`;
    if (m === null || typeof m !== 'object' || Array.isArray(m)) {
      push(`${at} 不是对象`);
      return;
    }
    for (const f of ['id', 'name', 'author', 'description']) {
      if (typeof m[f] !== 'string' || m[f].trim() === '') push(`${at} 缺少/为空字段 ${f}`);
    }
    if (typeof m.id === 'string') {
      if (seenIds.has(m.id)) push(`${at} id 重复：${m.id}（另见 modules[${seenIds.get(m.id)}]）`);
      else seenIds.set(m.id, i);
    }
    if (typeof m.verified !== 'boolean') push(`${at} verified 必须是布尔值`);

    if (!Array.isArray(m.versions)) {
      push(`${at} 缺少 versions 数组`);
      return;
    }
    if (m.versions.length === 0) push(`${at} versions 为空`);

    const seenCodes = new Set();
    m.versions.forEach((v, j) => {
      const vat = `${at}.versions[${j}]`;
      versionCount += 1;
      if (v === null || typeof v !== 'object') {
        push(`${vat} 不是对象`);
        return;
      }
      if (typeof v.version !== 'string' || v.version.trim() === '') push(`${vat} 缺少 version`);
      if (!Number.isInteger(v.versionCode)) push(`${vat} versionCode 必须是整数`);
      else {
        if (seenCodes.has(v.versionCode)) push(`${vat} versionCode 重复：${v.versionCode}`);
        seenCodes.add(v.versionCode);
      }
      if (typeof v.zipUrl !== 'string' || v.zipUrl.trim() === '') {
        push(`${vat} zipUrl 为空（解析器会直接拒收）`);
      } else if (!/^https?:\/\//i.test(v.zipUrl.trim())) {
        push(`${vat} zipUrl 不是 http(s)：${v.zipUrl}`);
      }
      if (typeof v.size !== 'number' || v.size <= 0) push(`${vat} size 必须是正数`);
      if (typeof v.time !== 'number' || v.time <= 0) push(`${vat} time 必须是正数（毫秒时间戳）`);
      if (typeof v.sha256 !== 'string' || !SHA256_RE.test(v.sha256)) {
        push(`${vat} sha256 必须是 64 位十六进制`);
      }
    });
  });

  return { ok: errors.length === 0, errors, moduleCount: doc.modules.length, versionCount };
}

export function main(argv = process.argv.slice(2)) {
  const target = argv[0] ? path.resolve(argv[0]) : DEFAULT_INDEX;
  if (!fs.existsSync(target)) {
    console.error(`[validate-index] 文件不存在：${target}`);
    return 1;
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(target, 'utf8'));
  } catch (e) {
    console.error(`[validate-index] JSON 解析失败：${e.message}`);
    return 1;
  }

  const r = validateIndex(doc);
  if (r.ok) {
    console.log(`[validate-index] 通过：${target}（${r.moduleCount} 个模块 / ${r.versionCount} 个版本）`);
    return 0;
  }
  console.error(`[validate-index] 失败：${target}`);
  for (const e of r.errors) console.error(`  - ${e}`);
  return 1;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exit(main());
}
