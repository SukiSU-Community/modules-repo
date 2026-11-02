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
 * 仓库相关字段（契约 §1）**全部可选** —— 老模块没有它们不该判失败；但只要出现就必须
 * 是**归一化后**的形状：`repoUrl` 是等值匹配的锚（`http://`、`.../tree/main`、
 * 大小写不同的域名都永远对不上 App 的绿标与复验状态），`repoDigest` 必须与 `sha256`
 * 是同一个字节摘要，`repoCoversLatest` 必须与最新版本相符（它是派生键，手改索引时
 * 最容易留下一句错话）。
 *
 * 作者主页两格（`authorCoolapkUrl` / `authorGithubUrl`，契约 §3 / §5.4）同样可选，
 * 但出现就必须是**归一化后的**固定形状：它们会被渲染成可点链接，`http://`、裸域名、
 * 尾斜杠这类值说明有人绕过了 build-index 直接改索引。
 *
 * 用法：node scripts/validate-index.mjs [文件路径]
 * 退出码 0 = 通过，1 = 有错误。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { normalizeAuthorCoolapkUrl, normalizeAuthorGithubUrl } from './lib/author-links.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_INDEX = path.join(REPO_ROOT, 'json', 'modules.json');

const SHA256_RE = /^[0-9a-fA-F]{64}$/;
/** 归一化后的仓库地址形状（与 build-index.mjs 的 normalizeRepoUrl 输出一致）。 */
const REPO_URL_RE = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]{1,100}$/;
const REPO_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const AUTO_VIAS = ['repo', 'update-json'];
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

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

    // ── 作者主页（契约 §3 / §5.4）─────────────────────────────────────────────
    // 两格可选：老条目没有它们是正常的（§5.5 不回溯、不猜）。但只要出现，就必须**已经是**
    // 归一化形状 —— `http://`、裸域名、尾斜杠、`www.github.com`、保留路径这些在 §3 里都是
    // 不合格的输入，出现在公开索引里只说明有人绕过 build-index 手改过。判据直接复用生产端
    // 那份归一化函数：这里校验的是「它是不是一个不动点」，两边不会漂。
    for (const [field, normalize, shape] of [
      ['authorCoolapkUrl', normalizeAuthorCoolapkUrl, 'https://www.coolapk.com/u/<4-12 位数字>'],
      ['authorGithubUrl', normalizeAuthorGithubUrl, 'https://github.com/<用户名>'],
    ]) {
      if (!hasOwn(m, field)) continue;
      const v = m[field];
      if (typeof v !== 'string' || v.trim() === '' || normalize(v) !== v) {
        push(`${at} ${field} 必须是归一化后的 ${shape}：${JSON.stringify(v).slice(0, 80)}`);
      }
    }

    // ── 源码仓库 / 自更新地址（契约 §1）─────────────────────────────────────
    // 全部可选：老模块没有这些键是正常的。但只要出现就必须成组、必须是归一化形状 ——
    // 「有地址没结论」会在 App 侧渲染成一个既绿又灰的状态，比不显示更糟。
    if (hasOwn(m, 'repoUrl')) {
      if (typeof m.repoUrl !== 'string' || !REPO_URL_RE.test(m.repoUrl)) {
        push(`${at} repoUrl 必须是归一化后的 https://github.com/<owner>/<repo>：${String(m.repoUrl).slice(0, 80)}`);
      }
      if (typeof m.repoVerified !== 'boolean') push(`${at} repoUrl 存在时 repoVerified 必须是布尔值`);
      if (typeof m.repoCheckedAt !== 'number' || !Number.isFinite(m.repoCheckedAt) || m.repoCheckedAt <= 0) {
        push(`${at} repoUrl 存在时 repoCheckedAt 必须是正数毫秒时间戳`);
      }
    } else {
      for (const f of ['repoVerified', 'repoCheckedAt', 'repoLicense', 'repoCoversLatest']) {
        if (hasOwn(m, f)) push(`${at} 没有 repoUrl 却带着 ${f} —— 仓库派生字段不能脱离仓库存在`);
      }
    }
    if (hasOwn(m, 'repoLicense')
      && (typeof m.repoLicense !== 'string' || m.repoLicense.trim() === '' || m.repoLicense.trim().length > 64)) {
      push(`${at} repoLicense 必须是非空 SPDX 字符串（≤64；无 LICENSE 请省略这个键）`);
    }
    if (hasOwn(m, 'repoCoversLatest') && typeof m.repoCoversLatest !== 'boolean') {
      push(`${at} repoCoversLatest 必须是布尔值`);
    }
    if (hasOwn(m, 'updateJson')) {
      const uj = m.updateJson;
      if (typeof uj !== 'string' || uj.trim() === '' || uj.length > 2048 || !/^https?:\/\//i.test(uj.trim())) {
        push(`${at} updateJson 必须是 http(s) 绝对地址（≤2048；没有就省略这个键）`);
      }
    }

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

      // ── 版本级仓库证据（契约 §1）──
      const hasTag = hasOwn(v, 'repoTag');
      if (hasTag && (typeof v.repoTag !== 'string' || v.repoTag.trim() === '' || v.repoTag.trim().length > 256)) {
        push(`${vat} repoTag 必须是非空字符串（≤256）：${JSON.stringify(v.repoTag)}`);
      }
      if (hasOwn(v, 'repoDigest')) {
        const d = v.repoDigest;
        if (typeof d !== 'string' || !REPO_DIGEST_RE.test(d)) {
          // 小写是硬要求：CI 的 §3.3 守卫与 App 侧都拿它做**字符串**比较。
          push(`${vat} repoDigest 必须是 sha256:<64 位小写十六进制>：${String(d).slice(0, 80)}`);
        } else if (typeof v.sha256 === 'string' && SHA256_RE.test(v.sha256) && d !== `sha256:${v.sha256.toLowerCase()}`) {
          push(`${vat} repoDigest 与 sha256 不是同一个包（repoDigest=${d.slice(0, 20)}…，sha256=${v.sha256.slice(0, 16)}…）`);
        }
      }
      if (hasOwn(v, 'auto') && typeof v.auto !== 'boolean') {
        push(`${vat} auto 必须是布尔值（只有自动收录才写 true）`);
      }
      if (hasOwn(v, 'autoVia')) {
        if (AUTO_VIAS.indexOf(v.autoVia) < 0) {
          push(`${vat} autoVia 只能是 ${AUTO_VIAS.join(' | ')}：${JSON.stringify(v.autoVia)}`);
        } else if (v.auto !== true) {
          push(`${vat} 有 autoVia 却没有 auto:true —— 自动收录的标记只说了一半`);
        }
      }
      if (v.auto === true) {
        if (!hasOwn(v, 'repoDigest')) push(`${vat} auto:true 却没有 repoDigest（§3.3 的守卫会拒收）`);
        if (!hasOwn(v, 'autoVia')) push(`${vat} auto:true 却没有 autoVia`);
        else if (v.autoVia === 'repo' && !hasTag) push(`${vat} autoVia=repo 却没有 repoTag`);
      }
    });

    // `repoCoversLatest` 是派生键：必须等于「versionCode 最大的版本有没有 repoTag」。
    // 单独校验它，是因为它最容易被手改留下错话（撤掉一个版本、换了最新版却没重算）。
    if (hasOwn(m, 'repoCoversLatest')) {
      const latestV = m.versions
        .filter((v) => v && typeof v === 'object' && Number.isInteger(v.versionCode))
        .reduce((a, b) => (!a || b.versionCode > a.versionCode ? b : a), null);
      const derived = !!(latestV && typeof latestV.repoTag === 'string' && latestV.repoTag.trim() !== '');
      if (m.repoCoversLatest !== derived) {
        push(`${at} repoCoversLatest=${JSON.stringify(m.repoCoversLatest)} 与最新版本不符（应为 ${derived}）`);
      }
    }
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
