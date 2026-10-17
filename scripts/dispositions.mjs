#!/usr/bin/env node
/**
 * dispositions.mjs —— 处置台账（下架 / 拉黑）的唯一判据实现。
 *
 * 为什么必须有这一份，而不是在 build-index、workflow、Worker 各写一遍：
 * 索引 = buildIndex(main 的 pending, main 的台账)。三处若各判各的，就会出现
 * 「CI 说没命中、推导说命中」，而重推导校验（verify-index-pr）恰恰是靠两边一致才放行的 ——
 * 两份实现的结果一旦漂移，要么索引 PR 永远合不进，要么（更糟）线上索引里留着一条已下架的模块。
 *
 * 失效方向一律**往严里设计**：
 *   * 台账读不出来 / schema 不认识 / 任一条目非法 → **抛错**，整次推导失败。
 *     曾经想过「跳过坏条目继续」，但那等于「把一条台账写坏就能让被下架的模块复活」，
 *     而且没有任何地方会红。判红最多冻住索引（上一次的结果继续服务），
 *     静默放过则是下架直接失效 —— 这两个后果不对称。
 *   * 空台账（文件不存在）是**合法状态**：项目第一天就还没有处置记录。
 *     注意这只对「文件不存在」成立；存在但内容坏了必须抛。
 *
 * 纯 node: 内置模块，不许装依赖（本仓库硬约束）。
 */

import fs from 'node:fs';

export const DISPOSITIONS_SCHEMA = 'sukisu-dispositions-v2';
/**
 * v2 相对 v1 只多了两个**可选**字段（`subject` / `evidence`），v1 的条目是 v2 的子集。
 * 所以读的一侧两个都认，写的一侧只写 v2 —— 而 `json/dispositions.json` 里现有的 5 条历史
 * 记录仍然是 v1，不改它们：改一份已经公示过的台账数据，等于用一次「迁移」的名义动处置本身。
 *
 * 这三份字符串的集合必须与 Worker（`contrib/worker/src/dispositions.ts`）和公示页
 * （modules-site `public/scripts/api.js`）**同集合**：Worker 那份遇未知 schema 抛错、
 * 调用侧按放行处理 —— 只升两侧的话，Worker 会静默停止拦截被拒收的包。
 * 钉子：modules-site `tools/selftest.mjs` 与 `worker/src/dispositions.test.ts` 各自跨仓比一次。
 */
export const LEGACY_DISPOSITIONS_SCHEMAS = ['sukisu-dispositions-v1'];
export const KNOWN_DISPOSITIONS_SCHEMAS = [DISPOSITIONS_SCHEMA, ...LEGACY_DISPOSITIONS_SCHEMAS];
export const DEFAULT_DISPOSITIONS_FILE = 'json/dispositions.json';

/** 处置种类。两个都是「挡住」，区别在挡住的是内容还是人。 */
export const KINDS = ['revoke', 'deny'];
/**
 * revoke —— 下架一段内容（按 id / id+versionCode / sha256 命中）。
 * deny    —— 拉黑一个主体或一个 id（按 coolapkUid / id 命中），拒收**未来任何**投稿。
 *
 * 为什么分成两个而不是一个 kind 加开关：判据的**粒度**不同。revoke 命中 sha256 时，
 * 同一个文件换皮投到别的 id 下也要挡；deny 命中 uid 时，这个人投什么都不行。
 * 合成一个就会诱惑人在下架一段坏包时顺手把整个人拉黑。
 */

/** 公示分类：前端按这个分组，所以必须是封闭集合（不许自由发挥）。 */
export const REASONS = [
  'test-probe',   // 流水线验证留下的探针包
  'malware',      // 恶意行为
  'policy',       // 违反本站收录规则（如 curl | sh 一类）
  'copyright',    // 版权/授权争议
  'impersonation',// 冒充他人或既有模块
  'security',     // 会弄坏设备或系统的包
  'abandoned',    // 作者要求下架或长期无人维护且有害
  'other',
];

const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const UID_RE = /^[0-9]{4,12}$/;
/**
 * v2 的 `evidence[].file`：只许指向 §8 固化 job 写出来的那个形状。
 * 写成整串正则而不是「以 evidence/ 开头」是因为这个值会被人当成链接渲染 ——
 * 允许 `../` 或绝对 URL 就等于让台账条目把公示页的点击导向仓库之外。
 */
const EVIDENCE_FILE_RE = /^evidence\/[0-9a-f]{64}\.json$/;
/** `subject.username` 是身份快照里抄来的昵称，不是给人自由发挥的字段。 */
const USERNAME_MAX = 64;
/**
 * 必须带时区偏移（Z 或 ±hh:mm）。
 * 处置记录回答的是「什么时候下的处置」，而 `Date.parse('2026-10-11 00:00:00')` 按**本机时区**
 * 解释 —— 同一份台账在 CI（UTC）和在国内机器（+08）上会差出 8 小时，公示出来的时刻就成了
 * 看谁跑的脚本。宁可让写台账的人多打一个 Z。
 */
const AT_RE = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?)?(Z|[+-]\d{2}:?\d{2})$/;

export class DispositionError extends Error {}

function fail(msg, ctx) {
  throw new DispositionError(ctx ? `${ctx}: ${msg}` : msg);
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim() !== '';
}

/**
 * 校验并归一化一份台账。返回可直接用于匹配的对象数组。
 *
 * @param {unknown} raw  已 JSON.parse 的对象
 * @param {string} ctx   出错信息里的定位前缀（文件路径 / git ref）
 */
export function parseDispositions(raw, ctx = '<memory>') {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    // 「文件不存在」由 loadDispositions 单独处理，走到这里就是存在但读不懂。
    // 这里不能当空台账放过：读不懂 == 不知道现在拉着哪些东西。
    fail('台账必须是对象（{ schema, dispositions: [] }）', ctx);
  }
  if (!KNOWN_DISPOSITIONS_SCHEMAS.includes(raw.schema)) {
    fail(`未知 schema：${JSON.stringify(raw.schema)}（本版本认 ${KNOWN_DISPOSITIONS_SCHEMAS.join(' / ')}）`, ctx);
  }
  if (!Array.isArray(raw.dispositions)) {
    fail('dispositions 必须是数组', ctx);
  }
  const out = [];
  raw.dispositions.forEach((d, i) => out.push(normalizeOne(d, `${ctx} dispositions[${i}]`)));
  return out;
}

function normalizeOne(d, ctx) {
  if (d === null || typeof d !== 'object' || Array.isArray(d)) fail('条目必须是对象', ctx);
  if (!KINDS.includes(d.kind)) fail(`kind 必须是 ${KINDS.join(' / ')}，收到 ${JSON.stringify(d.kind)}`, ctx);

  const hasId = isNonEmptyString(d.id);
  const hasSha = isNonEmptyString(d.sha256);
  const hasUid = isNonEmptyString(d.coolapkUid);
  const hasVc = d.versionCode !== undefined && d.versionCode !== null && d.versionCode !== '';

  // 选择器全空 == 匹配一切。宁可拒绝这条记录，也绝不能让它生效。
  if (!hasId && !hasSha && !hasUid) fail('必须至少给出 id / sha256 / coolapkUid 之一作为选择器', ctx);
  // versionCode 只能跟在 id 后面：脱离 id 的版本号没有任何意义，
  // 若允许它单独存在就会变成「按数字全局下架」，一个常见的 versionCode=1 能扫掉一片。
  if (hasVc && !hasId) fail('versionCode 必须与 id 同时出现', ctx);
  if (hasSha && !SHA256_RE.test(d.sha256.trim())) fail(`sha256 不是 64 位十六进制：${JSON.stringify(d.sha256)}`, ctx);
  if (hasUid && !UID_RE.test(d.coolapkUid.trim())) fail(`coolapkUid 不是 4~12 位数字：${JSON.stringify(d.coolapkUid)}`, ctx);
  if (hasVc && !Number.isFinite(Number(d.versionCode))) fail(`versionCode 不是数字：${JSON.stringify(d.versionCode)}`, ctx);

  // 无主章在追责链上是零价值 —— 与 pending 章 isApproved() 同一条理由。
  if (!isNonEmptyString(d.by)) fail('by 不能为空：下了处置必须留名，且是可回访的指针', ctx);
  if (!isNonEmptyString(d.reason) || !REASONS.includes(d.reason.trim())) {
    fail(`reason 必须是公示分类之一（${REASONS.join(' / ')}），收到 ${JSON.stringify(d.reason)}`, ctx);
  }
  if (!isNonEmptyString(d.at) || !AT_RE.test(String(d.at).trim())) {
    fail('at 必须是带时区的 ISO 8601（结尾 Z 或 ±hh:mm），收到 ' + JSON.stringify(d.at), ctx);
  }

  const norm = {
    kind: d.kind,
    reason: d.reason.trim(),
    by: d.by.trim(),
    at: new Date(String(d.at).trim()).toISOString(),
    note: isNonEmptyString(d.note) ? d.note.trim() : '',
  };
  if (typeof d.verify === 'string' && d.verify.trim()) norm.verify = d.verify.trim();
  if (hasId) norm.id = d.id.trim();
  if (hasSha) norm.sha256 = d.sha256.trim().toLowerCase();
  if (hasUid) norm.coolapkUid = d.coolapkUid.trim();
  if (hasVc) norm.versionCode = Number(d.versionCode);
  // v2 的两个可选字段。**不参与匹配** —— 命中与否仍然只看上面那四个选择器，
  // 这里加了字段就加判据等于悄悄改作用域。
  if (d.subject !== undefined) norm.subject = normalizeSubject(d.subject, ctx);
  if (d.evidence !== undefined) norm.evidence = normalizeEvidence(d.evidence, ctx);
  // 一个人两处名字必须是一个：条目按 coolapkUid 拉黑、人卡按 subject 聚合，
  // 两边不一致就是「把甲的处置挂到乙的头像下面」——公示页不会红，只会指着错的人。
  if (norm.subject && norm.coolapkUid && norm.subject.coolapkUid !== norm.coolapkUid) {
    fail('subject.coolapkUid 与条目选择器 coolapkUid 不一致：要么少写了选择器，要么处置挂错了人', ctx);
  }
  return norm;
}

/**
 * `subject` —— 被处置人的聚合键（人卡按它分组，spec §7.2.7 / §13.4）。
 * 只认 `coolapkUid`（必填）+ `username`（可选，投稿那一刻快照里的昵称）。
 * 不给 uid 就不叫 subject：空对象会让每个人卡都聚到同一个空键下。
 */
function normalizeSubject(raw, ctx) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    fail('subject 必须是对象（{ coolapkUid, username? }）', ctx);
  }
  const uid = isNonEmptyString(raw.coolapkUid) ? raw.coolapkUid.trim() : '';
  if (!uid || !UID_RE.test(uid)) fail(`subject.coolapkUid 必须是 4~12 位数字，收到 ${JSON.stringify(raw.coolapkUid)}`, ctx);
  const out = { coolapkUid: uid };
  if (raw.username !== undefined && raw.username !== null) {
    const name = String(raw.username).trim();
    if (!name) fail('给了 subject.username 就不能是空串（没抓到昵称就别带这个键）', ctx);
    if (name.length > USERNAME_MAX) fail(`subject.username 超过 ${USERNAME_MAX} 字符，收到 ${name.length}`, ctx);
    out.username = name;
  }
  return out;
}

/**
 * `evidence` —— §8 固化 job 写出来的那些文件的指针。
 * 空数组不算「没有证据」而算「固化过了但什么都没捞到」，这两种状态不许写成同一个形状。
 */
function normalizeEvidence(raw, ctx) {
  if (!Array.isArray(raw) || raw.length === 0) {
    fail('evidence 给了就必须是非空数组（没有要固化到的证据就整个别带这个键）', ctx);
  }
  return raw.map((item, i) => {
    const c = `${ctx} evidence[${i}]`;
    if (item === null || typeof item !== 'object' || Array.isArray(item)) fail('evidence 的每一项必须是对象', c);
    const file = isNonEmptyString(item.file) ? item.file.trim() : '';
    if (!EVIDENCE_FILE_RE.test(file)) {
      fail(`evidence.file 必须是 evidence/<64 位十六进制 sha256>.json，收到 ${JSON.stringify(item.file)}`, c);
    }
    const out = { file };
    if (item.pr !== undefined && item.pr !== null) {
      const pr = Number(item.pr);
      if (!Number.isInteger(pr) || pr < 1) fail(`evidence.pr 必须是正整数（承载它的 Issue/PR 号），收到 ${JSON.stringify(item.pr)}`, c);
      out.pr = pr;
    }
    if (item.at !== undefined && item.at !== null) {
      if (!AT_RE.test(String(item.at).trim())) fail(`evidence.at 必须是带时区的 ISO 8601，收到 ${JSON.stringify(item.at)}`, c);
      out.at = new Date(String(item.at).trim()).toISOString();
    }
    return out;
  });
}

/**
 * 从磁盘读台账。文件不存在 == 空台账（合法）；存在但读不懂 == 抛。
 * @param {string} file
 */
export function loadDispositions(file) {
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    fail(`读取失败（${e.code}）`, file);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    fail(`JSON 解析失败 - ${e.message}`, file);
  }
  return parseDispositions(parsed, file);
}

/**
 * 一条处置是否命中一个条目。
 *
 * `entry` 是 pending 条目 / 索引模块对象（有 id、versions[]，可能带 coolapkUid）。
 *
 * **所有给出的选择器必须同时成立（AND）**，不是任一命中（OR）。这一条是被单测逼出来的：
 * 写成 OR 时，「revoke id=demo sha256=<坏产物>」会把 demo 的**所有**版本一起抹掉 ——
 * 写的人明明指到了具体产物，判据却自己扩大成整模块下架。误伤好版本比漏判更难被发现：
 * 投稿者不知道自己被哪一条牵连，台账上又看不出越权。
 * 想「整个 id 下架」就只写 id；想「不管投到哪个 id 都挡」就只写 sha256 ——
 * 少写选择器才是放大作用域的正确方式。
 *
 * @returns {null | {matched: object, via: string, versionCode?: number}}
 */
export function matchDisposition(d, entry) {
  if (!d || !entry || typeof entry !== 'object') return null;
  const id = typeof entry.id === 'string' ? entry.id.trim() : '';
  const uid = typeof entry.coolapkUid === 'string' ? entry.coolapkUid.trim() : '';

  const sel = [];
  if (d.id) {
    if (id !== d.id) return null;
    sel.push('id');
  }
  if (d.coolapkUid) {
    if (!uid || uid !== d.coolapkUid) return null;
    sel.push('coolapkUid');
  }

  // 指到了产物级：必须在 versions 里找到同时满足 sha256 与 versionCode 的那一条。
  if (d.sha256 || d.versionCode !== undefined) {
    const versions = Array.isArray(entry.versions) ? entry.versions : [];
    const hit = versions.find(
      (v) =>
        v &&
        (!d.sha256 || (typeof v.sha256 === 'string' && v.sha256.trim().toLowerCase() === d.sha256)) &&
        (d.versionCode === undefined || Number(v.versionCode) === d.versionCode),
    );
    if (!hit) return null;
    if (d.sha256) sel.push('sha256');
    if (d.versionCode !== undefined) sel.push('versionCode');
    return { matched: d, via: sel.join('+'), versionCode: Number(hit.versionCode) };
  }

  // 没有产物级选择器时，必须至少剩一个主体级选择器（parseDispositions 已挡掉全空，
  // 这里再挡一次：判据不能因为调用方绕过校验就直接生效）。
  if (sel.length === 0) return null;
  return { matched: d, via: sel.join('+') };
}

/** 对一份台账逐条尝试匹配，返回第一个命中（台账顺序即优先级）。 */
export function matchAny(dispositions, entry) {
  for (const d of dispositions || []) {
    const m = matchDisposition(d, entry);
    if (m) return m;
  }
  return null;
}

/**
 * 这条处置是「模块级」还是「产物级」？
 *
 * 产物级（带 sha256 或 versionCode）只能抹掉具体版本；模块级（只写 id / 只写 coolapkUid）
 * 才是整个模块下架。分开是因为**零版本的模块**也要能被下架：
 * 按版本逐个过滤的写法对 `versions: []` 一条都匹配不上，于是「revoke 这个 id」对这种模块
 * 静默无效 —— 而索引里出现零版本模块（历史脏数据、或上一次抹掉最后一个版本留下的壳）
 * 恰恰是最该被下架清掉的东西。
 */
export function isModuleLevel(d) {
  return !!d && !d.sha256 && d.versionCode === undefined;
}

/**
 * 版本级过滤：一个已存在的索引模块要按台账**逐版本**剔除
 * （下架某一条产物不能把整个模块抹掉；抹掉整个模块要用不带 versionCode 的 revoke）。
 *
 * @returns {{removed: Array<object>, keptVersions: Array<object>}}
 */
export function filterVersions(dispositions, module) {
  const product = (dispositions || []).filter((d) => !isModuleLevel(d));
  const removed = [];
  const keptVersions = [];
  for (const v of (module && Array.isArray(module.versions) ? module.versions : [])) {
    const hit = matchAny(product, { id: module.id, versions: [v], coolapkUid: module.coolapkUid });
    if (hit) removed.push({ version: v, via: hit.via, disposition: hit.matched });
    else keptVersions.push(v);
  }
  return { removed, keptVersions };
}
