#!/usr/bin/env node
/**
 * build-index.mjs
 *
 * 扫描 pending/**\/*.json（递归，含 pending/<id>/<versionCode>.json 这种
 * Worker 实际产出的嵌套路径），把通过审核的条目合并进 json/modules.json。
 * 纯 Node 实现，只允许 node: 内置模块（这是本仓库的硬性约束）。
 *
 * 合并规则：
 *   1. 按 id 归并。
 *   2. 同 id 已存在 -> 只追加新版本，不覆盖已存在的版本。
 *   3. id + versionCode 相同但 sha256 不同 -> 记为冲突，不覆盖，写进冲突清单交人工。
 *   4. id + versionCode 相同且 sha256 相同 -> 幂等跳过。
 *   5. verified 字段：原样跟随 pending（本站没有人工复核这一档，所以生产上它一直是 false；
 *      要让它变真，得先把「谁有权置真」重新建出来，而不是由投稿者自己填）。
 *
 * 审核标记契约（与 contrib/audit/workflows/audit.yml 的唯一约定面）：
 *   APPROVAL_FIELD / APPROVED_STATUS 两个常量就是契约本身 —— audit.yml 的
 *   publish 步骤把 audit.yml 的 triage 结论写成 { audit: { status: "auto-approved", ... } }，
 *   本文件的 isApproved() 认这个 status 放行。改任一侧都必须同步改这两个常量。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DEFAULT_DISPOSITIONS_FILE, filterVersions, isModuleLevel, loadDispositions, matchAny } from './dispositions.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const PENDING_DIR = path.join(REPO_ROOT, 'pending');
export const INDEX_FILE = path.join(REPO_ROOT, 'json', 'modules.json');
export const CONFLICT_FILE = path.join(REPO_ROOT, 'conflicts.json');
/** 处置台账（下架/拉黑）。它是推导的**输入**，不是索引的附属说明文字。 */
export const DISPOSITIONS_FILE = path.join(REPO_ROOT, DEFAULT_DISPOSITIONS_FILE);

const SHA256_RE = /^[0-9a-fA-F]{64}$/;

/**
 * 酷安站内链接的判据 —— 与 Worker 侧 `contrib/worker/src/index.ts` 的 `coolapkSourceUrl()`
 * 是**同一套语义**：那边是投稿入口的第一道闸，这里是公开产物的最后一道闸。
 *
 * 为什么索引侧还要再守一遍：`json/modules.json` 是公开产物，App 会把 `source` 渲染成一个
 * 可点的链接。只要上游有一处漏校验（改判据、某条分支绕开、老 pending 躺在 main 上没人重跑），
 * `javascript:alert(1)` 这类值就会原样发出去 —— 那不是一个难看的字段，是一次点击即执行。
 * 判据不能只有生产者一份，消费侧也得自己验。**改一侧必须同步改另一侧。**
 *
 * 语义（与 Worker 逐条对齐）：
 *   - 空 / 非字符串 -> ''（调用方据此**省略** `source` 键）
 *   - 没写 scheme（`www.coolapk.com/feed/1`）-> 补 `https://` 再判；老 pending 里存的就是
 *     这种裸值，丢掉它等于把历史投稿的出处整批抹掉
 *   - 只认 http / https（顺带挡掉 `javascript:` / `data:`：它们补成 https 后解析不出合法 host）
 *   - host 必须是 `coolapk.com` 或它的子域；`coolapk.com.evil.com` / `evil.com/coolapk.com/x` 都不算
 *   - 通过返回 `URL#href` 规范化后的**绝对**地址（App 侧直接拿去 openUri）
 */
export function coolapkSourceUrl(raw) {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!v) return '';
  let u;
  try {
    u = new URL(/^https?:\/\//i.test(v) ? v : `https://${v}`);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
  const host = u.hostname.toLowerCase();
  if (host !== 'coolapk.com' && !host.endsWith('.coolapk.com')) return '';
  return u.href;
}

/**
 * 把 pending 里的 `submittedAt` 统一成**毫秒时间戳**。
 *
 * 两种写法都要收，因为真实数据里两种都存在：Worker 的 `buildPendingJson` 写的是 ISO 字符串
 * （`new Date(...).toISOString()`），而索引里其它时间字段（`versions[].time`）与任务口径
 * 都是毫秒数字。输出只有一种：**有限正整数**；认不出来返回 0，调用方据此省略这个键。
 * 绝不写 `null` —— 那会让「字段不在」这条降级判据失效，老 App 读到 null 会以为有值却算不出来。
 */
function submittedAtMs(raw) {
  if (typeof raw === 'number') return Number.isInteger(raw) && raw > 0 ? raw : 0;
  if (typeof raw !== 'string') return 0;
  const s = raw.trim();
  if (!s) return 0;
  // 纯数字字符串按毫秒理解（pending 里两种都出现过，别让 "1700000000000" 走 Date.parse）
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return Number.isInteger(n) && n > 0 ? n : 0;
  }
  const t = Date.parse(s);
  return Number.isInteger(t) && t > 0 ? t : 0;
}

/**
 * 「通过审核」字段契约 —— audit.yml 与 build-index.mjs 双方唯一约定面。
 *
 * audit.yml 的 publish 步骤在 pending JSON 里写入：
 *   { "audit": { "status": "auto-approved", "by": "ci:auto-approved", "at": "…", "risk": "low" } }
 * 这是**唯一**合法的 status：人工放行那一档（`human-approved`）已随「本站只有机器审核」删掉。
 * 删它的安全方向要说清 —— 它只影响**读**：main 上若残留一枚 `human-approved` 的旧章，
 * 现在会被当成没批准，那一条不会进索引（保守 = 不放行），而不是被当成章继续生效。
 *
 * 改这里必须同步改 contrib/audit/workflows/audit.yml 与本仓库 .github/workflows/audit.yml。
 */
export const APPROVAL_FIELD = 'audit';
export const APPROVED_STATUS = 'auto-approved';
export const APPROVED_STATUSES = [APPROVED_STATUS];

/**
 * pending 条目是否为「审核通过」。**只认契约字段 `audit`**，且章上必须有人。
 *
 * 以前这里还认两种快捷写法：`{ approved: true }` 与 `{ review: { approved: true } }`。
 * 它们等于一条绕过审核的后门 —— 任何人（包括将来招募来的贡献者）只要在
 * pending JSON 里手加一个字段，不需要改索引结构、不需要 CI 盖章，就能把包送进索引。
 * 「这一层是唯一的准入」这件事会被它整个作废。
 *
 * 同理，`{ audit: { status: "auto-approved" } }` 这种**没有 by 的无主章**也不算通过：
 * 追责链要回答的是「谁批的」，一个不带署名的章和没有章等价。
 * （`by` 必须可外部复验，判据在 publish-from-main.mjs 的 approvalBy。）
 */
export function isApproved(raw) {
  if (!raw || typeof raw !== 'object') return false;
  const a = raw[APPROVAL_FIELD];
  if (!a || typeof a !== 'object') return false;
  if (!APPROVED_STATUSES.includes(a.status)) return false;
  return typeof a.by === 'string' && a.by.trim() !== '';
}

/** 把 CI 的审核结论写进一个 pending 条目（幂等：重复调用结果相同）。 */
export function markApproved(entry, meta = {}) {
  const out = { ...(entry && typeof entry === 'object' ? entry : {}) };
  out[APPROVAL_FIELD] = {
    ...(out[APPROVAL_FIELD] && typeof out[APPROVAL_FIELD] === 'object' ? out[APPROVAL_FIELD] : {}),
    status: APPROVED_STATUS,
    ...meta,
  };
  return out;
}

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function sameMeta(a, b) {
  return a.name === b.name && a.author === b.author && a.description === b.description;
}

/**
 * 真实 module.prop 里常年缺、但 MMRL 索引又强制非空的字段，缺了**不能拒收**，必须兜底。
 *
 * KernelSU 只强制 module.prop 有 `id/name/version/versionCode`，`author`/`description`
 * 缺失极其常见；App 端 ModuleProp 对缺失字段给空串，Worker 的 buildPendingJson 原样
 * 透传，到本文件这里就是空串。若照旧拒收，后果是：投稿者的 PR 被合并了、CI 也放行
 * 了，但模块永远进不了索引，而且索引里什么都没有、PR 上也没有任何解释 —— 投稿者
 * 无从知道自己为什么失败。所以这里一律补齐，并把补齐动作记进 fallbacks，
 * 由 main() 打到 stdout，CI 再贴回 PR（见 audit.yml 的「把合并结果贴回 PR」步骤）。
 *
 * 兜底顺序：
 *   name        -> id
 *   author      -> uploader（投稿者署名，Worker 侧已强制非空）-> 'unknown'
 *   description -> "<name> <version>"（version 取 versionCode 最大的那个版本）
 *   version     -> "v<versionCode>"
 *
 * 只有 `id` 仍然强制非空：没有 id 无法归并，兜底也无意义。
 *
 * @returns {{ok: true, entry: object, fallbacks: Array<object>} | {ok: false, error: string}}
 */
export function normalizeEntry(raw, source = '<memory>') {
  const fail = (msg) => ({ ok: false, error: `${source}: ${msg}` });
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return fail('条目不是对象');

  if (!isNonEmptyString(raw.id)) return fail('缺少字段 id');

  const fallbacks = [];
  /** 记一次兜底并返回值：补齐过的字段必须让调用方（和投稿者）看得见。 */
  const fallback = (field, to, from) => {
    fallbacks.push({ field, from, to });
    return to;
  };

  const id = raw.id.trim();
  const name = isNonEmptyString(raw.name) ? raw.name.trim() : fallback('name', id, 'id');

  if (!Array.isArray(raw.versions) || raw.versions.length === 0) {
    return fail('versions 必须是非空数组');
  }

  const versions = [];
  for (const v of raw.versions) {
    if (!v || typeof v !== 'object') return fail('version 不是对象');
    // versionCode 必须先校验：version 的兜底值 "v<versionCode>" 依赖它。
    if (!Number.isInteger(v.versionCode)) {
      return fail(`versionCode 不是整数：${JSON.stringify(v.versionCode)}`);
    }
    const version = isNonEmptyString(v.version)
      ? v.version.trim()
      : fallback('version', `v${v.versionCode}`, `versionCode=${v.versionCode}`);
    if (!isNonEmptyString(v.zipUrl)) return fail(`version ${version} 的 zipUrl 为空`);
    if (typeof v.size !== 'number' || !Number.isFinite(v.size)) return fail(`version ${version} 的 size 不是数字`);
    if (typeof v.time !== 'number' || !Number.isFinite(v.time)) return fail(`version ${version} 的 time 不是数字`);
    if (!isNonEmptyString(v.sha256) || !SHA256_RE.test(v.sha256)) {
      return fail(`version ${version} 的 sha256 不是 64 位十六进制`);
    }
    versions.push({
      version,
      versionCode: v.versionCode,
      zipUrl: v.zipUrl,
      size: v.size,
      time: v.time,
      sha256: v.sha256.toLowerCase(),
    });
  }

  const uploader = isNonEmptyString(raw.uploader) ? raw.uploader.trim() : '';
  const author = isNonEmptyString(raw.author)
    ? raw.author.trim()
    : fallback('author', uploader || 'unknown', uploader ? 'uploader' : '常量 unknown');

  // description 兜底串里带上版本号，比单纯复读模块名有用得多。
  const latest = versions.reduce((a, b) => (b.versionCode > a.versionCode ? b : a), versions[0]);
  const description = isNonEmptyString(raw.description)
    ? raw.description.trim()
    : fallback('description', `${name} ${latest.version}`, 'name + version');

  // ── 出处与上传者（App 的「酷安模块详情页」要显示「从哪个帖子来的、谁传的」） ──────
  // 四格全部可选，且**只写有值的键**：App 用「键在不在」判断要不要渲染出处区，
  // 写成 `null` / `undefined` 会让这条判据失效 —— undefined 还会被 JSON.stringify 静默吞掉，
  // 于是本地看着对、发布产物里又是另一回事。老 pending 没有这些键，走的就是「省略」这条路。
  const sourceUrl = coolapkSourceUrl(raw.source);
  const coolapkUid = isNonEmptyString(raw.coolapkUid) ? raw.coolapkUid.trim() : '';
  const submittedAt = submittedAtMs(raw.submittedAt);

  // `coolapkUid` 进索引就是**公开**的，这一点已由 GOVERNANCE 第 6 节明确授权（条目公开
  // 出处 / 上传者昵称 / 上传者 UID / 提交时间 四格），第 9 节第 2 条同时写清了它的边界：
  // 「某个 moduleId 属于哪个 UID」这张映射随索引公开是可接受的（追责方向与公示页按 uid
  // 公开的口径一致），但**权威归属记录仍只住服务端** —— 索引里这一格是它的公开投影，
  // 用途是让 App 显示一个能点进 `coolapk.com/u/<UID>` 复核的上传者，而不是「谁能发下一版」
  // 的判据来源。
  return {
    ok: true,
    fallbacks,
    entry: {
      id,
      name,
      author,
      description,
      ...(sourceUrl ? { source: sourceUrl } : {}),
      ...(uploader ? { uploader } : {}),
      ...(coolapkUid ? { coolapkUid } : {}),
      ...(submittedAt > 0 ? { submittedAt } : {}),
      versions,
      // `verified` 恒等于投稿者自己在 pending JSON 里填的那个布尔，**不是**「复核过」的标记：
      // 本站没有「人工复核通过后置 true」这一档（见 GOVERNANCE 第 1 节），没有谁有权把它置真。
      // 要让它变真，得先把「谁有权置真、凭什么置真」重新建出来，而不是由投稿者自己填一个 true。
      verified: raw.verified === true,
    },
  };
}

/**
 * 合并核心逻辑（纯函数，供单测直接调用）。
 *
 * **处置台账在这里生效，而且是唯一生效的地方。** main() 和 verify-index-pr 的重推导
 * 都只调这个函数，所以「索引 = f(pending, 台账)」这条式子只有一份实现；
 * 判据写在 workflow、Worker 或 main() 里任何别处，都会出现两份结果 ——
 * 要么索引 PR 永远判不一致，要么（更糟）判得过而线上留着已下架的模块。
 *
 * @param {{index?: object, entries: Array<object>, dispositions?: Array<object>}} input
 * @returns {{index: object, conflicts: Array<object>, stats: object, fallbacks: Array<object>, blocked: Array<object>}}
 */
export function buildIndex({ index, entries, dispositions = [] }) {
  const base = index && typeof index === 'object' && !Array.isArray(index) ? index : {};
  const out = {
    name: typeof base.name === 'string' ? base.name : 'SukiSU-Ultra Modules',
    lastUpdate: typeof base.lastUpdate === 'number' ? base.lastUpdate : 0,
    modules: Array.isArray(base.modules) ? base.modules.map((m) => structuredClone(m)) : [],
  };

  const conflicts = [];
  const stats = {
    approved: 0, skipped: 0, invalid: 0, addedModules: 0, addedVersions: 0, conflicts: 0, fallbacks: 0,
    blocked: 0,          // 被台账挡下的投稿条目（不该进索引）
    removedVersions: 0,  // 从既有索引里按台账抹掉的版本（下架生效的那一步）
    removedModules: 0,   // 版本被抹空后连模块一起移除
  };
  // 被台账挡下的清单：CI 要把它贴回 PR / 写进日志，否则「为什么没进索引」无人可读。
  const blocked = [];
  // 补过字段的条目清单：[{ id, fallbacks: [{field, from, to}] }]，供 CI 贴回 PR 解释。
  const allFallbacks = [];
  const byId = new Map(out.modules.map((m) => [m.id, m]));

  for (const raw of entries) {
    if (!isApproved(raw)) {
      stats.skipped += 1;
      continue;
    }
    const n = normalizeEntry(raw, `${raw && raw.id ? raw.id : '<unknown>'}`);
    if (!n.ok) {
      stats.invalid += 1;
      // 非法条目同样计入 conflicts：它就是要交人工的东西，否则 stats.invalid>0
      // 却 stats.conflicts===0，main() 又照样 exit 2 —— 计数自相矛盾，
      // 排查的人只看到「exit 2」却找不到任何冲突记录。
      stats.conflicts += 1;
      conflicts.push({ type: 'invalid-entry', reason: n.error });
      continue;
    }
    const entry = n.entry;

    // 台账命中 → 不合并，且**不进 conflicts**：冲突是「要人判断」，
    // 台账命中是「已经判断过了」，把后者计成前者会让 exit 2 挡住 --consume，
    // 于是下一次重建又被同一批已下架的 pending 卡住（自我堵死）。
    //
    // 匹配用的是**归一化后的条目 + 原始 pending 的 coolapkUid**：条目里那一格是 trim 过、
    // 且值非法（空串 / 非字符串）时会被省略的版本；台账要的是投稿时原样记下的值。
    // 两边不是同一份事实，所以这里显式覆盖回 raw 那一格 —— 少了这行，「按人拉黑」
    // 会在 uid 带空白或类型不对时静默失效：判据看着在跑，其实永远匹配不上。
    const hit = matchAny(dispositions, { ...entry, coolapkUid: raw && raw.coolapkUid });
    if (hit) {
      stats.blocked += 1;
      blocked.push({
        id: entry.id,
        via: hit.via,
        versionCode: hit.versionCode,
        reason: hit.matched.reason,
        by: hit.matched.by,
        at: hit.matched.at,
        raw, // main() 靠这个引用认出它属于哪个 pending 文件，从而**不删**那个文件
      });
      continue;
    }

    stats.approved += 1;
    if (n.fallbacks && n.fallbacks.length > 0) {
      allFallbacks.push({ id: entry.id, fallbacks: n.fallbacks });
      stats.fallbacks += n.fallbacks.length;
    }

    const existing = byId.get(entry.id);
    if (!existing) {
      out.modules.push(structuredClone(entry));
      byId.set(entry.id, out.modules[out.modules.length - 1]);
      stats.addedModules += 1;
      stats.addedVersions += entry.versions.length;
      continue;
    }

    // 同 id：只追加新版本，绝不覆盖已有版本。
    if (!sameMeta(existing, entry)) {
      stats.conflicts += 1;
      conflicts.push({
        type: 'metadata-mismatch',
        id: entry.id,
        existing: { name: existing.name, author: existing.author, description: existing.description },
        incoming: { name: entry.name, author: entry.author, description: entry.description },
        action: '不覆盖，交人工确认',
      });
    }

    for (const v of entry.versions) {
      const hit = existing.versions.find((x) => x.versionCode === v.versionCode);
      if (!hit) {
        existing.versions.push(structuredClone(v));
        stats.addedVersions += 1;
        continue;
      }
      if (hit.sha256 === v.sha256) continue; // 幂等：同一版本同一产物
      stats.conflicts += 1;
      conflicts.push({
        type: 'version-conflict',
        id: entry.id,
        versionCode: v.versionCode,
        existingSha256: hit.sha256,
        incomingSha256: v.sha256,
        existingZipUrl: hit.zipUrl,
        incomingZipUrl: v.zipUrl,
        action: '不覆盖，交人工确认',
      });
    }
  }

  // 台账对**已在索引里的内容**同样生效 —— 这一步才是「下架」本身。
  // 只在合并时挡新条目是不够的：那样台账只能防未来，防不了过去，
  // 下一次重建会把旧版本原样从 base 带回来，看起来「下架过却又活了」。
  // 抹的是版本级：指到具体产物的处置不该连累同 id 的其它版本；版本抹空了才移除模块。
  if (dispositions.length > 0) {
    const moduleLevel = dispositions.filter(isModuleLevel);
    const kept = [];
    for (const m of out.modules) {
      const versionCodes = (Array.isArray(m.versions) ? m.versions : []).map((v) => v.versionCode);
      // 先判模块级：只写 id（或只写 coolapkUid）的处置就是整条下架，
      // 与它有几个版本无关 —— 零版本的模块壳也必须能被清掉。
      const whole = matchAny(moduleLevel, m);
      if (whole) {
        stats.removedModules += 1;
        stats.removedVersions += versionCodes.length;
        blocked.push({
          id: m.id, via: whole.via, removedVersions: versionCodes,
          reason: whole.matched.reason, by: whole.matched.by, at: whole.matched.at,
        });
        continue;
      }
      // 再判产物级：指到 sha256 / versionCode 的只抹那几条。
      const { removed, keptVersions } = filterVersions(dispositions, m);
      if (removed.length === 0) {
        kept.push(m);
        continue;
      }
      stats.removedVersions += removed.length;
      m.versions = keptVersions;
      blocked.push({
        id: m.id, via: removed[0].via, removedVersions: removed.map((r) => r.version.versionCode),
        reason: removed[0].disposition.reason, by: removed[0].disposition.by, at: removed[0].disposition.at,
      });
      if (keptVersions.length === 0) {
        stats.removedModules += 1; // 版本被抹空了，模块壳一并移除
        continue;
      }
      kept.push(m);
    }
    out.modules = kept;
    byId.clear();
    for (const m of out.modules) byId.set(m.id, m);
  }

  // 版本按 versionCode 降序，MMRL 客户端期望最新版在前。
  for (const m of out.modules) {
    m.versions.sort((a, b) => b.versionCode - a.versionCode);
  }
  out.modules.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  if (out.modules.length > 0) out.lastUpdate = Date.now();
  return { index: out, conflicts, stats, fallbacks: allFallbacks, blocked };
}

function isPendingJson(name) {
  const f = path.basename(name);
  // 以 . 开头的文件视为文档/示例，不参与合并（如 pending/.example.json）。
  return f.toLowerCase().endsWith('.json') && !f.startsWith('.');
}

/**
 * 递归收集 pending 目录下的 *.json（含 pending/<id>/<versionCode>.json）。
 *
 * Worker 开 PR 时写的是嵌套路径（见 contrib/worker/src/index.ts openPendingPr），
 * 顶层 readdirSync 一律读不到，所以必须递归。同时跳过 node_modules 等噪声目录。
 * @returns {Array<{file: string, rel: string, entries: Array<object>}>}
 */
export function collectPendingFiles(dir) {
  const out = [];
  const walk = (cur, depth) => {
    if (depth > 8) return; // 防御：避免异常深的目录把栈跑爆
    let names;
    try {
      names = fs.readdirSync(cur);
    } catch {
      return;
    }
    names.sort();
    for (const name of names) {
      const full = path.join(cur, name);
      let st;
      try {
        st = fs.statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (name === 'node_modules' || name.startsWith('.')) continue;
        walk(full, depth + 1);
        continue;
      }
      if (!isPendingJson(name)) continue;
      let entries = null;
      try {
        const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
        entries = Array.isArray(parsed) ? parsed : [parsed];
      } catch (e) {
        console.error(`[build-index] 跳过 ${path.relative(dir, full)}：JSON 解析失败 - ${e.message}`);
        continue;
      }
      out.push({ file: full, rel: path.relative(dir, full).split(path.sep).join('/'), entries });
    }
  };
  if (fs.existsSync(dir)) walk(dir, 0);
  return out;
}

/**
 * 解析 argv。
 *   --dry-run              只打印会发生什么，不写文件
 *   --consume              成功后删除已处理的 pending 条目；存在冲突或非法条目时自动跳过删除，
 *                          绝不在现场还有人看得懂之前把 pending 清掉（见 main() 里的删除块注释）
 *   --pending <dir>        指定 pending 目录（默认 <repo>/pending）
 *   --index <file>         指定索引文件（默认 <repo>/json/modules.json）
 *   --dispositions <file>  指定处置台账（默认 <repo>/json/dispositions.json；不存在=空台账）
 */
export function parseArgs(argv) {
  const opts = {
    dryRun: false,
    consume: false,
    pendingDir: PENDING_DIR,
    indexFile: INDEX_FILE,
    dispositionsFile: DISPOSITIONS_FILE,
    _: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') { opts.dryRun = true; continue; }
    if (a === '--consume') { opts.consume = true; continue; }
    if (a === '--pending' && i + 1 < argv.length) { opts.pendingDir = path.resolve(argv[++i]); continue; }
    if (a === '--index' && i + 1 < argv.length) { opts.indexFile = path.resolve(argv[++i]); continue; }
    if (a === '--dispositions' && i + 1 < argv.length) { opts.dispositionsFile = path.resolve(argv[++i]); continue; }
    opts._.push(a);
  }
  return opts;
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const pendingDir = opts.pendingDir;
  const indexFile = opts.indexFile;

  // 台账坏了必须**停下来**，不能当空台账继续：后者等于「一次坏 JSON 把所有下架抹掉」，
  // 而被下架的模块重新出现在索引里是无声的、没人会去查的动作。
  let dispositions;
  try {
    dispositions = loadDispositions(opts.dispositionsFile);
  } catch (e) {
    console.error(`[build-index] 处置台账读不懂，停止合并（不当空台账处理）：${e.message}`);
    return 3;
  }

  const current = fs.existsSync(indexFile)
    ? JSON.parse(fs.readFileSync(indexFile, 'utf8'))
    : { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] };

  const files = collectPendingFiles(pendingDir);
  const entries = [];
  for (const item of files) for (const e of item.entries) entries.push(e);
  const { index, conflicts, stats, fallbacks, blocked } = buildIndex({ index: current, entries, dispositions });

  if (!opts.dryRun) {
    fs.mkdirSync(path.dirname(indexFile), { recursive: true });
    fs.writeFileSync(indexFile, `${JSON.stringify(index, null, 2)}\n`, 'utf8');
    if (conflicts.length > 0) {
      fs.writeFileSync(CONFLICT_FILE, `${JSON.stringify(conflicts, null, 2)}\n`, 'utf8');
    } else if (fs.existsSync(CONFLICT_FILE)) {
      fs.rmSync(CONFLICT_FILE);
    }
    if (opts.consume) {
      // 递归删除：嵌套的 pending/<id>/<versionCode>.json 也要清掉，
      // 空掉的 <id>/ 目录顺手移除，否则下次 --consume 会看到一堆空目录。
      //
      // 但只要有冲突或非法条目就一律不删。这里曾经不看冲突直接删，后果是：
      // 退出码 2、冲突根本没解决、pending/<id>/ 整个消失 —— 投稿数据没了，
      // 而冲突清单里那一条从此无从追溯。重复处理只是噪音，静默丢投稿是事故。
      // 宁可让一个坏条目挡住整批清理，也不能在有人还看得懂现场之前把现场清掉。
      if (conflicts.length > 0 || stats.invalid > 0) {
        console.log(
          `[build-index] 已跳过 --consume：有 ${conflicts.length} 条冲突 / ${stats.invalid} 条非法条目未解决，` +
            `pending 文件全部保留，请人工处理后再重跑`,
        );
      } else {
        // 被台账挡下的条目**不删**。两个理由：
        //   1) 删了就等于把「为什么这条没进索引」的现场销毁 —— 台账可以事后被改，
        //      而 pending 一旦没了就无从复核；
        //   2) 重推导（verify-index-pr）比的是「base 索引 + 被消费的已批准条目」，
        //      悄悄多删一批文件会让 base 的起算点漂移，判据随之失去意义。
        // 留着它也不会自我堵死：过滤是 (pending, 台账) 的函数，同一批条目每次都被同样挡下，
        // 索引不再变化，因此不会反复触发重建。
        const blockedRaw = new Set(blocked.filter((b) => b.raw).map((b) => b.raw));
        let kept = 0;
        for (const item of files) {
          if (item.entries.some((e) => blockedRaw.has(e))) {
            kept += 1;
            continue;
          }
          fs.rmSync(item.file);
        }
        if (kept > 0) {
          console.log(`[build-index] --consume：保留 ${kept} 个被处置台账挡下的 pending 文件（不删，留作复核现场）`);
        }
        for (const d of fs.existsSync(pendingDir) ? fs.readdirSync(pendingDir) : []) {
          const full = path.join(pendingDir, d);
          try {
            if (fs.statSync(full).isDirectory() && fs.readdirSync(full).length === 0) fs.rmdirSync(full);
          } catch { /* 非空或已不存在，忽略 */ }
        }
      }
    }
  }

  console.log(
    `[build-index] 扫描 ${files.length} 个 pending 文件（${pendingDir}，递归）；` +
      `通过审核 ${stats.approved} / 未通过 ${stats.skipped} / 非法 ${stats.invalid} / 台账挡下 ${stats.blocked}；` +
      `新增模块 ${stats.addedModules}，追加版本 ${stats.addedVersions}，` +
      `台账抹掉版本 ${stats.removedVersions}（模块整条移除 ${stats.removedModules}），冲突 ${stats.conflicts}`,
  );
  if (files.length === 0) {
    console.log('[build-index] 没有待合并的 pending 条目，索引保持不变');
  }

  // 每一条挡下/抹掉都要说清「哪条台账、谁下的、什么时候」——
  // 处置生效必须是可见的，否则投稿者只看到「合并了但索引里没有」，
  // 而维护者也无法复核下架有没有越权（只指到一个产物却抹掉了整个模块）。
  if (blocked.length > 0) {
    console.log(`[build-index] 处置台账命中 ${blocked.length} 条：`);
    for (const b of blocked) {
      const vcs = b.removedVersions ? ` 抹掉版本 ${b.removedVersions.join(',')}` : b.versionCode ? ` 版本 ${b.versionCode}` : '';
      console.log(`  - ${b.id}${vcs} via ${b.via}｜reason=${b.reason}｜by=${b.by}｜at=${b.at}`);
    }
  }

  // 兜底必须说出来。以前缺 author/description/version 是「静默拒收」：
  // 索引里什么都没有、PR 上也没有任何解释，投稿者不知道自己为什么失败。
  // 现在补齐的同时把「缺 X -> 已用 Y 补齐」打到 stdout，CI 把它贴回 PR。
  if (fallbacks.length > 0) {
    console.log(`[build-index] 已为 ${fallbacks.length} 个条目兜底补齐缺失字段（module.prop 只强制 id/name/version/versionCode）：`);
    for (const f of fallbacks) {
      const parts = f.fallbacks.map((x) => `缺 ${x.field} -> 用 ${x.to}（取自 ${x.from}）`).join('；');
      console.log(`  - ${f.id}：${parts}`);
    }
  }

  if (conflicts.length > 0) {
    console.log(`[build-index] 冲突清单 -> ${CONFLICT_FILE}`);
    for (const c of conflicts) console.log(`  - ${c.type}: ${JSON.stringify(c)}`);
    if (!opts.dryRun && !opts.consume) {
      console.log('[build-index] pending 文件保留未删，请人工处理冲突后重跑');
    }
  }
  if (opts.dryRun) console.log('[build-index] --dry-run：未写入任何文件');
  return conflicts.length > 0 ? 2 : 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exit(main());
}
