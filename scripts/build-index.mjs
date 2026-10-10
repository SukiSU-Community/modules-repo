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
 *   5. verified 字段：自动放行的条目一律 false（人工复核后才置 true）。
 *
 * 审核标记契约（与 contrib/audit/workflows/audit.yml 的唯一约定面）：
 *   APPROVAL_FIELD / APPROVED_STATUS 两个常量就是契约本身 —— audit.yml 的
 *   publish 步骤把 audit.yml 的 triage 结论写成 { audit: { status: "auto-approved", ... } }，
 *   本文件的 isApproved() 认这个 status 放行。改任一侧都必须同步改这两个常量。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const PENDING_DIR = path.join(REPO_ROOT, 'pending');
export const INDEX_FILE = path.join(REPO_ROOT, 'json', 'modules.json');
export const CONFLICT_FILE = path.join(REPO_ROOT, 'conflicts.json');

const SHA256_RE = /^[0-9a-fA-F]{64}$/;

/**
 * 「通过审核」字段契约 —— audit.yml 与 build-index.mjs 双方唯一约定面。
 *
 * audit.yml 的 publish 步骤在 pending JSON 里写入：
 *   { "audit": { "status": "auto-approved", "by": "ci:auto-approved", "at": "…", "risk": "low" } }
 * 人工放行写的是同一个字段、不同的 status：
 *   { "audit": { "status": "human-approved", "by": "gh:<login>@<reviewId>", … } }
 *
 * 改这里必须同步改 contrib/audit/workflows/audit.yml 与本仓库 .github/workflows/audit.yml。
 */
export const APPROVAL_FIELD = 'audit';
export const APPROVED_STATUS = 'auto-approved';
export const HUMAN_APPROVED_STATUS = 'human-approved';
export const APPROVED_STATUSES = [APPROVED_STATUS, HUMAN_APPROVED_STATUS];

/**
 * pending 条目是否为「审核通过」。**只认契约字段 `audit`**，且章上必须有人。
 *
 * 以前这里还认两种快捷写法：`{ approved: true }` 与 `{ review: { approved: true } }`。
 * 它们等于一条绕过审核的后门 —— 任何人（包括将来招募来的贡献者）只要在
 * pending JSON 里手加一个字段，不需要改索引结构、不需要 CI 盖章，就能把包送进索引。
 * 「已收录模块的版本更新一律人工审核」这条核心防线会被它整个作废。
 *
 * 同理，`{ audit: { status: "auto-approved" } }` 这种**没有 by 的无主章**也不算通过：
 * 追责链要回答的是「谁批的」，一个不带署名的章和没有章等价。
 * （`by` 可外部复验 —— 那是 P4 双签要加严的地方，这里先把「有没有署名字段」钉住。）
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

  return {
    ok: true,
    fallbacks,
    entry: {
      id,
      name,
      author,
      description,
      versions,
      // 自动放行一律未复核；人工复核通过后再置 true。
      verified: raw.verified === true,
    },
  };
}

/**
 * 合并核心逻辑（纯函数，供单测直接调用）。
 *
 * @param {{index?: object, entries: Array<object>}} input
 * @returns {{index: object, conflicts: Array<object>, stats: object, fallbacks: Array<object>}}
 */
export function buildIndex({ index, entries }) {
  const base = index && typeof index === 'object' && !Array.isArray(index) ? index : {};
  const out = {
    name: typeof base.name === 'string' ? base.name : 'SukiSU-Ultra Modules',
    lastUpdate: typeof base.lastUpdate === 'number' ? base.lastUpdate : 0,
    modules: Array.isArray(base.modules) ? base.modules.map((m) => structuredClone(m)) : [],
  };

  const conflicts = [];
  const stats = { approved: 0, skipped: 0, invalid: 0, addedModules: 0, addedVersions: 0, conflicts: 0, fallbacks: 0 };
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
    stats.approved += 1;
    const entry = n.entry;
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

  // 版本按 versionCode 降序，MMRL 客户端期望最新版在前。
  for (const m of out.modules) {
    m.versions.sort((a, b) => b.versionCode - a.versionCode);
  }
  out.modules.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  if (out.modules.length > 0) out.lastUpdate = Date.now();
  return { index: out, conflicts, stats, fallbacks: allFallbacks };
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
 */
export function parseArgs(argv) {
  const opts = { dryRun: false, consume: false, pendingDir: PENDING_DIR, indexFile: INDEX_FILE, _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') { opts.dryRun = true; continue; }
    if (a === '--consume') { opts.consume = true; continue; }
    if (a === '--pending' && i + 1 < argv.length) { opts.pendingDir = path.resolve(argv[++i]); continue; }
    if (a === '--index' && i + 1 < argv.length) { opts.indexFile = path.resolve(argv[++i]); continue; }
    opts._.push(a);
  }
  return opts;
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const pendingDir = opts.pendingDir;
  const indexFile = opts.indexFile;

  const current = fs.existsSync(indexFile)
    ? JSON.parse(fs.readFileSync(indexFile, 'utf8'))
    : { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] };

  const files = collectPendingFiles(pendingDir);
  const entries = [];
  for (const item of files) for (const e of item.entries) entries.push(e);
  const { index, conflicts, stats, fallbacks } = buildIndex({ index: current, entries });

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
        for (const item of files) fs.rmSync(item.file);
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
      `通过审核 ${stats.approved} / 未通过 ${stats.skipped} / 非法 ${stats.invalid}；` +
      `新增模块 ${stats.addedModules}，追加版本 ${stats.addedVersions}，冲突 ${stats.conflicts}`,
  );
  if (files.length === 0) {
    console.log('[build-index] 没有待合并的 pending 条目，索引保持不变');
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
