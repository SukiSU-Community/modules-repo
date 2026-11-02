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
 *   6. 源码仓库（`repoUrl` 与它的结论 `repoVerified/repoCheckedAt/repoLicense`、以及
 *      `updateJson`）是**模块级、可覆盖**的：同 id 再投一版时 incoming 带什么就以什么为准，
 *      因为它来自一次更新的校验。`source` 反过来只补空、不覆盖（第一个帖子是历史事实）。
 *      `repoCoversLatest` 是派生键（最新版有没有仓库证据 `repoTag`），凡有 `repoUrl` 的模块都写。
 *   7. 作者主页（`authorCoolapkUrl` / `authorGithubUrl`，契约 §5.2）也是模块级，但只**补**不撤：
 *      incoming 带了就覆盖，没带就保留旧值 —— 作者这一版没重填，不等于他要撤销那句声明。
 *   8. `json/repo-state.json`（每日复验结论，可选输入）在**合并与下架之后**贴回模块头：
 *      只有 `repoUrl` 完全相等才贴，只贴结论（不动版本、不改已有的 `updateJson`）。
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
import { normalizeAuthorCoolapkUrl, normalizeAuthorGithubUrl } from './lib/author-links.mjs';

// 作者主页的两条判据放在 lib 里，与 validate-index.mjs 共用同一份实现（契约 §5.1 / §5.4）：
// 「生产端这么归一、校验端这么验」必须是同一句话，抄两份必然漂。
export { normalizeAuthorCoolapkUrl, normalizeAuthorGithubUrl };

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const PENDING_DIR = path.join(REPO_ROOT, 'pending');
export const INDEX_FILE = path.join(REPO_ROOT, 'json', 'modules.json');
export const CONFLICT_FILE = path.join(REPO_ROOT, 'conflicts.json');
/** 处置台账（下架/拉黑）。它是推导的**输入**，不是索引的附属说明文字。 */
export const DISPOSITIONS_FILE = path.join(REPO_ROOT, DEFAULT_DISPOSITIONS_FILE);
/** 每日复验结论（可选输入，由 verify-repos 那条流水线产出；文件不存在 = 没有这份状态）。 */
export const REPO_STATE_FILE = path.join(REPO_ROOT, 'json', 'repo-state.json');

const SHA256_RE = /^[0-9a-fA-F]{64}$/;
/** `sha256:` + 64 位小写十六进制 —— 与 §3.3 digest 校验用的是同一个形状。 */
const REPO_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
/** `autoVia` 的合法取值（契约 §1）：机器人从哪儿证明这个包该被自动收录。 */
const AUTO_VIAS = ['repo', 'update-json'];
/** `updateJson` 的长度上限（契约 §3.1）。 */
const UPDATE_JSON_MAX = 2048;
/**
 * owner 段：1-39 位字母数字或连字符，首尾不能是连字符（GitHub 的登录名规则里
 * 「不能连续两个连字符」这条这里不查 —— 它只会让一个更严格的名字被判非法，
 * 而我们要挡的是「不是名字的东西」，不是替 GitHub 做命名审查）。
 */
const REPO_OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * 源码仓库地址的判据 —— 与 Worker 侧 `contrib/worker/src/index.ts` 的 `normalizeRepoUrl()`
 * 是**同一套语义**（契约 §2.1）：那边是投稿入口的第一道闸，这里是公开产物的最后一道闸。
 * 改一侧必须同步改另一侧。
 *
 * 为什么索引侧还要再守一遍：`repoUrl` 是「这个包的字节能在哪个仓库里复核」的唯一锚点，
 * 而 `repoCoversLatest`、复验结论回贴、自动收录全拿它做**等值**匹配。一个没归一化的值
 * （`http://`、`.../tree/main`、`?tab=readme`）不会报错，只会**永远对不上** ——
 * 绿标永远不亮、复验结论永远贴不上，而且没有任何一处日志会说「为什么没生效」。
 *
 * 语义（顺序固定）：
 *   - 非字符串 / 空 -> ''（调用方据此**省略**这个键）
 *   - 必须能解析成 URL；协议必须 https；host 必须恰为 github.com（大小写不敏感）；
 *     不许有端口 / userinfo / query / fragment
 *   - 路径恰好两段 `<owner>/<repo>`（结尾 `/` 折掉；多一段就是 `.../tree/main` 这类）
 *   - repo 结尾的 `.git` 折掉（GitHub 的 clone 地址习惯）
 *   - owner 见 REPO_OWNER_RE；repo 必须是 `[A-Za-z0-9._-]{1,100}` 且不是 `.` / `..`
 *   - 输出 `https://github.com/<owner>/<repo>`，**大小写原样保留**：匹配是等值比较，
 *     擅自 lower 会让索引里显示出来的地址与投稿人填的不是同一个字符串。
 * 归一不出来返回 ''，由调用方决定是「省略」（空）还是「整条拒」（有值但不合法）。
 */
export function normalizeRepoUrl(raw) {
  if (typeof raw !== 'string') return '';
  const v = raw.trim();
  if (!v) return '';
  let u;
  try {
    u = new URL(v);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:') return '';
  if (u.hostname.toLowerCase() !== 'github.com') return '';
  // 注意：WHATWG URL 会把默认端口（:443）吃掉，所以这里查不到端口不等于用户没写，
  // 但输出是规范化地址，那条 :443 不会进索引 —— 与「拒绝端口」的结论一致。
  if (u.port || u.username || u.password || u.search || u.hash) return '';
  const segs = u.pathname.split('/').filter((s) => s !== '');
  if (segs.length !== 2) return '';
  const [owner, repoRaw] = segs;
  if (!REPO_OWNER_RE.test(owner)) return '';
  const repo = repoRaw.toLowerCase().endsWith('.git') ? repoRaw.slice(0, -4) : repoRaw;
  if (!REPO_NAME_RE.test(repo) || repo === '.' || repo === '..') return '';
  return `https://github.com/${owner}/${repo}`;
}

/**
 * 模块 `updateJson` 的判据（契约 §3.1）：http/https、长度 ≤2048。
 *
 * 与 repoUrl 相反，这里**归一不了就省略**而不是整条拒：`updateJson` 只是「这个模块
 * 能不能自己检查更新」的一个可选地址，地址坏了说明这一格没用了，不说明这条模块是假的。
 * 但值要**原样保留** —— 它是作者自己写的地址（可能带 query、可能不是 GitHub），
 * 重写成 `u.href` 会改掉作者实际给的链接。
 */
export function normalizeUpdateJson(raw) {
  if (typeof raw !== 'string') return '';
  const v = raw.trim();
  if (!v || v.length > UPDATE_JSON_MAX) return '';
  let u;
  try {
    u = new URL(v);
  } catch {
    return '';
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
  return v;
}

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

/**
 * 「这一格确实填了东西」—— 空值（`undefined` / `null` / 空白串）算没填，其余都算填了。
 *
 * 与 `isNonEmptyString` 的差别只有后半句：数字、对象这些**读不懂**的值也算「填了」。
 * 它们后面会被归一化函数判成 `''`，于是调用方会把整条投稿拒掉 —— 而不是当成「没填」
 * 静默略过。对作者主页这种「填错了本人还能改、被静默吞掉就再也看不见」的字段，
 * 这个区分就是契约 §5.1 那句「不静默丢」。
 */
function isProvided(v) {
  if (v === undefined || v === null) return false;
  if (typeof v === 'string') return v.trim().length > 0;
  return true;
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
    const sha256 = v.sha256.toLowerCase();

    // ── 版本级仓库证据（契约 §1 / §3.1）──────────────────────────────────────
    // `repoTag` / `repoDigest` 回答「这个包的字节还能在哪儿对上」；`auto` / `autoVia`
    // 回答「它是不是机器人自动收进来的」。四个键都只在有值时写，绝不写 null。
    const repoTag = isNonEmptyString(v.repoTag) && v.repoTag.trim().length <= 256 ? v.repoTag.trim() : '';
    const repoDigestRaw = typeof v.repoDigest === 'string' ? v.repoDigest.trim() : '';
    const repoDigest = repoDigestRaw.toLowerCase();
    if (repoDigestRaw && !REPO_DIGEST_RE.test(repoDigest)) {
      return fail(`version ${version} 的 repoDigest 不是「sha256:<64 位十六进制>」：${repoDigestRaw.slice(0, 80)}`);
    }
    // digest 与 sha256 必须是同一个字节摘要。对不上说明「声称的证据」和「这个产物」是两样东西 ——
    // 而 §3.3 的守卫正是靠这两个值相等来把自动收录钉在 GitHub 的资产上。
    if (repoDigest && repoDigest !== `sha256:${sha256}`) {
      return fail(
        `version ${version} 的 repoDigest 与 sha256 不是同一个包（repoDigest=${repoDigest.slice(0, 20)}…，sha256=${sha256.slice(0, 16)}…）`,
      );
    }
    if (v.auto !== undefined && typeof v.auto !== 'boolean') {
      return fail(`version ${version} 的 auto 不是布尔：${JSON.stringify(v.auto)}`);
    }
    const auto = v.auto === true;
    const autoVia = typeof v.autoVia === 'string' ? v.autoVia.trim() : '';
    // 「auto 却说不出 via」「说了 via 却不是 auto」都是**读不懂**的标记，一律拒：
    // 前者会让 §3.3 的每一条判据都落空（守卫要按 autoVia 分岔），
    // 后者更像一次降级（把自动收录改写成手投）—— 悄悄接受等于把闸整条跳过。
    if (auto && !AUTO_VIAS.includes(autoVia)) {
      return fail(`version ${version} 标了 auto:true 却没有合法的 autoVia（只认 ${AUTO_VIAS.join(' | ')}）`);
    }
    if (!auto && autoVia) {
      return fail(`version ${version} 带 autoVia「${autoVia.slice(0, 40)}」却没有 auto:true —— 自动收录的标记只说了一半，读不懂即拒`);
    }
    if (auto && !repoDigest) {
      return fail(`version ${version} 标了 auto:true 却没有 repoDigest —— 自动收录必须能对上仓库证据`);
    }
    if (auto && autoVia === 'repo' && !repoTag) {
      return fail(`version ${version} 是 autoVia=repo 却没有 repoTag —— 说不清证据在哪个 Release`);
    }

    versions.push({
      version,
      versionCode: v.versionCode,
      zipUrl: v.zipUrl,
      size: v.size,
      time: v.time,
      sha256,
      ...(repoTag ? { repoTag } : {}),
      ...(repoDigest ? { repoDigest } : {}),
      // 只有 `true` 值得写：false 与缺省同义（手投版本），写出来只会让「是不是自动收录的」
      // 这个问题多一种答法。
      ...(auto ? { auto: true } : {}),
      ...(auto && autoVia ? { autoVia } : {}),
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

  // ── 作者主页（契约 §3 / §5.1）────────────────────────────────────────────
  // 两格都是**上传者填写的声明**（界面必须标注「未验证」），最终会被网页与 App 渲染成
  // 可点链接。所以：填了就必须能归一化，归一不了**整条拒**，不静默丢掉 ——
  // 丢掉等于把一条填错的声明洗成「没填」，投稿人再也看不出自己的链接为什么没生效。
  // 与 `updateJson` 的「坏了就省略」是相反的取舍，理由在契约 §5.1 里：这里是可点的链接，
  // 那里只是一个可选的更新源。
  const authorCoolapkUrl = normalizeAuthorCoolapkUrl(raw.authorCoolapkUrl);
  if (isProvided(raw.authorCoolapkUrl) && !authorCoolapkUrl) {
    return fail(
      `authorCoolapkUrl 不是 https://www.coolapk.com/u/<4-12 位数字> 形式（收到「${String(raw.authorCoolapkUrl).trim().slice(0, 80)}」）`,
    );
  }
  const authorGithubUrl = normalizeAuthorGithubUrl(raw.authorGithubUrl);
  if (isProvided(raw.authorGithubUrl) && !authorGithubUrl) {
    return fail(`authorGithubUrl 不是 https://github.com/<用户名> 形式（收到「${String(raw.authorGithubUrl).trim().slice(0, 80)}」）`);
  }

  // ── 出处与上传者（App 的「酷安模块详情页」要显示「从哪个帖子来的、谁传的」） ──────
  // 四格全部可选，且**只写有值的键**：App 用「键在不在」判断要不要渲染出处区，
  // 写成 `null` / `undefined` 会让这条判据失效 —— undefined 还会被 JSON.stringify 静默吞掉，
  // 于是本地看着对、发布产物里又是另一回事。老 pending 没有这些键，走的就是「省略」这条路。
  const sourceUrl = coolapkSourceUrl(raw.source);
  const coolapkUid = isNonEmptyString(raw.coolapkUid) ? raw.coolapkUid.trim() : '';
  const submittedAt = submittedAtMs(raw.submittedAt);

  // ── 来源二选一：酷安帖子 或 源码仓库（契约 §1 / §3.1）───────────────────────
  // 以前 `source` 是唯一「这条投稿从哪来」的锚。现在允许只给仓库：仓库能给出比一个
  // 帖子强得多的证据（源码、LICENSE、Release 资产摘要），而帖子只能给出「谁发的」。
  const repoUrl = normalizeRepoUrl(raw.repoUrl);
  if (isNonEmptyString(raw.repoUrl) && !repoUrl) {
    // **整条拒**，不是悄悄省略这个键（契约 §3.1 明写）。作者明确声称了一个仓库，
    // 删掉它等于把一条假声明洗成「没填」：索引里看不出有人试过，投稿人也不会知道
    // 自己的仓库为什么没生效 —— 那正是「绿标永远不亮」这类无声故障的起点。
    return fail(`repoUrl 不是 https://github.com/<owner>/<repo> 形式（收到「${String(raw.repoUrl).trim().slice(0, 80)}」）`);
  }
  if (!repoUrl && !sourceUrl) {
    return fail('source 与 repoUrl 至少要有其中一个 —— 两个都没有时，这条模块在公示里没有任何可点回出处的锚');
  }
  // 有仓库就必须有结论：`repoVerified` 是「这台机器验过」，`repoCheckedAt` 是「什么时候验的」。
  // 只有地址没有结论的条目，在 App 侧会渲染成一个既是绿标又是灰标的暧昧状态 ——
  // 与其猜，不如让它在 CI 里变成一条可见的 invalid。
  const repoCheckedAt = typeof raw.repoCheckedAt === 'number' && Number.isFinite(raw.repoCheckedAt) && raw.repoCheckedAt > 0
    ? Math.floor(raw.repoCheckedAt)
    : 0;
  if (repoUrl && (typeof raw.repoVerified !== 'boolean' || repoCheckedAt === 0)) {
    return fail('repoUrl 存在时 repoVerified(布尔) 与 repoCheckedAt(正数毫秒) 必须同时存在（契约 §1）');
  }
  const repoVerified = repoUrl ? raw.repoVerified === true : false;
  // SPDX 标识符：无 LICENSE / NOASSERTION 一律省略（契约 §1），所以这里只收非空 ≤64 的串。
  const repoLicense = repoUrl && isNonEmptyString(raw.repoLicense) && raw.repoLicense.trim().length <= 64
    ? raw.repoLicense.trim()
    : '';
  // `updateJson` 形状不对就**省略**（契约 §1「空省略」）：坏地址只说明这一格不能用，
  // 不说明这条模块有问题 —— 与 repoUrl 的「整条拒」是两种相反方向的取舍，各有各的理由。
  const updateJson = normalizeUpdateJson(raw.updateJson);

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
      // 作者主页：可选，只写有值的键（消费侧用「键在不在」判断要不要画链接）。
      ...(authorCoolapkUrl ? { authorCoolapkUrl } : {}),
      ...(authorGithubUrl ? { authorGithubUrl } : {}),
      description,
      ...(sourceUrl ? { source: sourceUrl } : {}),
      ...(uploader ? { uploader } : {}),
      ...(coolapkUid ? { coolapkUid } : {}),
      ...(submittedAt > 0 ? { submittedAt } : {}),
      // 仓库四格 + 自更新地址：都是**可选**，且只写有值的键（App 用「键在不在」判断绿标）。
      ...(repoUrl ? { repoUrl, repoVerified, repoCheckedAt, ...(repoLicense ? { repoLicense } : {}) } : {}),
      ...(updateJson ? { updateJson } : {}),
      versions,
      // `verified` 恒等于投稿者自己在 pending JSON 里填的那个布尔，**不是**「复核过」的标记：
      // 本站没有「人工复核通过后置 true」这一档（见 GOVERNANCE 第 1 节），没有谁有权把它置真。
      // 要让它变真，得先把「谁有权置真、凭什么置真」重新建出来，而不是由投稿者自己填一个 true。
      verified: raw.verified === true,
    },
  };
}

/**
 * 把 `json/repo-state.json`（每日复验的结论）贴回索引里的模块头。
 *
 * 为什么需要这一层：仓库状态是**时间**的函数（今天公开、明天转私有；今天有 LICENSE、
 * 明天删了），而索引里的模块头只能由 pending 推导 —— 要改一枚**已经在索引里**的模块，
 * 过去只有「再发一个版本」这一条路。state 是这条路的例外：它是 CI 复验的产物，不是投稿。
 *
 * 三条边界（契约 §3.1），少一条都会让贴回变成「用旧结论给新地址背书」：
 *   1. 只认 `repoUrl` **完全相等**的模块。地址一换，旧地址上的结论就不再适用于这条模块，
 *      贴上去等于把「另一个仓库验过」说成「这个仓库验过」。
 *   2. 只覆盖 `repoVerified` / `repoCheckedAt` / `repoLicense`：state 不知道版本号，
 *      也不该改版本 —— 版本是 pending 的事。
 *   3. `updateJson` **只在模块没有时补**：作者写在 module.prop 里的值优先，
 *      复验脚本只是从 module.prop 里发现了一个此前没记下来的地址（§8：不自动改 updateJson）。
 *
 * 返回被改动的模块清单（供 main 打印）。state 读不懂时**不抛**：形状不对就当没有 ——
 * 但调用方（main）已经在读文件那一步拦掉了坏 JSON，这里只防御「形状对但某条不对」。
 *
 * @param {Array<object>} modules 就地修改
 * @param {object|null} state `{ checkedAt?, modules: { <id>: { repoUrl, repoVerified, repoCheckedAt, repoLicense?, updateJson? } } }`
 * @returns {Array<{id: string, repoVerified?: boolean, repoCheckedAt?: number, updateJson?: string}>}
 */
export function applyRepoState(modules, state) {
  const changed = [];
  if (!state || typeof state !== 'object' || Array.isArray(state)) return changed;
  const mods = state.modules;
  if (!mods || typeof mods !== 'object' || Array.isArray(mods)) return changed;
  for (const m of Array.isArray(modules) ? modules : []) {
    if (!m || typeof m !== 'object') continue;
    if (!Object.prototype.hasOwnProperty.call(mods, m.id)) continue;
    const st = mods[m.id];
    if (!st || typeof st !== 'object' || Array.isArray(st)) continue;
    const moduleUrl = typeof m.repoUrl === 'string' ? m.repoUrl : '';
    if (!moduleUrl) continue;
    // state 里的地址也走同一套归一化：写状态的是另一个脚本，不能假设它已经归一好了。
    if (normalizeRepoUrl(st.repoUrl) !== moduleUrl) continue;

    // 一条模块只记一条改动：调用方拿 `changed.length` 当「被改写的模块数」用，
    // 若按格计数，同一个模块改了两格就会在日志里变成两处「改写」。
    const rec = { id: m.id };
    let touched = false;

    const checkedAt = typeof st.repoCheckedAt === 'number' && Number.isFinite(st.repoCheckedAt) && st.repoCheckedAt > 0
      ? Math.floor(st.repoCheckedAt)
      : 0;
    if (checkedAt > 0 && typeof st.repoVerified === 'boolean') {
      const lic = isNonEmptyString(st.repoLicense) && st.repoLicense.trim().length <= 64 ? st.repoLicense.trim() : '';
      const before = `${m.repoVerified}|${m.repoCheckedAt}|${m.repoLicense ?? ''}`;
      m.repoVerified = st.repoVerified;
      m.repoCheckedAt = checkedAt;
      // 这次没读到 LICENSE 就把旧的 SPDX 删掉：留着一个已不存在的许可证，
      // 是比不显示更糟的错信息 —— 它会让用户以为这个模块有那个授权。
      if (lic) m.repoLicense = lic;
      else delete m.repoLicense;
      if (`${m.repoVerified}|${m.repoCheckedAt}|${m.repoLicense ?? ''}` !== before) {
        rec.repoVerified = m.repoVerified;
        rec.repoCheckedAt = m.repoCheckedAt;
        touched = true;
      }
    }

    const uj = normalizeUpdateJson(st.updateJson);
    if (uj && !m.updateJson) {
      m.updateJson = uj;
      rec.updateJson = uj;
      touched = true;
    }

    if (touched) changed.push(rec);
  }
  return changed;
}

/**
 * 合并核心逻辑（纯函数，供单测直接调用）。
 *
 * **处置台账在这里生效，而且是唯一生效的地方。** main() 和 verify-index-pr 的重推导
 * 都只调这个函数，所以「索引 = f(pending, 台账)」这条式子只有一份实现；
 * 判据写在 workflow、Worker 或 main() 里任何别处，都会出现两份结果 ——
 * 要么索引 PR 永远判不一致，要么（更糟）判得过而线上留着已下架的模块。
 *
 * @param {{index?: object, entries: Array<object>, dispositions?: Array<object>, repoState?: object|null}} input
 *   `repoState` 是可选输入（`json/repo-state.json` 的内容），应用边界见 applyRepoState。
 * @returns {{index: object, conflicts: Array<object>, stats: object, fallbacks: Array<object>, blocked: Array<object>, repoStateChanged: Array<object>}}
 */
export function buildIndex({ index, entries, dispositions = [], repoState = null }) {
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
    repoStateApplied: 0, // 被复验状态改写的模块数（绿标撤下/重新贴上、许可证变化）
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

    // ── 模块级作者主页：**新条目带了就覆盖，没带就保留**（契约 §5.2）──────────────
    // 归一化之后的空值会被 `normalizeEntry` 省略，所以「没带」= 这一版没填（或填的是空），
    // 那就沿用旧值 —— 作者主页是模块级声明，不该被「作者这次懒得重填」清掉。
    // 索引侧没有「删掉作者链接」这条路：真要撤，得走一次人工改动（同 updateJson 的口径）。
    if (entry.authorCoolapkUrl) existing.authorCoolapkUrl = entry.authorCoolapkUrl;
    if (entry.authorGithubUrl) existing.authorGithubUrl = entry.authorGithubUrl;

    // ── 模块级仓库字段：**可覆盖**（契约 §3.1）──────────────────────────────
    // 版本只追加，模块头则相反：老模块补仓库、复验结论变化、作者换了 updateJson，
    // 都只能靠这条路写进索引（没有第二处会改模块头）。
    // `source` 是唯一的例外 —— 第一次投稿的那个帖子是历史事实，后来的条目无权改写它，
    // 所以它只在**已有模块没有**时补一格。
    if (entry.repoUrl) {
      existing.repoUrl = entry.repoUrl;
      existing.repoVerified = entry.repoVerified;
      existing.repoCheckedAt = entry.repoCheckedAt;
      // 这次校验没读到 LICENSE 就把旧的 SPDX 删掉：留着一个不存在的许可证比不显示更糟。
      if (entry.repoLicense) existing.repoLicense = entry.repoLicense;
      else delete existing.repoLicense;
    }
    // `updateJson` 有值才覆盖（空 = module.prop 里没写，不代表作者要删掉这个地址）；
    // 真要删，得走一次显式的人工改动 —— §8 明确「不自动改 updateJson」。
    if (entry.updateJson) existing.updateJson = entry.updateJson;
    if (!existing.source && entry.source) existing.source = entry.source;

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

  // 复验结论在**合并与下架之后**贴：先定这一版索引有谁，再贴时间性的结论。
  // 反过来（先贴再下架）会让被下架的模块白贴一次结论，日志里还会出现「贴了又没了」。
  const stateChanged = applyRepoState(out.modules, repoState);
  stats.repoStateApplied = stateChanged.length;

  // 版本按 versionCode 降序，MMRL 客户端期望最新版在前。
  for (const m of out.modules) {
    m.versions.sort((a, b) => b.versionCode - a.versionCode);
  }
  out.modules.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // `repoCoversLatest` 是**派生**键（契约 §1：不写进 pending，由索引侧算）：
  // 最新版（versionCode 最大 = 排序后的 versions[0]）到底有没有仓库证据（`repoTag`）。
  // 有 `repoUrl` 的模块**都写** —— `false` 也是一句结论（「有仓库，但最新版没走仓库」）；
  // 没有仓库的模块一律不留这个键，App 靠「键在不在」区分这两件事。
  for (const m of out.modules) {
    if (m.repoUrl) {
      const latest = m.versions[0];
      m.repoCoversLatest = !!(latest && latest.repoTag);
    } else if (Object.prototype.hasOwnProperty.call(m, 'repoCoversLatest')) {
      delete m.repoCoversLatest;
    }
  }

  if (out.modules.length > 0) out.lastUpdate = Date.now();
  return { index: out, conflicts, stats, fallbacks: allFallbacks, blocked, repoStateChanged: stateChanged };
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
 *   --repo-state <file>    指定复验状态（默认 <repo>/json/repo-state.json；不存在=没有状态）
 */
export function parseArgs(argv) {
  const opts = {
    dryRun: false,
    consume: false,
    pendingDir: PENDING_DIR,
    indexFile: INDEX_FILE,
    dispositionsFile: DISPOSITIONS_FILE,
    repoStateFile: REPO_STATE_FILE,
    _: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') { opts.dryRun = true; continue; }
    if (a === '--consume') { opts.consume = true; continue; }
    if (a === '--pending' && i + 1 < argv.length) { opts.pendingDir = path.resolve(argv[++i]); continue; }
    if (a === '--index' && i + 1 < argv.length) { opts.indexFile = path.resolve(argv[++i]); continue; }
    if (a === '--dispositions' && i + 1 < argv.length) { opts.dispositionsFile = path.resolve(argv[++i]); continue; }
    if (a === '--repo-state' && i + 1 < argv.length) { opts.repoStateFile = path.resolve(argv[++i]); continue; }
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

  // 复验状态是**可选输入**：文件不在 = 这份状态还没产出（复验流水线尚未跑过），
  // 与「台账不存在 = 空台账」同一个口径。但文件在而读不懂时必须停下来：
  // 把坏 JSON 当「没有状态」，会让上一轮的绿标永远停在原地 —— 复验明明失败了，
  // 索引却还挂着上一次的「已验证」，而没有任何一处会报错说明这件事。
  let repoState = null;
  if (fs.existsSync(opts.repoStateFile)) {
    try {
      repoState = JSON.parse(fs.readFileSync(opts.repoStateFile, 'utf8'));
      if (!repoState || typeof repoState !== 'object' || Array.isArray(repoState)) {
        throw new Error('顶层不是对象');
      }
      if (repoState.modules !== undefined
        && (repoState.modules === null || typeof repoState.modules !== 'object' || Array.isArray(repoState.modules))) {
        throw new Error('modules 不是 { <id>: {...} } 形状');
      }
    } catch (e) {
      console.error(`[build-index] 复验状态读不懂，停止合并（不当「没有状态」处理）：${e.message}`);
      return 3;
    }
  }

  const current = fs.existsSync(indexFile)
    ? JSON.parse(fs.readFileSync(indexFile, 'utf8'))
    : { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] };

  const files = collectPendingFiles(pendingDir);
  const entries = [];
  for (const item of files) for (const e of item.entries) entries.push(e);
  const { index, conflicts, stats, fallbacks, blocked, repoStateChanged } = buildIndex({ index: current, entries, dispositions, repoState });

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
      `台账抹掉版本 ${stats.removedVersions}（模块整条移除 ${stats.removedModules}），` +
      `复验状态改写 ${stats.repoStateApplied}，冲突 ${stats.conflicts}`,
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

  // 复验结论的改写也要说出来：绿标消失对用户只是少了一个绿点，对维护者却最容易变成
  // 「没人知道为什么」。这里把 id 和最终结论打出来，日志本身就是那次撤标的凭据。
  if (repoStateChanged.length > 0) {
    console.log(`[build-index] 复验状态改写 ${repoStateChanged.length} 处（来自 repo-state.json）：`);
    for (const s of repoStateChanged) {
      const what = [];
      if (typeof s.repoVerified === 'boolean') what.push(`repoVerified=${s.repoVerified}`);
      if (typeof s.repoCheckedAt === 'number') what.push(`repoCheckedAt=${new Date(s.repoCheckedAt).toISOString()}`);
      if (s.updateJson) what.push(`updateJson=${s.updateJson}`);
      console.log(`  - ${s.id}：${what.join('，')}`);
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
