#!/usr/bin/env node
/**
 * verify-repos.mjs
 *
 * 每日复验「模块的源码仓库证据还成不成立」，把结论写进 `json/repo-state.json`。
 *
 * 复验要回答的事只有一件：索引里这一版凭什么说「仓库公开 + 这个 zip 是仓库产出的」？
 * 证据有两种（与 Worker 提交校验同一套语义，见契约 §2.1）：
 *   A. Release 资产的 digest 等于版本的 `repoDigest`，证据定位是 `repoTag=<tag_name>`；
 *   B. 仓库根 `checksums.txt` 里有一行摘要等于版本的 `repoDigest`，证据定位是
 *      `repoTag=checksums.txt@<default_branch>`。
 * 复验只做两件事：仓库是否仍然公开、这条证据是否仍然指向同一份字节。
 *
 * 判据里的「故障」与「撤销」必须分开：
 *   - 仓库 404 / 私有 / 证据消失 / 已经没有带 repoDigest 的版本 → `repoVerified:false`；
 *   - GitHub 5xx、rate limit → **保留旧状态**（一次宕机不该让一整排模块掉绿标）；
 *   - 401 / 其它 4xx / 网络故障 → 整个 run 红（按 §0「任何 GitHub 调用失败都硬失败」），
 *     让真话出现在日志里，而不是悄悄把状态改成「已验证」或「未验证」。
 *
 * 本文件同时被 `auto-update.mjs` 复用（它先跑一遍全量复验，再发现新版本，最后合成一个 PR），
 * 所以核心逻辑与 CLI 分开：`verifyReposCore()` 是纯编排，`main()` 才读环境变量、开 PR。
 * 这样「每日复验」只有一份实现，不会出现自动更新与独立复验两套判据。
 *
 * 单独运行（人工排查 / 手动补一轮）：
 *   node scripts/verify-repos.mjs --dry-run          # 只打印结论，不写文件、不开 PR
 *   node scripts/verify-repos.mjs --no-pr            # 写 json/repo-state.json，不开 PR
 *   node scripts/verify-repos.mjs                    # 有变化就通过 /auto/pr 开 PR
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { createSafeHttp, MAX_JSON_BYTES } from './lib/http-safe.mjs';
import { githubGetJson, parseRepoUrl, rawFileUrl, repoApiUrl } from './lib/github.mjs';
import { AUTO_PR_STATE_PATH, postAutoPr } from './lib/auto-pr.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const INDEX_FILE = path.join(REPO_ROOT, 'json', 'modules.json');
export const STATE_FILE = path.join(REPO_ROOT, AUTO_PR_STATE_PATH);
export const CHECKSUMS_TAG_PREFIX = 'checksums.txt@';

const SHA256_RE = /^[0-9a-f]{64}$/;
/** checksums.txt 的合法行：64 位摘要 + 空白 + 可选 `*` + 文件名。 */
const CHECKSUM_LINE_RE = /^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$/;

/** 空状态。`checkedAt` 是「上一次状态**发生变化**的时间」，不是「上一次检查的时间」。 */
export function emptyState() {
  return { checkedAt: 0, modules: {} };
}

/** 规范化 `sha256:<hex>`；不合法返回空串（调用方据此判「没有证据」）。 */
export function normalizeDigest(raw) {
  const s = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  return /^sha256:[0-9a-f]{64}$/.test(s) ? s : '';
}

/**
 * 找出「versionCode 最大且带 repoDigest」的版本 —— 复验只认它。
 *
 * 为什么不是「最新版本」：老版本可能没有仓库证据（补仓库之前发的），此时最新版本本来
 * 就没有可复验的证据；但这个模块仍可能因为某个历史版本有证据而绿着。契约要求看
 * 「最大 versionCode 且带 repoDigest 的那一版」，正是这个口径。
 */
export function latestEvidenceVersion(module) {
  const versions = Array.isArray(module && module.versions) ? module.versions : [];
  let best = null;
  for (const v of versions) {
    if (!v || typeof v !== 'object') continue;
    if (!Number.isInteger(v.versionCode) || v.versionCode <= 0) continue;
    if (!normalizeDigest(v.repoDigest)) continue;
    if (!best || v.versionCode > best.versionCode) best = v;
  }
  return best;
}

/** 解析 checksums.txt，返回 Map<小写摘要, 文件名>。认不出的行直接跳过（不是错误）。 */
export function parseChecksums(text) {
  const out = new Map();
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = CHECKSUM_LINE_RE.exec(line.trim());
    if (!m) continue;
    out.set(m[1].toLowerCase(), m[2]);
  }
  return out;
}

/** Release 里是否还有资产的 digest 等于该摘要（证据 A）。 */
export function releaseHasDigest(release, digest) {
  const want = normalizeDigest(digest);
  if (!want) return false;
  const assets = Array.isArray(release && release.assets) ? release.assets : [];
  return assets.some((a) => normalizeDigest(a && a.digest) === want);
}

/** 从仓库元数据里取 SPDX id；没有 LICENSE / NOASSERTION 时返回空串（调用方省略这个键）。 */
export function licenseFromRepo(repo) {
  const raw = repo && repo.license && typeof repo.license.spdx_id === 'string'
    ? repo.license.spdx_id.trim()
    : '';
  if (!raw || raw.toUpperCase() === 'NOASSERTION' || raw.length > 64) return '';
  return raw;
}

/** 状态条目只留契约里的五格，顺序固定 —— 状态文件的 diff 才是人读的。 */
export function cleanStateEntry(entry) {
  const out = {};
  if (!entry || typeof entry !== 'object') return out;
  if (typeof entry.repoUrl === 'string' && entry.repoUrl) out.repoUrl = entry.repoUrl;
  out.repoVerified = entry.repoVerified === true;
  if (Number.isFinite(entry.repoCheckedAt) && entry.repoCheckedAt > 0) {
    out.repoCheckedAt = Math.trunc(entry.repoCheckedAt);
  }
  if (typeof entry.repoLicense === 'string' && entry.repoLicense.trim()) {
    out.repoLicense = entry.repoLicense.trim();
  }
  if (typeof entry.updateJson === 'string' && entry.updateJson.trim()) {
    out.updateJson = entry.updateJson.trim();
  }
  return out;
}

/** 把状态 modules 规范化成「按 id 排序、字段顺序固定」的形状，用于无噪声比较。 */
export function canonicalModules(modules) {
  const out = {};
  const src = modules && typeof modules === 'object' ? modules : {};
  for (const id of Object.keys(src).sort()) out[id] = cleanStateEntry(src[id]);
  return out;
}

/** 逐 id 列出状态变化，供 PR 正文与日志用。 */
export function diffState(beforeModules, afterModules) {
  const before = canonicalModules(beforeModules);
  const after = canonicalModules(afterModules);
  const changes = [];
  for (const id of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    const a = before[id];
    const b = after[id];
    if (!a) changes.push({ id, kind: 'added' });
    else if (!b) changes.push({ id, kind: 'removed' });
    else if (a.repoVerified !== b.repoVerified) {
      changes.push({ id, kind: 'verified', from: a.repoVerified, to: b.repoVerified });
    } else if ((a.repoLicense || '') !== (b.repoLicense || '')) {
      changes.push({ id, kind: 'license', from: a.repoLicense || '', to: b.repoLicense || '' });
    } else if ((a.updateJson || '') !== (b.updateJson || '')) {
      changes.push({ id, kind: 'updateJson', from: a.updateJson || '', to: b.updateJson || '' });
    } else if (a.repoCheckedAt !== b.repoCheckedAt) {
      changes.push({ id, kind: 'checkedAt', from: a.repoCheckedAt, to: b.repoCheckedAt });
    }
  }
  return changes;
}

/**
 * 定稿状态：只有内容变化才更新 `checkedAt`。
 *
 * 反过来说：status 无变化时**不**刷新 `checkedAt`，否则每天都会因为一个时间戳而开 PR，
 * 「无变化不开 PR」就名存实亡。每个条目的 `repoCheckedAt` 也只在它的结论变化时更新。
 */
export function finalizeState(previous, modules, nowMs) {
  const prevModules = canonicalModules(previous && previous.modules);
  const nextModules = canonicalModules(modules);
  const changed = JSON.stringify(prevModules) !== JSON.stringify(nextModules);
  const prevCheckedAt = previous && Number.isFinite(previous.checkedAt) ? previous.checkedAt : 0;
  return {
    state: { checkedAt: changed ? Math.trunc(nowMs) : Math.trunc(prevCheckedAt), modules: nextModules },
    changed,
    changes: changed ? diffState(prevModules, nextModules) : [],
  };
}

/**
 * 把本轮复验结果合并成新状态。
 *
 * 规则（§3.1）：
 *   - 只有当前索引里**有 repoUrl** 的模块才配留在 state 里；模块没了/去掉了仓库 → 条目删掉；
 *   - 状态条目的 repoUrl 必须与当前模块一致，不一致的旧条目直接丢弃（不能把旧 URL 的
 *     验证结论贴到新 URL 上）；
 *   - 本轮没有复验到的模块（本轮没有更新）保留旧条目 —— 状态是全量的，不能因为某次只跑了
 *     一部分就把其余模块的绿标抹掉。
 */
export function mergeVerifiedState({ modules, previous, results, nowMs }) {
  const prevModules = canonicalModules(previous && previous.modules);
  const byId = new Map((Array.isArray(results) ? results : []).map((r) => [r.id, r.entry]));
  const next = {};
  for (const m of Array.isArray(modules) ? modules : []) {
    const slug = parseRepoUrl(m && m.repoUrl);
    if (!slug.ok) continue;
    const verifiedEntry = byId.get(m.id);
    const prev = prevModules[m.id] && prevModules[m.id].repoUrl === slug.url ? prevModules[m.id] : null;
    const entry = verifiedEntry || prev;
    if (entry) next[m.id] = cleanStateEntry(entry);
  }
  return finalizeState(previous, next, nowMs);
}

/** 条目「结论」与原状一致时原样返回旧对象，避免仅因为重新算了一遍就改时间戳。 */
function settleEntry({ repoUrl, repoVerified, repoLicense, updateJson, previous, nowMs }) {
  const uj = typeof updateJson === 'string' ? updateJson.trim() : '';
  const same = previous
    && previous.repoUrl === repoUrl
    && previous.repoVerified === repoVerified
    && (previous.repoLicense || '') === (repoLicense || '')
    && (previous.updateJson || '') === uj;
  if (same) return { entry: previous, changed: false };
  const entry = { repoUrl, repoVerified };
  if (repoLicense) entry.repoLicense = repoLicense;
  entry.repoCheckedAt = Math.trunc(nowMs);
  if (uj) entry.updateJson = uj;
  return { entry: cleanStateEntry(entry), changed: true };
}

/**
 * 复验一个模块。返回 `{entry, verdict, reason}`：
 *   verified  证据仍成立
 *   unverified 证据没了 / 仓库不可见（真要撤标）
 *   preserved  GitHub 故障，保留旧状态（不撤标）
 *
 * 抛错 = 硬失败（网络错误、401、意外 4xx）：调用方让整个 run 红。
 */
export async function verifyRepoOne({ module, previous, http, token, nowMs, log = () => {} }) {
  const updateJson = typeof module.updateJson === 'string' ? module.updateJson.trim() : '';
  const settle = (opts) => settleEntry({ updateJson, ...opts });
  const slug = parseRepoUrl(module.repoUrl);
  if (!slug.ok) {
    return {
      entry: settle({ repoUrl: module.repoUrl || '', repoVerified: false, previous: null, nowMs }).entry,
      verdict: 'unverified',
      reason: `repoUrl 不合法：${slug.error}`,
    };
  }

  const repoRes = await githubGetJson(http, token, repoApiUrl(slug.owner, slug.repo));
  const status = repoRes.status;
  if (status === 404 || status === 410) {
    const r = settle({ repoUrl: slug.url, repoVerified: false, previous, nowMs });
    return { entry: r.entry, verdict: 'unverified', reason: '仓库不存在或不是公开仓库' };
  }
  if (status >= 500 || status === 429 || isRateLimited(repoRes)) {
    return preserve(previous, slug.url, nowMs, `GitHub 返回 ${status}${isRateLimited(repoRes) ? '（rate limit）' : ''}`, updateJson);
  }
  if (status !== 200) {
    throw new Error(`复验 ${module.id} 时 GitHub 返回 ${status}（${repoApiUrl(slug.owner, slug.repo)}）`);
  }

  const repoLicense = licenseFromRepo(repoRes.json);
  const version = latestEvidenceVersion(module);
  if (!version) {
    const r = settle({ repoUrl: slug.url, repoVerified: false, repoLicense, previous, nowMs });
    return { entry: r.entry, verdict: 'unverified', reason: '没有任何带 repoDigest 的版本，无从复验' };
  }

  const digest = normalizeDigest(version.repoDigest);
  const repoTag = typeof version.repoTag === 'string' ? version.repoTag.trim() : '';
  if (!repoTag) {
    const r = settle({ repoUrl: slug.url, repoVerified: false, repoLicense, previous, nowMs });
    return { entry: r.entry, verdict: 'unverified', reason: `版本 ${version.versionCode} 有 digest 但没有 repoTag` };
  }

  if (repoTag.startsWith(CHECKSUMS_TAG_PREFIX)) {
    const branch = repoTag.slice(CHECKSUMS_TAG_PREFIX.length).trim();
    if (!branch) {
      const r = settle({ repoUrl: slug.url, repoVerified: false, repoLicense, previous, nowMs });
      return { entry: r.entry, verdict: 'unverified', reason: `repoTag 形状不对：${repoTag}` };
    }
    const url = rawFileUrl(slug.owner, slug.repo, branch, 'checksums.txt');
    const res = await http.getText(url, { headers: { accept: 'text/plain' }, maxBytes: MAX_JSON_BYTES });
    if (res.status === 404 || res.status === 410) {
      const r = settle({ repoUrl: slug.url, repoVerified: false, repoLicense, previous, nowMs });
      return { entry: r.entry, verdict: 'unverified', reason: `仓库根 checksums.txt 不在了（${url}）` };
    }
    if (res.status >= 500 || res.status === 429 || isRateLimited(res)) {
      return preserve(previous, slug.url, nowMs, `checksums.txt 返回 ${res.status}`, updateJson);
    }
    if (res.status !== 200) throw new Error(`拉取 ${url} 返回 ${res.status}`);
    const hex = digest.slice('sha256:'.length);
    const found = parseChecksums(res.text).has(hex);
    const r = settle({ repoUrl: slug.url, repoVerified: found, repoLicense, previous, nowMs });
    return {
      entry: r.entry,
      verdict: found ? 'verified' : 'unverified',
      reason: found ? `checksums.txt@${branch} 仍含该摘要` : `checksums.txt@${branch} 里已经没有该摘要`,
    };
  }

  const tagUrl = repoApiUrl(slug.owner, slug.repo, `/releases/tags/${encodeURIComponent(repoTag)}`);
  const tagRes = await githubGetJson(http, token, tagUrl);
  if (tagRes.status === 404 || tagRes.status === 410) {
    const r = settle({ repoUrl: slug.url, repoVerified: false, repoLicense, previous, nowMs });
    return { entry: r.entry, verdict: 'unverified', reason: `Release ${repoTag} 不在了` };
  }
  if (tagRes.status >= 500 || tagRes.status === 429 || isRateLimited(tagRes)) {
    return preserve(previous, slug.url, nowMs, `Release ${repoTag} 返回 ${tagRes.status}`, updateJson);
  }
  if (tagRes.status !== 200) throw new Error(`查询 Release ${repoTag} 返回 ${tagRes.status}`);

  const stillMatches = releaseHasDigest(tagRes.json, digest);
  const r = settle({ repoUrl: slug.url, repoVerified: stillMatches, repoLicense, previous, nowMs });
  return {
    entry: r.entry,
    verdict: stillMatches ? 'verified' : 'unverified',
    reason: stillMatches
      ? `Release ${repoTag} 的资产摘要仍匹配`
      : `Release ${repoTag} 里已经没有摘要 ${digest} 的资产`,
  };
}

function isRateLimited(res) {
  const headers = (res && res.headers) || {};
  const remaining = headers['x-ratelimit-remaining'];
  if (remaining !== undefined && String(remaining) === '0') return true;
  if (headers['retry-after'] !== undefined) return true;
  const message = res && res.json && typeof res.json.message === 'string' ? res.json.message : '';
  return /rate limit/i.test(message);
}

/** 故障保留：有旧条目就原样返回，没有就按「未验证」落一条（保守但不撤别人标）。 */
function preserve(previous, repoUrl, now, reason, updateJson = '') {
  if (previous) return { entry: previous, verdict: 'preserved', reason: `${reason}，保留旧状态` };
  return {
    entry: cleanStateEntry({ repoUrl, repoVerified: false, repoCheckedAt: now, updateJson }),
    verdict: 'preserved',
    reason: `${reason}，且没有旧状态可保留（按未验证记录）`,
  };
}

/**
 * 全量复验：对索引里每个有 repoUrl 的模块跑一遍 `verifyRepoOne`，合并成新状态。
 *
 * 这是 auto-update 与独立 CLI 共用的唯一实现。`previousState` 里旧 URL 的条目会被
 * `mergeVerifiedState` 丢掉；没有 repoUrl 的模块不产生条目。
 */
export async function verifyReposCore({ modules, previousState, http, token, nowMs, log = () => {} }) {
  const previousModules = (previousState && previousState.modules) || {};
  const results = [];
  const summary = { total: 0, verified: 0, unverified: 0, preserved: 0, details: [] };

  for (const module of Array.isArray(modules) ? modules : []) {
    const slug = parseRepoUrl(module && module.repoUrl);
    if (!slug.ok) continue;
    summary.total += 1;
    const prev = previousModules[module.id] && previousModules[module.id].repoUrl === slug.url
      ? cleanStateEntry(previousModules[module.id])
      : null;
    // 没有 state 时用索引里的 repoVerified 当基线：一次 5xx 不该把「提交时验过」的绿标撤掉。
    const baseline = prev || (module.repoVerified === true
      ? cleanStateEntry({
        repoUrl: slug.url,
        repoVerified: true,
        repoCheckedAt: Number(module.repoCheckedAt) || 0,
      })
      : null);

    const r = await verifyRepoOne({
      module, previous: baseline, http, token, nowMs, log,
    });
    results.push({ id: module.id, entry: r.entry });
    if (r.verdict === 'verified') summary.verified += 1;
    else if (r.verdict === 'unverified') summary.unverified += 1;
    else summary.preserved += 1;
    summary.details.push({ id: module.id, verdict: r.verdict, reason: r.reason });
    log(`复验 ${module.id}：${r.verdict} —— ${r.reason}`);
  }

  const merged = mergeVerifiedState({ modules, previous: previousState, results, nowMs });
  return { ...merged, results, summary };
}

// ── CLI ───────────────────────────────────────────────────────────────────

export function parseArgs(argv) {
  const out = { index: '', state: '', noPr: false, dryRun: false, help: false };
  const args = Array.isArray(argv) ? argv.slice() : [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--index') { out.index = args[i + 1] || ''; i += 1; }
    else if (a === '--state') { out.state = args[i + 1] || ''; i += 1; }
    else if (a === '--no-pr') out.noPr = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '-h' || a === '--help') out.help = true;
    else throw new Error(`不认识的参数：${a}`);
  }
  return out;
}

function readJsonFile(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  const raw = fs.readFileSync(file, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (err) {
    throw new Error(`${file} 不是合法 JSON：${err.message}`);
  }
}

function summaryMarkdown({ summary, changes, changed }) {
  const lines = [];
  lines.push('## 源码仓库复验');
  lines.push('');
  lines.push(`- 复验模块：${summary.total}`);
  lines.push(`- 证据成立：${summary.verified}`);
  lines.push(`- 证据失效：${summary.unverified}`);
  lines.push(`- GitHub 故障保留旧状态：${summary.preserved}`);
  lines.push(`- 状态变化：${changed ? changes.length : 0}`);
  if (changes.length > 0) {
    lines.push('');
    lines.push('| 模块 | 变化 |');
    lines.push('| --- | --- |');
    for (const c of changes) {
      let text = c.kind;
      if (c.kind === 'verified') text = `repoVerified ${c.from} → ${c.to}`;
      else if (c.kind === 'license') text = `LICENSE ${c.from || '(无)'} → ${c.to || '(无)'}`;
      else if (c.kind === 'updateJson') text = 'updateJson 更新';
      else if (c.kind === 'checkedAt') text = '复验时间更新';
      lines.push(`| ${c.id} | ${text} |`);
    }
  }
  return `${lines.join('\n')}\n`;
}

export async function main(argv = process.argv.slice(2), env = process.env, deps = {}) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('用法：node scripts/verify-repos.mjs [--index <file>] [--state <file>] [--no-pr|--dry-run]');
    return { changed: false, prUrl: null };
  }
  const root = deps.root || REPO_ROOT;
  const indexFile = path.resolve(root, args.index || INDEX_FILE);
  const stateFile = path.resolve(root, args.state || STATE_FILE);
  const token = env.GITHUB_TOKEN || '';
  if (!token) throw new Error('缺少 GITHUB_TOKEN：复验需要读 GitHub（公开仓库也建议带 token 以免撞 rate limit）');

  const index = readJsonFile(indexFile, null);
  if (!index || !Array.isArray(index.modules)) {
    throw new Error(`${indexFile} 里没有 modules 数组`);
  }
  const previousState = readJsonFile(stateFile, emptyState());
  const http = deps.http || createSafeHttp();
  const now = deps.now || Date.now;
  const log = deps.log || ((msg) => console.log(msg));

  const { state, changed, changes, summary } = await verifyReposCore({
    modules: index.modules,
    previousState,
    http,
    token,
    nowMs: now(),
    log,
  });

  const markdown = summaryMarkdown({ summary, changes, changed });
  if (deps.summaryFile) fs.writeFileSync(deps.summaryFile, markdown, 'utf8');

  if (!changed) {
    log('仓库状态没有变化 —— 不写文件、不开 PR。');
    return { changed: false, prUrl: null, markdown };
  }
  if (args.dryRun) {
    log(markdown);
    return { changed: true, prUrl: null, markdown, state };
  }

  const content = `${JSON.stringify(state, null, 2)}\n`;
  if (args.noPr) {
    fs.writeFileSync(stateFile, content, 'utf8');
    log(`已写入 ${stateFile}（--no-pr：未开 PR）。`);
    return { changed: true, prUrl: null, markdown, state };
  }

  const workerBase = env.WORKER_BASE || env.SUBMIT_WORKER_URL || '';
  const autoKey = env.AUTO_PR_KEY || '';
  const pr = await postAutoPr({
    http,
    workerBase,
    autoKey,
    title: `chore(auto): 复验源码仓库状态（${changes.length} 项变化）`,
    body: `${markdown}\n本 PR 由 \`scripts/verify-repos.mjs\` 生成；状态文件是索引的输入，合并后由 \`Rebuild Index From Main\` 消费。\n`,
    files: [{ path: AUTO_PR_STATE_PATH, content }],
    log,
  });
  return { changed: true, prUrl: pr.prUrl, markdown, state };
}

// 入口判据必须用 resolve(argv[1])：拿 argv[1] 拼 file:// URL 在 Windows 上永远不等于
// import.meta.url，脚本会静默不跑（README 教训 #5 记的就是这一类）。
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`::error::复验源码仓库失败：${err && err.message ? err.message : err}`);
    process.exitCode = 1;
  });
}
