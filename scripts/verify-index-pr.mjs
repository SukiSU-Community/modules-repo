#!/usr/bin/env node
/**
 * 验「索引 PR」—— 证明 json/modules.json 是 base 内容推导出来的，不是人手写的。
 *
 * 为什么需要它。分支保护要求「进 main 必须过 PR + 必须过 approve」，而索引改动只能
 * 走 PR（repo ruleset 不给 GitHub Actions 开 bypass：Integration actor 必须是 ruleset
 * source / org 里装的 App，"App" 又不是合法 actor_type）。问题来了：索引 PR 的 diff 是
 * 「json 变了 + pending 被删」，投稿扫描只认 pending 的新增/修改，于是索引 PR 一个
 * check 都不会产生 —— required check 从没上报过 = Expected = 永远合不了。
 *
 * 最省事的修法是把 json/** 也塞进扫描的触发路径，让「没投稿内容」的 PR 直接绿。
 * 那等于开门：任何人可以开一个只改 json/modules.json 的 PR，它落在「无批准事项」分支
 * 变绿、被合进 main —— 整条审核链被一次手抄索引绕过。
 *
 * 所以索引 PR 需要一个**按内容判定**的结论，而不是按「谁开的 / 有没有投稿」判定。
 * 判据只有一条，但必须严格：
 *
 *   PR 里的索引 == buildIndex(base 索引, base 上被这次 PR 删掉的那些 pending 条目)
 *
 * 而「被删掉的那些条目算已批准」这件事**不能由 PR 自己声明**：删掉一个从没批准的
 * pending 文件再把它手抄进索引，正好是绕过路径。批准依据必须是外部证据 ——
 * 当初把该文件带上 main 的那个提交所属 PR，其 head sha 上 `approve` 的结论为 success。
 * 这条依据由 publish-from-main.mjs 的 findPrForCommit / assertMergeApproved 提供，
 * 和盖审核章用的是同一个判据，不另起一套。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { buildIndex, markApproved, collectPendingFiles } from './build-index.mjs';
import { findPrForCommit, assertMergeApproved } from './publish-from-main.mjs';

/**
 * 归一化到能逐字段比的状态。
 *
 * lastUpdate 是时间戳不是内容（build-index 每次都会动它），留着会让每次比对都失败；
 * 模块顺序与版本顺序取决于遍历顺序，所以统一排序 —— 但字段本身一个都不容忍差异：
 * 少一个 name、多一个 version、verified 变了，都算「不是推导出来的」。
 */
export function normalizeIndex(doc) {
  const d = doc && typeof doc === 'object' ? doc : {};
  const modules = (Array.isArray(d.modules) ? d.modules : []).map((m) => ({
    ...m,
    versions: Array.isArray(m && m.versions)
      ? [...m.versions].sort((a, b) => Number(a?.versionCode) - Number(b?.versionCode))
      : [],
  })).sort((a, b) => String(a?.id).localeCompare(String(b?.id)));
  return { name: d.name ?? null, modules };
}

/** 稳定序列化：键顺序固定，否则同样的内容会因插入顺序不同而被判成不同。 */
export function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/** 逐模块比对，给出人能看懂的差异，而不是只说「不相等」。 */
export function diffIndexes(expected, actual) {
  const e = normalizeIndex(expected);
  const a = normalizeIndex(actual);
  const diffs = [];
  if (e.name !== a.name) diffs.push(`顶层 name 不同：推导 ${JSON.stringify(e.name)} / PR ${JSON.stringify(a.name)}`);
  const em = new Map(e.modules.map((m) => [m.id, m]));
  const am = new Map(a.modules.map((m) => [m.id, m]));
  for (const id of em.keys()) if (!am.has(id)) diffs.push(`PR 里缺模块 ${id}（推导认为该有）`);
  for (const id of am.keys()) if (!em.has(id)) diffs.push(`PR 里多出模块 ${id}（推导认为不该有）`);
  for (const [id, m] of em) {
    if (!am.has(id)) continue;
    const s1 = stableStringify(m);
    const s2 = stableStringify(am.get(id));
    if (s1 !== s2) diffs.push(`模块 ${id} 内容不同：\n  推导 ${s1.slice(0, 400)}\n  PR   ${s2.slice(0, 400)}`);
  }
  return diffs;
}

/**
 * 纯判定核心：把「哪些条目算批准」和「推导结果对不对」分开，前者必须是外部证据。
 *
 * @param {{
 *   baseIndex: object,
 *   baseEntries: Array<{path: string, entry: object}>,
 *   deletedPaths: string[],
 *   touchedPaths: string[],   // PR 里新增/修改的 pending 路径
 *   actualIndex: object,
 *   attest: (p: string) => {ok: boolean, reason: string}
 * }} input
 */
export function judgeIndexPr(input) {
  const { baseIndex, baseEntries = [], deletedPaths = [], touchedPaths = [], actualIndex, attest } = input;
  const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });

  // 索引 PR 的定义就是「不带新投稿」。带了就交给投稿扫描那条路判，别在这里混着批。
  if (touchedPaths.length) {
    return fail(`这个 PR 同时新增/修改了 pending 条目（${touchedPaths.slice(0, 3).join('、')}`
      + `${touchedPaths.length > 3 ? ' 等' : ''}），不是纯索引重建，不按推导放行`);
  }
  if (!deletedPaths.length) {
    return fail('这个 PR 改了 json/modules.json 但一个 pending 都没消费 —— 索引不是推导出来的，是手改的');
  }

  const byPath = new Map(baseEntries.map((e) => [e.path, e.entry]));
  const approved = [];
  const evidences = [];
  for (const p of deletedPaths) {
    const entry = byPath.get(p);
    if (!entry) {
      return fail(`删掉的 ${p} 在 base 上不存在 —— 推导无从起算，拒绝`);
    }
    const a = typeof attest === 'function' ? attest(p) : { ok: false, reason: '没有取证函数' };
    if (!a.ok) {
      return fail(`${p} 拿不到批准证据：${a.reason}`
        + '（删掉一个没批过的条目再手抄进索引，正是要挡的路径）');
    }
    approved.push(markApproved(entry, { by: a.by || 'ci:verify-index-pr', at: a.at || '' }));
    evidences.push({ path: p, ...a });
  }

  const { index: expected } = buildIndex({ index: baseIndex, entries: approved });
  const diffs = diffIndexes(expected, actualIndex);
  if (diffs.length) {
    return fail('PR 里的索引与推导结果不一致：\n  - ' + diffs.join('\n  - '), { diffs, evidences });
  }
  return { ok: true, reason: `索引与推导一致（消费 ${deletedPaths.length} 个已批准条目）`, evidences, consumed: deletedPaths };
}

/* ------------------------------------------------------------ 取证与 I/O */

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/** 读某个 ref 上的 JSON 对象；不存在返回 null。 */
function showJson(cwd, ref, file) {
  try {
    return JSON.parse(git(cwd, ['show', `${ref}:${file}`]));
  } catch {
    return null;
  }
}

/** 列出某 ref 下 pending/*.json 的路径（用正斜杠，跨平台一致）。 */
function listPending(cwd, ref, pendingDir) {
  let raw = '';
  try {
    raw = git(cwd, ['ls-tree', '-r', '--name-only', ref, '--', pendingDir]);
  } catch {
    return [];
  }
  return raw.split('\n').map((s) => s.trim()).filter((s) => s && s.endsWith('.json') && !path.basename(s).startsWith('.'));
}

/**
 * 找「把某个 pending 文件带上 main 的那次提交」。
 * 用 <ref> 限定历史，取最近一次真正改动过该路径的提交 —— 也就是它的到来。
 */
export function commitThatAdded(cwd, ref, file) {
  const out = git(cwd, ['log', '-1', '--format=%H', ref, '--', file]).trim();
  return out || '';
}

export async function attestPath({ cwd, baseRef, file, apiBase, token, owner, repo, mainBranch }) {
  const sha = commitThatAdded(cwd, baseRef, file);
  if (!/^[0-9a-f]{40}$/i.test(sha)) return { ok: false, reason: `找不到把它带上 ${baseRef} 的提交` };
  const { pr, checks = [] } = await findPrForCommit({ apiBase, token, owner, repo, sha, mainBranch, log: { log() {}, error() {} } });
  const v = assertMergeApproved({ pr, checks, mainBranch });
  if (!v.ok) return { ok: false, reason: `${v.reason}（引入提交 ${sha.slice(0, 12)}）`, commitSha: sha };
  return {
    ok: true,
    by: `ci:approve#${owner}/${repo}PR${v.evidence.pr}@${String(v.evidence.headSha).slice(0, 12)}`,
    at: new Date().toISOString(),
    commitSha: sha,
    pr: v.evidence.pr,
    headSha: v.evidence.headSha,
  };
}

export function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const k = argv[i].slice(2);
    const eq = k.indexOf('=');
    if (eq >= 0) { o[k.slice(0, eq)] = k.slice(eq + 1); continue; }
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) { o[k] = next; i++; } else o[k] = true;
  }
  return o;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const log = deps.log || console;
  if (opts.help || !opts.base || !opts.owner || !opts.repo) {
    log.log(`用法: node verify-index-pr.mjs --base <baseRef> --owner <o> --repo <r>
       [--pending-dir pending] [--index-file json/modules.json] [--cwd <dir>] [--report <file>]
   判定当前工作树里的索引是否等于「base 内容 + 被本 PR 消费的已批准条目」的推导结果。`);
    return opts.help ? 0 : 2;
  }
  const cwd = opts.cwd ? path.resolve(opts.cwd) : process.cwd();
  const pendingDir = opts['pending-dir'] || 'pending';
  const indexFile = opts['index-file'] || 'json/modules.json';
  const baseRef = String(opts.base);
  const mainBranch = opts['main-branch'] || 'main';
  const token = deps.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  const apiBase = deps.apiBase || process.env.GITHUB_API_URL || 'https://api.github.com';

  const report = { ok: false, reason: '', consumed: [], evidences: [] };
  const writeReport = () => { if (opts.report) fs.writeFileSync(path.resolve(opts.report), `${JSON.stringify(report, null, 2)}\n`, 'utf8'); };

  if (!token) { report.reason = '没有 GITHUB_TOKEN，取不到批准证据'; log.error('[verify-index-pr] ' + report.reason); writeReport(); return 1; }

  // 用 git 拿三方输入：base 的索引、base 的 pending 内容、以及本 PR 对 pending 做了什么。
  const headRef = opts.head || 'HEAD';
  const baseIndex = showJson(cwd, baseRef, indexFile);
  const actualIndex = showJson(cwd, headRef, indexFile);
  if (!baseIndex || !actualIndex) {
    report.reason = `读不到索引（base:${indexFile} 或 head:${indexFile}）`;
    log.error('[verify-index-pr] ' + report.reason);
    writeReport();
    return 1;
  }

  const basePending = listPending(cwd, baseRef, pendingDir);
  const headList = listPending(cwd, headRef, pendingDir);
  const headPending = new Set(headList);
  const baseSet = new Set(basePending);
  const deletedPaths = basePending.filter((p) => !headPending.has(p));
  // 路径层面新增的文件
  const touchedPaths = headList.filter((p) => !baseSet.has(p));
  // 路径两边都有但正文变了，同样算夹带投稿
  for (const p of headList) {
    if (!baseSet.has(p)) continue;
    const a = showJson(cwd, baseRef, p);
    const b = showJson(cwd, headRef, p);
    if (stableStringify(a) !== stableStringify(b)) touchedPaths.push(p);
  }

  const baseEntries = [];
  for (const p of basePending) {
    const obj = showJson(cwd, baseRef, p);
    if (obj == null) continue;
    for (const e of (Array.isArray(obj) ? obj : [obj])) baseEntries.push({ path: p, entry: e });
  }

  const attesters = new Map();
  const attest = (p) => {
    if (!attesters.has(p)) {
      attesters.set(p, deps.attest
        ? Promise.resolve(deps.attest(p))
        : attestPath({ cwd, baseRef, file: p, apiBase, token, owner: opts.owner, repo: opts.repo, mainBranch }));
    }
    return attesters.get(p);
  };

  // judgeIndexPr 是同步纯函数，而取证是异步的：先把证据取齐，再交给判定。
  const settled = new Map();
  for (const p of deletedPaths) settled.set(p, await attest(p));
  const verdict = judgeIndexPr({
    baseIndex, baseEntries, deletedPaths, touchedPaths, actualIndex,
    attest: (p) => settled.get(p) || { ok: false, reason: '未取证' },
  });
  report.ok = verdict.ok;
  report.reason = verdict.reason;
  report.consumed = deletedPaths;
  report.evidences = (verdict.evidences || []).map((e) => ({ path: e.path, pr: e.pr, commitSha: e.commitSha, ok: e.ok, reason: e.reason }));
  for (const line of String(verdict.reason).split('\n')) (verdict.ok ? log.log : log.error).call(log, '[verify-index-pr] ' + line);
  writeReport();
  return verdict.ok ? 0 : 1;
}

// 入口判据用 resolve 比对绝对路径，不要拿 argv[1] 拼 file:// URL —— 与 audit/scan.mjs
// 同一条坑：拼出来的串在 Windows 上永远不等于 import.meta.url，这个「验索引是否真由
// base 推导」的 CLI 就会静默 exit 0，看起来跑了、其实什么都没判。
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((rc) => { process.exitCode = rc; });
}
