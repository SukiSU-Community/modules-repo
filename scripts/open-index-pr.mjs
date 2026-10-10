#!/usr/bin/env node
/**
 * open-index-pr.mjs
 *
 * 把「工作树里已经算好的索引改动」交给 Worker，让它用 GitHub App 的身份开成索引 PR。
 *
 * 为什么要绕 Worker 一手（而不是在这里 git push + gh pr create）：
 *   1. org `SukiSU-Community` 禁止 GitHub Actions 创建/批准 PR —— `gh pr create` 直接失败，
 *      仓库级那个同名开关 PATCH 返回 409「organization does not allow」；
 *   2. **机器人写的提交不触发 pull_request 检查**：实测 Actions 推上来的索引分支开成 PR 后
 *      `no checks reported`，而人工补一个自己名下的提交后检查立刻跑起来。
 *   App 名下的提交两个问题都没有（投稿 PR #4 就是它开的，`audit`/`derive`/`approve` 照常跑）。
 *   于是分工变成：Actions 盖章 + 算索引 + 校验 + 等绿 + 合并，App 只负责「写分支、开 PR」。
 *
 * 这个脚本只做一件事：**从 git 里取改动集**，自检形状后 POST。
 * 它不直接碰 GitHub（App 凭据不在它手里），也不改工作树。
 *
 * 用法：
 *   node scripts/open-index-pr.mjs --worker <https url> --branch index/rebuild-<runId> \
 *        --base-sha <main 上的提交> [--root <仓库目录>] [--title ...] [--body ...] [--dry-run]
 *
 * 密钥从环境变量 REBUILD_TOKEN 读（Actions secret），**绝不进命令行** ——
 * 命令行参数会出现在 runner 的进程列表和日志回显里。
 *
 * 退出码：0 = PR 已就绪（新开或复用），1 = 没做成（原因打在 stderr）。
 * 只用 node: 内置模块（本仓库硬性约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

export const INDEX_FILE = 'json/modules.json';
export const PENDING_DIR = 'pending';
const BRANCH_RE = /^index\/rebuild-\d{1,20}$/;
const PENDING_PATH_RE = /^pending\/[A-Za-z0-9._-]{1,64}\/[0-9]{1,12}\.json$/;

function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
}

/**
 * ref 里被跟踪的 pending 文件。
 *
 * 用 `ls-tree` 而不是 `git diff`：diff 会把工作树里的未跟踪脏文件也算进来，
 * 而那些东西从没经过审核，不该出现在索引 PR 里。
 */
export function trackedPending(root, ref = 'HEAD') {
  const out = git(root, ['ls-tree', '-r', '--name-only', ref, '--', PENDING_DIR]);
  return out
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => PENDING_PATH_RE.test(s));
}

/**
 * 从 ref 与工作树的差集里取改动集。
 *
 * 删除 = ref 里跟踪、工作树里已不存在（那就是被索引消费掉的条目）；
 * 修改 = 两边都在但内容不同（盖章后的条目）；未跟踪的新文件一律忽略。
 *
 * @returns {{files: Array<{path: string, content: string|null}>, deleted: string[], modified: string[]}}
 */
export function collectChanges(root, ref = 'HEAD') {
  const deleted = [];
  const modified = [];
  for (const p of trackedPending(root, ref)) {
    const abs = path.resolve(root, p);
    if (!fs.existsSync(abs)) { deleted.push(p); continue; }
    let atRef = '';
    try { atRef = git(root, ['show', `${ref}:${p}`]); } catch { atRef = ''; }
    if (atRef !== fs.readFileSync(abs, 'utf8')) modified.push(p);
  }

  const indexPath = path.resolve(root, INDEX_FILE);
  if (!fs.existsSync(indexPath)) throw new Error(`${INDEX_FILE} 不存在，不能开「索引 PR」`);
  const indexContent = fs.readFileSync(indexPath, 'utf8');
  let indexAtRef = null;
  try { indexAtRef = git(root, ['show', `${ref}:${INDEX_FILE}`]); } catch { indexAtRef = null; }

  const files = [];
  // 索引文件没变就不列它：只消费 pending 而索引一字未动，说明那次合并没带来新条目。
  if (indexAtRef !== indexContent) files.push({ path: INDEX_FILE, content: indexContent });
  for (const p of deleted) files.push({ path: p, content: null });
  for (const p of modified) files.push({ path: p, content: fs.readFileSync(path.resolve(root, p), 'utf8') });
  return { files, deleted, modified };
}

/**
 * 端点侧的白名单在这里先自检一遍：省一次必然失败的往返，也让错误更早、更可解释。
 * @returns {string} 空串=合格，否则是拒绝理由
 */
export function validatePayload(payload) {
  const o = payload && typeof payload === 'object' ? payload : {};
  if (!BRANCH_RE.test(String(o.branch ?? ''))) return `branch 必须是 index/rebuild-<数字>，收到「${String(o.branch).slice(0, 60)}」`;
  if (!/^[0-9a-f]{40}$/.test(String(o.base_sha ?? ''))) return 'base_sha 必须是 40 位小写十六进制';
  if (!Array.isArray(o.files) || !o.files.length) return 'files 是空的：没有改动就别开索引 PR';
  const paths = o.files.map((f) => String((f && f.path) || ''));
  if (!paths.includes(INDEX_FILE)) return `files 里必须有 ${INDEX_FILE}`;
  if (!o.files.some((f) => f && f.content === null)) return '没有消费任何 pending 条目：这不是索引重建，是一次手改索引';
  const bad = paths.filter((p) => p !== INDEX_FILE && !PENDING_PATH_RE.test(p));
  if (bad.length) return `路径不在允许列表内：${bad.slice(0, 3).join(', ')}`;
  return '';
}

export function parseArgs(argv) {
  const opts = { _: [], dryRun: false, root: '.', title: 'chore(index): rebuild after merge [skip ci]', body: '' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--worker') opts.worker = next();
    else if (a === '--branch') opts.branch = next();
    else if (a === '--base-sha') opts.baseSha = next();
    else if (a === '--root') opts.root = next();
    else if (a === '--title') opts.title = next();
    else if (a === '--body') opts.body = next();
    else if (a === '--out-file') opts.outFile = next();
    else if (a === '--dry-run') opts.dryRun = true;
    else opts._.push(a);
  }
  return opts;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const log = deps.log || console;
  const fetchImpl = deps.fetch || ((u, init) => globalThis.fetch(u, init));

  const token = deps.token !== undefined ? deps.token : process.env.REBUILD_TOKEN;
  if (!token) {
    log.error('[open-index-pr] 没有 REBUILD_TOKEN 环境变量：宁可不发，也不发一个不带鉴权的写仓库请求');
    return 1;
  }
  if (!opts.worker || !/^https:\/\//i.test(String(opts.worker))) {
    log.error('[open-index-pr] --worker 必须是一个 https 地址');
    return 1;
  }

  let changes;
  try {
    changes = collectChanges(opts.root, 'HEAD');
  } catch (e) {
    log.error(`[open-index-pr] 取改动集失败：${e.message}`);
    return 1;
  }
  const payload = {
    base_sha: String(opts.baseSha ?? ''),
    branch: String(opts.branch ?? ''),
    title: opts.title,
    body: opts.body || '',
    files: changes.files,
  };
  log.log(`[open-index-pr] 改动 ${payload.files.length} 项：删除 ${changes.deleted.length}，修改 ${changes.modified.length}`);

  const err = validatePayload(payload);
  if (err) { log.error(`[open-index-pr] 载荷不合格：${err}`); return 1; }
  if (opts.dryRun) {
    log.log('[open-index-pr] --dry-run：' + JSON.stringify(payload.files.map((f) => ({ path: f.path, kind: f.content === null ? 'delete' : 'write' }))));
    return 0;
  }

  let res;
  try {
    res = await fetchImpl(String(opts.worker).replace(/\/$/, '') + '/rebuild-index', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-rebuild-token': token },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    log.error(`[open-index-pr] 请求没发出去：${e.message}（索引不会更新，main 上的 pending 仍在等下一次）`);
    return 1;
  }
  let json;
  try { json = await res.json(); } catch { json = { ok: false, status: 'http_' + res.status }; }
  if (!json || !json.ok) {
    log.error(`[open-index-pr] Worker 拒绝：status=${(json && json.status) || '?'} ${(json && json.error) || ''}（HTTP ${res.status}）`);
    return 1;
  }
  log.log(`[open-index-pr] 索引 PR ${json.status === 'exists' ? '已存在，复用' : '已创建'}：${json.pr}`);
  if (deps.onPr) deps.onPr(json.pr);
  // 写文件而不是只打日志：workflow 下一步要拿这个号去 `gh pr checks --watch`，
  // 从 stdout 里 sed 出来是最先坏掉的那种耦合。
  if (opts.outFile) fs.writeFileSync(opts.outFile, String(json.pr) + '\n');
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((rc) => { process.exitCode = rc; });
}
