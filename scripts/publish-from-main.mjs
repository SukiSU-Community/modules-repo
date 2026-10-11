#!/usr/bin/env node
/**
 * 合并后重建索引 —— 决定「main 上这些 pending 条目凭什么算审核通过」。
 *
 * 为什么要有这个文件。分支保护的语义是「进 main 必须过 PR、必须过审核 check」，
 * 而原来的 publish job 是在 PR 上下文里直接往 main 推索引提交的。想让 publish 改成
 * 「先往 PR 分支写索引、再合并 PR」并不通：那次索引提交落在 `pending/**` 上，会触发
 * `synchronize` 把审核再跑一遍，而新 head sha 的 required check 还没出结果时
 * `gh pr merge` 本身就过不去 —— 两个坑互锁。所以只能拆成两段：publish 只合并，
 * 索引由「已经落到 main 的内容」重建（见 .github/workflows/index.yml）。
 *
 * 拆开的代价是章没了：章是审核结论，原先由 publish 现场盖。这个文件补回这一环，
 * 而且补得比原来更硬 —— 它不读 PR 标签（有 triage 权限就能随手加一个
 * `auto-approved`）、不读评论正文（那是投稿者和模型都能影响的文本）、也不假设
 * 「分支保护肯定已经配好了」（配置是可以被另一个人关掉的，而这里要的是可复核的证据），
 * 而是回到 GitHub 去取那次审核 check 的**结论本身**：
 *
 *   checks.listForRef(pr.head.sha) 里名为 `approve` 的那一条必须 conclusion === success。
 *
 * 那条结论由 Actions 产出，仓库写权限改不了它。之所以还要专门查一次，是因为
 * 「条目出现在 main 上」并不等于「它被批准过」：pending JSON 的正文是投稿方可控文本，
 * 而合并动作在没上保护之前人类也能直接点。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { collectPendingFiles, markApproved, isApproved } from './build-index.mjs';

/**
 * 必须通过的 check 名。这个名字就是 audit.yml 里那个 job 的 `name:` ——
 * 两边靠字符串相等连接，所以 job 改名等于把闸门拆了：改名时必须同时改这里，
 * 而 test/publish-from-main.test.mjs 里钉着这条。
 */
export const APPROVE_CHECK_NAME = 'approve';

/** 人工批准的章（P4 的双签脚本会用），这里只认这个前缀，别的前缀一律不当证据 */
export const HUMAN_APPROVE_STATUS = 'human-approved';

/**
 * 从一组 check run 里取某个名字的**最终**结论。
 *
 * 同名多条是常态（re-run、多个 workflow 共用 job 名），所以按 completed_at 取最新，
 * 并且只认已经跑完的：status 还是 in_progress / queued 时 conclusion 是 null，
 * 那种情况必须当成「没通过」而不是「通过」。
 */
export function checkConclusion(runs, name = APPROVE_CHECK_NAME) {
  const list = (Array.isArray(runs) ? runs : []).filter(
    (r) => r && typeof r.name === 'string' && r.name === name
  );
  if (!list.length) return { found: false, conclusion: null };
  list.sort((a, b) => String(b.completed_at || '').localeCompare(String(a.completed_at || '')));
  const top = list[0];
  return { found: true, conclusion: top.conclusion ?? null, status: top.status ?? null };
}

/**
 * 人工批准的章。评论正文的**第一行**必须以这个标记开头，其余部分是理由。
 * 为什么用评论而不是标签：标签需要 triage 权限、而且改一次就看不出历史；评论带
 * `author_association` 与 `id`，两者都能被任何人复验（`gh api repos/<o>/<r>/issues/comments/<id>`）。
 */
export const HUMAN_APPROVAL_MARKER = '#' + HUMAN_APPROVE_STATUS;

/** 只有这两种身份算签核人（OWNER=仓库所有者，MEMBER=同 org 成员）。 */
export const TRUSTED_ASSOCIATIONS = new Set(['OWNER', 'MEMBER']);

/** 双签：默认要两个**不同的人**。同一个人发十条仍然是一签。 */
export const REQUIRED_SIGNERS = 2;

/**
 * 从 PR 评论里挑出有效的人工签。
 *
 * 判据全部是可复验的字段，不碰任何「看起来像官方」的文本：
 *   * 第一行以 `#human-approved` 开头（写在第一行是为了让人一眼看出这条评论的**用途**，
 *     而不是在讨论中间夹一句就能冒充）；
 *   * `author_association` ∈ {OWNER, MEMBER} —— 这是 GitHub 在读取时算出来的关系，
 *     冒充不了；
 *   * 有数字 `id`（拿它就能回访那条评论）。
 * 按 login 去重，所以同一个人刷多少条都只算一签。
 */
export function findHumanApprovals(comments = [], require = REQUIRED_SIGNERS) {
  const valid = [];
  const rejected = [];
  for (const c of (Array.isArray(comments) ? comments : [])) {
    const body = String((c && c.body) || '');
    const firstLine = body.trim().split('\n', 1)[0].trim();
    if (!firstLine.startsWith(HUMAN_APPROVAL_MARKER)) continue; // 不是签核评论，不参与判定
    const assoc = String((c && c.author_association) || '').toUpperCase();
    const login = String((c && c.user && c.user.login) || '');
    const id = Number(c && c.id);
    if (!TRUSTED_ASSOCIATIONS.has(assoc)) {
      rejected.push({ id, login, why: `身份是 ${assoc || '未知'}，不是 OWNER/MEMBER` });
      continue;
    }
    if (!login || !Number.isFinite(id)) {
      rejected.push({ id, login, why: '缺 login 或评论 id，无法复验' });
      continue;
    }
    valid.push({ id, login, assoc, reason: firstLine.slice(HUMAN_APPROVAL_MARKER.length).trim() });
  }
  const byLogin = new Map();
  for (const a of valid) {
    const k = a.login.toLowerCase();
    if (!byLogin.has(k)) byLogin.set(k, a); // 同一人取最早那条
  }
  const signers = [...byLogin.values()];
  return { signers, enough: signers.length >= require, require, rejected };
}

/**
 * 判定「这次合并算不算被批准」。纯函数，好测。
 *
 * 两条路，顺序不能反：
 *   1. **机器路**：head sha 上 `approve` 的结论是 success —— 审核流水线自己判的，证据最强。
 *   2. **人工路**：机器判了不通过（或没结论），但 PR 已被合并，且评论里有 ≥2 个
 *      OWNER/MEMBER 的 `#human-approved` 签名。这条路的成立前提本身就是「有人越过了红」：
 *      required check 红着的时候 Actions 合不动，所以合上的人一定是拿自己的权限点的。
 *      因此还要求 `merged_by` 不是 bot —— 哪天 org/ruleset 被改到允许 Actions 强合红 PR，
 *      这里必须拒绝盖章，而不是替那次合并背书。
 * @param {{ pr: object, checks: object[], comments?: object[], mainBranch: string, requireSigners?: number }} input
 * @returns {{ ok: boolean, reason: string, evidence: object }}
 */
export function assertMergeApproved({ pr, checks = [], comments = [], mainBranch = 'main', requireSigners = REQUIRED_SIGNERS } = {}) {
  const fail = (reason, extra = {}) => ({ ok: false, reason, evidence: { ...extra } });

  if (!pr || typeof pr !== 'object') return fail('拿不到这次推送对应的 PR，无法确认批准来源');
  if (pr.merged !== true) return fail(`PR #${pr.number} 不是已合并状态`, { pr: pr.number });
  const base = pr.base && pr.base.ref;
  if (base !== mainBranch) {
    return fail(`PR #${pr.number} 的 base 是 ${base}，不是 ${mainBranch}`, { pr: pr.number, base });
  }
  const headSha = pr.head && pr.head.sha;
  if (!/^[0-9a-f]{40}$/i.test(String(headSha || ''))) {
    return fail(`PR #${pr.number} 没有可用的 head sha`, { pr: pr.number });
  }

  const { found, conclusion } = checkConclusion(checks, APPROVE_CHECK_NAME);
  if (found && conclusion === 'success') {
    return {
      ok: true,
      kind: 'ci',
      reason: `PR #${pr.number} 的 ${APPROVE_CHECK_NAME} check 在 ${headSha.slice(0, 8)} 上为 success`,
      evidence: { pr: pr.number, headSha, checkName: APPROVE_CHECK_NAME, conclusion },
    };
  }

  // 机器路不通 —— 试人工路。先说清机器为什么不算通过，拒绝时两个理由都要能看见。
  const machine = !found
    ? `head ${headSha.slice(0, 8)} 上没有名为 ${APPROVE_CHECK_NAME} 的 check`
    : `${APPROVE_CHECK_NAME} 的结论是 ${conclusion}（不是 success）`;
  const sig = findHumanApprovals(comments, requireSigners);
  if (!sig.signers.length) {
    return fail(
      `PR #${pr.number} 未获批准：${machine}，而评论里一条 ${HUMAN_APPROVAL_MARKER} 人工签都没有`
      + '（要放行请在 PR 里留签名，见 GOVERNANCE.md）',
      { pr: pr.number, headSha, machine }
    );
  }
  if (!sig.enough) {
    return fail(
      `PR #${pr.number} 未获批准：${machine}，人工签只有 ${sig.signers.length} 个（${sig.signers.map((s) => s.login).join('、')}），`
      + `少于要求的 ${sig.require} 个不同的人`,
      { pr: pr.number, headSha, machine, signers: sig.signers }
    );
  }
  const mergedBy = String((pr.merged_by && pr.merged_by.login) || '');
  if (!mergedBy) {
    return fail(`PR #${pr.number} 查不到是谁合的，人工放行不留名等于没有放行`, { pr: pr.number, headSha, machine });
  }
  if (/\[bot\]$/i.test(mergedBy)) {
    return fail(
      `PR #${pr.number} 在 ${machine} 的情况下被 ${mergedBy}（bot）合并 —— 说明 org/ruleset 被改到允许`
      + ' Actions 强合红 PR 了。这里拒绝替那次合并盖章，请先去查保护配置。',
      { pr: pr.number, headSha, machine, mergedBy }
    );
  }
  return {
    ok: true,
    kind: 'human',
    reason: `PR #${pr.number} 由 ${mergedBy} 人工合并，并有 ${sig.signers.length} 个 OWNER/MEMBER 的 ${HUMAN_APPROVAL_MARKER} 签名`,
    evidence: { pr: pr.number, headSha, mergedBy, signers: sig.signers, machine },
  };
}

/**
 * 章上写什么。`by` 必须是**别人也能复验**的指针，而不是「ci 说过」这种自证：
 *   * 机器路：拿 pr + headSha，任何人 `gh api repos/<o>/<r>/check-runs/<headSha>?name=approve`
 *     都能重跑这个判断。
 *   * 人工路：把每个签名的**评论 id** 写进去，任何人
 *     `gh api repos/<o>/<r>/issues/comments/<id>` 就能看到是谁、以什么身份、写了什么理由。
 */
export function approvalBy({ owner, repo, evidence, kind } = {}) {
  const sha = String(evidence.headSha || '').slice(0, 12);
  // kind 从证据本身推：有签名列表就是人工路。多一个要手工同步的参数，就多一个会写错的地方。
  const k = kind || (evidence && evidence.signers ? 'human' : 'ci');
  if (k === 'human') {
    const ids = (evidence.signers || []).map((s) => `c${s.id}`).join('+');
    return `${HUMAN_APPROVE_STATUS}#${owner}/${repo}PR${evidence.pr}@${sha}/${ids}`;
  }
  return `ci:${APPROVE_CHECK_NAME}#${owner}/${repo}PR${evidence.pr}@${sha}`;
}

/** 复验路径：让人拿到章就知道该敲哪条命令，不用回去翻 workflow 日志。 */
export function approvalVerifyHint({ owner, repo, evidence } = {}) {
  if (evidence && evidence.signers) {
    const cmds = evidence.signers.map((s) => `gh api repos/${owner}/${repo}/issues/comments/${s.id}`);
    return cmds.join(' && ');
  }
  return `gh api repos/${owner}/${repo}/commits/${evidence.headSha}/pulls`;
}

/**
 * 给一个 pending 条目盖章（走 build-index 的 markApproved，契约只有一处定义）。
 * 已经 approved 的条目原样返回，避免每次重跑都改 `at` 造成无意义 diff。
 */
export function stampEntry(entry, { owner, repo, evidence, now = () => new Date().toISOString(), risk }) {
  if (isApproved(entry)) return { entry, stamped: false };
  const by = approvalBy({ owner, repo, evidence });
  const meta = { by, at: now() };
  if (risk) meta.risk = risk;
  // 把复验路径留在章里：以后有人问「凭什么」，不用回去翻 workflow 日志。
  meta.verify = approvalVerifyHint({ owner, repo, evidence });
  return { entry: markApproved(entry, meta), stamped: true };
}

/**
 * 读一个 pending 文件 -> 盖章 -> 写回。数组条目逐条处理。
 * @returns {{ changed: boolean, ids: string[], skipped: string[] }}
 */
export function stampPendingFile(
  file,
  { owner, repo, evidence, onlyPaths = null, risk, log = console }
) {
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) {
    // 被索引消费掉的 pending 是「删除」。workflow 侧已经用 --diff-filter=ACMR 挡了一道，
    // 这里再兜一次：读不到就当没这回事，别让一个已删除的条目把整次盖章判失败。
    log.log(`[publish-from-main] 跳过 ${path.basename(abs)}：文件已不存在（多半是被上一次索引消费了）`);
    return { changed: false, ids: [], skipped: [], missing: true };
  }
  const raw = JSON.parse(fs.readFileSync(abs, 'utf8'));
  const list = Array.isArray(raw) ? raw : [raw];
  const ids = [];
  const skipped = [];
  let changed = false;

  const targets = onlyPaths && !onlyPaths.includes(abs) ? [] : list;
  const stamped = targets.map((e) => {
    const r = stampEntry(e, { owner, repo, evidence, risk });
    if (r.stamped) {
      changed = true;
      if (e && e.id) ids.push(String(e.id));
    } else if (e && e.id) {
      skipped.push(String(e.id));
    }
    return r.entry;
  });
  const out = Array.isArray(raw) ? stamped : stamped[0];

  if (changed) {
    fs.writeFileSync(abs, `${JSON.stringify(out, null, 2)}\n`, 'utf8');
    log.log(`[publish-from-main] 盖章节 -> ${path.basename(abs)}（${ids.join(', ')}）`);
  } else if (onlyPaths && !onlyPaths.includes(abs)) {
    log.log(`[publish-from-main] 跳过 ${path.basename(abs)}：本次推送没有改动它`);
  }
  return { changed, ids, skipped };
}

/* ------------------------------------------------------------------ 取证据 */

async function ghFetch(apiBase, token, segs, opts = {}) {
  const url = `${apiBase.replace(/\/$/, '')}/${segs.join('/')}`;
  const res = await fetch(url, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
      ...(opts.headers || {}),
    },
    ...(opts.body ? { method: 'POST', body: JSON.stringify(opts.body) } : {}),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.json();
}

/**
 * 找到「把 sha 带进 main 的那个 PR」。squash 合并时一次推送只有一个 PR；
 * 真出现多个（merge commit 形式）时，取 base 是目标分支的那一个，并在日志里说明还有其它 ——
 * 这里刻意不做「多个 PR 分别验证」的复杂度：Worker 的投稿 PR 永远是一个 id 一个 PR，
 * 多 PR 混进同一次推送本来就该人工看。
 *
 * 注意不靠列表接口判断「是否已合并」：`/commits/{sha}/pulls` 返回的是精简对象，
 * 有没有 merged/merged_at 不在承诺范围内。合并状态一律由后面那次单 PR 详情来判断，
 * 所以这里只挑候选，判定交给 assertMergeApproved。
 */
export async function findPrForCommit({ apiBase, token, owner, repo, sha, mainBranch = 'main', log = console }) {
  const data = await ghFetch(apiBase, token, [`repos/${owner}/${repo}/commits/${sha}/pulls`]);
  // `/commits/{sha}/pulls` 返回的是**裸数组**，不是 `{ pull_requests: [...] }`。
  // 这个错只在真实调用里暴露：dispatch 到 PR #4 的合并提交时，脚本读到 undefined →
  // 认为「没有关联 PR」→ 拒绝盖章，而 gh api 手工查同一个提交明明有 PR #4。
  // 两种形状都认，是为了不再依赖单一版本的响应封装；但测试的桩必须改成 GitHub
  // 真实返回的那种（裸数组），否则桩和线上永远各说各话。
  const pulls = (Array.isArray(data) ? data
    : (data && Array.isArray(data.pull_requests) ? data.pull_requests : []));
  if (!pulls.length) {
    return { pr: null, checks: [], others: [], note: `提交 ${String(sha).slice(0, 8)} 没有关联的 PR（可能是人工直接推到 main）` };
  }
  const chosen = pulls.find((p) => p && p.base && p.base.ref === mainBranch) || pulls[0];
  const detail = await ghFetch(apiBase, token, [`repos/${owner}/${repo}/pulls/${chosen.number}`]);
  const pr = detail ? { ...chosen, ...detail } : chosen;
  const checksData = pr.head && pr.head.sha
    ? await ghFetch(apiBase, token, [`repos/${owner}/${repo}/commits/${pr.head.sha}/check-runs`])
    : null;
  const checks = (checksData && Array.isArray(checksData.check_runs) ? checksData.check_runs : []);
  // 评论只在机器路不通时才需要，但**一律取**：人工签的证据形状和机器路一样要能复验，
  // 少取一次就会变成「机器红着的时候没人能证明谁放行过」。分页取满 100 条足够 ——
  // 一条投稿 PR 的讨论不会更长，而超了也只是签核评论落在窗口外，判定会明确拒绝而不是放行。
  const commentsData = pr.number
    ? await ghFetch(apiBase, token, [`repos/${owner}/${repo}/issues/${pr.number}/comments?per_page=100`])
    : null;
  const comments = Array.isArray(commentsData) ? commentsData : [];
  if (pulls.length > 1) log.log(`[publish-from-main] 注意：该提交关联 ${pulls.length} 个 PR，按 #${pr.number} 判定`);
  return { pr, checks, comments, others: pulls.filter((p) => p.number !== pr.number) };
}

/* ---------------------------------------------------------------------- CLI */

export function parseArgs(argv) {
  const opts = { _: [], changed: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { opts._.push(a); continue; }
    const key = a.slice(2);
    const eq = key.indexOf('=');
    if (eq >= 0) { opts[key.slice(0, eq)] = key.slice(eq + 1); continue; }
    const next = argv[i + 1];
    if (key === 'changed') {
      // --changed 接多个路径，吃到下一个 -- 为止
      while (i + 1 < argv.length && !argv[i + 1].startsWith('--')) opts.changed.push(path.resolve(argv[++i]));
      continue;
    }
    if (next && !next.startsWith('--')) { opts[key] = next; i++; } else opts[key] = true;
  }
  return opts;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const log = deps.log || console;
  if (opts.help || !opts.pending || !opts.sha || !opts.owner || !opts.repo) {
    log.log(`用法: node publish-from-main.mjs --pending <dir> --sha <mainSha> --owner <o> --repo <r>
       [--index <json>] [--changed <path> ...] [--main-branch main] [--report <file.json>] [--dry-run]
   给「本次推送改动到的 pending 条目」盖审核章；章的证据是那 PR 上名为 approve 的 check 结论。`);
    return opts.help ? 0 : 2;
  }

  const token = deps.token || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
  if (!token) { log.error('[publish-from-main] 没有 GITHUB_TOKEN，取不到批准证据，拒绝盖章节。'); return 1; }
  const apiBase = deps.apiBase || process.env.GITHUB_API_URL || 'https://api.github.com';
  const mainBranch = opts['main-branch'] || 'main';

  const files = collectPendingFiles(path.resolve(opts.pending));
  // 判定结果落一份机器可读的报告：push 触发的 workflow 里没有 context.issue.number，
  // 要「把为什么没进索引贴回 PR」就只能靠这里留下的指针。不传 --report 则不写文件。
  const report = { ok: false, reason: '', pr: null, headSha: '', ids: [], pendingCount: files.length };
  const writeReport = () => {
    if (!opts.report) return;
    fs.writeFileSync(path.resolve(opts.report), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  };

  if (!files.length) { log.log('[publish-from-main] pending 目录是空的，无需重建索引。'); report.ok = true; report.reason = 'no-pending'; writeReport(); return 0; }

  const { pr, checks = [], comments = [], note } = await findPrForCommit({
    apiBase, token, owner: opts.owner, repo: opts.repo, sha: opts.sha, mainBranch, log,
  });
  const verdict = assertMergeApproved({ pr, checks, comments, mainBranch });
  report.pr = verdict.evidence?.pr ?? null;
  report.headSha = verdict.evidence?.headSha ?? '';
  if (!verdict.ok) {
    report.reason = verdict.reason;
    log.error(`[publish-from-main] 未获批准，不盖章节：${verdict.reason}${note ? `（${note}）` : ''}`);
    log.error(
      '[publish-from-main] 条目留在 main 上但不会进索引；要么让审核结论转为批准，'
      + `要么由两个 OWNER/MEMBER 在 PR 里各留一条以 ${HUMAN_APPROVAL_MARKER} 开头的评论再重跑（见 GOVERNANCE.md）。`
    );
    writeReport();
    return 1;
  }
  report.ok = true;
  report.kind = verdict.kind;
  report.reason = verdict.reason;
  log.log(`[publish-from-main] 批准证据成立（${verdict.kind === 'human' ? '人工双签' : '审核流水线'}）：${verdict.reason}`);

  let touched = 0;
  // collectPendingFiles 返回的是 { file, rel, entries }，不是路径字符串
  for (const rec of files) {
    const r = stampPendingFile(rec.file, {
      owner: opts.owner, repo: opts.repo, evidence: verdict.evidence,
      onlyPaths: opts.changed.length ? opts.changed : null, risk: opts.risk, log,
    });
    if (r.changed) touched++;
    report.ids.push(...r.ids);
  }
  if (!touched) {
    log.log('[publish-from-main] 本次推送没有需要盖章的新条目（都已经是 approved，或不在改动范围内）。');
  }
  if (opts['dry-run']) log.log('[publish-from-main] --dry-run：不写索引，仅止于盖章判定。');
  writeReport();
  return 0;
}

// 入口判据用 resolve 比对绝对路径，不要拿 argv[1] 拼 file:// URL：
// 拼出来的那串在 Windows 上永远不等于 import.meta.url（缺第三个斜杠），于是这个
// 负责「盖章」的 CLI 在开发机上静默 exit 0、什么也不做 —— 与 audit/scan.mjs 刚在
// Linux runner 上踩到的同一个坑（那边 argv[1] 还是相对的，坏得更彻底）。
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((rc) => { process.exitCode = rc; });
}
