#!/usr/bin/env node
/**
 * harvest-evidence.mjs —— §8 证据固化：把「处置针对的那次投稿」永久钉成一份可复核的文件。
 *
 * 为什么需要它：下架一条处置在台账里只剩选择器 + 理由 + 署名，而**当初审核过的那一包**散在三个
 * 会各自消失的地方 —— `pending/<id>/<versionCode>.json` 在合并后被 `build-index --consume` 从工作树
 * 删掉（只在 git 历史里活着）、扫描报告的 artifact 有保留期、只有 PR 评论是永久的。
 * 这一步把三者收进一个文件，文件名 = **它自己字节的 SHA-256**，于是台账里那条
 * `evidence[].file` 指的东西既不可悄悄替换、也不需要信任何人的自述。
 *
 * 执行者是这条 CLI 而不是 CI job（spec §8 原本写的是 CI），原因量在 `index.yml:214-221`：
 *   1. org 禁止 GitHub Actions 创建/批准 PR；
 *   2. **Actions 推的提交不触发 pull_request 检查** ⇒ 固化 job 往台账 PR 分支推一发，
 *      那条 PR 就变成「最新提交上没有 checks」的死局（ruleset 要 approve 才放行）。
 * 绕开它要么让 Worker 用 App 身份写（多一个「App 往任意分支写任意文件」的端点），
 * 要么靠 `[skip ci]`（等于自己把 checks 关掉）。这一层今天已经有人的凭据（`gh pr create` 就是人跑的），
 * 而处置这个动作本身就是人跑的 —— 固化挂在同一条命令上，不新增任何人工步骤，也不新增攻击面。
 *
 * 用法（独立跑，只打印不落盘；revoke.mjs 会自己带 --write）：
 *   node scripts/harvest-evidence.mjs --id e2e_probe_p04 --version-code 7301872
 *   node scripts/harvest-evidence.mjs --sha256 <64hex>
 *   node scripts/harvest-evidence.mjs --uid 10086001
 *
 * 只用 node: 内置模块（本仓库硬约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '..');

export const EVIDENCE_SCHEMA = 'sukisu-evidence-v1';
/** 与 scripts/verify-index-pr.mjs 的 EVIDENCE_DIR 同一个值；改名必须两处同改。 */
export const EVIDENCE_DIR = 'evidence';
/** audit.yml 发布 PR 评论那一步写死的那句标题（固化只认这一条是审核评论）。 */
export const AUDIT_COMMENT_HEAD = '## 模块投稿安全审核';
/** 一次固化最多写几个文件：按 UID 拉黑会命中这个人全部投稿，不设上限会变成一发写出上百个文件。 */
export const MAX_EVIDENCE_FILES = 10;

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * 文件的**唯一**字节定义。文件名按它算，所以「重新固化同一份内容」必然落回同一个文件 ——
 * 幂等不是额外逻辑，是这条定义的直接后果。
 */
export function canonicalBytes(obj) {
  return Buffer.from(JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

export function evidencePathFor(bytes) {
  return `${EVIDENCE_DIR}/${sha256Hex(bytes)}.json`;
}

/**
 * 从提交标题里取承载这次投稿的 PR 号。
 * 两种真实形状（都在线上见过）：squash 合并 `pending: e2e_probe_p04 7301872 (#30)`、
 * 合并提交 `Merge pull request #27 from ...`。分支上那些没有 PR 号的提交不算来源 ——
 * 它们指向的对象还没被合过，固化要的是「进了 main 的那一发」。
 */
export function prFromCommitSubject(subject) {
  const s = String(subject || '');
  const squash = s.match(/\(#(\d+)\)\s*$/);
  if (squash) return Number(squash[1]);
  const merge = s.match(/^Merge pull request #(\d+)/);
  if (merge) return Number(merge[1]);
  return null;
}

/** 选择器与一条 pending 记录是否对得上（AND 语义在这里退化成「任一选择器命中即算同一次投稿」）。 */
export function matchesSelectors(rec, sel) {
  if (!rec || typeof rec !== 'object') return false;
  const versions = Array.isArray(rec.versions) ? rec.versions : [];
  if (sel.id) {
    if (String(rec.id) !== String(sel.id)) return false;
    if (sel.versionCode !== undefined && sel.versionCode !== null) {
      return versions.some((v) => Number(v && v.versionCode) === Number(sel.versionCode));
    }
    return true;
  }
  if (sel.sha256) {
    const want = String(sel.sha256).toLowerCase();
    return versions.some((v) => String(v && v.sha256).toLowerCase() === want);
  }
  if (sel.coolapkUid) return String(rec.coolapkUid) === String(sel.coolapkUid);
  return false;
}

/**
 * 在 main 的历史里找那些「新增过 pending/**.json」的提交。
 * 只看 main 是因为 `--all` 会把分支上没合过的中间提交也算进来，而固化要的来源是被合过的那一发。
 */
export function findPendingCommits(git, cwd) {
  let raw;
  try {
    raw = git(cwd, ['log', 'main', '--diff-filter=A', '--name-only', '--format=%H%x1f%s', '--', 'pending/']);
  } catch (e) {
    // 没有本地 main 这个引用时必须把这句原话带出去，不能退化成「历史里没有命中」——
    // 后者是一句会诱导人去改选择器的诊断，而真正要修的是这个克隆的引用。
    throw new Error(`读不到本地 main 上的 pending 历史（${String((e && e.stderr) || (e && e.message) || e).trim().split('\n')[0]}）`
      + '—— 这条命令要在 modules-repo 的克隆里跑，且本地得有 main（git fetch origin main:main）');
  }
  const rows = [];
  let sha = '';
  let subject = '';
  for (const line of raw.split('\n')) {
    if (!line) continue;
    if (line.includes('\x1f')) {
      const i = line.indexOf('\x1f');
      sha = line.slice(0, i);
      subject = line.slice(i + 1);
    } else if (line.startsWith('pending/')) {
      rows.push({ commitSha: sha, commitSubject: subject, filePath: line.trim() });
    }
  }
  return rows;
}

/**
 * 取历史里那个 blob 的内容。**不能读工作树** —— 合并时 `build-index --consume` 会把
 * `pending/**` 从树里删掉（build-index.mjs:474），文件只在历史里活着；
 * 2026-10-17 第一版就是照工作树路径读的，于是「main 的历史里没有命中的 pending」这句假诊断
 * 把四条真夹具全判成没有 —— 这句话恰好是这条命令最容易伪装成功的失败方式。
 */
export function readBlob(git, cwd, commitSha, filePath) {
  return git(cwd, ['show', `${commitSha}:${filePath}`]);
}

/**
 * 解析审核评论里那一包一包的呈现块。
 * 静态块的正文里**自己带 ``` 围栏**（贴 script 片段用的），所以「数围栏」必然数错；
 * 这里按 `<details><summary>静态报告 · X</summary>` / `AI 安全员 · X` 这两种标记切段，
 * AI 段再取段首那个 json 围栏 —— 为什么只取第一个闭合点见 firstJsonFence 那段注释。
 */
export function parseAuditComment(body) {
  const text = String(body || '');
  const mark = /<details><summary>(静态报告|AI 安全员) · ([^<\n]*)<\/summary>\n?/g;
  const hits = [...text.matchAll(mark)];
  const byName = new Map();
  hits.forEach((h, i) => {
    const [, kind, name] = h;
    const from = h.index + h[0].length;
    const to = i + 1 < hits.length ? hits[i + 1].index : text.length;
    const seg = text.slice(from, to).replace(/\s*<\/details>\s*$/, '');
    if (!byName.has(name)) byName.set(name, { name, staticMarkdown: '', aiRaw: '', ai: null, aiParseFailed: false });
    const pkg = byName.get(name);
    if (kind === '静态报告') pkg.staticMarkdown = seg.trim();
    else {
      pkg.aiRaw = seg.trim();
      const span = firstJsonFence(pkg.aiRaw);
      if (span === null) { pkg.aiParseFailed = true; return; }
      try {
        pkg.ai = JSON.parse(span);
      } catch {
        pkg.aiParseFailed = true;
      }
    }
  });
  return [...byName.values()];
}

/**
 * 取段首那个 ```json 围栏到**它的第一个**闭合围栏之间的内容；配不上就 null（不猜）。
 *
 * 为什么只取第一个闭合点就够：那一串是 `audit.yml` 用 `JSON.stringify(pickAi(a), null, 2)` 产的，
 * JSON 的字符串值里不可能有真换行，所以合法的那一份里**只可能有一个**闭合围栏；
 * 数出第二个闭合围栏的段说明那段根本不是这个格式产的（被截断、被手工改过），那种情况判「读不出来」，
 * 而不是去试哪个闭合点能解析 —— 后者是在替一份坏数据编一个能过的形状。
 * 调用方传进来的是**已经 trim 过**的那一段（`<summary>` 与围栏之间隔着 markdown 要的空行，
 * 2026-10-17 拿真评论量到的第一条就是这个位置：不 trim 时每条评论都判成读不出来）。
 */
function firstJsonFence(seg) {
  const t = String(seg);
  const open = t.match(/^```[ \t]*json[ \t]*\r?\n/);
  if (!open) return null;
  const rest = t.slice(open[0].length);
  const close = rest.indexOf('\n```');
  return close < 0 ? null : rest.slice(0, close);
}

/**
 * 默认实现：本地 `fetch` + 可选 GITHUB_TOKEN。
 * 公开仓库不带 token 也能读（限流 60/小时），带 token 只是为了多下几发不被掐。
 */
export async function defaultFetchComments(ownerRepo, pr, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  const token = deps.token !== undefined ? deps.token : process.env.GITHUB_TOKEN || '';
  const url = `https://api.github.com/repos/${ownerRepo}/issues/${pr}/comments?per_page=100`;
  const headers = { 'user-agent': 'sukisu-revoke-cli', accept: 'application/vnd.github+json' };
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetchImpl(url, { headers });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = await res.json();
  return Array.isArray(json) ? json : [];
}

/** 从 origin 的远端地址推 owner/repo（不写死：fork 跑这条命令也该指向它自己的仓）。 */
export function ownerRepoFromRemote(git, cwd) {
  let url = '';
  try {
    url = git(cwd, ['config', '--get', 'remote.origin.url']).trim();
  } catch {
    return null;
  }
  const m = url.match(/github\.com[:/]([^/\s]+\/[^/\s]+?)(?:\.git)?\/?$/i);
  return m ? m[1] : null;
}

/**
 * 把一条已命中的 pending 记录 + 它的审核评论收成一份证据对象。
 * 评论拿不到（网络、限流、老 PR 被删）不写成「没有报告」，而是 `report: null` + `reportWhy` ——
 * 前者是「固化跑过了但没有报告」，后者是「固化没能力拿到报告」，两种状态不许长成同一个形状。
 *
 * ⚠️ 这个对象里**一个会变的字段都不许有**：文件名是它字节的 SHA-256，而「同一个包固化两次
 * 落回同一个文件」这条幂等性是整个命名的全部意义。所以这里不放 `capturedAt`，也不放
 * 「这次是用哪套选择器命中的」—— 前者属于台账的 `evidence[].at`（人的那一步才需要时间戳），
 * 后者由 `package` 里的 id/versionCode/sha256 完全决定，写第二份就是给同一份内容造第二个哈希。
 * 2026-10-17 实测：带 `capturedAt` 的第一版连跑三次给出三个文件名，幂等性是假的。
 */
export function buildEvidence({ match, packages, reportWhy = null }) {
  const rec = match.record;
  const versions = Array.isArray(rec.versions) ? rec.versions : [];
  // 一个 pending 文件只带一个版本（Worker 那份 buildPendingJson 写的就是 versions:[单条]），
  // 所以这里**不看调用方用了哪套选择器**：按记录自己的第一条取。
  // 照着选择器挑版本会让同一个包经 `--id` 和 `--sha256` 两条路固化出两份不同字节、两个文件名。
  const version = versions[0] || {};
  const identity = rec.identity && typeof rec.identity === 'object' ? rec.identity : null;
  const nickname = identity && (identity.nickname || identity.name) || rec.uploader || rec.author || null;
  const evidence = {
    schema: EVIDENCE_SCHEMA,
    capturedBy: 'scripts/harvest-evidence.mjs',
    integrity: {
      algorithm: 'sha256-of-file-bytes',
      note: '文件名 = 本文件字节的 SHA-256。字节定义：JSON.stringify(对象,null,2) + 一个换行，UTF-8。',
    },
    subject: {
      coolapkUid: String(rec.coolapkUid ?? ''),
      ...(nickname ? { username: String(nickname) } : {}),
    },
    package: {
      id: rec.id ?? null,
      versionCode: version.versionCode ?? null,
      sha256: version.sha256 ?? null,
      size: version.size ?? null,
      zipUrl: version.zipUrl ?? null,
      releaseTag: rec.releaseTag ?? null,
      assetName: rec.assetName ?? null,
      source: rec.source ?? null,
      submittedAt: rec.submittedAt ?? null,
    },
    pending: {
      path: match.filePath,
      commitSha: match.commitSha,
      commitSubject: match.commitSubject,
      record: rec,
    },
    pr: match.pr === null ? null : { number: match.pr, url: match.prUrl || null },
    // 三种状态分开写：拿到审核评论（哪怕里面 0 个逐包块）/ 没拿到评论。
    // 「评论里没块」和「没评论」是两件不同的事，合成 null 会让公示页把前者说成「报告丢了」。
    report: match.commentId !== undefined && match.commentId !== null
      ? { commentId: match.commentId, commentUrl: match.commentUrl ?? null, packages: packages || [] }
      : null,
    ...(reportWhy ? { reportWhy } : {}),
  };
  return evidence;
}

/**
 * 固化主流程。纯 IO 都从 deps 注入（git / fetchComments / ownerRepo / token），
 * 这样 test 里能用真 git 夹具跑同一条代码路径，而不是另养一份假实现。
 */
export async function harvest({ cwd = ROOT, selectors, deps = {} } = {}) {
  const git = deps.git || ((d, args) => execFileSync('git', args, { cwd: d, encoding: 'utf8' }));
  const ownerRepo = deps.ownerRepo || ownerRepoFromRemote(git, cwd) || 'SukiSU-Community/modules-repo';
  const fetchComments = deps.fetchComments
    || ((pr) => defaultFetchComments(ownerRepo, pr, { fetch: deps.fetch, token: deps.token }));
  const rows = findPendingCommits(git, cwd);
  const matches = [];
  const notes = [];
  let unreadable = 0;
  for (const row of rows) {
    if (matches.some((m) => m.filePath === row.filePath && m.commitSha === row.commitSha)) continue;
    let rec;
    try {
      rec = JSON.parse(readBlob(git, cwd, row.commitSha, row.filePath));
    } catch {
      // 读不动的那几条不许静默消失：它们会作为一句计数出现在结论里（见下面 whyEmpty）。
      unreadable += 1;
      continue;
    }
    if (!matchesSelectors(rec, selectors)) continue;
    const pr = prFromCommitSubject(row.commitSubject);
    const m = {
      ...row,
      record: rec,
      pr,
      prUrl: pr === null ? null : `https://github.com/${ownerRepo}/pull/${pr}`,
    };
    if (pr === null) {
      m.reportWhy = '承载它的提交标题里没有 PR 号 —— 这一发不是从 PR 合进 main 的，没有可回访的审核评论';
    } else {
      try {
        const comments = await fetchComments(pr);
        const audit = comments.filter((c) => String(c.body || '').startsWith(AUDIT_COMMENT_HEAD));
        const latest = audit[audit.length - 1];
        if (!latest) {
          m.reportWhy = `PR #${pr} 的评论里没有以「${AUDIT_COMMENT_HEAD}」开头的审核评论`;
        } else {
          m.commentId = latest.id;
          m.commentUrl = latest.html_url;
          m.packages = parseAuditComment(latest.body);
          if (m.packages.length === 0) {
            m.reportWhy = `PR #${pr} 的审核评论里没有「逐包呈现」块（这条评论早于逐包呈现上线，评论本身仍然可回访）`;
          }
        }
      } catch (e) {
        // 只把**稳定**的那部分写进证据：报错原文会随网络抖动变，而文件名字节里不许有会抖的东西。
        const why = String((e && e.message) || e);
        const http = why.match(/HTTP \d{3}/);
        m.reportWhy = `取不到 PR #${pr} 的评论：${http ? http[0] : '网络或凭据问题'}`;
      }
    }
    matches.push(m);
  }
  const truncated = matches.length > MAX_EVIDENCE_FILES;
  const kept = truncated ? matches.slice(0, MAX_EVIDENCE_FILES) : matches;
  if (truncated) notes.push(`命中 ${matches.length} 条，超过上限 ${MAX_EVIDENCE_FILES} —— 只固化前 ${MAX_EVIDENCE_FILES} 条（其余记在下面这句里）`);
  const files = kept.map((m) => {
    const obj = buildEvidence({ match: m, packages: m.packages || null, reportWhy: m.reportWhy || null });
    const bytes = canonicalBytes(obj);
    return { path: evidencePathFor(bytes), bytes, evidence: obj };
  });
  return {
    ok: files.length > 0,
    files,
    notes,
    matched: matches.length,
    scanned: rows.length,
    unreadable,
    truncated,
    whyEmpty: files.length ? null : whyNoEvidence(rows.length, unreadable, selectors),
  };
}

/**
 * 「没固化到东西」有三种形状，必须分成三句话说：树里从来没有过 pending（这个克隆不对）、
 * 有 N 条但没一条命中这套选择器（选择器不对，或那次投稿从没进过 main）、
 * 扫到了但blob 读不懂（历史被改写过 / 文件不是 JSON）。
 * 把它们并成一句「没有命中」就是在替诊断改口 —— 2026-10-17 那条假诊断正是这么来的。
 */
export function whyNoEvidence(scanned, unreadable, selectors) {
  const sel = JSON.stringify(selectors);
  if (scanned === 0) return '本地 main 的历史里一条「新增 pending/**」的提交都没有 —— 这个克隆没有投稿历史，不是选择器不对';
  if (unreadable > 0 && scanned === unreadable) {
    return `${scanned} 条 pending 提交全部读不出来（blob 不是合法 JSON？）；选择器：${sel}`;
  }
  const tail = unreadable > 0 ? `，另有 ${unreadable} 条 blob 读不出来被跳过` : '';
  return `${scanned} 条 pending 提交里没有一条命中这套选择器${tail}；选择器：${sel}`;
}

/**
 * 台账条目要带的两个字段（subject / evidence），从固化结果推出来。
 * `at` 挂在**台账那一侧**而不是证据文件里：它是「人什么时候跑的这条命令」，
 * 而证据文件必须只由不可变事实组成（否则同一个包固化两次会得到两个文件名）。
 *
 * 几份证据指向**不同的人**时不带 `subject`：一条台账记录只有一个 subject，
 * 硬取第一份等于把另几个人也挂到这个人头上 —— 那是台账里最贵的一种错。
 */
export function ledgerFieldsFrom(harvested, now = new Date()) {
  if (!harvested.ok) return null;
  const at = new Date(now).toISOString();
  const refs = harvested.files.map((f) => ({
    file: f.path,
    ...(f.evidence.pr ? { pr: f.evidence.pr.number } : {}),
    at,
  }));
  const uids = [...new Set(harvested.files.map((f) => f.evidence.subject.coolapkUid).filter(Boolean))];
  const out = { evidence: refs };
  if (uids.length === 1) {
    const first = harvested.files[0].evidence;
    out.subject = { coolapkUid: uids[0] };
    if (first.subject.username) out.subject.username = first.subject.username;
  }
  return out;
}

export function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    if (k === 'write' || k === 'json') { o[k] = true; continue; }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) { o[k] = true; continue; }
    o[k] = v;
    i++;
  }
  return o;
}

export async function main(argv = process.argv.slice(2), io = console, deps = {}) {
  const flags = parseArgs(argv);
  const selectors = {};
  if (flags.id) selectors.id = String(flags.id).trim();
  if (flags['version-code']) selectors.versionCode = Number(flags['version-code']);
  if (flags.sha256) selectors.sha256 = String(flags.sha256).trim().toLowerCase();
  if (flags.uid) selectors.coolapkUid = String(flags.uid).trim();
  if (!Object.keys(selectors).length) {
    io.error('用法: node scripts/harvest-evidence.mjs (--id <id> [--version-code <n>] | --sha256 <64hex> | --uid <UID>) [--write]');
    return 2;
  }
  if (selectors.versionCode !== undefined && !selectors.id) {
    io.error('--version-code 必须与 --id 同时给：脱离 id 的版本号会变成按数字全局固化');
    return 2;
  }
  const cwd = flags.cwd ? path.resolve(String(flags.cwd)) : ROOT;
  const harvested = await harvest({ cwd, selectors, deps });
  for (const n of harvested.notes) io.log(`[harvest] 注意：${n}`);
  if (!harvested.ok) {
    io.error(`[harvest] 没有可固化的东西：${harvested.whyEmpty}`);
    return 1;
  }
  for (const f of harvested.files) {
    const p = f.evidence.pending;
    io.log(`[harvest] ${f.path}`);
    io.log(`  ← ${p.path} @ ${f.evidence.pending.commitSha.slice(0, 9)}${f.evidence.pr ? ` · PR #${f.evidence.pr.number}` : ''}`);
    io.log(`  报告：${f.evidence.report
      ? `${f.evidence.report.packages.length} 包的呈现块，评论 ${f.evidence.report.commentUrl}${f.evidence.reportWhy ? ` —— ${f.evidence.reportWhy}` : ''}`
      : `没拿到 —— ${f.evidence.reportWhy}`}`);
    if (flags.write) {
      const abs = path.join(cwd, ...f.path.split('/'));
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, f.bytes);
      io.log(`  已写入 ${path.relative(cwd, abs)}`);
    }
  }
  if (!flags.write) io.log('[harvest] 只打印没落盘（要落盘加 --write；revoke.mjs 会自己带上）');
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exitCode = await main();
}
