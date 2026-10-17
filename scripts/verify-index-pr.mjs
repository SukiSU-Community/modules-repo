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
 * 判据只有一条式子，两种合法形态：
 *
 *   A 消费型：PR 里的索引 == buildIndex(base 索引, base 上被这次 PR 删掉的已批准条目, head 台账)
 *   B 台账型：PR 里的索引 == buildIndex(base 索引, [],                            head 台账)
 *
 * B 不是放宽 —— 它只是把「下架」表达成推导的第二个输入，而不是推导的例外。
 * 因此台账必须参与推导（它由 build-index 从 head 上读），而**不能**塞进 json/modules.json
 * 的某个顶层键：normalizeIndex 只比 name + modules，藏在索引里的东西等于免检。
 *
 * 但「这条 PR 该不该走机器路由」不由本脚本决定 —— 它只在被调用时回答「索引是不是推导出来的」。
 * 台账那条路今天有两道闸：
 *   ① 上游 audit.yml 的 kind 步按路径名单独认一次 json/dispositions.json 的改动（不带
 *      --diff-filter，所以整本被删也算），台账进过 diff 就不进机器路由；
 *   ② 本脚本的台账驱动分支要求人的署名：两名 author_association ∈ {OWNER,MEMBER} 的成员
 *      在这条 PR 的评论里各留一枚 #human-approved（判据复用 publish-from-main 的
 *      findHumanApprovals / REQUIRED_SIGNERS，不在这里另起一套），且每条**新增或改动**的处置，
 *      它的 by 要能回访成一条真评论、而作者就是那两个人之一。
 * 为什么必须有②：B 的判据是「重算结果与 PR 里的索引一致」，而一致是攻击者自己就能做出来的
 * —— 他手上和我们有同一份 build-index.mjs（公开仓库）。2026-10-17 本地复现打出的四格全是这个形状。
 * 另：normalizeIndex 只比 name + modules，所以索引里别的顶层键不过这道判定；要往索引里放新事实
 * 必须先扩 normalizeIndex，不能靠「推导看不见」混进去。
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
import { findPrForCommit, assertMergeApproved, approvalBy, findHumanApprovals, REQUIRED_SIGNERS } from './publish-from-main.mjs';
import { DEFAULT_DISPOSITIONS_FILE, parseDispositions } from './dispositions.mjs';
// `by` 的形状只在写入端校验过（revoke.mjs 的 PROOF_URL_RE）。CI 这一侧要复核同一条形状，
// 就复用那一个常量，不在这里再拼一份正则 —— 两份形状迟早漂，而漂了的那一份是没人看的判定。
import { PROOF_URL_RE } from './revoke.mjs';

/** 索引重建 PR 允许碰的文件。白名单外的任何改动都判「这不是重建，是夹带」。 */
export const ALLOWED_INDEX_PR_PATHS = ['json/modules.json', DEFAULT_DISPOSITIONS_FILE];

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
 * 两种合法的索引 PR：
 *   A 投稿消费型 —— 删掉了若干**有外部批准证据**的 pending，索引 = f(base 索引, 这些条目, 台账)
 *   B 台账驱动型 —— 没消费投稿，只改了处置台账（下架/拉黑），索引 = f(base 索引, [], 新台账)
 * 其余一律不认。判据仍是同一份 buildIndex，所以 B 不是放宽，只是换了第二个输入。
 *
 * @param {{
 *   baseIndex: object,
 *   baseEntries: Array<{path: string, entry: object}>,
 *   deletedPaths: string[],
 *   touchedPaths: string[],   // PR 里新增/修改的 pending 路径
 *   actualIndex: object,
 *   attest: (p: string) => {ok: boolean, reason: string},
 *   dispositions?: object[],  // head 上的台账（已校验）
 *   ledgerChanged?: boolean,
 *   changedPaths?: string[],  // 本 PR 改到的所有文件
 *   allowedPaths?: string[]
 * }} input
 */
export function judgeIndexPr(input) {
  const {
    baseIndex, baseEntries = [], deletedPaths = [], touchedPaths = [], actualIndex, attest,
    dispositions = [], ledgerChanged = false, changedPaths = null, allowedPaths = ALLOWED_INDEX_PR_PATHS,
    seal = null,
  } = input;
  const fail = (reason, extra = {}) => ({ ok: false, reason, ...extra });

  // 索引 PR 的定义就是「不带新投稿」。带了就交给投稿扫描那条路判，别在这里混着批。
  if (touchedPaths.length) {
    return fail(`这个 PR 同时新增/修改了 pending 条目（${touchedPaths.slice(0, 3).join('、')}`
      + `${touchedPaths.length > 3 ? ' 等' : ''}），不是纯索引重建，不按推导放行`);
  }

  // 文件集白名单。没有这一条，「改了 scan.mjs 让所有包都判低风险 + 附一份忠实推导的索引」
  // 也会被判成合法重建并被 merge-index 自动合掉 —— 推导只比索引内容，看不见代码被动过。
  // 这是接台账时顺手补的：json/dispositions.json 一进允许列表，就必须把「除此之外不许碰」
  // 同时写死，否则允许列表会变成又一条自由通道。
  if (changedPaths) {
    const outside = changedPaths.filter(
      (p) => !allowedPaths.includes(p) && !(p === 'pending' || p.startsWith('pending/')),
    );
    if (outside.length) {
      return fail(`这个 PR 除了索引还改了：${outside.slice(0, 5).join('、')}`
        + `${outside.length > 5 ? ' 等' : ''}。索引重建只许动 json/modules.json、json/dispositions.json 和 pending/**`
        + '（要改脚本请另开 PR 走人工审核）');
    }
  }

  if (!deletedPaths.length && !ledgerChanged) {
    return fail('这个 PR 改了 json/modules.json 但既没消费 pending、也没改处置台账'
      + ' —— 索引不是推导出来的，是手改的');
  }
  // 一个 PR 只做一个决定：混着来会让「这批投稿被批准了」和「这些内容被下架了」
  // 在同一个批准结论里，事后无从分别复核。
  if (deletedPaths.length && ledgerChanged) {
    return fail('这个 PR 同时消费投稿和修改处置台账，请拆成两条：一条只管收录，一条只管下架');
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

  const { index: expected } = buildIndex({ index: baseIndex, entries: approved, dispositions });
  const diffs = diffIndexes(expected, actualIndex);
  if (diffs.length) {
    return fail('PR 里的索引与推导结果不一致：\n  - ' + diffs.join('\n  - '), { diffs, evidences });
  }
  // 动了台账就必须要人的署名。位置在内容比对**之后**：先写索引的人更该先知道自己的索引算错了，
  // 而这一条不会因为顺序变松 —— 两道闸都在红的那一侧，攻击者做出来的「自洽索引」仍然过不了署名。
  // 为什么内容一致还不够：B 的判据是「重算结果与 PR 里的索引一致」，而一致是攻击者自己做得出来的
  // —— 他手上和我们有同一份 build-index.mjs（公开仓库）。2026-10-17 本地复现打出的四格全是这个形状。
  // 要的不是「算得对」，是「有人签过」：两名 OWNER/MEMBER 的 #human-approved，
  // 且每条新增/改动的处置的 by 要回访成其中一个真评论（判据复用 publish-from-main，不另起一套）。
  if (ledgerChanged) {
    if (!seal) {
      return fail('这个 PR 动了处置台账，但没拿到署名证据（调用方没给 --pr，取不到这条 PR 的人工签）'
        + ' —— 缺证据按不合格处理，不按「没有台账」处理');
    }
    if (!seal.ok) {
      return fail(`这个 PR 动了处置台账，而署名不合格：${seal.reason}`, { seal });
    }
  }

  if (ledgerChanged && !deletedPaths.length) {
    return {
      ok: true,
      reason: `索引与推导一致（台账驱动：按 ${dispositions.length} 条处置记录重算，未消费投稿；`
        + `署名为 ${(seal.signers || []).map((s) => `${s.login}(${s.assoc})`).join('、')}）`,
      evidences,
      consumed: [],
      seal,
    };
  }
  return { ok: true, reason: `索引与推导一致（消费 ${deletedPaths.length} 个已批准条目）`, evidences, consumed: deletedPaths };
}

/* ------------------------------------------------------------ 处置台账的署名 */

/**
 * 一条处置的「身份」= 它的选择器集合。
 * 为什么不用整条记录的 JSON 当身份：`by`/`at`/`reason`/`note` 变了也是动了台账
 * （换署名 = 换证人，换 reason = 换公示出来的罪名），必须一样要人签。
 */
function selectorOf(d) {
  return [d.kind, d.id ?? '', d.sha256 ?? '', d.coolapkUid ?? '',
    d.versionCode === undefined ? '' : String(d.versionCode)].join('|');
}

/**
 * base 与 head 两份台账之间被动过的条目，三个方向都算。
 *
 * 加一条（凭空下架 / 凭空拉黑）、改一条（换署名换理由）、**删一条**（把人从黑名单里放出来）——
 * #35 当初把台账挪出机器路由，为的就是最后那一格。删除那条没有 `by` 可查，
 * 所以它只计入「这条 PR 动了台账」这个事实，由「两名成员签」那一句拦住，不参与逐条对署名。
 */
export function ledgerTouched(baseList = [], headList = []) {
  const b = new Map(baseList.map((d) => [selectorOf(d), d]));
  const h = new Map(headList.map((d) => [selectorOf(d), d]));
  const added = [];
  const changed = [];
  const removed = [];
  for (const [k, d] of h) {
    if (!b.has(k)) { added.push(d); continue; }
    if (stableStringify(b.get(k)) !== stableStringify(d)) changed.push({ from: b.get(k), to: d });
  }
  for (const [k, d] of b) if (!h.has(k)) removed.push(d);
  return { added, changed, removed, any: added.length + changed.length + removed.length > 0 };
}

/** 把 `by` 那条证据链接拆成 owner/repo/issue/commentId；形状不对返回 null。 */
export function parseProofUrl(url) {
  const s = String(url || '').trim();
  if (!PROOF_URL_RE.test(s)) return null;
  const m = /^https:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/issues\/(\d+)#issuecomment-(\d+)$/.exec(s);
  if (!m) return null;
  return { owner: m[1], repo: m[2], issue: Number(m[3]), id: Number(m[4]), url: s };
}

const described = (d) => (d.id ? `id=${d.id}` : d.sha256 ? `sha256=${String(d.sha256).slice(0, 12)}` : `coolapkUid=${d.coolapkUid}`);

/**
 * 纯判定：这批台账改动够不够「两个人签过，且下处置的人就是签名的人」。
 * 证据（签名列表、每条 by 解析到的评论）都在外面取好了传进来 —— 这个函数不发请求，
 * 所以每一条失效方向都能被单测逐字打到。
 *
 * 信任的锚点只取一处：`signers` 来自 findHumanApprovals（它按 author_association ∈ {OWNER,MEMBER}
 * 与 login 去重，是 publish-from-main 人工路那份判据，不是这里新造的）。
 * 逐条 `by` 那次请求只回答两件事：那条评论**存在**，且它的**作者在这条 PR 上签过**。
 */
export function judgeLedgerSeal({ touched, signers = [], resolved = {}, require = REQUIRED_SIGNERS } = {}) {
  const who = signers.map((s) => `${s.login}(${s.assoc})`).join('、') || '一个都没有';
  if (!touched || !touched.any) {
    return { ok: true, reason: '台账内容没有实质改动（只动了 lastUpdate 一类的元数据）', signers, touched };
  }
  if (signers.length < require) {
    return {
      ok: false,
      reason: `动了 ${touched.added.length} 条新增 / ${touched.changed.length} 条改动 / ${touched.removed.length} 条删除，`
        + `而这条 PR 上只有 ${signers.length} 名成员的人工签（${who}），少于要求的 ${require} 名`
        + '（要签请在评论**首行**写 #human-approved，见 GOVERNANCE.md）',
      signers, touched,
    };
  }
  const signed = new Set(signers.map((s) => String(s.login).toLowerCase()));
  const bad = [];
  for (const d of [...touched.added, ...touched.changed.map((c) => c.to)]) {
    const p = parseProofUrl(d.by);
    if (!p) {
      bad.push(`${described(d)} 的 by 不是点得开的评论链接（${JSON.stringify(d.by)}）`);
      continue;
    }
    const r = resolved[p.url];
    if (!r) { bad.push(`${described(d)} 的 by 没有取证结果（${p.url}）`); continue; }
    if (!r.ok) { bad.push(`${described(d)} 的 by 回访不到那条评论：${r.reason}`); continue; }
    if (!r.login) { bad.push(`${described(d)} 的 by 那条评论没有作者，无从对署名`); continue; }
    if (!signed.has(String(r.login).toLowerCase())) {
      bad.push(`${described(d)} 的 by 署名是 ${r.login}，而这个人没有在这条 PR 上签 #human-approved`);
    }
  }
  if (bad.length) {
    return { ok: false, reason: `有 ${bad.length} 条处置的署名对不上：\n  - ` + bad.join('\n  - '), signers, touched };
  }
  const note = touched.removed.length ? `；其中 ${touched.removed.length} 条删除没有 by 可查，由上面那两名成员的签覆盖` : '';
  return {
    ok: true,
    reason: `${touched.added.length + touched.changed.length} 条新增/改动的 by 全部回访得到，作者都在 ${who} 之中${note}`,
    signers, touched,
  };
}

async function getJson(url, token, deps = {}) {
  const f = deps.fetch || globalThis.fetch;
  const res = await f(url, {
    headers: {
      'user-agent': 'modules-repo-verify-index-pr',
      accept: 'application/vnd.github+json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/**
 * 取这条 PR 的处置署名证据：评论列表 → findHumanApprovals → 逐条 by 回访那条评论。
 *
 * 用的是 `github.token`，与 pending 那条批准证据同一个身份；两个端点今天都被
 * findPrForCommit 在生产上跑过（`issues/{n}/comments`、`issues/comments/{id}` 单条实测回
 * `author_association`，取不到时是 404 而不是空数组 —— 所以这里的失败方向全是红，不是放行）。
 */
export async function ledgerSealEvidence({
  owner, repo, prNumber, baseLedger = [], headLedger = [],
  apiBase = 'https://api.github.com', token = '', require = REQUIRED_SIGNERS, deps = {},
} = {}) {
  const touched = ledgerTouched(baseLedger, headLedger);
  if (!touched.any) {
    return { ok: true, reason: '台账内容没有实质改动（只动了 lastUpdate 一类的元数据）', signers: [], touched };
  }
  const n = Number(prNumber);
  if (!Number.isInteger(n) || n <= 0) {
    return { ok: false, reason: `取不到这条 PR 的编号（--pr ${JSON.stringify(prNumber)}），没法查人工签`, touched };
  }
  const api = String(apiBase).replace(/\/$/, '');
  let comments;
  try {
    const data = await getJson(`${api}/repos/${owner}/${repo}/issues/${n}/comments?per_page=100`, token, deps);
    comments = Array.isArray(data) ? data : [];
  } catch (e) {
    return { ok: false, reason: `拿不到 PR #${n} 的评论：${String(e.message || e)}`, touched };
  }
  const sig = findHumanApprovals(comments, require);
  const resolved = {};
  for (const d of [...touched.added, ...touched.changed.map((c) => c.to)]) {
    const p = parseProofUrl(d.by);
    if (!p || resolved[p.url]) continue;   // 形状不对的交给 judgeLedgerSeal 报错，这里不重复判
    try {
      const c = await getJson(`${api}/repos/${p.owner}/${p.repo}/issues/comments/${p.id}`, token, deps);
      resolved[p.url] = { ok: true, login: (c && c.user && c.user.login) || '', assoc: String((c && c.author_association) || '').toUpperCase(), id: c && c.id };
    } catch (e) {
      resolved[p.url] = { ok: false, reason: String(e.message || e) };
    }
  }
  return judgeLedgerSeal({ touched, signers: sig.signers, resolved, require });
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

/**
 * 和 showJson 的区别只在一件事：**「文件不存在」和「文件在但读不懂」必须是两种结果**。
 * 台账走这条 —— 读不懂的台账若被当成「没有台账」，等于一次坏 JSON 把所有已下架的模块
 * 原样放回索引，而这件事不会有任何地方变红。
 */
function readJsonAt(cwd, ref, file) {
  let text;
  try {
    text = git(cwd, ['show', `${ref}:${file}`]);
  } catch (e) {
    const msg = String((e && e.stderr) || (e && e.message) || '');
    // 措辞有两家：does not exist in / exists on disk but not in <ref>。都算「这个 ref 上没有」。
    if (/does not exist in|exists on disk, but not in|does not exist on disk|pathspec/i.test(msg)) {
      return { present: false };
    }
    return { present: true, error: msg.trim().split('\n')[0] };
  }
  try {
    return { present: true, json: JSON.parse(text) };
  } catch (e) {
    return { present: true, error: `JSON 解析失败 - ${e.message}` };
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
  const { pr, checks = [], comments = [] } = await findPrForCommit({ apiBase, token, owner, repo, sha, mainBranch, log: { log() {}, error() {} } });
  const v = assertMergeApproved({ pr, checks, comments, mainBranch });
  if (!v.ok) return { ok: false, reason: `${v.reason}（引入提交 ${sha.slice(0, 12)}）`, commitSha: sha };
  return {
    ok: true,
    // 章的文字复用 approvalBy，不在这里再拼一遍：这个文件的存在理由就是「和盖审核章
    // 用的是同一个判据，不另起一套」。自己拼一份的结果是人工双签放行的条目在这里永远
    // 对不上 —— 那条 pending 会既进不了索引、又没人说为什么。
    by: approvalBy({ owner, repo, evidence: v.evidence }),
    at: new Date().toISOString(),
    commitSha: sha,
    pr: v.evidence.pr,
    headSha: v.evidence.headSha,
    kind: v.kind,
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
       [--pending-dir pending] [--index-file json/modules.json] [--dispositions-file json/dispositions.json]
       [--cwd <dir>] [--report <file>] [--pr <PR 编号>]
   判定当前工作树里的索引是否等于「base 内容 + 被本 PR 消费的已批准条目 + head 上的处置台账」的推导结果。
   动了处置台账时必须给 --pr：那一条分支要额外查两名成员的 #human-approved，而签是在 PR 的评论里。`);
    return opts.help ? 0 : 2;
  }
  const cwd = opts.cwd ? path.resolve(opts.cwd) : process.cwd();
  const pendingDir = opts['pending-dir'] || 'pending';
  const indexFile = opts['index-file'] || 'json/modules.json';
  const dispFile = opts['dispositions-file'] || DEFAULT_DISPOSITIONS_FILE;
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

  // ── 处置台账：第三个推导输入，只能从 ref 上读（工作树此刻是 PR head）──
  // head 上的台账参与推导；base 的那份只用来看「这个 PR 有没有动台账」。
  const baseLedger = readJsonAt(cwd, baseRef, dispFile);
  const headLedger = readJsonAt(cwd, headRef, dispFile);
  for (const [where, r] of [['base', baseLedger], ['head', headLedger]]) {
    if (r.error) {
      report.reason = `${where} 上的 ${dispFile} 读不懂：${r.error}（不当「没有台账」处理，停住）`;
      log.error('[verify-index-pr] ' + report.reason);
      writeReport();
      return 1;
    }
  }
  let dispositions = [];
  try {
    dispositions = headLedger.present ? parseDispositions(headLedger.json, `head:${dispFile}`) : [];
  } catch (e) {
    report.reason = `head 上的台账不合格：${e.message}`;
    log.error('[verify-index-pr] ' + report.reason);
    writeReport();
    return 1;
  }
  // base 那份也要**解析后的**条目，不只是用来比「动没动」：逐条对署名要问「哪些是这次新加的」。
  // base 读不懂时不能退回「base 是空的」—— 那会把整本台账都算成新增，等于把一次坏读取
  // 变成一次「所有处置都需要人签」或（更糟）「所有处置都是新写的」。停住才是对的。
  let baseDispositions = [];
  try {
    baseDispositions = baseLedger.present ? parseDispositions(baseLedger.json, `base:${dispFile}`) : [];
  } catch (e) {
    report.reason = `base 上的台账不合格：${e.message}`;
    log.error('[verify-index-pr] ' + report.reason);
    writeReport();
    return 1;
  }
  const ledgerChanged = stableStringify(baseLedger.json ?? null) !== stableStringify(headLedger.json ?? null);

  // 本 PR 到底动了哪些文件。拿不到就不判 —— 白名单检查缺席地「通过」比红更危险。
  let changedPaths = null;
  try {
    const mergeBase = git(cwd, ['merge-base', baseRef, headRef]).trim();
    changedPaths = git(cwd, ['diff', '--name-only', `${mergeBase}..${headRef}`])
      .split('\n').map((s) => s.trim()).filter(Boolean);
  } catch (e) {
    report.reason = `取不到本 PR 的改动文件集（merge-base ${baseRef}..${headRef} 失败：${String((e && e.stderr) || e.message).trim().split('\n')[0]}）`;
    log.error('[verify-index-pr] ' + report.reason);
    writeReport();
    return 1;
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

  // 动了台账 → 先取人的署名。取不到证据（没给 --pr、评论读不到、by 回访不到）一律按不合格处理，
  // 不按「这条 PR 没动台账」处理 —— 后者等于让一次网络抖动变成一次放行。
  let seal = null;
  if (ledgerChanged) {
    seal = deps.seal !== undefined
      ? deps.seal
      : await ledgerSealEvidence({
        owner: opts.owner, repo: opts.repo, prNumber: opts.pr,
        baseLedger: baseDispositions, headLedger: dispositions, apiBase, token, deps,
      });
  }

  const verdict = judgeIndexPr({
    baseIndex, baseEntries, deletedPaths, touchedPaths, actualIndex,
    attest: (p) => settled.get(p) || { ok: false, reason: '未取证' },
    dispositions, ledgerChanged, changedPaths, seal,
  });
  report.ok = verdict.ok;
  report.reason = verdict.reason;
  report.consumed = deletedPaths;
  report.ledger = { changed: ledgerChanged, entries: dispositions.length, file: dispFile };
  report.seal = seal ? {
    ok: seal.ok,
    reason: seal.reason,
    signers: (seal.signers || []).map((s) => ({ login: s.login, assoc: s.assoc, id: s.id })),
    touched: seal.touched
      ? { added: seal.touched.added.length, changed: seal.touched.changed.length, removed: seal.touched.removed.length }
      : null,
  } : null;
  report.changedPaths = changedPaths;
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
