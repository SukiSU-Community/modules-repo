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
 * 但「这次 PR 该不该走机器路由」不由本脚本决定 —— 它只在被调用时回答「索引是不是推导出来的」。
 * 台账那条路今天有两道闸：
 *   ① 上游 audit.yml 的 kind 步按路径名单独认一次 json/dispositions.json 的改动（不带
 *      --diff-filter，所以整本被删也算），台账进过 diff 就不进机器路由；
 *   ② 本脚本的台账驱动分支要求**机器章**：台账里每条新增或改动的处置，它的 `by` 要写成
 *      `ci:audit@<sha>`，那一枚 sha 必须是这条 PR 上的提交（`git rev-list base..head` 列得出它），
 *      且在那一枚提交上这条处置的实体已经以 `ci:audit@pending` 的形状等着盖章、实体与 head 上的
 *      逐字节相同，最后这一枚提交还要在本次运行给出的复核结论里判「成立」
 *      （逐字定位到归档包 + AI 复核；四条判据逐条写在 judgeLedgerSeal 上面）。
 *   换代说明：② 原先要的是两名有 write/admin 的人在这条 PR 评论首行各留一枚 #human-approved。
 *   owner 2026-10-21 拍「本站只有机器审核」，而那一支的正向支在生产上从来不可达（有写权限的人
 *   只有 1 个，要求 2 个）。旧的「谁算签核人」探针读数（不吃 author_association、逐个查
 *   permission）留在 git 历史里，换回人工时先读那一段。
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
import { findPrForCommit, assertMergeApproved, approvalBy } from './publish-from-main.mjs';
import { DEFAULT_DISPOSITIONS_FILE, EVIDENCE_FILE_RE, parseDispositions } from './dispositions.mjs';
// `by` 的形状只在写入端定义过一次（revoke.mjs 的 MACHINE_SEAL_RE）。CI 这一侧要复核同一条形状，
// 就复用那一个常量，不在这里再拼一份正则 —— 两份形状迟早漂，而漂了的那一份是没人看的判定。
import { MACHINE_SEAL_RE, SEAL_PENDING_BY, MACHINE_SEAL_PREFIX } from './revoke.mjs';

/** 索引重建 PR 允许碰的文件。白名单外的任何改动都判「这不是重建，是夹带」。 */
export const ALLOWED_INDEX_PR_PATHS = ['json/modules.json', DEFAULT_DISPOSITIONS_FILE];
/** §8 固化 job 写出来的那些证据文件住在哪个目录下（前缀，不是文件）。 */
export const EVIDENCE_DIR = 'evidence/';

/** 这个路径是不是证据文件？（只看目录，形状另判） */
export function isEvidencePath(p) {
  return typeof p === 'string' && p.startsWith(EVIDENCE_DIR);
}

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
 *   headEvidence?: string[] | null, // head 上 evidence/ 里的文件名全集（null = 调用方没列，跳过互指认）
 *   allowedPaths?: string[]
 * }} input
 */
export function judgeIndexPr(input) {
  const {
    baseIndex, baseEntries = [], deletedPaths = [], touchedPaths = [], actualIndex, attest,
    dispositions = [], ledgerChanged = false, changedPaths = null, allowedPaths = ALLOWED_INDEX_PR_PATHS,
    headEvidence = null, seal = null,
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
    const evidence = changedPaths.filter(isEvidencePath);
    const outside = changedPaths.filter(
      (p) => !allowedPaths.includes(p) && !(p === 'pending' || p.startsWith('pending/'))
        // `evidence/**` 只在「这条 PR 同时改了处置台账」时算合法文件。证据是台账条目的附件：
        // 一份不挂在任何处置上的证据文件不进双签，而公示页会把里面的人当真的念给投稿者。
        && !(isEvidencePath(p) && ledgerChanged),
    );
    if (outside.length) {
      return fail(`这个 PR 除了索引还改了：${outside.slice(0, 5).join('、')}`
        + `${outside.length > 5 ? ' 等' : ''}。索引重建只许动 json/modules.json、json/dispositions.json、`
        + 'evidence/**（仅当同一条 PR 改了台账）和 pending/**'
        + '（要改脚本请另开 PR 走人工审核）');
    }
    // 形状：证据文件名与台账里 `evidence[].file` 用的是同一个正则（dispositions.mjs 那份），
    // 不在这里另拼一份 —— 漂开的那一份没人看，而这两处一旦不一致就是「台账认得、白名单不认」。
    const badShape = evidence.filter((p) => !EVIDENCE_FILE_RE.test(p));
    if (badShape.length) {
      return fail(`evidence/ 下的文件名必须是 evidence/<64 位十六进制 sha256>.json，收到：`
        + `${badShape.slice(0, 5).join('、')}${badShape.length > 5 ? ' 等' : ''}`);
    }
  }

  // 证据与台账互相指认（只在调用方真的列到 head 的 evidence/ 时判；列不到就交给上面的白名单）。
  //   * 台账引用了 head 上不存在的文件 == 公示页给一条读不到的证据背书；
  //   * head 上有证据文件却没被任何条目引用 == 有人往公示数据里塞了一份不属于任何处置的材料。
  if (headEvidence !== null && headEvidence !== undefined) {
    const headSet = new Set(headEvidence);
    const referenced = new Set();
    for (const d of dispositions || []) {
      for (const e of (Array.isArray(d && d.evidence) ? d.evidence : [])) {
        if (e && typeof e.file === 'string') referenced.add(e.file);
      }
    }
    const missing = [...referenced].filter((f) => !headSet.has(f));
    if (missing.length) {
      return fail(`台账引用的证据文件在 head 上不存在：${missing.slice(0, 5).join('、')}`
        + `${missing.length > 5 ? ' 等' : ''} —— 引用了就得真在`);
    }
    const orphan = headEvidence.filter((f) => !referenced.has(f));
    if (orphan.length) {
      return fail(`evidence/ 里有文件没被台账任何一条引用：${orphan.slice(0, 5).join('、')}`
        + `${orphan.length > 5 ? ' 等' : ''} —— 证据要挂在处置上才有意义`);
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
  // 动了台账就必须要机器章。位置在内容比对**之后**：先写索引的人更该先知道自己的索引算错了，
  // 而这一条不会因为顺序变松 —— 两道闸都在红的那一侧，攻击者做出来的「自洽索引」仍然过不了章。
  // 要的不是「算得对」，是「有一次运行把这条处置的证据钉死了」（四条判据写在 judgeLedgerSeal 上面）。
  if (ledgerChanged) {
    if (!seal) {
      return fail('这个 PR 动了处置台账，但没拿到机器章的证据（调用方没给 --base/--reviews，'
        + '列不出这条 PR 的提交或取不到复核结论）—— 缺证据按不合格处理，不按「没有台账」处理');
    }
    if (!seal.ok) {
      return fail(`这个 PR 动了处置台账，而机器章不合格：${seal.reason}`, { seal });
    }
  }

  if (ledgerChanged && !deletedPaths.length) {
    return {
      ok: true,
      reason: `索引与推导一致（台账驱动：按 ${dispositions.length} 条处置记录重算，未消费投稿；`
        + `机器章 ${(seal.sealed || []).length} 枚，指向 ${(seal.sealed || []).map((s) => s.sha.slice(0, 12)).join('、') || '无'}）`,
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
 * 所以它只计入「这条 PR 动了台账」这个事实，由「两名有仓库写权限的人签」那一句拦住，不参与逐条对署名。
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

/**
 * 拆机器章。两种合法形状，含义相反：
 *   `ci:audit@<40hex>` ⇒ 已盖章，指向这条 PR 上的某一枚 commit；
 *   `ci:audit@pending` ⇒ 实体已写下、章还没盖（台账 PR 的第一枚提交就是这个形状）。
 * 其余任何文字（旧的评论 URL、`gh:<login>@…`、自由文本）返回 null —— 认不出来就是没盖章。
 */
export function parseSeal(by) {
  const s = String(by || '').trim();
  if (s === SEAL_PENDING_BY) return { pending: true, sha: '', text: s };
  if (!MACHINE_SEAL_RE.test(s)) return null;
  return { pending: false, sha: s.slice(MACHINE_SEAL_PREFIX.length).toLowerCase(), text: s };
}

const described = (d) => (d.id ? `id=${d.id}` : d.sha256 ? `sha256=${String(d.sha256).slice(0, 12)}` : `coolapkUid=${d.coolapkUid}`);

/**
 * 一条处置的**实体** = 除了「谁下的章、什么时候下的」以外的全部字节。
 *
 * 盖章那一枚提交只许改 `by`，所以比较的是这个投影而不是整条记录。时间也在投影之外，
 * 理由要说清：`at` 是写下实体的时间，重写一遍它就变 —— 而「章指向的那一枚提交上的实体
 * == head 上的实体」这条判据必须只跟内容有关，不然 C2 只是补一个章也会被判「动了实体」。
 */
export function dispositionSubstance(d = {}) {
  const out = {};
  for (const k of Object.keys(d).sort()) {
    if (k === 'by' || k === 'at') continue;
    out[k] = d[k];
  }
  return out;
}

/** 选择器相同的处置算同一条（与 revoke.mjs 的 sameSelectors 同一把尺）。 */
const sameSelectors = (a, b) => ['id', 'versionCode', 'sha256', 'coolapkUid']
  .every((k) => String(a[k] ?? '') === String(b[k] ?? ''));

/**
 * 纯判定：这批台账改动够不够「一次运行把每条处置的证据钉死了」。
 * 证据（这条 PR 有哪些 commit、每一枚 commit 上的台账、每一枚的复核结论）都在外面取好了
 * 传进来 —— 这个函数不发请求、不跑 git，所以每一条失效方向都能被单测逐字打到。
 *
 * 四条判据，缺一不可，各自挡的是不同的东西：
 *   ① `by` 是 `ci:audit@<40hex>` 而不是别的形状 —— 挡「自由文本冒充署名」。
 *   ② 那一枚 commit 必须是**这条 PR 上的**（base..head 可达）—— 挡「指一枚别处已经绿了的
 *      commit 借它的绿」。
 *   ③ 那一枚 commit 上，同样选择器的处置实体已经在那里等着盖章（`by` 是待盖值），
 *      且实体与 head 上的逐字节相同 —— 挡「章挂到一条当时还不存在的处置上」，
 *      也就是把 C2 的判定说成 C1 的判定。
 *   ④ 那一枚 commit 要有**复核结论**且结论是成立 —— 这才是章的实质内容：逐字定位到了
 *      归档包里、AI 复核判了成立。结论文件不存在 ⇒ 一条都不算成立（宁红不绿）。
 *
 * 删除（撤销处置）不在这里放行：台账里没有 restore 这一种，删一条 revoke 并不能让模块复活
 * （spec §9 已复核），所以「删除」必须由那条路自己实现，不能靠章覆盖。
 */
export function judgeLedgerSeal({ touched, prCommits = [], ledgerAt = {}, reviews = {}, readErrors = {} } = {}) {
  if (!touched || !touched.any) {
    return { ok: true, reason: '台账内容没有实质改动（只动了 lastUpdate 一类的元数据）', sealed: [] };
  }
  const onPr = new Set((Array.isArray(prCommits) ? prCommits : []).map((s) => String(s).toLowerCase()));
  const bad = [];
  const sealed = [];
  if (touched.removed.length) {
    bad.push(`有 ${touched.removed.length} 条处置被删掉：撤销处置要走 restore（spec §9 还没实现），`
      + '台账里没有这一种，删记录既不会让模块复活，也不该由章覆盖');
  }
  for (const d of [...touched.added, ...touched.changed.map((c) => c.to)]) {
    const who = described(d);
    const s = parseSeal(d.by);
    if (!s) { bad.push(`${who} 的 by 不是机器章（要 ${MACHINE_SEAL_PREFIX}<40 位十六进制>，收到 ${JSON.stringify(d.by)}）`); continue; }
    if (s.pending) { bad.push(`${who} 还挂着待盖值 ${SEAL_PENDING_BY}：这条处置的章没盖上`); continue; }
    if (!onPr.has(s.sha)) { bad.push(`${who} 的章指向 ${s.sha.slice(0, 12)}，那一枚 commit 不在这条 PR 上`); continue; }
    const at = ledgerAt[s.sha];
    if (!at) {
      bad.push(`${who} 的章指向 ${s.sha.slice(0, 12)}，那一枚提交上的台账读不出来`
        + (readErrors[s.sha] ? `（${readErrors[s.sha]}）` : '（没给出原因）'));
      continue;
    }
    const prior = at.find((x) => sameSelectors(x, d));
    if (!prior) { bad.push(`${who} 的章指向 ${s.sha.slice(0, 12)}，而那条提交上还没有这条处置的实体`); continue; }
    if (parseSeal(prior.by) === null || parseSeal(prior.by).pending !== true) {
      bad.push(`${who} 指向的那条提交上，同一条处置的 by 是 ${JSON.stringify(prior.by)} 而不是 ${SEAL_PENDING_BY}`);
      continue;
    }
    if (stableStringify(dispositionSubstance(prior)) !== stableStringify(dispositionSubstance(d))) {
      bad.push(`${who} 的实体与章指向的那条提交上的不一致：章只许盖在**当时就写好**的那一条上`);
      continue;
    }
    const rv = reviews[s.sha];
    if (!rv) { bad.push(`${who} 的章指向 ${s.sha.slice(0, 12)}，而这次运行没有给出复核结论（逐字复验 / AI 复核那一步没跑）`); continue; }
    if (rv.ok !== true) { bad.push(`${who} 的复核结论不成立：${rv.reason || rv.summary || '没写理由'}`); continue; }
    sealed.push({ sha: s.sha, summary: rv.summary || '' });
  }
  if (bad.length) {
    return { ok: false, reason: `台账的机器章有 ${bad.length} 处不合格：\n  - ` + bad.join('\n  - '), touched, sealed };
  }
  return {
    ok: true,
    reason: `${sealed.length} 条新增/改动的处置全部带着本 PR 上的机器章，章指向的那枚提交上实体已在、`
      + '且复核结论成立',
    touched, sealed,
  };
}

/**
 * 取机器章的证据：这条 PR 有哪些 commit + 每一枚章指向的提交上的台账长什么样。
 *
 * 全程只读 git，不发网络请求 —— 换代前人签那一版要打三个 API（评论列表、逐条回访评论、
 * 逐个查仓库权限），而其中「谁算签核人」那个来源本身按请求者会变（author_association 在
 * workflow token 下退化成 CONTRIBUTOR，canary #58/#59）。换成绑 commit 之后，判据要的
 * 两样东西仓库里都有，红绿不再取决于身份字段怎么算。
 *
 * `deps.prCommits` / `deps.ledgerAt` 是给单测换接口用的；不给就跑真 git。
 * 任何一步读不出来都写成「读不出来」交回 judgeLedgerSeal 判红，不静默当成空数组。
 */
export function ledgerSealEvidence({
  cwd, baseRef, headRef = 'HEAD', dispFile = DEFAULT_DISPOSITIONS_FILE,
  baseLedger = [], headLedger = [], reviews = {}, deps = {},
} = {}) {
  const touched = ledgerTouched(baseLedger, headLedger);
  if (!touched.any) {
    return { ok: true, reason: '台账内容没有实质改动（只动了 lastUpdate 一类的元数据）', sealed: [], prCommits: [], touched };
  }
  const listCommits = deps.prCommits || ((base, head) => git(cwd, ['rev-list', `${base}..${head}`])
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
  const readLedger = deps.ledgerAt || ((sha) => {
    const r = readJsonAt(cwd, sha, dispFile);
    if (!r.present) return [];                       // 那枚提交上还没有台账文件 == 实体不可能在，正常判红
    if (r.error) return null;                        // 读得出文件读不懂 ⇒ null ⇒ judgeLedgerSeal 报「读不出来」
    return parseDispositions(r.json, `${sha.slice(0, 12)} 上的台账`);
  });
  let prCommits;
  try {
    prCommits = listCommits(baseRef, headRef);
  } catch (e) {
    return { ok: false, reason: `列不出这条 PR 的提交（${String((e && e.stderr) || e.message || e).trim().split('\n')[0]}）`, touched };
  }
  const ledgerAt = {};
  const readErrors = {};
  for (const d of [...touched.added, ...touched.changed.map((c) => c.to)]) {
    const s = parseSeal(d.by);
    if (!s || s.pending || ledgerAt[s.sha] !== undefined) continue;
    try {
      ledgerAt[s.sha] = readLedger(s.sha);
    } catch (e) {
      // 读不出来与「那上面没有这条实体」是两种结论：前者的原因必须留在判定文字里，
      // 否则生产上只剩一句「读不出来」，没人知道是 git 抖了还是那本台账真坏了。
      ledgerAt[s.sha] = null;
      readErrors[s.sha] = String((e && e.message) || e).trim().split('\n')[0];
    }
  }
  return {
    ...judgeLedgerSeal({ touched, prCommits, ledgerAt, reviews, readErrors }),
    prCommits,
    ledgerAt,
    reviews,
    readErrors,
  };
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
  const { pr, checks = [] } = await findPrForCommit({ apiBase, token, owner, repo, sha, mainBranch, log: { log() {}, error() {} } });
  const v = assertMergeApproved({ pr, checks, mainBranch });
  if (!v.ok) return { ok: false, reason: `${v.reason}（引入提交 ${sha.slice(0, 12)}）`, commitSha: sha };
  return {
    ok: true,
    // 章的文字复用 approvalBy，不在这里再拼一遍：这个文件的存在理由就是「和盖审核章
    // 用的是同一个判据，不另起一套」。自己拼一份的结果是两边迟早漂，而漂了的那一份
    // 是没人看的判定 —— 那条 pending 会既进不了索引、又没人说为什么。
    by: approvalBy({ owner, repo, evidence: v.evidence }),
    at: new Date().toISOString(),
    commitSha: sha,
    pr: v.evidence.pr,
    headSha: v.evidence.headSha,
    kind: v.kind,
  };
}

/**
 * 复核结论文件的形状：`{ "<40 位十六进制 sha>": { ok: true|false, summary?, reason? } }`。
 *
 * 它是章的**实质内容** —— 一次运行对这一枚提交上的处置做过逐字定位与 AI 复核之后留下的读数。
 * 只认 sha 键（不是 sha 的键一律丢掉）：否则「顺手写一个 `latest` 指向最新结论」就会变成
 * 一枚谁都能引用的万能章。
 */
export function parseReviews(doc) {
  const out = {};
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return out;
  for (const [k, v] of Object.entries(doc)) {
    if (!/^[0-9a-f]{40}$/.test(k)) continue;
    if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
    out[k] = { ok: v.ok === true, summary: typeof v.summary === 'string' ? v.summary : '', reason: typeof v.reason === 'string' ? v.reason : '' };
  }
  return out;
}

/**
 * 读那份文件。读不到 / 读不懂 ⇒ 返回空对象，一条都不算成立。
 * 这一格必须是**默认拒绝**：上游那一步（逐字复验 / AI 复核）没跑成时台账 PR 应当红，
 * 而不是拿一个缺失的文件替它说「都通过了」。
 */
export function readReviews(file, log = console) {
  if (typeof file !== 'string' || !file) {
    log.error('[verify-index-pr] 没给 --reviews：动了台账就等于有处置要复核，而复核结论只能来自那一步运行');
    return {};
  }
  try {
    return parseReviews(JSON.parse(fs.readFileSync(path.resolve(file), 'utf8')));
  } catch (e) {
    log.error(`[verify-index-pr] 复核结论文件读不懂（${String((e && e.message) || e)}）—— 按一条都没复核处理`);
    return {};
  }
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
       [--cwd <dir>] [--report <file>] [--reviews <复核结论 JSON 文件>]
   判定当前工作树里的索引是否等于「base 内容 + 被本 PR 消费的已批准条目 + head 上的处置台账」的推导结果。
   动了处置台账时必须给 --reviews：那一条分支要逐条核机器章，而章的实质内容是**这一次运行给出的
   复核结论**（逐字定位到归档包 + AI 复核）。没有结论文件 = 一条都没复核 = 全红。`);
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

  // head 上 evidence/ 到底有哪些文件。列不出来（目录不存在时 git 也回成功且空）就按「没有」处理，
  // 但 git 本身失败必须红：那会让「引用了就得真在」这一判据静默不生效。
  let headEvidence = null;
  try {
    headEvidence = git(cwd, ['ls-tree', '-r', '--name-only', headRef, '--', 'evidence'])
      .split('\n').map((s) => s.trim()).filter(Boolean);
  } catch (e) {
    report.reason = `取不到 head 上的 evidence/ 清单（${String((e && e.stderr) || e.message).trim().split('\n')[0]}）`;
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

  // 动了台账 → 先取机器章的证据（这条 PR 有哪几枚提交 + 章指向的那枚提交上的台账长什么样）。
  // 取不到证据（列不出提交、那枚提交上的台账读不出、没有复核结论）一律按不合格处理，
  // 不按「这条 PR 没动台账」处理 —— 后者等于让一次读失败变成一次放行。
  let seal = null;
  if (ledgerChanged) {
    const reviews = deps.reviews !== undefined ? deps.reviews : readReviews(opts.reviews, log);
    seal = deps.seal !== undefined
      ? deps.seal
      : ledgerSealEvidence({
        cwd, baseRef, headRef, dispFile, reviews,
        baseLedger: baseDispositions, headLedger: dispositions, deps,
      });
    // 每一枚盖上了的章各打一行，章指向的那枚提交上的复核结论也各打一行：
    // 判定只看「全部对得上」，而生产上最需要看见的是哪一枚章、凭哪一次复核变绿的。
    for (const s of seal.sealed || []) {
      log.log(`[verify-index-pr] 机器章 ${s.sha} → 复核成立${s.summary ? `（${s.summary}）` : ''}`);
    }
    for (const [sha, r] of Object.entries(reviews)) {
      (r && r.ok ? log.log : log.error).call(log, `[verify-index-pr] 复核结论 ${sha} → ok=${r && r.ok ? 'yes' : 'no'}`
        + (r && (r.summary || r.reason) ? `：${r.summary || r.reason}` : ''));
    }
    if (!Object.keys(reviews).length) {
      log.error('[verify-index-pr] 这次运行一个复核结论都没有（没给 --reviews，或那份文件读不懂）'
        + ' —— 动了台账的 PR 因此必然红。这是设计内的默认拒绝：逐字复验与 AI 复核那一步没跑成，'
        + '就不许有人替它说「成立」。');
    }
  }

  const verdict = judgeIndexPr({
    baseIndex, baseEntries, deletedPaths, touchedPaths, actualIndex,
    attest: (p) => settled.get(p) || { ok: false, reason: '未取证' },
    dispositions, ledgerChanged, changedPaths, headEvidence, seal,
  });
  report.ok = verdict.ok;
  report.reason = verdict.reason;
  report.consumed = deletedPaths;
  report.ledger = { changed: ledgerChanged, entries: dispositions.length, file: dispFile };
  report.evidence = {
    changed: (changedPaths || []).filter(isEvidencePath),
    onHead: headEvidence,
    referenced: dispositions.reduce((n, d) => n + (Array.isArray(d && d.evidence) ? d.evidence.length : 0), 0),
  };
  report.seal = seal ? {
    ok: seal.ok,
    reason: seal.reason,
    // 章钉在哪一枚提交上、那一枚的复核结论是什么 —— 这两格是「凭什么绿」的全部信息，
    // 少了它们，report 就只剩一句「机器章成立」，跟没有证据一样不可复验。
    sealed: (seal.sealed || []).map((s) => ({ sha: s.sha, summary: s.summary || '' })),
    prCommits: seal.prCommits || null,
    readErrors: Object.keys(seal.readErrors || {}).length ? seal.readErrors : null,
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
