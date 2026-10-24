#!/usr/bin/env node
/**
 * verify-pending-proof.mjs —— pending 条目的 CI 侧凭据复核与来源核对（设计文档 §14.2）。
 *
 * 为什么必须有这一步。/submit 的归属闸（⑤-f）只挡得住从表单进来的提交；这个仓库还公开
 * 吃着 hand-written 的 pending/** PR —— audit.yml 的 locate 用路径白名单认 pending 的
 * 新增/修改，approve 只看扫描结论，今天没有任何一条检查看过 pending JSON 里的
 * pledge / ownership / identity。于是「把假条目喂进公示与追责链」这个目标，不碰酷安、
 * 不碰 /submit 也能达成。本脚本补的就是这一层。
 *
 * 两道检查，各自买到什么（这是本文件唯一不许含糊的地方，说过头比没有更糟）：
 *
 *  (a) 推导复算（checkPendingProof，离线、无密钥、无网络）：
 *      要求 `pledge.version` 在已发布集合内、`ownership.via` ∈ {'bio', 'bio-set', 'session'}，
 *      且口令前缀按 via 那一代各自复算：
 *        * `bio`（v1，单枚）  → `sha256(entry.id + ':' + <digest>)[0:8]`
 *        * `bio-set`（v2，集合）→ `sha256('sukisu-proof-v2:' + canon(这一套))[0:12]`，
 *          canon 见 canonicalProofSet（按 id 升序、同 id 再按 sha 升序，逐枚 `id:sha` 用 `,` 连接）
 *        * `session`（长效会话令牌）→ **没有可复算的前缀**：令牌在 Worker 的 KV 里，
 *          CI 这边既看不到也验不了，只能核形状（proofPrefix 与 nonce 是空串、
 *          verifiedAt 是正整数）。所以认它等于认「服务端说它验过了」而不是「我们复算过」，
 *          这一支的 (a) 层强度低于 bio/bio-set，账记在 OWNERSHIP_VIAS 上方那段注释里。
 *      —— 公式与 worker/src/proof.ts 的 proofPrefixFor / proofPrefixV2 和前端
 *      public/scripts/proof.js 是同一份实现口径（v1 三份各钉着黄金值：demo + e37287b0… → 4f91ceb8）。
 *      它挡的是「形状都不对」的伪造：懒得自洽的手写条目在这一层就红。
 *      它**挡不住**会自己算哈希的人 —— 谁都能用 node:crypto 拼一条自洽的。
 *      依赖要说破：<digest> 取自条目里**客户端自己上报**的 sha256（顶层或 versions[].sha256），
 *      它之所以等于 Worker ⑤-f 当时绑进口令的那份摘要，只因为 ⑤-c 拒绝了
 *      `claimedSha !== computedSha`（worker/src/index.ts:2136-2154）—— 那里一旦放宽，
 *      本步复算的就是一条 Worker 从来没有验过的字符串，(a) 的意义当场归零。
 *
 *  (b) 来源核对（checkActor，由调用方把 PR 开启者交给 --actor）：
 *      带新增/修改 pending 的 PR 必须由 Worker 那个 GitHub App 的身份开出。
 *      这一条才真正封死手写路径 —— (a) 挡不住的自洽伪造进不了 main，
 *      因为手写 PR 的 actor 对不上。白名单值住在 workflow 变量里而不是本脚本的常量里：
 *      名字要按线上载荷核实（见 task-13 回报），换 App / 换仓库不该改代码。
 *
 *  两者买不到的东西，按「谁能用」列清楚，别再说成只剩内部人：
 *   * **有 main 写权限的内部人**手写一条自洽 pending —— 挡它的是处置公示的
 *     `REQUIRED_SIGNERS = 2`（scripts/publish-from-main.mjs 的人工路），不在本闸的购买范围内。
 *   * **曾经存在的第二个门（任何账号都能走，不需要写权限；2026-10-17 已关）**：一个 PR 同时改
 *     `json/dispositions.json` 和一份对得上的 `json/modules.json`，曾被 audit.yml 判成
 *     `index_pr=true` 并自动批准、自动合并 —— 因为 verify-index-pr.mjs 的「台账驱动」分支
 *     （:172-179）只要重算结果与 PR 里的索引一致就放行，对台账 diff 既不看凭据也不看署名
 *     （`by` 是自由文本）。REQUIRED_SIGNERS 管的是 publish-from-main.mjs:84-102 那条**人工**路，
 *     而那条走的是 :140 的**机器**路。现在 kind 步（audit.yml `判定 PR 类型`）按路径名单独认一次
 *     台账改动，台账进过 diff 就不进机器路由，所以这条路今天既不经本闸、也不经机器路由。
 *     记在这里是为了让读到这段的人知道 §14.2 的「封死手写路径」说的是 pending 这条路，
 *     而台账那条路的闸门在 kind，不在本脚本。
 *
 * 作用范围（两处，缺一不可）：
 *   1. 检查的是**传给本脚本的目录**（audit.yml 接 pending-changed/pending，即 locate 用
 *      `git diff --no-renames --diff-filter=AM` 从 base..head 拷出的「本 PR 新增/修改」集合）。
 *      main 上的历史 pending（本轮之前投稿的、没有这三个字段的）天然不在范围内 —— 这不是容忍，
 *      是范围；test/verify-pending-proof.test.mjs 把接线钉住了，指回整棵 pending/ 会红。
 *   2. 但「locate 拷了什么就只查什么」等于把本闸的覆盖面交给一条 git 命令的分类方式，
 *      而那是攻击者能选的：`pending/demo/1.json` 改名成 `pending/evil/1.json` 顺手改个 `id`
 *      会被 git 判成 R068，`--diff-filter=AM` 一条都不打印（`--no-renames` 才打印新路径）；
 *      `1.JSON` 这种大写扩展名过不了 case-sensitive 的 pathspec，却照样被 build-index 的
 *      isPendingJson（toLowerCase 后比后缀）收进索引。两种形状在修复前的结局都一样：
 *      found=false → 本步根本不跑 → approve 按「无待审内容」退出 0 → 人看到绿勾就合 →
 *      publish-from-main.mjs:140-146 把那个 success 当成机器批准并盖章进公开索引。
 *      所以加了 --scope-base 之后，本脚本**自己**用 rename-agnostic 的
 *      `git ls-tree -r --name-only` 比 base/head 两棵 pending 树，独立算出「新增或改过」的
 *      路径集合（同一手法见 scripts/verify-index-pr.mjs:300-322），并要求每一条都能在传入
 *      的目录里找到；少一条就 ::error:: 退出 1 —— 本步拒绝「没被拷进来就不用查」这种安静。
 *      配套地，audit.yml 的 proof 步不再挂在 locate 的 found 上（每个 PR 都跑），
 *      而「目录里一个元数据都没有」也当成失败：它只在有事可检时被调用。
 *
 * 用法：
 *   node scripts/verify-pending-proof.mjs <pending 目录>
 *       [--require-actor <login[,login]>] [--actor <login>]
 *       [--scope-base <ref> [--scope-head <ref=HEAD>] [--scope-dir <仓库里的 pending 路径>]
 *        [--cwd <git 仓库目录>]]
 *
 * 退出码：0 = 全部过（或独立推导确认本 PR 没有任何新增/修改的 pending）；
 * 1 = 任一条目拒 / 来源不符 / 范围推不出或有路径没被拷进来 / 目录空 / 无从判定；2 = 参数错误。
 * 任一失败都打 `::error::` 前缀（给 GitHub Actions 注解用），非零退出。
 * 只用 node: 内置模块（本仓库硬性约束）；这里不联网、不要求任何密钥。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * 已发布的承诺文本版本 —— 与 worker/src/proof.ts 的 PLEDGE_VERSIONS 同一份口径。
 * 改文案就加一个新值，旧值继续有效。刻意不放 actor 白名单之类的部署相关常量：
 * 那些东西属于调用方（workflow 变量），烧进脚本就等于把闸焊死在一次的核实结果上。
 */
export const PLEDGE_VERSIONS = ['pledge-v1'];

const SHA256_RE = /^[0-9a-f]{64}$/;
const PREFIX_RE = /^[0-9a-f]{8}$/;
const PREFIX_V2_RE = /^[0-9a-f]{12}$/;

/**
 * 认得的 ownership.via 取值 —— 换代次序按设计文档 §15/§17.5「读的一侧先扩成旧值 ∪ 新值」：
 *   'bio'     = v1 单枚口令（今天线上唯一在跑的那一支，形状一个字不改）
 *   'bio-set' = v2 集合口令，一次批量投稿 N 枚共用一枚口令，前缀绑的是**整套**
 *   'session' = 服务端签发的长效会话令牌（90 天）。这一支**没有可复算的前缀**：
 *               令牌本身在 Worker 的 KV 里，CI 这边既看不到也验不了，只能核对形状
 *               （proofPrefix 与 nonce 都是空串、verifiedAt 是正整数）。所以它的
 *               (a) 层强度**低于** bio/bio-set 两支 —— 认它等于认「服务端说它验过了」，
 *               而不是「我们复算过」。这一点是刻意的：免改签名的代价就是把一次复算
 *               换成一次信任，写在这里是为了让后来的人看得见这笔账。
 * 未知值照旧一律拒 —— 扩的是白名单，不是「未知就当放行」。
 */
export const OWNERSHIP_VIAS = ['bio', 'bio-set', 'session'];
export const PROOF_PREFIX_LEN = 8;
export const PROOF_PREFIX_LEN_V2 = 12;
/** v2 的输入前缀，与 worker/src/proof.ts:132 逐字同一串；改它就是换代。 */
export const PROOF_V2_DOMAIN = 'sukisu-proof-v2:';

/**
 * 集合口令的规范串 —— 与 worker/src/proof.ts 的 canonicalProofSet 逐字同算法。
 *
 * 为什么这里要第三份实现：Worker 那份是写入端、前端 public/scripts/proof.js 是第二份，
 * 而 CI 这一份是**复算端**。复算端不复算，'bio-set' 就只剩一条「前缀是 12 个十六进制字符」的
 * 形状检查 —— 那等于把集合口令这一支的 (a) 层降到零，而 (a) 层存在的理由（本文件头部第 5-9 行）
 * 正是「手写自洽条目也得有人复算一遍」。
 * 三句边界与 Worker 那份同形（空集 / 非小写十六进制 / 同套重复 id）：都 throw，
 * 由调用方转成拒，不做「读不懂就跳过」。
 */
export function canonicalProofSet(items) {
  const list = [...(Array.isArray(items) ? items : [])];
  if (list.length === 0) throw new Error('口令集合不能为空');
  for (const it of list) {
    if (!it || typeof it.id !== 'string' || it.id === '') throw new Error('口令集合里有空模块 id');
    if (typeof it.zipSha !== 'string' || !SHA256_RE.test(it.zipSha)) {
      throw new Error(`这一枚的整包 sha256 不是 64 位小写十六进制：${it.id}`);
    }
  }
  if (new Set(list.map((i) => i.id)).size !== list.length) throw new Error('同一套里同一个模块 id 出现两次');
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  list.sort((a, b) => (a.id === b.id ? cmp(a.zipSha, b.zipSha) : cmp(a.id, b.id)));
  return list.map((i) => `${i.id}:${i.zipSha}`).join(',');
}

/** v2 集合前缀复算（同步版，理由同 proofPrefixFor：这里只有 node:crypto）。 */
export function proofPrefixForSet(items) {
  return createHash('sha256').update(`${PROOF_V2_DOMAIN}${canonicalProofSet(items)}`, 'utf8')
    .digest('hex').slice(0, PROOF_PREFIX_LEN_V2);
}

/**
 * 口令前缀复算：sha256(`${id}:${整包 sha256}`) 的前 8 位小写十六进制。
 * 同步版（WebCrypto 的两份实现都是异步的，这里只有 node:crypto，没有那个约束）。
 */
export function proofPrefixFor(id, zipSha) {
  return createHash('sha256').update(`${id}:${zipSha}`, 'utf8').digest('hex').slice(0, 8);
}

/**
 * 收集一条 pending 元数据里**所有**被声称的整包摘要（顶层 sha256 + versions[].sha256）。
 * 形状读不懂就返回 {ok:false, error}，不做「读不到就少算一枚」—— 少算一枚等于少覆盖一个包。
 * v1 用它逐枚复算（每一条都得对上那个前缀）；v2 用它判「这一枚能不能进声明集」。
 */
function collectShas(entry, id) {
  const candidates = [];
  if (typeof entry.sha256 === 'string') candidates.push({ where: '顶层 sha256', sha: entry.sha256.trim() });
  if (entry.versions !== undefined && !Array.isArray(entry.versions)) {
    return { ok: false, error: `${id}：versions 不是数组，读不懂即拒` };
  }
  for (const [i, v] of (Array.isArray(entry.versions) ? entry.versions : []).entries()) {
    const vc = v && v.versionCode !== undefined ? `versionCode=${v.versionCode}` : `#${i + 1}`;
    if (!v || typeof v !== 'object' || typeof v.sha256 !== 'string') {
      return { ok: false, error: `${id}：版本 ${vc} 没有 sha256 字段 —— 该包未被凭据覆盖，拒` };
    }
    candidates.push({ where: `versions[${i}] ${vc}`, sha: v.sha256.trim() });
  }
  return { ok: true, candidates };
}

/**
 * 单条 pending 元数据的推导复算。返回 {ok:true} 或 {ok:false, error}。
 *
 * 判据的次序是有意的：先形状（id/pledge/ownership/sha256 读不读得懂），后复算。
 * 「读不懂」一律是拒，不是跳 —— 一条 ownership 是字符串的条目比一条没有 ownership 的
 * 条目更可疑，跳过它等于把畸形当成豁免。
 *
 * @param {object} entry 待判的那一条 pending 元数据
 * @param {{batch?: object[]}} [ctx] 'bio-set' 那一支需要同批条目：`ctx.batch` 是**本次检查范围内
 *   读到的全部条目**（含 entry 自己）。没有它就只能判形状、判不了集合，而那一格按拒处理 ——
 *   「拿不到集合就当通过」正是本文件头部写明的「skip instead of reject」那个病。
 */
export function checkPendingProof(entry, ctx = {}) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return { ok: false, error: 'pending 条目不是一个对象，读不懂即拒（不做跳过处理）' };
  }
  const id = typeof entry.id === 'string' ? entry.id.trim() : '';
  if (!id) return { ok: false, error: 'pending 条目缺 id：没有 id 就无从复算口令' };

  // ── pledge ──
  const pledge = entry.pledge;
  if (!pledge || typeof pledge !== 'object' || Array.isArray(pledge)) {
    return { ok: false, error: `${id}：pledge 缺失或形状不对（应为 { version, … }），拒` };
  }
  if (typeof pledge.version !== 'string' || !PLEDGE_VERSIONS.includes(pledge.version.trim())) {
    return {
      ok: false,
      error: `${id}：pledge.version「${String(pledge.version).slice(0, 40)}」不在已发布承诺版本里（${PLEDGE_VERSIONS.join(', ')}），拒`,
    };
  }

  // ── ownership ──
  const own = entry.ownership;
  if (!own || typeof own !== 'object' || Array.isArray(own)) {
    return { ok: false, error: `${id}：ownership 缺失或形状不对（应为 { via, proofPrefix, … }），拒` };
  }
  if (!OWNERSHIP_VIAS.includes(own.via)) {
    return { ok: false, error: `${id}：ownership.via「${String(own.via).slice(0, 40)}」不在认得的取值里（${OWNERSHIP_VIAS.join(' | ')}，酷安签名核实），拒` };
  }
  if (typeof own.proofPrefix !== 'string') {
    return { ok: false, error: `${id}：ownership.proofPrefix 不是字符串（收到「${String(own.proofPrefix).slice(0, 40)}」），拒` };
  }

  // ── sha256 收集与复算 ──
  // 顶层 sha256（简化条目）与 versions[].sha256（Worker 的 buildPendingJson 形态）都要对得上。
  // 为什么每个版本都比而不是挑一个：条目里列出的每个包都会随条目进索引、进公示，
  // 而一条口令只覆盖它计算时那一个包 —— 没被覆盖的版本就是凭据没证明过的搭车货。
  const collected = collectShas(entry, id);
  if (!collected.ok) return { ok: false, error: collected.error };
  const candidates = collected.candidates;
  if (!candidates.length) {
    return { ok: false, error: `${id}：条目里找不到任何 sha256，无从复算口令，拒` };
  }
  for (const c of candidates) {
    if (!SHA256_RE.test(c.sha)) {
      return { ok: false, error: `${id}：${c.where}「${c.sha.slice(0, 72)}」不是 64 位小写十六进制的 sha256，拒` };
    }
  }

  // ── 'session'：服务端签发的长效会话令牌 ──
  // 这一支没有口令，所以**没有可复算的前缀**：能核对的只有形状。三条形状都有理由：
  //  · proofPrefix === ''：会话这条路压根没算过前缀，留个非空值只会让人以为它能复算；
  //  · nonce === ''：同理，令牌不是口令，写个 nonce 进来就是在冒充签名那条路；
  //  · verifiedAt 是正整数：它是「服务端哪一刻验的」，缺失或形状不对就无法追溯。
  // 判序刻意排在 'bio' 之前：'bio' 那条要求 8 位十六进制前缀，空串会被它用一句
  // 「不是 8 位小写十六进制」拒掉 —— 那句文案对会话这条路是错的（它不是格式写坏了，
  // 而是本来就没有）。先认出是哪一支，再按那一支的尺子量。
  if (own.via === 'session') {
    if (own.proofPrefix !== '') {
      return {
        ok: false,
        error: `${id}：ownership.via='session' 的 proofPrefix 必须是空串（收到「${String(own.proofPrefix).slice(0, 40)}」）`
          + ' —— 会话令牌那条路没有可复算的前缀，写一个前缀进来就是在冒充口令那条路，拒',
      };
    }
    if (own.nonce !== '') {
      return {
        ok: false,
        error: `${id}：ownership.via='session' 的 nonce 必须是空串（收到「${String(own.nonce).slice(0, 40)}」）`
          + ' —— 会话令牌不是口令，带 nonce 的会话条目读不懂，拒',
      };
    }
    if (typeof own.verifiedAt !== 'number' || !Number.isInteger(own.verifiedAt) || own.verifiedAt <= 0) {
      return {
        ok: false,
        error: `${id}：ownership.via='session' 的 verifiedAt 必须是正整数毫秒时间戳（收到「${String(own.verifiedAt).slice(0, 40)}」）`
          + ' —— 会话令牌那条路没有可复算的前缀，这一格是唯一的追溯锚点，缺了就拒',
      };
    }
    return { ok: true };
  }

  if (own.via === 'bio') {
    if (!PREFIX_RE.test(own.proofPrefix)) {
      return { ok: false, error: `${id}：ownership.via='bio' 的 proofPrefix 不是 8 位小写十六进制（收到「${own.proofPrefix.slice(0, 40)}」），拒` };
    }
    for (const c of candidates) {
      const expected = proofPrefixFor(id, c.sha);
      if (expected !== own.proofPrefix) {
        return {
          ok: false,
          error: `${id}：proofPrefix 与复算不符（${c.where}）—— 条目声称 ${own.proofPrefix}，`
            + `按 sha256(${id}:${c.sha})[0:8] 应为 ${expected}。同一个口令换个包就不认（§14.1）。`,
        };
      }
    }
    return { ok: true };
  }

  // ── 'bio-set'：v2 集合口令 ──
  // 前缀绑的是**整套**，所以复算的输入必须是整套的 (id, sha) 集合，不是这一条自己。
  // 「这一条的形状挺对」在集合口令这一支不构成任何证据。
  // 枚数不是判据（§15：一套一串、长度恒 19 与枚数无关）⇒ N=1 的一套同样合法；
  // 真正咬人的是「整套的字节集合」——少一枚、多一枚、换一枚都算出另一个前缀。
  if (!PREFIX_V2_RE.test(own.proofPrefix)) {
    return {
      ok: false,
      error: `${id}：ownership.via='bio-set' 的 proofPrefix 不是 12 位小写十六进制（收到「${own.proofPrefix.slice(0, 40)}」；`
        + `v1 那枚是 8 位，两代长度不同是刻意的 —— 见 §15「前缀从 8 位扩到 12 位」），拒`,
    };
  }
  const batch = Array.isArray(ctx.batch) ? ctx.batch : null;
  if (!batch) {
    return { ok: false, error: `${id}：集合口令（via='bio-set'）要拿同批条目才能复算，调用方没给 ctx.batch —— 判不了就是拒，不降级成形状检查` };
  }
  // 同一套的判据 = 认领同一个前缀的那一组 bio-set 条目。按前缀分组而不是「本目录全部条目」：
  // 一条 PR 里若混进两套（或 v1/v2 混投），各自独立复算，谁也不替谁作证。
  const group = batch.filter((e) => e && typeof e === 'object'
    && e.ownership && e.ownership.via === 'bio-set' && e.ownership.proofPrefix === own.proofPrefix);
  // 本条必须在声明集里：调用方给的这一批若被人削掉了本条（选择集被动过），
  // 就用它自己的 (id, sha) 补进去 —— 补进去之后要么复算通过、要么撞出「同 id 两枚」，两种都不是静默。
  const siblings = group.includes(entry) ? group : [...group, entry];
  const items = [];
  for (const e of siblings) {
    const eid = typeof e.id === 'string' ? e.id.trim() : '';
    if (!eid) return { ok: false, error: `${id}：集合里有认领同一前缀却没有 id 的条目，无法重建声明集，拒` };
    const sub = collectShas(e, eid);
    if (!sub.ok) return { ok: false, error: `${id}：集合成员「${eid}」读不懂（${sub.error}），整套拒` };
    if (sub.candidates.length !== 1) {
      return {
        ok: false,
        error: `${id}：集合成员「${eid}」带 ${sub.candidates.length} 个 sha256，而一枚口令只覆盖一枚包`
          + `（v2 的 canon 是「每枚一项」）—— 多于 1 枚就无法重建声明集，拒`,
      };
    }
    const sha = sub.candidates[0].sha;
    if (!SHA256_RE.test(sha)) return { ok: false, error: `${id}：集合成员「${eid}」的 sha256「${sha.slice(0, 72)}」形状不对，整套拒` };
    items.push({ id: eid, zipSha: sha });
  }
  let expected;
  try {
    expected = proofPrefixForSet(items);
  } catch (e) {
    return { ok: false, error: `${id}：声明集合不起来（${e.message}），拒` };
  }
  if (expected !== own.proofPrefix) {
    return {
      ok: false,
      error: `${id}：proofPrefix 与集合复算不符 —— 条目声称 ${own.proofPrefix}，按 sha256("${PROOF_V2_DOMAIN}${canonicalProofSet(items)}")[0:${PROOF_PREFIX_LEN_V2}]`
        + ` 应为 ${expected}（这套共 ${items.length} 枚）。少一枚、多一枚、换一枚都会算出另一个前缀（§15）。`,
    };
  }
  return { ok: true };
}


/**
 * 来源核对：本 PR 的开启者必须在允许列表里。列表由调用方给（workflow 变量），
 * 空白名单与空 actor 都是拒 —— 「配了检查却读不出被检对象」不是放行条件。
 */
export function checkActor(requireCsv, actor) {
  const allowed = String(requireCsv ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!allowed.length) {
    return { ok: false, error: '来源核对的允许列表（--require-actor）是空的 —— 宁可停住，不把「没配允许的 actor」当成放行' };
  }
  const a = String(actor ?? '').trim();
  if (!a) {
    return { ok: false, error: `拿不到本 PR 的开启者（--actor 为空），来源核对无法完成 —— 拒绝（允许列表：${allowed.join(', ')}）` };
  }
  if (!allowed.includes(a)) {
    return {
      ok: false,
      error: `本 PR 由「${a}」开出，不在允许的投稿来源里（${allowed.join(', ')}）—— `
        + 'pending 条目只能由 Worker 的 GitHub App 带进来；手写自洽伪造封在这一步（(a) 挡不住会算哈希的人）',
    };
  }
  return { ok: true };
}

/* ------------------------------------------------------- 范围（本步自己算） */

/**
 * 这条路径会不会被消费方（build-index.mjs 的 isPendingJson + collectPendingFiles）收走？
 * 判据必须**照着消费方**列，不能照着某条 git 命令的 pathspec 列：
 *   * 后缀比 toLowerCase() 之后的 —— 消费认 `.JSON`，只比原文就会把大写扩展名当成「不归我查」；
 *   * 文件名以 `.` 开头的（pending/.example.json）与 node_modules / .点开头的目录不算 ——
 *     消费方压根不读它们，要求它们被拷出来只会误红。
 */
export function isIngestedPendingPath(p) {
  const segs = String(p).split('/').filter(Boolean);
  const base = segs[segs.length - 1] || '';
  if (!base || base.startsWith('.')) return false;
  if (!base.toLowerCase().endsWith('.json')) return false;
  return !segs.slice(0, -1).some((s) => s === 'node_modules' || s.startsWith('.'));
}

function gitAt(cwd, args) {
  try {
    return { ok: true, out: execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }) };
  } catch (e) {
    const first = String(e.stderr || e.message || '').trim().split('\n')[0];
    return { ok: false, error: `git ${args.join(' ')}：${first}` };
  }
}

/** 某个 ref 下 pendingDir 里「消费方会收」的路径清单。读不出来 ≠ 空清单 —— 两者必须分得开。 */
function listPendingTree(run, ref, pendingDir) {
  const r = run(['ls-tree', '-r', '--name-only', ref, '--', pendingDir]);
  if (!r.ok) {
    return { ok: false, error: `读不到 ${ref} 上的 ${pendingDir}/（${r.error}）—— 范围推不出来时绝不当成「这个 ref 没有 pending」` };
  }
  return {
    ok: true,
    paths: r.out.split('\n').map((s) => s.trim()).filter((p) => p && isIngestedPendingPath(p)),
  };
}

/**
 * 独立复算「本 PR 新增/修改了哪些 pending 路径」，作为对 locate 那份选择集的交叉核对。
 *
 * 为什么不用 `git diff --diff-filter=AM`：那条命令先把 base..head 分类成 A/M/R/D，再按
 * filter 打印，而分类是攻击者能选的 —— 改名加一处编辑会被折叠成 R0xx，AM 一条都不打印。
 * `ls-tree -r --name-only` 只看两棵树各自有什么，rename 对它没有概念可言；再对两边都有的
 * 路径比一次正文，就得到「新出现或内容变过」的集合（同一手法见 scripts/verify-index-pr.mjs:300-322）。
 * 那里比的是 stableStringify(解析后的 JSON)，这里刻意改成**按字节比**：解析失败的条目
 * 正是本步要拒的东西，「读不懂」不允许被规范化成「两边一致」。
 *
 * @param {{cwd?: string, baseRef?: string, headRef?: string, pendingDir?: string}} opts
 * @param {{runGit?: (args: string[]) => {ok: boolean, out?: string, error?: string}}} [deps]
 * @returns {{ok: true, paths: string[], baseRef: string, headRef: string, pendingDir: string}
 *          | {ok: false, error: string}}
 */
export function derivePendingScope(opts = {}, deps = {}) {
  const cwd = opts.cwd ? path.resolve(String(opts.cwd)) : process.cwd();
  const run = deps.runGit || ((args) => gitAt(cwd, args));
  const rawDir = opts.pendingDir === undefined ? 'pending' : String(opts.pendingDir);
  const pendingDir = rawDir.split(path.sep).join('/').trim().replace(/\/+$/, '');
  const baseRef = String(opts.baseRef ?? '').trim();
  const headRef = String(opts.headRef ?? 'HEAD').trim() || 'HEAD';
  if (!baseRef) {
    return { ok: false, error: '要求独立推导范围却没拿到 base ref（--scope-base 是空的）—— 宁可停住，不把「推不出来」当成「没有投稿」' };
  }
  // 空的 scope-dir 会让 ls-tree 对整个仓库做范围推导：既慢又会把非投稿路径要求成「必须被拷进
  // pending-changed/pending」，那是误红；更要紧的是它说明调用方的 PREFIX 推导坏了。停住问。
  if (!pendingDir) {
    return { ok: false, error: '--scope-dir 不能是空的（空路径等于对整个仓库做范围推导）—— 检查调用方传给它的 pending 目录' };
  }

  const base = listPendingTree(run, baseRef, pendingDir);
  if (!base.ok) return base;
  const head = listPendingTree(run, headRef, pendingDir);
  if (!head.ok) return head;

  const baseSet = new Set(base.paths);
  const paths = [];
  for (const p of head.paths) if (!baseSet.has(p)) paths.push(p);
  // 只对「两边都有」的路径逐个取正文比（git show 两次/条）。成本由 base 上 pending/ 的规模兜住：
  // 索引 runner 会用 build-index --consume 把消费掉的条目删掉，main 上留不下多少历史文件。
  for (const p of head.paths) {
    if (!baseSet.has(p)) continue;
    const a = run(['show', `${baseRef}:${p}`]);
    const b = run(['show', `${headRef}:${p}`]);
    if (!a.ok || !b.ok) {
      return { ok: false, error: `${p} 在 ${baseRef}/${headRef} 上的正文读不出来（${!a.ok ? a.error : b.error}）—— 无法确认它没被改过，按拒处理` };
    }
    if (a.out !== b.out) paths.push(p);
  }
  return { ok: true, paths: paths.sort(), baseRef, headRef, pendingDir };
}

/**
 * 递归收集目录下的 *.json（一条元数据一个文件；数组形态照 build-index 拆成逐条）。
 *
 * 不 import build-index 的 collectPendingFiles —— 那份实现对 JSON 解析失败的文件是
 * console.error 之后**跳过**（索引重建尽力而为），而这里的语义正好相反：
 * 读不懂就是拒。安全复核里「跳过的文件」就是洞。
 */
function collectJsonFiles(dir) {
  const out = [];
  const walk = (cur, depth) => {
    if (depth > 8) return;
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
      // 扩展名判据照 build-index 的 isPendingJson —— toLowerCase() 之后比后缀。
      // 这里原来是大小写敏感的：pending/evil/1.JSON 被本脚本当成「不是元数据」跳过，
      // 而消费方（isPendingJson）照样把它收进索引 —— 检查范围比收录范围窄，就是洞。
      if (!name.toLowerCase().endsWith('.json') || name.startsWith('.')) continue;
      out.push(full);
    }
  };
  walk(dir, 0);
  return out;
}

/**
 * 逐个文件判定（rel 为相对 dir 的 / 分隔路径）。返回失败列表 [{file, error}]。
 *
 * 两遍走：先读齐这一批（选择集 = 本 PR 新增/修改的 pending，正是 Worker 一次批量投稿写出的那 N 份），
 * 再逐条判。为什么要先读齐：via='bio-set' 那一支的前缀绑的是**整套**，逐条独立判就只能判形状、
 * 判不了集合，而「集合这一支只做形状检查」等于这一支的 (a) 层不存在。
 * 读不懂的那个文件照样进失败列表（原文一字不改），只是它进不了集合 —— 少一枚 ⇒ 剩下的那几枚
 * 复算时对不上前缀 ⇒ 也拒。失效方向是整批红，不是「坏的那枚跳过」。
 */
export function checkPendingFiles(dir, files) {
  const failures = [];
  const read = [];
  for (const file of files) {
    const rel = path.relative(dir, file).split(path.sep).join('/');
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
      failures.push({ file: rel, error: `JSON 读不懂（${e.message}）—— 拒，不跳过` });
      continue;
    }
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    entries.forEach((raw, i) => read.push({ raw, label: entries.length > 1 ? `${rel}[${i}]` : rel }));
  }
  const batch = read.map((r) => r.raw);
  for (const { raw, label } of read) {
    const v = checkPendingProof(raw, { batch });
    if (!v.ok) failures.push({ file: label, error: v.error });
  }
  return failures;
}

/** 检查一个目录：返回失败列表 [{file, error}]。空目录 = 没有可判的东西，返回空列表。 */
export function checkPendingDir(dir) {
  return checkPendingFiles(dir, collectJsonFiles(dir));
}

export function parseArgs(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!String(a).startsWith('--')) { o._.push(a); continue; }
    const k = a.slice(2);
    const eq = k.indexOf('=');
    if (eq >= 0) { o[k.slice(0, eq)] = k.slice(eq + 1); continue; }
    const next = argv[i + 1];
    if (next !== undefined && !String(next).startsWith('--')) { o[k] = next; i++; } else o[k] = true;
  }
  return o;
}

export function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const log = deps.log || console;
  const fail = (msg) => { log.error('::error::' + msg); return 1; };

  if (opts.help) {
    log.log('用法: node verify-pending-proof.mjs <pending 目录> [--require-actor <login[,login]> --actor <login>]');
    log.log('      [--scope-base <ref> [--scope-head <ref=HEAD>] [--scope-dir <仓库里的 pending 路径>] [--cwd <git 仓库目录>]]');
    return 0;
  }
  if (opts._.length !== 1) {
    log.error('用法: node verify-pending-proof.mjs <pending 目录> [--require-actor <login[,login]> --actor <login>] [--scope-base <ref> [--scope-head <ref>] [--scope-dir <path>] [--cwd <dir>]]');
    return 2; // 参数错（缺目录=调用方写错了命令行，与「判不了」的 1 分开）
  }
  const dir = path.resolve(String(opts._[0]));

  // ── 0. 范围自己算一遍，不传 --scope-base 时退回旧行为（只信调用方拷来的东西）──
  const wantScope = opts['scope-base'] !== undefined;
  const scopeBaseRaw = (opts['scope-base'] === undefined || opts['scope-base'] === true) ? '' : String(opts['scope-base']);
  const scopeHead = typeof opts['scope-head'] === 'string' ? opts['scope-head'] : 'HEAD';
  const scopeDirOpt = typeof opts['scope-dir'] === 'string' ? opts['scope-dir'] : 'pending';
  let scopeRel = [];
  let scopeDesc = '';
  if (wantScope) {
    const r = derivePendingScope(
      { cwd: opts.cwd ? String(opts.cwd) : undefined, baseRef: scopeBaseRaw, headRef: scopeHead, pendingDir: scopeDirOpt },
      deps.runGit ? { runGit: deps.runGit } : {},
    );
    if (!r.ok) return fail(`本步自己算的范围不可用：${r.error}`);
    scopeDesc = `${r.baseRef}..${r.headRef} 的 ${r.pendingDir}/（git ls-tree 两棵树比出来的，改名与大小写都影响不了它）`;
    const cut = `${r.pendingDir.replace(/\/+$/, '')}/`;
    scopeRel = r.paths.map((p) => (p.startsWith(cut) ? p.slice(cut.length) : p));
    // 独立推导说「这个 PR 没碰任何会被收录的 pending」→ 确实没有可检对象，退出 0。
    // 注意这不是把决定权交回去：只要它说「有」而下面的目录里没有，就是硬失败。
    if (!scopeRel.length) {
      log.log(`[verify-pending-proof] ${scopeDesc} 之间没有新增/修改的 pending 元数据 —— 本步无事可检（不是「跳过检查」，是这个 PR 确实没投稿内容）`);
      return 0;
    }
  }

  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    return fail(`pending 目录不存在或不是目录：${dir}${wantScope ? ` —— 可 ${scopeDesc} 里有 ${scopeRel.length} 条新增/修改的 pending` : ''} —— 无从判定即拒`);
  }

  const files = collectJsonFiles(dir);
  const failures = [];

  // ── 1. 空集合 = 拒。本步只在有事可检时被调用，「0 个文件」只能是上游的选择集坏了 ──
  if (!files.length) {
    failures.push({
      file: '(范围)',
      error: `${dir} 里一个 pending 元数据都没有 —— 这一步只在「有事可检」时被调用，空目录说明上游的文件选择集坏了，`
        + '不是「这条 PR 没投稿」（那种情况上面已经由独立推导判掉了）。安静通过等于把闸交给坏掉的那半条链',
    });
  }

  // ── 2. 覆盖断言：独立推导出的每一条都必须真的被拷进来并被扫到 ──
  const have = new Set(files.map((f) => path.relative(dir, f).split(path.sep).join('/')));
  for (const rel of scopeRel) {
    if (have.has(rel)) continue;
    failures.push({
      file: rel,
      error: `${scopeDesc} 判它是新增/修改的 pending，可它没有出现在 ${dir} 里 —— 本步不接受「没被拷进来就不用查」。`
        + '要么上游的 diff 过滤漏了这种形状（改名带编辑会被折叠成 R、大写扩展名过不了 pathspec），'
        + '要么有人正拿它绕闸：把这条当成本闸的边界，改 locate 的过滤之前先想清楚',
    });
  }

  // ── 3. 逐条复算 ──
  failures.push(...checkPendingFiles(dir, files));

  // flag 存在但没带值时 parseArgs 记的是布尔 true —— 一律折算成空串，让 checkActor
  // 按 fail closed 处理；把 true 字符串化会变成「允许列表里有 'true'」这种荒唐形状。
  const requireActor = opts['require-actor'] === undefined
    ? undefined
    : (typeof opts['require-actor'] === 'string' ? opts['require-actor'] : '');
  const actorVal = typeof opts.actor === 'string' ? opts.actor : '';
  const actorRes = requireActor === undefined ? { ok: true } : checkActor(requireActor, actorVal);
  if (!actorRes.ok) failures.push({ file: '(来源)', error: actorRes.error });

  if (!failures.length) {
    const n = files.length;
    log.log(`[verify-pending-proof] 通过：${n} 个 pending 文件逐条复算一致（范围自算：${scopeDesc || '未启用 --scope-base，只信调用方拷来的目录'}）${requireActor === undefined ? '' : '，来源核对一致'}`);
    return 0;
  }
  for (const f of failures) {
    fail(`${f.file}：${f.error}`);
  }
  log.error('[verify-pending-proof] 以上任一失败都挡住 approve —— (a) 复算挡不自洽的伪造，(b) 来源挡手写路径，范围自算挡「选择集被挑坏」。');
  log.error('[verify-pending-proof] 本闸**不**覆盖两条路：① 有 main 写权限的内部人（那是 publish-from-main.mjs 人工路的 REQUIRED_SIGNERS=2）；② 改 json/dispositions.json 的索引重建 PR —— ② 今天不进机器路由（audit.yml 的 kind 步按路径名拦台账，见本文件头部说明），要合并得由两名组织成员签 #human-approved 后人工点。');
  return 1;
}

// 入口判据与 verify-index-pr.mjs 同款：resolve 比对绝对路径，不拼 file:// URL ——
// Windows 上拼出来的串永远不等于 import.meta.url，CLI 会静默不执行。
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main();
}
