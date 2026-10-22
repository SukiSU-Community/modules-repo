// publish-from-main.mjs 的单测 —— 「合并后凭什么算批准」这一段必须有测试，
// 因为它是整个自动放行链上唯一新增的信任点。
// 运行：node --test test/publish-from-main.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  APPROVE_CHECK_NAME,
  checkConclusion,
  assertMergeApproved,
  approvalBy,
  approvalVerifyHint,
  stampEntry,
  stampPendingFile,
  findPrForCommit,
  parseArgs,
  main,
} from '../scripts/publish-from-main.mjs';
import { isApproved, APPROVED_STATUSES } from '../scripts/build-index.mjs';
// 机器章的形状从写入端 import，别在测试里手抄一遍：抄了就有第二份定义，
// 而这两份漂移的方向一定是「测试还在钉旧形状、生产早就换了」。
import { MACHINE_SEAL_PREFIX, SEAL_PENDING_BY } from '../scripts/revoke.mjs';
import { MAX_PACKAGES_PER_RUN } from '../scripts/verify-report-evidence.mjs';

const SHA = 'a'.repeat(40);
const prOk = (over = {}) => ({
  number: 7, merged: true, merged_at: '2026-10-10T00:00:00Z',
  base: { ref: 'main' }, head: { sha: SHA }, ...over,
});
const check = (name, conclusion, over = {}) => ({ name, conclusion, status: 'completed', ...over });

/* ------------------------------------------------------------------ 取结论 */

test('checkConclusion：同名多条取 completed_at 最新的那一条', () => {
  const runs = [
    check(APPROVE_CHECK_NAME, 'failure', { completed_at: '2026-10-01T00:00:00Z' }),
    check(APPROVE_CHECK_NAME, 'success', { completed_at: '2026-10-09T00:00:00Z' }),
    check(APPROVE_CHECK_NAME, 'neutral', { completed_at: '2026-10-02T00:00:00Z' }),
  ];
  assert.equal(checkConclusion(runs).conclusion, 'success');
});

test('checkConclusion：没跑完的（conclusion=null）不算通过', () => {
  const r = checkConclusion([
    check(APPROVE_CHECK_NAME, null, { status: 'in_progress', completed_at: '2026-10-10T00:00:00Z' }),
    check(APPROVE_CHECK_NAME, 'success', { completed_at: '2026-10-01T00:00:00Z' }),
  ]);
  assert.equal(r.status, 'in_progress');
  assert.equal(r.conclusion, null);
});

test('checkConclusion：根本没有那条 check 时报 found=false', () => {
  const r = checkConclusion([check('audit', 'success'), check('其它', 'success')]);
  assert.equal(r.found, false);
  assert.equal(checkConclusion([]).found, false);
  assert.equal(checkConclusion(undefined).found, false);
});

/* -------------------------------------------------------------- 批准判定 */

test('批准证据成立：已合并 + base 是 main + approve 为 success', () => {
  const v = assertMergeApproved({ pr: prOk(), checks: [check(APPROVE_CHECK_NAME, 'success')], mainBranch: 'main' });
  assert.equal(v.ok, true);
  assert.equal(v.evidence.pr, 7);
  assert.equal(v.evidence.headSha, SHA);
});

for (const [label, checks, why] of [
  ['缺少 approve check', [], /没有名为 approve 的 check/],
  ['approve 是 failure', [check(APPROVE_CHECK_NAME, 'failure')], /结论是 failure/],
  ['approve 是 neutral（被跳过）', [check(APPROVE_CHECK_NAME, 'neutral')], /不是 success/],
  ['approve 是 action_required', [check(APPROVE_CHECK_NAME, 'action_required')], /不是 success/],
  ['approve 还在跑', [check(APPROVE_CHECK_NAME, null, { status: 'in_progress' })], /不是 success/],
]) {
  test(`${label} 时不能盖章 —— ${why}`, () => {
    const v = assertMergeApproved({ pr: prOk(), checks, mainBranch: 'main' });
    assert.equal(v.ok, false);
    assert.match(v.reason, why);
  });
}

test('PR 本身不合法的一律拒：没 PR / 未合并 / base 不是 main / 没有 head sha', () => {
  const good = [check(APPROVE_CHECK_NAME, 'success')];
  for (const [pr, why] of [
    [null, /拿不到这次推送对应的 PR/],
    [prOk({ merged: false, merged_at: null }), /不是已合并状态/],
    [prOk({ base: { ref: 'dev' } }), /base 是 dev/],
    [prOk({ head: { sha: 'not-a-sha' } }), /没有可用的 head sha/],
  ]) {
    const v = assertMergeApproved({ pr, checks: good, mainBranch: 'main' });
    assert.equal(v.ok, false, JSON.stringify(pr));
    assert.match(v.reason, why);
  }
});

test('标签、review、PR 正文都不是批准证据：只带 auto-approved 标签也拒', () => {
  // 这条钉住设计取舍：labels 有 triage 权限就能加，review 是别人随手点的，
  // body 是投稿者自己写的文本。批准的唯一来源是 check 结论，这里一条都不算。
  const v = assertMergeApproved({
    pr: prOk({
      labels: [{ name: 'auto-approved' }],
      body: 'CI says auto-approved ✅',
      reviews: [{ state: 'APPROVED', user: { login: 'alice' } }],
      review_comments: [{ body: '#human-approved' }],
    }),
    checks: [],
    mainBranch: 'main',
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /没有名为 approve 的 check/);
});

/* ------------------------------------------------ 机器唯一路（人工双签已删）

   2026-10-21 owner 拍「本站只有机器审核」：head sha 上 `approve` 的结论是 success 就是批准，
   不是 success（或根本没上报）就是不批准，**没有第二条路**。以前这里有一整套人工路
   （两名 OWNER/MEMBER 在 PR 评论首行写 `#human-approved`，由有写权限的人红着合并），
   它要求的两签在正向从来没数到过（有 write 权限的人只有 1 个），留着只是让文档可以声称有共治。
   下面这批用例锁的是「删干净了」这件事 —— 而不是「少了一条路」：
   已删的机制最坏的复活方式不是有人把代码写回来，是**数据看起来像还能用**。
*/

/** 已删标记：这里只作为**数据**出现，代码里已经没有它的常量了。 */
const MARKER = '#human-approved';
const humanComment = (id, login, assoc = 'MEMBER', body = `${MARKER} 扫描器把调试打印判成可疑，人工看过没问题`) => ({
  id, user: { login }, author_association: assoc, body,
});
const redApprove = [check(APPROVE_CHECK_NAME, 'failure')];
const twoSigns = [humanComment(101, 'alice'), humanComment(102, 'bob', 'OWNER')];

test('机器判红就是终点：approve 结论 failure ⇒ 不批准，理由点名结论，证据里没有人的位置', () => {
  const v = assertMergeApproved({ pr: prOk(), checks: redApprove, mainBranch: 'main' });
  assert.equal(v.ok, false);
  assert.match(v.reason, /结论是 failure/, '理由要说清是哪一种坏：没上报 / 没跑完 / 结论不是 success 是三件事');
  assert.match(v.reason, /不是 success/);
  assert.match(v.evidence.machine, /结论是 failure/);
  assert.equal(v.kind, undefined, '不批准时不该有任何 kind');
  assert.equal('signers' in v.evidence, false, '证据里不许有「谁签的」这一格');
  assert.equal('merged_by' in v.evidence, false, '也不许是「谁合的」');
});

test('approve 根本没上报 ⇒ 理由说「没有名为 approve 的 check」，不与「结论不对」混成一句', () => {
  const v = assertMergeApproved({ pr: prOk(), checks: [check('audit', 'success')], mainBranch: 'main' });
  assert.equal(v.ok, false);
  assert.match(v.reason, /没有名为 approve 的 check/);
  assert.match(v.reason, /没上报/);
  assert.doesNotMatch(v.reason, /结论是/, '这条的理由里没有结论那半句：混了人就去找错的键');
  assert.match(v.evidence.machine, /保护规则看不见/);
});

test('已删的人工双签不许被数据复活：评论里写满 #human-approved、人是合并者，照样拒', () => {
  // 这一条是这批用例的核心。assertMergeApproved 现在只有一条路，`comments` 与
  // `requireSigners` 这两个参数已经不存在 —— 它们还**传得进去**（JS 不嫌多余的键），
  // 所以唯一的证明方式是传进去之后结论仍然是拒。残留的 marker 检查若有半条，这里就绿了。
  const v = assertMergeApproved({
    pr: prOk({ merged_by: { login: 'yufeng-liang' } }),
    checks: redApprove,
    mainBranch: 'main',
    comments: [...twoSigns, humanComment(103, 'carol', 'OWNER')],
    requireSigners: 2,
  });
  assert.equal(v.ok, false, '三条 OWNER/MEMBER 的签名评论也补不上那一格');
  assert.match(v.reason, /本站只有机器审核/);
  assert.doesNotMatch(v.reason, /双签|人工放行|人工签只有/, '理由不许还教人走那条已经不存在的路');
  assert.ok(!JSON.stringify(v.evidence).includes('alice'), '签名人的名字不该进证据');
});

test('机器路优先且是唯一路：approve 是 success 时不把人算进章里', () => {
  const v = assertMergeApproved({
    pr: prOk({ merged_by: { login: 'yufeng-liang' } }),
    checks: [check(APPROVE_CHECK_NAME, 'success')],
    comments: twoSigns,
  });
  assert.equal(v.ok, true);
  assert.equal(v.kind, 'ci', '绿的 approve 才是唯一的批准来源');
  assert.equal('signers' in v.evidence, false, '章上不把人算进去');
});

test('章只有一枚形状：approvalBy 恒为 ci:approve#<o>/<r>PR<n>@<12hex>，verify 恒指向 commits/<headSha>/pulls', () => {
  const evidence = { pr: 7, headSha: SHA, checkName: APPROVE_CHECK_NAME, conclusion: 'success' };
  const expected = `ci:approve#o/rPR7@${SHA.slice(0, 12)}`;
  assert.equal(approvalBy({ owner: 'o', repo: 'r', evidence }), expected);
  // kind 参数已删：喂它一个人路形状（kind:'human' + signers），输出必须是同一枚章。
  assert.equal(
    approvalBy({ owner: 'o', repo: 'r', kind: 'human', evidence: { ...evidence, kind: 'human', signers: [{ login: 'alice', commentId: 101 }] } }),
    expected, '第二枚章（评论 id 那种）的形状不许回来'
  );
  assert.ok(isApproved({ audit: { status: 'auto-approved', by: expected } }), 'build-index 认这枚章');
  assert.equal(approvalVerifyHint({ owner: 'o', repo: 'r', evidence }), `gh api repos/o/r/commits/${SHA}/pulls`);
  assert.doesNotMatch(approvalVerifyHint({ owner: 'o', repo: 'r', evidence }), /comments/, '复验路径不再指向评论');
});


/* -------------------------------------------------------------- 章的内容 */

test('章里的 by 是可复验的指针（含 owner/repo/PR 号与 head sha 前缀）', () => {
  const by = approvalBy({ owner: 'SukiSU-Community', repo: 'modules-repo', evidence: { pr: 7, headSha: SHA } });
  assert.match(by, /^ci:approve#SukiSU-Community\/modules-repoPR7@a{12}$/);
  assert.ok(isApproved({ audit: { status: 'auto-approved', by } }), 'by 必须非空，否则 build-index 不认');
});

test('stampEntry 走 build-index 的 markApproved 契约，且幂等', () => {
  const entry = { id: 'mod_x', versions: [{ versionCode: 1 }] };
  const a = stampEntry(entry, {
    owner: 'o', repo: 'r', evidence: { pr: 7, headSha: SHA }, risk: 'low',
    now: () => '2026-10-10T00:00:00Z',
  });
  assert.equal(a.stamped, true);
  assert.equal(isApproved(a.entry), true);
  assert.equal(a.entry.audit.at, '2026-10-10T00:00:00Z');
  assert.equal(a.entry.audit.risk, 'low');
  assert.match(a.entry.audit.verify, /api\.github|gh api/, '章里要留复验路径');

  const b = stampEntry(a.entry, { owner: 'o', repo: 'r', evidence: { pr: 8, headSha: 'b'.repeat(40) }, now: () => '2026-10-11T00:00:00Z' });
  assert.equal(b.stamped, false, '已批准的条目不能被后一次合并改章');
  assert.equal(b.entry.audit.at, '2026-10-10T00:00:00Z');
});

test('stampPendingFile：只改 --changed 里的文件，其它原样不动', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfm-'));
  const mine = path.join(dir, 'mod_a-1.json');
  const theirs = path.join(dir, 'mod_b-1.json');
  const write = (p, o) => fs.writeFileSync(p, JSON.stringify(o, null, 2) + '\n');
  write(mine, { id: 'mod_a', versions: [{ versionCode: 1 }] });
  write(theirs, { id: 'mod_b', versions: [{ versionCode: 1 }] });
  const before = fs.readFileSync(theirs, 'utf8');
  const quiet = { log() {}, error() {} };

  const r1 = stampPendingFile(theirs, {
    owner: 'o', repo: 'r', evidence: { pr: 7, headSha: SHA }, onlyPaths: [mine], log: quiet,
  });
  assert.equal(r1.changed, false);
  assert.equal(fs.readFileSync(theirs, 'utf8'), before, '不在本次推送范围内的文件不能被改');

  const r2 = stampPendingFile(mine, {
    owner: 'o', repo: 'r', evidence: { pr: 7, headSha: SHA }, onlyPaths: [mine], log: quiet,
  });
  assert.equal(r2.changed, true);
  assert.deepEqual(r2.ids, ['mod_a']);
  assert.equal(isApproved(JSON.parse(fs.readFileSync(mine, 'utf8'))), true);
});

test('已删除的 pending 条目不能把整次盖章判失败', () => {
  // 索引消费 pending 的那次提交里，文件是「删除」。这一步要是抛错，
  // 表现是「索引 PR 建不出来」，而真实原因只是上一次已经消费过 —— 难查且没必要。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfm-missing-'));
  const gone = path.join(dir, 'mod_a-1.json');
  const quiet = { log() {}, error() {} };
  const r = stampPendingFile(gone, { owner: 'o', repo: 'r', evidence: { pr: 1, headSha: SHA }, log: quiet });
  assert.equal(r.changed, false);
  assert.equal(r.missing, true);
});

/* ---------------------------------------------------------------- main() */

const fakeLog = () => { const out = []; return { out, log: (...a) => out.push(a.join(' ')), error: (...a) => out.push('! ' + a.join(' ')) }; };

function stubFetch(handler) {
  const orig = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    urls.push(u);
    const res = handler(u, init);
    if (res === null) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => res };
  };
  // 返回的仍然是「还原」这个函数（现有用例都写 finally { restore() }），
  // 但带上这次桩收到过哪些 URL —— 断言「某一次请求根本没有发生」只有靠这个才做得到。
  const restore = () => { globalThis.fetch = orig; };
  restore.urls = urls;
  return restore;
}

// 三个端点的 URL 长得互相包含（.../commits/<sha>/pulls 也含 "/pulls"），
// 所以匹配顺序必须是 check-runs -> /pulls/<n> -> /commits/<sha>/pulls。
// 上一版测试把泛匹配放前面，结果详情接口返回了列表体，merged 字段凭空消失。
//
// 返回形状按 GitHub 的真实响应来：`/commits/{sha}/pulls` 是**裸数组**。
// 之前这里返回 `{ pull_requests: [...] }`，和被测代码的同一个误解正好对上，
// 于是 31 条测试全绿、线上第一次真调用就判成「提交没有关联 PR」而拒绝盖章。
//
// 评论那一条分支留着是故意的：人工双签删掉之后生产代码不该再来敲这扇门，
// 而「该不该敲」这件事只能由收到请求的桩说了算（见下面那条 URLs 断言）。
function stubApi({ pullList, pr, checkRuns, comments }) {
  return stubFetch((url) => {
    if (url.includes('/check-runs')) return { check_runs: checkRuns || [] };
    if (/\/issues\/\d+\/comments/.test(url)) return comments || [];
    if (/\/pulls\/\d+$/.test(url)) return pr || null;
    if (/\/commits\/[0-9a-f]+\/pulls$/.test(url)) return pullList || [];
    if (/\/pulls$/.test(url)) return pullList || [];
    return null;
  });
}

function pendingFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfm-main-'));
  const pd = path.join(dir, 'pending');
  fs.mkdirSync(pd, { recursive: true });
  const f = path.join(pd, 'mod_a-1.json');
  fs.writeFileSync(f, JSON.stringify({ id: 'mod_a', versions: [{ versionCode: 1, sha256: 'f'.repeat(64) }] }, null, 2) + '\n');
  return { dir, pd, f };
}

const PULL_LIST = [{ number: 7, base: { ref: 'main' } }];
const PR_BODY = { number: 7, merged: true, merged_at: '2026-10-10T00:00:00Z', base: { ref: 'main' }, head: { sha: SHA } };
const APPROVED = [{ name: APPROVE_CHECK_NAME, conclusion: 'success', status: 'completed' }];

test('main：approve 为 success 时盖章并写回', async () => {
  const { pd, f } = pendingFixture();
  const restore = stubApi({ pullList: PULL_LIST, pr: PR_BODY, checkRuns: APPROVED });
  const log = fakeLog();
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r', '--changed', f], { log, token: 't' });
    assert.equal(rc, 0, log.out.join('\n'));
    assert.equal(isApproved(JSON.parse(fs.readFileSync(f, 'utf8'))), true);
  } finally { restore(); }
});

test('main：approve 不存在时返回 1，且不碰任何文件', async () => {
  const { pd, f } = pendingFixture();
  const before = fs.readFileSync(f, 'utf8');
  const restore = stubApi({
    pullList: PULL_LIST, pr: PR_BODY,
    checkRuns: [{ name: 'audit', conclusion: 'success', status: 'completed' }],
  });
  const log = fakeLog();
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r'], { log, token: 't' });
    assert.equal(rc, 1);
    assert.ok(log.error, '必须给出为什么不盖');
    assert.equal(fs.readFileSync(f, 'utf8'), before, '未获批准时一个字节都不能改');
  } finally { restore(); }
});

test('main：提交没有关联 PR（人工直接推 main）时拒盖章', async () => {
  const { pd } = pendingFixture();
  const restore = stubApi({ pullList: [] });
  const log = fakeLog();
  try {
    assert.equal(await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r'], { log, token: 't' }), 1);
    assert.match(log.out.join('\n'), /拿不到这次推送对应的 PR/);
  } finally { restore(); }
});

test('main：PR 详情取不到（merged 字段没来源）时不猜，直接拒', async () => {
  const { pd } = pendingFixture();
  const restore = stubApi({ pullList: PULL_LIST, pr: null, checkRuns: APPROVED });
  const log = fakeLog();
  try {
    assert.equal(await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r'], { log, token: 't' }), 1);
    assert.match(log.out.join('\n'), /不是已合并状态|没有可用的 head sha/);
  } finally { restore(); }
});

test('main：没有 token 就拒绝工作，而不是静默盖一个无主章', async () => {
  const { pd } = pendingFixture();
  const saved = process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_TOKEN;
  const log = fakeLog();
  try {
    assert.equal(await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r'], { log, token: '' }), 1);
    assert.match(log.out.join('\n'), /没有 GITHUB_TOKEN/);
  } finally { if (saved !== undefined) process.env.GITHUB_TOKEN = saved; }
});

test('main：pending 目录为空时无事可做，返回 0', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pfm-empty-'));
  const pd = path.join(dir, 'pending');
  fs.mkdirSync(pd);
  const log = fakeLog();
  assert.equal(await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r'], { log, token: 't' }), 0);
  assert.match(log.out.join('\n'), /pending 目录是空的/);
});

test('findPrForCommit：多个关联 PR 时选 base 对的那一个，判定不靠列表接口的字段', async () => {
  const restore = stubApi({
    pullList: [{ number: 1, base: { ref: 'dev' } }, { number: 2, base: { ref: 'main' } }],
    pr: { number: 2, merged: true, merged_at: 'x', base: { ref: 'main' }, head: { sha: SHA } },
    checkRuns: APPROVED,
  });
  const log = fakeLog();
  try {
    const r = await findPrForCommit({ apiBase: 'https://api.github.com', token: 't', owner: 'o', repo: 'r', sha: SHA, log });
    assert.equal(r.pr.number, 2);
    assert.equal(assertMergeApproved({ pr: r.pr, checks: r.checks }).ok, true);
    assert.match(log.out.join('\n'), /关联 2 个 PR/);
  } finally { restore(); }
});

test('findPrForCommit 不再取 PR 评论 —— 那次多余的 API 调用真的没了（人工签的证据源断开）', async () => {
  // 桩里**备着**两条签名评论：代码不来取，就该一次请求都不发。
  // 这条钉的是「取证据的那一步整个删掉了」，而不只是「取了但不用」—— 后者意味着
  // 每次盖章还多打一次 issues/<n>/comments，而那个接口的内容已经没有任何判据读它。
  const restore = stubApi({
    pullList: PULL_LIST, pr: { ...PR_BODY, merged_by: { login: 'yufeng-liang' } },
    checkRuns: redApprove,
    comments: twoSigns,
  });
  try {
    const r = await findPrForCommit({ apiBase: 'https://api.github.com', token: 't', owner: 'o', repo: 'r', sha: SHA, log: fakeLog() });
    assert.equal('comments' in r, false, '返回值里不许再带 comments 键');
    assert.deepEqual(Object.keys(r).sort(), ['checks', 'others', 'pr']);
    assert.deepEqual(restore.urls, [
      `https://api.github.com/repos/o/r/commits/${SHA}/pulls`,
      'https://api.github.com/repos/o/r/pulls/7',
      `https://api.github.com/repos/o/r/commits/${SHA}/check-runs`,
    ], '只该发这三次请求，顺序也是这三次');
    assert.ok(!restore.urls.some((u) => /comments/.test(u)), `一次评论请求都不该发：${restore.urls.join(' | ')}`);
    const v = assertMergeApproved({ pr: r.pr, checks: r.checks });
    assert.equal(v.ok, false, '拿到的形状里没有任何人签可以补这一格');
    assert.match(v.reason, /结论是 failure/);
  } finally { restore(); }
});

test('main：批准成立时报告里 kind 恒为 ci，章上写的是 check 结论而不是评论 id', async () => {
  const { dir, pd, f } = pendingFixture();
  const report = path.join(dir, 'report.json');
  const restore = stubApi({
    pullList: PULL_LIST, pr: { ...PR_BODY, merged_by: { login: 'yufeng-liang' } },
    checkRuns: APPROVED, comments: twoSigns,
  });
  const log = fakeLog();
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r', '--changed', f, '--report', report], { log, token: 't' });
    assert.equal(rc, 0, log.out.join('\n'));
    const stamped = JSON.parse(fs.readFileSync(f, 'utf8'));
    assert.equal(stamped.audit.by, `ci:approve#o/rPR7@${SHA.slice(0, 12)}`);
    assert.equal(stamped.audit.verify, `gh api repos/o/r/commits/${SHA}/pulls`);
    const r = JSON.parse(fs.readFileSync(report, 'utf8'));
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'ci', '批准只有一种来源，报告里就不该出现第二种 kind');
    assert.doesNotMatch(log.out.join('\n'), /人工双签|#human-approved/, '日志里不许再宣传那条已删的路');
  } finally { restore(); }
});

test('main：机器判红 + 两条签名评论 ⇒ 退出 1、一个字节不改，那句解释不再教人写标记', async () => {
  const { pd, f } = pendingFixture();
  const before = fs.readFileSync(f, 'utf8');
  const restore = stubApi({
    pullList: PULL_LIST, pr: { ...PR_BODY, merged_by: { login: 'yufeng-liang' } },
    checkRuns: redApprove,
    comments: [...twoSigns, humanComment(57, 'carol', 'OWNER')],
  });
  const log = fakeLog();
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r', '--changed', f], { log, token: 't' });
    assert.equal(rc, 1, '三个人签了也不补这一格：本站只有机器审核');
    assert.equal(fs.readFileSync(f, 'utf8'), before, '未获批准时一个字节都不许改');
    assert.equal(isApproved(JSON.parse(fs.readFileSync(f, 'utf8'))), false);
    const text = log.out.join('\n');
    assert.match(text, /本站只有机器审核/);
    assert.doesNotMatch(text, /#human-approved|双签/, '给投稿者看的文案里留着一条走不通的官方路径，比没有文案更糟');
  } finally { restore(); }
});

test('main：--report 落下的判定结果能被 push 触发的 workflow 拿去贴回 PR', async () => {
  const { dir, pd, f } = pendingFixture();
  const report = path.join(dir, 'report.json');
  const restore = stubApi({
    pullList: PULL_LIST, pr: PR_BODY,
    checkRuns: [{ name: APPROVE_CHECK_NAME, conclusion: 'failure', status: 'completed' }],
  });
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r', '--changed', f, '--report', report], { log: fakeLog(), token: 't' });
    assert.equal(rc, 1);
    const r = JSON.parse(fs.readFileSync(report, 'utf8'));
    assert.equal(r.ok, false);
    assert.equal(r.pr, 7, '失败也要给出该通知谁的 PR 号');
    assert.match(r.reason, /结论是 failure/);
    assert.deepEqual(r.ids, []);
  } finally { restore(); }
});

/* -------------------------------------------------- 跨文件契约（字符串连接处） */

const WF_MAIN = path.resolve(import.meta.dirname, '../.github/workflows/audit.yml');
const WF_INDEX = path.resolve(import.meta.dirname, '../.github/workflows/index.yml');
const WF_TEMPLATE = path.resolve(import.meta.dirname, '../../audit/workflows/audit.yml');
const WF_INDEX_TEMPLATE = path.resolve(import.meta.dirname, '../../audit/workflows/index.yml');

/**
 * 同一份 workflow 的两个落地位置：仓库里实际生效的那份，和 monorepo 里的母本。
 * 母本只存在于 monorepo 布局 —— 独立 clone 的 modules-repo 没有 ../audit/，这时必须
 * 少比一份而不是 ENOENT：否则「把测试接进 CI」的第一步会为一个假理由红掉。
 * 但母本一旦存在就必须一起比：它是下一次复制回去的源，让它带着旧逻辑等于是
 * 埋一颗「改过的东西被冲掉」的雷（audit.yml 首行的警告说的就是这件事）。
 */
const AUDIT_COPIES = [WF_MAIN, WF_TEMPLATE].filter((f) => fs.existsSync(f));
const INDEX_COPIES = [WF_INDEX, WF_INDEX_TEMPLATE].filter((f) => fs.existsSync(f));

test('approve 这个 check 名必须真的就是 workflow 里那个 job 的 name', () => {
  // 两处靠字符串相等连接：job 改名 = 悄悄拆掉闸门。这条测试就是那根钉子。
  for (const f of AUDIT_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    assert.match(yml, new RegExp(`^\\s{2}${APPROVE_CHECK_NAME}:\\s*$`, 'm'), `${f} 里必须有个 name 为 ${APPROVE_CHECK_NAME} 的 job`);
    assert.match(yml, new RegExp(`name: ${APPROVE_CHECK_NAME}\\b`), `${f} 里 job 的 name: 必须是 ${APPROVE_CHECK_NAME}`);
  }
});

test('index.yml 调的是这个脚本，提交带 [skip ci]，且不自己重写批准判据', () => {
  const yml = fs.readFileSync(WF_INDEX, 'utf8');
  assert.match(yml, /publish-from-main\.mjs/);
  assert.match(yml, /\[skip ci\]/);
  // 盖章节点必须交给脚本，不能在 YAML 里再写一份「看标签/看评论」的判定 ——
  // 两处判定迟早分叉，而分叉的方向一定是松的那一处赢。
  assert.doesNotMatch(yml, /labels?\.|auto-approved.*===|===.*auto-approved/);
});

// 自动合并的那次 push 不触发任何 workflow（GitHub 刻意切断 GITHUB_TOKEN 造成的链），
// 实测证据：投稿 PR #4 被 publish 作业 squash 合并后，只有 pages 构建在跑，
// Rebuild Index From Main 一次都没启动 —— 模块合进了 main 却永远进不了索引。
// 所以这条链必须显式挂在 workflow_run 上，而不是指望 push。
test('index.yml 必须由 workflow_run 接住「审核自动合并」这一段', () => {
  const yml = fs.readFileSync(WF_INDEX, 'utf8');
  assert.match(yml, /workflow_run:/, '缺了它，自动放行的投稿会停在 main 上没人重建索引');
  // 接的对象必须是审核那条 workflow，而且名字要跟 audit.yml 的 name: 完全一致 ——
  // workflow_run 按名字匹配，改了 audit.yml 的 name 却忘了这里，链就静默断了。
  const auditName = fs.readFileSync(WF_MAIN, 'utf8').match(/^name:\s*(.+)$/m);
  assert.ok(auditName, 'audit.yml 得有 name');
  const name = auditName[1].trim();
  assert.ok(
    new RegExp(`workflows:\\s*\\[?\\s*'?${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'?`).test(yml),
    `index.yml 的 workflow_run 必须接「${name}」`
  );
  // 红了的审核运行不该顺带开一个空转的索引 PR
  assert.match(yml, /workflow_run\.conclusion\s*==\s*'success'/);
});

// 脚本把「没传 --changed」当成「不限范围」（stampPendingFile 的 onlyPaths=null）。
// 这条语义本身没错，错的是让 workflow 在 changed 列表为空时省略这个参数：
// 挂上 workflow_run 之后 index.yml 每次审核成功都会跑，某条只改 workflow 的维护 PR
// 就会拿自己那次 approve 的结论，给 main 上所有未消费的 pending 盖章 —— 借章。
test('不传 --changed 就是全部 pending：所以 workflow 必须在空列表时跳过盖章', () => {
  const o = parseArgs(['--pending', 'p', '--sha', 's']);
  assert.deepEqual(o.changed, [], 'parseArgs 不给默认值，语义交给调用方');

  const yml = fs.readFileSync(WF_INDEX, 'utf8');
  const stampAt = yml.indexOf('name: 盖章');
  assert.ok(stampAt > 0, '得有盖章那一步');
  const head = yml.slice(stampAt, stampAt + 900);
  assert.match(head, /if:\s*steps\.layout\.outputs\.changed_count\s*!=\s*'0'/,
    'changed_count 为 0 时必须整步跳过，不能靠省略 --changed');
});

test('index.yml 不开 PR 也不推 main：改动交给 App，自己只等绿并合并', () => {
  const yml = fs.readFileSync(WF_INDEX, 'utf8');
  // 注释里必须能写「为什么不用 gh pr create / 不 git push」，所以「不许出现」那两条
  // 只比可执行行 —— 上一轮就有人为了过测试把解释删掉，那是反方向的损失。
  const code = yml.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
  // 两条都是实测撞上的：org 禁止 Actions 创建/批准 PR（gh pr create 直接失败），
  // 而 bot 写的提交不触发 pull_request 检查（索引 PR 会卡在"永远没有 approve"）。
  assert.doesNotMatch(code, /gh pr create/, 'Actions 开不出 PR，写了只会得到一个红');
  assert.doesNotMatch(code, /git push/, '出现任何 push 就等于宣布「机器人有后门」，而事实是它没有');
  assert.match(yml, /open-index-pr\.mjs/, '开 PR 必须交给 Worker 的 App 身份');
  assert.match(yml, /SUBMIT_WORKER_URL/, 'Worker 地址来自仓库变量，不写死在 YAML 里');
  assert.match(yml, /REBUILD_TOKEN:\s*\$\{\{ secrets\.REBUILD_TOKEN \}\}/, '密钥走 env，不进命令行');
  assert.match(yml, /gh pr checks[^\n]*--watch/, '合并前必须等 required check 出结果');
  // 合并本身不在这条 workflow 里：它的 run 不是那条 PR 的 pull_request 上下文，
  // org 那道开关会让 mergePullRequest 直接 403（实测 run 38069741398）。见 audit.yml 的 merge-index。
  assert.doesNotMatch(code, /gh pr merge/, 'index.yml 不该试图合并 —— 它在这个上下文里合不动');
  // 不再 push，就不该再揣着 contents:write
  assert.match(yml, /contents: read/);
  // 消费掉的 pending 是删除，不能交给盖章脚本去读
  assert.match(yml, /diff-tree[\s\S]{0,80}--diff-filter=ACMR/);
});

// 索引 PR 的合并只能发生在「那条 PR 自己的 pull_request run」里 —— 这是本轮真跑撞出来的：
// index.yml 用同一个 GITHUB_TOKEN 合索引 PR 会得到
// `GraphQL: Resource not accessible by integration (mergePullRequest)`，
// 而 audit.yml 的 publish 作业在 pull_request 上下文里合自己的 PR（投稿 PR #15）是成功的。
test('索引 PR 的合并挂在 audit 的 pull_request 上下文里，且两个判据都缺一不可', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8')
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    assert.match(code, /^ {2}merge-index:$/m, `${path.basename(f)} 里得有 merge-index 作业`);
    const at = code.indexOf('  merge-index:');
    const next = code.slice(at + 2).search(/^ {2}[A-Za-z_-]+:$/m);
    const job = next < 0 ? code.slice(at) : code.slice(at, at + 2 + next);
    // 少 index_pr 这一半 = 任何改脚本/文档的维护 PR 都会被机器人合进 main；
    // 少 index_derived 这一半 = 手抄一份 json/modules.json 就能进 main。
    // 2026-10-17 加了第二条路由（台账改动 + 两名成员签），三条纪律都要保住：
    //   ① index_derived 仍是**整体合取项**，不许被折进那条 `||` 里 —— 折进去就等于
    //      「签齐了就不必对得上推导」，而签名买的是「有人看过这条处置」，买不到「索引算得对」；
    //   ② ledger 那一支必须自己带上 ledger_sealed，不能靠 index_pr 替它担保；
    //   ③ 两个 output 由 kind 互斥导出，所以这里不需要防「两个都真」，但要防「两个都不真时也能合」。
    assert.match(job, /if: needs\.audit\.outputs\.index_derived == 'true' && \(needs\.audit\.outputs\.index_pr == 'true' \|\| \(needs\.audit\.outputs\.ledger_pr == 'true' && needs\.audit\.outputs\.ledger_sealed == 'true'\)\)/,
      'index_derived 是整体合取项；两条路由各带自己的批准证据（ledger 那一条要带 ledger_sealed）');
    assert.doesNotMatch(job, /index_derived == 'true' \|\|/, 'index_derived 不许出现在 || 的任何一侧');
    assert.doesNotMatch(job, /if: needs\.audit\.outputs\.index_pr == 'true' && needs\.audit\.outputs\.index_derived == 'true'\s*$/,
      '旧的那条（只认 index_pr）不许回来：它把合法下架一并挡在了机器路由外面');
    assert.match(job, /needs: \[audit, approve\]/, 'approve 红了就不能合并（job 默认要求 needs 成功）');
    assert.match(job, /gh pr merge .*--squash/, '合并方式必须是 squash：main 上每个索引状态对应一个过检 PR');
  }
});

// approve 绑 head sha：head 不动，derive 那次判定的绿就一直挂着。而 derive 比的是 PR 创建时的
// base —— main 要是在这期间又进了新投稿，这条 PR 已经不是「当前 main 的函数」，合下去会反过来
// 把更新的索引退回去。#18 就是这次真跑留下的过期样本。
//
// 不用 ruleset 的 strict_required_status_checks_policy 来封：那是对所有 PR 生效的，会同时要求
// 投稿 PR 分支最新，而投稿方是不会 rebase 的机器人 —— 两条投稿挨着进来就把前一条永久卡死。
test('merge-index 必须按「此刻的 main」重推导一遍，且排在合并之前', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8')
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    const at = code.indexOf('  merge-index:');
    const next = code.slice(at + 2).search(/^ {2}[A-Za-z_-]+:$/m);
    const job = next < 0 ? code.slice(at) : code.slice(at, at + 2 + next);

    assert.match(job, /verify-index-pr\.mjs/, '重推导用的必须是同一个判定器，不是在 YAML 里再写一遍判据');
    assert.match(job, /git rev-parse "refs\/remotes\/origin\/\$\{BASE_REF}"/,
      'base 要现取此刻的 base 分支，不能用 GitHub 报的 base.sha');
    assert.match(job, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/,
      '得检 PR head 本身：默认的 merge ref 里 HEAD^ 不是分叉点');
    assert.ok(job.indexOf('verify-index-pr.mjs') < job.indexOf('gh pr merge'),
      '重推导必须排在合并之前 —— 反着写就等于先合再查');
  }
});

// 「索引 PR」的认定只看 json/modules.json，不看整个 json/。
// 为什么这算一条安全判据而不是分类细节：台账单独改动**既不消费 pending 也不改变当前索引**，
// 于是推导必然「一致」—— 如果它被认成索引 PR，删掉一条处置（把某人从黑名单放出来）
// 就会被 merge-index 自动合掉。削弱处置必须是人工判断。
//
// 2026-10-17 追加：光「不看 json/」这一句拦不住台账。本地复现打出四格，全是「改台账 + 一份索引」，
// 其中两格的索引只是缩进与键序变了 —— derive 按 normalizeIndex 判（丢 lastUpdate、模块与版本重排），
// 那种改动在它眼里等于没改，而这一步按字节判，于是把它认成索引重建 ⇒ 自动合。
// ⇒ 台账要单独拦一次，且**不能带 --diff-filter**（删掉整本台账是一次 D，那是一整本处置的消失）。
test('kind 只把「索引真的变了且没动台账」的 PR 认成索引 PR', () => {
  for (const f of AUDIT_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    const tag = `${path.basename(f)}：`;
    assert.ok(yml.includes(`--diff-filter=ACMR "$BASE_SHA" HEAD -- 'json/modules.json'`), `${tag}索引那条 diff 必须钉到 json/modules.json`);
    assert.ok(!yml.includes(`--diff-filter=ACMR "$BASE_SHA" HEAD -- 'json/'`), `${tag}'json/' 会把只改台账的 PR 也认成索引 PR，从而可被自动合并`);
    // 台账那条：只按路径名比。带上 --diff-filter 就漏掉「删掉整本 json/dispositions.json」那一格。
    assert.ok(yml.includes(`CHANGED_LEDGER=$(git diff --name-only "$BASE_SHA" HEAD -- 'json/dispositions.json' || true)`),
      `${tag}台账改动必须由一条不带 --diff-filter 的路径级 diff 认出来`);
    assert.ok(!yml.includes('CHANGED_LEDGER=$(git diff --name-only --diff-filter='),
      `${tag}CHANGED_LEDGER 不许带 --diff-filter：整本台账被删（D）同样是一次处置的消失`);
    assert.ok(yml.includes('[ -n "$CHANGED_JSON" ] && [ -z "$CHANGED_LEDGER" ] && [ "${FOUND:-}" != "true" ]'),
      `${tag}三个条件同时钉住，台账那一条是 -z（空才许走机器路由）`);
    // 两句 warning 说的是两个方向，不许合并成一句：混投稿要人去查投稿，动台账要的是机器章。
    assert.ok(yml.includes('这个 PR 动了处置台账'), `${tag}台账那一支要指名「处置是人工判断」`);
    assert.ok(yml.includes('elif [ -n "$CHANGED_JSON" ]; then'), `${tag}混投稿那一支要退成 elif，不许被台账那支吃掉`);
  }
});

/* ---------------------------------------------------------------- 台账那条路的接线

   两道闸分开发（#52 收紧 kind、#54 给 verify-index-pr 加署名、这一发把两者接上）。
   接线最容易出的错不是判据写错，是**顺序**：approve 里那句「没有投稿内容 ⇒ 无批准事项」
   会给一枚绿勾，而绿勾是会被点的 —— #53 那条 canary 在线上的读数就是这个形状。
*/
test('接线：kind 导出 ledger_pr，derive 两条路由都跑并核机器章，approve 的台账支排在「无批准事项」之前', () => {
  for (const f of AUDIT_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    const tag = `${path.basename(f)}：`;
    assert.ok(yml.includes('echo "ledger_pr=$([ -n "$CHANGED_LEDGER" ] && echo true || echo false)" >> "$GITHUB_OUTPUT"'),
      `${tag}kind 要把「动没动台账」单独导出，不能让 approve 自己去猜`);
    assert.ok(yml.includes('ledger_pr: ${{ steps.kind.outputs.ledger_pr }}'), `${tag}job output 少了 ledger_pr，approve 读到的永远是空`);
    assert.ok(yml.includes('ledger_sealed: ${{ steps.derive.outputs.sealed }}'), `${tag}job output 少了 ledger_sealed，同上`);
    assert.ok(yml.includes("if: steps.kind.outputs.index_pr == 'true' || steps.kind.outputs.ledger_pr == 'true'"),
      `${tag}derive 必须在两条路由上都跑 —— 机器章就核在那一次调用里`);
    // 两处调用（derive 与 merge-index 的重推导）都要带 --reviews：那份复核结论文件就是章的**实质内容**。
    // 少了第二处，台账类 PR 在合并那一步退成「内容对得上就合」，而那一步绑的是 head sha ——
    // base 变了要重算正是它存在的理由，不能当成已经查过。
    assert.equal(yml.split('--reviews "$REVIEWS_FILE"').length - 1, 2, `${tag}两处 verify-index-pr 调用都要带 --reviews`);
    // 三处声明：产结论的 report 步 + 读它的 derive + 合并前再读一次的 merge-index。
    // 两个 job 不共享工作区，所以 merge-index 那一处是从 job output 解回来的，不是同一份文件。
    assert.equal(yml.split('REVIEWS_FILE="ledger-reviews.json"').length - 1, 3, `${tag}report/derive/merge-index 三处都要自己声明复核结论文件的路径`);
    assert.equal(yml.split('rm -f "$REVIEWS_FILE"').length - 1, 2, `${tag}两处都要先删：这个文件名在仓库根上，PR 自己就能塞一份同名的假结论进来`);
    // 旧的接缝：--pr 是给 verify-index-pr 取人工双签用的，那条路已删。留着它等于给复活留门。
    assert.ok(!yml.includes('--pr "$PR_NUMBER"'), `${tag}--pr "$PR_NUMBER" 是人工签那条接缝，不许回来`);
    assert.ok(yml.includes('PR_NUMBER: ${{ github.event.pull_request.number }}'), `${tag}合并那一步要靠 PR_NUMBER 决定合哪条，缺了得先红`);
    // sealed 读的是 report 里的字段，不是那一步的退出码 —— 退出码 0 只说明「索引算得对」。
    assert.ok(yml.includes('if (r.seal && r.seal.ok) { sealed = true; }'), `${tag}sealed 要从 report.seal.ok 取`);

    const step = yml.slice(yml.indexOf('只批准「未命中拦截名单的首次收录'));
    assert.ok(step.length > 0, `${tag}approve 那一步的名字被改了，这段切片会静默变空`);
    const iDisp = step.indexOf('if [ "${DISPOSITION:-}" = "hit" ]');
    const iIndex = step.indexOf('if [ "${INDEX_PR:-}" = "true" ]');
    const iLedger = step.indexOf('if [ "${LEDGER_PR:-}" = "true" ]');
    const iFound = step.indexOf('if [ "${FOUND:-}" != "true" ]');
    for (const [name, at] of [['DISPOSITION', iDisp], ['INDEX_PR', iIndex], ['LEDGER_PR', iLedger], ['FOUND', iFound]]) {
      assert.ok(at >= 0, `${tag}approve 里找不到 ${name} 那一支`);
    }
    assert.ok(iDisp < iLedger, `${tag}台账支不许排在「无批准事项」之后`);
    assert.ok(iLedger < iFound, `${tag}台账支必须排在「没有投稿内容 ⇒ 无批准事项」之前（#53 线上读到的就是那枚绿勾）`);
    const ledgerBranch = step.slice(iLedger, iFound);
    assert.ok(ledgerBranch.includes('${LEDGER_SEALED:-}'), `${tag}台账支要读 derive 核出来的机器章结论`);
    assert.ok(/exit 0/.test(ledgerBranch) && ledgerBranch.includes('exit 1'),
      `${tag}台账支两面都要写：章齐 exit 0，章不齐 exit 1`);
    assert.ok(ledgerBranch.includes('::error::'), `${tag}章不齐那句必须是 ::error:: 而不是普通输出`);
    // 给投稿者/维护者看的两句要求要写当前的形状：照旧文案去凑「两名签」只会一直红。
    assert.ok(ledgerBranch.includes('ci:audit@'), `${tag}台账支要把机器章的形状写进报错（当前值 ${MACHINE_SEAL_PREFIX}<40hex>）`);
    assert.ok(ledgerBranch.includes(SEAL_PENDING_BY), `${tag}台账支要写出第一枚提交用的待盖值`);
    assert.doesNotMatch(ledgerBranch, /#human-approved|双签|两名[^。\n]{0,12}(签|放行)/,
      `${tag}已删的人工双签不许还以指令形式出现在这里`);
  }
});

test('接线：复核结论的生产者挂在 ledger_pr 上，且跨 job 走 base64', () => {
  for (const f of AUDIT_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    const tag = `${path.basename(f)}：`;
    const at = yml.indexOf('id: report');
    assert.ok(at > 0, `${tag}台账 PR 的逐字复核没有生产者 —— 机器章第 ④ 条就永远是一句空话`);
    const reportStep = yml.slice(at, yml.indexOf('- name:', at + 5));
    assert.ok(/if: steps\.kind\.outputs\.ledger_pr == 'true'/.test(reportStep),
      `${tag}复核步只该在台账 PR 上跑：别的 PR 没有下架要复核`);
    assert.ok(reportStep.includes('verify-report-evidence.mjs'), `${tag}复核步要调那个脚本，不是把判据再手抄一遍`);
    assert.ok(reportStep.includes('--base "$BASE_SHA"'), `${tag}对照物与索引都取 base，不是 PR 分支`);
    assert.ok(reportStep.includes('--out "$REVIEWS_FILE"'), `${tag}结论要落成 derive 读得到的那个文件名`);
    // 这一步自己**不判红**：不成立的事由 derive → approve 那条链去红，这里红一次会打断其余检查。
    assert.ok(reportStep.includes('set +e') && !/exit "\$RC"/.test(reportStep),
      `${tag}复核步不许把自己的退出码变成整条 run 的红`);
    assert.ok(reportStep.includes('base64 -w0'), `${tag}结论要 base64 之后再进 GITHUB_OUTPUT（reason 里有投稿方可控的文字）`);
    assert.ok(yml.includes('ledger_reviews_b64: ${{ steps.report.outputs.reviews_b64 }}'),
      `${tag}job output 没接上，merge-index 读到的永远是空`);

    const mi = yml.slice(yml.indexOf('  merge-index:'));
    assert.ok(mi.includes('REVIEWS_B64: ${{ needs.audit.outputs.ledger_reviews_b64 }}'),
      `${tag}合并前那一次重推导要拿到复核结论`);
    assert.ok(mi.includes('base64 -d > "$REVIEWS_FILE"'), `${tag}要把 job output 解回 derive 用的那个文件名`);
    assert.ok(mi.indexOf('base64 -d > "$REVIEWS_FILE"') < mi.indexOf('--reviews "$REVIEWS_FILE"'),
      `${tag}解结论必须排在重推导之前，顺序反了这一次读的还是空文件`);
    assert.doesNotMatch(mi, /REVIEWS_FILE="\$REVIEWS_FILE"|printf '%s' \$\{\{/,
      `${tag}不许把 job output 直接拼进 shell`);
    // kind 那句告警是台账 PR 的作者第一眼看到的话：照旧文案去凑「两名有写权限的人」只会一直红。
    assert.doesNotMatch(yml, /人工判断|查签名人的仓库权限|两名有写权限/,
      `${tag}kind 的台账告警还在教人来凑人工签名`);
  }
});

test('接线：merge-index 的重推导也核机器章（带 --reviews），且缺 PR 上下文时先红再谈合', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8').split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
    const at = code.indexOf('  merge-index:');
    const next = code.slice(at + 2).search(/^ {2}[A-Za-z_-]+:$/m);
    const job = next < 0 ? code.slice(at) : code.slice(at, at + 2 + next);
    assert.ok(job.includes('--reviews "$REVIEWS_FILE"'), `${path.basename(f)}：重推导不核机器章，台账类 PR 会在合并这一步退成「内容对得上就合」`);
    assert.ok(job.includes('REVIEWS_FILE="ledger-reviews.json"'), `${path.basename(f)}：这一步得自己声明复核结论文件，两个 job 之间不共享工作区`);
    assert.ok(!job.includes('--pr "$PR_NUMBER"'), `${path.basename(f)}：--pr 那条人工签接缝不许回来`);
    assert.ok(job.includes('if [ -z "${PR_NUMBER:-}" ]') && job.includes('没东西可合'),
      `${path.basename(f)}：PR_NUMBER 为空要红，不能空着继续判`);
    assert.ok(job.indexOf('--reviews "$REVIEWS_FILE"') < job.indexOf('gh pr merge'), '核机器章的那次重推导必须排在合并之前');
  }
});


/* ---------------------------------------------------------------- kind 那一步逐字执行

   上面那批断言读的是文本：它能钉住「这句话还写着」，钉不住「这条判据算得出正确的分类」。
   分类错一格 = 要么 merge-index 少拦一次、要么机器人那条重建合不动，两种都静默。
   所以这里把 workflow 里那段 bash 切出来、在有 origin 的临时仓库上**执行**
   （不复制判据 —— 复制了就变成测试只钉住测试里那一份）。
   起法与 runner 一致：`bash --noprofile --norc -e -o pipefail`（那个 -e 是 runner 给的）。
   脚本与 GITHUB_OUTPUT 都落在被测树**之外**：复现这条闸的时候我第一版把 `--report` 写进仓库根，
   下一个格子的 `git add -A` 就把报告当成了 PR 内容 ⇒ 四条对照组全红，而红的原因都不是它们要证的事。
*/
const KIND_STEP = '判定 PR 类型';

/** 切出某一步 `run: |` 的脚本体（dedent 到列 0）。块尾只到下一步的 `- name:` / `- uses:`。 */
function stepRunBody(wfText, name) {
  const lines = wfText.replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.ok(start >= 0, `workflow 里必须存在名为「${name}」的步骤（改名要一起改这里）`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {6}- (?:name|uses): /.test(lines[i])) { end = i; break; }
  }
  let open = -1;
  for (let i = start + 1; i < end; i += 1) if (/^\s*run: \|\s*$/.test(lines[i])) { open = i; break; }
  assert.ok(open >= 0, `步骤「${name}」里必须有 run: | 块`);
  const keyIndent = lines[open].length - lines[open].trimStart().length;
  const body = [];
  for (let i = open + 1; i < end; i += 1) {
    const l = lines[i];
    if (l.trim() !== '' && l.length - l.trimStart().length <= keyIndent) break;
    body.push(l);
  }
  const nonBlank = body.filter((l) => l.trim());
  assert.ok(nonBlank.length > 0, `步骤「${name}」的 run 块是空的`);
  const indent = Math.min(...nonBlank.map((l) => l.length - l.trimStart().length));
  return `${body.map((l) => l.slice(indent)).join('\n')}\n`;
}

const MOD = (id, vc) => ({
  id,
  name: id,
  author: 'someone',
  versions: [{ version: `v${vc}`, versionCode: vc, sha256: id.charCodeAt(0).toString(16).padEnd(64, '0'), zipUrl: `https://example.invalid/${id}-${vc}.zip`, size: 1 }],
});
const INDEX0 = { name: 'M', lastUpdate: 1, modules: [MOD('alpha', 1), MOD('beta', 2)] };
const LEDGER0 = { schema: 'sukisu-dispositions-v1', lastUpdate: 1, dispositions: [] };
// 夹具里的 by 用**当前合法的机器章形状**。kind 那一步只看路径、不看凭据，
// 所以拿一枚「看着就合格」的章去做形状，才测得出它到底有没有越权分类这条 PR。
const SEAL = { kind: 'revoke', reason: 'test-probe', by: `${MACHINE_SEAL_PREFIX}${'ab'.repeat(20)}`, at: '2026-10-17T00:00:00Z', note: '探针处置', id: 'beta' };

/** 起一个「有 origin 的仓库」：先按 shape.base 落 main，再按 shape.pr 落 PR 分支。 */
function makeKindRepo(shape) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kind-step-'));
  const repo = path.join(root, 'repo');
  execFileSync('git', ['init', '-q', '--bare', 'origin.git'], { cwd: root, encoding: 'utf8' });
  execFileSync('git', ['clone', '-q', path.join(root, 'origin.git'), 'repo'], { cwd: root, encoding: 'utf8' });
  const g = (args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();
  g(['config', 'user.email', 't@example.invalid']);
  g(['config', 'user.name', 't']);
  g(['config', 'core.autocrlf', 'false']);
  const ctx = {
    put: (rel, obj) => {
      const p = path.join(repo, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, `${JSON.stringify(obj, null, 2)}\n`, 'utf8');
    },
    rm: (rel) => fs.rmSync(path.join(repo, rel), { force: true }),
    // 内容一个字节不改、只把缩进与模块顺序换掉 —— derive 看不出差别，kind 看得出
    churn: () => {
      const cur = JSON.parse(fs.readFileSync(path.join(repo, 'json/modules.json'), 'utf8'));
      const out = { lastUpdate: cur.lastUpdate, modules: [...cur.modules].reverse(), name: cur.name };
      fs.writeFileSync(path.join(repo, 'json/modules.json'), `${JSON.stringify(out, null, 4)}\n`, 'utf8');
    },
  };
  g(['checkout', '-q', '-b', 'main']);
  ctx.put('json/modules.json', INDEX0);
  ctx.put('json/dispositions.json', LEDGER0);
  ctx.put('pending/alpha/1.json', MOD('alpha', 1));
  if (shape.base) shape.base(ctx);
  g(['add', '-A']);
  g(['commit', '-qm', 'base']);
  g(['push', '-q', '-u', 'origin', 'main']);
  const baseSha = g(['rev-parse', 'refs/remotes/origin/main']);
  g(['checkout', '-q', '-b', 'pr']);
  shape.pr(ctx);
  g(['add', '-A']);
  g(['commit', '-qm', 'pr']);
  return { root, repo, baseSha };
}

/** 在指定仓库里执行 kind 那一步，返回它写进 GITHUB_OUTPUT 的键。 */
function runKindStep({ root, repo }, js, found = 'false') {
  // 反斜杠路径在 bash 里不是「Windows 路径」，是一个含反斜杠的相对文件名 —— 脚本按相对名找不到、
  // `>> $GITHUB_OUTPUT` 也会往 cwd 里造一个怪名字的文件。两个路径都换成斜杠形式。
  const fwd = (p) => p.replace(/\\/g, '/');
  const sh = fwd(path.join(root, 'kind-step.sh'));
  const out = fwd(path.join(root, 'gh-output'));
  fs.writeFileSync(sh, js, 'utf8');
  fs.writeFileSync(out, '', 'utf8');
  let code = 0;
  let stream = '';
  try {
    const r = execFileSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', sh], {
      cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GITHUB_OUTPUT: out, BASE_REF: 'main', FOUND: found },
    });
    stream = `${r.stdout}${r.stderr}`;
  } catch (e) {
    code = e.status ?? 1;
    stream = `${String(e.stdout || '')}${String(e.stderr || '')}`;
  }
  const kv = {};
  for (const l of fs.readFileSync(out, 'utf8').split('\n').filter(Boolean)) {
    const i = l.indexOf('=');
    if (i > 0) kv[l.slice(0, i)] = l.slice(i + 1);
  }
  return { ...kv, code, stream };
}

const KIND_SHAPES = [
  { name: 'ledger-add-churn-index', expect: 'false', ledger: 'true', why: '台账加一条 + 索引只改缩进与键序（复现里走通的那格）',
    pr: ({ put, churn }) => { put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }); churn(); } },
  { name: 'ledger-add-rebuild-index', expect: 'false', ledger: 'true', why: '台账加一条 + 索引照推导删掉那个模块',
    pr: ({ put }) => {
      put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] });
      put('json/modules.json', { ...INDEX0, modules: INDEX0.modules.filter((m) => m.id !== 'beta') });
    } },
  { name: 'ledger-del-churn-index', expect: 'false', ledger: 'true', why: '台账删一条（解除封禁）+ 索引只改缩进与键序',
    base: ({ put }) => put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }),
    pr: ({ put, churn }) => { put('json/dispositions.json', LEDGER0); churn(); } },
  { name: 'ledger-only', expect: 'false', ledger: 'true', why: '只改台账、索引一个字节不动（#35 关掉的那格）',
    pr: ({ put }) => put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }) },
  { name: 'mode-a-consume', expect: 'true', ledger: 'false', why: '机器人那条：改了索引 + 消费掉 pending，台账不动 ⇒ 必须照旧进机器路由',
    pr: ({ put, rm }) => { put('json/modules.json', { ...INDEX0, modules: [...INDEX0.modules, MOD('alpha', 2)] }); rm('pending/alpha/1.json'); } },
  { name: 'index-only', expect: 'true', ledger: 'false', why: '手抄一份索引：分类仍是索引 PR，拦它的是下一步 derive，不是这一步',
    pr: ({ put }) => put('json/modules.json', { ...INDEX0, modules: INDEX0.modules.filter((m) => m.id !== 'beta') }) },
  { name: 'submission-plus-index', expect: 'false', ledger: 'false', found: 'true', why: '投稿 PR 里顺手带索引改动 ⇒ 按扫描结论走',
    pr: ({ put }) => { put('json/modules.json', { ...INDEX0, modules: [...INDEX0.modules, MOD('gamma', 1)] }); put('pending/gamma/1.json', MOD('gamma', 1)); } },
];

test('kind 逐字执行：四格台账形状留在人工合并，机器人那格照旧进机器路由', () => {
  const js = stepRunBody(fs.readFileSync(WF_MAIN, 'utf8'), KIND_STEP);
  assert.ok(js.includes('CHANGED_LEDGER'), '切出来的必须是含台账判据的那一步（切片切错就是空跑）');
  assert.ok(js.includes('BASE_SHA="$(git rev-parse "origin/$BASE_REF")"'), '切出来的必须真去解析 origin/<base>，不是拿 env 里现成的 sha');
  for (const s of KIND_SHAPES) {
    const r = runKindStep(makeKindRepo(s), js, s.found || 'false');
    assert.equal(r.code, 0, `${s.name}：这一步不该自己红（分类失败和判据失败是两件事）\n${r.stream}`);
    assert.equal(r.index_pr, s.expect, `${s.name}（${s.why}）期望 index_pr=${s.expect}，实得 ${r.index_pr}\n${r.stream}`);
    // ledger_pr 是另一条路由的入口，它和 index_pr 必须互斥 —— 两个都 true 就等于
    // 「同一条 PR 既能被当成索引重建、又能带着署名走第二支」，那正是 kind 该防的形状。
    assert.equal(r.ledger_pr, s.ledger, `${s.name} 期望 ledger_pr=${s.ledger}，实得 ${r.ledger_pr}\n${r.stream}`);
    assert.ok(!(r.index_pr === 'true' && r.ledger_pr === 'true'), `${s.name}：两个路由标记不许同时为真`);
    assert.match(r.base_sha || '', /^[0-9a-f]{40}$/, `${s.name}：base_sha 要解析成 40 位，否则后面两条 diff 都在比空气`);
  }
});

test('变异哨兵：摘掉 [ -z "$CHANGED_LEDGER" ] 那一格，churn 形状立刻回到机器路由（证明牙在这一句上）', () => {
  const js = stepRunBody(fs.readFileSync(WF_MAIN, 'utf8'), KIND_STEP);
  const mutated = js.replace('[ -z "$CHANGED_LEDGER" ] && ', '');
  assert.notEqual(mutated, js, '替换点漂了 —— kind 那一步的条件形状改了，要一起改这里');
  const shape = KIND_SHAPES.find((s) => s.name === 'ledger-add-churn-index');
  const before = runKindStep(makeKindRepo(shape), js);
  const after = runKindStep(makeKindRepo(shape), mutated);
  assert.equal(before.index_pr, 'false', '现行判据下这一格必须留在人工合并');
  assert.equal(after.index_pr, 'true', '摘掉台账那一条后它要翻回 true —— 不翻说明上面那批断言是空跑的');
});

// 下架的生效速度实际由 CDN 的 TTL 决定，不是由 main 决定：实测索引 PR #34 把索引推空之后
// 近 50 分钟，jsDelivr 上仍然返回下架前的 4 个模块（订阅那个地址的 App 照样能装到已下架的包）。
// 所以合并之后必须紧跟一次 purge；而它排在合并**之后**同样是判据的一部分 ——
// 先 purge 再合，清掉的是旧内容，新内容照样被缓存回去。
test('merge-index 合并之后必须 purge CDN，且顺序在合并之后', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8')
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    const at = code.indexOf('  merge-index:');
    const next = code.slice(at + 2).search(/^ {2}[A-Za-z_-]+:$/m);
    const job = next < 0 ? code.slice(at) : code.slice(at, at + 2 + next);
    assert.match(job, /node scripts\/purge-cdn\.mjs/, '清缓存要交给脚本，判据不在 YAML 里再写一遍');
    // repo variable 不会自动变成环境变量 —— 不显式传，README 里那句
    // 「其它镜像放进 CDN_PURGE_URLS」就是一条配了也不生效的死配置。
    assert.match(job, /CDN_PURGE_URLS: \$\{\{ vars\.CDN_PURGE_URLS \}\}/, 'CDN_PURGE_URLS 必须显式传给脚本');
    assert.ok(job.indexOf('gh pr merge') < job.indexOf('purge-cdn.mjs'),
      'purge 必须排在合并之后 —— 先清再合等于什么都没清');
  }
});

// 判定投稿的这套代码自己没过检，就没有资格批准任何投稿。
test('approve 必须依赖 selftest，且上游不 success 时自己判红（不能靠 skip）', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8')
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    assert.match(code, /^ {2}selftest:$/m, `${path.basename(f)} 里得有 selftest 作业`);
    const at = code.indexOf('  approve:');
    const job = code.slice(at, at + 600);
    assert.match(job, /needs: \[audit, selftest\]/,
      'approve 要 needs selftest：单测红 → approve 被 skip → required check 不成功 → 不放行');
    const st = code.slice(code.indexOf('  selftest:'), code.indexOf('  approve:'));
    assert.match(st, /node --test/, '真的把仓库单测跑起来，而不是留个占位作业');
    // selftest 自己不许写任何东西：它只是判据生产者
    assert.match(st, /permissions: \{\}/, 'selftest 不需要任何 GitHub 写权限');

    // 关键的一条：**不能让 approve 被 skip**。canary PR #24 实测「上游红 → approve skip」
    // 并不会挡住合并 —— skipped 的 required check 在 GitHub 眼里按满足处理，那条打坏了测试的
    // PR 直接被 gh pr merge 合进了 main。所以 approve 必须 always 跑，并且自己判红。
    assert.match(job, /^ {4}if: always\(\)$/m, 'approve 必须 always 跑：skip 等于放行');
    assert.match(job, /needs: \[audit, selftest\]/);
    const gate = code.slice(code.indexOf('上游没过检就没有批准资格'), code.indexOf('只批准「未命中拦截名单的首次收录'));
    assert.match(gate, /AUDIT_RESULT: \$\{\{ needs\.audit\.result \}\}/, '要读 needs.*.result，不是 outputs');
    assert.match(gate, /SELFTEST_RESULT: \$\{\{ needs\.selftest\.result \}\}/);
    assert.match(gate, /!= "success"/, '非 success（红/跳过/取消）都要 exit 1');
  }
});

// 索引 PR 由 App 建出来。PR 刚建的那几秒 check runs 还是空的，而 `gh pr checks --watch`
// 碰到空列表是**立刻退出 1**（run 38068977342 实测：PR #16 建好 0.9 秒就报 no checks
// reported 红掉，checks 后来其实会建出来）。而更要命的一种情况是提交信息里带了 [skip ci]
// —— GitHub 会干脆不为这条 PR 创建任何 run，于是这一段永远等不到东西。
// 这一步只观察并报到本 run 的日志里：合并本身在 audit.yml 的 merge-index（见上面那条测试）。
test('等索引 PR 过检那一段：先有界地等 checks 出现，再按 approve 的结论报状态', () => {
  for (const f of INDEX_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    const at = yml.indexOf('name: 等索引 PR 过检');
    assert.ok(at > 0, `${path.basename(f)} 里得有这样一步`);
    // 只比可执行行：注释里就会出现 `gh pr checks --watch` 这类字样（那正是它在解释的坑），
    // 整段按原文取下标会把「注释先出现」当成「代码先执行」，于是这条测试只在删注释时变绿。
    const block = yml
      .slice(at, at + 4000)
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');

    assert.match(block, /DEADLINE/, '等待必须有上界，否则这一步会挂死整个 workflow');
    const waits = block.indexOf('check-runs');
    const watches = block.indexOf('gh pr checks');
    const judges = block.indexOf('select(.name=="approve")');
    assert.ok(waits >= 0 && watches >= 0 && judges >= 0,
      `${path.basename(f)} 的这一步缺了三段之一：等 checks / watch / approve 判定`);
    assert.ok(waits < watches, '先确认 checks 存在，再 --watch —— 顺序反了就还是那个 0.9 秒的假红');
    assert.ok(judges > watches, 'approve 的结论要在 watch 之后查，抢跑等于没等');
    assert.match(block, /approve 在 .* 上的结论是/, 'approve 不是 success 时要说清结论是什么，而不是静默报好');
    assert.doesNotMatch(block, /gh pr merge/, '这一步不该试图合并：这个上下文里的 token 合不动（403）');
  }
});

/**
 * 同一个 job 里出现两次同名 key（我自己犯过一次：新步骤插到了 `steps:` 前面，于是有两个
 * `steps:`）。这类错不会让 CI 变红，而是让**整条 workflow 解析失败、一条 check 都不产生** ——
 * 而「required check 从没上报过」正是本仓库已经撞过两次的死法（所有 PR 永久 BLOCKED，
 * 或者更糟：没人知道它没在跑）。
 *
 * 本仓库不许装 npm 依赖，所以这里不引 YAML 解析器，只做够拦住该类的结构检查：
 * 只扫 `jobs:` 之下、缩进恰好 4 的 key（block scalar 的内容至少 8 空格，不会被误当 key）。
 */
function duplicateJobKeys(yml) {
  const lines = yml.split(/\r?\n/).filter((l) => !/^\s*#/.test(l));
  const dup = [];
  let inJobs = false;
  let job = null;
  let seen = new Set();
  for (const line of lines) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      inJobs = /^jobs:\s*$/.test(line);
      job = null;
      continue;
    }
    if (!inJobs) continue;
    if (indent === 2) {
      job = /^ {2}([A-Za-z_][\w-]*):/.exec(line)?.[1] ?? null;
      seen = new Set();
      continue;
    }
    if (indent === 4 && job) {
      const key = /^ {4}([A-Za-z_][\w-]*):/.exec(line)?.[1];
      if (!key) continue;
      if (seen.has(key)) dup.push(`${job}.${key}`);
      seen.add(key);
    }
  }
  return dup;
}

test('两份 workflow 都不许有同一 job 内的重复 key（那会让整条 workflow 不跑）', () => {
  // 夹具先证明它抓得到：两个 steps: 就是这次犯下的真错。
  assert.deepEqual(duplicateJobKeys('jobs:\n  a:\n    steps:\n          x\n    steps:\n          y\n'), ['a.steps']);
  assert.deepEqual(duplicateJobKeys('jobs:\n  a:\n    steps:\n    name: a\n'), []);
  // run: 块里的内容缩进更深，不该被当成 key
  assert.deepEqual(duplicateJobKeys('jobs:\n  a:\n    run: |\n          name: 里层\n    steps:\n'), []);

  for (const f of [...AUDIT_COPIES, ...INDEX_COPIES]) {
    assert.deepEqual(duplicateJobKeys(fs.readFileSync(f, 'utf8')), [],
      `${path.basename(f)} 里有重复的 job key`);
  }
});

/**
 * workflow 里 `steps.<id>` 是纯字符串连接：id 没声明时 GitHub 不报错，只是取到空串。
 * 于是 `${{ steps.build.outputs.build_rc }}` 少写一个 `id: build`，回帖就永远显示
 * 「退出码 0 ✅」—— 判据自己说自己绿，是这类错最难受的地方。runner 上的行为测不到，
 * 就在文本层把这根线钉住。注释行要剥掉：那里出现 steps.xxx 只是解释，不会被求值。
 */
function danglingStepRefs(yml) {
  const code = yml.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
  // `id:` 有两种合法写法：单独一行（本仓库用的是这种），或直接跟在列表项的 `- ` 后面。
  // 只认前一种的话，后一种写出来的 step 会被误判成"未声明"，于是这条测试会逼人改回
  // 它自己喜欢的那一种 —— 那是风格检查，不是正确性检查。
  const declared = new Set([...code.matchAll(/^\s*(?:-\s+)?id:\s*([A-Za-z0-9_-]+)\s*$/gm)].map((m) => m[1]));
  const refs = [...new Set([...code.matchAll(/\bsteps\.([A-Za-z0-9_-]+)/g)].map((m) => m[1]))];
  return refs.filter((r) => !declared.has(r));
}

test('workflow 里不许引用没声明 id 的 step（引用未声明=静默取空值）', () => {
  // 先证明这个检查不是摆设：漏一个 id 必须被抓到。夹具按真实缩进写，
  // 因为 `id:` 在 YAML 里永远是缩进行，正则也只认缩进行。
  assert.deepEqual(danglingStepRefs('      - id: x\n        run: ${{ steps.x.outputs.k }}'), []);
  assert.deepEqual(danglingStepRefs('      - name: n\n        id: x\n        run: ${{ steps.x.outputs.k }}'), []);
  assert.deepEqual(danglingStepRefs('      - id: x\n        run: ${{ steps.y.outputs.k }}'), ['y']);
  assert.deepEqual(danglingStepRefs('      # - run: ${{ steps.z.outputs.k }}\n      - id: x'), []);

  for (const f of [...AUDIT_COPIES, ...INDEX_COPIES]) {
    const dangling = danglingStepRefs(fs.readFileSync(f, 'utf8'));
    assert.deepEqual(dangling, [],
      `${path.basename(f)} 引用了未声明的 step id：${dangling.join(', ')} —— 那些取值恒为空串`);
  }
});

test('build_rc 必须真的从有 id 的那一步写出，否则回帖把冲突说成成功', () => {
  const yml = fs.readFileSync(WF_INDEX, 'utf8');
  assert.match(yml, /id:\s*build\b/, '写 PIPESTATUS 的那一步得叫 build');
  assert.match(yml, /BUILD_RC:\s*\$\{\{ steps\.build\.outputs\.build_rc \}\}/);
  // 反过来也得对上号：产出方确实写了这个 output 名
  assert.match(yml, /echo "build_rc=/);
});

test('approve 与 publish 的分工：没有待审内容时 approve 让路，但绝不合并', () => {
  // approve 在 found!=true 时也必须成功（否则删除 pending / 改脚本这类维护 PR 会卡在
  // 一个永远不会变绿的 required check 上）。正因如此，publish 不能只看 approve 成功就合，
  // 必须同时钉住 found 与 action —— 少一个条件就是「机器人自动合掉任意 PR」。
  const yml = fs.readFileSync(WF_MAIN, 'utf8');
  assert.match(yml, /found: \$\{\{ steps\.locate\.outputs\.found \}\}/, 'audit 必须把 found 提为 job output');
  assert.match(yml, /if: needs\.audit\.outputs\.found == 'true' && needs\.audit\.outputs\.action == 'auto-approve'/);
});

test('索引 PR 的判定必须排在「没有投稿内容」之前', () => {
  // 顺序就是安全性：索引 PR 的 found 天然不是 true，先走 found 分支等于
  // 「任何只改 json/modules.json 的 PR 一律放行」，手抄索引即可绕过整条审核链。
  const yml = fs.readFileSync(WF_MAIN, 'utf8');
  // 只在 approve 那一步的正文里比顺序：全文找 FOUND 会命中 kind 步骤里的日志文案，
  // 那是「比较位置」这类断言最容易假通过与假失败的地方。
  const anchor = yml.indexOf('INDEX_PR: ${{ needs.audit.outputs.index_pr }}');
  assert.ok(anchor > 0, 'approve 必须把 index_pr 读进来');
  const body = yml.slice(anchor);
  const i = body.indexOf('${INDEX_PR:-}');
  const j = body.indexOf('${FOUND:-}');
  assert.ok(i >= 0, 'approve 里必须显式处理索引 PR');
  assert.ok(j >= 0, 'approve 里必须处理 found!=true');
  assert.ok(i < j, '索引 PR 分支必须在 found 分支之前');
  assert.match(yml, /index_pr: \$\{\{ steps\.kind\.outputs\.index_pr \}\}/);
  assert.match(yml, /index_derived: \$\{\{ steps\.derive\.outputs\.derived \}\}/);
});

test('pull_request 触发不许带 paths 过滤：每个 PR 都必须拿到 approve', () => {
  // required check 从没上报过 = Expected = 永远合不了，这点和「它红了」在 GitHub 眼里是
  // 同一件事。带 paths 的版本只认 pending/**、json/**，改 scripts/ 或文档的维护 PR 根本
  // 不会触发审核 —— PR #5 就死在这上面（gh pr checks → no checks reported，
  // mergeStateStatus → BLOCKED），整条保护变成仓库的自我锁死。
  // 放行靠 locate 的 found=false 分支，不靠「干脆不触发」。
  for (const f of AUDIT_COPIES) {
    const yml = fs.readFileSync(f, 'utf8');
    const block = yml.slice(yml.indexOf('pull_request:'), yml.indexOf('workflow_dispatch:'));
    assert.ok(block.length > 0 && block.includes('types:'), `${f} 里得能定位到 pull_request 触发块`);
    assert.doesNotMatch(block, /^\s*paths:/m, `${f} 的 pull_request 触发里出现 paths 就会锁死维护类 PR`);
  }
});

// 闸门二曾经是 `git merge-base --is-ancestor origin/main HEAD`（PR 必须已包含当前 main）。
// PR #4 重跑时死在这句话上：main 会被机器人自己推进（索引重建 PR 也合进 main），于是任何
// 一条提交后稍等几分钟的投稿都会「不是后代」，而投稿方是不会 rebase 的机器人 —— 模块永远进不了索引。
// 要防的「拿古老分支当基准用旧扫描器定罪自己」早就被钉定 + 复核挡住了，所以这里只允许
// 「把当前 base 合进来，合不动（真冲突）才拒」这一种写法。
test('审核不许要求 PR 已包含当前 main，只允许「合得动就审」', () => {
  for (const f of AUDIT_COPIES) {
    // 只比可执行行：上面那段「这里原来写的是 …」的注释里就带着旧命令，整文件匹配会把
    // 解释历史的话当成违反约定，于是这条测试永远只能在删掉注释时变绿 —— 那正是它最该
    // 拦住的那种删除。
    const code = fs
      .readFileSync(f, 'utf8')
      .split(/\r?\n/)
      .filter((l) => !/^\s*#/.test(l))
      .join('\n');
    assert.doesNotMatch(code, /merge-base\s+--is-ancestor/, `${f} 里不许再有祖先检查，它会冻死机器人投稿`);
    assert.match(code, /git (?:-c \S+ )*merge --no-commit --no-ff/, `${f} 的闸门二必须是「合并当前 base」`);
    // 那两个 -c 不是装饰：runner 上没有 committer 身份，而「需要新建一个合并提交」的 merge ——
    // 重跑一条 base 已前进的旧 PR 就是这个形状 —— 即使带着 --no-commit 也照样要身份
    // （run 39022231657 attempt 2 实测红在那句；本地复现 rc=128 且不写 MERGE_HEAD）。
    // 真跑那一句的用例在 test/verify-pending-proof.test.mjs，这一格只钉它在场。
    assert.match(code, /-c user\.name=\S+ -c user\.email=\S+ merge --no-commit --no-ff/,
      `${f} 的闸门二必须自带占位身份，否则重跑旧 PR 会死在 Committer identity unknown`);
    assert.match(code, /git merge --abort/, `${f} 冲突时必须撤回合并并明确失败，不能猜哪一边`);
  }
});

test('verify-index-pr 在 audit 里被调用，且用同一套 check 名取证', () => {
  const yml = fs.readFileSync(WF_MAIN, 'utf8');
  assert.match(yml, /verify-index-pr\.mjs/);
  assert.match(yml, /checks: read/, '取证要读 check runs，权限缺了就只会得到一个红');
});

test('parseArgs：--changed 吃多个路径，且不把下一个 --flag 吞掉', () => {
  const o = parseArgs(['--pending', 'p', '--changed', 'a.json', 'b.json', '--dry-run']);
  assert.deepEqual(o.changed.map((p) => path.basename(p)), ['a.json', 'b.json']);
  assert.equal(o['dry-run'], true);
  assert.equal(o.pending, 'p');
});

/* ------------------------------------------------ P3：处置台账在 workflow 里的接线 */

/** 取 code（去掉注释行）里某个标记所在的 job 片段。 */
function jobCode(yml, jobKey) {
  const code = yml.split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
  const at = code.indexOf(`  ${jobKey}:`);
  assert.ok(at >= 0, `workflow 里得有 ${jobKey} 作业`);
  const next = code.slice(at + 1).search(/^ {2}\S.*:$/m);
  return code.slice(at, next < 0 ? undefined : at + 1 + next);
}

test('dispose 步存在、只在有投稿内容时跑，并把结论导出成 job output', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8').split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
    assert.match(code, /^ {8}id: dispose$/m, `${path.basename(f)} 里必须有 id 为 dispose 的步骤`);
    assert.match(code, /node "\$\{P\}scripts\/disposition-check\.mjs" --github-output/, '判据由脚本产出，不内联');
    assert.match(code, /disposition: \$\{\{ steps\.dispose\.outputs\.hit \}\}/, '结论必须导出，否则 approve 拿不到');
    assert.match(code, /disposition_reason: \$\{\{ steps\.dispose\.outputs\.why \}\}/);
    // 导出名与引用名靠字符串相等连接：改任何一边都等于悄悄断链
    const hit = code.match(/^ {6}disposition: \$\{\{ steps\.dispose\.outputs\.(\w+) \}\}/m);
    assert.ok(hit && hit[1] === 'hit', 'output 名必须就是 dispose 写的那个 key');
  }
});

test('approve 先看台账命中，且这一条排在索引 PR 分支之前', () => {
  for (const f of AUDIT_COPIES) {
    const job = jobCode(fs.readFileSync(f, 'utf8'), 'approve');
    const hitAt = job.indexOf('"${DISPOSITION:-}" = "hit"');
    const idxAt = job.indexOf('"${INDEX_PR:-}" = "true"');
    assert.ok(hitAt >= 0, 'approve 必须自己判台账命中 —— 命中就红，不能靠 needs 被 skip（skip 等于满足）');
    assert.ok(idxAt >= 0);
    assert.ok(hitAt < idxAt, '台账命中要先于一切放行分支：混合 PR 也不能从索引分支溜过去');
    assert.match(job, /DISPOSITION: \$\{\{ needs\.audit\.outputs\.disposition \}\}/);
    assert.match(job, /exit 1/, '被拒必须是明确的红，不是消失');
  }
});

test('两处 verify-index-pr 调用都要显式给 --dispositions-file（monorepo 布局下默认值是错的）', () => {
  const code = fs.readFileSync(WF_MAIN, 'utf8').split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
  // 计数而不是解析整段调用：workflow 里靠反斜杠续行，跨行正则会贪心把两次调用并成一次。
  assert.equal((code.match(/verify-index-pr\.mjs/g) || []).length, 2, 'derive 与 merge-index 各一次重推导');
  assert.equal((code.match(/--dispositions-file "\$DISPOSITIONS_FILE"/g) || []).length, 3,
    '三个读台账的调用（report/derive/merge-index）都要显式给台账路径：默认值相对 cwd，contrib/repo 布局下会读错文件');
  assert.equal((code.match(/DISPOSITIONS_FILE="\$\{PREFIX:\+\$PREFIX\/\}json\/dispositions\.json"/g) || []).length, 3);
});

test('workflow 不许内联台账匹配逻辑（判据只能有一份实现）', () => {
  for (const f of AUDIT_COPIES) {
    const code = fs.readFileSync(f, 'utf8').split(/\r?\n/).filter((l) => !/^\s*#/.test(l)).join('\n');
    assert.doesNotMatch(code, /matchAny\(|isModuleLevel\(|filterVersions\(/,
      '台账判据出现在 workflow 里就是第二份实现，早晚和 build-index 漂移');
  }
});

/* ------------------------------------------------ P4：治理文档不许比代码旧 */

const GOVERNANCE_FILE = path.resolve(import.meta.dirname, '../GOVERNANCE.md');

test('GOVERNANCE.md 存在，且写的就是当前这套机器章判据（不许还承诺两签放行）', () => {
  // 给投稿者看的文案指向这份文件。它一旦和 assertMergeApproved / judgeLedgerSeal 脱节，
  // 就等于告诉别人一条走不通的官方路径 —— 比没有文档更糟。
  // 下面每个值都从代码里 import，改代码不改文档会直接红。
  assert.ok(fs.existsSync(GOVERNANCE_FILE), 'GOVERNANCE.md 必须存在：报错文案指着它');
  const doc = fs.readFileSync(GOVERNANCE_FILE, 'utf8');

  assert.match(doc, /^# 治理与机器章（GOVERNANCE）\r?$/m, '标题要写的是机器章，不是双签（\r? 是因为这份文件用 CRLF）');
  assert.ok(doc.includes('本站没有人工审核'), '这条是整份文件的前提，必须写在脸上');
  assert.ok(doc.includes('这里没有人可以签你进来'), '申诉那一节要把「没有人能签你进来」说清');

  // 章的形状从写入端 import：文档里写的必须就是代码认的那一枚。
  assert.ok(doc.includes(MACHINE_SEAL_PREFIX), `文档要写当前的章形状 ${MACHINE_SEAL_PREFIX}<40hex>`);
  assert.ok(doc.includes(SEAL_PENDING_BY), `第一枚提交用的待盖值 ${SEAL_PENDING_BY} 是两枚提交那一段的核心`);
  assert.ok(doc.includes('judgeLedgerSeal'), '四条判据的实现处要点名到函数，否则文档指向的是一段不存在的代码');
  assert.match(doc, /gh api repos\/[^\s]+\/commits\/[^\s]+\/check-runs/, '要给出可复制的复验命令（回访的是 check，不是评论）');
  assert.ok(doc.includes('不是正式渠道'), '申诉入口要写明哪里不算数');

  // 反面：已删机制不许以任何「照着做就成」的形状留下。
  // 「两个不同的人」这四个字今天只许出现在否定句 / 历史句里，所以这里比的是指令形状，不是这个词。
  assert.doesNotMatch(doc, /#human-approved/, '已删标记不许留在治理文档里：那是给人照做的指令');
  assert.doesNotMatch(doc, /双签|人工签/, '本站没有这一档，文档不许把它写成一条可走的路');
  assert.doesNotMatch(doc, /^\|\s*签核人/m, '「签核人」那一档已从角色表删掉，不许回来');
  assert.doesNotMatch(doc, /首行写|各写一次/, '教人怎么签的句式一条都不许留');

  // ④ 的生产者已接线（2026-10-22），于是这一格有两种相反的漂移都咬得住：
  // 一是文档还写着「生产者还没上线」（那会把一条已经能走的路读成不可达，比不写更害人，
  // 因为公示页与这份文件是别人判断「这台机器会不会自己下架东西」的唯一依据）；
  // 二是文档把 ④ 写成包含 AI（那一步今天只有字节核对，一次模型调用都没有）。
  assert.doesNotMatch(doc, /今天还没有生产者|生产者还没接线/, '④ 的生产者已存在，这句会把走得通的路写成走不通');
  const producer = path.resolve(import.meta.dirname, '../scripts/verify-report-evidence.mjs');
  assert.ok(doc.includes('verify-report-evidence.mjs'), '第 3 节 ④ 要点名真正的生产者脚本，否则文档指向一段不存在的代码');
  assert.ok(fs.existsSync(producer), '文档点名的生产者必须真的在这棵树里');
  assert.doesNotMatch(doc, /复核成立[^。\n]*AI 复核/, '④ 今天不含 AI，不许把它写成两件事');

  // 文档里那个「每轮上限」是 owner 拍「定时批量」时定价的那个数：它比 CI 一轮能复核的包数还大，
  // 就等于每轮 cron 都开一条必然红的台账 PR。Worker 那一侧的同一条约束钉在 worker/ledger.test.ts，
  // 这里只比这份检出里读得到的那一份。
  const capInDoc = doc.match(/每轮上限 (\d+) 枚产物/);
  assert.ok(capInDoc, '定时批量那一格要把每轮上限写在脸上，不能只说“按批”');
  assert.ok(Number(capInDoc[1]) <= MAX_PACKAGES_PER_RUN,
    `文档写的每轮上限 ${capInDoc[1]} > CI 一轮复核得动的 ${MAX_PACKAGES_PER_RUN} 包`);
});

test('README 的标记契约表不许写已经不存在的常量与章形', () => {
  // 这一格是被 §11 那条「改代码必须同轮改文档」咬过第二次的位置：
  // 表里列的是**常量名**，读者（人和下一次改这里的项目）都拿它当「写入方还有这一档」的证据。
  // 人工双签整条支路删掉之后，表里那一行和那枚 `human-approved#…/c<id>+c<id>` 章形还留了一轮，
  // 形状上像官方路径，实际正向一次也走不通 —— 和 GOVERNANCE 那句「不许承诺两签放行」是同一条纪律。
  const doc = fs.readFileSync(path.resolve(import.meta.dirname, '../README.md'), 'utf8');
  assert.doesNotMatch(doc, /human-approved|HUMAN_APPROVED/, '这枚章已经没有写入方了，文档不许还把它列进契约表');
  assert.doesNotMatch(doc, /c<评论id>\+c<评论id>/, '两名签核评论 id 那枚章形不许还当作今天的形状展示');
  for (const status of APPROVED_STATUSES) {
    assert.ok(doc.includes(status), `isApproved 认的状态 ${status} 必须写在表里：它是两边的唯一约定面`);
  }
  assert.ok(doc.includes(MACHINE_SEAL_PREFIX), '台账那一枚章的形状要在 README 就点出来，不能只在 GOVERNANCE 里');
});

test('审核判红那条给投稿者看的报错，指向的文件和说法都必须是真实的', () => {
  // 这句文案在 shell 里，插值不到 JS 常量，所以只能反过来查文本：
  // 它必须指向 GOVERNANCE.md，且说法要与「本站只有机器审核」一致 ——
  // 教投稿者去凑两名签名，等于给一条永远红着的 PR 指一条不存在的路。
  for (const f of AUDIT_COPIES) {
    const line = fs.readFileSync(f, 'utf8').match(/::error::[^\n]*不满足自动放行条件[^\n]*/);
    assert.ok(line, `${path.basename(f)} 里必须留着那条报错`);
    assert.ok(line[0].includes('GOVERNANCE.md'), '报错指向的必须是治理文档，不是「README/GOVERNANCE.md」这种空位');
    assert.ok(line[0].includes('本站只有机器审核'), `报错要说当前的话：${line[0]}`);
    assert.doesNotMatch(line[0], /#human-approved|双签|两名/, '已删的人工双签不许还写在这句话里');
  }
});
