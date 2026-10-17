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
  HUMAN_APPROVAL_MARKER,
  HUMAN_APPROVE_STATUS,
  REQUIRED_SIGNERS,
  TRUSTED_ASSOCIATIONS,
  checkConclusion,
  assertMergeApproved,
  findHumanApprovals,
  approvalBy,
  approvalVerifyHint,
  stampEntry,
  stampPendingFile,
  findPrForCommit,
  parseArgs,
  main,
} from '../scripts/publish-from-main.mjs';
import { isApproved } from '../scripts/build-index.mjs';

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

test('标签和评论不是批准证据：只带 auto-approved 标签也拒', () => {
  // 这条钉住设计取舍：labels 有 triage 权限就能加，评论正文投稿者能影响。
  const v = assertMergeApproved({
    pr: prOk({ labels: [{ name: 'auto-approved' }], body: 'CI says auto-approved ✅' }),
    checks: [],
    mainBranch: 'main',
  });
  assert.equal(v.ok, false);
});

/* ------------------------------------------------------------ 人工双签放行 */

const sign = (id, login, assoc = 'MEMBER', body = `${HUMAN_APPROVAL_MARKER} 扫描器把调试打印判成可疑，人工看过没问题`) => ({
  id, user: { login }, author_association: assoc, body,
});
const humanPr = (over = {}) => prOk({ merged_by: { login: 'yufeng-liang' }, ...over });
const redApprove = [check(APPROVE_CHECK_NAME, 'failure')];

test('机器判红 + 两个不同 org 成员签名 + 人是合并者 → 人工路成立', () => {
  const v = assertMergeApproved({
    pr: humanPr(),
    checks: redApprove,
    comments: [sign(101, 'alice'), sign(102, 'bob', 'OWNER')],
    mainBranch: 'main',
  });
  assert.equal(v.ok, true);
  assert.equal(v.kind, 'human');
  assert.deepEqual(v.evidence.signers.map((s) => s.login), ['alice', 'bob']);
  assert.match(v.reason, /人工合并/);
});

test('只有一签不够；同一个人发十条也还是一签', () => {
  const one = assertMergeApproved({ pr: humanPr(), checks: redApprove, comments: [sign(1, 'alice')] });
  assert.equal(one.ok, false);
  assert.match(one.reason, /人工签只有 1 个/);
  assert.match(one.reason, /少于要求的 2 个不同的人/);
  const same = assertMergeApproved({
    pr: humanPr(), checks: redApprove,
    comments: [sign(1, 'alice'), sign(2, 'alice'), sign(3, 'ALICE')],
  });
  assert.equal(same.ok, false, '大小写不同的同名也是同一个人');
  assert.equal(same.evidence.signers.length, 1);
});

test('签核人身份不够就不算：CONTRIBUTOR / NONE / 空都拒', () => {
  for (const assoc of ['CONTRIBUTOR', 'NONE', 'COLLABORATOR', '']) {
    const v = assertMergeApproved({
      pr: humanPr(), checks: redApprove, comments: [sign(1, 'alice', assoc), sign(2, 'bob', assoc)],
    });
    assert.equal(v.ok, false, `${assoc} 不该算签`);
    assert.match(v.reason, /一条 #human-approved 人工签都没有/);
  }
});

test('标记必须在第一行开头：讨论里夹一句不算签', () => {
  const v = assertMergeApproved({
    pr: humanPr(), checks: redApprove,
    comments: [sign(1, 'alice', 'MEMBER', '我看了一下，' + HUMAN_APPROVAL_MARKER + ' 应该没问题'), sign(2, 'bob')],
  });
  assert.equal(v.ok, false);
});

test('红着被 bot 合并 → 人工路也拒：那是保护配置被改了，不是有人放行', () => {
  const v = assertMergeApproved({
    pr: humanPr({ merged_by: { login: 'github-actions[bot]' } }),
    checks: redApprove,
    comments: [sign(1, 'alice'), sign(2, 'bob')],
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /org\/ruleset 被改到允许/);
});

test('查不到是谁合的 → 拒（人工放行不留名等于没有放行）', () => {
  const v = assertMergeApproved({
    pr: humanPr({ merged_by: undefined }), checks: redApprove, comments: [sign(1, 'alice'), sign(2, 'bob')],
  });
  assert.equal(v.ok, false);
  assert.match(v.reason, /查不到是谁合的/);
});

test('机器路优先：approve 是 success 时不把人算进章里', () => {
  const v = assertMergeApproved({
    pr: humanPr(), checks: [check(APPROVE_CHECK_NAME, 'success')], comments: [sign(1, 'alice'), sign(2, 'bob')],
  });
  assert.equal(v.kind, 'ci');
  assert.equal(v.evidence.signers, undefined);
});

test('人工章写的是评论 id，任何人能回访；verify 指向那些评论', () => {
  const v = assertMergeApproved({
    pr: humanPr(), checks: redApprove, comments: [sign(101, 'alice'), sign(102, 'bob')],
  });
  const by = approvalBy({ owner: 'o', repo: 'r', evidence: v.evidence });
  assert.equal(by, `human-approved#o/rPR7@${SHA.slice(0, 12)}/c101+c102`);
  assert.ok(isApproved({ audit: { status: HUMAN_APPROVE_STATUS, by } }), 'build-index 认这个章');
  const hint = approvalVerifyHint({ owner: 'o', repo: 'r', evidence: v.evidence });
  assert.equal(hint, 'gh api repos/o/r/issues/comments/101 && gh api repos/o/r/issues/comments/102');
});

test('findHumanApprovals：非签名评论直接跳过，不参与判定也不报错', () => {
  const r = findHumanApprovals([
    { id: 1, user: { login: 'x' }, author_association: 'MEMBER', body: '普通讨论' },
    null,
    { body: HUMAN_APPROVAL_MARKER },
    sign(9, 'alice', 'MEMBER'),
  ]);
  assert.equal(r.signers.length, 1);
  assert.equal(r.enough, false);
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
  globalThis.fetch = async (url, init) => {
    const res = handler(String(url), init);
    if (res === null) return { ok: false, status: 404, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => res };
  };
  return () => { globalThis.fetch = orig; };
}

// 三个端点的 URL 长得互相包含（.../commits/<sha>/pulls 也含 "/pulls"），
// 所以匹配顺序必须是 check-runs -> /pulls/<n> -> /commits/<sha>/pulls。
// 上一版测试把泛匹配放前面，结果详情接口返回了列表体，merged 字段凭空消失。
//
// 返回形状按 GitHub 的真实响应来：`/commits/{sha}/pulls` 是**裸数组**。
// 之前这里返回 `{ pull_requests: [...] }`，和被测代码的同一个误解正好对上，
// 于是 31 条测试全绿、线上第一次真调用就判成「提交没有关联 PR」而拒绝盖章。
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

test('findPrForCommit 会取 PR 评论 —— 人工签的证据来源，漏取就等于人工放行永远不成立', async () => {
  const restore = stubApi({
    pullList: PULL_LIST, pr: { ...PR_BODY, merged_by: { login: 'yufeng-liang' } },
    checkRuns: [{ name: APPROVE_CHECK_NAME, conclusion: 'failure', status: 'completed' }],
    comments: [sign(55, 'alice'), sign(56, 'bob')],
  });
  try {
    const r = await findPrForCommit({ apiBase: 'https://api.github.com', token: 't', owner: 'o', repo: 'r', sha: SHA, log: fakeLog() });
    assert.equal(r.comments.length, 2);
    const v = assertMergeApproved({ pr: r.pr, checks: r.checks, comments: r.comments });
    assert.equal(v.ok, true);
    assert.equal(v.kind, 'human');
  } finally { restore(); }
});

test('main：机器判红但人工双签齐 → 照样盖章，章上写的是评论 id', async () => {
  const { pd, f } = pendingFixture();
  const report = path.join(pd, '..', 'report.json');
  const restore = stubApi({
    pullList: PULL_LIST, pr: { ...PR_BODY, merged_by: { login: 'yufeng-liang' } },
    checkRuns: [{ name: APPROVE_CHECK_NAME, conclusion: 'failure', status: 'completed' }],
    comments: [sign(55, 'alice'), sign(56, 'bob')],
  });
  const log = fakeLog();
  try {
    const rc = await main(['--pending', pd, '--sha', SHA, '--owner', 'o', '--repo', 'r', '--changed', f, '--report', report], { log, token: 't' });
    assert.equal(rc, 0, '人工路成立时不该返回失败');
    const stamped = JSON.parse(fs.readFileSync(f, 'utf8'));
    assert.match(stamped.audit.by, /^human-approved#o\/rPR7@a{12}\/c55\+c56$/);
    assert.match(stamped.audit.verify, /issues\/comments\/55/);
    const r = JSON.parse(fs.readFileSync(report, 'utf8'));
    assert.equal(r.kind, 'human', '报告要能看出这次是人工放行，不是流水线批的');
    assert.match(log.out.join('\n'), /人工双签/);
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
    assert.match(job, /if: needs\.audit\.outputs\.index_pr == 'true' && needs\.audit\.outputs\.index_derived == 'true'/,
      '两个条件必须同时钉住，且是 && 而不是 ||');
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
    // 两句 warning 说的是两个方向，不许合并成一句：混投稿要人去查投稿，动台账要的是两名成员签。
    assert.ok(yml.includes('这个 PR 动了处置台账'), `${tag}台账那一支要指名「处置是人工判断」`);
    assert.ok(yml.includes('elif [ -n "$CHANGED_JSON" ]; then'), `${tag}混投稿那一支要退成 elif，不许被台账那支吃掉`);
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
const SEAL = { kind: 'revoke', reason: 'test-probe', by: 'https://github.com/SukiSU-Community/modules-repo/issues/33#issuecomment-6104846280', at: '2026-10-17T00:00:00Z', note: '探针处置', id: 'beta' };

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
  { name: 'ledger-add-churn-index', expect: 'false', why: '台账加一条 + 索引只改缩进与键序（复现里走通的那格）',
    pr: ({ put, churn }) => { put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }); churn(); } },
  { name: 'ledger-add-rebuild-index', expect: 'false', why: '台账加一条 + 索引照推导删掉那个模块',
    pr: ({ put }) => {
      put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] });
      put('json/modules.json', { ...INDEX0, modules: INDEX0.modules.filter((m) => m.id !== 'beta') });
    } },
  { name: 'ledger-del-churn-index', expect: 'false', why: '台账删一条（解除封禁）+ 索引只改缩进与键序',
    base: ({ put }) => put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }),
    pr: ({ put, churn }) => { put('json/dispositions.json', LEDGER0); churn(); } },
  { name: 'ledger-only', expect: 'false', why: '只改台账、索引一个字节不动（#35 关掉的那格）',
    pr: ({ put }) => put('json/dispositions.json', { ...LEDGER0, dispositions: [SEAL] }) },
  { name: 'mode-a-consume', expect: 'true', why: '机器人那条：改了索引 + 消费掉 pending，台账不动 ⇒ 必须照旧进机器路由',
    pr: ({ put, rm }) => { put('json/modules.json', { ...INDEX0, modules: [...INDEX0.modules, MOD('alpha', 2)] }); rm('pending/alpha/1.json'); } },
  { name: 'index-only', expect: 'true', why: '手抄一份索引：分类仍是索引 PR，拦它的是下一步 derive，不是这一步',
    pr: ({ put }) => put('json/modules.json', { ...INDEX0, modules: INDEX0.modules.filter((m) => m.id !== 'beta') }) },
  { name: 'submission-plus-index', expect: 'false', found: 'true', why: '投稿 PR 里顺手带索引改动 ⇒ 按扫描结论走',
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
    const gate = code.slice(code.indexOf('上游没过检就没有批准资格'), code.indexOf('只批准「低风险'));
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
    assert.match(code, /git merge --no-commit --no-ff/, `${f} 的闸门二必须是「合并当前 base」`);
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
  assert.equal((code.match(/--dispositions-file "\$DISPOSITIONS_FILE"/g) || []).length, 2,
    '每次重推导都要显式给台账路径：默认值相对 cwd，contrib/repo 布局下会读错文件');
  assert.equal((code.match(/DISPOSITIONS_FILE="\$\{PREFIX:\+\$PREFIX\/\}json\/dispositions\.json"/g) || []).length, 2);
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

test('GOVERNANCE.md 存在，且写的就是当前这套双签判据', () => {
  // 给投稿者看的文案指向这份文件。它一旦和 assertMergeApproved 脱节，
  // 就等于告诉别人一条走不通的官方路径 —— 比没有文档更糟。
  // 下面每个值都从代码里 import，改代码不改文档会直接红。
  assert.ok(fs.existsSync(GOVERNANCE_FILE), 'GOVERNANCE.md 必须存在：报错文案指着它');
  const doc = fs.readFileSync(GOVERNANCE_FILE, 'utf8');

  assert.ok(doc.includes(HUMAN_APPROVAL_MARKER), `文档要写当前的标记 ${HUMAN_APPROVAL_MARKER}`);
  assert.ok(doc.includes(HUMAN_APPROVE_STATUS), `文档要写人工章的状态值 ${HUMAN_APPROVE_STATUS}`);
  assert.equal(REQUIRED_SIGNERS, 2, '文档正文写的是「两个不同的人」，改这个数必须连文档一起改');
  assert.ok(doc.includes('两个不同的人'), '几签要说人话写出来');
  for (const assoc of TRUSTED_ASSOCIATIONS) {
    assert.ok(doc.includes(assoc), `签核资格要列出 ${assoc}（当前白名单：${[...TRUSTED_ASSOCIATIONS].join('/')}）`);
  }
  assert.ok(doc.includes('红着被 bot 合并') || doc.includes('[bot]'),
    '「机器人合的不算人工放行」是这条路成立的前提，文档不能漏');
  assert.match(doc, /gh api repos\/[^\s]+\/issues\/comments\//, '要给出可复制的复验命令');
  assert.match(doc, /不是正式渠道/, '申诉入口要写明哪里不算数');
});

test('审核判红那条给投稿者看的报错，指向的文件和标记都必须是真实的', () => {
  // 这句文案在 shell 里，插值不到 JS 常量，所以只能反过来用 import 的值查文本。
  for (const f of AUDIT_COPIES) {
    const line = fs.readFileSync(f, 'utf8').match(/::error::[^\n]*不满足自动放行条件[^\n]*/);
    assert.ok(line, `${path.basename(f)} 里必须留着那条报错`);
    assert.ok(line[0].includes('GOVERNANCE.md'), '报错指向的必须是治理文档，不是「README/GOVERNANCE.md」这种空位');
    assert.ok(line[0].includes(HUMAN_APPROVAL_MARKER), `报错里教人写的标记必须等于 ${HUMAN_APPROVAL_MARKER}`);
  }
});
