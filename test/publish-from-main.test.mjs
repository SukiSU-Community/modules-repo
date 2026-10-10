// publish-from-main.mjs 的单测 —— 「合并后凭什么算批准」这一段必须有测试，
// 因为它是整个自动放行链上唯一新增的信任点。
// 运行：node --test test/publish-from-main.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  APPROVE_CHECK_NAME,
  checkConclusion,
  assertMergeApproved,
  approvalBy,
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
function stubApi({ pullList, pr, checkRuns }) {
  return stubFetch((url) => {
    if (url.includes('/check-runs')) return { check_runs: checkRuns || [] };
    if (/\/pulls\/\d+$/.test(url)) return pr || null;
    if (/\/pulls$/.test(url)) return { pull_requests: pullList || [] };
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

test('approve 这个 check 名必须真的就是 workflow 里那个 job 的 name', () => {
  // 两处靠字符串相等连接：job 改名 = 悄悄拆掉闸门。这条测试就是那根钉子。
  for (const f of [WF_MAIN, WF_TEMPLATE]) {
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

test('approve 与 publish 的分工：没有待审内容时 approve 让路，但绝不合并', () => {
  // approve 在 found!=true 时也必须成功（否则删除 pending / 改脚本这类维护 PR 会卡在
  // 一个永远不会变绿的 required check 上）。正因如此，publish 不能只看 approve 成功就合，
  // 必须同时钉住 found 与 action —— 少一个条件就是「机器人自动合掉任意 PR」。
  const yml = fs.readFileSync(WF_MAIN, 'utf8');
  assert.match(yml, /found: \$\{\{ steps\.locate\.outputs\.found \}\}/, 'audit 必须把 found 提为 job output');
  assert.match(yml, /if: needs\.audit\.outputs\.found == 'true' && needs\.audit\.outputs\.action == 'auto-approve'/);
});

test('parseArgs：--changed 吃多个路径，且不把下一个 --flag 吞掉', () => {
  const o = parseArgs(['--pending', 'p', '--changed', 'a.json', 'b.json', '--dry-run']);
  assert.deepEqual(o.changed.map((p) => path.basename(p)), ['a.json', 'b.json']);
  assert.equal(o['dry-run'], true);
  assert.equal(o.pending, 'p');
});
