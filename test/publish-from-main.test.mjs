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
function stubApi({ pullList, pr, checkRuns }) {
  return stubFetch((url) => {
    if (url.includes('/check-runs')) return { check_runs: checkRuns || [] };
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
  assert.match(yml, /gh pr merge[^\n]*--squash/);
  // 不再 push，就不该再揣着 contents:write
  assert.match(yml, /contents: read/);
  // 消费掉的 pending 是删除，不能交给盖章脚本去读
  assert.match(yml, /diff-tree[\s\S]{0,80}--diff-filter=ACMR/);
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
