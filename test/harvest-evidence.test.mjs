/**
 * harvest-evidence.mjs 的单测 —— §8 证据固化。
 * 运行：node --test test/harvest-evidence.test.mjs
 *
 * 锁的四件事：
 *   1. 文件名 = 它自己字节的 SHA-256，于是「同一个包固化两次」必须落回同一个名字；
 *   2. 来源读的是 **git 历史里的 blob**，不是工作树（合并时 pending/** 会被 --consume 删掉）；
 *   3. 审核评论的解析扛得住「静态块里自己带围栏」与「模型自由文本里带三个反引号」；
 *   4. 与 revoke.mjs 的接合：固化成功才带 subject/evidence，失败就退回不带且不写指针。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

import {
  EVIDENCE_SCHEMA, EVIDENCE_DIR, AUDIT_COMMENT_HEAD,
  canonicalBytes, evidencePathFor, sha256Hex, prFromCommitSubject, matchesSelectors,
  parseAuditComment, findPendingCommits, readBlob, whyNoEvidence, buildEvidence,
  harvest, ledgerFieldsFrom,
} from '../scripts/harvest-evidence.mjs';
import { EVIDENCE_FILE_RE, DISPOSITIONS_SCHEMA, parseDispositions } from '../scripts/dispositions.mjs';
import * as verifyMod from '../scripts/verify-index-pr.mjs';

const G = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });
const SHA = (c) => c.repeat(64);

/* ------------------------------------------------------------------ 纯函数 */

test('prFromCommitSubject：squash 与 merge 两种真实形状都认，认不出就 null（不猜）', () => {
  assert.equal(prFromCommitSubject('pending: e2e_probe_p04 7301872 (#30)'), 30);
  assert.equal(prFromCommitSubject('Merge pull request #27 from x/y'), 27);
  assert.equal(prFromCommitSubject('pending: e2e_probe_min 330580'), null, '分支上没合过的提交没有 PR 号');
  assert.equal(prFromCommitSubject('refactor: 把 (#12) 写进正文里 (#99)'), 99, '只认结尾那一个');
});

test('matchesSelectors：id / id+versionCode / sha256 / uid 四条路，以及各自的反例', () => {
  const rec = { id: 'mod_a', coolapkUid: '10086001', versions: [{ versionCode: 7, sha256: SHA('a') }] };
  assert.equal(matchesSelectors(rec, { id: 'mod_a' }), true);
  assert.equal(matchesSelectors(rec, { id: 'mod_a', versionCode: 7 }), true);
  assert.equal(matchesSelectors(rec, { id: 'mod_a', versionCode: 8 }), false, '指到版本就不是这一条');
  assert.equal(matchesSelectors(rec, { id: 'mod_b' }), false);
  assert.equal(matchesSelectors(rec, { sha256: SHA('A').toLowerCase() }), true, '哈希按不区分大小写比');
  assert.equal(matchesSelectors(rec, { sha256: SHA('b') }), false);
  assert.equal(matchesSelectors(rec, { coolapkUid: '10086001' }), true);
  assert.equal(matchesSelectors(rec, { coolapkUid: '10086002' }), false);
  assert.equal(matchesSelectors(null, { id: 'mod_a' }), false, '读不出来的记录不能算命中');
  assert.equal(matchesSelectors(rec, {}), false, '空选择器什么都不匹配');
});

/** 真评论的形状（线上 PR #47 那条的骨架）：静态块里自己带 ```sh 围栏。 */
function realShapedComment(pkg = 'mod_a-1.zip') {
  return `${AUDIT_COMMENT_HEAD}

- 风险等级：**HIGH**

### 逐包呈现（1 包：每包一块静态报告 + 一块 AI 安全员产物）

<details><summary>静态报告 · ${pkg}</summary>

### \`customize.sh\` — 134 B / 5 行

\`\`\`sh
su -c 'echo hi'
\`\`\`

</details>

<details><summary>AI 安全员 · ${pkg}</summary>

\`\`\`json
{
  "status": "ok",
  "agree": false,
  "risk": "high",
  "findings": [{ "file": "${pkg}", "line": 3 }]
}
\`\`\`

</details>
`;
}

test('parseAuditComment：静态块里的嵌套围栏不干扰，AI 的 json 解析出来', () => {
  const body = realShapedComment();
  const pkgs = parseAuditComment(body);
  assert.equal(pkgs.length, 1);
  const p = pkgs[0];
  assert.equal(p.name, 'mod_a-1.zip');
  assert.ok(p.staticMarkdown.includes('```sh'), '静态块逐字留着，包括它自己的围栏');
  // 整段都要在：从第一个小标题到围栏之后。按「数围栏」切的那一版会把围栏**之前**的半截整块丢掉，
  // 而只断言 includes('```sh') 看不出这一刀 —— 2026-10-17 的 M7 变异就是这么全绿的。
  assert.ok(p.staticMarkdown.startsWith('### `customize.sh`'), `静态段开头被切掉了：${JSON.stringify(p.staticMarkdown.slice(0, 40))}`);
  assert.ok(p.staticMarkdown.includes("su -c 'echo hi'"), '围栏里的内容也要在，那才是被处置的那一行的原文');
  assert.equal(p.aiParseFailed, false, `AI 块解析失败：${JSON.stringify(p.aiRaw.slice(0, 60))}`);
  assert.deepEqual(Object.keys(p.ai), ['status', 'agree', 'risk', 'findings']);
  assert.equal(p.ai.findings[0].line, 3);
});

test('parseAuditComment：模型文本里行中出现三个反引号不影响解析，围栏没闭合才算读不出来', () => {
  const inline = `${AUDIT_COMMENT_HEAD}

<details><summary>AI 安全员 · x.zip</summary>

\`\`\`json
{
  "reasons": "它写了 \`\`\` 这一段",
  "risk": "high"
}
\`\`\`

</details>
`;
  const p = parseAuditComment(inline)[0];
  assert.equal(p.aiParseFailed, false);
  assert.equal(p.ai.risk, 'high');
  assert.match(p.ai.reasons, /```/, '反引号原样留着：中和它是显示面的事，不是取证面的');

  // audit.yml 那一发会把超长 JSON 直接切半截（AI_MAX），所以「有开栏没有闭栏」是线上真会有的形状。
  const truncated = `${AUDIT_COMMENT_HEAD}

<details><summary>AI 安全员 · x.zip</summary>

\`\`\`json
{
  "reasons": "被 12000 字符上限切掉
</details>
`;
  const t = parseAuditComment(truncated)[0];
  assert.equal(t.ai, null, '不许去猜一个能过的跨度');
  assert.equal(t.aiParseFailed, true);
  assert.match(t.aiRaw, /被 12000 字符上限切掉/, '原文照留 —— 读不出来不等于什么都没发生');
});

test('parseAuditComment：没有 json 围栏 / 围栏没闭合 → aiParseFailed，原文照留', () => {
  const noFence = `${AUDIT_COMMENT_HEAD}\n\n<details><summary>AI 安全员 · x.zip</summary>\n\n本轮没有 AI 产物。\n\n</details>\n`;
  const p1 = parseAuditComment(noFence)[0];
  assert.equal(p1.ai, null);
  assert.equal(p1.aiParseFailed, true);
  assert.match(p1.aiRaw, /本轮没有 AI 产物/);
});

test('EVIDENCE_DIR 与文件名正则和两处权威实现同值（跨文件漂移的钉子）', () => {
  // 白名单那份带尾斜杠（它拿去做 startsWith），这边是路径段 —— 差的那一斜杠就是两处的全部区别。
  assert.equal(`${EVIDENCE_DIR}/`, verifyMod.EVIDENCE_DIR, '固化的目录必须就是白名单认的那个');
  const bytes = canonicalBytes({ schema: EVIDENCE_SCHEMA });
  const rel = evidencePathFor(bytes);
  assert.match(rel, EVIDENCE_FILE_RE, `产出的文件名必须过台账那条正则：${rel}`);
  assert.equal(rel, `${EVIDENCE_DIR}/${sha256Hex(bytes)}.json`);
});

/* ------------------------------------------------------------ git 夹具 */

function gitFixture({ withAuditComment = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'harvest-git-'));
  G(dir, 'init', '-q', '-b', 'main');
  G(dir, 'config', 'user.name', 't');
  G(dir, 'config', 'user.email', 't@example.invalid');
  fs.mkdirSync(path.join(dir, 'pending', 'mod_a'), { recursive: true });
  const rec = {
    id: 'mod_a', name: 'Mod A', author: 'a', description: 'd',
    versions: [{ version: 'v1', versionCode: 7, zipUrl: 'https://x/y.zip', size: 10, time: 1, sha256: SHA('a') }],
    source: 'https://www.coolapk.com/feed/1', uploader: 'a', coolapkUid: '10086001',
    pledge: { version: 'p1', atMs: 1 },
    ownership: { nonce: 'n1', proofPrefix: 'p', via: 'bio', verifiedAt: 1 },
    identity: { nickname: '昵称一', uid: '10086001' },
    storage: 'github-release-asset', releaseTag: 'assets-v1', assetName: `${SHA('a')}.zip`,
    submittedAt: '2026-10-11T00:00:00.000Z',
  };
  fs.writeFileSync(path.join(dir, 'pending', 'mod_a', '7.json'), JSON.stringify(rec, null, 2) + '\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'pending: mod_a 7 (#7)');
  // 复刻合并时发生的事：--consume 把 pending/** 从工作树删掉，只留在历史里。
  fs.rmSync(path.join(dir, 'pending'), { recursive: true, force: true });
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'chore(index): rebuild after merge [skip ci]');
  const comments = withAuditComment
    ? [{ id: 5001, html_url: 'https://github.com/o/r/pull/7#issuecomment-5001', body: realShapedComment('y.zip') }]
    : [];
  return { dir, rec, comments };
}

const gitDeps = (dir, comments, extra = {}) => ({
  git: (d, args) => G(dir, ...args),
  ownerRepo: 'o/r',
  fetchComments: async () => comments,
  ...extra,
});

test('findPendingCommits + readBlob：文件已不在工作树，仍然从历史里捞出来', () => {
  const { dir } = gitFixture();
  const rows = findPendingCommits((d, args) => G(dir, ...args), dir);
  assert.deepEqual(rows.map((r) => r.filePath), ['pending/mod_a/7.json']);
  assert.equal(rows[0].commitSubject, 'pending: mod_a 7 (#7)');
  const blob = readBlob((d, args) => G(dir, ...args), dir, rows[0].commitSha, rows[0].filePath);
  assert.equal(JSON.parse(blob).id, 'mod_a');
  assert.equal(fs.existsSync(path.join(dir, 'pending', 'mod_a', '7.json')), false,
    '夹具前提：这条记录在工作树里已经不存在');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('harvest：命中一条 pending + 一条审核评论 ⇒ 一份证据，pr/report/subject 都齐', async () => {
  const { dir, comments } = gitFixture();
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a', versionCode: 7 }, deps: gitDeps(dir, comments) });
  assert.equal(h.ok, true, h.whyEmpty);
  assert.equal(h.files.length, 1);
  const e = h.files[0].evidence;
  assert.equal(e.schema, EVIDENCE_SCHEMA);
  assert.equal(e.pending.path, 'pending/mod_a/7.json');
  assert.equal(e.pending.record.id, 'mod_a', 'pending 原文逐字进证据，不做二次脱敏');
  assert.equal(e.pr.number, 7);
  assert.equal(e.pr.url, 'https://github.com/o/r/pull/7');
  assert.equal(e.report.commentId, 5001);
  assert.equal(e.report.packages.length, 1);
  assert.equal(e.package.sha256, SHA('a'));
  assert.deepEqual(e.subject, { coolapkUid: '10086001', username: '昵称一' });
  assert.ok(!('capturedAt' in e), '证据文件里不许有时间戳：那会让文件名每次跑都变');
  assert.ok(!('matchedBy' in e), '也不许记「这次用哪套选择器命中的」：同一份内容会有两个哈希');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('harvest 幂等：换 now、换选择器路线，文件名字节级一致', async () => {
  const { dir, comments } = gitFixture();
  const a = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: gitDeps(dir, comments) });
  const b = await harvest({ cwd: dir, selectors: { id: 'mod_a', versionCode: 7 }, deps: gitDeps(dir, comments) });
  const c = await harvest({ cwd: dir, selectors: { sha256: SHA('a') }, deps: gitDeps(dir, comments) });
  assert.equal(a.files[0].path, b.files[0].path);
  assert.equal(a.files[0].path, c.files[0].path, `三条选择器路线给出三个名字：${[a, b, c].map((x) => x.files[0].path).join(' / ')}`);
  assert.ok(Buffer.compare(a.files[0].bytes, c.files[0].bytes) === 0);
  assert.equal(path.basename(a.files[0].path, '.json'), sha256Hex(a.files[0].bytes), '文件名 = 字节的 sha256');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('harvest：没有审核评论时 report 为 null 且说清原因，pending 那一份照样固化', async () => {
  const { dir } = gitFixture({ withAuditComment: false });
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: gitDeps(dir, []) });
  assert.equal(h.ok, true);
  const e = h.files[0].evidence;
  assert.equal(e.report, null);
  assert.match(e.reportWhy, /PR #7 的评论里没有/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('harvest：取评论抛错时只把稳定那句写进证据（报错原文会让文件名抖）', async () => {
  const { dir } = gitFixture();
  const deps = gitDeps(dir, [], { fetchComments: async () => { throw new Error('HTTP 403'); } });
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps });
  assert.match(h.files[0].evidence.reportWhy, /取不到 PR #7 的评论：HTTP 403/);
  const deps2 = gitDeps(dir, [], { fetchComments: async () => { throw new Error('HTTP 403 rate limited'); } });
  const h2 = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: deps2 });
  assert.equal(h.files[0].path, h2.files[0].path, '同一种失败必须落回同一个文件名');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('whyNoEvidence：三种「没固化到」分开说，不并成一句「没有命中」', () => {
  assert.match(whyNoEvidence(0, 0, { id: 'x' }), /这个克隆没有投稿历史，不是选择器不对/);
  assert.match(whyNoEvidence(6, 0, { id: 'x' }), /6 条 pending 提交里没有一条命中/);
  assert.match(whyNoEvidence(6, 6, { id: 'x' }), /6 条 pending 提交全部读不出来/);
  assert.match(whyNoEvidence(6, 2, { id: 'x' }), /另有 2 条 blob 读不出来被跳过/);
});

test('harvest：没有 main 这个引用时报原话，不退化成「没有命中」', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'harvest-nomain-'));
  const deps = {
    git: () => { throw new Error("fatal: ambiguous argument 'main': unknown revision or path not in the working tree."); },
    ownerRepo: 'o/r',
    fetchComments: async () => [],
  };
  await assert.rejects(() => harvest({ cwd: dir, selectors: { id: 'x' }, deps }), /读不到本地 main/);
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ------------------------------------------------- ledgerFieldsFrom 与 revoke 接合 */

test('ledgerFieldsFrom：evidence[].at 挂在台账那一侧，且过的了台账自己的校验', async () => {
  const { dir, comments } = gitFixture();
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: gitDeps(dir, comments) });
  const fields = ledgerFieldsFrom(h, new Date('2026-10-17T00:00:00Z'));
  assert.deepEqual(Object.keys(fields.evidence[0]), ['file', 'pr', 'at']);
  assert.equal(fields.evidence[0].at, '2026-10-17T00:00:00.000Z');
  const parsed = parseDispositions({
    schema: DISPOSITIONS_SCHEMA,
    dispositions: [{ kind: 'revoke', reason: 'malware', by: 'https://github.com/o/r/issues/3#issuecomment-1', at: '2026-10-17T00:00:00.000Z', id: 'mod_a', coolapkUid: '10086001', ...fields }],
  }, 't');
  assert.deepEqual(parsed[0].subject, { coolapkUid: '10086001', username: '昵称一' });
  assert.equal(parsed[0].evidence.length, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ledgerFieldsFrom：几份证据指向不同的人时不带 subject', () => {
  const mk = (uid) => ({ path: `evidence/${SHA(uid[0])}.json`, evidence: { pr: { number: 3 }, subject: { coolapkUid: uid, username: 'n' } } });
  const one = ledgerFieldsFrom({ ok: true, files: [mk('10086001')] }, new Date('2026-10-17T00:00:00Z'));
  assert.deepEqual(one.subject, { coolapkUid: '10086001', username: 'n' });
  const two = ledgerFieldsFrom({ ok: true, files: [mk('10086001'), mk('10086002')] }, new Date('2026-10-17T00:00:00Z'));
  assert.equal('subject' in two, false, '一条记录只能挂一个人，硬取第一份等于把另一个人也算进去');
  assert.equal(two.evidence.length, 2);
});

const quiet = () => {
  const out = [];
  return { out, log: (...a) => out.push(a.join(' ')), error: (...a) => out.push('! ' + a.join(' ')) };
};

/**
 * revoke.mjs 的写入端只认机器章：`--by` 必须是 `ci:audit@<40 位小写十六进制的 head commit sha>`
 * （或第一枚提交用的 `ci:audit@pending`）。人工双签已取消，旧的评论 URL 现在直接被
 * buildDisposition 拒收（退出码 2）—— 那正是「已删的机制不许被数据复活」的形状。
 * 下面三条接合用例要的是固化那几步的退出码，所以 `--by` 一律给章的形状。
 */
const SEAL_BY = `ci:audit@${'ab'.repeat(20)}`;

test('revoke 接合：固化成功 ⇒ 台账条目带 subject/evidence，证据文件真落盘', async () => {
  const { dir, comments } = gitFixture();
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: gitDeps(dir, comments) });
  const s = revokeSandbox(dir);
  const io = quiet();
  const rc = await revokeMain(['--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath,
    '--evidence-dir', dir,
    '--id', 'mod_a', '--kind', 'revoke', '--reason', 'malware', '--by', SEAL_BY],
  io, { harvest: async () => h, now: () => new Date('2026-10-17T00:00:00Z') });
  assert.equal(rc, 0, io.out.concat(io.err).join('\n'));
  const ledger = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8'));
  const entry = ledger.dispositions[0];
  assert.equal(entry.by, SEAL_BY, '落进台账的 by 就是那枚机器章，写入端不改形状');
  assert.equal(entry.subject.coolapkUid, '10086001');
  assert.equal(entry.evidence[0].file, h.files[0].path);
  const written = path.join(dir, ...h.files[0].path.split('/'));
  assert.ok(fs.existsSync(written), '证据文件必须与台账同批落盘，否则 PR 会红在互指认那一步');
  assert.ok(io.out.some((l) => String(l).includes('evidence/')), '下一步的 git add 要把 evidence/ 带上');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('revoke 接合：固化没东西 ⇒ 条目不带那两个键，并打出一句怎么补', async () => {
  const s = revokeSandbox();
  const io = quiet();
  const rc = await revokeMain(['--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath,
    '--id', 'mod_a', '--kind', 'revoke', '--reason', 'malware', '--by', SEAL_BY],
  io, { harvest: async () => ({ ok: false, files: [], notes: [], scanned: 3, whyEmpty: '3 条 pending 提交里没有一条命中' }) });
  assert.equal(rc, 0);
  const entry = JSON.parse(fs.readFileSync(s.ledgerPath, 'utf8')).dispositions[0];
  assert.equal('evidence' in entry, false, '没有证据就退回不带这个键 —— 写一个指空文件的指针会被互指认判红');
  assert.equal('subject' in entry, false);
  assert.ok(io.out.filter((l) => String(l).includes('harvest-evidence.mjs')).length > 0, '要给出事后补跑的那条命令');
});

test('revoke 接合：同名不同物的证据文件绝不覆盖，停下来问人', async () => {
  const { dir, comments } = gitFixture();
  const h = await harvest({ cwd: dir, selectors: { id: 'mod_a' }, deps: gitDeps(dir, comments) });
  const abs = path.join(dir, ...h.files[0].path.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, Buffer.from('有人改过的一份内容\n'));
  const s = revokeSandbox(dir);
  const io = quiet();
  const rc = await revokeMain(['--ledger', s.ledgerPath, '--index', s.indexPath, '--pending', s.pendingPath,
    '--evidence-dir', dir,
    '--id', 'mod_a', '--kind', 'revoke', '--reason', 'malware', '--by', SEAL_BY],
  io, { harvest: async () => h, now: () => new Date('2026-10-17T00:00:00Z') });
  assert.equal(rc, 6, '内容哈希撞车只有一种解释：证据被人改过');
  assert.equal(fs.readFileSync(abs, 'utf8'), '有人改过的一份内容\n', '不许覆盖');
  assert.equal(fs.existsSync(s.ledgerPath), false, '台账一个字都不该写 —— 半套状态比不写更糟');
  fs.rmSync(dir, { recursive: true, force: true });
});

/* 把 revoke.mjs 装进临时目录：它的 ROOT 是脚本所在目录，所以夹具放在那个目录下。 */
let revokeMod = null;
async function loadRevoke() {
  if (!revokeMod) revokeMod = await import('../scripts/revoke.mjs');
  return revokeMod;
}
async function revokeMain(argv, io, deps) {
  const m = await loadRevoke();
  return m.main(argv, io, deps);
}
function revokeSandbox(dir = null) {
  const base = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'revoke-harvest-'));
  fs.mkdirSync(path.join(base, 'json'), { recursive: true });
  fs.mkdirSync(path.join(base, 'pending'), { recursive: true });
  const indexPath = path.join(base, 'json', 'modules.json');
  fs.writeFileSync(indexPath, JSON.stringify({ name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] }, null, 2) + '\n');
  return { indexPath, ledgerPath: path.join(base, 'json', 'dispositions.json'), pendingPath: path.join(base, 'pending') };
}
