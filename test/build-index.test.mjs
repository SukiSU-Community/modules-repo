import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildIndex, normalizeEntry, isApproved,
  collectPendingFiles, markApproved, parseArgs, main, coolapkSourceUrl,
  applyRepoState, normalizeRepoUrl, normalizeUpdateJson,
  APPROVAL_FIELD, APPROVED_STATUS, APPROVED_STATUSES,
} from '../scripts/build-index.mjs';
import { validateIndex } from '../scripts/validate-index.mjs';

const sha = (n) => n.toString(16).padStart(64, '0');

/**
 * 造一个最小合法 pending 条目。
 *
 * `approved: true|false` 只是这里方便写字面量：**出桩时一律翻译成契约字段 `audit`**。
 * 夹具以前是直接发 `{ approved: true }` 的，而那种快捷写法本身就是被 isApproved
 * 关掉的那条后门 —— 夹具继续用它，等于所有测试都在测一条早晚会堵上的路。
 * 需要显式测后门行为的用例，自己手写那个字段，别走这里。
 */
function entry(over = {}) {
  const { approved = true, ...rest } = over;
  return {
    id: 'demo_mod',
    name: 'Demo',
    author: 'tester',
    description: 'demo module',
    // 契约 §1：`source` 与 `repoUrl` 至少要有其中一个，两个都没有的条目直接 invalid。
    // 夹具默认给一条酷安链接，免得每个用例都得为「让条目合法」写一行与断言无关的东西；
    // 要测「没有出处」的用例自己显式盖掉（那种条目现在会被拒，见对应用例的注释）。
    source: 'https://www.coolapk.com/feed/1',
    audit: {
      status: approved ? APPROVED_STATUS : 'needs-human-review',
      by: 'test:ci',
      at: '2026-01-01T00:00:00.000Z',
      risk: 'low',
    },
    versions: [
      {
        version: 'v1.0.0',
        versionCode: 100,
        zipUrl: 'https://example.com/a.zip',
        size: 1024,
        time: 1700000000000,
        sha256: sha(1),
      },
    ],
    ...rest,
  };
}

const emptyIndex = { name: 'SukiSU-Ultra Modules', lastUpdate: 0, modules: [] };

test('情况一：新增模块', () => {
  const { index, conflicts, stats } = buildIndex({ index: emptyIndex, entries: [entry()] });

  assert.equal(index.modules.length, 1);
  assert.equal(index.modules[0].id, 'demo_mod');
  assert.equal(index.modules[0].versions.length, 1);
  assert.equal(index.modules[0].verified, false, '自动放行的条目 verified 必须是 false');
  assert.equal(conflicts.length, 0);
  assert.equal(stats.addedModules, 1);
  assert.equal(stats.addedVersions, 1);
  // 合并结果本身要能过校验器
  assert.equal(validateIndex(index).ok, true);
});

test('情况二：追加版本（同 id、新 versionCode）', () => {
  const first = buildIndex({ index: emptyIndex, entries: [entry()] }).index;
  const v2 = {
    version: 'v2.0.0',
    versionCode: 200,
    zipUrl: 'https://example.com/b.zip',
    size: 2048,
    time: 1700000001000,
    sha256: sha(2),
  };
  const { index, conflicts, stats } = buildIndex({
    index: first,
    entries: [entry({ versions: [v2] })],
  });

  assert.equal(index.modules.length, 1, '不能新增重复模块');
  assert.equal(index.modules[0].versions.length, 2);
  assert.equal(stats.addedModules, 0);
  assert.equal(stats.addedVersions, 1);
  assert.equal(conflicts.length, 0);
  // 版本按 versionCode 降序，最新版在前
  assert.deepEqual(
    index.modules[0].versions.map((v) => v.versionCode),
    [200, 100],
  );
});

test('情况三：id 冲突且 sha256 不同时不覆盖', () => {
  const first = buildIndex({ index: emptyIndex, entries: [entry()] }).index;
  const conflicting = entry({
    versions: [
      {
        version: 'v1.0.0',
        versionCode: 100,
        zipUrl: 'https://evil.example.com/tampered.zip',
        size: 9999,
        time: 1700000002000,
        sha256: sha(0xdead),
      },
    ],
  });

  const { index, conflicts, stats } = buildIndex({ index: first, entries: [conflicting] });

  // 已存在的版本原封不动
  const v = index.modules[0].versions.find((x) => x.versionCode === 100);
  assert.equal(v.sha256, sha(1), '已有版本绝不能被覆盖');
  assert.equal(v.zipUrl, 'https://example.com/a.zip');
  assert.equal(v.size, 1024);

  assert.equal(stats.conflicts, 1);
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].type, 'version-conflict');
  assert.equal(conflicts[0].id, 'demo_mod');
  assert.equal(conflicts[0].existingSha256, sha(1));
  assert.equal(conflicts[0].incomingSha256, sha(0xdead));
});

test('补充：未通过审核的条目被忽略，且手写的快捷写法不再算通过', () => {
  const { index, stats } = buildIndex({
    index: emptyIndex,
    entries: [entry({ approved: false }), entry({ id: 'x' })],
  });
  assert.equal(index.modules.length, 1);
  assert.equal(index.modules[0].id, 'x');
  assert.equal(stats.skipped, 1);

  // 这两条以前都会被 isApproved 认下来 —— 等于任何人手加一个字段就能绕过 CI 盖章
  // 把包送进索引，「版本更新一律人工审核」这条防线会被整个作废。
  assert.equal(isApproved({ approved: true }), false, '手写 approved:true 不该算通过');
  assert.equal(isApproved({ review: { approved: true } }), false, '手写 review.approved 不该算通过');
  // 有章但没署名：追责链回答不了「谁批的」，与没有章等价
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: APPROVED_STATUS } }), false, '无主章不该算通过');
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: APPROVED_STATUS, by: '   ' } }), false);
  // 人工放行那一档（`human-approved`）已随「本站只有机器审核」删掉：走同一个字段、
  // 同样署名的旧章，现在一律不算通过。它的失效方向见下面那条专门钉它的用例。
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: 'human-approved', by: 'gh:yufeng-liang@1234' } }), false,
    'human-approved 已经不是放行状态');
});

test('人工档已删：残留的 human-approved 章按「没批准」处理，不进索引（fail-closed 方向）', () => {
  // 这一条钉的是删代码那一步的**读取侧后果**：main 上若还躺着一枚 2026-10-21 之前盖的
  // `human-approved` 章，它必须退化成「没有章」，而不是继续生效。方向要说清 ——
  // 保守 = 不放行；反过来（继续认它）等于用一条已经不存在的授权路径把包送进索引。
  assert.deepEqual(APPROVED_STATUSES, [APPROVED_STATUS], '放行状态只有一个，不许有第二档');
  const stale = entry({
    audit: { status: 'human-approved', by: 'gh:yufeng-liang@1234', at: '2026-10-18T00:00:00.000Z', risk: 'low' },
  });
  assert.equal(isApproved(stale), false);
  const { index, stats } = buildIndex({ index: emptyIndex, entries: [stale] });
  assert.equal(index.modules.length, 0, '那一条不该进索引');
  assert.equal(stats.approved, 0, '不该算「通过审核」');
  assert.equal(stats.skipped, 1, '要计成 skipped —— 否则「什么都没发生」看不出来');

  // 反面控制：同一份夹具换成机器章就必须放行。少了这一句，上面四条在
  // 「isApproved 永远返回 false」的变异下也会全绿（那就是空跑）。
  const ci = entry();
  assert.equal(isApproved(ci), true);
  assert.equal(buildIndex({ index: emptyIndex, entries: [ci] }).index.modules.length, 1);
});

test('补充：zipUrl 为空的条目被判非法，不写进索引', () => {
  const bad = entry();
  bad.versions[0].zipUrl = '';
  const { index, stats, conflicts } = buildIndex({ index: emptyIndex, entries: [bad] });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.invalid, 1);
  assert.match(conflicts[0].reason, /zipUrl/);
  assert.equal(normalizeEntry(bad).ok, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// 断点 ② 回归：pending 必须递归遍历，且 CI 写的 audit.status 必须被认
// ─────────────────────────────────────────────────────────────────────────────

function tmpPending(layout) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pending-'));
  for (const [rel, obj] of Object.entries(layout)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, JSON.stringify(obj, null, 2));
  }
  return dir;
}

test('回归 ②：递归读到 pending/<id>/<versionCode>.json（Worker 的实际写法）', () => {
  const dir = tmpPending({
    'demo_mod/100.json': entry({ approved: false }),
    '.example.json': { id: 'ignored', approved: true, versions: [] },
  });
  try {
    const files = collectPendingFiles(dir);
    // 以 . 开头的模板文件不参与合并，嵌套的必须被读到
    assert.equal(files.length, 1, '只应有 1 个参与合并的 pending 文件');
    assert.equal(files[0].rel.replace(/\\/g, '/'), 'demo_mod/100.json');
    assert.equal(files[0].entries[0].id, 'demo_mod');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('回归 ②：非递归的 readdirSync 读不到嵌套路径（修复前的断点复现）', () => {
  const dir = tmpPending({ 'demo_mod/100.json': entry() });
  try {
    const flat = fs.readdirSync(dir)
      .filter((f) => f.toLowerCase().endsWith('.json') && !f.startsWith('.'));
    assert.equal(flat.length, 0, '平铺遍历确实读不到嵌套条目 —— 这就是修复前的症状');
    assert.equal(collectPendingFiles(dir).length, 1, '递归遍历能读到');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 断点 ③ 回归：module.prop 缺 author / description / version 也必须进索引
//
// 背景：KernelSU 只强制 module.prop 有 id/name/version/versionCode，作者字段缺失
// 在真实模块里极其常见；App 端 ModuleProp 给空串、Worker 原样透传，到 build-index
// 这里就是空串。修复前 normalizeEntry 要求这些字段全部非空，于是投稿者的 PR 被
// 合并了、CI 也放行了，模块却永远进不了索引 —— 而且索引里空空如也、PR 上没有任何
// 解释（stats.invalid=1 但 stats.conflicts=0，main() 照样 exit 2）。
// ─────────────────────────────────────────────────────────────────────────────

test('回归 ③：module.prop 缺 author 也要进索引（最典型的真实场景）', () => {
  // 复刻真实链路：App 对缺失字段给空串，Worker 原样透传，投稿者署名在 uploader
  const raw = entry({ author: '', uploader: 'alice' });
  const { index, stats, fallbacks, conflicts } = buildIndex({ index: emptyIndex, entries: [raw] });

  assert.equal(index.modules.length, 1, '缺 author 绝不能再被拒收');
  assert.equal(index.modules[0].author, 'alice', 'author 应回落到投稿者 uploader');
  assert.equal(index.modules[0].author.trim().length > 0, true);
  assert.equal(stats.invalid, 0);
  assert.equal(conflicts.length, 0);
  assert.equal(fallbacks.length, 1);
  assert.deepEqual(fallbacks[0].fallbacks, [{ field: 'author', from: 'uploader', to: 'alice' }]);
  assert.equal(validateIndex(index).ok, true, '兜底后的索引必须通过校验器');
});

test('回归 ③：author 与 uploader 都缺时回落到 unknown，仍然进索引', () => {
  const raw = entry({ author: '   ' });
  const { index, stats } = buildIndex({ index: emptyIndex, entries: [raw] });
  assert.equal(index.modules.length, 1);
  assert.equal(index.modules[0].author, 'unknown');
  assert.equal(stats.invalid, 0);
  assert.equal(validateIndex(index).ok, true);
});

test('回归 ③：缺 description 也要进索引', () => {
  const raw = entry({ description: '' });
  const { index, stats, fallbacks, conflicts } = buildIndex({ index: emptyIndex, entries: [raw] });

  assert.equal(index.modules.length, 1, '缺 description 绝不能再被拒收');
  const m = index.modules[0];
  assert.equal(m.description, 'Demo v1.0.0', 'description 应回落到 "<name> <version>"');
  assert.equal(stats.invalid, 0);
  assert.equal(conflicts.length, 0);
  assert.equal(fallbacks[0].fallbacks[0].field, 'description');
  assert.equal(validateIndex(index).ok, true);
});

test('回归 ③：缺 version 也要进索引（回落到 v<versionCode>）', () => {
  const raw = entry();
  raw.versions[0].version = '';
  const { index, stats, fallbacks, conflicts } = buildIndex({ index: emptyIndex, entries: [raw] });

  assert.equal(index.modules.length, 1, '缺 version 绝不能再被拒收');
  assert.equal(index.modules[0].versions[0].version, 'v100', 'version 应回落到 v<versionCode>');
  assert.equal(stats.invalid, 0);
  assert.equal(conflicts.length, 0);
  assert.deepEqual(fallbacks[0].fallbacks[0], {
    field: 'version', from: 'versionCode=100', to: 'v100',
  });
  assert.equal(validateIndex(index).ok, true);
});

test('回归 ③：author / description / version 三者全缺也要进索引（复核脚本的原始场景）', () => {
  const raw = entry({ author: '', description: '', uploader: 'bob' });
  raw.versions[0].version = '';
  const { index, stats, fallbacks, conflicts } = buildIndex({ index: emptyIndex, entries: [raw] });

  assert.equal(index.modules.length, 1);
  const m = index.modules[0];
  assert.equal(m.author, 'bob');
  assert.equal(m.description, 'Demo v100', 'description 用兜底出来的 version 拼');
  assert.equal(m.versions[0].version, 'v100');
  assert.equal(stats.invalid, 0);
  assert.equal(stats.fallbacks, 3);
  assert.equal(conflicts.length, 0, '兜底不该产生任何冲突/冲突文件');
  assert.equal(validateIndex(index).ok, true);
});

test('回归 ③：兜底后的字段要能过 validate-index 的非空检查', () => {
  // 直接单测 normalizeEntry，确认每个字段都非空字符串
  const n = normalizeEntry(entry({ author: '', description: '', uploader: 'carol' }));
  assert.equal(n.ok, true);
  for (const f of ['id', 'name', 'author', 'description']) {
    assert.equal(typeof n.entry[f], 'string');
    assert.equal(n.entry[f].trim().length > 0, true, `${f} 兜底后仍不能为空`);
  }
  for (const v of n.entry.versions) assert.equal(v.version.trim().length > 0, true);
});

test('回归 ③：仍然拒绝真正非法的条目（sha256 不合法）', () => {
  // 兜底不是「什么都收」：sha256 / zipUrl 这类硬伤依旧拒收
  const raw = entry();
  raw.versions[0].sha256 = 'not-hex';
  const { index, stats, conflicts } = buildIndex({ index: emptyIndex, entries: [raw] });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.invalid, 1);
  assert.match(conflicts[0].reason, /sha256/);
});

test('回归 ③：非法条目必须计入 conflicts（修复前 invalid>0 却 conflicts=0）', () => {
  const bad = entry();
  bad.versions[0].zipUrl = '';
  const { stats, conflicts } = buildIndex({ index: emptyIndex, entries: [bad] });
  assert.equal(stats.invalid, 1);
  assert.equal(stats.conflicts, 1, 'invalid 与 conflicts 不能自相矛盾：exit 2 必须有对得上的计数');
  assert.equal(conflicts.length, 1);
});

test('回归 ③：仍然拒绝没有 id 的条目（无 id 无法归并，兜底无意义）', () => {
  const raw = entry({ id: '' });
  const n = normalizeEntry(raw);
  assert.equal(n.ok, false);
  assert.match(n.error, /id/);
});

test('回归 ②：CI 写的 audit.status=auto-approved 必须被 isApproved 认下', () => {
  // Worker 写出的原始 pending 没有 approved 字段
  const raw = {
    id: 'demo_mod', name: 'Demo', author: 'tester', description: 'd',
    source: 'https://www.coolapk.com/feed/1',
    versions: [{
      version: 'v1.0.0', versionCode: 100, zipUrl: 'https://example.com/a.zip',
      size: 1024, time: 1700000000000, sha256: sha(1),
    }],
    storage: 'github-release-asset',
  };
  assert.equal(isApproved(raw), false, '未盖章时不放行');

  const stamped = markApproved(raw, { by: 'ci:auto-approved', risk: 'low' });
  assert.equal(stamped[APPROVAL_FIELD].status, APPROVED_STATUS);
  assert.equal(isApproved(stamped), true, '盖章后必须放行');

  // 端到端：盖章 -> 合并 -> 过校验器
  const { index, stats } = buildIndex({ index: emptyIndex, entries: [stamped] });
  assert.equal(stats.approved, 1);
  assert.equal(index.modules.length, 1);
  assert.equal(index.modules[0].verified, false);
  assert.equal(validateIndex(index).ok, true);
});

test('回归 ④：--consume 在有冲突时不得删除 pending（曾经会静默丢投稿）', () => {
  // 复现当时的场景：同 id 投第二次、sha256 不同 -> 产生冲突、退出码 2。
  // 修复前 --consume 会把 pending/<id>/ 整个删光：退出码 2、冲突没解决、
  // 数据已消失，投稿者再也无从追溯。
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consume-conflict-'));
  const pendingDir = path.join(dir, 'pending');
  const nested = path.join(pendingDir, 'demo_mod');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(
    path.join(nested, '100.json'),
    `${JSON.stringify([entry({ approved: true })], null, 2)}\n`,
    'utf8',
  );

  const argIdx = process.argv.indexOf('--pending');
  assert.ok(argIdx === -1, '本用例自己调 main，不依赖外部 argv');

  // 先在索引里放一个同 id、不同 sha256 的版本，制造冲突
  const seeded = buildIndex({ index: emptyIndex, entries: [entry({ approved: true })] }).index;
  const indexFile = path.join(dir, 'json', 'modules.json');
  fs.mkdirSync(path.dirname(indexFile), { recursive: true });
  fs.writeFileSync(indexFile, `${JSON.stringify(seeded, null, 2)}\n`, 'utf8');

  const conflictEntry = entry({
    approved: true,
    versions: [{
      version: 'v1.0.0', versionCode: 100, zipUrl: 'https://example.com/b.zip',
      size: 2048, time: 1700000000000, sha256: sha(2),
    }],
  });
  fs.writeFileSync(
    path.join(nested, '200.json'),
    `${JSON.stringify([conflictEntry], null, 2)}\n`,
    'utf8',
  );

  const rc = main(['--pending', pendingDir, '--index', indexFile, '--consume']);
  assert.equal(rc, 2, '有冲突时退出码必须是 2');

  // 关键断言：文件还在。这是整个回归要锁的东西。
  assert.ok(
    fs.existsSync(path.join(nested, '100.json')),
    '有冲突时 --consume 必须保留 100.json',
  );
  assert.ok(
    fs.existsSync(path.join(nested, '200.json')),
    '有冲突时 --consume 必须保留 200.json',
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test('回归 ④：--consume 在无冲突时确实清理掉 pending（含嵌套目录）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consume-clean-'));
  const pendingDir = path.join(dir, 'pending');
  const nested = path.join(pendingDir, 'demo_mod');
  fs.mkdirSync(nested, { recursive: true });
  fs.writeFileSync(
    path.join(nested, '100.json'),
    `${JSON.stringify([entry({ approved: true })], null, 2)}\n`,
    'utf8',
  );
  const indexFile = path.join(dir, 'json', 'modules.json');

  const rc = main(['--pending', pendingDir, '--index', indexFile, '--consume']);
  assert.equal(rc, 0, '无冲突时退出码必须是 0');

  assert.ok(!fs.existsSync(path.join(nested, '100.json')), '无冲突时 --consume 应删掉已合并条目');
  assert.ok(!fs.existsSync(nested), '空掉的 <id>/ 目录应被移除');
  assert.ok(fs.existsSync(indexFile), '索引文件必须已写出');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('回归 ④：--consume 遇到非法条目时同样不删（invalid 也是未解决的现场）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consume-invalid-'));
  const pendingDir = path.join(dir, 'pending');
  fs.mkdirSync(pendingDir, { recursive: true });
  const bad = path.join(pendingDir, 'bad.json');
  // sha256 不合法 -> normalizeEntry 判非法 -> stats.invalid > 0
  fs.writeFileSync(
    bad,
    `${JSON.stringify([entry({ approved: true, versions: [{ version: 'v1', versionCode: 1, zipUrl: 'https://e.com/a.zip', size: 1, time: 1, sha256: 'zzz' }] })], null, 2)}\n`,
    'utf8',
  );
  const indexFile = path.join(dir, 'json', 'modules.json');

  const rc = main(['--pending', pendingDir, '--index', indexFile, '--consume']);
  assert.equal(rc, 2, '有非法条目时退出码必须是 2');
  assert.ok(fs.existsSync(bad), '有非法条目时 --consume 不得删除 pending');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('回归 ②：audit.status 不是 auto-approved 时不放行', () => {
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: 'needs-human-review' } }), false);
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: 'blocked' } }), false);
  assert.equal(isApproved({ [APPROVAL_FIELD]: {} }), false);
});

test('回归 ②：--pending / --index 参数解析', () => {
  const o = parseArgs(['--pending', 'P', '--index', 'I', '--dry-run', '--consume']);
  assert.equal(o.dryRun, true);
  assert.equal(o.consume, true);
  assert.equal(path.basename(o.pendingDir), 'P');
  assert.equal(path.basename(o.indexFile), 'I');
});

// ─────────────────────────────────────────────────────────────────────────────
// P3：处置台账参与推导
//
// 这里锁的是「索引 = f(pending, 台账)」这条式子里的第二个输入。
// 所有用例都**显式传 --dispositions**：默认值指向仓库里那份真台账，
// 不传就等于单测去读生产数据 —— 台账一改，测试结论跟着变，那是最坏的假绿。
// ─────────────────────────────────────────────────────────────────────────────

const { parseDispositions } = await import('../scripts/dispositions.mjs');
const ledger = (...list) => parseDispositions({ schema: 'sukisu-dispositions-v1', dispositions: list });

test('P3：台账命中的新条目不进索引，也不算冲突（算冲突会挡住 --consume，自我堵死）', () => {
  const { index, conflicts, stats, blocked } = buildIndex({
    index: emptyIndex,
    entries: [entry()],
    dispositions: ledger({ kind: 'revoke', id: 'demo_mod', reason: 'malware', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }),
  });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.blocked, 1);
  assert.equal(stats.approved, 0, '被挡下的不算「通过审核」');
  assert.equal(conflicts.length, 0);
  assert.equal(blocked.length, 1);
  assert.equal(blocked[0].via, 'id');
  assert.equal(blocked[0].reason, 'malware');
  assert.ok(blocked[0].by, '挡下的清单必须带得上面的章，否则事后无从复核');
});

test('P3：台账会把**已在索引里**的版本抹掉 —— 这一步才是下架本身', () => {
  const seeded = buildIndex({ index: emptyIndex, entries: [entry()] }).index;
  const { index, stats } = buildIndex({
    index: seeded,
    entries: [],
    dispositions: ledger({ kind: 'revoke', id: 'demo_mod', reason: 'policy', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }),
  });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.removedVersions, 1);
  assert.equal(stats.removedModules, 1, '版本抹空了要连模块一起移除');
});

test('P3：指到产物的处置不越权 —— 同 id 的另一个版本必须留着', () => {
  const two = buildIndex({
    index: emptyIndex,
    entries: [entry({
      versions: [
        { version: 'v1', versionCode: 100, zipUrl: 'https://e/1.zip', size: 1, time: 1, sha256: sha(1) },
        { version: 'v2', versionCode: 200, zipUrl: 'https://e/2.zip', size: 1, time: 1, sha256: sha(2) },
      ],
    })],
  }).index;
  const { index, stats } = buildIndex({
    index: two,
    entries: [],
    dispositions: ledger({ kind: 'revoke', id: 'demo_mod', sha256: sha(1), reason: 'malware', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }),
  });
  assert.equal(index.modules.length, 1, '模块还在，只是坏产物没了');
  assert.deepEqual(index.modules[0].versions.map((v) => v.versionCode), [200]);
  assert.equal(stats.removedVersions, 1);
  assert.equal(stats.removedModules, 0);
});

test('P3：换皮重投被同一条 sha256 抓住（改了 id 也没用）', () => {
  const resubmit = entry({ id: 'brand_new_name', versions: [{ version: 'v1', versionCode: 1, zipUrl: 'https://e/1.zip', size: 1, time: 1, sha256: sha(1) }] });
  const { index, stats } = buildIndex({
    index: emptyIndex,
    entries: [resubmit],
    dispositions: ledger({ kind: 'revoke', sha256: sha(1), reason: 'malware', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }),
  });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.blocked, 1);
});

test('P3：按 coolapkUid 拉黑能挡住投稿（normalizeEntry 不带 uid，漏接就会静默失效）', () => {
  const d = { kind: 'deny', coolapkUid: '10086001', reason: 'impersonation', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' };
  const hit = buildIndex({ index: emptyIndex, entries: [entry({ coolapkUid: '10086001' })], dispositions: ledger(d) });
  assert.equal(hit.index.modules.length, 0, '这个人的投稿不进索引');
  assert.equal(hit.stats.blocked, 1);
  const miss = buildIndex({ index: emptyIndex, entries: [entry({ coolapkUid: '1111111' })], dispositions: ledger(d) });
  assert.equal(miss.index.modules.length, 1, '别人不受牵连');
});

test('P3：空台账 = 行为与接台账之前逐字段一致（回归护栏）', () => {
  // 这条护栏在测的是「接台账之前与之后，产出的索引一模一样」，而它自己**不能**跟时钟赛跑。
  // 根因（p5-t33-run/p3-probe.mjs 实测，2026-10-14）：buildIndex 在 scripts/build-index.mjs:354
  // 会把 `out.lastUpdate = Date.now()` 写进产出（只在 modules 非空时），于是这里两次调用之间
  // 只要跨过一毫秒边界，deepEqual 就红 —— 200 次背靠背跑出 4 次红（2%），与「连跑 8 次红 1 次」同量级；
  // 强制隔 3 毫秒则必红，且红起来唯一的差异字段就是 lastUpdate（抹平它之后两边逐字段相等）。
  //
  // 治法选**钉时间源**，不选「把 lastUpdate 排除在比对之外」：后者等于给这条护栏开一个永远不被看的洞，
  // 而「空台账不许动 lastUpdate 之外的任何字段」这一格恰恰要靠全字段比对才成立。
  // 时间源钉不住时下面两条 assert.equal 会当场红 —— 钉了个寂寞也算故障。
  const FIXED_NOW = 1700000000000;
  const realNow = Date.now;
  let a;
  let b;
  try {
    Date.now = () => FIXED_NOW;
    a = buildIndex({ index: emptyIndex, entries: [entry()] });
    b = buildIndex({ index: emptyIndex, entries: [entry()], dispositions: ledger() });
  } finally {
    Date.now = realNow; // 夹具不许把时钟留给下一个测试
  }
  assert.equal(a.index.lastUpdate, FIXED_NOW, '时间源必须真的被钉住：钉不住时下面那条比对还是在跟毫秒赛跑');
  assert.equal(b.index.lastUpdate, FIXED_NOW, '接台账那一侧同样走钉住的时间源');
  assert.deepEqual(b.index, a.index);
  assert.equal(b.stats.blocked, 0);
});

test('P3 main：被挡下的 pending 不被 --consume 删除，正常消费的照删', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'consume-blocked-'));
  const pendingDir = path.join(dir, 'pending');
  const indexFile = path.join(dir, 'json', 'modules.json');
  const dispFile = path.join(dir, 'json', 'dispositions.json');
  fs.mkdirSync(path.join(pendingDir, 'blocked_mod'), { recursive: true });
  fs.mkdirSync(path.join(pendingDir, 'ok_mod'), { recursive: true });
  fs.mkdirSync(path.dirname(indexFile), { recursive: true });
  fs.writeFileSync(indexFile, `${JSON.stringify(emptyIndex, null, 2)}\n`, 'utf8');
  fs.writeFileSync(
    path.join(pendingDir, 'blocked_mod', '100.json'),
    JSON.stringify(entry({ id: 'blocked_mod' })),
    'utf8',
  );
  fs.writeFileSync(
    path.join(pendingDir, 'ok_mod', '100.json'),
    JSON.stringify(entry({ id: 'ok_mod', versions: [{ version: 'v1', versionCode: 100, zipUrl: 'https://e/ok.zip', size: 1, time: 1, sha256: sha(9) }] })),
    'utf8',
  );
  fs.writeFileSync(
    dispFile,
    JSON.stringify({ schema: 'sukisu-dispositions-v1', dispositions: [{ kind: 'revoke', id: 'blocked_mod', reason: 'test-probe', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }] }),
    'utf8',
  );

  const rc = main(['--pending', pendingDir, '--index', indexFile, '--dispositions', dispFile, '--consume']);
  assert.equal(rc, 0, '台账命中不是冲突，不该 exit 2');
  assert.ok(fs.existsSync(path.join(pendingDir, 'blocked_mod', '100.json')), '挡下的那条要留作复核现场');
  assert.equal(fs.existsSync(path.join(pendingDir, 'ok_mod', '100.json')), false, '正常消费的照删');
  const idx = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
  assert.deepEqual(idx.modules.map((m) => m.id), ['ok_mod']);

  // 幂等：再跑一次，结果不该变（留着坏条目不会反复触发重建）
  const rc2 = main(['--pending', pendingDir, '--index', indexFile, '--dispositions', dispFile, '--consume']);
  assert.equal(rc2, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(indexFile, 'utf8')).modules.map((m) => m.id), ['ok_mod']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('P3 main：台账读不懂 → 退出 3 且**不写索引**（不能当空台账把下架全抹掉）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-bad-'));
  const indexFile = path.join(dir, 'json', 'modules.json');
  const dispFile = path.join(dir, 'json', 'dispositions.json');
  fs.mkdirSync(path.dirname(indexFile), { recursive: true });
  const seeded = buildIndex({ index: emptyIndex, entries: [entry()] }).index;
  fs.writeFileSync(indexFile, `${JSON.stringify(seeded, null, 2)}\n`, 'utf8');
  const before = fs.readFileSync(indexFile, 'utf8');
  fs.writeFileSync(dispFile, '{ 坏掉的台账', 'utf8');

  const rc = main(['--pending', path.join(dir, 'pending'), '--index', indexFile, '--dispositions', dispFile, '--consume']);
  assert.equal(rc, 3);
  assert.equal(fs.readFileSync(indexFile, 'utf8'), before, '索引一个字节都不许动');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('P3 main：台账里那条选择器全空的记录会让整次推导停住（而不是被跳过）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ledger-badentry-'));
  const indexFile = path.join(dir, 'json', 'modules.json');
  const dispFile = path.join(dir, 'json', 'dispositions.json');
  fs.mkdirSync(path.dirname(indexFile), { recursive: true });
  fs.writeFileSync(indexFile, `${JSON.stringify(emptyIndex, null, 2)}\n`, 'utf8');
  // 选择器全空 == 匹配一切。跳过它继续跑，等于把整个索引抹空；停住才是对的方向。
  fs.writeFileSync(
    dispFile,
    JSON.stringify({ schema: 'sukisu-dispositions-v1', dispositions: [{ kind: 'revoke', reason: 'malware', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }] }),
    'utf8',
  );
  const before = fs.readFileSync(indexFile, 'utf8');
  assert.equal(main(['--pending', path.join(dir, 'pending'), '--index', indexFile, '--dispositions', dispFile]), 3);
  assert.equal(fs.readFileSync(indexFile, 'utf8'), before);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('P3：parseArgs 认 --dispositions，默认指向仓库那份', () => {
  const o = parseArgs(['--dispositions', 'D']);
  assert.equal(path.basename(o.dispositionsFile), 'D');
  assert.equal(path.basename(parseArgs([]).dispositionsFile), 'dispositions.json');
});

// ─────────────────────────────────────────────────────────────────────────────
// 出处四字段：source / uploader / coolapkUid / submittedAt
//
// 这四格是 App「酷安模块详情页」的数据来源，全部**可选**，消费侧的判据是「键在不在」——
// 所以这里的断言不只要看值对不对，还要看**缺的时候键真的不存在**。`null` 是这里最想抓住的
// 一种坏：`undefined` 会被 JSON.stringify 静默吞掉（测试在内存里跑绿、发布产物里是另一回事），
// `null` 则会一路活到线上，让老 App 以为有出处、却渲染出一个空链接。两种都必须在产出那一刻就没有。
// ─────────────────────────────────────────────────────────────────────────────

const ORIGIN_FIELDS = ['source', 'uploader', 'coolapkUid', 'submittedAt'];

test('出处 ①：四字段齐全时全部进索引（source 规范化成绝对地址、字符串 trim）', () => {
  const n = normalizeEntry(entry({
    source: '  https://www.coolapk.com/feed/123456  ',
    uploader: '  小绿  ',
    coolapkUid: ' 10086001 ',
    submittedAt: 1700000000000,
  }));

  assert.equal(n.ok, true);
  assert.equal(n.entry.source, 'https://www.coolapk.com/feed/123456');
  assert.equal(n.entry.uploader, '小绿', '昵称两侧空白要 trim（否则详情页会显示一段看不见的空格）');
  assert.equal(n.entry.coolapkUid, '10086001', 'UID trim 后才能拼出可点的 coolapk.com/u/<UID>');
  assert.equal(n.entry.submittedAt, 1700000000000);

  // 老结构一个都没被挤掉
  for (const f of ['id', 'name', 'author', 'description', 'versions', 'verified']) {
    assert.equal(f in n.entry, true, `新增字段不能挤掉 ${f}`);
  }
  // 多出来的键不能让索引校验器红（App 老版本读新索引走的也是这条路）
  const { index } = buildIndex({
    index: emptyIndex,
    entries: [entry({
      source: 'https://www.coolapk.com/feed/1', uploader: '小绿', coolapkUid: '10086001', submittedAt: 1700000000000,
    })],
  });
  assert.equal(validateIndex(index).ok, true);
});

test('出处 ②：只填了仓库时，出处四格**整个键不出现**（不是 null，也不是空串）', () => {
  // 契约 §1 要求 source 与 repoUrl 至少一个，所以「四格全缺」现在只能在有仓库的前提下存在 ——
  // 两个都没有的条目是 invalid（见出处 ③ 末尾那一条）。这里测的仍是同一件事：
  // 缺值不许变成 null / "" 一路活到线上。
  const m = buildIndex({
    index: emptyIndex,
    entries: [entry({
      source: undefined,
      repoUrl: 'https://github.com/acme/demo',
      repoVerified: true,
      repoCheckedAt: 1700000000000,
    })],
  }).index.modules[0];

  for (const f of ORIGIN_FIELDS) {
    assert.equal(f in m, false, `${f} 缺失时不许出现在索引里`);
  }
  // 序列化后再看一遍：undefined 会被吞掉、null 不会 —— 两种都不许有
  const json = JSON.stringify(m);
  assert.equal(json.includes('null'), false, '产物里不许出现 null（老 App 会把它当成「有出处」）');
  assert.equal(/"(source|uploader|coolapkUid|submittedAt)":/.test(json), false);
});

test('出处 ③：source 只认酷安站内 http(s)，其余一律丢掉（上游漏校验也不许发出去）', () => {
  const bad = [
    'javascript:alert(1)',                                  // 补 scheme 后解析不出合法 host
    'https://evil.com/x',                                   // 站外
    'https://coolapk.com.evil.com/x',                       // 后缀伪装，不是子域
    'https://evil.com/?r=https://www.coolapk.com/feed/1',   // 站内地址只出现在 query 里
    'data:text/html,<script>alert(1)</script>',
    '/feed/1',                                              // 相对路径
    '   ',                                                  // 空白
  ];
  for (const s of bad) {
    assert.equal(coolapkSourceUrl(s), '', `判据本身要拒：${s}`);
    // 出处这一格非法、但填了仓库 ⇒ 条目仍然合法（仓库就是那个可点回去的锚），只是 source 键省略。
    const m = buildIndex({
      index: emptyIndex,
      entries: [entry({
        source: s, repoUrl: 'https://github.com/acme/demo', repoVerified: true, repoCheckedAt: 1700000000000,
      })],
    }).index.modules[0];
    assert.equal('source' in m, false, `非法 source 必须省略：${s}`);
    // 反过来：唯一那个锚也是非法的，就没有任何可点回去的地方 ⇒ 整条 invalid（契约 §1）。
    // 静默丢成「没填」是最坏的结局：索引里看不出有人试过，投稿人也不知道自己的链接为什么没生效。
    const lone = normalizeEntry(entry({ source: s }));
    assert.equal(lone.ok, false, `唯一出处非法 ⇒ 整条 invalid：${s}`);
  }

  // 该放行的：子域、裸域名补 scheme、http
  assert.equal(coolapkSourceUrl('https://www.coolapk.com/feed/1'), 'https://www.coolapk.com/feed/1');
  assert.equal(coolapkSourceUrl('https://coolapk.com/feed/1'), 'https://coolapk.com/feed/1');
  assert.equal(coolapkSourceUrl('www.coolapk.com/feed/1'), 'https://www.coolapk.com/feed/1', '老 pending 存的裸域名要补成绝对地址');
  assert.equal(coolapkSourceUrl('http://coolapk.com/feed/1'), 'http://coolapk.com/feed/1');
});

test('出处 ④：submittedAt 收 Worker 的 ISO 字符串（真实 pending 就长这样），也收毫秒；认不出来就省略', () => {
  // Worker 的 buildPendingJson 写的是 ISO：`new Date(ms).toISOString()`
  assert.equal(
    normalizeEntry(entry({ submittedAt: '2026-10-23T00:00:00.000Z' })).entry.submittedAt,
    Date.parse('2026-10-23T00:00:00.000Z'),
  );
  assert.equal(normalizeEntry(entry({ submittedAt: '1700000000000' })).entry.submittedAt, 1700000000000);

  for (const bad of [0, -1, 1.5, NaN, Infinity, '', 'not-a-time', null, undefined, {}, []]) {
    assert.equal('submittedAt' in normalizeEntry(entry({ submittedAt: bad })).entry, false, `非法值不许写键：${String(bad)}`);
  }
});

test('出处 ⑤：老索引条目原样通过 —— 纯转发一个字节不变，重投也不凭空长出新键', () => {
  const legacy = {
    id: 'demo_mod',
    name: 'Demo',
    author: 'tester',
    description: 'demo module',
    versions: [{ version: 'v0.9.0', versionCode: 90, zipUrl: 'https://e/old.zip', size: 1, time: 1, sha256: sha(7) }],
    verified: false,
  };

  // ① 只按台账/时间重推导、没有新 pending：老条目必须原样出来
  const passthrough = buildIndex({ index: { ...emptyIndex, modules: [legacy] }, entries: [] }).index;
  assert.deepEqual(passthrough.modules[0], legacy, '老索引条目不许被改写');

  // ② 老模块再来一个新版本：`source` **补空但不覆盖**（契约 §3.1），另外三格不回填。
  //    分岔的理由是这三格记的是「这一位投稿人」—— 拿重投者的身份去填老模块，
  //    等于把索引里已有的归属关系悄悄换人。`source` 只是「这个模块从哪个帖子来」，
  //    老条目没有就是一个可点回去的地址都没有，补上重投者的那一条是净增益。
  const { index, conflicts } = buildIndex({
    index: { ...emptyIndex, modules: [legacy] },
    entries: [entry({ source: 'https://www.coolapk.com/feed/9', uploader: 'alice', coolapkUid: '10086001', submittedAt: 1700000000000 })],
  });
  assert.equal(conflicts.length, 0, '出处四格不进 sameMeta，不该被算成元信息冲突');
  assert.equal(index.modules.length, 1);
  assert.equal(index.modules[0].versions.length, 2);
  assert.equal(index.modules[0].source, 'https://www.coolapk.com/feed/9', 'source 只补空');
  for (const f of ['uploader', 'coolapkUid', 'submittedAt']) {
    assert.equal(f in index.modules[0], false, `${f} 不回填（记的是这一位投稿人，不能换成重投者）`);
  }
  // 反过来：老条目已经有 source 时，重投者的不许盖掉它（§3.1：只补，不覆盖）
  const withSource = { ...legacy, source: 'https://www.coolapk.com/feed/old' };
  const kept = buildIndex({
    index: { ...emptyIndex, modules: [withSource] },
    entries: [entry({ source: 'https://www.coolapk.com/feed/new' })],
  }).index.modules[0];
  assert.equal(kept.source, 'https://www.coolapk.com/feed/old', '已有 source 不许被覆盖');
});

test('出处 ⑥：uid 进索引 ⇒ 按 uid 的模块级处置开始能抹掉**已在索引里**的模块（副作用，钉住）', () => {
  const seeded = buildIndex({ index: emptyIndex, entries: [entry({ coolapkUid: '10086001' })] }).index;
  assert.equal(seeded.modules[0].coolapkUid, '10086001');

  // 以前 normalizeEntry 不投影 uid，索引里的模块身上没有这一格，于是「按人拉黑」只挡得住
  // **新投稿**、抹不掉已经进去了的模块。这一格公开之后，那条处置才真正落到老模块上。
  const { index, stats, blocked } = buildIndex({
    index: seeded,
    entries: [],
    dispositions: ledger({ kind: 'deny', coolapkUid: '10086001', reason: 'impersonation', by: 'gh:x@1', at: '2026-10-11T00:00:00Z' }),
  });
  assert.equal(index.modules.length, 0);
  assert.equal(stats.removedModules, 1);
  assert.equal(blocked[0].via, 'coolapkUid');
});

// ─────────────────────────────────────────────────────────────────────────────
// 仓库字段（契约 §1 / §3.1）—— 「来源」与「源码仓库」二选一之后，`repoUrl` 是
// 「这个包里那几行代码在哪儿能被复核」的唯一锚；`repoCoversLatest` 是派生给 App 的结论；
// `json/repo-state.json` 是每日复验把**时间性**的结论（还公开吗、许可证变了没）贴回索引
// 的那条路 —— 它是唯一能改一枚已在索引里的模块、却不经过一次新投稿的入口。
// ─────────────────────────────────────────────────────────────────────────────

const REPO_OK = { repoUrl: 'https://github.com/acme/demo', repoVerified: true, repoCheckedAt: 1700000000000 };
const v1 = { version: 'v1', versionCode: 1, zipUrl: 'https://e/1.zip', size: 1, time: 1, sha256: sha(1) };
const v2 = { version: 'v2', versionCode: 2, zipUrl: 'https://e/2.zip', size: 1, time: 2, sha256: sha(2) };

test('仓库 ①：repoUrl 归一化与 Worker 侧同一套语义（§2.1）', () => {
  const ok = [
    ['https://github.com/acme/demo', 'https://github.com/acme/demo'],
    ['  https://github.com/acme/demo  ', 'https://github.com/acme/demo'],
    ['https://github.com/acme/demo/', 'https://github.com/acme/demo'],
    ['https://github.com/acme/demo.git', 'https://github.com/acme/demo'],
    ['https://github.com/acme/demo.git/', 'https://github.com/acme/demo'],
    ['https://GitHub.com/acme/demo', 'https://github.com/acme/demo'],
    // owner/repo 的大小写**原样保留**：状态匹配、复验、自动收录全拿它做等值比较，
    // 擅自 lower 会让索引里显示的地址与投稿人填的不是同一个串。
    ['https://github.com/Acme/Demo', 'https://github.com/Acme/Demo'],
    ['https://github.com/a-1/b_2.c', 'https://github.com/a-1/b_2.c'],
  ];
  for (const [raw, want] of ok) assert.equal(normalizeRepoUrl(raw), want, `应归一化成 ${want}：${raw}`);

  const bad = [
    'http://github.com/acme/demo',            // 只认 https
    'https://gitlab.com/acme/demo',           // 只认 github.com
    'https://github.com.evil.com/acme/demo',  // 后缀伪装，不是同一个 host
    'https://github.com/acme',                // 少一段
    'https://github.com/acme/demo/tree/main', // 多一段（那是网页地址，不是仓库根）
    'https://github.com/acme/demo?tab=1',
    'https://github.com/acme/demo#readme',
    'https://user:pw@github.com/acme/demo',   // userinfo
    'https://github.com:8443/acme/demo',      // 端口
    'github.com/acme/demo',                   // 无协议
    '/acme/demo',
    '',
    '   ',
    null,
    undefined,
    {},
    42,
  ];
  for (const raw of bad) assert.equal(normalizeRepoUrl(raw), '', `应拒：${String(raw)}`);

  // updateJson 只查形状，不做归一化（它是模块作者自己写的地址，原样保留才叫「他写的那个」）
  assert.equal(normalizeUpdateJson('  https://acme.example/u.json  '), 'https://acme.example/u.json');
  assert.equal(normalizeUpdateJson('http://acme.example/u.json'), 'http://acme.example/u.json');
  for (const raw of ['ftp://x/u.json', 'not-a-url', '', '   ', null, `https://e/${'a'.repeat(2048)}`]) {
    assert.equal(normalizeUpdateJson(raw), '', `应省略：${String(raw).slice(0, 40)}`);
  }
});

test('仓库 ②：模块级/版本级仓库字段按 §1 投影，空值省略键', () => {
  const n = normalizeEntry(entry({
    ...REPO_OK,
    repoLicense: ' Apache-2.0 ',
    updateJson: ' https://acme.example/update.json ',
    versions: [{ ...v1, repoTag: ' v1 ', repoDigest: `sha256:${sha(1)}`, auto: true, autoVia: 'repo' }],
  }));
  assert.equal(n.ok, true, n.error);
  const m = n.entry;
  assert.equal(m.repoUrl, 'https://github.com/acme/demo');
  assert.equal(m.repoVerified, true);
  assert.equal(m.repoCheckedAt, 1700000000000);
  assert.equal(m.repoLicense, 'Apache-2.0');
  assert.equal(m.updateJson, 'https://acme.example/update.json');
  const v = m.versions[0];
  assert.equal(v.repoTag, 'v1');
  assert.equal(v.repoDigest, `sha256:${sha(1)}`);
  assert.equal(v.auto, true);
  assert.equal(v.autoVia, 'repo');
  // `repoCoversLatest` 是索引侧派生键，pending 里不该有（§1 明写「不写进 pending」）
  assert.equal('repoCoversLatest' in m, false);

  // `repoVerified: false` 是**真结论**（机器验过、结论是不绿），要写出来；其余空值一律省略
  const bare = normalizeEntry(entry({
    repoUrl: 'https://github.com/acme/demo', repoVerified: false, repoCheckedAt: 1, repoLicense: '  ', updateJson: '',
  })).entry;
  assert.equal(bare.repoVerified, false);
  assert.equal('repoLicense' in bare, false, '无 LICENSE ⇒ 省略（不写空串，也不写 NOASSERTION）');
  assert.equal('updateJson' in bare, false, 'module.prop 里没有 ⇒ 省略');

  // 没有仓库时，一个仓库键都不许出现（不是 null、不是 ''）
  const noRepo = normalizeEntry(entry()).entry;
  for (const f of ['repoUrl', 'repoVerified', 'repoCheckedAt', 'repoLicense', 'updateJson']) {
    assert.equal(f in noRepo, false, `${f} 没有值时不许出现`);
  }
  assert.equal(JSON.stringify(noRepo).includes('null'), false);
});

test('仓库 ③：非法仓库字段**整条拒**，不静默降级成「没填」', () => {
  const cases = [
    [{ repoUrl: 'http://github.com/acme/demo' }, /repoUrl/],
    [{ repoUrl: 'https://github.com/acme' }, /repoUrl/],
    [{ repoUrl: 'https://github.com/acme/demo/tree/main' }, /repoUrl/],
    // 有地址就必须有结论：只有地址的条目在 App 侧会变成既绿又灰的暧昧状态
    [{ repoUrl: 'https://github.com/acme/demo', repoVerified: undefined, repoCheckedAt: 1 }, /repoVerified/],
    [{ repoUrl: 'https://github.com/acme/demo', repoVerified: 'true', repoCheckedAt: 1 }, /repoVerified/],
    [{ repoUrl: 'https://github.com/acme/demo', repoVerified: true, repoCheckedAt: 0 }, /repoVerified/],
    [{ repoUrl: 'https://github.com/acme/demo', repoVerified: true, repoCheckedAt: -5 }, /repoVerified/],
    // 两个锚都没有：公示里没有任何可点回去的地址
    [{ source: undefined }, /source 与 repoUrl 至少要有其中一个/],
    // 酷安链接不是合法的，仓库地址也不合法：不能靠「有一格填了」蒙混过关
    [{ source: 'javascript:void(0)', repoUrl: 'https://gitlab.com/a/b' }, /repoUrl/],
  ];
  for (const [over, re] of cases) {
    const n = normalizeEntry(entry(over));
    assert.equal(n.ok, false, `应拒：${JSON.stringify(over)}`);
    assert.match(n.error, re);
  }
});

test('仓库 ④：版本级证据必须指向同一个包 —— digest 与 sha256 对不上就拒', () => {
  const cases = [
    [{ repoDigest: `sha256:${sha(2)}` }, /不是同一个包/],
    [{ repoDigest: 'sha256:XYZ' }, /repoDigest/],
    [{ repoTag: 'v1', auto: true, autoVia: 'repo' }, /repoDigest/],                       // auto 缺 digest
    [{ repoDigest: `sha256:${sha(1)}`, auto: true }, /autoVia/],                          // auto 说不出 via
    [{ repoDigest: `sha256:${sha(1)}`, auto: true, autoVia: 'git' }, /autoVia/],
    [{ repoDigest: `sha256:${sha(1)}`, autoVia: 'repo', repoTag: 'v1' }, /只说了一半/],   // via 却没有 auto
    [{ repoDigest: `sha256:${sha(1)}`, auto: true, autoVia: 'repo' }, /repoTag/],          // repo 却没有 tag
    [{ auto: 'yes' }, /auto 不是布尔/],
  ];
  for (const [over, re] of cases) {
    const n = normalizeEntry(entry({ ...REPO_OK, versions: [{ ...v1, ...over }] }));
    assert.equal(n.ok, false, `应拒：${JSON.stringify(over)}`);
    assert.match(n.error, re);
  }
});

test('仓库 ⑤：同 id 再来一版时模块级仓库字段**可覆盖**，license 跟最新结论走', () => {
  const seeded = buildIndex({
    index: emptyIndex,
    entries: [entry({
      ...REPO_OK, repoLicense: 'MIT', updateJson: 'https://acme.example/old.json',
      versions: [{ ...v1, repoTag: 'v1' }],
    })],
  }).index;
  assert.equal(seeded.modules[0].repoLicense, 'MIT');

  const { index, conflicts } = buildIndex({
    index: seeded,
    entries: [entry({
      repoUrl: 'https://github.com/acme/renamed',
      repoVerified: true,
      repoCheckedAt: 1800000000000,
      updateJson: 'https://acme.example/new.json',
      versions: [v2],
    })],
  });
  assert.equal(conflicts.length, 0);
  const m = index.modules[0];
  assert.equal(m.repoUrl, 'https://github.com/acme/renamed', '作者换了仓库地址，索引跟着换（Worker 已验过新仓库）');
  assert.equal(m.repoCheckedAt, 1800000000000);
  assert.equal('repoLicense' in m, false, '这次没读到 LICENSE ⇒ 旧的 SPDX 必须消失，不能留一个不存在的许可证');
  assert.equal(m.updateJson, 'https://acme.example/new.json');
  assert.equal(m.versions.length, 2);
});

test('仓库 ⑥：repoCoversLatest 按 versionCode 最大的版本算，没有仓库的模块不留这个键', () => {
  const withRepo = (versions) => buildIndex({ index: emptyIndex, entries: [entry({ ...REPO_OK, versions })] }).index.modules[0];

  assert.equal(withRepo([{ ...v1, repoTag: 'v1' }]).repoCoversLatest, true);
  assert.equal(withRepo([v1]).repoCoversLatest, false, '有仓库但最新版没证据 ⇒ false 也要写出来（那是结论）');
  // 只有低版本有证据、高版本没有：结论按**最高** versionCode 算
  assert.equal(withRepo([{ ...v1, repoTag: 'v1' }, v2]).repoCoversLatest, false);
  // 顺序打乱也一样（合并后会按 versionCode 降序排）
  assert.equal(withRepo([v2, { ...v1, repoTag: 'v1' }]).repoCoversLatest, false);

  const noRepo = buildIndex({ index: emptyIndex, entries: [entry()] }).index.modules[0];
  assert.equal('repoCoversLatest' in noRepo, false, '没有 repoUrl 就没有「覆盖」这个问题，键不该出现');
  // 老索引条目本来就没有这个键：纯转发也不许凭空长出来
  const legacy = { id: 'legacy', name: 'L', author: 'a', description: 'd', verified: false, versions: [v1] };
  const passthrough = buildIndex({ index: { ...emptyIndex, modules: [legacy] }, entries: [] }).index.modules[0];
  assert.equal('repoCoversLatest' in passthrough, false);
});

test('仓库 ⑦：repo-state 只贴到 repoUrl 完全相同的模块上，updateJson 只补不改', () => {
  const mod = (over = {}) => ({
    id: 'm1', name: 'M', author: 'a', description: 'd',
    repoUrl: 'https://github.com/acme/demo', repoVerified: true, repoCheckedAt: 1,
    versions: [v1], verified: false, ...over,
  });
  const ms = () => [mod(), mod({ id: 'm2', repoUrl: 'https://github.com/acme/other' })];
  const state = {
    checkedAt: 1800000000000,
    modules: {
      m1: {
        repoUrl: 'https://github.com/acme/demo', repoVerified: false, repoCheckedAt: 1800000000000,
        repoLicense: 'MIT', updateJson: 'https://acme.example/u.json',
      },
      // 地址不匹配（作者把仓库改名/搬走了）⇒ 旧地址上的结论不再适用于这条模块，一个字都不动
      m2: { repoUrl: 'https://github.com/acme/moved', repoVerified: false, repoCheckedAt: 1800000000000 },
      // 索引里没有这个 id ⇒ 忽略（state 只能更新已有模块，不能凭空造一个）
      m3: { repoUrl: 'https://github.com/acme/demo', repoVerified: false, repoCheckedAt: 1 },
    },
  };

  const a = ms();
  const changed = applyRepoState(a, state);
  assert.equal(a[0].repoVerified, false, '复验说撤标就撤标');
  assert.equal(a[0].repoCheckedAt, 1800000000000);
  assert.equal(a[0].repoLicense, 'MIT');
  assert.equal(a[0].updateJson, 'https://acme.example/u.json');
  assert.equal(a[1].repoVerified, true, 'repoUrl 不同的模块不许被改写');
  assert.equal('updateJson' in a[1], false);
  assert.deepEqual(changed.map((c) => c.id), ['m1']);

  // updateJson 只在模块**没有**时补：作者写在 module.prop 里的那个值优先
  const b = [mod({ updateJson: 'https://acme.example/authored.json' })];
  applyRepoState(b, state);
  assert.equal(b[0].updateJson, 'https://acme.example/authored.json');

  // state 是可选输入：形状坏成什么样都不许炸，也不许改任何东西
  for (const bad of [null, undefined, {}, { modules: [] }, { modules: { m1: null } }, { modules: { m1: { repoUrl: 'x' } } }]) {
    const c = ms();
    assert.doesNotThrow(() => applyRepoState(c, bad), `坏 state 不该抛：${JSON.stringify(bad)}`);
    assert.equal(c[0].repoCheckedAt, 1, `坏 state 不许改任何东西：${JSON.stringify(bad)}`);
  }
});

test('仓库 ⑧：buildIndex 接 repo-state —— 复验结论进索引并记账；不给 state 时逐字段不变', () => {
  const seeded = buildIndex({
    index: emptyIndex,
    entries: [entry({ ...REPO_OK, versions: [v1] })],
  }).index;
  assert.equal(seeded.modules[0].repoVerified, true);

  const { index, stats, repoStateChanged } = buildIndex({
    index: seeded,
    entries: [],
    repoState: {
      checkedAt: 2,
      modules: { demo_mod: { repoUrl: REPO_OK.repoUrl, repoVerified: false, repoCheckedAt: 1800000000000 } },
    },
  });
  assert.equal(index.modules[0].repoVerified, false);
  assert.equal(stats.repoStateApplied, 1, '改了几处要能看见（CI 日志是唯一的复核入口）');
  assert.equal(repoStateChanged.length, 1);
  assert.equal(repoStateChanged[0].id, 'demo_mod');

  const again = buildIndex({ index: seeded, entries: [] });
  assert.deepEqual(again.index.modules, seeded.modules, '不传 repoState 时行为必须与从前一致');
  assert.equal(again.stats.repoStateApplied, 0);
});

test('仓库 ⑨：main --repo-state —— 坏状态文件退出 3（不当「没有状态」），缺失当没有', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-state-'));
  const pendingDir = path.join(dir, 'pending');
  const indexFile = path.join(dir, 'json', 'modules.json');
  fs.mkdirSync(pendingDir, { recursive: true });
  fs.mkdirSync(path.dirname(indexFile), { recursive: true });
  fs.writeFileSync(indexFile, `${JSON.stringify(emptyIndex, null, 2)}\n`, 'utf8');
  fs.writeFileSync(path.join(pendingDir, 'a.json'), JSON.stringify(entry({ id: 'a_mod' })), 'utf8');

  // 缺文件 = 这套复验还没跑起来（或这个仓库没有这一步），当「没有状态」而不是失败
  assert.equal(main(['--pending', pendingDir, '--index', indexFile, '--repo-state', path.join(dir, 'nope.json')]), 0);

  // 读不懂的状态是**故障**，不是「没有状态」：静默当空会把复验结论悄悄丢掉，
  // 于是绿标该撤的撤不掉 —— 那种失败没有日志，只有「怎么还绿着」。
  const before = fs.readFileSync(indexFile, 'utf8');
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, '{ not json', 'utf8');
  assert.equal(main(['--pending', pendingDir, '--index', indexFile, '--repo-state', bad]), 3);
  assert.equal(fs.readFileSync(indexFile, 'utf8'), before, '读不懂状态时一个字节都不许写');

  const badShape = path.join(dir, 'bad-shape.json');
  fs.writeFileSync(badShape, JSON.stringify({ modules: [] }), 'utf8');
  assert.equal(main(['--pending', pendingDir, '--index', indexFile, '--repo-state', badShape]), 3);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('仓库 ⑩：validate-index 校验新字段的类型与依赖（坏值必须报出来，不许静默放行）', () => {
  const good = buildIndex({
    index: emptyIndex,
    entries: [entry({
      ...REPO_OK, repoLicense: 'MIT', updateJson: 'https://acme.example/u.json',
      versions: [{ ...v1, repoTag: 'v1', repoDigest: `sha256:${sha(1)}`, auto: true, autoVia: 'repo' }],
    })],
  }).index;
  const clean = validateIndex(good);
  assert.equal(clean.ok, true, clean.errors.join('；'));
  assert.equal(good.modules[0].repoCoversLatest, true);

  const mutate = (fn) => {
    const d = structuredClone(good);
    fn(d.modules[0]);
    return validateIndex(d).errors.join('；');
  };
  const cases = [
    [(m) => { m.repoUrl = 'http://github.com/acme/demo'; }, /repoUrl/],
    [(m) => { m.repoUrl = 'https://github.com/acme/demo/'; }, /repoUrl/],
    [(m) => { delete m.repoVerified; }, /repoVerified/],
    [(m) => { m.repoCheckedAt = 0; }, /repoCheckedAt/],
    [(m) => { m.repoLicense = ''; }, /repoLicense/],
    [(m) => { m.repoCoversLatest = false; }, /repoCoversLatest/],
    [(m) => { m.repoCoversLatest = 'yes'; }, /repoCoversLatest/],
    [(m) => { m.updateJson = 'ftp://x/u.json'; }, /updateJson/],
    [(m) => { delete m.repoUrl; }, /仓库派生字段|repoUrl/],
    [(m) => { m.versions[0].repoDigest = `sha256:${sha(9)}`; }, /repoDigest/],
    [(m) => { m.versions[0].autoVia = 'git'; }, /autoVia/],
    [(m) => { delete m.versions[0].autoVia; }, /autoVia/],
    [(m) => { delete m.versions[0].auto; }, /auto/],
    [(m) => { m.versions[0].repoTag = ''; }, /repoTag/],
  ];
  for (const [fn, re] of cases) {
    const errs = mutate(fn);
    assert.match(errs, re, `坏值必须报出来：${fn.toString()}`);
  }
});
