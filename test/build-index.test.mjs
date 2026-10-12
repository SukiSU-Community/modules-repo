import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  buildIndex, normalizeEntry, isApproved,
  collectPendingFiles, markApproved, parseArgs, main,
  APPROVAL_FIELD, APPROVED_STATUS, HUMAN_APPROVED_STATUS,
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
  // 人工放行走同一个字段，但 status 不同、且必须署名
  assert.equal(isApproved({ [APPROVAL_FIELD]: { status: HUMAN_APPROVED_STATUS, by: 'gh:yufeng-liang@1234' } }), true);
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
  const a = buildIndex({ index: emptyIndex, entries: [entry()] });
  const b = buildIndex({ index: emptyIndex, entries: [entry()], dispositions: ledger() });
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
