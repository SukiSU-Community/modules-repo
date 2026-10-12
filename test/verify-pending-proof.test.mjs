// verify-pending-proof.mjs 的单测 —— 这是 CI 侧「pending 条目来自 Worker」唯一的闸（设计文档 §14.2）。
// 和 verify-index-pr.test.mjs 同一个立场：测试的重点不是它放行什么，而是它挡住哪几种伪造。
// 每条用例都是「少做一件事」的形状：少了 pledge、少了 ownership、口令对不上包、
// 来源不是 Worker、范围算不出来 —— 任何一种都得有人变红。
// 运行：node --test test/verify-pending-proof.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  PLEDGE_VERSIONS, proofPrefixFor, checkPendingProof, checkActor, main,
  derivePendingScope, isIngestedPendingPath,
} from '../scripts/verify-pending-proof.mjs';

// ── 期望值由测试自己用 node:crypto 算，不从被测函数取 ──
// 实现改了公式（少冒号、换拼接顺序、取别的长度）时，这里复算出来的期望值不会跟着变，
// 对应断言立刻红。这与 worker/src/proof.test.ts、前端 selftest 是同一条纪律。
const wantPrefix = (id, sha) =>
  createHash('sha256').update(`${id}:${sha}`, 'utf8').digest('hex').slice(0, 8);

// 内嵌黄金值：与 worker/src/proof.test.ts:33 同一份（sha256("zip-a") 的整包摘要）。
// 三份实现（Worker / 前端 / 这条 CI 复算）必须对同一对输入给出同一个前缀。
const ZIP_A = 'e37287b0ddbda7edb55845acc6de4244cd82e14df5824bdd71007a452a7cbaab';

test('公式对齐全场：demo + ZIP_A → 4f91ceb8（测试自算与实现各钉一次）', () => {
  assert.equal(wantPrefix('demo', ZIP_A), '4f91ceb8');
  assert.equal(proofPrefixFor('demo', ZIP_A), '4f91ceb8');
});

/** Worker 实际写出的 pending 形态（buildPendingJson）：sha256 在 versions[0] 里。 */
const entry = (over = {}) => ({
  id: 'demo',
  name: 'Demo', author: 'a', description: 'd',
  versions: [{
    version: 'v1', versionCode: 1,
    zipUrl: `https://github.com/o/r/releases/download/t/${ZIP_A}.zip`,
    size: 10, time: 1791600000000, sha256: ZIP_A,
  }],
  source: 'https://www.coolapk.com/u/10086001',
  uploader: 'u', coolapkUid: '10086001',
  pledge: { version: 'pledge-v1', atMs: 1791600000000 },
  ownership: { nonce: 'abc123', proofPrefix: wantPrefix('demo', ZIP_A), via: 'bio', verifiedAt: 2 },
  identity: {},
  ...over,
});

const rm = (d) => fs.rmSync(d, { recursive: true, force: true });
const mk = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const write = (dir, rel, obj) => {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) + '\n', 'utf8');
  return p;
};
const quiet = () => {
  const out = [];
  const err = [];
  return { out, err, log: (...a) => out.push(a.join(' ')), error: (...a) => err.push(a.join(' ')) };
};
const allLogs = (l) => l.out.concat(l.err).join('\n');

/* ---------------------------------------------------------------- 纯判定核心 */

test('完整合法条目（Worker 形态，sha256 在 versions[0]）→ ok', () => {
  assert.deepEqual(checkPendingProof(entry()), { ok: true });
});

test('简化条目（顶层 sha256 + versionCode）→ ok；顶层与 versions 并存时两份都要对得上', () => {
  assert.deepEqual(checkPendingProof({
    id: 'demo', versionCode: 1, sha256: ZIP_A,
    pledge: { version: 'pledge-v1' },
    ownership: { via: 'bio', proofPrefix: wantPrefix('demo', ZIP_A) },
  }), { ok: true });

  // versions 里藏一个口令没覆盖的包：条目一旦收录，索引里那个版本同样带着公示与追责的份量，
  // 凭据没证明过它就不许搭车。
  const v = checkPendingProof(entry({
    versions: [
      ...entry().versions,
      { version: 'v2', versionCode: 2, sha256: '0'.repeat(64) },
    ],
  }));
  assert.equal(v.ok, false);
  assert.match(v.error, /proofPrefix/);
});

test('缺 pledge → 拒，文案点名 pledge；pledge.version 不在已发布集合 → 同样拒', () => {
  const e1 = entry();
  delete e1.pledge;
  assert.equal(checkPendingProof(e1).ok, false);
  assert.match(checkPendingProof(e1).error, /pledge/);

  assert.match(checkPendingProof(entry({ pledge: { version: 'pledge-v0' } })).error, /pledge/);
  // 形状都不对的 pledge（裸字符串，没有 version）也是拒，不是「读不到就当没要求」
  assert.match(checkPendingProof(entry({ pledge: 'pledge-v1' })).error, /pledge/);
  assert.ok(PLEDGE_VERSIONS.includes('pledge-v1'));
});

test('缺 ownership / via 不是 bio / ownership 畸形 → 一律拒（畸形是被跳过还是被拒，就是这条在盯）', () => {
  const e1 = entry();
  delete e1.ownership;
  const v1 = checkPendingProof(e1);
  assert.equal(v1.ok, false);
  assert.match(v1.error, /ownership/);

  assert.match(checkPendingProof(entry({
    ownership: { ...entry().ownership, via: 'self_report' },
  })).error, /ownership/);

  // ownership 是字符串 / 是 null：读不懂就是拒。若实现图省事写「没有 ownership 对象就跳过」，
  // 这一条会绿 —— 那正是「skip instead of reject」的形状。
  assert.match(checkPendingProof(entry({ ownership: 'bio' })).error, /ownership/);
  const e4 = entry();
  e4.ownership = null;
  assert.match(checkPendingProof(e4).error, /ownership/);

  const e5 = entry();
  delete e5.ownership.proofPrefix;
  assert.match(checkPendingProof(e5).error, /ownership/);
});

test('proofPrefix 与复算不符 → 拒（期望值来自测试自己的 node:crypto）', () => {
  const v = checkPendingProof(entry({
    ownership: { ...entry().ownership, proofPrefix: wantPrefix('demo', '0'.repeat(64)) },
  }));
  assert.equal(v.ok, false);
  assert.match(v.error, /proofPrefix/);
  // 文案把两边的值都给出来：绿勾不够，要人能复核
  assert.match(v.error, new RegExp(wantPrefix('demo', '0'.repeat(64))));
  assert.match(v.error, new RegExp(wantPrefix('demo', ZIP_A)));
});

test('同一个口令换个包就不认：口令按 ZIP_A 算，条目里换成 ZIP_B → 拒', () => {
  const ZIP_B = '2898d907fba3a01bbe9e078e73fb9c20c33a69fc322d062c61e826f2798e3621';
  const e = entry();
  e.versions[0].sha256 = ZIP_B;
  const v = checkPendingProof(e);
  assert.equal(v.ok, false);
  assert.match(v.error, /proofPrefix/);
});

test('sha256 不是 64 位小写十六进制 → 拒（大写、短、非十六进制各钉一次）', () => {
  const shapes = [ZIP_A.toUpperCase(), ZIP_A.slice(0, 63), 'z'.repeat(64)];
  for (const bad of shapes) {
    const e = entry();
    e.versions[0].sha256 = bad;
    // 注意：坏 sha256 必须先被形状检查拒掉，而不是侥幸靠复算不过蒙混 ——
    // 文案要点名 sha256。
    const v = checkPendingProof(e);
    assert.equal(v.ok, false, bad);
    assert.match(v.error, /sha256/, bad);
  }
  // 什么 sha256 都没有：无从复算就是拒，不是「没有就不比」
  const v = checkPendingProof(entry({ versions: [{ versionCode: 1 }] }));
  assert.equal(v.ok, false);
  assert.match(v.error, /sha256/);
});

test('checkActor：来源不一致 → 拒；一致 → 过；空白名单/空 actor → 拒（fail closed）', () => {
  assert.equal(checkActor('github-actions[bot]', 'someone@gmail.com').ok, false);
  assert.match(checkActor('github-actions[bot]', 'someone@gmail.com').error, /来源|actor/);
  assert.equal(checkActor('github-actions[bot]', 'github-actions[bot]').ok, true);
  assert.equal(checkActor('a[bot], b[bot]', 'b[bot]').ok, true);
  assert.equal(checkActor('a[bot]', '').ok, false); // 拿不到开启者 = 判不了 = 拒
  assert.equal(checkActor('', 'x').ok, false);      // 配了要求却是空的 = 不许当成放行
});

/* ---------------------------------------------------------------------- CLI */

test('CLI：目录里多个条目，任一条拒就整体拒，且报错点名是哪一个路径', () => {
  const dir = mk('vpp-multi-');
  try {
    write(dir, 'good/1.json', entry());
    const bad = entry({ id: 'evil_mod' });
    delete bad.pledge;
    write(dir, 'evil/9.json', bad);
    const log = quiet();
    const rc = main([dir], { log });
    assert.equal(rc, 1);
    assert.match(allLogs(log), /evil\/9\.json/);
    assert.match(allLogs(log), /pledge/);
    assert.match(allLogs(log), /::error::/);
  } finally { rm(dir); }
});

test('CLI：全部合法 → 0；读不懂的 JSON 是拒不是跳', () => {
  const dir = mk('vpp-ok-');
  try {
    write(dir, 'demo/1.json', entry());
    assert.equal(main([dir], { log: quiet() }), 0);
    write(dir, 'broken/2.json', '{ 半个 JSON');
    const log = quiet();
    assert.equal(main([dir], { log }), 1);
    assert.match(allLogs(log), /broken\/2\.json/);
  } finally { rm(dir); }
});

test('CLI：来源核对接在进入路径上 —— 不一致 1，一致 0', () => {
  const dir = mk('vpp-actor-');
  try {
    write(dir, 'demo/1.json', entry());
    const log = quiet();
    assert.equal(main([dir, '--require-actor', 'github-actions[bot]', '--actor', 'someone@gmail.com'], { log }), 1);
    assert.match(allLogs(log), /someone@gmail\.com/);
    assert.equal(main([dir, '--require-actor', 'github-actions[bot],sukisu-module-submissions[bot]',
      '--actor', 'sukisu-module-submissions[bot]'], { log: quiet() }), 0);
    // 没给 --actor 也是拒：来源核对不许以「读不到」为默认放行
    assert.equal(main([dir, '--require-actor', 'github-actions[bot]'], { log: quiet() }), 1);
  } finally { rm(dir); }
});

test('CLI 只吃交给它的那个目录：main 检出树旁边的历史 pending（无 ownership）不受影响', () => {
  // 复刻 checkout 后的目录形状：整棵 pending/ 里是本轮之前就投稿的老条目（没有 pledge/ownership
  // 三件套，形状与线上 PR #30 被索引消费前完全一致），而本 PR 新增/修改的集合在
  // pending-changed/pending/（locate 的 diff 语义保证只有这些）。
  const root = mk('vpp-tree-');
  try {
    const legacy = entry();
    delete legacy.pledge;
    delete legacy.ownership;
    delete legacy.identity;
    write(root, 'pending/e2e_probe_p04/7301872.json', legacy);
    write(root, 'pending-changed/pending/demo/1.json', entry());
    const log = quiet();
    const rc = main([path.join(root, 'pending-changed', 'pending'),
      '--require-actor', 'sukisu-module-submissions[bot]',
      '--actor', 'sukisu-module-submissions[bot]'], { log });
    assert.equal(rc, 0, allLogs(log));
    // 反过来：把同一个老目录直接指给它，就必须红 —— 「不受影响」靠的是作用范围，
    // 不是实现认了旧形状。
    assert.equal(main([path.join(root, 'pending')], { log: quiet() }), 1);
  } finally { rm(root); }
});

/* ------------------------------------------------------------ 范围自算（§14.2 的第三道） */
// 本步不能再把「查哪些文件」交给 locate 那条 git diff —— 那条命令的分类方式是攻击者能选的。
// 这一组用真 git 仓库钉住两件事：① 那个形状确实存在（AM 看不到、ls-tree 两棵树比得出）；
// ② 看漏了就必须红，而不是安静地「这次没投稿」。
const G = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8' });

/**
 * base 上有一条合法 pending/demo/1.json，head 分支按 shape 换成攻击者的形状。
 * shape: rename = demo/1.json 改名成 evil/1.json，只动 id 与凭据（自洽伪造）；
 *        touch  = 路径不动，只改一处正文。
 * @returns {{dir: string, base: string}}
 */
function scopeFixture(shape) {
  const dir = mk('vpp-scope-');
  G(dir, 'init', '-q', '-b', 'main');
  G(dir, 'config', 'user.name', 't');
  G(dir, 'config', 'user.email', 't@example.invalid');
  write(dir, 'pending/demo/1.json', entry());
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'base：main 上已有的合法投稿');
  const base = G(dir, 'rev-parse', 'HEAD').trim();
  G(dir, 'checkout', '-qb', 'feature/submit');
  if (shape === 'rename') {
    const moved = entry({
      id: 'evil_mod',
      ownership: { ...entry().ownership, proofPrefix: wantPrefix('evil_mod', ZIP_A) },
    });
    write(dir, 'pending/evil/1.json', moved);
    fs.rmSync(path.join(dir, 'pending', 'demo'), { recursive: true, force: true });
  } else if (shape === 'touch') {
    const f = path.join(dir, 'pending', 'demo', '1.json');
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace('"uploader": "u"', '"uploader": "v"'), 'utf8');
  } else {
    throw new Error(`未知 shape：${shape}`);
  }
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '夹带投稿');
  return { dir, base };
}

/** 复刻 workflow 里那条 locate 命令（flag 由 caller 决定带不带 --no-renames）。 */
function locateDiff(dir, { noRenames }) {
  const args = ['diff', '--name-only'];
  if (noRenames) args.push('--no-renames');
  args.push('--diff-filter=AM', 'HEAD~1', 'HEAD', '--', 'pending/**/*.json');
  return G(dir, ...args).trim();
}

test('夹具先证明危险形状是真的：改名带编辑 = git 判 R，AM 过滤一条都不打印', () => {
  const { dir } = scopeFixture('rename');
  try {
    const status = G(dir, 'diff', '--name-status', 'HEAD~1', 'HEAD').trim();
    // 这一条是夹具的自检：git 的重命名启发式哪天不认这个形状了，这里先红并说明原因，
    // 而不是让下面那条「AM 看不到」的断言变成莫名的失败。
    assert.match(status, /^R\d{2,3}\tpending\/demo\/1\.json\tpending\/evil\/1\.json$/m, status);
    assert.equal(locateDiff(dir, { noRenames: false }), '',
      '修复前的 locate：R 不会被 --diff-filter=AM 打印 —— found=false，复核整步不跑');
    assert.equal(locateDiff(dir, { noRenames: true }), 'pending/evil/1.json',
      '加了 --no-renames：同一笔改动是「删旧 + 增新」，新路径照常进入选择集');
  } finally { rm(dir); }
});

test('范围自算是 rename-agnostic 的：改名带编辑与同路径改正文都逃不掉', () => {
  const rename = scopeFixture('rename');
  try {
    const r = derivePendingScope({ cwd: rename.dir, baseRef: rename.base, headRef: 'HEAD', pendingDir: 'pending' });
    assert.equal(r.ok, true, r.error);
    assert.deepEqual(r.paths, ['pending/evil/1.json'],
      'ls-tree 只看两棵树：evil/1.json 是新出现的 = 必须查；demo/1.json 被删掉不算新增');
  } finally { rm(rename.dir); }

  const touch = scopeFixture('touch');
  try {
    const same = derivePendingScope({ cwd: touch.dir, baseRef: touch.base, headRef: 'HEAD', pendingDir: 'pending' });
    assert.deepEqual(same.paths, ['pending/demo/1.json'], '路径没动但正文变了，同样算夹带投稿');
    const noChange = derivePendingScope({ cwd: touch.dir, baseRef: 'HEAD', headRef: 'HEAD', pendingDir: 'pending' });
    assert.deepEqual(noChange.paths, [], '同一棵树比自己是空的（「本 PR 没投稿」判得出来）');
  } finally { rm(touch.dir); }
});

test('范围自算的判据照消费方列：.JSON 收录、大写路径认，点开头与 node_modules 不要求', () => {
  assert.equal(isIngestedPendingPath('pending/evil/1.JSON'), true, 'build-index 的 isPendingJson 比的是 toLowerCase 之后的后缀');
  assert.equal(isIngestedPendingPath('pending/evil/1.json'), true);
  assert.equal(isIngestedPendingPath('pending/evil/1.txt'), false);
  assert.equal(isIngestedPendingPath('pending/.example.json'), false);
  assert.equal(isIngestedPendingPath('pending/node_modules/x/1.json'), false);
  assert.equal(isIngestedPendingPath('pending/.git-dir/1.json'), false);
  assert.equal(isIngestedPendingPath('pending/demo'), false);

  // 只有 `.JSON` 这一条新增也必须进范围：pathspec 是大小写敏感的，locate 拷不出它，
  // 于是「范围里有它」正是让覆盖断言开火的前提。
  const trees = { BASE: [], HEAD: ['pending/evil/1.JSON'] };
  // git 参数形状：['ls-tree','-r','--name-only', <ref>, '--', <dir>] —— ref 在 args[3]
  const run = (args) => (args[0] === 'ls-tree'
    ? { ok: true, out: trees[args[3]].join('\n') + (trees[args[3]].length ? '\n' : '') }
    : { ok: false, error: '不该被调用' });
  const r = derivePendingScope({ baseRef: 'BASE', headRef: 'HEAD', pendingDir: 'pending' }, { runGit: run });
  assert.deepEqual(r.paths, ['pending/evil/1.JSON']);
});

test('范围自算读不出来时是拒，不是「没有 pending」（空 base ref / git 失败都停住）', () => {
  assert.equal(derivePendingScope({ baseRef: '', headRef: 'HEAD', pendingDir: 'pending' }).ok, false);
  const run = (args) => ({ ok: false, error: 'not a valid object name' });
  const r = derivePendingScope({ baseRef: 'BASE', headRef: 'HEAD', pendingDir: 'pending' }, { runGit: run });
  assert.equal(r.ok, false);
  assert.match(r.error, /范围推不出来/);
  // 两边都有但正文读不出来：不能当成「一致」放过去
  const trees = { BASE: ['pending/a/1.json'], HEAD: ['pending/a/1.json'] };
  const partial = (args) => (args[0] === 'ls-tree'
    ? { ok: true, out: trees[args[3]].join('\n') + '\n' }
    : { ok: false, error: 'fatal: bad file' });
  assert.equal(derivePendingScope({ baseRef: 'BASE', headRef: 'HEAD', pendingDir: 'pending' }, { runGit: partial }).ok, false);
});

test('覆盖断言：改过却没被拷进 pending-changed/pending 的条目 → ::error:: 退出 1', () => {
  const { dir, base } = scopeFixture('rename');
  const root = mk('vpp-cover-');
  try {
    // 复刻「locate 那条 diff 坏了」的现场：拷出来的目录里只有一条无关的合法历史条目。
    write(root, 'pending-changed/pending/legacy/1.json', entry());
    const log = quiet();
    const rc = main([path.join(root, 'pending-changed', 'pending'),
      '--require-actor', 'sukisu-module-submissions[bot]', '--actor', 'sukisu-module-submissions[bot]',
      '--scope-base', base, '--scope-head', 'HEAD', '--scope-dir', 'pending', '--cwd', dir], { log });
    assert.equal(rc, 1, allLogs(log));
    assert.match(allLogs(log), /evil\/1\.json/);
    assert.match(allLogs(log), /没有出现在/);
    assert.match(allLogs(log), /::error::/);

    // 对照组：同一个仓库、同一条目，只要真的被拷进来（= 修好的 locate 会做的事），
    // 覆盖断言就不开火，剩下的逐条复算与来源核对照常放行。
    write(root, 'pending-changed/pending/evil/1.json',
      entry({ id: 'evil_mod', ownership: { ...entry().ownership, proofPrefix: wantPrefix('evil_mod', ZIP_A) } }));
    const ok = quiet();
    assert.equal(main([path.join(root, 'pending-changed', 'pending'),
      '--require-actor', 'sukisu-module-submissions[bot]', '--actor', 'sukisu-module-submissions[bot]',
      '--scope-base', base, '--scope-head', 'HEAD', '--scope-dir', 'pending', '--cwd', dir], { log: ok }), 0, allLogs(ok));
  } finally { rm(dir); rm(root); }
});

test('大写扩展名的形状：既被逐条复算读到，也被覆盖断言点名', () => {
  const dir = mk('vpp-case-');
  const root = mk('vpp-case-root-');
  const repo = mk('vpp-case-repo-');
  try {
    // (1) 修好的 collectJsonFiles：`1.JSON` 不再被当成「不是元数据」跳过。
    write(dir, 'evil/1.JSON', entry({
      id: 'evil_mod',
      ownership: { ...entry().ownership, proofPrefix: 'deadbeef' }, // 不自洽，等着被拒
    }));
    const log = quiet();
    assert.equal(main([dir], { log }), 1, allLogs(log));
    assert.match(allLogs(log), /evil\/1\.JSON/);

    // (2) 合法的大写条目本身要放行（否则就是误红：消费方收它，我们也必须认它）。
    const d2 = mk('vpp-case2-');
    try {
      write(d2, 'demo/1.JSON', entry());
      assert.equal(main([d2], { log: quiet() }), 0);
    } finally { rm(d2); }

    // (3) 它没被拷进来时，覆盖断言要抓住（pathspec 大小写敏感，locate 就是拷不出它）。
    G(repo, 'init', '-q', '-b', 'main');
    G(repo, 'config', 'user.name', 't');
    G(repo, 'config', 'user.email', 't@example.invalid');
    write(repo, 'pending/demo/keep.json', entry());
    G(repo, 'add', '-A');
    G(repo, 'commit', '-qm', 'base');
    const base = G(repo, 'rev-parse', 'HEAD').trim();
    write(repo, 'pending/evil/1.JSON', entry({
      id: 'evil_mod',
      ownership: { ...entry().ownership, proofPrefix: wantPrefix('evil_mod', ZIP_A) },
    }));
    G(repo, 'add', '-A');
    G(repo, 'commit', '-qm', '夹带一条大写扩展名的投稿');
    // 现场复刻：locate 的 pathspec 过不了它，所以拷出来的目录里没有这条。
    write(root, 'pending-changed/pending/demo/keep.json', entry());
    const cover = quiet();
    const rc = main([path.join(root, 'pending-changed', 'pending'),
      '--require-actor', 'sukisu-module-submissions[bot]', '--actor', 'sukisu-module-submissions[bot]',
      '--scope-base', base, '--scope-head', 'HEAD', '--scope-dir', 'pending', '--cwd', repo], { log: cover });
    assert.equal(rc, 1, allLogs(cover));
    assert.match(allLogs(cover), /evil\/1\.JSON/);
    // 而那条 diff 确实看不见它 —— 这正是 (3) 必须由本步自己算范围的理由
    assert.equal(G(repo, 'diff', '--name-only', '--no-renames', '--diff-filter=AM', 'HEAD~1', 'HEAD',
      '--', 'pending/**/*.json').trim(), '');
  } finally { rm(dir); rm(root); rm(repo); }
});

test('空目录 = 拒：本步只在有事可检时被调用，「0 个文件」只能是选择集坏了', () => {
  const dir = mk('vpp-empty-');
  try {
    fs.mkdirSync(path.join(dir, 'pending-changed', 'pending'), { recursive: true });
    const log = quiet();
    const rc = main([path.join(dir, 'pending-changed', 'pending')], { log });
    assert.equal(rc, 1, allLogs(log));
    assert.match(allLogs(log), /一个 pending 元数据都没有/);
    assert.match(allLogs(log), /::error::/);
    // 目录压根不存在时同样是拒
    assert.equal(main([path.join(dir, 'nope')], { log: quiet() }), 1);
    // 但「独立推导确认没投稿」不算坏：那种情况退出 0，且不看目录存不存在
    const run = (args) => (args[0] === 'ls-tree'
      ? { ok: true, out: 'pending/demo/1.json\n' }
      : { ok: true, out: 'same' });
    const quietLog = quiet();
    assert.equal(main([path.join(dir, 'pending-changed', 'pending'),
      '--scope-base', 'BASE', '--scope-head', 'HEAD', '--scope-dir', 'pending'], { log: quietLog, runGit: run }), 0,
      allLogs(quietLog));
    assert.match(allLogs(quietLog), /没有新增\/修改的 pending/);
  } finally { rm(dir); }
});

/* --------------------------------------------------------- 与 Worker 的对齐 */

test('Worker 真写出的 pending JSON 能过本步复算（读得到 worker/src/index.ts 时）', async (t) => {
  // 手写夹具留着给 forks（那里没有 worker/），但键名口径漂了必须由这条先红：
  // Worker 改了字段名而 CI 没跟上时，线上每条投稿都会被拦，而单测全绿。
  const src = path.resolve(import.meta.dirname, '../../worker/src/index.ts');
  if (!fs.existsSync(src)) return t.skip('worker/src/index.ts 不在这个 checkout 里');
  let buildPendingJson;
  try {
    ({ buildPendingJson } = await import(pathToFileURL(src).href));
  } catch (e) {
    return t.skip(`这个 Node 读不了 Worker 的 TS 源码：${e.message}`);
  }
  if (typeof buildPendingJson !== 'function') return t.skip('worker/src/index.ts 没导出 buildPendingJson');
  const now = 1791600000000;
  const content = buildPendingJson({
    id: 'demo', name: 'Demo', version: 'v1', versionCode: 1, author: 'a', description: 'd',
    source: 'https://www.coolapk.com/u/10086001', uploader: 'u', coolapkUid: '10086001',
    pledge: { version: 'pledge-v1', atMs: now },
    ownership: { nonce: 'abcdef', proofPrefix: wantPrefix('demo', ZIP_A), via: 'bio', verifiedAt: now },
    identity: {}, sha256: ZIP_A, size: 10,
    zipUrl: `https://github.com/o/r/releases/download/demo-v1-1/${ZIP_A}.zip`,
    releaseTag: 'demo-v1', assetName: `${ZIP_A}.zip`, submittedAt: now,
  });
  const parsed = JSON.parse(content);
  assert.deepEqual(checkPendingProof(parsed), { ok: true },
    'Worker 自己写出的形状必须被 CI 复算放行 —— 这条红了就是「键名漂了、线上投稿全被拦」的提前报警');
  // 摘要只出现在 versions[].sha256（顶层没有这个键）：本步「每个版本都比一遍」的写法
  // 就是被这个形状逼出来的，把它钉住，别让「顺手改成只读顶层」蒙过 (a)。
  assert.equal(parsed.versions[0].sha256, ZIP_A);
  assert.ok(!('sha256' in parsed), 'Worker 的输出没有顶层 sha256 —— 简化条目那种形状是仓库内手写的另一支');
  // 手写的 entry() 与真输出的判据字段必须同集合，否则这份夹具在骗自己
  for (const k of ['id', 'versions', 'pledge', 'ownership']) {
    assert.ok(k in parsed && k in entry(), `Worker 输出与夹具的共有判据字段少了 ${k}`);
  }
  assert.equal(parsed.ownership.via, entry().ownership.via);
  assert.equal(parsed.pledge.version, entry().pledge.version);
  assert.deepEqual(Object.keys(parsed.ownership).sort(), Object.keys(entry().ownership).sort(),
    'ownership 的键集合漂了（改了名/加了必填键）—— 本步读的就是这几个键');
});
