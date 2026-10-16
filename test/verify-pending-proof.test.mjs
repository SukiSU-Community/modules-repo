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

/* ---------------------------------------------------------------- workflow */

const WF = path.resolve(import.meta.dirname, '../.github/workflows/audit.yml');

test('audit.yml 接线：复核只吃 pending-changed/pending，排在 locate 之后扫描之前，且不是 continue-on-error', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  // locate 的文件集来自 `--no-renames --diff-filter=AM` 的 base..head diff —— main 上没被本
  // PR 碰过的历史 pending 永远不会被拷进 pending-changed/pending。这是「旧条目不受影响」的
  // 构造性证明；而「拷漏了怎么办」由下面那条范围自算的接线负责，两者缺一不可。
  assert.match(wf, /--diff-filter=AM/);
  assert.match(wf, /cp "\$f" "pending-changed\/pending\/\$REL"/);

  const cmd = wf.match(/node "[^"\n]*verify-pending-proof\.mjs"\s+\S+/);
  assert.ok(cmd, 'workflow 必须调用 verify-pending-proof.mjs');
  assert.match(cmd[0], /pending-changed\/pending/,
    '只许检查本 PR 新增/修改的集合；指向整棵 pending/ 会把历史条目一起判死');
  assert.ok(wf.indexOf('定位投稿元数据') < wf.indexOf('verify-pending-proof.mjs'), '必须接在 locate 之后');
  assert.ok(wf.indexOf('verify-pending-proof.mjs') < wf.indexOf('运行 scan.mjs'), '必须排在扫描之前');

  const start = wf.indexOf('id: proof');
  assert.ok(start >= 0, '复核步必须声明 id: proof');
  const rest = wf.slice(start);
  const end = rest.search(/\n {6}- (?:name|uses):/);
  const block = rest.slice(0, end === -1 ? rest.length : end);
  assert.ok(!block.includes('continue-on-error'), '这条检查不许 continue-on-error');
  assert.match(block, /ACTOR: \$\{\{ github\.event\.pull_request\.user\.login \}\}/);
  assert.match(block, /--require-actor "\$REQUIRE_ACTORS"/);
  assert.match(block, /--actor "\$ACTOR"/);
});

/** 取出 proof 步整块（从 `id: proof` 到下一个同级步骤之前）。 */
function proofBlock(wf) {
  const start = wf.indexOf('id: proof');
  assert.ok(start >= 0, '复核步必须声明 id: proof');
  const rest = wf.slice(start);
  const end = rest.search(/\n {6}- (?:name|uses):/);
  return rest.slice(0, end === -1 ? rest.length : end);
}

test('locate 的那条 diff 带 --no-renames —— 改名带编辑不许被折叠成 R 而一条都不打印', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  const line = wf.match(/^ *PENDING=\$\(git diff .*--diff-filter=AM.*$/m);
  assert.ok(line, 'locate 里那条 git diff 得能找到（改写 workflow 时同步这条测试）');
  assert.match(line[0], /--no-renames/,
    '少了这个 flag：pending/demo/1.json 改名 + 改 id 会被 git 判成 R0xx，--diff-filter=AM 什么都不输出，'
    + '于是 found=false、复核整步不跑、approve 退出 0（见上面夹具那条真 git 证明）');
  assert.match(line[0], /"\$\{PENDING_DIR\}\/\*\*\/\*\.json"/, '路径白名单仍然由 PENDING_DIR 推导');
});

test('proof 步不再挂在 locate 的 found 上，并把「查哪些文件」交给脚本自己算', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  const block = proofBlock(wf);
  assert.match(block, /^ {8}if: github\.event_name == 'pull_request'$/m,
    '每个 PR 都跑：found=false 正是攻击者能挑出来的形状，把 if 挂回 found 等于让覆盖断言永远不开火');
  assert.ok(!block.includes('locate.outputs.found'), '不许再读 locate 的 found 来决定这一步跑不跑');
  assert.match(block, /BASE_SHA: \$\{\{ steps\.pin\.outputs\.base_sha \}\}/,
    '范围要比的 base 取自 pin 步已经解析并钉过的 commit，不在这里重新 origin/<ref> 一次');
  assert.match(block, /--scope-base "\$BASE_SHA"/);
  assert.match(block, /--scope-head HEAD/);
  assert.match(block, /--scope-dir "\$\{P\}pending"/,
    '范围要比的 pending 目录必须与 locate 的 PENDING_DIR 同源（都由 PREFIX 推导），否则两边比的不是同一棵树');
});

/** 取出某个步骤整块（从它的 `id: <name>` 到下一个同级步骤之前）。 */
function stepBlock(wf, idLine) {
  const start = wf.indexOf(idLine);
  assert.ok(start >= 0, `workflow 里找不到 ${idLine}`);
  const rest = wf.slice(start);
  const end = rest.search(/\n {6}- (?:name|uses):/);
  return rest.slice(0, end === -1 ? rest.length : end);
}

test('pin 只挂在 pull_request 上：dispatch 用自己这一份扫描器，而 PR 那三道闸一道都没少', () => {
  // 手动触发是给维护者做线上验证的那条路（`workflow_dispatch` 需要 write 权限，投稿者拿不到）。
  // 它天然没有 base_ref，所以「钉回 base」这一步在 dispatch 上没有对象 —— 但不能因此把整步删掉：
  // PR 那条路上「base 必须是 main」「钉回 base」「钉完再 diff 复核」三道闸都得原样在场。
  const wf = fs.readFileSync(WF, 'utf8');
  const block = stepBlock(wf, 'id: pin');
  assert.match(block, /^ {8}if: github\.event_name == 'pull_request'$/m,
    'pin 必须只在 PR 事件上跑；否则 dispatch 会撞在闸门一（base_ref 为空）上，这条路今天就是这样死的');
  assert.match(block, /闸门一/);
  assert.match(block, /git fetch --no-tags --depth=200 origin "\$BASE_REF"/);
  assert.match(block, /git diff --quiet "\$BASE_SHA" -- audit scripts json/);
  // 开了这条路不等于顺手开了合并：publish 仍然只认 audit 自己产出的 auto-approve。
  const pub = wf.slice(wf.indexOf('  publish:'));
  assert.match(pub, /if: needs\.audit\.outputs\.found == 'true' && needs\.audit\.outputs\.action == 'auto-approve'/,
    'dispatch 没有 PR 上下文；合并那一步的准入条件不许因为这条路被松动');
  // proof 早就只挂 PR（那条上面已钉）⇒ dispatch 不会去查凭据，也不会假绿：它连 pending 都不读。
  assert.match(stepBlock(wf, 'id: proof'), /^ {8}if: github\.event_name == 'pull_request'$/m);
});

/* --------------------------------------------------------- 与母本 / Worker 的对齐 */
const TEMPLATE = path.resolve(import.meta.dirname, '../../audit/workflows/audit.yml');

test('生效副本与 contrib/audit/workflows/audit.yml 母本只差开头 4 行标题（两边必须一起改）', (t) => {
  // 没有任何东西把这两份钉在一起 —— 母本的注释只是「说必须一起改」，那就由这条测试来当那个东西。
  // 索引仓库单独克隆时母本不在树上，那是正常形态，跳过而不是失败。
  if (!fs.existsSync(TEMPLATE)) return t.skip('母本不在这个 checkout 里（standalone 克隆的正常形态）');
  const body = (p) => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n').split('\n').slice(4).join('\n');
  const head = (p) => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n').split('\n').slice(0, 4).join('\n');
  assert.equal(body(TEMPLATE), body(WF),
    '除开头 4 行标题说明外必须逐字一致：改了这份没同步母本，下一次复制回去会把修过的东西冲掉');
  assert.match(head(WF), /^# 模块投稿安全审核流水线\n/, '生效副本的标题不带「（模板）」');
  assert.match(head(TEMPLATE), /^# 模块投稿安全审核流水线（模板）\n/);
  assert.notEqual(head(WF), head(TEMPLATE), '差异只许落在开头 4 行的标题里');
});

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

test('actor 白名单住在 workflow 变量里（默认值是核实过的 App 登录名），不住在脚本常量里', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  // 默认值 = 2026-10-12 用 gh api repos/SukiSU-Community/modules-repo/pulls/30 --jq .user.login
  // 从线上一份真 PR 的载荷里核实的值（见 task-13 回报）。可被 vars.SUBMISSION_PR_ACTORS 覆盖。
  assert.match(wf, /REQUIRE_ACTORS: \$\{\{ vars\.SUBMISSION_PR_ACTORS \|\| 'sukisu-module-submissions\[bot\]' \}\}/);
  const script = fs.readFileSync(path.resolve(import.meta.dirname, '../scripts/verify-pending-proof.mjs'), 'utf8');
  assert.ok(!script.includes('sukisu-module-submissions'),
    '脚本里不许烧死 actor 名 —— 白名单必须来自调用方，换 App/换仓库不用改代码');
});
