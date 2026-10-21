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
  OWNERSHIP_VIAS, canonicalProofSet, proofPrefixForSet, PROOF_PREFIX_LEN_V2,
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

/* ------------------------------------------------ bio-set：v2 集合口令（§15 / §17.5） */
// 这批用例是 2026-10-21 与 Worker「一次投稿多模块」那一条**同一轮**加的：Worker 侧一旦让
// pending 的 ownership.via 出现 'bio-set'，这一侧只认 'bio' 就会把批量投稿开出来的 PR 全拒。
// 老那批发 'bio' 的用例期望值一个字没动 —— 换代次序是「读的一侧扩成旧值 ∪ 新值」，不是换掉旧值。

const SET_ZIP_1 = ZIP_A;
const SET_ZIP_2 = '2898d907fba3a01bbe9e078e73fb9c20c33a69fc322d062c61e826f2798e3621';
const SET_ZIP_3 = 'f1e2d3c4b5a69788796a5b4c3d2e1f0011223344556677889900aabbccddeeff';

/** 期望值由测试自己算（与上面 wantPrefix 同一条纪律：不从被测函数取）。 */
const wantSetPrefix = (items) => {
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  const canon = [...items].sort((a, b) => (a.id === b.id ? cmp(a.zipSha, b.zipSha) : cmp(a.id, b.id)))
    .map((i) => `${i.id}:${i.zipSha}`).join(',');
  return createHash('sha256').update(`sukisu-proof-v2:${canon}`, 'utf8').digest('hex').slice(0, 12);
};

/** 批量投稿写出的一枚 pending：Worker 形状（sha 在 versions[0]），via='bio-set'，前缀是整套共用的那枚。 */
const setEntry = (id, sha, prefix) => entry({
  id,
  versions: [{ version: 'v1', versionCode: 1, sha256: sha, size: 10, time: 1791600000000 }],
  ownership: { nonce: 'abc123', proofPrefix: prefix, via: 'bio-set', verifiedAt: 2 },
});

const setBatch = (prefix = undefined) => {
  const items = [
    { id: 'aaa', zipSha: SET_ZIP_1 },
    { id: 'kkk', zipSha: SET_ZIP_2 },
    { id: 'mmm', zipSha: SET_ZIP_3 },
  ];
  const p = prefix ?? wantSetPrefix(items);
  return { prefix: p, batch: items.map((i) => setEntry(i.id, i.zipSha, p)), items };
};

test('bio-set：一枚集合口令覆盖整套 —— 三条各带同一 12 位前缀，逐条复算都过', () => {
  const { batch, prefix } = setBatch();
  assert.equal(prefix.length, 12, 'v2 前缀长度是 12（§15 第 4 条：从 8 位扩到 12 位）');
  assert.equal(OWNERSHIP_VIAS.includes('bio'), true, "旧值 'bio' 不许在这一轮退役（换代次序第一条）");
  assert.equal(OWNERSHIP_VIAS.includes('bio-set'), true);
  for (const e of batch) {
    assert.deepEqual(checkPendingProof(e, { batch }), { ok: true }, e.id);
  }
});

test('bio-set：投递顺序不是判据 —— 声明集按 id 升序，乱序递同样复算通过', () => {
  const { batch } = setBatch();
  const shuffled = [batch[2], batch[0], batch[1]];
  for (const e of shuffled) assert.deepEqual(checkPendingProof(e, { batch: shuffled }), { ok: true }, e.id);
  // canon 本身是排序不变得到的：把这条钉住，别让「按调用方给的顺序拼」混进来
  const a = canonicalProofSet([{ id: 'kkk', zipSha: SET_ZIP_2 }, { id: 'aaa', zipSha: SET_ZIP_1 }]);
  const b = canonicalProofSet([{ id: 'aaa', zipSha: SET_ZIP_1 }, { id: 'kkk', zipSha: SET_ZIP_2 }]);
  assert.equal(a, b);
  assert.equal(a, `aaa:${SET_ZIP_1},kkk:${SET_ZIP_2}`, '规范串的逐字形状：id:sha 用逗号连接');
});

test('bio-set：两代前缀长度互不通用 —— 8 位前缀走 v2 被拒，12 位前缀走 v1 同样被拒', () => {
  // 攻击形状：拿一条 v1 单枚口令的产物改个 via 冒充「这套是我一整套投的」。
  const one = setEntry('aaa', SET_ZIP_1, wantPrefix('aaa', SET_ZIP_1));
  const v = checkPendingProof(one, { batch: [one] });
  assert.equal(v.ok, false);
  assert.match(v.error, /12 位小写十六进制/);

  // 反方向：拿一枚真的 12 位集合前缀走 v1 那支 —— v1 的 8 位复算对不上，也是拒。
  const { batch, prefix } = setBatch();
  const back = { ...batch[0], ownership: { ...batch[0].ownership, via: 'bio' } };
  const w = checkPendingProof(back, { batch: [back] });
  assert.equal(w.ok, false);
  assert.match(w.error, /8 位小写十六进制/);
  assert.equal(prefix.length, 12);
});

test('bio-set：判不了集合就是拒 —— 没有 ctx.batch 时不降级成形状检查', () => {
  const { batch } = setBatch();
  // 少了调用方给的这一批：这一支只剩「12 个十六进制字符」那一句，等于没有 (a) 层。
  const noCtx = checkPendingProof(batch[0]);
  assert.equal(noCtx.ok, false);
  assert.match(noCtx.error, /ctx\.batch|同批/);
});

test('bio-set：枚数不是判据，整套的字节才是 —— N=1 合法，而三枚的前缀只递一枚复算必不通过', () => {
  // §15「口令 v2 一套一串、长度恒 19 与枚数无关」：单枚批量（manifest 带 1 枚）走的还是集合口令。
  const one = [{ id: 'aaa', zipSha: SET_ZIP_1 }];
  const p1 = wantSetPrefix(one);
  const e1 = setEntry('aaa', SET_ZIP_1, p1);
  assert.deepEqual(checkPendingProof(e1, { batch: [e1] }), { ok: true },
    'N=1 的一套必须过：把它当「少于 2 枚不是一套」拒掉，就会把单枚批量投稿全拒');

  // 反方向：这一枚的前缀本来是三枚那套算的 ⇒ 整套少两枚就算出另一个前缀 ⇒ 拒（少递那一格）。
  const { batch } = setBatch();
  const alone = checkPendingProof(batch[0], { batch: [batch[0]] });
  assert.equal(alone.ok, false);
  assert.match(alone.error, /复算不符/);
  assert.match(alone.error, /这套共 1 枚/, '文案要把复算用的枚数交出来，否则运维分不清「拆开投」与「口令算错」');
  // 只补回一枚（少递）同样红：整套的 3 枚缺一枚都不是同一套
  const two = checkPendingProof(batch[0], { batch: batch.slice(0, 2) });
  assert.equal(two.ok, false);
  assert.match(two.error, /proofPrefix/);
});

test('bio-set：换整套里任何一枚的字节就换整套 —— 一枚换成兄弟那枚的包，那一枚与它的兄弟都对不上', () => {
  const { batch } = setBatch();
  const swapped = batch.map((e, i) => (i === 1
    ? setEntry(e.id, SET_ZIP_3, batch[0].ownership.proofPrefix) // 内容换了，前缀照抄不动
    : e));
  for (const e of swapped) {
    const v = checkPendingProof(e, { batch: swapped });
    assert.equal(v.ok, false, e.id);
    assert.match(v.error, /proofPrefix/);
  }
  // 反过来证一次：真的按换掉后的整套算前缀，就能过（挡住「实现把复算写死成永远不过」那种假安全）
  const fixed = wantSetPrefix([{ id: 'aaa', zipSha: SET_ZIP_1 }, { id: 'kkk', zipSha: SET_ZIP_3 }, { id: 'mmm', zipSha: SET_ZIP_3 }]);
  const okBatch = [setEntry('aaa', SET_ZIP_1, fixed), setEntry('kkk', SET_ZIP_3, fixed), setEntry('mmm', SET_ZIP_3, fixed)];
  for (const e of okBatch) assert.deepEqual(checkPendingProof(e, { batch: okBatch }), { ok: true }, e.id);
});

test('bio-set：声明集不起来的那些形状各拒一次（重复 id / 成员带两个 sha / 成员缺 id）', () => {
  const { prefix } = setBatch();
  const dup = [setEntry('aaa', SET_ZIP_1, prefix), setEntry('aaa', SET_ZIP_2, prefix)];
  assert.match(checkPendingProof(dup[0], { batch: dup }).error, /重复|id/);

  const twoShas = [
    setEntry('aaa', SET_ZIP_1, prefix),
    setEntry('kkk', SET_ZIP_2, prefix),
    { ...setEntry('mmm', SET_ZIP_3, prefix), versions: [{ versionCode: 1, sha256: SET_ZIP_3 }, { versionCode: 2, sha256: SET_ZIP_1 }] },
  ];
  const v = checkPendingProof(twoShas[0], { batch: twoShas });
  assert.equal(v.ok, false, '一枚口令只覆盖一枚包：成员带两个 sha 时无法重建声明集');
  assert.match(v.error, /2 个 sha256|一枚口令只覆盖一枚包/);

  const noId = [setEntry('aaa', SET_ZIP_1, prefix), { ...setEntry('kkk', SET_ZIP_2, prefix), id: '  ' }];
  assert.match(checkPendingProof(noId[0], { batch: noId }).error, /id/);
});

test('bio-set：未知 via 一律拒 —— 扩的是白名单，不是「未知取值当放行」', () => {
  const { batch } = setBatch();
  for (const via of ['bio-set-v3', 'Bio', 'bio ', '', null, 'self_report']) {
    const e = { ...batch[0], ownership: { ...batch[0].ownership, via } };
    const v = checkPendingProof(e, { batch });
    assert.equal(v.ok, false, JSON.stringify(via));
    assert.match(v.error, /ownership/, JSON.stringify(via));
  }
});

test('bio-set：CLI 走真目录 —— 整批三枚 → 0；把其中一枚换成别的包 → 1 且点名那一枚', () => {
  const dir = mk('vpp-set-ok-');
  let dir2;
  try {
    const { batch } = setBatch();
    batch.forEach((e, i) => write(dir, `${['aaa', 'kkk', 'mmm'][i]}/1.json`, e));
    assert.equal(main([dir], { log: quiet() }), 0, '整批进目录必须全过：批量投稿开出来的 PR 不能被判据拒掉');

    dir2 = mk('vpp-set-bad-');
    const broken = batch.map((e, i) => (i === 2
      ? { ...e, versions: [{ versionCode: 1, sha256: '9'.repeat(64) }] } // 口令没换，字节换了
      : e));
    broken.forEach((e, i) => write(dir2, `${['aaa', 'kkk', 'mmm'][i]}/1.json`, e));
    const log = quiet();
    assert.equal(main([dir2], { log }), 1);
    assert.match(allLogs(log), /mmm\/1\.json/);
    assert.match(allLogs(log), /proofPrefix/);
  } finally { rm(dir); rm(dir2); }
});

test('bio-set：与 Worker 那份实现逐字同算法（读得到 contrib/worker 时跨实现比一次）', (t) => {
  const src = path.resolve(import.meta.dirname, '../../worker/src/proof.ts');
  if (!fs.existsSync(src)) return t.skip('worker/src/proof.ts 不在这个 checkout 里');
  // 必须在**子进程**里读那份 TS，不在本进程 import：本进程先 import proof.ts 会把 Node 的 TS
  // 加载切到 strip-only，于是后面那条「Worker 真写出的 pending JSON 能过本步复算」就再也读不了
  // worker/src/index.ts（parameter property 需要 transform）—— 拿一条用例的绿换另一条变 skip，
  // 是比红更难看见的退化。2026-10-21 实测到这一步会 skip，所以改成起子进程。
  const items = [
    { id: 'mmm', zipSha: SET_ZIP_3 },
    { id: 'aaa', zipSha: SET_ZIP_1 },
    { id: 'kkk', zipSha: SET_ZIP_2 },
  ];
  let out;
  try {
    out = execFileSync(process.execPath, ['--input-type=module', '-e', [
      `const m = await import(${JSON.stringify(pathToFileURL(src).href)});`,
      `const items = ${JSON.stringify(items)};`,
      'process.stdout.write(JSON.stringify({',
      '  canon: m.canonicalProofSet(items),',
      '  prefix: await m.proofPrefixV2(items),',
      '  len: m.PROOF_PREFIX_LEN_V2,',
      '}));',
    ].join('\n')], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    return t.skip(`这个 Node 读不了 Worker 的 TS 源码：${String(e.stderr || e.message).slice(0, 120)}`);
  }
  const w = JSON.parse(out);
  assert.equal(w.prefix, proofPrefixForSet(items),
    '复算端与写入端算出两个前缀 = 线上每条批量投稿都会被拒，而单测全绿');
  assert.equal(w.canon, canonicalProofSet(items), '规范串漂一个字，两侧对「同一套」就不是同一套');
  assert.equal(w.len, PROOF_PREFIX_LEN_V2, '前缀长度这一格漂了：12 位是 §15 第 4 条拍定的值');
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

test('pin 闸门二合不动时不许吞掉 git 的原话 —— 那句「冲突」曾经是一句没有依据的诊断', () => {
  // 2026-10-17 run 39009735993（重开的那条来源核对 canary）红在 `把扫描器…钉回 base 版本`，
  // 打出来的是一句 workflow 自己写的 `PR 分支与当前 origin/main 冲突`。我事后在本地把两种形状
  // 都复现过：head 落后 base 一个提交、以及直接取 PR 的 merge ref —— **两种都合得干净**（exit 0）。
  // 也就是说那句话当时是不是真的，谁都不知道，包括这条 workflow 自己：原来的写法是
  // `if ! git merge … >/dev/null 2>&1`，git 到底说了什么被整条抹掉，剩下的一律念成「内容冲突」。
  // 这一格改的只有观测：闸的行为（合不动 → abort → exit 1）一个字没动。
  const block = stepBlock(fs.readFileSync(WF, 'utf8'), 'id: pin');
  assert.ok(!/git merge --no-commit --no-ff "\$BASE_SHA" >\/dev\/null/.test(block),
    '那条 >/dev/null 2>&1 一回来，「冲突」这句就又可能只是一句没有依据的猜测');
  // ⚠️ 证据边界：这一格是**结构断言**，不是真跑那一步 —— 要真跑得造一个内容与 main 冲突的 PR 形状，
  // 而那次线上失败的形状我本地复现不出来，所以造不出可比的夹具。（下面那格能真跑，因为它复现的是
  // 「需要新建合并提交 + 没有 committer 身份」这一种，那种形状本地造得出来。）
  for (const must of [
    'MERGE_OUT="$(git -c user.name=modules-audit-pin -c user.email=modules-audit-pin@invalid.invalid merge --no-commit --no-ff "$BASE_SHA" 2>&1)"',
    `printf '%s\\n' "$MERGE_OUT"`,
    'git merge --abort 2>/dev/null || true',
  ]) assert.ok(block.includes(must), `这一格必须原样在场：${must}`);
  // 行为没被顺手放宽：合不动仍然是拒。
  assert.match(block, /exit 1/);
  assert.ok(block.includes('不替 git 改口'), '那句诊断的措辞要说明：git 的原话才是原因');
});

// 这一格真跑那一句 merge（不是结构断言）。形状来自 run 39022231657 的 attempt 2：
// 重跑一条 base 已前进的旧 PR ⇒ 这句 merge 需要**新建一个合并提交** ⇒ 没有 committer 身份就红。
test('pin 闸门二在「没有 git 身份 + 需要新建合并提交」时也必须合得动', () => {
  const block = stepBlock(fs.readFileSync(WF, 'utf8'), 'id: pin');
  const m = /MERGE_OUT="\$\((git [^"]*?merge --no-commit --no-ff "\$BASE_SHA" 2>&1)\)"/.exec(block);
  assert.ok(m, '得能从 pin 那一步里取出那句 merge，才能逐字跑它：\n' + block.slice(0, 400));
  const fixedCall = 'MERGE_OUT="$(' + m[1] + ')"';
  const bareCall = fixedCall.replace('-c user.name=modules-audit-pin -c user.email=modules-audit-pin@invalid.invalid ', '');
  // 起法必须逐字等于生产：那一步写的是 `if ! MERGE_OUT="$(…)" ; then` —— 直接 `MERGE_OUT="$(…)"` 再加
  // `set -e` 会在赋值那一行就退出，git 的原话根本来不及打（我第一版就是这么起的，红得没有输出可读）。
  const wrap = (call, sha) => [
    'set -euo pipefail',
    `BASE_SHA=${sha}`,
    `if ! ${call}; then`,
    '  printf \'%s\\n\' "$MERGE_OUT"',
    '  echo MERGE_FAILED',
    '  exit 3',
    'fi',
    'echo MERGE_OK',
  ].join('\n');

  const mk = () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pin-identity-'));
    const G = (...a) => execFileSync('git', a, { cwd: dir, encoding: 'utf8' });
    G('init', '-q', '-b', 'main');
    fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'json', 'modules.json'), '{}\n');
    G('add', '-A');
    // 这两次提交要身份 —— runner 上也有（actions/checkout 会设好），缺的是 merge 那一步的 committer。
    G('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'base');
    G('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'main 前进一格');
    G('branch', 'canary');
    G('checkout', '-q', 'canary');
    G('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'PR 自己的提交');
    G('checkout', '-q', 'main');
    G('-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-q', '--allow-empty', '-m', 'main 又前进一格');
    G('checkout', '-q', 'canary');
    const baseSha = G('rev-parse', 'main').trim();
    return { dir, baseSha };
  };
  const emptyConfig = path.join(os.tmpdir(), 'pin-none-gitconfig');
  fs.writeFileSync(emptyConfig, '');
  const noIdEnv = () => {
    const env = {
      ...process.env,
      GIT_CONFIG_GLOBAL: emptyConfig,
      GIT_CONFIG_NOSYSTEM: '1',
      HOME: os.tmpdir(),
      USERPROFILE: os.tmpdir(),
    };
    // 不许有人用环境变量把身份偷偷带进来（那样这两格都会假绿）—— 只在这格剥，不动测试进程自己的 env。
    for (const k of ['GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'EMAIL']) delete env[k];
    return env;
  };

  const run = (dir, sha, bare) => {
    const script = wrap(bare ? bareCall : fixedCall, sha);
    try {
      return { rc: 0, out: String(execFileSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
        { cwd: dir, encoding: 'utf8', env: noIdEnv() })) };
    } catch (e) {
      return { rc: e.status === undefined ? -1 : e.status, out: String((e.stdout || '') + (e.stderr || '')) };
    }
  };

  const fixed = mk();
  const r1 = run(fixed.dir, fixed.baseSha, false);
  assert.match(r1.out, /MERGE_OK/, '带占位身份的那句 merge 必须合得动，git 原话：' + r1.out);
  assert.equal(fs.existsSync(path.join(fixed.dir, '.git', 'MERGE_HEAD')), true,
    '合过了就该留下 MERGE_HEAD（--no-commit 停在提交之前，不写任何提交）');
  fs.rmSync(fixed.dir, { recursive: true, force: true });

  const bare = mk();
  const r2 = run(bare.dir, bare.baseSha, true);
  // 这一格断言的是**因果**，不是「一定红」：在某些机器上 git 能从别处凑出身份，那时 r2 会是 MERGE_OK。
  // 但一旦它红，原因只许是身份 —— 那句 workflow 自己写的「冲突」不许又复活成默认解释。
  if (r2.rc !== 0) {
    assert.match(r2.out, /MERGE_FAILED/, '红也要红在那句 if 里：' + r2.out);
    assert.match(r2.out, /identity unknown|empty ident|auto-detect email/i,
      '无身份的那句 merge 红了，但红的原因不是身份，这格的证据链就断了：' + r2.out);
  }
  fs.rmSync(bare.dir, { recursive: true, force: true });
});

test('写回 PR 的那两步只挂 pull_request —— dispatch 里没有 PR 可写，撞上去是通道自己坏', () => {
  // 2026-10-16 run 38890758068（第一条 dispatch canary）实测：AI 那一步 success、分流 success、
  // artifact 也传了，然后 发布 PR 评论 抛 `HttpError: Not Found` —— 因为它取的是
  // `context.issue.number`，而 dispatch 事件既没有 issue 也没有 pull_request，那个数是 0。
  // 后果不是「少一条评论」：整条 audit 作业判红 → approve 第一步按 fail-closed 再红一次，
  // 维护者拿不到「这条包过没过检」的读数。所以这两步在 dispatch 上必须**不跑**，而不是跑了再炸。
  const wf = fs.readFileSync(WF, 'utf8');
  const blockOf = (name) => {
    const start = wf.indexOf(`- name: ${name}`);
    assert.ok(start >= 0, `workflow 里必须存在名为「${name}」的步骤（改名要一起改这里）`);
    const rest = wf.slice(start);
    const end = rest.search(/\n {6}- (?:name|uses):/);
    return rest.slice(0, end === -1 ? rest.length : end);
  };
  for (const name of ['发布 PR 评论', '打标签']) {
    const block = blockOf(name);
    assert.match(block, /^ {8}if: github\.event_name == 'pull_request' && !cancelled\(\) && steps\.locate\.outputs\.found == 'true'$/m,
      `${name}：PR 上下文与 found 两个条件都要在，少一半就把线上验证路和自动放行路绑死在一起`
      + '（`!cancelled()` 是后加的：见下面那条「判据红那一发留下什么」—— 但加它的前提是 PR 条件仍在最前，dispatch 上这两步必须不跑）');
    assert.match(block, /actions\/github-script@v7/);
  }
});

test('判据红的那一发留下什么 —— 证据位与呈现位三步放宽（上传报告 / 发布 PR 评论 / 打标签），判据位两步不放宽', () => {
  // 2026-10-16 run 38908245528（坏配置的失败面 canary，修完 -e 那一发）实测：
  // `AI 安全员复核 => success`、`分流决策 => failure` 都对，但后面 `处置台账核对 / 上传报告 /
  // 上传待合并 pending / 发布 PR 评论 / 打标签` 全 `skipped` —— GitHub 对「前一步红」的默认处理
  // 就是跳过后续步骤，而那两步挂的 `if` 里没有 `always()` 家族的任何东西。
  // 后果是**最该留证据的那一发什么都没留**：整份 `audit-out/`（扫描报告 + AI 五态产物）只活在
  // runner 日志里，日志会过期，而投稿者那边只剩一个红叉。
  // 放宽的三格各买到什么，按「它会不会改变批准结论」划线：
  // - 上传报告：原样落盘的字节，不解释、不参与批准；
  // - 发布 PR 评论 / 打标签：给人读的文本与队列里的颜色。**这两格能加是欠的三件事补齐之后**
  //   （#48 写完 fail-closed 判据 → 三件事里的 ②③ 有地方渲染；run 39007438609 量到 ①），
  //   所以真正的钉子不在这一发 assert 的这几行 `if:`，而在 `test/audit-presentation.test.mjs`
  //   那批**真跑这段脚本**的用例：没有结论的那一发必须不念等级、不念处置，还要点名先红的是哪一步。
  // 判据位两步**不许**跟着加：
  // - 处置台账核对：它自己就是判据，跑在红之后只会把「谁挡的」变成两条互相覆盖的红。
  // - 上传待合并 pending：唯一的消费者是 publish，而它只认 `action == 'auto-approve'`
  //   ⇒ 红的那一发没有消费者（fail-closed 写的是 block），放宽它只是多传一份没人读的东西。
  const wf = fs.readFileSync(WF, 'utf8');
  // 只认**步骤级 `if:` 那一行**，不在整块里扫 `!cancelled` / `always()`：块尾会把下一步前面的
  // 那段注释一起吃进来（本文件那条「耦合钉子」用例就是被自己的注释打红的，同一个坑不踩第二次）。
  const ifLineOf = (name) => {
    const m = stepBlock(wf, `- name: ${name}`).match(/^ {8}if: .*$/m);
    assert.ok(m, `步骤「${name}」必须有步骤级 if`);
    return m[0];
  };
  const FOUND = "        if: steps.locate.outputs.found == 'true'";
  const PR_CANCELLED = "        if: github.event_name == 'pull_request' && !cancelled() && steps.locate.outputs.found == 'true'";

  assert.equal(ifLineOf('上传报告'),
    "        if: ${{ !cancelled() && steps.locate.outputs.found == 'true' }}",
    '报告 artifact 必须在判据红之后仍然上传（写成 `${{ }}` 形式是不让值以 `!` 开头 —— YAML 里那是标签起始符；这条是规范级说法，裸写法我没实测过）');
  const rep = stepBlock(wf, '- name: 上传报告');
  assert.match(rep, /name: module-audit-report/);
  assert.match(rep, /path: audit-out\//);

  assert.equal(ifLineOf('发布 PR 评论'), PR_CANCELLED,
    '投稿者屏幕上只有红叉就是这一格没跑；它渲染什么由 audit-presentation 那批用例钉，不由这条 if 钉');
  assert.equal(ifLineOf('打标签'), PR_CANCELLED,
    '同一发；LABEL 为空时那一步必须自己 return，不许拿空串去 addLabels（那条由下面的用例钉）');
  assert.equal(ifLineOf('处置台账核对（下架 / 黑名单）'), FOUND, '判据位不放宽：它在红之后再跑只会把「谁挡的」念成两条互相覆盖的红');
  assert.equal(ifLineOf('上传待合并 pending'), FOUND, '这份 artifact 的唯一消费者是 publish，而它只认 auto-approve');
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
