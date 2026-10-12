/**
 * 处置台账判据的单测。
 *
 * 跑法：node --test test/dispositions.test.mjs   （或仓库根 `node --test`）
 *
 * 这一份实现同时被 build-index 的推导、verify-index-pr 的重推导和 revoke.mjs 使用，
 * 所以这里钉住的行为就是「线上索引里留着什么」的行为。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import {
  DISPOSITIONS_SCHEMA,
  DispositionError,
  loadDispositions,
  matchAny,
  matchDisposition,
  parseDispositions,
  filterVersions,
  isModuleLevel,
} from '../scripts/dispositions.mjs';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function entry(over = {}) {
  return {
    id: 'demo',
    coolapkUid: '10086001',
    versions: [{ version: 'v1.0', versionCode: 100, sha256: SHA_A }],
    ...over,
  };
}

function d(over = {}) {
  return {
    kind: 'revoke',
    id: 'demo',
    reason: 'malware',
    by: 'gh:yufengliang@comment123',
    at: '2026-10-11T00:00:00.000Z',
    ...over,
  };
}

function doc(...list) {
  return { schema: DISPOSITIONS_SCHEMA, lastUpdate: 0, dispositions: list };
}

/* ------------------------------------------------ 读入与校验（全部失败关闭） */

test('台账文件不存在 → 空台账（项目第一天还没有处置记录，这是合法状态）', () => {
  const missing = path.join(os.tmpdir(), `nope-${process.pid}-${Date.now()}.json`);
  assert.equal(fs.existsSync(missing), false);
  assert.deepEqual(loadDispositions(missing), []);
});

test('文件存在但读不懂 → 抛，绝不能当空台账放过', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'disp-'));
  const f = path.join(dir, 'dispositions.json');
  fs.writeFileSync(f, '{ 这不是 JSON', 'utf8');
  assert.throws(() => loadDispositions(f), DispositionError);
  // 复活已下架内容比冻住索引严重得多：静默当空台账 = 一次坏 JSON 就把所有下架抹掉。
  fs.writeFileSync(f, JSON.stringify(doc(d())), 'utf8');
  assert.equal(loadDispositions(f).length, 1);
});

test('schema 不认识 → 抛（不许拿一份旧口径的台账来判新索引）', () => {
  assert.throws(() => parseDispositions({ schema: 'v0', dispositions: [] }), /未知 schema/);
  assert.throws(() => parseDispositions({ dispositions: [] }), /未知 schema/);
  assert.throws(() => parseDispositions([]), /台账必须是对象/);
  assert.throws(() => parseDispositions({ schema: DISPOSITIONS_SCHEMA }), /必须是数组/);
});

test('选择器全空 → 抛：它等价于「匹配一切」，绝不能生效', () => {
  assert.throws(() => parseDispositions(doc(d({ id: undefined }))), /至少给出 id \/ sha256 \/ coolapkUid/);
  assert.throws(() => parseDispositions(doc(d({ id: '   ' }))), /至少给出/);
});

test('versionCode 必须跟着 id：脱离 id 的版本号会变成按数字全局下架', () => {
  // 另一个选择器在场，才能走到这条检查（否则先被判「选择器全空」挡掉）。
  assert.throws(
    () => parseDispositions(doc(d({ id: undefined, coolapkUid: '10086001', versionCode: 1 }))),
    /versionCode 必须与 id 同时出现/,
  );
  assert.throws(
    () => parseDispositions(doc(d({ id: undefined, sha256: SHA_A, versionCode: 1 }))),
    /versionCode 必须与 id 同时出现/,
  );
});

test('字段形状不合格的条目逐条抛（sha256 / uid / by / reason / at / kind）', () => {
  assert.throws(() => parseDispositions(doc(d({ sha256: 'xyz' }))), /64 位十六进制/);
  assert.throws(() => parseDispositions(doc(d({ coolapkUid: '12' }))), /4~12 位数字/);
  assert.throws(() => parseDispositions(doc(d({ by: '  ' }))), /by 不能为空/);
  assert.throws(() => parseDispositions(doc(d({ reason: '我不喜欢它' }))), /reason 必须是公示分类之一/);
  assert.throws(() => parseDispositions(doc(d({ at: '昨天' }))), /at 必须是带时区/);
  assert.throws(() => parseDispositions(doc(d({ at: undefined }))), /at 必须是带时区/);
  // 不带时区的写法在不同机器上会解析成不同时刻（Date.parse 按本机时区），
  // 而处置记录的时间必须是确定 instant —— 所以这里必须拒，而不是宽容。
  assert.throws(() => parseDispositions(doc(d({ at: '2026-10-11 00:00:00' }))), /at 必须是带时区/);
  assert.throws(() => parseDispositions(doc(d({ kind: 'ban' }))), /kind 必须是 revoke \/ deny/);
  assert.throws(() => parseDispositions(doc('字符串')), /条目必须是对象/);
  assert.throws(() => parseDispositions(doc(d({ versionCode: 'abc' }))), /versionCode 不是数字/);
});

test('归一化：sha 转小写、at 统一成 ISO、缺 note 给空串、可选 verify 保留', () => {
  const [one] = parseDispositions(
    doc(d({ sha256: SHA_A.toUpperCase(), at: '2026-10-11T08:00:00+08:00', verify: 'gh api repos/o/r/issues/comments/1' })),
  );
  assert.equal(one.sha256, SHA_A);
  assert.equal(one.at, '2026-10-11T00:00:00.000Z', '+08:00 必须换算成同一个 UTC 时刻');
  assert.equal(one.note, '');
  assert.equal(one.verify, 'gh api repos/o/r/issues/comments/1');
});

/* ------------------------------------------------------------------ 匹配 */

test('按 sha256 命中：换皮重投（改了 id 不改文件）照样被同一条抓住', () => {
  const hit = matchDisposition(d({ id: undefined, sha256: SHA_A }), entry({ id: 'brand-new-name' }));
  assert.ok(hit);
  assert.equal(hit.via, 'sha256');
  assert.equal(hit.versionCode, 100);
});

test('按 id+versionCode 命中：只抹那一个版本，同 id 其它版本不受影响', () => {
  const dd = d({ versionCode: 100 });
  assert.equal(matchDisposition(dd, entry())?.via, 'id+versionCode');
  assert.equal(matchDisposition(dd, entry({ versions: [{ versionCode: 101, sha256: SHA_B }] })), null);
  assert.equal(matchDisposition(dd, entry({ id: 'other' })), null);
});

test('按 id 命中整个模块；按 coolapkUid 命中这个人的一切投稿', () => {
  assert.equal(matchDisposition(d(), entry())?.via, 'id');
  const deny = d({ kind: 'deny', id: undefined, coolapkUid: '10086001' });
  assert.equal(matchDisposition(deny, entry({ id: 'anything-else' }))?.via, 'coolapkUid');
  assert.equal(matchDisposition(deny, entry({ coolapkUid: '9999999' })), null);
});

test('都不命中 → null（宁可不抹，也不许把无关模块牵连进来）', () => {
  assert.equal(matchDisposition(d({ id: 'not-this' }), entry()), null);
  assert.equal(matchDisposition(d({ sha256: SHA_B }), entry()), null);
  assert.equal(matchAny([], entry()), null);
  assert.equal(matchDisposition(null, entry()), null);
  assert.equal(matchDisposition(d(), null), null);
});

test('选择器是 AND：指到 sha256 就不许顺手抹掉同 id 的其它版本', () => {
  // 这一条是修 bug 时补的：写成 OR 时，「revoke id=demo sha256=<坏产物>」会把 demo
  // 的所有版本一起抹掉 —— 误伤好版本，而且台账上看不出越权。
  const precise = d({ sha256: SHA_A });
  assert.equal(matchDisposition(precise, entry())?.via, 'id+sha256');
  const other = entry({ versions: [{ versionCode: 101, sha256: SHA_B }] });
  assert.equal(matchDisposition(precise, other), null, '同一 id 的另一个产物不受影响');
  assert.equal(matchDisposition(d(), other)?.via, 'id', '要抹整个 id 就只写 id');
});

test('matchAny 按台账顺序取第一个命中（写台账的人靠顺序表达优先级）', () => {
  const first = d({ id: undefined, sha256: SHA_A, reason: 'malware' });
  const second = d({ reason: 'policy' });
  assert.equal(matchAny([first, second], entry()).matched, first);
  assert.equal(matchAny([second, first], entry()).matched, second);
});

test('版本级过滤：只抹命中台账的那一条产物，模块本身留着其它版本', () => {
  const mod = {
    id: 'demo',
    versions: [
      { versionCode: 101, sha256: SHA_B },
      { versionCode: 100, sha256: SHA_A },
    ],
  };
  const { removed, keptVersions } = filterVersions([d({ versionCode: 100 })], mod);
  assert.equal(removed.length, 1);
  assert.equal(removed[0].version.versionCode, 100);
  assert.deepEqual(keptVersions.map((v) => v.versionCode), [101]);
});

test('版本级过滤只管产物级处置：模块级（只写 id）由 isModuleLevel 那条路处理', () => {
  const mod = { id: 'demo', versions: [{ versionCode: 101 }, { versionCode: 100 }] };
  // 只写 id 的处置是「整条下架」，不该在逐版本过滤里被拆成两次版本删除：
  // 那条路对 `versions: []` 的模块壳会静默失效（见 isModuleLevel 的注释）。
  assert.equal(isModuleLevel(d()), true);
  assert.equal(isModuleLevel(d({ sha256: SHA_A })), false);
  assert.equal(isModuleLevel(d({ versionCode: 100 })), false);
  const whole = filterVersions([d()], mod);
  assert.equal(whole.removed.length, 0, '模块级不进版本过滤');
  assert.equal(whole.keptVersions.length, 2);
  assert.equal(matchAny([d()], mod)?.via, 'id', '整条下架走模块级匹配');
});
