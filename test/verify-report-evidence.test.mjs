// verify-report-evidence.mjs 的单测 —— 这一步是「下架的凭据」唯一的实质内容，
// 所以测试的重点是它对哪几种假象说了「不」。
// 运行：node --test test/verify-report-evidence.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';

import {
  verifyReportEvidenceDoc, checkOneHit, reviewLedgerPr, main,
  REPORT_EVIDENCE_SCHEMA, MAX_PACKAGES_PER_RUN,
} from '../scripts/verify-report-evidence.mjs';
import { parseDispositions } from '../scripts/dispositions.mjs';

const SHA = (h) => h.repeat(64).slice(0, 64);
const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');
const SEAL1 = 'a'.repeat(40);
const BY1 = `ci:audit@${SEAL1}`;

/* --------------------------------------------------------------- zip 夹具 */

/** 造一枚真 zip（stored + deflate 都支持），字节与偏移都是真的。 */
function buildZip(entries) {
  const chunks = [], central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const data = Buffer.isBuffer(e.content) ? e.content : Buffer.from(e.content, 'utf8');
    const method = e.method ?? 8;
    const comp = method === 8 ? deflateRawSync(data) : data;
    const crcVal = crc32Buf(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(method, 10);
    local.writeUInt32LE(crcVal, 14);
    local.writeUInt32LE(comp.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, name, comp);

    // 中心目录的字段布局与本地头**不一样**：crc 在 16、压缩后在 20、解压后在 24、名字长在 28
    // （各比本地头晚 2 字节）。这里抄本地头的偏移，parseZip 会把 crc 当名字长读成 0，
    // 于是「归档里没有这个条目」——而纯判据那几发用例是注了 readEntry 的，根本不会走到这。
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(method, 10);
    cen.writeUInt32LE(crcVal, 16);
    cen.writeUInt32LE(comp.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(offset, 42);
    central.push(cen, name);
    offset += local.length + name.length + comp.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, cd, eocd]);
}
function crc32Buf(buf) {
  let c, crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = (crc ^ buf[i]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (c ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * 一份「真能过」的举报证据记录 + 对应的 zip。
 * 引用是从条目里**切出来的真字节**，偏移与 sha256 现算，不抄常量。
 * `opts.id` 必须与台账里那条处置的 id 同一个 —— 复核第一步就对这一格。
 */
function fixtureDoc(entries = [{ name: 'customize.sh', content: '#!/system/bin/sh\nrm -rf /data/adb/magisk\necho done\n' }], quoteEntry = 0, quoteText = 'rm -rf /data/adb/magisk', opts = {}) {
  const id = opts.id || 'mod_x';
  const zip = buildZip(entries);
  const entryBuf = Buffer.isBuffer(entries[quoteEntry].content)
    ? entries[quoteEntry].content
    : Buffer.from(entries[quoteEntry].content, 'utf8');
  const off = entryBuf.indexOf(quoteText);
  assert.ok(off >= 0, '夹具里那句引用得真在条目里');
  const needle = Buffer.from(quoteText, 'utf8');
  const sha = sha256Hex(zip);
  const doc = {
    schema: REPORT_EVIDENCE_SCHEMA,
    reportId: 'r1',
    package: { id, versionCode: 3, sha256: sha, assetName: `${sha}.zip`, releaseTag: 'assets-v1', assetUrl: opts.assetUrl || `https://github.com/o/r/releases/download/assets-v1/${sha}.zip`, size: zip.length },
    verdict: {
      established: true,
      code: 'located',
      thresholds: { identified: true, locatedAll: true },
      misses: [],
      unreadableEntries: [],
      hits: [{ claimedFile: entries[quoteEntry].name, entry: entries[quoteEntry].name, entryOffset: off, quoteBytes: needle.length, quoteSha256: sha256Hex(needle), excerpt: quoteText }],
    },
  };
  const bytes = Buffer.from(JSON.stringify(doc, null, 2) + '\n', 'utf8');
  return { doc, zip, file: `evidence/${sha256Hex(bytes)}.json`, evidenceBytes: bytes, sha, id, quoteText, off };
}

/* ------------------------------------------------------- 纯判据那一条路 */

/** 条目字节：偏移处正好是那串引用，前后各补一段。 */
function entryOf(f) {
  return Buffer.concat([Buffer.alloc(f.off, 0x20), Buffer.from(f.quoteText, 'utf8'), Buffer.from('tail', 'utf8')]);
}

test('逐字节都对上 ⇒ 成立，且报出复核了几段', () => {
  const f = fixtureDoc();
  const entry = Buffer.concat([Buffer.alloc(f.off, 0x20), Buffer.from(f.quoteText, 'utf8'), Buffer.from('tail', 'utf8')]);
  const r = verifyReportEvidenceDoc(f.doc, { openPackage: () => f.zip, readEntry: () => entry });
  assert.equal(r.ok, true, r.problems.join('；'));
  assert.equal(r.checked, 1);
});

test('这条举报自己就不成立 ⇒ 不许拿它盖章（连包都不取）', () => {
  const f = fixtureDoc();
  const bad = { ...f.doc, verdict: { ...f.doc.verdict, established: false, code: 'evidence_not_in_package' } };
  let opened = 0;
  const r = verifyReportEvidenceDoc(bad, { openPackage: () => { opened++; return f.zip; }, readEntry: () => entryOf(f) });
  assert.equal(r.ok, false);
  assert.match(r.problems.join(), /这条举报自己就不成立/);
  assert.equal(opened, 0, '已经不成立就不该再花一次归档下载');
});

test('记录里有没定位到的引用 / 有解不出来的条目 ⇒ 都不成立', () => {
  const f = fixtureDoc();
  for (const over of [
    { misses: [{ quoteBytes: 3, quoteSha256: SHA('a') }] },
    { unreadableEntries: [{ name: 'classes.dex', reason: '太大' }] },
    { thresholds: { identified: true, locatedAll: false } },
  ]) {
    const doc = { ...f.doc, verdict: { ...f.doc.verdict, ...over } };
    assert.equal(verifyReportEvidenceDoc(doc, { openPackage: () => f.zip, readEntry: () => entryOf(f) }).ok, false, JSON.stringify(over));
  }
});

test('一条引用都没有 ⇒ 没有可复核的字节，不成立', () => {
  const f = fixtureDoc();
  const doc = { ...f.doc, verdict: { ...f.doc.verdict, hits: [] } };
  const r = verifyReportEvidenceDoc(doc, { openPackage: () => f.zip, readEntry: () => entryOf(f) });
  assert.equal(r.ok, false);
  assert.match(r.problems.join(), /一条定位到的引用都没有/);
});

test('取回来的包摘要与记录里的不是同一个 ⇒ 红，且不再去解条目', () => {
  const f = fixtureDoc();
  let read = 0;
  const r = verifyReportEvidenceDoc(f.doc, {
    openPackage: () => Buffer.concat([f.zip, Buffer.from('x')]),  // 动一个字节
    readEntry: () => { read++; return entryOf(f); },
  });
  assert.equal(r.ok, false);
  assert.match(r.problems.join(), /实算 sha256 是 .{12}，与记录里的/);
  assert.equal(read, 0, '包都不是同一个，解条目没有意义');
});

test('偏移越界 / 字节不同 / 坐标非法 ⇒ 三种「对不上」各自说清对不上在哪', () => {
  const f = fixtureDoc();
  const base = { openPackage: () => f.zip };
  const mk = (over) => {
    const doc = JSON.parse(JSON.stringify(f.doc));
    Object.assign(doc.verdict.hits[0], over);
    return doc;
  };
  const cases = [
    [mk({ entryOffset: 10_000 }), /切不出/],
    [mk({ quoteBytes: 5 }), /不是同一段/],
    [mk({ entryOffset: -1 }), /偏移不是非负整数/],
    [mk({ quoteBytes: 0 }), /长度不是正整数/],
    [mk({ quoteSha256: 'zz' }), /sha256 不是 64 位十六进制/],
  ];
  for (const [doc, re] of cases) {
    const r = verifyReportEvidenceDoc(doc, { ...base, readEntry: () => entryOf(f) });
    assert.equal(r.ok, false, JSON.stringify(doc.verdict.hits[0]));
    assert.match(r.problems.join(), re);
  }
});

test('条目解不出来 ⇒ 红，并把抛出的理由带回去', () => {
  const f = fixtureDoc();
  const r = verifyReportEvidenceDoc(f.doc, { openPackage: () => f.zip, readEntry: () => { throw new Error('不支持的压缩方式 99'); } });
  assert.equal(r.ok, false);
  assert.match(r.problems.join(), /不支持的压缩方式 99/);
});

test('schema 不是举报证据那一版 ⇒ 一句话挡下，不假装复核过', () => {
  const f = fixtureDoc();
  const r = verifyReportEvidenceDoc({ ...f.doc, schema: 'sukisu-evidence-v1' }, { openPackage: () => f.zip, readEntry: () => entryOf(f) });
  assert.equal(r.ok, false);
  assert.match(r.problems.join(), /sukisu-report-evidence-v1/);
});

test('checkOneHit：短引用与长引用都要按实算长度切，多一个字节都算不是同一段', () => {
  const bytes = Buffer.from('0123456789', 'utf8');
  const hit = (from, len) => ({ entry: 'e', entryOffset: from, quoteBytes: len, quoteSha256: sha256Hex(bytes.subarray(from, from + len)) });
  assert.equal(checkOneHit(hit(0, 4), bytes), null);
  assert.match(checkOneHit({ ...hit(0, 4), quoteBytes: 5 }, bytes), /不是同一段/);
});

/* ------------------------------------------------------------ 真 git 那一路 */

const G = (dir, ...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' });

function ledgerRepo(published = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rre-'));
  G(dir, 'init', '-q', '-b', 'main');
  G(dir, 'config', 'user.name', 't');
  G(dir, 'config', 'user.email', 't@example.invalid');
  fs.mkdirSync(path.join(dir, 'json'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: [] }, null, 2) + '\n');
  fs.writeFileSync(path.join(dir, 'json', 'modules.json'),
    JSON.stringify({ name: 't', lastUpdate: 1, modules: publishOf(published) }, null, 2) + '\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'base：空台账 + 已发布索引');
  return dir;
}

/**
 * 「base 的索引里用户真能下到的那一包」—— 逐字复核的对照物就是它。
 * 同一 id 的多枚产物会并到一个 module 的 versions 里（与真索引同形）。
 */
function publishOf(list) {
  const byId = new Map();
  for (const f of list) {
    const m = byId.get(f.id) || { id: f.id, versions: [] };
    m.versions.push({
      version: `v${f.versionCode ?? 3}`, versionCode: f.versionCode ?? 3, sha256: f.sha,
      zipUrl: `https://github.com/o/r/releases/download/assets-v1/${f.sha}.zip`,
    });
    byId.set(f.id, m);
  }
  return [...byId.values()];
}

/** 一条处置 + 它的证据文件，写成 C1（待盖）与 C2（盖章）两枚提交，复刻 Worker 要做的事。 */
function makeLedgerCommits(dir, f, entryOver = {}) {
  const writeLedger = (by) => {
    const entry = parseDispositions({
      schema: 'sukisu-dispositions-v2',
      dispositions: [{
        kind: 'revoke', reason: 'malware', by, at: '2026-10-22T00:00:00.000Z', id: 'mod_x', versionCode: 3,
        sha256: f.sha, note: '逐字复核夹具', subject: { coolapkUid: '12345678' }, evidence: [{ file: f.file }],
        ...entryOver,
      }],
    }, '夹具')[0];
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
      JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: [entry] }, null, 2) + '\n');
  };
  const put = (file, bytes) => {
    const abs = path.join(dir, ...file.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, bytes);
  };
  G(dir, 'checkout', '-qb', 'dispose/mod_x');
  writeLedger('ci:audit@pending');
  put(f.file, f.evidenceBytes);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C1：实体与证据，待盖章');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  writeLedger(`ci:audit@${c1}`);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C2：盖上 C1 的章');
  return { c1 };
}

/** 按记录里的 sha256 发对应的那一包；认不出就抛 —— 与生产同一条形状。 */
const depsForList = (list, over = {}) => ({
  download: over.download || (async (pkg) => {
    const f = list.find((x) => x.sha === String(pkg.sha256).toLowerCase());
    if (!f) throw new Error(`夹具只备了 ${list.map((x) => x.sha.slice(0, 12)).join(', ')} 这几包`);
    return f.zip;
  }),
  // readEntry 默认**不**注：让生产那份 readZipEntryBytes 去解真临时 zip —— 夹具造的是一枚真包，
  // 注掉它就等于只测了自己的桩。
  ...over.deps,
});
const depsFor = (f, over = {}) => depsForList([f], over);

test('真 git 两枚提交：C2 上复核成立，结论的键就是 C1', async () => {
  // 记录里那个 assetUrl 故意指到**别处**：取包必须用索引里那条 zipUrl，用了记录里的那一条就该红。
  const f = fixtureDoc([{ name: 'customize.sh', content: '#!/system/bin/sh\nrm -rf /data/adb/magisk\necho done\n' }], 0, 'rm -rf /data/adb/magisk', {
    assetUrl: 'https://github.com/evil-owner/evil-repo/releases/download/evil-tag/' + 'f'.repeat(64) + '.zip',
  });
  const dir = ledgerRepo([f]);
  const { c1 } = makeLedgerCommits(dir, f);
  const seen = [];
  const { reviews, notes, packagesUsed } = await reviewLedgerPr({
    cwd: dir, baseRef: 'main', headRef: 'HEAD',
    deps: { download: async (pkg) => { seen.push(pkg); return f.zip; } },
  });
  assert.deepEqual(Object.keys(reviews), [c1], '结论要按章指向的那枚提交来索引');
  assert.equal(reviews[c1].ok, true, reviews[c1].reason);
  assert.match(reviews[c1].summary, /1 段引用在归档里逐字节对上/);
  assert.equal(packagesUsed, 1);
  assert.deepEqual(notes, []);
  assert.equal(seen.length, 1, '取包恰好一次');
  assert.equal(seen[0].assetUrl, `https://github.com/o/r/releases/download/assets-v1/${f.sha}.zip`, '取包地址来自 base 的索引');
  assert.doesNotMatch(seen[0].assetUrl, /evil/, '不许照证据记录里写的地址取包');
  assert.equal(seen[0].sha256, f.sha);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('head 上还挂着待盖值 ⇒ 一条结论都不产，并说明为什么不产', async () => {
  const dir = ledgerRepo();
  const f = fixtureDoc();
  G(dir, 'checkout', '-qb', 'dispose/pending');
  fs.writeFileSync(path.join(dir, ...f.file.split('/')), (() => {
    const abs = path.join(dir, ...f.file.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, f.evidenceBytes);
    return f.evidenceBytes;
  })(), { encoding: 'utf8' });
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), JSON.stringify({
    schema: 'sukisu-dispositions-v2',
    dispositions: parseDispositions({
      schema: 'sukisu-dispositions-v2',
      dispositions: [{ kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z', id: 'mod_x', evidence: [{ file: f.file }], subject: { coolapkUid: '12345678' } }],
    }),
  }, null, 2) + '\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '只有 C1');
  let downloaded = 0;
  const { reviews, notes } = await reviewLedgerPr({
    cwd: dir, baseRef: 'main', headRef: 'HEAD',
    deps: { download: async () => { downloaded++; return f.zip; }, readEntry: () => entryOf(f) },
  });
  assert.deepEqual(reviews, {}, '待盖值不该拿到任何结论');
  assert.equal(downloaded, 0, '没有章就不花归档下载');
  assert.match(notes.join(), /不为待盖值产结论/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('归档取回来不是同一个包 ⇒ 复核不成立，退出码 1，结论落在文件里', async () => {
  const f = fixtureDoc();
  const dir = ledgerRepo([f]);
  const { c1 } = makeLedgerCommits(dir, f);
  const out = path.join(dir, 'reviews.json');
  const log = { out: [], err: [], log(m) { this.out.push(String(m)); }, error(m) { this.err.push(String(m)); } };
  const rc = await main(['--cwd', dir, '--base', 'main', '--head', 'HEAD', '--out', out], log, {
    download: async () => Buffer.concat([f.zip, Buffer.from('x')]),
    readEntry: () => entryOf(f),
  });
  assert.equal(rc, 1, log.err.join('\n'));
  const wrote = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(wrote[c1].ok, false);
  assert.match(wrote[c1].reason, /不是同一个包/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('引用的证据文件同名不同物（不是自己字节的 sha256）⇒ 不成立', async () => {
  const f = fixtureDoc();
  const dir = ledgerRepo([f]);
  // 记录里改一个字节，文件名不动 —— 这正是「内容寻址」要挡的那一发：改了内容还挂着原名字。
  const tampered = Buffer.from(f.evidenceBytes.toString('utf8').replace('"r1"', '"r2"'), 'utf8');
  assert.notEqual(tampered, f.evidenceBytes, '夹具没替换到东西（记录里找不到 reportId）');
  makeLedgerCommits(dir, { ...f, evidenceBytes: tampered });
  const { reviews } = await reviewLedgerPr({ cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsFor(f) });
  const r = Object.values(reviews)[0];
  assert.equal(r.ok, false);
  assert.match(r.reason, /同名不同物/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('处置没带 evidence 文件 ⇒ 结论是不成立，而不是「没东西可复核所以放行」', async () => {
  const dir = ledgerRepo();
  const f = fixtureDoc();
  const noEv = { ...f, file: f.file };
  // 直接把台账里的 evidence 键去掉：用 entryOver 做不到（它覆盖而非删除），改走手写提交。
  const c1 = (() => {
    G(dir, 'checkout', '-qb', 'dispose/noev');
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), JSON.stringify({
      schema: 'sukisu-dispositions-v2',
      dispositions: [{ kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z', id: 'mod_x' }],
    }, null, 2) + '\n');
    G(dir, 'add', '-A');
    G(dir, 'commit', '-qm', 'C1');
    const s = G(dir, 'rev-parse', 'HEAD').trim();
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), JSON.stringify({
      schema: 'sukisu-dispositions-v2',
      dispositions: [{ kind: 'revoke', reason: 'malware', by: `ci:audit@${s}`, at: '2026-10-22T00:00:00.000Z', id: 'mod_x' }],
    }, null, 2) + '\n');
    G(dir, 'add', '-A');
    G(dir, 'commit', '-qm', 'C2');
    return s;
  })();
  const { reviews } = await reviewLedgerPr({ cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsFor(noEv) });
  assert.equal(reviews[c1].ok, false);
  assert.match(reviews[c1].reason, /没有带 evidence 文件/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('一轮要复核的包超过上限 ⇒ 超出的那些判不成立（不静默少做）', async () => {
  // 每枚包的内容都不一样 ⇒ sha 各不相同 ⇒ 真会取到上限那么多包。
  // 内容相同的话 zip 相同、按 sha 缓存成 1 包，这一发就只是在测夹具。
  const fsx = Array.from({ length: MAX_PACKAGES_PER_RUN + 1 }, (_, i) => fixtureDoc([
    { name: 'customize.sh', content: `#!/system/bin/sh\nrm -rf /data/adb/mod${i}\necho done\n` },
  ], 0, 'rm -rf /data/adb/mod', { id: `mod_${i}` }));
  const dir = ledgerRepo(fsx);
  G(dir, 'checkout', '-qb', 'dispose/batch');
  const entries = fsx.map((f, i) => ({
    kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z',
    id: `mod_${i}`, sha256: f.sha, evidence: [{ file: f.file }], subject: { coolapkUid: '12345678' },
  }));
  const writeLedger = (list) => fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: list }, null, 2) + '\n');
  for (const f of fsx) {
    const abs = path.join(dir, ...f.file.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, f.evidenceBytes);
  }
  writeLedger(entries);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C1');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  writeLedger(entries.map((e) => ({ ...e, by: `ci:audit@${c1}` })));
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C2');
  const { reviews, packagesUsed } = await reviewLedgerPr({
    cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsForList(fsx),
  });
  assert.equal(packagesUsed, MAX_PACKAGES_PER_RUN, '只该取到上限那么多包');
  assert.equal(reviews[c1].ok, false, '少复核了一枚就整体不算成立，不许「做了 8 枚算 8 枚都对」');
  assert.match(reviews[c1].reason, /超过上限/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('同一枚章上多条处置：一条失败 ⇒ 这一枚整体不成立（失败不许被后面的成功抹掉）', async () => {
  const bad = fixtureDoc([{ name: 'customize.sh', content: '#!/system/bin/sh\nrm -rf /data/adb/other\n' }], 0, 'rm -rf /data/adb/other', { id: 'mod_0' });
  const good = fixtureDoc([{ name: 'customize.sh', content: '#!/system/bin/sh\nrm -rf /data/adb/magisk\necho done\n' }], 0, 'rm -rf /data/adb/magisk', { id: 'mod_1' });
  const dir = ledgerRepo([good]);
  G(dir, 'checkout', '-qb', 'dispose/mixed');
  // 顺序是这一发的全部：**失败那条排在前面**，成功那条排在后面。
  // 「按 sha 覆写」那种写法正好是后面的成功把前面的失败抹掉 ⇒ 这一发的遍历顺序必须能打到它。
  const raw = [bad, good].map((f, i) => ({
    kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z',
    id: `mod_${i}`, sha256: f.sha, ...(i === 0 ? {} : { evidence: [{ file: f.file }] }),
    subject: { coolapkUid: '12345678' },
  }));
  const writeLedger = (list) => fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: list }, null, 2) + '\n');
  for (const f of [bad, good]) {
    const abs = path.join(dir, ...f.file.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, f.evidenceBytes);
  }
  writeLedger(raw);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C1');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  writeLedger(raw.map((e) => ({ ...e, by: `ci:audit@${c1}` })));
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C2');
  const { reviews, packagesUsed } = await reviewLedgerPr({
    cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsForList([bad, good]),
  });
  assert.equal(Object.keys(reviews).length, 1, '两条处置共享同一枚章 ⇒ 只有一格结论');
  assert.equal(reviews[c1].ok, false);
  assert.match(reviews[c1].reason, /没有带 evidence 文件/);
  assert.equal(packagesUsed, 1, '带证据那一枚还是要真去取包 —— 别因为同组有失败就连坐跳过');
  fs.rmSync(dir, { recursive: true, force: true });
});

/* ------------------------------------------------------------ 对照物那一格 */

test('台账 PR 自带一枚「索引里没有的产物」⇒ 不成立：验的字节必须由 base 的索引决定', async () => {
  // 攻击形状：有写权限的人在**一个真实存在的模块名下**自己造一包、写一条引用它的处置 ——
  // 记录与 zip 逐字节自洽，若照记录里的地址取包就能给自己造出一枚绿章。
  // 挡它的只有「必须先在那份索引里以同一个 sha 发布过」。
  const real = fixtureDoc();
  const fake = fixtureDoc([{ name: 'customize.sh', content: '#!/system/bin/sh\nrm -rf /data/adb/invented\n' }], 0, 'rm -rf /data/adb/invented', { id: 'mod_x' });
  assert.notEqual(fake.sha, real.sha, '夹具失效：伪包与真包成了同一枚');
  const dir = ledgerRepo([real]);   // 索引里只发布 real 那一枚
  G(dir, 'checkout', '-qb', 'dispose/fake');
  const entry = {
    kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z',
    id: 'mod_x', versionCode: 3, sha256: fake.sha, evidence: [{ file: fake.file }],
    subject: { coolapkUid: '12345678' },
  };
  const writeLedger = (list) => fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: list }, null, 2) + '\n');
  const abs = path.join(dir, ...fake.file.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, fake.evidenceBytes);
  writeLedger([entry]);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C1');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  writeLedger([{ ...entry, by: `ci:audit@${c1}` }]);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C2');
  let downloads = 0;
  const { reviews } = await reviewLedgerPr({
    cwd: dir, baseRef: 'main', headRef: 'HEAD',
    deps: { download: async () => { downloads++; return fake.zip; } },
  });
  assert.equal(downloads, 0, '对照不上的包一次都不该去取');
  assert.equal(reviews[c1].ok, false);
  assert.match(reviews[c1].reason, /id=mod_x 没有 .{12} 这一枚产物/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('处置没有 sha256（只按 id 整模块下架）⇒ 不成立：逐字证据只能指着一枚具体产物', async () => {
  const f = fixtureDoc();
  const dir = ledgerRepo([f]);
  G(dir, 'checkout', '-qb', 'dispose/whole');
  const entry = {
    kind: 'revoke', reason: 'malware', by: 'ci:audit@pending', at: '2026-10-22T00:00:00.000Z',
    id: 'mod_x', evidence: [{ file: f.file }], subject: { coolapkUid: '12345678' },
  };
  const writeLedger = (list) => fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
    JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: list }, null, 2) + '\n');
  const abs = path.join(dir, ...f.file.split('/'));
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, f.evidenceBytes);
  writeLedger([entry]);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C1');
  const c1 = G(dir, 'rev-parse', 'HEAD').trim();
  writeLedger([{ ...entry, by: `ci:audit@${c1}` }]);
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', 'C2');
  const { reviews } = await reviewLedgerPr({ cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsFor(f) });
  assert.equal(reviews[c1].ok, false);
  assert.match(reviews[c1].reason, /处置没有带 64 位十六进制的 sha256/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('证据记录指的是另一个模块 / 另一枚产物 ⇒ 各自说清对不上在哪一格', async () => {
  const f = fixtureDoc();
  const dir = ledgerRepo([f]);
  const { c1 } = makeLedgerCommits(dir, f);
  for (const [mutate, re] of [
    [(d) => { d.package.id = 'mod_other'; }, /与处置点名的 "mod_x" 不是同一个/],
    [(d) => { d.package.sha256 = 'b'.repeat(64); }, /与处置点名的 .{12} 不是同一枚产物/],
  ]) {
    const tamperedDoc = JSON.parse(JSON.stringify(f.doc));
    mutate(tamperedDoc);
    const tampered = Buffer.from(JSON.stringify(tamperedDoc, null, 2) + '\n', 'utf8');
    // 内容改了就必须换个文件名（不然先撞在「同名不同物」那一格，测不到这里）。
    const file = `evidence/${sha256Hex(tampered)}.json`;
    const entry = {
      kind: 'revoke', reason: 'malware', by: `ci:audit@${c1}`, at: '2026-10-22T00:00:00.000Z',
      id: 'mod_x', versionCode: 3, sha256: f.sha, evidence: [{ file }], subject: { coolapkUid: '12345678' },
    };
    G(dir, 'checkout', '-B', 'dispose/identity', `${c1}~1`);
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
      JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: [entry] }, null, 2) + '\n');
    const abs = path.join(dir, ...file.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, tampered);
    G(dir, 'add', '-A');
    G(dir, 'commit', '-qm', 'C1：换了内容的证据');
    const nc1 = G(dir, 'rev-parse', 'HEAD').trim();
    fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'),
      JSON.stringify({ schema: 'sukisu-dispositions-v2', dispositions: [{ ...entry, by: `ci:audit@${nc1}` }] }, null, 2) + '\n');
    G(dir, 'add', '-A');
    G(dir, 'commit', '-qm', 'C2');
    const { reviews } = await reviewLedgerPr({ cwd: dir, baseRef: 'main', headRef: 'HEAD', deps: depsFor(f) });
    assert.equal(reviews[nc1].ok, false, JSON.stringify(tamperedDoc.package));
    assert.match(reviews[nc1].reason, re);
    assert.ok(c1);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('base 的索引是坏 JSON ⇒ fatal，退成「没复核」而不是「这枚产物不存在」', async () => {
  const dir = ledgerRepo();
  // 坏索引要落在 base 那枚**提交**上（git show 读的是提交，不是工作树）。
  fs.writeFileSync(path.join(dir, 'json', 'modules.json'), '{ 坏掉的');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '坏索引进 main');
  G(dir, 'checkout', '-qb', 'dispose/any');
  fs.writeFileSync(path.join(dir, 'NOTES.md'), '分支上的一点改动\n');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '一条台账改动');
  const log = { out: [], err: [], log(m) { this.out.push(String(m)); }, error(m) { this.err.push(String(m)); } };
  const rc = await main(['--cwd', dir, '--base', 'main', '--head', 'HEAD'], log, { download: async () => Buffer.alloc(0) });
  assert.equal(rc, 1);
  assert.match(log.err.join('\n'), /索引读不出来|索引不是合法 JSON/);
  assert.doesNotMatch(log.err.join('\n'), /索引里 id=/, '对照物不见了不能写成「举报对象不存在」');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('台账读不出来 ⇒ fatal、退出 1，不在这里放行', async () => {
  const dir = ledgerRepo();
  fs.writeFileSync(path.join(dir, 'json', 'dispositions.json'), '{ 坏掉的');
  G(dir, 'checkout', '-qb', 'bad');
  G(dir, 'add', '-A');
  G(dir, 'commit', '-qm', '坏台账');
  const log = { out: [], err: [], log(m) { this.out.push(String(m)); }, error(m) { this.err.push(String(m)); } };
  const rc = await main(['--cwd', dir, '--base', 'main', '--head', 'HEAD'], log, { download: async () => Buffer.alloc(0) });
  assert.equal(rc, 1);
  assert.match(log.err.join('\n'), /台账读不出来|不在这里放行/);
  fs.rmSync(dir, { recursive: true, force: true });
});
