/**
 * audit-corpus.mjs 的用例 —— 真包语料这把「量尺」自己的刻度准不准。
 * 运行：node --test test/audit-corpus.test.mjs
 *
 * 这一格交付的是量尺，不是判据：族成员表、档位公式、decide() 一律不在这里改。
 * 所以这里的断言只做三件事 —— 清单不许夹带来路不明的下载物、族集重算与生产口径一字不差、
 * 输出目录不许落在任何 git 工作树里。
 *
 * 零网络、零下载：需要「包」的地方全部用 audit/fixtures/ 里那六枚常驻真 ELF。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CAPABILITY_FAMILIES, forensics, capabilityFamilies } from '../audit/elf-forensics.mjs';
import { scanZip } from '../audit/scan.mjs';
import { makeModuleZip } from '../audit/fixtures.mjs';
import {
  familiesUnder, validateManifest, findGitWorktreeRoot, sha256Of,
  placeZip, pickAsset, fetchOne, mergeLock, buildDumpRow, runScan, familiesOfDumpRow,
  candidateNarrowingProblems, diffDump, runDiff, familyTier, mergeDump,
  tableDriftProblems,
} from '../scripts/audit-corpus.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..');
const SCRIPT = join(REPO_ROOT, 'scripts', 'audit-corpus.mjs');
const MANIFEST = join(REPO_ROOT, 'scripts', 'corpus-manifest.json');
const FIXTURES = join(REPO_ROOT, 'audit', 'fixtures');

/** 工单那张表的逐字副本 —— 清单里五个 name 必须与它相符。 */
const EXPECTED = [
  { name: 'ReZygisk', repo: 'PerformanC/ReZygisk', tag: 'v1.0.0', asset: 'ReZygisk-v1.0.0-release.zip', bytes: 506334 },
  { name: 'HMA-OSS', repo: 'frknkrc44/HMA-OSS', tag: 'oss-173', asset: 'HMA-OSS-ZYGISK-oss-173-release.zip', bytes: 2743824 },
  { name: 'zygisk-detach', repo: 'j-hc/zygisk-detach', tag: 'v1.24.0', asset: 'zygisk-detach-v1.24.0.zip', bytes: 371409 },
  { name: 'Zygisk-Assistant', repo: 'snake-4/Zygisk-Assistant', tag: 'v2.1.4', asset: 'Zygisk-Assistant-v2.1.4-1013f8a-release.zip', bytes: 392961 },
  { name: 'device_faker', repo: 'Seyud/device_faker_release', tag: 'v1.6.0', asset: 'device_faker_v1.6.0.zip', bytes: 969705 },
];

const SIX = ['device_faker_cli', 'arm64-v8a.so', 'detach-arm32', 'hma-arm64.so', 'hma-armeabi-v7a.so', 'hma-x86.so'];

/** 真跑子进程，把非零退出当成数据而不是异常（execFileSync 在 rc!=0 时抛，err 上带 status）。 */
function runCli(args) {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, output: stdout };
  } catch (err) {
    return { status: typeof err.status === 'number' ? err.status : null, output: `${err.stdout || ''}${err.stderr || ''}` };
  }
}

/** 把真夹具的字节喂给 forensics()，取回生产口径里那份族进料（与 report.binaryForensics 同一个来源）。 */
function feedOf(fixtureName) {
  const rec = forensics(readFileSync(join(FIXTURES, fixtureName)), fixtureName);
  assert.ok(rec && Array.isArray(rec.capabilityImports), `${fixtureName} 没读到 capabilityImports`);
  return rec;
}

// ---------------------------------------------------------------------------
// Step 0.1 —— 清单结构
// ---------------------------------------------------------------------------

test('Step 0.1 清单：五条逐字相符、bytes 是正整数、且没有任何硬编码直链', () => {
  const raw = readFileSync(MANIFEST, 'utf8');
  const parsed = JSON.parse(raw);
  const v = validateManifest(parsed);
  assert.deepEqual(v.errors, [], `清单校验失败：${v.errors.join(' | ')}`);
  assert.equal(v.ok, true);
  assert.deepEqual(v.entries.map((e) => e.name), EXPECTED.map((e) => e.name));
  for (let i = 0; i < EXPECTED.length; i++) {
    assert.deepEqual(
      { name: v.entries[i].name, repo: v.entries[i].repo, tag: v.entries[i].tag, asset: v.entries[i].asset, bytes: v.entries[i].bytes },
      EXPECTED[i],
      `第 ${i} 条与那张表不符`
    );
    assert.ok(!('url' in v.entries[i]) && !('browser_download_url' in v.entries[i]),
      '清单里不许存下载直链：钉的是 tag，直链必须由 fetch 现问 API 现拿');
  }
  // 判据要能咬住直链本身，所以当场喂一份「带了直链的清单」证明闸是活的，不是摆设。
  const widened = JSON.parse(raw);
  widened.entries[0].browser_download_url = 'https://github.com/PerformanC/ReZygisk/releases/download/v1.0.0/ReZygisk-v1.0.0-release.zip';
  assert.equal(validateManifest(widened).ok, false, 'browser_download_url 出现在清单里必须被拒');
  const inlined = JSON.parse(raw);
  inlined.entries[1].asset = 'https://github.com/frknkrc44/HMA-OSS/releases/download/oss-173/x.zip';
  assert.equal(validateManifest(inlined).ok, false, 'asset 里塞 https:// 直链必须被拒');
  const stringBytes = JSON.parse(raw);
  stringBytes.entries[2].bytes = '371409';
  assert.equal(validateManifest(stringBytes).ok, false, 'bytes 不是正整数必须被拒');
});

// ---------------------------------------------------------------------------
// Step 0.2 —— familiesUnder 的单调性
// ---------------------------------------------------------------------------

test('Step 0.2 familiesUnder：现表给 EXEC+FILEWRITE，摘成员只可能让族变少', () => {
  const names = ['execvp', 'mkdir', 'unlink'];
  assert.deepEqual(familiesUnder(names, CAPABILITY_FAMILIES), ['EXEC', 'FILEWRITE']);

  // 逐词核过的现表事实：unlink 只在 FILEWRITE，但 mkdir **也**在 FILEWRITE。
  assert.deepEqual(CAPABILITY_FAMILIES.filter(([, , ps]) => ps.includes('unlink')).map(([f]) => f), ['FILEWRITE']);
  assert.deepEqual(CAPABILITY_FAMILIES.filter(([, , ps]) => ps.includes('mkdir')).map(([f]) => f), ['FILEWRITE']);

  const dropUnlink = CAPABILITY_FAMILIES.map(([f, l, ps]) => [f, l, f === 'FILEWRITE' ? ps.filter((p) => p !== 'unlink') : ps]);
  // 只摘 unlink 时 FILEWRITE 靠 mkdir 还在，族集**不变**。工单这一格写的期望值是 ['EXEC']，
  // 与现表（elf-forensics.mjs 里 mkdir 也在 FILEWRITE）对不上 —— 差异原样记在交付报告里，
  // 这里把「只摘 unlink」和「摘 unlink+mkdir」两个输入都钉住，谁偷偷改了语义都会红。
  assert.deepEqual(familiesUnder(names, dropUnlink), ['EXEC', 'FILEWRITE']);

  const dropBoth = CAPABILITY_FAMILIES.map(([f, l, ps]) => [f, l, f === 'FILEWRITE'
    ? ps.filter((p) => p !== 'unlink' && p !== 'mkdir') : ps]);
  assert.deepEqual(familiesUnder(names, dropBoth), ['EXEC']);

  const cur = new Set(familiesUnder(names, CAPABILITY_FAMILIES));
  for (const fams of [familiesUnder(names, dropUnlink), familiesUnder(names, dropBoth)]) {
    for (const f of fams) assert.ok(cur.has(f), `摘成员之后冒出候选外族 ${f}`);
    assert.ok(fams.length <= cur.size, '摘成员之后族数只增不减 —— 单调性写反了');
  }
  assert.deepEqual(familiesUnder([], CAPABILITY_FAMILIES), [], '空进料必须有确定的空输出');
});

// ---------------------------------------------------------------------------
// Step 0.3 —— 「不许发明第二份词汇表」那颗钉子（a 保真 + b 有牙）
// ---------------------------------------------------------------------------

test('Step 0.3a 同表等于 capabilityFamilies：六枚常驻夹具逐名比对，族集一字不差', () => {
  for (const name of SIX) {
    const rec = feedOf(name);
    assert.deepEqual(
      rec.capabilityImports.map((n) => familiesUnder([n], CAPABILITY_FAMILIES)),
      rec.capabilityImports.map((n) => capabilityFamilies([n])),
      `${name}：逐名喂两套算法结果不同，说明语料侧发明了第二份词汇表`
    );
    assert.deepEqual(familiesUnder(rec.capabilityImports, CAPABILITY_FAMILIES), capabilityFamilies(rec.capabilityImports),
      `${name}：整枚进料喂进去族集不同`);
  }
});

test('Step 0.3b 有牙的那一半：execvp 与 mkdir 真在 capabilityImports 里、且不在 sensitiveImports 里', () => {
  const rec = feedOf('device_faker_cli');
  for (const n of ['execvp', 'mkdir']) {
    assert.ok(rec.capabilityImports.includes(n), `${n} 应当出自该夹具的 capabilityImports，否则这颗钉子喂的是编造输入`);
    assert.ok(!rec.sensitiveImports.includes(n),
      `${n} 应当**不**在 sensitiveImports 里 —— 在的话「再过一遍 SENSITIVE」那发变异就逼不出来了`);
  }
  assert.deepEqual(familiesUnder(['execvp', 'mkdir'], CAPABILITY_FAMILIES), ['EXEC', 'FILEWRITE']);
});

// ---------------------------------------------------------------------------
// Step 0.4 —— --out 的 git 工作树闸 + 子命令必填
// ---------------------------------------------------------------------------

test('Step 0.4 --out 落在 git 工作树里就拒绝：自己问每一级祖先有没有 .git', () => {
  // 注入版：祖先链上任意一层有 .git 都认得出来，不只查「本仓」那一层。
  let probe = join(REPO_ROOT, 'x', 'a', 'b');
  const fakeFs = new Set([join(REPO_ROOT, 'x')]);
  assert.equal(findGitWorktreeRoot(probe, { hasDotGit: (p) => fakeFs.has(p) }), join(REPO_ROOT, 'x'));
  assert.equal(findGitWorktreeRoot(probe, { hasDotGit: () => false }), null);

  const dir = mkdtempSync(join(tmpdir(), 'corpus-out-'));
  try {
    assert.equal(findGitWorktreeRoot(dir, {}), null, 'mkdtemp 出来的目录不该在任何工作树里');
    const ok = runCli(['scan', '--out', dir]);
    assert.doesNotMatch(ok.output, /git 工作树/, `仓库外的 --out 不该被这道闸拦下：${ok.output}`);

    const inside = join(dir, 'inRepo');
    mkdirSync(join(inside, '.git'), { recursive: true });
    const bad = runCli(['scan', '--out', inside]);
    assert.equal(bad.status, 2, `--out 落在 git 工作树里必须以 2 退出，实测 ${bad.status}`);
    assert.match(bad.output, /git 工作树/, '拒绝理由要说明是 git 工作树这件事');

    // 只查本仓会漏掉的那一发：父目录才是工作树（两棵仓在同一个父目录下就是这个形状）。
    const nested = join(inside, 'deeper', 'still');
    mkdirSync(nested, { recursive: true });
    const bad2 = runCli(['scan', '--out', nested]);
    assert.equal(bad2.status, 2, `祖先层的工作树也要认出来，实测 ${bad2.status}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Step 0.4 子命令缺失与 --out 缺失：非零退出，且**不许**是 0', () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-args-'));
  const cases = [
    { args: [], why: '什么都不给' },
    { args: ['--out', dir], why: '缺子命令' },
    { args: ['scan'], why: '缺 --out' },
    { args: ['bogus', '--out', dir], why: '子命令不在值域里' },
  ];
  try {
    for (const c of cases) {
      const r = runCli(c.args);
      assert.notEqual(r.status, 0, `${c.why}：退出码不许是 0（打印用法后 exit 0 是本仓明令禁止的形状）`);
      assert.match(r.output, /用法|usage/i, `${c.why}：非零退出要把用法打出来`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Step 2 —— fetch 的身份绑定 + scan 的字段口径（全部离线，零网络）
// ---------------------------------------------------------------------------

/** 六枚常驻真 ELF 打成一个合成 zip，只用来量 scan 的字段口径，不当真包用。 */
function syntheticZip() {
  return makeModuleZip({ id: 'corpus-fixture-bundle', files: SIX.map((n) => [`lib/${n}`, readFileSync(join(FIXTURES, n))]) });
}

const SILENT = { log: () => {}, error: () => {}, warn: () => {} };

test('Step 2 身份绑定：同名不同字节就停下来报，绝不覆盖已有 zip', () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-bind-'));
  try {
    const target = join(dir, 'ReZygisk.zip');
    const oldBytes = Buffer.from('上一轮那个包的字节，谁也不许盖掉它'.repeat(3), 'utf8');
    writeFileSync(target, oldBytes);
    const fresh = Buffer.from('这一轮下载到的另一份字节'.repeat(4), 'utf8');
    const r = placeZip(target, fresh, { name: 'ReZygisk', bytes: fresh.length });
    assert.equal(r.ok, false, '同名不同字节必须判不成功');
    assert.equal(r.stopped, 'name-collision');
    assert.notEqual(r.existingSha, r.incomingSha);
    assert.deepEqual(readFileSync(target), oldBytes, '停下来之后盘上必须还是旧字节（覆盖=换芯）');
    // 同一个文件重放：字节一致才算 reused，不写第二遍。
    const same = placeZip(target, oldBytes, { name: 'ReZygisk', bytes: oldBytes.length });
    assert.equal(same.ok, true);
    assert.equal(same.reused, true);
    assert.equal(same.sha256, sha256Of(oldBytes));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Step 2 身份绑定：字节数与清单记的对不上就停（不落地、不进 lock）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-bytes-'));
  try {
    const target = join(dir, 'HMA-OSS.zip');
    const fresh = Buffer.alloc(128, 7);
    const r = placeZip(target, fresh, { name: 'HMA-OSS', bytes: 2743824 });
    assert.equal(r.ok, false);
    assert.equal(r.stopped, 'bytes-mismatch');
    assert.equal(r.actual, 128);
    assert.equal(existsSync(target), false, '字节对不上的东西不许落盘');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Step 2 pickAsset：附件名要逐字相符，近似名与 latest 换货都算没找到', () => {
  const entry = EXPECTED[0];
  const release = (names, size = entry.bytes, tag = entry.tag) => ({
    tag_name: tag,
    assets: names.map((n) => ({ name: n, size, browser_download_url: `//example/${n}` })),
  });
  const exact = pickAsset(release([entry.asset]), entry);
  assert.equal(exact.ok, true);
  assert.equal(pickAsset(release(['ReZygisk-v1.0.0.zip']), entry).ok, false, '少一个 -release 的近似名不许当命中');
  assert.equal(pickAsset(release([entry.asset.toUpperCase()]), entry).ok, false, '大小写不同不许当命中');
  assert.equal(pickAsset(release([entry.asset, entry.asset]), entry).ok, false, '同名两枚不许随便挑一个');
  assert.equal(pickAsset(release([entry.asset], entry.bytes + 1), entry).ok, false, 'API 报的字节与清单不符要报出来');
  assert.equal(pickAsset(release([entry.asset], entry.bytes, 'v9.9.9'), entry).ok, false, 'tag 被换过要报出来');
});

test('Step 2 fetchOne 全程离线重放：第二轮换了字节 ⇒ 停 + 盘上一个字节没动', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-fetch-'));
  try {
    const zipsDir = join(dir, 'zips');
    mkdirSync(zipsDir, { recursive: true });
    const entry = { ...EXPECTED[3], bytes: 64 };
    const v1 = Buffer.alloc(64, 1);
    const v2 = Buffer.alloc(64, 2);
    let payload = v1;
    const apiGet = async () => ({ tag_name: entry.tag, assets: [{ name: entry.asset, size: 64, browser_download_url: 'https://example.invalid/a.zip' }] });
    const download = () => payload;
    const r1 = await fetchOne(entry, { zipsDir, log: SILENT, apiGet, download });
    assert.equal(r1.ok, true, r1.why || '第一轮该成');
    assert.equal(r1.row.sha256, sha256Of(v1));
    assert.equal(r1.row.bytes, 64);
    // 同一个 name 换了字节（上游重发、或旧包盖新包）—— 这一发就是 MC1 的靶子。
    payload = v2;
    const r2 = await fetchOne(entry, { zipsDir, log: SILENT, apiGet, download });
    assert.equal(r2.ok, false, '同名不同字节必须判失败');
    assert.equal(r2.stopped, 'name-collision');
    assert.deepEqual(readFileSync(join(zipsDir, `${entry.name}.zip`)), v1, '停下来之后盘上必须还是第一轮那份字节');
    // lock 合并：--only 跑半截不许把别的包证人清空。
    const merged = mergeLock({ entries: [{ name: 'Other', sha256: 'x' }] }, [r1.row]);
    assert.deepEqual(merged.entries.map((e) => e.name).sort(), ['Other', entry.name]);
    const replaced = mergeLock({ entries: [r1.row] }, [{ ...r1.row, sha256: 'y' }]);
    assert.equal(replaced.entries.length, 1);
    assert.equal(replaced.entries[0].sha256, 'y');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Step 2 scan 拒绝没有 lock 的目录，lock 的 sha 对不上时停下来不扫', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-scan-'));
  try {
    const zipsDir = join(dir, 'zips');
    mkdirSync(zipsDir, { recursive: true });
    const zipPath = join(zipsDir, 'synthetic.zip');
    const made = syntheticZip();
    writeFileSync(zipPath, readFileSync(made));
    rmSync(dirname(made), { recursive: true, force: true });
    const manifest = { entries: [{ name: 'synthetic', repo: 'o/r', tag: 't', asset: 'a.zip', bytes: statOf(zipPath) }] };
    const noLock = await runScan({ log: SILENT, out: dir, manifest });
    assert.equal(noLock.code, 2, '没有 lock 就该拒绝跑');
    assert.match(noLock.problems.join(' '), /corpus-lock/, '拒绝理由要指名缺 lock');
    assert.equal(existsSync(join(dir, 'corpus-dump.json')), false, '拒绝跑的时候不许留产物');

    writeFileSync(join(dir, 'corpus-lock.json'), JSON.stringify({
      schema: 'audit-corpus-lock/v1',
      entries: [{ name: 'synthetic', url: 'https://example.invalid/a.zip', bytes: statOf(zipPath), sha256: '0'.repeat(64), fetched_at: 'x' }],
    }));
    const badLock = await runScan({ log: SILENT, out: dir, manifest });
    assert.notEqual(badLock.code, 0, '盘上 sha 与 lock 不符时不许扫成');
    assert.match(badLock.problems.join(' '), /sha256/);
    assert.equal(existsSync(join(dir, 'corpus-dump.json')), false, '字节对不上更不许写 dump');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function statOf(p) {
  return readFileSync(p).length;
}

test('Step 2 dump 字段口径一律从报告取：riskLevel/counts/decision/binaryForensics，ruleHistogram 是本工具衍生的', async () => {
  const zipPath = syntheticZip();
  const report = await scanZip(zipPath, { changeType: 'first' });
  assert.equal('level' in report, false, '报告里没有 level 这个键');
  assert.ok(['low', 'medium', 'high'].includes(report.riskLevel));
  assert.ok(['auto-approve', 'request-review', 'block'].includes(report.decision.action), 'decision 是对象，取 .action');
  assert.equal(report.binaries.length, 6);
  assert.equal(report.binaryForensics.length, 6);

  const row = buildDumpRow({ name: 'synthetic', zipPath, zipBytes: statOf(zipPath), zipSha256: sha256Of(zipPath) }, report);
  assert.equal(row.riskLevel, report.riskLevel);
  assert.deepEqual(row.counts, report.counts);
  assert.equal(row.decision, report.decision.action);
  assert.equal(row.zipSha256, sha256Of(zipPath));
  // ruleHistogram 是本工具数出来的，报告里没有这一格。
  const total = Object.values(row.ruleHistogram).reduce((a, b) => a + b, 0);
  assert.equal(total, report.findings.length);
  assert.equal('ruleHistogram' in report, false, '报告里本来没有 ruleHistogram —— 有就说明这格不是衍生的');

  assert.equal(row.binaries.length, 6);
  for (let i = 0; i < row.binaries.length; i++) {
    const src = report.binaryForensics[i];
    const b = row.binaries[i];
    assert.equal(b.name, src.name, '条目名与 report.binaries 同一套口径');
    assert.deepEqual(b.capabilityImports, src.capabilityImports || []);
    assert.deepEqual(b.sensitiveImports, src.sensitiveImports || []);
    assert.equal(b.capabilityImportsTotal, src.capabilityImportsTotal);
    // 那一格只在被截时才写：读它要 === true，键不存在时也不该冒出来。
    assert.equal(b.capabilityImportsCapped, src.capabilityImportsCapped === true ? true : undefined);
    // families 用报告的现算值，与 familiesUnder(同一份进料, 现表) 一字不差。
    assert.deepEqual(b.families, familiesUnder(b.capabilityImports, CAPABILITY_FAMILIES));
    assert.deepEqual(b.families, capabilityFamilies(b.capabilityImports));
  }
  // 条目名是 zip 里的**全名**（带 lib/ 前缀），不是 basename —— 与 report.binaries[].name 同一套口径。
  // detach-arm32 这一栏是 3 不是 4：NET 那一族本来只靠 `sendfile` 撑着，2026-10-16 摘掉 `send`
  // 这条前缀之后它落不到 NET 了。改的是这张表的成员，不是这里的计数口径。
  const byName = Object.fromEntries(row.binaries.map((b) => [b.name, b.families.length]));
  assert.deepEqual(byName, {
    'lib/device_faker_cli': 4, 'lib/arm64-v8a.so': 4, 'lib/detach-arm32': 3,
    'lib/hma-arm64.so': 0, 'lib/hma-armeabi-v7a.so': 0, 'lib/hma-x86.so': 0,
  });
  // 跨枚取并集是「包级最严」那一栏的族集口径，排序去重。
  assert.deepEqual(familiesOfDumpRow(row), ['EXEC', 'FILEWRITE', 'NET', 'NS', 'PROP']);
  rmSync(dirname(zipPath), { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Step 3 —— diff 的收窄闸，以及一张**不依赖下载**的前后表
// ---------------------------------------------------------------------------

/**
 * 未拍的候选表：还剩这四枚成员（族名 + 前缀，逐词对过现表）。
 * `['NET','send']` 那一元**已经不在**这张表里 —— 它不是候选，2026-10-16 拍了并落了地，
 * 现表 NET 里再也没有 `send` 这条前缀，所以留着它会让下面 narrow() 那条前提断言当场红
 * （那是它该有的行为，红过一次记在交付报告里）。落地之后的真值改由紧邻 B 的那条特征化断言钉，
 * 不再混在这张「还没拍」的候选表里；其余四条仍然是候选，谁顺手落一条都会红。
 */
const STEP4_REMOVALS = [['FILEWRITE', 'chdir'], ['NS', 'kill'], ['NS', 'sigaction'], ['NS', 'prctl']];

/** 从现表里按 [族,前缀] 摘成员。摘之前先确认它真在现表里 —— 表改了这发要响，而不是偷偷测了个空集。 */
function narrow(pairs) {
  for (const [family, prefix] of pairs) {
    const row = CAPABILITY_FAMILIES.find(([f]) => f === family);
    assert.ok(row && row[2].includes(prefix), `现表里 ${family} 没有前缀 ${prefix} —— 这张候选表的前提已经不成立了`);
  }
  return CAPABILITY_FAMILIES.map(([f, l, ps]) => [f, l, ps.filter((p) => !pairs.some(([pf, pp]) => pf === f && pp === p))]);
}

test('B 已落地那一格：现表 NET 里没有 send，而 arm64-v8a.so 那份筛后名单里 send 仍在（两份东西不许复合）', () => {
  const net = CAPABILITY_FAMILIES.find(([f]) => f === 'NET');
  assert.ok(net, 'NET 那一行还在：摘的是一条前缀，不是整个族');
  assert.equal(net[2].includes('send'), false, '现表 NET 里没有 `send` —— 这一发已经落地，不再是候选');
  assert.deepEqual(net[2], ['socket', 'connect', 'bind', 'listen', 'accept', 'recv', 'getaddrinfo'],
    '其余成员一字未动（EXEC / NS / PROP / FILEWRITE 四行由上面那张候选表继续管着）');

  const arm = forensics(readFileSync(join(FIXTURES, 'arm64-v8a.so')), 'arm64-v8a.so');
  assert.ok(arm.sensitiveImports.includes('send'), '给人看的那份名单里 send 还在：展示筛不为族表让路');
  assert.equal(arm.capabilityImports.includes('send'), false, '族进料里它不再出现 —— 这一对就是那面解耦墙');
  assert.deepEqual(capabilityFamilies(arm.capabilityImports), ['EXEC', 'FILEWRITE', 'NET', 'NS'],
    'NET 仍靠 recv 撑着：这一枚还是 4 族，摘一条前缀不等于摘一个族');
});

/** 离线造一份 dump：六枚常驻真 ELF 进合成 zip ⇒ 生产入口扫 ⇒ buildDumpRow。 */
async function offlineDump() {
  const zipPath = syntheticZip();
  const report = await scanZip(zipPath, { changeType: 'first' });
  const row = buildDumpRow({ name: 'fixtures-six', zipPath, zipBytes: statOf(zipPath), zipSha256: sha256Of(zipPath) }, report);
  rmSync(dirname(zipPath), { recursive: true, force: true });
  return { schema: 'audit-corpus-dump/v1', rows: [row] };
}

test('Step 3 收窄闸：候选表里有新增前缀或新增族 ⇒ 非零退出，且理由里写着「假的 0 移动」', () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-diff-'));
  try {
    // 纯函数那一层。
    assert.deepEqual(candidateNarrowingProblems(CAPABILITY_FAMILIES, CAPABILITY_FAMILIES), [], '现表自己是合格候选');
    assert.deepEqual(candidateNarrowingProblems(narrow(STEP4_REMOVALS), CAPABILITY_FAMILIES), [], 'Step 4 那张表是收窄，该放过');
    const addedPrefix = CAPABILITY_FAMILIES.map(([f, l, ps]) => (f === 'EXEC' ? [f, l, [...ps, 'ptrace']] : [f, l, ps]));
    assert.ok(candidateNarrowingProblems(addedPrefix, CAPABILITY_FAMILIES).length === 1, '把别族的前缀搬进 EXEC 也要算新增');
    assert.match(candidateNarrowingProblems(addedPrefix, CAPABILITY_FAMILIES)[0], /假的 0 移动/);
    const addedFamily = [...CAPABILITY_FAMILIES, ['OWN', '凭空一族', ['ptrace']]];
    assert.ok(candidateNarrowingProblems(addedFamily, CAPABILITY_FAMILIES).length === 1, '新增族同样要拦');

    // CLI 那一层：真跑一发，退出码必须是 2。
    const dump = { schema: 'audit-corpus-dump/v1', rows: [] };
    writeFileSync(join(dir, 'corpus-dump.json'), JSON.stringify(dump));
    const badCand = join(dir, 'widening.json');
    writeFileSync(badCand, JSON.stringify(addedPrefix));
    const r = runCli(['diff', '--out', dir, '--candidate', badCand]);
    assert.equal(r.status, 2, `加严的候选表必须以 2 退出，实测 ${r.status}`);
    assert.match(r.output, /假的 0 移动|全量 UND/, '报错要把理由写进去');

    const goodCand = join(dir, 'narrowing.json');
    writeFileSync(goodCand, JSON.stringify(narrow(STEP4_REMOVALS)));
    const ok = runCli(['diff', '--out', dir, '--candidate', goodCand]);
    assert.equal(ok.status, 0, ok.output);
    assert.match(ok.output, /汇总/);

    const noCand = runCli(['diff', '--out', dir]);
    assert.equal(noCand.status, 2, 'diff 少了 --candidate 也要非零');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Step 3 离线前后表：六枚常驻夹具 + Step 4 候选表 ⇒ 4→3 / 3→3 / 4→4 / 0→0×3，跨 ≥2 边界的枚数 = 0', async () => {
  const dump = await offlineDump();
  const result = diffDump(dump, narrow(STEP4_REMOVALS));
  assert.deepEqual(result.problems, [], `报告里的 families 与现表重算不一致：${result.problems.join(' | ')}`);
  assert.equal(result.packages.length, 1);
  const pkg = result.packages[0];
  const byName = Object.fromEntries(pkg.binaries.map((b) => [b.name.replace(/^lib\//, ''), b]));

  assert.deepEqual(Object.keys(byName).sort(), [...SIX].sort());
  assert.deepEqual([byName.device_faker_cli.beforeCount, byName.device_faker_cli.afterCount], [4, 3]);
  // detach-arm32 的前栏由 4 改 3、后栏 3 不改：NET 本来只靠 `sendfile` 撑着，那条前缀摘掉之后
  // 现表重算出来就是 EXEC+FILEWRITE+NS 三族（这一栏是从生产报告的 families 现算来的，不是手写的）。
  assert.deepEqual([byName['detach-arm32'].beforeCount, byName['detach-arm32'].afterCount], [3, 3]);
  assert.deepEqual([byName['arm64-v8a.so'].beforeCount, byName['arm64-v8a.so'].afterCount], [4, 4]);
  for (const n of ['hma-arm64.so', 'hma-armeabi-v7a.so', 'hma-x86.so']) {
    assert.deepEqual([byName[n].beforeCount, byName[n].afterCount], [0, 0], `${n} 两栏都该是 0`);
  }
  // 跨 ≥2 那条边界的枚数 = 0 ⇒ 这一发在夹具上不给档位变化（工单原话，跑出来不是 0 就是不一致）。
  assert.equal(result.summary.binariesCrossingTheTwoFamilyEdge, 0);
  assert.equal(pkg.packageTierBefore, 'high');
  assert.equal(pkg.packageTierAfter, 'high');

  // 前栏来自报告、后栏是候选表重算 —— 这两栏的来源要如实标出来。
  for (const b of pkg.binaries) {
    assert.equal(b.beforeSource, 'report');
    assert.equal(b.afterSource, 'candidate-recomputed');
    assert.ok(b.after.every((f) => b.before.includes(f)), `${b.name}：摘成员之后冒出前栏没有的族`);
  }

  // dump 过期那一格必须响：把某枚的 families 改成别的值，diff 要报不一致而不是安静地给假表。
  const stale = JSON.parse(JSON.stringify(dump));
  stale.rows[0].binaries[0].families = ['EXEC'];
  const r2 = diffDump(stale, narrow(STEP4_REMOVALS));
  assert.ok(r2.problems.length === 1, 'dump 与现表脱节时必须报出来');
  assert.match(r2.problems[0], /不一致/);

  // 族数档位那条公式本身也钉一下（0/1 → medium，≥2 → high），跨边界的计数才有出处。
  assert.equal(familyTier(['EXEC']), 'medium');
  assert.equal(familyTier(['EXEC', 'NET']), 'high');
});

test('Step 2 --only 重扫一个包不许把整份 dump 缩成一行（那会让下一张前后表说假话）', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'corpus-dumpmerge-'));
  try {
    const zipsDir = join(dir, 'zips');
    mkdirSync(zipsDir, { recursive: true });
    const made = syntheticZip();
    const body = readFileSync(made);
    rmSync(dirname(made), { recursive: true, force: true });
    for (const n of ['a', 'b']) writeFileSync(join(zipsDir, `${n}.zip`), body);
    const sha = sha256Of(body);
    writeFileSync(join(dir, 'corpus-lock.json'), JSON.stringify({
      schema: 'audit-corpus-lock/v1',
      entries: ['a', 'b'].map((n) => ({ name: n, url: `https://example.invalid/${n}.zip`, bytes: body.length, sha256: sha, fetched_at: 'x' })),
    }));
    const manifest = { entries: ['a', 'b'].map((n) => ({ name: n, repo: 'o/r', tag: 't', asset: 'a.zip', bytes: body.length })) };

    await runScan({ log: SILENT, out: dir, manifest, only: 'a' });
    await runScan({ log: SILENT, out: dir, manifest, only: 'b' });
    const dump = JSON.parse(readFileSync(join(dir, 'corpus-dump.json'), 'utf8'));
    assert.deepEqual(dump.rows.map((r) => r.name), ['a', 'b'], '两轮各扫一个包，dump 里应当是两个包');
    await runScan({ log: SILENT, out: dir, manifest, only: 'a' });
    const after = JSON.parse(readFileSync(join(dir, 'corpus-dump.json'), 'utf8'));
    assert.deepEqual(after.rows.map((r) => r.name), ['a', 'b'], '重扫 a 之后 b 那一行不许被抹掉');

    // 纯函数那一层：同名行以本次为准，排序稳定。
    const merged = mergeDump({ rows: [{ name: 'b', zipSha256: 'old' }, { name: 'a', zipSha256: 'old' }] }, [{ name: 'a', zipSha256: 'new' }]);
    assert.deepEqual(merged.rows.map((r) => [r.name, r.zipSha256]), [['a', 'new'], ['b', 'old']]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 主控复验补的那一格：dump 里 currentTable 那格原来**只写不读** —— 写了就等于没写。
// ---------------------------------------------------------------------------

test('表来源闸：dump 的 currentTable 与现表漂了 ⇒ 不出前后表、退出码 2、理由点名漂在哪个前缀', async () => {
  // 漂移挑 `property_`：它在六枚常驻夹具里**一次都不命中**，所以「逐枚 families 与现表重算比对」
  // 那道旧闸在这种漂移下照样绿 —— 这条用例的牙必须属于新闸，不能是搭旧闸的便车。
  for (const n of SIX) {
    for (const x of feedOf(n).capabilityImports) {
      assert.ok(!x.toLowerCase().startsWith('property_'), `${n} 命中了 property_，这条用例的前提没了`);
    }
  }

  const dump = await offlineDump();
  dump.currentTable = CAPABILITY_FAMILIES.map(([f, , ps]) => [f, ps]);
  const same = diffDump(dump, narrow(STEP4_REMOVALS));
  assert.deepEqual(same.tableDrift, [], '表没漂就不许多嘴');
  assert.deepEqual(same.problems, [], '这份 dump 的逐枚比对本来就一致，新闸不许把它判红');
  assert.equal(same.packages.length, 1);

  const drifted = JSON.parse(JSON.stringify(dump));
  drifted.currentTable = drifted.currentTable.map(([f, ps]) => [f, f === 'PROP' ? ps.filter((p) => p !== 'property_') : ps]);
  const r = diffDump(drifted, narrow(STEP4_REMOVALS));
  assert.equal(r.tableDrift.length, 1, `表漂了一处必须报出来，实测 ${JSON.stringify(r.tableDrift)}`);
  assert.match(r.tableDrift[0], /PROP/);
  assert.match(r.tableDrift[0], /property_/);
  assert.match(r.tableDrift[0], /先重跑 scan/);
  assert.deepEqual(r.packages, [], '表漂了就不许再打印前后表 —— 那是一张来源不明的表');
  assert.equal(r.summary.packages, 0);

  // 纯函数那一层：同表给空、少一族与少一个前缀都要点名（族整族不见 ⇒ 也是一条）。
  assert.deepEqual(tableDriftProblems(CAPABILITY_FAMILIES.map(([f, , ps]) => [f, ps]), CAPABILITY_FAMILIES), []);
  assert.equal(tableDriftProblems([['EXEC', ['exec']]], CAPABILITY_FAMILIES).length, 1, '少掉其余四族要报，不许当成「没漂」');
  const widened = CAPABILITY_FAMILIES.map(([f, , ps]) => [f, f === 'EXEC' ? [...ps, 'bogus_'] : ps]);
  assert.equal(tableDriftProblems(widened, CAPABILITY_FAMILIES).length, 1, 'dump 里的表比现表宽 ⇒ 同样是漂');

  // CLI 那一层真跑一发：这是前置条件不成立（不是「算完发现没变」），所以退出码 2。
  const dir = mkdtempSync(join(tmpdir(), 'corpus-drift-'));
  try {
    writeFileSync(join(dir, 'corpus-dump.json'), JSON.stringify(drifted));
    const cand = join(dir, 'cand.json');
    writeFileSync(cand, JSON.stringify(narrow(STEP4_REMOVALS)));
    const out = runCli(['diff', '--out', dir, '--candidate', cand]);
    assert.equal(out.status, 2, `dump 的表与现表漂了必须以 2 退出，实测 ${out.status}：${out.output}`);
    assert.match(out.output, /property_|先重跑 scan/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});


