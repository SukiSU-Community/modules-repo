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
import { readFileSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CAPABILITY_FAMILIES, forensics, capabilityFamilies } from '../audit/elf-forensics.mjs';
import { familiesUnder, validateManifest, findGitWorktreeRoot } from '../scripts/audit-corpus.mjs';

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
