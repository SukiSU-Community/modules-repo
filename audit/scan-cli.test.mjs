// scan.mjs 的 CLI 入口回归测试。
//
// 为什么单独有这个文件：CI 的扫描步骤一直是 success，却**一个字节都没扫过**。
// 真根因是入口判据拿原始 argv[1] 拼 file URL —— 调用方传的是相对路径
// `node audit/scan.mjs <zip>`，于是 `file:///audit/scan.mjs` 永远不等于
// `file:///home/runner/work/.../audit/scan.mjs`，main() 直接不跑，进程 exit 0、
// 不打印、不落盘。Windows 上却一切正常 —— 实测 Node 在 Windows 会把 process.argv[1]
// 规范化成绝对路径，拼出来的 URL 恰好对得上，所以本地全绿、只有 Linux runner 上静默失效。
// 结论：既要 spawn 一次跑真实形态，也要把判据本身抽成纯函数好让开发机也能覆盖两种形态。
//
// 运行：node --test audit/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isCliEntry } from './scan.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** 最小可用的模块 zip：根目录一个 module.prop（stored，免压缩）。 */
function probeZip(dir) {
  const prop = Buffer.from(
    'id=cli_probe\nname=CLI Probe\nversion=v1\nversionCode=1\nauthor=t\n"description"=x\n',
    'utf8'
  );
  const crc = (() => {
    let t = [];
    for (let i = 0; i < 256; i++) { let c = i; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[i] = c >>> 0; }
    return (buf) => { let c = 0xffffffff; for (const b of buf) c = t[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  })();
  const name = Buffer.from('module.prop');
  const crcV = crc(prop);
  const lh = Buffer.alloc(30);
  lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0, 8);
  lh.writeUInt32LE(crcV, 14); lh.writeUInt32LE(prop.length, 18); lh.writeUInt32LE(prop.length, 22);
  lh.writeUInt16LE(name.length, 26);
  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6);
  cd.writeUInt32LE(crcV, 16); cd.writeUInt32LE(prop.length, 20); cd.writeUInt32LE(prop.length, 24);
  cd.writeUInt16LE(name.length, 28); cd.writeUInt32LE(0, 38); cd.writeUInt32LE(0, 42);
  const ec = Buffer.alloc(22);
  ec.writeUInt32LE(0x06054b50, 0); ec.writeUInt16LE(1, 8); ec.writeUInt16LE(1, 10);
  ec.writeUInt32LE(cd.length, 12); ec.writeUInt32LE(30 + name.length + prop.length, 16);
  const p = join(dir, 'probe.zip');
  writeFileSync(p, Buffer.concat([lh, name, prop, cd, name, ec]));
  return p;
}

function runCli(args, cwd) {
  return spawnSync(process.execPath, args, { cwd, encoding: 'utf8' });
}

test('CLI：用**相对路径**调用（CI 的真实形态）必须真的跑起来', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-cli-'));
  const zip = probeZip(dir);
  const outDir = join(dir, 'out');

  // 关键：脚本写成相对路径 'audit/scan.mjs'，cwd 是仓库根 —— 与 .github/workflows/audit.yml
  // 里 `node "$SCANNER" ...`（SCANNER=audit/scan.mjs）完全同形。
  const r = runCli(
    ['audit/scan.mjs', zip, '--out-dir', outDir, '--quiet'],
    REPO_ROOT
  );

  assert.equal(r.status, 0, `exit=${r.status}\nstdout=${r.stdout}\nstderr=${r.stderr}`);
  assert.match(r.stdout, /\S/, 'CLI 必须打印一行结论；静默退出说明 main() 根本没跑');
  const produced = existsSync(outDir) ? readdirSync(outDir).filter((f) => f.endsWith('.audit.json')) : [];
  assert.equal(produced.length, 1, `应产出 1 份 *.audit.json，实际 ${produced.join(',') || '（无）'}`);
});

test('CLI：绝对路径调用同样要跑（不能只修好一边）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-cli-abs-'));
  const zip = probeZip(dir);
  const outDir = join(dir, 'out');
  const r = runCli(
    [join(REPO_ROOT, 'audit', 'scan.mjs'), zip, '--out-dir', outDir, '--quiet'],
    dir
  );
  assert.equal(r.status, 0, `exit=${r.status}\nstderr=${r.stderr}`);
  assert.match(r.stdout, /\S/, '绝对路径调用也必须打印结论');
});

// 整类问题的钉子：仓库里每个能当 CLI 跑的 .mjs 都必须用「解析成绝对路径再比」的判据。
// 靠拼 file:// URL 比字符串的写法，在一边平台上会静默不执行 —— 扫描器踩过这个坑
// （Linux runner 上 success 但零产出），盖章与验索引那两个脚本是同一形状。
//
// audit/ 与 scripts/ 的相对位置在两种落地形态里不一样（索引仓库在根 / monorepo 在
// contrib/repo/），所以目录自己探，别写死：写死的版本在母本那份里会因为找不到文件而炸，
// 而"炸在错误的布局上"只会让人把测试删掉。
const SCRIPTS_DIRS = [
  resolve(REPO_ROOT, 'scripts'),
  resolve(REPO_ROOT, 'repo', 'scripts'),
];
const SCRIPTS_DIR = SCRIPTS_DIRS.find((d) => existsSync(d)) || SCRIPTS_DIRS[0];

test('所有 CLI 入口判据都不许用拼 file:// URL 的写法', () => {
  const files = [
    join(REPO_ROOT, 'audit', 'scan.mjs'),
    ...['publish-from-main.mjs', 'verify-index-pr.mjs', 'build-index.mjs', 'fetch-pending-zip.mjs', 'validate-index.mjs']
      .map((f) => join(SCRIPTS_DIR, f))
      .filter((f) => existsSync(f)),
  ];
  assert.ok(files.length >= 3, `待查文件太少（${files.length}），八成是目录没探对：${SCRIPTS_DIR}`);
  for (const f of files) {
    const src = readFileSync(f, 'utf8');
    assert.doesNotMatch(
      src,
      /import\.meta\.url\s*===\s*[`'"]file:\/\//,
      `${f} 用拼 URL 比字符串当入口判据，会在某个平台上静默不跑`
    );
    if (/process\.argv\[1\]/.test(src)) {
      assert.match(src, /resolve\((?:\s*'[^']*',\s*)?process\.argv\[1\s*\]\s*\)|isCliEntry\(/, `${f} 的入口判据要比绝对路径`);
    }
  }
});

// Node 在 Windows 上会把 process.argv[1] 规范化成**绝对路径**，而 Linux 保持原样，
// CI 传的正是相对的 `audit/scan.mjs`。所以把判断抽成纯函数、由测试自己喂两种形态。
test('isCliEntry：相对与绝对两种 argv[1] 形态必须给出同一个答案', () => {
  const selfPath = join(REPO_ROOT, 'audit', 'scan.mjs');
  assert.equal(isCliEntry(selfPath, selfPath), true, '绝对形态');

  const rel = relative(process.cwd(), selfPath);
  assert.ok(rel && rel !== selfPath, '本条测试的前提是能构造出相对形态');
  assert.equal(isCliEntry(rel, selfPath), true, `相对形态「${rel}」就是 Linux runner 上的真实输入`);
  assert.equal(isCliEntry(`./${rel.replace(/\\/g, '/')}`, selfPath), true, './ 前缀同样要认');

  // 这一条不能写成裸 'scan.mjs'：cwd 正好是 audit/ 时它解析出来就是 selfPath，
  // 测试会因为运行目录不同而给出不同答案 —— 那就不是在测判据，而是在测 cwd。
  assert.equal(isCliEntry(join('nowhere', 'scan.mjs'), selfPath), false, '指向别的文件就不能算入口');
  assert.equal(isCliEntry(undefined, selfPath), false, 'node -e / 被 import 时没有 argv[1]');
  assert.equal(isCliEntry(selfPath, ''), false, '拿不到自身路径时宁可不当入口');
});

test('CLI：被 import 时不许自动跑 main（测试靠这个拿函数）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-cli-import-'));
  const probe = `
    const m = await import(${JSON.stringify(pathToFileURL(join(REPO_ROOT, 'audit', 'scan.mjs')).href)});
    if (typeof m.main !== 'function') throw new Error('main 没导出');
    if (typeof m.scanZip !== 'function') throw new Error('scanZip 没导出');
    process.stdout.write('IMPORTED-ONLY');
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', probe], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), 'IMPORTED-ONLY', 'import 不该触发 CLI 输出');
});
