#!/usr/bin/env node
/**
 * audit-corpus.mjs —— 把「真包语料」做成仓库常驻的一把量尺。
 *
 * 这工具存在的理由：危险族成员表将来可能要收窄（把不是本族链接期事实的成员摘出去），
 * 而收窄是**放宽方向**的改动，按规矩要先有「含原生码的公开包会不会因此翻结论」的影响面。
 * 影响量不出来就只能拍脑袋，所以这里把「下载 → 扫描 → 按候选表重算族集 → 打前后表」
 * 这条链固定成可重跑的命令，而不是一次性脚本里的临时产物。
 *
 * 三条硬规矩（写代码前先记住，改代码时更要记住）：
 * 1. **只读，绝不执行**：不 import、不 spawn、不 adb、不解压到盘外，包里任何文件都不当代码跑。
 *    扫描走 audit/scan.mjs 的 scanZip(zipPath, opts) —— 那是生产入口（AI 复核与 CI 用的同一把），
 *    收的是 zip 的路径而不是 Buffer。这里不 import audit/fixtures.mjs：那份文件是给测试改的，
 *    工具一旦依赖它，「和生产同一把」就成了假话。
 * 2. **CI 不许下载**：fetch 是唯一走网络的子命令，而且要人显式敲；scan / diff / selftest 零网络。
 *    下载的 zip 与两份 JSON 产物一律落在仓库外，见下面 --out 那道闸 —— 本仓 .gitignore 里有 *.zip，
 *    真把包下进仓里，git status 一个字都不会提醒，所以那道闸是唯一会响的那一个。
 * 3. **判据不许有第二份**：族词汇从 audit/elf-forensics.mjs 读（现表就是 CAPABILITY_FAMILIES 那一份），
 *    重算族集的 familiesUnder 只做「小写 + 前缀 startsWith」这一条，与 capabilitySymbols 的规则一字不差，
 *    并由 test/audit-corpus.test.mjs 钉住「同表时两套算法结果一致」。
 *
 * 用法见 USAGE。
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { CAPABILITY_FAMILIES, capabilityFamilies } from '../audit/elf-forensics.mjs';
import { isCliEntry } from '../audit/scan.mjs';

/** 清单与候选表的默认形状。 */
export const SUBCOMMANDS = ['fetch', 'scan', 'diff', 'selftest'];
const DEFAULT_MANIFEST = resolve(dirname(fileURLToPath(import.meta.url)), 'corpus-manifest.json');

const USAGE = `用法: node scripts/audit-corpus.mjs <fetch|scan|diff|selftest> --out <dir> [--manifest <path>] [--candidate <path>] [--only <name>]

  fetch      按清单里的 tag 现问 Releases API 取直链并下载（唯一走网络的子命令，CI 不许跑）。
             落 <out>/zips/<name>.zip，逐条把 sha256 等写进 <out>/corpus-lock.json。
  scan       对 <out>/zips/*.zip 逐个跑生产入口 scanZip，写 <out>/corpus-dump.json 并打一张人读表。
             没有 corpus-lock.json 就拒绝跑 —— 不扫来路不明的 zip。
  diff       读 <out>/corpus-dump.json，用 --candidate 那份候选族表只在族进料上重算族集，打逐包前后表。
             candidate 必须是现表的**收窄**（不许有现表里不存在的前缀）：加严需要全量 UND 进料，
             这份数据不在 dump 里，拿这张表算加严得出的「0 移动」是假的。
  selftest   零网络、零 zip，跑几个纯函数断言并打印 ok。

--out 必填，且解析后的路径与它的每一级祖先都不许有 .git（下载的包与产物不进仓库，也不进任何仓的工作树）。
非零退出一律带用法；缺参数不「打印用法后 exit 0」。`;

/**
 * 命令行解析。`--k=v` 与 `--k v` 两种写法都认，第一个裸参数当子命令。
 * @param {string[]} argv
 */
export function parseArgs(argv) {
  const o = { command: '', out: '', manifest: DEFAULT_MANIFEST, candidate: '', only: '', help: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = String(argv[i]);
    if (a === '--help' || a === '-h') { o.help = true; continue; }
    if (!a.startsWith('--')) { rest.push(a); continue; }
    const body = a.slice(2);
    const eq = body.indexOf('=');
    const key = eq >= 0 ? body.slice(0, eq) : body;
    let val = eq >= 0 ? body.slice(eq + 1) : undefined;
    if (val === undefined && i + 1 < argv.length && !String(argv[i + 1]).startsWith('--')) {
      val = String(argv[++i]);
    }
    if (key === 'out') o.out = val ?? '';
    else if (key === 'manifest') o.manifest = val || DEFAULT_MANIFEST;
    else if (key === 'candidate') o.candidate = val ?? '';
    else if (key === 'only') o.only = val ?? '';
    else o.unknown = [o.unknown || [], key].flat();
  }
  o.command = rest[0] || '';
  o.extra = rest.slice(1);
  return o;
}

/**
 * 清单校验。返回 { ok, errors, entries }，entries 是**只保留五个白名单键**的规范化副本 ——
 * 下载直链这类键就算混进了清单，也不会被规范化副本带到下游。
 * @param {unknown} value
 */
export function validateManifest(value) {
  const errors = [];
  const entries = [];
  const text = JSON.stringify(value ?? {});
  // 任何形式的带协议直链都不许出现在清单里。
  if (/https?:\/\//i.test(text)) {
    errors.push('清单里出现了带协议（http/https）的下载物地址：直链必须由 fetch 按 tag 现问 API 拿，写死进清单等于放弃身份绑定');
  }
  if (!value || typeof value !== 'object' || !Array.isArray(value.entries)) {
    errors.push('清单必须是一个带 entries 数组的对象');
    return { ok: false, errors, entries };
  }
  if (value.entries.length === 0) errors.push('entries 是空的，没有可下载的东西');
  const seen = new Set();
  value.entries.forEach((e, i) => {
    const at = `entries[${i}]`;
    if (!e || typeof e !== 'object' || Array.isArray(e)) { errors.push(`${at} 不是对象`); return; }
    // 键名层面也拦一次：值为空串的 url 键同样会让「钉的是 tag」这句话变成假话。
    for (const k of Object.keys(e)) {
      if (/url|link|href|download_uri/i.test(k)) errors.push(`${at}.${k}：清单里不许存下载地址，只存 repo/tag/asset 名`);
    }
    for (const k of ['name', 'repo', 'tag', 'asset']) {
      const v = e[k];
      if (typeof v !== 'string' || !v.trim()) errors.push(`${at}.${k} 必须是非空字符串（实测 ${JSON.stringify(v)}）`);
    }
    if (typeof e.repo === 'string' && !/^[^\s/]+\/[^\s/]+$/.test(e.repo.trim())) {
      errors.push(`${at}.repo 必须是 owner/name 形状（实测 "${e.repo}"）`);
    }
    if (typeof e.asset === 'string' && (e.asset.includes('/') || e.asset.includes('\\'))) {
      errors.push(`${at}.asset 是 release 附件的文件名，不许带路径分隔符（实测 "${e.asset}"）`);
    }
    if (!Number.isInteger(e.bytes) || e.bytes <= 0) {
      errors.push(`${at}.bytes 必须是正整数（身份绑定的一半，实测 ${JSON.stringify(e.bytes)}）`);
    }
    if (typeof e.name === 'string' && e.name.trim()) {
      if (seen.has(e.name)) errors.push(`${at}.name 与前一条重名：${e.name} —— 重名的两枚会互相盖写下载物`);
      seen.add(e.name);
    }
    entries.push({ name: e.name, repo: e.repo, tag: e.tag, asset: e.asset, bytes: e.bytes });
  });
  return { ok: errors.length === 0, errors, entries };
}

/**
 * 族表形状检查：[[族名, 标签, [前缀…]], …]。
 * 表不对就要炸出来 —— 静默把空表当「什么都不命中」，读的人会当成语料干净。
 */
export function assertFamilyTable(table, where = '族表') {
  if (!Array.isArray(table) || table.length === 0) throw new Error(`${where}必须是 [[族名,标签,[前缀…]],…] 形状且非空`);
  for (const row of table) {
    if (!Array.isArray(row) || row.length < 3 || typeof row[0] !== 'string' || !row[0].trim() || !Array.isArray(row[2])) {
      throw new Error(`${where} 的一条不合法：${JSON.stringify(row)}（要 [族名, 标签, 前缀数组]）`);
    }
    for (const p of row[2]) {
      if (typeof p !== 'string' || !p.trim()) throw new Error(`${where} ${row[0]} 的前缀名单里有空或非字符串项：${JSON.stringify(p)}`);
    }
  }
  return table;
}

/**
 * 按给定族表算族名集合（排序、去重）。
 * 规则与 audit/elf-forensics.mjs 的 capabilitySymbols **一字不差**：小写后 `startsWith(prefix)`，
 * 没有第二个条件。返回形状对齐 capabilityFamilies（排序去重的族名数组）。
 * @param {string[]} names 族进料（report.binaryForensics[].capabilityImports 那一格）
 * @param {Array<[string, string, string[]]>} table 族表，默认现表
 */
export function familiesUnder(names, table = CAPABILITY_FAMILIES) {
  assertFamilyTable(table, 'familiesUnder 的');
  const list = Array.isArray(names) ? names.filter((x) => typeof x === 'string' && x.length > 0) : [];
  const hit = new Set();
  for (const name of list) {
    const low = name.toLowerCase();
    for (const [family, , prefixes] of table) {
      if (prefixes.some((p) => low.startsWith(p))) hit.add(family);
    }
  }
  return [...hit].sort();
}

/**
 * 从 target 往上逐层问「这一层有没有 .git」。
 * 不只问本仓那一层：两棵仓在同一个父目录下时，只查本仓会让 `--out ..` 正好把 zip 摞在母本脚边。
 * @param {string} target
 * @param {{ hasDotGit?: (p: string) => boolean }} [fs]
 * @returns {string|null} 命中就返回那一级目录，否则 null
 */
export function findGitWorktreeRoot(target, { hasDotGit } = {}) {
  const has = typeof hasDotGit === 'function' ? hasDotGit : (p) => existsSync(resolve(p, '.git'));
  let cur = resolve(String(target || '.'));
  for (;;) {
    if (has(cur)) return cur;
    const parent = dirname(cur);
    if (parent === cur) return null;                        // 撞到文件系统根
    cur = parent;
  }
}

/**
 * --out 那道闸。返回 { ok, abs, root, reason }。
 * @param {string} out
 */
export function checkOutDir(out) {
  const abs = resolve(String(out || ''));
  const root = findGitWorktreeRoot(abs);
  if (root) {
    return {
      ok: false,
      abs,
      root,
      reason: `--out 解析到 ${abs}，它或它的某一级祖先 ${root} 里有 .git —— 下载的包与语料产物不许落在任何 git 工作树里。`,
    };
  }
  return { ok: true, abs, root: null, reason: '' };
}

/**
 * selftest：零网络、零 zip，把上面几个纯函数的关键刻度当场量一遍。
 * 这里放的是「不需要真包就能钉住」的那几条，其余在 test/audit-corpus.test.mjs。
 */
export function runSelftest(deps = {}) {
  const log = deps.log || console;
  const manifestPath = deps.manifestPath || DEFAULT_MANIFEST;
  const problems = [];
  const need = (cond, msg) => { if (!cond) problems.push(msg); };

  const names = ['execvp', 'mkdir', 'unlink'];
  need(JSON.stringify(familiesUnder(names, CAPABILITY_FAMILIES)) === JSON.stringify(['EXEC', 'FILEWRITE']),
    `familiesUnder(${names.join(',')}, 现表) 应为 [EXEC,FILEWRITE]`);
  need(JSON.stringify(familiesUnder([], CAPABILITY_FAMILIES)) === JSON.stringify([]),
    '空进料必须有确定的空输出');

  // 现表上两套算法一字不差 —— 判据只有一份这件事的当场自检。
  const probe = ['execve', 'socket', 'setns', '__system_property_get', 'unlink', 'fork', 'mkdir', 'chdir', 'bogus_name'];
  need(JSON.stringify(familiesUnder(probe, CAPABILITY_FAMILIES)) === JSON.stringify(capabilityFamilies(probe)),
    '同表时 familiesUnder 与 capabilityFamilies 必须一字不差（出现了第二份词汇表）');

  // 收窄只可能让族变少。
  const narrowed = CAPABILITY_FAMILIES.map(([f, l, ps]) => [f, l, f === 'FILEWRITE' ? ps.filter((p) => p !== 'unlink' && p !== 'mkdir') : ps]);
  need(familiesUnder(names, narrowed).length <= familiesUnder(names, CAPABILITY_FAMILIES).length,
    '摘成员之后族数反而变多 —— 单调性破了');

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    problems.push(`清单读不出来（${manifestPath}）：${err.message}`);
  }
  if (manifest) {
    const v = validateManifest(manifest);
    for (const e of v.errors) problems.push(`清单：${e}`);
    need(v.entries.length === 5, `清单应当是 5 条，实测 ${v.entries.length}`);
  }

  need(findGitWorktreeRoot(process.execPath, { hasDotGit: () => false }) === null, '祖先链走到文件系统根应当收口');

  for (const p of problems) log.error(`selftest 不通过：${p}`);
  if (problems.length) return 1;
  log.log('ok');
  return 0;
}

/**
 * @param {string[]} argv
 * @param {{ log?: { log:Function, error:Function }, fetchImpl?:Function, runDownload?:Function }} [deps]
 * @returns {Promise<number>} 退出码
 */
export async function main(argv = process.argv.slice(2), deps = {}) {
  const log = deps.log || console;
  const opts = parseArgs(argv);
  if (opts.help && !opts.command) {
    log.log(USAGE);
    return 0;
  }
  if (!opts.command || !SUBCOMMANDS.includes(opts.command)) {
    log.error(`子命令 "${opts.command || '(空)'}" 不在值域里 —— 只认 ${SUBCOMMANDS.join('/')}。`);
    log.error(USAGE);
    return 2;
  }
  if (!opts.out) {
    log.error('缺 --out：产物必须显式给一个仓库外的目录。');
    log.error(USAGE);
    return 2;
  }
  const gate = checkOutDir(opts.out);
  if (!gate.ok) {
    log.error(gate.reason);
    log.error(USAGE);
    return 2;
  }

  if (opts.command === 'selftest') {
    return runSelftest({ log, manifestPath: opts.manifest });
  }
  log.error(`子命令 ${opts.command} 还没接到这次交付里（本步只落 selftest 与清单校验）。`);
  log.error(USAGE);
  return 1;
}

// 入口判据用 resolve 比对绝对路径（与本仓其它 CLI 同一个形状）：拿 argv[1] 拼 file:// URL
// 在 Windows 上永远不等于 import.meta.url，脚本会静默不跑。
if (isCliEntry(process.argv[1], fileURLToPath(import.meta.url))) {
  main().then((rc) => { process.exitCode = rc; });
}
