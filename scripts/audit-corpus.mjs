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
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { CAPABILITY_FAMILIES, capabilityFamilies } from '../audit/elf-forensics.mjs';
import { isCliEntry, scanZip } from '../audit/scan.mjs';

/** 清单与候选表的默认形状。 */
export const SUBCOMMANDS = ['fetch', 'scan', 'diff', 'selftest'];
const DEFAULT_MANIFEST = resolve(dirname(fileURLToPath(import.meta.url)), 'corpus-manifest.json');
export const LOCK_NAME = 'corpus-lock.json';
export const DUMP_NAME = 'corpus-dump.json';
const API_ROOT = 'https://api.github.com';

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

/** sha256（Buffer 或文件路径）。语料的身份就靠这一个值。 */
export function sha256Of(input) {
  const buf = Buffer.isBuffer(input) ? input : readFileSync(input);
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * 按 tag 问 release（**不是 latest**）：钉的是 tag，取 latest 会让上游新版本悄悄换掉下载物。
 * @param {{ repo: string, tag: string }} entry
 * @param {{ apiGet?: Function }} [deps]
 */
export async function releaseForTag(entry, deps = {}) {
  const apiGet = deps.apiGet || defaultApiGet;
  return apiGet(entry.repo, entry.tag);
}

async function defaultApiGet(repo, tag) {
  const url = `${API_ROOT}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`;
  const res = await fetch(url, {
    method: 'GET',
    signal: AbortSignal.timeout(30000),
    headers: { 'user-agent': 'audit-corpus', accept: 'application/vnd.github+json' },
  });
  if (!res.ok) throw new Error(`GET /repos/${repo}/releases/tags/${tag} 回了 HTTP ${res.status}`);
  return res.json();
}

/**
 * 从 release 应答里挑出**名字逐字等于**清单 asset 的那一枚，同时核 API 报的字节数。
 * 名字近似（少一个 -release、大小写不同）一律算没找到：静默拿「长得像的那个」下来扫，
 * 事后没人知道扫的是哪个东西。
 */
export function pickAsset(release, entry) {
  const problems = [];
  if (!release || typeof release !== 'object') return { ok: false, problems: ['release 应答不是一个对象'] };
  if (String(release.tag_name || '') !== String(entry.tag)) {
    problems.push(`API 回显的 tag_name 是 "${release.tag_name}"，与清单钉的 "${entry.tag}" 不符`);
  }
  const assets = Array.isArray(release.assets) ? release.assets : [];
  const exact = assets.filter((a) => String(a && a.name) === String(entry.asset));
  if (exact.length !== 1) {
    problems.push(`按名逐字找附件 "${entry.asset}" 找到 ${exact.length} 个（清单钉的是全名）。可用附件：${assets.map((a) => a && a.name).join(', ') || '(空)'}`);
    return { ok: false, problems };
  }
  const asset = exact[0];
  if (!asset.browser_download_url) problems.push(`附件 ${entry.asset} 没有 browser_download_url`);
  if (Number.isInteger(asset.size) && asset.size !== entry.bytes) {
    problems.push(`${entry.asset}：API 报 ${asset.size} 字节，清单记 ${entry.bytes} 字节 —— 上游动过这个 release，或者清单记错了`);
  }
  return { ok: problems.length === 0, problems, asset };
}

/**
 * 下载后的身份绑定。**两道都要过**：
 * 1. 字节数与清单不符 ⇒ 停；
 * 2. 目标路径已存在同名文件而 sha256 与本次不同 ⇒ 停，**不覆盖**。
 *
 * 第 2 道是本仓最常翻车的地方：旧包的字节盖到新包上，之后所有扫描结论都记在一个从没存在过的
 * 东西身上，而 dump 里的 sha256 看着完全自洽。宁可停下来让人去看，不许静默换芯。
 * @param {string} targetPath <out>/zips/<name>.zip
 * @param {Buffer} incoming 本次下载到的字节
 * @param {{ bytes: number, name: string }} entry
 * @param {{ read?: Function, write?: Function, exists?: Function, sha256?: Function }} [fs]
 */
export function placeZip(targetPath, incoming, entry, fs = {}) {
  const read = fs.read || ((p) => readFileSync(p));
  const write = fs.write || ((p, b) => writeFileSync(p, b));
  const exists = fs.exists || ((p) => existsSync(p));
  const sha = fs.sha256 || sha256Of;
  const incomingSha = sha(incoming);
  const incomingBytes = Buffer.isBuffer(incoming) ? incoming.length : Number(incomingBytesOf(incoming));
  if (Number.isInteger(entry.bytes) && incomingBytes !== entry.bytes) {
    return { ok: false, stopped: 'bytes-mismatch', path: targetPath, expected: entry.bytes, actual: incomingBytes, sha256: incomingSha };
  }
  if (exists(targetPath)) {
    const existing = read(targetPath);
    const existingSha = sha(existing);
    if (existingSha !== incomingSha) {
      return { ok: false, stopped: 'name-collision', path: targetPath, existingBytes: existing.length, existingSha, incomingSha };
    }
    return { ok: true, reused: true, path: targetPath, sha256: incomingSha, bytes: incomingBytes };
  }
  write(targetPath, incoming);
  return { ok: true, wrote: true, path: targetPath, sha256: incomingSha, bytes: incomingBytes };
}

function incomingBytesOf(input) {
  return Buffer.isBuffer(input) ? input.length : String(input ?? '').length;
}

/** curl -sSL 下载。只把字节收进内存，落盘由 placeZip 决定。 */
function defaultDownload(url) {
  const r = spawnSync('curl', ['-sSL', '--fail', '--fail-early', '--max-time', '180', url], {
    encoding: 'buffer', maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`curl 起不来：${r.error.message}`);
  if (r.status !== 0) {
    const tail = Buffer.from(r.stderr || Buffer.alloc(0)).toString('utf8').trim().slice(0, 300);
    throw new Error(`curl 退出码 ${r.status}${tail ? `：${tail}` : ''}`);
  }
  return r.stdout;
}

/**
 * 取一个 lock 行（下载来路的证人）。缺 lock 就拒绝扫 —— 不扫不知道来路的 zip。
 * @param {string} lockPath
 * @param {{ name: string, repo: string, tag: string, asset: string, bytes: number }} entry
 */
export function lockRowFor(lock, entry) {
  const rows = Array.isArray(lock && lock.entries) ? lock.entries : [];
  return rows.find((r) => String(r && r.name) === String(entry.name)) || null;
}

/**
 * fetch 一个包：现问 API ⇒ 逐字挑附件 ⇒ curl 下载 ⇒ 身份绑定落盘 ⇒ 交 lock 行。
 * @param {{ name:string, repo:string, tag:string, asset:string, bytes:number }} entry
 * @param {object} [deps]
 */
export async function fetchOne(entry, deps = {}) {
  const log = deps.log || console;
  const zipsDir = deps.zipsDir;
  const targetPath = join(zipsDir, `${entry.name}.zip`);
  let release;
  try {
    release = await releaseForTag(entry, { apiGet: deps.apiGet });
  } catch (err) {
    return { ok: false, name: entry.name, why: `问 release 这一步就没成：${err.message}` };
  }
  const picked = pickAsset(release, entry);
  if (!picked.ok) return { ok: false, name: entry.name, why: picked.problems.join('；') };

  if (existsSync(targetPath)) log.log(`${entry.name}: ${targetPath} 已存在，照样下载一份来比字节（同名不同字节必须当场可见）`);
  let incoming;
  try {
    incoming = (deps.download || defaultDownload)(picked.asset.browser_download_url);
  } catch (err) {
    return { ok: false, name: entry.name, why: `下载失败（${picked.asset.browser_download_url}）：${err.message}` };
  }
  const placed = placeZip(targetPath, incoming, entry, { read: deps.read, write: deps.write, exists: deps.exists, sha256: deps.sha256 });
  if (!placed.ok) {
    const why = placed.stopped === 'name-collision'
      ? `同名不同字节：${placed.path} 已是 sha256 ${placed.existingSha}（${placed.existingBytes}B），本次下载到 ${placed.incomingSha} —— 不覆盖。可能是上游改过这个 release，也可能是旧包盖在新包上。`
      : `字节数与清单不符：清单记 ${placed.expected}，本次拿到 ${placed.actual} —— 不覆盖。`;
    return { ok: false, name: entry.name, why, stopped: placed.stopped };
  }
  return {
    ok: true,
    row: {
      name: entry.name, repo: entry.repo, tag: entry.tag, asset: entry.asset,
      url: picked.asset.browser_download_url, bytes: placed.bytes, sha256: placed.sha256,
      fetched_at: new Date().toISOString(), reused: placed.reused === true,
    },
  };
}

/**
 * 从生产报告里取一格现成的字段搭 dump 行。字段名一律取自报告，不做第二份猜法：
 * 报告里没有 level 这个键（只有 riskLevel），逐枚二进制在 binaryForensics 而不是 binaries，
 * decide() 返回的是对象（取 .action）。ruleHistogram 是**本工具自己数的**，报告里没有这一格。
 * @param {{ name: string, zipSha256: string, zipBytes: number, zipPath: string }} src
 * @param {object} report scanZip 的返回
 */
export function buildDumpRow(src, report) {
  const rows = Array.isArray(report.binaryForensics) ? report.binaryForensics : [];
  const histogram = new Map();
  for (const f of (Array.isArray(report.findings) ? report.findings : [])) {
    const id = String((f && f.ruleId) || '(无 ruleId)');
    histogram.set(id, (histogram.get(id) || 0) + 1);
  }
  return {
    name: src.name,
    zipPath: src.zipPath,
    zipBytes: src.zipBytes,
    zipSha256: src.zipSha256,
    riskLevel: report.riskLevel,
    counts: report.counts,
    decision: report.decision && report.decision.action,
    // 本工具衍生：报告里没有 ruleHistogram 这一格，这里只是把 findings 的 ruleId 数一遍，
    // 好让「这一包的噪声长什么样」在重跑之间可比。
    ruleHistogram: Object.fromEntries([...histogram.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
    binaries: rows.map((row) => {
      const out = {
        name: row.name,
        outcome: row.outcome,
        families: Array.isArray(row.families) ? row.families : [],
        importCount: row.importCount,
        sensitiveImports: Array.isArray(row.sensitiveImports) ? row.sensitiveImports : [],
        capabilityImports: Array.isArray(row.capabilityImports) ? row.capabilityImports : [],
        capabilityImportsTotal: row.capabilityImportsTotal,
      };
      if (row.machineName) out.machineName = row.machineName;
      if (Array.isArray(row.needed)) out.needed = row.needed;
      if (row.parseError) out.parseError = row.parseError;
      if (row.inputCapped === true) out.inputCapped = true;
      // 报告里这一格**只在被截时才写**，读它要 `=== true`，别假设键一定在。
      if (row.capabilityImportsCapped === true) out.capabilityImportsCapped = true;
      return out;
    }),
  };
}

/** 逐包的族集（取该包所有枚的并集，排序）。档位口径 ≥2 族才算危险族多族，见 diff 的前后表。 */
export function familiesOfDumpRow(row) {
  const set = new Set();
  for (const b of (row.binaries || [])) for (const f of (b.families || [])) set.add(f);
  return [...set].sort();
}

function renderScanTable(rows) {
  const lines = [];
  lines.push('包名 | ELF 数 | 每枚的族 | riskLevel | 结论');
  lines.push('--- | --- | --- | --- | ---');
  for (const r of rows) {
    const per = (r.binaries || []).map((b) => `${b.name}: ${(b.families || []).join('+') || '无族'}`).join(' ; ') || '(没有 ELF)';
    lines.push(`${r.name} | ${(r.binaries || []).length} | ${per} | ${r.riskLevel} | ${r.decision}`);
  }
  return lines;
}

/**
 * 把本次取到的 lock 行合进已有 lock（按 name 覆盖同名行，其余保留）。
 * 单独成函数是为了让 --only 跑半截时不至于把别的包证人清空 —— 那等于让 scan 再也认不出那些包。
 * 纯函数：不碰盘，只吃两个 JSON 对象。
 * @param {object|null} existing
 * @param {object[]} fresh
 */
export function mergeLock(existing, fresh) {
  const byName = new Map();
  for (const r of (Array.isArray(existing && existing.entries) ? existing.entries : [])) {
    if (r && typeof r.name === 'string') byName.set(r.name, r);
  }
  for (const r of (Array.isArray(fresh) ? fresh : [])) byName.set(r.name, r);
  return {
    schema: 'audit-corpus-lock/v1',
    updated_at: new Date().toISOString(),
    entries: [...byName.values()].sort((a, b) => (a.name < b.name ? -1 : 1)),
  };
}

/**
 * fetch：读清单 ⇒ 每条按 tag 现问 API ⇒ curl -sSL 下载 ⇒ 身份绑定落盘 ⇒ 写 <out>/corpus-lock.json。
 * 这是本工具唯一走网络的子命令，而且必须由人显式敲；CI 不许跑。
 * 一条身份绑定不过就整轮停下来报出来，不覆盖已有 zip。
 */
export async function runFetch(deps = {}) {
  const log = deps.log || console;
  const out = deps.out;
  const manifest = deps.manifest;
  const zipsDir = join(out, 'zips');
  mkdirSync(zipsDir, { recursive: true });
  const only = deps.only || '';
  const wanted = manifest.entries.filter((e) => !only || e.name === only);
  if (!wanted.length) return { code: 2, problems: [`--only "${only}" 在清单里没有这一条`] };

  const problems = [];
  const fresh = [];
  for (const entry of wanted) {
    const r = await fetchOne(entry, {
      zipsDir, log, apiGet: deps.apiGet, download: deps.download,
      read: deps.read, write: deps.write, exists: deps.exists, sha256: deps.sha256,
    });
    if (r.ok) {
      fresh.push(r.row);
      log.log(`${entry.name}: ${r.row.bytes} 字节 sha256=${r.row.sha256}（${r.row.reused ? '与盘上一致，未改写' : '新落盘'}）`);
    } else {
      problems.push(`${r.name}: ${r.why}`);
      log.error(`停下来 ${r.name}: ${r.why}`);
    }
  }
  const lockPath = join(out, LOCK_NAME);
  const existing = existsSync(lockPath) ? safeReadJson(lockPath) : null;
  const lock = mergeLock(existing, fresh);
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
  log.log(`lock 写了 ${fresh.length} 条（本次成功），累计 ${lock.entries.length} 条 ⇒ ${lockPath}`);
  if (problems.length) return { code: 1, problems, lock };
  return { code: 0, problems: [], lock };
}

function safeReadJson(p) {
  try {
    return JSON.parse(readFileSync(p, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * scan：读 <out>/zips/*.zip（按 lock 逐条核字节与 sha256）⇒ 每个包跑生产入口
 * scanZip(路径, { changeType: 'first' }) ⇒ 写 <out>/corpus-dump.json ⇒ 打人读表。
 * 只读，不执行包里任何东西。
 */
export async function runScan(deps = {}) {
  const log = deps.log || console;
  const out = deps.out;
  const manifest = deps.manifest;
  const zipsDir = join(out, 'zips');
  const lockPath = join(out, LOCK_NAME);
  if (!existsSync(lockPath)) {
    return { code: 2, problems: [`没有 ${LOCK_NAME} —— 拒绝扫描：不扫来路不明的 zip。先跑 fetch。`] };
  }
  let lock;
  try {
    lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  } catch (err) {
    return { code: 2, problems: [`${LOCK_NAME} 读不出来：${err.message}`] };
  }
  const only = deps.only || '';
  const wanted = manifest.entries.filter((e) => !only || e.name === only);
  if (!wanted.length) return { code: 2, problems: [`--only "${only}" 在清单里没有这一条`] };
  const rows = [];
  const problems = [];
  for (const entry of wanted) {
    const row = lockRowFor(lock, entry);
    if (!row) { problems.push(`${entry.name} 不在 ${LOCK_NAME} 里 —— 它没有来路证人，不扫。`); continue; }
    const zipPath = join(zipsDir, `${entry.name}.zip`);
    if (!existsSync(zipPath)) { problems.push(`${zipPath} 不在盘上（fetch 没成功或被删）。`); continue; }
    const actual = sha256Of(zipPath);
    if (actual !== row.sha256) {
      problems.push(`${entry.name}: 盘上字节 sha256 ${actual} 与 lock 记的 ${row.sha256} 不一致 —— 停下来，不扫一个说不清来路的东西。`);
      continue;
    }
    if (Number.isInteger(row.bytes) && statSize(zipPath) !== row.bytes) {
      problems.push(`${entry.name}: 盘上 ${statSize(zipPath)} 字节与 lock 记的 ${row.bytes} 不符。`);
      continue;
    }
    let report;
    try {
      report = await scanZip(zipPath, { changeType: 'first' });
    } catch (err) {
      problems.push(`${entry.name}: scanZip 抛了 —— ${err && err.message}`);
      continue;
    }
    rows.push(buildDumpRow({
      name: entry.name, zipPath, zipBytes: statSize(zipPath), zipSha256: row.sha256,
    }, report));
  }
  if (problems.length) return { code: 1, problems, rows };
  const dump = { schema: 'audit-corpus-dump/v1', generatedAt: new Date().toISOString(), tool: 'scripts/audit-corpus.mjs scan', currentTable: CAPABILITY_FAMILIES.map(([f, , ps]) => [f, ps]), rows };
  writeFileSync(join(out, DUMP_NAME), `${JSON.stringify(dump, null, 2)}\n`);
  log.log(`扫了 ${rows.length} 个包 ⇒ ${join(out, DUMP_NAME)}`);
  for (const line of renderScanTable(rows)) log.log(line);
  const capped = rows.flatMap((r) => (r.binaries || []).filter((b) => b.capabilityImportsCapped === true).map((b) => `${r.name}/${b.name}`));
  if (capped.length) log.log(`注意：这些枚的族名单被截过（族数偏低的那一格）：${capped.join(', ')}`);
  return { code: 0, problems: [], rows, dumpPath: join(out, DUMP_NAME) };
}

function statSize(p) {
  try {
    return statSync(p).size;
  } catch {
    return -1;
  }
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

  let manifestJson = null;
  try {
    manifestJson = JSON.parse(readFileSync(opts.manifest, 'utf8'));
  } catch (err) {
    log.error(`清单读不出来（${opts.manifest}）：${err.message}`);
    return 2;
  }
  const checked = validateManifest(manifestJson);
  if (!checked.ok) {
    for (const e of checked.errors) log.error(`清单：${e}`);
    log.error(USAGE);
    return 2;
  }
  const manifest = { schema: manifestJson.schema, entries: checked.entries };

  if (opts.command === 'fetch') {
    const r = await runFetch({
      log, out: gate.abs, manifest, only: opts.only,
      apiGet: deps.apiGet, download: deps.download, read: deps.read, write: deps.write, exists: deps.exists, sha256: deps.sha256,
    });
    for (const p of r.problems) log.error(p);
    return r.code;
  }
  if (opts.command === 'scan') {
    const r = await runScan({ log, out: gate.abs, manifest, only: opts.only });
    for (const p of r.problems) log.error(p);
    return r.code;
  }
  log.error(`子命令 ${opts.command} 还没接到这次交付里（本步只落 fetch 与 scan）。`);
  log.error(USAGE);
  return 1;
}

// 入口判据用 resolve 比对绝对路径（与本仓其它 CLI 同一个形状）：拿 argv[1] 拼 file:// URL
// 在 Windows 上永远不等于 import.meta.url，脚本会静默不跑。
if (isCliEntry(process.argv[1], fileURLToPath(import.meta.url))) {
  main().then((rc) => { process.exitCode = rc; });
}
