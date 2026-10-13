#!/usr/bin/env node
// 模块投稿安全审核 —— 静态风险扫描器
//
// 用法：
//   node scan.mjs <module.zip> [选项]
//
// 选项：
//   --declared-id <id>         投稿表单声明的 module id
//   --declared-version <ver>   投稿表单声明的 version
//   --change-type first|update 手动指定“首次收录 / 版本更新”
//   --index <index.json>       已收录索引（数组或 {modules:[]}），用于自动判定 first/update
//   --json <path>              JSON 报告输出路径（默认 <zip>.audit.json）
//   --markdown <path>          Markdown 报告输出路径（默认 <zip>.audit.md）
//   --out-dir <dir>            同时输出两种报告到该目录
//   --stdout                   额外把 markdown 打到 stdout
//   --quiet                    只输出一行结论
//   --fail-on <level>          风险 >= 该级别时退出码为 2（high|medium|low|never，默认 never）
//
// 仅使用 node: 内置模块，无任何 npm 依赖。

import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { basename, dirname, resolve, join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';

import {
  CONTENT_RULES, scanContent, checkMetadata, parseModuleProp,
  scoreRisk, decide, countsTowardRisk, CATEGORY_LABEL, SEVERITY_ORDER,
  inspectStructure, checkCoverage, checkUnread, checkBinaries, detectBinary,
  MAX_TEXT, MAX_ENTRY_UNCOMPRESSED, EXEC_BUNDLED_FILE,
} from './risk-rules.mjs';
// ---------------------------------------------------------------------------
// ZIP 解析（自带简易实现，失败时回退系统 unzip）
// ---------------------------------------------------------------------------

const SIG_EOCD = 0x06054b50;
const SIG_CEN = 0x02014b50;
const SIG_LOC = 0x04034b50;

function findEOCD(buf) {
  const maxBack = Math.min(buf.length, 65557);
  for (let i = buf.length - 22; i >= buf.length - maxBack && i >= 0; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

function parseZip(buf) {
  const eocd = findEOCD(buf);
  if (eocd < 0) throw new Error('找不到 EOCD 记录，文件可能不是 zip');
  let count = buf.readUInt16LE(eocd + 10);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // zip64：值为哨兵时改从 zip64 EOCD 读取
  if (count === 0xffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === 0x07064b50) {
      const z64 = Number(buf.readBigUInt64LE(loc + 8));
      if (buf.readUInt32LE(z64) === 0x06064b50) {
        count = Number(buf.readBigUInt64LE(z64 + 32));
        cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
      }
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CEN) break;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    let origSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const extAttrs = buf.readUInt32LE(p + 38);
    let localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);

    // zip64 扩展字段
    let z = 0;
    while (z + 4 <= extra.length) {
      const hid = extra.readUInt16LE(z);
      const hsz = extra.readUInt16LE(z + 2);
      const body = extra.subarray(z + 4, z + 4 + hsz);
      if (hid === 0x0001) {
        let q = 0;
        if (origSize === 0xffffffff && q + 8 <= body.length) { origSize = Number(body.readBigUInt64LE(q)); q += 8; }
        if (compSize === 0xffffffff && q + 8 <= body.length) { compSize = Number(body.readBigUInt64LE(q)); q += 8; }
        if (localOff === 0xffffffff && q + 8 <= body.length) { localOff = Number(body.readBigUInt64LE(q)); q += 8; }
      }
      z += 4 + hsz;
    }

    // 本地头 -> 数据起点
    let dataOff = null;
    let storedComp = compSize;
    if (localOff + 30 <= buf.length && buf.readUInt32LE(localOff) === SIG_LOC) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      dataOff = localOff + 30 + lNameLen + lExtraLen;
      // 本地头里若声明了 0（流式压缩），以中心目录为准，退化为按下一个已知边界推断
      const lComp = buf.readUInt32LE(localOff + 18);
      if (lComp !== 0 && lComp !== compSize) storedComp = lComp;
    }

    // unix 权限位藏在外部属性的两个高位字节里：0xA000 == S_IFLNK。
    // 这是唯一能在解压前认出符号链接的地方，而链接正是「模块内路径指向设备任意位置」
    // 的入口，所以必须在这里取到，不能等到读内容才发现。
    const unixMode = (extAttrs >>> 16) & 0xffff;

    entries.push({
      name, method, flags, compSize: storedComp || compSize, origSize, dataOff,
      encrypted: (flags & 0x1) !== 0,
      isDir: name.endsWith('/'),
      isSymlink: (unixMode & 0xf000) === 0xa000,
      unixMode,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/**
 * 解压单个条目。
 *
 * 上限必须在解压时就生效，而不是事后看比值：中心目录里的 origSize 是投稿者自己写的，
 * 一个声明 4 KB 实际解出 4 GB 的条目，光靠比值检查会当场把 runner 打满。
 * maxOutputLength 让 zlib 在越界时抛 ERR_BUFFER_TOO_LARGE，这条信息会被转成
 * 「审核未覆盖该条目」的 finding 参与定级，而不是留在 warnings 里好看一眼。
 */
function inflateEntry(buf, e, limit = MAX_ENTRY_UNCOMPRESSED) {
  if (e.dataOff == null) throw new Error(`无法定位 ${e.name} 的数据区`);
  const raw = buf.subarray(e.dataOff, e.dataOff + e.compSize);
  const over = (msg) => { const err = new Error(msg); err.overLimit = true; return err; };

  if (e.method === 0) {
    if (raw.length > limit) throw over(`stored 条目解压后 ${raw.length} B，超过上限 ${limit} B`);
    return raw;
  }
  if (e.method === 8) {
    if (Number(e.origSize) > limit) throw over(`声明解压后 ${e.origSize} B，超过上限 ${limit} B`);
    try {
      return inflateRawSync(raw, { maxOutputLength: limit });
    } catch (err) {
      if (err && err.code === 'ERR_BUFFER_TOO_LARGE') throw over(`解压后超过上限 ${limit} B（声明值不可信，已按实际解压拦下）`);
      throw err;
    }
  }
  throw new Error(`不支持的压缩方式 ${e.method}（${e.name}）`);
}

function listZipViaUnzip(zipPath) {
  const r = spawnSync('unzip', ['-Z1', zipPath], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0 && !r.stdout) throw new Error('unzip 不可用：' + (r.error ? r.error.message : r.stderr));
  return r.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

function readZipViaUnzip(zipPath, name) {
  const r = spawnSync('unzip', ['-p', zipPath, name], { maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error('unzip -p 失败：' + (r.error ? r.error.message : r.stderr));
  return r.stdout;
}

/**
 * 读取 zip 中所有文件
 * @param {string} zipPath
 * @param {number} [maxEntryBytes] 单条解压硬上限（测试与低配 runner 会想收紧）
 * @returns {{ files: Array<{name,size,content,head,truncated}>, entries: object[],
 *             unread: Array<{name,reason,overLimit}>, source: 'builtin'|'unzip', warnings: string[] }}
 */
export function readZip(zipPath, maxEntryBytes = MAX_ENTRY_UNCOMPRESSED) {
  const warnings = [];
  const buf = readFileSync(zipPath);
  let entries;
  try {
    entries = parseZip(buf);
  } catch (err) {
    warnings.push(`内置 zip 解析失败（${err.message}），回退到系统 unzip`);
    return readZipFallback(zipPath, warnings);
  }

  const files = [];
  const unread = [];
  for (const e of entries) {
    if (e.isDir) continue;
    try {
      files.push(toFileEntry(e.name, inflateEntry(buf, e, maxEntryBytes)));
    } catch (err) {
      warnings.push(`无法解压 ${e.name}：${err.message}`);
      unread.push({ name: e.name, reason: err.message, overLimit: Boolean(err && err.overLimit) });
    }
  }
  // 只有在「一个都没读出来，且不是因为主动挡下了超大条目」时才回退。
  // 否则回退等于把刚拦住的 zip bomb 交给系统 unzip 再试一遍。
  const deliberate = unread.some((u) => u.overLimit);
  if (files.length === 0 && entries.length > 0 && !deliberate) {
    warnings.push('没有成功解压出任何文件，回退到系统 unzip');
    return readZipFallback(zipPath, warnings);
  }
  return { files, entries, unread, source: 'builtin', warnings };
}

function readZipFallback(zipPath, warnings) {
  const names = listZipViaUnzip(zipPath);
  const files = [];
  const unread = [];
  for (const name of names) {
    if (name.endsWith('/')) continue;
    try {
      files.push(toFileEntry(name, readZipViaUnzip(zipPath, name)));
    } catch (err) {
      warnings.push(`无法读取 ${name}：${err.message}`);
      unread.push({ name, reason: err.message, overLimit: false });
    }
  }
  return { files, entries: [], unread, source: 'unzip', warnings };
}

function toFileEntry(name, buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const truncated = bytes.length > MAX_TEXT;
  return {
    name,
    size: bytes.length,
    // 行级规则必须跑全文：截断只能限制「报告里内嵌多少」，绝不能让后缀字节
    // 逃过检测，否则把 payload 塞到 512 KB 之后就是免检通道。
    content: bytes.toString('utf8'),
    head: bytes.subarray(0, 512),
    truncated,
  };
}

// ---------------------------------------------------------------------------
// 文件分类
// ---------------------------------------------------------------------------

export const CANONICAL_SCRIPTS = ['customize.sh', 'service.sh', 'post-fs-data.sh', 'uninstall.sh', 'action.sh'];

/**
 * 安装期真正会被执行的入口。
 *
 * 这几个名字不是「可能的脚本」，而是「解压后会被拿去跑的东西」：
 * update-binary 是安装器第一个执行的程序，updater-script 在某些实现里是被解释执行的脚本。
 * 它们此前落在 others 里、一行都没扫，等于「把恶意代码放进文件名最正当的那个文件」
 * 就能免检 —— 这是本次补盲里收益最大的一处。
 */
export const FLASH_ENTRY_POINTS = [
  'META-INF/com/google/android/update-binary',
  'META-INF/com/google/android/updater-script',
  'META-INF/com/google/android/update-binary.bin',
];

/** 会被解释执行的后缀。模块里出现的脚本语言就这几种。 */
export const SCRIPT_EXTS = ['.sh', '.lua', '.js'];

/** key=value 形式的属性文件，installer/resetprop 会读，同样纳入内容规则 */
export const PROP_EXTS = ['.prop'];

export function classify(files) {
  const norm = (p) => String(p).replace(/\\/g, '/');
  const base = (p) => basename(norm(p));
  const canonical = [];
  const otherScripts = [];
  const handlers = [];
  const props = [];
  const binaries = [];
  const others = [];
  let propEntry = null;

  for (const f of files) {
    const n = norm(f.name);
    const b = base(n);
    if (b === 'module.prop' && !propEntry) propEntry = f;

    // 二进制优先于扩展名判断：把 ELF 改名成 config.js 是绕过扩展名分类的最省事做法，
    // 所以先看魔数，再看名字。
    const bin = detectBinary(f.head);
    if (bin) { binaries.push({ ...f, binary: bin }); continue; }

    if (CANONICAL_SCRIPTS.includes(b)) { canonical.push(f); continue; }
    if (FLASH_ENTRY_POINTS.includes(n)) { handlers.push(f); continue; }
    const ext = extname(b).toLowerCase();
    if (SCRIPT_EXTS.includes(ext)) { otherScripts.push(f); continue; }
    if (PROP_EXTS.includes(ext)) { props.push(f); continue; }
    others.push(f);
  }
  // 规范脚本按既定顺序排列，便于阅读
  canonical.sort((a, b) => CANONICAL_SCRIPTS.indexOf(base(a.name)) - CANONICAL_SCRIPTS.indexOf(base(b.name)));
  return { canonical, otherScripts, handlers, props, binaries, others, propEntry };
}

// ---------------------------------------------------------------------------
// 扫描
// ---------------------------------------------------------------------------

// 引用写法里的模块目录前缀：$MODPATH/x、${MODDIR}/x、$TMPMODDIR/x 与
// /data/adb/modules/<id>/x 都归一到「模块根目录下的 x」。
const REF_MODDIR_PREFIX = /^\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?\//;
const REF_ABS_PREFIX = /^\/data\/adb\/modules\//;

/**
 * 把一条 EXEC_BUNDLED_FILE 的命中还原成「相对模块根的被引用路径」。
 *
 * 只做前缀剥离，不做模糊匹配：命中文本的尾部 token 就是 pattern 里那个 `[^\s"']+`
 * 匹配到的整段路径（引号被 `"?` 吃掉、路径本身不含空白），所以取尾部 token 是确定性的。
 * @returns {string|null} 解析不出模块内路径时返回 null
 */
function refRelPath(matchText, moduleId = '') {
  const token = (String(matchText).match(/[^\s"']+$/) || [''])[0];
  if (!token) return null;
  let p;
  if (REF_MODDIR_PREFIX.test(token)) p = token.replace(REF_MODDIR_PREFIX, '');
  else if (REF_ABS_PREFIX.test(token)) p = token.replace(REF_ABS_PREFIX, '');
  else return null;
  p = p.replace(/^\.\/+/, '');
  // 绝对写法带着模块 id：只有等于本次模块 id 时才剥掉，否则那是指向别的模块，不是包内条目。
  if (moduleId && p.startsWith(`${moduleId}/`)) p = p.slice(moduleId.length + 1);
  return p || null;
}

/**
 * 找出「被执行但当前不在扫描面里」的包内条目，供调用方追加进扫描面。
 *
 * 三条硬要求（缺一条这条闸就只剩名字）：
 *  1. 引用的路径必须在包内真实存在 —— 指向 /data/local/tmp 这类下载物的不算（那是 T3）；
 *  2. 条目名精确匹配、大小写原样，已在扫描面里或本次已取过的不重复追加（防环也防刷屏）；
 *     已经是被扫描的文本后缀（.sh/.lua/.js/.prop）不再升级 —— 它们本来就被逐行扫过。
 *  3. 只要被 sh/source 引用就当可执行文本纳入，**不管它像不像文本**：这条压过 T4 的
 *     可打印比例阈值，否则「把 payload 填成二进制样」就是现成的逃逸阀。
 * 返回的条目挂上 __from/__line/__ref，报告要能指出是谁在第几行引用了它。
 * 只递归一层：本函数只看初始扫描面的引用，不追随被升级条目自己的引用。
 * @param {Array<{name:string, content:string}>} scanTargets
 * @param {Array<{name:string}>} allEntries
 * @param {string} moduleId
 */
export function resolveBundledTargets(scanTargets = [], allEntries = [], moduleId = '') {
  const scanned = new Set(scanTargets.map((f) => f && f.name));
  const byName = new Map();
  for (const f of Array.isArray(allEntries) ? allEntries : []) {
    if (f && f.name && !byName.has(f.name)) byName.set(f.name, f);
  }
  const out = [];
  const taken = new Set();
  const re = new RegExp(
    EXEC_BUNDLED_FILE.pattern.source,
    EXEC_BUNDLED_FILE.pattern.flags.includes('g') ? EXEC_BUNDLED_FILE.pattern.flags : EXEC_BUNDLED_FILE.pattern.flags + 'g',
  );
  for (const f of scanTargets) {
    const lines = String(f && f.content != null ? f.content : '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(lines[i]))) {
        const rel = refRelPath(m[0], moduleId);
        if (rel) {
          const entry = byName.get(rel);
          // 要求 1：包内不存在就不升级（引用行本身已由 EXEC_BUNDLED_FILE 报出）
          if (entry && !scanned.has(entry.name) && !taken.has(entry.name)) {
            const n = String(entry.name).replace(/\\/g, '/');
            const ext = extname(basename(n)).toLowerCase();
            // 要求 2：已在扫描面里的文本后缀不重复纳入
            if (!SCRIPT_EXTS.includes(ext) && !PROP_EXTS.includes(ext)) {
              taken.add(entry.name);
              out.push({ ...entry, __from: f.name, __line: i + 1, __ref: m[0].trim() });
            }
          }
        }
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    }
  }
  return out;
}

/**
 * @param {string} zipPath
 * @param {{ declaredId?:string, declaredVersion?:string, changeType?: 'first'|'update', index?: object,
 *           maxEntryBytes?: number }} opts
 */
export function scanZip(zipPath, opts = {}) {
  const started = Date.now();
  const maxEntryBytes = Number(opts.maxEntryBytes) > 0 ? Number(opts.maxEntryBytes) : MAX_ENTRY_UNCOMPRESSED;
  const { files, entries, unread, source, warnings } = readZip(zipPath, maxEntryBytes);
  const { canonical, otherScripts, handlers, props, binaries, propEntry } = classify(files);

  // 行级规则覆盖「会被执行的文本」：规范脚本、其他脚本、安装期入口、属性文件。
  // 二进制只登记不逐行扫（见 checkBinaries 的理由），非脚本数据文件只进清单。
  const scanTargets = [...canonical, ...otherScripts, ...handlers, ...props];

  // 载荷间接执行：被脚本 sh/source 引用的包内条目必须进扫描面，而且必须发生在下面那个
  // 内容扫描循环之前 —— 追加在循环之后的话，那些条目一行都不会被扫，测试却照样能
  // 「命中 EXEC_BUNDLED_FILE」，于是这条闸变成只有名字没有牙的装饰。
  const escalated = [];
  const escalatedEntries = [];
  // modId 只能取 fields.id.value：fields.id 是 {value,line}，直接拿它当字符串会拼出
  // /data/adb/modules/[object Object]/，引用解析永远匹配不上真实条目（评审 F9）。
  const idField = propEntry ? parseModuleProp(propEntry.content).fields.id : null;
  const modId = (idField && idField.value) || opts.declaredId || '';
  for (const e of resolveBundledTargets(scanTargets, files, modId)) {
    scanTargets.push(e);
    escalatedEntries.push(e);
    escalated.push({ fromFile: e.__from, fromLine: e.__line, ref: e.__ref, resolvedEntry: e.name });
  }

  const findings = [];
  for (const f of scanTargets) {
    findings.push(...scanContent(f.name, f.content));
  }

  // module.prop 也要过一遍内容规则（里面可能有外联地址或隐私路径）
  const propFindings = propEntry && !scanTargets.includes(propEntry)
    ? scanContent(propEntry.name, propEntry.content)
    : [];

  const propMeta = propEntry
    ? { present: true, path: propEntry.name, fields: parseModuleProp(propEntry.content).fields, raw: propEntry.content }
    : { present: false, path: 'module.prop', fields: {} };
  const metaFindings = checkMetadata(propMeta, { id: opts.declaredId, version: opts.declaredVersion });

  // 结构与覆盖度。这些不是「补充说明」，而是与内容发现同级参与定级的依据：
  // 读不到的字节、看不全的文件、解压前就能看出的路径越界，都必须拦住自动放行。
  const struct = inspectStructure(source === 'builtin' ? entries : files.map((f) => ({ name: f.name })));
  // 报告里的上限必须是这次真正生效的上限，否则「按阈值放行」无法复核。
  struct.stats.limits.MAX_ENTRY_UNCOMPRESSED = maxEntryBytes;
  const coverFindings = checkCoverage(files);
  const unreadFindings = checkUnread(unread);
  const binFindings = checkBinaries(binaries.map((b) => ({ name: b.name, id: b.binary.id, why: b.binary.why, bytes: b.size })));
  const metadataFindings = source === 'unzip' ? [{
    ruleId: 'AUDIT_COVERAGE_METADATA',
    category: 'structure',
    severity: 'medium',
    file: '<zip>',
    line: 0,
    snippet: 'reader=unzip',
    message: '内置 zip 解析失败，回退到系统 unzip：条目名以外的元数据（符号链接、压缩比、外部属性）未经检查',
    advice: '回退通道看不到结构属性，因此本次审核不完整，不予自动放行。请用标准工具重新打包后再投。',
  }] : [];

  const all = [...findings, ...propFindings, ...metaFindings,
    ...struct.findings, ...coverFindings, ...unreadFindings, ...binFindings, ...metadataFindings]
    .filter((f) => f.severity != null)
    .sort((a, b) => {
      const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (d !== 0) return d;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });

  const { level, counts, reasons } = scoreRisk(all);
  const changeType = resolveChangeType(opts, propMeta);
  const decision = decide(level, changeType);

  return {
    schema: 'module-audit-report/v1',
    generatedAt: new Date().toISOString(),
    target: { zip: zipPath, zipName: basename(zipPath), bytes: statSync(zipPath).size },
    reader: source,
    declared: { id: opts.declaredId || null, version: opts.declaredVersion || null },
    meta: {
      id: propMeta.fields.id ? propMeta.fields.id.value : null,
      version: propMeta.fields.version ? propMeta.fields.version.value : null,
      name: propMeta.fields.name ? propMeta.fields.name.value : null,
      author: propMeta.fields.author ? propMeta.fields.author.value : null,
      description: propMeta.fields.description ? propMeta.fields.description.value : null,
      propPath: propMeta.present ? propMeta.path : null,
      propPresent: propMeta.present,
    },
    structure: struct.stats,
    unread,
    binaries: binaries.map((b) => ({ name: b.name, kind: b.binary.id, bytes: b.size })),
    // 被引用而升级进扫描面的条目：谁在第几行、用什么写法引用了它，解析到了哪个条目。
    // 人工复核与 T5 的 brief 都靠这个字段复现「引用 → 载荷」这条链。
    escalated,
    inventory: {
      totalEntries: files.length,
      canonicalScripts: canonical.map((f) => toInventoryRow(f)),
      otherScripts: otherScripts.map((f) => toInventoryRow(f)),
      handlers: handlers.map((f) => toInventoryRow(f)),
      props: props.map((f) => toInventoryRow(f)),
      // F11：升级过的条目同时要在清单里 —— 它们在 scanTargets 里，所以 othersCount 会把它们
      // 从 otherFiles 排除掉；不单独列出来的话，人看得见的清单里就查不到这个文件。
      escalated: escalatedEntries.map((e) => ({
        ...toInventoryRow(e), fromFile: e.__from, fromLine: e.__line, ref: e.__ref,
      })),
      otherFiles: othersCount(files, scanTargets, binaries),
    },
    // 全文内嵌只给人看的文本入口；二进制不进这一节（否则 PR 评论会被机器码灌满），
    // 它们单独出现在「包结构与审核覆盖度」一节里。
    // 用 scanTargets 而不是四个桶重组：桶里没有「被引用升级进来的条目」，
    // 走桶就等于把刚拉进扫描面的载荷从人看得见的一切清单里删掉（评审 F11）。
    scripts: scanTargets.map((f) => ({
      ...toInventoryRow(f), content: f.content,
    })),
    findings: all,
    counts,
    riskLevel: level,
    riskReasons: reasons,
    changeType,
    decision,
    warnings,
    durationMs: Date.now() - started,
  };
}

function toInventoryRow(f) {
  return { name: f.name, bytes: f.size, lines: countLines(f.content), truncated: f.truncated };
}

function countLines(s) { return s === '' ? 0 : s.split(/\r?\n/).length; }

function othersCount(files, scanned, binaries) {
  const set = new Set([...scanned, ...binaries].map((f) => f.name));
  return files.filter((f) => !set.has(f.name)).map((f) => f.name);
}

export function resolveChangeType(opts, propMeta) {
  if (opts.changeType === 'first' || opts.changeType === 'update') return opts.changeType;
  const id = propMeta.fields && propMeta.fields.id ? propMeta.fields.id.value : null;
  if (!id) return 'unknown';
  const idx = opts.index;
  if (!idx) return 'unknown';
  const list = Array.isArray(idx) ? idx : (idx && Array.isArray(idx.modules) ? idx.modules : null);
  if (!list) return 'unknown';
  const hit = list.some((m) => {
    if (!m) return false;
    if (typeof m === 'string') return m === id;
    return m.id === id || m.moduleId === id || m.module_id === id;
  });
  return hit ? 'update' : 'first';
}

// ---------------------------------------------------------------------------
// 报告渲染
// ---------------------------------------------------------------------------

const SEV_MARK = { high: '🔴 high', medium: '🟠 medium', low: '🟡 low', info: '🔵 info（不计入风险等级）' };

export function renderMarkdown(report) {
  const L = [];
  const m = report.meta;
  L.push('# 模块投稿安全审核报告');
  L.push('');
  L.push(`- 目标文件：\`${report.target.zipName}\``);
  L.push(`- zip 读取方式：${report.reader === 'builtin' ? '内置解析器' : '系统 unzip（回退）'}`);
  L.push(`- 生成时间：${report.generatedAt}`);
  L.push(`- 规则版本：静态规则表 \`risk-rules.mjs\`，共 ${CONTENT_RULES.length} 条内容规则`);
  L.push('');

  L.push('## 结论');
  L.push('');
  L.push(`**风险等级：${report.riskLevel.toUpperCase()}**`);
  L.push('');
  L.push(`- 变更类型：**${changeTypeLabel(report.changeType)}**`);
  L.push(`- 处置：**\`${report.decision.action}\`** / 标签 \`${report.decision.label}\``);
  L.push(`- 依据：${report.decision.reason}`);
  L.push(`- 命中统计：high ${report.counts.high} / medium ${report.counts.medium} / low ${report.counts.low} / info ${report.counts.info}`);
  L.push('');

  L.push('## 元数据');
  L.push('');
  L.push('| 字段 | module.prop | 投稿表单声明 | 是否一致 |');
  L.push('|---|---|---|---|');
  const idOk = !report.declared.id || !m.id ? '未声明' : (report.declared.id === m.id ? '✅ 一致' : '❌ 不一致');
  const verOk = !report.declared.version || !m.version ? '未声明' : (report.declared.version === m.version ? '✅ 一致' : '❌ 不一致');
  L.push(`| id | \`${m.id ?? '(缺失)'}\` | \`${report.declared.id ?? '(未提供)'}\` | ${idOk} |`);
  L.push(`| version | \`${m.version ?? '(缺失)'}\` | \`${report.declared.version ?? '(未提供)'}\` | ${verOk} |`);
  if (m.name) L.push('');
  if (m.name) L.push(`- name：${m.name}`);
  if (m.author) L.push(`- author：${m.author}`);
  if (m.description) L.push(`- description：${m.description}`);
  L.push(`- module.prop 路径：\`${m.propPath ?? '(缺失)'}\``);
  L.push('');

  L.push('## 文件清单');
  L.push('');
  L.push(`zip 内成功读出 ${report.inventory.totalEntries} 个文件条目，压缩后 ${(report.target.bytes / 1024).toFixed(1)} KB`
    + `，声明解压后 ${((report.structure && report.structure.totalUncompressed) / 1048576).toFixed(2)} MB。`);
  L.push('');
  L.push('| 类别 | 文件 | 大小 | 行数 |');
  L.push('|---|---|---:|---:|');
  const inv = report.inventory;
  for (const s of inv.canonicalScripts) L.push(`| 规范脚本 | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.handlers) L.push(`| 安装期入口 | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.otherScripts) L.push(`| 其他脚本(.sh/.lua/.js) | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.props) L.push(`| 属性文件(.prop) | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  for (const e of inv.escalated || []) {
    L.push(`| 被引用升级（原本不在扫描面） | \`${e.name}\` | ${e.bytes} B | ${e.lines} |`);
  }
  if (!inv.canonicalScripts.length && !inv.otherScripts.length && !inv.handlers.length) {
    L.push('| — | （无脚本类文件） | — | — |');
  }
  for (const b of report.binaries || []) L.push(`| 二进制（不逐行扫） | \`${b.name}\` | ${b.bytes} B | ${b.kind} |`);
  if (inv.otherFiles.length) {
    L.push('');
    L.push(`未纳入行级扫描的数据文件（${inv.otherFiles.length} 个，仅列前 30 个）：` +
      inv.otherFiles.slice(0, 30).map((n) => `\`${n}\``).join('、'));
  }
  if ((report.escalated || []).length) {
    // 引用链要单独打出来：EXEC_BUNDLED_FILE 只说「这行执行了模块自带的另一个文件」，
    // 而复核要看的是那个文件到底在哪、被哪一行拉进来的。
    L.push('');
    L.push(`被脚本引用而**升级进扫描面**的条目（${report.escalated.length} 个，其内容已逐行扫过并在「脚本全文」一节给出）：`);
    L.push('');
    for (const e of report.escalated) {
      L.push(`- \`${e.resolvedEntry}\` ← \`${e.fromFile}:${e.fromLine}\`（引用写法：\`${escapeCell(redactText(e.ref))}\`）`);
    }
  }
  L.push('');

  L.push('## 包结构与审核覆盖度');
  L.push('');
  const st = report.structure || {};
  const list = (a) => (a && a.length ? a.map((x) => `\`${x}\``).join('、') : '无');
  L.push(`- 条目总数：${st.entries ?? '—'}（文件 ${st.fileEntries ?? '—'} / 目录 ${st.dirEntries ?? '—'}），阈值 ${st.limits ? st.limits.MAX_ENTRIES : '—'}`);
  L.push(`- 最高声明压缩比：${st.maxRatio ?? 0}:1${st.maxRatioEntry ? `（\`${st.maxRatioEntry}\`）` : ''}，阈值 ${st.limits ? st.limits.MAX_RATIO : '—'}:1`);
  L.push(`- 符号链接条目：${list(st.symlinks)}`);
  L.push(`- 越界/绝对路径条目：${list(st.unsafePaths)}`);
  L.push(`- 重名条目：${list(st.duplicateNames)}`);
  L.push(`- 加密条目：${list(st.encrypted)}`);
  L.push(`- 不支持的压缩方式：${list(st.unsupportedMethods)}`);
  L.push(`- 反斜杠路径条目：${list(st.backslashPaths)}`);
  L.push(`- 解压失败的条目：${list((report.unread || []).map((u) => u.name))}`);
  L.push(`- 报告内嵌全文的上限：${st.limits ? (st.limits.MAX_TEXT / 1024).toFixed(0) : '512'} KB/文件（行级规则跑的仍是全文，截断只影响人工能看到多少）`);
  L.push('');

  L.push('## 风险发现');
  L.push('');
  const risk = report.findings.filter(countsTowardRisk);
  if (!risk.length) {
    L.push('未命中任何风险规则。');
  } else {
    const byCat = groupBy(risk, (f) => f.category);
    for (const [cat, items] of byCat) {
      L.push(`### ${CATEGORY_LABEL[cat] || cat}`);
      L.push('');
      L.push('| 级别 | 规则 | 文件:行 | 原文片段 | 建议 |');
      L.push('|---|---|---|---|---|');
      for (const f of items) {
        L.push(`| ${SEV_MARK[f.severity]} | \`${f.ruleId}\` | \`${f.file}:${f.line}\` | \`${escapeCell(f.snippet)}\` | ${f.advice} |`);
      }
      L.push('');
    }
  }

  const priv = report.findings.filter((f) => !countsTowardRisk(f));
  L.push('## 投稿者隐私提示（不计入风险等级）');
  L.push('');
  if (!priv.length) {
    L.push('未发现需要提醒的隐私信息。');
    L.push('');
  } else {
    L.push('> 以下条目用于**保护投稿者**，不代表模块有恶意。发布前请清理。');
    L.push('');
    L.push('| 规则 | 文件:行 | 原文片段（已脱敏） | 建议 |');
    L.push('|---|---|---|---|');
    for (const f of priv) {
      L.push(`| \`${f.ruleId}\` | \`${f.file}:${f.line}\` | \`${escapeCell(mask(f.snippet))}\` | ${f.advice} |`);
    }
    L.push('');
  }

  if (report.warnings.length) {
    L.push('## 解析告警');
    L.push('');
    for (const w of report.warnings) L.push(`- ${w}`);
    L.push('');
  }

  L.push('## 脚本全文（人工复核用）');
  L.push('');
  if (!report.scripts.length) {
    L.push('zip 内没有 shell 脚本。');
  }
  for (const s of report.scripts) {
    L.push(`### \`${s.name}\` — ${s.bytes} B / ${s.lines} 行${s.truncated ? `（报告只内嵌前 ${Math.round(MAX_TEXT / 1024)} KB，其余见产物；行级规则已跑全文）` : ''}`);
    L.push('');
    L.push('```sh');
    L.push(redactText(embedBody(s.content)));
    L.push('```');
    L.push('');
  }

  L.push('---');
  L.push('');
  L.push(`_本报告由 \`contrib/audit/scan.mjs\` 生成；${report.decision.needsHumanReview ? '本模块**需要人工审核**后才可进入正式索引。' : '本模块可自动进入索引。'}_`);
  L.push('');
  return L.join('\n');
}

function changeTypeLabel(t) {
  return t === 'first' ? '首次收录' : t === 'update' ? '版本更新（对已收录模块）' : '未知（未提供索引，无法判定）';
}

function groupBy(arr, fn) {
  const m = new Map();
  for (const x of arr) {
    const k = fn(x);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(x);
  }
  return m;
}

function escapeCell(s) {
  return String(s).replace(/\|/g, '\\|').replace(/`/g, "'");
}

/** 隐私片段脱敏：中间字符打码，保留首尾以便核对 */
export function mask(s) {
  const t = String(s);
  if (t.length <= 8) return t;
  const head = t.slice(0, 4);
  const tail = t.slice(-4);
  return `${head}${'*'.repeat(Math.min(12, t.length - 8))}${tail}`;
}

// ---------------------------------------------------------------------------
// 脚本全文脱敏
// ---------------------------------------------------------------------------

// 报告会作为 PR comment 公开发布，而 ① 要求脚本全文纳入报告。两者冲突时以
// “保护投稿者” 优先：对 privacy 类规则的命中原文做脱敏后再贴出全文。
const REDACT_RULES = CONTENT_RULES.filter((r) => r.category === 'privacy');

/** 对一段脚本文本做隐私脱敏（逐行命中 privacy 规则 -> 打码） */
export function redactText(text, rules = REDACT_RULES) {
  const lines = String(text == null ? '' : text).split(/\r?\n/);
  return lines.map((line) => {
    let out = line;
    for (const r of rules) {
      if (!r.pattern) continue;
      const flags = r.pattern.flags.includes('g') ? r.pattern.flags : r.pattern.flags + 'g';
      out = out.replace(new RegExp(r.pattern.source, flags), (m) => mask(m));
    }
    return out;
  }).join('\n');
}

/** 报告正文的嵌入上限：Markdown 会进 PR 评论，必须封顶 */
function embedBody(text, max = MAX_TEXT) {
  const s = String(text == null ? '' : text);
  return s.length > max ? s.slice(0, max) : s;
}

export function renderJSON(report) {
  // JSON 报告里保留脚本全文（① 要求），但隐私片段与脚本中的隐私原文做脱敏，
  // 避免报告本身二次泄露投稿者信息。
  // 分工：Markdown 只内嵌前 MAX_TEXT 字节（它要贴进 PR 评论），全文在这个产物里 ——
  // 所以 AUDIT_COVERAGE_TRUNCATED 的「其余见产物」是有指向的，不是空话。
  const out = {
    ...report,
    findings: report.findings.map((f) => (countsTowardRisk(f) ? f : { ...f, snippet: mask(f.snippet) })),
    scripts: report.scripts.map((s) => ({ ...s, content: redactText(s.content) })),
  };
  return JSON.stringify(out, null, 2);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { opts._.push(a); continue; }
    const key = a.slice(2);
    const eq = key.indexOf('=');
    if (eq >= 0) opts[key.slice(0, eq)] = key.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) { opts[key] = argv[i + 1]; i++; }
    else opts[key] = true;
  }
  return opts;
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help || opts._.length === 0) {
    process.stdout.write(`用法: node scan.mjs <module.zip> [--declared-id ID] [--declared-version VER]
       [--index index.json] [--change-type first|update] [--out-dir DIR]
       [--json PATH] [--markdown PATH] [--stdout] [--quiet] [--fail-on high|medium|low|never]\n`);
    return 0;
  }
  const zipPath = resolve(opts._[0]);
  if (!existsSync(zipPath)) {
    process.stderr.write(`找不到文件: ${zipPath}\n`);
    return 1;
  }

  let index = null;
  if (opts.index) {
    try { index = JSON.parse(readFileSync(resolve(opts.index), 'utf8')); }
    catch (err) { process.stderr.write(`索引读取失败（按 unknown 处理）：${err.message}\n`); }
  }

  const report = scanZip(zipPath, {
    declaredId: typeof opts['declared-id'] === 'string' ? opts['declared-id'] : undefined,
    declaredVersion: typeof opts['declared-version'] === 'string' ? opts['declared-version'] : undefined,
    changeType: opts['change-type'] === 'first' || opts['change-type'] === 'update' ? opts['change-type'] : undefined,
    index,
  });

  const md = renderMarkdown(report);
  const json = renderJSON(report);

  const outDir = opts['out-dir'] ? resolve(opts['out-dir']) : null;
  const jsonPath = opts.json && typeof opts.json === 'string'
    ? resolve(opts.json)
    : (outDir ? join(outDir, `${report.target.zipName}.audit.json`) : resolve(`${zipPath}.audit.json`));
  const mdPath = opts.markdown && typeof opts.markdown === 'string'
    ? resolve(opts.markdown)
    : (outDir ? join(outDir, `${report.target.zipName}.audit.md`) : resolve(`${zipPath}.audit.md`));

  for (const p of [jsonPath, mdPath]) {
    const d = dirname(p);
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
  }
  writeFileSync(jsonPath, json);
  writeFileSync(mdPath, md);

  if (opts.stdout) process.stdout.write(md);
  if (opts.quiet) {
    process.stdout.write(`${report.riskLevel} ${report.decision.action} ${report.decision.label} ` +
      `(high=${report.counts.high} medium=${report.counts.medium} low=${report.counts.low} info=${report.counts.info})\n`);
  } else if (!opts.stdout) {
    process.stdout.write(`风险等级 ${report.riskLevel} → ${report.decision.action} / ${report.decision.label}\n`);
    process.stdout.write(`  JSON: ${jsonPath}\n  Markdown: ${mdPath}\n`);
  }

  const failOn = opts['fail-on'] || 'never';
  if (failOn !== 'never') {
    const threshold = SEVERITY_ORDER[failOn] ?? 0;
    if (SEVERITY_ORDER[report.riskLevel] >= threshold && failOn !== 'never') return 2;
  }
  return 0;
}

// 仅当作为 CLI 直接运行时才跑 main。
//
// 判据必须是「解析成绝对路径后再比」，不能拿原始 argv[1] 拼 file URL：
// Linux 上 process.argv[1] 保持调用方给的样子（CI 传的是相对的 `audit/scan.mjs`），
// 旧写法得到 file:///audit/scan.mjs，与 import.meta.url 的
// file:///home/runner/work/.../audit/scan.mjs 永远不相等 → main() 一次都没跑，
// 进程 exit 0、不打印、不落盘。Windows 上 Node 会把 argv[1] 规范化成绝对路径，
// 所以本地怎么跑都是对的 —— 静默失效只有 runner 上看得见（真实表现：扫描步骤 success
// 却零产出，见 run 38061078816 / 38061728123）。
//
// 逻辑抽成纯函数并由调用方传 selfPath，是为了让这条「换平台才坏」的判断能在开发机上
// 被测出来（spawn 出来的子进程在 Windows 上 argv[1] 永远是绝对路径，测不到相对形态）。
export function isCliEntry(entry, selfPath) {
  if (!entry || !selfPath) return false;
  return resolve(entry) === selfPath;
}

if (isCliEntry(process.argv[1], fileURLToPath(import.meta.url))) {
  process.exitCode = main();
}
