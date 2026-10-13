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
  MAX_TEXT, MAX_ENTRY_UNCOMPRESSED, EXEC_BUNDLED_FILE, EXEC_INDIRECT, MODDIR_RUNTIME_WRITE, trimSnippet,
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

/**
 * 头两个字节是不是 shebang（`#!`）。
 * 只看 head（readZip 给的前 512 字节），不整读 —— 整读会把大二进制也读一遍，
 * 而且「后面某一行有 #!」不是 shebang（第二行的 `#!/x` 只是正文）。
 * 判据放在这里而不是后缀上：投稿者自己起名字，`post-fs-data` 不带 .sh 以前直接免检。
 * @param {Uint8Array|undefined} head
 */
export function hasShebang(head) {
  const b = head && head.length ? head : null;
  if (!b || b.length < 2) return false;
  return b[0] === 0x23 && b[1] === 0x21; // `#` `!`
}

/**
 * 不是 .sh，但内容本身就是可执行语义的文件：
 *   * `sepolicy.rule` —— Magisk/KernelSU 逐行喂给策略引擎的 SELinux 授权；
 *   * `.rc`           —— init 读的服务与触发器（模块放 system/etc/init/*.rc 是常规做法）；
 *   * `.te`           —— SELinux 策略源。
 * 它们以前落在 others 里一行都不扫，等于「把授权写进一个不像脚本的文件名」就能免检。
 */
export const POLICY_BASENAMES = ['sepolicy.rule'];
export const POLICY_EXTS = ['.rc', '.te'];

export function classify(files) {
  const norm = (p) => String(p).replace(/\\/g, '/');
  const base = (p) => basename(norm(p));
  const canonical = [];
  const otherScripts = [];
  const handlers = [];
  const props = [];
  const policy = [];
  const binaries = [];
  const others = [];
  let propEntry = null;

  for (const f of files) {
    const n = norm(f.name);
    const b = base(n);
    if (b === 'module.prop' && !propEntry) propEntry = f;

    // 二进制优先于扩展名判断：把 ELF 改名成 config.js 是绕过扩展名分类的最省事做法，
    // 所以先看魔数，再看名字。上面那三类新纳入的文件同样受这条闸管着 ——
    // 改名成 sepolicy.rule 的机器码照样落到 binaries，不许被「进扫描面」这一步捞回文本。
    const bin = detectBinary(f.head);
    if (bin) { binaries.push({ ...f, binary: bin }); continue; }

    if (CANONICAL_SCRIPTS.includes(b)) { canonical.push(f); continue; }
    if (FLASH_ENTRY_POINTS.includes(n)) { handlers.push(f); continue; }
    const ext = extname(b).toLowerCase();
    if (SCRIPT_EXTS.includes(ext)) { otherScripts.push(f); continue; }
    if (PROP_EXTS.includes(ext)) { props.push(f); continue; }
    // 会被真正读进策略引擎 / init 的文件（放在后缀判断之后、others 之前，且已经在魔数闸之后）
    if (POLICY_BASENAMES.includes(b) || POLICY_EXTS.includes(ext)) { policy.push(f); continue; }
    // 无后缀但首行是 shebang 的条目 —— 这次实测的漏检面之一（`post-fs-data` 不带 .sh 就直接免检）
    if (!ext && hasShebang(f.head)) { otherScripts.push(f); continue; }
    others.push(f);
  }
  // 规范脚本按既定顺序排列，便于阅读（policy 不参与这个排序：它不是 CANONICAL_SCRIPTS 的成员，
  // 混进 canonical 会被那个 sort 排到 customize.sh 前面，还会让报告把策略文件叫成「规范脚本」）
  canonical.sort((a, b) => CANONICAL_SCRIPTS.indexOf(base(a.name)) - CANONICAL_SCRIPTS.indexOf(base(b.name)));
  return { canonical, otherScripts, handlers, props, policy, binaries, others, propEntry };
}

// fix2-P5：scanZip 组扫描面用的桶名白名单。守卫测试把它与 classify() 的实际返回键做双向比对 ——
// 新增桶忘了接线时不再是「文件静静不进扫描面、报告 0 发现」，而是测试当场变红。
export const SCAN_TARGET_BUCKETS = ['canonical', 'otherScripts', 'handlers', 'props', 'policy'];

// ---------------------------------------------------------------------------
// 扫描
// ---------------------------------------------------------------------------

// 引用写法里的模块目录前缀：$MODPATH/x、${MODDIR}/x、$TMPMODDIR/x、反斜杠形态，以及
// /data/adb/modules/<id>/x —— 全部归一到「模块根目录下的 x」。
const REF_MODDIR_PREFIX = /^\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]/;
const REF_ABS_PREFIX = /^\/data\/adb\/modules\//;
const REF_IFS = /\$\{?IFS\}?/g;

/**
 * 相对路径归一化：反斜杠 -> 正斜杠、折叠重复斜杠、解析 ./ 与 ../。
 * 上跳越出模块根目录（`$MODDIR/../outside`）时返回 null：那不是包内条目，
 * 不能假装解析成功 —— 归一化只用来「认得出真实条目」，不用来把引用折到包外。
 * @returns {string|null}
 */
export function normalizeRefPath(rel) {
  if (!rel) return null;
  const segs = String(rel).replace(/\\/g, '/').split('/').filter((s) => s !== '' && s !== '.');
  const out = [];
  for (const s of segs) {
    if (s !== '..') { out.push(s); continue; }
    if (!out.length) return null;
    out.pop();
  }
  return out.length ? out.join('/') : null;
}

/**
 * 把一条 EXEC_BUNDLED_FILE 的命中还原成「相对模块根的被引用路径」。
 *
 * 顺序是固定的：先把 ${IFS}/$IFS 当空白展开（`sh${IFS}$MODDIR/x` 的尾部 token 连着 IFS，
 * 不归一化就剥不出前缀），再取尾部 token，再把反斜杠归成正斜杠，然后剥模块目录前缀与
 * 模块 id，最后做路径归一化。仍然只做前缀剥离 + 归一化，不做模糊匹配。
 * @returns {string|null} 解析不出模块内路径时返回 null
 */
function refRelPath(matchText, moduleId = '') {
  const spread = String(matchText).replace(REF_IFS, ' ');
  const token = (spread.match(/[^\s"']+$/) || [''])[0];
  if (!token) return null;
  const slashed = token.replace(/\\/g, '/');
  let p;
  if (REF_MODDIR_PREFIX.test(slashed)) p = slashed.replace(REF_MODDIR_PREFIX, '');
  else if (REF_ABS_PREFIX.test(slashed)) p = slashed.replace(REF_ABS_PREFIX, '');
  else return null;
  // 绝对写法带着模块 id：只有等于本次模块 id 时才剥掉，否则那是指向别的模块，不是包内条目。
  if (moduleId && p.startsWith(`${moduleId}/`)) p = p.slice(moduleId.length + 1);
  return normalizeRefPath(p);
}

/** 条目指纹：名字 + 长度 + 抽样哈希 + 首尾片段。同名不同内容的重复条目要能区分开。 */
function rowKey(f) {
  const c = String(f && f.content != null ? f.content : '');
  let h = c.length;
  for (let i = 0; i < c.length; i += 4099) h = (h * 31 + c.charCodeAt(i)) >>> 0;
  const name = f && f.name ? f.name : '';
  return `${name}|${c.length}|${h.toString(16)}|${c.slice(0, 64)}|${c.slice(-64)}`;
}

/** 按名字与小写名字建索引；同名重复条目全收，不偷偷只留第一份。 */
function indexEntries(allEntries) {
  const byName = new Map();
  const byLower = new Map();
  for (const f of Array.isArray(allEntries) ? allEntries : []) {
    if (!f || !f.name) continue;
    if (!byName.has(f.name)) byName.set(f.name, []);
    byName.get(f.name).push(f);
    const lo = String(f.name).toLowerCase();
    if (!byLower.has(lo)) byLower.set(lo, new Set());
    byLower.get(lo).add(f.name);
  }
  return { byName, byLower };
}

/**
 * 引用路径 -> 包内条目。精确匹配优先；只有「大小写不敏感后只剩唯一一个候选名」时才退到
 * 不区分大小写（评审 fix1-⑤：大小写变体以前解析不到，而 finding 文案承诺去读那个文件）。
 * 候选名多于一个时不猜 —— 那是把 A 的引用算到 B 头上。
 */
function lookupEntries(index, rel) {
  if (index.byName.has(rel)) return index.byName.get(rel);
  const names = index.byLower.get(String(rel).toLowerCase());
  if (!names || names.size !== 1) return [];
  return index.byName.get([...names][0]) || [];
}

/**
 * 同文件内的字面变量赋值表（fix2-P2）：`X="$MODDIR/payload.bin"` 里的 X 能不能钉成一个
 * 具体的包内路径。判据保守到近乎挑剔：
 *   * moddir   —— 值以模块目录前缀开头，且前缀之后不含新的展开/通配（能算出 rel 才算钉住）；
 *   * external —— 值是以 `/` 开头的包外绝对路径（`SCRIPT=/system/bin/sh`），等价于「执行包外程序」，
 *                 不是包内引用，撤销；
 *   * unknown  —— 其它一切（没赋值、值走命令替换、相对路径、含 glob）：钉不住，fail closed。
 * 只认 `NAME=` 一个形状；`declare -A`、数组、跨文件赋值都不认 —— 认得越多，误判越深。
 */
function pinLiteralValue(value, moduleId) {
  const s = String(value == null ? '' : value).replace(/\\/g, '/');
  if (!s) return { kind: 'unknown' };
  if (REF_MODDIR_PREFIX.test(s)) {
    const rel = normalizeRefPath(s.replace(REF_MODDIR_PREFIX, ''));
    if (rel && !/[\s$?*{}[\]"'`\\]/.test(rel)) return { kind: 'moddir', rel };
    return { kind: 'unknown' };
  }
  if (REF_ABS_PREFIX.test(s)) {
    const p = s.replace(REF_ABS_PREFIX, '');
    if (moduleId && p.startsWith(`${moduleId}/`)) {
      const rel = normalizeRefPath(p.slice(moduleId.length + 1));
      if (rel && !/[\s$?*{}[\]"'`\\]/.test(rel)) return { kind: 'moddir', rel };
    }
    return { kind: 'unknown' }; // 别的模块目录 / 越界 / glob：都不算钉住
  }
  if (/^\/[A-Za-z0-9_.-]+/.test(s) && !/\$\{?[A-Za-z_]/.test(s)) return { kind: 'external' };
  return { kind: 'unknown' };
}

function collectVarValues(text, moduleId) {
  const map = {};
  const lines = String(text == null ? '' : text).split(/\r?\n/);
  for (const raw of lines) {
    if (/^\s*#/.test(raw)) continue;
    const re = /(?:^|[;&|\s])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(["']?)([^\s"'|;&<>]*)/g;
    let m;
    while ((m = re.exec(raw))) {
      const name = m[1];
      if (name === 'MODPATH' || name === 'MODDIR' || name === 'TMPMODDIR') continue; // 目录根变量不参与引用
      if (!(name in map)) map[name] = pinLiteralValue(m[3], moduleId);
    }
  }
  return map;
}

/** for-in 模块目录 glob 迭代子（`for f in $MODDIR/*.bin`）：把能枚举到的包内条目拿出来。 */
function globIterableEntries(line, allEntries, moduleId) {
  const gm = line.match(new RegExp(
    '\\bfor\\s+\\w+\\s+in\\s+["\'} ]*(?:\\$\\{?(?:MODPATH|MODDIR|TMPMODDIR)\\}?[\\\\/]|\\/data\\/adb\\/modules\\/(?:'
    + String(moduleId || '[^/\\s"]+').replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\/)?)([^\\s"\']*[*?][^\\s"\']*)'));
  if (!gm) return [];
  const rx = new RegExp('^' + gm[1].replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
  return (Array.isArray(allEntries) ? allEntries : []).filter((e) => e && e.name && rx.test(e.name));
}

/**
 * 找出扫描面上每一条「执行包内另一个文件」的引用，并给出该拿它怎么办。
 *
 * fix2 起这条链有两个入口：
 *   EXEC_BUNDLED_FILE —— 字面 $MODDIR 路径；
 *   EXEC_INDIRECT     —— 变量间接（`sh $X` / `do $f`），变量值能用 collectVarValues 钉住时
 *                        按钉住后的路径解析（钉不住就是未验证引用，fail closed 成发现）。
 * 每条引用返回 { ruleId, fromFile, fromLine, ref, rel, resolved, covered, entries, unpinned }：
 *   resolved —— 归一化后能不能对上包内真实条目（或钉死为包外路径）；对不上就不能在报告里假装读过它；
 *   covered  —— 能对上，且同名条目**全部**已经在扫描面里（`sh $MODPATH/install.sh` 那种常规写法：
 *               那个文件本来就被逐行扫过，这条 high 该撤掉 —— 但见 applyBundledRefVerdicts 的 P3 闸）；
 *   entries  —— 需要升级进扫描面的条目（同名重复时可能多份，已在扫描面里的不重复取）；
 *   unpinned —— 变量钉不住：这是「未验证引用」，撤销判据对它永远不成立。
 * 只递归一层：只看初始扫描面的引用，不追随被升级条目自己的引用（防环）。
 * @param {Array<{name:string, content:string}>} scanTargets
 * @param {Array<{name:string}>} allEntries
 * @param {string} moduleId
 * @param {Object<string, Object<string, {kind:string, rel?:string}> >} [varMapsByFile]
 */
export function resolveBundledRefs(scanTargets = [], allEntries = [], moduleId = '', varMapsByFile = {}) {
  const index = indexEntries(allEntries);
  const onSurface = new Set();
  const surfaceRows = new Set();
  for (const f of Array.isArray(scanTargets) ? scanTargets : []) {
    if (!f || !f.name) continue;
    onSurface.add(f);
    surfaceRows.add(rowKey(f));
  }
  const regs = [EXEC_BUNDLED_FILE, EXEC_INDIRECT].map((rule) => ({
    rule,
    re: new RegExp(rule.pattern.source,
      rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g'),
  }));
  const refs = [];
  for (const f of Array.isArray(scanTargets) ? scanTargets : []) {
    const lines = String(f && f.content != null ? f.content : '').split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // 规则层的整行/字面迭代子豁免同样要在这跑：resolver 用原始 pattern，不看 exclude ——
      // 但 EXEC_INDIRECT 的「注释行不报」在这里也要一致（注释行照样允许升级进扫描面，见 risk-rules 注释）。
      for (const { rule, re } of regs) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(line))) {
          const ref = m[0].trim();
          const rec = { ruleId: rule.id, fromFile: f.name, fromLine: i + 1, ref,
            rel: null, resolved: false, covered: false, entries: [], unpinned: false };
          if (rule.id === 'EXEC_BUNDLED_FILE') {
            rec.rel = refRelPath(m[0], moduleId);
          } else {
            const varName = m[1] !== undefined ? m[1] : m[2];
            rec.varName = varName;
            const pin = (varMapsByFile[f.name] || {})[varName];
            if (pin && pin.kind === 'moddir') {
              rec.rel = pin.rel;
            } else if (pin && pin.kind === 'external') {
              rec.resolved = true; rec.covered = true; rec.external = true;
            } else {
              rec.unpinned = true;
              // for-in 模块目录 glob：迭代子本身是包内路径集合，能把没读过的载荷枚举出来升级
              for (const e of globIterableEntries(line, allEntries, moduleId)) {
                const k = rowKey(e);
                if (onSurface.has(e) || surfaceRows.has(k)) continue;
                if (!rec.entries.some((x) => rowKey(x) === k)) {
                  rec.entries.push({ ...e, __from: f.name, __line: i + 1, __ref: ref });
                }
              }
              if (rec.entries.length) rec.resolved = true;
            }
          }
          const group = rec.rel ? lookupEntries(index, rec.rel) : [];
          if (group.length) {
            rec.resolved = true;
            const seen = new Set(rec.entries.map((e) => rowKey(e)));
            for (const e of group) {
              const k = rowKey(e);
              // 要求 1：包内不存在就不升级；已在扫描面里的（同一个对象，或名字+内容同指纹）不再取一次。
              if (onSurface.has(e) || surfaceRows.has(k) || seen.has(k)) continue;
              seen.add(k);
              rec.entries.push({ ...e, __from: f.name, __line: i + 1, __ref: ref });
            }
            // 同名条目全都在扫描面里 = 这条引用没有把任何没读过的东西带进来，可以撤。
            // （撤不撤最终还过 applyBundledRefVerdicts 的 P3 覆写闸。）
            if (!rec.unpinned) rec.covered = rec.entries.length === 0;
          }
          refs.push(rec);
          if (m.index === re.lastIndex) re.lastIndex++;
        }
      }
    }
  }
  return refs;
}

/**
 * 引用记录里要升级进扫描面的条目，跨引用去重：
 * 同一个载荷被三行引用（或三种写法引用：`$MODDIR/x`、`$MODDIR//x`、`${MODDIR}/x`）时
 * 只进扫描面一次，`report.escalated` 与 `report.scripts` 里也不会出现两次。
 */
export function escalationsFromRefs(refs = []) {
  const out = [];
  const seen = new Set();
  for (const rec of Array.isArray(refs) ? refs : []) {
    for (const e of rec.entries || []) {
      const k = rowKey(e);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(e);
    }
  }
  return out;
}

/**
 * 原契约保持不变：返回「被执行但当前不在扫描面里」的包内条目，供调用方追加进扫描面。
 * 三条硬要求都还在（包内真实存在 / 不重复追加 / 不管像不像文本都要纳入），
 * 但「不重复追加」的判据从后缀换成了「它真的在不在扫描面里」—— 见 resolveBundledRefs。
 */
export function resolveBundledTargets(scanTargets = [], allEntries = [], moduleId = '') {
  return escalationsFromRefs(resolveBundledRefs(scanTargets, allEntries, moduleId));
}

/** 归一化后仍解析不到条目时，advice 不许再承诺「把那个文件也读一遍」—— 那是报告在说谎。 */
export const EXEC_UNRESOLVED_ADVICE =
  '脚本执行了模块自带的另一个文件，但这条引用归一化后解析不到包内条目'
  + '（路径不在包内，或上跳越出了模块根目录）：那个文件的内容本次**没有**被读过，本报告不能替你读它。'
  + '请人工确认它从哪来、运行期是否会被写出，再定处置。';

// fix2-P2：变量钉不住时的 advice —— 与 EXEC_UNRESOLVED_ADVICE 同理，报告不许承诺读过它。
export const EXEC_UNPINNED_ADVICE =
  '脚本的执行目标走变量间接：扫描器无法把这个变量钉成包内具体路径（文件内没有可确认的字面赋值、'
  + '值本身还含展开/通配，或赋值不在本次扫描面内）。变量运行期到底指向哪里没有核实过，'
  + '本次**没有**读过那个目标 —— 这是未验证引用，不是「干净」。请人工确认变量来源与所有赋值点。';
export const EXEC_OVERRIDDEN_ADVICE =
  '引用的同名条目确实已在扫描面里，但这个脚本（或同包另一脚本）还会在运行期向模块目录写出/解包'
  + '外部内容：真正落盘并被执行的字节不再是扫描面读过的那一份 —— 「同名」不等于「同字节」。'
  + '这条引用不能按「已逐行扫过」撤销；请人工核对写出来源与解包内容。';

/**
 * 用引用解析结果决定每条 EXEC_BUNDLED_FILE / EXEC_INDIRECT 发现的去处。这一步只能在 scanZip 里做 ——
 * 只有那里拿得到扫描面（risk-rules 的 makeLineRule 是纯逐行函数，拿不到它）。
 *   * 这一行的引用全部解析成功、且目标都已经逐行扫过、且包内没有「运行期写模块目录」的证据
 *     -> 撤掉这条发现（正经模块的常规写法）；有写出证据时撤销失效（fix2-P3：同名 ≠ 同字节）；
 *   * 有升级进来的条目 -> 保留 high，并把 snippet 换成那个真正没被扫过的引用，
 *     否则会出现「命中的是 install.sh、被拦的却是 payload.dat」这种没法复验的错配（fix2-P3 报告错配）；
 *   * 有钉不住的变量引用 -> 保留 high，advice 换成「未验证引用」文案（fix2-P2，fail closed）；
 *   * 有解析不到的引用（或这一行压根没有解析结果）-> 保留 high，但换成不承诺读过的 advice。
 * snippet 永远指向**造成保留的那条引用**（优先级：被升级的 > 钉不住的 > 解析不到的），
 * 报告不许把没造成升级的良性最左引用写成风险本体。
 * @param {object[]} findings
 * @param {object[]} refs resolveBundledRefs 的返回
 * @param {Map<string, number>|null} [writeInfo] 文件 -> 首个「运行期写模块目录」命中行（fix2-P3）
 * @returns {object[]} 新的发现数组（不改入参对象）
 */
export function applyBundledRefVerdicts(findings = [], refs = [], writeInfo = null) {
  const byLine = new Map();
  for (const rec of Array.isArray(refs) ? refs : []) {
    const k = JSON.stringify([rec.ruleId, rec.fromFile, rec.fromLine]);
    if (!byLine.has(k)) byLine.set(k, []);
    byLine.get(k).push(rec);
  }
  const out = [];
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || (f.ruleId !== 'EXEC_BUNDLED_FILE' && f.ruleId !== 'EXEC_INDIRECT')) { out.push(f); continue; }
    const recs = byLine.get(JSON.stringify([f.ruleId, f.file, f.line])) || [];
    // 拿不到解析结果时保守：照报，只是不许承诺读过。
    const dismissable = recs.length && recs.every((r) => r.resolved && r.covered);
    const hasPkgRef = recs.some((r) => !r.external);
    const overridden = dismissable && hasPkgRef && Boolean(writeInfo) && writeInfo.has(f.file);
    if (dismissable && !overridden) continue;
    const copy = { ...f };
    const escalated = recs.find((r) => r.entries && r.entries.length);
    const unpinned = recs.find((r) => r.unpinned);
    const unresolved = recs.find((r) => !r.resolved);
    const cause = escalated || unpinned || unresolved;
    if (cause) copy.snippet = trimSnippet(cause.ref);
    if (overridden) copy.advice = EXEC_OVERRIDDEN_ADVICE;
    else if (unpinned) copy.advice = EXEC_UNPINNED_ADVICE;
    else if (!recs.length || unresolved) copy.advice = EXEC_UNRESOLVED_ADVICE;
    out.push(copy);
  }
  return out;
}

/**
 * fix2-P3 跨文件那一半：A 脚本把外部字节解包/写进模块目录，B 脚本「执行同名已在扫描面」的条目 ——
 * B 的引用撤销不能替 A 写出后的磁盘字节作证。撤销闸只查同文件（applyBundledRefVerdicts），
 * 这里把跨文件的形状补成一条指名 B 的显式发现，让人看得见是谁的字节没被证实。
 */
export function crossFileOverrideFindings(refs = [], writeInfo = null) {
  if (!writeInfo || !writeInfo.size) return [];
  const out = [];
  const seen = new Set();
  const writers = [...writeInfo.keys()];
  for (const rec of Array.isArray(refs) ? refs : []) {
    if (!rec.resolved || !rec.covered || rec.external || !rec.rel) continue;
    if (writeInfo.has(rec.fromFile)) continue; // 同文件的情形已由撤销闸处理，不双报
    const writer = writers.find((w) => w !== rec.fromFile);
    if (!writer) continue;
    const k = `${rec.fromFile}\u0000${rec.rel}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({
      ruleId: 'MODDIR_RUNTIME_WRITE', category: 'execution', severity: 'high',
      file: rec.fromFile, line: rec.fromLine, snippet: trimSnippet(rec.ref),
      message: '执行了包内条目，而同包的另一个脚本会在运行期向模块目录写出/解包外部内容',
      advice: EXEC_OVERRIDDEN_ADVICE + `（写出证据：${writer}:${writeInfo.get(writer)}）`,
    });
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
  const cls = classify(files);
  const { canonical, otherScripts, handlers, props, policy, binaries, propEntry } = cls;

  // 行级规则覆盖「会被执行的文本」：规范脚本、其他脚本、安装期入口、属性文件、
  // 策略/初始化文件（sepolicy.rule / .rc / .te —— 内容本身就是可执行语义，T2 补的盲）。
  // 二进制只登记不逐行扫（见 checkBinaries 的理由），非脚本数据文件只进清单。
  // fix2-P5：桶清单从 classify() 的返回键里显式点名（SCAN_TARGET_BUCKETS）——
  // 以前这里是手写的展开，新增桶忘接线时不会报错，只会让那个桶的文件「安静地不进扫描面」
  // （P5 复现过的正是这种静默）。守卫测试对两边做双向比对，忘一条就红。
  const scanTargets = SCAN_TARGET_BUCKETS.flatMap((b) => cls[b] || []);

  // 载荷间接执行：被脚本 sh/source/变量间接引用的包内条目必须进扫描面，而且必须发生在下面那个
  // 内容扫描循环之前 —— 追加在循环之后的话，那些条目一行都不会被扫，测试却照样能
  // 「命中 EXEC_BUNDLED_FILE」，于是这条闸变成只有名字没有牙的装饰。
  const escalated = [];
  const escalatedEntries = [];
  // modId 只能取 fields.id.value：fields.id 是 {value,line}，直接拿它当字符串会拼出
  // /data/adb/modules/[object Object]/，引用解析永远匹配不上真实条目（评审 F9）。
  const idField = propEntry ? parseModuleProp(propEntry.content).fields.id : null;
  const modId = (idField && idField.value) || opts.declaredId || '';
  // fix2-P2：变量钉定表先按初始扫描面算好，resolver 判 `sh $X` 时才有「X 钉不钉得住」可查。
  const varMapsByFile = {};
  for (const f of scanTargets) varMapsByFile[f.name] = collectVarValues(f.content, modId);
  const bundledRefs = resolveBundledRefs(scanTargets, files, modId, varMapsByFile);
  for (const e of escalationsFromRefs(bundledRefs)) {
    scanTargets.push(e);
    escalatedEntries.push(e);
    escalated.push({ fromFile: e.__from, fromLine: e.__line, ref: e.__ref, resolvedEntry: e.name });
  }

  const rawFindings = [];
  for (const f of scanTargets) {
    rawFindings.push(...scanContent(f.name, f.content));
  }
  // 「引用目标是否已经被逐行扫过」只能在这里判（扫描面到这儿才齐），见 applyBundledRefVerdicts。
  // fix2-P3：先把「运行期向模块目录写出/解包」的命中行收成一表 —— 有这种证据的文件里，
  // 「同名条目已在扫描面」不再是字节证据，撤销闸必须失效。
  const writeInfo = new Map();
  for (const fd of rawFindings) {
    if (fd.ruleId === 'MODDIR_RUNTIME_WRITE' && !writeInfo.has(fd.file)) writeInfo.set(fd.file, fd.line);
  }
  const findings = applyBundledRefVerdicts(rawFindings, bundledRefs, writeInfo);
  // 跨文件的覆写形状（A 解包、B 执行）同样不许按「已扫过」静默放过：补成指名 B 的显式发现。
  findings.push(...crossFileOverrideFindings(bundledRefs, writeInfo));

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
      // T2：策略/初始化文件（sepolicy.rule / .rc / .te）单独一栏 —— 它们不是脚本，
      // 混进「规范脚本」会让报告说假话，混进 others 又等于没进扫描面。
      policyFiles: policy.map((f) => toInventoryRow(f)),
      // F11：升级过的条目同时要在清单里 —— 它们在 scanTargets 里，所以 othersCount 会把它们
      // 从 otherFiles 排除掉；不单独列出来的话，人看得见的清单里就查不到这个文件。
      escalated: escalatedEntries.map((e) => ({
        ...toInventoryRow(e), nonText: isNonTextContent(e),
        fromFile: e.__from, fromLine: e.__line, ref: e.__ref,
      })),
      otherFiles: othersCount(files, scanTargets, binaries),
    },
    // 全文内嵌只给人看的文本入口；二进制不进这一节（否则 PR 评论会被机器码灌满），
    // 它们单独出现在「包结构与审核覆盖度」一节里。
    // 用 scanTargets 而不是四个桶重组：桶里没有「被引用升级进来的条目」，
    // 走桶就等于把刚拉进扫描面的载荷从人看得见的一切清单里删掉（评审 F11）。
    // 但扫描面与渲染面要分开：升级条目照常进 scanContent，非文本条目在这里只给有界预览
    // （评审 fix1-③：1 MiB ELF 改名 .conf 实测把 Markdown 灌成 1.03 MB / 52 万个 NUL，
    //   8 MiB 把 JSON 灌成 50 MB —— 这些产物会作为公开 PR 评论发出去）。
    scripts: scanTargets.map((f) => scriptRow(f)),
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

/** 非文本条目在报告里给多少个字节的十六进制预览 */
const PREVIEW_BYTES = 64;

/** 内容里 NUL 的个数（渲染层与测试都要用得到这个数字，所以单独拿出来） */
function nulCount(text) {
  const c = String(text == null ? '' : text);
  let n = 0;
  for (let i = 0; i < c.length; i++) if (c.charCodeAt(i) === 0) n++;
  return n;
}

/**
 * 这条内容是不是「非文本」：魔数认得的机器码，或正文里含 NUL。
 * 判据刻意不依赖后缀 —— 后缀是投稿者自己起的（评审 fix1-① 的根源就在这儿）。
 */
export function isNonTextContent(f) {
  if (!f) return false;
  if (f.head && f.head.length && detectBinary(f.head)) return true;
  return String(f.content == null ? '' : f.content).indexOf('\u0000') >= 0;
}

/** 非文本条目的有界预览：NUL 计数 + 前 64 字节十六进制 + 一句「已按文本扫过」。 */
function nonTextPreview(f) {
  const nul = nulCount(f.content);
  const src = Buffer.isBuffer(f.head) && f.head.length
    ? f.head
    : Buffer.from(String(f.content == null ? '' : f.content).slice(0, PREVIEW_BYTES), 'latin1');
  const hex = src.subarray(0, PREVIEW_BYTES).toString('hex').replace(/(..)/g, '$1 ').trim();
  return `内容非文本（NUL ${nul} 个 / 共 ${f.size} B），已按文本逐行扫过；`
    + `机器码原文不进本报告，这里只给前 ${Math.min(PREVIEW_BYTES, src.length)} 字节十六进制预览：\n${hex}`;
}

/**
 * report.scripts 的一行。文本条目给全文；非文本条目给有界预览（contentKind 标出来），
 * 这样「扫过」与「贴出来」是两件事 —— 前者是审核职责，后者受公开评论的体积与注入面约束。
 */
function scriptRow(f) {
  const row = toInventoryRow(f);
  if (!isNonTextContent(f)) return { ...row, content: f.content };
  return { ...row, contentKind: 'non-text-preview', nonText: true, nulCount: nulCount(f.content),
    content: nonTextPreview(f) };
}

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
  // 条目名是投稿者自己起的，表格里也要过 escapeCell：反引号能提前关掉行内代码。
  for (const s of inv.canonicalScripts) L.push(`| 规范脚本 | \`${escapeCell(s.name)}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.handlers) L.push(`| 安装期入口 | \`${escapeCell(s.name)}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.otherScripts) L.push(`| 脚本(.sh/.lua/.js 或无后缀带 shebang) | \`${escapeCell(s.name)}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.props) L.push(`| 属性文件(.prop) | \`${escapeCell(s.name)}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of inv.policyFiles || []) L.push(`| 策略/初始化文件（会被读进策略引擎或 init） | \`${escapeCell(s.name)}\` | ${s.bytes} B | ${s.lines} |`);
  for (const e of inv.escalated || []) {
    L.push(`| 被引用升级（原本不在扫描面） | \`${escapeCell(e.name)}\` | ${e.bytes} B | ${e.lines} |`);
  }
  if (!inv.canonicalScripts.length && !inv.otherScripts.length && !inv.handlers.length
    && !(inv.policyFiles || []).length) {
    L.push('| — | （无脚本类文件） | — | — |');
  }
  for (const b of report.binaries || []) L.push(`| 二进制（不逐行扫） | \`${escapeCell(b.name)}\` | ${b.bytes} B | ${b.kind} |`);
  if (inv.otherFiles.length) {
    L.push('');
    L.push(`未纳入行级扫描的数据文件（${inv.otherFiles.length} 个，仅列前 30 个）：` +
      inv.otherFiles.slice(0, 30).map((n) => `\`${escapeCell(n)}\``).join('、'));
  }
  if ((report.escalated || []).length) {
    // 引用链要单独打出来：EXEC_BUNDLED_FILE 只说「这行执行了模块自带的另一个文件」，
    // 而复核要看的是那个文件到底在哪、被哪一行拉进来的。
    L.push('');
    L.push(`被脚本引用而**升级进扫描面**的条目（${report.escalated.length} 个，其内容已按文本逐行扫过；`
      + '文本条目在「脚本全文」一节给全文，非文本条目只给有界预览）：');
    L.push('');
    const invEsc = (report.inventory && report.inventory.escalated) || [];
    for (const e of report.escalated) {
      const row = invEsc.find((x) => x.name === e.resolvedEntry && x.fromFile === e.fromFile
        && x.fromLine === e.fromLine);
      const kind = row && row.nonText ? '，非文本：只给有界预览' : '';
      L.push(`- \`${escapeCell(e.resolvedEntry)}\` ← \`${escapeCell(e.fromFile)}:${e.fromLine}\``
        + `（引用写法：\`${escapeCell(redactText(e.ref))}\`${kind}）`);
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
      // fix2-P5 的最后防线：CATEGORY_LABEL 是名字白名单，白名单漏了某个分类时
      // 不许「文件顶着 0 发现出场」——分组照打，但标题必须写明「分类未识别」。
      const label = CATEGORY_LABEL[cat]
        ? CATEGORY_LABEL[cat]
        : `未分类（分类未识别：${cat}）`;
      L.push(`### ${label}`);
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
    const note = s.nonText
      ? '（内容非文本：已按文本逐行扫过，这里只给有界预览，机器码原文不进报告）'
      : (s.truncated ? `（报告只内嵌前 ${Math.round(MAX_TEXT / 1024)} KB，其余见产物；行级规则已跑全文）` : '');
    L.push(`### \`${escapeCell(s.name)}\` — ${s.bytes} B / ${s.lines} 行${note}`);
    L.push('');
    // 围栏体也要过显示层防护：正文里的 ``` 关不掉比它更长的围栏，控制字符换成可见占位。
    const body = sanitizeBody(redactText(embedBody(s.content)));
    const fence = fenceFor(body);
    L.push(`${fence}${s.nonText ? 'text' : 'sh'}`);
    L.push(body);
    L.push(fence);
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

/**
 * 代码围栏长度：正文里最长的反引号串 + 1（最少 3）。
 * CommonMark/GitHub 的闭栏要求「一行的反引号数 >= 开栏数」，所以开栏比正文里任何一段
 * 都长时，投稿者在脚本正文里写的 ``` 就关不掉我们的围栏 —— 这是公开 PR 评论的注入面，
 * 属于显示层（评审 fix1-③：包内写一句 `## 已由维护者批准 ✅` 实测漏进正文）。
 * 反过来如果只加长围栏不转义，正文里的反引号会被原样保留（人工复核要看的就是原文）。
 */
function fenceFor(body) {
  let max = 0;
  const runs = String(body).match(/`+/g);
  if (runs) for (const r of runs) max = Math.max(max, r.length);
  return '`'.repeat(Math.max(3, max + 1));
}

/** 渲染前把不可见控制字符换成可见占位（NUL 一类不许进公开评论；保留 \t 与 \n）。 */
function sanitizeBody(text) {
  // \x09 制表与 \x0a 换行留着（人要看的是原文排版），其余 C0 控制字符与 DEL 换成可见的 ?
  return String(text == null ? '' : text)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]/g, '?')
    .replace(/[\r\n]+$/, '');
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
