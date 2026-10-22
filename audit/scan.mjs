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
  classifyMalice, summarizeCoverage, MALICE_RULE_IDS, MALICE_LIST,
  inspectStructure, checkCoverage, checkUnread, checkBinaries, detectBinary,
  binaryForensicsRows, printableRatio, POLYGLOT_MIN_PRINTABLE,
  dexSurfaceSeverity,
  MAX_TEXT, MAX_ENTRY_UNCOMPRESSED, EXEC_BUNDLED_FILE, EXEC_INDIRECT, MODDIR_RUNTIME_WRITE, trimSnippet,
} from './risk-rules.mjs';
import { forensics, STRING_SCAN_LIMIT } from './elf-forensics.mjs';
import { forensics as dexForensics, dexStringSurface } from './dex-forensics.mjs';

/**
 * Task 5.7：二进制条目原始字节的保留上限（工单 §5 第 2 条那个「专门的字节上限」）。
 *
 * 为什么取这个数（= `STRING_SCAN_LIMIT`，数字只住在那一处，这里一字引用它）：
 *   1) 取证模块自己就只看到那么多字节 —— `elf-forensics.analyze()` 的 strings 那一步扫的是
 *      `min(buf.length, STRING_SCAN_LIMIT)`。留得比这更多，多出来的那些字节一个都不会被读到，
 *      所以这个上限永远不是「少读了」的原因，只可能是「少留了」的原因，而那正是我们要它做的。
 *   2) 它是 MAX_ENTRY_UNCOMPRESSED（64 MiB）的 1/4。拿 64 MiB 当这个闸等于没有闸：
 *      投稿者塞一枚 64 MiB 的「ELF」就能把 CI 的解析时间与内存端走（工单 §5 明令禁止复用那个上限）。
 *   3) 上限存在的真正理由是**可证性**：超过它的条目必须留下一句「只读了前 N 字节」，
 *      否则一枚 20 MiB 的 .so 会在前缀上解析成功，被念成「读到 N 个导入，无一落在危险族」——
 *      那是把「我们只看了前 N 字节」说成「它什么都不干」（§5 末段那一格，T57-09 / T57-14 压着）。
 *
 * 实现口径（照实写，别让注释比代码乐观）：`raw` 是已解压 Buffer 的 subarray **视图**，
 * 与既有的 `head` 同一个 ArrayBuffer ⇒ 它本身不多占字节；`raw` 只在 detectBinary 命中处保留，
 * 文本条目一律 `raw: null`（§5.1 那条「不许把文本条目的内存翻倍」）。
 * 实测参照（钉 tag 的语料，2026-10-21 复现）：最大 ELF 983,624 B（device_faker 的 arm64-v8a.so）、
 * 最大 dex 889,000 B（HMA-OSS 的 classes.dex），都离上限一个数量级。
 */
export const MAX_FORENSICS_BYTES = STRING_SCAN_LIMIT;
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
 * 单条目喂给**行级规则**的字节上限（Task 2.9，2026-10-14 用户拍定：字节上限 + 截断记账，
 * 不改 `PRIVACY_EMAIL` 的实现）。
 *
 * 为什么必须有：行级规则是「逐行 × 每条规则」的，而正则在最坏的一行上是**平方级**——
 * `PRIVACY_EMAIL` 的 `[A-Za-z0-9._%+-]+@…` 在 `a`×N 这种行上从每个起点都试到行尾。
 * 2026-10-14 在 `f79b784` 上实测（24 条内容规则，单行 UTF-8；曲线表与测量脚本见本轮报告
 * `.superpowers/sdd/2026-10-12-malicious-module-detection-hardening/task-2.9-report.md` 第 0/12 节）：
 *   8 KB=100.6ms 16 KB=337.1ms 24 KB=781.9ms 32 KB=1429.7ms 48 KB=2901.3ms
 *   64 KB=5218.3ms 120 KB=18273.8ms 240 KB=76572.2ms（指数 1.8–2.3，热点就是 PRIVACY_EMAIL）
 * 512 KB（= 报告内嵌上限 `MAX_TEXT`）单行按同一指数外推是**分钟级**，所以内嵌上限那一档
 * 当不得扫描上限：它只挡住了「报告贴多少」，挡不住「规则跑多少」。取 24 KB 是
 * 实测里最后一个让整包扫描留在 1 s 内的档位（32 KB 单行光规则就 1.43 s）。
 * 真包侧的代价照实记：`device_faker` 有 8 个压缩过的 Vue 打包件（最大 111,460 B 单行）
 * 会因此各得一条 `AUDIT_COVERAGE_TRUNCATED`（medium），结论仍是 block，不是放行。
 *
 * 硬边界（本轮验收的两条方向用例）：上限**只能让扫描更早停**，
 * 前 N 字节里的载荷照旧命中；落在 N 之后的载荷必须换成一条参与定级的截断记录，
 * 「读到一半」永远不等于「干净」。
 */
export const MAX_SCAN_BYTES_PER_ENTRY = 24 * 1024;

/**
 * 把上限落点退到一个完整的 UTF-8 码点边界，返回可以安全切开的字节数。
 * 尾字节 0x80–0xBF 是延续字节：`bytes[end]` 还是延续字节就说明那个字符正跨在边界上，
 * 往前退到某个字符的首字节为止 —— 否则半截序列会被 `toString('utf8')` 变成 U+FFFD 混进规则输入。
 * @param {Buffer} bytes
 * @param {number} max 上限（字节）
 */
export function scanFeedBytes(bytes, max = MAX_SCAN_BYTES_PER_ENTRY) {
  const len = Buffer.isBuffer(bytes) ? bytes.length : Buffer.byteLength(String(bytes == null ? '' : bytes), 'utf8');
  if (len <= max) return len;
  let end = max;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;
  return end;
}

/**
 * 这个条目真正喂给行级规则的那段文本。
 * 未超限时直接返回全文（一个字节都不许多切，也不许多拷一份）；超限时只返回前缀。
 * 全文 `content` 仍然是报告与 JSON 产物的依据 —— 上限只管「喂给规则多少」，
 * 不管「给人看多少」（见 checkCoverage 与 renderJSON 的分工）。
 * @param {{content:string, scanCapped?:boolean, scanText?:string|null}} f
 */
function lineRuleInput(f) {
  if (!f) return '';
  if (f.scanCapped && typeof f.scanText === 'string') return f.scanText;
  return String(f.content == null ? '' : f.content);
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

/**
 * 取**一个条目**的原始字节（不是 utf8 串），给「按字节偏移复核」用。
 *
 * 为什么不能复用 `readZip`：它给的是 `content = bytes.toString('utf8')`，原始字节在解码那一刻
 * 就已经毁了（Task 5.7 那条实测：一枚真 .so 从 13,480 B 解成 13,430 个字符，往返不相等）。
 * 而举报的逐字复核问的是「这个条目第 N 到 N+L 个字节是不是那串」—— 那必须在字节上做。
 * 上限与解压失败的方向都和 `readZip` 一致：读不出来说「读不出来」，不说「没有」。
 *
 * @returns {Buffer} @throws 条目不存在 / 加密 / 压缩方式不支持 / 超上限（err.overLimit=true）
 */
export function readZipEntryBytes(zipPath, name, limit = MAX_ENTRY_UNCOMPRESSED) {
  const buf = readFileSync(zipPath);
  const e = parseZip(buf).find((x) => x.name === name && !x.isDir);
  if (!e) throw new Error(`归档里没有这个条目：${JSON.stringify(name)}`);
  if (e.encrypted) throw new Error(`条目是加密的，解不出来：${name}`);
  if (e.isSymlink) throw new Error(`条目是符号链接，按内容复核没有意义：${name}`);
  return inflateEntry(buf, e, limit);
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
  // Task 2.9：行级规则的输入上限。这里只算「准备喂多少」，不声称「喂过了」——
  // 谁真的进了扫描面由 scanZip 决定（scanTruncated 在那儿打上），因为非条目面（图片、
  // 机器码）本来就不逐行扫，给它们记截断只是噪声。
  const scanBytes = scanFeedBytes(bytes);
  const scanCapped = scanBytes < bytes.length;
  // Task 5.7（工单 §5）：`content` 是 utf8 串，原始字节在解码那一刻就已经被毁掉了
  // ——实测一枚真 .so 从 13,480 B 解成 13,430 个字符、往返不相等，`forensics()` 第一行
  // 就按这个理由拒收字符串。所以要看二进制内部必须有原始字节，而它**只**在 detectBinary
  // 命中时留下（§5.1：不许所有条目都留 Buffer），并受 MAX_FORENSICS_BYTES 管住（§5.2）。
  // 超限那一条留 rawCapped=true，这是「看得见的记录」，不许静默变成「读不出」。
  // 这一格与 report 的产物面无关：raw 永远不进报告（§5.3，T57-15 按 JSON.stringify 钉）。
  // ⚠ 超限那一格必须**拷贝**而不是取视图：`subarray` 与父 ArrayBuffer 共享存储，
  // 取视图的话 `raw.length` 到了上限、被钉住的却还是整块 64 MiB —— 上限就成了只作用在「解析多少」，
  // 而这条闸要管的是「留多少」。不超限那一格反过来：整块本来就要留，留 `bytes` 本身是零拷贝、零浪费。
  const head = bytes.subarray(0, 512);
  const isBinary = Boolean(detectBinary(head));
  const rawCapped = isBinary && bytes.length > MAX_FORENSICS_BYTES;
  return {
    name,
    size: bytes.length,
    // 全文留给报告与 JSON 产物：截断只能限制「喂给规则多少」和「人看得见多少」，
    // 不能把产物里的正文也剪了 —— AUDIT_COVERAGE_TRUNCATED 的「其余见产物」靠它。
    // 注意 content 是全文，而 scanText 才是行级规则真正吃进去的那一段。
    content: bytes.toString('utf8'),
    head,
    raw: isBinary ? (rawCapped ? Buffer.from(bytes.subarray(0, MAX_FORENSICS_BYTES)) : bytes) : null,
    rawCapped,
    truncated,
    scanBytes,
    scanCapped,
    scanText: scanCapped ? bytes.subarray(0, scanBytes).toString('utf8') : null,
    scanTruncated: false,
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
 *   covered  —— 能对上，且同名条目**全部**都在可撤销面（`coveredSurface`，即扩面之前的五个桶）里
 *               （`sh $MODPATH/install.sh` 那种常规写法：
 *               那个文件本来就被逐行扫过，这条 high 该撤掉 —— 但见 applyBundledRefVerdicts 的 P3 闸）；
 *   entries  —— 需要升级进扫描面的条目（同名重复时可能多份，已在 feed 里的不重复取）；
 *   resolvedEntry —— 归一化后命中的**包内真实条目名**（引用里的拼法可能是大小写变体，
 *               fix8-E 的撤销记录要指认「机器读过的是哪一个条目」，不能抄引用写法）；
 *   unpinned —— 变量钉不住：这是「未验证引用」，撤销判据对它永远不成立。
 * 只递归一层：只看初始扫描面的引用，不追随被升级条目自己的引用（防环）。
 *
 * Task 2.7（fix10-P11）：这里曾经有第二个入参同时被当成三个不同的东西用，扩面时必须拆开。
 *   * **feed**（第 1 参 `scanTargets`）—— 谁会被喂进内容扫描；`onSurface` / `surfaceRows`
 *     由它建，用途是**去重**（同一个条目别推第二遍）与「它已经会被读到了，不必算升级」。
 *   * **covered**（第 5 参 `coveredSurface`）—— 这条引用**能不能撤**的判据面，
 *     只认扩面之前的那五个桶。`covered` 判在 feed 上等于把「会在扫描面上」当成
 *     「读过且无罪」：载荷改名成数据文件时它本来就会进 feed，撤销立刻成立，整包哑掉。
 *     两个集合共用一个的后果实测就是「同一条 finding 出现两次」（见 §0.13 / task-2.7-brief 第三行）。
 * @param {Array<{name:string, content:string}>} scanTargets feed：内容扫描实际会扫到的条目
 * @param {Array<{name:string}>} allEntries
 * @param {string} moduleId
 * @param {Object<string, Object<string, {kind:string, rel?:string}> >} [varMapsByFile]
 * @param {Array<{name:string, content:string}>} [coveredSurface] 可撤销面；缺省回落到 feed，
 *   使直接调用本函数的既有测试（fix2-P2 / fix2-P3）一字不动，且回落值就是改动前的语义。
 */
export function resolveBundledRefs(scanTargets = [], allEntries = [], moduleId = '',
  varMapsByFile = {}, coveredSurface = null) {
  const index = indexEntries(allEntries);
  const onSurface = new Set();
  const surfaceRows = new Set();
  for (const f of Array.isArray(scanTargets) ? scanTargets : []) {
    if (!f || !f.name) continue;
    onSurface.add(f);
    surfaceRows.add(rowKey(f));
  }
  // covered 集：判「这条引用指向的东西是不是**扩面之前**就在面上」，与上面那对去重集分家。
  const covFeed = coveredSurface || scanTargets;
  const covNames = new Set();
  const covRows = new Set();
  for (const f of Array.isArray(covFeed) ? covFeed : []) {
    if (!f || !f.name) continue;
    covNames.add(f);
    covRows.add(rowKey(f));
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
            rel: null, resolved: false, covered: false, entries: [], unpinned: false, resolvedEntry: null };
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
            // 命中的条目名（不是引用里的拼法）：大小写变体解析成功时，报告要指认真读过的那个条目。
            rec.resolvedEntry = group[0].name;
            const seen = new Set(rec.entries.map((e) => rowKey(e)));
            for (const e of group) {
              const k = rowKey(e);
              // 要求 1：包内不存在就不升级；已在 feed 里的（同一个对象，或名字+内容同指纹）不再取一次。
              // 判 feed 不判 covered：这里管的是「别把同一个条目推第二遍」，不是「这条引用能不能撤」
              //（Task 2.7：两者混用实测会让载荷的每条 finding 在公开评论的命中统计里出现两次）。
              if (onSurface.has(e) || surfaceRows.has(k) || seen.has(k)) continue;
              seen.add(k);
              rec.entries.push({ ...e, __from: f.name, __line: i + 1, __ref: ref });
            }
            // 可撤销判在 coveredSurface（扩面之前的五个桶）上，不判 feed：
            // 「这个条目本来就会被读到」≠「机器读过它、可以为它作证」。
            // 撤不撤最终还过 applyBundledRefVerdicts 的 P3 覆写闸。
            if (!rec.unpinned) rec.covered = group.every((e) => covNames.has(e) || covRows.has(rowKey(e)));
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
 *
 * fix8-E：撤销仍然撤销（等级、findings 内容一字不动 —— 那是正经模块的常规写法），
 * 但不再静默丢弃：每一次「机器替包内某个条目作过证」都要在 `revokedOut` 里留下一笔记录，
 * 由 `scanZip` 放进报告的专用字段 `revokedBundledRefs`，并让自动通道认下它。
 * 沉默必须显式声明，不许由「没命中」反推 —— 见 P14 立的那条规矩。
 * 放专用字段而不是 `findings` 里的一条 info：`renderJSON` 对所有
 * `countsTowardRisk() === false` 的 finding 无条件 `snippet: mask(...)`，而 info 混在
 * findings 里会让人分不清「这条为什么定级不算」。
 * 引用解析成**包外**程序（`SCRIPT=/system/bin/sh`）时不记这一笔：那时机器没有替任何包内条目作证。
 * @param {object[]} findings
 * @param {object[]} refs resolveBundledRefs 的返回
 * @param {Map<string, number>|null} [writeInfo] 文件 -> 首个「运行期写模块目录」命中行（fix2-P3）
 * @param {object[]|null} [revokedOut] 可选收集数组：每撤销一条 finding 推一项
 *        { ruleId, file, line, ref, resolvedEntry, covered }
 * @returns {object[]} 新的发现数组（不改入参对象）
 */
export function applyBundledRefVerdicts(findings = [], refs = [], writeInfo = null, revokedOut = null) {
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
    if (dismissable && !overridden) {
      // 撤销成立。记的是「哪一个包内条目被读过而没有被单独报出来」，
      // 取第一条真正的包内引用（外部目标不算替包内条目作证）。
      const vouched = recs.find((r) => !r.external && r.resolved && r.covered && r.resolvedEntry);
      if (vouched && Array.isArray(revokedOut)) {
        revokedOut.push({
          ruleId: f.ruleId, file: f.file, line: f.line,
          ref: trimSnippet(vouched.ref), resolvedEntry: vouched.resolvedEntry, covered: vouched.covered,
        });
      }
      continue;
    }
    const copy = { ...f };
    const escalated = recs.find((r) => r.entries && r.entries.length);
    const unpinned = recs.find((r) => r.unpinned);
    const unresolved = recs.find((r) => !r.resolved);
    // Task 2.7：扩面之后「被引用但撤销不成立」的条目不再产生升级记录（它本来就在 feed 里），
    // 于是同一行里「已撤销的常规写法 + 没被撤销的真载荷」这一格 cause 会全空，
    // snippet 退回规则自己的最左匹配 —— 报告就把已经作过证的 `install.sh` 写成风险本体。
    // 这一格补的是**作证的指向**，不是等级：撤销不成立的包内引用，指的就是它。
    const culprit = recs.find((r) => r.resolved && !r.covered && !r.external && r.resolvedEntry);
    const cause = escalated || culprit || unpinned || unresolved;
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
  // 二进制只登记不逐行扫（见 checkBinaries 的理由）—— 改名成数据文件的 ELF 由魔数落进
  // `binaries`，不在这里被捞回文本，那一格的证据是 STRUCT_BINARY 与 T5.5 取证。
  // Task 4 补的那一格在下面的 polyglot 那一步：分桶不动、文本桶不许捞它，但「整块可读」的
  // 那份字节要在**内容扫描**里被逐行读一遍（进 feed，不进可撤销面）。
  // fix2-P5：桶清单从 classify() 的返回键里显式点名（SCAN_TARGET_BUCKETS）——
  // 以前这里是手写的展开，新增桶忘接线时不会报错，只会让那个桶的文件「安静地不进扫描面」
  // （P5 复现过的正是这种静默）。守卫测试对两边做双向比对，忘一条就红。
  //
  // Task 2.7（fix10-P11）：这里分成两个集合，别再合并回一个。
  //   coveredSurface = 五个桶（**扩面之前**的面）—— 只用来判「这条引用能不能撤」；
  //   scanTargets    = 五个桶 ∪ cls.others —— 内容扫描实际喂进去的东西（feed）。
  // `others` 是「前 512 字节没有 NUL、也没被前面的桶接住」的条目（classify 的魔数闸在最前面，
  // 所以伪装成 .dat 的 ELF 落 binaries 不落这里，那条由 scan.test.mjs 的钉子压着）。
  // 引用方与被引用方都落在名单外时，两边都静默过一次：`config.json` 里的
  // `sh $MODDIR/payload.dat` 既不产生证人、载荷也没被读过，整包 0 发现 / auto-approve。
  // 撤销判据继续只认 coveredSurface —— 「会在扫描面上」不等于「读过且无罪」。
  const coveredSurface = SCAN_TARGET_BUCKETS.flatMap((b) => cls[b] || []);
  const scanTargets = coveredSurface.concat(cls.others || []);

  // Task 4：把「魔数/NUL 开头 + 后面整块是明文脚本」的 polyglot 条目**追加进 feed**。
  // `classify()` 的魔数闸让它落 `binaries` 并 `continue`，于是那种「整块可读」的条目在改前
  // 一行都没喂给内容规则 —— 报告只能说「有个二进制我读不了」，不能说「里面逐字写着
  // `curl | sh` / `setenforce 0`，第几行」。方向是加严，动的只有组扫描面这一步。
  // 先只算「哪些条目过线」（纯读 cls.binaries，不碰任何集合），真正 push 留到升级之后：
  // 这样 `coveredSurface` 继续是那五个桶，而「把 polyglot 并进可撤销面」是一处可指名的改法
  //（变异 M3 就改下面 `resolveBundledRefs` 的那一个实参）。
  const polyglotEligible = (cls.binaries || []).filter((b) => {
    const text = String(b.content == null ? '' : b.content);
    // 内容非空 + 整块可打印比例**严格大于**阈值（量法只有共享层那一份实现，见 risk-rules）
    return text.length > 0 && printableRatio(text) > POLYGLOT_MIN_PRINTABLE;
  });

  // 载荷间接执行：被脚本 sh/source/变量间接引用的包内条目必须进扫描面，而且必须发生在下面那个
  // 内容扫描循环之前 —— 追加在循环之后的话，那些条目一行都不会被扫，测试却照样能
  // 「命中 EXEC_BUNDLED_FILE」，于是这条闸变成只有名字没有牙的装饰。
  const escalated = [];
  const escalatedEntries = [];
  // modId 只能取 fields.id.value：fields.id 是 {value,line}，直接拿它当字符串会拼出
  // /data/adb/modules/[object Object]/，引用解析永远匹配不上真实条目（评审 F9）。
  const idField = propEntry ? parseModuleProp(propEntry.content).fields.id : null;
  const modId = (idField && idField.value) || opts.declaredId || '';
  // fix2-P2：变量钉定表要先算好，resolver 判 `sh $X` 时才有「X 钉不钉得住」可查。
  // Task 2.7：这张表跟着 feed（扩面之后）—— 引用在哪一层文件里，就要拿那个文件的赋值去钉；
  // 只按五个桶建表的话，`others` 里新扫出来的引用会全部落成「钉不住的未验证引用」。
  const varMapsByFile = {};
  for (const f of scanTargets) varMapsByFile[f.name] = collectVarValues(f.content, modId);
  // 第 1 参 = feed（去重与升级都照它），第 5 参 = coveredSurface（撤销只照它）。
  const bundledRefs = resolveBundledRefs(scanTargets, files, modId, varMapsByFile, coveredSurface);
  for (const e of escalationsFromRefs(bundledRefs)) {
    scanTargets.push(e);
    escalatedEntries.push(e);
    escalated.push({ fromFile: e.__from, fromLine: e.__line, ref: e.__ref, resolvedEntry: e.name });
  }

  // Task 4 的那一步真正落地：把过线的条目追加进 feed。三件事各管各的，一条都不许并（工单 §2）：
  //   * `coveredSurface` 一字未动 ⇒ 撤销照旧只认扩面之前那五个桶。这一格是 §0.13 的续命判据：
  //     「`sh $MODPATH/assets/payload.bin` 可以撤销」必须仍然不成立（夹具 T4-B3 / 变异 M3）。
  //   * push 排在 `resolveBundledRefs` **之后**：升级记账（`report.escalated`）说的还是
  //     「原本不在扫描面、因引用被拉进来」那件事，不许被本轮顶掉；已在 feed 上的条目
  //     （含被升级进来的那份拷贝，按 rowKey 比）不重复推第二遍 —— 同一个条目推两遍就是
  //     §0.16 那张表里「③ 跟着 ②」的同一个病：同一条 finding 出现两次、`counts.high` 变胖，
  //     而 `counts` 是直接写进公开评论「命中统计」的那一行。
  //   * push 排在本行的截断记账**之前**：polyglot 走的还是 Task 2.9 那条 24 KB 有界通道
  //     （`lineRuleInput`），超限照旧记 `AUDIT_COVERAGE_TRUNCATED`，不为它另开一条无上限的喂法。
  const polyglotFed = [];
  {
    const onFeed = new Set(scanTargets.map((f) => rowKey(f)));
    for (const b of polyglotEligible) {
      if (onFeed.has(rowKey(b))) continue;              // 已在 feed：不记第二份身份
      scanTargets.push(b);
      onFeed.add(rowKey(b));
      polyglotFed.push(b);
    }
  }
  // 渲染面按对象身份排除这一批（`escalated` 那些拷贝不在集合里，它们的清单行照旧在）。
  const polyglotSet = new Set(polyglotFed);

  // Task 2.9：扫描面到这儿才算齐（升级条目也在里面），所以「谁被喂进过行级规则、
  // 谁被上限砍过」只能在这里记账。escalated 那些是 `{...文件条目}` 的拷贝，
  // 按名字回到 files 里的原件上打标记，checkCoverage(files) 才看得见同一个数。
  const lineRuleNames = new Set();
  for (const f of scanTargets) if (f && f.name) lineRuleNames.add(f.name);
  if (propEntry) lineRuleNames.add(propEntry.name); // propFindings 那条通道同样吃上限
  for (const f of files) {
    if (f.scanCapped && lineRuleNames.has(f.name)) f.scanTruncated = true;
  }

  const rawFindings = [];
  for (const f of scanTargets) {
    // 上限只管这里：lineRuleInput(f) 是前缀（未超限时就是全文）。
    rawFindings.push(...scanContent(f.name, lineRuleInput(f)));
  }
  // 「引用目标是否已经被逐行扫过」只能在这里判（扫描面到这儿才齐），见 applyBundledRefVerdicts。
  // fix2-P3：先把「运行期向模块目录写出/解包」的命中行收成一表 —— 有这种证据的文件里，
  // 「同名条目已在扫描面」不再是字节证据，撤销闸必须失效。
  const writeInfo = new Map();
  for (const fd of rawFindings) {
    if (fd.ruleId === 'MODDIR_RUNTIME_WRITE' && !writeInfo.has(fd.file)) writeInfo.set(fd.file, fd.line);
  }
  // fix8-E：撤销记录。它不是发现（等级不动、评论噪声不动），但自动通道要认下它 ——
  // 见 risk-rules.decide 的第三个参数。
  const revokedBundledRefs = [];
  const findings = applyBundledRefVerdicts(rawFindings, bundledRefs, writeInfo, revokedBundledRefs);
  // 跨文件的覆写形状（A 解包、B 执行）同样不许按「已扫过」静默放过：补成指名 B 的显式发现。
  findings.push(...crossFileOverrideFindings(bundledRefs, writeInfo));

  // module.prop 也要过一遍内容规则（里面可能有外联地址或隐私路径）
  // Task 2.9：这条通道吃的也是同一个上限 —— module.prop 的名字由投稿者给，塞 2 MB 进来
  // 就走「不在扫描面上」这条路躲开上限的话，上限就成了按桶生效的半截闸。
  const propFindings = propEntry && !scanTargets.includes(propEntry)
    ? scanContent(propEntry.name, lineRuleInput(propEntry))
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
  struct.stats.limits.MAX_SCAN_BYTES_PER_ENTRY = MAX_SCAN_BYTES_PER_ENTRY;
  // 第三个参数只用来把阈值写进文案；「哪个条目被砍了多少」在 files[].scanBytes 上。
  const coverFindings = checkCoverage(files, MAX_TEXT, MAX_SCAN_BYTES_PER_ENTRY);
  const unreadFindings = checkUnread(unread);
  // Task 5.7 接线（工单 §2 末段）：对 classify() 的 binaries 逐条跑 forensics(raw)，
  // 按**条目名**建 map 再交给 checkBinaries。两份名字必须出自同一个表达式 ——
  // map 的 key 只要漂一个口径（归一化成 basename、把反斜杠折成正斜杠、拿原始 zip 条目名
  // 对工作区标签），整套新分支就一声不响地死掉：报告照旧是「medium / 我读不了」，
  // 而测试还能全绿。INV-A 与变异 M4（名字口径）、M6（字节口径）就是为这一格存在的。
  // 重名条目在 map 上必然共用一份记录（STRUCT_DUPLICATE_NAME 已经把那种包判 high 并拦住
  // 自动放行）；登记里 entryBytes 取条目自己、forensicsBytes 取记录，两者不一致时人看得见。
  const binList = binaries.map((b) => ({ name: b.name, id: b.binary.id, why: b.binary.why, bytes: b.size }));
  const forensicsByName = new Map();
  const dexSurfaces = [];
  for (let i = 0; i < binaries.length; i++) {
    const b = binaries[i];
    // 没留住原始字节就**不登记**（不拿 content 去凑：utf8 串喂进 forensics 只会得到
    // 一条「字节已经毁了」的 parseError，看着像「这个二进制读不出名堂」，
    // 而那正是 §1 硬边界最怕的静默失效 —— 工单 §5 数过这一格）。
    if (!Buffer.isBuffer(b.raw) || b.raw.length === 0) continue;
    // 第五十批：解析器按 detectBinary 已经算出来的 id 分派，而不是"两个都试一遍、谁返回 null
    // 就归另一个管"。后者会把「本轮故意不解析」（ZIP）与「解析失败」（parseError）压成同一格，
    // 而那两本的账完全不同 —— 沿用 §2.7 那条「看不见 ≠ 看不清」的纪律。
    const isDex = b.binary.id === 'DEX';
    const rec = isDex ? dexForensics(b.raw, binList[i].name) : forensics(b.raw, binList[i].name);
    // `rec === null` 也要 set：那是「归 ELF 管但读到不是 ELF」的确定读数（NOT_ELF 那一格靠它），
    // 不 set 就退成 NO_RECORD，报告念起来像"分支没接线"。
    const stored = rec && b.rawCapped ? { ...rec, inputCapped: true, rawBytes: b.raw.length } : rec;
    // 与「已经在逐行扫描面上」那一格**互斥**：Task 4 的 polyglot 扩面与 fix2-P5 的引用升级都可能
    // 把同一个条目推进 feed，那时它已经被逐行扫过一遍了；再摊一遍串池喂进去，同一条规则就会在
    // 同一个文件上命中两次 —— 而 `counts.high` 是直接写进公开评论「命中统计」的那一行（上面
    // 907-909 那段讲的正是这个病）。判据取 `lineRuleNames`（谁在 feed 上）而不是只取 polyglotSet：
    // 只防 polyglot 会漏掉被引用升级进来的那一支（本轮实测过，见 DXE-07）。
    // 被顶掉的那一格必须留下名字，不许静默：`surfaceSkipped` 进登记、也进那句话。
    if (isDex && stored && !stored.parseError) {
      if (lineRuleNames.has(binList[i].name)) {
        stored.surfaceSkipped = polyglotSet.has(b) ? 'polyglot' : 'escalated';
      } else {
        const s = dexStringSurface(stored);
        stored.surface = { lines: s.lines, trimmed: s.trimmed, dropped: s.dropped, escaped: s.escaped };
        if (s.text) dexSurfaces.push({ name: binList[i].name, text: s.text, stats: stored.surface });
      }
    }
    forensicsByName.set(binList[i].name, stored);
  }
  // dex 串面进规则那一步，排在 checkBinaries / binaryForensicsRows **之前**：降了几条要能回写进
  // 那个条目自己的登记句子（见下面 downgraded），而登记句子是这两行产出的。
  //   * 判据仍然只有 `CONTENT_RULES` 那一份 —— 这里只把常量池摊平成规则看得见的形状；
  //   * 定档换算只在 `dexSurfaceSeverity` 一个函数里（执行型 → info、存在型照原判据），
  //     不在这里比 severity、不在此处新增第二条规则、也不在 scan 这一层后处理 severity（fix6-F1 的病）；
  //   * 串面没喂全（dropped / trimmed）并进这个条目自己那句话，不另开一条 finding ——
  //     理由与 ELF 的 `INPUT_CAPPED` 同形，见 risk-rules 的 dexSurfaceNote 那段。
  // 为什么这里不复用 24 KB 那条 `lineRuleInput` 通道：实测同一枚真 dex 在 24 KB 预算下只喂得进
  // 44 行、丢掉 23,169 条 —— 那一档是为「单条长行把回溯炸到分钟级」准备的，而串池是几万条短行。
  // 对症的那一闸是单串上限（`DEX_SURFACE_LINE_MAX`），在 dexStringSurface 里落。
  const dexFindings = [];
  const downgradedByFile = new Map();
  for (const d of dexSurfaces) {
    for (const f0 of scanContent(d.name, d.text)) {
      const f = dexSurfaceSeverity(f0);
      if (f !== f0) downgradedByFile.set(d.name, (downgradedByFile.get(d.name) || 0) + 1);
      dexFindings.push(f);
    }
  }
  for (const d of dexSurfaces) {
    const rec = forensicsByName.get(d.name);
    if (rec && rec.surface) rec.surface.downgraded = downgradedByFile.get(d.name) || 0;
  }
  const binFindings = checkBinaries(binList, forensicsByName);
  const binaryForensics = binaryForensicsRows(binList, forensicsByName);
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
    ...struct.findings, ...coverFindings, ...unreadFindings, ...binFindings, ...metadataFindings,
    ...dexFindings]
    .filter((f) => f.severity != null)
    .sort((a, b) => {
      const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (d !== 0) return d;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });

  const { level, counts, reasons } = scoreRisk(all);
  const changeType = resolveChangeType(opts, propMeta);
  // 撤销覆盖度：decide 只需要「发生过几次撤销」与「撤销的是哪些条目」两件事。
  const decisionCoverage = {
    revokedCount: revokedBundledRefs.length,
    revokedEntries: [...new Set(revokedBundledRefs.map((r) => r.resolvedEntry))],
  };
  // ── 两轴分流（设计文档 §2 / §3.2 / §4 / §13.5）—— 2026-10-21 第二发：调用点已换轴 ─────
  // 第一发（判据与名单）把 classifyMalice / summarizeCoverage / MALICE_RULE_IDS 落进 risk-rules.mjs，
  // 但这一格仍走老轴（等级当判决），于是「正当功能的 high 不再拦上架」在生产上还没发生。
  // 这一发把它翻过来：`decide(...)` 的第 4 参接上恶意定性，**上不上架只由「命中拦截名单否」决定**
  //   * 命中 MALICE_RULE_IDS（11 条全 armed）∪ AI 恶意结论 ⇒ block；
  //   * 名单外的一切（含 PROP_BOOT_SPOOF / VERIFIED_BOOT_SPOOF / MAGISK_POLICY_LIVE / SELINUX_* /
  //     EXEC_BUNDLED_FILE / MODDIR_RUNTIME_WRITE 这些「正当功能本身就长得像能力」的 high）⇒ auto-approve，
  //     等级与读数退成 `annotation`（能力/覆盖轴，只写结论）；
  //   * `update` / `unknown` 与 fix8-E（撤销过）维持不放行 —— §13 第 2 条是**待拍**，本函数不自行默认。
  // AI 那一支在这里恒为 null：AI 产物在这一格还不存在（scan 在 AI 之前跑），
  // 恶意通道的 ∪ 发生在 audit.yml「分流决策」那一步（读 ai-<pkg>.json 的 maliceVerdict）。
  // 为什么不在这里 import ai-review：判据只许有一份，而这一层的取严规则住在 classifyMalice 里。
  const malice = classifyMalice(all, null);
  const annotation = summarizeCoverage(all, {
    level, counts,
    unreadCount: Array.isArray(unread) ? unread.length : 0,
  });
  const decision = decide(level, changeType, decisionCoverage, malice);

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
    // Task 5.7：取证数据单独一格，逐条目一条，key 与 report.binaries 的 name 同一套。
    // 为什么不放进 finding 的 snippet：renderJSON 对所有**不参与定级**的 finding 无条件
    // `snippet: mask(...)`，实测把证据打成 `AArc************语义`（§0 记过的那次），
    // 而这一格不受定级口径牵连。这里只有事实与一句话结论，**没有字节面**（§5.3，T57-15 钉）。
    binaryForensics,
    // 被引用而升级进扫描面的条目：谁在第几行、用什么写法引用了它，解析到了哪个条目。
    // 人工复核与 T5 的 brief 都靠这个字段复现「引用 → 载荷」这条链。
    escalated,
    // fix8-E：被「目标已在扫描面 ⇒ 这条引用不必单独报」撤销掉的执行类发现，逐笔留痕。
    // 与 `escalated` 是两种证人：那边是「确实读过一个没读过的东西」，这边是「机器替读过的东西
    // 撤了一条发现」。撤销本身照旧（等级不变），但它不再是静默的，也不再能换来自动放行。
    // 单独成字段而不是塞进 findings 当 info：见 applyBundledRefVerdicts 的理由。
    revokedBundledRefs,
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
    // Task 4：本轮追加进 feed 的 polyglot 也不进这一节 —— 同一个条目在报告清单里只有
    // 一份身份（`binaries` 那一行），它读到了什么由 findings 自己指名道姓（工单 §2.4）。
    scripts: scanTargets.filter((f) => !polyglotSet.has(f)).map((f) => scriptRow(f)),
    // 本轮的记账面：哪些 binaries 条目因为「整块可读」被追加进了内容扫描，读了多少字节。
    // 它不是 finding（不改等级、不加噪声），但「进过 feed」这件事必须人看得见、测得着 ——
    // 否则 B1「两条 descriptor 进面但 0 发现」与 B2「机器码不许进面」两侧都没有观测点。
    polyglotFed: polyglotFed.map((f) => ({
      name: f.name,
      kind: f.binary ? f.binary.id : null,
      bytes: f.size,
      printable: Number(printableRatio(f.content).toFixed(4)),
      scanBytes: f.scanBytes,
      scanCapped: Boolean(f.scanCapped),
    })),
    findings: all,
    counts,
    riskLevel: level,
    riskReasons: reasons,
    changeType,
    decision,
    // 两轴分流的两格新落点（§4 第三行把 decide() 拆成了「拦」与「标注」两件事）：
    //   malice    = 恶意行为轴，唯一决定上不上架的那一份判据（本发的 decision 就是吃它定的）
    //   annotation = 能力/覆盖轴，只写结论，不影响上架
    // 名字刻意不叫 review/humanReview —— 这一条链上今天没有人工那一格。
    malice,
    annotation,
    warnings,
    durationMs: Date.now() - started,
  };
}

function toInventoryRow(f) {
  return { name: f.name, bytes: f.size, lines: countLines(f.content), truncated: f.truncated,
    // Task 2.9：清单要能自证「这个条目实际被行级规则读了多少字节」——
    // 人工复核对着 AUDIT_COVERAGE_TRUNCATED 那条记录时，第二个数就在这儿。
    scanBytes: f.scanBytes, scanCapped: Boolean(f.scanCapped) };
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
  // T6.3：下面凡是从包里读出来、或从投稿表单读出来的字符串，落进 markdown 之前一律过
  // inertMarkdown。我们自己造的词（标题、级别、规则号、建议文案）一个都不过 ——
  // 人还得读得懂这份报告，而围栏里那份脚本原文是人工复核要看的东西。
  L.push(`- 目标文件：\`${inertMarkdown(report.target.zipName)}\``);
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
  // reason 里可能带着条目路径（decide() 撤销自动放行那一支把 ${shown} 写进句子，
  // shown 来自 zip 的条目名 == 投稿者可控），所以这一行也要过中和。
  L.push(`- 依据：${inertMarkdown(report.decision.reason)}`);
  L.push(`- 命中统计：high ${report.counts.high} / medium ${report.counts.medium} / low ${report.counts.low} / info ${report.counts.info}`);
  // ── 两轴的读数分开写（§10：三个落点别混；这一格是「索引仓库里的报告 → PR 评论」那一层）──
  // 等级仍然念出来，因为它现在是**标注**而不是判决；不念就等于把量过的东西藏起来。
  if (report.malice) {
    const names = [...new Set((report.malice.hits || []).filter((h) => h.source === 'static').map((h) => h.ruleId))];
    L.push(`- 恶意行为链：${report.malice.malicious ? `**命中** —— ${names.length ? names.join('、') : 'AI 恶意结论（引用已逐字复验）'}` : `未命中（名单共 ${MALICE_RULE_IDS.length} 条 armed / ${MALICE_LIST.length} 条定案）`}`);
    const deferred = MALICE_LIST.filter((m) => !m.armed);
    if (deferred.length) {
      L.push(`  - 名单里今天不 armed 的：${deferred.map((m) => `${m.id}（判据缺陷未修，见 risk-rules 的 closesWhen）`).join('、')} —— 缺席读数自己报出来，不装成名单里没有`);
    }
  }
  if (report.annotation) {
    const a = report.annotation;
    L.push(`- 标注（不影响上架）：危险能力 ${a.capabilities.length} 项${a.capabilities.length ? `（${a.capabilities.join('、')}）` : ''}；覆盖不全 ${a.coverageGaps.length} 项${a.coverageGaps.length ? `（${a.coverageGaps.join('、')}）` : ''}；上下文题 ${a.contextQuestions.length} 项${a.contextQuestions.length ? `（${a.contextQuestions.join('、')}）` : ''}`);
  }
  L.push('');

  L.push('## 元数据');
  L.push('');
  L.push('| 字段 | module.prop | 投稿表单声明 | 是否一致 |');
  L.push('|---|---|---|---|');
  const idOk = !report.declared.id || !m.id ? '未声明' : (report.declared.id === m.id ? '✅ 一致' : '❌ 不一致');
  const verOk = !report.declared.version || !m.version ? '未声明' : (report.declared.version === m.version ? '✅ 一致' : '❌ 不一致');
  // module.prop 整份是投稿者写的，表单声明也是他填的 —— 这一格的四面都要过中和。
  L.push(`| id | \`${inertMarkdown(m.id ?? '(缺失)')}\` | \`${inertMarkdown(report.declared.id ?? '(未提供)')}\` | ${idOk} |`);
  L.push(`| version | \`${inertMarkdown(m.version ?? '(缺失)')}\` | \`${inertMarkdown(report.declared.version ?? '(未提供)')}\` | ${verOk} |`);
  if (m.name) L.push('');
  if (m.name) L.push(`- name：${inertMarkdown(m.name)}`);
  if (m.author) L.push(`- author：${inertMarkdown(m.author)}`);
  if (m.description) L.push(`- description：${inertMarkdown(m.description)}`);
  L.push(`- module.prop 路径：\`${inertMarkdown(m.propPath ?? '(缺失)')}\``);
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
  for (const b of report.binaries || []) {
    // Task 4：进过内容扫描的那几条不许继续顶着「不逐行扫」这句话 —— 报告说的和做过的不许两样。
    // 措辞只说读过（逐行读到了什么由 findings 那一节自己指名），不说「审过了、没问题」。
    const label = (report.polyglotFed || []).some((x) => x.name === b.name)
      ? '二进制（已按内容规则逐行扫过）'
      : '二进制（不逐行扫）';
    L.push(`| ${label} | \`${escapeCell(b.name)}\` | ${b.bytes} B | ${b.kind} |`);
  }
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
      + '文本条目在「逐行扫过的文件全文」一节给全文，非文本条目只给有界预览）：');
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
  // 这一列出来的每一条都是条目名（符号链接/越界路径/重名/加密/不支持的压缩方式/反斜杠/解压失败），
  // 条目名是投稿者起的 —— 过同一把中和，别在这里再写第二份口径。
  const list = (a) => (a && a.length ? a.map((x) => `\`${inertMarkdown(x)}\``).join('、') : '无');
  L.push(`- 条目总数：${st.entries ?? '—'}（文件 ${st.fileEntries ?? '—'} / 目录 ${st.dirEntries ?? '—'}），阈值 ${st.limits ? st.limits.MAX_ENTRIES : '—'}`);
  L.push(`- 最高声明压缩比：${st.maxRatio ?? 0}:1${st.maxRatioEntry ? `（\`${inertMarkdown(st.maxRatioEntry)}\`）` : ''}，阈值 ${st.limits ? st.limits.MAX_RATIO : '—'}:1`);
  L.push(`- 符号链接条目：${list(st.symlinks)}`);
  L.push(`- 越界/绝对路径条目：${list(st.unsafePaths)}`);
  L.push(`- 重名条目：${list(st.duplicateNames)}`);
  L.push(`- 加密条目：${list(st.encrypted)}`);
  L.push(`- 不支持的压缩方式：${list(st.unsupportedMethods)}`);
  L.push(`- 反斜杠路径条目：${list(st.backslashPaths)}`);
  L.push(`- 解压失败的条目：${list((report.unread || []).map((u) => u.name))}`);
  // Task 2.9：这两行是分开的两件事 —— 内嵌上限管「人看得见多少」，扫描上限管「规则跑过多少」。
  // 旧文案在这里写「行级规则跑的仍是全文」，上限落地后那就是假话，所以按本次真正生效的阈值重说。
  const scanCap = st.limits ? st.limits.MAX_SCAN_BYTES_PER_ENTRY : MAX_SCAN_BYTES_PER_ENTRY;
  L.push(`- 行级规则的输入上限：${st.limits ? (scanCap / 1024).toFixed(0) : '24'} KB/条目（超出只把前缀喂给规则，`
    + '并逐条记 `AUDIT_COVERAGE_TRUNCATED`：哪个条目、原文多少字节、实扫多少字节）');
  L.push(`- 报告内嵌全文的上限：${st.limits ? (st.limits.MAX_TEXT / 1024).toFixed(0) : '512'} KB/文件`
    + `（Markdown 只贴前缀，全文在 JSON 产物里；上限之外的字节连规则也没读过，见上一条）`);
  // Task 4：这一行是「进 feed 这件事可观测」那一格（工单 §3 B1）。没有这类条目时一行都不许多，
  // 所以既有包的这一节逐字不变；有条目时要说清读的是哪几条、比例多少、读了多少字节。
  if ((report.polyglotFed || []).length) {
    L.push(`- 魔数/NUL 开头但整块可读、已追加进内容扫描面的条目（${report.polyglotFed.length} 个，`
      + '它们仍只登记在上面的二进制清单里，报告不为它们另立第二份身份）：');
    for (const x of report.polyglotFed) {
      L.push(`    - \`${escapeCell(x.name)}\`：${x.kind} / ${x.bytes} B，整块可打印 ${x.printable}`
        + `，行级规则读了 ${x.scanBytes} B${x.scanCapped ? `（超过单条目上限，已记 \`AUDIT_COVERAGE_TRUNCATED\`）` : ''}`);
    }
  }
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
        // file 是条目名、snippet 是原文匹配片段：两面都是投稿者来源，同一把中和。
        L.push(`| ${SEV_MARK[f.severity]} | \`${f.ruleId}\` | \`${inertMarkdown(f.file)}:${f.line}\` | \`${escapeCell(f.snippet)}\` | ${f.advice} |`);
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
      L.push(`| \`${f.ruleId}\` | \`${inertMarkdown(f.file)}:${f.line}\` | \`${escapeCell(mask(f.snippet))}\` | ${f.advice} |`);
    }
    L.push('');
  }

  if (report.warnings.length) {
    L.push('## 解析告警');
    L.push('');
    for (const w of report.warnings) L.push(`- ${inertMarkdown(w)}`);
    L.push('');
  }

  // Task 2.7（§2.7 文案纪律）：标题要说清这一节装的是什么。
  // 这一节列的是「本次被逐行喂进规则的文件」（feed = 五个桶 ∪ cls.others ∪ 升级条目），
  // 扩面之后 `cls.others` 里的数据文件（config.json / 字符串表 .dat 之类）也在里面 ——
  // 继续叫「脚本全文」就是把数据文件叫成脚本，而这一节的用途恰恰是让人照着它复核「读过什么」。
  L.push('## 逐行扫过的文件全文（人工复核用）');
  L.push('');
  if (!report.scripts.length) {
    // 「没有可扫的文本条目」是包本身的形状，不是「扫描没跑成」—— 两种说法不许合并。
    L.push('zip 内没有被逐行扫过的文本条目。');
  }
  for (const s of report.scripts) {
    const note = s.nonText
      ? '（内容非文本：已按文本逐行扫过，这里只给有界预览，机器码原文不进报告）'
      : (s.scanCapped
        // Task 2.9：这一行必须自己说清读了多少 —— 上限之外的字节连规则都没读过，
        // 只写「报告只内嵌前 N KB」会把「读到一半」渲染成「规则读完了、只是人看不全」。
        ? `（行级规则只跑了前 ${s.scanBytes} B（单条目上限 ${Math.round(MAX_SCAN_BYTES_PER_ENTRY / 1024)} KB），`
          + `原文 ${s.bytes} B；其余字节未逐行判过，已记 AUDIT_COVERAGE_TRUNCATED`
          + (s.truncated ? `；报告只内嵌前 ${Math.round(MAX_TEXT / 1024)} KB，其余见产物` : '') + '）'
        : (s.truncated ? `（报告只内嵌前 ${Math.round(MAX_TEXT / 1024)} KB，其余见产物）` : ''));
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
  // 这句话必须随轴走。分档判据取 decision 自己的形状，不取 reason 的正则：
  // 未命中那几句里也含「名单」二字（「未命中上架拦截名单」），拿 /名单/ 当判据会把待拍那一档
  // 念成「命中了名单」—— 那是替一个没命中的模块说一句指控，方向正好反了。
  const wired = report.decision.axis === 'malice';
  const hitList = wired && Array.isArray(report.decision.basis) && report.decision.basis.length > 0;
  L.push(`_本报告由 \`contrib/audit/scan.mjs\` 生成；**未经人工审核** —— 上不上架由一次可复验的机器运行判定（判据：\`risk-rules.mjs\` 的上架拦截名单 ∪ AI 恶意结论，§2）；${report.decision.needsHumanReview
    ? (wired
      ? `本次机器判定**不上架**${hitList ? '（命中上架拦截名单或 AI 恶意结论）' : '（未命中名单，但这一档按 §13 的待拍项 / 撤销记账维持保守分支）'}。`
      : '本次机器判定不放行；这一发的 decision 走的是老轴（调用点没传恶意定性）—— 生产调用点已接线，出现这句说明有人新增了调用点。')
    : '本模块可自动进入索引，随附上面的能力与覆盖标注。'}_`);
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

/**
 * T6.3：投稿者来源的字符串落进 markdown 之前先中和 markup —— **只中和不删字**。
 *
 * 与 6.2 给评论 intro 用的那把 `inert()`（`.github/workflows/audit.yml`）同形：
 * `&` 先转（避免二次转义），`<` `>` 反引号转实体，控制序列换空格。两层各管各的面，
 * 不许合并：那一把管「评论自己那几行原样插值」，这一把管「被插进评论正文的那份报告」。
 *
 * 三条不许越界：
 *  1) 判据只许有一份 —— 它住在 scan.mjs，workflow 里不许再抄第二份；
 *  2) **只作用于给人看的那一面**：不许顺着接到 renderJSON 上。AI 那一层吃的是 JSON
 *     （readZip 原文 + 报告 JSON），实体化会改变喂给模型的字节，把 6.1/6.2 的复验链打乱；
 *  3) 不许波及我们自己写的结构（标题、内联代码、代码围栏）—— 全文那一节留着真围栏，
 *     因为人工复核要看的是原文，而 fenceFor 保证投稿者关不掉它。
 */
export function inertMarkdown(v) {
  return String(v == null ? '' : v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/`/g, '&#96;')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ');
}

function escapeCell(s) {
  // 表格单元格与「### 条目名」这类标题都过这一把：条目名是投稿者起的，
  // `|` 要反斜杠、反引号与 `<` `>` 要实体（T6.3 之前只有前两件，所以一句 `</details>` 能漏进正文）。
  return inertMarkdown(s).replace(/\|/g, '\\|');
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
