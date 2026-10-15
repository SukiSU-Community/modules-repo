// audit/elf-forensics.mjs —— 只读 ELF 静态取证。不执行、不判档：只报"读到了什么"。
//
// 为什么要有这个模块（下游 risk-rules 用得到，代码里看不到）：
//   scan.mjs 对每个条目做 `content = bytes.toString('utf8')`。实测一个真 .so 从 983,624 B
//   膨胀成 1,530,819 B、84.3% 的字节位置被改写 —— 从 content 里解析任何结构都会给出
//   **自信的错误答案**。所以要看二进制内部只有这一条路：拿原始 Buffer，自己解析，报事实。
//
// 三条硬约束：
//   1) 不猜。任何偏离下面两张布局表的输入一律 { name, kind:'ELF', parseError } —— 未知 class、
//      大端、意外的 e_shentsize、越界的节头下标、任何跨过缓冲区末尾的表项，全部拒。
//   2) 畸形绝不抛。parseError 是正常失败通道，扫描器要继续跑。下游把"读不出来"当"未检查"从严
//      处理，所以这里最危险的不是拒，而是给出一个看似合理的数：unparseable 文件上出现
//      importCount: 0 会被念成"这个二进制什么都不导入"。因此 parseError 的输出里根本不带那些键。
//   3) 不返回严重性，不把"危险"编码成判断。sensitiveImports 只是一份过滤后的子集（名单已在真
//      模块上验过），判档是下游 Task 的事。
//
// 覆盖范围：ELFCLASS64 与 ELFCLASS32 的小端文件都读。32 位是刻意的 —— 实测五个真模块的 48 个
// 非文本条目里，18 个 64 位 ELF 今天就能给出可用的导入表，16 个 32 位今天什么都给不出（旧原型在
// EI_CLASS != 2 处直接退）。让"能不能看见"取决于作者有没有发 32 位 ABI，这个不对称没有安全含义。
// .dex/.apk 不在射程内（dex 字符串表记的是"出现过的名字"，不是链接期事实，不能用来放宽任何东西）。
//
// 读不到的东西（写清楚，别让下游以为这里看过）：不解析重定位、不跟 .plt/.got、不反汇编、
// 无法判断某个导入函数是否真被调用、对 dex/apk 一个字都不说。
//
// 零第三方依赖；不需要 readelf/nm/strings，CI 与开发机同结果。

/** 机器码 → 名字。未知就写 `#<数值>`，不猜别的名字。 */
const MACHINE = { 183: 'AArch64', 40: 'ARM', 3: 'x86', 62: 'x86-64', 243: 'RISC-V' };
const E_TYPE = { 2: 'EXEC', 3: 'DYN' };
const SHT_STRTAB = 3;

/**
 * 两个类的字段位置。这些偏移是在 audit/fixtures/ 的真字节上逐项量出来的，不是背出来的：每条都由
 * 三件事同时反证 —— `e_shoff + e_shnum * e_shentsize == 文件长度`、`e_shentsize == sizeof(ElfW(Shdr))`、
 * `e_shstrndx` 指向的最后一个节解出 `.shstrtab`。任一不成立就是 parseError。
 *
 * 历史 bug ①：e_shstrndx 被当成 8 字节**偏移**读过。它是 0x3e（64 位）/ 0x32（32 位）处的
 * 2 字节**下标**；读错后每个节名都成乱码，`.dynsym` 看上去不存在 —— 一个假得很有说服力的
 * "这个 .so 没有动态符号表"。
 */
const LAYOUT = {
  1: {
    className: 'ELF32', hdrSize: 52, shentsizes: [40, 64], wide: 4,
    phoff: 0x1c, shoff: 0x20, shentsize: 0x2e, shnum: 0x30, shstrndx: 0x32,
    sh: { name: 0x00, type: 0x04, offset: 0x10, size: 0x14, link: 0x18 },
    sym: { size: 16, name: 0x00, shndx: 0x0e },          // Elf32_Sym
    dyn: { size: 8, val: 0x04, tagIsBig: false },        // Elf32_Dyn：d_tag i32@0, d_un u32@4
  },
  2: {
    className: 'ELF64', hdrSize: 64, shentsizes: [64], wide: 8,
    phoff: 0x20, shoff: 0x28, shentsize: 0x3a, shnum: 0x3c, shstrndx: 0x3e,
    sh: { name: 0x00, type: 0x04, offset: 0x18, size: 0x20, link: 0x28 },
    sym: { size: 24, name: 0x00, shndx: 0x06 },          // Elf64_Sym
    dyn: { size: 16, val: 0x08, tagIsBig: true },        // Elf64_Dyn：d_tag i64@0, d_un u64@8
  },
};

const DT_NULL = 0n;
const DT_NEEDED = 1n;

/** 字符串扫描上限：文件比这大就只扫前 8 MiB，并用 stringsPartial 明说。 */
export const STRING_SCAN_LIMIT = 8 * 1024 * 1024;
const SAMPLE_CAP = 4096;    // 样本**条数**上限。只限制样本，绝不限制 total。
const IOC_SAMPLE_CAP = 8;   // 每个桶最多 8 条 `offset: 串`

class Refuse extends Error {}
const refuse = (msg) => { throw new Refuse(msg); };

const isBytes = (buf) => !!buf && typeof buf === 'object' && typeof buf.length === 'number' && typeof buf.readUInt8 === 'function';
const hasElfMagic = (buf) => buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;

/** 按宽度读一个小端整数；读不到就是拒，不是 0。 */
function readUint(buf, at, width, what) {
  if (!Number.isInteger(at) || at < 0 || at + width > buf.length) {
    refuse(`${what || `field at 0x${(at >>> 0).toString(16)}`} (${width}B) runs past the buffer (${buf.length}B)`);
  }
  return width === 8 ? Number(buf.readBigUInt64LE(at)) : buf.readUInt32LE(at);
}

/** 把"为什么拒"讲清楚；返回 null 表示可以解析。 */
function whyRefused(buf) {
  const cls = buf[4];
  const L = LAYOUT[cls];
  if (!L) return `unknown EI_CLASS=${cls} (only ELFCLASS32=1 and ELFCLASS64=2 are parsed)`;
  if (buf[5] !== 1) return `unsupported EI_DATA=${buf[5]} (big-endian ELF is out of scope; refusing instead of hard-reading it little-endian)`;
  if (buf.length < L.hdrSize) return `${L.className} header truncated: need ${L.hdrSize}B, buffer has ${buf.length}B`;
  const shentsize = buf.readUInt16LE(L.shentsize);
  if (!L.shentsizes.includes(shentsize)) return `unexpected ${L.className} e_shentsize=${shentsize} (accepting only ${L.shentsizes.join('/')})`;
  const shnum = buf.readUInt16LE(L.shnum);
  const shstrndx = buf.readUInt16LE(L.shstrndx);   // 2 字节**下标**，不是偏移
  if (shstrndx >= shnum) return `e_shstrndx=${shstrndx} is out of range (e_shnum=${shnum})`;
  return null;
}

/**
 * 判"这是不是我能读的 ELF"。能读就回头部字段，不能读一律 null —— 调用方拿到 null 之后不该再猜。
 * 只碰 e_ident 和头部那几个整数，不碰任何表。
 */
export function elfPeek(buf) {
  if (!isBytes(buf) || !hasElfMagic(buf)) return null;
  if (whyRefused(buf)) return null;
  const L = LAYOUT[buf[4]];
  const machine = buf.readUInt16LE(0x12);
  const eType = buf.readUInt16LE(0x10);
  return {
    class: buf[4] === 2 ? 64 : 32,
    className: L.className,
    machine,
    machineName: MACHINE[machine] || `#${machine}`,
    type: E_TYPE[eType] || `#${eType}`,
    phoff: readUint(buf, L.phoff, L.wide, 'e_phoff'),
    shoff: readUint(buf, L.shoff, L.wide, 'e_shoff'),
    shentsize: buf.readUInt16LE(L.shentsize),
    shnum: buf.readUInt16LE(L.shnum),
    shstrndx: buf.readUInt16LE(L.shstrndx),
  };
}

/** 读整张节头表并用 shstrtab 解出节名。跨过缓冲区末尾的表项是拒，不是"读到几个算几个"。 */
function readSections(buf, L, h) {
  const ent = h.shentsize;
  const count = h.shnum;
  if (h.shoff + count * ent > buf.length) {
    refuse(`section header table (e_shoff 0x${h.shoff.toString(16)}, ${count} x ${ent}B) runs past the buffer (${buf.length}B)`);
  }
  const raw = [];
  for (let i = 0; i < count; i++) {
    const o = h.shoff + i * ent;
    if (o + ent > buf.length) refuse(`section header #${i} at 0x${o.toString(16)} runs past the buffer (${buf.length}B)`);
    raw.push({
      nameOff: readUint(buf, o + L.sh.name, 4, `shdr#${i}.sh_name`),
      type: readUint(buf, o + L.sh.type, 4, `shdr#${i}.sh_type`),
      offset: readUint(buf, o + L.sh.offset, L.wide, `shdr#${i}.sh_offset`),
      size: readUint(buf, o + L.sh.size, L.wide, `shdr#${i}.sh_size`),
      link: readUint(buf, o + L.sh.link, 4, `shdr#${i}.sh_link`),
    });
  }
  const shstr = raw[h.shstrndx];
  if (shstr.offset + shstr.size > buf.length) refuse(`.shstrtab (sh_offset 0x${shstr.offset.toString(16)} + sh_size ${shstr.size}) runs past the buffer (${buf.length}B)`);
  const poolEnd = shstr.offset + shstr.size;
  // 节名只是描述性的（用来认 .dynsym / .symtab 在不在）。指不出池内位置就留空名，不编一个。
  const cstr = (rel) => {
    const at = shstr.offset + rel;
    if (rel < 0 || at >= poolEnd) return '';
    let i = at, s = '';
    while (i < poolEnd && buf[i] !== 0 && s.length < 120) s += String.fromCharCode(buf[i++]);
    return s;
  };
  return { secs: raw.map((s) => ({ ...s, name: cstr(s.nameOff) })) };
}

/** 取 sh_link 指向的字符串池；下标越界一律拒，链到的节不是 STRTAB 才退回 .dynstr 这个约定名。 */
function linkedStrtab(secs, link, buf, fallbackName) {
  if (link < 0 || link >= secs.length) refuse(`sh_link=${link} is past e_shnum=${secs.length}`);
  const s = secs[link];
  const fb = secs.find((x) => x.name === fallbackName);
  const chosen = s && s.type === SHT_STRTAB && s.size > 0 ? s : fb;
  if (!chosen) refuse(`sh_link=${link} does not point at a usable SHT_STRTAB and ${fallbackName} is absent`);
  if (chosen.offset + chosen.size > buf.length) refuse(`${fallbackName} (sh_offset 0x${chosen.offset.toString(16)} + sh_size ${chosen.size}) runs past the buffer (${buf.length}B)`);
  return chosen;
}

/**
 * 主入口。
 * @param {Buffer} buf 单个条目的**原始字节** —— 不是 content 字段（那已被 utf8 解码毁掉）
 * @param {string} name 条目名，只用于回填输出
 * @returns {object|null} 非 ELF → null；读不出来 → 只带 parseError 的对象（**不带 importCount**）；
 *   读出来了 → 完整事实。永不抛。
 */
export function forensics(buf, name = '') {
  if (!isBytes(buf)) {
    return { name, kind: 'ELF', parseError: 'input is not a raw byte Buffer (a decoded string would already have destroyed the binary bytes)' };
  }
  if (!hasElfMagic(buf)) return null;                       // 不是 ELF：不归本模块管
  if (buf.length < 8) return { name, kind: 'ELF', parseError: `ELF magic present but header truncated: buffer has ${buf.length}B` };
  const why = whyRefused(buf);
  if (why) return { name, kind: 'ELF', parseError: why };
  try {
    return analyze(buf, name);
  } catch (err) {
    if (err instanceof Refuse) return { name, kind: 'ELF', parseError: err.message };
    // 兜底：没预料到的实现缺陷也只能变成 parseError，不许把扫描器带崩。
    return { name, kind: 'ELF', parseError: `unexpected parse failure: ${(err && err.message) || String(err)}` };
  }
}

function analyze(buf, name) {
  const L = LAYOUT[buf[4]];
  const h = elfPeek(buf);
  if (!h) refuse(whyRefused(buf) || 'refused by elfPeek');
  const { secs } = readSections(buf, L, h);
  const find = (n) => secs.find((s) => s.name === n);

  const out = {
    name,
    kind: 'ELF',
    bytes: buf.length,
    machineName: h.machineName,
    type: h.type,
    sections: secs.map((s) => s.name).filter(Boolean),
    stripped: !secs.some((s) => s.name === '.symtab'),      // .symtab 没了 == 作者 strip 过
    importCount: 0,
    sensitiveImports: [],
    needed: [],
  };

  // ---- 导入：.dynsym 里 st_shndx == 0（SHN_UNDEF）的条目 == 链接期要从别的库要的名字 ----
  const dynsym = find('.dynsym');
  if (dynsym) {
    if (dynsym.offset + dynsym.size > buf.length) refuse(`.dynsym (sh_offset 0x${dynsym.offset.toString(16)} + sh_size ${dynsym.size}) runs past the buffer (${buf.length}B)`);
    const strtab = linkedStrtab(secs, dynsym.link, buf, '.dynstr');
    const poolEnd = strtab.offset + strtab.size;
    // 名字必须在池里闭合。读不出终止符就整份拒 —— 半个名字比没有名字更容易被念成事实。
    const nameAt = (rel) => {
      const at = strtab.offset + rel;
      if (rel < 0 || at >= poolEnd) refuse(`.dynsym st_name=${rel} is past .dynstr (${strtab.size}B)`);
      let i = at, s = '';
      while (i < poolEnd && buf[i] !== 0) { s += String.fromCharCode(buf[i]); i++; }
      if (i >= poolEnd) refuse(`unterminated name in .dynstr at 0x${at.toString(16)}`);
      return s;
    };
    const entries = Math.floor(dynsym.size / L.sym.size);
    const imports = [];
    for (let i = 0; i < entries; i++) {
      const o = dynsym.offset + i * L.sym.size;
      if (o + L.sym.size > buf.length) refuse(`.dynsym entry #${i} at 0x${o.toString(16)} runs past the buffer (${buf.length}B)`);
      const stName = readUint(buf, o + L.sym.name, 4, `.dynsym#${i}.st_name`);
      const stShndx = buf.readUInt16LE(o + L.sym.shndx);
      if (stShndx !== 0) continue;                          // 有定义的符号不是导入
      if (stName === 0) continue;                           // 第 0 项 null 符号：没有名字
      const n = nameAt(stName);
      if (n) imports.push(n);
    }
    out.importCount = imports.length;                       // 全集 = 分母，不按敏感名单筛
    out.sensitiveImports = [...new Set(imports.filter((x) => SENSITIVE.test(x)))].sort();
  }

  // ---- NEEDED：.dynamic 里的 DT_NEEDED，到 DT_NULL 收口 ----
  const dyn = find('.dynamic');
  if (dyn) {
    if (dyn.offset + dyn.size > buf.length) refuse(`.dynamic (sh_offset 0x${dyn.offset.toString(16)} + sh_size ${dyn.size}) runs past the buffer (${buf.length}B)`);
    const strtab = linkedStrtab(secs, dyn.link, buf, '.dynstr');
    const poolEnd = strtab.offset + strtab.size;
    const nameAt = (rel) => {
      const at = strtab.offset + rel;
      if (rel < 0 || at >= poolEnd) refuse(`DT_NEEDED str_offset=${rel} is past .dynstr (${strtab.size}B)`);
      let i = at, s = '';
      while (i < poolEnd && buf[i] !== 0) { s += String.fromCharCode(buf[i]); i++; }
      if (i >= poolEnd) refuse(`unterminated DT_NEEDED name at 0x${at.toString(16)}`);
      return s;
    };
    const needed = [];
    for (let o = dyn.offset; o + L.dyn.size <= dyn.offset + dyn.size; o += L.dyn.size) {
      if (o + L.dyn.size > buf.length) refuse(`.dynamic entry at 0x${o.toString(16)} runs past the buffer (${buf.length}B)`);
      // 历史 bug ②：d_tag 必须按 BigInt 比。写成 `=== 1` 时 BigInt 永远不等于 number —— 不崩溃、
      // 不报错，只是把 NEEDED 静默变成空表，一个错得很自信的答复。
      const tag = L.dyn.tagIsBig ? buf.readBigInt64LE(o) : BigInt(buf.readInt32LE(o));
      if (tag === DT_NULL) break;
      if (tag === DT_NEEDED) needed.push(nameAt(readUint(buf, o + L.dyn.val, L.wide, 'DT_NEEDED.d_un')));
    }
    out.needed = needed;
  }

  // ---- strings：total 是真实计数，samples 才是有上限的那一份 ----
  // （这个区分存在，是因为采样上限曾经污染过被上报的总数。）
  const scanEnd = Math.min(buf.length, STRING_SCAN_LIMIT);
  const { total, samples } = extractStrings(buf.subarray(0, scanEnd), 6, SAMPLE_CAP);
  out.stringTotal = total;
  out.stringSamples = samples.length;
  out.stringsPartial = buf.length > scanEnd;                // 只看了前缀就明说
  out.stringsScannedBytes = scanEnd;
  out.ioc = {};
  for (const [k, re] of Object.entries(IOC)) {
    const hits = samples.filter((x) => re.test(x.s));
    out.ioc[k] = hits.length;                               // 计数口径 = 已保留的样本
    out.ioc[`${k}@样本`] = hits.slice(0, IOC_SAMPLE_CAP).map((x) => `0x${x.off.toString(16)}: ${x.s.slice(0, 100)}`);
  }
  return out;
}

/** 已在真模块上验过的前缀名单。只是过滤器，不是判决。 */
const SENSITIVE = /^(p?open|read|write|close|execve|execl|exec[pl]|system|popen|fork|vfork|clone|posix_spawn|socket|connect|bind|listen|accept|send|recv|getaddrinfo|dlopen|dlsym|ptrace|mmap|mprotect|prctl|setns|unshare|chroot|mount|kill|sigaction|ioctl|__system_property_|android_|property_|syscall|unlink|chdir)/;

const IOC = {
  外联: /https?:\/\/|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\.(com|net|org|xyz|top|ru|cn|tk)\b/i,
  root路径: /\/data\/adb|\/data\/system|\/system\/bin|\/proc\/|\/dev\/|\/sys\/fs/,
  root语义: /magisk|kernelsu|sukisu|resetprop|magiskpolicy|setenforce|sepolicy|verifiedbootstate|debuggable/,
  执行: /sh -c|bash -c|busybox|chmod \+x|\/system\/bin\/sh/,
  属性名: /\bro\.[a-z0-9_.]+|persist\.[a-z0-9_.]+/,
};

/**
 * 可打印 ASCII 串（长度 >= min），带**原始 Buffer 里的字节位置** —— 复核者靠这个偏移用肉眼看串，
 * 所以它是真文件偏移，不是样本数组的下标。total 是全文计数；cap 只限制 samples 的长度。
 */
export function extractStrings(buf, min = 6, cap = Infinity) {
  const res = [];
  if (!isBytes(buf)) return { total: 0, samples: res };
  let total = 0, cur = '', start = 0;
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) { if (!cur.length) start = i; cur += String.fromCharCode(c); }
    else {
      if (cur.length >= min) { total++; if (res.length < cap) res.push({ off: start, s: cur }); }
      cur = '';
    }
  }
  if (cur.length >= min) { total++; if (res.length < cap) res.push({ off: start, s: cur }); }
  return { total, samples: res };
}

// ---------------------------------------------------------------------------
// T5.7 §2：危险能力族。
//
// 这张表**只住在这一个文件里**：risk-rules 与 scan 只许消费，不许抄第二份成员表
// （audit/scan.test.mjs 的 T57-07 按源码钉这一格）。族名与成员是工单 §2 那五行，
// 按前缀归族，成员全部来自上面 SENSITIVE 那份名单已经认出来的名字。
//
// 为什么这里只有「链接期事实」：`.dynsym` 里出现过的名字是动态链接器必须满足的集合，
// 出现过就一定用得到 —— 这是静态层唯一能拿到的硬证据。它不等于「会被调用」，更不等于
// 「安全」，所以这张表只用来把 STRUCT_BINARY 往严写，永远不用来放宽任何东西。
//
// 刻意**不算危险族**的：mmap / mprotect / read / write / close / ioctl / syscall
// （以及 open / opendir / readdir / writev / readlink 这些读侧与目录遍历形）。
// §0.8 那条边界是双向的 —— 「导入表干净」不等于安全，反过来「有 mmap」也不等于能执行；
// 把这些收进危险集会把我自己那条论证说反，而且会让每一个正经 .so 都亮灯（那种判据没有信息量）。
//
// 纯函数、确定性：输入是字符串数组，输出按族名排序、族内符号排序、族内代表符号封顶
// REPRESENTATIVE_CAP 个（总数另放在 symbolTotal 里，静默截断是不许的）。
// 空数组、非数组、未知名、大小写混写都必须有确定输出 —— 匹配时统一转小写，
// 所以 `FORK` / `fork` / `Fork` 归到同一族且去重成一条。
// ---------------------------------------------------------------------------

/** 族内代表符号的上限（工单 §2 第四、五行：「每族至多 5 个」）。 */
const REPRESENTATIVE_CAP = 5;

/** [族名, 人读标签, 前缀成员表]。前缀按 §2 那一行逐字落地，别用「差不多是」的正则。 */
const CAPABILITY_FAMILIES = [
  ['EXEC', '起新程序/运行时加载',
    ['exec', 'system', 'popen', 'fork', 'vfork', 'clone', 'posix_spawn', 'dlopen', 'dlsym']],
  ['NET', '网络收发',
    ['socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv', 'getaddrinfo']],
  ['NS', '命名空间与进程逃逸',
    ['setns', 'unshare', 'chroot', 'mount', 'pivot_root', 'ptrace', 'kill', 'sigaction', 'prctl']],
  ['PROP', '系统属性读写',
    ['__system_property_', 'android_', 'property_']],
  ['FILEWRITE', '文件写出与改名',
    ['unlink', 'rename', 'truncate', 'ftruncate', 'mkdir', 'rmdir', 'chdir']],
];

/**
 * 逐族展开：返回 [{family, label, symbols(≤5，已排序), symbolTotal}]，按族名排序。
 * @param {string[]} sensitiveImports forensics() 的 sensitiveImports（也可以喂任意名字数组）
 */
export function capabilitySymbols(sensitiveImports) {
  const names = Array.isArray(sensitiveImports)
    ? sensitiveImports.filter((x) => typeof x === 'string' && x.length > 0)
    : [];
  const out = [];
  for (const [family, label, prefixes] of CAPABILITY_FAMILIES) {
    const uniq = [...new Set(names.filter((s) => {
      const low = s.toLowerCase();
      return prefixes.some((p) => low.startsWith(p));
    }))].sort();
    if (uniq.length > 0) {
      out.push({ family, label, symbols: uniq.slice(0, REPRESENTATIVE_CAP), symbolTotal: uniq.length });
    }
  }
  return out.sort((a, b) => (a.family < b.family ? -1 : a.family > b.family ? 1 : 0));
}

/**
 * 族名集合（去重 + 排序）。危险族**数量**是唯一的升档依据：≥2 类才升 high。
 * @param {string[]} sensitiveImports
 * @returns {string[]} 例如 ['EXEC','FILEWRITE','NET','NS']；什么都落不到时 []
 */
export function capabilityFamilies(sensitiveImports) {
  return capabilitySymbols(sensitiveImports).map((x) => x.family);
}
