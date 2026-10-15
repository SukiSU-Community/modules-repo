// audit/elf-forensics.mjs 的回归测试。
//
// 这个文件存在的理由只有一条：scan.mjs 拿 `bytes.toString('utf8')` 当正文，二进制进去之后
// 983,624 B 会变成 1,530,819 B、84.3% 的字节位置被改写 —— 从那种 content 里解析任何东西都会
// 给出**自信的错误答案**。所以这里只喂原始 Buffer，并且把"错也错得显眼"当验收标准：
// 读不出来必须是 parseError，绝不能是一个看起来合理的 0。
//
// 两条纪律写死在测试里：
//   ① 两个真修过的 bug（e_shstrndx 读成 8 字节偏移、d_tag 用 === 1 比）各有一条会红的钉子；
//   ② 32 位的结论不许只靠"手写解析器自己说对" —— 每条都要跟一条**结构上完全不同**的路
//      （程序头表 + DT_* 动态项，完全不碰 e_shstrndx/sh_link/sh_offset）互相印证。
//
// 运行：node --test（仓库根，CI 形态）。测试期只读 audit/fixtures/。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { forensics, elfPeek, extractStrings } from './elf-forensics.mjs';

const FIXDIR = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const fix = (n) => readFileSync(join(FIXDIR, n));

const SCAN_LIMIT = 8 * 1024 * 1024;
const SENSITIVE = /^(p?open|read|write|close|execve|execl|exec[pl]|system|popen|fork|vfork|clone|posix_spawn|socket|connect|bind|listen|accept|send|recv|getaddrinfo|dlopen|dlsym|ptrace|mmap|mprotect|prctl|setns|unshare|chroot|mount|kill|sigaction|ioctl|__system_property_|android_|property_|syscall|unlink|chdir)/;
const LIBS = ['liblog.so', 'libc.so'];

//----------------------------------------------------------------------------
// A. 独立定位路径（测试自己写的，与被测实现结构不同）
//----------------------------------------------------------------------------

/**
 * 只用**程序头表**和 .dynamic 里的 DT_* 项把 .dynsym / .dynstr 找出来：
 *   PT_DYNAMIC -> 动态表；DT_STRTAB/DT_SYMTAB 给虚拟地址；PT_LOAD 换成文件偏移；
 *   DT_HASH 的 nchain（或退化版 DT_GNU_HASH：所有桶为 0 时 nchain==symndx）给条目数。
 * 全程不读 e_shstrndx、不读任何节头 —— 跟被测实现没有共享的失败模式。
 * 定不出条目数时 nchain 是 null，调用方必须显式处理，不许当成 0。
 */
function independentElf(b) {
  const is64 = b[4] === 2;
  assert.ok(b[4] === 1 || is64, '夹具必须是 ELFCLASS32/64');
  assert.equal(b[5], 1, '夹具必须是小端');
  const H = is64
    ? { symsz: 24, dynsz: 16, pent: 56, phoff: Number(b.readBigUInt64LE(0x20)), phentsize: b.readUInt16LE(0x36), phnum: b.readUInt16LE(0x38) }
    : { symsz: 16, dynsz: 8, pent: 32, phoff: b.readUInt32LE(0x1c), phentsize: b.readUInt16LE(0x2a), phnum: b.readUInt16LE(0x2c) };
  assert.equal(H.phentsize, H.pent, 'e_phentsize 应当等于 sizeof(ElfW(Phdr))，否则夹具读法有问题');

  const loads = [];
  let dynOff = null, dynSize = null;
  for (let i = 0; i < H.phnum; i++) {
    const p = H.phoff + i * H.pent;
    const ptype = b.readUInt32LE(p);
    const off = is64 ? Number(b.readBigUInt64LE(p + 8)) : b.readUInt32LE(p + 4);
    const va = is64 ? Number(b.readBigUInt64LE(p + 0x10)) : b.readUInt32LE(p + 8);
    const filesz = is64 ? Number(b.readBigUInt64LE(p + 0x20)) : b.readUInt32LE(p + 0x10);
    if (ptype === 1) loads.push({ off, va, filesz });
    else if (ptype === 2) { dynOff = off; dynSize = filesz; }
  }
  assert.ok(dynOff != null, '夹具里必须有 PT_DYNAMIC');
  const v2o = (va) => {
    for (const l of loads) if (l.filesz > 0 && va >= l.va && va < l.va + l.filesz) return va - l.va + l.off;
    return null;
  };

  const D = { strtab: null, symtab: null, strsz: null, hash: null, gnuhash: null };
  const neededOff = [];
  for (let o = dynOff; o + H.dynsz <= dynOff + dynSize; o += H.dynsz) {
    const t = is64 ? b.readBigInt64LE(o) : BigInt(b.readInt32LE(o));   // d_tag 也是 BigInt 比
    const v = is64 ? Number(b.readBigUInt64LE(o + 8)) : b.readUInt32LE(o + 4);
    if (t === 0n) break;                                     // DT_NULL
    if (t === 1n) neededOff.push(v);                         // DT_NEEDED
    else if (t === 4n) D.hash = v;
    else if (t === 5n) D.strtab = v;
    else if (t === 6n) D.symtab = v;
    else if (t === 10n) D.strsz = v;
    else if (t === 0x6ffffef5n) D.gnuhash = v;
  }
  const strOff = v2o(D.strtab), symOff = v2o(D.symtab);
  assert.ok(strOff != null && symOff != null && D.strsz != null, 'DT_STRTAB/DT_SYMTAB/DT_STRSZ 必须都能换成文件偏移');

  let nchain = null;
  if (D.hash != null) {
    const ho = v2o(D.hash);
    if (ho != null) nchain = b.readUInt32LE(ho + 4);         // Hash { nbuckets; nchain }
  } else if (D.gnuhash != null) {
    const go = v2o(D.gnuhash);
    const nbuckets = b.readUInt32LE(go), symndx = b.readUInt32LE(go + 4), maskwords = b.readUInt32LE(go + 8);
    const bucketAt = go + 16 + maskwords * (is64 ? 8 : 4);
    let anyBucket = false;
    for (let i = 0; i < nbuckets; i++) if (b.readUInt32LE(bucketAt + i * 4) !== 0) anyBucket = true;
    // 只有"无链可走"（桶全 0）时才能不依赖链尾哨兵位就把数定准。实测有链时 lld 不置哨兵位，
    // 靠走链定边界不可靠 —— 定不下来就 null，不猜。
    if (!anyBucket) nchain = symndx;
  }

  const poolBytes = b.subarray(strOff, strOff + D.strsz);
  const poolText = poolBytes.toString('latin1');
  const tokens = new Set(poolText.split('\0').filter(Boolean));
  const cstr = (strOffInPool) => poolText.slice(strOffInPool, poolText.indexOf('\0', strOffInPool) < 0 ? undefined : poolText.indexOf('\0', strOffInPool));

  const undNames = [];
  if (nchain != null) {
    for (let i = 0; i < nchain; i++) {
      const e = symOff + i * H.symsz;
      if (e + H.symsz > b.length) { nchain = null; break; }
      const stName = b.readUInt32LE(e);
      const stShndx = is64 ? b.readUInt16LE(e + 6) : b.readUInt16LE(e + 0xe);
      if (stShndx !== 0 || stName === 0 || stName >= D.strsz) continue;   // UND 且有名字才算导入
      const nm = cstr(stName);
      if (nm) undNames.push(nm);
    }
  }
  return { strOff, strsz: D.strsz, symOff, nchain, poolBytes, tokens, undNames, needed: neededOff.map(cstr) };
}

/** 整块 buffer 按 0x00 切片得到的可打印 ASCII 片段 —— 第三条与上面两条都不相干的路。 */
function rawNulTokens(b) {
  const set = new Set();
  let start = 0;
  for (let i = 0; i < b.length; i++) {
    if (b[i] !== 0) continue;
    const piece = b.subarray(start, i);
    if (piece.length && [...piece].every((c) => c >= 0x20 && c < 0x7f)) set.add(piece.toString('latin1'));
    start = i + 1;
  }
  return set;
}

//----------------------------------------------------------------------------
// B. 手搓 ELF32：32 位路径的边角只能这么测
//----------------------------------------------------------------------------

/**
 * 按被测实现承诺的 ELF32 布局逐字节写出来：
 *   e_ident[EI_CLASS]=1 / [EI_DATA]=1；e_type u16@0x10；e_machine u16@0x12；
 *   e_shoff u32@0x20；e_shentsize u16@0x2e；e_shnum u16@0x30；e_shstrndx u16@0x32；
 *   Elf32_Shdr=40B（sh_name@0 sh_type@4 sh_offset@0x10 sh_size@0x14 sh_link@0x18）；
 *   Elf32_Sym=16B（st_name@0 st_shndx@0xe）；Elf32_Dyn=8B（d_tag i32@0 d_un u32@4）。
 * dyns 支持 { tag: 1, name: 'libc.so' } —— 池内偏移由本函数自己算，测试不抄偏移。
 */
function buildElf32({
  machine = 40, type = 3, cls = 1, data = 1,
  syms = [],                 // [{ name, shndx }]
  dyns = [],                 // [{ tag, name|val }]，DT_NULL 由 withNullDyn 决定
  libs = LIBS,
  strNames = [],
  shentsize = 40,
  shstrndx,                  // 只改头部字段，不改真实节数（越界用例靠这个）
  dynsymSize,                // 覆盖 .dynsym 的 sh_size（越界用例靠这个）
  withNullSym = true,        // 符号表第 0 项恒为 null 符号
  withNullDyn = true,
  addSymtab = false,
} = {}) {
  // ---- .dynstr ----
  const pool = [''];
  for (const n of [...libs, ...syms.map((s) => s.name), ...strNames]) if (n && !pool.includes(n)) pool.push(n);
  const so = { '': 0 };
  let cur = 1;
  for (let i = 1; i < pool.length; i++) { so[pool[i]] = cur; cur += pool[i].length + 1; }
  const dynstr = Buffer.alloc(cur);
  for (const n of pool) if (n) dynstr.write(n, so[n], 'latin1');

  // ---- .dynsym ----
  const symList = withNullSym ? [{ name: '', shndx: 0 }, ...syms] : syms;
  const dynsym = Buffer.alloc(symList.length * 16);
  symList.forEach((s, i) => {
    dynsym.writeUInt32LE(so[s.name] ?? 0, i * 16);
    dynsym[i * 16 + 12] = 0x12;                             // st_info = GLOBAL|FUNC
    dynsym.writeUInt16LE(s.shndx, i * 16 + 0xe);
  });

  // ---- .dynamic ----
  const rows = dyns.slice();
  const dynbuf = Buffer.alloc((rows.length + (withNullDyn ? 1 : 0)) * 8);
  rows.forEach((d, i) => {
    dynbuf.writeInt32LE(d.tag, i * 8);
    dynbuf.writeUInt32LE(d.name != null ? so[d.name] : d.val, i * 8 + 4);
  });
  if (withNullDyn) dynbuf.writeInt32LE(0, rows.length * 8);

  // ---- .shstrtab ----
  const secNames = ['', '.dynsym', '.dynstr', '.dynamic', ...(addSymtab ? ['.symtab'] : []), '.shstrtab'];
  const secOffs = {};
  let scur = 1;
  for (let i = 1; i < secNames.length; i++) { secOffs[secNames[i]] = scur; scur += secNames[i].length + 1; }
  const shstrtab = Buffer.alloc(scur);
  for (let i = 1; i < secNames.length; i++) shstrtab.write(secNames[i], secOffs[secNames[i]], 'latin1');

  // ---- 排布：header | .dynstr | .dynsym | .dynamic | .shstrtab | 节头表 ----
  const align4 = (n) => Math.ceil(n / 4) * 4;
  const offStr = 52;
  const offSym = offStr + align4(dynstr.length);
  const offDyn = offSym + align4(dynsym.length);
  const offShstr = offDyn + align4(dynbuf.length);
  const secTab = offShstr + align4(shstrtab.length);
  const shnum = secNames.length;
  const b = Buffer.alloc(secTab + shnum * shentsize);

  b[0] = 0x7f; b[1] = 0x45; b[2] = 0x4c; b[3] = 0x46;
  b[4] = cls; b[5] = data; b[6] = 1;
  b.writeUInt16LE(type, 0x10);
  b.writeUInt16LE(machine, 0x12);
  b.writeUInt32LE(1, 0x14);                                  // e_version
  b.writeUInt32LE(0, 0x1c);                                  // e_phoff=0：本模块不许依赖程序头
  b.writeUInt32LE(secTab, 0x20);                             // e_shoff
  b.writeUInt16LE(shentsize, 0x2e);
  b.writeUInt16LE(shnum, 0x30);
  b.writeUInt16LE(shstrndx ?? shnum - 1, 0x32);

  dynstr.copy(b, offStr);
  dynsym.copy(b, offSym);
  dynbuf.copy(b, offDyn);
  shstrtab.copy(b, offShstr);

  const idx = Object.fromEntries(secNames.map((n, i) => [n, i]));
  const put = (name, stype, offset, size, link) => {
    const o = secTab + idx[name] * shentsize;
    b.writeUInt32LE(secOffs[name], o);
    b.writeUInt32LE(stype, o + 4);
    b.writeUInt32LE(offset, o + 0x10);
    b.writeUInt32LE(size, o + 0x14);
    b.writeUInt32LE(link, o + 0x18);
  };
  put('.dynsym', 11, offSym, dynsymSize ?? dynsym.length, idx['.dynstr']);
  put('.dynstr', 3, offStr, dynstr.length, 0);
  put('.dynamic', 6, offDyn, dynbuf.length, idx['.dynstr']);
  if (addSymtab) put('.symtab', 2, offSym, dynsym.length, idx['.shstrtab']);
  put('.shstrtab', 3, offShstr, shstrtab.length, 0);
  return b;
}

//----------------------------------------------------------------------------
// C. 两个真修过的 bug：各一条钉子
//----------------------------------------------------------------------------

test('bug#1：e_shstrndx 是 0x3e 处的 2 字节**下标**；读成 8 字节偏移会让 .dynsym 看起来不存在', () => {
  const b = fix('arm64-v8a.so');
  const h = elfPeek(b);
  assert.equal(h.shstrndx, 21, '0x3e 处的 u16 —— 它是下标，正指向最后一个节');
  assert.equal(h.shnum, 22);
  assert.equal(h.shentsize, 64);
  assert.ok(h.shstrndx < h.shnum);
  // 同一串字节按"偏移"读会得到什么：必须越界，否则这条钉子没有鉴别力。
  assert.ok(Number(b.readBigUInt64LE(0x3e)) >= h.shnum, '当 8 字节偏移读 → 越界值');
  assert.ok(b.readUInt32LE(0x32) >= h.shnum, '当 4 字节字段读（0x32）→ 也越界');

  const out = forensics(b, 'arm64-v8a.so');
  assert.equal(out.parseError, undefined, `解析必须成功：${out.parseError}`);
  // 下标读错时节名会变乱码，看上去像"这个 .so 没有 .dynsym" —— 那正是当年那条假结论。
  assert.ok(out.sections.includes('.dynsym'), '.dynsym 必须被找到');
  assert.equal(out.sections.at(-1), '.shstrtab');
  assert.equal(out.importCount, 86);
});

test('bug#2：d_tag 必须按 BigInt 比（=== 1n）；=== 1 不报错，只把 NEEDED 静默变空表', () => {
  const want = {
    'arm64-v8a.so': ['libdl.so', 'libc.so'],
    'hma-arm64.so': ['liblog.so', 'libm.so', 'libdl.so', 'libc.so'],
    'hma-armeabi-v7a.so': ['liblog.so', 'libm.so', 'libdl.so', 'libc.so'],
    'hma-x86.so': ['liblog.so', 'libm.so', 'libdl.so', 'libc.so'],
    'detach-arm32': ['libdl.so', 'libc.so'],
    'device_faker_cli': ['libdl.so', 'libc.so'],
  };
  for (const [f, list] of Object.entries(want)) {
    const out = forensics(fix(f), f);
    assert.equal(out.parseError, undefined, `${f}：${out.parseError}`);
    assert.ok(out.needed.length > 0, `${f}：NEEDED 为空就是 d_tag 退化成 === 1 的症状`);
    assert.deepEqual(out.needed, list, `${f} 的 DT_NEEDED 列表`);
  }
});

//----------------------------------------------------------------------------
// D. 64 位夹具锚点
//----------------------------------------------------------------------------

test('ELF64 锚点：arm64-v8a.so（983,624 B）逐项钉住', () => {
  const out = forensics(fix('arm64-v8a.so'), 'arm64-v8a.so');
  assert.equal(out.name, 'arm64-v8a.so');
  assert.equal(out.kind, 'ELF');
  assert.equal(out.bytes, 983624);
  assert.equal(out.machineName, 'AArch64');
  assert.equal(out.type, 'DYN');
  assert.equal(out.importCount, 86);
  assert.equal(out.stripped, true);
  assert.deepEqual(out.needed, ['libdl.so', 'libc.so']);
  assert.equal(out.stringTotal, 1373);
  assert.deepEqual(out.sensitiveImports, [
    'chdir', 'chroot', 'close', 'dlsym', 'fork', 'ioctl', 'kill', 'mmap', 'mmap64', 'mprotect',
    'open', 'prctl', 'read', 'readlink', 'recv', 'send', 'sigaction', 'syscall', 'unlink', 'write', 'writev',
  ]);
  assert.equal(out.stringsPartial, false);
});

test('ELF64 锚点：device_faker_cli 的 importCount/stringTotal 与那条读属性导入', () => {
  const out = forensics(fix('device_faker_cli'), 'device_faker_cli');
  assert.equal(out.bytes, 485944);
  assert.equal(out.machineName, 'AArch64');
  assert.equal(out.importCount, 70);
  assert.equal(out.stringTotal, 600);
  assert.ok(out.sensitiveImports.includes('__system_property_get'));
  assert.equal(out.stripped, true);
});

test('ELF64 锚点：hma-arm64.so 的 sensitiveImports 是精确集合', () => {
  const out = forensics(fix('hma-arm64.so'), 'hma-arm64.so');
  assert.equal(out.importCount, 24);
  assert.deepEqual(out.sensitiveImports, ['close', 'closedir', 'mmap', 'readdir64']);
  assert.deepEqual(out.needed, ['liblog.so', 'libm.so', 'libdl.so', 'libc.so']);
  assert.equal(out.stringTotal, 87);
});

//----------------------------------------------------------------------------
// E. 32 位：先差分印证，再钉数
//----------------------------------------------------------------------------

const ARM32 = {
  'hma-armeabi-v7a.so': { bytes: 9232, machineName: 'ARM', type: 'DYN', importCount: 25, stringTotal: 120, needed: ['liblog.so', 'libm.so', 'libdl.so', 'libc.so'], sensitiveImports: ['close', 'closedir', 'mmap', 'readdir64'] },
  'hma-x86.so': { bytes: 13456, machineName: 'x86', type: 'DYN', importCount: 24, stringTotal: 88, needed: ['liblog.so', 'libm.so', 'libdl.so', 'libc.so'], sensitiveImports: ['close', 'closedir', 'mmap', 'readdir64'] },
  'detach-arm32': { bytes: 118380, machineName: 'ARM', type: 'DYN', importCount: 62, stringTotal: 462, needed: ['libdl.so', 'libc.so'], sensitiveImports: ['chdir', 'chroot', 'close', 'closedir', 'dlsym', 'fork', 'ioctl', 'kill', 'open', 'opendir', 'read', 'readdir', 'sendfile', 'sigaction', 'syscall', 'unlink', 'write', 'writev'] },
};
const ALL6 = [...Object.keys(ARM32), 'arm64-v8a.so', 'device_faker_cli', 'hma-arm64.so'];

test('ELF32：三个 32 位夹具不再"读不出来"，而是给出完整事实（派生值钉住）', () => {
  for (const [f, want] of Object.entries(ARM32)) {
    const out = forensics(fix(f), f);
    assert.equal(out.parseError, undefined, `${f} 必须解析成功：${out.parseError}`);
    assert.equal(out.kind, 'ELF');
    assert.equal(out.name, f);
    assert.equal(out.bytes, want.bytes);
    assert.equal(out.machineName, want.machineName);
    assert.equal(out.type, want.type);
    assert.equal(out.importCount, want.importCount, `${f} importCount`);
    assert.deepEqual(out.needed, want.needed, `${f} needed`);
    assert.deepEqual(out.sensitiveImports, want.sensitiveImports, `${f} sensitiveImports`);
    assert.equal(out.stringTotal, want.stringTotal, `${f} stringTotal`);
    assert.equal(out.stripped, true);
    assert.ok(out.sections.includes('.dynsym') && out.sections.includes('.dynamic'), `${f} 节名必须可读`);
  }
});

test('ELF32 差分①：报告里每个符号名都逐字存在于独立定位的字节区，且是原文里完整的 NUL 片段', () => {
  for (const f of ALL6) {
    const b = fix(f);
    const out = forensics(b, f);
    assert.equal(out.parseError, undefined, `${f}：${out.parseError}`);
    const indep = independentElf(b);
    const reported = [...out.sensitiveImports, ...out.needed];
    assert.ok(reported.length > 0, `${f} 至少要有可核对的名字`);
    const raw = rawNulTokens(b);
    for (const n of reported) {
      assert.ok(indep.tokens.has(n), `${f}：报告的名字 "${n}" 不在独立定位的 .dynstr 里`);
      assert.ok(indep.poolBytes.includes(Buffer.from(`${n}\0`, 'latin1')), `${f}：${n} 没在池字节里逐字出现`);
      assert.ok(raw.has(n), `${f}：${n} 不是原文里一个完整的 NUL 分隔片段`);
    }
  }
});

test('ELF32 差分②：importCount == 第二条结构不同回路数出的 UND 条目数', () => {
  const bounded = [];
  for (const f of ALL6) {
    const b = fix(f);
    const out = forensics(b, f);
    const indep = independentElf(b);
    if (indep.nchain == null) {
      // arm64-v8a.so 只有 DT_GNU_HASH、且桶里有链；lld 没置链尾哨兵位，独立路定不出边界。
      assert.equal(f, 'arm64-v8a.so', `${f}：独立路定不出符号表边界是意外，必须查`);
      assert.ok(indep.undNames.length === 0);
      continue;
    }
    bounded.push(f);
    assert.equal(out.importCount, indep.undNames.length, `${f}：两条路的 UND 计数不一致`);
    assert.equal(new Set(indep.undNames).size, indep.undNames.length, `${f}：独立路出现重名，边界可能走过头`);
    assert.deepEqual(out.sensitiveImports, [...new Set(indep.undNames.filter((x) => SENSITIVE.test(x)))].sort(), `${f}：敏感子集不一致`);
    assert.deepEqual(out.needed, indep.needed, `${f}：DT_NEEDED 与独立动态表解析不一致`);
    assert.ok(indep.symOff > 0 && indep.strOff > indep.symOff, `${f}：两条路定位到的表应当在同一区域`);
  }
  assert.deepEqual(bounded.sort(), ['detach-arm32', 'device_faker_cli', 'hma-arm64.so', 'hma-armeabi-v7a.so', 'hma-x86.so']);
});

test('ELF32：同一个模块的三种 ABI 给出同族结论（能不能看见不该由 ABI 决定）', () => {
  const a = forensics(fix('hma-arm64.so'), 'hma-arm64.so');
  const v7 = forensics(fix('hma-armeabi-v7a.so'), 'hma-armeabi-v7a.so');
  const x86 = forensics(fix('hma-x86.so'), 'hma-x86.so');
  assert.deepEqual(v7.sensitiveImports, a.sensitiveImports);
  assert.deepEqual(x86.sensitiveImports, a.sensitiveImports);
  assert.deepEqual(v7.needed, a.needed);
  assert.deepEqual(x86.needed, a.needed);
  assert.ok(Math.abs(v7.importCount - a.importCount) <= 2 && Math.abs(x86.importCount - a.importCount) <= 2);
  assert.equal(a.machineName, 'AArch64');
  assert.equal(v7.machineName, 'ARM');
  assert.equal(x86.machineName, 'x86');
});

//----------------------------------------------------------------------------
// F. 拒答：parseError，不抛、不给 0
//----------------------------------------------------------------------------

test('parseError：截断的 Buffer —— 必须是 parseError，绝不能是 importCount: 0', () => {
  const b = fix('arm64-v8a.so');
  for (const cut of [512, 4096, b.length - 1]) {
    const out = forensics(b.subarray(0, cut), 'truncated');
    assert.equal(out.kind, 'ELF');
    assert.ok(out.parseError, `前 ${cut}B 必须给出 parseError`);
    assert.ok(!('importCount' in out), 'parseError 的输出里不许出现 importCount —— 0 会被读成"这个二进制什么都不导入"');
    assert.ok(!('stringTotal' in out), '同理不许出现 stringTotal');
    assert.ok(!('sensitiveImports' in out));
    assert.ok(!('needed' in out));
  }
  const tiny = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  const out = forensics(tiny, 'tiny');
  assert.ok(out.parseError && !('importCount' in out), '连头部都不完整的必须拒');
});

test('parseError：大端 EI_DATA 直接拒，不按小端硬读', () => {
  for (const f of ['arm64-v8a.so', 'hma-armeabi-v7a.so']) {
    const b = Buffer.from(fix(f));
    b[5] = 2;                                                // ELFDATA2MSB
    const out = forensics(b, `${f}:be`);
    assert.equal(out.kind, 'ELF');
    assert.ok(out.parseError, '大端必须 parseError');
    assert.match(out.parseError, /EI_DATA|大端|endian/i);
    assert.ok(!('importCount' in out));
    assert.equal(elfPeek(b), null, 'elfPeek 对不支持的输入给 null，不给半截头部');
  }
});

test('parseError：未知 EI_CLASS 拒', () => {
  const b = Buffer.from(fix('arm64-v8a.so'));
  b[4] = 3;
  const out = forensics(b, 'bad-class');
  assert.ok(out.parseError && !('importCount' in out));
  assert.equal(elfPeek(b), null);
});

test('parseError：e_shstrndx >= e_shnum 拒', () => {
  const base = { syms: [{ name: 'open', shndx: 0 }], dyns: LIBS.map((n) => ({ tag: 1, name: n })) };
  for (const over of [99, 255]) {
    const out = forensics(buildElf32({ ...base, shstrndx: over }), `shstrndx-${over}`);
    assert.ok(out.parseError, `e_shstrndx=${over} 必须拒`);
    assert.match(out.parseError, /shstrndx|shnum/);
    assert.ok(!('importCount' in out));
  }
  const b = Buffer.from(fix('hma-armeabi-v7a.so'));
  b.writeUInt16LE(99, 0x32);                                 // 真字节上只改这一个字段
  const out2 = forensics(b, 'hma-armeabi-v7a.so:bad-ndx');
  assert.ok(out2.parseError && !('importCount' in out2));
});

test('parseError：sh_offset + sh_size 越过缓冲区末尾拒', () => {
  const base = { syms: [{ name: 'open', shndx: 0 }], dyns: LIBS.map((n) => ({ tag: 1, name: n })) };
  assert.equal(forensics(buildElf32(base), 'ok').importCount, 1, '先确认基线能解析');
  const out = forensics(buildElf32({ ...base, dynsymSize: 1 << 20 }), 'dynsym-overrun');
  assert.ok(out.parseError, `越界必须是 parseError：${JSON.stringify(out)}`);
  assert.ok(!('importCount' in out), '越界时不许给"读到几个算几个"的自信数字');
});

test('parseError：e_shentsize 48 拒（只接受 40 / 64）', () => {
  const out = forensics(buildElf32({
    syms: [{ name: 'open', shndx: 0 }],
    dyns: LIBS.map((n) => ({ tag: 1, name: n })),
    shentsize: 48,
  }), 'shentsize-48');
  assert.ok(out.parseError, 'e_shentsize=48 必须拒');
  assert.match(out.parseError, /shentsize/);
  assert.ok(!('importCount' in out));
});

test('parseError：畸形一律拒答，绝不抛 —— 扫描器要能继续跑', () => {
  const b = fix('arm64-v8a.so');
  const cases = {
    'empty': Buffer.alloc(0),
    'short': Buffer.alloc(4, 0x7f),
    'zeros': Buffer.alloc(4096),
    'ffs': Buffer.alloc(4096, 0xff),
    'magic-only': Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(200)]),
    'truncated-head': b.subarray(0, 64),
    'middle-slice': b.subarray(1000, 100000),
    'huge-shoff': (() => { const x = Buffer.from(b); x.writeBigUInt64LE(1n << 48n, 0x28); return x; })(),
    'huge-shnum': (() => { const x = Buffer.from(b); x.writeUInt16LE(65535, 0x3c); return x; })(),
    'shentsize-0': (() => { const x = Buffer.from(b); x.writeUInt16LE(0, 0x3a); return x; })(),
    'utf8-poisoned': Buffer.from(b.toString('utf8'), 'utf8'),
    'string-input': b.toString('utf8'),
  };
  for (const [k, buf] of Object.entries(cases)) {
    let out;
    assert.doesNotThrow(() => { out = forensics(buf, k); }, `case ${k} 抛异常了`);
    if (out === null) continue;                              // 非 ELF：明说"不在射程内"，也不算猜
    assert.ok(out.parseError, `case ${k} 必须 parseError，实际 ${JSON.stringify(out).slice(0, 140)}`);
    assert.ok(!('importCount' in out), `case ${k} parseError 时不许带 importCount`);
  }
});

//----------------------------------------------------------------------------
// G. 合成 ELF32 的边角
//----------------------------------------------------------------------------

test('合成 ELF32：导入表、NEEDED、敏感子集逐字命中', () => {
  const b = buildElf32({
    syms: [
      { name: 'exit', shndx: 0 },
      { name: 'open', shndx: 0 },
      { name: 'ptrace', shndx: 0 },
      { name: '__system_property_get', shndx: 0 },
      { name: 'my_local_fn', shndx: 1 },                     // 有定义的符号：不算导入
    ],
    dyns: [{ tag: 5, val: 0 }, ...LIBS.map((n) => ({ tag: 1, name: n })), { tag: 0, val: 0 }],
  });
  const out = forensics(b, 'synth32');
  assert.equal(out.parseError, undefined, out.parseError);
  assert.equal(out.kind, 'ELF');
  assert.equal(out.bytes, b.length);
  assert.equal(out.machineName, 'ARM');
  assert.equal(out.importCount, 4, '只数 st_shndx==0 且有名字的条目；第 0 项 null 符号与 shndx=1 都不许进');
  assert.deepEqual(out.sensitiveImports, ['__system_property_get', 'open', 'ptrace'], 'exit 不在 SENSITIVE 前缀表里');
  assert.deepEqual(out.needed, LIBS, 'tag 5（DT_STRTAB）不许被当成 DT_NEEDED');
  assert.equal(out.stripped, true, '没有 .symtab == 作者 strip 过');
  assert.deepEqual(out.sections, ['.dynsym', '.dynstr', '.dynamic', '.shstrtab']);
});

test('合成 ELF32：空 .dynsym 是 0 导入，不是 parseError', () => {
  const out = forensics(buildElf32({ syms: [], dyns: [], withNullSym: false }), 'synth32-empty');
  assert.equal(out.parseError, undefined, out.parseError);
  assert.equal(out.importCount, 0);
  assert.deepEqual(out.sensitiveImports, []);
  assert.deepEqual(out.needed, []);
  assert.ok(out.sections.includes('.dynsym'), '空表是"真的没有导入"，节名要能证明读过 .dynsym');
});

test('合成 ELF32：.dynamic 必须在 DT_NULL 处收口，之后的 DT_NEEDED 不许进表', () => {
  const out = forensics(buildElf32({
    syms: [{ name: 'open', shndx: 0 }],
    libs: [...LIBS, 'libafternull.so'],
    dyns: [
      { tag: 1, name: LIBS[0] },
      { tag: 0, name: undefined, val: 0 },                   // DT_NULL
      { tag: 1, name: 'libafternull.so' },                  // DT_NULL 之后埋一条
    ],
    withNullDyn: false,
  }), 'synth32-dtnull');
  assert.deepEqual(out.needed, [LIBS[0]], 'DT_NULL 之后是未初始化区，读了就是编故事');
  assert.ok(!out.needed.includes('libafternull.so'));
});

test('合成 ELF32：.symtab 在场时 stripped 必须是 false', () => {
  const out = forensics(buildElf32({ syms: [{ name: 'open', shndx: 0 }], dyns: [], addSymtab: true }), 'synth32-symtab');
  assert.equal(out.stripped, false);
  assert.ok(out.sections.includes('.symtab'));
});

test('合成 ELF32：e_shentsize 64 也接受（步长 64，字段仍按 Elf32_Shdr）', () => {
  const out = forensics(buildElf32({ syms: [{ name: 'open', shndx: 0 }], dyns: [], shentsize: 64 }), 'synth32-shentsize64');
  assert.equal(out.parseError, undefined, out.parseError);
  assert.equal(out.importCount, 1);
  assert.deepEqual(out.sensitiveImports, ['open']);
});

test('合成 ELF32：机器码名表与未知机器码的写法', () => {
  for (const [m, want] of Object.entries({ 183: 'AArch64', 40: 'ARM', 3: 'x86', 62: 'x86-64', 243: 'RISC-V' })) {
    const out = forensics(buildElf32({ machine: Number(m), syms: [{ name: 'open', shndx: 0 }], dyns: [] }), `m${m}`);
    assert.equal(out.machineName, want);
  }
  assert.equal(forensics(buildElf32({ machine: 21, syms: [{ name: 'open', shndx: 0 }], dyns: [] }), 'm21').machineName, '#21');
});

test('elfPeek / forensics：非 ELF 一律 null（zip 头不能被判成 ELF）', () => {
  assert.equal(elfPeek(Buffer.from([0x50, 0x4b, 3, 4, ...new Array(60).fill(0)])), null);
  assert.equal(elfPeek(Buffer.alloc(0)), null);
  assert.equal(elfPeek(Buffer.alloc(64)), null);
  assert.equal(elfPeek(null), null);
  assert.equal(forensics(Buffer.from('%PDF-1.4 fake'), 'not-elf'), null);
  assert.equal(forensics(Buffer.from([0x50, 0x4b, 3, 4, ...new Array(60).fill(0)]), 'module.zip'), null);
  const h = elfPeek(fix('hma-armeabi-v7a.so'));
  assert.equal(h.class, 32);
  assert.equal(h.machineName, 'ARM');
  assert.equal(h.shentsize, 40);
  assert.equal(h.shstrndx, 25);
});

//----------------------------------------------------------------------------
// H. strings：总数与样本数必须分开
//----------------------------------------------------------------------------

test('stringTotal 是全文计数，samples 才有上限 —— 两个数不许混', () => {
  // 已知条数：20 条 6 字符 + 20 条 7 字符 + 1 条 5 字符（不该算）= 40 条 >=6 的串。
  const parts = [];
  for (let i = 0; i < 20; i++) parts.push('A'.repeat(6), '\0');
  for (let i = 0; i < 20; i++) parts.push('B'.repeat(7), '\0');
  parts.push('CCCCC', '\0');
  const known = Buffer.from(parts.join(''), 'latin1');
  const capped = extractStrings(known, 6, 5);
  assert.equal(capped.total, 40, '已知条数：total 必须是全文真实计数');
  assert.equal(capped.samples.length, 5, 'cap 只限制样本条数');
  assert.ok(capped.total > capped.samples.length, '总数 != 样本数');
  assert.equal(extractStrings(known, 6, Infinity).total, 40, 'cap 不许改变 total');
  assert.equal(extractStrings(known, 7, Infinity).total, 20, 'min 才改计数：7 字符起只剩 B 那 20 条');
  assert.equal(extractStrings(known, 8, Infinity).total, 0, '没有 8 字符的串就是 0，不是"少算"');

  // 混进真 ELF 之后：上报的总数仍是整块的真实计数，内部采样上限不许把它压小。
  const merged = Buffer.concat([buildElf32({ syms: [{ name: 'open', shndx: 0 }], dyns: [], strNames: ['ELFPOOLNAME'] }), known]);
  const out = forensics(merged, 'merged');
  assert.ok(out.stringTotal >= 40, `已知的 40 条必须都在计数里（实际 ${out.stringTotal}）`);
  assert.equal(out.stringTotal, extractStrings(merged, 6, Infinity).total, 'stringTotal 是全文计数，不是样本条数');
  assert.equal(out.stringSamples, Math.min(out.stringTotal, 4096), '样本数另有其数');
});

test('extractStrings：>=6 才算、偏移是真字节位置、结尾无 NUL 的一条也算', () => {
  // 字节图：0-5 'AAAAAA' | 6 NUL | 7-11 'BBBBB'(5 字符，不算) | 12 NUL | 13-18 'CCCCCC' | 19 NUL | 20-25 'DDDDDD'
  const b = Buffer.from('AAAAAA\0BBBBB\0CCCCCC\0DDDDDD', 'latin1');
  assert.equal(b.length, 26);
  const { total, samples } = extractStrings(b, 6, Infinity);
  assert.equal(total, 3);
  assert.deepEqual(samples.map((s) => s.s), ['AAAAAA', 'CCCCCC', 'DDDDDD']);
  assert.deepEqual(samples.map((s) => s.off), [0, 13, 20], '偏移必须是原始 Buffer 里的字节位置');
  for (const s of samples) assert.equal(b.subarray(s.off, s.off + s.s.length).toString('latin1'), s.s);
});

test('ioc：五个桶，且偏移是原始 Buffer 里的真偏移（复核靠它用肉眼验串）', () => {
  const f = 'device_faker_cli';
  const b = fix(f);
  const out = forensics(b, f);
  const buckets = ['外联', 'root路径', 'root语义', '执行', '属性名'];
  for (const k of buckets) {
    assert.equal(typeof out.ioc[k], 'number', `桶 ${k} 要有计数`);
    assert.ok(Array.isArray(out.ioc[`${k}@样本`]), `桶 ${k} 要有样本`);
    assert.ok(out.ioc[`${k}@样本`].length <= 8, `桶 ${k} 样本最多 8 条`);
    assert.ok(out.ioc[`${k}@样本`].length <= out.ioc[k]);
  }
  assert.equal(Object.keys(out.ioc).length, 10, '只有这五个桶：计数 + 样本各一条');
  const withSamples = buckets.filter((k) => out.ioc[`${k}@样本`].length > 0);
  assert.ok(withSamples.length >= 2, '真二进制至少该命中两个桶');
  for (const k of withSamples) {
    for (const line of out.ioc[`${k}@样本`]) {
      const m = /^(0x[0-9a-f]+): ([\s\S]*)$/.exec(line);
      assert.ok(m, `样本格式必须是 "offset: 串"，实际 ${line}`);
      const off = Number(BigInt(m[1]));
      const s = m[2];
      assert.equal(b.subarray(off, off + s.length).toString('latin1'), s,
        `${k} 的偏移必须能直接在原始字节上逐字复核：${line}`);
    }
  }
});

test('stringsPartial：超过扫描上限时如实声明只看了前 8 MiB', () => {
  const tile = Buffer.from('\0ABCDEF'.repeat(585), 'latin1');       // 4095 B = 585 条 6 字符串
  const filler = Buffer.alloc(SCAN_LIMIT);
  for (let o = 0; o + tile.length <= SCAN_LIMIT; o += tile.length) tile.copy(filler, o);
  const b = Buffer.concat([buildElf32({ syms: [{ name: 'open', shndx: 0 }], dyns: [] }), filler]);
  assert.ok(b.length > SCAN_LIMIT);
  const out = forensics(b, 'big');
  assert.equal(out.stringsPartial, true, '必须声明没扫完');
  assert.equal(out.stringsScannedBytes, SCAN_LIMIT);
  assert.equal(out.stringTotal, extractStrings(b.subarray(0, SCAN_LIMIT), 6, Infinity).total, '总数是"已扫前缀"的真实计数');
  assert.ok(out.stringTotal > 1e5 && out.stringSamples === 4096, '被截断时总数也不能塌成样本数');
  assert.ok(out.stringsScannedBytes < out.bytes, '声明只看了前缀时，前缀必须真的小于文件大小');
  assert.equal(out.importCount, 1, '字符串截断不影响符号表结论');
  assert.equal(forensics(fix('hma-x86.so'), 'hma-x86.so').stringsPartial, false);
});

//----------------------------------------------------------------------------
// I. 输出形状
//----------------------------------------------------------------------------

test('输出键集合固定，且本模块不给严重性、不判危险', () => {
  const wantKeys = ['bytes', 'importCount', 'ioc', 'kind', 'machineName', 'name', 'needed', 'sections',
    'sensitiveImports', 'stringSamples', 'stringTotal', 'stringsPartial', 'stringsScannedBytes', 'stripped', 'type'];
  for (const f of ['arm64-v8a.so', 'hma-armeabi-v7a.so']) {
    const out = forensics(fix(f), f);
    assert.deepEqual(Object.keys(out).sort(), wantKeys.slice().sort(), `${f} 的输出键必须正好是这一组`);
    for (const banned of ['severity', 'level', 'score', 'dangerous', 'verdict', 'finding', 'ruleId']) {
      assert.ok(!(banned in out), `${banned} 不属于本模块 —— 判档是下游 risk-rules 的事`);
    }
    assert.ok(Number.isInteger(out.importCount) && out.importCount > 0, `${f} 必须真的读到导入`);
    assert.ok(out.sensitiveImports.length <= out.importCount, '敏感子集不可能比全集大');
    assert.equal(out.bytes, fix(f).length);
  }
});
