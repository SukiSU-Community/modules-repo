#!/usr/bin/env node
// 标定探针生成器 —— 给 `AI Budget Calibrate` 这个一次性 workflow 造输入包。
//
// 为什么不把探针 zip 提交进仓库：本仓 `.gitignore` 里有 `*.zip`（`scripts/audit-corpus.mjs:18`
// 写明「下载的 zip 一律落在仓库外」）。标定的输入包不该为了这一次运行而在 git 历史里留一份
// 79 KB 的二进制，也不该为了它开一条 ignore 例外 —— 开了例外，以后「哪个 zip 能进仓」就
// 变成要逐个记住的事。这里改成**现场生成**：谁 dispatch 谁生成，用完即弃，可复现。
//
// 为什么体量必须落在真实工作点（这是整个脚本唯一重要的设计）：
//   标定读的是 `credits / neededBytes`，而 credits 里有一大块是**固定的系统提示成本**，
//   与 brief 字节数无关。探针越小，固定成本占比越高，按 credits 上限线性外推出来的
//   字节预算就越小 —— 小探针标出来的预算，上线后会把所有真实包判成 over-budget。
//   真包文本约 766 KB（见 audit/ai-review.mjs 文件头），所以默认按 780000 B 造，
//   落出来的 neededBytes 与真包同量级。
//
// 用法：
//   node audit/calibration-probe.mjs --out <zip 路径> [--text-bytes N]
//
// 产物形状：module.prop + post-fs-data.sh + payload/part-NNN.txt × N。
// 内容刻意平淡（无外联 URL、无 /data/adb 写路径、无 eval、无魔数）——
// 标定量的是「塞满字节要花多少钱」，探针一旦自己命中规则，读数里就混进与字节无关的变量。
import { writeFileSync, mkdirSync } from 'node:fs';
import { deflateRawSync } from 'node:zlib';
import { dirname, resolve } from 'node:path';

// 单条目进料的硬上限（audit/scan.mjs 的 MAX_SCAN_BYTES_PER_ENTRY = 24 KiB，也是
// ai-review.mjs 的 TEXT_FEED_CAP_BYTES）。摊到 12000 B 一个文件：留足余量，
// 且让行号前缀的开销也被如实算进 neededBytes。
const PER_FILE = 12000;

function argOf(argv, name, fallback) {
  const i = argv.indexOf(`--${name}`);
  if (i >= 0 && i + 1 < argv.length && !String(argv[i + 1]).startsWith('--')) return argv[i + 1];
  const eq = argv.find((a) => a.startsWith(`--${name}=`));
  return eq ? eq.slice(name.length + 3) : fallback;
}

/**
 * 一段平淡的技术说明文本。每行足够长，好让 brief 里「行号前缀 N| 」的字节开销
 * 也被计入 —— 真包里同样有这部分，探针少算了它，外推的预算就会偏大。
 */
function filler(seed, approxBytes) {
  const vocab = [
    'boot', 'kernel', 'module', 'mount', 'overlay', 'selinux', 'policy', 'ramdisk',
    'init', 'service', 'property', 'partition', 'superblock', 'vendor', 'system',
    'compile', 'syscall', 'hook', 'symbol', 'relocation', 'linker', 'namespace',
  ];
  const lines = [];
  let bytes = 0;
  let i = 0;
  while (bytes < approxBytes) {
    const w = vocab[(seed + i) % vocab.length];
    const w2 = vocab[(seed * 3 + i * 7) % vocab.length];
    const line = `# ${w} note ${i}: ${w2} handling for ${w} stage ${i % 97} `
      + `is documented here so the text volume matches a real payload.`;
    lines.push(line);
    bytes += Buffer.byteLength(line, 'utf8') + 1;
    i += 1;
  }
  return lines.join('\n');
}

// --- 最小 zip 写入器 -------------------------------------------------------
// 为什么要自己写而不用 Compress-Archive / zip 命令：那些工具跨平台行为不一致，
// 实测 Windows 的 Compress-Archive 会写出**反斜杠分隔**的条目名，直接触发
// STRUCT_BACKSLASH_PATH（medium）—— 探针一出生就带着一条与标定无关的发现。
// 这里只写 STORED/DEFLATE 两种、单卷、无 zip64（探针只有几百 KB），格式可控。
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i += 1) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function dosDateTime(d) {
  const time = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() / 2) & 0x1f);
  const date = (((d.getFullYear() - 1980) & 0x7f) << 9) | (((d.getMonth() + 1) & 0x0f) << 5) | (d.getDate() & 0x1f);
  return { time, date };
}

/**
 * @param {{name: string, content: string}[]} files 条目名必须用正斜杠
 * @returns {Buffer}
 */
function buildZip(files) {
  const { time, date } = dosDateTime(new Date());
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8'); // 正斜杠，不再折
    const raw = Buffer.from(f.content, 'utf8');
    const packed = deflateRawSync(raw, { level: 9 });
    // 压缩没变小就用 STORED（方法与大小必须自洽，否则解压器读到的是垃圾）
    const useStored = packed.length >= raw.length;
    const body = useStored ? raw : packed;
    const method = useStored ? 0 : 8;
    const crc = crc32(raw);

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);       // version needed
    local.writeUInt16LE(0, 6);        // flags
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);       // extra len
    name.copy(local, 30);

    locals.push(local, body);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);     // version made by
    central.writeUInt16LE(20, 6);     // version needed
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);     // extra
    central.writeUInt16LE(0, 32);     // comment
    central.writeUInt16LE(0, 34);     // disk
    central.writeUInt16LE(0, 36);     // internal attrs
    central.writeUInt32LE(0, 38);     // external attrs
    central.writeUInt32LE(offset, 42);
    name.copy(central, 46);

    centrals.push(central);
    offset += local.length + body.length;
  }

  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, cd, end]);
}

// --- 主流程 ---------------------------------------------------------------
const argv = process.argv.slice(2);
const out = argOf(argv, 'out', 'calibration-probe.zip');
const target = Number(argOf(argv, 'text-bytes', '780000'));
if (!Number.isFinite(target) || target <= 0) {
  process.stderr.write(`--text-bytes 必须是正数，读到 ${argOf(argv, 'text-bytes', '')}\n`);
  process.exit(2);
}

const files = [
  {
    name: 'module.prop',
    content: [
      'id=calibrationprobe',
      'name=Calibration Probe',
      'version=v1.0.0',
      'versionCode=10000',
      'author=modules-web',
      'description=Text-volume probe used once to calibrate the AI brief budget. Not a real module.',
    ].join('\n'),
  },
  {
    name: 'post-fs-data.sh',
    content: [
      '#!/system/bin/sh',
      '# mount the module over the stock partition layout',
      'MODDIR=${0%/*}',
      'mount --bind "$MODDIR/system" /system 2>/dev/null || true',
    ].join('\n'),
  },
];

// 把目标字节数摊到多个文件：全塞一个文件的话，超出 24 KiB 的部分不进 brief，
// neededBytes 就只剩下那个上限，标定量的不再是「真实工作点」。
const fileCount = Math.ceil(target / PER_FILE);
for (let n = 0; n < fileCount; n += 1) {
  files.push({ name: `payload/part-${String(n).padStart(3, '0')}.txt`, content: filler(n, PER_FILE) });
}

const zip = buildZip(files);
mkdirSync(dirname(resolve(out)), { recursive: true });
writeFileSync(out, zip);

const textBytes = files.reduce((s, f) => s + Buffer.byteLength(f.content, 'utf8'), 0);
process.stdout.write(`entries=${files.length}  textBytes=${textBytes}  zipBytes=${zip.length}  -> ${out}\n`);
