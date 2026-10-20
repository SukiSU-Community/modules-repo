// audit/dex-forensics.mjs —— 只读 DEX 容器静态取证。不执行、不判档：只报"读到了什么"。
//
// 为什么要有这个模块（对齐 §0.7 那条硬边界，先把它抄在最贵的位置上）：
//   计划 2026-10-12 §0.7 的 DEX 探针实测过一枚真 `classes.dex`：`string_ids` 解得出来（52,821 条），
//   但前 40 条是 `A0`…`A00aOo` 这种被混淆的类名。由此定下的原则是
//   **「只有链接期事实可以作降级依据 —— ELF 的 `.dynsym` 导入表是动态链接器必须满足的符号集合，
//   它出现过 == 它一定会用到；dex/apk 里的名字出现过不是这种事实」**。
//   ⚠️ 那一枚走的是 `latest`、当时没钉 tag，2026-10-21 在钉住的语料上复现不出来；上面那句话
//   记的是「名字形状可能毫无信息量」这个原则，不是某枚文件的读数。可复现的锚点是 LSPosed Manager 的
//   `classes.dex`（7,099,112 B / v038 / 23,213 条串全解出、0 失败、0 半截，串与串之间 0 缝 0 重叠 ——
//   这条平铺不变量由 DX-25 钉着）。原则与锚点都指向同一个结论：**串池值得读，但不许当放行依据**。
//   所以这个模块产出的东西按可信度分成两半，下游必须分开用：
//     ① **结构与字面量**（计数、版本、串池里的 URL / IP / 路径 / 命令串）：串池是常量池，
//        一个字面值要么在包里要么不在，跟"会不会被执行"无关 —— 它和文本层那些行级规则吃的
//        是同一类证据，所以 `dexStrings()` 的输出可以直接喂给既有规则，判据不必有第二份。
//     ② **名字**（类名 / 方法名 / 字段名）：只是"被引用过"，正经 App 的 dex 里出现
//        `Runtime;->exec` 是家常便饭。这一半只许往严登记，**永远不许用来放宽、也不许当升档依据**。
//
// 三条硬约束（与 elf-forensics 一字不差）：
//   1) 不猜。魔数不对 → null（不归本模块管）；header_size 非 0x70、endian_tag 反序、版本不在
//      认过的表里、任何跨过缓冲区末尾的表项，一律 { name, kind:'DEX', parseError }。
//   2) 畸形绝不抛。parseError 是正常失败通道，扫描器要继续跑。最危险的不是拒，而是给出一个
//      看似合理的数：读不出来的文件上出现 `stringIdsSize: 0` 会被念成"这个 dex 没有字符串"。
//      所以 parseError 的输出里根本不带那些键。
//   3) 不返回严重性，不把"危险"编码成判断。这里只报事实，判档是下游 risk-rules 的事。
//
// 读不到的东西（写清楚，别让下游以为这里看过）：
//   * 不解 dex 的字节码（dalvik 指令）、不建调用图，所以**说不出某个方法是否真被调用**；
//   * 不展开 zip 容器（apk/jar 套在里面那一层不归这里，本轮按"未展开"登记）；
//   * 不查 `map_list` 与各 section 的一致性（头表给的计数就是计数，它和实读不一致会被如实报成
//     两个数，而不是被折成一个）；
//   * 对 odex / vdex / apk（App Bundle 的 `.apk` 里是 zip）一个字都不说 —— 魔数不同，落到 null。
//
// 零第三方依赖；不需要 dexdump/apktool/jadx，CI 与开发机同结果。

/** dex header 固定 0x70 字节；不等于这个数就不是我们认过的 dex。 */
export const DEX_HEADER_SIZE = 0x70;
const ENDIAN_TAG = 0x12345678;
/**
 * 认过的 dex 版本。038 是本仓自建 Manager 的 `classes.dex`（7,099,112 B）上量出来的真值；
 * 035 是计划 §0.7 那枚探针读过的 `classes.dex` 所在那一族。表外的版本号一律拒 ——
 * 不是因为它一定解不开，而是因为**这里的偏移表没有对它验过**，按未验过的布局硬解就是猜。
 */
export const DEX_VERSIONS = ['035', '036', '037', '038', '039', '040'];

/** 样本条数上限：只限制**呈现**，绝不限制被上报的总数（这条区分存在的原因见 elf-forensics 同段注释）。 */
export const DEX_STRING_SAMPLE_CAP = 400;
/** 单串呈现长度上限（登记里贴出来的那一段）。 */
export const DEX_STRING_SAMPLE_LEN = 120;

class Refuse extends Error {}
const refuse = (msg) => { throw new Refuse(msg); };

const isBytes = (buf) => !!buf && typeof buf === 'object' && typeof buf.length === 'number' && typeof buf.readUInt8 === 'function';

/** 魔数：`dex\n` + 版本 3 位数字 + `0x00`。 */
function dexVersion(buf) {
  if (!buf || buf.length < 8) return null;
  if (buf[0] !== 0x64 || buf[1] !== 0x65 || buf[2] !== 0x78 || buf[3] !== 0x0a) return null;
  if (buf[7] !== 0x00) return null;
  const v = String.fromCharCode(buf[4], buf[5], buf[6]);
  return /^[0-9]{3}$/.test(v) ? v : null;
}

/** 读一个界内小端 u32；读不到就是拒，不是 0。 */
function u32(buf, at, what) {
  if (at < 0 || at + 4 > buf.length) refuse(`${what} at 0x${at.toString(16)} runs past the buffer (${buf.length}B)`);
  return buf.readUInt32LE(at);
}

/**
 * uleb128：dex 里所有长度都是它。越界与 >5 字节（会溢出 u32）一律拒。
 * 返回值带上消耗掉的字节数，调用方要用它定位数据起点。
 */
function uleb128(buf, at, what) {
  let result = 0, shift = 0, p = at;
  for (;;) {
    if (p >= buf.length) refuse(`${what} uleb128 runs past the buffer (at 0x${p.toString(16)}, ${buf.length}B)`);
    const b = buf[p++];
    result += (b & 0x7f) * 2 ** shift;          // 不用 << ：超过 32 位会被截成负数，静默错一个数
    if (!(b & 0x80)) break;
    shift += 7;
    if (shift > 28) refuse(`${what} uleb128 longer than 5 bytes at 0x${at.toString(16)}`);
  }
  if (!Number.isInteger(result) || result < 0) refuse(`${what} uleb128 overflow at 0x${at.toString(16)}`);
  return { value: result, bytes: p - at };
}

/**
 * MUTF-8 解码（到 NUL 收口）。三条和 UTF-8 不一样的地方，逐条落地：
 *   * `U+0000` 编成两字节 `0xC0 0x80`，串里的裸 `0x00` 是**终止符**而不是字符；
 *   * 代理对编成两个独立三字节序列（`0xED 0xA0-0xAF ...`），所以逐序列 fromCodePoint 就得到正确 JS 串；
 *   * 没有四字节形式。
 * 遇到非法序列不整份拒：这一条串记为 failed 并继续下一条 —— 一枚真 dex 的串池里躺着一个
 * 奇怪的常量是常态，为此丢掉整张表等于把可读的证据也一起丢了。failed 的条数会如实上报，
 * 所以下游看得见"少读了 N 条"，这不是静默跳过。
 * @returns {{ s: string|null, next: number }} s 为 null == 这条解码失败
 */
function mutf8(buf, at, end) {
  let s = '', i = at;
  while (i < end) {
    const c = buf[i];
    if (c === 0x00) return { s, next: i + 1, unterminated: false };  // 终止符：遇见它才算一个完整的串
    if (c < 0x80) { s += String.fromCharCode(c); i++; continue; }
    if ((c & 0xe0) === 0xc0) {                          // 两字节
      if (i + 1 >= end || (buf[i + 1] & 0xc0) !== 0x80) return { s: null, next: i };
      const cp = ((c & 0x1f) << 6) | (buf[i + 1] & 0x3f);
      if (cp === 0) { s += '\u0000'; i += 2; continue; } // 0xC0 0x80 == U+0000
      if (cp < 0x80) return { s: null, next: i };        // 非最短形式
      s += String.fromCharCode(cp); i += 2; continue;
    }
    if ((c & 0xf0) === 0xe0) {                          // 三字节（含代理的独立编码）
      if (i + 2 >= end || (buf[i + 1] & 0xc0) !== 0x80 || (buf[i + 2] & 0xc0) !== 0x80) return { s: null, next: i };
      const cp = ((c & 0x0f) << 12) | ((buf[i + 1] & 0x3f) << 6) | (buf[i + 2] & 0x3f);
      if (cp < 0x800) return { s: null, next: i };      // 非最短形式
      s += String.fromCharCode(cp); i += 3; continue;
    }
    return { s: null, next: i };                        // 0xF0 起头：MUTF-8 里没有这种形式
  }
  return { s: null, next: i, unterminated: true };  // 跑到缓冲区末尾还没 NUL == 半截串，不进可读面
}

/**
 * 主入口。
 * @param {Buffer} buf 单个条目的**原始字节** —— 不是 content 字段（那已被 utf8 解码毁掉）
 * @param {string} name 条目名，只用于回填输出
 * @returns {object|null} 非 dex → null；读不出来 → 只带 parseError 的对象（**不带计数字段**）；
 *   读出来了 → 完整事实 + `strings`（串池，喂给下游规则用）。永不抛。
 */
export function forensics(buf, name = '') {
  if (!isBytes(buf)) {
    return { name, kind: 'DEX', parseError: 'input is not a raw byte Buffer (a decoded string would already have destroyed the binary bytes)' };
  }
  const v = dexVersion(buf);
  if (!v) return null;                                  // 不是 dex：不归本模块管
  if (buf.length < DEX_HEADER_SIZE) {
    return { name, kind: 'DEX', parseError: `dex magic present but header truncated: buffer has ${buf.length}B, need ${DEX_HEADER_SIZE}B` };
  }
  try {
    return analyze(buf, name, v);
  } catch (err) {
    if (err instanceof Refuse) return { name, kind: 'DEX', parseError: err.message };
    return { name, kind: 'DEX', parseError: `unexpected parse failure: ${(err && err.message) || String(err)}` };
  }
}

function analyze(buf, name, v) {
  if (!DEX_VERSIONS.includes(v)) refuse(`dex version ${v} is not in the verified table (${DEX_VERSIONS.join('/')})`);
  const headerSize = u32(buf, 0x24, 'header_size');
  if (headerSize !== DEX_HEADER_SIZE) refuse(`header_size=0x${headerSize.toString(16)}, expected 0x70`);
  const endian = u32(buf, 0x28, 'endian_tag');
  // 反序 dex（endian_tag 读成 0x78563412）在这里是"我们没实现大端"，不是"这文件没问题"。
  if (endian !== ENDIAN_TAG) refuse(`endian_tag=0x${endian.toString(16)} != 0x12345678 (大端或反序的 dex 不支持)`);

  const fileSize = u32(buf, 0x20, 'file_size');
  const out = {
    name,
    kind: 'DEX',
    bytes: buf.length,
    dexVersion: v,
    fileSize,
    headerSize,
    mapOff: u32(buf, 0x34, 'map_off'),
    stringIdsSize: u32(buf, 0x38, 'string_ids_size'),
    stringIdsOff: u32(buf, 0x3c, 'string_ids_off'),
    typeIdsSize: u32(buf, 0x40, 'type_ids_size'),
    protoIdsSize: u32(buf, 0x48, 'proto_ids_size'),
    fieldIdsSize: u32(buf, 0x50, 'field_ids_size'),
    methodIdsSize: u32(buf, 0x58, 'method_ids_size'),
    classDefsSize: u32(buf, 0x60, 'class_defs_size'),
    dataSize: u32(buf, 0x68, 'data_size'),
    dataOff: u32(buf, 0x6c, 'data_off'),
  };

  // 声明长度与实际字节数的关系，两个方向各说各的话：
  //   declared > 实有 → 这就是「只喂进前缀」。dex 自己会写它多大，所以这一格不需要上游告诉：
  //     条目被 MAX_FORENSICS_BYTES 截过、或 zip 里的条目本身被截短过，都会走到这里。前缀里
  //     读到的东西照读，但 `inputCapped` 必须带上 —— 分派那一格要说「后半段一个字都没读到」，
  //     永远不许念成「取证成功、串池干净」。
  //   declared < 实有 → 尾巴上有额外字节（拼接、或尾部塞了别的负载），如实记 trailingBytes。
  out.inputCapped = buf.length < fileSize;
  if (fileSize < buf.length) out.trailingBytes = buf.length - fileSize;

  const tableEnd = out.stringIdsOff + out.stringIdsSize * 4;
  if (out.stringIdsSize > 0 && out.stringIdsOff < DEX_HEADER_SIZE) {
    refuse(`string_ids off 0x${out.stringIdsOff.toString(16)} is inside the header (${DEX_HEADER_SIZE}B)`);
  }
  // 表尾越界时分两种：整张表压根不在缓冲区里（结构坏了）→ 拒；前缀里还剩几项就能读几项
  // （输入被截过的典型形状）→ 读可及的那一段，并把「表没读全」单独数出来。
  // 反例钉在测试里：把这一格并回"一律拒"，一枚被截断的真 dex 就从「读了前 N 条 + 明说截断」
  // 退成「什么都没说」，而后者对复核者等于零信息。
  let readable = out.stringIdsSize;
  if (tableEnd > buf.length) {
    if (out.stringIdsOff >= buf.length) {
      refuse(`string_ids (off 0x${out.stringIdsOff.toString(16)} + ${out.stringIdsSize}×4B = ${tableEnd}) runs past the buffer (${buf.length}B)`);
    }
    readable = Math.floor((buf.length - out.stringIdsOff) / 4);
    out.stringIdsReadable = readable;
  }

  const pool = decodeStrings(buf, out.stringIdsOff, readable);
  out.stringsDecoded = pool.strings.length;
  out.stringsFailed = pool.failed;
  out.stringsUnterminated = pool.unterminated;
  out.stringsSizeMismatch = pool.strings.reduce((n, x) => n + (x.sizeMismatch ? 1 : 0), 0);
  out.strings = pool.strings;                            // 串池本体：给下游行级规则当输入，不进报告
  out.samples = pool.strings.slice(0, DEX_STRING_SAMPLE_CAP)
    .map((x) => ({ off: x.off, s: x.s.slice(0, DEX_STRING_SAMPLE_LEN) }));
  out.samplesCapped = pool.strings.length > DEX_STRING_SAMPLE_CAP;
  return out;
}

/**
 * 解 string_ids 表。两种"读不下去"分开数，别并成一格：
 *   `failed`       —— 这一项的字节序列不是合法 MUTF-8（单项越界也算），跳过它，其余照读；
 *   `unterminated` —— 跑到缓冲区末尾还没遇见 NUL，那是半截串（输入被截过的典型症状）。
 * 还有第三种，它**不在这个函数里**：单项里的 uleb128 跨过缓冲区末尾 ⇒ 整份拒（Refuse 往上冒）。
 * 这不是前后不一致，是两种账：跳过单项时总数与 failed 都还在，人看得见"少读了 N 条"；
 * 而长度前缀本身读不出来时，这张表还剩多少条是可读的**无从判断**，那就不能给任何计数 ——
 * 给一个数就是猜（硬约束 1）。
 */
function decodeStrings(buf, tableOff, size) {
  const strings = [];
  let failed = 0, unterminated = 0;
  for (let i = 0; i < size; i++) {
    const off = buf.readUInt32LE(tableOff + i * 4);
    if (off < DEX_HEADER_SIZE || off >= buf.length) { failed++; continue; }
    const len = uleb128(buf, off, `string_ids#${i}`);
    const start = off + len.bytes;
    // 长度按 UTF-16 code unit 计；实际字节数可能更多（中文/代理是 3 字节）。
    // 所以边界用"到 NUL 收口"这条真实规则查，不用 len 反推字节数 —— 后者会把合法文件判成越界。
    const dec = mutf8(buf, start, buf.length);
    if (dec.unterminated) { unterminated++; continue; }
    if (dec.s === null) { failed++; continue; }
    if (len.value !== dec.s.length) {
      // 声明的 code unit 数与实读不一致：串本身仍然可用（到 NUL 收口是权威），但这个不一致
      // 是结构异常，必须可数。不当失败丢，也不静默修。
      strings.push({ off, s: dec.s, sizeMismatch: true });
      continue;
    }
    strings.push({ off, s: dec.s });
  }
  return { strings, failed, unterminated };
}

/**
 * 串面喂入的两条闸，两条都是从真字节上量出来的，不是拍的：
 *
 * ① `DEX_SURFACE_LINE_MAX = 4096`（单串喂入长度上限，按 UTF-16 code unit 计）。
 *    `scan.MAX_SCAN_BYTES_PER_ENTRY`（24 KB）存在的理由是**长行**上的正则回溯 ——
 *    那条曲线（8 KB=100.6 ms 直到 240 KB=76,572 ms，热点 `PRIVACY_EMAIL`）量的是单行。
 *    而一枚真 dex 的常量池里就躺着长行：本仓自建 Manager 的 `classes.dex` 第 4、5 条串
 *    声明长度分别是 1,248 与 24,772 code unit。所以不能因为"总量不大"就把整池原样摊进去，
 *    也不能因为"曾经截过 24 KB"就宣称这一层的成本已经 bounded —— 单串上限才是这里对症的那一闸。
 *
 * ② `DEX_SURFACE_MAX_BYTES = 1 MiB`（一枚 dex 的串面总预算）。
 *    实测锚点（本仓自建 Manager 的 `classes.dex`，7,099,112 B / 23,213 条串，全部解出、0 条失败）：
 *      单串截到 4096 之后整池摊平 = **449,195 B / 23,213 行**，`scanContent` 跑完 **1,165–1,232 ms**；
 *      斜率按 1 MiB / 2 MiB / 4 MiB 合成面量出来是 **2.6 ms/KB 且线性**（4,926 / 9,681 / 19,754 ms）。
 *    所以 1 MiB = 实测最大池的 2.3 倍余量，单枚 dex 的规则时间约 2.6 s。
 *    **为什么不能直接沿用 `MAX_SCAN_BYTES_PER_ENTRY`（24 KB）**：同一枚 dex 把预算换成 24 KB，
 *    只喂进 **44 行、丢掉 23,169 条**（探针实测，`dropped` 那个数就是这么来的）。那一档是为
 *    「单条长行把回溯炸到分钟级」准备的，而串池是几万条短行 —— 照搬过去等于把整池当 44 条读，
 *    而且 d8 的 `string_ids` 顺序不带"可疑的在前"这种语义，截前缀就是一段没有优先级的抽样。
 *    超出 1 MiB 的部分必须换成 `dropped` 计数、由下游记一条**参与定级**的截断记录：
 *    「读到一半」永远不等于「干净」（与 Task 2.9 那条硬边界同一句）。
 *
 * ③ 顺带第三条（不是数值）：**喂进去的文本里不许有裸控制字符**。`\n` 会把"一串一行"的对应关系
 *    打断（行号就不再是串序号，复核者按行号去找串会找错），裸 `0x00` 会撞 T57-15 那根
 *    "产物里不许有 NUL"的钉子。所以转义后喂：LF/CR 变成可见的 `\n` / `\r`，其余控制字符（含 NUL）
 *    变成 U+FFFD，两者都计入 `escaped`。
 */
export const DEX_SURFACE_LINE_MAX = 4096;
export const DEX_SURFACE_MAX_BYTES = 1024 * 1024;

/** 见上面第 ③ 条：转义是必须的，但"转义过几行"这件事得数得出来。 */
function escapeForSurface(s) {
  let escaped = 0, out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c === 0x0a) { out += '\\n'; escaped++; }
    else if (c === 0x0d) { out += '\\r'; escaped++; }
    else if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) { out += '\uFFFD'; escaped++; }
    else out += ch;
  }
  return { text: out, escaped };
}

/**
 * 把串池摊成"一串一行"的文本面，交给既有行级规则消费。
 *
 * 为什么在这一点上判据可以只有一份实现：dex 的串池是**常量池**。一个字面值要么在里面要么不在，
 * 跟"这段代码会不会跑"无关 —— 所以这里不新写任何 IP / 域名 / 命令串的判据（那是 elf-forensics
 * 与 risk-rules 之间的老账：判据不许有第二份），只负责把常量摊平成规则看得见的形状。
 * 但注意别把这句话念过头：**「字面值在包里」是事实，「这行会被执行」不是** ——
 * 后者才是那 20 条执行/root/dangerous 类规则的定级前提，所以定档那一步在 risk-rules 的
 * `dexSurfaceSeverity` 里按证据类型分岔，不在这个文件里（本模块不返回严重性，一字都不判）。
 *
 * 名字类（类名 / 方法名 / 字段名）也一并摊进来是刻意的：它们照样过不了任何一条字面量判据
 * （`Landroid/app/NotificationManager;` 里没有 IP 也没有 URL），而 risk-rules 那边登记时会明说
 * 这一层"名字出现过 ≠ 会被调用"。不为了少几行输出把它们摘掉 —— 摘掉就等于宣称这一层人不需要看。
 *
 * @param {object} rec forensics() 的成功返回
 * @param {{lineMax?:number, budgetBytes?:number}} [opts] 只给测试用；生产走上面两个常量
 * @returns {{text:string, lines:number, trimmed:number, dropped:number, escaped:number}}
 *   `trimmed` = 被单串上限截过的串数；`dropped` = 因为超出总预算而**一个字都没喂**的串数；
 *   两个数都必须由下游念出来，不许在这里替它们折叠成一句"读过了"。
 */
export function dexStringSurface(rec, opts = {}) {
  const lineMax = Number.isInteger(opts.lineMax) && opts.lineMax > 0 ? opts.lineMax : DEX_SURFACE_LINE_MAX;
  const budget = Number.isInteger(opts.budgetBytes) && opts.budgetBytes >= 0
    ? opts.budgetBytes : DEX_SURFACE_MAX_BYTES;
  const strings = rec && Array.isArray(rec.strings) ? rec.strings : [];
  const lines = [];
  let bytes = 0, trimmed = 0, dropped = 0, escaped = 0;
  for (const item of strings) {
    const raw = typeof item.s === 'string' ? item.s : '';
    if (raw.length > lineMax) trimmed++;
    const cut = raw.length > lineMax ? raw.slice(0, lineMax) : raw;
    const e = escapeForSurface(cut);
    const size = Buffer.byteLength(e.text, 'utf8') + 1;      // +1 = 那一行自己的 LF
    if (bytes + size > budget) { dropped = strings.length - lines.length; break; }
    bytes += size;
    escaped += e.escaped;
    lines.push(e.text);
  }
  return { text: lines.join('\n'), lines: lines.length, trimmed, dropped, escaped };
}
