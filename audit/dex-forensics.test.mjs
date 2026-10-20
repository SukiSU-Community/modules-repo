// audit/dex-forensics.test.mjs —— dex 取证层的闸，逐条证明它会咬人。
//
// 这个文件存在的理由（与 elf-forensics.test.mjs 同一条纪律）：
//   1) **真字节锚一次**：`fixtures/d8-minimal.dex` 是 d8（build-tools 34.0.0）从一段自写 Java 编出来的
//      真 dex，1,460 B，版本 035。它不是手搓最小文件 —— 手搓的串表恰恰测不到 d8 的 uleb128、
//      串表顺序与常量池形状，而这三样正是这一层每天要解的东西。
//   2) **畸形路径靠合成**：大端、header_size 非 0x70、越界表项、半截串、非法 MUTF-8 这些形状在真包里
//      可遇不可求，而它们正是「读不出」那几格的成因。真夹具守"读得出来"，合成器守"读不出来时说什么"。
//   3) **两条不许复合的东西**：parseError 里不许出现计数字段（`stringIdsSize: 0` 会被念成「这枚 dex
//      没有字符串」）；上限只许限制呈现的条数，绝不限制被上报的总数。这两条各有一组钉子。
//   4) **不判档**：本模块只报事实。severity / category / 第二条字面值判据出现在这个文件里就是越界，
//      DX-18 用源码数着（T57-07 对 risk-rules 与 scan 做的是同一件事）。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  forensics, dexStringSurface, DEX_HEADER_SIZE, DEX_VERSIONS,
  DEX_STRING_SAMPLE_CAP, DEX_SURFACE_LINE_MAX, DEX_SURFACE_MAX_BYTES,
} from './dex-forensics.mjs';
import { MAX_SCAN_BYTES_PER_ENTRY } from './scan.mjs';
// dex 的起法只有 fixtures.mjs 那一份。这里再抄一份，两边的宽松程度早晚会分叉 ——
// 而分叉的那一侧照样是绿的（audit-corpus.mjs 那条"判据不许有第二份"同样管夹具的形状）。
import { makeDex as buildDex, dexUleb128 as uleb } from './fixtures.mjs';

const FIX = (f) => readFileSync(new URL(`./fixtures/${f}`, import.meta.url));

// 合成器住在 fixtures.mjs（makeDex / dexUleb128），这里只消费：起法写两份的话，两份的宽松程度
// 早晚分叉，而分叉那一侧照样绿。下面各组用例里的 buildDex / uleb 都是那两个导入的别名。

/** parseError 那一格的全部禁止键：任何"看起来像读数"的字段都不许出现。 */
const COUNT_KEYS = ['stringIdsSize', 'stringsDecoded', 'stringsFailed', 'stringsUnterminated',
  'stringsSizeMismatch', 'typeIdsSize', 'methodIdsSize', 'classDefsSize', 'inputCapped',
  'importCount', 'strings', 'samples', 'surface'];
function assertNoReadings(rec, label) {
  for (const k of COUNT_KEYS) {
    assert.equal(rec[k], undefined, `${label}：parseError 的返回里不许带 ${k}（0 会被念成"没有"）`);
  }
}

// ---------------------------------------------------------------------------
// A 组：真夹具的精确读数（这些数不是背下来的，是现跑现量的）
// ---------------------------------------------------------------------------

test('DX-01 真 d8 夹具的逐项读数：v035、33 条串全解出、0 失败、9 类型 / 7 方法 / 1 类定义', () => {
  const buf = FIX('d8-minimal.dex');
  assert.equal(buf.length, 1460);
  const r = forensics(buf, 'classes.dex');
  assert.equal(r.parseError, undefined, `真夹具必须读得出来：${r.parseError}`);
  assert.equal(r.kind, 'DEX');
  assert.equal(r.name, 'classes.dex');
  assert.equal(r.bytes, 1460);
  assert.equal(r.dexVersion, '035');
  assert.equal(r.headerSize, 0x70);
  assert.equal(r.fileSize, 1460, 'd8 自己声明的 file_size 与实际字节数一致');
  assert.equal(r.stringIdsSize, 33);
  assert.equal(r.stringsDecoded, 33, '一条都不许多丢');
  assert.equal(r.stringsFailed, 0);
  assert.equal(r.stringsUnterminated, 0);
  assert.equal(r.stringsSizeMismatch, 0);
  assert.equal(r.typeIdsSize, 9);
  assert.equal(r.methodIdsSize, 7);
  assert.equal(r.classDefsSize, 1);
  assert.equal(r.inputCapped, false);
  assert.equal(r.trailingBytes, undefined, '真夹具尾巴上没有多余字节');
});

test('DX-02 真夹具的串池里确实躺着那三条执行型字面值 —— 下游那条降级钉子吃的就是这个来源', () => {
  const set = forensics(FIX('d8-minimal.dex'), 'classes.dex').strings.map((x) => x.s);
  for (const need of ['rm -rf', 'base64 -d',
    'cp /data/system/packages.list /data/local/tmp/', '203.0.113.9:8080',
    'https://update.example.invalid/v1']) {
    assert.ok(set.includes(need), `夹具里必须有 ${JSON.stringify(need)}，否则 scan.test 那两条降级用例是空跑`);
  }
  // 类名/方法名同池：它们过不了任何一条字面量判据，所以不许被偷偷摘掉；摘了之后"引用面"就只剩
  // 好看的那几条串了。规则侧的对账（同一句字面值在两面各得各的档位）在 scan.test.mjs 的 DXE-01。
  assert.ok(set.some((s) => s.startsWith('Lcom/probe/dexfix/')), '引用面（类名）也在池里，不许被偷偷摘掉');
});

test('DX-02b 登记只带白名单里的读数：串池本体与 samples 不许顺着二进制登记漏进产物', async () => {
  const { binaryForensicsRows } = await import('./risk-rules.mjs');
  const rec = forensics(FIX('d8-minimal.dex'), 'classes.dex');
  rec.surface = { lines: 33, trimmed: 0, dropped: 0, escaped: 0 };
  const rows = binaryForensicsRows(
    [{ name: 'classes.dex', id: 'DEX', why: 'Android DEX', bytes: rec.bytes }],
    new Map([['classes.dex', rec]]));
  assert.equal(rows.length, 1, '逐条目一条，条目名就是 key（INV-B 按它逐条对账）');
  const row = rows[0];
  assert.equal(row.outcome, 'DEX_READ');
  assert.equal(row.kind, 'DEX');
  assert.equal(row.stringsDecoded, 33, '白名单里的读数要进登记，不然报告只能说"有个 dex 我读不了"');
  assert.equal(row.dexVersion, '035');
  assert.deepEqual(row.dexSurface, { lines: 33, trimmed: 0, dropped: 0, escaped: 0 });
  assert.equal(row.strings, undefined, '登记里不许有串池本体（那是规则的输入面，不是产物面）');
  assert.equal(row.samples, undefined, '登记里不许有 samples');
  assert.equal(JSON.stringify(row).includes('203.0.113.9'), false,
    '一条串的字面值不许直接躺在登记里 —— 它在 finding 的 snippet 里，那才是给人看的那一处');
});

test('DX-03 采样上限只限制 samples，绝不限制 stringsDecoded 与 strings 本体（那条历史污染）', () => {
  const many = Array.from({ length: DEX_STRING_SAMPLE_CAP + 7 }, (_, i) => `s${i}`);
  const r = forensics(buildDex({ entries: many }), 'classes.dex');
  assert.equal(r.parseError, undefined);
  assert.equal(r.strings.length, many.length, '池子本体是全量：截了它，规则就读不到第 401 条以后的载荷');
  assert.equal(r.samples.length, DEX_STRING_SAMPLE_CAP, '呈现那份才受上限管');
  assert.equal(r.samplesCapped, true);
  assert.equal(r.stringsDecoded, many.length);
});

// ---------------------------------------------------------------------------
// B 组：不归本模块管 vs 读不出来 —— 两种账不许并成一格
// ---------------------------------------------------------------------------

test('DX-04 非 dex 一律 null（ELF / PE / PNG / zip / 纯文本 / 空 Buffer 都不许冒充"读不出来"）', () => {
  for (const [label, buf] of [
    ['ELF 头', Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1')],
    ['MZ 头', Buffer.from('MZ\x90\x00', 'latin1')],
    ['PNG 头', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
    ['zip 容器', Buffer.from('PK\x03\x04abc', 'latin1')],
    ['纯文本', Buffer.from('id=foo\nname=bar\n', 'utf8')],
    ['空 Buffer', Buffer.alloc(0)],
  ]) assert.equal(forensics(buf, 'x'), null, `${label} 必须归 null`);
});

test('DX-05 喂字符串而不是 Buffer ⇒ parseError，而且不给任何读数（utf8 早已毁掉字节面）', () => {
  const r = forensics('dex\n035 not a buffer', 'classes.dex');
  assert.equal(r.kind, 'DEX');
  assert.match(r.parseError, /raw byte Buffer/);
  assertNoReadings(r, '非 Buffer 输入');
});

test('DX-06 header 不足 0x70：说"头被截了"，而不是硬解出 0 条串', () => {
  const r = forensics(Buffer.from('dex\n035\x00abcdef', 'latin1'), 'classes.dex');
  assert.match(r.parseError, /header truncated/);
  assertNoReadings(r, '截断的 header');
});

// ---------------------------------------------------------------------------
// C 组：结构畸形 —— 每一种都要给出"为什么这不是 0"
// ---------------------------------------------------------------------------

test('DX-07 endian_tag 反序（大端 dex）⇒ 明确拒，不许按小端硬解出一张漂到天上的表', () => {
  const r = forensics(buildDex({ endian: 0x78563412 }), 'classes.dex');
  assert.match(r.parseError, /endian_tag=0x78563412/);
  assertNoReadings(r, '大端 dex');
});

test('DX-08 header_size 非 0x70 ⇒ 拒；认过的版本表内每一版都能过这一关，表外的版本号一样拒', () => {
  const bad = forensics(buildDex({ headerSize: 0x74 }), 'classes.dex');
  assert.match(bad.parseError, /header_size=0x74/);
  assertNoReadings(bad, 'header_size 不符');
  for (const v of DEX_VERSIONS) {
    const ok = forensics(buildDex({ version: v }), 'classes.dex');
    assert.equal(ok.parseError, undefined, `版本 ${v} 在认过的表里，必须读得开`);
    assert.equal(ok.dexVersion, v);
  }
  const out = forensics(buildDex({ version: '999' }), 'classes.dex');
  assert.match(out.parseError, /version 999 is not in the verified table/);
  assertNoReadings(out, '表外版本');
});

test('DX-09 整张 string_ids 表落在缓冲区外 ⇒ 拒；表头压进 header 里也照样拒', () => {
  // total 必须显式给小：不写 total 时合成器会按 tableOfs 把缓冲区撑到 0x9008，
  // 那一格就自己测不到自己（这一类"夹具比被测面宽松一档"是本轮最容易自欺的一种绿）。
  const r = forensics(buildDex({ entries: ['a', 'b'], tableOfs: 0x9000, total: 0x200 }), 'classes.dex');
  assert.match(r.parseError, /string_ids/);
  assertNoReadings(r, '表整体越界');
  const inside = forensics(buildDex({ entries: ['a', 'b'], tableOfs: 0x60 }), 'classes.dex');
  assert.match(inside.parseError, /inside the header/, '表头压在 header 里也是结构错误，不许照读');
});

test('DX-10 文件自己声明 file_size 比实有大 ⇒ inputCapped：前缀照读，半截那条不进可读面', () => {
  const full = buildDex({ entries: ['alpha', 'bravo', 'charlie', 'delta'] });
  const cut = full.subarray(0, full.length - 6);   // 砍掉尾巴：表还在，最后一条串的字节没了
  const r = forensics(cut, 'classes.dex');
  assert.equal(r.parseError, undefined, '前缀里能读的部分要读，读得出多少报多少');
  assert.equal(r.inputCapped, true, `自己声明 ${full.length} B 只喂进 ${cut.length} B ⇒ 这就是输入不完整`);
  assert.equal(r.fileSize, full.length);
  assert.ok(r.stringsDecoded < 4, `半截的那条不许进可读面：实读 ${r.stringsDecoded}`);
  assert.ok(r.stringsUnterminated + r.stringsFailed > 0,
    '少掉那一条必须落在一个可数的格子上，不许静默消失');
});

test('DX-11 表尾越过缓冲区（输入被截过）⇒ 读可及项并记 stringIdsReadable，而不是一律拒', () => {
  const entries = Array.from({ length: 10 }, (_, i) => `e${i}`);
  const full = buildDex({ entries });
  // 截到「表还剩 4 项在缓冲区外」的位置：这一格如果整份拒，一枚被截断的真 dex 就只剩一句
  // "读不出"，而人能用的信息（前 6 项读了、第 7-10 项没读到）全丢了。
  const cut = full.subarray(0, DEX_HEADER_SIZE + 6 * 4);
  assert.ok(DEX_HEADER_SIZE + 6 * 4 < DEX_HEADER_SIZE + 10 * 4, '截点必须落在表中间，否则测的不是这一格');
  const r = forensics(cut, 'classes.dex');
  assert.equal(r.parseError, undefined, '可及的 6 项必须照读');
  assert.equal(r.stringIdsReadable, 6, `表只读到前几项要写成数，实得 ${r.stringIdsReadable}`);
  assert.equal(r.inputCapped, true);
  assert.ok(r.stringsDecoded <= 6);
  assert.equal(r.stringIdsSize, 10, '声明的总数与实读到的项数是两本账，都要在');
});

// ---------------------------------------------------------------------------
// D 组：单项畸形 —— 跳过的那一条必须可数，不许把表读短
// ---------------------------------------------------------------------------

test('DX-12 单项 string_data_off 越界 ⇒ 计入 stringsFailed，其余串一条不许多丢', () => {
  // 靠 table 造：'auto' 是合法项，中间那项写一个落在缓冲区外的偏移。
  // 只把坏字节塞进数据区是测不到这一格的 —— 表里的偏移仍然合法，解析器读到的是别的形状。
  const r = forensics(buildDex({
    entries: ['good1', 'x', 'good2'],
    table: ['auto', 0x7fff0000, 'auto'],
  }), 'classes.dex');
  assert.equal(r.parseError, undefined);
  assert.equal(r.stringsFailed, 1, '越界的偏移要数得出来，而不是整份拒或静默少一条');
  assert.equal(r.stringIdsSize, 3);
  assert.deepEqual(r.strings.map((x) => x.s), ['good1', 'good2']);
  assert.equal(r.stringsDecoded, 2);
  assert.equal(r.stringsDecoded + r.stringsFailed, r.stringIdsSize, '可读 + 失败 必须正好铺满声明的总数');
});

test('DX-13 非法 MUTF-8（四字节起头 / 非最短形式）⇒ 两种都数进 stringsFailed，池子其余照读', () => {
  const badFour = Buffer.concat([uleb(1), Buffer.from([0xf0, 0x9f, 0x98, 0x80, 0x00])]);
  const notShortest = Buffer.concat([uleb(1), Buffer.from([0xc1, 0x41, 0x00])]);
  const r = forensics(buildDex({ entries: ['ok1', { raw: badFour }, 'ok2', { raw: notShortest }] }), 'classes.dex');
  assert.equal(r.parseError, undefined);
  assert.equal(r.stringsFailed, 2, `两种非法形状都要数到，实得 ${r.stringsFailed}`);
  assert.deepEqual(r.strings.map((x) => x.s), ['ok1', 'ok2']);
});

test('DX-14 裸 0x00 是终止符不是字符：中途遇见它就收口，剩下的字节不算这条的一部分', () => {
  // MUTF-8 里 U+0000 必须编成 0xC0 0x80；所以 `a` + 裸 0x00 + `b` 读出来是 "a"，
  // 而把后面那截 `b` 也拼进去就等于替投稿者把两条串合成一条 —— 行号与串序号的对应当场错一位。
  const raw = Buffer.concat([uleb(3), Buffer.from([0x61, 0x00, 0x62, 0x00])]);
  const r = forensics(buildDex({ entries: [raw, 'tail'] }), 'classes.dex');
  assert.deepEqual(r.strings.map((x) => x.s), ['a', 'tail']);
});

test('DX-15 真正的 U+0000（0xC0 0x80）是一个字符，不许把这一条判成 terminated', () => {
  const raw = Buffer.concat([uleb(2), Buffer.from([0xc0, 0x80, 0x7a, 0x00])]);
  const r = forensics(buildDex({ entries: [raw] }), 'classes.dex');
  assert.equal(r.strings.length, 1);
  assert.equal(r.strings[0].s, '\u0000z', '两字节形式必须解成 U+0000');
  assert.equal(r.stringsFailed, 0);
  assert.equal(r.stringsUnterminated, 0);
});

test('DX-16 声明的 code unit 数与实读不一致 ⇒ 单独计数，串仍然进可读面（到 NUL 收口才权威）', () => {
  const liar = Buffer.concat([uleb(99), Buffer.from('truth', 'utf8'), Buffer.from([0x00])]);
  const r = forensics(buildDex({ entries: [liar, 'clean'] }), 'classes.dex');
  assert.equal(r.stringsSizeMismatch, 1, `声明与实际不符要数得出来，实得 ${r.stringsSizeMismatch}`);
  assert.deepEqual(r.strings.map((x) => x.s), ['truth', 'clean'], '不符不等于不可读，静默丢它才是丢证据');
});

test('DX-17 长度前缀本身读不出来（uleb128 跨过缓冲区末尾）⇒ 整份拒，不给任何计数', () => {
  // 与 DX-12 / DX-13 的区别写在这儿：那两种是「这一项坏、其余可数」；这一种是「这张表还剩多少条
  // 能读**无从判断**」。所以它必须走 parseError，不能报一个 stringsFailed —— 报了就是猜。
  // 造法：把第二项的偏移指到缓冲区最后一个字节，再就地把它写成 0xFF（continuation 位还亮着）。
  const total = 0x90;
  const r = forensics(buildDex({
    entries: ['ok', Buffer.from([0x41, 0x00])],
    total,
    table: ['auto', total - 1],
    patch: (b) => { b[total - 1] = 0xff; },
  }), 'classes.dex');
  assert.match(r.parseError, /uleb128/, `长度前缀坏了要说得出是哪一处：${r.parseError}`);
  assertNoReadings(r, 'uleb128 越界');
});

// ---------------------------------------------------------------------------
// E 组：不判档 —— 这一层的边界由源码本身守着
// ---------------------------------------------------------------------------

test('DX-18 本模块一个字都不判：源码里没有 severity、没有 category、没有第二条字面值判据', () => {
  const src = readFileSync(new URL('./dex-forensics.mjs', import.meta.url), 'utf8');
  for (const forbidden of ['severity', 'category', "'high'", "'medium'", "'low'", "'info'"]) {
    assert.equal(src.includes(forbidden), false, `dex-forensics 不许出现 ${forbidden}：判档是 risk-rules 的事`);
  }
  // 判据不许有第二份：这一层只摊平常量，识别 IP / URL 那件事留在 CONTENT_RULES
  const codeOnly = src.split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
  assert.equal(/\\d\{1,3\}\\./.test(codeOnly), false, '代码行里不许再写一份 IPv4 形状的正则');
  assert.equal(/https?:\\\/\\\//.test(codeOnly), false, '代码行里不许再写一份 URL 判据');
});

// ---------------------------------------------------------------------------
// F 组：串表面喂入的形状不变量
// ---------------------------------------------------------------------------

test('DX-19 一串一行：串里的 LF/CR 被转义、控制字符不落进喂入面，行号才等于串序号', () => {
  // 那枚 U+0000 走合法 MUTF-8 形式（0xC0 0x80）进来：写成 JS 字面量 '\u0000' 会被 buildDex
  // 用 utf8 编成裸 0x00，那在这一层是**终止符**，测的就不是转义而是终止了（DX-14 守那一格）。
  const nul = Buffer.concat([uleb(2), Buffer.from([0x6e, 0xc0, 0x80, 0x00])]);
  const r = forensics(buildDex({
    entries: ['line1\nline2', 'tab\there', { raw: nul }, 'plain'],
  }), 'classes.dex');
  assert.equal(r.parseError, undefined);
  const s = dexStringSurface(r);
  assert.equal(s.lines, 4, `四条串就该有四行，实得 ${s.lines}`);
  const rows = s.text.split('\n');
  assert.equal(rows.length, 4, '喂入面自身的行数必须等于串数 —— 多一行就说明某条串里还留着裸 LF');
  assert.equal(rows[0], 'line1\\nline2', 'LF 要变成可见的两字符转义，人复现时看得见那本来是个换行');
  assert.equal(rows[2], 'n\uFFFD', '合法的 U+0000 解出来了，但裸控制字符不许落进喂入面');
  assert.equal(s.escaped, 3, 'LF / TAB / U+0000 各一处，都要数到');
  assert.equal(s.text.includes('\u0000'), false, '喂入面里不许有裸 NUL（T57-15 那根钉子的同一族规矩）');
});

test('DX-20 单串上限才是对症的那一闸：长串被截、trimmed 计数，短串一个都不许多切', () => {
  const long = 'a'.repeat(DEX_SURFACE_LINE_MAX + 900);
  const r = forensics(buildDex({ entries: ['ip=203.0.113.9', long, 'tail'] }), 'classes.dex');
  const s = dexStringSurface(r, { lineMax: 200, budgetBytes: 1 << 20 });
  assert.equal(s.trimmed, 1, `只有那条超长串该被截，实得 ${s.trimmed}`);
  assert.equal(s.lines, 3);
  const rows = s.text.split('\n');
  assert.ok(rows[1].length <= 200, '被截的那条不许超过给定单串上限');
  assert.equal(rows[0], 'ip=203.0.113.9', '未超限的串一个字都不许多切');
  // 真夹具走默认值时必须一个字节都不切（它是给默认档当反例用的：正经串被切就是判据漏了）
  const real = dexStringSurface(forensics(FIX('d8-minimal.dex'), 'classes.dex'));
  assert.equal(real.trimmed, 0, '真夹具的串都在单串上限内，默认档不该动它');
  assert.equal(real.dropped, 0);
});

test('DX-21 预算吃紧时 dropped 必须报出"还剩多少条一个字都没喂"，不许静默读短', () => {
  const many = Array.from({ length: 12 }, (_, i) => `payload${i}.example.invalid/${'x'.repeat(30)}`);
  const r = forensics(buildDex({ entries: many }), 'classes.dex');
  assert.equal(dexStringSurface(r, { budgetBytes: 0 }).dropped, 12, '预算 0 ⇒ 一条都没喂，dropped 要说 12');
  assert.equal(dexStringSurface(r, { budgetBytes: 0 }).lines, 0);
  const half = dexStringSurface(r, { budgetBytes: 200 });
  assert.ok(half.lines > 0 && half.lines < 12, `夹在中间时两个数都该非零：${half.lines} / ${half.dropped}`);
  assert.equal(half.lines + half.dropped, 12, '喂进去的 + 丢掉的 == 池子条数，一格都不许少');
  // 默认档必须真的兜得住这枚小夹具（否则默认档就成了"每次都截断"，那和没接一样）
  assert.equal(dexStringSurface(r).dropped, 0);
});

test('DX-22 串面函数对"读不出来"的记录不许抛，也不许凭空造出一行', () => {
  for (const bad of [null, undefined, {}, { parseError: 'x' }, { strings: null }]) {
    const s = dexStringSurface(bad);
    assert.equal(s.lines, 0, `${JSON.stringify(bad)} 必须读出 0 行`);
    assert.equal(s.dropped, 0, '没有池子就没有"被丢弃"，不许把 parseError 念成丢过东西');
    assert.equal(s.text, '');
  }
});

test('DX-23 这一层的预算与 24 KB 那条条目级上限是两把不同的闸，不许并成一把', () => {
  // 并掉的后果不是"少读一点"，是**这一层直接失效**：实测同一枚真 dex（23,213 条串）在 24 KB 预算下
  // 只喂得进 44 行、丢掉 23,169 条。留两条闸、并让这条测试盯着它们不相等。
  assert.ok(DEX_SURFACE_MAX_BYTES > MAX_SCAN_BYTES_PER_ENTRY,
    `串面预算必须大于条目级上限，否则这一层等于没接线：${DEX_SURFACE_MAX_BYTES} vs ${MAX_SCAN_BYTES_PER_ENTRY}`);
  assert.ok(Number.isInteger(DEX_SURFACE_LINE_MAX) && DEX_SURFACE_LINE_MAX > 0);
  assert.ok(Number.isInteger(DEX_STRING_SAMPLE_CAP) && DEX_STRING_SAMPLE_CAP > 0);
});

test('DX-24 真夹具上做 24 处单字节翻转：永不抛；要么读出来，要么 parseError 且不带任何读数', () => {
  const base = FIX('d8-minimal.dex');
  const seen = { ok: 0, refused: 0 };
  for (let i = 0; i < 24; i++) {
    const at = (i * 71 + 13) % base.length;
    const buf = Buffer.from(base);
    buf[at] = buf[at] ^ 0xff;
    const r = forensics(buf, 'classes.dex');
    assert.notEqual(r, undefined, `第 ${i} 处翻转返回了 undefined（字节 ${at}）`);
    if (r === null) continue;                                 // 翻转把魔数改掉了 ⇒ 不归本模块管，合法结果
    if (r.parseError) { seen.refused++; assertNoReadings(r, `翻转@${at}`); continue; }
    seen.ok++;
    assert.ok(Number.isInteger(r.stringsDecoded), `翻转@${at}：读出来就必须有可数的串数`);
  }
  assert.ok(seen.refused + seen.ok > 0, '这一组翻转必须至少留下一格读数，否则测试是空跑的');
});


