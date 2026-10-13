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
    exclude = null,        // RegExp（整行命中则跳过）或 (match, line) => boolean
    severityFor = null,    // (match, line) => severity，用于同一规则内分档；返回 null 表示不构成发现
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
      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      for (let i = 0; i < lines.length && findings.length < maxPerFile; i++) {
        const line = lines[i];
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
            const skipped = typeof exclude === 'function' ? exclude(m, line) : exclude.test(line);
            if (skipped) continue;                      // 这个匹配可豁免；别的匹配未必
          }
          const sev = typeof severityFor === 'function' ? severityFor(m, line) : severity;
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
  pattern: /(?:^|[|;&`(]\s*)(?:curl|wget|busybox\s+wget|busybox\s+curl)\b[^\n|]*\|[^\n]*\b(?:sh|bash|ash|ksh|zsh|python3?|perl|su)\b|\b(?:sh|bash|ash)\s*<\(\s*(?:curl|wget)\b/,
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
 * 三个条件同时成立才算清单（条件③是刻意留的：行尾停在路径上时它更像「拿第二个路径当参数执行第一个」，
 * 那一支照旧说话，所以 `$MODDIR/payload.bin $MODDIR/cfg` 仍然是发现）：
 *   ① 空白分词后 ≥2 个 token 以模块目录前缀开头（只有一个不算：`$MODDIR/tool.bin` 单独一行就是执行）；
 *   ② 其余 token 只能是重定向（`2>/dev/null`）、续行反斜杠或引号残留 —— 混进任何别的词（选项、参数、
 *      管道）就不当它是清单；
 *   ③ 行尾停在续行反斜杠或重定向上。
 * 这条豁免只作用于「报不报」：scan.mjs 的 resolveBundledRefs 跑的是原始 pattern、不看 exclude，
 * 所以清单行引用的条目照样被拉进扫描面逐行读（见 scan.test.mjs 的 fix5-F1 端到端用例）。
 */
const MOD_PATH_TOKEN = /^(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)/;
// 命令位那一支的行首匹配：整个匹配从「可选引号 + 模块路径」开始，里面没有任何动词。
const BARE_MOD_PATH_MATCH = /^["']?(?:\$\{?(?:MODPATH|MODDIR|TMPMODDIR)\}?[\\/]|\/data\/adb\/modules\/)/;
const UNQUOTE_EDGE = /^["']+|["']+$/g;

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

export const EXEC_BUNDLED_FILE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'EXEC_BUNDLED_FILE', category: 'execution', severity: 'high',
  title: '脚本执行模块自带的另一个文件',
  // 注释行里的引用不是执行，按本仓既有先例豁免（HARDCODED_IP / SUSPICIOUS_DOMAIN / PRIVACY_SECRET
  // 都用 exclude: /^\s*#/）。豁免只作用于「报不报」：被引用的条目照样进扫描面，
  // 见 scan.mjs 的 resolveBundledRefs —— 它跑的是原始 pattern，不看 exclude。
  // fix5-F1 追加第二条豁免：纯模块路径清单（上一条命令的参数续行）不是执行，见上面
  // isModulePathListLine 的三个判据。它只看「行首那一支」的匹配，动词式与 `&&`/`||`/`(`/`;`
  // 之后的那一支照旧说话（实测真包里 `$(…)` 与 JS 的 exec('…') 都走后面那一支）。
  exclude(m, line) {
    if (/^\s*#/.test(line)) return true;
    if (!BARE_MOD_PATH_MATCH.test(m[0])) return false;       // 不是行首那一支，管不着
    if (!/^[\s]*$/.test(line.slice(0, m.index))) return false; // 前面还有词，不是行首形态
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
export const SELINUX_TYPE_PERMISSIVE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SELINUX_TYPE_PERMISSIVE', category: 'root', severity: 'high',
  title: 'permissive/typepermissive 关掉整个域的 SELinux 强制',
  advice: 'permissive 让该域的所有拒绝降级为只记日志，等同把这台机器上的一个域移出强制访问控制；'
    + '必须人工确认放开的是哪个域、模块自称的功能为什么需要它。',
  exclude: isDocOnlyMention,
  pattern: /(?:^\s*(?:type)?permissive\s+(?:\{[^}]*\}|[A-Za-z0-9_.\-:]+)|[^\w](?:type)?permissive\s+(?:\{[^}]*\}|[A-Za-z0-9_.\-:]+(?:\s+[A-Za-z0-9_.\-:]+)*)\s*;)/,
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

export const DEBUGGABLE_ENABLE = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'DEBUGGABLE_ENABLE', category: 'root', severity: 'medium', title: '改变整机安全档位',
  // 同样要覆盖 `.prop` 里的 `key=value` 形态，见下面那条 PROP_* 的说明；这里管脚本里的 set/resetprop。
  // `[=\s]+[01]\b` 是它的收窄条件：`resetprop ro.debuggable`（只删不改）、
  // `resetprop -w ro.debuggable $VALUE`（值走变量）、`getprop ro.debuggable`（只读）都不命中。
  // fix3-P7：两处 `[^\n]*` 一并换成 `[^|;&\n]*`（同 VERIFIED_BOOT_SPOOF 的理由）——
  // `echo "setprop ro.secure 0"; setprop ro.secure 0` 实测曾经 matches=1（两条命令被贪心 span 并成一个匹配）
  // → 整行被豁免 → 0 findings。锁成「动词、键名、值都在同一条命令里」之后是两个匹配，前半行豁免、后半行照报。
  exclude: isDocOnlyMention,
  pattern: /(?:^|[\s"';&|`(])(?:resetprop|setprop)[^|;&\n]*\bro\.(?:debuggable|secure)\b[^|;&\n]*[=\s]+[01]\b/,
  advice: 'ro.debuggable / ro.secure 会改变整机安全档位，作者必须在描述里说明理由。',
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
const WEAKEN_KEYS = '(?:ro\\.debuggable\\s*=\\s*1|ro\\.secure\\s*=\\s*0|ro\\.adb\\.secure\\s*=\\s*0|service\\.adb\\.root\\s*=\\s*1)(?![0-9.])';
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

export const SUSPICIOUS_DOMAIN = makeLineRule({
  anchor: 'anywhere', // fix4-P14：载荷出现在一行里任何位置都算（闭包表会用「x=1; 」前缀逐条验证）
  id: 'SUSPICIOUS_DOMAIN',
  category: 'network',
  severity: 'medium',
  title: '可疑域名（免费/匿名 TLD 或遥测广告特征）',
  advice: '确认该域名用途。遥测/广告 SDK 域名在 root 模块中出现需作者明确说明。',
  pattern: /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b/i,
  exclude: /^\s*#|localhost|android\.com|github\.com|githubusercontent\.com|magisk|kernelsu|kernelsu\.org|topjohnwu|google\.com|googleapis\.com|gstatic\.com|w3\.org|schema\.org|json\.org|example\.com/,
  severityFor(m) {
    const host = m[0].toLowerCase();
    if (SUSPICIOUS_KEYWORD.test(host)) return 'medium';
    if (SUSPICIOUS_TLD.test(host)) return 'medium';
    return null; // 返回 null 表示不构成发现
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

/** 内容读到了一半就截断 —— 人工复核看不全，属于覆盖度缺口，必须参与定级 */
export function checkCoverage(files = [], maxText = MAX_TEXT) {
  const out = [];
  for (const f of files) {
    if (!f || !f.truncated) continue;
    out.push({
      ruleId: 'AUDIT_COVERAGE_TRUNCATED',
      category: 'structure',
      severity: 'medium',
      file: String(f.name == null ? '' : f.name),
      line: 0,
      snippet: `${f.size} B`,
      message: `${f.name} 有 ${(f.size / 1048576).toFixed(2)} MB，报告只内嵌前 ${(maxText / 1024).toFixed(0)} KB`,
      advice: '行级规则跑的是全文，但人工复核与 PR 评论只能看到前缀。请不要把脚本塞到这么大；'
        + '确实需要长文件时把它拆成多个被引用的文件，或由人工下载产物通读。',
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

/** 二进制条目：行级规则对它无效，只能靠人/专门通道看 */
export function checkBinaries(binaries = []) {
  return (Array.isArray(binaries) ? binaries : []).map((b) => ({
    ruleId: 'STRUCT_BINARY',
    category: 'structure',
    severity: 'medium',
    file: String(b && b.name ? b.name : ''),
    line: 0,
    snippet: `${b.id} / ${b.bytes} B`,
    message: `${b.name} 是二进制负载（${b.why || b.id}），静态行级规则无法审查`,
    advice: '模块可以带二进制（busybox、update-binary 等），但它必须在 module.prop/描述里说明来源，'
      + '并给出可核对的上游或校验和；匿名可执行文件在 root 下运行等于把判断权交给机器码。',
  }));
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
 * @param {'low'|'medium'|'high'} level
 * @param {'first'|'update'|'unknown'} changeType
 */
export function decide(level, changeType) {
  if (level === 'low' && changeType === 'first') {
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
