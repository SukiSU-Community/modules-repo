// 模块投稿安全审核 —— 判定规则表（纯函数，无 I/O，便于单测）
//
// 每条规则是一个对象：
//   id        规则唯一 id
//   category  分类：dangerous / network / privacy / metadata
//   severity  默认风险等级：info / low / medium / high
//   title     人读标题
//   advice    处置建议
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

function makeLineRule(spec) {
  const {
    id, category, title, advice,
    severity = 'medium',
    pattern,               // RegExp，用于逐行匹配
    exclude = null,        // RegExp（整行命中则跳过）或 (match, line) => boolean
    severityFor = null,    // (match, line) => severity，用于同一规则内分档；返回 null 表示不构成发现
    maxPerFile = 20,       // 同一文件同一规则最多报多少条，防止刷屏
  } = spec;

  return {
    id, category, title, advice, severity,
    // 暴露 pattern 供报告渲染时对脚本全文做隐私脱敏（见 scan.mjs redactText）
    pattern,
    scan(file, text) {
      const findings = [];
      const lines = String(text == null ? '' : text).split(/\r?\n/);
      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      for (let i = 0; i < lines.length && findings.length < maxPerFile; i++) {
        const line = lines[i];
        const re = new RegExp(pattern.source, flags);
        const m = re.exec(line);
        if (!m) continue;
        if (exclude) {
          const skipped = typeof exclude === 'function' ? exclude(m, line) : exclude.test(line);
          if (skipped) continue;
        }
        const sev = typeof severityFor === 'function' ? severityFor(m, line) : severity;
        if (sev === null || sev === undefined) continue; // 规则内判定为“不构成发现”
        findings.push({
          ruleId: id,
          category,
          severity: sev,
          file,
          line: i + 1,
          snippet: trimSnippet(m[0]),
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
  id: 'PIPE_TO_SHELL',
  category: 'dangerous',
  severity: 'high',
  title: '下载内容直连 shell 执行（curl|sh / wget|sh）',
  advice: '禁止。远程内容可在 root 下任意执行且无法审计，必须先落盘、校验校验和，再执行。',
  pattern: /(?:^|[|;&`(]\s*)(?:curl|wget|busybox\s+wget|busybox\s+curl)\b[^\n|]*\|[^\n]*\b(?:sh|bash|ash|ksh|zsh|python3?|perl|su)\b|\b(?:sh|bash|ash)\s*<\(\s*(?:curl|wget)\b/,
});

export const DOWNLOAD_TO_STDOUT = makeLineRule({
  id: 'DOWNLOAD_TO_STDOUT',
  category: 'dangerous',
  severity: 'low',
  title: '下载工具接收标准输出（wget -O- / curl -o-）',
  advice: '若后续接管道执行即为“直连执行”（见 PIPE_TO_SHELL）；仅落盘使用时可放行。',
  pattern: /\bwget\b[^\n]*\s-O\s*-|\bcurl\b[^\n]*\s-o\s*-|\bcurl\b[^\n]*\s--output\s+-/,
});

export const OBFUSCATED_DECODE_EXEC = makeLineRule({
  id: 'OBFUSCATED_DECODE_EXEC',
  category: 'dangerous',
  severity: 'high',
  title: 'base64/xxd/openssl 混淆后直接执行',
  advice: '禁止。混淆执行是绕过静态审核的典型手法，必须还原为明文脚本再提交。',
  pattern: /^(?=.*\b(?:base64|xxd|uudecode|openssl\s+enc|busybox\s+base64)\b)(?=.*(?:\|\s*(?:sh|bash|ash)\b|\beval\b|>\s*\S+\s*(?:&&|;)\s*(?:sh|bash|ash)\b)).*$/,
});

export const OBFUSCATED_DECODE_ONLY = makeLineRule({
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
  id: 'WRITE_SYSTEM_VENDOR',
  category: 'dangerous',
  severity: 'high',
  title: '直接写入或重挂载 /system、/vendor 分区',
  advice: 'Magisk/KernelSU 模块应通过 $MODPATH/system 覆盖层修改，不得直接写真实分区；直接写会破坏 dm-verity 与 OTA。',
  pattern: /(?:\btouch\b|\bcp\b|\bmv\b|\bdd\b|\bmkdir\b|\bsed\s+-i\b|\btee\b|>>?)[^\n]*\/(?:system|vendor|product|system_ext|odm)\/|\bmount\b[^\n]*-o[^\n]*\b(?:rw|remount)\b|\bremount\b|\bmount\s+-o\s+rw[^\n]*\/(?:system|vendor)\b/,
  exclude: MODULE_OWN_DIR, // $MODPATH/system/... 是标准覆盖层写法
});

export const SELINUX_DISABLE = makeLineRule({
  id: 'SELINUX_DISABLE',
  category: 'dangerous',
  severity: 'high',
  title: '禁用/放宽 SELinux（setenforce 0）',
  advice: '禁止。关闭 SELinux 会让设备上所有应用失去强制访问控制，属于全局降级。',
  pattern: /\bsetenforce\s+(?:0|permissive)\b|[>]\s*\/sys\/fs\/selinux\/enforce\b|\bselinux\b[^\n]*=\s*0\b|\bsetprop\b[^\n]*selinux[^\n]*\b0\b/,
});

export const HOSTS_MODIFY = makeLineRule({
  id: 'HOSTS_MODIFY',
  category: 'dangerous',
  severity: 'medium',
  title: '修改 /system/etc/hosts',
  advice: '改 hosts 会全局劫持域名解析。广告屏蔽类模块属合法用途，但仍需人工确认拦截清单。',
  pattern: /(?:\btouch\b|\bcp\b|\bcat\b|\bsed\b|\becho\b|>>?|\bmount\b)[^\n]*\bhosts\b|\bhosts\b[^\n]*(?:>>?|\bsed\s+-i\b)/,
});

// ---------------------------------------------------------------------------
// ③ 外联
// ---------------------------------------------------------------------------

const PRIVATE_IP = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|255\.255\.255\.255$)/;

export const HARDCODED_IP = makeLineRule({
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
  DOWNLOAD_TO_STDOUT,
  OBFUSCATED_DECODE_EXEC,
  OBFUSCATED_DECODE_ONLY,
  WRITE_SYSTEM_VENDOR,
  SELINUX_DISABLE,
  HOSTS_MODIFY,
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
