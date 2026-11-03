#!/usr/bin/env node
/**
 * validate-proxies.mjs
 *
 * 校验 json/proxies.json —— 模块商店「GitHub 下载代理」的数据契约。
 *
 * 代理列表会被 App 直接拿来做字符串拼接：`baseUrl + GitHub 原始地址`。
 * 所以这里比普通展示字段更严：一旦混进带路径、带 query、带 userinfo 或
 * 非 443 端口的地址，App 那边拼出来的就是一个坏链接，而且下载失败只会
 * 表现为「网络错误」，没人会想到是索引里多了一个斜杠。
 *
 * 校验项：
 *   顶层  { schemaVersion(=1), lastUpdate(yyyy-MM-dd 且真实存在), proxies[] }
 *   proxy { id, name, baseUrl, note? }
 *   外加：proxies 非空且 ≤ 32 条；id 全局唯一、不是保留的 direct，且匹配
 *         ^[a-z0-9][a-z0-9-]{1,31}$；name 非空且 ≤ 40 字符；note 可选但 ≤ 60 字符；
 *         baseUrl 必须 https:// 开头、长度 ≤ 128、只有 host（无 path / query /
 *         fragment / userinfo / 非 443 端口），host 是纯 ASCII 域名（LDH，不是 IDN），
 *         且不与 GitHub 自己的下载域名重名；同一 host 只能出现一次。
 *
 * 口径来源：App 端 GithubProxy.ProxyUrl.isValidBaseUrl —— 长度 ≤ 128、https、
 * 只有 scheme + host、无 userinfo/query/fragment、端口 -1 或 443。索引这边
 * **只能更严不能更松**，否则会出现「索引里合法、App 解析时静默丢掉」：
 *   - 拒尾斜杠与大写 scheme：App 会 trimEnd('/') 并忽略 scheme 大小写，但索引只收
 *     规范形，免得同一个代理被写成两种、判重也判不到一起；
 *   - 拒 IDN 与下划线主机：java.net.URI 拿不到 host，App 那条 `continue` 没有任何日志；
 *   - 拒 GitHub 下载主机：App 的 parseProxyList 也会丢，写进 json 等于白写一条。
 * 宁可在这里报错让人改，也不要「保存成功」而用户端少一条。
 *
 * 用法：
 *   node scripts/validate-proxies.mjs [文件路径]   # 校验，退出码 0/1
 *   node scripts/validate-proxies.mjs --selftest   # 跑内置负例自测
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_PROXIES = path.join(REPO_ROOT, 'json', 'proxies.json');

/** App 侧只认这个版本；改结构必须同时改 App 解析器并升版本。 */
export const SCHEMA_VERSION = 1;
/** 上限不是技术极限，而是「一份人工核实的列表」的合理规模：太长必然有人没测就抄进来。 */
export const MAX_PROXIES = 32;
export const MAX_NAME_CHARS = 40;
export const MAX_NOTE_CHARS = 60;
/** App 端 ProxyUrl.MAX_PROXY_BASE_LENGTH 的同口径上限；超了 App 直接判废。 */
export const MAX_BASE_URL_CHARS = 128;
/** DNS 域名总长（RFC 1035）与单段长度；超了就算 App 能拼，实际也解析不到。 */
const MAX_HOST_CHARS = 253;
const MAX_LABEL_CHARS = 63;
/** 单段只许 ASCII 字母/数字/连字符（连字符不能打头收尾，另行判断）。 */
const LDH_LABEL_RE = /^[a-z0-9-]+$/i;
/**
 * GitHub 自己的下载域名，与 App 的 RegistryUrls.DOWNLOAD_HOSTS 同一份。
 * 代理主机写成它们只会把请求再套回 GitHub，App 解析时直接 `continue` 掉。
 */
export const GITHUB_DOWNLOAD_HOSTS = Object.freeze([
  'github.com',
  'objects.githubusercontent.com',
  'release-assets.githubusercontent.com',
]);
/** App 用它表示「不走代理」；远程清单里写这个 id 会被整条丢弃。 */
export const RESERVED_PROXY_ID = 'direct';
/** 2–32 位：首字符字母/数字，其余小写字母/数字/连字符（与 App 侧 id 规则一致）。 */
export const ID_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** yyyy-MM-dd 且真存在（2 月 30 日之类要挡住）。 */
export function isRealDate(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

/**
 * 检查 host 是不是一个 App 真能解析的 ASCII 域名。
 * 合法返回 null，否则返回一句人能直接照着改的中文说明。
 *
 * 为什么卡这么细：App 走 java.net.URI，`https://例え.jp`、`https://a_b.com`
 * 这类地址在 URI 里 host 为 null，isValidBaseUrl 直接 false，条目被静默跳过。
 * 索引这边先挡住，错误信息里能说清「为什么」，比 App 端无声少一条好排查。
 */
export function checkHostname(host) {
  if (!host) return 'host 为空';
  if (host.length > MAX_HOST_CHARS) {
    return `host 过长：${host.length} 字符（域名总长上限 ${MAX_HOST_CHARS}）`;
  }
  if (host.startsWith('.') || host.endsWith('.')) return 'host 不能以点开头或结尾';
  for (const label of host.split('.')) {
    if (label === '') return 'host 里有空的域名段（连续两个点）';
    if (label.length > MAX_LABEL_CHARS) {
      return `host 的某一段过长：${label.length} 字符（单段上限 ${MAX_LABEL_CHARS}）`;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return `host 的域名段不能以连字符开头或结尾：${JSON.stringify(label)}`;
    }
    if (!LDH_LABEL_RE.test(label)) {
      return (
        `host 只能含 ASCII 字母、数字、连字符和点：${JSON.stringify(label)} 含别的字符` +
        '（下划线不行；中文域名请先转 punycode，App 拿不到 host 会静默丢弃）'
      );
    }
  }
  if (GITHUB_DOWNLOAD_HOSTS.includes(host.toLowerCase())) {
    return 'host 是 GitHub 自己的下载域名，App 会直接丢弃该条（套娃没有意义，不是代理）';
  }
  return null;
}

/**
 * 检查 baseUrl 是否「只有 https 的 host」。
 * 合法返回 null，否则返回一句人能直接照着改的中文说明。
 *
 * 为什么不用 `new URL()` 一把梭：URL 会把 `https://a.com` 和 `https://a.com/`
 * 的 pathname 都归一成 `/`，分不清「裸 host」和「结尾多了个斜杠」。契约只收
 * scheme + host，且 App 是原样拼接，所以先按字面形状卡，再用 URL 校验 host/端口。
 */
export function checkBaseUrl(value) {
  if (value === undefined) return '缺失';
  if (typeof value !== 'string') return '必须是字符串';
  if (value.trim() === '') return '不能为空';
  if (value.length > MAX_BASE_URL_CHARS) {
    return `过长：${value.length} 字符（上限 ${MAX_BASE_URL_CHARS}，App 端超长会直接丢弃）`;
  }
  if (!value.startsWith('https://')) return '必须以 https:// 开头（只收 https 地址）';
  if (/\s/.test(value)) return '不能含空格';
  // 必须在 new URL() 之前挡：URL 会把 `例え.jp` 悄悄转成 punycode，看不出原样是 IDN。
  if (/[^\x21-\x7E]/.test(value)) {
    return '不能含非 ASCII 字符（中文域名请先转 punycode，App 拿不到 host 会静默丢弃）';
  }

  const authority = value.slice('https://'.length);
  if (authority === '') return 'host 为空';
  if (authority.includes('@')) return '不能带 userinfo（user:pass@）';
  if (authority.includes('?')) return '只能有 host，不能带 query';
  if (authority.includes('#')) return '只能有 host，不能带 fragment';
  if (authority.includes('/')) return '只能有 host，不能带路径（结尾的 / 也不行）';

  let url;
  try {
    url = new URL(value);
  } catch {
    return '不是合法的 https URL';
  }
  if (!url.hostname) return 'host 为空';

  const hostProblem = checkHostname(url.hostname);
  if (hostProblem) return hostProblem;

  // URL 会把默认端口 443 归一成空串，所以 port 非空就是显式写了别的端口。
  if (url.port !== '') return `只允许 443 端口（实际 ${url.port}）`;
  return null;
}

/**
 * @returns {{ok: boolean, errors: string[], proxyCount: number}}
 */
export function validateProxies(doc) {
  const errors = [];
  const push = (m) => errors.push(m);

  if (!isObject(doc)) {
    push('顶层必须是一个 JSON 对象');
    return { ok: false, errors, proxyCount: 0 };
  }
  if (doc.schemaVersion !== SCHEMA_VERSION) {
    push(`顶层 schemaVersion 必须是数字 ${SCHEMA_VERSION}`);
  }
  if (!isRealDate(doc.lastUpdate)) {
    push('顶层 lastUpdate 必须是 yyyy-MM-dd 且真实存在的日期');
  }
  if (!Array.isArray(doc.proxies)) {
    push('顶层缺少 proxies 数组（没有可用代理时也要发一份合法的空列表，别让 App 拿到 404）');
    return { ok: false, errors, proxyCount: 0 };
  }
  if (doc.proxies.length === 0) {
    push('proxies 不能是空数组（列表为空就删掉这个文件走直连，别装作有代理）');
  }
  if (doc.proxies.length > MAX_PROXIES) {
    push(`proxies 最多 ${MAX_PROXIES} 条（当前 ${doc.proxies.length} 条）`);
  }

  const seenIds = new Map();
  const seenHosts = new Map();

  doc.proxies.forEach((proxy, i) => {
    const at = `proxies[${i}]`;
    if (!isObject(proxy)) {
      push(`${at} 不是对象`);
      return;
    }

    // ── id：稳定标识，改地址时应保持不变 ────────────────────────────────────
    if (proxy.id === undefined) {
      push(`${at} 缺少字段 id`);
    } else if (typeof proxy.id !== 'string') {
      push(`${at}.id 必须是字符串`);
    } else if (proxy.id.trim() === '') {
      push(`${at}.id 不能为空`);
    } else if (!ID_RE.test(proxy.id)) {
      push(
        `${at}.id 不合法：${JSON.stringify(proxy.id)}` +
          '（须匹配 ^[a-z0-9][a-z0-9-]{1,31}$：2–32 位小写字母/数字/连字符，首字符不能是 -）',
      );
    } else if (proxy.id === RESERVED_PROXY_ID) {
      push(
        `${at}.id 不能是 ${JSON.stringify(RESERVED_PROXY_ID)}` +
          '（App 保留给「直连」，远程清单里写它会整条被丢弃）',
      );
    } else if (seenIds.has(proxy.id)) {
      push(`${at}.id 重复：${proxy.id}（另见 proxies[${seenIds.get(proxy.id)}]）`);
    } else {
      seenIds.set(proxy.id, i);
    }

    // ── name：展示名，通常就是 host ─────────────────────────────────────────
    if (proxy.name === undefined) {
      push(`${at} 缺少字段 name`);
    } else if (typeof proxy.name !== 'string') {
      push(`${at}.name 必须是字符串`);
    } else if (proxy.name.trim() === '') {
      push(`${at}.name 不能为空`);
    } else if (proxy.name.length > MAX_NAME_CHARS) {
      push(`${at}.name 过长：${proxy.name.length} 字符（上限 ${MAX_NAME_CHARS}）`);
    }

    // ── note：可选，一句人话备注 ────────────────────────────────────────────
    if (proxy.note !== undefined) {
      if (typeof proxy.note !== 'string') {
        push(`${at}.note 必须是字符串（没有备注就删掉这个字段，不要写 null）`);
      } else if (proxy.note.length > MAX_NOTE_CHARS) {
        push(`${at}.note 过长：${proxy.note.length} 字符（上限 ${MAX_NOTE_CHARS}）`);
      }
    }

    // ── baseUrl：拼接前缀，形状错一个字符就是坏链接 ────────────────────────
    const urlProblem = checkBaseUrl(proxy.baseUrl);
    if (urlProblem) {
      push(`${at}.baseUrl ${urlProblem}`);
      return;
    }
    // 只按 host 判重：大小写、显式 :443 都不该算成两个不同代理。
    const host = new URL(proxy.baseUrl).hostname.toLowerCase();
    if (seenHosts.has(host)) {
      push(`${at}.baseUrl 与 proxies[${seenHosts.get(host)}] 重复：${proxy.baseUrl}`);
    } else {
      seenHosts.set(host, i);
    }
  });

  return { ok: errors.length === 0, errors, proxyCount: doc.proxies.length };
}

/** 从文件读并校验；文件不存在也算失败（App 的拉取地址必须始终 200）。 */
export function validateProxiesFile(file = DEFAULT_PROXIES) {
  if (!fs.existsSync(file)) {
    return { ok: false, errors: [`文件不存在：${file}`], proxyCount: 0 };
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, errors: [`JSON 解析失败：${e.message}`], proxyCount: 0 };
  }
  return validateProxies(doc);
}

// ── 内置负例自测 ────────────────────────────────────────────────────────────
// 校验器的价值在于「坏数据进不来」，而不是「好数据能过」。下面每条负例都必须被挡住，
// 少挡一条就说明规则退化了 —— 用 --selftest 跑一遍，不需要联网、不读仓库文件。

function selfTestBase() {
  return {
    schemaVersion: 1,
    lastUpdate: '2026-11-04',
    proxies: [
      { id: 'gh-proxy-org', name: 'gh-proxy.org', baseUrl: 'https://gh-proxy.org', note: '实测最快' },
      { id: 'gh-proxy-com', name: 'gh-proxy.com', baseUrl: 'https://gh-proxy.com', note: '稳定' },
    ],
  };
}

const SELF_TEST_CASES = [
  {
    label: 'http 地址',
    expect: /proxies\[0\]\.baseUrl 必须以 https:\/\//,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'http://gh-proxy.org';
    },
  },
  {
    label: '带路径',
    expect: /proxies\[0\]\.baseUrl 只能有 host，不能带路径/,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'https://gh-proxy.org/gh/';
    },
  },
  {
    label: '重复 id',
    expect: /proxies\[1\]\.id 重复：gh-proxy-org/,
    mutate(doc) {
      doc.proxies[1].id = 'gh-proxy-org';
    },
  },
  {
    label: '重复 baseUrl',
    expect: /proxies\[1\]\.baseUrl 与 proxies\[0\] 重复/,
    mutate(doc) {
      doc.proxies[1].baseUrl = 'https://gh-proxy.org';
    },
  },
  {
    label: '坏日期',
    expect: /lastUpdate 必须是 yyyy-MM-dd/,
    mutate(doc) {
      doc.lastUpdate = '2026-02-30';
    },
  },
  {
    label: '缺 proxies',
    expect: /缺少 proxies 数组/,
    mutate(doc) {
      delete doc.proxies;
    },
  },
  {
    label: '非 443 端口',
    expect: /只允许 443 端口/,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'https://gh-proxy.org:8443';
    },
  },
  {
    // App 的 MAX_PROXY_BASE_LENGTH = 128，超了直接判废；索引这里不挡就会「存得进、用不了」。
    label: '超长 baseUrl',
    expect: /proxies\[0\]\.baseUrl 过长：\d+ 字符（上限 128/,
    mutate(doc) {
      doc.proxies[0].baseUrl = `https://${'a'.repeat(120)}.com`;
    },
  },
  {
    // java.net.URI 对下划线主机的 host 为 null，App 会静默跳过这一条。
    label: '主机带下划线',
    expect: /proxies\[0\]\.baseUrl host 只能含 ASCII 字母、数字、连字符和点/,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'https://gh_proxy.org';
    },
  },
  {
    label: 'IDN 中文域名',
    expect: /proxies\[0\]\.baseUrl 不能含非 ASCII 字符/,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'https://例え.jp';
    },
  },
  {
    // 与 App 的 RegistryUrls.DOWNLOAD_HOSTS 重名：App 解析时直接 continue。
    label: 'GitHub 下载主机',
    expect: /proxies\[0\]\.baseUrl host 是 GitHub 自己的下载域名/,
    mutate(doc) {
      doc.proxies[0].baseUrl = 'https://github.com';
    },
  },
  {
    // `direct` 是「不走代理」的保留 id，远程清单里写它会被 App 整条丢掉。
    label: '保留 id direct',
    expect: /proxies\[0\]\.id 不能是 "direct"/,
    mutate(doc) {
      doc.proxies[0].id = 'direct';
    },
  },
];

/**
 * 跑内置自测，返回失败项数（0 = 全过）。
 *
 * 不在这里设 process.exitCode：由 CLI 入口决定退出码，测试里 import 也不会污染 --test 进程。
 */
export function runSelfTest(log = console) {
  log.log('代理列表校验自测：');
  let failures = 0;

  const positive = validateProxies(selfTestBase());
  if (positive.ok) {
    log.log('  ✓ 正例（2 条合法代理）通过');
  } else {
    failures += 1;
    log.error(`  ✗ 正例本应通过，却报错：${JSON.stringify(positive.errors)}`);
  }

  for (const testCase of SELF_TEST_CASES) {
    const doc = selfTestBase();
    testCase.mutate(doc);
    const result = validateProxies(doc);
    const hit = result.errors.find((e) => testCase.expect.test(e));
    if (!result.ok && hit) {
      log.log(`  ✓ ${testCase.label}：已挡住（${hit}）`);
    } else {
      failures += 1;
      log.error(`  ✗ ${testCase.label}：没挡住（errors=${JSON.stringify(result.errors)}）`);
    }
  }

  if (failures > 0) {
    log.error(`自测失败：${failures} 项`);
    return failures;
  }
  log.log(`自测通过：${SELF_TEST_CASES.length} 条负例全部被挡住，正例通过`);
  return 0;
}

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  if (process.argv.includes('--selftest')) {
    if (runSelfTest() > 0) process.exitCode = 1;
  } else {
    const file = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_PROXIES;
    const result = validateProxiesFile(file);
    if (result.ok) {
      console.log(`✓ ${path.relative(REPO_ROOT, file)} 通过：${result.proxyCount} 个代理`);
    } else {
      console.error(`✗ ${path.relative(REPO_ROOT, file)} 有 ${result.errors.length} 处问题：`);
      for (const e of result.errors) console.error(`  - ${e}`);
      process.exitCode = 1;
    }
  }
}
