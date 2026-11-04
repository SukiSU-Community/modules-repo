#!/usr/bin/env node
/**
 * validate-answers.mjs
 *
 * 校验 json/chunqiu-answers.json —— 「春秋检测红项 → 原因 → 修法」的解释层数据契约。
 *
 * 这份数据不是给人从头读到尾的，而是给 App 侧的 AI 当检索库用：用户看到春秋
 * 报了个红项，App 拿红项名去 entries 里找一条，再把 detect / cause / fix 讲给他听。
 * 所以这里卡的不是「字段好不好看」，而是「检索会不会静默失效」：
 *   - id 重复 → 引用它的地方（专栏步骤、诊断结论）指向哪一条全看遍历顺序，
 *     改一次解析脚本就可能换一条，属于最难复现的那种错；
 *   - fix 为空数组 → AI 只能编一个修法出来，比不回答更糟；
 *   - deviceTypes 写错一个字 → App 按设备型筛选时那一整类红项直接消失；
 *   - detect / cause 超长 → AI 塞进上下文时被截断，理由说到一半断掉。
 * 宁可在这里报错让人改，也不要「存得进去、用的时候不对」。
 *
 * 校验项：
 *   顶层  { schemaVersion(=1), source(https), sourceUpdatedAt(yyyy-MM-dd 且真实存在),
 *           updatedAt(yyyy-MM-dd 且真实存在，且不早于 sourceUpdatedAt), entries[] }
 *   entry { id, title, aliases[], chapter, detect, cause, fix[], deviceTypes[], link }
 *   外加：entries 1–1000 条；id 全仓唯一、kebab-case；title 非空且全仓不重复；
 *         aliases 1–32 条、互不重复、单条 ≤ 80 字符；chapter 非空；detect / cause 是
 *         字符串（可为空，手册里确实有只写判据不写原因的条目）且 ≤ 400 字符；
 *         fix 至少 1 条非空、单条 ≤ 200 字符；deviceTypes 只能取四个设备型枚举；
 *         link 必须 https。
 *
 * 口径来源：本仓 json/ 下其它文件的既有约定（columns.json 的一条一步、proxies.json
 * 的「索引只能更严不能更松」）+ 解析脚本 scripts（构建期在仓库外，不入库）。
 *
 * 用法：
 *   node scripts/validate-answers.mjs [文件路径]   # 校验，退出码 0/1
 *   node scripts/validate-answers.mjs --selftest   # 跑内置负例自测
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_ANSWERS = path.join(REPO_ROOT, 'json', 'chunqiu-answers.json');

/** App 侧只认这个版本；改结构必须同时改 App 解析器并升版本。 */
export const SCHEMA_VERSION = 1;
/**
 * 手册当前 136 条。上限留到 1000 是给手册长大用的，不是给「解析脚本把每个段落
 * 都当成一条」用的：真到一千条，说明章节结构已经变了，该人工看一眼。
 */
export const MAX_ENTRIES = 1000;
/** detect / cause 是「摘录」，超了就是没摘干净 —— AI 读到的会是被截断的半句话。 */
export const MAX_DETECT_CHARS = 400;
export const MAX_CAUSE_CHARS = 400;
/** fix 要能被 App 一条一条展示，超过一屏的修法本来也该拆成多步。 */
export const MAX_FIX_ITEM_CHARS = 200;
/** 检测项名都很短，超过这个长度基本是把整段正文塞进标题了。 */
export const MAX_TITLE_CHARS = 120;
export const MAX_ALIAS_COUNT = 32;
export const MAX_ALIAS_CHARS = 80;
/** 与 App 侧 DeviceType 枚举一一对应；顺序不影响语义。 */
export const DEVICE_TYPES = Object.freeze(['unlocked', 'fake-relock', 'ramdisk', 'self-signed']);
/** kebab-case：小写字母/数字分段，段间单个连字符（例 avb-version-2-0）。 */
export const ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
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
 * 检查是不是一个能直接放进 App 的 https 地址。
 * 合法返回 null，否则返回一句人能直接照着改的中文说明。
 *
 * 为什么不只判 `startsWith('https://')`：`https://` 后面可以是空的、可以带空格、
 * 可以是 `javascript:` 套娃。这里用 new URL() 真解析一遍，只收 http(s) 且必须 https。
 */
export function checkHttpsUrl(value) {
  if (value === undefined) return '缺失';
  if (typeof value !== 'string') return '必须是字符串';
  if (value.trim() === '') return '不能为空';
  if (!value.startsWith('https://')) return '必须以 https:// 开头（只收 https 地址）';
  if (/\s/.test(value)) return '不能含空格';
  let url;
  try {
    url = new URL(value);
  } catch {
    return '不是合法的 https URL';
  }
  if (url.protocol !== 'https:') return `协议必须是 https（实际 ${url.protocol}）`;
  if (!url.hostname) return 'host 为空';
  return null;
}

/** 「必须是字符串且非空」的通用小工具，统一错误措辞。 */
function requireNonEmptyString(value, at, label, errors) {
  if (value === undefined) {
    errors.push(`${at} 缺少字段 ${label}`);
    return false;
  }
  if (typeof value !== 'string') {
    errors.push(`${at}.${label} 必须是字符串`);
    return false;
  }
  if (value.trim() === '') {
    errors.push(`${at}.${label} 不能为空`);
    return false;
  }
  return true;
}

/**
 * @returns {{ok: boolean, errors: string[], entryCount: number}}
 */
export function validateAnswers(doc) {
  const errors = [];
  const push = (m) => errors.push(m);

  if (!isObject(doc)) {
    push('顶层必须是一个 JSON 对象');
    return { ok: false, errors, entryCount: 0 };
  }

  if (doc.schemaVersion !== SCHEMA_VERSION) {
    push(`顶层 schemaVersion 必须是数字 ${SCHEMA_VERSION}`);
  }
  const sourceProblem = checkHttpsUrl(doc.source);
  if (sourceProblem) push(`顶层 source ${sourceProblem}（应指向手册的上游仓库）`);
  if (!isRealDate(doc.sourceUpdatedAt)) {
    push('顶层 sourceUpdatedAt 必须是 yyyy-MM-dd 且真实存在的日期（手册最后一次改动日期）');
  }
  if (!isRealDate(doc.updatedAt)) {
    push('顶层 updatedAt 必须是 yyyy-MM-dd 且真实存在的日期（本次生成日期）');
  }
  if (isRealDate(doc.sourceUpdatedAt) && isRealDate(doc.updatedAt) && doc.updatedAt < doc.sourceUpdatedAt) {
    push('顶层 updatedAt 不能早于 sourceUpdatedAt（生成日期不该早于内容日期）');
  }

  if (!Array.isArray(doc.entries)) {
    push('顶层缺少 entries 数组');
    return { ok: false, errors, entryCount: 0 };
  }
  if (doc.entries.length === 0) {
    push('entries 不能是空数组（手册解析失败时不要把空列表发出去，App 会以为「没有红项」）');
  }
  if (doc.entries.length > MAX_ENTRIES) {
    push(`entries 最多 ${MAX_ENTRIES} 条（当前 ${doc.entries.length} 条）`);
  }

  const seenIds = new Map();
  const seenTitles = new Map();

  doc.entries.forEach((entry, i) => {
    const at = `entries[${i}]`;
    if (!isObject(entry)) {
      push(`${at} 不是对象`);
      return;
    }

    // ── id：稳定标识，App 侧可能拿它做深链或缓存键 ────────────────────────
    if (entry.id === undefined) {
      push(`${at} 缺少字段 id`);
    } else if (typeof entry.id !== 'string') {
      push(`${at}.id 必须是字符串`);
    } else if (entry.id.trim() === '') {
      push(`${at}.id 不能为空`);
    } else if (!ID_RE.test(entry.id)) {
      push(
        `${at}.id 不合法：${JSON.stringify(entry.id)}` +
          '（须是 kebab-case：小写字母/数字，用单个 - 连接，如 avb-version-2-0）',
      );
    } else if (seenIds.has(entry.id)) {
      push(`${at}.id 重复：${entry.id}（另见 entries[${seenIds.get(entry.id)}]）`);
    } else {
      seenIds.set(entry.id, i);
    }

    // ── title：手册里的检测项名，用户看到的就是它 ──────────────────────────
    if (requireNonEmptyString(entry.title, at, 'title', errors)) {
      if (entry.title.length > MAX_TITLE_CHARS) {
        push(`${at}.title 过长：${entry.title.length} 字符（上限 ${MAX_TITLE_CHARS}）`);
      }
      const key = entry.title.trim();
      if (seenTitles.has(key)) {
        push(`${at}.title 重复：${key}（另见 entries[${seenTitles.get(key)}]）`);
      } else {
        seenTitles.set(key, i);
      }
    }

    // ── aliases：AI 检索的入口，宁多勿少，但不能是垃圾 ─────────────────────
    if (!Array.isArray(entry.aliases)) {
      push(`${at}.aliases 必须是字符串数组`);
    } else if (entry.aliases.length === 0) {
      push(`${at}.aliases 至少要有一条（否则只能靠 title 精确命中）`);
    } else if (entry.aliases.length > MAX_ALIAS_COUNT) {
      push(`${at}.aliases 最多 ${MAX_ALIAS_COUNT} 条（当前 ${entry.aliases.length} 条）`);
    } else {
      const seenAliases = new Map();
      entry.aliases.forEach((alias, j) => {
        const aliasAt = `${at}.aliases[${j}]`;
        if (typeof alias !== 'string') {
          push(`${aliasAt} 必须是字符串`);
          return;
        }
        if (alias.trim() === '') {
          push(`${aliasAt} 不能为空`);
          return;
        }
        if (alias.length > MAX_ALIAS_CHARS) {
          push(`${aliasAt} 过长：${alias.length} 字符（上限 ${MAX_ALIAS_CHARS}）`);
        }
        const key = alias.toLowerCase();
        if (seenAliases.has(key)) {
          push(`${aliasAt} 与 aliases[${seenAliases.get(key)}] 重复：${alias}`);
        } else {
          seenAliases.set(key, j);
        }
      });
    }

    // ── chapter：手册大章，App 用来分组展示 ────────────────────────────────
    requireNonEmptyString(entry.chapter, at, 'chapter', errors);

    // ── detect / cause：原文摘录，允许为空（手册里有只写判据、不写原因的条目）──
    for (const [field, limit] of [
      ['detect', MAX_DETECT_CHARS],
      ['cause', MAX_CAUSE_CHARS],
    ]) {
      if (entry[field] === undefined) {
        push(`${at} 缺少字段 ${field}（没有内容就写空字符串，别删字段）`);
      } else if (typeof entry[field] !== 'string') {
        push(`${at}.${field} 必须是字符串`);
      } else if (entry[field].length > limit) {
        push(`${at}.${field} 过长：${entry[field].length} 字符（上限 ${limit}）`);
      }
    }

    // ── fix：唯一「必须能照着做」的字段，空数组等于让 AI 自己编 ─────────────
    if (!Array.isArray(entry.fix)) {
      push(`${at}.fix 必须是字符串数组`);
    } else if (entry.fix.length === 0) {
      push(`${at}.fix 至少要有一条（手册没给修法时写一句「手册未给出独立解决办法」，不要留空数组）`);
    } else {
      entry.fix.forEach((item, j) => {
        const itemAt = `${at}.fix[${j}]`;
        if (typeof item !== 'string') {
          push(`${itemAt} 必须是字符串`);
          return;
        }
        if (item.trim() === '') {
          push(`${itemAt} 不能为空（要么删掉这一条，要么写清楚怎么做）`);
          return;
        }
        if (item.length > MAX_FIX_ITEM_CHARS) {
          push(`${itemAt} 过长：${item.length} 字符（上限 ${MAX_FIX_ITEM_CHARS}，请拆成多条）`);
        }
      });
    }

    // ── deviceTypes：App 按设备型筛选用，写错一个字整类红项就消失 ────────────
    if (!Array.isArray(entry.deviceTypes)) {
      push(`${at}.deviceTypes 必须是字符串数组（不区分设备型就写空数组）`);
    } else {
      const seenTypes = new Map();
      entry.deviceTypes.forEach((type, j) => {
        const typeAt = `${at}.deviceTypes[${j}]`;
        if (typeof type !== 'string') {
          push(`${typeAt} 必须是字符串`);
          return;
        }
        if (!DEVICE_TYPES.includes(type)) {
          push(
            `${typeAt} 不合法：${JSON.stringify(type)}` +
              `（只能是 ${DEVICE_TYPES.join(' / ')}）`,
          );
          return;
        }
        if (seenTypes.has(type)) {
          push(`${typeAt} 与 deviceTypes[${seenTypes.get(type)}] 重复：${type}`);
        } else {
          seenTypes.set(type, j);
        }
      });
    }

    // ── link：手册站点，App 里是「查看完整说明」的跳转 ─────────────────────
    const linkProblem = checkHttpsUrl(entry.link);
    if (linkProblem) push(`${at}.link ${linkProblem}`);
  });

  return { ok: errors.length === 0, errors, entryCount: doc.entries.length };
}

/** 从文件读并校验；文件不存在也算失败（App 的拉取地址必须始终 200）。 */
export function validateAnswersFile(file = DEFAULT_ANSWERS) {
  if (!fs.existsSync(file)) {
    return { ok: false, errors: [`文件不存在：${file}`], entryCount: 0 };
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, errors: [`JSON 解析失败：${e.message}`], entryCount: 0 };
  }
  return validateAnswers(doc);
}

// ── 内置负例自测 ────────────────────────────────────────────────────────────
// 校验器的价值在于「坏数据进不来」，而不是「好数据能过」。下面每条负例都必须被挡住，
// 少挡一条就说明规则退化了 —— 用 --selftest 跑一遍，不需要联网、不读仓库文件。

function selfTestBase() {
  return {
    schemaVersion: 1,
    source: 'https://github.com/mingzun09/Chunqiu-Detector-Problem-solution',
    sourceUpdatedAt: '2026-11-02',
    updatedAt: '2026-11-05',
    entries: [
      {
        id: 'bootloader-unlock',
        title: 'Bootloader unlock / 解锁属性',
        aliases: ['Bootloader unlock', '解锁属性', 'ro.boot.flash.locked'],
        chapter: '一、属性、构建信息与文本配置',
        detect: '读取 `ro.boot.flash.locked` 等属性，0 表示已解锁。',
        cause: '',
        fix: ['真解锁设备：用密钥模块把解锁状态对检测器隐藏。'],
        deviceTypes: ['unlocked'],
        link: 'https://mingzun09.github.io/Chunqiu-Detector-Problem-solution/',
      },
      {
        id: 'avb-version-2-0',
        title: 'avb校验异常 avb=2.0',
        aliases: ['avb', 'avb=2.0', 'ro.boot.avb_version'],
        chapter: '一、属性、构建信息与文本配置',
        detect: '',
        cause: 'ro.boot.avb_version 与实际 vbmeta 版本不一致。',
        fix: ['更换模块后重启复测。'],
        deviceTypes: [],
        link: 'https://mingzun09.github.io/Chunqiu-Detector-Problem-solution/',
      },
    ],
  };
}

const SELF_TEST_CASES = [
  {
    // 重复 id 会让「按 id 引用红项」的地方指向不可预期的某一条。
    label: '重复 id',
    expect: /entries\[1\]\.id 重复：bootloader-unlock/,
    mutate(doc) {
      doc.entries[1].id = 'bootloader-unlock';
    },
  },
  {
    label: '坏日期',
    expect: /顶层 sourceUpdatedAt 必须是 yyyy-MM-dd/,
    mutate(doc) {
      doc.sourceUpdatedAt = '2026-02-30';
    },
  },
  {
    label: 'deviceTypes 非法',
    expect: /entries\[0\]\.deviceTypes\[0\] 不合法/,
    mutate(doc) {
      doc.entries[0].deviceTypes = ['fake_unlock'];
    },
  },
  {
    // 空 fix 等于让 AI 现场编一个修法，比不回答更糟。
    label: 'fix 空数组',
    expect: /entries\[0\]\.fix 至少要有一条/,
    mutate(doc) {
      doc.entries[0].fix = [];
    },
  },
  {
    label: 'title 空',
    expect: /entries\[0\]\.title 不能为空/,
    mutate(doc) {
      doc.entries[0].title = '   ';
    },
  },
  {
    label: 'link 非 https',
    expect: /entries\[0\]\.link 必须以 https:\/\//,
    mutate(doc) {
      doc.entries[0].link = 'http://mingzun09.github.io/';
    },
  },
  {
    // 首页示例 id 是 avb-version-2-0，用了下划线就说明生成脚本没按契约走。
    label: 'id 不是 kebab-case',
    expect: /entries\[1\]\.id 不合法/,
    mutate(doc) {
      doc.entries[1].id = 'avb_version_2_0';
    },
  },
  {
    label: '缺 entries',
    expect: /顶层缺少 entries 数组/,
    mutate(doc) {
      delete doc.entries;
    },
  },
  {
    label: 'entries 空数组',
    expect: /entries 不能是空数组/,
    mutate(doc) {
      doc.entries = [];
    },
  },
  {
    label: 'title 重复',
    expect: /entries\[1\]\.title 重复/,
    mutate(doc) {
      doc.entries[1].title = doc.entries[0].title;
    },
  },
  {
    label: 'fix 单条超长',
    expect: /entries\[0\]\.fix\[0\] 过长/,
    mutate(doc) {
      doc.entries[0].fix = ['刷'.repeat(201)];
    },
  },
  {
    label: 'detect 超长',
    expect: /entries\[0\]\.detect 过长/,
    mutate(doc) {
      doc.entries[0].detect = 'x'.repeat(401);
    },
  },
  {
    label: 'source 缺失',
    expect: /顶层 source 缺失/,
    mutate(doc) {
      delete doc.source;
    },
  },
  {
    label: 'aliases 为空',
    expect: /entries\[0\]\.aliases 至少要有一条/,
    mutate(doc) {
      doc.entries[0].aliases = [];
    },
  },
];

/**
 * 跑内置自测，返回失败项数（0 = 全过）。
 *
 * 不在这里设 process.exitCode：由 CLI 入口决定退出码，测试里 import 也不会污染 --test 进程。
 */
export function runSelfTest(log = console) {
  log.log('春秋红项手册校验自测：');
  let failures = 0;

  const positive = validateAnswers(selfTestBase());
  if (positive.ok) {
    log.log('  ✓ 正例（2 条合法条目）通过');
  } else {
    failures += 1;
    log.error(`  ✗ 正例本应通过，却报错：${JSON.stringify(positive.errors)}`);
  }

  for (const testCase of SELF_TEST_CASES) {
    const doc = selfTestBase();
    testCase.mutate(doc);
    const result = validateAnswers(doc);
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
    const file = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_ANSWERS;
    const result = validateAnswersFile(file);
    if (result.ok) {
      console.log(`✓ ${path.relative(REPO_ROOT, file)} 通过：${result.entryCount} 个条目`);
    } else {
      console.error(`✗ ${path.relative(REPO_ROOT, file)} 有 ${result.errors.length} 处问题：`);
      for (const e of result.errors) console.error(`  - ${e}`);
      process.exitCode = 1;
    }
  }
}
