#!/usr/bin/env node
/**
 * validate-columns.mjs
 *
 * 校验 json/columns.json —— 模块商店「专栏」的数据契约（契约见
 * H:/sukisu/hide-env-column-contract.md §2）。
 *
 * 专栏是整份手写内容，不像 modules.json 那样由 pending 合并生成，所以更需要
 * 一道机械校验：错一个字段名，App 那边就是一片空白，而空白不会报错。
 *
 * 校验项：
 *   顶层  { schemaVersion, name, updatedAt, columns[] }
 *   column { id, title, subtitle, description, accent, icon, order, topics[] }
 *   topic  { id, title, summary, riskLevel, layers[], requires[], evidence, steps[], verifyHints[] }
 *   topic  可选 keybox { url(https), sha256(64 位小写), lastVerifiedAt(yyyy-MM-dd), providerNote, disclaimer }
 *   step   { id, title, kind, optional, note, source{ kind, repo, assetPattern, pinnedVersion, sha256, moduleId } }
 *   step  可选可执行字段 { command, filePath, fileContent, checkId, confirm }
 * 外加：column/topic/step 的 id 在本作用域内唯一、枚举取值合法、evidence 必须存在且
 * verifiedAt 是真日期 —— 「没有证据的专题不上架」是契约写死的规则，校验端要和 App
 * 一样严格，否则一条缺证据的专题会在评审通过后悄悄上线。
 *
 * 可执行字段是「远程下发到用户设备上执行」的内容，所以额外硬性要求：
 *   - runCommand 必须有非空 command，且不能命中危险命令黑名单（通配删除根目录、
 *     dd 写块设备、mkfs、写 /dev/block、reboot -f、chmod -R 777 /）；
 *   - writeFile / writeConfig 必须有绝对路径 filePath（不许 ..、通配符、根目录）
 *     和非空 fileContent；fileContent 允许 ${keybox} 占位符；
 *   - writeFile / writeConfig 的 filePath 还禁止落在只读系统分区前缀下（/system、
 *     /system_ext、/vendor、/product、/odm、/boot、/init）：那些挂载点是 EROFS 或启动镜像，
 *     写入必失败，而失败发生在用户设备上；/data/adb、/data/misc 仍是合法落点；
 *   - installModule 的 source.kind 只能是 upstream / updateJson / direct —— 执行器
 *     ColumnModuleFetcher.resolveOrThrow() 的 `store` 分支直接 throw，`askUser` 没有字节
 *     可交给 ksud；installModule 的资产必须是 .zip（assetPattern，或 direct 的 url），
 *     installApp 反过来必须是 .apk，否则要等 ksud 读 module.prop / 系统安装器读包时才炸；
 *   - direct 的 sha256 按原样匹配小写 hex（不再先 toLowerCase），大写 hex 直接拒绝；
 *   - verify 的 checkId 必填且只能取 App 侧 ColumnCheckIds 的九个值之一，且只允许出现在
 *     verify 步骤上；confirm 给了就不能是空串（空串等于没确认）。
 *
 * 用法：node scripts/validate-columns.mjs [文件路径]
 *       node scripts/validate-columns.mjs --selftest   # 跑内置负例自测（不读文件）
 * 退出码 0 = 通过，1 = 有错误。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_COLUMNS = path.join(REPO_ROOT, 'json', 'columns.json');

/** 与 App 侧 RepoColumnParser / UI 的白名单一一对应，改一侧必须同步改另一侧。 */
export const ACCENTS = ['root', 'hide', 'integrity', 'tool'];
// eye-off：隐藏类专栏用「闭眼」，和详情页 header 图标一致（App 侧 columnGlyph 的 hide 分支）。
export const ICONS = ['shield', 'eye-off', 'list', 'key', 'tool'];
export const RISK_LEVELS = ['low', 'medium', 'high'];
export const LAYERS = ['L1', 'L2', 'L3', 'L4', 'L5'];
/** 档位：day = 日用级，integrity = 三绿，game = 游戏（不推荐），tool = 工具。 */
export const TIERS = ['day', 'integrity', 'game', 'tool'];
export const STEP_KINDS = [
  'installModule',
  'installApp',
  'writeConfig',
  'writeFile',
  'writeHmaConfig',
  'runCommand',
  'verify',
  'reboot',
  'askUser',
];
export const SOURCE_KINDS = ['upstream', 'store', 'askUser', 'updateJson', 'direct'];

/**
 * installModule 的 source.kind 白名单。
 *
 * 执行器 ColumnModuleFetcher.resolveOrThrow() 只实现了 upstream / updateJson / direct 三条下载
 * 路径：`store` 分支是**直接 throw**（P1 阶段没有 moduleId → 下载地址的查询接口），`askUser`
 * 则根本没有字节可以交给 ksud。索引里写 store 能过校验、到用户点「执行」才炸，所以这里先拦。
 */
export const MODULE_SOURCE_KINDS = ['upstream', 'updateJson', 'direct'];

/**
 * 只读系统分区前缀。这些挂载点要么是 EROFS（只读），要么在启动镜像里，writeFile / writeConfig
 * 写进去必然失败 —— 而失败发生在用户设备上，不是在校验时。按路径段边界匹配，所以
 * `/system_ext` 不会被 `/system` 误伤，`/systemx` 也不会；`/init` 额外覆盖 `/init.rc` 这类
 * 启动脚本（它们是同一个只读根上的文件）。
 */
export const READONLY_SYSTEM_PREFIXES = ['/system', '/system_ext', '/vendor', '/product', '/odm', '/boot', '/init'];

/**
 * verify 步骤可选的自动检查项，与 App 侧 ColumnExecution.kt 的 ColumnCheckIds 一一对应。
 * 两端必须同时改：这里多一个 App 不认识，App 那边就会忽略；少一个则专栏写的手写检查
 * 会在执行器里变成死字段。
 */
export const CHECK_IDS = [
  'root-manager',
  'zygisk-next',
  'denylist-policy',
  'hma-config',
  'target-list',
  'keybox-valid',
  'hybrid-mount',
  'pathmask',
  'adb-disabled',
];

/** GitHub 的 owner/repo 形状（与 build-index.mjs 的 normalizeRepoUrl 同一套规则）。 */
const REPO_SHAPE_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9._-]{1,100}$/;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
/** keybox 校验值只收小写，避免「同一个值两种写法」导致比对时永远对不上。 */
const KEYBOX_SHA256_RE = /^[0-9a-f]{64}$/;
const CHECK_ID_SET = new Set(CHECK_IDS);

/**
 * 危险命令黑名单。下发的 command 等于在用户设备上跑一次 root shell，下面这几类
 * 一旦误发就是不可恢复的丢数据，所以直接拒绝，不接受「大概率没事」。
 * 规则宁宽勿窄：误报只让人改命令，漏报会毁设备。
 */
export const DANGEROUS_COMMAND_RULES = [
  {
    why: '禁止通配删除根目录（rm -rf / 或 /*）',
    test: (cmd) => /\brm\s+(?:-[A-Za-z]+\s+)*\/(?:\s|$|\*)/.test(cmd),
  },
  {
    why: '禁止用 dd 写设备（dd if= ...）',
    test: (cmd) => /\bdd\s+[^;&|]*\bif=/.test(cmd),
  },
  {
    why: '禁止格式化分区（mkfs）',
    test: (cmd) => /\bmkfs(?:\.[A-Za-z0-9]+)?\b/.test(cmd),
  },
  {
    why: '禁止直接写块设备（> /dev/block/...）',
    test: (cmd) => />>?\s*\/dev\/block\//.test(cmd),
  },
  {
    why: '禁止强制重启（reboot -f / --force），会跳过文件系统回写',
    test: (cmd) => /\breboot\s+(?:-[A-Za-z]*f[A-Za-z]*|--force)\b/.test(cmd),
  },
  {
    why: '禁止把根目录递归改成 777',
    test: (cmd) =>
      /\bchmod\b[^;&|]*?\s(?:-R|--recursive)\b[^;&|]*?\b0?777\b[^;&|]*?\s\/(?:\s|$|\*)/.test(cmd),
  },
];

/**
 * 命中黑名单时返回规则说明，否则返回 null。command 为空不算命中（空命令由
 * runCommand 的必填规则负责）。
 */
export function findDangerousCommand(command) {
  if (typeof command !== 'string' || command.trim() === '') return null;
  for (const rule of DANGEROUS_COMMAND_RULES) {
    if (rule.test(command)) return rule.why;
  }
  return null;
}

/**
 * 路径是否落在只读系统分区上：命中则返回那个前缀，否则 null。
 *
 * 按路径段边界比对，所以 `/system_ext/...` 命中 `/system_ext` 而不是 `/system`，`/systemx` 一个都不命中；
 * `/init` 是例外：它本身是启动镜像里的文件，`/init.rc` 这类同根脚本用「前缀 + 点」一起覆盖。
 */
export function findReadonlyPrefix(filePath) {
  if (typeof filePath !== 'string' || !filePath.startsWith('/')) return null;
  let p = filePath;
  while (p.endsWith('/')) p = p.slice(0, -1);
  for (const pre of READONLY_SYSTEM_PREFIXES) {
    if (p === pre || p.startsWith(pre + '/')) return pre;
    if (pre === '/init' && p.startsWith('/init.')) return pre;
  }
  return null;
}

/**
 * 写入路径必须是绝对路径，且不许 .. 跳转、通配符、根目录本身或以 / 结尾。
 * 这些写法在「远程下发」的场景里等同于把整台设备的写入权交出去。
 * 另外不许落在只读系统分区（/system、/vendor、/boot 这类 EROFS 或启动镜像）：
 * 那些地方写不进去，失败却发生在用户设备上；/data/adb、/data/misc 是合法落点。
 * 返回问题描述，合法时返回 null。
 */
export function checkWritePath(filePath) {
  if (typeof filePath !== 'string' || filePath.trim() === '') return '缺少 filePath';
  if (!filePath.startsWith('/')) return '必须以 / 开头（绝对路径）';
  if (filePath === '/') return '不能是根目录';
  if (filePath.includes('\0')) return '含非法字符 \\0';
  if (filePath.split('/').some((seg) => seg === '..')) return '不允许 .. 上级跳转';
  if (/[*?[\]]/.test(filePath)) return '不允许通配符（* ? [ ]）';
  if (filePath.endsWith('/')) return '不能以 / 结尾（那是目录不是文件）';
  const readonly = findReadonlyPrefix(filePath);
  if (readonly) return `不能写只读系统分区 ${readonly}（EROFS / 启动镜像，写入必失败）`;
  return null;
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';

/**
 * 检查 writeHmaConfig 的配置包。
 *
 * 执行器会把它合并进设备上 HMA-OSS 的 config.json（目录名带随机后缀，不能写死）：模板写进
 * `templates[templateName]`，`scope` 的每个 key 是一个目标应用，`globals` 里的键按「缺失才补」
 * 合并。这里只查结构，不查内容对不对（包名是否真实存在由执行时的设备决定）。
 */
export function checkHmaConfigPack(raw) {
  if (!nonEmpty(raw)) return 'fileContent 必须是非空字符串';
  let pack;
  try {
    pack = JSON.parse(raw);
  } catch (e) {
    return `不是合法 JSON（${e.message}）`;
  }
  if (!isObject(pack)) return '顶层必须是对象';
  if (pack.configVersion !== undefined && !(Number.isInteger(pack.configVersion) && pack.configVersion > 0)) {
    return 'configVersion 如果给了，必须是正整数';
  }
  if (!nonEmpty(pack.templateName)) return '缺少 templateName';
  const tpl = pack.template;
  if (!isObject(tpl)) return '缺少 template 对象';
  if (tpl.isWhitelist !== undefined && typeof tpl.isWhitelist !== 'boolean') return 'template.isWhitelist 必须是布尔值';
  if (!Array.isArray(tpl.appList) || tpl.appList.length === 0) return 'template.appList 必须是非空数组';
  if (tpl.appList.some((p) => !nonEmpty(p))) return 'template.appList 里必须都是非空字符串包名';
  if (pack.scope !== undefined) {
    if (!isObject(pack.scope)) return 'scope 必须是对象（key 是目标应用包名）';
    for (const [target, cfg] of Object.entries(pack.scope)) {
      if (!nonEmpty(target)) return 'scope 里有空的包名 key';
      if (!isObject(cfg)) return `scope["${target}"] 必须是对象`;
    }
  }
  if (pack.globals !== undefined && !isObject(pack.globals)) return 'globals 必须是对象';
  if (pack.disabledHooks !== undefined) {
    if (!Array.isArray(pack.disabledHooks)) return 'disabledHooks 必须是数组';
    for (const hook of pack.disabledHooks) {
      if (!isObject(hook)) return 'disabledHooks 里每一项都必须是对象';
      if (!nonEmpty(hook.className)) return 'disabledHooks 每项必须有 className';
      if (!nonEmpty(hook.methodName)) return 'disabledHooks 每项必须有 methodName';
    }
  }
  return null;
}

/** yyyy-MM-dd 且真存在（2 月 30 日之类要挡住）。 */
function isRealDate(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

/** 取 URL 末段的文件名（去掉 query / fragment），不是 https 地址时返回空串。 */
function urlBasename(u) {
  const s = String(u ?? '').trim();
  if (!/^https:\/\/[^\s]+$/i.test(s)) return '';
  const noQuery = s.split('#')[0].split('?')[0];
  const seg = noQuery.split('/').filter(Boolean).pop() ?? '';
  return seg;
}

/**
 * 下载资产的扩展名必须和步骤类型对得上：installModule 的字节最终交给 ksud 当模块 zip 解包，
 * installApp 的字节交给系统安装器当 apk 解析。装错格式的失败点在用户设备上（ksud 读
 * module.prop 失败 / 安装器报「解析包出错」），索引里看不出来，所以这里按来源逐条查：
 *   - upstream：assetPattern 是匹配规则，必须自身以 `.zip` / `.apk` 结尾；
 *   - direct：url 末段就是真实文件名，按它查；
 *   - updateJson：url 指向版本清单 JSON，资产名由清单里的字段给，索引侧没有名字可查，跳过；
 *   - store / askUser：没有可下载资产，跳过。
 * 返回问题描述，合法时返回 null。
 */
export function checkAssetExtension(stepKind, src) {
  const want = stepKind === 'installModule' ? '.zip' : stepKind === 'installApp' ? '.apk' : null;
  if (!want) return null;
  const label = stepKind === 'installModule' ? '模块包' : '安装包';
  if (src.kind === 'upstream') {
    const pattern = String(src.assetPattern ?? '').trim();
    if (!pattern.toLowerCase().endsWith(want)) {
      return `assetPattern 必须匹配 ${want} 文件（${label}），实际是 ${JSON.stringify(src.assetPattern)}`;
    }
    return null;
  }
  if (src.kind === 'direct') {
    const name = urlBasename(src.url);
    if (!name) return null; // url 本身不合法，由 direct 分支单独报错
    if (!name.toLowerCase().endsWith(want)) {
      return `url 指向的文件必须是 ${want}（${label}），实际是 ${JSON.stringify(name)}`;
    }
    return null;
  }
  return null;
}

/**
 * @returns {{ok: boolean, errors: string[], columnCount: number, topicCount: number, stepCount: number}}
 */
export function validateColumns(doc) {
  const errors = [];
  const push = (m) => errors.push(m);

  if (!isObject(doc)) {
    push('顶层必须是一个 JSON 对象');
    return { ok: false, errors, columnCount: 0, topicCount: 0, stepCount: 0 };
  }
  if (doc.schemaVersion !== 1) push('顶层 schemaVersion 必须是数字 1');
  if (!nonEmpty(doc.name)) push('顶层缺少 name');
  if (!isRealDate(doc.updatedAt)) push('顶层 updatedAt 必须是 yyyy-MM-dd 且真实存在的日期');
  if (!Array.isArray(doc.columns)) {
    push('顶层缺少 columns 数组');
    return { ok: false, errors, columnCount: 0, topicCount: 0, stepCount: 0 };
  }

  const columnIds = new Set();
  let topicCount = 0;
  let stepCount = 0;

  doc.columns.forEach((col, ci) => {
    const at = `columns[${ci}]`;
    if (!isObject(col)) {
      push(`${at} 不是对象`);
      return;
    }
    for (const f of ['id', 'title', 'subtitle', 'description']) {
      if (!nonEmpty(col[f])) push(`${at} 缺少/为空字段 ${f}`);
    }
    if (nonEmpty(col.id)) {
      if (columnIds.has(col.id)) push(`${at} id 重复：${col.id}`);
      columnIds.add(col.id);
    }
    if (!ACCENTS.includes(col.accent)) {
      push(`${at} accent 必须是 ${ACCENTS.join(' / ')} 之一，实际是 ${JSON.stringify(col.accent)}`);
    }
    if (!ICONS.includes(col.icon)) {
      push(`${at} icon 必须是 ${ICONS.join(' / ')} 之一，实际是 ${JSON.stringify(col.icon)}`);
    }
    // guide 是可选的「怎么选」引导：给了就每条都要有标题和正文，档位不能重复也不能乱写。
    if (col.guide !== undefined) {
      if (!Array.isArray(col.guide)) {
        push(`${at} guide 必须是数组（不需要就不写这个字段）`);
      } else {
        const seenTiers = new Set();
        col.guide.forEach((g, gi) => {
          const gat = `${at}.guide[${gi}]`;
          if (!isObject(g)) {
            push(`${gat} 不是对象`);
            return;
          }
          if (!nonEmpty(g.title)) push(`${gat} 缺少/为空字段 title`);
          if (!nonEmpty(g.body)) push(`${gat} 缺少/为空字段 body`);
          if (g.tier !== undefined && g.tier !== '') {
            if (!TIERS.includes(g.tier)) {
              push(`${gat}.tier 必须是 ${TIERS.join(' / ')} 之一，实际是 ${JSON.stringify(g.tier)}`);
            }
            if (seenTiers.has(g.tier)) push(`${gat}.tier 重复：${g.tier}`);
            seenTiers.add(g.tier);
          }
        });
      }
    }
    if (typeof col.order !== 'number' || !Number.isFinite(col.order)) {
      push(`${at} order 必须是数字`);
    }
    if (!Array.isArray(col.topics) || col.topics.length === 0) {
      push(`${at} topics 必须是非空数组`);
      return;
    }

    const topicIds = new Set();
    col.topics.forEach((topic, ti) => {
      topicCount += 1;
      const tat = `${at}.topics[${ti}]`;
      if (!isObject(topic)) {
        push(`${tat} 不是对象`);
        return;
      }
      for (const f of ['id', 'title', 'summary']) {
        if (!nonEmpty(topic[f])) push(`${tat} 缺少/为空字段 ${f}`);
      }
      if (nonEmpty(topic.id)) {
        if (topicIds.has(topic.id)) push(`${tat} id 在同一专栏内重复：${topic.id}`);
        topicIds.add(topic.id);
      }
      if (!RISK_LEVELS.includes(topic.riskLevel)) {
        push(`${tat} riskLevel 必须是 ${RISK_LEVELS.join(' / ')} 之一`);
      }
      // tier 只是展示用的档位标签，可以不写；写了就必须是白名单里的值。
      if (topic.tier !== undefined && topic.tier !== '' && !TIERS.includes(topic.tier)) {
        push(`${tat}.tier 必须是 ${TIERS.join(' / ')} 之一，实际是 ${JSON.stringify(topic.tier)}`);
      }
      if (!Array.isArray(topic.layers)) {
        push(`${tat} layers 必须是数组（没有可写空数组）`);
      } else {
        topic.layers.forEach((l, li) => {
          if (!LAYERS.includes(l)) push(`${tat}.layers[${li}] 取值非法：${JSON.stringify(l)}`);
        });
      }
      if (!Array.isArray(topic.requires)) push(`${tat} requires 必须是数组（人话描述的前置条件）`);

      // 「没有证据的专题不上架」——契约 §2.6。这里必须是硬错误，不是警告。
      if (!isObject(topic.evidence)) {
        push(`${tat} 缺少 evidence（没有证据的专题不允许上架）`);
      } else {
        const ev = topic.evidence;
        if (!isRealDate(ev.verifiedAt)) {
          push(`${tat}.evidence.verifiedAt 必须是 yyyy-MM-dd 且真实存在`);
        }
        for (const f of ['device', 'kernel', 'source', 'note']) {
          if (!nonEmpty(ev[f])) push(`${tat}.evidence 缺少/为空字段 ${f}`);
        }
      }

      // keybox 是主题级的可选字段：只在「有可信直链 + 能校验」时才允许登记。
      // 没有就干脆不写这个字段，让 UI 走「自备 keybox」的说明，而不是给个假地址。
      if (topic.keybox !== undefined && topic.keybox !== null) {
        const kb = topic.keybox;
        if (!isObject(kb)) {
          push(`${tat}.keybox 必须是对象（没有可信来源就别写这个字段）`);
        } else {
          if (typeof kb.url !== 'string' || !/^https:\/\//.test(kb.url)) {
            push(`${tat}.keybox.url 必须是 https:// 开头的直链`);
          }
          if (typeof kb.sha256 !== 'string' || !KEYBOX_SHA256_RE.test(kb.sha256)) {
            push(`${tat}.keybox.sha256 必须是 64 位小写十六进制`);
          }
          if (!isRealDate(kb.lastVerifiedAt)) {
            push(`${tat}.keybox.lastVerifiedAt 必须是 yyyy-MM-dd 且真实存在`);
          }
          for (const f of ['providerNote', 'disclaimer']) {
            if (kb[f] !== undefined && typeof kb[f] !== 'string') {
              push(`${tat}.keybox.${f} 必须是字符串`);
            }
          }
        }
      }

      if (!Array.isArray(topic.steps) || topic.steps.length === 0) {
        push(`${tat} steps 必须是非空数组`);
      } else {
        const stepIds = new Set();
        topic.steps.forEach((step, si) => {
          stepCount += 1;
          const sat = `${tat}.steps[${si}]`;
          if (!isObject(step)) {
            push(`${sat} 不是对象`);
            return;
          }
          for (const f of ['id', 'title']) {
            if (!nonEmpty(step[f])) push(`${sat} 缺少/为空字段 ${f}`);
          }
          if (nonEmpty(step.id)) {
            if (stepIds.has(step.id)) push(`${sat} id 在同一专题内重复：${step.id}`);
            stepIds.add(step.id);
          }
          if (!STEP_KINDS.includes(step.kind)) {
            push(`${sat} kind 必须是 ${STEP_KINDS.join(' / ')} 之一，实际是 ${JSON.stringify(step.kind)}`);
          }
          if (typeof step.optional !== 'boolean') push(`${sat} optional 必须是布尔值`);
          if (typeof step.note !== 'string') push(`${sat} note 必须是字符串（没有补充说明就写空串）`);

          // —— 可执行字段：这些内容会被 App 下发到设备上真的执行，校验必须比展示字段更严 ——
          if (step.kind === 'runCommand' && !nonEmpty(step.command)) {
            push(`${sat} 是 runCommand，command 必须是非空字符串`);
          } else if (step.command !== undefined && typeof step.command !== 'string') {
            push(`${sat}.command 必须是字符串`);
          }
          const danger = findDangerousCommand(step.command);
          if (danger) push(`${sat}.command 命中危险命令黑名单：${danger}`);

          if (step.kind === 'writeFile' || step.kind === 'writeConfig') {
            const pathProblem = checkWritePath(step.filePath);
            if (pathProblem) push(`${sat}.filePath 不合法：${pathProblem}`);
            if (!nonEmpty(step.fileContent)) {
              push(`${sat} 是 ${step.kind}，fileContent 必须是非空字符串`);
            }
          } else if (step.kind === 'writeHmaConfig') {
            // 执行器会把 fileContent 当「配置包」合并进设备上的 HMA config.json，坏 JSON 会让这步
            // 直接失败，所以这里先按结构查一遍。
            if (step.filePath !== undefined) {
              push(`${sat} 是 writeHmaConfig，不该带 filePath（路径由执行器在设备上探测）`);
            }
            const packProblem = checkHmaConfigPack(step.fileContent);
            if (packProblem) push(`${sat}.fileContent 不是合法的 HMA 配置包：${packProblem}`);
          } else if (step.filePath !== undefined || step.fileContent !== undefined) {
            // 死字段：填了也不会被执行器读到，留着只会误导下一个编辑者。
            push(`${sat} 只有 writeFile / writeConfig / writeHmaConfig 才能带可执行内容字段`);
          }

          if (step.checkId !== undefined) {
            if (step.kind !== 'verify') {
              push(`${sat}.checkId 只允许出现在 verify 步骤`);
            } else if (!nonEmpty(step.checkId) || !CHECK_ID_SET.has(step.checkId)) {
              push(
                `${sat}.checkId 必须是 ${CHECK_IDS.join(' / ')} 之一，实际是 ${JSON.stringify(step.checkId)}`,
              );
            }
          } else if (step.kind === 'verify') {
            // verify 是「让用户/执行器确认某项通过」的步骤，没有 checkId 就只剩一段说明文字，
            // 执行器只能原样回显 note（ColumnStepRunnerImpl.verify() 从不真跑检查），等于死步骤。
            push(`${sat} 是 verify，checkId 必填（${CHECK_IDS.join(' / ')} 之一）`);
          }

          if (step.confirm !== undefined) {
            if (typeof step.confirm !== 'string') push(`${sat}.confirm 必须是字符串`);
            else if (!nonEmpty(step.confirm)) push(`${sat}.confirm 给了就不能是空串（空串等于没做二次确认）`);
          }

          // link 是「官方渠道入口」：点了只打开浏览器，不执行任何东西，所以只做形状校验。
          // 但必须 https —— http 页面在真机上会被当明文，中间人换掉下载地址就等于投毒。
          if (step.link !== undefined) {
            if (typeof step.link !== 'string') {
              push(`${sat}.link 必须是字符串`);
            } else if (nonEmpty(step.link)) {
              // 除了外部网页，还允许 sukisu:// 站内入口（目前只有 sukisu://ai = 打开管理器里的 AI 助手）。
              if (!/^(https:\/\/[^\s]+|sukisu:\/\/[a-z][a-z0-9-]*)$/i.test(step.link)) {
                push(
                  `${sat}.link 必须是 https 地址或 sukisu:// 站内入口，实际是 ${JSON.stringify(step.link)}`,
                );
              } else if (step.link.length > 512) {
                push(`${sat}.link 太长（上限 512 字符）`);
              }
            } else {
              push(`${sat}.link 给了就不能是空串（不需要就整个字段删掉）`);
            }
          }

          // optIn：默认不装、由用户在向导里勾选后才执行的步骤（自检检测器就是这类）。
          // 只允许布尔；写成字符串 "true" 会被 App 当成 false，等于白写。
          if (step.optIn !== undefined && typeof step.optIn !== 'boolean') {
            push(`${sat}.optIn 必须是布尔值，实际是 ${JSON.stringify(step.optIn)}`);
          }

          if (!isObject(step.source)) {
            push(`${sat} 缺少 source 对象`);
            return;
          }
          const src = step.source;
          if (!SOURCE_KINDS.includes(src.kind)) {
            push(`${sat}.source.kind 必须是 ${SOURCE_KINDS.join(' / ')} 之一`);
          }
          if (step.kind === 'installModule' && !MODULE_SOURCE_KINDS.includes(src.kind)) {
            // 执行器的 resolveOrThrow() 对 store / askUser 直接 throw：能过校验，到用户点「执行」才炸。
            push(
              `${sat} 是 installModule，source.kind 只能是 ${MODULE_SOURCE_KINDS.join(' / ')}（执行器不支持 ${JSON.stringify(src.kind)}）`,
            );
          }
          if (step.kind === 'installModule' || step.kind === 'installApp') {
            const extProblem = checkAssetExtension(step.kind, src);
            if (extProblem) push(`${sat}.source ${extProblem}`);
          }
          if (step.kind === 'installApp' && src.kind === 'askUser') {
            push(`${sat} 是 installApp，source 必须给出可下载的来源（upstream / updateJson / store / direct）`);
          }
          // direct：第三方网盘或官方网盘的固定直链。这里没有上游版本信息可查，唯一能锁死的就是字节，
          // 所以 sha256 是硬要求 —— 没有哈希就不许走这条通道（链接被换包时无从发现）。
          if (src.kind === 'direct') {
            const u = String(src.url ?? '');
            if (!/^https:\/\/[^\s]+$/i.test(u)) {
              push(`${sat}.source.url 必须是 https 直链，实际是 ${JSON.stringify(src.url)}`);
            }
            // 按原样匹配，不做大小写归一：执行器是 `sha256.trim().lowercase()` 之后再比，
            // 索引里写大写 hex 会被这里放过去、到设备上却因归一化差异对不上，所以校验侧要更严。
            const h = String(src.sha256 ?? '').trim();
            if (!/^[0-9a-f]{64}$/.test(h)) {
              push(`${sat}.source.sha256 必须是 64 位小写十六进制（direct 来源强制要求哈希）`);
            }
          }
          if (src.kind === 'upstream') {
            if (!REPO_SHAPE_RE.test(String(src.repo ?? ''))) {
              push(`${sat}.source.repo 必须是 owner/repo 形状，实际是 ${JSON.stringify(src.repo)}`);
            }
            // pinnedVersion 可以空：空 = 每次取最新 release（用户要求永远拿最新版）。
            if (!nonEmpty(src.assetPattern)) push(`${sat}.source 缺 assetPattern（upstream 必须有）`);
            if (nonEmpty(src.sha256) && !SHA256_RE.test(src.sha256)) {
              push(`${sat}.source.sha256 不是合法的 64 位十六进制`);
            }
          }
          if (src.kind === 'store' && !nonEmpty(src.moduleId)) {
            push(`${sat}.source 缺 moduleId（store 必须有）`);
          }
          if (src.kind === 'updateJson') {
            const url = String(src.url ?? '');
            if (!nonEmpty(url)) push(`${sat}.source 缺 url（updateJson 必须有）`);
            else if (!/^https:\/\/[^\s]+$/i.test(url)) {
              push(`${sat}.source.url 必须是 https 地址，实际是 ${JSON.stringify(src.url)}`);
            }
          }
          if (src.kind === 'askUser') {
            // 用户自己去找的组件没有下载地址，但必须留下「去哪找」的线索，否则这条步骤等于没说。
            if (!nonEmpty(step.note)) {
              push(`${sat} 是 askUser 步骤，note 必须写清楚从哪获取`);
            }
          }
        });
      }

      if (!Array.isArray(topic.verifyHints)) push(`${tat} verifyHints 必须是数组`);
    });
  });

  if (doc.columns.length === 0) push('columns 不能是空数组（专栏数据缺失时宁可不发这一版）');

  return { ok: errors.length === 0, errors, columnCount: doc.columns.length, topicCount, stepCount };
}

/** 从文件读并校验；文件不存在也算失败（索引仓的 columns.json 必须始终存在）。 */
export function validateColumnsFile(file = DEFAULT_COLUMNS) {
  if (!fs.existsSync(file)) {
    return { ok: false, errors: [`文件不存在：${file}`], columnCount: 0, topicCount: 0, stepCount: 0 };
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return { ok: false, errors: [`JSON 解析失败：${e.message}`], columnCount: 0, topicCount: 0, stepCount: 0 };
  }
  return validateColumns(doc);
}

// ── 内置负例自测 ────────────────────────────────────────────────────────────
// 校验器的价值在于「坏数据进不来」，而不是「好数据能过」。下面每条负例都必须被挡住，
// 少挡一条就说明规则退化了 —— 用 --selftest 跑一遍，不需要联网、不读仓库文件。

function selfTestBase() {
  // 每次都造一份新对象：负例靠 mutate 改嵌套字段，共享引用会让改动串到别的步骤上。
  const askUserSource = () => ({
    kind: 'askUser',
    repo: '',
    assetPattern: '',
    pinnedVersion: '',
    sha256: '',
    moduleId: '',
  });
  return {
    schemaVersion: 1,
    name: '自测专栏',
    updatedAt: '2026-11-04',
    columns: [
      {
        id: 'selftest',
        title: '自测',
        subtitle: '内置负例用',
        description: '只在 --selftest 里存在',
        accent: 'root',
        icon: 'shield',
        order: 1,
        topics: [
          {
            id: 'selftest-topic',
            title: '自测专题',
            summary: '覆盖新增的 6 类规则',
            riskLevel: 'low',
            layers: ['L1'],
            requires: ['无'],
            evidence: {
              verifiedAt: '2026-11-04',
              device: '自测',
              kernel: '自测',
              source: '自测',
              note: '自测',
            },
            verifyHints: ['自测'],
            steps: [
              {
                id: 'mod',
                title: '装模块',
                kind: 'installModule',
                optional: false,
                note: '',
                source: {
                  kind: 'upstream',
                  repo: 'Dr-TSNG/ZygiskNext',
                  assetPattern: 'Zygisk-Next-*-release.zip',
                  pinnedVersion: '',
                  sha256: '',
                  moduleId: 'zygisksu',
                },
              },
              {
                id: 'app',
                title: '装应用',
                kind: 'installApp',
                optional: false,
                note: '',
                source: {
                  kind: 'upstream',
                  repo: 'eltavine/Duck-Detector-Refactoring',
                  assetPattern: 'Duck.Detector-*.apk',
                  pinnedVersion: '',
                  sha256: '',
                  moduleId: '',
                },
              },
              {
                id: 'direct-app',
                title: '直链装应用',
                kind: 'installApp',
                optional: false,
                note: '',
                source: {
                  kind: 'direct',
                  repo: '',
                  assetPattern: '',
                  pinnedVersion: '',
                  sha256: '1ca92901b74ff658988a4859d8cd2c6f20e45f722a88bc0361e9d33ee5a72866',
                  moduleId: '',
                  url: 'https://example.com/mirror/ChunqiuNativeCheck-4.6.2.apk',
                },
              },
              {
                id: 'write',
                title: '写文件',
                kind: 'writeFile',
                optional: false,
                note: '自测用',
                filePath: '/data/adb/zygisksu/denylist_enforce',
                fileContent: '1\n',
                source: askUserSource(),
              },
              {
                id: 'check',
                title: '自检',
                kind: 'verify',
                optional: false,
                note: '自测用',
                checkId: 'root-manager',
                source: askUserSource(),
              },
            ],
          },
        ],
      },
    ],
  };
}

const SELF_TEST_CASES = [
  {
    label: 'installModule 用 store 来源',
    expect: /是 installModule，source\.kind 只能是 upstream \/ updateJson \/ direct/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[0].source.kind = 'store';
    },
  },
  {
    label: 'installModule 资产不是 zip',
    expect: /assetPattern 必须匹配 \.zip/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[0].source.assetPattern = 'Zygisk-Next-*-release.apk';
    },
  },
  {
    label: 'installApp 资产不是 apk',
    expect: /assetPattern 必须匹配 \.apk/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[1].source.assetPattern = 'Duck.Detector-*.zip';
    },
  },
  {
    label: 'installApp 直链指向 zip',
    expect: /url 指向的文件必须是 \.apk/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[2].source.url =
        'https://example.com/mirror/ChunqiuNativeCheck-4.6.2.zip';
    },
  },
  {
    label: 'writeFile 写 /system',
    expect: /不能写只读系统分区 \/system/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[3].filePath = '/system/etc/hosts';
    },
  },
  {
    label: 'writeFile 写 /init.rc',
    expect: /不能写只读系统分区 \/init/,
    mutate(doc) {
      doc.columns[0].topics[0].steps[3].filePath = '/init.rc';
    },
  },
  {
    label: 'direct sha256 大写',
    expect: /sha256 必须是 64 位小写十六进制/,
    mutate(doc) {
      const s = doc.columns[0].topics[0].steps[2].source;
      s.sha256 = s.sha256.toUpperCase();
    },
  },
  {
    label: 'verify 缺 checkId',
    expect: /是 verify，checkId 必填/,
    mutate(doc) {
      delete doc.columns[0].topics[0].steps[4].checkId;
    },
  },
];

/**
 * 跑内置负例自测：正例必须过，每条负例必须被自己的 expect 命中。
 * 不在这里设 process.exitCode：由 CLI 入口决定退出码，测试里 import 也不会污染 --test 进程。
 */
export function runSelfTest(log = console) {
  log.log('专栏数据校验自测：');
  let failures = 0;

  const positive = validateColumns(selfTestBase());
  if (positive.ok) {
    log.log('  ✓ 正例（1 个专栏 / 1 个专题 / 5 步合法步骤）通过');
  } else {
    failures += 1;
    log.error(`  ✗ 正例本应通过，却报错：${JSON.stringify(positive.errors)}`);
  }

  for (const testCase of SELF_TEST_CASES) {
    const doc = selfTestBase();
    testCase.mutate(doc);
    const result = validateColumns(doc);
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
    const file = process.argv[2] ? path.resolve(process.argv[2]) : DEFAULT_COLUMNS;
    const result = validateColumnsFile(file);
    if (result.ok) {
      console.log(
        `✓ ${path.relative(REPO_ROOT, file)} 通过：${result.columnCount} 个专栏 / ` +
          `${result.topicCount} 个专题 / ${result.stepCount} 步`,
      );
    } else {
      console.error(`✗ ${path.relative(REPO_ROOT, file)} 有 ${result.errors.length} 处问题：`);
      for (const e of result.errors) console.error(`  - ${e}`);
      process.exitCode = 1;
    }
  }
}
