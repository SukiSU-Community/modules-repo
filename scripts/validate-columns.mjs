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
 *   - verify 的 checkId 只能取 App 侧 ColumnCheckIds 的九个值之一，且只允许出现在
 *     verify 步骤上；confirm 给了就不能是空串（空串等于没确认）。
 *
 * 用法：node scripts/validate-columns.mjs [文件路径]
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
export const ICONS = ['shield', 'list', 'key', 'tool'];
export const RISK_LEVELS = ['low', 'medium', 'high'];
export const LAYERS = ['L1', 'L2', 'L3', 'L4', 'L5'];
export const STEP_KINDS = [
  'installModule',
  'installApp',
  'writeConfig',
  'writeFile',
  'runCommand',
  'verify',
  'reboot',
  'askUser',
];
export const SOURCE_KINDS = ['upstream', 'store', 'askUser', 'updateJson'];

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
 * 写入路径必须是绝对路径，且不许 .. 跳转、通配符、根目录本身或以 / 结尾。
 * 这些写法在「远程下发」的场景里等同于把整台设备的写入权交出去。
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
  return null;
}

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const nonEmpty = (v) => typeof v === 'string' && v.trim() !== '';

/** yyyy-MM-dd 且真存在（2 月 30 日之类要挡住）。 */
function isRealDate(s) {
  if (typeof s !== 'string' || !DATE_RE.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
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
          } else if (step.filePath !== undefined || step.fileContent !== undefined) {
            // 死字段：填了也不会被执行器读到，留着只会误导下一个编辑者。
            push(`${sat} 只有 writeFile / writeConfig 才能带 filePath / fileContent`);
          }

          if (step.checkId !== undefined) {
            if (step.kind !== 'verify') {
              push(`${sat}.checkId 只允许出现在 verify 步骤`);
            } else if (!nonEmpty(step.checkId) || !CHECK_ID_SET.has(step.checkId)) {
              push(
                `${sat}.checkId 必须是 ${CHECK_IDS.join(' / ')} 之一，实际是 ${JSON.stringify(step.checkId)}`,
              );
            }
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
              if (!/^https:\/\/[^\s]+$/i.test(step.link)) {
                push(`${sat}.link 必须是 https 地址，实际是 ${JSON.stringify(step.link)}`);
              } else if (step.link.length > 512) {
                push(`${sat}.link 太长（上限 512 字符）`);
              }
            } else {
              push(`${sat}.link 给了就不能是空串（不需要就整个字段删掉）`);
            }
          }

          if (!isObject(step.source)) {
            push(`${sat} 缺少 source 对象`);
            return;
          }
          const src = step.source;
          if (!SOURCE_KINDS.includes(src.kind)) {
            push(`${sat}.source.kind 必须是 ${SOURCE_KINDS.join(' / ')} 之一`);
          }
          if (step.kind === 'installApp' && src.kind === 'askUser') {
            push(`${sat} 是 installApp，source 必须给出可下载的来源（upstream / updateJson / store）`);
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

const invokedDirectly =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
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
