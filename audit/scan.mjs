#!/usr/bin/env node
// 模块投稿安全审核 —— 静态风险扫描器
//
// 用法：
//   node scan.mjs <module.zip> [选项]
//
// 选项：
//   --declared-id <id>         投稿表单声明的 module id
//   --declared-version <ver>   投稿表单声明的 version
//   --change-type first|update 手动指定“首次收录 / 版本更新”
//   --index <index.json>       已收录索引（数组或 {modules:[]}），用于自动判定 first/update
//   --json <path>              JSON 报告输出路径（默认 <zip>.audit.json）
//   --markdown <path>          Markdown 报告输出路径（默认 <zip>.audit.md）
//   --out-dir <dir>            同时输出两种报告到该目录
//   --stdout                   额外把 markdown 打到 stdout
//   --quiet                    只输出一行结论
//   --fail-on <level>          风险 >= 该级别时退出码为 2（high|medium|low|never，默认 never）
//
// 仅使用 node: 内置模块，无任何 npm 依赖。

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { basename, dirname, resolve, join, extname } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { spawnSync } from 'node:child_process';

import {
  CONTENT_RULES, scanContent, checkMetadata, parseModuleProp,
  scoreRisk, decide, countsTowardRisk, CATEGORY_LABEL, SEVERITY_ORDER,
} from './risk-rules.mjs';
// ---------------------------------------------------------------------------
// ZIP 解析（自带简易实现，失败时回退系统 unzip）
// ---------------------------------------------------------------------------

const SIG_EOCD = 0x06054b50;
const SIG_CEN = 0x02014b50;
const SIG_LOC = 0x04034b50;

function findEOCD(buf) {
  const maxBack = Math.min(buf.length, 65557);
  for (let i = buf.length - 22; i >= buf.length - maxBack && i >= 0; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) return i;
  }
  return -1;
}

function parseZip(buf) {
  const eocd = findEOCD(buf);
  if (eocd < 0) throw new Error('找不到 EOCD 记录，文件可能不是 zip');
  let count = buf.readUInt16LE(eocd + 10);
  let cdOffset = buf.readUInt32LE(eocd + 16);

  // zip64：值为哨兵时改从 zip64 EOCD 读取
  if (count === 0xffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && buf.readUInt32LE(loc) === 0x07064b50) {
      const z64 = Number(buf.readBigUInt64LE(loc + 8));
      if (buf.readUInt32LE(z64) === 0x06064b50) {
        count = Number(buf.readBigUInt64LE(z64 + 32));
        cdOffset = Number(buf.readBigUInt64LE(z64 + 48));
      }
    }
  }

  const entries = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CEN) break;
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    let compSize = buf.readUInt32LE(p + 20);
    let origSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOff = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    const extra = buf.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);

    // zip64 扩展字段
    let z = 0;
    while (z + 4 <= extra.length) {
      const hid = extra.readUInt16LE(z);
      const hsz = extra.readUInt16LE(z + 2);
      const body = extra.subarray(z + 4, z + 4 + hsz);
      if (hid === 0x0001) {
        let q = 0;
        if (origSize === 0xffffffff && q + 8 <= body.length) { origSize = Number(body.readBigUInt64LE(q)); q += 8; }
        if (compSize === 0xffffffff && q + 8 <= body.length) { compSize = Number(body.readBigUInt64LE(q)); q += 8; }
        if (localOff === 0xffffffff && q + 8 <= body.length) { localOff = Number(body.readBigUInt64LE(q)); q += 8; }
      }
      z += 4 + hsz;
    }

    // 本地头 -> 数据起点
    let dataOff = null;
    let storedComp = compSize;
    if (localOff + 30 <= buf.length && buf.readUInt32LE(localOff) === SIG_LOC) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      dataOff = localOff + 30 + lNameLen + lExtraLen;
      // 本地头里若声明了 0（流式压缩），以中心目录为准，退化为按下一个已知边界推断
      const lComp = buf.readUInt32LE(localOff + 18);
      if (lComp !== 0 && lComp !== compSize) storedComp = lComp;
    }

    entries.push({
      name, method, flags, compSize: storedComp || compSize, origSize, dataOff, encrypted: (flags & 0x1) !== 0,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function inflateEntry(buf, e) {
  if (e.dataOff == null) throw new Error(`无法定位 ${e.name} 的数据区`);
  const raw = buf.subarray(e.dataOff, e.dataOff + e.compSize);
  if (e.method === 0) return raw;
  if (e.method === 8) return inflateRawSync(raw);
  throw new Error(`不支持的压缩方式 ${e.method}（${e.name}）`);
}

function listZipViaUnzip(zipPath) {
  const r = spawnSync('unzip', ['-Z1', zipPath], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0 && !r.stdout) throw new Error('unzip 不可用：' + (r.error ? r.error.message : r.stderr));
  return r.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}

function readZipViaUnzip(zipPath, name) {
  const r = spawnSync('unzip', ['-p', zipPath, name], { maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error('unzip -p 失败：' + (r.error ? r.error.message : r.stderr));
  return r.stdout;
}

/**
 * 读取 zip 中所有文本文件
 * @returns {{ files: Array<{name,size,content,truncated}>, source: 'builtin'|'unzip', warnings: string[] }}
 */
export function readZip(zipPath) {
  const warnings = [];
  const buf = readFileSync(zipPath);
  let entries;
  try {
    entries = parseZip(buf);
  } catch (err) {
    warnings.push(`内置 zip 解析失败（${err.message}），回退到系统 unzip`);
    return readZipFallback(zipPath, warnings);
  }

  const files = [];
  for (const e of entries) {
    if (e.name.endsWith('/')) continue;                  // 目录项
    let content;
    try {
      content = inflateEntry(buf, e);
    } catch (err) {
      warnings.push(`无法解压 ${e.name}：${err.message}`);
      continue;
    }
    if (e.encrypted) warnings.push(`条目 ${e.name} 被加密，无法静态审查`);
    files.push(toFileEntry(e.name, content));
  }
  if (files.length === 0 && entries.length > 0) {
    warnings.push('没有成功解压出任何文件，回退到系统 unzip');
    return readZipFallback(zipPath, warnings);
  }
  return { files, source: 'builtin', warnings };
}

function readZipFallback(zipPath, warnings) {
  const names = listZipViaUnzip(zipPath);
  const files = [];
  for (const name of names) {
    if (name.endsWith('/')) continue;
    try {
      files.push(toFileEntry(name, readZipViaUnzip(zipPath, name)));
    } catch (err) {
      warnings.push(`无法读取 ${name}：${err.message}`);
    }
  }
  return { files, source: 'unzip', warnings };
}

const MAX_TEXT = 512 * 1024; // 单文件纳入报告上限，超出截断并标注
function toFileEntry(name, buf) {
  const truncated = buf.length > MAX_TEXT;
  return {
    name,
    size: buf.length,
    content: buf.toString('utf8'),
    truncated,
  };
}

// ---------------------------------------------------------------------------
// 文件分类
// ---------------------------------------------------------------------------

export const CANONICAL_SCRIPTS = ['customize.sh', 'service.sh', 'post-fs-data.sh', 'uninstall.sh', 'action.sh'];

export function classify(files) {
  const base = (p) => basename(p.replace(/\\/g, '/'));
  const canonical = [];
  const otherScripts = [];
  const others = [];
  let propEntry = null;

  for (const f of files) {
    const b = base(f.name);
    if (b === 'module.prop' && !propEntry) propEntry = f;
    if (CANONICAL_SCRIPTS.includes(b)) { canonical.push(f); continue; }
    if (extname(b).toLowerCase() === '.sh') { otherScripts.push(f); continue; }
    others.push(f);
  }
  // 规范脚本按既定顺序排列，便于阅读
  canonical.sort((a, b) => CANONICAL_SCRIPTS.indexOf(base(a.name)) - CANONICAL_SCRIPTS.indexOf(base(b.name)));
  return { canonical, otherScripts, others, propEntry };
}

// ---------------------------------------------------------------------------
// 扫描
// ---------------------------------------------------------------------------

/**
 * @param {string} zipPath
 * @param {{ declaredId?:string, declaredVersion?:string, changeType?: 'first'|'update', index?: object }} opts
 */
export function scanZip(zipPath, opts = {}) {
  const started = Date.now();
  const { files, source, warnings } = readZip(zipPath);
  const { canonical, otherScripts, propEntry } = classify(files);

  const findings = [];
  for (const f of [...canonical, ...otherScripts]) {
    findings.push(...scanContent(f.name, f.content));
  }

  // module.prop 也要过一遍内容规则（里面可能有外联地址或隐私路径）
  const propFindings = propEntry ? scanContent(propEntry.name, propEntry.content) : [];

  const propMeta = propEntry
    ? { present: true, path: propEntry.name, fields: parseModuleProp(propEntry.content).fields, raw: propEntry.content }
    : { present: false, path: 'module.prop', fields: {} };
  const metaFindings = checkMetadata(propMeta, { id: opts.declaredId, version: opts.declaredVersion });

  const all = [...findings, ...propFindings, ...metaFindings]
    .filter((f) => f.severity != null)
    .sort((a, b) => {
      const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
      if (d !== 0) return d;
      if (a.file !== b.file) return a.file < b.file ? -1 : 1;
      return a.line - b.line;
    });

  const { level, counts, reasons } = scoreRisk(all);
  const changeType = resolveChangeType(opts, propMeta);
  const decision = decide(level, changeType);

  return {
    schema: 'module-audit-report/v1',
    generatedAt: new Date().toISOString(),
    target: { zip: zipPath, zipName: basename(zipPath), bytes: 0 },
    reader: source,
    declared: { id: opts.declaredId || null, version: opts.declaredVersion || null },
    meta: {
      id: propMeta.fields.id ? propMeta.fields.id.value : null,
      version: propMeta.fields.version ? propMeta.fields.version.value : null,
      name: propMeta.fields.name ? propMeta.fields.name.value : null,
      author: propMeta.fields.author ? propMeta.fields.author.value : null,
      description: propMeta.fields.description ? propMeta.fields.description.value : null,
      propPath: propMeta.present ? propMeta.path : null,
      propPresent: propMeta.present,
    },
    inventory: {
      totalEntries: files.length,
      canonicalScripts: canonical.map((f) => ({ name: f.name, bytes: f.size, lines: countLines(f.content), truncated: f.truncated })),
      otherScripts: otherScripts.map((f) => ({ name: f.name, bytes: f.size, lines: countLines(f.content), truncated: f.truncated })),
      otherFiles: othersCount(files, canonical, otherScripts),
    },
    scripts: [...canonical, ...otherScripts].map((f) => ({
      name: f.name, bytes: f.size, lines: countLines(f.content), truncated: f.truncated, content: f.content,
    })),
    findings: all,
    counts,
    riskLevel: level,
    riskReasons: reasons,
    changeType,
    decision,
    warnings,
    durationMs: Date.now() - started,
  };
}

function countLines(s) { return s === '' ? 0 : s.split(/\r?\n/).length; }

function othersCount(files, canonical, otherScripts) {
  const set = new Set([...canonical, ...otherScripts].map((f) => f.name));
  return files.filter((f) => !set.has(f.name)).map((f) => f.name);
}

export function resolveChangeType(opts, propMeta) {
  if (opts.changeType === 'first' || opts.changeType === 'update') return opts.changeType;
  const id = propMeta.fields && propMeta.fields.id ? propMeta.fields.id.value : null;
  if (!id) return 'unknown';
  const idx = opts.index;
  if (!idx) return 'unknown';
  const list = Array.isArray(idx) ? idx : (idx && Array.isArray(idx.modules) ? idx.modules : null);
  if (!list) return 'unknown';
  const hit = list.some((m) => {
    if (!m) return false;
    if (typeof m === 'string') return m === id;
    return m.id === id || m.moduleId === id || m.module_id === id;
  });
  return hit ? 'update' : 'first';
}

// ---------------------------------------------------------------------------
// 报告渲染
// ---------------------------------------------------------------------------

const SEV_MARK = { high: '🔴 high', medium: '🟠 medium', low: '🟡 low', info: '🔵 info（不计入风险等级）' };

export function renderMarkdown(report) {
  const L = [];
  const m = report.meta;
  L.push('# 模块投稿安全审核报告');
  L.push('');
  L.push(`- 目标文件：\`${report.target.zipName}\``);
  L.push(`- zip 读取方式：${report.reader === 'builtin' ? '内置解析器' : '系统 unzip（回退）'}`);
  L.push(`- 生成时间：${report.generatedAt}`);
  L.push(`- 规则版本：静态规则表 \`risk-rules.mjs\`，共 ${CONTENT_RULES.length} 条内容规则`);
  L.push('');

  L.push('## 结论');
  L.push('');
  L.push(`**风险等级：${report.riskLevel.toUpperCase()}**`);
  L.push('');
  L.push(`- 变更类型：**${changeTypeLabel(report.changeType)}**`);
  L.push(`- 处置：**\`${report.decision.action}\`** / 标签 \`${report.decision.label}\``);
  L.push(`- 依据：${report.decision.reason}`);
  L.push(`- 命中统计：high ${report.counts.high} / medium ${report.counts.medium} / low ${report.counts.low} / info ${report.counts.info}`);
  L.push('');

  L.push('## 元数据');
  L.push('');
  L.push('| 字段 | module.prop | 投稿表单声明 | 是否一致 |');
  L.push('|---|---|---|---|');
  const idOk = !report.declared.id || !m.id ? '未声明' : (report.declared.id === m.id ? '✅ 一致' : '❌ 不一致');
  const verOk = !report.declared.version || !m.version ? '未声明' : (report.declared.version === m.version ? '✅ 一致' : '❌ 不一致');
  L.push(`| id | \`${m.id ?? '(缺失)'}\` | \`${report.declared.id ?? '(未提供)'}\` | ${idOk} |`);
  L.push(`| version | \`${m.version ?? '(缺失)'}\` | \`${report.declared.version ?? '(未提供)'}\` | ${verOk} |`);
  if (m.name) L.push('');
  if (m.name) L.push(`- name：${m.name}`);
  if (m.author) L.push(`- author：${m.author}`);
  if (m.description) L.push(`- description：${m.description}`);
  L.push(`- module.prop 路径：\`${m.propPath ?? '(缺失)'}\``);
  L.push('');

  L.push('## 文件清单');
  L.push('');
  L.push(`zip 内共 ${report.inventory.totalEntries} 个文件条目。`);
  L.push('');
  L.push('| 类别 | 文件 | 大小 | 行数 |');
  L.push('|---|---|---:|---:|');
  for (const s of report.inventory.canonicalScripts) L.push(`| 规范脚本 | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  for (const s of report.inventory.otherScripts) L.push(`| 其他 .sh | \`${s.name}\` | ${s.bytes} B | ${s.lines} |`);
  if (!report.inventory.canonicalScripts.length && !report.inventory.otherScripts.length) {
    L.push('| — | （无 shell 脚本） | — | — |');
  }
  if (report.inventory.otherFiles.length) {
    L.push('');
    L.push(`其他非脚本文件（${report.inventory.otherFiles.length} 个，仅列前 30 个）：` +
      report.inventory.otherFiles.slice(0, 30).map((n) => `\`${n}\``).join('、'));
  }
  L.push('');

  L.push('## 风险发现');
  L.push('');
  const risk = report.findings.filter(countsTowardRisk);
  if (!risk.length) {
    L.push('未命中任何风险规则。');
  } else {
    const byCat = groupBy(risk, (f) => f.category);
    for (const [cat, items] of byCat) {
      L.push(`### ${CATEGORY_LABEL[cat] || cat}`);
      L.push('');
      L.push('| 级别 | 规则 | 文件:行 | 原文片段 | 建议 |');
      L.push('|---|---|---|---|---|');
      for (const f of items) {
        L.push(`| ${SEV_MARK[f.severity]} | \`${f.ruleId}\` | \`${f.file}:${f.line}\` | \`${escapeCell(f.snippet)}\` | ${f.advice} |`);
      }
      L.push('');
    }
  }

  const priv = report.findings.filter((f) => !countsTowardRisk(f));
  L.push('## 投稿者隐私提示（不计入风险等级）');
  L.push('');
  if (!priv.length) {
    L.push('未发现需要提醒的隐私信息。');
    L.push('');
  } else {
    L.push('> 以下条目用于**保护投稿者**，不代表模块有恶意。发布前请清理。');
    L.push('');
    L.push('| 规则 | 文件:行 | 原文片段（已脱敏） | 建议 |');
    L.push('|---|---|---|---|');
    for (const f of priv) {
      L.push(`| \`${f.ruleId}\` | \`${f.file}:${f.line}\` | \`${escapeCell(mask(f.snippet))}\` | ${f.advice} |`);
    }
    L.push('');
  }

  if (report.warnings.length) {
    L.push('## 解析告警');
    L.push('');
    for (const w of report.warnings) L.push(`- ${w}`);
    L.push('');
  }

  L.push('## 脚本全文（人工复核用）');
  L.push('');
  if (!report.scripts.length) {
    L.push('zip 内没有 shell 脚本。');
  }
  for (const s of report.scripts) {
    L.push(`### \`${s.name}\` — ${s.bytes} B / ${s.lines} 行${s.truncated ? '（内容已截断，仅前 ' + MAX_TEXT + ' 字节）' : ''}`);
    L.push('');
    L.push('```sh');
    L.push(redactText(s.content));
    L.push('```');
    L.push('');
  }

  L.push('---');
  L.push('');
  L.push(`_本报告由 \`contrib/audit/scan.mjs\` 生成；${report.decision.needsHumanReview ? '本模块**需要人工审核**后才可进入正式索引。' : '本模块可自动进入索引。'}_`);
  L.push('');
  return L.join('\n');
}

function changeTypeLabel(t) {
  return t === 'first' ? '首次收录' : t === 'update' ? '版本更新（对已收录模块）' : '未知（未提供索引，无法判定）';
}

function groupBy(arr, fn) {
  const m = new Map();
  for (const x of arr) {
    const k = fn(x);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(x);
  }
  return m;
}

function escapeCell(s) {
  return String(s).replace(/\|/g, '\\|').replace(/`/g, "'");
}

/** 隐私片段脱敏：中间字符打码，保留首尾以便核对 */
export function mask(s) {
  const t = String(s);
  if (t.length <= 8) return t;
  const head = t.slice(0, 4);
  const tail = t.slice(-4);
  return `${head}${'*'.repeat(Math.min(12, t.length - 8))}${tail}`;
}

// ---------------------------------------------------------------------------
// 脚本全文脱敏
// ---------------------------------------------------------------------------

// 报告会作为 PR comment 公开发布，而 ① 要求脚本全文纳入报告。两者冲突时以
// “保护投稿者” 优先：对 privacy 类规则的命中原文做脱敏后再贴出全文。
const REDACT_RULES = CONTENT_RULES.filter((r) => r.category === 'privacy');

/** 对一段脚本文本做隐私脱敏（逐行命中 privacy 规则 -> 打码） */
export function redactText(text, rules = REDACT_RULES) {
  const lines = String(text == null ? '' : text).split(/\r?\n/);
  return lines.map((line) => {
    let out = line;
    for (const r of rules) {
      if (!r.pattern) continue;
      const flags = r.pattern.flags.includes('g') ? r.pattern.flags : r.pattern.flags + 'g';
      out = out.replace(new RegExp(r.pattern.source, flags), (m) => mask(m));
    }
    return out;
  }).join('\n');
}

export function renderJSON(report) {
  // JSON 报告里保留脚本全文（① 要求），但隐私片段与脚本中的隐私原文做脱敏，
  // 避免报告本身二次泄露投稿者信息
  const out = {
    ...report,
    findings: report.findings.map((f) => (countsTowardRisk(f) ? f : { ...f, snippet: mask(f.snippet) })),
    scripts: report.scripts.map((s) => ({ ...s, content: redactText(s.content) })),
  };
  return JSON.stringify(out, null, 2);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { opts._.push(a); continue; }
    const key = a.slice(2);
    const eq = key.indexOf('=');
    if (eq >= 0) opts[key.slice(0, eq)] = key.slice(eq + 1);
    else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) { opts[key] = argv[i + 1]; i++; }
    else opts[key] = true;
  }
  return opts;
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help || opts._.length === 0) {
    process.stdout.write(`用法: node scan.mjs <module.zip> [--declared-id ID] [--declared-version VER]
       [--index index.json] [--change-type first|update] [--out-dir DIR]
       [--json PATH] [--markdown PATH] [--stdout] [--quiet] [--fail-on high|medium|low|never]\n`);
    return 0;
  }
  const zipPath = resolve(opts._[0]);
  if (!existsSync(zipPath)) {
    process.stderr.write(`找不到文件: ${zipPath}\n`);
    return 1;
  }

  let index = null;
  if (opts.index) {
    try { index = JSON.parse(readFileSync(resolve(opts.index), 'utf8')); }
    catch (err) { process.stderr.write(`索引读取失败（按 unknown 处理）：${err.message}\n`); }
  }

  const report = scanZip(zipPath, {
    declaredId: typeof opts['declared-id'] === 'string' ? opts['declared-id'] : undefined,
    declaredVersion: typeof opts['declared-version'] === 'string' ? opts['declared-version'] : undefined,
    changeType: opts['change-type'] === 'first' || opts['change-type'] === 'update' ? opts['change-type'] : undefined,
    index,
  });

  const md = renderMarkdown(report);
  const json = renderJSON(report);

  const outDir = opts['out-dir'] ? resolve(opts['out-dir']) : null;
  const jsonPath = opts.json && typeof opts.json === 'string'
    ? resolve(opts.json)
    : (outDir ? join(outDir, `${report.target.zipName}.audit.json`) : resolve(`${zipPath}.audit.json`));
  const mdPath = opts.markdown && typeof opts.markdown === 'string'
    ? resolve(opts.markdown)
    : (outDir ? join(outDir, `${report.target.zipName}.audit.md`) : resolve(`${zipPath}.audit.md`));

  for (const p of [jsonPath, mdPath]) {
    const d = dirname(p);
    if (!existsSync(d)) mkdirSync(d, { recursive: true });
  }
  writeFileSync(jsonPath, json);
  writeFileSync(mdPath, md);

  if (opts.stdout) process.stdout.write(md);
  if (opts.quiet) {
    process.stdout.write(`${report.riskLevel} ${report.decision.action} ${report.decision.label} ` +
      `(high=${report.counts.high} medium=${report.counts.medium} low=${report.counts.low} info=${report.counts.info})\n`);
  } else if (!opts.stdout) {
    process.stdout.write(`风险等级 ${report.riskLevel} → ${report.decision.action} / ${report.decision.label}\n`);
    process.stdout.write(`  JSON: ${jsonPath}\n  Markdown: ${mdPath}\n`);
  }

  const failOn = opts['fail-on'] || 'never';
  if (failOn !== 'never') {
    const threshold = SEVERITY_ORDER[failOn] ?? 0;
    if (SEVERITY_ORDER[report.riskLevel] >= threshold && failOn !== 'never') return 2;
  }
  return 0;
}

// 仅当作为 CLI 直接运行时才跑 main（process.argv[1] 在 node -e 下不存在，必须判空）
function runAsCli() {
  const entry = process.argv[1];
  if (!entry) return false;
  const self = new URL(import.meta.url);
  try {
    return self.href === new URL(`file:///${entry.replace(/\\/g, '/')}`).href;
  } catch {
    return entry.endsWith('scan.mjs');
  }
}

if (runAsCli()) {
  process.exitCode = main();
}
