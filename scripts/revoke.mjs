#!/usr/bin/env node
/**
 * revoke.mjs —— 下处置的唯一入口（下架 revoke / 拉黑 deny）。
 *
 * 它存在的理由是一条不变式：**json/modules.json 只能由 build-index 从 pending + 台账推导**。
 * 所以这个脚本只做两件事：
 *   1. 往 json/dispositions.json 追加一条**有署名、有时间、有分类**的处置记录；
 *   2. 用子进程调 scripts/build-index.mjs 重算索引（不自己写索引 —— 免得这里成为第二份写路径）。
 * 然后打印该走的分支/PR 步骤。索引最终对不对，由 CI 的 derive（verify-index-pr）说了算，
 * 不由这个脚本说了算 —— 它的作者也是人，人也会写错。
 *
 * 用法：
 *   node scripts/revoke.mjs --id e2e_probe_min --kind revoke --reason test-probe \
 *        --by gh:yufengliang@issuecomment-12345 --note "流水线验证留下的探针包" [--dry-run]
 *   node scripts/revoke.mjs --uid 2781460 --kind deny --reason impersonation --by gh:... --note ...
 *   node scripts/revoke.mjs --id some_mod --version-code 12 --sha256 <64hex> --kind revoke --reason malware --by gh:...
 *
 * 只用 node: 内置模块（本仓库硬约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { DISPOSITIONS_SCHEMA, REASONS, loadDispositions, parseDispositions } from './dispositions.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '..');

/**
 * 组一条处置记录。
 *
 * `by` 必须是**别人能回访的指针**（`gh:<login>@<reviewId|issuecomment-…>`），不是「admin 说的」。
 * 无主章在追责链上是零价值 —— 与 pending 章 isApproved() 同一条理由，
 * 而处置比放行更需要留名：放行错了顶多多一个包，下架错了是把别人的作品抹掉。
 */
export function buildDisposition(flags, now = new Date()) {
  const kind = flags.kind || 'revoke';
  const d = {
    kind,
    reason: flags.reason,
    by: flags.by,
    at: now.toISOString(),
  };
  if (flags.id) d.id = String(flags.id).trim();
  if (flags['version-code'] !== undefined) d.versionCode = Number(flags['version-code']);
  if (flags.sha256) d.sha256 = String(flags.sha256).trim().toLowerCase();
  if (flags.uid) d.coolapkUid = String(flags.uid).trim();
  if (flags.note) d.note = String(flags.note).trim();
  if (flags.verify) d.verify = String(flags.verify).trim();
  return d;
}

/**
 * 两条记录的选择器是否完全相同（用来挡重复下处置）。
 * 只比选择器不比 reason/by：同一件事被下两次，后果是台账里出现两条互相矛盾的记录，
 * 而公示页会把同一个模块列两次。
 */
export function sameSelectors(a, b) {
  const keys = ['id', 'versionCode', 'sha256', 'coolapkUid'];
  return keys.every((k) => String(a[k] ?? '') === String(b[k] ?? ''));
}

export function parseArgs(argv) {
  const o = { kind: 'revoke' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    if (k === 'dry-run') { o['dry-run'] = true; continue; }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) { o[k] = true; continue; }
    o[k] = v;
    i++;
  }
  return o;
}

export function main(argv = process.argv.slice(2), io = console, deps = {}) {
  const flags = parseArgs(argv);
  const now = deps.now ? deps.now() : new Date();
  const ledgerFile = path.resolve(ROOT, flags.ledger || 'json/dispositions.json');
  const indexFile = path.resolve(ROOT, flags.index || 'json/modules.json');

  const usage = `用法: node scripts/revoke.mjs --id <id> [--version-code <n>] [--sha256 <64hex>] [--uid <酷安UID>]
          --kind revoke|deny --reason ${REASONS.join('|')} --by <可回访指针> [--note <公示说明>] [--verify <复核命令>] [--dry-run]`;
  if (!flags.id && !flags.sha256 && !flags.uid) {
    io.error(`[revoke] 必须至少给一个选择器（--id / --sha256 / --uid）。\n${usage}`);
    return 2;
  }
  if (flags['version-code'] !== undefined && !flags.id) {
    io.error('[revoke] --version-code 必须与 --id 同时给：脱离 id 的版本号会变成按数字全局下架');
    return 2;
  }
  if (!REASONS.includes(flags.reason)) {
    io.error(`[revoke] --reason 必须是公示分类之一（${REASONS.join(' / ')}），收到 ${JSON.stringify(flags.reason)}`);
    return 2;
  }
  if (!flags.by || flags.by === true) {
    io.error('[revoke] --by 不能为空：下了处置必须留名，且是可回访的指针（gh:<login>@<reviewId|issuecomment-…>）');
    return 2;
  }

  const entry = buildDisposition(flags, now);
  // 归一化+校验走同一条 parseDispositions：脚本不能有一套比 CI 松的校验，
  // 否则「本地能写进去、CI 判红」的台账会一直留在 main 的历史里。
  let normalized;
  try {
    [normalized] = parseDispositions({ schema: DISPOSITIONS_SCHEMA, dispositions: [entry] }, 'revoke.mjs 新条目');
  } catch (e) {
    io.error(`[revoke] 这条记录不合格，拒写：${e.message}`);
    return 2;
  }

  let list = [];
  try {
    list = loadDispositions(ledgerFile); // 已存在的台账坏了 -> 抛；不修好就别往上追加
  } catch (e) {
    io.error(`[revoke] 现有台账读不懂，先修好它再来追加：${e.message}`);
    return 3;
  }
  const dup = list.find((d) => sameSelectors(d, normalized));
  if (dup) {
    io.error('[revoke] 台账里已经有同样选择器的记录了，不重复下处置：\n  '
      + JSON.stringify({ kind: dup.kind, id: dup.id, versionCode: dup.versionCode, sha256: dup.sha256, coolapkUid: dup.coolapkUid, by: dup.by, at: dup.at }));
    io.error('  要改理由/补说明请另开一条并只写要改的那部分选择器；要撤销处置就删掉那条记录并走同一条 PR 流程。');
    return 4;
  }

  const next = {
    schema: DISPOSITIONS_SCHEMA,
    lastUpdate: now.getTime(),
    dispositions: [...list, normalized],
  };
  const text = `${JSON.stringify(next, null, 2)}\n`;

  io.log(`[revoke] 准备写入 ${path.relative(ROOT, ledgerFile)}：新增 1 条（现有 ${list.length} 条）`);
  io.log(`  ${JSON.stringify(normalized)}`);
  if (flags['dry-run']) {
    io.log('[revoke] --dry-run：没写任何文件，也没重算索引');
    return 0;
  }

  fs.mkdirSync(path.dirname(ledgerFile), { recursive: true });
  fs.writeFileSync(ledgerFile, text, 'utf8');

  // 索引交给 build-index 自己算 —— 写路径只有一份。
  const script = path.join(ROOT, 'scripts', 'build-index.mjs');
  const pendingDir = path.resolve(ROOT, flags.pending || 'pending');
  const out = execFileSync(process.execPath, [
    script, '--pending', pendingDir, '--index', indexFile, '--dispositions', ledgerFile,
  ], { cwd: ROOT, encoding: 'utf8' });
  io.log(out.trimEnd());

  const validate = path.join(ROOT, 'scripts', 'validate-index.mjs');
  const v = execFileSync(process.execPath, [validate, indexFile], { cwd: ROOT, encoding: 'utf8' });
  io.log(v.trimEnd());

  io.log('');
  io.log('[revoke] 文件已改好，还没有提交。下一步（索引对不对由 CI 的 derive 判定，不由这个脚本判定）：');
  io.log(`  git checkout -b revoke/${normalized.id || normalized.sha256?.slice(0, 12) || normalized.coolapkUid}`);
  io.log('  git add json/dispositions.json json/modules.json');
  io.log('  git commit -m "chore(dispose): revoke ' + (normalized.id || normalized.sha256 || normalized.coolapkUid) + '"');
  io.log('  git push -u origin HEAD && gh pr create --title "chore(dispose): 下架 …" --body "…"');
  io.log('  然后看 approve 是否绿：它会重算一遍并逐字段比对（verify-index-pr 的台账驱动模式）。');
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exitCode = main();
}
