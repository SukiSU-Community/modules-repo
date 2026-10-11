#!/usr/bin/env node
/**
 * disposition-check.mjs —— 三处拦截里的「CI 侧」那一道。
 *
 * 投稿 PR 带着 pending 条目进来时，按 main/head 上的处置台账判一次：
 * 命中就不许自动放行（approve 变红），并把命中的是哪一条、谁下的、为什么写进结论。
 *
 * 为什么三处都要判，而不是只在这一处：
 *   * Worker 提交入口 —— 挡住就别再产生 release asset、分支和 PR（省一次污染，也让投稿者当场看见原因）；
 *   * 这里 —— Worker 的台账可能有缓存、也可能取不到（取不到时它是**放行**的，
 *     因为「酷安/网络挂了不能让所有人投不了稿」），所以不能只靠它；
 *   * build-index 推导 —— 最终防线。索引是推导出来的，台账参与推导，
 *     于是前面两处都漏了也进不了索引。三处用的是同一个 `scripts/dispositions.mjs`，
 *     判据只有一份。
 *
 * 只用 node: 内置模块（本仓库硬约束）。
 */
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { loadDispositions, matchAny } from './dispositions.mjs';

/** 取本次 PR 相对 base 新增/修改的 pending 路径。 */
export function changedPending({ cwd, base, pendingDir = 'pending' }) {
  const mb = base ? String(base).trim() : '';
  let out = '';
  if (mb) {
    out = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMR', `${mb}..HEAD`, '--', pendingDir], {
      cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
    });
  } else {
    // 没有 base（本地手工跑）：把整个 pending 都看一遍，宁可多判。
    const walk = (dir, depth) => {
      const acc = [];
      if (depth > 8 || !fs.existsSync(dir)) return acc;
      for (const name of fs.readdirSync(dir).sort()) {
        const full = path.join(dir, name);
        const st = fs.statSync(full);
        if (st.isDirectory()) acc.push(...walk(full, depth + 1));
        else if (name.endsWith('.json') && !name.startsWith('.')) acc.push(path.relative(cwd, full).split(path.sep).join('/'));
      }
      return acc;
    };
    out = walk(path.resolve(cwd, pendingDir), 0).join('\n');
  }
  return out.split('\n').map((s) => s.trim()).filter((s) => s && s.endsWith('.json') && !path.basename(s).startsWith('.'));
}

/**
 * 判一次。返回 {hit, lines}，lines 是要贴进结论/GITHUB_OUTPUT 的文本。
 *
 * @param {{cwd: string, ledgerFile: string, files: string[], log?: (s: string) => void}} input
 */
export function checkFiles({ cwd, ledgerFile, files }) {
  // 台账读不懂 → 抛给调用方，让它变成**红**而不是「没命中」。
  // 这里静默当空台账的话，一次坏 JSON 就等于把三道闸一起拆了。
  const dispositions = loadDispositions(ledgerFile);
  const hits = [];
  for (const rel of files) {
    const full = path.resolve(cwd, rel);
    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(full, 'utf8'));
    } catch (e) {
      // pending 读不懂是扫描那边的事（build-index 会记 invalid-entry），这里不越权判。
      hits.push({ file: rel, unreadable: `读不懂（${e.message}），交给 build-index 记非法条目` });
      continue;
    }
    for (const entry of Array.isArray(raw) ? raw : [raw]) {
      const hit = matchAny(dispositions, entry);
      if (!hit) continue;
      hits.push({
        file: rel,
        id: entry && entry.id,
        via: hit.via,
        versionCode: hit.versionCode,
        kind: hit.matched.kind,
        reason: hit.matched.reason,
        by: hit.matched.by,
        at: hit.matched.at,
        note: hit.matched.note,
      });
    }
  }
  const hit = hits.some((h) => !h.unreadable);
  const lines = hits.map((h) => (h.unreadable
    ? `  - ${h.file}：${h.unreadable}`
    : `  - ${h.id}${h.versionCode ? `@${h.versionCode}` : ''} 命中 ${h.kind}（via ${h.via}）｜reason=${h.reason}｜by=${h.by}｜at=${h.at}${h.note ? `｜note=${h.note}` : ''}｜文件 ${h.file}`));
  return { hit, lines, unreadable: hits.filter((h) => h.unreadable).length };
}

export function parseArgs(argv) {
  const o = { pendingDir: 'pending', _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--base') { o.base = argv[++i]; continue; }
    if (a === '--ledger') { o.ledger = argv[++i]; continue; }
    if (a === '--pending-dir') { o.pendingDir = argv[++i]; continue; }
    if (a === '--file') { (o.files ||= []).push(argv[++i]); continue; }
    if (a === '--github-output') { o.githubOutput = true; continue; }
    if (!a.startsWith('--')) o._.push(a);
  }
  return o;
}

export function main(argv = process.argv.slice(2), io = console) {
  const opts = parseArgs(argv);
  const cwd = process.cwd();
  const ledgerFile = path.resolve(cwd, opts.ledger || 'json/dispositions.json');
  const files = opts.files && opts.files.length ? opts.files : changedPending({ cwd, base: opts.base, pendingDir: opts.pendingDir });

  let r;
  try {
    r = checkFiles({ cwd, ledgerFile, files });
  } catch (e) {
    io.error(`[disposition-check] 台账读不懂，本次判定不通过（不当「没命中」处理）：${e.message}`);
    return 3;
  }

  if (opts.githubOutput) {
    const out = process.env.GITHUB_OUTPUT;
    if (out) {
      fs.appendFileSync(out, `hit=${r.hit ? 'hit' : 'clear'}\n`);
      fs.appendFileSync(out, `why=${(r.lines.length ? r.lines.join(' ') : `扫描 ${files.length} 个 pending 文件，无命中`).replace(/\r?\n/g, ' ')}\n`);
    }
  }
  io.log(`[disposition-check] 台账 ${path.relative(cwd, ledgerFile)}｜检查 ${files.length} 个 pending 文件｜结果=${r.hit ? '命中' : '未命中'}${r.unreadable ? `（另有 ${r.unreadable} 个文件读不懂）` : ''}`);
  for (const line of r.lines) io.log(line);
  // 命中不改变退出码语义：这一步只产出结论，红由 approve 判。
  // 让扫描作业因为「命中黑名单」而崩掉，会把 audit 的 report/label 全带走，
  // 投稿者只看到一个红叉而不知道为什么被拒。
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exitCode = main();
}
