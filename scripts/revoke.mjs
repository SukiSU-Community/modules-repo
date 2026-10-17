#!/usr/bin/env node
/**
 * revoke.mjs —— 下处置的唯一入口（下架 revoke / 拉黑 deny）。
 *
 * 它存在的理由是一条不变式：**json/modules.json 只能由 build-index 从 pending + 台账推导**。
 * 所以这个脚本只做三件事：
 *   1. 往 json/dispositions.json 追加一条**有署名、有时间、有分类**的处置记录；
 *   2. 用 §8 固化（harvest-evidence.mjs）把被处置那一包的证据落成 `evidence/<sha256>.json`，
 *      并给这条记录带上 `subject` / `evidence`（拿不到证据就退成不带这两个键，见那条注释）；
 *   3. 用子进程调 scripts/build-index.mjs 重算索引（不自己写索引 —— 免得这里成为第二份写路径）。
 * 然后打印该走的分支/PR 步骤。索引最终对不对，由 CI 的 derive（verify-index-pr）说了算，
 * 不由这个脚本说了算 —— 它的作者也是人，人也会写错。
 *
 * 用法：
 *   node scripts/revoke.mjs --id e2e_probe_min --kind revoke --reason test-probe \
 *        --by gh:yufengliang@issuecomment-12345 --note "流水线验证留下的探针包" [--dry-run]
 *   node scripts/revoke.mjs --uid 10086001 --kind deny --reason impersonation --by gh:... --note ...
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
import { harvest, ledgerFieldsFrom } from './harvest-evidence.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '..');

/**
 * 处置指针的规范形态：**浏览器里点得开的永久链接**。
 *
 * 为什么不是 `gh:<login>@issuecomment-<id>`（这是第一版随手写的形状）：GitHub 的评论 id
 * 单独拼不出 URL，必须知道它挂在哪个 issue 上 —— 只有 id 的指针在公示页上是一段死文本，
 * 谁都得自己去搜。实测过：`api.github.com/repos/<repo>/issues/comments/<id>` 会回 html_url，
 * 但那是要求访问者自己去查的东西，不该出现在「点一下就能看证据」这一步。
 *
 * 校验放在**写入端**而不是 dispositions.mjs 的通用校验里：台账里已经有 5 条旧形状的记录，
 * 让校验器拒收旧记录 = 读不懂台账 = 推导停住 = 索引冻死（那条失效方向是设计好的），
 * 而写入端收紧只影响以后下的处置。
 */
export const PROOF_URL_RE = /^https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/issues\/\d+#issuecomment-\d+$/;

/**
 * 组一条处置记录。
 *
 * `by` 必须是**别人能回访、且在浏览器里点得开**的证据链接，不是「admin 说的」。
 * 无主章在追责链上是零价值 —— 与 pending 章 isApproved() 同一条理由，
 * 而处置比放行更需要留名：放行错了顶多多一个包，下架错了是把别人的作品抹掉。
 */
export function buildDisposition(flags, now = new Date()) {
  const kind = flags.kind || 'revoke';
  const by = String(flags.by || '').trim();
  if (!PROOF_URL_RE.test(by)) {
    throw new Error(
      '--by 必须是点得开的 GitHub 证据链接（https://github.com/<owner>/<repo>/issues/<n>#issuecomment-<id>），'
      + `收到 ${JSON.stringify(flags.by)}。评论 URL 的拿法：在 issue 里发完说明后点那条评论的时间戳，`
      + '或 GET api.github.com/repos/<owner>/<repo>/issues/comments/<id> 取 html_url。'
    );
  }
  const d = {
    kind,
    reason: flags.reason,
    by,
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
    if (k === 'dry-run' || k === 'no-harvest') { o[k] = true; continue; }
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) { o[k] = true; continue; }
    o[k] = v;
    i++;
  }
  return o;
}

export async function main(argv = process.argv.slice(2), io = console, deps = {}) {
  const flags = parseArgs(argv);
  const now = deps.now ? deps.now() : new Date();
  const ledgerFile = path.resolve(ROOT, flags.ledger || 'json/dispositions.json');
  const indexFile = path.resolve(ROOT, flags.index || 'json/modules.json');

  const usage = `用法: node scripts/revoke.mjs --id <id> [--version-code <n>] [--sha256 <64hex>] [--uid <酷安UID>]
          --kind revoke|deny --reason ${REASONS.join('|')}
          --by https://github.com/<owner>/<repo>/issues/<n>#issuecomment-<id>
          [--note <公示说明>] [--verify <复核命令>] [--dry-run] [--no-harvest]`;
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
    io.error(`[revoke] --by 不能为空：下了处置必须留下点得开的证据链接。\n${usage}`);
    return 2;
  }

  let entry;
  try {
    entry = buildDisposition(flags, now);
  } catch (e) {
    io.error(`[revoke] ${e.message}`);
    return 2;
  }
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

  // ---- §8 证据固化：在写台账之前，把「当初审核过的那一包」落成 evidence/<sha256>.json。
  // 顺序是有意的：台账里那条 `evidence[].file` 必须指向**同一条 PR 里真的写出来的文件**，
  // 反过来说，固化没跑成功时这条记录就退回「没有附件的处置」（schema v2 的两个字段都是可选的），
  // 而不是写一个指空文件的指针 —— 后者会被 verify-index-pr 的互指认判红，等于把处置卡在 PR 外面。
  const harvestSelectors = {
    ...(normalized.id ? { id: normalized.id } : {}),
    ...(normalized.versionCode !== undefined ? { versionCode: normalized.versionCode } : {}),
    ...(normalized.sha256 ? { sha256: normalized.sha256 } : {}),
    ...(normalized.coolapkUid ? { coolapkUid: normalized.coolapkUid } : {}),
  };
  let harvested = null;
  if (flags['no-harvest']) {
    io.log('[revoke] --no-harvest：跳过 §8 固化，这条处置不带 subject / evidence');
  } else {
    try {
      const run = deps.harvest || harvest;
      harvested = await run({ cwd: ROOT, selectors: harvestSelectors, deps: deps.harvestDeps || {} });
    } catch (e) {
      io.error(`[revoke] 固化这一步跑挂了：${String((e && e.message) || e)}`);
      harvested = null;
    }
    if (harvested && !harvested.ok) {
      io.error(`[revoke] 没固化到证据：${harvested.whyEmpty}`);
      io.error(`  这条处置照写（evidence 是可选字段），但事后要补回来：\n`
        + `    node scripts/harvest-evidence.mjs ${Object.entries(harvestSelectors).map(([k, v]) => `--${k === 'coolapkUid' ? 'uid' : k === 'versionCode' ? 'version-code' : k} ${v}`).join(' ')} --write`);
      harvested = null;
    }
  }
  let finalEntry = normalized;
  if (harvested) {
    const fields = ledgerFieldsFrom(harvested, now);
    finalEntry = { ...normalized, ...fields };
    // 带上新字段再走一遍同一份校验：脚本这里不能比 CI 松（上面那句注释的同一条理由）。
    try {
      [finalEntry] = parseDispositions({ schema: DISPOSITIONS_SCHEMA, dispositions: [finalEntry] }, 'revoke.mjs 固化后的条目');
    } catch (e) {
      io.error(`[revoke] 固化带出来的 subject / evidence 不合格，拒写：${e.message}`);
      return 5;
    }
    for (const n of harvested.notes) io.log(`[revoke] 固化注意：${n}`);
    io.log(`[revoke] 固化到 ${harvested.files.length} 份证据（扫了 ${harvested.scanned} 条 pending 提交）`);
  }

  const next = {
    schema: DISPOSITIONS_SCHEMA,
    lastUpdate: now.getTime(),
    dispositions: [...list, finalEntry],
  };
  const text = `${JSON.stringify(next, null, 2)}\n`;

  io.log(`[revoke] 准备写入 ${path.relative(ROOT, ledgerFile)}：新增 1 条（现有 ${list.length} 条）`);
  io.log(`  ${JSON.stringify(finalEntry)}`);
  if (flags['dry-run']) {
    io.log('[revoke] --dry-run：没写任何文件，也没重算索引');
    return 0;
  }

  // 证据文件落在台账之前：文件名是它自己字节的哈希，已存在且同内容就跳过（同一份内容必然同名），
  // 已存在但**内容不同**必须停下来问人 —— 那是有人在改一份已经被人引用过的证据。
  if (harvested) {
    // 证据落在**仓库根**（白名单与互指认都按 `evidence/**` 这个根相对路径判），
    // --evidence-dir 只是给单测留的接缝：它不改变台账里写的路径，只改变落在哪儿。
    const evidenceRoot = flags['evidence-dir'] ? path.resolve(ROOT, String(flags['evidence-dir'])) : ROOT;
    for (const f of harvested.files) {
      const abs = path.join(evidenceRoot, ...f.path.split('/'));
      if (fs.existsSync(abs)) {
        const cur = fs.readFileSync(abs);
        if (cur.equals(f.bytes)) { io.log(`[revoke] ${f.path} 已存在且逐字节一致，跳过`); continue; }
        io.error(`[revoke] ${f.path} 已存在但内容不同 —— 同名不同物只有一种解释：有人改过证据。停下来问人，不覆盖。`);
        return 6;
      }
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, f.bytes);
      io.log(`[revoke] 已写 ${path.relative(ROOT, abs)}`);
    }
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
  const what = finalEntry.id || finalEntry.sha256?.slice(0, 12) || finalEntry.coolapkUid;
  io.log(`  git checkout -b revoke/${what}`);
  // 证据文件必须和台账**同一条 PR**：verify-index-pr 的白名单只在「这条 PR 同时改了台账」时
  // 才放行 evidence/**，而互指认那一步要求台账引用的文件真的在 head 上。漏掉这一格 = PR 直接红。
  io.log('  git add json/dispositions.json json/modules.json' + (finalEntry.evidence ? ' evidence/' : ''));
  io.log('  git commit -m "chore(dispose): revoke ' + what + '"');
  io.log('  git push -u origin HEAD && gh pr create --title "chore(dispose): 下架 …" --body "…"');
  io.log('  然后看 approve 是否绿：它会重算一遍并逐字段比对（verify-index-pr 的台账驱动模式）。');
  io.log('  ⚠️ 动了台账的 PR 不算索引重建，它换了一道准入：需要**两名不同的人**在本 PR 评论**首行**写');
  io.log('     #human-approved，且签的人得对这个仓库有 write/admin（CI 逐个查 permission，见 GOVERNANCE 第 7 节），');
  io.log('     要能回访成这两人之一的真评论 —— 所以 --by 必须是你们其中一人真发过的评论，不是「admin 说的」。');
  io.log('     签齐 ⇒ merge-index 自动合并在 main 上，并立刻 purge CDN；签不齐 ⇒ approve 红，什么都不合。');
  io.log('     判据在 scripts/verify-index-pr.mjs（复用 publish-from-main 的 REQUIRED_SIGNERS=2），见 GOVERNANCE.md 第 2 节。');
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  // main 现在是 async（§8 固化要读 git 历史与 PR 评论），所以退出码要等它。
  process.exitCode = await main();
}
