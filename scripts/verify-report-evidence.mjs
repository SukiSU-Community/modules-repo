#!/usr/bin/env node
/**
 * 台账 PR 的复核步 —— 把「这条下架凭什么成立」变成一次任何人都能重跑的字节的检查。
 *
 * 为什么需要它（判据层的第 ④ 条，见 verify-index-pr.mjs 的 judgeLedgerSeal）：机器章那四条
 * 结构判据谁都能凑齐 —— 形状对、指向本 PR 的提交、实体当时就在、字节没改。它们证明的是
 * 「这条记录没有被偷改」，证明不了「引用的那段东西真在包里」。而 §7 与 owner 拍板 #3 说的那道
 * 门槛正是后者：**实名 + 包内逐字定位到才下架**。这一步产出的 `{ "<章指向的 commit>": {ok} }`
 * 就是那一格的证据。
 *
 * 复核拿的是举报记录里已经存下的坐标（条目名 + 条目内字节偏移 + 那段的 sha256 + 长度），
 * 然后**独立地**再取一次归档：
 *   0. 处置点名的那枚产物必须**就在 base 的索引里**（同 id、同 sha256），取包地址用索引里那条
 *      zipUrl —— 不是证据记录里写的那一条（见 publishedVersion 的注释，那一格才是「不许自带 zip」的落点）；
 *   1. 按内容寻址名 `<sha256>.zip` 取包，实算摘要必须等于记录里那个 sha256；
 *   2. 解压记录点名的那一个条目（走 audit/scan.mjs 的 readZipEntryBytes，拿**原始字节**，
 *      不是 utf8 串 —— 串会毁掉字节，见那里的注释）；
 *   3. 切 [entryOffset, entryOffset+quoteBytes) 这一段，实算 sha256 必须等于 quoteSha256。
 * 四步全过才算这条引用定位到。任何一步取不到、读不出、对不上 ⇒ 这一枚章不算成立。
 *
 * 失效方向：全部**判红**（不成立 ⇒ approve 红 ⇒ merge-index 不合）。下架错了是把别人的作品
 * 抹掉并把名字挂上公示页，那种事上「拿不准」必须等于「不动」。
 *
 * 只用 node: 内置模块（本仓库硬约束）。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import { parseDispositions, DEFAULT_DISPOSITIONS_FILE } from './dispositions.mjs';
import { ledgerTouched, parseSeal } from './verify-index-pr.mjs';
import { assertDownloadUrl, downloadToBuffer, sha256Hex } from './fetch-pending-zip.mjs';
import { readZipEntryBytes } from '../audit/scan.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '..');

export const REPORT_EVIDENCE_SCHEMA = 'sukisu-report-evidence-v1';

/** 索引文件：被下架的那一枚产物「现在用户能不能下到」由它回答。 */
export const DEFAULT_INDEX_FILE = 'json/modules.json';

/** 一条 PR 里最多复核几包（每包一次归档下载）。批量口径的上限，防止一轮把 runner 拖死。 */
export const MAX_PACKAGES_PER_RUN = 8;

/** 单条目解压上限：与扫描面同一把尺（超大条目读不出来就是读不出来，不放行）。 */
export const ENTRY_LIMIT = 24 * 1024 * 1024;

export function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/** 读某个 ref 上的台账；不存在给空数组，读不懂**抛**（与 verify-index-pr 同一条方向）。 */
export function ledgerAtRef(cwd, ref, file = DEFAULT_DISPOSITIONS_FILE) {
  let text;
  try {
    text = git(cwd, ['show', `${ref}:${file}`]);
  } catch (e) {
    const msg = String((e && e.stderr) || (e && e.message) || '');
    if (/does not exist in|exists on disk, but not in|does not exist on disk|pathspec/i.test(msg)) return [];
    throw new Error(`${ref} 上的台账取不出来：${msg.trim().split('\n')[0]}`);
  }
  return parseDispositions(JSON.parse(text), `${ref}:${file}`);
}

/**
 * 读某个 ref 上的索引，并**把「没有这个文件」和「有但读不懂」分开**：前者在空索引仓库里是合法的，
 * 后者必须让整个复核判红 —— 一份坏掉的索引如果被当成「索引里没有这一枚」，
 * 就等于把「对照物不见了」伪装成「举报对象不存在」。
 */
export function indexAtRef(cwd, ref, file = DEFAULT_INDEX_FILE) {
  let text;
  try {
    text = git(cwd, ['show', `${ref}:${file}`]);
  } catch (e) {
    const msg = String((e && e.stderr) || (e && e.message) || '');
    if (/does not exist in|exists on disk, but not in|does not exist on disk|pathspec/i.test(msg)) {
      return { present: false, modules: [] };
    }
    throw new Error(`${ref} 上的索引取不出来：${msg.trim().split('\n')[0]}`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new Error(`${ref} 上的索引不是合法 JSON：${e.message}`);
  }
  return { present: true, modules: Array.isArray(doc && doc.modules) ? doc.modules : [] };
}

/**
 * 这一枚下架指的是「base 的索引里用户真能下到的那一包」吗。
 *
 * 为什么必须有这一格：举报证据记录里的 `package.sha256` 与 `assetUrl` 都是**文本**，
 * 一条台账 PR 如果照记录里写的地址去取包，那么一个有写权限的人可以自己在 releases 上
 * 传一枚 `<自己算的 sha>.zip`、再写一条引用它的处置 —— 逐字节复核会全绿，因为它验的
 * 是他自己造的那一包。把对照物换成 base 那份索引里同 id 同 sha 的**已发布产物**之后，
 * 「验的字节」必须由 main 上那条索引记录决定，而那份索引正是 `pin` 步钉回 base 的、
 * PR 改不动的东西。取不到对照 ⇒ 这一枚章不成立（宁可不下架）。
 *
 * @returns {{ok:true, version:object}|{ok:false, why:string}}
 */
export function publishedVersion(modules, d) {
  if (!d.id) return { ok: false, why: '处置只有 sha256/uid 选择器，索引里定位不到「下架的是哪一枚已发布产物」' };
  if (!/^[0-9a-f]{64}$/.test(String(d.sha256 || ''))) {
    return { ok: false, why: `处置没有带 64 位十六进制的 sha256（收到 ${JSON.stringify(d.sha256)}），无从与索引对照` };
  }
  const versions = modules.filter((m) => m && m.id === d.id)
    .flatMap((m) => (Array.isArray(m.versions) ? m.versions : []));
  if (!versions.length) return { ok: false, why: `base 的索引里没有 id=${d.id} 的任何产物` };
  const hit = versions.find((v) => String(v.sha256 || '').trim().toLowerCase() === d.sha256
    && (d.versionCode === undefined || Number(v.versionCode) === Number(d.versionCode)));
  if (!hit) {
    return {
      ok: false,
      why: `base 的索引里 id=${d.id} 没有 ${d.sha256.slice(0, 12)} 这一枚产物`
        + `（索引里是 ${versions.map((v) => String(v.sha256 || '').slice(0, 12)).join(', ') || '空'}）`,
    };
  }
  if (!isNonEmptyUrl(hit.zipUrl)) return { ok: false, why: `索引里那一枚产物没有可取的 zipUrl，逐字复核没有取包地址` };
  return { ok: true, version: hit };
}

function isNonEmptyUrl(s) {
  return typeof s === 'string' && /^https:\/\//i.test(s.trim());
}

/** 一条引用在字节上的复核：坐标合法 + 那段实算摘要对得上。 */
export function checkOneHit(hit, bytes) {
  const where = `${hit.entry}@${hit.entryOffset}`;
  if (!Number.isInteger(hit.entryOffset) || hit.entryOffset < 0) return `${where}：偏移不是非负整数`;
  if (!Number.isInteger(hit.quoteBytes) || hit.quoteBytes <= 0) return `${where}：长度不是正整数`;
  if (!/^[0-9a-f]{64}$/.test(String(hit.quoteSha256 || ''))) return `${where}：那段内容的 sha256 不是 64 位十六进制`;
  const to = hit.entryOffset + hit.quoteBytes;
  if (to > bytes.length) return `${where}：条目只有 ${bytes.length} 字节，切不出 [${hit.entryOffset}, ${to})`;
  const got = sha256Hex(bytes.subarray(hit.entryOffset, to));
  if (got !== String(hit.quoteSha256).toLowerCase()) {
    return `${where}：那 ${hit.quoteBytes} 个字节实算是 ${got.slice(0, 12)}，与记录里的 ${String(hit.quoteSha256).slice(0, 12)} 不是同一段`;
  }
  return null;
}

/**
 * 纯判据：一份举报证据记录 + 两个取字节的接口 ⇒ 这一枚章成不成立。
 *
 *   `openPackage(pkg)` → 整包的原始字节（调用方负责只取一次并算好摘要前先取到）
 *   `readEntry(name)`  → 那一枚条目的原始字节，读不出就抛
 *
 * 这一层不下载、不碰 zip 路径，所以每一条失效方向都能在没有网络的情况下逐字打到。
 */
export function verifyReportEvidenceDoc(ev, { openPackage, readEntry }) {
  const problems = [];
  if (!ev || typeof ev !== 'object') return { ok: false, problems: ['证据记录不是对象'], checked: 0 };
  if (ev.schema !== REPORT_EVIDENCE_SCHEMA) {
    return { ok: false, problems: [`证据记录的 schema 是 ${JSON.stringify(ev.schema)}，这一步只认 ${REPORT_EVIDENCE_SCHEMA}`], checked: 0 };
  }
  const v = ev.verdict || {};
  // 记录自己说「成立」只是**起点**：它决定我们有没有东西可复核，而真不真在下面逐字节验。
  // 反过来（拿一条被拒的举报来盖下架的章）必须在这一格就被挡下。
  if (v.established !== true) problems.push(`这条举报自己就不成立（code=${JSON.stringify(v.code)}），不该被拿去盖章`);
  if (v.thresholds && v.thresholds.locatedAll !== true) problems.push('记录说并非每条引用都在包里定位到');
  if (Array.isArray(v.misses) && v.misses.length) problems.push(`记录里有 ${v.misses.length} 条没定位到的引用`);
  if (Array.isArray(v.unreadableEntries) && v.unreadableEntries.length) {
    problems.push(`记录里有 ${v.unreadableEntries.length} 个条目当时解不出来（${v.unreadableEntries.map((u) => u.name).join(', ')}）`);
  }
  const hits = Array.isArray(v.hits) ? v.hits : [];
  if (!hits.length) problems.push('记录里一条定位到的引用都没有 —— 没有可复核的字节，就没有可盖章的东西');

  const pkg = ev.package || {};
  if (!/^[0-9a-f]{64}$/.test(String(pkg.sha256 || ''))) problems.push('package.sha256 不是 64 位十六进制，取哪一包都无从确定');
  if (problems.length) return { ok: false, problems, checked: 0 };

  let bytes = null;
  try {
    bytes = openPackage(pkg);
  } catch (e) {
    return { ok: false, problems: [`取归档失败：${String((e && e.message) || e)}`], checked: 0 };
  }
  const got = sha256Hex(bytes);
  if (got !== String(pkg.sha256).toLowerCase()) {
    return { ok: false, problems: [`取回来的包实算 sha256 是 ${got.slice(0, 12)}，与记录里的 ${String(pkg.sha256).slice(0, 12)} 不是同一个包`], checked: 0 };
  }
  let checked = 0;
  for (const hit of hits) {
    let entryBytes;
    try {
      entryBytes = readEntry(hit.entry);
    } catch (e) {
      problems.push(`条目 ${hit.entry} 解不出来：${String((e && e.message) || e)}`);
      continue;
    }
    const p = checkOneHit(hit, entryBytes);
    if (p) problems.push(p);
    else checked++;
  }
  return { ok: problems.length === 0, problems, checked, hits: hits.length };
}

/**
 * 复核一条台账 PR 的全部新增/改动处置 ⇒ `{ "<章指向的 commit>": {ok, summary|reason} }`。
 *
 * 归档按 sha256 只取一次（同一枚包可能被多条处置引用）。三个接口都能注入，因此这一层的
 * 每一条分支都在没有 runner、没有网络的情况下测得到；真 git 那一路另有用例作证。
 */
export async function reviewLedgerPr({
  cwd = ROOT, baseRef = 'origin/main', headRef = 'HEAD', dispFile = DEFAULT_DISPOSITIONS_FILE,
  indexFile = DEFAULT_INDEX_FILE, deps = {},
} = {}) {
  const download = deps.download || ((pkg) => {
    const checked = assertDownloadUrl(pkg.assetUrl || '', {
      assetName: pkg.assetName, sha256: pkg.sha256, releaseTag: pkg.releaseTag,
    });
    if (!checked.ok) return Promise.reject(new Error(`归档地址不被接受：${checked.error}`));
    return downloadToBuffer(checked.url).then((b) => new Uint8Array(b.buffer, b.byteOffset, b.byteLength));
  });
  // 把下载到的字节落成临时文件，是因为 readZipEntryBytes 收的是路径（与扫描面同一个入口，
  // 不在这里再写第二个 zip 解析器）。
  const materialize = deps.materialize || ((bytes) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-zip-'));
    const p = path.join(dir, 'package.zip');
    fs.writeFileSync(p, bytes);
    return { path: p, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
  });
  const readEntry = deps.readEntry || ((zipPath, name) => readZipEntryBytes(zipPath, name, ENTRY_LIMIT));

  let base, head;
  try {
    base = ledgerAtRef(cwd, baseRef, dispFile);
    head = ledgerAtRef(cwd, headRef, dispFile);
  } catch (e) {
    return { reviews: {}, notes: [String((e && e.message) || e)], packagesUsed: 0, touched: null, fatal: '台账读不出来' };
  }
  // 对照物读不出来 ⇒ 整步按「没复核」处理。这一格不能退成「索引里没有 ⇒ 复核不通过」的红：
  // 那种写法让一份坏 JSON 看起来和一次合法的举报落空一模一样，而它们需要的动作相反。
  let baseIndex;
  try {
    baseIndex = indexAtRef(cwd, baseRef, indexFile);
  } catch (e) {
    return { reviews: {}, notes: [String((e && e.message) || e)], packagesUsed: 0, touched: null, fatal: `${baseRef} 上的索引读不出来` };
  }
  const touched = ledgerTouched(base, head);
  const notes = [];
  // 按「章指向的那枚 commit」聚合，而不是按处置聚合：多条处置常常共享同一枚提交（一轮批量就是
  // 一次提交里写好几条）。判据是「这一枚提交上的**每一条**处置都复核过了」，所以任何一个
  // 失败都要留在这格的红里 —— 直接按 sha 覆写的话，前面那条的失败会被后面那条的成功抹掉。
  const acc = new Map();
  const addProblem = (sha, msg) => {
    if (!acc.has(sha)) acc.set(sha, { problems: [], checked: 0 });
    acc.get(sha).problems.push(msg);
  };
  const addChecked = (sha, n) => {
    if (!acc.has(sha)) acc.set(sha, { problems: [], checked: 0 });
    acc.get(sha).checked += n;
  };
  const packages = new Map();
  const cleanups = [];
  let packagesUsed = 0;

  const targets = [...touched.added, ...touched.changed.map((c) => c.to)];
  for (const d of targets) {
    const s = parseSeal(d.by);
    const who = d.id || d.sha256 || d.coolapkUid || '(无选择器)';
    if (!s || s.pending) {
      notes.push(`${who}：还没盖上章（by=${JSON.stringify(d.by)}），这一步不为待盖值产结论`);
      continue;
    }
    const files = Array.isArray(d.evidence) ? d.evidence.map((e) => e.file) : [];
    if (!files.length) {
      addProblem(s.sha, `${who}：这条处置没有带 evidence 文件，逐字复核无从做起`);
      continue;
    }
    // 对照物：这一枚下架指的是「base 的索引里用户真能下到的那一包」吗。
    // 放在取包之前，是因为这一步一旦放行，后面取的字节就由它决定了 —— 顺序反了就等于
    // 先按记录里写的地址把包取回来、再问该不该取。
    const anchor = publishedVersion(baseIndex.modules, d);
    if (!anchor.ok) {
      addProblem(s.sha, `${who}：${anchor.why}`);
      continue;
    }
    const problems = [];
    let reportDocs = 0;
    let checkedTotal = 0;
    for (const file of files) {
      let raw;
      try {
        raw = git(cwd, ['show', `${headRef}:${file}`]);
      } catch {
        problems.push(`${who} 的 ${file} 在 head 上没有`);
        continue;
      }
      const name = path.basename(file).replace(/\.json$/, '');
      const selfHash = sha256Hex(Buffer.from(raw, 'utf8'));
      if (selfHash !== name) {
        problems.push(`${who} 的 ${file} 自称内容寻址，可它自己字节的 sha256 是 ${selfHash.slice(0, 12)} —— 同名不同物`);
        continue;
      }
      let doc;
      try {
        doc = JSON.parse(raw);
      } catch (e) {
        problems.push(`${who} 的 ${file} 不是合法 JSON：${e.message}`);
        continue;
      }
      if (doc.schema !== REPORT_EVIDENCE_SCHEMA) {
        problems.push(`${who} 的 ${file} 的记录是 ${JSON.stringify(doc.schema)} 那一版，这一步只复核举报证据`);
        continue;
      }
      reportDocs++;
      const pkg = doc.package || {};
      // 记录指的是不是**处置点名的那一枚已发布产物**：id 与 sha 都要同一个。
      // 只比 sha 不够 —— 同一份字节可以被写成挂在另一个模块名下的一条证据，
      // 那样「下架 A」的章会盖在「B 的包里确实有这段话」上。
      if (String(pkg.id || '').trim() !== d.id) {
        problems.push(`${who} 的 ${file} 指的是模块 ${JSON.stringify(pkg.id)}，与处置点名的 ${JSON.stringify(d.id)} 不是同一个`);
        continue;
      }
      if (String(pkg.sha256 || '').trim().toLowerCase() !== d.sha256) {
        problems.push(`${who} 的 ${file} 指的是 ${String(pkg.sha256 || '(空)').slice(0, 12)}，与处置点名的 ${d.sha256.slice(0, 12)} 不是同一枚产物`);
        continue;
      }
      const sha = d.sha256;
      if (!packages.has(sha)) {
        if (packagesUsed >= MAX_PACKAGES_PER_RUN) {
          problems.push(`${who}：这一轮要复核的包超过上限 ${MAX_PACKAGES_PER_RUN} 枚，剩下的没有复核`);
          continue;
        }
        packagesUsed++;
        try {
          // 取包地址来自索引那条 version.zipUrl，不是证据记录里写的 —— 这是「自带一枚 zip
          // 就能给自己造出绿结论」那条路的终点。
          const bytes = await download({ ...pkg, sha256: sha, assetUrl: anchor.version.zipUrl });
          const m = materialize(bytes);
          cleanups.push(m.cleanup);
          packages.set(sha, { bytes, path: m.path });
        } catch (e) {
          problems.push(`${who}：取 ${sha.slice(0, 12) || '(摘要不合法)'} 那一包失败：${String((e && e.message) || e)}`);
          continue;
        }
      }
      const handle = packages.get(sha);
      const r = verifyReportEvidenceDoc(doc, {
        openPackage: () => handle.bytes,
        readEntry: (n) => readEntry(handle.path, n),
      });
      checkedTotal += r.checked;
      for (const p of r.problems) problems.push(`${who} 的 ${file}：${p}`);
    }
    if (!reportDocs && !problems.some((p) => /上限/.test(p))) problems.unshift(`${who}：引用的证据文件里没有一份是举报证据 —— 逐字复核没有输入`);
    for (const p of problems) addProblem(s.sha, p);
    if (!problems.length) addChecked(s.sha, checkedTotal);
  }
  for (const c of cleanups) { try { c(); } catch { /* 临时目录清不掉不影响结论 */ } }
  const reviews = {};
  for (const [sha, a] of acc) {
    reviews[sha] = a.problems.length
      ? { ok: false, reason: a.problems.join('；') }
      : { ok: true, summary: `逐字复核：${a.checked} 段引用在归档里逐字节对上` };
  }
  for (const [sha, r] of Object.entries(reviews)) if (!r.ok) notes.push(`${sha.slice(0, 12)} 不成立：${r.reason}`);
  return { reviews, notes, packagesUsed, touched };
}

export function parseArgs(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    if (!String(argv[i]).startsWith('--')) continue;
    const k = String(argv[i]).slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) { o[k] = next; i++; } else o[k] = true;
  }
  return o;
}

export async function main(argv = process.argv.slice(2), io = console, deps = {}) {
  const opts = parseArgs(argv);
  const cwd = opts.cwd ? path.resolve(opts.cwd) : ROOT;
  const out = opts.out ? path.resolve(String(opts.out)) : '';
  const { reviews, notes, packagesUsed, fatal } = await reviewLedgerPr({
    cwd,
    baseRef: String(opts.base || 'origin/main'),
    headRef: String(opts.head || 'HEAD'),
    dispFile: opts['dispositions-file'] ? String(opts['dispositions-file']) : DEFAULT_DISPOSITIONS_FILE,
    indexFile: opts['index-file'] ? String(opts['index-file']) : DEFAULT_INDEX_FILE,
    deps,
  });
  if (out) fs.writeFileSync(out, `${JSON.stringify(reviews)}\n`, 'utf8');
  const total = Object.keys(reviews).length;
  const okCount = Object.values(reviews).filter((r) => r.ok).length;
  io.log(`[report-review] 复核 ${total} 枚章（取归档 ${packagesUsed} 包），成立 ${okCount} 枚${out ? ` -> ${path.relative(ROOT, out)}` : ''}`);
  for (const n of notes) io.error(`[report-review] ${n}`);
  if (fatal) {
    io.error(`[report-review] ${fatal} —— 按没复核处理，不在这里放行。`);
    return 1;
  }
  if (total && okCount < total) {
    io.error(`[report-review] 有 ${total - okCount} 枚章的逐字复核没过 —— 这一步不放行，approve 会红。`);
    return 1;
  }
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) process.exitCode = await main(process.argv.slice(2));
