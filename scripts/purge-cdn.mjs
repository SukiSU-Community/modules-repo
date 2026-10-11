#!/usr/bin/env node
/**
 * purge-cdn.mjs —— 让 CDN 上那份索引立刻失效。
 *
 * 为什么必须有这一步：下架的生效速度其实由 CDN 说了算，而不是由 main 说了算。
 * 实测（2026-10-11）：索引 PR #34 把 json/modules.json 推空之后近 50 分钟，
 * `https://cdn.jsdelivr.net/gh/SukiSU-Community/modules-repo@main/json/modules.json`
 * 仍然返回下架前的 4 个模块 —— 订阅了这个地址的 App 照样能装到已被下架的包。
 * 「索引 = f(main)」这条不变式在源站上成立，在用户手里不成立。
 *
 * 只内置 jsDelivr 一家：它的 purge 端点是公开 GET、不需要凭据（往 CI 里塞一把能改 CDN 的
 * 钥匙，比这一步省下的麻烦贵得多）。别的 CDN 由运维把地址放进 CDN_PURGE_URLS，本脚本对它
 * 只认「jsdelivr 的 cdn→purge 换主机名」这一种映射，**认不出来就明说没清，不猜私有 API，
 * 也不假装清过了** —— 假装成功比不清更坏。
 *
 * 失效方向：合并已经发生，所以这一步红不会撤销任何事，只是把「缓存还在发旧索引」这件事
 * 变成一个看得见的失败（要红，不要静默）。
 *
 * 用法：
 *   node scripts/purge-cdn.mjs [--repo owner/name] [--branch main]
 *        [--file json/modules.json --file json/dispositions.json]
 *        [--extra <csv>] [--dry-run]
 *
 * 只用 node: 内置模块（本仓库硬约束）。
 */
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const JSDELIVR_CDN = 'cdn.jsdelivr.net';
const JSDELIVR_PURGE = 'purge.jsdelivr.net';

/**
 * 算出要清哪些地址。
 *
 * 本站的发布口径就是 jsDelivr（大陆直连 raw.githubusercontent 不稳），所以默认目标
 * 按 GITHUB_REPOSITORY 拼出来即可，不需要额外配置。
 */
export function purgeTargets({ repo, branch = 'main', files = ['json/modules.json', 'json/dispositions.json'], extra = [] } = {}) {
  const out = [];
  if (repo && /^[^/]+\/[^/]+$/.test(repo)) {
    for (const f of files) {
      const url = `https://${JSDELIVR_CDN}/gh/${repo}@${branch}/${f}`;
      out.push({ url, purgeUrl: `https://${JSDELIVR_PURGE}/gh/${repo}@${branch}/${f}`, how: 'jsdelivr' });
    }
  }
  for (const raw of extra) {
    const url = String(raw || '').trim();
    if (!url) continue;
    let u = null;
    try {
      u = new URL(url);
    } catch {
      out.push({ url, purgeUrl: '', how: 'unknown', why: '不是合法 URL' });
      continue;
    }
    if (u.hostname === JSDELIVR_CDN) {
      out.push({ url, purgeUrl: `https://${JSDELIVR_PURGE}${u.pathname}${u.search}`, how: 'jsdelivr' });
    } else {
      // 这一家本站没有清缓存的能力：只能报出来让人去它自己的控制台操作。
      out.push({ url, purgeUrl: '', how: 'unsupported', why: `没有 ${u.hostname} 的通用 purge 端点，需人工处理` });
    }
  }
  return out;
}

/**
 * 逐条清。返回三态：成功 / 失败 / 无能为力。
 * jsDelivr 的应答里 status 可能是 finished 或 scheduled（异步扩散），两个都算发起成功；
 * 只有 HTTP 不 2xx 或 status=error 才算失败。
 */
export async function purgeAll(targets, { fetchImpl = globalThis.fetch, log = console, timeoutMs = 15000, annotate = false } = {}) {
  const ok = [];
  const failed = [];
  const unsupported = [];
  for (const t of targets) {
    if (!t.purgeUrl) {
      unsupported.push(t);
      const line = `无法清除 ${t.url} —— ${t.why}`;
      log[annotate ? 'warn' : 'log'](`::warning::${line}`);
      continue;
    }
    try {
      const res = await fetchImpl(t.purgeUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(timeoutMs),
        headers: { 'user-agent': 'modules-repo-purge-cdn' },
      });
      const text = await res.text();
      let status = '';
      try {
        status = String(JSON.parse(text).status || '');
      } catch {
        /* 应答不是 JSON：下面按 HTTP 码判 */
      }
      if (!res.ok || status === 'error') {
        failed.push({ ...t, why: `HTTP ${res.status}${status ? ` status=${status}` : ''} ${text.slice(0, 160)}` });
        const line = `清除失败 ${t.purgeUrl}：${failed.at(-1).why}`;
        log[annotate ? 'error' : 'log'](`::error::${line}`);
        continue;
      }
      ok.push({ ...t, status: status || `HTTP ${res.status}` });
      log.log(`已发起清除（${ok.at(-1).status}）：${t.url}`);
    } catch (e) {
      failed.push({ ...t, why: (e && e.message) || String(e) });
      log[annotate ? 'error' : 'log'](`::error::清除异常 ${t.purgeUrl}：${(e && e.message) || String(e)}`);
    }
  }
  return { ok, failed, unsupported };
}

export function parseArgs(argv) {
  const o = { file: [], extra: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const eq = k.indexOf('=');
    let val;
    if (eq >= 0) {
      val = k.slice(eq + 1);
      argv[i] = '--' + k.slice(0, eq);
    }
    const name = k.slice(0, eq >= 0 ? eq : undefined);
    if (name === 'file') { o.file.push(val ?? argv[++i]); continue; }
    if (name === 'extra') {
      const raw = val ?? argv[++i] ?? '';
      o.extra.push(...String(raw).split(',').map((s) => s.trim()).filter(Boolean));
      continue;
    }
    if (name === 'dry-run') { o['dry-run'] = true; continue; }
    const next = val ?? argv[i + 1];
    if (next !== undefined && !String(next).startsWith('--')) { o[name] = next; i++; }
    else o[name] = true;
  }
  return o;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const log = deps.log || console;
  const env = deps.env ?? process.env;
  if (opts.help) {
    log.log(`用法: node purge-cdn.mjs [--repo owner/name] [--branch main] [--file <path>]... [--extra <csv>] [--dry-run]
   清掉 CDN 上那份公开索引与台账的缓存。默认目标按 GITHUB_REPOSITORY 拼 jsDelivr 地址。`);
    return 0;
  }
  const repo = opts.repo || env.GITHUB_REPOSITORY || '';
  const branch = opts.branch || env.INDEX_BRANCH || 'main';
  const envExtra = String(env.CDN_PURGE_URLS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const targets = purgeTargets({ repo, branch, files: opts.file.length ? opts.file : undefined, extra: [...opts.extra, ...envExtra] });

  if (!targets.length) {
    log.error('::error::没有任何可清除的目标（既没有 GITHUB_REPOSITORY，也没有 --extra / CDN_PURGE_URLS）。');
    return 1;
  }
  if (opts['dry-run']) {
    log.log('dry-run，只列出目标：');
    for (const t of targets) log.log(`  ${t.url}\n    -> ${t.purgeUrl || `（${t.why}）`}`);
    return 0;
  }

  const r = await purgeAll(targets, {
    fetchImpl: deps.fetchImpl,
    log,
    annotate: env.GITHUB_ACTIONS === 'true',
  });
  log.log(`purge 结果：成功 ${r.ok.length}，失败 ${r.failed.length}，无能为力 ${r.unsupported.length}`);
  if (r.failed.length) {
    log.log('合并已经完成，这一步只是告诉你 CDN 上还在发旧内容；重试：node scripts/purge-cdn.mjs');
    return 1;
  }
  return 0;
}

// 入口判据用 resolve 比对绝对路径（与 audit/scan.mjs、verify-index-pr.mjs 同一条坑）：
// 拿 argv[1] 拼 file:// URL 在 Windows 上永远不等于 import.meta.url，这个脚本就会静默不跑。
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then((rc) => {
    process.exitCode = rc;
  });
}
