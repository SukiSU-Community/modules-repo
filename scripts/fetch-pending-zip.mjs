#!/usr/bin/env node
/**
 * fetch-pending-zip.mjs
 *
 * 断点 ① 的另一半：Worker 开的 PR 里只有 pending/<id>/<versionCode>.json，
 * zip 本体在 GitHub Release asset 上（见 contrib/worker/src/index.ts buildPendingJson
 * 写出的 zipUrl/releaseTag/assetName 字段），所以 audit 必须先「读元数据 -> 拼下载地址
 * -> 下载 zip」，才能把 zip 交给 scan.mjs 扫描。本脚本就是这一步。
 *
 * 用法：
 *   node fetch-pending-zip.mjs <pending.json> [...] --out-dir <dir> [--force]
 *
 * 输出：
 *   - 每个 pending 条目下载一个 zip 到 <out-dir>/<id>-<versionCode>.zip
 *   - 写一份 <out-dir>/manifest.json：[{ zip, id, version, versionCode, zipUrl, size, sha256, pending }]
 *   - 下载失败（网络不通 / asset 404）时该条目记为 error，不影响其它条目
 *
 * 退出码：0 = 至少一个成功且没有失败；1 = 全部失败；2 = 参数错误。
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(__dirname, '..');

const MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024; // 单 zip 硬上限，防 OOM
const FETCH_TIMEOUT_MS = 120_000;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;

/** 一个 pending 条目里可能带多个版本；取「待审版本」用于下载。 */
export function pickVersion(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const list = Array.isArray(raw.versions) ? raw.versions : [];
  if (list.length === 0) return null;
  // 同一个 pending 文件通常只含一个版本；多个时取 versionCode 最大的（最新投稿）
  return list.reduce((a, b) => ((Number(b?.versionCode) || 0) > (Number(a?.versionCode) || 0) ? b : a));
}

/**
 * 允许 runner 去取 zip 的主机。
 *
 * pending JSON 里的 `zipUrl` 是**投稿方可控的文本**（Worker 写的是 GitHub Release 直链，
 * 但这个 JSON 任何有仓库写权限的人都能手搓）。原来照单全收并 `redirect:'follow'`，
 * 于是两个问题：① 指到 `http://169.254.169.254/` 之类，让 CI runner 替攻击者发内部请求
 * （SSRF）；② 合法主机 302 到一个外部主机会被一路跟下去，白名单形同虚设。
 *
 * 只放行 GitHub 的 release 下载域：`github.com` 给入口，
 * `objects.githubusercontent.com` 是它 302 之后真正吐字节的那个。
 */
export const ALLOWED_DOWNLOAD_HOSTS = new Set(['github.com', 'objects.githubusercontent.com']);
const MAX_REDIRECTS = 5;

/**
 * 校验一个下载地址能不能取。返回 { ok, url, error }。
 *
 * 判据不止主机名：还要求 https、URL 里不带凭据（`https://github.com@evil.tld/`
 * 这种经典写法靠解析主机名就能挡掉），并且把 `zipUrl` 尾巴、`assetName`、
 * `versions[].sha256` 三者钉死成同一个包 —— 直链落到的文件名必须就是声明的 asset，
 * 而 asset 必须是内容寻址名 `<sha256>.zip`。少任何一环，「元数据写一个干净的摘要、
 * zipUrl 指向另一个包」就能让扫的是 A、合的是 B，整个内容寻址的信任就空了。
 */
export function assertDownloadUrl(url, raw = {}) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return { ok: false, error: `下载地址不是合法 URL：${String(url).slice(0, 120)}` };
  }
  if (u.protocol !== 'https:') {
    return { ok: false, error: `下载地址必须是 https，收到 ${u.protocol}` };
  }
  if (u.username || u.password) {
    return { ok: false, error: '下载地址里不能带凭据（user:pass@host 形式的 URL 一律拒）' };
  }
  const host = u.hostname.toLowerCase();
  if (!ALLOWED_DOWNLOAD_HOSTS.has(host)) {
    return { ok: false, error: `下载地址主机不在允许列表内：${host}（只允许 ${[...ALLOWED_DOWNLOAD_HOSTS].join(', ')}）` };
  }
  const segs = decodeURIComponent(u.pathname).split('/').filter(Boolean);
  const last = segs[segs.length - 1] || '';
  const asset = typeof raw.assetName === 'string' ? raw.assetName.trim() : '';
  if (asset && last !== asset) {
    return { ok: false, error: `下载地址落到的是「${last}」，与元数据声明的 assetName「${asset}」不一致 —— 扫的包和合的包可能不是同一个` };
  }
  // 内容寻址名必须就是声明摘要那一个。只比 assetName 不够：手搓的 JSON 完全可以让
  // assetName 与 zipUrl 互相印证、却和 versions[].sha256 毫无关系，那样「扫 A 合 B」
  // 仍然成立。三个字段互为证据，缺一环就拒。
  const sha = String((pickVersion(raw) || {}).sha256 || raw.sha256 || '').trim().toLowerCase();
  if (sha) {
    if (!SHA256_RE.test(sha)) {
      return { ok: false, error: `声明的 sha256 不是 64 位十六进制：「${sha.slice(0, 80)}」` };
    }
    if (last !== `${sha}.zip`) {
      return { ok: false, error: `直链文件名「${last}」不是内容寻址名「${sha}.zip」—— 摘要与包对不上，不予下载` };
    }
  }
  const tag = typeof raw.releaseTag === 'string' ? raw.releaseTag.trim() : '';
  if (tag && !decodeURIComponent(u.pathname).includes(`/releases/download/${tag}/`)) {
    return { ok: false, error: `下载地址不在 release tag「${tag}」的下载路径下` };
  }
  return { ok: true, url: u.toString() };
}

/**
 * 从 pending 条目解析 zip 下载地址。三种写法都支持：
 *   1. versions[].zipUrl                      —— Worker 实际写出的字段
 *   2. 顶层 zipUrl                            —— 简化条目
 *   3. releaseTag + assetName                 —— 拼 GitHub Release 直链
 *
 * 解析完必须过 assertDownloadUrl；不通过就报错而不是照取。
 */
export function resolveDownloadUrl(raw, opts = {}) {
  const v = pickVersion(raw);
  const direct = (v && typeof v.zipUrl === 'string' ? v.zipUrl.trim() : '')
    || (typeof raw.zipUrl === 'string' ? raw.zipUrl.trim() : '');
  if (direct) {
    // 本地来源（file:// 或磁盘上的路径，含根本不成 URL 的串）是离线自测用的，CI 里默认不认：
    // pending JSON 的 zipUrl 是投稿方可控的文本，允许它指本地路径就等于允许读 runner
    // 文件系统上的任意文件。要开只能显式传 --allow-local-zipurl。
    if (!/^https?:\/\//i.test(direct)) {
      if (opts.allowLocal !== true) {
        return {
          url: '',
          source: 'zipUrl',
          error: `zipUrl 不是 http(s) 地址（「${direct.slice(0, 120)}」），按本地来源默认拒绝；离线自测请显式加 --allow-local-zipurl`,
        };
      }
      return { url: direct, source: 'zipUrl-local' };
    }
    const checked = assertDownloadUrl(direct, raw);
    if (!checked.ok) return { url: '', source: 'zipUrl', error: checked.error };
    return { url: checked.url, source: 'zipUrl' };
  }

  const tag = typeof raw.releaseTag === 'string' ? raw.releaseTag.trim() : '';
  const asset = typeof raw.assetName === 'string' ? raw.assetName.trim() : '';
  if (tag && asset) {
    const owner = (opts.owner || process.env.GITHUB_OWNER || '').trim();
    const repo = (opts.repo || process.env.GITHUB_REPO || '').trim();
    if (owner && repo) {
      return {
        url: `https://github.com/${owner}/${repo}/releases/download/${encodeURIComponent(tag)}/${asset
          .split('/')
          .map(encodeURIComponent)
          .join('/')}`,
        source: 'releaseTag+assetName',
      };
    }
    return { url: '', source: 'releaseTag+assetName', error: '缺少 owner/repo，无法拼 Release 直链' };
  }
  return { url: '', source: 'none', error: 'pending 条目里没有 zipUrl，也没有 releaseTag+assetName' };
}

/**
 * 下载一个 URL 到内存缓冲（zip 需整体读入才能交给 scan.mjs）。
 *
 * 重定向**自己跟**而不是 `redirect:'follow'`：GitHub 的 release 直链会 302 到
 * objects.githubusercontent.com，那是合法的；但「跟随」也意味着攻击者可以让
 * github.com 的 URL 一路跳到任何主机 —— 白名单只在第一跳生效等于没有白名单。
 * 所以每一跳都重新过 assertDownloadUrl（按主机/协议/凭据判），跳数封顶 MAX_REDIRECTS。
 */
export async function downloadToBuffer(url, opts = {}) {
  const timeout = opts.timeoutMs ?? FETCH_TIMEOUT_MS;
  let next = String(url);

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const checked = assertDownloadUrl(next, {});
    if (!checked.ok) throw new Error(`下载地址不合法：${checked.error}`);

    const ac = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = ac ? setTimeout(() => ac.abort(), timeout) : null;
    let res;
    try {
      res = await fetch(checked.url, {
        redirect: 'manual',
        ...(ac ? { signal: ac.signal } : {}),
        headers: { 'user-agent': 'sukisu-module-audit', accept: 'application/zip,*/*' },
      });
    } finally {
      if (timer) clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      if (!loc) throw new Error(`HTTP ${res.status} 却没有 Location 头`);
      next = new URL(loc, checked.url).toString();
      continue;
    }

    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    const len = Number(res.headers.get('content-length') ?? '');
    if (Number.isFinite(len) && len > MAX_DOWNLOAD_BYTES) {
      throw new Error(`zip 过大：${len} 字节 > 上限 ${MAX_DOWNLOAD_BYTES}`);
    }
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.byteLength > MAX_DOWNLOAD_BYTES) {
      throw new Error(`zip 过大：${buf.byteLength} 字节 > 上限 ${MAX_DOWNLOAD_BYTES}`);
    }
    return buf;
  }
  throw new Error(`重定向次数超过上限 ${MAX_REDIRECTS}，停止跟随`);
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** 本地文件 -> 缓冲（端到端自测时用本地假 zip，也方便离线跑）。 */
export function readLocalFile(p) {
  return new Uint8Array(fs.readFileSync(p));
}

export function parseArgs(argv) {
  const opts = { _: [], outDir: null, force: false, allowLocal: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out-dir' && i + 1 < argv.length) { opts.outDir = path.resolve(argv[++i]); continue; }
    if (a === '--force') { opts.force = true; continue; }
    if (a === '--allow-local-zipurl') { opts.allowLocal = true; continue; }
    if (a === '--owner' && i + 1 < argv.length) { opts.owner = argv[++i]; continue; }
    if (a === '--repo' && i + 1 < argv.length) { opts.repo = argv[++i]; continue; }
    opts._.push(a);
  }
  return opts;
}

/** 收集 pending 文件（复用 build-index 的递归遍历，保证两边看到的文件集一致）。 */
export async function collectPendingFiles(pendingDir) {
  const { collectPendingFiles: collect } = await import('./build-index.mjs');
  return collect(pendingDir);
}

export async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  const { outDir, force } = opts;
  if (!outDir) {
    console.error('用法: node fetch-pending-zip.mjs <pending.json|pending-dir> [...] --out-dir <dir> [--force]');
    return 2;
  }
  if (opts._.length === 0) {
    console.error('[fetch-pending-zip] 至少给一个 pending json 文件或目录');
    return 2;
  }
  fs.mkdirSync(outDir, { recursive: true });

  // 展开入参：目录 -> 递归收集 *.json；文件 -> 直接用
  const inputs = [];
  for (const arg of opts._) {
    const abs = path.resolve(arg);
    if (!fs.existsSync(abs)) {
      console.error(`[fetch-pending-zip] 不存在：${abs}`);
      continue;
    }
    if (fs.statSync(abs).isDirectory()) {
      for (const item of await collectPendingFiles(abs)) inputs.push({ file: item.file, entries: item.entries });
    } else {
      try {
        const parsed = JSON.parse(fs.readFileSync(abs, 'utf8'));
        inputs.push({ file: abs, entries: Array.isArray(parsed) ? parsed : [parsed] });
      } catch (e) {
        console.error(`[fetch-pending-zip] ${abs} JSON 解析失败：${e.message}`);
      }
    }
  }

  const manifest = [];
  let ok = 0;
  let failed = 0;

  for (const input of inputs) {
    for (const raw of input.entries) {
      const id = String((raw && raw.id) || 'unknown');
      const v = pickVersion(raw);
      const vc = v && Number.isFinite(Number(v.versionCode)) ? Number(v.versionCode) : 0;
      const target = path.join(outDir, `${id}-${vc}.zip`);

      const rec = {
        pending: input.file,
        id,
        version: (v && v.version) || '',
        versionCode: vc,
        declaredSha256: (v && v.sha256) || '',
        declaredSize: (v && v.size) || 0,
        zip: null,
        zipUrl: '',
        sha256: '',
        size: 0,
        error: null,
      };

      try {
        if (!fs.existsSync(target) || force) {
          const r = resolveDownloadUrl(raw, { owner: opts.owner, repo: opts.repo, allowLocal: opts.allowLocal });
          rec.zipUrl = r.url;
          if (!r.url) throw new Error(r.error || '无法解析下载地址');

          let buf;
          if (/^https?:\/\//i.test(r.url)) {
            buf = await downloadToBuffer(r.url);
          } else if (/^file:\/\//i.test(r.url)) {
            buf = readLocalFile(fileURLToPath(r.url));
          } else if (fs.existsSync(path.resolve(r.url))) {
            // 本地相对/绝对路径：离线自测用
            buf = readLocalFile(path.resolve(r.url));
          } else {
            throw new Error(`不支持的下载地址：${r.url}`);
          }

          if (buf.byteLength === 0) throw new Error('下载的 zip 为空');
          // 最小完整性检查：zip 以 PK\x03\x04（或空归档 PK\x05\x06）开头
          if (!(buf[0] === 0x50 && buf[1] === 0x4b)) {
            throw new Error('下载内容不是 zip（缺少 PK 文件头）');
          }
          if (rec.declaredSha256 && SHA256_RE.test(rec.declaredSha256)) {
            const actual = sha256Hex(buf);
            if (actual !== rec.declaredSha256.toLowerCase()) {
              throw new Error(`sha256 不匹配：元数据声明 ${rec.declaredSha256}，实际 ${actual}`);
            }
          } else if (/^https?:\/\//i.test(r.url)) {
            // 远端来源必须有可校验的摘要。没有声明值，就没有任何办法证明「扫过的那个包」
            // 与「合进索引的那个包」是同一个；离线自测的本地文件不受此约束（字节就在手上）。
            throw new Error(
              `远端来源缺少合法的 sha256 声明（收到「${String(rec.declaredSha256 || '').slice(0, 72) || '(空)'}」），无摘要不送审`
            );
          }
          fs.writeFileSync(target, buf);
          rec.sha256 = sha256Hex(buf);
          rec.size = buf.byteLength;
        } else {
          const buf = readLocalFile(target);
          rec.sha256 = sha256Hex(buf);
          rec.size = buf.byteLength;
        }
        rec.zip = target;
        ok += 1;
        console.log(`[fetch-pending-zip] ✓ ${id} ${vc} -> ${target}（${rec.size} 字节）`);
      } catch (e) {
        rec.error = e instanceof Error ? e.message : String(e);
        failed += 1;
        console.error(`[fetch-pending-zip] ✗ ${id} ${vc}：${rec.error}`);
      }
      manifest.push(rec);
    }
  }

  const manifestPath = path.join(outDir, 'manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  console.log(`[fetch-pending-zip] 成功 ${ok} / 失败 ${failed}；清单 -> ${manifestPath}`);
  if (ok === 0) return 1;
  return 0;
}

const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().then((code) => { process.exit(code); }, (e) => { console.error(e); process.exit(1); });
}
