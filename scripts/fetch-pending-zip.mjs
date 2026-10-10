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
 * 从 pending 条目解析 zip 下载地址。三种写法都支持：
 *   1. versions[].zipUrl                      —— Worker 实际写出的字段
 *   2. 顶层 zipUrl                            —— 简化条目
 *   3. releaseTag + assetName                 —— 拼 GitHub Release 直链
 */
export function resolveDownloadUrl(raw, opts = {}) {
  const v = pickVersion(raw);
  const direct = (v && typeof v.zipUrl === 'string' ? v.zipUrl.trim() : '')
    || (typeof raw.zipUrl === 'string' ? raw.zipUrl.trim() : '');
  if (direct) return { url: direct, source: 'zipUrl' };

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

/** 下载一个 URL 到内存缓冲（zip 需整体读入才能交给 scan.mjs）。 */
export async function downloadToBuffer(url, opts = {}) {
  const timeout = opts.timeoutMs ?? FETCH_TIMEOUT_MS;
  const ac = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = ac ? setTimeout(() => ac.abort(), timeout) : null;
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      ...(ac ? { signal: ac.signal } : {}),
      headers: { 'user-agent': 'sukisu-module-audit', accept: 'application/zip,*/*' },
    });
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
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** 本地文件 -> 缓冲（端到端自测时用本地假 zip，也方便离线跑）。 */
export function readLocalFile(p) {
  return new Uint8Array(fs.readFileSync(p));
}

export function parseArgs(argv) {
  const opts = { _: [], outDir: null, force: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out-dir' && i + 1 < argv.length) { opts.outDir = path.resolve(argv[++i]); continue; }
    if (a === '--force') { opts.force = true; continue; }
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
          const r = resolveDownloadUrl(raw, { owner: opts.owner, repo: opts.repo });
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
