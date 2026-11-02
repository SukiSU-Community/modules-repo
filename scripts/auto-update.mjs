#!/usr/bin/env node
/**
 * auto-update.mjs
 *
 * 每日自动更新：找出索引里「仓库已验/有 updateJson」的模块的新版本，把包落到索引仓的
 * `assets-v1` Release，然后通过 Worker 的 `POST /auto/pr` 一次性提一个 PR。
 *
 * 为什么要「一次性提一个 PR」而不是每个模块一个：
 *   - `json/repo-state.json` 是**全局**状态文件，两个 PR 同时改它必冲突；
 *   - Worker 的 `/auto/pr` 一次最多收 21 个文件（20 个 pending + 1 个 state），正好对得上
 *     一次最多 20 个模块的设计；
 *   - 一次 PR 只等一次 `approve`，索引链路的开销是常数而不是随模块数增长。
 *
 * 两条发现路径：
 *   A. repo：`repoUrl` 且 `repoVerified:true`。取 `/releases` 里 created_at 最新的「带 .zip
 *      资产」的 Release → 下载 → 解包根 `module.prop` → 版本号以包内为准。新包会被上传到
 *      索引仓的 `assets-v1`，并在版本上记 `repoTag=<tag_name>`，构成证据 A。
 *   B. updateJson：模块自带 `updateJson`。读它声明的 version/versionCode/zipUrl → 下载 zip
 *      → 解包 `module.prop` 复核 id 与 updateJson 未漂移 → 版本上记 `autoVia=update-json`。
 *      这条路径**不上传**：zip 由原作者托管，索引只记录地址与摘要。
 *
 * 拒绝与失败的区别：
 *   - 作者侧的问题（包坏、id 不符、versionCode 回退、updateJson 漂移、zipUrl 404、updateJson
 *     404/坏 JSON）→ 拒绝该模块，写清原因，继续处理别的模块；这不叫「半途发布」，因为
 *     最终的 PR 在全部模块处理完之后才提交。
 *   - 基础设施问题（GitHub 401/403/5xx/429、网络超时、上传失败）→ 整个 run 红。§0 要求
 *     「任何 GitHub 调用失败硬失败」，宁可当天不发，也不发一个基于半截数据的状态。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { createSafeHttp, MAX_JSON_BYTES, MAX_ZIP_BYTES, SafeHttpError } from './lib/http-safe.mjs';
import { inspectModuleZip } from './lib/zip.mjs';
import {
  GITHUB_UPLOADS, githubGetJson, githubHeaders, parseRepoUrl, repoApiUrl,
} from './lib/github.mjs';
import { AUTO_PR_STATE_PATH, postAutoPr } from './lib/auto-pr.mjs';
import {
  REPO_ROOT, cleanStateEntry, emptyState, finalizeState, verifyReposCore,
} from './verify-repos.mjs';

/** 一次最多提交多少个模块（20 个 pending + 1 个 state = /auto/pr 的 21 文件上限）。 */
export const MAX_MODULES_PER_RUN = 20;
/** `/releases` 只取最近的 30 个：更早的 Release 不可能承载「新版本」。 */
export const REPO_LIST_LIMIT = 30;
/** 索引仓里存放自动更新包的 Release tag，可用 RELEASE_TAG 覆盖。 */
export const DEFAULT_RELEASE_TAG = 'assets-v1';
/** 索引里一次最多读多少字节（正常只有几十 KB，16MiB 是防御性的上限）。 */
const MAX_INDEX_BYTES = 16 * 1024 * 1024;

const ID_RE = /^[A-Za-z0-9._-]+$/;

// ── 纯函数（可直接单测）─────────────────────────────────────────────────

/** 计算 sha256 的十六进制小写串。 */
export function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

/** Release 的排序时间戳；坏值当 0（排到最后，不会被选中）。 */
export function releaseTimestamp(release) {
  const t = Date.parse(release && (release.published_at || release.created_at) ? (release.published_at || release.created_at) : '');
  return Number.isFinite(t) ? t : 0;
}

/** Release 里第一个 `.zip` 资产；没有返回 null。 */
export function zipAssetOf(release) {
  const assets = Array.isArray(release && release.assets) ? release.assets : [];
  return assets.find((a) => a && typeof a.name === 'string' && a.name.toLowerCase().endsWith('.zip')) || null;
}

/**
 * 从 `/releases?per_page=30` 的结果里挑出「created_at 最新、带 .zip 资产、非草稿」的 Release。
 *
 * 用 created_at 而不是 published_at 排序：草稿发布后 published_at 可能为空，而 created_at
 * 一定存在；两者对「最近一次发布」的排序结果在实践中一致。
 */
/** 索引仓 assets-v1 里某个资产的公开下载地址（GitHub 固定格式）。 */
export function assetDownloadUrl(assetsRepo, tag, assetName) {
  return `https://github.com/${encodeURIComponent(assetsRepo.owner)}/${encodeURIComponent(assetsRepo.repo)}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(assetName)}`;
}

export function pickLatestZipRelease(releases) {
  const list = Array.isArray(releases) ? releases : [];
  return list
    .filter((r) => r && !r.draft && zipAssetOf(r))
    .sort((a, b) => releaseTimestamp(b) - releaseTimestamp(a))[0] || null;
}

/** 模块当前最高 versionCode（没有版本时 0）。 */
export function highestVersionCode(module) {
  const versions = Array.isArray(module && module.versions) ? module.versions : [];
  let best = 0;
  for (const v of versions) {
    if (v && Number.isInteger(v.versionCode) && v.versionCode > best) best = v.versionCode;
  }
  return best;
}

/** 索引里是否已有「这份字节」的版本（用版本级 repoDigest 判）。 */
export function hasDigest(module, digest) {
  const want = normalizeDigest(digest);
  if (!want) return false;
  const versions = Array.isArray(module && module.versions) ? module.versions : [];
  return versions.some((v) => v && normalizeDigest(v.repoDigest) === want);
}

/** `sha256:<hex>` 归一化（小写）；非法返回空串。 */
export function normalizeDigest(raw) {
  const s = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  return /^sha256:[0-9a-f]{64}$/.test(s) ? s : '';
}

/** `YYYY-MM-DDTHH:MM:SSZ` —— 只用于 pending 的 `submittedAt`（Worker 侧是 ISO 字符串）。 */
export function formatTimestamp(input) {
  const d = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(d.getTime())) return '';
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`;
}

/**
 * Release 的时间戳（毫秒）。索引里的 `versions[].time` 是数字毫秒 —— 不是 ISO 字符串，
 * 写错会被 build-index 拒收（`time 不是数字`）。
 */
export function releaseEpochMs(release, fallback) {
  const raw = release && (release.published_at || release.created_at);
  const t = Date.parse(typeof raw === 'string' ? raw : '');
  if (Number.isFinite(t) && t > 0) return Math.trunc(t);
  return Math.trunc(fallback);
}

/** 从 `module.prop` 取版本号；取不到就是拒绝理由。 */
export function versionFromProp(prop) {
  const versionCode = Number.parseInt(prop && prop.versionCode, 10);
  if (!Number.isInteger(versionCode) || versionCode <= 0) {
    return { ok: false, error: 'module.prop 的 versionCode 不是正整数' };
  }
  const version = typeof prop.version === 'string' ? prop.version.trim() : '';
  if (!version) return { ok: false, error: 'module.prop 里没有 version' };
  return { ok: true, version, versionCode };
}

/**
 * 新包的 `module.prop` 里的 `updateJson=` 必须与索引里的模块级 updateJson **完全一致**。
 *
 * 这是 §3.2 的硬要求，也是最容易忽略的一条：如果作者在包里把 updateJson 改到了另一个
 * 地址，那这个包就不再是「索引记录的那个来源」产出的，继续自动更新等于替作者把来源
 * 悄悄换掉。从无到有、从有到无都算不一致 —— 空串参与比较。
 */
export function checkUpdateJsonUnchanged(module, prop) {
  const indexed = typeof module.updateJson === 'string' ? module.updateJson.trim() : '';
  const incoming = typeof prop.updateJson === 'string' ? prop.updateJson.trim() : '';
  if (indexed !== incoming) {
    return {
      ok: false,
      error: `module.prop 的 updateJson 与索引不一致（索引 ${indexed || '(空)'}，包内 ${incoming || '(空)'}）`,
    };
  }
  return { ok: true };
}

/**
 * 组装 pending JSON（与 Worker `buildPendingJson` 的字段语义对齐）。
 *
 * 空值一律省略键，不写 null：契约 §1 要求「空值省略键」，而 `null` 会让下游的
 * `'x' in obj` 判据误以为字段存在。
 *
 * @param {object} p
 * @param {object} p.module 索引里的模块
 * @param {object} p.version 版本条目（zipUrl/size/time/sha256 等）
 * @param {string} [p.releaseTag] 仅 repo 路径（上传到 assets-v1）才有
 * @param {string} [p.assetName]
 * @param {string} p.submittedAt ISO 字符串
 * @param {number} p.repoCheckedAt 毫秒
 */
export function buildPendingJson({
  module, version, releaseTag, assetName, submittedAt, repoCheckedAt,
}) {
  const out = {
    id: module.id,
    name: module.name,
    author: module.author,
    description: module.description,
    versions: [version],
  };
  if (typeof module.source === 'string' && module.source.trim()) out.source = module.source.trim();

  const repoUrl = typeof module.repoUrl === 'string' ? module.repoUrl.trim() : '';
  if (releaseTag) {
    // 包真的传进了索引仓 assets-v1：版本用 repoTag 指向那个 Release，模块头也钉在这次
    // 复验的结论上。`repoUrl` 不是「这个 zip 一定由仓库构建」，而是「模块的源码仓库
    // 是这里」——版本级 repoTag 才是「这份字节在仓库里能对上」的证据。
    out.repoUrl = module.repoUrl;
    out.repoVerified = true;
    out.repoCheckedAt = Math.trunc(repoCheckedAt);
    if (typeof module.repoLicense === 'string' && module.repoLicense.trim()) {
      out.repoLicense = module.repoLicense.trim();
    }
  } else if (repoUrl && typeof module.repoVerified === 'boolean'
    && Number.isFinite(module.repoCheckedAt) && module.repoCheckedAt > 0) {
    // update-json 路径不写 repoTag（这份字节不在仓库里），但模块头本来就有仓库，
    // 必须原样带过去：build-index 的「source 与 repoUrl 至少一个」校验发生在合并之前，
    // 丢掉它会让这条 pending 直接 invalid，整轮自动更新跟着红。
    out.repoUrl = repoUrl;
    out.repoVerified = module.repoVerified === true;
    out.repoCheckedAt = Math.trunc(module.repoCheckedAt);
    if (typeof module.repoLicense === 'string' && module.repoLicense.trim()) {
      out.repoLicense = module.repoLicense.trim();
    }
  }
  if (typeof module.updateJson === 'string' && module.updateJson.trim()) {
    out.updateJson = module.updateJson.trim();
  }
  if (module.uploader) out.uploader = module.uploader;
  if (module.coolapkUid) out.coolapkUid = module.coolapkUid;
  if (releaseTag) {
    out.storage = 'github-release-asset';
    out.releaseTag = releaseTag;
    out.assetName = assetName;
  }
  out.submittedAt = submittedAt;
  return out;
}

/** 版本条目：两条路径共用 sha256/auto/autoVia/repoDigest，repo 路径多一个 repoTag。 */
export function buildVersionEntry({
  version, versionCode, zipUrl, size, time, sha256, autoVia, repoTag,
}) {
  const entry = {
    version,
    versionCode,
    zipUrl,
    size,
    time,
    sha256,
    repoDigest: `sha256:${sha256}`,
    auto: true,
    autoVia,
  };
  if (autoVia === 'repo' && repoTag) entry.repoTag = repoTag;
  return entry;
}

// ── 网络辅助 ──────────────────────────────────────────────────────────────

/** 作者侧问题 vs 基础设施问题：前者拒绝该模块，后者让 run 红。 */
function classifySafeHttpError(err) {
  if (!(err instanceof SafeHttpError)) return { reject: false };
  const rejectCodes = new Set(['bad-url', 'bad-protocol', 'blocked-host', 'blocked-address', 'too-large', 'bad-json', 'too-many-redirects']);
  return rejectCodes.has(err.code) ? { reject: true, reason: err.message } : { reject: false };
}

function assertGithubOk(res, what) {
  if (res.status === 200) return;
  const detail = res.json && typeof res.json.message === 'string' ? `：${res.json.message}` : '';
  throw new Error(`${what} 返回 HTTP ${res.status}${detail}（GitHub 调用失败，整个 run 中止）`);
}

/** 找同名资产（重复运行/并发时用）。 */
function findAsset(release, name) {
  const assets = Array.isArray(release && release.assets) ? release.assets : [];
  return assets.find((a) => a && a.name === name) || null;
}

async function fetchAssetsRelease({ http, token, owner, repo, tag }) {
  const res = await githubGetJson(http, token, repoApiUrl(owner, repo, `/releases/tags/${encodeURIComponent(tag)}`));
  if (res.status === 404) {
    throw new Error(`索引仓没有 Release「${tag}」：自动更新要往里放包，请先建好这个 Release（见 README 自动更新一节的部署说明）`);
  }
  assertGithubOk(res, `读取 Release ${tag}`);
  return res.json;
}

/**
 * 把 zip 传到索引仓 Release。同名资产已存在时直接复用 —— 资产名就是 sha256，同名即同字节。
 * 422 是 GitHub 对「同名资产已存在」的回应；再拉一次 Release 确认后复用，不当失败报。
 */
async function uploadZipAsset({
  http, token, owner, repo, release, assetName, bytes, log,
}) {
  const existing = findAsset(release, assetName);
  if (existing) {
    log(`资产 ${assetName} 已存在，复用 ${existing.browser_download_url}`);
    return { asset: existing, reused: true };
  }
  const url = `${GITHUB_UPLOADS}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/releases/${release.id}/assets?name=${encodeURIComponent(assetName)}`;
  log(`上传 ${assetName}（${bytes.length} 字节）→ ${url}`);
  const res = await http.postBinary(url, bytes, {
    headers: githubHeaders(token, { 'content-type': 'application/zip' }),
    maxBytes: MAX_JSON_BYTES,
  });
  if (res.status === 201 && res.json && typeof res.json.browser_download_url === 'string') {
    return { asset: res.json, reused: false };
  }
  if (res.status === 422) {
    const fresh = await fetchAssetsRelease({
      http, token, owner, repo, tag: release.tag_name,
    });
    const again = findAsset(fresh, assetName);
    if (again) {
      log(`资产 ${assetName} 在并发上传中已存在，复用`);
      return { asset: again, reused: true };
    }
  }
  const detail = res.json && res.json.message ? res.json.message : `HTTP ${res.status}`;
  throw new Error(`上传 ${assetName} 失败：${detail}`);
}

// ── 发现新版本：repo 路径 ─────────────────────────────────────────────────

/**
 * 从仓库发现新版本。返回 {status:'submitted', ...} / {status:'skipped', reason} /
 * {status:'rejected', reason} / {status:'fallback', reason}。
 *
 * fallback 只用于「这个仓库没有可用的 zip Release / 没有比索引更新的版本」——此时若模块
 * 还有 updateJson，可以走 B 路径。复核失败（id、updateJson、包结构）是 rejected，不回退。
 */
async function discoverFromRepo({
  module, slug, assetsRepo, http, token, nowMs, releaseTag, submit, log,
}) {
  const listUrl = repoApiUrl(slug.owner, slug.repo, `/releases?per_page=${REPO_LIST_LIMIT}`);
  const listRes = await githubGetJson(http, token, listUrl);
  assertGithubOk(listRes, `读取 ${slug.owner}/${slug.repo} 的 Releases`);

  const release = pickLatestZipRelease(listRes.json);
  if (!release) {
    return { status: 'fallback', reason: '仓库没有带 .zip 资产的 Release' };
  }
  const asset = zipAssetOf(release);

  // 同一份字节已经进过索引：不必再下载 64MiB，也不必重复上传。
  if (hasDigest(module, asset.digest)) {
    return { status: 'skipped', reason: `Release ${release.tag_name} 的字节已是最新（摘要已存在）` };
  }

  if (typeof asset.browser_download_url !== 'string' || !asset.browser_download_url) {
    throw new Error(`Release ${release.tag_name} 的资产 ${asset.name} 没有下载地址`);
  }
  const zipRes = await http.getBuffer(asset.browser_download_url, {
    headers: { accept: 'application/octet-stream' },
    maxBytes: MAX_ZIP_BYTES,
  });
  if (zipRes.status !== 200) {
    throw new Error(`下载 ${asset.browser_download_url} 返回 HTTP ${zipRes.status}（GitHub 资产下载失败，整个 run 中止）`);
  }
  const bytes = zipRes.body;
  const inspected = inspectModuleZip(bytes);
  if (!inspected.ok) {
    return { status: 'rejected', reason: `包不可用：${inspected.error}` };
  }
  if (inspected.prop.id !== module.id) {
    return { status: 'rejected', reason: `包内 id 是「${inspected.prop.id}」，与索引的「${module.id}」不一致` };
  }
  const ver = versionFromProp(inspected.prop);
  if (!ver.ok) return { status: 'rejected', reason: ver.error };

  const highest = highestVersionCode(module);
  if (ver.versionCode <= highest) {
    return { status: 'fallback', reason: `Release ${release.tag_name} 的 versionCode ${ver.versionCode} 不高于索引最高 ${highest}` };
  }
  const uj = checkUpdateJsonUnchanged(module, inspected.prop);
  if (!uj.ok) return { status: 'rejected', reason: uj.error };

  const digest = sha256Hex(bytes);
  // GitHub 的 asset digest 是这串字节的权威摘要；下载回来的字节必须与它一致，
  // 否则「Release 里的这份资产」和「我们实际落盘/索引的这份包」就不是同一份。
  const expectedDigest = normalizeDigest(asset.digest);
  if (!expectedDigest) {
    return { status: 'rejected', reason: `Release ${release.tag_name} 的资产 ${asset.name} 没有 digest，无法证明下载字节` };
  }
  if (expectedDigest !== `sha256:${digest}`) {
    return { status: 'rejected', reason: `下载字节与 Release 资产 digest 不一致（资产 ${expectedDigest}，下载 sha256:${digest}）` };
  }
  const assetName = `${digest}.zip`;
  const version = buildVersionEntry({
    version: ver.version,
    versionCode: ver.versionCode,
    zipUrl: assetDownloadUrl(assetsRepo, releaseTag, assetName),
    size: bytes.length,
    time: releaseEpochMs(release, nowMs),
    sha256: digest,
    autoVia: 'repo',
    repoTag: release.tag_name,
  });

  // dry-run 不真的上传，但 pending 里要给出「真跑时会写进去」的地址，否则演练结果没有参考价值。
  if (!submit) {
    return { status: 'submitted', version, releaseTag, assetName, reused: false };
  }

  const assetsRelease = await fetchAssetsRelease({
    http, token, owner: assetsRepo.owner, repo: assetsRepo.repo, tag: releaseTag,
  });
  const uploaded = await uploadZipAsset({
    http,
    token,
    owner: assetsRepo.owner,
    repo: assetsRepo.repo,
    release: assetsRelease,
    assetName,
    bytes,
    log,
  });
  return {
    status: 'submitted',
    version: { ...version, zipUrl: uploaded.asset.browser_download_url },
    releaseTag,
    assetName,
    reused: uploaded.reused,
  };
}

// ── 发现新版本：updateJson 路径 ───────────────────────────────────────────

async function discoverFromUpdateJson({
  module, http, nowMs, log,
}) {
  const url = String(module.updateJson || '').trim();
  if (!/^https:\/\//i.test(url)) {
    return { status: 'rejected', reason: `updateJson 不是 https 地址：${url || '(空)'}` };
  }

  let doc;
  try {
    const res = await http.getJson(url, { maxBytes: MAX_JSON_BYTES });
    if (res.status === 404 || res.status === 410) {
      return { status: 'rejected', reason: `updateJson 返回 HTTP ${res.status}：${url}` };
    }
    if (res.status === 429 || res.status >= 500) {
      throw new Error(`读取 updateJson 返回 HTTP ${res.status}（${url}），外部托管不可用，整个 run 中止`);
    }
    if (res.status !== 200) {
      return { status: 'rejected', reason: `updateJson 返回 HTTP ${res.status}：${url}` };
    }
    doc = res.json;
  } catch (err) {
    const c = classifySafeHttpError(err);
    if (c.reject) return { status: 'rejected', reason: `updateJson 不可用：${c.reason}` };
    throw err;
  }
  if (!doc || typeof doc !== 'object') {
    return { status: 'rejected', reason: 'updateJson 不是 JSON 对象' };
  }
  if (doc.id !== module.id) {
    return { status: 'rejected', reason: `updateJson 的 id 是「${doc.id}」，与索引的「${module.id}」不一致` };
  }
  const versionCode = Number(doc.versionCode);
  if (!Number.isInteger(versionCode) || versionCode <= 0) {
    return { status: 'rejected', reason: 'updateJson 的 versionCode 不是正整数' };
  }
  const highest = highestVersionCode(module);
  if (versionCode <= highest) {
    return { status: 'skipped', reason: `updateJson 声明 versionCode ${versionCode}，不高于索引最高 ${highest}` };
  }
  const version = typeof doc.version === 'string' ? doc.version.trim() : '';
  if (!version) return { status: 'rejected', reason: 'updateJson 没有 version' };
  const zipUrl = typeof doc.zipUrl === 'string' ? doc.zipUrl.trim() : '';
  if (!zipUrl) return { status: 'rejected', reason: 'updateJson 没有 zipUrl' };
  if (!/^https:\/\//i.test(zipUrl)) {
    return { status: 'rejected', reason: `updateJson 的 zipUrl 不是 https 地址：${zipUrl}` };
  }

  let bytes;
  try {
    const res = await http.getBuffer(zipUrl, { maxBytes: MAX_ZIP_BYTES });
    if (res.status === 404 || res.status === 410) {
      return { status: 'rejected', reason: `zipUrl 返回 HTTP ${res.status}：${zipUrl}` };
    }
    if (res.status === 429 || res.status >= 500) {
      throw new Error(`下载 zipUrl 返回 HTTP ${res.status}（${zipUrl}），外部托管不可用，整个 run 中止`);
    }
    if (res.status !== 200) {
      return { status: 'rejected', reason: `zipUrl 返回 HTTP ${res.status}：${zipUrl}` };
    }
    bytes = res.body;
  } catch (err) {
    const c = classifySafeHttpError(err);
    if (c.reject) return { status: 'rejected', reason: `zipUrl 不可下载：${c.reason}` };
    throw err;
  }

  const inspected = inspectModuleZip(bytes);
  if (!inspected.ok) return { status: 'rejected', reason: `包不可用：${inspected.error}` };
  if (inspected.prop.id !== module.id) {
    return { status: 'rejected', reason: `包内 id 是「${inspected.prop.id}」，与索引的「${module.id}」不一致` };
  }
  const propCode = Number.parseInt(inspected.prop.versionCode, 10);
  if (!Number.isInteger(propCode) || propCode <= 0) {
    // 包内没有 versionCode 就没法确认「下载的这份字节」真是 updateJson 声明的那个版本，
    // 不能睁一只眼闭一只眼放过去。
    return { status: 'rejected', reason: '包内 module.prop 没有合法的 versionCode，无法确认包版本' };
  }
  if (propCode !== versionCode) {
    return {
      status: 'rejected',
      reason: `包内 module.prop 的 versionCode ${propCode} 与 updateJson 声明的 ${versionCode} 不一致`,
    };
  }
  const uj = checkUpdateJsonUnchanged(module, inspected.prop);
  if (!uj.ok) return { status: 'rejected', reason: uj.error };

  const digest = sha256Hex(bytes);
  const entry = buildVersionEntry({
    version,
    versionCode,
    zipUrl,
    size: bytes.length,
    time: Math.trunc(nowMs),
    sha256: digest,
    autoVia: 'update-json',
  });
  log(`updateJson 发现新版本 ${module.id} ${version}（${versionCode}），${bytes.length} 字节`);
  return { status: 'submitted', version: entry, releaseTag: null, assetName: null };
}

// ── 主流程 ────────────────────────────────────────────────────────────────

function readIndex(indexFile) {
  const stat = fs.statSync(indexFile);
  if (stat.size > MAX_INDEX_BYTES) throw new Error(`索引文件过大（${stat.size} 字节）：${indexFile}`);
  const json = JSON.parse(fs.readFileSync(indexFile, 'utf8'));
  if (!json || !Array.isArray(json.modules)) throw new Error(`${indexFile} 里没有 modules 数组`);
  return json;
}

function readPreviousState(stateFile) {
  if (!fs.existsSync(stateFile)) return emptyState();
  const json = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  if (!json || typeof json !== 'object' || !json.modules || typeof json.modules !== 'object') {
    throw new Error(`${stateFile} 不是合法的 repo-state.json（缺 modules）`);
  }
  return json;
}

function summaryMarkdown({ verify, outcomes, submitted, filesCount, releaseTag }) {
  const lines = [];
  lines.push('## 自动更新扫描');
  lines.push('');
  lines.push(`- 复验仓库：${verify.summary.total} 个（成立 ${verify.summary.verified}，失效 ${verify.summary.unverified}，故障保留 ${verify.summary.preserved}）`);
  lines.push(`- 提交新版本：${submitted.length} 个模块`);
  lines.push(`- 待提交文件：${filesCount} 个（上传 Release：${releaseTag}）`);
  if (outcomes.length > 0) {
    lines.push('');
    lines.push('| 模块 | 结果 | 说明 |');
    lines.push('| --- | --- | --- |');
    for (const o of outcomes) {
      lines.push(`| ${o.id} | ${o.action} | ${String(o.reason || '').replace(/\|/g, '\\|')} |`);
    }
  }
  lines.push('');
  lines.push('本 PR 由 `scripts/auto-update.mjs` 生成；合并后 `Rebuild Index From Main` 会把 pending 消费进索引。');
  return `${lines.join('\n')}\n`;
}

/**
 * 主流程。`deps` 全部可注入，测试因此不必联网：
 *   - index / previousState：已解析的对象（缺省从磁盘读）
 *   - http：createSafeHttp() 的替代品
 *   - now：返回毫秒的函数
 *   - dryRun：true 时不写文件、不提 PR，只返回结果
 *   - autoPr：postAutoPr 的替代品
 */
export async function main(argv = process.argv.slice(2), env = process.env, deps = {}) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log('用法：node scripts/auto-update.mjs [--index <file>] [--state <file>] [--summary <file>] [--dry-run]');
    return { submitted: [], files: [], changed: false, prUrl: null };
  }
  const root = deps.root || REPO_ROOT;
  const indexFile = path.resolve(root, args.index || deps.indexFile || path.join('json', 'modules.json'));
  const stateFile = path.resolve(root, args.state || deps.stateFile || AUTO_PR_STATE_PATH);
  const log = deps.log || ((msg) => console.log(msg));
  const now = deps.now || Date.now;
  const nowMs = now();
  const releaseTag = env.RELEASE_TAG || env.ASSETS_RELEASE_TAG || DEFAULT_RELEASE_TAG;
  const dryRun = Boolean(args.dryRun || deps.dryRun);
  const token = deps.githubToken ?? env.GITHUB_TOKEN ?? '';
  if (!token) throw new Error('缺少 GITHUB_TOKEN：自动更新要读仓库、上传资产');

  const index = deps.index || readIndex(indexFile);
  const previousState = deps.previousState || readPreviousState(stateFile);
  const http = deps.http || createSafeHttp();
  const autoPr = deps.autoPr || postAutoPr;

  const assetsRepo = deps.assetsRepo || parseAssetsRepo(env);
  if (!assetsRepo) {
    throw new Error('不知道索引仓是哪个：需要 GITHUB_REPOSITORY=owner/repo（或 ASSETS_REPO）');
  }
  log(`索引仓：${assetsRepo.owner}/${assetsRepo.repo}，资产 Release：${releaseTag}`);

  // 1) 先全量复验：它给出「哪些模块的仓库现在还能用」，也产出本轮的状态基线。
  const verify = await verifyReposCore({
    modules: index.modules,
    previousState,
    http,
    token,
    nowMs,
    log,
  });
  const verifyById = new Map(verify.results.map((r) => [r.id, r]));

  const outcomes = [];
  const files = [];
  const submitted = [];
  let nextModules = { ...verify.state.modules };

  // 2) 逐个模块找新版本。索引顺序就是提交顺序（稳定、可预期）。
  for (const module of index.modules) {
    if (submitted.length >= MAX_MODULES_PER_RUN) {
      outcomes.push({ id: module.id, action: 'skipped', reason: `本轮已达 ${MAX_MODULES_PER_RUN} 个模块上限` });
      continue;
    }
    if (!module || typeof module.id !== 'string' || !ID_RE.test(module.id)) {
      outcomes.push({ id: String(module && module.id), action: 'rejected', reason: '模块 id 不能用作 pending 路径' });
      continue;
    }
    if (typeof module.name !== 'string' || typeof module.author !== 'string'
      || typeof module.description !== 'string') {
      outcomes.push({ id: module.id, action: 'rejected', reason: '模块缺 name/author/description，无法组装 pending' });
      continue;
    }

    const slug = parseRepoUrl(module.repoUrl);
    const repoUsable = slug.ok
      && module.repoVerified === true
      && verifyById.get(module.id)?.verdict !== 'unverified';
    let result = null;

    if (repoUsable) {
      result = await discoverFromRepo({
        module,
        slug,
        assetsRepo,
        http,
        token,
        nowMs,
        releaseTag,
        submit: !dryRun,
        log,
      });
      if (result.status === 'fallback') {
        log(`${module.id}：仓库路径没有新版本（${result.reason}），尝试 updateJson`);
      }
    }

    // 仓库路径没结果（没候选 / 没有更新）时，若模块还配了 updateJson，走 B 路径。
    const fallbackAllowed = !repoUsable
      || (result && (result.status === 'fallback' || result.status === 'skipped'));
    if ((!result || result.status === 'fallback' || result.status === 'skipped') && fallbackAllowed
      && typeof module.updateJson === 'string' && module.updateJson.trim()) {
      const viaJson = await discoverFromUpdateJson({
        module, http, nowMs, log,
      });
      if (viaJson.status === 'submitted' || viaJson.status === 'rejected') result = viaJson;
      else if (!result || result.status === 'fallback') result = viaJson;
    }

    if (!result) {
      outcomes.push({
        id: module.id,
        action: 'skipped',
        reason: module.repoVerified === true ? '没有可用的更新来源' : '没有已验仓库，也没有 updateJson',
      });
      continue;
    }
    if (result.status !== 'submitted') {
      // fallback 只是「仓库路径走不通」的中间态；到这还没换成 submitted，就等于本轮跳过。
      outcomes.push({
        id: module.id,
        action: result.status === 'fallback' ? 'skipped' : result.status,
        reason: result.reason,
      });
      continue;
    }

    // 复验刚查到的 LICENSE 比索引里可能有的旧值更新，优先用复验结果。
    const verifiedEntry = verify.state.modules[module.id] || {};
    const pendingModule = {
      ...module,
      // pending 里写归一化地址：Worker 会归一化后校验，但索引里这一格必须是规范形式，
      // 否则 state 与索引的 repoUrl 比较会因尾斜杠/.git 这种写法差异而失配。
      ...(slug.ok ? { repoUrl: slug.url } : {}),
      repoLicense: verifiedEntry.repoLicense || module.repoLicense,
      repoVerified: typeof verifiedEntry.repoVerified === 'boolean' ? verifiedEntry.repoVerified : module.repoVerified,
      repoCheckedAt: Number.isFinite(verifiedEntry.repoCheckedAt) ? verifiedEntry.repoCheckedAt : module.repoCheckedAt,
    };
    const pending = buildPendingJson({
      module: pendingModule,
      version: result.version,
      releaseTag: result.releaseTag || undefined,
      assetName: result.assetName || undefined,
      submittedAt: formatTimestamp(nowMs),
      repoCheckedAt: nowMs,
    });
    const relPath = `pending/${module.id}/${result.version.versionCode}.json`;
    files.push({ path: relPath, content: `${JSON.stringify(pending, null, 2)}\n` });
    submitted.push({ id: module.id, via: result.version.autoVia, versionCode: result.version.versionCode });
    outcomes.push({
      id: module.id,
      action: 'submitted',
      reason: `${result.version.autoVia === 'repo' ? '仓库' : 'updateJson'} → ${result.version.versionCode}${result.reused ? '（资产复用）' : ''}`,
    });

    if (result.version.autoVia === 'repo') {
      const previousEntry = verify.state.modules[module.id] || {};
      nextModules[module.id] = cleanStateEntry({
        ...previousEntry,
        repoUrl: slug.url,
        repoVerified: true,
        repoCheckedAt: nowMs,
        repoLicense: previousEntry.repoLicense || module.repoLicense,
      });
    }
    log(`提交 ${module.id} 版本 ${result.version.version}（${result.version.versionCode}），来源 ${result.version.autoVia}`);
  }

  // 3) 状态定稿：只有内容变了才把 checkedAt 往前推、才把 state 放进 PR。
  const finalized = finalizeState(previousState, nextModules, nowMs);
  if (finalized.changed) {
    files.push({ path: AUTO_PR_STATE_PATH, content: `${JSON.stringify(finalized.state, null, 2)}\n` });
  }

  const markdown = summaryMarkdown({
    verify, outcomes, submitted, filesCount: files.length, releaseTag,
  });
  const summaryFile = args.summary || deps.summaryFile;
  if (summaryFile) fs.writeFileSync(summaryFile, markdown, 'utf8');

  if (files.length === 0) {
    log('本轮没有新版本、状态也没有变化 —— 不开 PR。');
    return {
      submitted: [], files: [], changed: false, markdown, verify, state: finalized.state,
    };
  }

  if (dryRun) {
    log(`[dry-run] 将提交 ${files.length} 个文件：`);
    for (const f of files) log(`  - ${f.path}`);
    log(markdown);
    return {
      submitted, files, changed: finalized.changed, markdown, verify, state: finalized.state,
    };
  }

  const workerBase = env.WORKER_BASE || env.SUBMIT_WORKER_URL || '';
  const autoKey = env.AUTO_PR_KEY || '';
  const pr = await autoPr({
    http,
    workerBase,
    autoKey,
    title: `chore(auto): 自动更新 ${submitted.length} 个模块（${formatTimestamp(nowMs)}）`,
    body: markdown,
    files,
    log,
  });
  return {
    submitted, files, changed: finalized.changed, markdown, verify, state: finalized.state, prUrl: pr.prUrl,
  };
}

/** 索引仓 = 当前仓库。GitHub Actions 注入 GITHUB_REPOSITORY；本地可用 ASSETS_REPO 覆盖。 */
export function parseAssetsRepo(env) {
  const raw = (env && (env.ASSETS_REPO || env.GITHUB_REPOSITORY)) || '';
  const parts = String(raw).trim().split('/').filter(Boolean);
  if (parts.length === 2 && ID_RE.test(parts[0]) && ID_RE.test(parts[1])) {
    return { owner: parts[0], repo: parts[1] };
  }
  return null;
}

export function parseArgs(argv) {
  const out = {
    index: '', state: '', summary: '', dryRun: false, help: false,
  };
  const args = Array.isArray(argv) ? argv.slice() : [];
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--index') { out.index = args[i + 1] || ''; i += 1; }
    else if (a === '--state') { out.state = args[i + 1] || ''; i += 1; }
    else if (a === '--summary') { out.summary = args[i + 1] || ''; i += 1; }
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '-h' || a === '--help') out.help = true;
    else throw new Error(`不认识的参数：${a}`);
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`::error::自动更新失败：${err && err.stack ? err.stack : err}`);
    process.exitCode = 1;
  });
}
