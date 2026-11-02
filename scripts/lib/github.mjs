/**
 * github.mjs
 *
 * GitHub 相关的纯工具：repoUrl 归一化、API 地址、请求头、raw 文件地址。
 *
 * 自动更新与复验两个脚本共用这一份实现，免得「什么算合法 repoUrl」在两处漂成两种答案 ——
 * 那会让索引里的地址过得了复验、却过不了 auto 解析，或者反过来。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

export const GITHUB_API = 'https://api.github.com';
export const GITHUB_UPLOADS = 'https://uploads.github.com';
export const GITHUB_RAW = 'https://raw.githubusercontent.com';

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$/;
const REPO_RE = /^[A-Za-z0-9._-]+$/;

/** GitHub API 请求头。token 为空时不带 Authorization（复验公开信息用得到，但生产必须带）。 */
export function githubHeaders(token, extra = {}) {
  const out = {
    accept: 'application/vnd.github+json',
    'user-agent': 'suki-su-index-auto-update',
    'x-github-api-version': '2022-11-28',
    ...extra,
  };
  if (token) out.authorization = `Bearer ${token}`;
  return out;
}

/**
 * 归一化 `repoUrl`。只认 `https://github.com/<owner>/<repo>`，语义与 Worker 侧 §2.1 一致：
 * 允许结尾斜杠、去掉结尾 `.git`，拒绝 query / fragment / 端口 / userinfo / 多段路径 / 其它主机。
 *
 * @returns {{ok:true, owner:string, repo:string, url:string}|{ok:false, error:string}}
 */
export function parseRepoUrl(raw) {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!v) return { ok: false, error: '空值' };
  let u;
  try {
    u = new URL(v);
  } catch {
    return { ok: false, error: '不是合法 URL' };
  }
  if (u.protocol !== 'https:') return { ok: false, error: '只接受 https' };
  if (u.hostname.toLowerCase() !== 'github.com') return { ok: false, error: '只接受 github.com' };
  if (u.port) return { ok: false, error: '不接受端口' };
  if (u.username || u.password) return { ok: false, error: '不接受 URL 里的凭据' };
  if (u.search || u.hash) return { ok: false, error: '不接受 query 或 fragment' };
  const parts = u.pathname.replace(/^\/+|\/+$/g, '').split('/');
  if (parts.length !== 2) return { ok: false, error: '必须是 https://github.com/<owner>/<repo>' };
  let [owner, repo] = parts;
  if (repo.toLowerCase().endsWith('.git')) repo = repo.slice(0, -4);
  if (!owner || !repo) return { ok: false, error: '必须是 https://github.com/<owner>/<repo>' };
  if (!OWNER_RE.test(owner) || !REPO_RE.test(repo)) {
    return { ok: false, error: 'owner/repo 里含非法字符' };
  }
  return { ok: true, owner, repo, url: `https://github.com/${owner}/${repo}` };
}

/** 仓库 API 地址（suffix 以 / 开头）。 */
export function repoApiUrl(owner, repo, suffix = '') {
  return `${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}${suffix}`;
}

/** raw.githubusercontent.com 上的文件地址；分支名可能含 `/`，逐段编码。 */
export function rawFileUrl(owner, repo, branch, file) {
  const branchPath = String(branch).split('/').map(encodeURIComponent).join('/');
  return `${GITHUB_RAW}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${branchPath}/${encodeURIComponent(file)}`;
}

/** 带 GitHub 头的 GET JSON；返回 {status, headers, json}，4xx/5xx 不抛（交给调用方判）。 */
export async function githubGetJson(http, token, url, options = {}) {
  return http.getJson(url, {
    ...options,
    headers: { ...githubHeaders(token, options.headers || {}) },
  });
}
