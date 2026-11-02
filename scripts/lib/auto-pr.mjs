/**
 * auto-pr.mjs
 *
 * 把「自动更新算出来的文件」交给 Worker 的 `POST /auto/pr` 开成 PR。
 *
 * 为什么走 Worker 而不是在 Actions 里自己 `git push` + `gh pr create`：
 *   - org 禁止 GitHub Actions 创建/批准 PR（index.yml 的长注释记着实测报错）；
 *   - 机器人推上去的提交不触发 pull_request checks，没有 `approve`，索引 PR 永远合不了。
 *   Worker 用 App 身份写分支，两个问题都没有。这里只负责把文件按契约形状交过去，
 *   并在本地先做一遍 Worker 会做的校验 —— 否则一次 20 个模块跑完最后一秒被 400 拒掉，
 *   等于把整轮工作白做。
 *
 * 契约（§2.3）：
 *   - `files` 1~21 个；
 *   - path 只允许 `pending/<id>/<versionCode>.json` 与 `json/repo-state.json`；
 *   - 每个 content ≤512KB，总计 ≤2MiB；
 *   - 头 `X-Auto-Key`；返回 `{ ok:true, prUrl, branch }`。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

import { MAX_JSON_BYTES } from './http-safe.mjs';

export const AUTO_PR_STATE_PATH = 'json/repo-state.json';
export const AUTO_PR_MAX_FILES = 21;
export const AUTO_PR_FILE_MAX_BYTES = 512 * 1024;
export const AUTO_PR_TOTAL_MAX_BYTES = 2 * 1024 * 1024;

const PENDING_PATH_RE = /^pending\/([A-Za-z0-9._-]+)\/([1-9][0-9]*)\.json$/;

/**
 * 本地预检。返回问题清单（空数组 = 通过）。
 *
 * 与 Worker 的判据保持同一套语义；这里多查一条「pending 内容里的 id/versionCode 与路径一致」，
 * 因为 Worker 会因此 400，而等到那时前面下载/上传的包已经白做了。
 */
export function checkAutoPrFiles(files) {
  const problems = [];
  if (!Array.isArray(files) || files.length === 0) {
    return ['files 必须是非空数组'];
  }
  if (files.length > AUTO_PR_MAX_FILES) {
    problems.push(`files 超过 ${AUTO_PR_MAX_FILES} 个上限（实际 ${files.length}）`);
  }
  let total = 0;
  for (const f of files) {
    if (!f || typeof f !== 'object' || typeof f.path !== 'string' || typeof f.content !== 'string') {
      problems.push('files 里的每一项必须是 { path, content } 字符串');
      continue;
    }
    const bytes = Buffer.byteLength(f.content, 'utf8');
    if (bytes > AUTO_PR_FILE_MAX_BYTES) {
      problems.push(`${f.path} 超过 ${AUTO_PR_FILE_MAX_BYTES} 字节上限`);
    }
    total += bytes;

    if (f.path === AUTO_PR_STATE_PATH) {
      try {
        const json = JSON.parse(f.content);
        if (!json || typeof json !== 'object' || Array.isArray(json)) {
          problems.push(`${f.path} 必须是 JSON 对象`);
        }
      } catch {
        problems.push(`${f.path} 不是合法 JSON`);
      }
      continue;
    }

    const m = PENDING_PATH_RE.exec(f.path);
    if (!m) {
      problems.push(`不允许的路径：${f.path}（只允许 pending/<id>/<versionCode>.json 与 ${AUTO_PR_STATE_PATH}）`);
      continue;
    }
    let json;
    try {
      json = JSON.parse(f.content);
    } catch {
      problems.push(`${f.path} 不是合法 JSON`);
      continue;
    }
    const id = m[1];
    const versionCode = Number(m[2]);
    if (!json || typeof json !== 'object' || json.id !== id) {
      problems.push(`${f.path} 里的 id 与路径不一致`);
    }
    const v = Array.isArray(json.versions) ? json.versions[0] : null;
    if (!v || v.versionCode !== versionCode) {
      problems.push(`${f.path} 里的 versions[0].versionCode 与路径不一致`);
    }
  }
  if (total > AUTO_PR_TOTAL_MAX_BYTES) {
    problems.push(`files 总大小超过 ${AUTO_PR_TOTAL_MAX_BYTES} 字节上限`);
  }
  return problems;
}

/**
 * 提交自动更新 PR。失败一律抛（调用方让整个 run 红），不吞、不重试出半截状态。
 *
 * @returns {Promise<{ok:true, prUrl:string, branch:string}>}
 */
export async function postAutoPr({
  http,
  workerBase,
  autoKey,
  title,
  body,
  files,
  log = () => {},
}) {
  const base = typeof workerBase === 'string' ? workerBase.trim().replace(/\/+$/, '') : '';
  if (!base) throw new Error('缺少 WORKER_BASE（投稿 Worker 的 https 地址），自动更新开不出 PR');
  if (!autoKey) throw new Error('缺少 AUTO_PR_KEY，无法通过 /auto/pr 鉴权');

  const problems = checkAutoPrFiles(files);
  if (problems.length > 0) {
    throw new Error(`自动更新 PR 的文件不合契约：\n- ${problems.join('\n- ')}`);
  }

  const url = `${base}/auto/pr`;
  log(`向 Worker 提交自动更新 PR：${files.length} 个文件 -> ${url}`);
  const res = await http.postJson(url, { title, body, files }, {
    headers: { 'x-auto-key': autoKey },
    maxBytes: MAX_JSON_BYTES,
  });

  if (res.status !== 200) {
    const detail = res.json && res.json.error ? res.json.error : res.body.toString('utf8').slice(0, 300);
    throw new Error(`/auto/pr 返回 ${res.status}：${detail || '(无正文)'}`);
  }
  const json = res.json;
  if (!json || json.ok !== true || typeof json.prUrl !== 'string' || !json.prUrl) {
    throw new Error(`/auto/pr 的成功响应形状不对：${JSON.stringify(json)}`);
  }
  log(`自动更新 PR 已创建：${json.prUrl}（分支 ${json.branch || '?'}）`);
  return json;
}
