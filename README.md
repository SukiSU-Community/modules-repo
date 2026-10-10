# SukiSU-Ultra 模块索引仓库

本仓库**只放元数据**，不放任何 zip。模块的 zip 走 GitHub Release asset，
这里只有一份可被 MMRL / 我们的解析器直接消费的 `json/modules.json`。

## 为什么第一天就必须有一个空的 modules.json

我们踩过的坑：默认源 `modules.kernelsu.org` 返回 404，客户端拿不到 JSON，
界面只剩转圈，并弹出「网络未连接」的误报（SukiSU issue #969）。
所以本仓库第一条铁律是：**索引 URL 从建仓第一天起就必须 200**。
`json/modules.json` 因此在首次提交时就已经存在，内容是合法的空索引
（`modules: []`），而不是等第一个模块入库时才生成。

## 目录约定

```
repo/
├── json/
│   └── modules.json      # 唯一发布物，GitHub Pages 直接托管，必须始终合法 JSON
├── pending/
│   └── *.json            # 待合并条目，一个文件可含单条对象或数组
│                         # 以 . 开头的文件（如 .example.json）是模板，不参与合并
├── scripts/
│   ├── build-index.mjs   # pending -> json/modules.json（递归扫 pending）
│   ├── validate-index.mjs# 校验 json/modules.json
│   └── fetch-pending-zip.mjs  # 读 pending 元数据 -> 下载 zip，供 audit 扫描
├── test/
│   └── build-index.test.mjs
└── conflicts.json        # build-index 产出（有冲突时才有），人工处理清单
```

### zip 不在仓库里

本仓库**只有元数据**。模块 zip 放在 GitHub Release asset 上，
pending 条目里的 `versions[].zipUrl` 就是它的下载地址（另有 `releaseTag` + `assetName`
可拼出 GitHub 直链）。审核流水线要扫 zip 时，先用 `fetch-pending-zip.mjs` 下载：

```bash
node scripts/fetch-pending-zip.mjs pending/ --out-dir /tmp/zips \
  --owner <owner> --repo <repo>
```

它会产出 `/tmp/zips/*.zip` 和一份 `manifest.json`（含每个条目的 sha256 校验结果）。
**不要在 PR 里找 `*.zip`** —— Worker 的 PR 只含元数据 JSON，找不到任何 zip。

### json/modules.json 结构（MMRL 格式）

```json
{
  "name": "SukiSU-Ultra Modules",
  "lastUpdate": 0,
  "modules": [
    {
      "id": "module_id",
      "name": "模块名",
      "author": "作者",
      "description": "描述",
      "verified": false,
      "versions": [
        {
          "version": "v1.0.0",
          "versionCode": 100,
          "zipUrl": "https://github.com/owner/repo/releases/download/v1.0.0/mod.zip",
          "size": 1048576,
          "time": 1700000000000,
          "sha256": "…64 位十六进制…"
        }
      ]
    }
  ]
}
```

`verified` 是我们额外带的字段：**脚本自动放行的一律 `false`**，
只有人工复核通过后才置 `true`。`versions` 按 `versionCode` 降序，最新版在前。

### pending 条目格式

与上面的模块结构一致，额外多一个审核标记，二选一：

```json
{ "approved": true, "id": "…", "versions": [ … ] }
{ "review": { "approved": true }, "id": "…", "versions": [ … ] }
```

未带审核标记的条目会被 `build-index` 直接跳过，不进索引。

## 审核标记契约（audit.yml ↔ build-index.mjs）

**Workflow 写的、脚本认的，是同一个字段。** 这是两边的唯一约定面，改动必须同步：

| 常量 | 值 | 定义处 | 写入方 |
|---|---|---|---|
| `APPROVAL_FIELD` | `audit` | `scripts/build-index.mjs:32` | `contrib/audit/workflows/audit.yml` publish 步骤 |
| `APPROVED_STATUS` | `auto-approved` | `scripts/build-index.mjs:33` | 同上 |

Auto-approve 时 `audit.yml` 会在 pending 条目里写入：

```json
{ "audit": { "status": "auto-approved", "by": "ci:auto-approved", "at": "…", "risk": "low" } }
```

`build-index.mjs` 的 `isApproved()` 认三种写法，任一成立即放行：

1. `{ "audit": { "status": "auto-approved" } }` —— **CI 走的这条**（契约字段）
2. `{ "approved": true }` —— 人工/本地直接标记
3. `{ "review": { "approved": true } }` —— 人工/本地直接标记

> 为什么必须有这一段：Worker 写出的 pending JSON 没有 `approved` 字段，
> 而旧版 `isApproved` 只认 `approved === true`，于是 CI 盖了章也进不了索引。
> 现在 CI 统一写 `audit.status`，脚本统一认 `audit.status`，两边对齐。

## pending 目录是递归的

Worker 开 PR 时写的是 **嵌套路径** `pending/<id>/<versionCode>.json`
（见 `contrib/worker/src/index.ts` 的 `openPendingPr`），不是一个平铺的 `pending/*.json`。
`build-index.mjs` 因此递归遍历 `pending/`（跳过以 `.` 开头的文件与 `node_modules`），
两种布局都能读到：

```
pending/
├── .example.json          # 以 . 开头，是模板，不参与合并
├── legacy_flat.json       # 平铺写法，仍然支持
└── my_module/
    └── 100.json           # Worker 实际写的写法
```

## 脚本用法

两个脚本都是纯 Node，只用 `node:` 内置模块，无需 `npm install`。

### 合并待审条目

```bash
node scripts/build-index.mjs              # 递归扫描 pending/**/*.json 并写回 json/modules.json
node scripts/build-index.mjs --dry-run    # 只打印会发生什么，不写文件
node scripts/build-index.mjs --consume    # 成功后清空 pending/（有冲突时请慎用）
node scripts/build-index.mjs --pending <dir> --index <file>   # 指定目录/索引（CI 用）
```

合并规则：

1. 按 `id` 归并。
2. 同 `id` 已存在 —— 只追加新版本，不改动已有版本。
3. `id + versionCode` 相同但 `sha256` 不同 —— **不覆盖**，写入 `conflicts.json` 交人工。
4. `id + versionCode` 相同且 `sha256` 相同 —— 幂等跳过。
5. 模块元信息（name/author/description）不一致时也会记一条冲突，同样不覆盖。
6. 字段缺失、`zipUrl` 为空、`sha256` 不是 64 位十六进制的条目一律拒绝入索引。

有冲突时脚本退出码为 2，并保留 `pending/` 里的文件不动，等你人工处理。
（非法条目同样计入 `stats.conflicts` —— 否则会出现「`invalid>0` 但 `conflicts===0`」
却照样 `exit 2」的自相矛盾，排查时只看到一个红灯找不到任何冲突记录。）

### 缺失字段兜底（module.prop 只强制 `id/name/version/versionCode`）

KernelSU 只强制 `module.prop` 有 `id/name/version/versionCode`，真实模块缺 `author`
极其常见；App 端 `ModuleProp` 对缺失字段给空串，Worker 原样透传，到这里就是空串。
这些字段**不能拒收** —— 否则投稿者的 PR 被合并了、CI 也放行了，模块却永远进不了
索引，而索引里空空如也、PR 上也没有任何解释。所以一律补齐，并把补齐动作打到
stdout（CI 会贴回 PR）：

| 字段 | 缺失时回落为 | 取自 |
|---|---|---|
| `name` | `id` | 同条目的 `id` |
| `author` | `uploader`，再不然 `unknown` | 投稿者署名（Worker 侧已强制非空） |
| `description` | `"<name> <version>"` | 模块名 + 最大 `versionCode` 那个版本的 `version` |
| `version`（versions[] 内） | `"v<versionCode>"` | 该版本的 `versionCode` |

只有 `id` 仍然强制非空：没有 `id` 无法按 id 归并，兜底也无意义。

stdout 形如：

```
[build-index] 已为 1 个条目兜底补齐缺失字段（module.prop 只强制 id/name/version/versionCode）：
  - my_mod：缺 author -> 用 alice（取自 uploader）；缺 description -> 用 My Mod v1.2.3（取自 name + version）
```

### 校验索引

```bash
node scripts/validate-index.mjs                # 校验 json/modules.json
node scripts/validate-index.mjs path/to.json   # 校验指定文件
```

检查项：顶层结构、`modules` 数组存在（空数组合法）、每个模块
`id/name/author/description` 齐全且非空、`verified` 为布尔、
每个版本 `version/versionCode/zipUrl/size/time/sha256` 齐全且 `zipUrl` 非空、
`id` 与 `versionCode` 不重复、`sha256` 合法、`zipUrl` 为 http(s)。
退出码 0 通过，1 失败。建议接在 CI 和 pre-commit 上。

### 跑单测

```bash
node --test              # 跑 test/ 下的全部单测
node --test test/build-index.test.mjs   # 只跑这一个文件
```

> 注意：`node --test test/`（带目录参数）在 Node 26 上会把 `test/` 当模块去解析而报错，
> 用不带参数的 `node --test` 或上面的显式文件路径。

覆盖 `build-index` 的三种核心情况：新增模块、追加版本、id 冲突不覆盖。

## 发布

仓库推到 GitHub 后开启 **Settings → Pages → Deploy from branch（选默认分支的根目录）**，
索引地址形如：

```
https://<owner>.github.io/<repo>/json/modules.json
```

因为是根目录部署、`json/` 就在根下，这个 URL 从第一次部署起就是 200。
改完索引后务必先跑 `validate-index`，再提交。
