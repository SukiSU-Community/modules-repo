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

## 审核标记契约（audit.yml / index.yml ↔ build-index.mjs）

**Workflow 写的、脚本认的，是同一个字段。** 这是两边的唯一约定面，改动必须同步：

| 常量 | 值 | 定义处 | 写入方 |
|---|---|---|---|
| `APPROVAL_FIELD` | `audit` | `scripts/build-index.mjs` | `scripts/publish-from-main.mjs`（经 `markApproved`） |
| `APPROVED_STATUS` | `auto-approved` | 同上 | 同上 |
| `HUMAN_APPROVED_STATUS` | `human-approved` | 同上 | 人工双签脚本（P4，尚未实现） |
| `APPROVE_CHECK_NAME` | `approve` | `scripts/publish-from-main.mjs` | `audit.yml` 的 job `name:` |

自动放行时 pending 条目里的章长这样：

```json
{
  "audit": {
    "status": "auto-approved",
    "by": "ci:approve#SukiSU-Community/modules-repoPR7@aabbccddee12",
    "at": "2026-10-10T09:00:00.000Z",
    "risk": "low",
    "verify": "gh api repos/SukiSU-Community/modules-repo/commits/<headSha>/pulls"
  }
}
```

`by` 必须是**别人也能复验的指针**，不是「ci 说过」这种自证：拿 PR 号 + head sha，
任何人 `gh api .../check-runs?name=approve` 都能重跑这个判断。

`isApproved()` **只认 `audit` 这一个字段**，且章上必须有人（`by` 非空）。
以下写法一律不算通过：

- `{ "approved": true }`、`{ "review": { "approved": true" } }` —— 旧接口，已删。
  保留它们等于给「直接改 pending JSON」留一条比 CI 通道更高的权限捷径：索引文件由
  `build-index` 从 pending 派生，任何能写 pending 的人就能入索引；如果连布尔后门都在，
  这条捷径就完全不需要审核环节。
- `{ "audit": { "status": "auto-approved" } }` —— 无主章。`by` 为空说明盖章的人没留名，
  这种章在追责链上是零价值。

## 两段式自动放行（为什么 publish 不再直接写索引）

```
投稿 PR ──audit（扫描+报告）──> approve（只在「低风险+首次收录」时成功）
                                      │
                            publish（只 squash 合并）
                                      │
                              push 到 main
                                      │
                    index.yml ──> publish-from-main.mjs 回查那次 approve 的结论
                              ──> 盖章 ──> build-index --consume ──> validate-index
                              ──> 提交（带 [skip ci]）
```

不变式：**main 的唯一入口是「合并一个 approve 成功的 PR」，索引是 main 内容的函数。**

以前 publish 在 PR 上下文里直接往 main 推索引提交，于是 main 永远不能开
`require a pull request / restrict pushes`。改成「先往 PR 分支写索引、再合并 PR」也不行：
那次索引提交落在 `pending/**` 上会触发 `synchronize` 把审核再跑一遍，而新 head sha 的
required check 还没出结果时 `gh pr merge` 本身就过不去 —— 两个坑互锁。

拆成两段带来的真问题：合并进 main 的 pending JSON 上**没有章**。章由 `index.yml` 盖，
而它盖之前回查证据，刻意不依赖这三样东西：

| 不依赖 | 为什么 |
|---|---|
| PR 标签 | 有 triage 权限的人随手就能加一个 `auto-approved` |
| PR 评论 | 正文里混着投稿者可控文本与模型产出 |
| 「分支保护肯定配好了」 | 配置是别人可以改的，而 check 结论改不了 |

本地跑这段判定（离线自测，不需要真 token 也能验失败路径）：

```bash
node scripts/publish-from-main.mjs --pending pending --sha <main上的提交> \
     --owner SukiSU-Community --repo modules-repo --report r.json
node --test test/publish-from-main.test.mjs
```

## main 分支保护 runbook（**必须在新 workflow 上了 main 之后再执行**）

顺序错了会直接把生产线打死：`approve` 这个 required check 由新 workflow 产出，
在旧 workflow 还挂在 main 上时把它设为 required，所有投稿 PR 都会因「Expected 且永不发生」
卡死。所以下面这个顺序不能调换：**先推 workflow → 确认 workflow 存在 → 再建 ruleset**。

下面这组参数是拿真仓库一步步试出来的（每条都对着 GitHub 的校验器验过，不是抄文档）：

```bash
# 1) 确认 main 上的 workflow 已经有 approve job（推完再查，必须是 1）
gh api repos/SukiSU-Community/modules-repo/contents/.github/workflows/audit.yml?ref=main \
  --jq '.content' | base64 -d | grep -c 'name: approve'

# 2) 建 ruleset
gh api -X POST repos/SukiSU-Community/modules-repo/rulesets --input - <<'JSON'
{"name":"protect-main","target":"branch","enforcement":"active",
 "conditions":{"ref_name":{"include":["refs/heads/main"],"exclude":[]}},
 "rules":[
   {"type":"update"},
   {"type":"deletion"},
   {"type":"non_fast_forward"},
   {"type":"pull_request","parameters":{"require_extra_approval_for_unattributed_changes":false}},
   {"type":"required_status_checks","parameters":{
      "required_status_checks":[{"context":"approve","integration_id":15368}],
      "strict_required_status_checks_policy":false,
      "do_not_enforce_on_create":false}}
 ]}
JSON
```

踩过的四个坑，别再猜：

| 想当然的写法 | 实际要求 |
|---|---|
| `include: ["main"]` | 必须写**全 ref** `refs/heads/main`；`main`、`main*`、`*` 一律报 `Invalid target patterns` |
| `rules: { require_pull_request: ... }` | `rules` 是**数组**，每项 `{"type": ..., "parameters": ...}` |
| 禁强推叫 `force_pushes` | 类型名是 `non_fast_forward`；`force_push`/`force_pushes`/`branch_protection` 都不是合法 type |
| required check 写在 `parameters.checks[]` | 输入侧键名是 `parameters.required_status_checks[]`（回读时也是这个），`strict` 的真名是 `strict_required_status_checks_policy` |

**没有、也不该有 Actions 的 bypass。** repo ruleset 的 `bypass_actors` 只接受
`Integration / OrganizationAdmin / RepositoryRole / Team / DeployKey / User`；填 Actions
那个 Integration（本仓库 check run 里的 `app.id=15368`）会被拒：
`Actor GitHub Actions integration must be part of the ruleset source or owner organization`，
而 `"App"` 根本不是合法 actor_type。要开后门就得把某个 org 级 App 的凭据塞进 Actions secret。
结论：**索引改动也走 PR**（`index.yml` 自己建分支、开 PR、`gh pr checks --watch` 等 approve
变绿、再 squash 合并），于是「main 上的一切都来自一个过检的 PR」是字面为真，不靠豁免。

`required_approving_review_count` 的默认值是 **0**（bare `pull_request` 就是「必须过 PR，
不必须人类签字」）—— 这正是自动放行需要的；把它调到 1 会让机器人合不了任何 PR。
`require_extra_approval_for_unattributed_changes` 默认为 `true`，这里显式关掉：投稿 PR 与
索引 PR 的提交都由 bot 作者，留着它等于冻死整条流水线。这两个决定都是拿批准概率换审计强度，
第二条贡献者加入后应当重新评估（见 P4 的角色阶梯）。

`deletion` 与 `non_fast_forward` 必须真开：只上 require PR 却留着强推，等于在承重墙上
留一扇谁都能开的门 —— 索引与 pending 历史能被一次 `--force` 抹平，而这条 ruleset 看起来
仍是绿的。

配完之后跑一次真实投稿验证闭环（提交 → approve success → 合并 → index.yml 建索引 PR →
自动合并 → 模块出现在 `json/modules.json`），只看测试通过不算数。


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
