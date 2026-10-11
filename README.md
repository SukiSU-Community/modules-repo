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
                              ──> 把改动集交给 Worker：App 建分支 + 开**索引 PR**
                                      │
                    索引 PR 自己的 audit run ──> kind/derive 判「索引 == base 的推导」
                                      │
                            merge-index（squash 合并；只能在这个上下文里合，见上文第 4 条）
```

不变式：**main 的唯一入口是「合并一个 approve 成功的 PR」，索引是 main 内容的函数。**
而 `approve` 自己挂在 `selftest` 上 —— 判定器没通过仓库单测时，它没有资格批准任何东西。

索引改动自己也走 PR（而不是直接 push main），因为 repo ruleset 不给 GitHub Actions 开
bypass。于是多了一个必须回答的问题：*一个只改 `json/modules.json` 的 PR，凭什么算批准？*
答案是 `scripts/verify-index-pr.mjs`，判据只有一条，而且是按内容判：

```
PR 里的索引 == buildIndex(base 索引, base 上被本 PR 消费掉的那些 pending 条目)
```

「那些条目算已批准」**不由 PR 自己声明** —— 否则删掉一个从没批准的 `pending/xxx.json`
再把它手抄进索引就能过。批准依据必须去外部取：把该文件带上 main 的那个提交所属 PR，
其 head sha 上 `approve` 的结论为 success（复用 `publish-from-main.mjs` 的
`findPrForCommit` / `assertMergeApproved`，和盖审核章同一套判据）。

四种伪造各有对应断言，其中五种在 `test/verify-index-pr.test.mjs` 里用**真 git 仓库 +
真 build-index.mjs** 跑（`ls-tree` / `log -1 -- path` / `diff-filter` 这些行为靠读代码猜，
最容易落成「单测全绿但 CI 永远判不过」—— 事实上当初就撞出一个 `Set.prototype.filter`）：

| 伪造 | 结果 |
|---|---|
| 改了索引但一个 pending 都没消费 | 拒：索引不是推导出来的，是手改的 |
| 删掉没批过的 pending 再抄进索引 | 拒：拿不到批准证据 |
| 索引 PR 里夹带新投稿 | 拒：交回投稿扫描判定 |
| 内容对但字段被动过（如 `verified`） | 拒：逐字段差异报出来 |
| 只换 `lastUpdate` / 模块顺序 | 放行：时间戳与顺序不是内容 |

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

## 闭环实测记录（2026-10-10，投稿 PR #4 / 危险样本 PR #11）

上面那句话照做了，于是一连串「测试全绿但生产是死的」全部现形。每条都记在这里，
因为它们的共同形状是：**本地测不出来**，只有真跑一次才看得见。

| # | 现象（证据形态） | 根因 | 修法 | PR |
|---|---|---|---|---|
| 1 | 审核第一步就失败：`下载地址主机不在允许列表内：release-assets.githubusercontent.com` | GitHub 把 release asset 的 302 目标换了域，白名单把自己挡在门外 | 白名单加该域；中间跳只过协议/凭据/主机，「扫的包=合的包」仍由实下载字节的 sha256 比对兜住 | #5 |
| 2 | 维护 PR `gh pr checks` → no checks reported，`mergeStateStatus` → BLOCKED | 配了 required check 之后「从没上报」和「失败」对 GitHub 是同一件事，而触发带 `paths` 过滤 → 改 scripts/ 的 PR 永远不会有不存在的 approve | 去掉 `paths`，每个 PR 都跑；非投稿 PR 由 `found=false` 放行，而不是靠不触发 | #5 |
| 3 | `git push origin main` 与 `gh pr merge` 全被拒：`Cannot update this protected ref.` | ruleset 里的 `update`（Restrict updates）＋ `bypass_actors: []` ＝ 谁都不能更新 main，包括 Actions | 删掉 `update`；`deletion`/`non_fast_forward`/`pull_request`/`required_status_checks` 这四条已经足够，实测直接推 main 仍然被拒 | — |
| 4 | 重跑投稿审核时报 `PR 分支不是 origin/main 的后代` | main 会被机器人自己推进，投稿方是不会 rebase 的机器人 → 投稿永久冻死 | 闸门二改为 `git merge --no-commit --no-ff $BASE_SHA`：合得动就审，真冲突才拒（并 abort，不猜哪一边） | #6 |
| 5 | 扫描步骤 **success 却零产出**，失败要到下一步才以 `ls: cannot access '*.audit.json'` 冒出来 | `scan.mjs` 的 CLI 入口判据拿 `argv[1]` 拼 file URL；Linux 上 `argv[1]` 保持相对路径，拼出来永远不等于 `import.meta.url` → `main()` 整个不跑。Windows 把 argv[1] 规范化成绝对路径，所以本地 143 条测试全绿 | 判据换成 `resolve(argv[1]) === fileURLToPath(import.meta.url)`，并抽成纯函数好在开发机上测两种形态；同一形状的两个脚本一起改。**结论：这道审核闸上线以来没扫过任何一个模块** | #8 |
| 6 | 同上，但作为闸本身 | 「绿勾 + 一个字节都没扫」如果靠下游 `ls` 偶然兜住，只要哪天目录里有残留凑巧凑齐数量，就会放行未审内容 | 扫描步骤加覆盖度闸：`*.audit.json` 份数 < 待扫清单行数就 exit 1，并打出 WANT/GOT/PRODUCED | #7 |
| 7 | dispatch 盖章时报「提交 c8f6a036 没有关联的 PR（可能是人工直接推到 main）」 | `/commits/{sha}/pulls` 返回**裸数组**，代码读的是 `data.pull_requests`；而测试桩照同一个误解返回 `{pull_requests:[…]}` —— 桩与实现一起错 | 两种形状都认，桩改成 GitHub 的真实形状；验过牙齿（改回只认对象后 4 条用例立刻红） | #10 |
| 8 | 投稿被 approve 并合并之后，`Rebuild Index From Main` 一次都没启动 | GitHub 刻意切断 `GITHUB_TOKEN` 造成的 push 链 —— 机器人自己合的提交不触发任何 workflow | 索引重建挂 `workflow_run: Module Submission Audit`，并加 job 级 `if` 只跟成功的运行；实测 `workflow_run` 那条 run 起来了 | #9 |
| 9 | 挂上 workflow_run 之后，每次审核成功都会跑重建 | 脚本语义是「不传 `--changed` = 不限范围」，于是只改 workflow 的维护 PR 会拿自己那次 approve 给 main 上**所有**未消费的 pending 盖章（借章） | `changed_count == 0` 时整一步跳过盖章；重试旧投稿走 dispatch 的 sha 输入 | #9 |

同时验通的两条结论：

- 放行路径：`approve` 绿 → Actions 自己 `gh pr merge` 成功（说明 ruleset 没把机器人挡在外面）→
  盖章成立（`批准证据成立：PR #4 的 approve check 在 0426921a 上为 success`）→
  `build-index` → `validate-index` → 索引 PR 的 `derive` 判**索引与推导一致（消费 1 个已批准条目）** →
  合并后 `json/modules.json` 里出现该模块（`zipUrl` 指向内容寻址资产、`sha256` 一致、`verified:false`），
  `pending/` 只剩 `.example.json`，Worker 的 `/check?id=e2e_probe_module&versionCode=1` 返回 `recorded`。
- 拒绝路径：`customize.sh` 里放 `curl … | sh` + `setenforce 0` 的样本 → 扫描判高风险 →
  `approve` **fail** → 标签 `needs-human-review` + `blocked-auto-merge` → `mergeStateStatus: BLOCKED`，
  并且那次 `workflow_run` 触发的重建被 job 级 `if` **skipped**（红审核不会顺带开索引 PR）。

### 还开着的两个口子（不是代码能解决的）

> **状态更新（2026-10-11）**：这两条已经定案走**方案 ②**（App 开索引 PR），下面两段留作
> 「为什么现在长这样」的原因记录；第 2 条的判据后来被证明写宽了，纠正见下一节。

1. **本 org 禁止 GitHub Actions 创建/批准 PR**。索引那半步需要开 PR，于是 `gh pr create` 直接报
   `GitHub Actions is not permitted to create or approve pull requests`；仓库级同名开关也改不动，
   `PATCH /repos/{owner}/{repo}/actions/permissions/workflow` 返回
   `409 The organization does not allow GitHub Actions to create or approve pull requests`。
   要开只能由 org 管理员在组织设置里放行（当前维护者在该 org 是 admin，但 token 没有 `admin:org` 作用域）。
2. **机器人写的提交不触发 `pull_request` 检查**。实测：Actions 推上来的索引分支开成 PR 后
   `no checks reported`；我用 API 补一个**自己名下**的空提交，检查立刻跑起来并给出 approve。
   也就是说即使第 1 条放行，「机器人开的索引 PR」仍然拿不到 approve —— 两道闸是叠在一起的。

所以「索引 = main 内容的函数」这条不变式在**语义**上已经验通，但第二段还做不到全自动。
三条候选路（需要定一条，见任务 P2 之前）：

1. 索引发布到不受保护的分支（`gh-pages` / `index-data`），Actions 直接 push，不需要 PR、
   也不依赖 org 策略；代价是消费端索引 URL 要改（前端 `config.js` 本来就把索引地址做成可配置项）。
2. 由 Worker 已装的 GitHub App 来开索引 PR —— 它是被允许的 actor，代价是要把「什么时候该重建」
   显式告诉它（合并回执或定时兜底）。
3. 保持现在的设计，每次由人点一下开 PR + 合并（半自动，流程与今天一致，只是多两次人工）。

第 3 条今天就能跑（本次就是这么走完的），但它是「人工在场」，不是「自动放行」。

### 方案 ② 落地后真跑抓到的四件事（2026-10-11，投稿 PR #15 / 索引 PR #16 #19）

选定 ②：Actions 仍负责回查 approve → 盖章 → 算索引 → 校验 → 等绿，只把「写分支 + 开 PR」
这一脚交给 Worker 的 GitHub App（`POST /rebuild-index`，共享密钥 `REBUILD_TOKEN`）。跑之前上面
那段第 2 条得先纠正：**不触发检查的是用 `GITHUB_TOKEN` 推上去的提交**（作者 github-actions[bot]），
App 名下的提交会正常触发 —— 投稿 PR #15 就是 App 开的，`audit`/`approve`/`Merge Approved PR` 照常跑完。

真跑第一次死在四处，全都是「测试全绿但线上是死的」那同一类：

1. **tree 的删除项缺 `mode`** → GitHub 把整棵树 422 掉：
   `Must supply a valid tree.mode`。`sha: null` 只表达「删除」，`mode`/`type` 仍必填。
   单测当时全绿，是因为 `/git/trees` 的 stub 来者不拒 —— 它在回声实现自己发明的形状。
   现在 stub 按 GitHub 的规则校验 mode（含删除项），**stub 必须比实现更挑**，否则它只是面镜子。
2. **`[skip ci]` 进了提交信息** → GitHub 干脆不为这条 PR 创建任何 workflow run，索引 PR #16
   于是永远 `no checks reported`、永远等不到 approve。skip 标记只许留在 **PR 标题**上；提交信息由
   `commitMessageFor()` 剥干净。这条和第 4 条那句「防自转」是两个相反的要求，很容易写反。
3. **`gh pr checks --watch` 不等第一个 check 出现**：PR 刚建好的那几秒列表是空的，它直接
   `no checks reported` + 退出 1（实测 0.9 秒就把这一步判红，而 checks 后来是会建出来的）。
   现在先有界地等 check runs 出现（5 分钟上界，超时报错并指出「先看提交信息里有没有 skip 标记」），
   再 `--watch`，之后单独确认 `approve` 在那个 head sha 上为 success。
4. **合并要放在 `pull_request` 上下文的 run 里**：index.yml（`workflow_run` / `dispatch` 触发）拿
   `GITHUB_TOKEN` 去合索引 PR 得到
   `GraphQL: Resource not accessible by integration (mergePullRequest)`（run 38069741398 → #19），
   而同一个 token 在 audit.yml 的 publish 作业里合**自己那条**投稿 PR（#15）是成功的 —— org 那道
   「不允许 Actions 创建/批准 PR」的开关管的是「在跟目标 PR 无关的 run 里对 PR 动手」。
   因此索引 PR 的合并落在 audit.yml 新增的 `merge-index` 作业，判据两个缺一不可：
   `index_pr`（少它 = 维护类 PR 也会被机器人合掉）+ `index_derived`（少它 = 手抄索引能进 main）。
   `createComment` 在同一 job 里是成功的，所以这不是 `pull-requests: write` 权限不够。

顺带纠正本文以前的一处说法：**`[skip ci]` 不是防自转的承重墙**。`gh pr merge --squash` 的合并提交
信息取的是分支上那条提交的信息（#19 合出来是 `chore(index): rebuild after merge (#19)`，标题里
的 `[skip ci]` 没跟过去），而那条提交恰恰必须干净才能让自己的检查跑起来。真正拦住自转的是两条
结构条件：Actions 自己合出来的 push 不触发 workflow；人工合并时（实测 push run 38070248065 确实
触发了）索引合并提交对 pending 只有删除，`--diff-filter=ACMR` 之后 `changed_count=0`，整段跳过。

还剩一个口（不是这次要解决的）：

* **失败重试要人推一下**：一次重建失败会留下孤儿分支 `index/rebuild-<runId>`，同一个 run 重跑
  会被判 `conflict`（这是有意的：不在半截状态上二次写入）。换新 run（`workflow_dispatch` 填
  那次的 sha）就绕开了 —— 但「下一条无关的合并 PR」**不会**自动把这条被落下的 pending 捡起来，
  因为那次提交没带入 pending，`changed_count=0` 整步跳过。要自动化这一步，得让重建按
  「main 上是否存在未消费 pending」来判断范围，而不是按「这次提交带了什么」。

另外记一笔**已经封掉的那个**，因为它有一个看起来很诱人的错修法：

* **过期索引 PR**（`approve` 绑 head sha，head 不动那次推导判定的绿就一直挂着，而 main 可能已经
  前进）。封法是 `merge-index` 在合并前用**同一个判定器**按此刻的 main 再推导一遍，对得上才合。
  这条闸在索引 PR #28 上真跑过（不是只挂着）：

  ```
  Merge Index PR  steps: 按当前 main 重推导 → 合并
  重推导：base=02ff7eaa（此刻的 main），head=d700df5
  [verify-index-pr] 索引与推导一致（消费 1 个已批准条目）
  ```
  **不要**改成打开 ruleset 的 `strict_required_status_checks_policy`：那一条对所有 PR 生效，会同时
  要求投稿 PR 分支最新才许合，而投稿方是不会 rebase 的机器人 —— 两条投稿挨着进来就把前一条永久
  卡死，和本文上面修掉的「祖先检查冻死机器人投稿」是同一个形状。


### 一件被 canary 实测推翻的事：`skipped` 的 required check 等于**满足**

接完 `selftest` 之后我写的设计是「selftest 红 → `approve` 因 needs 不满足而被 skip →
required check 没成功 → 不放行」。听起来很顺，而且和本仓库以前那条经验（「check 从来没跑过」
和「check 失败」对 GitHub 是同一件事，PR 会永远 BLOCKED）长得几乎一样。

**它是错的。** 为了验证我开了一条故意打坏一个断言的 canary PR #24，实际结果是：

```
selftest        fail
approve         skipping        ← 不是 fail，是 skip
Scan & Triage   pass
gh pr view →  mergeable: MERGEABLE, mergeStateStatus: UNSTABLE
gh pr merge 24 → 合进去了
```

所以要分清两种「没有绿」：

| 状态 | ruleset 眼里的意思 |
| --- | --- |
| required check **从没上报过**（Expected） | 不满足 → BLOCKED（本文 paths 过滤那次撞的就是这个） |
| 上报了但结论是 **skipped** | **按满足处理** → 放行 |

也就是说「上游红了就让 approve 不跑」等于把闸门拆了还自以为关着 —— 而且它比没装闸更危险，
因为看的人会以为那个红色 job 挡住了什么。

改法：`approve` 加 `if: always()`，并把自己**第一步**的判据设成「`needs.audit.result` 与
`needs.selftest.result` 都必须是 `success`」，否则 `exit 1` —— 让 required check 明确**变红**，
而不是消失。这样 audit 自己崩了（扫描器挂掉、覆盖度闸开火）也不会出现「approve 缺席但被当成
通过」。

修完再开一次同样的 canary（#26，验完就关，没合），这次实测：

```
selftest          fail
approve           fail           ← 修之前这里是 skipping
Scan & Triage     pass
mergeStateStatus  BLOCKED
gh pr merge 26 → "the base branch policy prohibits the merge"
```

**这道闸现在是实测会咬人，不是看起来像装了。** 同一个 `if: always()` 也顺手堵掉了另一条同形状的
路：以前 `audit` 作业自己崩掉时，approve 同样是 skip = 放行。

`test/canary-selftest-proof.test.mjs` 已从 main 删掉（forward delete，见 #25），canary 只在
「开一条会红的 PR、验证它红且合不动、然后关掉」这个用途下存在。

顺带记一次我自己造的第二类错：把新 step 插在既有的 `steps:` **前面**，于是同一个 job 里出现
两个 `steps:` —— 这不是「CI 变红」，而是**整条 workflow 解析失败、一条 check 都不产生**，
正好落进上面表格的第一行，所有 PR 一起卡死。仓库不许装 YAML 依赖，所以补了
`duplicateJobKeys()` 这条结构检查（缩进恰好 4 的 key 不许重复）来拦这一类。

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

> **这些单测由 CI 的 `selftest` 作业跑，而 `approve` 依赖它**（2026-10-11 接上的）：selftest 红
> → approve 被 skip → required check 不成功 → 投稿与索引都停在门口。之前它们只在本地跑，那正是
> 本轮好几个「测试全绿但线上从没工作」的洞（scan.mjs 的 CLI 入口、`steps.build` 指向一个没声明的
> id、tree 删除项缺 mode）能带着绿灯上线的根因 —— 判定投稿能不能进 main 的那套代码自己没过检，
> 就没有资格批准任何投稿。
>
> 刻意接受的语义：**任意一条单测失败都会挡住合并**，包括与本次改动无关的失败。理由是本仓库的
> 测试只用 node 内置模块、不联网、自建临时 git 仓库。真出现 flaky 应该修测试，而不是把这道闸拆掉
> —— 拆的诱惑很大，因为每次红的都是别人的投稿。
>
> 另一处坑：母本相关的测试（`AUDIT_COPIES` / `INDEX_COPIES`）在独立 clone 里必须跳过而不是 ENOENT，
> 因为 `../../audit/workflows/` 只存在于 monorepo 布局。

## 处置（下架 / 拉黑）

`json/dispositions.json` 是索引推导的**第二个输入**：`索引 = buildIndex(pending, 台账)`。
它不是索引的附属说明，也不是删完就忘的黑名单 —— 判据只有一份
（`scripts/dispositions.mjs`），Worker 与公示页各自镜像/读取它，但不重算判据。

**三处拦截，失效方向刻意不对称：**

| 位置 | 读不到 / 读不懂台账时 | 为什么 |
|---|---|---|
| Worker `POST /submit`（intake） | **放行** | 这里拒掉的代价是「raw 抖一下所有人都投不了稿」；漏放只是这条投稿走到 CI 才被挡 |
| CI `audit.yml` 的 `dispose` 步 + `approve` | **停住判红** | 那里的失效方向是「这次审核没结论」，而「跳过一条坏条目」等于让被下架的模块复活 |
| `build-index.mjs` 推导 | **停住判红**（`--consume` 还不删被挡下的 pending，留作复核现场） | 同上，且起算点不能漂 |

选择器 `id` / `sha256` / `coolapkUid` 之间是 **AND**（写成 OR 会连累同 id 的好版本）；
`versionCode` 必须跟 `id` 同时出现。空选择器直接拒 —— 那条记录会匹配一切。

### 下一条处置

```bash
node scripts/revoke.mjs --id <模块ID> [--version-code <n>] [--sha256 <64hex>] [--uid <酷安UID>] \
     --kind revoke|deny --reason <公示分类> \
     --by https://github.com/<owner>/<repo>/issues/<n>#issuecomment-<id> \
     --note "<给人看的说明>" [--verify <任何人都能跑的复核命令>] [--dry-run]
```

`--by` 现在**必须**是浏览器里点得开的评论永久链接。旧形状 `gh:<login>@issuecomment-<id>`
只有评论 id、没有 issue 号，而 GitHub 无法从评论 id 反查 URL（`api.github.com/repos/<o>/<r>/issues/comments/<id>`
会回 `html_url`，但那是要求访问者自己去查的东西）。校验只加在**写入端**：让通用校验器拒收旧记录
= 读不懂台账 = 推导停住 = 索引冻死，那条失效方向是设计好的。
名字不再进台账 —— 谁下的处置看那条评论的作者，抄一份进台账就是引进一个会过期的字段。

### 为什么「只改台账」的 PR 不算索引 PR（一个被这次改动顺手关掉的洞）

`audit.yml` 的 `kind` 步只看 `json/modules.json` 有没有变。**以前看的是整个 `json/`**，
于是删掉一条处置记录（把某人从黑名单里放出来）会被认成索引重建：它既不消费 pending，
也不改变当前索引，推导必然「一致」→ `merge-index` 自动合。削弱处置不该由推导说了算，
它是人工判断 —— 现在这类 PR 落到「无投稿内容」分支，绿了也要人合。

它真正的后果（被放行的模块重新出现在下一次重建里）本来就依赖有人把那条 pending 留着，
这也正是 `--consume` 不删被台账挡下的 pending 的理由。

### 合并之后：CDN 必须失效

`merge-index` 在 `gh pr merge` 之后紧跟一步 `node scripts/purge-cdn.mjs`。
理由是一条实测：**下架的生效速度由 CDN 的 TTL 决定，而不是由 main 决定** ——
索引 PR #34 把 `json/modules.json` 推空之后近 50 分钟，
`https://cdn.jsdelivr.net/gh/SukiSU-Community/modules-repo@main/json/modules.json`
仍然返回下架前的 4 个模块，也就是订阅那个地址的 App 照样能装到已被下架的包。

- 只内置 jsDelivr 一家：它的 purge 是公开 GET、不需要凭据（往 CI 里塞一把能改 CDN 的钥匙，
  比这一步省下的麻烦贵得多）。别的镜像把地址放进 repo variable `CDN_PURGE_URLS`（逗号分隔），
  脚本对它只认「`cdn.` → `purge.` 换主机名」，认不出来就报「无能为力」并**继续绿** ——
  清不动第三方镜像是运维的事，不该把已经完成的合并判成失败。
- 清除失败（HTTP 非 2xx / `status=error` / 网络异常）→ **退出码 1**，输出里带重试命令。
  合并已经发生，这一步红不撤销任何事，只是把「CDN 还在发旧索引」变成看得见的失败。
- 本地开发机上 `node` 直连 `purge.jsdelivr.net` 会被 `ECONNRESET`（同一时刻 `curl` 打得通，
  `cdn.jsdelivr.net` 也打得通），所以这一步的绿只能在 CI 里看；失败路径与三态判定由
  `test/purge-cdn.test.mjs` 用注入的 fetch 覆盖。

**但 purge 只清得掉边缘，清不掉客户端。** jsDelivr 对 `@分支` 形式的地址回
`Cache-Control: public, max-age=604800, s-maxage=43200` —— **七天**。实测复现过：清完源站边缘之后，
同一个页面里 `fetch(url)` 仍然拿到 4 个模块，而 `fetch(url, { cache: 'reload' })` 拿到 0 个 ——
差的就是那层本地 HTTP 缓存。投稿站已经把索引与台账两处读取都改成 `cache: "no-cache"`
（配合对方给的弱 ETag，通常只是一个 304），**可管理器 App 自己发的那个订阅请求不归这里管**。
要把客户端那七天也压掉，只有三条路，都还没定：

1. 订阅地址换成带 commit 的固定版本 —— 内容不可变、没有陈旧问题，但地址每次发版都变，
   破坏「一个固定订阅地址」这个前提；
2. 自己出一份带短 `Cache-Control` 的镜像（Worker 加一个 `GET /index.json` 代理，或 GitHub Pages
   —— 后者大陆可达性差，前者要新端点 = 改契约）；
3. 接受它，把话说明白：下架到订阅者生效是「边缘分钟级、客户端最长七天」。

公示页在投稿站那边（`modules-web` 的 `#/incidents`），它显示的就是这份台账原文。

## 发布

仓库推到 GitHub 后开启 **Settings → Pages → Deploy from branch（选默认分支的根目录）**，
索引地址形如：

```
https://<owner>.github.io/<repo>/json/modules.json
```

因为是根目录部署、`json/` 就在根下，这个 URL 从第一次部署起就是 200。
改完索引后务必先跑 `validate-index`，再提交。
