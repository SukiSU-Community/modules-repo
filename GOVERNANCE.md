# 治理与双签（GOVERNANCE）

这份文件回答三个问题：**谁能放行、谁能下架、被挡住的人去哪儿说话。**
它不是承诺，每一条都指着一段已经跑着的代码 —— 代码改了这里必须一起改，
而 `test/publish-from-main.test.mjs` 里钉着「这份文件存在且写着当前那套标记」。

## 1. 角色

| 角色 | 怎么得到 | 能做什么 | 不能做什么 |
|---|---|---|---|
| 任何人 | 不需要 | 投稿、浏览索引、在 `#/incidents` 复验处置、**在索引仓库 issue 里申诉** | 不能影响任何判定 |
| 审核流水线（Actions + GitHub App） | 自动 | 低风险 + 首次收录 → 自动合；按 main 内容推导索引、开索引 PR | 不能批准自己判红的东西，也不能绕过分支保护 |
| 签核人（org member） | 在 `SukiSU-Community` 这个 org 里 | 在 PR 里留 `#human-approved` 签名（**人工放行的唯一凭据**）；下处置 | 不能单人放行（要两签）、不能改索引文件本体 |
| 维护者（repo admin） | GitHub 权限 | 在 PR 上手动合并（包括 `approve` 判红的 PR）；执行 `revoke.mjs` | 不能直接推 main（被 ruleset 挡住） |

**签核人 = org 成员**是刻意的宽：不维护第二份名单，org 的进出就是签核权的进出。
代价是 org 管理员实际上决定了谁能签 —— 这一层目前没有更硬的办法，也就不假装它有。

## 2. 自动放行的边界（不可协商）

1. `main` 的唯一入口是**合并一条过检的 PR**。
2. 索引内容 = `buildIndex(main 上的 pending, main 上的处置台账)` —— 手抄的索引不算数，
   `verify-index-pr.mjs` 会逐字段重算比对。
3. `approve` 这个 required check 必须**上报过且 success**；「没上报」和「上报了但 skipped」
   在 GitHub 的保护里是两种完全不同的东西（后者等于放行），所以 `approve` 用
   `if: always()` 自己判红。
4. 机器人只合两条：
   * **索引重建** —— 索引内容真的变了、变得能对得上推导（消费的是有外部批准证据的 pending），
     且这条 PR **没动处置台账**；
   * **处置台账改动** —— 这条 PR 有**两名不同的人**（CI 查的是此人对这个仓库有 write/admin，
     `GET /repos/{o}/{r}/collaborators/{login}/permission`；见第 7 节为什么不吃 `author_association`）在评论
     首行写 `#human-approved`，且每条新增/改动的处置的 `by` 能回访成这两人之一的真评论。
   签不齐的台账 PR，`approve` 直接红 —— 不是「绿着等人来点」，因为绿勾是会被点的。
   为什么动了台账要单独一条判据、光「推导一致」不算：重算是拿公开仓库里同一份 `build-index.mjs`
   就能自己做出来的，一致只证明内容自洽，证明不了有人看过这条处置。
   为什么连「同时配一份对得上推导的索引」也要单独认：那一步判据按**字节**认索引改没改，而推导按
   **归一化后的内容**认推不推得出，缩进与键序级别的改动让两边给出相反答案（2026-10-17 本地复现
   打出四格，`by` 是自由文本，伪造的署名还会被 Worker 当「下处置的人」念给投稿者）。
5. 下架与拉黑用的是**同一套签名标记与人数**（`#human-approved` × 两名不同的人，见第 3 节），
   区别在于：那里它是「人决定越过红的审核结论」的人工放行，这里它是这条路的**正常准入** ——
   签齐之后机器人才合（合完立刻 purge CDN，因为下架的生效速度由缓存 TTL 决定，不由 main 决定）。

## 3. 人工放行：唯一路径

审核结论是红，但人决定要收某个模块时，**只有一条路**，没有 override 端点、没有 ruleset bypass：

1. 由**两个不同的人**（都是 OWNER 或 MEMBER）在 PR 里各留一条评论，**第一行**以
   `#human-approved` 开头，后面写理由：

   ```
   #human-approved 扫描器把模块里的调试打印判成可疑行为；已人工读过 install.sh，
   # 它只往 /sdcard/ 写日志。有效期：下次重建前。
   ```

2. 由有权限的人在 PR 上点合并（红着的 required check 只有人合得动 —— 这既是权限，也是留痕）。
3. 之后索引重建与盖章照常跑。盖在 pending 上的章长这样：

   ```
   human-approved#<owner>/<repo>PR<号>@<head sha 前 12>/c<评论 id>+c<评论 id>
   ```

   任何人可以复验：

   ```bash
   gh api repos/<owner>/<repo>/issues/comments/<评论 id>   # 看是谁、以什么身份、写了什么理由
   ```

判据在 `scripts/publish-from-main.mjs`（`findHumanApprovals` / `assertMergeApproved`），
机器路和人工路**共用同一个函数**，索引 PR 的取证（`verify-index-pr.mjs`）也走它 —— 不另起一套。

四条硬规定，都是会被测试咬住的：

- **两签按 login 去重**：同一个人发十条仍然是一签。
- **标记必须在第一行开头**：讨论里夹一句 `#human-approved` 不算签 —— 用途要写在脸上。
- **身份在读取时判定**（`author_association`），不是看昵称像不像官方。
- **红着被 bot 合并 → 人工路也拒**。这条路的成立前提就是「有人拿自己的权限点的合并」；
  哪天 Actions 能强合红 PR，说明保护配置被改了，这里拒绝盖章并报错，而不是替那次合并背书。

## 4. 下架 / 拉黑

见 `README.md` 的「处置（下架 / 拉黑）」一节：台账是推导的第二个输入，三处拦截的失效方向
刻意不对称，`by` 必须是指向公开评论的永久链接，`verify` 是可复验命令。
入口只有一个：`scripts/revoke.mjs`（它只写台账 + 调 build-index 重算，绝不手改索引）。
同一条命令会把被处置那一包的原始记录与审核报告固化成 `evidence/<sha256>.json`（文件名 = 它自己字节的
SHA-256），并给台账条目填上 `subject` / `evidence`；捞不到证据就退回不带这两个键，并打出补跑的命令 ——
详见 `README.md` 的「同一条命令还会固化证据」。

## 5. 申诉

**唯一正式渠道：本仓库的 issue** —— https://github.com/SukiSU-Community/modules-repo/issues

- 被下架的模块：在对应处置记录的 `by` 那条 issue 下面回帖，或在**自己的 PR** 里说明。
  处置记录在投稿站的公示页 `#/incidents` 能查到（按模块 ID / 酷安 UID / sha256 过滤）。
- 被审核判红、没进索引的：直接在自己的投稿 PR 里回帖说明；要人放行需要两个签核人的
  `#human-approved`（第 3 节），**不是**你说服一个人就行。
- 申诉没有时限承诺，也没有「一定回复」的承诺 —— 这是社区索引，不是商业服务。
  能承诺的是：**任何一次放行或下架都留下可以复验的名字和证据**，所以「谁决定的」这个问题永远有答案。

酷安站内不是正式渠道：帖子会删、评论会折叠、账号会封，那些都不构成可复验的记录。
站内可以说话，但**结论只认 issue**。

## 6. 收录意味着什么（legal）

- 索引**只是目录**。每个模块 zip 由投稿人提供、存放在 GitHub Releases，本站不重新打包、
  不签名、不做功能保证，也不代表本站运行过它。
- 收录不代表推荐。刷入模块前请自己读 `install.sh` / `module.prop`；模块有弄坏设备的可能，
  后果由刷入者承担。
- 投稿即声明：你是该模块的作者，或已获得作者授权转载；你授权本站公开你填的
  昵称 / 酷安 UID / 出处链接 / 包哈希。
- 侵权与授权争议：出具权利证明后走 `revoke.mjs`（`--reason copyright`），处置记录与理由公开。
- 被下架不等于被定罪。公示页写的是「命中了什么、什么理由、谁下的、什么时候」，
  全部指向可回访的评论；不服就走第 5 节。

## 7. 这份治理的已知限度（不藏）

- 评论可以被作者**事后编辑**。签名有效性以读取时的正文与身份为准，编辑历史要靠 GitHub 的
  activity log 人工看，这里不假装能自动防。
- org 成员资格被回收**不会**追溯撤销已经发生过的签名。已经放行的模块要撤，走 `revoke.mjs`。
- 「谁算签核人」有**两个来源**，因为 `author_association` 是 GitHub **按请求者**算出来的字段：
  人拿自己的 token 跑 `publish-from-main.mjs` 时它是准的（OWNER/MEMBER），而 Actions 里那个
  `github.token` 读同一条评论只回 CONTRIBUTOR（2026-10-17 用 canary #58/#59 线上实测：
  维护者 admin、非协作者 octocat 也回 HTTP 200 但 `permission=read`、bot 回 `none`；
  `/orgs/{owner}/memberships/{login}` 在这个 token 下是 403）。所以 CI 那条路改吃**逐个查仓库权限**，
  判据是权限等级而不是「HTTP 200」。两条路的标记与人数是同一套，只有「谁算人」这一步按执行环境分。
- 签核人名单 = org 成员，所以 org 管理员实际上决定签核权（第 1 节已写明）。
- 目前实际维护者是一个人。也就是说「两个不同的人」这一条在多数时候意味着
  「我和一个愿意签的朋友」—— 比单人强，但别把它读成成熟的多人共治。

## 8. AI 安全员（QCA）的换代纪律

`audit.yml` 的 `id: ai` 那一步只认四个 variables 加一个 secret，且**只加严、永远不决定放行**：

| 键 | 含义 |
| --- | --- |
| `QODER_PAT`（secret） | 运行这一发的那把凭据。**资源必须建在同一把凭据的账号里** —— 用别的身份 `list` 出来能看到不算配好，要用它 `GET` 一次那个 id |
| `QCA_AGENT_ID` / `QCA_AGENT_VERSION` | agent 与**整数版本**。版本号必须成对改：跟着 latest 走 = 谁改了 system prompt 都是改了闸，而 CI 完全看不见 |
| `QCA_ENVIRONMENT_ID` | 排程环境：`networking=limited`、不给 MCP、不给包管理、不装任何包（这一层不执行投稿者的代码） |
| `QCA_PROMPT_SHA` | 期望的 prompt 摘要。设了且对不上 ⇒ 退出码 2、状态文件都写不出来；不设 ⇒ 只把算出的值记进产物 |

换代只有三句，顺序不许变（`repo/` 下执行）：

```sh
node -e "import('./audit/ai-review.mjs').then(m=>console.log(m.PROMPT_SHA256))"   # 现算，别抄任何文档里的旧值
# 用脚本 import 同一份 SYSTEM_PROMPT 更新 agent（POST /agents/<id> 带当前 version），再取回显算第二遍：
# 两次 sha 必须相等，也要等于上面那行；然后才改 QCA_PROMPT_SHA / QCA_AGENT_VERSION 这一对。
gh variable list -R <repo> | grep QCA                                              # 回读，不复述命令输出
```

**手抄 prompt 是被 sha 闸抓住的错，但它抓住的方式是 CI 红，不是静默跑偏** ⇒ 这类东西要么程序生成，
要么抄完双份对 sha。两处实测过的代价要带着：

- 判定的墙钟里大头是**排程**而不是模型（本机两发：约 312s 与约 790s，后者 635s 还在 `rescheduling`）。
  超时会把这一层念成 `failed`（往严，不会误放行），但**掐断之后那一发照样计费** ⇒ 超时不是免费的保守。
- 单发小包实测 `usage.total_credits` ≈ 10.72（≈21.5 KB brief、`medium`）。credits 与钱的换算没核过，
  「一条多包 PR × 每包一发」是本闸的真实成本形状，别按单次调用估。
