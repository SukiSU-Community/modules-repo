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
│   ├── modules.json      # 模块索引，GitHub Pages 直接托管，必须始终合法 JSON
│   ├── columns.json      # 商店「专栏」内容（人工维护，见下文），app 侧展示 + 按可执行字段执行
│   └── proxies.json      # 商店 GitHub 下载代理列表（人工维护，App 侧可远程更新）
├── pending/
│   └── *.json            # 待合并条目，一个文件可含单条对象或数组
│                         # 以 . 开头的文件（如 .example.json）是模板，不参与合并
├── scripts/
│   ├── build-index.mjs   # pending -> json/modules.json（递归扫 pending）
│   ├── validate-index.mjs# 校验 json/modules.json
│   ├── validate-columns.mjs  # 校验 json/columns.json
│   ├── validate-proxies.mjs  # 校验 json/proxies.json（下载代理列表）
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
      "authorCoolapkUrl": "https://www.coolapk.com/u/123456",
      "authorGithubUrl": "https://github.com/octocat",
      "description": "描述",
      "source": "https://www.coolapk.com/feed/123456",
      "uploader": "酷安昵称",
      "coolapkUid": "10086001",
      "submittedAt": 1700000000000,
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

`verified` 是我们额外带的字段：**一律 `false`**。本站没有「人工复核通过」这一档
（见 `GOVERNANCE.md` 第 1 节），所以没有谁有权把它置 `true` —— 要让它变真，得先把「谁有权
置真、凭什么置真」重新建出来，而不是由投稿者自己在 pending JSON 里填一个 `true`。
`versions` 按 `versionCode` 降序，最新版在前。

`source` / `uploader` / `coolapkUid` / `submittedAt` 是**可选**四格，用来给 App 的
「酷安模块详情页」显示出处与上传者，详见下一小节。

### 出处与上传者（可选四字段）

**四格全部可选，缺了就整个键不出现** —— 不是 `null`，也不是空串：消费侧的判据是「键在不在」，
而 `null` 会让老 App 以为有出处、却渲染出一个空链接。

| 字段 | 类型 | 含义 | 什么时候省略 |
|---|---|---|---|
| `source` | string | 出处（酷安帖子链接） | 不是酷安站内的 http(s) 地址 |
| `uploader` | string | 上传者的酷安昵称；**不是** `module.prop` 里的 `author` | trim 后为空 |
| `coolapkUid` | string | 上传者的酷安 UID（`coolapk.com/u/<UID>` 末尾那串数字，可点进去复核） | trim 后为空 |
| `submittedAt` | number | 提交时间（毫秒时间戳；产物里**只有这一种**形态） | 认不出是什么时间 |

两条规则值得单独写下来：

- **`source` 在索引侧再验一遍。** Worker 的投稿入口已经用 `coolapkSourceUrl()` 收口过（只认
  `coolapk.com` 及其子域的 http(s) 地址，裸域名补 `https://`），`scripts/build-index.mjs` 里的
  `coolapkSourceUrl()` 是**同一套判据的第二份实现**，改一侧必须同步改另一侧。理由：索引是公开
  产物，App 会把它渲染成一个可点的链接；上游只要漏一处校验，`javascript:` 之类的东西就在那里
  等着被点。`https://coolapk.com.evil.com/…` 与 `https://evil.com/?r=https://www.coolapk.com/…`
  都不算站内。
- **「字段缺失」是刻意的降级路径，不是数据没补全。** 老索引里没有这四格，新 App 就整块不显示
  出处区；反过来，老 App 按 `id` 取字段，多出来的键一律忽略。两边都不需要版本协商，也不需要
  为「老条目也要有出处」去回填 —— 回填等于替一条历史投稿挑一个出处，而它当时未必填过
  （真要补，得回 main 的历史提交里翻那枚 pending）。

`validate-index` **不校验**这四格：它们是可选的，缺了不算错；值域由 `build-index` 在写出去的
那一刻收口，别在两处维护第二份判据。

`submittedAt` 有**三种输入写法，产物里只有一种**：毫秒数字（`1700000000000`）、纯数字字符串
（`"1700000000000"`，按毫秒理解）、ISO 字符串（`"2026-10-23T00:00:00.000Z"` —— Worker 的
`buildPendingJson` 写的就是这一种）。三种都收，统一写成毫秒整数：为了一个时间戳逼消费方去猜
三四种格式，是那种「今天不出错、明年有人踩」的债。

### 作者主页（可选两字段）

`authorCoolapkUrl` / `authorGithubUrl` 是**上传者**替模块作者填的主页（契约 §2）。两格都可选，
没有就整个键不出现；有值就必须是**归一化后**的形状：

| 字段 | 类型 | 归一化后的形状 |
|---|---|---|
| `authorCoolapkUrl` | string | `https://www.coolapk.com/u/<4-12 位数字>` |
| `authorGithubUrl` | string | `https://github.com/<login>`（login 保留原始大小写） |

- **它只是一句声明，不是身份认证。** 界面必须标注「由上传者填写，未验证」。上传者自己的主页
  **不落库**：由 `coolapkUid` 派生成 `coolapk.com/u/<UID>`，索引里没有 `uploaderUrl` 这类键。
- **归一化在 `build-index` 里做，非法值整条拒收**（不是静默丢掉）：`http://` 升级成 https、
  裸域名补协议、尾斜杠折掉；其它 host、query、fragment、端口（含 `:443` 这类默认端口 ——
  解析器会把它们吃掉，所以判据在原始串上查一遍）、userinfo、多段路径、酷安
  `/u/` 后不是 4–12 位纯数字、GitHub 的 `www.github.com` / `.git` / 保留路径（`topics`、
  `settings` 等）一律判非法。判据在 `scripts/lib/author-links.mjs`，Worker 与网页侧是同一套
  语义（契约 §3），改一侧必须同步改另一侧。
- **合并时「带了就覆盖、没带就沿用」**：同 id 再投一版时，新条目没填这两格就保留索引里的旧值
  ——作者这一版没重填，不等于他要撤销那句声明。索引侧没有「删掉作者链接」这条路，真要撤
  得走一次人工改动。
- 老条目没有这两格是正常的：不回溯、不猜（契约 §5.5）。
- `validate-index` **会校验**这两格（与上面四格不同）：它们最终会被渲染成可点链接，形状不对
  的值只可能来自「绕过 `build-index` 手改索引」。

### json/columns.json（商店专栏）

`json/columns.json` 是 App 模块商店「专栏」的数据源，与 `modules.json` **同目录、同 baseUrl、同次发布**。
它不是模块索引，**不进 `build-index`**：专栏是人工维护的编排内容（哪些专题、按什么顺序、每一步装什么），
不存在「投稿→合并」的流水线。

结构（`schemaVersion: 1`）：

```
columns[]                    专栏
└── topics[]                 专题（一个专题 = 一套可验证的配置方案）
    ├── evidence             必填。没有证据的专题不允许上架
    ├── keybox               可选。keybox 直链登记：url / sha256 / lastVerifiedAt（没有可信来源就别写）
    ├── verifyHints[]        验收提示（人话，App 直接展示）
    └── steps[]              步骤（kind: installModule / writeConfig / writeFile / runCommand / verify / reboot / askUser）
        ├── source           upstream{repo, assetPattern, pinnedVersion, sha256} / store{moduleId} / askUser
        └── 可执行字段        command / filePath / fileContent / checkId / confirm
```

四条硬规则：

1. **每个 topic 必须有 `evidence`**（`verifiedAt` / `device` / `kernel` / `source` / `note`）。App 端按
   `verifiedAt` 算时效：≤90 天绿标、91–180 天黄标、>180 天灰标。缺证据的专题校验直接报错，不是警告。
2. **`source.kind = upstream` 记的是「我们锁定并核对过的上游版本」**，不是绿标 —— 上游模块不在本仓的
   来源／绿标体系里（见契约 §9.2）。`kind = askUser` 的步骤必须把「去哪拿」写进 `note`。
3. **步骤除了「说」还能「做」**：`runCommand` 必须有 `command`；`writeFile` / `writeConfig` 必须有
   绝对路径 `filePath` 与非空 `fileContent`（支持 `${keybox}` 占位符，由用户选中的本地文件替换）；
   `verify` 可选 `checkId`（九个自动检查项之一，见下表）；任何步骤都可带 `confirm`，App 执行前先弹
   二次确认。**没填可执行字段的步骤仍然只是展示 + 手动操作**，所以「不确定就退化 `askUser`」永远是
   安全的写法。
4. **`command` 与 `fileContent` 等同远程下发可执行内容，必须人工 review**：禁止通配删除、写块设备、
   `mkfs`、`reboot -f`、把根目录权限改成 777 —— 这几类已进校验器的危险命令黑名单，命中即报错。

步骤可执行字段（与 App 侧 `RepoColumnStep` / `RepoColumnKeybox` 一一对应）：

| 字段 | 适用 kind | 约束 | 说明 |
| --- | --- | --- | --- |
| `command` | `runCommand`（必填） | 非空字符串；多条命令用 `&&` 串联；命中危险命令黑名单即报错 | 由 root shell 原样执行 |
| `filePath` | `writeFile` / `writeConfig`（必填） | 必须以 `/` 开头；不许 `..`、通配符、根目录 `/`、以 `/` 结尾 | 目标文件绝对路径 |
| `fileContent` | `writeFile` / `writeConfig`（必填） | 非空字符串；支持 `${keybox}` 占位符 | 原样写入，不做换行／转义加工 |
| `checkId` | `verify`（可选） | 九选一：`root-manager` / `zygisk-next` / `denylist-policy` / `hma-config` / `target-list` / `keybox-valid` / `hybrid-mount` / `pathmask` / `adb-disabled` | 让 App 自动跑对应检查，省掉人工对照 |
| `confirm` | 任意 kind（可选） | 非空字符串 | 执行前的二次确认文案；空串等于没确认，校验会报错 |
| `keybox` | topic 级（可选） | `url` 必须 `https://`；`sha256` 64 位小写十六进制；`lastVerifiedAt` 真实 `yyyy-MM-dd`；可选 `providerNote` / `disclaimer` | 只在有可信直链 + 能校验时才登记；没有就别写这个字段 |

校验：

```bash
node scripts/validate-columns.mjs                # 校验 json/columns.json
node scripts/validate-columns.mjs path/to.json   # 校验指定文件
```

### json/proxies.json（下载代理）

`json/proxies.json` 是模块商店给 **GitHub Release 下载**用的代理前缀列表，与 `modules.json`、`columns.json`
**同目录、同发布路径**。App 从 CDN 拉取这一份：

```text
https://cdn.jsdelivr.net/gh/SukiSU-Community/modules-repo@main/json/proxies.json
```

拿到列表后，App 把代理前缀直接拼在 GitHub 原地址前面，形如
`https://gh-proxy.org/https://github.com/<owner>/<repo>/releases/download/...`；原地址本身一字不改，
代理只负责加速这一跳。所以列表必须能**远程更新** —— 代理今天能用不代表下周还能用，把列表编译进
App 就等于把「下载能不能成功」赌在某一家免费服务上。

结构（`schemaVersion: 1`）：

| 字段 | 类型 | 必填 | 约束 | 说明 |
| --- | --- | --- | --- | --- |
| `schemaVersion` | number | 是 | 必须等于 `1` | 结构版本，当前只认 `1` |
| `lastUpdate` | string | 是 | 真实日期 `yyyy-MM-dd` | 最后核实日期，也是「这版列表什么时候还有效」的线索 |
| `proxies` | array | 是 | 非空，≤ 32 条 | 按推荐顺序排列（实测快的在前） |
| `proxies[].id` | string | 是 | `^[a-z0-9][a-z0-9-]{1,31}$`，全局唯一 | 稳定标识，改地址时保持不变 |
| `proxies[].name` | string | 是 | 非空，≤ 40 字符 | 展示名，通常就是 host |
| `proxies[].baseUrl` | string | 是 | `https://` 开头、只有 host、全局唯一 | 拼接前缀，不能带 path / query / fragment / userinfo，只允许 443 端口 |
| `proxies[].note` | string | 否 | ≤ 60 字符 | 一句人话备注（实测速度、稳定性、节点位置） |

三条硬规则：

1. **只收 `https://` 且没有路径的地址**：App 做的是字符串拼接，`baseUrl` 后面直接跟 GitHub 原地址。
   多一个 `/path`、`?query`、`#fragment`、`user:pass@` 或非 443 端口，拼出来就不再是「代理 + 原地址」，
   而是一个谁都不认识的 URL。`http://` 一律不收 —— 下载的是可执行 zip，明文链路等于把「装什么」
   交给中间人。
2. **代理会失效，所以列表要能远程更新**：每次增删都改 `lastUpdate`，并让 jsDelivr 缓存失效（见
   「合并之后：CDN 必须失效」）。
   实测不通的 `ghfast.top`、`github.moeyy.xyz`、`gh.api.99988866.xyz` 和不支持 Range 请求的
   `gitproxy.click` 不收录；下次想加回来，先自己实测再改。
3. **App 只会把它当前缀**：形如 `https://gh-proxy.org/https://github.com/...`，GitHub 原地址保持不变。
   因此 `baseUrl` 只允许 scheme + host，不能以 `/` 结尾，也不能再包含第二段 `https://`。

校验：

```bash
node scripts/validate-proxies.mjs                # 校验 json/proxies.json
node scripts/validate-proxies.mjs path/to.json   # 校验指定文件
node scripts/validate-proxies.mjs --selftest     # 跑内置负例自测（不读文件）
```

### pending 条目格式

与上面的模块结构一致（可能多出 `source` / `uploader` / `coolapkUid` / `submittedAt` 这四格，
那是投稿入口写进去的原始数据；`build-index` 只负责校验与投影，不负责替谁补），额外多一枚**审核章**：

```json
{
  "audit": { "status": "auto-approved", "by": "ci:approve#<owner>/<repo>PR<n>@<headSha12>", "at": "…" },
  "id": "…",
  "versions": [ … ]
}
```

没有 `audit` 章、或章上没有 `by`（无主章）的条目，会被 `build-index` 跳过并计入「未通过」，
不进索引 —— 判据就是下一节那个 `isApproved()`，只有一份。`{ "approved": true }` 与
`{ "review": { "approved": true } }` 这两种旧后门**已删**，理由见下一节末尾。

## 审核标记契约（audit.yml / index.yml ↔ build-index.mjs）

**Workflow 写的、脚本认的，是同一个字段。** 这是两边的唯一约定面，改动必须同步：

| 常量 | 值 | 定义处 | 写入方 |
|---|---|---|---|
| `APPROVAL_FIELD` | `audit` | `scripts/build-index.mjs` | `scripts/publish-from-main.mjs`（经 `markApproved`） |
| `APPROVED_STATUS` | `auto-approved` | 同上 | 同上 |
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

两条路上盖的是两种章，`by` 的形状不一样，`isApproved()` 都只认非空 `by`：

```
ci:approve#<owner>/<repo>PR<n>@<headSha12>
ci:audit@<那一枚写下处置实体的 commit 的 40 位小写 sha>
```

前一枚回访的是**这次审核 run 在 head 上的 check**，后一枚回访的是**那条 commit 本身**：台账那条走的是
两枚提交（第一枚写实体与证据、`by` 填待盖值，第二枚只把待盖值换成第一枚的 sha），四条判据、
生产者在哪一步、这一枚章证明得了什么与证明不了什么：见 [GOVERNANCE.md](GOVERNANCE.md) 第 3 节。

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
投稿 PR ──audit（扫描+报告）──> approve（只在未命中上架拦截名单时成功；首投与更新同一套判据）
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

## 谁能发某个模块的新版本（归属）

首投合入之后，**该模块的版本更新只收首位成功投稿者**：服务端记着「哪个 moduleId 属于哪个
酷安 UID」，更新单出示的 UID 对不上就整单拒（全有全无，拒绝发生在任何 GitHub 写入之前）；
归属确认不出来时同样是拒，不是放行 —— 服务端故障在这一格等于「更新暂时投不进来」。
更新与首次收录走**同一套判据**（`audit/risk-rules.mjs` 的 `decide()`），不做跨版本差异比对。

归属记录的**权威副本**住在服务端，不进这个仓库 —— 索引是消费方可缓存的产物，会被镜像、被重建、
被老客户端长期拿着看，所以「谁能发某个模块的下一版」这格判据不能挂在它身上，得有一份服务端
说了算的记录。但有一点要直说：`GOVERNANCE.md` 第 6 节授权条目公开 出处 / 上传者昵称 /
上传者 UID / 提交时间 四格，条目里 moduleId 与 uid 同时出现，于是「谁投过哪些模块」这张清单
**随索引一起是公开的** —— 公开得与追责方向一致（第 3、4 节的章与公示页本来就按 uid 公开），
索引里那一格是权威记录的投影，不是判据来源。代价是这一格**没有给外人一条能自己跑一遍的复验
命令** —— 与第 3 节那枚钉在公开提交上的机器章不同。详见 `GOVERNANCE.md` 第 9 节。

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

> **注（2026-10-26）**：上面那条拒绝路径是当时的现场记录。标签与拒稿外观此后换过代 ——
> `block` 现在打 `auto-rejected`（不再打 `needs-human-review` / `blocked-auto-merge`）、在 PR 里
> 逐条列拒因、并自动关闭 PR；「转人工」那一态已从判据里删除，见 `GOVERNANCE.md` 第 2 节第 6 条。

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
`id` 与 `versionCode` 不重复、`sha256` 合法、`zipUrl` 为 http(s)；
可选字段 `repoUrl` / `repoDigest` / `repoCoversLatest` 与作者主页两格
（`authorCoolapkUrl` / `authorGithubUrl`）出现时必须是归一化后的形状。
退出码 0 通过，1 失败。建议接在 CI 和 pre-commit 上。

### 校验专栏

```bash
node scripts/validate-columns.mjs                # 校验 json/columns.json
node scripts/validate-columns.mjs path/to.json   # 校验指定文件
```

检查项：顶层 `schemaVersion/name/updatedAt`、每个专栏的 `id/title/subtitle/description/accent/icon/order`、
`accent` 与 `icon` 必须在白名单内（与 App 侧枚举一一对应）、每个专题必须有 `evidence` 且 `verifiedAt`
是真实日期、`riskLevel` / `layers` / 步骤 `kind` / `source.kind` 取值合法、`upstream` 步骤的
`repo` 必须是 `owner/repo` 形状且带 `assetPattern`、`store` 步骤必须带 `moduleId`、
`askUser` 步骤必须把获取方式写进 `note`。可执行字段另有几条硬检查：`runCommand` 必须有非空 `command`，
且不命中危险命令黑名单（通配删除根目录、`dd if=` 写设备、`mkfs`、写 `/dev/block`、`reboot -f`、
`chmod -R 777 /`）；`writeFile` / `writeConfig` 必须有绝对路径 `filePath`（不许 `..`、通配符、根目录）
与非空 `fileContent`；`checkId` 必须在九项白名单内且只允许出现在 `verify` 步骤；`confirm` 给了就不能
是空串；topic 级 `keybox` 的 `url` / `sha256` / `lastVerifiedAt` 形状不对直接报错。退出码 0 通过，1 失败。

### 校验代理列表

```bash
node scripts/validate-proxies.mjs                # 校验 json/proxies.json
node scripts/validate-proxies.mjs path/to.json   # 校验指定文件
node scripts/validate-proxies.mjs --selftest     # 跑内置负例自测（不读文件）
```

检查项：顶层 `schemaVersion` 必须是数字 `1`、`lastUpdate` 是真实存在的 `yyyy-MM-dd`；`proxies` 是非空数组且
≤ 32 条；每条 `id` 匹配 `^[a-z0-9][a-z0-9-]{1,31}$` 且全局唯一、`name` 非空且 ≤ 40 字符、可选 `note`
≤ 60 字符；`baseUrl` 必须 `https://` 开头且**只有 host**（无 path / query / fragment / userinfo / 非 443
端口），host 非空且不含空格，并按 host 全局唯一（大小写、显式 `:443` 算同一个）。错误信息带条目下标与
字段名（如 `proxies[1].baseUrl 只能有 host，不能带路径`），照着改即可。退出码 0 通过，1 失败。
`--selftest` 会验证 http 地址、带路径、重复 id、重复 baseUrl、坏日期、缺 `proxies`、非 443 端口七条负例
都能被挡住，适合改完校验器后先跑一遍。

### 跑单测

```bash
node --test              # 跑 test/ 下的全部单测
node --test test/build-index.test.mjs   # 只跑这一个文件
```

> 注意：`node --test test/`（带目录参数）在 Node 26 上会把 `test/` 当模块去解析而报错，
> 用不带参数的 `node --test` 或上面的显式文件路径。

覆盖 `build-index` 的三种核心情况：新增模块、追加版本、id 冲突不覆盖。另有 `verify-repos`、`auto-update`、`http-safe`、`zip`、`github-auto-pr` 几组测试：复验的故障语义（404 撤标 / 5xx 保留）、状态无变化时不动时间戳、两条发现路径与 pending 形状、SSRF/重定向/字节数上限、zip 解析与 `/auto/pr` 本地预检。这些测试全部离线，不联网。

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

## 自动更新（每日复验 + 自动发版）

`.github/workflows/auto-update.yml` 每天 03:30 UTC 跑一次（也可在 Actions 页面手动
`workflow_dispatch`），只执行 `scripts/auto-update.mjs`，一轮里做三件事：

1. **复验**：对索引里每个有 `repoUrl` 的模块跑 `scripts/verify-repos.mjs` 的
   `verifyReposCore()`（与独立 CLI 同一份实现）。仓库 404/私有 → 撤绿标（`repoVerified=false`）；
   GitHub 5xx / rate limit → **保留旧状态**（一次宕机不该撤任何人的标）；401/其它 4xx/网络错误
   → 整个 run 红，不产生半截状态。
2. **发现新版本**：`repoUrl && repoVerified` 的模块优先看仓库 Release（按 `created_at` 倒序，
   取第一个带 `.zip` 的），没有可用 Release 或版本没前进时回退到模块的 `updateJson`。
   两条路径都会下载 zip、解包根目录 `module.prop`，并复核：
   `id` 与索引一致、`versionCode` 严格大于索引当前最高、包内 `updateJson` 与索引**完全一致**
   （含从无到有/从有到无）。任一不符 → 拒绝该模块并写原因，绝不带上错误数据开 PR。
3. **提交**：zip 上传到本仓库的 `assets-v1` Release（asset 名是 `<sha256>.zip`，已存在则复用），
   然后**一次性** POST 到 Worker 的 `/auto/pr`，带上 `pending/<id>/<versionCode>.json` 与
   `json/repo-state.json`。上传失败或任何一步抛错，整个 run 红——不会只发一半。

一次最多提交 20 个模块（`/auto/pr` 单次最多 21 个文件，含状态文件）。

### 部署与密钥（都不写进仓库）

| 位置 | 名称 | 作用 |
|---|---|---|
| Worker secret | `AUTO_PR_KEY` | `wrangler secret put AUTO_PR_KEY`；`/auto/pr` 用它校验 `X-Auto-Key` |
| GitHub repo secret | `AUTO_PR_KEY` | 与上面**同值**；workflow 读它传给脚本 |
| GitHub repo variable | `WORKER_BASE` | Worker 根地址（`vars.WORKER_BASE`） |
| GitHub repo variable | `RELEASE_TAG`（可选） | 资产 Release 的 tag，默认 `assets-v1` |

还要先做两件事：

- 在仓库里建一个名为 `assets-v1` 的 Release（脚本只往上追加 asset，不负责创建 Release）；
- 确认 Actions 的 `GITHUB_TOKEN` 有 `contents: write`（workflow 里已经声明，仓库默认权限为只读时
  需要放开）。

> 定时任务只会在**默认分支**上生效；在特性分支上推 workflow 不会开始每日运行。
> `AUTO_PR_KEY` 只存在于 secrets 里，脚本从环境变量读取，不会打印、不会写进日志。

### 本地手动跑

```bash
# 只复验、只打印，不写文件也不开 PR（需要 GITHUB_TOKEN，公开仓库也建议带以免撞 rate limit）
node scripts/verify-repos.mjs --dry-run

# 复验并更新 json/repo-state.json，但不开 PR
node scripts/verify-repos.mjs --no-pr

# 完整发现 + 上传 + 开 PR；本地一般用 --dry-run 看会提交什么
node scripts/auto-update.mjs --dry-run
node scripts/auto-update.mjs --dry-run --summary /tmp/auto-update.md
```

`--dry-run` 会打印将要写入的 pending 路径与资产地址（与真跑一致），但不上传、不 POST。
本地跑 `auto-update.mjs` 还要 `GITHUB_TOKEN` 与 `GITHUB_REPOSITORY=owner/repo`（后者决定 zip
传到哪个仓库的 `assets-v1`）；`verify-repos.mjs` 同样要求 `GITHUB_TOKEN`（公开仓库不带也容易撞 rate limit）。
`json/repo-state.json` 由脚本维护，**不要手改**：结论没变时它连 `checkedAt` 都不动，
所以「没有变化」不会每天开一个只改时间戳的 PR。

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
     --by ci:audit@<这条台账 PR 上 C1 的 40 位 sha> \
     --note "<给人看的说明>" [--verify <任何人都能跑的复核命令>] [--dry-run] [--no-harvest]
```

`--by` 只能是机器章 `ci:audit@<40 位小写十六进制>`（或第一枚提交用的待盖值 `ci:audit@pending`）——
评论永久链接那个旧形状已经退场，理由见 GOVERNANCE 第 3 节：章要指向「哪一次运行把证据钉死了」，
而不是指向一条要人自己去查的评论。

**`--reason test-probe` 必须同时给 `--sha256`**：探针档复核的是「这一枚具体的包什么也不做」
（判据见 GOVERNANCE 3.1），只写 id 抹整个模块在这一档上没有可判的对象，写入端直接拒。

### 同一条命令还会固化证据（§8）

下处置的那一刻，`revoke.mjs` 顺手把**被处置的那一包当初审核过的东西**收进一个文件：

- 从 git 历史捞出 `pending/<id>/<versionCode>.json` 那一份 blob（合并时 `--consume` 把它从工作树删掉了，
  但历史里永远在）；
- 从承载它的 PR 评论里捞出扫描报告的呈现块（`audit.yml` 贴的那条，永久可回访）；
- 写成 `evidence/<sha256>.json` —— **文件名就是它自己字节的 SHA-256**，
  字节定义 `JSON.stringify(对象,null,2) + 一个换行`。于是同一份内容固化两次必然落回同一个名字，
  而「悄悄改掉一份已被人引用的证据」在结构上不可能不留痕迹：改名就是另一个文件，改内容就是撞名。

台账里那条记录同时被填上 `subject`（被处置人的 `coolapkUid` + 当时的昵称快照，公示页的人卡按它聚合）
和 `evidence[]`（指向那些文件）。这两个字段是 schema **v2** 新增的可选字段，所以：

- 捞不到证据时这条处置**照写**，只是不带这两个键 —— 写一个指向不存在文件的指针会被
  `verify-index-pr` 的互指认判红，等于把处置卡在 PR 外面。命令会打出一句怎么补跑。
- 想跳过这一步用 `--no-harvest`（离线跑、或者这个克隆没有投稿历史时用）。
- 证据文件与台账必须**同一条 PR**：`evidence/**` 只在「这条 PR 同时改了台账」时才算合法文件。

`--by` 的旧形状（评论永久链接、以及更早的 `gh:<login>@issuecomment-<id>`）都已退场，现在只收机器章
`ci:audit@<40 位小写十六进制>`：它指向「哪一次运行把这条下架决定的证据钉死了」，用
`gh api repos/<owner>/<repo>/commits/<sha>/check-runs` 就能复验。校验只加在**写入端**：让通用校验器
拒收旧记录 = 读不懂台账 = 推导停住 = 索引冻死，那条失效方向是设计好的。
名字不再进台账 —— 谁下的处置看那枚章，抄一份进台账就是引进一个会过期的字段。

### 探针包（`reason=test-probe`）

流水线自检会往真流水线上投几枚**几百字节、什么也不做**的包，用来验证「投稿 → 审核 → 合入 → 索引」
整条链路还通着。它们投稿时走的与任何用户投稿一模一样，所以事后清理也必须走同一枚章、同一条台账 PR。

这一档的复核判据与举报那条不同（`verify-report-evidence.mjs` 的 `judgeProbePackage`）：没有「指控引用的原文」
可核，改判「这枚包里**什么也不做**」—— 归档与解压总量有上限、每个条目必须是文本、
根上 `module.prop` 自报的 `id`/`versionCode` 必须与处置点名的一致、除 `module.prop` 外每条剥掉注释与空行后
只剩 `exit 0` / `exit` / `:` / `true`。详细四条与「挡的是什么」见 `GOVERNANCE.md` 3.1。

所以这一档必须点名产物：

```bash
node scripts/revoke.mjs --id <探针id> --version-code <n> --sha256 <64hex> \
     --kind revoke --reason test-probe --by ci:audit@pending \
     --note "流水线验证留下的探针包"
```

### 为什么「只改台账」的 PR 不算索引 PR（一个被这次改动顺手关掉的洞）

`audit.yml` 的 `kind` 步只看 `json/modules.json` 有没有变。**以前看的是整个 `json/`**，
于是删掉一条处置记录（把某人从黑名单里放出来）会被认成索引重建：它既不消费 pending，
也不改变当前索引，推导必然「一致」→ `merge-index` 自动合。削弱处置不该由推导说了算 ——
它今天走的是第三条：`kind` 步单独认出动了 `json/dispositions.json` 的 PR，导出 `ledger_pr=true`，
`derive` 那一步去核那条 PR 上的**机器章四条**（GOVERNANCE 第 3 节），四条全对才自动合，
少任何一条 `approve` 直接红。它既不吃「推导一致」这条绿灯，也不等人来点。

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
要把客户端那七天也压掉，三条路里选了**第 2 条并已落地**：

1. ~~订阅地址换成带 commit 的固定版本~~ —— 内容不可变、没有陈旧问题，但地址每次发版都变，
   破坏「一个固定订阅地址」这个前提；
2. **Worker 出镜像端点（已做）**：`GET /index.json` 与 `GET /dispositions.json` 原样透传源站，
   头由我们发 —— `cache-control: public, max-age=60` + 弱 ETag（客户端每分钟问一次，
   命中就 304 不带 body）。投稿站的 `INDEX_URL` 已换成这个地址，台账按同目录推导也落在同一个
   Worker 上，所以「一个固定订阅地址」的前提保住了。两个失败方向是刻意定的：
   **上游挂了绝不发 200 错误体**（MMRL 客户端会把 200 的 body 当索引进食，一个
   `{"error":...}` 能把用户的模块列表清空）—— 有旧副本就发旧副本并把 `x-mirror: stale(...)`、
   `max-age=5` 写在头上，一次都没成功过就 502，让客户端留着自己那份好的；
3. ~~接受它~~ —— 只剩一种情况还成立：**别人已经把这个仓库的 jsDelivr 地址抄进自己的配置里**。
   那条链上我们改不了头，只能靠上面那步 purge 把边缘清到分钟级，客户端那七天归他。

也就是说 purge 与镜像不是二选一：镜像管「我们发出去的订阅地址」，purge 管「别人手里那份
jsDelivr 地址」。

公示页在投稿站那边（`modules-web` 的 `#/incidents`），它显示的就是这份台账原文。

## 发布

仓库推到 GitHub 后开启 **Settings → Pages → Deploy from branch（选默认分支的根目录）**，
索引地址形如：

```
https://<owner>.github.io/<repo>/json/modules.json
```

因为是根目录部署、`json/` 就在根下，这个 URL 从第一次部署起就是 200。
改完索引后务必先跑 `validate-index`，再提交。
