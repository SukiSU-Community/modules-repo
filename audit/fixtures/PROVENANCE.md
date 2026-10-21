# 这些二进制为什么在仓库里，以及它们各自的出处

**一句话**：`elf-forensics.mjs` 的解析表（字段偏移、`Elf32_Sym=16 B`、`Elf32_Dyn=8 B`、
`e_shstrndx` 是 2 字节下标）不能靠自造的字节证明自己对 —— 本目录那两枚历史 bug
（`e_shstrndx` 被当成 8 字节**偏移**读、`d_tag` 按 number 而不是 BigInt 比）都只在**真 `lld` 产出的布局**上才暴露，
而自造最小 ELF 恰好测不到（那两个坑正是量真文件量出来的）。所以这里放的是**公开模块里原样取出的真 ELF**。

逐枚事实（字节数、sha256、机种、`DT_NEEDED` 全部由 `audit/elf-forensics.mjs` 现读现算，命令在文末）：

| 文件 | 来自（发布号 + 包内路径） | 字节 | sha256 | 机种 / 类型 / 导入数 | 许可证 |
| --- | --- | --- | --- | --- | --- |
| `arm64-v8a.so` | `Seyud/device_faker_release` **v1.6.0** 的包内 `zygisk/arm64-v8a.so` | 983,624 | `273fb76f…1f5a4e28` | AArch64 / DYN / 86 | **GPL-3.0**（源码仓 `Seyud/device_faker` 同为 GPL-3.0） |
| `device_faker_cli` | 同一发，包内 `bin/device_faker_cli` | 485,944 | `f73027f5…c0410ae1` | AArch64 / DYN / 70 | **GPL-3.0**（同上） |
| `detach-arm32` | `j-hc/zygisk-detach` **v1.24.0** 的包内 `bin/arm/detach` —— 它是这个模块的 **CLI 二进制**（Rust，静态链进 `bstr` 与 std 的 `src/*.rs` panic 位置），**不是** `zygisk/armeabi-v7a.so`（那一枚只有 6,736 B） | 118,380 | `cb82b3a8…7d0d1785` | ARM / DYN / 62 | **Apache-2.0** |
| `hma-arm64.so` | `frknkrc44/HMA-OSS` **oss-173** 的包内 `zygisk/arm64-v8a.so` | 13,480 | `dfa7bd47…f192d7c1` | AArch64 / DYN / 24 | **AGPL-3.0** |
| `hma-armeabi-v7a.so` | 同一发，包内 `zygisk/armeabi-v7a.so` | 9,232 | `7d7b4bdb…cd82de21` | ARM / DYN / 25 | **AGPL-3.0** |
| `hma-x86.so` | 同一发，包内 `zygisk/x86.so` | 13,456 | `e66239e4…c2b422df` | x86 / DYN / 24 | **AGPL-3.0** |

## 出处与许可证现在是怎么核上的（2026-10-17，全部现跑，不是回忆）

**六枚都逐字节对上了上游发布资产里的一个条目** —— 这一格从「未核对」变成「核对过」靠的是重新下载那三发 zip
并按 sha256 全比对，不是去读一眼上游 README：

| 上游那一发 | 资产大小 | 比对结果 |
| --- | --- | --- |
| `…/Seyud/device_faker_release/releases/download/v1.6.0/device_faker_v1.6.0.zip` | 969,705 B | 57 个条目里命中 2：`zygisk/arm64-v8a.so`、`bin/device_faker_cli`，各自 sha256 与本目录那两枚**完全相同** |
| `…/j-hc/zygisk-detach/releases/download/v1.24.0/zygisk-detach-v1.24.0.zip` | 371,409 B | 命中 1：`bin/arm/detach`（**唯一**一个 118,380 B 的条目，sha256 相同）；`zygisk/armeabi-v7a.so` 只有 6,736 B，另核过 v1.20.1 / v1.20.0 两发也都不是（5,972 B） |
| `…/frknkrc44/HMA-OSS/releases/download/oss-173/HMA-OSS-ZYGISK-oss-173-release.zip` | 2,743,824 B | 命中 3：`zygisk/arm64-v8a.so` / `armeabi-v7a.so` / `x86.so`，三枚 sha256 全相同 |

`detach-arm32` 那一枚为什么差点被当成来路不明：先按名字去比 `zygisk/*.so` 三发发布，全部不命中且尺寸差一个数量级；
转机是把文件里的可打印串捞出来，看到 `Accepted commands are: 'detach', 'detachall', 'reset', 'list', 'serialize'`
与 `Could not list detached pkgs:`，再拿这句话做一次 GitHub code search ⇒ 命中 `j-hc/zygisk-detach` 的
`cli/src/main.rs` ⇒ 它是该模块的 CLI，于是去整包（不再只挑 `.so`）按 sha256 全比对，一次命中。
⇒ **教训：别按文件名的直觉去猜出处；把二进制里的串捞出来搜一次，比按名字猜便宜且不会错。**

许可证那一栏的读法（`license.spdx_id`，2026-10-17 由 `gh api repos/<name>` 现读）：
`Seyud/device_faker_release` = GPL-3.0、`Seyud/device_faker` = GPL-3.0、`j-hc/zygisk-detach` = Apache-2.0、
`frknkrc44/HMA-OSS` = AGPL-3.0。⚠️ **边界要说清**：
① 这三个是**仓库级声明**，不是逐文件的授权声明 —— 上游若对个别文件另有说明，这里没读到；
② 这是**许可条款的搬运与署名义务**问题，不是法律意见；
③ GPL/AGPL 的「给二进制就得给得出源码」在本目录的形状是：源码就在上表那些**公开仓库**里，
   所以出处 URL 必须留着（抹掉 URL 才是真的把义务甩掉）；Apache-2.0 要求保留版权与许可声明。
⇒ 本目录**只读不执行**、不改写、不重新发布这些模块本身，且在表里逐枚点名来源与许可 —— 这三件事一起才构成
「公开可下载」之外的**可再分发**依据。

## 纪律（改这里的东西必须连带做什么）

1. **换/删任何一枚，`elf-forensics.test.mjs` 的锚点用例（逐枚钉 `bytes`/`machineName`/`importCount`/
   `needed`/`sensitiveImports`/`stringTotal` 的那几条）与 `scan.test.mjs` 的 `S3A-05`/`T57-10`/`T57-11` 必须跟着重算，
   且**期望值要来自重新读字节，不许凭记忆改**。锚点是给人复核用的，改错一次就永久失去那一条保护。
2. **不许往这里放任何来自投稿（用户提交）的样本** —— 这里的每一枚都必须是**主动从公开分发渠道取的测试数据**，
   并且只读不执行：整条审计线从不运行包内任何脚本（见 `elf-forensics.mjs` 文件头那三条硬约束）。
3. **新增/替换一枚的验收形状**（这次用的就是它，别只写「来自某仓」）：
   下载上游发布资产 → 解包 → **对每个条目按 sha256 与本目录那枚比** → 命中唯一一条才算出处成立；
   再 `gh api repos/<名>` 读 `license.spdx_id` 填许可证栏。两步都要把命令与读数写进上面那张表。
4. 重算命令（在 `repo/` 下）：
   ```sh
   node -e "const fs=require('fs');import('./audit/elf-forensics.mjs').then(({forensics})=>{
     for(const f of fs.readdirSync('audit/fixtures')){ if(f==='PROVENANCE.md')continue;
       const b=fs.readFileSync('audit/fixtures/'+f); const r=forensics(b,f);
       console.log(f, b.length, r.machineName, r.type, r.importCount, (r.needed||[]).join(','),
         require('crypto').createHash('sha256').update(b).digest('hex')); }});"
   ```

## 第五十批新增：`d8-minimal.dex` —— 第二种出处形状（自建，不是从公开渠道取的）

| 文件 | 来自 | 字节 | sha256 | 读数（`dex-forensics` 现读） | 许可证 |
| --- | --- | --- | --- | --- | --- |
| `d8-minimal.dex` | **本批自写的一个 Java 类**，`javac 17.0.15` + `d8`（Android build-tools **34.0.0**，`--release --min-api 21`）编出来的一枚真 `classes.dex` | 1,460 | `26331cedb7a2c8bce9afee6e012823e130f46b12ab7949638ffd66570251080d` | v`035` / string_ids **33**（33 解出、0 失败、0 半截） / type 9 / method 7 / class_defs 1 / `file_size` 与实际字节数一致 | 无第三方代码（那 15 行 Java 是本批写的，内容只有字符串常量与 `System.loadLibrary` / `Runtime.exec` 两个调用） |

**为什么这一枚不走上面那条「下载公开资产 → 逐条目比 sha256」的验收形状**：它不需要那个证人，因为它证明的不是
"现实里有这么一枚文件"，而是**"d8 那台编码器怎么摆 string_ids、uleb128 和常量池"** —— 格式保真度由工具保证，
出处由命令保证（上面那行就是全部命令，任何人可重跑）。而真包里的 dex 一枚都进不了仓：它们属于第三方 App
（许可证不明），尺寸也远超本目录的档位 —— 钉 tag 之后可复现的三枚是 HMA-OSS `oss-173` 的 `classes.dex`
**889,000 B**、同包 `manager.apk`（3,738,376 B）里那枚 **2,431,400 B**、以及 LSPosed Manager 的
`classes.dex` **7,099,112 B**（v038）。
> 出处更正（2026-10-21）：本节原先写的是「那 12 条 `classes*.dex` 最大一枚 8,602,872 B」，那是 2026-10-13
> 走 `latest` 下的包，**在钉 tag 之后的语料里复现不出来**（同一枚 HMA-OSS 在 `oss-173` 上只有一条 889,000 B 的
> dex 与一枚 3,738,376 B 的 apk）。结论不受影响（第三方 dex 仍然既没 licence 又太大），但依据只许留复现得出的数。

**它测不到什么**（别让下一轮以为 dex 层已经被"真包"验过）：

1. **混淆过的类名形状**。d8 `--release` 不做改名，所以这枚池子里的类名是 `Lcom/probe/dexfix/Probe;` 这种自白的名字。
   可复现的那枚真 dex（LSPosed Manager，23,213 条串）里 23,054 条纯可打印、**10 条含裸 U+0000**、
   最长一条 60,000 字符 —— 那种形状只有真包能测，而它没进仓。计划 §0.7 那句「前 40 条是 `A0`…`A00aOo`」
   记的是上面更正里那枚复现不出来的包，**别拿它的形状当基准**。
2. **大池的预算那一格**。33 条串离 `DEX_SURFACE_MAX_BYTES`（1 MiB）差四个数量级，所以"超预算丢尾"这一格
   靠的是 `scan.test.mjs` 的 DXE-06 合成池（300 条 × 4,300 字符），不是这枚夹具。
3. **非 d8 编码器**（r8 全模式、旧版 dx、手工重打包的 dex）产的形状差异没测过。第 1、3 条都撞在同一件事上：
   这一层的**放宽方向**判据只有 ELF 链接期那一份，所以这些没测到的形状最坏落到"读不出来"那一格，
   不会落到"读出来但念成干净"。

**它为什么值得进仓**（对比一下：手搓一枚假 dex 也照样能跑解析器）：`dex-forensics.test.mjs` 的畸形路径全部由
合成器覆盖（那里能精确造大端、越界表项、半截串），但**"读得出来"那一面必须有一次是真编码器说的**。
DX-01 的 33/9/7/1 与 DX-02 那五条字面值锚点就是从真 d8 字节上量的 —— 特别是那三条执行型串（`rm -rf`、
`base64 -d`、`cp /data/system/…`）：它们是 `dexSurfaceSeverity` 那条降档判据的**来源**，
如果换成手搓串，降档那条闸就变成"我自己造的串我自己判"，实测性归零。

