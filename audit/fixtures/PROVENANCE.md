# 这些 ELF 为什么在仓库里，以及它们各自的出处

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
