# 这些 ELF 为什么在仓库里，以及它们各自的出处

**一句话**：`elf-forensics.mjs` 的解析表（字段偏移、`Elf32_Sym=16 B`、`Elf32_Dyn=8 B`、
`e_shstrndx` 是 2 字节下标）不能靠自造的字节证明自己对 —— 本目录那两枚历史 bug
（`e_shstrndx` 被当成 8 字节**偏移**读、`d_tag` 按 number 而不是 BigInt 比）都只在**真 `lld` 产出的布局**上才暴露，
而自造最小 ELF 恰好测不到（那两个坑正是量真文件量出来的）。所以这里放的是**公开模块里原样取出的真 ELF**。

逐枚事实（字节数、sha256、机种、`DT_NEEDED` 全部由 `audit/elf-forensics.mjs` 现读现算，命令在文末）：

| 文件 | 来自 | 字节 | sha256 | 机种 / 类型 / 导入数 | 许可证 |
| --- | --- | --- | --- | --- | --- |
| `arm64-v8a.so` | `device_faker v1.6.0`，包内 `zygisk/arm64-v8a.so` | 983,624 | `273fb76f…1f5a4e28` | AArch64 / DYN / 86 | **未核对** |
| `device_faker_cli` | 同上，包内 `bin/device_faker_cli` | 485,944 | `f73027f5…c0410ae1` | AArch64 / DYN / 70 | **未核对** |
| `detach-arm32` | `zygisk-detach`，**arm32 构建**（仓外那份 `zygisk/arm64-v8a.so` 是 23 导入，仓库里这枚是 arm32 的 62 —— §0.26 订正过） | 118,380 | `cb82b3a8…7d0d1785` | ARM / DYN / 62 | **未核对** |
| `hma-arm64.so` | `HMA-OSS`，包内 `zygisk/arm64-v8a.so` | 13,480 | `dfa7bd47…f192d7c1` | AArch64 / DYN / 24 | **未核对** |
| `hma-armeabi-v7a.so` | 同上，`zygisk/armeabi-v7a.so` | 9,232 | `7d7b4bdb…cd82de21` | ARM / DYN / 25 | **未核对** |
| `hma-x86.so` | 同上，`zygisk/x86.so` | 13,456 | `e66239e4…c2b422df` | x86 / DYN / 24 | **未核对** |

## 出处里哪些是核过的、哪些不是（别把这张表当合规证明）

- **核过**：`device_faker v1.6.0` 的下载源在计划 §0.5 里有原样命令
  （`https://github.com/Seyud/device_faker_release/releases/download/v1.6.0/device_faker_v1.6.0.zip`，947 KiB zip），
  上面两枚就是从那一发 zip 里**逐字节取出**的。六枚的字节数与 sha256 是刚才现算的。
- **没核过，两件事各自独立**：
  ① `zygisk-detach` 与 `HMA-OSS` 这两轮的**版本号与源仓库地址**当时没记进计划（只记了包内路径），
  所以上表那三行「来自」只能写到模块名，写不到版本；
  ② **六枚的许可证一个都没核对过**。这不代表它们不能进仓 —— 它们来自公开分发的模块包，
  但「公开可下载」不等于「可以再分发」。⇒ **这一栏是欠着的债，登记在这里而不是抹掉。**
  补齐的动作很具体：取到上游 repo 后读它的 `LICENSE`（或 GitHub API 的 `license.spdx_id`），逐枚填进最后一栏；
  填不上的那一枚就从夹具表里换掉（换成同形状的自造 ELF，并接受它测不到真 `lld` 布局的代价）。

## 纪律（改这里的东西必须连带做什么）

1. **换/删任何一枚，`elf-forensics.test.mjs` 的锚点用例（逐枚钉 `bytes`/`machineName`/`importCount`/
   `needed`/`sensitiveImports`/`stringTotal` 的那几条）与 `scan.test.mjs` 的 `S3A-05`/`T57-10`/`T57-11` 必须跟着重算，
   且**期望值要来自重新读字节，不许凭记忆改**。锚点是给人复核用的，改错一次就永久失去那一条保护。
2. **不许往这里放任何来自投稿（用户提交）的样本** —— 这里的每一枚都必须是**主动从公开分发渠道取的测试数据**，
   并且只读不执行：整条审计线从不运行包内任何脚本（见 `elf-forensics.mjs` 文件头那三条硬约束）。
3. 重算命令（在 `repo/` 下）：
   ```sh
   node -e "const fs=require('fs');import('./audit/elf-forensics.mjs').then(({forensics})=>{
     for(const f of fs.readdirSync('audit/fixtures')){ if(f==='PROVENANCE.md')continue;
       const b=fs.readFileSync('audit/fixtures/'+f); const r=forensics(b,f);
       console.log(f, b.length, r.machineName, r.type, r.importCount, (r.needed||[]).join(','),
         require('crypto').createHash('sha256').update(b).digest('hex')); }});"
   ```
