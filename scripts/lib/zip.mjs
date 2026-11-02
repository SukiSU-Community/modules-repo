/**
 * zip.mjs
 *
 * 从模块 zip 里读根目录的 `module.prop` —— 自动更新只信「真的下载下来的那个包」里写的
 * id/versionCode/updateJson，不信 release 标题或 updateJson 里的自称。
 *
 * 为什么自己解析 zip 而不解压整个包：`node:zlib` 只给 inflate，没有 zip 容器解析；而自动
 * 更新要读的只有一个小文本文件。实现只做这一件事：定位中央目录里名为 `module.prop` 的
 * 条目，按压缩方式（stored / deflate）解出来，其余条目一个都不碰。这样既不执行任何东西，
 * 也不会因为包里有几万个文件而把内存吃掉。
 *
 * 只用 node: 内置模块（本仓库硬性约束）。
 */

import zlib from 'node:zlib';

/** 单个条目解压后的上限：module.prop 正常只有几百字节，1MiB 已经非常宽松。 */
export const MAX_ENTRY_BYTES = 1024 * 1024;

const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const ZIP64_MARKER = 0xffffffff;

/**
 * 从 zip buffer 里取出一个条目的内容。
 *
 * @returns {Buffer|null} 找不到返回 null；包结构坏掉时抛 Error（调用方据此拒绝这个模块）。
 */
export function readZipEntry(buffer, wantedName) {
  if (!Buffer.isBuffer(buffer)) throw new Error('不是合法的 zip：输入不是 Buffer');
  // 最小合法 zip 是 22 字节的 EOCD；比这短的不可能是 zip，直接说清楚而不是返回 null。
  if (buffer.length < 22) throw new Error('不是合法的 zip：文件太小');

  // 中央目录结尾（EOCD）在文件尾部，最多后面跟 64KiB 注释，所以从后往前找签名。
  let eocd = -1;
  const stop = Math.max(0, buffer.length - 22 - 0xffff);
  for (let i = buffer.length - 22; i >= stop; i -= 1) {
    if (buffer.readUInt32LE(i) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('不是合法的 zip：找不到中央目录结尾');

  const entryCount = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  if (centralOffset === ZIP64_MARKER || centralSize === ZIP64_MARKER) {
    throw new Error('不支持 zip64（模块包不会这么大）');
  }
  if (centralOffset + centralSize > buffer.length) throw new Error('zip 中央目录越界');

  let ptr = centralOffset;
  for (let i = 0; i < entryCount; i += 1) {
    if (ptr + 46 > buffer.length || buffer.readUInt32LE(ptr) !== SIG_CENTRAL) {
      throw new Error('zip 中央目录条目损坏');
    }
    const method = buffer.readUInt16LE(ptr + 10);
    const compressedSize = buffer.readUInt32LE(ptr + 20);
    const uncompressedSize = buffer.readUInt32LE(ptr + 24);
    const nameLen = buffer.readUInt16LE(ptr + 28);
    const extraLen = buffer.readUInt16LE(ptr + 30);
    const commentLen = buffer.readUInt16LE(ptr + 32);
    const localOffset = buffer.readUInt32LE(ptr + 42);
    if (ptr + 46 + nameLen > buffer.length) throw new Error('zip 条目名越界');
    const name = buffer.toString('utf8', ptr + 46, ptr + 46 + nameLen);
    ptr += 46 + nameLen + extraLen + commentLen;

    if (name !== wantedName) continue;

    if (compressedSize === ZIP64_MARKER || uncompressedSize === ZIP64_MARKER) {
      throw new Error('不支持 zip64 条目');
    }
    if (uncompressedSize > MAX_ENTRY_BYTES) {
      throw new Error(`${wantedName} 解压后超过 ${MAX_ENTRY_BYTES} 字节`);
    }
    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== SIG_LOCAL) {
      throw new Error(`zip 本地文件头损坏：${wantedName}`);
    }
    const localNameLen = buffer.readUInt16LE(localOffset + 26);
    const localExtraLen = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > buffer.length) throw new Error(`zip 条目数据越界：${wantedName}`);
    const raw = buffer.subarray(dataStart, dataEnd);

    if (method === 0) return Buffer.from(raw); // stored
    if (method === 8) {
      try {
        return zlib.inflateRawSync(raw, { maxOutputLength: MAX_ENTRY_BYTES });
      } catch (err) {
        throw new Error(`${wantedName} 解压失败：${err && err.message ? err.message : err}`);
      }
    }
    throw new Error(`${wantedName} 使用了不支持的压缩方式（method=${method}）`);
  }
  return null;
}

/**
 * 解析 module.prop（`key=value` 每行一条，# 开头是注释）。
 *
 * 重复键取**最后一个**：真实 module.prop 里重复键极少，而「最后一行生效」与 shell 里
 * `source` 的语义一致，比「第一个生效」更不容易让作者写出「看起来改了其实没改」的包。
 */
export function parseModuleProp(text) {
  const out = {};
  for (const rawLine of String(text || '').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    if (!key) continue;
    out[key] = line.slice(eq + 1).trim();
  }
  return out;
}

/**
 * 检查一个模块 zip：根目录必须正好有 `module.prop`，且能解析出 id / versionCode。
 *
 * @returns {{ok:true, prop:object, text:string}|{ok:false, error:string}}
 */
export function inspectModuleZip(buffer) {
  let text;
  try {
    const raw = readZipEntry(buffer, 'module.prop');
    if (raw === null) return { ok: false, error: '包根目录没有 module.prop' };
    text = raw.toString('utf8');
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : String(err) };
  }
  const prop = parseModuleProp(text);
  if (!prop.id) return { ok: false, error: 'module.prop 里没有 id' };
  return { ok: true, prop, text };
}
