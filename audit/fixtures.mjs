// 审核侧共享夹具（fixtures）—— 只负责「造一个像真实模块的 zip」和「拿一份扫描报告」，
// 不含任何判定逻辑：判定一律走 scan.mjs，夹具不能反过来替规则说话。
//
// 零依赖：只用 node 内置模块，stored（method 0）打包，条目名大小写原样保留 ——
// 引用解析要求「条目名精确匹配 + 大小写原样」，夹具要是偷偷规范化了名字，测试就测不到真东西。
//
// 命名坑（评审 F3）：scan.test.mjs 里已经有一个 buildZip(entries)，形状与本文件的内部构造器
// 不同（对象数组 vs 数组的数组）。所以这里不导出 buildZip，导出的构造入口叫 makeModuleZip，
// 免得两份形状在同一个测试文件里被 import 遮蔽。
//
// 签名坑（评审 F15）：scanToReport 必须带 opts。resolveChangeType 在没有 opts.changeType
// 也没有 opts.index 时返回 'unknown'，而 decide('low','unknown') 是 request-review ——
// 不带 opts 的干净模块永远拿不到 auto-approve，回归表那条「干净模块必须仍可自动放行」的
// 哨兵在这个签名下根本不可达。所以契约是 scanToReport(zip, opts = {})，
// 回归表用 { changeType: 'first' } 作为显式声明通道。

import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32 } from 'node:zlib';

import { scanZip } from './scan.mjs';

const SIG_LOC = 0x04034b50;
const SIG_CEN = 0x02014b50;
const SIG_EOCD = 0x06054b50;

function crc32buf(buf) {
  // node:zlib 的 crc32 在较新版本提供；zip 读取器不校验 CRC，取不到时兜 0。
  try { return crc32(buf); } catch { return 0; }
}

/**
 * stored zip 构造器（内部用，不导出）。
 * @param {Array<[string, string|Buffer]>} files 条目名 + 内容
 * @returns {Buffer}
 */
function storedZipBuffer(files) {
  const locals = [];
  const central = [];
  let offset = 0;
  for (const [name, body] of files) {
    const nameBuf = Buffer.from(String(name), 'utf8');
    const dataBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body == null ? '' : body), 'utf8');
    const crc = crc32buf(dataBuf);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(SIG_LOC, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(0, 8);            // method 0 = stored
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(dataBuf.length, 18);
    lh.writeUInt32LE(dataBuf.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, dataBuf);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(SIG_CEN, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(0, 10);           // method 0 = stored
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(dataBuf.length, 20);
    ch.writeUInt32LE(dataBuf.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf);

    offset += 30 + nameBuf.length + dataBuf.length;
  }
  const cdBuf = Buffer.concat(central);
  const bodyBuf = Buffer.concat(locals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(SIG_EOCD, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(bodyBuf.length, 16);
  return Buffer.concat([bodyBuf, cdBuf, eocd]);
}

/** 一份字段齐全的干净 module.prop：夹具不该顺手制造元数据告警。 */
export function moduleProp(id) {
  return `id=${id}\nname=${id}\ndescription=fixture module\nversion=v1.0\nversionCode=1\nauthor=fixture\n`;
}

/**
 * 造一个模块 zip 并写到临时目录，返回 zip 路径（scanZip 只吃路径）。
 * @param {{ id: string, files: Array<[string, string|Buffer]> }} opts
 * @returns {string} zip 路径
 */
export function makeModuleZip({ id, files = [] }) {
  const hasProp = files.some(([name]) => String(name) === 'module.prop');
  const entries = hasProp ? files : [['module.prop', moduleProp(id)], ...files];
  const dir = mkdtempSync(join(tmpdir(), 'modfixture-'));
  const p = join(dir, `${id}.zip`);
  writeFileSync(p, storedZipBuffer(entries));
  return p;
}

/**
 * 对 makeModuleZip 产出的包跑一次真扫描，返回报告对象。
 * @param {string} zip makeModuleZip 返回的 zip 路径
 * @param {{ declaredId?: string, declaredVersion?: string,
 *           changeType?: 'first'|'update', index?: object, maxEntryBytes?: number }} [opts]
 * @returns {Promise<object>} scanZip 的报告
 */
export async function scanToReport(zip, opts = {}) {
  return scanZip(zip, opts);
}
