// zip.mjs 的容器解析与 module.prop 读取测试（离线，包体由 test/zip-builder.mjs 现场生成）。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { readZipEntry, parseModuleProp, inspectModuleZip, MAX_ENTRY_BYTES } from '../scripts/lib/zip.mjs';
import { makeZip, makeModuleZip } from './zip-builder.mjs';

test('读取 deflate 压缩的 module.prop', () => {
  const zip = makeModuleZip({ id: 'demo', version: '1.2.3', versionCode: '7' });
  const raw = readZipEntry(zip, 'module.prop');
  assert.ok(raw);
  assert.match(raw.toString('utf8'), /id=demo/);
});

test('读取 stored（未压缩）的 module.prop', () => {
  const zip = makeZip([{ name: 'module.prop', data: 'id=demo\nversionCode=1\n', method: 0 }]);
  const raw = readZipEntry(zip, 'module.prop');
  assert.match(raw.toString('utf8'), /versionCode=1/);
});

test('只认根目录的 module.prop：子目录同名文件不算', () => {
  const zip = makeZip([{ name: 'sub/module.prop', data: 'id=x\n' }]);
  assert.equal(readZipEntry(zip, 'module.prop'), null);
  const inspected = inspectModuleZip(zip);
  assert.equal(inspected.ok, false);
  assert.match(inspected.error, /根目录没有 module.prop/);
});

test('module.prop 解析：去注释、去空白、重复键最后生效', () => {
  const prop = parseModuleProp([
    '# 注释',
    'id = demo ',
    '',
    'version=v1',
    'version=v2',
    'noeq',
  ].join('\n'));
  assert.deepEqual(prop, { id: 'demo', version: 'v2' });
});

test('inspectModuleZip：缺 id / 缺 versionCode 时如实报错', () => {
  const noId = inspectModuleZip(makeModuleZip({ version: '1' }));
  assert.equal(noId.ok, false);
  assert.match(noId.error, /没有 id/);

  const ok = inspectModuleZip(makeModuleZip({ id: 'demo', version: '1', versionCode: '3' }));
  assert.equal(ok.ok, true);
  assert.equal(ok.prop.id, 'demo');
  assert.equal(ok.prop.versionCode, '3');
});

test('坏 zip 被当成错误，而不是空内容', () => {
  assert.throws(() => readZipEntry(Buffer.from('not a zip at all'), 'module.prop'), /不是合法的 zip/);
  const inspected = inspectModuleZip(Buffer.from('not a zip at all'));
  assert.equal(inspected.ok, false);
});

test('解压后超过上限的条目被拒', () => {
  const zip = makeZip([{ name: 'module.prop', data: 'x'.repeat(MAX_ENTRY_BYTES + 1) }]);
  assert.throws(() => readZipEntry(zip, 'module.prop'), /超过/);
});

test('zip64 标记直接报错（模块包不该这么大）', () => {
  const zip = makeModuleZip({ id: 'demo' });
  // 把 EOCD 里的「中央目录偏移」改成 0xffffffff，模拟 zip64。
  const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  zip.writeUInt32LE(0xffffffff, eocd + 16);
  assert.throws(() => readZipEntry(zip, 'module.prop'), /zip64/);
});
