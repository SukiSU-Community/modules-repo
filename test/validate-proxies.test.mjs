/**
 * validate-proxies.mjs 的单测 —— 代理清单是 App 直接拿去拼 URL 的数据。
 *
 * 锁四件事：
 *   1. 仓库里真实的 json/proxies.json 能过（否则 CI 红得有道理）；
 *   2. 规则**只能比 App 更严不能更松**：App（ProxyUrl.isValidBaseUrl）会静默丢弃的形状，
 *      这里必须先报错，否则「保存成功、用户端少一条」，没人查得出来；
 *   3. 规范化形状（尾斜杠、大写 scheme）仍然拒 —— App 宽容，但索引只收一种写法；
 *   4. CLI 退出码：坏文件必须 1，因为 CI step 只看退出码。
 *
 * 运行：node --test test/validate-proxies.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  checkBaseUrl,
  checkHostname,
  validateProxies,
  validateProxiesFile,
  runSelfTest,
  MAX_BASE_URL_CHARS,
  REPO_ROOT,
} from '../scripts/validate-proxies.mjs';

const SCRIPT = path.join(REPO_ROOT, 'scripts', 'validate-proxies.mjs');

/** 一份最小合法文档，负例只改需要坏掉的那一处。 */
function doc(overrides = {}) {
  return {
    schemaVersion: 1,
    lastUpdate: '2026-11-04',
    proxies: [{ id: 'gh-proxy-org', name: 'gh-proxy.org', baseUrl: 'https://gh-proxy.org' }],
    ...overrides,
  };
}

const errorsOf = (overrides) => validateProxies(doc(overrides)).errors.join('\n');

// ── 真实数据 ────────────────────────────────────────────────────────────────

test('真实 json/proxies.json 通过校验', () => {
  const result = validateProxiesFile();
  assert.ok(result.ok, `真实数据不该报错：\n${result.errors.join('\n')}`);
  assert.ok(result.proxyCount >= 1);
});

// ── checkBaseUrl：能收的形状 ────────────────────────────────────────────────

test('checkBaseUrl：裸 host、显式 :443、punycode、IPv4 都收', () => {
  for (const ok of [
    'https://gh-proxy.org',
    'https://hk.gh-proxy.com',
    'https://gh-proxy.org:443', // URL 会把默认端口归一掉，与 App 的 port==443 同口径
    'https://xn--r8jz45g.jp', // IDN 的合法写法是 punycode，App 也认
    'https://1.2.3.4',
    'https://localhost',
  ]) {
    assert.equal(checkBaseUrl(ok), null, `${ok} 应通过，实际：${checkBaseUrl(ok)}`);
  }
});

test(`checkBaseUrl：恰好 ${MAX_BASE_URL_CHARS} 字符能过，多 1 个字符就拒`, () => {
  // host 必须是多段合法域名：单段 120 字符会先被「单段 ≤ 63」挡住，测不到长度边界。
  const host = `${'a'.repeat(60)}.${'b'.repeat(59)}`; // 120 字符
  const exact = `https://${host}`;
  assert.equal(exact.length, MAX_BASE_URL_CHARS);
  assert.equal(checkBaseUrl(exact), null, '边界值应与 App 的 `> 128` 一致');

  const tooLong = `${exact}a`;
  assert.match(checkBaseUrl(tooLong), /过长/);
});

// ── checkBaseUrl：App 会静默丢弃的形状 ──────────────────────────────────────

test('checkBaseUrl：只收规范形 —— 大写 scheme、尾斜杠、大小写混写都不行', () => {
  // App 对 scheme 用 equals(ignoreCase) 且 trimEnd('/')，索引这边故意更严：
  // 同一代理两种写法会让判重、人工核对都失真。
  assert.match(checkBaseUrl('HTTPS://gh-proxy.org'), /必须以 https:\/\//);
  assert.match(checkBaseUrl('https://gh-proxy.org/'), /不能带路径/);
});

test('checkBaseUrl：路径、query、fragment、userinfo、空格、http 一律拒', () => {
  assert.match(checkBaseUrl('http://gh-proxy.org'), /必须以 https:\/\//);
  assert.match(checkBaseUrl('https://gh-proxy.org/gh/'), /不能带路径/);
  assert.match(checkBaseUrl('https://gh-proxy.org?x=1'), /不能带 query/);
  assert.match(checkBaseUrl('https://gh-proxy.org#x'), /不能带 fragment/);
  assert.match(checkBaseUrl('https://u:p@gh-proxy.org'), /userinfo/);
  assert.match(checkBaseUrl('https://gh-proxy .org'), /不能含空格/);
  assert.match(checkBaseUrl('https://gh-proxy.org:8443'), /只允许 443 端口/);
});

test('checkBaseUrl：IDN 与下划线主机拒掉（App 的 java.net.URI 拿不到 host）', () => {
  assert.match(checkBaseUrl('https://例え.jp'), /非 ASCII/);
  assert.match(checkBaseUrl('https://gh_proxy.org'), /只能含 ASCII 字母、数字、连字符和点/);
  assert.match(checkBaseUrl('https://gh-proxy.org.'), /不能以点/);
  assert.match(checkBaseUrl('https://gh..proxy.org'), /空的域名段/);
});

test('checkBaseUrl：GitHub 自己的下载域名拒掉（App 解析时直接 continue）', () => {
  for (const host of ['github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com']) {
    assert.match(checkBaseUrl(`https://${host}`), /GitHub 自己的下载域名/, host);
    // 大小写不同不该绕过（App 那边是精确比较，索引这边先挡住更保险）
    assert.match(checkBaseUrl(`https://${host.toUpperCase()}`), /GitHub 自己的下载域名/);
  }
});

test('checkBaseUrl：缺失、非字符串、空白、空串', () => {
  assert.equal(checkBaseUrl(undefined), '缺失');
  assert.match(checkBaseUrl(null), /必须是字符串/);
  assert.match(checkBaseUrl(443), /必须是字符串/);
  assert.match(checkBaseUrl('   '), /不能为空/);
  assert.match(checkBaseUrl('https://'), /host 为空/);
});

// ── checkHostname：域名段规则 ───────────────────────────────────────────────

test('checkHostname：长度、空段、连字符位置、非法字符', () => {
  assert.equal(checkHostname('gh-proxy.org'), null);
  assert.equal(checkHostname('1.2.3.4'), null);
  assert.match(checkHostname(''), /host 为空/);
  assert.match(checkHostname(`a.${'b'.repeat(64)}.com`), /某一段过长/);
  assert.match(checkHostname(`${Array(5).fill('a'.repeat(60)).join('.')}.com`), /host 过长/);
  assert.match(checkHostname('a..b'), /空的域名段/);
  assert.match(checkHostname('.a.b'), /不能以点/);
  assert.match(checkHostname('a.b.'), /不能以点/);
  assert.match(checkHostname('-a.com'), /不能以连字符开头或结尾/);
  assert.match(checkHostname('a-.com'), /不能以连字符开头或结尾/);
  assert.match(checkHostname('a_b.com'), /只能含 ASCII 字母、数字、连字符和点/);
  assert.match(checkHostname('例え.jp'), /只能含 ASCII 字母、数字、连字符和点/);
});

// ── validateProxies：结构与语义 ─────────────────────────────────────────────

test('validateProxies：schemaVersion / lastUpdate / proxies 三项基本约束', () => {
  assert.equal(validateProxies(doc()).ok, true);
  assert.match(errorsOf({ schemaVersion: 2 }), /schemaVersion 必须是数字 1/);
  assert.match(errorsOf({ lastUpdate: '2026-02-30' }), /lastUpdate 必须是 yyyy-MM-dd/);
  assert.match(errorsOf({ proxies: [] }), /proxies 不能是空数组/);
  assert.match(errorsOf({ proxies: 'x' }), /缺少 proxies 数组/);
});

test('validateProxies：proxies 超过 32 条要拒', () => {
  const many = Array.from({ length: 33 }, (_, i) => ({
    id: `p${i}`,
    name: `p${i}.example.com`,
    baseUrl: `https://p${i}.example.com`,
  }));
  assert.match(errorsOf({ proxies: many }), /proxies 最多 32 条/);
});

test('validateProxies：id 重复、id 是保留的 direct、name/note 超长、条目不是对象', () => {
  assert.match(
    errorsOf({
      proxies: [
        { id: 'a1', name: 'a', baseUrl: 'https://a.example.com' },
        { id: 'a1', name: 'b', baseUrl: 'https://b.example.com' },
      ],
    }),
    /id 重复：a1/,
  );
  assert.match(errorsOf({ proxies: [{ id: 'direct', name: 'd', baseUrl: 'https://d.example.com' }] }), /不能是 "direct"/);
  assert.match(errorsOf({ proxies: [{ id: 'a1', name: 'x'.repeat(41), baseUrl: 'https://a.example.com' }] }), /name 过长/);
  assert.match(
    errorsOf({ proxies: [{ id: 'a1', name: 'a', baseUrl: 'https://a.example.com', note: 'x'.repeat(61) }] }),
    /note 过长/,
  );
  assert.match(errorsOf({ proxies: ['not-an-object'] }), /proxies\[0\] 不是对象/);
});

test('validateProxies：同一 host 不同写法算重复（大小写、显式 :443）', () => {
  assert.match(
    errorsOf({
      proxies: [
        { id: 'a1', name: 'a', baseUrl: 'https://a.example.com' },
        { id: 'a2', name: 'b', baseUrl: 'https://A.EXAMPLE.COM:443' },
      ],
    }),
    /baseUrl 与 proxies\[0\] 重复/,
  );
});

test('validateProxies：一条坏 baseUrl 只报错、不影响其它条目的判重', () => {
  const errors = errorsOf({
    proxies: [
      { id: 'bad1', name: 'bad', baseUrl: 'https://例え.jp' },
      { id: 'a1', name: 'a', baseUrl: 'https://a.example.com' },
      { id: 'a2', name: 'b', baseUrl: 'https://a.example.com' },
    ],
  });
  assert.match(errors, /proxies\[0\]\.baseUrl 不能含非 ASCII/);
  assert.match(errors, /proxies\[2\]\.baseUrl 与 proxies\[1\] 重复/);
});

// ── 自测入口与 CLI ─────────────────────────────────────────────────────────

test('runSelfTest：内置负例全过且返回 0', () => {
  const lines = [];
  const log = { log: (s) => lines.push(String(s)), error: (s) => lines.push(String(s)) };
  assert.equal(runSelfTest(log), 0, lines.join('\n'));
  assert.match(lines.join('\n'), /条负例全部被挡住/);
});

test('CLI：真实文件退出 0，--selftest 退出 0', () => {
  const ok = spawnSync(process.execPath, [SCRIPT], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /通过：\d+ 个代理/);

  const selftest = spawnSync(process.execPath, [SCRIPT, '--selftest'], { encoding: 'utf8' });
  assert.equal(selftest.status, 0, selftest.stderr);
});

test('CLI：坏文件退出 1（CI 只看退出码）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxies-'));
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, JSON.stringify(doc({ proxies: [{ id: 'x1', name: 'x', baseUrl: 'https://例え.jp' }] })));
  try {
    const r = spawnSync(process.execPath, [SCRIPT, bad], { encoding: 'utf8' });
    assert.equal(r.status, 1, r.stdout);
    assert.match(r.stderr, /不能含非 ASCII/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
