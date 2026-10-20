// audit.yml「分流决策」那一步的行为单测 —— 2026-10-13 因外部评审 F16 而加。
//
// 为什么这一步值得单独钉：它是「扫描结论 → 要不要自动合并」唯一的判据，而 publish 作业
// 合的是**整条 PR**。判据只读一份报告时，同 PR 里另一份高风险投稿就被顺带合并进去了 ——
// 这不是「少报一个信息」，是自动放行闸被结构性地绕过。所以这里所有用例都是多包形状，
// 单包只用来钉「修完没把干净投稿一起挡死」这条基线。
//
// 测试不复制判据代码，而是从 workflow 里**切出内联脚本再真跑一遍**：复制一份改进去，
// 就变成「测试钉住测试里那份」，workflow 本身可以随便漂。
// 运行：node --test test/audit-triage.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const WF = path.resolve(import.meta.dirname, '../.github/workflows/audit.yml');

/** 切出「分流决策」步骤里 `node -e '…'` 的那段 JS（去掉 YAML 的公共缩进）。 */
function extractTriage() {
  const lines = fs.readFileSync(WF, 'utf8').replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === '- name: 分流决策');
  assert.ok(start >= 0, 'workflow 里必须存在名为「分流决策」的步骤（改名要一起改这里）');
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {6}- name: /.test(lines[i])) { end = i; break; }
  }
  const region = lines.slice(start, end);
  const open = region.findIndex((l) => /^\s*node -e '$/.test(l));
  assert.ok(open >= 0, '该步骤里必须能找到 `node -e` 的开始行');
  const close = region.findIndex((l, i) => i > open && /^\s*'$/.test(l));
  assert.ok(close > open, '`node -e` 的单引号必须单独成行闭合');
  const body = region.slice(open + 1, close);
  const indent = Math.min(...body.filter((l) => l.trim()).map((l) => l.length - l.trimStart().length));
  return { text: body.map((l) => l.slice(indent)).join('\n'), region: region.join('\n') };
}

const { text: TRIAGE_JS, region: TRIAGE_REGION } = extractTriage();

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-triage-'));
const SCRIPT = path.join(TMP, 'triage.cjs');
fs.writeFileSync(SCRIPT, TRIAGE_JS, 'utf8');

/** 一份扫描报告的最小形状（字段名照 scan.mjs 的 report：riskLevel / changeType / riskReasons / meta）。 */
const rep = (riskLevel, changeType, over = {}) => ({
  schema: 'module-audit/1',
  riskLevel, changeType,
  riskReasons: over.reasons || [`原因 ${riskLevel}`],
  meta: { id: over.id ?? 'demo', version: over.version ?? '1' },
});

/**
 * AI 那一层的产物形状（字段照 ai-review.mjs 的 finish('ok', …)）。
 * `target.report` 的 basename 必须是 `<pkg>.audit.json` —— triage 拿它钉「复核的正是这一包」。
 */
const aiArt = (pkg, over = {}) => ({
  schema: 'ai-review/v1',
  status: over.status ?? 'ok',
  target: over.target ?? { zip: `audit-out/zips/${pkg}`, report: `audit-out/${pkg}.audit.json` },
  agree: over.agree ?? true,
  risk: over.risk === undefined ? null : over.risk,
  findings: over.findings ?? [],
  ...(over.reason === undefined ? {} : { reason: over.reason }),
});

/** 一条 AI 命中（severity 是抬级的输入，message 是进 reasons 的自由文本）。 */
const aiHit = (severity, message, over = {}) => ({
  ruleId: over.ruleId ?? 'AI_1', source: 'ai', category: 'ai', severity,
  file: over.file ?? 'install.sh', line: over.line ?? 7, snippet: over.snippet ?? 'rm -rf /',
  message,
});

/**
 * 真跑一次分流：在临时目录造 audit-out/，把 GITHUB_OUTPUT 指到一个文件，返回解析出的 kv。
 * reports 的 key 就是报告文件名（<pkg>.audit.json），所以用例能直接控制「哪几份存在」；
 * 真实形态下 <pkg> = zip 的 basename（**含 .zip**，scan.mjs 的默认命名就是 `<zip name>.audit.json`），
 * 所以下面 ai 的 key 与 reports 的 key 用同一个串 —— 口径钉子就钉在这儿。
 *
 * ai 的形状：{ '<pkg>': { status, ...artifact } }；缺省 artifact 按 status 造一份合规则的。
 * 第二个参数也接受字符串（= 只写状态文件、不写产物），那是「状态与产物对不上」那几发要的。
 */
function runTriage(reports, ai, opts = {}) {
  const dir = opts.dir || fs.mkdtempSync(path.join(TMP, 'run-'));
  fs.mkdirSync(path.join(dir, 'audit-out'), { recursive: true });
  for (const [pkg, r] of Object.entries(reports)) {
    const file = path.join(dir, 'audit-out', `${pkg}.audit.json`);
    // 传字符串时按原始字节写入 —— 「报告坏了」这类用例要能造出真的坏文件，而不是被 JSON 包一层。
    fs.writeFileSync(file, typeof r === 'string' ? r : JSON.stringify(r), 'utf8');
    const m = opts.mtime && opts.mtime[pkg];
    if (m !== undefined) fs.utimesSync(file, new Date(m), new Date(m));
  }
  for (const [pkg, v] of Object.entries(ai || {})) {
    const one = typeof v === 'string' ? { status: v } : v;
    fs.writeFileSync(path.join(dir, 'audit-out', `ai-${pkg}.status`), `${one.status}\n`, 'utf8');
    if (one.artifact !== null) {
      fs.writeFileSync(path.join(dir, 'audit-out', `ai-${pkg}.json`),
        JSON.stringify(one.artifact || aiArt(pkg, one)), 'utf8');
    }
  }
  // 直接给状态文件名的形状：造「口径漂了」（ai-<去掉了 .zip>）与「非法状态值」那几发。
  for (const [f, v] of Object.entries(opts.rawStatus || {})) {
    fs.writeFileSync(path.join(dir, 'audit-out', f), typeof v === 'string' ? `${v}\n` : v, 'utf8');
  }
  // 只有真需要 raiseLevel 的形态才装模块（装一份 ≈344KB，全量装会把这 30 发拖慢一档）。
  const needsModule = Object.values(ai || {}).some((v) => (typeof v === 'string' ? v : v.status) === 'ok')
    || Object.keys(opts.rawStatus || {}).length > 0;
  if (opts.module !== false && needsModule) installModule(dir, opts.moduleAt || 'audit');
  const out = path.join(dir, 'gh_output');
  fs.writeFileSync(out, '', 'utf8');
  let err = null;
  try {
    execFileSync(process.execPath, [opts.script || SCRIPT], {
      cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, GITHUB_OUTPUT: out },
    });
  } catch (e) { err = e; }
  const kv = {};
  for (const line of fs.readFileSync(out, 'utf8').split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1);
  }
  return { kv, err, stderr: err ? String(err.stderr || '') : '', dir };
}

/* ------------------------------------------------- G.2：红那一发写出的 fail-closed 判据 */

/**
 * 绿那一发与红那一发写出的键集必须逐字相同 —— 「缺的写成空值而不是整个消失」本身是契约
 * （同形的一条见 §0.44：评论顶层的 budgetBasis 写成 null 而不是不见）。
 */
const VERDICT_KEYS = ['risk', 'change_type', 'module_id', 'module_version', 'package_count',
  'ai_note', 'reasons', 'action', 'label', 'needs_human_review'].sort();

/**
 * 判据红的那一发必须写出的东西（盘点 G.2）。原来这批用例钉的是 `deepEqual(kv, {})`
 * （「失败时不许留下半份判据」），G.2 把它反过来：红那一发**必须**留下判据，否则下游
 * 想解释「红叉为什么」只能拿空值渲染 —— 那要么是一句假陈述，要么是通道自己坏。
 *
 * 不许留下的是**放行**。三格是硬的：
 *   action / label / needs_human_review 永远不过 decide()，红那一发只有 block 一个方向
 *   （action=auto-approve 是 publish 作业的门票、label=auto-approved 是标签步会真打上去的颜色）；
 *   risk 永远留空 —— 本轮没有产出等级，填 high 是把我们的故障说成投稿者的风险，
 *   填静态那一档是把「AI 没来得及抬级」说成「已经量过」，两句都是假陈述。
 */
function assertFailClosed(kv, msg = '') {
  assert.deepEqual(Object.keys(kv).sort(), VERDICT_KEYS, `${msg}键集要与绿那一发逐字相同`);
  assert.equal(kv.action, 'block', `${msg}红那一发的处置只有 block 一个方向`);
  assert.equal(kv.label, 'needs-human-review', msg);
  assert.equal(kv.needs_human_review, 'true', msg);
  assert.equal(kv.risk, '', `${msg}没有结论就留空，不许填一个看起来量出来的等级`);
}

/* ------------------------------------------------------------------ T6.1：AI 步（bash）的夹具 */

/** AI 步在 workflow 里的步骤名（改名要一起改这里 —— extractStep 会带着这句话红）。 */
const AI_STEP = 'AI 安全员复核';

/** triage 的 import 候选要命中真判据实现，就得把 base 里那一份（含它的依赖）装进临时 cwd。
 *  清单由目录现读，不写死：第五十批新增 audit/dex-forensics.mjs 时，下面那份手写的四元素清单
 *  让这套 e2e 直接红在 `Cannot find module …/dex-forensics.mjs`（risk-rules 现在 import 它）。
 *  手抄清单的毛病不是"多一行"，是**新增一个判据模块时它不会提醒任何人**：CI 里跑的是仓内真文件、
 *  这套 e2e 跑的是拷贝出去的那一份，两边对不齐就等于测了另一套代码。测试文件（*.test.mjs）
 *  仍然排除在外 —— 它们不是被 import 的实现，装进临时 cwd 只会多几份噪声。 */
const MODULE_SRC = path.resolve(import.meta.dirname, '../audit');
const MODULE_FILES = fs.readdirSync(MODULE_SRC)
  .filter((f) => f.endsWith('.mjs') && !f.endsWith('.test.mjs'))
  .sort();

/** 把「真正被 CI 执行的那份 raiseLevel」装到 <dir>/<at>/ 下（默认 audit/，另一种落地形态是 contrib/audit/）。 */
function installModule(dir, at = 'audit') {
  const dst = path.join(dir, at);
  fs.mkdirSync(dst, { recursive: true });
  for (const f of MODULE_FILES) fs.copyFileSync(path.join(MODULE_SRC, f), path.join(dst, f));
}

/** 切出某一步：region = 整步（含 if:/env:），text = `run: |`（或 key='script' 时 `script: |`）里的脚本体。 */
function extractStep(name, key = 'run') {
  const lines = fs.readFileSync(WF, 'utf8').replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.ok(start >= 0, `workflow 里必须存在名为「${name}」的步骤（改名要一起改这里）`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {6}- (?:name|uses): /.test(lines[i])) { end = i; break; }
  }
  const region = lines.slice(start, end).join('\n');
  const openRe = new RegExp(`^\\s*${key}: \\|\\s*$`);
  let open = -1;
  for (let i = start + 1; i < end; i += 1) {
    if (openRe.test(lines[i])) { open = i; break; }
  }
  assert.ok(open >= 0, `步骤「${name}」里必须有 ${key}: | 块`);
  const keyIndent = lines[open].length - lines[open].trimStart().length;
  const body = [];
  for (let i = open + 1; i < end; i += 1) {
    const l = lines[i];
    if (l.trim() !== '' && l.length - l.trimStart().length <= keyIndent) break;
    body.push(l);
  }
  const nonBlank = body.filter((l) => l.trim());
  assert.ok(nonBlank.length > 0, `步骤「${name}」的 ${key} 块是空的`);
  const indent = Math.min(...nonBlank.map((l) => l.length - l.trimStart().length));
  return { region, text: `${body.map((l) => l.slice(indent)).join('\n')}\n` };
}

/**
 * 假的 ai-review.mjs：按 fake-plan.json 写 status/产物，再按状态退出（ok→0，其余→1，
 * 计划里给 noWrite 就一份都不写并按 exit 退 —— 那是「这一层根本没运行」那一发）。
 * 它把每次调用的 argv 追加进 ai-calls.jsonl：「一份一包」只能靠调用参数钉，
 * 断言产物内容断不出 last-wins（同源纪律的老账）。
 */
const FAKE_STUB = [
  'const fs = require("fs");',
  'const path = require("path");',
  'const argv = process.argv.slice(2);',
  'const flag = (n) => { const i = argv.indexOf("--" + n); return i >= 0 ? argv[i + 1] : ""; };',
  'fs.appendFileSync("ai-calls.jsonl", JSON.stringify(argv) + "\\n");',
  'const plan = JSON.parse(fs.readFileSync("fake-plan.json", "utf8"));',
  'const zip = flag("zip");',
  'const p = plan[path.basename(zip)] || { status: "failed" };',
  'if (p.noWrite) process.exit(p.exit || 2);',
  'fs.writeFileSync(flag("status"), p.status + "\\n");',
  'const art = Object.assign({ schema: "ai-review/v1", status: p.status,',
  '  target: { zip: zip, report: flag("report") } }, p.artifact || {});',
  'fs.writeFileSync(flag("out"), JSON.stringify(art));',
  'process.exit(p.status === "ok" ? 0 : 1);',
  '',
].join('\n');

const CREDS = {
  QODER_PAT: 'pt_demo',
  QCA_AGENT_ID: 'agent_demo',
  QCA_AGENT_VERSION: '7',
  QCA_ENVIRONMENT_ID: 'env_demo',
};

/**
 * 在临时 cwd 里真跑 workflow 切出来的那段 AI 步 bash。
 * creds: 'full' | 'none' | 要抽掉的那几个键的数组；zips 决定清单；plan 决定每包的状态。
 */
function runAiStep(opts = {}) {
  const { text } = extractStep(AI_STEP);
  const dir = fs.mkdtempSync(path.join(TMP, 'ai-'));
  fs.mkdirSync(path.join(dir, 'audit-out', 'zips'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'ai-step.sh'), text, 'utf8');
  const zips = opts.zips || ['demo.zip', 'evil.zip'];
  for (const z of zips) {
    fs.writeFileSync(path.join(dir, 'audit-out', 'zips', z), 'PK 假包');
    fs.writeFileSync(path.join(dir, 'audit-out', `${z}.audit.json`),
      JSON.stringify(rep('low', 'first', { id: z.replace(/\.zip$/, '') })), 'utf8');
  }
  fs.writeFileSync(path.join(dir, 'zips.txt'), `${zips.map((z) => `audit-out/zips/${z}`).join('\n')}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'fake-plan.json'), JSON.stringify(opts.plan || {}), 'utf8');
  fs.writeFileSync(path.join(dir, 'fake-review.cjs'), FAKE_STUB, 'utf8');

  const env = { ...process.env, LOCATE_AI_REVIEW: 'fake-review.cjs', LOCATE_PREFIX: '' };
  for (const k of [...Object.keys(CREDS), 'QCA_PROMPT_SHA']) delete env[k];
  const missing = opts.creds === 'none' ? Object.keys(CREDS)
    : Array.isArray(opts.creds) ? opts.creds : [];
  for (const [k, v] of Object.entries(CREDS)) if (!missing.includes(k)) env[k] = v;
  if (opts.promptSha) env.QCA_PROMPT_SHA = opts.promptSha;

  let err = null;
  let stdout = '';
  let stderr = '';
  try {
    // 起法必须与 runner 一致（2026-10-16 run 38904316355 实测到的）：GitHub 对 `shell: bash` 展开成
    // `bash --noprofile --norc -e -o pipefail` —— **那个 `-e` 是 runner 给的，脚本里写 `set -uo pipefail`
    // 撤不掉它**。旧夹具用 `bash ai-step.sh`（没有 -e），跑这段 bash 的用例就全在比线上宽松一档的壳里：
    // 同一个缺陷（把 `|| CODE=$?` 退回裸 `node` + `CODE=$?`）在旧夹具下 57/57 全绿，在忠实夹具下 5 红。
    const r = execFileSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', 'ai-step.sh'], {
      cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env,
    });
    stdout = r.stdout;
    stderr = r.stderr;
  } catch (e) { err = e; stdout = String(e.stdout || ''); stderr = String(e.stderr || ''); }

  const outDir = path.join(dir, 'audit-out');
  const files = fs.readdirSync(outDir).sort();
  const status = {};
  for (const f of files) {
    if (/^ai-.*\.status$/.test(f)) status[f] = fs.readFileSync(path.join(outDir, f), 'utf8').trim();
  }
  const callsPath = path.join(dir, 'ai-calls.jsonl');
  const calls = fs.existsSync(callsPath)
    ? fs.readFileSync(callsPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  // ::error:: 那几行才是这一步的「说法」。本步按 workflow 的既有惯例写 stdout（scan 的覆盖度闸同形），
  // 所以断言从合并输出里挑出 error 行，而不是赌它落在哪条流上。
  const out = `${stdout}\n${stderr}`;
  const errors = out.split('\n').filter((l) => l.includes('::error::')).join('\n');
  return { code: err ? (err.status ?? 1) : 0, stdout, stderr, out, errors, dir, files, status, calls };
}

/** 从调用 argv 里取某个 flag 的值。 */
const argOf = (argv, name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};

/* --------------------------------------------------------------- 基线：单包 */

test('单包 low+first → auto-approve（修完不许把干净的首次投稿一起卡住）', () => {
  const { kv, err } = runTriage({ good: rep('low', 'first') });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.risk, 'low');
  assert.equal(kv.change_type, 'first');
  assert.equal(kv.action, 'auto-approve');
  assert.equal(kv.label, 'auto-approved');
  assert.equal(kv.needs_human_review, 'false');
  assert.equal(kv.package_count, '1');
  assert.equal(kv.reasons, '原因 low', '单包时 reasons 不该被包名前缀污染');
});

test('单包 low+update → request-review；medium/high → block（决策矩阵原样成立）', () => {
  assert.equal(runTriage({ a: rep('low', 'update') }).kv.action, 'request-review');
  assert.equal(runTriage({ a: rep('medium', 'first') }).kv.action, 'block');
  assert.equal(runTriage({ a: rep('high', 'first') }).kv.action, 'block');
});

/* --------------------------------------------------------------- F16：多包取最严 */

test('两包一 low 一 high → block（这就是修前会 auto-approve 的那一发）', () => {
  // 修前是 `ls -t audit-out/*.audit.json | head -n1`：只拿「时间戳最新那一份」定级。
  // 攻击形状 = 把自己那份干净的 low+first 排在高风险那份之后写出来，整条 PR 一起被 squash 合并。
  const { kv, err } = runTriage({ evil: rep('high', 'first'), good: rep('low', 'first') });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.package_count, '2');
  assert.equal(kv.risk, 'high', '等级必须取所有报告里最严的，不是取最新的一份');
  assert.equal(kv.action, 'block');
  assert.equal(kv.needs_human_review, 'true');
  assert.match(kv.reasons, /evil: 原因 high/);
  assert.match(kv.reasons, /good: 原因 low/);
});

test('low+first 与 low+update 混投 → 不是 auto-approve（changeType 混合要落进人工队列）', () => {
  const { kv } = runTriage({ a: rep('low', 'first'), b: rep('low', 'update') });
  assert.equal(kv.change_type, 'first+update');
  assert.equal(kv.risk, 'low');
  assert.equal(kv.action, 'request-review', '只要不是「每一份都 low+first」就不能自动合并');
});

test('三份里最严那份排最后也照样 block（判据与文件名顺序无关）', () => {
  const a = runTriage({ 'a-mod': rep('low', 'first'), 'z-mod': rep('medium', 'first') });
  const b = runTriage({ 'a-mod': rep('medium', 'first'), 'z-mod': rep('low', 'first') });
  assert.equal(a.kv.risk, 'medium');
  assert.equal(b.kv.risk, 'medium');
  assert.equal(a.kv.action, 'block');
  assert.equal(b.kv.action, 'block');
});

test('module_id 按包去重汇总（一条 PR 里几个投稿人要看得见）', () => {
  const { kv } = runTriage({
    one: rep('low', 'first', { id: 'mod-a' }),
    two: rep('high', 'first', { id: 'mod-b' }),
    three: rep('low', 'first', { id: 'mod-a' }),
  });
  assert.equal(kv.module_id, 'mod-a,mod-b');
});

/* --------------------------------------------------------------- 坏输入不许塌成低风险 */

test('报告缺 riskLevel 或等级不在枚举里 → 按 high 处理，不许塌成 low 而被自动放行', () => {
  const missing = { ...rep('low', 'first') };
  delete missing.riskLevel;
  assert.equal(runTriage({ a: missing }).kv.action, 'block', '读不懂的报告不是「低风险」');
  assert.equal(runTriage({ a: missing, b: rep('low', 'first') }).kv.action, 'block');
  assert.equal(runTriage({ a: rep('catastrophic', 'first') }).kv.action, 'block');
  assert.equal(runTriage({ a: rep('catastrophic', 'first') }).kv.risk, 'high');
});

test('audit-out 里一份报告都没有 → 这一步直接失败，并留下 fail-closed 判据（不是「什么都不留」）', () => {
  const { kv, err, stderr } = runTriage({});
  assert.notEqual(err, null, 'found=true 却没有报告时必须是红，不能给「什么都没扫到」盖章放行');
  assert.match(stderr, /没有任何 \.audit\.json/);
  assertFailClosed(kv);
  assert.equal(kv.package_count, '0', '一份报告文件都没有，这个 0 是数出来的不是兜出来的');
  assert.equal(kv.change_type, '');
  assert.equal(kv.module_id, '');
  // 这一发跟 AI 层无关（压根没走到那几格），所以不占 ai_note —— 评论层有它自己那句
  // 「分流这一步没写出复核方式」，比在这里替 AI 编一句准确。
  assert.equal(kv.ai_note, '');
  assert.match(kv.reasons, /没有任何 \.audit\.json/, '红叉的依据要能在 output 里读到，不只活在 runner 日志里');
});

test('有一份报告坏了 → 整步失败，不许「跳过坏的那份、用最严的好那份」继续定级', () => {
  // parse 抛错就是抛错。把它兜成「忽略这份」等于给投稿者一条「让扫描器产出一份读不懂的文件」的绕过路径。
  const { kv, err } = runTriage({ broken: '{ "riskLevel": "high"', good: rep('low', 'first') });
  assert.notEqual(err, null, 'JSON.parse 抛错必须把这一步带红');
  assertFailClosed(kv);
  // 读成 0 份，但文件确实有 2 份 —— 红那一发能说的只有后者，说前者是谎报。
  assert.equal(kv.package_count, '2');
  assert.equal(kv.module_id, '', '一份都没读成，就一个 id 都不许报（报出来的是「跳过坏的那份」的产物）');
  assert.match(kv.reasons, /分流决策异常/);
});

/* --------------------------------------------------------------- AI 复核只能加严 */

// 这条原本是 `llm.json agree:false → 抬等级`。T6.1 把 llm.json 换成了 ai-<pkg>.status，
// 按工单 §1 第 2 步的要求**改写成同形用例而不是删掉** —— 它是「AI 参与定级」唯一的机器检查。
test('ok 的三发：agree:false 且更严 → 抬等级；同意或不更严时不动静态结论', () => {
  const escalate = runTriage({ 'a.zip': rep('low', 'first') }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: false, risk: 'high', findings: [aiHit('high', '模型看到了别的')] }) },
  });
  assert.equal(escalate.kv.risk, 'high');
  assert.equal(escalate.kv.action, 'block');
  assert.match(escalate.kv.ai_note, /不同意/);
  assert.match(escalate.kv.reasons, /AI 复核：模型看到了别的/);

  const agree = runTriage({ 'a.zip': rep('low', 'first') }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: true, risk: 'high' }) },
  });
  assert.equal(agree.kv.action, 'auto-approve', 'agree:true 时模型声明的 risk 不参与定级（findings 恒空 = 没有可复验的线索）');

  const softer = runTriage({ 'a.zip': rep('high', 'first') }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: false, risk: 'low' }) },
  });
  assert.equal(softer.kv.risk, 'high', '复核只能加严，不能把静态的 high 放宽');
});

/* --------------------------------------------------------------- 变异哨兵 */

test('变异哨兵：把判据退回「只取最新那一份报告」，多包混投就会重新被自动放行', () => {
  // 这条不测新代码，它测的是上面那批断言**有没有在测东西**。
  // 做法：拿同一份内联脚本，只把「收集报告清单」那一行退回旧语义（按 mtime 取最新一份），
  // 然后喂同一个「一份 high 写得早、一份 low+first 写得晚」的 PR。
  // 旧语义在这里必须给出 auto-approve —— 给出了，才证明 F16 是真的洞、上面的 block 断言不是空跑。
  const mutated = TRIAGE_JS.replace(
    /^names=fs\.readdirSync[^\n]*/m,
    'names=(()=>{const all=fs.readdirSync(dir).filter((f)=>f.endsWith(".audit.json"));'
    + 'return [all.sort((a,b)=>fs.statSync(dir+"/"+b).mtimeMs-fs.statSync(dir+"/"+a).mtimeMs)[0]]})()',
  );
  assert.notEqual(mutated, TRIAGE_JS,
    '变异哨兵的替换点漂了（那行改了写法）—— 更新它，别删掉它');
  const old = path.join(TMP, 'triage-old.cjs');
  fs.writeFileSync(old, mutated, 'utf8');

  const { kv } = runTriage(
    { evil: rep('high', 'first'), good: rep('low', 'first') },
    undefined,
    { script: old, mtime: { evil: 1_000_000, good: 2_000_000 } }, // good 是「最新那份」
  );
  assert.equal(kv.package_count, '1', '旧语义只看得到一份报告');
  assert.equal(kv.risk, 'low', '那份 high 根本没参与定级');
  assert.equal(kv.action, 'auto-approve', '旧语义下这条混投 PR 会被自动合并 —— 这就是 F16');
});

/* ------------------------------------- 变异哨兵（G.2）：证明上面那批 fail-closed 断言不是空跑 */

/** 造一发判据红：AI 状态 failed 而静态是 low+first —— 最容易被「顺手放行」的那个形状。 */
const redRun = (script) => runTriage({ 'demo.zip': rep('low', 'first') },
  { 'demo.zip': { status: 'failed', artifact: aiArt('demo.zip', { status: 'failed', reason: '超时' }) } },
  { script });

test('变异哨兵：把 fail() 退回「先 exit 1、output 一段不写」，红那一发就又是一片空白', () => {
  const mutated = TRIAGE_JS.replace(
    /const fail=\(m,aboutAi\)=>\{[^\n]*\};/,
    'const fail=(m,aboutAi)=>{ console.error(`::error::分流决策：${m}`); process.exit(1); };',
  );
  assert.notEqual(mutated, TRIAGE_JS, '变异哨兵的替换点漂了（fail 那行改了写法）—— 更新它，别删掉它');
  const old = path.join(TMP, 'triage-silent.cjs');
  fs.writeFileSync(old, mutated, 'utf8');
  const { kv, err } = redRun(old);
  assert.notEqual(err, null, '退回旧写法照样是红 —— 这一发要证的是红那一发**什么都不说**');
  assert.deepEqual(kv, {}, '旧写法下 steps.triage.outputs.* 全空：下游想解释「红叉为什么」只能拿空值渲染');
});

test('变异哨兵：把红那一发的处置写成 auto-approve，就是给一发判据没跑成的投稿盖放行章', () => {
  const mutated = TRIAGE_JS.replace(
    'w("action","block"); w("label","needs-human-review"); w("needs_human_review","true");',
    'w("action","auto-approve"); w("label","auto-approved"); w("needs_human_review","false");',
  );
  assert.notEqual(mutated, TRIAGE_JS, '变异哨兵的替换点漂了（fail-closed 那三格改了写法）—— 更新它，别删掉它');
  const bad = path.join(TMP, 'triage-approve.cjs');
  fs.writeFileSync(bad, mutated, 'utf8');
  const { kv, err } = redRun(bad);
  assert.notEqual(err, null, '这一步仍然红：变异改的是它留下的话，不是它的结论');
  assert.equal(kv.action, 'auto-approve');
  assert.equal(kv.label, 'auto-approved');
  assert.equal(kv.needs_human_review, 'false');
  // 这三格正是 publish 作业的门票（它的 if 认 found 与 action 两个 output）与标签步会真打上去的颜色
  // ⇒ assertFailClosed 里那三条 equal 是挡住「通道坏了被渲染成已放行」的唯一一道牙。
});

/* --------------------------------------------------------------- 旧形态不许回来 */

test('分流这一步不再用「挑最新那一份报告」的写法', () => {
  // 只看真正被执行的 JS：上面那段 bash 注释里合法地引用了旧写法，那是说明不是代码。
  assert.doesNotMatch(TRIAGE_JS, /ls -t/, 'ls -t|head -n1 是 F16 的成因：它把多包 PR 当成单包定级');
  assert.doesNotMatch(TRIAGE_JS, /head -n1/);
  assert.match(TRIAGE_JS, /fs\.readdirSync\(dir\)/, '判据要读整个目录的报告清单；按名字挑一份就是 F16');
});

test('内联脚本本身可被独立执行（只读 cwd 与 GITHUB_OUTPUT，不吃 shell 变量）', () => {
  // 这一步切出来真跑，靠的就是「脚本里除了 cwd 和 GITHUB_OUTPUT 没有别的输入」。
  // 旧写法是 `node -e '…' "$JSON"` —— 输入由 bash 递进来，切出来就跑不了。
  // 有人日后往里塞 $ZIP / ${步间变量}，这段切出来的 JS 会先在这里红，而不是等到 CI 上半红半绿。
  assert.doesNotMatch(TRIAGE_JS, /process\.argv/, '判据不许依赖 bash 传进来的参数：那会让本测试测不到它');
  assert.ok(TRIAGE_JS.includes('process.env.GITHUB_OUTPUT'));
  assert.doesNotMatch(TRIAGE_REGION, /'\s+"?\$\w/, 'node -e 的收尾不该再把 shell 变量当参数递进去');
});

/* ===========================================================================
 * T6.1：AI 那一层的五种状态必须在分流里产生五种不同的下游后果（工单 §0.1）。
 * 判据不是「测试跑绿」：如果五态只落成评论文案、action 仍只由静态报告决定，
 * 下面 ok+raise 那一发与变异③就是打不响的空枪。
 * ========================================================================= */

/* --------------------------------------------------------------- AI 步（bash 真跑） */

test('AI 步：未配 QCA 凭据 → 逐包写 disabled、一次脚本都不调、这一步自己 exit 0', () => {
  const r = runAiStep({ creds: 'none' });
  assert.equal(r.code, 0, `没配凭据不是失败，是「这一层未参与」：红该由分流开火。stderr=${r.stderr}`);
  assert.deepEqual(r.status, { 'ai-demo.zip.status': 'disabled', 'ai-evil.zip.status': 'disabled' },
    'disabled 也要一份一包 —— 单文件 ai.status 在多包 PR 里会被后一包覆盖（§0.2-3）');
  assert.equal(r.calls.length, 0, '凭据不齐时不许调用脚本（缺凭据还发请求 = 拿匿名身份去问模型）');
  assert.ok(!r.files.some((f) => /^ai-.*\.json$/.test(f)), '不调脚本就不许有产物');
});

test('AI 步：QCA_AGENT_VERSION 缺失同样算未启用 —— 不许退化成 latest', () => {
  const r = runAiStep({ creds: ['QCA_AGENT_VERSION'] });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.calls.length, 0, 'agent 版本没钉住就发出去 = 把闸的语义交给供应商的默认值');
  assert.deepEqual(Object.values(r.status), ['disabled', 'disabled']);
});

test('AI 步：ok + over-budget 两包 → 这一步仍 exit 0，脚本被调的次数=包数、--status 一份一包', () => {
  const r = runAiStep({ plan: { 'demo.zip': { status: 'ok' }, 'evil.zip': { status: 'over-budget' } } });
  // 这一条就是 §0.2-2：分流那一步挂的是 found==true、没有 always()，
  // AI 步先红会把 triage 整个跳过 —— 五态文案永远出不来、PR 上一片沉默。
  assert.equal(r.code, 0, `非 ok 的状态不许在 AI 步开火（红由 triage 一处在判据那层产出）。stderr=${r.stderr}`);
  assert.equal(r.calls.length, 2, '假脚本被调用的次数必须= 包数：last-wins 的写法会只跑一包或只留一份状态');
  assert.deepEqual(r.status, {
    'ai-demo.zip.status': 'ok',
    'ai-evil.zip.status': 'over-budget',
  });
  const statusArgs = r.calls.map((a) => argOf(a, 'status'));
  assert.equal(new Set(statusArgs).size, 2, `--status 必须互不相同（收到的是 ${statusArgs.join(' / ')}）`);
  for (const [i, base] of ['demo.zip', 'evil.zip'].entries()) {
    assert.equal(statusArgs[i], `audit-out/ai-${base}.status`, '状态文件名 = ai-<zip basename>.status，含 .zip');
    assert.equal(argOf(r.calls[i], 'report'), `audit-out/${base}.audit.json`,
      '报告按 zip 名定位；ls -t|head -n1 会把 A 包配上 B 包的报告');
    assert.equal(argOf(r.calls[i], 'zip'), `audit-out/zips/${base}`);
    assert.equal(argOf(r.calls[i], 'out'), `audit-out/ai-${base}.json`);
  }
});

test('AI 步：QCA_PROMPT_SHA 未设=record-only，设了才透传 --expected-prompt-sha', () => {
  const bare = runAiStep({ plan: { 'demo.zip': { status: 'ok' } }, zips: ['demo.zip'] });
  assert.equal(bare.code, 0, bare.stderr);
  assert.equal(argOf(bare.calls[0], 'expected-prompt-sha'), undefined,
    '未设时不许塞空串：空串会被脚本当「设了但对不上」，把 record-only 变成配置错误');
  const pinned = runAiStep({ plan: { 'demo.zip': { status: 'ok' } }, zips: ['demo.zip'], promptSha: 'ab12' });
  assert.equal(pinned.code, 0, pinned.stderr);
  assert.equal(argOf(pinned.calls[0], 'expected-prompt-sha'), 'ab12');
});

test('AI 步：脚本 exit 2 且没写状态文件 → 这一步自己红，文案指名 prompt 分叉/配置错误', () => {
  const r = runAiStep({ plan: { 'demo.zip': { noWrite: true, exit: 2 }, 'evil.zip': { status: 'ok' } } });
  // 「运行了但状态不好」与「这一层根本没运行」不是一回事：后者只能由本步自己红。
  assert.notEqual(r.code, 0, '没写出状态文件时必须本步红，否则下游拿到的是没有 AI 意见的判据');
  assert.match(r.errors, /demo\.zip/, '要点名是哪一包');
  assert.match(r.errors, /分叉|配置错误/, 'prompt 分叉是运维错，不是模型跑败：混成一句就把人指去查供应商');
  assert.doesNotMatch(r.errors, /没跑成/, '「没跑成」是分流里 failed 那句串，AI 步不许提前用掉它');
});

test('AI 步：脚本崩溃（非 0 也非 2、没写状态）→ 同一条收口红，但不许说成 prompt 分叉', () => {
  const r = runAiStep({ plan: { 'demo.zip': { noWrite: true, exit: 1 }, 'evil.zip': { status: 'ok' } } });
  assert.notEqual(r.code, 0);
  assert.match(r.errors, /demo\.zip/);
  assert.match(r.errors, /状态文件/);
  assert.doesNotMatch(r.errors, /分叉/, '退出码 1 不是配置错误那条路；把两种病写成一句，运维就只能猜');
});

test('AI 步的形状：node 那发必须自带 `|| CODE=$?`、收口认全五态、if 仍挂 found（不许 always()）', () => {
  const { region } = extractStep(AI_STEP);
  const { text } = extractStep(AI_STEP);
  // 「非 ok 不在本步开火」这条规矩（§0.2-2）的兑现位置是**调用点**，不是脚本头的 `set` 行：
  // runner 把 `shell: bash` 展开成 `bash --noprofile --norc -e -o pipefail`（2026-10-16 run
  // 38904316355 实测），那个 `-e` 是它给的，脚本里写 `set -uo pipefail` 撤不掉。
  // 所以这里断言的是「预期会非 0 的那一发有没有带 `||`」——带了就收进 CODE，没带就是整步打断。
  assert.doesNotMatch(text, /set -eu/, '本步不额外加 -e：非 ok 的红由 分流决策 在判据那层开火');
  assert.match(text, /set -u/, 'set -u 要留着：拼错的变量名不该静默成空串（CODE 归零那条也靠它兜）');
  assert.ok(text.includes('node "$AI" "${ARGS[@]}" || CODE=$?'),
    '裸 `node` + 下一行 `CODE=$?` 在线上等于「第一个非 0 退出码当场打断整步」：CODE 来不及收，收口与 triage 一起没了');
  const nodeLine = text.split('\n').find((l) => l.includes('node "$AI" "${ARGS[@]}" || CODE=$?'));
  const bodyIndent = nodeLine.length - nodeLine.trimStart().length;
  assert.match(text, new RegExp(`^ {${bodyIndent}}CODE=0$`, 'm'),
    '每包归零，且必须与那发 node 同缩进（hoist 到 while 之外 = 又回到「上一包的退出码当成这一包的」）：'
    + '`||` 只在失败那发赋值，不归零还是 set -u 下的未绑定变量');
  assert.match(text, /disabled\|ok\|failed\|untrusted\|over-budget/,
    '收口的 case 必须含 over-budget：M1 之后脚本会真写它，漏了就是把合法状态判成非法（§0.2-1）');
  assert.match(region, /^ {8}if: steps\.locate\.outputs\.found == 'true'$/m,
    'found=false 时既没有 zip 也没有报告，放宽这条会让每个维护类 PR 都红');
  assert.doesNotMatch(region, /^ {8}if:.*always\(\)/m,
    '这一步不靠 always() 兜底跑完：红由 分流决策 开火，不靠把失败洗成继续跑');
  assert.doesNotMatch(region, /continue-on-error/);
  assert.doesNotMatch(text, /\|\|\s*true/, '|| true 会把收口一起吞掉：这是变异②的形状');
  assert.match(text, /CODE=\$\?/, '退出码先收进变量，不当场开火');
});

test('耦合钉子：AI 步与 分流决策 的步骤级 if 必须逐字相同（「零状态文件」那条绿分支全靠它撑着）', () => {
  // 分流里有一条**故意写绿**的分支：audit-out 里一个 ai-*.status 都没有 ⇒ 等级不动、
  // 文案「这一步没有产物」，low+first 照旧 auto-approve。它唯一的理由是
  // **AI 步先红会把 triage 整步跳过**（两步挂同一个 if、都没有 always()）。
  // 有人给 AI 步加开关（如 vars.AI_REVIEW_ENABLED）或给 triage 加 always() 之后，
  // 「没过 AI 也能自动合」会继续绿着，只多一句诚实文案。这里不改判据
  //（disabled 今天同样不抬级，那是用户认下的运维态），只把这个前提钉成事实。
  const ifOf = (name) => {
    const { region } = extractStep(name);
    // 只认 YAML 键位（行首 8 空格），不认全文：这一步的**注释里就写着「没有 always()」**，
    // 拿 /always\(\)/ 断言会被自己的注释打红（我第一发就是这么红的）。
    assert.doesNotMatch(region, /^ {8}if:.*always\(\)/m,
      `「${name}」的步骤级 if 不许挂 always()：那会把上一步的失败洗成继续跑`);
    assert.doesNotMatch(region, /^ {8}continue-on-error:/m, `「${name}」不许 continue-on-error：同上`);
    const hits = region.match(/^ {8}if: .*$/gm) || [];
    assert.equal(hits.length, 1, `「${name}」应当恰好一条步骤级 if，实到 ${hits.length} 条：${hits.join(' / ')}`);
    return hits[0];
  };
  const aiIf = ifOf(AI_STEP);
  const triageIf = ifOf('分流决策');
  assert.match(aiIf, /^ {8}if: steps\.locate\.outputs\.found == 'true'$/, `AI 步的 if 形状变了：${aiIf}`);
  assert.equal(triageIf, aiIf, '两步的步骤级 if 必须逐字相同：AI 步先红时 triage 必须整个被跳过，'
    + '否则「没有 AI 产物」这条路会在没人改判据的情况下自己活过来');
});

test('locate 探 ai-review.mjs 的候选与 scanner 同形状，并多输出一个 ai_review', () => {
  const wf = fs.readFileSync(WF, 'utf8').replace(/\r\n/g, '\n');
  const start = wf.indexOf('- name: 定位投稿元数据');
  const end = wf.indexOf('- name: pending 凭据与来源复核');
  assert.ok(start >= 0 && end > start, 'locate 步要能切出来');
  const locate = wf.slice(start, end);
  assert.match(locate, /AI_REVIEW_CANDIDATES=\("contrib\/audit\/ai-review\.mjs" "audit\/ai-review\.mjs"\)/,
    'monorepo 形态的候选');
  assert.match(locate, /AI_REVIEW_CANDIDATES=\("audit\/ai-review\.mjs" "contrib\/audit\/ai-review\.mjs"\)/,
    '索引仓库在根时的候选；两条都在 = 与 SCANNER_CANDIDATES 同形状，不是硬编');
  assert.match(locate, /echo "ai_review=\$AI_REVIEW" >> "\$GITHUB_OUTPUT"/);
});

/* --------------------------------------------------------------- 五态矩阵（分流侧真跑） */

test('矩阵·disabled：等级不动、action 不变、文案是「未启用」那句', () => {
  const { kv, err } = runTriage({ 'demo.zip': rep('low', 'first') }, { 'demo.zip': 'disabled' });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.risk, 'low');
  assert.equal(kv.action, 'auto-approve');
  assert.match(kv.ai_note, /未启用/);
  assert.doesNotMatch(kv.ai_note, /同意|复验/, '没跑过的层不许冒充跑过');
});

test('矩阵·failed：分流整步 exit 1，文案「没跑成」，判据留下但只有 fail-closed 那一个方向', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'failed', artifact: aiArt('demo.zip', { status: 'failed', reason: '模型调用失败：超时' }) } });
  assert.notEqual(err, null, 'failed 必须是红，不是「AI 没意见所以按静态放行」');
  assert.match(stderr, /没跑成/);
  assert.match(stderr, /demo\.zip/, '要点名是哪一包');
  assertFailClosed(kv);
  // 静态明明说 low，而这一轮没有结论 ⇒ risk 留空。写成 low 会让评论层落进「风险虽低但含版本更新」
  // 那句（说的是另一件事），写成 high 则是把平台故障算到投稿者头上（§2.7 文案纪律）。
  assert.equal(kv.change_type, 'first', 'changeType 是报告里的事实，与 AI 跑没跑成无关');
  assert.equal(kv.package_count, '1');
  assert.match(kv.ai_note, /没跑成/);
  assert.match(kv.reasons, /模型调用失败：超时/, '被弃的原因要能进 output，不只活在会过期的 runner 日志里');
});

test('矩阵·untrusted：exit 1，文案「判据不可采信」，与 failed 那句不同串', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'untrusted', artifact: aiArt('demo.zip', { status: 'untrusted', reason: 'quote 未能逐字复验' }) } });
  assert.notEqual(err, null);
  assert.match(stderr, /判据不可采信/);
  assert.doesNotMatch(stderr, /没跑成/, '四句串各用各的：合并成一句就等于只剩一种下游后果（§0.1）');
  assertFailClosed(kv);
  assert.match(kv.ai_note, /判据不可采信/);
  assert.doesNotMatch(kv.ai_note, /没跑成/, '同一句话进了 output 也还是不许并串');
});

test('矩阵·over-budget：exit 1，那句含「没看全」，绝不含「同意静态结论」', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first'), 'evil.zip': rep('low', 'first') },
    { 'demo.zip': 'disabled',
      'evil.zip': { status: 'over-budget', artifact: aiArt('evil.zip', { status: 'over-budget', reason: '需要 90000 B，预算 60000 B' }) } });
  assert.notEqual(err, null);
  assert.match(stderr, /没看全/);
  // 工单要求「不含同意」。字面断 !includes('同意') 做不到 —— over-budget 那句本身就该含
  // 「不是它同意，是没看全」（§1 第 2 步），所以钉子钉在「不许声称模型同意」那一侧。
  assert.doesNotMatch(stderr, /同意静态结论|模型同意|AI 全部看过/);
  assertFailClosed(kv);
  // 这一格原来钉的是 `ai_note === undefined`（「判据不成立时连文案都不许留下」）。G.2 把它反过来：
  // 文案正是这一发唯一能送到投稿者眼前的东西。要钉的是它**不许声称模型同意**，
  // 以及两包都是 low+first 时 risk 仍然留空 —— 「没结论」与「量出来是 low」是两句话。
  assert.match(kv.ai_note, /送不全/);
  assert.doesNotMatch(kv.ai_note, /同意静态结论|模型同意|AI 全部看过/);
  assert.doesNotMatch(stderr, /未启用/, '送不全不是未启用：那是运维没配凭据');
  assert.equal(kv.package_count, '2');
  assert.equal(kv.change_type, 'first');
});

test('矩阵·ok+raise：静态 low+first、模型 high → action 不再是 auto-approve（整层的存在理由）', () => {
  const { kv, err } = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: false, risk: 'high', findings: [aiHit('high', 'install.sh 里那条 rm -rf')] }) },
  });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.risk, 'high', 'AI 的结论必须参与定级，只进文案就是装饰（计划 §4 F1）');
  assert.notEqual(kv.action, 'auto-approve', '这一条变了，整层的承诺就没了');
  assert.equal(kv.action, 'block');
  assert.equal(kv.needs_human_review, 'true');
  assert.match(kv.ai_note, /不同意静态结论/);
  assert.match(kv.ai_note, /high/);
});

test('矩阵·ok + agree:false 但抬不动：静态已是 high，文案不许声称「同意静态结论」', () => {
  // 2026-10-16 CI run 38890758068 实测到的假陈述：产物里 agree:false、5 条 findings 全 high，
  // 而静态本来就是 high ⇒ raiseLevel 抬不动 ⇒ changed=false ⇒ 落到「同意静态结论，等级未抬」那一句。
  // 「没抬」是效果，「同意」是立场，两件事不能共用一个分支。
  const { kv, err } = runTriage({ 'demo.zip': rep('high', 'first') }, {
    'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: false, risk: 'high', findings: [aiHit('high', '下载后执行')] }) },
  });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.risk, 'high');
  assert.equal(kv.action, 'block');
  assert.match(kv.ai_note, /^AI 安全员已复核（每条引用都逐字复验过送出去的那一份原文）：不同意静态结论/,
    'agree:false 就是不同意；抬不动不等于同意');
});

test('矩阵·ok + agree:true 且未抬级：那一句仍然照旧写「同意静态结论」（加上一格时必须留着这一句）', () => {
  const { kv, err } = runTriage({ 'demo.zip': rep('high', 'first') }, {
    'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: true, risk: 'high', findings: [aiHit('medium', '只是提示')] }) },
  });
  assert.equal(err, null, err && err.stderr);
  assert.match(kv.ai_note, /：同意静态结论，等级未抬/,
    '模型真的同意时这句是准确的，不许被上一格一起改掉');
});

test('矩阵：抬级是逐包算的，另一包的静态等级仍一起进「取最严」', () => {
  const { kv } = runTriage({
    'a.zip': rep('low', 'first'),
    'b.zip': rep('medium', 'first'),
  }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: false, risk: 'high' }) },
    'b.zip': { status: 'ok', ...aiArt('b.zip', { agree: true }) },
  });
  assert.equal(kv.risk, 'high');
  assert.equal(kv.package_count, '2', '多包语义不许退回单包（变异哨兵会先红）');
  assert.equal(kv.action, 'block');
});

test('矩阵·混合 disabled + ok：按「有 N 包没有 AI 意见」呈现，不许写成全都看过', () => {
  const { kv, err } = runTriage({
    'a.zip': rep('low', 'first'),
    'b.zip': rep('low', 'first'),
  }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: true }) },
    'b.zip': 'disabled',
  });
  assert.equal(err, null, err && err.stderr);
  assert.match(kv.ai_note, /没有 AI 意见/);
  assert.match(kv.ai_note, /1 包/);
  assert.doesNotMatch(kv.ai_note, /全都看过|每包都/, '混合形态不许被洗成「AI 复核过了」');
});

test('矩阵：一包 ok 抬级、另一包 failed → 仍然红，红的是 failed 那一包', () => {
  const { kv, err, stderr } = runTriage({
    'a.zip': rep('low', 'first'),
    'b.zip': rep('low', 'first'),
  }, {
    'a.zip': { status: 'ok', ...aiArt('a.zip', { agree: false, risk: 'high' }) },
    'b.zip': 'failed',
  });
  assert.notEqual(err, null, '任何一包没跑成都不是「其余包按静态定级就行」');
  assert.match(stderr, /没跑成/);
  assert.match(stderr, /b\.zip/);
  assertFailClosed(kv, 'a.zip 抬到 high 这件事不许变成结论：');
  // 这一发最容易写错的地方：a.zip 真的 ok 且真的抬到了 high，于是「顺手把算出来的等级填进去」
  // 看起来很合理 —— 但整轮没有结论（b.zip 没跑成），填进去就是把半份定级说成定级。
  assert.equal(kv.risk, '');
  assert.match(kv.ai_note, /没跑成/);
  assert.match(kv.ai_note, /b\.zip/);
});

test('矩阵：一个 ai-*.status 都没有 → 等级不动，文案说「这一步没有产物」，不是旧的「已跳过 LLM 复核」', () => {
  const { kv, err } = runTriage({ 'demo.zip': rep('low', 'first') });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.action, 'auto-approve', 'found=true 但 AI 层没产物时，静态判据照旧（旧 12 发就靠这条活着）');
  assert.match(kv.ai_note, /没有产物/);
  assert.doesNotMatch(kv.ai_note, /已跳过 LLM 复核|未配置 AI_API_KEY/);
});

/* --------------------------------------------------------------- 口径钉子（basename / 状态值） */

test('口径钉子：状态名里把 .zip 去掉了 → 分流立刻红，不许悄悄退成「未启用」', () => {
  // 两侧各自的 basename 口径漂一个「.zip」，就是这份产物与那份报告配不上对。
  // 危险的形态是它绿：triage 读不到 ai-*.status，退到「这一步没有产物」，
  // 等级照旧 low、action 照旧 auto-approve —— 投稿者白得一次 AI 层不参与的放行。
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first') }, undefined,
    { rawStatus: { 'ai-demo.status': 'ok' } });
  assert.notEqual(err, null, '对不上口径必须红');
  assert.match(stderr, /口径|对不上/);
  assert.match(stderr, /ai-demo\.status/);
  assertFailClosed(kv);
  assert.match(kv.ai_note, /口径|对不上/, '漂了哪一个文件名要能在 output 里读到');
  assert.equal(kv.package_count, '1', 'ai-demo.status 不是 ai-demo.zip.status ⇒ 报告仍是一份');
});

test('口径钉子：另一包没有对应的 ai-*.status → 红（缺状态不等于没配凭据）', () => {
  const { err, stderr } = runTriage({
    'a.zip': rep('low', 'first'),
    'b.zip': rep('low', 'first'),
  }, { 'a.zip': 'disabled' });
  assert.notEqual(err, null, '有产物、但覆盖不全 —— 那是 AI 步的收口坏了，不是「未启用」');
  assert.match(stderr, /b\.zip/);
});

test('状态文件里写了五态之外的值 → 红，并点名是哪个值', () => {
  const { err, stderr, kv } = runTriage({ 'demo.zip': rep('low', 'first') }, undefined,
    { rawStatus: { 'ai-demo.zip.status': 'succeeded' } });
  assert.notEqual(err, null);
  assert.match(stderr, /不是五态之一/);
  assert.match(stderr, /succeeded/);
  assertFailClosed(kv);
  assert.match(kv.ai_note, /不是五态之一/);
  assert.match(kv.ai_note, /succeeded/, '认不出的那个值要念出来，否则运维不知道该改哪一格配置');
});

test('ok 但产物读不到 / 产物与状态不一致 / 产物指向别的包 → 三发都红', () => {
  const noArt = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'ok', artifact: null } });
  assert.notEqual(noArt.err, null, '状态说 ok、产物却不在，那就没有「逐字复验过」这回事');
  assert.match(noArt.stderr, /产物/);
  assertFailClosed(noArt.kv);

  const mismatch = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', artifact: aiArt('demo.zip', { status: 'failed' }) },
  });
  assert.notEqual(mismatch.err, null, 'status 文件说 ok、产物 JSON 说 failed：两份不一致时按红处理');
  assert.match(mismatch.stderr, /不一致/);
  assertFailClosed(mismatch.kv);

  const otherPkg = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', artifact: aiArt('demo.zip', { target: { zip: 'x.zip', report: 'audit-out/other.zip.audit.json' } }) },
  });
  assert.notEqual(otherPkg.err, null, 'A 包配 B 包的产物 = F7 那个错法的产物版');
  assert.match(otherPkg.stderr, /别的包|不一致/);
  assertFailClosed(otherPkg.kv);
  assert.equal(otherPkg.kv.module_id, 'demo', '这一发报告读成了，id 是事实位，照报');
});

/* --------------------------------------------------------------- 判据实现只许有一份 */

test('raiseLevel 从 base 里那份 ai-review.mjs 拿：两种落地形态的候选都要命中', () => {
  const shot = (moduleAt) => runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: false, risk: 'high', findings: [aiHit('high', '抬一发')] }) },
  }, { moduleAt }).kv;
  assert.equal(shot('audit').risk, 'high', '索引仓库在根：audit/ai-review.mjs');
  assert.equal(shot('contrib/audit').risk, 'high', 'monorepo 形态：contrib/audit/ai-review.mjs（候选探测，不是硬编）');

  const none = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: false, risk: 'high' }) } }, { module: false });
  assert.notEqual(none.err, null, 'ok 却拿不到 raiseLevel 的实现时宁可红，不许把抬级这一步省掉');
  assert.match(none.stderr, /ai-review\.mjs/);
});

test('AI 的 findings 并进 reasons：带「AI 复核：」前缀，条数≤10、单条≤200 的旧封口保留', () => {
  const long = 'x'.repeat(500);
  const findings = Array.from({ length: 15 }, (_, i) => aiHit('medium', `第 ${i} 条 ${i === 0 ? long : ''}`));
  const { kv } = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', ...aiArt('demo.zip', { agree: false, risk: 'medium', findings }) },
  });
  const parts = kv.reasons.split('；').filter((s) => s.startsWith('AI 复核：'));
  assert.equal(parts.length, 10, '自由文本进评论前的第三根柱子：条数封口');
  for (const p of parts) assert.ok(p.length <= 'AI 复核：'.length + 200, `单条被截到 200 以内，实际 ${p.length}`);
});

test('判自动放行只许一处：TRIAGE_JS 里 "auto-approve" 与「low+first」判据各只出现一次', () => {
  assert.equal((TRIAGE_JS.match(/"auto-approve"/g) || []).length, 1,
    'action 一律由 decide(risk, changeType) 重算；多一处字面量就是有人另开了一扇门');
  assert.equal((TRIAGE_JS.match(/===\s*"first"/g) || []).length, 1, '自动放行的判据只许在 decide 里算一次');
  assert.match(TRIAGE_JS, /=decide\(/);
  // 钉**调用点**（`=decide(`）而不是 `decide(`：writeFailClosed 上面那段注释里合法地写着
  // 「这三格永远不过 decide()」，扫关键字会把自己的说明当成第二个调用点打红 —— 与本文件那条
  // 「耦合钉子」被自己的注释打红是同一个坑，不踩第二次。
  assert.equal((TRIAGE_JS.match(/=decide\(/g) || []).length, 1,
    'decide() 只许被调用一次（绿那一发）：红那一发的处置是 writeFailClosed 里写死的三格，不过决策矩阵');
  assert.match(TRIAGE_JS, /w\("action","block"\); w\("label","needs-human-review"\); w\("needs_human_review","true"\);/,
    'fail-closed 那三格必须是写死的字面量 —— 让它由任何函数算出来，就等于给「算错方向」留了位置');
});

/* --------------------------------------------------------------- 旧分支已死 */

test('旧分支已死：workflow 全文不再有 llm.json / 已跳过 LLM 复核 / 未配 AI_API_KEY', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  for (const s of ['llm.json', '已跳过 LLM 复核', '未配 AI_API_KEY']) {
    assert.ok(!wf.includes(s), `「${s}」还留在 workflow 里：那条分支是从旧写法抄来的，不是五态里的任何一个`);
  }
  assert.doesNotMatch(wf, /AI_API_KEY/, '默认后端是 QCA：这一步不再读那个 key，留着就是给运维指错仓库配置');
});

test('旧两步已换成一步：id: mode 与 id: llm 都不存在，AI 步接管 found 条件', () => {
  const wf = fs.readFileSync(WF, 'utf8');
  assert.doesNotMatch(wf, /^ {8}id: mode$/m, '复核模式那一步的判断搬进了 AI 步的凭据闸');
  assert.doesNotMatch(wf, /^ {8}id: llm$/m);
  assert.ok(wf.includes('id: ai'));
  assert.equal((wf.match(/steps\.mode\.outputs/g) || []).length, 0, '不许再有步骤读那个已不存在的 output');
  assert.equal((wf.match(/steps\.llm\.outputs/g) || []).length, 0);
});

test('五态的四种「不是 ok」文案在分流里各占一句，互不复用', () => {
  const block = TRIAGE_REGION;
  for (const s of ['未启用', '没跑成', '判据不可采信', '送不全']) {
    assert.ok(block.includes(s), `缺「${s}」这条串`);
  }
});

/* --------------------------------------------------------------- 端到端：AI 步的产物喂给分流 */

test('端到端：AI 步写出的那批文件，分流按同一口径读得到（over-budget 那一发真的开火）', () => {
  const r = runAiStep({ plan: { 'demo.zip': { status: 'ok' }, 'evil.zip': { status: 'over-budget' } } });
  assert.equal(r.code, 0, r.stderr);
  installModule(r.dir);
  const { err, stderr, kv } = runTriage({}, undefined, { dir: r.dir, module: false });
  assert.notEqual(err, null, 'AI 步 exit 0 + 分流红 = §0.2-2 要求的分工');
  assert.match(stderr, /没看全/);
  assertFailClosed(kv);
  assert.match(kv.ai_note, /送不全/);
  assert.equal(kv.module_id, 'demo,evil', '这一发的报告是 AI 步真写出来的，事实位照报');
  assert.equal(kv.package_count, '2');
});

test('端到端：ok+agree:false 经 AI 步落盘后，分流的 action 从 auto-approve 变成 block', () => {
  const r = runAiStep({
    zips: ['demo.zip'],
    plan: {
      'demo.zip': { status: 'ok', artifact: { agree: false, risk: 'high', findings: [aiHit('high', '端到端抬一级')] },
      },
    },
  });
  assert.equal(r.code, 0, r.stderr);
  installModule(r.dir);
  const { kv, err } = runTriage({}, undefined, { dir: r.dir, module: false });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.risk, 'high');
  assert.equal(kv.action, 'block', '这一发证明「AI 参与定级」不是测试里的夹具，而是 workflow 两步之间真的接上了');
  assert.match(kv.reasons, /AI 复核：端到端抬一级/);
});

/* ===========================================================================
 * T6.2 呈现层：「发布 PR 评论」（actions/github-script）是整条流水线唯一给人看的地方。
 * 工单 §0 的验收判据只有一条 —— 陌生人只读这条评论要能回答三件事：
 *   ① AI 这一层跑没跑；② 它对哪几包说了什么；③ 它实际被喂进去多少东西。
 * 做法与上面同构：把 workflow 里那段内联 JS 切出来**真跑**，用假的 github/context 接住
 * createComment 的 body。复制一份进测试就变成「测试钉住测试里那份」，workflow 可以随便漂。
 * ========================================================================= */

const COMMENT_STEP = '发布 PR 评论';
const FENCE = '`'.repeat(3);

/** 评论步能读到的 triage 输出 → env 键。这张表就是「写出处 / 消费处」那根接缝本身。 */
const ENV_OF = {
  risk: 'RISK', action: 'ACTION', label: 'LABEL', change_type: 'CHANGE_TYPE',
  ai_note: 'AI_NOTE', module_id: 'MODULE_ID', package_count: 'PACKAGE_COUNT', reasons: 'REASONS',
};

/** createComment 的桩：把收到的整条参数写进 captured.json，由外层读回来（正文要量长度）。 */
const COMMENT_RUNNER = [
  'const step = require("./step.cjs");',
  'const fs = require("fs");',
  'let captured = null;',
  'const github = { rest: { issues: { createComment: async (o) => { captured = o; return { status: 201 }; } } } };',
  'const context = { issue: { number: 7 }, repo: { owner: "tester", repo: "modules-repo" }, eventName: "pull_request" };',
  'const core = { info: (m) => console.log(String(m)), warning: (m) => console.warn(String(m)), setOutput: () => {} };',
  'step(github, context, core).then(',
  '  () => fs.writeFileSync("captured.json", JSON.stringify(captured || {})),',
  '  (e) => { console.error("COMMENT-STEP-THREW: " + (e && e.message ? e.message : String(e))); process.exit(1); },',
  ');',
  '',
].join('\n');

/**
 * 在临时 cwd 里真跑评论步。env 里 undefined/null 展开成空串 —— 与 GitHub 对
 * `${{ steps.x.outputs.不存在 }}` 的处理同形，所以「键名漂了」在这里就是拿到空串，不是拿不到变量。
 */
function runCommentStep(opts = {}) {
  // `js` 只给变异哨兵用：默认**每次现切**，所以测试里改坏的副本不可能被下一条用例捡到。
  const slice = opts.js === undefined ? extractStep(COMMENT_STEP, 'script') : { text: opts.js, region: '' };
  const dir = opts.dir || fs.mkdtempSync(path.join(TMP, 'comment-'));
  fs.mkdirSync(path.join(dir, 'audit-out'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'step.cjs'),
    `module.exports = async function step(github, context, core) {\n${slice.text}\n}\n`, 'utf8');
  fs.writeFileSync(path.join(dir, 'runner.cjs'), COMMENT_RUNNER, 'utf8');
  const env = { ...process.env };
  for (const [k, v] of Object.entries(opts.env || {})) env[k] = v === undefined || v === null ? '' : String(v);
  let err = null;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, ['runner.cjs'], {
      cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env,
    });
  } catch (e) { err = e; stdout = String(e.stdout || ''); }
  const capPath = path.join(dir, 'captured.json');
  const captured = fs.existsSync(capPath) ? JSON.parse(fs.readFileSync(capPath, 'utf8')) : null;
  return {
    err, captured, stdout, dir, region: slice.region, script: slice.text,
    body: captured ? String(captured.body === undefined ? '' : captured.body) : '',
    stderr: err ? String(err.stderr || '') : '',
  };
}

/** 默认静态报告正文：每包一个唯一标记，「逐包」就只能靠「三个标记都在正文里」来判。 */
const mdOf = (pkg) => `# 静态报告 ${pkg}\n\n标记-${pkg}\n`;

/**
 * 端到端：真跑 分流决策 拿 kv → kv 映射成评论步的 env → 真跑评论步。
 * reports / ai / rawStatus 的形状与 runTriage 一致；md = { 包名: 正文 }，null = 一份 .audit.md 都不写。
 */
function runCommentFrom({ reports, ai, md, rawStatus, env = {}, moduleAt } = {}) {
  const dir = fs.mkdtempSync(path.join(TMP, 'e2e-'));
  const t = runTriage(reports || {}, ai, { dir, rawStatus, moduleAt });
  const wanted = {};
  if (md !== null) {
    for (const pkg of Object.keys(reports || {})) wanted[pkg] = mdOf(pkg);
    Object.assign(wanted, md || {});
  }
  for (const [pkg, one] of Object.entries(wanted)) {
    fs.writeFileSync(path.join(dir, 'audit-out', `${pkg}.audit.md`), one, 'utf8');
  }
  const mapped = {};
  for (const [k, v] of Object.entries(ENV_OF)) mapped[v] = t.kv[k];
  // `steps.<id>.conclusion` 这几格由 GitHub 填，本地这条链跑不到 ⇒ 在这儿显式补成
  // 「上游全部跑成」的形状。评论步现在**只认 conclusion 判有没有结论**（见 T6.3），
  // 不补就会把每一发 T6.2 都渲染成「分流整步没跑」—— 那是渲染层的形状，不是这些用例要量的东西。
  const conclusions = {
    TRIAGE_CONCLUSION: 'success', PROOF_CONCLUSION: 'success',
    SCAN_CONCLUSION: 'success', AI_CONCLUSION: 'success', DISPOSE_CONCLUSION: 'success',
    // 这条链只跑到分流，台账那一格没参与 ⇒ 显式给一个「没命中」，
    // 否则评论会按「没有结论」那一支渲染，而 T6.2 量的是绿那一发的正文。
    DISPOSITION: 'clear', DISPOSITION_REASON: '',
  };
  const c = runCommentStep({ dir, env: { ...conclusions, ...mapped, ...env } });
  return { ...c, kv: t.kv, triageErr: t.err, triageStderr: t.stderr };
}

/** 正文里那行「逐包呈现（N 包 …）」；取块口径一漂，包数先在这里露出来（比数块数好读）。 */
const leadOf = (body) => (body.match(/逐包呈现（[^）]*）/u) || ['（正文里没有「逐包呈现」那行）'])[0];

/** 渲染契约：每包的静态块以 `<summary>静态报告 · <pkg>` 开头，取到下一个 `<summary>` 为止。 */
function mdBlockRegion(body, pkg) {
  const at = body.indexOf(`<summary>静态报告 · ${pkg}`);
  assert.ok(at >= 0, `正文里没有「静态报告 · ${pkg}」那一块`);
  const next = body.indexOf('<summary>', at + 1);
  return body.slice(at, next < 0 ? body.length : next);
}

/** 渲染契约：每包的 AI 块以 `<summary>AI 安全员 · <pkg>` 开头，取到下一个 `<summary>` 为止。 */
function aiBlockRegion(body, pkg) {
  const at = body.indexOf(`<summary>AI 安全员 · ${pkg}`);
  assert.ok(at >= 0, `正文里没有「AI 安全员 · ${pkg}」那一块：逐包 = 每包一块，不是整条 PR 一块`);
  const next = body.indexOf('<summary>', at + 1);
  return body.slice(at, next < 0 ? body.length : next);
}

/**
 * 渲染契约（工单 §2 Step 1）：每包一块静态 <details> + 一块 AI 围栏，块头点名是哪一包。
 * 按包切围栏而不是「把全文所有围栏都算上」—— 两包时才能测出 A 包配 B 包产物那种 last-wins。
 */
function aiBlockOf(body, pkg) {
  const m = aiBlockRegion(body, pkg).match(new RegExp(`${FENCE}json\\n([\\s\\S]*?)\\n${FENCE}`));
  assert.ok(m, `「AI 安全员 · ${pkg}」那一块里没有 ${FENCE}json 围栏`);
  return m[1];
}

/**
 * 一份**完整形状**的 AI 产物（字段照 ai-review.mjs 的 finish('ok', …)）：
 * 白名单内的都有值，白名单外的（reason / problem / target / generatedAt / schema / attempt）也都有值，
 * 这样「白名单之外的键一律不许进正文」才量得出来。
 */
const fullArt = (pkg, over = {}) => ({
  schema: 'ai-review/v1',
  generatedAt: '2026-10-15T00:00:00Z',
  target: { zip: `audit-out/zips/${pkg}`, report: `audit-out/${pkg}.audit.json` },
  onlyTightens: true,
  promptSha256: 'ab12'.repeat(16),
  status: 'ok',
  staticRiskLevel: 'low',
  backend: 'qca',
  model: 'qfmodel',
  attempt: 1,
  agree: false,
  risk: 'high',
  levelAfterAi: 'high',
  findings: [aiHit('high', '模型原话：install.sh 第 2 行')],
  brief: {
    byteSize: 4321, neededBytes: 54321, corpusFiles: 7, fileCount: 9, overBudget: false, emptyInput: false,
    omitted: [{ name: 'assets/big.bin', bytes: 9999, reason: 'over-budget:binary-meta' }],
    maxBytes: 60000,
    shapes: { textEntries: 5, binaryDigestEntries: 2, polyglotAsText: 1, nonTextRerouted: 0, forensicsRowsSent: 1 },
    sections: [120, 3000, 200, 1],
    budgetBasis: '保守字节代理，未做 token 标定',
  },
  meta: {
    backend: 'qca', model: 'qfmodel', agentId: 'agent_demo', agentVersion: 7, sessionId: 'sess_1',
    totalCredits: 3, activeSeconds: 12, eventId: 'evt_1', agentMessageCount: 1, eventPages: 1, eventPageSize: 100,
  },
  ...over,
});

/* --------------------------------------------------------------- ① 逐包（工单 §2.1） */

test('T6.2·逐包：三份 .audit.md 都出现在正文里、各占一块，旧的「共 N 份里的这 1 份」必须消失', () => {
  const pkgs = ['a.zip', 'b.zip', 'c.zip'];
  const reports = {};
  for (const p of pkgs) reports[p] = rep('low', 'first', { id: p.replace(/\.zip$/, '') });
  const r = runCommentFrom({ reports });
  assert.equal(r.triageErr, null, r.triageStderr);
  assert.equal(r.err, null, `评论步本身不许抛：${r.stderr}`);
  for (const p of pkgs) {
    assert.ok(r.body.includes(`标记-${p}`), `${p} 的静态报告没进正文：只贴 files[0] 就是本轮要补的那笔欠账`);
    assert.ok(r.body.includes(`<summary>静态报告 · ${p}`), `${p} 没有自己那一块 <details>`);
  }
  assert.equal(r.kv.package_count, '3');
  assert.match(r.body, /逐包呈现（3 包/, '包清单 = 报告数：产物名与取块口径漂了就多出一包幽灵');
  assert.doesNotMatch(r.body, /这一包没有/, '一致的目录形状里不许出现「这一包没有 .audit.md」那种幽灵块');
  assert.ok((r.body.match(/<details>/g) || []).length >= 6, '逐包 = 每包一块静态 + 一块 AI，三包至少六块');
  assert.doesNotMatch(r.body, /份投稿里的这 1 份|其余见 workflow artifact/,
    '这句旧文案承认「另外几份只存在于 artifact」；本轮补成逐包之后它必须消失');
  assert.doesNotMatch(r.script, /files\[0\]/, '正文按包循环，不再挑排序后的第一份');
});

test('T6.2·逐包·混合：一包有产物、一包 disabled 时两块各说各的，不许把 disabled 洗成「也复验过了」', () => {
  // disabled 在 CI 里的真实形状是**只有 status、没有产物 JSON**（AI 步的凭据闸直接 continue），
  // 所以夹具也得写成 artifact:null —— 否则测的是「产物与状态并存」那一种，幽灵包那一发就漏过去了。
  const r = runCommentFrom({
    reports: { 'a.zip': rep('low', 'first'), 'b.zip': rep('low', 'first') },
    ai: { 'a.zip': { status: 'ok', artifact: fullArt('a.zip') }, 'b.zip': { status: 'disabled', artifact: null } },
  });
  assert.equal(r.triageErr, null, r.triageStderr);
  assert.match(r.body, /逐包呈现（2 包/, '包清单要与报告同源：幽灵包 = 把同一包拆成两块');
  assert.doesNotMatch(r.body, /这一包没有/, '一致的目录形状里不许出现「这一包没有 .audit.md」那种幽灵块');
  assert.equal(JSON.parse(aiBlockOf(r.body, 'a.zip')).status, 'ok');
  const bBlock = aiBlockRegion(r.body, 'b.zip');
  assert.match(bBlock, /本轮没有 AI 产物/, 'disabled 那一包要写明没有产物，不许留空');
  assert.match(bBlock, /disabled/, '要看得出是「未启用」而不是「跑败了」');
  assert.ok(!bBlock.includes(FENCE), 'b 包那一块里不许出现 json 围栏：没有产物就没有可呈现的东西');
  assert.ok(r.body.indexOf('<summary>AI 安全员 · b.zip') > r.body.indexOf('<summary>AI 安全员 · a.zip'),
    '两包两块（同一块里既写 a 又写 b = 按整条 PR 呈现，不是逐包）');
});

/* --------------------------------------------------------------- ② AI 块存在且有界 */

test('T6.2·budgetBasis 的真位置：产物只在 brief 里写它，评论顶层不许写 null', () => {
  // 2026-10-16 拿 run 38890758068 的 artifact 重放评论步时量出来的：顶层 `"budgetBasis": null`，
  // 而真字符串就在同一条 JSON 的 `brief.budgetBasis` 里。`ai-review.mjs` 从来只在 brief 里写它
  // （`BUDGET_BASIS` 进 `briefMeta`），所以顶层那一句 `strOf(a.budgetBasis)` 永远是空 ——
  // 而键集用例只钉「这个键在不在」，钉不出「这个键有没有值」。
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'ok', artifact: fullArt('demo.zip') } },
  });
  assert.equal(r.err, null, `评论步本身不许抛：${r.stderr}`);
  const block = JSON.parse(aiBlockOf(r.body, 'demo.zip'));
  assert.equal(block.budgetBasis, '保守字节代理，未做 token 标定',
    '顶层那一格必须带上真值：读者先看顶层，写 null 等于说「这条闸没有依据」，而依据一直都在');
  assert.equal(block.budgetBasis, block.brief.budgetBasis,
    '同一个值两个面必须同源 —— 不许顶层一个空串、brief 里一个真值');
});

test('T6.2·AI 块：有 ai-<zip>.json 时正文出现该包的围栏，可核验键一个都不许少', () => {
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'ok', artifact: fullArt('demo.zip') } },
  });
  assert.equal(r.err, null, `评论步本身不许抛：${r.stderr}`);
  // 取块口径钉子（§5 那一问）：包数必须等于报告数。产物名与评论步的取块漂一个「.zip」时，
  // 同一包会被拆成两块（一块真有围栏、一块写「本轮没有 AI 产物」）—— 包数先涨，这一发先红。
  assert.match(leadOf(r.body), /^逐包呈现（1 包/, leadOf(r.body));
  const block = JSON.parse(aiBlockOf(r.body, 'demo.zip'));
  // 工单 §2.1-2 点名的这几项：少了任何一项，「它实际被喂进去多少东西」就答不上来。
  for (const k of ['status', 'levelAfterAi', 'promptSha256', 'brief']) {
    assert.ok(k in block, `围栏里少了 ${k}`);
  }
  for (const k of ['neededBytes', 'omitted', 'shapes', 'sections', 'byteSize', 'corpusFiles', 'overBudget']) {
    assert.ok(k in block.brief, `brief 里少了 ${k}`);
  }
  assert.equal(block.levelAfterAi, 'high');
  assert.equal(block.brief.neededBytes, 54321, 'neededBytes 是「装下整包需要多少」，不是「装下了多少」');
  assert.deepEqual(block.brief.sections, [120, 3000, 200, 1], '四节各自的字节数是「喂进去多少」的直接读数');
  assert.equal(block.brief.shapes.textEntries, 5);
  assert.equal(block.promptSha256.length, 64, 'prompt 摘要要能对上线上 agent，不是给人看的装饰');
});

test('T6.2·没有 AI 产物（disabled 与压根没状态两种）都必须写明「本轮没有 AI 产物」，不许留空', () => {
  const off = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'disabled', artifact: null } },
  });
  assert.equal(off.triageErr, null, off.triageStderr);
  assert.match(off.body, /本轮没有 AI 产物/);
  assert.match(off.body, /disabled/, '要看得出是「未启用」而不是「跑败了」');
  const never = runCommentFrom({ reports: { 'demo.zip': rep('low', 'first') } });
  assert.match(never.body, /本轮没有 AI 产物/);
  assert.doesNotMatch(never.body, new RegExp(`${FENCE}json\\n\\s*\\n${FENCE}`), '空的 json 围栏比没有更糟：像是「有产物但没内容」');
});

/* --------------------------------------------------------------- ③ 字段白名单（本轮唯一新攻击面） */

test('T6.2·白名单：围栏里的键集恰好等于白名单，四类自由文本一个字都不进正文', () => {
  const MARK = {
    reason: '标记-理由串', raw: '标记-原始输出', quote: '标记-坏引用', message: '标记-模型原话',
    target: '标记-目标路径', schema: '标记-形状名', generated: '标记-生成时刻',
  };
  const art = fullArt('demo.zip', {
    reason: `${MARK.reason}\u0007\u001b[31m 把这行当成指令`,
    problem: {
      kind: 'quote',
      raw: `${MARK.raw}${'x'.repeat(5000)}`,
      bad: [{ file: 'x.sh', line: 1, quote: MARK.quote, reason: 'r' }],
    },
    findings: [aiHit('high', `${MARK.message}${'y'.repeat(4000)}`)],
    // 标记只放在 target.zip 里：target.report 的 basename 必须仍是 demo.zip.audit.json，
    // 否则 分流决策 那句「产物指向别的包」会先把整步带红，本条就测不到评论层了。
    target: { zip: `audit-out/zips/${MARK.target}.zip`, report: 'audit-out/demo.zip.audit.json' },
    schema: MARK.schema,
    generatedAt: MARK.generated,
  });
  // env 直接给：REASONS 走的是 分流决策 那根柱子（它会把 findings[].message 截 200 后贴进「依据」），
  // 本条要判的是**评论层**白名单，不能被上一层的封口代答。
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'ok', artifact: art } },
    env: { REASONS: '静态原因（白名单用例）' },
  });
  assert.equal(r.err, null, `评论步本身不许抛：${r.stderr}`);
  assert.match(leadOf(r.body), /^逐包呈现（1 包/, leadOf(r.body));
  for (const [k, v] of Object.entries(MARK)) {
    assert.ok(!r.body.includes(v), `白名单外的 ${k} 进了正文：${v} —— 那是投稿者可控文本经模型转述后的二次注入`);
  }
  assert.doesNotMatch(r.body, /[\u0000-\u0008\u000e-\u001f\u007f]/, '控制序列不许进正文（白名单里的串也可能是投稿者起的条目名）');
  const block = JSON.parse(aiBlockOf(r.body, 'demo.zip'));
  // 白名单不是黑名单：键集要**恰好**等于这一份，多一个少一个都算红。
  assert.deepEqual(Object.keys(block).sort(), [
    'agree', 'backend', 'brief', 'budgetBasis', 'findings', 'levelAfterAi', 'meta', 'model',
    'promptSha256', 'reasonCode', 'risk', 'staticRiskLevel', 'status',
  ], '围栏里的键集必须恰好是白名单：多一个键就是又开一扇门');
  assert.deepEqual(Object.keys(block.findings[0]).sort(), ['file', 'line', 'ruleId', 'severity'],
    'findings 每条只取这四个键；message 是模型转述的投稿者可控文本，评论层不许依赖上游消毒过');
  assert.equal(block.status, 'ok', '白名单内的可核验字段照旧要出现（不许用「什么都不贴」来过这条）');
  assert.equal(block.levelAfterAi, 'high');
});

test('T6.2·封口抄 分流决策 那两根柱子：findings 条数 ≤10、单条 ≤200，评论层再封一次', () => {
  const long = 'z'.repeat(500);
  const art = fullArt('demo.zip', {
    findings: Array.from({ length: 15 }, (_, i) => aiHit('medium', `模型原话第 ${i} 条`,
      { ruleId: `R${i}-${long}`, file: `f/${i}-${long}.sh` })),
    brief: {
      ...fullArt('demo.zip').brief,
      omitted: Array.from({ length: 15 }, (_, i) => ({ name: `e/${i}-${long}`, bytes: i, reason: long })),
    },
    meta: { backend: 'qca', sessionId: long, eventId: long, agentVersion: 7 },
  });
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'ok', artifact: art } },
    env: { REASONS: '静态原因（封口用例）' },
  });
  assert.equal(r.err, null, r.stderr);
  const block = JSON.parse(aiBlockOf(r.body, 'demo.zip'));
  assert.equal(block.findings.length, 10, '条数封顶沿用 :833 的 slice(0,10)，不在这里发明第二份口径');
  assert.equal(block.brief.omitted.length, 10, 'omitted 同一条柱子');
  for (const f of block.findings) {
    for (const v of [f.ruleId, f.severity, f.file]) {
      assert.ok(String(v).length <= 200, `单条长度封顶 200，实到 ${String(v).length}`);
    }
  }
  for (const o of block.brief.omitted) assert.ok(String(o.name).length <= 200 && String(o.reason).length <= 200);
  for (const v of Object.values(block.meta)) if (typeof v === 'string') assert.ok(v.length <= 200, 'meta 里的串一样过封口');
});

/* --------------------------------------------------------------- ④ 总长有界 + 截断看得见 */

test('T6.2·总长有界：六包超大报告下正文仍 ≤60000，且被撤下的包要点名（不许静默变短）', () => {
  const reports = {};
  const md = {};
  const names = [];
  for (let i = 1; i <= 6; i += 1) {
    const p = `p${i}.zip`;
    names.push(p);
    reports[p] = rep('low', 'first', { id: `p${i}` });
    md[p] = `# 报告 ${p}\n${'内'.repeat(40000)}\n标记-${p}\n`;
  }
  const r = runCommentFrom({ reports, ai: {}, md });
  assert.equal(r.triageErr, null, r.triageStderr);
  assert.equal(r.err, null, r.stderr);
  assert.ok(r.body.length <= 60000,
    `GitHub 评论上限是 65536，正文实测 ${r.body.length}：超限那一发 createComment 会被 API 拒绝，PR 上直接没话`);
  assert.match(r.body, /已截断/, '单节超限要写出来，与 AUDIT_COVERAGE_TRUNCATED 同形');
  assert.match(r.body, /workflow artifact/, '要说清完整报告在哪');
  const shown = names.filter((p) => r.body.includes(`标记-${p}`));
  const hidden = names.filter((p) => !r.body.includes(`标记-${p}`));
  assert.ok(hidden.length > 0, '这一发的形状要真的把总上限顶到');
  for (const p of hidden) {
    assert.ok(r.body.includes(p), `${p} 被整块撤下却不点名 = 让人以为 AI 与静态对这一包没话说`);
  }
  assert.match(r.body, /未贴出/, '要有一句「这些包没贴出来」');
});

test('T6.2·长度量得出：最大合法产物与最小产物各量一次，都在界内', () => {
  const long = 'w'.repeat(200);
  const biggest = runCommentFrom({
    reports: { 'big.zip': rep('low', 'first', { id: 'big' }) },
    ai: {
      'big.zip': {
        status: 'ok',
        artifact: fullArt('big.zip', {
          findings: Array.from({ length: 10 }, (_, i) => aiHit('high', 'x', { ruleId: `R${long}`, file: long })),
          brief: {
            ...fullArt('big.zip').brief,
            omitted: Array.from({ length: 10 }, (_, i) => ({ name: long, bytes: 1, reason: long })),
          },
          meta: { sessionId: long, eventId: long, backend: 'qca', agentVersion: 7 },
        }),
      },
    },
    md: { 'big.zip': `# 大报告\n${'a'.repeat(80000)}\n` },
  });
  assert.equal(biggest.err, null, biggest.stderr);
  assert.ok(biggest.body.length <= 60000, `最大合法形状实测 ${biggest.body.length}，必须 ≤60000`);
  assert.ok(biggest.body.length > 8000, `每块的封顶要真的用上（实测 ${biggest.body.length} 太小，封顶没生效）`);

  const smallest = runCommentFrom({
    reports: { 'min.zip': rep('low', 'first', { id: 'min' }) },
    ai: { 'min.zip': { status: 'ok', artifact: { status: 'ok', agree: true, risk: null, findings: [] } } },
    md: { 'min.zip': '# 小报告\nok\n' },
  });
  assert.equal(smallest.err, null, smallest.stderr);
  assert.ok(smallest.body.length < 2500, `最小形状实测 ${smallest.body.length}：逐包与 AI 块都不该把短投稿撑成长评论`);
  assert.ok(smallest.body.length > 200, '短也要仍然是完整的一条（不是截没了）');
  // 最小合法产物（只有 status/agree/risk/findings）也要长成完整的白名单形状：缺的键写成 null，
  // 不是整个消失 —— 「这一发有没有 levelAfterAi」必须能从键集读出来，而不是靠猜。
  assert.deepEqual(Object.keys(JSON.parse(aiBlockOf(smallest.body, 'min.zip'))).sort(), [
    'agree', 'backend', 'brief', 'budgetBasis', 'findings', 'levelAfterAi', 'meta', 'model',
    'promptSha256', 'reasonCode', 'risk', 'staticRiskLevel', 'status',
  ]);
  assert.equal(JSON.parse(aiBlockOf(smallest.body, 'min.zip')).status, 'ok');
});

/* --------------------------------------------------------------- ⑤ 改名闭合 + 接缝 */

test('T6.2·改名闭合：ai_note 同时钉在写出处与消费处，workflow 全文再无 llm_note / LLM_NOTE', () => {
  const wf = fs.readFileSync(WF, 'utf8').replace(/\r\n/g, '\n');
  assert.match(TRIAGE_JS, /w\("ai_note",/, '写出处：triage 的 output 键名');
  const { region } = extractStep(COMMENT_STEP, 'script');
  assert.match(region, /^ {10}AI_NOTE: \$\{\{ steps\.triage\.outputs\.ai_note \}\}$/m, '消费处 1：env 的键与来源');
  assert.match(region, /process\.env\.AI_NOTE/, '消费处 2：插值处');
  for (const s of ['llm_note', 'LLM_NOTE']) {
    assert.ok(!wf.includes(s), `「${s}」还留在 workflow 里：只改一处的那一发会让那句文案永远拿到空串`);
  }
});

test('T6.2·接缝：分流写出的那句复核方式真的出现在正文里（键名漂一处就是空串）', () => {
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('low', 'first') },
    ai: { 'demo.zip': { status: 'ok', artifact: fullArt('demo.zip', { agree: false, risk: 'high' }) } },
  });
  assert.equal(r.triageErr, null, r.triageStderr);
  assert.match(r.kv.ai_note, /不同意静态结论/);
  assert.match(r.body, /复核方式：AI 安全员已复核/, '评论步读到的必须是 triage 写出的那一句，不是自己拼的第二份文案');
  assert.ok(r.body.includes(r.kv.ai_note), '正文里那句必须与 output 逐字相同（截断也算不上，两句要能对上）');
});


test('T6.2·折叠边界：依据与模块 id 里的 `</details>`、反引号、控制序列都不许把评论的结构拆掉', () => {
  // 复验 6.2 时发现的一格：白名单管住了 AI 产物里的自由文本，但 intro 那七行是**原样插值**的。
  // REASONS 与 MODULE_ID 都不是我们自己造的串 ——
  //   REASONS 里有 risk-rules 的 `trimSnippet`（实测只压空白、不转义 `<`，risk-rules.mjs:40-43），
  //   MODULE_ID 是 `module.prop` 里的 `id=`（投稿者写的）。
  // 于是「一行折叠正文 + 一句 `</details>`」就能在评论里提前关掉别人的块、再开一个自己的块，
  // 或者用反引号把 `- 模块 id：\`…\`` 那段内联代码提前闭合。
  // 判据不新发明封口：与本步 `seal()` 同一套思路（洗控制序列 + 把 `<`、`>`、反引号变成实体），
  // 只作用在评论自己的插值上，**不动**静态报告正文（那是 renderMarkdown 那一层的事，另账）。
  const reason = 'rm 清理 </details><img src=q onerror=alert(1)> ``` 伪造围栏 \u0001 结尾';
  const r = runCommentFrom({
    reports: { 'demo.zip': rep('medium', 'first', { reasons: [reason], id: 'a`</details>伪造' }) },
    ai: { 'demo.zip': { status: 'ok', artifact: {
      status: 'ok', agree: true, findings: [], brief: { byteSize: 10, shapes: {}, sections: [] },
    } } },
  });
  assert.equal(r.err, null, `评论步本身不许抛：${r.stderr}`);
  // 一块静态 + 一块 AI ⇒ 恰好两个 </details>。注入的那两句各自多带一个，红在这里。
  assert.equal((r.body.match(/<\/details>/g) || []).length, 2,
    `折叠标签数量必须恰好等于块数（多出来的就是投稿者写的）：\n${r.body}`);
  assert.equal((r.body.match(/<details>/g) || []).length, 2, '开标签同样只许来自我们自己');
  assert.ok(!/<img\b/.test(r.body), '注入的 <img> 不许原样出现在正文（渲染态就是可执行的标签）');
  assert.ok(!r.body.includes('\u0001'), '控制序列不许原样进评论');
  // 三处合法的 ```（AI 块一开一合）之外不许再多出围栏
  assert.equal((r.body.match(/```/g) || []).length, 2,
    '反引号围栏只许来自我们的 AI 块；依据/模块 id 里的反引号必须先变成实体');
  assert.match(r.body, /&lt;|&#96;/, '被中和之后仍然要看得见原文内容，不许直接删掉（删了就没人知道投稿者写了什么）');
});

/* =========================================================================
 * T6.3 呈现层的「本轮到底有没有结论」：success / failure / 整步没跑 三种形状
 *
 * 上面那批 T6.2 全部是**绿那一发**的渲染（等级、逐包块、白名单、围栏）。这一批钉的是
 * 判据红之后评论与标签**还要不要跑、跑起来说什么** —— 2026-10-17 把这两步放宽成
 * `!cancelled()` 之前欠的三件事，做完的凭据在这儿，不在 `if:` 那几行结构断言里：
 *   ①「分流整步被跳过」与「分流跑了但判不动」两种空**长得一样、意思相反**，
 *     只有 steps.triage.conclusion 分得开（run 39007438609 / 38908245528 各是其一，都是实测）；
 *   ② 没有结论那一发**不许念等级、不许念处置**，还要点名先红的是哪一步；
 *   ③ 依据条数、模块 id 个数、单条长度都过 seal（≤10 条 / 单条 ≤200），藏了多少要点名。
 * 绿那一发的三支分支（✅ / ⚠️ / ⛔）这里不重复钉 —— T6.2 已经钉过，重复一份只会多一处要同步的口径。
 * ========================================================================= */

const CONCL_OK = {
  TRIAGE_CONCLUSION: 'success', PROOF_CONCLUSION: 'success',
  SCAN_CONCLUSION: 'success', AI_CONCLUSION: 'success', DISPOSE_CONCLUSION: 'success',
};

/** 只渲染 intro 的那一发：不放 audit-out 里的报告，逐包那一节自然走「没有可贴出的报告」。 */
const introOnly = (over = {}) => runCommentStep({
  env: {
    ...CONCL_OK, DISPOSITION: 'clear', DISPOSITION_REASON: '',
    RISK: 'low', ACTION: 'auto-approve', LABEL: 'auto-approved', CHANGE_TYPE: 'first',
    AI_NOTE: 'AI 安全员已复核：同意静态结论', MODULE_ID: 'demo', PACKAGE_COUNT: '1',
    REASONS: '静态扫描未发现风险', ...over,
  },
});

const introLine = (body, prefix) => body.split('\n').find((l) => l.startsWith(prefix));

test('T6.3·分流判不动而红：等级明确写「没有等级」，处置照抄 fail-closed 的 block，绝不念「中/高风险」', () => {
  const { body } = introOnly({
    TRIAGE_CONCLUSION: 'failure', RISK: '', ACTION: 'block', LABEL: 'needs-human-review',
    REASONS: '分流决策异常：x is not iterable', AI_NOTE: '',
  });
  assert.match(body, /- 风险等级：\*\*（本轮没有等级：分流自己没过检）\*\* —— 这一格空着是判据，不是漏填/);
  assert.doesNotMatch(body, /（取本 PR 全部报告里最严的一份）/, '那句是绿那一发的口径；判不动这一发没量过等级，不配引用它');
  assert.match(body, /- 处置：\*\*`block`\*\*/);
  assert.match(body, /故障安全方向/);
  assert.doesNotMatch(body, /⛔ 中\/高风险|✅|⚠️ 风险虽低/);
  // 空 ai_note 不能渲染成一对空反引号：那读起来是「没人说过话」，不是「这一格没写」
  assert.match(body, /- 复核方式：（分流这一步没写出复核方式/);
});

test('T6.3·分流整步没跑（proof 先红）：没有等级、没有处置、没有依据，且点名先红的是哪一步', () => {
  const { body } = introOnly({
    TRIAGE_CONCLUSION: '', PROOF_CONCLUSION: 'failure',
    RISK: '', ACTION: '', LABEL: '', CHANGE_TYPE: '', REASONS: '', AI_NOTE: '', MODULE_ID: '',
  });
  assert.match(body, /本轮\*\*没有判据\*\*：分流决策这一步没有运行（先红的是「验 pending 凭据与来源复核」）/);
  assert.equal(introLine(body, '- 风险等级'), undefined, '这一发没有任何一格被人写过，念出来就是一句假陈述');
  assert.equal(introLine(body, '- 处置：'), undefined);
  assert.equal(introLine(body, '- 依据：'), undefined);
  assert.doesNotMatch(body, /⛔|✅|⚠️ 风险虽低|故障安全方向/);
  // 「没跑完」不等于「不通过」这句必须在，否则投稿者只会把这条读成被拒
  assert.match(body, /不是「低风险」，也不是「不通过」，是没量/);
});

test('T6.3·同一形状里换成 AI 步先红：点名的是 AI，不许错怪 proof', () => {
  const { body } = introOnly({
    TRIAGE_CONCLUSION: '', PROOF_CONCLUSION: 'success', AI_CONCLUSION: 'failure',
    RISK: '', ACTION: '', LABEL: '', REASONS: '', AI_NOTE: '', MODULE_ID: '',
  });
  assert.match(body, /先红的是「AI 安全员复核」/);
  assert.doesNotMatch(body, /先红的是「验 pending 凭据/);
});

test('T6.3·上游一格读数都没有：不瞎猜是谁红的', () => {
  const { body } = introOnly({
    TRIAGE_CONCLUSION: '', PROOF_CONCLUSION: '', SCAN_CONCLUSION: '', AI_CONCLUSION: '',
    DISPOSE_CONCLUSION: '', RISK: '', ACTION: '', LABEL: '', REASONS: '', AI_NOTE: '', MODULE_ID: '',
  });
  assert.match(body, /分流决策这一步没有运行。/);
  assert.doesNotMatch(body, /先红的是/);
});

test('T6.3·封口 1：依据 25 条只贴 10 条，剩下 15 条要点名（静默变短等于让人以为没人说过话）', () => {
  const reasons = Array.from({ length: 25 }, (_, i) => '原因 ' + (i + 1)).join('；');
  const { body } = introOnly({ REASONS: reasons });
  assert.match(introLine(body, '- 依据：'), /原因 10…（另有 15 条未列出/);
  assert.doesNotMatch(body, /原因 11/);
});

test('T6.3·封口 2：单条依据 500 字截到 200 —— 沿用本步那把 seal，不发明第二个口径', () => {
  const { body } = introOnly({ REASONS: '长'.repeat(500) });
  const line = introLine(body, '- 依据：');
  assert.ok(line.startsWith('- 依据：' + '长'.repeat(200)), '必须正好截在 200');
  assert.equal(body.includes('长'.repeat(201)), false);
});

test('T6.3·封口 3：模块 id 30 个只贴 10 个并点名余下 20 个', () => {
  const ids = Array.from({ length: 30 }, (_, i) => 'mod_' + i).join(',');
  const { body } = introOnly({ MODULE_ID: ids, RISK: 'high', ACTION: 'request-review', LABEL: 'needs-human-review' });
  assert.match(introLine(body, '- 模块 id：'), /mod_9`…（另有 20 个未列出/);
  assert.doesNotMatch(body, /mod_10/);
});

test('T6.3·台账命中那一发：分流写的是 auto-approve，评论必须改口成「被台账拦下」，不许念 ✅', () => {
  // disposition-check 命中时**不改退出码**（scripts/disposition-check.mjs:132-135 那条设计），
  // 所以这一发 audit 作业全绿、triage conclusion 是 success、ACTION 是 auto-approve ——
  // 红的是 approve（读 needs.audit.outputs.disposition == 'hit'）。
  // 评论要是只看 ACTION，就会对着一条被黑名单拦下的投稿念「已自动合入索引」。
  const { body } = introOnly({ DISPOSITION: 'hit', DISPOSITION_REASON: '模块 demo 在黑名单里（dispositions.json 第 2 条）' });
  assert.match(body, /⛔ 分流给出的是 auto-approve，但\*\*处置台账命中\*\*（下架或黑名单）：本 PR 不会合入/);
  assert.match(body, /- 台账说：模块 demo 在黑名单里/);
  assert.doesNotMatch(body, /✅/);
});

test('T6.3·台账没给出结论（读不懂时它 exit 3，output 是空的）：不声称已合入', () => {
  const { body } = introOnly({ DISPOSITION: '', DISPOSE_CONCLUSION: 'failure' });
  assert.match(body, /🛑 分流给出的是 auto-approve，但处置台账那一格\*\*没有结论\*\*/);
  assert.doesNotMatch(body, /✅|已自动合入/);
});

test('T6.3·只有 DISPOSITION=clear 才配得上那句 ✅', () => {
  const { body } = introOnly({ DISPOSITION: 'clear' });
  assert.match(body, /✅ 静态扫描未发现风险且每份投稿都是首次收录，已自动合入索引/);
});

/* ------------------------------------------------------------- 打标签那一步 */
const LABEL_STEP = '打标签';

const LABEL_RUNNER = [
  'const step = require("./step.cjs");',
  'const fs = require("fs");',
  'const calls = [];',
  'const github = { rest: { issues: {',
  '  getLabel: async ({ name }) => { calls.push(["get", name]); return {}; },',
  '  createLabel: async ({ name }) => { calls.push(["create", name]); },',
  '  addLabels: async (o) => { calls.push(["add", ...(o.labels || [])]); },',
  '} } };',
  'const context = { issue: { number: 7 }, repo: { owner: "tester", repo: "modules-repo" } };',
  'const core = { info: (m) => console.log(String(m)), warning: (m) => console.warn(String(m)), setOutput: () => {} };',
  'step(github, context, core).then(',
  '  () => fs.writeFileSync("label.json", JSON.stringify(calls)),',
  '  (e) => { console.error("LABEL-STEP-THREW: " + (e && e.message ? e.message : String(e))); process.exit(1); },',
  ');',
  '',
].join('\n');

/** 真跑「打标签」；js 传进来时用于变异哨兵，默认就是 workflow 里那一段。 */
function runLabelStep(env = {}, js) {
  const slice = js === undefined ? extractStep(LABEL_STEP, 'script') : { text: js, region: '' };
  const dir = fs.mkdtempSync(path.join(TMP, 'label-'));
  fs.writeFileSync(path.join(dir, 'step.cjs'),
    `module.exports = async function step(github, context, core) {
${slice.text}
}
`, 'utf8');
  fs.writeFileSync(path.join(dir, 'runner.cjs'), LABEL_RUNNER, 'utf8');
  const full = { ...process.env };
  for (const [k, v] of Object.entries(env)) full[k] = v === undefined || v === null ? '' : String(v);
  let err = null;
  let stdout = '';
  try {
    stdout = execFileSync(process.execPath, ['runner.cjs'], { cwd: dir, encoding: 'utf8', env: full, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) { err = e; stdout = String(e.stdout || ''); }
  const p = path.join(dir, 'label.json');
  const calls = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
  return { err, stdout, calls, region: slice.region, script: slice.text,
    stderr: err ? String(err.stderr || '') : '' };
}

test('T6.3·LABEL 为空（分流整步没跑）：一个标签都不打、不建、也不 get —— 空串递进 addLabels 是 API 报错', () => {
  const r = runLabelStep({ LABEL: '' });
  assert.equal(r.err, null, `这一步不许自己炸：${r.stderr}`);
  assert.deepEqual(r.calls || [], [], '没标签可打时连一次 API 调用都不该发出去；报错会把「通道自己坏了」伪装成「打标签挂了」');
  assert.match(r.stdout, /本轮不打标签/);
});

test('T6.3·needs-human-review 照旧连带 blocked-auto-merge；auto-approved 单独一个', () => {
  const blocked = runLabelStep({ LABEL: 'needs-human-review' });
  assert.deepEqual((blocked.calls || []).find((c) => c[0] === 'add'), ['add', 'needs-human-review', 'blocked-auto-merge']);
  const ok = runLabelStep({ LABEL: 'auto-approved' });
  assert.deepEqual((ok.calls || []).find((c) => c[0] === 'add'), ['add', 'auto-approved']);
});

/* --------------------------------------------------------------- 变异哨兵 */

test('T6.3·变异一：把「有没有结论」改回读 risk 空不空 ⇒ 整步没跑那一发立刻开始念等级与处置', () => {
  const src = extractStep(COMMENT_STEP, 'script').text;
  const mutated = src.replace("const TRIAGE = String(process.env.TRIAGE_CONCLUSION || '');",
    "const TRIAGE = process.env.RISK ? 'success' : 'failure';");
  assert.notEqual(mutated, src, '变异没落地：TRIAGE 那一行的写法变了要一起改这里');
  const c = runCommentStep({ js: mutated, env: {
    TRIAGE_CONCLUSION: '', PROOF_CONCLUSION: 'failure', RISK: '', ACTION: '', LABEL: '',
    CHANGE_TYPE: '', REASONS: '', AI_NOTE: '', MODULE_ID: '', PACKAGE_COUNT: '1',
  } });
  // 这一发的真形状是「分流整步没跑」；退回读 risk 之后它落进 failure 那一支，
  // 于是开始念等级与处置 —— 那正是前提 ② 的原始症状。
  assert.match(c.body, /- 风险等级：/);
  assert.match(c.body, /- 处置：/);
});

test('T6.3·变异二：摘掉 LABEL 为空那道守卫 ⇒ addLabels 收到一个空串（就是那条 API 报错的成因）', () => {
  const src = extractStep(LABEL_STEP, 'script').text;
  const mutated = src.replace('if (!label) {', 'if (false) {');
  assert.notEqual(mutated, src, '变异没落地：那道守卫的写法变了要一起改这里');
  const r = runLabelStep({ LABEL: '' }, mutated);
  const add = (r.calls || []).find((c) => c[0] === 'add');
  assert.deepEqual(add, ['add', ''], '空串被当成一个标签递给 addLabels');
});

test('T6.3·变异三：把「✅ 只配 clear」那道闸退回成只看 ACTION ⇒ 被台账拦下那一发开始念已合入', () => {
  const src = extractStep(COMMENT_STEP, 'script').text;
  const mutated = src.replace("} else if (process.env.DISPOSITION === 'clear') {", '} else if (true) {');
  assert.notEqual(mutated, src, '变异没落地：DISPOSITION 那一行的写法变了要一起改这里');
  const c = runCommentStep({ js: mutated, env: {
    ...CONCL_OK, DISPOSITION: 'hit', DISPOSITION_REASON: '模块 demo 在黑名单里',
    RISK: 'low', ACTION: 'auto-approve', LABEL: 'auto-approved', CHANGE_TYPE: 'first',
    AI_NOTE: '同意静态结论', MODULE_ID: 'demo', PACKAGE_COUNT: '1', REASONS: '未发现风险',
  } });
  assert.match(c.body, /✅/, '变异体必须真的念出已合入 —— 念不出来是这条哨兵自己失效，不是闸还在');
  assert.doesNotMatch(c.body, /处置台账命中/, '变异体绕过了 hit 那一支，所以那句不该出现');
});
