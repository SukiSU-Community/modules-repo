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

/* ------------------------------------------------------------------ T6.1：AI 步（bash）的夹具 */

/** AI 步在 workflow 里的步骤名（改名要一起改这里 —— extractStep 会带着这句话红）。 */
const AI_STEP = 'AI 安全员复核';

/** triage 的 import 候选要命中真判据实现，就得把 base 里那一份（含它的依赖）装进临时 cwd。 */
const MODULE_SRC = path.resolve(import.meta.dirname, '../audit');
const MODULE_FILES = ['ai-review.mjs', 'scan.mjs', 'risk-rules.mjs', 'elf-forensics.mjs'];

/** 把「真正被 CI 执行的那份 raiseLevel」装到 <dir>/<at>/ 下（默认 audit/，另一种落地形态是 contrib/audit/）。 */
function installModule(dir, at = 'audit') {
  const dst = path.join(dir, at);
  fs.mkdirSync(dst, { recursive: true });
  for (const f of MODULE_FILES) fs.copyFileSync(path.join(MODULE_SRC, f), path.join(dst, f));
}

/** 切出某一步：region = 整步（含 if:/env:），text = `run: |` 里的 bash（去掉 YAML 公共缩进）。 */
function extractStep(name) {
  const lines = fs.readFileSync(WF, 'utf8').replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.ok(start >= 0, `workflow 里必须存在名为「${name}」的步骤（改名要一起改这里）`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {6}- (?:name|uses): /.test(lines[i])) { end = i; break; }
  }
  const region = lines.slice(start, end).join('\n');
  let open = -1;
  for (let i = start + 1; i < end; i += 1) {
    if (/^\s*run: \|\s*$/.test(lines[i])) { open = i; break; }
  }
  assert.ok(open >= 0, `步骤「${name}」里必须有 run: | 块`);
  const keyIndent = lines[open].length - lines[open].trimStart().length;
  const body = [];
  for (let i = open + 1; i < end; i += 1) {
    const l = lines[i];
    if (l.trim() !== '' && l.length - l.trimStart().length <= keyIndent) break;
    body.push(l);
  }
  const nonBlank = body.filter((l) => l.trim());
  assert.ok(nonBlank.length > 0, `步骤「${name}」的 run 块是空的`);
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
    const r = execFileSync('bash', ['ai-step.sh'], {
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
  return { code: err ? (err.status ?? 1) : 0, stdout, stderr, dir, files, status, calls };
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

test('audit-out 里一份报告都没有 → 这一步直接失败且不写任何判据', () => {
  const { kv, err, stderr } = runTriage({});
  assert.notEqual(err, null, 'found=true 却没有报告时必须是红，不能给「什么都没扫到」盖章放行');
  assert.match(stderr, /没有任何 \.audit\.json/);
  assert.deepEqual(kv, {}, '失败时不许留下半份判据让下游继续用');
});

test('有一份报告坏了 → 整步失败，不许「跳过坏的那份、用最严的好那份」继续定级', () => {
  // parse 抛错就是抛错。把它兜成「忽略这份」等于给投稿者一条「让扫描器产出一份读不懂的文件」的绕过路径。
  const { kv, err } = runTriage({ broken: '{ "riskLevel": "high"', good: rep('low', 'first') });
  assert.notEqual(err, null, 'JSON.parse 抛错必须把这一步带红');
  assert.equal(kv.action, undefined, '失败时不留下可被下游消费的判据');
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
  assert.match(escalate.kv.llm_note, /不同意/);
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
    /const names=[^\n]*/,
    'const names=(()=>{const all=fs.readdirSync(dir).filter((f)=>f.endsWith(".audit.json"));'
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
  assert.match(r.stderr, /demo\.zip/, '要点名是哪一包');
  assert.match(r.stderr, /分叉|配置错误/, 'prompt 分叉是运维错，不是模型跑败：混成一句就把人指去查供应商');
  assert.doesNotMatch(r.stderr, /没跑成/, '「没跑成」是 failed 那句串，AI 步不许提前用掉它');
});

test('AI 步：脚本崩溃（非 0 也非 2、没写状态）→ 同一条收口红，但不许说成 prompt 分叉', () => {
  const r = runAiStep({ plan: { 'demo.zip': { noWrite: true, exit: 1 }, 'evil.zip': { status: 'ok' } } });
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /demo\.zip/);
  assert.match(r.stderr, /状态文件/);
  assert.doesNotMatch(r.stderr, /分叉/, '退出码 1 不是配置错误那条路；把两种病写成一句，运维就只能猜');
});

test('AI 步的形状：不挂 set -e、收口认全五态、if 仍挂 found（不许 always()）', () => {
  const { region } = extractStep(AI_STEP);
  const { text } = extractStep(AI_STEP);
  assert.doesNotMatch(text, /set -eu/, 'set -e 会让 over-budget 那一发在 AI 步先红，triage 整步被跳过（§0.2-2）');
  assert.match(text, /set -u/, 'set -u 要留着：拼错的变量名不该静默成空串');
  assert.match(text, /disabled\|ok\|failed\|untrusted\|over-budget/,
    '收口的 case 必须含 over-budget：M1 之后脚本会真写它，漏了就是把合法状态判成非法（§0.2-1）');
  assert.match(region, /^ {8}if: steps\.locate\.outputs\.found == 'true'$/m,
    'found=false 时既没有 zip 也没有报告，放宽这条会让每个维护类 PR 都红');
  assert.doesNotMatch(region, /always\(\)/, '这一步不需要 always()：红由 triage 开火，不靠兜底跑完');
  assert.doesNotMatch(region, /continue-on-error/);
  assert.doesNotMatch(text, /\|\|\s*true/, '|| true 会把收口一起吞掉：这是变异②的形状');
  assert.match(text, /CODE=\$\?/, '退出码先收进变量，不当场开火');
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
  assert.match(kv.llm_note, /未启用/);
  assert.doesNotMatch(kv.llm_note, /同意|复验/, '没跑过的层不许冒充跑过');
});

test('矩阵·failed：分流整步 exit 1，文案「没跑成」，且不留下任何判据', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'failed', artifact: aiArt('demo.zip', { status: 'failed', reason: '模型调用失败：超时' }) } });
  assert.notEqual(err, null, 'failed 必须是红，不是「AI 没意见所以按静态放行」');
  assert.match(stderr, /没跑成/);
  assert.match(stderr, /demo\.zip/, '要点名是哪一包');
  assert.deepEqual(kv, {}, '红的时候不许留下半份判据给下游（approve 读到 action 就有一扇门）');
});

test('矩阵·untrusted：exit 1，文案「判据不可采信」，与 failed 那句不同串', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'untrusted', artifact: aiArt('demo.zip', { status: 'untrusted', reason: 'quote 未能逐字复验' }) } });
  assert.notEqual(err, null);
  assert.match(stderr, /判据不可采信/);
  assert.doesNotMatch(stderr, /没跑成/, '四句串各用各的：合并成一句就等于只剩一种下游后果（§0.1）');
  assert.deepEqual(kv, {});
});

test('矩阵·over-budget：exit 1，那句含「没看全」，绝不含「同意静态结论」，也不产出复核文案', () => {
  const { kv, err, stderr } = runTriage({ 'demo.zip': rep('low', 'first'), 'evil.zip': rep('low', 'first') },
    { 'demo.zip': 'disabled',
      'evil.zip': { status: 'over-budget', artifact: aiArt('evil.zip', { status: 'over-budget', reason: '需要 90000 B，预算 60000 B' }) } });
  assert.notEqual(err, null);
  assert.match(stderr, /没看全/);
  // 工单要求「不含同意」。字面断 !includes('同意') 做不到 —— over-budget 那句本身就该含
  // 「不是它同意，是没看全」（§1 第 2 步），所以钉子钉在「不许声称模型同意」那一侧：
  // 既不出现「同意静态结论」这类文案，也根本不产出 llm_note（红的时候 PR 上无话可说）。
  assert.doesNotMatch(stderr, /同意静态结论|模型同意|AI 全部看过/);
  assert.equal(kv.llm_note, undefined, '判据不成立时连文案都不许留下');
  assert.doesNotMatch(stderr, /未启用/, '送不全不是未启用：那是运维没配凭据');
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
  assert.match(kv.llm_note, /不同意静态结论/);
  assert.match(kv.llm_note, /high/);
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
  assert.match(kv.llm_note, /没有 AI 意见/);
  assert.match(kv.llm_note, /1 包/);
  assert.doesNotMatch(kv.llm_note, /全都看过|每包都/, '混合形态不许被洗成「AI 复核过了」');
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
  assert.deepEqual(kv, {});
});

test('矩阵：一个 ai-*.status 都没有 → 等级不动，文案说「这一步没有产物」，不是旧的「已跳过 LLM 复核」', () => {
  const { kv, err } = runTriage({ 'demo.zip': rep('low', 'first') });
  assert.equal(err, null, err && err.stderr);
  assert.equal(kv.action, 'auto-approve', 'found=true 但 AI 层没产物时，静态判据照旧（旧 12 发就靠这条活着）');
  assert.match(kv.llm_note, /没有产物/);
  assert.doesNotMatch(kv.llm_note, /已跳过 LLM 复核|未配置 AI_API_KEY/);
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
  assert.deepEqual(kv, {});
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
  assert.deepEqual(kv, {});
});

test('ok 但产物读不到 / 产物与状态不一致 / 产物指向别的包 → 三发都红', () => {
  const noArt = runTriage({ 'demo.zip': rep('low', 'first') },
    { 'demo.zip': { status: 'ok', artifact: null } });
  assert.notEqual(noArt.err, null, '状态说 ok、产物却不在，那就没有「逐字复验过」这回事');
  assert.match(noArt.stderr, /产物/);

  const mismatch = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', artifact: aiArt('demo.zip', { status: 'failed' }) },
  });
  assert.notEqual(mismatch.err, null, 'status 文件说 ok、产物 JSON 说 failed：两份不一致时按红处理');
  assert.match(mismatch.stderr, /不一致/);

  const otherPkg = runTriage({ 'demo.zip': rep('low', 'first') }, {
    'demo.zip': { status: 'ok', artifact: aiArt('demo.zip', { target: { zip: 'x.zip', report: 'audit-out/other.zip.audit.json' } }) },
  });
  assert.notEqual(otherPkg.err, null, 'A 包配 B 包的产物 = F7 那个错法的产物版');
  assert.match(otherPkg.stderr, /别的包|不一致/);
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
  assert.match(TRIAGE_JS, /decide\(/);
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
  assert.deepEqual(kv, {});
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
