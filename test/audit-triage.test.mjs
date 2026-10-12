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
 * 真跑一次分流：在临时目录造 audit-out/，把 GITHUB_OUTPUT 指到一个文件，返回解析出的 kv。
 * reports 的 key 就是报告文件名（<pkg>.audit.json），所以用例能直接控制「哪几份存在」。
 */
function runTriage(reports, llm, opts = {}) {
  const dir = fs.mkdtempSync(path.join(TMP, 'run-'));
  fs.mkdirSync(path.join(dir, 'audit-out'));
  for (const [pkg, r] of Object.entries(reports)) {
    const file = path.join(dir, 'audit-out', `${pkg}.audit.json`);
    // 传字符串时按原始字节写入 —— 「报告坏了」这类用例要能造出真的坏文件，而不是被 JSON 包一层。
    fs.writeFileSync(file, typeof r === 'string' ? r : JSON.stringify(r), 'utf8');
    const m = opts.mtime && opts.mtime[pkg];
    if (m !== undefined) fs.utimesSync(file, new Date(m), new Date(m));
  }
  if (llm !== undefined) {
    fs.writeFileSync(path.join(dir, 'audit-out', 'llm.json'),
      typeof llm === 'string' ? llm : JSON.stringify(llm), 'utf8');
  }
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
  return { kv, err, stderr: err ? String(err.stderr || '') : '' };
}

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

/* --------------------------------------------------------------- LLM 复核只能加严 */

test('llm.json agree:false 且更严 → 抬等级；同意或不更严时不动静态结论', () => {
  const escalate = runTriage({ a: rep('low', 'first') }, { agree: false, risk: 'high', reasons: ['模型看到了别的'] });
  assert.equal(escalate.kv.risk, 'high');
  assert.equal(escalate.kv.action, 'block');
  assert.match(escalate.kv.llm_note, /不同意/);
  assert.match(escalate.kv.reasons, /LLM 复核：模型看到了别的/);

  const agree = runTriage({ a: rep('low', 'first') }, { agree: true, risk: 'high' });
  assert.equal(agree.kv.action, 'auto-approve', 'agree:true 时模型说的 risk 不参与定级');

  const softer = runTriage({ a: rep('high', 'first') }, { agree: false, risk: 'low' });
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
