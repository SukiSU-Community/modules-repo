#!/usr/bin/env node
// 标定用：算出一枚包「装下整包需要多少字节」（neededBytes），供标定那一发当 --max-bytes。
//
// 为什么标定需要这个数、而不是让它自己去发现：
//   标定要量的是「把整包送出去花多少 credits」。所以那一发必须真的把整包发出去。
//   而 ai-review.mjs 在没有 --max-bytes 时会退回 DEFAULT_MAX_BRIEF_BYTES（240000）——
//   「不设预算」不等于「不设上限」。2026-10-27 实测就是这么翻车的：探针需要 815067 B，
//   默认预算 240000，于是那一发走了 over-budget 分支、**压根没调用模型**，
//   状态写的是 over-budget，credits 一个都读不到，而 job 里看上去「真发了一次」是绿的。
//
// 所以这里先用与线上完全相同的那条路（readZip + buildBrief）把 neededBytes 算出来，
// 标定那一发再把它当 --max-bytes 传进去：上限恰好等于「一条都不略」所需的量，
// 既不提前截断、也不放大到无意义的数字。
//
// 用法：node audit/calibration-budget.mjs <report.json> <module.zip>
// 输出（stdout，单行 JSON）：{"neededBytes":N,"byteSize":N,"fileCount":N,"textClipped":N}
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { readZip } from './scan.mjs';
import { buildBrief } from './ai-review.mjs';

const [reportPath, zipPath] = process.argv.slice(2);
if (!reportPath || !zipPath) {
  process.stderr.write('用法: node audit/calibration-budget.mjs <report.json> <module.zip>\n');
  process.exit(2);
}

const report = JSON.parse(readFileSync(resolve(reportPath), 'utf8'));
const z = readZip(resolve(zipPath));

// maxBytes 传一个远大于 neededBytes 的值：这一趟只想知道「一条都不略要多少」，
// 不想在算的过程中被默认预算截断（overBudget=true 时 neededBytes 仍然是对的，
// 但 byteSize 会缩水，读数容易看错）。
const brief = buildBrief({ report, entries: z.files, maxBytes: Number.MAX_SAFE_INTEGER });

process.stdout.write(`${JSON.stringify({
  neededBytes: brief.neededBytes,
  byteSize: brief.byteSize,
  fileCount: brief.fileCount,
  textClipped: brief.shapes && brief.shapes.textClipped || 0,
})}\n`);
