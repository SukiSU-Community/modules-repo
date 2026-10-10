// canary：故意打坏一条断言，用来实测 selftest 红的时候 approve 是否真的不放行。
// 这条 PR 不打算合，验完就关。
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('canary：这道闸应该因为这条失败而挡住合并', () => {
  assert.equal(1, 2, '故意失败');
});
