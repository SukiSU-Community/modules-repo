// canary #2：故意打坏一条断言。期望 approve 变**红**（而不是 skipping）且 PR BLOCKED。
// 这条不合并，验完就关。
import { test } from 'node:test';
import assert from 'node:assert/strict';

test('canary #2：selftest 必须红，approve 必须跟着红', () => {
  assert.equal(1, 2, '故意失败');
});
