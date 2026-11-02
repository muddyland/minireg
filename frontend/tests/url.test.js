// Run with `npm test` (node's built-in runner; no dependencies).
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { safeHttpUrl } from '../src/utils/url.js'

test('http and https links pass through', () => {
  assert.equal(safeHttpUrl('https://github.com/lodash/lodash'), 'https://github.com/lodash/lodash')
  assert.equal(safeHttpUrl('http://example.com/a?b=1#c'), 'http://example.com/a?b=1#c')
  assert.equal(safeHttpUrl('  HTTPS://Example.com/x '), 'https://example.com/x')
})

test('script and other schemes are refused', () => {
  for (const value of [
    'javascript:alert(document.cookie)',
    '  JaVaScRiPt:alert(1)',
    '\tjavascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    'git+https://github.com/x/y.git',
    '//evil.example/x',
    '/relative/path',
    'not a url',
    '',
    null,
    undefined,
    42,
  ]) {
    assert.equal(safeHttpUrl(value), null, String(value))
  }
})
