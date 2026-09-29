// node --test src/lib/format.test.ts (node 24 strips the types)
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { confidenceLabel, errorBar, round100 } from './format.ts'

test('largest remainder sums to 100 and favours the largest remainders', () => {
  const r = round100({ voip: 33.3, video: 33.3, web: 33.4 })
  assert.equal(Object.values(r).reduce((a, b) => a + b, 0), 100)
  assert.deepEqual(round100({ a: 18.4, b: 27.6, c: 54.0 }), { a: 18, b: 28, c: 54 })
  assert.deepEqual(round100({ a: 0, b: 0 }), { a: 0, b: 0 })
  const many = round100({ a: 12.49, b: 12.49, c: 12.49, d: 12.53, e: 50 })
  assert.equal(Object.values(many).reduce((x, y) => x + y, 0), 100)
})

test('error bars are clipped to 0-100', () => {
  assert.deepEqual(errorBar(4, 10), [0, 14])
  assert.deepEqual(errorBar(95, 12), [83, 100])
  assert.equal(errorBar(50, null), null)
})

test('confidence below 80% reads likely', () => {
  assert.equal(confidenceLabel(0.62), 'likely · 62%')
  assert.equal(confidenceLabel(0.93), '93%')
  assert.equal(confidenceLabel(null), 'not determinable')
})
