/**
 * E2-A: sticky per-session provider affinity + cooldown anti-bounce + short `Retry-After`
 * same-provider warm retry before a cold failover (KV-cache prefix protection).
 *
 * Purely behavioral: every assertion observes which profile endpoint a `providerPool` session
 * actually hit (via the injected `fetch` seam) or what `orderProfiles` returns.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { orderProfiles, providerPool, type PoolAffinityState, type ProviderOptions } from '../src/server/provider.ts'

process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

function makeProfile(id: string, port: number, priority: number, overrides: Partial<ResolvedModelProfile> = {}): ResolvedModelProfile {
  return {
    id,
    name: `Affinity ${id}`,
    endpoint: `http://127.0.0.1:${port}/v1`,
    model: 'affinity-model',
    protocol: 'responses',
    key: `affinity-key-${id}-123456`,
    enabled: true,
    priority,
    contextWindow: 128_000,
    maxTokens: 4_096,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    inputCostPerMtok: 1,
    cachedInputCostPerMtok: 0.25,
    outputCostPerMtok: 4,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
    ...overrides,
  }
}

function okSse(text: string): string {
  const events: Record<string, unknown>[] = [
    { type: 'response.created', response: { id: 'resp_aff', status: 'in_progress' } },
    { type: 'response.output_item.added', output_index: 0, item: { type: 'message', id: 'msg_aff', role: 'assistant', content: [], status: 'in_progress' } },
    { type: 'response.output_text.delta', output_index: 0, delta: text },
    {
      type: 'response.completed',
      response: {
        id: 'resp_aff',
        status: 'completed',
        output: [{ type: 'message', id: 'msg_aff', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] }],
        usage: { input_tokens: 1000, input_tokens_details: { cached_tokens: 900 }, output_tokens: 10 },
      },
    },
  ]
  return events.map(ev => `data: ${JSON.stringify(ev)}\n\n`).join('')
}

type Reply = { status: number; retryAfter?: string } | 'ok'

/**
 * Scripted fake upstream: `plan[profileId]` is a queue of replies consumed per request (falls back
 * to `'ok'` when empty). Every request appends the profile id to `hits`.
 */
function harness(profiles: readonly ResolvedModelProfile[], extra: Partial<ProviderOptions> = {}) {
  const hits: string[] = []
  const plan = new Map<string, Reply[]>()
  const byPort = new Map(profiles.map(p => [new URL(p.endpoint).port, p.id]))
  const fetchStub: typeof fetch = async input => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url)
    const id = byPort.get(url.port) ?? 'unknown'
    hits.push(id)
    const reply = plan.get(id)?.shift() ?? 'ok'
    if (reply === 'ok') {
      return new Response(okSse(`from-${id}`), { status: 200, headers: { 'content-type': 'text/event-stream' } })
    }
    const headers: Record<string, string> = { 'content-type': 'application/json' }
    if (reply.retryAfter !== undefined) headers['retry-after'] = reply.retryAfter
    return new Response(JSON.stringify({ error: { message: `scripted status ${reply.status}` } }), { status: reply.status, headers })
  }
  const failures: Array<{ id: string; hard: boolean }> = []
  const { models, model } = providerPool(profiles, 'eff-provider-affinity', {
    fetch: fetchStub,
    transportRetryBaseMs: 5,
    onProfileFailure: (id, _err, hard) => failures.push({ id, hard }),
    ...extra,
  })
  const turn = async (label: string) => {
    const s = models.stream(model, {
      systemPrompt: 'Affinity behavioral test.',
      messages: [{ role: 'user', content: label, timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of s) { /* drain */ }
    return s.result()
  }
  /** Run one turn and return exactly the profile ids it hit (in order). */
  const turnHits = async (label: string): Promise<string[]> => {
    const before = hits.length
    const res = await turn(label)
    assert.equal(res.stopReason, 'stop', `${label} must succeed`)
    return hits.slice(before)
  }
  return { hits, plan, failures, turn, turnHits }
}

const switches = (seq: readonly string[]): number => seq.reduce((n, id, i) => n + (i > 0 && id !== seq[i - 1] ? 1 : 0), 0)

describe('E2-A sticky per-session provider affinity', () => {
  test('pins one profile across turns within a session, balances equal tiers across sessions, respects priority tiers', async () => {
    const a = makeProfile('eq-a', 18601, 100)
    const b = makeProfile('eq-b', 18602, 100)

    const s1 = harness([a, b])
    const s1Turns = [
      ...(await s1.turnHits('t1')), ...(await s1.turnHits('t2')),
      ...(await s1.turnHits('t3')), ...(await s1.turnHits('t4')),
    ]
    assert.equal(s1Turns.length, 4)
    assert.equal(new Set(s1Turns).size, 1, `session must stay on one profile, got ${s1Turns.join(',')}`)

    const s2 = harness([a, b])
    const s2Turns = [...(await s2.turnHits('t1')), ...(await s2.turnHits('t2')), ...(await s2.turnHits('t3'))]
    assert.equal(new Set(s2Turns).size, 1, 'second session also stays pinned')
    assert.notEqual(s2Turns[0], s1Turns[0], 'consecutive sessions load-balance across equal-priority profiles')

    const low = makeProfile('tier-low', 18603, 100)
    const high = makeProfile('tier-high', 18604, 300)
    for (let i = 0; i < 3; i++) {
      const s = harness([low, high])
      assert.deepEqual(await s.turnHits('t1'), ['tier-high'], 'higher priority tier wins initial selection in every session')
      assert.deepEqual(await s.turnHits('t2'), ['tier-high'])
    }
  })

  test('orderProfiles keeps the warm pinned profile first after a higher tier recovers, but never pins a cooled-down profile', () => {
    const now = Date.now()
    const primaryRecovered = makeProfile('ord-primary', 18611, 300, { healthState: 'half_open', cooldownUntil: now - 1_000 })
    const secondary = makeProfile('ord-secondary', 18612, 100)
    const affinity: PoolAffinityState = { tick: 0, pinnedId: 'ord-secondary' }
    assert.deepEqual(orderProfiles([primaryRecovered, secondary], 1000, undefined, affinity).map(p => p.id), ['ord-secondary', 'ord-primary'])
    assert.deepEqual(orderProfiles([primaryRecovered, secondary], 1000, undefined, { tick: 0, pinnedId: null }).map(p => p.id), ['ord-primary', 'ord-secondary'])

    const pinnedCooling = makeProfile('ord-secondary', 18612, 100, { healthState: 'open', cooldownUntil: now + 60_000 })
    assert.deepEqual(orderProfiles([primaryRecovered, pinnedCooling], 1000, undefined, affinity).map(p => p.id), ['ord-primary'])

    const x = makeProfile('ord-x', 18613, 100)
    const y = makeProfile('ord-y', 18614, 100)
    const fixedTick: PoolAffinityState = { tick: 7, pinnedId: null }
    const first = orderProfiles([x, y], 1000, undefined, fixedTick).map(p => p.id)
    for (let i = 0; i < 5; i++) {
      assert.deepEqual(orderProfiles([x, y], 1000, undefined, fixedTick).map(p => p.id), first, 'a session tick never rotates per call')
    }
    assert.notDeepEqual(orderProfiles([x, y], 1000, undefined, { tick: 8, pinnedId: null }).map(p => p.id), first)
  })
})

describe('E2-A cooldown anti-bounce', () => {
  test('after failover to a warm secondary, turns stay there even once the primary cooldown expires (<= 1 switch)', async () => {
    const primary = makeProfile('ab-primary', 18621, 300)
    const secondary = makeProfile('ab-secondary', 18622, 100)
    const s = harness([primary, secondary])
    // Cold first turn: primary 429 with a 1s Retry-After (the minimum pool cooldown) -> immediate failover.
    s.plan.set('ab-primary', [{ status: 429, retryAfter: '1' }])
    const started = Date.now()
    assert.deepEqual(await s.turnHits('t1'), ['ab-primary', 'ab-secondary'])
    assert.ok(Date.now() - started < 900, 'cold 429 fails over without waiting on Retry-After')
    assert.deepEqual(await s.turnHits('t2'), ['ab-secondary'])

    await new Promise(r => setTimeout(r, 1_100)) // primary pool cooldown (1s) has now expired
    assert.deepEqual(await s.turnHits('t3'), ['ab-secondary'], 'no bounce-back to the recovered primary')
    assert.deepEqual(await s.turnHits('t4'), ['ab-secondary'])
    assert.equal(switches(s.hits), 1)

    // Same shape with a non-cooldown transient 5xx on the primary: the secondary stays pinned.
    const s5 = harness([makeProfile('ab5-primary', 18623, 300), makeProfile('ab5-secondary', 18624, 100)])
    s5.plan.set('ab5-primary', [{ status: 503 }])
    assert.deepEqual(await s5.turnHits('t1'), ['ab5-primary', 'ab5-secondary'])
    assert.deepEqual(await s5.turnHits('t2'), ['ab5-secondary'])
    assert.deepEqual(await s5.turnHits('t3'), ['ab5-secondary'])
    assert.equal(switches(s5.hits), 1)
  })
})

describe('E2-A short Retry-After same-provider warm retry', () => {
  test('a warm profile retries itself once on a short-Retry-After 429 and succeeds with zero switches', async () => {
    const warm = makeProfile('wr-warm', 18631, 300)
    const cold = makeProfile('wr-cold', 18632, 100)
    const s = harness([warm, cold])
    assert.deepEqual(await s.turnHits('t1'), ['wr-warm'])
    s.plan.set('wr-warm', [{ status: 429, retryAfter: '0.04' }])
    const started = Date.now()
    assert.deepEqual(await s.turnHits('t2'), ['wr-warm', 'wr-warm'])
    assert.ok(Date.now() - started >= 30, 'honors the short Retry-After before retrying')
    assert.deepEqual(await s.turnHits('t3'), ['wr-warm'])
    assert.equal(switches(s.hits), 0)
    assert.deepEqual(s.failures.map(f => f.id), ['wr-warm'])
  })

  test('long Retry-After, auth errors, cold profiles, and disabled transport retries fail over immediately', async () => {
    const cases: Array<{ name: string; reply: Reply; warmFirst: boolean; extra?: Partial<ProviderOptions> }> = [
      { name: 'long-retry-after', reply: { status: 429, retryAfter: '30' }, warmFirst: true },
      { name: 'auth', reply: { status: 401 }, warmFirst: true },
      { name: 'cold-first-turn', reply: { status: 429, retryAfter: '0.02' }, warmFirst: false },
      { name: 'retries-disabled', reply: { status: 429, retryAfter: '0.02' }, warmFirst: true, extra: { maxTransportRetries: 0 } },
    ]
    for (const [i, c] of cases.entries()) {
      const p = makeProfile(`ff-${c.name}-p`, 18640 + i * 2, 300)
      const q = makeProfile(`ff-${c.name}-q`, 18641 + i * 2, 100)
      const s = harness([p, q], c.extra)
      if (c.warmFirst) assert.deepEqual(await s.turnHits('t1'), [p.id])
      s.plan.set(p.id, [c.reply])
      const started = Date.now()
      assert.deepEqual(await s.turnHits('t2'), [p.id, q.id], `${c.name}: fails over without a same-provider retry`)
      assert.ok(Date.now() - started < 1_000, `${c.name}: no stall before failover`)
      assert.deepEqual(await s.turnHits('t3'), [q.id], `${c.name}: new warm profile is pinned`)
    }
  })
})

describe('E2-A sustained 429/5xx failover without stalling', () => {
  test('sustained 429 on the warm profile uses one retry, then fails over and pins the new profile', async () => {
    const warm = makeProfile('su-warm', 18661, 300)
    const next = makeProfile('su-next', 18662, 100)
    const s = harness([warm, next])
    assert.deepEqual(await s.turnHits('t1'), ['su-warm'])
    s.plan.set('su-warm', [{ status: 429, retryAfter: '0.01' }, { status: 429, retryAfter: '0.01' }, { status: 429, retryAfter: '0.01' }])
    assert.deepEqual(await s.turnHits('t2'), ['su-warm', 'su-warm', 'su-next'])
    assert.deepEqual(await s.turnHits('t3'), ['su-next'])
    assert.deepEqual(await s.turnHits('t4'), ['su-next'])
    assert.equal(switches(s.hits), 1)
  })

  test('5xx on the warm profile fails over cleanly and pins the new profile', async () => {
    const warm = makeProfile('sx-warm', 18671, 300)
    const next = makeProfile('sx-next', 18672, 100)
    const s = harness([warm, next])
    assert.deepEqual(await s.turnHits('t1'), ['sx-warm'])
    s.plan.set('sx-warm', [{ status: 503 }, { status: 503 }])
    assert.deepEqual(await s.turnHits('t2'), ['sx-warm', 'sx-next'])
    assert.deepEqual(await s.turnHits('t3'), ['sx-next'])
  })

  test('all candidates down terminates with a finite number of attempts instead of hanging', async () => {
    const warm = makeProfile('dn-warm', 18681, 300)
    const next = makeProfile('dn-next', 18682, 100)
    const s = harness([warm, next])
    assert.deepEqual(await s.turnHits('t1'), ['dn-warm'])
    const down: Reply = { status: 429, retryAfter: '0.01' }
    s.plan.set('dn-warm', Array.from({ length: 10 }, () => down))
    s.plan.set('dn-next', Array.from({ length: 10 }, () => down))
    const before = s.hits.length
    await assert.rejects(s.turn('t2'))
    const attempts = s.hits.slice(before)
    assert.ok(attempts.length <= 4, `bounded attempts, got ${attempts.join(',')}`)
    assert.equal(attempts[0], 'dn-warm')
    assert.ok(attempts.includes('dn-next'), 'every healthy candidate is tried')
  })

  test('the warm-retry wait is abort-signal aware', async () => {
    const warm = makeProfile('as-warm', 18691, 300)
    const next = makeProfile('as-next', 18692, 100)
    const controller = new AbortController()
    const s = harness([warm, next], { signal: controller.signal })
    assert.deepEqual(await s.turnHits('t1'), ['as-warm'])
    s.plan.set('as-warm', [{ status: 429, retryAfter: '5' }])
    const started = Date.now()
    setTimeout(() => controller.abort(new Error('test abort')), 40)
    await assert.rejects(s.turn('t2'))
    assert.ok(Date.now() - started < 2_000, 'abort interrupts the 5s warm-retry wait')
    assert.deepEqual(s.hits.slice(1), ['as-warm'], 'no further attempts after abort')
  })
})
