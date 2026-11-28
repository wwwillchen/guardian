/**
 * Recall Lever 1 — chain-depth-aware frontier & deferred suspect queue (fast, hermetic, behavioral).
 *
 * Pins, through runtime behavior only (no source-text assertions):
 *  (a) a deeper host-verified hop on already-seen tenant/role/service/surface reach is a productive
 *      frontier wave (no false `frontier_stagnated`), while genuinely flat waves still stagnate;
 *  (b) audit suspects are priority-sorted before Wave-1 conversion, the top 6 enter Wave-1 in
 *      priority order, and overflow suspects are queued (never dropped) and promoted as slots open;
 *  (c) `highPriorityQueueEmpty` stays false while open chain hypotheses or deferred suspects remain
 *      with budget / wall clock, and turns true once they resolve or the bounds are exhausted;
 *  (d) the World Graph renders a bounded `openChains[]` section, keeps multi-hop audit summaries,
 *      and carries endpoints on capability-ledger edges;
 *  (e) the planner prompt allows source-predicted next hops and open-chain continuation, and the
 *      Phase-0 code-audit ceiling scales modestly with `maxDurationMs` while staying bounded.
 */
import assert from 'node:assert/strict'
import { test, type TestContext } from 'node:test'

import { formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import {
  CODE_AUDIT_WAVE1_MAX_STEPS,
  convertCodeAuditSuspectsToChainSteps,
  coordinatorSchedulerDecision,
  deferredCodeAuditSuspectPool,
  planDeferredCodeAuditSuspects,
  promoteDeferredCodeAuditSuspects,
} from '../src/server/exec-dispatch.ts'
import { Execution } from '../src/server/execution.ts'
import {
  createEmptyReachState,
  evaluateWaveProgress,
  type VerifiedHopReceiptEvent,
  type WaveProgressInput,
} from '../src/server/frontier-scheduler.ts'
import { buildDeterministicFallbackPlan, planWithWorldGraph } from '../src/server/llm-planner.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { resolveSourceAuditSettlementMs, resolveSourceAuditWallClockMs } from '../src/server/run-actor.ts'
import type { Run, Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import {
  buildWorldGraphSnapshot,
  deriveOpenChainHypotheses,
  evaluateOpenChainHold,
  parseDeclaredChainHops,
  serializeWorldGraph,
  type WorldGraphFactInput,
} from '../src/server/world-graph.ts'
import { makeStore, setupApprovedRun, startMockLlmServer, stopExecution } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://app.example.test'
const THREE_HOP = 'Hop 1 (GET /api/v1/alpha, svc/a.ts:10, read) -> Hop 2 (POST /api/v1/beta, svc/b.ts:20, write) -> Hop 3 (GET /api/v1/gamma, svc/c.ts:30, read)'

// ---------------------------------------------------------------------------
// (a) Chain-depth productivity
// ---------------------------------------------------------------------------

function hop(id: string, branchKey: string, depth: number, extra: Partial<VerifiedHopReceiptEvent> = {}): VerifiedHopReceiptEvent {
  return { hopReceiptId: id, branchKey, depth, hostVerified: true, tenantScope: 'tenant_a', roleLabel: 'member', serviceOrigin: ORIGIN, surface: 'http', ...extra }
}

function wave(reach: WaveProgressInput['reach'], waveNo: number, streak: number, hops: VerifiedHopReceiptEvent[]) {
  return evaluateWaveProgress({ waveNo, completedAssignments: 1, reach, verifiedHopReceipts: hops, activeFrontierCount: 1, consecutiveUnproductiveWaves: streak, unproductiveWaveLimit: 2 })
}

test('(a) a deeper verified hop on saturated reach is productive; flat waves still stagnate', () => {
  const reach = createEmptyReachState()
  const w1 = wave(reach, 1, 0, [hop('h1', 'chain-a', 1)])
  assert.equal(w1.productive, true, 'first hop expands reach')
  assert.deepEqual(w1.reachDelta.newChainDepthHopReceiptIds, [], 'depth-1 hops never count as chain-depth advance')

  // Same tenant/role/service/surface, one hop deeper along the existing lineage.
  const w2 = wave(reach, 2, w1.nextUnproductiveWaves, [hop('h2', 'chain-a>h2', 2)])
  assert.equal(w2.productive, true)
  assert.equal(w2.decision, 'continue')
  assert.equal(w2.reason, 'frontier_progress')
  assert.deepEqual(w2.reachDelta.newTenants, [])
  assert.deepEqual(w2.reachDelta.newSurfaces, [])
  assert.deepEqual(w2.reachDelta.newChainDepthHopReceiptIds, ['h2'])
  assert.deepEqual(w2.reachDelta.newHopReceiptIds, ['h2'], 'depth advance is surfaced as a productive hop receipt')
  assert.equal(reach.maxVerifiedHopDepth, 2)

  // Run-wide advance with an unrelated per-edge branch key (no shared lineage) still counts.
  const w3 = wave(reach, 3, w2.nextUnproductiveWaves, [hop('h3', 'cap:edge-unique-3', 3)])
  assert.equal(w3.productive, true)
  assert.deepEqual(w3.reachDelta.newChainDepthHopReceiptIds, ['h3'])

  // A second lineage climbing to a depth below the run-wide max advances its own lineage.
  wave(reach, 4, 0, [hop('b1', 'chain-b', 1)])
  const w5 = wave(reach, 5, 0, [hop('b2', 'chain-b>h2', 2)])
  assert.deepEqual(w5.reachDelta.newChainDepthHopReceiptIds, ['b2'], 'existing lineage advanced 1 -> 2')

  // Genuinely flat waves: new receipts at already-reached depth on the same reach.
  const f1 = wave(reach, 6, 0, [hop('f1', 'chain-b>h2', 2)])
  assert.equal(f1.productive, false)
  assert.equal(f1.decision, 'continue')
  const f2 = wave(reach, 7, f1.nextUnproductiveWaves, [hop('f2', 'chain-a>h2', 2)])
  assert.equal(f2.productive, false)
  assert.equal(f2.decision, 'stop')
  assert.equal(f2.reason, 'frontier_stagnated')
})

test('(a) unverified or malformed hops never advance chain depth', () => {
  const reach = createEmptyReachState()
  wave(reach, 1, 0, [hop('h1', 'chain-a', 1)])
  const w = wave(reach, 2, 0, [
    hop('u2', 'chain-a>h2', 2, { hostVerified: false }),
    hop('n2', 'chain-a>h2', Number.NaN),
    hop('z2', 'chain-a>h2', 0),
  ])
  assert.equal(w.productive, false)
  assert.equal(reach.maxVerifiedHopDepth, 1)
})

// ---------------------------------------------------------------------------
// (b) Priority-sorted Wave-1 conversion + deferred overflow queue
// ---------------------------------------------------------------------------

async function seedSuspects(storage: Store, count: number, describe: (i: number) => { summary: string; hypothesis?: string; route: string }) {
  const { runId, run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const asset = run.candidates.find(c => run.approved.includes(c.id))!
  const auditor = storage.makeWorker(run, 'threat_model', asset, 'Source-First Code Audit', 'Audit')
  const facts = []
  for (let i = 0; i < count; i += 1) {
    const d = describe(i)
    // Distinct record timestamps: ranking ties break on (createdAt, id), independent of list order.
    for (const until = Date.now() + 2; Date.now() < until;) { /* spin 2ms */ }
    facts.push(storage.addFact(run, auditor, {
      kind: 'code_audit_suspect', origin: ORIGIN, summary: d.summary,
      data: { file: `svc/f${i}.ts`, line: 10 + i, routeOrAction: d.route, ...(d.hypothesis ? { hypothesis: d.hypothesis } : {}) },
    }))
  }
  return { runId, run: storage.run(runId), facts }
}

const routeOf = (title: string) => /· (\S+ \S+) \(/.exec(title)?.[1] ?? title

test('(b) overflow suspects are priority-sorted, top 6 enter Wave-1, overflow is queued and promoted as slots open', async (t: TestContext) => {
  const { storage } = makeStore(t)
  // idx 0-3: plain review leads (lower tier); idx 4-7: missing ownership checks (higher tier).
  // idx 1 and idx 5 declare multi-hop trajectories (declared hop count breaks priority ties).
  const { run, facts } = await seedSuspects(storage, 8, i => i < 4
    ? { summary: `Route handler review on /api/v1/item${'abcd'[i]}`, route: `GET /api/v1/item${'abcd'[i]}`, ...(i === 1 ? { hypothesis: 'Hop 1 (GET /api/v1/itemb) -> Hop 2 (POST /api/v1/share)' } : {}) }
    : { summary: `Missing ownership check on /api/v1/owned${'efgh'[i - 4]}`, route: `GET /api/v1/owned${'efgh'[i - 4]}`, ...(i === 5 ? { hypothesis: THREE_HOP } : {}) })

  const wave1 = convertCodeAuditSuspectsToChainSteps(storage, run, facts, undefined, { maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS, promoteMultiHop: true })
  assert.equal(wave1.length, 6)
  assert.deepEqual(wave1.map(s => routeOf(s.title)), [
    'GET /api/v1/ownedf', 'GET /api/v1/ownede', 'GET /api/v1/ownedg', 'GET /api/v1/ownedh', 'GET /api/v1/itemb', 'GET /api/v1/itema',
  ], 'priority desc, then declared hops desc, then record order')
  const priorities = wave1.map(s => s.priority)
  assert.ok(priorities.every((p, i) => i === 0 || priorities[i - 1]! >= p), 'Wave-1 priorities are non-increasing')
  assert.ok(priorities[3]! > priorities[4]!, 'missing-ownership suspects outrank plain review leads')

  const deferred = planDeferredCodeAuditSuspects(storage, run, facts)
  assert.deepEqual(deferred.map(f => f.id), [facts[2]!.id, facts[3]!.id], 'overflow suspects are queued in priority order, not dropped')
  assert.equal(deferredCodeAuditSuspectPool(storage, run).length, 8, 'durable pool re-reads every explicit suspect')

  // Re-running Wave-1 conversion is idempotent: already-converted suspects are never duplicated.
  const again = convertCodeAuditSuspectsToChainSteps(storage, run, facts, undefined, { maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS })
  assert.deepEqual(again.map(s => routeOf(s.title)), ['GET /api/v1/itemc', 'GET /api/v1/itemd'], 'only the deferred overflow converts')
  for (const step of again) storage.updateChainStep(step.id, { status: 'canceled' })
})

test('(b) deferred suspects wait while slots are full, then promote on a follow-up dispatch tick', async (t: TestContext) => {
  const { storage } = makeStore(t)
  const { run, facts } = await seedSuspects(storage, 8, i => ({ summary: `Missing authorization on /api/v1/res${'abcdefgh'[i]}`, route: `POST /api/v1/res${'abcdefgh'[i]}` }))
  const wave1 = convertCodeAuditSuspectsToChainSteps(storage, run, facts, undefined, { maxSteps: CODE_AUDIT_WAVE1_MAX_STEPS, promoteMultiHop: true })
  assert.equal(wave1.length, 6)

  // 6 ready Wave-1 steps fill a 6-slot fleet: nothing is promoted yet, nothing is lost.
  assert.deepEqual(promoteDeferredCodeAuditSuspects(storage, run, { configuredConcurrency: 6, activeAssignments: 0 }), [])
  assert.equal(planDeferredCodeAuditSuspects(storage, run, deferredCodeAuditSuspectPool(storage, run)).length, 2)

  // Wave-1 settles; slots open on the next tick and the overflow is promoted in priority order.
  for (const step of wave1) storage.updateChainStep(step.id, { status: 'complete' })
  const promoted = promoteDeferredCodeAuditSuspects(storage, run, { configuredConcurrency: 6, activeAssignments: 1 })
  assert.deepEqual(promoted.map(s => routeOf(s.title)), ['POST /api/v1/resg', 'POST /api/v1/resh'])
  assert.ok(promoted.every(s => s.status === 'ready' && s.skills.includes('multihop-chains')), 'promoted suspects are dispatchable chain steps')
  assert.equal(planDeferredCodeAuditSuspects(storage, run, deferredCodeAuditSuspectPool(storage, run)).length, 0, 'queue drains')
  assert.deepEqual(promoteDeferredCodeAuditSuspects(storage, run, { configuredConcurrency: 16, activeAssignments: 0 }), [], 'no duplicate promotion')
})

// ---------------------------------------------------------------------------
// (c) Open-chain-aware high-priority queue + stop guards
// ---------------------------------------------------------------------------

function stubBackend(): WorkerBackend {
  return {
    async run() { return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} } },
    async openSession(): Promise<WorkerSession> {
      return {
        stage: async name => `/evidence/${name}`,
        exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
        analyze: async () => ({ ok: true }),
        sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
        runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
        verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
        close: async () => undefined,
      }
    },
    async verifyStaticAst(_aid, req) {
      return { verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }
}

async function queueProbe(t: TestContext, maxDurationMs = 30 * 60_000) {
  const { storage } = makeStore(t)
  const seeded = await seedSuspects(storage, 1, () => ({ summary: 'Missing ownership check across a 3-hop export trajectory', hypothesis: THREE_HOP, route: 'GET /api/v1/alpha' }))
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false, maxDurationMs })
  t.after(() => stopExecution(engine as unknown as Parameters<typeof stopExecution>[0]))
  const empty = () => (engine as unknown as { highPriorityQueueEmpty(run: Pick<Run, 'id' | 'goalRevision'>): boolean }).highPriorityQueueEmpty(storage.run(seeded.run.id))
  const settleSteps = () => { for (const s of storage.listChainSteps(seeded.run.id)) if (s.status !== 'complete') storage.updateChainStep(s.id, { status: 'complete' }) }
  return { storage, ...seeded, empty, settleSteps }
}

test('(c) highPriorityQueueEmpty holds for deferred suspects and open chains, then releases once resolved', async (t: TestContext) => {
  const { storage, run, facts, empty, settleSteps } = await queueProbe(t)
  assert.equal(empty(), false, 'an unconverted deferred suspect keeps the queue open')

  convertCodeAuditSuspectsToChainSteps(storage, run, facts, undefined, { maxSteps: 1, promoteMultiHop: true })
  settleSteps()
  assert.equal(empty(), false, 'converted 3-hop chain with 0 verified hops remains an open hypothesis')

  // Host-verified ledger hop landing on the declared Hop 3 endpoint closes the chain.
  const ledger = storage.capabilityLedger(run.id)
  const seed = formatDerivedCapabilityHandle('r1seed', 'session')
  const leaf = formatDerivedCapabilityHandle('r1leaf', 'export_handle')
  ledger.addCapability({ capId: seed, kind: 'identity_session', provenance: 'attacker_seed', tenantScope: 'tenant_a', actorPersona: 'member', serviceOrigin: ORIGIN, surface: 'http', artifactDigest: 'a'.repeat(64), artifactSummary: 'seed', createdAtMs: 1000 })
  ledger.addCapability({ capId: leaf, kind: 'state_handle', provenance: 'derived_hop', tenantScope: 'tenant_a', actorPersona: 'member', serviceOrigin: ORIGIN, surface: 'http', artifactDigest: 'b'.repeat(64), artifactSummary: 'leaf', metadata: { endpoint: '/api/v1/gamma', method: 'GET' }, createdAtMs: 1100 })
  ledger.addCausalEdge({ preconditionCapIds: [seed], actorContext: { persona: 'member', serviceOrigin: ORIGIN }, hopReceiptId: 'r1-hop-3', edgeBindingKind: 'value_binding', postconditionCapId: leaf, sourceTimestampMs: 1000, targetTimestampMs: 1100 })
  assert.equal(empty(), true, 'max verified hop reached the declared hop count')
})

test('(c) open chains are released after the strike limit or when budget / wall clock is exhausted', async (t: TestContext) => {
  const exhausted = await queueProbe(t)
  convertCodeAuditSuspectsToChainSteps(exhausted.storage, exhausted.run, exhausted.facts, undefined, { maxSteps: 1, promoteMultiHop: true })
  exhausted.settleSteps()
  assert.equal(exhausted.empty(), false)
  exhausted.storage.addChainStep(exhausted.run, {
    title: 'Open chain continuation attempt 2', hypothesis: 'Continue toward the next declared hop.', priority: 70,
    targetAssetIds: exhausted.run.approved, dependsOnFactIds: [exhausted.facts[0]!.id],
  })
  exhausted.settleSteps()
  assert.equal(exhausted.empty(), true, 'two terminal attempts exhaust the hypothesis (no infinite planner loop)')

  const broke = await queueProbe(t)
  broke.storage.updateRun(broke.run.id, { spentUsd: broke.run.budgetUsd + 1 })
  assert.equal(broke.empty(), true, 'USD budget exhaustion releases the hold')

  // Pure bounds: wall-clock reserve, request budget, and drained work all release the hold.
  const base = { openChainCount: 1, deferredSuspectCount: 0, elapsedMs: 0, maxDurationMs: 600_000 }
  assert.deepEqual(evaluateOpenChainHold(base), { hold: true, reason: 'open_chain_hypotheses' })
  assert.deepEqual(evaluateOpenChainHold({ ...base, deferredSuspectCount: 2 }), { hold: true, reason: 'deferred_suspects' })
  assert.equal(evaluateOpenChainHold({ ...base, elapsedMs: 545_000 }).reason, 'wall_reserve_exhausted')
  assert.equal(evaluateOpenChainHold({ ...base, requestsSpent: 50, requestBudget: 50 }).reason, 'request_budget_exhausted')
  assert.equal(evaluateOpenChainHold({ ...base, openChainCount: 0 }).hold, false)
  assert.equal(evaluateOpenChainHold({ ...base, budgetUsdSpent: 0.5, budgetUsdLimit: 1, requestBudget: 0 }).hold, true, '0 request budget means unlimited')
})

test('(c) coordinator stop gates respect a non-empty high-priority queue; exhaustion still wins', () => {
  const now = Date.now()
  const base = { budgetExhausted: false, budgetRequests: 100, spentRequests: 10, startedAt: now, maxDurationMs: 600_000 }
  const frontierStop = { decision: 'stop' as const, reason: 'frontier_stagnated' as const, productive: false, nextUnproductiveWaves: 2, detail: 'stagnated',
    reachDelta: { newTenants: [], newRoles: [], newServices: [], newSurfaces: [], newHopReceiptIds: [], newCompositeReceiptIds: [] } }
  assert.equal(coordinatorSchedulerDecision({ ...base, coordinatorDone: true, highPriorityQueueEmpty: false }).decision, 'continue')
  assert.equal(coordinatorSchedulerDecision({ ...base, coordinatorDone: true, highPriorityQueueEmpty: true }).reason, 'coordinator_done')
  assert.equal(coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: false, consecutiveDryRounds: 4, frontierDecision: frontierStop }).decision, 'continue')
  assert.equal(coordinatorSchedulerDecision({ ...base, highPriorityQueueEmpty: true, consecutiveDryRounds: 4, frontierDecision: frontierStop }).reason, 'diminishing_returns')
  assert.equal(coordinatorSchedulerDecision({ ...base, startedAt: now - 700_000, coordinatorDone: true, highPriorityQueueEmpty: false }).reason, 'wallclock_exhausted')
  assert.equal(coordinatorSchedulerDecision({ ...base, emptyRounds: 2, coordinatorDone: true, highPriorityQueueEmpty: false }).reason, 'diminishing_returns',
    'K=2 empty planner rounds still bound a planner that cannot progress an open chain')
})

// ---------------------------------------------------------------------------
// (d) World Graph openChains[], multi-hop summaries, ledger edge endpoints
// ---------------------------------------------------------------------------

function chainFact(i: number, hops = 4): WorldGraphFactInput {
  const routes = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'].slice(0, hops)
  const trajectory = routes.map((r, h) => `Hop ${h + 1} (${h % 2 ? 'POST' : 'GET'} /api/v1/${r}, svc/${r}.ts:${10 + h}, sink)`).join(' -> ')
  return {
    id: `fact-chain-${String.fromCharCode(97 + i)}`, origin: ORIGIN, kind: 'code_audit_suspect',
    summary: `Cross-tenant export trajectory through a weak ownership boundary across the reporting service: ${trajectory}`,
    data: { subkind: 'code_audit_suspect', hypothesis: trajectory },
  }
}

test('(d) parseDeclaredChainHops reads the generic Hop N trajectory format', () => {
  const hops = parseDeclaredChainHops(THREE_HOP)
  assert.deepEqual(hops.map(h => [h.hop, h.method, h.endpoint]), [[1, 'GET', '/api/v1/alpha'], [2, 'POST', '/api/v1/beta'], [3, 'GET', '/api/v1/gamma']])
  assert.deepEqual(parseDeclaredChainHops('no trajectory here'), [])
  assert.equal(parseDeclaredChainHops('Hop 1 then Hop 99 then Hop 2').length, 2, 'out-of-range hop numbers are ignored')
})

test('(d) World Graph renders bounded openChains with stalled endpoints, multi-hop summaries, and ledger endpoints', () => {
  const facts = Array.from({ length: 10 }, (_, i) => chainFact(i))
  const ledgerEdges = [
    { edgeId: 'edge-1', fromOrigin: ORIGIN, from: 'member value_binding', toOrigin: ORIGIN, to: 'identity_session http', endpoint: '/api/v1/alpha' },
    { edgeId: 'edge-2', fromOrigin: ORIGIN, from: 'member value_binding', toOrigin: ORIGIN, to: 'scoped_token http', endpoint: '/api/v1/beta' },
  ]
  const snapshot = buildWorldGraphSnapshot({ runId: 'run-r1', endpoints: [], exchanges: [], facts, ledgerEdges, approvedOrigins: [ORIGIN] })

  assert.equal(snapshot.openChains.length, 4, 'openChains is bounded')
  assert.equal(snapshot.truncation.omittedOpenChains, 6)
  const chain = snapshot.openChains[0]!
  assert.equal(chain.declaredHops, 4)
  assert.equal(chain.maxVerifiedHop, 2, 'matched against host-verified ledger hop endpoints')
  assert.equal(chain.stalledEndpoint, 'GET /api/v1/gamma')
  assert.ok(chain.nextHop?.includes('/api/v1/gamma'))

  const fact = snapshot.facts.find(f => f.id === 'fact-chain-a')!
  assert.ok(fact.summary.includes('Hop 3 GET /api/v1/gamma') && fact.summary.includes('Hop 4 POST /api/v1/delta'), 'Hop 3+ survives summary compaction')
  assert.ok(fact.summary.length <= 240)
  assert.ok(snapshot.facts.every(f => f.summary.length <= 240))

  const edge = snapshot.edges.find(e => e.id === 'edge-2')!
  assert.equal(edge.endpoint, '/api/v1/beta', 'capability-ledger edges carry the endpoint the hop landed on')

  for (const budget of [4096, 1500]) {
    const json = serializeWorldGraph(snapshot, budget)
    assert.ok(Buffer.byteLength(json, 'utf8') <= budget, `fits ${budget}B`)
    const parsed = JSON.parse(json) as typeof snapshot
    assert.equal(parsed.openChains.length + parsed.truncation.omittedOpenChains, 10, 'omitted count stays exact')
  }

  const closed = deriveOpenChainHypotheses({ suspects: [chainFact(0, 2)], verifiedEndpoints: ['/api/v1/alpha', '/api/v1/beta'] })
  assert.deepEqual(closed, [], 'fully verified chains are not open')
})

// ---------------------------------------------------------------------------
// (e) Planner source-predicted hops + scaled code-audit ceiling
// ---------------------------------------------------------------------------

function mockProfile(endpoint: string): ResolvedModelProfile {
  return {
    id: 'r1-mock-profile', name: 'R1 Mock', endpoint, model: 'mock-r1', protocol: 'responses', key: 'sk-test-r1-planner',
    priority: 100, enabled: true, contextWindow: 128_000, maxTokens: 4096, thinkingLevel: 'off', roleAffinity: 'tactical',
    inputCostPerMtok: 0, cachedInputCostPerMtok: 0, outputCostPerMtok: 0, healthState: 'closed', cooldownUntil: null, lastError: null,
  } as ResolvedModelProfile
}

test('(e) planner prompt allows source-predicted next hops and keeps open chains out of done', async (t: TestContext) => {
  const snapshot = buildWorldGraphSnapshot({
    runId: 'run-r1-plan', endpoints: [], exchanges: [], facts: [chainFact(0)], approvedOrigins: [ORIGIN],
    ledgerEdges: [{ edgeId: 'edge-1', fromOrigin: ORIGIN, from: 'member value_binding', toOrigin: ORIGIN, to: 'identity_session http', endpoint: '/api/v1/alpha' }],
  })
  const llm = await startMockLlmServer(t, () => ({ type: 'text', text: JSON.stringify({ summary: 'ok', done: false, newSteps: [], cancelStepIds: [] }) }))
  const decision = await planWithWorldGraph({ runId: 'run-r1-plan', goal: 'Verify chained authorization boundaries', roundNo: 2, snapshot, approvedOrigins: [ORIGIN], profiles: [mockProfile(llm.endpoint)], remainingStepCap: 4 })
  assert.equal(decision.parseError, null)
  const request = JSON.stringify(llm.calls[0]!.body)
  assert.ok(request.includes('source-predicted'), 'planner may propose source-predicted / code-audit next hops')
  assert.ok(request.includes('openChains is empty'), 'done requires no open chain hypothesis')
  assert.ok(request.includes('stalledEndpoint') && request.includes('POST /api/v1/beta'), 'snapshot carries the stalled hop')

  // `$0` floor continues open chains first, citing the chain fact id.
  const floor = buildDeterministicFallbackPlan({ snapshot, approvedOrigins: [ORIGIN], remainingStepCap: 3 })
  assert.equal(floor[0]!.dependsOnFactIds[0], 'fact-chain-a')
  assert.ok(floor[0]!.title.includes('Hop 2/4') && floor[0]!.title.includes('POST /api/v1/beta'))
})

test('(e) Phase-0 code-audit ceiling scales modestly with maxDurationMs and stays bounded', () => {
  assert.equal(resolveSourceAuditWallClockMs(4 * 60_000), 45_000, 'smoke runs keep the floor')
  assert.equal(resolveSourceAuditWallClockMs(10 * 60_000), 90_000, 'short runs stay <= 90s')
  assert.equal(resolveSourceAuditWallClockMs(15 * 60_000), 90_000, 'continuous at the short-run threshold')
  assert.equal(resolveSourceAuditWallClockMs(20 * 60_000), 120_000)
  assert.equal(resolveSourceAuditWallClockMs(30 * 60_000), 180_000)
  assert.equal(resolveSourceAuditWallClockMs(4 * 60 * 60_000), 210_000, 'finite long-run ceiling')
  let previous = 0
  for (let min = 1; min <= 120; min += 1) {
    const ms = resolveSourceAuditWallClockMs(min * 60_000)
    assert.ok(ms >= previous && ms <= 210_000, `monotone and bounded at ${min}m`)
    previous = ms
  }
  assert.ok(resolveSourceAuditSettlementMs(resolveSourceAuditWallClockMs(30 * 60_000)) < 180_000, 'settlement prompt still fires before the cap')
})
