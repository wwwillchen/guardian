/**
 * R2 — Proof-carrying rotation handoff & post-persistence confirmation (behavioral guards).
 *
 * Pins, against real exported functions plus a real SQLite `Store` / `ExecReconPlanner`:
 *  1. Hop-checkpoint handoff briefs carry a sanitized `proofDraft` (rejectedBy, missingEvidence,
 *     redacted script skeleton, ordered hops) and trimming under a tight byte budget drops
 *     notebook chatter / draft snippets / off-spine hops first while preserving the root hop and
 *     the terminal hop of the root-to-terminal spine.
 *  2. The continuation directive asks the worker to skip redundant recon but re-execute the full
 *     ordered hop chain from root to terminal in ONE verification script, and continuation steps
 *     surface the proof draft's repair context.
 *  3. Confirmation is recorded only after proof persistence returns a persisted finding.
 *  4. A confirmed composite shorter than the parent's declared hop chain keeps continuing, targets
 *     the predicted next hop (not the last exchange), and an active proof draft grants +1 continuation.
 */
import assert from 'node:assert/strict'
import { test, type TestContext } from 'node:test'

import {
  AssignmentProofHandoffState,
  CapabilityLedger,
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  buildNearMissProofDraft,
  finalizeHopCheckpointBrief,
  formatDerivedCapabilityHandle,
  isActiveProofDraft,
  parseDeclaredHopsFromText,
  redactProofScriptSkeleton,
  renderHopContinuationRepairContext,
  resolveContinuationParentContext,
  resolveHopContinuationBudget,
  resolvePredictedNextHop,
  sanitizeProofDraft,
  type CompactCheckpointHop,
  type HopCheckpointBrief,
  type HopProofDraft,
} from '../src/server/capability-ledger.ts'
import { HOP_CONTINUATION_DIRECTIVE, type ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { Execution, MAX_CHAIN_CONTINUATIONS } from '../src/server/execution.ts'
import type { ChainStep, Fact, Run, Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://app.example.invalid'
const FAKE_BEARER = `Bearer ${'Q'.repeat(12)}.${'R'.repeat(16)}.${'S'.repeat(16)}`
const FAKE_JWT = `eyJ${'a'.repeat(20)}.${'b'.repeat(20)}.${'c'.repeat(20)}`

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function hop(n: number, extra: Partial<CompactCheckpointHop> = {}): CompactCheckpointHop {
  return {
    hop: n, receiptId: `rcpt:hop-${n}`, capId: `cap:hop_h${n}:slot`, kind: 'state_handle', surface: 'http',
    service: `${ORIGIN}/service-${n}`, tenant: 'tenant_alpha', actor: 'member_alpha', role: 'member', binding: 'value_binding', ...extra,
  }
}

function sampleDraft(): HopProofDraft {
  return {
    rejectedBy: 'composite_receipt:terminal_oracle',
    missingEvidence: ['terminal exchange lacks foreign-tenant marker', 'control exchange missing', 'edge h2->h3 unbound'],
    orderedHops: ['POST /api/v1/a', 'GET /api/v1/b', 'PUT /api/v1/c'],
    scriptSkeleton: 'const a = await ctx.http.post(\'/api/v1/a\')\nconst b = await ctx.http.get(\'/api/v1/b\')\nreturn ctx.prove_composite({ hops })',
  }
}

function bigBrief(hops: CompactCheckpointHop[], proofDraft?: HopProofDraft): HopCheckpointBrief {
  const filler = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => `${prefix} /api/v1/resource-${i}/collection-item [persona_${i}] -> 200 observed notebook chatter`)
  return {
    schema: 'v8.hop_checkpoint.v1', branchKey: 'branch:r2', depth: hops.length, targetHop: hops.length + 1, mode: 'pivot', evi: 1,
    verifiedHops: hops, capabilityHandles: hops.map(h => h.capId),
    nextGoal: { targetSurfaceKey: `${ORIGIN}|http|/api/v1/next`, surface: 'http', service: ORIGIN, endpoint: '/api/v1/next', hypothesisClass: 'multi_hop_chain', goal: HOP_CONTINUATION_DIRECTIVE },
    workflowNotebook: { triedRecipes: filler('GET', 10), discoveredRoutes: filler('POST', 10), openHypotheses: filler('open', 6), verifiedHypotheses: filler('verified', 6) },
    ...(proofDraft ? { proofDraft } : {}),
    doNotRediscover: true,
  }
}

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

interface PlannerHarness { storage: Store; run: Run; planner: ExecReconPlanner; assetId: string }

async function plannerHarness(t: TestContext): Promise<PlannerHarness> {
  const { storage } = makeStore(t, 'kovo-r2-proof-')
  const { run } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const engine = new Execution(storage, { backend: stubBackend(), maxDurationMs: 900_000 })
  t.after(() => engine.stop())
  const planner = (engine as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
  return { storage, run, planner, assetId: run.candidates.find(c => run.approved.includes(c.id))!.id }
}

function addChainHopFacts(h: PlannerHarness, worker: Parameters<Store['addFact']>[1]): Fact[] {
  const spec = [
    { endpoint: '/api/v1/a', method: 'POST', verified: true },
    { endpoint: '/api/v1/b', method: 'GET', verified: true },
    { endpoint: '/api/v1/c', method: 'PUT', verified: false },
  ]
  return spec.map((s, i) => h.storage.addFact(h.run, worker, {
    kind: 'note', origin: ORIGIN, summary: `Declared hop ${i + 1} ${s.method} ${s.endpoint}`,
    data: { subkind: 'chain_hop', hop: { hopId: `hop:r2:${i + 1}`, roundNo: i + 1, hopIndex: i, artifactKind: 'workflow_state_handle', artifactRef: `state:r2-${i + 1}`, ...s } },
    sourceOrigins: [ORIGIN],
  }))
}

function checkpointBriefOf(storage: Store, run: Run, step: ChainStep): HopCheckpointBrief | null {
  const ids = new Set(step.dependsOnFactIds)
  const fact = storage.listFacts(run.id, { includeTainted: false, limit: 500 }).find(f => ids.has(f.id) && f.data?.subkind === 'hop_checkpoint')
  return (fact?.data?.checkpointBrief as HopCheckpointBrief | undefined) ?? null
}

function seedSealedLedgerCap(storage: Store, runId: string, slot: string): string {
  const capId = formatDerivedCapabilityHandle(`r2_${slot}`, 'derived')
  storage.capabilityLedger(runId).addCapability({
    capId, kind: 'state_handle', provenance: 'derived_hop', tenantScope: 'tenant_alpha', actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN, surface: 'http', artifactDigest: 'd'.repeat(64), artifactSummary: 'Derived state handle', createdAtMs: 1000,
  })
  return capId
}

// ---------------------------------------------------------------------------
// 1. Proof-carrying brief + root-hop-preserving trimming
// ---------------------------------------------------------------------------

test('R2.1a: buildNearMissProofDraft captures rejectedBy, missingEvidence, ordered 2xx/3xx hops, and a redacted skeleton', () => {
  const script = [
    '// helper comment that must not survive',
    `const auth = { authorization: '${FAKE_BEARER}' }`,
    `const a = await ctx.http.post('/api/v1/a', { headers: { authorization: '${FAKE_BEARER}' } })`,
    `const b = await ctx.http.get('/api/v1/b?token=${FAKE_JWT}')`,
    'const unused = 1 + 2',
    'return ctx.prove_composite({ hops: [a, b] })',
  ].join('\n')
  const draft = buildNearMissProofDraft({
    script, rejectedBy: 'composite_receipt', failedStage: 'terminal_oracle', reason: 'terminal oracle not satisfied',
    missingEvidence: ['control exchange missing'],
    transcript: [
      { seq: 3, method: 'get', pathAndQuery: '/api/v1/b?x=1', status: 200 },
      { seq: 1, method: 'POST', pathAndQuery: '/api/v1/a', status: 201 },
      { seq: 2, method: 'GET', pathAndQuery: '/api/v1/denied', status: 403 },
      { seq: 4, method: 'GET', pathAndQuery: '/api/v1/b', status: 200 },
    ],
  })
  assert.ok(draft)
  assert.equal(draft.rejectedBy, 'composite_receipt:terminal_oracle')
  assert.deepEqual(draft.missingEvidence, ['control exchange missing', 'terminal oracle not satisfied'])
  assert.deepEqual(draft.orderedHops, ['POST /api/v1/a', 'GET /api/v1/b'], 'ordered by seq, 2xx/3xx only, consecutive duplicates collapsed')
  const skeleton = draft.scriptSkeleton ?? ''
  assert.ok(skeleton.includes('ctx.prove_composite'), 'structural verification call survives')
  assert.ok(skeleton.includes('ctx.http.post'), 'hop call outline survives')
  assert.ok(!skeleton.includes('helper comment'), 'comments are dropped')
  assert.ok(!skeleton.includes('const unused'), 'non-structural lines are dropped')
  assert.ok(!skeleton.includes(FAKE_BEARER) && !skeleton.includes(FAKE_JWT), 'raw credentials are redacted from the skeleton')
  assert.ok(isActiveProofDraft(draft))
  assert.equal(isActiveProofDraft({ orderedHops: ['GET /x'] }), false, 'no rejection -> not an active repair handoff')
  assert.equal(buildNearMissProofDraft({}), undefined)
})

test('R2.1b: sanitizeProofDraft scrubs secrets in every field and bounds the skeleton', () => {
  const clean = sanitizeProofDraft({
    rejectedBy: `oracle ${FAKE_BEARER}`, missingEvidence: [`missing access_token=${'z'.repeat(24)}`],
    orderedHops: [`GET /api/v1/items?sig=${FAKE_JWT}`], scriptSkeleton: `await ctx.http.get('/x', '${FAKE_JWT}')`,
  })
  const json = JSON.stringify(clean)
  assert.ok(!json.includes(FAKE_JWT) && !json.includes('z'.repeat(24)) && !json.includes(FAKE_BEARER))
  assert.ok(redactProofScriptSkeleton(Array.from({ length: 80 }, (_, i) => `await ctx.http.get('/api/v1/r${i}')`).join('\n')).length <= 560)
  assert.equal(sanitizeProofDraft({}), undefined)
})

test('R2.1c: finalizeHopCheckpointBrief keeps proofDraft and the root-to-terminal hop spine under a tight budget', () => {
  const spine = [1, 2, 3, 4, 5].map(n => hop(n))
  const sideBranch = hop(9, { capId: 'cap:hop_side:slot', receiptId: 'rcpt:side', offSpine: true })
  const raw = bigBrief([spine[0]!, sideBranch, ...spine.slice(1)], sampleDraft())

  const full = finalizeHopCheckpointBrief(raw, DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  assert.ok(full.checkpointBytes <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES)
  assert.equal(full.brief.verifiedHops[0]!.capId, spine[0]!.capId, 'root hop never dropped from the front')
  assert.equal(full.brief.verifiedHops.at(-1)!.capId, spine[4]!.capId, 'terminal hop preserved')
  assert.equal(full.brief.verifiedHops.some(h => h.offSpine), false, 'off-spine side branch trimmed before spine hops')
  assert.deepEqual(full.brief.verifiedHops.map(h => h.capId), spine.map(h => h.capId), 'contiguous spine survives intact at 2 KB')
  assert.ok(full.brief.proofDraft?.rejectedBy, 'proofDraft retained in the 2 KB handoff')
  assert.ok(full.brief.workflowNotebook === undefined || (full.brief.workflowNotebook.triedRecipes?.length ?? 0) < 10, 'notebook chatter trimmed first')

  const tight = finalizeHopCheckpointBrief(raw, 1100)
  assert.ok(tight.checkpointBytes <= 1100, `expected <= 1100 B, got ${tight.checkpointBytes}`)
  assert.equal(tight.brief.truncated, true)
  assert.equal(tight.brief.workflowNotebook, undefined, 'notebook chatter is the first thing dropped')
  assert.equal(tight.brief.verifiedHops[0]!.capId, spine[0]!.capId, 'root hop survives a tight budget')
  assert.equal(tight.brief.verifiedHops.at(-1)!.capId, spine[4]!.capId, 'terminal hop survives a tight budget')
  assert.ok((tight.brief.omittedEarlierHops ?? 0) >= 1, 'omitted hops are accounted for')

  const lean = finalizeHopCheckpointBrief(raw, 700)
  assert.ok(lean.checkpointBytes <= 700, `expected <= 700 B, got ${lean.checkpointBytes}`)
  assert.equal(lean.brief.verifiedHops.length, 1, 'only the root survives a lean budget')
  assert.equal(lean.brief.verifiedHops[0]!.receiptId, spine[0]!.receiptId, 'the root hop is the last hop standing')

  const floor = finalizeHopCheckpointBrief(raw, 512)
  assert.ok(floor.checkpointBytes <= 512, `hard byte cap still holds at the ledger minimum (got ${floor.checkpointBytes})`)
})

test('R2.1d: CapabilityLedger.buildHopCheckpointBrief marks side branches off-spine, carries proofDraft, and trims them first', () => {
  const ledger = new CapabilityLedger(':memory:', { runId: 'run-r2' })
  const caps = [1, 2, 3, 4].map(n => formatDerivedCapabilityHandle(`spine${n}`, 'slot'))
  const side = formatDerivedCapabilityHandle('side1', 'slot')
  const add = (capId: string, at: number, provenance: 'attacker_seed' | 'derived_hop') => ledger.addCapability({
    capId, kind: 'state_handle', provenance, tenantScope: 'tenant_alpha', actorPersona: 'member_alpha',
    serviceOrigin: ORIGIN, surface: 'http', artifactDigest: computeDigest(capId), artifactSummary: `node ${capId}`, createdAtMs: at,
  })
  add(caps[0]!, 1000, 'attacker_seed'); add(side, 1050, 'attacker_seed')
  caps.slice(1).forEach((c, i) => add(c, 1100 + i * 100, 'derived_hop'))
  caps.slice(1).forEach((c, i) => ledger.addCausalEdge({
    preconditionCapIds: i === 1 ? [caps[i]!, side] : [caps[i]!], actorContext: { persona: 'member_alpha', tenantScope: 'tenant_alpha' },
    hopReceiptId: `rcpt-${i + 1}-${i + 2}`, edgeBindingKind: 'value_binding', postconditionCapId: c,
    sourceTimestampMs: 1000 + i * 100, targetTimestampMs: 1100 + i * 100,
  }))
  const brief = ledger.buildHopCheckpointBrief(caps[3]!, DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES, { proofDraft: sampleDraft() })
  assert.equal(brief.verifiedHops[0]!.capId, caps[0], 'root-most hop first')
  assert.equal(brief.verifiedHops.at(-1)!.capId, caps[3], 'terminal hop last')
  assert.deepEqual(brief.verifiedHops.filter(h => h.offSpine).map(h => h.capId), [side], 'only the side branch is off-spine')
  assert.equal(brief.proofDraft?.rejectedBy, 'composite_receipt:terminal_oracle')
  assert.deepEqual(brief.proofDraft?.orderedHops, sampleDraft().orderedHops)

  const tight = finalizeHopCheckpointBrief({ ...brief, workflowNotebook: bigBrief([]).workflowNotebook! }, 900)
  assert.ok(tight.checkpointBytes <= 900)
  assert.equal(tight.brief.verifiedHops[0]!.capId, caps[0], 'root hop preserved through trimming')
  assert.equal(tight.brief.verifiedHops.at(-1)!.capId, caps[3], 'terminal hop preserved through trimming')
  assert.equal(tight.brief.verifiedHops.some(h => h.capId === side), false, 'off-spine hop dropped before any spine hop')
})

function computeDigest(seed: string): string {
  let hex = ''
  for (let i = 0; hex.length < 64; i += 1) hex += (seed.charCodeAt(i % seed.length) + i).toString(16).padStart(2, '0')
  return hex.slice(0, 64)
}

// ---------------------------------------------------------------------------
// 2. Continuation prompt contract
// ---------------------------------------------------------------------------

test('R2.2a: HOP_CONTINUATION_DIRECTIVE skips redundant recon but replays the full ordered chain in ONE script', () => {
  const d = HOP_CONTINUATION_DIRECTIVE.toLowerCase()
  assert.ok(d.includes('skip redundant discovery/recon'))
  assert.ok(d.includes('re-execute the full ordered hop chain from root to terminal'))
  assert.ok(HOP_CONTINUATION_DIRECTIVE.includes('ONE verification script'))
  assert.ok(d.includes('ctx.prove_composite'))
  assert.equal(d.includes('do not repeat'), false, 'no contradictory "do not repeat verified hops" guidance')
  assert.ok(HOP_CONTINUATION_DIRECTIVE.length <= 180, 'fits the 180-char nextGoal.goal field without truncation')
})

test('R2.2b: renderHopContinuationRepairContext surfaces the structured near-miss repair context', () => {
  const text = renderHopContinuationRepairContext({
    partialComposite: true, confirmedCompositeHopCount: 2, declaredHopCount: 3,
    nextHop: { hopIndex: 2, endpoint: '/api/v1/c', method: 'put', verified: false }, proofDraft: sampleDraft(),
  })
  assert.ok(text.includes('Partial composite confirmed (2/3 hops)'))
  assert.ok(text.includes('PUT /api/v1/c'))
  assert.ok(text.includes('rejectedBy=composite_receipt:terminal_oracle'))
  assert.ok(text.includes('missingEvidence=[terminal exchange lacks foreign-tenant marker'))
  assert.ok(text.includes('orderedHops=1) POST /api/v1/a -> 2) GET /api/v1/b -> 3) PUT /api/v1/c'))
  assert.ok(text.includes('script outline:'))
  assert.ok(text.length <= 640)
  assert.equal(renderHopContinuationRepairContext({ partialComposite: false, confirmedCompositeHopCount: 0, declaredHopCount: 0, nextHop: null }), '')
})

test('R2.2c: a rotated continuation step carries the directive plus the proofDraft into hypothesis and persisted brief', async (t) => {
  const h = await plannerHarness(t)
  const step = h.storage.addChainStep(h.run, {
    title: 'Multi-hop state pivot', hypothesis: 'Chain a derived state handle across services.', category: 'broken-access-control', priority: 90,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives'],
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const cap = seedSealedLedgerCap(h.storage, h.run.id, 'prompt')
  const res = h.planner.enqueueHopContinuationOnRotation({
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: false, partialSummary: '[partial] near-miss composite',
    recordedFacts: [], recordedExchanges: [{ id: 'ex-1', origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/a', status: 201 }],
    sealedCapHandles: [cap], trigger: 'wall_clock_rotated', proofDraft: sampleDraft(),
  })
  assert.equal(res.enqueued, true, `expected enqueue, got ${res.reason}`)
  const cont = res.continuationStep!
  assert.ok(cont.hypothesis.includes(HOP_CONTINUATION_DIRECTIVE))
  assert.ok(cont.hypothesis.includes('rejectedBy=composite_receipt:terminal_oracle'), 'repair context surfaced in the continuation prompt')
  const brief = checkpointBriefOf(h.storage, h.run, cont)
  assert.ok(brief, 'continuation has a persisted hop_checkpoint brief')
  assert.equal(brief.proofDraft?.rejectedBy, 'composite_receipt:terminal_oracle', 'rotated worker receives proofDraft on handoff')
  assert.deepEqual(brief.proofDraft?.orderedHops, sampleDraft().orderedHops)
})

// ---------------------------------------------------------------------------
// 3. Post-persistence confirmation ordering
// ---------------------------------------------------------------------------

test('R2.3: confirmation is recorded only after persistence returns a persisted finding', () => {
  const throwing = new AssignmentProofHandoffState()
  throwing.recordNearMiss({ rejectedBy: 'receipt', missingEvidence: ['x'], transcript: [{ seq: 1, method: 'GET', pathAndQuery: '/a', status: 200 }] })
  assert.throws(() => throwing.commitPersistence(() => { throw new Error('persist failed') }, 3), /persist failed/)
  assert.equal(throwing.confirmed, false, 'a throwing persist keeps retries and continuations enabled')
  assert.equal(throwing.confirmedCompositeHopCount, 0)
  assert.ok(throwing.proofDraft, 'near-miss draft survives a failed persist for the handoff')

  const empty = new AssignmentProofHandoffState()
  assert.throws(() => empty.commitPersistence(() => ({ findingId: '' }), 2), /no confirmed finding/)
  assert.equal(empty.confirmed, false, 'a non-persisting outcome does not confirm')

  const ok = new AssignmentProofHandoffState()
  ok.recordNearMiss({ rejectedBy: 'receipt', missingEvidence: ['x'], transcript: [{ seq: 1, method: 'GET', pathAndQuery: '/a', status: 200 }] })
  const persisted = ok.commitPersistence(() => ({ findingId: 'finding-1', replaySpecId: 'spec-1', receiptId: null }), 2)
  assert.equal(persisted.findingId, 'finding-1')
  assert.equal(ok.confirmed, true)
  assert.equal(ok.confirmedCompositeHopCount, 2, 'confirmed composite hop count tracked for partial-chain decisions')
  assert.equal(ok.proofDraft, undefined, 'a persisted confirmation retires the near-miss draft')
  ok.commitPersistence(() => ({ findingId: 'finding-2' }), 1)
  assert.equal(ok.confirmedCompositeHopCount, 2, 'keeps the largest persisted composite')
})

// ---------------------------------------------------------------------------
// 4. Partial composite continuation + repair bonus
// ---------------------------------------------------------------------------

test('R2.4a: parent context marks shorter composites partial, picks the predicted next hop, and grants the repair bonus', () => {
  const predicted = [
    { hopIndex: 0, endpoint: '/api/v1/a', method: 'POST', verified: true },
    { hopIndex: 1, endpoint: '/api/v1/b', method: 'GET', verified: true },
    { hopIndex: 2, endpoint: '/api/v1/c', method: 'PUT', verified: false },
  ]
  const partial = resolveContinuationParentContext({ parentBriefs: [], predictedHops: predicted, confirmedCompositeHopCount: 2, proofDraft: sampleDraft() })
  assert.equal(partial.partialComposite, true)
  assert.equal(partial.declaredHopCount, 3)
  assert.equal(partial.nextHop?.endpoint, '/api/v1/c')
  assert.equal(partial.repairBonus, 1)

  const full = resolveContinuationParentContext({ parentBriefs: [], predictedHops: predicted, confirmedCompositeHopCount: 3 })
  assert.equal(full.partialComposite, false, 'a composite covering every declared hop is a full chain')
  assert.equal(full.repairBonus, 0)

  const byBrief = resolveContinuationParentContext({ parentBriefs: [bigBrief([hop(1), hop(2), hop(3)], sampleDraft())], predictedHops: [], confirmedCompositeHopCount: 2 })
  assert.equal(byBrief.declaredHopCount, 4, 'parent brief targetHop declares the chain length')
  assert.equal(byBrief.partialComposite, true)
  assert.equal(byBrief.proofDraft?.rejectedBy, 'composite_receipt:terminal_oracle', 'draft inherited from the parent brief')
  assert.equal(byBrief.notebooks.length, 1)

  assert.equal(resolveContinuationParentContext({ parentBriefs: [], predictedHops: [] }).partialComposite, false, 'unconfirmed / undeclared stays non-partial')
  assert.equal(resolvePredictedNextHop(predicted, 0)?.endpoint, '/api/v1/c', 'first unverified predicted hop')
  assert.equal(resolvePredictedNextHop([{ hopIndex: 0, verified: false }], 0), null, 'hops without an endpoint are ignored')

  assert.equal(resolveHopContinuationBudget({ requestedMax: 2, genericCap: 1, hasSealedLedgerCap: true, repairBonus: 1 }), 3)
  assert.equal(resolveHopContinuationBudget({ requestedMax: 2, genericCap: 1, hasSealedLedgerCap: false, repairBonus: 0 }), 1)
  assert.equal(resolveHopContinuationBudget({ requestedMax: 2, genericCap: 1, hasSealedLedgerCap: false, repairBonus: 5 }), 2, 'bonus is bounded to +1')
})

test('R2.4b: a confirmed 2-of-3-hop composite keeps continuing and targets the predicted next hop, not the last exchange', async (t) => {
  const h = await plannerHarness(t)
  const anchor = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, 'anchor', 'anchor', { sourceOrigins: [ORIGIN] })
  const hopFacts = addChainHopFacts(h, anchor)
  const step = h.storage.addChainStep(h.run, {
    title: 'Declared three-hop chain', hypothesis: 'Chain a derived handle across three hops.', category: 'broken-access-control', priority: 90,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives'], dependsOnFactIds: hopFacts.map(f => f.id),
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const base = {
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: true, partialSummary: 'Confirmed a 2-hop composite.',
    recordedFacts: [], recordedExchanges: [{ id: 'ex-last', origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/b?page=2', status: 200 }],
    sealedCapHandles: [], trigger: 'partial_composite' as const,
  }

  const fullChain = h.planner.enqueueHopContinuationOnRotation({ ...base, confirmedCompositeHopCount: 3 })
  assert.equal(fullChain.enqueued, false)
  assert.equal(fullChain.reason, 'already_confirmed', 'a full-chain composite still halts continuation')

  const partial = h.planner.enqueueHopContinuationOnRotation({ ...base, confirmedCompositeHopCount: 2 })
  assert.equal(partial.enqueued, true, `partial composite must not halt continuation (reason=${partial.reason})`)
  const brief = checkpointBriefOf(h.storage, h.run, partial.continuationStep!)
  assert.ok(brief)
  assert.equal(brief.nextGoal.endpoint, '/api/v1/c', 'targets the predicted next hop')
  assert.equal(brief.nextGoal.method, 'PUT')
  assert.notEqual(brief.nextGoal.endpoint, '/api/v1/b', 'does not blindly repeat the last exchange sent')
  assert.ok(partial.continuationStep!.hypothesis.includes('Partial composite confirmed (2/3 hops)'))
})

test('R2.4c: without a predicted next hop the continuation falls back to the last exchange', async (t) => {
  const h = await plannerHarness(t)
  const step = h.storage.addChainStep(h.run, {
    title: 'Undeclared chain', hypothesis: 'Chain a derived handle.', category: 'broken-access-control', priority: 90,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives'],
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const res = h.planner.enqueueHopContinuationOnRotation({
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: false, partialSummary: '[partial] progress',
    recordedFacts: [], recordedExchanges: [{ id: 'ex-1', origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/v1/last?x=1', status: 200 }],
    sealedCapHandles: [seedSealedLedgerCap(h.storage, h.run.id, 'fallback')], trigger: 'wall_clock_rotated',
  })
  assert.equal(res.enqueued, true, `expected enqueue, got ${res.reason}`)
  const brief = checkpointBriefOf(h.storage, h.run, res.continuationStep!)
  assert.equal(brief?.nextGoal.endpoint, '/api/v1/last')
  assert.equal(brief?.nextGoal.method, 'PATCH')
})

test('R2.4d: an active proofDraft grants one extra continuation beyond MAX_CHAIN_CONTINUATIONS', async (t) => {
  const h = await plannerHarness(t)
  const depth = MAX_CHAIN_CONTINUATIONS
  const step = h.storage.addChainStep(h.run, {
    title: `Deep chain [continuation #${depth}]`, hypothesis: HOP_CONTINUATION_DIRECTIVE, category: 'broken-access-control', priority: 95,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives', `chain_continuation:${depth}`],
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const cap = seedSealedLedgerCap(h.storage, h.run.id, 'bonus')
  const base = {
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: false, partialSummary: '[partial] near miss',
    recordedFacts: [], recordedExchanges: [{ id: 'ex-1', origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/a', status: 201 }],
    sealedCapHandles: [cap], trigger: 'wall_clock_rotated' as const,
  }
  const capped = h.planner.enqueueHopContinuationOnRotation(base)
  assert.equal(capped.enqueued, false)
  assert.equal(capped.reason, 'max_continuations_reached', 'no draft -> normal depth cap')

  const inactive = h.planner.enqueueHopContinuationOnRotation({ ...base, proofDraft: { orderedHops: ['POST /api/v1/a'] } })
  assert.equal(inactive.reason, 'max_continuations_reached', 'a draft without a rejection is not a repair handoff')

  const repaired = h.planner.enqueueHopContinuationOnRotation({ ...base, proofDraft: sampleDraft() })
  assert.equal(repaired.enqueued, true, `active near-miss draft must grant +1 continuation (reason=${repaired.reason})`)
  assert.equal(repaired.continuationDepth, depth + 1)
})

test('R2.4e: audit-declared "Hop 1 -> Hop 2 -> Hop 3 -> Hop 4" suspects continue past a 2-hop partial composite targeting Hop 3', async (t) => {
  const h = await plannerHarness(t)
  const auditText = 'Hop 1 (POST /api/v1/seed, a.ts:10) -> Hop 2 (GET /api/v1/pivot, b.ts:20) -> Hop 3 (PUT /api/v1/elevate, c.ts:30) -> Hop 4 (DELETE /api/v1/target, d.ts:40)'
  const parsed = parseDeclaredHopsFromText([auditText])
  assert.deepEqual(parsed.map(p => `${p.hopIndex}:${p.method} ${p.endpoint}`), [
    '0:POST /api/v1/seed', '1:GET /api/v1/pivot', '2:PUT /api/v1/elevate', '3:DELETE /api/v1/target',
  ])
  const step = h.storage.addChainStep(h.run, {
    title: 'Source audit verify · multi-hop suspect', hypothesis: auditText, category: 'broken-access-control', priority: 92,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives'],
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const res = h.planner.enqueueHopContinuationOnRotation({
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: true, partialSummary: 'Confirmed 2-hop partial composite.',
    recordedFacts: [], recordedExchanges: [{ id: 'ex-2', origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/pivot', status: 200 }],
    sealedCapHandles: [], trigger: 'partial_composite', confirmedCompositeHopCount: 2,
  })
  assert.equal(res.enqueued, true, `audit-declared 4-hop chain must continue after 2-hop partial (reason=${res.reason})`)
  const brief = checkpointBriefOf(h.storage, h.run, res.continuationStep!)
  assert.equal(brief?.nextGoal.endpoint, '/api/v1/elevate')
  assert.equal(brief?.nextGoal.method, 'PUT')
})

test('R2.4f: proof_draft_repair trigger enqueues a repair continuation even without recorded exchanges or sealed handles', async (t) => {
  const h = await plannerHarness(t)
  const step = h.storage.addChainStep(h.run, {
    title: 'Multi-hop repair handoff', hypothesis: 'Repair near-miss composite verification.', category: 'broken-access-control', priority: 90,
    targetAssetIds: [h.assetId], sourceOrigins: [ORIGIN], skills: ['multihop-chains', 'chain-primitives'],
  })
  const worker = h.storage.makeWorker(h.run, 'investigation', h.run.candidates[0]!, step.title, step.hypothesis, { stepId: step.id, sourceOrigins: [ORIGIN] })
  const res = h.planner.enqueueHopContinuationOnRotation({
    run: h.run, step, assignment: worker, targetOrigins: [ORIGIN], confirmed: false, partialSummary: 'Near-miss composite rejected.',
    recordedFacts: [], recordedExchanges: [], sealedCapHandles: [], trigger: 'proof_draft_repair', proofDraft: sampleDraft(),
  })
  assert.equal(res.enqueued, true, `proof_draft_repair must enqueue repair handoff (reason=${res.reason})`)
  const brief = checkpointBriefOf(h.storage, h.run, res.continuationStep!)
  assert.equal(brief?.proofDraft?.rejectedBy, 'composite_receipt:terminal_oracle')
})
