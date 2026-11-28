/**
 * Stream E1 — sibling-trial cancellation on composite confirm, shared ledger lineage key, and
 * smart parallel-trial pacing (fast, hermetic, behavioral; no source-text assertions).
 *
 * Pins, through runtime behavior only:
 *  (1) persisting a confirmed full/terminal `kovo_verify` finding early-stops active sibling trials
 *      of the same trial group (never the winner), leaving unrelated steps untouched;
 *  (2) R2 partial composites, held (`needs_review`) findings, and failed persistence never cancel
 *      siblings, and a cancellation fault is reported instead of thrown into the tool result;
 *  (3) every hop of one ledger chain shares a stable root `lineageKey` with depth advancing per
 *      hop, so `frontier-scheduler` marks a deeper hop on that lineage productive;
 *  (4) multi-trial fan-out spends at most one upfront duplicate trial per hypothesis and only on
 *      truly idle worker slots (running assignments count as busy).
 */
import assert from 'node:assert/strict'
import { test, type TestContext } from 'node:test'

import { AssignmentProofHandoffState, formatDerivedCapabilityHandle } from '../src/server/capability-ledger.ts'
import { computeMultiTrialFanout, multiTrialSurplusSlots, planMultiTrialExpansion } from '../src/server/exec-dispatch.ts'
import { resolveCausalEdgeLineage, type ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { cancelSiblingTrialsAfterProofPersistence } from '../src/server/exec-worker-runner.ts'
import { Execution } from '../src/server/execution.ts'
import { createEmptyReachState, evaluateWaveProgress, type VerifiedHopReceiptEvent } from '../src/server/frontier-scheduler.ts'
import type { ChainStep, Run, Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSession } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun, stopExecution } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const ORIGIN = 'https://app.example.test'
const THREE_HOP = 'Hop 1 (GET /api/v1/alpha, svc/a.ts:10, read) -> Hop 2 (POST /api/v1/beta, svc/b.ts:20, write) -> Hop 3 (GET /api/v1/gamma, svc/c.ts:30, read)'

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

interface EngineInternals {
  cancelSiblingTrialsForStep(run: Run, stepId: string, winnerAssignmentId: string, findingId?: string): string[]
  expandEligibleMultiTrialSteps(run: Run): void
  safeEvent(runId: string, kind: string, message: string, detail?: Record<string, unknown>): void
  reconPlanner: ExecReconPlanner
  active: Map<string, unknown>
}

async function engineFixture(t: TestContext) {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const engine = new Execution(storage, { backend: stubBackend(), deterministicSweep: false })
  t.after(() => stopExecution(engine as unknown as Parameters<typeof stopExecution>[0]))
  const internals = engine as unknown as EngineInternals
  const events: Array<{ kind: string; detail?: Record<string, unknown> }> = []
  const host = {
    cancelSiblingTrialsForStep: (...a: Parameters<EngineInternals['cancelSiblingTrialsForStep']>) => internals.cancelSiblingTrialsForStep(...a),
    safeEvent: (id: string, kind: string, message: string, detail?: Record<string, unknown>) => { events.push({ kind, ...(detail ? { detail } : {}) }); internals.safeEvent(id, kind, message, detail) },
    reconPlanner: internals.reconPlanner,
  }
  return { storage, run: storage.run(runId), internals, host, events }
}

/** One trial group (winner + 2 siblings) plus an unrelated step and a step in another trial group. */
function seedTrialGroup(storage: Store, run: Run, hypothesis = THREE_HOP) {
  const add = (title: string, extra: Partial<Parameters<Store['addChainStep']>[1]> = {}) => storage.addChainStep(run, {
    title, hypothesis, category: 'access_control', priority: 96, targetAssetIds: run.approved, ...extra,
  })
  const winner = add('Chain verify · export trajectory', { trialGroupId: 'grp-e1', trialIndex: 0 })
  const sibA = add('Chain verify · export trajectory [trial 2]', { trialGroupId: 'grp-e1', trialIndex: 1 })
  const sibB = add('Chain verify · export trajectory [trial 3]', { trialGroupId: 'grp-e1', trialIndex: 2 })
  const unrelated = add('Unrelated chain · invoice lookup')
  const otherGroup = add('Other group · profile update', { trialGroupId: 'grp-other', trialIndex: 0 })
  storage.updateChainStep(winner.id, { status: 'running' })
  storage.updateChainStep(sibA.id, { status: 'ready' })
  storage.updateChainStep(sibB.id, { status: 'pending' })
  storage.updateChainStep(unrelated.id, { status: 'ready' })
  storage.updateChainStep(otherGroup.id, { status: 'ready' })
  const status = () => Object.fromEntries(storage.listChainSteps(run.id).map(s => [s.id, s.status])) as Record<string, ChainStep['status']>
  return { winner: storage.listChainSteps(run.id).find(s => s.id === winner.id)!, sibA, sibB, unrelated, otherGroup, status }
}

// ---------------------------------------------------------------------------
// (1) Confirmed full/terminal composite cancels active siblings of the same step only
// ---------------------------------------------------------------------------

test('(1) a confirmed full composite early-stops sibling trials of the same step and nothing else', async (t: TestContext) => {
  const { storage, run, host } = await engineFixture(t)
  const g = seedTrialGroup(storage, run)
  const before = g.status()

  const canceled = cancelSiblingTrialsAfterProofPersistence(host, {
    run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-1', findingStatus: 'confirmed' }, compositeHopCount: 3,
  })
  const after = g.status()
  assert.deepEqual([...canceled].sort(), [g.sibA.id, g.sibB.id].sort())
  assert.equal(after[g.sibA.id], 'canceled')
  assert.equal(after[g.sibB.id], 'canceled')
  assert.equal(after[g.winner.id], before[g.winner.id], 'the winning step is never canceled')
  assert.equal(after[g.unrelated.id], 'ready', 'steps outside the trial group are untouched')
  assert.equal(after[g.otherGroup.id], 'ready', 'other trial groups are untouched')

  const early = storage.eventsAfter(run.id, 0, 500).filter(e => e.kind === 'trial.early_stopped')
  assert.equal(early.length, 1)
  assert.equal((early[0]!.detail as Record<string, unknown>).winnerAssignmentId, 'asg-winner')
  assert.equal((early[0]!.detail as Record<string, unknown>).findingId, 'finding-1')

  // Idempotent: a duplicate confirm on the same step finds no active sibling left.
  assert.deepEqual(cancelSiblingTrialsAfterProofPersistence(host, {
    run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-1', findingStatus: 'confirmed' }, compositeHopCount: 3,
  }), [])
})

test('(1) a confirmed single-receipt (non-composite) finding is terminal and early-stops siblings', async (t: TestContext) => {
  const { storage, run, host } = await engineFixture(t)
  const g = seedTrialGroup(storage, run, 'Missing ownership check on GET /api/v1/invoices/{id}')
  const canceled = cancelSiblingTrialsAfterProofPersistence(host, {
    run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-2', findingStatus: 'confirmed' }, compositeHopCount: 0,
  })
  assert.equal(canceled.length, 2)
  assert.equal(g.status()[g.unrelated.id], 'ready')
})

// ---------------------------------------------------------------------------
// (2) Partial composites, held findings, failed persistence: siblings keep running
// ---------------------------------------------------------------------------

test('(2) an R2 partial composite (2 of 3 declared hops) leaves every sibling running', async (t: TestContext) => {
  const { storage, run, host, internals } = await engineFixture(t)
  const g = seedTrialGroup(storage, run)
  assert.equal(internals.reconPlanner.isPartialCompositeConfirmation(run, g.winner, 2), true)
  assert.equal(internals.reconPlanner.isPartialCompositeConfirmation(run, g.winner, 3), false)
  assert.equal(internals.reconPlanner.isPartialCompositeConfirmation(run, g.winner, 0), false, 'no composite is never partial')
  const before = g.status()
  assert.deepEqual(cancelSiblingTrialsAfterProofPersistence(host, {
    run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-3', findingStatus: 'confirmed' }, compositeHopCount: 2,
  }), [])
  assert.deepEqual(g.status(), before)
})

test('(2) held / unconfirmed persisted findings never cancel siblings', async (t: TestContext) => {
  const { storage, run, host } = await engineFixture(t)
  const g = seedTrialGroup(storage, run)
  const before = g.status()
  for (const findingStatus of ['needs_review', 'rejected', '']) {
    assert.deepEqual(cancelSiblingTrialsAfterProofPersistence(host, {
      run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-4', findingStatus }, compositeHopCount: 3,
    }), [], `findingStatus=${findingStatus || '(empty)'}`)
  }
  assert.deepEqual(g.status(), before)
  assert.equal(storage.eventsAfter(run.id, 0, 500).some(e => e.kind === 'trial.early_stopped'), false)
})

test('(2) failed persistence throws before any early stop; a cancellation fault is reported, not thrown', async (t: TestContext) => {
  const { storage, run, host, events } = await engineFixture(t)
  const g = seedTrialGroup(storage, run)
  const before = g.status()

  // The worker calls the early stop only after `commitPersistence` returns; a non-persisting
  // persist throws there, so confirmation (and cancellation) never happens.
  const handoff = new AssignmentProofHandoffState()
  assert.throws(() => handoff.commitPersistence(() => ({ findingId: null })), /no confirmed finding/)
  assert.equal(handoff.confirmed, false)
  assert.deepEqual(g.status(), before)

  const faulty = { ...host, cancelSiblingTrialsForStep: () => { throw new Error('storage busy') } }
  assert.deepEqual(cancelSiblingTrialsAfterProofPersistence(faulty, {
    run, step: g.winner, assignmentId: 'asg-winner', persisted: { findingId: 'finding-5', findingStatus: 'confirmed' }, compositeHopCount: 3,
  }), [])
  assert.ok(events.some(e => e.kind === 'trial.early_stop_failed' && e.detail?.stepId === g.winner.id))
  assert.deepEqual(g.status(), before)
})

// ---------------------------------------------------------------------------
// (3) Shared ledger lineage key → chain-depth productivity
// ---------------------------------------------------------------------------

function seedLedgerChain(storage: Store, runId: string, prefix: string, hops: number, t0: number) {
  const ledger = storage.capabilityLedger(runId)
  const caps = Array.from({ length: hops + 1 }, (_, i) => {
    const capId = formatDerivedCapabilityHandle(`${prefix}${i}`, i === 0 ? 'session' : 'state_handle')
    ledger.addCapability({
      capId, kind: i === 0 ? 'identity_session' : 'state_handle', provenance: i === 0 ? 'attacker_seed' : 'derived_hop', tenantScope: 'tenant_a',
      actorPersona: 'member', serviceOrigin: ORIGIN, surface: 'http', artifactDigest: String(i).repeat(64).slice(0, 64), artifactSummary: `${prefix} ${i}`, createdAtMs: t0 + i,
    })
    return capId
  })
  const edges = caps.slice(1).map((cap, i) => ledger.addCausalEdge({
    preconditionCapIds: [caps[i]!], actorContext: { persona: 'member', serviceOrigin: ORIGIN }, hopReceiptId: `${prefix}-hop-${i + 1}`,
    edgeBindingKind: 'value_binding', postconditionCapId: cap, sourceTimestampMs: t0 + i, targetTimestampMs: t0 + i + 1,
  }))
  return { ledger, caps, edges }
}

const hopEvent = (edge: { hopReceiptId: string; postconditionCapId: string | null; edgeId: string }, extra: Partial<VerifiedHopReceiptEvent>): VerifiedHopReceiptEvent => ({
  hopReceiptId: edge.hopReceiptId, branchKey: edge.postconditionCapId ?? edge.edgeId, depth: 2, hostVerified: true,
  tenantScope: 'tenant_a', roleLabel: 'member', serviceOrigin: ORIGIN, surface: 'http', ...extra,
})

test('(3) every hop of one ledger chain shares a root lineageKey and depth advances per hop', async (t: TestContext) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const { ledger, caps, edges } = seedLedgerChain(storage, runId, 'e1a', 3, 1000)
  const lineages = edges.map(edge => resolveCausalEdgeLineage(ledger, edge))
  assert.deepEqual(lineages.map(l => l.depth), [2, 3, 4])
  assert.equal(new Set(lineages.map(l => l.lineageKey)).size, 1, 'one chain, one lineage')
  assert.equal(lineages[0]!.lineageKey, `ledger:${caps[0]}`)

  const other = seedLedgerChain(storage, runId, 'e1b', 1, 5000)
  assert.notEqual(resolveCausalEdgeLineage(other.ledger, other.edges[0]!).lineageKey, lineages[0]!.lineageKey, 'distinct chains keep distinct lineages')

  // Cycle-safe and bounded even if a ledger view ever reports a cyclic incoming relation.
  const cyclic = { getIncomingEdges: (capId: string) => [{ ...edges[0]!, preconditionCapIds: [capId === 'x' ? 'y' : 'x'], postconditionCapId: capId }] }
  const resolved = resolveCausalEdgeLineage(cyclic, { edgeId: 'e-cyc', preconditionCapIds: ['x'], postconditionCapId: 'z' })
  assert.ok(Number.isFinite(resolved.depth) && resolved.depth >= 2)
  assert.ok(resolved.lineageKey.startsWith('ledger:'))
})

test('(3) the shared lineage makes a deeper hop on a second chain productive below the run-wide max', async (t: TestContext) => {
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN], tier: 2 })
  const deep = seedLedgerChain(storage, runId, 'e1d', 3, 1000)
  const second = seedLedgerChain(storage, runId, 'e1s', 2, 5000)
  const shared = (ledger: typeof deep.ledger, edge: (typeof deep.edges)[number]) => hopEvent(edge, resolveCausalEdgeLineage(ledger, edge))
  const wave = (reach: ReturnType<typeof createEmptyReachState>, waveNo: number, hops: VerifiedHopReceiptEvent[]) =>
    evaluateWaveProgress({ waveNo, completedAssignments: 1, reach, verifiedHopReceipts: hops, activeFrontierCount: 1, consecutiveUnproductiveWaves: 0, unproductiveWaveLimit: 3 })

  const reach = createEmptyReachState()
  assert.equal(wave(reach, 1, deep.edges.map(e => shared(deep.ledger, e))).productive, true)
  assert.equal(reach.maxVerifiedHopDepth, 4)
  const s1 = wave(reach, 2, [shared(second.ledger, second.edges[0]!)])
  assert.equal(s1.productive, false, 'a depth-2 hop on saturated reach below the run-wide max is flat')
  const s2 = wave(reach, 3, [shared(second.ledger, second.edges[1]!)])
  assert.equal(s2.productive, true, 'the next hop on the same lineage advances it (2 -> 3)')
  assert.deepEqual(s2.reachDelta.newChainDepthHopReceiptIds, [second.edges[1]!.hopReceiptId])

  // Counterfactual: legacy per-edge keys + flat depth never see the lineage advance.
  const legacy = createEmptyReachState()
  wave(legacy, 1, deep.edges.map(e => hopEvent(e, {})))
  wave(legacy, 2, [hopEvent(second.edges[0]!, {})])
  assert.equal(wave(legacy, 3, [hopEvent(second.edges[1]!, {})]).productive, false)
})

// ---------------------------------------------------------------------------
// (4) Parallel-trial fan-out pacing
// ---------------------------------------------------------------------------

const queuedStep = (id: number, priority: number, extra: Record<string, unknown> = {}) => ({
  id: `step-${id}`, title: `Hypothesis ${id}`, status: 'ready' as const, priority, dependsOnFactIds: [] as string[], trialGroupId: null as string | null, ...extra,
})

test('(4) high-priority suspects get at most one upfront duplicate trial', () => {
  for (const priority of [88, 92, 96, 100]) {
    assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 8 }, { priority, dependsOnFactIds: [], trialGroupId: null }), 2, `priority ${priority}`)
  }
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 8 }, { priority: 60, dependsOnFactIds: ['f1'], trialGroupId: null }, new Set(['f1'])), 2)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 8 }, { priority: 85, dependsOnFactIds: [], trialGroupId: null }), 1)
  assert.equal(computeMultiTrialFanout({ multiTrialEnabled: true, workerConcurrency: 8 }, { priority: 99, dependsOnFactIds: [], trialGroupId: 'grp' }), 1, 'existing trials never re-expand')
  const idle = planMultiTrialExpansion({ steps: [queuedStep(1, 96)], concurrency: 8 })
  assert.deepEqual(idle.map(e => e.fanout), [2], 'an idle fleet still adds exactly one duplicate')
})

test('(4) duplicate trials only spend truly idle slots: running assignments count as busy', () => {
  assert.equal(multiTrialSurplusSlots(1, 6, 5), 0)
  assert.equal(multiTrialSurplusSlots(1, 6, 4), 1)
  assert.equal(multiTrialSurplusSlots(1, 6, -3), 5, 'negative active counts clamp to 0')
  const steps = [queuedStep(1, 96), queuedStep(2, 92)]
  assert.deepEqual(planMultiTrialExpansion({ steps, concurrency: 6, activeAssignments: 4 }), [], 'busy fleet: no upfront duplicates')
  const one = planMultiTrialExpansion({ steps, concurrency: 6, activeAssignments: 3 })
  assert.deepEqual(one.map(e => [e.step.id, e.fanout]), [['step-1', 2]], 'one idle slot buys one duplicate for the top hypothesis')
  const both = planMultiTrialExpansion({ steps, concurrency: 6, activeAssignments: 0 })
  assert.deepEqual(both.map(e => e.fanout), [2, 2])
})

test('(4) live Execution expansion caps a priority-96 suspect at one duplicate and skips a busy fleet', async (t: TestContext) => {
  const { storage, run, internals } = await engineFixture(t)
  const step = storage.addChainStep(run, { title: 'Source audit verify · POST /api/v1/export', hypothesis: 'Missing ownership check', category: 'access_control', priority: 96, targetAssetIds: run.approved })
  storage.updateChainStep(step.id, { status: 'ready' })
  const groupOf = (id: string) => storage.listChainSteps(run.id).find(s => s.id === id)?.trialGroupId ?? null

  // Busy fleet: every other worker slot is held by a running investigation assignment.
  const conc = run.workerConcurrency
  for (let i = 0; i < conc - 1; i += 1) internals.active.set(`busy-${i}`, { assignment: { runId: run.id, phase: 'investigation' }, controller: new AbortController() })
  internals.expandEligibleMultiTrialSteps(storage.run(run.id))
  assert.equal(groupOf(step.id), null, 'no duplicate trial beside a busy fleet')

  internals.active.clear()
  internals.expandEligibleMultiTrialSteps(storage.run(run.id))
  const group = groupOf(step.id)
  assert.ok(group, 'idle fleet expands the suspect')
  assert.equal(storage.listChainSteps(run.id).filter(s => s.trialGroupId === group).length, 2, 'primary + exactly one duplicate trial')
})
