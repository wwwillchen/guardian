// @fixes R3-05
/**
 * Stream S2 behavioral guard suite (zero-LLM, hermetic, zero source-text assertions):
 *
 *  1. D1 taxonomy closure — every label/canonical class registered in
 *     `DEFAULT_ORACLE_SPEC_REGISTRY` resolves in `src/vuln-taxonomy.ts`, and `spec.cwes ⊆ cweFamily`
 *     for every class-pure spec. Multi-class umbrella specs are an explicit, ratcheted exemption
 *     whose CWEs must still all be classified (widening a specific class family to an umbrella's
 *     CWEs would let that receipt class be relabelled as an unrelated class).
 *  2. D2 `unclassified` gate — an unclassified receipt class never persists as `confirmed`; it is
 *     held at `needs_review` with a structured note and keeps the `unclassified` attribution visible.
 *  3. E1 + E3 verified terminal — a confirmed finding persists `{ method, endpoint, terminalExchangeId }`
 *     from a cited host-recorded exchange; a proof without one is held at `needs_review`; harness
 *     route/endpoint extraction prefers the persisted terminal and the verifying spec only.
 *  4. A4 + E2 — `multi_step_chain` only for a confirmed composite with `hopCount >= 2`, and the
 *     attribution spec cites only receipt-cited exchanges (single-hop and composite).
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'

import type { Finding } from '../src/domain.ts'
import type { AgentScriptProofResult, V8CompositeProofBundle } from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { CompositeProofReceipt, HostSignedTranscript } from '../src/server/composite-receipt.ts'
import {
  agentProofAttribution,
  buildHostRecordedExchangeIndex,
  ExecVerifier,
  isCweConsistentWithReceiptClass,
  replayUnclassifiedConfirmationNote,
  resolveAgentProofPersistenceGate,
  resolveVerifiedProofTerminal,
  type ExecVerifyHost,
} from '../src/server/exec-verify.ts'
import {
  auditOracleTaxonomyClosure,
  citedProofExchangeIds,
  DEFAULT_ORACLE_SPEC_REGISTRY,
  evaluateProofPromotion,
  MULTI_CLASS_ORACLE_SPEC_IDS,
  resolveProofChainShape,
  type OracleSpec,
} from '../src/server/oracle-spec.ts'
import { findings, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { attributionFromTaxonomy, cweFamiliesConflict, lookupVulnTaxonomy } from '../src/vuln-taxonomy.ts'
import { buildFalsePositiveEvidence, persistedVerifiedTerminal, translateFindings } from '../scripts/benchmark-realistic.ts'
import { buildUnmatchedFindingsDetail } from '../scripts/benchmark-multihop.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

function makeStore(t: test.TestContext): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-taxonomy-plumbing-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* temp dir cleanup is best-effort */ }
  })
  return storage
}

const dummyBackend: WorkerBackend = {
  async run() {
    return { exitCode: 0, stdout: '', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
  },
  async verifyStaticAst() {
    return {
      verified: false, engine: 'ast-grep', repo: 'app', file: 'src/a.ts', startLine: 1, endLine: 1,
      matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1,
    }
  },
  async openSession() {
    throw new Error('openSession is not used by persistence tests')
  },
}

function makeVerifier(storage: Store): ExecVerifier {
  const host: ExecVerifyHost = {
    storage,
    broker: new RequestBroker({ rejectUnauthorized: false }),
    browser: null as unknown as ExecVerifyHost['browser'],
    canaryBroker: new CanaryBroker({ storage }),
    backend: dummyBackend,
    approvedOriginsSet: run => new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin)),
    permitted: (run, origin) => run.candidates.some(c => run.approved.includes(c.id) && c.origin === origin),
    check: job => storage.run(job.assignment.runId),
    buildGrant: (_job, run, permitted) => ({
      grant: makeLabGrant([...permitted][0] ?? run.candidates[0]!.origin),
      secrets: [],
      currentSecrets: () => [],
    }),
    projectReposMount: () => ({ reposDir: undefined, mountedRepos: [] }),
    isCanaryDnsConfigured: () => false,
    isCanaryListenerConfigured: () => false,
    markEndpointCoverage: () => undefined,
    markReplaySpecCoverage: () => undefined,
    waitForTier3Approval: async () => ({ approved: true }),
    postVerificationVerdict: () => null,
    cancelSiblingTrialsOnConfirmation: () => undefined,
    scheduleVariantSweepForFinding: () => undefined,
    completeWorker: () => undefined,
    recordSpecVerification: () => undefined,
    resolveInlineVerdictRow: (_runId, row) => row,
  }
  return new ExecVerifier(host)
}

function attempt(n: 1 | 2, digest: string) {
  return {
    attempt: n, nonce: `nonce-${digest}`, exitCode: 0, durationMs: 8, oraclePassed: true, failures: [],
    claimCount: 1, exchangeCount: 2, transcriptDigest: digest, signaturesValid: true, causal: [], title: null,
    nonceMismatch: false, rejectedBy: null, missingEvidence: [], transcriptSummary: [],
  }
}

type ScriptExchange = AgentScriptProofResult['exchanges'][number]

function exchange(id: string, origin: string, method: string, path: string, status: number, role: 'control' | 'probe'): ScriptExchange {
  return {
    exchangeId: id, op: 'http', method, pathAndQuery: path, origin, status, durationMs: 3,
    personaHandle: 'member_a', sessionRole: role, actorRoleLabel: 'member', body: '{}',
    requestHeaders: {}, responseHeaders: { 'content-type': 'application/json' },
  }
}

function proofShell(prefix: string, exchanges: ScriptExchange[]): Omit<AgentScriptProofResult, 'receipt' | 'compositeReceipt' | 'vulnClass' | 'hostTranscript'> {
  return {
    verdict: {
      confirmed: true, reason: 'confirmed', detail: 'Two fresh runs confirmed the proof.',
      attempts: [attempt(1, `a-${prefix}`), attempt(2, `b-${prefix}`)],
      disagreements: [], claimTitle: `proof ${prefix}`, rejectedBy: null, missingEvidence: [], transcriptSummary: [],
    },
    exchanges,
    transcriptDigests: [`a-${prefix}`, `b-${prefix}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    claimTitle: `proof ${prefix}`,
    severity: 'high',
    description: 'Behavioral fixture proof.',
  }
}

/**
 * Single-hop proof: the receipt cites a denied control + succeeding probe on `path`; an extra
 * uncited exchange on `/unrelated/inventory` is recorded by the script but never cited.
 */
function singleHopProof(opts: {
  origin: string
  path: string
  vulnClass: string
  prefix: string
  citeExchanges?: boolean
}): AgentScriptProofResult {
  const ctrl = `${opts.prefix}-ctrl`
  const probe = `${opts.prefix}-probe`
  const uncited = `${opts.prefix}-uncited`
  const exchanges = [
    exchange(uncited, opts.origin, 'GET', '/unrelated/inventory', 200, 'probe'),
    exchange(ctrl, opts.origin, 'GET', opts.path, 403, 'control'),
    exchange(probe, opts.origin, 'GET', opts.path, 200, 'probe'),
  ]
  return {
    ...proofShell(opts.prefix, exchanges),
    receipt: {
      receipt: {
        vulnClass: opts.vulnClass,
        target: { origin: opts.origin, method: 'GET', pathAndQuery: opts.path },
        exchangeIds: opts.citeExchanges === false ? [] : [ctrl, probe],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `${opts.vulnClass} delta`,
      },
      verification: {
        confirmed: true, vulnClass: opts.vulnClass, rule: 'impact', reason: `${opts.vulnClass} verified`,
        observed: '200', expected: '403',
      },
    },
    compositeReceipt: null,
    vulnClass: opts.vulnClass,
    hostTranscript: null,
  }
}

/**
 * Composite proof with `hopPaths.length` hops (terminal = last), a pre-chain control and a
 * post-chain readback, plus one uncited script exchange on `/unrelated/inventory`.
 */
function compositeProof(opts: {
  origin: string
  chainId: string
  hopPaths: readonly string[]
  terminalVulnClass?: string
}): AgentScriptProofResult {
  const terminalVulnClass = opts.terminalVulnClass ?? 'dual_tenant_abac'
  const hopIds = opts.hopPaths.map((_, i) => `${opts.chainId}-h${i + 1}`)
  const terminalPath = opts.hopPaths[opts.hopPaths.length - 1]!
  const ctrl = `${opts.chainId}-ctrl`
  const readback = `${opts.chainId}-rb`
  const uncited = `${opts.chainId}-uncited`
  const receipt: CompositeProofReceipt = {
    chainId: opts.chainId,
    terminalVulnClass,
    replayMode: 'fresh_clean_replay',
    hops: opts.hopPaths.map((path, i) => ({
      hopId: `h${i + 1}`,
      surface: 'http',
      target: { origin: opts.origin, method: 'GET', pathAndQuery: path },
      exchangeIds: [hopIds[i]!],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `hop ${i + 1}`,
      producedCapabilities: [],
      consumedCapabilities: [],
    })),
    causalEdges: [],
    terminalImpact: {
      terminalHopId: `h${opts.hopPaths.length}`,
      claimedImpact: 'Terminal impact verified.',
      summary: 'Terminal impact verified.',
      terminalExchangeId: hopIds[hopIds.length - 1]!,
      oracleFamily: terminalVulnClass as CompositeProofReceipt['terminalImpact']['oracleFamily'],
      preChainControlExchangeIds: [ctrl],
      postChainReadbackExchangeIds: [readback],
    },
  }
  const bundle: V8CompositeProofBundle = {
    receipt,
    verification: {
      confirmed: true, chainId: opts.chainId, terminalVulnClass, replayMode: 'fresh_clean_replay',
      modeBVerified: false, hopCount: opts.hopPaths.length, verifiedEdges: [], reason: 'Composite chain verified.',
      terminalOracleFamily: terminalVulnClass, terminalEndpoint: terminalPath,
    },
    hopActors: Object.fromEntries(opts.hopPaths.map((_, i) => [`h${i + 1}`, 'member_a'])),
  }
  const exchanges: ScriptExchange[] = [
    exchange(uncited, opts.origin, 'GET', '/unrelated/inventory', 200, 'probe'),
    exchange(ctrl, opts.origin, 'GET', terminalPath, 403, 'control'),
    ...opts.hopPaths.map((path, i) => exchange(hopIds[i]!, opts.origin, 'GET', path, 200, i === opts.hopPaths.length - 1 ? 'probe' : 'control')),
    exchange(readback, opts.origin, 'GET', terminalPath, 200, 'control'),
  ]
  const hostTranscript: HostSignedTranscript = {
    entries: exchanges.map((ex, idx) => ({
      exchangeId: ex.exchangeId,
      origin: ex.origin,
      seq: idx + 1,
      timestampMs: 1_700_000_000_000 + idx * 10,
      step: {
        id: ex.exchangeId,
        arm: ex.sessionRole === 'probe' ? 'probe' : 'control',
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        actor: { handle: 'member_a', role: 'member', tenant: 'tenant_a', auth: 'bearer', sameSite: null },
      },
    })),
  }
  return {
    ...proofShell(opts.chainId, exchanges),
    receipt: null,
    compositeReceipt: bundle,
    vulnClass: terminalVulnClass,
    hostTranscript,
  }
}

async function persistScenario(t: test.TestContext, origin: string, proof: AgentScriptProofResult) {
  const storage = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const worker = storage.makeWorker(run, 'investigation', run.candidates[0]!, 'Worker', 'taxonomy plumbing')
  const verifier = makeVerifier(storage)
  const upserted: Finding[] = []
  const original = storage.upsertChainFinding.bind(storage)
  storage.upsertChainFinding = ((...args: Parameters<Store['upsertChainFinding']>) => {
    upserted.push(structuredClone(args[2]))
    return original(...args)
  }) as Store['upsertChainFinding']
  const result = verifier.persistAgentScriptProof({ run, assignment: worker, script: '// proof', runtime: 'ts', proof, secrets: [] })
  const row = storage.db.select().from(findings).where(eq(findings.id, result.findingId)).get()
  assert.ok(row, 'persisted finding row must exist')
  const specRow = storage.db.select().from(replaySpecs).where(eq(replaySpecs.id, result.replaySpecId)).get()
  const persisted = row.finding as Finding & { evidence?: Record<string, unknown> }
  return { result, row, persisted, specRow, incoming: upserted[upserted.length - 1]!, verifier }
}

/**
 * A held finding is never confirmed in any persisted representation. The authoritative finding JSON
 * carries `needs_review`; the promoted SQL `status` column is synced by a store trigger that does not
 * yet enumerate `needs_review` (it records `pending`), so only "not confirmed" is pinned for it.
 */
function assertHeldAtNeedsReview(row: { status: string; verificationClass: string }, persisted: Finding): void {
  assert.equal(persisted.status, 'needs_review')
  assert.notEqual(row.status, 'confirmed')
  assert.equal(row.verificationClass, 'open_proof_gap')
  assert.equal(persisted.verificationTier, undefined)
}

function specFrom(base: OracleSpec, patch: Partial<OracleSpec>): OracleSpec {
  return { ...base, ...patch } as OracleSpec
}

// ---------------------------------------------------------------------------------------------
// 1. D1 taxonomy closure
// ---------------------------------------------------------------------------------------------

test('D1: every registered oracle label and canonical class resolves to a classified taxonomy entry', () => {
  const specs = DEFAULT_ORACLE_SPEC_REGISTRY.list()
  assert.ok(specs.length > 0)
  for (const spec of specs) {
    for (const label of [...spec.labels, spec.canonicalVulnClass]) {
      const entry = lookupVulnTaxonomy(label)
      assert.ok(entry, `oracle spec ${spec.id} label "${label}" must resolve in VULN_TAXONOMY`)
      assert.equal(attributionFromTaxonomy(label).unclassified, false, `label "${label}" must not attribute as unclassified`)
      assert.equal(agentProofAttribution(label).unclassified, false)
    }
  }
  // Every cross-tenant label registered on the authorization oracle is classified as BOLA.
  const authz = DEFAULT_ORACLE_SPEC_REGISTRY.get('impact:authorization')!
  for (const label of authz.labels.filter(l => l.startsWith('cross_tenant'))) {
    assert.equal(attributionFromTaxonomy(label).cwe, 'CWE-639', label)
  }
})

test('D1: spec.cwes ⊆ cweFamily for every class-pure spec; multi-class specs keep every CWE classified', () => {
  const specs = DEFAULT_ORACLE_SPEC_REGISTRY.list()
  const classified = new Set<string>()
  for (const spec of specs) for (const label of spec.labels) for (const c of lookupVulnTaxonomy(label)!.cweFamily) classified.add(c)
  for (const spec of specs) {
    if (MULTI_CLASS_ORACLE_SPEC_IDS.has(spec.id)) {
      for (const cwe of spec.cwes) assert.ok(classified.has(cwe), `multi-class spec ${spec.id} CWE ${cwe} must be classified`)
      continue
    }
    for (const label of spec.labels) {
      const family = lookupVulnTaxonomy(label)!.cweFamily
      for (const cwe of spec.cwes) {
        assert.ok(family.includes(cwe), `spec ${spec.id} label "${label}" family must include ${cwe}`)
      }
    }
  }
  assert.deepEqual(auditOracleTaxonomyClosure(specs), [])
})

test('D1: the multi-class exemption is minimal and ratcheted; the audit flags drift', () => {
  const specs = DEFAULT_ORACLE_SPEC_REGISTRY.list()
  // Every exempt spec genuinely spans classes (some label family omits one of its CWEs).
  for (const id of MULTI_CLASS_ORACLE_SPEC_IDS) {
    const spec = DEFAULT_ORACLE_SPEC_REGISTRY.get(id)
    assert.ok(spec, `exempt spec ${id} must be registered`)
    assert.ok(spec.labels.some(label => spec.cwes.some(c => !lookupVulnTaxonomy(label)!.cweFamily.includes(c))), `${id} must need the exemption`)
  }
  const kinds = (violations: ReturnType<typeof auditOracleTaxonomyClosure>) => violations.map(v => v.kind).sort()

  assert.deepEqual(kinds(auditOracleTaxonomyClosure(specs, new Set([...MULTI_CLASS_ORACLE_SPEC_IDS, 'impact:csrf']))), ['stale_multi_class_exemption'])
  assert.deepEqual(kinds(auditOracleTaxonomyClosure(specs, new Set([...MULTI_CLASS_ORACLE_SPEC_IDS, 'not:registered']))), ['stale_multi_class_exemption'])

  const csrf = DEFAULT_ORACLE_SPEC_REGISTRY.get('impact:csrf')!
  const drifted = [
    specFrom(csrf, { id: 'test:unclassified_label', labels: ['csrf', 'zz_unmapped_receipt_class'] }),
    specFrom(csrf, { id: 'test:cwe_outside_family', cwes: ['CWE-352', 'CWE-89'] }),
    specFrom(csrf, { id: 'test:unclassified_canonical', canonicalVulnClass: 'zz_unmapped_canonical' }),
  ]
  const violations = auditOracleTaxonomyClosure(drifted, new Set())
  assert.deepEqual(kinds(violations), ['cwe_outside_label_family', 'unclassified_canonical_class', 'unclassified_label'])
  assert.deepEqual(violations.find(v => v.kind === 'cwe_outside_label_family')?.cwes, ['CWE-89'])

  const umbrella = specFrom(csrf, { id: 'test:umbrella', labels: ['csrf', 'sqli'], cwes: ['CWE-352', 'CWE-89', 'CWE-99999'] })
  const umbrellaViolations = auditOracleTaxonomyClosure([umbrella], new Set(['test:umbrella']))
  assert.deepEqual(kinds(umbrellaViolations), ['cwe_unclassified'])
  assert.deepEqual(umbrellaViolations[0]!.cwes, ['CWE-99999'])
})

test('D1: closure never widens a specific class into its umbrella siblings (attribution + dedupe soundness)', () => {
  // A SQL-injection receipt must not accept path-traversal / OS-command CWEs from the umbrella oracle.
  assert.equal(isCweConsistentWithReceiptClass('CWE-22', 'sqli'), false)
  assert.equal(isCweConsistentWithReceiptClass('CWE-78', 'blind_sqli'), false)
  assert.equal(isCweConsistentWithReceiptClass('CWE-89', 'sqli'), true)
  // A cross-surface pivot may carry the access-control CWE its oracle confirms...
  assert.equal(isCweConsistentWithReceiptClass('CWE-639', 'cross_surface_pivot'), true)
  // ...while the SSRF and authorization dedupe families stay disjoint.
  assert.equal(cweFamiliesConflict('CWE-918', 'CWE-639'), true)
  assert.equal(cweFamiliesConflict('CWE-918', 'CWE-284'), true)
  // The bare broad token is not a confirmation label (R3-11 N2 keeps it unclassified).
  assert.equal(DEFAULT_ORACLE_SPEC_REGISTRY.resolveByExactLabel('webhook'), null)
  assert.equal(lookupVulnTaxonomy('webhook'), null)
  assert.equal(DEFAULT_ORACLE_SPEC_REGISTRY.resolveByExactLabel('webhook_forgery', { oobEventIds: [] })?.id, 'webhook')
})

// ---------------------------------------------------------------------------------------------
// 2. D2 unclassified confirmation gate
// ---------------------------------------------------------------------------------------------

const TERMINAL = { method: 'GET', endpoint: '/resource/1', terminalExchangeId: 'ex-1' }

test('D2: promotion gate holds unclassified attributions at needs_review with a structured note', () => {
  const held = evaluateProofPromotion({ receiptClass: 'zz_unmapped_receipt_class', verifiedTerminal: TERMINAL })
  assert.equal(held.status, 'needs_review')
  assert.deepEqual(held.blockers, ['unclassified_attribution'])
  assert.ok(held.status === 'needs_review' && held.note.includes('unclassified_attribution'))
  assert.ok(held.status === 'needs_review' && held.note.includes('runtime_confirmed'))

  // The gate's unclassified check agrees with the persisted attribution for the same class.
  assert.equal(agentProofAttribution('zz_unmapped_receipt_class').unclassified, true)
  assert.deepEqual(evaluateProofPromotion({ receiptClass: 'bola', verifiedTerminal: TERMINAL }), { status: 'confirmed', blockers: [] })
  assert.deepEqual(evaluateProofPromotion({ receiptClass: 'zz_unmapped_receipt_class', verifiedTerminal: null }).blockers, ['unclassified_attribution', 'missing_verified_terminal'])
  assert.deepEqual(evaluateProofPromotion({ receiptClass: 'bola', verifiedTerminal: null }).blockers, ['missing_verified_terminal'])
  // `undefined` = terminal not applicable (replay specs bind their endpoint separately).
  assert.deepEqual(evaluateProofPromotion({ receiptClass: 'bola' }), { status: 'confirmed', blockers: [] })

  // The shared persistence gate wires terminal + promotion + chain shape together.
  const origin = 'http://127.0.0.1:4709'
  const proof = singleHopProof({ origin, path: '/resource/50', vulnClass: 'zz_unmapped_receipt_class', prefix: 'gate' })
  const gate = resolveAgentProofPersistenceGate(null, proof.receipt!.receipt, 'zz_unmapped_receipt_class', buildHostRecordedExchangeIndex(proof))
  assert.equal(gate.promoted, false)
  assert.deepEqual(gate.verifiedTerminal, { method: 'GET', endpoint: '/resource/50', terminalExchangeId: 'gate-probe' })
  assert.deepEqual(gate.chainShape, { hopCount: 1, multiStepChain: false })
  assert.match(gate.note ?? '', /unclassified_attribution/)
})

test('D2: replay confirmation note fires only for a confirmed receipt with an unclassified class', () => {
  const receipt = (vulnClass: string, confirmed: boolean) => ({
    receipt: {
      receipt: {
        vulnClass, target: { origin: 'http://127.0.0.1:4701' }, exchangeIds: ['ex-1'], oobEventIds: [],
        browserTraceIds: [], claimedDelta: 'delta',
      },
      verification: { confirmed, vulnClass, rule: 'impact' as const, reason: 'r', observed: 'o', expected: 'e' },
    },
  }) as unknown as Parameters<typeof replayUnclassifiedConfirmationNote>[0]
  assert.match(replayUnclassifiedConfirmationNote(receipt('zz_unmapped_receipt_class', true)) ?? '', /unclassified_attribution/)
  assert.equal(replayUnclassifiedConfirmationNote(receipt('zz_unmapped_receipt_class', false)), null)
  assert.equal(replayUnclassifiedConfirmationNote(receipt('bola', true)), null)
  assert.equal(replayUnclassifiedConfirmationNote({ receipt: null } as unknown as Parameters<typeof replayUnclassifiedConfirmationNote>[0]), null)
})

test('D2: persisting an unclassified receipt yields a visible needs_review finding, never confirmed', async t => {
  const origin = 'http://127.0.0.1:4702'
  const { result, row, persisted, specRow } = await persistScenario(
    t, origin, singleHopProof({ origin, path: '/resource/41', vulnClass: 'zz_unmapped_receipt_class', prefix: 'uncl' }),
  )
  assert.equal(result.findingStatus, 'needs_review')
  assertHeldAtNeedsReview(row, persisted)
  // R3-11 visibility: the unclassified attribution is kept (no fabricated CWE).
  assert.equal(row.cwe, 'unclassified')
  assert.equal(persisted.category, 'unclassified')
  assert.match(persisted.runtimeProofGap ?? '', /unclassified_attribution/)
  assert.deepEqual((persisted.evidence?.confirmationGate as { blockers: string[] }).blockers, ['unclassified_attribution'])
  const diff = specRow?.lastVerificationDiff as { verdict?: string; verificationTier?: string } | null
  assert.equal(diff?.verdict, 'needs_review')
  assert.equal(diff?.verificationTier, undefined)
})

// ---------------------------------------------------------------------------------------------
// 3. E1 + E3 verified terminal + harness plumbing
// ---------------------------------------------------------------------------------------------

test('E1: verified terminal comes only from a cited host-recorded exchange', () => {
  const origin = 'http://127.0.0.1:4703'
  const single = singleHopProof({ origin, path: '/resource/7', vulnClass: 'bola', prefix: 'term' })
  const index = buildHostRecordedExchangeIndex(single)
  assert.deepEqual(
    resolveVerifiedProofTerminal({ compositeReceipt: null, receipt: single.receipt!.receipt, exchangeById: index }),
    { method: 'GET', endpoint: '/resource/7', terminalExchangeId: 'term-probe' },
  )
  // Uncited script traffic (even a succeeding probe) is never a terminal.
  assert.equal(resolveVerifiedProofTerminal({ compositeReceipt: null, receipt: { exchangeIds: [] }, exchangeById: index }), null)
  assert.equal(resolveVerifiedProofTerminal({ compositeReceipt: null, receipt: { exchangeIds: ['not-recorded'] }, exchangeById: index }), null)

  const composite = compositeProof({ origin, chainId: 'term-chain', hopPaths: ['/setup/1', '/resource/9'] })
  assert.deepEqual(
    resolveVerifiedProofTerminal({ compositeReceipt: composite.compositeReceipt!.receipt, receipt: null, exchangeById: buildHostRecordedExchangeIndex(composite) }),
    { method: 'GET', endpoint: '/resource/9', terminalExchangeId: 'term-chain-h2' },
  )
})

test('E1: a confirmed single-hop finding round-trips its verified terminal through SQLite', async t => {
  const origin = 'http://127.0.0.1:4704'
  const { result, row, persisted } = await persistScenario(t, origin, singleHopProof({ origin, path: '/resource/42', vulnClass: 'bola', prefix: 'conf' }))
  assert.equal(result.findingStatus, 'confirmed')
  assert.equal(row.status, 'confirmed')
  assert.equal(row.verificationClass, 'runtime_confirmed')
  assert.equal(row.cwe, 'CWE-639')
  assert.deepEqual(persisted.evidence?.verifiedTerminal, { method: 'GET', endpoint: '/resource/42', terminalExchangeId: 'conf-probe' })
  assert.equal(persisted.evidence?.confirmationGate, undefined)
  assert.equal(persisted.runtimeProofGap ?? null, null)
  assert.deepEqual(persistedVerifiedTerminal(persisted), { method: 'GET', path: '/resource/42' })
})

test('E1: a receipt with no cited host-recorded terminal is held at needs_review', async t => {
  const origin = 'http://127.0.0.1:4705'
  const { result, row, persisted } = await persistScenario(
    t, origin, singleHopProof({ origin, path: '/resource/43', vulnClass: 'bola', prefix: 'noterm', citeExchanges: false }),
  )
  assert.equal(result.findingStatus, 'needs_review')
  assertHeldAtNeedsReview(row, persisted)
  assert.equal(persisted.evidence?.verifiedTerminal, undefined)
  assert.match(persisted.runtimeProofGap ?? '', /missing_verified_terminal/)
  assert.deepEqual((persisted.evidence?.confirmationGate as { blockers: string[] }).blockers, ['missing_verified_terminal'])
})

test('E3: harness route/endpoints prefer the persisted terminal and the verifying spec only', () => {
  const finding = {
    id: 'f-route', origin: 'http://127.0.0.1:4706', title: 'Cross-tenant read', status: 'confirmed', severity: 'high',
    reason: 'verified', remediation: 'fix', evidenceIds: [], scopeRevision: 1, cwe: 'CWE-639', category: 'broken-access-control',
    exchangeIds: ['ex-a'],
    evidence: { verifiedTerminal: { method: 'POST', endpoint: '/tenants/acct_2/exports', terminalExchangeId: 'ex-t' } },
  } as unknown as Finding
  const step = (id: string, role: 'control' | 'probe', path: string) => ({ id, role, request: { method: 'GET', pathAndQuery: path } })
  const replaySpecs = [
    { id: 's-verify', findingId: 'f-route', createdAt: 3, lastVerificationDiff: { verdict: 'confirmed' }, spec: { kind: 'http_chain', steps: [step('c', 'control', '/tenants/acct_1/exports'), step('p', 'probe', '/tenants/acct_2/exports')] } },
    { id: 's-other-1', findingId: 'f-route', createdAt: 2, spec: { kind: 'http_chain', steps: [step('c', 'control', '/unrelated/a'), step('p', 'probe', '/unrelated/b')] } },
    { id: 's-other-2', findingId: 'f-route', createdAt: 1, spec: { kind: 'http_chain', steps: [step('c', 'control', '/unrelated/c'), step('p', 'probe', '/unrelated/d')] } },
  ]
  const [submitted] = translateFindings({
    findings: [finding], replaySpecs, exchanges: [{ id: 'ex-a', method: 'GET', pathAndQuery: '/unrelated/exchange' }],
  })
  assert.ok(submitted)
  assert.deepEqual(submitted.endpoints[0], { method: 'POST', path: '/tenants/acct_2/exports' })
  const paths = submitted.endpoints.map(ep => ep.path)
  assert.ok(paths.includes('/tenants/acct_1/exports'), 'verifying-spec steps are kept')
  assert.equal(paths.some(p => p.startsWith('/unrelated/')), false, `no endpoints from unrelated specs or traffic: ${paths.join(',')}`)

  const [fp] = buildFalsePositiveEvidence({ findingIds: ['f-route'], findings: [finding], replaySpecs })
  assert.equal(fp?.route.method, 'POST')
  assert.equal(fp?.route.pathTemplate.startsWith('/tenants/'), true)

  const [unmatched] = buildUnmatchedFindingsDetail({ findings: [finding], submitted: [], chains: [] })
  assert.equal(unmatched?.route, 'POST /tenants/acct_2/exports')

  // Without a persisted terminal the verifying spec alone drives endpoints (still no union).
  const legacy = { ...finding, evidence: undefined } as unknown as Finding
  const [legacySubmitted] = translateFindings({ findings: [legacy], replaySpecs })
  assert.deepEqual(legacySubmitted?.endpoints.map(ep => ep.path), ['/tenants/acct_1/exports', '/tenants/acct_2/exports'])
})

// ---------------------------------------------------------------------------------------------
// 4. A4 hop-count gate + E2 cited-only attribution spec
// ---------------------------------------------------------------------------------------------

test('A4: chain shape is multi_step_chain only for a confirmed composite with >= 2 hops', () => {
  const bundle = (hops: number, confirmed: boolean) => ({ receipt: { hops: Array.from({ length: hops }, () => ({})) }, verification: { confirmed } })
  assert.deepEqual(resolveProofChainShape(null), { hopCount: 1, multiStepChain: false })
  assert.deepEqual(resolveProofChainShape(bundle(1, true)), { hopCount: 1, multiStepChain: false })
  assert.deepEqual(resolveProofChainShape(bundle(3, false)), { hopCount: 1, multiStepChain: false })
  assert.deepEqual(resolveProofChainShape(bundle(2, true)), { findingKind: 'multi_step_chain', hopCount: 2, multiStepChain: true })
  assert.deepEqual(resolveProofChainShape(bundle(4, true)), { findingKind: 'multi_step_chain', hopCount: 4, multiStepChain: true })
})

test('A4: persistence stamps multi_step_chain + hopCount only for a confirmed >= 2-hop composite', async t => {
  const origin = 'http://127.0.0.1:4707'
  const single = await persistScenario(t, origin, singleHopProof({ origin, path: '/resource/44', vulnClass: 'bola', prefix: 'a4s' }))
  assert.equal(single.incoming.findingKind, undefined, 'single-hop proofs are not multi-step chains')
  assert.equal(single.persisted.evidence?.hopCount, 1)
  assert.equal(single.persisted.evidence?.multiStepChain, false)

  const oneHop = await persistScenario(t, origin, compositeProof({ origin, chainId: 'a4-one', hopPaths: ['/resource/45'] }))
  assert.equal(oneHop.incoming.findingKind, undefined, '1-hop composites are not multi-step chains')
  assert.equal(oneHop.persisted.evidence?.hopCount, 1)
  assert.equal(oneHop.persisted.evidence?.multiStepChain, false)

  const twoHop = await persistScenario(t, origin, compositeProof({ origin, chainId: 'a4-two', hopPaths: ['/setup/46', '/resource/46'] }))
  assert.equal(twoHop.result.findingStatus, 'confirmed')
  assert.equal(twoHop.incoming.findingKind, 'multi_step_chain')
  assert.equal(twoHop.persisted.evidence?.hopCount, 2)
  assert.equal(twoHop.persisted.evidence?.multiStepChain, true)
  assert.deepEqual(twoHop.persisted.evidence?.verifiedTerminal, { method: 'GET', endpoint: '/resource/46', terminalExchangeId: 'a4-two-h2' })
})

test('E2: attribution spec cites only receipt-cited exchanges (single-hop and composite)', async t => {
  const origin = 'http://127.0.0.1:4708'
  const storage = makeStore(t)
  const verifier = makeVerifier(storage)
  const specPaths = (spec: unknown) => ((spec as { steps: Array<{ request: { pathAndQuery: string } }> }).steps).map(s => s.request.pathAndQuery)
  const baseInput = {
    origin, title: 't', severity: 'high' as const,
    envelope: { kind: 'agent_script', runtime: 'ts', script: '//', scriptSha256: 'x', verdict: 'confirmed', exchangeIds: [], transcriptDigests: [] } as never,
  }

  const single = singleHopProof({ origin, path: '/resource/47', vulnClass: 'bola', prefix: 'e2s' })
  const singleSpec = verifier.agentProofAttributionSpec({ ...baseInput, attribution: agentProofAttribution('bola'), proof: single, receipt: single.receipt!.receipt })
  assert.deepEqual(specPaths(singleSpec), ['/resource/47', '/resource/47'])

  // Composite receipts carry no single-hop `receipt.exchangeIds`; their hop/terminal citations define the set.
  const composite = compositeProof({ origin, chainId: 'e2c', hopPaths: ['/setup/48', '/resource/48'] })
  const cited = citedProofExchangeIds({ compositeReceipt: composite.compositeReceipt!.receipt, receipt: null })
  assert.deepEqual(cited.sort(), ['e2c-ctrl', 'e2c-h1', 'e2c-h2', 'e2c-rb'])
  const compositeSpec = verifier.agentProofAttributionSpec({
    ...baseInput, attribution: agentProofAttribution('dual_tenant_abac'), proof: composite, receipt: null,
    compositeReceipt: composite.compositeReceipt!.receipt,
  })
  assert.equal(specPaths(compositeSpec).includes('/unrelated/inventory'), false)
  assert.deepEqual([...new Set(specPaths(compositeSpec))].sort(), ['/resource/48', '/setup/48'])

  // A long chain keeps the verified terminal inside the step cap as the final probe.
  const long = compositeProof({ origin, chainId: 'e2l', hopPaths: Array.from({ length: 8 }, (_, i) => `/step/${i + 1}`) })
  const longSpec = verifier.agentProofAttributionSpec({
    ...baseInput, attribution: agentProofAttribution('dual_tenant_abac'), proof: long, receipt: null,
    compositeReceipt: long.compositeReceipt!.receipt,
  }) as unknown as { steps: Array<{ role: string; request: { pathAndQuery: string } }> }
  assert.equal(longSpec.steps.length, 8)
  assert.equal(longSpec.steps[longSpec.steps.length - 1]!.request.pathAndQuery, '/step/8')
  assert.equal(longSpec.steps[longSpec.steps.length - 1]!.role, 'probe')
  assert.equal(longSpec.steps.some(s => s.request.pathAndQuery === '/unrelated/inventory'), false)

  // End-to-end: the persisted composite finding's attribution row never carries uncited traffic.
  const persisted = await persistScenario(t, origin, compositeProof({ origin, chainId: 'e2p', hopPaths: ['/setup/49', '/resource/49'] }))
  assert.equal(specPaths(persisted.specRow?.spec).includes('/unrelated/inventory'), false)
})
