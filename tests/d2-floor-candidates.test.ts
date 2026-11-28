/**
 * Track D Cut 2 (`d2-delete-jq-vm`): candidate enumeration for the deterministic floor.
 *
 * The legacy `deterministic-specs.ts` synthesizer and the in-verifier jq assertion VM are deleted.
 * `planFloorCandidates` must emit only:
 *   - wired typed floor recipes (Track A2 Tier-1 primitive + ProofReceipt owns the verdict), or
 *   - zero-jq typed runner specs (`rce_proof`, `auth_protocol_proof`).
 *
 * Everything else fails closed with no candidate, so no probe can silently fall back to jq.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { declarativeReplaySpecSchema, floorRecipeEnvelopeSchema, summarizeVerifiedReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { EnginePersona } from '../src/server/deterministic-engine.ts'
import {
  RECEIPT_EXEMPT_HOST_SPEC_KINDS,
  RETIRED_LEGACY_SPEC_REASON,
  planFloorCandidates,
} from '../src/server/floor-recipe-engine.ts'
import type { EngineHypothesis } from '../src/server/floor-heuristics.ts'
import { retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import type { DifferentialProbeClass } from '../src/server/surface-engine.ts'
import type { DifferentialResult } from '../src/server/probes/context.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:41990'

const personas: EnginePersona[] = [
  { handle: 'owner', roleLabel: 'Owner (org-a)', privilege: 'owner', tenant: 'org-a' },
  { handle: 'other', roleLabel: 'Member (org-b)', privilege: 'member', tenant: 'org-b' },
]

function hypothesis(overrides: Partial<EngineHypothesis> & { probeClass: DifferentialProbeClass }): EngineHypothesis {
  return {
    key: `d2|${overrides.probeClass}`,
    endpoint: { id: 'ep-1', origin: ORIGIN, method: 'GET', pathTemplate: '/api/items/:id', params: [] },
    intent: 'authz',
    method: 'GET',
    pathAndQuery: '/api/items/item_1',
    ownerPersona: 'owner',
    otherPersona: 'other',
    risk: 50,
    ...overrides,
  } as EngineHypothesis
}

function probe(overrides: Partial<DifferentialResult> & { probeClass: DifferentialProbeClass }): DifferentialResult {
  return {
    origin: ORIGIN,
    pathAndQuery: '/api/items/item_1',
    verdict: 'signal',
    summary: 'signal',
    anomalies: [],
    details: {},
    requestsSent: 2,
    exchangeIds: ['ex-1'],
    stoppedReason: null,
    notes: [],
    durationMs: 1,
    ...overrides,
  }
}

describe('Track D Cut 2: planFloorCandidates emits typed recipes / zero-jq runners only', () => {
  test('an authz signal plans the wired access_boundary recipe (no legacy spec synthesis)', () => {
    const candidates = planFloorCandidates({
      hypothesis: hypothesis({ probeClass: 'authz_matrix', intent: 'authz', pathAndQuery: '/api/items/{{id}}', resourceIds: ['item_1'] }),
      probe: probe({
        probeClass: 'authz_matrix',
        anomalies: [{ type: 'unauthorized_access', resourceId: 'item_1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 1 }],
      }),
      personas,
    })
    assert.equal(candidates.length, 1)
    const [candidate] = candidates
    assert.equal(candidate!.mode, 'recipe')
    if (candidate!.mode !== 'recipe') return
    assert.equal(candidate.plan.recipeId, 'access_boundary')
    assert.equal(candidate.plan.vulnClass, 'bola')
    assert.equal(candidate.plan.skipReason, undefined)
  })

  test('an evaluated SSTI signal builds a schema-valid zero-jq rce_proof candidate', () => {
    const candidates = planFloorCandidates({
      hypothesis: hypothesis({
        probeClass: 'ssti_math',
        intent: 'ssti',
        pathAndQuery: '/search?q=1',
        param: { name: 'q', location: 'query' },
        location: 'query',
      }),
      probe: probe({ probeClass: 'ssti_math', anomalies: [{ type: 'expression_evaluated', engine: 'jinja2/twig' }] }),
      personas,
    })
    assert.equal(candidates.length, 1)
    const [candidate] = candidates
    assert.equal(candidate!.mode, 'spec')
    if (candidate!.mode !== 'spec') return
    assert.equal(candidate.specRecord.kind, 'rce_proof')
    assert.equal(candidate.specRecord.vulnClass, 'ssti')
    assert.equal(candidate.specRecord.spec.assertionsJq, undefined, 'typed runners must not carry jq')
    const parsed = declarativeReplaySpecSchema.safeParse(candidate.specRecord.spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
  })

  test('a forged JWT signal builds a schema-valid zero-jq auth_protocol_proof candidate', () => {
    const candidates = planFloorCandidates({
      hypothesis: hypothesis({
        probeClass: 'auth_protocol_audit',
        intent: 'auth_protocol',
        pathAndQuery: '/api/me',
      }),
      probe: probe({
        probeClass: 'auth_protocol_audit',
        anomalies: [{
          type: 'jwt_authorization_forgery',
          payload: { sub: 'user_1', role: 'admin', tenant: 'org-a' },
          declaredAlg: 'HS256',
          transport: 'header',
        }],
      }),
      personas,
    })
    assert.equal(candidates.length, 1)
    const [candidate] = candidates
    assert.equal(candidate!.mode, 'spec')
    if (candidate!.mode !== 'spec') return
    assert.equal(candidate.specRecord.kind, 'auth_protocol_proof')
    assert.equal(candidate.specRecord.spec.assertionsJq, undefined)
    const parsed = declarativeReplaySpecSchema.safeParse(candidate.specRecord.spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
  })

  test('a class with no wired recipe and no zero-jq runner fails closed with no candidate', () => {
    const candidates = planFloorCandidates({
      hypothesis: hypothesis({
        probeClass: 'path_traversal_benign',
        intent: 'traversal',
        pathAndQuery: '/files?name=index',
        param: { name: 'name', location: 'query' },
        location: 'query',
      }),
      probe: probe({ probeClass: 'path_traversal_benign', anomalies: [{ type: 'traversal_signal' }] }),
      personas,
    })
    assert.deepEqual(candidates, [])
  })

  test('a no-signal probe emits no candidates (never a speculative spec)', () => {
    const candidates = planFloorCandidates({
      hypothesis: hypothesis({ probeClass: 'authz_matrix', pathAndQuery: '/api/items/{{id}}', resourceIds: ['item_1'] }),
      probe: probe({ probeClass: 'authz_matrix', verdict: 'no_signal' }),
      personas,
    })
    assert.deepEqual(candidates, [])
  })

  test('auth_protocol_proof mutation candidate rejects unknown mutation and binds matching principal on control', () => {
    const unknown = planFloorCandidates({
      hypothesis: hypothesis({ probeClass: 'auth_protocol_audit', intent: 'auth_protocol', pathAndQuery: '/api/me' }),
      probe: probe({
        probeClass: 'auth_protocol_audit',
        anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'unrecognized_mutation' }],
      }),
      personas,
    })
    assert.deepEqual(unknown, [])

    const valid = planFloorCandidates({
      hypothesis: hypothesis({ probeClass: 'auth_protocol_audit', intent: 'auth_protocol', pathAndQuery: '/api/me' }),
      probe: probe({
        probeClass: 'auth_protocol_audit',
        anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'alg_none' }],
      }),
      personas,
    })
    assert.equal(valid.length, 1)
    const [candidate] = valid
    assert.equal(candidate!.mode, 'spec')
    if (candidate!.mode !== 'spec') return
    const parsed = declarativeReplaySpecSchema.safeParse(candidate.specRecord.spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
    if (!parsed.success || parsed.data.kind !== 'auth_protocol_proof') return
    const [ctrl, prb] = parsed.data.steps
    assert.equal(ctrl!.request.persona, 'owner')
    assert.equal(prb!.request.persona, 'owner')
    assert.equal(ctrl!.request.authMutation?.kind, 'expired_replay')
    assert.equal(prb!.request.authMutation?.kind, 'alg_none')
  })

  test('command_injection candidate rejects unknown variant and only restores {{nonce_*}} placeholders', () => {
    const unknownVariant = planFloorCandidates({
      hypothesis: hypothesis({
        probeClass: 'command_injection',
        intent: 'command_injection',
        pathAndQuery: '/ping?host=127.0.0.1&tag=%7B%7Buser_var%7D%7D',
        param: { name: 'host', location: 'query' },
        location: 'query',
      }),
      probe: probe({
        probeClass: 'command_injection',
        anomalies: [{ type: 'command_executed', variant: 'nonexistent_variant' }],
      }),
      personas,
    })
    assert.deepEqual(unknownVariant, [])

    const valid = planFloorCandidates({
      hypothesis: hypothesis({
        probeClass: 'command_injection',
        intent: 'command_injection',
        pathAndQuery: '/ping?host=127.0.0.1&tag=%7B%7Buser_var%7D%7D',
        param: { name: 'host', location: 'query' },
        location: 'query',
      }),
      probe: probe({
        probeClass: 'command_injection',
        anomalies: [{ type: 'command_executed', variant: 'quote_break_id' }],
      }),
      personas,
    })
    assert.equal(valid.length, 1)
    const [candidate] = valid
    assert.equal(candidate!.mode, 'spec')
    if (candidate!.mode !== 'spec') return
    const parsed = declarativeReplaySpecSchema.safeParse(candidate.specRecord.spec)
    assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
    if (!parsed.success || parsed.data.kind !== 'rce_proof') return
    const pq = parsed.data.probeStep.request.pathAndQuery
    assert.ok(pq.includes('{{nonce_part1}}'), 'verifier-minted nonce placeholder must be restored')
    assert.ok(pq.includes('{{nonce_part2}}'), 'verifier-minted nonce placeholder must be restored')
    assert.ok(!pq.includes('{{user_var}}'), 'non-nonce target placeholders must remain URL-escaped')
  })
})

describe('R3-05 independent review regressions: fail-closed retired retest and VerifiedReplaySpec currency', () => {
  const baseFields = {
    version: 1 as const,
    origin: ORIGIN,
    title: 'Retired legacy spec fixture',
    category: 'security-check',
    cwe: 'CWE-89',
    severity: 'high' as const,
    severityRationale: 'Regression test fixture.',
    impact: 'Verifies fail-closed retirement.',
    remediation: 'Use typed recipes.',
    recheckInstructions: 'Retest via typed recipe.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "ok", expected: "ok" }',
  }

  test('retired http_chain, ws_chain, and upload_probe specs fail closed on verify and NEVER return fixed on retest', async () => {
    assert.equal(RECEIPT_EXEMPT_HOST_SPEC_KINDS.has('ws_chain'), false)
    assert.equal(RECEIPT_EXEMPT_HOST_SPEC_KINDS.has('upload_probe'), false)
    const broker = new RequestBroker({ transport: async () => ({ status: 200, headers: {}, body: 'ok' }) })
    const backend = new LocalJqBackend()
    const grant = makeLabGrant(ORIGIN, { tier: 3, isStateChangeApproved: () => true })
    const signal = AbortSignal.timeout(5_000)

    const retiredSpecs = [
      {
        ...baseFields,
        kind: 'http_chain' as const,
        steps: [
          { id: 'c1', role: 'control' as const, description: 'ctl', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/ok' } },
          { id: 'p1', role: 'probe' as const, description: 'prb', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/prb' } },
        ],
      },
      {
        ...baseFields,
        kind: 'ws_chain' as const,
        steps: [
          { id: 'c1', role: 'control' as const, description: 'open control', origin: ORIGIN, pathAndQuery: '/ws', sendMessages: ['ping'] },
          { id: 'p1', role: 'probe' as const, description: 'open probe', origin: ORIGIN, pathAndQuery: '/ws', sendMessages: ['probe'] },
        ],
      },
      {
        ...baseFields,
        kind: 'upload_probe' as const,
        requiresTier3Approval: true as const,
        uploadStep: {
          id: 'u1',
          role: 'probe' as const,
          description: 'upload',
          origin: ORIGIN,
          method: 'POST' as const,
          pathAndQuery: '/upload',
          fieldName: 'file',
          filename: 'a.txt',
          contentType: 'text/plain',
          contentTemplate: 'benign {{upload_nonce}}',
        },
        fetchStep: { id: 'f1', role: 'probe' as const, description: 'fetch', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/uploads/a.txt' } },
      },
    ]

    for (const spec of retiredSpecs) {
      const verify = await verifyReplaySpec({ spec, broker, backend, grant, signal, envelopeTrust: 'host_persisted' })
      assert.equal(verify.verdict, 'dismissed')
      assert.equal(verify.outcome.confirmed, false)
      assert.equal(verify.outcome.reason, RETIRED_LEGACY_SPEC_REASON)

      const retest = await retestReplaySpec({ spec, broker, backend, grant, signal, envelopeTrust: 'host_persisted' })
      assert.equal(retest.verdict, 'inconclusive', `${spec.kind} must never return fixed on retest`)
      assert.equal(retest.replay.outcome.confirmed, false)
      assert.equal(retest.replay.outcome.reason, RETIRED_LEGACY_SPEC_REASON)
      const health = retest.replay.evidencePayload.retestHealth as { failureReason?: string; code?: string } | undefined
      assert.equal(health?.failureReason, 'receipt_unbuildable')
      assert.equal(health?.code, 'receipt_unbuildable')
    }
  })

  test('retestReplaySpec persisted-recipe path rejects out-of-scope sibling step origins and destructive content', async () => {
    const broker = new RequestBroker({ transport: async () => ({ status: 200, headers: {}, body: 'ok' }) })
    const backend = new LocalJqBackend()
    const grant = makeLabGrant(ORIGIN, { tier: 3, isStateChangeApproved: () => true })
    const signal = AbortSignal.timeout(5_000)
    const recipe = floorRecipeEnvelopeSchema.parse({
      recipeId: 'redirect',
      args: {
        origin: ORIGIN,
        method: 'GET',
        pathAndQuery: '/login?next=/home',
        controlPathAndQuery: '/login?next=/home',
        probePathAndQuery: '/login?next=https://example.invalid/x',
        vulnClass: 'open_redirect',
        actor: { handle: 'anonymous', role: 'anonymous' },
      },
    })

    const outOfScopeStepSpec = {
      ...baseFields,
      kind: 'http_chain' as const,
      recipe,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'ctl', request: { origin: 'http://127.0.0.1:49999', method: 'GET' as const, pathAndQuery: '/leak' } },
        { id: 'p1', role: 'probe' as const, description: 'prb', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/login' } },
      ],
    }
    const scopeRes = await retestReplaySpec({ spec: outOfScopeStepSpec, broker, backend, grant, signal, envelopeTrust: 'host_persisted' })
    assert.equal(scopeRes.verdict, 'inconclusive')
    assert.match(scopeRes.replay.outcome.reason ?? '', /not in approved scope/i)

    const destructiveSpec = {
      ...baseFields,
      kind: 'http_chain' as const,
      title: 'DROP TABLE users',
      recipe,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'ctl', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/login' } },
        { id: 'p1', role: 'probe' as const, description: 'prb', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/login' } },
      ],
    }
    const destRes = await retestReplaySpec({ spec: destructiveSpec, broker, backend, grant, signal, envelopeTrust: 'host_persisted' })
    assert.equal(destRes.verdict, 'inconclusive')
    assert.match(destRes.replay.outcome.reason ?? '', /destructive-payload denylist/i)
  })

  test('summarizeVerifiedReplaySpec fails closed for unparsed specs, disallowed recipe pairings, and meta-only agent_script rows', () => {
    const validRecipe = floorRecipeEnvelopeSchema.parse({
      recipeId: 'redirect',
      args: { origin: ORIGIN, method: 'GET', pathAndQuery: '/login' },
    })

    // Disallowed kind/recipe pairing (ws_chain + redirect) stays legacy
    const disallowed = summarizeVerifiedReplaySpec({
      ...baseFields,
      kind: 'ws_chain',
      steps: [
        { id: 'c1', role: 'control', description: 'open control', origin: ORIGIN, pathAndQuery: '/ws' },
        { id: 'p1', role: 'probe', description: 'open probe', origin: ORIGIN, pathAndQuery: '/ws' },
      ],
      recipe: validRecipe,
    })
    assert.equal(disallowed.currency, 'legacy')
    assert.equal(disallowed.verificationTier, 'unverified')

    // Meta-only proofKind='agent_script' without valid envelope stays legacy
    const metaOnly = summarizeVerifiedReplaySpec({ origin: ORIGIN, agentScript: { invalid: true } }, { proofKind: 'agent_script' })
    assert.equal(metaOnly.currency, 'legacy')
    assert.equal(metaOnly.verificationTier, 'unverified')

    // Unparsed typed_runner kind stays legacy
    const malformedRunner = summarizeVerifiedReplaySpec({ kind: 'rce_proof', origin: ORIGIN })
    assert.equal(malformedRunner.currency, 'legacy')
    assert.equal(malformedRunner.verificationTier, 'unverified')

    // Schema-valid static_ast_proof is tagged static verificationTier
    const staticSpec = summarizeVerifiedReplaySpec({
      ...baseFields,
      kind: 'static_ast_proof',
      repo: 'acme/app',
      file: 'src/app.ts',
      startLine: 10,
      endLine: 12,
      engine: 'opengrep',
      ruleOrPattern: 'render($X)',
      runtimeProofGap: 'Static sink verified without live execution.',
    })
    assert.equal(staticSpec.currency, 'typed_runner')
    assert.equal(staticSpec.verificationTier, 'static')
  })
})
