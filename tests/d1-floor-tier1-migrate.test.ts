/**
 * Track D Cut 1 (`d1-floor-tier1-migrate`) — Behavioral tests for migrating Kovo's $0 active
 * deterministic fast-lane onto Track A2's 5 universal Tier-1 verification primitives with zero
 * runtime `jq` VM invocations.
 */
import assert from 'node:assert/strict'
import test, { describe } from 'node:test'
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { runDeterministicEngine } from '../src/server/deterministic-engine.ts'
import { ExecFloorLane } from '../src/server/exec-floor-lane.ts'
import {
  TYPED_RECIPE_ASSERTION,
  authProtocolTier1Decision,
  executeFloorRecipeById,
  oobCanarySeam,
  planFloorRecipe,
  recipeSpecRecord,
  runAuthProtocolProofRecipe,
  runCacheDifferentialRecipe,
  runPlannedRecipe,
  runRceProofRecipe,
  tier1HostSigner,
  tier1PrimitiveForRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { LEGACY_UNWIRED_SPECKINDS, brokerFloorRecipeDeps, wiredRecipeForSpecKind } from '../src/server/floor-recipes.ts'
import { assessBoundary } from '../src/server/oracle-invariants.ts'
import { evaluateUniversalPrimitive } from '../src/server/v8-oracle-families.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'http://127.0.0.1:41990'

const noJqBackend = {
  async run() {
    throw new Error('Track D Cut 1: jq VM must never be invoked on the $0 floor path')
  },
} as unknown as WorkerBackend

function baseSpec<T extends Record<string, unknown>>(extra: T) {
  return {
    version: 1 as const,
    origin: ORIGIN,
    title: 'Track D Cut 1 behavioral verification',
    category: 'broken-access-control' as const,
    cwe: 'CWE-347',
    severity: 'high' as const,
    severityRationale: 'Behavioral verification fixture.',
    impact: 'Boundary or execution invariant violation.',
    remediation: 'Enforce strict server-side validation.',
    recheckInstructions: 'Replay the differential verification.',
    assertionsJq: TYPED_RECIPE_ASSERTION,
    ...extra,
  }
}

function makeJwt(header: Record<string, unknown>, payload: Record<string, unknown>, sig = 'sig_valid_token_abc'): string {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url')
  return `${b64(header)}.${b64(payload)}.${sig}`
}

describe('Track D Cut 1: graduated floor recipes via Track A2 Tier-1 primitives', () => {
  test('LEGACY_UNWIRED_SPECKINDS is empty and graduated classes map to Tier-1 primitives', () => {
    assert.equal(LEGACY_UNWIRED_SPECKINDS.length, 0)
    assert.equal(wiredRecipeForSpecKind('http_chain', 'mass_assignment'), 'persisted_mutation')
    assert.equal(wiredRecipeForSpecKind('http_chain', 'csrf'), 'persisted_mutation')
    assert.equal(wiredRecipeForSpecKind('http_chain', 'info_disclosure'), 'disclosure')
    assert.equal(wiredRecipeForSpecKind('http_chain', 'ssrf'), 'oob_callback')
    assert.equal(wiredRecipeForSpecKind('http_chain', 'xxe'), 'oob_callback')
    assert.equal(tier1PrimitiveForRecipe('persisted_mutation', 'mass_assignment'), 'state_delta_and_conservation')
    assert.equal(tier1PrimitiveForRecipe('disclosure', 'info_disclosure'), 'access_differential')
    assert.equal(tier1PrimitiveForRecipe('oob_callback', 'ssrf'), 'oob_and_execution_witness')
  })

  test('persisted_mutation (state_delta_and_conservation): confirms genuine persisted mutation and rejects zero-delta or unpersisted probe values', async () => {
    const makeBroker = (mode: 'tp' | 'fp_noop' | 'fp_control_only') => {
      let role = 'member'
      return new RequestBroker({
        transport: async (url, _addr, _sig, opts) => {
          if (url.pathname === '/api/profile' && opts?.method === 'PATCH') {
            const parsed = JSON.parse(String(opts.body ?? '{}')) as { role?: string }
            if (mode === 'tp' && parsed.role) role = parsed.role
            if (mode === 'fp_control_only' && parsed.role === 'member') role = 'baseline_only'
            return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ok: true, role }) }
          }
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'u1', role }) }
        },
      })
    }

    const actor = { handle: 'alice', role: 'member' as const, tenant: 'org-a', auth: 'bearer' as const }
    const personas = new Map([['alice', { handle: 'alice', roleLabel: 'Member (org-a)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-alice', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-alice' } }]])
    const grant = makeLabGrant(ORIGIN, { tier: 3, personas: personas as never, isStateChangeApproved: () => true })
    const args = {
      origin: ORIGIN,
      method: 'PATCH',
      pathAndQuery: '/api/profile',
      vulnClass: 'mass_assignment',
      actor,
      body: { role: 'admin' },
      baselineMethod: 'GET',
      baselinePathAndQuery: '/api/profile',
      readbackMethod: 'GET',
      readbackPathAndQuery: '/api/profile',
      readbackActor: actor,
      baselineWrite: { body: { role: 'member' }, actor, method: 'PATCH', restoreOriginal: false },
    }

    const tp = await executeFloorRecipeById('persisted_mutation', args, brokerFloorRecipeDeps({ broker: makeBroker('tp'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-pm-tp' }))
    assert.equal(tp.result.confirmed, true, JSON.stringify(tp.failure))
    assert.equal(tp.primitive?.primitive, 'state_delta_and_conservation')
    assert.equal(tp.primitive?.satisfied, true)

    const fpNoop = await executeFloorRecipeById('persisted_mutation', args, brokerFloorRecipeDeps({ broker: makeBroker('fp_noop'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-pm-noop' }))
    assert.equal(fpNoop.result.confirmed, false)

    const fpCtrl = await executeFloorRecipeById('persisted_mutation', args, brokerFloorRecipeDeps({ broker: makeBroker('fp_control_only'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-pm-ctrl' }))
    assert.equal(fpCtrl.result.confirmed, false)
  })

  test('disclosure (access_differential): confirms cross-tenant disclosure and rejects anonymous control, masked payload, or own-tenant response', async () => {
    const owner = { handle: 'owner_b', role: 'owner' as const, tenant: 'org-b', auth: 'bearer' as const }
    const probe = { handle: 'probe_a', role: 'member' as const, tenant: 'org-a', auth: 'bearer' as const }
    const peer = { handle: 'peer_c', role: 'viewer' as const, tenant: 'org-c', auth: 'bearer' as const }
    const personas = new Map([
      ['owner_b', { handle: 'owner_b', roleLabel: 'Owner (org-b)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-b', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-b' } }],
      ['probe_a', { handle: 'probe_a', roleLabel: 'Member (org-a)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-a', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-a' } }],
      ['peer_c', { handle: 'peer_c', roleLabel: 'Viewer (org-c)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-c', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-c' } }],
    ])
    const grant = makeLabGrant(ORIGIN, { tier: 2, personas: personas as never })

    const makeBroker = (mode: 'tp' | 'masked' | 'own_tenant') => new RequestBroker({
      transport: async (url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        if (url.pathname.endsWith('/self')) {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'self-a', tenant: 'org-a', email: 'a@org-a.invalid' }) }
        }
        if (auth === 'Bearer tok-c' || !auth) {
          return { status: 403, headers: { 'content-type': 'application/json' }, body: '{"error":"forbidden"}' }
        }
        if (auth === 'Bearer tok-b') {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'rec-99', tenant: 'org-b', recordNote: 'confidential_org_b_value_9921' }) }
        }
        if (mode === 'masked') {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'rec-99', tenant: 'org-b', recordNote: '****9921' }) }
        }
        if (mode === 'own_tenant') {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'rec-99', tenant: 'org-a', note: 'own tenant data' }) }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'rec-99', tenant: 'org-b', recordNote: 'confidential_org_b_value_9921' }) }
      },
    })

    const baseArgs = { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/99', vulnClass: 'info_disclosure', owner, probe, denied: peer, resourceTenant: 'org-b' }
    const tp = await executeFloorRecipeById('disclosure', baseArgs, brokerFloorRecipeDeps({ broker: makeBroker('tp'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-disc-tp' }))
    assert.equal(tp.result.confirmed, true, JSON.stringify(tp.failure))
    assert.equal(tp.primitive?.primitive, 'access_differential')
    assert.equal(tp.primitive?.satisfied, true)

    const fpMasked = await executeFloorRecipeById('disclosure', baseArgs, brokerFloorRecipeDeps({ broker: makeBroker('masked'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-disc-mask' }))
    assert.equal(fpMasked.result.confirmed, false)

    const fpOwn = await executeFloorRecipeById('disclosure', baseArgs, brokerFloorRecipeDeps({ broker: makeBroker('own_tenant'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-disc-own' }))
    assert.equal(fpOwn.result.confirmed, false)

    const anonActor = { handle: '', role: null, tenant: null, auth: 'unknown' as const }
    const fpAnon = await executeFloorRecipeById('disclosure', { ...baseArgs, denied: anonActor }, brokerFloorRecipeDeps({ broker: makeBroker('tp'), grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-disc-anon' }))
    assert.equal(fpAnon.result.confirmed, false)
  })

  test('oob_callback (oob_and_execution_witness): confirms via canary relay seam and rejects reflected-only or control-triggered canaries', async () => {
    const probeToken = 'oob_canary_probe_99112233'
    const controlToken = 'oob_canary_ctrl_44556677'
    const grant = makeLabGrant(ORIGIN, { tier: 2 })
    const broker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        // Echoes request body to prove reflection alone never satisfies oob_and_execution_witness.
        body: JSON.stringify({ echoed: String(opts?.body ?? '') }),
      }),
    })
    const args = {
      origin: ORIGIN,
      method: 'POST',
      pathAndQuery: '/api/fetch',
      vulnClass: 'ssrf',
      token: probeToken,
      injectJsonBody: { url: `http://127.0.0.1/${probeToken}` },
      controlToken,
      controlJsonBody: { url: `http://127.0.0.1/${controlToken}` },
    }
    const relayFor = (triggeredTokens: Set<string>, tsOffsetMs = 10) => oobCanarySeam({
      origin: ORIGIN,
      canaryBroker: {
        checkCanary: (tok: string) => ({
          triggered: triggeredTokens.has(tok),
          hits: triggeredTokens.has(tok) ? [{ timestamp: new Date(Date.now() + tsOffsetMs).toISOString() }] : [],
          detail: 'unit relay',
        }),
      } as unknown as CanaryBroker,
    })

    // TP: only probe token observed on independent OOB relay
    const tp = await executeFloorRecipeById('oob_callback', args, brokerFloorRecipeDeps({ broker, grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-oob-tp', oob: relayFor(new Set([probeToken])) }))
    assert.equal(tp.result.confirmed, true, JSON.stringify(tp.failure))
    assert.equal(tp.primitive?.primitive, 'oob_and_execution_witness')
    assert.equal(tp.primitive?.satisfied, true)

    // FP 1: reflected canary in HTTP response, ZERO OOB relay callback
    const fpReflected = await executeFloorRecipeById('oob_callback', args, brokerFloorRecipeDeps({ broker, grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-oob-refl', oob: relayFor(new Set()) }))
    assert.equal(fpReflected.result.confirmed, false)

    // FP 2: control canary also fired on relay
    const fpControlFired = await executeFloorRecipeById('oob_callback', args, brokerFloorRecipeDeps({ broker, grant, signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-oob-ctrl', oob: relayFor(new Set([probeToken, controlToken])) }))
    assert.equal(fpControlFired.result.confirmed, false)

    // Planned recipe execution via runPlannedRecipe uses oobCanarySeam seamlessly
    const plan = planFloorRecipe({
      hypothesis: { intent: 'ssrf', probeClass: 'ssrf_canary', method: 'POST', pathAndQuery: '/api/fetch', endpoint: { origin: ORIGIN, pathTemplate: '/api/fetch', method: 'POST', params: [], riskScore: 80, source: 'openapi' }, risk: 80 } as never,
      probe: { verdict: 'signal', probeClass: 'ssrf_canary', anomalies: [{ type: 'oob_canary', canaryToken: probeToken, controlToken }], details: {}, exchangeIds: [], requestsSent: 2, summary: 'ssrf signal' } as never,
      specKind: 'http_chain',
      vulnClass: 'ssrf',
      personas: [],
      candidateSpec: { steps: [{ role: 'control', request: { method: 'POST', pathAndQuery: '/api/fetch', jsonBody: { url: `http://127.0.0.1/${controlToken}` } } }, { role: 'probe', request: { method: 'POST', pathAndQuery: '/api/fetch', jsonBody: { url: `http://127.0.0.1/${probeToken}` } } }] },
    })
    assert.ok(plan && !plan.skipReason && plan.recipeId === 'oob_callback')
    const plannedExec = await runPlannedRecipe({
      plan,
      hypothesis: { intent: 'ssrf', probeClass: 'ssrf_canary', method: 'POST', pathAndQuery: '/api/fetch', endpoint: { origin: ORIGIN, pathTemplate: '/api/fetch', method: 'POST' } } as never,
      broker,
      grant,
      signal: AbortSignal.timeout(5_000),
      runId: 'run-d1-oob-plan',
      oob: async ({ token }) => token === probeToken ? { id: 'oob-evt-1', callbackId: 'oob:1', token, targetOrigin: ORIGIN, delivered: true, stage: 'immediate', receivedAtMs: Date.now() + 10, injectedAtMs: Date.now() } : null,
    })
    assert.equal(plannedExec.result.confirmed, true)
    const specRec = recipeSpecRecord(plan, plannedExec)
    assert.equal(specRec.spec.assertionsJq, TYPED_RECIPE_ASSERTION)
  })
})

describe('Track D Cut 1: zero-jq Cut-3e runners via Track A2 Tier-1 primitives', () => {
  test('rce_proof (oob_and_execution_witness): confirms dynamic_math evaluation and rejects reflected/control-present values with zero jq', async () => {
    const grant = makeLabGrant(ORIGIN, { tier: 3, isStateChangeApproved: () => true })
    const evalBroker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => {
        const body = JSON.parse(String(opts?.body ?? '{}')) as { expr?: string }
        const m = String(body.expr ?? '').match(/^(\d+)\*(\d+)$/)
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ out: m ? String(Number(m[1]) * Number(m[2])) : body.expr }) }
      },
    })
    const reflectBroker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: String(opts?.body ?? '{}'),
      }),
    })
    const spec = baseSpec({
      kind: 'rce_proof' as const,
      cwe: 'CWE-1336',
      proofMode: 'dynamic_math' as const,
      requiresTier3Approval: true,
      controlStep: { id: 'c', role: 'control' as const, description: 'benign', request: { origin: ORIGIN, method: 'POST' as const, pathAndQuery: '/render', jsonBody: { expr: 'hello' } } },
      probeStep: { id: 'p', role: 'probe' as const, description: 'math', request: { origin: ORIGIN, method: 'POST' as const, pathAndQuery: '/render', jsonBody: { expr: '{{nonce_a}}*{{nonce_b}}' } } },
    })

    const tp = await runRceProofRecipe(spec as never, { broker: evalBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-rce-tp' })
    assert.equal(tp.verdict, 'confirmed')
    assert.equal((tp.evidencePayload.proof as { tier1Primitive?: { primitive: string; satisfied: boolean } }).tier1Primitive?.primitive, 'oob_and_execution_witness')
    assert.equal((tp.evidencePayload.proof as { tier1Primitive?: { satisfied: boolean } }).tier1Primitive?.satisfied, true)

    const fp = await runRceProofRecipe(spec as never, { broker: reflectBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-rce-fp' })
    assert.equal(fp.verdict, 'dismissed')
  })

  test('cache_differential (wire_framing_and_cache_differential): confirms cache priming and rejects pre-exposed control or cross-route mismatch with zero jq', async () => {
    const grant = makeLabGrant(ORIGIN, { tier: 2 })
    const poisoned = new Map<string, string>()
    const broker = new RequestBroker({
      transport: async (url, _addr, _sig, opts) => {
        const gcb = url.searchParams.get('_gcb') ?? ''
        const xfh = opts?.headers?.['X-Forwarded-Host'] ?? opts?.headers?.['x-forwarded-host']
        if (xfh && gcb) poisoned.set(gcb, xfh)
        if (poisoned.has(gcb)) {
          return { status: 200, headers: { 'content-type': 'text/plain', 'x-cache': xfh ? 'MISS' : 'HIT', ...(xfh ? {} : { age: '7' }) }, body: `HOST=${poisoned.get(gcb)}` }
        }
        return { status: 200, headers: { 'content-type': 'text/plain', 'x-cache': 'MISS' }, body: 'HOST=clean' }
      },
    })
    const spec = baseSpec({
      kind: 'cache_differential' as const,
      cwe: 'CWE-444',
      targetOrigin: ORIGIN,
      method: 'GET' as const,
      mode: 'poisoning' as const,
      proofMode: 'header_hit' as const,
      controlPath: '/home?_gcb={{control_gcb}}',
      probePath: '/home?_gcb={{probe_gcb}}',
      poisonHeaders: { 'X-Forwarded-Host': 'poison.invalid' },
    })

    const tp = await runCacheDifferentialRecipe(spec as never, { broker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-cache-tp' })
    assert.equal(tp.verdict, 'confirmed')
    assert.equal((tp.evidencePayload.cacheProof as { tier1Primitive?: { primitive: string; satisfied: boolean } }).tier1Primitive?.primitive, 'wire_framing_and_cache_differential')
    assert.equal((tp.evidencePayload.cacheProof as { tier1Primitive?: { satisfied: boolean } }).tier1Primitive?.satisfied, true)

    // FP 1: cross-route mismatch between control (/public) and verify (/home)
    const fpRoute = await runCacheDifferentialRecipe({ ...spec, controlPath: '/public?_gcb={{control_gcb}}' } as never, { broker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-cache-route' })
    assert.equal(fpRoute.verdict, 'dismissed')
    assert.equal((fpRoute.evidencePayload.cacheProof as { tier1Primitive?: { reason: string } }).tier1Primitive?.reason, 'control_and_variant_route_mismatch')

    // FP 2: clean control already contains victim content
    const preExposedBroker = new RequestBroker({
      transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain', 'x-cache': 'HIT', age: '5' }, body: 'HOST=poison.invalid' }),
    })
    const fpPre = await runCacheDifferentialRecipe(spec as never, { broker: preExposedBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-cache-pre' })
    assert.equal(fpPre.verdict, 'dismissed')
  })

  test('auth_protocol_proof (zero-jq): confirms denied-control signature_validity & valid-control forged-token differential; rejects spoofed anon control, identical body, and cross-route mismatch', async () => {
    const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'alice', role: 'user' })
    const personas = new Map([
      ['alice', { handle: 'alice', roleLabel: 'User', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: jwt, session: { headerName: 'Authorization', headerType: 'Bearer', value: jwt } }],
    ])
    const grant = makeLabGrant(ORIGIN, { tier: 2, personas: personas as never })

    // TP 1: denied control (401) vs accepted alg_none probe (200) -> wire_framing_and_cache_differential:signature_validity
    const deniedVsForgedBroker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        if (!auth.startsWith('Bearer ')) return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"unauthorized"}' }
        const hdr = JSON.parse(Buffer.from(auth.slice(7).split('.')[0]!, 'base64url').toString('utf8')) as { alg?: string }
        if (hdr.alg === 'none') return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"sub":"admin","role":"admin","secret":"vault_8842"}' }
        return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"invalid_sig"}' }
      },
    })
    const tpDenied = await runAuthProtocolProofRecipe(baseSpec({
      kind: 'auth_protocol_proof' as const,
      protocol: 'jwt' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'signed token rejected on admin', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/admin', persona: 'alice' } },
        { id: 'p1', role: 'probe' as const, description: 'alg:none accepted', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/admin', persona: 'alice', authMutation: { kind: 'alg_none' as const } } },
      ],
    }) as never, { broker: deniedVsForgedBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-auth-tp1' })
    assert.equal(tpDenied.verdict, 'confirmed')
    assert.equal((tpDenied.evidencePayload.tier1Primitive as { primitive: string; subRule: string }).primitive, 'wire_framing_and_cache_differential')
    assert.equal((tpDenied.evidencePayload.tier1Primitive as { subRule: string }).subRule, 'signature_validity')

    // TP 2: valid-token control (200 standard view) vs forged alg_none probe (200 elevated admin data) -> wire_framing_and_cache_differential
    const validVsForgedBroker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        const hdr = auth.startsWith('Bearer ') ? JSON.parse(Buffer.from(auth.slice(7).split('.')[0]!, 'base64url').toString('utf8')) as { alg?: string } : {}
        const elevated = hdr.alg === 'none'
        return {
          status: 200,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(elevated
            ? { isAdmin: true, user: 'alice', summary: 'elevated admin console active', seatLimit: 500 }
            : { isAdmin: false, user: 'alice', summary: 'standard member view', seatLimit: 5 }),
        }
      },
    })
    const tpValid = await runAuthProtocolProofRecipe(baseSpec({
      kind: 'auth_protocol_proof' as const,
      protocol: 'jwt' as const,
      category: 'security-misconfiguration' as const,
      cwe: 'CWE-345',
      expectControlDenied: false,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'valid jwt', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/me', persona: 'alice' } },
        { id: 'p1', role: 'probe' as const, description: 'alg:none jwt', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/me', persona: 'alice', authMutation: { kind: 'alg_none' as const } } },
      ],
    }) as never, { broker: validVsForgedBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-auth-tp2' })
    assert.equal(tpValid.verdict, 'confirmed')
    assert.equal((tpValid.evidencePayload.tier1Primitive as { primitive: string }).primitive, 'wire_framing_and_cache_differential')

    // FP 1: patched target rejects alg_none with 401
    const patchedBroker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        const hdr = auth.startsWith('Bearer ') ? JSON.parse(Buffer.from(auth.slice(7).split('.')[0]!, 'base64url').toString('utf8')) as { alg?: string } : {}
        if (hdr.alg === 'none') return { status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"alg_none_rejected"}' }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"isAdmin":false}' }
      },
    })
    const fpPatched = await runAuthProtocolProofRecipe(baseSpec({
      kind: 'auth_protocol_proof' as const,
      protocol: 'jwt' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'valid jwt', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/me', persona: 'alice' } },
        { id: 'p1', role: 'probe' as const, description: 'alg:none rejected', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/me', persona: 'alice', authMutation: { kind: 'alg_none' as const } } },
      ],
    }) as never, { broker: patchedBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-auth-fp1' })
    assert.equal(fpPatched.verdict, 'dismissed')

    // FP 2: static public endpoint returning identical 200 to control and probe
    const staticBroker = new RequestBroker({
      transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"public":"static"}' }),
    })
    const fpStatic = await runAuthProtocolProofRecipe(baseSpec({
      kind: 'auth_protocol_proof' as const,
      protocol: 'jwt' as const,
      steps: [
        { id: 'c1', role: 'control' as const, description: 'valid', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/public', persona: 'alice' } },
        { id: 'p1', role: 'probe' as const, description: 'alg:none', request: { origin: ORIGIN, method: 'GET' as const, pathAndQuery: '/api/public', persona: 'alice', authMutation: { kind: 'alg_none' as const } } },
      ],
    }) as never, { broker: staticBroker, backend: noJqBackend, grant, signal: AbortSignal.timeout(5_000), assignmentId: 'asg-auth-fp2' })
    assert.equal(fpStatic.verdict, 'dismissed')

    // FP 3: spoofed anonymous 401 control vs normal authenticated 200 probe (no token mutation)
    const fpAnon = authProtocolTier1Decision({
      control: { exchangeId: 'ex-c', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 401, mediaType: 'application/json', body: '{"error":"unauth"}', reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      probe: { exchangeId: 'ex-p', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"user":"alice"}', reqHeaders: {}, respHeaders: {}, personaHandle: 'alice' } as never },
    })
    assert.equal(fpAnon.satisfied, false)
    assert.equal(fpAnon.reason, 'unauthenticated_baseline_control')

    // FP 4: cross-route mismatch (same authenticated actor, mismatched route)
    const fpCrossRoute = authProtocolTier1Decision({
      control: { exchangeId: 'ex-c', exchange: { method: 'GET', pathAndQuery: '/api/a', status: 401, mediaType: 'application/json', body: '{"error":"unauth"}', reqHeaders: { authorization: 'Bearer tok-a' }, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'ex-p', exchange: { method: 'GET', pathAndQuery: '/api/b', status: 200, mediaType: 'application/json', body: '{"admin":true}', reqHeaders: { authorization: 'Bearer tok-b' }, respHeaders: {}, personaHandle: 'alice', wireCredentialProvenance: { jarCookieNames: [], vaultHeaderNames: ['authorization'], callerAuthHeaderNames: [], authMutated: true } } as never, authMutation: { kind: 'alg_none' } },
    })
    assert.equal(fpCrossRoute.satisfied, false)
    assert.equal(fpCrossRoute.reason, 'control_and_variant_route_mismatch')
  })

  test('R3-05 Opus soundness regressions (H1-H4, M1-M2): stale OOB hit, owner-as-probe disclosure, response-derived redirect canary, 200 nonce/error diff, anon-401+cookie bypass, and dynamic cache miss all fail closed', async () => {
    // H1: stale pre-injection discovery hit is rejected by oobCanarySeam; missing controlToken skips plan
    const staleSeam = oobCanarySeam({
      origin: ORIGIN,
      canaryBroker: {
        checkCanary: () => ({ triggered: true, hits: [{ timestamp: new Date(Date.now() - 60_000).toISOString() }], detail: 'stale' }),
      } as unknown as CanaryBroker,
    })
    assert.equal(await staleSeam({ token: 'oob_stale_token_1234', injectedAtMs: Date.now() }), null)
    const noCtrlPlan = planFloorRecipe({
      hypothesis: { intent: 'ssrf', probeClass: 'ssrf_canary', method: 'POST', pathAndQuery: '/api/fetch', endpoint: { origin: ORIGIN, pathTemplate: '/api/fetch', method: 'POST', params: [], riskScore: 80, source: 'openapi' }, risk: 80 } as never,
      probe: { verdict: 'signal', probeClass: 'ssrf_canary', anomalies: [{ type: 'oob_canary', canaryToken: 'oob_only_probe_1234' }], details: {}, exchangeIds: [], requestsSent: 1, summary: 'ssrf' } as never,
      specKind: 'http_chain', vulnClass: 'ssrf', personas: [],
    })
    assert.ok(noCtrlPlan?.skipReason?.includes('benign control canary'))

    // H2: owner-as-probe disclosure with lower-role denied peer fails closed in planner and execution
    const ownerProbePlan = planFloorRecipe({
      hypothesis: { intent: 'info_disclosure', probeClass: 'authz_matrix', method: 'GET', pathAndQuery: '/api/admin/integrations/int_1', ownerPersona: 'admin_a', endpoint: { origin: ORIGIN, pathTemplate: '/api/admin/integrations/:id', method: 'GET', params: [], riskScore: 80, source: 'openapi' }, risk: 80 } as never,
      probe: { verdict: 'signal', probeClass: 'authz_matrix', anomalies: [], details: {}, exchangeIds: [], requestsSent: 2, summary: 'disc' } as never,
      specKind: 'http_chain', vulnClass: 'info_disclosure',
      personas: [
        { handle: 'admin_a', roleLabel: 'Admin (acme)', privilege: 'admin', tenant: 'acme' },
        { handle: 'viewer_a', roleLabel: 'Viewer (acme)', privilege: 'viewer', tenant: 'acme' },
      ],
    })
    assert.ok(ownerProbePlan?.skipReason?.includes('distinct authenticated owner and probe'))
    const adminActor = { handle: 'admin_a', role: 'admin' as const, tenant: 'acme', auth: 'bearer' as const }
    const viewerActor = { handle: 'viewer_a', role: 'viewer' as const, tenant: 'acme', auth: 'bearer' as const }
    const h2Personas = new Map([
      ['admin_a', { handle: 'admin_a', roleLabel: 'Admin (acme)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-adm', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-adm' } }],
      ['viewer_a', { handle: 'viewer_a', roleLabel: 'Viewer (acme)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-vw', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-vw' } }],
    ])
    const h2Broker = new RequestBroker({
      transport: async (_url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        if (auth === 'Bearer tok-vw') return { status: 403, headers: { 'content-type': 'application/json' }, body: '{"error":"forbidden"}' }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"id":"int_1","name":"Billing","endpoint_url":"https://hooks.acme.test/billing"}' }
      },
    })
    const h2Exec = await executeFloorRecipeById('disclosure', {
      origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/integrations/int_1', vulnClass: 'info_disclosure',
      owner: adminActor, probe: adminActor, denied: viewerActor,
    }, brokerFloorRecipeDeps({ broker: h2Broker, grant: makeLabGrant(ORIGIN, { tier: 2, personas: h2Personas as never }), signal: AbortSignal.timeout(5_000), origin: ORIGIN, runId: 'run-d1-h2' }))
    assert.equal(h2Exec.result.confirmed, false)

    // H3: 302 to registered IdP hostname NOT injected in probe request fails closed; probe-injected external canary confirms
    const h3Fp = authProtocolTier1Decision({
      origin: ORIGIN,
      control: { exchangeId: 'c-idp', exchange: { origin: ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize?redirect_uri=https://app.example.test/cb', status: 200, mediaType: 'text/html', body: 'ok', reqHeaders: {}, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-idp', exchange: { origin: ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize?redirect_uri=https://attacker-canary.invalid/cb', status: 302, mediaType: 'text/plain', body: '', reqHeaders: {}, respHeaders: { location: 'https://login.idp-provider.example/auth' }, personaHandle: 'alice' } as never },
    })
    assert.equal(h3Fp.satisfied, false)
    const h3Tp = authProtocolTier1Decision({
      origin: ORIGIN,
      control: { exchangeId: 'c-red', exchange: { origin: ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize?redirect_uri=https://app.example.test/cb', status: 200, mediaType: 'text/html', body: 'ok', reqHeaders: {}, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-red', exchange: { origin: ORIGIN, method: 'GET', pathAndQuery: '/oauth/authorize?redirect_uri=https://attacker-canary.invalid/cb', status: 302, mediaType: 'text/plain', body: '', reqHeaders: {}, respHeaders: { location: 'https://attacker-canary.invalid/cb?code=123' }, personaHandle: 'alice' } as never },
    })
    assert.equal(h3Tp.satisfied, true)
    assert.equal(h3Tp.primitive, 'oob_and_execution_witness')

    // H4: 200-vs-200 nonce/timestamp diff and 200 error page fail closed (never hostVerified causal_dag)
    const h4Nonce = authProtocolTier1Decision({
      control: { exchangeId: 'c-n', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"user":"alice","nonce":"111"}', reqHeaders: { authorization: 'Bearer a' }, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-n', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"user":"alice","nonce":"222"}', reqHeaders: { authorization: 'Bearer b' }, respHeaders: {}, personaHandle: 'alice', wireCredentialProvenance: { jarCookieNames: [], vaultHeaderNames: ['authorization'], callerAuthHeaderNames: [], authMutated: true } } as never, authMutation: { kind: 'alg_none' } },
    })
    assert.equal(h4Nonce.satisfied, false)
    assert.equal(h4Nonce.reason, 'no_privilege_escalation_in_200_response')
    const h4Err = authProtocolTier1Decision({
      control: { exchangeId: 'c-e', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"isAdmin":false,"user":"alice"}', reqHeaders: { authorization: 'Bearer a' }, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-e', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"ok":false,"error":"invalid_signature","isAdmin":true}', reqHeaders: { authorization: 'Bearer b' }, respHeaders: {}, personaHandle: 'alice', wireCredentialProvenance: { jarCookieNames: [], vaultHeaderNames: ['authorization'], callerAuthHeaderNames: [], authMutated: true } } as never, authMutation: { kind: 'alg_none' } },
    })
    assert.equal(h4Err.satisfied, false)

    // M1: anonymous 401 control paired with cookie-authenticated alice 200 probe fails closed; unchanged wire credential fails closed
    const m1Anon = authProtocolTier1Decision({
      control: { exchangeId: 'c-m1', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 401, mediaType: 'application/json', body: '{"error":"unauth"}', reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      probe: { exchangeId: 'p-m1', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"user":"alice","role":"member"}', reqHeaders: { cookie: 'sid=abc', authorization: 'Bearer forged' }, respHeaders: {}, personaHandle: 'alice', wireCredentialProvenance: { jarCookieNames: ['sid'], vaultHeaderNames: [], callerAuthHeaderNames: ['authorization'], authMutated: true } } as never, authMutation: { kind: 'alg_none' } },
    })
    assert.equal(m1Anon.satisfied, false)
    assert.equal(m1Anon.reason, 'control_and_variant_actor_mismatch')
    const m1SameWire = authProtocolTier1Decision({
      control: { exchangeId: 'c-m1w', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 401, mediaType: 'application/json', body: '{"error":"unauth"}', reqHeaders: { authorization: 'Bearer same' }, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-m1w', exchange: { method: 'GET', pathAndQuery: '/api/me', status: 200, mediaType: 'application/json', body: '{"user":"alice"}', reqHeaders: { authorization: 'Bearer same' }, respHeaders: {}, personaHandle: 'alice' } as never, authMutation: { kind: 'alg_none' } },
    })
    assert.equal(m1SameWire.satisfied, false)
    assert.equal(m1SameWire.reason, 'no_wire_differential_between_control_and_variant')
    // Plain login password diff (with unused minted token) and non-token body param diff must fail closed
    const unusedMint = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ2aWN0aW0ifQ.'
    const m1Login = authProtocolTier1Decision({
      control: { exchangeId: 'c-login', requestBody: '{"password":"wrong"}', exchange: { method: 'POST', pathAndQuery: '/api/login', status: 403, mediaType: 'application/json', body: '{"error":"bad_creds"}', reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      probe: { exchangeId: 'p-login', requestBody: '{"password":"real"}', exchange: { method: 'POST', pathAndQuery: '/api/login', status: 200, mediaType: 'application/json', body: '{"ok":true,"access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.sig"}', reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      hasTokenMints: true, mintedTokenValues: [unusedMint],
    })
    assert.equal(m1Login.satisfied, false)
    assert.equal(m1Login.reason, 'no_wire_differential_between_control_and_variant')
    const m1Lookup = authProtocolTier1Decision({
      control: { exchangeId: 'c-lk', requestBody: '{"id":1}', exchange: { method: 'POST', pathAndQuery: '/api/lookup', status: 200, mediaType: 'application/json', body: '{"user_id":"u1"}', reqHeaders: {}, respHeaders: {}, personaHandle: 'alice' } as never },
      probe: { exchangeId: 'p-lk', requestBody: '{"id":2}', exchange: { method: 'POST', pathAndQuery: '/api/lookup', status: 200, mediaType: 'application/json', body: '{"user_id":"u2"}', reqHeaders: {}, respHeaders: {}, personaHandle: 'alice' } as never },
      hasTokenMints: true, mintedTokenValues: [unusedMint],
    })
    assert.equal(m1Lookup.satisfied, false)
    assert.equal(m1Lookup.reason, 'no_wire_differential_between_control_and_variant')
    // Echoed submitted forged token or active:false response must NOT satisfy isTokenMintGrant
    const m1Echoed = authProtocolTier1Decision({
      control: { exchangeId: 'c-ec', requestBody: '{"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSJ9.bad"}', exchange: { method: 'POST', pathAndQuery: '/api/token', status: 401, mediaType: 'application/json', body: '{"error":"invalid"}', reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      probe: { exchangeId: 'p-ec', requestBody: `{"token":"${unusedMint}"}`, exchange: { method: 'POST', pathAndQuery: '/api/token', status: 200, mediaType: 'application/json', body: JSON.stringify({ access_token: unusedMint, active: false }), reqHeaders: {}, respHeaders: {}, personaHandle: null } as never },
      hasTokenMints: true, mintedTokenValues: [unusedMint],
    })
    assert.equal(m1Echoed.satisfied, false)
    // Same-tenant viewer 403 + admin control 200 + admin probe 200 with resourceTenant === probe tenant must reject controlDenied
    const h2Mirror = assessBoundary({
      impactClass: 'authorization', boundaryClass: 'access', resourceTenant: 'acme', expectControlDenied: true,
      steps: [
        { id: 'c1', arm: 'control', method: 'GET', route: '/api/admin/items/1', status: 403, actor: { handle: 'viewer_a', role: 'viewer', tenant: 'acme', auth: 'bearer', sameSite: null } },
        { id: 'c2', arm: 'control', method: 'GET', route: '/api/admin/items/1', status: 200, actor: { handle: 'admin_a', role: 'admin', tenant: 'acme', auth: 'bearer', sameSite: null }, json: { id: '1' } },
        { id: 'p1', arm: 'probe', method: 'GET', route: '/api/admin/items/1', status: 200, actor: { handle: 'admin_a', role: 'admin', tenant: 'acme', auth: 'bearer', sameSite: null }, json: { id: '1' } },
      ],
    })
    assert.equal(h2Mirror.controlDenied, false)
    assert.equal(h2Mirror.satisfied, false)

    // M2: dynamic-content cache HIT without poison-header reflection fails closed
    let reqIdx = 0
    const cachedByGcb = new Map<string, string>()
    const m2Broker = new RequestBroker({
      transport: async (url) => {
        const gcb = url.searchParams.get('_gcb') ?? ''
        const hit = cachedByGcb.has(gcb)
        if (!hit) cachedByGcb.set(gcb, `page_variant_${++reqIdx}_${'x'.repeat(reqIdx * 40)}`)
        return { status: 200, headers: { 'content-type': 'text/plain', 'x-cache': hit ? 'HIT' : 'MISS', ...(hit ? { age: '6' } : {}) }, body: cachedByGcb.get(gcb)! }
      },
    })
    const m2Res = await runCacheDifferentialRecipe(baseSpec({
      kind: 'cache_differential' as const, cwe: 'CWE-444', targetOrigin: ORIGIN, method: 'GET' as const, mode: 'poisoning' as const, proofMode: 'header_hit' as const,
      controlPath: '/home?_gcb={{control_gcb}}', probePath: '/home?_gcb={{probe_gcb}}', poisonHeaders: { 'X-Forwarded-Host': 'poison.invalid' },
    }) as never, { broker: m2Broker, backend: noJqBackend, grant: makeLabGrant(ORIGIN, { tier: 2 }), signal: AbortSignal.timeout(5_000), assignmentId: 'asg-m2-fp' })
    assert.equal(m2Res.verdict, 'dismissed')
  })

  test('host-signed transcript verification rejects tampered signatures fail-closed', () => {
    const signer = tier1HostSigner()
    const ctrl = signer.sign({ id: 'c1', timestampMs: 1, status: 403, method: 'GET', route: '/api/r/1', actorId: 'peer' })
    const variant = signer.sign({ id: 'p1', timestampMs: 2, status: 200, method: 'GET', route: '/api/r/1', actorId: 'probe', json: { secret: 'val' } })
    const tampered = { ...variant, hostSignature: '0'.repeat(64) }
    const res = evaluateUniversalPrimitive('access_differential', { control: ctrl, variant: tampered, bindRoute: true, controlPrincipal: 'any', verifySignature: signer.verify })
    assert.equal(res.satisfied, false)
    assert.match(res.reason, /signature|tamper|invalid/i)
  })
})

describe('Track D Cut 1: $0 fast-lane callers emit unified Verified Replay Specs with zero jq VM calls', () => {
  test('deterministic-engine.ts verifies via floor recipes and emits Verified Replay Spec without invoking jq backend', async () => {
    const personas = new Map([
      ['owner_a', { handle: 'owner_a', roleLabel: 'Owner (org-a)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-a', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-a' } }],
      ['other_b', { handle: 'other_b', roleLabel: 'Member (org-b)', authKind: 'bearer' as const, originAllowlist: [ORIGIN], secret: 'tok-b', session: { headerName: 'Authorization', headerType: 'Bearer', value: 'tok-b' } }],
    ])
    const broker = new RequestBroker({
      transport: async (url, _addr, _sig, opts) => {
        const auth = String(opts?.headers?.authorization ?? opts?.headers?.Authorization ?? '')
        if (url.pathname === '/api/invoices') {
          const item = auth === 'Bearer tok-a'
            ? { id: 'inv_1', tenant: 'org-a', owner: 'owner_a' }
            : { id: 'inv_2', tenant: 'org-b', owner: 'other_b' }
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify([item]) }
        }
        if (url.pathname === '/api/invoices/inv_1') {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'inv_1', tenant: 'org-a', total: 4200, owner: 'owner_a' }) }
        }
        return { status: 404, headers: { 'content-type': 'application/json' }, body: '{"error":"not_found"}' }
      },
    })
    const confirmed: Array<{ spec: Record<string, unknown>; vulnClass: string; evidencePayload: Record<string, unknown> }> = []
    const report = await runDeterministicEngine({
      runId: 'run-d1-engine',
      assignmentId: 'asg-d1-engine',
      signal: AbortSignal.timeout(5_000),
      endpoints: [
        { id: 'ep-list', origin: ORIGIN, method: 'GET', pathTemplate: '/api/invoices', params: [], riskScore: 80, source: 'openapi' },
        { id: 'ep-1', origin: ORIGIN, method: 'GET', pathTemplate: '/api/invoices/:id', params: [{ name: 'id', location: 'path' }], riskScore: 90, source: 'openapi' },
      ],
      personas: [
        { handle: 'owner_a', roleLabel: 'Owner (org-a)', privilege: 'owner', tenant: 'org-a' },
        { handle: 'other_b', roleLabel: 'Member (org-b)', privilege: 'member', tenant: 'org-b' },
      ],
      broker,
      grant: makeLabGrant(ORIGIN, { tier: 2, personas: personas as never }),
      backend: noJqBackend,
      tier: 2,
      maxRequests: 40,
      maxDurationMs: 8_000,
      probe: async (req) => req.probeClass === 'authz_matrix'
        ? {
            probeClass: 'authz_matrix', origin: ORIGIN, pathAndQuery: req.pathAndQuery, verdict: 'signal', requestsSent: 2, summary: 'cross-persona access',
            anomalies: [{ type: 'unauthorized_access', resourceId: 'inv_1', actor: 'other_persona', method: 'GET', status: 200, similarityToOwner: 1 }],
            details: { matrix: [{ resourceId: 'inv_1', actor: 'owner', status: 200, bodyBytes: 64, bodySha256: 'aaa', accessible: true }, { resourceId: 'inv_1', actor: 'other_persona', status: 200, bodyBytes: 64, similarityToOwner: 1, accessible: true }] },
            exchangeIds: ['ex-probe-1'], stoppedReason: null, notes: [], durationMs: 5,
          }
        : { probeClass: req.probeClass, origin: ORIGIN, pathAndQuery: req.pathAndQuery, verdict: 'no_signal', requestsSent: 1, summary: 'none', anomalies: [], details: {}, exchangeIds: [], stoppedReason: null, notes: [], durationMs: 1 },
      onConfirmed: input => {
        confirmed.push({ spec: input.spec as unknown as Record<string, unknown>, vulnClass: input.vulnClass, evidencePayload: input.result.evidencePayload })
        return 'finding-d1-1'
      },
    })

    assert.equal(report.confirmed, 1, JSON.stringify(report))
    assert.equal(confirmed.length, 1)
    assert.equal(confirmed[0]!.spec.assertionsJq, TYPED_RECIPE_ASSERTION)
    assert.equal((confirmed[0]!.spec.recipe as { recipeId?: string } | undefined)?.recipeId, 'access_boundary')
    assert.ok((confirmed[0]!.evidencePayload.tier1Primitive as { primitive?: string } | undefined)?.primitive)
  })

  test('exec-floor-lane.ts persists typed recipe envelopes with TYPED_RECIPE_ASSERTION (zero inline jq)', async t => {
    const { dir, storage } = makeStore(t, 'kovo-d1-lane-')
    const { runId, personaMap } = await setupApprovedRun(storage, {
      seeds: [ORIGIN],
      tier: 2,
      personas: [
        { handle: 'owner_a', roleLabel: 'Owner (org-a)', authKind: 'bearer', secret: 'tok-a' },
        { handle: 'other_b', roleLabel: 'Member (org-b)', authKind: 'bearer', secret: 'tok-b' },
      ],
    })
    storage.updateRun(runId, { status: 'running', phase: 'investigation' })
    storage.upsertEndpoint({ runId, origin: ORIGIN, method: 'GET', pathTemplate: '/api/items/:id', source: 'openapi', riskScore: 95 })
    storage.recordResourceSample({ runId, origin: ORIGIN, endpoint: '/api/items/:id', method: 'GET', resourceKey: 'id', resourceId: 'item_42', ownerPersona: 'owner_a' })

    const broker = new RequestBroker({
      transport: async (url) => {
        if (url.pathname === '/api/items/item_42') {
          return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 'item_42', owner: 'owner_a', tenant: 'org-a', secret: 'val_42' }) }
        }
        return { status: 404, headers: { 'content-type': 'application/json' }, body: '{"error":"not_found"}' }
      },
    })
    const grant = makeLabGrant(ORIGIN, { tier: 2, personas: personaMap })

    const lane = new ExecFloorLane({
      storage,
      broker,
      browser: {} as never,
      canaryBroker: new CanaryBroker(),
      backend: noJqBackend,
      dataDir: dir,
      probePlans: { get: () => null } as never,
      stagingTaggedMutations: new Map(),
      stagingUntaggedSkipped: new Map(),
      stagingCleaned: new Map(),
      stagingCreatedEntities: new Map(),
      approvedOriginsSet: () => new Set([ORIGIN]),
      permitted: () => true,
      buildGrant: () => ({ grant, secrets: [], currentSecrets: () => [] }),
      beginFloorRequestPhase: () => undefined,
      phaseRequestRemaining: () => 50,
      markEndpointCoverage: () => undefined,
      scanSecondOrderExchange: () => undefined,
      createConfirmedReplaySpec: () => { throw new Error('not expected') },
    } as never)

    await lane.runDeterministicInvestigation(storage.run(runId))
    const specs = storage.listReplaySpecs(runId)
    assert.ok(specs.length >= 1, 'expected at least one persisted deterministic replay spec')
    for (const row of specs) {
      const parsed = declarativeReplaySpecSchema.safeParse(row.spec)
      assert.equal(parsed.success, true, parsed.success ? '' : parsed.error.message)
      assert.equal(row.spec.assertionsJq, TYPED_RECIPE_ASSERTION)
      assert.ok(row.spec.recipe?.recipeId, 'persisted floor spec must carry a typed recipe envelope')
    }
  })
})
