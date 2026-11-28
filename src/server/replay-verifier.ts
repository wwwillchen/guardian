import { randomUUID } from 'node:crypto'
import type { VerificationTier } from '../domain.ts'
import {
  declarativeReplaySpecSchema,
  floorRecipeEnvelopeSchema,
  replaySpecOrigins,
} from '../replay-spec.ts'
import type { DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayAssertionOutcome } from '../replay-spec.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { Store } from './store.ts'
import type { WorkerBackend } from './worker-backend.ts'
import { MAX_REPLAY_REGEX_HAYSTACK_LENGTH, isSafeRegexPattern, proofReceiptMode, safeRegexTest, validateReplayAgentScriptEnvelope, validateReplayRecipeEnvelope } from './proof-receipt.ts'
import type { ProofReceipt, ProofReceiptMode, ReceiptVerification } from './proof-receipt.ts'
import { persistedAgentScriptOf, retestPersistedAgentScript } from './agent-script-proof.ts'
import { assessDeclarativeRetestHealth } from './retest-health.ts'
import {
  CWE_TO_RECEIPT_CLASS,
  RETIRED_LEGACY_SPEC_KINDS,
  RETIRED_LEGACY_SPEC_REASON,
  SEVERITY_BY_CLASS,
  browserSessionSeam,
  hasDestructiveContent,
  inconclusiveResult,
  isReceiptExemptHostSpec,
  retestPersistedRecipe,
  retiredLegacyResult,
  runAuthProtocolProofRecipe,
  runCacheDifferentialRecipe,
  runRceProofRecipe,
  runStaticAstProofRecipe,
} from './floor-recipe-engine.ts'
import { isProtocolBrowserSpec, wiredRecipeForSpecKind } from './floor-recipes.ts'

// Re-export stable verifier helpers & class maps so callers (`exec-verify.ts`, `patch-workflow.ts`,
// `replay-feedback.ts`, and benchmarks) keep importing them from the verifier.
export {
  CWE_TO_RECEIPT_CLASS,
  RETIRED_LEGACY_SPEC_KINDS,
  RETIRED_LEGACY_SPEC_REASON,
  SEVERITY_BY_CLASS,
  inconclusiveResult,
} from './floor-recipe-engine.ts'
export { MAX_REPLAY_REGEX_HAYSTACK_LENGTH, MAX_REPLAY_REGEX_PATTERN_LENGTH, isSafeRegexPattern, proofReceiptMode, safeRegexTest } from './proof-receipt.ts'
export type { ProofReceiptMode } from './proof-receipt.ts'

// Inline verification feedback lives in its own module; re-exported here.
export { buildInlineVerifyFeedback, verifyReplaySpecInline } from './replay-feedback.ts'
export type {
  EnrichedInlineVerifyFeedback,
  InlineExchangeHeaderSummary,
  InlineReplayVerificationResult,
  InlineStepBodyPreview,
  VerifyReplaySpecInlineParams,
} from './replay-feedback.ts'

// Agent-script proof execution lives in its own module; re-exported here.
export { persistedAgentScriptOf, retestPersistedAgentScript, runAgentScriptProof } from './agent-script-proof.ts'
export type { AgentScriptProofParams, AgentScriptProofResult } from './agent-script-proof.ts'

// Re-exported for tests and callers that only import the verifier.
export {
  awaitReplayCanary,
  defaultReplayCanaryImmediateMs,
  intersectStructuralDeltas,
  normalizeStructuralTokens,
  structuralDiff,
  structuralSimilarity,
} from './verify-support.ts'
export type { CanaryWaitOutcome, ReplayCanaryWaitOptions, StructuralDiff } from './verify-support.ts'

export type ReplayVerdict = 'confirmed' | 'static_verified' | 'dismissed' | 'inconclusive'
export type RetestVerdict = 'reproduced' | 'fixed' | 'inconclusive'

export interface VerifyReplaySpecParams {
  spec: DeclarativeReplaySpec | unknown
  broker: RequestBroker
  browser?: ScopedBrowser
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  /** Host path of the read-only repo mount; required for static_ast_proof. */
  reposDir?: string
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId?: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
  /** Trust level for `recipe`/`agentScript` envelopes (`'untrusted'` blocks model-supplied envelopes). */
  envelopeTrust?: 'host_persisted' | 'untrusted'
}

export interface ReplayVerificationResult {
  verdict: ReplayVerdict
  /** 'runtime_confirmed' only for runtime-confirmed verdicts; 'static_verified' for static_ast_proof; never both. */
  verificationTier?: VerificationTier
  outcome: ReplayAssertionOutcome
  exchangeIds: string[]
  exchanges: BrokerExchangeResult[]
  evidencePayload: Record<string, unknown>
  evidenceSha256: string
  /**
   * ProofReceipt check over the host-recorded transcript. Present whenever the replay could be
   * expressed as a receipt (impact or out-of-band). `mode` defaults to `'strict'` (gating), or
   * `'shadow'` when explicitly opted in via `KOVO_PROOF_RECEIPT=shadow`; see `proofReceiptMode`.
   */
  receipt?: ReplayReceiptCheck
}

export interface ReplayReceiptCheck {
  receipt: ProofReceipt
  verification: ReceiptVerification
  mode: Exclude<ProofReceiptMode, 'off'>
}

export interface RetestReplayResult {
  verdict: RetestVerdict
  replay: ReplayVerificationResult
}

async function verifyReplaySpecInner(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const { broker, backend, grant, signal } = params
  const assignmentId = params.assignmentId ?? randomUUID()
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []

  // 1. Structural validation
  const parsed = declarativeReplaySpecSchema.safeParse(params.spec)
  if (!parsed.success) {
    return inconclusiveResult(`Invalid DeclarativeReplaySpec: ${parsed.error.issues[0]?.message ?? 'schema mismatch'}`, exchanges, exchangeIds, {})
  }
  const spec = parsed.data

  // 2. Policy & scope validation (H-5: always enforce scope on `spec.origin`, even for static_ast_proof).
  const isStatic = spec.kind === 'static_ast_proof'
  const origins = [...new Set([...replaySpecOrigins(spec), spec.origin])]
  for (const origin of origins) {
    if (!grant.canRead(origin)) {
      grant.audit('denied', origin)
      return inconclusiveResult(`Replay spec origin ${origin} is not in approved scope.`, exchanges, exchangeIds, { kind: spec.kind, origins })
    }
  }
  if (!isStatic && hasDestructiveContent(JSON.stringify(spec))) {
    grant.audit('denied', spec.origin)
    return inconclusiveResult('Replay spec rejected by Kovo destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
  }
  if ((grant.tier ?? 1) === 0 && !isStatic) {
    return inconclusiveResult('Live replay verification is disabled in Tier 0.', exchanges, exchangeIds, { kind: spec.kind })
  }

  // 3. Floor-recipe envelope dispatch runs BEFORE retired legacy VM rejection (H-5 validated first).
  const persistedRecipe = persistedRecipeOf(params.spec)
  if (persistedRecipe) {
    const recipeCheck = validatePersistedRecipeEnvelope(spec, persistedRecipe, grant, params)
    if (!recipeCheck.ok) {
      grant.audit('denied', persistedRecipe.origin || spec.origin)
      return inconclusiveResult(recipeCheck.reason, exchanges, exchangeIds, { kind: spec.kind, recipeId: persistedRecipe.envelope.recipeId })
    }
    return (await runPersistedFloorRecipe(persistedRecipe, params, spec.origin)).replay
  }

  // 4. Reject all retired legacy declarative kinds (raw `http_chain` without a typed recipe falls through to step 6).
  if (RETIRED_LEGACY_SPEC_KINDS.has(spec.kind)) {
    return retiredLegacyResult(spec.kind, exchanges, exchangeIds)
  }

  // 5. Zero-jq typed runners (`static_ast_proof`, `rce_proof`, `cache_differential`, `auth_protocol_proof`).
  const runnerCtx = {
    broker,
    canaryBroker: params.canaryBroker,
    backend,
    reposDir: params.reposDir,
    grant,
    signal,
    storage: params.storage,
    runId: params.runId,
    assignmentId,
    onExchange: params.onExchange,
  }
  if (spec.kind === 'static_ast_proof') return runStaticAstProofRecipe(spec, runnerCtx)
  if (spec.kind === 'rce_proof') return runRceProofRecipe(spec, runnerCtx)
  if (spec.kind === 'cache_differential') return runCacheDifferentialRecipe(spec, runnerCtx)
  if (spec.kind === 'auth_protocol_proof') return runAuthProtocolProofRecipe(spec, runnerCtx)

  // Fail closed: legacy jq VM is retired; no other spec kinds are executable here.
  return retiredLegacyResult(spec.kind, exchanges, exchangeIds)
}

export async function verifyReplaySpec(params: VerifyReplaySpecParams): Promise<ReplayVerificationResult> {
  const result = await verifyReplaySpecInner(params)
  return withVerificationTier(result)
}

/** Cut 3 no-fallback invariant at the product floor boundary. */
export class RecipeWiredLegacyCallError extends Error {
  readonly code = 'KOVO_RECIPE_WIRED_LEGACY_CALL'
  readonly specKind: string
  readonly vulnClass: string

  constructor(specKind: string, vulnClass: string) {
    super(`verifyReplaySpec() received a recipe-wired spec kind ${specKind}/${vulnClass}; the floor must confirm it through its ProofReceipt recipe, not the legacy DSL verifier.`)
    this.name = 'RecipeWiredLegacyCallError'
    this.specKind = specKind
    this.vulnClass = vulnClass
  }
}

/** The class a spec claims, in the vocabulary the recipe table uses. */
function recipeClassOfSpec(spec: DeclarativeReplaySpec): string | null {
  switch (spec.kind) {
    case 'sql_boolean_diff':
    case 'sql_time_diff':
      return 'sqli'
    case 'race_burst':
      return 'race_double_spend'
    case 'http_chain':
      return typeof spec.category === 'string' ? spec.category : null
    default:
      return null
  }
}

/** Throw (and warn) when a wired pair would be routed to the legacy verifier. */
export function assertNotRecipeWiredLegacyCall(spec: DeclarativeReplaySpec | unknown): void {
  if (!spec || typeof spec !== 'object') return
  const kind = (spec as { kind?: unknown }).kind
  if (typeof kind !== 'string') return
  if (kind === 'browser_chain') {
    const steps = (spec as { steps?: unknown }).steps
    if (Array.isArray(steps) && isProtocolBrowserSpec(steps as Array<Record<string, unknown>>)) return
  }
  const vulnClass = recipeClassOfSpec(spec as DeclarativeReplaySpec)
  const recipe = vulnClass ? wiredRecipeForSpecKind(kind, vulnClass) : null
  if (!recipe) return
  const error = new RecipeWiredLegacyCallError(kind, vulnClass ?? 'unknown')
  process.emitWarning(error.message, { code: error.code })
  throw error
}

function withVerificationTier(result: ReplayVerificationResult): ReplayVerificationResult {
  const verificationTier: VerificationTier | undefined = result.verdict === 'static_verified'
    ? 'static_verified'
    : result.verdict === 'confirmed' ? 'runtime_confirmed' : undefined
  return { ...result, ...(verificationTier ? { verificationTier } : {}) }
}

async function runPersistedFloorRecipe(
  persisted: NonNullable<ReturnType<typeof persistedRecipeOf>>,
  params: VerifyReplaySpecParams,
  originFallback?: string,
) {
  const args = persisted.envelope.args as { vulnClass?: unknown; pathAndQuery?: unknown }
  const origin = persisted.origin || originFallback || ''
  return retestPersistedRecipe({
    envelope: persisted.envelope,
    specKind: persisted.kind,
    vulnClass: typeof args.vulnClass === 'string' && args.vulnClass ? args.vulnClass : persisted.kind,
    endpoint: typeof args.pathAndQuery === 'string' ? args.pathAndQuery : origin,
    origin,
    broker: params.broker,
    grant: params.grant,
    signal: params.signal,
    ...(params.runId ? { runId: params.runId } : {}),
    ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
    ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    browserSession: browserSessionSeam({
      browser: params.browser ?? new ScopedBrowser(params.broker),
      grant: params.grant,
      signal: params.signal,
      origin,
      ...(params.runId ? { runId: params.runId } : {}),
      ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
      ...(params.onExchange ? { recordExchange: (exchange: BrokerExchangeResult) => params.onExchange?.(exchange) } : {}),
    }),
  })
}

function validatePersistedRecipeEnvelope(
  spec: Pick<DeclarativeReplaySpec, 'kind' | 'origin'>,
  persisted: NonNullable<ReturnType<typeof persistedRecipeOf>>,
  grant: Grant,
  params: VerifyReplaySpecParams,
) {
  // H-5: Default-deny whenever envelopeTrust is omitted or anything other than 'host_persisted'.
  const trust = params.envelopeTrust === 'host_persisted' ? 'host_persisted' : 'untrusted'
  return validateReplayRecipeEnvelope({
    specKind: spec.kind, specOrigin: spec.origin, recipeId: persisted.envelope.recipeId,
    recipeArgs: persisted.envelope.args, recipeOrigin: persisted.origin,
    envelopeTrust: trust, tier: grant.tier ?? 1,
    canRead: o => grant.canRead(o), hasDestructive: hasDestructiveContent,
  })
}

export async function retestReplaySpec(params: VerifyReplaySpecParams): Promise<RetestReplayResult> {
  const persisted = persistedRecipeOf(params.spec)
  if (persisted) {
    const parsedSpec = declarativeReplaySpecSchema.safeParse(params.spec)
    const specLike = parsedSpec.success ? { kind: parsedSpec.data.kind, origin: parsedSpec.data.origin } : { kind: persisted.kind as DeclarativeReplaySpec['kind'], origin: persisted.origin }
    const originFallback = specLike.origin || persisted.origin
    if (!originFallback || !params.grant.canRead(originFallback)) {
      params.grant.audit('denied', originFallback || 'unknown')
      return { verdict: 'inconclusive', replay: inconclusiveResult(`Replay spec origin ${originFallback || '(missing)'} is not in approved scope.`, [], [], { kind: specLike.kind, recipeId: persisted.envelope.recipeId }) }
    }
    if (parsedSpec.success) {
      const origins = [...new Set([...replaySpecOrigins(parsedSpec.data), parsedSpec.data.origin])]
      for (const origin of origins) {
        if (!params.grant.canRead(origin)) {
          params.grant.audit('denied', origin)
          return { verdict: 'inconclusive', replay: inconclusiveResult(`Replay spec origin ${origin} is not in approved scope.`, [], [], { kind: specLike.kind, recipeId: persisted.envelope.recipeId, origins }) }
        }
      }
    }
    if (hasDestructiveContent(JSON.stringify(params.spec))) {
      params.grant.audit('denied', originFallback)
      return { verdict: 'inconclusive', replay: inconclusiveResult('Replay spec rejected by Kovo destructive-payload denylist.', [], [], { kind: specLike.kind, recipeId: persisted.envelope.recipeId }) }
    }
    const recipeCheck = validatePersistedRecipeEnvelope(specLike, persisted, params.grant, params)
    if (!recipeCheck.ok) {
      params.grant.audit('denied', persisted.origin || specLike.origin)
      return { verdict: 'inconclusive', replay: inconclusiveResult(recipeCheck.reason, [], [], { kind: specLike.kind, recipeId: persisted.envelope.recipeId }) }
    }
    const result = await runPersistedFloorRecipe(persisted, params, originFallback)
    return { verdict: result.verdict, replay: result.replay }
  }
  const agentScript = persistedAgentScriptOf(params.spec)
  if (agentScript) {
    const trust = params.envelopeTrust === 'host_persisted' ? 'host_persisted' : 'untrusted'
    const scriptCheck = validateReplayAgentScriptEnvelope({
      specKind: params.spec && typeof params.spec === 'object' ? (params.spec as { kind?: unknown }).kind : undefined,
      origin: agentScript.origin, verdict: agentScript.envelope.verdict, envelopeTrust: trust,
      tier: params.grant.tier ?? 1, canRead: o => params.grant.canRead(o),
    })
    if (!scriptCheck.ok) {
      params.grant.audit('denied', agentScript.origin)
      return { verdict: 'inconclusive', replay: inconclusiveResult(scriptCheck.reason, [], [], { kind: 'agent_script' }) }
    }
    return retestPersistedAgentScript(agentScript.envelope, { ...params, origin: agentScript.origin } as VerifyReplaySpecParams & { origin?: string })
  }
  const replay = await verifyReplaySpec(params)
  if (replay.verdict === 'confirmed' || replay.verdict === 'static_verified') return { verdict: 'reproduced', replay }
  if (replay.evidencePayload?.retired === true) {
    const retiredHealth = {
      healthy: false,
      code: 'receipt_unbuildable' as const,
      failureReason: 'receipt_unbuildable' as const,
      reason: RETIRED_LEGACY_SPEC_REASON,
    }
    const evidencePayload = { ...replay.evidencePayload, retestHealth: retiredHealth }
    return {
      verdict: 'inconclusive',
      replay: {
        ...replay,
        verdict: 'inconclusive',
        outcome: { ...replay.outcome, confirmed: false, controlPassed: false, reason: RETIRED_LEGACY_SPEC_REASON },
        evidencePayload,
      },
    }
  }
  const parsedSpec = declarativeReplaySpecSchema.safeParse(params.spec)
  const trust = params.envelopeTrust === 'host_persisted' ? 'host_persisted' : 'untrusted'
  const receiptBuildable = Boolean(replay.receipt) || (parsedSpec.success && (
    parsedSpec.data.kind === 'static_ast_proof'
    || (parsedSpec.data.kind === 'rce_proof' && trust === 'host_persisted')
    || isReceiptExemptHostSpec(parsedSpec.data, trust)
  ))
  const health = assessDeclarativeRetestHealth(parsedSpec.success ? parsedSpec.data : params.spec, replay, { receiptBuildable })
  const fixed = replay.verdict === 'dismissed' && health.healthy && health.failureReason === 'claim_not_reproduced'
  const evidencePayload = { ...replay.evidencePayload, retestHealth: health }
  return fixed
    ? { verdict: 'fixed', replay: { ...replay, evidencePayload } }
    : { verdict: 'inconclusive', replay: { ...replay, verdict: 'inconclusive', outcome: { ...replay.outcome, confirmed: false, controlPassed: false, reason: health.reason ?? replay.outcome.reason ?? 'Retest health check failed.' }, evidencePayload } }
}

function persistedRecipeOf(spec: unknown): { envelope: FloorRecipeEnvelope; kind: string; origin: string } | null {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) return null
  const record = spec as Record<string, unknown>
  const parsed = floorRecipeEnvelopeSchema.safeParse(record.recipe)
  if (!parsed.success) return null
  return { envelope: parsed.data, kind: typeof record.kind === 'string' ? record.kind : parsed.data.recipeId, origin: typeof record.origin === 'string' ? record.origin : '' }
}
