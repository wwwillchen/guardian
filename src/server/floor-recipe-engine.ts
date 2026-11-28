/**
 * Floor recipe planner (Cut 3a) — the production bridge between the deterministic floor's legacy
 * hypothesis/spec vocabulary and the typed recipe library in `floor-recipes.ts`.
 *
 * The floor forms a hypothesis, runs its benign differential probe, and gets a signal. For a
 * **wired** spec kind/class pair this module:
 *   1. derives the recipe arguments from the hypothesis, probe evidence and approved personas,
 *   2. runs the recipe through `runFloorRecipe` with the broker-backed deps
 *      (`brokerFloorRecipeDeps`), so every exchange is a real brokered request with the run's
 *      grant, staging headers, probe class and persisted exchange id,
 *   3. records a `SynthesizedEngineSpec` whose steps are the recipe's own host-recorded exchanges and
 *      whose assertion re-checks the receipt's claim on a later retest replay.
 *
 * Confirmation itself is the recipe's `ProofReceipt` verified by `verifyReceipt` — never a
 * declarative-spec assertion. A wired pair must not fall back to `verifyReplaySpec`; the verifier
 * throws if it is called for one (`assertRecipeWiredKind`).
 */
import { createHash, createHmac, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto'
import { diffResponse } from '../../worker/analyzers.ts'
import type { StateChangeApprovalContext } from './approval-judge.ts'
import { baseFields } from './floor-heuristics.ts'
import type { EngineHypothesis, Severity, SynthesizedEngineSpec } from './floor-heuristics.ts'
import {
  POSTURE_CATEGORY_RE,
  POSTURE_CWES,
  PRIVILEGED_ACTION_RE,
  bogusIdFor,
  fillResourceId,
  isSafeFieldName,
  isSafeResourceId,
  pickBaselineWrite,
  resolveAuthzReadbackTemplate,
  rolePrivilegeRank,
} from './floor-heuristics.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { BrowserSessionStep } from './scoped-browser.ts'
import type { EnginePersona } from './deterministic-engine.ts'
import type { DifferentialResult } from './surface-engine.ts'
import { anomalyCandidatePairs, buildTypedRunnerCandidate, probeClassCandidatePairs, requestFromInjection } from './floor-candidate-planner.ts'
import { CUT3_FLOOR_RECIPE_IDS, brokerFloorRecipeDeps, browserSinkEnvelopeFromSteps, cut3FloorRecipe, floorRecipe, isProtocolBrowserSpec, runCut3Recipe, runFloorRecipe, wiredRecipeForSpecKind } from './floor-recipes.ts'
import type {
  AccessBoundaryArgs,
  BooleanOrTimingArgs,
  BrowserSinkArgs,
  ConservedBalanceArgs,
  Cut3FloorRecipeArgs,
  DisclosureArgs,
  OobCallbackArgs,
  Cut3FloorRecipeArgsMap,
  Cut3FloorRecipeId,
  FloorActor,
  FloorRecipeArgs,
  FloorRecipeArgsMap,
  FloorRecipeDeps,
  FloorRecipeExecution,
  FloorRecipeId,
  FloorRequestSpec,
  InjectionFingerprintArgs,
  PersistedMutationArgs,
  RaceBurstArgs,
} from './floor-recipes.ts'
import { actorFromPersona, assessBoundary, assessImpactEvidence, assessMassAssignmentImpact, assessMfaBypass, assessStatusOnlyDivergence, classifyBoundaryClaim, classifyImpactDescriptor, normalizeRole, resolvePersonaIdentity } from './oracle-invariants.ts'
import type { ActorIdentity, AmbientAuth, ImpactStep, PersonaCredentialSource, RoleName } from './oracle-invariants.ts'
import { classifyRetestHealth } from './retest-health.ts'
import type { RetestHealthAssessment } from './retest-health.ts'
import { HostFactLog } from './host-fact-log.ts'
import { isPureJobOrHandleStubChain, proofReceiptMode } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptTranscript, ReceiptTranscriptEntry, ReceiptVerification } from './proof-receipt.ts'
import { defaultTerminalOracleRegistry } from './terminal-oracle-registry.ts'
import { evaluateUniversalPrimitive, resolveUniversalPrimitive } from './v8-oracle-families.ts'
import type { HostSignedRecord, SignatureVerifier, UniversalEvidencePrimitive, UniversalPrimitiveDecision } from './v8-oracle-families.ts'
import type { ProofReceiptMode, ReplayReceiptCheck, ReplayVerdict, ReplayVerificationResult, RetestVerdict } from './replay-verifier.ts'

export { proofReceiptMode }
import { cacheBusterValueRegex, containsDestructivePayload, extractCacheBusterParam } from '../replay-spec.ts'
import type { AuthMutation, DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'
import { normalizeStructuralTokens, openCanarySession, structuralDiffNormalized } from './verify-support.ts'
import type { EphemeralCanarySession } from './verify-support.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type PersistedFloorRecipeId = FloorRecipeId | Cut3FloorRecipeId
export type PersistedFloorRecipeArgs = FloorRecipeArgs | Cut3FloorRecipeArgs

const CUT3_RECIPE_ID_SET: ReadonlySet<string> = new Set(CUT3_FLOOR_RECIPE_IDS)

function isCut3RecipeId(id: PersistedFloorRecipeId): id is Cut3FloorRecipeId {
  return CUT3_RECIPE_ID_SET.has(id)
}

/** Dispatch any persisted floor recipe id (core 6 + Cut 3 recipes) through its typed runner and TerminalOracleRegistry. */
export async function executeFloorRecipeById(
  recipeId: PersistedFloorRecipeId,
  args: PersistedFloorRecipeArgs,
  deps: FloorRecipeDeps,
): Promise<FloorRecipeExecution> {
  const exec = isCut3RecipeId(recipeId)
    ? await runCut3Recipe(
        cut3FloorRecipe(recipeId, args as Cut3FloorRecipeArgsMap[typeof recipeId]),
        deps,
      )
    : await runFloorRecipe(
        floorRecipe(recipeId, args as FloorRecipeArgsMap[typeof recipeId]),
        deps,
      )
  if (!exec.result.confirmed) return exec
  const factLog = HostFactLog.fromTranscript(exec.result.transcript)
  const oracle = defaultTerminalOracleRegistry.evaluate(
    factLog,
    { kind: 'single_hop', receipt: exec.receipt },
    { strictHostDerivation: false },
  )
  if (oracle.confirmed) return applyTier1Gate(recipeId, args, exec)
  const verification: ReceiptVerification = oracle.singleHop ?? {
    confirmed: false,
    vulnClass: exec.receipt.vulnClass,
    rule: exec.result.verification.rule,
    reason: oracle.reason,
    observed: exec.receipt.claimedDelta,
    expected: 'host-custody verified floor receipt',
  }
  return {
    ...exec,
    result: { ...exec.result, confirmed: false, verification },
    failure: {
      code: 'receipt_rejected',
      message: verification.reason,
      missingRoles: ['impact_evidence'],
    },
  }
}

/** The exact target a wired recipe confirmed; the record spec re-uses it. */
// ---------------------------------------------------------------------------------------------
// Track D Cut 1 — Track A2 Tier-1 universal primitive gate (receipt -> terminal oracle -> primitive)
// ---------------------------------------------------------------------------------------------

const TIER1_MUTATION_CLASSES: ReadonlySet<string> = new Set(['mass_assignment', 'workflow_bypass', 'business_logic', 'price_tampering', 'csrf'])
type Tier1Rec = { role: string; record: HostSignedRecord }
type Tier1Signer = { sign: (r: Omit<HostSignedRecord, 'hostSignature'>) => HostSignedRecord; verify: SignatureVerifier }

/** Tier-1 primitive that must also confirm a recipe execution (null = the receipt rule alone gates it). */
export function tier1PrimitiveForRecipe(recipeId: PersistedFloorRecipeId, vulnClass: string): UniversalEvidencePrimitive | null {
  if (recipeId === 'disclosure') return 'access_differential'
  if (recipeId === 'oob_callback') return 'oob_and_execution_witness'
  return recipeId === 'persisted_mutation' && TIER1_MUTATION_CLASSES.has(vulnClass) ? 'state_delta_and_conservation' : null
}

const stableJson = (v: unknown): string => v === null || typeof v !== 'object' ? JSON.stringify(v) ?? 'null'
  : Array.isArray(v) ? `[${v.map(stableJson).join(',')}]`
    : `{${Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, x]) => `${JSON.stringify(k)}:${stableJson(x)}`).join(',')}}`

/** Per-evaluation host signer: every primitive input record is HMAC-bound to the host transcript and re-verified. */
export function tier1HostSigner(): Tier1Signer {
  const key = randomBytes(32), mac = (r: Omit<HostSignedRecord, 'hostSignature'>): Buffer => createHmac('sha256', key).update(stableJson(r)).digest()
  return {
    sign: r => ({ ...r, hostSignature: mac(r).toString('hex') }),
    verify: ({ hostSignature, ...rest }) => /^[0-9a-f]{64}$/.test(hostSignature) && timingSafeEqual(Buffer.from(hostSignature, 'hex'), mac(rest)),
  }
}

/** Host transcript entries as signed records; timestamps are the host transcript order (never worker-supplied). */
export function tier1TranscriptRecords(transcript: ReceiptTranscript, signer: Tier1Signer): Tier1Rec[] {
  return (transcript.entries ?? []).map((e, i) => ({
    role: e.evidenceRole ?? e.step.evidenceRole ?? '',
    record: signer.sign({ id: e.exchangeId, timestampMs: i + 1, status: e.step.status, method: e.step.method, route: e.step.route ?? e.step.pathAndQuery, pathAndQuery: e.step.pathAndQuery, actorId: e.step.actor.handle ?? null, tenantId: e.step.actor.tenant ?? null, body: e.step.body, json: e.step.json, requestHeaders: e.step.requestHeaders ?? null, responseHeaders: e.step.responseHeaders ?? null }),
  }))
}

const roleRec = (recs: readonly Tier1Rec[], role: string): HostSignedRecord => recs.find(r => r.role === role)?.record as HostSignedRecord
const isScalar = (v: unknown): v is string | number | boolean => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
function jsonHasField(node: unknown, key: string, value: string | number | boolean, depth = 0): boolean {
  if (!node || typeof node !== 'object' || depth > 6) return false
  if (Array.isArray(node)) return node.some(n => jsonHasField(n, key, value, depth + 1))
  const rec = node as Record<string, unknown>
  return (Object.hasOwn(rec, key) && isScalar(rec[key]) && String(rec[key]) === String(value)) || Object.values(rec).some(v => jsonHasField(v, key, value, depth + 1))
}

/** Field binding: a probe-only body value must be newly persisted, and no control-write-only value may appear. */
export function mutationBindingError(args: Pick<PersistedMutationArgs, 'body' | 'baselineWrite'>, before: unknown, after: unknown): string | null {
  const control = args.baselineWrite?.body ?? {}, newly = (k: string, v: unknown) => isScalar(v) && jsonHasField(after, k, v) && !jsonHasField(before, k, v)
  if (Object.entries(control).some(([k, v]) => args.body[k] !== v && newly(k, v))) return 'control_write_value_leaked_into_readback'
  return Object.entries(args.body).some(([k, v]) => control[k] !== v && newly(k, v)) ? null : 'probe_value_not_newly_persisted'
}

function tier1Decision(primitive: UniversalEvidencePrimitive, args: PersistedFloorRecipeArgs, transcript: ReceiptTranscript): UniversalPrimitiveDecision {
  const signer = tier1HostSigner(), recs = tier1TranscriptRecords(transcript, signer), verifySignature = signer.verify
  if (primitive === 'access_differential') {
    const a = args as DisclosureArgs, control = roleRec(recs, 'denied_control'), variant = roleRec(recs, 'probe_request'), entitled = roleRec(recs, 'entitled_read')
    if (control && !control.actorId) return { primitive, required: true, satisfied: false, reason: 'anonymous_denied_control' }
    if ((a.owner.handle && a.probe.handle && a.owner.handle === a.probe.handle) || (entitled?.actorId && variant?.actorId && entitled.actorId === variant.actorId)) {
      return { primitive, required: true, satisfied: false, reason: 'probe_reuses_entitled_owner_actor' }
    }
    const deniedRank = rolePrivilegeRank(a.denied?.role), probeRank = rolePrivilegeRank(a.probe.role)
    const sameScope = (a.denied?.tenant && a.probe.tenant && a.denied.tenant === a.probe.tenant) || (!a.denied?.tenant && !a.probe.tenant) || (a.owner.tenant && a.probe.tenant && a.owner.tenant === a.probe.tenant)
    if (sameScope && deniedRank !== null && probeRank !== null && deniedRank < probeRank) {
      return { primitive, required: true, satisfied: false, reason: 'denied_control_lower_privilege_than_probe' }
    }
    return evaluateUniversalPrimitive(primitive, { control, variant, bindRoute: true, requireChronology: true, controlPrincipal: 'any', ownTenants: a.probe.tenant ? [a.probe.tenant] : [], verifySignature })
  }
  if (primitive === 'oob_and_execution_witness') {
    const a = args as OobCallbackArgs, events = transcript.oobEvents ?? [], controlRec = recs.find(r => r.role === 'benign_control')?.record, triggerRec = roleRec(recs, 'injection_exchange')
    const hit = events.find(e => e.token === a.token && e.delivered), ctl = a.controlToken ? events.find(e => e.token === a.controlToken && e.delivered) : undefined
    if (hit && (typeof hit.receivedAtMs !== 'number' || !Number.isFinite(hit.receivedAtMs) || typeof hit.injectedAtMs !== 'number' || !Number.isFinite(hit.injectedAtMs))) {
      return { primitive, required: true, satisfied: false, reason: 'missing_oob_host_timestamps' }
    }
    const resignTs = (r: HostSignedRecord | undefined, timestampMs: number): HostSignedRecord | undefined => {
      if (!r) return undefined
      const { hostSignature: _sig, ...rest } = r
      return signer.sign({ ...rest, timestampMs })
    }
    const trigger = hit && triggerRec ? resignTs(triggerRec, hit.injectedAtMs!)! : triggerRec
    const control = hit && controlRec ? resignTs(controlRec, hit.injectedAtMs! - 1) : controlRec
    const witness = hit ? signer.sign({ id: hit.id, timestampMs: hit.receivedAtMs, status: 200, surface: 'webhook' }) : undefined
    return evaluateUniversalPrimitive(primitive, { kind: 'oob_callback', trigger, witness: witness as HostSignedRecord, hostCanary: a.token, observedCanary: hit?.token ?? null, ...(control ? { control, controlObservedCanary: ctl ? a.token : null } : {}), verifySignature })
  }
  const a = args as PersistedMutationArgs, baselineReadback = roleRec(recs, 'baseline_read'), finalReadback = roleRec(recs, 'post_mutation_read')
  const decision = evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback, finalReadback, actions: recs.filter(r => r.role === 'mutation_probe').map(r => r.record), structuralOnly: true, verifySignature })
  const bindErr = decision.satisfied ? mutationBindingError(a, baselineReadback.json, finalReadback.json) : null
  return bindErr ? { ...decision, satisfied: false, reason: bindErr } : decision
}

/** Gate a receipt-confirmed execution through its Tier-1 primitive; a primitive denial is a fail-closed rejection. */
export function applyTier1Gate(recipeId: PersistedFloorRecipeId, args: PersistedFloorRecipeArgs, exec: FloorRecipeExecution): FloorRecipeExecution {
  const primitive = tier1PrimitiveForRecipe(recipeId, args.vulnClass)
  if (!primitive || !exec.result.confirmed) return exec
  const decision = tier1Decision(primitive, args, exec.result.transcript)
  if (decision.satisfied) return { ...exec, primitive: decision }
  const reason = `tier1_primitive_rejected: ${primitive} ${decision.reason}`
  return { ...exec, primitive: decision, result: { ...exec.result, confirmed: false, verification: { ...exec.result.verification, confirmed: false, reason } }, failure: { code: 'receipt_rejected', message: reason, missingRoles: ['tier1_primitive'] } }
}

export interface FloorRecipePlan {
  recipeId: PersistedFloorRecipeId
  /** Legacy spec kind this plan replaces (used for attribution and the no-fallback assertion). */
  specKind: string
  vulnClass: string
  endpoint: string
  args: PersistedFloorRecipeArgs
  /** Injection location of the parameter the recipe drives (record-spec metadata). */
  paramLocation?: string
  /** Machine-readable reason the plan could not be expressed, when `args` is absent. */
  skipReason?: string
}

export interface FloorRecipePlanInput {
  hypothesis: EngineHypothesis
  probe: DifferentialResult
  /** Legacy candidate kind/class the synthesizer would have emitted. */
  specKind: string
  vulnClass: string
  personas: readonly EnginePersona[]
  /** Run-scoped headers (staging tenant/run tag) applied to every recipe exchange. */
  headers?: Record<string, string>
  /** The synthesized legacy candidate, when the planner needs its request steps (browser specs). */
  candidateSpec?: Record<string, unknown>
}

const ANONYMOUS_HANDLE = 'anon'

function personaOf(handle: string | null | undefined, personas: readonly EnginePersona[]): EnginePersona | undefined {
  if (!handle) return undefined
  return personas.find(persona => persona.handle === handle)
}

/** Build the recipe actor for a persona handle (or the unauthenticated actor for a null handle). */
export function floorActorFor(handle: string | null | undefined, personas: readonly EnginePersona[]): FloorActor {
  if (!handle) return { handle: ANONYMOUS_HANDLE, role: null, tenant: null, auth: 'unknown' }
  const persona = personaOf(handle, personas)
  // R3-19: Typed persona privilege and tenant always take precedence over free-text role labels;
  // untyped legacy personas fall back to label parsing strictly inside `resolvePersonaIdentity`
  // where fallbacks are counted. Never allow `roleLabel` to override a typed `privilege`.
  //
  // Callers with opaque UI-style labels ('User A', 'Account 1') pass typed `tenant` and
  // `privilege` directly and incur zero label-fallback increments.
  const identity = resolvePersonaIdentity({
    roleLabel: persona?.roleLabel ?? null,
    tenantRef: persona?.tenant ?? null,
    privilege: persona?.privilege ?? null,
    handle,
  })
  return {
    handle,
    role: identity.privilege,
    tenant: identity.tenant,
    auth: 'cookie',
  }
}

// ---------------------------------------------------------------------------------------------
// Boolean / timing SQL injection
// ---------------------------------------------------------------------------------------------

type BooleanStyle = 'single' | 'double' | 'numeric' | 'or'

function booleanStyleOf(raw: unknown): BooleanStyle {
  const style = String(raw ?? '')
  if (style === 'double_quote' || style === 'double') return 'double'
  if (style === 'numeric') return 'numeric'
  if (style === 'or_branch' || style === 'or') return 'or'
  return 'single'
}

function booleanExpression(style: BooleanStyle, baseline: string, key: number, arm: 'true' | 'false'): string {
  const expr = arm === 'true' ? `${key}=${key}` : `${key}=${key + 1}`
  switch (style) {
    case 'numeric': return `${baseline} AND ${expr}`
    case 'double': return `${baseline}" AND ${expr}-- -`
    case 'or': return `${baseline}' OR ${expr}-- -`
    default: return `${baseline}' AND ${expr}-- -`
  }
}

/**
 * Build one arm of the boolean pair. The probe reports the exact operand and a single replay
 * template for the shape that passed; replaying that pair keeps the differential grounded in the
 * target's own data instead of a dev fixture literal that may not exist in this catalog. A template
 * is preferred because the proven shape may not be one of the four legacy style branches.
 */
function booleanArm(input: {
  template: string | null
  style: BooleanStyle
  baseline: string
  key: number
  arm: 'true' | 'false'
}): string {
  const expr = `${input.key}=${input.arm === 'true' ? input.key : input.key + 1}`
  if (input.template) {
    return input.template.replaceAll('{{baseline}}', input.baseline).replaceAll('{{sql_expr}}', expr)
  }
  return booleanExpression(input.style, input.baseline, input.key, input.arm)
}

function armOverrideOf(req: Pick<FloorRequestSpec, 'pathAndQuery' | 'jsonBody' | 'textBody' | 'headers'>) {
  if (req.textBody === undefined && !req.headers) return undefined
  return {
    pathAndQuery: req.pathAndQuery,
    ...(req.jsonBody !== undefined ? { jsonBody: req.jsonBody } : {}),
    ...(req.textBody !== undefined ? { textBody: req.textBody } : {}),
    ...(req.headers ? { headers: req.headers } : {}),
  }
}

function planBooleanRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const sketch: FloorRecipePlan = {
    recipeId: 'boolean_or_timing',
    specKind: input.specKind,
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  if (!hyp.param) return { ...sketch, skipReason: 'sqli hypothesis has no injected parameter' }
  const buildArgs = (
    mode: 'boolean' | 'timing',
    control: NonNullable<ReturnType<typeof requestFromInjection>>,
    probe: NonNullable<ReturnType<typeof requestFromInjection>>,
    extra: Partial<BooleanOrTimingArgs>,
  ): FloorRecipePlan => {
    const controlReq = armOverrideOf(control)
    const probeReq = armOverrideOf(probe)
    const args: BooleanOrTimingArgs = {
      mode,
      origin: hyp.endpoint.origin,
      method: probe.method,
      pathAndQuery: probe.pathAndQuery,
      controlPathAndQuery: control.pathAndQuery,
      probePathAndQuery: probe.pathAndQuery,
      param: hyp.param!.name,
      vulnClass: 'sqli',
      actor: floorActorFor(hyp.ownerPersona ?? null, input.personas),
      ...(control.jsonBody !== undefined ? { controlJsonBody: control.jsonBody } : {}),
      ...(probe.jsonBody !== undefined ? { probeJsonBody: probe.jsonBody } : {}),
      ...(controlReq ? { controlRequest: controlReq } : {}),
      ...(probeReq ? { probeRequest: probeReq } : {}),
      ...(input.headers ?? hyp.headers ? { headers: { ...(hyp.headers ?? {}), ...(input.headers ?? {}) } } : {}),
      ...extra,
    }
    return { ...sketch, args, paramLocation: hyp.location ?? hyp.param!.location }
  }
  const timingHit = input.probe.anomalies.find(anomaly => anomaly.type === 'sql_time_differential')
  if (timingHit) {
    const baseline = hyp.baselineValue ?? (typeof timingHit.baselineValue === 'string' ? timingHit.baselineValue : '1')
    const dialectRaw = String(timingHit.dialect ?? '')
    const dialect = ['mysql', 'postgres', 'sqlite', 'mssql'].includes(dialectRaw) ? dialectRaw : 'postgres'
    const delayMs = Math.max(1500, Math.min(3000, Number(timingHit.delayMs) || 2500))
    const seconds = (delayMs / 1000).toFixed(2)
    const probeValue = dialect === 'mysql'
      ? `${baseline}' AND SLEEP(${seconds})-- -`
      : dialect === 'postgres'
        ? `${baseline}' AND (SELECT 1 FROM pg_sleep(${seconds})) IS NULL-- -`
        : dialect === 'mssql'
          ? `${baseline}'; WAITFOR DELAY '0:0:${Math.max(1, Math.round(delayMs / 1000))}'-- -`
          : `${baseline}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${delayMs * 25_000}))))-- -`
    const control = requestFromInjection({ hyp, value: baseline })
    const probe = requestFromInjection({ hyp, value: probeValue })
    if (!control || !probe) return { ...sketch, skipReason: 'sqli timing injection point could not be expressed as a recipe request' }
    return buildArgs('timing', control, probe, { receiptClass: 'blind_sqli', baselineValue: baseline, quoteStyle: 'single' })
  }
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'boolean_differential')
  const baseline = (typeof hit?.baselineValue === 'string' ? hit.baselineValue : null) ?? hyp.baselineValue ?? '1'
  const key = 7_919
  const style = booleanStyleOf(hit?.style)
  const rawTemplate = typeof hit?.valueTemplate === 'string' && hit.valueTemplate.includes('{{sql_expr}}') ? hit.valueTemplate : null
  const rawQuote = typeof hit?.quoteStyle === 'string' ? hit.quoteStyle : ''
  const quoteStyle: 'single' | 'double' | 'numeric' = rawQuote === 'double' || rawQuote === 'numeric' ? rawQuote : 'single'
  const control = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'true' }) })
  const probe = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'false' }) })
  if (!control || !probe) return { ...sketch, skipReason: 'sqli injection point could not be expressed as a recipe request' }
  return buildArgs('boolean', control, probe, {
    rounds: 2,
    baselineValue: baseline,
    quoteStyle,
    ...(rawTemplate ? { valueTemplate: rawTemplate } : {}),
  })
}

// ---------------------------------------------------------------------------------------------
// Race burst
// ---------------------------------------------------------------------------------------------

function planRaceRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'race_double_spend')
  const sketch: FloorRecipePlan = {
    recipeId: 'conserved_balance',
    specKind: input.specKind,
    vulnClass: 'race_double_spend',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as ConservedBalanceArgs,
  }
  if (!hit) return { ...sketch, skipReason: 'no race_double_spend evidence on the probe result' }
  const amountField = isSafeFieldName(hit.amountField) ? hit.amountField : ''
  const balanceField = isSafeFieldName(hit.balanceField) ? hit.balanceField : undefined
  const amount = Number(hit.amount)
  const burst = Number(hit.burstSize)
  if (!amountField || !Number.isFinite(amount) || amount <= 0) {
    return { ...sketch, skipReason: 'race evidence did not name a positive amount field' }
  }
  if (!Number.isFinite(burst) || burst < 2 || burst > 10) {
    return { ...sketch, skipReason: 'race evidence did not name a usable burst size' }
  }
  const raceOrigin = typeof hit.raceOrigin === 'string' && /^https?:\/\//.test(hit.raceOrigin)
    ? hit.raceOrigin
    : hyp.endpoint.origin
  const path = typeof hit.path === 'string' && hit.path.startsWith('/')
    ? hit.path.split('?')[0]!
    : hyp.pathAndQuery.split('?')[0]!
  const idempotencyKey = typeof hit.idempotencyKey === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(hit.idempotencyKey)
    ? hit.idempotencyKey
    : null
  const bodyFor = (value: number): Record<string, unknown> => ({
    [amountField]: value,
    ...(idempotencyKey ? { idempotencyKey } : {}),
  })
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const actor = floorActorFor(hyp.ownerPersona ?? null, input.personas)
  const args: ConservedBalanceArgs = {
    origin: raceOrigin,
    method: 'POST',
    pathAndQuery: path,
    vulnClass: 'race_double_spend',
    actor,
    body: bodyFor(amount),
    burst: Math.min(8, Math.trunc(burst)),
    readback: {
      method: 'POST',
      pathAndQuery: path,
      jsonBody: bodyFor(0),
      actor,
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
    },
    ...(balanceField ? { balanceField } : {}),
    unitDebit: amount,
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args }
}

// ---------------------------------------------------------------------------------------------
// Object-level / function-level authorization
// ---------------------------------------------------------------------------------------------

function resourceIdOf(input: FloorRecipePlanInput): string | null {
  const matrix = Array.isArray(input.probe.details.matrix)
    ? input.probe.details.matrix as Array<Record<string, unknown>>
    : null
  const ownerBytes = (id: string): number => {
    if (!matrix) return 0
    let best = 0
    for (const row of matrix) {
      if (String(row.resourceId ?? '') !== id || String(row.actor ?? '') !== 'owner' || row.accessible !== true) continue
      const status = typeof row.status === 'number' ? row.status : 0
      if (status < 200 || status >= 300) continue
      const bytes = typeof row.bodyBytes === 'number' ? row.bodyBytes : 0
      if (bytes > best) best = bytes
    }
    return best
  }
  const candidates = input.probe.anomalies
    .filter(anomaly => anomaly.type === 'unauthorized_access' &&
      String(anomaly.method ?? 'GET').toUpperCase() === input.hypothesis.method &&
      isSafeResourceId(anomaly.resourceId))
    .map(anomaly => anomaly.resourceId as string)
  if (candidates.length > 0) {
    let best = candidates[0]!
    let bestBytes = ownerBytes(best)
    for (const candidate of candidates.slice(1)) {
      const bytes = ownerBytes(candidate)
      if (bytes > bestBytes) { best = candidate; bestBytes = bytes }
    }
    return best
  }
  return input.hypothesis.resourceIds?.find(isSafeResourceId) ?? null
}

function authzReadbackPath(input: FloorRecipePlanInput, id: string | null, functionLevel: boolean): string | null {
  const resolved = resolveAuthzReadbackTemplate(input.hypothesis, functionLevel)
  if (!resolved) return null
  if (!functionLevel && !id) return null
  return id ? fillResourceId(resolved.template, id) : resolved.template
}

function authzBodyOf(input: FloorRecipePlanInput): Record<string, unknown> | null {
  const hyp = input.hypothesis
  if (hyp.functionState?.body) return hyp.functionState.body
  const hits = input.probe.anomalies.filter(anomaly =>
    anomaly.type === 'unauthorized_access' &&
    anomaly.bodyTemplate !== undefined && anomaly.bodyTemplate !== null &&
    typeof anomaly.bodyTemplate === 'object' && !Array.isArray(anomaly.bodyTemplate))
  const hit = hits.find(anomaly => String(anomaly.method ?? 'GET').toUpperCase() === hyp.method) ?? hits[0]
  if (hit?.bodyTemplate) return hit.bodyTemplate as Record<string, unknown>
  return hyp.jsonBody ?? null
}

function selectLowerRoleDeniedPeer(
  owner: FloorActor,
  probe: FloorActor,
  personas: readonly EnginePersona[],
): FloorActor | null {
  const ownerRank = rolePrivilegeRank(owner.role)
  const candidates = personas
    .filter(p => p.handle !== owner.handle && p.handle !== probe.handle)
    .map(p => floorActorFor(p.handle, personas))
    .filter(actor => {
      const rank = rolePrivilegeRank(actor.role)
      if (ownerRank !== null && rank !== null) return rank < ownerRank
      return actor.role !== owner.role || actor.tenant !== owner.tenant
    })
  if (candidates.length === 0) return null
  candidates.sort((a, b) => (rolePrivilegeRank(a.role) ?? 0) - (rolePrivilegeRank(b.role) ?? 0))
  return candidates[0]!
}

function planAuthzRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const recipeId: FloorRecipeId = hyp.method === 'GET' ? 'access_boundary' : 'persisted_mutation'
  const vulnClass = hyp.functionLevel ? 'bfla' : 'bola'
  const sketch: FloorRecipePlan = {
    recipeId,
    specKind: input.specKind,
    vulnClass,
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  const ownerHandle = hyp.ownerPersona
  const probeHandle = hyp.otherPersona
  if (!ownerHandle || !probeHandle) return { ...sketch, skipReason: 'authz hypothesis has no owner/probe persona pair' }
  const id = resourceIdOf(input)
  const functionLevel = hyp.functionLevel === true
  if (!functionLevel && !id) return { ...sketch, skipReason: 'object-level authz hypothesis has no usable resource identifier' }
  const privileged = PRIVILEGED_ACTION_RE.test(hyp.pathAndQuery.split('?')[0]!)
  // A destructive probe matrix consumes the identifiers it exercises. The engine reserves one live
  // victim for the replay when a privileged delete needs an observable removal; reuse it so the
  // pre-read, mutation and post-read all address a real object.
  const reserved = hyp.method === 'DELETE' && !functionLevel && privileged && hyp.reservedVictimId
    ? hyp.reservedVictimId
    : null
  const resolvedId = reserved && isSafeResourceId(reserved) ? reserved : id
  const realPath = resolvedId ? fillResourceId(hyp.pathAndQuery, resolvedId) : hyp.pathAndQuery
  const owner = floorActorFor(ownerHandle, input.personas)
  const probe = floorActorFor(probeHandle, input.personas)
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }

  if (hyp.method === 'GET') {
    // The legacy read proof is an entitled read plus a cross-actor read, with an authenticated
    // bogus-id control where the route only denies nonexistent identifiers. For same-path / BFLA
    // reads (H-17), never reuse `owner` as the denied control arm — require a distinct lower-role peer.
    const deniedPath = id && !functionLevel ? fillResourceId(hyp.pathAndQuery, bogusIdFor(id)) : realPath
    const samePath = deniedPath === realPath
    let deniedActor: FloorActor
    if (samePath) {
      const peer = selectLowerRoleDeniedPeer(owner, probe, input.personas)
      if (!peer) {
        return {
          ...sketch,
          skipReason: 'function-level authz read requires a distinct lower-role peer persona for the denied control arm',
        }
      }
      deniedActor = peer
    } else {
      deniedActor = owner
    }
    const idInPath = /\/\{\{id\}\}(?:\/|$|\?)/.test(hyp.pathAndQuery) || /\/:\w+(?:\/|$|\?)/.test(hyp.pathAndQuery)
    const args: AccessBoundaryArgs = {
      origin: hyp.endpoint.origin,
      method: 'GET',
      pathAndQuery: realPath,
      vulnClass,
      owner,
      probe,
      denied: deniedActor,
      ...(deniedPath !== realPath ? { deniedPathAndQuery: deniedPath } : {}),
      ...(!idInPath && !functionLevel ? { controlEvidence: 'denial_or_distinct' as const } : {}),
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
    }
    return { ...sketch, args, paramLocation: 'path' }
  }

  // A mutation proves impact only through a separate readback. The legacy shape needs both a
  // pre-mutation readback and a post-mutation delta, plus a control that keeps the delta
  // attributable (a fresh baseline write, or a reset for self-service session state).
  const body = authzBodyOf(input)
  if (!body) return { ...sketch, skipReason: 'authz mutation hypothesis has no request body template' }
  const readbackPath = authzReadbackPath(input, resolvedId, functionLevel)
  if (!readbackPath) return { ...sketch, skipReason: 'authz mutation hypothesis has no separate readback route' }
  const readbackActor = floorActorFor(hyp.readbackPersona ?? ownerHandle, input.personas)
  const selfState = Boolean(hyp.functionState?.bindings?.length)
  const baselineWrite = !functionLevel && !selfState && hyp.method !== 'DELETE' ? pickBaselineWrite(body) : null
  const resetBody = hyp.functionState?.reset?.length
    ? { ...body, ...Object.fromEntries(hyp.functionState.reset.map(item => [item.field, item.value])) }
    : null
  const args: PersistedMutationArgs = {
    origin: hyp.endpoint.origin,
    method: hyp.method,
    pathAndQuery: realPath,
    vulnClass,
    actor: probe,
    body,
    baselineMethod: 'GET',
    baselinePathAndQuery: readbackPath,
    readbackMethod: 'GET',
    readbackPathAndQuery: readbackPath,
    readbackActor,
    ...(baselineWrite
      ? {
          baselineWrite: {
            body: baselineWrite.baselineBody,
            actor: owner,
            method: hyp.method,
            field: baselineWrite.field,
            restoreOriginal: true,
          },
        }
      : {}),
    ...(resetBody ? { reset: { body: resetBody, actor: probe, method: hyp.method } } : {}),
    ...(hyp.authzRequiredRole ? { requiredRole: hyp.authzRequiredRole } : {}),
    ...(functionLevel && privileged && hyp.authzRequiredRole ? { oracleEvents: ['privilege_escalation'] } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args, paramLocation: 'path' }
}

// ---------------------------------------------------------------------------------------------
// Planning entrypoint
// ---------------------------------------------------------------------------------------------

/**
 * Resolve a wired recipe plan for one legacy candidate, or null when the pair is not wired. A wired
 * pair that cannot be expressed returns a plan with `skipReason` so the engine records a named
 * rejection instead of silently taking the legacy path.
 */
function planBrowserRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const sketch: FloorRecipePlan = {
    recipeId: 'browser_sink',
    specKind: input.specKind,
    vulnClass: input.vulnClass || 'dom_xss',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  const spec = input.candidateSpec
  let steps = Array.isArray(spec?.steps) ? spec!.steps as Array<Record<string, unknown>> : null
  if (!steps || steps.length === 0) {
    // Direct floor-recipe planning for reflected xss_context without throwaway browser_chain jq synthesis.
    const hit = input.probe.anomalies.find(a => a.type === 'xss_context')
    const context = String(hit?.context ?? 'html_body')
    const chars = Array.isArray(hit?.unencodedChars) ? hit!.unencodedChars.map(String) : []
    if (!hit || !hyp.param || hyp.location !== 'query' || context !== 'html_body' || !chars.includes('<') || !chars.includes('"')) {
      return { ...sketch, skipReason: 'browser spec carried no steps to replay' }
    }
    const sep = hyp.pathAndQuery.includes('?') ? '&' : '?'
    const key = encodeURIComponent(hyp.param.name)
    const controlPath = `${hyp.pathAndQuery}${sep}${key}=kovo`
    const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
    const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
    const probePath = `${hyp.pathAndQuery}${sep}${key}=${encodedPayload}`
    const persona = hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}
    steps = [
      { id: 'c1', role: 'control', origin: hyp.endpoint.origin, ...persona, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
      { id: 'p1', role: 'probe', origin: hyp.endpoint.origin, ...persona, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
    ]
  }
  if (isProtocolBrowserSpec(steps)) return { ...sketch, skipReason: 'protocol browser proof (postMessage/fetch/builtin) stays on the framework verifier' }
  const origin = typeof steps[0]?.origin === 'string' ? String(steps[0].origin) : hyp.endpoint.origin
  const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps })
  if (!envelope) return { ...sketch, skipReason: 'browser spec steps could not be expressed as a browser_sink recipe' }
  return { ...sketch, vulnClass: input.vulnClass || envelope.args.vulnClass, args: envelope.args }
}

type CandidateStepView = { role?: string; request?: { method?: string; pathAndQuery?: string; persona?: string; jsonBody?: unknown; textBody?: string; headers?: Record<string, string>; session?: string; csrfBind?: boolean } }
const candidateStepsOf = (spec?: Record<string, unknown>): CandidateStepView[] => Array.isArray(spec?.steps) ? spec.steps as CandidateStepView[] : []
const isPlainRecord = (v: unknown): v is Record<string, unknown> => Boolean(v && typeof v === 'object' && !Array.isArray(v))

function planPersistedMutationRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis, sketch: FloorRecipePlan = { recipeId: 'persisted_mutation', specKind: input.specKind, vulnClass: input.vulnClass, endpoint: hyp.endpoint.pathTemplate, args: {} as FloorRecipeArgs }
  const steps = candidateStepsOf(input.candidateSpec), probeStep = steps.find(s => s.role === 'probe')?.request
  const ctrlWrite = steps.find(s => s.role === 'control' && s.request?.method && s.request.method.toUpperCase() !== 'GET')?.request
  const readStep = steps.find(s => s.request?.method?.toUpperCase() === 'GET' && s.role !== 'setup')?.request
  const primeStep = steps.find(s => s.role === 'setup' && s.request?.method?.toUpperCase() === 'GET')?.request
  const body = isPlainRecord(probeStep?.jsonBody) ? probeStep.jsonBody : authzBodyOf(input)
  if (!body || Object.keys(body).length === 0) return { ...sketch, skipReason: `${input.vulnClass} persisted_mutation requires a mutating JSON body` }
  const id = resourceIdOf(input), realPath = probeStep?.pathAndQuery ?? (id ? fillResourceId(hyp.pathAndQuery, id) : hyp.pathAndQuery)
  const readbackPath = readStep?.pathAndQuery ?? authzReadbackPath(input, id, false) ?? (hyp.method !== 'GET' ? realPath : null)
  if (!readbackPath) return { ...sketch, skipReason: `${input.vulnClass} persisted_mutation requires a separate readback route` }
  const actor = floorActorFor(probeStep?.persona ?? hyp.otherPersona ?? hyp.ownerPersona, input.personas)
  const readbackActor = floorActorFor(readStep?.persona ?? hyp.readbackPersona ?? hyp.ownerPersona ?? hyp.otherPersona, input.personas)
  const baselinePicked = isPlainRecord(ctrlWrite?.jsonBody) ? { body: ctrlWrite.jsonBody, actor: floorActorFor(ctrlWrite.persona ?? hyp.ownerPersona, input.personas), method: ctrlWrite.method ?? hyp.method, ...(ctrlWrite.csrfBind ? { csrfBind: true } : {}), restoreOriginal: true }
    : (() => { const p = pickBaselineWrite(body); return p ? { body: p.baselineBody, actor: readbackActor, method: hyp.method, field: p.field, restoreOriginal: true } : undefined })()
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const session = probeStep?.session ?? ctrlWrite?.session
  const args: PersistedMutationArgs = {
    origin: hyp.endpoint.origin, method: probeStep?.method ?? hyp.method, pathAndQuery: realPath, vulnClass: input.vulnClass, actor, body,
    baselineMethod: 'GET', baselinePathAndQuery: readbackPath, readbackMethod: 'GET', readbackPathAndQuery: readbackPath, readbackActor,
    ...(baselinePicked ? { baselineWrite: baselinePicked } : {}), ...(session ? { session } : {}), ...(primeStep?.pathAndQuery ? { primePath: primeStep.pathAndQuery } : {}),
    ...(probeStep?.headers ? { probeHeaders: probeStep.headers } : {}), ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args, paramLocation: 'json' }
}

function planDisclosureRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis, sketch: FloorRecipePlan = { recipeId: 'disclosure', specKind: input.specKind, vulnClass: input.vulnClass, endpoint: hyp.endpoint.pathTemplate, args: {} as FloorRecipeArgs }
  const ownerHandle = hyp.ownerPersona, probeHandle = hyp.otherPersona
  if (!ownerHandle || !probeHandle || ownerHandle === probeHandle) return { ...sketch, skipReason: 'disclosure requires distinct authenticated owner and probe personas' }
  const owner = floorActorFor(ownerHandle, input.personas), probe = floorActorFor(probeHandle, input.personas)
  const probeRank = rolePrivilegeRank(probe.role)
  const peerAllowed = (peer: FloorActor): boolean => {
    const rank = rolePrivilegeRank(peer.role)
    const sameScope = (peer.tenant && probe.tenant && peer.tenant === probe.tenant) || (!peer.tenant && !probe.tenant) || (owner.tenant && probe.tenant && owner.tenant === probe.tenant)
    return !(sameScope && rank !== null && probeRank !== null && rank < probeRank)
  }
  const peers = input.personas.filter(p => p.handle !== owner.handle && p.handle !== probe.handle).map(p => floorActorFor(p.handle, input.personas)).filter(peerAllowed)
  const lower = selectLowerRoleDeniedPeer(owner, probe, input.personas)
  const denied = (lower && peerAllowed(lower) ? lower : undefined) ?? peers[0]
  if (!denied || denied.handle === ANONYMOUS_HANDLE) return { ...sketch, skipReason: 'disclosure requires an authenticated non-lower-role peer persona for the denied control arm' }
  const id = resourceIdOf(input), realPath = id ? fillResourceId(hyp.pathAndQuery, id) : hyp.pathAndQuery
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const args: DisclosureArgs = {
    origin: hyp.endpoint.origin, method: hyp.method || 'GET', pathAndQuery: realPath, vulnClass: input.vulnClass,
    owner, probe, denied, ...(hyp.readbackPath ? { baselinePathAndQuery: hyp.readbackPath } : {}), ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args, paramLocation: 'path' }
}

function planOobCallbackRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis, sketch: FloorRecipePlan = { recipeId: 'oob_callback', specKind: input.specKind, vulnClass: input.vulnClass, endpoint: hyp.endpoint.pathTemplate, args: {} as FloorRecipeArgs }
  const steps = candidateStepsOf(input.candidateSpec), probeStep = steps.find(s => s.role === 'probe')?.request, ctrlStep = steps.find(s => s.role === 'control')?.request
  const hit = input.probe.anomalies.find(a => typeof (a.canaryToken ?? a.token ?? a.canaryId) === 'string')
  const token = String(hit?.canaryToken ?? hit?.token ?? hit?.canaryId ?? '').trim()
  if (token.length < 8) return { ...sketch, skipReason: `${input.vulnClass} oob_callback requires a host-minted canary token` }
  const controlToken = typeof hit?.controlToken === 'string' && hit.controlToken.trim().length >= 8 ? hit.controlToken.trim() : undefined
  if (!controlToken) return { ...sketch, skipReason: `${input.vulnClass} oob_callback requires a benign control canary token` }
  const actor = floorActorFor(probeStep?.persona ?? hyp.ownerPersona, input.personas)
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const args: OobCallbackArgs = {
    origin: hyp.endpoint.origin, method: probeStep?.method ?? hyp.method, pathAndQuery: probeStep?.pathAndQuery ?? hyp.pathAndQuery, vulnClass: input.vulnClass, token, actor,
    ...(probeStep?.jsonBody !== undefined ? { injectJsonBody: probeStep.jsonBody } : {}), ...(probeStep?.textBody !== undefined ? { injectTextBody: probeStep.textBody } : {}), ...(probeStep?.headers ? { injectHeaders: probeStep.headers } : {}),
    controlToken, ...(ctrlStep?.pathAndQuery ? { controlPathAndQuery: ctrlStep.pathAndQuery } : {}), ...(ctrlStep?.jsonBody !== undefined ? { controlJsonBody: ctrlStep.jsonBody } : {}), ...(ctrlStep?.textBody !== undefined ? { controlTextBody: ctrlStep.textBody } : {}), ...(ctrlStep?.headers ? { controlHeaders: ctrlStep.headers } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args }
}

function planInjectionFingerprintRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const sketch: FloorRecipePlan = {
    recipeId: 'injection_fingerprint',
    specKind: input.specKind,
    vulnClass: input.vulnClass,
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'db_error_fingerprint')
  if (!hit || !hyp.param) return { ...sketch, skipReason: 'error-based injection signal has no injected parameter' }
  const details = input.probe.details as Record<string, unknown>
  const baseline = typeof details.baselineValue === 'string' ? details.baselineValue : (hyp.baselineValue ?? '1')
  const payload = `${baseline}'`
  const control = requestFromInjection({ hyp, value: baseline })
  const probeReq = requestFromInjection({ hyp, value: payload })
  if (!control || !probeReq) return { ...sketch, skipReason: 'error-based injection point could not be expressed as a recipe request' }
  const actor = floorActorFor(hyp.ownerPersona ?? null, input.personas)
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const args: InjectionFingerprintArgs = {
    origin: hyp.endpoint.origin,
    method: probeReq.method,
    pathAndQuery: probeReq.pathAndQuery,
    vulnClass: 'injection',
    param: hyp.param.name,
    payload,
    controlValue: baseline,
    family: 'sqli',
    actor,
    ...(probeReq.jsonBody !== undefined ? { jsonBody: probeReq.jsonBody } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args, paramLocation: hyp.location ?? hyp.param.location }
}

export function planFloorRecipe(input: FloorRecipePlanInput): FloorRecipePlan | null {
  const recipe = wiredRecipeForSpecKind(input.specKind, input.vulnClass)
  if (!recipe) return null
  switch (recipe) {
    case 'boolean_or_timing': return planBooleanRecipe(input)
    case 'race_burst':
    case 'conserved_balance': return planRaceRecipe(input)
    case 'browser_sink': return planBrowserRecipe(input)
    case 'access_boundary': return planAuthzRecipe(input)
    case 'persisted_mutation': return TIER1_MUTATION_CLASSES.has(input.vulnClass) ? planPersistedMutationRecipe(input) : planAuthzRecipe(input)
    case 'disclosure': return planDisclosureRecipe(input)
    case 'oob_callback': return planOobCallbackRecipe(input)
    case 'injection_fingerprint': return planInjectionFingerprintRecipe(input)
    default: return {
      recipeId: recipe,
      specKind: input.specKind,
      vulnClass: input.vulnClass,
      endpoint: input.hypothesis.endpoint.pathTemplate,
      args: {} as FloorRecipeArgs,
      skipReason: `${recipe} is wired but has no planner for ${input.specKind}/${input.vulnClass}`,
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Candidate enumeration: typed recipes and zero-jq runners (no legacy synthesizer / jq VM)
// ---------------------------------------------------------------------------------------------

/**
 * One confirmable candidate for a signaled floor hypothesis.
 *
 * - `recipe` — a wired legacy kind/class pair resolved to a typed floor recipe (Track A2 Tier-1
 *   primitive + ProofReceipt owns the verdict).
 * - `spec` — a zero-jq typed runner shape (`rce_proof`, `auth_protocol_proof`) whose declarative
 *   spec is built directly from the hypothesis and probe evidence.
 *
 * Anything else (a class with no wired recipe and no zero-jq runner) is deliberately not emitted:
 * the engine records a structured `spec_skipped` note instead of falling back to the retired jq VM.
 */
export type FloorCandidate =
  | { mode: 'recipe'; plan: FloorRecipePlan }
  | { mode: 'spec'; specRecord: SynthesizedEngineSpec }

export type FloorCandidatePlanInput = Omit<FloorRecipePlanInput, 'specKind' | 'vulnClass'>

/**
 * Enumerate the confirmable candidates for a signaled probe: wired typed recipes first, then
 * zero-jq typed runners. Replaces the deleted `deterministic-specs.ts` synthesizer; every emitted
 * candidate is either a Track A2 Tier-1 recipe or a typed runner that never executes jq.
 */
export function planFloorCandidates(input: FloorCandidatePlanInput): FloorCandidate[] {
  if (input.probe.verdict !== 'signal') return []
  const anomalyPairs = anomalyCandidatePairs(input.probe)
  const pairs = anomalyPairs.length > 0 ? anomalyPairs : probeClassCandidatePairs(input.hypothesis, input.probe)
  const candidates: FloorCandidate[] = []
  for (const pair of pairs) {
    if (wiredRecipeForSpecKind(pair.specKind, pair.vulnClass)) {
      const plan = planFloorRecipe({ ...input, specKind: pair.specKind, vulnClass: pair.vulnClass })
      if (plan) candidates.push({ mode: 'recipe', plan })
      continue
    }
    const specRecord = buildTypedRunnerCandidate(pair, input.hypothesis, input.probe)
    if (specRecord) candidates.push({ mode: 'spec', specRecord })
  }
  return candidates
}

// ---------------------------------------------------------------------------------------------
// Recipe execution through the broker
// ---------------------------------------------------------------------------------------------

/**
 * Host seam for browser recipes: run an ordered navigate/fill/click session through the same
 * `ScopedBrowser` the framework verifier uses and return only the traces whose canary reached an
 * executable sink. The recipe still owns the confirmation rule; this only records evidence.
 */
export function browserSessionSeam(input: {
  browser: ScopedBrowser
  grant: Grant
  signal: AbortSignal
  origin: string
  runId?: string
  assignmentId?: string
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
}): NonNullable<FloorRecipeDeps['browserSession']> {
  return async session => {
    if (typeof input.browser.runBrowserSession !== 'function') return null
    const defaultPersona = session.actor?.handle &&
      session.actor.handle !== 'anonymous' &&
      session.actor.handle !== ANONYMOUS_HANDLE
      ? session.actor.handle
      : undefined
    const sessionSteps: BrowserSessionStep[] = session.steps.map((step, index) => {
      const persona = step.persona ?? defaultPersona
      return {
        id: `b${index + 1}`,
        role: step.role,
        origin: input.origin,
        ...(step.pathAndQuery !== undefined ? { pathAndQuery: step.pathAndQuery } : {}),
        ...(step.reusePage ? { reusePage: true } : {}),
        ...(persona ? { persona } : {}),
        action: step.action,
        ...(step.selector !== undefined ? { selector: step.selector } : {}),
        ...(step.value !== undefined ? { value: step.value } : {}),
        ...(step.waitAfterLoadMs !== undefined ? { waitAfterLoadMs: step.waitAfterLoadMs } : {}),
        canaryToken: session.canaryToken,
        checkKind: 'dom_xss' as const,
        enableSinkHook: true,
        ...(input.runId ? { runId: input.runId } : {}),
        ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
        ...(input.recordExchange ? { onExchange: input.recordExchange } : {}),
      }
    })
    const visits = await input.browser.runBrowserSession(sessionSteps, input.grant, input.signal)
    const traces: Array<{ id: string; origin: string; sinks: string[] }> = []
    let sinkHit = false
    visits.forEach((visit, index) => {
      if (!visit) return
      const hits = visit.domSinkTraces.filter(trace => trace.containsCanary)
      // A sink trace proves only that a canary-bearing value reached a setter; the value itself may
      // be inert. Likewise, the driver's generic canary flag also fires for a surviving marker
      // attribute. Require an execution effect: the verifier-owned window flag, or a title change
      // that was not already rendered by the server.
      const globalFlag = visit.canaryCheck.triggered === true &&
        visit.canaryCheck.token === session.canaryToken &&
        visit.canaryCheck.detail === 'DOM execution canary flag observed on window.'
      const serverRenderedTitle = (visit.exchanges ?? []).some(exchange =>
        [...String(exchange.body ?? '').matchAll(/<title\b[^>]*>([\s\S]*?)<\/title>/gi)]
          .some(match => match[1]!.trim() === session.canaryToken))
      const titleHit = visit.title === session.canaryToken && !serverRenderedTitle
      if (!globalFlag && !titleHit) return
      sinkHit = true
      const sinks = [
        ...new Set(hits.map(trace => `dom_xss:${trace.sink}`)),
        ...(titleHit ? ['canary:title'] : []),
        ...(globalFlag ? ['canary:executed'] : []),
      ]
      traces.push({
        id: `browser-${index + 1}`,
        origin: input.origin,
        sinks,
      })
    })
    return { traces, sinkHit }
  }
}

const parseCanaryHitMs = (hit: { timestamp?: unknown }): number => typeof hit.timestamp === 'number' ? hit.timestamp : Date.parse(String(hit.timestamp ?? ''))

function replaceTokenDeep<T>(value: T, from: string, to: string): T {
  if (!from || from === to) return value
  if (typeof value === 'string') return value.replaceAll(from, to) as T
  if (Array.isArray(value)) return value.map(item => replaceTokenDeep(item, from, to)) as T
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, replaceTokenDeep(v, from, to)])) as T
  return value
}

/** Host canary relay seam for `oob_callback` floor recipes (never reads HTTP response reflection or stale pre-injection hits). */
export function oobCanarySeam(input: { canaryBroker: Pick<CanaryBroker, 'checkCanary'>; origin: string; signal?: AbortSignal; storage?: Store; runId?: string; injectedAtMs?: number }): NonNullable<FloorRecipeDeps['oob']> {
  const seamCreatedAtMs = Date.now()
  return async ({ token, injectedAtMs }) => {
    input.signal?.throwIfAborted()
    const opts = input.storage || input.runId ? { ...(input.storage ? { storage: input.storage } : {}), ...(input.runId ? { runId: input.runId } : {}) } : undefined
    const check = input.canaryBroker.checkCanary(token, opts)
    if (!check?.triggered) return null
    const minTs = injectedAtMs ?? input.injectedAtMs ?? seamCreatedAtMs
    const hits = Array.isArray(check.hits) ? check.hits : []
    const qualifying = hits.map(parseCanaryHitMs).filter(ts => Number.isFinite(ts) && ts >= minTs)
    if (qualifying.length === 0) return null
    const receivedAtMs = Math.min(...qualifying)
    return { id: `oob-${token.slice(0, 12)}`, callbackId: `oob:${token.slice(0, 16)}`, token, targetOrigin: input.origin, delivered: true, stage: 'immediate', receivedAtMs, injectedAtMs: minTs }
  }
}

export interface RunPlannedRecipeInput {
  plan: FloorRecipePlan
  hypothesis: EngineHypothesis
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  runId?: string
  headers?: Record<string, string>
  /** Scoped browser used by browser recipes; omitted by callers that never plan one. */
  browser?: ScopedBrowser
  /** Host canary relay used by `oob_callback` recipes. */
  canaryBroker?: CanaryBroker
  storage?: Store
  oob?: FloorRecipeDeps['oob']
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
}

/** Run a plan through the broker-backed Layer-1 adapter. Never falls back to the legacy verifier. */
export async function runPlannedRecipe(input: RunPlannedRecipeInput): Promise<FloorRecipeExecution> {
  if (input.plan.recipeId === 'boolean_or_timing' &&
      (input.plan.args as BooleanOrTimingArgs).mode === 'timing' && (input.grant.tier ?? 1) < 3) {
    input.grant.audit('denied', input.plan.args.origin || input.hypothesis.endpoint.origin)
    throw new BrokerDenied('Timing differential recipes require Tier 3 verification scope.')
  }
  const targetOrigin = input.plan.args.origin || input.hypothesis.endpoint.origin
  const runId = (input.runId ?? '').trim() || `floor_ephemeral_${randomUUID()}`
  let args = input.plan.args
  if (input.plan.recipeId === 'oob_callback' && input.canaryBroker && !input.oob && typeof input.canaryBroker.mintCanary === 'function') {
    const oobArgs = args as OobCallbackArgs
    const freshProbe = input.canaryBroker.mintCanary(runId, `floor_oob_probe:${input.plan.vulnClass}`, undefined, { ...(input.storage ? { storage: input.storage } : {}), ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}) })
    let updated = replaceTokenDeep(oobArgs, oobArgs.token, freshProbe.token)
    if (oobArgs.controlToken) {
      const freshCtrl = input.canaryBroker.mintCanary(runId, `floor_oob_control:${input.plan.vulnClass}`, undefined, { ...(input.storage ? { storage: input.storage } : {}), ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}) })
      updated = replaceTokenDeep(updated, oobArgs.controlToken, freshCtrl.token)
    }
    args = updated
  }
  const oob = input.oob ?? (input.plan.recipeId === 'oob_callback' && input.canaryBroker ? oobCanarySeam({ canaryBroker: input.canaryBroker, origin: targetOrigin, signal: input.signal, ...(input.storage ? { storage: input.storage } : {}), runId }) : undefined)
  const deps = brokerFloorRecipeDeps({
    broker: input.broker,
    grant: input.grant,
    signal: input.signal,
    origin: targetOrigin,
    probeClass: input.hypothesis.probeClass,
    runId,
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
    ...(input.headers ? { headers: input.headers } : {}),
    ...(oob ? { oob } : {}),
    ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
  })
  const browser = input.browser ?? new ScopedBrowser(input.broker)
  const withBrowser: FloorRecipeDeps = input.plan.recipeId === 'browser_sink'
    ? {
        ...deps,
        browserSession: browserSessionSeam({
          browser,
          grant: input.grant,
          signal: input.signal,
          origin: input.plan.args.origin || input.hypothesis.endpoint.origin,
          ...(input.runId ? { runId: input.runId } : {}),
          ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
          ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
        }),
      }
    : deps
  return executeFloorRecipeById(input.plan.recipeId, args, withBrowser)
}

// ---------------------------------------------------------------------------------------------
// Persisted record spec + verification result
// ---------------------------------------------------------------------------------------------

export const SEVERITY_BY_CLASS: Readonly<Record<string, Severity>> = {
  bola: 'high',
  idor: 'high',
  bfla: 'high',
  cross_tenant_read: 'high',
  cross_tenant_write: 'critical',
  mass_assignment: 'high',
  workflow_bypass: 'high',
  business_logic: 'high',
  price_tampering: 'high',
  csrf: 'high',
  info_disclosure: 'high',
  secret_disclosure: 'high',
  xxe: 'high',
  ssrf: 'high',
  webhook_forgery: 'high',
  sqli: 'high',
  race_double_spend: 'critical',
  open_redirect: 'medium',
  url_redirect: 'medium',
  dom_xss: 'high',
  xss: 'high',
  xss_reflected: 'high',
  xss_stored: 'high',
  injection: 'high',
}

const CWE_BY_CLASS: Readonly<Record<string, string>> = {
  bola: 'CWE-639',
  idor: 'CWE-639',
  bfla: 'CWE-285',
  authorization: 'CWE-285',
  cross_tenant_read: 'CWE-639',
  cross_tenant_write: 'CWE-639',
  mass_assignment: 'CWE-915',
  workflow_bypass: 'CWE-840',
  business_logic: 'CWE-840',
  price_tampering: 'CWE-472',
  csrf: 'CWE-352',
  info_disclosure: 'CWE-200',
  secret_disclosure: 'CWE-200',
  xxe: 'CWE-611',
  ssrf: 'CWE-918',
  webhook_forgery: 'CWE-345',
  sqli: 'CWE-89',
  race_double_spend: 'CWE-362',
  open_redirect: 'CWE-601',
  url_redirect: 'CWE-601',
  dom_xss: 'CWE-79',
  xss: 'CWE-79',
  xss_reflected: 'CWE-79',
  xss_stored: 'CWE-79',
  injection: 'CWE-89',
}

const TITLE_BY_RECIPE: Readonly<Record<PersistedFloorRecipeId, string>> = {
  access_boundary: 'Cross-actor object or function access',
  persisted_mutation: 'Persisted unauthorized state change',
  boolean_or_timing: 'SQL injection differential',
  oob_callback: 'Out-of-band callback from injected payload',
  race_burst: 'Synchronized burst double-spend',
  disclosure: 'Unauthorized record disclosure',
  redirect: 'Open redirect to off-origin destination',
  browser_sink: 'Client-side browser sink execution',
  injection_fingerprint: 'Parser or engine injection fingerprint',
  conserved_balance: 'Conserved-balance concurrency violation',
}

/**
 * Fail-closed attribution assertion stamped on every recipe record (Track D Cut 1). The recipe
 * envelope owns confirmation and retest (receipt + Tier-1 primitive): no jq program is synthesized
 * on the floor path, and a record whose envelope is stripped can never confirm through the DSL.
 */
export const TYPED_RECIPE_ASSERTION = '{ controlPassed: false, confirmed: false, observed: "typed floor recipe: verdict owned by the recipe envelope", expected: "Tier-1 primitive and ProofReceipt verdict" }'

function recordSteps(
  origin: string,
  execution: FloorRecipeExecution,
): Array<{ id: string; role: 'setup' | 'control' | 'probe' | 'cleanup'; description: string; request: Record<string, unknown> }> {
  const entries = execution.result.transcript.entries ?? []
  return entries.map((entry, index) => {
    const step: ImpactStep = entry.step
    const persona = step.actor.handle && step.actor.handle !== ANONYMOUS_HANDLE ? step.actor.handle : null
    return {
      id: `s${index + 1}`,
      role: step.arm,
      description: execution.result.steps[index]?.role ?? step.arm,
      request: {
        origin,
        method: step.method,
        pathAndQuery: step.pathAndQuery ?? step.route ?? '/',
        ...(persona ? { persona } : {}),
        ...(step.requestJson !== undefined ? { jsonBody: step.requestJson } : {}),
        ...(step.requestHeaders ? { headers: step.requestHeaders } : {}),
        followRedirects: false,
      },
    }
  })
}

function recordSpecFor(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  origin: string,
): Record<string, unknown> {
  const severity = SEVERITY_BY_CLASS[plan.vulnClass] ?? 'high'
  const cwe = CWE_BY_CLASS[plan.vulnClass] ?? 'CWE-639'
  const title = TITLE_BY_RECIPE[plan.recipeId]
  const steps = recordSteps(origin, execution)
  const base = baseFields(origin, title, cwe, plan.vulnClass, severity, TYPED_RECIPE_ASSERTION)
  if (plan.specKind === 'sql_boolean_diff') {
    const args = plan.args as BooleanOrTimingArgs
    return {
      ...base,
      kind: 'sql_boolean_diff',
      targetOrigin: origin,
      method: args.method.toUpperCase(),
      pathAndQuery: args.pathAndQuery,
      paramName: args.param ?? 'q',
      paramLocation: plan.paramLocation ?? 'query',
      baselineValue: args.baselineValue ?? '1',
      quoteStyle: args.quoteStyle ?? 'single',
      ...(args.valueTemplate ? { valueTemplate: args.valueTemplate } : {}),
      ...(args.probeJsonBody !== undefined ? { jsonBody: args.probeJsonBody } : {}),
      ...(args.headers ? { headers: args.headers } : {}),
    }
  }
  if (plan.specKind === 'race_burst') {
    const args = plan.args as RaceBurstArgs
    const burst = steps
      .filter(step => step.role === 'probe')
      .map(step => ({
        origin,
        method: step.request.method,
        pathAndQuery: step.request.pathAndQuery,
        ...(step.request.persona ? { persona: step.request.persona } : {}),
        ...(step.request.jsonBody !== undefined ? { jsonBody: step.request.jsonBody } : {}),
        ...(step.request.headers ? { headers: step.request.headers } : {}),
        followRedirects: false,
      }))
    return {
      ...base,
      kind: 'race_burst',
      burst: burst.length >= 2 ? burst : [
        { origin, method: args.method, pathAndQuery: args.pathAndQuery, jsonBody: args.body, followRedirects: false },
        { origin, method: args.method, pathAndQuery: args.pathAndQuery, jsonBody: args.body, followRedirects: false },
      ],
    }
  }
  if (plan.recipeId === 'browser_sink' || plan.specKind === 'browser_chain') {
    const args = plan.args as BrowserSinkArgs
    const defaultPersona = args.actor?.handle && args.actor.handle !== 'anonymous' && args.actor.handle !== ANONYMOUS_HANDLE
      ? args.actor.handle
      : undefined
    const browserSteps = (args.steps && args.steps.length > 0)
      ? args.steps.map((step, index) => ({
          id: `${step.role === 'control' ? 'c' : 'p'}${index + 1}`,
          role: step.role,
          description: `${step.role} ${step.action}`,
          origin,
          ...(step.pathAndQuery !== undefined ? { pathAndQuery: step.pathAndQuery } : index === 0 ? { pathAndQuery: args.pathAndQuery || '/' } : {}),
          ...(step.reusePage ? { reusePage: true } : {}),
          ...(step.persona ?? defaultPersona ? { persona: step.persona ?? defaultPersona } : {}),
          action: step.action,
          ...(step.selector ? { selector: step.selector } : {}),
          ...(step.value !== undefined ? { value: step.value } : {}),
          ...(step.waitAfterLoadMs !== undefined ? { waitAfterLoadMs: step.waitAfterLoadMs } : {}),
          checkKind: 'dom_xss' as const,
          enableSinkHook: true,
        }))
      : [
          { id: 'c1', role: 'control' as const, description: 'Control view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const, checkKind: 'dom_xss' as const, enableSinkHook: true },
          { id: 'p1', role: 'probe' as const, description: 'Probe view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const, checkKind: 'dom_xss' as const, enableSinkHook: true },
        ]
    // Ensure schema invariants: at least one control and one probe step, and step 1 has pathAndQuery.
    const hasControl = browserSteps.some(s => s.role === 'control')
    const hasProbe = browserSteps.some(s => s.role === 'probe')
    const validSteps = [
      ...(hasControl ? [] : [{ id: 'c0', role: 'control' as const, description: 'Control view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const }]),
      ...browserSteps,
      ...(hasProbe ? [] : [{ id: 'p0', role: 'probe' as const, description: 'Probe view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const }]),
    ]
    return { ...base, kind: 'browser_chain', steps: validSteps }
  }
  return { ...base, kind: 'http_chain', steps }
}

/** Build the persisted spec record for a recipe confirmation (steps = host-recorded exchanges). */
export function recipeSpecRecord(plan: FloorRecipePlan, execution: FloorRecipeExecution): SynthesizedEngineSpec {
  return {
    kind: plan.specKind,
    vulnClass: plan.vulnClass,
    endpoint: plan.endpoint,
    // The receipt owns the retest: persist the exact recipe that confirmed so a retest re-runs it and
    // validates a fresh ProofReceipt instead of re-interpreting the legacy declarative shape.
    spec: { ...recordSpecFor(plan, execution, plan.args.origin), recipe: { recipeId: plan.recipeId, args: plan.args } },
  }
}

/**
 * Project the receipt execution onto the verifier's result shape so the finding pipeline stores the
 * same artifact (exchange ids, transcript, evidence payload) it stores for a legacy confirmation.
 */
export function recipeVerificationResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
): ReplayVerificationResult {
  return recipeResult(plan, execution, exchangeIds, true)
}

/** Retest projection: `reproduced` keeps the confirmation shape, a rejected receipt is `dismissed`. */
export function recipeRetestResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
): ReplayVerificationResult {
  return recipeResult(plan, execution, exchangeIds, execution.result.confirmed)
}

export { assessRetestHealth, classifyRetestHealth } from './retest-health.ts'
export type { RetestFailureReason, RetestHealthAssessment, RetestHealthCode } from './retest-health.ts'

/**
 * Receipt-based retest of a persisted recipe (Cut 3 retest migration).
 *
 * Re-runs the exact `recipeId` + args the confirmation recorded, through the same broker seam, and
 * lets `runFloorRecipe` → `verifyReceipt()` decide. The legacy declarative verifier is never called
 * for a recipe-owned proof, so the persisted spec's shape is not the retest contract.
 *
 * Verdict mapping keeps the patch gate's semantics:
 *   - the receipt confirms again → `reproduced`
 *   - `classifyRetestHealth` confirms positive baseline + probe health → `fixed`
 *   - any unhealthy control/probe, missing control, budget overflow, or oracle disagreement → `inconclusive`
 */
export async function retestPersistedRecipe(input: {
  envelope: FloorRecipeEnvelope
  specKind: string
  vulnClass: string
  endpoint: string
  /** Target origin for every exchange; callers rebase it when a rebuilt lab moves ports. */
  origin: string
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  runId?: string
  assignmentId?: string
  probeClass?: string
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
  browserTrace?: FloorRecipeDeps['browserTrace']
  browserSession?: FloorRecipeDeps['browserSession']
}): Promise<{ verdict: RetestVerdict; execution: FloorRecipeExecution | null; replay: ReplayVerificationResult }> {
  const args = input.envelope.args as unknown as PersistedFloorRecipeArgs
  const plan: FloorRecipePlan = {
    recipeId: input.envelope.recipeId,
    specKind: input.specKind,
    vulnClass: input.vulnClass,
    endpoint: input.endpoint,
    args,
  }
  let execution: FloorRecipeExecution
  try {
    const baseDeps = brokerFloorRecipeDeps({
      broker: input.broker,
      grant: input.grant,
      signal: input.signal,
      origin: input.origin,
      ...(input.probeClass ? { probeClass: input.probeClass } : {}),
      runId: (input.runId ?? '').trim() || `floor_retest_${randomUUID()}`,
      ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
      ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
    })
    const deps: FloorRecipeDeps = {
      ...baseDeps,
      ...(input.browserTrace ? { browserTrace: input.browserTrace } : {}),
      ...(input.browserSession ? { browserSession: input.browserSession } : {}),
    }
    execution = await executeFloorRecipeById(input.envelope.recipeId, args, deps)
  } catch (error) {
    // A recipe that cannot execute at all is not evidence the vulnerability is gone.
    const reason = `recipe retest could not run: ${error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300)}`
    const health: RetestHealthAssessment = { healthy: false, code: 'recipe_error', failureReason: 'baseline_unhealthy', reason }
    return {
      verdict: 'inconclusive',
      execution: null,
      replay: {
        verdict: 'inconclusive',
        outcome: { confirmed: false, controlPassed: false, observed: reason, expected: 'the persisted recipe re-executes', reason },
        exchangeIds: [],
        exchanges: [],
        evidencePayload: { kind: plan.specKind, recipe: plan.recipeId, confirmation: 'proof_receipt', retestHealth: health },
        evidenceSha256: createHash('sha256').update(reason).digest('hex'),
      },
    }
  }
  const exchangeIds = [...execution.result.exchangeIds]
  const baseReplay = recipeRetestResult(plan, execution, exchangeIds)
  const health = classifyRetestHealth(execution)
  const replay: ReplayVerificationResult = {
    ...baseReplay,
    evidencePayload: { ...baseReplay.evidencePayload, retestHealth: health },
  }
  const verdict: RetestVerdict = execution.result.confirmed
    ? 'reproduced'
    : health.healthy && health.failureReason === 'claim_not_reproduced'
      ? 'fixed'
      : 'inconclusive'
  if (verdict === 'inconclusive') {
    const reason = health.reason ?? execution.failure?.message ?? replay.outcome.reason ?? 'The persisted recipe could not establish retest health.'
    return {
      verdict,
      execution,
      replay: {
        ...replay,
        verdict: 'inconclusive',
        outcome: { ...replay.outcome, confirmed: false, controlPassed: false, reason },
      },
    }
  }
  return { verdict, execution, replay }
}

function recipeResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
  confirmed: boolean,
): ReplayVerificationResult {
  const verification = execution.result.verification
  const steps = recordSteps(plan.args.origin, execution)
  const burstResults = plan.specKind === 'race_burst'
    ? execution.result.steps
      .filter(step => step.role.startsWith('burst_'))
      .map(step => ({ status: step.status, method: step.method, pathAndQuery: step.pathAndQuery, durationMs: step.durationMs }))
    : null
  const evidencePayload: Record<string, unknown> = {
    kind: plan.specKind,
    origin: plan.args.origin,
    replayedAt: null,
    confirmation: 'proof_receipt',
    recipe: plan.recipeId,
    tier1Primitive: execution.primitive
      ? { primitive: execution.primitive.primitive, subRule: execution.primitive.subRule, satisfied: execution.primitive.satisfied, reason: execution.primitive.reason }
      : { primitive: resolveUniversalPrimitive(plan.vulnClass), satisfied: confirmed, rule: verification.rule },
    receipt: execution.receipt,
    verification,
    ...(burstResults && burstResults.length > 0 ? { burst: { results: burstResults } } : {}),
    steps: Object.fromEntries(steps.map((step, index) => [step.id, {
      role: step.role,
      status: execution.result.steps[index]?.status ?? null,
      method: step.request.method,
      pathAndQuery: step.request.pathAndQuery,
    }])),
    exchangeIds: [...execution.result.exchangeIds],
  }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  const isRecipeError = !confirmed && execution.failure?.code === 'recipe_error'
  const reason = isRecipeError
    ? (execution.failure?.message ?? verification.reason)
    : !confirmed && execution.failure?.code === 'precondition_unsatisfied'
      ? execution.failure.message
      : verification.reason
  return {
    verdict: confirmed ? 'confirmed' : isRecipeError ? 'inconclusive' : 'dismissed',
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: confirmed,
      observed: verification.observed.slice(0, 1200),
      expected: verification.expected.slice(0, 1200),
      reason: reason.slice(0, 1200),
    },
    exchangeIds: [...exchangeIds],
    exchanges: [],
    evidencePayload,
    evidenceSha256,
    receipt: { receipt: execution.receipt, verification, mode: 'strict' },
  }
}


// ---------------------------------------------------------------------------------------------
// Cut 3e: Typed runners retiring legacy VM branches from replay-verifier.ts
// ---------------------------------------------------------------------------------------------

export interface LegacySpecRunnerContext {
  broker: RequestBroker
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  reposDir?: string
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

function runnerSecrets(grant: Grant, broker: RequestBroker): NamedSecret[] {
  return [
    ...(grant.secrets ?? []),
    ...(grant.personas ? personaSecrets(grant.personas) : []),
    ...(broker.getRegisteredSecrets?.() ?? []),
  ]
}

function makeRunnerRecorder(ctx: LegacySpecRunnerContext, fallbackPrefix: string) {
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string => {
    exchanges.push(ex)
    const id = ctx.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return `${fallbackPrefix}-${exchanges.length}`
  }
  return { exchanges, exchangeIds, recordExchange }
}

function runnerIsPrime(n: number): boolean {
  if (n < 2) return false
  if (n % 2 === 0) return n === 2
  const limit = Math.floor(Math.sqrt(n))
  for (let i = 3; i <= limit; i += 2) {
    if (n % i === 0) return false
  }
  return true
}

function runnerFiveDigitPrime(exclude?: number): number {
  for (;;) {
    const candidate = randomInt(10_007, 99_991) | 1
    if (candidate !== exclude && runnerIsPrime(candidate)) return candidate
  }
}

function runnerAlphaToken(len = 7): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  const bytes = randomBytes(len)
  let out = ''
  for (let i = 0; i < len; i += 1) out += alphabet[bytes[i] % alphabet.length]
  return out
}

function runnerBase64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

async function runnerSleepAbortable(ms: number, signal: AbortSignal) {
  if (signal.aborted) throw signal.reason
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

function evaluateRunnerOobReceipt(input: {
  origin: string
  stepId: string
  exchange: BrokerExchangeResult
  exchangeId: string
  request: BrokerHttpRequest
  oobEventId: string
  callbackPrefix: string
  token: string
  probeWait: { triggered: boolean; stage?: string; subscriptionId?: string | null }
  controlTriggered: boolean
  claimedDelta: string
  injectedAtMs: number
  carrierExtra?: string
}): ReplayReceiptCheck {
  const receipt: ProofReceipt = {
    vulnClass: 'oob',
    target: { origin: input.origin, method: input.exchange.method.toUpperCase(), pathAndQuery: input.exchange.pathAndQuery },
    exchangeIds: [input.exchangeId],
    oobEventIds: [input.oobEventId],
    browserTraceIds: [],
    claimedDelta: input.claimedDelta,
    injectedAtMs: input.injectedAtMs,
  }
  const carrierBase = `${input.request.pathAndQuery}\n${JSON.stringify(input.request.headers ?? {})}\n${input.request.body ?? ''}`
  const transcript: ReceiptTranscript = {
    entries: [{
      exchangeId: input.exchangeId,
      step: {
        id: input.stepId,
        arm: 'probe',
        method: input.exchange.method.toUpperCase(),
        route: input.exchange.pathAndQuery.split('?')[0] || '/',
        pathAndQuery: input.exchange.pathAndQuery,
        status: input.exchange.status,
        actor: { handle: input.exchange.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
        json: null,
        body: input.exchange.body,
      },
      carrierText: input.carrierExtra ? `${carrierBase}\n${input.carrierExtra}` : carrierBase,
    }],
    oobEvents: [{
      id: input.oobEventId,
      callbackId: input.probeWait.subscriptionId ?? `${input.callbackPrefix}:${input.exchangeId}`,
      token: input.token,
      targetOrigin: input.origin,
      delivered: input.probeWait.triggered && !input.controlTriggered,
      stage: input.probeWait.stage === 'late' ? 'late' : 'immediate',
      receivedAtMs: Date.now(),
      injectedAtMs: input.injectedAtMs,
    }],
  }
  const verification = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript(transcript),
    { kind: 'single_hop', receipt },
    { strictHostDerivation: true },
  ).singleHop!
  return { receipt, verification, mode: 'strict' }
}

async function runRunnerSpaCatchall(input: {
  origin: string
  ctx: LegacySpecRunnerContext
  recordExchange: (ex: BrokerExchangeResult) => string
  targets: readonly { id: string; exchange: BrokerExchangeResult }[]
}): Promise<{ summary: Record<string, unknown>; allProbesMatchedCatchall: boolean }> {
  const catchallPath = `/.kovo-nonexistent-${randomUUID()}`
  const catchallEx = await input.ctx.broker.executeHttp({
    origin: input.origin,
    method: 'GET',
    pathAndQuery: catchallPath,
    followRedirects: true,
  }, input.ctx.grant, input.ctx.signal)
  input.recordExchange(catchallEx)
  const comparisons: Record<string, Record<string, unknown>> = {}
  let allProbesMatchedCatchall = input.targets.length > 0
  for (const target of input.targets) {
    const diff = diffResponse(
      { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
      { status: target.exchange.status, body: target.exchange.body, mediaType: target.exchange.mediaType },
    )
    comparisons[target.id] = diff
    if (!diff.likelySpaCatchall) allProbesMatchedCatchall = false
  }
  return {
    summary: { path: catchallPath, ...summarizeExchange(catchallEx), comparisons, allProbesMatchedCatchall },
    allProbesMatchedCatchall,
  }
}

function runnerHandleError(
  err: unknown,
  ctx: LegacySpecRunnerContext,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
  evidencePayload: Record<string, unknown>,
): ReplayVerificationResult {
  const secrets = runnerSecrets(ctx.grant, ctx.broker)
  const safePayload = redactJsonValue(evidencePayload, secrets)
  if (err instanceof BrokerDenied || err instanceof BrokerCircuitOpen || err instanceof BrokerApprovalRequired) {
    return inconclusiveResult(redact(err.message, secrets), exchanges, exchangeIds, safePayload)
  }
  const message = redact(err instanceof Error ? err.message : String(err), secrets)
  return inconclusiveResult(`Replay execution failed: ${message}`, exchanges, exchangeIds, safePayload)
}

/**
 * Cut 3e typed runner for `static_ast_proof` (zero-jq).
 * Enforces strict tier separation: can only ever emit `static_verified`, `dismissed`, or `inconclusive`.
 */
export async function runStaticAstProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'static_ast_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  if (!ctx.reposDir) {
    return inconclusiveResult('static_ast_proof requires the read-only /repos mount (reposDir).', [], [], { kind: spec.kind })
  }
  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  try {
    const astResult = await ctx.backend.verifyStaticAst(ctx.assignmentId, {
      repo: spec.repo,
      file: spec.file,
      startLine: spec.startLine,
      endLine: spec.endLine,
      engine: spec.engine,
      ruleOrPattern: spec.ruleOrPattern,
    }, ctx.signal, { reposDir: ctx.reposDir, ...(ctx.runId ? { runId: ctx.runId } : {}) })
    const evidencePayload = redactJsonValue({
      ...basePayload,
      repo: spec.repo,
      file: spec.file,
      startLine: spec.startLine,
      endLine: spec.endLine,
      engine: spec.engine,
      ruleOrPattern: spec.ruleOrPattern,
      sourceToSinkTrace: spec.sourceToSinkTrace ?? null,
      runtimeProofGap: spec.runtimeProofGap,
      verificationTier: 'static_verified',
      astVerify: astResult,
      static: {
        verified: astResult.verified,
        matchCount: astResult.matchCount,
        matchedLines: astResult.matchedLines,
        controlPassed: astResult.verified,
      },
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
    if (astResult.verified) {
      return {
        verdict: 'static_verified',
        verificationTier: 'static_verified',
        outcome: {
          confirmed: true,
          controlPassed: true,
          observed: `Static AST matched ${astResult.matchCount} line(s) in ${spec.repo}/${spec.file}:${spec.startLine}-${spec.endLine}.`,
          expected: `Pattern ${spec.ruleOrPattern} verified in cited source range.`,
        },
        exchangeIds: [],
        exchanges: [],
        evidencePayload,
        evidenceSha256,
      }
    }
    const reason = `Static AST re-verification failed: ${astResult.reason ?? 'pattern not found in the cited range.'}`
    return {
      verdict: 'dismissed',
      outcome: {
        confirmed: false,
        controlPassed: true,
        observed: reason.slice(0, 1200),
        expected: `Pattern ${spec.ruleOrPattern} verified in cited source range.`,
        reason: reason.slice(0, 1200),
      },
      exchangeIds: [],
      exchanges: [],
      evidencePayload,
      evidenceSha256,
    }
  } catch (err) {
    return runnerHandleError(err, ctx, [], [], basePayload)
  }
}

/** Shared runner verdict projection (confirmed results carry the runtime tier). */
function runnerResult(verdict: ReplayVerdict, outcome: ReplayVerificationResult['outcome'], exchanges: BrokerExchangeResult[], exchangeIds: string[], evidencePayload: Record<string, unknown>, evidenceSha256: string, extra: Partial<ReplayVerificationResult> = {}): ReplayVerificationResult {
  return { verdict, ...(verdict === 'confirmed' ? { verificationTier: 'runtime_confirmed' as const } : {}), outcome, exchangeIds, exchanges, evidencePayload, evidenceSha256, ...extra }
}

const jsonOfExchange = (ex: BrokerExchangeResult): unknown => { if (!ex.mediaType.includes('json')) return undefined; try { return JSON.parse(ex.body) } catch { return undefined } }
/** Host-signed Tier-1 record for a runner exchange; the timestamp is the host call order. */
function exchangeRecord(signer: Tier1Signer, id: string, ordinal: number, ex: BrokerExchangeResult, artifactDigest?: string): HostSignedRecord {
  return signer.sign({ id, timestampMs: ordinal, status: ex.status, method: ex.method.toUpperCase(), route: ex.pathAndQuery.split('?')[0] || '/', pathAndQuery: ex.pathAndQuery, actorId: ex.personaHandle, body: ex.body, json: jsonOfExchange(ex), requestHeaders: ex.reqHeaders, responseHeaders: ex.respHeaders, ...(artifactDigest ? { artifactDigest } : {}) })
}

/** rce_proof Tier-1 verdict: host-evaluated expression (math/split) or OOB canary witness, with the benign control. */
export function rceWitnessDecision(input: { controlEx: BrokerExchangeResult; probeEx: BrokerExchangeResult; controlId: string; probeId: string; hostCanary: string; expected?: string; oob?: { triggered: boolean; controlTriggered: boolean; token: string } }): UniversalPrimitiveDecision {
  const signer = tier1HostSigner(), control = exchangeRecord(signer, input.controlId, 1, input.controlEx), trigger = exchangeRecord(signer, input.probeId, 2, input.probeEx), oob = input.oob
  if (oob) {
    const witness = oob.triggered ? signer.sign({ id: `${input.probeId}:oob`, timestampMs: 3, status: 200, surface: 'webhook' }) : undefined
    return evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'oob_callback', trigger, witness: witness as HostSignedRecord, hostCanary: oob.token, observedCanary: oob.triggered ? oob.token : null, control, controlObservedCanary: oob.controlTriggered ? oob.token : null, verifySignature: signer.verify })
  }
  return evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'host_evaluated_expression', trigger, witness: trigger, hostCanary: input.hostCanary, ...(input.expected ? { expectedValue: input.expected } : {}), control, verifySignature: signer.verify })
}

/**
 * Cut 3e typed runner for `rce_proof` (zero-jq; Tier-3 + HITL gate, non-reflectable math/split_echo,
 * and ProofReceipt-verified OOB callbacks), gated by the Tier-1 execution witness.
 */
export async function runRceProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'rce')

  // Hard Tier 3 + HITL approval gate
  const tier = ctx.grant.tier ?? 1
  const gateRequest = spec.probeStep.request
  if (tier < 3) {
    ctx.grant.audit('denied', gateRequest.origin)
    return inconclusiveResult(`${spec.kind} replay specs are blocked below Tier 3.`, exchanges, exchangeIds, { kind: spec.kind })
  }
  const localLab = Boolean(ctx.grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')
  const approvalContext: StateChangeApprovalContext = {
    personaHandle: gateRequest.persona ?? null,
    body: gateRequest.textBody ?? (gateRequest.jsonBody !== undefined ? JSON.stringify(gateRequest.jsonBody) : null),
    hasMultipart: false,
    isRaceBurst: false,
    isRceProof: true,
  }
  const approved = ctx.grant.isStateChangeApproved
    ? ctx.grant.isStateChangeApproved(gateRequest.origin, gateRequest.method, gateRequest.pathAndQuery, approvalContext)
    : localLab
  if (!approved) {
    ctx.grant.audit('denied', gateRequest.origin)
    return inconclusiveResult(`${spec.kind} requires explicit Tier 3 HITL operator approval.`, exchanges, exchangeIds, { kind: spec.kind })
  }

  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  const controlVars: Record<string, string> = {}
  const probeVars: Record<string, string> = {}
  const proofMeta: Record<string, unknown> = { mode: spec.proofMode }

  let canarySession: EphemeralCanarySession | undefined
  let controlCanaryToken: string | undefined
  let probeCanaryToken: string | undefined
  let expectedNonceProduct: string | undefined
  let expectedSplitAssembled: string | undefined
  let hostCanary = '', oobWitness: { triggered: boolean; controlTriggered: boolean; token: string } | undefined

  try {
    if (spec.proofMode === 'dynamic_math') {
      const a = runnerFiveDigitPrime()
      const b = runnerFiveDigitPrime(a)
      expectedNonceProduct = String(a * b)
      probeVars.nonce_a = String(a)
      probeVars.nonce_b = String(b)
      proofMeta.nonceA = a
      proofMeta.nonceB = b
      proofMeta.expectedProduct = expectedNonceProduct
      hostCanary = `kovo-rce-math-${a}-${b}`
    } else if (spec.proofMode === 'split_echo') {
      const part1 = runnerAlphaToken(7)
      const part2 = runnerAlphaToken(7)
      expectedSplitAssembled = part1 + part2
      probeVars.nonce_part1 = part1
      probeVars.nonce_part2 = part2
      proofMeta.expectedAssembled = expectedSplitAssembled
      hostCanary = `kovo-rce-split-${part1}-${part2}`
    } else {
      canarySession = await openCanarySession(ctx.canaryBroker, ctx.storage, ctx.runId, ctx.assignmentId, spec.origin)
      const controlCanary = canarySession.mint(`rce_proof:control:${spec.title}`)
      const probeCanary = canarySession.mint(`rce_proof:probe:${spec.title}`)
      controlCanaryToken = controlCanary.token
      probeCanaryToken = probeCanary.token
      controlVars.canary_token = controlCanary.token
      controlVars.canary_url = controlCanary.url
      controlVars.canary_dns_host = controlCanary.dnsHost
      probeVars.canary_token = probeCanary.token
      probeVars.canary_url = probeCanary.url
      probeVars.canary_dns_host = probeCanary.dnsHost
      proofMeta.controlCanaryToken = controlCanary.token
      proofMeta.probeCanaryToken = probeCanary.token
    }

    const controlReq = stepToBrokerRequest(spec.controlStep, controlVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const probeReq = stepToBrokerRequest(spec.probeStep, probeVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const serializedProbeReq = JSON.stringify(probeReq)

    if (hasDestructiveContent(JSON.stringify(controlReq)) || hasDestructiveContent(serializedProbeReq)) {
      return inconclusiveResult('Interpolated rce_proof request matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'split_echo' && expectedSplitAssembled && serializedProbeReq.includes(expectedSplitAssembled)) {
      return inconclusiveResult('Invalid split_echo template: nonce_part1 and nonce_part2 must be separated by execution concatenation syntax.', exchanges, exchangeIds, { kind: spec.kind })
    }

    const controlEx = await ctx.broker.executeHttp(controlReq, ctx.grant, ctx.signal)
    const controlExchangeId = recordExchange(controlEx)
    const injectedAtMs = Date.now()
    const probeEx = await ctx.broker.executeHttp(probeReq, ctx.grant, ctx.signal)
    const probeExchangeId = recordExchange(probeEx)

    let deterministicProofPassed = false
    let receiptCheck: ReplayVerificationResult['receipt']
    let observed = probeEx.bodyPreview.slice(0, 400) || `status=${probeEx.status}`

    if (spec.proofMode === 'dynamic_math' && expectedNonceProduct) {
      const inProbe = probeEx.body.includes(expectedNonceProduct)
      const inControl = controlEx.body.includes(expectedNonceProduct)
      deterministicProofPassed = inProbe && !inControl && !serializedProbeReq.includes(expectedNonceProduct)
      proofMeta.mathVerified = deterministicProofPassed
      proofMeta.productInProbe = inProbe
      proofMeta.productInControl = inControl
      observed = deterministicProofPassed
        ? `Evaluated dynamic_math product ${expectedNonceProduct} observed exclusively in probe.`
        : `dynamic_math product not evaluated (inProbe=${inProbe}, inControl=${inControl}).`
    } else if (spec.proofMode === 'split_echo' && expectedSplitAssembled) {
      const inProbe = probeEx.body.includes(expectedSplitAssembled)
      const inControl = controlEx.body.includes(expectedSplitAssembled)
      deterministicProofPassed = inProbe && !inControl && !serializedProbeReq.includes(expectedSplitAssembled)
      proofMeta.splitEchoVerified = deterministicProofPassed
      proofMeta.assembledInProbe = inProbe
      proofMeta.assembledInControl = inControl
      observed = deterministicProofPassed
        ? `Concatenated split_echo token observed exclusively in probe.`
        : `split_echo concatenation not observed (inProbe=${inProbe}, inControl=${inControl}).`
    } else if (spec.proofMode === 'oob_canary' && canarySession && controlCanaryToken && probeCanaryToken) {
      const probeWait = await canarySession.waitForCallback(probeCanaryToken, ctx.signal)
      const controlCheck = canarySession.check(controlCanaryToken)
      proofMeta.canaryProbeTriggered = probeWait.triggered
      proofMeta.canaryProbeStage = probeWait.stage
      proofMeta.canaryProbePromoted = probeWait.promoted
      proofMeta.canaryProbeDetail = probeWait.detail
      proofMeta.canaryControlTriggered = controlCheck.triggered
      proofMeta.canaryControlDetail = controlCheck.detail
      receiptCheck = evaluateRunnerOobReceipt({
        origin: spec.origin,
        stepId: spec.probeStep.id,
        exchange: probeEx,
        exchangeId: probeExchangeId,
        request: probeReq,
        oobEventId: 'rce-oob-canary',
        callbackPrefix: 'rce',
        token: probeCanaryToken,
        probeWait,
        controlTriggered: controlCheck.triggered,
        claimedDelta: 'Probe triggered an out-of-band execution callback that control did not.',
        injectedAtMs,
      })
      deterministicProofPassed = probeWait.triggered && !controlCheck.triggered && receiptCheck.verification.confirmed
      oobWitness = { triggered: probeWait.triggered, controlTriggered: controlCheck.triggered, token: probeCanaryToken }
      observed = `probeCanary=${probeWait.triggered}, controlCanary=${controlCheck.triggered}`
    }

    const primitive = rceWitnessDecision({ controlEx, probeEx, controlId: controlExchangeId, probeId: probeExchangeId, hostCanary, expected: expectedNonceProduct ?? expectedSplitAssembled, oob: oobWitness })
    deterministicProofPassed &&= primitive.satisfied
    proofMeta.tier1Primitive = { primitive: primitive.primitive, subRule: primitive.subRule, satisfied: primitive.satisfied, reason: primitive.reason }
    proofMeta.cryptographicProofPassed = deterministicProofPassed
    const evidencePayload = redactJsonValue({
      ...basePayload,
      proofMode: spec.proofMode,
      control: summarizeExchange(controlEx),
      probe: summarizeExchange(probeEx),
      proof: proofMeta,
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')

    const controlPassed = !isUnexpectedErrorStatus(controlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus) &&
      controlEx.status >= 200 && controlEx.status < 500
    const expected = 'Untrusted input is never evaluated as template or command code.'
    const receiptExtra = receiptCheck ? { receipt: receiptCheck } : {}
    if (deterministicProofPassed && controlPassed) {
      return runnerResult('confirmed', { confirmed: true, controlPassed: true, observed: observed.slice(0, 1200), expected }, exchanges, exchangeIds, evidencePayload, evidenceSha256, receiptExtra)
    }
    const reason = deterministicProofPassed
      ? `Control step returned unexpected HTTP ${controlEx.status}.`
      : 'Cryptographic non-destructive proof-of-execution check did not pass (possible reflection or unexecuted payload).'
    return runnerResult(controlPassed ? 'dismissed' : 'inconclusive', { confirmed: false, controlPassed, observed: observed.slice(0, 1200), expected, reason }, exchanges, exchangeIds, evidencePayload, evidenceSha256, receiptExtra)
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  } finally {
    await canarySession?.close()
  }
}

const digestText = (text: string): string => createHash('sha256').update(text).digest('hex').slice(0, 32)
const cacheExchangeRecord = (signer: Tier1Signer, id: string, ordinal: number, ex: BrokerExchangeResult, artifactDigest: string): HostSignedRecord => {
  const json = jsonOfExchange(ex)
  return signer.sign({ id, timestampMs: ordinal, status: ex.status, method: ex.method.toUpperCase(), route: ex.pathAndQuery.split('?')[0] || '/', pathAndQuery: ex.pathAndQuery, actorId: ex.personaHandle, ...(json !== undefined ? { json, body: ex.body } : {}), requestHeaders: ex.reqHeaders, responseHeaders: ex.respHeaders, artifactDigest })
}

/** cache_differential Tier-1 verdict: host-signed wire_framing_and_cache_differential (cache_priming). */
export function cacheDifferentialDecision(input: {
  controlEx: BrokerExchangeResult; probeEx: BrokerExchangeResult; verifyEx: BrokerExchangeResult
  controlId: string; probeId: string; verifyId: string
  victimDigest: string; controlDigest: string; verifyDigest: string
  controlContainsVictimData: boolean; requireDistinctPrincipals?: boolean
}): UniversalPrimitiveDecision {
  const signer = tier1HostSigner()
  const control = cacheExchangeRecord(signer, input.controlId, 1, input.controlEx, input.controlDigest)
  const prime = cacheExchangeRecord(signer, input.probeId, 2, input.probeEx, input.victimDigest)
  const variant = cacheExchangeRecord(signer, input.verifyId, 3, input.verifyEx, input.verifyDigest)
  return evaluateUniversalPrimitive('wire_framing_and_cache_differential', {
    property: 'cache_priming', control, prime, variant,
    victimDigest: input.victimDigest, controlContainsVictimData: input.controlContainsVictimData,
    ...(input.requireDistinctPrincipals ? { requireDistinctPrincipals: true } : {}), verifySignature: signer.verify,
  })
}

/**
 * Cut 3e typed runner for `cache_differential` (zero-jq), gated by Tier-1 wire_framing_and_cache_differential.
 */
export async function runCacheDifferentialRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'cache_differential' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'cache')
  const basePayload: Record<string, unknown> = { kind: spec.kind, origin: spec.origin, replayedAt: new Date().toISOString() }

  try {
    const controlGcb = randomUUID(), probeGcb = randomUUID(), repeatGcb = randomUUID()
    const resolveCachePath = (raw: string, token: string): string =>
      raw.replaceAll('{{control_gcb}}', controlGcb).replaceAll('{{probe_gcb}}', probeGcb).replaceAll('{{repeat_gcb}}', repeatGcb).replaceAll('{{cache_buster}}', token)

    const controlPath = resolveCachePath(spec.controlPath, controlGcb), probePath = resolveCachePath(spec.probePath, probeGcb)
    const verifyPath = spec.verifyPath ? resolveCachePath(spec.verifyPath, probeGcb) : probePath
    const repeatPath = spec.repeatPath ? resolveCachePath(spec.repeatPath, repeatGcb) : null

    const actualCtrlGcb = extractCacheBusterParam(controlPath), actualProbeGcb = extractCacheBusterParam(probePath)
    if (!actualCtrlGcb || !cacheBusterValueRegex.test(actualCtrlGcb) || !actualProbeGcb || !cacheBusterValueRegex.test(actualProbeGcb)) {
      return inconclusiveResult('cache_differential requires valid ?_gcb=<16-36 hex/uuid> tokens.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (actualCtrlGcb.toLowerCase() === actualProbeGcb.toLowerCase()) {
      return inconclusiveResult('cache_differential cannot reuse _gcb between control and probe.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'body_repeat' && !repeatPath) {
      return inconclusiveResult('cache_differential body_repeat proof requires a repeatPath.', exchanges, exchangeIds, { kind: spec.kind })
    }

    const executeCacheReq = (pathAndQuery: string, extra: Partial<BrokerHttpRequest>) =>
      ctx.broker.executeHttp({ origin: spec.targetOrigin, method: spec.method, pathAndQuery, followRedirects: false, runId: ctx.runId, assignmentId: ctx.assignmentId, ...extra }, ctx.grant, ctx.signal)

    const controlEx = await executeCacheReq(controlPath, { ...(spec.controlPersona ? { persona: spec.controlPersona } : {}), probeClass: 'cache_differential' })
    const controlId = recordExchange(controlEx)
    const probeEx = await executeCacheReq(probePath, { headers: spec.poisonHeaders, persona: spec.poisonPersona, probeClass: 'cache_poison_deception' })
    const probeId = recordExchange(probeEx)
    const verifyEx = await executeCacheReq(verifyPath, { ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}), probeClass: 'cache_differential', cacheVerify: true })
    const verifyId = recordExchange(verifyEx)

    let repeatEx: BrokerExchangeResult | null = null
    if (spec.proofMode === 'body_repeat' && repeatPath) {
      await runnerSleepAbortable(150, ctx.signal)
      repeatEx = await executeCacheReq(repeatPath, { ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}), probeClass: 'cache_differential', cacheVerify: true })
      recordExchange(repeatEx)
    }

    const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
    let forcedInconclusiveReason: string | null = null
    if (guardControlErrors) {
      if (isUnexpectedErrorStatus(controlEx.status, spec.expectedStatus)) forcedInconclusiveReason = `Unexpected HTTP ${controlEx.status} on cache_differential control step (requireControlNonError).`
      else if (isUnexpectedErrorStatus(verifyEx.status, spec.expectedStatus)) forcedInconclusiveReason = `Unexpected HTTP ${verifyEx.status} on cache_differential verify step (requireControlNonError).`
    }

    const ageRaw = verifyEx.respHeaders.age, age = ageRaw !== undefined ? Number(ageRaw) : NaN
    const cacheHeaderSignal = [verifyEx.respHeaders['x-cache'], verifyEx.respHeaders['cf-cache-status'], verifyEx.respHeaders['x-cache-status'], verifyEx.respHeaders['x-proxy-cache'], verifyEx.respHeaders['cache-status']].some(v => typeof v === 'string' && /\bhit\b/i.test(v))
    const normControlBody = normalizeStructuralTokens(controlEx.body), normProbeBody = normalizeStructuralTokens(probeEx.body), normVerifyBody = normalizeStructuralTokens(verifyEx.body)
    const simControlVsVerify = structuralDiffNormalized(normControlBody, normVerifyBody).similarity
    const simProbeVsVerify = structuralDiffNormalized(normProbeBody, normVerifyBody).similarity

    let cacheHitObserved: boolean, poisonPersistedToVictim: boolean
    let markerInControl = false, markerInProbe = false, markerInVerify = false, markerInRepeat = false, repeatBodyMatches = false, timingSignal = false
    let victimDigest: string, controlDigest: string, verifyDigest: string, controlContainsVictimData: boolean
    if (spec.proofMode === 'body_repeat') {
      const marker = spec.marker
      markerInControl = Boolean(marker && controlEx.body.includes(marker))
      markerInProbe = Boolean(marker && probeEx.body.includes(marker))
      markerInVerify = Boolean(marker && verifyEx.body.includes(marker))
      markerInRepeat = Boolean(marker && repeatEx?.body.includes(marker))
      const actorDifferential = Boolean(spec.poisonPersona) && (spec.verifyPersona ?? null) !== spec.poisonPersona
      const bodyPersisted = verifyEx.body === probeEx.body && verifyEx.body !== controlEx.body
      repeatBodyMatches = Boolean(repeatEx && repeatEx.body === verifyEx.body && repeatEx.body !== controlEx.body)
      const markerPersisted = Boolean(marker) && markerInProbe && markerInVerify && !markerInControl
      cacheHitObserved = Boolean(marker) ? markerPersisted : bodyPersisted
      poisonPersistedToVictim = actorDifferential && cacheHitObserved && repeatBodyMatches && (!marker || markerInRepeat)
      timingSignal = Boolean(repeatEx) && repeatBodyMatches
      victimDigest = marker ? digestText(`marker:${marker}`) : digestText(probeEx.body)
      controlDigest = marker && markerInControl ? victimDigest : digestText(controlEx.body)
      verifyDigest = (marker ? markerInVerify && repeatBodyMatches : verifyEx.body === probeEx.body) ? victimDigest : digestText(verifyEx.body)
      controlContainsVictimData = marker ? markerInControl : controlEx.body === probeEx.body
    } else {
      cacheHitObserved = (Number.isFinite(age) && age > 0) || cacheHeaderSignal
      const poisonValues = Object.values(spec.poisonHeaders ?? {}).map(v => String(v ?? '').trim()).filter(v => v.length >= 4)
      const poisonReflected = poisonValues.length === 0 || poisonValues.some(v =>
        (probeEx.body.includes(v) || String(probeEx.respHeaders.location ?? '').includes(v)) &&
        (verifyEx.body.includes(v) || String(verifyEx.respHeaders.location ?? '').includes(v)) &&
        !controlEx.body.includes(v) && !String(controlEx.respHeaders.location ?? '').includes(v))
      poisonPersistedToVictim = (simControlVsVerify < 0.95 || verifyEx.status !== controlEx.status) && simProbeVsVerify >= 0.85 && verifyEx.status === probeEx.status && poisonReflected
      controlDigest = digestText(`${controlEx.status}|${normControlBody}`)
      victimDigest = digestText(`${probeEx.status}|${normProbeBody}`)
      verifyDigest = digestText(`${verifyEx.status}|${normVerifyBody}`)
      controlContainsVictimData = controlDigest === victimDigest
    }

    const primitive = cacheDifferentialDecision({
      controlEx, probeEx, verifyEx, controlId, probeId, verifyId, victimDigest, controlDigest, verifyDigest, controlContainsVictimData,
      ...((spec.proofMode === 'body_repeat' || (Boolean(spec.poisonPersona) && Object.keys(spec.poisonHeaders ?? {}).length === 0)) ? { requireDistinctPrincipals: true } : {}),
    })
    const deterministicProofPassed = cacheHitObserved && poisonPersistedToVictim && primitive.satisfied
    const proofFailureReason = deterministicProofPassed ? ''
      : !primitive.satisfied ? `tier1_primitive_rejected: ${primitive.primitive} ${primitive.reason}`
        : spec.proofMode === 'body_repeat'
          ? (!cacheHitObserved ? 'Header-free cache proof: the clean verify did not receive the warm marker/body.' : 'Header-free cache proof: repeat fetch did not reproduce the poisoned body, or the control did not differ.')
          : !cacheHitObserved ? 'Verify request did not observe a cache hit (missing HIT header or Age > 0).' : 'Clean unauthenticated verify response matched clean control rather than poisoned probe.'

    let spaCatchall: Record<string, unknown> | undefined
    if (spec.spaCatchallControl) {
      const catchall = await runRunnerSpaCatchall({ origin: spec.targetOrigin, ctx, recordExchange, targets: [{ id: 'verify', exchange: verifyEx }] })
      spaCatchall = catchall.summary
      if (catchall.allProbesMatchedCatchall) forcedInconclusiveReason = 'cache_differential verify response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
    }

    const controlSummary = { id: 'control', role: 'control', ...summarizeExchange(controlEx) }
    const probeSummary = { id: 'probe', role: 'probe', ...summarizeExchange(probeEx) }
    const verifySummary = { id: 'verify', role: 'probe', ...summarizeExchange(verifyEx) }
    const repeatSummary = repeatEx ? { id: 'repeat', role: 'probe', ...summarizeExchange(repeatEx) } : undefined

    const evidencePayload = redactJsonValue({
      ...basePayload, targetOrigin: spec.targetOrigin, mode: spec.mode,
      control: controlSummary, probe: probeSummary, verify: verifySummary, ...(repeatSummary ? { repeat: repeatSummary } : {}),
      steps: { control: controlSummary, probe: probeSummary, verify: verifySummary, ...(repeatSummary ? { repeat: repeatSummary } : {}) },
      ...(spaCatchall ? { spaCatchall } : {}),
      cacheProof: {
        mode: spec.mode, proofMode: spec.proofMode, controlGcb: actualCtrlGcb, probeGcb: actualProbeGcb,
        cacheHitObserved, poisonPersistedToVictim, simControlVsVerify, simProbeVsVerify, age: Number.isFinite(age) ? age : null,
        markerPresent: Boolean(spec.marker), markerInControl, markerInProbe, markerInVerify, markerInRepeat, repeatBodyMatches, timingSignal,
        tier1Primitive: { primitive: primitive.primitive, subRule: primitive.subRule, satisfied: primitive.satisfied, reason: primitive.reason },
      },
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')

    const expected = 'Unkeyed input or victim response is not cached and served across clients.'
    if (forcedInconclusiveReason) {
      return runnerResult('inconclusive', { confirmed: false, controlPassed: false, observed: verifyEx.bodyPreview.slice(0, 400), expected: 'Clean uncached or isolated response.', reason: forcedInconclusiveReason }, exchanges, exchangeIds, evidencePayload, evidenceSha256)
    }
    const controlPassed = controlEx.status >= 200 && controlEx.status < 500
    if (deterministicProofPassed && controlPassed) {
      return runnerResult('confirmed', { confirmed: true, controlPassed: true, observed: `Cache ${spec.mode} persisted poisoned response to clean verify (simControl=${simControlVsVerify.toFixed(2)}, simProbe=${simProbeVsVerify.toFixed(2)}).`, expected }, exchanges, exchangeIds, evidencePayload, evidenceSha256)
    }
    return runnerResult(controlPassed ? 'dismissed' : 'inconclusive', { confirmed: false, controlPassed, observed: verifyEx.bodyPreview.slice(0, 400) || `verifyStatus=${verifyEx.status}`, expected, reason: proofFailureReason || `Control step returned HTTP ${controlEx.status}.` }, exchanges, exchangeIds, evidencePayload, evidenceSha256)
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  }
}

const AUTH_WIRE_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token|x-(?:hub-|webhook-)?signature(?:-256)?)$/i
const PRIV_BOOL_KEYS = ['isAdmin', 'is_admin', 'admin', 'bypassed', 'elevated', 'superuser', 'isSuperuser', 'is_superuser', 'staff', 'is_staff'] as const
const ROLE_STR_KEYS = ['role', 'privilege', 'accountRole', 'userRole'] as const
const IDENTITY_CLAIM_KEYS = ['sub', 'userId', 'user_id', 'tenant', 'tenantId', 'tenant_id', 'orgId', 'org_id'] as const
const ELEVATED_SCOPE_RE = /^(?:admin|owner|superadmin|root|\*|write:admin|manage(?::.*)?)$/i

const JWT_LITERAL_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g
function hasBodyMintedTokenDiff(cBody: string | undefined, pBody: string | undefined, minted: readonly string[] | undefined): boolean {
  if (!cBody || !pBody || !minted?.length) return false
  if (!minted.some(t => t.length >= 12 && pBody.includes(t) && !cBody.includes(t))) return false
  const strip = (s: string) => minted.reduce((acc, t) => (t.length >= 12 ? acc.replaceAll(t, '<TOKEN>') : acc), s).replace(JWT_LITERAL_RE, '<TOKEN>')
  return strip(cBody) === strip(pBody)
}

function authWireFingerprint(ex: BrokerExchangeResult, authMutation?: AuthMutation, bodyTokenDigest?: string): string {
  const hdrs = Object.entries(ex.reqHeaders ?? {}).filter(([k]) => AUTH_WIRE_HEADER_RE.test(k)).sort(([a], [b]) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1)).map(([k, v]) => `${k.toLowerCase()}=${v}`)
  const prov = ex.wireCredentialProvenance
  return digestText([...hdrs, `mut=${prov?.authMutated === true ? (authMutation?.kind ?? 'mutated') : 'none'}`, `caller=${(prov?.callerAuthHeaderNames ?? []).join(',')}`, `vault=${(prov?.vaultHeaderNames ?? []).join(',')}`, `jar=${(prov?.jarCookieNames ?? []).join(',')}`, ...(bodyTokenDigest ? [`bodyTok=${bodyTokenDigest}`] : [])].join('|'))
}

const authRequestText = (ex: BrokerExchangeResult, extra?: string): string => [ex.pathAndQuery, ...Object.entries(ex.reqHeaders ?? {}).map(([k, v]) => `${k}:${v}`), extra ?? ''].join('\n').toLowerCase()
const TOKEN_MINT_KEY_RE = /^(?:access_?token|id_?token|session_?token|jwt|bearer_?token|auth_?token)$/i
const TOKEN_MINT_DISQ_RE = /^(?:job_?id|export_?id|task_?id|upload_?id|delivery_?id|webhook_?id|signed_?url|presigned_?url|download_?url|url|href|link|location|error|err|errorCode|error_description)$/i
function isTokenMintGrant(json: unknown, status: number, method: string, secretMatches?: readonly unknown[], minted?: readonly string[], reqBody?: string): boolean {
  if (status !== 200 || !/^(?:POST|PUT)$/i.test(method) || !json || typeof json !== 'object' || Array.isArray(json)) return false
  const entries = Object.entries(json as Record<string, unknown>)
  if (entries.some(([k, v]) => TOKEN_MINT_DISQ_RE.test(k) || ((k === 'ok' || k === 'success' || k === 'valid' || k === 'authenticated' || k === 'active' || k === 'verified') && v === false))) return false
  return entries.some(([k, v]) => {
    if (!TOKEN_MINT_KEY_RE.test(k) || typeof v !== 'string') return false
    const tv = v.trim()
    if (minted?.includes(tv) || (reqBody && tv.length >= 8 && reqBody.includes(tv))) return false
    return tv.length >= 12 || (/^\[redacted(?::[^\]]+)?\]$/i.test(tv) && (secretMatches?.length ?? 0) > 0)
  })
}

function hasAuthPrivilegeEscalation(cJson: unknown, pJson: unknown): boolean {
  if (!cJson || typeof cJson !== 'object' || Array.isArray(cJson) || !pJson || typeof pJson !== 'object' || Array.isArray(pJson)) return false
  const c = cJson as Record<string, unknown>, p = pJson as Record<string, unknown>
  if (p.ok === false || p.authenticated === false || p.success === false || p.valid === false || Boolean(p.error || p.err || p.errorCode || p.error_description)) return false
  if (PRIV_BOOL_KEYS.some(k => p[k] === true && c[k] !== true)) return true
  if (ROLE_STR_KEYS.some(k => typeof c[k] === 'string' && typeof p[k] === 'string' && c[k] !== p[k] && ((rolePrivilegeRank(p[k] as RoleName) ?? -1) > (rolePrivilegeRank(c[k] as RoleName) ?? 99) || (ELEVATED_SCOPE_RE.test(p[k]) && !ELEVATED_SCOPE_RE.test(c[k]))))) return true
  if ((['roles', 'scopes', 'permissions'] as const).some(k => Array.isArray(p[k]) && (p[k] as unknown[]).some(v => ELEVATED_SCOPE_RE.test(String(v)) && !new Set((Array.isArray(c[k]) ? c[k] : []).map(x => String(x).toLowerCase())).has(String(v).toLowerCase())))) return true
  return IDENTITY_CLAIM_KEYS.some(k => typeof c[k] === 'string' && typeof p[k] === 'string' && c[k].trim().length > 0 && p[k].trim().length > 0 && c[k] !== p[k])
}

/** auth_protocol_proof Tier-1 verdict (zero-jq): OOB witness, signature_validity wire diff, access_differential, or request-injected redirect canary. */
export function authProtocolTier1Decision(input: {
  control?: { exchange: BrokerExchangeResult; exchangeId: string; requestText?: string; requestBody?: string }
  probe?: { exchange: BrokerExchangeResult; exchangeId: string; authMutation?: AuthMutation; requestText?: string; requestBody?: string }
  origin?: string; hasTokenMints?: boolean; mintedTokenValues?: readonly string[]; oob?: { triggered: boolean; controlTriggered: boolean; token: string }
}): UniversalPrimitiveDecision {
  const signer = tier1HostSigner(), verifySignature = signer.verify
  if (!input.control || !input.probe) return { primitive: 'access_differential', required: true, satisfied: false, reason: 'missing_control_or_probe_exchange' }
  const cEx = input.control.exchange, pEx = input.probe.exchange
  const cRec = exchangeRecord(signer, input.control.exchangeId, 1, cEx), pRec = exchangeRecord(signer, input.probe.exchangeId, 2, pEx)
  if (input.oob) {
    const witness = input.oob.triggered ? signer.sign({ id: `${input.probe.exchangeId}:oob`, timestampMs: 3, status: 200, surface: 'webhook' }) : undefined
    return evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'oob_callback', trigger: pRec, witness: witness as HostSignedRecord, hostCanary: input.oob.token, observedCanary: input.oob.triggered ? input.oob.token : null, control: cRec, controlObservedCanary: input.oob.controlTriggered ? input.oob.token : null, verifySignature })
  }
  const bodyTokenForged = hasBodyMintedTokenDiff(input.control.requestBody, input.probe.requestBody, input.mintedTokenValues)
  const hasMutation = Boolean(input.probe.authMutation?.kind || input.hasTokenMints)
  const cWire = authWireFingerprint(cEx, undefined, bodyTokenForged ? digestText(input.control.requestBody!) : undefined)
  const pWire = authWireFingerprint(pEx, input.probe.authMutation, bodyTokenForged ? digestText(input.probe.requestBody!) : undefined)
  if (cEx.status === 401 || cEx.status === 403) {
    if (!hasMutation) return evaluateUniversalPrimitive('access_differential', { control: cRec, variant: pRec, bindRoute: true, requireChronology: true, verifySignature })
    const res = evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'signature_validity', control: cRec, variant: pRec, controlWireValue: cWire, variantWireValue: pWire, bindActor: true, verifySignature })
    return !res.satisfied && res.reason === 'terminal_impact_unproven_intermediate_stub' && (bodyTokenForged || pEx.wireCredentialProvenance?.authMutated === true) && isTokenMintGrant(pRec.json, pEx.status, pEx.method, pEx.secretMatches, input.mintedTokenValues, input.probe.requestBody)
      ? { ...res, satisfied: true, reason: 'wire_differential_token_mint_confirmed', evidence: { controlId: cRec.id, variantId: pRec.id } }
      : res
  }
  if (pEx.status >= 300 && pEx.status < 400) {
    const loc = Object.entries(pEx.respHeaders ?? {}).find(([k]) => k.toLowerCase() === 'location')?.[1]?.trim() ?? ''
    let locHost = '', targetHost = ''
    try { if (/^https?:\/\//i.test(loc) || loc.startsWith('//')) locHost = new URL(loc.startsWith('//') ? `https:${loc}` : loc).hostname.toLowerCase() } catch { /* ignore */ }
    try { if (input.origin || pEx.origin) targetHost = new URL(input.origin ?? pEx.origin).hostname.toLowerCase() } catch { /* ignore */ }
    if (locHost.length >= 8 && locHost !== targetHost && authRequestText(pEx, input.probe.requestText).includes(locHost) && !authRequestText(cEx, input.control.requestText).includes(locHost)) {
      return evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'redirect_canary', trigger: pRec, witness: pRec, hostCanary: locHost, observedCanary: null, control: cRec, verifySignature })
    }
  }
  if (cEx.status >= 200 && cEx.status < 300 && pEx.status >= 200 && pEx.status < 300 && hasMutation) {
    if (!signer.verify(cRec) || !signer.verify(pRec)) return { primitive: 'wire_framing_and_cache_differential', required: true, satisfied: false, reason: 'invalid_host_signature' }
    if (cRec.route !== pRec.route) return { primitive: 'wire_framing_and_cache_differential', required: true, satisfied: false, reason: 'control_and_variant_route_mismatch' }
    if (!cRec.actorId || cRec.actorId !== pRec.actorId) return { primitive: 'wire_framing_and_cache_differential', required: true, satisfied: false, reason: 'control_and_variant_actor_mismatch' }
    if (cWire === pWire) return { primitive: 'wire_framing_and_cache_differential', required: true, satisfied: false, reason: 'no_wire_differential_between_control_and_variant' }
    if (!hasAuthPrivilegeEscalation(cRec.json, pRec.json)) return { primitive: 'wire_framing_and_cache_differential', required: true, satisfied: false, reason: 'no_privilege_escalation_in_200_response' }
    return { primitive: 'wire_framing_and_cache_differential', subRule: 'signature_validity', required: true, satisfied: true, reason: 'wire_differential_privilege_escalation_confirmed', evidence: { controlId: cRec.id, variantId: pRec.id } }
  }
  return { primitive: hasMutation ? 'wire_framing_and_cache_differential' : 'access_differential', required: true, satisfied: false, reason: pEx.status >= 200 && pEx.status < 300 ? 'control_not_denied' : 'variant_rejected' }
}

/**
 * Cut 3e typed runner for `auth_protocol_proof` (zero-jq, Tier-1 universal primitive gated).
 */
export async function runAuthProtocolProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'auth_protocol_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'auth')
  const basePayload: Record<string, unknown> = { kind: spec.kind, origin: spec.origin, replayedAt: new Date().toISOString() }
  const vars: Record<string, string> = {}, stepsOut: Record<string, unknown> = {}
  const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult; exchangeId: string; request: BrokerHttpRequest; authMutation?: AuthMutation }> = []
  const replayJarPrefix = randomUUID().slice(0, 8)
  let firstControlStep: Record<string, unknown> | undefined, firstProbeStep: Record<string, unknown> | undefined
  let firstControlExchange: { exchange: BrokerExchangeResult; exchangeId: string; requestText?: string; requestBody?: string } | undefined

  const mintedTokens: Array<{ name: string; alg: string }> = []
  if (spec.tokenMints?.length) {
    const nowSeconds = Math.floor(Date.now() / 1000)
    vars.now = String(nowSeconds)
    vars.now_plus_1h = String(nowSeconds + 3600)
    for (const mint of spec.tokenMints) {
      const header = { alg: mint.signature === 'none' ? 'none' : 'HS256', typ: 'JWT', ...(mint.header ?? {}) }
      const resolveClaims = (value: unknown): unknown => {
        if (value === '{{now}}') return nowSeconds
        if (value === '{{now_plus_1h}}') return nowSeconds + 3600
        if (Array.isArray(value)) return value.map(resolveClaims)
        if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, resolveClaims(v)]))
        return value
      }
      const headerJson = interpolateValue(resolveClaims(header), vars) as Record<string, unknown>
      const payloadJson = interpolateValue(resolveClaims(mint.payload), vars) as Record<string, unknown>
      vars[mint.name] = `${runnerBase64urlJson(headerJson)}.${runnerBase64urlJson(payloadJson)}.`
      mintedTokens.push({ name: mint.name, alg: String(headerJson.alg ?? 'none') })
    }
  }

  const serializedSteps = JSON.stringify(spec.steps)
  const needsCanary = spec.steps.some(s => s.request.authMutation?.kind === 'jku_x5u_canary') || /\{\{canary_(?:url|token|dns_host)\}\}/.test(serializedSteps)
  let canarySession: EphemeralCanarySession | undefined
  let ctrlCanary: { url: string; token: string; dnsHost: string } | undefined
  let prbCanary: { url: string; token: string; dnsHost: string } | undefined
  let forcedInconclusiveReason: string | null = null, deterministicProofPassed = true, proofFailureReason = ''

  try {
    if (needsCanary) {
      canarySession = await openCanarySession(ctx.canaryBroker, ctx.storage, ctx.runId, ctx.assignmentId, spec.origin)
      ctrlCanary = canarySession.mint(`auth_protocol_proof:control:${spec.title}`)
      prbCanary = canarySession.mint(`auth_protocol_proof:probe:${spec.title}`)
    }

    const injectedAtMs = Date.now()
    for (const step of spec.steps) {
      ctx.signal.throwIfAborted()
      const stepVars: Record<string, string> = { ...vars }
      if (ctrlCanary && prbCanary) {
        const activeCanary = step.role === 'control' ? ctrlCanary : prbCanary
        stepVars.canary_url = activeCanary.url; stepVars.canary_token = activeCanary.token; stepVars.canary_dns_host = activeCanary.dnsHost
      }
      const brokerReq = stepToBrokerRequest(step, stepVars, { replayJarPrefix, runId: ctx.runId, assignmentId: ctx.assignmentId })
      if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
        brokerReq.authMutation = { ...brokerReq.authMutation, url: step.role === 'control' ? ctrlCanary.url : prbCanary.url }
      }
      const ex = await ctx.broker.executeHttp(brokerReq, ctx.grant, ctx.signal)
      const exId = recordExchange(ex)
      extractVariables(step, ex, vars)
      const stepEntry: Record<string, unknown> = { id: step.id, role: step.role, ...summarizeExchange(ex) }
      stepsOut[step.id] = stepEntry
      if (step.role === 'control' && !firstControlStep) { firstControlStep = stepEntry; firstControlExchange = { exchange: ex, exchangeId: exId, requestText: `${brokerReq.pathAndQuery}\n${brokerReq.body ?? ''}`, ...(brokerReq.body !== undefined ? { requestBody: brokerReq.body } : {}) } }
      if (step.role === 'probe') {
        if (!firstProbeStep) firstProbeStep = stepEntry
        probeStepExchanges.push({ id: step.id, exchange: ex, exchangeId: exId, request: brokerReq, authMutation: step.request.authMutation })
      }
    }

    const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
    if (guardControlErrors) {
      for (const step of spec.steps) {
        if (step.role !== 'control' && step.role !== 'probe') continue
        const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
        if (typeof status === 'number' && isUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
          forcedInconclusiveReason = `Unexpected HTTP ${status} on ${step.role} step "${step.id}" (requireControlNonError); declare expectedStatus ${status} to test error behavior.`
          break
        }
      }
    }

    let canaryProof: Record<string, unknown> | undefined
    let oobReceiptCheck: ReplayVerificationResult['receipt']
    let oobWitness: { triggered: boolean; controlTriggered: boolean; token: string } | undefined
    if (canarySession && prbCanary && ctrlCanary) {
      const probeWait = await canarySession.waitForCallback(prbCanary.token, ctx.signal)
      const controlCheck = canarySession.check(ctrlCanary.token)
      oobWitness = { triggered: probeWait.triggered, controlTriggered: controlCheck.triggered, token: prbCanary.token }
      deterministicProofPassed = probeWait.triggered && !controlCheck.triggered
      if (!deterministicProofPassed) proofFailureReason = 'auth_protocol_proof OOB canary callback did not trigger exclusively on probe step.'
      canaryProof = { probeTriggered: probeWait.triggered, probeStage: probeWait.stage, probePromoted: probeWait.promoted, controlTriggered: controlCheck.triggered, probeDetail: probeWait.detail, controlDetail: controlCheck.detail }
      const primaryProbe = probeStepExchanges[0]
      if (primaryProbe) {
        const carrierExtra = primaryProbe.request.authMutation?.kind === 'jku_x5u_canary' ? (primaryProbe.request.authMutation.url ?? primaryProbe.request.authMutation.value ?? '') : ''
        oobReceiptCheck = evaluateRunnerOobReceipt({
          origin: spec.origin, stepId: primaryProbe.id, exchange: primaryProbe.exchange, exchangeId: primaryProbe.exchangeId, request: primaryProbe.request,
          oobEventId: 'auth-oob-canary', callbackPrefix: 'auth', token: prbCanary.token, probeWait, controlTriggered: controlCheck.triggered,
          claimedDelta: 'Auth protocol token header triggered an out-of-band canary fetch on probe only.', injectedAtMs, carrierExtra,
        })
        if (!oobReceiptCheck.verification.confirmed) { deterministicProofPassed = false; proofFailureReason = oobReceiptCheck.verification.reason }
      }
    }

    let spaCatchall: Record<string, unknown> | undefined
    if (spec.spaCatchallControl) {
      const catchall = await runRunnerSpaCatchall({ origin: spec.origin, ctx, recordExchange, targets: probeStepExchanges })
      spaCatchall = catchall.summary
      if (catchall.allProbesMatchedCatchall) forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
    }

    const authSteps = impactStepsFromStepsOut(spec, stepsOut)
    const authBoundaryClass = canaryProof ? 'other' as const : classifyBoundaryClaim({ cwe: spec.cwe, category: spec.category, title: spec.title, impact: spec.impact })
    const authBoundaryGate = authBoundaryClass === 'mfa'
      ? assessMfaBypass({ impactClass: 'other', steps: authSteps, targetOrigin: spec.origin })
      : authBoundaryClass === 'auth' || authBoundaryClass === 'access'
        ? assessBoundary({ impactClass: 'other', steps: authSteps, boundaryClass: authBoundaryClass, expectControlDenied: spec.expectControlDenied, targetOrigin: spec.origin })
        : null
    if (authBoundaryGate?.required && !authBoundaryGate.satisfied) { deterministicProofPassed = false; proofFailureReason = authBoundaryGate.reason }

    const primaryProbe = probeStepExchanges[probeStepExchanges.length - 1]
    const primitive = authProtocolTier1Decision({
      origin: spec.origin,
      control: firstControlExchange,
      probe: primaryProbe ? { exchange: primaryProbe.exchange, exchangeId: primaryProbe.exchangeId, authMutation: primaryProbe.authMutation, requestText: `${primaryProbe.request.pathAndQuery}\n${primaryProbe.request.body ?? ''}`, ...(primaryProbe.request.body !== undefined ? { requestBody: primaryProbe.request.body } : {}) } : undefined,
      hasTokenMints: Boolean(spec.tokenMints?.length),
      ...(mintedTokens.length > 0 ? { mintedTokenValues: mintedTokens.map(m => vars[m.name]).filter((v): v is string => typeof v === 'string' && v.length > 0) } : {}),
      ...(oobWitness ? { oob: oobWitness } : {}),
    })
    if (!primitive.satisfied) {
      deterministicProofPassed = false
      proofFailureReason = proofFailureReason || `tier1_primitive_rejected: ${primitive.primitive} ${primitive.reason}`
    }

    const evidencePayload = redactJsonValue({
      ...basePayload, protocol: spec.protocol, steps: stepsOut,
      ...(firstControlStep ? { control: firstControlStep } : {}), ...(firstProbeStep ? { probe: firstProbeStep } : {}),
      extractedVars: vars, ...(mintedTokens.length > 0 ? { mintedTokens } : {}), ...(canaryProof ? { canaryProof } : {}),
      ...(spaCatchall ? { spaCatchall } : {}), ...(authBoundaryGate ? { boundaryGate: authBoundaryGate } : {}),
      tier1Primitive: { primitive: primitive.primitive, subRule: primitive.subRule, satisfied: primitive.satisfied, reason: primitive.reason },
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload, null, 2)).digest('hex')
    const receiptExtra = oobReceiptCheck ? { receipt: oobReceiptCheck } : {}
    const controlStatus = (firstControlStep as { status?: number } | undefined)?.status ?? null
    const controlPassed = forcedInconclusiveReason === null && controlStatus !== null && controlStatus >= 200 && controlStatus < 500
    const expected = canaryProof ? 'Token header URL is never fetched.' : 'Invalid, forged, or unauthorized protocol token is rejected.'
    if (forcedInconclusiveReason) {
      return runnerResult('inconclusive', { confirmed: false, controlPassed: false, observed: canaryProof ? 'oob_canary' : `status=${primaryProbe?.exchange.status ?? 'none'}`, expected, reason: forcedInconclusiveReason }, exchanges, exchangeIds, evidencePayload, evidenceSha256, receiptExtra)
    }
    if (deterministicProofPassed && controlPassed) {
      const observed = canaryProof ? 'jku_x5u_oob_confirmed' : `auth_protocol_tier1_confirmed (${primitive.primitive}:${primitive.subRule ?? 'ok'}, probeStatus=${primaryProbe?.exchange.status ?? 'none'})`
      return runnerResult('confirmed', { confirmed: true, controlPassed: true, observed, expected }, exchanges, exchangeIds, evidencePayload, evidenceSha256, receiptExtra)
    }
    const observed = canaryProof ? 'jku_x5u_oob_not_triggered' : `auth_protocol_rejected (${primitive.reason}, probeStatus=${primaryProbe?.exchange.status ?? 'none'})`
    return runnerResult(controlPassed ? 'dismissed' : 'inconclusive', { confirmed: false, controlPassed, observed, expected, reason: proofFailureReason || 'Auth protocol Tier-1 proof did not pass.' }, exchanges, exchangeIds, evidencePayload, evidenceSha256, receiptExtra)
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  } finally {
    await canarySession?.close()
  }
}

/** Direct zero-jq Tier-1 runner dispatch for non-recipe floor spec kinds (`rce_proof`, `cache_differential`, `auth_protocol_proof`). */
export async function runTypedFloorSpec(spec: DeclarativeReplaySpec, ctx: LegacySpecRunnerContext): Promise<ReplayVerificationResult | null> {
  if (spec.kind === 'rce_proof') return runRceProofRecipe(spec, ctx)
  if (spec.kind === 'cache_differential') return runCacheDifferentialRecipe(spec, ctx)
  if (spec.kind === 'auth_protocol_proof') return runAuthProtocolProofRecipe(spec, ctx)
  return null
}

// ---------------------------------------------------------------------------------------------
// Verification assessment + receipt helpers (moved from replay-verifier.ts, Cut 3f)
//
// These helpers implement the legacy declarative VM's impact/proof-strength gates and the receipt
// gate. They live with the recipe engine so `replay-verifier.ts` stays a thin validation/dispatch
// module; every public symbol is re-exported from the verifier.
// ---------------------------------------------------------------------------------------------

function interpolateString(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g, (full, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : full)
}

function interpolateValue(value: unknown, vars: Record<string, string>): unknown {
  if (typeof value === 'string') return interpolateString(value, vars)
  if (Array.isArray(value)) return value.map(v => interpolateValue(v, vars))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = interpolateValue(v, vars)
    }
    return out
  }
  return value
}

function readJsonPath(obj: unknown, path: string): string | null {
  const clean = path.replace(/^\$\.?/, '')
  const segments = clean.split('.').filter(Boolean)
  let cur: unknown = obj
  for (const seg of segments) {
    if (cur === null || cur === undefined) return null
    const arrayMatch = seg.match(/^([a-zA-Z0-9_-]*)\[(\d+)\]$/)
    if (arrayMatch) {
      const [, key, idxStr] = arrayMatch
      if (key) cur = (cur as Record<string, unknown>)[key]
      if (!Array.isArray(cur)) return null
      cur = cur[Number(idxStr)]
    } else if (typeof cur === 'object') {
      cur = (cur as Record<string, unknown>)[seg]
    } else {
      return null
    }
  }
  if (cur === null || cur === undefined) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

export function extractVariables(step: ReplayStep, exchange: BrokerExchangeResult, vars: Record<string, string>) {
  for (const rule of step.extract ?? []) {
    let extracted: string | null = null
    if (rule.from === 'status') {
      extracted = String(exchange.status)
    } else if (rule.from === 'header') {
      extracted = exchange.respHeaders[rule.selector.toLowerCase()] ?? null
    } else if (rule.from === 'json') {
      try {
        const parsed = JSON.parse(exchange.body) as unknown
        extracted = readJsonPath(parsed, rule.selector)
      } catch {
        extracted = null
      }
    } else if (rule.from === 'regex') {
      try {
        const re = new RegExp(rule.selector)
        const m = exchange.body.match(re)
        extracted = m ? (m[1] ?? m[0] ?? null) : null
      } catch {
        extracted = null
      }
    }
    if (extracted !== null) vars[rule.varName] = extracted.slice(0, 512)
  }
}

const BFLA_CWE_RE = /^CWE-(?:285|269|862|863)$/i
const BFLA_TEXT_RE = /\b(?:bfla|broken function[- ]level|function[- ]level|privilege escalation|vertical access)\b/i
const READ_ONLY_REPLAY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const MUTATING_REPLAY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export interface BflaImpactAssessment {
  required: boolean
  satisfied: boolean
  reason: string
  evidence?: Record<string, unknown>
}

function normalizedReplayPath(value: string | undefined): string {
  if (!value) return ''
  return value.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/'
}

/** Parse the body the host actually sent, including form/XML carriers, for shared impact oracles. */
function recordedRequestJson(entry: Record<string, unknown> | undefined, request: ReplayStep['request']): unknown {
  const raw = typeof entry?.requestBody === 'string' ? entry.requestBody : request.textBody
  if (raw === undefined) return request.jsonBody
  const contentType = String(entry?.requestHeaders && typeof entry.requestHeaders === 'object'
    ? Object.entries(entry.requestHeaders as Record<string, unknown>).find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? ''
    : Object.entries(request.headers ?? {}).find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? '')
  if (/application\/x-www-form-urlencoded/i.test(contentType)) {
    return Object.fromEntries(new URLSearchParams(raw).entries())
  }
  if (/json/i.test(contentType) || /^(?:\{|\[)/.test(raw.trim())) {
    try { return JSON.parse(raw) } catch { return raw }
  }
  return raw
}

/**
 * Map recorded replay steps onto the shared evidence model. Role/tenant/auth metadata is enriched
 * into each step summary at record time (see `personaActorFields`), so the same validators can run
 * on a spec whose persona handles are opaque.
 */
export function impactStepsFromStepsOut(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): ImpactStep[] {
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return []
  return spec.steps.map(step => {
    const entry = stepsOut[step.id] as Record<string, unknown> | undefined
    const handle = (typeof entry?.personaHandle === 'string' ? entry.personaHandle : null) ?? step.request.persona ?? null
    const declaredRole = typeof entry?.actorRole === 'string' ? normalizeRole(entry.actorRole) : null
    let entryJson = entry?.json ?? null
    if (entryJson === null && typeof entry?.body === 'string') {
      // Unit-level callers may provide only the recorded body; parse it so the shared validators
      // see the same shape the wire recorder produces.
      try { entryJson = JSON.parse(entry.body) } catch { entryJson = null }
    }
    return {
      id: step.id,
      arm: step.role,
      method: step.request.method.toUpperCase(),
      route: normalizedReplayPath(typeof entry?.pathAndQuery === 'string' ? entry.pathAndQuery : step.request.pathAndQuery),
      pathAndQuery: typeof entry?.pathAndQuery === 'string' ? entry.pathAndQuery : step.request.pathAndQuery,
      status: typeof entry?.status === 'number' ? entry.status : null,
      actor: {
        handle,
        role: declaredRole ?? normalizeRole(step.request.persona),
        tenant: typeof entry?.actorTenant === 'string' ? entry.actorTenant : null,
        auth: (typeof entry?.ambientAuth === 'string' ? entry.ambientAuth : 'unknown') as AmbientAuth,
        sameSite: typeof entry?.sessionSameSite === 'string' ? entry.sessionSameSite : null,
      } satisfies ActorIdentity,
      json: entryJson,
      body: typeof entry?.body === 'string' ? entry.body : '',
      ...(Array.isArray(entry?.secretMatches)
        ? { secretMatches: (entry.secretMatches as Array<Record<string, unknown>>).map(match => String(match.sha256Prefix ?? '')).filter(Boolean) }
        : {}),
      requestJson: recordedRequestJson(entry, step.request),
      requestHeaders: (entry?.requestHeaders as Record<string, string> | undefined) ?? step.request.headers ?? null,
      responseHeaders: (entry?.headers as Record<string, string> | undefined) ?? null,
    }
  })
}

/**
 * Vertical (function-level) BFLA needs *impact*, not just a 2xx from a lower-privileged actor.
 * A read-only route that every authenticated role may legitimately read must never confirm as
 * privilege escalation: the replay must show a role/tenant differential *and* a real side effect
 * (or an owner-scoped disclosure for reads). Object-level BOLA (CWE-639) is handled by the shared
 * impact gate, not here.
 */
export function assessBflaImpact(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): BflaImpactAssessment {
  if (spec.kind !== 'http_chain') {
    return { required: false, satisfied: true, reason: 'Not an HTTP chain replay spec.' }
  }
  const descriptor = `${spec.cwe} ${spec.category} ${spec.title} ${spec.impact} ${spec.severityRationale}`
  const vertical = BFLA_CWE_RE.test(spec.cwe) || BFLA_TEXT_RE.test(descriptor)
  if (!vertical || spec.steps.length < 2) {
    return { required: false, satisfied: true, reason: 'Not a function-level BFLA proof.' }
  }
  const assessment = assessImpactEvidence({
    impactClass: 'bfla',
    steps: impactStepsFromStepsOut(spec, stepsOut),
    requiredRole: spec.requiredRole ?? null,
    resourceTenant: spec.resourceTenant ?? null,
    expectControlDenied: spec.expectControlDenied,
    oracleEvents: spec.expectedImpactEvents,
    targetOrigin: spec.origin,
  })
  return {
    required: true,
    satisfied: assessment.satisfied,
    reason: assessment.reason,
    ...(assessment.evidence ? { evidence: assessment.evidence } : {}),
  }
}

// ---------------------------------------------------------------------------
// v5.1 Slice 4 — proof-strength + endpoint-binding guards for LLM-authored
// http_chain specs. These guards are strictly additive: they can only turn a
// would-be confirmation into `inconclusive`, never the other way around.
// ---------------------------------------------------------------------------

type HttpChainSpec = Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>

/** Vertical/horizontal authorization claims, identified by CWE or category only (never free text). */
const AUTHZ_CWE_RE = /^CWE-(?:269|284|285|566|639|862|863|1220)$/i
const AUTHZ_CATEGORY_RE = /(?:^|[-_\s])(?:broken[-_\s]?access[-_\s]?control|access[-_\s]?control|idor|bola|bfla|authori[sz]ation|privilege[-_\s]?escalation|tenant[-_\s]?isolation)(?:$|[-_\s])/i

function isAuthorizationClaim(spec: HttpChainSpec): boolean {
  return AUTHZ_CWE_RE.test(spec.cwe) || AUTHZ_CATEGORY_RE.test(spec.category)
}

export type HttpChainAssertionEvidence = 'status_only' | 'unbound_content' | 'content_bound'

/**
 * Classify what the jq assertion actually proves. `status_only` inspects nothing but status codes;
 * `unbound_content` reads a body/header without binding it to an identifier, extracted variable or
 * field comparison (a dynamic page differs on every request); `content_bound` compares structured
 * fields, extracted identifiers, canary/canary-fingerprint evidence or secret fingerprints.
 */
export function classifyHttpChainAssertion(program: string): HttpChainAssertionEvidence {
  const fields = new Set<string>()
  for (const match of program.matchAll(/\.steps\.[A-Za-z0-9_-]+\.([A-Za-z0-9_]+)/g)) {
    fields.add(match[1].toLowerCase())
  }
  const contentFields = [...fields].filter(field =>
    field !== 'status' && field !== 'statuses' && field !== 'id' && field !== 'role' && field !== 'batchcount')
  const topLevelProof = /\.(?:proofMatches|extractedVars|secretMatches|canary|cacheProof|uploadProof|cryptographicProofPassed)\b/.test(program)
  if (contentFields.length === 0) return topLevelProof ? 'content_bound' : 'status_only'
  if (fields.has('json') || fields.has('secretmatches')) return 'content_bound'
  const identifierBound = topLevelProof ||
    /\$[A-Za-z_][A-Za-z0-9_]*/.test(program) ||
    /\.(?:body|bodyPreview)\s*\|\s*(?:index|contains|startswith|endswith|test|match|capture|split|ltrimstr|rtrimstr)\s*\(/.test(program) ||
    /\b(?:index|contains|startswith|endswith)\s*\(\s*(?:"[^"]*"|\$[A-Za-z_])/.test(program)
  if (identifierBound) return 'content_bound'
  // A body/header byte-length differential is structural (a masked value cannot be longer than the
  // value it masks); any other unbound body/header read is only a "different body" observation.
  if (fields.has('bodybytes')) return 'content_bound'
  return 'unbound_content'
}

interface JsonFieldRef {
  stepId: string
  path: string[]
}

/** Extract `.steps.<id>.json.<field>` / `.json["field"]` references (bounded, no array indexes). */
function referencedJsonPaths(program: string): JsonFieldRef[] {
  const out: JsonFieldRef[] = []
  const seen = new Set<string>()
  const refPattern = /\.steps\.([A-Za-z0-9_-]+)\.json((?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:"[^"]{1,64}"|\d{1,3})\])+)/g
  for (const match of program.matchAll(refPattern)) {
    const segments = [...match[2].matchAll(/\[(?:"([^"]{1,64})"|\d{1,3})\]|\.([A-Za-z_][A-Za-z0-9_]*)/g)]
    if (segments.some(seg => seg[1] === undefined && seg[2] === undefined)) continue
    if (/\[\d{1,3}\]/.test(match[2])) continue
    const path = segments.map(seg => seg[1] ?? seg[2]).filter((seg): seg is string => Boolean(seg))
    if (path.length === 0) continue
    const key = `${match[1]}|${path.join('.')}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ stepId: match[1], path })
    if (out.length >= 24) break
  }
  return out
}

function readJsonField(json: unknown, path: readonly string[]): string | null {
  let cur: unknown = json
  for (const segment of path) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur)) return null
    cur = (cur as Record<string, unknown>)[segment]
  }
  if (cur === undefined || cur === null) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

/** Non-secret quoted literals used by the assertion, for identifier-bound marker disclosure checks. */
function jqStringLiterals(program: string): string[] {
  const out = new Set<string>()
  for (const match of program.matchAll(/"((?:[^"\\]|\\.){8,120})"/g)) {
    const value = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\')
    if (!value || /[\r\n\0]/.test(value)) continue
    if (/^(?:application\/json|content-type|content-security-policy)$/i.test(value)) continue
    out.add(value)
    if (out.size >= 8) break
  }
  return [...out]
}

function normalizeOriginValue(value: string | undefined): string {
  if (!value) return ''
  try {
    const url = new URL(value)
    return `${url.protocol}//${url.host.toLowerCase()}`
  } catch {
    return value.trim().toLowerCase().replace(/\/+$/, '')
  }
}

function originHost(value: string | undefined): string {
  try {
    return value ? new URL(value).host.toLowerCase() : ''
  } catch {
    return ''
  }
}

interface HttpChainStepSnapshot {
  index: number
  id: string
  role: string
  method: string
  route: string
  pathAndQuery: string
  actor: string
  status: number | null
  body: string
  bodyBytes: number
  mediaType: string
  json: unknown
  requestJson?: unknown
  requestBody?: string
  requestHeaders?: Record<string, string> | null
  secretMatches: number
}

export function isSuccessStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

export type HttpChainDifferential =
  | 'denied_then_allowed'
  | 'cross_actor_access'
  | 'field_bound'
  | 'state_delta'
  | 'identifier_proof'
  | null

export interface HttpChainProofStrength {
  claim: 'authorization' | 'other'
  assertionEvidence: HttpChainAssertionEvidence
  differential: HttpChainDifferential
  satisfied: boolean
  reason: string
}

function detectHttpChainDifferential(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainDifferential {
  const controls = snapshots.filter(step => step.role === 'control')
  const probes = snapshots.filter(step => step.role === 'probe')
  const dataBearing = (step: HttpChainStepSnapshot) => isSuccessStatus(step.status) && step.bodyBytes >= 8
  const sameRoute = (a: HttpChainStepSnapshot, b: HttpChainStepSnapshot) =>
    a.method === b.method && a.route === b.route && a.route !== ''
  const denied = (step: HttpChainStepSnapshot) => step.status === 401 || step.status === 403
  // A control that is bounced (login/SSO redirect) did not receive the resource either.
  const bounced = (step: HttpChainStepSnapshot) =>
    step.status !== null && step.status >= 300 && step.status < 400

  // 1. The same endpoint is denied to the control caller and served to the probe caller.
  if (probes.some(probe => dataBearing(probe) && controls.some(control => sameRoute(control, probe) && (denied(control) || bounced(control))))) {
    return 'denied_then_allowed'
  }

  // 2. A different actor reaches the exact endpoint the control actor reached.
  if (probes.some(probe => dataBearing(probe) && controls.some(control =>
    sameRoute(control, probe) && control.actor !== probe.actor && (isSuccessStatus(control.status) || denied(control))))) {
    return 'cross_actor_access'
  }

  // 3. A declared response field carries a different value for the probe than for the control.
  const assertionsJq = spec.assertionsJq ?? ''
  for (const ref of referencedJsonPaths(assertionsJq)) {
    const probe = probes.find(step => step.id === ref.stepId && isSuccessStatus(step.status))
    if (!probe) continue
    const probeValue = readJsonField(probe.json, ref.path)
    if (probeValue === null) continue
    if (controls.some(control => control.status !== null && readJsonField(control.json, ref.path) !== probeValue)) {
      return 'field_bound'
    }
  }

  // 4. A privileged mutation succeeds and a later read observes the mutated state (or its removal).
  const mutatingProbe = probes.find(step => MUTATING_REPLAY_METHODS.has(step.method) && isSuccessStatus(step.status))
  if (mutatingProbe) {
    const reads = snapshots.filter(step => READ_ONLY_REPLAY_METHODS.has(step.method) && step.index !== mutatingProbe.index)
    const before = [...reads].reverse().find(step => step.index < mutatingProbe.index && isSuccessStatus(step.status) && step.bodyBytes > 0)
    const after = reads.find(step => step.index > mutatingProbe.index)
    if (before && after) {
      if ((after.status !== null && after.status >= 400) || (after.bodyBytes > 0 && after.body !== before.body)) {
        return 'state_delta'
      }
    }
  }

  // 5. Identifier-bound proof: pre-redaction secret fingerprints or an asserted marker observed only
  //    in the probe response.
  if (probes.some(step => isSuccessStatus(step.status) && step.secretMatches > 0)) return 'identifier_proof'
  const controlBodies = controls.map(step => step.body)
  for (const literal of jqStringLiterals(assertionsJq)) {
    if (probes.some(step => step.body !== '' && step.body.includes(literal)) &&
        !controlBodies.some(body => body.includes(literal))) {
      return 'identifier_proof'
    }
  }

  return null
}

/**
 * Proof-strength gate for authorization `http_chain` specs. A status-only claim (or a bare
 * "the body differs" claim) is never a control-vs-probe differential, and a content assertion must
 * be backed by an observable differential in the recorded exchanges (denied-then-allowed,
 * cross-actor access, field-bound value change, state delta, or identifier-bound proof).
 */
export function assessHttpChainProofStrength(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainProofStrength {
  const assertionEvidence = classifyHttpChainAssertion(spec.assertionsJq ?? '')
  // Universal status-only ban: a bare 2xx -> 4xx/5xx divergence can never confirm ANY class. The
  // injection/authz/redirect oracles still run afterwards; this is a floor, not a substitute.
  if (assertionEvidence === 'status_only') {
    const statusOnly = assessStatusOnlyDivergence(
      snapshots.map(snapshot => ({
        id: snapshot.id,
        arm: snapshot.role === 'probe'
          ? 'probe' as const
          : snapshot.role === 'control'
            ? 'control' as const
            : snapshot.role === 'cleanup'
              ? 'cleanup' as const
              : 'setup' as const,
        method: snapshot.method,
        route: snapshot.route,
        pathAndQuery: snapshot.pathAndQuery,
        status: snapshot.status,
        actor: actorFromPersona(snapshot.actor, []),
        json: snapshot.json,
        body: snapshot.body,
        ...(snapshot.requestJson !== undefined ? { requestJson: snapshot.requestJson } : {}),
        ...(snapshot.requestBody !== undefined ? { requestBody: snapshot.requestBody } : {}),
        ...(snapshot.requestHeaders ? { requestHeaders: snapshot.requestHeaders } : {}),
      })),
    )
    if (statusOnly.statusOnly) {
      return {
        claim: isAuthorizationClaim(spec) ? 'authorization' : 'other',
        assertionEvidence,
        differential: null,
        satisfied: false,
        reason: statusOnly.reason,
      }
    }
  }
  if (!isAuthorizationClaim(spec)) {
    return { claim: 'other', assertionEvidence, differential: null, satisfied: true, reason: 'Not an authorization claim.' }
  }
  if (assertionEvidence === 'status_only') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: null,
      satisfied: false,
      reason: 'Authorization claim is status-only: a 2xx status (or status equality) is not an access-control differential. Assert a cross-actor resource read, a field/identifier bound to the victim object, or a state delta.',
    }
  }
  // Canary / cryptographic proof is produced by the verifier itself (distinct control vs probe
  // tokens, non-destructive math), so it is already an identifier-bound execution differential.
  if (/\.(?:canary|proof)\b/.test(spec.assertionsJq ?? '')) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: 'identifier_proof',
      satisfied: true,
      reason: 'Authorization claim is bound to verifier-minted canary/cryptographic proof.',
    }
  }
  const differential = detectHttpChainDifferential(spec, snapshots)
  if (assertionEvidence === 'unbound_content' && differential !== 'state_delta' && differential !== 'field_bound') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim rests on a different-body observation without identifier binding; assert a field-bound value, extracted victim identifier, secret fingerprint, or state delta.',
    }
  }
  if (differential === null) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim has no genuine control-vs-probe differential in the recorded exchanges (no denied-then-allowed route, cross-actor access, field-bound change, or state delta).',
    }
  }
  return {
    claim: 'authorization',
    assertionEvidence,
    differential,
    satisfied: true,
    reason: `Authorization differential proven: ${differential}.`,
  }
}

export function summarizeExchange(ex: BrokerExchangeResult) {  let json: unknown = null
  if (ex.mediaType.includes('json')) {
    try { json = JSON.parse(ex.body) } catch { json = null }
  }
  return {
    origin: ex.origin,
    finalOrigin: ex.finalOrigin,
    redirectOrigins: ex.redirectOrigins,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    personaHandle: ex.personaHandle,
    status: ex.status,
    mediaType: ex.mediaType,
    headers: ex.respHeaders,
    setCookies: ex.setCookies,
    body: ex.body.slice(0, 64 * 1024),
    bodyPreview: ex.bodyPreview,
    bodyBytes: ex.bodyBytes,
    bodySha256: ex.bodySha256,
    durationMs: ex.durationMs,
    // Pre-redaction structural proof: fingerprints only (never the raw value), so an assertion can
    // prove a disclosed secret matched the entitled view even after the body was scrubbed.
    ...(ex.secretMatches?.length
      ? {
          secretMatches: ex.secretMatches.slice(0, 16).map(m => ({
            kind: m.kind,
            sha256Prefix: m.sha256Prefix,
            ...(m.fieldPath ? { fieldPath: m.fieldPath } : {}),
            count: m.count,
          })),
        }
      : {}),
    ...(json !== null ? { json } : {}),
  }
}

export function hasDestructiveContent(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

export const RETIRED_LEGACY_SPEC_KINDS: ReadonlySet<string> = new Set([
  'dns_takeover', 'tls_audit', 'browser_dom', 'ws_chain', 'upload_probe',
  'sql_boolean_diff', 'sql_time_diff', 'race_burst', 'browser_chain',
])
export const RETIRED_LEGACY_SPEC_REASON = 'retired_legacy_spec_kind: use kovo_verify'

export function retiredLegacyResult(
  kind: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
): ReplayVerificationResult {
  const evidencePayload = { kind, retired: true, reason: RETIRED_LEGACY_SPEC_REASON }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  return {
    verdict: 'dismissed',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: RETIRED_LEGACY_SPEC_REASON,
      expected: 'Proof submitted via kovo_verify or a wired floor recipe.',
      reason: RETIRED_LEGACY_SPEC_REASON,
    },
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
  }
}

export function inconclusiveResult(
  reason: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
  evidencePayload: Record<string, unknown>,
): ReplayVerificationResult {
  const payload = { ...evidencePayload, error: reason }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  return {
    verdict: 'inconclusive',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: reason.slice(0, 1200),
      expected: 'Clean replay execution passing control and deterministic assertions.',
      reason: reason.slice(0, 1200),
    },
    exchangeIds,
    exchanges,
    evidencePayload: payload,
    evidenceSha256,
  }
}

/**
 * Mint a throw-away signing key and a fresh timestamp, then compute the HMAC over the documented
 * canonical form. Used only for self-signed webhook proof (no real secret ever enters the spec).
 */

function applyBodySignature(interpolated: unknown, signable: NonNullable<ReplayStep['request']['bodySignature']>): unknown {
  const input = interpolated && typeof interpolated === 'object' && !Array.isArray(interpolated)
    ? { ...(interpolated as Record<string, unknown>) }
    : {}
  const key = `kovo_whk_${randomBytes(8).toString('hex')}`
  const ts = String(Math.floor(Date.now() / 1000))
  if (signable.timestampField) input[signable.timestampField] = ts
  input[signable.keyField] = key
  const withoutSig = { ...input }
  delete withoutSig[signable.signatureField]
  const event = signable.eventField
    ? withoutSig[signable.eventField]
    : (withoutSig.event ?? withoutSig.payload ?? withoutSig.data ?? withoutSig)
  const asText = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value))
  const canonical = signable.canonical === 'ts_event'
    ? `${ts}.${asText(event)}`
    : signable.canonical === 'ts_body'
      ? `${ts}.${JSON.stringify(withoutSig)}`
      : signable.canonical === 'event'
        ? asText(event)
        : JSON.stringify(withoutSig)
  input[signable.signatureField] = createHmac('sha256', key).update(canonical).digest(signable.encoding)
  return input
}

function requestShapeToBrokerRequest(
  req: ReplayStep['request'],
  vars: Record<string, string>,
  opts?: {
    sessionId?: string
    sessionGroupRole?: 'setup' | 'control' | 'probe' | 'cleanup'
    runId?: string
    assignmentId?: string
  },
): BrokerHttpRequest {
  const pathAndQuery = interpolateString(req.pathAndQuery, vars)
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    headers[k] = interpolateString(v, vars)
  }
  let body: string | undefined
  if (req.textBody !== undefined) {
    body = interpolateString(req.textBody, vars)
  } else if (req.jsonBody !== undefined) {
    const interpolated = interpolateValue(req.jsonBody, vars)
    const signable = (req as ReplayStep['request']).bodySignature
    const signed = signable ? applyBodySignature(interpolated, signable) : interpolated
    body = JSON.stringify(signed)
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
  }
  const maybeReq = req as ReplayStep['request']
  let authMutation: AuthMutation | undefined = maybeReq.authMutation
  if (authMutation && authMutation.kind === 'jku_x5u_canary') {
    const rawUrl = authMutation.url ?? authMutation.value
    const interpUrl = rawUrl !== undefined ? interpolateString(rawUrl, vars) : undefined
    authMutation = {
      ...authMutation,
      ...(authMutation.url !== undefined && interpUrl !== undefined ? { url: interpUrl } : {}),
      ...(authMutation.value !== undefined && interpUrl !== undefined ? { value: interpUrl } : {}),
    }
  }
  return {
    origin: req.origin,
    method: req.method,
    pathAndQuery,
    headers,
    body,
    persona: req.persona,
    ...(opts?.sessionId ?? req.session ? { session: opts?.sessionId ?? req.session } : {}),
    ...(opts?.sessionGroupRole ? { sessionGroupRole: opts.sessionGroupRole } : {}),
    ...(req.csrfBind !== undefined ? { csrfBind: req.csrfBind } : {}),
    ...(authMutation ? { authMutation } : {}),
    ...(maybeReq.traceId ? { traceId: maybeReq.traceId } : {}),
    ...(opts?.runId ? { runId: opts.runId } : {}),
    ...(opts?.assignmentId ? { assignmentId: opts.assignmentId } : {}),
    followRedirects: req.followRedirects,
  }
}

export function stepToBrokerRequest(
  step: ReplayStep,
  vars: Record<string, string>,
  opts?: { replayJarPrefix?: string; runId?: string; assignmentId?: string },
): BrokerHttpRequest {
  let sessionId: string | undefined
  if (step.request.session) {
    if (opts?.replayJarPrefix) {
      const candidate = `rv-${opts.replayJarPrefix}-${step.request.session}`
      sessionId = candidate.length <= 32
        ? candidate
        : `rv-${opts.replayJarPrefix}-${createHash('sha256').update(step.request.session).digest('hex').slice(0, 12)}`.slice(0, 32)
    } else {
      sessionId = step.request.session
    }
  }
  return requestShapeToBrokerRequest(step.request, vars, {
    sessionId,
    sessionGroupRole: step.role,
    runId: opts?.runId,
    assignmentId: opts?.assignmentId,
  })
}

/** requireControlNonError defaults to true for posture / auth-bypass style specs. */
export function defaultRequireControlNonError(spec: DeclarativeReplaySpec): boolean {
  if (spec.kind === 'static_ast_proof') return false
  return POSTURE_CWES.has(spec.cwe) || POSTURE_CATEGORY_RE.test(spec.category)
}

function statusMatchesExpected(expected: number | number[] | undefined, status: number): boolean {
  if (expected === undefined) return false
  return Array.isArray(expected) ? expected.includes(status) : expected === status
}

export function isUnexpectedErrorStatus(status: number, ...expected: Array<number | number[] | undefined>): boolean {
  if (status !== 404 && status < 500) return false
  return !expected.some(e => statusMatchesExpected(e, status))
}

/**
 * Map a replay spec onto a receipt class. Only classes whose evidence the receipt model can
 * re-derive in-process are returned; everything else stays on the legacy verdict (no invented
 * receipt rule keeps a confirmation alive).
 */

const CWE_NUMBER_RE = /\bCWE-(\d{1,5})\b/i

export const CWE_TO_RECEIPT_CLASS: Record<number, string> = {
  918: 'ssrf',
  611: 'xxe',
  601: 'open_redirect',
  345: 'webhook_forgery',
  287: 'auth_bypass',
  288: 'auth_bypass',
  290: 'auth_bypass',
  306: 'auth_bypass',
  307: 'auth_bypass',
  347: 'auth_bypass',
  384: 'auth_bypass',
  613: 'auth_bypass',
  798: 'auth_bypass',
  352: 'csrf',
  915: 'mass_assignment',
  79: 'xss_stored',
  80: 'xss_stored',
  83: 'xss_stored',
  89: 'injection',
  564: 'injection',
  943: 'injection',
  269: 'bfla',
  285: 'bfla',
  862: 'bfla',
  863: 'bfla',
  284: 'bola',
  362: 'bola',
  566: 'bola',
  639: 'bola',
  1021: 'bola',
  1220: 'bola',
  840: 'business_logic',
  841: 'business_logic',
  472: 'business_logic',
  1284: 'business_logic',
  200: 'info_disclosure',
  359: 'info_disclosure',
  522: 'info_disclosure',
  532: 'info_disclosure',
}

const DEDICATED_RECEIPT_CLASSES = new Set(['ssrf', 'xxe', 'open_redirect', 'webhook_forgery'])

const EXPLICIT_KEYWORD_CLASS_MATCHERS: ReadonlyArray<{ receiptClass: string; pattern: RegExp }> = [
  { receiptClass: 'ssrf', pattern: /\bssrf\b|server[- ]side request/i },
  { receiptClass: 'xxe', pattern: /\bxxe\b|external entit/i },
  { receiptClass: 'open_redirect', pattern: /\bopen[-_ ]?redirect\b|unvalidated[- ]redirect/i },
  { receiptClass: 'webhook_forgery', pattern: /webhook[^.]{0,80}(?:signature|forger|tamper)|(?:signature|forger)[^.]{0,80}webhook/i },
  { receiptClass: 'csrf', pattern: /\bcsrf\b|cross[- ]site\s+request\s+forgery/i },
  { receiptClass: 'xss_stored', pattern: /\b(?:xss|cross[- ]site\s+scripting)\b/i },
  { receiptClass: 'injection', pattern: /\b(?:sqli|sql[-_ ]?injection|nosql[-_ ]?injection)\b/i },
  { receiptClass: 'mass_assignment', pattern: /\bmass[- ]?assign|over[- ]?post/i },
  { receiptClass: 'auth_bypass', pattern: /\b(?:auth(?:entication)?[- ]bypass|jwt[- ]forgery|oauth[- ]bypass|mfa[- ]bypass)\b/i },
]

function explicitKeywordReceiptClasses(labelText: string): string[] {
  const matched: string[] = []
  for (const { receiptClass, pattern } of EXPLICIT_KEYWORD_CLASS_MATCHERS) {
    if (pattern.test(labelText)) matched.push(receiptClass)
  }
  return matched
}

/**
 * R2-H-14 / H-18: Map a replay spec onto a receipt class strictly CWE-first.
 *
 * When `spec.cwe` names a CWE identifier:
 *   - Unmodelled CWEs (e.g. CWE-22) fail closed (`null`) regardless of keywords in title/impact;
 *   - Conflicting explicit class keywords in model-authored labels fail closed (`null`).
 * Only when no CWE identifier is present does classification fall back to label keywords (still
 * failing closed if two distinct explicit keyword classes conflict).
 */
export function receiptVulnClassFor(spec: DeclarativeReplaySpec): string | null {
  const labelText = `${spec.category ?? ''} ${spec.title ?? ''} ${spec.impact ?? ''}`
  const keywordClasses = explicitKeywordReceiptClasses(labelText)
  const cweMatch = CWE_NUMBER_RE.exec(spec.cwe ?? '')
  if (cweMatch) {
    const cweNum = Number(cweMatch[1])
    const cweClass = Object.prototype.hasOwnProperty.call(CWE_TO_RECEIPT_CLASS, cweNum)
      ? CWE_TO_RECEIPT_CLASS[cweNum]!
      : null
    if (!cweClass) return null
    if (!DEDICATED_RECEIPT_CLASSES.has(cweClass) && spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') {
      return null
    }
    // Fail closed whenever model-authored label keywords name a different receipt class than the CWE.
    if (keywordClasses.some(cls => cls !== cweClass)) return null
    return cweClass
  }

  // No CWE present: fall back to label keywords, failing closed on multi-class ambiguity.
  if (keywordClasses.length > 1) return null
  if (keywordClasses.length === 1) {
    const only = keywordClasses[0]!
    if (DEDICATED_RECEIPT_CLASSES.has(only)) return only
  }
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return null
  if (classifyBoundaryClaim({
    cwe: spec.cwe,
    category: spec.category,
    title: spec.title,
    impact: spec.impact,
  }) === 'auth') {
    return 'auth_bypass'
  }
  return vulnClassForImpactClass(classifyImpactDescriptor({
    cwe: spec.cwe,
    category: spec.category,
    title: spec.title,
    impact: spec.impact,
  }))
}

function vulnClassForImpactClass(impactClass: string | null | undefined): string | null {
  switch (impactClass) {
    case 'authorization':
    case 'bola':
      return 'bola'
    case 'bfla': return 'bfla'
    case 'mass_assignment': return 'mass_assignment'
    case 'csrf': return 'csrf'
    case 'business_logic': return 'business_logic'
    case 'markup': return 'xss_stored'
    case 'disclosure': return 'info_disclosure'
    case 'injection': return 'injection'
    default: return null
  }
}

const replayCanaryTokenRe = /kovo-canary-[a-f0-9]{24}/i

/**
 * Build a ProofReceipt + transcript from a completed replay. The transcript is the host-recorded
 * evidence the verifier already produced (`stepsOut` + exchange ids); nothing is re-executed.
 * Returns null when the spec has no receipt representation.
 */
export function buildReplayReceipt(input: {
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
  canaryBroker?: Pick<CanaryBroker, 'checkCanary'>
  canaryRunId?: string
  canaryStorage?: Store
}): { receipt: ProofReceipt; transcript: ReceiptTranscript; factLog: HostFactLog; trustedOracleEvents: string[] } | null {
  const impactGate = input.evidencePayload.impactGate as { required?: boolean } | undefined
  const bflaImpact = input.evidencePayload.bflaImpact as { required?: boolean } | undefined
  const boundaryGate = input.evidencePayload.boundaryGate as { required?: boolean; satisfied?: boolean; boundaryClass?: string } | undefined
  const evidenceClass = typeof input.evidencePayload.evidenceClass === 'string'
    ? input.evidencePayload.evidenceClass
    : null
  const specClass = receiptVulnClassFor(input.spec)
  // R2-H-14: When the spec carries an explicit CWE that failed closed (unmodelled or keyword conflict),
  // never let evidenceClass override the CWE-first rejection.
  if (CWE_NUMBER_RE.test(input.spec.cwe ?? '') && specClass === null) return null
  const baseVulnClass = vulnClassForImpactClass(evidenceClass) ?? specClass
  const isBoundaryAuth = (baseVulnClass === null || baseVulnClass === 'auth_bypass') &&
    boundaryGate?.required === true && boundaryGate.boundaryClass === 'auth'
  const vulnClass = baseVulnClass ?? (isBoundaryAuth ? 'auth_bypass' : null)
  if (!vulnClass) return null
  const canary = input.evidencePayload.canary as {
    triggered?: boolean
    probeTriggered?: boolean
    controlTriggered?: boolean
    token?: string
    callbackId?: string
    stage?: 'immediate' | 'late'
    receivedAtMs?: number
  } | undefined
  const isOob = vulnClass === 'ssrf' || vulnClass === 'xxe' ||
    (vulnClass === 'webhook_forgery' && canary?.triggered === true)
  const isRedirect = vulnClass === 'open_redirect'
  const isWebhook = vulnClass === 'webhook_forgery' && !isOob
  // Require a gated class (impactGate, bflaImpact, OOB, redirect, webhook differential, or boundaryGate auth
  // bypass) to emit a receipt. Dedicated rules re-derive their evidence from the host transcript.
  if (!isOob && !isRedirect && !isWebhook && !isBoundaryAuth && impactGate?.required !== true && bflaImpact?.required !== true) return null
  const stepsOut = (input.evidencePayload.steps ?? {}) as Record<string, unknown>
  const steps = impactStepsFromStepsOut(input.spec, stepsOut)
  if (steps.length === 0 && vulnClass !== 'ssrf' && vulnClass !== 'xxe') return null
  const exchangeById = new Map<string, BrokerExchangeResult>()
  input.exchangeIds.forEach((id, index) => {
    const exchange = input.exchanges[index]
    if (exchange) exchangeById.set(id, exchange)
  })
  const entries: ReceiptTranscriptEntry[] = []
  const orderedIds: string[] = []
  for (const [index, step] of steps.entries()) {
    const recorded = stepsOut[step.id] as { exchangeId?: unknown; durationMs?: unknown; requestBody?: unknown } | undefined
    const id = typeof recorded?.exchangeId === 'string'
      ? recorded.exchangeId
      : input.exchangeIds[index] ?? `exchange-${index}`
    if (!id) continue
    const exchange = exchangeById.get(id) ?? (input.exchangeIds.length === 0 ? input.exchanges[index] : undefined)
    const durationMs = typeof recorded?.durationMs === 'number' ? recorded.durationMs : exchange?.durationMs
    const requestBody = typeof recorded?.requestBody === 'string' ? recorded.requestBody : ''
    entries.push({
      exchangeId: id,
      step,
      seq: index + 1,
      origin: exchange?.origin || input.spec.origin,
      ...(typeof durationMs === 'number' ? { durationMs } : {}),
      ...(exchange || requestBody
        ? { carrierText: `${exchange?.pathAndQuery ?? step.pathAndQuery ?? ''}\n${JSON.stringify(step.requestHeaders ?? {})}\n${requestBody}` }
        : {}),
    })
    orderedIds.push(id)
  }

  if (isOob) {
    // C-3 & R2-H-14: Require canary.triggered === true AND an independently checked host CanaryBroker hit.
    const token = canary?.token
    if (canary?.triggered !== true || !token || !replayCanaryTokenRe.test(token) || !canary.callbackId || canary.controlTriggered === true) return null
    const hostCheck = input.canaryBroker?.checkCanary(token, {
      ...(input.canaryStorage ? { storage: input.canaryStorage } : {}),
      ...(input.canaryRunId ? { runId: input.canaryRunId } : {}),
    })
    if (!hostCheck?.hit || !hostCheck.hits.some(hit => hit.token === token)) return null
    const detail = hostCheck.detail ?? {}
    const receivedAtMs = typeof detail.timestamp === 'number' && Number.isFinite(detail.timestamp)
      ? detail.timestamp
      : typeof detail.receivedAt === 'string' ? Date.parse(detail.receivedAt) : Number.NaN
    if (!Number.isFinite(receivedAtMs)) return null
    const carrying = entries.find(entry => (entry.carrierText ?? '').includes(token))
    if (!carrying) return null
    const receipt = {
      vulnClass,
      target: {
        origin: input.spec.origin,
        method: carrying.step.method.toUpperCase(),
        ...(carrying.step.pathAndQuery ? { pathAndQuery: carrying.step.pathAndQuery } : {}),
      },
      exchangeIds: [carrying.exchangeId],
      oobEventIds: ['replay-canary'],
      browserTraceIds: [],
      claimedDelta: `The target fetched the injected out-of-band canary after the ${vulnClass.toUpperCase()} probe.`,
    }
    const transcript: ReceiptTranscript = {
      entries: [carrying],
      oobEvents: [{
        id: 'replay-canary',
        callbackId: canary.callbackId,
        token,
        targetOrigin: input.spec.origin,
        delivered: true,
        stage: canary.stage === 'late' ? 'late' : 'immediate',
        receivedAtMs,
      }],
      browserTraces: [],
    }
    return { receipt: receipt as ProofReceipt, transcript, factLog: HostFactLog.fromTranscript(transcript), trustedOracleEvents: [] }
  }

  if (orderedIds.length === 0) return null
  const targetExchangeStep = steps.find(step => step.arm === 'probe') ?? steps[0]
  const targetEntry = entries.find(entry => entry.step === targetExchangeStep) ?? entries[0]
  // H-1: Only derive trustedOracleEvents from host-observed controls (csrfBind verified against
  // host cookie-authenticated probe headers), NEVER from raw model-authored spec.expectedImpactEvents.
  const csrfModelled = vulnClass === 'csrf' && 'steps' in input.spec && Array.isArray(input.spec.steps) &&
    input.spec.steps.some(s => Boolean((s as { request?: { csrfBind?: unknown } }).request?.csrfBind))
  const hasHostCookieProbe = entries.some(entry =>
    entry.step.arm === 'probe' && (
      entry.step.actor.auth === 'cookie' ||
      Object.entries(entry.step.requestHeaders ?? {}).some(([k, v]) => k.toLowerCase() === 'cookie' && Boolean(v?.trim()))
    ),
  )
  const trustedOracleEvents = csrfModelled && hasHostCookieProbe ? ['csrf_state_change'] : []
  const receipt = {
    vulnClass,
    target: {
      origin: input.spec.origin,
      method: targetEntry.step.method.toUpperCase(),
      ...(targetEntry.step.pathAndQuery ? { pathAndQuery: targetEntry.step.pathAndQuery } : {}),
    },
    exchangeIds: orderedIds,
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: (input.spec.expectedImpactEvents ?? []).length
      ? `Replay observed the declared impact: ${(input.spec.expectedImpactEvents ?? []).join(', ')}.`
      : `Replay moved state across the ${vulnClass} boundary described by "${input.spec.title.slice(0, 120)}".`,
    ...(trustedOracleEvents.length ? { oracleEvents: trustedOracleEvents } : {}),
    ...('proofPatterns' in input.spec && Array.isArray(input.spec.proofPatterns) && input.spec.proofPatterns.length
      ? { proofPatterns: input.spec.proofPatterns as string[] }
      : {}),
    ...('requiredRole' in input.spec && input.spec.requiredRole ? { requiredRole: input.spec.requiredRole } : {}),
    ...('resourceTenant' in input.spec && input.spec.resourceTenant ? { resourceTenant: input.spec.resourceTenant } : {}),
    ...('expectControlDenied' in input.spec && input.spec.expectControlDenied ? { expectControlDenied: true } : {}),
  }
  const transcript: ReceiptTranscript = { entries }
  return { receipt: receipt as ProofReceipt, transcript, factLog: HostFactLog.fromTranscript(transcript), trustedOracleEvents }
}

/**
 * Apply the receipt to a verdict. Shadow mode only annotates; strict mode can only downgrade a
 * confirmation (never promote one), so precision is monotonic.
 */
export function applyReceiptGate(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  receipt: ProofReceipt
  verification: ReceiptVerification
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off') return { verdict: input.verdict, outcome: input.outcome }
  const check: ReplayReceiptCheck = { receipt: input.receipt, verification: input.verification, mode: input.mode }
  if (input.mode === 'strict' && input.verdict === 'confirmed' && !input.verification.confirmed) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...input.outcome,
        confirmed: false,
        reason: `ProofReceipt rejected the confirmation: ${input.verification.reason}`.slice(0, 1200),
      },
      check,
    }
  }
  return { verdict: input.verdict, outcome: input.outcome, check }
}

/**
 * Explicit, bounded allowlist of host-persisted deterministic floor spec kinds that do not yet
 * construct a dedicated ProofReceipt. Untrusted/inline specs and all other kinds (including
 * `http_chain`, `sql_*`, `browser_chain`, `race_burst`, `rce_proof`, `agent_script`) ALWAYS fail
 * closed in strict mode when no ProofReceipt can be built.
 */
export const RECEIPT_EXEMPT_HOST_SPEC_KINDS: ReadonlySet<DeclarativeReplaySpec['kind']> = new Set([
  'cache_differential',
  'auth_protocol_proof',
])

export function isReceiptExemptHostSpec(
  spec: Pick<DeclarativeReplaySpec, 'kind'>,
  envelopeTrust?: 'host_persisted' | 'untrusted',
): boolean {
  return envelopeTrust === 'host_persisted' && RECEIPT_EXEMPT_HOST_SPEC_KINDS.has(spec.kind)
}

export function receiptCheckForResult(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
  envelopeTrust?: 'host_persisted' | 'untrusted'
  canaryBroker?: Pick<CanaryBroker, 'checkCanary'>
  canaryRunId?: string
  canaryStorage?: Store
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off' || input.verdict !== 'confirmed') return { verdict: input.verdict, outcome: input.outcome }
  // Floor-path intermediate job/handle stub guard: even before receipt construction (or on exempt
  // host-persisted kinds), a pure job/handle/ack stub chain with no substantive post-probe readback
  // never confirms in strict mode.
  if (input.mode === 'strict' && (input.spec.kind === 'http_chain' || input.spec.kind === 'auth_protocol_proof')) {
    const stepsOut = (input.evidencePayload.steps ?? {}) as Record<string, unknown>
    const floorSteps = impactStepsFromStepsOut(input.spec, stepsOut)
    const specClass = receiptVulnClassFor(input.spec)
    const isStubGuardedClass = specClass === null ||
      (specClass !== 'ssrf' && specClass !== 'xxe' && specClass !== 'injection' &&
        specClass !== 'open_redirect' && specClass !== 'webhook_forgery' &&
        !specClass.startsWith('xss') && !specClass.startsWith('dom_'))
    if (isStubGuardedClass && isPureJobOrHandleStubChain(floorSteps)) {
      return {
        verdict: 'inconclusive',
        outcome: {
          ...input.outcome,
          confirmed: false,
          reason: 'terminal_impact_unproven: floor probe returned only an intermediate job/handle/ack stub without substantive post-probe terminal impact.',
        },
      }
    }
  }
  const built = buildReplayReceipt({
    spec: input.spec,
    evidencePayload: input.evidencePayload,
    exchangeIds: input.exchangeIds,
    exchanges: input.exchanges,
    ...(input.canaryBroker ? { canaryBroker: input.canaryBroker } : {}),
    ...(input.canaryRunId ? { canaryRunId: input.canaryRunId } : {}),
    ...(input.canaryStorage ? { canaryStorage: input.canaryStorage } : {}),
  })
  // Fail closed in strict mode whenever a confirmed replay cannot construct a host-verified ProofReceipt,
  // preserving only the explicit host-persisted allowlist (`RECEIPT_EXEMPT_HOST_SPEC_KINDS`).
  if (!built) {
    if (input.mode === 'strict' && !isReceiptExemptHostSpec(input.spec, input.envelopeTrust)) {
      return {
        verdict: 'inconclusive',
        outcome: {
          ...input.outcome,
          confirmed: false,
          reason: 'ProofReceipt could not be built from host-recorded replay exchanges (fail-closed strict mode).',
        },
      }
    }
    return { verdict: input.verdict, outcome: input.outcome }
  }
  const strictHostDerivation = input.envelopeTrust !== 'host_persisted'
  const oracleRes = defaultTerminalOracleRegistry.evaluate(
    built.factLog,
    { kind: 'single_hop', receipt: built.receipt },
    {
      // H-6 / R2-H-9: Enforce strictHostDerivation on untrusted/inline specs and NEVER pass
      // spec-derived trustedOracleEvents under strict host derivation.
      strictHostDerivation,
      ...(!strictHostDerivation && built.trustedOracleEvents.length ? { trustedOracleEvents: built.trustedOracleEvents } : {}),
    },
  )
  const verification: ReceiptVerification = oracleRes.singleHop ?? {
    confirmed: oracleRes.confirmed,
    vulnClass: built.receipt.vulnClass,
    rule: 'none',
    reason: oracleRes.reason,
    observed: built.receipt.claimedDelta,
    expected: 'host-custody verified floor receipt',
  }
  return applyReceiptGate({
    mode: input.mode,
    verdict: input.verdict,
    outcome: input.outcome,
    receipt: built.receipt,
    verification,
  })
}
