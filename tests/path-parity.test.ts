/**
 * Wave 2 / Item #4 — Confirmation-Path Parity Corpus & Per-Path Guard Closure.
 *
 * Replays recorded TP/FP host-exchange + claim-envelope transcripts from
 * `tests/parity/corpus/*.json` through ALL live confirmation entry points:
 *   1. `verifyReplaySpec` (strict receipt default, real loopback HTTP + RequestBroker + LocalJqBackend)
 *   2. Floor recipe engine (`receiptCheckForResult` + `runCut3Recipe('injection_fingerprint')`)
 *   3. `evaluateClaims` (`TranscriptStore` + `HostFactLog.fromTranscriptStore`)
 *   4. `verifyCompositeReceipt` (multi-hop composite chains + decoy twins)
 *
 * Enforces label-permutation invariance (`canonical`, `'other'`, `CWE-20`, `CWE-only`,
 * `free-text title`) and pins all closed per-path fail-open seams.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readdirSync, readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker, type BrokerExchangeResult, type Grant } from '../src/server/broker.ts'
import {
  deriveSignedTerminalOrigin,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { resolveCompositeTerminalExchange } from '../src/server/composite-terminal.ts'
import { inspectCompositeHostOrigin, type HostRecordedExchangeView } from '../src/server/exec-verify.ts'
import {
  RECEIPT_EXEMPT_HOST_SPEC_KINDS,
  classifyRetestHealth,
  isReceiptExemptHostSpec,
  receiptCheckForResult,
  retestPersistedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { cut3FloorRecipe, runCut3Recipe, type FloorRecipeExecution } from '../src/server/floor-recipes.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { buildCompositeVerifyOptionsFromGrant } from '../src/server/agent-script-proof.ts'
import { serverBoundGrantTenant } from '../src/server/v8-oracle-families.ts'
import { classifyBoundaryClaim, classifyImpactDescriptor, type BoundaryClass, type ImpactClass, type ImpactStep, type InjectionFamily, type RoleName } from '../src/server/oracle-invariants.ts'
import {
  HostMintedOracle,
  buildAgentScriptReceipt,
  buildProofReceipt,
  isPureJobOrHandleStubChain,
  proofReceiptMode,
  receiptRuleFor,
  signOobCallback,
  verifyReceipt,
  type ReceiptBrowserTrace,
  type ReceiptOobEvent,
  type ReceiptTranscript,
  type ReceiptTranscriptEntry,
  type ReceiptVerification,
} from '../src/server/proof-receipt.ts'
import { retestPersistedAgentScript, retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { assessDeclarativeRetestHealth, assessRetestHealth, type RetestFailureReason, type RetestHealthAssessment } from '../src/server/retest-health.ts'
import {
  REGISTERED_V8_ORACLE_FAMILIES,
  SINGLE_HOP_ORACLE_RULES,
  defaultTerminalOracleRegistry,
  evaluateSingleHopProductionEnvelope,
  type SingleHopOracleRule,
} from '../src/server/terminal-oracle-registry.ts'
import type { V8OracleFamily } from '../src/server/v8-oracle-families.ts'
import { TranscriptStore, evaluateClaims, type VerifyClaim } from '../src/server/verify-claims.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_CONTEXT_NAME, VERIFY_RPC_HEADER, VERIFY_RPC_SOCKET_NAME, VERIFY_RPC_TOKEN_NAME } from '../src/server/verify-rpc.ts'
import type { VerifyScriptRequest, VerifyScriptResult, WorkerBackend, WorkerSession, WorkerSessionOptions } from '../src/server/worker-backend.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CORPUS_DIR = join(REPO_ROOT, 'tests', 'parity', 'corpus')
const SIGNING_KEY = 'path-parity-corpus-signing-key-987654321'

interface ParityPersona {
  handle: string
  roleLabel: string
  role: RoleName
  tenant: string
  auth: 'bearer' | 'cookie' | 'header' | 'unknown'
  headerName: string
  headerValue: string
}

interface ParityExchange {
  id: string
  arm: 'control' | 'probe' | 'setup' | 'cleanup'
  role: 'control' | 'probe' | 'setup' | 'cleanup'
  op?: 'http' | 'http2' | 'race' | 'oob' | 'browser'
  evidenceRole?: string
  booleanPairArm?: 'baseline' | 'true' | 'false'
  booleanPairRound?: number
  raceBatchId?: string
  durationMs?: number
  startedAtOffsetMs?: number
  endedAtOffsetMs?: number
  actorRoleLabel?: string
  emittedCapabilities?: string[]
  consumedCapabilities?: string[]
  /** Derived (capability-sealed) credential handle (`cap:hop_<id>:<slot>`) this exchange authenticated with. */
  actorCapability?: string
  /** Persona that MINTED `actorCapability` (its role label is inherited by the capability actor, as in production). */
  actorCapabilitySourcePersona?: string
  originOverride?: string
  oobToken?: string
  oobHit?: boolean
  method: string
  pathAndQuery: string
  persona: string | null
  requestJson?: unknown
  requestHeaders?: Record<string, string>
  status: number
  mediaType: string
  responseHeaders: Record<string, string>
  body: string
  executedSentinels?: string[]
}

interface ParityLabel {
  cwe?: string
  category?: string
  title?: string
  impact?: string
  claimedImpact?: ImpactClass
  claimedBoundary?: BoundaryClass
  vulnClass?: string
  injectionFamily?: InjectionFamily
}

interface ParityCase {
  id: string
  side: 'tp' | 'fp' | 'retest'
  archetype: string
  description: string
  canonicalLabel: ParityLabel
  freeTextLabel: { title: string; impact?: string }
  paths: {
    replay: boolean
    floorReceipt: boolean
    evaluateClaims: boolean
    composite: boolean
    floorInjectionRecipe: boolean
    proofReceipt?: boolean
    retest?: boolean
    /** `buildAgentScriptReceipt` -> production single-hop envelope (`evaluateSingleHopProductionEnvelope`). */
    agentScriptReceipt?: boolean
  }
  expected: { confirmed: boolean }
  /** Substring the agentScriptReceipt rejection reason must contain (pins the specific soundness gate). */
  agentScriptExpectedReason?: string
  /** Host-recorded REJECTED CompositeProofReceipt written to the TranscriptStore (the worker omits its claim). */
  compositeRejected?: {
    chainId: string
    terminalVulnClass: string
    failedStage: string
    rejectedBy: string
  }
  retest?: {
    scenario: 'drifted_session' | 'unbuildable_receipt' | 'composite_stage_rejected' | 'clean_fix'
    expectedVerdict: 'fixed' | 'inconclusive' | 'reproduced'
    expectedFailureReason: RetestFailureReason
    failedStage?: string
  }
  personas: ParityPersona[]
  exchanges: ParityExchange[]
  replaySpec?: {
    assertionsJq: string
    resourceTenant?: string
    requiredRole?: RoleName
    expectedImpactEvents?: string[]
  }
  injectionRecipe?: {
    param: string
    controlValue: string
    payload: string
    family?: InjectionFamily
  }
  proofReceipt?: {
    vulnClass?: string
    param?: string
    claimedDelta: string
    targetMethod?: string
    targetPathAndQuery?: string
    oobEvents?: Array<{
      id: string
      canaryId: string
      token: string
      delivered: boolean
      stage?: 'immediate' | 'late'
      latencyMs?: number
      receivedAtOffsetMs: number
      injectedAtOffsetMs?: number
    }>
    browserTraces?: Array<{
      id: string
      sinks: string[]
    }>
    timingChallenge?: {
      family: 'timing' | 'sqli' | 'nosqli' | 'cmdi'
      delayMs: number
    }
    mintRedirectCanary?: boolean
    mintBooleanPair?: {
      baseValue: string
      param: string
      style?: 'numeric' | 'single_quote' | 'double_quote'
    }
    conservedBalance?: {
      balanceField?: string
      capField?: string
      unitDebit?: number
    }
  }
  claims?: VerifyClaim[]
  bareClaims?: VerifyClaim[]
  composite?: {
    chainId: string
    terminalVulnClass: string
    oracleFamily: string
    capabilityToken?: string
    claimedDelta: string
    singleHop?: boolean
    omitTerminalExchangeId?: boolean
    attackerPersonas?: string[]
    forbiddenShortcutPersonas?: string[]
    expectedFailedStage?: string
    hop1TargetOverride?: { origin?: string; method?: string; pathAndQuery?: string }
    hop2TargetOverride?: { origin?: string; method?: string; pathAndQuery?: string }
    preChainControlIds?: string[]
    postChainReadbackIds?: string[]
    terminalExchangeId?: string
    v8OracleInput?: {
      family: V8OracleFamily
      rawInput: Record<string, unknown>
    }
    /** Host-configured Tier-2 policy judge (deterministic skeptic verdict + refusal control) run via the registry. */
    tier2Judge?: {
      skepticVerdict: 'confirmed' | 'rejected' | 'needs_review'
      refusalControl: { kind: 'serial_4xx' | 'clean_session_403' | 'boundary_flip_403_200'; controlExchangeIds: string[]; probeExchangeId: string }
    }
  }
}

export type PermutationKind = 'canonical' | 'cwe_only' | 'free_text' | 'adversarial_title' | 'cwe_20' | 'other'
export const PERMUTATIONS: readonly PermutationKind[] = [
  'canonical',
  'cwe_only',
  'free_text',
  'adversarial_title',
  'cwe_20',
  'other',
]

export type ParityEntryPoint =
  | 'verifyReplaySpec'
  | 'floor-recipe-engine'
  | 'evaluateClaims'
  | 'verifyCompositeReceipt'

export interface OtherLabelLayeringException {
  readonly entryPoint: ParityEntryPoint
  readonly permutation: 'other' | 'cwe_20' | 'free_text'
  readonly impactFilter?: 'all' | 'injection' | 'non_injection'
  readonly tpExpectedConfirmed: boolean
  readonly fpExpectedConfirmed: false
  readonly invariant: string
  readonly rationale: string
}

/**
 * R2-11 explicit typed layering table documenting why strict declarative/floor receipt paths
 * fail closed on unmodelled labels (`other`, `cwe_20`, and schema-required `CWE-0` in
 * `verifyReplaySpec` under `free_text`), while structured-claim (`evaluateClaims`) and
 * self-bound composite (`verifyCompositeReceipt`) entry points confirm genuine TPs.
 *
 * Every `(entryPoint, side, permutation)` cell asserts a deterministic verdict through this table.
 */
export const OTHER_LABEL_EXCEPTION_TABLE: ReadonlyArray<OtherLabelLayeringException> = [
  {
    entryPoint: 'verifyReplaySpec',
    permutation: 'other',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'DeclarativeReplaySpec requires a modelled CWE; generic "other"/CWE-0 fails closed in strict ProofReceipt mode.',
  },
  {
    entryPoint: 'verifyReplaySpec',
    permutation: 'cwe_20',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'Unmodelled CWE-20 has no strict receipt rule in CWE_TO_RECEIPT_CLASS and fails closed.',
  },
  {
    entryPoint: 'verifyReplaySpec',
    permutation: 'free_text',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'declarativeReplaySpecSchema mandates /^CWE-\\d{1,5}$/; free-text-only specs carry placeholder CWE-0 which fails closed under CWE-first classification.',
  },
  {
    entryPoint: 'floor-recipe-engine',
    permutation: 'other',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'receiptCheckForResult has no strict receipt rule for generic "other" labels without CWE or class keywords.',
  },
  {
    entryPoint: 'floor-recipe-engine',
    permutation: 'cwe_20',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'receiptCheckForResult rejects unmodelled CWE-20 strictly (CWE-first classification forbids keyword bypass).',
  },
  {
    entryPoint: 'floor-recipe-engine',
    permutation: 'free_text',
    impactFilter: 'non_injection',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-H-14',
    rationale: 'When CWE is omitted on an in-memory floor spec, receiptVulnClassFor falls back to unambiguous free-text keywords for non-injection classes so valid TPs confirm while FPs fail closed.',
  },
  {
    entryPoint: 'floor-recipe-engine',
    permutation: 'free_text',
    impactFilter: 'injection',
    tpExpectedConfirmed: false,
    fpExpectedConfirmed: false,
    invariant: 'oracle-invariants:594',
    rationale: 'classifyImpactDescriptor classifies injection strictly from CWE or category (never free-text prose alone) to prevent narrative rebranding; free-text-only injection specs fail closed in receiptCheckForResult.',
  },
  {
    entryPoint: 'evaluateClaims',
    permutation: 'other',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'Structured kernel claims carry self-contained oracle proofs independent of outer label; TPs pass while FPs fail closed via transcript-shape inference.',
  },
  {
    entryPoint: 'evaluateClaims',
    permutation: 'cwe_20',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'Structured kernel claims prove impact directly from host transcript even when outer finding CWE is generic CWE-20; FPs fail closed.',
  },
  {
    entryPoint: 'evaluateClaims',
    permutation: 'free_text',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'Structured kernel claims confirm TPs and reject FPs uniformly under free-text-only labels.',
  },
  {
    entryPoint: 'verifyCompositeReceipt',
    permutation: 'other',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'CompositeProofReceipt binds terminalVulnClass inside the host-verified receipt rather than outer labels; TPs confirm and FPs fail closed.',
  },
  {
    entryPoint: 'verifyCompositeReceipt',
    permutation: 'cwe_20',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'CompositeProofReceipt terminal oracle is bound to receipt.terminalVulnClass, invariant to outer CWE-20 labels.',
  },
  {
    entryPoint: 'verifyCompositeReceipt',
    permutation: 'free_text',
    tpExpectedConfirmed: true,
    fpExpectedConfirmed: false,
    invariant: 'R2-11',
    rationale: 'CompositeProofReceipt terminal oracle is invariant to outer free-text labels.',
  },
]

function expectedVerdictFor(
  entryPoint: ParityEntryPoint,
  c: Pick<ParityCase, 'side' | 'canonicalLabel'>,
  perm: PermutationKind,
): boolean {
  if (c.side === 'fp') return false
  if (perm === 'canonical' || perm === 'cwe_only' || perm === 'adversarial_title') return true
  const isInjection = c.canonicalLabel.claimedImpact === 'injection'
  const row = OTHER_LABEL_EXCEPTION_TABLE.find(e =>
    e.entryPoint === entryPoint &&
    e.permutation === perm &&
    (!e.impactFilter || e.impactFilter === 'all' || (e.impactFilter === 'injection' ? isInjection : !isInjection)),
  )
  assert.ok(row, `Missing OTHER_LABEL_EXCEPTION_TABLE entry for (${entryPoint}, ${perm}, injection=${isInjection})`)
  return row.tpExpectedConfirmed
}

type ManifestReceiptRule = SingleHopOracleRule
const MANIFEST_RECEIPT_RULES: readonly ManifestReceiptRule[] = SINGLE_HOP_ORACLE_RULES

interface CorpusClassExemption {
  readonly rule: ManifestReceiptRule
  readonly ticket: string
  readonly reason: string
  readonly expires: string
}

interface FpCorpusBackfillRatchetEntry {
  readonly oracle: ManifestReceiptRule | V8OracleFamily
  readonly ticket: string
  readonly reason: string
  readonly expires: string
}

/**
 * Ticketed exemption list for manifest receipt classes that cannot run purely offline.
 * Currently empty because every manifest receipt rule has at least one offline corpus fixture.
 */
export const CORPUS_CLASS_EXEMPTIONS: ReadonlyArray<CorpusClassExemption> = []

/**
 * R3-12 strictly-shrinking FP corpus backfill ratchet for single-hop rules that do not yet have
 * an explicit `side === 'fp'` fixture in `tests/parity/corpus/*.json` (TP cases do NOT count).
 * Prune-fail: once an FP corpus case lands for a listed rule, this test fails until removed here.
 */
export const FP_RULE_BACKFILL_RATCHET: ReadonlyArray<FpCorpusBackfillRatchetEntry> = [
  { oracle: 'oob', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
  { oracle: 'timing', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
  { oracle: 'browser', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
  { oracle: 'redirect', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
  { oracle: 'conserved_balance', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
  { oracle: 'webhook', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
]

/**
 * R3-12 strictly-shrinking FP corpus backfill ratchet for V8 oracle families that do not yet have
 * an explicit `side === 'fp'` fixture with `composite.v8OracleInput.family` in `tests/parity/corpus/*.json`.
 * Prune-fail: once an FP corpus case lands for a listed family, this test fails until removed here.
 */
export const V8_FP_FAMILY_BACKFILL_RATCHET: ReadonlyArray<FpCorpusBackfillRatchetEntry> = [
  { oracle: 'temporal_revocation', ticket: 'R3-12-FP-CORPUS-BACKFILL', reason: 'Pending V8 FP corpus fixture once tests/parity/corpus/*.json lease is free (covered live in tests/kernel-archetype-matrix.test.ts).', expires: '2026-12-31' },
]

function loadCorpus(): ParityCase[] {
  const files = readdirSync(CORPUS_DIR).filter(f => f.endsWith('.json')).sort()
  assert.ok(files.length >= 14, `expected >= 14 parity corpus files, found ${files.length}`)
  return files.map(f => JSON.parse(readFileSync(join(CORPUS_DIR, f), 'utf8')) as ParityCase)
}

function permuteLabel(c: ParityCase, perm: PermutationKind): ParityLabel {
  switch (perm) {
    case 'canonical':
      return { ...c.canonicalLabel }
    case 'other':
      return {
        category: 'other',
        title: 'Endpoint verification finding',
        impact: 'Observed response behavior on target route.',
        claimedImpact: 'other',
        claimedBoundary: 'other',
      }
    case 'cwe_20':
      return {
        cwe: 'CWE-20',
        category: 'input-validation',
        title: 'Improper input validation',
        impact: 'Unexpected behavior on supplied input.',
        claimedImpact: 'other',
        claimedBoundary: 'other',
      }
    case 'cwe_only': {
      const cwe = c.canonicalLabel.cwe
      const derivedImpact = classifyImpactDescriptor({ cwe })
      const derivedBoundary = classifyBoundaryClaim({ cwe })
      return {
        ...(cwe ? { cwe } : {}),
        category: 'other',
        title: 'Security finding',
        impact: 'Observed response difference.',
        claimedImpact: derivedImpact,
        claimedBoundary: derivedBoundary,
      }
    }
    case 'adversarial_title': {
      const cwe = c.canonicalLabel.cwe
      const derivedImpact = classifyImpactDescriptor({ cwe })
      const derivedBoundary = classifyBoundaryClaim({ cwe })
      return {
        ...(cwe ? { cwe } : {}),
        category: 'other',
        title: 'Routine telemetry status notice',
        impact: 'Normal benign endpoint diagnostic observation.',
        claimedImpact: derivedImpact,
        claimedBoundary: derivedBoundary,
      }
    }
    case 'free_text': {
      const title = c.freeTextLabel.title
      const impact = c.freeTextLabel.impact ?? title
      return {
        title,
        impact,
        claimedImpact: classifyImpactDescriptor({ title, impact }),
        claimedBoundary: classifyBoundaryClaim({ title, impact }),
      }
    }
  }
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function parseJsonSafe(body: string): unknown {
  try { return JSON.parse(body) } catch { return undefined }
}

function buildGrant(origin: string, personas: readonly ParityPersona[]): Grant {
  return makeLabGrant(origin, {
    tier: 3,
    personas: new Map(personas.map((p, idx) => [p.handle, {
      id: `persona-${idx}-${p.handle}`,
      handle: p.handle,
      roleLabel: p.roleLabel,
      originAllowlist: [origin],
      authKind: p.auth === 'bearer' ? 'bearer' : p.auth === 'cookie' ? 'cookie' : 'header',
      headerName: p.headerName,
      secret: p.headerValue.replace(/^Bearer\s+/i, ''),
      canaryMarkers: [],
    }])),
  })
}

function buildReplaySpec(
  c: ParityCase,
  origin: string,
  label: ParityLabel,
  opts?: { allowEmptyCwe?: boolean },
): DeclarativeReplaySpec {
  const cweValue = label.cwe ?? (opts?.allowEmptyCwe ? '' : 'CWE-0')
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: label.title ?? 'Security finding',
    category: label.category ?? 'other',
    cwe: cweValue,
    severity: 'high',
    severityRationale: 'Parity corpus evaluation.',
    impact: label.impact ?? 'Observed behavior.',
    remediation: 'Enforce strict server-side verification.',
    recheckInstructions: 'Re-run parity transcript.',
    assertionsJq: c.replaySpec!.assertionsJq,
    ...(c.replaySpec!.resourceTenant ? { resourceTenant: c.replaySpec!.resourceTenant } : {}),
    ...(c.replaySpec!.requiredRole ? { requiredRole: c.replaySpec!.requiredRole } : {}),
    ...(c.replaySpec!.expectedImpactEvents ? { expectedImpactEvents: c.replaySpec!.expectedImpactEvents } : {}),
    steps: c.exchanges.map(ex => ({
      id: ex.id,
      role: ex.role,
      description: ex.id,
      request: {
        origin,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        ...(ex.persona ? { persona: ex.persona } : {}),
        ...(ex.requestJson !== undefined ? { jsonBody: ex.requestJson } : {}),
        ...(ex.requestHeaders ? { headers: ex.requestHeaders } : {}),
        followRedirects: false,
      },
    })),
  } as unknown as DeclarativeReplaySpec
}

function substituteTemplate(text: string, vars: Readonly<Record<string, string>>): string {
  let out = text
  for (const [k, v] of Object.entries(vars)) {
    out = out.replaceAll(`{{${k}}}`, v)
  }
  return out
}

function substituteHeaders(headers: Record<string, string>, vars: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) out[k] = substituteTemplate(v, vars)
  return out
}

function populateTranscriptStore(
  c: ParityCase,
  origin: string,
  templateVars: Readonly<Record<string, string>> = {},
  opts: { typedPersonaTenant?: boolean } = {},
): { store: TranscriptStore; idMap: Map<string, string> } {
  const store = new TranscriptStore(Buffer.alloc(32, 7))
  const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
  const idMap = new Map<string, string>()
  const baseTs = 1_700_000_000_000
  let ts = baseTs
  for (const ex of c.exchanges) {
    ts = ex.startedAtOffsetMs !== undefined ? baseTs + ex.startedAtOffsetMs : ts + 100
    const persona = ex.persona ? personaByHandle.get(ex.persona) : undefined
    // Production attribution (verify-rpc B1): a capability actor inherits its minter's role label, but its tenant
    // is ONLY the server-bound tenant the host observed in the minting session-grant response (else unknown).
    const capMinter = ex.actorCapability ? personaByHandle.get(ex.actorCapabilitySourcePersona ?? '') : undefined
    const capMintEx = ex.actorCapability ? c.exchanges.find(m => m.emittedCapabilities?.includes(ex.actorCapability!)) : undefined
    const capIdentity = ex.actorCapability
      ? { personaHandle: ex.actorCapability, actorRoleLabel: capMinter?.roleLabel ?? null, actorTenant: capMintEx ? serverBoundGrantTenant(capMintEx.body, capMintEx.status, capMintEx.method) : null }
      : null
    const reqHeaders: Record<string, string> = substituteHeaders(ex.requestHeaders ?? {}, templateVars)
    if (persona) reqHeaders[persona.headerName.toLowerCase()] = persona.headerValue
    const pathAndQuery = substituteTemplate(ex.pathAndQuery, templateVars)
    const responseHeaders = substituteHeaders(ex.responseHeaders, templateVars)
    const body = substituteTemplate(ex.body, templateVars)
    const reqBody = ex.requestJson !== undefined ? JSON.stringify(ex.requestJson) : ''
    const op = ex.op ?? (ex.executedSentinels?.length ? 'browser' : 'http')
    const artifact = ex.op === 'oob'
      ? { kind: 'oob-mint' as const, token: ex.oobToken, hit: Boolean(ex.oobHit) }
      : ex.executedSentinels?.length
        ? { kind: 'browser' as const, executedSentinels: ex.executedSentinels }
        : undefined
    const rec = store.record({
      op,
      startedAt: ts,
      durationMs: ex.durationMs ?? 12,
      request: {
        origin: ex.originOverride ?? origin,
        method: ex.method,
        pathAndQuery,
        headers: reqHeaders,
        bodyBytes: Buffer.byteLength(reqBody, 'utf8'),
        bodySha256: sha256(reqBody),
        personaHandle: capIdentity?.personaHandle ?? persona?.handle ?? null,
        sessionRole: ex.arm,
        actorRoleLabel: capIdentity ? capIdentity.actorRoleLabel : ex.actorRoleLabel !== undefined ? (ex.actorRoleLabel || null) : (persona?.roleLabel ?? null),
        ...(capIdentity ? { actorTenant: capIdentity.actorTenant } : opts.typedPersonaTenant && persona ? { actorTenant: persona.tenant } : {}),
        nonce: 'parity-nonce',
      },
      response: {
        status: ex.status,
        headers: responseHeaders,
        bodyBytes: Buffer.byteLength(body, 'utf8'),
        bodySha256: sha256(body),
        mediaType: ex.mediaType,
      },
      ...(artifact ? { artifact } : {}),
      rawRequestBody: reqBody || undefined,
      body,
    })
    idMap.set(ex.id, rec.exchangeId)
  }
  if (c.compositeRejected) {
    const storeIds = c.exchanges.map(e => idMap.get(e.id)!)
    store.recordCompositeVerification({
      chainId: c.compositeRejected.chainId,
      terminalVulnClass: c.compositeRejected.terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      hopCount: 1,
      confirmed: false,
      verifiedEdgeCount: 0,
      reason: `CompositeProofReceipt rejected at ${c.compositeRejected.failedStage}`,
      failedStage: c.compositeRejected.failedStage,
      rejectedBy: c.compositeRejected.rejectedBy,
      missingEvidence: [c.compositeRejected.rejectedBy],
      exchangeIds: storeIds,
      terminalExchangeId: storeIds[storeIds.length - 1] ?? null,
    })
  }
  return { store, idMap }
}

/**
 * Production agent-script single-hop path: the host-recorded transcript is signed with the session key (with
 * host capability emission/consumption provenance), the verify oracle (`evaluateClaims`) must pass on the
 * script's claims, and the host-built receipt must confirm through the production single-hop envelope with the
 * grant's persona policy.
 */
function evaluateAgentScriptReceiptPath(c: ParityCase, origin: string): { built: boolean; oraclePassed: boolean; confirmed: boolean; reason: string } {
  // Production verify-rpc records the host-resolved TYPED persona tenant (never a label-derived one).
  const { store, idMap } = populateTranscriptStore(c, origin, {}, { typedPersonaTenant: true })
  const byStoreId = new Map(c.exchanges.map(ex => [idMap.get(ex.id)!, ex]))
  const projected = HostFactLog.fromTranscriptStore(store).toHostSignedTranscript()
  const entries: HostTranscriptEntry[] = (projected.entries ?? []).map(entry => {
    const ex = byStoreId.get(entry.exchangeId)
    const { hostSignature: _unsigned, ...rest } = entry
    const base: HostTranscriptEntry = {
      ...rest,
      ...(ex?.emittedCapabilities?.length ? { emittedCapabilities: ex.emittedCapabilities } : {}),
      ...(ex?.consumedCapabilities?.length || ex?.actorCapability ? { consumedCapabilities: ex.consumedCapabilities ?? [ex.actorCapability!] } : {}),
      cleanSession: true,
    }
    return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
  })
  const factLog = HostFactLog.fromTranscriptStore(store, { hostTranscript: { ...projected, entries } })
  const claims = remapClaimIds(c.claims ?? [], idMap)
  const oracle = evaluateClaims(store, claims, {
    factLog,
    allowedExchangeIds: new Set(store.list().map(r => r.exchangeId)),
    claimedImpact: c.canonicalLabel.claimedImpact,
    claimedBoundary: c.canonicalLabel.claimedBoundary,
    cwe: c.canonicalLabel.cwe ?? null,
    category: c.canonicalLabel.category ?? null,
    title: c.canonicalLabel.title ?? null,
    description: c.canonicalLabel.impact ?? null,
  })
  const built = buildAgentScriptReceipt({ claims: claims as unknown as Record<string, unknown>[], exchanges: [], factLog, origin, title: c.canonicalLabel.title ?? c.id })
  if (!built) return { built: false, oraclePassed: oracle.passed, confirmed: false, reason: 'receipt_unbuildable' }
  const grant = buildGrant(origin, c.personas)
  const personaRoleLabels = Object.fromEntries(c.personas.map(p => [p.handle, p.roleLabel]))
  const res = evaluateSingleHopProductionEnvelope(built.factLog, built, {
    signingKey: SIGNING_KEY,
    compositeOptions: { personaRoleLabels, ...buildCompositeVerifyOptionsFromGrant(grant) },
  })
  return { built: true, oraclePassed: oracle.passed, confirmed: oracle.passed && res.confirmed, reason: oracle.passed ? res.reason : oracle.failures.join('; ') }
}

function remapClaimIds(claims: readonly VerifyClaim[], idMap: ReadonlyMap<string, string>): VerifyClaim[] {
  const mapId = (id: string): string => idMap.get(id) ?? id
  return claims.map(claim => {
    switch (claim.kind) {
      case 'status':
      case 'header':
      case 'body_contains':
      case 'jsonpath':
      case 'css':
      case 'dom_sentinel':
      case 'oob':
        return { ...claim, exchangeId: mapId(claim.exchangeId) }
      case 'boundary':
        return { ...claim, controlExchangeId: mapId(claim.controlExchangeId), probeExchangeId: mapId(claim.probeExchangeId) }
      case 'impact':
        return {
          ...claim,
          probeExchangeId: mapId(claim.probeExchangeId),
          ...(claim.beforeExchangeId ? { beforeExchangeId: mapId(claim.beforeExchangeId) } : {}),
          ...(claim.afterExchangeId ? { afterExchangeId: mapId(claim.afterExchangeId) } : {}),
          ...(claim.controlExchangeIds ? { controlExchangeIds: claim.controlExchangeIds.map(mapId) } : {}),
        }
      case 'structural_diff':
        return { ...claim, controlIds: claim.controlIds.map(mapId), variantIds: claim.variantIds.map(mapId) }
      case 'timing':
        return { ...claim, controlIds: claim.controlIds.map(mapId), variantIds: claim.variantIds.map(mapId) }
      case 'race':
      case 'composite_receipt':
        return { ...claim, exchangeIds: claim.exchangeIds.map(mapId) }
      case 'host_evaluated_expression':
        return { ...claim, controlIds: claim.controlIds.map(mapId), probeIds: claim.probeIds.map(mapId) }
      case 'mfa':
        return {
          ...claim,
          enrolledExchangeId: mapId(claim.enrolledExchangeId),
          preChallengeExchangeId: mapId(claim.preChallengeExchangeId),
          postChallengeExchangeId: mapId(claim.postChallengeExchangeId),
          ...(claim.challengeExchangeId ? { challengeExchangeId: mapId(claim.challengeExchangeId) } : {}),
        }
    }
  })
}

function buildCompositeFixture(c: ParityCase, origin: string): {
  receipt: CompositeProofReceipt
  transcript: HostSignedTranscript
  store: TranscriptStore
  claim: VerifyClaim
  options: { signingKey: string; attackerPersonas?: string[]; forbiddenShortcutPersonas?: string[] }
  exchangeById: Map<string, HostRecordedExchangeView>
} {
  const comp = c.composite!
  const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
  const capHandle = comp.capabilityToken ? `cap:hop_1:${comp.capabilityToken}` : null
  const entries: HostTranscriptEntry[] = []
  let ts = 1_700_000_000_000
  let seq = 0
  for (const ex of c.exchanges) {
    ts += 250
    seq += 1
    const p = ex.persona ? personaByHandle.get(ex.persona) : undefined
    const json = parseJsonSafe(ex.body)
    const emitted = ex.emittedCapabilities ?? (capHandle && ex.id === 'hop1_ex' ? [capHandle] : undefined)
    const consumed = ex.consumedCapabilities ?? (capHandle && ex.id === 'hop2_prb' ? [capHandle] : undefined)
    const capActor = !p && consumed?.length ? consumed[0]! : null
    const step: ImpactStep = {
      id: ex.id,
      arm: ex.arm,
      method: ex.method,
      route: ex.pathAndQuery.split('?')[0] ?? '/',
      pathAndQuery: ex.pathAndQuery,
      status: ex.status,
      actor: {
        handle: p?.handle ?? capActor,
        role: p?.role ?? null,
        tenant: p?.tenant ?? null,
        auth: p?.auth ?? (capActor ? 'bearer' : 'unknown'),
        sameSite: null,
      },
      ...(json !== undefined ? { json } : {}),
      body: ex.body,
      ...(ex.requestJson !== undefined ? { requestJson: ex.requestJson } : {}),
      requestHeaders: {
        ...(p ? { [p.headerName]: p.headerValue } : {}),
        ...(ex.requestHeaders ?? {}),
      },
      responseHeaders: ex.responseHeaders,
    }
    const extra: Partial<HostTranscriptEntry> = {
      seq,
      origin: ex.originOverride ?? origin,
      timestampMs: ts,
      actorPersona: p?.handle ?? capActor,
      actorRoleLabel: ex.actorRoleLabel !== undefined ? (ex.actorRoleLabel || null) : (p?.roleLabel ?? null),
      cleanSession: true,
      ...(emitted?.length ? { emittedCapabilities: emitted } : {}),
      ...(consumed?.length ? { consumedCapabilities: consumed } : {}),
    }
    const base: HostTranscriptEntry = { exchangeId: ex.id, step, ...extra }
    entries.push({ ...base, hostSignature: signHostRecord(base, SIGNING_KEY) })
  }

  let receipt: CompositeProofReceipt
  if (comp.singleHop) {
    const termExId = comp.terminalExchangeId ?? c.exchanges[c.exchanges.length - 1]!.id
    const termEx = c.exchanges.find(e => e.id === termExId) ?? c.exchanges[c.exchanges.length - 1]!
    const preCtrls = comp.preChainControlIds ?? c.exchanges.filter(e => e.arm === 'control').map(e => e.id)
    const postRbIds = comp.postChainReadbackIds ?? []
    const hopExIds = c.exchanges.filter(e => !preCtrls.includes(e.id) && !postRbIds.includes(e.id)).map(e => e.id)
    receipt = {
      chainId: comp.chainId,
      terminalVulnClass: comp.terminalVulnClass,
      hops: [
        {
          hopId: 'hop_1',
          surface: 'http',
          target: {
            origin: comp.hop1TargetOverride?.origin ?? origin,
            method: comp.hop1TargetOverride?.method ?? termEx.method,
            pathAndQuery: comp.hop1TargetOverride?.pathAndQuery ?? termEx.pathAndQuery,
          },
          exchangeIds: hopExIds.length > 0 ? hopExIds : [termEx.id],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: comp.claimedDelta,
          producedCapabilities: [],
          consumedCapabilities: [],
        },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        ...(comp.omitTerminalExchangeId ? {} : { terminalExchangeId: termEx.id }),
        claimedImpact: comp.claimedDelta,
        summary: comp.claimedDelta,
        preChainControlExchangeIds: preCtrls,
        postChainReadbackExchangeIds: postRbIds,
      },
      replayMode: 'fresh_clean_replay',
    }
  } else {
    const hop1 = c.exchanges.find(e => e.id === 'hop1_ex')!
    const hop2 = c.exchanges.find(e => e.id === 'hop2_prb')!
    const hop2Ctl = c.exchanges.find(e => e.id === 'hop2_ctl')
    const hop2ExIds = hop2Ctl ? [hop2Ctl.id, hop2.id] : [hop2.id]
    receipt = {
      chainId: comp.chainId,
      terminalVulnClass: comp.terminalVulnClass,
      hops: [
        {
          hopId: 'hop_1',
          surface: 'http',
          target: {
            origin: comp.hop1TargetOverride?.origin ?? origin,
            method: comp.hop1TargetOverride?.method ?? hop1.method,
            pathAndQuery: comp.hop1TargetOverride?.pathAndQuery ?? hop1.pathAndQuery,
          },
          exchangeIds: [hop1.id],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Minted cross-tenant capability handle.',
          producedCapabilities: capHandle ? [capHandle] : [],
          consumedCapabilities: [],
        },
        {
          hopId: 'hop_2',
          surface: 'http',
          target: {
            origin: comp.hop2TargetOverride?.origin ?? origin,
            method: comp.hop2TargetOverride?.method ?? hop2.method,
            pathAndQuery: comp.hop2TargetOverride?.pathAndQuery ?? hop2.pathAndQuery,
          },
          exchangeIds: hop2ExIds,
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: comp.claimedDelta,
          producedCapabilities: [],
          consumedCapabilities: capHandle ? [capHandle] : [],
        },
      ],
      causalEdges: capHandle
        ? [
            {
              fromHopId: 'hop_1',
              toHopId: 'hop_2',
              kind: 'value_binding',
              capabilityHandle: capHandle,
              sourceExchangeId: hop1.id,
              targetExchangeId: hop2.id,
            },
          ]
        : [],
      terminalImpact: {
        terminalHopId: 'hop_2',
        ...(comp.omitTerminalExchangeId ? {} : { terminalExchangeId: hop2.id }),
        claimedImpact: comp.claimedDelta,
        summary: comp.claimedDelta,
        preChainControlExchangeIds: comp.preChainControlIds ?? (hop2Ctl ? [hop2Ctl.id] : []),
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
  }

  const transcript: HostSignedTranscript = { entries }
  const options = {
    signingKey: SIGNING_KEY,
    ...(comp.attackerPersonas ? { attackerPersonas: comp.attackerPersonas } : {}),
    ...(comp.forbiddenShortcutPersonas ? { forbiddenShortcutPersonas: comp.forbiddenShortcutPersonas } : {}),
  }
  const hostCompRes = verifyCompositeReceipt(receipt, transcript, options)
  const { store, idMap } = populateTranscriptStore(c, origin)
  const storeExchangeIds = c.exchanges.map(e => idMap.get(e.id)!)
  const verifiedRec = store.recordCompositeVerification({
    chainId: comp.chainId,
    terminalVulnClass: comp.terminalVulnClass,
    confirmed: hostCompRes.confirmed,
    hopCount: hostCompRes.hopCount,
    verifiedEdgeCount: hostCompRes.verifiedEdges.filter(e => e.verified).length,
    replayMode: hostCompRes.replayMode,
    reason: hostCompRes.reason,
    ...(hostCompRes.failedStage ? { failedStage: hostCompRes.failedStage } : {}),
    rejectedBy: hostCompRes.rejectedBy ?? null,
    missingEvidence: hostCompRes.missingEvidence ?? [],
    exchangeIds: storeExchangeIds,
  })
  const claim: VerifyClaim = {
    kind: 'composite_receipt',
    verificationId: verifiedRec.verificationId,
    chainId: comp.chainId,
    terminalVulnClass: comp.terminalVulnClass,
    exchangeIds: storeExchangeIds,
    ...(comp.omitTerminalExchangeId
      ? {}
      : { terminalExchangeId: idMap.get(receipt.terminalImpact.terminalExchangeId ?? '') ?? storeExchangeIds[storeExchangeIds.length - 1]! }),
  }
  const exchangeById = new Map<string, HostRecordedExchangeView>(
    entries.map(e => [
      e.exchangeId,
      {
        exchangeId: e.exchangeId,
        origin: e.origin ?? '',
        method: e.step.method.toUpperCase(),
        pathAndQuery: e.step.pathAndQuery ?? e.step.route ?? '',
        status: e.step.status,
        sessionRole: e.step.arm,
      },
    ]),
  )
  return { receipt, transcript, store, claim, options, exchangeById }
}

// ============================================================================
// 1. Corpus completeness, >=2 entry points per case, & manifest class coverage
// ============================================================================

test('parity corpus: covers both TP and FP sides including anon-control authz and error-status-only injection', () => {
  const corpus = loadCorpus()
  const tps = corpus.filter(c => c.side === 'tp')
  const fps = corpus.filter(c => c.side === 'fp')
  assert.ok(tps.length >= 5, `expected >= 5 TP corpus cases, got ${tps.length}`)
  assert.ok(fps.length >= 8, `expected >= 8 FP corpus cases, got ${fps.length}`)
  assert.ok(corpus.length >= 29, `expected >= 29 total parity corpus cases after R2-11 backfill, got ${corpus.length}`)
  const archetypes = new Set(corpus.map(c => c.archetype))
  assert.ok(archetypes.has('anon-control-authz'), 'missing anon-control-authz archetype')
  assert.ok(archetypes.has('error-status-only-injection'), 'missing error-status-only-injection archetype')
  assert.ok(archetypes.has('cross-tenant-bola'), 'missing cross-tenant-bola archetype')
  assert.ok(archetypes.has('bfla-vertical'), 'missing bfla-vertical archetype')
  assert.ok(archetypes.has('sqli-echoed-error'), 'missing sqli-echoed-error archetype')
  assert.ok(archetypes.has('xss-json-escaped-echo'), 'missing xss-json-escaped-echo archetype')
  assert.ok(archetypes.has('job-handle-stub'), 'missing job-handle-stub archetype')
  assert.ok(archetypes.has('composite-multihop-cross-tenant'), 'missing composite-multihop archetype')
  assert.ok(archetypes.has('composite-stub-decoy'), 'missing composite-stub-decoy archetype')
  // R2-11 backfilled missing receipt classes & R3 kernel classes
  for (const requiredArchetype of [
    'boolean-differential',
    'r3-c4-integer-coercion-boolean',
    'timing-differential',
    'oob-durable-callback',
    'ssrf-oob-callback',
    'open-redirect-canary',
    'race-conserved-balance',
    'auth-bypass-header',
    'webhook-inline-hmac',
    'r3-c5-signed-url-scope-replay',
    'r3-c5-batch-partial-cache-bleed',
    'r3-h4-forbidden-admin-cap',
    'r3-h4-junk-bearer-control',
    'r3-h13-hop-target-mismatch',
    'composite-no-terminal-exchange-id',
  ]) {
    assert.ok(archetypes.has(requiredArchetype), `missing R2-11 required archetype: ${requiredArchetype}`)
  }

  // R2-11: Every corpus case MUST assert at least TWO entry points (preventing single-path placeholders).
  for (const c of corpus) {
    if (c.side === 'retest') {
      assert.equal(c.paths.retest, true, `retest case ${c.id} must enable retest (3 engines: floor + declarative + agent-script)`)
      continue
    }
    const activeCount = [
      c.paths.replay,
      c.paths.floorReceipt,
      c.paths.evaluateClaims,
      c.paths.composite,
      c.paths.floorInjectionRecipe,
      Boolean(c.paths.proofReceipt),
      Boolean(c.paths.agentScriptReceipt),
    ].filter(Boolean).length
    assert.ok(
      activeCount >= 2,
      `R2-11: corpus case ${c.id} must assert at least 2 entry points, found ${activeCount}`,
    )
  }

  // R2-11: Every manifest receipt class must be covered by the corpus or carry a valid ticketed exemption.
  const coveredRules = new Set<ManifestReceiptRule>()
  const fpCoveredRules = new Set<ManifestReceiptRule>()
  const fpCoveredV8Families = new Set<V8OracleFamily>()
  for (const c of corpus) {
    const cls = c.proofReceipt?.vulnClass ?? c.canonicalLabel.vulnClass
    if (cls) {
      const oobIds = c.proofReceipt?.oobEvents?.map(e => e.id) ?? []
      const { rule } = receiptRuleFor(cls, { oobEventIds: oobIds })
      if (rule !== 'none') {
        coveredRules.add(rule)
        if (c.side === 'fp') fpCoveredRules.add(rule)
      }
    }
    if (c.side === 'fp' && c.composite?.v8OracleInput?.family) {
      fpCoveredV8Families.add(c.composite.v8OracleInput.family)
    }
  }
  const exemptionsByRule = new Map(CORPUS_CLASS_EXEMPTIONS.map(ex => [ex.rule, ex]))
  for (const rule of MANIFEST_RECEIPT_RULES) {
    if (coveredRules.has(rule)) continue
    const ex = exemptionsByRule.get(rule)
    assert.ok(ex, `R2-11 manifest receipt class "${rule}" has zero parity corpus coverage and no ticketed exemption`)
    assert.ok(ex.ticket.trim().length > 0 && ex.reason.trim().length > 0 && /^\d{4}-\d{2}-\d{2}$/.test(ex.expires))
  }

  // R3-12: FP-only completeness across EVERY single-hop rule AND EVERY registered V8 oracle family.
  // TP cases NO LONGER satisfy FP coverage. Any currently uncovered rule/family must be tracked in the
  // monotone-shrinking (prune-fail) backfill ratchet with a ticket, reason, and ISO expiry date.
  const fpRuleRatchet = new Map(FP_RULE_BACKFILL_RATCHET.map(e => [e.oracle, e]))
  for (const rule of SINGLE_HOP_ORACLE_RULES) {
    const ratcheted = fpRuleRatchet.get(rule)
    if (fpCoveredRules.has(rule)) {
      assert.equal(
        ratcheted,
        undefined,
        `R3-12 prune-fail: single-hop rule "${rule}" now has an FP corpus case — remove it from FP_RULE_BACKFILL_RATCHET`,
      )
      continue
    }
    assert.ok(
      ratcheted,
      `R3-12 FP completeness: single-hop rule "${rule}" has ZERO FP corpus cases (TP cases do not count) and is not in FP_RULE_BACKFILL_RATCHET`,
    )
    assert.ok(
      ratcheted.ticket.trim().length > 0 && ratcheted.reason.trim().length > 0 && /^\d{4}-\d{2}-\d{2}$/.test(ratcheted.expires),
      `R3-12 invalid FP_RULE_BACKFILL_RATCHET entry for "${rule}"`,
    )
  }

  const fpV8Ratchet = new Map(V8_FP_FAMILY_BACKFILL_RATCHET.map(e => [e.oracle, e]))
  for (const family of REGISTERED_V8_ORACLE_FAMILIES) {
    const ratcheted = fpV8Ratchet.get(family)
    if (fpCoveredV8Families.has(family)) {
      assert.equal(
        ratcheted,
        undefined,
        `R3-12 prune-fail: V8 oracle family "${family}" now has an FP corpus case — remove it from V8_FP_FAMILY_BACKFILL_RATCHET`,
      )
      continue
    }
    assert.ok(
      ratcheted,
      `R3-12 FP completeness: V8 oracle family "${family}" has ZERO FP corpus cases with composite.v8OracleInput (TP cases do not count) and is not in V8_FP_FAMILY_BACKFILL_RATCHET`,
    )
    assert.ok(
      ratcheted.ticket.trim().length > 0 && ratcheted.reason.trim().length > 0 && /^\d{4}-\d{2}-\d{2}$/.test(ratcheted.expires),
      `R3-12 invalid V8_FP_FAMILY_BACKFILL_RATCHET entry for "${family}"`,
    )
  }
})

// ============================================================================
// 2. Entry point 1: verifyReplaySpec (strict receipt default) + label permutations
// ============================================================================

test('path parity [verifyReplaySpec]: retired declarative jq VM fails closed and never confirms TP or FP corpus specs under any label permutation', async (t) => {
  const corpus = loadCorpus().filter(c => c.paths.replay)
  assert.ok(corpus.length >= 10)

  let activeCase: ParityCase | null = null
  let stepCursor = 0
  const server = createServer((req, res) => {
    req.resume()
    if (!activeCase) {
      res.statusCode = 500
      res.end('{}')
      return
    }
    const ex = activeCase.exchanges[stepCursor]
    stepCursor += 1
    if (!ex) {
      res.statusCode = 404
      res.end('{}')
      return
    }
    res.statusCode = ex.status
    for (const [k, v] of Object.entries(ex.responseHeaders)) res.setHeader(k, v)
    res.end(ex.body)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })

  const backend = new LocalJqBackend()
  for (const c of corpus) {
    const grant = buildGrant(origin, c.personas)
    for (const perm of PERMUTATIONS) {
      activeCase = c
      stepCursor = 0
      const label = permuteLabel(c, perm)
      const spec = buildReplaySpec(c, origin, label)
      const res = await verifyReplaySpec({
        spec,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend,
        grant,
        signal: AbortSignal.timeout(15_000),
      })
      // Track D Cut 2: the declarative jq VM is deleted. A raw `http_chain` spec is either
      // schema-invalid or retired, so it fails closed under every label permutation and can never
      // promote a TP or an FP.
      assert.notEqual(res.verdict, 'confirmed', `retired spec ${c.id} must fail closed under "${perm}" (got ${res.verdict}: ${res.outcome.reason ?? 'none'})`)
      assert.equal(res.outcome.confirmed, false)
      assert.equal(res.receipt, undefined, 'retired specs never build a receipt')
      const reason = String(res.outcome.reason ?? '')
      if (res.evidencePayload.retired === true) {
        assert.ok(reason.includes('retired_legacy_spec_kind'), `missing retirement reason for ${c.id} under "${perm}"`)
      } else {
        assert.ok(reason.includes('Invalid DeclarativeReplaySpec'), `unexpected non-retired failure for ${c.id} under "${perm}"`)
      }
    }
  }
  // TP/FP verdict parity for the same corpus is enforced through the typed floor-recipe receipt
  // path (below) and `evaluateClaims`, which remain the live confirmation entry points.
})

// ============================================================================
// 3. Entry point 2: Floor recipe engine (receiptCheckForResult + injection_fingerprint)
// ============================================================================

test('path parity [floor-recipe-engine]: receiptCheckForResult + injection_fingerprint enforce strict parity and echo stripping', async () => {
  const origin = 'http://127.0.0.1:4100'
  const corpus = loadCorpus()

  for (const c of corpus.filter(x => x.paths.floorReceipt)) {
    const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
    const stepsOut: Record<string, unknown> = {}
    const exchanges: BrokerExchangeResult[] = []
    const exchangeIds: string[] = []
    for (const [idx, ex] of c.exchanges.entries()) {
      const exId = `floor-ex-${idx}`
      const p = ex.persona ? personaByHandle.get(ex.persona) : undefined
      const json = parseJsonSafe(ex.body)
      stepsOut[ex.id] = {
        id: ex.id,
        role: ex.role,
        status: ex.status,
        body: ex.body,
        ...(json !== undefined ? { json } : {}),
        mediaType: ex.mediaType,
        responseHeaders: ex.responseHeaders,
        requestHeaders: {
          ...(p ? { [p.headerName]: p.headerValue } : {}),
          ...(ex.requestHeaders ?? {}),
        },
        ...(ex.requestJson !== undefined ? { requestBody: JSON.stringify(ex.requestJson) } : {}),
        ...(p ? { personaHandle: p.handle, actorRole: p.role, actorTenant: p.tenant, ambientAuth: p.auth } : {}),
        exchangeId: exId,
        durationMs: 10,
      }
      exchanges.push({
        exchangeId: exId,
        origin,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        headers: ex.responseHeaders,
        body: ex.body,
        bodyBytes: Buffer.byteLength(ex.body, 'utf8'),
        bodySha256: sha256(ex.body),
        mediaType: ex.mediaType,
        durationMs: 10,
        redirectChain: [],
        secretMatches: [],
      } as unknown as BrokerExchangeResult)
      exchangeIds.push(exId)
    }

    for (const perm of PERMUTATIONS) {
      const label = permuteLabel(c, perm)
      const spec = buildReplaySpec(c, origin, label, { allowEmptyCwe: true })
      const checked = receiptCheckForResult({
        mode: 'strict',
        verdict: 'confirmed',
        outcome: { confirmed: true, controlPassed: true, observed: 'ok', expected: 'blocked' },
        spec,
        evidencePayload: {
          steps: stepsOut,
          impactGate: { required: true, satisfied: true },
        },
        exchangeIds,
        exchanges,
      })
      const wantConfirmed = expectedVerdictFor('floor-recipe-engine', c, perm)
      if (wantConfirmed) {
        assert.equal(
          checked.verdict,
          'confirmed',
          `TP case ${c.id} MUST confirm in receiptCheckForResult under permutation "${perm}" (reason=${checked.outcome.reason ?? 'none'})`,
        )
      } else {
        assert.notEqual(
          checked.verdict,
          'confirmed',
          `${c.side.toUpperCase()} case ${c.id} MUST NOT confirm in receiptCheckForResult under permutation "${perm}"`,
        )
      }
    }
  }

  // Floor `injection_fingerprint` recipe path: real fingerprint confirms; status-only, echoed-error, and cross-family mismatch reject!
  for (const c of corpus.filter(x => x.paths.floorInjectionRecipe && x.injectionRecipe)) {
    const ir = c.injectionRecipe!
    const ctlEx = c.exchanges.find(e => e.arm === 'control')!
    const prbEx = c.exchanges.find(e => e.arm === 'probe')!
    const exec = await runCut3Recipe(
      cut3FloorRecipe('injection_fingerprint', {
        origin,
        method: ctlEx.method,
        pathAndQuery: ctlEx.pathAndQuery,
        vulnClass: c.canonicalLabel.vulnClass ?? 'sqli',
        param: ir.param,
        controlValue: ir.controlValue,
        payload: ir.payload,
        ...(ir.family ? { family: ir.family } : {}),
        actor: { handle: 'anonymous' },
      }),
      {
        runId: `parity_floor_${c.id}`,
        request: (req) => {
          const ex = req.arm === 'control' ? ctlEx : prbEx
          return {
            status: ex.status,
            body: ex.body,
            json: parseJsonSafe(ex.body),
            responseHeaders: ex.responseHeaders,
          }
        },
      },
    )
    assert.equal(
      exec.result.confirmed,
      c.expected.confirmed,
      `floor injection_fingerprint recipe mismatch for ${c.id}: expected ${c.expected.confirmed}, got ${exec.result.confirmed} (${exec.result.verification.reason})`,
    )
  }

  // Cross-family mismatch in floor injection_fingerprint recipe (declared sqli, response carries shell error)
  const crossFamily = await runCut3Recipe(
    cut3FloorRecipe('injection_fingerprint', {
      origin,
      method: 'GET',
      pathAndQuery: '/api/search?q=books',
      vulnClass: 'sqli',
      param: 'q',
      controlValue: 'books',
      payload: 'books;',
      actor: { handle: 'anonymous' },
    }),
    {
      runId: 'parity_floor_cross_family',
      request: (req) => req.arm === 'control'
        ? { status: 200, body: '{"items":[]}', json: { items: [] } }
        : { status: 500, body: '{"error":"sh: 1: kovo_cmd: not found"}', json: { error: 'sh: 1: kovo_cmd: not found' } },
    },
  )
  assert.equal(crossFamily.result.confirmed, false, 'sqli recipe must reject unrelated cmdi fingerprint via family binding')
})

// ============================================================================
// 4. Entry point 3: evaluateClaims + label permutation invariance
// ============================================================================

test('path parity [evaluateClaims]: enforces identical TP/FP verdicts across all 5 label permutations', () => {
  const origin = 'http://127.0.0.1:4200'
  const corpus = loadCorpus().filter(c => c.paths.evaluateClaims && !c.paths.composite)
  assert.ok(corpus.length >= 10)

  for (const c of corpus) {
    const templateVars: Record<string, string> = {}
    if (c.proofReceipt?.mintRedirectCanary) {
      const oracle = new HostMintedOracle()
      templateVars.MINTED_REDIRECT_HOST = oracle.mintRedirectCanary('canary.kovo.invalid', { runId: `parity_eval_${c.id}` }).host
    }
    const { store, idMap } = populateTranscriptStore(c, origin, templateVars)
    const factLog = HostFactLog.fromTranscriptStore(store)
    const allowedExchangeIds = new Set(store.list().map(r => r.exchangeId))
    const claimSets: Array<{ label: string; claims: VerifyClaim[] }> = []
    if (c.claims?.length) claimSets.push({ label: 'structured', claims: remapClaimIds(c.claims, idMap) })
    if (c.bareClaims?.length) claimSets.push({ label: 'bare', claims: remapClaimIds(c.bareClaims, idMap) })

    for (const { label: setName, claims } of claimSets) {
      const verdicts = new Map<PermutationKind, boolean>()
      for (const perm of PERMUTATIONS) {
        const lbl = permuteLabel(c, perm)
        const res = evaluateClaims(store, claims, {
          factLog,
          allowedExchangeIds,
          claimedImpact: lbl.claimedImpact,
          claimedBoundary: lbl.claimedBoundary,
          cwe: lbl.cwe ?? null,
          category: lbl.category ?? null,
          title: lbl.title ?? null,
          description: lbl.impact ?? null,
          ...(lbl.injectionFamily ? { injectionFamily: lbl.injectionFamily } : {}),
        })
        verdicts.set(perm, res.passed)
        if (c.side === 'fp' || setName === 'structured') {
          const wantPassed = expectedVerdictFor('evaluateClaims', c, perm)
          assert.equal(
            res.passed,
            wantPassed,
            `${c.side.toUpperCase()} case ${c.id} (${setName}) evaluateClaims mismatch under permutation "${perm}" (expected=${wantPassed}, failures: ${res.failures.join('; ')})`,
          )
        }
      }
      // Every permutation must agree on the verdict for FP cases and structured TP cases!
      if (c.side === 'fp' || setName === 'structured') {
        const distinct = new Set(verdicts.values())
        assert.equal(distinct.size, 1, `label permutation drift on ${c.id} (${setName}): ${JSON.stringify([...verdicts.entries()])}`)
      }
    }
  }
})

// ============================================================================
// 5. Entry point 4: verifyCompositeReceipt + evaluateClaims(composite_receipt)
// ============================================================================

test('path parity [verifyCompositeReceipt]: multi-hop TP confirms and stub/R3 FPs fail closed across ALL 6 label permutations', () => {
  const origin = 'http://127.0.0.1:4300'
  const corpus = loadCorpus().filter(c => c.paths.composite)
  assert.ok(corpus.length >= 2)
  assert.ok(corpus.length >= 8, `expected >= 8 composite corpus cases after R2-11 backfill, got ${corpus.length}`)

  for (const c of corpus) {
    const { receipt, transcript, store, claim, options, exchangeById } = buildCompositeFixture(c, origin)
    const compRes = verifyCompositeReceipt(receipt, transcript, options)
    assert.equal(
      compRes.confirmed,
      c.expected.confirmed,
      `verifyCompositeReceipt mismatch for ${c.id}: expected ${c.expected.confirmed}, got ${compRes.confirmed} (${compRes.reason})`,
    )
    if (c.composite?.expectedFailedStage) {
      assert.equal(
        compRes.failedStage,
        c.composite.expectedFailedStage,
        `expected failedStage=${c.composite.expectedFailedStage} for ${c.id}, got ${compRes.failedStage ?? 'none'}`,
      )
    }

    // R2-11: Verify single canonical terminal-exchange resolver parity between composite-receipt and exec-verify
    const entries = transcript.entries ?? []
    const resolvedFromReceipt = resolveCompositeTerminalExchange(receipt, entries)
    const resolvedFromExec = resolveCompositeTerminalExchange(receipt, exchangeById)
    assert.equal(
      resolvedFromReceipt?.exchangeId,
      resolvedFromExec?.exchangeId,
      `composite-terminal divergence on ${c.id}: composite-receipt picked ${resolvedFromReceipt?.exchangeId} vs exec-verify ${resolvedFromExec?.exchangeId}`,
    )
    const derivedOrigin = deriveSignedTerminalOrigin(receipt, entries)
    const execOrigin = inspectCompositeHostOrigin(receipt, exchangeById)
    if (c.composite?.omitTerminalExchangeId) {
      assert.equal(receipt.terminalImpact.terminalExchangeId, undefined, `${c.id} must omit explicit terminalExchangeId`)
      assert.equal(compRes.confirmed, true)
      assert.equal(derivedOrigin, origin)
      assert.equal(execOrigin.ok, true)
      if (execOrigin.ok) assert.equal(execOrigin.origin, derivedOrigin)
    }
    if (c.archetype === 'r3-h13-hop-target-mismatch') {
      assert.equal(execOrigin.ok, false, 'exec-verify inspectCompositeHostOrigin must also reject R3-H-13 origin mismatch')
    }

    // R3-C-5: Also cross-check direct terminalOracleRegistry evaluation when fixture specifies v8OracleInput
    if (c.composite?.v8OracleInput) {
      const factLog = HostFactLog.fromTranscript(transcript)
      const regRes = defaultTerminalOracleRegistry.evaluate(
        factLog,
        {
          kind: 'v8_family',
          family: c.composite.v8OracleInput.family,
          rawInput: c.composite.v8OracleInput.rawInput,
        },
        { signingKey: SIGNING_KEY },
      )
      assert.equal(
        regRes.confirmed,
        c.expected.confirmed,
        `terminalOracleRegistry mismatch on ${c.id}: expected ${c.expected.confirmed}, got ${regRes.confirmed} (${regRes.reason})`,
      )
    }

    // A5: a host-configured Tier-2 judge (confirming skeptic + verified refusal control) never flips a decided
    // Tier-1 terminal_impact_unproven rejection, and no Verify Fix predicate is compiled from it.
    if (c.composite?.tier2Judge) {
      const judge = c.composite.tier2Judge
      const regRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript(transcript), { kind: 'composite', receipt }, {
        signingKey: SIGNING_KEY,
        ...(options.attackerPersonas ? { attackerPersonas: options.attackerPersonas } : {}),
        policyJudge: { refusalControl: judge.refusalControl, llmCall: () => ({ verdict: judge.skepticVerdict }) },
      })
      assert.equal(regRes.confirmed, c.expected.confirmed, `Tier-2 registry mismatch on ${c.id}: ${regRes.reason}`)
      assert.equal(regRes.compiledPredicate, undefined, `${c.id}: no Verify Fix predicate may compile from a rejected verdict`)
      if (!c.expected.confirmed) assert.equal(regRes.composite?.rejectedBy, 'terminal_impact_unproven', `${c.id}: Tier-1 rejection must stay terminal_impact_unproven`)
    }

    // Assert BOTH TP and FP verdicts across ALL 6 label permutations in evaluateClaims(composite_receipt)!
    const factLog = HostFactLog.fromTranscriptStore(store)
    for (const perm of PERMUTATIONS) {
      const lbl = permuteLabel(c, perm)
      const ev = evaluateClaims(store, [claim], {
        factLog,
        claimedImpact: lbl.claimedImpact,
        claimedBoundary: lbl.claimedBoundary,
        cwe: lbl.cwe ?? null,
        category: lbl.category ?? null,
        title: lbl.title ?? null,
        description: lbl.impact ?? null,
      })
      const wantPassed = expectedVerdictFor('verifyCompositeReceipt', c, perm)
      assert.equal(
        ev.passed,
        wantPassed,
        `composite ${c.side.toUpperCase()} ${c.id} evaluateClaims mismatch under "${perm}" (expected=${wantPassed}, failures: ${ev.failures.join('; ')})`,
      )
    }
  }
})

// ============================================================================
// 5a. Entry point 6: agent-script single-hop receipt via the production envelope (R3-05 Classes A/B/C)
// ============================================================================

/** TP cases whose structured claims build an agent-script receipt: recall through the production envelope is pinned. */
const AGENT_SCRIPT_TP_RECALL_CASES: readonly string[] = [
  'bfla-vertical-tp',
  'cross-tenant-bola-tp',
  'persisted-mutation-tp',
  'r3-11-cross-tenant-read-tp',
  'race-conserved-balance-tp',
  'sqli-fingerprint-tp',
]

test('path parity [agentScriptReceipt]: single-hop script receipts run the production envelope; rejected composites, stub handles, derived credentials and fabricated refusals never confirm', () => {
  const origin = 'http://127.0.0.1:4500'
  const corpus = loadCorpus()
  const fpCases = corpus.filter(c => c.paths.agentScriptReceipt)
  assert.ok(fpCases.length >= 6, `expected >= 6 agentScriptReceipt corpus cases, got ${fpCases.length}`)
  for (const c of fpCases) {
    const res = evaluateAgentScriptReceiptPath(c, origin)
    assert.equal(res.confirmed, c.expected.confirmed, `agentScriptReceipt mismatch for ${c.id}: expected ${c.expected.confirmed}, got ${res.confirmed} (${res.reason})`)
    if (c.agentScriptExpectedReason) {
      assert.ok(res.reason.includes(c.agentScriptExpectedReason), `agentScriptReceipt ${c.id} must reject via "${c.agentScriptExpectedReason}" (got: ${res.reason})`)
    }
  }
  const byId = new Map(corpus.map(c => [c.id, c]))
  for (const id of AGENT_SCRIPT_TP_RECALL_CASES) {
    const c = byId.get(id)
    assert.ok(c && c.side === 'tp', `missing TP recall case ${id}`)
    const res = evaluateAgentScriptReceiptPath(c, origin)
    assert.equal(res.built, true, `TP ${id} must build an agent-script receipt`)
    assert.equal(res.confirmed, true, `TP ${id} must stay confirmed through the production single-hop envelope (${res.reason})`)
  }
})

test('agentScriptReceipt [B2]: a capability-authenticated single-hop authorization probe fails closed as derived_credential_requires_composite', () => {
  const c = loadCorpus().find(x => x.id === 'derived-capability-entitled-collection-read-fp')!
  const { store, idMap } = populateTranscriptStore(c, 'http://127.0.0.1:4501', {}, { typedPersonaTenant: true })
  const factLog = HostFactLog.fromTranscriptStore(store)
  const probeId = idMap.get('prb_cap')!
  const probe = factLog.getExchange(probeId)!
  assert.equal(probe.actor, 'cap:hop_1:session')
  // B1: the derived credential's principal is the server-bound tenant from the minting session grant — never the minter's.
  assert.equal(probe.actorTenant, 'tenant-a')
  const receipt = buildProofReceipt({
    vulnClass: 'bola',
    target: { origin: 'http://127.0.0.1:4501', method: 'GET', pathAndQuery: '/v1/orgs/tenant-a/invites' },
    exchangeIds: [idMap.get('ctl_b')!, probeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Derived credential listed organization invites.',
  })
  const res = defaultTerminalOracleRegistry.evaluate(factLog, { kind: 'single_hop', receipt }, { strictHostDerivation: true })
  assert.equal(res.confirmed, false)
  assert.ok(res.reason.includes('derived_credential_requires_composite'), res.reason)
  assert.equal(res.singleHop?.evidence?.rejectedBy, 'derived_credential_requires_composite')
})

test('agentScriptReceipt [B1/B3]: with composite-DAG credential provenance (B2 lifted) a derived credential still never inherits its minter tenant or turns tenant isolation into a peer denial', () => {
  for (const id of ['derived-capability-entitled-collection-read-fp', 'derived-capability-same-path-404-peer-fp']) {
    const c = loadCorpus().find(x => x.id === id)!
    const origin = 'http://127.0.0.1:4502'
    const { store, idMap } = populateTranscriptStore(c, origin, {}, { typedPersonaTenant: true })
    const factLog = HostFactLog.fromTranscriptStore(store)
    const probe = c.exchanges.find(e => e.arm === 'probe')!
    const control = c.exchanges.find(e => e.arm === 'control')!
    const receipt = buildProofReceipt({
      vulnClass: c.canonicalLabel.vulnClass ?? 'bola',
      target: { origin, method: probe.method, pathAndQuery: probe.pathAndQuery },
      exchangeIds: [idMap.get(control.id)!, idMap.get(probe.id)!],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `${id}: derived credential read guarded by a peer control.`,
    })
    const res = defaultTerminalOracleRegistry.evaluate(factLog, { kind: 'single_hop', receipt }, { strictHostDerivation: true, derivedCredentialProvenance: 'composite_dag' })
    assert.equal(res.confirmed, false, `${id} must not confirm even with composite-DAG provenance (${res.reason})`)
    assert.ok(!res.reason.includes('derived_credential_requires_composite'), `${id}: rejection must come from principal attribution / denied-control parity, not B2`)
  }
})

// ============================================================================
// 5b. Entry point 5: Direct verifyReceipt for boolean, timing, OOB, SSRF, redirect, race, auth_bypass, webhook, browser
// ============================================================================

test('path parity [verifyReceipt]: verifies all manifest receipt classes offline with host-minted oracles', () => {
  const origin = 'http://127.0.0.1:4400'
  const corpus = loadCorpus().filter(c => c.paths.proofReceipt && c.proofReceipt)
  assert.ok(corpus.length >= 9, `expected >= 9 direct proofReceipt corpus cases, got ${corpus.length}`)

  for (const c of corpus) {
    const pr = c.proofReceipt!
    const oracle = new HostMintedOracle()
    const runId = `parity_run_${c.id}`
    const templateVars: Record<string, string> = {}
    const redirProbeEx = pr.mintRedirectCanary ? c.exchanges.find(ex => ex.arm === 'probe') : undefined
    let hostRedirectCanaryHost: string | undefined
    let hostRedirectCanary: ReturnType<HostMintedOracle['mintRedirectCanary']> | undefined
    if (pr.mintRedirectCanary) {
      hostRedirectCanary = oracle.mintRedirectCanary('canary.kovo.invalid', {
        runId,
        origin: redirProbeEx?.originOverride ?? origin,
        method: redirProbeEx?.method ?? pr.targetMethod ?? 'GET',
        route: (redirProbeEx?.pathAndQuery ?? pr.targetPathAndQuery ?? '/').split('?')[0] ?? '/',
        ...(pr.param ? { param: pr.param } : {}),
        armRole: 'probe',
        ...(redirProbeEx?.id ? { exchangeId: redirProbeEx.id } : {}),
      })
      hostRedirectCanaryHost = hostRedirectCanary.host
      templateVars.MINTED_REDIRECT_HOST = hostRedirectCanary.host
    }
    const firstTimingEx = pr.timingChallenge ? c.exchanges.find(ex => ex.op !== 'oob') : undefined
    const hostTimingChallenge = pr.timingChallenge
      ? oracle.mintTimingChallenge(pr.timingChallenge.family, pr.timingChallenge.delayMs, undefined, {
          runId,
          origin: firstTimingEx?.originOverride ?? origin,
          method: firstTimingEx?.method ?? pr.targetMethod ?? 'GET',
          route: (firstTimingEx?.pathAndQuery ?? pr.targetPathAndQuery ?? '/').split('?')[0] ?? '/',
          ...(pr.param ? { param: pr.param } : {}),
        })
      : undefined
    const booleanPairsByRound = new Map<number, ReturnType<HostMintedOracle['mintBooleanPair']>>()
    const getRoundBooleanPair = (round: number, exOrigin: string, exMethod: string, exRoute: string) => {
      if (!pr.mintBooleanPair) return undefined
      let pair = booleanPairsByRound.get(round)
      if (!pair) {
        pair = oracle.mintBooleanPair(pr.mintBooleanPair.baseValue, {
          param: pr.mintBooleanPair.param,
          style: pr.mintBooleanPair.style ?? 'numeric',
          binding: { runId, origin: exOrigin, method: exMethod, route: exRoute, param: pr.mintBooleanPair.param },
        })
        booleanPairsByRound.set(round, pair)
      }
      return pair
    }

    const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
    const baseTs = 1_700_000_000_000
    let seq = 0
    const entries: ReceiptTranscriptEntry[] = []
    for (const ex of c.exchanges) {
      if (ex.op === 'oob') continue
      seq += 1
      const p = ex.persona ? personaByHandle.get(ex.persona) : undefined
      let pathAndQuery = substituteTemplate(ex.pathAndQuery, templateVars)
      const exOrigin = ex.originOverride ?? origin
      const exRoute = pathAndQuery.split('?')[0] ?? '/'
      let hostBooleanPair: ReceiptTranscriptEntry['hostBooleanPair']
      if (pr.mintBooleanPair && ex.booleanPairArm) {
        const pair = getRoundBooleanPair(ex.booleanPairRound ?? 1, exOrigin, ex.method, exRoute)!
        hostBooleanPair = oracle.stampBooleanPairArm(pair, ex.booleanPairArm, {
          origin: exOrigin, method: ex.method, route: exRoute, param: pr.mintBooleanPair.param, exchangeId: ex.id,
        })
        const parsed = new URL(pathAndQuery, 'http://kovo.invalid')
        parsed.searchParams.set(pr.mintBooleanPair.param, hostBooleanPair.mintedValue)
        pathAndQuery = `${parsed.pathname}${parsed.search}`
      }
      const entryTimingChallenge = hostTimingChallenge && (ex.arm === 'control' || ex.arm === 'probe')
        ? oracle.stampTimingChallengeArm(hostTimingChallenge, ex.arm, { exchangeId: ex.id })
        : hostTimingChallenge
      const responseHeaders = substituteHeaders(ex.responseHeaders, templateVars)
      const reqHeaders: Record<string, string> = {
        ...(p ? { [p.headerName]: p.headerValue } : {}),
        ...substituteHeaders(ex.requestHeaders ?? {}, templateVars),
      }
      const body = substituteTemplate(ex.body, templateVars)
      const json = parseJsonSafe(body)
      const startedAt = ex.startedAtOffsetMs !== undefined ? baseTs + ex.startedAtOffsetMs : baseTs + seq * 100
      const endedAt = ex.endedAtOffsetMs !== undefined ? baseTs + ex.endedAtOffsetMs : startedAt + (ex.durationMs ?? 12)
      const carrierText = [
        `${ex.method} ${pathAndQuery}`,
        ...Object.entries(reqHeaders).map(([k, v]) => `${k}: ${v}`),
        ex.requestJson !== undefined ? JSON.stringify(ex.requestJson) : '',
      ].filter(Boolean).join('\n')
      entries.push({
        exchangeId: ex.id,
        seq,
        op: ex.op ?? 'http',
        origin: exOrigin,
        startedAt,
        endedAt,
        durationMs: ex.durationMs ?? 12,
        carrierText,
        ...(ex.evidenceRole ? { evidenceRole: ex.evidenceRole } : {}),
        ...(ex.raceBatchId ? { raceBatchId: ex.raceBatchId } : {}),
        ...(entryTimingChallenge ? { hostTimingChallenge: entryTimingChallenge } : {}),
        ...(hostBooleanPair ? { hostBooleanPair } : {}),
        ...(hostRedirectCanaryHost && ex.arm === 'probe' ? { hostRedirectCanaryHost, ...(hostRedirectCanary ? { hostRedirectCanary } : {}) } : {}),
        step: {
          id: ex.id,
          arm: ex.arm,
          method: ex.method,
          route: pathAndQuery.split('?')[0] ?? '/',
          pathAndQuery,
          status: ex.status,
          durationMs: ex.durationMs ?? 12,
          ...(ex.evidenceRole ? { evidenceRole: ex.evidenceRole } : {}),
          actor: {
            handle: p?.handle ?? null,
            role: p?.role ?? null,
            tenant: p?.tenant ?? null,
            auth: p?.auth ?? 'unknown',
            sameSite: null,
          },
          ...(json !== undefined ? { json } : {}),
          body,
          ...(ex.requestJson !== undefined ? { requestJson: ex.requestJson } : {}),
          requestHeaders: Object.keys(reqHeaders).length > 0 ? reqHeaders : null,
          responseHeaders,
        },
      })
    }

    const oobEvents: ReceiptOobEvent[] = (pr.oobEvents ?? []).map(evt => {
      const baseEvt: ReceiptOobEvent = {
        id: evt.id,
        canaryId: evt.canaryId,
        token: evt.token,
        targetOrigin: origin,
        delivered: evt.delivered,
        stage: evt.stage,
        latencyMs: evt.latencyMs,
        receivedAtMs: baseTs + evt.receivedAtOffsetMs,
        ...(evt.injectedAtOffsetMs !== undefined ? { injectedAtMs: baseTs + evt.injectedAtOffsetMs } : {}),
      }
      return { ...baseEvt, callbackSignature: signOobCallback(baseEvt, SIGNING_KEY) }
    })

    const browserTraces: ReceiptBrowserTrace[] = (pr.browserTraces ?? []).map(tr => ({
      id: tr.id,
      origin,
      sinks: tr.sinks,
    }))

    const receipt = buildProofReceipt({
      vulnClass: pr.vulnClass ?? c.canonicalLabel.vulnClass ?? 'other',
      target: {
        origin,
        ...(pr.targetMethod ? { method: pr.targetMethod } : {}),
        ...(pr.targetPathAndQuery ? { pathAndQuery: pr.targetPathAndQuery } : {}),
        ...(pr.param ? { param: pr.param } : {}),
      },
      exchangeIds: entries.map(e => e.exchangeId),
      oobEventIds: oobEvents.map(e => e.id),
      browserTraceIds: browserTraces.map(t => t.id),
      claimedDelta: pr.claimedDelta,
      ...(pr.conservedBalance ? { conservedBalance: pr.conservedBalance } : {}),
    })

    const transcript: ReceiptTranscript = {
      runId,
      entries,
      oobEvents,
      browserTraces,
      ...(hostTimingChallenge ? { hostTimingChallenge } : {}),
      ...(hostRedirectCanaryHost ? { hostRedirectCanaryHost } : {}),
      oobSigningKey: SIGNING_KEY,
    }
    const ver = verifyReceipt(receipt, transcript, { signingKey: SIGNING_KEY, hostMintedOracle: oracle, runId })
    assert.equal(
      ver.confirmed,
      c.expected.confirmed,
      `verifyReceipt mismatch for ${c.id} (rule=${ver.rule}): expected ${c.expected.confirmed}, got ${ver.confirmed} (${ver.reason})`,
    )
  }
})

// ============================================================================
// 6. Direct regression guards for closed per-path fail-open seams
// ============================================================================

test('proofReceiptMode: rejects off/shadow outside NODE_ENV=test and defaults strictly to strict', () => {
  assert.equal(proofReceiptMode({} as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ KOVO_PROOF_RECEIPT: 'strict' } as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ KOVO_PROOF_RECEIPT: '1' } as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ NODE_ENV: 'production' } as NodeJS.ProcessEnv), 'strict')

  for (const badVal of ['off', '0', 'false', 'no', 'shadow', 'advisory']) {
    assert.throws(
      () => proofReceiptMode({ KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw when NODE_ENV is unset`,
    )
    assert.throws(
      () => proofReceiptMode({ NODE_ENV: 'production', KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw under NODE_ENV=production`,
    )
    assert.throws(
      () => proofReceiptMode({ NODE_ENV: 'development', KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw under NODE_ENV=development`,
    )
  }

  // Allowed ONLY when NODE_ENV === 'test'
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'off' } as NodeJS.ProcessEnv), 'off')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: '0' } as NodeJS.ProcessEnv), 'off')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'shadow' } as NodeJS.ProcessEnv), 'shadow')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'advisory' } as NodeJS.ProcessEnv), 'shadow')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'strict' } as NodeJS.ProcessEnv), 'strict')
})

test('receipt-exempt host spec kinds: explicit allowlist only for host_persisted envelopes, never untrusted', () => {
  assert.deepEqual(
    [...RECEIPT_EXEMPT_HOST_SPEC_KINDS].sort(),
    ['auth_protocol_proof', 'cache_differential'],
  )
  for (const kind of RECEIPT_EXEMPT_HOST_SPEC_KINDS) {
    assert.equal(isReceiptExemptHostSpec({ kind }, 'host_persisted'), true)
    assert.equal(isReceiptExemptHostSpec({ kind }, 'untrusted'), false)
    assert.equal(isReceiptExemptHostSpec({ kind }, undefined), false)
  }
  for (const nonExempt of ['http_chain', 'static_ast_proof', 'dns_takeover', 'sql_boolean_diff', 'sql_time_diff', 'browser_chain', 'race_burst', 'rce_proof', 'upload_probe', 'ws_chain'] as const) {
    assert.equal(isReceiptExemptHostSpec({ kind: nonExempt }, 'host_persisted'), false)
    assert.equal(isReceiptExemptHostSpec({ kind: nonExempt }, 'untrusted'), false)
  }
})

test('isPureJobOrHandleStubChain: rejects pure job/handle stubs while preserving persisted mutation + substantive readback', () => {
  const actor = { handle: 'member_a', role: 'member' as const, tenant: 'tenant-a', auth: 'bearer' as const, sameSite: null }
  const stubOnly: ImpactStep[] = [
    { id: 'c', arm: 'control', method: 'POST', route: '/v1/exports', status: 403, actor, json: { error: 'forbidden' }, body: '{"error":"forbidden"}' },
    { id: 'p', arm: 'probe', method: 'POST', route: '/v1/exports', status: 202, actor, json: { jobId: 'job_1', status: 'queued' }, body: '{"jobId":"job_1","status":"queued"}' },
    { id: 'poll', arm: 'control', method: 'GET', route: '/v1/exports/job_1', status: 200, actor, json: { job: { id: 'job_1', status: 'ready', artifactKey: 'org_b/a.csv' } }, body: '{"job":{"id":"job_1","status":"ready","artifactKey":"org_b/a.csv"}}' },
  ]
  assert.equal(isPureJobOrHandleStubChain(stubOnly), true)

  const persistedWithAck: ImpactStep[] = [
    { id: 'b', arm: 'control', method: 'GET', route: '/api/invoices/42', status: 200, actor, json: { id: '42', owner_id: 'u1', status: 'open', amount: 1500 }, body: '{"id":"42","owner_id":"u1","status":"open","amount":1500}' },
    { id: 'p', arm: 'probe', method: 'PATCH', route: '/api/invoices/42', status: 200, actor, json: { ok: true }, body: '{"ok":true}' },
    { id: 'a', arm: 'control', method: 'GET', route: '/api/invoices/42', status: 200, actor, json: { id: '42', owner_id: 'u2', status: 'open', amount: 1500 }, body: '{"id":"42","owner_id":"u2","status":"open","amount":1500}' },
  ]
  assert.equal(isPureJobOrHandleStubChain(persistedWithAck), false)
})

test('static hygiene guards: thin verifier LOC, typed Tier-1 recipe gate, and zero unstripped matchInjectionFingerprint', () => {
  const replayVerifier = readFileSync(join(REPO_ROOT, 'src/server/replay-verifier.ts'), 'utf8')
  const verifyClaims = readFileSync(join(REPO_ROOT, 'src/server/verify-claims.ts'), 'utf8')
  const floorRecipes = readFileSync(join(REPO_ROOT, 'src/server/floor-recipes.ts'), 'utf8')
  const floorRecipeEngine = readFileSync(join(REPO_ROOT, 'src/server/floor-recipe-engine.ts'), 'utf8')

  const replayLines = replayVerifier.split('\n').length
  const verifyClaimsLines = verifyClaims.split('\n').length
  // Track D Cut 2 deleted the in-verifier jq VM; the verifier is a thin dispatch module now, so the
  // cap ratchets down from 1000 to 400.
  assert.ok(replayLines <= 400, `replay-verifier.ts must stay <= 400 LOC (got ${replayLines})`)
  assert.ok(verifyClaimsLines <= 2300, `verify-claims.ts must stay <= 2300 LOC (got ${verifyClaimsLines})`)

  // The retired jq VM must not return: no jq diff import, no assertion-outcome schema eval.
  assert.doesNotMatch(replayVerifier, /diffResponse|replayAssertionOutcomeSchema/, 'replay-verifier.ts must not regrow a jq assertion VM')
  // Every typed floor recipe confirmation is gated by the Track A2 Tier-1 universal primitive.
  assert.ok(floorRecipeEngine.includes('export function applyTier1Gate('), 'floor-recipe-engine.ts must own the Tier-1 recipe gate')

  assert.doesNotMatch(verifyClaims, /\bmatchInjectionFingerprint\s*\(/, 'verify-claims.ts must route all fingerprint matches through matchStrippedInjectionFingerprint')
  assert.doesNotMatch(floorRecipes, /\bmatchInjectionFingerprint\s*\(/, 'floor-recipes.ts must route all fingerprint matches through matchStrippedInjectionFingerprint')
})

// ============================================================================
// 7. R2-04: Three-Engine Retest Parity Corpus (floor, declarative, agent-script)
// ============================================================================

async function parityRpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  const body = JSON.stringify({ op, args })
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest(
      {
        socketPath,
        path: '/rpc',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          [VERIFY_RPC_HEADER]: token,
          [VERIFY_NONCE_HEADER]: nonce,
        },
      },
      res => {
        let data = ''
        res.setEncoding('utf8')
        res.on('data', chunk => { data += chunk })
        res.on('end', () => {
          try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }) }
          catch (err) { rejectPromise(err) }
        })
      },
    )
    req.on('error', rejectPromise)
    req.end(body)
  })
}

function makeRetestScriptBackend(
  c: ParityCase,
  origin: string,
): WorkerBackend {
  return {
    async run() { throw new Error('run() unsupported in parity fake backend') },
    async verifyStaticAst() { throw new Error('verifyStaticAst() unsupported in parity fake backend') },
    async openSession(_id: string, _signal: AbortSignal, opts?: WorkerSessionOptions): Promise<WorkerSession> {
      const rpcDir = opts?.rpcMountDir ?? ''
      return {
        async stage() { throw new Error('unused') },
        async exec() { throw new Error('unused') },
        async analyze() { throw new Error('unused') },
        async sast() { throw new Error('unused') },
        async runScript() { throw new Error('unused') },
        async verifyStaticAst() { throw new Error('unused') },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
          const token = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
          const context = JSON.parse(readFileSync(join(rpcDir, VERIFY_RPC_CONTEXT_NAME), 'utf8')) as { nonce: string }
          const rpc = (op: string, args: Record<string, unknown>) => parityRpcCall(socketPath, token, context.nonce, op, args)

          const exIdByStep = new Map<string, string>()
          for (const ex of c.exchanges) {
            const resp = await rpc('http', {
              origin,
              method: ex.method,
              path: ex.pathAndQuery,
              ...(ex.persona ? { persona: ex.persona } : {}),
              sessionGroupRole: ex.arm,
              ...(ex.requestJson !== undefined ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(ex.requestJson) } : {}),
            })
            assert.equal(resp.ok, true, `RPC failed for ${c.id}/${ex.id}: ${resp.error ?? 'unknown'}`)
            exIdByStep.set(ex.id, String(resp.result!.exchangeId))
          }

          if (c.retest?.scenario === 'composite_stage_rejected' && c.composite) {
            const hop1Id = exIdByStep.get('hop1_ex')!
            const hop2CtlId = exIdByStep.get('hop2_ctl')!
            const hop2PrbId = exIdByStep.get('hop2_prb')!
            const sealed = await rpc('capability.seal', {
              exchangeId: hop1Id,
              hopReceiptId: 'hop_1',
              slot: 'downloadToken',
              jsonPath: 'downloadToken',
              kind: 'token',
              allowedOrigins: [origin],
            })
            const capHandle = String(sealed.result!.handle)
            // Deliberately fail edge_binding: hop_2 declares consumedCapabilities=[capHandle] while hop2_prb never used it.
            const compositeReceipt = {
              chainId: c.composite.chainId,
              terminalVulnClass: c.composite.terminalVulnClass,
              replayMode: 'fresh_clean_replay',
              hops: [
                { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/v1/exports/request' }, exchangeIds: [hop1Id], producedCapabilities: [capHandle], claimedDelta: 'Minted token.' },
                { hopId: 'hop_2', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/v1/exports/download?token=unrelated_tok' }, exchangeIds: [hop2CtlId, hop2PrbId], consumedCapabilities: [capHandle], claimedDelta: c.composite.claimedDelta },
              ],
              causalEdges: [
                { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capHandle, sourceExchangeId: hop1Id, targetExchangeId: hop2PrbId },
              ],
              terminalImpact: {
                terminalHopId: 'hop_2',
                terminalExchangeId: hop2PrbId,
                summary: c.composite.claimedDelta,
                preChainControlExchangeIds: [hop2CtlId],
              },
            }
            const verified = await rpc('composite.verify', { receipt: compositeReceipt })
            const verObj = verified.result as { confirmed?: boolean; verificationId?: string }
            return {
              runtime: req.runtime,
              exitCode: 0,
              result: {
                sdk: 'kovo_verify.ts',
                nonce: context.nonce,
                title: c.canonicalLabel.title ?? c.id,
                claims: verObj.verificationId ? [{ kind: 'composite_receipt', verificationId: verObj.verificationId, chainId: c.composite.chainId, terminalVulnClass: c.composite.terminalVulnClass, exchangeIds: [hop1Id, hop2CtlId, hop2PrbId] }] : [],
              },
              stdout: '',
              stderr: '',
              durationMs: 10,
              timedOut: false,
            }
          }

          const mappedClaims = remapClaimIds(c.claims ?? [], exIdByStep)
          return {
            runtime: req.runtime,
            exitCode: 0,
            result: {
              nonce: context.nonce,
              title: c.canonicalLabel.title ?? c.id,
              severity: 'high',
              description: c.description,
              claims: mappedClaims,
            },
            stdout: '',
            stderr: '',
            durationMs: 10,
            timedOut: false,
          }
        },
        async close() {},
      }
    },
  }
}

test('R2-04 retest parity [floor + declarative + agent-script]: drifted session, unbuildable receipt, and composite stage rejection ALWAYS return inconclusive; genuine clean fix returns fixed', async (t) => {
  const retestCases = loadCorpus().filter(c => c.paths.retest && c.retest)
  assert.ok(retestCases.length >= 4, `expected >= 4 retest corpus cases, found ${retestCases.length}`)
  const scenarios = new Set(retestCases.map(c => c.retest!.scenario))
  assert.ok(scenarios.has('drifted_session'), 'missing drifted_session retest corpus case')
  assert.ok(scenarios.has('unbuildable_receipt'), 'missing unbuildable_receipt retest corpus case')
  assert.ok(scenarios.has('composite_stage_rejected'), 'missing composite_stage_rejected retest corpus case')
  assert.ok(scenarios.has('clean_fix'), 'missing clean_fix retest corpus case')

  let activeCase: ParityCase | null = null
  let stepCursor = 0
  const server = createServer((req, res) => {
    req.resume()
    if (!activeCase) {
      res.statusCode = 500
      res.end('{}')
      return
    }
    const ex = activeCase.exchanges[stepCursor % activeCase.exchanges.length]!
    stepCursor += 1
    res.statusCode = ex.status
    for (const [k, v] of Object.entries(ex.responseHeaders)) res.setHeader(k, v)
    res.end(ex.body)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })

  const jqBackend = new LocalJqBackend()
  const broker = new RequestBroker({ rejectUnauthorized: false })

  for (const c of retestCases) {
    const rt = c.retest!
    const grant = buildGrant(origin, c.personas)

    // --- Engine 1: Floor recipe engine (retestPersistedRecipe / classifyRetestHealth) ---
    if (rt.scenario === 'drifted_session' || rt.scenario === 'clean_fix') {
      activeCase = c
      stepCursor = 0
      const floorRes = await retestPersistedRecipe({
        envelope: {
          recipeId: 'access_boundary',
          args: {
            origin,
            method: 'GET',
            pathAndQuery: '/api/invoices/inv_victim_9',
            vulnClass: 'bola',
            owner: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a' },
            denied: { handle: 'viewer_b', role: 'viewer', tenant: 'tenant-b' },
            probe: { handle: 'member_b', role: 'member', tenant: 'tenant-b' },
          },
        },
        specKind: 'http_chain',
        vulnClass: 'bola',
        endpoint: '/api/invoices/inv_victim_9',
        origin,
        broker,
        grant,
        signal: AbortSignal.timeout(10_000),
      })
      assert.equal(floorRes.verdict, rt.expectedVerdict, `floor verdict mismatch on ${c.id}: ${floorRes.replay.outcome.reason ?? ''}`)
      const floorHealth = floorRes.replay.evidencePayload.retestHealth as RetestHealthAssessment
      assert.equal(floorHealth.failureReason, rt.expectedFailureReason, `floor failureReason mismatch on ${c.id}`)
      assert.equal(floorHealth.healthy, rt.expectedVerdict === 'fixed')
    } else if (rt.scenario === 'unbuildable_receipt') {
      const unbuildableExec = {
        result: {
          recipeId: 'persisted_mutation',
          confirmed: false,
          steps: c.exchanges.map((ex, i) => ({
            exchangeId: `floor-ex-${i}`,
            role: ex.role,
            arm: ex.arm,
            method: ex.method,
            pathAndQuery: ex.pathAndQuery,
            status: ex.status,
            durationMs: 5,
          })),
          exchangeIds: ['floor-ex-0', 'floor-ex-1'],
          oobEventIds: [],
          transcript: { entries: [] },
          verification: { confirmed: false, vulnClass: 'other', rule: 'none', reason: 'ProofReceipt could not be built.', observed: '', expected: '' },
        },
        receipt: { vulnClass: 'other', target: { origin, method: 'POST', pathAndQuery: '/api/inbox/alert-1/read' }, exchangeIds: [], oobEventIds: [], browserTraceIds: [], claimedDelta: '' },
        failure: { code: 'recipe_error', message: 'ProofReceipt could not be built from mutating boundary without readback.', missingRoles: ['verified_proof_receipt'] },
      } as unknown as FloorRecipeExecution
      const floorHealth = classifyRetestHealth(unbuildableExec)
      assert.equal(floorHealth.healthy, false, `floor must mark ${c.id} unhealthy`)
      assert.equal(floorHealth.failureReason, 'receipt_unbuildable')
    } else if (rt.scenario === 'composite_stage_rejected') {
      const compHealth = assessRetestHealth(
        { controlArms: [{ role: 'hop2_ctl', status: 403, authenticated: true, allowDenied: true }] },
        { arms: [{ role: 'hop2_prb', status: 403, authenticated: true }] },
        { compositeRejectedStage: rt.failedStage ?? 'edge_binding', failureDetail: 'Composite edge_binding stage rejected.' },
      )
      assert.equal(compHealth.healthy, false, `floor/shared assessor must mark ${c.id} unhealthy`)
      assert.equal(compHealth.failureReason, 'composite_stage_rejected')
    }

    // --- Engine 2: Declarative replay engine (retestReplaySpec) ---
    // Track D Cut 2: raw declarative `http_chain` is retired, so the declarative leg persists the
    // same typed `access_boundary` recipe envelope as the floor engine. Retest then re-runs the
    // recipe and validates a fresh ProofReceipt instead of the deleted jq VM.
    activeCase = c
    stepCursor = 0
    const declSpec = {
      ...buildReplaySpec(c, origin, c.canonicalLabel),
      recipe: {
        recipeId: 'access_boundary',
        args: {
          origin,
          method: 'GET',
          pathAndQuery: '/api/invoices/inv_victim_9',
          vulnClass: 'bola',
          owner: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a' },
          denied: { handle: 'viewer_b', role: 'viewer', tenant: 'tenant-b' },
          probe: { handle: 'member_b', role: 'member', tenant: 'tenant-b' },
        },
      },
    } as DeclarativeReplaySpec
    if (rt.scenario === 'composite_stage_rejected') {
      const declReplay = await verifyReplaySpec({ spec: declSpec, broker, backend: jqBackend, grant, signal: AbortSignal.timeout(10_000), envelopeTrust: 'host_persisted' })
      const declHealth = assessDeclarativeRetestHealth(declSpec, {
        ...declReplay,
        evidencePayload: {
          ...declReplay.evidencePayload,
          compositeVerification: { confirmed: false, failedStage: rt.failedStage ?? 'edge_binding', reason: 'Edge hop_1 -> hop_2 missing consumed capability attestation.' },
        },
      }, { receiptBuildable: true })
      assert.equal(declHealth.healthy, false, `declarative health must reject ${c.id}`)
      assert.equal(declHealth.failureReason, 'composite_stage_rejected')
    } else if (rt.scenario === 'unbuildable_receipt') {
      // The declarative corpus case pins the shared health mapping: a replay with healthy
      // baseline/probe arms but no buildable ProofReceipt is `receipt_unbuildable`, never `fixed`.
      const declHealth = assessDeclarativeRetestHealth(declSpec, {
        verdict: 'inconclusive',
        outcome: { confirmed: false, controlPassed: true, reason: 'ProofReceipt could not be built.' },
        evidencePayload: {
          steps: {
            entitled: { role: 'control', status: 200, personaHandle: 'owner_a', method: 'GET' },
            probe: { role: 'probe', status: 403, personaHandle: 'member_b', method: 'GET' },
          },
        },
      }, { receiptBuildable: false })
      assert.equal(declHealth.healthy, false, `declarative health must reject ${c.id}`)
      assert.equal(declHealth.failureReason, rt.expectedFailureReason, `declarative failureReason mismatch on ${c.id}`)
    } else {
      const declRetest = await retestReplaySpec({
        spec: declSpec,
        broker,
        backend: jqBackend,
        grant,
        envelopeTrust: 'host_persisted',
        signal: AbortSignal.timeout(10_000),
      })
      assert.equal(declRetest.verdict, rt.expectedVerdict, `declarative verdict mismatch on ${c.id}: ${declRetest.replay.outcome.reason ?? ''}`)
      const declHealth = declRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment
      assert.equal(declHealth.failureReason, rt.expectedFailureReason, `declarative failureReason mismatch on ${c.id}`)
      assert.equal(declHealth.healthy, rt.expectedVerdict === 'fixed')
    }

    // --- Engine 3: Agent-script engine (retestPersistedAgentScript) ---
    activeCase = c
    stepCursor = 0
    const scriptText = `// parity retest script for ${c.id}\nexport default async () => ({ ok: true })\n`
    const envelope = {
      kind: 'agent_script' as const,
      runtime: 'ts' as const,
      script: scriptText,
      scriptSha256: sha256(scriptText),
      verdict: 'confirmed' as const,
      exchangeIds: ['ex-orig'],
      vulnClass: c.canonicalLabel.vulnClass ?? 'bola',
      transcriptDigests: [],
      confirmedAt: Date.now(),
    }
    const scriptBackend = makeRetestScriptBackend(c, origin)
    const agentRetest = await retestPersistedAgentScript(envelope, {
      spec: { origin, agentScript: envelope },
      origin,
      broker,
      grant,
      backend: scriptBackend,
      runId: `parity-${c.id}`,
      assignmentId: `assign-${c.id}`,
      signal: AbortSignal.timeout(15_000),
    })
    assert.equal(agentRetest.verdict, rt.expectedVerdict, `agent-script verdict mismatch on ${c.id}: ${agentRetest.replay.outcome.reason ?? ''}`)
    const agentHealth = agentRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment
    assert.equal(agentHealth.failureReason, rt.expectedFailureReason, `agent-script failureReason mismatch on ${c.id}`)
    assert.equal(agentHealth.healthy, rt.expectedVerdict === 'fixed')
  }
})

