// Finding inspector (owned by Agent Q). Opened from Findings, and by every
// cross-link to a finding (Surface, Workflow, Exchanges, palette…).
//
// Evidence-first order: (1) the verdict card — status, effective severity, latest Verify Fix
// outcome, one-line summary, control vs. variant; (2) Proof — structured receipt diff, composite
// chain rail, cited exchanges (open for confirmed findings); (3) Fix — remediation, code, retests,
// patches. Triage lives in a header popover (`t`); Verify Fix is the sticky footer's primary action.
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'

import { generatePatchAction } from '../../../actions.ts'
import { reviewPatchProposalAction, triageFindingAction } from '../../../actions-triage.ts'
import type { OperatorSeverityOverride, OperatorTriageStatus, PatchProposalReviewStatus } from '../../../actions-triage.ts'
import { indexFindingFixStates, normalizeFindingSeverity, normalizeFindingSeverityOverride } from '../../../findings-view.ts'
import type { FindingFixInfo, FindingFixState } from '../../../findings-view.ts'
import { callerCompatibilityLabels, dynamicRetestLabels, patchStatusLabels } from '../../../report-summary.ts'
import { useRun, useRunModel } from '../data.tsx'
import { Disclosure, EmptyState, FindingTitle, HostLabel, LinkRow, Props, Section, Tag } from '../display.tsx'
import { cap, fmtDate, host, operatorErrorCopy, plural } from '../format.ts'
import { CopyMorphIcon, FIX_STATE_LABEL, SevGlyph, StatusGlyph, useCopyFlash } from '../glyphs.tsx'
import { Icon } from '../icons.tsx'
import type { IconName } from '../icons.tsx'
import { useShortcuts } from '../keyboard.tsx'
import { covCat, normFStatus, prettyCat, SEV_LABEL, stLabel } from '../meta.ts'
import type { Detail, FindingRow } from '../model.ts'
import { useLinks } from '../nav.tsx'
import { ExchangeLink, PaneBody, PaneFooter, PaneHeader } from '../pane.tsx'
import type { InspectorProps } from '../pane.tsx'
import { useToast } from '../toast.tsx'
import { cn, runBtn, runDdItem, RW } from '../tw.ts'
import { getTriageStatusMeta, getTriageStatusOptions } from './findings.tsx'
import type { FindingWithTriage } from './findings.tsx'
import { CodeLocations, extractReplayInfraFailure, FoundBy, OnSurface, redactedCurlFor, ReplayFailureCallout } from './queue-read.tsx'

/** Unified Verify Fix gate across FindingInspector and ReportView: server requires runtime-confirmed finding + `replaySpecId`. */
export function canVerifyFix(f: Pick<FindingRow, 'status' | 'replaySpecId'>): boolean {
  return f.status !== 'static_verified' && normFStatus(f.status) === 'confirmed' && Boolean(f.replaySpecId)
}

/** Unified Generate Verified Patch gate across FindingInspector and ReportView. */
export function canGeneratePatch(f: Pick<FindingRow, 'status' | 'codeLocations'>): boolean {
  return (f.status === 'confirmed' || f.status === 'static_verified') && (f.codeLocations?.length ?? 0) > 0
}

/** SHA-256 of the 0-LLM Verify Fix predicate compiled at confirmation (persisted inside `proof_receipt` JSON), if any. */
function compiledPredicateShaOf(proofReceipt: unknown): string | null {
  const compiled = proofReceipt && typeof proofReceipt === 'object' ? (proofReceipt as { compiledPredicate?: { predicateSha256?: unknown } | null }).compiledPredicate : null
  return typeof compiled?.predicateSha256 === 'string' && compiled.predicateSha256 ? compiled.predicateSha256 : null
}
const TIER_L: Record<string, string> = { runtime_confirmed: 'Runtime confirmed', static_verified: 'Static advisory', baseline_confirmed: 'Baseline confirmed' }
const RETEST_L: Record<string, string> = { reproduced: 'Still reproducible', fixed: 'Verified fixed', inconclusive: 'Inconclusive' }
const RETEST_ST: Record<string, string> = { reproduced: 'failed', fixed: 'fixed', inconclusive: 'inconclusive' }
const RETEST_TONE: Record<string, string> = { reproduced: 'text-danger', fixed: 'text-ok' }

const PATCH_BROKE_HOP_FALLBACK_RE = /\bpatchBrokeHopId\s*[:=]\s*["']?([A-Za-z0-9._:-]{1,128})["']?/i
const EXCHANGES_PAGE_SIZE = 12
const EVIDENCE_PAGE_SIZE = 8

export interface CompositeDagHopSummary {
  order: number
  hopId: string
  surface: string
  origin: string
  method: string | null
  pathAndQuery: string | null
  actor: string | null
  claimedDelta: string
  producedCapabilities: string[]
  consumedCapabilities: string[]
  isTerminal: boolean
  patchBrokeHere: boolean
}

export interface CompositeDagEdgeSummary {
  fromHopId: string
  toHopId: string
  kind: string
  capabilityHandles: string[]
  detail: string
  verified: boolean | null
}

export interface CompositeDagSummary {
  chainId: string
  terminalVulnClass: string
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript'
  confirmed: boolean | null
  terminalOracleFamily: string | null
  verificationReason: string | null
  failedStage: string | null
  terminalHopId: string
  claimedImpact: string
  patchBrokeHopId: string | null
  patchRetestVerdict: string | null
  hops: CompositeDagHopSummary[]
  edges: CompositeDagEdgeSummary[]
}

/** Operator copy for composite causal-edge kinds (card bindings + `CompositeDagRail` labels). */
export const EDGE_KIND_LABEL: Record<string, string> = {
  value_binding: 'value binding',
  derived_crypto_binding: 'derived crypto',
  state_transition_binding: 'state transition',
  async_pivot_binding: 'async pivot',
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0) : []
}

function orderDagHops<T extends { hopId: string }>(
  hops: readonly T[],
  edges: ReadonlyArray<{ fromHopId: string; toHopId: string }>,
): T[] {
  if (hops.length <= 1 || edges.length === 0) return [...hops]
  const byId = new Map(hops.map((h, idx) => [h.hopId, { hop: h, idx }]))
  const inDeg = new Map(hops.map(h => [h.hopId, 0]))
  const adj = new Map<string, string[]>(hops.map(h => [h.hopId, []]))
  for (const edge of edges) {
    if (!byId.has(edge.fromHopId) || !byId.has(edge.toHopId) || edge.fromHopId === edge.toHopId) continue
    adj.get(edge.fromHopId)!.push(edge.toHopId)
    inDeg.set(edge.toHopId, (inDeg.get(edge.toHopId) ?? 0) + 1)
  }
  const ready = hops.filter(h => (inDeg.get(h.hopId) ?? 0) === 0).map(h => h.hopId)
  const ordered: T[] = []
  const visited = new Set<string>()
  while (ready.length > 0) {
    ready.sort((a, b) => (byId.get(a)?.idx ?? 0) - (byId.get(b)?.idx ?? 0))
    const current = ready.shift()!
    if (visited.has(current)) continue
    visited.add(current)
    const entry = byId.get(current)
    if (entry) ordered.push(entry.hop)
    for (const next of adj.get(current) ?? []) {
      const nextDeg = (inDeg.get(next) ?? 0) - 1
      inDeg.set(next, nextDeg)
      if (nextDeg === 0) ready.push(next)
    }
  }
  for (const hop of hops) {
    if (!visited.has(hop.hopId)) ordered.push(hop)
  }
  return ordered
}

/** Browser-safe extractor for multi-hop `CompositeProofReceipt` DAG metadata attached to a replay spec row. */
export function extractCompositeProofSummary(
  replaySpec: {
    proofReceipt?: unknown
    proofVerdict?: string | null
    lastVerificationDiff?: unknown
  } | null | undefined,
  retests: ReadonlyArray<{ verdict?: string | null; summary?: string | null; patchBrokeHopId?: string | null }> = [],
): CompositeDagSummary | null {
  const rawProof = replaySpec?.proofReceipt
  if (!rawProof || typeof rawProof !== 'object') return null
  const envelope = rawProof as Record<string, unknown>
  const candidate = envelope.compositeReceipt && typeof envelope.compositeReceipt === 'object'
    ? envelope.compositeReceipt as Record<string, unknown>
    : (Array.isArray(envelope.hops) && typeof envelope.chainId === 'string' ? envelope : null)
  if (!candidate || typeof candidate.chainId !== 'string' || !Array.isArray(candidate.hops) || candidate.hops.length === 0) {
    return null
  }

  const verification = envelope.compositeVerification && typeof envelope.compositeVerification === 'object'
    ? envelope.compositeVerification as Record<string, unknown>
    : null
  const hopActors = envelope.hopActors && typeof envelope.hopActors === 'object'
    ? envelope.hopActors as Record<string, unknown>
    : {}
  const terminalImpact = candidate.terminalImpact && typeof candidate.terminalImpact === 'object'
    ? candidate.terminalImpact as Record<string, unknown>
    : {}
  const rawEdges = Array.isArray(candidate.causalEdges) ? candidate.causalEdges : []
  const verifiedEdgesRaw = Array.isArray(verification?.verifiedEdges) ? verification!.verifiedEdges : []
  const edgeVerifiedByKey = new Map<string, boolean>()
  for (const ve of verifiedEdgesRaw) {
    if (!ve || typeof ve !== 'object') continue
    const rec = ve as Record<string, unknown>
    if (typeof rec.fromHopId === 'string' && typeof rec.toHopId === 'string' && typeof rec.kind === 'string' && typeof rec.verified === 'boolean') {
      edgeVerifiedByKey.set(`${rec.fromHopId}->${rec.toHopId}:${rec.kind}`, rec.verified)
    }
  }

  const latestRetest = retests[0]
  let patchBrokeHopId: string | null = typeof envelope.patchBrokeHopId === 'string' && envelope.patchBrokeHopId.trim()
    ? envelope.patchBrokeHopId.trim()
    : null
  if (!patchBrokeHopId && latestRetest) {
    if (typeof latestRetest.patchBrokeHopId === 'string' && latestRetest.patchBrokeHopId.trim()) {
      patchBrokeHopId = latestRetest.patchBrokeHopId.trim()
    } else if (typeof latestRetest.summary === 'string') {
      const m = PATCH_BROKE_HOP_FALLBACK_RE.exec(latestRetest.summary)
      if (m?.[1]) patchBrokeHopId = m[1]
    }
  }

  const parsedEdges: CompositeDagEdgeSummary[] = rawEdges
    .filter((e): e is Record<string, unknown> => Boolean(e && typeof e === 'object'))
    .map(edge => {
      const fromHopId = typeof edge.fromHopId === 'string' ? edge.fromHopId : ''
      const toHopId = typeof edge.toHopId === 'string' ? edge.toHopId : ''
      const kind = typeof edge.kind === 'string' ? edge.kind : 'value_binding'
      const capabilityHandles = [
        edge.capabilityHandle,
        edge.sourceCapabilityId,
        edge.derivedCapabilityId,
      ].filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
      const detailParts: string[] = []
      if (typeof edge.alg === 'string' && edge.alg) detailParts.push(`alg ${edge.alg}`)
      if (typeof edge.valueDigest === 'string' && edge.valueDigest) detailParts.push(`digest ${edge.valueDigest.slice(0, 12)}…`)
      if (typeof edge.entityId === 'string' && edge.entityId) detailParts.push(`entity ${edge.entityId}`)
      if (typeof edge.mutationKind === 'string' && edge.mutationKind) detailParts.push(edge.mutationKind)
      if (Array.isArray(edge.ablationExchangeIds) && edge.ablationExchangeIds.length > 0) {
        detailParts.push(`${edge.ablationExchangeIds.length} ablation ctrl`)
      }
      if (typeof edge.channel === 'string' && edge.channel) detailParts.push(edge.channel)
      if (typeof edge.correlationId === 'string' && edge.correlationId) detailParts.push(`corr ${edge.correlationId}`)
      const verified = edgeVerifiedByKey.get(`${fromHopId}->${toHopId}:${kind}`) ?? null
      return {
        fromHopId,
        toHopId,
        kind,
        capabilityHandles,
        detail: detailParts.join(' · '),
        verified,
      }
    })
    .filter(e => e.fromHopId.length > 0 && e.toHopId.length > 0)

  const rawHops = candidate.hops
    .filter((h): h is Record<string, unknown> => Boolean(h && typeof h === 'object' && typeof (h as Record<string, unknown>).hopId === 'string'))
    .map(h => ({
      hopId: String(h.hopId),
      raw: h,
    }))
  if (rawHops.length === 0) return null

  const terminalHopId = typeof terminalImpact.terminalHopId === 'string' && terminalImpact.terminalHopId
    ? terminalImpact.terminalHopId
    : rawHops[rawHops.length - 1]!.hopId
  const orderedHops = orderDagHops(rawHops, parsedEdges)

  const hops: CompositeDagHopSummary[] = orderedHops.map(({ hopId, raw }, idx) => {
    const target = raw.target && typeof raw.target === 'object' ? raw.target as Record<string, unknown> : {}
    const actorRaw = hopActors[hopId]
    return {
      order: idx + 1,
      hopId,
      surface: typeof raw.surface === 'string' && raw.surface ? raw.surface : 'http',
      origin: typeof target.origin === 'string' ? target.origin : '',
      method: typeof target.method === 'string' && target.method ? target.method : null,
      pathAndQuery: typeof target.pathAndQuery === 'string' && target.pathAndQuery ? target.pathAndQuery : null,
      actor: typeof actorRaw === 'string' && actorRaw.trim() ? actorRaw.trim() : null,
      claimedDelta: typeof raw.claimedDelta === 'string' ? raw.claimedDelta : '',
      producedCapabilities: asStringList(raw.producedCapabilities),
      consumedCapabilities: asStringList(raw.consumedCapabilities),
      isTerminal: hopId === terminalHopId,
      patchBrokeHere: patchBrokeHopId === hopId,
    }
  })

  const replayMode: 'fresh_clean_replay' | 'one_shot_transcript' = candidate.replayMode === 'one_shot_transcript'
    ? 'one_shot_transcript'
    : 'fresh_clean_replay'
  const diffVerdict = replaySpec?.lastVerificationDiff && typeof replaySpec.lastVerificationDiff === 'object'
    ? (replaySpec.lastVerificationDiff as { verdict?: unknown }).verdict
    : undefined
  const confirmed: boolean | null = typeof verification?.confirmed === 'boolean'
    ? verification.confirmed
    : replaySpec?.proofVerdict === 'confirmed' || diffVerdict === 'confirmed'
      ? true
      : replaySpec?.proofVerdict === 'dismissed' || replaySpec?.proofVerdict === 'inconclusive' || replaySpec?.proofVerdict === 'needs_review'
        ? false
        : null
  const terminalOracleFamily = typeof verification?.terminalOracleFamily === 'string' && verification.terminalOracleFamily
    ? verification.terminalOracleFamily
    : typeof terminalImpact.oracleFamily === 'string' && terminalImpact.oracleFamily
      ? terminalImpact.oracleFamily
      : null

  return {
    chainId: candidate.chainId,
    terminalVulnClass: typeof candidate.terminalVulnClass === 'string' ? candidate.terminalVulnClass : 'composite_chain',
    replayMode,
    confirmed,
    terminalOracleFamily,
    verificationReason: typeof verification?.reason === 'string' && verification.reason ? verification.reason : null,
    failedStage: typeof verification?.failedStage === 'string' && verification.failedStage ? verification.failedStage : null,
    terminalHopId,
    claimedImpact: typeof terminalImpact.claimedImpact === 'string' && terminalImpact.claimedImpact
      ? terminalImpact.claimedImpact
      : (typeof terminalImpact.summary === 'string' ? terminalImpact.summary : ''),
    patchBrokeHopId,
    patchRetestVerdict: typeof latestRetest?.verdict === 'string' ? latestRetest.verdict : null,
    hops,
    edges: parsedEdges,
  }
}

/**
 * Multi-hop CompositeProofReceipt card shared by FindingInspector and ReportView: one surface with the
 * chain header, the hop timeline (`children`, normally the lazily loaded `CompositeDagRail`) and the
 * terminal impact. Without a rail (static / SSR contexts) it lists the causal bindings inline.
 */
export function CompositeProofDagCard({
  summary,
  title,
  compact = false,
  children,
}: {
  summary: CompositeDagSummary
  title?: string
  compact?: boolean
  children?: ReactNode
}) {
  const modeLabel = summary.replayMode === 'fresh_clean_replay' ? 'Mode-A · fresh replay' : 'Mode-B · transcript'
  const oracleLabel = summary.confirmed === true
    ? 'Terminal oracle: Confirmed'
    : summary.confirmed === false
      ? `Terminal oracle: Unverified${summary.failedStage ? ` (${summary.failedStage})` : ''}`
      : 'Terminal oracle: Recorded'
  const bindings = [...new Set(summary.edges.flatMap(e => [(EDGE_KIND_LABEL[e.kind] ?? e.kind) + (e.verified === true ? ' ✓' : ''), ...e.capabilityHandles]))]

  return <div
    data-slot="composite-proof-dag"
    className={cn('min-w-0 rounded-[8px] border border-line bg-sunk/60', compact ? 'mb-2.5 p-2.5' : 'mb-4 p-3')}
  >
    <div className="mb-2.5 flex min-w-0 flex-wrap items-center gap-1.5">
      <span className="inline-flex items-center gap-1.5 text-[12px] font-medium text-fg">
        <Icon name="chain" className="text-fg-muted" />
        {title ? title : 'Multi-hop proof chain'}
      </span>
      <span className="min-w-0 max-w-full truncate font-mono text-[11px] text-fg-subtle" title={summary.chainId}>{summary.chainId}</span>
      <Tag tone={summary.confirmed === true ? 'accent' : summary.confirmed === false ? 'warn' : undefined}>
        <StatusGlyph status={summary.confirmed === true ? 'confirmed' : summary.confirmed === false ? 'inconclusive' : 'pending'} />
        {oracleLabel}
      </Tag>
      <Tag>{modeLabel}</Tag>
      {summary.terminalOracleFamily && <Tag>{summary.terminalOracleFamily}</Tag>}
      {summary.patchBrokeHopId && <Tag tone="warn">Patch broke at {summary.patchBrokeHopId}</Tag>}
    </div>
    {children ?? (bindings.length > 0 && <div data-slot="dag-bindings" className="flex min-w-0 flex-wrap gap-x-2 font-mono text-[11px] text-fg-muted">
      {bindings.map(b => <span key={b} className="min-w-0 max-w-full truncate" title={b}>{b}</span>)}
    </div>)}
    {(summary.claimedImpact || summary.verificationReason) && (
      <div className="mt-2.5 border-t border-line pt-2 text-[11.5px] leading-[17px] text-fg-muted">
        {summary.claimedImpact && <div className="[overflow-wrap:anywhere]"><b className="font-medium text-fg">Terminal impact ({summary.terminalHopId}):</b> {summary.claimedImpact}</div>}
        {summary.verificationReason && <div className="mt-0.5 text-fg-subtle [overflow-wrap:anywhere]">{summary.verificationReason}</div>}
      </div>
    )}
  </div>
}

/** Pre-block text: strings verbatim, structured values pretty-printed (never one compact JSON line). */
const text = (v: unknown) => v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v, null, 2)

/** Expected/Observed table cell: strings inline, structured receipts as an indented block, empty as "—". */
function ObservedValue({ value }: { value: unknown }) {
  if (value == null || value === '') return <span className="font-sans text-fg-subtle">—</span>
  if (typeof value !== 'object') return <>{String(value)}</>
  const pretty = JSON.stringify(value, (_k, v: unknown) => v === null ? undefined : v, 2)
  if (!pretty || pretty === '{}' || pretty === '[]') return <span className="font-sans text-fg-subtle">—</span>
  return <pre data-slot="observed-receipt" className={cn(RW.pre, 'm-0 max-h-40 rounded-none border-0 bg-transparent p-0 text-fg')}>{pretty}</pre>
}

/** Prose with paired backticks rendered as inline code spans (plain React text nodes, no HTML injection). */
function ProseWithCode({ children }: { children: string }) {
  const parts = children.split(/`([^`]+)`/)
  return <>{parts.map((part, i) => i % 2 === 1
    ? <code key={i} className="rounded-[4px] bg-sunk px-1 font-mono text-[11.5px] text-fg">{part}</code>
    : part)}</>
}

/** Unified-diff block: add/remove lines tinted, lines never broken mid-token (scrolls horizontally instead). */
function DiffBlock({ diff }: { diff: string }) {
  return <pre data-slot="patch-diff" className={cn(RW.pre, 'mt-1.5 max-h-[240px] overflow-x-auto whitespace-pre break-normal [overflow-wrap:normal] px-0')}>
    <div className="w-max min-w-full">
      {diff.split('\n').map((l, i) => <div
        key={i}
        className={cn('px-3', l[0] === '+' && !l.startsWith('+++') ? 'bg-ok-soft' : l[0] === '-' && !l.startsWith('---') ? 'bg-danger-soft' : '')}
      >{l || ' '}</div>)}
    </div>
  </pre>
}

/** 12px spinner for in-flight actions; static under reduced motion. */
function BusySpinner() {
  return <svg className="block flex-none motion-safe:animate-spin motion-safe:[animation-duration:800ms]" viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" data-slot="busy-spinner">
    <circle cx="6" cy="6" r="4.5" fill="none" stroke="currentColor" strokeOpacity=".25" strokeWidth="1.5" />
    <path d="M6 1.5A4.5 4.5 0 0 1 10.5 6" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
}

/** Inline Verify Fix failure under the action row (replaces the far-away toast-only failure). */
function VerifyFixError({ reason, onRetry }: { reason: string; onRetry: () => void }) {
  return <div
    role="alert"
    data-testid="verify-fix-error"
    className="mb-2.5 flex items-start gap-2 rounded-[7px] bg-warn-soft px-2.5 py-2 text-[12px] leading-[17px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]"
  >
    <Icon name="alert" className="mt-0.5 flex-none text-warn" />
    <p className="m-0! min-w-0 flex-1 break-words text-[12px]! leading-[17px]! text-fg-muted!">
      <b className="font-medium text-fg">Couldn&rsquo;t queue Verify Fix</b> — {reason}
    </p>
    <button type="button" className={cn(runBtn({ variant: 'ghost', size: 'sm' }), 'flex-none')} onClick={onRetry}>Retry</button>
  </div>
}

const SEVERITY_OVERRIDE_OPTIONS: readonly { value: OperatorSeverityOverride; label: string }[] = [
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
]

export type PatchProposalItem = Detail['patchProposals'][number]

/** Shared Approve / Reject + editable review notes control for patch proposals in FindingInspector and ReportView. */
export function PatchProposalReview({
  runId,
  proposal,
  onReviewed,
  compact = false,
}: {
  runId: string
  proposal: PatchProposalItem
  onReviewed: () => Promise<void>
  compact?: boolean
}) {
  const toast = useToast()
  const [notes, setNotes] = useState(proposal.reviewNotes ?? '')
  const [busy, setBusy] = useState<'approved' | 'rejected' | 'notes' | null>(null)

  useEffect(() => {
    setNotes(proposal.reviewNotes ?? '')
  }, [proposal.id, proposal.updatedAt, proposal.reviewNotes])

  const notesDirty = notes.trim() !== (proposal.reviewNotes ?? '').trim()

  const submit = async (status: PatchProposalReviewStatus, mode: 'approved' | 'rejected' | 'notes') => {
    setBusy(mode)
    try {
      await reviewPatchProposalAction({
        data: {
          runId,
          proposalId: proposal.id,
          status,
          reviewNotes: notes,
        },
      })
      await onReviewed()
      toast.show(
        mode === 'approved' ? 'Patch approved' : mode === 'rejected' ? 'Patch rejected' : 'Patch review notes saved',
        { icon: 'check' },
      )
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo could not update this patch review.', { tone: 'error' })
    } finally {
      setBusy(null)
    }
  }

  const currentReviewStatus: PatchProposalReviewStatus = proposal.status === 'approved'
    ? 'approved'
    : proposal.status === 'rejected'
      ? 'rejected'
      : 'pending'

  return <div className="mt-1.5" data-slot="patch-proposal-review">
    <textarea
      aria-label="Patch review notes"
      rows={compact ? 2 : 2}
      className={cn(RW.fieldTextarea, 'w-full')}
      placeholder="Operator review notes…"
      value={notes}
      disabled={busy !== null}
      onChange={e => setNotes(e.target.value)}
    />
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
      <button
        type="button"
        className={runBtn({ variant: proposal.status === 'approved' ? 'primary' : 'default', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit('approved', 'approved')}
      >
        <Icon name="check" />{busy === 'approved' ? 'Approving…' : 'Approve'}
      </button>
      <button
        type="button"
        className={runBtn({ variant: proposal.status === 'rejected' ? 'dangerSolid' : 'default', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit('rejected', 'rejected')}
      >
        <Icon name="x" />{busy === 'rejected' ? 'Rejecting…' : 'Reject'}
      </button>
      {notesDirty && <button
        type="button"
        className={runBtn({ variant: 'ghost', size: 'sm' })}
        disabled={busy !== null}
        onClick={() => void submit(currentReviewStatus, 'notes')}
      >
        {busy === 'notes' ? 'Saving…' : 'Save notes'}
      </button>}
    </div>
  </div>
}

// ---------------------------------------------------------------- triage popover

/** Operator triage form (status, severity override, notes) persisted alongside the machine verdict. */
function TriageForm({ runId, f, onSaved }: { runId: string; f: FindingWithTriage; onSaved: () => void }) {
  const { refresh } = useRun()
  const toast = useToast()
  const triage = f.operatorTriage ?? null
  const savedStatus: OperatorTriageStatus = triage?.status ?? 'open'
  const savedSeverity: OperatorSeverityOverride | null = triage?.severityOverride ?? null
  const savedNotes = triage?.notes ?? ''

  const [status, setStatus] = useState<OperatorTriageStatus>(savedStatus)
  const [severityOverride, setSeverityOverride] = useState<OperatorSeverityOverride | null>(savedSeverity)
  const [notes, setNotes] = useState(savedNotes)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    setStatus(savedStatus)
    setSeverityOverride(savedSeverity)
    setNotes(savedNotes)
  }, [f.id, triage?.updatedAt, savedStatus, savedSeverity, savedNotes])

  const dirty = status !== savedStatus || severityOverride !== savedSeverity || notes.trim() !== savedNotes.trim()

  const save = async () => {
    setSaving(true)
    try {
      await triageFindingAction({ data: { runId, findingId: f.id, status, severityOverride, notes } })
      await refresh()
      toast.show('Triage saved', { icon: 'check', sub: f.title || 'Untitled finding' })
      onSaved()
    } catch (e) {
      toast.show(e instanceof Error ? e.message : 'Kovo could not save triage.', { tone: 'error' })
    } finally {
      setSaving(false)
    }
  }

  return <div data-slot="finding-triage-bar">
    <div className="mb-1.5 flex items-center justify-between gap-2">
      <span className="text-[11.5px] font-medium text-fg-subtle">Triage</span>
      {triage?.updatedAt ? <span className="text-[11px] text-fg-subtle">Updated <span className="num">{fmtDate(triage.updatedAt)}</span></span> : null}
    </div>
    <div className="flex flex-wrap items-center gap-1.5">
      <select aria-label="Triage status" className={cn(RW.fieldInput, 'min-w-[130px] flex-1')} value={status} disabled={saving}
        onChange={e => setStatus(e.target.value as OperatorTriageStatus)}>
        {getTriageStatusOptions().map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
      </select>
      <select aria-label="Severity override" className={cn(RW.fieldInput, 'min-w-[135px] flex-1')} value={severityOverride ?? ''} disabled={saving}
        onChange={e => setSeverityOverride((e.target.value || null) as OperatorSeverityOverride | null)}>
        <option value="">{f.severity ? `Severity: Machine (${SEV_LABEL[f.severity] ?? f.severity})` : 'Severity: Machine (unrated)'}</option>
        {SEVERITY_OVERRIDE_OPTIONS.map(opt => <option key={opt.value} value={opt.value}>Override: {opt.label}</option>)}
      </select>
    </div>
    <textarea aria-label="Operator triage notes" rows={2} className={cn(RW.fieldTextarea, 'mt-1.5 w-full')} placeholder="Operator triage notes…"
      value={notes} disabled={saving} onChange={e => setNotes(e.target.value)} />
    <div className="mt-1.5 flex justify-end">
      <button type="button" className={runBtn({ variant: dirty ? 'primary' : 'default', size: 'sm' })} disabled={!dirty || saving} onClick={() => void save()}>
        <Icon name="check" />{saving ? 'Saving…' : 'Save'}
      </button>
    </div>
  </div>
}

/** Close an open popover on outside pointer-down or Escape (Escape outranks inspector bindings). */
function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const down = (e: PointerEvent) => { if (!ref.current?.contains(e.target as Node)) close() }
    window.addEventListener('pointerdown', down)
    return () => window.removeEventListener('pointerdown', down)
  }, [open, close])
  useShortcuts([{ key: 'Escape', allowInInput: true, run: () => { if (!open) return false; close() } }], { priority: 90, enabled: open })
  return ref
}

/** Header `Triage ▾` popover (`t` toggles it); a dot marks a set status, severity override or note. */
function TriagePopover({ runId, f }: { runId: string; f: FindingWithTriage }) {
  const [open, setOpen] = useState(false)
  const close = useCallback(() => setOpen(false), [])
  const ref = useDismiss(open, close)
  useEffect(() => { setOpen(false) }, [f.id])
  useShortcuts([{ key: 't', run: () => setOpen(o => !o) }], { priority: 20 })
  const t = f.operatorTriage
  const isSet = Boolean(t && (t.status !== 'open' || t.severityOverride || t.notes?.trim()))
  return <div ref={ref}>
    <button type="button" data-testid="triage-toggle" className={cn(runBtn({ variant: open ? 'ghostOn' : 'ghost', size: 'sm' }), 'relative')}
      aria-haspopup="dialog" aria-expanded={open} title={'Triage (T)' + (isSet ? ' · set' : '')} onClick={() => setOpen(o => !o)}>
      Triage<Icon name="chev" className="text-fg-subtle" />
      {isSet && <span data-slot="triage-dot" aria-hidden="true" className="absolute right-0.5 top-0.5 size-1.5 rounded-full bg-accent" />}
    </button>
    {/* Anchored to the inspector aside (nearest positioned ancestor) so it spans the pane at any width. */}
    {open && <div role="dialog" aria-label="Triage" data-slot="triage-popover"
      className="absolute inset-x-3 top-[46px] z-30 rounded-card bg-raise p-2.5 shadow-[0_0_0_1px_var(--line-2),var(--shadow-pop)]">
      <TriageForm runId={runId} f={f} onSaved={close} />
    </div>}
  </div>
}

// ---------------------------------------------------------------- footer actions

const loadProof = () => import('./proof-viewers.tsx')
const ReceiptView = lazy(() => loadProof().then(m => ({ default: m.ReceiptView })))
const ControlVariantCells = lazy(() => loadProof().then(m => ({ default: m.ControlVariantCells })))
/** Lazily loaded `CompositeDagRail` (code-split proof viewers chunk), shared with ReportView. */
export const LazyDagRail = lazy(() => loadProof().then(m => ({ default: m.CompositeDagRail })))

type ReplayRow = Detail['replaySpecs'][number]

/**
 * Verify Fix button: the inspector's single filled primary action. Reads busy (spinner, full opacity,
 * progress cursor) rather than disabled while a retest is in flight and reserves the longest label.
 */
function VerifyFixButton({ busy, disabled, onClick }: { busy: boolean; disabled: boolean; onClick: () => void }) {
  return <button
    type="button"
    data-testid="verify-fix"
    className={cn(runBtn({ variant: 'primary' }), 'min-w-[118px]', busy && 'disabled:cursor-progress disabled:opacity-100')}
    disabled={disabled}
    aria-busy={busy || undefined}
    onClick={onClick}
    title="Re-run automated replay after shipping a fix"
  >
    {busy ? <BusySpinner /> : <Icon name="replay" />}
    <span className="grid">
      <span aria-hidden="true" className="invisible col-start-1 row-start-1">Verifying fix…</span>
      <span className="col-start-1 row-start-1">{busy ? 'Verifying fix…' : 'Verify Fix'}</span>
    </span>
  </button>
}

type CopyKind = 'curl' | 'receipt' | 'link' | 'export'
const COPY_LABEL: Record<CopyKind, string> = { curl: 'Copy as cURL', receipt: 'Copy receipt JSON (redacted)', link: 'Copy finding link', export: 'Export finding (redacted)' }
const COPY_ICON: Record<CopyKind, IconName> = { curl: 'copy', receipt: 'fact', link: 'ext', export: 'download' }

function findingLink(runId: string, id: string): string {
  return `${window.location.origin}/runs/${encodeURIComponent(runId)}?view=findings&sel=finding:${encodeURIComponent(id)}`
}

/** Split button: primary copy action + `▾` menu (cURL, redacted receipt JSON, link, redacted export) with in-button check feedback. */
function FindingCopyMenu({ f, replay, primaryExchangeId, fixLabel }: { f: FindingRow; replay?: ReplayRow; primaryExchangeId?: string; fixLabel: string | null }) {
  const { detail } = useRun()
  const model = useRunModel()
  const toast = useToast()
  const [copied, flash] = useCopyFlash()
  const [last, setLast] = useState<CopyKind | null>(null)
  const [open, setOpen] = useState(false)
  const close = useCallback(() => setOpen(false), [])
  const ref = useDismiss(open, close)
  const runId = detail.run.id
  const produce: Record<CopyKind, () => Promise<string | null>> = {
    curl: async () => (primaryExchangeId ? redactedCurlFor(runId, primaryExchangeId, model.exchangeById.get(primaryExchangeId)) : null),
    receipt: async () => {
      const { redactForClipboard } = await loadProof()
      const payload = { findingId: f.id, replaySpecId: replay?.id ?? null, proofVerdict: replay?.proofVerdict ?? null, proofReceipt: replay?.proofReceipt ?? null, lastVerificationDiff: replay?.lastVerificationDiff ?? null }
      return JSON.stringify(redactForClipboard(payload), null, 2)
    },
    link: async () => findingLink(runId, f.id),
    export: async () => {
      const { formatFindingMarkdown } = await loadProof()
      const md = formatFindingMarkdown(f, { status: stLabel(normFStatus(f.status)), severity: SEV_LABEL[f.severity] ?? (f.severity || 'Unrated'), fix: fixLabel, link: findingLink(runId, f.id) })
      const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown; charset=utf-8' }))
      const a = document.createElement('a')
      a.href = url
      a.download = `kovo-finding-${f.id.slice(0, 12)}.md`
      a.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      return null
    },
  }
  const run = async (k: CopyKind) => {
    setOpen(false)
    try {
      const text = await produce[k]()
      if (k !== 'export') {
        if (text == null) { toast.show('Exchange details unavailable', { tone: 'error' }); return }
        await navigator.clipboard?.writeText(text)
      }
      setLast(k)
      flash()
    } catch {
      toast.show(k === 'export' ? 'Kovo could not export this finding.' : 'Could not copy to clipboard', { tone: 'error' })
    }
  }
  const primary: CopyKind = primaryExchangeId ? 'curl' : 'link'
  const items: [CopyKind, boolean][] = [['curl', !primaryExchangeId], ['receipt', !replay], ['link', false], ['export', false]]
  const done = copied ? (last === 'export' ? 'Exported' : 'Copied') : null
  return <div ref={ref} className="relative ml-auto flex flex-none items-center">
    <button type="button" data-testid="copy-primary" className={cn(runBtn(), 'rounded-r-none')} title={COPY_LABEL[primary]} onClick={() => void run(primary)}>
      <CopyMorphIcon copied={copied} />
      <span className="grid">
        <span aria-hidden="true" className="invisible col-start-1 row-start-1">{primary === 'curl' ? 'Copy as cURL' : 'Copy link'}</span>
        <span className="col-start-1 row-start-1" aria-live="polite">{done ?? (primary === 'curl' ? 'Copy as cURL' : 'Copy link')}</span>
      </span>
    </button>
    <button type="button" data-testid="copy-menu" className={cn(runBtn(), '-ml-px rounded-l-none px-1.5')} aria-label="More copy and export actions"
      aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(o => !o)}>
      <Icon name="chev" />
    </button>
    {open && <div role="menu" data-slot="copy-menu" className="absolute bottom-[calc(100%+6px)] right-0 z-30 w-[240px] rounded-card bg-raise p-1.5 shadow-[0_0_0_1px_var(--line-2),var(--shadow-pop)]">
      {items.map(([k, disabled]) => <button key={k} type="button" role="menuitem" className={runDdItem()} disabled={disabled} onClick={() => void run(k)}>
        <Icon name={COPY_ICON[k]} className="text-fg-subtle" />{COPY_LABEL[k]}
      </button>)}
    </div>}
  </div>
}

/** Why Verify Fix is unavailable, worded for the footer (never empty). */
function verifyFixReason(f: FindingRow): string {
  if (f.status === 'static_verified') return 'Static advisories skip Verify Fix'
  if (normFStatus(f.status) !== 'confirmed') return 'Verify Fix needs replay confirmation'
  return 'No replay recorded for Verify Fix'
}

/** Sticky inspector footer: Verify Fix (primary) + copy/export split button; inline failure strip above. */
function FindingFooter({ f, replay, primaryExchangeId, fix, fixLabel }: {
  f: FindingRow
  replay?: ReplayRow
  primaryExchangeId?: string
  fix: FindingFixInfo
  fixLabel: string | null
}) {
  const { send, pending } = useRun()
  const toast = useToast()
  const [verifying, setVerifying] = useState(false)
  const [verifyError, setVerifyError] = useState<string | null>(null)
  useEffect(() => { setVerifyError(null) }, [f.id])
  const canRetest = canVerifyFix(f)
  const active = fix.state === 'verifying'
  const runVerifyFix = async () => {
    setVerifying(true)
    setVerifyError(null)
    try {
      await send({ action: 'retest_finding', findingId: f.id })
      toast.show('Verify Fix queued', { icon: 'replay', sub: f.title || 'Untitled finding' })
    } catch (e) {
      // `send` also raises the global toast; the inline strip keeps the failure next to the button.
      setVerifyError(operatorErrorCopy(e))
    } finally {
      setVerifying(false)
    }
  }
  return <>
    {verifyError && <div className="flex-none border-t border-line bg-panel px-3 pt-2.5"><VerifyFixError reason={verifyError} onRetry={() => void runVerifyFix()} /></div>}
    <PaneFooter>
      {canRetest
        ? <VerifyFixButton busy={active || verifying} disabled={active || verifying || pending > 0} onClick={() => void runVerifyFix()} />
        : <span className="min-w-0 flex-1 truncate text-[12px] text-fg-subtle" title={verifyFixReason(f)}>{verifyFixReason(f)}</span>}
      <FindingCopyMenu f={f} replay={replay} primaryExchangeId={primaryExchangeId} fixLabel={fixLabel} />
    </PaneFooter>
  </>
}

// ---------------------------------------------------------------- fix beat

/** Beat 3 body: Generate verified patch, the 0-LLM predicate marker, retest history and patch proposals. */
function FixHistory({ f, replay }: { f: FindingRow; replay?: ReplayRow }) {
  const { detail, refresh } = useRun()
  const toast = useToast()
  const [patching, setPatching] = useState(false)
  const retests = detail.retestRuns.filter(r => r.findingId === f.id).slice().sort((a, b) => b.createdAt - a.createdAt)
  const patches = (detail.patchProposals ?? []).filter(p => p.findingId === f.id)
  const compiledPredicateSha = canVerifyFix(f) ? compiledPredicateShaOf(replay?.proofReceipt) : null
  const canPatch = canGeneratePatch(f)
  if (!canPatch && !compiledPredicateSha && !retests.length && !patches.length) return null

  const runGeneratePatch = async () => {
    setPatching(true)
    try {
      await generatePatchAction({ data: { runId: detail.run.id, findingId: f.id, repo: f.codeLocations?.[0]?.repo } })
      await refresh()
      toast.show('Verified patch generated', { icon: 'check', sub: f.title || 'Untitled finding' })
    } catch (e) {
      toast.show(e instanceof Error ? operatorErrorCopy(e) : 'Kovo could not generate a verified patch.', { tone: 'error' })
    } finally {
      setPatching(false)
    }
  }

  return <>
    {(canPatch || compiledPredicateSha) && <div className="mb-2.5 mt-2 flex flex-wrap items-center gap-2">
      {canPatch && <button type="button" className={runBtn()} disabled={patching} onClick={() => void runGeneratePatch()} title="Generate and verify a code patch for this finding">
        <Icon name="edit" />{patching ? 'Generating patch…' : 'Generate verified patch'}
      </button>}
      {compiledPredicateSha && <Tag mono title={`Verify Fix replays a compiled, deterministic predicate (no model calls) · sha256 ${compiledPredicateSha.slice(0, 12)}`}>0-LLM predicate</Tag>}
    </div>}
    {retests.length > 0 && <div className="divide-y divide-dashed divide-line">
      {retests.map(r => <div key={r.id} data-slot="retest-row" data-verdict={r.verdict} className="grid grid-cols-[14px_minmax(0,1fr)] gap-2 py-1.5 text-[12px] leading-[18px] text-fg-muted">
        <StatusGlyph status={RETEST_ST[r.verdict] ?? r.verdict} />
        <div className="min-w-0">
          <b className={cn('font-medium', RETEST_TONE[r.verdict] ?? 'text-fg')}>{RETEST_L[r.verdict] ?? cap(r.verdict)}</b>{' '}
          <span className="text-fg-subtle">· <span className="num">{fmtDate(r.createdAt)}</span></span>
          {r.summary && <div className="break-words text-fg-subtle [overflow-wrap:anywhere]">{r.summary}</div>}
        </div>
      </div>)}
    </div>}
    {patches.length > 0 && <div className="mt-2 divide-y divide-dashed divide-line">
      {patches.map(p => <div key={p.id} className="py-2 text-[12px] leading-[18px] text-fg-muted">
        <div className="mb-1 flex flex-wrap items-center gap-1.5">
          <Tag tone={p.status === 'withheld' || p.status === 'rejected' ? 'warn' : p.status === 'approved' ? 'accent' : undefined}>{patchStatusLabels[p.status]}</Tag>
          <Tag>{callerCompatibilityLabels[p.callerCompatibility]}</Tag>
          <Tag>{dynamicRetestLabels[p.dynamicRetestVerdict]}</Tag>
        </div>
        {p.status === 'approved' && p.diff.trim() && <DiffBlock diff={p.diff} />}
        <PatchProposalReview runId={detail.run.id} proposal={p} onReviewed={refresh} compact />
      </div>)}
    </div>}
  </>
}

// ---------------------------------------------------------------- verdict + proof beats

/** Pane-header sub: "High · host" with no dangling separator; "Unrated" when both are empty. */
function findingSub(sev: string, origin: string): string {
  return [sev ? (SEV_LABEL[sev] ?? sev) : '', origin ? host(origin) : ''].filter(Boolean).join(' · ') || 'Unrated'
}

/** First sentence of the reason for the verdict card's one-line "what happened". */
function firstSentence(s: string | null | undefined): string {
  const t = (s ?? '').trim()
  const m = /^(.{12,}?[.!?])(\s|$)/.exec(t)
  return m ? m[1]! : t
}

/** Inspector property rows; values that can be long carry titles and truncate or wrap as chips. */
function findingPropRows(
  f: FindingRow,
  spans: readonly string[],
  on: { origin: () => void; category?: () => void },
): [ReactNode, ReactNode, (() => void)?][] {
  const rows: [ReactNode, ReactNode, (() => void)?][] = []
  if (f.origin) rows.push(['Origin', <HostLabel host={host(f.origin)} max={36} className="font-mono text-[12px]" />, on.origin])
  rows.push(['Category', prettyCat(f.category), on.category])
  if (f.cwe) rows.push(['Weakness', <span className="font-mono text-[12px]" title={f.cwe}>{f.cwe}</span>])
  if (f.verificationTier) rows.push(['Verified', TIER_L[f.verificationTier] ?? cap(f.verificationTier)])
  if (spans.length > 1) {
    rows.push(['Spans', <span className="rw-wrap flex min-w-0 flex-wrap gap-1 py-0.5" data-slot="finding-spans">
      {spans.map(o => host(o)).map((h, i) => <Tag key={i + h} mono title={h} className="max-w-full"><span className="min-w-0 truncate">{h}</span></Tag>)}
    </span>])
  }
  return rows
}

const BADGE_FADE = 'transition-[color,background-color,border-color,opacity] duration-150 ease-out motion-reduce:transition-none'
const FIX_TAG_TONE: Record<FindingFixState, string> = {
  none: '', verifying: 'text-fg-muted shadow-[inset_0_0_0_1px_var(--line-2)]', verified_fixed: 'bg-ok-soft text-ok', still_reproducible: 'bg-danger-soft text-danger',
}

/** Beat 1: the single elevated verdict surface (status, effective severity, Verify Fix outcome, summary, control vs. variant). */
function VerdictCard({ f, st, sev, machineSev, fix, triage, replay, noReceipt }: {
  f: FindingRow
  st: ReturnType<typeof normFStatus>
  sev: string
  machineSev: string
  fix: FindingFixInfo
  triage: FindingWithTriage['operatorTriage']
  replay?: ReplayRow
  noReceipt: boolean
}) {
  const triageMeta = triage && triage.status !== 'open' ? getTriageStatusMeta(triage.status) : null
  const fixText = fix.state === 'none' ? null
    : [(st === 'confirmed' ? 'Confirmed' : stLabel(st)) + ' → ' + FIX_STATE_LABEL[fix.state], fix.at ? fmtDate(fix.at) : ''].filter(Boolean).join(' · ')
  const summary = firstSentence(f.reason)
  return <section data-slot="verdict-card" aria-label="Verdict" className="mb-4 min-w-0 rounded-[10px] bg-raise p-3 shadow-[0_0_0_1px_var(--line-2),var(--shadow-sm)]">
    <div className="mb-2 flex min-w-0 flex-wrap items-center gap-1.5">
      <Tag tone={st === 'confirmed' ? 'accent' : st === 'static_verified' ? 'solid' : st === 'needs_review' ? 'warn' : undefined} className={BADGE_FADE}><StatusGlyph status={st} />{stLabel(st)}</Tag>
      <Tag title={sev !== machineSev ? `Operator override · machine severity ${SEV_LABEL[machineSev] ?? machineSev}` : undefined}>
        <SevGlyph sev={sev} />{sev ? (SEV_LABEL[sev] ?? sev) : 'Unrated'}
      </Tag>
      {fixText && <span data-slot="fix-header-tag" data-fix-state={fix.state} className={cn('inline-flex h-5 min-w-0 items-center gap-1 rounded-[10px] px-[7px] text-[11.5px] font-medium', BADGE_FADE, FIX_TAG_TONE[fix.state])}>
        <span className="min-w-0 truncate">{fixText}</span>
      </span>}
      {noReceipt && <Tag tone="warn">No receipt attached</Tag>}
      {triageMeta && <Tag tone={triageMeta.tone}>Triage: {triageMeta.short}</Tag>}
    </div>
    {st === 'needs_review' && <div data-slot="needs-review-banner" className="mb-2.5 flex items-start gap-2 rounded-[7px] bg-warn-soft px-2.5 py-2 text-[12px] leading-[17px] text-fg-muted shadow-[inset_0_0_0_1px_var(--warn-line)]">
      <Icon name="alert" className="mt-0.5 flex-none text-warn" />
      <span><b className="font-medium text-fg">Needs review</b> — the policy judge found supporting evidence but could not confirm it by replay. Review the evidence before reporting this finding.</span>
    </div>}
    <h2 className="m-0 mb-1.5 break-words text-[15px] font-semibold leading-[22px] tracking-[-0.012em] text-fg"><FindingTitle title={f.title} /></h2>
    {summary && <p data-slot="verdict-summary" className="m-0 mb-2.5 line-clamp-2 text-[12.5px] leading-[19px] text-fg-muted" title={f.reason}>{summary}</p>}
    <Suspense fallback={<div className="h-[44px]" aria-hidden="true" />}>
      <ControlVariantCells diff={replay?.lastVerificationDiff} proofReceipt={replay?.proofReceipt} exchangeIds={f.exchangeIds ?? []} />
    </Suspense>
  </section>
}

/** Beat 2: evidence — expected/observed, structured receipt diff, composite chain rail and cited exchanges. */
function ProofBeat({ f, st, replay, dag, exIds }: { f: FindingRow; st: string; replay?: ReplayRow; dag: CompositeDagSummary | null; exIds: readonly string[] }) {
  const model = useRunModel()
  const obs = f.check?.observed
  const hasCheck = Boolean(f.check && (f.check.expected || obs !== undefined))
  const longReason = Boolean(f.reason && firstSentence(f.reason) !== f.reason.trim())
  if (!hasCheck && !replay && !dag && !exIds.length && !longReason) return null
  return <Disclosure title="Proof" defaultOpen={st === 'confirmed' || st === 'needs_review'}
    right={[replay ? 'receipt' : '', exIds.length ? plural(exIds.length, 'exchange') : ''].filter(Boolean).join(' · ') || undefined}>
    <div data-slot="proof-beat" className="min-w-0 pt-1">
      {longReason && <p className="mb-2.5! text-fg!">{f.reason}</p>}
      {hasCheck && <div className={cn(RW.cmp, 'divide-y divide-line')}>
        <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
          <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Expected</span>
          <span className="min-w-0 break-words px-2.5 py-[7px] text-fg-muted [overflow-wrap:anywhere]">{f.check?.expected || '—'}</span>
        </div>
        <div className="grid grid-cols-[72px_1fr] text-[12px] leading-[18px]">
          <span className="min-w-0 border-r border-line bg-sunk px-2.5 py-[7px] text-fg-subtle">Observed</span>
          <span className="min-w-0 break-words px-2.5 py-[7px] font-mono text-[12px] text-fg [overflow-wrap:anywhere]"><ObservedValue value={obs} /></span>
        </div>
      </div>}
      <Suspense fallback={<p className="text-[12px]! text-fg-subtle!">Loading proof…</p>}>
        {replay && <ReceiptView diff={replay.lastVerificationDiff} proofReceipt={replay.proofReceipt} exchangeIds={exIds} />}
        {dag && <CompositeProofDagCard summary={dag} compact><LazyDagRail summary={dag} /></CompositeProofDagCard>}
      </Suspense>
      {exIds.length > 0 && <div data-slot="proof-exchanges" className="mb-1">
        {exIds.slice(0, 3).map(id => <ExchangeLink key={id} id={id} showHost={model.exchangeById.get(id)?.origin !== f.origin} />)}
        {exIds.length > 3 && <p className="mt-1! text-[12px]! text-fg-subtle!">{plural(exIds.length - 3, 'more exchange')} under Technical details.</p>}
      </div>}
    </div>
  </Disclosure>
}

export function FindingInspector({ sel }: InspectorProps) {
  const model = useRunModel()
  const links = useLinks()
  const [showAllExchanges, setShowAllExchanges] = useState(false)
  const [showAllEvidence, setShowAllEvidence] = useState(false)
  useEffect(() => {
    setShowAllExchanges(false)
    setShowAllEvidence(false)
  }, [sel.id])
  const f = model.findingById.get(sel.id)
  if (!f) {
    return <>
      <PaneHeader title="Finding" sub={<span title={`Finding ${sel.id}`}>Not found</span>} />
      <PaneBody><EmptyState icon="findings" title="Finding not found">It may have been superseded since the run refreshed.</EmptyState></PaneBody>
    </>
  }
  const st = normFStatus(f.status)
  const cat = covCat(f.category)
  const chain = f.findingKind === 'multi_step_chain'
  const replay = model.detail.replaySpecs.find(r => (f.replaySpecId && r.id === f.replaySpecId) || r.findingId === f.id)
  const retests = model.detail.retestRuns.filter(r => r.findingId === f.id).slice().sort((a, b) => b.createdAt - a.createdAt)
  const compositeDag = extractCompositeProofSummary(replay, retests)
  const spans = replay?.sourceOrigins ?? []
  const exIds = f.exchangeIds ?? []
  const primaryExchangeId = exIds[0] ?? (model.exchangesByOrigin.get(f.origin)?.find(e => e.pathAndQuery === '/' && e.method === 'GET') ?? model.exchangesByOrigin.get(f.origin)?.[0])?.id
  const evs = f.evidenceIds.map(id => model.evidenceById.get(id)).filter(Boolean)
  const visibleExIds = showAllExchanges ? exIds : exIds.slice(0, EXCHANGES_PAGE_SIZE)
  const visibleEvs = showAllEvidence ? evs : evs.slice(0, EVIDENCE_PAGE_SIZE)
  const workers = model.findingWorkers.get(f.id) ?? []
  const superseded = f.supersededByFindingId ? model.findingById.get(f.supersededByFindingId) : undefined
  const codeLocs = f.codeLocations ?? []
  const diff = replay?.lastVerificationDiff as unknown
  const replayInfraFailure = extractReplayInfraFailure(f, diff)
  const triage = (f as FindingWithTriage).operatorTriage ?? null
  const machineSev = f.severity ? normalizeFindingSeverity(f.severity) : ''
  const sev = normalizeFindingSeverityOverride(triage?.severityOverride) ?? machineSev
  const fix = indexFindingFixStates([f], model.detail).get(f.id) ?? { state: 'none' as const, at: null }
  const fixLabel = fix.state === 'none' ? null : FIX_STATE_LABEL[fix.state]
  const hasPatches = (model.detail.patchProposals ?? []).some(p => p.findingId === f.id)

  const hasTechnicalDetails = Boolean(
    f.verification || replay || f.counterevidence
    || f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap
    || workers.length || cat || exIds.length || evs.length,
  )
  const techSummary = [
    exIds.length ? plural(exIds.length, 'exchange') : '',
    evs.length ? plural(evs.length, 'record') : '',
  ].filter(Boolean).join(' · ')

  const bannerCls = 'mb-3 flex items-center gap-2 rounded-[7px] bg-sunk px-2.5 py-2 text-[12px] text-fg-muted shadow-[inset_0_0_0_1px_var(--line)]'

  return <>
    <PaneHeader title="Finding" sub={<span title={`Finding ${f.id}`}>{findingSub(sev, f.origin)}</span>}
      extra={<TriagePopover runId={model.detail.run.id} f={f as FindingWithTriage} />} />
    <PaneBody><div className={cn(RW.detail, 'pb-6 [overflow-wrap:anywhere]')}>
      {superseded && <div className={bannerCls}><Icon name="alert" /><span>Superseded by a newer finding.</span>
        <button type="button" className={cn(runBtn({ variant: 'ghost' }), 'ml-auto')} onClick={() => links.finding(superseded.id)}>Open<Icon name="arrowR" /></button></div>}
      <VerdictCard f={f} st={st} sev={sev} machineSev={machineSev} fix={fix} triage={triage} replay={replay}
        noReceipt={st === 'confirmed' && !replay && !evs.length && !exIds.length} />
      {replayInfraFailure && <ReplayFailureCallout reason={replayInfraFailure} />}
      <Props rows={findingPropRows(f, spans, {
        origin: () => links.host(f.origin),
        category: cat ? () => links.cell(f.origin, cat) : undefined,
      })} />

      {f.impact && <Section title="Why it matters"><p>{f.impact}</p></Section>}

      <ProofBeat f={f} st={st} replay={replay} dag={compositeDag} exIds={exIds} />

      {(f.remediation || f.recheck || codeLocs.length > 0 || canGeneratePatch(f) || hasPatches || retests.length > 0) && <Section title="Fix" right={fixLabel ?? undefined}>
        {f.remediation && <p><ProseWithCode>{f.remediation}</ProseWithCode></p>}
        {f.recheck && <p><b className="font-medium text-fg">Recheck.</b> <ProseWithCode>{f.recheck}</ProseWithCode></p>}
        {!f.remediation && !f.recheck && !codeLocs.length && <p className="text-fg-subtle!">No remediation guidance was recorded for this finding.</p>}
        <CodeLocations codeLocs={codeLocs} />
        <FixHistory f={f} replay={replay} />
      </Section>}

      {hasTechnicalDetails && <Disclosure title="Technical details & raw evidence" right={techSummary || undefined}>
        <Props rows={[
          ['Kind', <>{chain ? <><Icon name="chain" />Multi-step chain</> : 'Baseline check'}{f.check?.id && !chain && <span className="font-mono text-[12px] text-fg-subtle">{f.check.id}</span>}</>],
          ...(f.confidence ? [['Confidence', cap(f.confidence)] as [string, ReactNode]] : []),
        ]} />
        {f.verification && <Section title="Verification"><p>{f.verification}</p></Section>}
        {replay && <Section title="Automated replay" right={replay.verifiedInline ? 'Verified inline' : plural(replay.attemptCount, 'attempt')}>
          <p title={`Replay spec ${replay.id}`}>Automated replay over {(replay.sourceOrigins ?? []).map(host).filter(Boolean).join(', ') || 'the recorded origins'}. Re-sends the recorded HTTP requests directly and compares control vs. variant responses; the structured receipt is under Proof.</p>
          {typeof diff === 'string' && diff.trim() && <pre className={RW.pre}>{text(diff)}</pre>}
        </Section>}
        {f.counterevidence && <Section title="Counterevidence"><p>{f.counterevidence}</p></Section>}
        {(f.confidenceRationale || f.severityChangeConditions || f.runtimeProofGap) && <Section title="Confidence & proof">
          {f.confidenceRationale && <p>{f.confidenceRationale}</p>}
          {f.severityChangeConditions && <p><b className="font-medium text-fg">Severity would change if</b> {f.severityChangeConditions}</p>}
          {f.runtimeProofGap && <p><b className="font-medium text-fg">Runtime proof gap.</b> {f.runtimeProofGap}</p>}
        </Section>}
        <FoundBy workers={workers} />
        {cat && <OnSurface origin={f.origin} category={cat} />}
        {exIds.length > 0 && <Section title="Exchanges" right={<span className="tabular-nums">{exIds.length}</span>}>
          {visibleExIds.map(id => <ExchangeLink key={id} id={id} showHost={model.exchangeById.get(id)?.origin !== f.origin} />)}
          {exIds.length > EXCHANGES_PAGE_SIZE && (
            <button
              type="button"
              className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1 text-[12px]')}
              onClick={() => setShowAllExchanges(v => !v)}
            >
              {showAllExchanges ? `Show first ${EXCHANGES_PAGE_SIZE} items` : `Show all ${exIds.length} items`}
            </button>
          )}
        </Section>}
        {evs.length > 0 && <Section title="Evidence records" right={<span className="tabular-nums">{evs.length}</span>}>
          {visibleEvs.map(e => <LinkRow key={e!.id} icon="fact" right={e!.kind} trailing={null} onClick={() => links.evidence(e!.id)}>{e!.title}</LinkRow>)}
          {evs.length > EVIDENCE_PAGE_SIZE && (
            <button
              type="button"
              className={cn(runBtn({ variant: 'link', size: 'none' }), 'mt-1 text-[12px]')}
              onClick={() => setShowAllEvidence(v => !v)}
            >
              {showAllEvidence ? `Show first ${EVIDENCE_PAGE_SIZE} items` : `Show all ${evs.length} items`}
            </button>
          )}
        </Section>}
      </Disclosure>}
    </div></PaneBody>
    <FindingFooter f={f} replay={replay} primaryExchangeId={primaryExchangeId} fix={fix} fixLabel={fixLabel} />
  </>
}
