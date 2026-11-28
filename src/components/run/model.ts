// Run model: pure derivations over the run detail, built once per detail
// snapshot (memoised in `useRunModel()`). Views read from here instead of
// re-deriving. Everything is real data; no links are invented.
import type { RunDetail } from '../run-state.ts'
import { projectRunFindings } from '../../findings-view.ts'
import { isTerminalRunStatus } from '../../server/run-status.ts'
import { capF, firstSentence, host, sharedApex, words } from './format.ts'
import { COV_L, covCat, FSTAT_ORDER, PHASE_LABEL, PHASE_ORDER, runLifecycleMeta, runLifecycleOf, SEV, SEV_ORDER } from './meta.ts'
import type { RiskTier, RunLifecycle, Severity } from './meta.ts'
import type { LifecycleTone } from '../run-state.ts'

export type Detail = RunDetail
export type Run = RunDetail['run']
export type FindingRow = RunDetail['findings'][number]
export type Assignment = RunDetail['assignments'][number]
export type Exchange = RunDetail['exchangesSummary'][number]
export type Approval = RunDetail['approvals'][number]
export type Coverage = RunDetail['coverageEntries'][number]
export type Message = RunDetail['messages'][number]
export type Fact = RunDetail['facts'][number]
export type Evidence = RunDetail['evidence'][number]
export type ChainStep = RunDetail['chainSteps'][number]
export type Report = RunDetail['reports'][number]
export type ThreatEntry = NonNullable<RunDetail['threatModel']>['entries'][number]

/** A run event as streamed over SSE (`/api/runs/:id/events`). */
export interface RunEvent {
  id: number
  runId: string | null
  kind: string
  message: string
  detail: Record<string, unknown>
  createdAt: number
}

// ---------------------------------------------------------------- verdict

export interface Verdict {
  /** One-line headline (B): "Two medium-severity weaknesses confirmed across 30 hosts; nothing high or critical." */
  hed: string
  /** Second line, used while paused ("Six Tier 3 requests are waiting…"). */
  dek: string | null
  /** The most serious finding (confirmed when complete; worst drafted while paused). */
  worst: FindingRow | null
  conf: {
    /** High / Moderate / Limited / Provisional / Not yet assessed */
    word: string
    text: string
    /** [count, colour, label] segments for the confidence meter. */
    seg: [number, string, string][]
  }
  /** Counts by severity (excluding dismissed/suppressed) and by projected disposition/status. */
  n: Record<string, number>
  hosts: number
  confirmed: number
  reportable: number
  suppressed: number
  followups: number
  pendingApprovals: Approval[]
}

export function buildVerdict(d: Detail, findings: readonly FindingRow[], interrupted: boolean): Verdict {
  const r = d.run
  const approvedSet = new Set(r.approved ?? [])
  const approvedOrigins = (r.candidates ?? []).filter(c => approvedSet.has(c.id)).map(c => c.origin)
  const hasScope = approvedOrigins.length > 0 || (r.scopeRevision ?? 0) > 0
  const runExt = r as Run & { authOrigins?: string[]; assetOrigins?: string[] }
  const provenanceAllowedOrigins = [...(runExt.authOrigins ?? []), ...(runExt.assetOrigins ?? [])]
  const taintedFactIds = (d.facts ?? []).filter(f => f.tainted).map(f => f.id)
  const view = projectRunFindings(findings, {
    ...(hasScope ? { approvedOrigins, approvedAssetIds: approvedSet, provenanceAllowedOrigins } : {}),
    ...(taintedFactIds.length ? { taintedFactIds } : {}),
  })
  const c = view.counts
  const n: Record<string, number> = {
    total: c.total,
    ...c.bySeverity,
    confirmed: c.confirmed,
    static_verified: c.advisories,
    inconclusive: c.inconclusive,
    dismissed: c.dismissed,
    pending: c.pending,
    reportable: c.reportable,
    suppressed: c.suppressed,
  }
  const confirmed = view.confirmed
  const hosts = r.approved.length || new Set(d.coverageEntries.map(x => x.origin)).size
  const pendingApprovals = d.approvals.filter(a => a.status === 'pending')
  const followups = d.coverageEntries.filter(x => x.status === 'needs_follow_up').length
  const hostsW = words(hosts) + ' host' + (hosts === 1 ? '' : 's')
  let hed: string
  let dek: string | null = null
  let worst: FindingRow | null = null
  const live = !isTerminalRunStatus(d.activity?.lifecycle ?? r.status)
  const wp = (k: number, s: string, p = s + 's') => capF(words(k)) + ' ' + (k === 1 ? s : p)
  if (r.status === 'waiting') {
    hed = 'Awaiting your consent to begin. Nothing has been sent.'
  } else if (live && confirmed.length === 0) {
    const p = pendingApprovals.length
    const state = r.status === 'running' ? 'the investigation is running' : r.status === 'budget_paused' ? 'the run is paused at its budget' : 'the investigation is paused'
    hed = c.total
      ? wp(c.total, 'finding') + ' drafted, none yet verified; ' + state + '.'
      : 'No findings drafted yet; ' + state + '.'
    const dekParts: string[] = []
    if (interrupted) dekParts.push('The application restarted mid-round.')
    if (p) dekParts.push(wp(p, 'approval-gated write request') + ' waiting on your decision before work can resume.')
    else if (r.status !== 'running') dekParts.push('Resume to continue from saved evidence.')
    dek = dekParts.length ? dekParts.join(' ') : null
    worst = [...view.advisories, ...view.unverified.filter(x => x.finding.status !== 'dismissed')]
      .sort((a, b) => (SEV_ORDER[a.effectiveSeverity] ?? 9) - (SEV_ORDER[b.effectiveSeverity] ?? 9))[0]?.finding ?? null
  } else {
    const top = SEV.find(s => c.byConfirmedSeverity[s] > 0)
    if (!top) {
      hed = hosts ? 'No weakness could be confirmed across ' + hostsW + '.' : 'Nothing was tested.'
      const dekParts: string[] = hosts ? [] : ['No hosts were in scope.']
      if (n.static_verified) dekParts.push(wp(n.static_verified, 'static advisory', 'static advisories') + ' (not runtime-confirmed).')
      if (n.inconclusive) dekParts.push(wp(n.inconclusive, 'observation remains', 'observations remain') + ' inconclusive.')
      dek = dekParts.length ? dekParts.join(' ') : null
    } else {
      const k = c.byConfirmedSeverity[top]
      const i = SEV.indexOf(top)
      const above = i === 2 ? '; nothing high or critical' : i > 2 ? '; nothing more severe' : ''
      hed = wp(k, top + '-severity weakness', top + '-severity weaknesses') + ' confirmed across ' + hostsW + above + '.'
      worst = confirmed.filter(x => x.effectiveSeverity === top).map(x => x.finding)
        .sort((a, b) => Number(b.findingKind === 'multi_step_chain') - Number(a.findingKind === 'multi_step_chain'))[0] ?? null
      if (live) dek = 'Provisional: the run is ' + (r.status === 'running' ? 'still running' : 'paused') + ', so more may follow.'
    }
  }
  let conf: Verdict['conf']
  if (r.status === 'waiting') {
    conf = { word: 'Not yet assessed', text: 'Confidence is earned by automated replay once work begins. Nothing has been observed.', seg: [] }
  } else {
    const standing = c.total - n.dismissed
    const k = confirmed.length
    const ratio = standing ? k / standing : 0
    const word = live ? 'Provisional' : ratio >= 0.6 ? 'High' : ratio >= 0.3 ? 'Moderate' : 'Limited'
    const parts = [standing
      ? k + ' of ' + standing + ' standing findings confirmed by automated replay'
      : c.total ? 'No standing findings remain' : 'No findings to verify']
    if (n.static_verified) parts.push(n.static_verified + ' static ' + (n.static_verified === 1 ? 'advisory' : 'advisories'))
    if (n.dismissed) parts.push(n.dismissed + ' dismissed on replay')
    if (n.inconclusive) parts.push(n.inconclusive + ' inconclusive')
    if (n.pending) parts.push(n.pending + ' awaiting verification')
    let text = parts.join('; ') + '.'
    if (followups) text += ' ' + wp(followups, 'coverage area needs', 'coverage areas need') + ' follow-up.'
    conf = {
      word, text,
      seg: [
        [k, 'var(--fg-2)', 'Confirmed'],
        [n.static_verified, 'var(--fg-3)', 'Static advisory'],
        [n.pending, 'var(--med)', 'Awaiting'],
        [n.inconclusive, 'var(--fg-4)', 'Inconclusive'],
        [n.dismissed, 'var(--line-strong)', 'Dismissed'],
      ],
    }
  }
  return { hed, dek, worst, conf, n, hosts, confirmed: c.confirmed, reportable: c.reportable, suppressed: c.suppressed, followups, pendingApprovals }
}

// ---------------------------------------------------------------- queue (E's triage)

export type QueueSection = 'decide' | 'review' | 'follow' | 'done'
export type QueueItem =
  | { key: string; kind: 'consent'; title: string; t: number }
  | { key: string; kind: 'approval'; ap: Approval; title: string; t: number }
  | {
    key: string; kind: 'finding'; bundle: boolean; list: FindingRow[]; finding: FindingRow
    sev: Severity; status: string; origins: string[]; title: string; t: number
  }
  | { key: string; kind: 'follow'; cov: Coverage; title: string; origins: string[]; t: number; risk: number }

export type QueueBase = Record<QueueSection, QueueItem[]>

/**
 * Queue key of the consent item. Discovery consent and the later scope approval are two
 * separate decisions, so the key carries the phase: approving discovery must not mark the
 * scope review (same run, phase `review`) as already decided.
 */
export const consentKey = (run: Pick<Run, 'phase'>) => 'consent:' + run.phase

/** True when a still-pending approval has passed its client-side expiry timestamp. */
export function isApprovalExpired(a: Pick<Approval, 'status' | 'expiresAt'>, now = Date.now()): boolean {
  return a.status === 'pending' && Number.isFinite(a.expiresAt) && a.expiresAt > 0 && now >= a.expiresAt
}

export const QSEC: [QueueSection, string, string][] = [
  ['decide', 'Decide', 'Needs your decision before work continues'],
  ['review', 'Review', 'Unverified findings, bundled by check'],
  ['follow', 'Follow up', 'Coverage the coordinator flagged'],
  ['done', 'Done', 'Server-side decisions and approval audit log'],
]

function buildQueue(d: Detail, _findings: readonly FindingRow[], risk: Map<string, ThreatEntry>, _evidenceById: Map<string, Evidence>, now = Date.now()): QueueBase {
  const run = d.run
  const riskRank = (o: string) => ({ critical: 0, high: 1, medium: 2, low: 3 } as Record<string, number>)[risk.get(o)?.riskTier ?? ''] ?? 4
  const base: QueueBase = { decide: [], review: [], follow: [], done: [] }
  if (run.status === 'waiting' && (run.phase === 'consent' || run.phase === 'review')) {
    base.decide.push({ key: consentKey(run), kind: 'consent', title: run.phase === 'review' ? 'Approve scope to start the run' : 'Approve discovery to start the run', t: run.createdAt })
  }
  for (const a of d.approvals.slice().sort((x, y) => x.createdAt - y.createdAt)) {
    const it: QueueItem = { key: 'ap:' + a.id, kind: 'approval', ap: a, title: a.method + ' ' + host(a.origin) + a.pathAndQuery, t: a.createdAt }
    ;(a.status === 'pending' && !isApprovalExpired(a, now) ? base.decide : base.done).push(it)
  }
  // Follow-ups send a real `inject_hint` command only while the run can still plan.
  const canScheduleFollowUp = run.phase !== 'complete' && !isTerminalRunStatus(d.activity?.lifecycle ?? run.status)
  if (canScheduleFollowUp) {
    for (const x of d.coverageEntries.filter(c => c.status === 'needs_follow_up')) {
      base.follow.push({ key: 'cv:' + x.id, kind: 'follow', cov: x, title: firstSentence(x.summary), origins: [x.origin], t: x.updatedAt || run.createdAt, risk: riskRank(x.origin) })
    }
    base.follow.sort((a, b) => a.kind === 'follow' && b.kind === 'follow' ? a.risk - b.risk || host(a.cov.origin).localeCompare(host(b.cov.origin)) : 0)
  }
  base.done.sort((a, b) => b.t - a.t)
  return base
}

// ---------------------------------------------------------------- surface (D's matrix)

export interface SurfaceOrigin {
  origin: string
  host: string
  tier: RiskTier
  tags: string[]
  rationale: string
  /** findings / exchanges (in the loaded window) / charted categories */
  nf: number
  nx: number
  ncov: number
}

export interface SurfaceModel {
  origins: SurfaceOrigin[]
  /** true when nothing is recorded yet and the rows are just the project seeds */
  ghost: boolean
  apex: string | null
  /** cov[origin][category] */
  cov: Record<string, Record<string, Coverage>>
  /** findings by origin, and by `origin|category` cell (sorted by severity, then status) */
  findingsByOrigin: Record<string, FindingRow[]>
  findingsByCell: Record<string, FindingRow[]>
  workersByOrigin: Record<string, Set<string>>
  approvalsByOrigin: Record<string, Approval[]>
  maxExchanges: number
}

export const cellKey = (origin: string, category: string) => origin + '|' + category
export const cellStatus = (m: SurfaceModel, origin: string, category: string) => m.cov[origin]?.[category]?.status ?? 'untested'

function buildSurface(d: Detail, findings: readonly FindingRow[], ix: Pick<RunModel, 'findingById' | 'workerById' | 'exchangesByOrigin' | 'risk'>): SurfaceModel {
  const set = new Map<string, true>()
  const add = (o: string | null | undefined) => { if (o && !set.has(o)) set.set(o, true) }
  d.run.candidates.forEach(c => add(c.origin))
  d.coverageEntries.forEach(x => add(x.origin))
  findings.forEach(f => add(f.origin))
  d.exchangesSummary.forEach(e => add(e.origin))
  let ghost = false
  if (!set.size) { d.project.seeds.forEach(s => add(/^https?:\/\//.test(s) ? s : 'https://' + s)); ghost = true }
  const apex = sharedApex([...set.keys()].map(host))
  const cov: SurfaceModel['cov'] = {}
  d.coverageEntries.forEach(x => { (cov[x.origin] ??= {})[x.category] = x })
  const fBy: Record<string, FindingRow[]> = {}
  const fCell: Record<string, FindingRow[]> = {}
  for (const f of findings) {
    (fBy[f.origin] ??= []).push(f)
    const cat = covCat(f.category)
    if (cat) (fCell[cellKey(f.origin, cat)] ??= []).push(f)
  }
  for (const cv of d.coverageEntries) {
    if (!cv.linkedFindingId) continue
    const f = ix.findingById.get(cv.linkedFindingId)
    const k = cellKey(cv.origin, cv.category)
    if (f && !(fCell[k] ?? []).includes(f)) (fCell[k] ??= []).push(f)
  }
  const fs = (a: FindingRow, b: FindingRow) => (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((FSTAT_ORDER[a.status] ?? 9) - (FSTAT_ORDER[b.status] ?? 9))
  Object.values(fBy).forEach(a => a.sort(fs))
  Object.values(fCell).forEach(a => a.sort(fs))
  const wBy: Record<string, Set<string>> = {}
  const addW = (o: string, wid: string | null | undefined) => { if (wid && ix.workerById.has(wid)) (wBy[o] ??= new Set()).add(wid) }
  d.assignments.forEach(a => { if (a.sourceOrigins.length <= 3) a.sourceOrigins.forEach(o => addW(o, a.id)) })
  d.exchangesSummary.forEach(e => addW(e.origin, e.assignmentId))
  d.coverageEntries.forEach(x => addW(x.origin, x.assignmentId))
  const apprBy: Record<string, Approval[]> = {}
  d.approvals.forEach(a => (apprBy[a.origin] ??= []).push(a))
  const origins: SurfaceOrigin[] = [...set.keys()].map(o => {
    const t = ix.risk.get(o)
    return {
      origin: o, host: host(o), tier: (t?.riskTier ?? 'unranked') as RiskTier, tags: t?.surfaceTags ?? [], rationale: t?.rationale ?? '',
      nf: (fBy[o] ?? []).length, nx: (ix.exchangesByOrigin.get(o) ?? []).length, ncov: Object.keys(cov[o] ?? {}).length,
    }
  })
  return { origins, ghost, apex, cov, findingsByOrigin: fBy, findingsByCell: fCell, workersByOrigin: wBy, approvalsByOrigin: apprBy, maxExchanges: Math.max(1, ...origins.map(o => o.nx)) }
}

// ---------------------------------------------------------------- workflow inputs

export interface WorkflowEdge { from: string; to: string; kind: 'handoff' | 'causal' }
export interface WorkflowModel {
  /** Phase columns in order: discovery, threat_model, investigation, verification, then any extra (retest). */
  phases: string[]
  byPhase: Map<string, Assignment[]>
  /** `input_assignment_id` handoffs (solid) and causal links via parent facts / step dependencies (dashed). */
  edges: WorkflowEdge[]
  upstream: Map<string, WorkflowEdge[]>
  downstream: Map<string, WorkflowEdge[]>
}

function buildWorkflow(d: Detail, ix: Pick<RunModel, 'workerById' | 'factById' | 'stepById'>): WorkflowModel {
  const base = ['discovery', 'threat_model', 'investigation', 'verification']
  const extra = [...new Set(d.assignments.map(a => a.phase))].filter(p => !base.includes(p)).sort((a, b) => (PHASE_ORDER[a] ?? 9) - (PHASE_ORDER[b] ?? 9))
  const phases = base.concat(extra)
  const byPhase = new Map<string, Assignment[]>(phases.map(p => [p, []]))
  d.assignments.forEach(a => byPhase.get(a.phase)?.push(a))
  const edges: WorkflowEdge[] = []
  const seen = new Set<string>()
  const push = (from: string | null | undefined, to: string, kind: WorkflowEdge['kind']) => {
    if (!from || from === to || !ix.workerById.has(from)) return
    const k = from + '>' + to
    if (seen.has(k)) return
    seen.add(k)
    edges.push({ from, to, kind })
  }
  for (const a of d.assignments) push(a.inputAssignmentId, a.id, 'handoff')
  for (const a of d.assignments) {
    for (const fid of a.parentFactIds) push(ix.factById.get(fid)?.assignmentId, a.id, 'causal')
    const step = a.stepId ? ix.stepById.get(a.stepId) : undefined
    if (step) {
      for (const sid of step.dependsOnStepIds) push(ix.stepById.get(sid)?.assignedWorkerId, a.id, 'causal')
      for (const fid of step.dependsOnFactIds) push(ix.factById.get(fid)?.assignmentId, a.id, 'causal')
    }
  }
  const upstream = new Map<string, WorkflowEdge[]>()
  const downstream = new Map<string, WorkflowEdge[]>()
  for (const e of edges) {
    upstream.set(e.to, [...(upstream.get(e.to) ?? []), e])
    downstream.set(e.from, [...(downstream.get(e.from) ?? []), e])
  }
  return { phases, byPhase, edges, upstream, downstream }
}

/** Full upstream and downstream lineage of a worker (transitive). */
export function lineage(w: WorkflowModel, id: string) {
  const walk = (start: string, next: Map<string, WorkflowEdge[]>, pick: (e: WorkflowEdge) => string) => {
    const out = new Set<string>()
    const stack = [start]
    while (stack.length) {
      for (const e of next.get(stack.pop()!) ?? []) {
        const n = pick(e)
        if (!out.has(n)) { out.add(n); stack.push(n) }
      }
    }
    return out
  }
  return { up: walk(id, w.upstream, e => e.from), down: walk(id, w.downstream, e => e.to) }
}

// ---------------------------------------------------------------- the model

export interface RunModel {
  detail: Detail
  run: Run
  /** Run start and the latest timestamp seen in the detail (end of the run, or "now" while live). */
  base: number
  end: number
  /** Current (non-superseded) findings. `allFindings` includes superseded rows. */
  findings: FindingRow[]
  allFindings: FindingRow[]
  findingById: Map<string, FindingRow>
  workerById: Map<string, Assignment>
  stepById: Map<string, ChainStep>
  stepByWorker: Map<string, ChainStep>
  exchangeById: Map<string, Exchange>
  evidenceById: Map<string, Evidence>
  factById: Map<string, Fact>
  approvalById: Map<string, Approval>
  factsByWorker: Map<string, Fact[]>
  evidenceByWorker: Map<string, Evidence[]>
  exchangesByWorker: Map<string, Exchange[]>
  exchangesByOrigin: Map<string, Exchange[]>
  /** finding ↔ worker: workers that recorded the finding's cited evidence or made its cited exchanges (no chain-fact authors, no invented links) */
  findingWorkers: Map<string, string[]>
  workerFindings: Map<string, FindingRow[]>
  /** exchange → findings that cite it; evidence → findings that cite it */
  exchangeFindings: Map<string, FindingRow[]>
  evidenceFindings: Map<string, FindingRow[]>
  risk: Map<string, ThreatEntry>
  /** Approved scope origins (falls back to project seeds before consent). */
  scopeOrigins: string[]
  queue: QueueBase
  /** queue item lookup by key, across all sections */
  queueItem: Map<string, QueueItem>
  surface: SurfaceModel
  workflow: WorkflowModel
  /** Latest report, if any. */
  report: Report | null
  /** Coordinator thread (operator, coordinator and kovo messages) and worker report messages. */
  coordinatorMessages: Message[]
  workerMessages: Message[]
  /** Model missing: scope approved and the run is in a model-driven phase without a usable model. */
  needsModel: boolean
}

const group = <T, K>(items: readonly T[], key: (t: T) => K | null | undefined) => {
  const m = new Map<K, T[]>()
  for (const it of items) {
    const k = key(it)
    if (k == null) continue
    const list = m.get(k)
    if (list) list.push(it)
    else m.set(k, [it])
  }
  return m
}

export function computeRunEnd(d: Detail): number {
  let max = d.run.createdAt
  const p = (v: unknown) => { if (typeof v === 'number' && Number.isFinite(v) && v > max) max = v }
  const r = d.run as Run & { endedAt?: number | null; updatedAt?: number | null }
  p(r.endedAt); p(r.updatedAt); p(r.phase0CompletedAt)
  for (const e of d.exchangesSummary) {
    p(e.createdAt)
    if (typeof e.durationMs === 'number' && Number.isFinite(e.durationMs) && e.durationMs > 0) p(e.createdAt + e.durationMs)
  }
  for (const a of d.assignments as (Assignment & { endedAt?: number | null; updatedAt?: number | null })[]) {
    p(a.createdAt); p(a.endedAt); p(a.updatedAt)
  }
  for (const list of [d.chainSteps, d.boardMembers, d.patchProposals ?? [], d.endpoints ?? []]) {
    for (const x of list) { p(x.createdAt); p(x.updatedAt) }
  }
  for (const c of d.coverageEntries) p(c.updatedAt)
  for (const a of d.approvals) { p(a.createdAt); p(a.decidedAt) }
  for (const list of [d.boardMessages, d.facts, d.evidence, d.messages, d.reports, d.retestRuns]) {
    for (const x of list) p(x.createdAt)
  }
  return max
}

// ---------------------------------------------------------------- boundary normalisation

type Loose = Record<string, unknown>
const arr = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : [])
const str = (v: unknown, fallback: string) => (typeof v === 'string' ? v : v == null ? fallback : String(v))
/** Coerce nullable array/string fields on each row; rows that are not objects are dropped. */
const rows = (v: unknown, arrays: readonly string[], strings: Readonly<Record<string, string>> = {}): Loose[] => {
  const out: Loose[] = []
  for (const row of arr<unknown>(v)) {
    if (!row || typeof row !== 'object') continue
    const r = row as Loose
    let next: Loose | null = null
    const set = (k: string, val: unknown) => { (next ??= { ...r })[k] = val }
    for (const k of arrays) if (!Array.isArray(r[k])) set(k, [])
    for (const k in strings) if (typeof r[k] !== 'string') set(k, str(r[k], strings[k]))
    out.push(next ?? r)
  }
  return out
}

/**
 * Normalise a run detail at the data boundary (initial load and every refresh / SSE merge)
 * so one malformed row (`sourceOrigins: null`, a missing title) cannot throw inside
 * `buildRunModel` and take the whole run page down. Pure: returns a shallow-copied detail
 * and only copies rows that needed coercion.
 */
export function normalizeRunDetail(detail: Detail): Detail {
  const d = detail as unknown as Loose
  const run = (d.run && typeof d.run === 'object' ? d.run : {}) as Loose
  const project = (d.project && typeof d.project === 'object' ? d.project : {}) as Loose
  const tm = d.threatModel && typeof d.threatModel === 'object' ? d.threatModel as Loose : null
  const out: Loose = {
    ...d,
    run: { ...run, approved: arr(run.approved), candidates: rows(run.candidates, [], { origin: '' }) },
    project: { ...project, seeds: arr<unknown>(project.seeds).filter((x): x is string => typeof x === 'string'), name: str(project.name, 'Untitled project') },
    threatModel: tm ? { ...tm, entries: rows(tm.entries, ['surfaceTags'], { origin: '' }) } : d.threatModel ?? null,
    assignments: rows(d.assignments, ['sourceOrigins', 'parentFactIds'], { title: 'Untitled worker', phase: 'investigation', status: 'queued', id: '' }),
    findings: rows(d.findings, ['evidenceIds', 'exchangeIds'], { title: '', origin: '', category: '', id: '' }),
    chainSteps: rows(d.chainSteps, ['dependsOnStepIds', 'dependsOnFactIds'], { id: '' }),
    exchangesSummary: rows(d.exchangesSummary, [], { origin: '', id: '' }),
    approvals: rows(d.approvals, [], { origin: '', method: 'GET', pathAndQuery: '', id: '' }),
    coverageEntries: rows(d.coverageEntries, [], { origin: '', category: '', id: '' }),
    evidence: rows(d.evidence, [], { id: '' }),
    facts: rows(d.facts, [], { id: '' }),
    messages: rows(d.messages, []),
    reports: rows(d.reports, []),
    boardMembers: rows(d.boardMembers, []),
    boardMessages: rows(d.boardMessages, []),
    retestRuns: rows(d.retestRuns, []),
  }
  if ('patchProposals' in d) out.patchProposals = rows(d.patchProposals, [])
  if ('endpoints' in d) out.endpoints = rows(d.endpoints, [])
  return out as unknown as Detail
}

export function buildRunModel(d: Detail, now = Date.now()): RunModel {
  const byId = <T extends { id: string }>(xs: readonly T[]) => new Map(xs.map(x => [x.id, x]))
  const push = <K, V>(m: Map<K, V[]>, k: K, v: V) => { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]) }
  const allFindings = d.findings
  const findings = allFindings.filter(f => !f.supersededByFindingId)
  const findingById = byId(allFindings)
  const workerById = byId(d.assignments)
  const stepById = byId(d.chainSteps)
  const stepByWorker = new Map(d.chainSteps.filter(s => s.assignedWorkerId).map(s => [s.assignedWorkerId!, s]))
  const exchangeById = byId(d.exchangesSummary)
  const evidenceById = byId(d.evidence)
  const factById = byId(d.facts)
  const approvalById = byId(d.approvals)
  const factsByWorker = group(d.facts, f => f.assignmentId)
  const evidenceByWorker = group(d.evidence, e => e.assignmentId)
  const exchangesByWorker = group(d.exchangesSummary, e => e.assignmentId)
  const exchangesByOrigin = group(d.exchangesSummary, e => e.origin)

  const findingWorkers = new Map<string, string[]>()
  const workerFindings = new Map<string, FindingRow[]>()
  const exchangeFindings = new Map<string, FindingRow[]>()
  const evidenceFindings = new Map<string, FindingRow[]>()
  for (const f of findings) {
    const w = new Set<string>()
    for (const e of f.evidenceIds) {
      const aid = evidenceById.get(e)?.assignmentId
      if (aid) w.add(aid)
      push(evidenceFindings, e, f)
    }
    for (const e of f.exchangeIds ?? []) {
      const aid = exchangeById.get(e)?.assignmentId
      if (aid) w.add(aid)
      push(exchangeFindings, e, f)
    }
    const ws = [...w].filter(a => workerById.has(a))
    findingWorkers.set(f.id, ws)
    for (const a of ws) push(workerFindings, a, f)
  }

  const end = computeRunEnd(d)

  const risk = new Map((d.threatModel?.entries ?? []).map(e => [e.origin, e]))
  const approved = new Set(d.run.approved)
  const scopeFromCandidates = d.run.candidates.filter(c => approved.has(c.id)).map(c => c.origin)
  const scopeOrigins = scopeFromCandidates.length ? scopeFromCandidates : d.project.seeds

  const queue = buildQueue(d, findings, risk, evidenceById, now)
  const queueItem = new Map<string, QueueItem>()
  for (const list of Object.values(queue)) for (const it of list) queueItem.set(it.key, it)

  const partial = { findingById, workerById, exchangesByOrigin, risk, factById, stepById }
  const surface = buildSurface(d, findings, partial)
  const workflow = buildWorkflow(d, partial)
  const report = d.reports.slice().sort((a, b) => b.version - a.version)[0] ?? null
  const coordinatorMessages = d.messages.filter(m => m.threadId === d.run.coordinatorId || m.role === 'operator' || m.role === 'kovo')
  const workerMessages = d.messages.filter(m => m.role === 'worker')
  const needsModel = !d.hasModel && d.run.approved.length > 0 && ['threat_model', 'investigation', 'verification'].includes(d.run.phase)
    && !isTerminalRunStatus(d.activity?.lifecycle ?? d.run.status)

  return {
    detail: d, run: d.run, base: d.run.createdAt, end,
    findings, allFindings, findingById, workerById, stepById, stepByWorker, exchangeById, evidenceById, factById, approvalById,
    factsByWorker, evidenceByWorker, exchangesByWorker, exchangesByOrigin,
    findingWorkers, workerFindings, exchangeFindings, evidenceFindings,
    risk, scopeOrigins, queue, queueItem, surface, workflow, report, coordinatorMessages, workerMessages, needsModel,
  }
}

// ---------------------------------------------------------------- small selectors

/** Findings sorted most serious first: severity, then confirmed before unverified, chains first. */
export function bySeriousness(a: FindingRow, b: FindingRow) {
  return (SEV_ORDER[a.severity] - SEV_ORDER[b.severity]) || ((FSTAT_ORDER[a.status] ?? 9) - (FSTAT_ORDER[b.status] ?? 9))
    || (Number(b.findingKind === 'multi_step_chain') - Number(a.findingKind === 'multi_step_chain'))
}

export function worstSeverity(list: readonly FindingRow[]): Severity {
  return list.reduce<Severity>((s, f) => (SEV_ORDER[f.severity] < SEV_ORDER[s] ? f.severity : s), 'informational')
}

/** Coverage counts by status, in display order. */
export function coverageCounts(cov: readonly Coverage[]) {
  const order = ['reported', 'needs_follow_up', 'no_issue_found', 'ruled_out', 'not_applicable'] as const
  const ct: Record<string, number> = {}
  for (const x of cov) ct[x.status] = (ct[x.status] ?? 0) + 1
  return order.filter(k => ct[k]).map(k => ({ status: k, label: COV_L[k], count: ct[k] }))
}

// ---------------------------------------------------------------- traffic sparkline ([U7])

/** Live runs chart the trailing hour; a quiet notice appears after 10 minutes without traffic. */
export const SPARK_LIVE_WINDOW_MS = 60 * 60_000
export const SPARK_QUIET_MS = 10 * 60_000
const SPARK_MAX_BUCKETS = 60

/** Target-side refusals and errors drawn as red ticks (proxy denials are counted separately by kind). */
export const isDeniedHttpStatus = (status: number) => status === 403 || status === 429 || status >= 500

export interface TrafficBucket {
  /** Bucket start (ms epoch). */
  t: number
  /** Requests sent through the safety proxy in this bucket. */
  count: number
  /** `count` normalised to requests per minute. */
  perMin: number
  /** Proxy denials plus 403 / 429 / 5xx responses in this bucket. */
  denied: number
}

export interface TrafficSparkline {
  window: 'live' | 'full'
  t0: number
  t1: number
  bucketMs: number
  buckets: TrafficBucket[]
  /** Reference line: `maxRpsPerOrigin × 60` requests per minute (0 when uncapped). */
  capPerMin: number
  /** The cap line sits inside the y-range (otherwise it is labelled as off-scale). */
  capInScale: boolean
  peakPerMin: number
  yMax: number
  total: number
  denied: number
  lastAt: number | null
  /** No traffic was ever recorded. */
  empty: boolean
  /** Live run with traffic, but none in the last 10 minutes. */
  quiet: boolean
}

/**
 * Requests/min sparkline: the last 60 minutes while the run is live (running, paused, awaiting
 * approval), the full traffic span once terminal. Prefers the broker event stream (complete) and
 * falls back to the loaded exchange window. The full-run domain ends at the last traffic
 * timestamp, so a late non-traffic record cannot stretch the axis and pile requests into bucket 0.
 */
export function buildTrafficSparkline(input: {
  status: string
  createdAt: number
  now: number
  maxRpsPerOrigin: number
  exchanges: readonly { createdAt: number; status: number }[]
  events: readonly { kind: string; createdAt: number }[]
  window?: 'live' | 'full'
}): TrafficSparkline {
  const finite = (t: unknown): t is number => typeof t === 'number' && Number.isFinite(t)
  const allowedEv: number[] = []
  const deniedAt: number[] = []
  for (const e of input.events) {
    if (!finite(e.createdAt)) continue
    if (e.kind === 'broker.allowed') allowedEv.push(e.createdAt)
    else if (e.kind === 'broker.denied') deniedAt.push(e.createdAt)
  }
  const sent = allowedEv.length ? allowedEv : input.exchanges.map(e => e.createdAt).filter(finite)
  for (const e of input.exchanges) if (finite(e.createdAt) && isDeniedHttpStatus(Number(e.status))) deniedAt.push(e.createdAt)
  let lastAt: number | null = null
  for (const t of [...sent, ...deniedAt]) if (lastAt == null || t > lastAt) lastAt = t
  const live = runLifecycleMeta[runLifecycleOf(input.status)].live
  const window = input.window ?? (live ? 'live' : 'full')
  let t0: number
  let bucketMs: number
  let n: number
  if (window === 'live') {
    bucketMs = 60_000
    n = SPARK_MAX_BUCKETS
    t0 = input.now - n * bucketMs
  } else {
    t0 = finite(input.createdAt) ? input.createdAt : Infinity
    for (const t of sent) if (t < t0) t0 = t
    for (const t of deniedAt) if (t < t0) t0 = t
    if (!Number.isFinite(t0)) t0 = input.now - 60_000
    const tEnd = Math.max(t0 + 60_000, (lastAt ?? t0) + 1)
    bucketMs = Math.max(60_000, Math.ceil((tEnd - t0) / SPARK_MAX_BUCKETS))
    n = Math.max(1, Math.min(SPARK_MAX_BUCKETS, Math.ceil((tEnd - t0) / bucketMs)))
  }
  const buckets: TrafficBucket[] = Array.from({ length: n }, (_, i) => ({ t: t0 + i * bucketMs, count: 0, perMin: 0, denied: 0 }))
  const slot = (t: number) => {
    const i = Math.floor((t - t0) / bucketMs)
    return i >= 0 && i < n ? buckets[i] : window === 'full' ? buckets[Math.min(n - 1, Math.max(0, i))] : undefined
  }
  let total = 0
  let denied = 0
  for (const t of sent) { const b = slot(t); if (b) { b.count += 1; total += 1 } }
  for (const t of deniedAt) { const b = slot(t); if (b) { b.denied += 1; denied += 1 } }
  let peak = 0
  for (const b of buckets) {
    b.perMin = Math.round(b.count / (bucketMs / 60_000) * 10) / 10
    if (b.perMin > peak) peak = b.perMin
  }
  const capPerMin = input.maxRpsPerOrigin > 0 ? input.maxRpsPerOrigin * 60 : 0
  const capInScale = capPerMin > 0 && capPerMin <= Math.max(1, peak) * 4
  const yMax = Math.max(1, peak * 1.15, capInScale ? capPerMin * 1.1 : 0)
  const empty = sent.length === 0 && deniedAt.length === 0
  const quiet = live && !empty && (lastAt == null || input.now - lastAt > SPARK_QUIET_MS)
  return { window, t0, t1: t0 + n * bucketMs, bucketMs, buckets, capPerMin, capInScale, peakPerMin: peak, yMax, total, denied, lastAt, empty, quiet }
}

// ---------------------------------------------------------------- state-aware run hero ([U4])

export type HeroActionId = 'raise_budget' | 'resume' | 'show_failed' | 'approve' | 'inspect'

export interface RunHeroModel {
  lifecycle: RunLifecycle
  tone: LifecycleTone
  title: string
  detail: string
  /** The single filled call to action, when the state needs the operator. */
  primary: { id: HeroActionId; label: string } | null
  /** A quiet link-style follow-up (never filled). */
  secondary: { id: HeroActionId; label: string } | null
}

/** "Awaiting approval — discovery consent" / "— scope review": shared by the hero and the consent sheet. */
export function awaitingApprovalTitle(phase: string): string {
  const label = runLifecycleMeta.awaiting_approval.label
  return phase === 'consent' ? `${label} — discovery consent` : phase === 'review' ? `${label} — scope review` : label
}

const grouped = (n: number) => Number.isFinite(n) ? Math.round(n).toLocaleString('en-US') : '0'
const usd = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })
const workersWord = (n: number) => `${grouped(n)} ${n === 1 ? 'worker' : 'workers'}`

/**
 * One hero per run state, replacing the budget banner, the "Provisional summary · As of <now>"
 * eyebrow and the duplicate header primaries. Exactly one primary when the state is actionable.
 */
export function deriveRunHero(input: {
  status: string
  phase: string
  roundNo: number
  spentUsd: number
  budgetUsd: number
  spentRequests: number
  budgetRequests: number
  workers: readonly { status: string; outcome?: string | null }[]
  endedAt: number
  liveSummary?: string
  reportLabel?: string | null
  context?: readonly (string | null | undefined | false)[]
  fmtWhen: (ms: number) => string
}): RunHeroModel {
  const lifecycle = runLifecycleOf(input.status)
  const tone = runLifecycleMeta[lifecycle].tone
  const failed = input.workers.filter(w => w.status === 'failed')
  const parked = input.workers.filter(w => w.status === 'paused' || w.status === 'waiting_approval').length
  const running = input.workers.filter(w => w.status === 'running').length
  const ctx = (extra: readonly (string | null | undefined | false)[]) => [...extra, ...(input.context ?? [])].filter(Boolean).join(' · ')
  const phase = PHASE_LABEL[input.phase] ?? (input.phase ? capF(input.phase.replace(/_/g, ' ')) : 'Running')
  const showFailed = failed.length > 0 ? { id: 'show_failed' as const, label: failed.length === 1 ? 'Show failed worker' : 'Show failed workers' } : null
  const base = { lifecycle, tone }
  switch (lifecycle) {
    case 'awaiting_approval': {
      const consent = input.phase === 'consent'
      return {
        ...base,
        title: awaitingApprovalTitle(input.phase),
        detail: consent
          ? 'Nothing has been sent yet. Approve discovery to map the project seeds.'
          : 'Approve the hosts, mode and budget to start testing.',
        primary: { id: 'approve', label: 'Approve & start' },
        secondary: null,
      }
    }
    case 'running':
      return {
        ...base,
        title: `Running — ${phase}`,
        detail: ctx([input.liveSummary || `Round ${grouped(input.roundNo)}`, failed.length > 0 && `${workersWord(failed.length)} failed`]),
        primary: null,
        secondary: showFailed ?? (running > 0 ? { id: 'inspect', label: 'Inspect' } : null),
      }
    case 'paused': {
      if (input.status === 'budget_paused') {
        const reqHit = input.budgetRequests > 0 && input.spentRequests >= input.budgetRequests
        const usdHit = input.budgetUsd > 0 && input.spentUsd >= input.budgetUsd
        const title = reqHit
          ? `Paused at request budget — ${grouped(input.spentRequests)} / ${grouped(input.budgetRequests)}`
          : usdHit
            ? `Paused at spend budget — ${usd.format(input.spentUsd)} / ${usd.format(input.budgetUsd)}`
            : 'Paused at budget'
        return { ...base, title, detail: ctx(['Partial report saved', 'raise the cap to resume where testing stopped']), primary: { id: 'raise_budget', label: 'Raise budget' }, secondary: null }
      }
      return {
        ...base,
        title: 'Paused — ready to resume',
        detail: ctx([parked > 0 && `${workersWord(parked)} parked`, `Round ${grouped(input.roundNo)}`]),
        primary: input.phase === 'complete' ? null : { id: 'resume', label: 'Resume' },
        secondary: showFailed,
      }
    }
    case 'failed': {
      const reason = failed.map(w => stripFailurePrefix(w.outcome)).find(Boolean)
      return {
        ...base,
        title: failed.length > 0 ? `Failed — ${workersWord(failed.length)} exited` : 'Failed — the run stopped on an error',
        detail: ctx([reason ? firstSentence(reason) : null, input.reportLabel]),
        primary: showFailed,
        secondary: null,
      }
    }
    case 'stopped':
      return { ...base, title: `Stopped ${input.fmtWhen(input.endedAt)}`, detail: ctx([input.reportLabel ?? 'No report saved']), primary: null, secondary: showFailed }
    case 'complete':
      return { ...base, title: `Complete — finished ${input.fmtWhen(input.endedAt)}`, detail: ctx([input.reportLabel]), primary: null, secondary: null }
    default: {
      const never: never = lifecycle
      return never
    }
  }
}

// ---------------------------------------------------------------- worker triage ([U6])

/** Outcome text without the redundant "Worker failed:" lead-in. */
const stripFailurePrefix = (outcome: string | null | undefined) => String(outcome ?? '').replace(/^\s*worker failed:\s*/i, '').trim()

/** Active-now rows shown before the "Show all {n}" toggle. */
export const ACTIVE_NOW_CAP = 6

export type AttentionKind = 'failed' | 'approval' | 'stalled'

export interface AttentionGroup {
  key: string
  kind: AttentionKind
  /** Normalised failure signature shared by every member ("Upstream model endpoint returned 503"). */
  signature: string
  /** One-line reason shown on the lane row. */
  reason: string
  workers: Assignment[]
}

/**
 * Failure signature: the first sentence of the outcome with volatile tokens (ids, hex, numbers
 * other than HTTP-like status codes, URLs, quoted values) folded, so five workers that failed on the
 * same upstream timeout group as one "×5" row instead of five.
 */
export function failureSignature(outcome: string | null | undefined): string {
  const first = firstSentence(stripFailurePrefix(outcome)).replace(/\.$/, '').trim()
  if (!first) return 'Worker exited without a recorded reason'
  const folded = first
    .replace(/https?:\/\/\S+/gi, '<url>')
    .replace(/(["'`]).*?\1/g, '…')
    .replace(/\b[0-9a-f]{8,}\b/gi, '<id>')
    .replace(/\b(?![1-5]\d\d\b)\d[\d,._:]*(ms|s|m|h|kb|mb|gb)?\b/gi, (_m, unit: string | undefined) => 'N' + (unit ?? ''))
    .replace(/\s+/g, ' ')
  return capF(folded.length > 96 ? folded.slice(0, 95).trimEnd() + '…' : folded)
}

/**
 * Failure-first triage lane: failed workers grouped by signature, workers waiting on an approval,
 * and stalled workers (paused while the run itself is running). Returns the member ids so the
 * phase groups below can exclude them (each worker is listed exactly once).
 */
export function buildAttentionLane(workers: readonly Assignment[], runStatus: string): { groups: AttentionGroup[]; ids: Set<string> } {
  const runLive = runLifecycleOf(runStatus) === 'running'
  const terminal = !runLifecycleMeta[runLifecycleOf(runStatus)].live
  const by = new Map<string, AttentionGroup>()
  const add = (kind: AttentionKind, signature: string, reason: string, a: Assignment) => {
    const key = kind + ':' + signature
    const g = by.get(key)
    if (g) g.workers.push(a)
    else by.set(key, { key, kind, signature, reason, workers: [a] })
  }
  for (const a of workers) {
    if (a.status === 'failed') {
      const sig = failureSignature(a.outcome)
      add('failed', sig, sig, a)
    } else if (!terminal && a.status === 'waiting_approval') {
      add('approval', 'approval', 'Waiting for an operator approval decision', a)
    } else if (runLive && a.status === 'paused') {
      add('stalled', 'stalled', 'Paused while the run is still running', a)
    }
  }
  const rank: Record<AttentionKind, number> = { failed: 0, approval: 1, stalled: 2 }
  const groups = [...by.values()].sort((x, y) => rank[x.kind] - rank[y.kind] || y.workers.length - x.workers.length || x.signature.localeCompare(y.signature))
  for (const g of groups) g.workers.sort((x, y) => x.createdAt - y.createdAt)
  return { groups, ids: new Set(groups.flatMap(g => g.workers.map(a => a.id))) }
}

/** Active-now rows: the first `cap` unless expanded, plus how many are folded behind "Show all". */
export function capActiveNow<T>(items: readonly T[], showAll: boolean, cap = ACTIVE_NOW_CAP): { shown: T[]; hidden: number } {
  if (showAll || items.length <= cap) return { shown: items.slice(), hidden: 0 }
  return { shown: items.slice(0, cap), hidden: items.length - cap }
}

// ---------------------------------------------------------------- turn timeline rail ([U6])

export type ToolStatus = 'ok' | 'error' | 'finding' | 'pending'
export type TurnFilter = 'all' | 'errors' | 'findings' | 'slow'
export const SLOW_TURN_MS = 10_000

export interface TimelineTurnInput {
  turn: number
  durationMs?: number
  tools: readonly { id: string; status: ToolStatus; durationMs?: number }[]
}

export interface TimelineRow {
  turn: number
  /** Bar width as a share of the slowest turn (equal ticks when durations are absent). */
  width: number
  durationMs: number | null
  segments: { id: string; status: ToolStatus; share: number }[]
  errors: number
  findings: number
  slow: boolean
}

/**
 * One rail row per turn with a proportional duration bar whose segments are the turn's tool calls
 * coloured by outcome. Missing durations fall back to equal ticks, so the rail never collapses.
 */
export function buildTurnTimeline(turns: readonly TimelineTurnInput[]): { rows: TimelineRow[]; counts: Record<TurnFilter, number>; proportional: boolean } {
  const dur = (t: TimelineTurnInput) => {
    if (typeof t.durationMs === 'number' && Number.isFinite(t.durationMs) && t.durationMs >= 0) return t.durationMs
    const sum = t.tools.reduce((s, x) => s + (typeof x.durationMs === 'number' && Number.isFinite(x.durationMs) ? Math.max(0, x.durationMs) : 0), 0)
    return sum > 0 ? sum : null
  }
  const ds = turns.map(dur)
  const proportional = ds.some(d => d != null && d > 0)
  const maxD = Math.max(1, ...ds.map(d => d ?? 0))
  const rows = turns.map((t, i): TimelineRow => {
    const d = ds[i] ?? null
    const known = t.tools.map(x => (typeof x.durationMs === 'number' && Number.isFinite(x.durationMs) ? Math.max(0, x.durationMs) : 0))
    const knownSum = known.reduce((a, b) => a + b, 0)
    const segments = t.tools.map((x, k) => ({ id: x.id, status: x.status, share: knownSum > 0 ? known[k]! / knownSum : 1 / Math.max(1, t.tools.length) }))
    return {
      turn: t.turn,
      width: proportional ? Math.max(0.04, (d ?? 0) / maxD) : 1,
      durationMs: d,
      segments,
      errors: t.tools.filter(x => x.status === 'error').length,
      findings: t.tools.filter(x => x.status === 'finding').length,
      slow: d != null && d > SLOW_TURN_MS,
    }
  })
  const counts: Record<TurnFilter, number> = {
    all: rows.length,
    errors: rows.filter(r => r.errors > 0).length,
    findings: rows.filter(r => r.findings > 0).length,
    slow: rows.filter(r => r.slow).length,
  }
  return { rows, counts, proportional }
}

export function matchesTurnFilter(row: Pick<TimelineRow, 'errors' | 'findings' | 'slow'>, filter: TurnFilter): boolean {
  return filter === 'all' || (filter === 'errors' ? row.errors > 0 : filter === 'findings' ? row.findings > 0 : row.slow)
}

/** Successful tool calls collapse to one line; errors and findings open by default. */
export const toolOpenByDefault = (status: ToolStatus) => status === 'error' || status === 'finding'

/** Window a long trace: render only rows near the viewport once a trace passes `threshold` turns. */
export const TRACE_WINDOW_THRESHOLD = 40
export function traceWindow(total: number, firstVisible: number, opts: { threshold?: number; size?: number; overscan?: number } = {}): { start: number; end: number; windowed: boolean } {
  const threshold = opts.threshold ?? TRACE_WINDOW_THRESHOLD
  if (total <= threshold) return { start: 0, end: total, windowed: false }
  const size = opts.size ?? 24
  const over = opts.overscan ?? 8
  const start = Math.max(0, Math.min(total - 1, firstVisible) - over)
  return { start, end: Math.min(total, start + size + over * 2), windowed: true }
}

/** Aggregate status of a group of workers (paused/waiting beats running beats failed beats complete). */
export function aggStatus(list: readonly { status: string }[]) {
  const has = (s: string) => list.some(a => a.status === s)
  return has('paused') || has('waiting_approval') ? 'paused' : has('running') ? 'running' : has('failed') ? 'failed' : 'complete'
}
