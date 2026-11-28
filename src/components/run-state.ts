import type { runData } from '../actions.ts'
import type { ApprovalPolicy, BoardMemberState, BoardMessageKind, CapabilityTier, OwaspCategory, Phase, RunStatus } from '../domain.ts'
import type { IconName } from './run/icons.tsx'

export type RunDetail = Awaited<ReturnType<typeof runData>>
export type Worker = RunDetail['assignments'][number]

export const phaseNames: Record<Phase, string> = {
  consent: 'Discovery consent',
  discovery: 'Discovery',
  review: 'Awaiting scope approval',
  threat_model: 'Threat model',
  investigation: 'Investigation',
  verification: 'Verification',
  complete: 'Complete',
}

export const capabilityTierMeta: Record<CapabilityTier, { name: string; short: string; summary: string }> = {
  0: {
    name: 'Offline Review',
    short: 'Offline',
    summary: 'No live network traffic. Reviews prepared exports, DNS records, lockfiles, and access policies only.',
  },
  1: {
    name: 'Read-Only Scan',
    short: 'Read-Only',
    summary: 'Safe read-only HTTP checks, JavaScript and API discovery, scoped browser inspection, live DNS/TLS checks, and benign verification probes.',
  },
  2: {
    name: 'Authenticated Testing',
    short: 'Authenticated',
    summary: 'Includes read-only checks plus signed-in testing with your test accounts on approved hosts for cross-account access, role, and session checks.',
  },
  3: {
    name: 'Active Testing (Approval-Gated)',
    short: 'Active (Gated)',
    summary: 'Includes authenticated testing plus approval-gated state checks and strictly non-destructive proof-of-execution verification.',
  },
}

// ---------------------------------------------------------------- one run vocabulary ([U4])
//
// Every surface that names a run's mode, lifecycle or phase (project overview + runs tabs, run
// header, run hero, consent stepper, rail, palette) reads these tables, so the same run never
// reads "Authenticated Testing" in one place and "Passive Scan" in another.

/** Testing mode: what the run may send. Derived from capability tier × approval policy. */
export type RunMode = 'offline' | 'passive' | 'supervised' | 'autonomous'

export const runModeMeta: Record<RunMode, {
  /** Canonical short label used in badges, the run header and the hero ("Passive"). */
  label: string
  /** Long form used in the New-run / scope selectors and search ("Passive Scan"). */
  scanLabel: string
  tone: 'neutral' | 'accent' | 'warn'
  summary: string
}> = {
  offline: {
    label: 'Offline',
    scanLabel: 'Offline Review',
    tone: 'neutral',
    summary: 'No live network traffic; reviews prepared exports and records only.',
  },
  passive: {
    label: 'Passive',
    scanLabel: 'Passive Scan',
    tone: 'neutral',
    summary: 'Read-only checks (plus bound test accounts); never mutates state.',
  },
  supervised: {
    label: 'Supervised',
    scanLabel: 'Supervised Scan',
    tone: 'accent',
    summary: 'Safe active checks automatically; pauses for approval before risky writes.',
  },
  autonomous: {
    label: 'Autonomous',
    scanLabel: 'Autonomous Scan',
    tone: 'warn',
    summary: 'All in-scope active probes automatically with hard safety guardrails enforced.',
  },
}

/** Mode of a run or draft: tier 3 + `yolo` is autonomous, tier 3 otherwise supervised, tier 0 offline. */
export function runModeOf(run: { capabilityTier: CapabilityTier | number; approvalPolicy?: ApprovalPolicy | null }): RunMode {
  if (run.capabilityTier === 0) return 'offline'
  if (run.capabilityTier === 3) return run.approvalPolicy === 'yolo' ? 'autonomous' : 'supervised'
  return 'passive'
}

/** Operator-facing lifecycle: the six states a run can be in, whatever the raw status string. */
export type RunLifecycle = 'running' | 'paused' | 'awaiting_approval' | 'complete' | 'failed' | 'stopped'

/** Canonical lifecycle order (posture breakdowns and filter counts read in this order). */
export const RUN_LIFECYCLES: readonly RunLifecycle[] = ['running', 'paused', 'awaiting_approval', 'complete', 'failed', 'stopped']

export type LifecycleTone = 'accent' | 'warn' | 'ok' | 'danger' | 'neutral'

export const runLifecycleMeta: Record<RunLifecycle, {
  label: string
  tone: LifecycleTone
  icon: IconName
  /** Status string `StatusGlyph` renders for this lifecycle. */
  glyph: string
  /** Tailwind background class for the 7–8px status dot. */
  dot: string
  /** Still consuming budget or waiting on an operator (not terminal). */
  live: boolean
}> = {
  running: { label: 'Running', tone: 'accent', icon: 'play', glyph: 'running', dot: 'bg-accent', live: true },
  paused: { label: 'Paused', tone: 'warn', icon: 'pause', glyph: 'paused', dot: 'bg-warn', live: true },
  awaiting_approval: { label: 'Awaiting approval', tone: 'warn', icon: 'shield', glyph: 'waiting', dot: 'bg-warn', live: true },
  complete: { label: 'Complete', tone: 'ok', icon: 'check', glyph: 'complete', dot: 'bg-ok', live: false },
  failed: { label: 'Failed', tone: 'danger', icon: 'alert', glyph: 'failed', dot: 'bg-danger', live: false },
  stopped: { label: 'Stopped', tone: 'neutral', icon: 'stop', glyph: 'stopped', dot: 'bg-fg-faint', live: false },
}

const LIFECYCLE_BY_STATUS: Record<RunStatus, RunLifecycle> = {
  waiting: 'awaiting_approval',
  running: 'running',
  paused: 'paused',
  budget_paused: 'paused',
  stopped: 'stopped',
  failed: 'failed',
  complete: 'complete',
}
const LEGACY_LIFECYCLE: Record<string, RunLifecycle> = { queued: 'paused', completed: 'complete', canceled: 'stopped', cancelled: 'stopped' }

/** Map any run status string (canonical or legacy alias) onto the six-state lifecycle. */
export function runLifecycleOf(status: string | null | undefined): RunLifecycle {
  const s = String(status ?? '').trim().toLowerCase()
  return (LIFECYCLE_BY_STATUS as Record<string, RunLifecycle>)[s] ?? LEGACY_LIFECYCLE[s] ?? 'stopped'
}

/** Canonical label for a run status ("waiting" → "Awaiting approval", "budget_paused" → "Paused"). */
export function runLifecycleLabel(status: string | null | undefined): string {
  return runLifecycleMeta[runLifecycleOf(status)].label
}

/** Exact per-lifecycle counts plus a "1 running · 1 paused · 1 awaiting approval" sentence. */
export function lifecycleBreakdown(
  runs: readonly { status: string }[],
  opts: { liveOnly?: boolean } = {},
): { counts: Record<RunLifecycle, number>; text: string } {
  const counts: Record<RunLifecycle, number> = { running: 0, paused: 0, awaiting_approval: 0, complete: 0, failed: 0, stopped: 0 }
  for (const run of runs) {
    const lc = runLifecycleOf(run.status)
    // A terminal run that still has live work winding down reads as running in a live-only breakdown.
    counts[opts.liveOnly && !runLifecycleMeta[lc].live ? 'running' : lc] += 1
  }
  const text = RUN_LIFECYCLES
    .filter(lc => counts[lc] > 0)
    .map(lc => `${formatCount(counts[lc])} ${runLifecycleMeta[lc].label.toLowerCase()}`)
    .join(' · ')
  return { counts, text }
}

/** One canonical phase track: consent stepper, header KPI strip and workflow summary all use it. */
export const RUN_PHASES = [
  { key: 'scope', label: 'Scope', summary: 'Approve hosts, mode, and budget.' },
  { key: 'threat_model', label: 'Threat model', summary: 'Rank hosts by attack surface.' },
  { key: 'investigation', label: 'Investigation', summary: 'Workers test through the safety proxy.' },
  { key: 'verification', label: 'Verification', summary: 'Automated replay confirms every finding.' },
  { key: 'report', label: 'Report', summary: 'Findings, coverage, and gaps.' },
] as const
export type RunPhaseKey = typeof RUN_PHASES[number]['key']

const PHASE_STEP: Record<string, RunPhaseKey> = {
  consent: 'scope', discovery: 'scope', review: 'scope', threat_model: 'threat_model',
  investigation: 'investigation', verification: 'verification', retest: 'verification', complete: 'report', report: 'report',
}

export interface RunPhaseInfo {
  key: RunPhaseKey
  /** 1-based position in `RUN_PHASES`. */
  index: number
  total: number
  label: string
  ariaLabel: string
  /** The run finished every phase (`phase === 'complete'`). */
  done: boolean
}

/** Position of a run (or worker) phase on the canonical track: "Phase 2 of 5: Threat model". */
export function runPhaseOf(phase: Phase | string | null | undefined): RunPhaseInfo {
  const key = PHASE_STEP[String(phase ?? '')] ?? 'scope'
  const i = RUN_PHASES.findIndex(p => p.key === key)
  const step = RUN_PHASES[i]!
  const total = RUN_PHASES.length
  return { key, index: i + 1, total, label: step.label, ariaLabel: `Phase ${i + 1} of ${total}: ${step.label}`, done: phase === 'complete' }
}

export const approvalPolicyMeta: Record<ApprovalPolicy, {
  label: string
  short: string
  optionLabel: string
  summary: string
}> = {
  auto_review: {
    label: 'Auto-Review',
    short: 'Auto-Review',
    optionLabel: 'Auto-Review (Recommended)',
    summary: 'Fast-paths safe read-only checks, reviews write requests with an independent safety checker, and always asks you before deletes, uploads, billing/admin actions, or execution checks.',
  },
  yolo: {
    label: 'Autonomous',
    short: 'Autonomous',
    optionLabel: 'Autonomous (Auto-approve in scope)',
    summary: 'Automatically approves all in-scope active checks with full audit logging. Hard safety guardrails (approved hosts only, private network block, destructive denylist, rate limits, and safety pauses) remain enforced.',
  },
  strict: {
    label: 'Manual Approval',
    short: 'Manual',
    optionLabel: 'Manual (Approve every write)',
    summary: 'Pauses and requires your explicit approval before every state-changing test request.',
  },
}

export const owaspCategoryLabels: Record<OwaspCategory, string> = {
  'broken-access-control': 'Broken Access Control',
  'auth-identity': 'Auth & Identity',
  'injection-input': 'Injection & Input',
  'cors-client-side': 'CORS & Client-Side',
  'ssrf-redirects': 'SSRF & Redirects',
  'crypto-tls-transport': 'Crypto, TLS & Transport',
  'misconfig-exposure': 'Misconfiguration & Exposure',
  'upload-storage': 'Upload & Storage',
  'business-logic-race': 'Business Logic & Race',
  'dns-takeover-infra': 'DNS Takeover & Infra',
  'llm-ai-security': 'LLM & AI Security',
}

const usdFormatter = new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' })
const countFormatter = new Intl.NumberFormat('en-US')

/** Grouped USD ("$1,234.56"); sub-cent spend reads "<$0.01". */
export function formatUsd(amount: number) {
  if (!Number.isFinite(amount)) return usdFormatter.format(0)
  return amount < 0.01 && amount > 0 ? '<$0.01' : usdFormatter.format(amount)
}

/** Grouped integer counts for run metadata ("999,999"). Non-finite values read as 0. */
export function formatCount(n: number) {
  return countFormatter.format(Number.isFinite(n) ? n : 0)
}

export const boardKindLabels: Record<BoardMessageKind, string> = {
  brief: 'BRIEF',
  claim: 'CLAIM',
  handoff: 'HANDOFF',
  lead: 'LEAD',
  blocker: 'BLOCKER',
  approval: 'APPROVAL',
  verdict: 'VERDICT',
  status: 'STATUS',
  note: 'NOTE',
}

export const boardStateMeta: Record<BoardMemberState, { label: string; symbol: string; className: string }> = {
  working: { label: 'working', symbol: '●', className: 'state-working' },
  waiting: { label: 'waiting', symbol: '○', className: 'state-waiting' },
  paused: { label: 'paused', symbol: '⏸', className: 'state-paused' },
  retired: { label: 'retired', symbol: '✓', className: 'state-retired' },
}

export const boardRoleLabels: Record<string, string> = {
  operator: 'Operator',
  coordinator: 'Coordinator',
  specialist: 'Specialist',
  verifier: 'Verifier',
  system: 'System',
}
